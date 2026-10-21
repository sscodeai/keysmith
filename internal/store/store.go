// Package store implements an age-encrypted key-value store for secrets.
//
// Design goals:
//   - Secrets at rest are ALWAYS encrypted with age (X25519). A plaintext file
//     never exists on disk.
//   - Encrypted blobs are safe to read into agent context — they contain no
//     plaintext, so "encrypted residency" means even a leaked context is harmless.
//   - Reads decrypt in memory only; the plaintext is never written back to disk.
//   - File permissions are 0600.
package store

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"

	"github.com/sscodeai/keysmith/internal/mask"
)

// Store is an age-encrypted secret KV store rooted at a directory.
type Store struct {
	dir string // directory holding secrets.enc + key.txt (key is 0600)
}

// ErrNotFound is returned when a key does not exist.
var ErrNotFound = errors.New("secret not found")

// New creates a Store rooted at dir, initializing the age keypair if absent.
func New(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", dir, err)
	}
	s := &Store{dir: dir}
	// Two processes may initialize the same directory at once (for example an
	// MCP server and an interactive `keysmith set`). Serialize key creation so
	// they cannot write two different identities over each other.
	unlock, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := s.ensureKey(); err != nil {
		return nil, err
	}
	return s, nil
}

// lockPath is the writer lock file next to the encrypted store.
func (s *Store) lockPath() string { return filepath.Join(s.dir, "store.lock") }

// lock takes the exclusive writer lock. The returned function releases it.
func (s *Store) lock() (func(), error) {
	l, err := lockFile(s.lockPath())
	if err != nil {
		return nil, fmt.Errorf("lock store: %w", err)
	}
	return l.Unlock, nil
}

// KeyPath returns the path to the secret key file.
func (s *Store) KeyPath() string { return filepath.Join(s.dir, "key.txt") }

// Dir returns the store directory. Callers that need to place files next to the
// store (for example the MCP inbox) resolve them against this path.
func (s *Store) Dir() string { return s.dir }

// DataPath returns the path to the encrypted secrets file.
func (s *Store) DataPath() string { return filepath.Join(s.dir, "secrets.enc") }

func (s *Store) ensureKey() error {
	keyPath := s.KeyPath()
	if _, err := os.Stat(keyPath); err == nil {
		return nil
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return fmt.Errorf("generate age identity: %w", err)
	}
	// 0600 — key file must never be world-readable.
	if err := os.WriteFile(keyPath, []byte(identity.String()+"\n"), 0o600); err != nil {
		return fmt.Errorf("write key file: %w", err)
	}
	// Ensure data file exists (empty encrypted blob).
	if _, err := os.Stat(s.DataPath()); os.IsNotExist(err) {
		if err := s.writeEncrypted(map[string]string{}); err != nil {
			return err
		}
	}
	return nil
}

// loadIdentity reads and parses the age identity from key.txt.
func (s *Store) loadIdentity() (age.Identity, error) {
	b, err := os.ReadFile(s.KeyPath())
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	identities, err := age.ParseIdentities(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("parse identity: %w", err)
	}
	if len(identities) == 0 {
		return nil, errors.New("no identity found in key file")
	}
	return identities[0], nil
}

// loadRecipient returns the age recipient (public key) derived from our identity.
func (s *Store) loadRecipient() (age.Recipient, error) {
	id, err := s.loadIdentity()
	if err != nil {
		return nil, err
	}
	// age.X25519Identity exposes Recipient(); other identity types return a
	// recipient via the Recipient() method on the concrete type.
	if xid, ok := id.(*age.X25519Identity); ok {
		return xid.Recipient(), nil
	}
	// Fallback: derive recipient from the identity's own public key string.
	// X25519Identity.String() returns "AGE-SECRET-KEY-..."; the recipient is
	// the matching "age1..." public key. We reconstruct it via ParseRecipients
	// on the identity's string form is NOT possible, so error clearly.
	return nil, errors.New("unsupported identity type for recipient derivation")
}

// readDecrypted loads and decrypts the secrets map from disk.
func (s *Store) readDecrypted() (map[string]string, error) {
	raw, err := os.ReadFile(s.DataPath())
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, fmt.Errorf("read data: %w", err)
	}
	if len(raw) == 0 {
		return map[string]string{}, nil
	}
	id, err := s.loadIdentity()
	if err != nil {
		return nil, err
	}
	r := armor.NewReader(bytes.NewReader(raw))
	rr, err := age.Decrypt(r, id)
	if err != nil {
		return nil, fmt.Errorf("decrypt data: %w", err)
	}
	plain, err := io.ReadAll(rr)
	if err != nil {
		return nil, fmt.Errorf("read decrypted: %w", err)
	}
	m := map[string]string{}
	if len(plain) > 0 {
		if err := json.Unmarshal(plain, &m); err != nil {
			return nil, fmt.Errorf("parse secrets json: %w", err)
		}
	}
	return m, nil
}

// writeEncrypted encrypts and writes the secrets map to disk (atomic, 0600).
func (s *Store) writeEncrypted(m map[string]string) error {
	rec, err := s.loadRecipient()
	if err != nil {
		return err
	}
	plain, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal secrets: %w", err)
	}
	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	w, err := age.Encrypt(aw, rec)
	if err != nil {
		return fmt.Errorf("age encrypt: %w", err)
	}
	if _, err := w.Write(plain); err != nil {
		return fmt.Errorf("age write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("age close: %w", err)
	}
	// age's writer does NOT close the underlying armor writer; closing it
	// writes the trailing checksum + END marker, completing the armored blob.
	if err := aw.Close(); err != nil {
		return fmt.Errorf("armor close: %w", err)
	}
	// Atomic write: temp file in the same directory, then rename. The name is
	// unique per write so two writers can never share (and truncate) a temp
	// file, even if one of them ignores the lock.
	f, err := os.CreateTemp(s.dir, "secrets.enc.tmp-*")
	if err != nil {
		return fmt.Errorf("write temp: %w", err)
	}
	tmp := f.Name()
	if _, err := f.Write(buf.Bytes()); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("write temp: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("write temp: %w", err)
	}
	if err := os.Rename(tmp, s.DataPath()); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename temp: %w", err)
	}
	return nil
}

// Set stores a secret value under key. Returns an error if key is invalid.
func (s *Store) Set(key, value string) error {
	if key == "" || strings.ContainsAny(key, " \t\n=") {
		return fmt.Errorf("invalid key %q", key)
	}
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	return s.setLocked(key, value)
}

// setLocked performs Set's read-modify-write. The caller must hold the lock.
func (s *Store) setLocked(key, value string) error {
	m, err := s.readDecrypted()
	if err != nil {
		return err
	}
	m[key] = value
	return s.writeEncrypted(m)
}

// Get returns the plaintext value for key. Returns ErrNotFound if absent.
// NOTE: caller must treat the returned value as secret — never log it.
func (s *Store) Get(key string) (string, error) {
	m, err := s.readDecrypted()
	if err != nil {
		return "", err
	}
	v, ok := m[key]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}

// List returns all keys (masked values). The values returned are ALREADY
// masked — safe for agent context.
func (s *Store) List() (map[string]string, error) {
	m, err := s.readDecrypted()
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = mask.MaskKey(k, v)
	}
	return out, nil
}

// Delete removes a key. Returns ErrNotFound if absent.
func (s *Store) Delete(key string) error {
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	m, err := s.readDecrypted()
	if err != nil {
		return err
	}
	if _, ok := m[key]; !ok {
		return ErrNotFound
	}
	delete(m, key)
	return s.writeEncrypted(m)
}

// Rotate generates a new random value for key and returns it masked.
// This is the "self-healing rotation" primitive — a new strong secret is
// generated and stored atomically.
func (s *Store) Rotate(key string, length int) (string, error) {
	if length < 16 {
		length = 32
	}
	val, err := randomSecret(length)
	if err != nil {
		return "", err
	}
	unlock, err := s.lock()
	if err != nil {
		return "", err
	}
	defer unlock()
	if err := s.setLocked(key, val); err != nil {
		return "", err
	}
	return mask.MaskKey(key, val), nil
}

// CreatedAt returns the file mtime of the data file (approximate store age).
func (s *Store) CreatedAt() time.Time {
	fi, err := os.Stat(s.DataPath())
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime()
}

// SortedKeys returns store keys sorted alphabetically.
func (s *Store) SortedKeys() ([]string, error) {
	m, err := s.readDecrypted()
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, nil
}

func randomSecret(n int) (string, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	// Rejection sampling: 256 is not a multiple of len(alphabet), so taking a
	// modulus of every byte would bias the first 8 letters. Bytes above the
	// largest multiple are discarded instead.
	const limit = 256 - 256%len(alphabet)
	out := make([]byte, n)
	buf := make([]byte, n)
	for i := 0; i < n; {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			if int(b) >= limit {
				continue
			}
			out[i] = alphabet[int(b)%len(alphabet)]
			i++
			if i == n {
				break
			}
		}
	}
	return string(out), nil
}
