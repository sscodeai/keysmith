// Package redeem implements the local redemption layer: the point where a
// non-secret placeholder token inside a *locally* assembled command is replaced
// with the real value, without the value ever entering a model request, a
// transcript, or a process argument list.
//
// Design rules enforced here (see docs/THREAT-MODEL.md):
//
//   - deterministic: a regex match plus a table lookup, no model in the path
//   - fail closed: every error aborts the caller; nothing is ever forwarded
//     with a literal placeholder left in it, and no error carries a value
//   - session bound: a token is honoured only if its session id exists, is
//     unexpired, and had that key name issued — this blocks replay of tokens
//     copied out of an old transcript
//
// Token format:
//
//	[[keysmith:v1:NAME:sid8]]
//
// where NAME matches [A-Za-z0-9_.-]{1,64} and sid8 is the first 8 hex
// characters of the issuing session id.
package redeem

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	// Prefix is the reserved marker prefix. Text carrying it is either a valid
	// token or refused — it is never passed through unchanged.
	Prefix = "[[keysmith:"

	// Version identifies the token encoding and the session semantics.
	Version = "v1"

	// DefaultTTL is how long an issued session stays usable.
	DefaultTTL = time.Hour

	sessionsDir = "sessions"
	currentFile = "current"
	auditFile   = "audit.log"
)

// Fail-closed errors. Every one of these means: do not run the command.
var (
	ErrNoSession      = errors.New("no active redemption session: issue a token with `keysmith token NAME` first")
	ErrSessionUnknown = errors.New("session id is not known to this store")
	ErrSessionExpired = errors.New("session has expired: issue a fresh token")
	ErrNameNotIssued  = errors.New("key name was not issued in this session")
	ErrMalformedToken = errors.New("malformed or incomplete keysmith token")
	ErrBadName        = errors.New("invalid key name")
	ErrNoValues       = errors.New("resolver has no value source")
)

var tokenRe = regexp.MustCompile(`\[\[keysmith:v1:([A-Za-z0-9_.-]{1,64}):([0-9a-f]{8})\]\]`)

var nameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// ValueSource resolves a key name to its plaintext value. *store.Store
// satisfies this. Implementations must return an error for unknown names.
type ValueSource interface {
	Get(key string) (string, error)
}

// Session is an issued redemption session.
type Session struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Names     []string  `json:"names"`
}

// Token renders the token a caller should embed for this session.
func (s *Session) Token(name string) string {
	return fmt.Sprintf("%s%s:%s:%s]]", Prefix, Version, name, s.ID[:8])
}

// HasName reports whether name was issued in this session.
func (s *Session) HasName(name string) bool {
	for _, n := range s.Names {
		if n == name {
			return true
		}
	}
	return false
}

// AuditRecord is one line of the redemption audit log. It deliberately has no
// field for a value and no field for the full argument list.
type AuditRecord struct {
	TS      string   `json:"ts"`
	Session string   `json:"session"`
	Keys    []string `json:"keys"`
	Command string   `json:"command"`
	Argc    int      `json:"argc"`
	PID     int      `json:"pid"`
}

// Sessions stores issued sessions next to the encrypted store.
type Sessions struct {
	dir string
}

// NewSessions returns a session store rooted at <storeDir>/sessions.
func NewSessions(storeDir string) *Sessions {
	return &Sessions{dir: filepath.Join(storeDir, sessionsDir)}
}

// Current returns the most recently issued, still-valid session.
func (s *Sessions) Current() (*Session, error) {
	b, err := os.ReadFile(filepath.Join(s.dir, currentFile))
	if err != nil {
		return nil, ErrNoSession
	}
	id := strings.TrimSpace(string(b))
	if id == "" {
		return nil, ErrNoSession
	}
	return s.Load(id)
}

// Load reads a session by full id, rejecting unknown or expired ones.
func (s *Sessions) Load(id string) (*Session, error) {
	b, err := os.ReadFile(filepath.Join(s.dir, id+".json"))
	if err != nil {
		return nil, ErrSessionUnknown
	}
	var sess Session
	if err := json.Unmarshal(b, &sess); err != nil {
		return nil, ErrSessionUnknown
	}
	if time.Now().After(sess.ExpiresAt) {
		return nil, ErrSessionExpired
	}
	return &sess, nil
}

// LoadPrefix resolves a full session id or its 8-character token prefix.
// An unknown or nonexistent session prefix is reported as ErrSessionUnknown:
// the caller holds a token that this store cannot honour.
func (s *Sessions) LoadPrefix(prefix string) (*Session, error) {
	if prefix == "" {
		return nil, ErrSessionUnknown
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, ErrSessionUnknown
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		id := strings.TrimSuffix(name, ".json")
		if !strings.HasPrefix(id, prefix) {
			continue
		}
		return s.Load(id)
	}
	return nil, ErrSessionUnknown
}

// Issue records that name is available for redemption in the current session.
// It reuses the current session when one is still valid, so several tokens
// issued in a row share a session id, and extends the TTL on each call.
func (s *Sessions) Issue(name string, ttl time.Duration) (*Session, error) {
	if !nameRe.MatchString(name) {
		return nil, fmt.Errorf("%w: %q", ErrBadName, name)
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return nil, err
	}

	sess, err := s.Current()
	if err != nil {
		id, idErr := newID()
		if idErr != nil {
			return nil, idErr
		}
		sess = &Session{ID: id, CreatedAt: time.Now(), Names: []string{}}
	}
	if !sess.HasName(name) {
		sess.Names = append(sess.Names, name)
	}
	sess.ExpiresAt = time.Now().Add(ttl)

	if err := s.write(sess); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(s.dir, currentFile), []byte(sess.ID), 0o600); err != nil {
		return nil, err
	}
	return sess, nil
}

func (s *Sessions) write(sess *Session) error {
	b, err := json.MarshalIndent(sess, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.dir, sess.ID+".json"), b, 0o600)
}

// Resolver substitutes tokens using issued sessions and a value source.
type Resolver struct {
	sessions *Sessions
	values   ValueSource
}

// NewResolver builds a resolver over an issued-session store and a value source.
func NewResolver(sessions *Sessions, values ValueSource) *Resolver {
	return &Resolver{sessions: sessions, values: values}
}

// HasToken reports whether text contains the reserved prefix.
func HasToken(text string) bool {
	return strings.Contains(text, Prefix)
}

// Resolve replaces every well-formed token in text with its stored value and
// returns the key names it redeemed (sorted, deduplicated) for auditing.
//
// Any problem — unknown session, expired session, name not issued in that
// session, missing key in the store, malformed token — returns an error and no
// output. Error messages never contain a value.
func (r *Resolver) Resolve(text string) (string, []string, error) {
	if !HasToken(text) {
		return text, nil, nil
	}
	if r == nil || r.values == nil {
		return "", nil, ErrNoValues
	}
	if r.sessions == nil {
		return "", nil, ErrNoSession
	}

	locs := tokenRe.FindAllStringSubmatchIndex(text, -1)
	if len(locs) == 0 {
		return "", nil, ErrMalformedToken
	}

	// Refuse a partial token: anything carrying the reserved prefix that the
	// token regex does not fully consume is treated as malformed rather than
	// left in place.
	if stripped := tokenRe.ReplaceAllString(text, ""); strings.Contains(stripped, Prefix) {
		return "", nil, ErrMalformedToken
	}

	var b strings.Builder
	last := 0
	seen := map[string]bool{}
	names := make([]string, 0, len(locs))
	for _, loc := range locs { // loc = [full0 full1 name0 name1 sid0 sid1]
		b.WriteString(text[last:loc[0]])
		name := text[loc[2]:loc[3]]
		sid := text[loc[4]:loc[5]]

		sess, err := r.loadBySID(sid)
		if err != nil {
			return "", nil, err
		}
		if !sess.HasName(name) {
			return "", nil, fmt.Errorf("%w: %q in session %s", ErrNameNotIssued, name, sess.ID[:8])
		}
		val, err := r.values.Get(name)
		if err != nil {
			return "", nil, fmt.Errorf("key %q is not available in the store: %w", name, err)
		}
		if val == "" {
			return "", nil, fmt.Errorf("key %q resolves to an empty value", name)
		}
		b.WriteString(val)
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
		last = loc[1]
	}
	b.WriteString(text[last:])

	sort.Strings(names)
	return b.String(), names, nil
}

// loadBySID finds the session whose id starts with the 8-hex-character prefix
// carried by a token. Tokens do not carry the full session id.
func (r *Resolver) loadBySID(sid string) (*Session, error) {
	return r.sessions.LoadPrefix(sid)
}

// AppendAudit appends one JSON record to the audit log next to the store.
// It never records a value, and never records the full argument list.
func AppendAudit(storeDir string, rec AuditRecord) error {
	if rec.TS == "" {
		rec.TS = time.Now().UTC().Format(time.RFC3339)
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(storeDir, auditFile), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(line, '\n'))
	return err
}

// SortedUnique returns the names sorted and without duplicates, for audit
// records and status output.
func SortedUnique(names []string) []string {
	seen := make(map[string]bool, len(names))
	out := make([]string, 0, len(names))
	for _, n := range names {
		if seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func newID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
