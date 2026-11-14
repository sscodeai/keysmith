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
	sessionLock = "sessions.lock"
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
	// ErrBindingConflict: re-issuing a name with a different binding inside one
	// session is refused, so a binding cannot be widened after the fact.
	ErrBindingConflict = errors.New("conflicting target binding in this session")
	// ErrMixedSessions: one command carries tokens issued in different
	// sessions. The audit record and binding check are per-session, so refuse
	// rather than check one token against another session's bindings.
	ErrMixedSessions = errors.New("tokens from multiple sessions cannot be redeemed in one command")
	// ErrAmbiguousSession: a session id prefix matches more than one session.
	// Picking one arbitrarily could enforce the wrong binding, so refuse.
	ErrAmbiguousSession = errors.New("session id prefix is ambiguous")
)

var tokenRe = regexp.MustCompile(`\[\[keysmith:v1:([A-Za-z0-9_.-]{1,64}):([0-9a-f]{8})\]\]`)

var nameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// Session ids are 16 lowercase hex characters (8 random bytes). A token
// carries the first 8; --session may use a full id or a unique prefix.
var sessionIDRe = regexp.MustCompile(`^[0-9a-f]{16}$`)
var sessionPrefixRe = regexp.MustCompile(`^[0-9a-f]{1,16}$`)

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
	// Bindings restricts where each issued name may be redeemed. A name that is
	// absent here (or present with a zero binding) may be redeemed anywhere.
	Bindings map[string]Binding `json:"bindings,omitempty"`
}

// Binding returns the binding recorded for name, if any.
func (s *Session) Binding(name string) (Binding, bool) {
	if s.Bindings == nil {
		return Binding{}, false
	}
	b, ok := s.Bindings[name]
	return b, ok
}

// Token renders the token a caller should embed for this session.
func (s *Session) Token(name string) string {
	return fmt.Sprintf("%s%s:%s:%s]]", Prefix, Version, name, s.ShortID())
}

// ShortID is the first 8 characters of the session id, or the whole id when a
// malformed session carries fewer. It never panics on a short id.
func (s *Session) ShortID() string {
	if s == nil {
		return ""
	}
	if len(s.ID) <= 8 {
		return s.ID
	}
	return s.ID[:8]
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

// Resolved is one token occurrence: the key name and the session that issued
// it. Binding enforcement uses the issuing session, never an unrelated
// current session.
type Resolved struct {
	Name    string
	Session *Session
}

// SessionOf returns the single session that issued all resolved tokens. A mix
// of sessions is refused: the audit record and binding check are per-session,
// and checking a token against another session's bindings would skip them.
func SessionOf(resolved []Resolved) (*Session, error) {
	if len(resolved) == 0 {
		return nil, nil
	}
	sess := resolved[0].Session
	if sess == nil {
		return nil, ErrSessionUnknown
	}
	for _, r := range resolved[1:] {
		if r.Session == nil {
			return nil, ErrSessionUnknown
		}
		if r.Session.ID != sess.ID {
			return nil, fmt.Errorf("%w: %s and %s", ErrMixedSessions, sess.ShortID(), r.Session.ShortID())
		}
	}
	return sess, nil
}

// AuditRecord is one line of the redemption audit log. It deliberately has no
// field for a value and no field for the full argument list. Target holds the
// host and path of the declared destination, never its query string.
type AuditRecord struct {
	TS      string   `json:"ts"`
	Session string   `json:"session"`
	Keys    []string `json:"keys"`
	Command string   `json:"command"`
	Argc    int      `json:"argc"`
	PID     int      `json:"pid"`
	Target  string   `json:"target,omitempty"`
}

// Sessions stores issued sessions next to the encrypted store.
type Sessions struct {
	dir string
}

// NewSessions returns a session store rooted at <storeDir>/sessions.
func NewSessions(storeDir string) *Sessions {
	return &Sessions{dir: filepath.Join(storeDir, sessionsDir)}
}

// lockPath is the writer lock file next to the session files.
func (s *Sessions) lockPath() string { return filepath.Join(s.dir, sessionLock) }

// lock serializes the read-modify-write in IssueBound. Without it, two
// concurrent `keysmith token` calls can lose names or create two sessions.
func (s *Sessions) lock() (func(), error) {
	l, err := lockFile(s.lockPath())
	if err != nil {
		return nil, fmt.Errorf("lock sessions: %w", err)
	}
	return l.Unlock, nil
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

// Load reads a session by full id, rejecting unknown or expired ones. The id
// is validated before it is joined to the sessions directory, so a tampered
// `current` file cannot turn this into a path traversal.
func (s *Sessions) Load(id string) (*Session, error) {
	if !sessionIDRe.MatchString(id) {
		return nil, ErrSessionUnknown
	}
	b, err := os.ReadFile(filepath.Join(s.dir, id+".json"))
	if err != nil {
		return nil, ErrSessionUnknown
	}
	var sess Session
	if err := json.Unmarshal(b, &sess); err != nil {
		return nil, ErrSessionUnknown
	}
	// A copied or renamed session file whose content names a different id is
	// not the session the caller asked for.
	if sess.ID != id {
		return nil, ErrSessionUnknown
	}
	if time.Now().After(sess.ExpiresAt) {
		return nil, ErrSessionExpired
	}
	return &sess, nil
}

// LoadPrefix resolves a full session id or its 8-character token prefix.
// An unknown or nonexistent session prefix is reported as ErrSessionUnknown:
// the caller holds a token that this store cannot honour. A prefix matching
// more than one session is refused rather than resolved to an arbitrary one.
func (s *Sessions) LoadPrefix(prefix string) (*Session, error) {
	if !sessionPrefixRe.MatchString(prefix) {
		return nil, ErrSessionUnknown
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, ErrSessionUnknown
	}
	match := ""
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		id := strings.TrimSuffix(name, ".json")
		if !sessionIDRe.MatchString(id) || !strings.HasPrefix(id, prefix) {
			continue
		}
		if match != "" {
			return nil, fmt.Errorf("%w: %s", ErrAmbiguousSession, prefix)
		}
		match = id
	}
	if match == "" {
		return nil, ErrSessionUnknown
	}
	return s.Load(match)
}

// Issue records that name is available for redemption in the current session,
// with no target binding. It reuses the current session when one is still valid,
// so several tokens issued in a row share a session id, and extends the TTL on
// each call.
func (s *Sessions) Issue(name string, ttl time.Duration) (*Session, error) {
	return s.IssueBound(name, ttl, Binding{})
}

// IssueBound is Issue with a target binding recorded for the name. Re-issuing a
// name that already carries a different binding fails closed, so a binding
// cannot be widened (or silently dropped) inside one session.
func (s *Sessions) IssueBound(name string, ttl time.Duration, b Binding) (*Session, error) {
	if !nameRe.MatchString(name) {
		return nil, fmt.Errorf("%w: %q", ErrBadName, name)
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(s.dir, 0o700); err != nil {
		return nil, err
	}
	unlock, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()

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
	if prev, ok := sess.Binding(name); ok && prev.String() != b.String() {
		return nil, fmt.Errorf("%w: key %q already has binding %s in session %s",
			ErrBindingConflict, name, prev.String(), sess.ShortID())
	}
	if !b.IsZero() {
		if sess.Bindings == nil {
			sess.Bindings = map[string]Binding{}
		}
		sess.Bindings[name] = b
	}
	sess.ExpiresAt = time.Now().Add(ttl)

	if err := s.write(sess); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(filepath.Join(s.dir, currentFile), []byte(sess.ID), 0o600); err != nil {
		return nil, err
	}
	return sess, nil
}

func (s *Sessions) write(sess *Session) error {
	b, err := json.MarshalIndent(sess, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(s.dir, sess.ID+".json"), b, 0o600)
}

// writeFileAtomic writes b through a uniquely named temp file in the same
// directory and a rename, so a concurrent reader never sees a partial session
// or current pointer.
func writeFileAtomic(path string, b []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	cleanup := func() {
		_ = f.Close()
		_ = os.Remove(tmp)
	}
	if err := f.Chmod(mode); err != nil {
		cleanup()
		return err
	}
	if _, err := f.Write(b); err != nil {
		cleanup()
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
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
	out, resolved, err := r.ResolveDetailed(text)
	if err != nil {
		return "", nil, err
	}
	if len(resolved) == 0 {
		return out, nil, nil
	}
	names := make([]string, 0, len(resolved))
	for _, item := range resolved {
		names = append(names, item.Name)
	}
	return out, SortedUnique(names), nil
}

// ResolveDetailed is Resolve with the issuing session attached to every name.
// Binding enforcement must use the session that actually issued the token, not
// an unrelated current session.
func (r *Resolver) ResolveDetailed(text string) (string, []Resolved, error) {
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
	resolved := make([]Resolved, 0, len(locs))
	for _, loc := range locs { // loc = [full0 full1 name0 name1 sid0 sid1]
		b.WriteString(text[last:loc[0]])
		name := text[loc[2]:loc[3]]
		sid := text[loc[4]:loc[5]]

		sess, err := r.loadBySID(sid)
		if err != nil {
			return "", nil, err
		}
		if !sess.HasName(name) {
			return "", nil, fmt.Errorf("%w: %q in session %s", ErrNameNotIssued, name, sess.ShortID())
		}
		val, err := r.values.Get(name)
		if err != nil {
			return "", nil, fmt.Errorf("key %q is not available in the store: %w", name, err)
		}
		if val == "" {
			return "", nil, fmt.Errorf("key %q resolves to an empty value", name)
		}
		b.WriteString(val)
		resolved = append(resolved, Resolved{Name: name, Session: sess})
		last = loc[1]
	}
	b.WriteString(text[last:])

	return b.String(), resolved, nil
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
