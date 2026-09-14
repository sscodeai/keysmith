package redeem

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Synthetic fixture. Never use a value that could be a real credential here,
// and never print it in a test failure message (see AGENTS.md).
const canary = "sk-synthetic-CANARY-0001"

type stubValues map[string]string

func (s stubValues) Get(key string) (string, error) {
	v, ok := s[key]
	if !ok {
		return "", errors.New("secret not found")
	}
	return v, nil
}

func newTestResolver(t *testing.T) (*Sessions, *Resolver, string) {
	t.Helper()
	dir := t.TempDir()
	sessions := NewSessions(dir)
	return sessions, NewResolver(sessions, stubValues{"DEMO_KEY": canary, "DB_URL": "postgres://u:p@db/app"}), dir
}

func TestPassthroughWithoutToken(t *testing.T) {
	_, r, _ := newTestResolver(t)
	in := "curl -s https://example.test/health"
	out, names, err := r.Resolve(in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != in {
		t.Fatalf("text without a token must be returned unchanged")
	}
	if names != nil {
		t.Fatalf("no names expected, got %v", names)
	}
}

func TestResolveReplacesIssuedToken(t *testing.T) {
	sessions, r, _ := newTestResolver(t)
	sess, err := sessions.Issue("DEMO_KEY", time.Minute)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	out, names, err := r.Resolve("Bearer " + sess.Token("DEMO_KEY"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if out != "Bearer "+canary {
		t.Fatalf("token was not replaced with the stored value")
	}
	if len(names) != 1 || names[0] != "DEMO_KEY" {
		t.Fatalf("expected redeemed name DEMO_KEY, got %v", names)
	}
	if tokenRe.FindString(sess.Token("DEMO_KEY")) == "" {
		t.Fatalf("issued token does not match the token grammar")
	}
}

func TestResolveMultipleNamesSortedAndDeduplicated(t *testing.T) {
	sessions, r, _ := newTestResolver(t)
	if _, err := sessions.Issue("DEMO_KEY", time.Minute); err != nil {
		t.Fatal(err)
	}
	sess, err := sessions.Issue("DB_URL", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	in := sess.Token("DB_URL") + "|" + sess.Token("DEMO_KEY") + "|" + sess.Token("DEMO_KEY")
	out, names, err := r.Resolve(in)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if out != "postgres://u:p@db/app|"+canary+"|"+canary {
		t.Fatalf("unexpected resolution output")
	}
	if len(names) != 2 || names[0] != "DB_URL" || names[1] != "DEMO_KEY" {
		t.Fatalf("expected sorted deduplicated names, got %v", names)
	}
}

func TestIssueReusesActiveSession(t *testing.T) {
	sessions, _, _ := newTestResolver(t)
	first, err := sessions.Issue("DEMO_KEY", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	second, err := sessions.Issue("DB_URL", 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID {
		t.Fatalf("consecutive issues should share one session")
	}
	if len(second.Names) != 2 {
		t.Fatalf("expected both names in one session, got %v", second.Names)
	}
	if !second.ExpiresAt.After(first.ExpiresAt) {
		t.Fatalf("re-issuing should extend the TTL")
	}
}

func TestIssueRejectsInvalidName(t *testing.T) {
	sessions, _, _ := newTestResolver(t)
	for _, bad := range []string{"", "has space", "semi;colon", strings.Repeat("A", 65)} {
		if _, err := sessions.Issue(bad, time.Minute); !errors.Is(err, ErrBadName) {
			t.Fatalf("name %q should be rejected", bad)
		}
	}
}

func TestRefusesNameNotIssuedInSession(t *testing.T) {
	sessions, r, _ := newTestResolver(t)
	sess, err := sessions.Issue("DEMO_KEY", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// Same, valid session id — but DB_URL was never issued in it.
	_, _, err = r.Resolve(sess.Token("DB_URL"))
	if !errors.Is(err, ErrNameNotIssued) {
		t.Fatalf("expected ErrNameNotIssued, got %v", err)
	}
}

func TestRefusesUnknownSession(t *testing.T) {
	_, r, _ := newTestResolver(t)
	_, _, err := r.Resolve("[[keysmith:v1:DEMO_KEY:deadbeef]]")
	if !errors.Is(err, ErrSessionUnknown) {
		t.Fatalf("expected ErrSessionUnknown, got %v", err)
	}
}

func TestRefusesExpiredSession(t *testing.T) {
	sessions, r, _ := newTestResolver(t)
	sess, err := sessions.Issue("DEMO_KEY", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	tok := sess.Token("DEMO_KEY")

	// Force expiry on disk, then try to redeem.
	sess.ExpiresAt = time.Now().Add(-time.Second)
	if err := sessions.write(sess); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Resolve(tok); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("expected ErrSessionExpired, got %v", err)
	}
}

func TestRefusesMissingValue(t *testing.T) {
	sessions, r, _ := newTestResolver(t)
	sess, err := sessions.Issue("GHOST", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = r.Resolve(sess.Token("GHOST"))
	if err == nil {
		t.Fatalf("expected an error for a name missing from the store")
	}
	if !strings.Contains(err.Error(), "GHOST") {
		t.Fatalf("error should name the offending key, got %v", err)
	}
}

func TestRefusesMalformedReservedPrefix(t *testing.T) {
	sessions, r, _ := newTestResolver(t)
	if _, err := sessions.Issue("DEMO_KEY", time.Minute); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		"[[keysmith:v1:DEMO_KEY]]",                              // no session segment
		"[[keysmith:v2:DEMO_KEY:deadbeef]]",                     // unknown version
		"[[keysmith:v1:DEMO_KEY:ZZZZZZZZ]]",                     // session segment is not hex
		"[[keysmith:v1:DEMO_KEY:deadbeef]",                      // missing closing bracket
		"prefix [[keysmith: garbage suffix",                     // reserved prefix, no token
		"[[keysmith:v1:DEMO_KEY:deadbeef]] tail [[keysmith:v1:", // truncated second prefix
	} {
		if _, _, err := r.Resolve(bad); !errors.Is(err, ErrMalformedToken) {
			t.Fatalf("%q should be refused as malformed, got %v", bad, err)
		}
	}
}

func TestErrorsNeverContainAValue(t *testing.T) {
	sessions, r, _ := newTestResolver(t)
	sess, err := sessions.Issue("DEMO_KEY", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	inputs := []string{
		sess.Token("DB_URL"),                    // not issued
		sess.Token("GHOST"),                     // not in store
		"[[keysmith:v1:DEMO_KEY:deadbeef]]",     // unknown session
		"[[keysmith:v1:DEMO_KEY]]",              // malformed
		sess.Token("DEMO_KEY") + " [[keysmith:", // malformed among valid
	}
	for _, in := range inputs {
		_, _, err := r.Resolve(in)
		if err == nil {
			t.Fatalf("expected an error for %q", in)
		}
		if strings.Contains(err.Error(), canary) {
			t.Fatalf("an error message leaked a value: %v", err)
		}
	}
}

func TestEmptyStoredValueRefused(t *testing.T) {
	dir := t.TempDir()
	sessions := NewSessions(dir)
	r := NewResolver(sessions, stubValues{"EMPTY": ""})
	sess, err := sessions.Issue("EMPTY", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Resolve(sess.Token("EMPTY")); err == nil {
		t.Fatalf("an empty stored value must be refused")
	}
}

func TestRefreshDetectsTokens(t *testing.T) {
	if !HasToken("x [[keysmith:v1:A:deadbeef]] y") {
		t.Fatalf("HasToken should detect a token")
	}
	if !HasToken("dangling [[keysmith: prefix") {
		t.Fatalf("HasToken should detect the reserved prefix on its own")
	}
	if HasToken("curl https://example.test") {
		t.Fatalf("HasToken should not fire on ordinary text")
	}
}

// A stored value that itself contains a token is inserted literally: nested
// redemption is documented as unsupported.
func TestNestedTokenIsNotReExpanded(t *testing.T) {
	dir := t.TempDir()
	sessions := NewSessions(dir)
	r := NewResolver(sessions, stubValues{"A": "inner [[keysmith:v1:B:deadbeef]]", "B": canary})
	sess, err := sessions.Issue("A", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	out, names, err := r.Resolve(sess.Token("A"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !strings.Contains(out, "[[keysmith:v1:B:deadbeef]]") {
		t.Fatalf("nested tokens must be inserted literally")
	}
	if len(names) != 1 || names[0] != "A" {
		t.Fatalf("only the outer name should be recorded, got %v", names)
	}
}

func TestAuditLogRecordsNamesNotValues(t *testing.T) {
	dir := t.TempDir()
	rec := AuditRecord{
		Session: "abcd1234",
		Keys:    []string{"DEMO_KEY"},
		Command: "curl",
		Argc:    3,
		PID:     os.Getpid(),
	}
	if err := AppendAudit(dir, rec); err != nil {
		t.Fatalf("append audit: %v", err)
	}
	if err := AppendAudit(dir, rec); err != nil {
		t.Fatalf("append audit (second): %v", err)
	}

	path := filepath.Join(dir, auditFile)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	body := string(b)
	if strings.Contains(body, canary) {
		t.Fatalf("audit log must never contain a value")
	}
	if strings.Count(body, "\n") != 2 {
		t.Fatalf("expected two JSON lines, got %d", strings.Count(body, "\n"))
	}
	if !strings.Contains(body, `"DEMO_KEY"`) || !strings.Contains(body, `"curl"`) {
		t.Fatalf("audit log should record key names and the command basename")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("audit log must be 0600, got %v", info.Mode().Perm())
	}
}

func TestSessionFilesArePrivate(t *testing.T) {
	sessions, _, dir := newTestResolver(t)
	if _, err := sessions.Issue("DEMO_KEY", time.Minute); err != nil {
		t.Fatal(err)
	}
	dirInfo, err := os.Stat(filepath.Join(dir, sessionsDir))
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("sessions dir must be 0700, got %v", dirInfo.Mode().Perm())
	}
	entries, err := os.ReadDir(filepath.Join(dir, sessionsDir))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s must be 0600, got %v", e.Name(), info.Mode().Perm())
		}
	}
}
