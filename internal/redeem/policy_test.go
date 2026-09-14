package redeem

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestParseTargetAcceptsExpectedURLs(t *testing.T) {
	ok := map[string]Target{
		"https://api.example.test/v1/me": {Host: "api.example.test", Path: "/v1/me", Secure: true},
		"https://API.Example.Test":       {Host: "api.example.test", Path: "/", Secure: true},
		"http://127.0.0.1:8080/v1/x":     {Host: "127.0.0.1", Port: "8080", Path: "/v1/x"},
		"http://localhost:11434/api":     {Host: "localhost", Port: "11434", Path: "/api"},
		"http://[::1]:9000/ping":         {Host: "::1", Port: "9000", Path: "/ping"},
	}
	for raw, want := range ok {
		got, err := ParseTarget(raw)
		if err != nil {
			t.Fatalf("%s: unexpected error %v", raw, err)
		}
		if g, w := *got, want; g.Host != w.Host || g.Path != w.Path || g.Port != w.Port {
			t.Fatalf("%s: got %+v, want %+v", raw, g, w)
		}
	}
}

func TestParseTargetRefusesUnsafeURLs(t *testing.T) {
	bad := []string{
		"",
		"api.example.test/v1",             // no scheme
		"ftp://api.example.test/x",        // unsupported scheme
		"http://api.example.test/x",       // plain http to a remote host
		"https://api.example.test/v1?k=v", // query string (a place to hide a destination)
		"https://api.example.test/v1#frag",
	}
	for _, raw := range bad {
		if _, err := ParseTarget(raw); err == nil {
			t.Fatalf("%q should be refused", raw)
		}
	}
}

func TestHostAllowedSemantics(t *testing.T) {
	if !hostAllowed("api.example.test", []string{"api.example.test"}) {
		t.Fatalf("exact host should match")
	}
	if !hostAllowed("api.example.test", []string{".example.test"}) {
		t.Fatalf("a .suffix entry should match a subdomain")
	}
	if hostAllowed("example.test", []string{".example.test"}) {
		t.Fatalf("a .suffix entry should not match the bare domain")
	}
	if hostAllowed("evil-example.test", []string{".example.test"}) {
		t.Fatalf("a look-alike domain must not match")
	}
	if !hostAllowed("api.example.test", []string{"OTHER.test", ".EXAMPLE.test"}) {
		t.Fatalf("matching should be case-insensitive")
	}
	if hostAllowed("api.example.test", nil) {
		t.Fatalf("an empty allow list allows nothing")
	}
}

func tgt(t *testing.T, raw string) *Target {
	t.Helper()
	t2, err := ParseTarget(raw)
	if err != nil {
		t.Fatalf("ParseTarget(%q): %v", raw, err)
	}
	return t2
}

func TestBindingCheck(t *testing.T) {
	var zero Binding
	if err := zero.Check(nil, "curl https://anything.test"); err != nil {
		t.Fatalf("a zero binding must allow a command with no declared target: %v", err)
	}

	b := Binding{Hosts: []string{"api.example.test"}, PathPrefixes: []string{"/v1/"}}

	if err := b.Check(nil, "curl https://api.example.test/v1/x"); err == nil {
		t.Fatalf("a bound token must refuse a run with no --target")
	} else if !strings.Contains(err.Error(), "--target") {
		t.Fatalf("the refusal should say how to declare a target, got %v", err)
	}

	if err := b.Check(tgt(t, "https://api.example.test/v1/x"), "curl https://api.example.test/v1/x"); err != nil {
		t.Fatalf("matching host and path must be allowed: %v", err)
	}
	if err := b.Check(tgt(t, "https://evil.example.test/v1/x"), "curl https://evil.example.test/v1/x"); err == nil {
		t.Fatalf("a different host must be refused")
	}
	if err := b.Check(tgt(t, "https://api.example.test/v2/x"), "curl https://api.example.test/v2/x"); err == nil {
		t.Fatalf("a different path must be refused")
	}
}

func TestBindingCheckRequiresDeclaredHeader(t *testing.T) {
	b := Binding{Hosts: []string{"api.example.test"}, Headers: []string{"Authorization"}}
	t2 := tgt(t, "https://api.example.test/v1")

	if err := b.Check(t2, "AUTH=Bearer token"); err == nil {
		t.Fatalf("a binding that names a header must require it in the command")
	}
	if err := b.Check(t2, "AUTH=--header Authorization: Bearer [[keysmith:v1:A:deadbeef]]"); err != nil {
		t.Fatalf("the header appears case-insensitively as NAME: and must pass: %v", err)
	}
	if err := b.Check(t2, "authorization: bearer x"); err != nil {
		t.Fatalf("header matching must ignore case: %v", err)
	}
}

func TestCheckRedemptionMixedBindings(t *testing.T) {
	dir := t.TempDir()
	sessions := NewSessions(dir)
	if _, err := sessions.Issue("FREE_KEY", time.Minute); err != nil {
		t.Fatal(err)
	}
	sess, err := sessions.IssueBound("BOUND_KEY", time.Minute, Binding{Hosts: []string{"api.example.test"}})
	if err != nil {
		t.Fatal(err)
	}

	names := []string{"BOUND_KEY", "FREE_KEY"}

	// The unbound name alone needs no target.
	if _, err := CheckRedemption(sess, []string{"FREE_KEY"}, nil, ""); err != nil {
		t.Fatalf("an unbound name must pass without a target: %v", err)
	}

	// The bound name does, and the error names it.
	_, err = CheckRedemption(sess, names, nil, "")
	if err == nil {
		t.Fatalf("the bound name must require a target")
	}
	if !strings.Contains(err.Error(), "BOUND_KEY") {
		t.Fatalf("the refusal should name the offending key, got %v", err)
	}

	bound, err := CheckRedemption(sess, names, tgt(t, "https://api.example.test/v1"), "")
	if err != nil {
		t.Fatalf("a matching target must pass for the bound name: %v", err)
	}
	if len(bound) != 1 || bound[0] != "BOUND_KEY" {
		t.Fatalf("only the bound name should be reported, got %v", bound)
	}

	unbound := UnboundNames(sess, names)
	if len(unbound) != 1 || unbound[0] != "FREE_KEY" {
		t.Fatalf("unbound names should be reported for the warning, got %v", unbound)
	}
}

func TestPolicyErrorsCarryNoValue(t *testing.T) {
	dir := t.TempDir()
	sessions := NewSessions(dir)
	b := Binding{Hosts: []string{"api.example.test"}, PathPrefixes: []string{"/v1/"}, Headers: []string{"Authorization"}}
	sess, err := sessions.IssueBound("DEMO_KEY", time.Minute, b)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"https://evil.example.test/v1/", "https://api.example.test/other"} {
		if _, err := CheckRedemption(sess, []string{"DEMO_KEY"}, tgt(t, raw), ""); err == nil {
			t.Fatalf("%s should be refused", raw)
		} else if strings.Contains(err.Error(), canary) {
			t.Fatalf("an error message leaked a value: %v", err)
		}
	}
}

func TestIssueBoundRecordsBindingAndRefusesWidening(t *testing.T) {
	dir := t.TempDir()
	sessions := NewSessions(dir)
	b := Binding{Hosts: []string{"api.example.test"}}

	sess, err := sessions.IssueBound("DEMO_KEY", time.Minute, b)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := sess.Binding("DEMO_KEY")
	if !ok || got.String() != b.String() {
		t.Fatalf("binding not recorded: %v %v", got, ok)
	}

	// Same binding again is fine (idempotent re-issue).
	if _, err := sessions.IssueBound("DEMO_KEY", time.Minute, b); err != nil {
		t.Fatalf("re-issuing the same binding should be allowed: %v", err)
	}

	// A different binding, or dropping it, must fail closed.
	if _, err := sessions.IssueBound("DEMO_KEY", time.Minute, Binding{Hosts: []string{"other.test"}}); !errors.Is(err, ErrBindingConflict) {
		t.Fatalf("a different binding must conflict, got %v", err)
	}
	if _, err := sessions.Issue("DEMO_KEY", time.Minute); !errors.Is(err, ErrBindingConflict) {
		t.Fatalf("re-issuing without a binding must conflict, got %v", err)
	}

	// The binding survives a round trip through the session file.
	reloaded, err := sessions.Load(sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := reloaded.Binding("DEMO_KEY"); !ok || got.String() != b.String() {
		t.Fatalf("binding lost across a reload: %v %v", got, ok)
	}
}
