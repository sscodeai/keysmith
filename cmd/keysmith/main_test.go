package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const token = "[[keysmith:v1:DEMO_KEY:8f3a2b1c]]"

func TestCheckHTTPBindingRequiresAuthOffLoopback(t *testing.T) {
	cases := []struct {
		addr, token string
		wantErr     bool
	}{
		{"127.0.0.1:8080", "", false},
		{"[::1]:8080", "", false},
		{"localhost:8080", "", false},
		{":8080", "", true},
		{"0.0.0.0:8080", "", true},
		{"192.168.1.10:8080", "", true},
		{"192.168.1.10:8080", "s3cret", false},
	}
	for _, c := range cases {
		err := checkHTTPBinding(c.addr, c.token)
		if (err != nil) != c.wantErr {
			t.Errorf("checkHTTPBinding(%q, %q) = %v, wantErr %v", c.addr, c.token, err, c.wantErr)
		}
	}
}

func TestRequireBearer(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(requireBearer(ok, "s3cret"))
	defer srv.Close()

	do := func(header string) int {
		req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	if got := do(""); got != http.StatusUnauthorized {
		t.Errorf("no header: status %d, want 401", got)
	}
	if got := do("Bearer wrong"); got != http.StatusUnauthorized {
		t.Errorf("wrong token: status %d, want 401", got)
	}
	if got := do("Bearer s3cret"); got != http.StatusNoContent {
		t.Errorf("correct token: status %d, want 204", got)
	}
}

func TestParseRunArgsSplitsOptionsAndCommand(t *testing.T) {
	opts, err := parseRunArgs(
		[]string{"--session", "8f3a2b1c", "--target", "https://api.example.test/v1/me",
			"--env", "AUTH=Bearer " + token, "--env=EXTRA=plain", "--", "curl", "-s", "https://example.test"},
		"")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.Session != "8f3a2b1c" {
		t.Fatalf("session not parsed: %q", opts.Session)
	}
	if opts.Target != "https://api.example.test/v1/me" {
		t.Fatalf("target not parsed: %q", opts.Target)
	}
	if len(opts.Envs) != 2 || opts.Envs[0] != "AUTH=Bearer "+token || opts.Envs[1] != "EXTRA=plain" {
		t.Fatalf("envs not parsed: %v", opts.Envs)
	}
	want := []string{"curl", "-s", "https://example.test"}
	if len(opts.Command) != len(want) || opts.Command[0] != want[0] || opts.Command[2] != want[2] {
		t.Fatalf("command not parsed: %v", opts.Command)
	}
}

func TestParseRunArgsTargetForms(t *testing.T) {
	for _, args := range [][]string{
		{"--target", "https://a.test/x", "--env", "A=1", "--", "true"},
		{"--target=https://a.test/x", "--env", "A=1", "--", "true"},
	} {
		opts, err := parseRunArgs(args, "")
		if err != nil {
			t.Fatalf("%v: unexpected error %v", args, err)
		}
		if opts.Target != "https://a.test/x" {
			t.Fatalf("%v: target not parsed: %q", args, opts.Target)
		}
	}
}

func TestParseRunArgsDefaultsSessionFromEnv(t *testing.T) {
	opts, err := parseRunArgs([]string{"--env", "A=p", "--", "true"}, "from-env")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.Session != "from-env" {
		t.Fatalf("expected the environment session to be used, got %q", opts.Session)
	}

	opts, err = parseRunArgs([]string{"--session=explicit", "--env", "A=p", "--", "true"}, "from-env")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.Session != "explicit" {
		t.Fatalf("explicit --session should win, got %q", opts.Session)
	}
}

func TestParseRunArgsRefusesOptionsAfterSeparator(t *testing.T) {
	// Everything after -- belongs to the command, so a stray flag is a command
	// argument; an option BEFORE -- that we do not know is a usage error.
	if _, err := parseRunArgs([]string{"--nope", "value", "--", "true"}, ""); err == nil {
		t.Fatalf("an unknown option before -- must be refused")
	} else if !strings.Contains(err.Error(), "unexpected argument") {
		t.Fatalf("error should name the offending argument, got %v", err)
	}

	opts, err := parseRunArgs([]string{"--env", "A=p", "--", "curl", "--env", "not-an-option"}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(opts.Command) != 3 {
		t.Fatalf("arguments after -- must stay untouched, got %v", opts.Command)
	}
}

func TestCheckNoTokensInCommand(t *testing.T) {
	if err := checkNoTokensInCommand([]string{"curl", "https://example.test"}); err != nil {
		t.Fatalf("an ordinary command must pass: %v", err)
	}
	err := checkNoTokensInCommand([]string{"curl", "-H", "Authorization: Bearer " + token})
	if err == nil {
		t.Fatalf("a token in argv must be refused")
	}
	if !strings.Contains(err.Error(), "argv") {
		t.Fatalf("the refusal must explain argv exposure, got %v", err)
	}
	if !strings.Contains(err.Error(), "--env") {
		t.Fatalf("the refusal must point at the safe pattern, got %v", err)
	}
}

func TestParseEnvTemplate(t *testing.T) {
	key, tpl, err := parseEnvTemplate("AUTH=Bearer " + token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != "AUTH" || tpl != "Bearer "+token {
		t.Fatalf("split wrong: %q / %q", key, tpl)
	}

	if _, _, err := parseEnvTemplate("=no-key"); err == nil {
		t.Fatalf("an empty name must be refused")
	}
	if _, _, err := parseEnvTemplate("NOEQUALS"); err == nil {
		t.Fatalf("a missing = must be refused")
	}
	if _, _, err := parseEnvTemplate("1BAD=x"); err == nil {
		t.Fatalf("a name starting with a digit must be refused")
	}
	if _, _, err := parseEnvTemplate("A=1=2"); err != nil {
		t.Fatalf("only the first = separates: %v", err)
	}
}

func TestMergeEnvReplacesStaleValues(t *testing.T) {
	got := mergeEnv([]string{"PATH=/bin", "AUTH=stale", "HOME=/root"}, []string{"AUTH=fresh"})
	if len(got) != 3 {
		t.Fatalf("expected 3 entries, got %v", got)
	}
	seen := 0
	for _, e := range got {
		if strings.HasPrefix(e, "AUTH=") {
			seen++
			if e != "AUTH=fresh" {
				t.Fatalf("override must win, got %q", e)
			}
		}
	}
	if seen != 1 {
		t.Fatalf("exactly one AUTH entry expected, got %d", seen)
	}
	if got[len(got)-1] != "AUTH=fresh" {
		t.Fatalf("overrides must come last, got %v", got)
	}
}

func TestEnvWithoutAndValidEnvName(t *testing.T) {
	got := envWithout([]string{"PATH=/bin", "KEYSMITH_SESSION=abc", "A=1"}, "KEYSMITH_SESSION")
	for _, e := range got {
		if strings.HasPrefix(e, "KEYSMITH_SESSION=") {
			t.Fatalf("KEYSMITH_SESSION must be stripped, got %v", got)
		}
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %v", got)
	}

	valid := []string{"A", "_x", "A1", "LONG_NAME_2"}
	for _, v := range valid {
		if !validEnvName(v) {
			t.Fatalf("%q should be valid", v)
		}
	}
	invalid := []string{"", "1A", "A-B", "A B", "A.B"}
	for _, v := range invalid {
		if validEnvName(v) {
			t.Fatalf("%q should be invalid", v)
		}
	}
}

func TestContainsFlag(t *testing.T) {
	if !containsFlag([]string{"get", "KEY", "--unsafe"}, "--unsafe") {
		t.Fatalf("containsFlag should find the flag")
	}
	if containsFlag([]string{"get", "KEY"}, "--unsafe") {
		t.Fatalf("containsFlag should not find an absent flag")
	}
}

func TestParseTokenArgs(t *testing.T) {
	name, ttl, b, err := parseTokenArgs([]string{
		"DB_PASSWORD",
		"--ttl", "15m",
		"--allow-host", "api.example.test",
		"--allow-host=.example.test",
		"--allow-path=/v1/",
		"--allow-header", "Authorization",
	})
	if err != nil {
		t.Fatalf("parseTokenArgs: %v", err)
	}
	if name != "DB_PASSWORD" {
		t.Fatalf("name = %q, want DB_PASSWORD", name)
	}
	if ttl != 15*time.Minute {
		t.Fatalf("ttl = %v, want 15m", ttl)
	}
	if len(b.Hosts) != 2 || b.Hosts[0] != "api.example.test" || b.Hosts[1] != ".example.test" {
		t.Fatalf("hosts = %v", b.Hosts)
	}
	if len(b.PathPrefixes) != 1 || b.PathPrefixes[0] != "/v1/" {
		t.Fatalf("paths = %v", b.PathPrefixes)
	}
	if len(b.Headers) != 1 || b.Headers[0] != "Authorization" {
		t.Fatalf("headers = %v", b.Headers)
	}
}

func TestParseTokenArgsRejectsMalformedBindings(t *testing.T) {
	cases := [][]string{
		{}, // no name
		{"KEY", "--allow-host", "api.example.test", "--allow-path"}, // dangling flag
		{"KEY", "--allow-host", "--allow-path", "/v1/"},             // flag consumed as value
		{"KEY", "--allow-host=--allow-path"},                        // same, equals form
		{"KEY", "--allow-path"},                                     // dangling path
		{"KEY", "--allow-header"},                                   // dangling header
		{"KEY", "--ttl"},                                            // dangling ttl
		{"KEY", "--ttl", "0"},                                       // non-positive ttl
		{"KEY", "--ttl", "-1h"},                                     // non-positive ttl
		{"KEY", "--allow-host="},                                    // empty value
		{"KEY", "--unknown", "x"},                                   // unknown option
		{"KEY", "extra"},                                            // stray positional
	}
	for _, args := range cases {
		if _, _, _, err := parseTokenArgs(args); err == nil {
			t.Errorf("parseTokenArgs(%v) = nil error, want refusal", args)
		}
	}
}
