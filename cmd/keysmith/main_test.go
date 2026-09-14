package main

import (
	"strings"
	"testing"
)

const token = "[[keysmith:v1:DEMO_KEY:8f3a2b1c]]"

func TestParseRunArgsSplitsOptionsAndCommand(t *testing.T) {
	opts, err := parseRunArgs(
		[]string{"--session", "8f3a2b1c", "--env", "AUTH=Bearer " + token, "--env=EXTRA=plain", "--", "curl", "-s", "https://example.test"},
		"")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.Session != "8f3a2b1c" {
		t.Fatalf("session not parsed: %q", opts.Session)
	}
	if len(opts.Envs) != 2 || opts.Envs[0] != "AUTH=Bearer "+token || opts.Envs[1] != "EXTRA=plain" {
		t.Fatalf("envs not parsed: %v", opts.Envs)
	}
	want := []string{"curl", "-s", "https://example.test"}
	if len(opts.Command) != len(want) || opts.Command[0] != want[0] || opts.Command[2] != want[2] {
		t.Fatalf("command not parsed: %v", opts.Command)
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

func TestFlagValueAndContainsFlag(t *testing.T) {
	if v, ok := flagValue([]string{"--ttl", "15m"}, "--ttl"); !ok || v != "15m" {
		t.Fatalf("space form failed: %q %v", v, ok)
	}
	if v, ok := flagValue([]string{"--ttl=2h"}, "--ttl"); !ok || v != "2h" {
		t.Fatalf("equals form failed: %q %v", v, ok)
	}
	if _, ok := flagValue([]string{"--other", "x"}, "--ttl"); ok {
		t.Fatalf("absent flag should not be found")
	}
	if !containsFlag([]string{"get", "KEY", "--unsafe"}, "--unsafe") {
		t.Fatalf("containsFlag should find the flag")
	}
}
