package leakscan

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sscodeai/keysmith/internal/store"
)

// setupRepo creates a throwaway git repo at dir with one commit containing a
// leaked secret.
func setupRepo(t *testing.T, dir, filename, content string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "init", "-b", "main")
	runGit(t, dir, "config", "user.name", "test")
	runGit(t, dir, "config", "user.email", "test@test")
	if err := os.WriteFile(filepath.Join(dir, filename), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "-m", "leak test")
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func TestScanDetectsLeakedSecret(t *testing.T) {
	repo := t.TempDir()
	setupRepo(t, repo, "config.env", "API_KEY=sk-REALLEAKED1234567890\n")

	results, err := ScanGitHistory(repo, nil, false)
	if err != nil {
		t.Fatalf("ScanGitHistory: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected at least 1 leak result")
	}
	found := false
	for _, r := range results {
		if strings.Contains(r.Location, "sk-REALLEAKED") {
			found = true
		}
	}
	if !found {
		t.Errorf("did not find the leaked value in results: %+v", results)
	}
}

func TestScanExactValueAndAutoRotate(t *testing.T) {
	// Create a store with a known secret.
	storeDir := t.TempDir()
	st, err := store.New(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	secret := "sk-DEPLOYED-KEY-1234567890abcdef"
	if err := st.Set("DEPLOY_KEY", secret); err != nil {
		t.Fatal(err)
	}
	oldVal, _ := st.Get("DEPLOY_KEY")

	// Repo leaks that exact value.
	repo := t.TempDir()
	setupRepo(t, repo, "app.env", "deploy_key="+secret+"\n")

	// Scan WITHOUT rotate: flag only, value unchanged.
	results, err := ScanGitHistory(repo, st, false)
	if err != nil {
		t.Fatal(err)
	}
	matched := false
	for _, r := range results {
		if r.Key == "DEPLOY_KEY" && r.Pattern == "exact-value" {
			matched = true
			if r.Rotated {
				t.Error("should not rotate when autoRotate=false")
			}
		}
	}
	if !matched {
		t.Error("expected exact-value match on DEPLOY_KEY")
	}
	got, _ := st.Get("DEPLOY_KEY")
	if got != oldVal {
		t.Error("value changed despite autoRotate=false")
	}

	// Scan WITH rotate: value must change (self-healing).
	results, err = ScanGitHistory(repo, st, true)
	if err != nil {
		t.Fatal(err)
	}
	rotated := false
	for _, r := range results {
		if r.Key == "DEPLOY_KEY" && r.Rotated {
			rotated = true
		}
	}
	if !rotated {
		t.Error("expected auto-rotation on exact-value leak")
	}
	got, _ = st.Get("DEPLOY_KEY")
	if got == oldVal {
		t.Error("value did not change after auto-rotate")
	}
	if len(got) < 16 {
		t.Errorf("rotated value too short: %d", len(got))
	}
}

func TestIsSecretPatternSkipsComments(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{"// sk- prefix in docs", false},
		{"# comment with ghp_", false},
		{"API_KEY=sk-REAL1234567890", true},
		{"deploy_key: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIx", true},
		{"known value prefixes (sk-, ghp_)", false},
	}
	for _, c := range cases {
		if got := isSecretPattern(c.line); got != c.want {
			t.Errorf("isSecretPattern(%q) = %v, want %v", c.line, got, c.want)
		}
	}
}
