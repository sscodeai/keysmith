package mcp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The value_file argument is agent-controlled. These cases are the access
// control for it: only files inside the inbox may be read (and then removed).
func TestResolveInside(t *testing.T) {
	root := t.TempDir()
	inbox := filepath.Join(root, "inbox")
	if err := os.MkdirAll(inbox, 0o700); err != nil {
		t.Fatalf("mkdir inbox: %v", err)
	}
	outsideDir := filepath.Join(root, "outside")
	if err := os.MkdirAll(outsideDir, 0o700); err != nil {
		t.Fatalf("mkdir outside: %v", err)
	}
	outsideFile := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("not-for-mcp"), 0o600); err != nil {
		t.Fatalf("write outside: %v", err)
	}
	insideFile := filepath.Join(inbox, "value.txt")
	if err := os.WriteFile(insideFile, []byte("ok"), 0o600); err != nil {
		t.Fatalf("write inside: %v", err)
	}
	link := filepath.Join(inbox, "escape.txt")
	if err := os.Symlink(outsideFile, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	t.Run("accepts a file inside the inbox", func(t *testing.T) {
		got, err := resolveInside(inbox, insideFile)
		if err != nil {
			t.Fatalf("resolveInside: %v", err)
		}
		if !strings.HasSuffix(got, "value.txt") {
			t.Errorf("resolved to %q, want the inbox file", got)
		}
	})

	refused := []struct {
		name string
		path string
	}{
		{"absolute path outside", outsideFile},
		{"relative escape", filepath.Join(inbox, "..", "outside", "secret.txt")},
		{"symlink pointing outside", link},
		{"the inbox directory itself", inbox},
		{"empty path", "   "},
	}
	for _, c := range refused {
		t.Run("refuses "+c.name, func(t *testing.T) {
			if _, err := resolveInside(inbox, c.path); err == nil {
				t.Fatalf("resolveInside(%q) = nil error, want refusal", c.path)
			}
		})
	}
}

func TestReadValueFileRemovesTheFileAfterReading(t *testing.T) {
	inbox := t.TempDir()
	path := filepath.Join(inbox, "value.txt")
	if err := os.WriteFile(path, []byte("sk-test-1234567890\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := readValueFile(inbox, path)
	if err != nil {
		t.Fatalf("readValueFile: %v", err)
	}
	if got != "sk-test-1234567890" {
		t.Errorf("got %q, want the trimmed value", got)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("value file still exists after read: %v", err)
	}
}
