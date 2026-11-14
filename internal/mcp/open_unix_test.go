//go:build unix

package mcp

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenNoFollowRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	f, err := openNoFollow(link)
	if err == nil {
		_ = f.Close()
		t.Fatal("openNoFollow accepted a symlink in the final component")
	}
}
