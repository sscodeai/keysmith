package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestNewCreatesEncryptedFiles(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Key file exists and is 0600.
	fi, err := os.Stat(s.KeyPath())
	if err != nil {
		t.Fatalf("key file missing: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("key file perms = %o, want 600", fi.Mode().Perm())
	}
	// Data file exists and contains NO plaintext key material.
	data, err := os.ReadFile(s.DataPath())
	if err != nil {
		t.Fatalf("data file missing: %v", err)
	}
	if strings.Contains(string(data), "AGE-SECRET-KEY") {
		t.Error("data file contains secret key material — must be encrypted")
	}
}

func TestSetGet(t *testing.T) {
	s := newTestStore(t)
	if err := s.Set("API_KEY", "sk-test1234567890"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := s.Get("API_KEY")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "sk-test1234567890" {
		t.Errorf("Get = %q, want original", got)
	}
}

func TestGetNotFound(t *testing.T) {
	s := newTestStore(t)
	_, err := s.Get("nope")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Get missing = %v, want ErrNotFound", err)
	}
}

func TestListIsMasked(t *testing.T) {
	s := newTestStore(t)
	if err := s.Set("API_KEY", "sk-abcdefghij123456"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := s.Set("DEBUG", "true"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	items, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	// Secret value masked.
	if v := items["API_KEY"]; strings.Contains(v, "abcdefghij123456") {
		t.Errorf("List leaked plaintext: %q", v)
	}
	// Non-secret stays clear.
	if v := items["DEBUG"]; v != "true" {
		t.Errorf("List DEBUG = %q, want true", v)
	}
}

func TestDelete(t *testing.T) {
	s := newTestStore(t)
	if err := s.Set("TMP", "secret1"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := s.Delete("TMP"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get("TMP"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get after delete = %v, want ErrNotFound", err)
	}
	if err := s.Delete("MISSING"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Delete missing = %v, want ErrNotFound", err)
	}
}

func TestRotate(t *testing.T) {
	s := newTestStore(t)
	if err := s.Set("TOKEN", "old-value-123"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	masked, err := s.Rotate("TOKEN", 32)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	// Value changed.
	got, _ := s.Get("TOKEN")
	if got == "old-value-123" {
		t.Error("Rotate did not change value")
	}
	if len(got) != 32 {
		t.Errorf("Rotate length = %d, want 32", len(got))
	}
	if strings.Contains(masked, got[2:len(got)-2]) {
		t.Error("Rotate returned unmasked value")
	}
}

func TestPersistenceAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	s1, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s1.Set("API_KEY", "sk-persist1234567890"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	// Reopen same dir — data must survive.
	s2, err := New(dir)
	if err != nil {
		t.Fatalf("Reopen: %v", err)
	}
	got, err := s2.Get("API_KEY")
	if err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}
	if got != "sk-persist1234567890" {
		t.Errorf("persistence broken: got %q", got)
	}
}

func TestInvalidKeyRejected(t *testing.T) {
	s := newTestStore(t)
	for _, bad := range []string{"", "has space", "has=equals", "tab\there"} {
		if err := s.Set(bad, "v"); err == nil {
			t.Errorf("Set(%q) should error", bad)
		}
	}
}

func TestDataFileEncryptedNoPlaintext(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	secret := "sk-ThisIsMySuperSecretValue1234567890"
	if err := s.Set("API_KEY", secret); err != nil {
		t.Fatalf("Set: %v", err)
	}
	raw, err := os.ReadFile(s.DataPath())
	if err != nil {
		t.Fatalf("read data: %v", err)
	}
	if strings.Contains(string(raw), secret) {
		t.Fatal("secrets.enc contains plaintext — encryption broken")
	}
	if !strings.Contains(string(raw), "-----BEGIN AGE ENCRYPTED FILE-----") {
		t.Error("secrets.enc missing BEGIN armor marker")
	}
	if !strings.Contains(string(raw), "-----END AGE ENCRYPTED FILE-----") {
		t.Error("secrets.enc missing END armor marker")
	}
}

func TestStoreDirPerms(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "nested")
	if _, err := New(sub); err != nil {
		t.Fatalf("New nested: %v", err)
	}
	fi, err := os.Stat(sub)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Errorf("store dir perms = %o, want 700", fi.Mode().Perm())
	}
}
