//go:build unix

package store

import (
	"os"

	"golang.org/x/sys/unix"
)

// fileLock serializes writers across processes that share a store directory
// (the MCP server and the CLI, for example). Reads do not take it: the data
// file is replaced by rename, so a reader always sees a complete blob.
type fileLock struct {
	f *os.File
}

// lockFile opens (creating if needed) path and takes an exclusive advisory
// lock, blocking until it is available.
func lockFile(path string) (*fileLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &fileLock{f: f}, nil
}

// Unlock releases the lock and closes the descriptor.
func (l *fileLock) Unlock() {
	_ = unix.Flock(int(l.f.Fd()), unix.LOCK_UN)
	_ = l.f.Close()
}
