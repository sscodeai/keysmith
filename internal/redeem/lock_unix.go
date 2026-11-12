//go:build unix

package redeem

import (
	"os"

	"golang.org/x/sys/unix"
)

// fileLock serializes session issuance across processes that share a store
// directory. Reads do not take it: session files are replaced by rename.
type fileLock struct {
	f *os.File
}

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

func (l *fileLock) Unlock() {
	_ = unix.Flock(int(l.f.Fd()), unix.LOCK_UN)
	_ = l.f.Close()
}
