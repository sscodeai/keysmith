//go:build !unix

package store

import "os"

// fileLock is a best-effort lock on platforms without flock. Writers are
// serialized only within one process; concurrent writers from different
// processes are not protected, so run a single writer on these platforms.
type fileLock struct {
	f *os.File
}

func lockFile(path string) (*fileLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	return &fileLock{f: f}, nil
}

// Unlock closes the descriptor.
func (l *fileLock) Unlock() {
	_ = l.f.Close()
}
