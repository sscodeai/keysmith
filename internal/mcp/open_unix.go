//go:build unix

package mcp

import (
	"os"

	"golang.org/x/sys/unix"
)

// openNoFollow opens path for reading but refuses a symlink in the final
// component. resolveInside resolves the path first; this closes the window
// where an agent swaps the file for a symlink between that check and the open.
func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
}
