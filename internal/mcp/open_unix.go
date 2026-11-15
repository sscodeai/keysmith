//go:build unix

package mcp

import (
	"os"

	"golang.org/x/sys/unix"
)

// openNoFollow opens path for reading but refuses a symlink in the final
// component. resolveInside resolves the path first; this closes the window
// where an agent swaps the file for a symlink between that check and the open.
//
// O_NONBLOCK matters for FIFOs: opening a FIFO read-only without it blocks
// until a writer appears, which an agent could use to hang the MCP server.
// Non-regular files are rejected by the caller's f.Stat check.
func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
}
