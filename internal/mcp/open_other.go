//go:build !unix

package mcp

import "os"

// openNoFollow has no O_NOFOLLOW equivalent on this platform; resolveInside
// still performs the path check, but the final-component race is not closed.
func openNoFollow(path string) (*os.File, error) {
	return os.Open(path)
}
