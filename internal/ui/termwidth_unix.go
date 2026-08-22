//go:build !windows

package ui

import (
	"os"

	"golang.org/x/sys/unix"
)

// termWidth reports the live column count of the terminal attached to f, or
// zero when the ioctl fails (not a tty, or geometry denied) so callers fall
// back to their default width.
func termWidth(f *os.File) int {
	ws, err := unix.IoctlGetWinsize(int(f.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		return 0
	}
	return int(ws.Col)
}
