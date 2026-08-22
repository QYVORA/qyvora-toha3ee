//go:build windows

package ui

import "os"

// termWidth reports the live column count of the terminal attached to f.
// Windows consoles are not queried; a zero width makes renderers fall back to
// their default width, matching the non-tty behaviour on other platforms.
func termWidth(f *os.File) int {
	return 0
}
