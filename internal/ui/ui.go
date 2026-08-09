// Package ui renders the toha3ee console: an ANSI-styled, bettercap-inspired
// output layer. It builds the banner, fixed-width sections, aligned tables and
// status glyphs used by the REPL, the wizard and the one-shot commands. When
// output is not a terminal (pipes, caplet logs, CI) every renderer falls back
// to plain text.
//
// Glyph colouring is deliberate: green for success, amber for warnings, red
// reserved for hard errors, and white/dim for information. Horizontal rules
// are used sparingly and always span the full section width so the console
// stays clean and aligned.
package ui

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// ANSI style codes. Red is reserved for hard errors; warnings use Amber and
// successes use Green.
const (
	Reset   = "\x1b[0m"
	Bold    = "\x1b[1m"
	Dim     = "\x1b[2m"
	Red     = "\x1b[31m"
	Green   = "\x1b[32m"
	Amber   = "\x1b[33m"
	White   = "\x1b[37m"
	OnBlack = "\x1b[40m"
	OnRed   = "\x1b[41m"
	OnWhite = "\x1b[107m"
)

// sectionWidth is the fixed visible width of every section rule.
const sectionWidth = 60

// UI renders styled output to one writer. Colors are enabled only when the
// writer is a terminal and NO_COLOR is not set.
type UI struct {
	// w is the destination all formatted output is written to.
	w io.Writer
	// color toggles ANSI emission; false forces plain text.
	color bool
}

// New returns a UI writing to w, with color auto-detected from the terminal.
func New(w io.Writer) *UI {
	u := &UI{w: w}
	if os.Getenv("NO_COLOR") == "" {
		// Honor the NO_COLOR convention (https://no-color.org): when unset,
		// auto-detect whether the writer is a real terminal.
		u.color = isTerminal(w)
	}
	return u
}

// NewFile returns a UI for a plain *os.File (auto-detects a terminal).
func NewFile(f *os.File) *UI { return New(f) }

// Writer returns the underlying writer the UI renders to.
func (u *UI) Writer() io.Writer { return u.w }

// SetColor forces colors on or off regardless of terminal detection.
func (u *UI) SetColor(on bool) { u.color = on }

// Enabled reports whether colors are currently active.
func (u *UI) Enabled() bool { return u.color }

// paint wraps s in code/Reset when colors are active; empty strings stay
// untouched so padding calculations never see invisible ANSI bytes.
func (u *UI) paint(s, code string) string {
	if !u.color || s == "" {
		return s
	}
	return code + s + Reset
}

// Red paints a string red (reserved for hard errors).
func (u *UI) Red(s string) string { return u.paint(s, Red) }

// Green paints a string green (success).
func (u *UI) Green(s string) string { return u.paint(s, Green) }

// Amber paints a string amber (warning).
func (u *UI) Amber(s string) string { return u.paint(s, Amber) }

// RiskLevel paints a risk label: critical is red, high is amber, and the
// remaining levels stay plain white. Red is used sparingly, so it is reserved
// for the most disruptive classification only.
func (u *UI) RiskLevel(name string) string {
	switch strings.ToLower(name) {
	case "critical":
		return u.Red(name)
	case "high":
		return u.Amber(name)
	default:
		return u.White(name)
	}
}

// White paints a string plain white (information).
func (u *UI) White(s string) string { return u.paint(s, White) }

// BoldWhite paints a string bold white (headings).
func (u *UI) BoldWhite(s string) string { return u.paint(s, Bold+White) }

// DimWhite paints a string dim white (muted).
func (u *UI) DimWhite(s string) string { return u.paint(s, Dim+White) }

// Black paints a string black (on the default terminal background).
func (u *UI) Black(s string) string { return u.paint(s, "\x1b[30m") }

// Section prints a fixed-width horizontal rule carrying the title, e.g.
// "──────────────────────── hosts ─────────────────────────". Every section
// line is exactly sectionWidth visible columns wide regardless of the title,
// so rules always line up. A blank line separates sections from prior output.
func (u *UI) Section(title string) {
	label := strings.TrimSpace(title)
	if label == "" {
		// No title: print a bare rule instead of a malformed section.
		u.Rule()
		return
	}
	// inner is the dash space available after reserving the title and its
	// two surrounding spaces.
	inner := sectionWidth - runeLen(label) - 2
	if inner < 2 {
		// Very long titles: keep at least a dash on each side so the rule
		// still reads as a section boundary.
		inner = 2
	}
	// Split the dash budget so an odd total leaves the extra on the right,
	// which reads more naturally for LTR text.
	left := inner / 2
	right := inner - left
	line := strings.Repeat("─", left) + " " + label + " " + strings.Repeat("─", right)
	fmt.Fprintf(u.w, "\n%s\n", u.DimWhite(line))
}

// Rule prints a full-width dim rule. Use it sparingly; Section is preferred.
func (u *UI) Rule() {
	fmt.Fprintln(u.w, u.DimWhite(strings.Repeat("─", sectionWidth)))
}

// Clear clears the terminal screen (a no-op when output is not a terminal,
// e.g. caplets or eval mode piping to a file).
func (u *UI) Clear() {
	if isTerminal(u.w) {
		// ANSI "erase display then move cursor home"; only meaningful on a
		// live terminal.
		fmt.Fprint(u.w, "\x1b[2J\x1b[H")
	}
}

// KV prints a "  key: value" pair with the key emphasized.
func (u *UI) KV(key, value string) {
	fmt.Fprintf(u.w, "  %s %s\n", u.BoldWhite(key+":"), u.White(value))
}

// KVf is KV with a formatted value.
func (u *UI) KVf(key, format string, args ...any) {
	u.KV(key, fmt.Sprintf(format, args...))
}

// Status prints a bettercap-style status line with a colored glyph:
//
//	[+] success (green)
//	[*] info / running (white)
//	[!] warning (amber; hard errors stay red)
//	[x] hard error (red)
//	[>] system (bold white)
//	[-] neutral (dim white)
func (u *UI) Status(glyph, format string, args ...any) {
	sym := u.Glyph(glyph)
	fmt.Fprintf(u.w, "  %s %s\n", sym, u.White(fmt.Sprintf(format, args...)))
}

// Err prints a hard-error line with a red [x] glyph. It is the console's one
// red emphasis: warnings use [!], only failures and the prompt accent use red.
func (u *UI) Err(format string, args ...any) {
	fmt.Fprintf(u.w, "  %s %s\n", u.paint("[x]", Bold+Red), u.Red(fmt.Sprintf(format, args...)))
}

// Prompt builds the interactive prompt with the framework name in bold red
// (the deliberate accent color) and a bold white chevron.
func (u *UI) Prompt(name string) string {
	return u.paint(name, Bold+Red) + u.paint(" > ", Bold+White)
}

// Glyph returns a colored "[x]" token for a status glyph character.
func (u *UI) Glyph(glyph string) string {
	switch glyph {
	case "+":
		return u.paint("[+]", Green)
	case "*":
		return u.paint("[*]", White)
	case "!":
		return u.paint("[!]", Amber)
	case "x", "X":
		return u.paint("[x]", Bold+Red)
	case ">":
		return u.paint("[>]", Bold+White)
	case "-":
		return u.paint("[-]", Dim+White)
	default:
		// Unknown glyphs are still bracketed so output stays column-aligned.
		return u.paint("["+glyph+"]", White)
	}
}

// HUD prints a single-line status bar with a red edge block, left and right
// sections, and space padding between them so the bar spans the terminal
// width. It is the persistent status strip shown above the prompt.
func (u *UI) HUD(left, right string) {
	cols := 80
	if w := u.TermWidth(); w > 20 {
		// Use the live terminal width when it is usable; the 20-column floor
		// guards against degenerate winsize reports.
		cols = w
	}
	// Padding bridges the gap so left and right sections are visually
	// separated; the -1 accounts for the leading "▮ " block.
	pad := cols - runeLen(left) - runeLen(right) - 1
	if pad < 1 {
		pad = 1
	}
	fmt.Fprintf(u.w, "%s %s%s\n", u.paint("▮", Bold+Red), left, strings.Repeat(" ", pad)+right)
}

// TermWidth reports the terminal column count, or 0 when the writer is not an
// interactive terminal.
func (u *UI) TermWidth() int {
	f, ok := u.w.(*os.File)
	if !ok {
		// Only real files can carry a terminal geometry.
		return 0
	}
	ws, err := unix.IoctlGetWinsize(int(f.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		// Not a tty (or ioctl denied): report zero so callers fall back.
		return 0
	}
	return int(ws.Col)
}

// Table prints a header and aligned rows. Header cells are bold white and
// rows plain white; columns are padded to their widest visible cell using the
// display width (ANSI codes and wide characters are accounted for). Tables
// carry no horizontal rules of their own — the section header above is the
// structural line.
func (u *UI) Table(headers []string, rows [][]string) {
	if len(headers) == 0 {
		return
	}
	// Pass 1: compute each column's width as the widest visible cell, which
	// guarantees alignment even when rows are ragged or contain ANSI codes.
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = runeLen(h)
	}
	for _, r := range rows {
		for i := 0; i < len(headers) && i < len(r); i++ {
			if l := runeLen(r[i]); l > widths[i] {
				widths[i] = l
			}
		}
	}

	// Header row, printed before any data rows.
	var b strings.Builder
	for i, h := range headers {
		if i > 0 {
			b.WriteString("  ")
		}
		b.WriteString(padTo(u.BoldWhite(h), widths[i]))
	}
	fmt.Fprintln(u.w, b.String())

	// Data rows: missing cells render as empty, keeping columns aligned.
	for _, r := range rows {
		var rb strings.Builder
		for i := 0; i < len(headers); i++ {
			if i > 0 {
				rb.WriteString("  ")
			}
			var cell string
			if i < len(r) {
				cell = r[i]
			}
			rb.WriteString(padTo(u.White(cell), widths[i]))
		}
		fmt.Fprintln(u.w, rb.String())
	}
}

// Banner prints the console banner art followed by the tagline.
func (u *UI) Banner(tagline string) {
	for _, line := range bannerArt {
		fmt.Fprintln(u.w, u.White(line))
	}
	fmt.Fprintln(u.w)
	fmt.Fprintln(u.w, u.BoldWhite(strings.TrimSpace(tagline)))
	fmt.Fprintln(u.w)
}

// BannerFoot prints the interface/version footer under the banner.
func (u *UI) BannerFoot(iface, version string) {
	if iface != "" {
		u.Status(">", "iface %s", iface)
	}
	u.Status(">", "v %s", version)
	fmt.Fprintln(u.w, u.DimWhite("type 'help' for commands, 'modules' for the catalogue, 'quit' to exit"))
	fmt.Fprintln(u.w)
}

// width reports the visible width of a string (ANSI codes ignored).
func (u *UI) width(s string) int { return runeLen(s) }

// runeLen counts the display width of s, stripping ANSI escape sequences
// first and counting wide (CJK/emoji) characters as two columns.
func runeLen(s string) int {
	if strings.Contains(s, "\x1b") {
		// Painted strings carry ANSI bytes that would corrupt width math.
		s = stripANSI(s)
	}
	n := 0
	for _, r := range s {
		if isWide(r) {
			n += 2
		} else {
			n++
		}
	}
	return n
}

// isWide reports whether r occupies two terminal columns (East Asian width).
// The ranges mirror the Unicode EastAsianWidth property used by wcwidth.
func isWide(r rune) bool {
	switch {
	case r >= 0x1100 && r <= 0x115F, // Hangul Jamo
		r >= 0x2329 && r <= 0x232A,   // angle brackets
		r >= 0x2E80 && r <= 0xA4CF,   // CJK radicals, Kanji, Hangul
		r >= 0xAC00 && r <= 0xD7A3,   // Hangul syllables
		r >= 0xF900 && r <= 0xFAFF,   // CJK compatibility ideographs
		r >= 0xFE10 && r <= 0xFE19,   // vertical forms
		r >= 0xFE30 && r <= 0xFE6F,   // CJK compatibility forms
		r >= 0xFF00 && r <= 0xFF60,   // fullwidth forms
		r >= 0xFFE0 && r <= 0xFFE6,   // fullwidth signs
		r >= 0x1F300 && r <= 0x1F64F, // emoji and pictographs
		r >= 0x1F900 && r <= 0x1F9FF: // supplemental symbols
		return true
	}
	return false
}

// stripANSI removes ANSI escape sequences from s.
func stripANSI(s string) string {
	var out strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '\x1b' {
			// Consume everything up to and including the terminating 'm',
			// which ends a CSI SGR sequence like "\x1b[31m".
			j := i + 1
			for j < len(s) && s[j] != 'm' {
				j++
			}
			if j < len(s) {
				j++ // skip the terminating 'm'
			}
			i = j
			continue
		}
		out.WriteByte(s[i])
		i++
	}
	return out.String()
}

// padTo pads s (which may contain ANSI codes) with trailing spaces to a
// visible width of n columns.
func padTo(s string, n int) string {
	pad := n - runeLen(s)
	if pad <= 0 {
		// Already at or past the target width; adding spaces would break
		// alignment rather than fix it.
		return s
	}
	return s + strings.Repeat(" ", pad)
}

// NewLineWriter wraps w and recolors bettercap-style "[sym]" / "[module.id]"
// prefixes at the start of every output line. Modules write through this
// writer via AttackCtx.Out, so every module gets consistent color with no
// per-module changes. It passes color off when the wrapped UI is disabled.
func NewLineWriter(u *UI) io.Writer {
	return &lineWriter{w: u.w, ui: u}
}

// lineWriter is the concrete writer that splits input on newlines and
// colorizes each line's leading "[token]" prefix.
type lineWriter struct {
	w  io.Writer // destination for the recolored output
	ui *UI       // provides palette and the color-enabled flag
}

// Write recolors the prefix of every line in p, preserving the original
// byte count so callers (fmt writers) see a correct short-write accounting.
func (lw *lineWriter) Write(p []byte) (int, error) {
	lines := bytes.Split(p, []byte{'\n'})
	for i, line := range lines {
		if i > 0 {
			// Re-emit the newline that bytes.Split removed between lines.
			if _, err := lw.w.Write([]byte{'\n'}); err != nil {
				return 0, err
			}
		}
		if len(line) == 0 {
			// Empty lines (including a trailing newline) need no prefix.
			continue
		}
		out := recolorPrefix(line, lw.ui)
		if _, err := lw.w.Write(out); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// recolorPrefix colorizes the leading "[sym]" / "[module.id]" token on a
// single output line, leaving the rest untouched.
func recolorPrefix(line []byte, u *UI) []byte {
	if !u.Enabled() || len(line) == 0 || line[0] != '[' {
		return line
	}
	end := bytes.IndexByte(line, ']')
	// Require a sane token length: "[module.id]" style prefixes are short;
	// a long "token" is unlikely to be a prefix and is left as-is.
	if end <= 0 || end > 24 {
		return line
	}
	tok := string(line[1:end])
	switch tok {
	case "*":
		tok = u.paint("*", White)
	case "+":
		tok = u.paint("+", Green)
	case "!":
		tok = u.paint("!", Amber)
	case ">":
		tok = u.paint(">", Bold+White)
	case "-":
		tok = u.paint("-", Dim+White)
	case "~":
		tok = u.paint("~", White)
	case "x", "X":
		tok = u.paint("x", Bold+Red)
	case "OK":
		tok = u.paint("OK", Green)
	case "FIX":
		tok = u.paint("FIX", Amber)
	case "BLK":
		tok = u.paint("BLK", Amber)
	default:
		// Unknown tokens (e.g. module ids) are emphasized bold white, which
		// visually separates them from plain prose.
		tok = u.paint(tok, Bold+White)
	}
	// Reassemble "[painted-token]" + the rest of the line, sizing the buffer
	// for the added ANSI bytes to avoid regrowth.
	out := make([]byte, 0, len(line)+32)
	out = append(out, '[')
	out = append(out, tok...)
	out = append(out, ']')
	out = append(out, line[end+1:]...)
	return out
}

// isTerminal reports whether w is an interactive character device.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	// /dev/tty, ptys and the console are character devices; regular files and
	// pipes are not.
	return fi.Mode()&os.ModeCharDevice != 0
}

// bannerArt is the framework banner (ASCII art). Kept as its own file so it
// can be regenerated independently of the renderer.
var bannerArt = []string{
	"                         @                           ",
	"                         @                         ",
	"           @           @@ @@    @@@@@@@@@@              ",
	"            @@        @     @@@@@@@@@@@@@@@@@@             ",
	"             @@@   @@@@@@@  @@@@@@@@@@@@@@@@@@@@@@            ",
	"              @@@@@   @    @@@@@@@@@@@@@@@@@@@@@@@            ",
	"               @@@@@@  @   @@@@@@@@@@@@@@@@@@ @@@             ",
	"               @@@@@@   @ @@@@@@@@@@@@@@@@@   @@@            ",
	"                @@@@@@    @@@@@@@@@@@@@@@     @@@              ",
	"                   @@@@@  @@@@@@@@@@@@@@@    @@@             ",
	"                    @@@@@  @@@@@@@@@@@@@@   @@@               ",
	"                      @@@    @@@@@@@@@@@@@ @@@@               ",
	"                    @@  @@@@  @@@@@   @@@@@@@@@               ",
	"                  @@@@@@@@@@@@@  @@@@@@    @@@                 ",
	"              @@@@@@@@@@@@@@@@@@@  @@@@@@@   @@@               ",
	"             @@@@@@@@@@@@@@@@@@@@@@@     @@@ @@@@@@            ",
	"           @@@@@@@@@@@@@@@@@@@@@@   @@@   @@@@@@@@@@          ",
	"           @@@@@@@@@@@@@@@@@@@@@@@@@@@@@   @@@@@@@@@          ",
	"          @@@@@@@@@@@@@@@@@@   @@@@@@@@@@@@ @@@@@@@@@         ",
	"         @@@@@@@@@@@@@@@    @@@@@@@@@@@@@  @@@@@@@@@@@        ",
	"          @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  @@@@@@@@@@@   ",
}
