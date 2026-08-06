// Package ui renders the toha3ee console: an ANSI-styled, bettercap-inspired
// output layer restricted to the framework's black/red/white palette. It
// builds the banner, colored sections, aligned tables and status glyphs used
// by the REPL, the wizard and the one-shot commands. When output is not a
// terminal (pipes, caplet logs, CI) every renderer falls back to plain text.
package ui

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"
)

// ANSI style codes for the black/red/white palette.
const (
	Reset   = "\x1b[0m"
	Bold    = "\x1b[1m"
	Dim     = "\x1b[2m"
	Red     = "\x1b[31m"
	White   = "\x1b[37m"
	OnBlack = "\x1b[40m"
	OnRed   = "\x1b[41m"
	OnWhite = "\x1b[107m"
)

// UI renders styled output to one writer. Colors are enabled only when the
// writer is a terminal and NO_COLOR is not set.
type UI struct {
	w     io.Writer
	color bool
}

// New returns a UI writing to w, with color auto-detected from the terminal.
func New(w io.Writer) *UI {
	u := &UI{w: w}
	if os.Getenv("NO_COLOR") == "" {
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

func (u *UI) paint(s, code string) string {
	if !u.color || s == "" {
		return s
	}
	return code + s + Reset
}

// Red paints a string red (framework "warning/error" color).
func (u *UI) Red(s string) string { return u.paint(s, Red) }

// White paints a string plain white (framework "information" color).
func (u *UI) White(s string) string { return u.paint(s, White) }

// BoldWhite paints a string bold white (framework "heading" color).
func (u *UI) BoldWhite(s string) string { return u.paint(s, Bold+White) }

// DimWhite paints a string dim white (framework "muted" color).
func (u *UI) DimWhite(s string) string { return u.paint(s, Dim+White) }

// Black paints a string black (on the default terminal background).
func (u *UI) Black(s string) string { return u.paint(s, "\x1b[30m") }

const sectionWidth = 60

// Section prints a centered title on a horizontal rule, e.g. "── hosts ──".
func (u *UI) Section(title string) {
	label := strings.TrimSpace(title)
	if label == "" {
		fmt.Fprintln(u.w, u.DimWhite(strings.Repeat("─", sectionWidth)))
		return
	}
	left := (sectionWidth - runeLen(label) - 2) / 2
	if left < 1 {
		left = 1
	}
	rule := strings.Repeat("─", left)
	fmt.Fprintf(u.w, "\n%s %s %s\n", u.DimWhite(rule), u.BoldWhite(label), u.DimWhite(rule))
}

// Rule prints a full-width dim rule.
func (u *UI) Rule() {
	fmt.Fprintln(u.w, u.DimWhite(strings.Repeat("─", sectionWidth)))
}

// Clear clears the terminal screen (a no-op when output is not a terminal,
// e.g. caplets or eval mode piping to a file).
func (u *UI) Clear() {
	if isTerminal(u.w) {
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
//	[+] good / info (bold white)
//	[*] running / notice (white)
//	[!] warning / error (bold red)
//	[>] system (bold white)
//	[-] neutral (dim white)
func (u *UI) Status(glyph, format string, args ...any) {
	sym := "  " + glyph
	switch glyph {
	case "+", ">":
		sym = u.paint("[+]", Bold+White)
	case "*":
		sym = u.paint("[*]", White)
	case "!":
		sym = u.paint("[!]", Bold+Red)
	case "-":
		sym = u.paint("[-]", Dim+White)
	default:
		sym = u.paint("["+glyph+"]", White)
	}
	fmt.Fprintf(u.w, "%s %s\n", sym, u.White(fmt.Sprintf(format, args...)))
}

// Table prints a header, an underline rule and aligned rows. Header cells are
// bold white, rows plain white and the separator dim white.
func (u *UI) Table(headers []string, rows [][]string) {
	if len(headers) == 0 {
		return
	}
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

	var b strings.Builder
	for i, h := range headers {
		if i > 0 {
			b.WriteString("  ")
		}
		b.WriteString(padTo(u.BoldWhite(h), widths[i]))
	}
	fmt.Fprintln(u.w, b.String())

	var sep strings.Builder
	for i, wdt := range widths {
		if i > 0 {
			sep.WriteString("  ")
		}
		sep.WriteString(strings.Repeat("─", wdt))
	}
	fmt.Fprintln(u.w, u.DimWhite(sep.String()))

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

// Banner prints the console banner (figlet "small" font, uppercase ASCII).
func (u *UI) Banner(tagline string) {
	art := []string{
		" _       _         ____",
		"| |_ ___| |_  __ _|__ / ___ ___",
		"|  _/ _ \\ ' \\/ _` ||_ \\/ -_) -_)",
		" \\__\\___/_||_\\__,_|___/\\___\\___|",
	}
	for _, line := range art {
		fmt.Fprintln(u.w, u.White(line))
	}
	fmt.Fprintln(u.w)
	fmt.Fprintln(u.w, u.BoldWhite(strings.TrimSpace(tagline)))
	fmt.Fprintln(u.w)
}

// BannerFoot prints the interface/version footer under the banner.
func (u *UI) BannerFoot(iface, version string) {
	if iface != "" {
		fmt.Fprintf(u.w, "  %s %s\n", u.Red("iface"), u.White(iface))
	}
	fmt.Fprintf(u.w, "  %s %s\n", u.Red("v"), u.White(version))
	fmt.Fprintln(u.w, u.DimWhite("type 'help' for commands, 'modules' for the catalogue, 'quit' to exit"))
	fmt.Fprintln(u.w)
}

// width reports the visible rune count of a string (ANSI codes ignored).
func (u *UI) width(s string) int { return runeLen(s) }

// runeLen counts runes, stripping ANSI escape sequences first.
func runeLen(s string) int {
	if !strings.Contains(s, "\x1b") {
		return utf8.RuneCountInString(s)
	}
	return utf8.RuneCountInString(stripANSI(s))
}

// stripANSI removes ANSI escape sequences from s.
func stripANSI(s string) string {
	var out strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '\x1b' {
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
// visible width of n runes.
func padTo(s string, n int) string {
	pad := n - runeLen(s)
	if pad <= 0 {
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

type lineWriter struct {
	w  io.Writer
	ui *UI
}

func (lw *lineWriter) Write(p []byte) (int, error) {
	lines := bytes.Split(p, []byte{'\n'})
	for i, line := range lines {
		if i > 0 {
			if _, err := lw.w.Write([]byte{'\n'}); err != nil {
				return 0, err
			}
		}
		if len(line) == 0 {
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
	if end <= 0 || end > 24 {
		return line
	}
	tok := string(line[1:end])
	switch tok {
	case "*":
		tok = u.paint("*", White)
	case "+":
		tok = u.paint("+", Bold+White)
	case "!":
		tok = u.paint("!", Bold+Red)
	case ">":
		tok = u.paint(">", Bold+White)
	case "-":
		tok = u.paint("-", Dim+White)
	case "~":
		tok = u.paint("~", White)
	case "OK":
		tok = u.paint("OK", Bold+White)
	case "FIX":
		tok = u.paint("FIX", Bold+White)
	case "BLK":
		tok = u.paint("BLK", Bold+Red)
	default:
		tok = u.paint(tok, Bold+White)
	}
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
	return fi.Mode()&os.ModeCharDevice != 0
}
