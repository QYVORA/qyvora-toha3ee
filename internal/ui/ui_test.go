package ui

import (
	"strings"
	"testing"
)

func TestStripANSI(t *testing.T) {
	in := "\x1b[1m\x1b[37mbold\x1b[0m"
	if got := stripANSI(in); got != "bold" {
		t.Fatalf("stripANSI(%q) = %q, want %q", in, got, "bold")
	}
}

func TestRuneLenIgnoresANSI(t *testing.T) {
	if got := runeLen("\x1b[1mtoha3ee\x1b[0m"); got != 7 {
		t.Fatalf("runeLen with ANSI = %d, want 7", got)
	}
}

func TestTableAlignmentWithColor(t *testing.T) {
	var sb strings.Builder
	u := New(&sb)
	u.SetColor(true)
	u.Table([]string{"id", "desc"}, [][]string{{"net.scan", "x"}, {"arp.spoof", "longer"}})

	lines := strings.Split(strings.TrimRight(sb.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("table produced %d lines, want 3 (no header rule):\n%s", len(lines), sb.String())
	}
	// Column widths are driven by the widest visible cell: 9 ("arp.spoof")
	// and 6 ("longer"). Assert the exact rendered rows so alignment is pinned.
	want := []string{
		"id         desc  ",
		"net.scan   x     ",
		"arp.spoof  longer",
	}
	for i, line := range lines {
		if got := stripANSI(line); got != want[i] {
			t.Fatalf("line %d = %q, want %q", i, got, want[i])
		}
	}
}

func TestSectionConstantWidth(t *testing.T) {
	var sb strings.Builder
	u := New(&sb)
	u.SetColor(true)
	u.Section("hosts")
	u.Section("ranked attack vectors")
	lines := strings.Split(strings.TrimRight(sb.String(), "\n"), "\n")
	n := 0
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if l := runeLen(line); l != sectionWidth {
			t.Fatalf("section line %d width = %d, want %d: %q", n, l, sectionWidth, line)
		}
		n++
	}
	if n != 2 {
		t.Fatalf("expected 2 section lines, got %d", n)
	}
}

func TestRuneLenWideCharacters(t *testing.T) {
	if got := runeLen("主机"); got != 4 {
		t.Fatalf("runeLen of CJK = %d, want 4 (2 wide chars)", got)
	}
	if got := runeLen("ab"); got != 2 {
		t.Fatalf("runeLen of ascii = %d, want 2", got)
	}
}

func TestRecolorPrefix(t *testing.T) {
	u := New(&strings.Builder{})
	u.SetColor(true)

	cases := map[string]string{
		"[*] running":       White + "*" + Reset,
		"[!] error":         Amber + "!" + Reset,
		"[+] done":          Green + "+" + Reset,
		"[arp.spoof] spoof": Bold + White + "arp.spoof" + Reset,
		"no prefix line":    "",
	}
	for in, want := range cases {
		got := string(recolorPrefix([]byte(in), u))
		if want == "" {
			if got != in {
				t.Fatalf("recolorPrefix(%q) = %q, want untouched", in, got)
			}
			continue
		}
		if !strings.Contains(got, want) {
			t.Fatalf("recolorPrefix(%q) = %q, missing %q", in, got, want)
		}
	}
}

func TestLineWriterColorizesEachLine(t *testing.T) {
	var sb strings.Builder
	u := New(&sb)
	u.SetColor(true)
	lw := NewLineWriter(u)

	if _, err := lw.Write([]byte("[*] first\n[!] second\nplain")); err != nil {
		t.Fatal(err)
	}
	out := sb.String()
	if !strings.Contains(out, White+"*"+Reset) {
		t.Fatalf("first line not colorized: %q", out)
	}
	if !strings.Contains(out, Amber+"!"+Reset) {
		t.Fatalf("second line not colorized: %q", out)
	}
	if !strings.Contains(out, "plain") {
		t.Fatalf("plain line lost: %q", out)
	}
}

func TestLineWriterNoColorPassthrough(t *testing.T) {
	var sb strings.Builder
	u := New(&sb)
	u.SetColor(false)
	lw := NewLineWriter(u)

	if _, err := lw.Write([]byte("[*] first\n[!] second")); err != nil {
		t.Fatal(err)
	}
	if got := sb.String(); got != "[*] first\n[!] second" {
		t.Fatalf("no-color passthrough mangled output: %q", got)
	}
}
