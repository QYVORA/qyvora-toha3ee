package session

import (
	"bytes"
	"strings"
	"testing"
)

func newTestSession(t *testing.T) (*Session, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	s := New(nil, &buf, nil)
	return s, &buf
}

func TestShellKind(t *testing.T) {
	s, _ := newTestSession(t)
	cases := []struct {
		line string
		want string
	}{
		{"!ls -l", "shell"},
		{"!pwd", "shell"},
		{"shell", "interactive"},
		{"shell uname -a", "shell"},
		{"cd /tmp", "shell"},
		{"cd", "shell"},
		{"pwd", "shell"},
		{"help", ""},
		{"net.scan", ""},
		{"set arp.spoof.targets 10.0.0.5", ""},
	}
	for _, tc := range cases {
		if got := s.shellKind(tc.line); got != tc.want {
			t.Errorf("shellKind(%q) = %q, want %q", tc.line, got, tc.want)
		}
	}
}

func TestChangeDir(t *testing.T) {
	s, _ := newTestSession(t)

	dir := t.TempDir()
	if _, err := s.exec(nil, "cd "+dir); err != nil {
		t.Fatalf("cd %s: %v", dir, err)
	}
	if s.cwd != dir {
		t.Errorf("cwd = %q, want %q", s.cwd, dir)
	}

	if _, err := s.exec(nil, "cd /nonexistent-dir-xyz"); err == nil {
		t.Error("cd /nonexistent-dir-xyz: expected error")
	}
	if s.cwd != dir {
		t.Errorf("cwd after failed cd = %q, want unchanged %q", s.cwd, dir)
	}

	if _, err := s.exec(nil, "pwd"); err != nil {
		t.Fatalf("pwd: %v", err)
	}
	if !strings.Contains(s.Out.(*bytes.Buffer).String(), dir) {
		t.Errorf("pwd output missing %q: %q", dir, s.Out.(*bytes.Buffer).String())
	}
}

func TestShellBangUnknown(t *testing.T) {
	s, _ := newTestSession(t)
	_, err := s.exec(nil, "!definitely_not_a_command_xyz")
	if err == nil || !strings.Contains(err.Error(), "command not found") {
		t.Errorf("expected command not found, got %v", err)
	}
}
