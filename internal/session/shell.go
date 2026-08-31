package session

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/chzyer/readline"
)

// shellKind classifies a console line as a host-shell invocation. It returns
// "interactive" for lines that drop into a live interactive shell, "shell"
// for one-shot host commands, and "" for anything else.
//
// The console ships with a deliberate shell escape hatch, exactly like
// Metasploit's `shell` and bettercap's `!` prefix: every unhandled command
// that starts with "!" is executed on the host, bare `shell` drops into an
// interactive shell, and `cd`/`pwd` manage the console's working directory.
// The operator typed the command themselves; it is never reachable from scan
// results, caplets or any other untrusted input.
func (s *Session) shellKind(line string) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	switch strings.ToLower(fields[0]) {
	case "cd", "pwd":
		return "shell"
	case "shell":
		if len(fields) == 1 {
			return "interactive"
		}
		return "shell"
	}
	if strings.HasPrefix(fields[0], "!") {
		return "shell"
	}
	return ""
}

// changeDir updates the console's working directory. A platform absolute path
// (leading "/" on unix, a drive or UNC path on Windows) is taken as-is;
// everything else resolves relative to the current console cwd (which stays
// across commands, mirroring a real shell).
func (s *Session) changeDir(arg string) error {
	base := s.cwd
	if base == "" {
		wd, err := os.Getwd()
		if err != nil {
			return err
		}
		base = wd
	}
	target := base
	if arg != "" {
		if filepath.IsAbs(arg) {
			target = filepath.Clean(arg)
		} else {
			target = filepath.Join(base, arg)
		}
	}
	info, err := os.Stat(target)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("cd: not a directory: %s", arg)
	}
	s.cwd = target
	s.statusf("cwd %s", s.cwd)
	return nil
}

// printCwd prints the console's working directory.
func (s *Session) printCwd() {
	cwd := s.cwd
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	s.statusf("cwd %s", cwd)
}

// runHostCommand executes a one-shot host command with stdout/stderr wired to
// the console output so the operator sees the same thing they would in a
// terminal. The console's working directory is inherited so `cd` applies.
func (s *Session) runHostCommand(name string, args []string) error {
	bin, err := exec.LookPath(name)
	if err != nil {
		return fmt.Errorf("%s: command not found", name)
	}
	cwd := s.cwd
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	cmd := exec.CommandContext(context.Background(), bin, args...)
	cmd.Dir = cwd
	cmd.Stdout = s.Out
	cmd.Stderr = s.Out
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

// runHostShell launches an interactive shell in the console's working
// directory, giving the operator a full terminal inside the console (the
// Metasploit `shell` / bettercap `!` escape hatch).
func (s *Session) runHostShell() error {
	s.statusf("starting interactive shell; type 'exit' to return")
	cwd := s.cwd
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}
	cmd := exec.CommandContext(context.Background(), shell, "-i")
	cmd.Dir = cwd
	cmd.Stdout = s.Out
	cmd.Stderr = s.Out
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

// changeDirOrEscape implements the interactive "shell --prompt" flow: an
// empty line keeps the current directory, a directory argument changes it,
// and "exit"/"quit" drops into the interactive shell. It mirrors
// Metasploit's `shell` flow.
func (s *Session) changeDirOrEscape(rl *readline.Instance) error {
	if rl == nil {
		return errors.New("interactive shell requires a terminal")
	}
	for {
		rl.SetPrompt(s.UI.DimWhite("cd (enter to keep, 'exit' to start shell)") + " > ")
		line, err := rl.Readline()
		rl.SetPrompt(s.UI.Prompt("toha3ee"))
		if err != nil {
			return nil // EOF (Ctrl-D) falls through to the interactive shell
		}
		line = strings.TrimSpace(line)
		low := strings.ToLower(line)
		if low == "exit" || low == "quit" {
			return s.runHostShell()
		}
		if line == "" {
			return s.runHostShell()
		}
		if err := s.changeDir(line); err != nil {
			s.errorf("%v", err)
			continue
		}
		return s.runHostShell()
	}
}
