package main

import (
	"context"
	"errors"
	"testing"

	"github.com/spf13/cobra"
)

// The interface tokenises a typed line and hands the runner bare words, but the
// console parses a single string. Round-tripping through a plain space join
// would corrupt any argument containing one, and toha3ee's console has a host
// shell escape hatch where quoting is load-bearing.
func TestRejoinArgsRestoresQuoting(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"simple", []string{"net", "scan", "10.0.0.1"}, "net scan 10.0.0.1"},
		{"empty", nil, ""},
		{"single", []string{"status"}, "status"},
		{"inner space", []string{"shell", "echo a b"}, `shell "echo a b"`},
		{"inner quote", []string{"shell", `say "hi"`}, `shell "say \"hi\""`},
		{"inner backslash", []string{"shell", `win C:\tmp`}, `shell "win C:\\tmp"`},
		{"inner dollar", []string{"shell", "echo $HOME"}, `shell "echo \$HOME"`},
		// Both backticks are escaped, not just the first: inside a
		// double-quoted string an unescaped backtick would still start a
		// substitution, so escaping one would leave the argument unsafe.
		{"inner backtick", []string{"shell", "echo `id`"}, "shell \"echo \\`id\\`\""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := rejoinArgs(tc.args); got != tc.want {
				t.Errorf("rejoinArgs(%q) = %q, want %q", tc.args, got, tc.want)
			}
		})
	}
}

// A cancelled session must exit 130, not 1. A wrapper script that cannot tell an
// operator pressing Ctrl+C from a broken binary will treat every interrupted
// scan as a failure.
func TestExitCodeForReportsCancellation(t *testing.T) {
	if got := exitCodeFor(context.Canceled); got != exitInterrupted {
		t.Errorf("exitCodeFor(context.Canceled) = %d, want %d", got, exitInterrupted)
	}
	if got := exitCodeFor(&tuiExitError{code: 130}); got != 130 {
		t.Errorf("exitCodeFor(tuiExitError{130}) = %d, want 130", got)
	}
	// Wrapped cancellation must still be recognised: the error travels through
	// the session's own plumbing before it reaches the process exit.
	if got := exitCodeFor(errors.Join(errors.New("cleanup"), context.Canceled)); got != exitInterrupted {
		t.Errorf("exitCodeFor(wrapped Canceled) = %d, want %d", got, exitInterrupted)
	}
	// Ordinary failures must not be mistaken for interrupts.
	if got := exitCodeFor(errors.New("boom")); got != exitRuntime {
		t.Errorf("exitCodeFor(plain error) = %d, want %d", got, exitRuntime)
	}
	if got := exitCodeFor(usageError{errors.New("bad flag")}); got != exitUsage {
		t.Errorf("exitCodeFor(usageError) = %d, want %d", got, exitUsage)
	}
	if got := exitCodeFor(nil); got != exitOK {
		t.Errorf("exitCodeFor(nil) = %d, want %d", got, exitOK)
	}
}

// The interface completes against the console's own command list. An empty list
// would leave tab-completion offering nothing, which reads as a broken prompt.
func TestTUICommandMetaCoversConsoleCommands(t *testing.T) {
	meta := tuiCommandMeta()
	if len(meta) == 0 {
		t.Fatal("tuiCommandMeta returned no commands; completion would be empty")
	}
	present := map[string]bool{}
	for _, c := range meta {
		if c.Name == "" {
			t.Error("tuiCommandMeta contains a command with no name")
		}
		present[c.Name] = true
	}
	for _, want := range []string{"help", "status", "modules", "net.show", "report"} {
		if !present[want] {
			t.Errorf("tuiCommandMeta is missing %q", want)
		}
	}
}

// The disable words must not read as a request to send the stream somewhere.
// `toha3ee --events off` asks for no stream at all, and refusing to open the
// session for it would be refusing an ordinary interactive run.
func TestEventsDisabledCoversTheDisableWords(t *testing.T) {
	for _, spec := range []string{"", "off", "OFF", "none", "disable", "disabled", "Off"} {
		if !eventsDisabled(spec) {
			t.Errorf("eventsDisabled(%q) = false, want true", spec)
		}
	}
	for _, spec := range []string{"stdout", "stderr", "session.jsonl", "/tmp/e.jsonl", "off.jsonl"} {
		if eventsDisabled(spec) {
			t.Errorf("eventsDisabled(%q) = true, want false", spec)
		}
	}
}

// Escalation happens before the interface can discover it has no terminal, so
// this predicate is what stops a redirected run from asking for a password
// nobody can type. A redirected --eval is a real run and must still escalate.
func TestOpensInteractiveSession(t *testing.T) {
	root := &cobra.Command{Use: "toha3ee"}
	tuiCmd := &cobra.Command{Use: "tui", Aliases: []string{"repl"}, Run: func(*cobra.Command, []string) {}}
	report := &cobra.Command{Use: "report", Run: func(*cobra.Command, []string) {}}
	root.AddCommand(tuiCmd, report)

	cases := []struct {
		name string
		cmd  *cobra.Command
		eval bool
		want bool
	}{
		{"bare root", root, false, true},
		{"bare root with eval", root, true, false},
		{"tui", tuiCmd, false, true},
		{"tui with eval", tuiCmd, true, true},
		{"unrelated subcommand", report, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := opensInteractiveSession(tc.cmd, tc.eval); got != tc.want {
				t.Errorf("opensInteractiveSession(%s, eval=%v) = %v, want %v",
					tc.cmd.Name(), tc.eval, got, tc.want)
			}
		})
	}
}
