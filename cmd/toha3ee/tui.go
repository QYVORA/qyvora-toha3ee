package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-tui"

	"github.com/QYVORA/qyvora-toha3ee/internal/session"
	"github.com/QYVORA/qyvora-toha3ee/internal/version"
)

// sessionRunner drives the shared terminal application from a session that
// already exists.
//
// Every other QYVORA tool's adapter re-enters its own command tree once per
// typed line, which works because their commands are self-contained. toha3ee's
// are not: the discovered hosts, credentials, sessions and running modules live
// in a single in-memory store that the console builds up, and nothing writes it
// to disk. Re-entering would hand every line a brand-new empty store, so
// `net.scan` would report success and `net.show` would then display nothing --
// a session that silently discards the operator's work after every command.
//
// Holding the session here instead is what makes the shared interface usable
// for this tool: the interface still sees one line in and one result block out,
// and the state those lines build up stays alive between them.
type sessionRunner struct {
	sess *session.Session
	meta []tui.Command
}

func (r *sessionRunner) Name() string { return "toha3ee" }

func (r *sessionRunner) Commands() []tui.Command { return r.meta }

// Run evaluates one typed line against the live session.
//
// The session already routes its JSONL event stream to standard output, so the
// only thing missing here is the redirection: Capture points both descriptors at
// the interface for the duration of the call, and the interface tells the two
// apart by shape. Nothing is parsed from prose, and the session's own
// structured stream is the sole source of what the interface renders
// structurally.
func (r *sessionRunner) Run(ctx context.Context, args []string, events io.Writer) (int, error) {
	line := rejoinArgs(args)
	if strings.TrimSpace(line) == "" {
		return 0, nil
	}

	var runErr error
	captureErr := tui.Capture(events, func() error {
		runErr = r.sess.Eval(line)
		return nil
	})
	if captureErr != nil {
		// The capture itself failed, so the session never ran. That is the
		// interface's problem to report, not a command failure.
		return 1, captureErr
	}
	if runErr != nil {
		return 1, runErr
	}
	if ctx.Err() != nil {
		// The line finished despite the interrupt. Report the interrupt, since
		// that is what the operator asked for by pressing Ctrl+C.
		return tui.ExitCancelled, nil
	}
	return 0, nil
}

// rejoinArgs turns the interface's tokenised line back into the single string
// the console parses.
//
// The interface strips quotes while splitting, so joining with plain spaces
// would corrupt any argument that contained one: `!shell ls -l "/tmp/a b"`
// would arrive as three tokens where the console expects a single quoted path.
// Re-quoting restores what the operator typed, which matters because toha3ee's
// console language has a host-shell escape hatch where quoting is load-bearing.
func rejoinArgs(args []string) string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if a == "" || strings.ContainsAny(a, " \t\n\"'\\$`") {
			out = append(out, `"`+strings.NewReplacer(
				`\`, `\\`, `"`, `\"`, "`", "\\`", `$`, `\$`,
			).Replace(a)+`"`)
			continue
		}
		out = append(out, a)
	}
	return strings.Join(out, " ")
}

// tuiCommandMeta describes the console's commands to the shared interface.
//
// The names come from the console's own completer, so a module added to the
// registry becomes completable without a second list drifting out of step.
func tuiCommandMeta() []tui.Command {
	names := session.CommandNames()
	out := make([]tui.Command, 0, len(names))
	for _, n := range names {
		out = append(out, tui.Command{Name: n})
	}
	return out
}

// runTUI serves the shared terminal application from a live session.
//
// It goes through the same run() the console does, so interface selection,
// config loading, the event stream, signal handling and the shutdown that
// restores the network are all shared. The one thing that changes is the body:
// instead of a readline loop, it draws the interface and evaluates each line
// against the session it was handed.
func runTUI(root *cobra.Command, ctx context.Context, ifaceName, configPath, output string, verbose, noColor bool) error {
	// A TUI needs a terminal. When stdout is redirected, or when the binary is
	// driven by something that is not a human, fall through to ordinary
	// behaviour: printing the command list is useful, and it is what a piped
	// or CI invocation needs. Launching a full-screen interface into a pipe
	// would fill it with escape codes and destroy the machine-readable output
	// the tool exists to produce.
	//
	// This is checked before the session is built, before the interface is
	// chosen and before root is asked for, so a redirected run costs nothing
	// and asks for no password.
	if !tui.IsInteractive(os.Stdout) {
		return root.Help()
	}

	// A machine event destination and the interface are contradictory: one
	// screen cannot hand the same bytes to a renderer and to a file. The
	// destination used to be ignored in silence, so a bare
	// `--events out.jsonl` opened the session and wrote no file.
	if root.Flags().Changed("events") && !eventsDisabled(eventsStream) {
		return usageError{fmt.Errorf("cannot open the interactive session with a machine event destination (--events %s); the session transcript is already its event stream. Use --eval for machine output, or drop --events to use the session", eventsStream)}
	}

	// A machine report format writes the session report to standard output when
	// the body returns, which inside the interface would be spliced into the
	// event stream. The interface is the report; asking for a second one is a
	// contradiction, so say so rather than emitting both.
	if f := normalizeOutput(output); f == "json" || f == "markdown" {
		return usageError{fmt.Errorf("the interactive session does not support -o %s; use `report -o %s` inside the session", f, f)}
	}

	// Inside the session the transcript is the event stream: the session emits
	// JSONL to standard output and Capture routes it to the interface, which
	// parses the envelopes. Nothing is written to a file instead, because there
	// is no one to read it.
	prevStream := eventsStream
	eventsStream = "stdout"
	defer func() { eventsStream = prevStream }()

	return run(ifaceName, configPath, output, verbose, noColor, func(s *session.Session) error {
		runner := &sessionRunner{sess: s, meta: tuiCommandMeta()}
		code, err := tui.Run(tui.Config{
			Title:   "QYVORA / TOHA3EE",
			Version: version.String(),
			Runner:  runner,
			Out:     os.Stdout,
		})
		if err != nil {
			if tui.IsNotInteractive(err) {
				return root.Help()
			}
			return err
		}
		if code != 0 {
			return &tuiExitError{code: code}
		}
		return nil
	})
}

// tuiExitError carries the session's exit status out through run's error
// plumbing. The console's own REPL has no such code, so the mapping lives here.
type tuiExitError struct{ code int }

func (e *tuiExitError) Error() string {
	return fmt.Sprintf("last session command exited with status %d", e.code)
}

// eventsDisabled reports whether a --events value asks for no stream at all.
//
// It sits beside the other two preflights because they answer the same
// question from different angles: is this invocation for a person at a terminal,
// or for a program reading a stream? A value that turns the stream off must not
// read as a request to send it somewhere, or `toha3ee --events off` would be
// refused for asking for nothing.
func eventsDisabled(spec string) bool {
	switch strings.ToLower(spec) {
	case "", "off", "none", "disable", "disabled":
		return true
	}
	return false
}

// opensInteractiveSession reports whether this invocation would draw the
// interface if it had a terminal.
//
// The question is asked in two parts, and both parts matter. Which commands draw
// the interface decides whether root is needed; whether a terminal exists decides
// whether there is anyone to ask for a password. PersistentPreRunE combines them
// so a redirected run costs nothing, while a redirected --eval still escalates:
// it touches the network stack whether or not anyone is watching.
//
// evalRequested is passed rather than read, because the flag targets a local in
// newRootCmd. Widening it to a package var would put it back in reach of every
// command built later, which is the leak the local exists to prevent.
func opensInteractiveSession(cmd *cobra.Command, evalRequested bool) bool {
	isRoot := cmd == cmd.Root()
	// Only the bare root falls through to the session. A root invocation with
	// --eval, or with a subcommand, is a one-shot run and needs root either way.
	if isRoot && evalRequested {
		return false
	}
	// `tui` and its aliases always draw it; any other subcommand is its own
	// thing and maybeElevate decides what it needs.
	// A named event destination means the operator wants machine output.
	// The flag has to have been asked for: a tool that defaults --events
	// to stderr would otherwise refuse every interactive run.
	if cmd.Flags().Changed("events") && !eventsDisabled(eventsStream) {
		return false
	}
	return isRoot || cmd.Name() == "tui"
}
