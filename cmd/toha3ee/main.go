// Command toha3ee is the network exploitation framework's CLI: an
// interactive REPL, a guided wizard, a caplet runner and a one-shot -eval
// mode. All attack functionality lives in self-registering modules under
// internal/attacks; this binary only wires them up.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-toha3ee/internal/attacks"
	"github.com/QYVORA/qyvora-toha3ee/internal/config"
	"github.com/QYVORA/qyvora-toha3ee/internal/events"
	"github.com/QYVORA/qyvora-toha3ee/internal/netx"
	"github.com/QYVORA/qyvora-toha3ee/internal/session"
	"github.com/QYVORA/qyvora-toha3ee/internal/ui"

	// Register all attack modules and vector rules.
	// Each package runs an init() that self-registers its modules (and, for
	// vectors/rules, its vector rules) in the central attacks registry, so the
	// CLI never needs to know what modules exist at compile time.
	_ "github.com/QYVORA/qyvora-toha3ee/internal/attacks/auth"
	_ "github.com/QYVORA/qyvora-toha3ee/internal/attacks/enum"
	_ "github.com/QYVORA/qyvora-toha3ee/internal/attacks/espionage"
	_ "github.com/QYVORA/qyvora-toha3ee/internal/attacks/mitm"
	_ "github.com/QYVORA/qyvora-toha3ee/internal/attacks/osint"
	_ "github.com/QYVORA/qyvora-toha3ee/internal/attacks/post"
	_ "github.com/QYVORA/qyvora-toha3ee/internal/attacks/recon"
	_ "github.com/QYVORA/qyvora-toha3ee/internal/attacks/switch"
	_ "github.com/QYVORA/qyvora-toha3ee/internal/attacks/web"
	_ "github.com/QYVORA/qyvora-toha3ee/internal/attacks/wlan"
	_ "github.com/QYVORA/qyvora-toha3ee/internal/vectors/rules"
)

// noSudo is set by the --no-sudo flag and suppresses the automatic sudo
// re-exec escalation (see maybeElevate).
var noSudo bool

// Exit statuses documented in man/toha3ee.1 (EXIT STATUS).
const (
	exitOK          = 0
	exitRuntime     = 1
	exitUsage       = 2
	exitInterrupted = 130 // 128 + SIGINT, the conventional "interrupted" status
)

// usageError marks an error as a usage mistake so it maps to exit code 2
// instead of 1. The cobra arg validators report wrong argument counts as
// plain errors, so they are wrapped to keep the documented contract honest.
type usageError struct{ err error }

func (u usageError) Error() string { return u.err.Error() }
func (u usageError) Unwrap() error { return u.err }

// exactArgsUsage enforces an exact argument count, classifying violations as
// usage errors (exit 2).
func exactArgsUsage(n int) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if err := cobra.ExactArgs(n)(cmd, args); err != nil {
			return usageError{err}
		}
		return nil
	}
}

// isValidOutput reports whether -o names a supported report format.// isValidOutput reports whether -o names a supported report format.
func isValidOutput(spec string) bool {
	switch spec {
	case "terminal", "json", "markdown":
		return true
	}
	return false
}

// exitCodeFor maps an execution error to the documented exit status: usage
// mistakes (bad flags, wrong argument counts, unknown subcommands) exit 2,
// everything else 1.
func exitCodeFor(err error) int {
	if err == nil {
		return exitOK
	}
	var ue usageError
	if errors.As(err, &ue) {
		return exitUsage
	}
	// Cobra reports unknown subcommands ("unknown command \"x\" for
	// \"toha3ee\"") as plain errors; treat them as usage mistakes too.
	if msg := err.Error(); strings.HasPrefix(msg, "unknown command") && strings.Contains(msg, " for ") {
		return exitUsage
	}
	return exitRuntime
}

func main() {
	// Panic recovery: even if a module or handler panics, run the global
	// cleanup registry so the network is restored before we exit.
	defer func() {
		if r := recover(); r != nil {
			// Print the panic and a stack trace so the operator can report the
			// bug, then continue unwinding.
			fmt.Fprintf(os.Stderr, "\n[!] PANIC: %v\n%s\n", r, debug.Stack())
			fmt.Fprintln(os.Stderr, "[*] Running cleanup handlers...")
			// The session's deferred Shutdown() still runs after this
			// recover, so cleanup is guaranteed.
		}
	}()

	// Command-line state shared by every subcommand below; the persistent
	// flags write into these locals.
	var ifaceName string
	var configPath string
	var eval string
	var output string
	var verbose bool
	var noColor bool

	root := &cobra.Command{
		Use:           "toha3ee",
		Short:         "network exploitation & MITM framework",
		SilenceUsage:  true,
		SilenceErrors: true,
		// Bare "toha3ee" drops straight into the interactive console;
		// "--eval \"net.scan; net.show\"" runs without a subcommand too.
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Reject an unknown -o value before any command runs so the exit
			// status is the documented 2 (usage) rather than a runtime error.
			if output != "" && !isValidOutput(output) {
				return usageError{fmt.Errorf("invalid output format %q (terminal, json, markdown)", output)}
			}
			// Any invocation (subcommand or not) escalates to root before it
			// touches the network stack.
			return maybeElevate()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// With no subcommand, --eval runs a one-shot sequence; otherwise
			// fall into the interactive REPL.
			if eval != "" {
				return run(ifaceName, configPath, verbose, noColor, func(s *session.Session) error {
					return s.Eval(eval)
				})
			}
			return run(ifaceName, configPath, verbose, noColor, func(s *session.Session) error {
				return s.REPL()
			})
		},
	}

	root.PersistentFlags().StringVar(&ifaceName, "iface", "", "network interface to attack from")
	root.PersistentFlags().StringVar(&configPath, "config", "", "config file path (default toha3ee.json)")
	root.PersistentFlags().StringVar(&eval, "eval", "", "run a one-shot command sequence and exit, e.g. \"net.scan; net.show\"")
	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose logging")
	root.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "suppress informational status output")
	root.PersistentFlags().BoolVar(&noColor, "no-color", false, "disable colored output")
	root.PersistentFlags().BoolVar(&noSudo, "no-sudo", false, "do not auto-escalate to root via sudo")
	root.PersistentFlags().StringVarP(&output, "output", "o", "", "output format for reports and version: terminal, json, markdown")
	root.PersistentFlags().StringVar(&eventsStream, "events", "", "emit JSONL event stream to stdout, stderr, or a file path (e.g. --events session.jsonl)")

	// Flag parse failures are usage errors: classify them so the process
	// exits with status 2 (see man/toha3ee.1 EXIT STATUS).
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return usageError{err}
	})

	// `toha3ee interactive` is the explicit spelling of the default REPL mode.
	replCmd := &cobra.Command{
		Use:     "interactive",
		Aliases: []string{"repl", "shell"},
		Short:   "start the interactive console",
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(ifaceName, configPath, verbose, noColor, func(s *session.Session) error {
				return s.REPL()
			})
		},
	}

	// `toha3ee wizard` runs the guided attack setup against stdin.
	wizardCmd := &cobra.Command{
		Use:   "wizard",
		Short: "guided attack setup",
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(ifaceName, configPath, verbose, noColor, func(s *session.Session) error {
				return runWizard(s)
			})
		},
	}

	evalCmd := &cobra.Command{
		Use:   "eval",
		Short: "run a one-shot command sequence and exit",
		RunE: func(cmd *cobra.Command, args []string) error {
			// The sequence comes from --eval first, then the positional arg,
			// so both "toha3ee eval --eval 'net.show'" and
			// "toha3ee eval 'net.show'" work.
			seq := eval
			if seq == "" && len(args) > 0 {
				seq = args[0]
			}
			if seq == "" {
				return usageError{fmt.Errorf("eval: nothing to run (pass --eval or a quoted string)")}
			}
			return run(ifaceName, configPath, verbose, noColor, func(s *session.Session) error {
				return s.Eval(seq)
			})
		},
	}

	// `toha3ee run` dispatches on the file extension: ".toha3ee" scripts run
	// through the script engine, anything else is treated as a caplet.
	runCapletCmd := &cobra.Command{
		Use:   "run",
		Short: "execute a script or caplet non-interactively",
		Args:  exactArgsUsage(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(ifaceName, configPath, verbose, noColor, func(s *session.Session) error {
				if strings.HasSuffix(args[0], ".toha3ee") {
					return s.RunScript(args[0])
				}
				return s.RunCaplet(args[0])
			})
		},
	}

	scriptCmd := &cobra.Command{
		Use:   "script",
		Short: "execute a .toha3ee script file",
		Args:  exactArgsUsage(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(ifaceName, configPath, verbose, noColor, func(s *session.Session) error {
				return s.RunScript(args[0])
			})
		},
	}

	// `toha3ee build` parses the script and prints a dry-run plan without
	// touching the network, for safe review before an actual run.
	buildCmd := &cobra.Command{
		Use:   "build",
		Short: "validate a .toha3ee script and print a dry-run plan",
		Args:  exactArgsUsage(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(ifaceName, configPath, verbose, noColor, func(s *session.Session) error {
				return s.BuildScript(args[0])
			})
		},
	}

	// `toha3ee modules` prints the module catalogue directly, without
	// touching the network or requiring a session at all.
	modulesCmd := &cobra.Command{
		Use:   "modules",
		Short: "list all registered modules",
		RunE: func(cmd *cobra.Command, args []string) error {
			u := ui.New(os.Stdout)
			u.SetColor(!noColor && u.Enabled())
			u.Banner("network exploitation & MITM framework")
			u.BannerFoot("", session.Version)
			printModules(u, attacks.List())
			return nil
		},
	}

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "print the version",
		RunE: func(cmd *cobra.Command, args []string) error {
			switch output {
			case "json":
				data, err := json.MarshalIndent(map[string]string{
					"framework": "toha3ee",
					"version":   session.Version,
				}, "", "  ")
				if err != nil {
					return err
				}
				_, _ = fmt.Fprintln(os.Stdout, string(data))
			case "markdown":
				_, _ = fmt.Fprintf(os.Stdout, "**toha3ee** %s\n", session.Version)
			default:
				u := ui.New(os.Stdout)
				u.SetColor(!noColor && u.Enabled())
				u.Banner("network exploitation & MITM framework")
				u.BannerFoot("", session.Version)
			}
			return nil
		},
	}

	// `toha3ee report [file]` re-renders a previously written session report
	// in the requested -o format. The on-disk artifact stays JSON; -o only
	// controls what is printed to stdout (terminal, json, markdown).
	reportCmd := &cobra.Command{
		Use:   "report",
		Short: "render a saved session report (default toha3ee-report.json)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "toha3ee-report.json"
			if len(args) == 1 {
				path = args[0]
			}
			rep, err := session.LoadReport(path)
			if err != nil {
				return err
			}
			switch output {
			case "json":
				data, err := rep.RenderJSON()
				if err != nil {
					return err
				}
				_, err = os.Stdout.Write(data)
				if err != nil {
					return err
				}
				_, _ = fmt.Fprintln(os.Stdout)
			case "markdown":
				_, _ = fmt.Fprint(os.Stdout, rep.RenderMarkdown())
			default:
				_, _ = fmt.Fprint(os.Stdout, rep.RenderTerminal())
			}
			return nil
		},
	}

	// `toha3ee completion <shell>` emits a shell completion script. It is the
	// canonical verb shared with the other QYVORA frameworks.
	completionCmd := &cobra.Command{
		Use:   "completion bash|zsh|fish|powershell",
		Short: "generate a shell completion script",
		Args:  exactArgsUsage(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return root.GenBashCompletionV2(os.Stdout, true)
			case "zsh":
				return root.GenZshCompletion(os.Stdout)
			case "fish":
				return root.GenFishCompletion(os.Stdout, true)
			case "powershell":
				return root.GenPowerShellCompletionWithDesc(os.Stdout)
			default:
				return usageError{fmt.Errorf("unknown shell %q (bash, zsh, fish, powershell)", args[0])}
			}
		},
	}

	root.AddCommand(replCmd, wizardCmd, evalCmd, runCapletCmd, scriptCmd, buildCmd, modulesCmd, versionCmd, reportCmd, completionCmd)
	root.SetArgs(os.Args[1:])
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "toha3ee:", err)
		os.Exit(exitCodeFor(err))
	}
}

// printModules renders the module catalogue grouped by category through u.
func printModules(u *ui.UI, mods []attacks.Module) {
	// Bucket modules by category, keeping the first-seen category order for
	// a stable listing before the final sort.
	byCat := make(map[string][]attacks.Module)
	var cats []string
	for _, m := range mods {
		c := m.Meta().Category
		if _, ok := byCat[c]; !ok {
			cats = append(cats, c)
		}
		byCat[c] = append(byCat[c], m)
	}
	// Categories render alphabetically for predictable output.
	sort.Strings(cats)
	for _, c := range cats {
		u.Section(c)
		rows := make([][]string, 0, len(byCat[c]))
		for _, m := range byCat[c] {
			meta := m.Meta()
			rows = append(rows, []string{meta.ID, u.RiskLevel(meta.Risk.String()), meta.Description})
		}
		u.Table([]string{"id", "risk", "description"}, rows)
	}
	u.Status("+", "%d modules registered", len(mods))
}

// eventsStream is bound to the --events persistent flag. It is package-level
// because the run/openEventsWriter helpers are called from every subcommand.
var eventsStream string

// quiet is bound to the -q/--quiet flag and suppresses informational status
// lines (never errors or command results).
var quiet bool

// openEventsWriter resolves the --events destination spec into a writer:
//
//	""        disabled (no event stream)
//	"stdout"  JSONL to stdout (machine output; do not mix with human reports)
//	"stderr"  JSONL to stderr (the default choice for interactive use)
//	anything else is a file path, created/truncated with 0600
//
// The returned close function must be called when the stream is done.
func openEventsWriter(spec string) (io.Writer, func() error, error) {
	switch spec {
	case "":
		return nil, nil, nil
	case "stdout":
		return os.Stdout, nil, nil
	case "stderr":
		return os.Stderr, nil, nil
	}
	f, err := os.OpenFile(spec, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("events file: %w", err)
	}
	return f, f.Close, nil
}

// newEventsEmitter builds an emitter bound to the --events destination. It
// returns (nil, nil, nil) when the stream is disabled.
func newEventsEmitter() (*events.Emitter, func(), error) {
	w, closeFn, err := openEventsWriter(eventsStream)
	if err != nil {
		return nil, nil, err
	}
	if w == nil {
		return nil, nil, nil
	}
	execID := fmt.Sprintf("toha3ee-%d", time.Now().UnixNano())
	return events.NewEmitter(w, execID), func() {
		if closeFn != nil {
			_ = closeFn()
		}
	}, nil
}

// run executes the session body (REPL, eval, script, build) against a live
// session, wiring the optional JSONL event stream around it.
func run(ifaceName, configPath string, verbose, noColor bool, body func(*session.Session) error) error {
	log := slog.Default()
	if !verbose {
		// Non-verbose: drop all log output so only the UI writes to stdout.
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	var iface *netx.Iface
	var err error
	if ifaceName != "" {
		// An explicit -iface flag wins; otherwise pick a suitable default.
		iface, err = netx.SelectIface(ifaceName)
	} else {
		iface, err = netx.AutoSelectIface()
	}
	if err != nil {
		return fmt.Errorf("select interface: %w", err)
	}

	s := session.New(iface, os.Stdout, log)
	if quiet {
		s.UI.Quiet = true
	}
	if noColor {
		s.SetColor(false)
	}
	// Shutdown always runs on the way out (including panics via the recover
	// above) so modules are stopped and the network restored.
	defer s.Shutdown()

	// Handle SIGINT/SIGTERM for graceful cleanup.
	// The channel is buffered so a signal arriving while the goroutine is
	// still finishing up is not dropped.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "\n[*] Caught signal, cleaning up...")
		s.Shutdown()
		os.Exit(exitInterrupted)
	}()

	// Apply a user-supplied config file on top of the defaults; errors are
	// deliberately ignored so a bad file just falls back to defaults.
	if configPath != "" {
		if cfg, err := config.Load(configPath); err == nil {
			s.Conf = cfg
		}
	}

	// Bind the optional JSONL event stream before any command runs so the
	// full lifecycle (run.started .. run.completed) is captured.
	emitter, closeStream, err := newEventsEmitter()
	if err != nil {
		return err
	}
	if closeStream != nil {
		defer closeStream()
	}
	if emitter != nil {
		s.Events = emitter
		events.SubscribeJSONL(s.Bus, emitter)
		emitter.Info("toha3ee", events.RunStarted, map[string]any{
			"version": session.Version,
			"iface":   iface.Name,
			"cidr":    iface.CIDR(),
		})
	}
	runErr := body(s)
	if emitter != nil {
		if runErr != nil {
			emitter.Fail("toha3ee", events.Error, map[string]any{"message": runErr.Error()})
		} else {
			emitter.Info("toha3ee", events.RunCompleted, map[string]any{
				"hosts":    len(s.Store.Hosts()),
				"creds":    len(s.Store.Creds()),
				"sessions": len(s.Store.Sessions()),
				"events":   len(s.Store.Events()),
			})
		}
	}
	return runErr
}

func runWizard(s *session.Session) error {
	return s.WizardWithStdin()
}

// shouldElevate reports whether the process must re-exec itself as root. The
// framework needs raw sockets and packet capture, so unless it is already
// running as root (or the user explicitly opted out) every invocation escalates
// via sudo and prompts for the admin password.
func shouldElevate(euid int, noSudo, windows bool) bool {
	// On Windows there is no sudo model, and a non-zero euid already running
	// does not imply a privilege problem, so escalation never applies.
	return euid != 0 && !noSudo && !windows
}

// maybeElevate re-runs the current executable under sudo when it is not root.
// Use --no-sudo or TOHA3EE_NO_SUDO=1 to skip the prompt (e.g. for a plain
// `version` or `modules` listing).
func maybeElevate() error {
	if os.Getenv("TOHA3EE_NO_SUDO") == "1" {
		return nil
	}
	if !shouldElevate(os.Geteuid(), noSudo, runtime.GOOS == "windows") {
		return nil
	}
	if _, err := exec.LookPath("sudo"); err != nil {
		return errors.New("toha3ee needs root privileges, but sudo was not found; re-run as root")
	}
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve own executable path: %w", err)
	}
	fmt.Fprintln(os.Stderr, "[*] toha3ee needs admin privileges; escalating via sudo (enter the admin password)...")
	// Re-exec with the exact same args so flags are preserved under sudo.
	// sudo inherits our stdio so the password prompt and output stay attached
	// to the same terminal.
	cmd := exec.Command("sudo", append([]string{self}, os.Args[1:]...)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			// The child already printed its error; mirror only its exit code.
			os.Exit(ee.ExitCode())
		}
		return err
	}
	// The elevated child succeeded; this (original) process must not continue
	// as non-root. Exit with success so the parent shell sees a clean status.
	os.Exit(0)
	return nil
}
