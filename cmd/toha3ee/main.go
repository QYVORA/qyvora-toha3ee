// Command toha3ee is the network exploitation framework's CLI: an
// interactive REPL, a guided wizard, a caplet runner and a one-shot -eval
// mode. All attack functionality lives in self-registering modules under
// internal/attacks; this binary only wires them up.
package main

import (
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

	"github.com/spf13/cobra"

	"github.com/qyvora/toha3ee/internal/attacks"
	"github.com/qyvora/toha3ee/internal/config"
	"github.com/qyvora/toha3ee/internal/netx"
	"github.com/qyvora/toha3ee/internal/session"
	"github.com/qyvora/toha3ee/internal/ui"

	// Register all attack modules and vector rules.
	// Each package runs an init() that self-registers its modules (and, for
	// vectors/rules, its vector rules) in the central attacks registry, so the
	// CLI never needs to know what modules exist at compile time.
	_ "github.com/qyvora/toha3ee/internal/attacks/auth"
	_ "github.com/qyvora/toha3ee/internal/attacks/enum"
	_ "github.com/qyvora/toha3ee/internal/attacks/espionage"
	_ "github.com/qyvora/toha3ee/internal/attacks/mitm"
	_ "github.com/qyvora/toha3ee/internal/attacks/osint"
	_ "github.com/qyvora/toha3ee/internal/attacks/post"
	_ "github.com/qyvora/toha3ee/internal/attacks/recon"
	_ "github.com/qyvora/toha3ee/internal/attacks/switch"
	_ "github.com/qyvora/toha3ee/internal/attacks/web"
	_ "github.com/qyvora/toha3ee/internal/attacks/wlan"
	_ "github.com/qyvora/toha3ee/internal/vectors/rules"
)

// noSudo is set by the --no-sudo flag and suppresses the automatic sudo
// re-exec escalation (see maybeElevate).
var noSudo bool

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
	root.PersistentFlags().BoolVar(&noColor, "no-color", false, "disable colored output")
	root.PersistentFlags().BoolVar(&noSudo, "no-sudo", false, "do not auto-escalate to root via sudo")

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
				return fmt.Errorf("eval: nothing to run (pass --eval or a quoted string)")
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
		Args:  cobra.ExactArgs(1),
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
		Args:  cobra.ExactArgs(1),
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
		Args:  cobra.ExactArgs(1),
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
		Run: func(cmd *cobra.Command, args []string) {
			u := ui.New(os.Stdout)
			u.SetColor(!noColor && u.Enabled())
			u.Banner("network exploitation & MITM framework")
			u.BannerFoot("", session.Version)
		},
	}

	root.AddCommand(replCmd, wizardCmd, evalCmd, runCapletCmd, scriptCmd, buildCmd, modulesCmd, versionCmd)
	root.SetArgs(os.Args[1:])
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "toha3ee:", err)
		os.Exit(1)
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
		os.Exit(0)
	}()

	// Apply a user-supplied config file on top of the defaults; errors are
	// deliberately ignored so a bad file just falls back to defaults.
	if configPath != "" {
		if cfg, err := config.Load(configPath); err == nil {
			s.Conf = cfg
		}
	}
	return body(s)
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
