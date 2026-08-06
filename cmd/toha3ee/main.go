// Command toha3ee is the network exploitation framework's CLI: an
// interactive REPL, a guided wizard, a caplet runner and a one-shot -eval
// mode. All attack functionality lives in self-registering modules under
// internal/attacks; this binary only wires them up.
package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"sort"
	"strconv"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/qyvora/toha3ee/internal/attacks"
	"github.com/qyvora/toha3ee/internal/config"
	"github.com/qyvora/toha3ee/internal/netx"
	"github.com/qyvora/toha3ee/internal/session"
	"github.com/qyvora/toha3ee/internal/ui"

	// Register all attack modules and vector rules.
	_ "github.com/qyvora/toha3ee/internal/attacks/auth"
	_ "github.com/qyvora/toha3ee/internal/attacks/espionage"
	_ "github.com/qyvora/toha3ee/internal/attacks/mitm"
	_ "github.com/qyvora/toha3ee/internal/attacks/post"
	_ "github.com/qyvora/toha3ee/internal/attacks/recon"
	_ "github.com/qyvora/toha3ee/internal/attacks/switch"
	_ "github.com/qyvora/toha3ee/internal/attacks/wlan"
	_ "github.com/qyvora/toha3ee/internal/vectors/rules"
)

func main() {
	// Panic recovery: even if a module or handler panics, run the global
	// cleanup registry so the network is restored before we exit.
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "\n[!] PANIC: %v\n%s\n", r, debug.Stack())
			fmt.Fprintln(os.Stderr, "[*] Running cleanup handlers...")
			// The session's deferred Shutdown() still runs after this
			// recover, so cleanup is guaranteed.
		}
	}()

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
		RunE: func(cmd *cobra.Command, args []string) error {
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

	runCapletCmd := &cobra.Command{
		Use:   "run",
		Short: "execute a caplet script non-interactively",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(ifaceName, configPath, verbose, noColor, func(s *session.Session) error {
				return s.RunCaplet(args[0])
			})
		},
	}

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

	root.AddCommand(replCmd, wizardCmd, evalCmd, runCapletCmd, modulesCmd, versionCmd)
	root.SetArgs(os.Args[1:])
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "toha3ee:", err)
		os.Exit(1)
	}
}

// printModules renders the module catalogue grouped by category through u.
func printModules(u *ui.UI, mods []attacks.Module) {
	byCat := make(map[string][]attacks.Module)
	var cats []string
	for _, m := range mods {
		c := m.Meta().Category
		if _, ok := byCat[c]; !ok {
			cats = append(cats, c)
		}
		byCat[c] = append(byCat[c], m)
	}
	sort.Strings(cats)
	for _, c := range cats {
		u.Section(c)
		rows := make([][]string, 0, len(byCat[c]))
		for _, m := range byCat[c] {
			meta := m.Meta()
			rows = append(rows, []string{meta.ID, meta.Risk.String(), meta.Description})
		}
		u.Table([]string{"id", "risk", "description"}, rows)
	}
	fmt.Fprintf(u.Writer(), "\n%s %s\n", u.BoldWhite("total:"), u.White(strconv.Itoa(len(mods))))
}

func run(ifaceName, configPath string, verbose, noColor bool, body func(*session.Session) error) error {
	log := slog.Default()
	if !verbose {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	var iface *netx.Iface
	var err error
	if ifaceName != "" {
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
	defer s.Shutdown()

	// Handle SIGINT/SIGTERM for graceful cleanup.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "\n[*] Caught signal, cleaning up...")
		s.Shutdown()
		os.Exit(0)
	}()

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
