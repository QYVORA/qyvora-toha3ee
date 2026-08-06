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
	"syscall"

	"github.com/spf13/cobra"

	"github.com/qyvora/toha3ee/internal/attacks"
	"github.com/qyvora/toha3ee/internal/config"
	"github.com/qyvora/toha3ee/internal/netx"
	"github.com/qyvora/toha3ee/internal/session"

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

var version = "0.1.0"

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

	root := &cobra.Command{
		Use:           "toha3ee",
		Short:         "network exploitation & MITM framework",
		SilenceUsage:  true,
		SilenceErrors: true,
		// `toha3ee --eval "net.scan; net.show"` runs without a subcommand.
		RunE: func(cmd *cobra.Command, args []string) error {
			if eval != "" {
				return run(ifaceName, configPath, verbose, func(s *session.Session) error {
					return s.Eval(eval)
				})
			}
			return cmd.Help()
		},
	}

	root.PersistentFlags().StringVar(&ifaceName, "iface", "", "network interface to attack from")
	root.PersistentFlags().StringVar(&configPath, "config", "", "config file path (default toha3ee.json)")
	root.PersistentFlags().StringVar(&eval, "eval", "", "run a one-shot command sequence and exit, e.g. \"net.scan; net.show\"")
	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose logging")

	replCmd := &cobra.Command{
		Use:     "interactive",
		Aliases: []string{"repl", "shell"},
		Short:   "start the interactive console",
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(ifaceName, configPath, verbose, func(s *session.Session) error {
				return s.REPL()
			})
		},
	}

	wizardCmd := &cobra.Command{
		Use:   "wizard",
		Short: "guided attack setup",
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(ifaceName, configPath, verbose, func(s *session.Session) error {
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
			return run(ifaceName, configPath, verbose, func(s *session.Session) error {
				return s.Eval(seq)
			})
		},
	}

	runCapletCmd := &cobra.Command{
		Use:   "run",
		Short: "execute a caplet script non-interactively",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(ifaceName, configPath, verbose, func(s *session.Session) error {
				return s.RunCaplet(args[0])
			})
		},
	}

	modulesCmd := &cobra.Command{
		Use:   "modules",
		Short: "list all registered modules",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("%-24s %-10s %-8s %s\n", "ID", "category", "risk", "description")
			for _, m := range attacks.List() {
				meta := m.Meta()
				fmt.Printf("%-24s %-10s %-8s %s\n", meta.ID, meta.Category, meta.Risk, meta.Description)
			}
			return nil
		},
	}

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "print the version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("toha3ee " + version)
		},
	}

	root.AddCommand(replCmd, wizardCmd, evalCmd, runCapletCmd, modulesCmd, versionCmd)
	root.SetArgs(os.Args[1:])
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "toha3ee:", err)
		os.Exit(1)
	}
}

func run(ifaceName, configPath string, verbose bool, body func(*session.Session) error) error {
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
	fmt.Fprintf(s.Out, "toha3ee wizard (%s)\n", s.Iface.String())
	return s.WizardWithStdin()
}
