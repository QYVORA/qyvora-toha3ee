package session

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/QYVORA/qyvora-toha3ee/internal/attacks"
	"github.com/QYVORA/qyvora-toha3ee/internal/script"
	"github.com/QYVORA/qyvora-toha3ee/internal/store"
)

// ScriptRunner adapts a Session to the script engine's Runner contract, so a
// ".toha3ee" script drives the exact same module lifecycle as the REPL.
func (s *Session) ScriptRunner() script.Runner { return &scriptRunner{s: s} }

// scriptRunner is the Session-side implementation of the engine's Runner.
type scriptRunner struct{ s *Session }

// Echo prints a value through the console.
func (r *scriptRunner) Echo(msg string) {
	r.s.UI.Status(">", "%s", msg)
}

// SetConfig writes a "module.key" value.
func (r *scriptRunner) SetConfig(key, value string) error {
	// The key must be "module.param"; splitModuleKey handles dotted ids.
	module, param, ok := splitModuleKey(key)
	if !ok {
		return fmt.Errorf("script: config key must be 'module.key' (got %q)", key)
	}
	r.s.Conf.Set(module, param, value)
	// Config changes are logged as events so the session audit trail shows
	// what a script mutated.
	r.s.Store.LogEvent("config.set", fmt.Sprintf("%s = %s", key, value))
	return nil
}

// GetConfig reads a "module.key" value.
func (r *scriptRunner) GetConfig(key string) string {
	return r.s.Conf.GetFromKey(key)
}

// Start launches a module. Running a script is itself an explicit, authorized
// action, so the high/critical-risk confirmation gate is satisfied on the
// script's behalf.
func (r *scriptRunner) Start(id string, opts map[string]string) error {
	if _, ok := attacks.Get(id); !ok {
		return fmt.Errorf("unknown module %q", id)
	}
	// Confirm the risk unconditionally: the user already signed off by
	// choosing to run the script at all.
	r.s.Conf.ConfirmRisk(id)
	return r.s.StartModule(id, opts)
}

// Stop halts a running module.
func (r *scriptRunner) Stop(id string) error { return r.s.StopModule(id) }

// IsRunning reports a module's liveness.
func (r *scriptRunner) IsRunning(id string) bool { return r.s.IsRunning(id) }

// Show prints module metadata.
func (r *scriptRunner) Show(id string) error { return r.s.showModule(id) }

// Report writes a session report.
func (r *scriptRunner) Report(path string) error { return r.s.report([]string{path}) }

// Cmd runs a one-shot REPL command line.
func (r *scriptRunner) Cmd(line string) error { return r.s.execOnce(line) }

// Prop resolves live session state for $(...) interpolation.
func (r *scriptRunner) Prop(name string) (string, bool) {
	s := r.s
	switch name {
	// Counters and lists of discovered hosts.
	case "hosts.count", "net.hosts.count":
		return strconv.Itoa(len(s.Store.Hosts())), true
	case "hosts.list", "net.hosts":
		return joinHostList(s.Store.Hosts()), true
	// Loot counters.
	case "creds.count":
		return strconv.Itoa(len(s.Store.Creds())), true
	case "sessions.count":
		return strconv.Itoa(len(s.Store.Sessions())), true
	case "events.count":
		return strconv.Itoa(len(s.Store.Events())), true
	// Live module state.
	case "running.count":
		return strconv.Itoa(len(s.Running())), true
	case "running.list":
		return strings.Join(s.Running(), ","), true
	// Interface facts; the nil guards keep scripts working even when no
	// interface is available (e.g. unit tests or odd setups).
	case "iface.ip":
		return ifaceIP(s), true
	case "iface.name":
		if s.Iface != nil {
			return s.Iface.Name, true
		}
		return "", true
	case "iface.cidr":
		if s.Iface != nil {
			return s.Iface.CIDR(), true
		}
		return "", true
	case "iface.gateway":
		if s.Iface != nil {
			if gw, err := s.Iface.Gateway(); err == nil {
				return gw.String(), true
			}
		}
		// "unknown" (not an error) keeps the interpolation useful when no
		// gateway exists.
		return "unknown", true
	case "iface.mac":
		if s.Iface != nil && s.Iface.MAC != nil {
			return s.Iface.MAC.String(), true
		}
		return "", true
	case "version":
		return Version, true
	}
	// Any "config.xxx" path is a direct config store read.
	if strings.HasPrefix(name, "config.") {
		return s.Conf.GetFromKey(strings.TrimPrefix(name, "config.")), true
	}
	return "", false
}

// RunScript executes a ".toha3ee" script file through the shared engine.
func (s *Session) RunScript(path string) error {
	e := script.NewEngine(s.ScriptRunner())
	return e.RunFile(path)
}

// BuildScript parses a ".toha3ee" file and prints a dry-run plan of what it
// would do. It never touches the network.
func (s *Session) BuildScript(path string) error {
	data, err := readCaplet(path)
	if err != nil {
		return err
	}
	prog, err := script.Parse(string(data))
	if err != nil {
		return err
	}
	s.UI.Section("script plan " + path)
	for _, line := range script.Describe(prog) {
		s.UI.Status("-", "%s", line)
	}
	return nil
}

// ifaceIP returns the bound interface's IP, or "" when unavailable.
func ifaceIP(s *Session) string {
	if s.Iface != nil && s.Iface.IP != nil {
		return s.Iface.IP.String()
	}
	return ""
}

// joinHostList renders the discovered hosts as a comma-separated IP list.
func joinHostList(hosts []*store.Host) string {
	ips := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if h.IP != nil {
			ips = append(ips, h.IP.String())
		}
	}
	return strings.Join(ips, ",")
}
