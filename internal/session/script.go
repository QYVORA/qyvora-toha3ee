package session

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/QYVORA/qyvora-script/ast"
	"github.com/QYVORA/qyvora-script/binding"
	"github.com/QYVORA/qyvora-script/interpreter"
	"github.com/QYVORA/qyvora-script/parser"

	"github.com/QYVORA/qyvora-toha3ee/internal/attacks"
	"github.com/QYVORA/qyvora-toha3ee/internal/store"
)

// ScriptBinding adapts a Session to the shared qyvora-script binding.Binding,
// so a ".qs"/".toha3ee" script drives the exact same module lifecycle as the
// REPL. Every capability the script language can invoke is routed here.
func (s *Session) ScriptBinding() binding.Binding { return &scriptBinding{s: s} }

// scriptBinding is the Session-side implementation of binding.Binding.
type scriptBinding struct{ s *Session }

// Call dispatches a script capability onto the live session.
func (b *scriptBinding) Call(capabilityID string, args []binding.Value) (binding.Value, error) {
	s := b.s
	switch capabilityID {
	case binding.CapEcho:
		s.UI.Status(">", "%s", args[0].(string))
		return nil, nil

	case binding.CapSetConfig:
		key, value := args[0].(string), args[1].(string)
		// The key must be "module.param"; splitModuleKey handles dotted ids.
		module, param, ok := splitModuleKey(key)
		if !ok {
			return nil, fmt.Errorf("script: config key must be 'module.key' (got %q)", key)
		}
		s.Conf.Set(module, param, value)
		// Config changes are logged as events so the session audit trail shows
		// what a script mutated.
		s.Store.LogEvent("config.set", fmt.Sprintf("%s = %s", key, value))
		return nil, nil

	case binding.CapGetConfig:
		return s.Conf.GetFromKey(args[0].(string)), nil

	case binding.CapStart:
		id := args[0].(string)
		opts, _ := args[1].(map[string]string)
		if _, ok := attacks.Get(id); !ok {
			return nil, fmt.Errorf("unknown module %q", id)
		}
		// Running a script is itself an explicit, authorized action, so the
		// high/critical-risk confirmation gate is satisfied on the script's
		// behalf.
		s.Conf.ConfirmRisk(id)
		return nil, s.StartModule(id, opts)

	case binding.CapStop:
		return nil, s.StopModule(args[0].(string))

	case binding.CapIsRunning:
		return s.IsRunning(args[0].(string)), nil

	case binding.CapShow:
		return nil, s.showModule(args[0].(string))

	case binding.CapReport:
		return nil, s.report([]string{args[0].(string)})

	case binding.CapExec:
		return nil, s.execOnce(args[0].(string))

	case binding.CapProp:
		v, ok := b.prop(args[0].(string))
		if !ok {
			return nil, nil
		}
		return v, nil
	}
	return nil, fmt.Errorf("script: unsupported capability %q", capabilityID)
}

// Capabilities lists the capability IDs this binding supports.
func (b *scriptBinding) Capabilities() []string {
	return []string{
		binding.CapEcho, binding.CapSetConfig, binding.CapGetConfig,
		binding.CapStart, binding.CapStop, binding.CapIsRunning,
		binding.CapShow, binding.CapReport, binding.CapProp, binding.CapExec,
	}
}

// AllowShellOut gates exec/run.cmd. It is false unless the session was built
// with --allow-shellout or the QYVORA_ALLOW_SHELLOUT environment variable is
// set, so a script can never shell out silently.
func (b *scriptBinding) AllowShellOut() bool {
	if b.s.AllowShellOut {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv(interpreter.AllowShellOutEnv))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// AuditEvent records a security-relevant script event in the shared session
// event contract (used for shell-out).
func (b *scriptBinding) AuditEvent(kind, detail string) {
	b.s.Store.LogEvent(kind, detail)
}

// prop resolves live session state for $(...) interpolation.
func (b *scriptBinding) prop(name string) (string, bool) {
	s := b.s
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

// RunScript executes a script file through the shared qyvora-script engine.
func (s *Session) RunScript(path string) error {
	e := interpreter.NewEngine(s.ScriptBinding())
	e.Events = consoleEventWriter{s: s}
	return e.RunFile(path)
}

// BuildScript parses a script file and prints a dry-run plan of what it would
// do. It never touches the network.
func (s *Session) BuildScript(path string) error {
	data, err := readCaplet(path)
	if err != nil {
		return err
	}
	prog, err := parser.Parse(string(data))
	if err != nil {
		return err
	}
	s.UI.Section("script plan " + path)
	for _, line := range ast.Describe(prog) {
		s.UI.Status("-", "%s", line)
	}
	return nil
}

// consoleEventWriter adapts the session's human writer so the engine's JSONL
// shell-out events land in the operator's console stream. The structured
// session event log is handled separately by the binding's AuditEvent.
type consoleEventWriter struct{ s *Session }

func (w consoleEventWriter) Write(p []byte) (int, error) {
	if w.s.Out == nil {
		return len(p), nil
	}
	return w.s.Out.Write(p)
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
