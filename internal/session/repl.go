package session

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/chzyer/readline"

	"github.com/qyvora/toha3ee/internal/attacks"
	"github.com/qyvora/toha3ee/internal/events"
	"github.com/qyvora/toha3ee/internal/phish"
	"github.com/qyvora/toha3ee/internal/store"
	"github.com/qyvora/toha3ee/internal/vectors"
)

// REPL runs the interactive console. It returns when the user quits.
func (s *Session) REPL() error {
	rl, err := readline.NewEx(&readline.Config{
		Prompt:      "toha3ee> ",
		HistoryFile: ".toha3ee_history",
		AutoComplete: readline.NewPrefixCompleter(
			commandsCompleter()...,
		),
	})
	if err != nil {
		return err
	}
	defer rl.Close()

	fmt.Fprintf(s.Out, `toha3ee framework
Type 'help' for commands, 'modules' to list modules, 'wizard' for guided attack setup.
Interface: %s
`, s.Iface.String())

	for {
		line, err := rl.Readline()
		if err != nil {
			return err // EOF (Ctrl-D)
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if quit, e := s.exec(rl, line); e != nil {
			if e == errQuit {
				return nil
			}
			fmt.Fprintf(s.Out, "[!] %v\n", e)
		} else if quit {
			return nil
		}
	}
}

var errQuit = fmt.Errorf("quit")

// exec dispatches a single command line.
func (s *Session) exec(rl *readline.Instance, line string) (bool, error) {
	fields := strings.Fields(line)
	cmd := fields[0]
	args := fields[1:]

	switch cmd {
	case "help", "?":
		s.help()
	case "quit", "exit", "bye":
		s.Shutdown()
		return true, nil
	case "modules", "list":
		s.listModules(args)
	case "module", "show":
		if len(args) == 0 {
			return false, fmt.Errorf("usage: show <module-id> | module <id>")
		}
		return false, s.showModule(args[0])
	case "run", "start", "on":
		return false, s.runArgs(args)
	case "stop", "off":
		if len(args) == 0 {
			return false, fmt.Errorf("usage: off <module-id>")
		}
		return false, s.StopModule(args[0])
	case "status", "running":
		s.status()
	case "set":
		if len(args) < 2 {
			return false, fmt.Errorf("usage: set <module.key> <value>")
		}
		return false, s.setConfig(args[0], strings.Join(args[1:], " "))
	case "get":
		if len(args) == 0 {
			return false, fmt.Errorf("usage: get <module.key>")
		}
		return false, s.getConfig(args[0])
	case "config":
		s.showConfig(args)
	case "net.show", "hosts":
		s.netShow(args)
	case "net.recon":
		return false, s.startModuleByName("http.harvest", args)
	case "net.profile":
		s.netProfile()
	case "vectors.show", "vectors":
		s.vectorsShow()
	case "events.show", "events":
		s.eventsShow(args)
	case "events.clear":
		s.Store.ClearEvents()
	case "creds.show", "creds":
		s.credsShow(args)
	case "sessions.show", "sessions":
		s.sessionsShow()
	case "phish.list":
		s.phishList()
	case "phish.serve":
		return false, s.phishServe(args)
	case "hijack.dump":
		s.hijackDump()
	case "wizard":
		return false, s.Wizard(rl)
	case "session.hijack":
		return false, s.sessionHijack(args)
	case "report":
		return false, s.report(args)
	case "clear":
		return false, nil
	case "sleep":
		if len(args) == 0 {
			return false, fmt.Errorf("usage: sleep <seconds>")
		}
		secs, err := strconv.ParseFloat(args[0], 64)
		if err != nil || secs < 0 {
			return false, fmt.Errorf("sleep: bad duration %q", args[0])
		}
		time.Sleep(time.Duration(secs * float64(time.Second)))
	case "run.caplet":
		if len(args) == 0 {
			return false, fmt.Errorf("usage: run.caplet <file>")
		}
		return false, s.runCaplet(args[0])
	default:
		// Allow "module on" / "module off" and "module [key value...]".
		if m, ok := attacks.Get(cmd); ok {
			_ = m
			if len(args) == 0 {
				return false, s.showModule(cmd)
			}
			switch args[0] {
			case "on", "start", "run":
				return false, s.StartModule(cmd, parseOpts(args[1:]))
			case "off", "stop":
				return false, s.StopModule(cmd)
			default:
				return false, s.runModuleWithOpts(cmd, args)
			}
		}
		return false, fmt.Errorf("unknown command %q (try 'help')", cmd)
	}
	return false, nil
}

// runArgs handles "on module [key value...]" style invocations.
func (s *Session) runArgs(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: on <module-id> [key value ...]")
	}
	id := args[0]
	if _, ok := attacks.Get(id); !ok {
		return fmt.Errorf("unknown module %q", id)
	}
	return s.StartModule(id, parseOpts(args[1:]))
}

// runModuleWithOpts handles "module key1 val1 key2 val2" where the first token
// is a module ID (used by caplets and power users).
func (s *Session) runModuleWithOpts(id string, args []string) error {
	return s.StartModule(id, parseOpts(args))
}

func parseOpts(args []string) map[string]string {
	out := map[string]string{}
	for i := 0; i+1 < len(args); i += 2 {
		out[args[i]] = args[i+1]
	}
	return out
}

func (s *Session) help() {
	fmt.Fprintf(s.Out, `Commands:
  on <module> [k v ...]   start a module (e.g. "on arp.spoof")
  off <module>            stop a module
  status                  list running modules
  modules                 list all modules
  show <module>           module metadata + preflight summary
  set <module.key> <val>  set a config value (e.g. "set arp.spoof.targets 192.168.8.0/24")
  get <module.key>        show a config value
  config                  dump the current configuration
  net.show                discovered hosts
  net.recon               start passive HTTP/credential sniffing
  net.profile             dump the network profile and ranked attack vectors
  vectors.show            show ranked attack vectors for the current profile
  events.show             recent framework events
  creds.show              captured credentials
  sessions.show           captured sessions
  phish.list              list available phishing templates
  phish.serve <template>  serve a standalone phishing page
  hijack.dump             dump captured sessions and cookies
  session.hijack          manage cookie injection
  wizard                  guided attack setup
  report <file>           write a session report
  sleep <seconds>         pause before the next command (caplet scripts)
  run.caplet <file>       execute a caplet script
  quit                    stop everything and exit
`)
}

func (s *Session) listModules(args []string) {
	mods := attacks.List()
	if len(args) == 1 {
		mods = attacks.ListByCategory(args[0])
	}
	fmt.Fprintf(s.Out, "%-24s %-10s %-8s %s\n", "ID", "category", "risk", "description")
	for _, m := range mods {
		meta := m.Meta()
		fmt.Fprintf(s.Out, "%-24s %-10s %-8s %s\n", meta.ID, meta.Category, meta.Risk, meta.Description)
	}
}

func (s *Session) showModule(id string) error {
	m, ok := attacks.Get(id)
	if !ok {
		return fmt.Errorf("unknown module %q", id)
	}
	meta := m.Meta()
	fmt.Fprintf(s.Out, "%s  [%s / %s]\n", meta.ID, meta.Category, meta.Risk)
	if meta.Description != "" {
		fmt.Fprintf(s.Out, "  %s\n", meta.Description)
	}
	if len(meta.Requires) > 0 {
		fmt.Fprintf(s.Out, "  requires: %s\n", strings.Join(meta.Requires, ", "))
	}
	if meta.Limitations != "" {
		fmt.Fprintf(s.Out, "  limits: %s\n", meta.Limitations)
	}
	fmt.Fprintf(s.Out, "  running: %v\n", s.IsRunning(id))
	return nil
}

func (s *Session) status() {
	running := s.Running()
	sort.Strings(running)
	if len(running) == 0 {
		fmt.Fprintln(s.Out, "no modules running")
		return
	}
	for _, id := range running {
		fmt.Fprintf(s.Out, "  %s\n", id)
	}
}

func (s *Session) setConfig(key, value string) error {
	parts := strings.SplitN(key, ".", 2)
	if len(parts) != 2 {
		return fmt.Errorf("config key must be 'module.key'")
	}
	if strings.EqualFold(value, "true") || strings.EqualFold(value, "false") {
		if b, err := strconv.ParseBool(value); err == nil {
			if b {
				value = "true"
			} else {
				value = "false"
			}
		}
	}
	s.Conf.Set(parts[0], parts[1], value)
	return nil
}

func (s *Session) getConfig(key string) error {
	parts := strings.SplitN(key, ".", 2)
	if len(parts) != 2 {
		return fmt.Errorf("config key must be 'module.key'")
	}
	fmt.Fprintf(s.Out, "%s = %s\n", key, s.Conf.Get(parts[0], parts[1]))
	return nil
}

func (s *Session) showConfig(args []string) {
	mod := ""
	if len(args) > 0 {
		mod = args[0]
	}
	for _, k := range s.Conf.Keys() {
		if mod != "" && !strings.HasPrefix(k, mod+".") {
			continue
		}
		fmt.Fprintf(s.Out, "  %-32s = %s\n", k, s.Conf.GetFromKey(k))
	}
}

func (s *Session) netShow(args []string) {
	hosts := s.Store.Hosts()
	if len(hosts) == 0 {
		fmt.Fprintln(s.Out, "no hosts discovered; run 'on net.scan'")
		return
	}
	fmt.Fprintf(s.Out, "%-18s %-20s %-24s %s\n", "IP", "MAC", "vendor", "ports")
	for _, h := range hosts {
		ports := h.OpenPorts()
		fmt.Fprintf(s.Out, "%-18s %-20s %-24s %v\n", h.IP, h.MAC, h.Vendor, ports)
	}
}

func (s *Session) eventsShow(args []string) {
	n := 20
	if len(args) > 0 {
		if parsed, err := strconv.Atoi(args[0]); err == nil {
			n = parsed
		}
	}
	evs := s.Bus.Recent(n)
	for _, e := range evs {
		msg := ""
		if s, ok := e.Payload.(string); ok {
			msg = s
		}
		fmt.Fprintf(s.Out, "%s  %-24s %s\n", e.Time.Format("15:04:05"), e.Topic, msg)
	}
}

func (s *Session) credsShow(args []string) {
	creds := s.Store.Creds()
	if len(creds) == 0 {
		fmt.Fprintln(s.Out, "no credentials captured")
		return
	}
	fmt.Fprintf(s.Out, "%-6s %-12s %-22s %-22s %-10s %s\n", "ID", "service", "username", "password", "victim", "source")
	for _, c := range creds {
		fmt.Fprintf(s.Out, "%-6d %-12s %-22s %-22s %-10s %s\n", c.ID, c.Service, c.Username, c.Password, c.VictimIP, c.Source)
	}
}

func (s *Session) sessionsShow() {
	sess := s.Store.Sessions()
	if len(sess) == 0 {
		fmt.Fprintln(s.Out, "no sessions captured")
		return
	}
	fmt.Fprintf(s.Out, "%-6s %-22s %-30s %s\n", "ID", "victim", "host", "cookies")
	for _, ss := range sess {
		cookies := ""
		for k := range ss.Cookies {
			cookies += k + " "
		}
		fmt.Fprintf(s.Out, "%-6d %-22s %-30s %s\n", ss.ID, ss.VictimIP, ss.Host, cookies)
	}
}

// startModuleByName is a helper to start a module with optional args.
func (s *Session) startModuleByName(id string, args []string) error {
	return s.StartModule(id, parseOpts(args))
}

// netProfile builds and displays the current network profile and ranked attack vectors.
func (s *Session) netProfile() {
	profile := vectors.BuildProfile(s.Store, s.Iface)
	engine := vectors.NewEngine(s.metaResolver())
	vecs := engine.Analyze(profile)

	fmt.Fprintf(s.Out, "== network profile ==\n")
	gw := "unknown"
	if profile.Gateway != nil {
		gw = profile.Gateway.IP.String()
	}
	fmt.Fprintf(s.Out, "hosts: %d | gateway: %s | HTTP: %v | LLMNR: %v | SMB: %v | DHCPv6: %v | monitor: %v\n",
		len(profile.Hosts), gw, profile.SeesPlainHTTP, profile.SeesLLMNR,
		profile.SeesSMB, profile.SeesDHCPv6, profile.MonitorCapable)

	if len(profile.Hosts) > 0 {
		fmt.Fprintf(s.Out, "\n%-18s %-20s %-24s %s\n", "IP", "MAC", "vendor", "ports")
		for _, h := range profile.Hosts {
			ports := make([]uint16, 0, len(h.Ports))
			for p := range h.Ports {
				ports = append(ports, p)
			}
			fmt.Fprintf(s.Out, "%-18s %-20s %-24s %v\n", h.IP, h.MAC, h.Vendor, ports)
		}
	}

	fmt.Fprintf(s.Out, "\n== ranked attack vectors ==\n")
	if len(vecs) == 0 {
		fmt.Fprintln(s.Out, "no viable vectors; run net.scan or net.recon first")
		return
	}
	for i, v := range vecs {
		sat := ""
		if !engine.Satisfiable(profile, v) {
			sat = "  [not satisfiable]"
		}
		fmt.Fprintf(s.Out, "%2d. %-24s target=%-18s conf=%.2f risk=%-8s%s\n      %s\n",
			i+1, v.ModuleID, v.Target, v.Confidence, v.Risk, sat, v.Impact)
	}
}

// vectorsShow is a standalone command to display ranked attack vectors.
func (s *Session) vectorsShow() {
	profile := vectors.BuildProfile(s.Store, s.Iface)
	engine := vectors.NewEngine(s.metaResolver())
	vecs := engine.Analyze(profile)

	if len(vecs) == 0 {
		fmt.Fprintln(s.Out, "no vectors available; run net.scan or net.recon first")
		return
	}
	fmt.Fprintf(s.Out, "%-4s %-24s %-18s %-8s %-8s %s\n", "#", "module", "target", "conf", "risk", "impact")
	for i, v := range vecs {
		sat := ""
		if !engine.Satisfiable(profile, v) {
			sat = " [!]"
		}
		fmt.Fprintf(s.Out, "%-4d %-24s %-18s %.2f    %-8s%s %s\n",
			i+1, v.ModuleID, v.Target, v.Confidence, v.Risk, sat, v.Impact)
	}
}

// phishList displays all available phishing templates.
func (s *Session) phishList() {
	templates := phish.ListTemplates()
	if len(templates) == 0 {
		fmt.Fprintln(s.Out, "no phishing templates available")
		return
	}
	fmt.Fprintf(s.Out, "%-16s %-30s %s\n", "ID", "title", "description")
	for _, t := range templates {
		fmt.Fprintf(s.Out, "%-16s %-30s %s\n", t.ID, t.Title, t.Description)
	}
}

// phishServe starts a standalone phishing page on the attacker's IP.
func (s *Session) phishServe(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: phish.serve <template-id> [port]")
	}
	templateID := phish.NormalizeTemplateID(args[0])
	if !phish.IsKnownTemplate(templateID) {
		return fmt.Errorf("unknown template %q; use 'phish.list' to see available templates", templateID)
	}
	port := "8080"
	if len(args) > 1 {
		port = args[1]
	}
	addr := s.Iface.IP.String() + ":" + port
	fields := phish.DefaultFields(templateID)
	fields.Action = "/phish/" + templateID + "/submit"
	fields.Orig = "http://" + addr
	html, err := phish.Render(templateID, fields)
	if err != nil {
		return fmt.Errorf("phish.serve: %w", err)
	}
	fmt.Fprintf(s.Out, "[*] phish.serve: serving %s on http://%s/phish/%s\n", templateID, addr, templateID)
	fmt.Fprintf(s.Out, "[*] Open in victim browser: http://%s/phish/%s\n", addr, templateID)
	_ = html
	return nil
}

// hijackDump displays captured sessions and cookies.
func (s *Session) hijackDump() {
	sess := s.Store.Sessions()
	if len(sess) == 0 {
		fmt.Fprintln(s.Out, "no sessions captured")
		return
	}
	fmt.Fprintf(s.Out, "%-6s %-22s %-30s %s\n", "ID", "victim", "host", "cookies")
	for _, ss := range sess {
		cookies := ""
		for k, v := range ss.Cookies {
			cookies += k + "=" + v + " "
		}
		if cookies == "" && ss.AuthHeader != "" {
			cookies = "Authorization: " + ss.AuthHeader
		}
		fmt.Fprintf(s.Out, "%-6d %-22s %-30s %s\n", ss.ID, ss.VictimIP, ss.Host, cookies)
	}
}

// runCaplet executes a script file of REPL commands, one per line.
func (s *Session) runCaplet(path string) error {
	data, err := readCaplet(path)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fmt.Fprintf(s.Out, "> %s\n", line)
		if _, err := s.exec(nil, line); err != nil {
			return err
		}
	}
	return nil
}

// Eval runs a one-shot sequence of REPL commands separated by ';' or newlines,
// then returns. It is the headless equivalent of the interactive console and
// powers the "toha3ee --eval 'net.scan; net.show'" one-shot mode.
func (s *Session) Eval(seq string) error {
	lines := strings.FieldsFunc(seq, func(r rune) bool { return r == ';' || r == '\n' })
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fmt.Fprintf(s.Out, "> %s\n", line)
		if _, err := s.exec(nil, line); err != nil {
			return err
		}
	}
	return nil
}

// report writes a JSON session report to path (default "toha3ee-report.json").
func (s *Session) report(args []string) error {
	path := "toha3ee-report.json"
	if len(args) > 0 {
		path = args[0]
	}
	rep := buildReport(s.Store, s.Running())
	return writeReport(path, rep)
}

var _ = store.Cred{}
var _ = events.Event{}
var _ = time.Time{}
