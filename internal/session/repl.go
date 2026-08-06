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
		Prompt:      s.UI.BoldWhite("toha3ee> "),
		HistoryFile: ".toha3ee_history",
		AutoComplete: readline.NewPrefixCompleter(
			commandsCompleter()...,
		),
	})
	if err != nil {
		return err
	}
	defer rl.Close()

	s.UI.Banner("network exploitation & MITM framework")
	s.UI.BannerFoot(s.Iface.String(), versionString())
	s.statusf("session ready. type 'help' for commands.")
	s.Store.LogEvent(events.TopicLog, "console started")

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
			s.warnf("%v", e)
		} else if quit {
			return nil
		}
	}
}

var errQuit = fmt.Errorf("quit")

// versionString returns the build version (injected by the CLI at build time).
func versionString() string {
	return Version
}

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
		s.UI.Clear()
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
	type grp struct {
		name string
		cmds [][2]string
	}
	groups := []grp{
		{"Core", [][2]string{
			{"on <module> [k v ...]", "start a module (e.g. \"on arp.spoof\")"},
			{"off <module>", "stop a running module"},
			{"status", "list running modules"},
			{"set <module.key> <val>", "set a config value (e.g. \"set arp.spoof.targets 192.168.8.0/24\")"},
			{"get <module.key>", "show a config value"},
			{"config", "dump the current configuration"},
		}},
		{"Modules", [][2]string{
			{"modules [category]", "list all modules (optionally filtered by category)"},
			{"show <module>", "module metadata + preflight summary"},
			{"module on|off [k v ...]", "start/stop a module by its id"},
		}},
		{"Recon", [][2]string{
			{"net.show", "discovered hosts"},
			{"net.recon", "start passive HTTP/credential sniffing"},
			{"net.profile", "network profile + ranked attack vectors"},
			{"vectors.show", "show ranked attack vectors for the current profile"},
		}},
		{"Loot", [][2]string{
			{"events.show [n]", "recent framework events"},
			{"creds.show", "captured credentials"},
			{"sessions.show", "captured sessions"},
			{"hijack.dump", "dump captured sessions and cookies"},
			{"phish.list", "list available phishing templates"},
			{"phish.serve <template>", "serve a standalone phishing page"},
			{"session.hijack", "manage cookie injection"},
		}},
		{"Automation", [][2]string{
			{"wizard", "guided attack setup"},
			{"report <file>", "write a session report"},
			{"run.caplet <file>", "execute a caplet script"},
			{"sleep <seconds>", "pause before the next command (caplet scripts)"},
			{"quit", "stop everything and exit"},
		}},
	}
	for _, g := range groups {
		s.UI.Section(g.name)
		rows := make([][]string, 0, len(g.cmds))
		for _, item := range g.cmds {
			rows = append(rows, []string{item[0], item[1]})
		}
		s.UI.Table([]string{"command", "description"}, rows)
	}
}

func (s *Session) listModules(args []string) {
	mods := attacks.List()
	if len(args) == 1 {
		mods = attacks.ListByCategory(args[0])
	}
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
		s.UI.Section(c)
		rows := make([][]string, 0, len(byCat[c]))
		for _, m := range byCat[c] {
			meta := m.Meta()
			rows = append(rows, []string{meta.ID, s.UI.RiskLevel(meta.Risk.String()), meta.Description})
		}
		s.UI.Table([]string{"id", "risk", "description"}, rows)
	}
	s.goodf("%d modules listed", len(mods))
}

func (s *Session) showModule(id string) error {
	m, ok := attacks.Get(id)
	if !ok {
		return fmt.Errorf("unknown module %q", id)
	}
	meta := m.Meta()
	s.UI.Section("module " + meta.ID)
	s.UI.KV("category", meta.Category)
	s.UI.KV("risk", s.UI.RiskLevel(meta.Risk.String()))
	if meta.Description != "" {
		s.UI.KV("description", meta.Description)
	}
	if len(meta.Requires) > 0 {
		s.UI.KV("requires", strings.Join(meta.Requires, ", "))
	}
	if meta.Limitations != "" {
		s.UI.KV("limitations", meta.Limitations)
	}
	if meta.Passive {
		s.UI.KV("mode", "passive")
	}
	s.UI.KV("running", strconv.FormatBool(s.IsRunning(id)))
	return nil
}

func (s *Session) status() {
	running := s.Running()
	sort.Strings(running)
	if len(running) == 0 {
		s.UI.Section("running modules")
		s.statusf("no modules running")
		return
	}
	s.UI.Section("running modules")
	rows := make([][]string, 0, len(running))
	for _, id := range running {
		if rm, ok := s.runningModule(id); ok {
			meta, _ := attacks.Get(id)
			rows = append(rows, []string{id, s.UI.RiskLevel(meta.Meta().Risk.String()), rm.started.Format("15:04:05")})
		}
	}
	s.UI.Table([]string{"id", "risk", "started"}, rows)
}

// runningModule returns a live runningModule by id (locked access).
func (s *Session) runningModule(id string) (*runningModule, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rm, ok := s.running[id]
	return rm, ok
}

func (s *Session) setConfig(key, value string) error {
	module, param, ok := splitModuleKey(key)
	if !ok {
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
	s.Conf.Set(module, param, value)
	s.goodf("%s = %s", key, value)
	return nil
}

// splitModuleKey resolves "module.param" by splitting on the last dot so that
// dotted module IDs like "arp.spoof.targets" resolve correctly.
func splitModuleKey(key string) (module, param string, ok bool) {
	for i := len(key) - 1; i > 0; i-- {
		if key[i] == '.' {
			return key[:i], key[i+1:], true
		}
	}
	return "", "", false
}

func (s *Session) getConfig(key string) error {
	module, param, ok := splitModuleKey(key)
	if !ok {
		return fmt.Errorf("config key must be 'module.key'")
	}
	s.UI.KV(key, s.Conf.Get(module, param))
	return nil
}

func (s *Session) showConfig(args []string) {
	mod := ""
	if len(args) > 0 {
		mod = args[0]
	}
	s.UI.Section("configuration")
	rows := make([][]string, 0)
	for _, k := range s.Conf.Keys() {
		if mod != "" && !strings.HasPrefix(k, mod+".") {
			continue
		}
		rows = append(rows, []string{k, s.Conf.GetFromKey(k)})
	}
	s.UI.Table([]string{"key", "value"}, rows)
}

func (s *Session) netShow(args []string) {
	hosts := s.Store.Hosts()
	if len(hosts) == 0 {
		s.UI.Section("net.show")
		s.statusf("no hosts discovered; run 'on net.scan'")
		return
	}
	s.UI.Section("net.show " + strconv.Itoa(len(hosts)) + " hosts")
	rows := make([][]string, 0, len(hosts))
	for _, h := range hosts {
		rows = append(rows, []string{h.IP.String(), h.MAC.String(), h.Vendor, fmt.Sprint(h.OpenPorts())})
	}
	s.UI.Table([]string{"ip", "mac", "vendor", "ports"}, rows)
}

func (s *Session) eventsShow(args []string) {
	n := 20
	if len(args) > 0 {
		if parsed, err := strconv.Atoi(args[0]); err == nil {
			n = parsed
		}
	}
	evs := s.Bus.Recent(n)
	if len(evs) == 0 {
		s.statusf("no events recorded")
		return
	}
	s.UI.Section("events.show")
	rows := make([][]string, 0, len(evs))
	for _, e := range evs {
		msg := ""
		if s, ok := e.Payload.(string); ok {
			msg = s
		}
		rows = append(rows, []string{e.Time.Format("15:04:05"), e.Topic, msg})
	}
	s.UI.Table([]string{"time", "topic", "detail"}, rows)
}

func (s *Session) credsShow(args []string) {
	creds := s.Store.Creds()
	if len(creds) == 0 {
		s.UI.Section("creds.show")
		s.statusf("no credentials captured")
		return
	}
	s.UI.Section("creds.show " + strconv.Itoa(len(creds)) + " entries")
	rows := make([][]string, 0, len(creds))
	for _, c := range creds {
		rows = append(rows, []string{strconv.Itoa(c.ID), c.Service, c.Username, c.Password, c.VictimIP, c.Source})
	}
	s.UI.Table([]string{"id", "service", "username", "password", "victim", "source"}, rows)
}

func (s *Session) sessionsShow() {
	sess := s.Store.Sessions()
	if len(sess) == 0 {
		s.UI.Section("sessions.show")
		s.statusf("no sessions captured")
		return
	}
	s.UI.Section("sessions.show " + strconv.Itoa(len(sess)) + " sessions")
	rows := make([][]string, 0, len(sess))
	for _, ss := range sess {
		var cookies []string
		for k := range ss.Cookies {
			cookies = append(cookies, k)
		}
		rows = append(rows, []string{strconv.Itoa(ss.ID), ss.VictimIP, ss.Host, strings.Join(cookies, " ")})
	}
	s.UI.Table([]string{"id", "victim", "host", "cookies"}, rows)
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

	gw := "unknown"
	if profile.Gateway != nil {
		gw = profile.Gateway.IP.String()
	}
	s.UI.Section("network profile")
	s.UI.KV("hosts", strconv.Itoa(len(profile.Hosts)))
	s.UI.KV("gateway", gw)
	s.UI.KV("plaintext http", strconv.FormatBool(profile.SeesPlainHTTP))
	s.UI.KV("llmnr", strconv.FormatBool(profile.SeesLLMNR))
	s.UI.KV("smb", strconv.FormatBool(profile.SeesSMB))
	s.UI.KV("dhcpv6", strconv.FormatBool(profile.SeesDHCPv6))
	s.UI.KV("monitor", strconv.FormatBool(profile.MonitorCapable))

	if len(profile.Hosts) > 0 {
		rows := make([][]string, 0, len(profile.Hosts))
		for _, h := range profile.Hosts {
			ports := make([]uint16, 0, len(h.Ports))
			for p := range h.Ports {
				ports = append(ports, p)
			}
			rows = append(rows, []string{h.IP.String(), h.MAC.String(), h.Vendor, fmt.Sprint(ports)})
		}
		s.UI.Table([]string{"ip", "mac", "vendor", "ports"}, rows)
	}

	s.UI.Section("ranked attack vectors")
	if len(vecs) == 0 {
		s.statusf("no viable vectors; run net.scan or net.recon first")
		return
	}
	s.printVectors(vecs, engine, profile)
}

// printVectors renders a ranked vector list with confidence and satisfiability.
func (s *Session) printVectors(vecs []vectors.Vector, engine *vectors.Engine, profile *vectors.Profile) {
	rows := make([][]string, 0, len(vecs))
	for i, v := range vecs {
		sat := "yes"
		if !engine.Satisfiable(profile, v) {
			sat = s.UI.Amber("no")
		}
		rows = append(rows, []string{
			strconv.Itoa(i + 1),
			v.ModuleID,
			v.Target,
			fmt.Sprintf("%.2f", v.Confidence),
			s.UI.RiskLevel(v.Risk),
			sat,
		})
	}
	s.UI.Table([]string{"#", "module", "target", "conf", "risk", "satisfiable"}, rows)
	for i, v := range vecs {
		if v.Impact != "" {
			fmt.Fprintf(s.Out, "  %s %s\n", s.UI.DimWhite(strconv.Itoa(i+1)+"."), s.UI.White(v.Impact))
		}
	}
}

// vectorsShow is a standalone command to display ranked attack vectors.
func (s *Session) vectorsShow() {
	profile := vectors.BuildProfile(s.Store, s.Iface)
	engine := vectors.NewEngine(s.metaResolver())
	vecs := engine.Analyze(profile)

	if len(vecs) == 0 {
		s.UI.Section("vectors.show")
		s.statusf("no vectors available; run net.scan or net.recon first")
		return
	}
	s.UI.Section("ranked attack vectors")
	s.printVectors(vecs, engine, profile)
}

// phishList displays all available phishing templates.
func (s *Session) phishList() {
	templates := phish.ListTemplates()
	if len(templates) == 0 {
		s.statusf("no phishing templates available")
		return
	}
	s.UI.Section("phishing templates")
	rows := make([][]string, 0, len(templates))
	for _, t := range templates {
		rows = append(rows, []string{t.ID, t.Title, t.Description})
	}
	s.UI.Table([]string{"id", "title", "description"}, rows)
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
	s.statusf("phish.serve: serving %s on http://%s/phish/%s", templateID, addr, templateID)
	s.statusf("open in victim browser: http://%s/phish/%s", addr, templateID)
	_ = html
	return nil
}

// hijackDump displays captured sessions and cookies.
func (s *Session) hijackDump() {
	sess := s.Store.Sessions()
	if len(sess) == 0 {
		s.UI.Section("hijack.dump")
		s.statusf("no sessions captured")
		return
	}
	s.UI.Section("hijack.dump " + strconv.Itoa(len(sess)) + " sessions")
	rows := make([][]string, 0, len(sess))
	for _, ss := range sess {
		var cookies []string
		for k, v := range ss.Cookies {
			cookies = append(cookies, k+"="+v)
		}
		if len(cookies) == 0 && ss.AuthHeader != "" {
			cookies = append(cookies, "Authorization: "+ss.AuthHeader)
		}
		rows = append(rows, []string{strconv.Itoa(ss.ID), ss.VictimIP, ss.Host, strings.Join(cookies, " ")})
	}
	s.UI.Table([]string{"id", "victim", "host", "cookies"}, rows)
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
		s.echoCommand(line)
		if _, err := s.exec(nil, line); err != nil {
			return err
		}
	}
	return nil
}

// echoCommand prints a command being executed (caplets and eval mode).
func (s *Session) echoCommand(line string) {
	fmt.Fprintf(s.Out, "  %s %s\n", s.UI.Glyph(">"), s.UI.White(line))
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
		s.echoCommand(line)
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
