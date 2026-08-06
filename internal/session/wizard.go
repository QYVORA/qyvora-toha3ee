package session

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/chzyer/readline"

	"github.com/qyvora/toha3ee/internal/attacks"
	"github.com/qyvora/toha3ee/internal/vectors"
)

// WizardWithStdin runs the wizard against a fresh readline instance so the
// "toha3ee wizard" subcommand works outside the REPL.
func (s *Session) WizardWithStdin() error {
	rl, err := readline.NewEx(&readline.Config{
		Prompt:      "wizard> ",
		HistoryFile: ".toha3ee_history",
	})
	if err != nil {
		return err
	}
	defer rl.Close()
	return s.Wizard(rl)
}

// Wizard guides the user through recon → vector analysis → module launch.
func (s *Session) Wizard(rl *readline.Instance) error {
	ask := func(prompt, def string) string {
		line, err := rl.ReadlineWithDefault(prompt)
		if err != nil {
			return def
		}
		line = strings.TrimSpace(line)
		if line == "" {
			return def
		}
		return line
	}

	fmt.Fprintln(s.Out, "== toha3ee wizard ==")
	fmt.Fprintf(s.Out, "Interface: %s  (%s)\n", s.Iface.Name, s.Iface.IP)

	if ans := strings.ToLower(ask("Run a network sweep (net.scan for ~10s)? [Y/n]: ", "y")); !strings.HasPrefix(ans, "n") {
		fmt.Fprintln(s.Out, "[*] sweeping subnet (10s)...")
		if err := s.StartModule("net.scan", nil); err != nil {
			return err
		}
		time.Sleep(10 * time.Second)
		_ = s.StopModule("net.scan")
		fmt.Fprintf(s.Out, "[*] %d host(s) discovered.\n", len(s.Store.Hosts()))
	}

	if ans := strings.ToLower(ask("Run a passive HTTP/LLMNR probe for ~15s? [Y/n]: ", "y")); !strings.HasPrefix(ans, "n") {
		fmt.Fprintln(s.Out, "[*] probing network traffic (15s)...")
		if err := s.StartModule("http.harvest", nil); err != nil {
			fmt.Fprintf(s.Out, "[!] probe: %v\n", err)
		} else {
			time.Sleep(15 * time.Second)
			_ = s.StopModule("http.harvest")
		}
	}

	profile := vectors.BuildProfile(s.Store, s.Iface)
	engine := vectors.NewEngine(s.metaResolver())
	vectorsList := engine.Analyze(profile)

	fmt.Fprintf(s.Out, "\n== network profile ==\n")
	fmt.Fprintf(s.Out, "hosts: %d | gateway: %v | plaintext HTTP: %v | LLMNR: %v | SMB: %v | DHCPv6: %v | monitor: %v\n",
		len(profile.Hosts), gatewayStr(profile), profile.SeesPlainHTTP, profile.SeesLLMNR,
		profile.SeesSMB, profile.SeesDHCPv6, profile.MonitorCapable)

	fmt.Fprintf(s.Out, "\n== ranked attack vectors ==\n")
	if len(vectorsList) == 0 {
		fmt.Fprintln(s.Out, "no viable vectors; run recon first")
		return nil
	}
	for i, v := range vectorsList {
		sat := ""
		if !engine.Satisfiable(profile, v) {
			sat = "  [not satisfiable]"
		}
		fmt.Fprintf(s.Out, "%2d. %-24s target=%-18s conf=%.2f risk=%-8s%s\n      %s\n",
			i+1, v.ModuleID, v.Target, v.Confidence, v.Risk, sat, v.Impact)
	}

	sel := ask("\nPick vector number to launch (comma list, 'all', or blank to skip): ", "")
	if sel == "" {
		fmt.Fprintln(s.Out, "wizard done (nothing launched)")
		return nil
	}

	indexes := parseSelection(sel, len(vectorsList))
	if indexes == nil && strings.EqualFold(sel, "all") {
		for i := range vectorsList {
			indexes = append(indexes, i)
		}
	}

	for _, idx := range indexes {
		v := vectorsList[idx]
		if !engine.Satisfiable(profile, v) {
			fmt.Fprintf(s.Out, "[!] skipping %s (prerequisites not satisfiable)\n", v.ModuleID)
			continue
		}
		if err := s.launchVector(v, ask); err != nil {
			fmt.Fprintf(s.Out, "[!] %s: %v\n", v.ModuleID, err)
		}
	}
	fmt.Fprintln(s.Out, "\nwizard done. Use 'status' to see running modules, 'creds.show' for loot.")
	return nil
}

// launchVector applies module-specific wizard defaults and starts the module.
func (s *Session) launchVector(v vectors.Vector, ask func(string, string) string) error {
	meta, _ := attacks.Get(v.ModuleID)
	_ = meta

	switch v.ModuleID {
	case "arp.spoof":
		if s.Conf.Get("arp.spoof", "targets") == "" {
			s.Conf.Set("arp.spoof", "targets", s.Iface.CIDR())
		}
		if s.Conf.Get("arp.spoof", "internal") == "" {
			s.Conf.Set("arp.spoof", "internal", "false")
		}
	case "dns.spoof":
		if s.Conf.Get("dns.spoof", "domains") == "" {
			domains := ask("Domain(s) to spoof (comma list; blank = all queries): ", "")
			if domains == "" {
				s.Conf.Set("dns.spoof", "all", "true")
			} else {
				s.Conf.Set("dns.spoof", "domains", domains)
			}
		}
	case "phish.inject":
		if s.Conf.Get("phish.inject", "brand") == "" {
			brand := ask("Phishing brand (facebook, google, microsoft, generic, router, captiveportal): ", "generic")
			s.Conf.Set("phish.inject", "brand", brand)
		}
	}

	if ans := strings.ToLower(ask(fmt.Sprintf("Launch %s? [Y/n]: ", v.ModuleID), "y")); strings.HasPrefix(ans, "n") {
		return nil
	}

	if parseRisk(v.Risk) >= attacks.RiskHigh {
		s.Conf.ConfirmRisk(v.ModuleID)
	}
	return s.StartModule(v.ModuleID, nil)
}

// metaResolver adapts the attacks registry to the vector engine.
func (s *Session) metaResolver() vectors.MetaResolver {
	return func(id string) (vectors.MetaInfo, bool) {
		m, ok := attacks.Get(id)
		if !ok {
			return vectors.MetaInfo{}, false
		}
		meta := m.Meta()
		return vectors.MetaInfo{
			Category:    meta.Category,
			Risk:        meta.Risk.String(),
			Targets:     meta.Targets,
			Requires:    meta.Requires,
			Passive:     meta.Passive,
			Description: meta.Description,
			Limitations: meta.Limitations,
		}, true
	}
}

func parseRisk(s string) attacks.Risk {
	return attacks.ParseRisk(s)
}

// parseSelection converts "1,3,5" into zero-based indexes; nil when invalid.
func parseSelection(sel string, n int) []int {
	var out []int
	for _, tok := range strings.Split(sel, ",") {
		tok = strings.TrimSpace(tok)
		i, err := strconv.Atoi(tok)
		if err != nil || i < 1 || i > n {
			return nil
		}
		out = append(out, i-1)
	}
	return out
}

func gatewayStr(p *vectors.Profile) string {
	if p.Gateway == nil {
		return "unknown"
	}
	return p.Gateway.IP.String()
}
