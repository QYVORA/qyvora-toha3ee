package session

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/chzyer/readline"

	"github.com/QYVORA/qyvora-toha3ee/internal/attacks"
	"github.com/QYVORA/qyvora-toha3ee/internal/vectors"
)

// WizardWithStdin runs the wizard against a fresh readline instance so the
// "toha3ee wizard" subcommand works outside the REPL.
func (s *Session) WizardWithStdin() error {
	rl, err := readline.NewEx(&readline.Config{
		Prompt:      s.UI.BoldWhite("wizard> "),
		HistoryFile: ".toha3ee_history",
	})
	if err != nil {
		return err
	}
	defer func() { _ = rl.Close() }()
	return s.Wizard(rl)
}

// Wizard guides the user through recon → vector analysis → module launch.
func (s *Session) Wizard(rl *readline.Instance) error {
	// ask prompts for input with a visible default; pressing Enter or
	// encountering EOF falls back to the default.
	ask := func(prompt, def string) string {
		line, err := rl.ReadlineWithDefault(s.UI.White(prompt + " "))
		if err != nil {
			return def
		}
		line = strings.TrimSpace(line)
		if line == "" {
			return def
		}
		return line
	}

	s.UI.Banner("guided attack wizard")
	s.UI.BannerFoot(s.Iface.String(), versionString())

	// Step 1: an optional subnet sweep (host discovery) for ~10s.
	if ans := strings.ToLower(ask("Run a network sweep (net.scan for ~10s)? [Y/n]: ", "y")); !strings.HasPrefix(ans, "n") {
		s.statusf("sweeping subnet (10s)...")
		if err := s.StartModule("net.scan", nil); err != nil {
			return err
		}
		time.Sleep(10 * time.Second)
		_ = s.StopModule("net.scan")
		s.goodf("%d host(s) discovered.", len(s.Store.Hosts()))
	}

	// Step 2: an optional passive HTTP/LLMNR probe for ~15s.
	if ans := strings.ToLower(ask("Run a passive HTTP/LLMNR probe for ~15s? [Y/n]: ", "y")); !strings.HasPrefix(ans, "n") {
		s.statusf("probing network traffic (15s)...")
		if err := s.StartModule("http.harvest", nil); err != nil {
			// The probe is optional; a failure here only warns and the
			// wizard continues with whatever was already discovered.
			s.warnf("probe: %v", err)
		} else {
			time.Sleep(15 * time.Second)
			_ = s.StopModule("http.harvest")
		}
	}

	// Step 3: deep, procedural service recon. The wizard's default path now
	// progresses beyond host discovery into service.synscan → service.fingerprint
	// and then into protocol enumeration for whatever services it finds, so the
	// profile and vectors below are built from real service knowledge rather
	// than host presence alone.
	if ans := strings.ToLower(ask("Run deep service recon (synscan → fingerprint → enum)? [Y/n]: ", "y")); !strings.HasPrefix(ans, "n") {
		if err := s.runReconChain(); err != nil {
			s.warnf("deep recon: %v", err)
		}
	}

	// Build the network profile and ranked attack vectors from the loot
	// gathered in the recon steps above.
	profile := vectors.BuildProfile(s.Store, s.Iface)
	engine := vectors.NewEngine(s.metaResolver())
	vectorsList := engine.Analyze(profile)

	s.UI.Section("network profile")
	s.UI.KV("hosts", strconv.Itoa(len(profile.Hosts)))
	s.UI.KV("gateway", gatewayStr(profile))
	s.UI.KV("plaintext http", strconv.FormatBool(profile.SeesPlainHTTP))
	s.UI.KV("llmnr", strconv.FormatBool(profile.SeesLLMNR))
	s.UI.KV("smb", strconv.FormatBool(profile.SeesSMB))
	s.UI.KV("dhcpv6", strconv.FormatBool(profile.SeesDHCPv6))
	s.UI.KV("monitor", strconv.FormatBool(profile.MonitorCapable))

	s.UI.Section("ranked attack vectors")
	if len(vectorsList) == 0 {
		s.statusf("no viable vectors; run recon first")
		return nil
	}
	s.printVectors(vectorsList, engine, profile)

	// Step 3: the user picks which vectors to launch, by index, "all", or none.
	sel := ask("\nPick vector number to launch (comma list, 'all', or blank to skip): ", "")
	if sel == "" {
		s.statusf("wizard done (nothing launched)")
		return nil
	}

	indexes := parseSelection(sel, len(vectorsList))
	if indexes == nil && strings.EqualFold(sel, "all") {
		// "all" expands to every vector index (1-based → 0-based).
		for i := range vectorsList {
			indexes = append(indexes, i)
		}
	}

	for _, idx := range indexes {
		v := vectorsList[idx]
		// Skip vectors whose prerequisites cannot currently be satisfied
		// rather than letting StartModule fail with a confusing error.
		if !engine.Satisfiable(profile, v) {
			s.warnf("skipping %s (prerequisites not satisfiable)", v.ModuleID)
			continue
		}
		if err := s.launchVector(v, ask); err != nil {
			s.warnf("%s: %v", v.ModuleID, err)
		}
	}
	s.goodf("wizard done. use 'status' to see running modules, 'creds.show' for loot.")
	return nil
}

// launchVector applies module-specific wizard defaults and starts the module.
func (s *Session) launchVector(v vectors.Vector, ask func(string, string) string) error {
	meta, _ := attacks.Get(v.ModuleID)
	_ = meta

	// Module-specific pre-launch configuration: fill in sensible defaults the
	// wizard can ask for, one module at a time.
	switch v.ModuleID {
	case "arp.spoof":
		// Default targets = whole subnet; internal stays false so the gateway
		// is included in the spoof.
		if s.Conf.Get("arp.spoof", "targets") == "" {
			s.Conf.Set("arp.spoof", "targets", s.Iface.CIDR())
		}
		if s.Conf.Get("arp.spoof", "internal") == "" {
			s.Conf.Set("arp.spoof", "internal", "false")
		}
	case "dns.spoof":
		// No domains means answering all DNS queries.
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

	// Per-module confirmation gate before anything launches.
	if ans := strings.ToLower(ask(fmt.Sprintf("Launch %s? [Y/n]: ", v.ModuleID), "y")); strings.HasPrefix(ans, "n") {
		return nil
	}

	// The wizard explicitly presents high-risk modules, so its confirmation
	// doubles as the risk_confirm the REPL gate requires.
	if parseRisk(v.Risk) >= attacks.RiskHigh {
		s.Conf.ConfirmRisk(v.ModuleID)
	}
	return s.StartModule(v.ModuleID, nil)
}

// metaResolver adapts the attacks registry to the vector engine.
func (s *Session) metaResolver() vectors.MetaResolver {
	// The vector engine only needs the metadata fields, so the registry's
	// rich Module is narrowed down to the vectors.MetaInfo view.
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
		// Indexes are 1-based in the UI; anything out of range invalidates
		// the whole selection so the caller can treat it as a typo.
		i, err := strconv.Atoi(tok)
		if err != nil || i < 1 || i > n {
			return nil
		}
		out = append(out, i-1)
	}
	return out
}

// gatewayStr formats the profile gateway as an IP string for the KV display.
func gatewayStr(p *vectors.Profile) string {
	if p.Gateway == nil {
		return "unknown"
	}
	return p.Gateway.IP.String()
}
