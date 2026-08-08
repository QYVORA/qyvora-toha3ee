package enum

import (
	"fmt"
	"net"
	"time"

	"github.com/qyvora/toha3ee/internal/attacks"
	"github.com/qyvora/toha3ee/internal/netx/ndp"
	"github.com/qyvora/toha3ee/internal/store"
)

// IP6Sweep discovers IPv6 hosts on the local link with Neighbor Solicitation /
// Advertisement exchange, the IPv6 counterpart of an ARP sweep.
type IP6Sweep struct{}

// Meta implements attacks.Module.
func (*IP6Sweep) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "net.ip6sweep",
		Category:    "enum",
		Risk:        attacks.RiskLow,
		Targets:     []string{"subnet"},
		Requires:    []string{"cap.raw_socket"},
		Description: "discover IPv6 hosts on the local link via Neighbor Discovery (NS/NA) sweep",
		Limitations: "probes a configurable candidate range; hosts that do not answer NS (or are firewalled) are missed",
	}
}

// Preflight needs root and an interface.
func (*IP6Sweep) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if err := requireRoot(rep); err != nil {
		return rep, nil
	}
	if ctx.Iface == nil || ctx.Iface.Name == "" {
		rep.AddBlocked("interface", "no interface bound; use --iface")
	} else {
		rep.AddOK("interface", ctx.Iface.Name)
	}
	if len(ctx.Store.Hosts()) == 0 {
		rep.AddOK("note", "no hosts yet; sweep will seed the store with responders")
	}
	return rep, nil
}

// Run performs the NS/NA sweep.
func (*IP6Sweep) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	timeout := ctx.Conf.GetDuration("net.ip6sweep", "timeout", 1200*time.Millisecond)
	candidates, err := ip6Candidates(ctx)
	if err != nil {
		return err
	}
	if len(candidates) == 0 {
		return fmt.Errorf("net.ip6sweep: no IPv6 address on %s to build candidates from", ctx.Iface.Name)
	}
	srcIP := ctx.Iface.IPv6
	if srcIP == nil {
		return fmt.Errorf("net.ip6sweep: interface %s has no IPv6 address", ctx.Iface.Name)
	}
	srcMAC := ctx.Iface.MAC

	sender, err := ndp.NewSender(ctx.Iface.Name)
	if err != nil {
		return err
	}
	defer sender.Close()

	found, err := sender.NeighborSweep(candidates, srcIP, srcMAC, timeout)
	if err != nil {
		return err
	}
	for _, ip := range found {
		ctx.Store.UpsertHost(&store.Host{IP: ip, MAC: srcMAC})
		emit(ctx, "finding", fmt.Sprintf("net.ip6sweep: live IPv6 host %s", ip))
	}
	ctx.SetState("net.ip6sweep", len(found))
	ctx.Printf("[*] net.ip6sweep complete: %d live IPv6 host(s).\n", len(found))
	return nil
}

// ip6Candidates builds the candidate address list from the interface prefix.
// It walks the low 8 bits (a /120 of the interface's /64) by default, capped.
func ip6Candidates(ctx *attacks.AttackCtx) ([]net.IP, error) {
	ip := ctx.Iface.IPv6
	if ip == nil {
		return nil, fmt.Errorf("net.ip6sweep: interface %s has no IPv6 address", ctx.Iface.Name)
	}
	prefix := ip.To16()[:8]
	bits := ctx.Conf.GetInt("net.ip6sweep", "scanbits", 8)
	if bits > 16 {
		bits = 16
	}
	count := 1 << bits
	var out []net.IP
	for i := 0; i < count; i++ {
		c := make(net.IP, 16)
		copy(c, prefix)
		if bits <= 8 {
			c[15] = byte(i)
			c[14] = 0
		} else {
			c[15] = byte(i & 0xff)
			c[14] = byte(i >> 8)
		}
		if !c.Equal(ip) {
			out = append(out, c)
		}
	}
	return out, nil
}

// Verify reports the sweep result.
func (*IP6Sweep) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("net.ip6sweep")
	if !ok {
		return nil, fmt.Errorf("net.ip6sweep not run")
	}
	n, _ := v.(int)
	return &attacks.Impact{Summary: fmt.Sprintf("found %d live IPv6 host(s)", n)}, nil
}

// Cleanup is a no-op.
func (*IP6Sweep) Cleanup(ctx *attacks.AttackCtx) error { return nil }

var _ attacks.Module = (*IP6Sweep)(nil)
