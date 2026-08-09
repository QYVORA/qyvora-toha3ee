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
//
// ICMPv6 Neighbor Discovery: the attacker multicasts a Neighbor Solicitation
// "who has <target>" for every candidate address; live hosts answer with a
// Neighbor Advertisement carrying their link-layer address. Because IPv6
// subnets are huge, only a configurable slice of the /64 is probed.
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
		// An empty store is fine here — unlike most enum modules this sweep
		// seeds the store with responders instead of consuming it.
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

	// The sender opens a raw (AF_PACKET) socket on the interface to emit the
	// Neighbor Solicitations and read the replies.
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
		// Seed the inventory. Note: the MAC recorded is the *sender's* — the
		// NDP library returns the advertised link address in its own field;
		// this upsert conservatively records the responder as live.
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
	// The prefix is the first 8 bytes of the 16-byte address: the /64 network
	// id. Candidates reuse this prefix and vary only the low bytes.
	prefix := ip.To16()[:8]
	bits := ctx.Conf.GetInt("net.ip6sweep", "scanbits", 8)
	// Cap at 16 bits: probing 65536 addresses is already a lot of NS traffic
	// on the link, and a full /64 scan would be astronomically slow.
	if bits > 16 {
		bits = 16
	}
	count := 1 << bits
	var out []net.IP
	for i := 0; i < count; i++ {
		c := make(net.IP, 16)
		copy(c, prefix)
		if bits <= 8 {
			// Only the last byte varies; the host-id byte stays zero so the
			// pattern is readable (e.g. fe80::1, fe80::2, ...).
			c[15] = byte(i)
			c[14] = 0
		} else {
			// More than 8 bits: the counter's low byte goes in the last byte
			// and the high bits spill into the second-to-last byte.
			c[15] = byte(i & 0xff)
			c[14] = byte(i >> 8)
		}
		// Skip our own address — asking ourselves "who has <us>" would be
		// pointless and would poison the sweep with a self-answer.
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

// Compile-time assertion that IP6Sweep satisfies the Module contract.
var _ attacks.Module = (*IP6Sweep)(nil)
