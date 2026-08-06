// Package recon contains the passive/active discovery modules: ARP host
// discovery, service scanning and fingerprinting.
package recon

import (
	"fmt"
	"time"

	"github.com/qyvora/toha3ee/internal/attacks"
	"github.com/qyvora/toha3ee/internal/events"
	"github.com/qyvora/toha3ee/internal/netx/arp"
	"github.com/qyvora/toha3ee/internal/oui"
	"github.com/qyvora/toha3ee/internal/safety"
)

func init() {
	attacks.Register(&NetScan{})
	attacks.Register(&ServiceScan{})
	attacks.Register(&ServiceFingerprint{})
}

// NetScan is an ARP-based host discovery module.
type NetScan struct{}

// Meta implements attacks.Module.
func (*NetScan) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "net.scan",
		Category:    "recon",
		Risk:        attacks.RiskLow,
		Targets:     []string{"subnet"},
		Requires:    []string{"cap.raw_socket"},
		Description: "ARP sweep of the subnet to discover live hosts and their MAC vendors",
		Limitations: "hosts that drop unsolicited ARP requests or are behind firewalls may be missed",
	}
}

type netScanState struct {
	sc    *arp.Scanner
	start time.Time
	count int
}

// Preflight checks root and the interface.
func (*NetScan) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
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
	return rep, nil
}

// Run sweeps the interface subnet until ctx.Done is closed.
func (*NetScan) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	sc, err := arp.NewScanner(ctx.Iface, ctx.Bus, ctx.Store, oui.New())
	if err != nil {
		return fmt.Errorf("net.scan: %w", err)
	}
	sc.Start()

	ctx.SetState("net.scan", &netScanState{sc: sc, start: time.Now()})
	ctx.Printf("[*] net.scan sweeping %s... press Ctrl-C or 'net.scan off' to stop.\n", ctx.Iface.CIDR())

	hb := safety.NewHeartbeat()
	ctx.Heartbeat = hb.Beat
	ctx.Safety.RegisterHeartbeat("net.scan", hb)

	for {
		select {
		case <-ctx.Done:
			return nil
		case <-time.After(2 * time.Second):
			hb.Beat()
		}
	}
}

// Verify reports the discovered host count.
func (*NetScan) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("net.scan")
	if !ok {
		return nil, fmt.Errorf("net.scan not running")
	}
	st := v.(*netScanState)
	hosts := ctx.Store.Hosts()
	imp := &attacks.Impact{
		Summary: fmt.Sprintf("found %d host(s) on %s", len(hosts), ctx.Iface.CIDR()),
	}
	imp.Add("hosts", fmt.Sprintf("%d", len(hosts)))
	imp.Add("macs_resolved", fmt.Sprintf("%d", st.sc.MACsResolved()))
	imp.Add("uptime", fmt.Sprintf("%s", time.Since(st.start).Round(time.Second)))
	for _, h := range hosts {
		imp.Add("host", h.IP.String())
	}
	return imp, nil
}

// Cleanup stops the scanner.
func (*NetScan) Cleanup(ctx *attacks.AttackCtx) error {
	ctx.Safety.UnregisterHeartbeat("net.scan")
	if v, ok := ctx.GetState("net.scan"); ok {
		v.(*netScanState).sc.Stop()
	}
	ctx.Store.LogEvent(events.TopicModuleStopped, "net.scan stopped")
	return nil
}

var _ attacks.Module = (*NetScan)(nil)
