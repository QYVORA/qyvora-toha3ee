// Package recon contains the passive/active discovery modules: ARP host
// discovery, service scanning and fingerprinting.
package recon

import (
	"fmt"
	"time"

	"github.com/QYVORA/qyvora-toha3ee/internal/attacks"
	"github.com/QYVORA/qyvora-toha3ee/internal/events"
	"github.com/QYVORA/qyvora-toha3ee/internal/netx/arp"
	"github.com/QYVORA/qyvora-toha3ee/internal/oui"
	"github.com/QYVORA/qyvora-toha3ee/internal/safety"
	"github.com/QYVORA/qyvora-toha3ee/internal/stealth"
)

// init registers every recon module with the attacks registry at startup.
func init() {
	attacks.Register(&NetScan{})
	attacks.Register(&ServiceScan{})
	attacks.Register(&ServiceFingerprint{})
	attacks.Register(&WebDir{})
	attacks.Register(&ServiceTLS{})
	attacks.Register(&NetPing{})
	attacks.Register(&NetTraceroute{})
	attacks.Register(&NetOSDetect{})
	attacks.Register(&TCPConnectScan{})
	attacks.Register(&UDPScan{})
	attacks.Register(&FlagScan{})
	attacks.Register(&ACKScan{})
	attacks.Register(&ProtocolScan{})
	attacks.Register(&IdleScan{})
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

// netScanState is the live state carried between Run, Verify and Cleanup.
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
	sc.SetStealth(stealth.FromConfig(ctx.Conf, "net.scan"))
	sc.Start()

	ctx.SetState("net.scan", &netScanState{sc: sc, start: time.Now()})
	ctx.Printf("[*] net.scan sweeping %s... press Ctrl-C or 'net.scan off' to stop.\n", ctx.Iface.CIDR())

	// The module runs until stopped: register a heartbeat so the safety
	// watchdog does not kill it as unresponsive.
	hb := safety.NewHeartbeat()
	ctx.Heartbeat = hb.Beat
	ctx.Safety.RegisterHeartbeat("net.scan", hb)

	timeout := ctx.Conf.GetDuration("net.scan", "timeout", 750*time.Millisecond)
	repeat := ctx.Conf.GetDuration("net.scan", "repeat", 30*time.Second)

	// Active sweep loop: the full subnet is swept in randomized, paced order
	// so discovery stays fast without a uniform, detectable probe cadence.
	go func() {
		for {
			select {
			case <-ctx.Done:
				return
			default:
			}
			if ctx.Iface.Net != nil {
				found, err := sc.Scan(arp.CIDRHosts(ctx.Iface.Net), timeout)
				if err == nil {
					if st, ok := ctx.GetState("net.scan"); ok {
						st.(*netScanState).count = len(found)
					}
					ctx.Store.LogEvent(events.TopicLog,
						fmt.Sprintf("net.scan: sweep answered %d host(s)", len(found)))
				}
			}
			select {
			case <-ctx.Done:
				return
			case <-time.After(repeat):
			}
		}
	}()

	// Block the main module goroutine: a beat every 2s keeps the watchdog
	// happy while the sweep goroutine above does the actual work.
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
