package recon

import (
	"fmt"
	"strconv"
	"time"

	"github.com/qyvora/toha3ee/internal/attacks"
	"github.com/qyvora/toha3ee/internal/events"
	"github.com/qyvora/toha3ee/internal/netx/ports"
	"github.com/qyvora/toha3ee/internal/stealth"
)

// ACKScan maps firewall rules using ACK probes: every port on a stateful
// firewall is filtered, while unfiltered hosts answer with RST. It never
// reveals open ports, only the firewall topology in front of them.
type ACKScan struct{}

// Meta implements attacks.Module.
func (*ACKScan) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "service.ack",
		Category:    "recon",
		Risk:        attacks.RiskLow,
		Targets:     []string{"host"},
		Requires:    []string{"cap.raw_socket"},
		Description: "ACK scan: map firewall rule sets by distinguishing filtered from unfiltered ports via RST replies",
		Limitations: "ACK scans report firewall state, not open ports; pair with service.synscan for actual service discovery",
	}
}

// Preflight checks root and hosts.
func (*ACKScan) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if err := requireRootRep(rep); err != nil {
		return rep, nil
	}
	if len(ctx.Store.Hosts()) == 0 {
		rep.AddFixable("targets", "no hosts discovered; run net.scan first")
	} else {
		rep.AddOK("targets", fmt.Sprintf("%d host(s) discovered", len(ctx.Store.Hosts())))
	}
	return rep, nil
}

// Run sends ACK probes to each configured port.
func (*ACKScan) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	portsToScan := ports.CommonPorts
	if p := ctx.Conf.Get("service.ack", "ports"); p != "" {
		portsToScan = parsePorts(splitList(p))
	}
	timeout := ctx.Conf.GetDuration("service.ack", "timeout", 1500*time.Millisecond)

	scanner, err := ports.NewScanner(ctx.Iface)
	if err != nil {
		return fmt.Errorf("service.ack: %w", err)
	}
	defer scanner.Close()
	scanner.SetStealth(stealth.FromConfig(ctx.Conf, "service.ack"))

	unfiltered := 0
	filtered := 0
	for _, h := range ctx.Store.Hosts() {
		select {
		case <-ctx.Done:
			return nil
		default:
		}
		res, err := scanner.ScanFlags(h.IP, portsToScan, timeout, ports.ScanACK)
		if err != nil {
			continue
		}
		for _, r := range res {
			if r.State == ports.Unfiltered {
				unfiltered++
				ctx.Emit(events.TopicLog, fmt.Sprintf("service.ack: %s:%d unfiltered (RST returned)", h.IP, r.Port), nil)
			} else {
				filtered++
				ctx.Emit(events.TopicLog, fmt.Sprintf("service.ack: %s:%d filtered", h.IP, r.Port), nil)
			}
		}
	}
	ctx.SetState("service.ack", unfiltered)
	ctx.Printf("[*] service.ack complete: %d unfiltered, %d filtered.\n", unfiltered, filtered)
	return nil
}

// Verify reports the unfiltered count.
func (*ACKScan) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("service.ack")
	if !ok {
		return nil, fmt.Errorf("service.ack not run")
	}
	n, _ := v.(int)
	imp := &attacks.Impact{Summary: fmt.Sprintf("%d port(s) unfiltered by firewall", n)}
	imp.Add("unfiltered", strconv.Itoa(n))
	return imp, nil
}

// Cleanup is a no-op.
func (*ACKScan) Cleanup(ctx *attacks.AttackCtx) error { return nil }

var _ attacks.Module = (*ACKScan)(nil)
