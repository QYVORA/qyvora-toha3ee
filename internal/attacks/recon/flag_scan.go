package recon

import (
	"fmt"
	"strconv"
	"time"

	"github.com/QYVORA/qyvora-toha3ee/internal/attacks"
	"github.com/QYVORA/qyvora-toha3ee/internal/events"
	"github.com/QYVORA/qyvora-toha3ee/internal/netx/ports"
	"github.com/QYVORA/qyvora-toha3ee/internal/stealth"
)

// FlagScan performs FIN/NULL/XMAS scans. These probes use unusual TCP control
// flags to bypass stateless firewalls: RFC-compliant stacks answer a closed
// port with RST and stay silent on open ports, so silence means open|filtered.
type FlagScan struct{}

// Meta implements attacks.Module, returning the module's registry descriptor.
func (*FlagScan) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:       "service.finxmas",
		Category: "recon",
		Risk:     attacks.RiskLow,
		Targets:  []string{"host"},
		// Crafting unusual-flag probes and sniffing replies requires raw
		// sockets.
		Requires:    []string{"cap.raw_socket"},
		Description: "FIN/NULL/XMAS scan: unusual-flag probes that bypass stateless firewalls and map stateful ones",
		Limitations: "most modern stacks and middleboxes reply with RST to all flag sets, so silence-based verdicts lose precision; use service.synscan for reliable open ports",
	}
}

// Preflight checks root and hosts.
func (*FlagScan) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
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

// Run scans each host with the configured flag mode.
func (*FlagScan) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	// The flag mode comes from config, overridable per-run via opts.
	mode := ports.ParseScanMode(ctx.Conf.Get("service.finxmas", "mode"))
	if m, ok := opts["mode"]; ok && m != "" {
		mode = ports.ParseScanMode(m)
	}
	portsToScan := ports.CommonPorts
	if p := ctx.Conf.Get("service.finxmas", "ports"); p != "" {
		portsToScan = parsePorts(splitList(p))
	}
	timeout := ctx.Conf.GetDuration("service.finxmas", "timeout", 1800*time.Millisecond)

	scanner, err := ports.NewScanner(ctx.Iface)
	if err != nil {
		return fmt.Errorf("service.finxmas: %w", err)
	}
	defer scanner.Close()
	scanner.SetStealth(stealth.FromConfig(ctx.Conf, "service.finxmas"))

	results := 0
	for _, h := range ctx.Store.Hosts() {
		select {
		case <-ctx.Done:
			return nil
		default:
		}
		res, err := scanner.ScanFlags(h.IP, portsToScan, timeout, mode)
		if err != nil {
			continue
		}
		// With FIN/NULL/XMAS a RST reply proves the port is closed; silence
		// means the probe was accepted (open) or dropped (filtered).
		for _, r := range res {
			if r.State == ports.Closed {
				results++
				ctx.Emit(events.TopicLog,
					fmt.Sprintf("service.finxmas: %s:%d closed (mode=%s)", h.IP, r.Port, mode), nil)
				continue
			}
			if r.State == ports.OpenFiltered {
				ctx.Emit(events.TopicLog,
					fmt.Sprintf("service.finxmas: %s:%d open|filtered (mode=%s)", h.IP, r.Port, mode), nil)
			}
		}
	}
	ctx.SetState("service.finxmas", results)
	ctx.Printf("[*] service.finxmas complete (mode=%s): %d closed port(s) mapped, rest open|filtered.\n", mode, results)
	return nil
}

// Verify reports the closed-port count.
func (*FlagScan) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("service.finxmas")
	if !ok {
		return nil, fmt.Errorf("service.finxmas not run")
	}
	n, _ := v.(int)
	imp := &attacks.Impact{Summary: fmt.Sprintf("mapped %d closed port(s) with %s probes", n, ctx.Conf.Get("service.finxmas", "mode"))}
	imp.Add("closed", strconv.Itoa(n))
	return imp, nil
}

// Cleanup is a no-op.
func (*FlagScan) Cleanup(ctx *attacks.AttackCtx) error { return nil }

// Compile-time assertion that FlagScan implements attacks.Module.
var _ attacks.Module = (*FlagScan)(nil)
