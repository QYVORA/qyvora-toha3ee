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

// IdleScan maps open TCP ports of a target through an idle "zombie" third
// host, so neither the target nor the zombie ever learns the scanner's real
// address. It works by watching the zombie's predictable IP identification
// counter react to SYN packets spoofed from the zombie.
type IdleScan struct{}

// Meta implements attacks.Module.
func (*IdleScan) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "service.idle",
		Category:    "recon",
		Risk:        attacks.RiskLow,
		Targets:     []string{"host"},
		Requires:    []string{"cap.raw_socket"},
		Description: "idle/zombie TCP scan: map open ports through an idle third host, hiding the scanner's address",
		Limitations: "needs a usable idle zombie with an open TCP port and predictable IP IDs (e.g. an idle printer); modern hosts with randomized IP IDs cannot be zombies",
	}
}

// Preflight checks root, hosts and a configured zombie.
func (*IdleScan) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if err := requireRootRep(rep); err != nil {
		return rep, nil
	}
	if ctx.Conf.Get("service.idle", "zombie") == "" {
		rep.AddFixable("zombie", "set service.idle.zombie to an idle host usable as the scan proxy")
	}
	if len(ctx.Store.Hosts()) == 0 {
		rep.AddFixable("targets", "no hosts discovered; run net.scan first")
	} else {
		rep.AddOK("targets", fmt.Sprintf("%d host(s) discovered", len(ctx.Store.Hosts())))
	}
	return rep, nil
}

// Run performs the idle scan against each discovered host.
func (*IdleScan) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	zombie := ctx.Conf.Get("service.idle", "zombie")
	if o, ok := opts["zombie"]; ok && o != "" {
		zombie = o
	}
	portsToScan := ports.CommonPorts
	if p := ctx.Conf.Get("service.idle", "ports"); p != "" {
		portsToScan = parsePorts(splitList(p))
	}
	timeout := ctx.Conf.GetDuration("service.idle", "timeout", 2*time.Second)

	scanner, err := ports.NewScanner(ctx.Iface)
	if err != nil {
		return fmt.Errorf("service.idle: %w", err)
	}
	defer scanner.Close()
	scanner.SetStealth(stealth.FromConfig(ctx.Conf, "service.idle"))

	open := 0
	for _, h := range ctx.Store.Hosts() {
		select {
		case <-ctx.Done:
			return nil
		default:
		}
		res, err := scanner.IdleScan(h.IP, parseSingleIP(zombie), portsToScan, timeout)
		if err != nil {
			ctx.Printf("[!] service.idle: %s: %v\n", h.IP, err)
			continue
		}
		for _, r := range res {
			if r.State != ports.Open {
				continue
			}
			open++
			setHostPort(ctx, h.IP, r.Port, "")
			ctx.Emit(events.TopicLog,
				fmt.Sprintf("service.idle: %s:%d open (via zombie %s)", h.IP, r.Port, zombie), nil)
		}
	}
	ctx.SetState("service.idle", open)
	ctx.Printf("[*] service.idle complete: %d open port(s) mapped through zombie %s.\n", open, zombie)
	return nil
}

// Verify reports the open-port count.
func (*IdleScan) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("service.idle")
	if !ok {
		return nil, fmt.Errorf("service.idle not run")
	}
	n, _ := v.(int)
	imp := &attacks.Impact{
		Summary: fmt.Sprintf("%d open port(s) mapped through zombie %s", n, ctx.Conf.Get("service.idle", "zombie"))}
	imp.Add("open", strconv.Itoa(n))
	return imp, nil
}

// Cleanup is a no-op.
func (*IdleScan) Cleanup(ctx *attacks.AttackCtx) error { return nil }

var _ attacks.Module = (*IdleScan)(nil)
