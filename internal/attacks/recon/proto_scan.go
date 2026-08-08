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

// ProtocolScan determines which IP protocols a host answers, by sending raw IP
// packets for each protocol number and watching for ICMP
// protocol-unreachable replies. This maps a host's protocol firewall before
// any service-level probing.
type ProtocolScan struct{}

// Meta implements attacks.Module.
func (*ProtocolScan) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "service.protoscan",
		Category:    "recon",
		Risk:        attacks.RiskLow,
		Targets:     []string{"host"},
		Requires:    []string{"cap.raw_socket"},
		Description: "IP protocol scan: which network-layer protocols a host accepts",
		Limitations: "silence means the protocol is open OR filtered; hosts behind firewalls that drop such traffic report nothing",
	}
}

// Preflight checks root and hosts.
func (*ProtocolScan) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
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

// Run scans each discovered host for open IP protocols.
func (*ProtocolScan) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	protocols := ports.ProtocolSet
	if p := ctx.Conf.Get("service.protoscan", "protocols"); p != "" {
		protocols = parseProtocols(splitList(p))
	}
	timeout := ctx.Conf.GetDuration("service.protoscan", "timeout", 1500*time.Millisecond)

	scanner, err := ports.NewScanner(ctx.Iface)
	if err != nil {
		return fmt.Errorf("service.protoscan: %w", err)
	}
	defer scanner.Close()
	scanner.SetStealth(stealth.FromConfig(ctx.Conf, "service.protoscan"))

	total := 0
	for _, h := range ctx.Store.Hosts() {
		select {
		case <-ctx.Done:
			return nil
		default:
		}
		res, err := scanner.ScanProtocols(h.IP, protocols, timeout)
		if err != nil {
			continue
		}
		for _, r := range res {
			if r.State == ports.Closed {
				continue
			}
			total++
			ctx.Emit(events.TopicLog,
				fmt.Sprintf("service.protoscan: %s accepts IP protocol %d (%s)", h.IP, r.Protocol, protoName(r.Protocol)), nil)
			if ph := ctx.Store.Host(h.IP); ph != nil {
				ph.OSGuess = maybeProtocolOS(ph.OSGuess, r.Protocol)
			}
		}
	}
	ctx.SetState("service.protoscan", total)
	ctx.Printf("[*] service.protoscan complete: %d protocol(s) reported open|filtered.\n", total)
	return nil
}

func parseProtocols(in []string) []uint8 {
	var out []uint8
	for _, s := range in {
		if n, err := strconv.Atoi(s); err == nil && n >= 0 && n <= 255 {
			out = append(out, uint8(n))
		}
	}
	if len(out) == 0 {
		return ports.ProtocolSet
	}
	return out
}

func protoName(p uint8) string {
	switch p {
	case 0:
		return "ipv6-hop-by-hop"
	case 4:
		return "ipip"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 41:
		return "ipv6"
	case 47:
		return "gre"
	case 50:
		return "esp"
	case 51:
		return "ah"
	case 58:
		return "icmpv6"
	case 88:
		return "eigrp"
	case 89:
		return "ospf"
	case 103:
		return "pim"
	case 115:
		return "l2tp"
	case 132:
		return "sctp"
	case 136:
		return "udplite"
	case 143:
		return "ethernet"
	}
	return "unknown"
}

// maybeProtocolOS feeds protocol evidence into the OS guess: GRE/ESP/OSPF
// suggest router/network gear, while TCP/UDP are present on almost everything.
func maybeProtocolOS(guess string, p uint8) string {
	switch p {
	case 47, 50, 51, 88, 89, 103:
		if guess == "" {
			return "network-device"
		}
	case 6, 17:
		return guess
	}
	return guess
}

// Verify reports the protocol count.
func (*ProtocolScan) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("service.protoscan")
	if !ok {
		return nil, fmt.Errorf("service.protoscan not run")
	}
	n, _ := v.(int)
	imp := &attacks.Impact{Summary: fmt.Sprintf("%d IP protocol(s) accepted", n)}
	imp.Add("protocols", strconv.Itoa(n))
	return imp, nil
}

// Cleanup is a no-op.
func (*ProtocolScan) Cleanup(ctx *attacks.AttackCtx) error { return nil }

var _ attacks.Module = (*ProtocolScan)(nil)
