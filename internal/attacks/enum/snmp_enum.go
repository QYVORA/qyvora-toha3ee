package enum

import (
	"fmt"
	"net"
	"time"

	"github.com/qyvora/toha3ee/internal/attacks"
	"github.com/qyvora/toha3ee/internal/netx/snmp"
)

// SNMPEnum probes SNMP agents with common community strings and walks the
// system MIB for host information, interface tables and routing tables.
//
// SNMPv1/v2c authenticate with a plaintext "community string" shared secret.
// Vendors ship "public"/"private" defaults, so when those are left in place
// the whole system, interface and routing MIB becomes readable by anyone —
// a classic network-recon goldmine.
type SNMPEnum struct{}

// Meta implements attacks.Module.
func (*SNMPEnum) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "snmp.enum",
		Category:    "enum",
		Risk:        attacks.RiskInfo,
		Targets:     []string{"service"},
		Description: "SNMP community-string probing and MIB walk for system info, interfaces and routes",
		Limitations: "only SNMPv1/v2c (no v3 auth); weak or default community strings ('public'/'private') are required to read data",
	}
}

// snmpResult captures one readable agent.
type snmpResult struct {
	Host      string
	Community string
	System    *snmp.System
}

// Preflight needs at least one host with SNMP (161) or a forced target.
func (*SNMPEnum) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if len(ctx.Store.Hosts()) == 0 {
		rep.AddFixable("targets", "no hosts discovered; run net.scan first")
	} else {
		rep.AddOK("targets", fmt.Sprintf("%d host(s) available", len(ctx.Store.Hosts())))
	}
	if p := ctx.Conf.Get("snmp.enum", "port"); p != "" {
		rep.AddOK("port", "forced SNMP port "+p)
	}
	return rep, nil
}

// Run probes every discovered host (or those with port 161 open).
func (*SNMPEnum) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	communities := ctx.Conf.Get("snmp.enum", "communities")
	var comms []string
	if communities == "" {
		// Default to the built-in list of known weak community strings.
		comms = snmp.CommonCommunities
	} else {
		comms = splitUsers(communities, "")
	}
	port := ctx.Conf.Get("snmp.enum", "port")
	if port == "" {
		port = "161"
	}
	// SNMP lives on UDP; a short timeout keeps the probe sweep fast because
	// non-responders simply time out.
	timeout := ctx.Conf.GetDuration("snmp.enum", "timeout", 1200*time.Millisecond)

	var out []snmpResult
	for _, h := range openHosts(ctx) {
		// Only touch hosts that actually serve SNMP unless a port is forced.
		if port == "161" && !hasPort(h, 161) {
			continue
		}
		addr := net.JoinHostPort(h.IP.String(), port)
		// First connection just learns the agent's default community
		// behaviour.
		c, err := snmp.Dial(addr, "public", timeout)
		if err != nil {
			continue
		}
		community := ""
		for _, comm := range comms {
			if c.ProbeCommunity(comm) {
				community = comm
				break
			}
		}
		c.Close()
		if community == "" {
			emit(ctx, "log", fmt.Sprintf("snmp.enum: %s:%s no accepted community string", h.IP, port))
			continue
		}
		// Re-dial with the accepted community and pull the system MIB tables.
		c, err = snmp.Dial(addr, community, timeout)
		if err != nil {
			continue
		}
		sys, err := c.System()
		c.Close()
		if err != nil {
			continue
		}
		out = append(out, snmpResult{Host: h.IP.String(), Community: community, System: sys})
		emit(ctx, "finding", fmt.Sprintf("snmp.enum: %s:%s community=%q sysname=%q descr=%q ifaces=%d routes=%d",
			h.IP, port, community, sys.Name, truncate(sys.Descr, 60), len(sys.Ifaces), len(sys.Routes)))
	}
	ctx.SetState("snmp.enum", out)
	ctx.Printf("[*] snmp.enum complete: %d agent(s) answered a community string.\n", len(out))
	return nil
}

// Verify reports the readable agents.
func (*SNMPEnum) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("snmp.enum")
	if !ok {
		return nil, fmt.Errorf("snmp.enum not run")
	}
	res, _ := v.([]snmpResult)
	imp := &attacks.Impact{Summary: fmt.Sprintf("read %d SNMP agent(s) with default communities", len(res))}
	for _, r := range res {
		imp.Add("agent", r.Host+" community="+r.Community+" name="+r.System.Name)
	}
	return imp, nil
}

// Cleanup is a no-op.
func (*SNMPEnum) Cleanup(ctx *attacks.AttackCtx) error { return nil }

// truncate shortens s to n bytes plus an ellipsis for report friendliness.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// Compile-time assertion that SNMPEnum satisfies the Module contract.
var _ attacks.Module = (*SNMPEnum)(nil)
