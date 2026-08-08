package auth

import (
	"fmt"

	"github.com/qyvora/toha3ee/internal/attacks"
)

// ASREP suggests the AS-REP roasting angle of an Active Directory attack: any
// user account with DONT_REQUIRE_PREAUTH set exposes an AS-REP that can be
// requested without any password and cracked offline. This module only finds
// likely Kerberos KDCs in the host inventory and reports whether the technique
// applies; it never sends Kerberos traffic itself.
type ASREP struct{}

// Meta implements attacks.Module.
func (*ASREP) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "auth.asrep",
		Category:    "auth",
		Risk:        attacks.RiskInfo,
		Targets:     []string{"host"},
		Passive:     true,
		Description: "locate Kerberos KDCs and advise whether AS-REP roasting of pre-auth-disabled accounts applies",
		Limitations: "infers KDC presence from open ports only; confirming DONT_REQUIRE_PREAUTH needs an authenticated AS-REQ from a domain user",
	}
}

type asrepCandidate struct {
	ip    string
	ports []uint16
}

// Preflight needs hosts.
func (*ASREP) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if len(ctx.Store.Hosts()) == 0 {
		rep.AddFixable("hosts", "no hosts in the store; run net.scan + service.synscan first")
		return rep, nil
	}
	rep.AddOK("hosts", fmt.Sprintf("%d host(s) available", len(ctx.Store.Hosts())))
	return rep, nil
}

// Run scans for Kerberos-enabled hosts.
func (*ASREP) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	var kdcs []asrepCandidate
	for _, h := range ctx.Store.Hosts() {
		ports := h.OpenPorts()
		if containsPort(ports, 88) {
			kdcs = append(kdcs, asrepCandidate{ip: h.IP.String(), ports: ports})
		}
	}
	ctx.SetState("auth.asrep", kdcs)
	if len(kdcs) == 0 {
		ctx.Printf("[*] auth.asrep: no Kerberos (:88) host found; AS-REP roasting not applicable.\n")
		return nil
	}
	for _, k := range kdcs {
		ctx.Printf("[!] auth.asrep: %s serves Kerberos (ports %v). If this is an AD KDC, query AS-REPs for users with DONT_REQUIRE_PREAUTH set (impacket GetNPUsers, hashcat mode 18200) once a domain account is available.\n", k.ip, k.ports)
	}
	return nil
}

// Verify reports the KDC count.
func (*ASREP) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("auth.asrep")
	if !ok {
		return &attacks.Impact{Summary: "AS-REP assessment complete"}, nil
	}
	kdcs := v.([]asrepCandidate)
	imp := &attacks.Impact{
		Summary: fmt.Sprintf("found %d Kerberos KDC candidate(s); AS-REP roasting applicable if pre-auth-disabled accounts exist", len(kdcs)),
	}
	for _, k := range kdcs {
		imp.Add("kdc", k.ip)
	}
	return imp, nil
}

// Cleanup is a no-op.
func (*ASREP) Cleanup(ctx *attacks.AttackCtx) error { return nil }

var _ attacks.Module = (*ASREP)(nil)
