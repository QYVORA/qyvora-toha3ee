package enum

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/qyvora/toha3ee/internal/attacks"
	"github.com/qyvora/toha3ee/internal/netx/ldap"
)

// LDAPEnum tests directory servers for unauthenticated/anonymous binds and
// lists naming contexts and interesting objects.
type LDAPEnum struct{}

// Meta implements attacks.Module.
func (*LDAPEnum) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "ldap.enum",
		Category:    "enum",
		Risk:        attacks.RiskInfo,
		Targets:     []string{"service"},
		Description: "test LDAP servers for anonymous/simple binds and enumerate naming contexts and directory objects",
		Limitations: "read-only: lists what anonymous access permits; ADLDAP often restricts anonymous reads to the root DSE",
	}
}

type ldapResult struct {
	Host    string
	Bind    string // anonymous | simple | rejected
	RootDN  string
	Objects int
}

// Preflight needs a host with LDAP (389/636) open.
func (*LDAPEnum) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	for _, h := range openHosts(ctx) {
		for _, p := range h.Ports {
			if p == 389 || p == 636 {
				rep.AddOK("targets", fmt.Sprintf("LDAP service on %s:%s", h.IP, portStr(p)))
				return rep, nil
			}
		}
	}
	rep.AddFixable("targets", "no LDAP service (389/636) discovered; run service.synscan first")
	return rep, nil
}

// Run probes each LDAP host.
func (*LDAPEnum) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	port := ctx.Conf.Get("ldap.enum", "port")
	if port == "" {
		port = "389"
	}
	timeout := ctx.Conf.GetDuration("ldap.enum", "timeout", 5*time.Second)

	var out []ldapResult
	for _, h := range openHosts(ctx) {
		if port == "389" && !hasPort(h, 389) && !hasPort(h, 636) {
			continue
		}
		addr := net.JoinHostPort(h.IP.String(), port)
		res := ldapResult{Host: h.IP.String(), Bind: "rejected"}
		c, err := ldap.Dial(addr, "", "", timeout)
		if err != nil {
			continue
		}
		// Root DSE read works on most servers without a bind.
		entries, err := c.Search("", ldap.ScopeBase, "", timeout)
		if err == nil {
			for _, e := range entries {
				if dns := e.Attributes["namingContexts"]; len(dns) > 0 && res.RootDN == "" {
					res.RootDN = dns[0]
				}
			}
		}
		// Anonymous bind attempt.
		c2, err := ldap.Dial(addr, "", "", timeout)
		if err == nil {
			c2.Close()
			res.Bind = "anonymous"
		} else {
			emit(ctx, "log", fmt.Sprintf("ldap.enum: %s:%s anonymous bind rejected", h.IP, port))
		}
		// One-level search under the first naming context.
		if res.RootDN != "" {
			entries, err := c.Search(res.RootDN, ldap.ScopeOneLevel, "", timeout)
			if err == nil {
				res.Objects = len(entries)
				for _, e := range entries {
					if n := e.Attributes["sAMAccountName"]; len(n) > 0 {
						emit(ctx, "finding", fmt.Sprintf("ldap.enum: %s user=%q", h.IP, n[0]))
					}
				}
			}
		}
		c.Close()
		emit(ctx, "finding", fmt.Sprintf("ldap.enum: %s:%s bind=%s rootDN=%q objects=%d",
			h.IP, port, res.Bind, res.RootDN, res.Objects))
		out = append(out, res)
	}
	ctx.SetState("ldap.enum", out)
	ctx.Printf("[*] ldap.enum complete: %d directory server(s) probed.\n", len(out))
	return nil
}

// Verify reports the bind results.
func (*LDAPEnum) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("ldap.enum")
	if !ok {
		return nil, fmt.Errorf("ldap.enum not run")
	}
	res, _ := v.([]ldapResult)
	imp := &attacks.Impact{Summary: fmt.Sprintf("probed %d LDAP server(s)", len(res))}
	for _, r := range res {
		imp.Add("ldap", r.Host+" bind="+r.Bind+" rootDN="+r.RootDN+" objects="+strconv.Itoa(r.Objects))
	}
	return imp, nil
}

// Cleanup is a no-op.
func (*LDAPEnum) Cleanup(ctx *attacks.AttackCtx) error { return nil }

var _ attacks.Module = (*LDAPEnum)(nil)
