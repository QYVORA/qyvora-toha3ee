package enum

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/QYVORA/qyvora-toha3ee/internal/attacks"
	"github.com/QYVORA/qyvora-toha3ee/internal/netx/ldap"
)

// LDAPEnum tests directory servers for unauthenticated/anonymous binds and
// lists naming contexts and interesting objects.
//
// LDAP allows a "bind" with empty credentials on many directories; when it
// succeeds the anonymous session can often read the root DSE (naming
// contexts) and, on misconfigured servers, enumerate user objects. This is
// the classic unauthenticated LDAP dump.
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

// ldapResult summarises one server's anonymous-bind findings.
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
func (*LDAPEnum) Run(ctx *attacks.AttackCtx, _ map[string]string) error {
	port := ctx.Conf.Get("ldap.enum", "port")
	if port == "" {
		port = "389"
	}
	timeout := ctx.Conf.GetDuration("ldap.enum", "timeout", 5*time.Second)

	var out []ldapResult
	for _, h := range openHosts(ctx) {
		// When probing the default port, only touch hosts that actually serve
		// LDAP; a forced port skips this gate.
		if port == "389" && !hasPort(h, 389) && !hasPort(h, 636) {
			continue
		}
		addr := net.JoinHostPort(h.IP.String(), port)
		// Assume rejection until proven otherwise.
		res := ldapResult{Host: h.IP.String(), Bind: "rejected"}
		c, err := ldap.Dial(addr, "", "", timeout)
		if err != nil {
			continue
		}
		// Root DSE read works on most servers without a bind.
		entries, err := c.Search("", ldap.ScopeBase, "", timeout)
		if err == nil {
			for _, e := range entries {
				// namingContexts is the root DSE attribute that lists the
				// directory's base DNs; the first one is the top of the tree.
				if dns := e.Attributes["namingContexts"]; len(dns) > 0 && res.RootDN == "" {
					res.RootDN = dns[0]
				}
			}
		}
		// Anonymous bind attempt: a fresh connection that dials and closes
		// without credentials. Dial succeeding already proves the server
		// accepted the (empty) bind — that IS the anonymous bind.
		c2, err := ldap.Dial(addr, "", "", timeout)
		if err == nil {
			_ = c2.Close()
			res.Bind = "anonymous"
		} else {
			emit(ctx, "log", fmt.Sprintf("ldap.enum: %s:%s anonymous bind rejected", h.IP, port))
		}
		// One-level search under the first naming context. This enumerates
		// what sits directly below the root — usually users, groups and
		// computers.
		if res.RootDN != "" {
			entries, err := c.Search(res.RootDN, ldap.ScopeOneLevel, "", timeout)
			if err == nil {
				res.Objects = len(entries)
				for _, e := range entries {
					// sAMAccountName is the Windows user login name; any
					// object exposing it is a user account.
					if n := e.Attributes["sAMAccountName"]; len(n) > 0 {
						emit(ctx, "finding", fmt.Sprintf("ldap.enum: %s user=%q", h.IP, n[0]))
					}
				}
			}
		}
		_ = c.Close()
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
func (*LDAPEnum) Cleanup(_ *attacks.AttackCtx) error { return nil }

// Compile-time assertion that LDAPEnum satisfies the Module contract.
var _ attacks.Module = (*LDAPEnum)(nil)
