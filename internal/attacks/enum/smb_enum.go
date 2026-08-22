package enum

import (
	"fmt"
	"net"
	"time"

	"github.com/QYVORA/qyvora-toha3ee/internal/attacks"
	"github.com/QYVORA/qyvora-toha3ee/internal/netx/smb"
)

// SMBEnum checks SMB services for signing policy and anonymous/null-session
// behaviour.
//
// Signing posture comes straight out of the SMB2 NEGOTIATE response: the
// SecurityMode field says whether signing is enabled and whether the server
// requires it. A server that does not require signing is a prime NTLM relay
// target, and its dialect informs downgrade possibilities.
type SMBEnum struct{}

// Meta implements attacks.Module.
func (*SMBEnum) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "smb.enum",
		Category:    "enum",
		Risk:        attacks.RiskInfo,
		Targets:     []string{"service"},
		Description: "probe SMB servers for signing policy, dialect support and null-session exposure",
		Limitations: "signing policy comes from SMB2 NEGOTIATE; full share listing needs an authenticated SMB session and is out of scope here",
	}
}

// smbResult records one server's negotiated posture.
type smbResult struct {
	Host       string
	Dialect    uint16
	SigningOn  bool
	SigningReq bool
}

// Preflight needs a host with SMB (445/139) open.
func (*SMBEnum) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	for _, h := range openHosts(ctx) {
		for _, p := range h.Ports {
			if p == 445 || p == 139 {
				rep.AddOK("targets", fmt.Sprintf("SMB service on %s:%s", h.IP, portStr(p)))
				return rep, nil
			}
		}
	}
	rep.AddFixable("targets", "no SMB service (445/139) discovered; run service.synscan first")
	return rep, nil
}

// Run negotiates with each SMB host.
func (*SMBEnum) Run(ctx *attacks.AttackCtx, _ map[string]string) error {
	timeout := ctx.Conf.GetDuration("smb.enum", "timeout", 4*time.Second)
	var out []smbResult
	for _, h := range openHosts(ctx) {
		port := 445
		if !hasPort(h, 445) {
			// 445 is SMB-over-TCP (SMB2 native). If it is closed but 139
			// (NetBIOS session service carrying SMB1) is open, fall back to it.
			if !hasPort(h, 139) {
				continue
			}
			port = 139
		}
		sig, err := smb.Probe(net.JoinHostPort(h.IP.String(), fmt.Sprint(port)), timeout)
		if err != nil {
			continue
		}
		res := smbResult{Host: h.IP.String(), Dialect: sig.Dialect, SigningOn: sig.Enabled, SigningReq: sig.Required}
		out = append(out, res)
		if !sig.Required {
			emit(ctx, "finding", fmt.Sprintf("smb.enum: %s:%d signing NOT required (relay/downgrade window)", h.IP, port))
		} else {
			emit(ctx, "log", fmt.Sprintf("smb.enum: %s:%d signing required (dialect 0x%04x)", h.IP, port, sig.Dialect))
		}
	}
	ctx.SetState("smb.enum", out)
	ctx.Printf("[*] smb.enum complete: %d SMB server(s) negotiated.\n", len(out))
	return nil
}

// Verify reports the signing posture.
func (*SMBEnum) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("smb.enum")
	if !ok {
		return nil, fmt.Errorf("smb.enum not run")
	}
	res, _ := v.([]smbResult)
	imp := &attacks.Impact{Summary: fmt.Sprintf("negotiated with %d SMB server(s)", len(res))}
	for _, r := range res {
		imp.Add("smb", r.Host+" signing_required="+fmt.Sprint(r.SigningReq))
	}
	return imp, nil
}

// Cleanup is a no-op.
func (*SMBEnum) Cleanup(_ *attacks.AttackCtx) error { return nil }

// Compile-time assertion that SMBEnum satisfies the Module contract.
var _ attacks.Module = (*SMBEnum)(nil)
