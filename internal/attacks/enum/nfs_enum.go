package enum

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/QYVORA/qyvora-toha3ee/internal/attacks"
	"github.com/QYVORA/qyvora-toha3ee/internal/netx/rpc"
)

// NFSEnum lists NFS exports and checks for readable mounts and service
// presence via the rpcbind/MOUNT protocol.
//
// NFSv3 locates the mount daemon through rpcbind (port 111): a GETPORT call
// asks "which port runs the MOUNT program?" and a MOUNTPROC_EXPORT then lists
// the exported directories with their access groups. NFSv4 instead listens
// directly on 2049.
type NFSEnum struct{}

// Meta implements attacks.Module.
func (*NFSEnum) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "nfs.enum",
		Category:    "enum",
		Risk:        attacks.RiskInfo,
		Targets:     []string{"service"},
		Description: "enumerate NFS exports via rpcbind/MOUNT protocol and probe NFS service presence",
		Limitations: "needs rpcbind on port 111 (NFSv3) or direct NFSv4 on 2049; export lists can be restricted by mountd config",
	}
}

// nfsResult captures one host's NFS posture.
type nfsResult struct {
	Host    string
	NFSv4   bool
	Exports []*rpc.MountExport
}

// Preflight needs a host with NFS-ish ports.
func (*NFSEnum) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	for _, h := range openHosts(ctx) {
		for _, p := range h.Ports {
			if p == 111 || p == 2049 {
				rep.AddOK("targets", fmt.Sprintf("NFS/rpcbind service on %s:%s", h.IP, portStr(p)))
				return rep, nil
			}
		}
	}
	rep.AddFixable("targets", "no rpcbind (111) or NFS (2049) service discovered; run service.synscan first")
	return rep, nil
}

// Run enumerates NFS on each candidate host.
func (*NFSEnum) Run(ctx *attacks.AttackCtx, _ map[string]string) error {
	timeout := ctx.Conf.GetDuration("nfs.enum", "timeout", 3*time.Second)
	var out []nfsResult
	for _, h := range openHosts(ctx) {
		hasRPC := hasPort(h, 111)
		hasNFS := hasPort(h, 2049)
		if !hasRPC && !hasNFS {
			continue
		}
		res := nfsResult{Host: h.IP.String()}
		if hasNFS {
			// A NULL RPC program call on 2049 answers even without mounting,
			// proving an NFSv4 server is present.
			if err := rpc.NFSNullProbe(net.JoinHostPort(h.IP.String(), "2049"), 4, timeout); err == nil {
				res.NFSv4 = true
			}
		}
		if hasRPC {
			// rpcbind GETPORT for the MOUNT program (100005), version 3, over
			// TCP — the port mountd actually listens on.
			mountPort, err := rpc.PortMapGetPort(h.IP.String(), rpc.ProgMount, 3, 6, timeout)
			if err == nil && mountPort > 0 {
				exports, err := rpc.MountExports(net.JoinHostPort(h.IP.String(), strconv.Itoa(int(mountPort))), timeout)
				if err == nil {
					res.Exports = exports
					for _, ex := range exports {
						// Read-only exports are still interesting but less
						// critical than writable ones.
						ro := ""
						if ex.Readonly {
							ro = " [read-only]"
						}
						emit(ctx, "finding", fmt.Sprintf("nfs.enum: %s exports %q%s groups=%v", h.IP, ex.Dir, ro, ex.Groups))
					}
				}
			}
		}
		emit(ctx, "log", fmt.Sprintf("nfs.enum: %s nfsv4=%v exports=%d", h.IP, res.NFSv4, len(res.Exports)))
		out = append(out, res)
	}
	ctx.SetState("nfs.enum", out)
	ctx.Printf("[*] nfs.enum complete: %d NFS host(s) checked.\n", len(out))
	return nil
}

// Verify reports the exports found.
func (*NFSEnum) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("nfs.enum")
	if !ok {
		return nil, fmt.Errorf("nfs.enum not run")
	}
	res, _ := v.([]nfsResult)
	imp := &attacks.Impact{Summary: fmt.Sprintf("checked %d NFS host(s)", len(res))}
	for _, r := range res {
		imp.Add("nfs", r.Host+" nfsv4="+fmt.Sprint(r.NFSv4)+" exports="+fmt.Sprint(len(r.Exports)))
	}
	return imp, nil
}

// Cleanup is a no-op.
func (*NFSEnum) Cleanup(_ *attacks.AttackCtx) error { return nil }

// Compile-time assertion that NFSEnum satisfies the Module contract.
var _ attacks.Module = (*NFSEnum)(nil)
