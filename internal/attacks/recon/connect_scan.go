package recon

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/qyvora/toha3ee/internal/attacks"
	"github.com/qyvora/toha3ee/internal/events"
	"github.com/qyvora/toha3ee/internal/netx/ports"
	"github.com/qyvora/toha3ee/internal/stealth"
)

// TCPConnectScan performs a full TCP connect scan (complete three-way
// handshake) against discovered hosts. It needs no raw sockets, so it works
// without root, at the cost of being the noisiest scan mode.
type TCPConnectScan struct{}

// Meta implements attacks.Module, returning the module's registry descriptor.
func (*TCPConnectScan) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:       "service.tcpconnect",
		Category: "recon",
		Risk:     attacks.RiskLow,
		Targets:  []string{"host"},
		// No Requires: net.Dial completes real connections through the kernel
		// stack, so no root or raw sockets are needed.
		Description: "full TCP connect scan (three-way handshake) of well-known ports; no root needed, noisier than SYN",
		Limitations: "completes connections, so it is the most detectable scan mode and leaves connection logs",
	}
}

// Preflight needs hosts.
func (*TCPConnectScan) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if len(ctx.Store.Hosts()) == 0 {
		rep.AddFixable("targets", "no hosts discovered; run net.scan first")
	} else {
		rep.AddOK("targets", fmt.Sprintf("%d host(s) discovered", len(ctx.Store.Hosts())))
	}
	return rep, nil
}

// Run dials every configured port on every discovered host.
func (*TCPConnectScan) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	portsToScan := ports.CommonPorts
	if p := ctx.Conf.Get("service.tcpconnect", "ports"); p != "" {
		portsToScan = parsePorts(splitList(p))
	}
	timeout := ctx.Conf.GetDuration("service.tcpconnect", "timeout", 1200*time.Millisecond)
	workers := ctx.Conf.GetInt("service.tcpconnect", "workers", 16)
	st := stealth.FromConfig(ctx.Conf, "service.tcpconnect")

	// The worker pool is bounded by a semaphore so we never open more than
	// `workers` simultaneous connections; the mutex guards the shared counter.
	var mu sync.Mutex
	open := 0
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup

	for _, h := range ctx.Store.Hosts() {
		for _, p := range portsToScan {
			select {
			case <-ctx.Done:
				// Cancel: wait for in-flight probes to finish so the shared
				// counter and host store are not mutated while being torn down.
				wg.Wait()
				return nil
			default:
			}
			st.JitterSleep()
			wg.Add(1)
			sem <- struct{}{}
			go func(ip net.IP, port uint16) {
				defer wg.Done()
				defer func() { <-sem }() // release the worker slot
				addr := net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
				// A successful Dial means the full SYN -> SYN-ACK -> ACK
				// handshake completed, i.e. the port is open.
				conn, err := net.DialTimeout("tcp", addr, timeout)
				if err != nil {
					// Dial errors (RST/refused, timeout) mean closed or
					// filtered; either way not an open port.
					return
				}
				conn.Close()
				mu.Lock()
				open++
				mu.Unlock()
				svc := ports.GuessService(port)
				setHostPort(ctx, ip, port, svc)
				ctx.Emit(events.TopicLog, fmt.Sprintf("service.tcpconnect: %s:%d open (%s)", ip, port, svc), nil)
			}(h.IP, p)
		}
	}
	wg.Wait()
	ctx.SetState("service.tcpconnect", open)
	ctx.Printf("[*] service.tcpconnect complete: %d open port(s).\n", open)
	return nil
}

// Verify reports the open port count.
func (*TCPConnectScan) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("service.tcpconnect")
	if !ok {
		return nil, fmt.Errorf("service.tcpconnect not run")
	}
	n, _ := v.(int)
	imp := &attacks.Impact{Summary: fmt.Sprintf("found %d open service port(s)", n)}
	imp.Add("open_ports", strconv.Itoa(n))
	for _, h := range ctx.Store.Hosts() {
		if len(h.OpenPorts()) > 0 {
			imp.Add("host", h.IP.String()+" "+fmt.Sprint(h.OpenPorts()))
		}
	}
	return imp, nil
}

// Cleanup is a no-op.
func (*TCPConnectScan) Cleanup(ctx *attacks.AttackCtx) error { return nil }

// Compile-time assertion that TCPConnectScan implements attacks.Module.
var _ attacks.Module = (*TCPConnectScan)(nil)
