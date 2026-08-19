package recon

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/QYVORA/qyvora-toha3ee/internal/attacks"
	"github.com/QYVORA/qyvora-toha3ee/internal/events"
	"github.com/QYVORA/qyvora-toha3ee/internal/netx/ports"
	"github.com/QYVORA/qyvora-toha3ee/internal/stealth"
)

// UDPScan probes UDP ports of discovered hosts using connected sockets: an
// ICMP port-unreachable marks a port closed, a reply marks it open, and
// silence marks open-or-filtered.
type UDPScan struct{}

// Meta implements attacks.Module.
func (*UDPScan) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "service.udpscan",
		Category:    "recon",
		Risk:        attacks.RiskLow,
		Targets:     []string{"host"},
		Description: "UDP port scan via connected-socket ICMP unreachable detection; slow, often filtered",
		Limitations: "UDP scanning is inherently unreliable: silence means open-or-filtered, and ICMP rate-limiting skews results",
	}
}

// UDPCommonPorts is the default UDP service set (DNS, DHCP, NTP, SNMP, mDNS,
// CoAP, memcached, MongoDB, etc.).
var UDPCommonPorts = []uint16{
	53, 67, 68, 69, 123, 137, 138, 161, 162, 389, 500, 514, 520,
	1900, 2222, 3478, 4500, 5353, 5683, 11211, 27017,
}

// Preflight needs hosts.
func (*UDPScan) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if len(ctx.Store.Hosts()) == 0 {
		rep.AddFixable("targets", "no hosts discovered; run net.scan first")
	} else {
		rep.AddOK("targets", fmt.Sprintf("%d host(s) discovered", len(ctx.Store.Hosts())))
	}
	return rep, nil
}

// Run probes each UDP port with a connected socket.
func (*UDPScan) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	portsToScan := UDPCommonPorts
	if p := ctx.Conf.Get("service.udpscan", "ports"); p != "" {
		portsToScan = parsePorts(splitList(p))
	}
	timeout := ctx.Conf.GetDuration("service.udpscan", "timeout", 1800*time.Millisecond)
	workers := ctx.Conf.GetInt("service.udpscan", "workers", 8)
	st := stealth.FromConfig(ctx.Conf, "service.udpscan")

	// Counters are shared across the worker goroutines, so they are guarded
	// by the mutex; the worker semaphore caps concurrent in-flight probes.
	var mu sync.Mutex
	open := 0
	closed := 0
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup

	for _, h := range ctx.Store.Hosts() {
		for _, p := range portsToScan {
			select {
			case <-ctx.Done:
				wg.Wait()
				return nil
			default:
			}
			st.JitterSleep()
			wg.Add(1)
			sem <- struct{}{}
			go func(ip net.IP, port uint16) {
				defer wg.Done()
				defer func() { <-sem }()
				addr := &net.UDPAddr{IP: ip, Port: int(port)}
				conn, err := net.DialUDP("udp", nil, addr)
				if err != nil {
					return
				}
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(timeout))
				_, _ = conn.Write([]byte{0})
				buf := make([]byte, 512)
				n, err := conn.Read(buf)
				if err != nil {
					// ICMP port-unreachable surfaces as ECONNREFUSED on a
					// connected socket; timeouts mean open-or-filtered.
					if isConnRefused(err) {
						mu.Lock()
						closed++
						mu.Unlock()
					}
					return
				}
				svc := ports.GuessService(port)
				mu.Lock()
				open++
				mu.Unlock()
				// A non-empty reply is a live service; an empty one still
				// proves the port is reachable.
				if n > 0 {
					setHostPort(ctx, ip, port, "udp/"+svc)
					ctx.Emit(events.TopicLog, fmt.Sprintf("service.udpscan: %s:%d/udp answered (%s)", ip, port, svc), nil)
				} else {
					ctx.Emit(events.TopicLog, fmt.Sprintf("service.udpscan: %s:%d/udp responded empty (%s)", ip, port, svc), nil)
				}
			}(h.IP, p)
		}
	}
	wg.Wait()
	ctx.SetState("service.udpscan", open)
	ctx.Printf("[*] service.udpscan complete: %d open, %d closed, rest open|filtered.\n", open, closed)
	return nil
}

// isConnRefused recognizes ICMP port-unreachable surfaced as an OS error on a
// connected UDP socket (Linux reports ECONNREFUSED on the next read).
func isConnRefused(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	var ne *net.OpError
	if errors.As(err, &ne) && errors.Is(ne.Err, syscall.ECONNREFUSED) {
		return true
	}
	return strings.Contains(err.Error(), "connection refused")
}

// Verify reports the open UDP count.
func (*UDPScan) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("service.udpscan")
	if !ok {
		return nil, fmt.Errorf("service.udpscan not run")
	}
	n, _ := v.(int)
	imp := &attacks.Impact{Summary: fmt.Sprintf("%d UDP port(s) answered", n)}
	imp.Add("open_udp", strconv.Itoa(n))
	return imp, nil
}

// Cleanup is a no-op.
func (*UDPScan) Cleanup(ctx *attacks.AttackCtx) error { return nil }

var _ attacks.Module = (*UDPScan)(nil)
