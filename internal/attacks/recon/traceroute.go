package recon

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/qyvora/toha3ee/internal/attacks"
	"github.com/qyvora/toha3ee/internal/events"
	"github.com/qyvora/toha3ee/internal/safety"
	"github.com/qyvora/toha3ee/internal/stealth"
)

// NetTraceroute maps the network path to a target using the classic
// UDP-mode traceroute: increasing IP TTLs with ICMP time-exceeded replies
// identifying each hop.
type NetTraceroute struct{}

// Meta implements attacks.Module.
func (*NetTraceroute) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "net.traceroute",
		Category:    "recon",
		Risk:        attacks.RiskInfo,
		Targets:     []string{"host"},
		Requires:    []string{"cap.raw_socket"},
		Description: "UDP-mode traceroute to map the network path and intermediate hops",
		Limitations: "firewalls that rate-limit or drop ICMP time-exceeded make some hops appear as '*'",
	}
}

// Preflight checks root and the interface.
func (*NetTraceroute) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if err := safety.RequireRoot(); err != nil {
		rep.AddBlocked("root", err.Error())
	} else {
		rep.AddOK("root", "ICMP raw socket available")
	}
	if ctx.Iface == nil {
		rep.AddBlocked("iface", "no interface configured")
	}
	return rep, nil
}

// hopResult is one resolved hop on the path.
type hopResult struct {
	Hop  int
	IP   string
	RTT  time.Duration
	Done bool // reached the target
}

// Run traces the path to the target (default: the interface gateway).
func (*NetTraceroute) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	target := ctx.Conf.Get("net.traceroute", "target")
	if target == "" {
		gw, err := ctx.Iface.Gateway()
		if err != nil {
			return fmt.Errorf("net.traceroute: set net.traceroute.target (no default gateway found)")
		}
		target = gw.String()
	}
	targetIP := net.ParseIP(target)
	if targetIP == nil {
		return fmt.Errorf("net.traceroute: invalid target %q", target)
	}
	maxHops := ctx.Conf.GetInt("net.traceroute", "max_hops", 30)
	timeout := ctx.Conf.GetDuration("net.traceroute", "timeout", time.Second)
	probes := ctx.Conf.GetInt("net.traceroute", "probes", 3)
	st := stealth.FromConfig(ctx.Conf, "net.traceroute")
	basePort := ctx.Conf.GetInt("net.traceroute", "port", 33434)

	ic, err := icmp.ListenPacket("ip4:icmp", ctx.Iface.IP.String())
	if err != nil {
		return fmt.Errorf("net.traceroute: open icmp socket: %w", err)
	}
	defer ic.Close()

	// The UDP socket carries the probes; we vary the per-probe TTL via
	// PacketConn so the kernel stamps the outgoing IP header for us.
	udp, err := net.ListenPacket("udp4", "")
	if err != nil {
		return fmt.Errorf("net.traceroute: open udp socket: %w", err)
	}
	defer udp.Close()
	pc := ipv4.NewPacketConn(udp)
	if err := pc.SetTTL(1); err != nil {
		return fmt.Errorf("net.traceroute: set ttl: %w", err)
	}

	// replies maps probe identity -> hop source IP.
	// probe identity is the UDP destination port; reply src is the hop.
	type probeKey struct{ port int }
	replies := map[int]string{}
	done := map[int]bool{}

	// Collector goroutine for ICMP answers.
	stop := make(chan struct{})
	go func() {
		buf := make([]byte, 1500)
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = ic.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			n, peer, err := ic.ReadFrom(buf)
			if err != nil {
				continue
			}
			rm, err := icmp.ParseMessage(1, buf[:n])
			if err != nil {
				continue
			}
			port := quotedUDPPort(rm)
			if port == 0 {
				continue
			}
			if src, ok := peer.(*net.IPAddr); ok {
				replies[port] = src.IP.String()
				// Destination unreachable means the target itself answered:
				// it refused our UDP datagram on the chosen (unused) port.
				if rm.Type == ipv4.ICMPTypeDestinationUnreachable {
					done[port] = true
				}
			}
		}
	}()

	var hops []hopResult
	progress := 0
	for ttl := 1; ttl <= maxHops; ttl++ {
		select {
		case <-ctx.Done:
			close(stop)
			return nil
		default:
		}
		_ = pc.SetTTL(ttl)
		best := time.Duration(0)
		got := ""
		reached := false
		for i := 0; i < probes; i++ {
			st.JitterSleep()
			// Each probe gets a fresh destination port so the collector can
			// correlate the ICMP quote back to this hop iteration.
			port := basePort + progress
			progress++
			start := time.Now()
			if _, err := udp.WriteTo([]byte{0}, &net.UDPAddr{IP: targetIP, Port: port}); err != nil {
				continue
			}
			// Wait for this probe's reply.
			deadline := time.Now().Add(timeout)
			for time.Now().Before(deadline) {
				if src, ok := replies[port]; ok {
					rtt := time.Since(start)
					if best == 0 || rtt < best {
						best = rtt
						got = src
					}
					reached = done[port]
					delete(replies, port)
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
		}
		hops = append(hops, hopResult{Hop: ttl, IP: got, RTT: best, Done: reached})
		if got != "" {
			ctx.Emit(events.TopicLog, fmt.Sprintf("net.traceroute: hop %d %s %s", ttl, got, best.Round(time.Millisecond)), nil)
		}
		if reached {
			break
		}
	}
	close(stop)

	ctx.SetState("net.traceroute", hops)
	for _, h := range hops {
		label := "*"
		if h.IP != "" {
			label = fmt.Sprintf("%s (%s)", h.IP, h.RTT.Round(time.Millisecond))
		}
		ctx.Printf("[*] net.traceroute: %2d  %s\n", h.Hop, label)
	}
	return nil
}

// quotedUDPPort extracts the original UDP destination port from an ICMP
// time-exceeded / unreachable message body (the quoted IP packet).
func quotedUDPPort(rm *icmp.Message) int {
	var data []byte
	switch body := rm.Body.(type) {
	case *icmp.TimeExceeded:
		data = body.Data
	case *icmp.DstUnreach:
		data = body.Data
	default:
		return 0
	}
	if len(data) < 20 {
		return 0
	}
	if data[0]>>4 != 4 { // quoted packet must be IPv4
		return 0
	}
	// The quoted header's version/IHL byte tells us where the UDP header
	// begins; the destination port is its first two bytes.
	ihl := int(data[0]&0x0f) * 4
	if len(data) < ihl+4 {
		return 0
	}
	return int(data[ihl])<<8 | int(data[ihl+1])
}

// Verify reports the traced path.
func (*NetTraceroute) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("net.traceroute")
	if !ok {
		return nil, fmt.Errorf("net.traceroute not run")
	}
	hops, _ := v.([]hopResult)
	sort.Slice(hops, func(i, j int) bool { return hops[i].Hop < hops[j].Hop })
	imp := &attacks.Impact{Summary: fmt.Sprintf("traced %d hop(s)", len(hops))}
	imp.Add("hops", strconv.Itoa(len(hops)))
	for _, h := range hops {
		if h.IP != "" {
			imp.Add("hop", fmt.Sprintf("%d %s", h.Hop, h.IP))
		}
	}
	return imp, nil
}

// Cleanup is a no-op.
func (*NetTraceroute) Cleanup(ctx *attacks.AttackCtx) error { return nil }

var _ attacks.Module = (*NetTraceroute)(nil)
