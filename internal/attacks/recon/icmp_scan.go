package recon

import (
	"fmt"
	"math/rand/v2"
	"net"
	"sort"
	"strconv"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/qyvora/toha3ee/internal/attacks"
	"github.com/qyvora/toha3ee/internal/events"
	"github.com/qyvora/toha3ee/internal/netx/arp"
	"github.com/qyvora/toha3ee/internal/netx/ports"
	"github.com/qyvora/toha3ee/internal/safety"
	"github.com/qyvora/toha3ee/internal/stealth"
)

// NetPing is an ICMP host-discovery sweep using echo, timestamp or address-
// mask requests. It complements the ARP sweep for hosts beyond the local
// subnet.
type NetPing struct{}

// Meta implements attacks.Module.
func (*NetPing) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "net.ping",
		Category:    "recon",
		Risk:        attacks.RiskLow,
		Targets:     []string{"subnet"},
		Requires:    []string{"cap.raw_socket"},
		Description: "host discovery sweep (ICMP echo/timestamp/address-mask, TCP SYN ping, UDP ping)",
		Limitations: "hosts that block the chosen probe type are not detected; combine modes to cover hardened targets",
	}
}

// Preflight checks root and the interface.
func (*NetPing) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
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

// icmpType maps the configured probe mode to request/reply ICMP types.
type icmpMode struct {
	req byte
	rep byte
}

var icmpModes = map[string]icmpMode{
	"echo":        {req: 8, rep: 0},
	"timestamp":   {req: 13, rep: 14},
	"addressmask": {req: 17, rep: 18},
}

// Run dispatches by probe mode: ICMP echo/timestamp/address-mask, a TCP SYN
// ping against common service ports, or a UDP ping that watches for ICMP
// port-unreachable replies.
func (*NetPing) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	mode := ctx.Conf.Get("net.ping", "mode")
	if m, ok := opts["mode"]; ok && m != "" {
		mode = m
	}
	switch mode {
	case "tcpsyn":
		return runTCPPing(ctx, opts)
	case "udp":
		return runUDPPing(ctx, opts)
	}
	if _, ok := icmpModes[mode]; !ok {
		mode = "echo"
	}
	return runICMPPing(ctx, mode)
}

func runICMPPing(ctx *attacks.AttackCtx, mname string) error {
	mode := icmpModes[mname]
	timeout := ctx.Conf.GetDuration("net.ping", "timeout", 1200*time.Millisecond)
	st := stealth.FromConfig(ctx.Conf, "net.ping")

	targets, err := pingTargets(ctx)
	if err != nil {
		return err
	}
	st.Shuffle(len(targets), func(i, j int) { targets[i], targets[j] = targets[j], targets[i] })

	conn, err := icmp.ListenPacket("ip4:icmp", ctx.Iface.IP.String())
	if err != nil {
		return fmt.Errorf("net.ping: open icmp socket: %w", err)
	}
	defer conn.Close()

	id := uint16(rand.IntN(0xffff))
	alive := make([]net.IP, 0, len(targets))
	sent := 0
	for _, ip := range targets {
		select {
		case <-ctx.Done:
			return nil
		default:
		}
		st.JitterSleep()
		var msg icmp.Message
		switch mode.req {
		case 13:
			msg = icmp.Message{Type: ipv4.ICMPType(mode.req), Code: 0, Body: &icmp.RawBody{Data: make([]byte, 12)}}
		case 17:
			msg = icmp.Message{Type: ipv4.ICMPType(mode.req), Code: 0, Body: &icmp.RawBody{Data: make([]byte, 4)}}
		default:
			msg = icmp.Message{Type: ipv4.ICMPType(mode.req), Code: 0, Body: &icmp.Echo{ID: int(id), Seq: sent + 1, Data: []byte("toha3ee")}}
		}
		wb, err := msg.Marshal(nil)
		if err != nil {
			continue
		}
		if _, err := conn.WriteTo(wb, &net.IPAddr{IP: ip}); err == nil {
			sent++
		}
	}

	// Collect answers for the sweep window.
	deadline := time.Now().Add(timeout)
	got := map[string]bool{}
	buf := make([]byte, 1500)
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}
		rm, err := icmp.ParseMessage(1, buf[:n])
		if err != nil {
			continue
		}
		if rm.Type != ipv4.ICMPType(mode.rep) {
			continue
		}
		if pa, ok := peer.(*net.IPAddr); ok && !got[pa.IP.String()] {
			got[pa.IP.String()] = true
			alive = append(alive, pa.IP)
		}
	}

	for _, ip := range alive {
		ctx.Emit(events.TopicLog, fmt.Sprintf("net.ping: %s answered (mode=%s)", ip, modeName(mode.req)), nil)
	}
	ctx.SetState("net.ping", alive)
	ctx.Printf("[*] net.ping complete: %d/%d host(s) answered %s probes.\n", len(alive), len(targets), modeName(mode.req))
	return nil
}

func modeName(req byte) string {
	for k, m := range icmpModes {
		if m.req == req {
			return k
		}
	}
	return "icmp"
}

// pingTargets resolves the module's target set: explicit targets config wins,
// otherwise the whole interface subnet.
func pingTargets(ctx *attacks.AttackCtx) ([]net.IP, error) {
	t := ctx.Conf.Get("net.ping", "targets")
	if t != "" {
		return parseIPsAndCIDRs(t)
	}
	if ctx.Iface == nil || ctx.Iface.Net == nil {
		return nil, fmt.Errorf("net.ping: no targets configured and no interface subnet")
	}
	return arp.CIDRHosts(ctx.Iface.Net), nil
}

// Verify reports the number of live hosts.
func (*NetPing) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("net.ping")
	if !ok {
		return nil, fmt.Errorf("net.ping not run")
	}
	alive, _ := v.([]net.IP)
	imp := &attacks.Impact{Summary: fmt.Sprintf("%d host(s) responded to ICMP", len(alive))}
	imp.Add("alive", strconv.Itoa(len(alive)))
	sort.Slice(alive, func(i, j int) bool { return alive[i].String() < alive[j].String() })
	for _, ip := range alive {
		imp.Add("host", ip.String())
	}
	return imp, nil
}

// Cleanup is a no-op.
func (*NetPing) Cleanup(ctx *attacks.AttackCtx) error { return nil }

var _ attacks.Module = (*NetPing)(nil)

// tcpPingPorts are the service ports probed by a TCP SYN ping.
var tcpPingPorts = []uint16{22, 25, 80, 443, 445, 8080, 3389}

// runTCPPing discovers hosts by sending SYN probes to common service ports.
// A host is alive if any port replies with SYN-ACK (open) or RST (closed);
// filtered ports alone mean the host may still be up but the probe was dropped.
func runTCPPing(ctx *attacks.AttackCtx, opts map[string]string) error {
	portsToScan := tcpPingPorts
	if p := ctx.Conf.Get("net.ping", "ports"); p != "" {
		portsToScan = parsePorts(splitList(p))
	}
	timeout := ctx.Conf.GetDuration("net.ping", "timeout", 1200*time.Millisecond)

	scanner, err := ports.NewScanner(ctx.Iface)
	if err != nil {
		return fmt.Errorf("net.ping: %w", err)
	}
	defer scanner.Close()
	scanner.SetStealth(stealth.FromConfig(ctx.Conf, "net.ping"))

	targets, err := pingTargets(ctx)
	if err != nil {
		return err
	}
	var alive []net.IP
	for _, ip := range targets {
		select {
		case <-ctx.Done:
			return nil
		default:
		}
		res, err := scanner.Scan(ip, portsToScan, timeout/3)
		if err != nil {
			continue
		}
		up := false
		for _, r := range res {
			if r.State != ports.Filtered {
				up = true
				break
			}
		}
		if up {
			alive = append(alive, ip)
			ctx.Emit(events.TopicLog, fmt.Sprintf("net.ping: %s answered TCP SYN probes", ip), nil)
		}
	}
	ctx.SetState("net.ping", alive)
	ctx.Printf("[*] net.ping complete (mode=tcpsyn): %d/%d host(s) answered.\n", len(alive), len(targets))
	return nil
}

// runUDPPing discovers hosts by sending a UDP datagram to a likely-closed port
// and listening for the ICMP port-unreachable reply, which is proof the host
// is up even when it drops ICMP echo.
func runUDPPing(ctx *attacks.AttackCtx, opts map[string]string) error {
	port := ctx.Conf.GetInt("net.ping", "udpport", 40125)
	timeout := ctx.Conf.GetDuration("net.ping", "timeout", 1500*time.Millisecond)
	st := stealth.FromConfig(ctx.Conf, "net.ping")

	targets, err := pingTargets(ctx)
	if err != nil {
		return err
	}
	st.Shuffle(len(targets), func(i, j int) { targets[i], targets[j] = targets[j], targets[i] })

	ic, err := icmp.ListenPacket("ip4:icmp", ctx.Iface.IP.String())
	if err != nil {
		return fmt.Errorf("net.ping: open icmp socket: %w", err)
	}
	defer ic.Close()

	got := map[string]bool{}
	var alive []net.IP
	for _, ip := range targets {
		select {
		case <-ctx.Done:
			return nil
		default:
		}
		st.JitterSleep()
		conn, err := net.DialTimeout("udp", net.JoinHostPort(ip.String(), fmt.Sprint(port)), timeout)
		if err != nil {
			continue
		}
		if _, err := conn.Write([]byte{0x00}); err == nil {
			// The ICMP unreachable will quote this socket's port; any reply
			// from this host means it is up.
		}
		conn.Close()
	}

	// Collect ICMP port-unreachable replies for the sweep window.
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 1500)
	for time.Now().Before(deadline) {
		_ = ic.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, peer, err := ic.ReadFrom(buf)
		if err != nil {
			continue
		}
		rm, err := icmp.ParseMessage(1, buf[:n])
		if err != nil {
			continue
		}
		if rm.Type != ipv4.ICMPType(3) || rm.Code != 3 {
			continue
		}
		if _, ok := rm.Body.(*icmp.DstUnreach); !ok {
			continue
		}
		pa, ok := peer.(*net.IPAddr)
		if !ok || got[pa.IP.String()] {
			continue
		}
		got[pa.IP.String()] = true
		alive = append(alive, pa.IP)
		ctx.Emit(events.TopicLog, fmt.Sprintf("net.ping: %s answered UDP probes (ICMP port-unreachable)", pa.IP), nil)
	}
	ctx.SetState("net.ping", alive)
	ctx.Printf("[*] net.ping complete (mode=udp): %d/%d host(s) answered.\n", len(alive), len(targets))
	return nil
}
