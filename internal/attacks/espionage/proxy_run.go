package espionage

import (
	"fmt"
	"strings"
	"time"

	"github.com/qyvora/toha3ee/internal/attacks"
	"github.com/qyvora/toha3ee/internal/hijack"
	"github.com/qyvora/toha3ee/internal/netx/proxy"
	"github.com/qyvora/toha3ee/internal/safety"
	"github.com/qyvora/toha3ee/pkg/certutil"
)

// proxyConfig builds a proxy.Config from the session context. The generic
// http.proxy namespace supplies the listener address and injected JS while
// the ssl.strip namespace toggles link/header stripping, so every proxy-based
// module shares the same plumbing.
func proxyConfig(ctx *attacks.AttackCtx, withCA bool) proxy.Config {
	cfg := proxy.Config{
		ListenAddr: ctx.Conf.GetDefault("http.proxy", "listen", "0.0.0.0:8080"),
		DB:         ctx.Store,
		Bus:        ctx.Bus,
		Injector:   hijack.NewInjector(),
		InjectedJS: ctx.Conf.Get("http.proxy", "javascript"),
		// Stripping is on if either namespace opts in — this lets ssl.strip
		// enable it from its own module without a second config knob.
		SSLStrip: isTrue(ctx.Conf.Get("ssl.strip", "sslstrip")) || isTrue(ctx.Conf.Get("http.proxy", "sslstrip")),
	}
	if withCA {
		// HTTPS interception needs the framework CA so the proxy can mint
		// per-host leaf certificates victims will trust.
		cfg.CA = sessionCA(ctx)
	}
	return cfg
}

// isTrue parses a loose boolean config value ("1", "true", "yes", "on").
// Config files commonly use any of these spellings, so the parser accepts the
// full family instead of requiring "true".
func isTrue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on", "enabled":
		return true
	}
	return false
}

// sessionCA loads (or creates) the framework CA for HTTPS interception. The
// CA persists between sessions (pem/key files) so victims only install the
// trust anchor once.
func sessionCA(ctx *attacks.AttackCtx) *certutil.CA {
	certPath := ctx.Conf.GetDefault("https.proxy", "ca_cert", "toha3ee-ca.pem")
	keyPath := ctx.Conf.GetDefault("https.proxy", "ca_key", "toha3ee-ca.key")
	ca, err := certutil.LoadOrCreateCA(certPath, keyPath)
	if err != nil {
		// The proxy can still run in tunnel mode; interception just won't
		// work. Warn loudly and continue without a CA.
		ctx.Printf("[!] https.proxy: CA unavailable: %v (install %s on victims)\n", err, certPath)
		return nil
	}
	return ca
}

// startProxy creates and starts the proxy with the desired MITM posture. It
// stores the instance in ctx.State and registers the safety cleanup so any
// session teardown stops the listener.
func startProxy(ctx *attacks.AttackCtx, withCA bool) (*proxy.MITMProxy, error) {
	cfg := proxyConfig(ctx, withCA)
	mp := proxy.New(cfg)
	addr, err := mp.Start()
	if err != nil {
		return nil, err
	}
	ctx.SetState(proxyStateKey, mp)
	ctx.Safety.RegisterCleanup(proxyStateKey, "stop MITM proxy", func() error {
		mp.Stop()
		return nil
	})
	_ = addr
	return mp, nil
}

// proxyStateKey is the shared AttackCtx key under which the running proxy is
// stored. Sharing one key lets Verify/Cleanup across all proxy modules use
// the same code path.
const proxyStateKey = "mitm.proxy"

// blockProxy keeps a long-running proxy module alive: it beats the watchdog
// every 2 seconds and returns when the session signals shutdown.
func blockProxy(ctx *attacks.AttackCtx, mp *proxy.MITMProxy, name string) error {
	hb := safety.NewHeartbeat()
	ctx.Heartbeat = hb.Beat
	ctx.Safety.RegisterHeartbeat(name, hb)
	for {
		select {
		case <-ctx.Done:
			return nil
		case <-time.After(2 * time.Second):
			hb.Beat()
		}
	}
}

// proxyImpact builds the shared Impact for every proxy module from the
// live proxy's counters.
func proxyImpact(ctx *attacks.AttackCtx, name string) (*attacks.Impact, error) {
	v, ok := ctx.GetState(proxyStateKey)
	if !ok {
		return nil, fmt.Errorf("%s not running", name)
	}
	mp := v.(*proxy.MITMProxy)
	reqs, harvest, swaps := mp.Stats()
	imp := &attacks.Impact{
		Summary: fmt.Sprintf("proxy handled %d request(s); %d harvest(s), %d form swap(s)", reqs, harvest, swaps),
	}
	imp.Add("requests", fmt.Sprintf("%d", reqs))
	imp.Add("harvests", fmt.Sprintf("%d", harvest))
	imp.Add("swaps", fmt.Sprintf("%d", swaps))
	imp.Add("listener", mp.Addr())
	imp.Add("tls_mitm", fmt.Sprintf("%v", mp.TLSEnabled()))
	return imp, nil
}

// stopProxy tears down a proxy module: it unregisters the heartbeat/cleanup
// entries first (so shutdown cannot double-stop) and then stops the proxy.
func stopProxy(ctx *attacks.AttackCtx, name string) error {
	ctx.Safety.UnregisterHeartbeat(name)
	ctx.Safety.UnregisterCleanup(proxyStateKey)
	if v, ok := ctx.GetState(proxyStateKey); ok {
		v.(*proxy.MITMProxy).Stop()
	}
	return nil
}
