package recon

import (
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-toha3ee/internal/attacks"
	"github.com/QYVORA/qyvora-toha3ee/internal/events"
	"github.com/QYVORA/qyvora-toha3ee/internal/stealth"
)

// ServiceTLS fingerprints the TLS stack of HTTPS services: certificate
// details, negotiated protocol version, cipher suite and ALPN. It also flags
// weak configuration (legacy TLS, weak ciphers, expired certificates) which
// feeds the vector engine's attack ranking.
type ServiceTLS struct{}

// Meta implements attacks.Module.
func (*ServiceTLS) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "service.tls",
		Category:    "recon",
		Risk:        attacks.RiskLow,
		Targets:     []string{"service"},
		Description: "TLS handshake probe of HTTPS services: certificate, protocol, cipher and weak-config findings",
		Limitations: "SNI-based virtual hosts may present a default certificate; only ports open per the scan are probed",
	}
}

// tlsFinding is the summary of one successful TLS handshake probe.
type tlsFinding struct {
	Host    string
	Port    uint16
	Version string
	Cipher  string
	ALPN    string
	Issuer  string
	Subject string
	SANs    string
	Expires string
	Issues  []string
}

// Preflight needs discovered hosts.
func (*ServiceTLS) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if len(ctx.Store.Hosts()) == 0 {
		rep.AddFixable("targets", "no hosts discovered; run net.scan first")
	} else {
		rep.AddOK("targets", fmt.Sprintf("%d host(s) available", len(ctx.Store.Hosts())))
	}
	return rep, nil
}

// Run dials TLS on HTTPS ports of each discovered host.
func (*ServiceTLS) Run(ctx *attacks.AttackCtx, _ map[string]string) error {
	st := stealth.FromConfig(ctx.Conf, "service.tls")
	timeout := ctx.Conf.GetDuration("service.tls", "timeout", 2*time.Second)
	portsToScan := parsePorts(strings.Split(ctx.Conf.Get("service.tls", "ports"), ","))
	if len(portsToScan) == 0 {
		portsToScan = []uint16{443, 8443}
	}

	var findings []tlsFinding
	probed := 0
	for _, h := range ctx.Store.Hosts() {
		open := map[uint16]bool{}
		for _, p := range h.OpenPorts() {
			open[p] = true
		}
		for _, p := range portsToScan {
			if !open[p] {
				continue
			}
			select {
			case <-ctx.Done:
				return nil
			default:
			}
			st.JitterSleep()
			f, err := probeTLS(h.IP, p, timeout)
			if err != nil {
				continue
			}
			probed++
			findings = append(findings, f)
			summary := fmt.Sprintf("service.tls: %s:%d %s cipher=%s", h.IP, p, f.Version, f.Cipher)
			if len(f.Issues) > 0 {
				summary += " issues=[" + strings.Join(f.Issues, ",") + "]"
			}
			ctx.Emit(events.TopicLog, summary, nil)
			h.SetPort(p, "tls/"+f.Version)
			h.TLS = true
		}
	}
	ctx.SetState("service.tls", findings)
	ctx.Printf("[*] service.tls complete: %d TLS service(s) fingerprinted.\n", probed)
	return nil
}

// probeTLS performs a full TLS handshake and summarizes the certificate.
func probeTLS(ip net.IP, port uint16, timeout time.Duration) (tlsFinding, error) {
	d := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(int(port))), &tls.Config{
		InsecureSkipVerify: true, // we want the cert regardless of chain trust
		MinVersion:         tls.VersionTLS10,
	})
	if err != nil {
		return tlsFinding{}, err
	}
	defer func() { _ = conn.Close() }()

	f := tlsFinding{Host: ip.String(), Port: port}
	state := conn.ConnectionState()
	f.Version = tls.VersionName(state.Version)
	f.Cipher = tls.CipherSuiteName(state.CipherSuite)
	f.ALPN = state.NegotiatedProtocol

	// Flag weak configuration for the vector engine.
	if state.Version < tls.VersionTLS12 {
		f.Issues = append(f.Issues, "legacy-tls")
	}
	if strings.HasPrefix(f.Cipher, "TLS_RSA_WITH_") {
		f.Issues = append(f.Issues, "weak-cipher")
	}
	// Summarize the first non-empty certificate in the presented chain.
	for _, cert := range state.PeerCertificates {
		if cert == nil || cert.Subject.CommonName == "" && len(cert.DNSNames) == 0 {
			continue
		}
		f.Subject = cert.Subject.String()
		f.Issuer = cert.Issuer.String()
		f.Expires = cert.NotAfter.Format("2006-01-02")
		sans := append(append([]string{}, cert.DNSNames...), ipNames(cert.IPAddresses)...)
		f.SANs = strings.Join(sans, ",")
		if time.Now().After(cert.NotAfter) {
			f.Issues = append(f.Issues, "expired")
		}
		break
	}
	return f, nil
}

// ipNames formats the IP SANs of a certificate as strings.
func ipNames(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

// Verify reports the TLS findings and weak-configuration count.
func (*ServiceTLS) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("service.tls")
	if !ok {
		return nil, fmt.Errorf("service.tls not run")
	}
	findings, _ := v.([]tlsFinding)
	imp := &attacks.Impact{Summary: fmt.Sprintf("fingerprinted %d TLS service(s)", len(findings))}
	imp.Add("tls_services", strconv.Itoa(len(findings)))
	issues := 0
	for _, f := range findings {
		imp.Add("tls", fmt.Sprintf("%s:%d %s %s", f.Host, f.Port, f.Version, f.Cipher))
		if len(f.Issues) > 0 {
			issues += len(f.Issues)
			imp.Add("issue", fmt.Sprintf("%s:%d [%s]", f.Host, f.Port, strings.Join(f.Issues, ",")))
		}
	}
	imp.Add("issues", strconv.Itoa(issues))
	return imp, nil
}

// Cleanup is a no-op.
func (*ServiceTLS) Cleanup(_ *attacks.AttackCtx) error {
	return nil
}

var _ attacks.Module = (*ServiceTLS)(nil)
