package recon

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/qyvora/toha3ee/internal/attacks"
	"github.com/qyvora/toha3ee/internal/events"
	"github.com/qyvora/toha3ee/internal/netx/ports"
	"github.com/qyvora/toha3ee/internal/safety"
	"github.com/qyvora/toha3ee/internal/stealth"
)

// ServiceScan is a raw SYN scanner against discovered hosts.
type ServiceScan struct{}

// Meta implements attacks.Module.
func (*ServiceScan) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "service.synscan",
		Category:    "recon",
		Risk:        attacks.RiskLow,
		Targets:     []string{"host"},
		Requires:    []string{"cap.raw_socket"},
		Description: "half-open SYN scan of well-known ports on all discovered hosts",
		Limitations: "stealth firewalls report filtered rather than closed; slow targets may be missed",
	}
}

// Preflight checks root, interface and that hosts exist.
func (*ServiceScan) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if err := safety.RequireRoot(); err != nil {
		rep.AddBlocked("root", err.Error())
	} else {
		rep.AddOK("root", "raw packet injection available")
	}
	if ctx.Iface == nil {
		rep.AddBlocked("iface", "no interface configured")
		return rep, nil
	}
	rep.AddOK("iface", ctx.Iface.String())
	hosts := ctx.Store.Hosts()
	if len(hosts) == 0 {
		rep.AddFixable("targets", "no hosts discovered; run net.scan first")
	} else {
		rep.AddOK("targets", fmt.Sprintf("%d host(s) discovered", len(hosts)))
	}
	return rep, nil
}

// Run scans each discovered host on the common ports.
func (*ServiceScan) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	scanner, err := ports.NewScanner(ctx.Iface)
	if err != nil {
		return fmt.Errorf("service.synscan: %w", err)
	}
	defer scanner.Close()
	scanner.SetStealth(stealth.FromConfig(ctx.Conf, "service.synscan"))

	prune := ctx.Conf.Get("service.synscan", "ports")
	portsToScan := ports.CommonPorts
	if strings.TrimSpace(prune) != "" {
		portsToScan = parsePorts(strings.Split(prune, ","))
	}

	timeout := ctx.Conf.GetDuration("service.synscan", "timeout", 2500*time.Millisecond)
	targets := ctx.Store.Hosts()
	if len(targets) == 0 {
		return fmt.Errorf("service.synscan: no hosts; run net.scan first")
	}

	open := 0
	for _, h := range targets {
		results, err := scanner.Scan(h.IP, portsToScan, timeout)
		if err != nil {
			continue
		}
		for _, r := range results {
			if r.State != ports.Open {
				continue
			}
			open++
			svc := ports.GuessService(r.Port)
			h.SetPort(r.Port, svc)
			ctx.Store.LogEvent(events.TopicLog,
				fmt.Sprintf("service.synscan: %s/%d open (%s)", h.IP, r.Port, svc))
			ctx.Emit(events.TopicLog, fmt.Sprintf("[+] %s:%d %s", h.IP, r.Port, svc), nil)
		}
	}
	ctx.SetState("service.synscan", open)
	ctx.Printf("[*] service.synscan complete: %d open port(s) across %d host(s).\n", open, len(targets))
	return nil
}

// Verify reports the open port count.
func (*ServiceScan) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	open, _ := ctx.GetState("service.synscan")
	n, _ := open.(int)
	imp := &attacks.Impact{
		Summary: fmt.Sprintf("found %d open service port(s)", n),
	}
	imp.Add("open_ports", strconv.Itoa(n))
	for _, h := range ctx.Store.Hosts() {
		if len(h.OpenPorts()) > 0 {
			imp.Add("host", h.IP.String()+" "+fmt.Sprint(h.OpenPorts()))
		}
	}
	return imp, nil
}

// Cleanup is a no-op (scanner is closed in Run).
func (*ServiceScan) Cleanup(ctx *attacks.AttackCtx) error {
	return nil
}

func parsePorts(in []string) []uint16 {
	var out []uint16
	for _, s := range in {
		s = strings.TrimSpace(s)
		n, err := strconv.Atoi(s)
		if err != nil {
			continue
		}
		if n > 0 && n <= 65535 {
			out = append(out, uint16(n))
		}
	}
	if len(out) == 0 {
		return ports.CommonPorts
	}
	return out
}

// ServiceFingerprint grabs banners and HTTP titles from open ports.
type ServiceFingerprint struct{}

// Meta implements attacks.Module.
func (*ServiceFingerprint) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "service.fingerprint",
		Category:    "recon",
		Risk:        attacks.RiskLow,
		Targets:     []string{"host"},
		Description: "banner grab and HTTP title/session cookie fingerprinting of open ports",
		Limitations: "services that require protocol handshakes before a banner do not respond to a raw read",
	}
}

// Preflight just needs hosts.
func (*ServiceFingerprint) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if len(ctx.Store.Hosts()) == 0 {
		rep.AddFixable("targets", "no hosts discovered; run net.scan first")
	} else {
		rep.AddOK("targets", fmt.Sprintf("%d host(s) available", len(ctx.Store.Hosts())))
	}
	return rep, nil
}

// Run fingerprints open ports on discovered hosts.
func (*ServiceFingerprint) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	scanner, err := ports.NewScanner(ctx.Iface)
	if err != nil {
		return fmt.Errorf("service.fingerprint: %w", err)
	}
	defer scanner.Close()
	scanner.SetStealth(stealth.FromConfig(ctx.Conf, "service.fingerprint"))
	st := stealth.FromConfig(ctx.Conf, "service.fingerprint")

	timeout := ctx.Conf.GetDuration("service.fingerprint", "timeout", 1500*time.Millisecond)
	client := &http.Client{Timeout: timeout}
	identified := 0
	for _, h := range ctx.Store.Hosts() {
		if len(h.OpenPorts()) == 0 {
			continue
		}
		for _, p := range h.OpenPorts() {
			svc := ports.GuessService(p)
			if svc == "http" || svc == "http-proxy" || svc == "https" || svc == "https-alt" {
				if title := httpTitle(client, h.IP, p, st); title != "" {
					h.SetPort(p, svc+"/"+title)
					ctx.Emit(events.TopicLog, fmt.Sprintf("[*] %s:%d -> %s", h.IP, p, title), nil)
					identified++
					continue
				}
			}
			banners := scanner.GrabBanners(h.IP, []uint16{p}, timeout)
			if len(banners) > 0 && banners[0].Banner != "" {
				h.SetPort(p, svc+" ("+banners[0].Banner+")")
				ctx.Emit(events.TopicLog, fmt.Sprintf("[*] %s:%d -> %s", h.IP, p, banners[0].Banner), nil)
				identified++
			}
		}
	}
	ctx.SetState("service.fingerprint", identified)
	ctx.Printf("[*] service.fingerprint complete: %d service(s) identified.\n", identified)
	return nil
}

func httpTitle(client *http.Client, ip net.IP, port uint16, st *stealth.Config) string {
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s/", scheme, net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", st.UserAgent())
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return resp.Header.Get("Server")
}

// Verify reports identification count.
func (*ServiceFingerprint) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	n, _ := ctx.GetState("service.fingerprint")
	count, _ := n.(int)
	imp := &attacks.Impact{Summary: fmt.Sprintf("identified %d service(s)", count)}
	imp.Add("identified", strconv.Itoa(count))
	return imp, nil
}

// Cleanup is a no-op.
func (*ServiceFingerprint) Cleanup(ctx *attacks.AttackCtx) error {
	return nil
}

var (
	_ attacks.Module = (*ServiceScan)(nil)
	_ attacks.Module = (*ServiceFingerprint)(nil)
)
