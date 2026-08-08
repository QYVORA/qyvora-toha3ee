package osint

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/qyvora/toha3ee/internal/attacks"
)

// Shodan looks up a host's pre-indexed banners, open ports and known
// vulnerabilities through the Shodan API. It makes no contact with the target
// itself.
type Shodan struct{}

// Meta implements attacks.Module.
func (*Shodan) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "osint.shodan",
		Category:    "osint",
		Risk:        attacks.RiskInfo,
		Targets:     []string{"ip"},
		Description: "pre-indexed Shodan host lookup: open ports, banners and exposed CVEs without touching the target",
		Limitations: "requires a Shodan API key (osint.shodan.key) and only shows data Shodan has already scanned",
	}
}

type shodanHost struct {
	IP       string   `json:"ip_str"`
	Hostnames []string `json:"hostnames"`
	OS       string   `json:"os"`
	Ports    []int    `json:"ports"`
	Vulns    []string `json:"vulns"`
	Services []struct {
		Port    int    `json:"port"`
		Product string `json:"product"`
		Version string `json:"version"`
		Data    string `json:"data"`
	} `json:"data"`
}

type shodanResult struct {
	IP     string
	OS     string
	Ports  []int
	Vulns  []string
}

// Preflight needs an API key and a target.
func (*Shodan) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if ctx.Conf.Get("osint.shodan", "key") == "" {
		rep.AddBlocked("key", "set osint.shodan.key to your Shodan API key")
	} else {
		rep.AddOK("key", "Shodan API key set")
	}
	t, err := target(ctx, "osint.shodan", "target")
	if err != nil {
		rep.AddFixable("target", err.Error())
		return rep, nil
	}
	rep.AddOK("target", t)
	return rep, nil
}

// Run queries the Shodan host API for each configured target.
func (*Shodan) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	key := ctx.Conf.Get("osint.shodan", "key")
	if key == "" {
		return fmt.Errorf("osint.shodan: set osint.shodan.key first")
	}
	t := ctx.Conf.Get("osint.shodan", "target")
	if o, ok := opts["target"]; ok && o != "" {
		t = o
	}
	timeout := ctx.Conf.GetDuration("osint.shodan", "timeout", 20*time.Second)

	raw, err := httpGet(fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=%s", t, key), timeout)
	if err != nil {
		return fmt.Errorf("osint.shodan: %w", err)
	}
	var h shodanHost
	if err := json.Unmarshal(raw, &h); err != nil {
		return fmt.Errorf("osint.shodan: %w", err)
	}
	res := shodanResult{IP: h.IP, OS: h.OS, Ports: h.Ports, Vulns: h.Vulns}
	for _, s := range h.Services {
		if s.Product != "" {
			emit(ctx, "finding", fmt.Sprintf("osint.shodan: %s:%d %s %s", h.IP, s.Port, s.Product, s.Version))
		}
	}
	for _, v := range h.Vulns {
		emit(ctx, "finding", fmt.Sprintf("osint.shodan: %s CVE %s", h.IP, v))
	}
	ctx.SetState("osint.shodan", res)
	ctx.Printf("[*] osint.shodan: %s has %d indexed port(s), %d CVE(s).\n", h.IP, len(h.Ports), len(h.Vulns))
	return nil
}

// Verify reports the host summary.
func (*Shodan) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("osint.shodan")
	if !ok {
		return nil, fmt.Errorf("osint.shodan not run")
	}
	h, _ := v.(shodanResult)
	imp := &attacks.Impact{Summary: fmt.Sprintf("Shodan: %d ports, %d CVEs on %s", len(h.Ports), len(h.Vulns), h.IP)}
	for _, p := range h.Ports {
		imp.Add("port", fmt.Sprint(p))
	}
	for _, c := range h.Vulns {
		imp.Add("cve", c)
	}
	return imp, nil
}

// Cleanup is a no-op.
func (*Shodan) Cleanup(ctx *attacks.AttackCtx) error { return nil }

var _ attacks.Module = (*Shodan)(nil)
