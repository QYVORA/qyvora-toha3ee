package attacks

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/qyvora/toha3ee/internal/netx/arp"
	"github.com/qyvora/toha3ee/internal/oui"
	"github.com/qyvora/toha3ee/internal/store"
)

// GatewayIP returns the default gateway of the session interface.
func GatewayIP(ctx *AttackCtx) (net.IP, error) {
	if ctx.Iface == nil {
		return nil, fmt.Errorf("no interface configured")
	}
	return ctx.Iface.Gateway()
}

// ResolveMAC returns the hardware address for ip, consulting the host
// inventory first and falling back to an ARP probe.
func ResolveMAC(ctx *AttackCtx, ip net.IP, timeout time.Duration) (net.HardwareAddr, error) {
	if h := ctx.Store.Host(ip); h != nil && h.MAC != nil {
		return h.MAC, nil
	}
	sc, err := arp.NewScanner(ctx.Iface, ctx.Bus, ctx.Store, oui.New())
	if err != nil {
		return nil, err
	}
	defer sc.Stop()
	return sc.Resolve(ip, timeout)
}

// ExpandTargets converts a comma/space separated list of IPs and CIDRs into
// concrete IPv4 addresses, skipping the attacker itself and the gateway when
// skipGateway is set.
func ExpandTargets(ctx *AttackCtx, raw string, skipGateway bool) ([]net.IP, error) {
	var ips []net.IP
	for _, tok := range splitList(raw) {
		if strings.Contains(tok, "/") {
			_, ipnet, err := net.ParseCIDR(tok)
			if err != nil {
				return nil, fmt.Errorf("bad cidr %q: %w", tok, err)
			}
			ips = append(ips, arp.CIDRHosts(ipnet)...)
			continue
		}
		ip := net.ParseIP(tok)
		if ip == nil {
			return nil, fmt.Errorf("bad ip %q", tok)
		}
		ips = append(ips, ip)
	}
	return filterLocal(ctx, ips, skipGateway), nil
}

func splitList(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == ';' })
	out := fields[:0]
	for _, f := range fields {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

func filterLocal(ctx *AttackCtx, ips []net.IP, skipGateway bool) []net.IP {
	var out []net.IP
	seen := map[string]bool{}
	var gw net.IP
	if skipGateway {
		gw, _ = GatewayIP(ctx)
	}
	for _, ip := range ips {
		if ctx.Iface != nil && ip.Equal(ctx.Iface.IP) {
			continue
		}
		if gw != nil && ip.Equal(gw) {
			continue
		}
		if seen[ip.String()] {
			continue
		}
		seen[ip.String()] = true
		out = append(out, ip)
	}
	return out
}

// TargetsFromConfig resolves the configured target list into hosts.
func TargetsFromConfig(ctx *AttackCtx, module, param string, skipGateway bool) ([]*store.Host, error) {
	raw := ctx.Conf.Get(module, param)
	if raw == "" {
		for _, t := range ctx.Conf.Targets {
			raw += t + " "
		}
	}
	ips, err := ExpandTargets(ctx, raw, skipGateway)
	if err != nil {
		return nil, err
	}
	var hosts []*store.Host
	for _, ip := range ips {
		h := ctx.Store.Host(ip)
		if h == nil {
			h = &store.Host{IP: ip}
		}
		hosts = append(hosts, h)
	}
	return hosts, nil
}

// Printf is a convenience alias so modules can log to the session console.
func Printf(ctx *AttackCtx, format string, args ...any) {
	ctx.Printf(format, args...)
}
