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

// GatewayIP returns the default gateway of the session interface. The gateway
// is usually the router the target subnet is reached through; many attacks
// (ARP spoofing, MITM) need to exclude it from the target list so the link is
// not broken.
func GatewayIP(ctx *AttackCtx) (net.IP, error) {
	if ctx.Iface == nil {
		return nil, fmt.Errorf("no interface configured")
	}
	return ctx.Iface.Gateway()
}

// ResolveMAC returns the hardware address for ip, consulting the host
// inventory first and falling back to an ARP probe.
func ResolveMAC(ctx *AttackCtx, ip net.IP, timeout time.Duration) (net.HardwareAddr, error) {
	// Fast path: if the target is already in the store we know its MAC and can
	// skip putting an ARP request on the wire (less noise, faster).
	if h := ctx.Store.Host(ip); h != nil && h.MAC != nil {
		return h.MAC, nil
	}
	// Slow path: build a scanner bound to the session interface; it emits an
	// ARP who-has request and waits for the answer.
	sc, err := arp.NewScanner(ctx.Iface, ctx.Bus, ctx.Store, oui.New())
	if err != nil {
		return nil, err
	}
	// The scanner owns the pcap handle; stop it as soon as we have the answer
	// so the interface is not held in promiscuous mode any longer than needed.
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
			// CIDR notation: expand to every address in the block. A raw CIDR
			// can span millions of hosts, so it is the caller's job to keep
			// the scope sane.
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
	// Drop ourselves and (optionally) the gateway so an attack never poisons
	// or disconnects the very link it runs on.
	return filterLocal(ctx, ips, skipGateway), nil
}

// splitList tokenizes a target string on commas, spaces and semicolons,
// discarding empty tokens so a trailing separator does not produce a bogus
// "empty IP" entry.
func splitList(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == ';' })
	// Reuse the backing array: out can never exceed fields in length.
	out := fields[:0]
	for _, f := range fields {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// filterLocal removes the attacker's own IP, the gateway (when requested) and
// duplicate addresses from the candidate list. Deduping is important because a
// single IP listed both bare and inside a CIDR must only be attacked once.
func filterLocal(ctx *AttackCtx, ips []net.IP, skipGateway bool) []net.IP {
	var out []net.IP
	seen := map[string]bool{}
	var gw net.IP
	if skipGateway {
		// Ignore the error: on failure gw stays nil and no filtering happens.
		gw, _ = GatewayIP(ctx)
	}
	for _, ip := range ips {
		// Never attack our own address — spoofing ourselves would break the
		// session's own connectivity.
		if ctx.Iface != nil && ip.Equal(ctx.Iface.IP) {
			continue
		}
		// Skip the gateway so MITM/spoof modules cannot take out the router.
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

// TargetsFromConfig resolves the configured target list into hosts. If the
// module's own target knob is empty, the session-wide target list is used.
func TargetsFromConfig(ctx *AttackCtx, module, param string, skipGateway bool) ([]*store.Host, error) {
	raw := ctx.Conf.Get(module, param)
	if raw == "" {
		// Fall back to the global targets: build the same comma/space list
		// ExpandTargets expects by joining every session target.
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
		// Reuse the store entry when known (it carries MAC, vendor, ports,
		// OS guess) and fabricate a bare host otherwise.
		h := ctx.Store.Host(ip)
		if h == nil {
			h = &store.Host{IP: ip}
		}
		hosts = append(hosts, h)
	}
	return hosts, nil
}

// Printf is a convenience alias so modules can log to the session console.
// Keeping it in the attacks package avoids every module importing context.go
// helpers just to print a status line.
func Printf(ctx *AttackCtx, format string, args ...any) {
	ctx.Printf(format, args...)
}
