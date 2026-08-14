package recon

import (
	"fmt"
	"net"
	"strings"

	"github.com/QYVORA/qyvora-toha3ee/internal/attacks"
	"github.com/QYVORA/qyvora-toha3ee/internal/safety"
)

// setHostPort records an open port on the matching store host.
func setHostPort(ctx *attacks.AttackCtx, ip net.IP, port uint16, banner string) {
	for _, h := range ctx.Store.Hosts() {
		if h.IP != nil && h.IP.Equal(ip) {
			h.SetPort(port, banner)
			return
		}
	}
}

// requireRootRep adds a root check to a preflight report. It returns non-nil
// when root is missing.
func requireRootRep(rep *attacks.PreflightReport) error {
	if err := safety.RequireRoot(); err != nil {
		rep.AddBlocked("root", err.Error())
		return err
	}
	rep.AddOK("root", "raw packet injection available")
	return nil
}

// parseIPsAndCIDRs parses a comma/space-separated list of IPs and CIDRs into
// a flat host list.
func parseIPsAndCIDRs(s string) ([]net.IP, error) {
	var out []net.IP
	for _, tok := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if ip := net.ParseIP(tok); ip != nil {
			out = append(out, ip)
			continue
		}
		if _, ipnet, err := net.ParseCIDR(tok); err == nil {
			hosts, err := hostsInNet(ipnet)
			if err != nil {
				return nil, err
			}
			out = append(out, hosts...)
			continue
		}
		return nil, fmt.Errorf("invalid target %q (want an IP or CIDR)", tok)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no valid targets in %q", s)
	}
	return out, nil
}

// parseSingleIP parses one IP literal.
func parseSingleIP(s string) net.IP {
	s = strings.TrimSpace(s)
	if ip := net.ParseIP(s); ip != nil {
		return ip
	}
	return nil
}

// hostsInNet expands an IPv4 network into its usable host addresses.
func hostsInNet(ipnet *net.IPNet) ([]net.IP, error) {
	if ipnet.IP.To4() == nil {
		return nil, fmt.Errorf("IPv6 ranges are not supported here")
	}
	var out []net.IP
	ip := ipnet.IP.To4()
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		cp := make(net.IP, 4)
		copy(cp, ip)
		out = append(out, cp)
	}
	// Drop network and broadcast addresses on real subnets.
	if ones, bits := ipnet.Mask.Size(); ones < bits-1 {
		out = out[1 : len(out)-1]
	}
	return out, nil
}

// incIP increments an IPv4 address in place, carrying the overflow upward so
// the caller can walk a whole subnet range.
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}
