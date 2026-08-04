// Package netx provides low-level network primitives: interface discovery,
// gateway detection and helpers shared by every L2/L3 attack.
package netx

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// Iface describes a local network interface with its primary addresses.
type Iface struct {
	Name  string
	Index int
	IP    net.IP
	Net   *net.IPNet
	IPv6  net.IP
	MAC   net.HardwareAddr
	MTU   int
}

// String returns a compact human-readable description.
func (i *Iface) String() string {
	return fmt.Sprintf("%s (%s, %s)", i.Name, i.IP, i.MAC)
}

// CIDR returns the interface's network in CIDR notation, e.g. "192.168.8.0/24".
func (i *Iface) CIDR() string {
	if i.Net == nil {
		return ""
	}
	return i.Net.String()
}

// NetworkMask returns the interface's network mask.
func (i *Iface) NetworkMask() net.IPMask {
	if i.Net == nil {
		return nil
	}
	return i.Net.Mask
}

// Interfaces enumerates every local interface, attaching the first IPv4 and
// IPv6 address to each.
func Interfaces() ([]*Iface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	var out []*Iface
	for _, ni := range ifs {
		addrs, err := ni.Addrs()
		if err != nil {
			continue
		}
		inf := &Iface{Name: ni.Name, Index: ni.Index, MAC: ni.HardwareAddr, MTU: ni.MTU}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipn.IP
			if ip.To4() != nil {
				if inf.IP == nil {
					inf.IP = ip.To4()
					inf.Net = &net.IPNet{IP: ip.To4(), Mask: ipn.Mask}
				}
			} else if inf.IPv6 == nil {
				inf.IPv6 = ip
			}
		}
		out = append(out, inf)
	}
	return out, nil
}

// SelectIface looks up an interface by name.
func SelectIface(name string) (*Iface, error) {
	ifs, err := Interfaces()
	if err != nil {
		return nil, err
	}
	for _, i := range ifs {
		if i.Name == name {
			if i.IP == nil {
				return nil, fmt.Errorf("interface %s has no IPv4 address", name)
			}
			return i, nil
		}
	}
	return nil, fmt.Errorf("interface %s not found", name)
}

// AutoSelectIface picks the first up, non-loopback interface with an IPv4
// address. It is used when no --iface flag is supplied.
func AutoSelectIface() (*Iface, error) {
	ifs, err := Interfaces()
	if err != nil {
		return nil, err
	}
	for _, i := range ifs {
		if i.IP == nil || i.MAC == nil {
			continue
		}
		if i.Name == "lo" || strings.HasPrefix(i.Name, "docker") || strings.HasPrefix(i.Name, "br-") || strings.HasPrefix(i.Name, "veth") {
			continue
		}
		return i, nil
	}
	// Fall back to any non-loopback interface with an IP.
	for _, i := range ifs {
		if i.IP != nil && i.Name != "lo" {
			return i, nil
		}
	}
	return nil, errors.New("no usable network interface found")
}

// Gateway returns the default gateway IPv4 for the interface by parsing
// /proc/net/route.
func (i *Iface) Gateway() (net.IP, error) {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return nil, fmt.Errorf("read /proc/net/route: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n")[1:] {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] != i.Name {
			continue
		}
		if fields[1] != "00000000" { // not the default route
			continue
		}
		gw, err := hexToIP(fields[2])
		if err != nil {
			continue
		}
		if gw.Equal(net.IPv4zero) {
			continue
		}
		return gw, nil
	}
	return nil, fmt.Errorf("no default gateway for interface %s", i.Name)
}

// hexToIP converts the little-endian hex IP format used in /proc/net/route
// (e.g. "0101A8C0") into a net.IP.
func hexToIP(s string) (net.IP, error) {
	if len(s) != 8 {
		return nil, errors.New("bad hex ip length")
	}
	raw, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return nil, err
	}
	return net.IPv4(byte(raw), byte(raw>>8), byte(raw>>16), byte(raw>>24)), nil
}

// IPToHex converts a net.IP to the little-endian hex format of
// /proc/net/route.
func IPToHex(ip net.IP) string {
	ip = ip.To4()
	if ip == nil {
		return "00000000"
	}
	return fmt.Sprintf("%02X%02X%02X%02X", ip[3], ip[2], ip[1], ip[0])
}
