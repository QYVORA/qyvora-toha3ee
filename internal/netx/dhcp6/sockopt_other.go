//go:build !linux

package dhcp6

import (
	"fmt"
	"net"

	"golang.org/x/net/ipv6"
)

// joinGroup subscribes the UDP socket to a multicast group on iface. Linux
// uses a raw setsockopt (sockopt_linux.go); every other platform (darwin,
// windows, BSDs) uses the portable x/net/ipv6 helpers.
func joinGroup(conn *net.UDPConn, iface *net.Interface, group net.IP) error {
	pc := ipv6.NewPacketConn(conn)
	if err := pc.SetMulticastInterface(iface); err != nil {
		return fmt.Errorf("set multicast interface: %w", err)
	}
	if err := pc.JoinGroup(iface, &net.UDPAddr{IP: group}); err != nil {
		return fmt.Errorf("join group: %w", err)
	}
	return nil
}
