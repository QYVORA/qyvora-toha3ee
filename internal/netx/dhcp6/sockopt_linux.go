//go:build linux

package dhcp6

import (
	"fmt"
	"net"
	"syscall"
)

// joinGroup subscribes the UDP socket to a multicast group on iface using a
// raw setsockopt so no external dependency is required.
func joinGroup(conn *net.UDPConn, iface *net.Interface, group net.IP) error {
	// SyscallConn exposes the raw file descriptor so we can issue the
	// IPV6_JOIN_GROUP socket option directly.
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	err = raw.Control(func(fd uintptr) {
		// IPv6 multicast group membership request (struct ipv6_mreq):
		// the group address plus the interface index to join on.
		var mreq syscall.IPv6Mreq
		copy(mreq.Multiaddr[:], group.To16())
		mreq.Interface = uint32(iface.Index)
		serr = syscall.SetsockoptIPv6Mreq(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_JOIN_GROUP, &mreq)
	})
	if err != nil {
		return fmt.Errorf("control: %w", err)
	}
	return serr
}
