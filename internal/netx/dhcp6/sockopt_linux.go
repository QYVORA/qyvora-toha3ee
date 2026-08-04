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
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	err = raw.Control(func(fd uintptr) {
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
