// Package store is the shared, concurrency-safe data layer of the framework.
//
// It holds the live host inventory (target DB), the source-tracked credential
// database, captured sessions and the event log. Every module reads and writes
// state exclusively through this package so that reporting and the REPL always
// see a single consistent view.
package store

import (
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Host describes a single host observed on the network.
type Host struct {
	IP        net.IP
	MAC       net.HardwareAddr
	Vendor    string
	Name      string
	OSGuess   string
	TLS       bool
	FirstSeen time.Time
	LastSeen  time.Time
	// Ports maps a TCP port to its grabbed banner.
	Ports map[uint16]string
	// Sent and Recv are packet counters maintained by ARP probing. They are
	// atomic so sniffers and the REPL can update/read them from any goroutine.
	Sent atomic.Uint64
	Recv atomic.Uint64

	// mu guards Ports; all other fields are written once at creation or by
	// the single store writer, so they need no locking.
	mu sync.Mutex // guards Ports
}

// Copy returns a shallow copy safe to hand to callers outside the store.
// Atomic counters are copied by value.
func (h *Host) Copy() *Host {
	h.mu.Lock()
	defer h.mu.Unlock()
	c := &Host{
		IP:        h.IP,
		MAC:       h.MAC,
		Vendor:    h.Vendor,
		Name:      h.Name,
		OSGuess:   h.OSGuess,
		TLS:       h.TLS,
		FirstSeen: h.FirstSeen,
		LastSeen:  h.LastSeen,
		Ports:     make(map[uint16]string, len(h.Ports)),
	}
	// Deep-copy the ports map so external callers mutating the snapshot
	// cannot corrupt the store's live map.
	for k, v := range h.Ports {
		c.Ports[k] = v
	}
	// atomic.Uint64 must be copied via Load/Store, never by struct
	// assignment, so the new instance has independent counter storage.
	c.Sent.Store(h.Sent.Load())
	c.Recv.Store(h.Recv.Load())
	return c
}

// SetPort records a banner for a TCP port.
func (h *Host) SetPort(port uint16, banner string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.Ports == nil {
		// A freshly discovered host may never have had ports set.
		h.Ports = make(map[uint16]string)
	}
	h.Ports[port] = banner
}

// PortBanner returns the banner for a TCP port.
func (h *Host) PortBanner(port uint16) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.Ports[port]
}

// OpenPorts returns the sorted list of open TCP ports.
func (h *Host) OpenPorts() []uint16 {
	h.mu.Lock()
	defer h.mu.Unlock()
	ports := make([]uint16, 0, len(h.Ports))
	for p := range h.Ports {
		ports = append(ports, p)
	}
	// Sorting gives a deterministic, human-friendly listing for the REPL.
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	return ports
}

// Cred is a single captured credential.
type Cred struct {
	ID       int
	Service  string // "http.post", "http.basic", "ntlmv2", "phish", "formswap", ...
	Username string
	Password string
	Extra    string // OTP, token, hash, session, ...
	Host     string // hostname/domain the cred belongs to
	VictimIP string
	VictimUA string
	Source   string // how & where it was captured
	Time     time.Time
}

// Session is a captured HTTP session (cookies + auth headers).
type Session struct {
	ID         int
	VictimIP   string
	Host       string
	Cookies    map[string]string
	AuthHeader string
	Captured   time.Time
}

// EventRecord is a logged event for the REPL feed and report generation.
type EventRecord struct {
	Time  time.Time
	Topic string
	Msg   string
}

// ModuleRun records the outcome of one bounded module execution. It is the
// framework's structured exploitation result: every successful, failed and
// stopped module run is persisted here so reports and the event feed carry a
// consistent view of "what ran and what it proved".
type ModuleRun struct {
	ID          int               `json:"id"`                     // stable run counter
	Module      string            `json:"module"`                 // module id, e.g. "spray.ntlmv2"
	Started     time.Time         `json:"started"`                // when Run began
	Finished    time.Time         `json:"finished"`               // when the run completed
	Status      string            `json:"status"`                 // "success" | "failed" | "stopped"
	Error       string            `json:"error,omitempty"`        // failure message when Status=failed
	Summary     string            `json:"summary,omitempty"`      // verified impact verdict
	Metrics     map[string]string `json:"metrics,omitempty"`      // quantified proof (creds, hashes, ...)
	EvidenceRef string            `json:"evidence_ref,omitempty"` // pointer into creds/sessions/hosts data
}

// Recon accumulates environment evidence gathered passively during recon.
// Flags are set by sniffers and low-level listeners and read by the vector
// engine when building the network profile.
type Recon struct {
	SeesPlainHTTP atomic.Bool // plaintext HTTP on :80 observed
	SeesDoH       atomic.Bool // TLS on :853 (DNS-over-HTTPS) observed
	SeesLLMNR     atomic.Bool // LLMNR queries (:5355) observed
	SeesMDNS      atomic.Bool // mDNS queries (:5353) observed
	SeesNBNS      atomic.Bool // NetBIOS name service (:137) observed
	SeesEAPOL     atomic.Bool // 802.1X EAPOL frames observed
	SeesDHCPv6    atomic.Bool // DHCPv6 solicit observed
	SeesDNSSEC    atomic.Bool // DNSSEC/secure resolution signals observed
	SeesSMB       atomic.Bool // SMB (:445) traffic observed
}

// Store is the process-wide state container.
type Store struct {
	// mu guards the creds/sessions/events/runs slices and their id counters.
	mu         sync.RWMutex
	hosts      sync.Map // key: string(ip) -> *Host
	creds      []Cred
	sessions   []Session
	events     []EventRecord
	runs       []ModuleRun
	nextCredID int
	nextSessID int
	nextRunID  int
	// capEvents bounds the in-memory event log.
	capEvents int

	// Recon holds the accumulated environment evidence.
	Recon Recon
}

// New returns an empty Store. capEvents bounds the in-memory event log.
func New(capEvents int) *Store {
	if capEvents <= 0 {
		// Default log size keeps the REPL feed responsive without unbounded
		// memory growth during long engagements.
		capEvents = 5000
	}
	return &Store{capEvents: capEvents}
}

// UpsertHost records or refreshes a host, emitting nothing itself.
func (s *Store) UpsertHost(h *Host) *Host {
	key := string(h.IP)
	now := time.Now()
	if old, ok := s.hosts.Load(key); ok {
		oh := old.(*Host)
		// Known host: refresh liveness and merge any newly-learned fields,
		// never clobbering existing data with empty updates.
		oh.LastSeen = now
		if h.Vendor != "" {
			oh.Vendor = h.Vendor
		}
		if h.Name != "" {
			oh.Name = h.Name
		}
		if h.OSGuess != "" {
			oh.OSGuess = h.OSGuess
		}
		if h.TLS {
			oh.TLS = true
		}
		// Ports merge under the host's own lock because a scanner goroutine
		// may be updating them concurrently.
		if len(h.Ports) > 0 {
			oh.mu.Lock()
			for p, b := range h.Ports {
				if oh.Ports == nil {
					oh.Ports = make(map[uint16]string)
				}
				oh.Ports[p] = b
			}
			oh.mu.Unlock()
		}
		return oh
	}
	// New host: stamp first/last seen so the inventory has a timeline.
	h.FirstSeen = now
	h.LastSeen = now
	s.hosts.Store(key, h)
	return h
}

// UpsertMAC refreshes the MAC of a host if it was previously unknown.
func (s *Store) UpsertMAC(ip net.IP, mac net.HardwareAddr) *Host {
	h := &Host{IP: ip, MAC: mac}
	return s.UpsertHost(h)
}

// Host returns the stored host for ip, or nil.
func (s *Store) Host(ip net.IP) *Host {
	if v, ok := s.hosts.Load(string(ip)); ok {
		return v.(*Host)
	}
	return nil
}

// Hosts returns a snapshot of all known hosts.
func (s *Store) Hosts() []*Host {
	var out []*Host
	// sync.Map.Range visits every entry; order is unspecified, so callers
	// that need ordering must sort the returned slice.
	s.hosts.Range(func(_, v any) bool {
		out = append(out, v.(*Host))
		return true
	})
	return out
}

// AddCred appends a credential to the source-tracked database.
func (s *Store) AddCred(c Cred) Cred {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextCredID++
	c.ID = s.nextCredID
	s.creds = append(s.creds, c)
	return c
}

// Creds returns a snapshot of all captured credentials.
func (s *Store) Creds() []Cred {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Copy so callers cannot mutate the store's backing slice.
	return append([]Cred(nil), s.creds...)
}

// CredsBySource returns credentials whose Source starts with source (prefix
// match, e.g. "phish" matches "phish:facebook").
func (s *Store) CredsBySource(source string) []Cred {
	out := []Cred{}
	for _, c := range s.Creds() {
		if strings.HasPrefix(c.Source, source) {
			out = append(out, c)
		}
	}
	return out
}

// AddSession records a captured HTTP session.
func (s *Store) AddSession(sess Session) Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextSessID++
	sess.ID = s.nextSessID
	s.sessions = append(s.sessions, sess)
	return sess
}

// Sessions returns a snapshot of all captured sessions.
func (s *Store) Sessions() []Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Session(nil), s.sessions...)
}

// LogEvent appends a human-readable event to the store's log.
func (s *Store) LogEvent(topic, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, EventRecord{Time: time.Now(), Topic: topic, Msg: msg})
	if len(s.events) > s.capEvents {
		// Trim the oldest events by slicing from the end, keeping the most
		// recent capEvents entries.
		s.events = s.events[len(s.events)-s.capEvents:]
	}
}

// Events returns a snapshot of the event log, oldest first.
func (s *Store) Events() []EventRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]EventRecord(nil), s.events...)
}

// ClearEvents empties the in-memory event log.
func (s *Store) ClearEvents() {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Reuse the backing array instead of allocating a fresh slice.
	s.events = s.events[:0]
}

// AddRun appends a structured module run record and returns it with its
// stable run id assigned.
func (s *Store) AddRun(r ModuleRun) ModuleRun {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextRunID++
	r.ID = s.nextRunID
	s.runs = append(s.runs, r)
	return r
}

// Runs returns a snapshot of all recorded module runs, oldest first.
func (s *Store) Runs() []ModuleRun {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]ModuleRun(nil), s.runs...)
}

// RunCount returns how many module runs have been recorded.
func (s *Store) RunCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.runs)
}
