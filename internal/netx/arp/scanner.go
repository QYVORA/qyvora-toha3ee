// Package arp implements ARP scanning, ARP cache manipulation and ARP table
// restore primitives used by the recon pipeline and the arp.spoof module.
package arp

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/QYVORA/qyvora-toha3ee/internal/events"
	"github.com/QYVORA/qyvora-toha3ee/internal/netx"
	"github.com/QYVORA/qyvora-toha3ee/internal/oui"
	"github.com/QYVORA/qyvora-toha3ee/internal/stealth"
	"github.com/QYVORA/qyvora-toha3ee/internal/store"
)

// Scanner performs active ARP sweeps and passively tracks ARP traffic. It is
// the primary source of the host inventory (target DB).
type Scanner struct {
	iface   *netx.Iface
	handle  *pcap.Handle
	bus     *events.Bus
	db      *store.Store
	vend    *oui.DB
	stealth *stealth.Config

	stop chan struct{} // closed by Stop to unblock the passive listener
	wg   sync.WaitGroup

	sent atomic.Uint64 // who-has probes transmitted
	recv atomic.Uint64 // Ethernet frames observed by the listener
}

// NewScanner opens a promiscuous pcap handle on iface and returns a Scanner
// ready for Start.
func NewScanner(iface *netx.Iface, bus *events.Bus, db *store.Store, vend *oui.DB) (*Scanner, error) {
	// Promiscuous mode is required so the listener sees replies addressed to
	// other hosts as well as our own.
	handle, err := pcap.OpenLive(iface.Name, 65535, true, 500*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", iface.Name, err)
	}
	// Keep only ARP traffic; the passive listener and the sweep reader share
	// this filter so unrelated frames never reach the capture loop.
	if err := handle.SetBPFFilter("arp"); err != nil {
		handle.Close()
		return nil, fmt.Errorf("set bpf arp: %w", err)
	}
	return &Scanner{
		iface:   iface,
		handle:  handle,
		bus:     bus,
		db:      db,
		vend:    vend,
		stealth: stealth.New(),
		stop:    make(chan struct{}),
	}, nil
}

// SetStealth applies a stealth profile to active sweeps.
func (s *Scanner) SetStealth(cfg *stealth.Config) {
	// A nil profile means "keep defaults"; only install an explicit one.
	if cfg != nil {
		s.stealth = cfg
	}
}

// Start begins the passive listener goroutine that ingests ARP replies.
func (s *Scanner) Start() {
	s.wg.Add(1)
	go s.listen()
}

// Stop terminates the listener and closes the pcap handle.
func (s *Scanner) Stop() {
	// Close the stop channel first so the listener's pcap read unblocks,
	// then wait for it to exit before tearing down the shared handle.
	close(s.stop)
	s.wg.Wait()
	s.handle.Close()
}

// Stats returns the sent and received packet counters.
func (s *Scanner) Stats() (sent, recv uint64) {
	return s.sent.Load(), s.recv.Load()
}

// MACsResolved returns the number of ARP replies observed.
func (s *Scanner) MACsResolved() uint64 {
	return s.recv.Load()
}

// listen passively ingests every ARP frame on the wire and folds observed
// sender IP/MAC pairs into the host database. It doubles as an online host
// detector: hosts that talk while a scan runs are discovered for free.
func (s *Scanner) listen() {
	defer s.wg.Done()
	ps := gopacket.NewPacketSource(s.handle, layers.LayerTypeEthernet)
	ps.NoCopy = true
	for {
		// Poll for shutdown between reads so Stop() is honoured promptly.
		select {
		case <-s.stop:
			return
		default:
		}
		pkt, err := ps.NextPacket()
		if err != nil {
			// A pcap timeout or transient error is not fatal: keep polling the
			// stop channel so we still react to Stop() while a link is quiet.
			select {
			case <-s.stop:
				return
			default:
				time.Sleep(20 * time.Millisecond)
				continue
			}
		}
		if eth := pkt.Layer(layers.LayerTypeEthernet); eth != nil {
			s.recv.Add(1)
			src := eth.(*layers.Ethernet).SrcMAC
			// Ignore our own frames; otherwise we would inventory ourselves.
			if src != nil && !srcEqual(src, s.iface.MAC) {
				if arpL := pkt.Layer(layers.LayerTypeARP); arpL != nil {
					a := arpL.(*layers.ARP)
					if len(a.SourceProtAddress) >= 4 {
						ip := net.IP(a.SourceProtAddress[:4])
						if h := s.db.Host(ip); h == nil {
							// First sighting of this host: resolve the vendor
							// from its OUI and announce it on the event bus.
							nh := &store.Host{IP: ip, MAC: src, Vendor: s.vend.Lookup(src)}
							s.db.UpsertHost(nh)
							if s.bus != nil {
								s.bus.Emit(events.TopicHostNew, ip.String())
							}
						} else {
							// Known host: refresh the MAC/vendor in case it
							// changed or we previously saw a spoofed address.
							s.db.UpsertHost(&store.Host{IP: ip, MAC: src, Vendor: s.vend.Lookup(src)})
						}
					}
				}
			}
		}
	}
}

// Resolve performs a single who-has probe and returns the target MAC or an
// error if no reply arrives before the timeout.
func (s *Scanner) Resolve(ip net.IP, timeout time.Duration) (net.HardwareAddr, error) {
	// Buffered so the goroutine never blocks delivering the reply.
	probe := make(chan net.HardwareAddr, 1)
	ps := gopacket.NewPacketSource(s.handle, layers.LayerTypeEthernet)
	ps.NoCopy = true

	// Use the main capture handle through a helper that watches for the reply.
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-done:
				return
			default:
			}
			pkt, err := ps.NextPacket()
			if err != nil {
				return
			}
			if arpL := pkt.Layer(layers.LayerTypeARP); arpL != nil {
				a := arpL.(*layers.ARP)
				// Accept only an is-at reply for the queried IP.
				if a.Operation == layers.ARPReply && len(a.SourceProtAddress) >= 4 && net.IP(a.SourceProtAddress[:4]).Equal(ip) {
					select {
					case probe <- a.SourceHwAddress:
					case <-done:
					}
					return
				}
			}
		}
	}()

	// Broadcast the who-has for ip and wait for the helper goroutine.
	if err := s.sendRequest(ip, broadcastMAC); err != nil {
		return nil, err
	}
	s.sent.Add(1)

	select {
	case mac := <-probe:
		return mac, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("no ARP reply from %s", ip)
	}
}

// Scan sweeps ips with who-has probes and returns the hosts that answered.
// The hosts are also written to the shared store.
func (s *Scanner) Scan(ips []net.IP, timeout time.Duration) ([]*store.Host, error) {
	return s.Sweep(ips, timeout)
}

// Sweep sends who-has probes to every ip in randomized, paced order and reads
// the replies through a single capture loop. Compared to per-host probing it
// is faster (burst-serialized sends with one reader) and quieter (order is
// shuffled and pacing jitters each probe).
func (s *Scanner) Sweep(ips []net.IP, timeout time.Duration) ([]*store.Host, error) {
	if timeout <= 0 {
		timeout = 750 * time.Millisecond
	}
	// Randomized order avoids a top-down sweep that IDSes trivially recognize.
	s.stealth.Shuffle(len(ips), func(i, j int) { ips[i], ips[j] = ips[j], ips[i] })

	// wanted maps the string form of each target IP back to the net.IP used to
	// rebuild store.Host values; the map key is also the filter for replies.
	wanted := make(map[string]net.IP, len(ips))
	for _, ip := range ips {
		wanted[ip.String()] = ip
	}
	// found records the first MAC each target advertised; replies are written
	// from the reader goroutine, so writes are serialized under foundMu.
	found := make(map[string]net.HardwareAddr, len(ips))
	var foundMu sync.Mutex

	done := make(chan struct{})
	var rw sync.WaitGroup
	rw.Add(1)
	go func() {
		defer rw.Done()
		ps := gopacket.NewPacketSource(s.handle, layers.LayerTypeEthernet)
		ps.NoCopy = true
		for {
			select {
			case <-done:
				return
			default:
			}
			pkt, err := ps.NextPacket()
			if err != nil {
				select {
				case <-done:
					return
				default:
					time.Sleep(10 * time.Millisecond)
					continue
				}
			}
			arpL := pkt.Layer(layers.LayerTypeARP)
			eth := pkt.Layer(layers.LayerTypeEthernet)
			if arpL == nil || eth == nil {
				continue
			}
			a := arpL.(*layers.ARP)
			// Only is-at replies carry usable IP->MAC claims.
			if a.Operation != layers.ARPReply || len(a.SourceProtAddress) < 4 {
				continue
			}
			ip := net.IP(a.SourceProtAddress[:4]).String()
			if _, ok := wanted[ip]; !ok {
				continue // unsolicited reply for a host we did not ask about
			}
			foundMu.Lock()
			if _, ok := found[ip]; !ok {
				// Keep the first answer per IP; later duplicates are ignored.
				found[ip] = eth.(*layers.Ethernet).SrcMAC
			}
			foundMu.Unlock()
		}
	}()

	pace := stealth.NewPacer(s.stealth)
	for _, ip := range ips {
		if err := s.sendRequest(ip, broadcastMAC); err != nil {
			close(done)
			rw.Wait()
			return nil, err
		}
		s.sent.Add(1)
		pace.Wait() // enforce burst/pause cadence between probes
	}

	// Read until every target replied or the deadline expires.
	deadline := time.After(timeout)
	poll := time.NewTicker(5 * time.Millisecond)
	defer poll.Stop()
loop:
	for {
		foundMu.Lock()
		complete := len(found) == len(ips)
		foundMu.Unlock()
		if complete {
			break
		}
		select {
		case <-deadline:
			break loop
		case <-poll.C:
		}
	}
	close(done)
	rw.Wait()

	// Fold the results into the store and hand them back to the caller.
	foundMu.Lock()
	out := make([]*store.Host, 0, len(found))
	for ipStr, mac := range found {
		h := &store.Host{IP: wanted[ipStr], MAC: mac, Vendor: s.vend.Lookup(mac)}
		s.db.UpsertHost(h)
		out = append(out, h)
	}
	foundMu.Unlock()
	return out, nil
}

// ScanCIDR sweeps every address in the given CIDR.
func (s *Scanner) ScanCIDR(cidr string, timeout time.Duration) ([]*store.Host, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("parse cidr %s: %w", cidr, err)
	}
	ips := CIDRHosts(ipnet)
	return s.Scan(ips, timeout)
}

// CIDRHosts expands a CIDR into its usable unicast IPv4 addresses (network
// and broadcast excluded).
func CIDRHosts(ipnet *net.IPNet) []net.IP {
	start := ipnet.IP.To4()
	if start == nil {
		return nil // not an IPv4 network
	}
	// Normalize to the network address (mask applied).
	start = start.Mask(ipnet.Mask)
	// The broadcast address is network | ~mask, computed per octet.
	broadcast := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		broadcast[i] = start[i] | ^ipnet.Mask[i]
	}

	var out []net.IP
	cur := append(net.IP(nil), start...) // copy so nextIP can mutate it
	first := true
	for {
		if first {
			first = false
		} else if equalIP(cur, broadcast) {
			break // reached the end of the range
		}
		// Skip the network and broadcast addresses of the whole subnet.
		if !equalIP(cur, start) && !equalIP(cur, broadcast) {
			out = append(out, append(net.IP(nil), cur...))
		}
		cur = nextIP(cur)
	}
	return out
}

// equalIP is a byte-wise equality check for net.IP values of equal length.
func equalIP(a, b net.IP) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// nextIP increments an IPv4 address in place, propagating carries from the
// least significant octet upward like integer addition.
func nextIP(ip net.IP) net.IP {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break // no carry into the next octet
		}
	}
	return ip
}

// sendRequest crafts and transmits a who-has probe.
func (s *Scanner) sendRequest(targetIP net.IP, targetMAC net.HardwareAddr) error {
	raw, err := BuildRequest(s.iface.MAC, s.iface.IP, targetMAC, targetIP)
	if err != nil {
		return err
	}
	return s.handle.WritePacketData(raw)
}

// broadcastMAC is the Ethernet broadcast address (ff:ff:ff:ff:ff:ff) used for
// who-has probes when the target's MAC is unknown.
var broadcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// srcEqual compares two MACs without importing bytes.
func srcEqual(a, b net.HardwareAddr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// DecodeIP converts a 4-byte ARP address into a net.IP.
func DecodeIP(b []byte) net.IP {
	if len(b) < 4 {
		return nil
	}
	// Slice only the first 4 bytes; a longer buffer is an over-read hazard.
	return net.IP(b[:4])
}
