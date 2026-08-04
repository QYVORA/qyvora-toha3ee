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

	"github.com/qyvora/toha3ee/internal/events"
	"github.com/qyvora/toha3ee/internal/netx"
	"github.com/qyvora/toha3ee/internal/oui"
	"github.com/qyvora/toha3ee/internal/store"
)

// Scanner performs active ARP sweeps and passively tracks ARP traffic. It is
// the primary source of the host inventory (target DB).
type Scanner struct {
	iface  *netx.Iface
	handle *pcap.Handle
	bus    *events.Bus
	db     *store.Store
	vend   *oui.DB

	stop chan struct{}
	wg   sync.WaitGroup

	sent atomic.Uint64
	recv atomic.Uint64
}

// NewScanner opens a promiscuous pcap handle on iface and returns a Scanner
// ready for Start.
func NewScanner(iface *netx.Iface, bus *events.Bus, db *store.Store, vend *oui.DB) (*Scanner, error) {
	handle, err := pcap.OpenLive(iface.Name, 65535, true, 500*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", iface.Name, err)
	}
	if err := handle.SetBPFFilter("arp"); err != nil {
		handle.Close()
		return nil, fmt.Errorf("set bpf arp: %w", err)
	}
	return &Scanner{
		iface:  iface,
		handle: handle,
		bus:    bus,
		db:     db,
		vend:   vend,
		stop:   make(chan struct{}),
	}, nil
}

// Start begins the passive listener goroutine that ingests ARP replies.
func (s *Scanner) Start() {
	s.wg.Add(1)
	go s.listen()
}

// Stop terminates the listener and closes the pcap handle.
func (s *Scanner) Stop() {
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

func (s *Scanner) listen() {
	defer s.wg.Done()
	ps := gopacket.NewPacketSource(s.handle, layers.LayerTypeEthernet)
	ps.NoCopy = true
	for {
		select {
		case <-s.stop:
			return
		default:
		}
		pkt, err := ps.NextPacket()
		if err != nil {
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
			if src != nil && !srcEqual(src, s.iface.MAC) {
				if arpL := pkt.Layer(layers.LayerTypeARP); arpL != nil {
					a := arpL.(*layers.ARP)
					if len(a.SourceProtAddress) >= 4 {
						ip := net.IP(a.SourceProtAddress[:4])
						if h := s.db.Host(ip); h == nil {
							nh := &store.Host{IP: ip, MAC: src, Vendor: s.vend.Lookup(src)}
							s.db.UpsertHost(nh)
							if s.bus != nil {
								s.bus.Emit(events.TopicHostNew, ip.String())
							}
						} else {
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
	var found []*store.Host
	results := make(chan *store.Host, len(ips))

	var wg sync.WaitGroup
	sem := make(chan struct{}, 64) // bound in-flight probes
	for _, ip := range ips {
		ip := ip
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			mac, err := s.Resolve(ip, timeout)
			if err != nil {
				return
			}
			h := &store.Host{IP: ip, MAC: mac, Vendor: s.vend.Lookup(mac)}
			s.db.UpsertHost(h)
			results <- h
		}()
	}
	wg.Wait()
	close(results)
	for h := range results {
		found = append(found, h)
	}
	return found, nil
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
		return nil
	}
	start = start.Mask(ipnet.Mask)
	broadcast := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		broadcast[i] = start[i] | ^ipnet.Mask[i]
	}

	var out []net.IP
	cur := append(net.IP(nil), start...)
	first := true
	for {
		if first {
			first = false
		} else if equalIP(cur, broadcast) {
			break
		}
		// Skip the network and broadcast addresses of the whole subnet.
		if !equalIP(cur, start) && !equalIP(cur, broadcast) {
			out = append(out, append(net.IP(nil), cur...))
		}
		cur = nextIP(cur)
	}
	return out
}

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

func nextIP(ip net.IP) net.IP {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
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
	return net.IP(b[:4])
}
