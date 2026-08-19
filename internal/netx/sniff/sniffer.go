// Package sniff implements passive traffic capture: raw packets are written
// to a pcap file while TCP streams are reassembled and dissected for HTTP
// credentials, sessions and recon evidence.
package sniff

import (
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/tcpassembly"

	"github.com/QYVORA/qyvora-toha3ee/internal/events"
	"github.com/QYVORA/qyvora-toha3ee/internal/netx"
	"github.com/QYVORA/qyvora-toha3ee/internal/store"
)

// Sniffer captures and dissects live traffic.
type Sniffer struct {
	iface *netx.Iface
	bus   *events.Bus
	db    *store.Store
	log   *slog.Logger

	handle *pcap.Handle
	writer *pcapgo.Writer
	file   *os.File

	assembly *tcpassembly.Assembler
	stop     chan struct{} // closed by Stop to end the capture loop
	wg       sync.WaitGroup

	packets atomic.Uint64 // packets seen
	bytes   atomic.Uint64 // bytes captured
}

// New opens a promiscuous capture handle on iface.
func New(iface *netx.Iface, bus *events.Bus, db *store.Store, log *slog.Logger) (*Sniffer, error) {
	// Snapshot length 65535 captures whole frames; promiscuous mode sees
	// traffic not destined to this host; 100ms read timeout bounds blocking.
	handle, err := pcap.OpenLive(iface.Name, 65535, true, 100*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", iface.Name, err)
	}
	s := &Sniffer{
		iface:  iface,
		bus:    bus,
		db:     db,
		log:    log,
		handle: handle,
		stop:   make(chan struct{}),
	}
	// The assembler feeds stream factory methods (s.New) that create one
	// httpStream per TCP connection direction.
	s.assembly = tcpassembly.NewAssembler(tcpassembly.NewStreamPool(s))
	return s, nil
}

// Start begins capture. If outFile is non-empty, raw packets are written to
// that pcap file.
func (s *Sniffer) Start(outFile string) error {
	if outFile != "" {
		f, err := os.Create(outFile)
		if err != nil {
			return fmt.Errorf("create pcap: %w", err)
		}
		s.file = f
		s.writer = pcapgo.NewWriter(f)
		// A pcap file starts with a 24-byte global header declaring the max
		// snapshot length and the link-layer type (ethernet).
		if err := s.writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
			_ = f.Close()
			return fmt.Errorf("write pcap header: %w", err)
		}
	}
	s.wg.Add(1)
	go s.capture()
	return nil
}

// Stop halts capture, flushes reassembly and closes the pcap file.
func (s *Sniffer) Stop() {
	close(s.stop)
	s.wg.Wait()
	if s.file != nil {
		_ = s.file.Sync()
		_ = s.file.Close()
		s.file = nil
	}
	s.handle.Close()
}

// Stats returns the packet and byte counters.
func (s *Sniffer) Stats() (packets, bytes uint64) {
	return s.packets.Load(), s.bytes.Load()
}

// capture is the main capture loop: pull packets until Stop, tolerating
// transient pcap errors with a short sleep.
func (s *Sniffer) capture() {
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
			// pcap read timeouts are normal; only exit on Stop.
			select {
			case <-s.stop:
				return
			default:
				time.Sleep(10 * time.Millisecond)
				continue
			}
		}
		s.process(pkt)
	}
}

// process handles one captured packet: counter/archiving, recon evidence for
// notable protocols, TCP reassembly, and UDP dissectors.
func (s *Sniffer) process(pkt gopacket.Packet) {
	if pkt == nil || pkt.Metadata() == nil {
		return
	}
	s.packets.Add(1)
	s.bytes.Add(uint64(pkt.Metadata().CaptureLength))
	// Archive the raw frame to the pcap file when requested.
	if s.writer != nil {
		_ = s.writer.WritePacket(pkt.Metadata().CaptureInfo, pkt.Data())
	}

	// Recon evidence + special protocols, then TCP reassembly.
	netLayer := pkt.NetworkLayer()
	tcpL := pkt.Layer(layers.LayerTypeTCP)
	udpL := pkt.Layer(layers.LayerTypeUDP)

	if tcpL != nil {
		tcp := tcpL.(*layers.TCP)
		if tcp.DstPort == 853 || tcp.SrcPort == 853 {
			s.db.Recon.SeesDoH.Store(true) // DNS over TLS
		}
		if tcp.DstPort == 80 || tcp.SrcPort == 80 {
			s.db.Recon.SeesPlainHTTP.Store(true)
		}
		if tcp.DstPort == 445 || tcp.SrcPort == 445 {
			s.db.Recon.SeesSMB.Store(true)
		}
		// Reassemble the TCP stream so the HTTP dissector can parse requests
		// spanning multiple segments.
		if netLayer != nil {
			s.assembly.AssembleWithTimestamp(netLayer.NetworkFlow(), tcp, pkt.Metadata().Timestamp)
		}
		return
	}

	if udpL != nil {
		udp := udpL.(*layers.UDP)
		// Port 5355 = LLMNR, 5353 = mDNS, 137 = NetBIOS name service,
		// 53 = DNS, 547 = DHCPv6 server port.
		switch {
		case udp.DstPort == 5355 || udp.SrcPort == 5355:
			s.db.Recon.SeesLLMNR.Store(true)
		case udp.DstPort == 5353 || udp.SrcPort == 5353:
			s.db.Recon.SeesMDNS.Store(true)
		case udp.DstPort == 137 || udp.SrcPort == 137:
			s.db.Recon.SeesNBNS.Store(true)
		case udp.DstPort == 53 || udp.SrcPort == 53:
			s.dissectDNS(pkt, netLayer, udp)
		case udp.DstPort == 547 || udp.SrcPort == 547:
			s.db.Recon.SeesDHCPv6.Store(true)
		}
	}
}
