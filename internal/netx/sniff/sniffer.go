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

	"github.com/qyvora/toha3ee/internal/events"
	"github.com/qyvora/toha3ee/internal/netx"
	"github.com/qyvora/toha3ee/internal/store"
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
	stop     chan struct{}
	wg       sync.WaitGroup

	packets atomic.Uint64
	bytes   atomic.Uint64
}

// New opens a promiscuous capture handle on iface.
func New(iface *netx.Iface, bus *events.Bus, db *store.Store, log *slog.Logger) (*Sniffer, error) {
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
		if err := s.writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
			f.Close()
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
		s.file.Sync()
		s.file.Close()
		s.file = nil
	}
	s.handle.Close()
}

// Stats returns the packet and byte counters.
func (s *Sniffer) Stats() (packets, bytes uint64) {
	return s.packets.Load(), s.bytes.Load()
}

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

func (s *Sniffer) process(pkt gopacket.Packet) {
	if pkt == nil || pkt.Metadata() == nil {
		return
	}
	s.packets.Add(1)
	s.bytes.Add(uint64(pkt.Metadata().CaptureLength))
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
			s.db.Recon.SeesDoH.Store(true)
		}
		if tcp.DstPort == 80 || tcp.SrcPort == 80 {
			s.db.Recon.SeesPlainHTTP.Store(true)
		}
		if tcp.DstPort == 445 || tcp.SrcPort == 445 {
			s.db.Recon.SeesSMB.Store(true)
		}
		if netLayer != nil {
			s.assembly.AssembleWithTimestamp(netLayer.NetworkFlow(), tcp, pkt.Metadata().Timestamp)
		}
		return
	}

	if udpL != nil {
		udp := udpL.(*layers.UDP)
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
