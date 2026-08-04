package wlan

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// BuildBeacon crafts a raw radio-tap 802.11 beacon frame advertising the given
// SSID from bssid on channel, optionally with an RSN (WPA2) element.
func BuildBeacon(bssid net.HardwareAddr, ssid string, channel uint8, wpa2 bool) ([]byte, error) {
	if len(bssid) != 6 {
		return nil, errors.New("wlan: bssid must be 6 bytes")
	}
	var tags []byte
	tags = append(tags, 0x00, byte(len(ssid))) // SSID
	tags = append(tags, []byte(ssid)...)
	tags = append(tags, 0x01, 0x01, 0x04)    // supported rates
	tags = append(tags, 0x03, 0x01, channel) // DS parameter set
	tags = append(tags, 0x2d, 0x01, 0x10)    // HT capabilities (short)
	if wpa2 {
		tags = append(tags, 0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
			0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02,
			0x00, 0x00)
	}
	tags = append(tags, 0x32, 0x04, 0x0c, 0x12, 0x18, 0x60) // extended rates

	beacon := &layers.Dot11MgmtBeacon{
		Timestamp: uint64(time.Now().UnixNano() / 1000),
		Interval:  100,
		Flags:     0x0001, // ESS
	}
	beacon.Contents = make([]byte, 12) // 8 timestamp + 2 interval + 2 flags
	beacon.Payload = tags

	dot11 := &layers.Dot11{
		Type:     layers.Dot11TypeMgmtBeacon,
		Address1: broadcastMAC,
		Address2: bssid,
		Address3: bssid,
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	radioTap := &layers.RadioTap{}
	if err := gopacket.SerializeLayers(buf, opts, radioTap, dot11, beacon); err != nil {
		return nil, err
	}
	// Dot11MgmtBeacon.SerializeTo writes only the 12-byte fixed header; the
	// information elements in beacon.Payload must be appended by hand.
	out := append(buf.Bytes(), tags...)
	return out, nil
}

// BuildProbeResponse crafts a probe-response frame from bssid advertising
// ssid, used by the KARMA responder.
func BuildProbeResponse(bssid net.HardwareAddr, ssid string, channel uint8, wpa2 bool) ([]byte, error) {
	beacon, err := BuildBeacon(bssid, ssid, channel, wpa2)
	if err != nil {
		return nil, err
	}
	// Rebuild the frame with type ProbeResponse by patching the dot11 type
	// octet. Management subtypes: beacon=0x08, probe resp=0x05. The type/flag
	// byte is offset 24 in the radio-tap+dot11 frame (8 byte radiotap header
	// + 24 byte dot11 header, type byte is the first of the two).
	frame := append([]byte(nil), beacon...)
	if len(frame) >= 32 {
		frame[24] = 0x50 // subtype 5 (probe response), 0 = toDS bit
	}
	return frame, nil
}

// BroadcastSender floods crafted frames on a monitor interface.
type BroadcastSender struct {
	iface  string
	handle *pcap.Handle
	Sent   int
}

// NewBroadcastSender opens an injection-capable monitor handle.
func NewBroadcastSender(iface string) (*BroadcastSender, error) {
	handle, err := pcap.OpenLive(iface, 65535, true, 100*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("wlan: open inject %s: %w", iface, err)
	}
	return &BroadcastSender{iface: iface, handle: handle}, nil
}

// Send writes a single prebuilt frame.
func (b *BroadcastSender) Send(frame []byte) error {
	if err := b.handle.WritePacketData(frame); err != nil {
		return err
	}
	b.Sent++
	return nil
}

// Close releases the handle.
func (b *BroadcastSender) Close() { b.handle.Close() }

// PMKID reports the presence of an RSN PMKID element in an EAPOL message.
type PMKID struct {
	BSSID net.HardwareAddr
	STA   net.HardwareAddr
	ID    []byte // 16-byte PMKID
	Time  time.Time
}

// PMKIDScanner extracts PMKIDs from captured EAPOL key frames. The PMKID is
// carried in message 1 of the 4-way handshake inside the key data as a KDE
// with OUI 00:0f:ac:04. Capturing it allows offline cracking without a client.
type PMKIDScanner struct {
	handle  *pcap.Handle
	stopped chan struct{}
	mu      sync.Mutex
	pmkids  map[string]*PMKID
}

// NewPMKIDScanner opens a monitor handle for PMKID capture.
func NewPMKIDScanner(iface string) (*PMKIDScanner, error) {
	handle, err := pcap.OpenLive(iface, 65535, true, 500*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("wlan: open %s: %w", iface, err)
	}
	return &PMKIDScanner{
		handle:  handle,
		stopped: make(chan struct{}),
		pmkids:  map[string]*PMKID{},
	}, nil
}

// Start begins the capture loop.
func (s *PMKIDScanner) Start() { go s.readLoop() }

func (s *PMKIDScanner) readLoop() {
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
		s.process(data, ci.Timestamp)
	}
}

func (s *PMKIDScanner) process(data []byte, ts time.Time) {
	bssid, sta, pmkid, ok := ExtractPMKID(data)
	if !ok {
		return
	}
	s.mu.Lock()
	key := string(bssid) + string(sta)
	s.pmkids[key] = &PMKID{BSSID: bssid, STA: sta, ID: pmkid, Time: ts}
	s.mu.Unlock()
}

// PMKIDs returns a snapshot of captured PMKIDs.
func (s *PMKIDScanner) PMKIDs() []PMKID {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]PMKID, 0, len(s.pmkids))
	for _, p := range s.pmkids {
		out = append(out, *p)
	}
	return out
}

// Close stops capture and releases the handle.
func (s *PMKIDScanner) Close() {
	select {
	case <-s.stopped:
	default:
		close(s.stopped)
	}
	s.handle.Close()
}

// ExtractPMKID parses a raw frame and returns the BSSID, station and PMKID
// when an RSN-PMKID KDE is present in an EAPOL-Key message.
func ExtractPMKID(data []byte) (bssid, sta net.HardwareAddr, pmkid []byte, ok bool) {
	packet := gopacket.NewPacket(data, layers.LayerTypeRadioTap, gopacket.NoCopy)
	dot11Layer := packet.Layer(layers.LayerTypeDot11)
	if dot11Layer == nil {
		return nil, nil, nil, false
	}
	dot11, _ := dot11Layer.(*layers.Dot11)
	if dot11 == nil || dot11.Type.MainType() != layers.Dot11TypeData {
		return nil, nil, nil, false
	}
	if dot11.Flags.ToDS() {
		bssid, sta = dot11.Address1, dot11.Address2
	} else {
		bssid, sta = dot11.Address2, dot11.Address1
	}

	eapolLayer := packet.Layer(layers.LayerTypeEAPOL)
	if eapolLayer == nil {
		return nil, nil, nil, false
	}
	eapol, ok := eapolLayer.(*layers.EAPOL)
	if !ok {
		return nil, nil, nil, false
	}
	if eapol.Type != layers.EAPOLTypeKey {
		return nil, nil, nil, false
	}
	key := packet.Layer(layers.LayerTypeEAPOLKey)
	if key == nil {
		return nil, nil, nil, false
	}
	// EAPOL-Key payload starts after the 5-byte EAPOL header; the key data is
	// at offset 99 in the key descriptor (2 type/version + ...). Simplest is
	// to scan the key frame bytes for the PMKID KDE marker.
	kd := key.LayerContents()
	if len(kd) < 95 {
		return nil, nil, nil, false
	}
	keyDataLen := int(kd[81])<<8 | int(kd[82])
	keyDataStart := 95
	if keyDataStart+keyDataLen > len(kd) {
		keyDataLen = len(kd) - keyDataStart
	}
	keyData := kd[keyDataStart : keyDataStart+keyDataLen]
	if id := findPMKID(keyData); len(id) == 16 {
		return bssid, sta, id, true
	}
	return nil, nil, nil, false
}

// findPMKID scans key data for the RSN-PMKID KDE: OUI 00:0f:ac:04 followed by
// the 16-byte PMKID.
func findPMKID(kd []byte) []byte {
	for i := 0; i+20 <= len(kd); i++ {
		if kd[i] == 0xdd && kd[i+1] == 20 && kd[i+2] == 0x00 && kd[i+3] == 0x0f && kd[i+4] == 0xac && kd[i+5] == 0x04 {
			return kd[i+6 : i+22]
		}
	}
	return nil
}

var broadcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
