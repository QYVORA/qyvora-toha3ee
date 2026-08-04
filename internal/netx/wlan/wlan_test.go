package wlan

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func tagBytes(id byte, val []byte) []byte {
	return append([]byte{id, byte(len(val))}, val...)
}

func makeBeacon(bssid net.HardwareAddr, ssid string, channel byte, wpa2 bool) []byte {
	radioTap := &layers.RadioTap{}
	dot11 := &layers.Dot11{
		Type: layers.Dot11TypeMgmtBeacon,

		Address1: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		Address2: bssid,
		Address3: bssid,
	}
	beacon := &layers.Dot11MgmtBeacon{Timestamp: 1000, Interval: 100, Flags: 0x0001}
	var tags []byte
	tags = append(tags, tagBytes(0, []byte(ssid))...)
	tags = append(tags, tagBytes(3, []byte{channel})...)
	if wpa2 {
		tags = append(tags, tagBytes(48, []byte{0x30, 0x18, 0x01, 0x00})...)
	}
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, radioTap, dot11, beacon)
	return append(buf.Bytes(), tags...)
}

func TestScannerParsesBeacon(t *testing.T) {
	sc := &Scanner{aps: map[string]*AP{}, clients: map[string]*Client{}, hs: map[string]*Handshake{}}
	bssid := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	data := makeBeacon(bssid, "CorpWiFi", 6, true)

	sc.process(data, gopacket.CaptureInfo{Timestamp: time.Now()})

	aps := sc.APs()
	if len(aps) != 1 {
		t.Fatalf("expected 1 AP, got %d", len(aps))
	}
	ap := aps[0]
	if ap.SSID != "CorpWiFi" || ap.Channel != 6 || ap.Security != "wpa2" {
		t.Fatalf("bad AP: %+v", ap)
	}
	if !bytes.Equal(ap.BSSID, bssid) {
		t.Fatalf("bad bssid: %s", ap.BSSID)
	}
}

func TestParseOpenBeacon(t *testing.T) {
	sc := &Scanner{aps: map[string]*AP{}, clients: map[string]*Client{}, hs: map[string]*Handshake{}}
	data := makeBeacon(net.HardwareAddr{1, 2, 3, 4, 5, 6}, "Guest", 11, false)
	sc.process(data, gopacket.CaptureInfo{Timestamp: time.Now()})
	ap := sc.APs()[0]
	if ap.Security != "open" {
		t.Fatalf("expected open, got %s", ap.Security)
	}
}

func TestBuildDeauth(t *testing.T) {
	ap := net.HardwareAddr{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa}
	sta := net.HardwareAddr{0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb}
	frame, err := BuildDeauth(ap, sta, layers.Dot11ReasonDeauthStLeaving)
	if err != nil {
		t.Fatal(err)
	}
	if len(frame) < 24 {
		t.Fatalf("frame too short: %d", len(frame))
	}
	pkt := gopacket.NewPacket(frame, layers.LayerTypeRadioTap, gopacket.DecodeOptions{})
	dot11, ok := pkt.Layer(layers.LayerTypeDot11).(*layers.Dot11)
	if !ok {
		t.Fatal("no dot11 layer")
	}
	if dot11.Type != layers.Dot11TypeMgmtDeauthentication {
		t.Fatalf("type = %v", dot11.Type)
	}
	if !bytes.Equal(dot11.Address2, ap) || !bytes.Equal(dot11.Address1, sta) {
		t.Fatalf("bad addresses: %s %s", dot11.Address1, dot11.Address2)
	}
	deauth, ok := pkt.Layer(layers.LayerTypeDot11MgmtDeauthentication).(*layers.Dot11MgmtDeauthentication)
	if !ok {
		t.Fatal("no deauth layer")
	}
	if deauth.Reason != layers.Dot11ReasonDeauthStLeaving {
		t.Fatalf("reason = %v", deauth.Reason)
	}
}

func TestBroadcastDeauth(t *testing.T) {
	ap := net.HardwareAddr{1, 2, 3, 4, 5, 6}
	frame, err := BuildDeauth(ap, nil, layers.Dot11ReasonUnspecified)
	if err != nil {
		t.Fatal(err)
	}
	if len(frame) == 0 {
		t.Fatal("empty frame")
	}
}
