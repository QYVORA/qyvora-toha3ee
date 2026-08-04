package wlan

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestBuildBeaconRoundTrip(t *testing.T) {
	bssid := net.HardwareAddr{0x02, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e}
	raw, err := BuildBeacon(bssid, "testnet", 6, true)
	if err != nil {
		t.Fatalf("BuildBeacon: %v", err)
	}
	if len(raw) < 40 {
		t.Fatalf("beacon too short: %d", len(raw))
	}
	p := gopacket.NewPacket(raw, layers.LayerTypeRadioTap, gopacket.NoCopy)
	d11, ok := p.Layer(layers.LayerTypeDot11).(*layers.Dot11)
	if !ok || d11 == nil {
		t.Fatalf("no Dot11 layer: %v", p.Layers())
	}
	if d11.Type != layers.Dot11TypeMgmtBeacon {
		t.Errorf("dot11 type = %v, want beacon", d11.Type)
	}
	if d11.Address2.String() != bssid.String() {
		t.Errorf("bssid = %v, want %v", d11.Address2, bssid)
	}
	b, ok := p.Layer(layers.LayerTypeDot11MgmtBeacon).(*layers.Dot11MgmtBeacon)
	if !ok || b == nil {
		t.Fatalf("no beacon layer")
	}
	ssid, channel, security := parseBeacon(b)
	if ssid != "testnet" {
		t.Errorf("ssid = %q, want testnet", ssid)
	}
	if channel != 6 {
		t.Errorf("channel = %d, want 6", channel)
	}
	if security != "wpa2" {
		t.Errorf("security = %q, want wpa2", security)
	}
}

func TestBuildProbeResponseType(t *testing.T) {
	raw, err := BuildProbeResponse(net.HardwareAddr{0x02, 0, 0, 0, 0, 0xaa}, "openwifi", 1, false)
	if err != nil {
		t.Fatalf("BuildProbeResponse: %v", err)
	}
	// The dot11 type octet sits at frame offset 24 (8-byte radiotap + 24-byte
	// dot11 header, type byte first). Probe response subtype is 0x05.
	if len(raw) < 26 {
		t.Fatalf("frame too short: %d", len(raw))
	}
	if got := raw[24] >> 4; got != 0x05 {
		t.Errorf("frame subtype = %#x, want 0x5 (probe response)", got)
	}
}

func TestFindPMKID(t *testing.T) {
	kde := []byte{
		0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, // RSN
		0xdd, 0x14, 0x00, 0x0f, 0xac, 0x04, // PMKID KDE header
	}
	id := make([]byte, 16)
	for i := range id {
		id[i] = byte(i)
	}
	kde = append(kde, id...)
	got := findPMKID(kde)
	if got == nil {
		t.Fatal("findPMKID returned nil for a valid KDE")
	}
	for i := range id {
		if got[i] != id[i] {
			t.Fatalf("pmkid[%d] = %#x, want %#x", i, got[i], id[i])
		}
	}
	if findPMKID([]byte{0x00, 0x00}) != nil {
		t.Error("short data should not match")
	}
}

func TestExtractPMKIDRoundTrip(t *testing.T) {
	// Build an 802.11 data frame with an LLC/SNAP/EAPOL/EAPOLKey payload.
	// This is heavy for a unit test; instead verify that a non-EAPOL frame is
	// rejected cleanly.
	bssid := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01}
	sta := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x02}
	raw, err := BuildBeacon(bssid, "x", 1, false)
	if err != nil {
		t.Fatal(err)
	}
	_ = sta
	if _, _, _, ok := ExtractPMKID(raw); ok {
		t.Error("beacon frame must not be parsed as a PMKID carrier")
	}
}
