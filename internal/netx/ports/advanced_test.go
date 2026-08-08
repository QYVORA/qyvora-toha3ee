package ports

import (
	"net"
	"testing"
)

func TestFragmentPacket(t *testing.T) {
	srcMAC := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	dstMAC := net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	raw, err := BuildSYNEx(
		net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"),
		srcMAC, dstMAC, 45678, 443, 123456, 64, true, 64240, 7)
	if err != nil {
		t.Fatal(err)
	}
	frags, err := fragmentPacket(raw, 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(frags) != 2 {
		t.Fatalf("expected 2 fragments, got %d", len(frags))
	}
	// Fragment 1 must carry the more-fragments flag.
	if frags[0][20]&0x20 == 0 {
		t.Error("fragment 1 missing MF flag")
	}
	// Fragment 2 must carry a nonzero fragment offset (bytes 6-7 of IP header,
	// which starts at offset 14 of the frame).
	off := int(frags[1][20])<<8 | int(frags[1][21])
	if off == 0 {
		t.Error("fragment 2 missing fragment offset")
	}
	// Both headers must have valid checksums.
	for i, f := range frags {
		cs := ipChecksum(f[14:34])
		if cs != 0 {
			t.Errorf("fragment %d checksum invalid: %04x", i, cs)
		}
	}
	// Reassembled IP payload must equal the original IP payload (the frame may
	// carry ethernet padding after the IP datagram, so use the IP total-length
	// field). IP starts at frame offset 14; the header ends at offset 34.
	ipTotal := int(raw[16])<<8 | int(raw[17])
	orig := ipTotal - 20
	reassembled := len(frags[0]) - 34 + len(frags[1]) - 34
	if reassembled != orig {
		t.Errorf("reassembled payload %d != original %d", reassembled, orig)
	}
	// Fragment 2 offset in bytes must be fragSize.
	if off*8 != 8 {
		t.Errorf("fragment 2 offset %d bytes, want 8", off*8)
	}
}

func TestIpChecksum(t *testing.T) {
	// 0x4500 0x0028 ... computed over a minimal header should validate.
	hdr := []byte{
		0x45, 0x00, 0x00, 0x28, 0x00, 0x07, 0x40, 0x00,
		0x40, 0x06, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02,
	}
	cs := ipChecksum(hdr)
	if cs == 0 {
		t.Fatal("checksum must be non-zero for a header with zeroed checksum")
	}
	// Putting the checksum back in must make the total sum zero.
	hdr[10] = byte(cs >> 8)
	hdr[11] = byte(cs)
	if ipChecksum(hdr) != 0 {
		t.Error("checksum validation failed after insertion")
	}
}

func TestApplySourceIP(t *testing.T) {
	srcMAC := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	dstMAC := net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	raw, err := BuildSYN(
		net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"),
		srcMAC, dstMAC, 45678, 443, 123456)
	if err != nil {
		t.Fatal(err)
	}
	d := applySourceIP(raw, net.ParseIP("172.16.9.9"))
	if d == nil {
		t.Fatal("applySourceIP returned nil")
	}
	if !net.IP(d[26:30]).Equal(net.ParseIP("172.16.9.9")) {
		t.Errorf("src IP not rewritten: %v", d[26:30])
	}
	if ipChecksum(d[14:34]) != 0 {
		t.Error("rewritten header checksum invalid")
	}
}

func TestDecoyProbes(t *testing.T) {
	// DecoyProbes on a bare Scanner must not panic and returns 0.
	s := &Scanner{}
	if n := s.DecoyProbes(); n != 0 {
		t.Errorf("DecoyProbes = %d", n)
	}
}
