package ndp

import (
	"net"
	"testing"
)

func TestPrefixFrom(t *testing.T) {
	ip := net.ParseIP("2001:db8:1:2::dead")
	p := prefixFrom(ip)
	want := net.ParseIP("2001:db8:1:2::")
	if !p.Equal(want) {
		t.Errorf("prefixFrom(%v) = %v, want %v", ip, p, want)
	}
}

func TestPrefixInfoData(t *testing.T) {
	d := prefixInfoData(64, net.ParseIP("2001:db8:1:2::"))
	if len(d) != 30 {
		t.Fatalf("prefix info data length = %d, want 30", len(d))
	}
	if d[0] != 64 {
		t.Errorf("prefix length = %d, want 64", d[0])
	}
	if d[1] != 0xc0 {
		t.Errorf("flags = %#x, want 0xc0 (on-link + autonomous)", d[1])
	}
	if !net.IP(d[14:]).Equal(net.ParseIP("2001:db8:1:2::")) {
		t.Errorf("embedded prefix = %v", net.IP(d[14:]))
	}
}

func TestRAOptionsPaddedTo8(t *testing.T) {
	// Source-link-layer (MAC=6 data => 8 total), prefix info (30 data => 32
	// total), MTU (6 data => 8 total): every option must be 8-byte aligned for
	// ICMPv6Options.SerializeTo (length/8).
	cases := []struct {
		data []byte
		want int
	}{
		{[]byte(net.HardwareAddr{1, 2, 3, 4, 5, 6}), 8},
		{prefixInfoData(64, net.ParseIP("2001:db8::")), 32},
		{[]byte{0x00, 0x00, 0x00, 0x05, 0xdc, 0x00}, 8}, // MTU 1500
	}
	for _, c := range cases {
		if (len(c.data)+2)%8 != 0 {
			t.Errorf("option with %d data bytes does not pad to %d", len(c.data), c.want)
		}
	}
}
