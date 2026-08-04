package dhcp

import (
	"bytes"
	"net"
	"testing"
)

func TestDiscoverMarshalUnmarshal(t *testing.T) {
	mac := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	raw, err := Discover(mac, 0xdeadbeef)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	h, err := Unmarshal(raw)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if h.Op != opRequest {
		t.Errorf("op = %d, want %d", h.Op, opRequest)
	}
	if h.Xid != 0xdeadbeef {
		t.Errorf("xid = %08x, want deadbeef", h.Xid)
	}
	if !bytes.Equal(h.CHAddr, mac) {
		t.Errorf("chaddr = %v, want %v", h.CHAddr, mac)
	}
	if got := getMessageType(h.Options); got != TypeDiscover {
		t.Errorf("message type = %d, want %d", got, TypeDiscover)
	}
}

func TestOfferContainsRogueOptions(t *testing.T) {
	raw, err := Offer(0x01020304, net.HardwareAddr{0x02, 0, 0, 0, 0, 0x02},
		net.IPv4(192, 168, 8, 50), net.IPv4(192, 168, 8, 116), net.IPv4(255, 255, 255, 0))
	if err != nil {
		t.Fatalf("Offer: %v", err)
	}
	h, err := Unmarshal(raw)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if h.Op != opReply {
		t.Errorf("op = %d, want reply", h.Op)
	}
	if !h.YIAddr.Equal(net.IPv4(192, 168, 8, 50)) {
		t.Errorf("yiaddr = %v, want 192.168.8.50", h.YIAddr)
	}
	if got := getMessageType(h.Options); got != TypeOffer {
		t.Errorf("message type = %d, want %d", got, TypeOffer)
	}
	// Verify the rogue router/DNS options are present.
	seenRouter, seenDNS := false, false
	for _, o := range parseOptions(h.Options) {
		switch o.Code {
		case 3:
			seenRouter = bytes.Equal(o.Data, []byte{192, 168, 8, 116})
		case 6:
			seenDNS = bytes.Equal(o.Data, []byte{192, 168, 8, 116})
		}
	}
	if !seenRouter {
		t.Error("offer does not set rogue router (option 3)")
	}
	if !seenDNS {
		t.Error("offer does not set rogue DNS (option 6)")
	}
}

func TestNextAddrCyclesPool(t *testing.T) {
	r := NewResponder(Config{ServerIP: net.IPv4(192, 168, 8, 116), Pool: net.IPv4(192, 168, 8, 100), Size: 5})
	first := r.nextAddr()
	if !first.Equal(net.IPv4(192, 168, 8, 100)) {
		t.Errorf("first addr = %v, want 192.168.8.100", first)
	}
	for i := 1; i < 5; i++ {
		r.nextAddr()
	}
	wrap := r.nextAddr()
	if !wrap.Equal(first) {
		t.Errorf("after pool wrap addr = %v, want %v (cycle)", wrap, first)
	}
}

func TestMalformedUnmarshal(t *testing.T) {
	if _, err := Unmarshal([]byte{1, 2, 3}); err == nil {
		t.Error("short packet should error")
	}
	raw, _ := Discover(net.HardwareAddr{1, 2, 3, 4, 5, 6}, 1)
	if _, err := Unmarshal(raw[:100]); err == nil {
		t.Error("short packet should error")
	}
	bad := append([]byte(nil), raw...)
	bad[232] ^= 0xff // corrupt the magic cookie
	if _, err := Unmarshal(bad); err == nil {
		t.Error("bad magic cookie should error")
	}
}

func parseOptions(opts []byte) []Option {
	var out []Option
	for i := 0; i+1 < len(opts); {
		code := opts[i]
		if code == 0 {
			i++
			continue
		}
		if code == 255 {
			break
		}
		l := int(opts[i+1])
		if i+2+l > len(opts) {
			break
		}
		out = append(out, Option{Code: code, Data: opts[i+2 : i+2+l]})
		i += 2 + l
	}
	return out
}
