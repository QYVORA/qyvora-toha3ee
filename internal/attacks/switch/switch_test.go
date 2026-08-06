package switchattack

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/qyvora/toha3ee/internal/netx"
)

func testIface() *netx.Iface {
	return &netx.Iface{
		Name: "eth0",
		MAC:  net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		IP:   net.IPv4(192, 168, 1, 50),
	}
}

func TestRootBridgeID(t *testing.T) {
	mac := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	id := rootBridgeID(mac)
	if len(id) != 8 {
		t.Fatalf("bridge id length = %d, want 8", len(id))
	}
	if id[0] != 0 || id[1] != 0 {
		t.Errorf("priority = %02x%02x, want 0x0000", id[0], id[1])
	}
	for i := 0; i < 6; i++ {
		if id[2+i] != mac[i] {
			t.Fatalf("bridge id mac mismatch at byte %d", i)
		}
	}
}

func TestBuildBPDU(t *testing.T) {
	mac := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	frame, err := buildBPDU(mac)
	if err != nil {
		t.Fatalf("buildBPDU: %v", err)
	}
	// 14 ethernet + 8 LLC/SNAP + 35 BPDU = 57
	if len(frame) != 57 {
		t.Fatalf("frame length = %d, want 57", len(frame))
	}
	if got := frame[:6]; string(got) != string([]byte{0x01, 0x80, 0xc2, 0x00, 0x00, 0x00}) {
		t.Errorf("dst = % x, want STP multicast", got)
	}
	if frame[12] != 0x00 || frame[13] != 43 {
		t.Errorf("802.3 length = %02x%02x, want 0x002b", frame[12], frame[13])
	}
	// LLC/SNAP PID 802.1D spanning tree.
	if string(frame[14:22]) != string([]byte{0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x00, 0x01}) {
		t.Errorf("LLC/SNAP = % x", frame[14:22])
	}
	bpdu := frame[22:]
	if bpdu[0] != 0 || bpdu[1] != 0 {
		t.Errorf("protocol id = %02x%02x", bpdu[0], bpdu[1])
	}
	if bpdu[3] != 0x00 {
		t.Errorf("BPDU type = %#x, want 0x00 (configuration)", bpdu[3])
	}
	// Root priority (upper 16 bits of bridge id) must be 0 => strictly better.
	prio := binary.BigEndian.Uint16(bpdu[5:7])
	if prio != 0 {
		t.Errorf("root priority = %d, want 0", prio)
	}
	// Root id carries our MAC.
	if string(bpdu[7:13]) != string(mac) {
		t.Errorf("root id mac = % x, want %v", bpdu[7:13], mac)
	}
	// Timers: max age 0x14, hello 0x0f, forward delay 0x0f (in 1/256s).
	if binary.BigEndian.Uint16(bpdu[29:31]) != 0x0014 {
		t.Errorf("max age = %#x", binary.BigEndian.Uint16(bpdu[29:31]))
	}
	if binary.BigEndian.Uint16(bpdu[31:33]) != 0x000f {
		t.Errorf("hello = %#x", binary.BigEndian.Uint16(bpdu[31:33]))
	}
	if binary.BigEndian.Uint16(bpdu[33:35]) != 0x000f {
		t.Errorf("forward delay = %#x", binary.BigEndian.Uint16(bpdu[33:35]))
	}
}

func TestBuildCDP(t *testing.T) {
	frame := buildCDP(testIface())
	if len(frame) < 14 {
		t.Fatalf("CDP frame too short: %d", len(frame))
	}
	// CDP multicast + ethertype 0x2000.
	if string(frame[0:6]) != string([]byte{0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc}) {
		t.Errorf("dst = % x", frame[0:6])
	}
	if frame[12] != 0x20 || frame[13] != 0x00 {
		t.Errorf("ethertype = %02x%02x, want 0x2000", frame[12], frame[13])
	}
	if frame[14] != 0x02 {
		t.Errorf("CDP version = %#x, want 2", frame[14])
	}
	// The TLV length field must hold 4+payload and the body must be a
	// multiple-of-4-free valid TLV chain ending before frame end.
	body := frame[22:]
	i := 0
	for i+4 <= len(body) {
		length := binary.BigEndian.Uint16(body[i+2 : i+4])
		if int(length) < 4 {
			t.Fatalf("TLV at %d has length %d < 4", i, length)
		}
		if i+int(length) > len(body) {
			t.Fatalf("TLV at %d overruns body (%d > %d)", i, i+int(length), len(body))
		}
		i += int(length)
	}
	if i != len(body) {
		t.Fatalf("TLV chain ended at %d of %d", i, len(body))
	}
	// Ones'-complement checksum must equal the stored value. Replicate the
	// builder's exact summation (words from offset 2, checksum field zeroed).
	sumStart := append([]byte(nil), frame...)
	sumStart[16], sumStart[17] = 0, 0
	var sum uint32
	for j := 2; j+1 < len(sumStart); j += 2 {
		sum += uint32(binary.BigEndian.Uint16(sumStart[j : j+2]))
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	want := ^uint16(sum)
	if got := binary.BigEndian.Uint16(frame[16:18]); got != want {
		t.Errorf("CDP checksum = %#x, want %#x", got, want)
	}
}

func TestBuildLLDP(t *testing.T) {
	frame := buildLLDP(testIface())
	if len(frame) < 14 {
		t.Fatalf("LLDP frame too short: %d", len(frame))
	}
	if string(frame[0:6]) != string([]byte{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e}) {
		t.Errorf("dst = % x, want LLDP multicast", frame[0:6])
	}
	if frame[12] != 0x88 || frame[13] != 0xcc {
		t.Errorf("ethertype = %02x%02x, want 0x88cc", frame[12], frame[13])
	}
	// First TLV must be chassis id (type 0).
	payload := frame[14:]
	typLen := binary.BigEndian.Uint16(payload[0:2])
	if typLen>>9 != 0 {
		t.Errorf("first TLV type = %d, want 0 (chassis id)", typLen>>9)
	}
	// The type field must be split correctly: type<<9 | length. Length of a
	// TLVs 1..127 must not overflow 9 bits.
	if typLen&0x01ff == 0 {
		t.Error("first TLV has zero length")
	}
}
