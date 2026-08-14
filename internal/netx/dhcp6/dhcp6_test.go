package dhcp6

import (
	"net"
	"testing"

	"github.com/QYVORA/qyvora-toha3ee/internal/events"
)

func buildClientMsg(msgType byte, iaid []byte, clientID []byte) []byte {
	pkt := []byte{msgType, 0x12, 0x34, 0x56}
	if clientID != nil {
		pkt = appendOption(pkt, optClientID, clientID)
	}
	if iaid != nil {
		iana := append([]byte{}, iaid...)
		iana = append(iana, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
		pkt = appendOption(pkt, optIANA, iana)
	}
	pkt = appendOption(pkt, optORO, []byte{0, 23})
	return pkt
}

func TestResponderSolicitAdvertise(t *testing.T) {
	r := New(&net.Interface{Index: 1, Name: "wlan0"}, net.ParseIP("2001:db8::1"), events.NewBus())
	pkt := buildClientMsg(msgSolicit, []byte{1, 2, 3, 4}, []byte{9, 9, 9})
	out := r.handle(pkt)
	if out == nil {
		t.Fatal("no response to solicit")
	}
	if out[0] != msgAdvertise {
		t.Fatalf("expected advertise, got type %d", out[0])
	}
	foundDNS := false
	for _, o := range parseOptions(out[4:]) {
		if o.code == optDNS {
			foundDNS = true
			if len(o.data) != 16 || !net.IP(o.data).Equal(r.attackerIP) {
				t.Fatalf("bad DNS option: %x", o.data)
			}
		}
	}
	if !foundDNS {
		t.Fatal("DNS server option missing")
	}
}

func TestResponderRequestReply(t *testing.T) {
	r := New(&net.Interface{Index: 1}, net.ParseIP("2001:db8::2"), events.NewBus())
	out := r.handle(buildClientMsg(msgRequest, []byte{5, 5, 5, 5}, nil))
	if out == nil || out[0] != msgReply {
		t.Fatalf("expected reply, got %v", out)
	}
}

func TestResponderIgnoresUnknown(t *testing.T) {
	r := New(&net.Interface{Index: 1}, net.ParseIP("2001:db8::3"), events.NewBus())
	// Release (type 7) and malformed packets must not produce a reply.
	if out := r.handle([]byte{msgReply, 0, 0, 0}); out != nil {
		t.Fatal("unexpected reply for unsolicited type")
	}
	if out := r.handle([]byte{1, 2}); out != nil {
		t.Fatal("malformed packet produced a reply")
	}
}

func TestParseOptions(t *testing.T) {
	msg := buildClientMsg(msgSolicit, []byte{1, 2, 3, 4}, []byte{7, 7})
	opts := parseOptions(msg[4:])
	seen := map[uint16]bool{}
	for _, o := range opts {
		seen[o.code] = true
	}
	if !seen[optIANA] || !seen[optClientID] || !seen[optORO] {
		t.Fatalf("options missing: %v", seen)
	}
}
