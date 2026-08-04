package llmnr

import (
	"net"
	"testing"

	"github.com/miekg/dns"

	"github.com/qyvora/toha3ee/internal/events"
	"github.com/qyvora/toha3ee/internal/store"
)

func queryPacket(name string, qtype uint16) []byte {
	msg := new(dns.Msg)
	msg.Id = 0xbeef
	msg.SetQuestion(dns.Fqdn(name), qtype)
	out, _ := msg.Pack()
	return out
}

func TestResponderAnswersQuery(t *testing.T) {
	db := store.New(100)
	r := New(net.ParseIP("10.0.0.7"), events.NewBus(), db)
	attacker := net.ParseIP("10.0.0.7").To4()

	resp, name := r.buildResponse(queryPacket("print-server", dns.TypeA))
	if resp == nil || name != "print-server" {
		t.Fatal("no answer produced")
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(resp); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if len(msg.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(msg.Answer))
	}
	a, ok := msg.Answer[0].(*dns.A)
	if !ok || !a.A.Equal(attacker) {
		t.Fatalf("bad answer: %v", msg.Answer[0])
	}
}

func TestResponderIgnoresResponses(t *testing.T) {
	r := New(net.ParseIP("10.0.0.7"), events.NewBus(), store.New(10))
	msg := new(dns.Msg)
	msg.SetReply(new(dns.Msg))
	msg.Response = true
	out, _ := msg.Pack()
	if resp, _ := r.buildResponse(out); resp != nil {
		t.Fatal("response message should be ignored")
	}
	if r.Queries.Load() != 0 {
		t.Fatal("response counted as query")
	}
}

func TestResponderCounter(t *testing.T) {
	r := New(net.ParseIP("10.0.0.7"), nil, nil)
	for i := 0; i < 3; i++ {
		if resp, _ := r.buildResponse(queryPacket("host-1", dns.TypeA)); resp == nil {
			t.Fatal("no reply")
		}
	}
	if r.Queries.Load() != 3 {
		t.Fatalf("queries counter wrong: %d", r.Queries.Load())
	}
}
