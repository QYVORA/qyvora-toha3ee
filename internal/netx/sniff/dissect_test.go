package sniff

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/QYVORA/qyvora-toha3ee/internal/events"
	"github.com/QYVORA/qyvora-toha3ee/internal/store"
)

func testSniffer() *Sniffer {
	db := store.New(0)
	return &Sniffer{
		bus: events.NewBus(),
		db:  db,
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func makeRequest(method, target, body string, hdr http.Header) *http.Request {
	req, _ := http.NewRequest(method, target, nil)
	for k, v := range hdr {
		req.Header[k] = v
	}
	if body != "" {
		req.Body = io.NopCloser(newStringReader(body))
	}
	return req
}

type stringReader struct{ s string }

func (s *stringReader) Read(p []byte) (int, error) {
	if len(s.s) == 0 {
		return 0, io.EOF
	}
	n := copy(p, s.s)
	s.s = s.s[n:]
	return n, nil
}

func newStringReader(s string) *stringReader { return &stringReader{s: s} }

func TestHTTPPostCredentialExtraction(t *testing.T) {
	s := testSniffer()
	flow := gopacket.NewFlow(layers.EndpointIPv4,
		net.ParseIP("192.168.8.107").To4(), net.ParseIP("93.184.216.34").To4())
	req := makeRequest(http.MethodPost, "http://login.example.com/auth",
		"username=alice&password=hunter2&login=SignIn", http.Header{
			"Content-Type": {"application/x-www-form-urlencoded"},
			"User-Agent":   {"curl/8.0"},
		})
	s.handleRequest(flow, req)

	creds := s.db.Creds()
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}
	c := creds[0]
	if c.Username != "alice" || c.Password != "hunter2" {
		t.Fatalf("creds = %+v", c)
	}
	if c.VictimIP != "192.168.8.107" {
		t.Fatalf("victim ip = %q", c.VictimIP)
	}
	if c.Service != "http.form" {
		t.Fatalf("service = %q", c.Service)
	}
}

func TestHTTPBasicAuthExtraction(t *testing.T) {
	s := testSniffer()
	flow := gopacket.NewFlow(layers.EndpointIPv4,
		net.ParseIP("10.0.0.5").To4(), net.ParseIP("10.0.0.1").To4())
	req := makeRequest(http.MethodGet, "http://router/admin", "", http.Header{
		"Authorization": {"Basic YWRtaW46Y2hhbmdlbWU="}, // admin:changeme
	})
	s.handleRequest(flow, req)
	creds := s.db.Creds()
	if len(creds) != 1 || creds[0].Service != "http.basic" {
		t.Fatalf("basic auth not extracted: %+v", creds)
	}
	if creds[0].Username != "admin" || creds[0].Password != "changeme" {
		t.Fatalf("basic creds = %+v", creds[0])
	}
}

func TestQueryParamExtraction(t *testing.T) {
	s := testSniffer()
	flow := gopacket.NewFlow(layers.EndpointIPv4,
		net.ParseIP("192.168.8.10").To4(), net.ParseIP("192.168.8.1").To4())
	req := makeRequest(http.MethodGet, "http://portal/login?user=carol&password=pass123", "", nil)
	s.handleRequest(flow, req)
	creds := s.db.Creds()
	if len(creds) != 1 || creds[0].Username != "carol" || creds[0].Password != "pass123" {
		t.Fatalf("query creds = %+v", creds)
	}
}

func TestSessionCaptureFromCookies(t *testing.T) {
	s := testSniffer()
	flow := gopacket.NewFlow(layers.EndpointIPv4,
		net.ParseIP("192.168.8.107").To4(), net.ParseIP("93.184.216.34").To4())
	req := makeRequest(http.MethodGet, "http://bank.com/account", "", http.Header{
		"Cookie": {"session=abc123; csrf=x9y"},
	})
	s.handleRequest(flow, req)
	sessions := s.db.Sessions()
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	if sessions[0].Cookies["session"] != "abc123" {
		t.Fatalf("session cookie not captured: %+v", sessions[0].Cookies)
	}
}

func TestResponseSetCookieCapture(t *testing.T) {
	s := testSniffer()
	flow := gopacket.NewFlow(layers.EndpointIPv4,
		net.ParseIP("93.184.216.34").To4(), net.ParseIP("192.168.8.107").To4())
	resp := &http.Response{
		StatusCode: 200,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"Set-Cookie": {"sid=deadbeef; Path=/"}},
		Body:       io.NopCloser(&stringReader{""}),
	}
	s.handleResponse(flow, resp)
	sessions := s.db.Sessions()
	if len(sessions) != 1 || sessions[0].Cookies["sid"] != "deadbeef" {
		t.Fatalf("set-cookie not captured: %+v", sessions)
	}
}

func TestJSONCredentialExtraction(t *testing.T) {
	got := guessJSONFields([]byte(`{"username": "dave", "password": "s3cr3t", "remember": true}`))
	if got["username"] != "dave" || got["password"] != "s3cr3t" {
		t.Fatalf("json fields = %v", got)
	}
}

func TestNestedJSONNoExtraction(t *testing.T) {
	got := guessJSONFields([]byte(`{"config": {"username": "nested"}, "items": [1,2]}`))
	if len(got) != 0 {
		t.Fatalf("nested fields should not be extracted: %v", got)
	}
}

func TestStreamParserMultipleRequests(t *testing.T) {
	s := testSniffer()
	h := &httpStream{net: gopacket.Flow{}, transport: gopacket.Flow{}, sniffer: s}
	raw := "POST /a HTTP/1.1\r\nHost: x.com\r\nContent-Length: 25\r\n\r\nusername=bob&password=pw1" +
		"POST /b HTTP/1.1\r\nHost: x.com\r\nContent-Length: 25\r\n\r\nusername=eve&password=pw2"
	h.buf.WriteString(raw)
	h.ReassemblyComplete()
	creds := s.db.Creds()
	if len(creds) != 2 {
		t.Fatalf("expected 2 creds from pipelined requests, got %d", len(creds))
	}
	if creds[0].Username != "bob" || creds[1].Username != "eve" {
		t.Fatalf("wrong users: %+v", creds)
	}
}
