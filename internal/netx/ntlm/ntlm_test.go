package ntlm

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func buildType3(username, domain string, ntresp []byte) []byte {
	// Header: signature(8) + type(4) + 6 security buffers(48) + flags(4) + version(8) + MIC(4).
	payloadOff := 76
	buf := make([]byte, 0, 4096)
	buf = append(buf, Signature...)
	var mtype [4]byte
	binary.LittleEndian.PutUint32(mtype[:], msgAuthentic)
	buf = append(buf, mtype[:]...)

	// Reserve space for 6 security buffers.
	secBase := len(buf)
	sec := make([]byte, 48)
	buf = append(buf, sec...)
	// flags
	var fl [4]byte
	binary.LittleEndian.PutUint32(fl[:], flagUnicode|flagNTLM)
	buf = append(buf, fl[:]...)
	// version + MIC
	buf = append(buf, make([]byte, 12)...)

	offset := uint32(payloadOff)
	put := func(data []byte) uint32 {
		if data == nil {
			return 0
		}
		off := offset
		buf = append(buf, data...)
		offset += uint32(len(data))
		return off
	}

	// LM response (empty) at secBase+0, NT response at secBase+8, domain +8, username +8, workstation +8, session key +8.
	_ = put(nil) // LM
	ntOff := put(ntresp)
	domOff := put([]byte(domain))
	userOff := put([]byte(username))
	_ = put(nil) // workstation
	_ = put(nil) // session key

	write := func(at int, data []byte, off uint32) {
		binary.LittleEndian.PutUint16(buf[at:], uint16(len(data)))
		binary.LittleEndian.PutUint16(buf[at+2:], uint16(len(data)))
		binary.LittleEndian.PutUint32(buf[at+4:], off)
	}
	write(secBase, nil, 0)          // LM
	write(secBase+8, ntresp, ntOff) // NT
	write(secBase+16, []byte(domain), domOff)
	write(secBase+24, []byte(username), userOff)
	write(secBase+32, nil, 0)
	write(secBase+40, nil, 0)
	return buf
}

func TestMessageHelpers(t *testing.T) {
	pkt := buildType3("alice", "CORP", bytes.Repeat([]byte{0x42}, 48))
	if !IsNTLM(pkt) {
		t.Fatal("signature not detected")
	}
	mt, err := MessageType(pkt)
	if err != nil || mt != msgAuthentic {
		t.Fatalf("type = %d, err=%v", mt, err)
	}
	t3, err := ParseType3(pkt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if t3.Username != "alice" || t3.Domain != "CORP" {
		t.Fatalf("fields wrong: %+v", t3)
	}
	if len(t3.NTResponse) != 48 || t3.NTResponse[0] != 0x42 {
		t.Fatalf("NT response wrong: %x", t3.NTResponse)
	}
}

func TestParseType1(t *testing.T) {
	pkt := buildType3("", "", nil)
	if _, err := MessageType(pkt); err != nil {
		t.Fatal(err)
	}
	// Craft a minimal type 1.
	m1 := append([]byte{}, Signature...)
	var mt [4]byte
	binary.LittleEndian.PutUint32(mt[:], msgNegotiate)
	m1 = append(m1, mt[:]...)
	m1 = append(m1, make([]byte, 36)...)
	t1, err := ParseType1(m1)
	if err != nil {
		t.Fatalf("parse type1: %v", err)
	}
	_ = t1
}

func TestServerCapture(t *testing.T) {
	var got *CapturedHash
	done := make(chan struct{})
	srv := NewServer(func(h CapturedHash) {
		got = &h
		close(done)
	}, "CORP")
	addr, err := srv.Start("127.0.0.1:0")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer srv.Stop()

	challenge := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Client sends type 1 negotiate.
	t1 := append([]byte{}, Signature...)
	var mt [4]byte
	binary.LittleEndian.PutUint32(mt[:], msgNegotiate)
	t1 = append(t1, mt[:]...)
	t1 = append(t1, make([]byte, 36)...)
	if _, err := conn.Write(t1); err != nil {
		t.Fatal(err)
	}

	// Read type 2 challenge.
	read := make([]byte, 512)
	n, err := conn.Read(read)
	if err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	mt2, err := MessageType(read[:n])
	if err != nil || mt2 != msgChallenge {
		t.Fatalf("expected challenge, got type %d err=%v", mt2, err)
	}

	// Send type 3 authenticate with the challenge echoed in the NT response.
	ntresp := append([]byte{}, challenge...)
	ntresp = append(ntresp, make([]byte, 40)...)
	if _, err := conn.Write(buildType3("bob", "CORP", ntresp)); err != nil {
		t.Fatal(err)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("capture handler never called")
	}
	if got.Username != "bob" || got.Domain != "CORP" {
		t.Fatalf("captured wrong: %+v", got)
	}
	if len(got.NTResponse) != 48 {
		t.Fatalf("nt response size = %d", len(got.NTResponse))
	}
	if srv.Captured.Load() != 1 || srv.Accepted.Load() != 1 {
		t.Fatalf("counters wrong: captured=%d accepted=%d", srv.Captured.Load(), srv.Accepted.Load())
	}
}

func TestBuildChallenge(t *testing.T) {
	ch, err := BuildChallenge([]byte{9, 9, 9, 9, 9, 9, 9, 9}, "TEST")
	if err != nil {
		t.Fatal(err)
	}
	mt, _ := MessageType(ch)
	if mt != msgChallenge {
		t.Fatalf("wrong type %d", mt)
	}
	// Challenge bytes at offset 40+? Header: 8+4+16(secbuf) = 28, +4 flags = 32, challenge at 32.
	if !bytes.Equal(ch[32:40], []byte{9, 9, 9, 9, 9, 9, 9, 9}) {
		t.Fatalf("challenge wrong: %x", ch[32:40])
	}
}
