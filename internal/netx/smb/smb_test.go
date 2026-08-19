package smb

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// mockServer serves a fixed SMB2 negotiate response with the given security
// mode.
func mockServer(mode uint16) (addr string, close func(), err error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	done := make(chan struct{})
	stop := func() { done <- struct{}{} }
	go func() {
		defer func() { _ = ln.Close() }()
		defer stop()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		// Consume the request.
		req := make([]byte, 102)
		if _, err := readFull(conn, req); err != nil {
			return
		}
		resp := make([]byte, 64+70)
		copy(resp, protoID)
		binary.LittleEndian.PutUint16(resp[4:], 64)            // structure size
		binary.LittleEndian.PutUint16(resp[12:], cmdNegotiate) // command
		body := resp[64:]
		binary.LittleEndian.PutUint16(body[0:], 65) // structure size
		binary.LittleEndian.PutUint16(body[2:], mode)
		binary.LittleEndian.PutUint16(body[4:], dialect202)
		_, _ = conn.Write(resp)
	}()
	close = func() {
		_ = ln.Close()
		<-done
	}
	return ln.Addr().String(), close, nil
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func TestProbeSigningRequired(t *testing.T) {
	addr, close, err := mockServer(SecurityModeSigningEnabled | SecurityModeSigningRequired)
	if err != nil {
		t.Fatal(err)
	}
	defer close()

	res, err := Probe(addr, 2*time.Second)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if !res.Enabled || !res.Required {
		t.Fatalf("expected signing enabled+required, got %+v", res)
	}
	if res.Dialect != dialect202 {
		t.Fatalf("dialect = %#x", res.Dialect)
	}
}

func TestProbeSigningNotRequired(t *testing.T) {
	addr, close, err := mockServer(0)
	if err != nil {
		t.Fatal(err)
	}
	defer close()

	res, err := Probe(addr, 2*time.Second)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if res.Required {
		t.Fatal("signing should not be required")
	}
}

func TestProbeConnectionRefused(t *testing.T) {
	if _, err := Probe("127.0.0.1:1", 500*time.Millisecond); err == nil {
		t.Fatal("expected error for refused connection")
	}
}
