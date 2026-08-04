// Package smb implements the minimal SMB2 client primitives needed by the
// framework's service-authentication modules.
package smb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// SMB2 command codes.
const (
	cmdNegotiate = 0x0000
)

// Security mode flags from the negotiate response.
const (
	SecurityModeSigningEnabled  = 0x0001
	SecurityModeSigningRequired = 0x0002
)

// Dialect we negotiate: SMB 2.0.2.
const dialect202 = 0x0202

var protoID = []byte{0xfe, 'S', 'M', 'B'}

// SigningResult is the outcome of an SMB signing probe.
type SigningResult struct {
	Dialect uint16
	// Enabled is true when the server advertises message signing as a
	// capability (signatures may be absent but are accepted).
	Enabled bool
	// Required is true when the server refuses unsigned connections, which
	// defeats pass-the-hash/relay-style downgrade attacks.
	Required bool
}

// Dial is the connection dialer used by Probe. Replaced in tests.
var Dial = func(addr string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("tcp", addr, timeout)
}

// Probe negotiates SMB2 against addr and reports the server's signing policy.
func Probe(addr string, timeout time.Duration) (*SigningResult, error) {
	conn, err := Dial(addr, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(buildNegotiate()); err != nil {
		return nil, err
	}
	resp, err := readResponse(conn)
	if err != nil {
		return nil, err
	}
	return parseNegotiateResponse(resp)
}

// buildNegotiate assembles an SMB2 NEGOTIATE request for dialect 2.0.2.
func buildNegotiate() []byte {
	buf := make([]byte, 64+38)
	copy(buf, protoID)
	le := binary.LittleEndian
	le.PutUint16(buf[4:], 64)            // structure size
	le.PutUint16(buf[12:], cmdNegotiate) // command
	le.PutUint16(buf[14:], 1)            // credit request
	le.PutUint64(buf[24:], 1)            // message id

	body := buf[64:]
	le.PutUint16(body[0:], 36)          // structure size
	le.PutUint16(body[2:], 1)           // dialect count
	le.PutUint16(body[4:], 0)           // security mode
	le.PutUint16(body[36:], dialect202) // dialect list
	return buf
}

// readResponse reads a full SMB2 header plus body from the connection. The
// body length is taken from the protocol structure size, capped to keep the
// reader bounded.
func readResponse(conn net.Conn) ([]byte, error) {
	head := make([]byte, 64)
	if _, err := io.ReadFull(conn, head); err != nil {
		return nil, err
	}
	if !bytes.Equal(head[:4], protoID) {
		return nil, errors.New("smb: not an SMB2 response")
	}
	if binary.LittleEndian.Uint16(head[12:]) != cmdNegotiate {
		return nil, fmt.Errorf("smb: unexpected command 0x%04x", binary.LittleEndian.Uint16(head[12:]))
	}
	bodyLen := int(binary.LittleEndian.Uint16(head[4:]))
	if bodyLen > 4096 {
		bodyLen = 4096
	}
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	return append(head, body...), nil
}

// parseNegotiateResponse extracts the signing policy from an SMB2 NEGOTIATE
// response.
func parseNegotiateResponse(pkt []byte) (*SigningResult, error) {
	if len(pkt) < 70 {
		return nil, errors.New("smb: truncated negotiate response")
	}
	if !bytes.Equal(pkt[:4], protoID) {
		return nil, errors.New("smb: bad protocol id")
	}
	// Header ends at 64; body[0:2] structure size, body[2:4] security mode.
	mode := binary.LittleEndian.Uint16(pkt[66:68])
	dialect := binary.LittleEndian.Uint16(pkt[68:70])
	return &SigningResult{
		Dialect:  dialect,
		Enabled:  mode&SecurityModeSigningEnabled != 0,
		Required: mode&SecurityModeSigningRequired != 0,
	}, nil
}
