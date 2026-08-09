// Package snmp implements a minimal SNMPv1/v2c client for service
// enumeration: community-string probing, system queries and MIB walks. It is
// a read-only client (GET/GETNEXT) and never modifies managed objects.
package snmp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// BER tags used by SNMP. These are the ASN.1/BER type identifiers (the
// "tag" octet of each TLV) that structure every SNMP message.
const (
	berInteger     = 0x02 // INTEGER
	berOctetString = 0x04 // OCTET STRING
	berNull        = 0x05 // NULL
	berOID         = 0x06 // OBJECT IDENTIFIER
	berSequence    = 0x30 // SEQUENCE (constructed)
	berIpAddress   = 0x40 // IpAddress (4-byte octet string)
	berGetResp     = 0xa2 // GET-RESPONSE PDU (context-specific, constructed)
)

// OIDs commonly gathered during a system walk. All live in the
// iso(1).org(3).dod(6).internet(1).mgmt(2).mib-2(1) tree.
var (
	oidSystem      = []uint32{1, 3, 6, 1, 2, 1, 1} // system subtree
	oidSysDescr    = []uint32{1, 3, 6, 1, 2, 1, 1, 1, 0}
	oidSysUpTime   = []uint32{1, 3, 6, 1, 2, 1, 1, 3, 0}
	oidSysContact  = []uint32{1, 3, 6, 1, 2, 1, 1, 4, 0}
	oidSysName     = []uint32{1, 3, 6, 1, 2, 1, 1, 5, 0}
	oidSysLocation = []uint32{1, 3, 6, 1, 2, 1, 1, 6, 0}
	oidInterfaces  = []uint32{1, 3, 6, 1, 2, 1, 2, 2, 1, 2}  // ifDescr
	oidIPRouteNext = []uint32{1, 3, 6, 1, 2, 1, 4, 21, 1, 7} // ipRouteNextHop
)

// CommonCommunities is the ordered list of community strings tried during a
// read-only community probe. Values are the default strings shipped by the
// most common network equipment vendors.
var CommonCommunities = []string{"public", "private", "manager", "admin", "monitor", "cisco", "secret", "readonly"}

// System holds the headline values of an SNMP walk.
type System struct {
	Community string
	Descr     string
	Name      string
	Contact   string
	Location  string
	UpTime    string
	Ifaces    []string
	Routes    []string
	Walk      []*VarBind
}

// VarBind is one (OID, value) binding returned by a walk.
type VarBind struct {
	OID   string
	Value string
}

// Client is a small UDP SNMP v1/v2c client.
type Client struct {
	addr      string
	community string // community string used for requests
	timeout   time.Duration
	conn      net.Conn
	reqID     uint32 // monotonically increasing request ID
}

// Dial returns a connected SNMP client for addr (host:161).
func Dial(addr, community string, timeout time.Duration) (*Client, error) {
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(timeout))
	return &Client{addr: addr, community: community, timeout: timeout, conn: conn}, nil
}

// Close releases the socket.
func (c *Client) Close() error { return c.conn.Close() }

// Get reads the value of a single OID.
func (c *Client) Get(oid []uint32) (string, error) {
	req := c.build(0, []*VarBind{{OID: oidString(oid)}}) // 0 = GET request
	resp, err := c.roundtrip(req)
	if err != nil {
		return "", err
	}
	vbs, err := parseResponse(resp)
	if err != nil {
		return "", err
	}
	if len(vbs) == 0 {
		return "", errors.New("snmp: empty response")
	}
	return vbs[0].Value, nil
}

// ProbeCommunity checks whether community is accepted by the agent. A
// successful sysName GET means the agent answered with the given string.
func (c *Client) ProbeCommunity(community string) bool {
	old := c.community
	c.community = community
	_, err := c.Get(oidSysName)
	c.community = old
	return err == nil
}

// Walk enumerates the subtree rooted at startOID until the lexicographic
// successor leaves it, or max entries are gathered. Each iteration GETNEXTs
// the previous result, which is how a table/subtree is traversed in SNMP.
func (c *Client) Walk(start []uint32, max int) ([]*VarBind, error) {
	var out []*VarBind
	cur := append([]uint32(nil), start...)
	for i := 0; i < max; i++ {
		req := c.build(1, []*VarBind{{OID: oidString(cur)}}) // GETNEXT
		resp, err := c.roundtrip(req)
		if err != nil {
			return out, err
		}
		vbs, err := parseResponse(resp)
		if err != nil {
			return out, err
		}
		if len(vbs) == 0 {
			return out, nil
		}
		nxt := vbs[0]
		nextOID, ok := parseOIDString(nxt.OID)
		// The walk ends when the successor falls outside the start subtree
		// (SNMP servers return the next OID even when past the tree).
		if !ok || !oidInSubtree(nextOID, start) {
			return out, nil
		}
		out = append(out, nxt)
		cur = nextOID
	}
	return out, nil
}

// System gathers the headline system objects plus interface/route tables.
func (c *Client) System() (*System, error) {
	sys := &System{Community: c.community}
	get := func(oid []uint32) string {
		v, err := c.Get(oid)
		if err != nil {
			return ""
		}
		return v
	}
	sys.Descr = get(oidSysDescr)
	sys.Name = get(oidSysName)
	sys.Contact = get(oidSysContact)
	sys.Location = get(oidSysLocation)
	sys.UpTime = get(oidSysUpTime)
	if vbs, err := c.Walk(oidInterfaces, 64); err == nil {
		for _, vb := range vbs {
			sys.Ifaces = append(sys.Ifaces, vb.Value)
		}
	}
	if vbs, err := c.Walk(oidIPRouteNext, 128); err == nil {
		for _, vb := range vbs {
			sys.Routes = append(sys.Routes, vb.Value)
		}
	}
	sys.Walk, _ = c.Walk(oidSystem, 128)
	return sys, nil
}

// build assembles one SNMPv2c message: outer SEQUENCE { version, community,
// PDU }, where the PDU is 0xA0+type. pduType 0 = GET, 1 = GETNEXT.
func (c *Client) build(pduType int, vbs []*VarBind) []byte {
	c.reqID++
	// varlist SEQUENCE with a placeholder length patched in below.
	varlist := []byte{berSequence, 0, 0}
	for _, vb := range vbs {
		oid, _ := parseOIDString(vb.OID)
		enc := encodeOID(oid)
		// A var-bind is SEQUENCE { OID, NULL }; GET/GETNEXT request NULLs.
		var content []byte
		content = append(content, berLen(len(enc))...)
		content = append(content, enc...)
		content = append(content, berNull, 0)
		varlist = append(varlist, berSequence, byte(len(content)))
		varlist = append(varlist, content...)
	}
	varlist[1] = byte(len(varlist) - 2) // patch varlist length

	reqID := make([]byte, 4)
	binary.BigEndian.PutUint32(reqID, c.reqID)

	// PDU body: request-id, error-status(0), error-index(0), varbinds.
	pdu := []byte{byte(0xa0 + pduType)}
	body := []byte{berInteger, 4}
	body = append(body, reqID...)
	body = append(body, berInteger, 1, 0, berInteger, 1, 0)
	body = append(body, varlist...)
	pdu = append(pdu, berLen(len(body))...)
	pdu = append(pdu, body...)

	ver := []byte{berInteger, 1, 1} // version 1 (SNMPv2c)
	comm := []byte{berOctetString, byte(len(c.community))}
	comm = append(comm, []byte(c.community)...)

	// Outer message SEQUENCE wrapping version, community and the PDU.
	msg := []byte{berSequence}
	inner := append(ver, comm...)
	inner = append(inner, pdu...)
	msg = append(msg, berLen(len(inner))...)
	return append(msg, inner...)
}

// roundtrip sends the request datagram and waits for a single response. The
// 65535-byte buffer covers the maximum UDP datagram size.
func (c *Client) roundtrip(pkt []byte) ([]byte, error) {
	if _, err := c.conn.Write(pkt); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	n, err := c.conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// parseResponse extracts the var-bind list from a response PDU.
func parseResponse(pkt []byte) ([]*VarBind, error) {
	// Locate the PDU: the response PDU tag 0xa2 followed by its length.
	idx := indexTag(pkt, berGetResp)
	if idx < 0 {
		return nil, errors.New("snmp: no response PDU")
	}
	body, err := readTLV(pkt, idx)
	if err != nil {
		return nil, err
	}
	// body: request-id, error-status, error-index, varbind list
	pos := 0
	for i := 0; i < 3; i++ {
		_, _, n, err := parseTLV(body, pos)
		if err != nil {
			return nil, err
		}
		pos = n
	}
	if pos >= len(body) || body[pos] != berSequence {
		return nil, errors.New("snmp: bad varbind list")
	}
	vbs, _, _, err := parseVarbinds(body, pos)
	return vbs, err
}

// parseVarbinds decodes the SEQUENCE of var-binds at offset at, returning the
// bindings, the sequence's content length and its end offset.
func parseVarbinds(pkt []byte, at int) ([]*VarBind, int, int, error) {
	_, l, n, err := parseTLV(pkt, at)
	if err != nil {
		return nil, 0, 0, err
	}
	body := pkt[n : n+l]
	pos := 0
	var out []*VarBind
	for pos < len(body) {
		if body[pos] != berSequence {
			return nil, 0, 0, errors.New("snmp: malformed varbind")
		}
		// Each var-bind is SEQUENCE { OID, value }.
		_, bl, bn, err := parseTLV(body, pos)
		if err != nil {
			return nil, 0, 0, err
		}
		inner := body[bn : bn+bl]
		o, _, on, err := parseTLV(inner, 0)
		if err != nil {
			return nil, 0, 0, err
		}
		oid := parseOIDBytes(inner[on : on+o])
		val, _, err := parseValue(inner, on+o)
		if err != nil {
			return nil, 0, 0, err
		}
		out = append(out, &VarBind{OID: oidString(oid), Value: val})
		pos = bn + bl
	}
	return out, l, n, nil
}

// parseValue decodes one BER value of any known SNMP type at offset at,
// returning it as a printable string plus the end offset.
func parseValue(pkt []byte, at int) (string, int, error) {
	if at >= len(pkt) {
		return "", 0, errors.New("snmp: truncated value")
	}
	tag := pkt[at]
	switch tag {
	case berOctetString, berIpAddress:
		_, l, n, err := parseTLV(pkt, at)
		if err != nil {
			return "", 0, err
		}
		return strings.TrimSpace(string(pkt[n : n+l])), n + l, nil
	case berInteger:
		_, l, n, err := parseTLV(pkt, at)
		if err != nil {
			return "", 0, err
		}
		v, err := berInt(pkt[n : n+l])
		if err != nil {
			return "", 0, err
		}
		return fmt.Sprintf("%d", v), n + l, nil
	case berOID:
		_, l, n, err := parseTLV(pkt, at)
		if err != nil {
			return "", 0, err
		}
		return oidString(parseOIDBytes(pkt[n : n+l])), n + l, nil
	case berNull:
		// noValue: e.g. an out-of-range GETNEXT still returns a NULL binding.
		_, l, n, err := parseTLV(pkt, at)
		if err != nil {
			return "", 0, err
		}
		return "", n + l, nil
	default:
		// Unknown types are reported as "(tag)" and skipped over.
		_, l, n, err := parseTLV(pkt, at)
		if err != nil {
			return "", 0, err
		}
		return fmt.Sprintf("(%02x)", tag), n + l, nil
	}
}

// --- BER primitives ---

// berLen encodes a BER length octet (or long-form length sequence) for n.
func berLen(n int) []byte {
	if n < 128 {
		return []byte{byte(n)}
	}
	return []byte{0x80 | byte(len(intBytes(n))), intBytes(n)[0]}
}

// intBytes returns the minimal big-endian bytes needed to hold n (1-4 bytes).
func intBytes(n int) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(n))
	if n < 1<<24 {
		return b[1:]
	}
	return b[:]
}

// berInt decodes a two's-complement BER integer of any width.
func berInt(b []byte) (int64, error) {
	var v int64
	for _, x := range b {
		v = v<<8 | int64(x)
	}
	if len(b) > 0 && b[0]&0x80 != 0 {
		// negative (unexpected for SNMP counters, but keep two's-complement)
		v -= 1 << (8 * uint(len(b)))
	}
	return v, nil
}

// encodeOID encodes an OID into BER sub-identifier bytes. The first two arcs
// are packed as first*40+second, per the BER OID encoding rule.
func encodeOID(oid []uint32) []byte {
	var out []byte
	if len(oid) < 2 {
		return out
	}
	out = append(out, byte(oid[0]*40+oid[1]))
	for _, v := range oid[2:] {
		out = append(out, encodeSubID(v)...)
	}
	return out
}

// encodeSubID encodes one OID arc in base-128 with the continuation bit (0x80)
// set on every byte except the last.
func encodeSubID(v uint32) []byte {
	var rev []byte
	for {
		b := byte(v % 128)
		v /= 128
		if v > 0 {
			b |= 0x80
		}
		rev = append([]byte{b}, rev...)
		if v == 0 {
			break
		}
	}
	return rev
}

// parseOIDBytes decodes BER sub-identifier bytes back into OID arcs.
func parseOIDBytes(b []byte) []uint32 {
	var out []uint32
	if len(b) == 0 {
		return out
	}
	first := b[0]
	out = append(out, uint32(first/40), uint32(first%40))
	// Subsequent arcs accumulate 7 bits per byte; a cleared high bit marks
	// the end of an arc.
	var cur uint32
	for _, x := range b[1:] {
		cur = cur<<7 | uint32(x&0x7f)
		if x&0x80 == 0 {
			out = append(out, cur)
			cur = 0
		}
	}
	return out
}

// oidString renders an OID as the dotted-decimal form used in output.
func oidString(oid []uint32) string {
	parts := make([]string, 0, len(oid))
	for _, v := range oid {
		parts = append(parts, fmt.Sprintf("%d", v))
	}
	return strings.Join(parts, ".")
}

// parseOIDString parses a dotted-decimal OID string back into arcs.
func parseOIDString(s string) ([]uint32, bool) {
	var out []uint32
	for _, p := range strings.Split(s, ".") {
		var v uint32
		if _, err := fmt.Sscanf(p, "%d", &v); err != nil {
			return nil, false
		}
		out = append(out, v)
	}
	return out, len(out) > 0
}

// oidInSubtree reports whether oid lies within the subtree rooted at root
// (i.e. root is a prefix of oid).
func oidInSubtree(oid, root []uint32) bool {
	if len(oid) < len(root) {
		return false
	}
	for i := range root {
		if oid[i] != root[i] {
			return false
		}
	}
	return true
}

// parseTLV reads one TLV at pkt[at], returning (valueLen, valueStart,
// valueEnd). The tag byte is checked by callers. Handles both short and
// long-form BER lengths with a 4-byte cap and full bounds checking.
func parseTLV(pkt []byte, at int) (int, int, int, error) {
	if at >= len(pkt) {
		return 0, 0, 0, errors.New("ber: out of range")
	}
	// tag byte skipped; length follows
	pos := at + 1
	if pos >= len(pkt) {
		return 0, 0, 0, errors.New("ber: truncated length")
	}
	l := int(pkt[pos])
	pos++
	if l&0x80 != 0 {
		// Long form: the low 7 bits say how many length bytes follow.
		n := l & 0x7f
		// Reject indefinite (n==0) or oversized length encodings.
		if n == 0 || n > 4 || pos+n > len(pkt) {
			return 0, 0, 0, errors.New("ber: bad long length")
		}
		l = 0
		for i := 0; i < n; i++ {
			l = l<<8 | int(pkt[pos+i])
		}
		pos += n
	}
	if pos+l > len(pkt) {
		return 0, 0, 0, errors.New("ber: value overflows packet")
	}
	return l, pos, pos + l, nil
}

// readTLV returns the value bytes of the TLV at offset at.
func readTLV(pkt []byte, at int) ([]byte, error) {
	_, n, end, err := parseTLV(pkt, at)
	if err != nil {
		return nil, err
	}
	return pkt[n:end], nil
}

// indexTag finds the first occurrence of a BER tag octet in pkt. This is a
// scan rather than a walk because the PDU can be nested at any depth; the
// response tag 0xa2 is unambiguous in well-formed responses.
func indexTag(pkt []byte, tag byte) int {
	return bytes.IndexByte(pkt, tag)
}
