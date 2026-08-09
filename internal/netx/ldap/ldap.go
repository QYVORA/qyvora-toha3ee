// Package ldap implements a minimal read-only LDAPv3 client: anonymous/simple
// binds and one-level subtree searches. It is used by the enumeration modules
// to test for unauthenticated binds and to list directory objects.
package ldap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

// LDAPMessage / protocol operation tags (application tags). The leading byte
// of each LDAP PDU's operation TLV identifies which operation it is; the tags
// are DER [APPLICATION n] constructed sequences.
const (
	opBindRequest   = 0x60 // BindRequest
	opBindResponse  = 0x61 // BindResponse
	opSearchRequest = 0x63 // SearchRequest
	opSearchResult  = 0x64 // SearchResultEntry
	opSearchDone    = 0x65 // SearchResultDone
	opUnbindRequest = 0x42 // UnbindRequest (primitive)
)

// Filter type tags. LDAP search filters are built from these ASN.1 context
// tags; [APPLICATION] tags would be the actual values used in a server.
const (
	filterAnd     = 0xa0 // and
	filterOr      = 0xa1 // or
	filterNot     = 0xa2 // not
	filterEq      = 0xa3 // equalityMatch
	filterPresent = 0x87 // present (primitive)
)

// Search scopes.
const (
	ScopeBase     = 0
	ScopeOneLevel = 1
	ScopeSubtree  = 2
)

// Client is a minimal LDAP client over TCP.
type Client struct {
	conn     net.Conn
	msgID    int    // per-connection message counter for the messageID field
	baseDN   string // DN used by bind and as the default search base
	auth     string // empty => anonymous
	password string
	rootDSE  bool
}

// Dial opens a connection and performs a bind. A nil bindDN means an
// anonymous bind. When bindDN is empty string and rootDSE is true, we skip
// the bind entirely and can still read the root DSE.
func Dial(addr, bindDN, password string, timeout time.Duration) (*Client, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	// One absolute deadline covers the whole handshake; individual operations
	// replace it with their own deadlines afterwards.
	conn.SetDeadline(time.Now().Add(timeout))
	c := &Client{conn: conn, baseDN: bindDN, password: password}
	if bindDN != "" || password != "" {
		// Only bind when credentials were supplied; an empty bindDN plus empty
		// password stays anonymous and skips the round-trip.
		if err := c.bind(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("ldap bind: %w", err)
		}
	}
	return c, nil
}

// Close closes the connection.
func (c *Client) Close() error { return c.conn.Close() }

// BindError indicates the server rejected the bind.
type BindError struct{ Result string }

// Error implements the error interface.
func (e *BindError) Error() string { return "ldap: bind rejected: " + e.Result }

// bind performs a simple bind: a BindRequest carrying the DN and an
// octet-string password as the authentication field.
func (c *Client) bind() error {
	dn := c.baseDN
	if dn == "" && c.password == "" {
		return nil // nothing to authenticate with
	}
	// AuthenticationChoice simple: context tag 0x80 followed by the password
	// as an LDAPString (octet string).
	var auth []byte
	auth = append(auth, 0x80, byte(len(c.password)))
	auth = append(auth, []byte(c.password)...)

	inner := []byte{berInteger, 1, 3} // LDAPv3 (version 3)
	inner = append(inner, 0x04, byte(len(dn)))
	inner = append(inner, []byte(dn)...)
	inner = append(inner, auth...)

	msg := c.message(opBindRequest, inner)
	if err := c.write(msg); err != nil {
		return err
	}
	resp, err := c.readMessage()
	if err != nil {
		return err
	}
	return c.parseBindResponse(resp)
}

// parseBindResponse reads the resultCode out of a BindResponse.
func (c *Client) parseBindResponse(pkt []byte) error {
	body, err := readTLV(pkt, 0)
	if err != nil {
		return err
	}
	if len(body) < 3 {
		return errors.New("ldap: truncated bind response")
	}
	// body: bindResponse tag already stripped; contents: [resultCode INTEGER]
	_, rl, rn, err := parseTLV(body, 0)
	if err != nil {
		return err
	}
	// resultCode 0 (success) means the bind was accepted.
	if rl == 1 && body[rn] == 0 {
		return nil
	}
	code, _ := berInt(body[rn : rn+rl])
	return &BindError{Result: resultCode(code)}
}

// Entry is one returned directory entry.
type Entry struct {
	DN         string
	Attributes map[string][]string
}

// Search reads entries under baseDN with the given scope. When baseDN is
// empty it reads the root DSE (which requires no bind on most servers).
func (c *Client) Search(baseDN string, scope int, filter string, timeout time.Duration) ([]*Entry, error) {
	// Replace the handshake deadline with one for this search only.
	c.conn.SetDeadline(time.Now().Add(timeout))
	f, err := c.filterBytes(filter)
	if err != nil {
		return nil, err
	}
	// SearchRequest body: baseObject, scope, derefAliases, sizeLimit,
	// timeLimit, typesOnly, filter, attributes.
	inner := []byte{0x04, byte(len(baseDN))}
	inner = append(inner, []byte(baseDN)...)
	inner = append(inner, berEnumScope(scope)...)
	inner = append(inner, berInteger, 1, 0) // derefAliases: never
	inner = append(inner, berInteger, 1, 0) // size limit: none
	inner = append(inner, berInteger, 1, 0) // time limit: none
	inner = append(inner, berBool(true)...) // typesOnly: false
	inner = append(inner, f...)
	inner = append(inner, 0x30, 0) // attributes: all (empty SEQUENCE)

	if err := c.write(c.message(opSearchRequest, inner)); err != nil {
		return nil, err
	}

	var out []*Entry
	for {
		pkt, err := c.readMessage()
		if err != nil {
			return out, err
		}
		body, err := readTLV(pkt, 0)
		if err != nil {
			return out, err
		}
		op := pkt[0]
		switch op {
		case opSearchResult:
			// One SearchResultEntry per matched object; parse and accumulate.
			e := parseSearchEntry(body)
			if e != nil {
				out = append(out, e)
			}
		case opSearchDone:
			// End of the result set.
			return out, nil
		default:
			return out, fmt.Errorf("ldap: unexpected op 0x%02x", op)
		}
	}
}

// parseSearchEntry decodes one SearchResultEntry body: objectName, then a
// SEQUENCE of PartialAttribute (type + SET OF values).
func parseSearchEntry(body []byte) *Entry {
	pos := 0
	// objectName OCTET STRING
	_, dl, dn, err := parseTLV(body, pos)
	if err != nil {
		return nil
	}
	dnVal := string(body[dn : dn+dl])
	pos = dn + dl
	if pos >= len(body) || body[pos] != berSequence {
		return nil // attributes must be a SEQUENCE
	}
	_, al, an, err := parseTLV(body, pos)
	if err != nil {
		return nil
	}
	attrs := body[an : an+al]
	e := &Entry{DN: dnVal, Attributes: map[string][]string{}}
	apos := 0
	for apos < len(attrs) {
		if attrs[apos] != berSequence {
			break // attribute is not a SEQUENCE; stop parsing
		}
		_, bl, bn, err := parseTLV(attrs, apos)
		if err != nil {
			break
		}
		at := attrs[bn : bn+bl]
		var o, vn int
		if len(at) > 0 {
			// First element is the attribute type (OCTET STRING).
			_, o, vn, err = parseTLV(at, 0)
			if err != nil {
				break
			}
		}
		name := string(at[vn : vn+o])
		var values []string
		vpos := vn + o
		for vpos < len(at) {
			if at[vpos] != 0x31 { // set
				break
			}
			_, sl, sn, err := parseTLV(at, vpos)
			if err != nil {
				break
			}
			sv := at[sn : sn+sl]
			spos := 0
			for spos < len(sv) {
				if sv[spos] != 0x04 {
					break
				}
				_, il, in, err := parseTLV(sv, spos)
				if err != nil {
					break
				}
				values = append(values, string(sv[in:in+il]))
				spos = in + il
			}
			vpos = sn + sl
		}
		e.Attributes[name] = values
		apos = bn + bl
	}
	return e
}

// filterBytes turns the simple "attr=value" filter syntax into an ASN.1
// equalityMatch filter. An empty filter becomes a present (objectClass=*)
// filter, matching every entry.
func (c *Client) filterBytes(f string) ([]byte, error) {
	if f == "" {
		return []byte{filterPresent, 1, 0x04, 0}, nil // objectClass=* present filter
	}
	// Support simple "attr=value" equality filters; anything else is rejected.
	eq := bytes.IndexByte([]byte(f), '=')
	if eq < 1 {
		return nil, fmt.Errorf("ldap: unsupported filter %q", f)
	}
	attr := []byte(f[:eq])
	val := []byte(f[eq+1:])
	// Equality filter content: assertionValue OCTET STRING, then the
	// "matchingValue" OCTET STRING — actually two octet strings.
	content := []byte{0x04, byte(len(attr))}
	content = append(content, attr...)
	content = append(content, 0x04, byte(len(val)))
	content = append(content, val...)
	out := []byte{filterEq}
	out = append(out, berLen(len(content))...)
	return append(out, content...), nil
}

// message wraps an operation in an LDAPMessage envelope: SEQUENCE of
// [messageID INTEGER, op TLV]. messageID is monotonically incremented per
// call so a client can match responses to requests.
func (c *Client) message(op byte, inner []byte) []byte {
	c.msgID++
	mid := make([]byte, 2)
	binary.BigEndian.PutUint16(mid, uint16(c.msgID))
	// The messageID must be a positive INTEGER; only the low byte is used for
	// the realistic range of message counts in a session.
	id := []byte{berInteger, 1, mid[1]}
	msg := []byte{berSequence}
	content := append(id, op)
	content = append(content, berLen(len(inner))...)
	content = append(content, inner...)
	msg = append(msg, berLen(len(content))...)
	return append(msg, content...)
}

// write sends one whole message on the wire.
func (c *Client) write(pkt []byte) error {
	_, err := c.conn.Write(pkt)
	return err
}

// readMessage reads one LDAPMessage and returns the operation TLV, with the
// messageID INTEGER already skipped.
func (c *Client) readMessage() ([]byte, error) {
	var tag [1]byte
	if _, err := readFull(c.conn, tag[:]); err != nil {
		return nil, err
	}
	if tag[0] != berSequence {
		return nil, errors.New("ldap: not an LDAP message")
	}
	ln, err := readLen(c.conn)
	if err != nil {
		return nil, err
	}
	// 4 MiB cap bounds memory use against a malicious server.
	if ln > 4<<20 {
		return nil, errors.New("ldap: oversized message")
	}
	body := make([]byte, ln)
	if _, err := readFull(c.conn, body); err != nil {
		return nil, err
	}
	// Skip the messageID INTEGER; the operation TLV follows.
	_, _, n, err := parseTLV(body, 0)
	if err != nil {
		return nil, err
	}
	if n >= len(body) {
		return nil, errors.New("ldap: no operation in message")
	}
	return body[n:], nil
}

// readLen reads a BER length field from the connection. Short form (high bit
// clear) is a single byte; long form is 1-4 length bytes in big-endian order.
func readLen(conn net.Conn) (int, error) {
	var b [1]byte
	if _, err := readFull(conn, b[:]); err != nil {
		return 0, err
	}
	if b[0]&0x80 == 0 {
		return int(b[0]), nil
	}
	n := int(b[0] & 0x7f)
	if n == 0 || n > 4 {
		return 0, errors.New("ldap: unsupported length encoding")
	}
	buf := make([]byte, n)
	if _, err := readFull(conn, buf); err != nil {
		return 0, err
	}
	var l int
	for _, x := range buf {
		l = l<<8 | int(x)
	}
	return l, nil
}

// --- shared BER helpers (kept local to avoid an extra dependency) ---

// Universal BER tag constants used across every message.
const (
	berInteger  = 0x02
	berOctetStr = 0x04
	berNull     = 0x05
	berSequence = 0x30
)

// berEnumScope encodes the search scope as an ENUMERATED value.
func berEnumScope(scope int) []byte {
	switch scope {
	case ScopeOneLevel:
		return []byte{0x0a, 1, 1}
	case ScopeSubtree:
		return []byte{0x0a, 1, 2}
	default:
		return []byte{0x0a, 1, 0}
	}
}

// berBool encodes a BOOLEAN value (0xff for true, 0x00 for false).
func berBool(b bool) []byte {
	if b {
		return []byte{0x01, 1, 0xff}
	}
	return []byte{0x01, 1, 0x00}
}

// berLen writes a BER length field. Values below 128 use the short form; the
// few messages this client emits never exceed 255 bytes, so the long form is
// a single 0x81-prefixed byte.
func berLen(n int) []byte {
	if n < 128 {
		return []byte{byte(n)}
	}
	return []byte{0x81, byte(n)}
}

// berLenValue decodes a single-byte short-form BER length.
func berLenValue(b byte) (int, error) {
	if b&0x80 == 0 {
		return int(b), nil
	}
	return 0, errors.New("ldap: unsupported length encoding")
}

// parseTLV reads one TLV starting at at and returns (length, dataStart,
// dataEnd, error). Long-form lengths are handled with a 4-byte cap.
func parseTLV(pkt []byte, at int) (int, int, int, error) {
	if at >= len(pkt) {
		return 0, 0, 0, errors.New("ber: out of range")
	}
	pos := at + 1
	if pos >= len(pkt) {
		return 0, 0, 0, errors.New("ber: truncated")
	}
	l := int(pkt[pos])
	pos++
	if l&0x80 != 0 {
		// Long form: the low 7 bits count the length bytes that follow.
		n := l & 0x7f
		if n > 4 || pos+n > len(pkt) {
			return 0, 0, 0, errors.New("ber: bad length")
		}
		l = 0
		for i := 0; i < n; i++ {
			l = l<<8 | int(pkt[pos+i])
		}
		pos += n
	}
	if pos+l > len(pkt) {
		return 0, 0, 0, errors.New("ber: overflow")
	}
	return l, pos, pos + l, nil
}

// readTLV parses one TLV and returns its value bytes.
func readTLV(pkt []byte, at int) ([]byte, error) {
	_, n, end, err := parseTLV(pkt, at)
	if err != nil {
		return nil, err
	}
	return pkt[n:end], nil
}

// berInt decodes a BER INTEGER value as big-endian bytes.
func berInt(b []byte) (int64, error) {
	var v int64
	for _, x := range b {
		v = v<<8 | int64(x)
	}
	return v, nil
}

// readFull reads until buf is filled, tolerating short reads from TCP.
func readFull(conn net.Conn, buf []byte) (int, error) {
	n, err := conn.Read(buf)
	if err != nil {
		return n, err
	}
	for n < len(buf) {
		m, err := conn.Read(buf[n:])
		if err != nil {
			return n, err
		}
		n += m
	}
	return n, nil
}

// resultCode maps an LDAP resultCode integer to its RFC 4511 name.
func resultCode(code int64) string {
	switch code {
	case 0:
		return "success"
	case 1:
		return "operationsError"
	case 2:
		return "protocolError"
	case 49:
		return "invalidCredentials"
	case 50:
		return "insufficientAccess"
	case 53:
		return "unwillingToPerform"
	case 32:
		return "noSuchObject"
	default:
		return fmt.Sprintf("code %d", code)
	}
}
