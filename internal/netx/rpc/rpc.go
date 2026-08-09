// Package rpc implements the minimal ONC RPC client primitives (XDR wire
// format plus a call/response cycle) needed by the NFS enumeration module:
// rpcbind lookups, MOUNTv3 export listing and NFS NULL probes. It is
// read-only.
package rpc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Well-known programs. RPC program numbers are registered in the IANA rpcbind
// namespace; each program implements several versions and procedures.
const (
	ProgPortmap  = 100000 // rpcbind / portmapper
	ProgMount    = 100005 // MOUNT protocol (export listing)
	ProgNFS      = 100003 // NFS file service
	ProgNFSMount = 100005 // alias of the MOUNT program
)

// Message types and reply stats. These are the XDR enum values in the RPC
// reply header: msg_type, then reply_stat/accept_stat.
const (
	msgCall        = 0 // message is a call
	msgReply       = 1 // message is a reply
	replyAccepted  = 0 // MSG_ACCEPTED: the call was accepted
	authNone       = 0 // AUTH_NONE: no credentials
	portmapGetPort = 1 // PMAPPROC_GETPORT
	mountExport    = 1 // MOUNTPROC_EXPORT
)

// Call performs an ONC RPC call to prog/vers/proc at addr, sending args and
// returning the raw accepted-reply payload. prot selects tcp(6)/udp(17).
func Call(addr string, prog, vers, proc uint32, prot int, args []byte, timeout time.Duration) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	return callConn(conn, prog, vers, proc, args)
}

// callConn performs the call/response cycle over an open connection. RPC over
// TCP is framed with the record-marking protocol: each record is prefixed by
// a 4-byte big-endian marker whose high bit signals "last fragment" and whose
// low 31 bits carry the fragment length.
func callConn(conn net.Conn, prog, vers, proc uint32, args []byte) ([]byte, error) {
	// RPC record marker: 0x80000000 | len (last fragment).
	pkt := buildCall(prog, vers, proc, args)
	record := make([]byte, 4)
	binary.BigEndian.PutUint32(record, 0x80000000|uint32(len(pkt)))
	if _, err := conn.Write(append(record, pkt...)); err != nil {
		return nil, err
	}

	// Read the reply's record marker: high bit = last fragment, low 31 bits
	// = length of the following record bytes.
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return nil, err
	}
	marker := binary.BigEndian.Uint32(head)
	blen := int(marker & 0x7fffffff)
	// Cap the accepted record size so a hostile server cannot make us buffer
	// an unbounded reply.
	if blen > 1<<20 {
		return nil, errors.New("rpc: response too large")
	}
	body := make([]byte, blen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}

	// Reply header: xid(4) + msg_type(4) + reply_stat(4) + verf
	// {flavor(4), body_len(4)} + accept_stat(4) = 28 bytes.
	if len(body) < 28 {
		return nil, errors.New("rpc: truncated reply")
	}
	xid, msgType := binary.BigEndian.Uint32(body[0:4]), binary.BigEndian.Uint32(body[4:8])
	if msgType != msgReply {
		return nil, fmt.Errorf("rpc: unexpected message type %d (xid %08x)", msgType, xid)
	}
	// reply_stat, verf (auth_flavor + body), accept_stat, then payload.
	accept := binary.BigEndian.Uint32(body[24:28])
	if accept != replyAccepted {
		return nil, fmt.Errorf("rpc: procedure not accepted (status %d)", accept)
	}
	rest := body[28:]
	// Skip the program-specific filler/void fields by returning raw payload;
	// callers parse what they need from the record.
	return rest, nil
}

// buildCall assembles a record-marked RPC call message in XDR encoding. The
// argument area after the fixed header is left to the caller's args.
func buildCall(prog, vers, proc uint32, args []byte) []byte {
	// xid, msg_type, rpcvers, prog, vers, proc, cred, verf, args
	var b []byte
	b = appendU32(b, 0x10000000) // xid (arbitrary; not matched by our parser)
	b = appendU32(b, msgCall)
	b = appendU32(b, 2) // rpcvers (RPC version 2)
	b = appendU32(b, prog)
	b = appendU32(b, vers)
	b = appendU32(b, proc)
	b = appendU32(b, authNone) // cred flavor
	b = appendU32(b, 0)        // cred body length
	b = appendU32(b, authNone) // verf flavor
	b = appendU32(b, 0)        // verf body length
	return append(b, args...)
}

// appendU32 appends one big-endian XDR uint32.
func appendU32(b []byte, v uint32) []byte {
	var t [4]byte
	binary.BigEndian.PutUint32(t[:], v)
	return append(b, t[:]...)
}

// appendStr appends an XDR string: a length-prefix followed by the bytes,
// padded to a 4-byte boundary.
func appendStr(b []byte, s string) []byte {
	b = appendU32(b, uint32(len(s)))
	b = append(b, []byte(s)...)
	return pad4(b)
}

// pad4 appends zero bytes until the buffer length is a multiple of 4 (XDR
// alignment).
func pad4(b []byte) []byte {
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

// PortMapGetPort asks rpcbind on host:port for the port of prog/vers on the
// given protocol (6=tcp, 17=udp). The PMAPPROC_GETPORT argument is the XDR
// mapping {prog, vers, prot, port}; port 0 means "report the registered port".
func PortMapGetPort(host string, prog, vers uint32, prot int, timeout time.Duration) (uint32, error) {
	var args []byte
	args = appendU32(args, prog)
	args = appendU32(args, vers)
	args = appendU32(args, uint32(prot))
	args = appendU32(args, 0)
	raw, err := Call(net.JoinHostPort(host, "111"), ProgPortmap, 2, portmapGetPort, prot, args, timeout)
	if err != nil {
		return 0, err
	}
	// The reply is a single XDR uint32: the transport port for the service.
	if len(raw) < 4 {
		return 0, errors.New("rpc: short getport reply")
	}
	return binary.BigEndian.Uint32(raw[0:4]), nil
}

// MountExport is one exported share.
type MountExport struct {
	Dir      string
	Groups   []string
	Readonly bool
}

// MountExports lists NFSv3 exports via the MOUNT protocol. addr is the mountd
// endpoint (use PortMapGetPort to discover it, or default 111/2049 probes).
func MountExports(addr string, timeout time.Duration) ([]*MountExport, error) {
	// MOUNTPROC3_EXPORT has no arguments.
	raw, err := Call(addr, ProgMount, 3, mountExport, 6, nil, timeout)
	if err != nil {
		return nil, err
	}
	return parseExportList(raw)
}

// parseExportList decodes the XDR exportlist returned by MOUNTPROC3_EXPORT:
// {n_exports, <exportnode>[]} where each node is dirpath string, groups< >,
// readonly bool, then v3-only fields we skip.
func parseExportList(raw []byte) ([]*MountExport, error) {
	// Reply: exportnode {
	//   dirpath export; groups< >; ... opaque-ish for v3:
	//   dirpath string, groups array, readonly bool, flags, mount options
	// }
	var out []*MountExport
	r := &xdrReader{buf: raw}
	n, err := r.readU32()
	if err != nil {
		return nil, err
	}
	// Bounds check against a nonsense count from a misbehaving server.
	if n > 1024 {
		return nil, errors.New("rpc: implausible export count")
	}
	for i := uint32(0); i < n; i++ {
		dir, err := r.readString()
		if err != nil {
			return nil, err
		}
		groups, err := r.readStringArray()
		if err != nil {
			return nil, err
		}
		readonly, err := r.readBool()
		if err != nil {
			return nil, err
		}
		if err := r.skip(4); err != nil { // fhsize (v3)
			return nil, err
		}
		out = append(out, &MountExport{Dir: dir, Groups: groups, Readonly: readonly})
	}
	return out, nil
}

// NFSNullProbe checks whether an NFS service answers the NULL procedure on
// addr (usually :2049). Procedure 0 always succeeds on a live RPC endpoint,
// so any accepted reply proves the service is up.
func NFSNullProbe(addr string, vers uint32, timeout time.Duration) error {
	_, err := Call(addr, ProgNFS, vers, 0, 6, nil, timeout)
	return err
}

// xdrReader is a cursor over a byte slice enforcing XDR (big-endian) reads
// with bounds checks on every access.
type xdrReader struct {
	buf []byte
	pos int
}

// readU32 reads the next big-endian uint32 and advances the cursor.
func (r *xdrReader) readU32() (uint32, error) {
	if r.pos+4 > len(r.buf) {
		return 0, errors.New("xdr: short read")
	}
	v := binary.BigEndian.Uint32(r.buf[r.pos : r.pos+4])
	r.pos += 4
	return v, nil
}

// readBool reads an XDR boolean (0 = false, nonzero = true).
func (r *xdrReader) readBool() (bool, error) {
	v, err := r.readU32()
	return v != 0, err
}

// readString reads an XDR string: a uint32 length, the bytes, then skipping
// any padding to the next 4-byte boundary.
func (r *xdrReader) readString() (string, error) {
	n, err := r.readU32()
	if err != nil {
		return "", err
	}
	// Reject absurd lengths before doing arithmetic on them.
	if n > 1<<20 {
		return "", errors.New("xdr: string too large")
	}
	// Padded XDR size: round n up to a multiple of 4.
	bytes := n + (4-n%4)%4
	if r.pos+int(bytes) > len(r.buf) {
		return "", errors.New("xdr: string overflow")
	}
	s := string(r.buf[r.pos : r.pos+int(n)])
	r.pos += int(bytes)
	return s, nil
}

// readStringArray reads an XDR array of strings: a count then that many
// strings.
func (r *xdrReader) readStringArray() ([]string, error) {
	n, err := r.readU32()
	if err != nil {
		return nil, err
	}
	if n > 1024 {
		return nil, errors.New("xdr: array too large")
	}
	var out []string
	for i := uint32(0); i < n; i++ {
		s, err := r.readString()
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// skip advances the cursor n bytes (used to pass over fields we do not care
// about, like the v3 filehandle size).
func (r *xdrReader) skip(n int) error {
	if r.pos+n > len(r.buf) {
		return errors.New("xdr: skip overflow")
	}
	r.pos += n
	return nil
}
