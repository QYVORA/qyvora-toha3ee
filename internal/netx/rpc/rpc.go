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

// Well-known programs.
const (
	ProgPortmap  = 100000
	ProgMount    = 100005
	ProgNFS      = 100003
	ProgNFSMount = 100005
)

// Message types and reply stats.
const (
	msgCall        = 0
	msgReply       = 1
	replyAccepted  = 0
	authNone       = 0
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

func callConn(conn net.Conn, prog, vers, proc uint32, args []byte) ([]byte, error) {
	// RPC record marker: 0x80000000 | len (last fragment).
	pkt := buildCall(prog, vers, proc, args)
	record := make([]byte, 4)
	binary.BigEndian.PutUint32(record, 0x80000000|uint32(len(pkt)))
	if _, err := conn.Write(append(record, pkt...)); err != nil {
		return nil, err
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return nil, err
	}
	marker := binary.BigEndian.Uint32(head)
	blen := int(marker & 0x7fffffff)
	if blen > 1<<20 {
		return nil, errors.New("rpc: response too large")
	}
	body := make([]byte, blen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}

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

func buildCall(prog, vers, proc uint32, args []byte) []byte {
	// xid, msg_type, rpcvers, prog, vers, proc, cred, verf, args
	var b []byte
	b = appendU32(b, 0x10000000) // xid (arbitrary)
	b = appendU32(b, msgCall)
	b = appendU32(b, 2) // rpcvers
	b = appendU32(b, prog)
	b = appendU32(b, vers)
	b = appendU32(b, proc)
	b = appendU32(b, authNone) // cred flavor
	b = appendU32(b, 0)        // cred body length
	b = appendU32(b, authNone) // verf flavor
	b = appendU32(b, 0)        // verf body length
	return append(b, args...)
}

func appendU32(b []byte, v uint32) []byte {
	var t [4]byte
	binary.BigEndian.PutUint32(t[:], v)
	return append(b, t[:]...)
}

func appendStr(b []byte, s string) []byte {
	b = appendU32(b, uint32(len(s)))
	b = append(b, []byte(s)...)
	return pad4(b)
}

func pad4(b []byte) []byte {
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

// PortMapGetPort asks rpcbind on host:port for the port of prog/vers on the
// given protocol (6=tcp, 17=udp).
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
// addr (usually :2049).
func NFSNullProbe(addr string, vers uint32, timeout time.Duration) error {
	_, err := Call(addr, ProgNFS, vers, 0, 6, nil, timeout)
	return err
}

type xdrReader struct {
	buf []byte
	pos int
}

func (r *xdrReader) readU32() (uint32, error) {
	if r.pos+4 > len(r.buf) {
		return 0, errors.New("xdr: short read")
	}
	v := binary.BigEndian.Uint32(r.buf[r.pos : r.pos+4])
	r.pos += 4
	return v, nil
}

func (r *xdrReader) readBool() (bool, error) {
	v, err := r.readU32()
	return v != 0, err
}

func (r *xdrReader) readString() (string, error) {
	n, err := r.readU32()
	if err != nil {
		return "", err
	}
	if n > 1<<20 {
		return "", errors.New("xdr: string too large")
	}
	bytes := n + (4-n%4)%4
	if r.pos+int(bytes) > len(r.buf) {
		return "", errors.New("xdr: string overflow")
	}
	s := string(r.buf[r.pos : r.pos+int(n)])
	r.pos += int(bytes)
	return s, nil
}

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

func (r *xdrReader) skip(n int) error {
	if r.pos+n > len(r.buf) {
		return errors.New("xdr: skip overflow")
	}
	r.pos += n
	return nil
}
