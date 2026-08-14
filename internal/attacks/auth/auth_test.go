package auth

import (
	"bytes"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/QYVORA/qyvora-toha3ee/internal/attacks"
	"github.com/QYVORA/qyvora-toha3ee/internal/config"
	"github.com/QYVORA/qyvora-toha3ee/internal/events"
	"github.com/QYVORA/qyvora-toha3ee/internal/netx/ntlm"
	"github.com/QYVORA/qyvora-toha3ee/internal/safety"
	"github.com/QYVORA/qyvora-toha3ee/internal/store"
)

var ntlmSig = []byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0}

// buildType3 assembles a minimal NTLM authenticate message for testing.
func buildType3(username, domain string, ntresp []byte) []byte {
	payloadOff := 76
	buf := make([]byte, 0, 4096)
	buf = append(buf, ntlmSig...)
	var mtype [4]byte
	binary.LittleEndian.PutUint32(mtype[:], 3)
	buf = append(buf, mtype[:]...)
	secBase := len(buf)
	buf = append(buf, make([]byte, 48)...)
	var fl [4]byte
	binary.LittleEndian.PutUint32(fl[:], 1|0x200)
	buf = append(buf, fl[:]...)
	buf = append(buf, make([]byte, 12)...)

	offset := uint32(payloadOff)
	appendPayload := func(data []byte) uint32 {
		if data == nil {
			return 0
		}
		off := offset
		buf = append(buf, data...)
		offset += uint32(len(data))
		return off
	}
	appendPayload(nil)
	ntOff := appendPayload(ntresp)
	domOff := appendPayload([]byte(domain))
	userOff := appendPayload([]byte(username))
	appendPayload(nil)
	appendPayload(nil)

	write := func(at int, data []byte, off uint32) {
		binary.LittleEndian.PutUint16(buf[at:], uint16(len(data)))
		binary.LittleEndian.PutUint16(buf[at+2:], uint16(len(data)))
		binary.LittleEndian.PutUint32(buf[at+4:], off)
	}
	write(secBase, nil, 0)
	write(secBase+8, ntresp, ntOff)
	write(secBase+16, []byte(domain), domOff)
	write(secBase+24, []byte(username), userOff)
	write(secBase+32, nil, 0)
	write(secBase+40, nil, 0)
	return buf
}

func testCtx(db *store.Store) (*attacks.AttackCtx, chan struct{}) {
	done := make(chan struct{})
	return &attacks.AttackCtx{
		ID:      "test",
		Bus:     events.NewBus(),
		Conf:    config.Default(),
		Store:   db,
		Safety:  safety.NewManager(events.NewBus(), slog.New(slog.NewTextHandler(io.Discard, nil))),
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Out:     io.Discard,
		Done:    done,
		State:   &sync.Map{},
		Targets: nil,
	}, done
}

func hostWithPort(ip string, port uint16) *store.Host {
	h := &store.Host{IP: net.ParseIP(ip)}
	h.SetPort(port, "http")
	return h
}

func TestDefaultCredsFindsDefault(t *testing.T) {
	// Backend that accepts admin/admin via basic auth.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if ok && user == "admin" && pass == "admin" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="router"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	addr := srv.Listener.Addr().(*net.TCPAddr)

	db := store.New(100)
	h := hostWithPort("127.0.0.1", uint16(addr.Port))
	db.UpsertHost(h)
	ctx, _ := testCtx(db)
	ctx.Conf.Settings["default.creds"] = map[string]string{"ports": strconv.Itoa(addr.Port)}

	m := &DefaultCreds{}
	if err := m.Run(ctx, nil); err != nil {
		t.Fatalf("run: %v", err)
	}
	creds := db.CredsBySource("default.creds")
	if len(creds) != 1 {
		t.Fatalf("expected 1 cred, got %d (%+v)", len(creds), creds)
	}
	if creds[0].Username != "admin" || creds[0].Password != "admin" {
		t.Fatalf("wrong cred: %+v", creds[0])
	}
	imp, err := m.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if imp.Summary == "" {
		t.Fatal("empty impact")
	}
}

func TestDefaultCredsRejectsWrong(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="router"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	addr := srv.Listener.Addr().(*net.TCPAddr)

	db := store.New(100)
	db.UpsertHost(hostWithPort("127.0.0.1", uint16(addr.Port)))
	ctx, _ := testCtx(db)
	ctx.Conf.Settings["default.creds"] = map[string]string{"ports": strconv.Itoa(addr.Port)}

	m := &DefaultCreds{}
	if err := m.Run(ctx, nil); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(db.CredsBySource("default.creds")) != 0 {
		t.Fatal("unexpected cred captured")
	}
}

func TestSMBProbeModule(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		req := make([]byte, 102)
		for i := range req {
			if _, err := conn.Read(req[i : i+1]); err != nil {
				return
			}
		}
		// 65-byte negotiate response body with signing not required.
		resp := make([]byte, 64+65)
		copy(resp, []byte{0xfe, 'S', 'M', 'B'})
		resp[4], resp[5] = 64, 0
		resp[12], resp[13] = 0, 0
		resp[64], resp[65] = 65, 0 // structure size, security mode (0)
		conn.Write(resp)
	}()

	db := store.New(100)
	host := &store.Host{IP: net.ParseIP("127.0.0.1")}
	host.SetPort(445, "netbios-ssn")
	db.UpsertHost(host)
	ctx, _ := testCtx(db)
	ctx.Conf.Settings["smb.signing"] = map[string]string{"port": strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)}

	m := &SMBSigning{}
	if err := m.Run(ctx, nil); err != nil {
		t.Fatalf("run: %v", err)
	}
	v, _ := ctx.GetState("smb.signing")
	res, _ := v.(map[string]bool)
	if res["127.0.0.1"] {
		t.Fatalf("expected signing NOT required (relayable), got %v", res)
	}
	imp, err := m.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if imp.Metrics["relayable"] != "1" {
		t.Fatalf("impact: %+v", imp)
	}
}

func TestNTLMRelayCapture(t *testing.T) {
	db := store.New(100)
	ctx, done := testCtx(db)
	ctx.Conf.Settings["ntlm.relay"] = map[string]string{"port": "0"}

	m := &NTLMRelay{}
	errCh := make(chan error, 1)
	go func() { errCh <- m.Run(ctx, nil) }()
	defer func() {
		close(done)
		select {
		case <-errCh:
		case <-time.After(5 * time.Second):
			t.Error("module did not stop")
		}
	}()

	// Wait for the capture server to bind.
	var srv *ntlm.Server
	for i := 0; i < 200; i++ {
		if v, ok := ctx.GetState("ntlm.relay"); ok {
			srv = v.(*ntlm.Server)
			if srv != nil && srv.Addr() != nil {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if srv == nil || srv.Addr() == nil {
		t.Fatal("capture server never came up")
	}

	conn, err := net.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// NTLM type 1 negotiate.
	t1 := append([]byte{}, ntlmSig...)
	t1 = append(t1, 1, 0, 0, 0)
	t1 = append(t1, make([]byte, 36)...)
	if _, err := conn.Write(t1); err != nil {
		t.Fatal(err)
	}
	// Read the type 2 challenge.
	read := make([]byte, 256)
	if _, err := conn.Read(read); err != nil {
		t.Fatalf("read challenge: %v", err)
	}

	// Send type 3 authenticate with a fake NTLMv2 response.
	ntresp := bytes.Repeat([]byte{0xde}, 48)
	if _, err := conn.Write(buildType3("carol", "CORP", ntresp)); err != nil {
		t.Fatal(err)
	}

	// Wait for the store to record the hash.
	for i := 0; i < 200; i++ {
		if len(db.CredsBySource("ntlm.relay")) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	creds := db.CredsBySource("ntlm.relay")
	if len(creds) != 1 {
		t.Fatalf("expected 1 cred, got %d", len(creds))
	}
	if creds[0].Username != "carol" || creds[0].Password != hex(bytes.Repeat([]byte{0xde}, 48)) {
		t.Fatalf("wrong cred: %+v", creds[0])
	}
	imp, err := m.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if imp.Metrics["captured"] != "1" {
		t.Fatalf("impact: %+v", imp)
	}
}
