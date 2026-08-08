package rpc

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestXDRStringRoundtrip(t *testing.T) {
	s := "exported_dir"
	var b []byte
	b = appendStr(b, s)
	r := &xdrReader{buf: b}
	got, err := r.readString()
	if err != nil {
		t.Fatal(err)
	}
	if got != s {
		t.Errorf("got %q, want %q", got, s)
	}
}

func TestParseExportList(t *testing.T) {
	var b []byte
	b = appendU32(b, 1)
	b = appendStr(b, "/srv/data")
	b = appendU32(b, 1)
	b = appendStr(b, "10.0.0.0/8")
	b = appendU32(b, 1) // readonly true
	b = appendU32(b, 0) // fhsize
	exports, err := parseExportList(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(exports) != 1 {
		t.Fatalf("got %d exports", len(exports))
	}
	if exports[0].Dir != "/srv/data" || !exports[0].Readonly {
		t.Errorf("unexpected export %+v", exports[0])
	}
	if len(exports[0].Groups) != 1 || exports[0].Groups[0] != "10.0.0.0/8" {
		t.Errorf("unexpected groups %v", exports[0].Groups)
	}
}

func TestCallNoServer(t *testing.T) {
	_, err := Call("127.0.0.1:1", ProgPortmap, 2, 1, 6, nil, 200*time.Millisecond)
	if err == nil {
		t.Error("expected error against a dead port")
	}
}

func TestAppendPad(t *testing.T) {
	var b []byte
	b = appendU32(b, 5)
	if len(b) != 4 {
		t.Fatal("appendU32 must be 4 bytes")
	}
	marker := binary.BigEndian.Uint32(b)
	if marker != 5 {
		t.Errorf("got %d", marker)
	}
}
