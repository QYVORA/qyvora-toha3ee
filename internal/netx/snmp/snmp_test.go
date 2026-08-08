package snmp

import (
	"testing"
	"time"
)

func TestEncodeDecodeOID(t *testing.T) {
	oid := []uint32{1, 3, 6, 1, 2, 1, 1, 1, 0}
	enc := encodeOID(oid)
	dec := parseOIDBytes(enc)
	if len(dec) != len(oid) {
		t.Fatalf("roundtrip len %d != %d (%v)", len(dec), len(oid), dec)
	}
	for i := range oid {
		if dec[i] != oid[i] {
			t.Errorf("oid[%d] = %d, want %d", i, dec[i], oid[i])
		}
	}
}

func TestEncodeSubID(t *testing.T) {
	cases := []uint32{0, 1, 127, 128, 255, 256, 12345, 268435455}
	for _, v := range cases {
		enc := encodeSubID(v)
		var got uint32
		for _, b := range enc {
			got = got<<7 | uint32(b&0x7f)
			if b&0x80 != 0 {
				continue
			}
		}
		if got != v {
			t.Errorf("subid %d encoded %v decoded %d", v, enc, got)
		}
	}
}

func TestBerInt(t *testing.T) {
	v, err := berInt([]byte{0x02})
	if err != nil {
		t.Fatal(err)
	}
	if v != 2 {
		t.Errorf("got %d", v)
	}
}

func TestOidInSubtree(t *testing.T) {
	root := []uint32{1, 3, 6, 1, 2, 1, 1}
	if !oidInSubtree([]uint32{1, 3, 6, 1, 2, 1, 1, 1, 0}, root) {
		t.Error("expected subtree match")
	}
	if oidInSubtree([]uint32{1, 3, 6, 1, 2, 1, 2}, root) {
		t.Error("expected no match")
	}
}

func TestDialNoServer(t *testing.T) {
	c, err := Dial("127.0.0.1:9", "public", 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Get(oidSysName); err == nil {
		t.Error("expected error against a dead port")
	}
}
