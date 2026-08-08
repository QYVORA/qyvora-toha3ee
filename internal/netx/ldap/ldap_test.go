package ldap

import (
	"testing"
	"time"
)

func TestFilterBytes(t *testing.T) {
	c := &Client{}
	f, err := c.filterBytes("uid=admin")
	if err != nil {
		t.Fatal(err)
	}
	if f[0] != filterEq {
		t.Errorf("expected equality filter, got 0x%02x", f[0])
	}
	if _, err := c.filterBytes("(|(a)(b))"); err == nil {
		t.Error("expected error for unsupported complex filter")
	}
}

func TestBerHelpers(t *testing.T) {
	if got := berLen(5); len(got) != 1 || got[0] != 5 {
		t.Errorf("berLen(5) = %v", got)
	}
	if got := berLen(200); len(got) != 2 || got[0] != 0x81 || got[1] != 200 {
		t.Errorf("berLen(200) = %v", got)
	}
	n, err := berLenValue(5)
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Errorf("berLenValue = %d", n)
	}
	if _, err := berLenValue(0x81); err == nil {
		t.Error("expected unsupported-length error for multibyte header")
	}
}

func TestParseTLV(t *testing.T) {
	pkt := []byte{0x04, 0x03, 'a', 'b', 'c'}
	l, n, end, err := parseTLV(pkt, 0)
	if err != nil {
		t.Fatal(err)
	}
	if l != 3 || n != 2 || end != 5 {
		t.Errorf("parseTLV = %d,%d,%d", l, n, end)
	}
	if string(pkt[n:end]) != "abc" {
		t.Errorf("value = %q", pkt[n:end])
	}
}

func TestResultCodes(t *testing.T) {
	if resultCode(49) != "invalidCredentials" {
		t.Error("bad result code mapping")
	}
}

func TestDialNoServer(t *testing.T) {
	_, err := Dial("127.0.0.1:1", "", "", 200*time.Millisecond)
	if err == nil {
		t.Error("expected error against a dead port")
	}
}
