package oui

import (
	"net"
	"testing"
)

func TestLookupKnown(t *testing.T) {
	d := New()
	cases := map[string]string{
		"3c:22:fb:12:34:56": "Apple",
		"8C:16:45:AA:BB:CC": "Intel",
		"50:c7:bf:00:00:01": "TP-Link",
		"B8:27:EB:12:34:56": "Raspberry Pi",
		"00:0c:29:12:34:56": "VMware",
		"52:54:00:12:34:56": "QEMU",
	}
	for macStr, want := range cases {
		mac, err := net.ParseMAC(macStr)
		if err != nil {
			t.Fatalf("parse %s: %v", macStr, err)
		}
		if got := d.Lookup(mac); got != want {
			t.Errorf("Lookup(%s) = %q, want %q", macStr, got, want)
		}
	}
}

func TestLookupUnknown(t *testing.T) {
	d := New()
	mac, _ := net.ParseMAC("11:22:33:44:55:66")
	if got := d.Lookup(mac); got != "" {
		t.Errorf("expected empty vendor, got %q", got)
	}
}

func TestLookupNil(t *testing.T) {
	d := New()
	if got := d.Lookup(nil); got != "" {
		t.Errorf("expected empty vendor for nil, got %q", got)
	}
}
