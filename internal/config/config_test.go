package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadMissingReturnsDefault(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Iface != "eth0" {
		t.Fatalf("expected default iface, got %q", cfg.Iface)
	}
	if cfg.Settings == nil {
		t.Fatal("settings map should be initialized")
	}
}

func TestSaveAndLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cfg.json")
	cfg, _ := Load(path)
	cfg.Iface = "wlan0"
	cfg.Targets = []string{"192.168.8.0/24"}
	cfg.Set("arp.spoof", "fullduplex", "true")
	cfg.Set("dns.spoof", "domains", "*.bank.com")
	if err := cfg.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Iface != "wlan0" {
		t.Fatalf("iface = %q", got.Iface)
	}
	if len(got.Targets) != 1 || got.Targets[0] != "192.168.8.0/24" {
		t.Fatalf("targets = %v", got.Targets)
	}
	if got.Get("arp.spoof", "fullduplex") != "true" {
		t.Fatalf("fullduplex setting lost")
	}
	if got.Get("dns.spoof", "domains") != "*.bank.com" {
		t.Fatalf("dns domains setting lost")
	}
}

func TestSetRemovesEmpty(t *testing.T) {
	cfg := Default()
	cfg.Set("m", "k", "v")
	if cfg.Get("m", "k") != "v" {
		t.Fatal("set failed")
	}
	cfg.Set("m", "k", "")
	if cfg.Get("m", "k") != "" {
		t.Fatal("empty set should remove the key")
	}
}

func TestGetBoolAndIntDefaults(t *testing.T) {
	cfg := Default()
	if cfg.GetBool("m", "missing", true) != true {
		t.Fatal("default bool not used")
	}
	if cfg.GetInt("m", "missing", 42) != 42 {
		t.Fatal("default int not used")
	}
	cfg.Set("m", "b", "false")
	cfg.Set("m", "n", "7")
	if cfg.GetBool("m", "b", true) != false {
		t.Fatal("bool parse failed")
	}
	if cfg.GetInt("m", "n", 0) != 7 {
		t.Fatal("int parse failed")
	}
}

func TestGetDuration(t *testing.T) {
	cfg := Default()
	cfg.Set("m", "d", "500ms")
	if cfg.GetDuration("m", "d", time.Second) != 500*time.Millisecond {
		t.Fatal("duration parse failed")
	}
	if cfg.GetDuration("m", "bad", time.Second) != time.Second {
		t.Fatal("invalid duration should fall back to default")
	}
}

func TestRiskConfirmationPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "risk.json")
	cfg, _ := Load(path)
	if cfg.IsRiskConfirmed("wlan.deauth") {
		t.Fatal("should not be confirmed initially")
	}
	cfg.ConfirmRisk("wlan.deauth")
	if !cfg.IsRiskConfirmed("wlan.deauth") {
		t.Fatal("confirmation not recorded")
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	got, _ := Load(path)
	if !got.IsRiskConfirmed("wlan.deauth") {
		t.Fatal("confirmation not persisted")
	}
}

func TestCorruptConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for corrupt config")
	}
}
