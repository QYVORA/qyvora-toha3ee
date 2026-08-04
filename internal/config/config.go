// Package config manages persistent framework and per-module settings.
//
// Configuration is a single JSON document on disk. Modules read their tuning
// knobs through Config.Get/GetDefault so that the REPL can expose
// "<module>.<param> <value>" for any knob, and caplets can script them.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"
)

// DefaultConfigPath is used when no --config flag is given.
const DefaultConfigPath = "toha3ee.json"

// Config is the on-disk representation of all framework settings.
type Config struct {
	// Path is where the config was loaded from / will be saved to.
	Path string `json:"-"`

	// Iface is the primary network interface used for L2 attacks.
	Iface string `json:"iface"`
	// SniffOutput is the pcap file path used by net.sniff / pcap.export.
	SniffOutput string `json:"sniff_output"`
	// CAFile and CAPrivateKey point at the framework CA material.
	CAFile       string `json:"ca_file"`
	CAPrivateKey string `json:"ca_private_key"`
	// ProxyHTTPAddr is where the HTTP MITM proxy listens.
	ProxyHTTPAddr string `json:"proxy_http_addr"`
	// ProxyHTTPSAddr is where the HTTPS CONNECT MITM proxy listens.
	ProxyHTTPSAddr string `json:"proxy_https_addr"`
	// ARPRefresh is the ARP spoof refresh interval.
	ARPRefresh time.Duration `json:"arp_refresh"`
	// DNSUPstream is an optional upstream resolver for DNS spoof forwarding.
	DNSUPstream string `json:"dns_upstream"`
	// Targets are default targets for L2/L3 modules, e.g. "192.168.8.0/24".
	Targets []string `json:"targets"`
	// Settings holds per-module parameters keyed by module ID then parameter.
	Settings map[string]map[string]string `json:"settings"`
	// ConfirmedRisks remembers High/Critical modules the user already approved.
	ConfirmedRisks map[string]bool `json:"confirmed_risks"`
}

// Default returns a Config populated with sane defaults for a Kali host.
func Default() *Config {
	return &Config{
		Iface:          "eth0",
		SniffOutput:    "capture.pcap",
		CAFile:         "toha3ee-ca.pem",
		CAPrivateKey:   "toha3ee-ca.key",
		ProxyHTTPAddr:  ":8080",
		ProxyHTTPSAddr: ":8443",
		ARPRefresh:     2 * time.Second,
		Targets:        nil,
		Settings:       make(map[string]map[string]string),
		ConfirmedRisks: make(map[string]bool),
	}
}

// Load reads the JSON config at path. If the file does not exist, Default is
// returned (the file is created on the first Save).
func Load(path string) (*Config, error) {
	cfg := Default()
	cfg.Path = path
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if cfg.Settings == nil {
		cfg.Settings = make(map[string]map[string]string)
	}
	if cfg.ConfirmedRisks == nil {
		cfg.ConfirmedRisks = make(map[string]bool)
	}
	cfg.Path = path
	return cfg, nil
}

// Save writes the config to Path, creating parent directories if needed.
func (c *Config) Save() error {
	if c.Path == "" {
		return errors.New("config has no path")
	}
	if dir := filepath.Dir(c.Path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create config dir: %w", err)
		}
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	return os.WriteFile(c.Path, data, 0o644)
}

// Set stores a per-module parameter. An empty value removes it.
func (c *Config) Set(module, key, value string) {
	if c.Settings == nil {
		c.Settings = make(map[string]map[string]string)
	}
	mod := c.Settings[module]
	if mod == nil {
		mod = make(map[string]string)
	}
	if value == "" {
		delete(mod, key)
		if len(mod) == 0 {
			delete(c.Settings, module)
		}
	} else {
		mod[key] = value
	}
	c.Settings[module] = mod
}

// Get returns the raw per-module parameter value ("" if unset).
func (c *Config) Get(module, key string) string {
	if mod, ok := c.Settings[module]; ok {
		return mod[key]
	}
	return ""
}

// GetDefault returns the parameter value or def when unset.
func (c *Config) GetDefault(module, key, def string) string {
	if v := c.Get(module, key); v != "" {
		return v
	}
	return def
}

// Keys returns all "module.key" pairs currently set, sorted by module.
func (c *Config) Keys() []string {
	mods := make([]string, 0, len(c.Settings))
	for m := range c.Settings {
		mods = append(mods, m)
	}
	sort.Strings(mods)
	var out []string
	for _, m := range mods {
		for k := range c.Settings[m] {
			out = append(out, m+"."+k)
		}
	}
	return out
}

// GetFromKey resolves a "module.key" key to its value.
func (c *Config) GetFromKey(key string) string {
	for i := len(key) - 1; i > 0; i-- {
		if key[i] == '.' {
			return c.Get(key[:i], key[i+1:])
		}
	}
	return ""
}

// GetBool interprets a parameter as a boolean.
func (c *Config) GetBool(module, key string, def bool) bool {
	v := c.Get(module, key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

// GetInt interprets a parameter as an integer.
func (c *Config) GetInt(module, key string, def int) int {
	v := c.Get(module, key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

// GetDuration interprets a parameter as a duration.
func (c *Config) GetDuration(module, key string, def time.Duration) time.Duration {
	v := c.Get(module, key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

// ConfirmRisk remembers that the user approved a High/Critical module.
func (c *Config) ConfirmRisk(moduleID string) {
	if c.ConfirmedRisks == nil {
		c.ConfirmedRisks = make(map[string]bool)
	}
	c.ConfirmedRisks[moduleID] = true
}

// IsRiskConfirmed reports whether the user already approved moduleID.
func (c *Config) IsRiskConfirmed(moduleID string) bool {
	if c.ConfirmedRisks == nil {
		return false
	}
	return c.ConfirmedRisks[moduleID]
}
