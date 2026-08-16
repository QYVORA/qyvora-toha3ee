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
	"sync"
	"time"
)

// DefaultConfigPath is used when no --config flag is given.
const DefaultConfigPath = "toha3ee.json"

// Config is the on-disk representation of all framework settings.
type Config struct {
	// Path is where the config was loaded from / will be saved to. It is
	// excluded from JSON serialization: the file location is a runtime
	// concern, not a persisted setting.
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

	// mu guards Settings and ConfirmedRisks: module goroutines read them on
	// every run loop while the REPL, wizard, and scripts write them live.
	mu sync.Mutex `json:"-"`
}

// Default returns a Config populated with sane defaults for a Kali host.
//
// The returned Config is the base that Load overlays JSON onto, and is also
// used directly by code that never touches disk. The two maps are
// pre-initialized so Set/ConfirmRisk never nil-panic on a defaulted Config.
func Default() *Config {
	return &Config{
		// Bind L2 attacks to the first wired interface; users override it
		// via --iface or the REPL.
		Iface: "eth0",
		// Capture artifacts and CA material land in the working directory.
		SniffOutput:    "capture.pcap",
		CAFile:         "toha3ee-ca.pem",
		CAPrivateKey:   "toha3ee-ca.key",
		ProxyHTTPAddr:  ":8080",
		ProxyHTTPSAddr: ":8443",
		// Re-assert ARP spoofing every 2s to survive host counter-spoofing
		// and neighbor cache expiry.
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
		// A missing file is not an error: fall back to defaults and let the
		// first Save create it. Any other read failure is real.
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}
	// Unmarshal overlays only the tagged JSON fields onto the defaults, so a
	// partially-populated file keeps sane values for everything else.
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	// Hand-written or older configs may omit the maps; re-init them so the
	// accessors below never need nil guards.
	if cfg.Settings == nil {
		cfg.Settings = make(map[string]map[string]string)
	}
	if cfg.ConfirmedRisks == nil {
		cfg.ConfirmedRisks = make(map[string]bool)
	}
	// Path carries a `json:"-"` tag, so Unmarshal leaves it exactly as set
	// above; this re-assignment keeps the invariant explicit and local.
	cfg.Path = path
	return cfg, nil
}

// Save writes the config to Path, creating parent directories if needed.
func (c *Config) Save() error {
	if c.Path == "" {
		// Refuse to guess a location for a Config that was never loaded or
		// given an explicit path.
		return errors.New("config has no path")
	}
	// The target directory may not exist yet (e.g. a fresh install); create
	// it recursively so the final write cannot fail on a missing parent.
	if dir := filepath.Dir(c.Path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create config dir: %w", err)
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// MarshalIndent produces the human-editable, two-space-indented JSON
	// document the REPL and users interact with.
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	// 0644: the file holds module tuning and target lists, no secrets.
	return os.WriteFile(c.Path, data, 0o644)
}

// Set stores a per-module parameter. An empty value removes it.
func (c *Config) Set(module, key, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Lazily initialize the two-level map so Set works on a zero-value Config.
	if c.Settings == nil {
		c.Settings = make(map[string]map[string]string)
	}
	mod := c.Settings[module]
	if mod == nil {
		mod = make(map[string]string)
	}
	if value == "" {
		// An empty value is the way to unset a knob: delete the key, and once
		// a module has no parameters left prune its entry entirely so it does
		// not linger in listings as an empty section.
		delete(mod, key)
		if len(mod) == 0 {
			delete(c.Settings, module)
		}
	} else {
		mod[key] = value
	}
	// Write back even for the delete path: mod was only ever a copy-on-read
	// map that needs re-attaching when the module slot was created here.
	c.Settings[module] = mod
}

// Get returns the raw per-module parameter value ("" if unset).
func (c *Config) Get(module, key string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if mod, ok := c.Settings[module]; ok {
		// A missing key and an explicitly empty value both read as "";
		// callers wanting a fallback use GetDefault.
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
	c.mu.Lock()
	defer c.mu.Unlock()
	// Module names are sorted first so the resulting list is deterministic
	// and grouped for stable REPL/config listings.
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
	// Scan backwards so the split lands on the LAST '.', which guarantees we
	// find a separator whenever one exists and treats anything after it as
	// the parameter name.
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
		// Unparseable values (e.g. a typo like "tru") degrade to the default
		// instead of erroring, keeping config handling tolerant.
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
		// Non-numeric values fall back to the default rather than aborting.
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
		// Malformed duration strings (e.g. "10" without a unit) fall back to
		// the default rather than aborting the module.
		return def
	}
	return d
}

// ConfirmRisk remembers that the user approved a High/Critical module.
func (c *Config) ConfirmRisk(moduleID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ConfirmedRisks == nil {
		c.ConfirmedRisks = make(map[string]bool)
	}
	// The bool value is always true; the map key alone records approval.
	c.ConfirmedRisks[moduleID] = true
}

// IsRiskConfirmed reports whether the user already approved moduleID.
func (c *Config) IsRiskConfirmed(moduleID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ConfirmedRisks == nil {
		// A nil map reads as "nothing approved yet".
		return false
	}
	return c.ConfirmedRisks[moduleID]
}
