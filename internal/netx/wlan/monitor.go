// Package wlan provides monitor-mode interface management and wireless frame
// primitives used by the wireless attack modules.
package wlan

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// DetectWirelessIface returns the name of a wireless interface, if any.
// A NIC is deemed wireless when the kernel exposes a "wireless" directory
// under its /sys/class/net entry.
func DetectWirelessIface() (string, bool) {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return "", false
	}
	for _, e := range entries {
		path := filepath.Join("/sys/class/net", e.Name(), "wireless")
		if _, err := os.Stat(path); err == nil {
			return e.Name(), true
		}
	}
	return "", false
}

// IsMonitor reports whether the interface is currently in monitor mode.
func IsMonitor(ifname string) bool {
	out, err := exec.Command("iw", "dev", ifname, "info").CombinedOutput()
	if err != nil {
		// Fall back to the link type: 803 = ARPHRD_IEEE80211_RADIOTAP.
		// Linux records the ARP hardware type of an interface at
		// /sys/class/net/<iface>/type.
		data, rerr := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/type", ifname))
		if rerr != nil {
			return false
		}
		return strings.TrimSpace(string(data)) == "803"
	}
	// iw's human-readable dump lists the mode as "type monitor".
	return strings.Contains(string(out), "type monitor")
}

// SetMonitorMode switches a wireless interface to monitor mode and returns a
// restore function that returns it to managed mode. It requires root and the
// iw utility.
func SetMonitorMode(ifname string) (restore func() error, err error) {
	if ifname == "" {
		return nil, errors.New("empty interface name")
	}
	run := func(args ...string) error {
		return exec.Command("iw", args...).Run()
	}
	// Switch the NIC's 802.11 mode to monitor so raw frames can be captured
	// and injected; this drops any existing association.
	if err := run("dev", ifname, "set", "type", "monitor"); err != nil {
		return nil, fmt.Errorf("iw set monitor: %w", err)
	}
	// Bring the interface administratively up (some drivers need this after a
	// mode change before frames flow).
	if err := exec.Command("ip", "link", "set", ifname, "up").Run(); err != nil {
		return nil, fmt.Errorf("ip link up: %w", err)
	}
	// The returned closure restores managed mode; it is idempotent so callers
	// may run it more than once safely.
	restored := false
	return func() error {
		if restored {
			return nil
		}
		restored = true
		if err := run("dev", ifname, "set", "type", "managed"); err != nil {
			return err
		}
		return exec.Command("ip", "link", "set", ifname, "up").Run()
	}, nil
}
