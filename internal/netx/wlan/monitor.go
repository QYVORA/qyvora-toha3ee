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
		data, rerr := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/type", ifname))
		if rerr != nil {
			return false
		}
		return strings.TrimSpace(string(data)) == "803"
	}
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
	if err := run("dev", ifname, "set", "type", "monitor"); err != nil {
		return nil, fmt.Errorf("iw set monitor: %w", err)
	}
	if err := exec.Command("ip", "link", "set", ifname, "up").Run(); err != nil {
		return nil, fmt.Errorf("ip link up: %w", err)
	}
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
