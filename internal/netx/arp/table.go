package arp

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

// Row is a snapshot of one kernel ARP entry (exported for modules that restore
// the table after poisoning).
type Row struct {
	IP    net.IP
	MAC   net.HardwareAddr
	Iface string // interface the entry was learned on, used for "ip neigh ... dev"
}

// SnapshotTable returns the current kernel ARP table for later restoration
// after an ARP-poisoning engagement.
func SnapshotTable() ([]Row, error) {
	rows, err := readARPRows()
	if err != nil {
		return nil, err
	}
	// Copy the parsed rows into the exported Row type so callers do not depend
	// on the internal arpRow representation.
	out := make([]Row, 0, len(rows))
	for _, r := range rows {
		out = append(out, Row(r))
	}
	return out, nil
}

// Restore rewrites the kernel ARP cache to the entries captured by
// SnapshotTable, using the iproute2 "ip neigh" command.
func Restore(rows []Row) error {
	for _, r := range rows {
		// Skip malformed rows; a valid MAC is always exactly 6 bytes.
		if r.IP == nil || r.MAC == nil || len(r.MAC) != 6 {
			continue
		}
		// "nud permanent" pins the entry so the kernel does not expire or
		// re-probe it after the poisoning stopped.
		args := []string{"neigh", "replace", r.IP.String(), "lladdr", r.MAC.String(), "nud", "permanent"}
		if r.Iface != "" {
			args = append(args, "dev", r.Iface)
		}
		// CombinedOutput captures stderr so the error message is actionable.
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("arp.Restore(%s): %v: %s", r.IP, err, out)
		}
	}
	return nil
}

// readARPRows parses /proc/net/arp into structured rows. Columns are:
// IP address  HW type  Flags  HW address  Mask  Device
func readARPRows() ([]arpRow, error) {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, fmt.Errorf("open /proc/net/arp: %w", err)
	}
	defer func() { _ = f.Close() }()

	var rows []arpRow
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 {
			continue // malformed or otherwise incomplete row
		}
		ip := net.ParseIP(fields[0])
		if ip == nil {
			continue
		}
		mac, err := net.ParseMAC(fields[3])
		if err != nil {
			continue // unresolved entry has no usable hardware address
		}
		// The kernel fills unresolved entries with the zero MAC; skip them.
		if strings.EqualFold(mac.String(), "00:00:00:00:00:00") {
			continue
		}
		rows = append(rows, arpRow{IP: ip, MAC: mac, Iface: fields[5]})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return rows, nil
}
