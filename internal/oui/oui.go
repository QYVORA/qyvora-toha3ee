// Package oui provides a bundled IEEE OUI vendor lookup table. The full IEEE
// registry is large; this package ships a curated set of the vendors most
// commonly seen on home/SOHO and lab networks, with a lookup that is safe to
// call for arbitrary MACs.
package oui

import (
	"net"
	"strings"
)

// DB resolves the first three bytes of a MAC address to a vendor name.
type DB struct {
	// table maps the uppercase "AA:BB:CC" OUI to its vendor name.
	table map[string]string
}

// New returns a DB loaded with the bundled OUI table.
func New() *DB {
	return &DB{table: bundled}
}

// Lookup returns the vendor for a hardware address, or "" if unknown.
func (d *DB) Lookup(mac net.HardwareAddr) string {
	// MACs shorter than 3 bytes (e.g. bogus/empty frames) have no OUI.
	if len(mac) < 3 {
		return ""
	}
	// mac.String() yields "aa:bb:cc:dd:ee:ff"; the first 8 chars are the OUI
	// as "AA:BB:CC", which is exactly the table's key format.
	key := strings.ToUpper(mac.String()[:8]) // "AA:BB:CC"
	if v, ok := d.table[key]; ok {
		return v
	}
	// Some vendors change the third byte; match on two bytes as a fallback.
	// This probes for a "AA:BB:XX" entry that represents a whole /24-style
	// range for vendors that shuffle the final OUI octet.
	key2 := key[:5] + "XX"
	if v, ok := d.table[key2]; ok {
		return v
	}
	return ""
}

// bundled is the curated OUI table. Keys use uppercase "AA:BB:CC".
// Entries are grouped by vendor; an "AA:BB:XX" entry would act as a two-byte
// wildcard fallback for vendors that vary the third octet.
var bundled = map[string]string{
	// Apple
	"3C:22:FB": "Apple", "F8:1E:DF": "Apple", "D0:E1:40": "Apple",
	"00:17:F2": "Apple", "AC:BC:32": "Apple", "88:66:5A": "Apple",
	"A8:5C:2C": "Apple", "6C:70:9F": "Apple", "F0:18:98": "Apple",
	"B4:8B:19": "Apple", "A4:83:E7": "Apple", "F4:F5:D8": "Apple",
	"40:CB:C0": "Apple", "C8:69:CD": "Apple",
	// Intel
	"8C:16:45": "Intel", "00:1E:67": "Intel", "40:B4:CD": "Intel",
	"00:1C:BF": "Intel", "8C:EC:4B": "Intel", "3C:97:0E": "Intel",
	"68:1C:A2": "Intel", "A4:34:B9": "Intel", "6C:3B:6B": "Intel",
	"5C:26:0A": "Intel", "F8:1A:67": "Intel", "B4:CD:27": "Intel",
	"7C:7A:91": "Intel", "00:13:E8": "Intel", "00:21:6A": "Intel",
	// TP-Link
	"50:C7:BF": "TP-Link", "60:32:B1": "TP-Link", "74:DA:88": "TP-Link",
	"1C:3B:F3": "TP-Link", "A4:2B:B0": "TP-Link", "48:46:FB": "TP-Link",
	"F4:F2:6D": "TP-Link", "90:0D:CB": "TP-Link", "64:66:B3": "TP-Link",
	"80:81:A5": "TP-Link", "D4:DA:21": "TP-Link", "EC:88:8F": "TP-Link",
	"FC:D2:B6": "TP-Link", "C0:06:C3": "TP-Link", "18:D6:C7": "TP-Link",
	// Samsung
	"F8:5E:3C": "Samsung", "00:12:FB": "Samsung", "44:8C:3B": "Samsung",
	"58:4F:6A": "Samsung", "88:74:2A": "Samsung", "54:CB:30": "Samsung",
	// Cisco
	"00:00:0C": "Cisco", "00:1B:0C": "Cisco", "70:2B:CB": "Cisco",
	"6C:41:6A": "Cisco", "00:1B:54": "Cisco", "00:26:0B": "Cisco",
	// Huawei / PCS
	"00:25:9E": "Huawei", "8C:34:FD": "Huawei", "E4:2B:84": "Huawei",
	"A0:F4:77": "Huawei", "84:1B:5E": "Huawei", "28:6E:D4": "PCS/Huawei",
	"3C:77:E6": "PCS/Huawei", "04:BD:88": "PCS/Huawei",
	// Dell
	"00:14:22": "Dell", "00:18:8B": "Dell", "18:66:DA": "Dell",
	// HP / Aruba
	"00:1B:78": "HP", "74:2B:0F": "HP", "3C:D9:2B": "HP",
	"00:0B:86": "Aruba/HP",
	// Raspberry Pi
	"B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
	// Google / Nest
	"18:B4:30": "Google", "94:EB:2C": "Google", "A4:C1:38": "Google",
	// Amazon
	"F0:27:2D": "Amazon", "78:E1:03": "Amazon", "AC:63:BE": "Amazon",
	// Xiaomi
	"00:9A:CD": "Xiaomi", "78:C2:C0": "Xiaomi", "34:CE:00": "Xiaomi",
	"64:09:80": "Xiaomi",
	// Lenovo
	"00:24:BE": "Lenovo", "54:EE:75": "Lenovo",
	// ASUS
	"D8:50:E6": "ASUSTek", "90:9F:33": "ASUSTek",
	// Netgear
	"20:E5:2A": "Netgear", "A0:40:A0": "Netgear", "E8:FC:AF": "Netgear",
	// D-Link
	"00:1B:11": "D-Link", "28:10:7B": "D-Link",
	// ZTE
	"00:13:4A": "ZTE", "6C:8B:2F": "ZTE",
	// Motorola
	"08:00:37": "Motorola", "00:15:56": "Motorola",
	// LG
	"00:1A:A3": "LG", "90:B6:86": "LG",
	// Sony
	"54:8C:A0": "Sony", "00:1D:BA": "Sony",
	// HTC
	"00:12:74": "HTC", "F8:DB:88": "HTC",
	// OnePlus
	"A4:77:33": "OnePlus",
	// Espressif
	"18:FE:34": "Espressif", "24:0A:C4": "Espressif", "30:AE:A4": "Espressif",
	// MediaTek
	"64:DB:E9": "MediaTek",
	// Qualcomm / QCA
	"00:23:BC": "Qualcomm", "00:03:7F": "Qualcomm", "2C:59:E5": "Qualcomm",
	// Marvell
	"00:50:43": "Marvell",
	// Realtek
	"00:01:5C": "Realtek", "00:E0:4C": "Realtek",
	// Virtualisation
	"52:54:00": "QEMU", "00:05:69": "VMware", "00:0C:29": "VMware",
	"00:50:56": "VMware",
	// Network equipment
	"00:05:85": "Juniper", "00:09:0F": "Fortinet", "08:5B:0E": "Fortinet",
	"4C:5E:0C": "MikroTik", "48:8F:5A": "MikroTik",
	"00:15:6D": "Ubiquiti", "24:A4:3C": "Ubiquiti", "78:8A:20": "Ubiquiti",
	"00:0D:88": "Sercomm", "00:19:26": "Sagemcom", "00:24:9F": "Sagemcom",
	"00:1A:DA": "Arcadyan", "74:31:70": "Arcadyan", "00:04:0D": "Avaya",
	// Consumer electronics / IoT
	"30:07:4D": "Roku", "90:33:37": "Roku", "9C:45:18": "Fitbit",
	"00:22:A0": "Garmin", "F4:8E:38": "NVIDIA", "00:04:4B": "NVIDIA",
	"00:03:FF": "Microsoft", "48:50:73": "Microsoft",
}
