package session

import "testing"

func TestSplitModuleKey(t *testing.T) {
	cases := []struct {
		in, module, param string
		ok                bool
	}{
		{"arp.spoof.targets", "arp.spoof", "targets", true},
		{"net.scan.iface", "net.scan", "iface", true},
		{"module.simple", "module", "simple", true},
		{"noseparator", "", "", false},
	}
	for _, c := range cases {
		m, p, ok := splitModuleKey(c.in)
		if m != c.module || p != c.param || ok != c.ok {
			t.Fatalf("splitModuleKey(%q) = %q, %q, %v; want %q, %q, %v",
				c.in, m, p, ok, c.module, c.param, c.ok)
		}
	}
}
