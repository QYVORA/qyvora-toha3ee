package main

import (
	"testing"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-toha3ee/internal/attacks"
)

// TestModuleTreeCoversRegistry locks the generated recon/exploit/report tree to
// the module registry: every module whose category maps to a tier must be
// reachable as `<tier> <group> <action>`, no module may be reachable twice, and
// no leaf may exist that is absent from the registry. It also enforces the
// parent contract that keeps tier/group commands from escalating for sudo.
func TestModuleTreeCoversRegistry(t *testing.T) {
	tiers := map[string]*cobra.Command{
		"recon":   {Use: "recon"},
		"exploit": {Use: "exploit"},
		"report":  {Use: "report"},
	}
	env := cmdEnv{}
	env.attachModuleTree(tiers)

	reachable := map[string]string{} // module id -> "tier group"
	leafCount := 0
	for tierName, tier := range tiers {
		for _, grp := range tier.Commands() {
			// Groups are navigational parents: they must not own a Run/RunE,
			// otherwise isReadOnlyVerb would treat them as network verbs and
			// prompt for sudo just to list modules.
			if grp.Run != nil || grp.RunE != nil {
				t.Errorf("group %q must be a pure parent", grp.Name())
			}
			for _, leaf := range grp.Commands() {
				leafCount++
				id := grp.Name() + "." + leaf.Name()
				if leaf.RunE == nil {
					t.Errorf("leaf %s.%s has no RunE", tierName, id)
				}
				if prev, dup := reachable[id]; dup {
					t.Errorf("module %s reachable twice: %s and %s ", id, prev, tierName)
				}
				reachable[id] = tierName + " " + grp.Name()
			}
		}
	}

	want := 0
	for _, m := range attacks.List() {
		meta := m.Meta()
		if moduleTier[meta.Category] == "" {
			continue // intentionally not surfaced on the CLI
		}
		want++
		if _, ok := reachable[meta.ID]; !ok {
			t.Errorf("module %s (category %s) is not reachable on the CLI", meta.ID, meta.Category)
		}
	}
	if leafCount != want {
		t.Errorf("generated %d leaves, want %d (one per mapped module)", leafCount, want)
	}

	// Spot-check the category -> tier routing the plan fixes.
	checks := map[string]string{
		"net.scan":        "recon",
		"osint.dns":       "recon",
		"wlan.deauth":     "exploit",
		"switch.flood":    "exploit",
		"auth.brute":      "exploit",
		"web.misconfig":   "exploit",
		"report.generate": "report",
		"session.replay":  "report",
	}
	for id, tier := range checks {
		if got, ok := reachable[id]; !ok {
			t.Errorf("expected module %s on the CLI, missing", id)
		} else if got[:len(tier)] != tier {
			t.Errorf("module %s landed in tier %q, want %q", id, got, tier)
		}
	}
}
