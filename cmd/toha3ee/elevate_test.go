package main

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestShouldElevate(t *testing.T) {
	tests := []struct {
		name    string
		euid    int
		noSudo  bool
		windows bool
		want    bool
	}{
		{"already root skips escalation", 0, false, false, false},
		{"non-root escalates by default", 1000, false, false, true},
		{"--no-sudo skips escalation", 1000, true, false, false},
		{"windows skips escalation", 1000, false, true, false},
	}
	for _, tt := range tests {
		if got := shouldElevate(tt.euid, tt.noSudo, tt.windows); got != tt.want {
			t.Errorf("%s: shouldElevate(%d, %v, %v) = %v, want %v",
				tt.name, tt.euid, tt.noSudo, tt.windows, got, tt.want)
		}
	}
}

// TestIsReadOnlyVerb guards the no-sudo-for-read-only-verbs contract: an
// automation layer must be able to run version/modules/completion without a
// password prompt, while verbs that touch the network stack still elevate.
// Synthetic command trees are used because the real tree is assembled inside
// main().
func TestIsReadOnlyVerb(t *testing.T) {
	readOnly := []string{"version", "modules", "completion", "help"}
	for _, name := range readOnly {
		if !isReadOnlyVerb(&cobra.Command{Use: name}) {
			t.Errorf("isReadOnlyVerb(%q) = false, want true", name)
		}
	}

	interactive := []string{"eval", "run", "interactive", "wizard", "script", "build", "report"}
	for _, name := range interactive {
		if isReadOnlyVerb(&cobra.Command{Use: name}) {
			t.Errorf("isReadOnlyVerb(%q) = true, want false", name)
		}
	}
}

// TestIsReadOnlyVerbNested verifies the parent walk resolves subcommands
// invoked through the root ("toha3ee version").
func TestIsReadOnlyVerbNested(t *testing.T) {
	root := &cobra.Command{Use: "toha3ee"}
	root.AddCommand(&cobra.Command{Use: "modules"})
	if !isReadOnlyVerb(root.Commands()[0]) {
		t.Error("nested read-only verb not detected")
	}

	root2 := &cobra.Command{Use: "toha3ee"}
	root2.AddCommand(&cobra.Command{Use: "eval"})
	if isReadOnlyVerb(root2.Commands()[0]) {
		t.Error("nested interactive verb misclassified as read-only")
	}
}
