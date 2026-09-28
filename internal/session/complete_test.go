package session

import "testing"

// The shared terminal application completes against this flat list, so it has
// to name the same commands the console accepts. A second hand-written list
// would be free to drift, which is why this is derived from the completer.
func TestCommandNamesCoverTheConsoleVerbs(t *testing.T) {
	names := CommandNames()
	if len(names) < 10 {
		t.Fatalf("CommandNames returned %d names (%v), want the full command set", len(names), names)
	}

	present := make(map[string]bool, len(names))
	for _, n := range names {
		if n == "" {
			t.Error("CommandNames contains an empty name")
		}
		present[n] = true
	}

	for _, want := range []string{
		"help", "modules", "status", "hosts", "report", "quit", "shell",
	} {
		if !present[want] {
			t.Errorf("CommandNames is missing %q", want)
		}
	}

	// Module ids must appear too, or a module command is not completable.
	if !present["net.show"] {
		t.Error("CommandNames is missing the net.show module command")
	}

	// A repeat wastes a completion slot and suggests two commands share a name.
	seen := map[string]int{}
	for _, n := range names {
		seen[n]++
	}
	for n, c := range seen {
		if c > 1 {
			t.Errorf("CommandNames repeats %q %d times", n, c)
		}
	}
}
