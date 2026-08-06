package main

import "testing"

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
