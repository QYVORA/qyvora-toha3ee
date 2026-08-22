package selfupdate

import "testing"

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want int
	}{
		{"equal", "v1.0.0", "v1.0.0", 0},
		{"patch bump", "v1.0.0", "v1.1.0", -1},
		{"numeric not lexical", "v1.9.0", "v1.10.0", -1},
		{"major bump", "v1.10.0", "v2.0.0", -1},
		{"reverse numeric", "v1.10.0", "v1.9.0", 1},
		{"missing v prefix", "1.2.0", "v1.2.1", -1},
		{"uppercase V", "V1.2.0", "v1.2.0", 0},
		{"short vs long segment", "v1.2", "v1.2.0", 0},
		{"prerelease below release", "v1.0.0-rc.1", "v1.0.0", -1},
		{"release above prerelease", "v2.0.0", "v2.0.0-beta", 1},
		{"numeric prerelease ids", "v1.0.0-rc.2", "v1.0.0-rc.10", -1},
		{"build metadata ignored", "v1.0.0+build.7", "v1.0.0", 0},
		{"double digits patch", "v1.2.9", "v1.2.19", -1},
		{"zero padded equal", "v1.02.0", "v1.2.0", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CompareVersions(tt.a, tt.b); got != tt.want {
				t.Errorf("CompareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestIsReleaseVersion(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"dev", false},
		{"DEV", false},
		{"", false},
		{"(devel)", false},
		{"none", false},
		{"unknown", false},
		{"v1.3.0", true},
		{"1.3.0", true},
		{"v0.1.0", true},
	}
	for _, tt := range tests {
		if got := IsReleaseVersion(tt.in); got != tt.want {
			t.Errorf("IsReleaseVersion(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestNormalizeDisplay(t *testing.T) {
	tests := map[string]string{
		"1.2.0":  "v1.2.0",
		"v1.2.0": "v1.2.0",
		"":       "",
		"dev":    "dev",
	}
	for in, want := range tests {
		if got := normalizeDisplay(in); got != want {
			t.Errorf("normalizeDisplay(%q) = %q, want %q", in, got, want)
		}
	}
}
