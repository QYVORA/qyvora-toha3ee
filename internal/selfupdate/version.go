package selfupdate

import (
	"strconv"
	"strings"
)

// CompareVersions compares two release versions and returns -1, 0 or 1.
//
// It implements numeric semantic-version comparison — v1.10.0 sorts after
// v1.9.0, unlike a lexical string compare — tolerates an optional leading
// "v"/"V", ignores build metadata ("+build"), and applies semver prerelease
// ordering: 1.0.0-rc.1 < 1.0.0, and numeric prerelease identifiers compare
// numerically (1.0.0-2 < 1.0.0-10).
func CompareVersions(a, b string) int {
	pa := parseVersion(a)
	pb := parseVersion(b)

	for i := 0; i < len(pa.core) || i < len(pb.core); i++ {
		var sa, sb int
		if i < len(pa.core) {
			sa = pa.core[i]
		}
		if i < len(pb.core) {
			sb = pb.core[i]
		}
		switch {
		case sa < sb:
			return -1
		case sa > sb:
			return 1
		}
	}

	// A version without a prerelease outranks one with it.
	switch {
	case pa.pre == "" && pb.pre != "":
		return 1
	case pa.pre != "" && pb.pre == "":
		return -1
	case pa.pre == pb.pre:
		return 0
	}
	return comparePrerelease(pa.pre, pb.pre)
}

type versionParts struct {
	core []int
	pre  string
}

func parseVersion(v string) versionParts {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	// Build metadata never affects precedence.
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	parts := versionParts{}
	if i := strings.IndexByte(v, '-'); i >= 0 {
		parts.pre = v[i+1:]
		v = v[:i]
	}
	for _, seg := range strings.Split(v, ".") {
		n, err := strconv.Atoi(strings.TrimSpace(seg))
		if err != nil {
			n = 0
		}
		parts.core = append(parts.core, n)
	}
	if parts.core == nil {
		parts.core = []int{0}
	}
	return parts
}

func comparePrerelease(a, b string) int {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		an, aerr := strconv.Atoi(as[i])
		bn, berr := strconv.Atoi(bs[i])
		switch {
		case aerr == nil && berr == nil:
			switch {
			case an < bn:
				return -1
			case an > bn:
				return 1
			}
		case aerr == nil:
			// Numeric identifiers sort before alphanumeric ones.
			return -1
		case berr == nil:
			return 1
		default:
			if c := strings.Compare(as[i], bs[i]); c != 0 {
				return c
			}
		}
	}
	switch {
	case len(as) < len(bs):
		return -1
	case len(as) > len(bs):
		return 1
	}
	return 0
}

// IsReleaseVersion reports whether v looks like a stamped release version
// rather than a development placeholder such as "dev".
func IsReleaseVersion(v string) bool {
	t := strings.ToLower(strings.TrimSpace(v))
	if t == "" {
		return false
	}
	t = strings.TrimPrefix(t, "v")
	if t[0] < '0' || t[0] > '9' {
		return false
	}
	return true
}
