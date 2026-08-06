package vectors

import (
	"fmt"
	"sort"
)

// MetaInfo is the minimal module metadata the engine needs. It is provided by
// the session through a MetaResolver built from the attacks registry, keeping
// vectors free of dependencies on the attacks package.
type MetaInfo struct {
	Category    string
	Risk        string
	Targets     []string
	Requires    []string
	Passive     bool
	Description string
	Limitations string
}

// MetaResolver returns metadata for a module ID.
type MetaResolver func(id string) (MetaInfo, bool)

// Vector is a single ranked attack suggestion.
type Vector struct {
	ModuleID string
	Target   string
	// Confidence is the estimated probability of success in [0,1].
	Confidence float64
	Risk       string
	// Impact describes what the attack would achieve.
	Impact string
	// Requires lists capability IDs that must be satisfiable.
	Requires []string
}

// Engine runs the rules over a Profile and ranks the results.
type Engine struct {
	meta MetaResolver
}

// NewEngine returns an engine backed by the given module metadata resolver.
func NewEngine(meta MetaResolver) *Engine {
	if meta == nil {
		meta = func(string) (MetaInfo, bool) { return MetaInfo{}, false }
	}
	return &Engine{meta: meta}
}

// Rule is a single vector rule. Rules self-register via the RuleRegistry.
type Rule func(p *Profile) []Vector

// RuleRegistry is populated by rule packages during init().
var RuleRegistry []Rule

// RegisterRule adds a rule (idempotent per function pointer is not enforced;
// rule packages must register exactly once).
func RegisterRule(r Rule) {
	RuleRegistry = append(RuleRegistry, r)
}

// Analyze runs every registered rule, merges the results, attaches metadata
// from the resolver and returns the vectors ranked by confidence.
func (e *Engine) Analyze(p *Profile) []Vector {
	seen := map[string]bool{}
	var out []Vector
	for _, rule := range RuleRegistry {
		for _, v := range rule(p) {
			if v.ModuleID == "" {
				continue
			}
			key := v.ModuleID + "|" + v.Target
			if seen[key] {
				continue
			}
			seen[key] = true
			if meta, ok := e.meta(v.ModuleID); ok {
				if v.Risk == "" {
					v.Risk = meta.Risk
				}
				if len(v.Requires) == 0 {
					v.Requires = append([]string(nil), meta.Requires...)
				}
				if v.Impact == "" {
					v.Impact = meta.Description
				}
			} else if v.Risk == "" {
				v.Risk = "unknown"
			}
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Confidence == out[j].Confidence {
			return out[i].ModuleID < out[j].ModuleID
		}
		return out[i].Confidence > out[j].Confidence
	})
	return out
}

// Satisfiable reports whether every capability in Requires is available.
func (e *Engine) Satisfiable(p *Profile, v Vector) bool {
	for _, cap := range v.Requires {
		switch cap {
		case "cap.ip_forward", "cap.raw_socket", "cap.root":
			// These are auto-fixable at runtime; considered satisfiable.
		case "cap.monitor_iface":
			if !p.MonitorCapable {
				return false
			}
		case "cap.ca_trust":
			// Never auto-satisfiable; requires a manual CA install.
			return false
		default:
			// Unknown capabilities default to satisfiable.
		}
	}
	return true
}

// String renders a vector as a one-line table row.
func (v Vector) String() string {
	return fmt.Sprintf("%-24s %-18s %.2f  %-8s %s",
		v.ModuleID, v.Target, v.Confidence, v.Risk, v.Impact)
}
