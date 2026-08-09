package vectors

import (
	"fmt"
	"sort"
)

// MetaInfo is the minimal module metadata the engine needs. It is provided by
// the session through a MetaResolver built from the attacks registry, keeping
// vectors free of dependencies on the attacks package.
type MetaInfo struct {
	// Category groups the module (e.g. "recon", "attack", "wlan").
	Category string
	// Risk is the module's default risk name ("low".."critical").
	Risk string
	// Targets are the module's default target selectors.
	Targets []string
	// Requires lists capability IDs that must be satisfiable.
	Requires []string
	// Passive reports whether the module makes no active changes.
	Passive bool
	// Description is a short human summary of what the module does.
	Description string
	// Limitations notes conditions that constrain the module.
	Limitations string
}

// MetaResolver returns metadata for a module ID.
type MetaResolver func(id string) (MetaInfo, bool)

// Vector is a single ranked attack suggestion.
type Vector struct {
	// ModuleID names the attack module to run, e.g. "arp.spoof".
	ModuleID string
	// Target is the object the attack would run against (IP, "subnet", ...).
	Target string
	// Confidence is the estimated probability of success in [0,1].
	Confidence float64
	// Risk is the severity classification; empty means "inherit from meta".
	Risk string
	// Impact describes what the attack would achieve.
	Impact string
	// Requires lists capability IDs that must be satisfiable.
	Requires []string
}

// Engine runs the rules over a Profile and ranks the results.
type Engine struct {
	// meta resolves module metadata, or the nil-safe fallback when unset.
	meta MetaResolver
}

// NewEngine returns an engine backed by the given module metadata resolver.
func NewEngine(meta MetaResolver) *Engine {
	if meta == nil {
		// Fallback resolver reports "unknown module" for everything so the
		// engine still works without an attacks registry (e.g. in tests).
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
				// A rule returned an empty suggestion; skip it so garbage
				// never reaches the ranking step.
				continue
			}
			// Deduplicate on (module, target) so overlapping rules cannot
			// suggest the same attack twice.
			key := v.ModuleID + "|" + v.Target
			if seen[key] {
				continue
			}
			seen[key] = true
			// Fill defaults from metadata only where the rule left them
			// empty; rule-specific values always win.
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
				// Unknown module: mark the risk explicitly instead of
				// presenting an empty cell in the table.
				v.Risk = "unknown"
			}
			out = append(out, v)
		}
	}
	// Rank: highest confidence first; ties break on module ID so the order
	// is deterministic across runs.
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
