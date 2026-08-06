// Package attacks defines the module contract for every attack in toha3ee.
//
// The framework core knows nothing about what an attack does; it only knows
// that every Module implements the lifecycle Preflight → Run → Verify →
// Cleanup. Modules self-register into Registry through init(), which keeps the
// core free of direct dependencies on any attack implementation.
package attacks

import (
	"fmt"
	"sort"
	"strings"

	"github.com/qyvora/toha3ee/internal/safety"
)

// Risk classifies how disruptive an attack is. The ordering matters and is
// shared with safety.RiskLevel.
type Risk int

// Risk levels from least to most disruptive.
const (
	RiskInfo Risk = iota
	RiskLow
	RiskMedium
	RiskHigh
	RiskCritical
)

// String returns the canonical lowercase name.
func (r Risk) String() string {
	switch r {
	case RiskInfo:
		return "info"
	case RiskLow:
		return "low"
	case RiskMedium:
		return "medium"
	case RiskHigh:
		return "high"
	case RiskCritical:
		return "critical"
	}
	return "unknown"
}

// ParseRisk converts a name to a Risk. Defaults to RiskInfo.
func ParseRisk(s string) Risk {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "low":
		return RiskLow
	case "medium", "med":
		return RiskMedium
	case "high":
		return RiskHigh
	case "critical", "crit":
		return RiskCritical
	}
	return RiskInfo
}

// ModuleMeta is the static description of a module, used by the vector engine
// and the wizard to decide when the module is relevant.
type ModuleMeta struct {
	// ID is the dotted module identifier, e.g. "arp.spoof".
	ID string
	// Category groups modules: mitm, wireless, http, auth, service, post.
	Category string
	// Risk is the module's disruptiveness.
	Risk Risk
	// Targets lists the target kinds the module operates on: "host",
	// "gateway", "subnet", "ap", "domain", "service".
	Targets []string
	// Requires lists prerequisite capability IDs, e.g. "cap.ip_forward",
	// "cap.monitor_iface", "cap.raw_socket".
	Requires []string
	// Passive is true when the module emits zero network noise.
	Passive bool
	// Description is a short, honest summary.
	Description string
	// Limitations notes known environmental limits surfaced in the UI.
	Limitations string
}

// SupportsTarget reports whether the module can act on the given target kind.
func (m ModuleMeta) SupportsTarget(t string) bool {
	for _, tt := range m.Targets {
		if tt == t || tt == "*" {
			return true
		}
	}
	return false
}

// PreflightReport is the outcome of a module's preflight checks.
type PreflightReport = safety.PreflightReport

// Check is a single preflight check.
type Check = safety.Check

// Impact quantifies the result of a module after verification.
type Impact struct {
	// Summary is a human-readable verdict, e.g. "3 credentials captured".
	Summary string
	// Metrics are key/value quantifiers for reports.
	Metrics map[string]string
}

// Add records a quantified metric.
func (i *Impact) Add(key, value string) {
	if i.Metrics == nil {
		i.Metrics = make(map[string]string)
	}
	i.Metrics[key] = value
}

// Module is the lifecycle contract every attack must satisfy.
type Module interface {
	// Meta returns the module's static metadata.
	Meta() ModuleMeta
	// Preflight validates the environment and may auto-fix issues. It must
	// return a report with no blocked checks for Run to be permitted.
	Preflight(ctx *AttackCtx) (*PreflightReport, error)
	// Run performs the attack. For long-running attacks it must block until
	// ctx.Done is closed or return an error.
	Run(ctx *AttackCtx, opts map[string]string) error
	// Verify proves whether the attack worked and quantifies impact.
	Verify(ctx *AttackCtx) (*Impact, error)
	// Cleanup restores the network to its prior state.
	Cleanup(ctx *AttackCtx) error
}

// Registry is the global module registry. Modules self-register via init().
var Registry = map[string]Module{}

// Register adds a module to the global registry. Duplicate IDs panic so that
// developer mistakes surface immediately at startup.
func Register(m Module) {
	meta := m.Meta()
	if meta.ID == "" {
		panic("attacks: module registered with empty ID")
	}
	if _, dup := Registry[meta.ID]; dup {
		panic(fmt.Sprintf("attacks: duplicate module ID %q", meta.ID))
	}
	Registry[meta.ID] = m
}

// Get returns a registered module by ID.
func Get(id string) (Module, bool) {
	m, ok := Registry[id]
	return m, ok
}

// List returns all registered modules sorted by ID.
func List() []Module {
	ids := make([]string, 0, len(Registry))
	for id := range Registry {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]Module, 0, len(ids))
	for _, id := range ids {
		out = append(out, Registry[id])
	}
	return out
}

// ListIDs returns the sorted module IDs.
func ListIDs() []string {
	ids := make([]string, 0, len(Registry))
	for id := range Registry {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Categories returns the sorted set of module categories present.
func Categories() []string {
	seen := map[string]bool{}
	for _, m := range Registry {
		seen[m.Meta().Category] = true
	}
	var cats []string
	for c := range seen {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	return cats
}

// ListByCategory returns the modules in a category, sorted by ID.
func ListByCategory(cat string) []Module {
	var out []Module
	for _, m := range List() {
		if m.Meta().Category == cat {
			out = append(out, m)
		}
	}
	return out
}
