package safety

import "strings"

// Status is the outcome of a single preflight check.
type Status string

// Preflight check outcomes.
const (
	StatusOK      Status = "ok"
	StatusFixable Status = "fixable"
	StatusBlocked Status = "blocked"
)

// Check is one item in a PreflightReport.
type Check struct {
	// Name identifies the check, e.g. "root", "ip_forward", "monitor_iface".
	Name string
	// Status is ok, fixable or blocked.
	Status Status
	// AutoFixed is true when the framework fixed the issue during Preflight.
	AutoFixed bool
	// Detail is a human-readable explanation.
	Detail string
}

// PreflightReport aggregates the outcome of a module's preflight checks.
type PreflightReport struct {
	// Checks is the ordered list of checks.
	Checks []Check
}

// Add appends a check.
func (r *PreflightReport) Add(name string, status Status, autoFixed bool, detail string) {
	r.Checks = append(r.Checks, Check{Name: name, Status: status, AutoFixed: autoFixed, Detail: detail})
}

// AddOK appends a passing check.
func (r *PreflightReport) AddOK(name, detail string) {
	r.Add(name, StatusOK, false, detail)
}

// AddFixed appends a check that the framework auto-fixed.
func (r *PreflightReport) AddFixed(name, detail string) {
	r.Add(name, StatusOK, true, detail)
}

// AddFixable appends a check the framework could fix but chose not to.
func (r *PreflightReport) AddFixable(name, detail string) {
	r.Add(name, StatusFixable, false, detail)
}

// AddBlocked appends a check that prevents the attack from running.
func (r *PreflightReport) AddBlocked(name, detail string) {
	r.Add(name, StatusBlocked, false, detail)
}

// Blocked returns the first blocked check name, or "" when none is blocked.
func (r *PreflightReport) Blocked() string {
	for _, c := range r.Checks {
		if c.Status == StatusBlocked {
			return c.Name
		}
	}
	return ""
}

// OK reports whether no check is blocked.
func (r *PreflightReport) OK() bool {
	return r.Blocked() == ""
}

// Fixed lists the checks the framework auto-fixed.
func (r *PreflightReport) Fixed() []Check {
	var out []Check
	for _, c := range r.Checks {
		if c.AutoFixed {
			out = append(out, c)
		}
	}
	return out
}

// String renders the report as a compact multi-line listing.
func (r *PreflightReport) String() string {
	var b strings.Builder
	for _, c := range r.Checks {
		icon := "[OK]  "
		switch c.Status {
		case StatusBlocked:
			icon = "[BLK] "
		case StatusFixable:
			icon = "[FIX] "
		}
		b.WriteString(icon + c.Name)
		if c.Detail != "" {
			b.WriteString(" - " + c.Detail)
		}
		b.WriteString("\n")
	}
	return b.String()
}
