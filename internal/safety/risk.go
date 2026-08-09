package safety

import (
	"fmt"
	"strings"
)

// RiskLevel is a coarse classification of how disruptive an attack is.
// The values intentionally match the ordering used by attacks.Risk so that
// generic helpers here can reason about severity without importing the
// attacks package (which would create an import cycle).
type RiskLevel int

// Risk levels, lowest to highest severity.
const (
	// RiskInfo is benign/no-impact activity.
	RiskInfo RiskLevel = iota
	// RiskLow is minimally disruptive (mostly passive).
	RiskLow
	// RiskMedium adds noise but does not drop traffic.
	RiskMedium
	// RiskHigh interrupts connectivity for targeted hosts.
	RiskHigh
	// RiskCritical is network-wide and sustained disruption.
	RiskCritical
)

// String returns the canonical risk name.
func (r RiskLevel) String() string {
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

// FromString parses a risk name (case-insensitive). Returns unknown on error.
func FromString(s string) RiskLevel {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info":
		return RiskInfo
	case "low":
		return RiskLow
	// "med" and "crit" are accepted as shorthand from the REPL.
	case "medium", "med":
		return RiskMedium
	case "high":
		return RiskHigh
	case "critical", "crit":
		return RiskCritical
	}
	return RiskInfo
}

// IsElevated reports whether the named risk requires explicit confirmation.
func IsElevated(riskName string) bool {
	switch strings.ToLower(riskName) {
	case "high", "critical":
		return true
	}
	return false
}

// BlastRadius returns a human-readable estimate of the impact radius for a
// risk level. It is shown to the user BEFORE confirming a High/Critical
// module in wizard mode.
func BlastRadius(riskName string) string {
	// These strings are deliberately specific about collateral damage so a
	// wizard user can make an informed consent decision.
	switch strings.ToLower(riskName) {
	case "critical":
		return "may drop all clients from the network/AP for a sustained period and trigger network-wide alarms"
	case "high":
		return "interrupts connectivity for targeted hosts for the duration of the attack (~seconds to minutes)"
	case "medium":
		return "adds noise to the network but does not drop traffic; captured data may be sensitive"
	case "low":
		return "minimal footprint; mostly passive observation"
	default:
		return "no significant footprint"
	}
}

// ConfirmText renders the blast radius prompt used by the wizard.
func ConfirmText(moduleID, riskName, description string) string {
	return fmt.Sprintf(
		"[!] %s is %s risk.\n    Blast radius: %s.\n    %s\n    Proceed? [y/N] ",
		moduleID, strings.ToUpper(riskName), BlastRadius(riskName), description,
	)
}
