package safety

import "time"

// Profile defines operational parameters for red team operations
type Profile struct {
	Name             string        // Profile name
	Description      string        // Profile description
	MaxNoiseLevel    NoiseLevel    // Maximum allowed noise level
	RateLimit        time.Duration // Minimum delay between operations
	Jitter           time.Duration // Timing jitter for anti-fingerprinting
	MaxParallel      int           // Maximum parallel operations
	PreferSimulation bool          // Prefer simulation when available
}

// Predefined operational profiles
var (
	// StealthProfile minimizes detection risk
	StealthProfile = Profile{
		Name:             "stealth",
		Description:      "Minimize operational footprint: passive/low noise only",
		MaxNoiseLevel:    NoiseLevelLow,
		RateLimit:        5 * time.Second,
		Jitter:           3 * time.Second,
		MaxParallel:      1,
		PreferSimulation: true,
	}

	// StandardProfile balances speed and discretion
	StandardProfile = Profile{
		Name:             "standard",
		Description:      "Balanced approach: moderate noise allowed",
		MaxNoiseLevel:    NoiseLevelModerate,
		RateLimit:        1 * time.Second,
		Jitter:           500 * time.Millisecond,
		MaxParallel:      5,
		PreferSimulation: false,
	}

	// AggressiveProfile prioritizes speed and coverage
	AggressiveProfile = Profile{
		Name:             "aggressive",
		Description:      "Maximum effectiveness: all noise levels",
		MaxNoiseLevel:    NoiseLevelAggressive,
		RateLimit:        100 * time.Millisecond,
		Jitter:           50 * time.Millisecond,
		MaxParallel:      20,
		PreferSimulation: false,
	}
)

// GetProfile returns the profile by name, defaulting to StandardProfile
func GetProfile(name string) Profile {
	switch name {
	case "stealth":
		return StealthProfile
	case "aggressive":
		return AggressiveProfile
	case "standard":
		return StandardProfile
	default:
		return StandardProfile
	}
}

// Allows reports whether a noise level is permitted under this profile
func (p Profile) Allows(noiseLevel NoiseLevel) bool {
	return noiseLevel <= p.MaxNoiseLevel
}
