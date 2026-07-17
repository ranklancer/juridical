package blast

import "math"

// Reach is the live blast radius computed from real topology (NOT from the
// declared params) — the internal design spec §4.3. It is rendered into the plan and covered by
// the plan hash so a human approves exactly the reach they saw (T3).
type Reach struct {
	Hosts     int `json:"hosts"`     // distinct hosts the resolved action touches
	Services  int `json:"services"`  // distinct services in the resolved set
	Instances int `json:"instances"` // resolved instance (container) count
	FleetPct  int `json:"fleet_pct"` // Instances / inventory * 100, rounded up
}

// ComputeFleetPct returns ceil(instances / inventory * 100), clamped to 0..100.
// inventory is the reachable inventory of like units. A zero or negative
// inventory yields 100 (treat an unknowable denominator as maximal reach —
// fail-closed toward the larger blast radius).
func ComputeFleetPct(instances, inventory int) int {
	if instances <= 0 {
		return 0
	}
	if inventory <= 0 {
		return 100
	}
	pct := int(math.Ceil(float64(instances) / float64(inventory) * 100))
	if pct > 100 {
		return 100
	}
	return pct
}
