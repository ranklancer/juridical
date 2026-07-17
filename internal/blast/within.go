package blast

// Mode is a per-axis enforcement mode (progressive enforcement, the design notes).
type Mode string

const (
	ModeOff   Mode = "off"   // axis not enforced
	ModeWarn  Mode = "warn"  // over-reach recorded/surfaced but permitted (default)
	ModeBlock Mode = "block" // over-reach refused (fail-closed)
)

// Enforcement is the per-axis mode set carried in the plan.
type Enforcement struct {
	MaxHosts Mode `json:"max_hosts"`
	Service  Mode `json:"service"`
	FleetPct Mode `json:"fleet_pct"`
}

// Verdict is the outcome of comparing a computed reach to a declared bound.
type Verdict string

const (
	VerdictAllow Verdict = "ALLOW"
	VerdictWarn  Verdict = "WARN"
	VerdictBlock Verdict = "BLOCK"
)

// AxisBreach names an axis whose reach exceeded the declared bound.
type AxisBreach struct {
	Axis     string
	Declared int
	Reached  int
	Mode     Mode
}

// Within reports whether every axis satisfies reach.axis <= declared.axis,
// with services required to be exactly 1 for a single-service action
// (the internal design spec §4.3). It is the pure comparison, independent of enforcement mode.
func Within(declared DeclaredBound, reach Reach) bool {
	if reach.Services != 1 {
		return false
	}
	return reach.Hosts <= declared.MaxHosts &&
		reach.Instances >= 0 &&
		reach.FleetPct <= declared.FleetPct
}

// Evaluate compares reach to declared under the given enforcement modes and
// returns a Verdict plus the set of breaching axes. A breach on a Block axis
// yields BLOCK (fail-closed); a breach only on Warn axes yields WARN; no breach
// (or breaches only on Off axes) yields ALLOW. The exactly-one-service rule is
// enforced on the service axis.
func Evaluate(declared DeclaredBound, reach Reach, e Enforcement) (Verdict, []AxisBreach) {
	var breaches []AxisBreach
	add := func(axis string, dec, got int, m Mode) {
		if m == ModeOff {
			return
		}
		breaches = append(breaches, AxisBreach{Axis: axis, Declared: dec, Reached: got, Mode: m})
	}
	if reach.Hosts > declared.MaxHosts {
		add(AxisMaxHosts, declared.MaxHosts, reach.Hosts, e.MaxHosts)
	}
	if reach.Services != 1 {
		// A single-service action resolving to !=1 service is the canonical
		// over-reach (wildcard/group). Declared "1", reached services count.
		add(AxisService, 1, reach.Services, e.Service)
	}
	if reach.FleetPct > declared.FleetPct {
		add(AxisFleetPct, declared.FleetPct, reach.FleetPct, e.FleetPct)
	}

	verdict := VerdictAllow
	for _, b := range breaches {
		if b.Mode == ModeBlock {
			return VerdictBlock, breaches
		}
		if b.Mode == ModeWarn {
			verdict = VerdictWarn
		}
	}
	return verdict, breaches
}
