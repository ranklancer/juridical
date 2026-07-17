// Package blast is the blast-radius limiter: the primitive the whole product
// exists to own (the internal design spec/F6 §4). An action declares a machine-checkable bound;
// the live reach is computed independently and compared axis-by-axis. Anything
// that cannot be positively shown to be within bound fails closed.
package blast

import (
	"errors"
	"fmt"
)

// Axis names the blast-radius dimensions active in Phase 1 (compose).
// namespace/node/AZ are declared dormant and rejected as unrecognised
// (fail-closed, not silently ignored) — see ValidateDeclared.
const (
	AxisMaxHosts = "max_hosts"
	AxisService  = "service"
	AxisFleetPct = "fleet_pct"
)

// DeclaredBound is the machine-checkable bound an action ships with its plan
// request (the internal design spec §4.1/§4.2). A bound that is absent, unparseable, or names a
// dormant dimension is a refusal (FC3), never a pass.
type DeclaredBound struct {
	MaxHosts int    `json:"max_hosts"` // distinct hosts the action may touch (default 1)
	Service  string `json:"service"`   // exactly-one-service constraint
	FleetPct int    `json:"fleet_pct"` // 0..100 ceiling on reachable like-units
}

// ErrNoBound is returned when a required declared bound is absent.
var ErrNoBound = errors.New("blast: declared bound is absent (fail-closed, FC3)")

// ValidateDeclared enforces FC3: the bound must be present, parseable, and use
// only active Phase-1 dimensions. dormant carries any dimension keys that were
// present in the request but are not active in Phase 1; any such key refuses.
func ValidateDeclared(b DeclaredBound, dormant []string) error {
	if len(dormant) > 0 {
		return fmt.Errorf("blast: declared bound references dormant dimension(s) %v (fail-closed, FC3)", dormant)
	}
	if b.Service == "" {
		return errors.New("blast: declared bound.service must name exactly one service (fail-closed, FC3)")
	}
	if b.MaxHosts < 0 {
		return fmt.Errorf("blast: declared bound.max_hosts %d is negative (fail-closed, FC3)", b.MaxHosts)
	}
	if b.FleetPct < 0 || b.FleetPct > 100 {
		return fmt.Errorf("blast: declared bound.fleet_pct %d out of range 0..100 (fail-closed, FC3)", b.FleetPct)
	}
	return nil
}
