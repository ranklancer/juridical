// Package approve owns the plan → approval-token half of the mutation loop
// (the internal design spec §6). A plan renders the live reach and its bound evaluation and is
// hashed; an approval token is minted against that hash by a human, one-time
// and short-lived, so an execution authorizes exactly the plan that was
// approved.
package approve

import (
	"time"

	"github.com/juridical-docker/juridical/internal/blast"
)

// Plan is the non-mutating dry-run result of POST /v1/plans (the internal design spec §6.1).
// An over-bound plan is still produced (for visibility) but WithinBound is
// false and it is not executable.
type Plan struct {
	PlanID        string              `json:"plan_id"`
	Action        string              `json:"action"`
	Backend       string              `json:"backend"`
	Project       string              `json:"project"`
	Params        map[string]string   `json:"params"`
	Target        string              `json:"target"`
	DeclaredBound blast.DeclaredBound `json:"declared_bound"`
	ComputedReach blast.Reach         `json:"computed_reach"`
	Enforcement   blast.Enforcement   `json:"enforcement"`
	Verdict       blast.Verdict       `json:"verdict"`
	WithinBound   bool                `json:"within_bound"`
	PlanHash      string              `json:"plan_hash"`
	CreatedAt     time.Time           `json:"created_at"`
	ExpiresAt     time.Time           `json:"expires_at"`
}

// Executable reports whether a plan may be approved and executed: it must be
// within bound and its verdict must not be BLOCK.
func (p Plan) Executable() bool {
	return p.WithinBound && p.Verdict != blast.VerdictBlock
}
