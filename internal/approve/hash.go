package approve

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"

	"github.com/juridical-docker/juridical/internal/blast"
)

// hashTuple is the exact, ordered set of fields the plan hash covers
// (the internal design spec §6.2). Any drift in params OR computed reach changes the hash and
// therefore invalidates any token bound to it (T3).
type hashTuple struct {
	Action        string              `json:"action"`
	Backend       string              `json:"backend"`
	Project       string              `json:"project"`
	Params        map[string]string   `json:"params"`
	DeclaredBound blast.DeclaredBound `json:"declared_bound"`
	ComputedReach blast.Reach         `json:"computed_reach"`
	Target        string              `json:"target"`
}

// PlanHash returns SHA-256(canonical_json) as lowercase hex, where
// canonical_json is UTF-8 with lexicographically sorted keys and no
// insignificant whitespace, over {action, backend, project, params,
// declared_bound, computed_reach, target}. encoding/json already sorts map
// keys and struct fields are emitted in declaration order; we additionally
// canonicalize params to guarantee deterministic ordering across producers.
func PlanHash(p Plan) string {
	t := hashTuple{
		Action:        p.Action,
		Backend:       p.Backend,
		Project:       p.Project,
		Params:        canonicalParams(p.Params),
		DeclaredBound: p.DeclaredBound,
		ComputedReach: p.ComputedReach,
		Target:        p.Target,
	}
	b, _ := json.Marshal(t) // hashTuple marshals deterministically
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// canonicalParams returns a new map with the same entries. encoding/json emits
// map keys sorted, so the copy is sufficient for canonical ordering; the
// explicit sort here documents intent and guards against a future non-map type.
func canonicalParams(in map[string]string) map[string]string {
	if in == nil {
		return map[string]string{}
	}
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(map[string]string, len(in))
	for _, k := range keys {
		out[k] = in[k]
	}
	return out
}
