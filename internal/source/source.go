// Package source resolves an action's target to its live blast reach against
// real topology (the internal design spec §4.3: Resolve -> Reach). Reach is computed from what
// is actually running, never from the declared params, so a human approves the
// true blast radius.
package source

import (
	"context"

	"github.com/juridical-docker/juridical/internal/blast"
)

// Container is one live workload instance discovered from a backend.
type Container struct {
	ID      string
	Service string
	Host    string
}

// Topology is the live-topology provider. Resolve returns the containers that
// match (project, service) on the backend and the reachable inventory of like
// units (the denominator for fleet_pct). An unknown backend or an
// unevaluable/unresolvable selector returns an error so the caller can fail
// closed to a dry-run report (FC7).
type Topology interface {
	Resolve(ctx context.Context, backend, project, service string) (matched []Container, inventory int, err error)
}

// Reach folds a matched container set (and its inventory) into a blast.Reach.
// Hosts and Services are distinct counts; Instances is the matched count;
// FleetPct is matched/inventory rounded up.
func Reach(matched []Container, inventory int) blast.Reach {
	hosts := map[string]struct{}{}
	services := map[string]struct{}{}
	for _, c := range matched {
		if c.Host != "" {
			hosts[c.Host] = struct{}{}
		}
		if c.Service != "" {
			services[c.Service] = struct{}{}
		}
	}
	return blast.Reach{
		Hosts:     len(hosts),
		Services:  len(services),
		Instances: len(matched),
		FleetPct:  blast.ComputeFleetPct(len(matched), inventory),
	}
}
