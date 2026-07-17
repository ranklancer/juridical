package action

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/juridical-docker/juridical/internal/blast"
	"github.com/juridical-docker/juridical/internal/source"
)

// Restarter performs a compose restart scoped to exactly one service.
type Restarter interface {
	Restart(ctx context.Context, backend, project, service string) error
}

// RestartService is the smallest reversible mutation and the first proof of the
// full plan -> token -> execute -> audit loop (the internal design spec §3.1). Tier M, compose.
type RestartService struct {
	Topo      source.Topology
	Restarter Restarter
}

// Name reports the action name.
func (RestartService) Name() string { return "restart-service" }

// Tier reports the mutation tier.
func (RestartService) Tier() string { return "M" }

// Backend reports the only backend supported in Phase 1.
func (RestartService) Backend() string { return "compose" }

// ValidateBound requires a single named service (FC3).
func (RestartService) ValidateBound(b blast.DeclaredBound) error {
	if strings.TrimSpace(b.Service) == "" {
		return errors.New("restart-service: bound.service must name exactly one service (FC3)")
	}
	if strings.ContainsAny(b.Service, "*?,[] ") {
		return fmt.Errorf("restart-service: bound.service %q looks like a wildcard/group; exactly one service is required (FC3)", b.Service)
	}
	return nil
}

// Resolve enumerates live containers for (project, service) and folds them into
// a reach. A wildcard/group service that resolves to more than one service is
// reflected in reach.Services (the caller's blast comparison refuses it). An
// unresolvable target returns an error so the caller fails closed (FC7).
func (a RestartService) Resolve(ctx context.Context, params map[string]string) (blast.Reach, string, error) {
	service := strings.TrimSpace(params["service"])
	project := strings.TrimSpace(params["project"])
	if service == "" || project == "" {
		return blast.Reach{}, "", errors.New("restart-service: params.service and params.project are required")
	}
	if a.Topo == nil {
		return blast.Reach{}, "", errors.New("restart-service: no topology provider wired")
	}
	matched, inventory, err := a.Topo.Resolve(ctx, a.Backend(), project, service)
	if err != nil {
		return blast.Reach{}, "", fmt.Errorf("restart-service: cannot resolve target (fail-closed, FC7): %w", err)
	}
	if len(matched) == 0 {
		return blast.Reach{}, "", fmt.Errorf("restart-service: target %s/%s resolved to no running containers (fail-closed, FC7)", project, service)
	}
	target := a.Backend() + ":" + project + "/" + service
	return source.Reach(matched, inventory), target, nil
}

// Execute restarts the one service. Idempotent-safe; no image change.
func (a RestartService) Execute(ctx context.Context, params map[string]string) (string, error) {
	service := strings.TrimSpace(params["service"])
	project := strings.TrimSpace(params["project"])
	if a.Restarter == nil {
		return "", errors.New("restart-service: no restarter wired")
	}
	if err := a.Restarter.Restart(ctx, a.Backend(), project, service); err != nil {
		return "", err
	}
	return fmt.Sprintf("restarted %s/%s on %s", project, service, a.Backend()), nil
}
