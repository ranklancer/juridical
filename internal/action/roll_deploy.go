package action

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/juridical-docker/juridical/internal/blast"
	"github.com/juridical-docker/juridical/internal/source"
)

// Deployer rolls a single compose service to a new image reference.
type Deployer interface {
	Deploy(ctx context.Context, backend, project, service, imageRef string) error
}

// RollDeploy rolls one service to a new image (Tier M, compose). Unlike
// restart-service it changes the running image, so it is less trivially
// reversible (rollback = redeploy the prior image). It shares the same
// single-service blast bound and resolve semantics; the new image reference is
// part of the plan params and therefore covered by the plan hash, so approving
// a roll-deploy authorizes exactly one image (T3). The image is applied as-is;
// image trust (signature/provenance) is the deferred gate.ImageVerdict seam,
// off by default in v0.1.
type RollDeploy struct {
	Topo     source.Topology
	Deployer Deployer
}

// Name reports the action name.
func (RollDeploy) Name() string { return "roll-deploy" }

// Tier reports the mutation tier.
func (RollDeploy) Tier() string { return "M" }

// Backend reports the only backend supported in Phase 1.
func (RollDeploy) Backend() string { return "compose" }

// ValidateBound requires a single named service (FC3).
func (RollDeploy) ValidateBound(b blast.DeclaredBound) error {
	if strings.TrimSpace(b.Service) == "" {
		return errors.New("roll-deploy: bound.service must name exactly one service (FC3)")
	}
	if strings.ContainsAny(b.Service, "*?,[] ") {
		return fmt.Errorf("roll-deploy: bound.service %q looks like a wildcard/group; exactly one service is required (FC3)", b.Service)
	}
	return nil
}

// Resolve enumerates live containers for (project, service) and folds them into
// a reach; requires a non-empty image_ref. An unresolvable target fails closed
// (FC7). The target string embeds image_ref so any image drift changes the plan
// hash.
func (a RollDeploy) Resolve(ctx context.Context, params map[string]string) (blast.Reach, string, error) {
	service := strings.TrimSpace(params["service"])
	project := strings.TrimSpace(params["project"])
	imageRef := strings.TrimSpace(params["image_ref"])
	if service == "" || project == "" {
		return blast.Reach{}, "", errors.New("roll-deploy: params.service and params.project are required")
	}
	if imageRef == "" {
		return blast.Reach{}, "", errors.New("roll-deploy: params.image_ref is required")
	}
	if a.Topo == nil {
		return blast.Reach{}, "", errors.New("roll-deploy: no topology provider wired")
	}
	matched, inventory, err := a.Topo.Resolve(ctx, a.Backend(), project, service)
	if err != nil {
		return blast.Reach{}, "", fmt.Errorf("roll-deploy: cannot resolve target (fail-closed, FC7): %w", err)
	}
	if len(matched) == 0 {
		return blast.Reach{}, "", fmt.Errorf("roll-deploy: target %s/%s resolved to no running containers (fail-closed, FC7)", project, service)
	}
	target := a.Backend() + ":" + project + "/" + service + "@" + imageRef
	return source.Reach(matched, inventory), target, nil
}

// Execute rolls the service to the new image.
func (a RollDeploy) Execute(ctx context.Context, params map[string]string) (string, error) {
	service := strings.TrimSpace(params["service"])
	project := strings.TrimSpace(params["project"])
	imageRef := strings.TrimSpace(params["image_ref"])
	if imageRef == "" {
		return "", errors.New("roll-deploy: params.image_ref is required")
	}
	if a.Deployer == nil {
		return "", errors.New("roll-deploy: no deployer wired")
	}
	if err := a.Deployer.Deploy(ctx, a.Backend(), project, service, imageRef); err != nil {
		return "", err
	}
	return fmt.Sprintf("rolled %s/%s to %s on %s", project, service, imageRef, a.Backend()), nil
}
