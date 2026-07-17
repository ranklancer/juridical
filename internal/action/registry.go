// Package action is the curated, finite action set (the internal design spec §3). There is no
// generic "run arbitrary command" verb by design; each action has a fixed
// Tier, a declared blast-radius bound schema, a Resolve step (target -> live
// reach) and an Execute step.
package action

import (
	"context"
	"errors"
	"sort"

	"github.com/juridical-docker/juridical/internal/blast"
)

// Action is one registered, bounded, auditable operation.
type Action interface {
	Name() string
	Tier() string    // e.g. "M" (mutating)
	Backend() string // e.g. "compose"

	// ValidateBound rejects a declared bound that is malformed for this action
	// (fail-closed, FC3).
	ValidateBound(b blast.DeclaredBound) error

	// Resolve computes the live reach for the given params and returns the
	// canonical target string. An unresolvable/ambiguous target returns an
	// error so callers fail closed to a dry-run report (FC7).
	Resolve(ctx context.Context, params map[string]string) (reach blast.Reach, target string, err error)

	// Execute performs the mutation and returns a human-readable outcome. It is
	// only ever called after a plan is within-bound, approved, and its token
	// consumed, and after an execute-time reach recheck (FC6).
	Execute(ctx context.Context, params map[string]string) (outcome string, err error)
}

// ErrUnknownAction is returned by a Registry for an unregistered name.
var ErrUnknownAction = errors.New("action: unknown action")

// Registry holds the finite set of registered actions.
type Registry struct {
	m map[string]Action
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{m: map[string]Action{}} }

// Register adds a, panicking on a duplicate name (registration is a static,
// program-startup concern).
func (r *Registry) Register(a Action) {
	if _, dup := r.m[a.Name()]; dup {
		panic("action: duplicate registration: " + a.Name())
	}
	r.m[a.Name()] = a
}

// Get returns the action by name.
func (r *Registry) Get(name string) (Action, error) {
	a, ok := r.m[name]
	if !ok {
		return nil, ErrUnknownAction
	}
	return a, nil
}

// Names returns the registered action names, sorted.
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.m))
	for n := range r.m {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
