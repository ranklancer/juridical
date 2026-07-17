package action

import (
	"context"
	"errors"
	"testing"

	"github.com/juridical-docker/juridical/internal/blast"
	"github.com/juridical-docker/juridical/internal/source"
)

type stubTopo struct {
	m   []source.Container
	inv int
	err error
}

func (s stubTopo) Resolve(context.Context, string, string, string) ([]source.Container, int, error) {
	return s.m, s.inv, s.err
}

type stubRestarter struct{ err error }

func (s stubRestarter) Restart(context.Context, string, string, string) error { return s.err }

func TestRestartService_ValidateBound(t *testing.T) {
	a := RestartService{}
	if err := a.ValidateBound(blast.DeclaredBound{Service: "api"}); err != nil {
		t.Fatalf("single service ok, got %v", err)
	}
	if err := a.ValidateBound(blast.DeclaredBound{Service: ""}); err == nil {
		t.Fatal("empty service must refuse")
	}
	if err := a.ValidateBound(blast.DeclaredBound{Service: "api-*"}); err == nil {
		t.Fatal("wildcard service must refuse")
	}
}

func TestRestartService_Resolve(t *testing.T) {
	ctx := context.Background()
	base := map[string]string{"service": "api", "project": "web"}

	if _, _, err := (RestartService{}).Resolve(ctx, map[string]string{"service": "api"}); err == nil {
		t.Fatal("missing project must error")
	}
	if _, _, err := (RestartService{}).Resolve(ctx, base); err == nil {
		t.Fatal("nil topo must error")
	}
	a := RestartService{Topo: stubTopo{err: errors.New("boom")}}
	if _, _, err := a.Resolve(ctx, base); err == nil {
		t.Fatal("topo error must fail closed")
	}
	a = RestartService{Topo: stubTopo{m: nil, inv: 0}}
	if _, _, err := a.Resolve(ctx, base); err == nil {
		t.Fatal("empty match must fail closed")
	}
	a = RestartService{Topo: stubTopo{m: []source.Container{{ID: "c1", Service: "api", Host: "h1"}}, inv: 1}}
	reach, target, err := a.Resolve(ctx, base)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if reach.Services != 1 || reach.Instances != 1 || target != "compose:web/api" {
		t.Fatalf("bad reach/target: %+v %q", reach, target)
	}
}

func TestRestartService_Execute(t *testing.T) {
	ctx := context.Background()
	base := map[string]string{"service": "api", "project": "web"}
	if _, err := (RestartService{}).Execute(ctx, base); err == nil {
		t.Fatal("nil restarter must error")
	}
	if _, err := (RestartService{Restarter: stubRestarter{err: errors.New("x")}}).Execute(ctx, base); err == nil {
		t.Fatal("restarter error must propagate")
	}
	out, err := (RestartService{Restarter: stubRestarter{}}).Execute(ctx, base)
	if err != nil || out == "" {
		t.Fatalf("execute: %v %q", err, out)
	}
	if (RestartService{}).Name() != "restart-service" || (RestartService{}).Tier() != "M" || (RestartService{}).Backend() != "compose" {
		t.Fatal("metadata mismatch")
	}
}

func TestRegistry(t *testing.T) {
	r := NewRegistry()
	r.Register(RestartService{})
	if _, err := r.Get("nope"); !errors.Is(err, ErrUnknownAction) {
		t.Fatalf("unknown, got %v", err)
	}
	if a, err := r.Get("restart-service"); err != nil || a.Name() != "restart-service" {
		t.Fatalf("get: %v", err)
	}
	if names := r.Names(); len(names) != 1 || names[0] != "restart-service" {
		t.Fatalf("names: %v", names)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("duplicate registration must panic")
		}
	}()
	r.Register(RestartService{})
}
