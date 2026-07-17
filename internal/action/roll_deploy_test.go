package action

import (
	"context"
	"errors"
	"testing"

	"github.com/juridical-docker/juridical/internal/blast"
	"github.com/juridical-docker/juridical/internal/source"
)

type stubDeployer struct {
	err   error
	calls int
}

func (s *stubDeployer) Deploy(context.Context, string, string, string, string) error {
	s.calls++
	return s.err
}

func TestRollDeploy_Metadata(t *testing.T) {
	if (RollDeploy{}).Name() != "roll-deploy" || (RollDeploy{}).Tier() != "M" || (RollDeploy{}).Backend() != "compose" {
		t.Fatal("metadata mismatch")
	}
}

func TestRollDeploy_ValidateBound(t *testing.T) {
	a := RollDeploy{}
	if err := a.ValidateBound(blast.DeclaredBound{Service: "api"}); err != nil {
		t.Fatalf("single service ok, got %v", err)
	}
	if err := a.ValidateBound(blast.DeclaredBound{Service: ""}); err == nil {
		t.Fatal("empty service must refuse")
	}
	if err := a.ValidateBound(blast.DeclaredBound{Service: "api,worker"}); err == nil {
		t.Fatal("group service must refuse")
	}
}

func TestRollDeploy_Resolve(t *testing.T) {
	ctx := context.Background()
	full := map[string]string{"service": "api", "project": "web", "image_ref": "example.com/acme/api@sha256:abc"}

	if _, _, err := (RollDeploy{}).Resolve(ctx, map[string]string{"service": "api", "project": "web"}); err == nil {
		t.Fatal("missing image_ref must error")
	}
	if _, _, err := (RollDeploy{}).Resolve(ctx, map[string]string{"image_ref": "x", "project": "web"}); err == nil {
		t.Fatal("missing service must error")
	}
	if _, _, err := (RollDeploy{}).Resolve(ctx, full); err == nil {
		t.Fatal("nil topo must error")
	}
	a := RollDeploy{Topo: stubTopo{err: errors.New("boom")}}
	if _, _, err := a.Resolve(ctx, full); err == nil {
		t.Fatal("topo error must fail closed")
	}
	a = RollDeploy{Topo: stubTopo{m: nil, inv: 0}}
	if _, _, err := a.Resolve(ctx, full); err == nil {
		t.Fatal("empty match must fail closed")
	}
	a = RollDeploy{Topo: stubTopo{m: []source.Container{{ID: "c1", Service: "api", Host: "h1"}}, inv: 1}}
	reach, target, err := a.Resolve(ctx, full)
	if err != nil || reach.Instances != 1 || target != "compose:web/api@example.com/acme/api@sha256:abc" {
		t.Fatalf("resolve: %v reach=%+v target=%q", err, reach, target)
	}
}

func TestRollDeploy_Execute(t *testing.T) {
	ctx := context.Background()
	full := map[string]string{"service": "api", "project": "web", "image_ref": "example.com/acme/api@sha256:abc"}
	if _, err := (RollDeploy{}).Execute(ctx, map[string]string{"service": "api", "project": "web"}); err == nil {
		t.Fatal("missing image_ref must error")
	}
	if _, err := (RollDeploy{}).Execute(ctx, full); err == nil {
		t.Fatal("nil deployer must error")
	}
	if _, err := (RollDeploy{Deployer: &stubDeployer{err: errors.New("x")}}).Execute(ctx, full); err == nil {
		t.Fatal("deployer error must propagate")
	}
	d := &stubDeployer{}
	out, err := (RollDeploy{Deployer: d}).Execute(ctx, full)
	if err != nil || out == "" || d.calls != 1 {
		t.Fatalf("execute: %v %q calls=%d", err, out, d.calls)
	}
}
