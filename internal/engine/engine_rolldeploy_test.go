package engine

import (
	"context"
	"testing"

	"github.com/juridical-docker/juridical/internal/action"
	"github.com/juridical-docker/juridical/internal/approve"
	"github.com/juridical-docker/juridical/internal/audit"
	"github.com/juridical-docker/juridical/internal/blast"
	"github.com/juridical-docker/juridical/internal/source"
)

type fakeDeployer struct {
	calls   int
	lastImg string
	err     error
}

func (f *fakeDeployer) Deploy(_ context.Context, _, _, _, imageRef string) error {
	f.calls++
	f.lastImg = imageRef
	return f.err
}

func newRollEngine(t *testing.T, topo source.Topology, d action.Deployer) (*Engine, *fakeDeployer) {
	t.Helper()
	reg := action.NewRegistry()
	reg.Register(action.RollDeploy{Topo: topo, Deployer: d})
	log, err := audit.Open("")
	if err != nil {
		t.Fatal(err)
	}
	e := New(reg, approve.NewTokenStore(), log)
	e.Enforcement = blockAll
	fd, _ := d.(*fakeDeployer)
	return e, fd
}

func rollReq(image string) PlanRequest {
	return PlanRequest{
		Action: "roll-deploy", Backend: "compose", Project: "web",
		Params:        map[string]string{"service": "api", "project": "web", "image_ref": image},
		DeclaredBound: blast.DeclaredBound{MaxHosts: 1, Service: "api", FleetPct: 100},
		ProposerKeyID: "agent-key-1",
	}
}

func TestEngine_RollDeploy_HappyPath(t *testing.T) {
	e, fd := newRollEngine(t, &fakeTopo{matched: onePod(), inventory: 1}, &fakeDeployer{})
	ctx := context.Background()
	img := "example.com/acme/api@sha256:aaaa"
	p, err := e.Plan(ctx, rollReq(img))
	if err != nil || !p.Executable() {
		t.Fatalf("plan: %v executable=%v", err, p.Executable())
	}
	tok, err := e.Approve(ctx, ApproveRequest{PlanID: p.PlanID, PlanHash: p.PlanHash, Approver: "alice@sso", ApproverIsHuman: true})
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	res, err := e.Execute(ctx, ExecuteRequest{PlanID: p.PlanID, Token: tok})
	if err != nil || fd.calls != 1 || fd.lastImg != img {
		t.Fatalf("execute: %v calls=%d img=%q res=%+v", err, fd.calls, fd.lastImg, res)
	}
	recs, _ := e.Audit.Records()
	if len(recs) != 3 || recs[2].Event != audit.EventExecute {
		t.Fatalf("audit rows: %+v", recs)
	}
	if bad, err := audit.Verify(recs); err != nil {
		t.Fatalf("chain broke at %d: %v", bad, err)
	}
}

// The new image reference is part of the plan hash: a different image yields a
// different hash (so a token bound to image A can never authorize image B, T3).
func TestEngine_RollDeploy_ImageIsCoveredByPlanHash(t *testing.T) {
	e, _ := newRollEngine(t, &fakeTopo{matched: onePod(), inventory: 1}, &fakeDeployer{})
	ctx := context.Background()
	pA, _ := e.Plan(ctx, rollReq("example.com/acme/api@sha256:aaaa"))
	pB, _ := e.Plan(ctx, rollReq("example.com/acme/api@sha256:bbbb"))
	if pA.PlanHash == pB.PlanHash {
		t.Fatal("different image_ref must yield a different plan hash")
	}
	// a token minted for plan A cannot be presented against plan B's hash.
	tokA, _ := e.Approve(ctx, ApproveRequest{PlanID: pA.PlanID, PlanHash: pA.PlanHash, Approver: "alice@sso", ApproverIsHuman: true})
	if _, err := e.Tokens.Consume(tokA, pB.PlanHash); err == nil {
		t.Fatal("token bound to image A must not consume against image B's hash")
	}
}
