package engine

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/juridical-docker/juridical/internal/action"
	"github.com/juridical-docker/juridical/internal/approve"
	"github.com/juridical-docker/juridical/internal/audit"
	"github.com/juridical-docker/juridical/internal/blast"
	"github.com/juridical-docker/juridical/internal/source"
)

// fakeTopo returns a preset matched set / inventory / error.
type fakeTopo struct {
	matched   []source.Container
	inventory int
	err       error
	calls     int
}

func (f *fakeTopo) Resolve(_ context.Context, _, _, _ string) ([]source.Container, int, error) {
	f.calls++
	return f.matched, f.inventory, f.err
}

// fakeRestarter records restart calls.
type fakeRestarter struct {
	calls int
	err   error
}

func (f *fakeRestarter) Restart(_ context.Context, _, _, _ string) error {
	f.calls++
	return f.err
}

func newEngine(t *testing.T, topo source.Topology, r action.Restarter, enf blast.Enforcement) (*Engine, *fakeRestarter) {
	t.Helper()
	reg := action.NewRegistry()
	fr, _ := r.(*fakeRestarter)
	reg.Register(action.RestartService{Topo: topo, Restarter: r})
	log, err := audit.Open("")
	if err != nil {
		t.Fatal(err)
	}
	e := New(reg, approve.NewTokenStore(), log)
	e.Enforcement = enf
	return e, fr
}

func onePod() []source.Container {
	return []source.Container{{ID: "c1", Service: "api", Host: "h1"}}
}

var blockAll = blast.Enforcement{MaxHosts: blast.ModeBlock, Service: blast.ModeBlock, FleetPct: blast.ModeBlock}

func goodPlanReq() PlanRequest {
	return PlanRequest{
		Action: "restart-service", Backend: "compose", Project: "web",
		Params:        map[string]string{"service": "api", "project": "web"},
		DeclaredBound: blast.DeclaredBound{MaxHosts: 1, Service: "api", FleetPct: 100},
		ProposerKeyID: "agent-key-1",
	}
}

func TestEngine_HappyPath_PlanApproveExecuteAudit(t *testing.T) {
	topo := &fakeTopo{matched: onePod(), inventory: 1}
	e, fr := newEngine(t, topo, &fakeRestarter{}, blockAll)
	ctx := context.Background()

	p, err := e.Plan(ctx, goodPlanReq())
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if !p.WithinBound || p.Verdict != blast.VerdictAllow || !p.Executable() {
		t.Fatalf("plan should be within-bound/allow/executable: %+v", p)
	}
	tok, err := e.Approve(ctx, ApproveRequest{PlanID: p.PlanID, PlanHash: p.PlanHash, Approver: "alice@sso", ApproverIsHuman: true})
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	res, err := e.Execute(ctx, ExecuteRequest{PlanID: p.PlanID, Token: tok})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if res.Verdict != blast.VerdictAllow || fr.calls != 1 {
		t.Fatalf("execute must restart once: res=%+v restarts=%d", res, fr.calls)
	}
	// audit chain: plan, approve, execute; intact and redaction-safe.
	recs, _ := e.Audit.Records()
	if len(recs) != 3 {
		t.Fatalf("want 3 audit rows, got %d", len(recs))
	}
	if recs[0].Event != audit.EventPlan || recs[1].Event != audit.EventApprove || recs[2].Event != audit.EventExecute {
		t.Fatalf("unexpected event order: %v", []audit.Event{recs[0].Event, recs[1].Event, recs[2].Event})
	}
	if bad, err := audit.Verify(recs); err != nil {
		t.Fatalf("audit chain broken at %d: %v", bad, err)
	}
	if recs[2].Approver != "alice@sso" || recs[2].ProposerKeyID != "agent-key-1" {
		t.Fatalf("execute row must carry dual identity: %+v", recs[2])
	}
}

// Adversarial #1: over-reach refused in Block mode.
func TestEngine_Adversarial_OverReachRefusedInBlock(t *testing.T) {
	// two distinct services resolved -> services=2 -> service-axis breach.
	topo := &fakeTopo{matched: []source.Container{
		{ID: "c1", Service: "api", Host: "h1"},
		{ID: "c2", Service: "api-worker", Host: "h2"},
	}, inventory: 2}
	e, _ := newEngine(t, topo, &fakeRestarter{}, blockAll)
	p, err := e.Plan(context.Background(), goodPlanReq())
	if err != nil {
		t.Fatalf("plan should still render (visibility): %v", err)
	}
	if p.WithinBound || p.Verdict != blast.VerdictBlock || p.Executable() {
		t.Fatalf("over-reach plan must be BLOCK/not-executable: %+v", p)
	}
	// approving a non-executable plan is refused.
	if _, err := e.Approve(context.Background(), ApproveRequest{PlanID: p.PlanID, PlanHash: p.PlanHash, Approver: "alice@sso", ApproverIsHuman: true}); err == nil {
		t.Fatal("must refuse approval of an over-bound plan")
	}
}

// Adversarial #2: automation cannot approve its own proposal (SoD).
func TestEngine_Adversarial_SelfApprovalRefused(t *testing.T) {
	e, _ := newEngine(t, &fakeTopo{matched: onePod(), inventory: 1}, &fakeRestarter{}, blockAll)
	p, _ := e.Plan(context.Background(), goodPlanReq())
	// same identity as proposer, and marked non-human.
	if _, err := e.Approve(context.Background(), ApproveRequest{PlanID: p.PlanID, PlanHash: p.PlanHash, Approver: "agent-key-1", ApproverIsHuman: false}); !errors.Is(err, approve.ErrNotHuman) {
		t.Fatalf("automation self-approval must be refused (ErrNotHuman), got %v", err)
	}
	// even a human whose principal collides with the proposer is refused.
	if _, err := e.Approve(context.Background(), ApproveRequest{PlanID: p.PlanID, PlanHash: p.PlanHash, Approver: "agent-key-1", ApproverIsHuman: true}); !errors.Is(err, approve.ErrSelfApproval) {
		t.Fatalf("approver==proposer must be refused (ErrSelfApproval), got %v", err)
	}
}

// Adversarial #3: plan-hash drift invalidates the token.
func TestEngine_Adversarial_HashDriftInvalidatesToken(t *testing.T) {
	e, _ := newEngine(t, &fakeTopo{matched: onePod(), inventory: 1}, &fakeRestarter{}, blockAll)
	p, _ := e.Plan(context.Background(), goodPlanReq())
	// approve with a mismatched hash -> refused at mint time.
	if _, err := e.Approve(context.Background(), ApproveRequest{PlanID: p.PlanID, PlanHash: p.PlanHash + "00", Approver: "alice@sso", ApproverIsHuman: true}); !errors.Is(err, approve.ErrHashMismatch) {
		t.Fatalf("hash drift must be refused (ErrHashMismatch), got %v", err)
	}
}

// Adversarial #4: expired/reused token rejected.
func TestEngine_Adversarial_ExpiredAndReusedToken(t *testing.T) {
	e, fr := newEngine(t, &fakeTopo{matched: onePod(), inventory: 1}, &fakeRestarter{}, blockAll)
	ctx := context.Background()

	// reuse: consume once (ok), then again (rejected).
	p, _ := e.Plan(ctx, goodPlanReq())
	tok, _ := e.Approve(ctx, ApproveRequest{PlanID: p.PlanID, PlanHash: p.PlanHash, Approver: "alice@sso", ApproverIsHuman: true})
	if _, err := e.Execute(ctx, ExecuteRequest{PlanID: p.PlanID, Token: tok}); err != nil {
		t.Fatalf("first execute: %v", err)
	}
	if _, err := e.Execute(ctx, ExecuteRequest{PlanID: p.PlanID, Token: tok}); !errors.Is(err, approve.ErrTokenConsumed) {
		t.Fatalf("token reuse must be rejected (ErrTokenConsumed), got %v", err)
	}
	if fr.calls != 1 {
		t.Fatalf("reuse must not execute a second time: restarts=%d", fr.calls)
	}

	// expiry: mint with a store clock pushed past TTL.
	e.TokenTTL = 1 * time.Millisecond
	p2, _ := e.Plan(ctx, goodPlanReq())
	tok2, _ := e.Approve(ctx, ApproveRequest{PlanID: p2.PlanID, PlanHash: p2.PlanHash, Approver: "alice@sso", ApproverIsHuman: true})
	time.Sleep(3 * time.Millisecond)
	if _, err := e.Execute(ctx, ExecuteRequest{PlanID: p2.PlanID, Token: tok2}); !errors.Is(err, approve.ErrTokenExpired) {
		t.Fatalf("expired token must be rejected (ErrTokenExpired), got %v", err)
	}
}

// Adversarial #5: ambiguous target -> dry-run report, never execute (FC7).
func TestEngine_Adversarial_AmbiguousTargetFailsClosed(t *testing.T) {
	e, fr := newEngine(t, &fakeTopo{err: errors.New("selector cannot be evaluated")}, &fakeRestarter{}, blockAll)
	_, err := e.Plan(context.Background(), goodPlanReq())
	if err == nil || !strings.Contains(err.Error(), "FC7") {
		t.Fatalf("ambiguous target must fail closed (FC7), got %v", err)
	}
	if fr.calls != 0 {
		t.Fatalf("ambiguous target must never execute: restarts=%d", fr.calls)
	}
	// a refuse row was written.
	recs, _ := e.Audit.Records()
	if len(recs) != 1 || recs[0].Event != audit.EventRefuse {
		t.Fatalf("ambiguous target must append a refuse row: %+v", recs)
	}
}

// FC6: execute-time recheck refuses when live reach grows after approval.
func TestEngine_Adversarial_ExecuteTimeRecheckRefuses(t *testing.T) {
	topo := &fakeTopo{matched: onePod(), inventory: 1}
	e, fr := newEngine(t, topo, &fakeRestarter{}, blockAll)
	ctx := context.Background()
	p, _ := e.Plan(ctx, goodPlanReq())
	tok, _ := e.Approve(ctx, ApproveRequest{PlanID: p.PlanID, PlanHash: p.PlanHash, Approver: "alice@sso", ApproverIsHuman: true})
	// topology grows between approval and execute: now spans 2 hosts + 2 services.
	topo.matched = []source.Container{
		{ID: "c1", Service: "api", Host: "h1"},
		{ID: "c2", Service: "api", Host: "h2"},
		{ID: "c3", Service: "api-canary", Host: "h3"},
	}
	topo.inventory = 3
	if _, err := e.Execute(ctx, ExecuteRequest{PlanID: p.PlanID, Token: tok}); err == nil || !strings.Contains(err.Error(), "FC6") {
		t.Fatalf("execute-time over-bound must refuse (FC6), got %v", err)
	}
	if fr.calls != 0 {
		t.Fatalf("FC6 refusal must not execute: restarts=%d", fr.calls)
	}
}
