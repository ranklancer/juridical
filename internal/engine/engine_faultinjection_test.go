package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/juridical-docker/juridical/internal/audit"
	"github.com/juridical-docker/juridical/internal/source"
)

// flakyTopo models a topology source that is reachable for the first
// (failFrom-1) Resolve calls and then becomes unreachable. failFrom is 1-based;
// failFrom==1 fails immediately, failFrom==2 fails on the execute-time recheck.
type flakyTopo struct {
	matched   []source.Container
	inventory int
	err       error
	failFrom  int
	calls     int
}

func (f *flakyTopo) Resolve(_ context.Context, _, _, _ string) ([]source.Container, int, error) {
	f.calls++
	if f.failFrom > 0 && f.calls >= f.failFrom {
		return nil, 0, f.err
	}
	return f.matched, f.inventory, nil
}

func hasRefuse(recs []audit.Record) bool {
	for _, r := range recs {
		if r.Event == audit.EventRefuse {
			return true
		}
	}
	return false
}

func approveGood(t *testing.T, e *Engine, planID, planHash string) string {
	t.Helper()
	tok, err := e.Approve(context.Background(), ApproveRequest{
		PlanID: planID, PlanHash: planHash, Approver: "alice@sso", ApproverIsHuman: true,
	})
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	return tok
}

// Fault-injection matrix: for each failed dependency the executor must fail
// CLOSED — refuse, perform NO mutation, and leave a durable refuse audit record.

// Topology unreachable at plan time -> plan fails closed, nothing mutates.
func TestEngine_Fault_TopologyUnreachableAtPlan(t *testing.T) {
	topo := &flakyTopo{matched: onePod(), inventory: 1, err: errors.New("dial topology: connection refused"), failFrom: 1}
	e, fr := newEngine(t, topo, &fakeRestarter{}, blockAll)
	if _, err := e.Plan(context.Background(), goodPlanReq()); err == nil {
		t.Fatal("plan must fail closed when the topology source is unreachable")
	}
	if fr.calls != 0 {
		t.Fatalf("no mutation may occur, restart called %d times", fr.calls)
	}
}

// Topology reachable at plan but unreachable at execute -> execute recheck
// (FC6/FC7) refuses, nothing mutates, refuse audit is written.
func TestEngine_Fault_TopologyUnreachableAtExecute(t *testing.T) {
	topo := &flakyTopo{matched: onePod(), inventory: 1, err: errors.New("dial topology: connection refused"), failFrom: 2}
	e, fr := newEngine(t, topo, &fakeRestarter{}, blockAll)
	ctx := context.Background()
	p, err := e.Plan(ctx, goodPlanReq())
	if err != nil {
		t.Fatalf("plan should succeed while topology is reachable: %v", err)
	}
	tok := approveGood(t, e, p.PlanID, p.PlanHash)
	res, err := e.Execute(ctx, ExecuteRequest{PlanID: p.PlanID, Token: tok})
	if err == nil {
		t.Fatal("execute must fail closed when topology is unreachable at execute time")
	}
	if fr.calls != 0 {
		t.Fatalf("no mutation may occur, restart called %d times", fr.calls)
	}
	if res.ExecutionID != "" {
		t.Fatalf("no execution result on failure, got id=%q", res.ExecutionID)
	}
	recs, rerr := e.Audit.Records()
	if rerr != nil {
		t.Fatal(rerr)
	}
	if !hasRefuse(recs) {
		t.Fatal("a durable refuse audit record must be written")
	}
}

// The actuator (compose restart) fails -> execute returns the error, reports no
// success, and writes a refuse audit. The mutation was ATTEMPTED once but the
// executor never claims success.
func TestEngine_Fault_ActuatorFailsClosed(t *testing.T) {
	topo := &fakeTopo{matched: onePod(), inventory: 1}
	e, fr := newEngine(t, topo, &fakeRestarter{err: errors.New("compose restart: exit status 1")}, blockAll)
	ctx := context.Background()
	p, err := e.Plan(ctx, goodPlanReq())
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	tok := approveGood(t, e, p.PlanID, p.PlanHash)
	res, err := e.Execute(ctx, ExecuteRequest{PlanID: p.PlanID, Token: tok})
	if err == nil {
		t.Fatal("execute must surface the actuator error, not report success")
	}
	if res.ExecutionID != "" {
		t.Fatalf("no success result on actuator failure, got id=%q", res.ExecutionID)
	}
	if fr.calls != 1 {
		t.Fatalf("actuator should have been attempted exactly once, got %d", fr.calls)
	}
	recs, _ := e.Audit.Records()
	if !hasRefuse(recs) {
		t.Fatal("a durable refuse audit record must be written on actuator failure")
	}
}

// Approver offline / non-human -> SoD refuses, no token is issued, and with no
// valid token execute cannot mutate.
func TestEngine_Fault_NonHumanApproverGetsNoTokenNoMutation(t *testing.T) {
	topo := &fakeTopo{matched: onePod(), inventory: 1}
	e, fr := newEngine(t, topo, &fakeRestarter{}, blockAll)
	ctx := context.Background()
	p, err := e.Plan(ctx, goodPlanReq())
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	tok, err := e.Approve(ctx, ApproveRequest{PlanID: p.PlanID, PlanHash: p.PlanHash, Approver: "automation@bot", ApproverIsHuman: false})
	if err == nil {
		t.Fatal("a non-human approver must be refused (SoD)")
	}
	if tok != "" {
		t.Fatalf("no token may be issued to a non-human approver, got %q", tok)
	}
	res, xerr := e.Execute(ctx, ExecuteRequest{PlanID: p.PlanID, Token: "deadbeefdeadbeef"})
	if xerr == nil {
		t.Fatal("execute must fail closed without a valid token")
	}
	if fr.calls != 0 {
		t.Fatalf("no mutation may occur, restart called %d times", fr.calls)
	}
	if res.ExecutionID != "" {
		t.Fatalf("no execution result, got id=%q", res.ExecutionID)
	}
}

// A forged / unknown token (token-store rejects the consume) -> execute refuses
// with no mutation.
func TestEngine_Fault_ForgedTokenFailsClosed(t *testing.T) {
	topo := &fakeTopo{matched: onePod(), inventory: 1}
	e, fr := newEngine(t, topo, &fakeRestarter{}, blockAll)
	ctx := context.Background()
	p, err := e.Plan(ctx, goodPlanReq())
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	// Approve to create a real token, but never use it — present a forgery.
	_ = approveGood(t, e, p.PlanID, p.PlanHash)
	res, xerr := e.Execute(ctx, ExecuteRequest{PlanID: p.PlanID, Token: "0000000000000000"})
	if xerr == nil {
		t.Fatal("execute must fail closed on a forged/unknown token")
	}
	if fr.calls != 0 {
		t.Fatalf("no mutation may occur, restart called %d times", fr.calls)
	}
	if res.ExecutionID != "" {
		t.Fatalf("no execution result, got id=%q", res.ExecutionID)
	}
}
