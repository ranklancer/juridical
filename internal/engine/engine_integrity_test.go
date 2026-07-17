package engine

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/juridical-docker/juridical/internal/audit"
)

// failingAudit wraps a real in-memory Log but forces Append to fail for one
// chosen event, simulating a durable-write failure (fsync/ENOSPC/permission)
// on that specific record.
type failingAudit struct {
	*audit.Log
	failOn audit.Event
}

func (f *failingAudit) Append(r audit.Record) (audit.Record, error) {
	if r.Event == f.failOn {
		return audit.Record{}, errors.New("simulated durable audit-write failure")
	}
	return f.Log.Append(r)
}

// A mutation must never be reported as a success if its audit record could not
// be durably persisted. The side effect may already have happened, but Execute
// must surface an integrity error rather than returning success silently.
func TestEngine_ExecuteFailsWhenAuditWriteFails(t *testing.T) {
	topo := &fakeTopo{matched: onePod(), inventory: 1}
	e, fr := newEngine(t, topo, &fakeRestarter{}, blockAll)
	base, err := audit.Open("")
	if err != nil {
		t.Fatal(err)
	}
	e.Audit = &failingAudit{Log: base, failOn: audit.EventExecute}
	ctx := context.Background()

	p, err := e.Plan(ctx, goodPlanReq())
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	tok, err := e.Approve(ctx, ApproveRequest{PlanID: p.PlanID, PlanHash: p.PlanHash, Approver: "alice@sso", ApproverIsHuman: true})
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	res, err := e.Execute(ctx, ExecuteRequest{PlanID: p.PlanID, Token: tok})
	if err == nil {
		t.Fatal("execute must fail when the audit record cannot be persisted")
	}
	if !strings.Contains(err.Error(), "audit record could not be persisted") {
		t.Fatalf("expected an integrity-violation error, got: %v", err)
	}
	if fr.calls != 1 {
		t.Fatalf("the mutation should have been attempted exactly once, got %d", fr.calls)
	}
	if res.ExecutionID != "" {
		t.Fatalf("no execution result must be returned on failure, got id=%q", res.ExecutionID)
	}
}

// Approving is the point where a one-time token is issued; issuing it without a
// durable approval record is an integrity gap, so Approve must fail closed and
// return no token.
func TestEngine_ApproveFailsWhenAuditWriteFails(t *testing.T) {
	topo := &fakeTopo{matched: onePod(), inventory: 1}
	e, _ := newEngine(t, topo, &fakeRestarter{}, blockAll)
	base, err := audit.Open("")
	if err != nil {
		t.Fatal(err)
	}
	e.Audit = &failingAudit{Log: base, failOn: audit.EventApprove}
	ctx := context.Background()

	p, err := e.Plan(ctx, goodPlanReq())
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	tok, err := e.Approve(ctx, ApproveRequest{PlanID: p.PlanID, PlanHash: p.PlanHash, Approver: "alice@sso", ApproverIsHuman: true})
	if err == nil {
		t.Fatal("approve must fail when its audit record cannot be persisted")
	}
	if tok != "" {
		t.Fatalf("no token must be returned on audit-write failure, got %q", tok)
	}
}

// A declared bound that references a dormant blast dimension must be refused at
// plan time (FC3) rather than silently dropped — the "unknown-axis rejected"
// guarantee at the engine boundary. Until the /v1 HTTP API lands (P1-d), this
// is the enforced decode-equivalent; strict JSON decoding (DisallowUnknownFields)
// is tracked for that API boundary.
func TestEngine_PlanRefusesDormantDimension(t *testing.T) {
	topo := &fakeTopo{matched: onePod(), inventory: 1}
	e, _ := newEngine(t, topo, &fakeRestarter{}, blockAll)
	req := goodPlanReq()
	req.DormantDims = []string{"namespace"}
	_, err := e.Plan(context.Background(), req)
	if err == nil {
		t.Fatal("plan must refuse a bound that references a dormant dimension (FC3)")
	}
	if !strings.Contains(err.Error(), "dormant dimension") {
		t.Fatalf("expected a dormant-dimension refusal, got: %v", err)
	}
}
