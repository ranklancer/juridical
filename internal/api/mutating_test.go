package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/juridical-docker/juridical/internal/action"
	"github.com/juridical-docker/juridical/internal/approve"
	"github.com/juridical-docker/juridical/internal/audit"
	"github.com/juridical-docker/juridical/internal/blast"
	"github.com/juridical-docker/juridical/internal/engine"
	"github.com/juridical-docker/juridical/internal/source"
)

// ---- test fixtures: a real engine wired to a fake topology/restarter ----
// (mirrors internal/engine's own test doubles; kept local since those are
// unexported in that package.)

type fakeTopo struct {
	matched   []source.Container
	inventory int
	err       error
}

func (f *fakeTopo) Resolve(_ context.Context, _, _, _ string) ([]source.Container, int, error) {
	return f.matched, f.inventory, f.err
}

type fakeRestarter struct {
	calls int
	err   error
}

func (f *fakeRestarter) Restart(_ context.Context, _, _, _ string) error {
	f.calls++
	return f.err
}

func onePod() []source.Container {
	return []source.Container{{ID: "c1", Service: "api", Host: "h1"}}
}

// mutatingServer builds a Server backed by a real *engine.Engine (warn-mode
// enforcement so a routine plan is executable) plus a fake actuator, so
// these tests exercise the true HTTP -> engine -> audit path end to end.
func mutatingServer(t *testing.T) (*Server, *fakeRestarter, *audit.Log) {
	t.Helper()
	keys := NewStaticKeyStore()
	keys.Add("proposer-key", "auto-1", ScopeOrchestrator)
	keys.Add("operator-key", "auto-2", ScopeOperator)

	reg := action.NewRegistry()
	fr := &fakeRestarter{}
	reg.Register(action.RestartService{Topo: &fakeTopo{matched: onePod(), inventory: 1}, Restarter: fr})

	log, err := audit.Open("")
	if err != nil {
		t.Fatal(err)
	}
	eng := engine.New(reg, approve.NewTokenStore(), log)
	eng.Enforcement = blast.Enforcement{MaxHosts: blast.ModeBlock, Service: blast.ModeBlock, FleetPct: blast.ModeBlock}

	srv := New(Config{Audit: log, Authn: keys, Engine: eng, HumanHeader: "X-Forwarded-User"})
	return srv, fr, log
}

func planBody() string {
	return `{"action":"restart-service","backend":"compose","project":"web","params":{"service":"api","project":"web"},"declared_bound":{"max_hosts":1,"service":"api","fleet_pct":100}}`
}

type planResp struct {
	PlanID   string `json:"plan_id"`
	PlanHash string `json:"plan_hash"`
}

type approveResp struct {
	Token string `json:"token"`
}

type executeResp struct {
	ExecutionID string `json:"execution_id"`
	Verdict     string `json:"verdict"`
}

func mustPlan(t *testing.T, s *Server, bearer string) planResp {
	t.Helper()
	w := do(s, "POST", "/v1/plans", map[string]string{"Authorization": "Bearer " + bearer, "Content-Type": "application/json"}, planBody())
	if w.Code != http.StatusOK {
		t.Fatalf("plan: status=%d body=%s", w.Code, w.Body.String())
	}
	var p planResp
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatalf("plan: decode: %v body=%s", err, w.Body.String())
	}
	return p
}

// ---- 1. happy path: create -> approve -> execute, distinct human actors ----

func TestMutating_HappyPath_PlanApproveExecute_AuditChainWithHumanActors(t *testing.T) {
	s, fr, log := mutatingServer(t)

	p := mustPlan(t, s, "proposer-key")

	approveBody := `{"plan_id":"` + p.PlanID + `","plan_hash":"` + p.PlanHash + `","reason":"routine restart"}`
	wa := do(s, "POST", "/v1/approvals", map[string]string{"X-Forwarded-User": "alice@example.com", "Content-Type": "application/json"}, approveBody)
	if wa.Code != http.StatusOK {
		t.Fatalf("approve: status=%d body=%s", wa.Code, wa.Body.String())
	}
	var ar approveResp
	if err := json.Unmarshal(wa.Body.Bytes(), &ar); err != nil {
		t.Fatalf("approve: decode: %v", err)
	}
	if ar.Token == "" {
		t.Fatal("approve: expected a non-empty token")
	}

	execBody := `{"plan_id":"` + p.PlanID + `","token":"` + ar.Token + `"}`
	we := do(s, "POST", "/v1/executions", map[string]string{"Authorization": "Bearer operator-key", "Content-Type": "application/json"}, execBody)
	if we.Code != http.StatusOK {
		t.Fatalf("execute: status=%d body=%s", we.Code, we.Body.String())
	}
	var er executeResp
	if err := json.Unmarshal(we.Body.Bytes(), &er); err != nil {
		t.Fatalf("execute: decode: %v", err)
	}
	if er.Verdict != "ALLOW" || fr.calls != 1 {
		t.Fatalf("execute must restart exactly once: verdict=%s calls=%d", er.Verdict, fr.calls)
	}

	recs, err := log.Records()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 3 {
		t.Fatalf("want 3 audit rows, got %d: %+v", len(recs), recs)
	}
	if recs[0].Event != audit.EventPlan || recs[1].Event != audit.EventApprove || recs[2].Event != audit.EventExecute {
		t.Fatalf("unexpected event order: %v/%v/%v", recs[0].Event, recs[1].Event, recs[2].Event)
	}
	if bad, err := audit.Verify(recs); err != nil {
		t.Fatalf("audit chain broken at %d: %v", bad, err)
	}
	// Distinct human actors: proposer is the automation key id, approver is
	// the human forward-auth identity — never the same identity class.
	if recs[1].ProposerKeyID != "auto-1" || recs[1].Approver != "alice@example.com" {
		t.Fatalf("approve row must carry dual identity: %+v", recs[1])
	}
	if recs[2].ProposerKeyID != "auto-1" || recs[2].Approver != "alice@example.com" {
		t.Fatalf("execute row must carry dual identity: %+v", recs[2])
	}
}

// ---- 2. execute without approval fails closed ----

func TestMutating_Execute_WithoutApproval_FailsClosed(t *testing.T) {
	s, fr, _ := mutatingServer(t)
	p := mustPlan(t, s, "proposer-key")

	execBody := `{"plan_id":"` + p.PlanID + `","token":"0000000000000000000000000000000000000000000000000000000000000000"}`
	w := do(s, "POST", "/v1/executions", map[string]string{"Authorization": "Bearer operator-key", "Content-Type": "application/json"}, execBody)
	if w.Code != http.StatusConflict {
		t.Fatalf("status=%d want 409, body=%s", w.Code, w.Body.String())
	}
	if fr.calls != 0 {
		t.Fatalf("no restart may occur without a valid approval: calls=%d", fr.calls)
	}
}

// ---- 3. SoD: approver == proposer is refused, no state change ----

func TestMutating_Approve_BySameIdentityAsProposer_SoD403(t *testing.T) {
	s, fr, log := mutatingServer(t)
	p := mustPlan(t, s, "proposer-key")

	// The human forward-auth identity happens to collide with the
	// automation proposer's key id — SoD must still refuse it.
	approveBody := `{"plan_id":"` + p.PlanID + `","plan_hash":"` + p.PlanHash + `"}`
	w := do(s, "POST", "/v1/approvals", map[string]string{"X-Forwarded-User": "auto-1", "Content-Type": "application/json"}, approveBody)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403, body=%s", w.Code, w.Body.String())
	}
	if got := decodeErr(t, w).Code; got != "sod_violation" {
		t.Errorf("code=%q want sod_violation", got)
	}
	if strings.Contains(w.Body.String(), `"token"`) {
		t.Fatalf("no token may leak from a refused approval: %s", w.Body.String())
	}
	recs, _ := log.Records()
	for _, r := range recs {
		if r.Event == audit.EventApprove {
			t.Fatalf("SoD violation must not mint/record an approval: %+v", r)
		}
	}
	if fr.calls != 0 {
		t.Fatalf("no restart may occur: calls=%d", fr.calls)
	}
}

// ---- 4. one-time approval token: second use fails closed ----

func TestMutating_ApprovalToken_ReuseFailsClosed(t *testing.T) {
	s, fr, _ := mutatingServer(t)
	p := mustPlan(t, s, "proposer-key")
	approveBody := `{"plan_id":"` + p.PlanID + `","plan_hash":"` + p.PlanHash + `"}`
	wa := do(s, "POST", "/v1/approvals", map[string]string{"X-Forwarded-User": "alice@example.com", "Content-Type": "application/json"}, approveBody)
	var ar approveResp
	_ = json.Unmarshal(wa.Body.Bytes(), &ar)

	execBody := `{"plan_id":"` + p.PlanID + `","token":"` + ar.Token + `"}`
	we1 := do(s, "POST", "/v1/executions", map[string]string{"Authorization": "Bearer operator-key", "Content-Type": "application/json"}, execBody)
	if we1.Code != http.StatusOK {
		t.Fatalf("first execute: status=%d body=%s", we1.Code, we1.Body.String())
	}
	we2 := do(s, "POST", "/v1/executions", map[string]string{"Authorization": "Bearer operator-key", "Content-Type": "application/json"}, execBody)
	if we2.Code != http.StatusConflict {
		t.Fatalf("reused token: status=%d want 409, body=%s", we2.Code, we2.Body.String())
	}
	if fr.calls != 1 {
		t.Fatalf("reuse must not execute a second time: calls=%d", fr.calls)
	}
}

// ---- 5. cross-plan token reuse == plan_hash mismatch at execute ----

func mustPlanWithBody(t *testing.T, s *Server, bearer, body string) planResp {
	t.Helper()
	w := do(s, "POST", "/v1/plans", map[string]string{"Authorization": "Bearer " + bearer, "Content-Type": "application/json"}, body)
	if w.Code != http.StatusOK {
		t.Fatalf("plan: status=%d body=%s", w.Code, w.Body.String())
	}
	var p planResp
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatalf("plan: decode: %v body=%s", err, w.Body.String())
	}
	return p
}

func TestMutating_CrossPlanTokenReuse_HashMismatch_FailsClosed(t *testing.T) {
	s, fr, _ := mutatingServer(t)

	// Two plans with genuinely different content (distinct project) so their
	// plan_hash values differ; the fake topology ignores project/service and
	// still resolves both, so both plans render successfully.
	bodyA := `{"action":"restart-service","backend":"compose","project":"web-a","params":{"service":"api","project":"web-a"},"declared_bound":{"max_hosts":1,"service":"api","fleet_pct":100}}`
	bodyB := `{"action":"restart-service","backend":"compose","project":"web-b","params":{"service":"api","project":"web-b"},"declared_bound":{"max_hosts":1,"service":"api","fleet_pct":100}}`
	pA := mustPlanWithBody(t, s, "proposer-key", bodyA)
	pB := mustPlanWithBody(t, s, "proposer-key", bodyB)
	if pA.PlanHash == pB.PlanHash {
		t.Fatalf("test setup invalid: plan A and B must hash differently (A=%s B=%s)", pA.PlanHash, pB.PlanHash)
	}

	approveBodyA := `{"plan_id":"` + pA.PlanID + `","plan_hash":"` + pA.PlanHash + `"}`
	wa := do(s, "POST", "/v1/approvals", map[string]string{"X-Forwarded-User": "alice@example.com", "Content-Type": "application/json"}, approveBodyA)
	var ar approveResp
	_ = json.Unmarshal(wa.Body.Bytes(), &ar)

	// Token minted for plan A, presented against plan B's id: the token is
	// bound to plan A's hash, which does not match plan B's -> refused.
	execBody := `{"plan_id":"` + pB.PlanID + `","token":"` + ar.Token + `"}`
	w := do(s, "POST", "/v1/executions", map[string]string{"Authorization": "Bearer operator-key", "Content-Type": "application/json"}, execBody)
	if w.Code != http.StatusConflict {
		t.Fatalf("status=%d want 409 (plan_hash mismatch), body=%s", w.Code, w.Body.String())
	}
	if fr.calls != 0 {
		t.Fatalf("a hash-mismatched token must never execute: calls=%d", fr.calls)
	}
}

// ---- 6. missing forward-auth identity on /v1/approvals fails closed ----

func TestMutating_MissingForwardAuthIdentity_Approvals_FailsClosed(t *testing.T) {
	s, _, log := mutatingServer(t)
	p := mustPlan(t, s, "proposer-key")

	approveBody := `{"plan_id":"` + p.PlanID + `","plan_hash":"` + p.PlanHash + `"}`
	w := do(s, "POST", "/v1/approvals", map[string]string{"Content-Type": "application/json"}, approveBody)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401, body=%s", w.Code, w.Body.String())
	}
	if got := decodeErr(t, w).Code; got != "unauthenticated" {
		t.Errorf("code=%q want unauthenticated", got)
	}
	recs, _ := log.Records()
	for _, r := range recs {
		if r.Event == audit.EventApprove {
			t.Fatalf("no domain call may occur without a human identity: %+v", r)
		}
	}
}

// ---- 7. missing/insufficient automation key on plans & executions ----

func TestMutating_Plans_MissingKey_FailsClosed_NoDomainCall(t *testing.T) {
	s, _, log := mutatingServer(t)
	w := do(s, "POST", "/v1/plans", map[string]string{"Content-Type": "application/json"}, planBody())
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401, body=%s", w.Code, w.Body.String())
	}
	recs, _ := log.Records()
	if len(recs) != 0 {
		t.Fatalf("no domain call may occur without a key: %+v", recs)
	}
}

func TestMutating_Executions_InsufficientScope_FailsClosed_NoDomainCall(t *testing.T) {
	s, fr, _ := mutatingServer(t)
	keys := NewStaticKeyStore()
	keys.Add("observer-only", "auto-3", ScopeObserver)
	// rebuild a server sharing the same underlying engine's registry is not
	// possible via the public API, so this asserts the scope gate directly:
	// an orchestrator-scope key (which can plan but not execute) must be
	// refused at /v1/executions.
	p := mustPlan(t, s, "proposer-key")
	w := do(s, "POST", "/v1/executions", map[string]string{"Authorization": "Bearer proposer-key", "Content-Type": "application/json"}, `{"plan_id":"`+p.PlanID+`","token":"deadbeef"}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403, body=%s", w.Code, w.Body.String())
	}
	if got := decodeErr(t, w).Code; got != "scope_denied" {
		t.Errorf("code=%q want scope_denied", got)
	}
	if fr.calls != 0 {
		t.Fatalf("no restart may occur: calls=%d", fr.calls)
	}
	_ = keys
}

// ---- 8. audit-write failure at execute -> 500, no reported success ----

type failingAudit struct {
	*audit.Log
	failOn audit.Event
}

func (f *failingAudit) Append(r audit.Record) (audit.Record, error) {
	if r.Event == f.failOn {
		return audit.Record{}, errors.New("simulated durable audit-write failure: disk full at /var/lib/juridical/audit.jsonl")
	}
	return f.Log.Append(r)
}

func TestMutating_AuditWriteFailureAtExecute_500_NoReportedSuccessOrLeak(t *testing.T) {
	keys := NewStaticKeyStore()
	keys.Add("proposer-key", "auto-1", ScopeOrchestrator)
	keys.Add("operator-key", "auto-2", ScopeOperator)

	reg := action.NewRegistry()
	fr := &fakeRestarter{}
	reg.Register(action.RestartService{Topo: &fakeTopo{matched: onePod(), inventory: 1}, Restarter: fr})

	base, err := audit.Open("")
	if err != nil {
		t.Fatal(err)
	}
	failing := &failingAudit{Log: base, failOn: audit.EventExecute}
	eng := engine.New(reg, approve.NewTokenStore(), base)
	eng.Enforcement = blast.Enforcement{MaxHosts: blast.ModeBlock, Service: blast.ModeBlock, FleetPct: blast.ModeBlock}
	eng.Audit = failing

	s := New(Config{Audit: failing, Authn: keys, Engine: eng, HumanHeader: "X-Forwarded-User"})

	p := mustPlan(t, s, "proposer-key")
	approveBody := `{"plan_id":"` + p.PlanID + `","plan_hash":"` + p.PlanHash + `"}`
	wa := do(s, "POST", "/v1/approvals", map[string]string{"X-Forwarded-User": "alice@example.com", "Content-Type": "application/json"}, approveBody)
	var ar approveResp
	_ = json.Unmarshal(wa.Body.Bytes(), &ar)
	if ar.Token == "" {
		t.Fatalf("approve should succeed here: %s", wa.Body.String())
	}

	execBody := `{"plan_id":"` + p.PlanID + `","token":"` + ar.Token + `"}`
	we := do(s, "POST", "/v1/executions", map[string]string{"Authorization": "Bearer operator-key", "Content-Type": "application/json"}, execBody)
	if we.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500, body=%s", we.Code, we.Body.String())
	}
	ee := decodeErr(t, we)
	if ee.Code != "internal_error" {
		t.Errorf("code=%q want internal_error", ee.Code)
	}
	leak := []string{"simulated durable audit-write failure", "disk full", "/var/lib", ".go:", "goroutine"}
	for _, marker := range leak {
		if strings.Contains(we.Body.String(), marker) {
			t.Fatalf("zero-leak violated: response body contains internal detail %q: %s", marker, we.Body.String())
		}
	}
	recs, _ := failing.Log.Records()
	for _, r := range recs {
		if r.Event == audit.EventExecute {
			t.Fatalf("execute must never leave a successful audit row when its own write failed: %+v", r)
		}
	}
}

// ---- 9. oversized body / wrong content type (reuse of P1-d-1 guards) ----

func TestMutating_OversizedBody_413(t *testing.T) {
	s, _, _ := mutatingServer(t)
	huge := strings.Repeat("a", int(MaxBodyBytes)+1)
	body := `{"action":"restart-service","backend":"compose","project":"web","params":{"pad":"` + huge + `"},"declared_bound":{"max_hosts":1,"service":"api","fleet_pct":100}}`
	w := do(s, "POST", "/v1/plans", map[string]string{"Authorization": "Bearer proposer-key", "Content-Type": "application/json"}, body)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d want 413, body=%s", w.Code, w.Body.String())
	}
}

func TestMutating_WrongContentType_415(t *testing.T) {
	s, _, _ := mutatingServer(t)
	w := do(s, "POST", "/v1/plans", map[string]string{"Authorization": "Bearer proposer-key", "Content-Type": "text/plain"}, planBody())
	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status=%d want 415, body=%s", w.Code, w.Body.String())
	}
}

// ---- 10. tampered/malformed bound and unknown action fail closed ----

func TestMutating_DormantDimensionInBound_FailsClosed(t *testing.T) {
	s, _, _ := mutatingServer(t)
	body := `{"action":"restart-service","backend":"compose","project":"web","params":{"service":"api","project":"web"},"declared_bound":{"max_hosts":1,"service":"api","fleet_pct":100,"namespace":"prod"}}`
	w := do(s, "POST", "/v1/plans", map[string]string{"Authorization": "Bearer proposer-key", "Content-Type": "application/json"}, body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 (dormant dimension), body=%s", w.Code, w.Body.String())
	}
}

func TestMutating_UnknownAction_400(t *testing.T) {
	s, _, _ := mutatingServer(t)
	body := `{"action":"delete-everything","backend":"compose","project":"web","params":{},"declared_bound":{"max_hosts":1,"service":"api","fleet_pct":100}}`
	w := do(s, "POST", "/v1/plans", map[string]string{"Authorization": "Bearer proposer-key", "Content-Type": "application/json"}, body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400, body=%s", w.Code, w.Body.String())
	}
}

func TestMutating_TrailingDataAfterJSON_400(t *testing.T) {
	s, _, _ := mutatingServer(t)
	body := planBody() + `{"evil":true}`
	w := do(s, "POST", "/v1/plans", map[string]string{"Authorization": "Bearer proposer-key", "Content-Type": "application/json"}, body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 (trailing data), body=%s", w.Code, w.Body.String())
	}
}

func TestMutating_UnknownFieldInRequest_400(t *testing.T) {
	s, _, _ := mutatingServer(t)
	body := `{"action":"restart-service","backend":"compose","project":"web","params":{"service":"api","project":"web"},"declared_bound":{"max_hosts":1,"service":"api","fleet_pct":100},"unexpected_field":true}`
	w := do(s, "POST", "/v1/plans", map[string]string{"Authorization": "Bearer proposer-key", "Content-Type": "application/json"}, body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 (unknown field), body=%s", w.Code, w.Body.String())
	}
}

// ---- 11. zero-leak: error bodies are only the generic envelope ----

func TestMutating_ZeroLeak_ErrorBodiesAreEnvelopeOnly(t *testing.T) {
	s, _, _ := mutatingServer(t)
	p := mustPlan(t, s, "proposer-key")

	cases := []struct {
		name   string
		method string
		path   string
		hdr    map[string]string
		body   string
	}{
		{"approve-missing-human", "POST", "/v1/approvals", map[string]string{"Content-Type": "application/json"}, `{"plan_id":"` + p.PlanID + `","plan_hash":"` + p.PlanHash + `"}`},
		{"execute-bad-token", "POST", "/v1/executions", map[string]string{"Authorization": "Bearer operator-key", "Content-Type": "application/json"}, `{"plan_id":"` + p.PlanID + `","token":"bogus"}`},
		{"plans-bad-action", "POST", "/v1/plans", map[string]string{"Authorization": "Bearer proposer-key", "Content-Type": "application/json"}, `{"action":"nope","backend":"compose","project":"web","params":{},"declared_bound":{"max_hosts":1,"service":"api","fleet_pct":100}}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := do(s, c.method, c.path, c.hdr, c.body)
			if w.Code < 400 {
				t.Fatalf("expected an error status, got %d", w.Code)
			}
			var generic map[string]json.RawMessage
			if err := json.Unmarshal(w.Body.Bytes(), &generic); err != nil {
				t.Fatalf("body is not JSON: %s", w.Body.String())
			}
			if _, ok := generic["error"]; !ok || len(generic) != 1 {
				t.Fatalf("body must be exactly the {error:{...}} envelope, got: %s", w.Body.String())
			}
			e := decodeErr(t, w)
			for _, marker := range []string{"panic", "goroutine", ".go:", "internal/", "operator-key", "proposer-key"} {
				if strings.Contains(e.Message, marker) {
					t.Fatalf("zero-leak violated in message %q (marker %q)", e.Message, marker)
				}
			}
		})
	}
}
