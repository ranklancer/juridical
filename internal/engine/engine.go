// Package engine is the composition root of the mutation loop
// (plan -> approval-token -> execute -> hash-chained audit, the internal design spec §6). It
// wires the blast limiter, the approval-token store, the action registry, and
// the audit log, enforcing every fail-closed invariant (FC1..FC7) in one place.
// The HTTP API (/v1) and the CLI both drive this engine.
package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/juridical-docker/juridical/internal/action"
	"github.com/juridical-docker/juridical/internal/approve"
	"github.com/juridical-docker/juridical/internal/audit"
	"github.com/juridical-docker/juridical/internal/blast"
)

// DefaultTokenTTL is the Phase-1 default approval-token lifetime (the internal design spec §6.3).
const DefaultTokenTTL = 300 * time.Second

// AuditSink is the narrow audit-write dependency the engine needs; *audit.Log
// satisfies it. Append MUST return a non-nil error if the record was not
// durably persisted (the file-backed Log fsyncs before returning). The engine
// treats an audit-write error on a side-effect-bearing path (approve, execute)
// as fail-closed: no such success is returned without a durable audit record.
type AuditSink interface {
	Append(audit.Record) (audit.Record, error)
	// Records returns the current chain for verification/read-back.
	Records() ([]audit.Record, error)
}

// Engine composes the mutation loop.
type Engine struct {
	Registry    *action.Registry
	Tokens      *approve.TokenStore
	Audit       AuditSink
	Enforcement blast.Enforcement
	TokenTTL    time.Duration

	now   func() time.Time
	mu    sync.Mutex
	idseq uint64
	plans map[string]stored
}

type stored struct {
	plan     approve.Plan
	proposer string
}

// New builds an Engine with sane defaults (warn-mode enforcement, 300s TTL).
func New(reg *action.Registry, tokens *approve.TokenStore, log *audit.Log) *Engine {
	return &Engine{
		Registry:    reg,
		Tokens:      tokens,
		Audit:       log,
		Enforcement: blast.Enforcement{MaxHosts: blast.ModeWarn, Service: blast.ModeWarn, FleetPct: blast.ModeWarn},
		TokenTTL:    DefaultTokenTTL,
		now:         time.Now,
		plans:       map[string]stored{},
	}
}

// PlanRequest is the input to Plan (POST /v1/plans).
type PlanRequest struct {
	Action        string
	Backend       string
	Project       string
	Params        map[string]string
	DeclaredBound blast.DeclaredBound
	DormantDims   []string // dimension keys present but not active in Phase 1
	ProposerKeyID string   // automation key that proposes (Tier T)
}

// Plan resolves live reach, evaluates the bound, renders and hashes the plan.
// It mutates nothing. An over-bound plan is returned (not executable); an
// unparseable bound or an unresolvable/ambiguous target fails closed (FC3/FC7)
// with a refuse audit row and no plan.
func (e *Engine) Plan(ctx context.Context, req PlanRequest) (approve.Plan, error) {
	act, err := e.Registry.Get(req.Action)
	if err != nil {
		return approve.Plan{}, err
	}
	if err := blast.ValidateDeclared(req.DeclaredBound, req.DormantDims); err != nil {
		_ = e.refuse(req.Action, req.Backend, req.Project, req.Params, req.DeclaredBound, blast.Reach{}, req.ProposerKeyID, "", err.Error())
		return approve.Plan{}, err
	}
	if err := act.ValidateBound(req.DeclaredBound); err != nil {
		_ = e.refuse(req.Action, req.Backend, req.Project, req.Params, req.DeclaredBound, blast.Reach{}, req.ProposerKeyID, "", err.Error())
		return approve.Plan{}, err
	}
	reach, target, err := act.Resolve(ctx, req.Params)
	if err != nil {
		// FC7: ambiguous / unresolvable -> dry-run report, never execute.
		_ = e.refuse(req.Action, req.Backend, req.Project, req.Params, req.DeclaredBound, blast.Reach{}, req.ProposerKeyID, "", err.Error())
		return approve.Plan{}, err
	}
	verdict, _ := blast.Evaluate(req.DeclaredBound, reach, e.Enforcement)
	within := blast.Within(req.DeclaredBound, reach)

	now := e.now().UTC()
	p := approve.Plan{
		PlanID:        e.newID("pln"),
		Action:        req.Action,
		Backend:       req.Backend,
		Project:       req.Project,
		Params:        req.Params,
		Target:        target,
		DeclaredBound: req.DeclaredBound,
		ComputedReach: reach,
		Enforcement:   e.Enforcement,
		Verdict:       verdict,
		WithinBound:   within,
		CreatedAt:     now,
		ExpiresAt:     now.Add(e.TokenTTL),
	}
	p.PlanHash = approve.PlanHash(p)

	e.mu.Lock()
	e.plans[p.PlanID] = stored{plan: p, proposer: req.ProposerKeyID}
	e.mu.Unlock()

	_ = e.audit(audit.EventPlan, p, string(verdict), req.ProposerKeyID, "", "plan rendered")
	return p, nil
}

// ApproveRequest is the input to Approve (POST /v1/approvals, human SSO only).
type ApproveRequest struct {
	PlanID          string
	PlanHash        string
	Approver        string
	ApproverIsHuman bool
}

// Approve verifies the supplied hash matches the stored plan, enforces SoD, and
// mints a one-time token bound to the plan hash. A non-executable plan is
// refused.
func (e *Engine) Approve(ctx context.Context, req ApproveRequest) (string, error) {
	e.mu.Lock()
	s, ok := e.plans[req.PlanID]
	e.mu.Unlock()
	if !ok {
		return "", errors.New("engine: unknown plan_id")
	}
	if req.PlanHash != s.plan.PlanHash {
		err := approve.ErrHashMismatch
		_ = e.audit(audit.EventRefuse, s.plan, "REFUSED", s.proposer, req.Approver, err.Error())
		return "", err
	}
	if !s.plan.Executable() {
		err := fmt.Errorf("engine: plan is not executable (within_bound=%v verdict=%s)", s.plan.WithinBound, s.plan.Verdict)
		_ = e.audit(audit.EventRefuse, s.plan, "REFUSED", s.proposer, req.Approver, err.Error())
		return "", err
	}
	if err := approve.CheckSoD(s.proposer, req.Approver, req.ApproverIsHuman); err != nil {
		_ = e.audit(audit.EventRefuse, s.plan, "REFUSED", s.proposer, req.Approver, err.Error())
		return "", err
	}
	token, err := e.Tokens.Mint(s.plan.PlanHash, s.proposer, req.Approver, e.TokenTTL)
	if err != nil {
		return "", err
	}
	if err := e.audit(audit.EventApprove, s.plan, "ALLOW", s.proposer, req.Approver, "token minted"); err != nil {
		return "", fmt.Errorf("engine: approval token minted but its audit record could not be persisted (integrity violation): %w", err)
	}
	return token, nil
}

// ExecuteRequest is the input to Execute (POST /v1/executions, operator+token).
type ExecuteRequest struct {
	PlanID string
	Token  string
}

// ExecuteResult is the outcome of a successful execution.
type ExecuteResult struct {
	ExecutionID string
	Verdict     blast.Verdict
	ReachAtExec blast.Reach
	Outcome     string
}

// Execute consumes the token (one-time), rechecks reach against live topology
// at execute time (FC6), performs the mutation, and writes the audit record.
// Any token failure or over-bound recheck refuses with no execution.
func (e *Engine) Execute(ctx context.Context, req ExecuteRequest) (ExecuteResult, error) {
	e.mu.Lock()
	s, ok := e.plans[req.PlanID]
	e.mu.Unlock()
	if !ok {
		return ExecuteResult{}, errors.New("engine: unknown plan_id")
	}
	consumed, err := e.Tokens.Consume(req.Token, s.plan.PlanHash)
	if err != nil {
		_ = e.audit(audit.EventRefuse, s.plan, "REFUSED", s.proposer, "", err.Error())
		return ExecuteResult{}, err
	}
	act, err := e.Registry.Get(s.plan.Action)
	if err != nil {
		return ExecuteResult{}, err
	}
	// FC6 recheck against live topology at execute time.
	reach, _, err := act.Resolve(ctx, s.plan.Params)
	if err != nil {
		_ = e.audit(audit.EventRefuse, s.plan, "REFUSED", s.proposer, consumed.Approver, "execute-time resolve failed: "+err.Error())
		return ExecuteResult{}, fmt.Errorf("engine: execute-time recheck failed (FC7): %w", err)
	}
	verdict, breaches := blast.Evaluate(s.plan.DeclaredBound, reach, e.Enforcement)
	if verdict == blast.VerdictBlock || !blast.Within(s.plan.DeclaredBound, reach) {
		p := s.plan
		p.ComputedReach = reach
		_ = e.audit(audit.EventRefuse, p, "REFUSED", s.proposer, consumed.Approver,
			fmt.Sprintf("execute-time reach exceeds approved bound (FC6): %v", breaches))
		return ExecuteResult{}, fmt.Errorf("engine: execute-time reach exceeds approved bound (FC6): %v", breaches)
	}
	outcome, err := act.Execute(ctx, s.plan.Params)
	if err != nil {
		p := s.plan
		p.ComputedReach = reach
		_ = e.audit(audit.EventRefuse, p, "REFUSED", s.proposer, consumed.Approver, "execute failed: "+err.Error())
		return ExecuteResult{}, err
	}
	p := s.plan
	p.ComputedReach = reach
	if err := e.audit(audit.EventExecute, p, "ALLOW", s.proposer, consumed.Approver, outcome); err != nil {
		return ExecuteResult{}, fmt.Errorf("engine: CRITICAL: mutation executed but its audit record could not be persisted (integrity violation): %w", err)
	}
	return ExecuteResult{
		ExecutionID: e.newID("exe"),
		Verdict:     blast.VerdictAllow,
		ReachAtExec: reach,
		Outcome:     outcome,
	}, nil
}

func (e *Engine) refuse(actionName, backend, project string, params map[string]string, db blast.DeclaredBound, reach blast.Reach, proposer, approver, outcome string) error {
	_, err := e.Audit.Append(audit.Record{
		Event:          audit.EventRefuse,
		Action:         actionName,
		Backend:        backend,
		Project:        project,
		ParamsRedacted: params,
		DeclaredBound:  db,
		ComputedReach:  reach,
		Verdict:        "REFUSED",
		Outcome:        outcome,
		ProposerKeyID:  proposer,
		Approver:       approver,
	})
	return err
}

func (e *Engine) audit(ev audit.Event, p approve.Plan, verdict, proposer, approver, outcome string) error {
	_, err := e.Audit.Append(audit.Record{
		Event:          ev,
		Action:         p.Action,
		Backend:        p.Backend,
		Project:        p.Project,
		ParamsRedacted: p.Params,
		DeclaredBound:  p.DeclaredBound,
		ComputedReach:  p.ComputedReach,
		Verdict:        verdict,
		Outcome:        outcome,
		ProposerKeyID:  proposer,
		Approver:       approver,
		PlanHash:       p.PlanHash,
	})
	return err
}

func (e *Engine) newID(prefix string) string {
	e.mu.Lock()
	e.idseq++
	n := e.idseq
	e.mu.Unlock()
	return fmt.Sprintf("%s_%06d", prefix, n)
}
