// Mutating /v1 routes (P1-d-2): plan -> approve -> execute, wired to the real
// domain engine (internal/engine). This file adds only the mutating
// lifecycle; the read surface and security scaffolding (auth, error
// envelope, body limits, request id) live in api.go (P1-d-1) and are reused
// unchanged by every handler below.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/juridical-docker/juridical/internal/action"
	"github.com/juridical-docker/juridical/internal/approve"
	"github.com/juridical-docker/juridical/internal/blast"
	"github.com/juridical-docker/juridical/internal/engine"
)

// Engine is the narrow subset of *engine.Engine the API depends on. Defining
// it here (rather than importing *engine.Engine directly as a concrete
// field) lets handler tests inject a fake without a real domain wiring, and
// keeps this package's dependency on internal/engine limited to its request
// result DTOs. *engine.Engine already satisfies this interface.
type Engine interface {
	Plan(ctx context.Context, req engine.PlanRequest) (approve.Plan, error)
	Approve(ctx context.Context, req engine.ApproveRequest) (string, error)
	Execute(ctx context.Context, req engine.ExecuteRequest) (engine.ExecuteResult, error)
}

// registerMutating adds the plan -> approve -> execute lifecycle routes to
// the mux built in New().
func (s *Server) registerMutating() {
	s.mux.Handle("POST /v1/plans", s.withKey(ScopeOrchestrator, s.handlePlans))
	s.mux.Handle("POST /v1/approvals", s.withHuman(s.handleApprovals))
	s.mux.Handle("POST /v1/executions", s.withKey(ScopeOperator, s.handleExecutions))
}

// ---- forward-auth human identity (the internal design spec §9 OF6-5) ----
//
// SECURITY ASSUMPTION: s.humanHeader is trusted ONLY because this server is
// deployed bound to loopback and fronted exclusively by the trusted reverse
// proxy + Authentik forward-auth outpost (the internal design spec §1/§8.4). The outpost
// authenticates the human and injects this header itself before the request
// ever reaches juridical; juridical never terminates a public listener and
// never authenticates the human directly. If this assumption is ever
// violated — the API exposed without the fronting proxy in front of it — a
// caller could forge this header and impersonate any human SSO principal.
// That deployment configuration must never be allowed (see cmd/juridical's
// serve command, which refuses to bind anything but loopback).
//
// withHuman requires a non-empty forward-auth human identity header and
// never falls back to the automation Bearer-key identity: the two identity
// classes are structurally distinct (the internal design spec §1), and this is the ONLY route
// where a human identity is accepted at all — no automation key may mint an
// approval (the internal design spec §5; the design notes Decision 4). A missing/empty header fails
// closed with 401 before any domain call.
func (s *Server) withHuman(h func(http.ResponseWriter, *http.Request, string)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		human := strings.TrimSpace(r.Header.Get(s.humanHeader))
		if human == "" {
			writeError(w, http.StatusUnauthorized, "unauthenticated", "missing human identity (forward-auth)")
			return
		}
		h(w, r, human)
	})
}

// ---- strict JSON decode ----
//
// decodeStrict rejects unknown fields and any trailing data after the single
// JSON value. The latter check matters: json.Decoder.Decode consumes exactly
// one JSON value and silently ignores bytes after it, so without an explicit
// post-decode dec.More() check a body like `{...}{"evil":true}` or
// `{...}\r\nGARBAGE` would decode "successfully" from only its first value.
// Every untrusted mutating-route body goes through this.
var errTrailingData = errors.New("api: trailing data after JSON value")

func decodeStrict(r io.Reader, v any) error {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errTrailingData
	}
	return nil
}

// writeBadBody classifies a decodeStrict failure and writes the matching
// zero-leak envelope: a body that exceeded the global MaxBodyBytes limit
// (enforced upstream by limitAndTypeJSON via http.MaxBytesReader) is 413, not
// a generic 400 — the JSON decoder just sees that as a read error partway
// through, so it must be classified explicitly rather than falling through
// to "malformed".
func writeBadBody(w http.ResponseWriter, err error, genericMsg string) {
	var mbErr *http.MaxBytesError
	if errors.As(err, &mbErr) {
		writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large", "request body too large")
		return
	}
	writeError(w, http.StatusBadRequest, "bad_request", genericMsg)
}

// ---- POST /v1/plans (the internal design spec §9 §5.1) ----

// declaredBoundWire is the wire shape of declared_bound's Phase-1 active
// dimensions (the internal design spec §4.1).
type declaredBoundWire struct {
	MaxHosts int    `json:"max_hosts"`
	Service  string `json:"service"`
	FleetPct int    `json:"fleet_pct"`
}

type plansRequest struct {
	Action        string            `json:"action"`
	Backend       string            `json:"backend"`
	Project       string            `json:"project"`
	Params        map[string]string `json:"params"`
	DeclaredBound json.RawMessage   `json:"declared_bound"`
}

// activeBoundDims is the Phase-1 recognized declared_bound key set. Any other
// key present is a dormant dimension and must be refused, not ignored (FC3).
var activeBoundDims = map[string]bool{"max_hosts": true, "service": true, "fleet_pct": true}

// parseDeclaredBound decodes raw into a blast.DeclaredBound and separately
// computes which JSON object keys (if any) fall outside the Phase-1 active
// dimension set, so the domain layer (blast.ValidateDeclared) can refuse
// them by name (FC3) with a specific, auditable reason rather than the API
// layer silently rejecting on a generic decode error.
func parseDeclaredBound(raw json.RawMessage) (blast.DeclaredBound, []string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return blast.DeclaredBound{}, nil, blast.ErrNoBound
	}
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(raw, &generic); err != nil {
		return blast.DeclaredBound{}, nil, err
	}
	var dormant []string
	for k := range generic {
		if !activeBoundDims[k] {
			dormant = append(dormant, k)
		}
	}
	var w declaredBoundWire
	if err := json.Unmarshal(raw, &w); err != nil {
		return blast.DeclaredBound{}, nil, err
	}
	return blast.DeclaredBound{MaxHosts: w.MaxHosts, Service: w.Service, FleetPct: w.FleetPct}, dormant, nil
}

// handlePlans serves POST /v1/plans: Tier T, orchestrator-scope automation
// key. Non-mutating dry-run; an over-bound plan still renders (200) for
// visibility but is not executable (approve.Plan.Executable()).
func (s *Server) handlePlans(w http.ResponseWriter, r *http.Request, p principal) {
	var req plansRequest
	if err := decodeStrict(r.Body, &req); err != nil {
		writeBadBody(w, err, "malformed plan request body")
		return
	}
	req.Action = strings.TrimSpace(req.Action)
	req.Backend = strings.TrimSpace(req.Backend)
	req.Project = strings.TrimSpace(req.Project)
	if req.Action == "" || req.Backend == "" || req.Project == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "action, backend, and project are required")
		return
	}
	bound, dormant, err := parseDeclaredBound(req.DeclaredBound)
	if err != nil {
		writeError(w, http.StatusBadRequest, "malformed_bound", "declared_bound is missing or malformed")
		return
	}

	plan, err := s.engine.Plan(r.Context(), engine.PlanRequest{
		Action:        req.Action,
		Backend:       req.Backend,
		Project:       req.Project,
		Params:        req.Params,
		DeclaredBound: bound,
		DormantDims:   dormant,
		ProposerKeyID: p.keyID,
	})
	if err != nil {
		switch {
		case errors.Is(err, action.ErrUnknownAction):
			writeError(w, http.StatusBadRequest, "bad_request", "unknown action")
		case errors.Is(err, engine.ErrValidation):
			writeError(w, http.StatusBadRequest, "malformed_bound", "declared bound is invalid for this action")
		case errors.Is(err, engine.ErrUnresolvable):
			writeError(w, http.StatusUnprocessableEntity, "unresolvable_target", "target could not be resolved")
		default:
			writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		}
		return
	}
	writeJSON(w, http.StatusOK, plan)
}

// ---- POST /v1/approvals (the internal design spec §9 §5.2) ----

type approvalsRequest struct {
	PlanID   string `json:"plan_id"`
	PlanHash string `json:"plan_hash"`
	Reason   string `json:"reason"`
}

type approvalsResponse struct {
	Token    string `json:"token"`
	PlanHash string `json:"plan_hash"`
	Approver string `json:"approver"`
}

// handleApprovals serves POST /v1/approvals: human SSO only, no automation
// key may call this (the internal design spec §5). human is the trusted forward-auth
// identity (withHuman already required it be non-empty); it is passed as
// ApproverIsHuman: true because the ONLY way to reach this handler is
// through a verified forward-auth header — there is no automation path here.
func (s *Server) handleApprovals(w http.ResponseWriter, r *http.Request, human string) {
	var req approvalsRequest
	if err := decodeStrict(r.Body, &req); err != nil {
		writeBadBody(w, err, "malformed approval request body")
		return
	}
	req.PlanID = strings.TrimSpace(req.PlanID)
	req.PlanHash = strings.TrimSpace(req.PlanHash)
	if req.PlanID == "" || req.PlanHash == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "plan_id and plan_hash are required")
		return
	}

	token, err := s.engine.Approve(r.Context(), engine.ApproveRequest{
		PlanID:          req.PlanID,
		PlanHash:        req.PlanHash,
		Approver:        human,
		ApproverIsHuman: true,
	})
	if err != nil {
		switch {
		case errors.Is(err, engine.ErrUnknownPlan):
			writeError(w, http.StatusNotFound, "not_found", "unknown plan_id")
		case errors.Is(err, approve.ErrSelfApproval), errors.Is(err, approve.ErrNotHuman):
			writeError(w, http.StatusForbidden, "sod_violation", "approver must differ from the proposer")
		case errors.Is(err, approve.ErrHashMismatch):
			writeError(w, http.StatusConflict, "token_invalid", "plan_hash no longer matches the stored plan")
		case errors.Is(err, engine.ErrNotExecutable):
			writeError(w, http.StatusUnprocessableEntity, "over_bound", "plan is not executable (over bound)")
		default:
			writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		}
		return
	}
	writeJSON(w, http.StatusOK, approvalsResponse{Token: token, PlanHash: req.PlanHash, Approver: human})
}

// ---- POST /v1/executions (the internal design spec §9 §5.3) ----

type executionsRequest struct {
	PlanID string `json:"plan_id"`
	Token  string `json:"token"`
}

type executionsResponse struct {
	ExecutionID            string        `json:"execution_id"`
	Verdict                blast.Verdict `json:"verdict"`
	ComputedReachAtExecute blast.Reach   `json:"computed_reach_at_execute"`
	Outcome                string        `json:"outcome"`
}

// handleExecutions serves POST /v1/executions: Tier M, operator-scope
// automation key + a valid one-time approval token. The human actor for this
// event is already carried by the token (the approver who minted it,
// recorded at /v1/approvals) and is written into the execute audit row by
// the engine (Approver: consumed.Approver) — SoD was already enforced at
// mint time, so execute does not re-collect a forward-auth header; doing so
// would add no additional guarantee while breaking the automation-initiated
// execute path the spec's two-identity-class model depends on.
func (s *Server) handleExecutions(w http.ResponseWriter, r *http.Request, _ principal) {
	var req executionsRequest
	if err := decodeStrict(r.Body, &req); err != nil {
		writeBadBody(w, err, "malformed execution request body")
		return
	}
	req.PlanID = strings.TrimSpace(req.PlanID)
	req.Token = strings.TrimSpace(req.Token)
	if req.PlanID == "" || req.Token == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "plan_id and token are required")
		return
	}

	res, err := s.engine.Execute(r.Context(), engine.ExecuteRequest{PlanID: req.PlanID, Token: req.Token})
	if err != nil {
		switch {
		case errors.Is(err, engine.ErrUnknownPlan):
			writeError(w, http.StatusNotFound, "not_found", "unknown plan_id")
		case errors.Is(err, approve.ErrTokenUnknown), errors.Is(err, approve.ErrTokenExpired),
			errors.Is(err, approve.ErrTokenConsumed), errors.Is(err, approve.ErrHashMismatch):
			writeError(w, http.StatusConflict, "token_invalid", "approval token is invalid, expired, or already used")
		case errors.Is(err, engine.ErrUnresolvable):
			writeError(w, http.StatusUnprocessableEntity, "unresolvable_target", "target could not be resolved at execute time")
		case errors.Is(err, engine.ErrOverBound):
			writeError(w, http.StatusConflict, "over_bound", "execute-time reach exceeds the approved bound")
		case errors.Is(err, engine.ErrExecutionFailed):
			writeError(w, http.StatusInternalServerError, "execution_failed", "execution failed")
		default:
			// Includes engine.ErrAuditWriteFailed: a durable-audit failure on
			// the execute path is always a generic, zero-leak 500 — never a
			// reason string that could hint at infra internals.
			writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		}
		return
	}
	writeJSON(w, http.StatusOK, executionsResponse{
		ExecutionID:            res.ExecutionID,
		Verdict:                res.Verdict,
		ComputedReachAtExecute: res.ReachAtExec,
		Outcome:                res.Outcome,
	})
}
