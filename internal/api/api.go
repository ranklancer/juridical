// Package api wires the juridical control-plane HTTP surface (the internal design spec §9, /v1).
// P1-d-1 provided the security scaffolding — stdlib net/http only, bearer-key
// auth + scope model, forward-auth human identity, a zero-leak error
// envelope, request limits, and the read surface (healthz, paginated audit).
// P1-d-2 (this slice, see mutating.go) adds the mutating lifecycle routes
// (POST /v1/plans, /v1/approvals, /v1/executions) wired to the real domain
// engine (internal/engine), fail-closed throughout.
package api

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/juridical-docker/juridical/internal/audit"
)

// MaxBodyBytes caps request bodies (the internal design spec §9 OF6-API-1, approved 64 KiB).
const MaxBodyBytes int64 = 64 << 10

// Audit pagination defaults (OF6-API-3, approved).
const (
	defaultAuditLimit = 100
	maxAuditLimit     = 1000
)

// Scope is an automation key's privilege tier; higher includes lower.
type Scope int

const (
	ScopeNone Scope = iota
	ScopeObserver
	ScopeOrchestrator
	ScopeOperator
)

// KeyAuthenticator resolves a presented bearer key to a key id and scope. Keys
// are matched against stored hashes; the raw key is never logged or echoed.
type KeyAuthenticator interface {
	Authenticate(bearer string) (keyID string, scope Scope, ok bool)
}

// AuditReader is the read side of the append-only log.
type AuditReader interface {
	Records() ([]audit.Record, error)
}

// Server is the /v1 HTTP surface.
type Server struct {
	mux         *http.ServeMux
	audit       AuditReader
	authn       KeyAuthenticator
	engine      Engine // domain engine backing the mutating routes (mutating.go, P1-d-2)
	humanHeader string // forward-auth header carrying the SSO principal (OF6-5)
}

// Config configures a Server. humanHeader is the trusted forward-auth header
// (set by the fronting proxy) that carries the human SSO principal. Engine is
// the domain engine (internal/engine.Engine satisfies it) backing the
// mutating lifecycle routes; a nil Engine means those routes are registered
// but will fail closed (panic -> recoverPanic -> zero-leak 500) if ever
// invoked, which only happens on a serve-wiring bug, never in production.
type Config struct {
	Audit       AuditReader
	Authn       KeyAuthenticator
	Engine      Engine
	HumanHeader string
}

// New builds the /v1 mux.
func New(cfg Config) *Server {
	hdr := cfg.HumanHeader
	if hdr == "" {
		hdr = "X-Forwarded-User"
	}
	s := &Server{mux: http.NewServeMux(), audit: cfg.Audit, authn: cfg.Authn, engine: cfg.Engine, humanHeader: hdr}
	// healthz: no auth, liveness only.
	s.mux.HandleFunc("GET /v1/healthz", s.handleHealthz)
	// audit: observer scope; paginated, redacted.
	s.mux.Handle("GET /v1/audit", s.withKey(ScopeObserver, s.handleAudit))
	// mutating lifecycle routes (P1-d-2, see mutating.go).
	s.registerMutating()
	return s
}

// ServeHTTP applies the global middleware chain then routes.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	withRequestID(recoverPanic(limitAndTypeJSON(s.mux))).ServeHTTP(w, r)
}

// ---- error envelope (the internal design spec §9 OF6-API-2, approved) ----

type errBody struct {
	Error errObj `json:"error"`
}
type errObj struct {
	Code     string `json:"code"`
	Message  string `json:"message"`
	FCRule   string `json:"fc_rule,omitempty"`
	AuditSeq uint64 `json:"audit_seq,omitempty"`
}

// writeError emits the zero-leak envelope. message must already be a safe,
// redacted string — callers never pass raw internal error text that could carry
// secrets, key material, tokens, or host addresses.
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errBody{Error: errObj{Code: code, Message: message}})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ---- middleware ----

// limitAndTypeJSON caps the body at MaxBodyBytes and, for requests that carry a
// body, requires application/json. Oversize -> 413; wrong type -> 415.
func limitAndTypeJSON(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
			ct := r.Header.Get("Content-Type")
			if i := strings.IndexByte(ct, ';'); i >= 0 {
				ct = ct[:i]
			}
			if !strings.EqualFold(strings.TrimSpace(ct), "application/json") {
				writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "request body must be application/json")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}

// recoverPanic converts a handler panic into a zero-leak 500 (never a stack).
func recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// withRequestID assigns a request id and echoes it in the response header. The
// id is opaque and carries no client data.
func withRequestID(next http.Handler) http.Handler {
	var seq uint64
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddUint64(&seq, 1)
		id := "req_" + strconv.FormatUint(n, 36)
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r)
	})
}

// ---- auth ----

// principal carries the authenticated automation identity for a request.
type principal struct {
	keyID string
	scope Scope
}

// withKey authenticates the bearer key and enforces the minimum scope before
// invoking h. A missing/invalid key -> 401; insufficient scope -> 403. The key
// itself is never logged.
func (s *Server) withKey(min Scope, h func(http.ResponseWriter, *http.Request, principal)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer, ok := bearerToken(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "unauthenticated", "missing or malformed bearer credential")
			return
		}
		keyID, scope, ok := s.authn.Authenticate(bearer)
		if !ok {
			writeError(w, http.StatusUnauthorized, "unauthenticated", "invalid credential")
			return
		}
		if scope < min {
			writeError(w, http.StatusForbidden, "scope_denied", "insufficient scope for this action")
			return
		}
		h(w, r, principal{keyID: keyID, scope: scope})
	})
}

func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if len(h) <= len(p) || !strings.EqualFold(h[:len(p)], p) {
		return "", false
	}
	tok := strings.TrimSpace(h[len(p):])
	if tok == "" {
		return "", false
	}
	return tok, true
}

// ---- handlers ----

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type auditResponse struct {
	Records   []audit.Record `json:"records"`
	NextSince uint64         `json:"next_since,omitempty"`
}

// handleAudit serves GET /v1/audit?since=&event=&limit= — oldest-first by seq,
// redacted records only (the log stores params already redacted).
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, _ principal) {
	q := r.URL.Query()

	var since uint64
	if v := strings.TrimSpace(q.Get("since")); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "since must be a non-negative seq cursor")
			return
		}
		since = n
	}

	event := strings.TrimSpace(q.Get("event"))
	if event != "" && !validEvent(event) {
		writeError(w, http.StatusBadRequest, "bad_request", "event is not a recognized audit event")
		return
	}

	limit := defaultAuditLimit
	if v := strings.TrimSpace(q.Get("limit")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "bad_request", "limit must be a positive integer")
			return
		}
		limit = n
	}
	if limit > maxAuditLimit {
		limit = maxAuditLimit
	}

	all, err := s.audit.Records()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "audit log unavailable")
		return
	}

	out := make([]audit.Record, 0, limit)
	var nextSince uint64
	for _, rec := range all { // Records() returns oldest-first by seq
		if rec.Seq <= since {
			continue
		}
		if event != "" && string(rec.Event) != event {
			continue
		}
		if len(out) == limit {
			nextSince = out[len(out)-1].Seq // more remain past the page
			break
		}
		out = append(out, rec)
	}
	writeJSON(w, http.StatusOK, auditResponse{Records: out, NextSince: nextSince})
}

func validEvent(e string) bool {
	switch audit.Event(e) {
	case audit.EventPlan, audit.EventApprove, audit.EventRefuse, audit.EventExecute, audit.EventBreakGlass:
		return true
	}
	return false
}

// StaticKeyStore is a simple in-memory KeyAuthenticator: it matches a presented
// key against stored SHA-256 hashes. Intended for a config-provided key set;
// production keys come from the secrets manager, never a CLI flag.
type StaticKeyStore struct {
	byHash map[[32]byte]staticKey
}
type staticKey struct {
	id    string
	scope Scope
}

// NewStaticKeyStore returns an empty store.
func NewStaticKeyStore() *StaticKeyStore {
	return &StaticKeyStore{byHash: make(map[[32]byte]staticKey)}
}

// Add registers a raw key (stored only as its SHA-256) with an id and scope.
func (k *StaticKeyStore) Add(rawKey, id string, scope Scope) {
	k.byHash[sha256.Sum256([]byte(rawKey))] = staticKey{id: id, scope: scope}
}

// Authenticate matches the presented bearer against the stored hashes. The key
// is high-entropy, so a hash-map lookup is not a meaningful timing oracle.
func (k *StaticKeyStore) Authenticate(bearer string) (string, Scope, bool) {
	e, ok := k.byHash[sha256.Sum256([]byte(bearer))]
	if !ok {
		return "", ScopeNone, false
	}
	return e.id, e.scope, true
}
