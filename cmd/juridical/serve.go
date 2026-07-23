// `juridical serve` constructs the /v1 API handler (internal/api) wired to
// the real domain engine (internal/engine) — the finite action registry, the
// approval-token store, and the hash-chained audit log — and runs it. Per
// the internal design spec §1/§8.4 the control plane binds loopback only and is fronted
// exclusively by a reverse proxy + Authentik forward-auth outpost; it is
// never exposed directly, and this command refuses to bind anything else.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/juridical-docker/juridical/internal/action"
	"github.com/juridical-docker/juridical/internal/api"
	"github.com/juridical-docker/juridical/internal/approve"
	"github.com/juridical-docker/juridical/internal/audit"
	"github.com/juridical-docker/juridical/internal/engine"
)

const defaultHumanHeader = "X-Forwarded-User"

// serveConfig is the resolved, validated configuration for `serve`.
type serveConfig struct {
	addr        string
	auditPath   string
	humanHeader string
	devInMemory bool
}

// parseServeFlags parses and validates serve's own flags. It never accepts
// automation keys as a flag (the internal design spec §1: keys are sourced from the secrets
// manager, never a CLI flag) — see loadKeysFromEnv.
func parseServeFlags(args []string, stderr io.Writer) (serveConfig, error) {
	fs := flag.NewFlagSet("juridical serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", "127.0.0.1:8080", "listen address; must be loopback (127.0.0.1:PORT, localhost:PORT, or [::1]:PORT)")
	auditPath := fs.String("audit-log", "", "path to the append-only audit JSONL file (required unless -dev; written 0600, keep it outside any web root)")
	humanHeader := fs.String("human-header", defaultHumanHeader, "forward-auth header carrying the human SSO principal (OF6-5); trusted only because this server binds loopback behind the trusted reverse proxy + Authentik forward-auth outpost")
	dev := fs.Bool("dev", false, "DANGEROUS: use a non-durable in-memory audit log instead of -audit-log; local development only, never production")
	if err := fs.Parse(args); err != nil {
		return serveConfig{}, err
	}
	if err := validateLoopbackAddr(*addr); err != nil {
		return serveConfig{}, err
	}
	if strings.TrimSpace(*auditPath) == "" && !*dev {
		return serveConfig{}, errors.New("serve: -audit-log is required (or pass -dev for a non-durable local run)")
	}
	return serveConfig{addr: *addr, auditPath: *auditPath, humanHeader: *humanHeader, devInMemory: *dev}, nil
}

// validateLoopbackAddr fails closed on any bind address that is not
// explicitly loopback (the internal design spec §1: "Bind loopback only ... never 0.0.0.0,
// never a direct public address").
func validateLoopbackAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("serve: -addr must be host:port: %w", err)
	}
	if strings.TrimSpace(port) == "" {
		return errors.New("serve: -addr must include a port")
	}
	switch host {
	case "127.0.0.1", "localhost", "::1":
		return nil
	default:
		return fmt.Errorf("serve: -addr host %q is not loopback; refusing to bind (fail-closed, the internal design spec §1)", host)
	}
}

// loadKeysFromEnv builds the automation-key store from JURIDICAL_KEYS — never
// a CLI flag. Format: comma-separated "id:scope:rawkey" entries; scope is one
// of observer|orchestrator|operator. Raw keys are hashed immediately by
// api.StaticKeyStore.Add and never retained or logged in cleartext.
func loadKeysFromEnv(getenv func(string) string) (*api.StaticKeyStore, error) {
	store := api.NewStaticKeyStore()
	raw := strings.TrimSpace(getenv("JURIDICAL_KEYS"))
	if raw == "" {
		return store, nil // an empty key set is valid: every request 401s/403s.
	}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, ":", 3)
		if len(parts) != 3 {
			return nil, errors.New("serve: malformed JURIDICAL_KEYS entry (want id:scope:key)")
		}
		id, scopeName, key := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), parts[2]
		if id == "" || key == "" {
			return nil, fmt.Errorf("serve: malformed JURIDICAL_KEYS entry for id %q", id)
		}
		scope, err := parseScope(scopeName)
		if err != nil {
			return nil, fmt.Errorf("serve: JURIDICAL_KEYS entry %q: %w", id, err)
		}
		store.Add(key, id, scope)
	}
	return store, nil
}

func parseScope(s string) (api.Scope, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "observer":
		return api.ScopeObserver, nil
	case "orchestrator":
		return api.ScopeOrchestrator, nil
	case "operator":
		return api.ScopeOperator, nil
	default:
		return api.ScopeNone, fmt.Errorf("unknown scope %q (want observer|orchestrator|operator)", s)
	}
}

// newRegistry registers the finite Phase-1 action set (the internal design spec §3).
//
// KNOWN GAP: the live compose backend (topology discovery + restart/deploy
// actuation) is not implemented anywhere in this repository yet — that is a
// separate, not-yet-specified slice, not part of P1-d-2 (API wiring). Actions
// are still registered here with their Topo/Restarter/Deployer fields left
// unwired: each already fails closed with a clear "no ... provider wired"
// error at Resolve/Execute (see internal/action) rather than panicking, so
// `serve` is honest about the gap instead of silently no-op'ing or hiding it
// behind an empty registry.
func newRegistry() *action.Registry {
	reg := action.NewRegistry()
	reg.Register(action.RestartService{})
	reg.Register(action.RollDeploy{})
	return reg
}

// buildServer resolves serve's configuration and constructs the fully wired
// /v1 API handler: action registry -> approval-token store -> audit log ->
// engine -> api.Server. It performs no network I/O, so it is unit-testable
// without binding a socket.
func buildServer(args []string, stderr io.Writer, getenv func(string) string) (*api.Server, string, error) {
	cfg, err := parseServeFlags(args, stderr)
	if err != nil {
		return nil, "", err
	}
	keys, err := loadKeysFromEnv(getenv)
	if err != nil {
		return nil, "", err
	}
	auditPath := cfg.auditPath
	if cfg.devInMemory {
		auditPath = ""
	}
	log, err := audit.Open(auditPath)
	if err != nil {
		return nil, "", fmt.Errorf("serve: opening audit log: %w", err)
	}
	eng := engine.New(newRegistry(), approve.NewTokenStore(), log)
	srv := api.New(api.Config{Audit: log, Authn: keys, Engine: eng, HumanHeader: cfg.humanHeader})
	return srv, cfg.addr, nil
}

// newHTTPServer builds the *http.Server with the timeouts serve enforces
// (the internal design spec §9 hardening) wrapping the given handler. Extracted out of
// runServe (pure construction, no behavior change) so tests can exercise the
// exact same goroutine-owning Serve/ListenAndServe lifecycle that runServe
// runs in production, including a real graceful Shutdown, without binding
// to runServe's fixed -addr-derived listener.
func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

// runServe implements `juridical serve`.
func runServe(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	srv, addr, err := buildServer(args, stderr, getenv)
	if err != nil {
		fmt.Fprintf(stderr, "juridical: serve: %v\n", err)
		return 2
	}
	httpSrv := newHTTPServer(addr, srv)
	fmt.Fprintf(stdout, "juridical: listening on %s\n", addr)
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(stderr, "juridical: serve: %v\n", err)
		return 1
	}
	return 0
}
