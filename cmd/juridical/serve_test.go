package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func noEnv(string) string { return "" }

func envWith(vals map[string]string) func(string) string {
	return func(k string) string { return vals[k] }
}

func TestBuildServer_MissingAuditLog_Errors(t *testing.T) {
	var errb bytes.Buffer
	_, _, err := buildServer(nil, &errb, noEnv)
	if err == nil {
		t.Fatal("expected an error when neither -audit-log nor -dev is set")
	}
	if !strings.Contains(err.Error(), "audit-log") {
		t.Fatalf("expected an audit-log error, got: %v", err)
	}
}

func TestBuildServer_NonLoopbackAddr_Errors(t *testing.T) {
	var errb bytes.Buffer
	_, _, err := buildServer([]string{"-dev", "-addr", "0.0.0.0:8080"}, &errb, noEnv)
	if err == nil {
		t.Fatal("expected an error binding a non-loopback address")
	}
	if !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("expected a loopback-binding error, got: %v", err)
	}
}

func TestBuildServer_MalformedKeysEnv_Errors(t *testing.T) {
	var errb bytes.Buffer
	_, _, err := buildServer([]string{"-dev"}, &errb, envWith(map[string]string{"JURIDICAL_KEYS": "not-well-formed"}))
	if err == nil {
		t.Fatal("expected an error for a malformed JURIDICAL_KEYS entry")
	}
}

func TestBuildServer_UnknownScopeInKeysEnv_Errors(t *testing.T) {
	var errb bytes.Buffer
	_, _, err := buildServer([]string{"-dev"}, &errb, envWith(map[string]string{"JURIDICAL_KEYS": "auto-1:superuser:somekey"}))
	if err == nil {
		t.Fatal("expected an error for an unrecognized scope name")
	}
}

// A tampered audit log at -audit-log must not be silently trusted: buildServer
// wires the engine to audit.Open's return value directly, so a chain that
// fails verification must abort server construction entirely (fail-closed) --
// the engine must never be handed an appender for a compromised chain.
func TestBuildServer_TamperedAuditLog_FailsClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	// A record whose stored record_hash cannot match its recomputed hash --
	// representative of any tampered/corrupted log an operator might point
	// -audit-log at.
	tampered := `{"seq":1,"ts":"2024-01-01T00:00:00Z","event":"plan","record_hash":"00"}` + "\n"
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatalf("writing tampered fixture: %v", err)
	}

	var errb bytes.Buffer
	srv, addr, err := buildServer([]string{"-audit-log", path}, &errb, noEnv)
	if err == nil {
		t.Fatal("buildServer must fail closed when -audit-log points at a tampered chain")
	}
	if srv != nil {
		t.Fatal("buildServer must not return a usable *api.Server when the audit log fails to open")
	}
	if addr != "" {
		t.Fatalf("buildServer must not return an addr on failure, got %q", addr)
	}
	if !strings.Contains(err.Error(), "audit") {
		t.Fatalf("expected an audit-log-opening error, got: %v", err)
	}

	// The tampered file itself must be left untouched -- buildServer/audit.Open
	// must not attempt any repair of a chain it refuses to trust.
	after, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatalf("re-reading tampered fixture: %v", rerr)
	}
	if string(after) != tampered {
		t.Fatalf("buildServer must not modify a tampered audit log on disk;\nbefore=%q\nafter=%q", tampered, after)
	}
}

func TestBuildServer_DevMode_HealthzWorks(t *testing.T) {
	var errb bytes.Buffer
	srv, addr, err := buildServer([]string{"-dev"}, &errb, noEnv)
	if err != nil {
		t.Fatalf("buildServer: %v", err)
	}
	if addr == "" {
		t.Fatal("expected a non-empty default addr")
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/v1/healthz", nil)
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("healthz status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestBuildServer_ValidKeysEnv_AuthenticatesRequest(t *testing.T) {
	var errb bytes.Buffer
	srv, _, err := buildServer([]string{"-dev"}, &errb, envWith(map[string]string{"JURIDICAL_KEYS": "auto-1:orchestrator:s3cr3t-raw-key"}))
	if err != nil {
		t.Fatalf("buildServer: %v", err)
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/v1/audit", nil)
	r.Header.Set("Authorization", "Bearer s3cr3t-raw-key")
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("audit status=%d body=%s (key should authenticate at >= observer scope)", w.Code, w.Body.String())
	}
}

func TestValidateLoopbackAddr(t *testing.T) {
	cases := []struct {
		addr    string
		wantErr bool
	}{
		{"127.0.0.1:8080", false},
		{"localhost:8080", false},
		{"[::1]:8080", false},
		{"0.0.0.0:8080", true},
		{"192.0.2.10:8080", true},
		{"example.com:8080", true},
		{"not-a-valid-addr", true},
	}
	for _, c := range cases {
		err := validateLoopbackAddr(c.addr)
		if (err != nil) != c.wantErr {
			t.Errorf("validateLoopbackAddr(%q) err=%v, wantErr=%v", c.addr, err, c.wantErr)
		}
	}
}
