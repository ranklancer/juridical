package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
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
