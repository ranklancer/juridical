package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/juridical-docker/juridical/internal/audit"
)

func testServer(t *testing.T, keys *StaticKeyStore) (*Server, *audit.Log) {
	t.Helper()
	log, err := audit.Open("")
	if err != nil {
		t.Fatal(err)
	}
	return New(Config{Audit: log, Authn: keys, HumanHeader: "X-Forwarded-User"}), log
}

func do(s *Server, method, target string, hdr map[string]string, body string) *httptest.ResponseRecorder {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func decodeErr(t *testing.T, w *httptest.ResponseRecorder) errObj {
	t.Helper()
	var e errBody
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil {
		t.Fatalf("error body not JSON envelope: %s", w.Body.String())
	}
	return e.Error
}

func TestHealthz_NoAuth_OKWithRequestID(t *testing.T) {
	s, _ := testServer(t, NewStaticKeyStore())
	w := do(s, "GET", "/v1/healthz", nil, "")
	if w.Code != http.StatusOK {
		t.Fatalf("healthz status=%d", w.Code)
	}
	if w.Header().Get("X-Request-Id") == "" {
		t.Error("missing X-Request-Id")
	}
	if !strings.Contains(w.Body.String(), `"status":"ok"`) {
		t.Errorf("body=%s", w.Body.String())
	}
}

func TestAudit_MissingKey_401(t *testing.T) {
	s, _ := testServer(t, NewStaticKeyStore())
	w := do(s, "GET", "/v1/audit", nil, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", w.Code)
	}
	if got := decodeErr(t, w).Code; got != "unauthenticated" {
		t.Errorf("code=%q", got)
	}
}

func TestAudit_BadKey_401(t *testing.T) {
	keys := NewStaticKeyStore()
	keys.Add("goodkey", "auto-1", ScopeObserver)
	s, _ := testServer(t, keys)
	w := do(s, "GET", "/v1/audit", map[string]string{"Authorization": "Bearer wrongkey"}, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", w.Code)
	}
}

func TestAudit_InsufficientScope_403(t *testing.T) {
	keys := NewStaticKeyStore()
	keys.Add("nokey", "auto-1", ScopeNone) // below observer
	s, _ := testServer(t, keys)
	w := do(s, "GET", "/v1/audit", map[string]string{"Authorization": "Bearer nokey"}, "")
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d", w.Code)
	}
	if got := decodeErr(t, w).Code; got != "scope_denied" {
		t.Errorf("code=%q", got)
	}
}

func seedAudit(t *testing.T, log *audit.Log, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := log.Append(audit.Record{Event: audit.EventPlan, Action: "restart-service"}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAudit_Pagination_SinceLimitNextSince(t *testing.T) {
	keys := NewStaticKeyStore()
	keys.Add("obs", "auto-1", ScopeObserver)
	s, log := testServer(t, keys)
	seedAudit(t, log, 5) // seq 1..5
	auth := map[string]string{"Authorization": "Bearer obs"}

	w := do(s, "GET", "/v1/audit?limit=2", auth, "")
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var resp auditResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Records) != 2 || resp.Records[0].Seq != 1 || resp.Records[1].Seq != 2 {
		t.Fatalf("page1 unexpected: %+v", resp.Records)
	}
	if resp.NextSince != 2 {
		t.Fatalf("next_since=%d want 2", resp.NextSince)
	}
	// follow the cursor
	w2 := do(s, "GET", "/v1/audit?since=2&limit=2", auth, "")
	var r2 auditResponse
	_ = json.Unmarshal(w2.Body.Bytes(), &r2)
	if len(r2.Records) != 2 || r2.Records[0].Seq != 3 || r2.NextSince != 4 {
		t.Fatalf("page2 unexpected: %+v next=%d", r2.Records, r2.NextSince)
	}
	// last page: no next_since
	w3 := do(s, "GET", "/v1/audit?since=4&limit=2", auth, "")
	var r3 auditResponse
	_ = json.Unmarshal(w3.Body.Bytes(), &r3)
	if len(r3.Records) != 1 || r3.Records[0].Seq != 5 || r3.NextSince != 0 {
		t.Fatalf("page3 unexpected: %+v next=%d", r3.Records, r3.NextSince)
	}
}

func TestAudit_BadParams_400(t *testing.T) {
	keys := NewStaticKeyStore()
	keys.Add("obs", "auto-1", ScopeObserver)
	s, _ := testServer(t, keys)
	auth := map[string]string{"Authorization": "Bearer obs"}
	for _, q := range []string{"?since=abc", "?limit=0", "?limit=x", "?event=bogus"} {
		w := do(s, "GET", "/v1/audit"+q, auth, "")
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status=%d want 400", q, w.Code)
		}
	}
}

func TestAudit_ZeroLeak_RedactsSecretParams(t *testing.T) {
	keys := NewStaticKeyStore()
	keys.Add("obs", "auto-1", ScopeObserver)
	s, log := testServer(t, keys)
	if _, err := log.Append(audit.Record{
		Event: audit.EventExecute, Action: "x",
		ParamsRedacted: map[string]string{"token": "supersecretvalue"},
	}); err != nil {
		t.Fatal(err)
	}
	w := do(s, "GET", "/v1/audit", map[string]string{"Authorization": "Bearer obs"}, "")
	if strings.Contains(w.Body.String(), "supersecretvalue") {
		t.Fatalf("secret leaked into audit response: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "[REDACTED]") {
		t.Errorf("expected redaction marker, body=%s", w.Body.String())
	}
}

func TestMiddleware_NonJSONBody_415(t *testing.T) {
	s, _ := testServer(t, NewStaticKeyStore())
	// POST to any path with a non-JSON content type is rejected before routing.
	w := do(s, "POST", "/v1/healthz", map[string]string{"Content-Type": "text/plain"}, "hello")
	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status=%d want 415", w.Code)
	}
	if got := decodeErr(t, w).Code; got != "unsupported_media_type" {
		t.Errorf("code=%q", got)
	}
}

func TestMiddleware_PanicRecovered_500NoLeak(t *testing.T) {
	boom := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom-secret-internal-detail") })
	w := httptest.NewRecorder()
	recoverPanic(boom).ServeHTTP(w, httptest.NewRequest("GET", "/x", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d", w.Code)
	}
	if strings.Contains(w.Body.String(), "boom-secret-internal-detail") {
		t.Fatalf("panic detail leaked: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"internal_error"`) {
		t.Errorf("body=%s", w.Body.String())
	}
}
