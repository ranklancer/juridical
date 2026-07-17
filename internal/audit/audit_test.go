package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRedact(t *testing.T) {
	in := map[string]string{"service": "api", "api_token": "abc", "PASSWORD": "x", "note": "ok"}
	out := Redact(in)
	if out["service"] != "api" || out["note"] != "ok" {
		t.Fatal("non-secret keys must pass through")
	}
	if out["api_token"] != redactedMarker || out["PASSWORD"] != redactedMarker {
		t.Fatalf("secret-shaped keys must be redacted: %+v", out)
	}
	if in["api_token"] != "abc" {
		t.Fatal("Redact must not mutate the input")
	}
	if Redact(nil) != nil {
		t.Fatal("nil in -> nil out")
	}
}

func TestChainVerify_DetectsTamper(t *testing.T) {
	l, _ := Open("")
	for i := 0; i < 3; i++ {
		if _, err := l.Append(Record{Event: EventPlan, Action: "restart-service"}); err != nil {
			t.Fatal(err)
		}
	}
	recs, _ := l.Records()
	if bad, err := Verify(recs); err != nil {
		t.Fatalf("clean chain must verify, broke at %d: %v", bad, err)
	}
	// tamper with a field -> record_hash mismatch
	recs[1].Outcome = "tampered"
	if bad, err := Verify(recs); err == nil || bad != 1 {
		t.Fatalf("tamper must be detected at record 1, got bad=%d err=%v", bad, err)
	}
	// break the prev-link
	clean, _ := l.Records()
	clean[2].PrevRecordHash = "deadbeef"
	if bad, err := Verify(clean); err == nil || bad != 2 {
		t.Fatalf("broken prev-link must be detected at 2, got bad=%d err=%v", bad, err)
	}
}

func TestLog_FilePersistenceAndPerms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(Record{Event: EventPlan, Action: "a", ParamsRedacted: map[string]string{"token": "secret"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(Record{Event: EventExecute, Action: "a"}); err != nil {
		t.Fatal(err)
	}
	// 0600 perms
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("audit file must be 0600, got %v", fi.Mode().Perm())
	}
	// re-open resumes the chain and verifies
	l2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if _, err := l2.Append(Record{Event: EventPlan, Action: "b"}); err != nil {
		t.Fatal(err)
	}
	recs, _ := l2.Records()
	if len(recs) != 3 {
		t.Fatalf("want 3 records after reopen+append, got %d", len(recs))
	}
	if bad, err := Verify(recs); err != nil {
		t.Fatalf("chain broke at %d: %v", bad, err)
	}
	// redaction persisted
	if recs[0].ParamsRedacted["token"] != redactedMarker {
		t.Fatalf("secret must be redacted on disk: %+v", recs[0].ParamsRedacted)
	}
	// tampered file must refuse to open
	bad := filepath.Join(dir, "bad.jsonl")
	if err := os.WriteFile(bad, []byte(`{"seq":1,"event":"plan","record_hash":"00"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(bad); err == nil {
		t.Fatal("opening a tampered log must fail closed")
	}
}
