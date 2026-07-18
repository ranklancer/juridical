package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun_VersionFlag(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"-version"}, &out, &errb); code != 0 {
		t.Fatalf("exit=%d, want 0", code)
	}
	if !strings.Contains(out.String(), "juridical") {
		t.Fatalf("version output missing product name: %q", out.String())
	}
}

func TestRun_NoArgsPrintsUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(nil, &out, &errb); code != 0 {
		t.Fatalf("exit=%d, want 0", code)
	}
	if !strings.Contains(out.String(), "Usage:") {
		t.Fatalf("expected usage, got %q", out.String())
	}
}

func TestRun_KnownCommandNotImplemented(t *testing.T) {
	var out, errb bytes.Buffer
	// serve is implemented as of P1-d-2 (see serve_test.go); action/plan/
	// approve/audit remain scaffold stubs.
	if code := run([]string{"action"}, &out, &errb); code != 3 {
		t.Fatalf("exit=%d, want 3 (not implemented)", code)
	}
	if !strings.Contains(errb.String(), "not implemented") {
		t.Fatalf("expected not-implemented notice, got %q", errb.String())
	}
}

func TestRun_Serve_MisconfiguredExitsNonZero(t *testing.T) {
	// No -audit-log and no -dev: serve must refuse to start (fail-closed)
	// rather than silently falling back to a non-durable audit log.
	var out, errb bytes.Buffer
	if code := run([]string{"serve"}, &out, &errb); code == 0 {
		t.Fatalf("exit=%d, want non-zero for a misconfigured serve", code)
	}
	if !strings.Contains(errb.String(), "audit-log") {
		t.Fatalf("expected an audit-log configuration error, got %q", errb.String())
	}
}

// Process-level proof of the audit tamper-evidence fail-closed guarantee:
// pointing `juridical serve` at an on-disk audit log whose hash chain does
// not verify must exit non-zero and must never reach the point of binding a
// listener -- the engine must not be able to start appending onto a
// compromised chain.
func TestRun_Serve_TamperedAuditLog_ExitsNonZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	tampered := `{"seq":1,"ts":"2024-01-01T00:00:00Z","event":"plan","record_hash":"00"}` + "\n"
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatalf("writing tampered fixture: %v", err)
	}

	var out, errb bytes.Buffer
	code := run([]string{"serve", "-audit-log", path}, &out, &errb)
	if code == 0 {
		t.Fatalf("exit=%d, want non-zero when the audit log fails tamper verification", code)
	}
	if !strings.Contains(errb.String(), "audit") {
		t.Fatalf("expected an audit-log error on stderr, got %q", errb.String())
	}
	if strings.Contains(out.String(), "listening on") {
		t.Fatalf("serve must never report listening when the audit log fails to open, got %q", out.String())
	}
}

func TestRun_UnknownCommand(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"bogus"}, &out, &errb); code != 2 {
		t.Fatalf("exit=%d, want 2 (unknown)", code)
	}
}
