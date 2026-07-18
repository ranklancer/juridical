package main

import (
	"bytes"
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

func TestRun_UnknownCommand(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"bogus"}, &out, &errb); code != 2 {
		t.Fatalf("exit=%d, want 2 (unknown)", code)
	}
}
