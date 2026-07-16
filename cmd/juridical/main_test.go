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
	if code := run([]string{"serve"}, &out, &errb); code != 3 {
		t.Fatalf("exit=%d, want 3 (not implemented)", code)
	}
	if !strings.Contains(errb.String(), "not implemented") {
		t.Fatalf("expected not-implemented notice, got %q", errb.String())
	}
}

func TestRun_UnknownCommand(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"bogus"}, &out, &errb); code != 2 {
		t.Fatalf("exit=%d, want 2 (unknown)", code)
	}
}
