package approve

import (
	"errors"
	"testing"
	"time"

	"github.com/juridical-docker/juridical/internal/blast"
)

func samplePlan() Plan {
	return Plan{
		Action: "restart-service", Backend: "compose", Project: "web",
		Params:        map[string]string{"service": "api", "project": "web"},
		Target:        "compose:web/api",
		DeclaredBound: blast.DeclaredBound{MaxHosts: 1, Service: "api", FleetPct: 100},
		ComputedReach: blast.Reach{Hosts: 1, Services: 1, Instances: 1, FleetPct: 100},
	}
}

func TestPlanHash_DeterministicAndDrifts(t *testing.T) {
	p := samplePlan()
	h1 := PlanHash(p)
	if h1 == "" || len(h1) != 64 {
		t.Fatalf("hash should be 64 hex chars, got %q", h1)
	}
	// param order must not matter
	p2 := samplePlan()
	p2.Params = map[string]string{"project": "web", "service": "api"}
	if PlanHash(p2) != h1 {
		t.Fatal("param ordering must not change the hash")
	}
	// reach drift changes the hash (T3)
	p3 := samplePlan()
	p3.ComputedReach.Instances = 2
	if PlanHash(p3) == h1 {
		t.Fatal("reach drift must change the hash")
	}
	// param drift changes the hash
	p4 := samplePlan()
	p4.Params["service"] = "api2"
	if PlanHash(p4) == h1 {
		t.Fatal("param drift must change the hash")
	}
}

func TestTokenStore(t *testing.T) {
	s := NewTokenStore()
	if _, err := s.Mint("", "agent", "alice", time.Minute); !errors.Is(err, ErrEmptyPlanHash) {
		t.Fatalf("empty plan hash must refuse, got %v", err)
	}
	tok, err := s.Mint("hashA", "agent", "alice", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Consume(tok, "hashB"); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("hash mismatch, got %v", err)
	}
	if _, err := s.Consume("nothex", "hashA"); !errors.Is(err, ErrTokenUnknown) {
		t.Fatalf("non-hex secret => unknown, got %v", err)
	}
	if _, err := s.Consume("aabbcc", "hashA"); !errors.Is(err, ErrTokenUnknown) {
		t.Fatalf("wrong-length secret => unknown, got %v", err)
	}
	c, err := s.Consume(tok, "hashA")
	if err != nil || c.Approver != "alice" || c.ProposerKeyID != "agent" {
		t.Fatalf("consume: %v %+v", err, c)
	}
	if _, err := s.Consume(tok, "hashA"); !errors.Is(err, ErrTokenConsumed) {
		t.Fatalf("reuse => consumed, got %v", err)
	}
	// expiry
	tok2, _ := s.Mint("hashC", "agent", "bob", time.Millisecond)
	time.Sleep(3 * time.Millisecond)
	if _, err := s.Consume(tok2, "hashC"); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expired, got %v", err)
	}
}

func TestCheckSoD(t *testing.T) {
	if err := CheckSoD("agent", "alice", true); err != nil {
		t.Fatalf("distinct human approver ok, got %v", err)
	}
	if err := CheckSoD("agent", "agent", true); !errors.Is(err, ErrSelfApproval) {
		t.Fatalf("self-approval, got %v", err)
	}
	if err := CheckSoD("agent", "alice", false); !errors.Is(err, ErrNotHuman) {
		t.Fatalf("non-human approver, got %v", err)
	}
	if err := CheckSoD("agent", "  ", true); !errors.Is(err, ErrNotHuman) {
		t.Fatalf("empty approver, got %v", err)
	}
}

func TestExecutable(t *testing.T) {
	p := samplePlan()
	p.WithinBound = true
	p.Verdict = blast.VerdictAllow
	if !p.Executable() {
		t.Fatal("within+allow should be executable")
	}
	p.Verdict = blast.VerdictBlock
	if p.Executable() {
		t.Fatal("block must not be executable")
	}
}
