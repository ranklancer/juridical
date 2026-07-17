package blast

import "testing"

func TestValidateDeclared(t *testing.T) {
	base := DeclaredBound{MaxHosts: 1, Service: "api", FleetPct: 100}
	if err := ValidateDeclared(base, nil); err != nil {
		t.Fatalf("valid bound rejected: %v", err)
	}
	if err := ValidateDeclared(base, []string{"namespace"}); err == nil {
		t.Fatal("dormant dimension must refuse (FC3)")
	}
	if err := ValidateDeclared(DeclaredBound{Service: "", FleetPct: 100}, nil); err == nil {
		t.Fatal("missing service must refuse")
	}
	if err := ValidateDeclared(DeclaredBound{Service: "api", MaxHosts: -1, FleetPct: 100}, nil); err == nil {
		t.Fatal("negative max_hosts must refuse")
	}
	if err := ValidateDeclared(DeclaredBound{Service: "api", FleetPct: 101}, nil); err == nil {
		t.Fatal("fleet_pct>100 must refuse")
	}
}

func TestComputeFleetPct(t *testing.T) {
	cases := []struct{ inst, inv, want int }{
		{0, 10, 0}, {1, 1, 100}, {1, 4, 25}, {1, 3, 34}, {5, 0, 100}, {10, 5, 100},
	}
	for _, c := range cases {
		if got := ComputeFleetPct(c.inst, c.inv); got != c.want {
			t.Errorf("ComputeFleetPct(%d,%d)=%d want %d", c.inst, c.inv, got, c.want)
		}
	}
}

func TestWithinAndEvaluate(t *testing.T) {
	db := DeclaredBound{MaxHosts: 1, Service: "api", FleetPct: 100}
	ok := Reach{Hosts: 1, Services: 1, Instances: 1, FleetPct: 100}
	if !Within(db, ok) {
		t.Fatal("in-bound reach should be within")
	}
	if Within(db, Reach{Hosts: 2, Services: 1, FleetPct: 100}) {
		t.Fatal("host over-reach should not be within")
	}
	if Within(db, Reach{Hosts: 1, Services: 2, FleetPct: 100}) {
		t.Fatal("multi-service should not be within")
	}

	block := Enforcement{MaxHosts: ModeBlock, Service: ModeBlock, FleetPct: ModeBlock}
	if v, _ := Evaluate(db, ok, block); v != VerdictAllow {
		t.Fatalf("in-bound => ALLOW, got %s", v)
	}
	if v, br := Evaluate(db, Reach{Hosts: 2, Services: 1, FleetPct: 100}, block); v != VerdictBlock || len(br) == 0 {
		t.Fatalf("host breach in block => BLOCK, got %s %v", v, br)
	}
	warn := Enforcement{MaxHosts: ModeWarn, Service: ModeWarn, FleetPct: ModeWarn}
	if v, _ := Evaluate(db, Reach{Hosts: 2, Services: 1, FleetPct: 100}, warn); v != VerdictWarn {
		t.Fatalf("host breach in warn => WARN, got %s", v)
	}
	off := Enforcement{MaxHosts: ModeOff, Service: ModeOff, FleetPct: ModeOff}
	if v, br := Evaluate(db, Reach{Hosts: 9, Services: 3, FleetPct: 100}, off); v != VerdictAllow || len(br) != 0 {
		t.Fatalf("off axes => ALLOW no breach, got %s %v", v, br)
	}
}
