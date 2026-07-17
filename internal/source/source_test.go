package source

import "testing"

func TestReach(t *testing.T) {
	// two hosts, one service, three instances, inventory 6 -> 50%
	m := []Container{
		{ID: "c1", Service: "api", Host: "h1"},
		{ID: "c2", Service: "api", Host: "h1"},
		{ID: "c3", Service: "api", Host: "h2"},
	}
	r := Reach(m, 6)
	if r.Hosts != 2 || r.Services != 1 || r.Instances != 3 || r.FleetPct != 50 {
		t.Fatalf("unexpected reach: %+v", r)
	}
	// multi-service matched set is reflected in Services (over-reach signal)
	multi := []Container{
		{ID: "c1", Service: "api", Host: "h1"},
		{ID: "c2", Service: "worker", Host: "h1"},
	}
	if r := Reach(multi, 2); r.Services != 2 {
		t.Fatalf("multi-service reach.Services=%d want 2", r.Services)
	}
	if r := Reach(nil, 0); r.Instances != 0 || r.FleetPct != 0 {
		t.Fatalf("empty reach: %+v", r)
	}
}
