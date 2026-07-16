package version

import (
	"runtime"
	"strings"
	"testing"
)

func TestGetPopulatesGoVersion(t *testing.T) {
	got := Get()
	if got.Go != runtime.Version() {
		t.Fatalf("Go = %q, want %q", got.Go, runtime.Version())
	}
	if got.Version == "" || got.Commit == "" || got.Date == "" {
		t.Fatalf("build metadata must not be empty: %+v", got)
	}
}

func TestStringMentionsVersionAndCommit(t *testing.T) {
	i := Info{Version: "1.2.3", Commit: "abc1234", Date: "2026-01-01T00:00:00Z", Go: "go1.22"}
	s := i.String()
	for _, want := range []string{"juridical", "1.2.3", "abc1234", "go1.22"} {
		if !strings.Contains(s, want) {
			t.Fatalf("String()=%q missing %q", s, want)
		}
	}
}
