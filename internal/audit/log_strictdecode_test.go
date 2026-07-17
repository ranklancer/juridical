package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An unknown/renamed field on an otherwise-VALID, correctly hash-chained record
// must fail the load CLOSED. Injecting the field into the on-disk line does not
// touch the hash-covered struct fields, so absent strict decode the record would
// decode (unknown field ignored), its record_hash would still verify, and Open
// would SUCCEED — this test therefore isolates the strict-decode behaviour: it
// goes red if readAll reverts to a lenient json.Unmarshal.
func TestOpen_RejectsUnknownFieldRecord(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")

	l, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(Record{Event: EventPlan, Action: "restart-service"}); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimRight(string(raw), "\n")
	if !strings.HasSuffix(line, "}") {
		t.Fatalf("unexpected record encoding: %s", line)
	}
	tampered := line[:len(line)-1] + `,"injected_field":"x"}` + "\n"
	if err := os.WriteFile(p, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(p); err == nil {
		t.Fatal("Open must fail closed on an audit record with an unknown/renamed field")
	}
}

// Round-trip guard: strict decode must still accept a well-formed record the
// log wrote itself, so the hardening does not break normal operation.
func TestOpen_AcceptsWellFormedRecord(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	l, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(Record{Event: EventPlan, Action: "restart-service"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(p); err != nil {
		t.Fatalf("strict decode must accept a well-formed, log-written record: %v", err)
	}
}
