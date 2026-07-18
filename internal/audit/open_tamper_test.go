package audit

// Fault-injection coverage for Open's verify-on-open, fail-closed behaviour
// (tamper-evidence: the internal design spec section 7). Each test builds a real, on-disk
// N-record chain through the genuine Append path (so every record is
// byte-for-byte what the log itself produces, including fsync), corrupts it
// exactly one way on disk, and asserts that Open (a) returns a non-nil
// error, (b) returns no usable *Log, and (c) leaves the tampered file
// byte-identical on disk -- Open must never repair, truncate, or otherwise
// rewrite a chain it refuses to trust. Each assertion here goes red if
// verify-on-open were removed from Open (i.e. if Open reverted to trusting
// the tail read without calling Verify).
import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildChainFile opens a fresh log at a temp path, appends n well-formed
// records through the real Append path, and returns the path and the
// records as written (with their final Seq/PrevRecordHash/RecordHash).
func buildChainFile(t *testing.T, n int) (path string, recs []Record) {
	t.Helper()
	dir := t.TempDir()
	path = filepath.Join(dir, "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open (fresh log): %v", err)
	}
	for i := 0; i < n; i++ {
		r, err := l.Append(Record{Event: EventPlan, Action: "restart-service", Backend: "compose", Project: "p"})
		if err != nil {
			t.Fatalf("Append record %d: %v", i, err)
		}
		recs = append(recs, r)
	}
	return path, recs
}

// readLines returns the on-disk JSONL file split into its record lines
// (trailing newline stripped, no empty trailing element).
func readLines(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path) // #nosec G304 -- test fixture path is t.TempDir()-derived
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	s := strings.TrimRight(string(raw), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// writeLines rewrites path from lines, one JSON record per line, with a
// trailing newline (matching the real appendLine format).
func writeLines(t *testing.T, path string, lines []string) {
	t.Helper()
	content := strings.Join(lines, "\n")
	if len(lines) > 0 {
		content += "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

// assertOpenFailsClosedNoRepair opens path (which must already be in its
// final tampered-on-disk state) and asserts: Open returns a non-nil error,
// Open returns no usable *Log, and the file on disk is untouched by the
// failed Open call -- proving Open does not attempt to repair, truncate, or
// silently rewrite a chain it cannot verify.
func assertOpenFailsClosedNoRepair(t *testing.T, path string) {
	t.Helper()
	before, err := os.ReadFile(path) // #nosec G304 -- test fixture path is t.TempDir()-derived
	if err != nil {
		t.Fatalf("reading tampered fixture before Open: %v", err)
	}
	l, err := Open(path)
	if err == nil {
		t.Fatal("Open must fail closed on a tampered log, but returned a nil error")
	}
	if l != nil {
		t.Fatalf("Open must return a nil *Log on failure, got a usable log: %+v", l)
	}
	after, rerr := os.ReadFile(path) // #nosec G304 -- test fixture path is t.TempDir()-derived
	if rerr != nil {
		t.Fatalf("re-reading tampered fixture after Open: %v", rerr)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("Open must not repair/truncate/rewrite a tampered log on disk;\nbefore=%s\nafter=%s", before, after)
	}
}

// Happy path: a clean, on-disk chain built by real Append calls must open
// successfully, and the next Append after reopen must link onto the
// verified tail (not an unverified tail read).
func TestOpen_HappyPath_VerifiesExistingChainAndAppends(t *testing.T) {
	path, want := buildChainFile(t, 3)

	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open of a clean chain must succeed: %v", err)
	}
	rec, err := l.Append(Record{Event: EventExecute, Action: "restart-service"})
	if err != nil {
		t.Fatalf("Append after reopen: %v", err)
	}
	if rec.Seq != 4 {
		t.Fatalf("want seq 4 after reopen+append, got %d", rec.Seq)
	}
	if rec.PrevRecordHash != want[2].RecordHash {
		t.Fatalf("new record must link to the verified tail's hash %q, got %q", want[2].RecordHash, rec.PrevRecordHash)
	}
	recs, err := l.Records()
	if err != nil {
		t.Fatalf("Records: %v", err)
	}
	if len(recs) != 4 {
		t.Fatalf("want 4 records after reopen+append, got %d", len(recs))
	}
	if bad, verr := Verify(recs); verr != nil {
		t.Fatalf("chain must verify end-to-end after reopen+append, broke at %d: %v", bad, verr)
	}
}

// (a) A mutated field in a middle record: its stored record_hash no longer
// matches the recomputed hash over its (now-changed) content.
func TestOpen_FailsClosed_MutatedField(t *testing.T) {
	path, _ := buildChainFile(t, 3)
	lines := readLines(t, path)
	if len(lines) != 3 {
		t.Fatalf("test setup: want 3 lines, got %d", len(lines))
	}
	mutated := strings.Replace(lines[1], `"action":"restart-service"`, `"action":"tampered-action"`, 1)
	if mutated == lines[1] {
		t.Fatal("test setup: mutation did not change record 1's line")
	}
	lines[1] = mutated
	writeLines(t, path, lines)

	assertOpenFailsClosedNoRepair(t, path)
}

// (b) A broken prev-hash link: record N's prev_record_hash no longer equals
// record N-1's record_hash. The tampered record's own record_hash is
// recomputed to stay self-consistent, so this isolates the prev-hash link
// check from the record_hash check.
func TestOpen_FailsClosed_BrokenPrevHashLink(t *testing.T) {
	path, recs := buildChainFile(t, 3)

	tampered := recs[2]
	tampered.PrevRecordHash = strings.Repeat("0", 64) // plausible-looking but wrong
	newHash, err := ComputeRecordHash(tampered)
	if err != nil {
		t.Fatalf("ComputeRecordHash: %v", err)
	}
	tampered.RecordHash = newHash

	b, err := json.Marshal(tampered)
	if err != nil {
		t.Fatalf("marshal tampered record: %v", err)
	}
	lines := readLines(t, path)
	if len(lines) != 3 {
		t.Fatalf("test setup: want 3 lines, got %d", len(lines))
	}
	lines[2] = string(b)
	writeLines(t, path, lines)

	assertOpenFailsClosedNoRepair(t, path)
}

// (c) A reordered pair of records: swapping two on-disk lines breaks the
// prev-hash chain (and seq monotonicity) even though every individual line
// is a well-formed, self-consistent record.
func TestOpen_FailsClosed_ReorderedRecords(t *testing.T) {
	path, _ := buildChainFile(t, 3)
	lines := readLines(t, path)
	if len(lines) != 3 {
		t.Fatalf("test setup: want 3 lines, got %d", len(lines))
	}
	lines[1], lines[2] = lines[2], lines[1]
	writeLines(t, path, lines)

	assertOpenFailsClosedNoRepair(t, path)
}

// (d) A truncated/partial trailing line: the last record is cut mid-JSON
// with no closing brace and no trailing newline, simulating a crash or
// partial write that was never fsync'd as a complete record.
func TestOpen_FailsClosed_TruncatedTrailingLine(t *testing.T) {
	path, _ := buildChainFile(t, 3)
	lines := readLines(t, path)
	if len(lines) != 3 {
		t.Fatalf("test setup: want 3 lines, got %d", len(lines))
	}
	last := lines[2]
	if len(last) < 40 {
		t.Fatalf("test setup: last line too short to truncate meaningfully: %q", last)
	}
	truncated := last[:len(last)-20] // mid-object, no closing brace
	content := lines[0] + "\n" + lines[1] + "\n" + truncated
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing truncated fixture: %v", err)
	}

	assertOpenFailsClosedNoRepair(t, path)
}

// (e) An unknown/extra field on an otherwise well-formed, correctly
// hash-chained record: strict decode must reject it even though the
// hash-covered struct fields were never touched (this is the same
// invariant TestOpen_RejectsUnknownFieldRecord in log_strictdecode_test.go
// pins for a single-record chain; this variant confirms it also holds
// mid-chain, over a real N-record file built by Append).
func TestOpen_FailsClosed_UnknownFieldInRecord(t *testing.T) {
	path, _ := buildChainFile(t, 3)
	lines := readLines(t, path)
	if len(lines) != 3 {
		t.Fatalf("test setup: want 3 lines, got %d", len(lines))
	}
	line := lines[1]
	if !strings.HasSuffix(line, "}") {
		t.Fatalf("unexpected record encoding: %s", line)
	}
	lines[1] = line[:len(line)-1] + `,"injected_field":"x"}`
	writeLines(t, path, lines)

	assertOpenFailsClosedNoRepair(t, path)
}

// (f) An empty-but-present file is treated as a fresh chain, per the same
// convention as a missing file (readAll returns no records, Verify of an
// empty slice trivially holds) -- Open must succeed and the first append
// must start a brand-new chain at seq 1 linked to genesis.
func TestOpen_EmptyButPresentFile_IsFreshChain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(path, []byte{}, 0o600); err != nil {
		t.Fatalf("writing empty fixture: %v", err)
	}

	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open of an empty-but-present file must succeed as a fresh chain: %v", err)
	}
	r, err := l.Append(Record{Event: EventPlan, Action: "restart-service"})
	if err != nil {
		t.Fatalf("Append on a fresh chain: %v", err)
	}
	if r.Seq != 1 {
		t.Fatalf("first record on a fresh chain must be seq 1, got %d", r.Seq)
	}
	if r.PrevRecordHash != GenesisPrevHash {
		t.Fatalf("first record must link to genesis, got %q", r.PrevRecordHash)
	}
}

// (f) A file with garbage content (not JSON at all) must fail closed, in
// contrast with the empty-file case above.
func TestOpen_FailsClosed_GarbageFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(path, []byte("this is not json at all\nneither is this\n"), 0o600); err != nil {
		t.Fatalf("writing garbage fixture: %v", err)
	}

	assertOpenFailsClosedNoRepair(t, path)
}
