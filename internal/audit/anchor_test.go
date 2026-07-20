package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// anchorBytes reads the raw anchor file for a log path. Any error (missing,
// unreadable, or a directory in its place) is treated as "no bytes to show"
// -- this helper exists purely for before/after diffing in the fail-closed
// tests, not to assert anchor semantics.
func anchorBytes(t *testing.T, logPath string) []byte {
	t.Helper()
	b, err := os.ReadFile(anchorPath(logPath)) // #nosec G304 -- test fixture path is t.TempDir()-derived
	if err != nil {
		return nil
	}
	return b
}

// assertAnchorFailsClosed opens logPath (already in its final tampered
// on-disk state) and asserts: Open returns a non-nil error, no usable *Log,
// and neither the log file nor the anchor file were modified by the failed
// Open -- Open must never repair a chain, or its anchor, that it refuses to
// trust. It returns the error for case-specific message assertions.
func assertAnchorFailsClosed(t *testing.T, logPath string) error {
	t.Helper()
	beforeLog, lerr := os.ReadFile(logPath) // #nosec G304 -- test fixture path is t.TempDir()-derived
	if lerr != nil && !os.IsNotExist(lerr) {
		t.Fatalf("reading log before Open: %v", lerr)
	}
	beforeAnchor := anchorBytes(t, logPath)

	l, err := Open(logPath)
	if err == nil {
		t.Fatal("Open must fail closed, but returned a nil error")
	}
	if l != nil {
		t.Fatalf("Open must return a nil *Log on failure, got a usable log: %+v", l)
	}

	afterLog, rerr := os.ReadFile(logPath) // #nosec G304 -- test fixture path is t.TempDir()-derived
	if rerr != nil && !os.IsNotExist(rerr) {
		t.Fatalf("re-reading log after Open: %v", rerr)
	}
	if string(beforeLog) != string(afterLog) {
		t.Fatalf("Open must not modify the log file on a failed open;\nbefore=%s\nafter=%s", beforeLog, afterLog)
	}
	afterAnchor := anchorBytes(t, logPath)
	if string(beforeAnchor) != string(afterAnchor) {
		t.Fatalf("Open must not modify the anchor file on a failed open;\nbefore=%s\nafter=%s", beforeAnchor, afterAnchor)
	}
	return err
}

// --- Case 1: anchor present, matches head -> OK --------------------------

func TestAnchor_Case1_MatchesHead_OK(t *testing.T) {
	path, want := buildChainFile(t, 3)

	ab := anchorBytes(t, path)
	if ab == nil {
		t.Fatal("Append must have created an anchor file")
	}
	var st anchorState
	if err := json.Unmarshal(ab, &st); err != nil {
		t.Fatalf("anchor file is not valid JSON: %v", err)
	}
	if st.Seq != want[2].Seq || st.RecordHash != want[2].RecordHash {
		t.Fatalf("anchor does not match written head: got %+v, want seq=%d hash=%s", st, want[2].Seq, want[2].RecordHash)
	}

	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open with a matching anchor must succeed: %v", err)
	}
	if _, err := l.Append(Record{Event: EventExecute, Action: "x"}); err != nil {
		t.Fatalf("Append after a clean reopen: %v", err)
	}
}

// --- Case 2: anchor present, head seq < anchor seq (truncated) -----------

func TestAnchor_Case2_TruncatedTrailingRecords_FailsClosed(t *testing.T) {
	path, _ := buildChainFile(t, 3)
	lines := readLines(t, path)
	if len(lines) != 3 {
		t.Fatalf("test setup: want 3 lines, got %d", len(lines))
	}
	// Drop the last record. The remaining 2-record chain still verifies
	// internally -- Verify alone would not catch this, only the anchor
	// (which still expects seq 3) does.
	writeLines(t, path, lines[:2])

	err := assertAnchorFailsClosed(t, path)
	if !strings.Contains(err.Error(), "truncat") {
		t.Fatalf("expected a truncation error, got: %v", err)
	}
}

// --- Case 3: anchor present, head hash != anchor hash at same seq --------

func TestAnchor_Case3_HeadHashMismatchAtSameSeq_FailsClosed(t *testing.T) {
	path, recs := buildChainFile(t, 3)

	tampered := recs[2]
	tampered.Action = "different-action"
	tampered.PrevRecordHash = recs[1].RecordHash // unchanged link
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
	lines[2] = string(b)
	writeLines(t, path, lines)

	// Sanity: this file still passes chain Verify -- record 3 is
	// self-consistent and correctly linked. Only the anchor comparison
	// catches that it isn't the record the anchor expects.
	verifyRecs, rerr := readAll(path)
	if rerr != nil {
		t.Fatalf("readAll: %v", rerr)
	}
	if bad, verr := Verify(verifyRecs); verr != nil {
		t.Fatalf("test setup: expected the tampered-but-consistent file to pass Verify, broke at %d: %v", bad, verr)
	}

	err = assertAnchorFailsClosed(t, path)
	if !strings.Contains(err.Error(), "tamper") {
		t.Fatalf("expected a tamper error, got: %v", err)
	}
}

// --- Case 4: log non-empty, anchor missing --------------------------------

func TestAnchor_Case4_MissingAnchorOnNonEmptyLog_FailsClosed(t *testing.T) {
	path, _ := buildChainFile(t, 3)
	if err := os.Remove(anchorPath(path)); err != nil {
		t.Fatalf("removing anchor: %v", err)
	}

	err := assertAnchorFailsClosed(t, path)
	if !strings.Contains(err.Error(), "no anchor exists") {
		t.Fatalf("expected a missing-anchor error, got: %v", err)
	}
}

// --- Case 5: no log, no anchor -> OK (fresh install) ----------------------

func TestAnchor_Case5_FreshInstall_OK(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open of a nonexistent log with no anchor must succeed: %v", err)
	}
	r, err := l.Append(Record{Event: EventPlan, Action: "a"})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if r.Seq != 1 {
		t.Fatalf("want seq 1, got %d", r.Seq)
	}
	if anchorBytes(t, path) == nil {
		t.Fatal("first successful Append must create an anchor")
	}
}

// --- Case 6: log empty/absent, anchor present with seq > 0 ---------------

func TestAnchor_Case6_LogDestroyedButAnchorPresent_FailsClosed(t *testing.T) {
	path, _ := buildChainFile(t, 3)
	// Empty the log entirely (e.g. an attacker truncating the whole file to
	// zero bytes) while the anchor still expects seq 3.
	if err := os.WriteFile(path, []byte{}, 0o600); err != nil {
		t.Fatalf("emptying log: %v", err)
	}

	err := assertAnchorFailsClosed(t, path)
	if !strings.Contains(err.Error(), "destroyed") {
		t.Fatalf("expected a log-destroyed error, got: %v", err)
	}
}

// --- Case 7: anchor unreadable/corrupt/garbage ----------------------------

func TestAnchor_Case7_CorruptAnchor_FailsClosed_NotTreatedAsMissing(t *testing.T) {
	path, _ := buildChainFile(t, 3)
	if err := os.WriteFile(anchorPath(path), []byte("not json at all"), 0o600); err != nil {
		t.Fatalf("corrupting anchor: %v", err)
	}

	err := assertAnchorFailsClosed(t, path)
	// A corrupt anchor must produce a distinct "corrupt/unreadable" error,
	// not the "no anchor exists" message case 4 uses -- proving it is NOT
	// silently degraded to the "missing" case.
	if strings.Contains(err.Error(), "no anchor exists") {
		t.Fatalf("a corrupt anchor must not be treated as a missing anchor, got: %v", err)
	}
	if !strings.Contains(err.Error(), "corrupt") && !strings.Contains(err.Error(), "unparseable") {
		t.Fatalf("expected a corrupt/unparseable anchor error, got: %v", err)
	}
}

func TestAnchor_Case7_AnchorPathIsDirectory_FailsClosed(t *testing.T) {
	path, _ := buildChainFile(t, 3)
	if err := os.Remove(anchorPath(path)); err != nil {
		t.Fatalf("removing anchor: %v", err)
	}
	if err := os.Mkdir(anchorPath(path), 0o755); err != nil {
		t.Fatalf("making anchor a directory: %v", err)
	}

	if err := assertAnchorFailsClosed(t, path); err == nil {
		t.Fatal("an anchor path shadowed by a directory must fail closed")
	}
}

// --- Bonus (beyond the 7 required cases): log ahead of a stale anchor ----

func TestAnchor_LogAheadOfAnchor_FailsClosed(t *testing.T) {
	path, recs := buildChainFile(t, 3)
	// Simulate the Append-succeeded-but-anchor-write-failed crash window
	// (see Append in log.go): append a 4th record to the log directly via
	// the internal appendLine helper, WITHOUT updating the anchor.
	next := Record{Seq: 4, Event: EventExecute, Action: "d", PrevRecordHash: recs[2].RecordHash}
	h, err := ComputeRecordHash(next)
	if err != nil {
		t.Fatalf("ComputeRecordHash: %v", err)
	}
	next.RecordHash = h
	if err := appendLine(path, next); err != nil {
		t.Fatalf("appendLine: %v", err)
	}

	err = assertAnchorFailsClosed(t, path)
	if !strings.Contains(err.Error(), "ahead of anchor") {
		t.Fatalf("expected a log-ahead-of-anchor error, got: %v", err)
	}
}

// --- Append fails closed when the anchor write itself fails --------------

func TestAppend_AnchorWriteFailure_FailsClosedButRecordPersists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := l.Append(Record{Event: EventPlan, Action: "a"}); err != nil {
		t.Fatalf("first Append: %v", err)
	}

	// Sabotage the anchor path so the next anchor write's rename fails
	// (rename-file-onto-directory fails with EISDIR regardless of
	// privilege, unlike a plain permission bit which root bypasses).
	ap := anchorPath(path)
	if err := os.Remove(ap); err != nil {
		t.Fatalf("removing anchor: %v", err)
	}
	if err := os.Mkdir(ap, 0o755); err != nil {
		t.Fatalf("mkdir over anchor path: %v", err)
	}

	rec2, err := l.Append(Record{Event: EventExecute, Action: "b"})
	if err == nil {
		t.Fatal("Append must fail closed when the anchor update fails")
	}
	if rec2.Seq != 0 || rec2.RecordHash != "" {
		t.Fatalf("a failed Append must return a zero Record, got %+v", rec2)
	}

	// The underlying log record is already durably fsync'd before the
	// anchor update is attempted, and Append cannot un-write it -- the
	// error signals "not provably anchored," not "nothing happened."
	recs, rerr := readAll(path)
	if rerr != nil {
		t.Fatalf("readAll: %v", rerr)
	}
	if len(recs) != 2 {
		t.Fatalf("want 2 records durably on disk despite the anchor failure, got %d", len(recs))
	}
}

// --- InitAnchor: the explicit adoption path for a pre-anchor log ---------

func TestInitAnchor_AdoptsExistingAnchorlessLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	// Build a "legacy" log the way a pre-anchor-feature version of this
	// package would have: real, correctly hash-chained records written via
	// the unexported appendLine helper directly, bypassing Append's (now
	// anchor-aware) path entirely, so no anchor file exists.
	prev := GenesisPrevHash
	var last Record
	for i := 1; i <= 3; i++ {
		r := Record{Seq: uint64(i), Event: EventPlan, Action: "legacy", PrevRecordHash: prev}
		h, err := ComputeRecordHash(r)
		if err != nil {
			t.Fatalf("ComputeRecordHash: %v", err)
		}
		r.RecordHash = h
		if err := appendLine(path, r); err != nil {
			t.Fatalf("appendLine: %v", err)
		}
		prev = h
		last = r
	}
	if anchorBytes(t, path) != nil {
		t.Fatal("test setup: legacy log must not have an anchor yet")
	}

	// Case 4 in action: Open refuses this anchor-less-but-non-empty log.
	if _, err := Open(path); err == nil {
		t.Fatal("Open of an existing verified log with no anchor must fail closed before adoption")
	}

	// Adoption is a distinct, explicit call -- never automatic.
	if err := InitAnchor(path); err != nil {
		t.Fatalf("InitAnchor: %v", err)
	}
	ab := anchorBytes(t, path)
	if ab == nil {
		t.Fatal("InitAnchor must create an anchor file")
	}
	var st anchorState
	if err := json.Unmarshal(ab, &st); err != nil {
		t.Fatalf("anchor is not valid JSON: %v", err)
	}
	if st.Seq != last.Seq || st.RecordHash != last.RecordHash {
		t.Fatalf("adopted anchor does not match the log's actual head: got %+v, want seq=%d hash=%s", st, last.Seq, last.RecordHash)
	}

	// Open now succeeds, and normal operation (Append updating the anchor)
	// resumes.
	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open must succeed once the anchor is adopted: %v", err)
	}
	if _, err := l.Append(Record{Event: EventExecute, Action: "e"}); err != nil {
		t.Fatalf("Append after adoption: %v", err)
	}
	recs, err := l.Records()
	if err != nil {
		t.Fatalf("Records: %v", err)
	}
	if len(recs) != 4 {
		t.Fatalf("want 4 records, got %d", len(recs))
	}
}

func TestInitAnchor_RefusesIfAnchorAlreadyExists(t *testing.T) {
	path, _ := buildChainFile(t, 2) // Append already created a valid anchor
	if err := InitAnchor(path); err == nil {
		t.Fatal("InitAnchor must refuse to overwrite an existing anchor")
	}
}

func TestInitAnchor_RefusesUnverifiableLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	bad := `{"seq":1,"event":"plan","record_hash":"00"}` + "\n"
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatalf("writing bad fixture: %v", err)
	}
	if err := InitAnchor(path); err == nil {
		t.Fatal("InitAnchor must refuse to anchor a chain that does not verify")
	}
	if anchorBytes(t, path) != nil {
		t.Fatal("InitAnchor must not create an anchor for a chain that failed verification")
	}
}

func TestInitAnchor_InMemoryLogRejected(t *testing.T) {
	if err := InitAnchor(""); err == nil {
		t.Fatal("InitAnchor must reject an in-memory (empty path) log")
	}
}
