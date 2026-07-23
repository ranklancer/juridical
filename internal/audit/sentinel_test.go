package audit

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestCheckAnchor_SentinelsMatchCaseTable proves each of the eight
// Open-path anchor cases is distinguishable via errors.Is against the
// exported sentinels (the internal design spec-AUDITCLI prerequisite): a CLI mapping exit
// codes must never string-match error text.
func TestCheckAnchor_SentinelsMatchCaseTable(t *testing.T) {
	t.Run("case1_MatchesHead_OK", func(t *testing.T) {
		path, _ := buildChainFile(t, 3)
		if _, err := Open(path); err != nil {
			t.Fatalf("want nil error, got %v", err)
		}
	})

	t.Run("case2_Truncated_ErrTruncated", func(t *testing.T) {
		path, _ := buildChainFile(t, 3)
		lines := readLines(t, path)
		writeLines(t, path, lines[:2])
		_, err := Open(path)
		if !errors.Is(err, ErrTruncated) {
			t.Fatalf("want errors.Is ErrTruncated, got %v", err)
		}
	})

	t.Run("case3_Tampered_ErrTampered", func(t *testing.T) {
		path, recs := buildChainFile(t, 3)
		tampered := recs[2]
		tampered.Action = "different-action"
		tampered.PrevRecordHash = recs[1].RecordHash
		h, err := ComputeRecordHash(tampered)
		if err != nil {
			t.Fatalf("ComputeRecordHash: %v", err)
		}
		tampered.RecordHash = h
		b, err := json.Marshal(tampered)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		lines := readLines(t, path)
		lines[2] = string(b)
		writeLines(t, path, lines)
		_, oerr := Open(path)
		if !errors.Is(oerr, ErrTampered) {
			t.Fatalf("want errors.Is ErrTampered, got %v", oerr)
		}
	})

	t.Run("case4_AnchorMissing_ErrAnchorMissing", func(t *testing.T) {
		path, _ := buildChainFile(t, 3)
		if err := os.Remove(anchorPath(path)); err != nil {
			t.Fatalf("removing anchor: %v", err)
		}
		_, err := Open(path)
		if !errors.Is(err, ErrAnchorMissing) {
			t.Fatalf("want errors.Is ErrAnchorMissing, got %v", err)
		}
	})

	t.Run("case5_FreshInstall_OK", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "audit.jsonl")
		if _, err := Open(path); err != nil {
			t.Fatalf("want nil error, got %v", err)
		}
	})

	t.Run("case6_LogDestroyed_ErrTruncated", func(t *testing.T) {
		path, _ := buildChainFile(t, 3)
		if err := os.WriteFile(path, []byte{}, 0o600); err != nil {
			t.Fatalf("emptying log: %v", err)
		}
		_, err := Open(path)
		if !errors.Is(err, ErrTruncated) {
			t.Fatalf("want errors.Is ErrTruncated, got %v", err)
		}
	})

	// case 7 is load-bearing: proves a corrupt anchor is NEVER degraded to
	// the case-4 "missing" verdict, at the sentinel level (not just by
	// message-substring, as anchor_test.go already checks).
	t.Run("case7_CorruptAnchor_ErrAnchorCorrupt_NotErrAnchorMissing", func(t *testing.T) {
		path, _ := buildChainFile(t, 3)
		if err := os.WriteFile(anchorPath(path), []byte("not json at all"), 0o600); err != nil {
			t.Fatalf("corrupting anchor: %v", err)
		}
		_, err := Open(path)
		if !errors.Is(err, ErrAnchorCorrupt) {
			t.Fatalf("want errors.Is ErrAnchorCorrupt, got %v", err)
		}
		if errors.Is(err, ErrAnchorMissing) {
			t.Fatalf("a corrupt anchor must NOT also satisfy errors.Is ErrAnchorMissing (case 7 vs case 4): %v", err)
		}
	})

	t.Run("case8_LogAheadOfAnchor_ErrLogAheadOfAnchor", func(t *testing.T) {
		path, recs := buildChainFile(t, 3)
		next := Record{Seq: 4, Event: EventExecute, Action: "d", PrevRecordHash: recs[2].RecordHash}
		h, err := ComputeRecordHash(next)
		if err != nil {
			t.Fatalf("ComputeRecordHash: %v", err)
		}
		next.RecordHash = h
		if err := appendLine(path, next); err != nil {
			t.Fatalf("appendLine: %v", err)
		}
		_, oerr := Open(path)
		if !errors.Is(oerr, ErrLogAheadOfAnchor) {
			t.Fatalf("want errors.Is ErrLogAheadOfAnchor, got %v", oerr)
		}
	})
}

// TestInspectAnchor_Case8Detail proves AnchorSnapshot correctly reports the
// case-8 "excess is exactly one record, prior hash matches anchor" signature
// -- the exact evidence `juridical audit verify` must print for an operator
// to judge (SECURITY.md: this signature is reproducible by a one-record
// forgery and must never be auto-blessed).
func TestInspectAnchor_Case8Detail(t *testing.T) {
	path, recs := buildChainFile(t, 2)
	// Snapshot the anchor at seq=2 before appending a third record whose
	// anchor update we then "lose" (simulating the crash window), leaving
	// the log durably at 3 records but the anchor stuck at seq=2 -- the
	// real case-8 shape, built entirely from genuine writes.
	staleAnchor, err := os.ReadFile(anchorPath(path)) // #nosec G304 -- t.TempDir()-derived
	if err != nil {
		t.Fatalf("reading anchor snapshot: %v", err)
	}

	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	third, err := l.Append(Record{Event: EventExecute, Action: "c", PrevRecordHash: recs[1].RecordHash})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := os.WriteFile(anchorPath(path), staleAnchor, 0o600); err != nil {
		t.Fatalf("restoring stale anchor: %v", err)
	}

	snap, verr := InspectAnchor(path)
	if !errors.Is(verr, ErrLogAheadOfAnchor) {
		t.Fatalf("want errors.Is ErrLogAheadOfAnchor, got %v", verr)
	}
	if snap.ExcessRecords != 1 {
		t.Fatalf("want ExcessRecords=1, got %d", snap.ExcessRecords)
	}
	if !snap.PriorMatchesAnchor {
		t.Fatalf("want PriorMatchesAnchor=true (prior record's hash must match the stale anchor), snap=%+v", snap)
	}
	if snap.HeadHash != third.RecordHash {
		t.Fatalf("want HeadHash to be the excess record's hash, got %q want %q", snap.HeadHash, third.RecordHash)
	}
}
