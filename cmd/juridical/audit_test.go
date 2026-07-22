package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/juridical-docker/juridical/internal/audit"
)

// buildAuditChain builds a REAL on-disk audit log with n records via the
// genuine audit.Open + Log.Append path -- the same path production `serve`
// uses -- which also creates/updates the anchor after every successful
// Append.
func buildAuditChain(t *testing.T, n int) (path string, recs []audit.Record) {
	t.Helper()
	dir := t.TempDir()
	path = filepath.Join(dir, "audit.jsonl")
	l, err := audit.Open(path)
	if err != nil {
		t.Fatalf("Open (fresh log): %v", err)
	}
	for i := 0; i < n; i++ {
		r, err := l.Append(audit.Record{Event: audit.EventPlan, Action: "restart-service"})
		if err != nil {
			t.Fatalf("Append record %d: %v", i, err)
		}
		recs = append(recs, r)
	}
	return path, recs
}

func anchorFilePath(logPath string) string { return logPath + ".anchor" }

func readFileOrNil(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- test fixture path is t.TempDir()-derived
	if err != nil {
		return nil
	}
	return b
}

func readRawLines(t *testing.T, path string) []string {
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

func writeRawLines(t *testing.T, path string, lines []string) {
	t.Helper()
	content := strings.Join(lines, "\n")
	if len(lines) > 0 {
		content += "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

// assertVerifyDoesNotMutate runs `audit verify` against logPath and asserts
// the log file and anchor file are byte-identical before and after --
// proving the read-only verb never creates, repairs, or removes anything.
func assertVerifyDoesNotMutate(t *testing.T, logPath string) (code int, out, errOut string) {
	t.Helper()
	beforeLog := readFileOrNil(t, logPath)
	beforeAnchor := readFileOrNil(t, anchorFilePath(logPath))

	var stdout, stderr bytes.Buffer
	code = runAuditVerify([]string{"-audit-log", logPath}, &stdout, &stderr)

	afterLog := readFileOrNil(t, logPath)
	afterAnchor := readFileOrNil(t, anchorFilePath(logPath))
	if !bytes.Equal(beforeLog, afterLog) {
		t.Fatalf("verify must not mutate the log file;\nbefore=%s\nafter=%s", beforeLog, afterLog)
	}
	if !bytes.Equal(beforeAnchor, afterAnchor) {
		t.Fatalf("verify must not mutate the anchor file;\nbefore=%s\nafter=%s", beforeAnchor, afterAnchor)
	}
	return code, stdout.String(), stderr.String()
}

// --- Case 1: anchor matches head -> exit 0 --------------------------------

func TestAuditVerify_Case1_OK_Exit0(t *testing.T) {
	path, _ := buildAuditChain(t, 3)
	code, out, errOut := assertVerifyDoesNotMutate(t, path)
	if code != 0 {
		t.Fatalf("exit=%d, want 0; out=%s stderr=%s", code, out, errOut)
	}
	if !strings.Contains(out, "OK") {
		t.Fatalf("expected an OK result in output, got %q", out)
	}
}

// --- Case 2: truncated tail -> exit 2 -------------------------------------

func TestAuditVerify_Case2_Truncated_Exit2(t *testing.T) {
	path, _ := buildAuditChain(t, 3)
	lines := readRawLines(t, path)
	if len(lines) != 3 {
		t.Fatalf("test setup: want 3 lines, got %d", len(lines))
	}
	writeRawLines(t, path, lines[:2])

	code, _, errOut := assertVerifyDoesNotMutate(t, path)
	if code != 2 {
		t.Fatalf("exit=%d, want 2; stderr=%s", code, errOut)
	}
}

// --- Case 3: tampered head at same seq -> exit 2 --------------------------

func TestAuditVerify_Case3_Tampered_Exit2(t *testing.T) {
	path, recs := buildAuditChain(t, 3)
	tampered := recs[2]
	tampered.Action = "different-action"
	tampered.PrevRecordHash = recs[1].RecordHash
	newHash, err := audit.ComputeRecordHash(tampered)
	if err != nil {
		t.Fatalf("ComputeRecordHash: %v", err)
	}
	tampered.RecordHash = newHash
	b, err := json.Marshal(tampered)
	if err != nil {
		t.Fatalf("marshal tampered record: %v", err)
	}
	lines := readRawLines(t, path)
	lines[2] = string(b)
	writeRawLines(t, path, lines)

	code, _, errOut := assertVerifyDoesNotMutate(t, path)
	if code != 2 {
		t.Fatalf("exit=%d, want 2; stderr=%s", code, errOut)
	}
}

// --- Case 4: anchor missing on a non-empty log -> exit 4 ------------------

func TestAuditVerify_Case4_AnchorMissing_Exit4(t *testing.T) {
	path, _ := buildAuditChain(t, 3)
	if err := os.Remove(anchorFilePath(path)); err != nil {
		t.Fatalf("removing anchor: %v", err)
	}

	code, _, errOut := assertVerifyDoesNotMutate(t, path)
	if code != 4 {
		t.Fatalf("exit=%d, want 4; stderr=%s", code, errOut)
	}
}

// --- Case 5: no log, no anchor -> exit 0 (fresh install) ------------------

func TestAuditVerify_Case5_FreshInstall_Exit0(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	code, _, errOut := assertVerifyDoesNotMutate(t, path)
	if code != 0 {
		t.Fatalf("exit=%d, want 0; stderr=%s", code, errOut)
	}
}

// --- Case 6: log destroyed but anchor present with seq>0 -> exit 2 -------

func TestAuditVerify_Case6_LogDestroyed_Exit2(t *testing.T) {
	path, _ := buildAuditChain(t, 3)
	if err := os.WriteFile(path, []byte{}, 0o600); err != nil {
		t.Fatalf("emptying log: %v", err)
	}

	code, _, errOut := assertVerifyDoesNotMutate(t, path)
	if code != 2 {
		t.Fatalf("exit=%d, want 2; stderr=%s", code, errOut)
	}
}

// --- Case 7: anchor corrupt -> exit 5, and NEGATIVE assertion vs case 4 ---

func TestAuditVerify_Case7_CorruptAnchor_Exit5_NotCase4(t *testing.T) {
	path, _ := buildAuditChain(t, 3)
	if err := os.WriteFile(anchorFilePath(path), []byte("not json at all"), 0o600); err != nil {
		t.Fatalf("corrupting anchor: %v", err)
	}

	code, _, errOut := assertVerifyDoesNotMutate(t, path)
	if code != 5 {
		t.Fatalf("exit=%d, want 5 (corrupt), not 4 (missing); stderr=%s", code, errOut)
	}
	if code == 4 {
		t.Fatal("a corrupt anchor must never produce the case-4 (missing) exit code")
	}

	// Stronger, sentinel-level negative assertion (not just the exit code):
	// the underlying error must satisfy errors.Is ErrAnchorCorrupt and must
	// NOT satisfy errors.Is ErrAnchorMissing -- proving the CLI's exit-code
	// 5 vs 4 split reflects a genuinely distinct error, not a coincidence
	// of two code paths returning the same integer.
	_, ierr := audit.InspectAnchor(path)
	if !errors.Is(ierr, audit.ErrAnchorCorrupt) {
		t.Fatalf("want errors.Is ErrAnchorCorrupt, got %v", ierr)
	}
	if errors.Is(ierr, audit.ErrAnchorMissing) {
		t.Fatalf("a corrupt anchor's error must NOT also satisfy errors.Is ErrAnchorMissing: %v", ierr)
	}
}

// --- Case 8: log ahead of anchor -> exit 3, with case-8 detail printed ---

func TestAuditVerify_Case8_LogAheadOfAnchor_Exit3(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	l, err := audit.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := l.Append(audit.Record{Event: audit.EventPlan, Action: "a"}); err != nil {
		t.Fatalf("first Append: %v", err)
	}
	// Snapshot the anchor at seq=1 (genuine Append output) before the
	// second append, then restore it afterward to simulate the documented
	// crash window: the second record's write is durably fsynced but its
	// anchor update is lost. Every byte on disk was produced by a real
	// Append call; this only re-orders which anchor snapshot survives.
	staleAnchor := readFileOrNil(t, anchorFilePath(path))
	if staleAnchor == nil {
		t.Fatal("expected an anchor after the first append")
	}
	if _, err := l.Append(audit.Record{Event: audit.EventExecute, Action: "b"}); err != nil {
		t.Fatalf("second Append: %v", err)
	}
	if err := os.WriteFile(anchorFilePath(path), staleAnchor, 0o600); err != nil {
		t.Fatalf("restoring stale anchor: %v", err)
	}

	code, out, errOut := assertVerifyDoesNotMutate(t, path)
	if code != 3 {
		t.Fatalf("exit=%d, want 3; stderr=%s", code, errOut)
	}
	if !strings.Contains(out, "exactly one record") {
		t.Fatalf("expected case-8 detail about exactly-one-record excess, got %q", out)
	}
	if !strings.Contains(out, "MATCHES") {
		t.Fatalf("expected case-8 detail reporting the prior hash MATCHES the anchor, got %q", out)
	}
}

// --- Usage errors --------------------------------------------------------

func TestAuditVerify_MissingLogFlag_Exit1(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runAuditVerify(nil, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit=%d, want 1", code)
	}
}

func TestRunAudit_UnknownSubcommand_Exit1(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runAudit([]string{"bogus"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit=%d, want 1", code)
	}
}

func TestRunAudit_NoSubcommand_Exit1(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runAudit(nil, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit=%d, want 1", code)
	}
}

// --- adopt-anchor ----------------------------------------------------------

func TestAuditAdopt_RefusesIfAnchorExists(t *testing.T) {
	path, _ := buildAuditChain(t, 2) // Append already created a valid anchor
	var stdout, stderr bytes.Buffer
	code := runAuditAdopt([]string{"-audit-log", path}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("adopt-anchor must refuse when an anchor already exists, got exit 0; stdout=%s", stdout.String())
	}
}

func TestAuditAdopt_RefusesUnverifiableChain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	bad := `{"seq":1,"event":"plan","record_hash":"00"}` + "\n"
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatalf("writing bad fixture: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := runAuditAdopt([]string{"-audit-log", path}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("adopt-anchor must refuse to anchor a chain that does not verify")
	}
	if readFileOrNil(t, anchorFilePath(path)) != nil {
		t.Fatal("adopt-anchor must not create an anchor for a chain that failed verification")
	}
}

func TestAuditAdopt_SucceedsOnAnchorlessVerifiedLog_ThenVerifyExit0(t *testing.T) {
	// Build a real chain via genuine Append (which also creates an
	// anchor), then remove the anchor to model "an existing, already
	// verified log with no anchor" -- e.g. a deployment upgrading from a
	// pre-anchor-feature version. The log content itself is 100% genuine
	// Append output.
	path, _ := buildAuditChain(t, 3)
	if err := os.Remove(anchorFilePath(path)); err != nil {
		t.Fatalf("removing anchor: %v", err)
	}
	if readFileOrNil(t, anchorFilePath(path)) != nil {
		t.Fatal("test setup: anchor must be gone before adoption")
	}

	var adoptOut, adoptErr bytes.Buffer
	code := runAuditAdopt([]string{"-audit-log", path}, &adoptOut, &adoptErr)
	if code != 0 {
		t.Fatalf("adopt-anchor exit=%d, want 0; stderr=%s", code, adoptErr.String())
	}
	if readFileOrNil(t, anchorFilePath(path)) == nil {
		t.Fatal("adopt-anchor must have created an anchor")
	}

	var verifyOut, verifyErr bytes.Buffer
	vcode := runAuditVerify([]string{"-audit-log", path}, &verifyOut, &verifyErr)
	if vcode != 0 {
		t.Fatalf("verify after adoption exit=%d, want 0; stderr=%s", vcode, verifyErr.String())
	}
}

func TestAuditAdopt_MissingLogFlag_Exit1(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runAuditAdopt(nil, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit=%d, want 1", code)
	}
}
