package audit

// Anchor: out-of-band tail-truncation detection.
//
// Hash-chaining (chain.go) proves every record present in the log is
// unmutated and correctly linked to its predecessor. It cannot prove that no
// records are missing from the END of the chain: an attacker who deletes
// trailing lines, or empties the file entirely, is left with a shorter chain
// that still verifies internally -- the surviving records are self
// consistent, they are just incomplete. History silently disappears.
//
// The anchor closes that gap. After every successful Append, the expected
// chain head (the last record's seq and record hash) is persisted to a
// SEPARATE file alongside the log (<path>.anchor). On Open, once the normal
// chain Verify succeeds, the log's actual head is compared against the
// anchor; any disagreement fails Open closed. See checkAnchor for the exact
// case-by-case behaviour.
//
// THREAT MODEL -- read this before trusting the anchor as more than it is.
// The anchor lives on the same filesystem, under the same write access, as
// the log itself. It is NOT cryptographic notarization, a WORM store, or a
// remote/append-only ledger: it raises the bar from "tamper one file
// consistently" to "tamper two files consistently," nothing more. An
// attacker (or process) with the same write access as the audit engine --
// e.g. root on the host, or the service account that owns the log directory
// -- can rewrite the log to pass Verify AND rewrite the anchor to match,
// defeating this control entirely. Real notarization against that adversary
// requires replicating the head state somewhere the attacker does not
// control (a remote log sink, a WORM bucket, a value signed by a key the
// service does not hold) -- explicitly out of scope here. This change only
// raises the cost of a same-host truncation attack; it does not eliminate it.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// anchorSuffix names the out-of-band anchor file relative to the log path.
const anchorSuffix = ".anchor"

// anchorState is the anchor file's on-disk content: the expected chain head.
type anchorState struct {
	Seq        uint64 `json:"seq"`
	RecordHash string `json:"record_hash"`
}

func anchorPath(logPath string) string {
	return logPath + anchorSuffix
}

// writeAnchor atomically persists st to <logPath>.anchor: write to a temp
// file in the same directory, fsync the temp file's contents, rename over
// the destination (atomic on the same filesystem), then fsync the directory
// so the rename itself survives a crash. Mode 0600, matching the log file's
// own durability/permission discipline.
func writeAnchor(logPath string, st anchorState) error {
	dst := anchorPath(logPath)
	dir := filepath.Dir(dst)

	b, err := json.Marshal(st)
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".anchor-tmp-*") // #nosec G304 -- dir derived from operator-configured log path
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return err
	}
	committed = true

	d, derr := os.Open(dir) // #nosec G304 -- dir derived from operator-configured log path
	if derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// readAnchor loads the anchor file for logPath, if any.
//
// It returns (nil, nil) ONLY when the anchor file does not exist at all. Any
// other failure -- permission error, a directory where a file is expected,
// malformed JSON, unknown fields, trailing garbage after the JSON value --
// is returned as a non-nil error and MUST NOT be treated as "missing" by the
// caller. Degrading a corrupt anchor to "missing" would let an attacker
// destroy the anchor's protection just by corrupting it instead of cleanly
// deleting it.
func readAnchor(logPath string) (*anchorState, error) {
	b, err := os.ReadFile(anchorPath(logPath)) // #nosec G304 -- derived from operator-configured log path
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("audit: reading anchor: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var st anchorState
	if err := dec.Decode(&st); err != nil {
		return nil, fmt.Errorf("audit: anchor file is corrupt/unparseable: %w", err)
	}
	if dec.More() {
		return nil, errors.New("audit: anchor file has trailing content after its JSON object")
	}
	return &st, nil
}

// checkAnchor enforces the out-of-band anchor against the log's actual head,
// derived from records (already chain-Verify'd by the caller). Cases:
//
//  1. anchor present, matches head                         -> OK
//  2. anchor present, head seq < anchor seq                 -> FAIL CLOSED (truncated)
//  3. anchor present, head hash != anchor hash at same seq  -> FAIL CLOSED (tamper)
//  4. log non-empty, anchor MISSING                         -> FAIL CLOSED (cannot prove completeness)
//  5. no log, no anchor                                     -> OK (fresh install)
//  6. log empty/absent, anchor PRESENT with seq > 0         -> FAIL CLOSED (log destroyed)
//  7. anchor unreadable/corrupt/garbage                     -> FAIL CLOSED (never degrades to "missing")
//
// An eighth, unlisted case is handled the same conservative way: a log head
// AHEAD of the anchor (more records than the anchor last saw) also fails
// closed. That can only happen if a prior Append wrote its record but its
// anchor update failed before landing (Append itself already fails that
// call closed -- see log.go -- but the record is durably on disk by then
// and cannot be un-written). Silently trusting an un-anchored tail would
// defeat the control, so it requires the same explicit re-adoption as case 4.
func checkAnchor(logPath string, records []Record) error {
	anchor, err := readAnchor(logPath)
	if err != nil {
		return err // case 7
	}

	var headSeq uint64
	var headHash string
	if n := len(records); n > 0 {
		headSeq = records[n-1].Seq
		headHash = records[n-1].RecordHash
	}

	switch {
	case anchor == nil && headSeq == 0:
		return nil // case 5
	case anchor == nil:
		return fmt.Errorf("audit: log has %d record(s) but no anchor exists; cannot prove no records were truncated (see InitAnchor to adopt one explicitly for an existing verified log)", headSeq) // case 4
	case headSeq == 0:
		if anchor.Seq > 0 {
			return fmt.Errorf("audit: anchor expects seq %d but the log is empty; log destroyed", anchor.Seq) // case 6
		}
		return nil // anchor and log both agree on "nothing yet"
	case headSeq < anchor.Seq:
		return fmt.Errorf("audit: log head is at seq %d but the anchor expects seq %d; log truncated", headSeq, anchor.Seq) // case 2
	case headSeq == anchor.Seq:
		if headHash != anchor.RecordHash {
			return fmt.Errorf("audit: log head at seq %d does not match the anchor's recorded hash; tampered", headSeq) // case 3
		}
		return nil // case 1
	default: // headSeq > anchor.Seq
		return fmt.Errorf("audit: log head is at seq %d, ahead of anchor seq %d (a prior anchor update likely failed); re-verify integrity and re-adopt an anchor", headSeq, anchor.Seq)
	}
}

// InitAnchor establishes an anchor for an existing, already-verified log at
// path. It is the deliberate, explicit adoption path for:
//
//   - a log written before this feature existed (an "existing verified
//     log" per the backward-compatibility requirement), and
//   - re-establishing an anchor after out-of-band remediation, once an
//     operator has independently confirmed the log's current content is
//     exactly the history they intend to protect going forward.
//
// InitAnchor is deliberately NOT invoked automatically by Open. An automatic
// "adopt on first Open" would let an attacker who has already truncated a
// log establish a false anchor that matches their truncated copy, silently
// defeating the whole control the very first time it would matter. Adoption
// must be a separate, explicit, human/operator-initiated step.
//
// InitAnchor refuses to run if an anchor already exists at path, so it can
// never be used to silently overwrite/repair a mismatched anchor -- to
// re-adopt, an operator must first remove the stale anchor out-of-band (a
// second deliberate act) and then call InitAnchor again.
func InitAnchor(path string) error {
	if path == "" {
		return errors.New("audit: InitAnchor requires a file-backed log path (got an in-memory log)")
	}
	if _, err := os.Stat(anchorPath(path)); err == nil {
		return errors.New("audit: an anchor already exists at this path; refusing to overwrite it (remove it out-of-band first if re-adoption is truly intended)")
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("audit: InitAnchor: checking for an existing anchor: %w", err)
	}

	records, err := readAll(path)
	if err != nil {
		return fmt.Errorf("audit: InitAnchor: reading log: %w", err)
	}
	if bad, verr := Verify(records); verr != nil {
		return fmt.Errorf("audit: InitAnchor: refusing to anchor an unverified chain at record %d: %w", bad, verr)
	}

	var st anchorState
	if n := len(records); n > 0 {
		st.Seq = records[n-1].Seq
		st.RecordHash = records[n-1].RecordHash
	}
	return writeAnchor(path, st)
}
