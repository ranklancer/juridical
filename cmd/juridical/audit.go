// `juridical audit` provides two operator-facing subcommands for the
// out-of-band anchor introduced alongside the hash-chained audit log
// (internal/audit, see anchor.go): `verify` (read-only diagnosis) and
// `adopt-anchor` (explicit, non-repairing adoption). Recovering a
// power-lossed engine previously required writing and running Go directly
// against audit.InitAnchor -- an availability gap for a service that
// refuses to start without a clean Open. See SECURITY.md for the operator
// recovery runbook these verbs exist to support.
//
// Both verbs consume only the exported internal/audit surface (Open-path
// diagnostics via InspectAnchor, InitAnchor, and the exported sentinel
// errors); neither touches serve, the engine, or the append path.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/juridical-docker/juridical/internal/audit"
)

const auditUsage = `juridical audit - inspect and recover the audit log's out-of-band chain anchor.

Usage:
  juridical audit verify --audit-log <path>
  juridical audit adopt-anchor --audit-log <path>

verify        read-only: reports which anchor case applies (see SECURITY.md);
              never creates, repairs, or removes an anchor.
adopt-anchor  adopts an anchor for an existing, verified, anchor-less log.
              Refuses if an anchor already exists or the chain does not
              verify. There is deliberately no --force/--replace flag: see
              SECURITY.md for why re-adoption requires a separate, manual
              removal of the stale anchor first.

Exit codes (both subcommands):
  0  OK -- verified, or anchor adopted
  1  usage or I/O error
  2  truncation or tamper detected -- INCIDENT, do not adopt
  3  log ahead of anchor -- crash-window candidate, operator judgment required
  4  anchor missing on a non-empty log -- adoption required
  5  anchor corrupt or unreadable -- distinct from missing by design
`

// runAudit dispatches `juridical audit <subcommand>`.
func runAudit(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, auditUsage)
		return 1
	}
	switch args[0] {
	case "verify":
		return runAuditVerify(args[1:], stdout, stderr)
	case "adopt-anchor":
		return runAuditAdopt(args[1:], stdout, stderr)
	case "-help", "--help", "help":
		fmt.Fprint(stdout, auditUsage)
		return 0
	default:
		fmt.Fprintf(stderr, "juridical: audit: unknown subcommand %q\n\n%s", args[0], auditUsage)
		return 1
	}
}

// parseAuditLogFlag parses a single required -audit-log flag shared by both
// audit subcommands. The flag name intentionally reuses the exact spelling
// `serve` already uses for the audit log (see parseServeFlags in serve.go)
// so operators never learn a second spelling for the same path.
func parseAuditLogFlag(fsName string, args []string, stderr io.Writer) (string, int, bool) {
	fs := flag.NewFlagSet(fsName, flag.ContinueOnError)
	fs.SetOutput(stderr)
	logPath := fs.String("audit-log", "", "path to the append-only audit JSONL file (required; same spelling as `serve -audit-log`)")
	if err := fs.Parse(args); err != nil {
		return "", 1, false
	}
	if strings.TrimSpace(*logPath) == "" {
		fmt.Fprintf(stderr, "juridical: %s: -audit-log is required\n", fsName)
		return "", 1, false
	}
	return *logPath, 0, true
}

// auditExitCode maps an internal/audit anchor error to this CLI's exit-code
// table via errors.Is against the exported sentinels -- never by matching
// error text, which would be fragile and would silently mis-map on any
// message edit in internal/audit.
func auditExitCode(err error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, audit.ErrTruncated), errors.Is(err, audit.ErrTampered):
		return 2
	case errors.Is(err, audit.ErrLogAheadOfAnchor):
		return 3
	case errors.Is(err, audit.ErrAnchorMissing):
		return 4
	case errors.Is(err, audit.ErrAnchorCorrupt):
		return 5
	default:
		// Any other error (log unreadable, chain fails Verify for reasons
		// unrelated to the anchor, etc.) is a generic I/O/usage failure --
		// distinct from the five documented anchor cases, and does not
		// collide with their exit codes.
		return 1
	}
}

// runAuditVerify implements `juridical audit verify`: strictly read-only.
// It runs the same checks Open would (via audit.InspectAnchor) and reports
// which case fired, the anchor seq/hash, the observed head seq/hash, and --
// for a case-8 result -- whether the excess is exactly one record and
// whether that record's prior link matches the anchor. It never creates,
// repairs, or removes the anchor, and never touches the log.
func runAuditVerify(args []string, stdout, stderr io.Writer) int {
	logPath, code, ok := parseAuditLogFlag("juridical audit verify", args, stderr)
	if !ok {
		return code
	}

	snap, err := audit.InspectAnchor(logPath)
	exitCode := auditExitCode(err)

	fmt.Fprintf(stdout, "juridical audit verify: %s\n", logPath)
	if snap.AnchorExists {
		fmt.Fprintf(stdout, "  anchor: seq=%d hash=%s\n", snap.AnchorSeq, snap.AnchorHash)
	} else {
		fmt.Fprintf(stdout, "  anchor: (none)\n")
	}
	fmt.Fprintf(stdout, "  log head: seq=%d hash=%s\n", snap.HeadSeq, snap.HeadHash)

	switch {
	case err == nil:
		fmt.Fprintln(stdout, "  result: OK -- chain and anchor agree")
	case errors.Is(err, audit.ErrTruncated):
		fmt.Fprintln(stdout, "  result: FAIL -- log truncated relative to its anchor (case 2/6) -- INCIDENT, do not adopt")
	case errors.Is(err, audit.ErrTampered):
		fmt.Fprintln(stdout, "  result: FAIL -- log tampered (case 3) -- INCIDENT, do not adopt")
	case errors.Is(err, audit.ErrAnchorMissing):
		fmt.Fprintln(stdout, "  result: FAIL -- anchor missing on a non-empty log (case 4) -- adoption required")
	case errors.Is(err, audit.ErrAnchorCorrupt):
		fmt.Fprintln(stdout, "  result: FAIL -- anchor corrupt or unreadable (case 7) -- distinct from missing, inspect before deleting")
	case errors.Is(err, audit.ErrLogAheadOfAnchor):
		fmt.Fprintf(stdout, "  result: FAIL -- log ahead of anchor by %d record(s) (case 8) -- operator judgment required\n", snap.ExcessRecords)
		if snap.ExcessRecords == 1 {
			match := "does NOT match"
			if snap.PriorMatchesAnchor {
				match = "MATCHES"
			}
			fmt.Fprintf(stdout, "  case-8 detail: excess is exactly one record; the prior record's hash %s the anchor's recorded hash\n", match)
			fmt.Fprintln(stdout, "  case-8 detail: this signature is reproducible by an attacker appending one forged record -- it cannot be auto-blessed; judge using independent evidence (see SECURITY.md)")
		} else {
			fmt.Fprintf(stdout, "  case-8 detail: excess is %d record(s), not exactly one -- treat as a truncation/tamper incident, not a simple crash window\n", snap.ExcessRecords)
		}
	default:
		fmt.Fprintf(stdout, "  result: FAIL -- %v\n", err)
	}
	if err != nil {
		fmt.Fprintf(stderr, "juridical: audit verify: %v\n", err)
	}
	return exitCode
}

// runAuditAdopt implements `juridical audit adopt-anchor`: a thin wrapper
// over audit.InitAnchor, which already refuses in-memory paths, refuses if
// an anchor exists, and refuses if the chain does not verify. There is
// deliberately no --force/--replace flag; do not add one (see SECURITY.md
// and the InitAnchor doc comment) -- a force flag is exactly the mechanism
// by which a truncation gets laundered into a trusted head.
func runAuditAdopt(args []string, stdout, stderr io.Writer) int {
	logPath, code, ok := parseAuditLogFlag("juridical audit adopt-anchor", args, stderr)
	if !ok {
		return code
	}
	if err := audit.InitAnchor(logPath); err != nil {
		fmt.Fprintf(stderr, "juridical: audit adopt-anchor: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "juridical audit adopt-anchor: anchor adopted for %s\n", logPath)
	return 0
}
