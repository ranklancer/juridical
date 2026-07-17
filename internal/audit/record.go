// Package audit is the append-only, hash-chained audit trail (the internal design spec §7).
// Every plan, approval, refusal, execution, and break-glass event appends one
// record; records are chained so any edit or removal is detectable. Records are
// zero-leak: params are redacted and no key material or host addresses are
// written.
package audit

import "github.com/juridical-docker/juridical/internal/blast"

// Event enumerates the auditable event kinds.
type Event string

const (
	EventPlan       Event = "plan"
	EventApprove    Event = "approve"
	EventRefuse     Event = "refuse"
	EventExecute    Event = "execute"
	EventBreakGlass Event = "break_glass"
)

// Record is one audit row (the internal design spec §7). RecordHash is computed over the record
// with RecordHash itself zeroed, and PrevRecordHash links to the prior row.
type Record struct {
	Seq            uint64              `json:"seq"`              // monotonic
	TS             string              `json:"ts"`               // RFC3339 UTC
	Event          Event               `json:"event"`            // plan|approve|refuse|execute|break_glass
	Action         string              `json:"action"`           //
	Backend        string              `json:"backend"`          // "compose"
	Project        string              `json:"project"`          //
	ParamsRedacted map[string]string   `json:"params_redacted"`  // secret-shaped values redacted
	DeclaredBound  blast.DeclaredBound `json:"declared_bound"`   //
	ComputedReach  blast.Reach         `json:"computed_reach"`   // at decision time
	Verdict        string              `json:"verdict"`          // ALLOW|WARN|BLOCK|REFUSED
	Outcome        string              `json:"outcome"`          // effect or refusal reason
	ProposerKeyID  string              `json:"proposer_key_id"`  // automation key id, never the key
	Approver       string              `json:"approver"`         // human SSO principal (empty for T/plan rows)
	PlanHash       string              `json:"plan_hash"`        // hex
	PrevRecordHash string              `json:"prev_record_hash"` // hex
	RecordHash     string              `json:"record_hash"`      // hex, SHA-256 over the record minus this field
}

// redactKeySubstrings marks params whose KEY looks secret-shaped; their values
// are replaced with a redaction marker before an audit row is written.
var redactKeySubstrings = []string{
	"secret", "token", "password", "passwd", "pass", "key", "credential",
	"auth", "bearer", "digest", "signature", "cookie", "session",
}

const redactedMarker = "[REDACTED]"

// Redact returns a copy of params with secret-shaped values replaced. It never
// mutates the input. A nil map yields a nil map.
func Redact(params map[string]string) map[string]string {
	if params == nil {
		return nil
	}
	out := make(map[string]string, len(params))
	for k, v := range params {
		if isSecretKey(k) {
			out[k] = redactedMarker
			continue
		}
		out[k] = v
	}
	return out
}

func isSecretKey(k string) bool {
	lk := toLowerASCII(k)
	for _, s := range redactKeySubstrings {
		if containsASCII(lk, s) {
			return true
		}
	}
	return false
}

func toLowerASCII(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

func containsASCII(hay, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
