package approve

import (
	"errors"
	"strings"
)

// Identity classes: proposal is an automation key, approval is a human SSO
// principal. Separation of duties is structural (different identity classes)
// and additionally checked here (the internal design spec §6.4, T6).

// ErrSelfApproval is returned when the approver equals the proposer.
var ErrSelfApproval = errors.New("approve: approver must differ from proposer (SoD, FC5)")

// ErrNotHuman is returned when a non-human (automation) identity attempts to
// approve. Automation may never mint, hold, or present approval.
var ErrNotHuman = errors.New("approve: only a human SSO principal may approve (FC5)")

// CheckSoD enforces separation of duties for an approval. proposerKeyID is the
// automation key that proposed the plan; approver is the human SSO principal.
// approverIsHuman must be true (the caller sets it from the authenticated
// identity class). Approver must be non-empty and must differ from the
// proposer.
func CheckSoD(proposerKeyID, approver string, approverIsHuman bool) error {
	if !approverIsHuman {
		return ErrNotHuman
	}
	if strings.TrimSpace(approver) == "" {
		return ErrNotHuman
	}
	if strings.EqualFold(strings.TrimSpace(approver), strings.TrimSpace(proposerKeyID)) {
		return ErrSelfApproval
	}
	return nil
}
