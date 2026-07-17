package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// GenesisPrevHash is the prev_record_hash of the first record in a chain.
const GenesisPrevHash = ""

// ComputeRecordHash returns the lowercase-hex SHA-256 of the record with its
// RecordHash field zeroed, so the hash is self-consistent and covers every
// other field including PrevRecordHash (which chains records together).
func ComputeRecordHash(r Record) (string, error) {
	r.RecordHash = ""
	b, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Verify walks a slice of records and confirms the hash chain is intact:
// monotonic seq, each PrevRecordHash equals the prior RecordHash, and each
// RecordHash recomputes. It returns the index of the first broken record, or
// -1 when the whole chain verifies.
func Verify(records []Record) (int, error) {
	prev := GenesisPrevHash
	for i, r := range records {
		if r.PrevRecordHash != prev {
			return i, errBroken("prev_record_hash mismatch")
		}
		want, err := ComputeRecordHash(r)
		if err != nil {
			return i, err
		}
		if want != r.RecordHash {
			return i, errBroken("record_hash mismatch")
		}
		if i > 0 && r.Seq != records[i-1].Seq+1 {
			return i, errBroken("seq not monotonic")
		}
		prev = r.RecordHash
	}
	return -1, nil
}

type chainErr string

func (e chainErr) Error() string { return "audit: chain broken: " + string(e) }

func errBroken(msg string) error { return chainErr(msg) }
