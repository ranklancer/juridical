package audit

// Native fuzz targets for the audit package's untrusted-input boundary:
// the on-disk, hash-chained JSONL record decode (readAll, used by Open and
// Log.Records) that must fail CLOSED on any malformed, truncated, oversized,
// non-UTF8, or unknown-field input rather than panicking or silently
// coercing a corrupted record (retroactive hardening sweep, B3).

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzReadAllRecord fuzzes the JSONL record-decode/verify path with arbitrary
// bytes written as an audit log file, exactly as an operator or attacker with
// filesystem write access to a corrupted/tampered log would present it to
// Open/Records. Invariant: readAll never panics, and for any input it either
// (a) fails closed with an error (malformed JSON, unknown field, trailing
// garbage, oversized line, non-UTF8, etc.), or (b) returns records that are
// individually well-formed: ComputeRecordHash never panics/errors on them and
// each one round-trips through re-marshal + strict re-decode. Verify is also
// exercised on the decoded slice to confirm it never panics on fuzzer-derived
// records (its pass/fail outcome is not asserted here -- that invariant is
// covered by the existing chain tests).
func FuzzReadAllRecord(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("\n"))
	f.Add([]byte("{}"))
	f.Add([]byte("not json at all\n"))
	f.Add([]byte(`{"seq":1,"ts":"2024-01-01T00:00:00Z","event":"plan","action":"a","backend":"compose","project":"p","params_redacted":{},"declared_bound":{"max_hosts":1,"service":"s","fleet_pct":1},"computed_reach":{"hosts":1,"services":1,"instances":1,"fleet_pct":1},"verdict":"ALLOW","outcome":"","proposer_key_id":"k","approver":"","plan_hash":"ab","prev_record_hash":"","record_hash":"cd"}` + "\n"))
	// well-formed record with one extra, unknown/renamed field -- must fail closed.
	f.Add([]byte(`{"seq":1,"ts":"2024-01-01T00:00:00Z","event":"plan","action":"a","backend":"compose","project":"p","params_redacted":{},"declared_bound":{"max_hosts":1,"service":"s","fleet_pct":1},"computed_reach":{"hosts":1,"services":1,"instances":1,"fleet_pct":1},"verdict":"ALLOW","outcome":"","proposer_key_id":"k","approver":"","plan_hash":"ab","prev_record_hash":"","record_hash":"cd","injected_field":"x"}` + "\n"))
	// truncated mid-object on the second line.
	f.Add([]byte(`{"seq":1,"event":"plan"}` + "\n" + `{"seq":2,"event":`))
	// two JSON values crammed onto one line (trailing data within a line).
	f.Add([]byte(`{"seq":1}{"seq":2}` + "\n"))
	// duplicate keys within one record.
	f.Add([]byte(`{"seq":1,"seq":2,"event":"plan"}` + "\n"))
	// non-UTF8 bytes inside a string value.
	f.Add([]byte("{\"seq\":1,\"event\":\"plan\",\"action\":\"\xff\xfe bad\"}\n"))
	// deeply nested value under an otherwise-unused-but-still-unknown field.
	f.Add([]byte(`{"seq":1,"event":"plan","x":` + strings.Repeat("[", 5000) + strings.Repeat("]", 5000) + "}\n"))
	// large blob, no newline at all.
	f.Add(bytes.Repeat([]byte("a"), 200000))
	// many short "lines" (stresses the scanner's line loop).
	f.Add(bytes.Repeat([]byte("{}\n"), 5000))

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		p := filepath.Join(dir, "audit.jsonl")
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatalf("test setup: writing fuzz input to a temp file failed: %v", err)
		}

		records, err := readAll(p)
		if err != nil {
			// Failing closed on malformed/unknown-field/oversized/non-decodable
			// input is the required, correct behaviour -- nothing further to
			// assert on this path.
			return
		}

		// Exercise Verify too: it must never panic on fuzzer-derived records,
		// regardless of whether the chain happens to verify.
		_, _ = Verify(records)

		for i, r := range records {
			h, herr := ComputeRecordHash(r)
			if herr != nil {
				t.Fatalf("record %d: ComputeRecordHash errored on a successfully decoded record: %v", i, herr)
			}
			if len(h) != 64 {
				t.Fatalf("record %d: record hash must be 64 hex chars, got %d (%q)", i, len(h), h)
			}

			// Round-trip: a record readAll accepted must re-marshal and then
			// re-decode cleanly under the same strict decoder readAll itself
			// uses -- i.e. it is itself a well-formed record, not an artifact
			// of a lenient intermediate step.
			b, merr := json.Marshal(r)
			if merr != nil {
				t.Fatalf("record %d: re-marshal of a decoded record failed: %v", i, merr)
			}
			var r2 Record
			dec := json.NewDecoder(bytes.NewReader(b))
			dec.DisallowUnknownFields()
			if derr := dec.Decode(&r2); derr != nil {
				t.Fatalf("record %d: round-trip strict re-decode failed: %v (re-marshaled: %s)", i, derr, b)
			}
		}
	})
}
