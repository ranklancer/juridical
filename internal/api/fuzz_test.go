package api

// Native fuzz targets for the /v1 API package's untrusted-input boundary:
// the shared strict-JSON request-body decoder (decodeStrict, used by every
// mutating route under the 64KiB body cap) and the declared_bound wire
// parser (parseDeclaredBound), which turns a caller-controlled JSON blob into
// the blast-radius bound a plan is judged against (retroactive hardening
// sweep, B3).

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/juridical-docker/juridical/internal/blast"
)

// FuzzDecodeStrictPlansRequest fuzzes decodeStrict -- the strict JSON decode
// helper (DisallowUnknownFields + explicit trailing-data rejection) every
// mutating /v1 route body goes through -- using plansRequest as a
// representative decode target, with arbitrary bytes as the raw request
// body. Invariant: decodeStrict never panics and never partially applies (v
// is only meaningfully populated when it returns nil); it either returns an
// error (malformed JSON, unknown field, or trailing data), or the decoded
// value is itself well-formed enough to re-marshal and round-trip through the
// same strict decoder again.
func FuzzDecodeStrictPlansRequest(f *testing.F) {
	f.Add([]byte(`{"action":"restart","backend":"compose","project":"web","params":{"k":"v"},"declared_bound":{"max_hosts":1,"service":"api","fleet_pct":10}}`))
	f.Add([]byte(``))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"action":"a"}{"extra":"data"}`))                                               // trailing data after the value
	f.Add([]byte(`{"action":"a"}` + "\r\nGARBAGE"))                                               // trailing garbage after newline
	f.Add([]byte(`{"action":"a","unknown_field":"x"}`))                                           // unknown top-level field
	f.Add([]byte(`{"params":{"a":"b","a":"c"}}`))                                                 // duplicate map keys
	f.Add([]byte("\x00\x01\x02"))                                                                 // non-UTF8/binary garbage
	f.Add([]byte(strings.Repeat("[", 20000)))                                                     // deeply nested, unterminated
	f.Add([]byte(`{"action":"a","params":{` + strings.Repeat(`"k":"v",`, 3000) + `"last":"v"}}`)) // very wide object
	f.Add([]byte(`{"action":123}`))                                                               // wrong JSON type for a string field
	f.Add([]byte(`{"declared_bound":` + strings.Repeat("1", 4000) + `}`))                         // huge numeric literal

	f.Fuzz(func(t *testing.T, data []byte) {
		var req plansRequest
		err := decodeStrict(bytes.NewReader(data), &req)
		if err != nil {
			return
		}

		// Round-trip: anything decodeStrict accepted must re-marshal and
		// then decode cleanly through decodeStrict again -- i.e. it is a
		// genuinely well-formed value, not an artifact of a lenient step.
		b, merr := json.Marshal(req)
		if merr != nil {
			t.Fatalf("re-marshal of a successfully decoded request failed: %v", merr)
		}
		var req2 plansRequest
		if err := decodeStrict(bytes.NewReader(b), &req2); err != nil {
			t.Fatalf("round-trip decode of a re-marshaled request failed: %v (re-marshaled: %s)", err, b)
		}
	})
}

// FuzzParseDeclaredBound fuzzes parseDeclaredBound -- the declared_bound wire
// parser that turns the raw JSON a caller submits in POST /v1/plans into a
// blast.DeclaredBound plus the set of "dormant" (unrecognized/Phase-2)
// dimension keys present in the request. Invariant (FC3, fail-closed): parsing
// never panics, and whenever it succeeds with one or more dormant dimension
// keys present, blast.ValidateDeclared MUST refuse the bound (an unknown
// blast-radius dimension can never be silently accepted).
func FuzzParseDeclaredBound(f *testing.F) {
	f.Add([]byte(`{"max_hosts":1,"service":"api","fleet_pct":10}`))
	f.Add([]byte(`null`))
	f.Add([]byte(``))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"namespace":"ns1"}`))                                              // dormant-only dimension
	f.Add([]byte(`{"max_hosts":"not-a-number"}`))                                     // wrong JSON type
	f.Add([]byte(`{"max_hosts":1,"service":"api","fleet_pct":10,"node":"n1"}`))       // active + dormant mixed
	f.Add([]byte(`{"max_hosts":1,"service":"api","fleet_pct":10,"az":"us-east-1a"}`)) // another dormant axis
	f.Add([]byte(`[1,2,3]`))                                                          // wrong top-level shape
	f.Add([]byte(`{"max_hosts":-999999999999}`))                                      // extreme negative number
	f.Add([]byte(`{"service":""}`))                                                   // empty required field
	f.Add([]byte(`{"service":"api","service":"other"}`))                              // duplicate key

	f.Fuzz(func(t *testing.T, data []byte) {
		bound, dormant, err := parseDeclaredBound(data)
		if err != nil {
			return
		}
		if len(dormant) > 0 {
			if verr := blast.ValidateDeclared(bound, dormant); verr == nil {
				t.Fatalf("dormant dimension(s) %v must fail closed via ValidateDeclared, got nil error (bound=%+v)", dormant, bound)
			}
		}
	})
}
