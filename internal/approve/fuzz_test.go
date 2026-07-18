package approve

// Native fuzz targets for the approve package's untrusted-input boundary:
// the one-time approval TOKEN parse (hex decode, length check, constant-time
// compare) presented at POST /v1/executions, and the canonical-JSON plan_hash
// construction that a human approves and that gates every execution
// (retroactive hardening sweep, B3).

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/juridical-docker/juridical/internal/blast"
)

// FuzzTokenStoreConsume fuzzes TokenStore.Consume's token-parse step
// (hex.DecodeString + 32-byte length check + constant-time compare) with
// arbitrary strings, exactly as an attacker presenting a forged/garbled
// bearer-adjacent secret at POST /v1/executions would. Invariant (FC4): a
// string that is not valid hex, or that does not decode to exactly 32 bytes,
// must fail closed with ErrTokenUnknown -- never panic, never a different
// error, and never a success. A string that DOES decode to exactly 32 bytes
// must succeed only if those bytes are exactly the minted secret's bytes
// (compared byte-for-byte, not string-for-string, since hex decoding is
// case-insensitive); any other 32-byte value must also fail closed.
func FuzzTokenStoreConsume(f *testing.F) {
	f.Add("")
	f.Add("00")
	f.Add(strings.Repeat("0", 64))
	f.Add(strings.Repeat("f", 64))
	f.Add(strings.Repeat("F", 64))             // uppercase hex, still valid length
	f.Add(strings.Repeat("a", 63))             // odd length
	f.Add(strings.Repeat("a", 65))             // one too many
	f.Add(strings.Repeat("a", 62) + "gg")      // non-hex trailing chars
	f.Add("0x" + strings.Repeat("a", 64))      // 0x-prefixed, wrong length once decoded
	f.Add(strings.Repeat("00", 32))            // 64 zero bytes' worth of hex chars is fine at 64 chars = 32 bytes
	f.Add(" " + strings.Repeat("a", 64) + " ") // whitespace padding
	f.Add(strings.Repeat("a", 64) + "\n")      // trailing newline
	f.Add("not hex at all")
	f.Add(strings.Repeat("é", 32)) // multi-byte unicode, not ASCII hex

	f.Fuzz(func(t *testing.T, secretHex string) {
		s := NewTokenStore()
		const planHash = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

		minted, err := s.Mint(planHash, "key-1", "approver-1", time.Minute)
		if err != nil {
			t.Fatalf("Mint on a fixed valid planHash must not fail: %v", err)
		}
		mintedRaw, decErr := hex.DecodeString(minted)
		if decErr != nil || len(mintedRaw) != 32 {
			t.Fatalf("Mint must always return a 32-byte hex secret, got %q", minted)
		}

		_, cErr := s.Consume(secretHex, planHash)

		raw, hexErr := hex.DecodeString(secretHex)
		if hexErr != nil || len(raw) != 32 {
			// Not a well-formed 32-byte token: must fail closed with the
			// specific "unknown" error, never panic, never succeed.
			if cErr != ErrTokenUnknown {
				t.Fatalf("malformed token %q must fail closed with ErrTokenUnknown, got %v", secretHex, cErr)
			}
			return
		}

		// Well-formed 32 bytes: success is only correct if it is exactly the
		// minted secret's bytes.
		if bytes.Equal(raw, mintedRaw) {
			if cErr != nil {
				t.Fatalf("consuming the freshly minted token must succeed, got %v", cErr)
			}
		} else if cErr == nil {
			t.Fatalf("consuming an unminted 32-byte token %q unexpectedly succeeded", secretHex)
		}
	})
}

// FuzzPlanHash fuzzes the canonical-JSON plan_hash construction (the internal design spec
// §6.2) with arbitrary strings for every field a caller controls, including
// non-UTF8 byte sequences smuggled into a Go string. PlanHash sits on the
// approval boundary: a human approves exactly the plan_hash they saw, so it
// must never panic on adversarial input and must be perfectly deterministic
// -- the same logical plan must always hash identically, or the approval
// binding in T3 breaks.
func FuzzPlanHash(f *testing.F) {
	f.Add("restart-service", "compose", "web", "service", "api", "compose:web/api")
	f.Add("", "", "", "", "", "")
	f.Add("a\x00b", "back\xffend", "line\nbreak", "k\tey", "val\"ue", "tar get")
	f.Add(strings.Repeat("x", 5000), "b", "p", "k", "v", "t")
	f.Add("action", "backend", "project", "", "", "target")
	f.Add("\xff\xfe", "\xed\xa0\x80", "ok", "k", "v", "t") // invalid UTF-8 sequences

	f.Fuzz(func(t *testing.T, action, backend, project, paramKey, paramVal, target string) {
		p := Plan{
			Action:  action,
			Backend: backend,
			Project: project,
			Params:  map[string]string{paramKey: paramVal},
			Target:  target,
			DeclaredBound: blast.DeclaredBound{
				MaxHosts: 1, Service: "svc", FleetPct: 10,
			},
			ComputedReach: blast.Reach{
				Hosts: 1, Services: 1, Instances: 1, FleetPct: 10,
			},
		}

		h1 := PlanHash(p)
		h2 := PlanHash(p)
		if h1 != h2 {
			t.Fatalf("PlanHash must be deterministic for an identical plan: %q vs %q", h1, h2)
		}
		if len(h1) != 64 {
			t.Fatalf("PlanHash must be a 64-character hex string, got %d chars: %q", len(h1), h1)
		}
		for _, c := range h1 {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Fatalf("PlanHash must be lowercase hex, got %q", h1)
			}
		}
	})
}
