---
name: repo
type: repo
agent: CodeActAgent
---

# Juridical — repo agent (always loaded)

You are operating inside **juridical**: a control plane that sits in front of
operational actions (restart a service, roll a deployment, later reboot a host)
and refuses to let any of them run further than declared, without a valid
approval, and without an immutable record. Its whole job is **authorize,
adjudicate, bound, audit**.

Flow: `request → plan (blast radius) → gate (Off/Warn/Block) → approval token → execute → audit`.

> Status: **v0.1 founding scaffold** — quality gate + CI/supply-chain hardening;
> Phase-1 action code lands one reviewed PR at a time. The repo is private until
> an explicit public flip, so hygiene is absolute.

## Your role in the loop

OpenHands is the **routine-tier producer only** — you author a focused change
and open a PR. You do not review and do not merge. The engineered dev-loop:

`pull → plan → build → FULL GATE → document → open PR → independent adversarial review → auto-merge on clean`

You own `pull → … → open PR`; the independent review-loop owns the rest.

## PR & branch discipline

- Branch from the default branch; prefix work branches `openhands/…`.
- **Never** push to the default branch (`main`). **Never** self-merge — the
  PR-only credential enforces this; do not try to bypass it.
- Every change is a PR; nothing is self-merged; each PR gets an independent
  review pass. One logical change per PR. Conventional Commits.

## The full gate — MUST pass before you call anything done

`make gate-full` is the **single source of truth**; `ci.yml` runs the identical
target, so local and CI stay in lockstep. Do not mark work done without proof.

`gate-full: fmt vet build test cover lint gosec gitleaks pii smoke`

- `fmt` — `go fmt` + `gofmt -l` check over `cmd internal` (fails on drift).
- `vet` — `go vet ./...`.
- `build` — `CGO_ENABLED=0 go build -trimpath` → `./juridical`.
- `test` — `go test -race -count=1 ./...` (also runs `FuzzXxx` seed corpora as
  ordinary subtests).
- `cover` — total-coverage floor `COVER_FLOOR=74` (atomic profile).
- `lint` — `golangci-lint run` (required in CI).
- `gosec` — `gosec -quiet ./...` (required in CI).
- `gitleaks` — `gitleaks detect --redact --exit-code 1` (required in CI).
- `pii` — `./tools/pii_scan.sh` (no host IPs, real emails, or domains).
- `smoke` — build + `./juridical -version` + `./juridical help`.
- **Advisory, not in the blocking path:** `make fuzz` runs native Go fuzz
  targets (`FUZZTIME=15s` each) over the untrusted-input security boundaries —
  audit record decode, approval-token parse, `plan_hash` construction, `/v1`
  request-body decode, `declared_bound` parsing. A long-tail fuzz finding is a
  signal to investigate, not a per-commit merge blocker. Add a `FuzzXxx` target
  whenever you add a parser on an untrusted boundary.
- **Supply chain (CI):** SHA-pinned Actions, least-privilege workflow tokens,
  CodeQL, OpenSSF Scorecard, `govulncheck`; releases are signed, SBOM-bearing,
  SLSA-provenanced.

## Security doctrine (design constraint, not a phase)

- **Fail-closed everywhere.** Juridical computes actual reach against live
  topology and refuses anything outside the declared bound. Progressive
  enforcement runs Off/Warn/Block and defaults to **Warn** (the design notes) — observe
  before you ratchet; never loosen a control to force a pass.
- **Approval is plan-bound.** A plan is hashed; a single-use token authorizes
  exactly that plan, with separation-of-duties checks. One token, one plan.
- **Break-glass is always audited.** The override is itself a first-class,
  hash-chained audit record — never a silent bypass.
- **Append-only, hash-chained audit** with redaction of sensitive fields.
- **Least privilege. Zero-leak. Root cause, not band-aid. Minimal surface.**
  Never commit or echo a secret (refer by shape/fingerprint). No PII in code,
  fixtures, or docs — use RFC-5737 / RFC-1918, `example.com`, `noreply@…`.

## Repo context

- **Language:** Go 1.22, module `github.com/juridical-docker/juridical`
  (note: the Go module path differs from the GitHub owner — keep imports on the
  `juridical-docker` path). Single static binary, `CGO_ENABLED=0` (the design notes).
- **Directories:** `cmd/juridical` (entrypoint), `internal/` (`blast`,
  `approve`, `audit`, `api`, `version`, …), `adr/` (design decisions),
  `docs/`, `tools/` (incl. `pii_scan.sh`), `wiki/`.
- **Build/dev:** `make build`; `make tools` installs `golangci-lint`, `gosec`,
  `govulncheck`.
- **Phase-1 order:** `internal/blast` + `restart-service` end-to-end →
  `roll-deploy` → `approve`/`gate`/`audit` hardening (plan hashing, SoD,
  break-glass, redaction, chain verification) → the `/v1` HTTP API.

## Tier note

The routine tier runs on **local Devstral**. Keep changes small, focused, and
verifier-friendly — narrow diffs, tests alongside, clear commit messages. This
is a security-critical control plane in scaffold stage: prefer the smallest
correct step and split anything that wants to sprawl into separate reviewable
PRs.
