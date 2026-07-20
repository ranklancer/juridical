# AGENTS.md — Juridical

**Canonical agent instructions for this repository.** Every coding agent — Claude
Code, OpenHands, or a human following the same loop — reads *this* file.
`CLAUDE.md` and `.openhands/microagents/repo.md` are thin pointers here; do not
duplicate content into them.

## What this repo is

**Juridical** is a control plane that sits in front of operational actions —
restart a service, roll a deployment, later reboot a host — and refuses to let
any of them run further than declared, without a valid approval, and without an
immutable record of the decision. Named for the Forerunner *Juridical* rate: the
office of authorization and oversight. The whole job is **authorize, adjudicate,
bound, audit.**

Flow: `request → plan (blast radius) → gate (Off/Warn/Block) → approval token → execute → audit`

Juridical is the *act* stage of the suite:
forge ([ecumene](https://github.com/ranklancer/ecumene)) →
verify ([bulwark](https://github.com/ranklancer/bulwark)) → **act (juridical)**.

> **Status: v0.1 founding scaffold.** The repo currently holds the project
> skeleton, quality gate, and CI/supply-chain hardening — no action-execution
> code yet. Phase-1 features land one reviewed pull request at a time. The repo
> is **private until an explicit public flip**, so hygiene is absolute.

## The engineered dev-loop

`pull → plan → build → FULL GATE → document → open PR → independent adversarial review → auto-merge on clean`

Agents are the **routine-tier producer only**. You author focused changes and
open a pull request. You are *not* the reviewer and *not* the merger. The
independent adversarial review-loop owns everything after the PR is opened.

### Local-first workflow

Work in a real checkout; do not iterate through CI.

1. **Pull** the default branch and create a **git worktree** for the change:
   `git worktree add ../juridical-<slug> -b <branch> origin/main`
   A worktree keeps the change isolated and leaves your primary checkout clean.
2. **Plan** before code: approach, files touched, risks, definition of done. Any
   task of three or more steps, or any architectural decision, gets a plan first.
   If execution diverges from the plan, stop and replan. Architectural decisions
   are recorded as ADRs under `adr/`.
3. **Build**, then **run `make gate-full` locally** and **iterate until green**.
   A red gate is not a PR.
4. **Document** the change (code comments where non-obvious, `docs/` or an ADR
   where the decision is architectural).
5. **Open the PR** only once the gate is green locally.
6. Remove the worktree when the PR merges:
   `git worktree remove ../juridical-<slug>`

## PR & branch discipline

- Branch from the default branch (`main`). The **OpenHands lane** prefixes work
  branches `openhands/…`.
- **Never push to `main`.** **Never self-merge** — the PR-only credential
  enforces this; do not attempt to work around it.
- Every change is a pull request; nothing is self-merged; each PR gets an
  independent review pass. One logical change per PR.
- Conventional Commits (`feat(approve): …`, `fix(audit): …`, `chore(ci): …`).

## The full gate — MUST pass before anything is "done"

**`make gate-full` is the single source of truth for the quality bar**, and
`ci.yml` runs the identical target so local and CI stay in lockstep. Never mark
work complete without proof it is green — unverified means unfinished.

`gate-full: fmt vet build test cover lint gosec gitleaks pii smoke`

- `fmt` — `go fmt` plus a `gofmt -l` check over `cmd internal` (fails on drift).
- `vet` — `go vet ./...`.
- `build` — `CGO_ENABLED=0 go build -trimpath` → `./juridical`.
- `test` — `go test -race -count=1 ./...`. Note this also executes every
  `FuzzXxx` target over its **seed corpus** as an ordinary subtest.
- `cover` — total-coverage floor `COVER_FLOOR=74` (atomic profile).
- `lint` — `golangci-lint run` (required in CI).
- `gosec` — `gosec -quiet ./...` (required in CI).
- `gitleaks` — `gitleaks detect --redact --exit-code 1` (required in CI).
- `pii` — `./tools/pii_scan.sh`.
- `smoke` — build, then `./juridical -version` and `./juridical help`.

**Advisory, deliberately outside the blocking path:** `make fuzz` runs the
native Go fuzz targets (`FUZZTIME=15s` each) over the untrusted-input security
boundaries — audit record decode (`internal/audit`), approval-token consume and
`plan_hash` construction (`internal/approve`), `/v1` request-body decode and
`declared_bound` parsing (`internal/api`). Random-mutation search sits on top of
what `test` already covers, so a long-tail finding is a signal to investigate,
not a per-commit merge blocker. **Add a `FuzzXxx` target whenever you add a
parser on an untrusted boundary.**

**Supply chain (CI):** least-privilege workflow tokens, SHA-pinned Actions,
CodeQL, OpenSSF Scorecard, `govulncheck`, and signed, SBOM-bearing,
SLSA-provenanced releases.

## Security doctrine

Security is a **design constraint from the first line**, never a later phase.
This is a control plane whose entire purpose is safety — the doctrine *is* the
product.

- **Fail-closed bounding.** Every action declares how far it may reach.
  Juridical computes actual reach against live topology and refuses anything
  outside the declared bound. Never loosen a control to force a pass.
- **Progressive enforcement.** The gate runs Off / Warn / Block and defaults to
  **Warn** (the design notes), so operators observe what *would* be blocked before
  ratcheting to enforcement. Respect that default.
- **Approval is plan-bound.** A plan is hashed; a single-use token is minted
  against that hash with separation-of-duties checks. A token authorizes one
  plan and nothing else.
- **Break-glass is always audited.** Emergencies get an explicit, authorized
  override path — and the override is itself a first-class audit record, never a
  silent bypass.
- **Append-only, hash-chained audit** with redaction of sensitive fields. Every
  decision — allowed, warned, blocked, or broken-glass — is recorded.
- **Least privilege.** Minimum scope for every credential, token, and action.
- **Zero-leak.** Never commit, echo, or log a secret — in chat, logs, command
  lines, or files; not even rotated ones. Refer to secrets by shape or
  fingerprint only.
- **PII-clean.** No host IPs, real emails, or real domains in code, fixtures, or
  docs — use RFC-5737 / RFC-1918 ranges, `example.com`, and `noreply@…`.
  Enforced by `./tools/pii_scan.sh`.
- **Root cause, not band-aid.** Fix the actual defect; no patches that mask
  symptoms.
- **Minimal impact / minimal surface.** Touch the least code that achieves the
  goal; leave unrelated code alone.

## Repo context

- **Language:** Go 1.22, single static binary, `CGO_ENABLED=0` (the design notes).
- **Module path:** `github.com/juridical-docker/juridical` — **note this differs
  from the GitHub owner (`ranklancer`)**. Keep all imports and `-ldflags` version
  paths on the `juridical-docker` module path.
- **Layout:**
  - `cmd/juridical` — entrypoint / CLI
  - `internal/` — `blast` (radius primitive), `approve` (plan hash, tokens, SoD),
    `audit` (append-only hash chain), `api` (`/v1`), `version`
  - `adr/` — architecture decision records
  - `docs/`, `wiki/` — documentation
  - `tools/` — `pii_scan.sh` and dev tooling
- **Build:** `make build`. `make tools` installs `golangci-lint`, `gosec`,
  `govulncheck`.
- **CLI surface:** the Phase-1 subcommands (`serve`, `action`, `plan`,
  `approve`, `audit`) are declared in `juridical -help` and implemented across
  later pull requests.
- **Phase-1 order:** `internal/blast` + `restart-service` end-to-end (plan →
  approval token → execute → hash-chained audit) → `roll-deploy` →
  `approve`/`gate`/`audit` hardening (plan hashing, SoD, break-glass, redaction,
  chain verification) → the `/v1` HTTP API.

## Tier note

The routine tier runs on **local Devstral**. Keep changes small, focused, and
verifier-friendly — narrow diffs, tests alongside, clear commit messages. This
is a security-critical control plane in scaffold stage: prefer the smallest
correct step, and split anything that wants to sprawl into separate reviewable
PRs.
