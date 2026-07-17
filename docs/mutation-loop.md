# The mutation loop: plan → approval-token → execute → audit

Juridical performs no single-call mutation. Every mutating action (`Tier M`)
passes through four stages, and every stage that cannot be positively shown to
be safe fails closed. This document describes Phase-1 PR1: the `internal/blast`
limiter and the `restart-service` action, wired end-to-end by `internal/engine`.

## Stages

| Stage | Package | What happens | Mutates? |
|---|---|---|---|
| **plan** | `engine.Plan` → `action.Resolve` + `blast` | Resolve live reach from real topology, evaluate it against the declared bound, render + hash the plan | no (dry-run) |
| **approve** | `engine.Approve` → `approve` | A human verifies the plan hash, SoD is enforced, a one-time short-TTL token is minted (stored hashed) | no |
| **execute** | `engine.Execute` → `approve` + `action.Execute` | The token is consumed (one-time), reach is re-checked against live topology, then the mutation runs | yes |
| **audit** | `audit` | Every plan/approve/refuse/execute appends one hash-chained, redacted record | — |

## Blast radius (Phase 1, compose)

An action **declares** a machine-checkable bound; the **reach** is computed
independently from live topology; `blast.Within` compares them axis-by-axis.

| Axis | Meaning | Default bound |
|---|---|---|
| `max_hosts` | distinct hosts the action would touch | 1 |
| `service` | exactly-one-service constraint (resolved set must be 1) | required, single |
| `fleet_pct` | resolved instances ÷ reachable inventory × 100 (rounded up) | operator ceiling |

`namespace`, `node`, `AZ` are declared **dormant**: a bound that references them
is refused, not silently ignored. Each axis has an independent enforcement mode
 `off` / `warn` / `block`, **warn by default** — so adoption never breaks a
running homelab; operators ratchet each axis to `block` when ready.

## Fail-closed invariants enforced here

| ID | Invariant |
|---|---|
| FC3 | Absent / unparseable / dormant-dimension declared bound → refuse |
| FC4 | Token missing / expired / reused / plan-hash-mismatch → reject |
| FC5 | Approver ≠ proposer; only a human SSO principal may approve |
| FC6 | Computed reach > approved bound (Block) → refuse, **including the execute-time recheck** |
| FC7 | Unknown backend / ambiguous / unresolvable target → dry-run report, never execute |

The plan hash covers `{action, backend, project, params, declared_bound,
computed_reach, target}` (canonical JSON, SHA-256, lowercase hex). Any drift in
params **or** computed reach changes the hash and therefore invalidates any
token bound to it — a human approves *exactly the reach they saw*.

## Audit chain

Each record carries `prev_record_hash` (linking to the prior record) and
`record_hash = SHA-256(record with record_hash zeroed)`. `audit.Verify` walks
the chain and detects any edit, removal, or reordering. Records are **zero-leak**:
`params` are redacted before write (secret-shaped keys → `[REDACTED]`), and no
key material or host addresses are stored. The Phase-1 backing store is an
append-only `0600` JSONL file outside the web root; opening a tampered log fails
closed.

## `restart-service` (Tier M, compose)

The smallest reversible mutation and the first proof of the whole loop. Params
`{service, project, backend: "compose"}`; declared bound requires a single
service. Resolve enumerates live containers for that service in the project and
folds them into a reach; execute runs `compose restart` scoped to the one
service (idempotent, no image change; rollback = re-run). Canonical over-reach
cases that must refuse in Block mode: a wildcard/group `service` resolving to
more than one service, or resolution spanning more than `max_hosts`.

## `roll-deploy` (Tier M, compose)

Rolls a single service to a **new image**. Params `{service, project,
image_ref, backend: "compose"}`; the declared bound requires a single service,
same as restart-service. Resolve enumerates live containers for the service and
folds them into a reach; execute rolls the service to `image_ref`. Because
`image_ref` is part of the plan params (and embedded in the plan target), it is
covered by the plan hash: a token approved for image A can never authorize
image B (T3). It is **less trivially reversible** than restart-service (rollback
= redeploy the prior image). Image *trust* (signature/provenance) is the
deferred `gate.ImageVerdict` seam — a no-op `ALLOW` stub, off by default in
v0.1 — so roll-deploy applies the reference as given; the blast/approval/audit
guarantees are identical to restart-service.

## What PR1 does not include

The `/v1` HTTP API, the optional bulwark
`gate.ImageVerdict` seam (a no-op `ALLOW` stub, off by default in v0.1), and
break-glass hardening are later, independently reviewed PRs. PR1 delivers the
domain loop and its adversarial guarantees as library code with tests.

## P1-d-1 — /v1 API security scaffolding (the internal design spec §9)

`internal/api` wires the control-plane HTTP surface with stdlib `net/http`
(Go 1.22 method+wildcard `ServeMux`). This first slice lands the security
scaffolding and the read surface:

- Global middleware: 64 KiB body cap + `application/json`-only (415) on write
  methods, panic-recovery (zero-leak 500), and an opaque `X-Request-Id`.
- Auth: `Authorization: Bearer <key>` matched against SHA-256 hashes
  (`StaticKeyStore`), resolved to a `Scope` (observer < orchestrator < operator);
  `tier <= scope` or 403.
- Zero-leak error envelope `{error:{code,message,fc_rule?,audit_seq?}}` —
  `message` is always a safe, redacted string.
- Routes: `GET /v1/healthz` (no auth) and `GET /v1/audit` (observer; paginated
  `since`/`event`/`limit`, `next_since` cursor, oldest-first, redacted records).

Deferred to **P1-d-2**: the mutating lifecycle routes (`/v1/plans`,
`/v1/approvals`, `/v1/executions`) with FC-rule→status mapping and the
forward-auth human-identity path, plus the remaining read routes and
`/v1/break-glass`.
