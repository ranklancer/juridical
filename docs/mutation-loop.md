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

## What PR1 does not include

The `/v1` HTTP API, the `roll-deploy` action, the optional bulwark
`gate.ImageVerdict` seam (a no-op `ALLOW` stub, off by default in v0.1), and
break-glass hardening are later, independently reviewed PRs. PR1 delivers the
domain loop and its adversarial guarantees as library code with tests.
