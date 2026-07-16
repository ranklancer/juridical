# Juridical - Wiki

Welcome to the Juridical wiki. Juridical is a control plane that **bounds the
blast radius of operational actions, requires an approval, and keeps an
immutable receipt.** Named for the Forerunner *Juridical* rate - authorize,
adjudicate, bound, audit.

> **Project status:** v0.1 founding scaffold. Skeleton, quality gate, and
> supply-chain hardening are in place; action-execution features land one
> reviewed pull request at a time. The repository is private until an explicit
> public flip.

## Start here

- **README** - product overview, quick start, roadmap: see the repository root.
- **Security policy** - how to report a vulnerability (`SECURITY.md`).
- **Contributing** - workflow and the quality gate (`CONTRIBUTING.md`).
- **Architecture decisions** - `adr/the design notes..0003`.

## The four ideas

| Idea | Package | The question it answers |
|---|---|---|
| Blast radius | `internal/blast` | How far does this action reach, and is that within its declared bound? |
| Approval | `internal/approve` | Is there a valid, single-use, plan-bound token (with separation of duties)? |
| Gate | `internal/gate` | Off / Warn / Block - does policy allow it, or is a break-glass override in effect? |
| Audit | `internal/audit` | Is every decision in an append-only, hash-chained log? |

## Enforcement modes

Juridical defaults to **Warn**, so you can see what *would* be blocked against
real traffic before ratcheting to **Block** (the design notes):

| Mode | Behavior |
|---|---|
| `Off` | No gating. Actions run; nothing is adjudicated. |
| `Warn` | Denied actions are recorded and surfaced but still proceed (default). |
| `Block` | Denied actions are refused - fail-closed. Break-glass is the only override, and it is audited. |

## Roadmap (Phase 1)

1. `internal/blast` + `restart-service` end-to-end.
2. `roll-deploy`.
3. `approve` / `gate` / `audit` hardening.
4. `/v1` HTTP API.

## Quality bar

Every change passes `make gate-full` (formatting, vet, build, race tests with a
coverage floor, lint, gosec, gitleaks, PII scan, smoke, fuzz) and is merged only
after an independent review. Nothing is self-merged.
