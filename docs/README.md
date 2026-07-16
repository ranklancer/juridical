# Juridical documentation

This directory holds design and operational documentation. Architectural
decisions live under [`../adr/`](../adr/).

## Contents

- Architecture decision records - `../adr/the design notes..0003`
- Security policy - [`../SECURITY.md`](../SECURITY.md)
- Contributing guide - [`../CONTRIBUTING.md`](../CONTRIBUTING.md)

## Concepts

Juridical bounds and adjudicates operational actions. Four ideas recur
throughout the docs and the code:

| Concept | Package | Question it answers |
|---|---|---|
| Blast radius | `internal/blast` | How far does this action reach, and is that within its declared bound? |
| Approval | `internal/approve` | Is there a valid, single-use, plan-bound token authorizing it (with separation of duties)? |
| Gate | `internal/gate` | Off / Warn / Block - does policy allow it, or is a break-glass override in effect? |
| Audit | `internal/audit` | Is every decision recorded in an append-only, hash-chained log? |

Detailed per-component docs land alongside their implementation, one reviewed
pull request at a time (the internal design spec).
