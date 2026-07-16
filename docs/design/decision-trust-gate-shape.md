# the design notes: Independent copy of the trust-gate shape (no shared runtime dependency)

- Status: Accepted
- Date: 2026-07-16

## Context

The trust-gate model - `Gate` / `Policy` / `Verdict`, with Off/Warn/Block and
break-glass - is proven in a sibling supply-chain project. Juridical needs the
same decision *shape* for its image-verdict integration point, and reuse is
tempting.

## Decision

Juridical carries its own independent implementation of the gate shape in
`internal/gate` for v0.1. It is not a shared runtime dependency on the sibling
project's module; the two evolve separately (per the internal design spec O-F2-1). Only the
conceptual shape is shared.

## Consequences

- Juridical has no external module coupling to another product's internals and
  no cross-repo version lockstep.
- Some duplication is accepted deliberately; if the shape stabilizes across
  both products, a shared library can be reconsidered in a later ADR.
- The `ImageVerdict` stub in `internal/gate` documents the seam where an
  external verifier would plug in.
