# the design notes: Progressive enforcement - Off / Warn / Block, Warn by default

- Status: Accepted
- Date: 2026-07-16

## Context

Juridical gates actions by blast radius and approval. A gate that blocks from
day one is either ignored (set to Off) or routed around. Adoption requires a
path from observability to enforcement without a flag day.

## Decision

The gate has three modes - `Off`, `Warn`, `Block` - and defaults to `Warn`.
In `Warn`, a denied action is recorded and surfaced but still proceeds; in
`Block`, it is refused (fail-closed). A break-glass path allows an explicitly
authorized override, always audited.

## Consequences

- Operators can deploy in `Warn`, watch what *would* be blocked against real
  traffic, tune policy, then ratchet to `Block`.
- The default is safe-by-visibility, not silently permissive: every warn is an
  audit record.
- Enforcement state is part of the audited decision, so a mode change is itself
  observable.
