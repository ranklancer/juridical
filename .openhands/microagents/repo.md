---
name: repo
type: repo
agent: CodeActAgent
---

# Juridical — OpenHands repo agent

## Read `AGENTS.md` first

The canonical agent instructions for this repository are in **`AGENTS.md` at the
repo root**. Read it at the start of every task. It is the single source of
truth for:

- what Juridical is (guardrailed action control plane;
  `request → plan (blast radius) → gate → approval token → execute → audit`)
- the engineered dev-loop and the **local-first worktree workflow**
- the **full gate** that must pass (`make gate-full`, mirrored by `ci.yml`)
- PR & branch discipline
- the security doctrine (fail-closed bounding, progressive enforcement,
  plan-bound tokens, audited break-glass, hash-chained audit)
- repo structure and build/test commands

Everything below is **OpenHands-lane specific only**. Shared conventions are not
repeated here — if this file and `AGENTS.md` ever disagree, `AGENTS.md` wins.

## OpenHands-specific

- **You are the routine-tier producer only.** Author a focused change and open a
  pull request. You do not review and you do not merge; the independent
  adversarial review-loop owns everything after the PR is opened.
- **Branch prefix:** this lane prefixes work branches **`openhands/…`** (the
  Claude lane uses its own prefixes). Branch from `main`.
- **Never push to `main`; never self-merge.** The PR-only credential enforces
  this — treat a permission error there as correct behavior, not an obstacle to
  route around.
- **Work in a git worktree and get `make gate-full` green locally before opening
  the PR.** Do not use CI as your iteration loop. Full sequence in `AGENTS.md`.
- **Tier:** this lane runs on **local Devstral**. Keep changes small, focused,
  and verifier-friendly — narrow diffs, tests alongside, clear commit messages.
  This is a security-critical control plane in scaffold stage: prefer the
  smallest correct step and split anything that sprawls into separate PRs.
- **Module path trap:** imports use `github.com/juridical-docker/juridical`,
  which is *not* the GitHub owner. Do not "correct" it to `ranklancer`.
- **Adding a parser on an untrusted boundary?** Add a matching `FuzzXxx` target
  (see `make fuzz` in `AGENTS.md`) — advisory, but expected.
