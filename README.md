<p align="center">
  <img src="assets/logo-dark.svg" alt="Juridical — the Juridical (Forerunner mark)" width="200" height="200">
</p>

# Juridical

[![CI](https://github.com/ranklancer/juridical/actions/workflows/ci.yml/badge.svg)](https://github.com/ranklancer/juridical/actions/workflows/ci.yml)
[![Secret scan](https://github.com/ranklancer/juridical/actions/workflows/sanitization.yml/badge.svg)](https://github.com/ranklancer/juridical/actions/workflows/sanitization.yml)
[![Go 1.22](https://img.shields.io/badge/go-1.22-00ADD8.svg)](go.mod)
[![License: AGPL-3.0-only](https://img.shields.io/badge/license-AGPL--3.0--only-blue.svg)](LICENSE)

**Bound the blast radius. Require the approval. Keep the receipt.**

Juridical is a control plane that sits in front of operational actions - restart
a service, roll a deployment, and (later) reboot a host - and refuses to let any
of them run further than they were declared to reach, without a valid approval,
and without an immutable record of the decision.

It is named for the Forerunner *Juridical* rate: the office of authorization and
oversight. That is the whole job here - **authorize, adjudicate, bound, audit.**

> Status: **v0.1 founding scaffold.** This repository currently contains the
> project skeleton, quality gate, and CI/supply-chain hardening only - no
> action-execution code yet. Phase-1 features land one reviewed pull request at
> a time (see the roadmap below). The repository is private until an explicit
> public flip.

## Why

Automation that can act on production is only as safe as the guardrails around
it. Most tools either ask for blanket credentials and hope, or bolt on approvals
that are trivially bypassed and leave no trail. Juridical inverts that: an action
does not execute unless the plan is inside its declared blast radius, an approval
token authorizes exactly that plan, and the outcome is appended to a tamper-
evident log.

## What it does

| Capability | What it means |
|---|---|
| **Blast-radius bounding** | Every action declares how far it may reach. Juridical computes the actual reach against live topology and refuses anything outside the bound - fail-closed. |
| **Approval gate** | A plan is hashed; a single-use token is minted against that hash, with separation-of-duties checks. A token authorizes one plan and nothing else. |
| **Progressive enforcement** | The gate runs Off / Warn / Block and defaults to Warn, so you can observe what *would* be blocked before you ratchet to enforcement (the design notes). |
| **Append-only audit** | Every decision - allowed, warned, blocked, or broken-glass - is written to an append-only, hash-chained log with redaction of sensitive fields. |
| **Break-glass, always audited** | Emergencies get an explicit, authorized override path. The override is itself a first-class audit record. |

## How it fits together

```
request → plan (blast radius) → gate (Off/Warn/Block) → approval token → execute → audit
              │                        │                      │                        │
              └ declared vs computed   └ policy + break-glass  └ single-use, plan-bound └ append-only, hash-chained
```

## Design at a glance

- **Language:** Go 1.22, a single static binary (`CGO_ENABLED=0`) - the design notes.
- **License:** AGPL-3.0-only.
- **Quality gate:** `make gate-full` - fmt, vet, build, race tests with a
  coverage floor, `golangci-lint`, `gosec`, `gitleaks`, a PII/infra scan, a
  smoke check, and fuzzing of untrusted-input parsers. CI runs the identical
  target.
- **Supply chain:** least-privilege workflow tokens, SHA-pinned Actions, CodeQL,
  OpenSSF Scorecard, `govulncheck`, and signed, SBOM-bearing, SLSA-provenanced
  releases.
- **Governance:** every change is a pull request; nothing is self-merged; each
  PR gets an independent review pass.

## Quick start (scaffold)

```sh
git clone https://github.com/juridical-docker/juridical.git
cd juridical
make gate-full     # run the full local quality gate
make build         # produce the ./juridical binary
./juridical -version
```

The Phase-1 subcommands (`serve`, `action`, `plan`, `approve`, `audit`) are
declared in `juridical -help` and implemented in later pull requests.

## Roadmap (Phase 1)

1. `internal/blast` primitive + `restart-service` end-to-end (plan → approval
   token → execute → hash-chained audit).
2. `roll-deploy` action.
3. `approve` / `gate` / `audit` hardening (plan hashing, SoD, break-glass,
   redaction, chain verification).
4. The `/v1` HTTP API.

## Security

See [`SECURITY.md`](SECURITY.md) for private vulnerability reporting, response
targets, and safe harbor.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Design decisions are recorded as ADRs
under [`adr/`](adr/).

## License

GNU Affero General Public License, version 3.0 only ([AGPL-3.0-only](LICENSE)) — see [`NOTICE`](NOTICE) for the commercial dual-license option. Copyright (C) 2026 ranklancer.