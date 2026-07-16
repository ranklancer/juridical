# the design notes: Single static binary (CGO_ENABLED=0)

- Status: Accepted
- Date: 2026-07-16

## Context

Juridical is a control plane that must deploy predictably across heterogeneous
Linux hosts (x86-64 servers, ARM SBCs) with no assumptions about the target's C
runtime, glibc version, or package manager.

## Decision

Build Juridical as a single, statically linked Go binary with `CGO_ENABLED=0`,
`-trimpath`, and version metadata injected via `-ldflags -X`. No cgo, no dynamic
linking, no runtime interpreter.

## Consequences

- The same artifact runs on any supported `GOOS/GOARCH` with no shared-library
  dependencies; container images can be `FROM scratch`.
- Cross-compilation is trivial and reproducible, which the release pipeline
  (GoReleaser + SBOM + cosign + SLSA) relies on.
- Any future need for a cgo-only library must be revisited here first; the
  default remains pure Go.
