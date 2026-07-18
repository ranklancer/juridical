# Juridical build + gate. `make gate-full` is the single source of truth for
# the quality bar; CI runs the same target so local and CI stay identical.

GO            ?= go
COVER_FLOOR   ?= 74
BINARY        ?= juridical
PKG           ?= ./...
VERSION       ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)
COMMIT        ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE          ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS       := -s -w \
	-X github.com/juridical-docker/juridical/internal/version.Version=$(VERSION) \
	-X github.com/juridical-docker/juridical/internal/version.Commit=$(COMMIT) \
	-X github.com/juridical-docker/juridical/internal/version.Date=$(DATE)

.PHONY: all gate-full fmt vet build test cover lint gosec gitleaks pii smoke fuzz tools clean

all: build

fmt:
	$(GO) fmt $(PKG)
	@test -z "$$(gofmt -l cmd internal 2>/dev/null)" || { echo "gofmt: files need formatting"; gofmt -l cmd internal; exit 1; }

vet:
	$(GO) vet $(PKG)

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/juridical

test:
	$(GO) test -race -count=1 $(PKG)

cover:
	@$(GO) test -covermode=atomic -coverprofile=cover.out $(PKG) >/dev/null
	@pct=$$($(GO) tool cover -func=cover.out | awk '/^total:/ {gsub(/%/,"",$$3); print $$3}'); \
	echo "total coverage: $$pct% (floor $(COVER_FLOOR)%)"; \
	awk -v p="$$pct" -v f="$(COVER_FLOOR)" 'BEGIN { exit (p+0 >= f+0) ? 0 : 1 }' || { echo "coverage below floor"; exit 1; }

lint:
	@if command -v golangci-lint >/dev/null 2>&1; then golangci-lint run $(PKG); else echo "golangci-lint not installed; skipping (required in CI)"; fi

gosec:
	@if command -v gosec >/dev/null 2>&1; then gosec -quiet ./...; else echo "gosec not installed; skipping (required in CI)"; fi

gitleaks:
	@if command -v gitleaks >/dev/null 2>&1; then gitleaks detect --source . --redact --no-banner --exit-code 1; else echo "gitleaks not installed; skipping (required in CI)"; fi

pii:
	./tools/pii_scan.sh

smoke: build
	./$(BINARY) -version >/dev/null
	./$(BINARY) help >/dev/null

# fuzz runs the native Go fuzz targets over untrusted-input security-boundary
# parsers (audit record decode, approval token parse, plan_hash construction,
# /v1 request-body decode, declared_bound parsing) for a short bounded time
# each. Advisory: it exercises the fuzzing engine's random-mutation search on
# top of what `test` already runs (the same FuzzXxx funcs execute over their
# seed corpus as ordinary subtests during `make test`), so it is deliberately
# NOT a gate-full dependency -- a long-tail fuzz finding is a signal to
# investigate, not a merge blocker on every commit.
FUZZTIME ?= 15s
fuzz:
	@echo "advisory: native fuzz targets, $(FUZZTIME) each; not part of gate-full's blocking path"
	$(GO) test -run '^$$' -fuzz=FuzzReadAllRecord -fuzztime=$(FUZZTIME) ./internal/audit/
	$(GO) test -run '^$$' -fuzz=FuzzTokenStoreConsume -fuzztime=$(FUZZTIME) ./internal/approve/
	$(GO) test -run '^$$' -fuzz=FuzzPlanHash -fuzztime=$(FUZZTIME) ./internal/approve/
	$(GO) test -run '^$$' -fuzz=FuzzDecodeStrictPlansRequest -fuzztime=$(FUZZTIME) ./internal/api/
	$(GO) test -run '^$$' -fuzz=FuzzParseDeclaredBound -fuzztime=$(FUZZTIME) ./internal/api/

# Full local gate, mirrored by ci.yml.
gate-full: fmt vet build test cover lint gosec gitleaks pii smoke
	@echo "gate-full: OK"

tools:
	$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	$(GO) install github.com/securego/gosec/v2/cmd/gosec@latest
	$(GO) install golang.org/x/vuln/cmd/govulncheck@latest

clean:
	rm -f $(BINARY) cover.out
