# imgowner — CLAUDE.md

## 1. Project Context

**Purpose:** CLI tool that attributes container image CVEs by layer owner (base image / added OS packages / app libraries) and auto-updates pinned OS package versions in Dockerfiles via pull requests.

**Status:** M1 in progress. Specs signed off. See `docs/specs/` for requirements, design, workflows, and tickets.

**Module:** `github.com/Arham1716/imgowner`

**Go version:** 1.23.4

---

## 2. Stack

- **Language:** Go 1.23
- **CLI framework:** `github.com/spf13/cobra`
- **Scanner:** Trivy (external binary, minimum v0.76.0) — invoked via `os/exec`, never as a Go library
- **Registry access:** `github.com/google/go-containerregistry`
- **Dockerfile parsing:** `github.com/moby/buildkit/frontend/dockerfile/parser`
- **Shell parsing (RUN instructions):** `mvdan.cc/sh/v3`
- **Config:** `gopkg.in/yaml.v3` with `KnownFields(true)` strict decode
- **Parallelism:** `golang.org/x/sync/errgroup` (concurrency cap = 3 for base candidate scans)
- **SCM — GitHub:** `github.com/google/go-github/v67`
- **SCM — Azure DevOps:** `github.com/microsoft/azure-devops-go-api/azuredevops/v7`

---

## 3. Architecture

Single static binary. In-process pipeline — data flows as typed structs in memory. Trivy JSON is cached by `$TMPDIR/imgowner/<digest>__<trivyversion>.json`.

```
cmd/imgowner/main.go          — cobra root + attribute / pins / ci subcommands
internal/config/              — .imgowner.yaml loader (strict, precedence: CLI > file > defaults)
internal/scan/                — Trivy runner + digest cache + version check
internal/image/               — registry access: resolve digest, fetch image/base config
internal/dockerfile/          — Dockerfile parser, stage tree, ARG resolution, RUN extraction
internal/attribution/         — CVE classifier (base/added-os/app/unattributed) + line mapper
internal/baserec/             — base image candidate enumeration + parallel scan + CVE diff
internal/pins/                — pin extractor, version lookup (container run), compare, byte editor
internal/report/              — Markdown / JSON / SARIF output
internal/scm/                 — SCM provider detection, GitHub and Azure DevOps PR/comment clients
testdata/fixtures/            — recorded Trivy JSON + image configs for golden-file tests
```

---

## 4. Conventions

- Every exported function takes `context.Context` as its first argument.
- External calls (Trivy, registry, `docker run`, SCM API) must respect the context deadline.
- Exit codes: `0` success · `1` policy breach · `2` tool/config error.
- All errors in CI mode are JSON on stderr — never raw stack traces.
- Typed sentinel errors: `scan.ErrToolMissing`, `scan.ErrVersionTooOld`. Wrap with `fmt.Errorf("imgowner: %w", err)`.
- No secrets, tokens, or PII in any log line or report.
- Never push to the default branch. Fix branches only (prefix `fix/os-pins-`).
- `--scanners vuln` is hardcoded in `scan.Runner.Scan` — never expose this as a flag.
- PR comments use the `<!-- imgowner -->` HTML marker for idempotent find-or-update.

---

## 5. Running locally

```powershell
# Build
go build -o imgowner.exe ./cmd/imgowner

# Run
./imgowner.exe --help
./imgowner.exe attribute --image python:3.12-slim --dockerfile Dockerfile

# Tests
go test ./...
```

Requires: Go 1.23+, Trivy ≥ 0.76.0, Docker or Podman (for `pins` commands only).
