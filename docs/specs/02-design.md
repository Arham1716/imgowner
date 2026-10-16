# imgowner — Design Document

**Version:** 1.0  
**Date:** 2026-10-15  
**Status:** SIGNED OFF 2026-10-15  
**Requires:** docs/specs/01-requirements.md (SIGNED OFF 2026-10-15)

---

## Design Questions Resolved

| # | Question | Decision |
|---|---|---|
| DQ-1 | Cache Trivy scan results? | Yes — cache by image digest to OS temp dir |
| DQ-2 | Registry auth | Docker credential chain only (`~/.docker/config.json` + helpers) |
| DQ-3 | SCM provider detection | Auto-detect from `GITHUB_ACTIONS` / `TF_BUILD` env vars; fallback to `scm.provider` in config |
| DQ-4 | GitHub Action — Trivy install | Download pinned Trivy binary from GitHub Releases at runtime |

---

## Option A — In-Process Pipeline with Digest Cache ✅ RECOMMENDED

**Summary:** A single Go process where all phases (scan → attribute → recommend → pins → report) run as sequential function calls, sharing typed structs in memory. Trivy JSON is cached on disk by image digest so local re-runs skip the scan entirely.

**How it works:**
Each cobra command builds a `Pipeline` struct, calls phases in order, and passes results forward as typed structs (`ScanResult`, `Attribution`, `PinReport`). The scan phase writes Trivy JSON to `$TMPDIR/imgowner/<digest>.json`; a second run with the same digest reads from cache and skips Trivy entirely. The `ci` command runs all phases end-to-end and writes a single structured error to stderr on failure. No intermediate artifacts are written to the project directory unless the user requests a report format.

**Pros:**
- Simplest data flow — no file I/O coordination between phases; a bug in one phase is caught in one place
- Digest cache solves the 30–90 s re-scan problem without multi-artifact complexity
- Each internal package (`internal/attribution`, `internal/pins`, etc.) is independently unit-testable against typed inputs — no disk fixtures needed for unit tests
- Single-process errors are straightforward to propagate and wrap with context

**Cons:**
- No way to re-run attribution from a saved scan result without re-writing code (power-user limitation)
- Cache invalidation is only by digest; if Trivy is upgraded mid-session, stale cached JSON may use the old schema until the digest changes
- All phases must complete in one process — a crash mid-pipeline leaves no partial artifacts to inspect

**Complexity:** Medium

**New dependencies flagged:**
- `gopkg.in/yaml.v3` — strict config YAML decoding with `KnownFields(true)` to satisfy FR-29 (unknown keys fail); Apache-2.0 compatible, no known HIGH/CRITICAL CVEs
- `golang.org/x/sync/errgroup` — bounded parallel base candidate scanning (FR-10); part of the Go project, BSD-3-Clause

**Failure modes:**
- Trivy not found or below min version → exit 2, structured JSON (FR-30)
- Cache hit with schema mismatch (Trivy upgraded) → detect via version field in cached JSON; invalidate and re-scan
- Registry unreachable → exit 2, structured JSON; never silently attribute as `unattributed` due to a network error
- Container runtime absent in CI mode → attribution completes; pins section reports "skipped" (FR-27)
- Partial base candidate failure → log the failed candidate, continue with the rest; report which candidates were skipped

---

## Option B — Artifact-First Pipeline

**Summary:** Each phase writes a structured JSON artifact (`scan.json`, `attribution.json`, `pins.json`) to `report.output_dir` before proceeding. Subsequent phases read from those artifacts, enabling any phase to be re-run independently.

**How it works:**
Each cobra subcommand writes its output JSON to disk and exits. The `ci` command chains subcommand invocations via Go function calls (not subprocess exec), checking for an existing phase artifact before re-running. A developer can run `imgowner scan`, then tweak the Dockerfile, then run `imgowner attribute` — the scan artifact is reused. Each artifact file is the authoritative input for the next phase.

**Pros:**
- Full audit trail: every intermediate result is on disk and inspectable
- Any phase can be re-run independently for debugging without re-running upstream phases
- Failures are localized — a broken pins run doesn't discard a completed scan and attribution

**Cons:**
- Stale artifact problem: if the Dockerfile changes between `scan` and `attribute`, the user gets wrong output silently unless explicit invalidation logic is added
- Increases CLI surface area — users must know which artifacts exist and when to delete them
- File I/O at every phase boundary adds complexity and potential race conditions in parallel CI runs sharing `output_dir`
- More complex integration tests — must set up and tear down artifact files

**Complexity:** High

**New dependencies:** same as Option A, plus explicit artifact versioning/invalidation logic (no external dep, but significant internal code)

**Failure modes:** same as Option A, plus stale artifact hazard; partial artifact corruption if a phase crashes mid-write

---

## Recommendation: Option A

The digest cache (DQ-1) resolves the main practical problem Option B was designed to solve — slow re-runs — without introducing artifact coordination complexity. In production CI, the pipeline always runs end-to-end; the artifact trail Option B provides is useful only during development of the tool itself, and golden-file tests in `testdata/` cover that need.

Option B should be revisited if the tool gains a `scan` subcommand exposed to users as a standalone step (post-MVP).

---

## Architecture Detail (Option A)

```
cmd/imgowner/
  main.go              cobra root + subcommands (attribute, pins, ci)

internal/
  scan/
    runner.go          exec Trivy, write/read digest cache, decode JSON
    cache.go           $TMPDIR/imgowner/<sha256>.json read/write + version check
  image/
    registry.go        go-containerregistry: resolve digest, fetch config/history
  dockerfile/
    parser.go          buildkit parser: stage tree, ARG resolution, RUN extraction
    shell.go           mvdan/sh: shell-parse RUN instructions, extract pin tokens
  attribution/
    classifier.go      layer map + base prefix match → Owner per finding
    mapper.go          Dockerfile line mapping (exact → fuzzy → none)
  baserec/
    enumerator.go      list patch tags from registry
    scanner.go         parallel scan with errgroup (concurrency 3)
  pins/
    extractor.go       extract pkg=version tokens with line+byte offsets
    lookup.go          one docker run per stage, batch script
    compare.go         dpkg/apk in-container version comparison
    editor.go          byte-level token replacement (FR-20)
  report/
    markdown.go        MD report
    json.go            JSON report
    sarif.go           SARIF report
  scm/
    detect.go          auto-detect GitHub/ADO from env vars (DQ-3)
    github.go          go-github: open/update PR, find/edit comment by marker
    azuredevops.go     azure-devops-go-api: PR and comment client
  config/
    loader.go          yaml.v3 strict decode, CLI flag merge, defaults

testdata/
  fixtures/            recorded Trivy JSON + image configs (golden-file tests)
```

**Context propagation:** every exported function accepts `context.Context` as first argument; all external calls (Trivy exec, registry fetch, `docker run`, SCM API) pass it through.

**Error types:** typed sentinel errors (`ErrToolMissing`, `ErrVersionTooOld`, `ErrBaseUnresolvable`) wrapped with `fmt.Errorf("imgowner: %w", err)`. CI mode marshals to JSON before writing to stderr.

**SCM detection (DQ-3):** `detect.go` checks `GITHUB_ACTIONS`, then `TF_BUILD`, then `scm.provider` in config. If none is set and a PR comment is attempted, exit 2 with a structured error.

**GitHub Action:** composite action downloads `imgowner` and Trivy binaries from GitHub Releases (pinned versions), installs them to `$RUNNER_TOOL_CACHE`, then invokes `imgowner ci`. No Docker-in-Docker needed — Docker is pre-installed on standard GitHub runners (DQ-4).

---

## Deferred Design Questions

_None — all questions resolved above._

---

## Out of Scope (design layer)

- Trivy Go library as an alternative to CLI invocation (rejected: CLI is stable, avoids linking Trivy's full dependency tree)
- Viper for config loading (rejected: does not natively fail on unknown keys; `yaml.v3` strict decode is simpler and correct)
- Azure DevOps Marketplace extension (deferred to v2 per requirements)

---

Do you sign off on this design? Type **SIGNED OFF** to finalize, or tell me what to change.
