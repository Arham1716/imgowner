# imgowner — Workflows

**Version:** 1.0  
**Date:** 2026-10-15  
**Status:** SIGNED OFF 2026-10-15  
**Requires:** docs/specs/01-requirements.md, docs/specs/02-design.md (both SIGNED OFF 2026-10-15)

---

## Part 1 — The Sort

| Feature (from Feature Map) | FRs | Classification |
|---|---|---|
| Image Scanning & Layer Mapping | FR-01–04 | SPEC → combined into Flow 1 |
| CVE Classification | FR-05–08 | SPEC → combined into Flow 1 |
| Base Image Recommendation | FR-09–11 | SPEC → combined into Flow 1 |
| Pin Discovery | FR-12–14 | SPEC → combined into Flow 2 |
| Pin Status Check | FR-15–17 | SPEC → combined into Flow 2 |
| Pin Update PR | FR-18–22 | SPEC → Flow 3 |
| CI Integration & Policy | FR-23–28 | SPEC → Flow 4 |
| Configuration & Runtime | FR-29–30 | STANDARD |

Features 1–3 execute as one `imgowner attribute` command; features 4–5 execute as one `imgowner pins check` command. Combining avoids 7 flow cards (above the 6-card limit) and aligns flows to user-facing commands.

**Result: 4 SPEC flows + 1 STANDARD feature.**

---

## Part 2 — Flow Cards

---

### Flow Card 1 — Image Attribution Pipeline (`imgowner attribute`)

**Happy path:**
1. Validate `--image` and `--dockerfile` flags are present and Dockerfile is readable (F10 gate).
2. Check Trivy version; resolve image to digest-pinned reference (F1, F3, F4 gates).
3. Check digest cache in `$TMPDIR/imgowner/`; if hit, verify embedded schema version matches current Trivy version (F2 gate). On miss or mismatch, invoke Trivy and write new cache.
4. Fetch image config from registry; build layer map (DiffID → history entry).
5. Parse Dockerfile; resolve final-stage `FROM`; fetch base image config; verify `diff_ids` prefix match (F5/F6 fall to unattributed with reason).
6. Classify every finding (`base` / `added-os` / `app` / `unattributed` + reason for unattributed).
7. Map each finding to a Dockerfile line (exact → fuzzy → none + confidence).
8. Enumerate ≤N patch-tag candidates; scan in parallel (concurrency 3); diff CVE sets; emit digest-pinned `FROM` recommendation (F7/F8 warn and continue).
9. Write report(s) to `output_dir`; exit 0.

**HANDLE in v1:**

| # | Trigger | System does | User sees |
|---|---|---|---|
| F1 | Trivy missing or below `trivy_min_version` | Exit 2 immediately, before any network call | `{"error":"trivy version too old","found":"0.55.0","required":"0.76.0"}` or `{"error":"trivy not found","hint":"install trivy ≥ 0.76.0"}` |
| F2 | Cache hit but Trivy schema version mismatch | Delete stale cache file; re-invoke Trivy; write fresh cache | Pipeline continues normally; debug log: "cache invalidated: schema version mismatch" |
| F3 | Registry unreachable (network error) | Exit 2 with structured error naming the host and underlying OS error | `{"error":"registry unreachable","host":"registry-1.docker.io","cause":"connection refused"}` |
| F4 | Image reference not found in registry | Exit 2 with structured error including the full reference | `{"error":"image not found","ref":"python:3.12-nonexistent"}` |
| F10 | `--dockerfile` path missing or unreadable | Exit 2 immediately, before Trivy is invoked | `{"error":"dockerfile not found","path":"./Dockerfile"}` |

**DEFER:** F5 (ARG-only FROM → unattributed + reason), F6 (prefix mismatch → unattributed + reason), F7 (all candidates fail → report with no recommendation + warn), F8 (partial candidate failure → recommendation from successful ones + warn), F12 (auth failure surfaces as F3).

**WONT HANDLE:** F9 (squashed images — documented non-support), F11 (`FROM scratch` — all findings classified `app`), F13 (Trivy timeout — Trivy's own handling sufficient).

---

### Flow Card 2 — Pin Analysis (`imgowner pins check`)

**Happy path:**
1. Preflight: detect Docker or Podman (F1 gate).
2. Shell-parse all `RUN` instructions across all stages; extract `pkg=version` tokens with line + byte offsets.
3. Resolve `ARG`/`ENV` substitutions; mark ARG-only pins (no default) as `variable`, warn and skip.
4. Detect third-party sources; mark downstream pins `unsupported`, warn and skip.
5. Determine distro + release per stage from base image config.
6. If no pinned packages found in any stage, exit 0 with info message (F8).
7. For each stage, run one batched `docker run --rm <base>@<digest>` under `lookup_timeout`; on timeout, mark all pins in that stage `unknown (lookup timeout)` and continue (F2).
8. Compare versions in-container (`dpkg --compare-versions` / `apk version -t`); classify each pin: `current` / `update-available` / `fixes-CVE(s)` / `unavailable` (F5).
9. Write pin status report; exit 0.

**HANDLE in v1:**

| # | Trigger | System does | User sees |
|---|---|---|---|
| F1 | Docker and Podman both absent | Exit 2 before any parse work | `{"error":"no container runtime found","hint":"install Docker Engine or Podman"}` |
| F2 | Container run exceeds `lookup_timeout` for a stage | Mark all pins in that stage as `unknown (lookup timeout)`; continue remaining stages | Report section for that stage: "Pin lookup timed out — statuses unknown" |
| F5 | Package entirely absent from distro repo | Classify pin as `unavailable`; include in report | Report row: `curl \| 7.88.1-10 \| — \| unavailable` |
| F8 | No pinned packages found in any stage | Exit 0 with info message | `{"info":"no pinned packages found in Dockerfile"}` |

**DEFER:** F3 (pull failure → exit-2, same path as Flow 1), F6 (malformed container output → `unknown (parse error)` per package + warn), F7 (distroless → stage marked `unsupported (no package manager)`, skipped).

**WONT HANDLE:** F4 (`FROM scratch` — no OS, stage skipped silently), F11 (container start race — no shared state).

---

### Flow Card 3 — Pin Update PR (`imgowner pins update`)

**Happy path:**
1. Run pin analysis (Flow 2) internally; collect all `update-available`, `fixes-CVE(s)`, and `unavailable` pins.
2. If no pins changed, exit 0 with info message (F1).
3. If `--open-pr` flag absent, print report and exit 0 — no SCM code runs (F10).
4. Validate all byte-level edits in memory; abort before any git write if any offset produces invalid syntax (F6).
5. Apply edits to Dockerfile: replace version bytes at recorded offsets; mark `unavailable` pins with bumped version and note in PR body.
6. Detect SCM provider (F2 gate); authenticate (F3 gate).
7. Search open PRs for `<!-- imgowner -->` marker. If found, push to its branch and PATCH body. If closed/merged or not found, create new branch (`fix/os-pins-<timestamp>`) and open new PR.
8. Apply configured labels; warn and skip any that don't exist. Exit 0.

**HANDLE in v1:**

| # | Trigger | System does | User sees |
|---|---|---|---|
| F1 | No pins changed after analysis | Exit 0 with info message; no git write | `{"info":"no pins updated, nothing to commit"}` |
| F2 | SCM provider undetectable | Exit 2 before any SCM call | `{"error":"scm provider undetectable","hint":"set scm.provider in .imgowner.yaml or run in GitHub Actions / Azure DevOps"}` |
| F3 | SCM API token absent or invalid | Exit 2; distinguish 401 from 403 | `{"error":"scm auth failed","status":401,"hint":"check GITHUB_TOKEN or Azure DevOps build service permissions"}` |
| F6 | Byte-level edit produces invalid syntax | Abort entire PR flow before any push; exit 2 with affected line and token | `{"error":"dockerfile edit invalid","line":12,"token":"curl=7.88.1-10"}` |
| F10 | `--open-pr` absent (dry-run) | Print report; return before any SCM code path; exit 0 | Full pin status report, no PR link |

**DEFER:** F4 (branch conflict — force-push if tool-owned branch, else exit 2), F5 (closed/merged PR — search open only; create fresh if none found), F7 (unavailable pin — skip edit, note in PR body), F8 (missing labels — warn and skip), F9 (PATCH fails post-push — log with PR URL, exit 0 with warning).

**WONT HANDLE:** none.

---

### Flow Card 4 — CI Integration & Policy (`imgowner ci`)

**Happy path:**
1. If `new_only: true` and `--base-image-ref` absent — exit 2 immediately (F1).
2. Run Image Attribution Pipeline (Flow 1) against `--image`. Propagate any Flow 1 exit-2 errors (F3).
3. If `--base-image-ref` provided: run attribution against it; diff findings. If baseline scan fails, fall back to full scan and warn in comment.
4. Preflight container runtime. If absent: mark pins "skipped: no container runtime"; continue to step 6 (F4).
5. Run Pin Analysis (Flow 2) against `--dockerfile`.
6. Evaluate policy: `app` + `added-os` findings at or above `fail_on` severity that are new (when `new_only`) → breach. `base` + `unattributed` → report only, no breach (F6).
7. Post or update PR comment via SCM (find `<!-- imgowner -->` marker; edit in-place or post fresh). SCM failure is best-effort — never changes exit code. Skip if no PR context.
8. Exit 1 on policy breach (F5); exit 0 otherwise.

**HANDLE in v1:**

| # | Trigger | System does | User sees |
|---|---|---|---|
| F1 | `new_only: true`, `--base-image-ref` absent | Exit 2 before any scan | `{"error":"new_only requires --base-image-ref","hint":"pass the target branch image ref with --base-image-ref"}` |
| F3 | Attribution pipeline fails | Exit 2; propagate structured error from Flow 1 | Same structured JSON as Flow 1 F1/F3/F4 |
| F4 | No container runtime on CI runner | Attribution completes; pins marked "skipped: no container runtime"; exit by policy | Comment includes "Pin check skipped — no container runtime detected" |
| F5 | `app` / `added-os` findings breach policy | Post comment first; exit 1 with breach payload | `{"policy":"breach","findings":[...]}` on stderr; PR comment updated |
| F6 | Only `base` / `unattributed` findings | Exit 0; post comment with full report | Comment shows all findings; no CI failure |

**DEFER:** F2 (no new findings → exit 0 + comment), F7 (SCM detection failure → log warning, exit by policy), F8 (SCM API error → log + exit by policy), F9 (baseline scan fails → full scan + warn in comment), F10 (no PR context → skip comment, write report to file).

**WONT HANDLE:** none.
