# imgowner — Jira Tickets

**Version:** 1.0  
**Date:** 2026-10-15  
**Status:** SIGNED OFF 2026-10-15

---

## Epic 1 — Image Attribution Pipeline

*Implements Flow Card 1 (`imgowner attribute`): scan → layer map → classify → recommend.*  
*Covers FR-01 through FR-11.*

---

### Story 1.1 — Resolve image digest and validate inputs

**User story:** As a DevOps engineer, I want the tool to validate my inputs and resolve the image to a pinned digest before any work begins, so that I get an immediate, actionable error if my command is wrong.

**Size:** S

**Description:** Implements the FR-01 input validation and FR-30 Trivy version check. Covers Flow 1 HANDLE rows F1, F4, and F10 — the three early-exit gates before any network or scan work runs.

**Acceptance criteria:**
- Given `--dockerfile` points to a non-existent path, when the command runs, then exit 2 with `{"error":"dockerfile not found","path":"<path>"}` before Trivy is invoked.
- Given Trivy is absent or below `trivy_min_version`, when the command runs, then exit 2 with `{"error":"trivy not found"}` or `{"error":"trivy version too old","found":"<v>","required":"<min>"}`.
- Given a valid image reference, when the command runs, then the image is resolved to a digest-pinned reference (e.g. `python:3.12-slim@sha256:abc123`) before scanning.
- Given an image reference that does not exist in the registry, when resolution runs, then exit 2 with `{"error":"image not found","ref":"<ref>"}`.

---

### Story 1.2 — Invoke Trivy with digest cache

**User story:** As a DevOps engineer, I want Trivy scan results cached by image digest, so that re-running attribution on the same image is instant.

**Size:** M

**Description:** Implements FR-02 (Trivy invocation with `--scanners vuln`) and the digest cache (DQ-1 from design). Covers Flow 1 HANDLE row F2 (cache schema mismatch → invalidate and re-scan) and F3 (registry unreachable).

**Acceptance criteria:**
- Given a valid image digest, when the scan runs, then the command issued is exactly `trivy image --format json --scanners vuln --platform <platform> <image>@<digest>`.
- Given a prior scan result exists at `$TMPDIR/imgowner/<digest>.json` with a matching schema version, when the scan runs, then Trivy is not invoked and the cached JSON is used.
- Given a cached file whose embedded schema version does not match the current Trivy version, when the scan runs, then the cache file is deleted, Trivy is invoked, and a fresh file is written.
- Given the registry is unreachable during digest resolution, when the command runs, then exit 2 with `{"error":"registry unreachable","host":"<host>","cause":"<os error>"}`.

---

### Story 1.3 — Build layer map and identify base layers

**User story:** As a DevOps engineer, I want the tool to identify which layers belong to my base image, so that CVEs from the base are correctly separated from ones I own.

**Size:** M

**Description:** Implements FR-03 (layer map) and FR-04 (base layer identification via `diff_ids` prefix match, OCI annotation fallback, `--base-digest` flag fallback). Unresolvable findings fall to `unattributed` with a reason string.

**Acceptance criteria:**
- Given an image config with `history` and `rootfs.diff_ids`, when the layer map is built, then every non-empty history entry maps to exactly one DiffID and the mapping is reproducible across runs.
- Given a base image whose `diff_ids` are an exact prefix of the final image's `diff_ids`, when base layer identification runs, then the first N layers are marked base layers.
- Given no prefix match is found, when identification runs, then the tool falls back to OCI annotations, then `--base-digest`, then marks all unresolvable findings `unattributed` with reason `"base-unresolvable"`.

---

### Story 1.4 — Classify CVE findings by owner

**User story:** As a DevOps engineer, I want every CVE labelled with who owns it (base image team, my OS packages, or my app), so that I know what to fix and what to escalate.

**Size:** M

**Description:** Implements FR-05 (4-way classification), FR-06 (Dockerfile line mapping), FR-07 (`COPY --from` classification), and FR-08 (unattributed surfacing with reason). Maps findings to Dockerfile lines with confidence labels.

**Acceptance criteria:**
- Given a finding on a layer with index < base layer count, when classification runs, then the finding is classified `base`.
- Given a finding with Trivy class `os-pkgs` on a post-base layer, when classification runs, then the finding is classified `added-os`.
- Given a finding with Trivy class `lang-pkgs` on a post-base layer, when classification runs, then the finding is classified `app`.
- Given a finding whose layer is missing or unmappable, when classification runs, then the finding is classified `unattributed` with a human-readable reason string.
- Given a finding from a `COPY --from=<stage>` layer, when classification runs, then `lang-pkgs` → `app` and `os-pkgs` → `added-os`, both annotated with "copied from stage `<stage>`".
- Given a classified finding, when Dockerfile line mapping runs, then the finding records the matching line number and confidence (`exact`, `fuzzy`, or `none`).
- Given an `unattributed` finding, when the report is generated, then it appears in the report with its reason string and is never silently omitted.

---

### Story 1.5 — Base image recommendation

**User story:** As a DevOps engineer, I want the tool to tell me which newer base image tag removes the most CVEs, so that I can fix base-image findings without manually comparing tags.

**Size:** M ⚠️ spillover risk — candidate scanning is the most network-dependent story in the epic; if registry latency is high in practice, this may need splitting at M2.

**Description:** Implements FR-09 (enumerate patch-tag candidates), FR-10 (parallel scan with concurrency 3), and FR-11 (digest-pinned `FROM` line output). Uses `errgroup` for bounded parallelism.

**Acceptance criteria:**
- Given a base image with a parseable tag, when candidates are enumerated, then up to N (default 5, configurable via `base_candidates`) patch tags are returned from the registry.
- Given N candidates, when scanning runs, then at most 3 are scanned simultaneously regardless of N.
- Given a successful candidate scan, when the recommendation is emitted, then the output is a valid, digest-pinned `FROM` line (e.g. `FROM python:3.12-slim@sha256:...`) ready to paste into a Dockerfile.
- Given some (but not all) candidates fail to scan, when the recommendation is emitted, then it is based on the successful candidates with a warning naming the skipped ones.
- Given all candidates fail to scan, when the report is generated, then no recommendation is emitted and a warning is included.

---

## Epic 2 — Pin Analysis

*Implements Flow Card 2 (`imgowner pins check`): discover → lookup → compare.*  
*Covers FR-12 through FR-17.*

---

### Story 2.1 — Extract pinned packages from Dockerfile

**User story:** As a DevOps engineer, I want the tool to find all exact-pinned packages across every Dockerfile stage, so that I have a complete inventory of pins that could go stale.

**Size:** S

**Description:** Implements FR-12 (shell-parse `RUN` instructions across all stages), FR-13 (ARG/ENV resolution; `variable` status for build-arg-only pins), and FR-14 (third-party repo detection; `unsupported` status).

**Acceptance criteria:**
- Given a Dockerfile with `pkg=version` tokens in `apt-get install` / `apt install` / `apk add` across multiple stages, when extraction runs, then every token is recorded with stage name, line number, byte offset, package name, and pinned version.
- Given a pin whose version is an `ARG` with no default value, when extraction runs, then the pin is marked `variable`, a warning is emitted, and the pin is skipped without failing the run.
- Given a `RUN` instruction that adds a third-party apt/apk source before installing from it, when extraction runs, then packages from that source are marked `unsupported` with the source named in the warning.
- Given no pinned packages exist in any stage, when the command runs, then exit 0 with `{"info":"no pinned packages found in Dockerfile"}`.

---

### Story 2.2 — Look up available versions via container run

**User story:** As a DevOps engineer, I want the tool to look up the latest available version for each pinned package in the actual distro repository, so that version comparisons are accurate and distro-aware.

**Size:** M

**Description:** Implements FR-15 (one `docker run` per stage, batched script), FR-17 (Docker/Podman preflight), and the Flow 2 HANDLE rows F1 and F2. Uses the stage's base image at its resolved digest.

**Acceptance criteria:**
- Given Docker or Podman is absent, when the command runs, then exit 2 before any parse work with `{"error":"no container runtime found","hint":"install Docker Engine or Podman"}`.
- Given a set of pinned packages in one stage, when version lookup runs, then a single `docker run --rm <base>@<digest>` executes one batched script covering all packages in that stage.
- Given a container run exceeds `lookup_timeout`, when the timeout fires, then all pins in that stage are marked `unknown (lookup timeout)`, remaining stages continue, and the report notes the timeout.
- Container runs must not mount host volumes and must not use host networking.

---

### Story 2.3 — Compare versions and classify pin status

**User story:** As a DevOps engineer, I want each pinned package classified as current, outdated, CVE-fixing, or unavailable, so that I can prioritise which pins to update.

**Size:** S

**Description:** Implements FR-16 (in-container `dpkg --compare-versions` / `apk version -t`; 4-way status classification). Covers Flow 2 HANDLE row F5 (unavailable status).

**Acceptance criteria:**
- Given a pinned version equal to the highest available version, when comparison runs, then the pin is classified `current`.
- Given a newer version available with no linked CVE fix, when comparison runs, then the pin is classified `update-available`.
- Given a newer version that resolves one or more attributed CVEs, when comparison runs, then the pin is classified `fixes-CVE(s)` with the CVE IDs listed.
- Given the pinned version is absent from the repository, when comparison runs, then the pin is classified `unavailable`.
- Given Debian/Ubuntu packages, when version comparison runs, then `dpkg --compare-versions` is used inside the container.
- Given Alpine packages, when version comparison runs, then `apk version -t` is used inside the container.

---

## Epic 3 — Pin Update PR

*Implements Flow Card 3 (`imgowner pins update`): edit Dockerfile → open/update PR.*  
*Covers FR-18 through FR-22.*

---

### Story 3.1 — Apply byte-level Dockerfile edits

**User story:** As a DevOps engineer, I want pin version strings updated in my Dockerfile without any other bytes changing, so that my formatting, comments, and whitespace are preserved exactly.

**Size:** M

**Description:** Implements FR-19 (entirely absent packages → no edit + manual action note), FR-20 (byte-level token replacement), and Flow 3 HANDLE row F6 (invalid syntax abort). Implements FR-18 (unavailable pins bumped to newest available, PR body flagged).

**Acceptance criteria:**
- Given one or more pins with `update-available` or `fixes-CVE(s)` status, when edits are applied, then only the version string bytes at the recorded offset are replaced; all other bytes are unchanged.
- Given an `unavailable` pin with at least one version available in the repo, when edits are applied, then the pin is bumped to the newest available version and the PR body notes it under "Unavailable pins bumped".
- Given a package entirely absent from the repo (no version available), when edits are applied, then the Dockerfile is not changed for that package and it appears in the PR body under "Requires manual action".
- Given an in-memory edit validation that produces invalid Dockerfile syntax (offset drift), when the check runs, then the entire PR flow is aborted before any git write, with exit 2 naming the affected line and token.
- Given no pins have changed after analysis, when the command runs, then exit 0 with `{"info":"no pins updated, nothing to commit"}` and no SCM interaction occurs.

---

### Story 3.2 — Open or update SCM pull request

**User story:** As a DevOps engineer, I want the tool to open a PR with updated pins (or update an existing one), so that pin updates go through the normal review process without me doing it manually.

**Size:** L

**Description:** Implements FR-21 (open or update PR via `<!-- imgowner -->` marker), FR-22 (missing labels — warn and skip), and Flow 3 HANDLE rows F1, F2, F3, F10. Covers both GitHub and Azure DevOps SCM clients.

**Acceptance criteria:**
- Given `--open-pr` is absent, when the command runs, then the pin status report is printed and no SCM code runs.
- Given the SCM provider cannot be detected from env vars or config, when the command runs, then exit 2 with `{"error":"scm provider undetectable","hint":"..."}` before any git write.
- Given a valid SCM token but the token lacks sufficient scope (403), when the PR step runs, then exit 2 distinguishing 401 (invalid token) from 403 (insufficient scope) in the message.
- Given no open PR with the `<!-- imgowner -->` marker exists, when the PR step runs, then a new branch (`fix/os-pins-<timestamp>`) is created and a new PR is opened.
- Given an open PR with the `<!-- imgowner -->` marker exists, when the PR step runs, then commits are pushed to its branch and the PR body is PATCHed in-place.
- Given configured labels that do not exist in the repo, when the PR is opened, then the PR is created without those labels and a warning names each missing label; the command does not fail.

---

## Epic 4 — CI Integration & Policy

*Implements Flow Card 4 (`imgowner ci`): attribute + pins + policy + PR comment.*  
*Covers FR-23 through FR-28.*

---

### Story 4.1 — Orchestrate full CI pipeline and evaluate policy

**User story:** As a DevOps engineer, I want a single `ci` command that runs attribution, pin check, and policy evaluation, so that I can wire up one command in my pipeline and get a structured pass/fail result.

**Size:** L

**Description:** Implements FR-23 (ci command orchestration), FR-24 (policy exit codes: 0/1/2), FR-25 (`new_only` + `--base-image-ref` gate), FR-27 (no container runtime → partial run). Covers Flow 4 HANDLE rows F1, F3, F4, F5, F6.

**Acceptance criteria:**
- Given `policy.new_only: true` and `--base-image-ref` is absent, when the command runs, then exit 2 immediately with `{"error":"new_only requires --base-image-ref","hint":"..."}` before any scan.
- Given attribution fails (Trivy missing, registry down, image not found), when the command runs, then exit 2 propagating the structured error from the attribution pipeline.
- Given no container runtime is available, when the command runs, then attribution completes normally, pins are marked "skipped: no container runtime", and the tool exits based on policy (attribution findings only).
- Given `app` or `added-os` findings at or above `fail_on` severity that are new, when policy is evaluated, then the PR comment is posted first, then the tool exits 1 with `{"policy":"breach","findings":[...]}`.
- Given only `base` or `unattributed` findings are present, when policy is evaluated, then the tool exits 0 and the PR comment includes the full report.
- Given `new_only: true` and `--base-image-ref` is provided, when the baseline scan succeeds, then only findings absent from the baseline are subject to policy evaluation.

---

### Story 4.2 — Post and update PR comment

**User story:** As a DevOps engineer, I want the CI run to post a structured comment on my PR with the full attribution and pin report, updated in-place on each run, so that reviewers always see the latest state without a flood of new comments.

**Size:** M

**Description:** Implements FR-26 (post/update PR comment via `<!-- imgowner -->` marker) and FR-28 (Markdown, JSON, SARIF output formats). SCM errors are best-effort and never change the policy exit code (Flow 4 DEFER F7, F8, F10).

**Acceptance criteria:**
- Given a previous `ci` run posted a comment containing `<!-- imgowner -->`, when the current run completes, then the existing comment body is replaced in-place; no second comment is created.
- Given no prior comment with `<!-- imgowner -->` exists, when the current run completes, then a new comment is posted.
- Given `--format md,json,sarif`, when the report step runs, then three files are written under `output_dir`: one `.md`, one `.json`, and one `.sarif`.
- Given the SCM API returns an error when posting the comment, when the error occurs, then it is logged with the response status and the tool exits based on policy result only — the SCM error does not change the exit code.
- Given no PR context exists (e.g. push to branch without an open PR), when the comment step runs, then it is silently skipped and the report is written to file only.

---

## Epic 5 — Configuration & Runtime

*STANDARD feature. Covers FR-29 and FR-30.*

---

### Story 5.1 — Load and validate `.imgowner.yaml`

**User story:** As a DevOps engineer, I want the tool to fail immediately with a clear error if my config file has unknown keys or bad values, so that I catch configuration mistakes before they silently affect scan results.

**Size:** S

**Description:** Implements FR-29: strict YAML decoding with `yaml.v3` `KnownFields(true)`, CLI flag precedence over config file, config over built-in defaults. Unknown keys cause exit 2.

**Acceptance criteria:**
- Given `.imgowner.yaml` contains an unknown key, when the tool starts, then exit 2 with `{"error":"unknown config key","key":"<key>"}` before any work begins.
- Given both a CLI flag and a config file value for the same setting, when the tool runs, then the CLI flag takes precedence.
- Given no `.imgowner.yaml` is present, when the tool runs, then all built-in defaults apply and no error is emitted.

---

### Story 5.2 — Enforce Trivy minimum version at startup

**User story:** As a DevOps engineer, I want the tool to reject an outdated Trivy installation with a clear message, so that I don't get silent wrong results from a schema mismatch.

**Size:** XS

**Description:** Implements FR-30: check Trivy version at startup; exit 2 with structured error if below `scan.trivy_min_version` (default `0.76.0`). This is also the F1 gate in Flow Card 1.

**Acceptance criteria:**
- Given Trivy `0.55.0` is installed and `trivy_min_version: "0.76.0"`, when the tool starts, then exit 2 with `{"error":"trivy version too old","found":"0.55.0","required":"0.76.0"}`.
- Given Trivy is not installed, when the tool starts, then exit 2 with `{"error":"trivy not found","hint":"install trivy ≥ 0.76.0"}`.
- Given Trivy `0.76.0` or newer is installed, when the tool starts, then the version check passes silently and the tool proceeds.
