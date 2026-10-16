# imgowner — Requirements Specification

**Version:** 1.0  
**Date:** 2026-10-15  
**Status:** Awaiting sign-off

---

## 1. Functional Requirements

### 1.1 Image Scanning & Layer Mapping

**FR-01** — The tool shall accept an image reference (name + tag or digest) and a Dockerfile path as required inputs to all attribution commands.

> **Given** a valid image reference and a Dockerfile path are provided,  
> **When** the user runs any attribution command,  
> **Then** the tool resolves the image to a digest-pinned reference before scanning.

---

**FR-02** — The tool shall invoke Trivy as an external CLI with `--format json --scanners vuln` and capture the JSON output; secret scanning must never be enabled, and the scanners flag must not be user-configurable.

> **Given** an image reference is resolved,  
> **When** the scan step runs,  
> **Then** the command issued is exactly `trivy image --format json --scanners vuln --platform <platform> <image>@<digest>` and the resulting JSON is parsed into a typed findings struct.

---

**FR-03** — The tool shall build a deterministic layer map by walking the image `history` in order and assigning each non-empty history entry the next `DiffID` from `rootfs.diff_ids`.

> **Given** a fetched image config with `history` and `rootfs.diff_ids`,  
> **When** the layer map is built,  
> **Then** every non-empty history entry maps to exactly one DiffID, and the mapping is reproducible across runs.

---

**FR-04** — The tool shall identify base layers by fetching the base image config and verifying that its `diff_ids` form an exact prefix of the final image's `diff_ids`; if no prefix match is found it shall fall back to OCI annotations, then `--base-digest` CLI flag, then mark all unresolvable findings as `unattributed`.

> **Given** a resolved base image reference from the Dockerfile `FROM` line,  
> **When** base layer identification runs,  
> **Then** all layers whose DiffID appears in the base image's `diff_ids` list are marked as base layers, and findings on those layers are classified `base`.

---

### 1.2 CVE Classification

**FR-05** — The tool shall classify every Trivy finding as exactly one of: `base`, `added-os`, `app`, or `unattributed`, using layer index and Trivy's `Class` field.

> **Given** a complete layer map and identified base layer count,  
> **When** classification runs,  
> **Then** each finding with layer index < base layer count → `base`; `os-pkgs` class on a post-base layer → `added-os`; `lang-pkgs` class on a post-base layer → `app`; missing or unmappable layer → `unattributed`.

---

**FR-06** — The tool shall map each finding to a Dockerfile instruction line using ordered match (exact `created_by` match), then fuzzy match on `created_by` text, and record the confidence level (`exact`, `fuzzy`, or `none`).

> **Given** a classified finding and a parsed Dockerfile,  
> **When** line mapping runs,  
> **Then** the finding's `Instruction` field is set to the matching line and line number, or `nil` with confidence `none` if no match is found.

---

**FR-07** — The tool shall classify findings from `COPY --from=<stage>` layers in the final stage as `app` when the Trivy class is `lang-pkgs`, and as `added-os` when the class is `os-pkgs`; both shall be annotated with "copied from stage `<stage>`".

> **Given** a multi-stage Dockerfile where the final stage copies artifacts from a builder stage,  
> **When** classification runs on a finding from a `COPY --from` layer,  
> **Then** the finding is classified `app` or `added-os` (not `base`) and the annotation names the source stage.

---

**FR-08** — The tool shall surface every `unattributed` finding in the report with a human-readable reason describing why attribution failed (e.g. "squashed image — no DiffID match", "base image not resolvable", "layer missing from history").

> **Given** a finding that cannot be attributed to any layer,  
> **When** the report is generated,  
> **Then** the finding appears in an `unattributed` section with a reason string, and is never silently omitted.

---

### 1.3 Base Image Recommendation

**FR-09** — The tool shall enumerate up to N patch-tag candidates for the base image (default N=5; configurable via `base_candidates: N` in `.imgowner.yaml` or `--base-candidates` CLI flag), where candidates are tags that share the same name and major version as the current base but have a higher patch component.

> **Given** a base image reference with a parseable tag,  
> **When** candidate enumeration runs,  
> **Then** the tool queries the registry and returns the N most-recent patch tags as candidates, stopping at N even if more exist.

---

**FR-10** — The tool shall scan each base image candidate in parallel with a concurrency limit of 3, diff its CVE set against the current base, and report the number of CVEs removed per candidate.

> **Given** a list of up to N base image candidates,  
> **When** candidate scanning runs,  
> **Then** at most 3 candidates are scanned simultaneously; each result includes a CVE-removed count and the digest-pinned `FROM` line to use.

---

**FR-11** — The tool shall output the recommended base image as a complete, digest-pinned `FROM` line (e.g. `FROM python:3.12-slim@sha256:abc123`) in both the report and the CI comment.

> **Given** a candidate with the highest CVE-removed count,  
> **When** the recommendation is emitted,  
> **Then** the output line is a valid Dockerfile `FROM` statement with a pinned digest that can be pasted directly into the Dockerfile.

---

### 1.4 Pin Discovery

**FR-12** — The tool shall shell-parse every `RUN` instruction across all Dockerfile stages (not only the final stage) and extract all exact-pinned packages in the form `pkg=version` for `apt-get install` / `apt install` / `apk add`.

> **Given** a Dockerfile with pinned packages across multiple stages,  
> **When** pin extraction runs,  
> **Then** every `pkg=version` token is recorded with its stage name, instruction line number, package name, and pinned version.

---

**FR-13** — The tool shall resolve `ARG` and `ENV` variable substitutions in pin expressions; pins whose version is defined only via a build-arg with no default shall be marked `variable` and skipped with a warning.

> **Given** a `RUN apt-get install -y curl=$CURL_VERSION` where `CURL_VERSION` has no default,  
> **When** pin extraction runs,  
> **Then** the pin is recorded with status `variable` and a warning is emitted; the tool continues processing other pins without failing.

---

**FR-14** — The tool shall detect packages installed from third-party repositories (e.g. custom apt sources added via `RUN echo "deb ..."`) and mark their downstream pins as `unsupported`, skipping version lookup for those pins.

> **Given** a Dockerfile that adds a third-party apt source before installing from it,  
> **When** pin extraction runs,  
> **Then** packages resolved from that source are marked `unsupported` and excluded from version lookup; a warning names the source.

---

### 1.5 Pin Status Check

**FR-15** — The tool shall run one container per Dockerfile stage (using the stage's base image at the resolved digest) to look up available package versions, batching all packages for that stage into a single shell script to minimise container startup overhead.

> **Given** a set of pinned packages extracted from one stage,  
> **When** version lookup runs,  
> **Then** a single `docker run --rm <base>@<digest>` call executes one script that returns available versions for all packages in that stage.

---

**FR-16** — The tool shall compare pinned versions against available versions using in-container tooling (`dpkg --compare-versions` for Debian/Ubuntu; `apk version -t` for Alpine) and classify each pin as `current`, `update-available`, `fixes-CVE(s)`, or `unavailable`.

> **Given** a pinned package and its available versions from the container run,  
> **When** version comparison runs,  
> **Then** each pin is assigned exactly one status: `current` if pinned equals highest available, `update-available` if a newer version exists, `fixes-CVE(s)` if the newer version resolves one or more attributed CVEs, or `unavailable` if the pinned version is absent from the repository.

---

**FR-17** — The tool shall use a preflight check at startup to confirm that Docker or Podman is accessible before running any `pins check` or `pins update` command; if neither is found it shall exit with code 2 and a structured JSON error.

> **Given** the user runs `imgowner pins check` or `imgowner pins update`,  
> **When** the preflight check runs,  
> **Then** if no container runtime is detected the tool exits immediately with code 2 and a JSON body naming the missing dependency; it never proceeds silently.

---

### 1.6 Pin Update PR

**FR-18** — The tool shall bump `unavailable` pins to the newest available version in the same OS release, still exactly pinned; the PR body must explicitly flag these as "previously unavailable — build would have failed" changes.

> **Given** a pin whose exact version is no longer in the repository,  
> **When** the update PR is prepared,  
> **Then** the pin is replaced with the highest available version for that package in the same release, and the PR body lists it under a "Unavailable pins bumped" heading.

---

**FR-19** — If a package is entirely absent from the OS repository (no version available), the tool shall not change that pin in the Dockerfile and shall list it in the report as requiring manual action.

> **Given** a package that no longer exists in the OS repository,  
> **When** the update PR is prepared,  
> **Then** the Dockerfile is unchanged for that package, and the PR body includes a "Requires manual action" section listing it with its last known pinned version.

---

**FR-20** — The tool shall edit the Dockerfile by byte-level token replacement of each pin version at its known line and column offset; the Dockerfile must never be re-serialized from a parsed AST.

> **Given** a Dockerfile with known pin token positions,  
> **When** pin versions are updated,  
> **Then** only the exact version string bytes at each recorded offset are replaced; all other bytes, whitespace, and comments are preserved unchanged.

---

**FR-21** — The tool shall open a pull request on the detected SCM (GitHub or Azure DevOps) on a new branch prefixed with `fix/os-pins`; if a PR from a previous `pins update` run already exists (identified by the `<!-- imgowner -->` marker in the PR body), it shall update that PR in-place rather than opening a new one.

> **Given** a completed pin update with one or more version changes,  
> **When** the PR step runs,  
> **Then** the tool searches open PRs for the `<!-- imgowner -->` marker; if found it edits that PR's body and pushes to its branch; if not found it opens a new PR on a new branch.

---

**FR-22** — If the SCM labels configured in `.imgowner.yaml` (`scm.labels`) do not exist in the repository, the tool shall emit a warning naming the missing labels and open the PR without them; it must never create labels and must never fail because of missing labels.

> **Given** `.imgowner.yaml` lists `labels: [security, dependencies]` and neither label exists in the repository,  
> **When** the PR is opened,  
> **Then** the PR is created successfully without labels, and a warning line is printed: "Label 'security' not found — skipping. Label 'dependencies' not found — skipping."

---

### 1.7 CI Integration & Policy

**FR-23** — The tool shall provide a `ci` command that runs attribution, pin check, policy evaluation, and PR comment in a single invocation.

> **Given** the user runs `imgowner ci --image <ref> --dockerfile Dockerfile`,  
> **When** the command completes,  
> **Then** the output includes the attribution report, pin statuses, policy verdict, and a PR comment has been posted or updated.

---

**FR-24** — The tool shall fail CI (exit code 1) only for findings classified `app` or `added-os` at or above the configured severity threshold, and only when those findings are new relative to the baseline; `base` and `unattributed` findings shall always be report-only and shall never cause a CI failure.

> **Given** a CI run with `policy.fail_on: [CRITICAL, HIGH]` and `enforce_owners: [app, added-os]`,  
> **When** policy evaluation runs,  
> **Then** exit 1 is returned only if at least one `app` or `added-os` finding at CRITICAL or HIGH severity is absent from the baseline; a scan with only `base` CVEs exits 0 regardless of severity.

---

**FR-25** — When `policy.new_only: true`, the tool shall require `--base-image-ref` (the image reference from the target branch); if the flag is absent the tool shall exit with code 2 and a structured JSON error explaining the requirement.

> **Given** `policy.new_only: true` in the config and `--base-image-ref` is not provided,  
> **When** the `ci` command runs,  
> **Then** the tool exits immediately with code 2 and a JSON body: `{"error": "new_only requires --base-image-ref", "hint": "pass the image from the target branch"}`.

---

**FR-26** — The tool shall post or update a PR comment containing the attribution summary, pin status table, and policy verdict; it shall identify an existing comment to update by the `<!-- imgowner -->` HTML marker, and edit it in-place rather than appending a new comment.

> **Given** a previous `ci` run has already posted a comment containing `<!-- imgowner -->`,  
> **When** the current run completes,  
> **Then** the existing comment is found by marker and its body is replaced; no second comment is created.

---

**FR-27** — If no container runtime is available during `ci` mode, the tool shall still run attribution and emit the full attribution report, but shall list pin statuses as "skipped: no container runtime" and note this explicitly in the PR comment; it must never skip silently.

> **Given** Docker and Podman are both absent on the CI runner,  
> **When** `imgowner ci` runs,  
> **Then** attribution completes normally, the PR comment includes a "Pin check skipped — no container runtime detected" notice, and the tool exits 0 (pins skipping is not a policy failure).

---

**FR-28** — The tool shall support Markdown, JSON, and SARIF output formats, selectable via `--format` or `report.formats` in config; multiple formats may be selected simultaneously and each is written to a separate file under `report.output_dir`.

> **Given** `--format md,json,sarif` is passed,  
> **When** the report step runs,  
> **Then** three files are written to the output directory: one `.md`, one `.json`, and one `.sarif`; all three contain the same finding data in their respective formats.

---

### 1.8 Configuration & Runtime

**FR-29** — The tool shall load `.imgowner.yaml` with precedence: CLI flags > config file > built-in defaults; any unknown keys in the config file shall cause an immediate exit with code 2 and a structured JSON error naming the unknown key.

> **Given** `.imgowner.yaml` contains an unrecognised key `foo: bar`,  
> **When** the tool starts,  
> **Then** it exits with code 2 and JSON: `{"error": "unknown config key", "key": "foo"}` before performing any work.

---

**FR-30** — The tool shall check the installed Trivy version at startup and exit with code 2 and a structured error if the version is below the configured minimum (`scan.trivy_min_version`, default `0.76.0`).

> **Given** Trivy 0.55.0 is installed and `trivy_min_version: "0.76.0"`,  
> **When** the tool starts,  
> **Then** it exits with code 2 and JSON: `{"error": "trivy version too old", "found": "0.55.0", "required": "0.76.0"}` before running any scan.

---

## 2. Non-Functional Requirements

**NFR-01** — Every external call (Trivy invocation, registry fetch, container run, SCM API call) must run under a `context.Context` with a configurable timeout; hanging calls must not block indefinitely.

**NFR-02** — Exit codes must be: `0` for success, `1` for policy failure (findings that breach configured thresholds), `2` for tool/configuration errors (missing dependency, bad config, missing flag). No other exit codes are used.

**NFR-03** — All errors emitted in CI mode must be structured JSON on stderr; raw Go stack traces and bare error strings must never appear in CI output.

**NFR-04** — No secrets, tokens, passwords, or PII must appear in any log line, report file, or PR comment body; the tool must redact or omit credential material from all output paths.

**NFR-05** — The tool must never push to the repository's default branch; all SCM writes go to a fix branch; the default branch is inferred from the SCM API response and the tool must refuse to target it.

**NFR-06** — SCM authentication must use only CI-provided identity tokens (e.g. `GITHUB_TOKEN`, Azure DevOps build service); the tool must not read or store personal access tokens.

**NFR-07** — The tool must be distributable as a single static Go binary, as a container image, as a GitHub composite Action, and as an Azure DevOps YAML pipeline template; all four distributions must be released together.

**NFR-08** — Candidate base image scans must run with a concurrency limit of 3; the limit must be enforced regardless of the value of `base_candidates`.

**NFR-09** — Container runs for pin lookup must not mount host volumes and must not use host networking; outbound network access is permitted only for package repository lookups (`apt-get update`, `apk update`); each container run must have a configurable timeout (default 5 minutes, `pins.lookup_timeout`).

---

## 3. Feature Map

```
Feature: Image Scanning & Layer Mapping  -> FR-01, FR-02, FR-03, FR-04
Feature: CVE Classification              -> FR-05, FR-06, FR-07, FR-08
Feature: Base Image Recommendation       -> FR-09, FR-10, FR-11
Feature: Pin Discovery                   -> FR-12, FR-13, FR-14
Feature: Pin Status Check                -> FR-15, FR-16, FR-17
Feature: Pin Update PR                   -> FR-18, FR-19, FR-20, FR-21, FR-22
Feature: CI Integration & Policy         -> FR-23, FR-24, FR-25, FR-26, FR-27, FR-28
Feature: Configuration & Runtime         -> FR-29, FR-30
```

---

## 4. Assumptions

The following assumptions were confirmed by the System Designer during the requirements session:

1. **Report-only for base & unattributed findings** — Base and unattributed CVEs are surfaced in reports and PR comments but never trigger a CI failure. Rationale: the app team cannot fix base image CVEs directly; the base recommendation feature is the remediation path.

2. **Unattributed findings are always surfaced with a reason** — The tool never silently drops unattributed findings. Each one includes a machine-readable reason string (e.g. `"squashed-image"`, `"base-unresolvable"`) so teams can investigate the classification gap.

3. **`new_only` requires `--base-image-ref`; absent flag = hard failure** — There is no fallback behaviour when `new_only: true` and `--base-image-ref` is missing. This is a strict requirement to prevent silent full-scan failures from masquerading as "no new findings."

4. **`--scanners vuln` is unconditional** — Secret scanning is outside scope. The flag is hardcoded and not exposed in config or CLI. This avoids scope creep and keeps scan times predictable.

5. **Default 5 patch-tag candidates, configurable** — `base_candidates: N` in `.imgowner.yaml` overrides the default. Concurrency is always capped at 3 regardless of N.

6. **PR comment is edited in-place using `<!-- imgowner -->` marker** — The marker is written into every comment body the tool creates. On subsequent runs the tool searches open PR comments for this marker and PATCHes the matching comment rather than posting a new one.

7. **Missing SCM labels → warn and skip, never fail** — The tool cannot reliably know labels exist before opening the PR. Creating labels requires elevated permissions that CI identities may not have. Failing on a cosmetic label is a poor trade-off.

---

## 5. Out of Scope (MVP)

- Secret scanning in container images (Trivy's `--scanners secret` mode)
- Time-boxed CVE exceptions / VEX export (planned post-MVP extension)
- Unpinned package updates (tool never unpins packages; that removes reproducibility)
- SBOM generation or export
- Language package pin updates (pip, npm, NuGet) — only OS packages (apt/apk)
- Builder-stage base image attribution — only the final stage's base is scanned
- Windows container images — only Linux (`linux/amd64` default)
- Docker Hub rate-limit handling beyond standard credential chain
- Azure DevOps Marketplace extension (YAML pipeline template only for MVP)
- Automatic creation of SCM labels
- Configurable secret scanning toggle

---

## 6. Open Questions

_None. All questions were resolved during the requirements session._

---

## Sign-off

Do you sign off on these requirements? Type **SIGNED OFF** to finalize, or tell me what to change.
