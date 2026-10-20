# imgowner

Container CVE attribution and OS package pin updater.

A vulnerability scanner tells you a container has 241 CVEs. It does not tell you
which ones your team introduced. `imgowner` answers that question: it maps every
finding back to the layer that produced it and reports whether the base image,
your own `apt-get install` line, or your application's dependencies brought it in.

```
CVE-2024-1111  CRITICAL  openssl   owner: added-os  Dockerfile:4
CVE-2024-2222  HIGH      curl      owner: added-os  Dockerfile:3
CVE-2024-3333  HIGH      libc6     owner: base
CVE-2024-5555  HIGH      requests  owner: app       Dockerfile:7
```

Findings on the base image are the upstream maintainer's to fix — usually by
bumping the `FROM` tag. The rest are yours.

## Install

Download a binary from the [releases page](https://github.com/Arham1716/imgowner/releases),
or build from source:

```bash
go install github.com/Arham1716/imgowner/cmd/imgowner@latest
```

[Trivy](https://github.com/aquasecurity/trivy) v0.76.0 or newer must be on `PATH`;
`imgowner` runs it to perform the scan itself.

```bash
brew install trivy          # macOS
winget install aquasecurity.trivy   # Windows
```

The `pins` subcommands additionally need Docker or Podman, because package
versions are resolved by querying the package manager inside the image.

## Usage

### Attribute CVEs to an owner

```bash
imgowner attribute --image myapp:latest --dockerfile Dockerfile
```

### Check whether pinned package versions are stale

```bash
imgowner pins check --dockerfile Dockerfile
```

```
curl=7.88.1-10            UPDATE  -> 7.88.1-12
openssl=3.0.11-1          UPDATE  -> 3.0.11-3
ca-certificates=20230311  OK
```

### Apply those updates and open a pull request

```bash
imgowner pins update --dockerfile Dockerfile --open-pr
```

Version strings are replaced at their exact byte offsets, so comments,
line continuations and formatting are preserved.

### Run the full pipeline in CI

```bash
imgowner ci --image myapp:${GIT_SHA} --dockerfile Dockerfile \
            --format md,json,sarif --output-dir imgowner-report
```

Exit codes: `0` clean, `1` policy breach, `2` tool or configuration error.

## Base image digests

Attribution works by checking that the base image's layers form an exact prefix
of the scanned image's layers. Resolving `FROM python:3.12-slim` gives whatever
that tag points at *today*, which may not be what the image was built from
weeks ago.

When the layers do not line up, `imgowner` reports every finding as
`unattributed` and explains why, rather than guessing an owner and blaming the
wrong team. Pin the base explicitly to resolve it:

```bash
imgowner attribute --image myapp:latest --base-digest sha256:abc123...
```

In CI, `imgowner ci` fails by default when the boundary cannot be verified.
Pass `--fail-on-base-mismatch=false` to downgrade that to a warning.

## GitHub Action

```yaml
- uses: Arham1716/imgowner@v0.1.0
  with:
    image: myapp:${{ github.sha }}
    dockerfile: Dockerfile
    format: md,json,sarif
    pr-id: ${{ github.event.pull_request.number }}
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

SARIF output is uploaded to the repository's Security tab, and a single comment
is kept up to date on the pull request rather than a new one per run.

A complete workflow is in [`examples/github-workflow.yml`](examples/github-workflow.yml).

## Configuration

`imgowner` reads `.imgowner.yaml` from the working directory. Every key is
optional; unknown keys are rejected rather than silently ignored. See
[`examples/imgowner.yaml.example`](examples/imgowner.yaml.example) for the full
set of options.

```yaml
scan:
  platform: linux/amd64
  trivy_min_version: "0.76.0"
  base_candidates: 3

policy:
  fail_on: [CRITICAL, HIGH]
  enforce_owners: [app, added-os]   # base CVEs do not fail the build

pins:
  ignore_packages: [ca-certificates]
```

`enforce_owners` is what makes the attribution actionable: a CRITICAL in the
base image will not fail your build, because you cannot fix it without changing
the base.

## How it works

1. The image reference is resolved to a digest and scanned with Trivy.
2. The image config's `rootfs.diff_ids` and history are walked to build a layer
   map, which is matched against the Dockerfile's instructions.
3. The base image's `diff_ids` are checked against the scanned image's as an
   exact prefix. The match point is the boundary between base and your layers.
4. Each finding's layer position and package class decide its owner: below the
   boundary is `base`, OS packages above it are `added-os`, language packages
   are `app`.
5. Scan results are cached by image digest and Trivy version, so repeat runs
   over an unchanged image skip the scan.

## Limitations

- Attribution needs per-layer `DiffID`s from Trivy. Squashed images do not carry
  them, and findings without one are reported as `unattributed`.
- `apt` and `apk` only. RPM-based images are scanned and attributed normally,
  but their pins are not managed.
- Pin lookup assumes one package manager per stage.
- `linux/amd64` is the default platform; others work via `scan.platform` but are
  less well tested.

## Development

```bash
go test ./...                      # unit tests
go test -tags e2e ./internal/e2e/  # needs trivy + network
```

The `e2e` suite scans real public images and asserts structural properties of
the attribution, so it is excluded from the default test run.

## License

MIT — see [LICENSE](LICENSE).
