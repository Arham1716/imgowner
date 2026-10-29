# imgowner for VS Code

See which container vulnerabilities your team actually owns — right in your
Dockerfile.

A scanner tells you an image has 200+ CVEs. Most of them came with the base
image and aren't yours to fix. This extension runs
[imgowner](https://github.com/Arham1716/imgowner) and shows you the ones that
are: CVEs introduced by your own `apt-get install` lines and app dependencies
are underlined on the line that added them, and stale pinned package versions
are flagged on the exact version string.

## Features

- **Inline diagnostics** — CVEs on the `RUN` line that introduced them, with a
  link to the NVD entry; stale or missing pinned versions underlined on the
  version token itself.
- **Hover details** — every finding on a line in one tooltip: owner, installed
  and fixed versions, and a one-click link to update pins.
- **Findings sidebar** — CVEs grouped by owner (`added-os`, `app`,
  `unattributed`, `base`) and pins grouped by status. Click any item to jump to
  its line.
- **Status bar** — the number of issues that are actually actionable for the
  open Dockerfile. Base-image CVEs are counted separately, since you fix those
  by changing the `FROM` line, not your own code.
- **Pin updates** — rewrite stale `pkg=version` pins in place without touching
  the rest of the file.

## Installation

This extension isn't on the VS Code Marketplace yet — install it from the
`.vsix` attached to each [GitHub release](https://github.com/Arham1716/imgowner/releases),
signed the same way as every other release artifact (see
[Verifying a release](https://github.com/Arham1716/imgowner#verifying-a-release)).

1. Download `imgowner-vscode_X.Y.Z.vsix` from the latest release.
2. Install it:
   ```sh
   code --install-extension imgowner-vscode_X.Y.Z.vsix
   ```
   or, from VS Code: Extensions view → `...` menu → **Install from VSIX...**.
3. Update the same way when a new release ships — reinstalling with `--force`
   overwrites the old version.

## Requirements

The extension drives the `imgowner` CLI; it doesn't bundle it.

1. **imgowner** — download a binary from the
   [releases page](https://github.com/Arham1716/imgowner/releases), or
   `go install github.com/Arham1716/imgowner/cmd/imgowner@latest`.
2. **Trivy ≥ 0.76.0** on `PATH` — imgowner uses it for the scan itself.
3. **Docker or Podman** — only for the pin commands, which query each image's
   package manager for available versions.

If `imgowner` isn't on `PATH`, set `imgowner.binaryPath`.

## Usage

Open a Dockerfile, then from the Command Palette:

| Command | What it does |
|---|---|
| `imgowner: Attribute CVEs for Current Dockerfile` | Scans the image and attributes each CVE to an owner |
| `imgowner: Check Pinned Package Versions` | Flags pins with newer or missing versions |
| `imgowner: Update Pinned Package Versions` | Rewrites stale pins in the file |
| `imgowner: Set Image Reference for This Workspace` | Sets which image to scan |
| `imgowner: Refresh` | Re-runs whatever has already been run for this file |

CVE attribution scans a **built image**, so it needs to know which one —
for example `myapp:latest`. You're asked the first time and it's saved to the
workspace's `imgowner.image` setting. Re-run attribution after rebuilding the
image; it doesn't run on save, because the image on disk wouldn't have changed.

Pin checks do run on save (`imgowner.autoRunOnSave`), since they only read the
Dockerfile. Pin squiggles disappear while you type and come back on save,
because any edit can shift the position they're anchored to.

## Settings

| Setting | Default | Description |
|---|---|---|
| `imgowner.binaryPath` | `imgowner` | Path to the CLI binary |
| `imgowner.image` | *(empty)* | Image to scan for CVE attribution |
| `imgowner.configPath` | `.imgowner.yaml` | CLI config file, relative to the workspace root |
| `imgowner.autoRunOnSave` | `true` | Re-check pins when a Dockerfile is saved |

## When findings show as "unattributed"

imgowner tells base-image layers apart from yours by checking that the base
image's layers are an exact prefix of the scanned image's. If the `FROM` tag
has moved since the image was built, that check fails and imgowner reports
every finding as `unattributed` rather than guess and blame the wrong team.
The reason is written to the **imgowner** Output panel. Rebuilding the image
against the current base usually resolves it.

## Feedback

Issues and feature requests:
[github.com/Arham1716/imgowner/issues](https://github.com/Arham1716/imgowner/issues).
Security reports: see
[SECURITY.md](https://github.com/Arham1716/imgowner/blob/main/SECURITY.md).
