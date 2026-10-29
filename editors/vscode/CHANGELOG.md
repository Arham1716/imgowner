# Changelog

## 0.1.1

- Fixed: every command (attribute, pins check, pins update) always passed
  `--config .imgowner.yaml` to the CLI, even when no such file existed.
  imgowner treats an explicitly-named `--config` as required to exist (a
  typo'd path must not be silently ignored), so this failed in any workspace
  without a committed config file -- the common case. `--config` is now only
  passed when the file exists, unless `imgowner.configPath` was explicitly
  set, in which case a missing file still errors loudly as before.

## 0.1.0

Initial release.

- Inline diagnostics for attributed CVEs and stale pinned package versions
- Combined hover for every finding on a line
- Findings sidebar grouped by owner and pin status
- Status bar count of actionable issues for the open Dockerfile
- Commands: attribute CVEs, check pins, update pins, set image reference, refresh
