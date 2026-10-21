# Security Policy

imgowner is a security tool, so vulnerabilities in it get priority attention.

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Use GitHub's private vulnerability reporting instead:

1. Go to the [Security tab](https://github.com/Arham1716/imgowner/security) of this repository.
2. Click **Report a vulnerability**.
3. Describe the issue, including steps to reproduce and the affected version.

This opens a private advisory visible only to the maintainer until a fix is
ready, so the issue isn't disclosed before it can be patched.

If you're unable to use GitHub's reporting flow, open a regular issue asking
for an alternative contact method — without any vulnerability details in it.

## What counts as a vulnerability here

imgowner's job is to classify CVE ownership and manage OS package pins. The
things most worth reporting privately:

- A case where attribution would **misattribute or silently hide** CVE
  ownership (for example, reporting `base` findings as `added-os`, or
  reporting false confidence after a failed layer check) — this is the most
  serious class of bug for this project, since it causes wrong security
  decisions.
- Shell/command injection through Dockerfile content, image references, or
  config values passed to `trivy`, `docker`/`podman`, or the SCM clients.
- Credential or token handling issues (e.g. a secret ending up in a cache
  file, log line, or report output).

Non-security bugs (crashes, wrong CLI output, missing features) belong in a
normal [GitHub issue](https://github.com/Arham1716/imgowner/issues).

## Supported versions

Only the latest released version is supported. `v0.1.0` is retracted — see
its [release notes](https://github.com/Arham1716/imgowner/releases/tag/v0.1.0)
for why — and should not be used regardless of security status.

| Version | Supported |
|---------|-----------|
| latest  | ✅ |
| v0.1.0  | ❌ retracted |
| older   | ❌ |
