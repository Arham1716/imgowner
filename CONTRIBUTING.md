# Contributing to imgowner

Thanks for considering a contribution. This project is small and maintained
by one person, so keeping changes focused and well-tested makes review much
faster.

## Before you start

- For a bug fix: open an issue first only if the fix isn't obvious — small,
  clearly-scoped PRs can skip straight to a pull request.
- For a new feature: open an issue first to discuss the approach before
  writing code. This avoids spending time on something that doesn't fit the
  project's scope (see [README.md § Limitations](README.md#limitations) for
  what's intentionally out of scope).
- For a security vulnerability: do **not** open a public issue. See
  [SECURITY.md](SECURITY.md).

## Development setup

```bash
git clone https://github.com/Arham1716/imgowner.git
cd imgowner
go build ./...
go test ./...
```

You'll also need [Trivy](https://github.com/aquasecurity/trivy) ≥ 0.76.0 on
`PATH` to run the full test suite, and Docker or Podman for the `pins`
package's container-based tests.

```bash
go test ./...                      # unit tests, no external dependencies
go test -tags e2e ./internal/e2e/  # scans real images; needs trivy + network
golangci-lint run                  # same linter config CI runs
gofmt -l .                         # must print nothing
```

## Making a change

1. Create a branch: `feature/short-description`, `fix/short-description`, or
   `hotfix/short-description`.
2. Write the code, then write or update tests for it. A PR that changes
   behavior without a test covering that behavior will be asked for one —
   this project has already found multiple real bugs this way, including two
   that silently misattributed CVE ownership.
3. Run `gofmt -w .` and `golangci-lint run` before opening the PR; CI enforces
   both and a dirty formatter or a lint finding will fail the build.
4. Keep commits focused. A commit message should explain *why*, not just
   *what* — the diff already shows what changed.

## Pull request checklist

- [ ] `go build ./...` succeeds
- [ ] `go test ./...` passes
- [ ] `gofmt -l .` prints nothing
- [ ] `golangci-lint run` reports no issues
- [ ] New behavior has a test; a bug fix has a regression test
- [ ] `README.md` is updated if the change affects usage, flags, or config

## Code style

- Idiomatic Go; `gofmt` and `golangci-lint` are the enforced style, not a
  separate style guide.
- Comments explain *why*, not *what* — see the existing codebase for the
  expected level of detail. A comment that just restates the code it sits
  above will be removed in review.
- No speculative abstractions for hypothetical future requirements. Add the
  interface when there are two real implementations, not before.

## Scope

imgowner attributes container CVEs to base image / added-os / app ownership
and keeps pinned OS package versions current. Features that don't serve
either of those two goals — for example, becoming a general-purpose
vulnerability scanner or a full SBOM generator — are likely out of scope.
When in doubt, open an issue and ask before building it.
