#!/usr/bin/env bash
# NFR-16: rebuilding a tag must yield a byte-identical binary. Rebuilds the
# linux/amd64 binary from the checked-out tag with exactly the flags
# .goreleaser.yml uses, and compares its SHA-256 with the binary goreleaser
# just built (or any binary passed as $2).
#
# Usage: verify-reproducible.sh <version-without-v> [built-binary]
set -euo pipefail

version="$1"
built="${2:-dist/imgowner_linux_amd64_v1/imgowner}"
commit="$(git rev-parse HEAD)"
# goreleaser's {{.CommitDate}}: the commit time in UTC, RFC 3339, with a Z.
commit_date="$(TZ=UTC git log -1 --format=%cd --date=format-local:'%Y-%m-%dT%H:%M:%SZ' HEAD)"

out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false \
  -ldflags "-s -w -X main.version=${version} -X main.commit=${commit} -X main.date=${commit_date}" \
  -o "$out/imgowner" ./cmd/imgowner

want="$(sha256sum "$built" | cut -d' ' -f1)"
got="$(sha256sum "$out/imgowner" | cut -d' ' -f1)"
if [ "$want" != "$got" ]; then
  echo "::error::rebuilding v${version} produced a different binary (built ${want}, rebuilt ${got}); the build is not reproducible"
  exit 1
fi
echo "reproducible: rebuilt v${version} is byte-identical (sha256 ${got})"
