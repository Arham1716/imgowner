#!/usr/bin/env bash
# Download a release tarball, verify it against a SHA-256 pinned in the
# workflow, and install one binary from it. Pinning the hash here (rather than
# trusting a checksums file fetched from the same release) means a tampered
# or replaced release asset fails the job instead of running in CI.
#
# Usage: fetch-verified.sh <url> <sha256> <binary-name> <dest-dir>
set -euo pipefail

url="$1"
want="$2"
binary="$3"
dest="$4"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

curl -fsSL --retry 3 -o "$work/archive.tar.gz" "$url"
got="$(sha256sum "$work/archive.tar.gz" | cut -d' ' -f1)"
if [ "$got" != "$want" ]; then
  echo "::error::checksum mismatch for $url (got $got, want $want)"
  exit 1
fi

tar -xzf "$work/archive.tar.gz" -C "$work" "$binary"
install -m 0755 "$work/$binary" "$dest/$binary"
echo "installed $binary from $url (sha256 $got)"
