#!/usr/bin/env bash
# NFR-18 for the VS Code extension: the .vsix may hold only the compiled
# extension, its manifest, docs, licence and icon -- no TypeScript source,
# node_modules, tests, source maps or CI files.
#
# Usage: check-vsix-contents.sh <file.vsix>
set -euo pipefail

vsix="$1"
fail=0

is_allowed() {
  case "$1" in
    "extension.vsixmanifest" | "[Content_Types].xml") return 0 ;;
    extension/package.json | extension/readme.md | extension/changelog.md | extension/LICENSE.txt) return 0 ;;
    extension/out/*.js) return 0 ;;
    extension/resources/*.svg | extension/resources/*.png) return 0 ;;
    *) return 1 ;;
  esac
}

echo "checking $vsix"
while IFS= read -r entry; do
  [ -z "$entry" ] && continue
  [[ "$entry" == */ ]] && continue
  if ! is_allowed "$entry"; then
    echo "::error::$vsix contains disallowed file: $entry"
    fail=1
  fi
done < <(unzip -Z1 "$vsix")

if [ "$fail" -ne 0 ]; then
  echo "::error::extension content check failed; release stays draft"
  exit 1
fi
echo "the extension package contains only allowed files"
