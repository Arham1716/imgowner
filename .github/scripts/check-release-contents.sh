#!/usr/bin/env bash
# NFR-18: a shipped archive may contain only product code and its runtime
# dependencies -- no CI workflows, test code, fixtures, dev dependencies or
# frontend source. Fails the release (which stays draft; see release.yml) if
# any archive in dist/ contains anything outside this allowlist.
set -euo pipefail

dist="${1:-dist}"
fail=0

is_allowed() {
  case "$1" in
    imgowner|imgowner.exe) return 0 ;;
    LICENSE) return 0 ;;
    examples/*) return 0 ;; # user-facing samples, not test fixtures (requirements §5)
    *) return 1 ;;
  esac
}

for archive in "$dist"/*.tar.gz "$dist"/*.zip; do
  [ -e "$archive" ] || continue
  echo "checking $archive"

  if [[ "$archive" == *.tar.gz ]]; then
    entries=$(tar -tzf "$archive")
  else
    entries=$(unzip -Z1 "$archive")
  fi

  while IFS= read -r entry; do
    [ -z "$entry" ] && continue
    [[ "$entry" == */ ]] && continue # directory entries are not content
    if ! is_allowed "$entry"; then
      echo "::error::$archive contains disallowed file: $entry"
      fail=1
    fi
  done <<< "$entries"
done

if [ "$fail" -ne 0 ]; then
  echo "::error::release content check failed; release stays draft"
  exit 1
fi
echo "all archives contain only allowed files"
