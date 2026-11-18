#!/usr/bin/env bash
# bin/suite-guard.sh: the guard against test suites that prove nothing. Self-contained (bash, git); no dependency on the release chain.
#   files [ROOT]                          no TRACKED test file (bin/*-test.*, test_*, *_test.*, anything under a tests/ directory) is zero bytes or whitespace-only
# Why: a script committed as an empty file exits 0, so "rc 0" proved nothing (release chain PR 3, bin/check-file-allowlist-test.sh).
set -euo pipefail
case_file() { # is a test file by name: under a tests/ directory, or named *-test.*, test_* or *_test.*
  printf '%s\n' "$1" | grep -Eq '(^|/)tests/|(^|/)test_[^/]*$|-test\.[^/]*$|_test\.[^/]*$'
}
cmd_files() {
  local root=${1:-.} bad=0 f
  while IFS= read -r -d '' f; do
    case_file "$f" || continue
    if [ ! -s "$root/$f" ] || [ -z "$(tr -d ' \t\r\n' < "$root/$f" | head -c 1)" ]; then
      echo "suite-guard: $f is a test file with no content (zero bytes or whitespace only)" >&2; bad=1
    fi
  done < <(git -C "$root" ls-files -z)
  [ "$bad" = 0 ] || exit 1
  echo "suite-guard: every tracked test file has content"
}
sub=${1:-}; shift || true
case "$sub" in
  files) cmd_files "$@" ;;
  *) echo "usage: suite-guard.sh files [ROOT]" >&2; exit 2 ;;
esac
