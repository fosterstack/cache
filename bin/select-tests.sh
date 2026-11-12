#!/usr/bin/env bash
# Prints the suite commands a change needs, one per line (REQ-CI-001-AC3).
#   bin/select-tests.sh BASE HEAD
# The changed files are those of BASE...HEAD. .github/policy/test-paths.json maps path patterns (bash case patterns, * matches slashes)
# to suite commands; commands come in the map's order, once each. A changed file that matches no entry fails the run, so a new
# directory needs a map entry; an entry with no suites covers its paths with none.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
for rev in "${1:-}" "${2:-}"; do
  git -C "$root" rev-parse --verify --quiet "${rev}^{commit}" >/dev/null || { echo "select-tests: '${rev}' is not a commit" >&2; exit 1; }
done
files=()
while IFS= read -r -d '' f; do files+=("$f"); done < <(git -C "$root" diff -z --name-only "$1...$2")
paths=() suites=()
while IFS=$'\t' read -r kind idx text; do
  if [ "$kind" = P ]; then paths+=("$idx"$'\t'"$text"); else suites+=("$idx"$'\t'"$text"); fi
done < <(jq -r '.entries | to_entries[] | .key as $i | (.value.paths[] | "P\t\($i)\t\(.)"), (.value.suites[] | "S\t\($i)\t\(.)")' "$root/.github/policy/test-paths.json")
declare -A hit=()
for f in "${files[@]}"; do
  matched=
  for p in "${paths[@]}"; do
    # shellcheck disable=SC2254
    case "$f" in ${p#*$'\t'}) hit[${p%%$'\t'*}]=1; matched=1 ;; esac
  done
  [ -n "$matched" ] || { echo "select-tests: no entry in .github/policy/test-paths.json matches '$f'" >&2; exit 1; }
done
declare -A seen=()
for s in "${suites[@]}"; do
  [ -n "${hit[${s%%$'\t'*}]:-}" ] || continue
  cmd=${s#*$'\t'}
  [ -z "${seen[$cmd]:-}" ] || continue
  seen[$cmd]=1
  printf '%s\n' "$cmd"
done
