#!/usr/bin/env bash
# bin/suite-guard-run.sh: the run-all half of the suite guard (bin/suite-guard.sh holds the checks; this file executes suites, so CI steps that only
# check files and floors do not read it).
#   run [--count-only] FLOORS SUITE PATH   runs `bash PATH` with stdin closed, requires a case count at or above the floor of SUITE, and (unless
#                                          --count-only, for a suite with known reds) a zero exit; prints `suite-guard: SUITE: count N (floor F) rc=R`
#   all [--count-only] FLOORS [ROOT]       runs every suite the floors file names (key = file name, found once under ROOT) through `run`; any failure fails
set -euo pipefail
guard=$(cd "$(dirname "$0")" && pwd)/suite-guard.sh
die() { echo "suite-guard: $*" >&2; exit 1; }
cmd_run() {
  local only=0; [ "${1:-}" != --count-only ] || { only=1; shift; }
  local floors=$1 name=$2 path=$3 log rc=0 n fl
  # Every step returns its failure explicitly: `all` calls this in an `||` context, where `set -e` is off and a bare failing command would be swallowed.
  [ -s "$path" ] || { echo "suite-guard: suite $name: $path is empty or missing" >&2; return 1; }
  log=$(mktemp) || return 1
  bash "$path" < /dev/null > "$log" 2>&1 || rc=$?
  n=$(bash "$guard" count "$log" 2>&1) || { rm -f "$log"; echo "suite-guard: suite $name: $n (rc=$rc)" >&2; return 1; }
  rm -f "$log"
  fl=$(bash "$guard" floor "$floors" "$name" "$n" 2>&1) || { echo "$fl" >&2; return 1; }
  echo "suite-guard: $name: count $n rc=$rc"
  [ "$only" = 1 ] || [ "$rc" = 0 ] || { echo "suite-guard: suite $name exited $rc" >&2; return 1; }
  return 0
}
cmd_all() { # all [--count-only] FLOORS [ROOT]: runs every suite the floors file names (keys are file names, each found exactly once under ROOT); fails if any fails its guard
  local only=() ; [ "${1:-}" != --count-only ] || { only=(--count-only); shift; }
  local floors=$1 root=${2:-.} bad=0 s
  [ -s "$floors" ] || die "the floors file $floors is empty or missing"
  # the suite names are read synchronously: a floors file that is not a non-empty JSON object of integers fails here, before any suite runs
  local names
  names=$(python3 - "$floors" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
if not isinstance(d, dict) or not d or not all(isinstance(v, int) and not isinstance(v, bool) for v in d.values()):
    sys.exit("the floors file is not a non-empty JSON object of integer floors")
print("\n".join(d))
PY
  ) || die "the floors file $floors cannot be read as suite floors"
  while IFS= read -r s; do
    local found=(); mapfile -t found < <(find "$root" -type f -name "$s" -not -path '*/.git/*')
    [ "${#found[@]}" = 1 ] || { echo "suite-guard: the floors file names $s, which is ${#found[@]} files under $root (it must be exactly one)" >&2; bad=1; continue; }
    cmd_run ${only[@]+"${only[@]}"} "$floors" "$s" "${found[0]}" || bad=1
  done <<< "$names"
  [ "$bad" = 0 ] || exit 1
}
sub=${1:-}; shift || true
case "$sub" in
  run) cmd_run "$@" || exit 1 ;;
  all) cmd_all "$@" ;;
  *) echo "usage: suite-guard-run.sh run [--count-only] FLOORS SUITE PATH | all [--count-only] FLOORS [ROOT]" >&2; exit 2 ;;
esac
