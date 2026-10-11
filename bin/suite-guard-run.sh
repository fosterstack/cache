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
  local floors=$1 name=$2 path=$3 log rc=0 n
  [ -s "$path" ] || die "suite $name: $path is empty or missing"
  log=$(mktemp); trap 'rm -f "$log"' RETURN
  bash "$path" < /dev/null > "$log" 2>&1 || rc=$?
  n=$(bash "$guard" count "$log" 2>&1) || die "suite $name: $n (rc=$rc)"
  bash "$guard" floor "$floors" "$name" "$n" > /dev/null
  echo "suite-guard: $name: count $n rc=$rc"
  [ "$only" = 1 ] || [ "$rc" = 0 ] || die "suite $name exited $rc"
}
cmd_all() { # all [--count-only] FLOORS [ROOT]: runs every suite the floors file names (keys are file names, each found exactly once under ROOT); fails if any fails its guard
  local only=() ; [ "${1:-}" != --count-only ] || { only=(--count-only); shift; }
  local floors=$1 root=${2:-.} bad=0 s
  while IFS= read -r s; do
    local found=(); mapfile -t found < <(find "$root" -type f -name "$s" -not -path '*/.git/*')
    [ "${#found[@]}" = 1 ] || { echo "suite-guard: the floors file names $s, which is ${#found[@]} files under $root (it must be exactly one)" >&2; bad=1; continue; }
    ( cmd_run ${only[@]+"${only[@]}"} "$floors" "$s" "${found[0]}" ) || bad=1
  done < <(python3 - "$floors" <<'PY'
import json, sys
print("\n".join(json.load(open(sys.argv[1]))))
PY
)
  [ "$bad" = 0 ] || exit 1
}
sub=${1:-}; shift || true
case "$sub" in
  run) cmd_run "$@" ;;
  all) cmd_all "$@" ;;
  *) echo "usage: suite-guard-run.sh run [--count-only] FLOORS SUITE PATH | all [--count-only] FLOORS [ROOT]" >&2; exit 2 ;;
esac
