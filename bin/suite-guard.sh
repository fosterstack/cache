#!/usr/bin/env bash
# bin/suite-guard.sh: the guard against test suites that prove nothing. Self-contained (bash, git, python3); no dependency on the release chain.
#   files [ROOT]                          no TRACKED test file (bin/*-test.*, test_*, *_test.*, anything under a tests/ directory) is zero bytes or whitespace-only
#   count LOG                             prints the case count a suite's log carries (`pass=N`, `N passed`, `passed: N`, `Ran N tests`, `N killed`, else the
#                                         number of ok/PASS lines); none, or zero, fails
#   floor FLOORS SUITE N                  N must be at least the committed floor of SUITE (an unlisted suite, or a floor below 1, fails)
#   (run and all, which execute suites, are bin/suite-guard-run.py)
#   floors-vs-base [--allow-lowered A,B | --allow-from-body] REF FLOORS   FLOORS (a path in the working tree) may not lower or drop a floor the file at REF
#                                         holds, unless the suite is named in --allow-lowered (the PR body names it); no file at REF: passes. A dropped suite
#                                         always fails. A named suite must be one whose floor is lowered. --allow-from-body reads the environment variable
#                                         PR_BODY (the pull request's body, passed by ci.yml through env) and takes the rest of its first line that starts exactly
#                                         with "Lowered floors: " (carriage returns removed): the suites' file names, comma-separated, as written in the floors file.
#                                         The ok line names each lowering.
# Why: a script committed as an empty file exits 0, so "rc 0" proved nothing (release chain PR 3, bin/check-file-allowlist-test.sh).
set -euo pipefail
die() { echo "suite-guard: $*" >&2; exit 1; }
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
count_of() { # prints the count or nothing: an explicit summary first, else the number of ok/PASS lines
  local n
  n=$(sed -n -E 's/.*pass=([0-9]+).*/\1/p; s/.*[^0-9]([0-9]+) passed.*/\1/p; s/^([0-9]+) passed.*/\1/p; s/.*passed: ([0-9]+).*/\1/p; s/^Ran ([0-9]+) tests?.*/\1/p; s/.*[^0-9]([0-9]+) killed.*/\1/p' "$1" | tail -1)
  if [ -z "$n" ]; then
    n=$(grep -c -E '^(ok|PASS)([: ]|$)' "$1" || true)
    [ "$n" != 0 ] || n=""
  fi
  printf '%s' "$n"
}
cmd_count() {
  local n; n=$(count_of "$1")
  [ -n "$n" ] || die "no case count in $1 (a suite must print pass=N or N passed)"
  [ "$n" -gt 0 ] || die "the case count in $1 is zero"
  echo "$n"
}
floor_of() { python3 - "$1" "$2" <<'PY'
import json, sys
def hook(pairs):
    d = {}
    for k, v in pairs:
        if k in d: print("duplicate key %s" % k); sys.exit(3)
        d[k] = v
    return d
try:
    d = json.load(open(sys.argv[1]), object_pairs_hook=hook)
except (OSError, ValueError) as e:
    print("unreadable floors file: %s" % e); sys.exit(3)
if not all(isinstance(v, int) and not isinstance(v, bool) and v >= 1 for v in d.values()):
    print("floor must be an integer of at least 1"); sys.exit(3)
if sys.argv[2] not in d: sys.exit(4)
print(d[sys.argv[2]])
PY
}
cmd_floor() {
  local f rc=0; f=$(floor_of "$1" "$2") || rc=$?
  case "$rc" in 0) ;; 4) die "no floor for suite $2 in $1 (add it to the floors file in the same PR)" ;; *) die "$1: $f" ;; esac
  [ "$3" -ge "$f" ] || die "suite $2 printed $3 cases, below its floor of $f"
  echo "ok $2 $3 >= $f"
}
lowered_from_body() { # the rest of the first line of $PR_BODY that starts exactly "Lowered floors: " (carriage returns removed), or nothing
  printf '%s\n' "${PR_BODY:-}" | tr -d '\r' | sed -n 's/^Lowered floors: //p' | head -n 1
}
cmd_vs_base() {
  local allow=""
  case "${1:-}" in
    --allow-lowered) allow=${2-}; shift 2 ;;
    --allow-from-body) allow=$(lowered_from_body); shift ;;
  esac
  local ref=$1 file=$2 old
  # An absent file at a base that can be read is the first PR that adds it; a base that cannot be read (no such revision, an empty or odd name) or a floors
  # file there that cannot be read is NOT "no floors file": the guard fails closed (a floors check that silently passes is no check).
  [ -n "$ref" ] && git rev-parse --verify --quiet "$ref^{commit}" > /dev/null 2>&1 || die "the base revision '$ref' cannot be read: the floors cannot be compared with it"
  if ! git cat-file -e "$ref:$file" 2> /dev/null; then echo "suite-guard: no floors file at $ref: nothing to hold"; return 0; fi
  old=$(git show "$ref:$file" 2> /dev/null) || die "the floors file $file at $ref cannot be read"
  python3 - "$file" "$allow" "$old" <<'PY'
import json, sys
try:
    new = json.load(open(sys.argv[1])); old = json.loads(sys.argv[3])
    if not isinstance(new, dict) or not isinstance(old, dict):
        raise ValueError("a floors file is a JSON object")
except (OSError, ValueError) as e:
    print("suite-guard: the floors file or its base version cannot be read as JSON (%s)" % e, file=sys.stderr); sys.exit(1)
allow = set(x.strip() for x in sys.argv[2].split(",") if x.strip())
bad, lowered = [], []
for k, v in old.items():
    if k not in new: bad.append("%s was dropped (floor %s)" % (k, v))
    elif new[k] < v and k not in allow: bad.append("%s was lowered from %s to %s and the PR does not name it" % (k, v, new[k]))
    elif new[k] < v: lowered.append("%s %s->%s" % (k, v, new[k]))
for k in sorted(allow):
    if not (k in old and k in new and new[k] < old[k]): bad.append("%s is named as lowered but its floor is not lowered" % k)
if bad:
    print("suite-guard: floors may only rise: " + "; ".join(bad), file=sys.stderr); sys.exit(1)
print("ok floors did not fall" + (" except the named: " + ", ".join(lowered) if lowered else ""))
PY
}
sub=${1:-}; shift || true
case "$sub" in
  files) cmd_files "$@" ;;
  count) cmd_count "$@" ;;
  floor) cmd_floor "$@" ;;
  floors-vs-base) cmd_vs_base "$@" ;;
  *) echo "usage: suite-guard.sh files [ROOT] | count LOG | floor FLOORS SUITE N | floors-vs-base [--allow-lowered A,B] REF FLOORS" >&2; exit 2 ;;
esac
