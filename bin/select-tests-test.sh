#!/usr/bin/env bash
# proves: REQ-CI-001-AC3
# bin/select-tests.sh BASE HEAD prints the suite commands a change needs, from the committed map .github/policy/test-paths.json
# ({"entries": [{"paths": [bash case patterns, * matches slashes], "suites": [shell command strings]}]}). Judged here offline in throwaway
# git repositories that hold a copy of the script and a map written by this test: the commands come one per line in the map's order
# without repeats; a changed file that matches no entry fails the run (exit 1, the path named); an entry with no suites selects nothing;
# a base or head that is not a commit fails the run. The changed files are those of BASE...HEAD (from the merge base).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
ok() { pass=$((pass+1)); echo "PASS $1"; }
no() { failn=$((failn+1)); echo "FAIL $1 :: $2"; }
g() { git -c user.name=t -c user.email=t@t -c commit.gpgsign=false "$@"; }

if [ -f "$root/bin/select-tests.sh" ]; then ok "bin/select-tests.sh exists"; else no "bin/select-tests.sh exists" "missing"; fi

MAP='{"entries": [
 {"paths": ["tools/*"],               "suites": ["s-tools", "s-shared"]},
 {"paths": ["bin/*"],                 "suites": ["s-bin", "s-shared"]},
 {"paths": ["*.go"],                  "suites": ["s-go", "go test ./... -run '"'"'A|B'"'"' && echo \"done\""]},
 {"paths": ["docs/*", "*.md"],        "suites": []},
 {"paths": ["cfg/[ab].json", "x?.txt"], "suites": ["s-cfg"]}
]}'

# mkrepo NAME: a repository with the script copy and the map committed as its first commit; prints its path
mkrepo() {
  local d="$work/$1"; rm -rf "$d"; mkdir -p "$d/bin" "$d/.github/policy"
  cp "$root/bin/select-tests.sh" "$d/bin/select-tests.sh" 2>/dev/null || :
  printf '%s\n' "${2:-$MAP}" > "$d/.github/policy/test-paths.json"
  ( cd "$d" && git init -q -b main && g add -A && g commit -qm base ) >/dev/null 2>&1
  echo "$d"
}
# change REPO FILE...: one commit on the current branch touching each file (create or rewrite; a name starting with - removes the file)
change() {
  local d="$1"; shift
  ( cd "$d"
    for f in "$@"; do
      case "$f" in
        -*) git rm -q -f -- "${f#-}" ;;
        *) mkdir -p "$(dirname "$f")"; echo "$RANDOM$RANDOM" >> "$f"; git add -- "$f" ;;
      esac
    done
    g commit -qm change ) >/dev/null 2>&1
}
# sel REPO BASE HEAD: sets out (stdout), err, rc
sel() { local rcf="$work/rc"; ( cd "$1" && bash bin/select-tests.sh "$2" "$3" >"$work/out" 2>"$work/err"; echo $? >"$rcf" ) || :; out=$(cat "$work/out"); err=$(cat "$work/err"); rc=$(cat "$rcf"); }
expect() {   # expect NAME WANT_RC WANT_OUT   (WANT_OUT compared to stdout exactly)
  if [ "$rc" = "$2" ] && [ "$out" = "$3" ]; then ok "$1"; else no "$1" "rc=$rc want $2; out=[$out] want [$3]; err=[$err]"; fi
}
nl=$'\n'

# a fresh repo with a change of the given files on top of the base; BASE is the first commit, HEAD the second
run_change() {  # run_change NAME FILE...  -> sets out/err/rc
  local n="$1"; shift
  local d; d=$(mkrepo "$n")
  local b; b=$(cd "$d" && git rev-parse HEAD)
  change "$d" "$@"
  sel "$d" "$b" "$(cd "$d" && git rev-parse HEAD)"
}

run_change one-entry tools/a.sh
expect "one changed file: the suites of its entry, one per line" 0 "s-tools${nl}s-shared"

run_change order bin/x.sh tools/y.sh
expect "the map's order, not the file order (tools is listed first in the map, bin sorts first in the diff), and no repeats (s-shared once)" 0 "s-tools${nl}s-shared${nl}s-bin"

run_change overlap bin/z.go
expect "a file matching two entries selects both, in map order, without repeats" 0 "s-bin${nl}s-shared${nl}s-go${nl}go test ./... -run 'A|B' && echo \"done\""

run_change same-entry-twice tools/a.sh tools/b.sh
expect "two files of one entry select its suites once" 0 "s-tools${nl}s-shared"

run_change slashes tools/deep/er/file.txt
expect "* matches slashes: a file deep under tools/ matches tools/*" 0 "s-tools${nl}s-shared"

run_change spaces "tools/a b.txt"
expect "a path with a space is one path" 0 "s-tools${nl}s-shared"

run_change class cfg/a.json
expect "a bash case pattern with a character class matches" 0 "s-cfg"
run_change qmark xz.txt
expect "a bash case pattern with ? matches one character" 0 "s-cfg"

run_change docs-only docs/readme.txt README.md
expect "an entry with no suites selects nothing and the run still passes (exit 0, no output)" 0 ""

run_change docs-and-code docs/readme.txt tools/a.sh
expect "a covered-by-no-suite file next to a code file selects only the code file's suites" 0 "s-tools${nl}s-shared"

run_change deleted-first tools/gone.sh
d="$work/deleted-first"; b=$(cd "$d" && git rev-parse HEAD)
change "$d" -tools/gone.sh
sel "$d" "$b" "$(cd "$d" && git rev-parse HEAD)"
expect "a deleted file counts as changed and matches its entry" 0 "s-tools${nl}s-shared"

# a rename counts as both its old path and its new path (BASE...HEAD, so the old path must not be dropped by rename detection)
rename_change() {  # rename_change NAME OLD NEW -> sets out/err/rc; OLD is committed in the base, renamed to NEW in the head
  local d; d=$(mkrepo "$1"); mkdir -p "$d/$(dirname "$2")"; seq 1 40 > "$d/$2"
  ( cd "$d" && git add -- "$2" && g commit -qm old ) >/dev/null 2>&1
  local b; b=$(cd "$d" && git rev-parse HEAD)
  ( cd "$d" && mkdir -p "$(dirname "$3")" && git mv "$2" "$3" && g commit -qm rename ) >/dev/null 2>&1
  sel "$d" "$b" "$(cd "$d" && git rev-parse HEAD)"
}
rename_change rename-across tools/a.sh bin/a.sh
expect "a rename from a path of one entry to a path of another selects the suites of both, in map order, without repeats" 0 "s-tools${nl}s-shared${nl}s-bin"
rename_change rename-to-other-suites cfg/a.json tools/a.json
expect "a rename from the cfg entry to the tools entry selects the suites of both, in map order" 0 "s-tools${nl}s-shared${nl}s-cfg"
rename_change rename-to-no-suite tools/a.sh docs/a.txt
expect "a rename from a path with suites to a path whose entry has none still selects the old path's suites" 0 "s-tools${nl}s-shared"
rename_change rename-inside tools/a.sh tools/b.sh
expect "a rename inside one entry selects that entry once, no repeat" 0 "s-tools${nl}s-shared"

run_change unmatched newdir/f.txt
if [ "$rc" = 1 ] && printf '%s\n%s' "$out" "$err" | grep -qF "newdir/f.txt"; then ok "a changed file that matches no entry: exit 1 naming the path"; else no "unmatched path" "rc=$rc out=[$out] err=[$err]"; fi

run_change unmatched-with-match tools/a.sh newdir/f.txt
if [ "$rc" = 1 ] && printf '%s\n%s' "$out" "$err" | grep -qF "newdir/f.txt"; then ok "an unmatched file fails the run even when another file matches"; else no "unmatched next to matched" "rc=$rc out=[$out] err=[$err]"; fi

run_change unmatched-class cfg/c.json
if [ "$rc" = 1 ] && printf '%s\n%s' "$out" "$err" | grep -qF "cfg/c.json"; then ok "a path the entry's class pattern does not match is unmatched"; else no "class unmatched" "rc=$rc out=[$out] err=[$err]"; fi

run_change unmatched-two "zzz/one.txt" "zzz/two.txt"
if [ "$rc" = 1 ] && printf '%s\n%s' "$out" "$err" | grep -qF "zzz/one.txt"; then ok "several unmatched files: exit 1 naming the first"; else no "two unmatched" "rc=$rc out=[$out] err=[$err]"; fi

# no change
d=$(mkrepo nochange); b=$(cd "$d" && git rev-parse HEAD); sel "$d" "$b" "$b"
expect "base equal to head: nothing changed, nothing selected, exit 0" 0 ""

# BASE...HEAD: the files changed on the head's side since the merge base only
d=$(mkrepo threedots); c0=$(cd "$d" && git rev-parse HEAD)
( cd "$d" && git checkout -q -b feature ) >/dev/null 2>&1; change "$d" bin/f.sh; feat=$(cd "$d" && git rev-parse HEAD)
( cd "$d" && git checkout -q main ) >/dev/null 2>&1; change "$d" tools/m.sh; mainc=$(cd "$d" && git rev-parse HEAD)
sel "$d" "$mainc" "$feat"
expect "the changed files are those of BASE...HEAD (from the merge base): a later change on the base side is not selected" 0 "s-bin${nl}s-shared"

# a base or head that is not a commit
d=$(mkrepo badrefs); b=$(cd "$d" && git rev-parse HEAD); change "$d" tools/a.sh; h=$(cd "$d" && git rev-parse HEAD)
bad_ok() {  # bad_ok NAME BASE HEAD
  sel "$d" "$2" "$3"
  if [ "$rc" = 1 ] && [ -z "$out" ]; then ok "$1: exit 1, nothing selected"; else no "$1" "rc=$rc out=[$out] err=[$err]"; fi
}
bad_ok "a base that is not a revision" "no-such-ref" "$h"
bad_ok "a head that is not a revision" "$b" "no-such-ref"
bad_ok "a head that is a tree, not a commit" "$b" "$(cd "$d" && git rev-parse "$h^{tree}")"
bad_ok "a base that is a tree, not a commit" "$(cd "$d" && git rev-parse "$b^{tree}")" "$h"
bad_ok "a base that is a blob" "$(cd "$d" && git rev-parse "$h:.github/policy/test-paths.json")" "$h"
bad_ok "an empty base" "" "$h"
bad_ok "an empty head" "$b" ""
bad_ok "an unrelated unknown sha" "0000000000000000000000000000000000000001" "$h"
# the happy path of the same repository, so the refusals above are not a script that always fails
sel "$d" "$b" "$h"; expect "the same repository with good commits selects" 0 "s-tools${nl}s-shared"

echo "select-tests: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
