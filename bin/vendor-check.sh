#!/usr/bin/env bash
# The vendored tree is what CI regenerates (REQ-VEND-001-AC2): go mod verify, then go mod vendor in a scratch copy of the tree, then a
# byte-for-byte comparison of the committed vendor/ with the regenerated one, a mode check (every vendored file mode 100644, no link, no
# special file), a path check (no dot directory; a dot-named file is allowed exactly when regenerated), a .gitattributes guard, in a git work tree a comparison
# of the index with the regenerated paths, bytes and mode 100644, and a check that go mod vendor left go.mod and go.sum as committed.
#
#   bin/vendor-check.sh [ROOT]      ROOT defaults to the current directory (the repository root); run it from there
#
# Exit codes: 0 identical (or the narrow no-vendor case below) | 1 a difference is named, or the check could not be completed (no go
# toolchain, a failed go mod verify or go mod vendor, a tree or a base that cannot be read in full) | 2 refused: not run from the
# repository root, a GOFLAGS that is not empty or -mod=mod, an unknown argument, an unreadable tree, a go.mod or go.sum that is a link, a vendor path that is not a vendor/ directory at the top, or a tree without
# go.mod, go.sum or vendor/. It writes nothing but its scratch directory and the Go tool's own caches, and it only compares: no token, no commit; GOAUTH is set to off, so the Go tool reads no .netrc and runs no auth command. The Go environment
# (GOPROXY, GOFLAGS, GOSUMDB) is the caller's, so a CI run uses the checksum database and a fixture run uses a file proxy.
#
# The one pass without a comparison: vendor/ is absent from the tree AND absent from origin/main (no path with a vendor component),
# the tree holds no vendor path anywhere, and both listings completed. Any other tree is judged in full or fails.
set -uo pipefail

die() { echo "vendor-check.sh: $1" >&2; exit "${2:-2}"; }

self=${0%/*}; [ "$self" != "$0" ] || self=.
[ -f bin/vendor-check.sh ] && [ "$(cd "$self/.." 2>/dev/null && pwd -P)" = "$(pwd -P)" ] || die "run it from the repository root"
[ $# -le 1 ] || die "usage: bin/vendor-check.sh [ROOT]"
src=${1:-.}
case $src in -*) die "unknown argument $src";; esac
case ${GOFLAGS:-} in
  ""|-mod=mod) ;;
  *) die "GOFLAGS is not empty or -mod=mod: a flag such as -modfile, -overlay or -o would change what is judged or where it is written" ;;
esac
[ -d "$src" ] && [ -r "$src" ] || die "the tree $src is not a readable directory"
src=$(cd "$src" 2>/dev/null && pwd -P) || die "the tree $src cannot be resolved to a physical directory"

scratch=""
cleanup() { local rc=$?; set +e; [ -z "$scratch" ] || { chmod -R u+w "$scratch" 2>/dev/null; rm -rf "$scratch"; }; exit $rc; }
trap cleanup EXIT

if [ ! -d "$src/vendor" ] || [ -L "$src/vendor" ]; then
  command -v find git grep tr head mktemp rm >/dev/null 2>&1 || die "find, git, grep, tr, head and mktemp are required to judge a tree without vendor/" 1
  found=$(find "$src" -name .git -prune -o -name vendor -print -quit)
  [ $? -eq 0 ] || die "the tree $src could not be listed in full" 1
  [ -z "$found" ] || die "a vendor path that is not a vendor/ directory at the top of the tree: $found"
  git -C "$src" rev-parse --git-dir >/dev/null 2>&1 || die "no vendor/ here, and $src is not a git tree to read origin/main from" 1
  top=$(git -C "$src" rev-parse --show-toplevel 2>/dev/null)
  [ "$top" = "$src" ] || die "no vendor/ here, and $src is not the top of its git tree: a subdirectory is never judged as the whole tree"
  basecommit=$(git -C "$src" rev-parse --verify --quiet "refs/remotes/origin/main^{commit}" 2>/dev/null) || die "no vendor/ here, and origin/main cannot be read" 1
  scratch=$(mktemp -d) || die "no scratch directory" 1
  git -C "$src" ls-tree -r -t -z --full-tree --name-only "$basecommit" >"$scratch/base.z" 2>/dev/null || die "origin/main cannot be listed" 1
  tr '\0' '\n' <"$scratch/base.z" >"$scratch/base.txt" || die "origin/main listing cannot be read" 1
  grep -E '(^|/)vendor(/|$)' "$scratch/base.txt" >"$scratch/base.hit"
  case $? in
    0) hit=$(head -n 1 "$scratch/base.hit"); die "vendor/ is on origin/main, as $hit, but not in this tree" 1 ;;
    1) ;;
    *) die "origin/main listing could not be searched" 1 ;;
  esac
  echo "vendor-check: no vendor/ in this tree and none on origin/main"
  exit 0
fi

[ -f "$src/go.mod" ] && [ -f "$src/go.sum" ] || die "$src holds no go.mod and go.sum next to vendor/"
[ ! -L "$src/go.mod" ] && [ ! -L "$src/go.sum" ] || die "go.mod or go.sum is a link: a repair would land in its target and hide from the comparison"
command -v go >/dev/null 2>&1 || die "go toolchain not found: the vendored tree cannot be regenerated" 1
effflags=$(go env GOFLAGS 2>/dev/null) || die "go env GOFLAGS cannot be read" 1
case $effflags in
  ""|-mod=mod) ;;
  *) die "the effective GOFLAGS (environment or go env file) is not empty or -mod=mod: a flag such as -modfile, -overlay or -o would change what is judged or where it is written" ;;
esac
command -v find diff cmp tar mktemp rm head >/dev/null 2>&1 || die "a required tool (find, diff, cmp, tar, mktemp, rm, head) is not found" 1

emptyd=$(find "$src/vendor" -type d -empty -print -quit)
[ $? -eq 0 ] || die "vendor/ could not be listed in full" 1
[ -z "$emptyd" ] || die "vendor/ holds an empty directory: $emptyd" 1
odd=$(find "$src/vendor" ! -type f ! -type d -print -quit)
[ $? -eq 0 ] || die "vendor/ could not be listed in full" 1
[ -z "$odd" ] || die "vendor/ holds a link or a special file: $odd" 1
dotted=$(find "$src/vendor" -type d -name '.*' -print -quit)
[ $? -eq 0 ] || die "vendor/ could not be listed in full" 1
[ -z "$dotted" ] || die "vendor/ holds a dot directory: $dotted" 1
modeodd=$(find "$src/vendor" -type f ! -perm 644 -print -quit)
[ $? -eq 0 ] || die "vendor/ could not be listed in full" 1
[ -z "$modeodd" ] || die "vendor/ holds a file whose mode is not 100644 (mode): $modeodd" 1

# A vendored .gitattributes can change what a checkout or a release archive holds without changing a committed byte. Only plain `text`
# and `eol=lf` pass among the text/eol forms; any other form of a git-acting attribute, a macro, or a line this reader cannot
# tokenize fails closed, naming file:line. Plain ASCII text, at most 1 MB, no NUL byte.
oversize=$(find "$src/vendor" -name .gitattributes -type f -size +1048576c -print -quit)
[ $? -eq 0 ] || die "vendor/ could not be listed in full" 1
[ -z "$oversize" ] || die "$oversize is larger than 1 MB: the .gitattributes reader refuses what it cannot read in full" 1
nbytes=$(find "$src/vendor" -name .gitattributes -type f -exec cat {} + | wc -c) || die "the .gitattributes files could not be read" 1
nplain=$(find "$src/vendor" -name .gitattributes -type f -exec cat {} + | tr -d '\000' | wc -c) || die "the .gitattributes files could not be read" 1
[ "$((nbytes))" -eq "$((nplain))" ] || die "a vendored .gitattributes holds a NUL byte" 1
find "$src/vendor" -name .gitattributes -type f -exec env LC_ALL=C awk '
function fail(msg) { print "vendor-check.sh: " FILENAME ":" FNR ": " msg > "/dev/stderr"; exit 1 }
BEGIN {
  n = split("export-ignore export-subst filter diff merge ident text eol crlf binary working-tree-encoding", names, " ")
  for (k = 1; k <= n; k++) forbidden[names[k]] = 1
}
{
  line = $0
  if (line ~ /[^\11\40-\176]/) fail("a byte the .gitattributes reader does not read (not plain ASCII text)")
  sub(/^[ \t]+/, "", line)
  if (line == "" || substr(line, 1, 1) == "#") next
  if (substr(line, 1, 1) == "[") fail("a macro definition or a line the reader cannot tokenize: " line)
  if (substr(line, 1, 1) == "\"") fail("a quoted pattern, which the reader does not tokenize: " line)
  cnt = split(line, tok, /[ \t]+/)
  for (i = 2; i <= cnt; i++) {
    a = tok[i]
    if (a == "") continue
    v = a
    pre = substr(v, 1, 1)
    if (pre == "-" || pre == "!") v = substr(v, 2); else pre = ""
    name = v; val = ""; hasval = 0
    eq = index(v, "=")
    if (eq > 0) { name = substr(v, 1, eq - 1); val = substr(v, eq + 1); hasval = 1 }
    if (name !~ /^[A-Za-z0-9_.][A-Za-z0-9_.-]*$/) fail("an attribute the reader cannot tokenize: " a)
    if (hasval && (pre != "" || val == "" || val ~ /=/)) fail("an attribute form the reader cannot tokenize: " a)
    if (tolower(name) in forbidden) {
      if (a == "text" || a == "eol=lf") continue
      fail("a git-acting attribute that is not allowed (only text and eol=lf pass): " a)
    }
  }
}' {} + || die "a vendored .gitattributes was refused (see above) or could not be read" 1

scratch=$(mktemp -d) || die "no scratch directory" 1
tree="$scratch/tree"; mkdir "$tree" || die "no scratch tree" 1
( cd "$src" && tar -cf - --exclude=./.git --exclude=./vendor . ) | ( cd "$tree" && tar -xf - ) || die "cannot copy $src" 1
( cd "$tree" && GOAUTH=off go mod verify ) >"$scratch/verify.log" 2>&1 || { cat "$scratch/verify.log" >&2; die "go mod verify failed" 1; }
( umask 022; export GOAUTH=off; cd "$tree" && go mod vendor ) >"$scratch/vendor.log" 2>&1 || { cat "$scratch/vendor.log" >&2; die "go mod vendor failed" 1; }
cmp -s "$src/go.mod" "$tree/go.mod" || die "go mod vendor changed go.mod: the committed go.mod is not what the vendored tree was made from" 1
cmp -s "$src/go.sum" "$tree/go.sum" || die "go mod vendor changed go.sum: the committed go.sum is not what the vendored tree was made from" 1

regenempty=$(find "$tree/vendor" -type d -empty -print -quit)
[ $? -eq 0 ] || die "the regenerated vendor/ could not be listed in full" 1
[ -z "$regenempty" ] || die "the regenerated vendor/ holds an empty directory: $regenempty" 1
regenodd=$(find "$tree/vendor" -type f ! -perm 644 -print -quit)
[ $? -eq 0 ] || die "the regenerated vendor/ could not be listed in full" 1
[ -z "$regenodd" ] || die "the regenerated vendor/ holds a file whose mode is not 100644 (mode): $regenodd" 1

if ! diff -rq "$src/vendor" "$tree/vendor" >"$scratch/diff.txt" 2>&1; then
  first=$(head -n 1 "$scratch/diff.txt")
  die "vendor/ differs from the regenerated tree: $first" 1
fi

# In a git work tree the index is judged as well: the tracked paths under vendor/ are exactly the regenerated paths, each tracked blob is
# the regenerated bytes (hashed without any filter) and every index mode is 100644. A .gitignore that leaves a file untracked, or a
# .gitattributes that would change the checkout's bytes, shows up here. A tree that is not a git work tree keeps the comparison above.
if [ "$(git -C "$src" rev-parse --is-inside-work-tree 2>/dev/null)" = true ]; then
  command -v git paste sort sed tr wc >/dev/null 2>&1 || die "git, paste, sort, sed, tr and wc are required to judge the index" 1
  nnul=$(cd "$tree" && find vendor -type f -print0 | tr -cd '\000' | wc -c) || die "the regenerated paths could not be listed" 1
  nlin=$(cd "$tree" && find vendor -type f -print | wc -l) || die "the regenerated paths could not be listed" 1
  [ "$((nnul))" -eq "$((nlin))" ] || die "a regenerated path holds a newline: the index comparison cannot be made" 1
  ( cd "$tree" && find vendor -type f -print | LC_ALL=C sort ) >"$scratch/paths.txt" || die "the regenerated paths could not be listed" 1
  ( cd "$tree" && git hash-object --no-filters --stdin-paths <"$scratch/paths.txt" ) >"$scratch/hashes.txt" || die "the regenerated files could not be hashed" 1
  sed 's/^/100644 /; s/$/ 0/' "$scratch/hashes.txt" >"$scratch/modes.txt" || die "the regenerated hashes could not be read" 1
  paste -d '\t' "$scratch/modes.txt" "$scratch/paths.txt" | LC_ALL=C sort >"$scratch/regen.idx" || die "the regenerated index lines could not be built" 1
  git -C "$src" ls-files -s -z -- vendor | tr '\000' '\n' | LC_ALL=C sort >"$scratch/tracked.idx" || die "the index could not be listed" 1
  if ! cmp -s "$scratch/regen.idx" "$scratch/tracked.idx"; then
    diff "$scratch/tracked.idx" "$scratch/regen.idx" >"$scratch/idx.diff" 2>&1
    first=$(head -n 1 "$scratch/idx.diff"; sed -n 2p "$scratch/idx.diff")
    die "the git index of vendor/ is not the regenerated tree (tracked paths, blobs or mode 100644): $first" 1
  fi
fi
echo "vendor-check: vendor/ is what go mod vendor regenerates"
exit 0
