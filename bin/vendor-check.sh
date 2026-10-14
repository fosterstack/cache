#!/usr/bin/env bash
# The vendored tree is what CI regenerates (REQ-VEND-001-AC2): go mod verify, then go mod vendor in a scratch copy of the tree, then a
# byte-for-byte comparison of the committed vendor/ with the regenerated one, a mode check (every vendored file mode 100644, no link, no
# special file), a path check (no dot component) and a check that go mod vendor left go.mod and go.sum as they were committed.
#
#   bin/vendor-check.sh [ROOT]      ROOT defaults to the current directory (the repository root); run it from there
#
# Exit codes: 0 identical (or the narrow no-vendor case below) | 1 a difference is named, or the check could not be completed (no go
# toolchain, a failed go mod verify or go mod vendor, a tree or a base that cannot be read in full) | 2 refused: not run from the
# repository root, an unknown argument, an unreadable tree, a go.mod or go.sum that is a link, a vendor path that is not a vendor/ directory at the top, or a tree without
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
  git -C "$src" rev-parse --verify --quiet "origin/main^{commit}" >/dev/null 2>&1 || die "no vendor/ here, and origin/main cannot be read" 1
  scratch=$(mktemp -d) || die "no scratch directory" 1
  git -C "$src" ls-tree -r -z --full-tree --name-only origin/main >"$scratch/base.z" 2>/dev/null || die "origin/main cannot be listed" 1
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
command -v find diff cmp tar mktemp rm head >/dev/null 2>&1 || die "a required tool (find, diff, cmp, tar, mktemp, rm, head) is not found" 1

odd=$(find "$src/vendor" ! -type f ! -type d -print -quit)
[ $? -eq 0 ] || die "vendor/ could not be listed in full" 1
[ -z "$odd" ] || die "vendor/ holds a link or a special file: $odd" 1
dotted=$(find "$src/vendor" -name '.*' -print -quit)
[ $? -eq 0 ] || die "vendor/ could not be listed in full" 1
[ -z "$dotted" ] || die "vendor/ holds a path with a dot component: $dotted" 1
modeodd=$(find "$src/vendor" -type f ! -perm 644 -print -quit)
[ $? -eq 0 ] || die "vendor/ could not be listed in full" 1
[ -z "$modeodd" ] || die "vendor/ holds a file whose mode is not 100644 (mode): $modeodd" 1

scratch=$(mktemp -d) || die "no scratch directory" 1
tree="$scratch/tree"; mkdir "$tree" || die "no scratch tree" 1
( cd "$src" && tar -cf - --exclude=./.git --exclude=./vendor . ) | ( cd "$tree" && tar -xf - ) || die "cannot copy $src" 1
( cd "$tree" && GOAUTH=off go mod verify ) >"$scratch/verify.log" 2>&1 || { cat "$scratch/verify.log" >&2; die "go mod verify failed" 1; }
( umask 022; export GOAUTH=off; cd "$tree" && go mod vendor ) >"$scratch/vendor.log" 2>&1 || { cat "$scratch/vendor.log" >&2; die "go mod vendor failed" 1; }
cmp -s "$src/go.mod" "$tree/go.mod" || die "go mod vendor changed go.mod: the committed go.mod is not what the vendored tree was made from" 1
cmp -s "$src/go.sum" "$tree/go.sum" || die "go mod vendor changed go.sum: the committed go.sum is not what the vendored tree was made from" 1

regenodd=$(find "$tree/vendor" -type f ! -perm 644 -print -quit)
[ $? -eq 0 ] || die "the regenerated vendor/ could not be listed in full" 1
[ -z "$regenodd" ] || die "the regenerated vendor/ holds a file whose mode is not 100644 (mode): $regenodd" 1

if diff -rq "$src/vendor" "$tree/vendor" >"$scratch/diff.txt" 2>&1; then
  echo "vendor-check: vendor/ is what go mod vendor regenerates"
  exit 0
fi
first=$(head -n 1 "$scratch/diff.txt")
die "vendor/ differs from the regenerated tree: $first" 1
