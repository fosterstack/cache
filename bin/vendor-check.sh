#!/usr/bin/env bash
# The vendored tree is what CI regenerates (REQ-VEND-001-AC2): go mod verify, then go mod vendor in a scratch copy of the tree, then a
# byte-for-byte comparison of the committed vendor/ with the regenerated one, then a mode check (every vendored file mode 100644, no
# link, no special file).
#
#   bin/vendor-check.sh [ROOT]      ROOT defaults to the current directory (the repository root); run it from there
#
# Exit codes: 0 identical (or the narrow no-vendor case below) | 1 a difference is named, or the check could not be completed (no go
# toolchain, a failed go mod verify or go mod vendor, a base that cannot be read) | 2 refused: not run from the repository root, an
# unknown argument, an unreadable tree, a vendor path that is not a vendor/ directory at the top, or a tree without go.mod, go.sum or
# vendor/. It writes nothing but its scratch directory, and it only compares: no token, no commit. The Go environment (GOPROXY,
# GOFLAGS, GOSUMDB) is the caller's, so a CI run uses the checksum database and a fixture run uses a file proxy.
#
# The one pass without a comparison: vendor/ is absent from the tree AND absent from origin/main (no path with a vendor component),
# and the tree holds no vendor path anywhere. Any other tree is judged in full or fails.
set -uo pipefail

die() { echo "vendor-check.sh: $1" >&2; exit "${2:-2}"; }

[ -f bin/vendor-check.sh ] || die "run it from the repository root"
[ $# -le 1 ] || die "usage: bin/vendor-check.sh [ROOT]"
src=${1:-.}
case $src in -*) die "unknown argument $src";; esac
[ -d "$src" ] && [ -r "$src" ] || die "the tree $src is not a readable directory"

if [ ! -d "$src/vendor" ] || [ -L "$src/vendor" ]; then
  command -v find >/dev/null 2>&1 && command -v git >/dev/null 2>&1 || die "find and git are required to judge a tree without vendor/" 1
  found=$(find "$src" -name .git -prune -o -name vendor -print 2>/dev/null | head -n 1)
  [ -z "$found" ] || die "a vendor path that is not a vendor/ directory at the top of the tree: $found"
  git -C "$src" rev-parse --git-dir >/dev/null 2>&1 || die "no vendor/ here, and $src is not a git tree to read origin/main from" 1
  git -C "$src" rev-parse --verify --quiet "origin/main^{commit}" >/dev/null 2>&1 || die "no vendor/ here, and origin/main cannot be read" 1
  base=$(git -C "$src" ls-tree -r --name-only origin/main 2>/dev/null) || die "origin/main cannot be listed" 1
  hit=$(printf '%s\n' "$base" | grep -E '(^|/)vendor(/|$)' | head -n 1)
  [ -z "$hit" ] || die "vendor/ is on origin/main ($hit) but not in this tree" 1
  echo "vendor-check: no vendor/ in this tree and none on origin/main"
  exit 0
fi

[ -f "$src/go.mod" ] && [ -f "$src/go.sum" ] || die "$src holds no go.mod and go.sum next to vendor/"
command -v go >/dev/null 2>&1 || die "go toolchain not found: the vendored tree cannot be regenerated" 1
command -v find diff cp mktemp rm head >/dev/null 2>&1 || die "a required tool (find, diff, cp, mktemp, rm, head) is not found" 1

odd=$(find "$src/vendor" ! -type f ! -type d -print 2>/dev/null | head -n 1)
[ -z "$odd" ] || die "vendor/ holds a link or a special file: $odd" 1
modeodd=$(find "$src/vendor" -type f \( -perm -u+x -o -perm -g+x -o -perm -o+x \) -print 2>/dev/null | head -n 1)
[ -z "$modeodd" ] || die "vendor/ holds a file whose mode is not 100644 (mode): $modeodd" 1

tmp=$(mktemp -d) || die "no scratch directory" 1
cleanup() { local rc=$?; set +e; chmod -R u+w "$tmp" 2>/dev/null; rm -rf "$tmp"; exit $rc; }
trap cleanup EXIT

cp -R "$src/." "$tmp/" || die "cannot copy $src" 1
rm -rf "$tmp/vendor" "$tmp/.git"
( cd "$tmp" && go mod verify ) >"$tmp.verify.log" 2>&1 || { cat "$tmp.verify.log" >&2; rm -f "$tmp.verify.log"; die "go mod verify failed" 1; }
rm -f "$tmp.verify.log"
( cd "$tmp" && go mod vendor ) >"$tmp.vendor.log" 2>&1 || { cat "$tmp.vendor.log" >&2; rm -f "$tmp.vendor.log"; die "go mod vendor failed" 1; }
rm -f "$tmp.vendor.log"

if diff -rq "$src/vendor" "$tmp/vendor" >"$tmp.diff" 2>&1; then
  rm -f "$tmp.diff"
  echo "vendor-check: vendor/ is what go mod vendor regenerates"
  exit 0
fi
first=$(head -n 1 "$tmp.diff"); rm -f "$tmp.diff"
die "vendor/ differs from the regenerated tree: $first" 1
