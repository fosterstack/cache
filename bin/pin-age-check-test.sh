#!/usr/bin/env bash
# proves: REQ-SUP-001-AC2, REQ-SUP-001-AC3
# The pin age check (owner ratified Oct 5, rule 1; advisor 0172/0175): a pull request that moves an action pin, or the version of a tool, image or
# package a workflow downloads, fails unless that version has been public 7 days by a SERVER-SIDE time. Proved offline: each case builds a small git
# repository (a base commit and a head commit that moves one thing) and runs the real check against a fixtures file that stands in for the servers.
#   python3 bin/pin-age-check.py --root REPO --base REV --head REV --fixtures FILE [--json FILE] [--now ISO] [--min-days N]
#   exit 0: nothing moved, or every moved version is old enough; exit 1: a moved version is too young or its age cannot be proven.
#   An item is "<kind>:<name>@<version>"; kinds: action (version = the pinned commit), tool (the installer actions' version inputs and install-scanner.sh's
#   *_VER pins), gotool (go install path@version in run steps), package (pypi/<name>@<version> from the hash-pinned requirements), image (name@sha256:digest).
#   Fixtures: {"now": ISO, "times": {ITEM: {"time": ISO, "source": S}}, "first_seen": {ITEM: ISO}}. Sources that count: github-release, pypi, go-index,
#   registry-push. A source of commit-date, tag-date or image-config is NEVER a proof (the publisher or the builder controls it).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
chk="$root/bin/pin-age-check.py"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
ok()  { pass=$((pass+1)); echo "ok   $1"; }
bad() { failn=$((failn+1)); echo "FAIL $1"; }
CASE=""
check() { if "$@" >/dev/null 2>&1; then ok "$CASE"; else bad "$CASE"; fi; }
NOW="2026-10-05T12:00:00Z"
d() { python3 -c "import datetime,sys;print((datetime.datetime(2026,10,5,12)-datetime.timedelta(days=float(sys.argv[1]))).strftime('%Y-%m-%dT%H:%M:%SZ'))" "$1"; }
SHA1=$(printf '1%.0s' $(seq 40)); SHA2=$(printf '2%.0s' $(seq 40)); SHA3=$(printf '3%.0s' $(seq 40)); SHA4=$(printf '4%.0s' $(seq 40)); SHA5=$(printf '5%.0s' $(seq 40))
DIG1=sha256:$(printf '1%.0s' $(seq 64)); DIG2=sha256:$(printf '2%.0s' $(seq 64)); DIG3=sha256:$(printf '3%.0s' $(seq 64))

# --- the base repository: one of every kind of pin --------------------------------------------------------------------
base="$work/base"; mkdir -p "$base/.github/workflows" "$base/.github/actions/local" "$base/.github/agent" "$base/bin" "$base/build/docker"
cat >"$base/.github/workflows/ci.yml" <<EOF
on: pull_request
jobs:
  j:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/own/ci@$DIG1
    steps:
      - uses: actions/checkout@$SHA1 # v4.1.0
      - uses: golangci/golangci-lint-action@$SHA2 # v9.3.0
        with:
          version: v2.13.2
      - uses: actions/setup-go@$SHA3 # v6.0.0
        with:
          go-version: '1.27'
      - uses: actions/setup-python@$SHA4 # v6.1.0
        with:
          python-version: '3.12'
      - run: |
          go install github.com/securego/gosec/v2/cmd/gosec@v2.29.0
          python3 -m pip install --require-hashes -r .github/agent/adjudicator-requirements.txt
EOF
cat >"$base/.github/actions/local/action.yml" <<EOF
name: local
runs:
  using: composite
  steps:
    - uses: actions/cache@$SHA5 # v4.2.0
EOF
cat >"$base/bin/install-scanner.sh" <<'EOF'
#!/usr/bin/env bash
TRIVY_VER=0.74.0
GRYPE_VER=0.118.0
GITSIGN_VER=0.17.1
EOF
cat >"$base/.github/agent/adjudicator-requirements.txt" <<'EOF'
# hash-pinned
anthropic==1.9.0 \
    --hash=sha256:aaaa
requests==2.32.0 \
    --hash=sha256:bbbb
EOF
printf 'FROM gcr.io/distroless/static@%s\n' "$DIG2" >"$base/build/docker/Dockerfile.production"
printf 'module x\n\ngo 1.27\n\ntoolchain go1.27.1\n\nrequire github.com/foo/bar v1.0.0\n' >"$base/go.mod"
git -C "$base" init -q; git -C "$base" add -A; git -C "$base" -c user.name=t -c user.email=t@x commit -q -m base

# newcase NAME 'python edit run in the repo root' -> $work/NAME (a copy of base with a head commit)
newcase() {
  local n=$1; rm -rf "$work/$n"; cp -R "$base" "$work/$n"
  ( cd "$work/$n" && python3 - "$2" <<'PY'
import sys
exec(sys.argv[1])
PY
    git add -A; git -c user.name=t -c user.email=t@x commit -q -m head )
}
# runck NAME FIXTURES-JSON [extra args] -> sets rc, $work/NAME.out
runck() {
  local n=$1 fx=$2; shift 2; echo "$fx" >"$work/$n.fx.json"; rc=0
  python3 "$chk" --root "$work/$n" --base HEAD~1 --head HEAD --fixtures "$work/$n.fx.json" --now "$NOW" --json "$work/$n.json" "$@" >"$work/$n.out" 2>&1 || rc=$?
}
sub() { echo "import re,pathlib; p=pathlib.Path('$1'); p.write_text(p.read_text().replace('$2','$3'))"; }
OLD=$(d 10); YOUNG=$(d 3)

# --- nothing moves ------------------------------------------------------------------------------------------------------
newcase none "pathlib=__import__('pathlib'); pathlib.Path('README.md').write_text('hi')"
runck none '{"times": {}}'
CASE="no pin moved: exit 0, says so, and needs no data at all"
check test "$rc" -eq 0; check grep -qi 'no pin moved' "$work/none.out"

# --- an action pin moves: AC2 names it, AC3 measures its age ---------------------------------------------------------------
NEW1=$(printf 'a%.0s' $(seq 40))
newcase act "$(sub .github/workflows/ci.yml "actions/checkout@$SHA1 # v4.1.0" "actions/checkout@$NEW1 # v4.2.0")"
runck act "{\"times\": {\"action:actions/checkout@$NEW1\": {\"time\": \"$OLD\", \"source\": \"github-release\"}}}"
CASE="a moved action pin whose release is 10 days old passes, and the check NAMES it"
check test "$rc" -eq 0; check grep -q "action:actions/checkout@$NEW1" "$work/act.out"
runck act "{\"times\": {\"action:actions/checkout@$NEW1\": {\"time\": \"$YOUNG\", \"source\": \"github-release\"}}}"
CASE="the same pin released 3 days ago FAILS (exit 1) and says how young it is"
check test "$rc" -eq 1; check grep -qi 'FAIL' "$work/act.out"; check grep -q "action:actions/checkout@$NEW1" "$work/act.out"
runck act '{"times": {}}'
CASE="a moved pin with no age data FAILS: age not provable is a failure, never a pass"
check test "$rc" -eq 1; check grep -qi 'not provable\|cannot prove\|unprovable' "$work/act.out"
runck act "{\"times\": {\"action:actions/checkout@$NEW1\": {\"time\": \"$OLD\", \"source\": \"commit-date\"}}}"
CASE="a COMMIT date is never a proof of age (the publisher controls it): fails"
check test "$rc" -eq 1
runck act "{\"times\": {\"action:actions/checkout@$NEW1\": {\"time\": \"$OLD\", \"source\": \"tag-date\"}}}"
CASE="a TAG date is never a proof either: fails"
check test "$rc" -eq 1
runck act "{\"times\": {\"action:actions/checkout@$NEW1\": {\"time\": \"$YOUNG\", \"source\": \"github-release\"}}, \"first_seen\": {\"action:actions/checkout@$NEW1\": \"$OLD\"}}"
CASE="when the release is young but the exact version first appeared in one of OUR pull requests 10 days ago, it passes (the third server-side source)"
check test "$rc" -eq 0
runck act "{\"times\": {}, \"first_seen\": {\"action:actions/checkout@$NEW1\": \"$YOUNG\"}}"
CASE="first seen in our own PR only 3 days ago: still too young, fails"
check test "$rc" -eq 1
runck act "{\"times\": {\"action:actions/checkout@$NEW1\": {\"time\": \"$(d 7)\", \"source\": \"github-release\"}}}"
CASE="exactly 7 days old passes (the boundary is 7 days, not 7 days and a minute)"
check test "$rc" -eq 0
runck act "{\"times\": {\"action:actions/checkout@$NEW1\": {\"time\": \"$(d 6.99)\", \"source\": \"github-release\"}}}"
CASE="just under 7 days old fails"
check test "$rc" -eq 1
runck act "{\"times\": {\"action:actions/checkout@$NEW1\": {\"time\": \"2099-01-01T00:00:00Z\", \"source\": \"github-release\"}}}"
CASE="a publish time in the FUTURE is not a proof: fails"
check test "$rc" -eq 1
runck act "{\"times\": {\"action:actions/checkout@$NEW1\": {\"time\": \"not a date\", \"source\": \"github-release\"}}}"
CASE="an unparseable time is unprovable: fails"
check test "$rc" -eq 1
runck act "{\"times\": {\"action:actions/checkout@$NEW1\": {\"time\": \"$OLD\", \"source\": \"made-up\"}}}"
CASE="a source the check does not know is not a proof: fails"
check test "$rc" -eq 1
runck act "{\"times\": {\"action:actions/checkout@$NEW1\": {\"time\": \"$OLD\", \"source\": \"github-release\"}}}" --min-days 30
CASE="--min-days is honoured (a 10-day-old version fails a 30-day rule)"
check test "$rc" -eq 1

# --- every other kind of pin the age check covers (AC2) ---------------------------------------------------------------------
cover() { # <name> <edit> <item key> <source>
  newcase "$1" "$2"
  runck "$1" "{\"times\": {\"$3\": {\"time\": \"$OLD\", \"source\": \"$4\"}}}"
  CASE="$1: moved, named and (10 days old via $4) accepted"; check test "$rc" -eq 0; check grep -qF "$3" "$work/$1.out"
  runck "$1" "{\"times\": {\"$3\": {\"time\": \"$YOUNG\", \"source\": \"$4\"}}}"
  CASE="$1: the same item 3 days old fails"; check test "$rc" -eq 1
  runck "$1" '{"times": {}}'
  CASE="$1: with no age data fails"; check test "$rc" -eq 1
}
cover tool-scanner "$(sub bin/install-scanner.sh 'TRIVY_VER=0.74.0' 'TRIVY_VER=0.75.0')" "tool:trivy@0.75.0" github-release
cover tool-gitsign "$(sub bin/install-scanner.sh 'GITSIGN_VER=0.17.1' 'GITSIGN_VER=0.18.0')" "tool:gitsign@0.18.0" github-release
cover tool-installer-input "$(sub .github/workflows/ci.yml 'version: v2.13.2' 'version: v2.14.0')" "tool:golangci-lint@v2.14.0" github-release
cover tool-python-version "$(sub .github/workflows/ci.yml "python-version: '3.12'" "python-version: '3.13'")" "tool:python@3.13" github-release
cover gotool "$(sub .github/workflows/ci.yml 'gosec@v2.29.0' 'gosec@v2.30.0')" "gotool:github.com/securego/gosec/v2/cmd/gosec@v2.30.0" go-index
cover package "$(sub .github/agent/adjudicator-requirements.txt 'anthropic==1.9.0' 'anthropic==1.10.0')" "package:pypi/anthropic@1.10.0" pypi
cover image-container "$(sub .github/workflows/ci.yml "ghcr.io/own/ci@$DIG1" "ghcr.io/own/ci@$DIG3")" "image:ghcr.io/own/ci@$DIG3" registry-push
NEW5=$(printf 'b%.0s' $(seq 40))
cover local-composite-action "$(sub .github/actions/local/action.yml "actions/cache@$SHA5" "actions/cache@$NEW5")" "action:actions/cache@$NEW5" github-release

# --- a go install tool: the module INDEX's time, never the version-control time -------------------------------------------------
runck gotool "{\"times\": {\"gotool:github.com/securego/gosec/v2/cmd/gosec@v2.30.0\": {\"time\": \"$OLD\", \"source\": \"vcs-time\"}}}"
CASE="a go install tool's age from the version-control .info time is refused (the index timestamp is the server-side one): fails"
check test "$rc" -eq 1
# --- an image: the registry's push time, never the image's own created field ----------------------------------------------------
runck image-container "{\"times\": {\"image:ghcr.io/own/ci@$DIG3\": {\"time\": \"$OLD\", \"source\": \"image-config\"}}}"
CASE="an image's own 'created' field is refused (the builder sets it): fails"
check test "$rc" -eq 1

# --- name:tag@sha256:digest counts as PINNED (Docker ignores the tag when a digest is present): the image is the name without the tag, the version the digest ----
newcase tagdigest "$(sub .github/workflows/ci.yml "ghcr.io/own/ci@$DIG1" "ghcr.io/own/ci:v2@$DIG3")"
runck tagdigest "{\"times\": {\"image:ghcr.io/own/ci@$DIG3\": {\"time\": \"$OLD\", \"source\": \"registry-push\"}}}"
CASE="an image written name:tag@sha256:digest is the SAME item as name@sha256:digest (the tag is ignored): moved, named by its digest, and accepted at 10 days"
check test "$rc" -eq 0; check grep -qF "image:ghcr.io/own/ci@$DIG3" "$work/tagdigest.out"
newcase tagonly "$(sub .github/workflows/ci.yml "ghcr.io/own/ci@$DIG1" "ghcr.io/own/ci:v2")"
runck tagonly '{"times": {}}'
CASE="an image with only a tag (no digest) is not a pin the age check can measure: it fails rather than passing silently"
check test "$rc" -eq 1

# --- NOT covered: the product's base image, Go modules, the Go toolchain (amendments 1 and 2) -------------------------------------
newcase notcovered "$(sub build/docker/Dockerfile.production "$DIG2" "$DIG3")
$(sub go.mod 'go1.27.1' 'go1.27.2')
$(sub .github/workflows/ci.yml "go-version: '1.27'" "go-version: '1.28'")
$(sub go.mod 'v1.0.0' 'v1.1.0')"
runck notcovered '{"times": {}}'
CASE="the product base image, a Go module bump, go.mod's toolchain and setup-go's version are NOT covered: they move with no data and no failure"
check test "$rc" -eq 0; check grep -qi 'no pin moved' "$work/notcovered.out"

# --- several moves: every one is named, one young one fails the whole check ---------------------------------------------------------
newcase multi "$(sub .github/workflows/ci.yml "actions/checkout@$SHA1 # v4.1.0" "actions/checkout@$NEW1 # v4.2.0")
$(sub bin/install-scanner.sh 'TRIVY_VER=0.74.0' 'TRIVY_VER=0.75.0')
$(sub .github/agent/adjudicator-requirements.txt 'requests==2.32.0' 'requests==2.33.0')"
runck multi "{\"times\": {\"action:actions/checkout@$NEW1\": {\"time\": \"$OLD\", \"source\": \"github-release\"}, \"tool:trivy@0.75.0\": {\"time\": \"$YOUNG\", \"source\": \"github-release\"}, \"package:pypi/requests@2.33.0\": {\"time\": \"$OLD\", \"source\": \"pypi\"}}}"
CASE="three moves, one of them 3 days old: exit 1, and the output names ALL THREE (so a reviewer sees what moved) and blames the young one"
check test "$rc" -eq 1
check grep -qF "action:actions/checkout@$NEW1" "$work/multi.out"; check grep -qF "tool:trivy@0.75.0" "$work/multi.out"; check grep -qF "package:pypi/requests@2.33.0" "$work/multi.out"
check python3 - "$work/multi.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
moved = {m["item"]: m for m in d["moved"]}
assert set(moved) == {"action:actions/checkout@" + "a" * 40, "tool:trivy@0.75.0", "package:pypi/requests@2.33.0"}, sorted(moved)
assert moved["tool:trivy@0.75.0"]["ok"] is False and moved["package:pypi/requests@2.33.0"]["ok"] is True, moved
PY

# --- a NEW pin counts as moved; a removed pin is no age problem --------------------------------------------------------------
NEW6=$(printf 'c%.0s' $(seq 40))
newcase added "$(sub .github/workflows/ci.yml "      - uses: actions/checkout@$SHA1 # v4.1.0" "      - uses: actions/checkout@$SHA1 # v4.1.0\n      - uses: actions/upload-artifact@$NEW6 # v7.0.1")"
runck added '{"times": {}}'
CASE="a brand-new action pin counts as moved: with no age data it fails"
check test "$rc" -eq 1; check grep -qF "action:actions/upload-artifact@$NEW6" "$work/added.out"
newcase removed "$(sub .github/workflows/ci.yml "      - uses: actions/checkout@$SHA1 # v4.1.0" "")"
runck removed '{"times": {}}'
CASE="removing a pin is not an age problem: exit 0"
check test "$rc" -eq 0

# --- a moved pin whose version is the SAME item elsewhere (the same commit used twice) is judged once, and an UNCHANGED pin never needs data ----------
runck none '{"times": {}}'
CASE="an unchanged workflow with 5 pins needs no data (only what MOVED is measured)"
check test "$rc" -eq 0

echo "pin-age-check: $pass passed, $failn failed"
test "$failn" -eq 0
