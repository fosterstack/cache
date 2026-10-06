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
SHA6=$(printf '6%.0s' $(seq 40)); DIG4=sha256:$(printf '4%.0s' $(seq 64)); DIG5=sha256:$(printf '5%.0s' $(seq 64)); DIG1=sha256:$(printf '1%.0s' $(seq 64)); DIG2=sha256:$(printf '2%.0s' $(seq 64)); DIG3=sha256:$(printf '3%.0s' $(seq 64))

# --- the base repository: one of every kind of pin --------------------------------------------------------------------
base="$work/base"; mkdir -p "$base/.github/workflows" "$base/.github/actions/local" "$base/.github/pins" "$base/bin" "$base/build/docker"
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
          python3 -m pip install --require-hashes -r .github/pins/adjudicator-requirements.txt
      - uses: goreleaser/goreleaser-action@$SHA6 # v7.2.3
        with:
          version: '2.17.1'
      - uses: helm/kind-action@$SHA6 # v1.15.0
        with:
          node_image: kindest/node:v1.31.0@$DIG4
      - run: |
          curl -fsSL https://github.com/cli/cli/releases/download/v2.40.0/gh_2.40.0_linux_amd64.tar.gz -o gh.tgz
          python3 -m pip install --quiet black==24.1.0
          docker run --rm alpine:3.20@$DIG5 true
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
cat >"$base/.github/pins/adjudicator-requirements.txt" <<'EOF'
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
sub() { python3 -c "import sys;print('import pathlib; p=pathlib.Path(%r); p.write_text(p.read_text().replace(%r,%r))' % tuple(sys.argv[1:]))" "$@"; }
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
cover package "$(sub .github/pins/adjudicator-requirements.txt 'anthropic==1.9.0' 'anthropic==1.10.0')" "package:pypi/anthropic@1.10.0" pypi
cover image-container "$(sub .github/workflows/ci.yml "ghcr.io/own/ci@$DIG1" "ghcr.io/own/ci@$DIG3")" "image:ghcr.io/own/ci@$DIG3" registry-push
cover tool-goreleaser "$(sub .github/workflows/ci.yml "version: '2.17.1'" "version: '2.18.0'")" "tool:goreleaser@2.18.0" github-release
cover tool-curl-download "$(sub .github/workflows/ci.yml 'releases/download/v2.40.0/gh_2.40.0_linux_amd64' 'releases/download/v2.41.0/gh_2.41.0_linux_amd64')" "tool:cli/cli@2.41.0" github-release
cover package-in-run-step "$(sub .github/workflows/ci.yml 'black==24.1.0' 'black==24.2.0')" "package:pypi/black@24.2.0" pypi
cover image-in-run-step "$(sub .github/workflows/ci.yml "alpine:3.20@$DIG5" "alpine:3.20@$DIG3")" "image:alpine@$DIG3" registry-push
cover image-installer-input "$(sub .github/workflows/ci.yml "kindest/node:v1.31.0@$DIG4" "kindest/node:v1.31.0@$DIG3")" "image:kindest/node@$DIG3" registry-push
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
$(sub .github/pins/adjudicator-requirements.txt 'requests==2.32.0' 'requests==2.33.0')"
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
newcase added "$(sub .github/workflows/ci.yml "      - uses: actions/checkout@$SHA1 # v4.1.0" "      - uses: actions/checkout@$SHA1 # v4.1.0"$'\n'"      - uses: actions/upload-artifact@$NEW6 # v7.0.1")"
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

# --- a workflow whose filename is not ASCII is still read (git quotes such paths; a pin there must never go unmeasured) --------------------------------------------
newcase unicode "$(sub .github/workflows/ci.yml "actions/checkout@$SHA1 # v4.1.0" "actions/checkout@$NEW1 # v4.2.0")
import pathlib, shutil
shutil.copy('.github/workflows/ci.yml', '.github/workflows/\u00e9.yml')
pathlib.Path('.github/workflows/ci.yml').write_text(pathlib.Path('.github/workflows/ci.yml').read_text().replace('actions/checkout@$NEW1', 'actions/checkout@$SHA1'))"
runck unicode '{"times": {}}'
CASE="a new pin in .github/workflows/\u00e9.yml (a non-ASCII file name) is named and measured like any other"
check test "$rc" -eq 1; check grep -qF "action:actions/checkout@$NEW1" "$work/unicode.out"

# --- the 'first seen in one of OUR pull requests' proof matches the WHOLE version and only PRs from our own repository ------------------------------------------------
mkdir -p "$work/stubfs"
cat >"$work/stubfs/gh" <<'STUB'
#!/bin/sh
case "$*" in
  *pulls*) if [ "$GH_PR_FORK" = 1 ]; then echo '[{"created_at":"2026-01-01T00:00:00Z","title":"Bump java to 21","head":{"repo":{"full_name":"stranger/cache"}}}]'; elif [ "$GH_PR_NOTNAMED" = 1 ]; then echo '[{"created_at":"2026-01-01T00:00:00Z","title":"Unrelated old PR","body":"nothing","head":{"repo":{"full_name":"o/r"}}}]'; else echo '[{"created_at":"2026-01-01T00:00:00Z","title":"Bump java to 21","head":{"repo":{"full_name":"o/r"}}}]'; fi;;
  *) exit 1;;
esac
STUB
chmod +x "$work/stubfs/gh"
rm -rf "$work/fs"; mkdir -p "$work/fs/.github/workflows"; git -C "$work/fs" init -q
printf 'note: released in 2021 and 12.1\n' >"$work/fs/.github/workflows/a.yml"; git -C "$work/fs" add -A; git -C "$work/fs" -c user.name=t -c user.email=t@x commit -q -m a
firstseen() { ( cd "$work" && GITHUB_REPOSITORY=o/r GH_PR_FORK="${3:-0}" GH_PR_NOTNAMED="${4:-0}" PATH="$work/stubfs:$PATH" python3 - "$chk" "$work/fs" "$1" "$2" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("ac", sys.argv[1]); ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
print(ac._first_seen(ac.inv.Item("tool", "java", sys.argv[4]), sys.argv[2]))
PY
) 2>&1 | tail -1; }
CASE="first seen: version 21 does NOT match the text 2021 or 12.1 (a substring is not the version): no proof"
check test "$(firstseen x 21)" = None
printf 'java-version: 21\n' >"$work/fs/.github/workflows/a.yml"; git -C "$work/fs" add -A; git -C "$work/fs" -c user.name=t -c user.email=t@x commit -q -m b
CASE="first seen: the whole version as its own token IS found, and gives the PR's server-side creation time"
check test "$(firstseen x 21)" = 2026-01-01T00:00:00Z
CASE="first seen: a pull request from someone's FORK never starts the clock"
check test "$(firstseen x 21 1)" = None
CASE="first seen: an OLD pull request that does not name the version (a pin added to it later) lends it no age"
check test "$(firstseen x 21 0 1)" = None

# --- inventory edge cases from review: the word `uses` in env is data, digests anywhere, continuation lines, several go install targets, case-folded installer names -------------
DIG6=sha256:$(printf '6%.0s' $(seq 64))
newcase envuses "$(sub .github/workflows/ci.yml '      - run: |' $'      - env:\n          uses: \'${{ secrets.SECRETNAME_Y }}\'\n        run: echo hi\n      - run: |')"
runck envuses '{"times": {}}'
CASE="the word uses inside env: is data, not an action: nothing moved, and the secret name it carries is never printed"
check test "$rc" -eq 0; check bash -c "! grep -q SECRETNAME_Y '$work/envuses.out'"
newcase badyaml "open('.github/workflows/ci.yml','a').write('\\n  broken: [SECRETNAME_Y\\n')"
runck badyaml '{"times": {}}'
CASE="a workflow that does not parse fails the check (exit 2) and the message names the file and line only, never the source text"
check test "$rc" -eq 2; check bash -c "! grep -q SECRETNAME_Y '$work/badyaml.out'"; check grep -q 'does not parse (line' "$work/badyaml.out"
newcase driveropts "$(sub .github/workflows/ci.yml '      - run: |' $'      - uses: docker/setup-buildx-action@'$SHA6$' # v3\n        with:\n          driver-opts: image=moby/buildkit@'$DIG4$'\n      - run: |')"
git -C "$work/driveropts" commit -q --amend -m head
newcase driveropts2 "$(sub .github/workflows/ci.yml '      - run: |' $'      - uses: docker/setup-buildx-action@'$SHA6$' # v3\n        with:\n          driver-opts: image=moby/buildkit@'$DIG6$'\n      - run: |')"
CASE="a digest-pinned image inside a with: value (BuildKit's driver-opts) is an inventory item: named, and judged like any image"
runck driveropts2 '{"times": {}}'; check test "$rc" -eq 1; check grep -qF "image:moby/buildkit@$DIG6" "$work/driveropts2.out"
newcase multipip "import pathlib; p=pathlib.Path('.github/workflows/ci.yml'); t=p.read_text(); p.write_text(t.replace('          python3 -m pip install --require-hashes', '          python3 -m pip install --quiet \\\\\\n            isort==5.13.0 \\\\\\n            ruff==0.5.0\\n          python3 -m pip install --require-hashes'))"
runck multipip '{"times": {}}'
CASE="a pip install continued over several lines is read as one command: both pinned packages are named"
check test "$rc" -eq 1; check grep -qF "package:pypi/isort@5.13.0" "$work/multipip.out"; check grep -qF "package:pypi/ruff@0.5.0" "$work/multipip.out"
newcase twogo "$(sub .github/workflows/ci.yml 'go install github.com/securego/gosec/v2/cmd/gosec@v2.29.0' 'go install github.com/securego/gosec/v2/cmd/gosec@v2.29.0 example.org/other/cmd/tool@v1.2.3')"
runck twogo '{"times": {}}'
CASE="a go install of two targets names both"
check test "$rc" -eq 1; check grep -qF "gotool:example.org/other/cmd/tool@v1.2.3" "$work/twogo.out"
newcase casefold "$(sub .github/workflows/ci.yml 'golangci/golangci-lint-action@' 'Golangci/Golangci-Lint-Action@')
$(sub .github/workflows/ci.yml 'version: v2.13.2' 'version: v2.14.0')"
runck casefold '{"times": {}}'
CASE="GitHub folds case in action names: Golangci/Golangci-Lint-Action still counts as the installer action, so its version input is measured"
check test "$rc" -eq 1; check grep -qF "tool:golangci-lint@v2.14.0" "$work/casefold.out"

# --- an action's age from its release: every tag at the commit is tried, and the commit must already have existed when the release was published --------------------------
cat >"$work/stubfs/ghmap" <<'STUB'
#!/usr/bin/env python3
# a gh stub for the offline tests: GH_MAP is a JSON file {api path: value}; --jq supports .field, .a.b and .[]
import json, os, sys
a = sys.argv[1:]
if a[0] != "api":
    sys.exit(1)
jq = a[a.index("--jq") + 1] if "--jq" in a else None
path = [x for x in a[1:] if not x.startswith("-") and x != jq][0]
m = json.load(open(os.environ["GH_MAP"]))
if path not in m:
    sys.stderr.write("gh: Not Found (HTTP 404)\n"); sys.exit(1)
v = m[path]
if isinstance(v, dict) and "__err" in v:
    sys.stderr.write(v["__err"] + "\n"); sys.exit(1)
if jq == ".[]":
    for x in v: print(json.dumps(x))
elif jq and jq.startswith("."):
    for k in jq[1:].split("."):
        v = v[k]
    print(v if isinstance(v, str) else json.dumps(v))
else:
    print(json.dumps(v))
STUB
chmod +x "$work/stubfs/ghmap"; cp "$work/stubfs/ghmap" "$work/stubfs/gh2"
liveproof() { # $1 = commit date of the pinned commit
  python3 - "$work/map.json" "$1" "$SHA1" <<'PY'
import json, sys
m = {"repos/o/act/git/matching-refs/tags?per_page=100": [{"ref": "refs/tags/v4", "object": {"type": "commit", "sha": sys.argv[3]}}, {"ref": "refs/tags/v4.1.0", "object": {"type": "commit", "sha": sys.argv[3]}}],
     "repos/o/act/releases/tags/v4.1.0": {"published_at": "2026-09-01T00:00:00Z"},
     "repos/o/act/commits/" + sys.argv[3]: {"commit": {"committer": {"date": sys.argv[2]}}}}
json.dump(m, open(sys.argv[1], "w"))
PY
  ( cd "$work" && env -u GITHUB_REPOSITORY GH_MAP="$work/map.json" PATH="$work/stubfs:$PATH" python3 - "$chk" "$SHA1" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("ac", sys.argv[1]); ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
ac._gh_api.__globals__["subprocess"]  # real module
import subprocess
orig = subprocess.run
def run(cmd, *a, **k):
    if cmd and cmd[0] == "gh": cmd = ["gh2", *cmd[1:]]
    return orig(cmd, *a, **k)
subprocess.run = run
print(ac.live_proofs(ac.inv.Item("action", "o/act", sys.argv[2], ""), "."))
PY
) 2>&1 | tail -1; }
CASE="live action proof: v4 has no release but v4.1.0 does, and the commit is older than the release: github-release proof from the SECOND tag"
out=$(liveproof 2026-08-01T00:00:00Z); case "$out" in *github-release*) ok "$CASE";; *) bad "$CASE";; esac
CASE="live action proof: a tag redirected to a commit NEWER than the release it carries (commit date after the publish time) gives no proof"
out=$(liveproof 2026-09-30T00:00:00Z); case "$out" in *github-release*) bad "$CASE";; *) ok "$CASE";; esac

# --- live mode (no fixtures) against a stub gh: a rate limit is "could not look" (exit 2), a 404 is "no proof" (exit 1); neither is ever a pass -------------------------
mkdir -p "$work/stubbin"
cat >"$work/stubbin/gh" <<'STUB'
#!/bin/sh
case "$GH_MODE" in
  ratelimit) echo "gh: API rate limit exceeded for user ID 1 (HTTP 403)" >&2; exit 1;;
  notfound)  echo "gh: Not Found (HTTP 404)" >&2; exit 1;;
esac
exit 1
STUB
chmod +x "$work/stubbin/gh"
newcase livea "$(sub .github/workflows/ci.yml "actions/checkout@$SHA1 # v4.1.0" "actions/checkout@$NEW1 # v4.2.0")"
live() { rc=0; ( cd "$work" && env -u GITHUB_REPOSITORY GH_MODE="$1" PATH="$work/stubbin:$PATH" python3 "$chk" --root "$work/livea" --base HEAD~1 --head HEAD --now "$NOW" ) >"$work/live.out" 2>&1 || rc=$?; }
live ratelimit
CASE="live: GitHub's rate limit is 'could not look': exit 2, says so and is not a pass"
check test "$rc" -eq 2; check grep -qi 'rate limit' "$work/live.out"
live notfound
CASE="live: a 404 (no release for that commit) is 'age not provable': exit 1"
check test "$rc" -eq 1; check grep -qi 'not provable' "$work/live.out"

echo "pin-age-check: $pass passed, $failn failed"
test "$failn" -eq 0
