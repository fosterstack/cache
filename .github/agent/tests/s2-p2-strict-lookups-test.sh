#!/usr/bin/env bash
# proves: REQ-SUP-001-AC3, REQ-SUP-001-AC5
# cache#359 round 5, section 2, group P2, rows 1-3: a lookup that cannot be answered is a FAILURE, never "no proof" or "nothing there".
#   (1) PyPI, the Go proxy and the Go index: an outage (network error, 5xx) raises CouldNotLook; only a 404 stays "not there".
#       pin-audit's published-name query to PyPI is strict as well (a failure, not the pinned name alone).
#   (2) a gotool item is dated by the Go index time: an older PR clock must not win over it.
#   (3) an action.yml that cannot be read fails in nested() (Fail), which the nested pass turns into an incomplete run, and prints no "no known-compromised" line.
# In-process: the network is replaced by a fake urlopen, gh by a script on a scratch path. Written from the English rows only.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
export SC="$here/../supply-chain"
work=$(mktemp -d -t s2p2-strict.XXXXXX); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
ok()  { pass=$((pass+1)); echo "ok   $1"; }
bad() { failn=$((failn+1)); echo "FAIL $1"; }
CASE=""
check() { if "$@" >"$work/last.out" 2>&1; then ok "$CASE"; else bad "$CASE"; sed 's/^/     | /' "$work/last.out" | tail -5; fi; }

cat >"$work/pre.py" <<'PY'
import base64, contextlib, datetime as dt, hashlib, importlib.util, io, json, os, sys, urllib.error, urllib.request
D = os.environ["SC"]
def load(n):
    s = importlib.util.spec_from_file_location(n.replace("-", "_") + "_t", os.path.join(D, n + ".py"))
    m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
class R:
    def __init__(self, body): self.b = body if isinstance(body, bytes) else json.dumps(body).encode()
    def read(self, n=-1): return self.b if n is None or n < 0 else self.b[:n]
    def __enter__(self): return self
    def __exit__(self, *a): return False
def serve(handler):
    def fake(req, timeout=None, **kw):
        return handler(req if isinstance(req, str) else req.full_url)
    urllib.request.urlopen = fake
def down(url): raise urllib.error.URLError("simulated outage")
def code(c):
    def h(url): raise urllib.error.HTTPError(url, c, "simulated", {}, None)
    return h
def raises(exc, fn):
    try: fn()
    except exc: return True
    return False
NOW = dt.datetime(2026, 10, 5, 12, tzinfo=dt.timezone.utc)
def ago(days): return (NOW - dt.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
PY
cat >"$work/gh404" <<'SH'
#!/bin/sh
echo "gh: Not Found (HTTP 404)" >&2; exit 1
SH
cat >"$work/ghok" <<'SH'
#!/bin/sh
echo '[]'
SH
cat >"$work/ghyaml" <<'SH'
#!/bin/sh
python3 -c 'import base64,json;print(json.dumps({"content": base64.b64encode(b"runs: [unclosed").decode()}))'
SH
chmod +x "$work/gh404" "$work/ghok" "$work/ghyaml"

# --- (1) PyPI -----------------------------------------------------------------------------------------------------------------
PYPI='age = load("pin-age-check"); it = age.inv.Item("package", "pypi/requests", "2.32.0")'
CASE="PyPI network outage while dating a package is CouldNotLook, not 'no proof'"
check python3 - "$work/pre.py" <<PY
import sys; exec(open(sys.argv[1]).read()); $PYPI
serve(down)
assert raises(age.CouldNotLook, lambda: age.live_proofs(it, "/nonexistent", None)), "outage read as no proof"
PY
CASE="PyPI answering HTTP 503 is CouldNotLook"
check python3 - "$work/pre.py" <<PY
import sys; exec(open(sys.argv[1]).read()); $PYPI
serve(code(503))
assert raises(age.CouldNotLook, lambda: age.live_proofs(it, "/nonexistent", None)), "503 read as no proof"
PY
CASE="PyPI answering 404 stays 'not there': no proof, no exception"
check python3 - "$work/pre.py" <<PY
import sys; exec(open(sys.argv[1]).read()); $PYPI
serve(code(404))
assert age.live_proofs(it, "/nonexistent", None) == []
PY

# --- (1) Go proxy and Go index ---------------------------------------------------------------------------------------------------
GOT='age = load("pin-age-check"); it = age.inv.Item("gotool", "github.com/securego/gosec/v2/cmd/gosec", "v2.29.0")'
CASE="Go proxy network outage while dating a go install is CouldNotLook"
check python3 - "$work/pre.py" <<PY
import sys; exec(open(sys.argv[1]).read()); $GOT
serve(down)
assert raises(age.CouldNotLook, lambda: age.live_proofs(it, "/nonexistent", None)), "proxy outage read as no proof"
PY
CASE="Go proxy answering HTTP 502 is CouldNotLook"
check python3 - "$work/pre.py" <<PY
import sys; exec(open(sys.argv[1]).read()); $GOT
serve(code(502))
assert raises(age.CouldNotLook, lambda: age.live_proofs(it, "/nonexistent", None)), "proxy 502 read as no proof"
PY
GOIDX='
def h(url):
    if "proxy.golang.org" in url: return R({"Version": "v2.29.0", "Time": "2026-09-01T00:00:00Z"})
    return INDEX(url)
'
CASE="Go index network outage (the proxy answered) is CouldNotLook"
check python3 - "$work/pre.py" <<PY
import sys; exec(open(sys.argv[1]).read()); $GOT
INDEX = down
$GOIDX
serve(h)
assert raises(age.CouldNotLook, lambda: age.live_proofs(it, "/nonexistent", None)), "index outage read as no proof"
PY
CASE="Go index answering HTTP 500 is CouldNotLook"
check python3 - "$work/pre.py" <<PY
import sys; exec(open(sys.argv[1]).read()); $GOT
INDEX = code(500)
$GOIDX
serve(h)
assert raises(age.CouldNotLook, lambda: age.live_proofs(it, "/nonexistent", None)), "index 500 read as no proof"
PY
CASE="Go index that answers with the module's row yields the go-index proof (a working path stays working)"
check python3 - "$work/pre.py" <<PY
import sys; exec(open(sys.argv[1]).read()); $GOT
row = json.dumps({"Path": "github.com/securego/gosec/v2/cmd/gosec", "Version": "v2.29.0", "Timestamp": "2026-09-02T00:00:00Z"}) + "\n"
INDEX = lambda url: R(row.encode())
$GOIDX
serve(h)
got = age.live_proofs(it, "/nonexistent", None)
assert ("2026-09-02T00:00:00Z", "go-index") in got, got
PY

# --- pin-audit's published-name query to PyPI ----------------------------------------------------------------------------------
CASE="pin-audit: an unreachable PyPI while it asks for the published name of a package is a failure (Fail or CouldNotLook), not the pinned name alone"
check python3 - "$work/pre.py" "$work/ghok" <<'PY'
import sys; exec(open(sys.argv[1]).read())
aud = load("pin-audit")
def h(url):
    if "pypi.org" in url: raise urllib.error.URLError("simulated outage")
    if "api.osv.dev" in url: return R({})
    raise urllib.error.HTTPError(url, 404, "nf", {}, None)
serve(h)
net = aud.LiveNet([sys.argv[2]], "/nonexistent")
it = aud.inv.Item("package", "pypi/requests", "2.32.0")
assert raises((aud.Fail, aud.age.CouldNotLook), lambda: net.lists(it)), "PyPI outage ignored by the advisory query"
PY

# --- (2) gotool is dated by the Go index time -----------------------------------------------------------------------------------
CASE="gotool: a PR clock older than the Go index time does not win; the item is too young by the index time"
check python3 - "$work/pre.py" <<PY
import sys; exec(open(sys.argv[1]).read()); $GOT
ok, why, proof = age.judge_item(it, [(ago(30), "pr-clock"), (ago(3), "go-index")], NOW)
assert not ok and proof and proof["source"] == "go-index", (ok, why, proof)
PY
CASE="gotool: the go-index time decides even when it is older than the PR clock, and then passes"
check python3 - "$work/pre.py" <<PY
import sys; exec(open(sys.argv[1]).read()); $GOT
ok, why, proof = age.judge_item(it, [(ago(2), "pr-clock"), (ago(30), "go-index")], NOW)
assert ok and proof["source"] == "go-index", (ok, why, proof)
PY
CASE="gotool: with no go-index time at all, the PR clock alone still dates it (the existing fallback)"
check python3 - "$work/pre.py" <<PY
import sys; exec(open(sys.argv[1]).read()); $GOT
ok, why, proof = age.judge_item(it, [(ago(30), "pr-clock")], NOW)
assert ok and proof["source"] == "pr-clock", (ok, why, proof)
PY

# --- (3) an unreadable action.yml ------------------------------------------------------------------------------------------------
# the run: pin-audit's nested pass reads action.yml through LiveNet.nested; a Fail there is turned into incomplete by nested_safe
cat >"$work/nested-run.py" <<'PY'
import sys; exec(open(sys.argv[1]).read())
import subprocess
work, gh = sys.argv[2], sys.argv[3]; r = work + "/repo-" + os.path.basename(gh)
os.makedirs(r + "/.github/workflows", exist_ok=True)
open(r + "/.github/workflows/ci.yml", "w").write("on: pull_request\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@" + "1" * 40 + " # v4.1.0\n")
g = lambda *a: subprocess.run(["git", "-C", r, "-c", "user.name=t", "-c", "user.email=t@x", *a], check=True, capture_output=True)
g("init", "-q"); g("add", "-A"); g("commit", "-q", "-m", "x")
json.dump({"lists": {}, "versions": {}, "prs": []}, open(work + "/fx.json", "w"))
aud = load("pin-audit")
live = aud.LiveNet([gh], "/nonexistent")
aud.FixtureNet.nested = lambda self, item: live.nested(item)
out, err = io.StringIO(), io.StringIO()
with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
    rc = aud.main(["--root", r, "--fixtures", work + "/fx.json", "--now", "2026-10-05T12:00:00Z", "--gh", "true"])
assert "could not be read" in out.getvalue(), out.getvalue()[-400:]
assert rc != 0 and "no known-compromised" not in out.getvalue(), (rc, out.getvalue()[-300:])
PY
CASE="an action.yml and action.yaml that are both missing (404) end the run incomplete: no 'no known-compromised' line, non-zero exit"
check python3 "$work/nested-run.py" "$work/pre.py" "$work" "$work/gh404"
CASE="an action.yml that is not valid YAML ends the run incomplete: no 'no known-compromised' line, non-zero exit"
check python3 "$work/nested-run.py" "$work/pre.py" "$work" "$work/ghyaml"

echo "s2-p2-strict-lookups: $pass ok, $failn failed"
[ "$failn" -eq 0 ]
