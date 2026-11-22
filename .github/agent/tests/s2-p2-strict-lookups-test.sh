#!/usr/bin/env bash
# proves: REQ-SUP-001-AC5
# cache#359 round 5, section 2, group P2, rows 1-3: a lookup that cannot be answered is a FAILURE, never "no proof" or
# "nothing there".
#   (1) pin-audit's published-name query to PyPI is strict (an outage is a failure, not the pinned name alone).
#   (3) an action.yml that cannot be read fails in nested() (Fail), which the nested pass turns into an incomplete run,
#   and prints no "no known-compromised" line.
# In-process: the network is replaced by a fake urlopen, gh by a script on a scratch path. Written from the English
# rows only.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
export SC="$here/../supply-chain"
work=$(mktemp -d -t s2p2-strict.XXXXXX); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
ok()  { pass=$((pass+1)); echo "ok   $1"; }
bad() { failn=$((failn+1)); echo "FAIL $1"; }
CASE=""
check() {
  if "$@" >"$work/last.out" 2>&1; then
    ok "$CASE"
  else
    bad "$CASE"
    sed 's/^/     | /' "$work/last.out" | tail -5
  fi
}

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
def raises(exc, fn):
    try: fn()
    except exc: return True
    return False
def caught(exc, fn):
    try: fn()
    except exc as e: return str(e)
    return None
PY
cat >"$work/ghok" <<'SH'
#!/bin/sh
echo '[]'
SH
cat >"$work/ghyaml" <<'SH'
#!/bin/sh
python3 -c 'import base64,json;print(json.dumps({"content": base64.b64encode(b"runs: [unclosed").decode()}))'
SH
chmod +x "$work/ghok" "$work/ghyaml"

# --- pin-audit's published-name query to PyPI -------------------------------------------------------------------------
CASE="pin-audit: an unreachable PyPI while it asks for the published name of a package is a failure (Fail "
CASE+="or CouldNotLook), not the pinned name alone"
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
msg = caught((aud.Fail, aud.age.CouldNotLook), lambda: net.lists(it))
assert msg and "could not be asked" in msg, ("PyPI outage ignored by the advisory query", msg)
PY

# --- (3) an unreadable action.yml -------------------------------------------------------------------------------------
# the run: pin-audit's nested pass reads action.yml through LiveNet.nested; a Fail there is turned into incomplete by
# nested_safe
cat >"$work/nested-run.py" <<'PY'
import sys; exec(open(sys.argv[1]).read())
import subprocess
work, gh = sys.argv[2], sys.argv[3]; r = work + "/repo-" + os.path.basename(gh)
os.makedirs(r + "/.github/workflows", exist_ok=True)
open(r + "/.github/workflows/ci.yml", "w").write(
    "on: pull_request\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@"
    + "1" * 40 + " # v4.1.0\n")
g = lambda *a: subprocess.run(["git", "-C", r, "-c", "user.name=t", "-c", "user.email=t@x", *a],
                              check=True, capture_output=True)
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
CASE="an action.yml that is not valid YAML ends the run incomplete: no 'no known-compromised' line, non-zero exit"
check python3 "$work/nested-run.py" "$work/pre.py" "$work" "$work/ghyaml"

# --- (4) an action that cannot be read is a FINDING on that item (exit 1), never an incomplete run ---------------------
# a gh that serves files by path from GH_FILES (a map of the path in the action's repository to its text; any other path
# is a 404) and answers the issue calls of the run
cat >"$work/gh-files" <<'PY'
#!/usr/bin/env python3
import base64, json, os, sys
a = sys.argv[1:]
if a[:2] == ["issue", "list"]:
    print("[]"); sys.exit(0)
if a[:2] in (["issue", "create"], ["issue", "edit"]):
    open(os.environ["GH_LOG"], "a").write(open(a[a.index("--body-file") + 1]).read() + "\n")
    print("https://github.com/x/y/issues/9"); sys.exit(0)
if a[:1] != ["api"]:
    sys.exit(0)
path = [x for x in a[1:] if not x.startswith("-")][0].split("?")[0]
files = json.loads(os.environ["GH_FILES"])
rest = path.partition("/contents/")[2]
if rest not in files:
    sys.stderr.write("gh: Not Found (HTTP 404)\n"); sys.exit(1)
print(json.dumps({"content": base64.b64encode(files[rest].encode()).decode()}))
PY
chmod +x "$work/gh-files"
# the audit over a one-workflow tree whose actions are read through gh-files; CASES[name] = the files of the tree, the files of
# the remote action, the fixtures, and what the run must show: a finding named N (exit 1, no incomplete run) or a hit on N
cat >"$work/nested-find.py" <<'PY'
import sys; exec(open(sys.argv[1]).read())
import subprocess
work, name = sys.argv[2], sys.argv[3]
SO, SI = "a" * 40, "b" * 40
HEAD = "on: pull_request\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n"
COMP = "runs:\n  using: composite\n  steps:\n    - uses: o/inner@" + SI + " # v1\n"
HIT = {"lists": {"action:o/inner@" + SI: {"github": [{"id": "GHSA-aaaa-bbbb-cccc", "incident": "INC-1", "affected": True,
                                                    "modified": "2026-10-04T00:00:00Z"}], "osv": []}}}
def wf(uses): return {".github/workflows/ci.yml": HEAD + "      - uses: " + uses + "\n"}
CASES = {
    "local-yml-read":    (dict(wf("./.github/actions/ny"), **{".github/actions/ny/action.yml": COMP}), {}, HIT, "hit", "o/inner"),
    "local-yaml-read":   (dict(wf("./.github/actions/ny"), **{".github/actions/ny/action.yaml": COMP}), {}, HIT, "hit", "o/inner"),
    "local-clean":       (dict(wf("./.github/actions/ok"), **{".github/actions/ok/action.yml": "runs:\n  using: node20\n  main: x.js\n"}), {}, {}, "clean", ""),
    "remote-yml-read":   (wf("o/act@" + SO + " # v1"), {"action.yml": COMP}, HIT, "hit", "o/inner"),
    "remote-yaml-read":  (wf("o/act@" + SO + " # v1"), {"action.yaml": COMP}, HIT, "hit", "o/inner"),
    "remote-sub-yaml-read": (wf("o/act/sub/dir@" + SO + " # v1"), {"sub/dir/action.yaml": COMP}, HIT, "hit", "o/inner"),
    "local-neither":     (wf("./.github/actions/gone"), {}, {}, "finding", ".github/actions/gone"),
    "local-dir-no-file": (dict(wf("./.github/actions/empty"), **{".github/actions/empty/README.md": "x\n"}), {}, {}, "finding",
                          ".github/actions/empty"),
    "remote-neither":    (wf("actions/checkout@" + SO + " # v4.1.0"), {}, {}, "finding", "actions/checkout"),
    "remote-sub-neither": (wf("o/act/sub/dir@" + SO + " # v1"), {}, {}, "finding", "o/act"),
    "remote-reusable-workflow": ({".github/workflows/ci.yml": "on: pull_request\njobs:\n  j:\n    uses: o/r/.github/workflows/w.yml@" + SO + " # v1\n"},
                                 {}, {}, "finding", "o/r"),
}
files, remote, fx, want, named = CASES[name]
r = work + "/repo-nf-" + name
for path, text in files.items():
    os.makedirs(os.path.dirname(r + "/" + path), exist_ok=True); open(r + "/" + path, "w").write(text)
g = lambda *a: subprocess.run(["git", "-C", r, "-c", "user.name=t", "-c", "user.email=t@x", *a], check=True, capture_output=True)
g("init", "-q"); g("add", "-A"); g("commit", "-q", "-m", "x")
json.dump(dict({"lists": {}, "versions": {}, "prs": []}, **fx), open(work + "/fx-nf.json", "w"))
os.environ["GH_FILES"] = json.dumps(remote); os.environ["GH_LOG"] = work + "/nf.issues"
open(os.environ["GH_LOG"], "w").close()
gh = work + "/gh-files"
aud = load("pin-audit")
live = aud.LiveNet([gh], "/nonexistent")
aud.FixtureNet.nested = lambda self, item: live.nested(item)
out, err = io.StringIO(), io.StringIO()
with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
    rc = aud.main(["--root", r, "--fixtures", work + "/fx-nf.json", "--now", "2026-10-05T12:00:00Z", "--gh", gh])
text = out.getvalue() + err.getvalue() + open(os.environ["GH_LOG"]).read()
if want == "clean":
    assert rc == 0 and not open(os.environ["GH_LOG"]).read(), ("want exit 0 and no issue", rc, text[-600:])
    sys.exit(0)
assert rc == 1, ("want exit 1", rc, text[-600:])
assert named in text, ("the output does not name " + named, text[-600:])
if want == "finding":
    assert "incomplete" not in text.lower() and "could not be read" not in text, text[-600:]
PY
for c in local-yml-read local-yaml-read remote-yml-read remote-yaml-read remote-sub-yaml-read; do
  CASE="an action read from its action file ($c): the action it calls inside is checked, so a compromised one is a hit on it (exit 1)"
  check python3 "$work/nested-find.py" "$work/pre.py" "$work" "$c"
done
CASE="a valid local action (action.yml in the checkout): exit 0, no issue filed"
check python3 "$work/nested-find.py" "$work/pre.py" "$work" local-clean
for c in local-neither local-dir-no-file remote-neither remote-sub-neither remote-reusable-workflow; do
  CASE="an action with no action.yml or action.yaml, or a remote reusable workflow ($c): a finding on that item (exit 1, "
  CASE+="named), never an incomplete run"
  check python3 "$work/nested-find.py" "$work/pre.py" "$work" "$c"
done

echo "s2-p2-strict-lookups: $pass ok, $failn failed"
[ "$failn" -eq 0 ]
