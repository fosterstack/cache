#!/usr/bin/env bash
# proves: REQ-SUP-001-AC5
# cache#359 round 5, section 2, group P2, rows "exact 404 token" and "a 404 on a list endpoint is Fail":
#   (1) "not there" is gh's exact status token (HTTP 404, 410 or 422), never the digits anywhere in gh's output: a 403 whose URL, id or body holds 404 is a
#       failure to look (CouldNotLook / Fail), not "absent".
#   (2) strict mode: a 404 on a list endpoint (a path with '?') is Fail, never "no advisories"; a 404 on a single record stays "absent" (None).
# Written from the English rows only; gh is a script on a scratch path, the helpers are called in-process.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
export SC="$here/../supply-chain"
work=$(mktemp -d -t s2p2-gh404.XXXXXX); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
ok()  { pass=$((pass+1)); echo "ok   $1"; }
bad() { failn=$((failn+1)); echo "FAIL $1"; }
CASE=""
check() { if "$@" >"$work/last.out" 2>&1; then ok "$CASE"; else bad "$CASE"; sed 's/^/     | /' "$work/last.out" | tail -5; fi; }
cat >"$work/pre.py" <<'PY'
import importlib.util, os, sys, types
D = os.environ["SC"]
def load(n):
    s = importlib.util.spec_from_file_location(n.replace("-", "_") + "_t", os.path.join(D, n + ".py"))
    m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
def res(err="", out="", rc=1): return types.SimpleNamespace(returncode=rc, stderr=err, stdout=out)
def raises(exc, fn):
    try: fn()
    except exc: return True
    return False
PY
# a gh that prints STDERR text from $GH_ERR and exits 1
cat >"$work/gh" <<'SH'
#!/bin/sh
printf '%s\n' "$GH_ERR" >&2; exit 1
SH
chmod +x "$work/gh"

for tok in 404 410 422; do
  CASE="_gh_failed: gh's exact status token (HTTP $tok) is 'not there' (True, no exception)"
  check python3 - "$work/pre.py" "$tok" <<'PY'
import sys; exec(open(sys.argv[1]).read())
age = load("pin-age-check")
assert age._gh_failed(res("gh: Not Found (HTTP %s)" % sys.argv[2])) is True
PY
done
for body in \
  "gh: Resource not accessible by integration (HTTP 403)|https://api.github.com/repos/o/r404/git/ref/tags/v1" \
  "gh: API rate limit exceeded for user ID 40404. (HTTP 403)|" \
  "gh: Server Error (HTTP 500)|repos/o/r/git/ref/tags/v4.0.4040" \
  "gh: Forbidden (HTTP 403)|{\"message\":\"x\",\"documentation_url\":\"https://docs.github.com/rest/404-not-found\"}" \
  "gh: Bad credentials (HTTP 401)|request id 7E04:404E:1" \
  "gh: Resource not accessible by integration (HTTP 403)|https://api.github.com/repos/o/r/contents/404/action.yml" \
  "gh: Bad Gateway (HTTP 502)|upstream sent 404 to the proxy" ; do
  CASE="_gh_failed: '${body%%|*}' with 404 elsewhere in the output is a failure to look (CouldNotLook), not 'not there'"
  check python3 - "$work/pre.py" "$body" <<'PY'
import sys; exec(open(sys.argv[1]).read())
age = load("pin-age-check")
err, _, out = sys.argv[2].partition("|")
assert raises(age.CouldNotLook, lambda: age._gh_failed(res(err, out))), "digits 404 in a longer text read as 'not there'"
PY
done
CASE="_gh_api: a 403 whose URL contains 404 raises CouldNotLook instead of returning None"
check python3 - "$work/pre.py" "$work/gh" <<'PY'
import sys; exec(open(sys.argv[1]).read())
age = load("pin-age-check")
os.environ["PATH"] = os.path.dirname(sys.argv[2]) + ":" + os.environ["PATH"]
os.environ["GH_ERR"] = "gh: Forbidden (HTTP 403)  https://api.github.com/repos/o/404/releases/tags/v1"
assert raises(age.CouldNotLook, lambda: age._gh_api("repos/o/404/releases/tags/v1", (("tag_name", str),)))
PY
CASE="_gh_api: a real 404 still means 'not there' (None)"
check python3 - "$work/pre.py" "$work/gh" <<'PY'
import sys; exec(open(sys.argv[1]).read())
age = load("pin-age-check")
os.environ["PATH"] = os.path.dirname(sys.argv[2]) + ":" + os.environ["PATH"]
os.environ["GH_ERR"] = "gh: Not Found (HTTP 404)"
assert age._gh_api("repos/o/r/releases/tags/v1", (("tag_name", str),)) is None
PY

LN='aud = load("pin-audit"); net = aud.LiveNet([sys.argv[2]], "/nonexistent")'
CASE="pin-audit _gh_json (strict): a 403 whose URL contains 404 is Fail, not 'absent'"
check python3 - "$work/pre.py" "$work/gh" <<PY
import sys; exec(open(sys.argv[1]).read()); $LN
os.environ["GH_ERR"] = "gh: Forbidden (HTTP 403)  https://api.github.com/repos/o/404/contents/action.yml"
for strict in (True, False):
    assert raises(aud.Fail, lambda: net._gh_json("repos/o/404/contents/action.yml", need=(("content", str),), strict=strict)), strict
PY
CASE="pin-audit _gh_json (strict): a 404 on a single record is still absent (None)"
check python3 - "$work/pre.py" "$work/gh" <<PY
import sys; exec(open(sys.argv[1]).read()); $LN
os.environ["GH_ERR"] = "gh: Not Found (HTTP 404)"
assert net._gh_json("repos/o/r/git/ref/tags/v1", need=(("object", dict),), strict=True) is None
PY
CASE="pin-audit _gh_json (strict): a 404 on a list endpoint (path with ?) is Fail, never 'no advisories'"
check python3 - "$work/pre.py" "$work/gh" <<PY
import sys; exec(open(sys.argv[1]).read()); $LN
os.environ["GH_ERR"] = "gh: Not Found (HTTP 404)"
p = "advisories?ecosystem=pip&affects=requests&per_page=100&page=1"
assert raises(aud.Fail, lambda: net._gh_json(p, rows=(("ghsa_id", str),), strict=True)), "list 404 read as an empty list"
PY
CASE="pin-audit _gh_json (strict): a 404 on a list endpoint is Fail for a releases list too"
check python3 - "$work/pre.py" "$work/gh" <<PY
import sys; exec(open(sys.argv[1]).read()); $LN
os.environ["GH_ERR"] = "gh: Not Found (HTTP 404)"
assert raises(aud.Fail, lambda: net._gh_json("repos/o/r/releases?per_page=100&page=1", rows=(("tag_name", str),), strict=True))
PY
CASE="pin-audit: the advisory list of a package whose GitHub list answers 404 ends lists() in Fail, not in an empty advisory list"
check python3 - "$work/pre.py" "$work/gh" <<PY
import sys, urllib.request, urllib.error, json; exec(open(sys.argv[1]).read()); $LN
os.environ["GH_ERR"] = "gh: Not Found (HTTP 404)"
class R:
    def __init__(s, b): s.b = json.dumps(b).encode()
    def read(s, n=-1): return s.b
    def __enter__(s): return s
    def __exit__(s, *a): return False
def fake(req, timeout=None, **kw):
    url = req if isinstance(req, str) else req.full_url
    if "api.osv.dev/v1/query" in url: return R({})
    if "pypi.org" in url: return R({"info": {"name": "requests"}})
    raise urllib.error.HTTPError(url, 404, "nf", {}, None)
urllib.request.urlopen = fake
it = aud.inv.Item("package", "pypi/requests", "2.32.0")
assert raises(aud.Fail, lambda: net.lists(it)), "a 404 on the advisory list read as no advisories"
PY

echo "s2-p2-gh-404: $pass ok, $failn failed"
[ "$failn" -eq 0 ]
