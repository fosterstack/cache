#!/usr/bin/env bash
# proves: REQ-SUP-001-AC3, REQ-SUP-001-AC15
# cache#359 round 5, section 2, group P2, rows "parse_time rejects +99:99" and "load_exceptions: explicit failure, duplicate-key guard":
#   (1) parse_time validates the UTC offset (hours 00-23, minutes 00-59): +99:99 and its kin are not a time (None); real offsets still parse.
#   (2) pin-audit load_exceptions raises Fail (never an AssertionError, and never a silent pass when assertions are stripped by python -O) on a
#       malformed file, and raises Fail on a repeated JSON key, at the top and inside an exception.
# Written from the English rows only; in-process against the two scripts.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
export SC="$here/../supply-chain"
work=$(mktemp -d -t s2p2-time.XXXXXX); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
ok()  { pass=$((pass+1)); echo "ok   $1"; }
bad() { failn=$((failn+1)); echo "FAIL $1"; }
CASE=""
check() { if "$@" >"$work/last.out" 2>&1; then ok "$CASE"; else bad "$CASE"; sed 's/^/     | /' "$work/last.out" | tail -5; fi; }
cat >"$work/pre.py" <<'PY'
import importlib.util, json, os, sys
D = os.environ["SC"]
def load(n):
    s = importlib.util.spec_from_file_location(n.replace("-", "_") + "_t", os.path.join(D, n + ".py"))
    m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
GOOD = {"ids": ["GHSA-aaaa-bbbb-cccc"], "package": "x", "version": "1.0", "ruling": "r", "evidence": ["e"], "date": "2026-01-01",
        "authoritative": {"source": "github", "id": "GHSA-aaaa-bbbb-cccc", "ranges": ["<2"]}, "modified": {"GHSA-aaaa-bbbb-cccc": "2026-01-01T00:00:00Z"}}
PY

for off in +99:99 +12:99 -99:00 +00:60 +9999 -2460; do
  CASE="parse_time: the offset $off is not a time (None)"
  check python3 - "$work/pre.py" "$off" <<'PY'
import sys; exec(open(sys.argv[1]).read())
age = load("pin-age-check")
assert age.parse_time("2026-10-05T12:00:00" + sys.argv[2]) is None
assert age.parse_time("2026-10-05T12:00:00.5" + sys.argv[2]) is None
assert age.parse_time("2026-10-05T12:00:00" + sys.argv[2], clock=True) is None
PY
done
CASE="parse_time: real offsets still parse (Z, +05:30, -0800, +23:59, -00:00) to the right UTC instant"
check python3 - "$work/pre.py" <<'PY'
import sys; exec(open(sys.argv[1]).read())
age = load("pin-age-check")
t = lambda s: age.parse_time(s).strftime("%Y-%m-%dT%H:%M:%SZ")
assert t("2026-10-05T12:00:00Z") == "2026-10-05T12:00:00Z"
assert t("2026-10-05T12:00:00+05:30") == "2026-10-05T06:30:00Z"
assert t("2026-10-05T12:00:00-0800") == "2026-10-05T20:00:00Z"
assert t("2026-10-05T12:00:00+23:59") == "2026-10-04T12:01:00Z"
assert t("2026-10-05T12:00:00-00:00") == "2026-10-05T12:00:00Z"
PY
CASE="parse_time: a time with no zone is still UTC, and a fractional second still rounds up for a publication time"
check python3 - "$work/pre.py" <<'PY'
import sys; exec(open(sys.argv[1]).read())
age = load("pin-age-check")
assert age.parse_time("2026-10-05T12:00:00").strftime("%H:%M:%S") == "12:00:00"
assert age.parse_time("2026-10-05T12:00:00.2").strftime("%H:%M:%S") == "12:00:01"
PY
CASE="pin-age-check no longer carries _STRICT_TIME (parse_time validates the offset itself)"
check python3 - "$work/pre.py" <<'PY'
import sys; exec(open(sys.argv[1]).read())
age = load("pin-age-check")
assert not hasattr(age, "_STRICT_TIME"), "the one-caller patch is still there"
PY

# --- load_exceptions ------------------------------------------------------------------------------------------------------------
w() { python3 -c 'import json,sys; exec(open(sys.argv[1]).read()); ex=dict(GOOD); exec(sys.argv[3]); json.dump({"exceptions":[ex]}, open(sys.argv[2],"w"))' "$work/pre.py" "$1" "$2"; }
w "$work/good.json" 'pass'
w "$work/emptyver.json" 'ex["version"]=""'
w "$work/idstr.json" 'ex["ids"]="GHSA-aaaa-bbbb-cccc"'
w "$work/ranges.json" 'ex["authoritative"]["ranges"]=[1]'
w "$work/ev.json" 'ex["evidence"]=[]'
printf '{"exceptions": [], "exceptions": []}' >"$work/dup-top.json"
python3 - "$work" <<'PY'
import json, sys
w = sys.argv[1]
good = json.dumps({"ids": ["GHSA-aaaa-bbbb-cccc"], "package": "x", "version": "1.0", "ruling": "r", "evidence": ["e"], "date": "2026-01-01",
  "authoritative": {"source": "github", "id": "GHSA-aaaa-bbbb-cccc", "ranges": ["<2"]}, "modified": {"GHSA-aaaa-bbbb-cccc": "2026-01-01T00:00:00Z"}})
open(w + "/dup-inner.json", "w").write('{"exceptions": [' + good[:-1] + ', "ruling": "a second ruling"}]}')
open(w + "/dup-modified.json", "w").write('{"exceptions": [' + good.replace('"modified": {"GHSA-aaaa-bbbb-cccc": "2026-01-01T00:00:00Z"}', '"modified": {"GHSA-aaaa-bbbb-cccc": "2026-01-01T00:00:00Z", "GHSA-aaaa-bbbb-cccc": "2026-02-01T00:00:00Z"}') + ']}')
PY
CASE="load_exceptions: a well-formed file loads (control)"
check python3 - "$work/pre.py" "$work/good.json" <<'PY'
import sys; exec(open(sys.argv[1]).read())
aud = load("pin-audit")
assert len(aud.load_exceptions(sys.argv[2], True)) == 1
PY
for f in emptyver idstr ranges ev; do
  CASE="load_exceptions: the malformed file '$f' raises Fail (not an AssertionError)"
  check python3 - "$work/pre.py" "$work/$f.json" <<'PY'
import sys; exec(open(sys.argv[1]).read())
aud = load("pin-audit")
try: aud.load_exceptions(sys.argv[2], True)
except aud.Fail as e: assert str(e).strip(), "empty message"
else: raise SystemExit("no failure")
PY
  CASE="load_exceptions: the malformed file '$f' raises Fail even under python -O (no assert doing the validation)"
  check python3 -O - "$work/pre.py" "$work/$f.json" <<'PY'
import sys; exec(open(sys.argv[1]).read())
aud = load("pin-audit")
try: aud.load_exceptions(sys.argv[2], True)
except aud.Fail: pass
else: raise SystemExit("python -O: the malformed file was accepted")
PY
done
for f in dup-top dup-inner dup-modified; do
  CASE="load_exceptions: a repeated JSON key ($f) raises Fail naming the file"
  check python3 - "$work/pre.py" "$work/$f.json" <<'PY'
import sys; exec(open(sys.argv[1]).read())
aud = load("pin-audit")
try: aud.load_exceptions(sys.argv[2], True)
except aud.Fail as e: assert sys.argv[2] in str(e), str(e)
else: raise SystemExit("a repeated key was accepted")
PY
done
CASE="pin-audit end to end: a repeated key in --exceptions ends the run with exit 2 and 'cannot do its job'"
mkdir -p "$work/r/.github/workflows"
printf 'on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n' >"$work/r/.github/workflows/ci.yml"
git -C "$work/r" init -q; git -C "$work/r" add -A; git -C "$work/r" -c user.name=t -c user.email=t@x commit -q -m x
echo '{"lists": {}, "versions": {}, "prs": []}' >"$work/fx.json"
rc=0; python3 "$SC/pin-audit.py" --root "$work/r" --fixtures "$work/fx.json" --now 2026-10-05T12:00:00Z --gh true --exceptions "$work/dup-top.json" >"$work/e2e.out" 2>"$work/e2e.err" || rc=$?
check test "$rc" -eq 2
CASE="pin-audit end to end: the stderr says 'cannot do its job'"
check grep -q 'cannot do its job' "$work/e2e.err"

echo "s2-p2-time-exceptions: $pass ok, $failn failed"
[ "$failn" -eq 0 ]
