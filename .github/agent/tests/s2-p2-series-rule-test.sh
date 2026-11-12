#!/usr/bin/env bash
# proves: REQ-SUP-001-AC2, REQ-SUP-001-AC3
# cache#359 round 5, section 2, group P2, row "a series is not a pin": for EVERY installer-input tool (INSTALLER_INPUTS of pin-inventory.py: golangci-lint,
# python, java, node, goreleaser, cosign, gcloud, helm, buildx, kind, kubectl) a version of fewer than three numeric parts (v2.1, 2.1, 3) is a series, not an
# exact release: the age judge refuses it ("not a pin"/"series") whatever proof it is given. Three numeric parts still pass with an old enough proof.
# Written from the English rows only; judge_item is called in-process.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
export SC="$here/../supply-chain"
work=$(mktemp -d -t s2p2-series.XXXXXX); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
ok()  { pass=$((pass+1)); echo "ok   $1"; }
bad() { failn=$((failn+1)); echo "FAIL $1"; }
CASE=""
check() { if "$@" >"$work/last.out" 2>&1; then ok "$CASE"; else bad "$CASE"; sed 's/^/     | /' "$work/last.out" | tail -5; fi; }
cat >"$work/pre.py" <<'PY'
import datetime as dt, importlib.util, os, sys
D = os.environ["SC"]
def load(n):
    s = importlib.util.spec_from_file_location(n.replace("-", "_") + "_t", os.path.join(D, n + ".py"))
    m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
NOW = dt.datetime(2026, 10, 5, 12, tzinfo=dt.timezone.utc)
OLD = (NOW - dt.timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
age = load("pin-age-check")
TOOLS = sorted({t for ins in age.inv.INSTALLER_INPUTS.values() for _, t in ins if t})
PY
CASE="the installer-input tool list is the eleven the rows name (the loop below covers every one of them)"
check python3 - "$work/pre.py" <<'PY'
import sys; exec(open(sys.argv[1]).read())
assert TOOLS == sorted("golangci-lint python java node goreleaser cosign gcloud helm buildx kind kubectl".split()), TOOLS
PY
CASE="every installer-input tool: a two-part version (v2.1 and 2.1) is a series, refused as 'not a pin' even with a 30-day-old release proof"
check python3 - "$work/pre.py" <<'PY'
import sys; exec(open(sys.argv[1]).read())
bad = []
for t in TOOLS:
    for v in ("v2.1", "2.1", "v2", "2"):
        ok, why, proof = age.judge_item(age.inv.Item("tool", t, v), [(OLD, "github-release")], NOW)
        if ok or not ("series" in why or "not a pin" in why):
            bad.append((t, v, ok, why))
assert not bad, bad
PY
for t in golangci-lint helm kind buildx; do
  CASE="$t: v2.1 is not a pin (the rows name this tool), with a reason saying so"
  check python3 - "$work/pre.py" "$t" <<'PY'
import sys; exec(open(sys.argv[1]).read())
ok, why, proof = age.judge_item(age.inv.Item("tool", sys.argv[2], "v2.1"), [(OLD, "github-release")], NOW)
assert not ok and ("series" in why or "not a pin" in why), (ok, why)
PY
done
CASE="every installer-input tool: three numeric parts (v2.1.3 and 2.1.3) still pass with an old enough release proof"
check python3 - "$work/pre.py" <<'PY'
import sys; exec(open(sys.argv[1]).read())
bad = []
for t in TOOLS:
    for v in ("v2.1.3", "2.1.3"):
        ok, why, proof = age.judge_item(age.inv.Item("tool", t, v), [(OLD, "github-release")], NOW)
        if not ok:
            bad.append((t, v, why))
assert not bad, bad
PY
CASE="a tool that no installer input names (a release asset download, trivy) is not touched by the rule: 0.74.0 passes"
check python3 - "$work/pre.py" <<'PY'
import sys; exec(open(sys.argv[1]).read())
ok, why, proof = age.judge_item(age.inv.Item("tool", "trivy", "0.74.0"), [(OLD, "github-release")], NOW)
assert ok, why
PY
echo "s2-p2-series-rule: $pass ok, $failn failed"
[ "$failn" -eq 0 ]
