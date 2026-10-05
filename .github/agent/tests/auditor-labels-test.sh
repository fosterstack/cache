#!/usr/bin/env bash
# proves: REQ-SCAN-005-AC1, REQ-SCAN-009-AC5
# The first live auditor run (Oct 5) delivered its draft PR and then died creating the owner-report issue: `gh issue create --label
# owner-decision` fails when the label does not exist, and the repository only had GitHub's defaults. A report must never be lost to a
# missing label, so every issue the auditor opens first makes sure its labels exist: `gh label create <name> --description --color` (NOT
# --force: that would overwrite the colour and description of a label that already exists, such as `security`), tolerating
# "already exists". Proved here on the panel's delivery (a recording runner) and the main auditor's owner-issue paths.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
bin="$root/.github/agent/bin"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
ok()  { pass=$((pass+1)); echo "ok   $1"; }
bad() { failn=$((failn+1)); echo "FAIL $1"; }
CASE=""
check() { if "$@" >/dev/null 2>&1; then ok "$CASE"; else bad "$CASE"; fi; }

CASE="policy names the three labels the delivery uses, each with a description and a colour, and builds a create command without --force"
check python3 - "$bin" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from auditorlib import policy
for name in ("owner-decision", "daily-rescan", "security"):
    c = policy.label_create_cmd(name)
    assert c[:4] == ["gh", "label", "create", name], c
    assert "--force" not in c, "--force would overwrite an existing label's colour and description: " + str(c)
    assert c[c.index("--description") + 1].strip() and len(c[c.index("--color") + 1]) == 6, c
try:
    policy.label_create_cmd("not-a-lane-label")
    raise SystemExit("an unknown label must not be invented")
except KeyError:
    pass
PY

# --- the panel's delivery: every issue create is preceded by the creation of exactly the labels it passes ----------
cat >"$work/deliver.py" <<'PY'
import importlib.util, json, os, subprocess, sys, tempfile, types
bindir, mode = sys.argv[1], sys.argv[2]
sys.path.insert(0, bindir)
spec = importlib.util.spec_from_file_location("ap", bindir + "/auditor-panel.py"); ap = importlib.util.module_from_spec(spec); spec.loader.exec_module(ap)
d, repo = tempfile.mkdtemp(), tempfile.mkdtemp()
subprocess.run(["git", "-C", repo, "init", "-q"])
json.dump({}, open(d + "/state.json", "w"))
json.dump({"vex": [], "profiles": [], "issue": "tracking body", "owner": ["decide x"]}, open(d + "/day.json", "w"))
calls = []
def run(cmd, **kw):
    calls.append(cmd)
    if cmd[:3] == ["gh", "label", "create"]:
        if mode == "exists":
            return types.SimpleNamespace(returncode=1, stdout="", stderr='label with name "%s" already exists' % cmd[3])
        if mode == "denied":
            return types.SimpleNamespace(returncode=1, stdout="", stderr="HTTP 403: Resource not accessible")
    return types.SimpleNamespace(returncode=0, stdout="", stderr="")
os.environ["AUDITOR_ALLOW_REAL_GH"] = "1"
a = types.SimpleNamespace(out=d, repo=repo, today="2026-10-05", dry_run=False)
rc = ap.cmd_deliver(a, run=run)
json.dump({"rc": rc, "calls": calls}, open(sys.argv[3], "w"))
PY
for mode in ok exists denied; do
  python3 "$work/deliver.py" "$bin" "$mode" "$work/deliver-$mode.json" >/dev/null 2>"$work/deliver-$mode.err" || true
done
CASE="panel: before each issue create the labels that create passes are created (tracking: daily-rescan, security; owner report: owner-decision)"
check python3 - "$work/deliver-ok.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); calls = d["calls"]; assert d["rc"] == 0, d
def idx(pred): return [i for i, c in enumerate(calls) if pred(c)]
creates = idx(lambda c: c[:3] == ["gh", "issue", "create"])
assert len(creates) == 2, calls
for i in creates:
    want = [calls[i][j + 1] for j, x in enumerate(calls[i]) if x == "--label"]
    for lab in want:
        made = idx(lambda c: c[:4] == ["gh", "label", "create", lab])
        assert made and made[0] < i, ("label not created before its issue", lab, calls)
PY
CASE="panel: a label that already exists (create fails with 'already exists') does not stop delivery: both issues are still created, exit 0"
check python3 - "$work/deliver-exists.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); assert d["rc"] == 0, d
assert len([c for c in d["calls"] if c[:3] == ["gh", "issue", "create"]]) == 2, d["calls"]
PY
CASE="panel: when a label cannot be created (403) the issue create is still attempted, so the original error (not a swallowed one) is what surfaces"
check python3 - "$work/deliver-denied.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert len([c for c in d["calls"] if c[:3] == ["gh", "issue", "create"]]) == 2, d
PY
CASE="panel: the delivery code creates the three labels through policy.label_create_cmd and never forces"
check python3 - "$bin" <<'PY'
import sys
src = open(sys.argv[1] + "/auditor-panel.py").read()
import re
assert not re.search(r'label[^\n]*--force', src), "a label command must never force (git's own --force on branches is unrelated)"
assert src.count("label_create_cmd") >= 2 and '("daily-rescan", "security")' in src, "the panel must ensure daily-rescan, security and owner-decision"
PY

# --- the main auditor's two owner-issue paths ensure the label first -----------------------------------------------
CASE="auditor-run.py: both places that create the owner-decision issue run the label creation first (static: the call precedes each create)"
check python3 - "$bin" <<'PY'
import re, sys
src = open(sys.argv[1] + "/auditor-run.py").read()
creates = [m.start() for m in re.finditer(r'"--label", policy\.OWNER_LABEL', src)]
assert len(creates) >= 2, creates
for pos in creates:
    window = src[max(0, pos - 1500):pos]
    assert "label_create_cmd" in window, ("no label creation shortly before the create at", src[:pos].count("\n") + 1)
assert "--force" not in src.split("label_create_cmd", 1)[1][:400]
PY

echo "auditor-labels: $pass passed, $failn failed"
test "$failn" -eq 0
