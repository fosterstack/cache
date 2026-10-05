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
bindir, mode, outp = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, bindir)
spec = importlib.util.spec_from_file_location("ap", bindir + "/auditor-panel.py"); ap = importlib.util.module_from_spec(spec); spec.loader.exec_module(ap)
d, repo = tempfile.mkdtemp(), tempfile.mkdtemp()
subprocess.run(["git", "-C", repo, "init", "-q"])
json.dump({}, open(d + "/state.json", "w"))
json.dump({"vex": [], "profiles": [], "issue": "tracking body", "owner": ["decide x"]}, open(d + "/day.json", "w"))
calls = []
labels = {"daily-rescan", "security", "owner-decision"} if mode == "exists" else set()     # the repository's labels, as a STATE
def run(cmd, **kw):
    calls.append(cmd)
    if cmd[:3] == ["gh", "label", "create"]:
        if mode == "denied":
            return types.SimpleNamespace(returncode=1, stdout="", stderr="HTTP 403: Resource not accessible by integration")
        if cmd[3] in labels:
            return types.SimpleNamespace(returncode=1, stdout="", stderr='label with name "%s" already exists' % cmd[3])
        labels.add(cmd[3]); return types.SimpleNamespace(returncode=0, stdout="", stderr="")
    if cmd[:3] == ["gh", "issue", "create"]:
        for i, x in enumerate(cmd):
            if x == "--label" and cmd[i + 1] not in labels:
                return types.SimpleNamespace(returncode=1, stdout="", stderr="could not add label: '%s' not found" % cmd[i + 1])
    return types.SimpleNamespace(returncode=0, stdout="", stderr="")
os.environ["AUDITOR_ALLOW_REAL_GH"] = "1"
a = types.SimpleNamespace(out=d, repo=repo, today="2026-10-05", dry_run=False)
res = {"calls": calls}
try:
    res["rc"] = ap.cmd_deliver(a, run=run)
except Exception as e:
    res["error"] = "%s: %s" % (type(e).__name__, e)
json.dump(res, open(outp, "w"))
PY
for mode in ok exists denied; do
  python3 "$work/deliver.py" "$bin" "$mode" "$work/deliver-$mode.json" >/dev/null 2>"$work/deliver-$mode.err" || true
done
CASE="panel: before each issue create the labels that create passes are created (tracking: daily-rescan, security; owner report: owner-decision)"
check python3 - "$work/deliver-ok.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); calls = d["calls"]; assert d.get("rc") == 0, d
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
d = json.load(open(sys.argv[1])); assert d.get("rc") == 0, d
assert len([c for c in d["calls"] if c[:3] == ["gh", "issue", "create"]]) == 2, d["calls"]
PY
CASE="panel: when a label cannot be created (403) the issue create is still attempted and ITS error (the missing label) is what surfaces, never a silent success"
check python3 - "$work/deliver-denied.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert "rc" not in d and "could not add label" in d.get("error", ""), d
assert [c for c in d["calls"] if c[:3] == ["gh", "issue", "create"]], d
PY
CASE="panel: starting from NO labels, delivery succeeds only because each label was created first (the fake refuses an issue whose label does not exist)"
check python3 - "$work/deliver-ok.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); assert d.get("rc") == 0 and "error" not in d, d
PY
CASE="panel: the delivery code creates the three labels through policy.label_create_cmd and never forces"
check python3 - "$bin" <<'PY'
import sys
src = open(sys.argv[1] + "/auditor-panel.py").read()
import re
assert not re.search(r'label[^\n]*--force', src), "a label command must never force (git's own --force on branches is unrelated)"
assert src.count("label_create_cmd") >= 2 and '("daily-rescan", "security")' in src, "the panel must ensure daily-rescan, security and owner-decision"
PY

# --- the main auditor's two owner-issue paths, EXECUTED against the same stateful fake ------------------------------------
cat >"$work/driver.py" <<'PY'
import importlib.util, json, os, subprocess, sys, types
bindir, which, outp = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, bindir)
spec = importlib.util.spec_from_file_location("r", bindir + "/auditor-run.py"); R = importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
calls, labels = [], set()
def fake(cmd, *a, **kw):
    calls.append(cmd)
    out = lambda rc=0, so="", se="": types.SimpleNamespace(returncode=rc, stdout=so, stderr=se)
    if cmd[:3] == ["gh", "label", "create"]:
        if cmd[3] in labels:
            return out(1, se='label with name "%s" already exists' % cmd[3])
        labels.add(cmd[3]); return out()
    if cmd[:3] == ["gh", "issue", "list"]:
        return out(0, "[]")
    if cmd[:3] == ["gh", "issue", "create"]:
        for i, x in enumerate(cmd):
            if x == "--label" and cmd[i + 1] not in labels:
                return out(1, se="could not add label: '%s' not found" % cmd[i + 1])
        return out(0, "https://github.com/x/y/issues/7\n")
    return out()
R.subprocess.run = fake
os.environ["AUDITOR_ALLOW_REAL_GH"] = "1"; os.environ.pop("AUDITOR_GIT_SHIM_LOG", None)
if which == "owner":
    ok, ref = R._emit_owner_issue("owner-decision: x", "body", False, [], ())
else:
    ok, ref = R._standing_issue(["an item"], False, [])
json.dump({"ok": ok, "ref": ref, "calls": calls}, open(outp, "w"))
PY
for which in owner standing; do
  python3 "$work/driver.py" "$bin" "$which" "$work/driver-$which.json" >/dev/null 2>"$work/driver-$which.err" || true
  CASE="auditor-run.py ($which issue): starting from no labels, the issue is created (the fake refuses it unless owner-decision was created first), and the label is created BEFORE the issue"
  check python3 - "$work/driver-$which.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); calls = d["calls"]
assert d["ok"] is True, d
mk = [i for i, c in enumerate(calls) if c[:4] == ["gh", "label", "create", "owner-decision"]]
cr = [i for i, c in enumerate(calls) if c[:3] == ["gh", "issue", "create"]]
assert mk and cr and mk[0] < cr[0], calls
PY
done

# --- the rescan workflow's tracking-issue step (the third creator the first review found) --------------------------------
CASE="main-candidate-rescan.yml: the step that creates the tracking issue creates daily-rescan and security first, with the very descriptions and colours policy.py holds"
check python3 - "$root" <<'PY'
import re, sys, yaml
root = sys.argv[1]
sys.path.insert(0, root + "/.github/agent/bin")
from auditorlib import policy
wf = yaml.safe_load(open(root + "/.github/workflows/main-candidate-rescan.yml"))
runs = [str(s.get("run", "")) for j in wf["jobs"].values() for s in j.get("steps", []) if "gh issue create" in str(s.get("run", ""))]
assert len(runs) == 1, runs
run = runs[0]
create = run.index("gh issue create --title")
for name in ("daily-rescan", "security"):
    m = re.search(r'gh label create ' + name + r' --description "([^"]*)" --color ([0-9A-Fa-f]{6})', run)
    assert m and m.start() < create, ("label not created before the issue", name)
    assert (m.group(1), m.group(2)) == policy.LABELS[name], ("drifted from policy.LABELS", name, m.groups(), policy.LABELS[name])
assert "--force" not in run
PY

echo "auditor-labels: $pass passed, $failn failed"
test "$failn" -eq 0
