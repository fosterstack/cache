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
    if cmd[:2] == ["gh", "api"]:       # the signed delivery's API calls (advisor 0209): a ref read, the commit mutation, the PR head
        if "graphql" in cmd:
            return types.SimpleNamespace(returncode=0, stderr="", stdout=json.dumps({"data": {"createCommitOnBranch": {"commit": {"oid": "b" * 40, "signature": {"isValid": True, "state": "VALID"}}}}}))
        if any("git/ref/heads" in x for x in cmd) and "--method" not in cmd:
            return types.SimpleNamespace(returncode=0, stderr="", stdout=("c" * 40 + "\n") if "--jq" in cmd else json.dumps({"object": {"sha": "c" * 40}}))
    if cmd[:3] == ["gh", "pr", "view"]:
        return types.SimpleNamespace(returncode=0, stderr="", stdout=("b" * 40 + "\n") if "--jq" in cmd else json.dumps({"headRefOid": "b" * 40, "autoMergeRequest": None}))
    return types.SimpleNamespace(returncode=0, stdout="", stderr="")
os.environ["AUDITOR_ALLOW_REAL_GH"] = "1"
os.environ["GITHUB_REPOSITORY"] = "o/r"; os.environ["GITHUB_SHA"] = "a" * 40
ss = os.path.join(d, "state-source"); open(ss, "w").write("")       # a real delivery needs the state-source record (here: no open PR was read)
a = types.SimpleNamespace(out=d, repo=repo, today="2026-10-05", dry_run=False, state_source=ss)
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
mode = sys.argv[4] if len(sys.argv) > 4 else "missing"
sys.path.insert(0, bindir)
spec = importlib.util.spec_from_file_location("r", bindir + "/auditor-run.py"); R = importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
calls, labels, tokens = [], ({"owner-decision"} if mode == "exists" else set()), []
def fake(cmd, *a, **kw):
    calls.append(cmd)
    if cmd[:3] == ["gh", "label", "create"]:
        tokens.append((kw.get("env") or {}).get("GH_TOKEN"))
    out = lambda rc=0, so="", se="": types.SimpleNamespace(returncode=rc, stdout=so, stderr=se)
    if cmd[:3] == ["gh", "label", "create"]:
        if mode == "denied":
            return out(1, se="HTTP 403: Resource not accessible")
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
json.dump({"ok": ok, "ref": ref, "calls": calls, "tokens": tokens}, open(outp, "w"))
PY
for which in owner standing; do
  for mode in missing exists denied; do
    AUDITOR_ISSUES_TOKEN=issues-token-xyz GH_TOKEN=job-token-abc python3 "$work/driver.py" "$bin" "$which" "$work/driver-$which-$mode.json" "$mode" >/dev/null 2>"$work/driver-$which.err" || true
  done
  cp "$work/driver-$which-missing.json" "$work/driver-$which.json"
  CASE="auditor-run.py ($which issue): an existing label (create fails 'already exists') does not stop the issue"
  check python3 - "$work/driver-$which-exists.json" <<'PY'
import json, sys
assert json.load(open(sys.argv[1]))["ok"] is True
PY
  CASE="auditor-run.py ($which issue): a label that cannot be created (403) leaves the issue create to fail with its OWN error: the result is failure, never a false 'opened'"
  check python3 - "$work/driver-$which-denied.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["ok"] is False, d
assert [c for c in d["calls"] if c[:3] == ["gh", "issue", "create"]], "the issue create must still be attempted"
PY
  CASE="auditor-run.py ($which issue): the label call carries the issues token (AUDITOR_ISSUES_TOKEN), like the issue calls"
  check python3 - "$work/driver-$which-missing.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["tokens"] and all(t == "issues-token-xyz" for t in d["tokens"]), d["tokens"]
PY
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

# --- the rescan workflows' tracking-issue creators, EXECUTED (two of them: a bash step with gh, and a github-script step with Octokit) -------
python3 - "$root" "$work" <<'PY'
import re, sys, yaml
root, work = sys.argv[1], sys.argv[2]
wf = yaml.safe_load(open(root + "/.github/workflows/main-candidate-rescan.yml"))
steps = [s for j in wf["jobs"].values() for s in j.get("steps", [])]
bash = [s for s in steps if "gh issue create" in str(s.get("run", ""))]
js = [s for s in steps if "github.rest.issues.create(" in str(s.get("with", {}).get("script", ""))]
assert len(bash) == 1 and len(js) == 1, (len(bash), len(js))
open(work + "/rescan-step.sh", "w").write(bash[0]["run"])
src = js[0]["with"]["script"].replace("${{ toJSON(matrix.target) }}", '{"release":"v0.2.0","variant":"production","digest":"sha256:' + "a" * 64 + '","scanner":"grype"}')
open(work + "/rescan-step.js", "w").write(src)
PY
# a stateful gh: the repository's labels are files; `issue create --label X` fails unless X exists
mkdir -p "$work/ghbin"
cat >"$work/ghbin/gh" <<'SH'
#!/usr/bin/env bash
L="$GH_STATE/labels"; mkdir -p "$L"
case "$1 $2" in
  "label create") [ "${GH_DENY_LABELS:-}" = 1 ] && { echo "HTTP 403" >&2; exit 1; }; [ -e "$L/$3" ] && { echo "label with name \"$3\" already exists" >&2; exit 1; }; : >"$L/$3"; exit 0 ;;
  "issue list") exit 0 ;;
  "issue create") prev=""; for a in "$@"; do [ "$prev" = --label ] && [ ! -e "$L/$a" ] && { echo "could not add label: '$a' not found" >&2; exit 1; }; prev="$a"; done; echo created >"$GH_STATE/created"; exit 0 ;;
esac
exit 0
SH
chmod +x "$work/ghbin/gh"
runbash() { # <name> <pre-existing labels...>; env GH_DENY_LABELS passes through
  local n=$1; shift; export GH_STATE="$work/gs-$n"; rm -rf "$GH_STATE"; mkdir -p "$GH_STATE/labels" /tmp/panel-out
  for l in "$@"; do : >"$GH_STATE/labels/$l"; done
  printf 'finding body\n' >/tmp/panel-out/issue.md
  rc=0; PATH="$work/ghbin:$PATH" GITHUB_SHA=abc RUN_URL=http://x bash -e "$work/rescan-step.sh" >/dev/null 2>"$GH_STATE/err" || rc=$?
}
runbash none
CASE="rescan workflow (gh step): starting from NO labels the tracking issue is created (the stateful gh refuses it unless daily-rescan and security exist first)"
check test "$rc" -eq 0 -a -e "$work/gs-none/created"
runbash both daily-rescan security
CASE="rescan workflow (gh step): with both labels already present it still creates the issue (an 'already exists' failure is tolerated)"
check test "$rc" -eq 0 -a -e "$work/gs-both/created"
GH_DENY_LABELS=1 runbash denied
CASE="rescan workflow (gh step): if the labels cannot be created, the step FAILS with the issue create's own error (no silent success)"
check test "$rc" -ne 0 -a ! -e "$work/gs-denied/created"
check grep -q "could not add label" "$work/gs-denied/err"
unset GH_DENY_LABELS
cat >"$work/runjs.js" <<'JS'
const fs = require("fs");
const [, , scriptPath, mode, outPath] = process.argv;
const labels = new Set(mode === "both" ? ["daily-rescan", "security"] : []);
const calls = [];
const github = { rest: { issues: {
  listForRepo: async () => ({ data: [] }),
  createComment: async () => ({}),
  createLabel: async ({ name }) => {
    calls.push("createLabel:" + name);
    if (mode === "denied") { const e = new Error("Resource not accessible"); e.status = 403; throw e; }
    if (labels.has(name)) { const e = new Error("Validation Failed: already_exists"); e.status = 422; throw e; }
    labels.add(name); return {};
  },
  create: async ({ labels: want }) => {
    calls.push("create:" + want.join(","));
    for (const l of want) if (!labels.has(l)) { const e = new Error("Validation Failed: label " + l + " does not exist"); e.status = 422; throw e; }
    return { data: { number: 1 } };
  },
} } };
const context = { repo: { owner: "o", repo: "r" }, serverUrl: "https://github.com", runId: 1 };
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const fn = new AsyncFunction("github", "context", "core", fs.readFileSync(scriptPath, "utf8"));
fn(github, context, {}).then(() => fs.writeFileSync(outPath, JSON.stringify({ ok: true, calls })),
  (e) => fs.writeFileSync(outPath, JSON.stringify({ ok: false, error: String(e.message), calls })));
JS
for mode in none both denied; do node "$work/runjs.js" "$work/rescan-step.js" "$mode" "$work/js-$mode.json" >/dev/null 2>&1 || true; done
CASE="rescan workflow (github-script step): starting from NO labels the tracking issue is created, the labels having been created first"
check python3 - "$work/js-none.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); c = d["calls"]
assert d["ok"] is True, d
assert [x for x in c if x.startswith("createLabel:daily-rescan")] and [x for x in c if x.startswith("createLabel:security")], c
assert max(i for i, x in enumerate(c) if x.startswith("createLabel")) < c.index("create:daily-rescan,security"), c
PY
CASE="rescan workflow (github-script step): existing labels (a 422 on create) do not stop it"
check python3 - "$work/js-both.json" <<'PY'
import json, sys
assert json.load(open(sys.argv[1]))["ok"] is True
PY
CASE="rescan workflow (github-script step): when the labels cannot be created the issue create's own validation error is what surfaces"
check python3 - "$work/js-denied.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["ok"] is False and "does not exist" in d["error"], d
PY
CASE="the labels both workflow steps create carry exactly the descriptions and colours policy.py holds"
check python3 - "$root" "$work" <<'PY'
import re, sys
root, work = sys.argv[1], sys.argv[2]
sys.path.insert(0, root + "/.github/agent/bin")
from auditorlib import policy
sh, js = open(work + "/rescan-step.sh").read(), open(work + "/rescan-step.js").read()
for name in ("daily-rescan", "security"):
    m = re.search(r'gh label create ' + name + r' --description "([^"]*)" --color ([0-9A-Fa-f]{6})', sh)
    assert m and (m.group(1), m.group(2)) == policy.LABELS[name], ("bash step drifted", name)
    m = re.search(r"\[\s*'" + name + r"'\s*,\s*(?:\"([^\"]*)\"|'([^']*)')\s*,\s*'([0-9A-Fa-f]{6})'\s*\]", js)
    assert m and (m.group(1) or m.group(2), m.group(3)) == policy.LABELS[name], ("script step drifted", name)
assert "--force" not in sh
PY

echo "auditor-labels: $pass passed, $failn failed"
test "$failn" -eq 0
