#!/usr/bin/env bash
# proves: REQ-REL-014-AC1, REQ-REL-014-AC2, REQ-REL-014-AC3
# Pull requests run six checks (test, lint, govulncheck, analyze (go), fips140-only, scan with the jobs scan needs), the held check
# marker-gate, customer-words-edited, agent-review-gate.yml and dependabot-auto-merge.yml; every other job runs on push to main, on a
# schedule or in the release chain (REQ-REL-014-AC1). supply-chain.yml has no pull_request trigger, no pin-age job and runs only its
# daily audit; required-checks.json has no pin-age entry (AC2) and no acceptance entry, and every check it scopes to push is produced by a
# job that runs on push (AC3). Reads the committed workflows and required-checks.json.
set -uo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out=$(python3 -I - "$root" <<'PY'
import glob, json, os, sys
import yaml
root = sys.argv[1]
wf = {os.path.basename(f): yaml.safe_load(open(f)) for f in glob.glob(root + "/.github/workflows/*.yml")}
results = []
def res(ok, label): results.append(("ok: " if ok else "FAIL: ") + label)

def triggers(d):
    on = d.get(True) if True in d else d.get("on")
    if isinstance(on, str): return {on: None}
    if isinstance(on, list): return {e: None for e in on}
    return on or {}

# An `if` is judged for one event name. Only comparisons of github.event_name are decided; every other atom (always(),
# !cancelled(), a field of the event) may be true, so the job may run. Parentheses are respected at the top level.
def split_top(expr, op):
    parts, depth, cur, i = [], 0, "", 0
    while i < len(expr):
        c = expr[i]
        depth += (c == "(") - (c == ")")
        if depth == 0 and expr.startswith(op, i):
            parts.append(cur); cur = ""; i += len(op); continue
        cur += c; i += 1
    return parts + [cur]
def wrapped(s):   # the first "(" closes at the very end
    depth = 0
    for i, c in enumerate(s):
        depth += (c == "(") - (c == ")")
        if depth == 0 and i < len(s) - 1: return False
    return True
def runs_on(cond, event):
    if cond is None: return True
    s = str(cond).strip()
    if s.startswith("${{") and s.endswith("}}"): s = s[3:-2].strip()
    return judge(s, event)
def judge(s, event):
    s = s.strip()
    while s.startswith("(") and s.endswith(")") and wrapped(s):
        s = s[1:-1].strip()
    ors = split_top(s, "||")
    if len(ors) > 1: return any(judge(p, event) for p in ors)
    ands = split_top(s, "&&")
    if len(ands) > 1: return all(judge(p, event) for p in ands)
    for op in ("==", "!="):
        pre = "github.event_name " + op + " '"
        if s.startswith(pre) and s.endswith("'"):
            return (s[len(pre):-1] == event) == (op == "==")
    return True


res(runs_on("github.event_name == 'push'", "pull_request") is False
    and runs_on("github.event_name == 'push'", "push") is True
    and runs_on("${{ always() && github.event_name == 'push' }}", "merge_group") is False
    and runs_on("github.event_name != 'pull_request' && github.event_name != 'merge_group'", "merge_group") is False
    and runs_on("github.event_name != 'pull_request' && github.event_name != 'merge_group'", "push") is True
    and runs_on("${{ always() }}", "pull_request") is True
    and runs_on("github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'", "pull_request") is False
    and runs_on("github.event_name == 'pull_request'", "merge_group") is False
    and runs_on("github.event_name == 'schedule' || (github.event_name == 'dispatch' && inputs.x == '')", "pull_request") is False
    and runs_on("(github.event_name == 'push') || always()", "pull_request") is True,
    "the condition reader decides event-name conditions and lets every other condition run (fixture)")


PR_EVENTS = ("pull_request", "merge_group", "pull_request_target")
def jobs_on(event):
    got = set()
    for f, d in wf.items():
        if event not in triggers(d): continue
        for k, jb in (d.get("jobs") or {}).items():
            if runs_on((jb or {}).get("if"), event): got.add(f + ":" + k)
    return got
def cond(f, j):   # a job's condition without a ${{ }} wrapper
    c = ((wf[f].get("jobs") or {}).get(j) or {}).get("if")
    if c is None: return None
    c = str(c).strip()
    return c[3:-2].strip() if c.startswith("${{") and c.endswith("}}") else c

# ---- REQ-REL-014-AC1: what runs on a pull request
SIX = {"ci.yml:test", "ci.yml:lint", "ci.yml:govulncheck", "ci.yml:fips140-only", "codeql.yml:analyze", "scan.yml:scan"}
SCAN_NEEDS = {"scan.yml:build", "scan.yml:scanner", "scan.yml:inspector"}
HELD = {"ci.yml:marker-gate"}
OTHER = {"customer-words-edited.yml:customer-words-edited", "dependabot-auto-merge.yml:auto-merge",
         "agent-review-gate.yml:judge", "agent-review-gate.yml:publish"}
ALLOWED = SIX | SCAN_NEEDS | HELD | OTHER
on_pr = set().union(*(jobs_on(e) for e in PR_EVENTS))
res(on_pr == ALLOWED, "AC1: the jobs that run on pull_request, merge_group or pull_request_target are exactly the allowed ones "
    "(extra: %s; missing: %s)" % (sorted(on_pr - ALLOWED), sorted(ALLOWED - on_pr)))
res(not (on_pr - ALLOWED), "AC1: no other job runs on a pull request or the merge queue (%s)" % sorted(on_pr - ALLOWED)[:12])
pr = jobs_on("pull_request")
res((SIX - {"codeql.yml:analyze"} | SCAN_NEEDS | HELD | {"customer-words-edited.yml:customer-words-edited"}) <= pr,
    "AC1: the six, scan's jobs, marker-gate and customer-words-edited run on pull_request (missing: %s)"
    % sorted((SIX | SCAN_NEEDS | HELD | {"customer-words-edited.yml:customer-words-edited"}) - pr))
res("codeql.yml:analyze" in pr, "AC1: analyze (go) runs on pull_request")
res(cond("ci.yml", "marker-gate") == "github.event_name == 'pull_request'", "AC1: the held check marker-gate keeps its if: github.event_name == 'pull_request' (%r)" % cond("ci.yml", "marker-gate"))

# the six keep their check names and no job-level condition that reads the event
NAMES = {"ci.yml:test": "test", "ci.yml:lint": "lint", "ci.yml:govulncheck": "govulncheck", "ci.yml:fips140-only": "fips140-only",
         "codeql.yml:analyze": "analyze (go)", "scan.yml:scan": "scan"}
for key, name in sorted(NAMES.items()):
    f, j = key.split(":")
    jb = wf[f]["jobs"].get(j) or {}
    res(jb.get("name", j) == name, "AC1: %s keeps the check name %r" % (key, name))
    res("github.event" not in str(jb.get("if")) and runs_on(jb.get("if"), "pull_request") and runs_on(jb.get("if"), "merge_group"),
        "AC1: %s has no job-level condition that could skip it on a pull request (%r)" % (key, jb.get("if")))
for key in sorted(SCAN_NEEDS):
    f, j = key.split(":")
    res("github.event" not in str((wf[f]["jobs"].get(j) or {}).get("if")), "AC1: %s, a job scan needs, has no condition that reads the event" % key)

res(set(triggers(wf["acceptance.yml"])) == {"workflow_call"}, "AC1: acceptance.yml has only the workflow_call trigger (%s)" % sorted(triggers(wf["acceptance.yml"])))

# ---- jobs that run on push to main only: their job-level if is the one string, so they cannot run on a pull request
PUSH_IF = {("ci.yml", "allowlist"): "github.event_name == 'push'",
           ("ci.yml", "suite-list"): "github.event_name == 'push'",
           ("ci.yml", "suites"): "github.event_name == 'push'",
           ("ci.yml", "allowlist-chain"): "always() && github.event_name == 'push'",
           ("ci.yml", "requirements"): "github.event_name == 'push'",
           ("ci.yml", "go-exact-pins"): "github.event_name == 'push'",
           ("scan.yml", "reproducibility"): "always() && github.event_name == 'push'"}
for (f, j), want in sorted(PUSH_IF.items()):
    jb = (wf[f].get("jobs") or {}).get(j)
    res(jb is not None, "AC1: %s has the job %s" % (f, j))
    if jb is None: continue
    res(cond(f, j) == want, "AC1: %s %s has the job-level if %r (%r)" % (f, j, want, cond(f, j)))
    res(not runs_on(jb.get("if"), "pull_request") and not runs_on(jb.get("if"), "merge_group"),
        "AC1: %s %s does not run on pull_request or merge_group" % (f, j))
    res(runs_on(jb.get("if"), "push") and "push" in triggers(wf[f]), "AC1: %s %s runs on push" % (f, j))

# ---- REQ-REL-014-AC2: supply-chain.yml and the list of required checks
sc = wf["supply-chain.yml"]
res("pull_request" not in triggers(sc), "AC2: supply-chain.yml has no pull_request trigger (%s)" % sorted(triggers(sc)))
res(set(triggers(sc)) == {"schedule", "workflow_dispatch"}, "AC2: supply-chain.yml runs on schedule and workflow_dispatch only (%s)" % sorted(triggers(sc)))
res("pin-age" not in (sc.get("jobs") or {}), "AC2: supply-chain.yml has no pin-age job")
res(not any(j.get("name") == "pin-age" for j in (sc.get("jobs") or {}).values()), "AC2: no job of supply-chain.yml is named pin-age")
res(set(sc.get("jobs") or {}) == {"daily-audit", "evidence-letter-present"}, "AC2: daily-audit and evidence-letter-present are the jobs left in supply-chain.yml (%s)" % sorted(sc.get("jobs") or {}))
res(not any(k.startswith("supply-chain.yml:") for k in on_pr), "AC2: no job of supply-chain.yml runs on pull_request, merge_group or pull_request_target")
for jn in ("daily-audit", "evidence-letter-present"):
    jb = (sc.get("jobs") or {}).get(jn) or {}
    res(runs_on(jb.get("if"), "schedule") and runs_on(jb.get("if"), "workflow_dispatch") and not runs_on(jb.get("if"), "pull_request"),
        "AC2: %s runs on schedule and workflow_dispatch and not on pull_request (%r)" % (jn, jb.get("if")))
checks = json.load(open(root + "/.github/policy/required-checks.json"))["required_checks"]
scopes = {c["context"]: c["scope"] for c in checks}
res(len(scopes) == len(checks), "AC2: required-checks.json names no context twice")
res("pin-age" not in scopes, "AC2: required-checks.json has no pin-age entry")

# ---- REQ-REL-014-AC3: a push-scoped check is produced by a job that runs on push; acceptance is no entry
res("acceptance" not in scopes, "AC3: required-checks.json has no acceptance entry")
WANT = {"test": "push", "lint": "push", "govulncheck": "push", "allowlist": "push", "allowlist-chain": "push",
        "requirements": "push", "reproducibility": "push", "scan": "push", "go-exact-pins": "push",
        "auditor-review-gate": "pull_request"}
res(scopes == WANT, "AC3: required-checks.json holds exactly the ten remaining contexts with their scopes (diff: %s)"
    % sorted(k for k in set(scopes) | set(WANT) if scopes.get(k) != WANT.get(k)))
res([c for c in checks if c["context"] == "go-exact-pins"] == [{"context": "go-exact-pins", "integration_id": 15368, "scope": "push"}],
    "AC3: required-checks.json has exactly one go-exact-pins entry, integration_id 15368, scope push")
gj = (wf["ci.yml"].get("jobs") or {}).get("go-exact-pins") or {}
gsteps = gj.get("steps") or []
res(gj.get("name", "go-exact-pins") == "go-exact-pins", "AC3: the ci.yml job go-exact-pins has the check name go-exact-pins")
res(any("actions/checkout" in str(st.get("uses")) and (st.get("with") or {}).get("persist-credentials") is False for st in gsteps),
    "AC3: go-exact-pins checks out the repo with persist-credentials: false")
on_push = jobs_on("push")
produced = {}
for key in on_push:
    f, j = key.split(":")
    produced.setdefault(wf[f]["jobs"][j].get("name", j), []).append(key)
for ctx, scope in sorted(scopes.items()):
    if scope == "push":
        res(ctx in produced, "AC3: the push-scoped check %s is produced by a job that runs on push (%s)" % (ctx, produced.get(ctx)))
print("\n".join(results))
PY
)
echo "$out"
pass=$(printf '%s\n' "$out" | grep -c '^ok: ')
failn=$(printf '%s\n' "$out" | grep -vc '^ok: ')
echo "chain-pull-request-checks: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
