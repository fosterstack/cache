#!/usr/bin/env bash
# proves: REQ-REL-014-AC1, REQ-REL-014-AC2, REQ-REL-014-AC3
# Pull requests run six checks (test, lint, govulncheck, analyze (go), fips140-only, scan with the jobs scan needs), the held
# checks (marker-gate, image-signatures), customer-words-edited, agent-review-gate.yml and dependabot-auto-merge.yml; every
# other job runs on push to main, on a schedule or in the release chain. pin-age and dependency-review judge a push's
# versions (the commit before the push to the commit after it). Reads the committed workflows and required-checks.json.
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

SIX = {"ci.yml:test", "ci.yml:lint", "ci.yml:govulncheck", "ci.yml:fips140-only", "codeql.yml:analyze", "scan.yml:scan"}
SCAN_NEEDS = {"scan.yml:build", "scan.yml:scanners", "scan.yml:scanner", "scan.yml:inspector"}
HELD = {"ci.yml:marker-gate", "supply-chain.yml:image-signatures"}
OTHER = {"customer-words-edited.yml:customer-words-edited", "dependabot-auto-merge.yml:auto-merge",
         "agent-review-gate.yml:judge", "agent-review-gate.yml:publish"}
ALLOWED = SIX | SCAN_NEEDS | HELD | OTHER
on_pr = set().union(*(jobs_on(e) for e in PR_EVENTS))
res(on_pr == ALLOWED, "the jobs that run on pull_request, merge_group or pull_request_target are exactly the allowed ones "
    "(extra: %s; missing: %s)" % (sorted(on_pr - ALLOWED), sorted(ALLOWED - on_pr)))
res(not (on_pr - ALLOWED), "no other job runs on a pull request or the merge queue (%s)" % sorted(on_pr - ALLOWED)[:6])
mq = jobs_on("merge_group")
res((SIX | SCAN_NEEDS) <= mq, "the six checks and the jobs scan needs run on merge_group (missing: %s)" % sorted((SIX | SCAN_NEEDS) - mq))
res(not (mq - SIX - SCAN_NEEDS), "nothing else runs on merge_group (%s)" % sorted(mq - SIX - SCAN_NEEDS)[:6])
pr = jobs_on("pull_request")
res((SIX | SCAN_NEEDS | HELD | {"customer-words-edited.yml:customer-words-edited"}) <= pr,
    "the six, scan's jobs, the held checks and customer-words-edited run on pull_request (missing: %s)"
    % sorted((SIX | SCAN_NEEDS | HELD | {"customer-words-edited.yml:customer-words-edited"}) - pr))
for h in sorted(HELD):
    f, j = h.split(":")
    res(wf[f]["jobs"][j].get("if") == "github.event_name == 'pull_request'", "%s keeps its if: github.event_name == 'pull_request'" % j)

# the six keep their check names and no job-level condition that reads the event
NAMES = {"ci.yml:test": "test", "ci.yml:lint": "lint", "ci.yml:govulncheck": "govulncheck", "ci.yml:fips140-only": "fips140-only",
         "codeql.yml:analyze": "analyze (go)", "scan.yml:scan": "scan"}
for key, name in sorted(NAMES.items()):
    f, j = key.split(":")
    jb = wf[f]["jobs"].get(j) or {}
    res(jb.get("name", j) == name, "%s keeps the check name %r" % (key, name))
    res("github.event" not in str(jb.get("if")) and runs_on(jb.get("if"), "pull_request") and runs_on(jb.get("if"), "merge_group"),
        "%s has no job-level condition that could skip it on a pull request (%r)" % (key, jb.get("if")))

res(set(triggers(wf["acceptance.yml"])) == {"workflow_call"}, "acceptance.yml has only the workflow_call trigger (%s)" % sorted(triggers(wf["acceptance.yml"])))

# jobs that run on push to main only
PUSH_ONLY = {"ci.yml": ["vendor", "coverage", "gosec", "allowlist", "allowlist-persona", "allowlist-chain-1", "allowlist-chain-2",
                        "allowlist-chain-3", "allowlist-chain-4", "allowlist-chain", "allowlist-pins-auditor", "requirements",
                        "dependency-review"],
             "scan.yml": ["rebuild", "reproducibility"], "supply-chain.yml": ["pin-age"]}
for f, names in PUSH_ONLY.items():
    for j in names:
        jb = (wf[f].get("jobs") or {}).get(j)
        res(jb is not None, "%s has the job %s" % (f, j))
        if jb is None: continue
        res(not runs_on(jb.get("if"), "pull_request") and not runs_on(jb.get("if"), "merge_group"),
            "%s %s: its job-level if is false on pull_request and on merge_group (%r)" % (f, j, jb.get("if")))
        res(runs_on(jb.get("if"), "push"), "%s %s: its job-level if is true on push (%r)" % (f, j, jb.get("if")))
        res("push" in triggers(wf[f]), "%s runs on push (%s)" % (f, j))
for f, j in (("supply-chain.yml", "rerun-held"), ("supply-chain.yml", "daily-audit"), ("supply-chain.yml", "evidence-letter-present")):
    jb = wf[f]["jobs"][j]
    res(not runs_on(jb.get("if"), "pull_request") and not runs_on(jb.get("if"), "merge_group")
        and runs_on(jb.get("if"), "schedule") and runs_on(jb.get("if"), "workflow_dispatch"),
        "%s keeps schedule and dispatch only (%r)" % (j, jb.get("if")))
# the push trigger of supply-chain.yml
sc = triggers(wf["supply-chain.yml"])
res(isinstance(sc.get("push"), dict) and sc["push"].get("branches") == ["main"],
    "supply-chain.yml runs on push with branches [main] (%r)" % (sc.get("push"),))
# pull_request stays in the workflow only for the held check image-signatures (judged above); no pin-age step reads it
res("merge_group" not in sc, "supply-chain.yml has no merge_group trigger")
res("schedule" in sc and "workflow_dispatch" in sc, "supply-chain.yml keeps its schedule and dispatch triggers")

# pin-age reads the push: the commit before it, then the commit after it
pa = wf["supply-chain.yml"]["jobs"]["pin-age"]
pa_text = json.dumps(pa.get("steps"))
res("pull_request" not in pa_text and "merge_group" not in pa_text, "no pin-age step names pull_request or merge_group")
checkouts = [s for s in pa.get("steps") or [] if str(s.get("uses", "")).startswith("actions/checkout") and (s.get("with") or {}).get("path") == "trusted"]
res(len(checkouts) == 1 and checkouts[0]["with"].get("ref") == "${{ github.event.before }}",
    "pin-age pulls the trusted checker at ref ${{ github.event.before }}")
runs = "\n".join(s.get("run", "") for s in pa.get("steps") or [])
res("--base ${{ github.event.before }}" in runs.replace('"', "") or ('--base "$BASE_SHA"' in runs and 'BASE_SHA="${{ github.event.before }}"' in runs),
    "pin-age compares --base ${{ github.event.before }}")
res("--head ${{ github.sha }}" in runs.replace('"', "") or ('--head "$HEAD_SHA"' in runs and 'HEAD_SHA="${{ github.sha }}"' in runs),
    "pin-age compares --head ${{ github.sha }}")

# dependency-review reads the push too
dr = wf["ci.yml"]["jobs"]["dependency-review"]
withs = [s.get("with") or {} for s in dr.get("steps") or [] if str(s.get("uses", "")).startswith("actions/dependency-review-action")]
res(len(withs) == 1 and withs[0].get("base-ref") == "${{ github.event.before }}" and withs[0].get("head-ref") == "${{ github.sha }}",
    "dependency-review compares base-ref ${{ github.event.before }} with head-ref ${{ github.sha }} (%r)" % withs)
res("merge_group" not in json.dumps(dr.get("steps")), "no dependency-review step names a merge_group field")

# required-checks.json: the three acceptance entries are gone (the release's Check stage runs them), the scopes of dependency-review and pin-age change
scopes = {c["context"]: c["scope"] for c in json.load(open(root + "/.github/policy/required-checks.json"))["required_checks"]}
WANT = {"test": "push", "lint": "push", "gosec": "push", "govulncheck": "push", "analyze (go)": "push", "allowlist": "push",
        "allowlist-persona": "push", "allowlist-chain": "push", "allowlist-pins-auditor": "push", "dependency-review": "push",
        "fips140-only": "push", "requirements": "push", "reproducibility": "push", "coverage": "push", "scan": "push", "pin-age": "push",
        "auditor-review-gate": "pull_request", "vendor": "push", "marker-gate": "pull_request"}
res(scopes.get("dependency-review") == "push", "required-checks.json scopes dependency-review to push (%r)" % scopes.get("dependency-review"))
res(scopes.get("pin-age") == "push", "required-checks.json scopes pin-age to push (%r)" % scopes.get("pin-age"))
res(scopes == WANT, "required-checks.json lost exactly the three acceptance contexts and changed nothing else (diff: %s)"
    % sorted(k for k in set(scopes) | set(WANT) if scopes.get(k) != WANT.get(k)))
print("\n".join(results))
PY
)
echo "$out"
pass=$(printf '%s\n' "$out" | grep -c '^ok: ')
failn=$(printf '%s\n' "$out" | grep -vc '^ok: ')
echo "chain-pull-request-checks: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
