#!/usr/bin/env bash
# proves: REQ-DEP-001-AC1, REQ-DEP-001-AC5, REQ-DEP-001-AC6, REQ-DEP-001-AC8, REQ-DEP-002-AC1, REQ-DEP-003-AC1
# The dependency lanes' wiring (register rows 75, 80): the reviewer runs hourly from main and never on a PR
# event, one run at a time; it arms or holds and posts its check but opens no PR and edits nothing; its
# evidence upload can never fail a run; the required-check guard runs on every PR and push to main; the
# patch/minor lane arms squash auto-merge only after the guard, and never for a major. Each real workflow
# must pass; each mutated copy must be caught.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0

judge() { python3 - "$1" "$2" <<'PY'
import re, sys, yaml
kind, path = sys.argv[1], sys.argv[2]
d = {} if kind == "reviewer-py" else yaml.load(open(path), Loader=yaml.BaseLoader)
on = d.get("on", {})
bad = []
def runs(job):
    return [(s, (s.get("run") or "")) for s in job.get("steps", [])]
if kind == "reviewer":
    if not isinstance(on, dict) or set(on) != {"schedule", "workflow_dispatch"}:
        bad.append(f"triggers are {sorted(on) if isinstance(on, dict) else on}, not exactly schedule + workflow_dispatch")
    crons = [c.get("cron", "") for c in (on.get("schedule") or [])] if isinstance(on, dict) else []
    if len(crons) != 1 or not re.fullmatch(r"[0-9]{1,2} \* \* \* \*", crons[0] if crons else ""):
        bad.append(f"schedule {crons} is not once an hour")
    c = d.get("concurrency", {})
    if not isinstance(c, dict) or not c.get("group") or "${{" in c.get("group", "") or c.get("cancel-in-progress") != "false":
        bad.append("runs are not serialised (one constant concurrency group, cancel-in-progress: false)")
    job = d.get("jobs", {}).get("review", {})
    perms = job.get("permissions", {})
    if isinstance(perms, dict) and perms.get("contents") not in (None, "read"):
        bad.append(f"the job token can write contents ({perms.get('contents')})")
    text = "\n".join(r for _, r in runs(job))
    for verb in (r"\bgit\s+push\b", r"\bgit\s+commit\b", r"\bgh\s+pr\s+create\b", r"\bgh\s+pr\s+edit\b",
                 r"\bgh\s+api\b[^\n]*/contents/[^\n]*-X\s*(PUT|DELETE)", r"\bgh\s+release\b"):
        if re.search(verb, text):
            bad.append(f"a step edits or opens something: /{verb}/")
    if not any("permission-checks: write" in str(s.get("with", "")) or s.get("with", {}).get("permission-checks") == "write"
               for s in job.get("steps", [])):
        bad.append("no App token scoped to checks:write for the verdict check")
    up = [s for s in job.get("steps", []) if str(s.get("uses", "")).startswith("actions/upload-artifact@")]
    if len(up) != 1:
        bad.append("no single evidence upload")
    else:
        u = up[0]
        if "always()" not in u.get("if", "") or u.get("continue-on-error") != "true":
            bad.append("the evidence upload is not always() + continue-on-error")
        if (u.get("with") or {}).get("path") != "${{ runner.temp }}/work" or "$RUNNER_TEMP/work" not in text:
            bad.append("the evidence upload does not keep the run's work directory (bundles, answers, decisions)")
elif kind == "reviewer-py":
    # the reviewer's own code: no call that opens, edits or pushes anything, however it is spelled
    import ast
    tree = ast.parse(open(path).read())
    seqs, strings = [], []
    for node in ast.walk(tree):
        if isinstance(node, (ast.List, ast.Tuple)):
            seqs.append([e.value for e in node.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)])
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            strings.append(node.value)
    forbidden = [("gh", "pr", "create"), ("gh", "pr", "edit"), ("gh", "pr", "close"), ("gh", "release"),
                 ("git", "push"), ("git", "commit")]
    for sq in seqs:
        # the reviewer's own code only ever READS the API: a write method or a field in a gh api call is refused
        if True:  # any sequence: _gh_json prepends `gh api` at run time, so its callers' lists count too
            for i, a in enumerate(sq):
                if a in ("-X", "--method") and i + 1 < len(sq) and sq[i + 1].upper() != "GET":
                    bad.append("the reviewer writes through the API (" + " ".join(sq[i:i + 2]) + ")")
                if a in ("-f", "-F", "--field", "--raw-field", "--input"):
                    bad.append("the reviewer sends fields through the API (" + a + ")")
        for f in forbidden:
            for i in range(len(sq) - len(f) + 1):
                if tuple(sq[i:i + len(f)]) == f:
                    bad.append("the reviewer calls " + " ".join(f))
    for st in strings:
        for pat in (r"\bgh\s+pr\s+(create|edit|close)\b", r"\bgh\s+release\b", r"\bgit\s+(push|commit)\b",
                    r"/contents/\S*.*-X\s*(PUT|DELETE)", r"-X\s*(PUT|DELETE)\b.*/contents/"):
            if re.search(pat, st):
                bad.append("the reviewer runs: " + st[:60])
elif kind == "guard":
    if "pull_request" not in on or (isinstance(on.get("pull_request"), dict) and on.get("pull_request")):
        bad.append("not on every pull request")
    push = on.get("push") if isinstance(on, dict) else None
    if not isinstance(push, dict) or push != {"branches": ["main"]}:
        bad.append("not on every push to main")
    job = d.get("jobs", {}).get("required-check-guard", {})
    if "if" in job or "continue-on-error" in job:
        bad.append("the guard job is conditional")
    hit = [s for s, r in runs(job) if r.strip() == "bash bin/required-check-guard.sh .github/policy/required-checks.json"]
    if len(hit) != 1 or any(k in hit[0] for k in ("if", "continue-on-error", "shell")):
        bad.append("the guard step is missing, conditional or re-shelled")
elif kind == "automerge":
    if on != "pull_request":
        bad.append(f"trigger is {on!r}, not pull_request")
    job = d.get("jobs", {}).get("auto-merge", {})
    if "dependabot[bot]" not in job.get("if", ""):
        bad.append("not limited to Dependabot's PRs")
    steps = job.get("steps", [])
    if any(str(s.get("uses", "")).startswith("actions/checkout@") for s in steps):
        bad.append("checks out the PR")
    nonmajor = "steps.meta.outputs.update-type != 'version-update:semver-major'"
    guard = [i for i, (s, r) in enumerate(runs(job)) if "required-check-guard.sh" in r]
    arm = [i for i, (s, r) in enumerate(runs(job)) if re.search(r"gh pr merge --auto --squash", r)]
    if len(arm) != 1:
        bad.append("no single squash auto-merge step")
    elif steps[arm[0]].get("if") != nonmajor or "continue-on-error" in steps[arm[0]]:
        bad.append("auto-merge is not limited to non-majors, or can fail silently")
    if len(guard) != 1 or steps[guard[0]].get("if") != nonmajor or "continue-on-error" in steps[guard[0]]:
        bad.append("the guard step is missing, wrongly conditioned, or can fail silently")
    elif arm and guard[0] > arm[0]:
        bad.append("auto-merge is armed before the guard")
print("; ".join(bad) or "ok")
sys.exit(1 if bad else 0)
PY
}

pycase() {  # pycase <name> <expect> <python source line appended to a copy of the reviewer, or empty>
  local f="$work/$1.py"
  cp "$root/bin/dependabot-reviewer.py" "$f"
  [ -n "$3" ] && printf '\n%s\n' "$3" >> "$f"
  if out=$(judge reviewer-py "$f"); then got=ok; else got=bad; fi
  if [ "$got" = "$2" ]; then pass=$((pass+1)); echo "PASS $1 → $got ($out)"
  else failn=$((failn+1)); echo "FAIL $1 → $got, want $2 ($out)"; fi
}

case_() {  # case_ <kind> <file> <name> <expect ok|bad> <python edit of the parsed copy, or empty>
  local f="$work/$3.yml"
  cp "$root/.github/workflows/$2" "$f"
  if [ -n "$5" ]; then python3 - "$f" "$5" <<'PY'
import sys, yaml
p, edit = sys.argv[1], sys.argv[2]
d = yaml.load(open(p), Loader=yaml.BaseLoader)
exec(edit)
yaml.safe_dump(d, open(p, "w"), sort_keys=False)
PY
  fi
  if out=$(judge "$1" "$f"); then got=ok; else got=bad; fi
  if [ "$got" = "$4" ]; then pass=$((pass+1)); echo "PASS $3 → $got ($out)"
  else failn=$((failn+1)); echo "FAIL $3 → $got, want $4 ($out)"; fi
}

R=dependabot-reviewer.yml; H=hygiene.yml; A=dependabot-auto-merge.yml
rs='d["jobs"]["review"]["steps"]'; gs='d["jobs"]["required-check-guard"]["steps"]'; as_='d["jobs"]["auto-merge"]["steps"]'
case_ reviewer $R reviewer-real            ok  ""
case_ reviewer $R reviewer-on-pr           bad "d['on']['pull_request'] = ''"
case_ reviewer $R reviewer-on-push         bad "d['on']['push'] = {'branches': ['main']}"
case_ reviewer $R reviewer-every-10-min    bad "d['on']['schedule'] = [{'cron': '*/10 * * * *'}]"
case_ reviewer $R reviewer-not-serialised  bad "d['concurrency']['cancel-in-progress'] = 'true'"
case_ reviewer $R reviewer-git-push        bad "$rs.append({'run': 'git push origin HEAD'})"
case_ reviewer $R reviewer-opens-pr        bad "$rs.append({'run': 'gh pr create --fill'})"
case_ reviewer $R reviewer-contents-write  bad "d['jobs']['review'].setdefault('permissions', {})['contents'] = 'write'"
case_ reviewer $R reviewer-no-checks-app   bad "[s.get('with', {}).pop('permission-checks', None) for s in $rs if isinstance(s.get('with'), dict)]"
case_ reviewer $R reviewer-evidence-fails  bad "[s.pop('continue-on-error', None) for s in $rs if str(s.get('uses','')).startswith('actions/upload-artifact@')]"
case_ reviewer $R reviewer-no-evidence     bad "$rs[:] = [s for s in $rs if not str(s.get('uses','')).startswith('actions/upload-artifact@')]"
case_ reviewer $R reviewer-group-per-run  bad "d['concurrency']['group'] = '\${{ github.run_id }}'"
case_ reviewer $R reviewer-evidence-path   bad "[s['with'].__setitem__('path', '/nonexistent') for s in $rs if str(s.get('uses','')).startswith('actions/upload-artifact@')]"
pycase reviewer-py-real        ok  ""
pycase reviewer-py-pr-create   bad 'subprocess.run(["gh", "pr", "create", "--fill"])'
pycase reviewer-py-push        bad '_run(["git", "push", "origin", "HEAD"])'
pycase reviewer-py-shell       bad 'os.system("gh pr edit 99 --add-label x")'
pycase reviewer-py-contents    bad '_run(["gh", "api", "-X", "PUT", "repos/o/r/contents/x"])'
pycase reviewer-py-field-post  bad '_run(["gh", "api", "repos/o/r/issues", "-f", "title=x"])'
pycase reviewer-py-via-helper  bad '_gh_json(["repos/o/r/contents/x", "-X", "DELETE"])'
case_ guard    $H guard-real               ok  ""
case_ guard    $H guard-pr-filtered        bad "d['on']['pull_request'] = {'paths': ['bin/**']}"
case_ guard    $H guard-job-if             bad "d['jobs']['required-check-guard']['if'] = 'false'"
case_ guard    $H guard-step-continue      bad "[s.__setitem__('continue-on-error', 'true') for s in $gs if s.get('run','').strip().startswith('bash bin/required-check-guard.sh .github')]"
case_ guard    $H guard-step-removed       bad "$gs[:] = [s for s in $gs if not s.get('run','').strip().startswith('bash bin/required-check-guard.sh .github')]"
case_ automerge $A automerge-real          ok  ""
case_ automerge $A automerge-target        bad "d['on'] = 'pull_request_target'"
case_ automerge $A automerge-any-author    bad "d['jobs']['auto-merge']['if'] = 'true'"
case_ automerge $A automerge-majors-too    bad "[s.pop('if', None) for s in $as_ if 'gh pr merge --auto' in (s.get('run') or '')]"
case_ automerge $A automerge-no-guard      bad "$as_[:] = [s for s in $as_ if 'required-check-guard.sh' not in (s.get('run') or '')]"
case_ automerge $A automerge-guard-soft    bad "[s.__setitem__('continue-on-error', 'true') for s in $as_ if 'required-check-guard.sh' in (s.get('run') or '')]"
case_ automerge $A automerge-arm-first     bad "i = [n for n, s in enumerate($as_) if 'required-check-guard.sh' in (s.get('run') or '')][0]; g = $as_.pop(i); $as_.append(g)"
case_ automerge $A automerge-checkout      bad "$as_.insert(0, {'uses': 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1'})"

echo "dependency-lanes: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
