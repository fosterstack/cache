#!/usr/bin/env bash
# proves: REQ-DEP-001-AC1, REQ-DEP-001-AC3, REQ-DEP-001-AC5, REQ-DEP-001-AC6, REQ-DEP-001-AC8, REQ-DEP-001-AC9, REQ-DEP-001-AC10, REQ-DEP-002-AC1, REQ-DEP-003-AC1, REQ-DEP-003-AC2, REQ-DEP-003-AC3
# The dependency lanes' wiring (register rows 75, 80): the reviewer runs hourly from main and never on a PR
# event, one run at a time; it arms or holds and posts its check but opens no PR and edits nothing; its
# evidence upload can never fail a run; the required-check guard runs on every PR and push to main; the
# patch/minor lane arms squash auto-merge only after the guard, and never for a major. Each real workflow
# must pass; each mutated copy must be caught.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
work_am=$work/am.out

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
    # AC3: the readers go through the federation, model identifiers only from environment secrets
    act = [s for s in job.get("steps", []) if s.get("id") == "act"]
    env = (act[0].get("env") or {}) if act else {}
    for k, sec in (("ANTHROPIC_FEDERATION_RULE_ID", "REVIEWER_FEDERATION_RULE_ID"), ("ANTHROPIC_ORGANIZATION_ID", None),
                   ("ANTHROPIC_SERVICE_ACCOUNT_ID", None), ("ANTHROPIC_WORKSPACE_ID", None),
                   ("AUDITOR_MODEL_PRIMARY", None), ("AUDITOR_MODEL_FALLBACK", None)):
        if env.get(k, "").strip() != "${{ secrets.%s }}" % (sec or k):
            bad.append(f"{k} does not come from its environment secret")
    if re.search(r"\bclaude-[a-z0-9]|ANTHROPIC_API_KEY", open(path).read()):
        bad.append("a model id or an API key is written into the workflow")
    # advisor Oct 12: the pinned tool module tools/govulncheck is held out of auto-merge and handled as a normal lane PR (both Codex seats review it, a lane merges it): a bump there is never armed, because its version is also written in ci.yml, which
    # Dependabot cannot change (the PR's own files are read, so the hold does not depend on a metadata output)
    cand = [s for s in job.get("steps", []) if s.get("id") == "candidates"]
    cr = cand[0].get("run") or "" if cand else ""
    hold = cr.find('startswith("tools/govulncheck/")')
    if "(.files | length) >= 100" not in cr:
        bad.append("a PR whose file list is at the API's cap of 100 is not held (it cannot be judged: the candidates step must hold >= 100 files)")
    if hold < 0 or "--json number,title,body,headRefOid,files" not in cr or hold > cr.find("dependabot-reviewer.py updates") or "pr merge --disable-auto" not in cr[hold:cr.find("dependabot-reviewer.py updates")]:
        bad.append("a PR that touches tools/govulncheck/ is not held (the candidates step must read the PR's files first, disarm it and skip it, never review or arm it)")
    # REQ-DEP-001-AC10: the candidate step and the hold issue select major OR flagged, never majors only
    cand = [r for st, r in runs(job) if st.get("id") == "candidates"]
    if len(cand) != 1 or "select(.major or .flagged)" not in cand[0] or "select(.major)" in cand[0]:
        bad.append("the candidate step does not select a flagged non-major beside a major")
    if len(cand) == 1 and ("auto_merge_disabled github-actions" not in cand[0] or "required-check-guard.sh" not in cand[0] or '--match-head-commit "$sha"' not in cand[0]):
        bad.append("the candidate step does not put back (guard first, exact head) an arm the lane turned off after the reviewer approved the head")
    if len(cand) == 1 and "if .flagged then .major = true" not in cand[0]:
        bad.append("the candidate step does not hand a flagged update to the (hash-pinned) act step as a major")
    # AC9: auto-merge is armed only for the reviewed head
    arms = re.findall(r"gh pr merge --auto[^\n]*", text)
    if not arms or any('--match-head-commit "$sha"' not in a for a in arms):
        bad.append("auto-merge is not bound to the reviewed head (--match-head-commit \"$sha\")")
    # AC3: the evidence directory is masked, in place, right before the upload, and the upload needs it
    names = [s.get("id") for s in job.get("steps", [])]
    mk = [s for s in job.get("steps", []) if s.get("id") == "mask"]
    if not mk or (mk[0].get("run") or "").strip() != 'python3 bin/dependabot-reviewer.py mask-tree "$RUNNER_TEMP/work"' \
            or "always()" not in mk[0].get("if", "") or mk[0].get("continue-on-error") != "true":
        bad.append("no step masks the evidence directory before upload, never failing the run (AC6)")
    up = [s for s in job.get("steps", []) if str(s.get("uses", "")).startswith("actions/upload-artifact@")]
    if len(up) != 1:
        bad.append("no single evidence upload")
    else:
        u = up[0]
        if u.get("if", "").strip() != "${{ always() && steps.candidates.outputs.count != '0' && steps.mask.outcome == 'success' }}" or u.get("continue-on-error") != "true":
            bad.append("the evidence upload is not always() + continue-on-error")
        if (u.get("with") or {}).get("path") != "${{ runner.temp }}/work" or "$RUNNER_TEMP/work" not in text:
            bad.append("the evidence upload does not keep the run's work directory (bundles, answers, decisions)")
elif kind == "reviewer-py":
    # the reviewer's own code: no call that opens, edits or pushes anything, however it is spelled
    import ast
    tree = ast.parse(open(path).read())
    seqs, strings = [], []
    # mask_tree rewrites the evidence directory it is given (the workflow passes $RUNNER_TEMP/work, pinned below)
    mask_fns = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "mask_tree"]
    def flat(n):
        """a command list as written, concatenations joined; a non-literal element is None (unknown)"""
        if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
            return flat(n.left) + flat(n.right)
        if isinstance(n, (ast.List, ast.Tuple)):
            return [e.value if isinstance(e, ast.Constant) and isinstance(e.value, str) else None for e in n.elts]
        return [None]
    for node in ast.walk(tree):
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            seqs.append(flat(node))
        elif isinstance(node, (ast.List, ast.Tuple)):
            seqs.append(flat(node))
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            strings.append(node.value)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open" and len(node.args) > 1 \
                and not any(fn.name == "mask_tree" and fn.lineno <= node.lineno <= fn.end_lineno for fn in mask_fns):
            mode = node.args[1].value if isinstance(node.args[1], ast.Constant) else None
            target = node.args[0]
            # the reviewer writes only its own outputs (under the --out directory it is given)
            if mode is None or any(c in str(mode) for c in "wax+"):
                is_out = lambda n: isinstance(n, ast.Attribute) and n.attr == "out"
                under_out = isinstance(target, ast.Call) and getattr(target.func, "attr", "") == "join" and target.args and is_out(target.args[0])
                if not (is_out(target) or under_out):
                    bad.append("the reviewer writes a file outside its output directory (open(..., %r))" % (mode,))
    forbidden = [("gh", "pr", "create"), ("gh", "pr", "edit"), ("gh", "pr", "close"), ("gh", "release"),
                 ("git", "push"), ("git", "commit"),
                 ("grype",), ("trivy",), ("syft",), ("osv-scanner",), ("snyk",), ("docker",), ("govulncheck",)]
    for sq in seqs:
        # the reviewer's own code only ever READS the API: a write method or a field in a gh api call is refused
        if True:  # any sequence: _gh_json prepends `gh api` at run time, so its callers' lists count too
            for i, a in enumerate(sq):
                if a in ("-X", "--method") and (i + 1 >= len(sq) or sq[i + 1] is None or sq[i + 1].upper() != "GET"):
                    bad.append("the reviewer writes through the API (%s %s)" % (a, sq[i + 1] if i + 1 < len(sq) else ""))
                if isinstance(a, str) and a.startswith(("--method=", "-X=")) and a.split("=", 1)[1].upper() != "GET":
                    bad.append("the reviewer writes through the API (" + a + ")")
                if a in ("-f", "-F", "--field", "--raw-field", "--input"):
                    bad.append("the reviewer sends fields through the API (" + a + ")")
        for f in forbidden:
            for i in range(len(sq) - len(f) + 1):
                if tuple(sq[i:i + len(f)]) == f:
                    bad.append("the reviewer calls " + " ".join(f))
    for st in strings:
        for pat in (r"^(grype|trivy|syft|osv-scanner|snyk|docker|govulncheck)\b", r"\bgh\s+pr\s+(create|edit|close)\b", r"\bgh\s+release\b", r"\bgit\s+(push|commit)\b",
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
    nonmajor = "steps.meta.outputs.update-type != 'version-update:semver-major' && steps.screen.outputs.flagged != 'true'"
    # REQ-DEP-003-AC2: a non-major whose release notes say breaking/deprecat is screened by main's own
    # reviewer script (same code that decides who the reviewer reads), before any arming
    scr = [i for i, s in enumerate(steps) if s.get("id") == "screen"]
    if len(scr) != 1:
        bad.append("no single screen step for flagged non-majors")
    else:
        st, sr = steps[scr[0]], steps[scr[0]].get("run") or ""
        if "continue-on-error" in st or "if" in st:
            bad.append("the screen step is conditional or can fail silently")
        if "<<'PY'" not in sr or 'os.environ["PR_BODY"]' not in sr or ">> \"$GITHUB_OUTPUT\"" not in sr:
            bad.append("the screen is not a quoted heredoc that reads PR_BODY from env and writes flagged= to GITHUB_OUTPUT")
        if re.search(r"https?://|\bgh\b|contents/", sr):
            bad.append("the screen downloads something (a downloaded script is refused by the pin checker, handoff 0094)")
        if "${{" in sr:
            bad.append("the screen interpolates an expression into a script (pass it by env)")
        if "github.event.pull_request.body" not in str((st.get("env") or {}).get("PR_BODY", "")):
            bad.append("the screen does not take the PR body from env PR_BODY")
    guard = [i for i, (s, r) in enumerate(runs(job)) if "required-check-guard.sh" in r]
    arm = [i for i, (s, r) in enumerate(runs(job)) if re.search(r"gh pr merge --auto --squash", r) and "--disable-auto" not in r]
    if len(arm) != 1:
        bad.append("no single squash auto-merge step")
    elif "--match-head-commit \"$HEAD_SHA\"" not in runs(job)[arm[0]][1] or "github.event.pull_request.head.sha" not in str((steps[arm[0]].get("env") or {}).get("HEAD_SHA", "")):
        bad.append("auto-merge is not bound to the head this run screened (--match-head-commit \"$HEAD_SHA\")")
    elif steps[arm[0]].get("if") != nonmajor or "continue-on-error" in steps[arm[0]]:
        bad.append("auto-merge is not limited to non-majors, or can fail silently")
    else:
        ar = steps[arm[0]].get("run") or ""
        hold, merge = ar.find('startswith("tools/govulncheck/")'), ar.find("gh pr merge --auto --squash")
        if '-ge 100' not in ar[:merge]:
            bad.append("auto-merge is armed for a PR whose file list is at the API's cap of 100 (it cannot be judged: the arming step must hold >= 100 files)")
        if hold < 0 or hold > merge or "--json files" not in ar[:merge] or "exit 0" not in ar[hold:merge]:
            bad.append("auto-merge is armed for a PR that touches tools/govulncheck/ (the arming step must read the PR's files and leave the PR out of auto-merge before it merges: a normal lane PR)")
    major = "${{ !cancelled() && (steps.meta.outputs.update-type == 'version-update:semver-major' || steps.screen.outputs.flagged == 'true' || steps.screen.outcome == 'failure') }}"
    disarm = [(s, r) for s, r in runs(job) if "gh pr merge --disable-auto" in r]
    if len(disarm) != 1 or disarm[0][0].get("if") != major or "continue-on-error" in disarm[0][0]:
        bad.append("a push to a major PR does not turn its auto-merge off (the reviewed head's verdict is void)")
    elif "check-runs?check_name=dependabot-reviewer" not in disarm[0][1] or "headRefOid" not in disarm[0][1]:
        bad.append("the disarm does not judge the PR's CURRENT head by its reviewer check (a stale push job must not disarm a newer approved head)")
    if (job.get("permissions") or {}).get("checks") != "read":
        bad.append("the lane cannot read the reviewer's check (permissions: checks: read)")
    if len(guard) != 1 or steps[guard[0]].get("if") != nonmajor or "continue-on-error" in steps[guard[0]]:
        bad.append("the guard step is missing, wrongly conditioned, or can fail silently")
    elif arm and guard[0] > arm[0]:
        bad.append("auto-merge is armed before the guard")
    if scr and arm and scr[0] > arm[0]:
        bad.append("auto-merge is armed before the screen")
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

R=dependabot-reviewer.yml; H=ci.yml; A=dependabot-auto-merge.yml
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
case_ reviewer $R reviewer-evidence-narrow bad "[s.__setitem__('if', s['if'].replace('}}', \"&& steps.act.outcome == 'success' }}\")) for s in $rs if str(s.get('uses','')).startswith('actions/upload-artifact@')]"
case_ reviewer $R reviewer-model-literal  bad "[s['env'].__setitem__('AUDITOR_MODEL_PRIMARY', 'claude-opus-9') for s in $rs if s.get('id') == 'act']"
case_ reviewer $R reviewer-no-federation  bad "[s['env'].__setitem__('ANTHROPIC_FEDERATION_RULE_ID', 'invalid') for s in $rs if s.get('id') == 'act']"
case_ reviewer $R reviewer-evidence-path   bad "[s['with'].__setitem__('path', '/nonexistent') for s in $rs if str(s.get('uses','')).startswith('actions/upload-artifact@')]"
pycase reviewer-py-real        ok  ""
pycase reviewer-py-pr-create   bad 'subprocess.run(["gh", "pr", "create", "--fill"])'
pycase reviewer-py-push        bad '_run(["git", "push", "origin", "HEAD"])'
pycase reviewer-py-shell       bad 'os.system("gh pr edit 99 --add-label x")'
pycase reviewer-py-contents    bad '_run(["gh", "api", "-X", "PUT", "repos/o/r/contents/x"])'
pycase reviewer-py-field-post  bad '_run(["gh", "api", "repos/o/r/issues", "-f", "title=x"])'
pycase reviewer-py-via-helper  bad '_gh_json(["repos/o/r/contents/x", "-X", "DELETE"])'
pycase reviewer-py-concat      bad 'subprocess.run(["gh", "pr"] + ["create", "--fill"])'
pycase reviewer-py-method-eq   bad '_gh_json(["repos/o/r/contents/x", "--method=DELETE"])'
pycase reviewer-py-method-var  bad 'm = "PUT"; _gh_json(["repos/o/r/contents/x", "-X", m])'
pycase reviewer-py-scans       bad '_run(["grype", "dir:."])'
pycase reviewer-py-edits-file  bad 'open("go.mod", "w").write("module changed")'
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
case_ automerge $A automerge-no-disarm     bad "$as_[:] = [s for s in $as_ if 'gh pr merge --disable-auto' not in (s.get('run') or '')]"
case_ reviewer $R reviewer-arm-any-head    bad "[s.__setitem__('run', s['run'].replace('--match-head-commit \"\$sha\" ', '')) for s in $rs if s.get('id') == 'act']"
case_ reviewer $R reviewer-majors-only     bad "[s.__setitem__('run', s['run'].replace('select(.major or .flagged)', 'select(.major)')) for s in $rs if s.get('id') == 'candidates']"
case_ reviewer $R reviewer-flagged-unnamed bad "[s.__setitem__('run', s['run'].replace('if .flagged then .major = true', 'if .flagged then .major = false')) for s in $rs if s.get('id') == 'candidates']"
case_ reviewer $R reviewer-put-back-unguarded bad "[s.__setitem__('run', s['run'].replace('bash bin/required-check-guard.sh \"\$RUNNER_TEMP/work/heal-required-checks.json\"', 'true')) for s in $rs if s.get('id') == 'candidates']"
case_ reviewer $R reviewer-no-put-back     bad "[s.__setitem__('run', s['run'].replace('auto_merge_disabled github-actions', 'auto_merge_disabled nobody')) for s in $rs if s.get('id') == 'candidates']"
case_ reviewer $R reviewer-no-mask         bad "$rs[:] = [s for s in $rs if s.get('id') != 'mask']"
case_ automerge $A automerge-event-head    bad "[s.__setitem__('run', s['run'].replace('headRefOid', 'title')) for s in $as_ if 'gh pr merge --disable-auto' in (s.get('run') or '')]"
case_ automerge $A automerge-disarm-blind  bad "[s.__setitem__('run', 'gh pr merge --disable-auto \"\$PR_URL\"') for s in $as_ if 'gh pr merge --disable-auto' in (s.get('run') or '')]"
case_ reviewer $R reviewer-mask-fails-run  bad "[s.pop('continue-on-error', None) for s in $rs if s.get('id') == 'mask']"
case_ automerge $A automerge-flagged-arms   bad "[s.__setitem__('if', \"steps.meta.outputs.update-type != 'version-update:semver-major'\") for s in $as_ if 'gh pr merge --auto' in (s.get('run') or '')]"
case_ automerge $A automerge-arm-any-head   bad "[s.__setitem__('run', s['run'].replace('--match-head-commit \"\$HEAD_SHA\" ', '')) for s in $as_ if 'gh pr merge --auto' in (s.get('run') or '')]"
case_ automerge $A automerge-no-screen      bad "$as_[:] = [s for s in $as_ if s.get('id') != 'screen']"
case_ automerge $A automerge-screen-soft    bad "[s.__setitem__('continue-on-error', 'true') for s in $as_ if s.get('id') == 'screen']"
case_ automerge $A automerge-screen-fetches bad "[s.__setitem__('run', s['run'].replace('set -euo pipefail', 'set -euo pipefail\\necho contents/bin/dependabot-reviewer.py')) for s in $as_ if s.get('id') == 'screen']"
case_ automerge $A automerge-screen-late    bad "i = [n for n, s in enumerate($as_) if s.get('id') == 'screen'][0]; g = $as_.pop(i); $as_.append(g)"
case_ automerge $A automerge-screen-body-inline bad "[s.__setitem__('run', s['run'] + ' echo \${{ github.event.pull_request.body }}') for s in $as_ if s.get('id') == 'screen']"
case_ automerge $A automerge-failed-screen-keeps-arm bad "[s.__setitem__('if', \"steps.meta.outputs.update-type == 'version-update:semver-major' || steps.screen.outputs.flagged == 'true'\") for s in $as_ if 'gh pr merge --disable-auto' in (s.get('run') or '')]"
case_ automerge $A automerge-flagged-no-void bad "[s.__setitem__('if', \"steps.meta.outputs.update-type == 'version-update:semver-major'\") for s in $as_ if 'gh pr merge --disable-auto' in (s.get('run') or '')]"
case_ automerge $A automerge-checkout      bad "$as_.insert(0, {'uses': 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1'})"

# the pinned tool module is held out of auto-merge, a normal lane PR (advisor Oct 12); a list at the API's cap of 100 files cannot be judged and is held too
case_ automerge $A automerge-hold-removed  bad "[s.__setitem__('run', s['run'].replace('startswith(\"tools/govulncheck/\")', 'startswith(\"tools/other/\")')) for s in $as_ if 'gh pr merge --auto --squash' in (s.get('run') or '')]"
case_ automerge $A automerge-hold-after    bad "[s.__setitem__('run', 'gh pr merge --auto --squash \"\$PR_URL\"\\n' + s['run']) for s in $as_ if 'gh pr merge --auto --squash' in (s.get('run') or '')]"
case_ reviewer  $R reviewer-hold-removed   bad "[s.__setitem__('run', s['run'].replace('startswith(\"tools/govulncheck/\")', 'startswith(\"tools/other/\")')) for s in $rs if s.get('id') == 'candidates']"
case_ reviewer  $R reviewer-hold-no-files  bad "[s.__setitem__('run', s['run'].replace('number,title,body,headRefOid,files', 'number,title,body,headRefOid')) for s in $rs if s.get('id') == 'candidates']"
case_ automerge $A automerge-cap-widened   bad "[s.__setitem__('run', s['run'].replace('-ge 100', '-ge 101')) for s in $as_ if 'gh pr merge --auto --squash' in (s.get('run') or '')]"
case_ automerge $A automerge-cap-removed   bad "[s.__setitem__('run', s['run'].replace('-ge 100', '-ge 0 -a 1 -eq 2')) for s in $as_ if 'gh pr merge --auto --squash' in (s.get('run') or '')]"
case_ reviewer  $R reviewer-cap-widened    bad "[s.__setitem__('run', s['run'].replace('>= 100', '>= 101')) for s in $rs if s.get('id') == 'candidates']"
case_ reviewer  $R reviewer-cap-removed    bad "[s.__setitem__('run', s['run'].replace('(.files | length) >= 100', 'false')) for s in $rs if s.get('id') == 'candidates']"
case_ reviewer  $R reviewer-hold-no-disarm bad "[s.__setitem__('run', s['run'].replace('--disable-auto', '--help')) for s in $rs if s.get('id') == 'candidates']"

# Codex 4b-5 r1 (A B4, B B3): the arming step is EXECUTED against a double of gh, not only read: held paths and the cap arm nothing, a lookalike directory and 99 files
# arm against the head that was read, an unreadable PR stops the step, and the arm always carries --match-head-commit
python3 - "$root/.github/workflows/$A" > "$work_am" 2>&1 <<'PY' && { pass=$((pass+1)); echo "PASS the arming step, executed against a gh double: held, lookalike, 99, 100, unreadable and head-bound cases"; } || { failn=$((failn+1)); echo "FAIL the arming step executed against a gh double: $(head -c 400 "$work_am")"; }
import json, os, stat, subprocess, sys, tempfile, yaml
d = yaml.safe_load(open(sys.argv[1]))
step = [s for s in d["jobs"]["auto-merge"]["steps"] if s.get("name") == "enable auto-merge"]
assert len(step) == 1, "no single `enable auto-merge` step"
run = step[0]["run"]
HEAD = "a" * 40
def case(files, view_rc=0, head=HEAD, screened=HEAD):
    t = tempfile.mkdtemp()
    os.makedirs(t + "/bin")
    open(t + "/snap.json", "w").write(json.dumps({"files": [{"path": f} for f in files], "headRefOid": head}))
    open(t + "/bin/gh", "w").write('#!/bin/sh\necho "gh $*" >> "$LOGF"\ncase "$1 $2" in\n  "pr view") [ "${VIEW_RC:-0}" = 0 ] || exit 1; cat "$SNAP" ;;\n  "pr merge") exit 0 ;;\n  *) exit 3 ;;\nesac\n')
    os.chmod(t + "/bin/gh", 0o755)
    open(t + "/step.sh", "w").write(run)
    env = dict(os.environ, PATH=t + "/bin:" + os.environ["PATH"], LOGF=t + "/log", SNAP=t + "/snap.json", VIEW_RC=str(view_rc),
               GITHUB_STEP_SUMMARY=t + "/summary", GH_TOKEN="x", HEAD_SHA=screened, **{"PR_URL": "https://github.com/o/r/pull/7"})
    r = subprocess.run(["bash", t + "/step.sh"], env=env, capture_output=True, text=True)
    log = open(t + "/log").read().splitlines() if os.path.exists(t + "/log") else []
    return r.returncode, [l for l in log if l.startswith("gh pr merge")]
bad = []
rc, m = case(["tools/govulncheck/go.mod"])
if rc != 0 or m: bad.append("a PR that touches tools/govulncheck/ was armed or the step failed: %s %s" % (rc, m))
rc, m = case(["docs/a.md", "tools/govulncheck/go.sum", "go.mod"])
if rc != 0 or m: bad.append("a mixed PR that touches tools/govulncheck/ was armed: %s %s" % (rc, m))
rc, m = case(["tools/govulncheck-extra/a.go", "go.mod", "go.sum"])
if rc != 0 or len(m) != 1 or "--match-head-commit " + HEAD not in m[0] or "--auto" not in m[0] or "--squash" not in m[0]:
    bad.append("a lookalike directory was held, or the arm is not bound to the head that was read: %s %s" % (rc, m))
rc, m = case(["f%d.md" % i for i in range(99)])
if rc != 0 or len(m) != 1 or "--match-head-commit " + HEAD not in m[0]: bad.append("99 files were not armed against the head: %s %s" % (rc, m))
rc, m = case(["f%d.md" % i for i in range(100)])
if rc != 0 or m: bad.append("a list of 100 files was armed (it cannot be judged): %s %s" % (rc, m))
rc, m = case(["go.mod"], view_rc=1)
if rc == 0 or m: bad.append("an unreadable PR did not stop the step or was armed: %s %s" % (rc, m))
rc, m = case(["go.mod"], head="")
if rc == 0 or m: bad.append("a PR with no readable head was armed: %s %s" % (rc, m))
# main's binding (REQ-DEP-001, cache#489 line): the arm is bound to the head THIS RUN SCREENED; a PR that has a newer head by now is not armed, and an unusable screened head stops the step
rc, m = case(["go.mod"], head="b" * 40)
if rc != 0 or m: bad.append("a PR with a newer head than the one the run screened was armed: %s %s" % (rc, m))
rc, m = case(["go.mod"], screened="")
if rc == 0 or m: bad.append("an empty screened head armed or did not stop the step: %s %s" % (rc, m))
print("; ".join(bad) or "ok")
sys.exit(1 if bad else 0)
PY

# REQ-DEP-003-AC2: the disarm step, run for real against a stub gh: armed with no verdict on the current head -> disarmed (the reviewer's
# next pass puts the arm back if it had approved the head: its own test covers that side, from GitHub's event record); not armed -> nothing;
# the reviewer's success already on the head -> auto-merge stands.
if python3 - "$root" "$work" <<'PY'
import os, subprocess, sys, yaml
root, work = sys.argv[1], sys.argv[2]
d = yaml.safe_load(open(os.path.join(root, ".github/workflows/dependabot-auto-merge.yml")))
run = [s["run"] for s in d["jobs"]["auto-merge"]["steps"] if "gh pr merge --disable-auto" in (s.get("run") or "")][0]
def go(verdict, armed="true"):
    bd = os.path.join(work, "disarm-stub"); os.makedirs(bd, exist_ok=True)
    log = os.path.join(bd, "log"); open(log, "w").close()
    open(os.path.join(bd, "gh"), "w").write("""#!/usr/bin/env bash
echo "gh $*" >> %s
case "$1 $2" in
  "pr view") case "$*" in *headRefOid*) echo HEAD1 ;; *autoMergeRequest*) echo %s ;; esac ;;
  "api repos/o/r/commits/HEAD1/check-runs?check_name=dependabot-reviewer") echo %s ;;
esac
""" % (log, armed, verdict))
    os.chmod(os.path.join(bd, "gh"), 0o755)
    env = {**os.environ, "PATH": bd + ":" + os.environ["PATH"], "GH_TOKEN": "x", "PR_URL": "https://example.invalid/pr/1", "HEAD_SHA": "HEAD1", "GITHUB_REPOSITORY": "o/r"}
    p = subprocess.run(["bash", "-e", "-o", "pipefail", "-c", run], env=env, capture_output=True, text=True)
    return p.returncode, open(log).read()
bad = []
rc, log = go("none")
if rc != 0 or "pr merge --disable-auto" not in log:
    bad.append("armed with no verdict: it must disarm (rc %s)\n%s" % (rc, log))
rc, log = go("none", armed="false")
if rc != 0 or "--disable-auto" in log:
    bad.append("not armed: nothing to do (rc %s)\n%s" % (rc, log))
rc, log = go("success")
if rc != 0 or "--disable-auto" in log:
    bad.append("success on the head: auto-merge must stand and nothing be written (rc %s)\n%s" % (rc, log))
print("disarm: " + ("ok" if not bad else "; ".join(bad)))
sys.exit(1 if bad else 0)
PY
then pass=$((pass+1)); echo "PASS disarm-only-an-unsupported-arm"; else failn=$((failn+1)); echo "FAIL disarm-only-an-unsupported-arm"; fi

# REQ-DEP-003-AC2: the screen's heredoc IS the reviewer's rule, byte for byte: the workflow's code must equal what is generated from
# bin/dependabot-reviewer.py (imports, the patterns, _Text, _drop_targets, is_flagged), so the two lanes cannot drift apart.
if python3 - "$root" <<'PY'
import ast, os, sys, yaml
root = sys.argv[1]
def heredoc(py_path):
    src = open(py_path).read(); lines = src.splitlines(); tree = ast.parse(src); chunks = []
    for node in tree.body:
        name = None
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) and node.targets[0].id in {"_FLAG", "_MDADJ", "_MDEXOTIC", "_MDLINK", "_CHARREF", "_MDLABEL", "_MDDEF"}: name = 1
        elif isinstance(node, (ast.ClassDef, ast.FunctionDef)) and node.name in ("_Text", "_drop_targets", "is_flagged"): name = 1
        if name: chunks.append("\n".join(lines[node.lineno - 1:node.end_lineno]))
    return "import html, os, re\nfrom html.parser import HTMLParser\n" + "\n".join(chunks) + '\nprint("flagged=" + str(is_flagged(os.environ["PR_BODY"])).lower())\n'
d = yaml.safe_load(open(os.path.join(root, ".github/workflows/dependabot-auto-merge.yml")))
run = [s["run"] for s in d["jobs"]["auto-merge"]["steps"] if s.get("id") == "screen"][0]
got = run.split("<<'PY'\n", 1)[1].rsplit("PY", 1)[0]
want = heredoc(os.path.join(root, "bin/dependabot-reviewer.py"))
print("screen heredoc == generated from the reviewer: " + ("ok" if got == want else "DIFFERS"))
sys.exit(0 if got == want else 1)
PY
then pass=$((pass+1)); echo "PASS screen-is-the-reviewers-code"; else failn=$((failn+1)); echo "FAIL screen-is-the-reviewers-code"; fi

# REQ-DEP-003-AC2: the screen's heredoc and the reviewer's is_flagged are the same rule. Run the workflow's
# own code against a corpus (the real Dependabot bodies and written edge cases) and compare.
if python3 - "$root" <<'PY'
import importlib.util, json, os, subprocess, sys, yaml
root = sys.argv[1]
d = yaml.safe_load(open(os.path.join(root, ".github/workflows/dependabot-auto-merge.yml")))
run = [s["run"] for s in d["jobs"]["auto-merge"]["steps"] if s.get("id") == "screen"][0]
spec = importlib.util.spec_from_file_location("reviewer", os.path.join(root, "bin/dependabot-reviewer.py"))
r = importlib.util.module_from_spec(spec); spec.loader.exec_module(r)
corpus = [json.load(open(os.path.join(root, "test-evidence/dependabot-reviewer", "pr-%d.json" % n)))["body"] for n in (99, 91, 124, 90, 400)]
corpus += ["", "Bumps a from 1.0.0 to 1.1.0.", "x <details>Breaking</details>", "breaking <details>fine</details>",
           "<DETAILS>DEPRECATED</DETAILS>", "<details><summary>a</summary><details>nested deprecates</details></details>",
           "<details>unclosed breaking", "<details>break<!-- > -->ing</details>", "<details>depre<span title=\">\">cat</span>ed</details>", "<code>&lt;breaking&gt;</code>", "<details><!-- </details> -->Breaking change<!-- <details> --></details>", "```\n<details>deprecated</details>\n```", "plain text, nothing", "**Break**ing change", "Depre*cat*ed", "[Break](https://example.invalid)ing", "![break*ing*](https://e.invalid/i.png)", "**Fixes** a [typo](https://e.invalid)", "[Break][ref]ing", "[Break](u (a)b)ing", "[Break](https://e.invalid/a(b)/c)**ing**", "[Break][ref]**ing**\n\n[ref]: https://e.invalid", "[Break](u \"a)b\")ing", "[Break](unterminated", "[Break][ref\\]*x]**ing** change\n\n[ref\\]*x]: https://e.invalid", "[Break](<#a)/b>)**ing** change", "[Break][r&#93; x]**ing**", "[Break][r\\] x]**ing**", "[Break](a&#41;b)<em>ing</em>", "[Break](a&#0041;b)<em>ing</em>", "[Break](a&#X29;b)<em>ing</em>", "[Break](a&#x0029;b)<em>ing</em>", "[Break](a&#41b)<em>ing</em>", "See [the docs](https://e.invalid/a(b)/c \"t\") and (parens)", "<details>Breaking change", "<details>Breaking change<details>fine</details>", "<details open>Breaking change</details>", "<details open>fine</details>", "</details> stray", "<details class=\"x\"><summary>s</summary>ok</details>", "<detailsx>breaking</detailsx>", "<details>break<b>ing</b> change</details>", "<details>depre&#99;ated</details>", "<details>break&lt;b&gt;ing</details>", "<details>&lt;p&gt;Deprecated&lt;/p&gt;</details>", "<details>a</details> deprecat <details>b</details>", "no notes, breaking change outside"]
bad = []
for body in corpus:
    p = subprocess.run(["bash", "-c", run], env={**os.environ, "PR_BODY": body, "GITHUB_OUTPUT": "/dev/stdout"}, capture_output=True, text=True)
    got = p.stdout.strip() == "flagged=true"
    if p.returncode != 0 or got != r.is_flagged(body):
        bad.append((body[:40], p.stdout.strip(), r.is_flagged(body), p.stderr[-80:]))
print("screen heredoc == reviewer is_flagged on %d bodies" % len(corpus) if not bad else "DISAGREE: %s" % bad)
sys.exit(1 if bad else 0)
PY
then pass=$((pass+1)); echo "PASS screen-agrees-with-reviewer"; else failn=$((failn+1)); echo "FAIL screen-agrees-with-reviewer"; fi

echo "dependency-lanes: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
