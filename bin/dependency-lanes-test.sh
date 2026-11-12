#!/usr/bin/env bash
# proves: REQ-DEP-001-AC1, REQ-DEP-001-AC3, REQ-DEP-001-AC5, REQ-DEP-001-AC6, REQ-DEP-001-AC8, REQ-DEP-001-AC9, REQ-DEP-001-AC10, REQ-DEP-001-AC11, REQ-DEP-001-AC12, REQ-DEP-001-AC13, REQ-DEP-002-AC1, REQ-DEP-003-AC1, REQ-DEP-003-AC2, REQ-DEP-003-AC3
# The dependency lanes' wiring (register rows 75, 80): the reviewer runs hourly from main and never on a PR
# event, one run at a time; it reads every Dependabot bump, arms or holds and posts its check but opens no PR and
# edits nothing; it carries a success to a new head only past the same-diff proof, and settles the arms after its act
# step; its evidence upload can never fail a run; the required-check guard runs on every PR and push to main; the
# patch/minor lane arms squash auto-merge only after the guard, never for a major and never for a head the reviewer
# failed, and its last step turns off an arm the reviewer's verdict does not allow. Each real workflow must pass;
# each mutated copy must be caught.
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
def in_order(text, *subs):
    """every sub is in text, each first occurrence after the one before"""
    at = [text.find(x) for x in subs]
    return all(i >= 0 for i in at) and at == sorted(at) and len(set(at)) == len(at)
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
    # REQ-DEP-001-AC2: every bump is read: the candidate step drops no pull request for its update kind, and the act step names EVERY update
    # of a bump (in its check and in the issue of a held one), never the majors only
    cand = [r for st, r in runs(job) if st.get("id") == "candidates"]
    acts = [r for st, r in runs(job) if st.get("id") == "act"]
    if len(cand) != 1 or re.search(r"select\(\.major|the patch/minor lane's\"; continue", cand[0]):
        bad.append("the candidate step leaves a pull request out for its update kind")
    if len(acts) != 1 or """names=$(jq -r '[.[]|"\\(.name) \\(.from)→\\(.to)"]|join(", ")'""" not in acts[0] or "select(.major)" in acts[0]:
        bad.append("the act step does not name every update of a bump (it selects by major)")
    # REQ-DEP-001-AC2, AC9: the act step gathers the diff of exactly the candidate's commit, and looks at the PR's head again after the
    # readers answered, before anything is armed, held or published
    if len(acts) == 1:
        a = acts[0]
        g = 'python3 bin/dependabot-reviewer.py gather --pr "$n" --sha "$sha" --updates "$W/updates-$n.json" --out "$d"'
        h = 'if [ "$head_now" != "$sha" ]; then'
        if not in_order(a, g, "decide --reader", h, 'case "$decision" in') \
                or not re.search(r'if \[ "\$head_now" != "\$sha" \]; then\n[^\n]*; continue\n', a):
            bad.append("the act step does not gather the diff of the candidate's exact commit, or does not skip a head that moved before it acts")
    # REQ-DEP-001-AC13: a verdict that is not success first fails the review gate's own check on that head, by the same App token, with the
    # gate's own fields; no step ever publishes a gate success; without the gate failure the reviewer's own check does not go up
    alltext = "\n".join(r for _, r in runs(job))
    gate_cmds = re.findall(r"gh api \"repos/\$\{GITHUB_REPOSITORY\}/check-runs\" -f name=auditor-review-gate(?:[^\n]*\\\n)*[^\n]*", alltext)
    if len(gate_cmds) != 3 or any("-f status=completed -f conclusion=failure -f details_url=\"$RUN_URL\"" not in c
                                  or '-f "output[title]=auditor review gate: failure"' not in c or "head_sha=" not in c for c in gate_cmds):
        bad.append("the review gate's check is not published exactly as a failure in the gate's own form (three places: candidates, act, cancellation)")
    if re.search(r"name=auditor-review-gate(?:(?!name=dependabot-reviewer)[\s\S]){0,400}?conclusion=(?!failure)", alltext):
        bad.append("a step publishes the review gate's check with a conclusion that is not failure")
    if len(acts) == 1:
        a = acts[0]
        own = 'GH_TOKEN="$CHECKS_TOKEN" gh api "repos/${GITHUB_REPOSITORY}/check-runs" -f name=dependabot-reviewer'
        gate = 'GH_TOKEN="$CHECKS_TOKEN" gh api "repos/${GITHUB_REPOSITORY}/check-runs" -f name=auditor-review-gate'
        m = re.search(r'publish\(\) \{[^\n]*\n\s*if \[ "\$2" != success \]; then\n\s*' + re.escape(gate) + r'(?:[^\n]*\\\n)*[^\n]*>/dev/null \|\| return 1\n\s*fi\n\s*' + re.escape(own), a)
        if not m or a.count("name=dependabot-reviewer") != 1 or a.count("name=auditor-review-gate") != 1:
            bad.append("the act step's one publish function does not fail the review gate's check first (and stop without it) for every verdict that is not success")
    if len(cand) == 1:
        c = cand[0]
        first = 'if ! gate_fail "$sha" "The Dependabot reviewer is $again"; then'
        if c.count("conclusion=neutral") != 1 or not in_order(c, first, "conclusion=neutral") \
                or not re.search(re.escape(first) + r"\n[^\n]*\n\s*lookup_failed=1; continue\n", c) \
                or 'GH_TOKEN="$APP_TOKEN" gh api "repos/${GITHUB_REPOSITORY}/check-runs" -f name=auditor-review-gate' not in c \
                or 'gate_stands "$n" "$sha" failure ||' not in c or 'if [ "$prior" = neutral ] && ! gate_stands "$n" "$sha" neutral; then' not in c:
            bad.append("the candidate step does not fail the review gate's check before its neutral, or does not fail it again over a failure or neutral verdict")
    canc = [r for st, r in runs(job) if (st.get("name") or "").startswith("on cancellation")]
    if len(canc) != 1 or canc[0].count("conclusion=neutral") != 1 \
            or not in_order(canc[0], "check-runs\" -f name=auditor-review-gate", "check-runs\" -f name=dependabot-reviewer") \
            or not re.search(r"name=auditor-review-gate(?:[^\n]*\\\n)*[^\n]*>/dev/null \\\n\s*&& \\\n\s*GH_TOKEN=\"\$APP_TOKEN\" gh api \"repos/\$\{GITHUB_REPOSITORY\}/check-runs\" -f name=dependabot-reviewer", canc[0]):
        bad.append("the cancellation step does not fail the review gate's check before its neutral (the neutral only after it)")
    # REQ-DEP-001-AC10 / REQ-DEP-003-AC1: whose arm a head's is before a verdict: the lane's only when EVERY update is a plain patch or minor
    # (not a major, not flagged, not one that could not be read)
    if len(cand) == 1 and """lane=$(jq -r 'if length > 0 and all(.[]; .kind == "not-major") then "yes" else "no" end'""" not in cand[0]:
        bad.append("the candidate step does not keep the lane's arm for plain patch and minor bumps only (every update of kind not-major)")
    # REQ-DEP-001-AC13: a success verdict (read or carried) over a stale gate failure has the failure published again, by the gate's own six-hour line
    if len(cand) == 1 and (not re.search(r'if \[ "\$prior" = success \]; then\n\s+gate_refresh "\$n" "\$sha" \|\|', cand[0])
                           or '[ "$g" = stale ] || return 0' not in cand[0] or "(now - (.completed_at | fromdate)) < 21600" not in cand[0]):
        bad.append("the candidate step does not publish a stale gate failure again over a success verdict")
    if len(cand) == 1 and ("auto_merge_disabled github-actions" not in cand[0] or "required-check-guard.sh" not in cand[0] or '--match-head-commit "$sha"' not in cand[0]):
        bad.append("the candidate step does not put back (guard first, exact head) an arm the lane turned off after the reviewer approved the head")
    # REQ-DEP-001-AC11: the one success this step publishes itself (the carried one) comes only past the same-diff proof, never on a forced run
    if len(cand) == 1:
        proof = 'if [ -n "$from" ] && python3 bin/dependabot-reviewer.py same-diff --repo "$GITHUB_REPOSITORY" --base main "$from" "$sha"; then'
        guard = 'if [ "$prior" = none ] && [ "$FORCE" != "true" ]; then'
        if cand[0].count("conclusion=success") != 1 or proof not in cand[0] or guard not in cand[0] \
                or not cand[0].index(guard) < cand[0].index(proof) < cand[0].index("conclusion=success"):
            bad.append("the candidate step publishes a success that is not behind the same-diff proof (a head with no verdict, not forced)")
    # REQ-DEP-001-AC12: the settle step runs after the act step and the cancellation cleanup, whatever became of them, and can fail the run
    names = [s.get("id") or s.get("name", "") for s in job.get("steps", [])]
    st = [s for s in job.get("steps", []) if s.get("id") == "settle"]
    cancel = [i for i, x in enumerate(names) if x.startswith("on cancellation")]
    if len(st) != 1 or "continue-on-error" in st[0] or len(cancel) != 1 or "act" not in names or not names.index("act") < cancel[0] < names.index("settle") \
            or st[0].get("if") != "${{ always() && steps.candidates.outputs.count != '0' && steps.candidates.outputs.count != '' && steps.app-merge.outcome == 'success' }}":
        bad.append("no settle step after the act step and the cancellation cleanup, always run, able to fail the run")
    elif len(cand) == 1 and ('>> "$RUNNER_TEMP/work/lane-arms.txt"' not in cand[0] or 'grep -qx "$n $sha" "$W/lane-arms.txt"' not in (st[0].get("run") or "")
                             or "required-check-guard.sh" not in (st[0].get("run") or "") or '"failure true")' not in (st[0].get("run") or "")):
        bad.append("the settle step does not turn off an arm over a failure verdict, or does not put back (guard first) exactly the lane's arms the candidate step remembered")
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
    # REQ-DEP-003-AC3: the arm step reads the reviewer's verdict on the head it arms first, and leaves a failed head unarmed
    elif "set -euo pipefail" not in runs(job)[arm[0]][1] or "commits/${HEAD_SHA}/check-runs?check_name=dependabot-reviewer" not in runs(job)[arm[0]][1] \
            or not re.search(r'if \[ "\$verdict" = failure \]; then [^\n]*exit 0; fi\n\s*gh pr merge --auto --squash', runs(job)[arm[0]][1]):
        bad.append("the arm step does not read the reviewer's verdict on this head first and leave a failed head unarmed")
    # the last step: no arm the reviewer's verdict on the current head does not allow. Run for every bump (a failed patch too); the
    # no-verdict disarm applies to a major, a flagged bump or a failed screen (WAITS_FOR_VERDICT)
    major = "${{ steps.meta.outputs.update-type == 'version-update:semver-major' || steps.screen.outputs.flagged == 'true' || steps.screen.outcome == 'failure' || steps.meta.outcome == 'failure' }}"
    disarm = [(i, s, r) for i, (s, r) in enumerate(runs(job)) if "gh pr merge --disable-auto" in r]
    if len(disarm) != 1 or disarm[0][1].get("if") != "${{ !cancelled() }}" or "continue-on-error" in disarm[0][1]:
        bad.append("no single last step, run for every bump, that turns off an arm the reviewer's verdict does not allow")
    elif (disarm[0][1].get("env") or {}).get("WAITS_FOR_VERDICT") != major:
        bad.append("a push to a major PR does not turn its auto-merge off (the reviewed head's verdict is void)")
    elif "check-runs?check_name=dependabot-reviewer" not in disarm[0][2] or "headRefOid" not in disarm[0][2]:
        bad.append("the disarm does not judge the PR's CURRENT head by its reviewer check (a stale push job must not disarm a newer approved head)")
    elif arm and disarm[0][0] < arm[0]:
        bad.append("the look at the reviewer's verdict that can disarm comes before the arm: a failure published while the lane arms would stay armed")
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
case_ reviewer $R reviewer-majors-only     bad "[s.__setitem__('run', s['run'].replace('all(.[]; .kind == \"not-major\")', 'all(.[]; .major | not)')) for s in $rs if s.get('id') == 'candidates']"
case_ reviewer $R reviewer-no-stale-refresh bad "[s.__setitem__('run', s['run'].replace('gate_refresh \"\$n\" \"\$sha\" ||', 'true ||')) for s in $rs if s.get('id') == 'candidates']"
case_ reviewer $R reviewer-refresh-any-failure bad "[s.__setitem__('run', s['run'].replace('[ \"\$g\" = stale ] || return 0', '[ \"\$g\" != success ] || return 0')) for s in $rs if s.get('id') == 'candidates']"
case_ reviewer $R reviewer-update-unnamed  bad "[s.__setitem__('run', s['run'].replace('[.[]|\"', '[.[]|select(.major)|\"')) for s in $rs if s.get('id') == 'act']"
case_ reviewer $R reviewer-patches-skipped bad "[s.__setitem__('run', s['run'].replace('lane=\$(jq', 'jq -e \"any(.[]; select(.major))\" x || continue; lane=\$(jq')) for s in $rs if s.get('id') == 'candidates']"
case_ reviewer $R reviewer-gather-any-head bad "[s.__setitem__('run', s['run'].replace('gather --pr \"\$n\" --sha \"\$sha\"', 'gather --pr \"\$n\"')) for s in $rs if s.get('id') == 'act']"
case_ reviewer $R reviewer-moved-head-acts bad "[s.__setitem__('run', s['run'].replace('if [ \"\$head_now\" != \"\$sha\" ]; then', 'if false; then')) for s in $rs if s.get('id') == 'act']"
case_ reviewer $R reviewer-gate-not-first  bad "[s.__setitem__('run', s['run'].replace('if [ \"\$2\" != success ]; then', 'if false; then')) for s in $rs if s.get('id') == 'act']"
case_ reviewer $R reviewer-gate-soft       bad "[s.__setitem__('run', s['run'].replace('it is not passed.\" >/dev/null || return 1', 'it is not passed.\" >/dev/null || true')) for s in $rs if s.get('id') == 'act']"
case_ reviewer $R reviewer-gate-success    bad "$rs.append({'run': 'gh api \"repos/\${GITHUB_REPOSITORY}/check-runs\" -f name=auditor-review-gate -f head_sha=x -f status=completed -f conclusion=success'})"
case_ reviewer $R reviewer-force-no-gate   bad "[s.__setitem__('run', s['run'].replace('if ! gate_fail \"\$sha\" \"The Dependabot reviewer is', 'if ! true \"\$sha\" \"The Dependabot reviewer is')) for s in $rs if s.get('id') == 'candidates']"
case_ reviewer $R reviewer-no-gate-again   bad "[s.__setitem__('run', s['run'].replace('gate_stands \"\$n\" \"\$sha\" failure ||', 'true ||')) for s in $rs if s.get('id') == 'candidates']"
case_ reviewer $R reviewer-cancel-no-gate  bad "[s.__setitem__('run', s['run'].replace('name=auditor-review-gate', 'name=dependabot-reviewer', 1)) for s in $rs if (s.get('name') or '').startswith('on cancellation')]"
case_ reviewer $R reviewer-carry-unproven  bad "[s.__setitem__('run', s['run'].replace('python3 bin/dependabot-reviewer.py same-diff --repo \"\$GITHUB_REPOSITORY\" --base main \"\$from\" \"\$sha\"', 'true')) for s in $rs if s.get('id') == 'candidates']"
case_ reviewer $R reviewer-carry-forced    bad "[s.__setitem__('run', s['run'].replace('if [ \"\$prior\" = none ] && [ \"\$FORCE\" != \"true\" ]; then', 'if [ \"\$prior\" = none ]; then')) for s in $rs if s.get('id') == 'candidates']"
case_ reviewer $R reviewer-no-settle       bad "$rs[:] = [s for s in $rs if s.get('id') != 'settle']"
case_ reviewer $R reviewer-settle-soft     bad "[s.__setitem__('continue-on-error', 'true') for s in $rs if s.get('id') == 'settle']"
case_ reviewer $R reviewer-settle-early    bad "i = [n for n, s in enumerate($rs) if s.get('id') == 'settle'][0]; g = $rs.pop(i); $rs.insert([n for n, s in enumerate($rs) if s.get('id') == 'act'][0], g)"
case_ reviewer $R reviewer-settle-not-always bad "[s.__setitem__('if', s['if'].replace('always()', '!cancelled()')) for s in $rs if s.get('id') == 'settle']"
case_ reviewer $R reviewer-settle-unguarded bad "[s.__setitem__('run', s['run'].replace('bash bin/required-check-guard.sh \"\$W/settle-required-checks.json\"', 'true')) for s in $rs if s.get('id') == 'settle']"
case_ reviewer $R reviewer-settle-keeps-failed-arm bad "[s.__setitem__('run', s['run'].replace('\"failure true\")', '\"failure never\")')) for s in $rs if s.get('id') == 'settle']"
case_ reviewer $R reviewer-lane-arm-forgotten bad "[s.__setitem__('run', s['run'].replace('>> \"\$RUNNER_TEMP/work/lane-arms.txt\"', '>> /dev/null')) for s in $rs if s.get('id') == 'candidates']"
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
case_ automerge $A automerge-failed-screen-keeps-arm bad "[s['env'].__setitem__('WAITS_FOR_VERDICT', \"\${{ steps.meta.outputs.update-type == 'version-update:semver-major' || steps.screen.outputs.flagged == 'true' }}\") for s in $as_ if 'gh pr merge --disable-auto' in (s.get('run') or '')]"
case_ automerge $A automerge-flagged-no-void bad "[s['env'].__setitem__('WAITS_FOR_VERDICT', \"\${{ steps.meta.outputs.update-type == 'version-update:semver-major' }}\") for s in $as_ if 'gh pr merge --disable-auto' in (s.get('run') or '')]"
case_ automerge $A automerge-failed-meta-keeps-arm bad "[s['env'].__setitem__('WAITS_FOR_VERDICT', s['env']['WAITS_FOR_VERDICT'].replace(\" || steps.meta.outcome == 'failure'\", '')) for s in $as_ if 'gh pr merge --disable-auto' in (s.get('run') or '')]"
case_ automerge $A automerge-failed-patch-keeps-arm bad "[s.__setitem__('if', \"\${{ !cancelled() && (steps.meta.outputs.update-type == 'version-update:semver-major' || steps.screen.outputs.flagged == 'true' || steps.screen.outcome == 'failure') }}\") for s in $as_ if 'gh pr merge --disable-auto' in (s.get('run') or '')]"
case_ automerge $A automerge-arms-failed-head bad "[s.__setitem__('run', '\\n'.join(l for l in s['run'].split('\\n') if 'verdict' not in l)) for s in $as_ if 'gh pr merge --auto' in (s.get('run') or '')]"
case_ automerge $A automerge-arms-blind      bad "[s.__setitem__('run', s['run'].replace('set -euo pipefail', 'set +e')) for s in $as_ if 'gh pr merge --auto' in (s.get('run') or '')]"
case_ automerge $A automerge-void-before-arm bad "i = [n for n, s in enumerate($as_) if 'gh pr merge --disable-auto' in (s.get('run') or '')][0]; g = $as_.pop(i); $as_.insert(0, g)"
case_ automerge $A automerge-checkout      bad "$as_.insert(0, {'uses': 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1'})"

# REQ-DEP-003-AC2, AC3: the lane's last step, run for real against a stub gh. A major, a flagged bump or a failed screen (WAITS_FOR_VERDICT
# true): armed with no verdict on the current head -> disarmed (the reviewer's next pass puts the arm back if it had approved the head: its
# own test covers that side, from GitHub's event record); not armed -> nothing; the reviewer's success already on the head -> auto-merge
# stands. A plain patch or minor (false): its arm stands with no verdict. Any bump: armed over the reviewer's failure -> disarmed.
# And the arm step: it arms a patch whose head has no verdict, a neutral or a success, never one the reviewer failed, and nothing when
# the verdict cannot be read.
if python3 - "$root" "$work" <<'PY'
import os, subprocess, sys, yaml
root, work = sys.argv[1], sys.argv[2]
d = yaml.safe_load(open(os.path.join(root, ".github/workflows/dependabot-auto-merge.yml")))
steps = d["jobs"]["auto-merge"]["steps"]
last = [s["run"] for s in steps if "gh pr merge --disable-auto" in (s.get("run") or "")][0]
arm = [s["run"] for s in steps if "gh pr merge --auto --squash" in (s.get("run") or "")][0]
def go(run, verdict, armed="true", waits="true", lookup_fails=False):
    bd = os.path.join(work, "disarm-stub"); os.makedirs(bd, exist_ok=True)
    log = os.path.join(bd, "log"); open(log, "w").close()
    open(os.path.join(bd, "gh"), "w").write("""#!/usr/bin/env bash
echo "gh $*" >> %s
case "$1 $2" in
  "pr view") case "$*" in *headRefOid*) echo HEAD1 ;; *autoMergeRequest*) echo %s ;; esac ;;
  "api repos/o/r/commits/HEAD1/check-runs?check_name=dependabot-reviewer") %s echo %s ;;
esac
""" % (log, armed, "exit 1;" if lookup_fails else "", verdict))
    os.chmod(os.path.join(bd, "gh"), 0o755)
    env = {**os.environ, "PATH": bd + ":" + os.environ["PATH"], "GH_TOKEN": "x", "PR_URL": "https://example.invalid/pr/1", "HEAD_SHA": "HEAD1", "GITHUB_REPOSITORY": "o/r",
           "WAITS_FOR_VERDICT": waits}
    p = subprocess.run(["bash", "-e", "-o", "pipefail", "-c", run], env=env, capture_output=True, text=True)
    return p.returncode, open(log).read()
bad = []
rc, log = go(last, "none")
if rc != 0 or "pr merge --disable-auto" not in log:
    bad.append("a major armed with no verdict: it must disarm (rc %s)\n%s" % (rc, log))
rc, log = go(last, "none", armed="false")
if rc != 0 or "--disable-auto" in log:
    bad.append("not armed: nothing to do (rc %s)\n%s" % (rc, log))
rc, log = go(last, "success")
if rc != 0 or "--disable-auto" in log:
    bad.append("success on the head: auto-merge must stand and nothing be written (rc %s)\n%s" % (rc, log))
for verdict in ("none", "neutral"):
    rc, log = go(last, verdict, waits="false")
    if rc != 0 or "--disable-auto" in log:
        bad.append("a plain patch armed with verdict %s: the lane's arm must stand (rc %s)\n%s" % (verdict, rc, log))
for waits in ("false", "true"):
    rc, log = go(last, "failure", waits=waits)
    if rc != 0 or "pr merge --disable-auto" not in log:
        bad.append("armed over the reviewer's failure (waits=%s): it must disarm (rc %s)\n%s" % (waits, rc, log))
    rc, log = go(last, "failure", armed="false", waits=waits)
    if rc != 0 or "--disable-auto" in log:
        bad.append("a failed head that is not armed (waits=%s): nothing to do (rc %s)\n%s" % (waits, rc, log))
rc, log = go(last, "none", waits="false", lookup_fails=True)
if rc == 0 or "pr merge" in log:
    bad.append("the verdict cannot be read: the step must fail loudly and write nothing (rc %s)\n%s" % (rc, log))
for verdict in ("none", "neutral", "success"):
    rc, log = go(arm, verdict, armed="false")
    if rc != 0 or "pr merge --auto --squash --match-head-commit HEAD1 https://example.invalid/pr/1" not in log:
        bad.append("the arm step, verdict %s: it must arm exactly this head (rc %s)\n%s" % (verdict, rc, log))
    elif log.index("check-runs?check_name=dependabot-reviewer") > log.index("pr merge --auto"):
        bad.append("the arm step must read the verdict BEFORE it arms\n%s" % log)
rc, log = go(arm, "failure", armed="false")
if rc != 0 or "pr merge" in log:
    bad.append("the arm step on a head the reviewer failed: it must arm nothing and not fail (rc %s)\n%s" % (rc, log))
rc, log = go(arm, "none", armed="false", lookup_fails=True)
if rc == 0 or "pr merge" in log:
    bad.append("the arm step when the verdict cannot be read: it must fail and arm nothing (rc %s)\n%s" % (rc, log))
print("lane arm and last step: " + ("ok" if not bad else "; ".join(bad)))
sys.exit(1 if bad else 0)
PY
then pass=$((pass+1)); echo "PASS arm-never-a-failed-head-and-disarm-only-an-unsupported-arm"; else failn=$((failn+1)); echo "FAIL arm-never-a-failed-head-and-disarm-only-an-unsupported-arm"; fi

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

# REQ-DEP-001-AC13: the reviewer publishes a gate failure again only when the gate's sweep has stopped judging it.
# Each reads the age of the App's newest gate check with its own command. Run for real over the same check runs, the
# two must give the same answer at every age, or a failure falls between them (too old for the sweep, not old enough
# for the reviewer) and the head stays red.
if python3 - "$root" "$work" <<'PY'
import datetime, json, os, re, subprocess, sys, yaml
root, work = sys.argv[1], sys.argv[2]
def run_text(workflow, job, pick):
    steps = yaml.safe_load(open(os.path.join(root, ".github/workflows", workflow)))["jobs"][job]["steps"]
    (text,) = [s["run"] for s in steps if pick(s)]
    return text
sweep = run_text("agent-review-gate.yml", "sweep", lambda s: "check_name=auditor-review-gate" in (s.get("run") or ""))
cand = run_text("dependabot-reviewer.yml", "review", lambda s: s.get("id") == "candidates")
# each workflow's own lookup, cut out whole: the sweep's `last="$(…)"` and the reviewer's function gate_of
(sweep_cmd,) = re.findall(r'last="\$\((GH_TOKEN="\$APP_TOKEN" gh api [^\n]*check_name=auditor-review-gate.*?)\)" \\\n',
                          sweep, re.S)
(gate_of,) = re.findall(r'(?m)^(gate_of\(\) \{.*?\n\})\n', cand, re.S)
stub = os.path.join(work, "window-stub"); os.makedirs(stub, exist_ok=True)
open(os.path.join(stub, "gh"), "w").write("""#!/usr/bin/env bash
f=; while [ $# -gt 0 ]; do [ "$1" = --jq ] && f="$2"; shift; done
jq -r "$f" "$CHECK_RUNS"
""")
os.chmod(os.path.join(stub, "gh"), 0o755)
def answer(script, runs):
    path = os.path.join(work, "window-runs.json")
    json.dump({"check_runs": runs}, open(path, "w"))
    env = {**os.environ, "PATH": stub + ":" + os.environ["PATH"], "CHECK_RUNS": path, "APP_TOKEN": "t",
           "APP_SLUG": "the-app", "GITHUB_REPOSITORY": "o/r", "sha": "abc"}
    p = subprocess.run(["bash", "-euo", "pipefail", "-c", script], env=env, capture_output=True, text=True)
    return p.stdout.strip() if p.returncode == 0 else "error: " + p.stderr.strip()[-80:]
def aged(conclusion, hours):
    at = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=hours)
    return {"conclusion": conclusion, "completed_at": at.strftime("%Y-%m-%dT%H:%M:%SZ"), "app": {"slug": "the-app"}}
bad, seen = [], set()
cases = [("no check", [])] + [("a success %sh old" % h, [aged("success", h)]) for h in (1, 30)] \
    + [("a failure %sh old" % h, [aged("failure", h)]) for h in (0.1, 1, 3, 5, 5.9, 6.1, 7, 9, 12, 24, 72)]
for name, runs in cases:
    a, b = answer(sweep_cmd, runs), answer(gate_of + "\ngate_of abc", runs)
    seen.add(a)
    if a != b or a not in ("none", "success", "failure", "stale"):
        bad.append("%s: the sweep reads %r, the reviewer reads %r" % (name, a, b))
if seen != {"none", "success", "failure", "stale"}:
    bad.append("the cases did not reach all four answers: %s" % sorted(seen))
print("gate window: " + ("the sweep and the reviewer read every age alike" if not bad else "; ".join(bad)))
sys.exit(1 if bad else 0)
PY
then pass=$((pass+1)); echo "PASS gate-window-same-in-both"
else failn=$((failn+1)); echo "FAIL gate-window-same-in-both"; fi

echo "dependency-lanes: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
