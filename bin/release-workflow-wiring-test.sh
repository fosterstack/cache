#!/usr/bin/env bash
# proves: REQ-CHAIN-001-AC9, REQ-CHAIN-003-AC5, REQ-CHAIN-004-AC1, REQ-CHAIN-004-AC12, REQ-CHAIN-004-AC14, REQ-CHAIN-004-AC19, REQ-CHAIN-005-AC1, REQ-CHAIN-005-AC5, REQ-CHAIN-005-AC7, REQ-CHAIN-006-AC1
# The release is ONE workflow file, .github/workflows/release.yml (owner rule workflow-grouped-by-purpose, Nov 13 2026; orchestrator rulings in
# /srv/handoffs/briefs/cache-921-signer-identity-ruling.md and kvm-postponed-one-build-path.md). This suite judges that file from the PARSED workflow (never from substrings of
# the text), once on the real file, which must pass, and on mutated copies, each of which must be refused FOR THE REASON NAMED (a refusal for another reason, or a crash, counts as a failure).
# What it pins is what the English rows say and nothing more:
#   REQ-CHAIN-005-AC5  the job graph: the chain jobs and their needs, the gate G on build-freeze, the guard S on sign, sign-rebuild, sign-check and (followed by && !contains(github.ref_name, '-')) sign-release and release, the Check jobs'
#                      condition, no if on the Rebuild jobs, workflow-level permissions {}, the allowed other jobs, the dry-run input a boolean
#   REQ-CHAIN-001-AC9  the four sign jobs: environment sign, exactly contents read and id-token write, the three KMS federation literals as job env, the only jobs that run a signing
#                      command; the release job holds no AWS role and no id-token; no other file's job names the key role
#   REQ-CHAIN-004-AC1  Build: build-freeze, build-apk (matrix over both chips), build-assemble, their permissions, steps and shape
#   REQ-CHAIN-004-AC12 the one input `mode` on workflow_call, the guard step after the checkout, one Witness step per mode with its closed step name
#   REQ-CHAIN-004-AC19 the hostile Build step runs in every build: no condition, no token
#   REQ-CHAIN-005-AC1 / AC7  Rebuild: rebuild-apk (needs build-assemble only) is ONE job over both chips (no second per-chip job), rebuild-assemble, both starting from the unsigned artifact witness-build in every mode, the snapshot step names
#   REQ-CHAIN-006-AC1  Check: check-govulncheck and check (ONE job over both chips, one script bin/check-phase.sh, no arm64 job or script)
#   REQ-CHAIN-004-AC14 the snapshot callers scan.yml and main-candidate-rescan.yml (their job build; the permissions ceiling is the called file's set; no job reachable in snapshot
#                      mode requests a write or an id-token) -- the callers' own shape is also judged by bin/workflow-consolidation-test.sh
#   REQ-CHAIN-003-AC5  who may call release.yml (only those two, in snapshot mode) and the guard of every sign job and of release, one case each
# Needs python3 with PyYAML (apt: python3-yaml). No network, no secrets.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
python3 -c 'import yaml' 2> /dev/null || { echo "FAIL python3 needs PyYAML (install the python3-yaml package)"; exit 1; }
cat > "$work/judge.py" <<'PY'
import glob, json, os, re, sys, yaml

path, root = sys.argv[1], sys.argv[2]
WF = os.path.join(root, ".github/workflows")
RUNNERS = ["ubuntu-24.04", "ubuntu-24.04-arm"]
SIGN_JOBS = ["sign", "sign-rebuild", "sign-check", "sign-release"]
BUILD_JOBS = ["build-freeze", "build-apk", "build-assemble"]
REBUILD_JOBS = ["rebuild-apk", "rebuild-assemble"]
CHECK_JOBS = ["check-govulncheck", "check"]
RELEASE_JOBS = ["release-compare", "release-verify", "release"]
EVIDENCE_STEPS = [("release-assets", "bin/release-assets.sh"), ("release-postverify", "bin/release-postverify.sh")]
CHAIN = BUILD_JOBS + ["sign"] + REBUILD_JOBS + ["sign-rebuild"] + CHECK_JOBS + ["sign-check"] + RELEASE_JOBS + ["sign-release", "release-evidence"]
OTHER_ALLOWED = {"decide", "patch-notes", "patch-failed", "live-test", "live-test-release"}   # and the hostile-* jobs; persona-uat has its own file
KMS_ENV = ["AWS_ROLE_ARN", "AWS_REGION", "RELEASE_KMS_KEY_REF"]
NEEDS = {   # exactly, as REQ-CHAIN-005-AC5 lists them
    "build-freeze": [], "build-apk": ["build-freeze"], "rebuild-apk": ["build-assemble"], "build-assemble": ["build-apk"], "sign": ["build-assemble"],
    "rebuild-assemble": ["rebuild-apk"], "sign-rebuild": ["build-assemble", "rebuild-assemble"],
    "sign-check": ["build-assemble", "check"],
    "release-compare": ["check", "sign", "sign-rebuild", "sign-check"], "release-verify": ["release-compare"],
    "release": ["release-verify", "release-compare"], "sign-release": ["build-assemble", "release"], "release-evidence": ["sign-release"],
}
NEEDS_AT_LEAST = {"check": ["check-govulncheck", "build-assemble", "sign"]}

def norm(expr):
    """an expression with the ${{ }} wrapper removed and whitespace removed only OUTSIDE quoted strings (exact comparison)"""
    e = str(expr).strip()
    m = re.fullmatch(r"\$\{\{(.*)\}\}", e, re.S)
    e = m.group(1) if m else e
    out, q = [], None
    for c in e:
        if q:
            out.append(c); q = None if c == q else q
        elif c in "'\"":
            out.append(c); q = c
        elif not c.isspace():
            out.append(c)
    return "".join(out)
G = norm("(github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')) || inputs.dry-run == true || inputs.mode == 'snapshot'")
S = norm("inputs.mode != 'snapshot' && github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && startsWith(github.workflow_ref, format('{0}/.github/workflows/release.yml@', github.repository))")
S_TAG = S + norm(" && !contains(github.ref_name, '-')")   # sign-release, release and release-evidence: S, then the release-candidate rule, in the job's if
NOT_SNAPSHOT = norm("inputs.mode != 'snapshot'")

def load(p): return yaml.load(open(p), Loader=yaml.BaseLoader)
def needs_of(j):
    n = j.get("needs") or []
    return [n] if isinstance(n, str) else list(n)
def steps_of(j): return [s for s in (j.get("steps") or []) if isinstance(s, dict)]
def runs_of(j): return "\n".join((s.get("run") or "") for s in steps_of(j))
def text_of(o): return json.dumps(o, sort_keys=True)
def matrix_runners(j):
    m = ((j.get("strategy") or {}).get("matrix") or {})
    vals = [v for k, v in m.items() if k not in ("include", "exclude")]
    return vals[0] if len(vals) == 1 and isinstance(vals[0], list) else None
def witness_lines(j):   # (step name, script) of every witnessed(-local).sh line of a job
    out = []
    for s in steps_of(j):
        for m in re.finditer(r"bash bin/witnessed(?:-local)?\.sh (\S+) (\S+)", s.get("run") or ""):
            out.append((m.group(1), m.group(2), s))
    return out

bad = []
d = load(path)
jobs = d.get("jobs") or {}
on = d.get("on") or {}
if not isinstance(on, dict):
    bad.append("on: is not a mapping"); on = {}

# ---- the triggers and the workflow level (REQ-CHAIN-004-AC12, REQ-CHAIN-005-AC5) -------------------------------------------------------------------------
wc = on.get("workflow_call")
if wc is None:
    bad.append("release.yml has no workflow_call trigger (scan.yml and main-candidate-rescan.yml call it in snapshot mode)")
else:
    ins = (wc or {}).get("inputs") or {}
    if sorted(ins) != ["mode"] or ins["mode"].get("type") != "string" or ins["mode"].get("default") != "release":
        bad.append("workflow_call takes exactly one input, mode (type string, default release): %s" % ins)
    if (wc or {}).get("secrets"):
        bad.append("workflow_call declares secrets: the callers pass none")
dispatch = on.get("workflow_dispatch")
if isinstance(dispatch, dict) and "dry-run" in (dispatch.get("inputs") or {}) and dispatch["inputs"]["dry-run"].get("type") != "boolean":
    bad.append("the dry-run dispatch input is not of type boolean (a string would make inputs.dry-run == true false and silently skip the dry run)")
if d.get("permissions") != {}:
    bad.append("the workflow-level permissions are not empty ({}): %s" % d.get("permissions"))
for k in ("env", "defaults"):
    if d.get(k):
        bad.append("release.yml has a workflow-level %s" % k)

# ---- the job set and the graph (REQ-CHAIN-005-AC5) -------------------------------------------------------------------------------------------------
for jn in CHAIN:
    if jn not in jobs:
        bad.append("release.yml has no chain job %s" % jn)
for old in ("build", "rebuild", "check-arm64", "rapk", "rapk-arm", "apk", "assemble", "freeze", "govulncheck-build", "compare", "verify"):
    if old in jobs:
        bad.append("release.yml still has the stage-era job %s (the jobs are %s)" % (old, ", ".join(CHAIN)))
for jn in jobs:
    if jn not in CHAIN and jn not in OTHER_ALLOWED and not jn.startswith("hostile-") and jobs[jn].get("uses") != "./.github/workflows/persona-uat.yml":
        bad.append("job %s is not a chain job nor on the allowed list (decide, patch-notes, patch-failed, live-test, live-test-release, hostile-*)" % jn)
for jn, want in NEEDS.items():
    if jn in jobs and sorted(needs_of(jobs[jn])) != sorted(want):
        bad.append("job %s needs %s, it must need exactly %s" % (jn, sorted(needs_of(jobs[jn])), sorted(want)))
for jn, want in NEEDS_AT_LEAST.items():
    if jn in jobs and not set(want) <= set(needs_of(jobs[jn])):
        bad.append("job %s must need at least %s: %s" % (jn, want, needs_of(jobs[jn])))
if "check-govulncheck" in jobs and "check-govulncheck" in needs_of(jobs["check-govulncheck"]):
    bad.append("check-govulncheck needs itself")
for jn in CHAIN:
    j = jobs.get(jn)
    if not j:
        continue
    for k in ("continue-on-error", "secrets", "container", "services", "defaults"):
        if k in j:
            bad.append("chain job %s carries %s" % (jn, k))
    if "uses" in j:
        bad.append("chain job %s is a reusable-workflow call: the release is one file" % jn)
    ro = j.get("runs-on")
    if ro is None or (isinstance(ro, str) and not re.fullmatch(r"ubuntu-24\.04(-arm)?|\$\{\{\s*matrix\.[A-Za-z_-]+\s*\}\}", ro)):
        bad.append("chain job %s does not run on a GitHub-hosted ubuntu-24.04 runner: %s" % (jn, ro))
    if jn not in SIGN_JOBS and "env" in j:
        bad.append("chain job %s has a job-level env (only the sign jobs hold the three federation literals)" % jn)
    if "permissions" not in j:
        bad.append("chain job %s declares no permissions of its own" % jn)
# the gate G on build-freeze, the guard S on the five jobs, the Check jobs' condition, no if on the others of Build and Rebuild
if "build-freeze" in jobs and norm(jobs["build-freeze"].get("if", "")) != G:
    bad.append("build-freeze does not carry the gate G exactly: %s" % jobs["build-freeze"].get("if"))
for jn in SIGN_JOBS + ["release", "release-evidence"]:
    want = S_TAG if jn in ("sign-release", "release", "release-evidence") else S
    if jn in jobs and norm(jobs[jn].get("if", "")) != want:
        bad.append("guard S: %s does not carry the guard S exactly%s (it must run only on a v* tag push of release.yml itself, never in snapshot mode or under workflow_call): %s" % (jn, " followed by && !contains(github.ref_name, '-') (a release candidate never enters the environment)" if want == S_TAG else "", jobs[jn].get("if")))
for jn in ("sign-release", "release", "release-evidence"):
    for s in steps_of(jobs.get(jn) or {}):
        if "contains(github.ref_name,'-')" in norm(s.get("if", "")):
            bad.append("candidate rule: a step of %s carries the release-candidate condition (it belongs in the job's if)" % jn)
for jn in CHECK_JOBS:
    if jn in jobs and norm(jobs[jn].get("if", "")) != NOT_SNAPSHOT:
        bad.append("the Check job %s does not carry exactly inputs.mode != 'snapshot': %s" % (jn, jobs[jn].get("if")))
for jn in ["build-apk", "build-assemble"] + REBUILD_JOBS:
    if jn in jobs and "if" in jobs[jn]:
        bad.append("%s carries an if (Build and Rebuild run through needs; only build-freeze is gated)" % jn)
for jn in ["patch-notes"]:
    if jn in jobs and norm(jobs[jn].get("if", "")) != norm("${{ needs.decide.outputs.tagged == 'true' }}"):
        bad.append("patch-notes does not run only if needs.decide.outputs.tagged == 'true'")
if "patch-failed" in jobs and not set(needs_of(jobs["patch-failed"])) <= set(CHAIN):
    bad.append("patch-failed needs a job that is not a chain job: %s" % needs_of(jobs["patch-failed"]))
if "decide" in jobs and "patch-notes" in jobs and needs_of(jobs["patch-notes"]) != ["decide"]:
    bad.append("patch-notes must need exactly decide: %s" % needs_of(jobs["patch-notes"]))

# ---- every action pinned by full digest (REQ-CHAIN-001-AC1) ---------------------------------------------------------------------------------------
for jn, j in jobs.items():
    for s in steps_of(j):
        u = s.get("uses")
        if u and not re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", u):
            bad.append("job %s: the action %s is not pinned by a full digest" % (jn, u))

# ---- the sign jobs and the key (REQ-CHAIN-001-AC9) --------------------------------------------------------------------------------------------------
SIGNING = re.compile(r"bin/release-sign\.sh|bin/release-apks\.sh|bin/release-sign-apks\.sh|witness-sign-staged\.sh|with-aws-token\.sh|chain-verify\.py\s+(?:-\S+\s+)*sign(?:-records)?(?:\s|$)")
for jn in SIGN_JOBS:
    j = jobs.get(jn)
    if not j:
        continue
    if j.get("environment") != "sign":
        bad.append("sign job %s is not in the environment sign: %s" % (jn, j.get("environment")))
    p = j.get("permissions")
    want = {"contents": "read", "id-token": "write"}
    if jn == "sign-release":
        if not isinstance(p, dict) or any(p.get(k) != v for k, v in want.items()) or set(p) - set(want) - {"packages"} or p.get("packages", "write") != "write":
            bad.append("sign-release holds more than contents read, id-token write and the packages write its registry credential needs: %s" % p)
    elif p != want:
        bad.append("sign job %s does not hold exactly contents read and id-token write: %s" % (jn, p))
    env = j.get("env")
    if not isinstance(env, dict) or sorted(env) != sorted(KMS_ENV) or any(not str(env[k]).strip() or "${{" in str(env[k]) for k in KMS_ENV):
        bad.append("sign job %s does not carry exactly the three KMS federation literals %s as job env: %s" % (jn, KMS_ENV, env))
    for s in steps_of(j):
        if set(s.get("env") or {}) & set(KMS_ENV):
            bad.append("a step of %s carries a KMS federation literal (only the job does)" % jn)
    if "with" in j or j.get("secrets"):
        bad.append("sign job %s takes an input or a secret" % jn)
    if "needs.build-assemble.outputs.digests" not in text_of(j):
        bad.append("sign job %s does not read Build's digests through needs.build-assemble.outputs.digests" % jn)
    if not SIGNING.search(runs_of(j)):
        bad.append("sign job %s runs no signing command" % jn)
if "sign-release" in jobs:
    r = runs_of(jobs["sign-release"])
    if "bin/release-apks.sh" not in r or "bin/release-sign.sh" not in r:
        bad.append("sign-release does not run bin/release-apks.sh and bin/release-sign.sh")
    if re.search(r"bin/release-(publish|assets|postverify|verify|compare)\.sh", r):
        bad.append("sign-release runs more of Release than its two signing scripts")
    # it signs the release stage's two local records, as the other sign jobs sign theirs, before release-apks and release-sign (ruling Q-e)
    one = re.sub(r"\s+", " ", r.replace("\\\n", " "))
    m = re.search(r"chain-verify\.py sign-records --stage release\b[^\n]*", one)
    if not m:
        bad.append("sign-release does not run chain-verify.py sign-records --stage release on the release stage's local records")
    elif not all(x in m.group(0) for x in ("--record-dir rec-release/witness-release-verify", "--record-dir rec-release/witness-release-publish")) or "--expect-digests" in m.group(0) or "--artifacts-dir" in m.group(0):
        bad.append("sign-release: the sign-records --stage release step takes exactly the two record dirs of release-verify and release-publish and no --expect-digests or --artifacts-dir")
    if "witness-sign-staged.sh staged signed" not in one or one.find("witness-sign-staged.sh") > one.find("bin/witnessed.sh release-apks"):
        bad.append("sign-release does not sign the staged release records (witness-sign-staged.sh staged signed) before its release-apks step")
    if "actions/download-artifact" not in text_of(jobs["sign-release"]) or "witness-release" not in text_of(jobs["sign-release"]) or "signed-witness-release" not in text_of(jobs["sign-release"]):
        bad.append("sign-release does not download witness-release and upload signed-witness-release")
    if [(n, sc) for n, sc, _ in witness_lines(jobs["sign-release"])] != [("release-apks", "bin/release-apks.sh"), ("release-sign", "bin/release-sign.sh")] or re.search(r"bin/witnessed-local\.sh", r):
        bad.append("sign-release does not run release-apks and release-sign through bin/witnessed.sh and nothing else witnessed")
for jn in ("sign", "sign-rebuild", "sign-check"):
    if jn in jobs and "chain-verify.py sign-records" not in re.sub(r"\s+", " ", runs_of(jobs[jn]).replace("\\\n", " ")):
        bad.append("sign job %s does not run chain-verify.py sign-records" % jn)
for jn, j in jobs.items():
    if jn in SIGN_JOBS:
        continue
    t = text_of(j)
    if j.get("environment") == "sign":
        bad.append("job %s is in the environment sign, which only the four sign jobs carry" % jn)
    for k in KMS_ENV:
        if re.search(r"\b%s\b" % k, t):
            bad.append("job %s names %s: only the four sign jobs carry the KMS federation" % (jn, k))
    if SIGNING.search(runs_of(j)):
        bad.append("job %s runs a signing command (the signing subcommand, bin/release-sign.sh and bin/release-apks.sh belong to the sign jobs)" % jn)
rel = jobs.get("release") or {}
if re.search(r"bin/release-(assets|postverify)\.sh", runs_of(rel)):
    bad.append("the release job runs release-assets or release-postverify (they belong to release-evidence, after the signatures exist)")
ev = jobs.get("release-evidence")
if ev:
    if ev.get("permissions") != {"contents": "write"}:
        bad.append("release-evidence does not hold exactly contents write (no id-token): %s" % ev.get("permissions"))
    if "environment" in ev:
        bad.append("release-evidence carries an environment: %s" % ev.get("environment"))
    local_steps = re.findall(r"bash bin/witnessed-local\.sh (\S+) (\S+)", runs_of(ev))
    if local_steps != EVIDENCE_STEPS:
        bad.append("release-evidence does not run exactly the witnessed-local steps release-assets and release-postverify in that order: %s" % local_steps)
    if re.search(r"bin/witnessed\.sh", runs_of(ev)):
        bad.append("release-evidence uses bin/witnessed.sh, which needs the KMS role (it has none): it uses bin/witnessed-local.sh")
# the release job runs release-verify and release-publish under bin/witnessed-local.sh, holds no KMS role, only contents write and packages write (ruling Q-e)
if rel:
    if [(n, sc) for n, sc, _ in witness_lines(rel)] != [("release-verify", "bin/release-verify.sh"), ("release-publish", "bin/release-publish.sh")] or re.search(r"bin/witnessed\.sh", runs_of(rel)) or len(re.findall(r"bin/witnessed-local\.sh", runs_of(rel))) != 2:
        bad.append("the release job does not run exactly release-verify then release-publish through bin/witnessed-local.sh (never bin/witnessed.sh)")
    if rel.get("permissions") != {"contents": "write", "packages": "write"}:
        bad.append("the release job does not hold exactly contents write and packages write: %s" % rel.get("permissions"))
    pub = [s for n, sc, s in witness_lines(rel) if n == "release-publish"]
    if pub and sorted(pub[0].get("env") or {}) != ["DOCKERHUB_TOKEN", "DOCKERHUB_USERNAME", "GH_TOKEN"]:
        bad.append("the release-publish step of the release job does not carry exactly DOCKERHUB_USERNAME, DOCKERHUB_TOKEN and GH_TOKEN as env: %s" % sorted((pub[0].get("env") or {})))
if isinstance(rel.get("permissions"), dict) and "id-token" in rel["permissions"]:
    bad.append("the release job holds an identity token (id-token): it holds no key role")
if rel.get("permissions") == "write-all":
    bad.append("the release job holds write-all")
# no other file's job names the key role (persona-uat.yml, the live tests, every other workflow)
for f in sorted(glob.glob(os.path.join(WF, "*.y*ml"))):
    b = os.path.basename(f)
    if b == "release.yml" or b == os.path.basename(path):
        continue
    t = open(f).read()
    if re.search(r"\bRELEASE_KMS_KEY_REF\b|fosterstack-cache-release-signing|environment:\s*sign\s*$", t, re.M):
        bad.append("%s names the key role or the environment sign" % b)

# ---- the snapshot reach (REQ-CHAIN-004-AC14): every job that requests a write or an id-token carries the snapshot guard ----------------------------------
def requests_write(j):
    p = j.get("permissions")
    if p == "write-all":
        return True
    return isinstance(p, dict) and any(v == "write" or k == "id-token" for k, v in p.items())
for jn, j in jobs.items():
    if requests_write(j) and NOT_SNAPSHOT not in norm(j.get("if", "")):
        bad.append("job %s requests a write or an id-token and is reachable in snapshot mode or under workflow_call (its if lacks inputs.mode != 'snapshot')" % jn)

# ---- persona-uat.yml is called from one guarded job at most (REQ-UAT-001-AC6) -----------------------------------------------------------------------
for jn, j in jobs.items():
    if j.get("uses"):
        if j["uses"] != "./.github/workflows/persona-uat.yml":
            bad.append("job %s calls %s: release.yml calls no workflow file but persona-uat.yml" % (jn, j["uses"]))
        else:
            c = j.get("if", "")
            if "PERSONA_UAT_ENABLED" not in c or "-rc" not in c or NOT_SNAPSHOT not in norm(c):
                bad.append("the persona-uat.yml call %s lacks the gate PERSONA_UAT_ENABLED, the release-candidate tag condition or the snapshot guard: %s" % (jn, c))
            if "secrets" in j and j["secrets"] == "inherit":
                bad.append("the persona-uat.yml call %s passes secrets: inherit" % jn)

# ---- Build (REQ-CHAIN-004-AC1, AC12, AC19) ----------------------------------------------------------------------------------------------------------
def step_names_ok(jn, j, mode_input=True):
    ss = steps_of(j)
    if len(ss) < 2 or "actions/checkout@" not in str(ss[0].get("uses")) or (ss[0].get("with") or {}).get("persist-credentials") != "false":
        bad.append("%s: the first step is not the checkout with persist-credentials: false" % jn)
    g = ss[1] if len(ss) > 1 else {}
    if "inputs.mode" not in text_of(g.get("env") or {}) or not g.get("run"):
        bad.append("%s: the step right after the checkout is not the mode guard (env MODE from inputs.mode, a run that refuses any other value)" % jn)
READ = {"contents": "read"}
if "build-freeze" in jobs:
    j = jobs["build-freeze"]
    if j.get("runs-on") != "ubuntu-24.04" or j.get("permissions") != READ:
        bad.append("build-freeze is not on ubuntu-24.04 with exactly contents read: %s %s" % (j.get("runs-on"), j.get("permissions")))
    step_names_ok("build-freeze", j)
    if len(steps_of(j)) != 5 or witness_lines(j) or "bin/build-freeze.sh" not in runs_of(j) or "install-scanner.sh go" not in runs_of(j):
        bad.append("build-freeze steps are not exactly checkout, the mode guard, the Go install, the freeze script and the upload (no Witness step)")
if "build-apk" in jobs:
    j = jobs["build-apk"]
    if matrix_runners(j) != RUNNERS:
        bad.append("build-apk is not a matrix over the two native runners %s: %s" % (RUNNERS, matrix_runners(j)))
    if j.get("permissions") != {"contents": "read", "checks": "read", "statuses": "read", "pull-requests": "read"}:
        bad.append("build-apk does not hold exactly contents, checks, statuses and pull-requests read: %s" % j.get("permissions"))
if "build-assemble" in jobs:
    j = jobs["build-assemble"]
    if j.get("runs-on") != "ubuntu-24.04" or j.get("permissions") != READ or "strategy" in j:
        bad.append("build-assemble is not one job on ubuntu-24.04 with exactly contents read: %s %s" % (j.get("runs-on"), j.get("permissions")))
SNAP = {"build-apk": ("snapshot-apk", "bin/build-stage-snapshot-apk.sh", "apk", "bin/build-stage-apk.sh"),
        "build-assemble": ("snapshot-build", "bin/build-stage-snapshot-assemble.sh", "build", "bin/build-stage-assemble.sh"),
        "rebuild-apk": ("snapshot-rapk", "bin/build-stage-snapshot-rebuild-apk.sh", "rapk", "bin/build-stage-rebuild-apk.sh"),
        "rebuild-assemble": ("snapshot-rebuild", "bin/build-stage-snapshot-rebuild-assemble.sh", "rebuild", "bin/build-stage-rebuild-assemble.sh")}
for jn, (sstep, sscript, rstep, rscript) in SNAP.items():
    j = jobs.get(jn)
    if not j:
        continue
    step_names_ok(jn, j)
    if jn.startswith("rebuild-") and j.get("permissions") != READ:
        bad.append("%s does not hold exactly contents read: %s" % (jn, j.get("permissions")))
    for k in ("container", "services", "env", "defaults", "secrets", "continue-on-error"):
        if k in j:
            bad.append("%s carries %s" % (jn, k))
    p = j.get("permissions") or {}
    if "id-token" in p or p.get("packages") == "write":
        bad.append("%s holds an id-token or packages write" % jn)
    wl = witness_lines(j)
    by = {n: (sc, st) for n, sc, st in wl}
    if len(wl) != 2 or set(by) != {sstep, rstep}:
        bad.append("%s does not have exactly the two Witness steps %s and %s: %s" % (jn, rstep, sstep, [n for n, _, _ in wl])); continue
    if by[sstep][0] != sscript or by[rstep][0] != rscript:
        bad.append("%s: a Witness step runs another script than %s / %s" % (jn, rscript, sscript))
    sif, rif = norm(by[sstep][1].get("if", "")), norm(by[rstep][1].get("if", ""))
    if "inputs.mode" not in sif or "snapshot" not in sif or sif == rif:
        bad.append("%s: the snapshot Witness step %s is not gated by the mode" % (jn, sstep))
    if "inputs.mode" not in rif or not (rif == norm("inputs.mode != 'snapshot'") or rif == norm("inputs.mode == 'release'")):
        bad.append("%s: the release Witness step %s is not gated by the mode" % (jn, rstep))
    if "GH_TOKEN" in text_of(by[sstep][1]) or re.search(r"\bsecrets\.", text_of(by[sstep][1])):
        bad.append("%s: the snapshot Witness step %s carries a token or a secret (no GH_TOKEN, no gh call, no admission in snapshot mode)" % (jn, sstep))
    if jn in ("build-apk", "rebuild-apk") and matrix_runners(j) != RUNNERS:
        bad.append("%s is not ONE job with a matrix over both chips %s: %s" % (jn, RUNNERS, matrix_runners(j)))
    if jn in ("build-assemble", "rebuild-assemble") and j.get("runs-on") != "ubuntu-24.04":
        bad.append("%s does not run on ubuntu-24.04" % jn)
# the hostile Build step runs in every build (REQ-CHAIN-004-AC19)
hostile = [(jn, s) for jn in BUILD_JOBS if jn in jobs for s in steps_of(jobs[jn]) if "chain-hostile-step.sh" in (s.get("run") or "")]
if len(hostile) != 1:
    bad.append("the hostile Build step (bin/chain-hostile-step.sh) is not run by exactly one step of the Build jobs: %d" % len(hostile))
for jn, s in hostile:
    if "if" in s:
        bad.append("the hostile Build step in %s carries a condition (it runs in every build): %s" % (jn, s.get("if")))
    if s.get("env") or re.search(r"\bsecrets\.|GH_TOKEN|GITHUB_TOKEN", text_of(s)):
        bad.append("the hostile Build step in %s holds a token or an env" % jn)
for jn in BUILD_JOBS:
    j = jobs.get(jn)
    if not j:
        continue
    t = text_of(j)
    if re.search(r"inputs\.hostile|\bhostile\s*:|contains\(github\.ref_name,\s*'-rc'\)", t) and jn != "build-freeze":
        bad.append("%s still makes the hostile step depend on a release-candidate tag or a hostile input" % jn)
    for s in steps_of(j):
        if "hostile" in (s.get("name") or "") and "if" in s:
            bad.append("the step %r of %s carries a condition: the hostile step and its upload run in every build" % (s.get("name"), jn))
if "build-assemble" in jobs and (jobs["build-assemble"].get("outputs") or {}).get("hostile"):
    bad.append("build-assemble exposes a hostile output")
if "hostile" in ((wc or {}).get("inputs") or {}):
    bad.append("workflow_call still takes a hostile input")

# ---- Rebuild (REQ-CHAIN-005-AC1): rebuild-apk is ONE job over both chips -----------------------------------------------------------------------------
for jn in REBUILD_JOBS:   # both start from Build's UNSIGNED record, in release and snapshot mode alike
    if jn in jobs:
        rec = [s for s in steps_of(jobs[jn]) if "actions/download-artifact@" in str(s.get("uses")) and "witness-build" in str((s.get("with") or {}).get("name"))]   # an expression that picks between the two names counts as a name
        if len(rec) != 1 or (rec[0].get("with") or {}).get("name") != "witness-build" or str((rec[0].get("with") or {}).get("path", "")).rstrip("/") != "witness-build" or "if" in rec[0]:
            bad.append("%s does not download the unsigned record artifact witness-build exactly once into witness-build/ with no condition (never signed-witness-build, no mode conditional): %s" % (jn, [(s.get("with"), s.get("if")) for s in rec]))
        if "signed-witness-build" in text_of(jobs[jn]):
            bad.append("%s names signed-witness-build (Rebuild needs Build only, so it cannot need Sign)" % jn)
if "rebuild-assemble" in jobs and "stage-start" not in runs_of(jobs["rebuild-assemble"]) + runs_of(jobs.get("rebuild-apk") or {}) + "\n".join(
        open(os.path.join(root, "bin", b)).read() for b in ("build-stage-rebuild-apk.sh", "build-stage-rebuild-assemble.sh") if os.path.exists(os.path.join(root, "bin", b))):
    bad.append("Rebuild does not start from chain-verify.py stage-start against Build's record (in the jobs or their two scripts)")

# ---- Check (REQ-CHAIN-006-AC1) ------------------------------------------------------------------------------------------------------------------------
if "check-govulncheck" in jobs:
    j = jobs["check-govulncheck"]
    if j.get("runs-on") != "ubuntu-24.04" or j.get("permissions") != READ or "strategy" in j:
        bad.append("check-govulncheck is not one job on ubuntu-24.04 with exactly contents read")
    ss = steps_of(j)
    if len(ss) != 5 or "actions/checkout@" not in str(ss[0].get("uses")) or (ss[0].get("with") or {}).get("persist-credentials") != "false" \
            or "install-scanner.sh go" not in (ss[1].get("run") or "") or "install-scanner.sh govulncheck" not in (ss[2].get("run") or "") \
            or "bin/pack-govulncheck.sh" not in (ss[3].get("run") or "") or "actions/upload-artifact@" not in str(ss[4].get("uses")):
        bad.append("check-govulncheck steps are not the checkout, the pinned Go install, the govulncheck build, the pack step and one upload")
if "check" in jobs:
    j = jobs["check"]
    if matrix_runners(j) != RUNNERS:
        bad.append("check is not ONE job with a matrix over the two native runners %s: %s" % (RUNNERS, matrix_runners(j)))
    if j.get("permissions") != READ:
        bad.append("check does not hold exactly contents read (no identity token): %s" % j.get("permissions"))
    for k in ("container", "services", "env", "defaults", "secrets", "environment"):
        if k in j:
            bad.append("check carries %s" % k)
    if (j.get("outputs") or {}) or "outputs" in j:
        bad.append("check has job outputs (a matrix job keeps one output per key, so two chips cannot both set records): its records travel as one artifact per architecture: %s" % (j.get("outputs") or {}))
    r = [s.get("run", "").strip() for s in steps_of(j) if "witnessed-local.sh" in (s.get("run") or "")]
    if r != ["bash bin/witnessed-local.sh %s bin/check-phase.sh %s" % (x, x) for x in ("scanners", "acceptance", "runtime")]:
        bad.append("check does not run exactly the three single-line steps `bash bin/witnessed-local.sh STEP bin/check-phase.sh STEP` (scanners, acceptance, runtime in that order): %s" % r)
    inst = re.findall(r"bash bin/install-scanner\.sh (\S+)", runs_of(j))
    if inst != ["witness", "grype", "osv-scanner", "go"]:
        bad.append("check does not install, in this order, witness, grype, osv-scanner and go with bin/install-scanner.sh: %s" % inst)
    if "check-phase-arm64" in text_of(j) or re.search(r"check-phase-(scanners|acceptance|runtime)\.sh", text_of(j)):
        bad.append("check names an arm64 script or a per-phase script (bin/check-phase.sh is the one script on both chips)")
    ups = [(s.get("with") or {}).get("name", "") for s in steps_of(j) if "actions/upload-artifact@" in str(s.get("uses"))]
    if not any(u.startswith("witness-check-") for u in ups) or not any(u.startswith("check-results-") for u in ups):
        bad.append("check does not upload witness-check-<runner> and check-results-<runner>: %s" % ups)
    if not any(u.startswith("check-records-") for u in ups):
        bad.append("check does not upload one record artifact per architecture (check-records-<runner>): %s" % ups)
    dl = [(s.get("with") or {}) for s in steps_of(j) if "actions/download-artifact@" in str(s.get("uses"))]
    if sum(1 for w in dl if w.get("name") == "images") != 1:
        bad.append("check does not download the images artifact exactly once")
if "rebuild-apk" in jobs:
    j = jobs["rebuild-apk"]
    if "outputs" in j:
        bad.append("rebuild-apk has job outputs (a matrix job keeps one output per key): its records travel as one artifact per architecture: %s" % (j.get("outputs"),))
    ups = [(s.get("with") or {}).get("name", "") for s in steps_of(j) if "actions/upload-artifact@" in str(s.get("uses"))]
    if not any(u.startswith("rebuild-records-") for u in ups):
        bad.append("rebuild-apk does not upload one record artifact per architecture (rebuild-records-<runner>): %s" % ups)
for jn in SIGN_JOBS:
    if jn in jobs and re.search(r"needs\.(check|rebuild-apk)\.outputs", text_of(jobs[jn])):
        bad.append("sign job %s reads record digests from needs.%s.outputs: it reads the downloaded record artifacts" % (jn, "check or rebuild-apk"))
if not os.path.exists(os.path.join(root, "bin/check-phase.sh")):
    bad.append("bin/check-phase.sh (the one Check script on both chips) does not exist")
if os.path.exists(os.path.join(root, "bin/check-phase-arm64.sh")):
    bad.append("bin/check-phase-arm64.sh still exists (no arm64 script remains)")

# ---- who may call release.yml (REQ-CHAIN-003-AC5, REQ-CHAIN-004-AC14), over the real directory ---------------------------------------------------------------
if os.path.basename(path) == "release.yml" or os.environ.get("RELEASE_WF_CALLERS") == "1":
    for f in sorted(glob.glob(os.path.join(WF, "*.y*ml"))):
        b = os.path.basename(f)
        w = load(f) or {}
        for jn, j in ((w.get("jobs") or {}) if isinstance(w.get("jobs"), dict) else {}).items():
            refs = [str(j.get("uses", ""))] + [str(s.get("uses", "")) for s in steps_of(j)]
            for r in refs:
                if re.search(r"\.github/workflows/release\.ya?ml", r) and b not in ("scan.yml", "main-candidate-rescan.yml"):
                    bad.append("%s job %s calls release.yml: only scan.yml and main-candidate-rescan.yml may, in snapshot mode" % (b, jn))
                if re.search(r"\.github/workflows/stage-", r):
                    bad.append("%s job %s calls a stage-*.yml file" % (b, jn))
                m = re.fullmatch(r"\./\.github/workflows/([^@\s]+)", r)
                if m and not os.path.exists(os.path.join(WF, m.group(1))):
                    bad.append("%s job %s calls %s, which does not exist" % (b, jn, m.group(1)))
print("; ".join(bad) or "ok")
sys.exit(1 if bad else 0)
PY
# case NAME want WORD EDIT   (want ok|bad; WORD: text the refusal must contain; EDIT: python on the parsed workflow d, empty = the real file)
case_() {
  local f="$work/$1.yml"
  cp "$root/.github/workflows/release.yml" "$f"
  if [ -n "$4" ]; then python3 - "$f" "$4" <<'PY' || { failn=$((failn+1)); echo "FAIL $1 (the mutation did not apply)"; return 0; }
import sys, yaml
p, edit = sys.argv[1], sys.argv[2]
d = yaml.load(open(p), Loader=yaml.BaseLoader)
def hit(xs):   # a comprehension that matched nothing is a mutation that did not apply, never a silent pass
    xs = list(xs); assert xs, "the mutation matched nothing"; return xs
exec(edit)
yaml.safe_dump(d, open(p, "w"), sort_keys=False, width=100000)
PY
  fi
  local out rc=0
  local callers=0; [ "$1" = real ] && callers=1       # the cross-file check reads every workflow: once, on the real file (the mutations change release.yml only)
  out=$(RELEASE_WF_CALLERS=$callers python3 "$work/judge.py" "$f" "$root" 2>&1) || rc=$?
  if [ "$2" = ok ]; then
    if [ "$rc" = 0 ]; then pass=$((pass+1)); echo "PASS $1 -> ok"; else failn=$((failn+1)); echo "FAIL $1 -> $out"; fi
  elif [ "$rc" = 1 ] && grep -Fq -- "$3" <<< "$out"; then pass=$((pass+1)); echo "PASS $1 -> refused ($3)"
  else failn=$((failn+1)); echo "FAIL $1 -> rc=$rc, wanted a refusal containing '$3': ${out:0:400}"; fi
}
J='d["jobs"]'
case_ real ok "" ""

# the triggers and the workflow level
case_ no-workflow-call        bad "no workflow_call trigger" "d['on'].pop('workflow_call')"
case_ mode-input-gone         bad "exactly one input, mode" "d['on']['workflow_call']['inputs'].pop('mode')"
case_ second-input            bad "exactly one input, mode" "d['on']['workflow_call']['inputs']['hostile'] = {'type': 'boolean'}"
case_ mode-not-string         bad "exactly one input, mode" "d['on']['workflow_call']['inputs']['mode']['type'] = 'boolean'"
case_ mode-default-snapshot   bad "exactly one input, mode" "d['on']['workflow_call']['inputs']['mode']['default'] = 'snapshot'"
case_ workflow-call-secrets   bad "declares secrets" "d['on']['workflow_call']['secrets'] = {'K': {'required': 'true'}}"
case_ dry-run-a-string        bad "dry-run dispatch input" "d['on']['workflow_dispatch']['inputs']['dry-run']['type'] = 'string'"
case_ workflow-permissions-read bad "workflow-level permissions are not empty" "d['permissions'] = {'contents': 'read'}"
case_ workflow-permissions-gone bad "workflow-level permissions are not empty" "d.pop('permissions')"
case_ workflow-env            bad "workflow-level env" "d['env'] = {'X': 'y'}"
case_ workflow-defaults       bad "workflow-level defaults" "d['defaults'] = {'run': {'shell': 'bash'}}"

# the job set and the graph (REQ-CHAIN-005-AC5)
for jn in build-freeze build-apk build-assemble sign rebuild-apk rebuild-assemble sign-rebuild check-govulncheck check sign-check release-compare release-verify release sign-release release-evidence; do
  case_ "job-$jn-gone"        bad "no chain job $jn" "$J.pop('$jn')"
done
for old in rapk rapk-arm check-arm64 govulncheck-build apk assemble freeze rebuild build compare verify; do
  case_ "stage-era-job-$old"  bad "stage-era job $old" "$J['$old'] = {'runs-on': 'ubuntu-24.04', 'steps': []}"
done
case_ unlisted-job            bad "not a chain job nor on the allowed list" "$J['extra'] = {'runs-on': 'ubuntu-24.04', 'permissions': {'contents': 'read'}, 'steps': []}"
case_ persona-uat-job-here    bad "not a chain job nor on the allowed list" "$J['persona-uat'] = {'runs-on': 'ubuntu-24.04', 'permissions': {'contents': 'read'}, 'steps': []}"
case_ hostile-job-allowed     ok  "" "$J['hostile-verify'] = {'runs-on': 'ubuntu-24.04', 'permissions': {'contents': 'read'}, 'needs': 'build-assemble', 'steps': []}"
for pair in "build-apk:build-freeze" "build-assemble:build-apk" "sign:build-assemble" "rebuild-assemble:rebuild-apk"; do
  jn=${pair%%:*}
  case_ "needs-$jn-widened"   bad "job $jn needs" "$J['$jn']['needs'] = ['${pair##*:}', 'check']"
  case_ "needs-$jn-dropped"   bad "job $jn needs" "$J['$jn'].pop('needs')"
done
case_ sign-rebuild-no-rebuild bad "job sign-rebuild needs" "$J['sign-rebuild']['needs'] = ['build-assemble']"
case_ sign-check-no-check     bad "job sign-check needs" "$J['sign-check']['needs'] = ['build-assemble']"
case_ release-compare-no-sign-check bad "job release-compare needs" "$J['release-compare']['needs'] = ['check', 'sign', 'sign-rebuild']"
case_ release-verify-no-compare bad "job release-verify needs" "$J['release-verify'].pop('needs')"
case_ release-no-verify       bad "job release needs" "$J['release']['needs'] = ['release-compare']"
case_ sign-release-before-release bad "job sign-release needs" "$J['sign-release']['needs'] = ['release-verify']"
case_ sign-release-no-build-assemble bad "job sign-release needs" "$J['sign-release']['needs'] = ['release']"
case_ sign-release-no-release bad "job sign-release needs" "$J['sign-release']['needs'] = ['build-assemble']"
case_ release-evidence-needs-release bad "job release-evidence needs" "$J['release-evidence']['needs'] = ['release']"
case_ release-evidence-needs-both bad "job release-evidence needs" "$J['release-evidence']['needs'] = ['release', 'sign-release']"
case_ release-evidence-no-needs bad "job release-evidence needs" "$J['release-evidence'].pop('needs')"
case_ check-not-after-govulncheck bad "job check must need at least" "$J['check']['needs'] = ['build-assemble', 'sign']"
case_ check-not-after-sign    bad "job check must need at least" "$J['check']['needs'] = ['check-govulncheck', 'build-assemble']"
case_ rebuild-apk-not-after-build bad "job rebuild-apk needs" "$J['rebuild-apk'].pop('needs')"
case_ rebuild-apk-needs-sign  bad "job rebuild-apk needs" "$J['rebuild-apk']['needs'] = ['build-assemble', 'sign']"
for jn in sign rebuild-apk check release; do
  case_ "$jn-continue-on-error" bad "chain job $jn carries continue-on-error" "$J['$jn']['continue-on-error'] = 'true'"
  case_ "$jn-secrets"         bad "chain job $jn carries secrets" "$J['$jn']['secrets'] = 'inherit'"
  case_ "$jn-container"       bad "chain job $jn carries container" "$J['$jn']['container'] = 'alpine'"
done
case_ sign-self-hosted        bad "does not run on a GitHub-hosted" "$J['sign']['runs-on'] = 'self-hosted'"
case_ release-no-permissions  bad "release declares no permissions of its own" "$J['release'].pop('permissions')"
case_ unpinned-action         bad "not pinned by a full digest" "$J['release-compare']['steps'][0]['uses'] = 'actions/checkout@v4'"
# the gate G and the guard S, one case each (REQ-CHAIN-003-AC5, REQ-CHAIN-005-AC5)
case_ gate-gone               bad "gate G" "$J['build-freeze'].pop('if')"
case_ gate-without-dry-run    bad "gate G" "$J['build-freeze']['if'] = \"\${{ (github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')) || inputs.mode == 'snapshot' }}\""
case_ gate-without-snapshot   bad "gate G" "$J['build-freeze']['if'] = \"\${{ (github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')) || inputs.dry-run == true }}\""
case_ gate-dispatch-on-tag    bad "gate G" "$J['build-freeze']['if'] = \"\${{ startsWith(github.ref, 'refs/tags/v') || inputs.dry-run == true || inputs.mode == 'snapshot' }}\""
for jn in sign sign-rebuild sign-check sign-release release release-evidence; do
  case_ "guard-$jn-gone"           bad "guard S: $jn" "$J['$jn'].pop('if')"
  case_ "guard-$jn-no-snapshot"    bad "guard S: $jn" "$J['$jn']['if'] = \"\${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && startsWith(github.workflow_ref, format('{0}/.github/workflows/release.yml@', github.repository)) }}\""
  case_ "guard-$jn-no-push"        bad "guard S: $jn" "$J['$jn']['if'] = \"\${{ inputs.mode != 'snapshot' && startsWith(github.ref, 'refs/tags/v') && startsWith(github.workflow_ref, format('{0}/.github/workflows/release.yml@', github.repository)) }}\""
  case_ "guard-$jn-no-tag"         bad "guard S: $jn" "$J['$jn']['if'] = \"\${{ inputs.mode != 'snapshot' && github.event_name == 'push' && startsWith(github.workflow_ref, format('{0}/.github/workflows/release.yml@', github.repository)) }}\""
  case_ "guard-$jn-no-workflow-ref" bad "guard S: $jn" "$J['$jn']['if'] = \"\${{ inputs.mode != 'snapshot' && github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') }}\""
  case_ "guard-$jn-always"         bad "guard S: $jn" "$J['$jn']['if'] = 'always()'"
done
# the release-candidate rule is in the job's if of sign-release and release (guard S followed by && !contains(github.ref_name, '-')), nowhere else
for jn in sign sign-rebuild sign-check; do
  case_ "guard-$jn-with-candidate-rule" bad "guard S: $jn" "$J['$jn']['if'] = $J['$jn']['if'] + \" && !contains(github.ref_name, '-')\""
done
for jn in sign-release release release-evidence; do
  case_ "guard-$jn-without-candidate-rule" bad "guard S: $jn" "$J['$jn']['if'] = $J['sign']['if']"
  case_ "guard-$jn-candidate-rule-other" bad "guard S: $jn" "$J['$jn']['if'] = $J['sign']['if'] + \" && !contains(github.ref_name, '-rc')\""
  case_ "guard-$jn-candidate-rule-first" bad "guard S: $jn" "$J['$jn']['if'] = \"\${{ !contains(github.ref_name, '-') && \" + $J['sign']['if'].replace('\${{ ', '', 1)"
  case_ "guard-$jn-candidate-rule-on-step" bad "candidate rule: a step of $jn" "$J['$jn']['steps'][-1]['if'] = \"\${{ !contains(github.ref_name, '-') }}\""
done
case_ check-no-snapshot-guard bad "Check job check does not carry" "$J['check'].pop('if')"
case_ govulncheck-no-guard    bad "Check job check-govulncheck does not carry" "$J['check-govulncheck'].pop('if')"
case_ check-guard-is-S        bad "Check job check does not carry" "$J['check']['if'] = $J['sign']['if']"
for jn in build-apk build-assemble rebuild-apk rebuild-assemble; do
  case_ "$jn-has-if"          bad "$jn carries an if" "$J['$jn']['if'] = \"\${{ github.event_name == 'push' }}\""
done
case_ patch-notes-ungated     bad "patch-notes does not run only if" "$J['decide'] = {'runs-on': 'ubuntu-24.04', 'permissions': {'contents': 'read'}, 'steps': []}; $J['patch-notes'] = {'needs': 'decide', 'if': 'always()', 'runs-on': 'ubuntu-24.04', 'permissions': {'contents': 'read'}, 'steps': []}"

# the four sign jobs and the key (REQ-CHAIN-001-AC9)
for jn in sign sign-rebuild sign-check sign-release; do
  case_ "$jn-no-environment"  bad "$jn is not in the environment sign" "$J['$jn'].pop('environment')"
  case_ "$jn-environment-release" bad "$jn is not in the environment sign" "$J['$jn']['environment'] = 'release'"
  w=$([ "$jn" = sign-release ] && echo "sign-release holds more" || echo "$jn does not hold")
  case_ "$jn-no-id-token"     bad "$w" "$J['$jn']['permissions'].pop('id-token')"
  case_ "$jn-contents-write"  bad "$w" "$J['$jn']['permissions']['contents'] = 'write'"
  case_ "$jn-no-federation"   bad "$jn does not carry exactly the three KMS federation literals" "$J['$jn'].pop('env')"
  case_ "$jn-env-extra"       bad "$jn does not carry exactly the three KMS federation literals" "$J['$jn']['env']['X'] = 'y'"
  case_ "$jn-env-role-gone"   bad "$jn does not carry exactly the three KMS federation literals" "$J['$jn']['env'].pop('AWS_ROLE_ARN')"
  case_ "$jn-env-from-input"  bad "$jn does not carry exactly the three KMS federation literals" "$J['$jn']['env']['AWS_ROLE_ARN'] = \"\${{ inputs.role }}\""
  case_ "$jn-step-carries-role" bad "a step of $jn carries a KMS federation literal" "$J['$jn']['steps'][-1].setdefault('env', {})['AWS_REGION'] = 'us-east-1'"
  case_ "$jn-takes-input"     bad "$jn takes an input or a secret" "$J['$jn']['with'] = {'x': 'y'}"
done
for jn in sign sign-rebuild sign-check; do
  case_ "$jn-digests-not-from-build" bad "$jn does not read Build's digests" "$J['$jn']['steps'] = [dict(s, **{'env': {k: v.replace('needs.build-assemble.outputs.digests', 'needs.sign.outputs.digests') for k, v in (s.get('env') or {}).items()}}) if s.get('env') else s for s in $J['$jn']['steps']]"
done
case_ sign-release-no-release-sign bad "sign-release does not run bin/release-apks.sh and bin/release-sign.sh" "$J['sign-release']['steps'] = [s for s in $J['sign-release']['steps'] if 'release-sign.sh' not in (s.get('run') or '')]"
case_ sign-release-no-sign-records bad "sign-release does not run chain-verify.py sign-records --stage release" "$J['sign-release']['steps'] = [s for s in $J['sign-release']['steps'] if 'sign-records' not in (s.get('run') or '')]"
case_ sign-release-stage-check bad "sign-release does not run chain-verify.py sign-records --stage release" "hit(s.__setitem__('run', s['run'].replace('--stage release', '--stage check')) for s in $J['sign-release']['steps'] if 'sign-records' in (s.get('run') or ''))"
case_ sign-release-one-record-dir bad "takes exactly the two record dirs" "hit(s.__setitem__('run', s['run'].replace('--record-dir rec-release/witness-release-publish', '')) for s in $J['sign-release']['steps'] if 'sign-records' in (s.get('run') or ''))"
case_ sign-release-expect-digests bad "takes exactly the two record dirs" "hit(s.__setitem__('run', s['run'] + ' --expect-digests digests.json') for s in $J['sign-release']['steps'] if 'sign-records' in (s.get('run') or ''))"
case_ sign-release-artifacts-dir bad "takes exactly the two record dirs" "hit(s.__setitem__('run', s['run'] + ' --artifacts-dir artifacts') for s in $J['sign-release']['steps'] if 'sign-records' in (s.get('run') or ''))"
case_ sign-release-no-staged-sign bad "does not sign the staged release records" "$J['sign-release']['steps'] = [s for s in $J['sign-release']['steps'] if 'witness-sign-staged' not in (s.get('run') or '')]"
case_ sign-release-no-digests bad "sign job sign-release does not read Build's digests" "hit(s.__setitem__('env', {k: v.replace('needs.build-assemble.outputs.digests', 'needs.release.outputs.digests') for k, v in (s.get('env') or {}).items()}) for s in $J['sign-release']['steps'] if s.get('env') and 'needs.build-assemble.outputs.digests' in str(s['env']))"
case_ sign-release-local-witness bad "does not run release-apks and release-sign through bin/witnessed.sh" "hit(s.__setitem__('run', s['run'].replace('witnessed.sh', 'witnessed-local.sh')) for s in $J['sign-release']['steps'] if 'witnessed.sh release-apks' in (s.get('run') or ''))"
case_ release-job-witnessed-kms bad "does not run exactly release-verify then release-publish through bin/witnessed-local.sh" "hit(s.__setitem__('run', s['run'].replace('witnessed-local.sh', 'witnessed.sh')) for s in $J['release']['steps'] if 'witnessed-local.sh release-publish' in (s.get('run') or ''))"
case_ release-job-verify-kms bad "does not run exactly release-verify then release-publish through bin/witnessed-local.sh" "hit(s.__setitem__('run', s['run'].replace('witnessed-local.sh', 'witnessed.sh')) for s in $J['release']['steps'] if 'witnessed-local.sh release-verify' in (s.get('run') or ''))"
case_ release-job-no-publish bad "does not run exactly release-verify then release-publish through bin/witnessed-local.sh" "$J['release']['steps'] = [s for s in $J['release']['steps'] if 'release-publish' not in (s.get('run') or '')]"
case_ release-job-packages-gone bad "the release job does not hold exactly contents write and packages write" "$J['release']['permissions'].pop('packages')"
case_ release-job-extra-permission bad "the release job does not hold exactly contents write and packages write" "$J['release']['permissions']['actions'] = 'read'"
case_ release-publish-env-extra bad "does not carry exactly DOCKERHUB_USERNAME, DOCKERHUB_TOKEN and GH_TOKEN" "hit(s['env'].__setitem__('X', 'y') for s in $J['release']['steps'] if 'witnessed-local.sh release-publish' in (s.get('run') or ''))"
case_ sign-release-publishes  bad "sign-release runs more of Release" "$J['sign-release']['steps'].append({'run': 'bash bin/release-publish.sh'})"
case_ sign-runs-no-sign-records bad "does not run chain-verify.py sign-records" "$J['sign']['steps'] = [s for s in $J['sign']['steps'] if 'sign-records' not in (s.get('run') or '')]"
# no other job holds the key, the environment or a signing command
for jn in build-assemble rebuild-assemble check release release-verify release-compare; do
  case_ "$jn-environment-sign"  bad "job $jn is in the environment sign" "$J['$jn']['environment'] = 'sign'"
  case_ "$jn-names-the-role"    bad "job $jn names AWS_ROLE_ARN" "$J['$jn'].setdefault('env', {}); $J['$jn']['env']['AWS_ROLE_ARN'] = 'arn:aws:iam::1:role/x'"
  case_ "$jn-runs-release-sign" bad "job $jn runs a signing command" "$J['$jn']['steps'].append({'run': 'bash bin/release-sign.sh'})"
done
case_ release-runs-release-apks bad "job release runs a signing command" "$J['release']['steps'].append({'run': 'bash bin/release-apks.sh'})"
case_ release-runs-sign-subcommand bad "job release runs a signing command" "$J['release']['steps'].append({'run': 'python3 -I -B bin/chain-verify.py sign --check'})"
case_ release-holds-id-token  bad "the release job holds an identity token" "$J['release']['permissions']['id-token'] = 'write'"
case_ release-holds-id-token-read bad "the release job holds an identity token" "$J['release']['permissions']['id-token'] = 'read'"
# release-evidence (Q-c): assets and post-verify run after the signatures exist, with contents write and no key
case_ release-evidence-id-token bad "release-evidence does not hold exactly contents write" "$J['release-evidence']['permissions']['id-token'] = 'write'"
case_ release-evidence-contents-read bad "release-evidence does not hold exactly contents write" "$J['release-evidence']['permissions']['contents'] = 'read'"
case_ release-evidence-packages bad "release-evidence does not hold exactly contents write" "$J['release-evidence']['permissions']['packages'] = 'write'"
case_ release-evidence-environment-sign bad "job release-evidence is in the environment sign" "$J['release-evidence']['environment'] = 'sign'"
case_ release-evidence-environment-release bad "release-evidence carries an environment" "$J['release-evidence']['environment'] = 'release'"
case_ release-evidence-names-role bad "job release-evidence names AWS_ROLE_ARN" "$J['release-evidence'].setdefault('env', {}); $J['release-evidence']['env']['AWS_ROLE_ARN'] = 'arn:aws:iam::1:role/x'"
case_ release-evidence-names-key bad "job release-evidence names RELEASE_KMS_KEY_REF" "$J['release-evidence']['steps'][-1].setdefault('env', {})['RELEASE_KMS_KEY_REF'] = 'x'"
case_ release-evidence-runs-release-sign bad "job release-evidence runs a signing command" "$J['release-evidence']['steps'].append({'run': 'bash bin/release-sign.sh'})"
case_ release-evidence-assets-gone bad "release-evidence does not run exactly the witnessed-local steps" "$J['release-evidence']['steps'] = [s for s in $J['release-evidence']['steps'] if 'witnessed-local.sh release-assets' not in (s.get('run') or '')]"
case_ release-evidence-postverify-gone bad "release-evidence does not run exactly the witnessed-local steps" "$J['release-evidence']['steps'] = [s for s in $J['release-evidence']['steps'] if 'witnessed-local.sh release-postverify' not in (s.get('run') or '')]"
case_ release-evidence-kms-witness bad "release-evidence uses bin/witnessed.sh" "hit(s.__setitem__('run', s['run'].replace('witnessed-local.sh', 'witnessed.sh')) for s in $J['release-evidence']['steps'] if 'witnessed-local.sh release-assets' in (s.get('run') or ''))"
case_ release-assets-back-in-release bad "the release job runs release-assets or release-postverify" "$J['release']['steps'].append({'run': 'bash bin/witnessed.sh release-assets bin/release-assets.sh'})"
case_ release-postverify-back-in-release bad "the release job runs release-assets or release-postverify" "$J['release']['steps'].append({'run': 'bash bin/witnessed.sh release-postverify bin/release-postverify.sh'})"
case_ release-postverify-in-sign-release bad "sign-release runs more of Release" "$J['sign-release']['steps'].append({'run': 'bash bin/witnessed.sh release-postverify bin/release-postverify.sh'})"
case_ release-assets-in-sign-release bad "sign-release runs more of Release" "$J['sign-release']['steps'].append({'run': 'bash bin/witnessed.sh release-assets bin/release-assets.sh'})"
case_ live-test-names-kms     bad "names RELEASE_KMS_KEY_REF" "$J['live-test'].setdefault('env', {}); $J['live-test']['env']['RELEASE_KMS_KEY_REF'] = 'x'"
case_ live-test-release-env-sign bad "job live-test-release is in the environment sign" "$J['live-test-release']['environment'] = 'sign'"

# the snapshot reach (REQ-CHAIN-004-AC14): a job that requests a write or an id-token must carry the snapshot guard
case_ decide-reachable-in-snapshot bad "reachable in snapshot mode" "$J['decide'] = {'runs-on': 'ubuntu-24.04', 'permissions': {'contents': 'write'}, 'if': \"\${{ github.ref == 'refs/heads/main' }}\", 'steps': []}"
case_ build-apk-gets-id-token bad "reachable in snapshot mode" "$J['build-apk']['permissions']['id-token'] = 'write'"
case_ rebuild-assemble-writes bad "reachable in snapshot mode" "$J['rebuild-assemble']['permissions']['packages'] = 'write'"
case_ live-test-writes-in-snapshot bad "reachable in snapshot mode" "$J['live-test']['permissions'] = {'id-token': 'write'}; $J['live-test'].pop('if', None)"
case_ persona-call-unguarded  bad "reachable in snapshot mode" "$J['persona-uat-rc'] = {'needs': 'build-assemble', 'uses': './.github/workflows/persona-uat.yml', 'permissions': {'contents': 'read', 'id-token': 'write'}, 'if': \"\${{ vars.PERSONA_UAT_ENABLED == 'true' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}\"}"
case_ persona-call-ok         ok  "" "$J['persona-uat-rc'] = {'needs': 'build-assemble', 'uses': './.github/workflows/persona-uat.yml', 'permissions': {'contents': 'read', 'id-token': 'write'}, 'if': \"\${{ inputs.mode != 'snapshot' && vars.PERSONA_UAT_ENABLED == 'true' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}\"}"
case_ persona-call-no-gate    bad "lacks the gate PERSONA_UAT_ENABLED" "$J['persona-uat-rc'] = {'needs': 'build-assemble', 'uses': './.github/workflows/persona-uat.yml', 'permissions': {'contents': 'read'}, 'if': \"\${{ inputs.mode != 'snapshot' && contains(github.ref_name, '-rc') }}\"}"
case_ persona-call-no-rc      bad "lacks the gate PERSONA_UAT_ENABLED" "$J['persona-uat-rc'] = {'needs': 'build-assemble', 'uses': './.github/workflows/persona-uat.yml', 'permissions': {'contents': 'read'}, 'if': \"\${{ inputs.mode != 'snapshot' && vars.PERSONA_UAT_ENABLED == 'true' }}\"}"
case_ calls-another-workflow  bad "release.yml calls no workflow file but persona-uat.yml" "$J['x'] = {'uses': './.github/workflows/ci.yml'}; $J['x']['permissions'] = {'contents': 'read'}"

# Build (REQ-CHAIN-004-AC1, AC12)
case_ freeze-wrong-runner     bad "build-freeze is not on ubuntu-24.04" "$J['build-freeze']['runs-on'] = 'ubuntu-24.04-arm'"
case_ freeze-id-token         bad "build-freeze is not on ubuntu-24.04" "$J['build-freeze']['permissions']['id-token'] = 'write'"
case_ freeze-extra-step       bad "build-freeze steps are not exactly" "$J['build-freeze']['steps'].append({'run': 'echo x'})"
case_ freeze-witness-step     bad "build-freeze steps are not exactly" "$J['build-freeze']['steps'][2] = {'run': 'bash bin/witnessed-local.sh freeze bin/build-freeze.sh'}"
case_ build-apk-one-runner    bad "build-apk is not a matrix over the two native runners" "$J['build-apk']['strategy']['matrix'][list($J['build-apk']['strategy']['matrix'])[0]] = ['ubuntu-24.04']"
case_ build-apk-no-admission-reads bad "build-apk does not hold exactly contents, checks" "$J['build-apk']['permissions'] = {'contents': 'read'}"
case_ build-apk-packages-write bad "build-apk does not hold exactly" "$J['build-apk']['permissions']['packages'] = 'write'"
case_ build-assemble-matrix   bad "build-assemble is not one job" "$J['build-assemble']['strategy'] = {'matrix': {'r': ['ubuntu-24.04']}}"
case_ build-assemble-arm      bad "build-assemble is not one job" "$J['build-assemble']['runs-on'] = 'ubuntu-24.04-arm'"
case_ build-assemble-checks   bad "build-assemble is not one job" "$J['build-assemble']['permissions']['checks'] = 'read'"
for jn in build-apk build-assemble rebuild-apk rebuild-assemble; do
  case_ "$jn-no-guard-step"   bad "$jn: the step right after the checkout is not the mode guard" "del $J['$jn']['steps'][1]"
  case_ "$jn-guard-not-mode"  bad "$jn: the step right after the checkout is not the mode guard" "$J['$jn']['steps'][1]['env'] = {'MODE': 'release'}"
  case_ "$jn-no-persist-false" bad "$jn: the first step is not the checkout with persist-credentials: false" "$J['$jn']['steps'][0]['with'] = {}"
  case_ "$jn-env"             bad "$jn carries env" "$J['$jn']['env'] = {'X': 'y'}"
  case_ "$jn-container"       bad "chain job $jn carries container" "$J['$jn']['container'] = 'alpine'"
  case_ "$jn-snapshot-step-ungated" bad "the snapshot Witness step" "hit(s.pop('if', None) for s in $J['$jn']['steps'] if 'witnessed' in (s.get('run') or '') and 'snapshot' in (s.get('run') or ''))"
  case_ "$jn-release-step-ungated" bad "the release Witness step" "hit(s.pop('if', None) for s in $J['$jn']['steps'] if 'witnessed' in (s.get('run') or '') and 'snapshot' not in (s.get('run') or ''))"
  case_ "$jn-snapshot-step-token" bad "the snapshot Witness step" "hit(s.__setitem__('env', {'GH_TOKEN': '\${{ github.token }}'}) for s in $J['$jn']['steps'] if 'witnessed' in (s.get('run') or '') and 'snapshot' in (s.get('run') or ''))"
  case_ "$jn-snapshot-step-name" bad "does not have exactly the two Witness steps" "hit(s.__setitem__('run', s['run'].replace('snapshot-', 'snap-', 1)) for s in $J['$jn']['steps'] if 'witnessed' in (s.get('run') or '') and 'snapshot' in (s.get('run') or ''))"
  case_ "$jn-third-witness-step" bad "does not have exactly the two Witness steps" "$J['$jn']['steps'].append({'run': 'bash bin/witnessed-local.sh extra bin/build-stage-apk.sh'})"
  case_ "$jn-id-token"        bad "holds an id-token or packages write" "$J['$jn']['permissions']['id-token'] = 'write'"
done
case_ build-apk-snapshot-script bad "runs another script" "hit(s.__setitem__('run', s['run'].replace('build-stage-snapshot-apk.sh', 'build-stage-apk.sh')) for s in $J['build-apk']['steps'] if 'snapshot-apk' in (s.get('run') or ''))"
case_ rebuild-assemble-snapshot-script bad "runs another script" "hit(s.__setitem__('run', s['run'].replace('build-stage-snapshot-rebuild-assemble.sh', 'build-stage-rebuild-assemble.sh')) for s in $J['rebuild-assemble']['steps'] if 'snapshot-rebuild' in (s.get('run') or ''))"
case_ build-hostile-input     bad "workflow_call still takes a hostile input" "d['on']['workflow_call']['inputs']['hostile'] = {'type': 'boolean'}"

# the hostile Build step runs in every build (REQ-CHAIN-004-AC19)
case_ hostile-step-only-rc    bad "carries a condition" "hit(s.__setitem__('if', \"\${{ contains(github.ref_name, '-rc') }}\") for jn in ('build-apk', 'build-assemble') for s in $J[jn]['steps'] if 'chain-hostile-step.sh' in (s.get('run') or ''))"
case_ hostile-step-input      bad "carries a condition" "hit(s.__setitem__('if', '\${{ inputs.hostile }}') for jn in ('build-apk', 'build-assemble') for s in $J[jn]['steps'] if 'chain-hostile-step.sh' in (s.get('run') or ''))"
case_ hostile-step-snapshot-skipped bad "carries a condition" "hit(s.__setitem__('if', \"\${{ inputs.mode != 'snapshot' }}\") for jn in ('build-apk', 'build-assemble') for s in $J[jn]['steps'] if 'chain-hostile-step.sh' in (s.get('run') or ''))"
case_ hostile-step-gone       bad "not run by exactly one step" "for jn in ('build-apk', 'build-assemble'): $J[jn]['steps'] = [s for s in $J[jn]['steps'] if 'chain-hostile-step.sh' not in (s.get('run') or '')]"
case_ hostile-step-twice      bad "not run by exactly one step" "$J['build-apk']['steps'].append({'run': 'bash bin/chain-hostile-step.sh'}); $J['build-assemble']['steps'].append({'run': 'bash bin/chain-hostile-step.sh'})"
case_ hostile-step-token      bad "holds a token or an env" "hit(s.__setitem__('env', {'GH_TOKEN': '\${{ github.token }}'}) for jn in ('build-apk', 'build-assemble') for s in $J[jn]['steps'] if 'chain-hostile-step.sh' in (s.get('run') or ''))"
case_ hostile-output-back     bad "exposes a hostile output" "$J['build-assemble'].setdefault('outputs', {})['hostile'] = \"\${{ github.ref_name }}\""

# Rebuild (REQ-CHAIN-005-AC1, AC7)
case_ rebuild-apk-one-runner  bad "rebuild-apk is not ONE job with a matrix over both chips" "$J['rebuild-apk']['strategy']['matrix'][list($J['rebuild-apk']['strategy']['matrix'])[0]] = ['ubuntu-24.04']"
case_ rebuild-apk-no-matrix   bad "rebuild-apk is not ONE job" "$J['rebuild-apk'].pop('strategy')"
for jn in rebuild-apk rebuild-assemble; do
  case_ "$jn-record-signed"      bad "$jn does not download the unsigned record artifact witness-build" "hit(s['with'].__setitem__('name', 'signed-witness-build') for s in $J['$jn']['steps'] if 'witness-build' in (s.get('with') or {}).get('name', ''))"
  case_ "$jn-record-gone"        bad "$jn does not download the unsigned record artifact witness-build" "$J['$jn']['steps'] = [s for s in $J['$jn']['steps'] if 'witness-build' not in (s.get('with') or {}).get('name', '')]"
  case_ "$jn-record-by-mode"     bad "$jn does not download the unsigned record artifact witness-build" "hit(s.__setitem__('if', \"\${{ inputs.mode != 'snapshot' }}\") for s in $J['$jn']['steps'] if 'witness-build' in (s.get('with') or {}).get('name', ''))"
  case_ "$jn-record-elsewhere"   bad "$jn does not download the unsigned record artifact witness-build" "hit(s['with'].__setitem__('path', 'records') for s in $J['$jn']['steps'] if 'witness-build' in (s.get('with') or {}).get('name', ''))"
  case_ "$jn-record-twice"       bad "$jn does not download the unsigned record artifact witness-build" "$J['$jn']['steps'].append({'uses': 'actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333', 'with': {'name': 'signed-witness-build', 'path': 'witness-build'}})"
done
case_ rebuild-permissions     bad "rebuild-apk does not hold exactly contents read" "$J['rebuild-apk']['permissions']['checks'] = 'read'"
case_ rebuild-assemble-arm    bad "rebuild-assemble does not run on ubuntu-24.04" "$J['rebuild-assemble']['runs-on'] = 'ubuntu-24.04-arm'"

# Check (REQ-CHAIN-006-AC1)
case_ check-one-runner        bad "check is not ONE job with a matrix" "$J['check']['strategy']['matrix'][list($J['check']['strategy']['matrix'])[0]] = ['ubuntu-24.04']"
case_ check-no-matrix         bad "check is not ONE job with a matrix" "$J['check'].pop('strategy')"
case_ check-id-token          bad "check does not hold exactly contents read" "$J['check']['permissions']['id-token'] = 'write'"
case_ check-environment       bad "check carries environment" "$J['check']['environment'] = 'agent'"
case_ check-env               bad "check carries env" "$J['check']['env'] = {'X': 'y'}"
case_ check-arm64-script      bad "arm64 script or a per-phase script" "$J['check']['steps'].append({'run': 'bash bin/witnessed-local.sh scanners bin/check-phase-arm64.sh scanners'})"
case_ check-per-phase-script  bad "arm64 script or a per-phase script" "hit(s.__setitem__('run', 'bash bin/witnessed-local.sh scanners bin/check-phase-scanners.sh') for s in $J['check']['steps'] if 'witnessed-local.sh scanners' in (s.get('run') or ''))"
case_ check-phase-order       bad "does not run exactly the three single-line steps" "$J['check']['steps'] = [s for s in $J['check']['steps'] if 'witnessed-local.sh runtime' not in (s.get('run') or '')]"
case_ check-phase-two-lines   bad "does not run exactly the three single-line steps" "hit(s.__setitem__('run', s['run'] + ' && true') for s in $J['check']['steps'] if 'witnessed-local.sh acceptance' in (s.get('run') or ''))"
case_ check-no-grype          bad "does not install, in this order" "$J['check']['steps'] = [s for s in $J['check']['steps'] if 'install-scanner.sh grype' not in (s.get('run') or '')]"
case_ check-outputs-record    bad "check has job outputs" "$J['check']['outputs'] = {'records': \"\${{ steps.w.outputs.records }}\"}"
case_ check-outputs-per-chip  bad "check has job outputs" "$J['check']['outputs'] = {'records': 'a', 'records-arm64': 'b'}"
case_ check-no-record-upload  bad "does not upload one record artifact per architecture" "$J['check']['steps'] = [s for s in $J['check']['steps'] if not str((s.get('with') or {}).get('name', '')).startswith('check-records-')]"
case_ rebuild-apk-outputs     bad "rebuild-apk has job outputs" "$J['rebuild-apk']['outputs'] = {'records': 'x'}"
case_ rebuild-apk-no-record-upload bad "rebuild-apk does not upload one record artifact" "$J['rebuild-apk']['steps'] = [s for s in $J['rebuild-apk']['steps'] if not str((s.get('with') or {}).get('name', '')).startswith('rebuild-records-')]"
case_ sign-check-digests-from-needs bad "reads record digests from needs" "$J['sign-check']['steps'].append({'run': 'x', 'env': {'D': \"\${{ needs.check.outputs.records }}\"}})"
case_ check-images-twice      bad "images artifact exactly once" "$J['check']['steps'].append({'uses': 'actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333', 'with': {'name': 'images', 'path': 'images'}})"
case_ check-no-result-uploads bad "does not upload witness-check-<runner>" "$J['check']['steps'] = [s for s in $J['check']['steps'] if 'upload-artifact' not in str(s.get('uses'))]"
case_ govulncheck-matrix      bad "check-govulncheck is not one job" "$J['check-govulncheck']['strategy'] = {'matrix': {'r': ['a']}}"
case_ govulncheck-arm         bad "check-govulncheck is not one job" "$J['check-govulncheck']['runs-on'] = 'ubuntu-24.04-arm'"
case_ govulncheck-id-token    bad "check-govulncheck is not one job" "$J['check-govulncheck']['permissions']['id-token'] = 'write'"
case_ govulncheck-steps       bad "check-govulncheck steps are not" "$J['check-govulncheck']['steps'].pop(3)"

# who may call release.yml (REQ-CHAIN-003-AC5): a second caller, a stage file, a missing callee
caller_case() { # caller_case NAME want WORD FILE PYEDIT: judge the real release.yml against a scratch directory whose FILE is edited
  local t="$work/tree-$1"; rm -rf "$t"; mkdir -p "$t/.github/workflows" "$t/bin"; cp "$root"/.github/workflows/*.y*ml "$t/.github/workflows/"; cp "$root"/bin/check-phase*.sh "$t/bin/" 2> /dev/null || true
  python3 - "$t/.github/workflows/$4" "$5" <<'PY'
import sys, yaml
p, edit = sys.argv[1], sys.argv[2]
d = yaml.load(open(p), Loader=yaml.BaseLoader)
exec(edit)
yaml.safe_dump(d, open(p, "w"), sort_keys=False, width=100000)
PY
  local out rc=0
  out=$(RELEASE_WF_CALLERS=1 python3 "$work/judge.py" "$t/.github/workflows/release.yml" "$t" 2>&1) || rc=$?
  if [ "$rc" = 1 ] && grep -Fq -- "$3" <<< "$out"; then pass=$((pass+1)); echo "PASS $1 -> refused ($3)"
  else failn=$((failn+1)); echo "FAIL $1 -> rc=$rc, wanted a refusal containing '$3': ${out:0:400}"; fi
}
caller_case ci-calls-release      bad "ci.yml job extra calls release.yml" ci.yml "d['jobs']['extra'] = {'uses': './.github/workflows/release.yml', 'with': {'mode': 'snapshot'}}"
caller_case auditor-calls-release bad "auditor.yml job extra calls release.yml" auditor.yml "d['jobs']['extra'] = {'uses': 'fosterstack/cache/.github/workflows/release.yml@0123456789abcdef0123456789abcdef01234567'}"
caller_case ci-step-calls-release bad "calls release.yml" ci.yml "d['jobs']['test']['steps'].append({'uses': './.github/workflows/release.yml'})"
caller_case scan-calls-stage      bad "calls a stage-*.yml file" scan.yml "d['jobs']['build']['uses'] = './.github/workflows/stage-build.yml'"
caller_case scan-calls-missing    bad "which does not exist" scan.yml "d['jobs']['extra'] = {'uses': './.github/workflows/nothing.yml'}"
caller_case other-job-calls-stage bad "calls a stage-*.yml file" scan.yml "d['jobs']['artifact-acceptance'] = {'needs': 'build', 'uses': './.github/workflows/stage-acceptance-artifacts.yml'}"

echo "release-workflow-wiring: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
