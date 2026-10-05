#!/usr/bin/env bash
# proves: REQ-UAT-001-AC1, REQ-UAT-001-AC2, REQ-UAT-001-AC3, REQ-UAT-001-AC4, REQ-UAT-001-AC5
# Where the persona UAT runs (owner ratified Oct 3 and Oct 4; point 9). The wiring is read from the PARSED workflows, never
# from substrings: a persona-uat job in the release chain that runs only for v*-rc.* tags, after the image and promotion,
# in the persona-uat environment, taking the image by the chain's digests, running the driver as a step that nothing can
# skip or make non-fatal, with the owner's model/budget variables and the model identity on THAT step, uploading the
# driver's output directory (transcripts and reports) even when personas fail; and a persona-uat job in the weekly
# workflow that runs only on its Monday cron, resolves the LATEST release's image digest, and runs the same driver with
# --publish. The pinned CI tools file holds exactly Jenkins, a GitLab runner, kind and the persona shell, each by digest.
# Neither job nor the driver, agent or provider may name a cloud CLI. The real workflows must pass; each of ~30 mutations
# (structurally valid YAML/JSON, made through the parsed document) must be rejected FOR THE REASON NAMED, so a checker
# crash or an unrelated failure cannot count as a catch.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
export PERSONA_ROOT="$root"
python3 - <<'PY'
import copy, json, os, re, sys, tempfile, yaml

root = os.environ["PERSONA_ROOT"]
REL = os.path.join(root, ".github/workflows/release.yml")
FRESH = os.path.join(root, ".github/workflows/go-freshness.yml")
TOOLS = os.path.join(root, "bin/persona-uat-tools.json")
SRC = [os.path.join(root, "bin", f) for f in ("persona-uat.py", "persona-uat-agent.py", "persona-uat-provider.py")]

def load(path): return yaml.load(open(path), Loader=yaml.BaseLoader)

CLOUD = re.compile(r"\b(terraform|tofu|pulumi|eksctl|doctl|az|gcloud|aws|kubectl|helm|ibmcloud|oci|linode-cli|vultr-cli)\b")
MODEL = re.compile(r"[Cc]laude|[Oo]pus|[Ss]onnet|[Hh]aiku|[Ff]able|gpt-|[Gg]emini|[Ll]lama|\bo[134]-")
PIN_USES = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
PIN_IMG = re.compile(r"^[a-z0-9][a-z0-9./_-]*(:[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}$")
CREDS = ("ANTHROPIC_FEDERATION_RULE_ID", "ANTHROPIC_ORGANIZATION_ID", "ANTHROPIC_SERVICE_ACCOUNT_ID", "ANTHROPIC_WORKSPACE_ID")
VARS = ("PERSONA_UAT_MODEL", "PERSONA_UAT_COMPLIANCE_MODEL", "PERSONA_UAT_TOKEN_BUDGET")

def norm(expr):
    """a workflow expression with the ${{ }} wrapper and all whitespace removed, for an EXACT comparison"""
    e = str(expr).strip()
    m = re.fullmatch(r"\$\{\{(.*)\}\}", e, re.S)
    return re.sub(r"\s+", "", m.group(1) if m else e)

def common(name, job, bad):
    steps = job.get("steps", [])
    if str(job.get("continue-on-error", "false")).lower() == "true":
        bad.append(f"{name}: continue-on-error on the job lets a persona failure pass")
    for k in ("container", "services"):
        if k in job:
            bad.append(f"{name}: the job declares {k}: the CI tools run only inside the driver, by digest, never as job {k}")
    drivers = [s for s in steps if "persona-uat.py" in str(s.get("run", ""))]
    if len(drivers) != 1:
        bad.append(f"{name}: expected exactly one step running bin/persona-uat.py, found {len(drivers)}"); return None
    d = drivers[0]
    run = str(d.get("run", ""))
    if "if" in d:
        bad.append(f"{name}: the driver step has an if: the persona run could be skipped")
    # a POSITIVE rule: the run is ONE command, the driver, with nothing that can swallow its status: no pipe, no &, no ;, no
    # conditional, no negation, no second command; $(...) substitutions inside its arguments are allowed
    body = "\n".join(l for l in run.splitlines() if l.strip() and not l.strip().startswith("#"))
    flat = re.sub(r"\$\([^()]*\)", "SUBST", body.replace("\\\n", " "))
    if not re.match(r"^python3 bin/persona-uat\.py\b", flat.strip()) or re.search(r"[|&;!<>`]|\bif\b|\bthen\b|\|\||\n", flat.strip()):
        bad.append(f"{name}: the driver step is not exactly one bare driver command (pipe, &, ;, if, !, a second command or redirect can swallow its exit status)")
    if str(d.get("continue-on-error", "false")).strip() not in ("false",):
        bad.append(f"{name}: the driver step has continue-on-error: its failure would not fail the run")
    if "timeout-minutes" not in job or not str(job.get("timeout-minutes", "")).isdigit() or int(job["timeout-minutes"]) > 180:
        bad.append(f"{name}: the job has no timeout-minutes (<= 180): a hung persona must not hold the runner")
    for flag in ("--out ", "--repo ", "--tools bin/persona-uat-tools.json", "--agent ", "--publish", "--image "):
        if flag not in run:
            bad.append(f"{name}: the driver is not run with {flag.strip()}")
    if "bin/persona-uat-agent.py" not in run:
        bad.append(f"{name}: the driver is not given bin/persona-uat-agent.py as its agent")
    for k in list(job.get("env", {})):
        if k in CREDS or k in VARS or k.startswith("ANTHROPIC_"):
            bad.append(f"{name}: {k} is set at job level: the secrets and owner variables belong on the driver step only")
    for s in steps:
        if s is not d:
            for k in s.get("env", {}):
                if k in CREDS or k in VARS:
                    bad.append(f"{name}: {k} is set on a step other than the driver")
    env = d.get("env", {})
    for v in VARS:
        if norm(env.get(v, "")) != f"vars.{v}":
            bad.append(f"{name}: {v} is not exactly vars.{v} on the driver step (the owner's variable)")
    for c in CREDS:
        if norm(env.get(c, "")) != f"secrets.{c}":
            bad.append(f"{name}: {c} is not exactly secrets.{c} on the driver step")
    if "ANTHROPIC_IDENTITY_TOKEN_FILE" not in env and not any("ANTHROPIC_IDENTITY_TOKEN_FILE" in json.dumps(s) for s in steps):
        bad.append(f"{name}: nothing provides ANTHROPIC_IDENTITY_TOKEN_FILE (the OIDC identity for the model)")
    before = steps[:steps.index(d)]
    if not any("getIDToken" in json.dumps(s) and "ANTHROPIC_IDENTITY_TOKEN_FILE" in json.dumps(s) for s in before):
        bad.append(f"{name}: no step before the driver mints the model identity token (OIDC, no keys)")
    if MODEL.search(json.dumps(job)):
        bad.append(f"{name}: a model name is written in the workflow")
    if CLOUD.search("\n".join(str(s.get("run", "")) for s in steps)):
        bad.append(f"{name}: a run step names a cloud CLI: nothing is provisioned in a cloud")
    ALLOWED = ("actions/checkout", "actions/github-script", "actions/upload-artifact")
    for s in steps:
        u = str(s.get("uses", ""))
        if u and not PIN_USES.match(u):
            bad.append(f"{name}: action {u} is not pinned to a commit digest")
        if u and u.split("@")[0] not in ALLOWED:
            bad.append(f"{name}: action {u.split('@')[0]} is not on the persona job's allowlist {ALLOWED}")
        if re.search(r"\bdocker\b", str(s.get("run", ""))):
            bad.append(f"{name}: a run step names docker: containers are started only by the driver, by pinned digest")
    for s in steps:
        if "actions/checkout" in str(s.get("uses", "")) and str(s.get("with", {}).get("persist-credentials", "")).lower() != "false":
            bad.append(f"{name}: checkout keeps the job's credentials (persist-credentials must be false)")
    ups = [s for s in steps if "upload-artifact" in str(s.get("uses", ""))]
    if len(ups) != 1:
        bad.append(f"{name}: expected exactly one transcript upload step, found {len(ups)}")
    for u in ups:
        if norm(u.get("if", "")) != "always()":
            bad.append(f"{name}: the transcript upload must run always() (found {u.get('if')!r})")
        outdir = re.search(r"--out\s+(\S+)", run)
        path = str(u.get("with", {}).get("path", "")).strip()
        if not outdir or outdir.group(1).strip("\"'").rstrip("/") != path.rstrip("/"):
            bad.append(f"{name}: the upload path {path!r} is not the driver's --out directory")
        if str(u.get("with", {}).get("if-no-files-found", "")) != "error":
            bad.append(f"{name}: the upload must fail on missing files (if-no-files-found: error)")
    for s in steps:
        if s is not d and s not in ups and "if" in s and "persona" in json.dumps(s).lower():
            bad.append(f"{name}: a persona step has an if: {s.get('if')!r}")
    return d

def judge_release(r, bad):
    j = r.get("jobs", {}).get("persona-uat")
    if not j:
        bad.append("release.yml has no persona-uat job"); return
    d = common("release persona-uat", j, bad)
    needs = j.get("needs", [])
    needs = [needs] if isinstance(needs, str) else needs
    for n in ("image", "promotion"):
        if n not in needs:
            bad.append(f"release persona-uat does not wait for {n}")
    if norm(j.get("if", "")) != "startsWith(github.ref,'refs/tags/v')&&contains(github.ref_name,'-rc.')":
        bad.append(f"release persona-uat does not run only for v*-rc.* tags (if: {j.get('if')!r})")
    env = j.get("environment")
    if (env if isinstance(env, str) else (env or {}).get("name")) != "persona-uat":
        bad.append("release persona-uat does not run in the persona-uat environment")
    p = j.get("permissions", {})
    want = {"contents": "read", "id-token": "write", "issues": "write", "packages": "read"}
    if any(p.get(k) != v for k, v in want.items()) or set(p) - set(want):
        bad.append(f"release persona-uat permissions are not exactly {want} (found {p})")
    if d is not None:
        run = str(d.get("run", ""))
        m = re.search(r"--image\s+(\S+(?:\s*\"[^\"]*\")?)", run)
        img = m.group(1) if m else ""
        arg = run.split("--image", 1)[-1].split(" --", 1)[0]
        if not re.search(r"fromJSON\(\s*needs\.image\.outputs\.digests\s*\)\.production", arg) or "@" not in arg:
            bad.append("release persona-uat takes the image from something other than the chain's digests (fromJSON(needs.image.outputs.digests).production)")
        if "--mode rc" not in run:
            bad.append("release persona-uat does not run the driver with --mode rc")

def judge_weekly(f, bad):
    j = f.get("jobs", {}).get("persona-uat")
    if not j:
        bad.append("go-freshness.yml has no persona-uat job"); return
    d = common("weekly persona-uat", j, bad)
    cron = [c.get("cron") for c in (f.get("on", {}).get("schedule") or [])] if isinstance(f.get("on"), dict) else []
    if norm(j.get("if", "")) != "github.event.schedule=='43 6 * * 1'".replace(" ", "") or "43 6 * * 1" not in cron:
        bad.append(f"weekly persona-uat does not run only on the Monday cron (if: {j.get('if')!r})")
    p = j.get("permissions", {})
    want = {"contents": "read", "id-token": "write", "issues": "write", "packages": "read"}
    if any(p.get(k) != v for k, v in want.items()) or set(p) - set(want):
        bad.append(f"weekly persona-uat permissions are not exactly {want} (found {p})")
    steps = j.get("steps", [])
    res = [s for s in steps if "gh release view" in str(s.get("run", ""))]
    if len(res) != 1 or re.search(r"gh release view\s+[\"']?[vV]?\d", str(res[0].get("run", ""))) or "imagetools inspect" not in str(res[0].get("run", "")):
        bad.append("weekly persona-uat does not resolve the LATEST release's image digest (gh release view with no fixed tag, then imagetools inspect)")
    elif d is not None:
        rid = res[0].get("id")
        run = str(d.get("run", ""))
        if not rid or f"steps.{rid}.outputs" not in run.split("--image", 1)[-1].split("--", 1)[0] or "@" not in run.split("--image", 1)[-1].split("--", 1)[0]:
            bad.append("weekly persona-uat does not hand the resolved latest-release image digest to --image")
    if d is not None and "--mode weekly" not in str(d.get("run", "")):
        bad.append("weekly persona-uat does not run the driver with --mode weekly")

def judge_tools(t, bad):
    if not isinstance(t, dict) or sorted(t) != ["gitlab-runner", "jenkins", "kind", "shell"]:
        bad.append(f"the persona tools file must hold exactly the keys gitlab-runner, jenkins, kind, shell (found {sorted(t) if isinstance(t, dict) else t})")
        return
    for k, v in t.items():
        if not PIN_IMG.match(str(v)):
            bad.append(f"tool {k} is not pinned by digest ({v!r})")

def judge_source(bad):
    for p in SRC:
        try:
            src = open(p).read()
        except OSError:
            bad.append(f"{os.path.relpath(p, root)} is missing"); continue
        code = "\n".join(l for l in src.splitlines() if not l.lstrip().startswith("#"))
        cmd = re.search(r"[\"'](?:terraform|tofu|pulumi|eksctl|doctl|aws|gcloud|az|kubectl|helm|ibmcloud|oci|linode-cli|vultr-cli)(?:\s|[\"'])", code)
        if cmd:
            bad.append(f"{os.path.relpath(p, root)} runs a cloud CLI: {cmd.group(0)}")
        for m in re.finditer(r"[\"']((?:[a-z0-9.-]+/)+[a-z0-9._-]+(?::[\w.-]+)?)[\"']", code):
            if re.search(r"(docker\.io|ghcr\.io|quay\.io|library|jenkins|gitlab|kindest)", m.group(1)) and "@sha256:" not in m.group(1):
                bad.append(f"{os.path.relpath(p, root)} names an image not pinned by digest: {m.group(1)}")

def judge(r, f, t):
    bad = []
    judge_release(r, bad); judge_weekly(f, bad); judge_tools(t, bad); judge_source(bad)
    return bad

R, F, T = load(REL), load(FRESH), json.load(open(TOOLS)) if os.path.exists(TOOLS) else None
passed = failed = 0
def result(ok, msg):
    global passed, failed
    if ok: passed += 1; print("ok  ", msg)
    else: failed += 1; print("FAIL", msg)

bad = judge(R, F, T if T is not None else "missing")
result(not bad, "the real workflows, tools file and sources satisfy the persona UAT wiring" + ("" if not bad else ": " + "; ".join(bad)))

def mutate(name, expect, fn, which="rel"):
    r, f, t = copy.deepcopy(R), copy.deepcopy(F), copy.deepcopy(T)
    try:
        {"rel": lambda: fn(r["jobs"]["persona-uat"]), "fresh": lambda: fn(f["jobs"]["persona-uat"]), "tools": lambda: fn(t)}[which]()
    except Exception as e:     # the real file lacks the thing being mutated: the real-file case above already failed
        result(False, f"mutation could not be applied ({name}): {type(e).__name__}: {e}"); return
    # round-trip through YAML text so the mutated document is valid YAML, not just a dict
    for doc in (r, f):
        yaml.safe_load(yaml.safe_dump(doc))
    found = judge(r, f, t)
    result(any(expect in b for b in found), f"caught: {name} (reason: {expect!r})" + ("" if any(expect in b for b in found) else f"; saw {found}"))

def drv(job): return next(s for s in job["steps"] if "persona-uat.py" in str(s.get("run", "")))
def up(job): return next(s for s in job["steps"] if "upload-artifact" in str(s.get("uses", "")))

# release job
mutate("rc job no longer waits for promotion", "does not wait for promotion", lambda j: j.update(needs=[n for n in j["needs"] if n != "promotion"]))
mutate("rc job runs for every tag", "does not run only for v*-rc.* tags", lambda j: j.update({"if": "${{ startsWith(github.ref, 'refs/tags/v') }}"}))
mutate("rc job's predicate gains && false", "does not run only for v*-rc.* tags", lambda j: j.update({"if": str(j["if"]).rstrip("} ") + " && false }}"}))
mutate("rc job continue-on-error", "continue-on-error on the job", lambda j: j.update({"continue-on-error": "true"}))
mutate("rc driver step continue-on-error", "the driver step has continue-on-error", lambda j: drv(j).update({"continue-on-error": "true"}))
mutate("rc driver step if: false", "the driver step has an if", lambda j: drv(j).update({"if": "false"}))
mutate("rc driver step is piped through tee", "not exactly one bare driver command", lambda j: drv(j).update(run=drv(j)["run"].rstrip() + " | tee persona.log"))
mutate("rc driver step is backgrounded", "not exactly one bare driver command", lambda j: drv(j).update(run=drv(j)["run"].rstrip() + " &"))
mutate("rc driver step wrapped in if !", "not exactly one bare driver command", lambda j: drv(j).update(run="if ! " + drv(j)["run"].strip() + "; then echo no; fi"))
mutate("rc driver continue-on-error is an expression", "the driver step has continue-on-error", lambda j: drv(j).update({"continue-on-error": "${{ always() }}"}))
mutate("rc job has no timeout", "no timeout-minutes", lambda j: j.pop("timeout-minutes"))
mutate("rc job uses a kind action", "is not on the persona job's allowlist", lambda j: j["steps"].insert(0, {"uses": "helm/kind-action@" + "a" * 40}))
mutate("rc job runs docker itself", "names docker", lambda j: j["steps"].insert(0, {"run": "docker run -d jenkins/jenkins:lts"}))
mutate("rc secrets set at job level", "set at job level", lambda j: j.setdefault("env", {}).update(ANTHROPIC_WORKSPACE_ID="${{ secrets.ANTHROPIC_WORKSPACE_ID }}"))
mutate("rc image argument is the raw digests JSON", "takes the image from something other than the chain's digests",
       lambda j: drv(j).update(run=re.sub(r"fromJSON\(needs\.image\.outputs\.digests\)\.production", "needs.image.outputs.digests", drv(j)["run"])))
mutate("rc driver step ends with || true", "not exactly one bare driver command", lambda j: drv(j).update(run=drv(j)["run"].rstrip() + " || true"))
mutate("rc driver step gets a tag, not the chain's digests", "takes the image from something other than the chain's digests",
       lambda j: drv(j).update(run=re.sub(r"fromJSON\(needs\.image\.outputs\.digests\)\.production", "github.ref_name", drv(j)["run"])))
mutate("rc job leaves the persona-uat environment", "persona-uat environment", lambda j: j.update(environment="release"))
mutate("rc model variable hard-coded", "PERSONA_UAT_MODEL is not exactly vars.PERSONA_UAT_MODEL", lambda j: drv(j).setdefault("env", {}).update(PERSONA_UAT_MODEL="m-1"))
mutate("rc owner variables moved off the driver step onto the upload step", "is not exactly vars.PERSONA_UAT_MODEL",
       lambda j: (up(j).update(env={v: drv(j)["env"].pop(v) for v in VARS if v in drv(j).get("env", {})})))
mutate("rc budget variable dropped", "PERSONA_UAT_TOKEN_BUDGET is not exactly vars.PERSONA_UAT_TOKEN_BUDGET", lambda j: drv(j)["env"].pop("PERSONA_UAT_TOKEN_BUDGET"))
mutate("rc compliance variable replaced by the default one", "PERSONA_UAT_COMPLIANCE_MODEL is not exactly vars.PERSONA_UAT_COMPLIANCE_MODEL",
       lambda j: drv(j)["env"].update(PERSONA_UAT_COMPLIANCE_MODEL="${{ vars.PERSONA_UAT_MODEL }}"))
mutate("rc federation secret dropped", "ANTHROPIC_WORKSPACE_ID is not exactly secrets.ANTHROPIC_WORKSPACE_ID", lambda j: drv(j)["env"].pop("ANTHROPIC_WORKSPACE_ID"))
mutate("rc upload path is not the driver's output", "is not the driver's --out directory", lambda j: up(j)["with"].update(path="/tmp/unrelated"))
mutate("rc upload skipped on failure", "must run always()", lambda j: up(j).update({"if": "${{ always() && false }}"}))
mutate("rc upload tolerates no files", "if-no-files-found: error", lambda j: up(j)["with"].update({"if-no-files-found": "ignore"}))
mutate("rc job provisions a cloud instance (plain form)", "names a cloud CLI",
       lambda j: j["steps"].insert(0, {"run": "aws --region us-east-1 ec2 run-instances --image-id ami-1"}))
mutate("rc job declares an unpinned job container", "declares container", lambda j: j.update(container="jenkins/jenkins:lts"))
mutate("rc job declares an unpinned service", "declares services", lambda j: j.update(services={"jenkins": {"image": "jenkins/jenkins:lts"}}))
mutate("rc checkout keeps credentials", "persist-credentials must be false", lambda j: j["steps"].insert(0, {"uses": "actions/checkout@" + "a" * 40, "with": {}}))
mutate("rc job uses an action by tag", "is not pinned to a commit digest", lambda j: j["steps"].insert(0, {"uses": "actions/checkout@v4"}))
mutate("rc driver step drops --publish", "--publish", lambda j: drv(j).update(run=drv(j)["run"].replace("--publish", "")))
mutate("rc job permissions gain contents: write", "permissions are not exactly", lambda j: j["permissions"].update(contents="write"))
mutate("rc job loses issues: write (friction could not be filed)", "permissions are not exactly", lambda j: j["permissions"].pop("issues"))
mutate("rc job mints no model identity token", "mints the model identity token", lambda j: j.update(steps=[s for s in j["steps"] if "getIDToken" not in json.dumps(s)]))
# weekly job
mutate("weekly job runs on every cron", "does not run only on the Monday cron", lambda j: j.update({"if": "${{ github.event_name == 'schedule' }}"}), "fresh")
mutate("weekly job resolves a fixed release tag", "does not resolve the LATEST release's image digest",
       lambda j: next(s for s in j["steps"] if "gh release view" in str(s.get("run", ""))).update(run="gh release view v0.2.0 --json tagName; docker buildx imagetools inspect x"), "fresh")
mutate("weekly driver is handed a fixed image", "does not hand the resolved latest-release image digest",
       lambda j: drv(j).update(run=re.sub(r"--image\s+\S+", "--image ghcr.io/x/cache@sha256:" + "a" * 64, drv(j)["run"])), "fresh")
mutate("weekly driver runs in rc mode", "--mode weekly", lambda j: drv(j).update(run=drv(j)["run"].replace("--mode weekly", "--mode rc")), "fresh")
mutate("weekly driver step is non-fatal", "not exactly one bare driver command", lambda j: drv(j).update(run=drv(j)["run"].rstrip() + " || true"), "fresh")
# tools file
mutate("tools: jenkins by tag", "tool jenkins is not pinned by digest", lambda t: t.update(jenkins="docker.io/jenkins/jenkins:lts"), "tools")
mutate("tools: the persona shell by tag", "tool shell is not pinned by digest", lambda t: t.update(shell="docker.io/library/debian:12"), "tools")
mutate("tools: the kind entry is missing", "must hold exactly the keys", lambda t: t.pop("kind"), "tools")
mutate("tools: an extra tool appears", "must hold exactly the keys", lambda t: t.update(terraform="docker.io/hashicorp/terraform@sha256:" + "5" * 64), "tools")

print(f"persona-uat wiring: {passed} passed, {failed} failed")
sys.exit(0 if failed == 0 else 1)
PY
