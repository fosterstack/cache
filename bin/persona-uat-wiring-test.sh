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

CLOUD = re.compile(r"\b(terraform|tofu|pulumi|eksctl|doctl|az|gcloud|aws|ibmcloud|oci|linode-cli|vultr-cli)\b")
MODEL = re.compile(r"[Cc]laude|[Oo]pus|[Ss]onnet|[Hh]aiku|[Ff]able|gpt-|[Gg]emini|[Ll]lama|\bo[134]-")
PIN_USES = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
PIN_IMG = re.compile(r"^[a-z0-9][a-z0-9./_-]*(:[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}$")
CREDS = ("ANTHROPIC_FEDERATION_RULE_ID", "ANTHROPIC_ORGANIZATION_ID", "ANTHROPIC_SERVICE_ACCOUNT_ID", "ANTHROPIC_WORKSPACE_ID")
VARS = ("PERSONA_UAT_MODEL", "PERSONA_UAT_COMPLIANCE_MODEL", "PERSONA_UAT_TOKEN_BUDGET")

def norm(expr):
    """a workflow expression with the ${{ }} wrapper removed and whitespace removed only OUTSIDE quoted strings, for an EXACT
    comparison (a cron literal's own spaces are part of it)"""
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

def expr_is(val, expr):
    """val is exactly the GitHub expression ${{ expr }} (whitespace inside the braces free), never the literal text expr"""
    return re.fullmatch(r"\$\{\{\s*" + re.escape(expr) + r"\s*\}\}", str(val).strip()) is not None

def literal_false(v):
    return str(v).strip() in ("", "false") if v is not None else True

def common(name, job, bad):
    steps = job.get("steps", [])
    weekly = name.startswith("weekly")
    pre = "harness/" if weekly else ""                    # the weekly job keeps TODAY's tested harness apart from the release's docs
    repo_dir = "release-docs" if weekly else "."
    if not literal_false(job.get("continue-on-error")):
        bad.append(f"{name}: continue-on-error on the job lets a persona failure pass")
    if str(job.get("defaults", {}).get("run", {}).get("shell", "bash")) != "bash":
        bad.append(f"{name}: the job's default shell is not plain bash")
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
    body = "\n".join(l for l in run.replace("\\\n", " ").splitlines() if l.strip() and not l.strip().startswith("#"))
    flat = re.sub(r"\$\([^()]*\)", "SUBST", body)
    if not re.match(r"^python3 " + re.escape(pre) + r"bin/persona-uat\.py\b", flat.strip()) or re.search(r"[|&;!<>`]|\bif\b|\bthen\b|\|\||\n", flat.strip()):
        bad.append(f"{name}: the driver step is not exactly one bare driver command (pipe, &, ;, if, !, a second command or redirect can swallow its exit status)")
    if not literal_false(d.get("continue-on-error")):
        bad.append(f"{name}: the driver step has continue-on-error: its failure would not fail the run")
    if str(d.get("shell", "bash")) != "bash":
        bad.append(f"{name}: the driver step's shell is {d.get('shell')!r}, not plain bash (a custom shell can swallow the exit status)")
    if "timeout-minutes" not in job or not str(job.get("timeout-minutes", "")).isdigit() or int(job["timeout-minutes"]) > 180:
        bad.append(f"{name}: the job has no timeout-minutes (<= 180): a hung persona must not hold the runner")
    import shlex
    try:
        argv = shlex.split(flat.replace("SUBST", "SUBSTVAL"), comments=True)     # a trailing `# --publish` is a comment, not a flag
    except ValueError:
        argv = []
    opts = [t for t in argv if t.startswith("--")]
    for flag in ("--mode", "--image", "--repo", "--out", "--tools", "--agent", "--publish"):
        if opts.count(flag) != 1:
            bad.append(f"{name}: the driver is not run with {flag} exactly once (found {opts.count(flag)}): the last occurrence would win")
    if sorted(set(opts) - {"--mode", "--image", "--repo", "--out", "--tools", "--agent", "--publish"}):
        bad.append(f"{name}: the driver is given options outside the contract: {sorted(set(opts) - {'--mode', '--image', '--repo', '--out', '--tools', '--agent', '--publish'})}")
    first = next((i for i, t in enumerate(argv) if t.endswith("bin/persona-uat.py")), None)       # skip `python3` and the driver script itself
    positional = [] if first is None else [t for i, t in enumerate(argv[first + 1:], first + 1)
                                           if not t.startswith("--") and not (argv[i - 1].startswith("--") and argv[i - 1] != "--publish")]
    if positional:
        bad.append(f"{name}: the driver command has tokens that are no option or option value: {positional}")
    if d.get("working-directory") or (job.get("defaults", {}).get("run", {}) or {}).get("working-directory"):
        bad.append(f"{name}: a working-directory on the driver step or the job: the relative checkout, driver, agent and docs paths assume the workspace root")
    def optval(f):
        return argv[argv.index(f) + 1] if f in argv[:-1] else None
    if optval("--tools") != pre + "bin/persona-uat-tools.json":
        bad.append(f"{name}: --tools is not {pre}bin/persona-uat-tools.json")
    if optval("--repo") != repo_dir:
        bad.append(f"{name}: --repo is not the docs checkout ({repo_dir})")
    if optval("--agent") != f"python3 {pre}bin/persona-uat-agent.py":
        bad.append(f"{name}: the driver is not given 'python3 {pre}bin/persona-uat-agent.py' as its agent")
    for k in list(job.get("env", {})):
        if k in CREDS or k in VARS or k.startswith("ANTHROPIC_"):
            bad.append(f"{name}: {k} is set at job level: the secrets and owner variables belong on the driver step only")
    for s in steps:
        if s is not d:
            for k in s.get("env", {}):
                if k in CREDS or k in VARS:
                    bad.append(f"{name}: {k} is set on a step other than the driver")
    env = d.get("env", {})
    extra_env = sorted(set(env) - set(VARS) - set(CREDS) - {"GH_TOKEN"})
    if extra_env:
        bad.append(f"{name}: the driver step carries environment outside the contract (no other credential, and no override of the identity token file the identity step exports): {extra_env}")
    for v in VARS:
        if not expr_is(env.get(v, ""), f"vars.{v}"):
            bad.append(f"{name}: {v} is not exactly vars.{v} on the driver step (the owner's variable)")
    if not expr_is(env.get("GH_TOKEN", ""), "github.token"):
        bad.append(f"{name}: GH_TOKEN is not exactly github.token on the driver step (its gh calls need it)")
    for c in CREDS:
        if not expr_is(env.get(c, ""), f"secrets.{c}"):
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
    for s in steps:
        if "actions/github-script" in str(s.get("uses", "")):
            body = str(s.get("with", {}).get("script", ""))
            if CLOUD.search(body) or re.search(r"\bexec\b|child_process|require\(['\"](?!fs['\"])", body):
                bad.append(f"{name}: the github-script body runs a command or names a cloud CLI (it may only mint and write the identity token)")
            if "if" in s or str(s.get("continue-on-error", "false")) not in ("false",):
                bad.append(f"{name}: the identity step has an if or continue-on-error: the persona job could run without its identity")
            wm = re.search(r"fs\.writeFileSync\(\s*(\w+)\s*,\s*token\s*\)", body)
            if not wm or not re.search(r"exportVariable\(\s*'ANTHROPIC_IDENTITY_TOKEN_FILE'\s*,\s*" + re.escape(wm.group(1)) + r"\s*\)", body.replace('"', "'")):
                bad.append(f"{name}: the identity step does not write the token to a file and export ANTHROPIC_IDENTITY_TOKEN_FILE for THAT file")
    for s in steps:
        for k, v in (s.get("with") or {}).items():
            if k != "script" and CLOUD.search(str(v)):
                bad.append(f"{name}: a step input names a cloud CLI ({k})")
    ALLOWED = ("actions/checkout", "actions/github-script", "actions/upload-artifact")
    for s in steps:
        u = str(s.get("uses", ""))
        if u and not PIN_USES.match(u):
            bad.append(f"{name}: action {u} is not pinned to a commit digest")
        if u and u.split("@")[0] not in ALLOWED:
            bad.append(f"{name}: action {u.split('@')[0]} is not on the persona job's allowlist {ALLOWED}")
        if re.search(r"\bdocker\b(?!\s+buildx\s+imagetools\s+inspect\b)", str(s.get("run", ""))):
            bad.append(f"{name}: a run step uses docker for more than `docker buildx imagetools inspect`: containers are started only by the driver, by pinned digest")
    for s in steps:
        if "actions/checkout" in str(s.get("uses", "")) and str(s.get("with", {}).get("persist-credentials", "")).lower() != "false":
            bad.append(f"{name}: checkout keeps the job's credentials (persist-credentials must be false)")
    di = steps.index(d)
    for i, s in enumerate(steps):
        if s is d: continue
        isrun = "run" in s
        is_resolver = isrun and "gh release view" in str(s.get("run", "")) and name.startswith("weekly")
        is_boot = isrun and re.fullmatch(r"python3 -m pip install --quiet --require-hashes --only-binary=:all: -r " + re.escape(pre) + r"bin/persona-uat-requirements\.txt\s*",
                                         str(s.get("run", "")).strip()) is not None
        if i > di and "upload-artifact" not in str(s.get("uses", "")):
            bad.append(f"{name}: a step after the driver other than the transcript upload could alter the files before upload")
        if i < di and isrun and not is_resolver and not is_boot:
            bad.append(f"{name}: a run step before the driver other than the latest-release resolver and the one hash-pinned SDK install (it could change what the driver sees)")
    cos = [s for s in steps if "actions/checkout" in str(s.get("uses", ""))]
    if len(cos) != (2 if weekly else 1) or any(steps.index(c) > di for c in cos):
        bad.append(f"{name}: expected exactly {2 if weekly else 1} actions/checkout step(s) before the driver (the personas read the docs they bring; without them the docs directory is empty)")
    for c in cos:
        wi = c.get("with", {}) or {}
        if "repository" in wi:
            bad.append(f"{name}: a checkout of another repository: the personas must read THIS repository's docs")
    if not weekly and cos:
        wi = cos[0].get("with", {}) or {}
        if "path" in wi or ("ref" in wi and not expr_is(wi["ref"], "github.sha")):
            bad.append(f"{name}: the release-candidate checkout is not of the candidate commit (no path, no ref other than github.sha): the personas would read other docs than the candidate's")
    if weekly and len(cos) == 2:
        paths = sorted(str((c.get("with", {}) or {}).get("path", "")) for c in cos)
        if paths != ["harness", "release-docs"]:
            bad.append(f"{name}: the two checkouts must be path: harness (today's tested driver) and path: release-docs (the released docs): {paths}")
        for c in cos:
            if str((c.get("with", {}) or {}).get("path", "")) == "harness" and "ref" in (c.get("with", {}) or {}):
                bad.append(f"{name}: the harness checkout must be today's main (no ref): an old release has no driver")
    boots = [s for s in steps if re.fullmatch(r"python3 -m pip install --quiet --require-hashes --only-binary=:all: -r " + re.escape(pre) + r"bin/persona-uat-requirements\.txt\s*", str(s.get("run", "")).strip())]
    harness_co = [c for c in cos if str((c.get("with", {}) or {}).get("path", "")) in ("", "harness")]
    if len(boots) != 1 or (harness_co and steps.index(boots[0]) < steps.index(harness_co[0])) or steps.index(boots[0]) > di:
        bad.append(f"{name}: expected exactly one hash-pinned SDK install, after the harness checkout and before the driver")
    ups = [s for s in steps if "upload-artifact" in str(s.get("uses", ""))]
    if len(ups) != 1:
        bad.append(f"{name}: expected exactly one transcript upload step, found {len(ups)}")
    for u in ups:
        if not literal_false(u.get("continue-on-error")):
            bad.append(f"{name}: the transcript upload has continue-on-error: a run could go green without retaining its transcripts")
        if steps.index(u) != di + 1:
            bad.append(f"{name}: the transcript upload must be the step immediately after the driver")
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

def run_resolver(script):
    """EXECUTE the weekly resolver against recording gh/docker stubs: it must ask gh for the latest release's tag in THIS repository (GH_REPO),
    inspect <registry>/<owner>/cache:<tag without the leading v> (the published image tags are unprefixed) with a digest-only --format, and
    write tag=<the release tag, with its v> and image=<registry>/<owner>/cache@<that digest> to GITHUB_OUTPUT."""
    import subprocess
    out = []
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(d + "/bin")
        open(d + "/bin/gh", "w").write("#!/bin/sh\n[ -n \"$GH_REPO\" ] || { echo 'no repo' >&2; exit 1; }\n"
                                       "echo \"gh $*\" >> \"$REC\"\n"
                                       "case \"$*\" in 'release view --json tagName -q .tagName'|'release view --json tagName --jq .tagName') echo v0.2.1;; *) echo \"unexpected gh call: $*\" >&2; exit 1;; esac\n")
        open(d + "/bin/docker", "w").write("#!/bin/sh\necho \"docker $*\" >> \"$REC\"\n"
                                           "[ \"$1 $2 $3\" = 'buildx imagetools inspect' ] || { echo 'unexpected docker call' >&2; exit 1; }\n"
                                           "[ \"$4\" = 'ghcr.io/own/cache:0.2.1' ] || { echo \"wrong image reference: $4\" >&2; exit 1; }\n"
                                           "case \"$*\" in *\"--format '{{.Manifest.Digest}}'\"*|*'--format {{.Manifest.Digest}}'*) echo sha256:" + "d" * 64 + ";; *) echo wrong-format;; esac\n")
        for f in ("gh", "docker"):
            os.chmod(d + "/bin/" + f, 0o755)
        open(d + "/script.sh", "w").write(script)
        env = {"PATH": d + "/bin:" + os.environ["PATH"], "GH_REPO": "own/cache", "REGISTRY_OWNER": "own", "GITHUB_OUTPUT": d + "/out", "REC": d + "/rec", "HOME": d}
        open(d + "/out", "w").close(); open(d + "/rec", "w").close()
        r = subprocess.run(["bash", "-e", d + "/script.sh"], env=env, capture_output=True, text=True)
        outs = open(d + "/out").read()
        if r.returncode != 0:
            out.append("weekly persona-uat's resolver failed against recording gh/docker (wrong repository, wrong image reference, or a bad call): " + r.stderr.strip()[:200])
        elif "tag=v0.2.1" not in outs.splitlines() or ("image=ghcr.io/own/cache@sha256:" + "d" * 64) not in outs.splitlines():
            out.append("weekly persona-uat's resolver does not write tag=<release tag> and image=<registry>/<owner>/cache@<inspected digest> to GITHUB_OUTPUT: " + repr(outs))
    return out

def run_identity(step):
    """EXECUTE the identity step's script in node against a fake core and a capturing console: the token is minted (awaited), the TOKEN ITSELF is
    registered for masking, it is written to a file, that file is what ANTHROPIC_IDENTITY_TOKEN_FILE is exported as, and it is never logged."""
    import subprocess, shutil
    if not shutil.which("node"):
        return ["node is required to execute the identity step's script (the proof must not be skipped)"]
    body = str((step.get("with", {}) or {}).get("script", ""))
    with tempfile.TemporaryDirectory() as d:
        open(d + "/s.js", "w").write(body)
        open(d + "/run.js", "w").write("""
const fs = require('fs'); const body = fs.readFileSync(process.argv[2], 'utf8');
const calls = {exported: {}, masked: [], logs: []};
const core = { getIDToken: (aud) => new Promise((res) => setTimeout(() => res('FIXTURE-TOKEN:' + aud), 5)), setSecret: (t) => calls.masked.push(t),
               exportVariable: (k, v) => { calls.exported[k] = v; }, setFailed: () => {}, info: (m) => calls.logs.push(String(m)), debug: (m) => calls.logs.push(String(m)) };
const cons = { log: (...a) => calls.logs.push(a.join(' ')), info: (...a) => calls.logs.push(a.join(' ')), warn: (...a) => calls.logs.push(a.join(' ')), error: (...a) => calls.logs.push(a.join(' ')) };
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
new AsyncFunction('core', 'require', 'process', 'console', body)(core, require, process, cons).then(() => {
  const f = calls.exported.ANTHROPIC_IDENTITY_TOKEN_FILE; let content = null; try { content = fs.readFileSync(f, 'utf8'); } catch (e) {}
  fs.writeFileSync(process.argv[3], JSON.stringify({file: f || null, content, masked: calls.masked, logs: calls.logs}));
}).catch((e) => fs.writeFileSync(process.argv[3], JSON.stringify({error: String(e)})));
""")
        env = dict(os.environ, RUNNER_TEMP=d)
        subprocess.run(["node", d + "/run.js", d + "/s.js", d + "/res.json"], env=env, capture_output=True, text=True)
        try:
            res = json.load(open(d + "/res.json"))
        except Exception:
            return ["the identity step's script could not be executed"]
        tok = "FIXTURE-TOKEN:https://api.anthropic.com"
        if res.get("error") or not res.get("file") or res.get("content") != tok or tok not in (res.get("masked") or []):
            return [f"the identity step does not mint (await), mask THE TOKEN and write it to the file it exports: {res}"]
        if any("FIXTURE-TOKEN" in l for l in res.get("logs", [])):
            return ["the identity step logs the token"]
    return []

def judge_requirements(bad):
    p = os.path.join(root, "bin/persona-uat-requirements.txt")
    try:
        txt = open(p).read()
    except OSError:
        bad.append("bin/persona-uat-requirements.txt is missing (the one hash-pinned SDK install the persona jobs run)"); return
    reqs = [l for l in re.sub(r"\\\n", " ", txt).splitlines() if l.strip() and not l.strip().startswith("#")]
    if not any(l.startswith("anthropic==") for l in reqs) or any("--hash=sha256:" not in l for l in reqs):
        bad.append("bin/persona-uat-requirements.txt must pin anthropic== and every requirement by --hash=sha256:")

def workflow_defaults(doc, label, bad):
    """a workflow-level `defaults.run` (working-directory or shell) is inherited by every job: the driver's relative paths assume the workspace root"""
    run = (doc.get("defaults", {}) or {}).get("run", {}) or {}
    if run.get("working-directory"):
        bad.append(f"{label} has a workflow-level working-directory: the relative checkout, driver, agent and docs paths assume the workspace root")
    if str(run.get("shell", "bash")) != "bash":
        bad.append(f"{label} has a workflow-level default shell that is not plain bash")

def judge_release(r, bad):
    workflow_defaults(r, "release.yml", bad)
    push = (r.get("on", {}).get("push", {}) or {}) if isinstance(r.get("on"), dict) else {}
    tags = push.get("tags", [])
    if (tags if isinstance(tags, list) else [tags]) != ["v*"] or "tags-ignore" in push:
        bad.append("release.yml's push tags are not exactly ['v*'] (a negation or tags-ignore could disable the release-candidate trigger)")
    pf = r.get("jobs", {}).get("patch-failed", {}) or {}
    pfn = pf.get("needs", [])
    if "persona-uat" not in ([pfn] if isinstance(pfn, str) else pfn):
        bad.append("release.yml's patch-failed does not list persona-uat in needs (a failed RC persona run must open the failure issue)")
    j = r.get("jobs", {}).get("persona-uat")
    if not j:
        bad.append("release.yml has no persona-uat job"); return
    d = common("release persona-uat", j, bad)
    for s_ in j.get("steps", []):
        if "actions/github-script" in str(s_.get("uses", "")):
            bad.extend(run_identity(s_))
    needs = j.get("needs", [])
    needs = [needs] if isinstance(needs, str) else needs
    for n in ("image", "promotion"):
        if n not in needs:
            bad.append(f"release persona-uat does not wait for {n}")
    if set(needs) != {"image", "promotion"}:
        bad.append(f"release persona-uat's needs are not exactly image and promotion (an extra dependency that is skipped on RC tags would skip every persona): {sorted(needs)}")
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
        arg = run.replace("\\\n", " ").split("--image", 1)[-1].split(" --", 1)[0]
        if not re.search(r"\$\{\{\s*fromJSON\(\s*needs\.image\.outputs\.digests\s*\)\.production\s*\}\}", arg) or "@" not in arg:
            bad.append("release persona-uat takes the image from something other than the chain's digests (fromJSON(needs.image.outputs.digests).production)")
        if "--mode rc" not in run:
            bad.append("release persona-uat does not run the driver with --mode rc")

def judge_weekly(f, bad):
    workflow_defaults(f, "go-freshness.yml", bad)
    j = f.get("jobs", {}).get("persona-uat")
    if not j:
        bad.append("go-freshness.yml has no persona-uat job"); return
    d = common("weekly persona-uat", j, bad)
    for s_ in j.get("steps", []):
        if "actions/github-script" in str(s_.get("uses", "")):
            bad.extend(run_identity(s_))
    cron = [c.get("cron") for c in (f.get("on", {}).get("schedule") or [])] if isinstance(f.get("on"), dict) else []
    if norm(j.get("if", "")) != norm("github.event.schedule == '43 6 * * 1'") or "43 6 * * 1" not in cron:
        bad.append(f"weekly persona-uat does not run only on the Monday cron (if: {j.get('if')!r})")
    if "needs" in j:
        bad.append("weekly persona-uat has needs: a skipped dependency (the daily check job is skipped on the Monday cron) would skip every persona")
    env_ = j.get("environment")
    if (env_ if isinstance(env_, str) else (env_ or {}).get("name")) != "persona-uat":
        bad.append("weekly persona-uat does not run in the persona-uat environment")
    p = j.get("permissions", {})
    want = {"contents": "read", "id-token": "write", "issues": "write", "packages": "read"}
    if any(p.get(k) != v for k, v in want.items()) or set(p) - set(want):
        bad.append(f"weekly persona-uat permissions are not exactly {want} (found {p})")
    steps = j.get("steps", [])
    res = [s for s in steps if "gh release view" in str(s.get("run", ""))]
    if len(res) != 1:
        bad.append("weekly persona-uat does not resolve the LATEST release's image digest (expected exactly one gh release view step)")
    else:
        r = res[0]; rrun = "\n".join(l for l in str(r.get("run", "")).splitlines() if not l.strip().startswith("#"))
        if not expr_is((r.get("env", {}) or {}).get("GH_REPO", ""), "github.repository") or not expr_is((r.get("env", {}) or {}).get("REGISTRY_OWNER", ""), "github.repository_owner"):
            bad.append("weekly persona-uat's resolver step needs env GH_REPO = github.repository and REGISTRY_OWNER = github.repository_owner (it runs before any checkout)")
        bad.extend(run_resolver(rrun))
        m = re.search(r"(\w+)=\$\(\s*gh release view\s+--json tagName\s+(?:-q|--jq)\s+\.tagName\s*\)", rrun)
        if not m:
            bad.append("weekly persona-uat does not resolve the LATEST release's image digest (gh release view --json tagName -q .tagName, no fixed tag)")
        else:
            var = m.group(1)
            if "if" in r or not literal_false(r.get("continue-on-error")):
                bad.append("weekly persona-uat's resolver step is conditional or non-fatal: the weekly run could go on without an image")
            insp = [l for l in rrun.splitlines() if "imagetools inspect" in l]
            if not insp or not re.search(r"\$\{?" + re.escape(var) + r"\}?(?![\w])", insp[0]):
                bad.append("weekly persona-uat does not inspect the image of the release it just resolved (imagetools inspect must use the resolved tag)")
            dm = re.search(r"(\w+)=\$\([^\n]*imagetools inspect[^\n]*\)", rrun)
            if dm and "--format" not in dm.group(0):
                bad.append("weekly persona-uat's resolver does not extract the digest (imagetools inspect needs --format '{{.Manifest.Digest}}')")
            if not dm or not re.search(r"image=[^\n]*@\$\{?" + re.escape(dm.group(1)) + r"\}?(?![\w])[^\n]*>>\s*\"?\$GITHUB_OUTPUT", rrun):
                bad.append("weekly persona-uat's resolver does not write an image= output built from the digest it inspected")
            if not expr_is(r.get("env", {}).get("GH_TOKEN", ""), "github.token"):
                bad.append("weekly persona-uat's resolver does not get GH_TOKEN = github.token")
        if d is not None:
            if steps.index(r) > steps.index(d):
                bad.append("weekly persona-uat resolves the latest release AFTER running the driver")
            cos = [s for s in steps if "actions/checkout" in str(s.get("uses", "")) and str((s.get("with", {}) or {}).get("path", "")) == "release-docs"]
            if cos and (steps.index(cos[0]) < steps.index(r) or not re.fullmatch(r"\$\{\{\s*steps\." + re.escape(str(r.get("id"))) + r"\.outputs\.tag\s*\}\}", str(cos[0].get("with", {}).get("ref", "")).strip())):
                bad.append("weekly persona-uat's checkout is not of the resolved release's tag (ref: steps.<resolver>.outputs.tag, after the resolver): the personas would read the wrong docs")
            if not re.search(r"tag=[^\n]*>>\s*\"?\$GITHUB_OUTPUT", rrun):
                bad.append("weekly persona-uat's resolver does not write its tag= output")
            run = str(d.get("run", ""))
            arg = run.split("--image", 1)[-1].split(" --", 1)[0].strip()
            if not r.get("id") or not re.fullmatch(r"\$\{\{\s*steps\." + re.escape(str(r.get("id"))) + r"\.outputs\.image\s*\}\}", arg.strip().strip("\"'")):
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
    want = {"jenkins": "jenkins/jenkins", "gitlab-runner": "gitlab/gitlab-runner", "kind": "kindest/node"}
    for k, repo in want.items():
        got = str(t.get(k, "")).split("@")[0].split(":")[0]
        if not (got == repo or got.endswith("/" + repo)):
            bad.append(f"tool {k} does not name its own image (expected the repository {repo!r}): {t.get(k)!r}")
    if len({str(v).split("@")[0] for v in t.values()}) != 4:
        bad.append("the persona tools are not four distinct images")

def judge_source(bad):
    for p in SRC:
        try:
            src = open(p).read()
        except OSError:
            bad.append(f"{os.path.relpath(p, root)} is missing"); continue
        code = "\n".join(l for l in src.splitlines() if not l.lstrip().startswith("#"))
        cmd = re.search(r"[\"'](?:terraform|tofu|pulumi|eksctl|doctl|aws|gcloud|az|ibmcloud|oci|linode-cli|vultr-cli)(?:\s|[\"'])", code)
        if cmd:
            bad.append(f"{os.path.relpath(p, root)} runs a cloud CLI: {cmd.group(0)}")
        for m in re.finditer(r"[\"']((?:[a-z0-9.-]+/)+[a-z0-9._-]+(?::[\w.-]+)?)[\"']", code):
            if re.search(r"(docker\.io|ghcr\.io|quay\.io|library|jenkins|gitlab|kindest)", m.group(1)) and "@sha256:" not in m.group(1):
                bad.append(f"{os.path.relpath(p, root)} names an image not pinned by digest: {m.group(1)}")

def judge(r, f, t):
    bad = []
    judge_release(r, bad); judge_weekly(f, bad); judge_tools(t, bad); judge_source(bad); judge_requirements(bad)
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
        if which == "rel_top":
            r["on"]["push"]["tags"] = ["x*"]
        elif which == "rel_tags":
            r["on"]["push"]["tags"] = ["v*", "!v*-rc.*"]
        elif which == "rel_defaults":
            r["defaults"] = {"run": {"working-directory": "harness"}}
        elif which == "fresh_defaults":
            f["defaults"] = {"run": {"working-directory": "harness"}}
        elif which == "rel_defaults_shell":
            r["defaults"] = {"run": {"shell": "pwsh"}}
        elif which == "rel_patchfailed":
            r["jobs"]["patch-failed"]["needs"] = [n for n in r["jobs"]["patch-failed"]["needs"] if n != "persona-uat"]
        else:
            {"rel": lambda: fn(r["jobs"]["persona-uat"]), "fresh": lambda: fn(f["jobs"]["persona-uat"]), "tools": lambda: fn(t)}[which]()
    except Exception as e:     # the real file lacks the thing being mutated: the real-file case above already failed
        result(False, f"mutation could not be applied ({name}): {type(e).__name__}: {e}"); return
    # round-trip through YAML text so the mutated document is valid YAML, not just a dict
    for doc in (r, f):
        yaml.safe_load(yaml.safe_dump(doc))
    if (r, f, t) == (R, F, T):
        result(False, f"mutation changed nothing ({name})"); return
    found = judge(r, f, t)
    result(any(expect in b for b in found), f"caught: {name} (reason: {expect!r})" + ("" if any(expect in b for b in found) else f"; saw {found}"))

def set_image(job, value):
    """replace the driver's whole --image argument (quoted or not, spaces inside allowed), whatever its formatting"""
    d = next(s for s in job["steps"] if "persona-uat.py" in str(s.get("run", "")))
    new, n = re.subn(r"--image\s+(\"[^\"]*\"|'[^']*'|\S+)", lambda m: "--image " + value, d["run"].replace("\\\n", " "), count=1)
    assert n == 1 and new != d["run"], "set_image changed nothing"
    d["run"] = new

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
mutate("rc job runs docker itself", "uses docker for more than", lambda j: j["steps"].insert(0, {"run": "docker run -d jenkins/jenkins:lts"}))
mutate("rc secrets set at job level", "set at job level", lambda j: j.setdefault("env", {}).update(ANTHROPIC_WORKSPACE_ID="${{ secrets.ANTHROPIC_WORKSPACE_ID }}"))
mutate("rc image argument is the raw digests JSON", "takes the image from something other than the chain's digests",
       lambda j: drv(j).update(run=re.sub(r"fromJSON\(needs\.image\.outputs\.digests\)\.production", "needs.image.outputs.digests", drv(j)["run"])))
mutate("rc job continue-on-error is an expression", "continue-on-error on the job", lambda j: j.update({"continue-on-error": "${{ true }}"}))
mutate("rc driver step uses a custom shell", "not plain bash", lambda j: drv(j).update({"shell": "bash {0}"}))
mutate("rc driver command is only echoed", "not exactly one bare driver command", lambda j: drv(j).update(run="echo " + drv(j)["run"].strip()))
mutate("rc owner model overridden in the command", "not exactly one bare driver command", lambda j: drv(j).update(run="PERSONA_UAT_MODEL=m-1 " + drv(j)["run"].strip()))
mutate("rc budget overridden in the command", "not exactly one bare driver command", lambda j: drv(j).update(run="PERSONA_UAT_TOKEN_BUDGET=1000 " + drv(j)["run"].strip()))
mutate("rc transcripts deleted before upload", "after the driver other than the transcript upload", lambda j: j["steps"].insert(j["steps"].index(up(j)), {"run": "rm -f persona-uat-out/*.transcript.txt"}))
def _upload_before_driver(j):
    u = up(j); j["steps"].remove(u); j["steps"].insert(j["steps"].index(drv(j)), u)
mutate("rc upload runs before the driver", "immediately after the driver", _upload_before_driver)
mutate("rc a setup step runs before the driver", "a run step before the driver other than", lambda j: j["steps"].insert(j["steps"].index(drv(j)), {"run": "echo hi"}))
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
mutate("rc image is a literal, not an expression", "takes the image from something other than the chain's digests",
       lambda j: set_image(j, "ghcr.io/fosterstack/cache@fromJSON(needs.image.outputs.digests).production"))
mutate("rc image is a fixed digest", "takes the image from something other than the chain's digests",
       lambda j: set_image(j, "ghcr.io/x/cache@sha256:" + "c" * 64))
mutate("rc gains a skipped dependency (decide)", "needs are not exactly image and promotion", lambda j: j.update(needs=list(j["needs"]) + ["decide"]))
mutate("rc upload may fail without failing the job", "without retaining its transcripts", lambda j: up(j).update({"continue-on-error": "true"}))
mutate("rc driver step carries an extra credential", "outside the contract", lambda j: drv(j).setdefault("env", {}).update(AWS_SECRET_ACCESS_KEY="x"))
mutate("rc identity step writes one file and exports another", "for THAT file",
       lambda j: next(s for s in j["steps"] if "github-script" in str(s.get("uses", ""))).setdefault("with", {}).update(script="const p='/a'; const q='/b'; fs.writeFileSync(p, token); core.exportVariable('ANTHROPIC_IDENTITY_TOKEN_FILE', q)"))
mutate("rc job has no checkout", "actions/checkout step(s) before the driver", lambda j: j.update(steps=[s for s in j["steps"] if "actions/checkout" not in str(s.get("uses", ""))]))
mutate("rc job checks out after the driver", "actions/checkout step(s) before the driver",
       lambda j: (lambda c: (j["steps"].remove(c), j["steps"].insert(j["steps"].index(drv(j)) + 1, c)))(next(s for s in j["steps"] if "actions/checkout" in str(s.get("uses", "")))))
mutate("release tags gain a negation", "push tags are not exactly", lambda j: None, "rel_tags")
mutate("rc job loses its SDK install", "expected exactly one hash-pinned SDK install", lambda j: j.update(steps=[s for s in j["steps"] if "pip install" not in str(s.get("run", ""))]))
mutate("rc SDK install runs before the checkout", "expected exactly one hash-pinned SDK install",
       lambda j: (lambda b: (j["steps"].remove(b), j["steps"].insert(0, b)))(next(s for s in j["steps"] if "pip install" in str(s.get("run", "")))))
mutate("patch-failed no longer names persona-uat", "patch-failed does not list persona-uat", lambda j: None, "rel_patchfailed")
def _tokvar(script):
    m = re.search(r"(?:const|let|var)\s+(\w+)\s*=\s*await\s+core\.getIDToken", script)
    return m.group(1) if m else "token"
def _id_step(j): return next(s for s in j["steps"] if "github-script" in str(s.get("uses", "")))
mutate("rc identity step prints the token", "logs the token",
       lambda j: _id_step(j)["with"].update(script=_id_step(j)["with"]["script"] + "\nconsole.log(" + _tokvar(_id_step(j)["with"]["script"]) + ")"))
mutate("rc identity step masks a literal, not the token", "mask THE TOKEN",
       lambda j: _id_step(j)["with"].update(script=re.sub(r"core\.setSecret\(\s*\w+\s*\)", "core.setSecret('x')", _id_step(j)["with"]["script"])))
mutate("rc driver's --publish is commented out", "is not run with --publish exactly once", lambda j: drv(j).update(run=drv(j)["run"].replace("--publish", "# --publish")))
mutate("rc driver step gets a working-directory", "a working-directory on the driver step", lambda j: drv(j).update({"working-directory": "harness"}))
mutate("rc job default working-directory", "a working-directory on the driver step", lambda j: j.update(defaults={"run": {"working-directory": "x"}}))
mutate("release.yml gets a workflow-level working-directory", "workflow-level working-directory", lambda j: None, which="rel_defaults")
mutate("go-freshness.yml gets a workflow-level working-directory", "workflow-level working-directory", lambda j: None, which="fresh_defaults")
mutate("release.yml gets a workflow-level default shell", "workflow-level default shell", lambda j: None, which="rel_defaults_shell")
mutate("rc driver gets a stray positional token", "tokens that are no option or option value", lambda j: drv(j).update(run=drv(j)["run"].rstrip() + " extra"))
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
mutate("weekly cron literal reformatted", "does not run only on the Monday cron", lambda j: j.update({"if": "${{ github.event.schedule == '436**1' }}"}), "fresh")
mutate("weekly resolver moved after the driver", "AFTER running the driver", lambda j: (lambda r: (j["steps"].remove(r), j["steps"].insert(j["steps"].index(drv(j)) + 1, r)))(next(s for s in j["steps"] if "gh release view" in str(s.get("run", "")))), "fresh")
mutate("weekly resolver uses a fixed tag variable", "does not resolve the LATEST release's image digest",
       lambda j: next(s for s in j["steps"] if "gh release view" in str(s.get("run", ""))).update(run='tag=v0.1.0; gh release view "$tag" --json tagName; d=$(docker buildx imagetools inspect "ghcr.io/x/cache:$tag"); echo "image=$d" >> "$GITHUB_OUTPUT"'), "fresh")
mutate("weekly resolver inspects an unrelated tag", "does not inspect the image of the release it just resolved",
       lambda j: next(s for s in j["steps"] if "gh release view" in str(s.get("run", ""))).update(run=re.sub(r"imagetools inspect \S+", "imagetools inspect ghcr.io/x/cache:latest", next(s for s in j["steps"] if "gh release view" in str(s.get("run", "")))["run"])), "fresh")
mutate("weekly driver image argument fully replaced", "does not hand the resolved latest-release image digest",
       lambda j: set_image(j, "ghcr.io/x/cache@sha256:" + "a" * 64), "fresh")
mutate("weekly image is the literal text, not an expression", "does not hand the resolved latest-release image digest",
       lambda j: set_image(j, "steps." + next(s for s in j["steps"] if "gh release view" in str(s.get("run", "")))["id"] + ".outputs.image"), "fresh")
def _docs_checkout(j): return next(s for s in j["steps"] if "actions/checkout" in str(s.get("uses", "")) and str((s.get("with", {}) or {}).get("path", "")) == "release-docs")
def _harness_checkout(j): return next(s for s in j["steps"] if "actions/checkout" in str(s.get("uses", "")) and str((s.get("with", {}) or {}).get("path", "")) == "harness")
def _resolver(j): return next(s for s in j["steps"] if "gh release view" in str(s.get("run", "")))
mutate("weekly docs checkout is of main, not the resolved tag", "checkout is not of the resolved release's tag", lambda j: _docs_checkout(j)["with"].pop("ref"), "fresh")
mutate("weekly harness checkout takes a ref (an old release has no driver)", "harness checkout must be today's main", lambda j: _harness_checkout(j)["with"].update(ref="v0.2.1"), "fresh")
mutate("weekly job has a single checkout", "expected exactly 2 actions/checkout", lambda j: j.update(steps=[s for s in j["steps"] if s is not _harness_checkout(j)]), "fresh")
mutate("weekly job gains needs (skipped on the Monday cron)", "has needs", lambda j: j.update(needs=["check"]), "fresh")
mutate("weekly resolver emits tag=main", "does not write tag=<release tag>",
       lambda j: _resolver(j).update(run=re.sub(r"(?m)^.*tag=.*GITHUB_OUTPUT.*$", 'echo "tag=main" >> "$GITHUB_OUTPUT"', _resolver(j)["run"])), "fresh")
mutate("weekly resolver inspects the v-prefixed image tag", "resolver failed against recording gh/docker",
       lambda j: _resolver(j).update(run=_resolver(j)["run"].replace("${tag#v}", "${tag}")), "fresh")
mutate("weekly resolver asks for the wrong digest format", "does not write tag=<release tag>",
       lambda j: _resolver(j).update(run=_resolver(j)["run"].replace("{{.Manifest.Digest}}", "{{.Name}}")), "fresh")
mutate("weekly resolver has no GH_REPO", "needs env GH_REPO", lambda j: _resolver(j)["env"].pop("GH_REPO"), "fresh")
mutate("weekly docs checkout of another repository", "checkout of another repository", lambda j: _docs_checkout(j)["with"].update(repository="evil/cache"), "fresh")
mutate("rc checkout takes ref main", "release-candidate checkout is not of the candidate commit", lambda j: next(s for s in j["steps"] if "actions/checkout" in str(s.get("uses", ""))).setdefault("with", {}).update(ref="main"))
mutate("rc checkout of another repository", "checkout of another repository", lambda j: next(s for s in j["steps"] if "actions/checkout" in str(s.get("uses", ""))).setdefault("with", {}).update(repository="evil/cache"))
mutate("rc driver step overrides the identity token file", "outside the contract", lambda j: drv(j).setdefault("env", {}).update(ANTHROPIC_IDENTITY_TOKEN_FILE="/missing"))
mutate("rc identity step never awaits the token", "does not mint (await)",
       lambda j: (lambda s_: s_["with"].update(script=s_["with"]["script"].replace("await core.getIDToken", "core.getIDToken")))(next(s for s in j["steps"] if "github-script" in str(s.get("uses", "")))))
mutate("rc SDK install without hashes", "a run step before the driver other than",
       lambda j: next(s for s in j["steps"] if "pip install" in str(s.get("run", ""))).update(run="python3 -m pip install anthropic"))
mutate("tools: all four point at one image", "not four distinct images", lambda t: t.update({k: t["shell"] for k in ("jenkins", "gitlab-runner", "kind")}), "tools")
mutate("tools: jenkins names another image", "does not name its own image", lambda t: t.update(jenkins=t["shell"]), "tools")
mutate("weekly job leaves the persona-uat environment", "does not run in the persona-uat environment", lambda j: j.pop("environment"), "fresh")
mutate("weekly resolver is conditional", "resolver step is conditional or non-fatal",
       lambda j: next(s for s in j["steps"] if "gh release view" in str(s.get("run", ""))).update({"if": "false"}), "fresh")
mutate("weekly resolver does not extract a digest", "does not extract the digest",
       lambda j: (lambda r: r.update(run=r["run"].replace(" --format '{{.Manifest.Digest}}'", "").replace(" --format \"{{.Manifest.Digest}}\"", "")))(next(s for s in j["steps"] if "gh release view" in str(s.get("run", "")))), "fresh")
mutate("weekly resolver emits an unrelated fixed digest", "built from the digest it inspected",
       lambda j: (lambda r: r.update(run=re.sub(r'image=[^\n]*>>', 'image=ghcr.io/x/cache@sha256:' + 'a' * 64 + ' >>', r["run"])))(next(s for s in j["steps"] if "gh release view" in str(s.get("run", "")))), "fresh")
mutate("rc driver is given a second --mode (last wins)", "--mode exactly once", lambda j: drv(j).update(run=drv(j)["run"].rstrip() + " --mode weekly"))
mutate("rc driver is given a second --image (last wins)", "--image exactly once", lambda j: drv(j).update(run=drv(j)["run"].rstrip() + " --image ghcr.io/x/cache@sha256:" + "b" * 64))
mutate("rc driver --repo points elsewhere", "--repo is not the docs checkout", lambda j: drv(j).update(run=re.sub(r"--repo\s+\S+", "--repo /tmp/empty", drv(j)["run"])))
mutate("rc owner variable is the literal text", "is not exactly vars.PERSONA_UAT_MODEL", lambda j: drv(j)["env"].update(PERSONA_UAT_MODEL="vars.PERSONA_UAT_MODEL"))
mutate("rc secret is the literal text", "is not exactly secrets.ANTHROPIC_WORKSPACE_ID", lambda j: drv(j)["env"].update(ANTHROPIC_WORKSPACE_ID="secrets.ANTHROPIC_WORKSPACE_ID"))
mutate("rc GH_TOKEN missing", "GH_TOKEN is not exactly github.token", lambda j: drv(j)["env"].pop("GH_TOKEN"))
mutate("rc identity step provisions cloud inside github-script", "runs a command or names a cloud CLI",
       lambda j: next(s for s in j["steps"] if "github-script" in str(s.get("uses", ""))).setdefault("with", {}).update(script="await exec.exec('aws', ['ec2','run-instances'])"))
mutate("rc identity step is conditional", "identity step has an if", lambda j: next(s for s in j["steps"] if "github-script" in str(s.get("uses", ""))).update({"if": "false"}))
mutate("rc identity step exports a path it never writes", "does not write the token to a file",
       lambda j: next(s for s in j["steps"] if "github-script" in str(s.get("uses", ""))).setdefault("with", {}).update(script="core.exportVariable('ANTHROPIC_IDENTITY_TOKEN_FILE', '/nonexistent')"))
mutate("release.yml loses its v* tag trigger", "push tags are not exactly", lambda j: None, "rel_top")
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
