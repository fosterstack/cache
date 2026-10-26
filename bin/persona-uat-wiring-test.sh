#!/usr/bin/env bash
# proves: REQ-UAT-001-AC1, REQ-UAT-001-AC2, REQ-UAT-001-AC3, REQ-UAT-001-AC4, REQ-UAT-001-AC5
# AC3's workflow-graph guard (no downstream job can open an issue) is NOT proven by these tests: three review rounds could not close it (advisor 0244, rule 4); the driver-level
# proof (the driver opens no issue and never calls gh) remains. Only the simple structural check stays: release.yml's patch-failed does not list persona-uat in needs.
# Where the persona UAT runs (owner ratified Oct 3 and Oct 4; point 9). The wiring is read from the PARSED workflows, never
# from substrings: a persona-uat job in the release chain that runs only for v*-rc.* tags, after the image and promotion,
# in the persona-uat environment, taking the image by the chain's digests, running the driver as a step that nothing can
# skip or make non-fatal, with the owner's model/budget variables and the model identity on THAT step, uploading the
# driver's output directory (transcripts and reports) even when personas fail; and a persona-uat job in the weekly
# workflow that runs only on its Monday cron, resolves the LATEST release's image digest, and runs the same driver with
# --publish. The pinned CI tools file (advisor 0207, delta 2) holds exactly nine entries, each by digest, distinct, and each naming its own OFFICIAL repository:
# cosign, gitlab-runner, gradle, jenkins, kind, kubectl, maven and the persona shell (the curl image); no driver, agent or provider source may run a
# privileged container (the kind cluster is created by the job's kind binary).
# MODEL IDS ARE SECRETS (advisor 0233, owner's rule): GitHub prints a step's `env:` values in the step header before its script runs, so a model id from `vars.*` would be
# public in the job log. PERSONA_UAT_MODEL and PERSONA_UAT_COMPLIANCE_MODEL therefore arrive on the DRIVER step as ${{ secrets.PERSONA_UAT_MODEL }} / ${{ secrets.PERSONA_UAT_COMPLIANCE_MODEL }}
# (masked automatically) and nowhere else; PERSONA_UAT_TOKEN_BUDGET stays ${{ vars.PERSONA_UAT_TOKEN_BUDGET }}. The judge rejects `vars.` for a model id, a literal model id, and a model
# id in any other step, job or workflow env or in any run text.
# Results stay private (amendment 0215): the persona jobs open no issue, upload ONLY the encrypted <persona>.cms files under ONE fixed artifact name that the local
# decrypt script (bin/persona-uat-decrypt.sh) downloads by that exact name, and a failed persona run fails the job without any job opening a public issue.
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
MODEL_SECRETS = ("PERSONA_UAT_MODEL", "PERSONA_UAT_COMPLIANCE_MODEL")       # secrets (masked), on the driver step only; the budget is the one variable

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

KIND_RUN = 'kind version || { echo "::error::PIPELINE, no kind"; exit 1; }'
def is_kind_run(run):
    """the ONLY accepted way to have `kind` in the job (amended Oct 24, rule 13 of the simplest-correct-form rules): the
    runner image's own kind, proved present by this one run step: it prints the version and fails with a labelled
    error"""
    return run.strip() == KIND_RUN

def crane_re(pre):
    """the ONLY accepted way to get `crane` onto the weekly job: the repo's own installer (version and sha256 pinned inside it), the tool the chain already pins for every digest read"""
    return re.compile(r"^(?:\./)?" + re.escape(pre) + r"bin/install-scanner\.sh crane$")

def judge_crane(name, steps, d, pre, bad):
    """the weekly job installs crane in ONE unconditional run step, after the root checkout (it provides bin/install-scanner.sh) and BEFORE the resolver that calls it"""
    cands = [(i, s) for i, s in enumerate(steps) if "run" in s and re.search(r"\bcrane\b", str(s["run"])) and "gh release view" not in str(s["run"])]
    good = [(i, s) for i, s in cands if crane_re(pre).match(str(s["run"]).strip())]
    if len(good) != 1 or len(cands) != 1:
        bad.append(f"{name}: the job must install crane with exactly one step `./{pre}bin/install-scanner.sh crane` (the chain's pinned tool for digest reads; no other crane download or install step); found {[str(s['run'])[:60] for _, s in cands]}")
        return
    i, s = good[0]
    res = next((k for k, x in enumerate(steps) if "gh release view" in str(x.get("run", ""))), None)
    cos = [(k, x) for k, x in enumerate(steps) if "actions/checkout" in str(x.get("uses", ""))]
    prov = next((k for k, x in cos if not str((x.get("with") or {}).get("path", ""))), None)
    if prov is None or i < prov:
        bad.append(f"{name}: the crane install step runs BEFORE the checkout that provides bin/install-scanner.sh (or there is none)")
    if res is None or i > res:
        bad.append(f"{name}: the crane install step runs AFTER the resolver that calls crane digest (or there is no resolver)")
    if s.get("if") is not None or not literal_false(s.get("continue-on-error")):
        bad.append(f"{name}: the crane install step is conditional or non-fatal: a job without crane must fail, never skip it")
    if str(s.get("shell", "bash")) != "bash" or s.get("working-directory") or s.get("env"):
        bad.append(f"{name}: the crane install step has a custom shell, working-directory or env")

def judge_install(name, steps, d, pre, bad):
    """the job checks the runner image's kind in ONE unconditional run step BEFORE the driver
    (no download, no install)"""
    di = steps.index(d)
    cands = [(i, s) for i, s in enumerate(steps) if "run" in s and re.search(r"\bkind\b|install-scanner", str(s["run"])) and not crane_re(pre).match(str(s["run"]).strip())]
    good = [(i, s) for i, s in cands if is_kind_run(str(s["run"]))]
    if len(good) != 1 or len(cands) != 1:
        found = [str(s["run"])[:60] for _, s in cands]
        bad.append(f"{name}: the job must check kind with exactly one step `{KIND_RUN}` "
                   f"(the runner image's kind; no kind download or install step); found {found}")
        return
    i, s = good[0]
    if i > di:
        bad.append(f"{name}: kind is checked AFTER the driver step: the driver would run without the check")
    if s.get("if") is not None or not literal_false(s.get("continue-on-error")):
        bad.append(f"{name}: the kind check step is conditional or non-fatal: a job without kind must fail")
    if str(s.get("shell", "bash")) != "bash" or s.get("working-directory") or s.get("env"):
        bad.append(f"{name}: the kind check step has a custom shell, working-directory or env")

import http.server, shutil, subprocess, tempfile, threading

# --- prerequisites of the job (defined BEFORE common(), which calls them; the complete-workflow control below runs them through judge()) ----------------
CRED_REF = re.compile(r"secrets\.|vars\.PERSONA_UAT|github\.token|ANTHROPIC_")
# The pip that runs the SDK install is itself pinned (REQ-SUP-001-AC13): one step, in the form the other workflows use, before the SDK install. This test
# recognizes the step by its shape only; WHICH requirement file it reads, and that the file holds the one hash-checked pip, is proved on the real tree by the
# pip-pin test (REQ-SUP-001-AC13), so the auditor's directory is not named here (REQ-AUD-18 AC1).
PIN_PIP_SHAPE = re.compile(r"python3 -m pip install --quiet --require-hashes --only-binary=:all: --break-system-packages -r \S+/pip-requirements\.txt\npython3 -m pip --version")
PIN_PIP_RUN = ("python3 -m pip install --quiet --require-hashes --only-binary=:all: --break-system-packages -r agent-dir/pip-requirements.txt\n"
               "python3 -m pip --version")   # the fixtures' step
def is_pin_pip(x):
    return PIN_PIP_SHAPE.fullmatch(str(x.get("run", "")).strip()) is not None

CLEANUP_RUN = 'python3 bin/persona-uat.py --remove-identity "${RUNNER_TEMP}/anthropic-identity-token" || rm -f "${RUNNER_TEMP}/anthropic-identity-token" "${RUNNER_TEMP}/anthropic-identity-token.tmp"'      # the job's last step (always()): the driver removes the token file under the same lock the refresher renews it under

STEP_ALLOW = {      # STRUCTURAL rule: a prerequisite step may carry only these keys (and, for checkout and the uploads, only these `with` options); anything else
                    # (if, continue-on-error, working-directory, shell, env, timeout-minutes, sparse-checkout, filter, fetch-depth, lfs, ...) can change what it does
    "checkout": ({"uses", "with", "name", "id"}, {"persist-credentials", "ref", "path"}),
    "install": ({"run", "name", "id"}, None), "sdk": ({"run", "name", "id"}, None), "pinpip": ({"run", "name", "id"}, None),
    "resolver": ({"run", "env", "name", "id"}, None),
    "identity": ({"uses", "with", "name", "id"}, {"script"}),
    "upload": ({"uses", "with", "if", "continue-on-error", "name", "id"}, {"name", "path", "if-no-files-found", "retention-days"}),
    "refresher": ({"run", "name", "id"}, None),
    "cleanup": ({"run", "name", "if"}, None),
}

def step_kind(x, pre, weekly):
    u, r = str(x.get("uses", "")), str(x.get("run", "")).strip()
    if "actions/checkout" in u: return "checkout"
    if "actions/github-script" in u: return "identity"
    if "upload-artifact" in u: return "upload"
    if "nohup" in r and "--mint-identity" in r: return "refresher"
    if r == CLEANUP_RUN: return "cleanup"
    if is_kind_run(r) or crane_re(pre).match(r): return "install"
    if PIN_PIP_SHAPE.fullmatch(r): return "pinpip"
    if "pip install" in r and "persona-uat-requirements" in r: return "sdk"
    if weekly and "gh release view" in r: return "resolver"
    return None

def judge_prereqs(name, job, steps, bad):
    weekly = name.startswith("weekly")
    pre = ""         # every harness command is a plain committed path (the pin checker reads only paths relative to the repository root): the root checkout is today's main in BOTH jobs
    ro = str(job.get("runs-on", ""))
    if not re.fullmatch(r"ubuntu-[0-9]{2}\.[0-9]{2}(-arm)?|ubuntu-latest", ro):
        bad.append(f"{name}: runs-on is {ro!r}, not an ubuntu runner (the host kubectl and the docker the personas use are the ubuntu image's)")
    if job.get("strategy") is not None:
        bad.append(f"{name}: the job has a strategy/matrix: the persona UAT would run more than once (or not at all)")
    for i, x in enumerate(steps):
        kind = step_kind(x, pre, weekly)
        if kind is None:
            continue
        keys, withs = STEP_ALLOW[kind]
        if set(x) - keys:
            bad.append(f"{name}: the {kind} step {i} carries keys outside its allowlist {sorted(keys)}: {sorted(set(x) - keys)}")
        if withs is not None and set(x.get("with") or {}) - withs:
            bad.append(f"{name}: the {kind} step {i} carries options outside its allowlist {sorted(withs)} (sparse-checkout, filter, fetch-depth, ... could drop docs/): {sorted(set(x.get('with') or {}) - withs)}")
        if kind in ("checkout", "sdk", "refresher") and (x.get("if") is not None or not literal_false(x.get("continue-on-error"))):
            bad.append(f"{name}: the {kind if kind != 'sdk' else 'SDK install'} step is conditional or non-fatal: the persona UAT could run without it")
        if kind != "upload" and kind != "resolver" and "env" in x:
            bad.append(f"{name}: the {kind} step has an env")
    # the checked-out tree must hold the public docs: the repository under test has them, and no checkout option may thin the tree
    if not (os.path.isdir(os.path.join(root, "docs")) and os.path.isfile(os.path.join(root, "README.md"))):
        bad.append(f"{name}: the repository has no docs/ and README.md for the personas to read")

# the persona jobs and the workflows that hold them carry NO env at the job or workflow scope: any key (BASH_ENV, BASH_FUNC_<name>%%, PATH, LD_PRELOAD, OPENSSL_CONF, a proxy, a
# harmless-looking name) would be inherited by every step, the resolver and the driver included, and a deny list cannot name them all. The real files have none.
def judge_shell_env(env, where, bad):
    if env:      # a mapping with any key, or an expression string
        bad.append(f"{where} must be empty: any variable set there is inherited by every step (the resolver and the driver included), and a list of bad names cannot be complete (BASH_ENV, BASH_FUNC_*, PATH, LD_*, a proxy, a CA bundle ...)")

def judge_workflow_env(doc, label, bad):
    """workflow-level `env` is inherited by every job and step: no credential, owner variable, model name or alias of one may be declared there"""
    judge_shell_env(doc.get("env"), f"{label} workflow-level env", bad)
    for k, v in (doc.get("env") or {}).items():
        if k in CREDS or k in VARS or k.startswith(("ANTHROPIC_", "AWS_", "ACTIONS_")) or CRED_REF.search(str(v)) or MODEL.search(str(v)) or MODEL.search(str(k)):
            bad.append(f"{label} declares {k} in a workflow-level env: it would be inherited by every step, not only the driver's")

def decrypt_text():
    try:
        return open(os.path.join(root, "bin/persona-uat-decrypt.sh")).read()
    except OSError:
        return None
DECRYPT_TEXT = decrypt_text()
SYN_DECRYPT = 'gh run download "$run" -R "$repo" -n persona-uat-encrypted --dir "$art"\n'

def judge_script_artifact(text, upload_name, name, bad):
    """the local decrypt script downloads the persona artifact by an EXACT name (a single -n); the upload must publish under that very name (when the script is not
    committed yet the synthetic default stands in for it, and the real-file case below stays red)"""
    t = SYN_DECRYPT if text is None else text
    code = "\n".join(l for l in t.replace("\\\n", " ").splitlines() if not l.lstrip().startswith("#"))      # no comments; continuations joined
    cmds = [l for l in code.splitlines() if re.search(r"\bgh\s+run\s+download\b", l)]
    if len(cmds) != 1:
        bad.append(f"{name}: the decrypt script must run `gh run download` exactly once (found {len(cmds)})"); return
    names = re.findall(r"(?:^|\s)(?:-n|--name)[ =]+[\"']?([A-Za-z0-9._-]+)", cmds[0])       # the -n of THAT command only
    if len(names) != 1:
        bad.append(f"{name}: the decrypt script must download the persona artifact with exactly ONE -n/--name on its `gh run download` command (found {names}): without -n gh downloads every artifact, nested")
    elif names[0] != upload_name:
        bad.append(f"{name}: the upload publishes the artifact as {upload_name!r} but the decrypt script downloads {names[0]!r}: the run could never be decrypted")

def common(name, job, bad):
    steps = job.get("steps", [])
    for si, st_ in enumerate(steps):
        if "${{" in str(st_.get("run", "")):
            bad.append(f"{name}: step {si} interpolates an expression into its run script (${{{{ }}}} inside run:): pass it through env: and quote the shell variable")
    weekly = name.startswith("weekly")
    pre = ""                                              # the harness is the ROOT checkout (today's main) in both jobs; the weekly job's released docs are under release-docs/
    repo_dir = "release-docs" if weekly else "."
    if not literal_false(job.get("continue-on-error")):
        bad.append(f"{name}: continue-on-error on the job lets a persona failure pass")
    if str(job.get("defaults", {}).get("run", {}).get("shell", "bash")) != "bash":
        bad.append(f"{name}: the job's default shell is not plain bash")
    for k in ("container", "services"):
        if k in job and not (k == "services" and name == "release persona-uat"):     # the rc job's one registry service is judged in judge_release
            bad.append(f"{name}: the job declares {k}: the CI tools run only inside the driver, by digest, never as job {k}")
    drivers = [s for s in steps if "persona-uat.py" in str(s.get("run", "")) and not re.search(r"--(?:mint|remove)-identity", str(s.get("run", "")))]
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
    for flag in ("--mode", "--image", "--repo", "--out", "--tools", "--agent", "--recipient"):
        if opts.count(flag) != 1:
            bad.append(f"{name}: the driver is not run with {flag} exactly once (found {opts.count(flag)}): the last occurrence would win")
    contract = {"--mode", "--image", "--repo", "--out", "--tools", "--agent", "--recipient"} | ({"--allow-listen"} if name == "release persona-uat" else set())
    if sorted(set(opts) - contract):
        bad.append(f"{name}: the driver is given options outside the contract (no --publish, no --gh: results stay private, no issue is opened): {sorted(set(opts) - contract)}")
    if name == "release persona-uat":     # the registry service listens on the runner's loopback; the driver's stray-listener guard must know that one port and no other
        ports = [argv[i + 1] for i, t in enumerate(argv[:-1]) if t == "--allow-listen"]
        if ports != ["5000"]:
            bad.append(f"{name}: the driver must be given --allow-listen 5000 exactly once and no other allowed listener (found {ports}): the registry's port is the one listener that may exist")
    first = next((i for i, t in enumerate(argv) if t == pre + "bin/persona-uat.py"), None)       # the EXACT script token (`python3 <pre>bin/persona-uat.py`), never a suffix such as .py.bak
    if first is None or first != 1 or argv[0] != "python3":
        bad.append(f"{name}: the driver command is not exactly `python3 {pre}bin/persona-uat.py ...` (the tested driver must be the one that runs)")
    positional = [] if first is None else [t for i, t in enumerate(argv[first + 1:], first + 1)
                                           if not t.startswith("--") and not argv[i - 1].startswith("--")]
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
    if optval("--recipient") != pre + "bin/persona-uat-recipient.pem":
        bad.append(f"{name}: --recipient is not {pre}bin/persona-uat-recipient.pem (the committed certificate the artifacts are encrypted to)")
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
    judge_shell_env(job.get("env"), f"{name}: the job-level env", bad)
    for k, v in (job.get("env") or {}).items():
        if CRED_REF.search(str(v)) or MODEL.search(str(v)):
            bad.append(f"{name}: the job-level env {k} carries a credential reference or a model name ({v!r}): every step would inherit it")
    for s in steps:
        if s is not d:
            for k, v in (s.get("env") or {}).items():
                if re.search(r"secrets\.|vars\.PERSONA_UAT|ANTHROPIC_", str(v)) or MODEL.search(str(v)) or (CRED_REF.search(str(v)) and not (k == "GH_TOKEN" and expr_is(v, "github.token") and "gh release view" in str(s.get("run", "")))):
                    bad.append(f"{name}: the env {k} of a step other than the driver carries a credential reference or a model name ({v!r})")
    env = d.get("env", {})
    extra_env = sorted(set(env) - set(VARS) - set(CREDS) - {"ANTHROPIC_IDENTITY_TOKEN_FILE", "PERSONA_UAT_IMAGE"})
    if extra_env:
        bad.append(f"{name}: the driver step carries environment outside the contract (the six secrets, the budget and the identity token file path only): {extra_env}")
    if not re.fullmatch(r"\$\{\{\s*runner\.temp\s*\}\}/anthropic-identity-token", str(env.get("ANTHROPIC_IDENTITY_TOKEN_FILE", ""))):
        bad.append(f"{name}: the driver step's ANTHROPIC_IDENTITY_TOKEN_FILE is not exactly ${{{{ runner.temp }}}}/anthropic-identity-token (the file the identity step writes and the refresher renews; it reaches the driver step only, never a later step)")
    for v in VARS:
        kind = "secrets" if v in MODEL_SECRETS else "vars"
        if not expr_is(env.get(v, ""), f"{kind}.{v}"):
            bad.append(f"{name}: {v} is not exactly {kind}.{v} on the driver step ({'the model id is a masked secret: a vars.* value would be printed in the step header' if kind == 'secrets' else 'the owner variable'})")
    if re.search(r"PERSONA_UAT_(COMPLIANCE_)?MODEL|secrets\.", run):
        bad.append(f"{name}: the driver's command text names a model id or a secret: they arrive only through the step's env")
    for s_ in steps:
        if s_ is not d and re.search(r"PERSONA_UAT_(COMPLIANCE_)?MODEL", json.dumps(s_)):
            bad.append(f"{name}: a step other than the driver names a model id (PERSONA_UAT_MODEL / PERSONA_UAT_COMPLIANCE_MODEL): the model ids reach the driver step's env only")
    if re.search(r"PERSONA_UAT_(COMPLIANCE_)?MODEL", json.dumps({k: v for k, v in job.items() if k != "steps"})):
        bad.append(f"{name}: the job (outside the driver step) names a model id: the model ids reach the driver step's env only")
    if "GH_TOKEN" in env or "GITHUB_TOKEN" in env:
        bad.append(f"{name}: the driver step carries a GitHub token: it makes no gh call and opens no issue (results stay private)")
    for c in CREDS:
        if not expr_is(env.get(c, ""), f"secrets.{c}"):
            bad.append(f"{name}: {c} is not exactly secrets.{c} on the driver step")
    before = steps[:steps.index(d)]
    if not any("getIDToken" in json.dumps(s) and "anthropic-identity-token" in json.dumps(s) for s in before):
        bad.append(f"{name}: no step before the driver mints the model identity token (OIDC, no keys) into RUNNER_TEMP/anthropic-identity-token")
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
            wm = re.search(r"fs\.writeFileSync\(\s*(\w+)\s*,\s*token\s*(?:,\s*\{[^}]*\}\s*)?\)", body)
            if not wm or not re.search(r"(?:const|let|var)\s+" + re.escape(wm.group(1)) + r"\s*=\s*process\.env\.RUNNER_TEMP\s*\+\s*['\"]/anthropic-identity-token['\"]", body):
                bad.append(f"{name}: the identity step does not write the token to a file, RUNNER_TEMP/anthropic-identity-token, which is the file the driver step reads")
            if "exportVariable" in body or re.search(r"\bset(Interval|Timeout)\b", body):
                bad.append(f"{name}: the identity step exports the token file's path to every later step or starts a timer: the path reaches the driver step's env only, and a timer inside github-script dies with the step (the refresher is its own detached process)")
    for s in steps:
        for k, v in (s.get("with") or {}).items():
            if k != "script" and CLOUD.search(str(v)):
                bad.append(f"{name}: a step input names a cloud CLI ({k})")
    for s_ in steps:
        blob = json.dumps(s_)
        if re.search(r"PRIVATE KEY|persona-uat\.key|-inkey|cms\s+-decrypt|PERSONA_UAT_(PRIVATE|KEY)|\.key\b", blob) or re.search(r"secrets\.(?!ANTHROPIC_(FEDERATION_RULE_ID|ORGANIZATION_ID|SERVICE_ACCOUNT_ID|WORKSPACE_ID)\b|PERSONA_UAT_(COMPLIANCE_)?MODEL\b)", blob):
            bad.append(f"{name}: a step writes or reads a private key or a secret that holds one (only the four ANTHROPIC_* identity secrets and the two model-id secrets may reach the job; the decryption key never touches CI)")
    ALLOWED = ("actions/checkout", "actions/github-script", "actions/upload-artifact") + (("actions/download-artifact",) if name == "release persona-uat" else ())   # the rc job downloads Build's images artifact
    for s in steps:
        u = str(s.get("uses", ""))
        if u and not PIN_USES.match(u):
            bad.append(f"{name}: action {u} is not pinned to a commit digest")
        if u and u.split("@")[0] not in ALLOWED:
            bad.append(f"{name}: action {u.split('@')[0]} is not on the persona job's allowlist {ALLOWED}")
        if re.search(r"\bdocker\b|\bbuildx\b", str(s.get("run", ""))):
            bad.append(f"{name}: a run step uses docker or buildx: containers are started only by the driver, by pinned digest; every digest read uses the chain's pinned `crane digest` (rule 61: no buildx anywhere)")
    for s in steps:
        if "actions/checkout" in str(s.get("uses", "")) and str(s.get("with", {}).get("persist-credentials", "")).lower() != "false":
            bad.append(f"{name}: checkout keeps the job's credentials (persist-credentials must be false)")
    di = steps.index(d)
    for i, s in enumerate(steps):
        if s is d: continue
        isrun = "run" in s
        is_resolver = isrun and "gh release view" in str(s.get("run", "")) and name.startswith("weekly")
        kind_run_text = str(s.get("run", ""))
        is_install = isrun and (is_kind_run(kind_run_text) or crane_re(pre).match(kind_run_text.strip()) is not None)
        is_boot = isrun and re.fullmatch(r"python3 -m pip install --quiet --break-system-packages --require-hashes --only-binary=:all: -r " + re.escape(pre) + r"bin/persona-uat-requirements\.txt\s*",
                                         str(s.get("run", "")).strip()) is not None
        is_pin = isrun and is_pin_pip(s)
        is_load = isrun and name == "release persona-uat" and "crane push" in str(s.get("run", ""))      # judged in judge_rc_registry
        is_cleanup = step_kind(s, pre, name.startswith("weekly")) == "cleanup"
        is_refresher = step_kind(s, pre, name.startswith("weekly")) == "refresher"
        if i > di and "upload-artifact" not in str(s.get("uses", "")) and not is_cleanup:
            bad.append(f"{name}: a step after the driver other than the transcript upload and the identity token cleanup could alter the files before upload")
        if i < di and isrun and not is_resolver and not is_boot and not is_install and not is_refresher and not is_pin and not is_load:
            bad.append(f"{name}: a run step before the driver other than the latest-release resolver, "
                       f"the one hash-pinned SDK install and the one kind check (it could change what the driver sees)")
    judge_install(name, steps, d, pre, bad)
    if weekly:
        judge_crane(name, steps, d, pre, bad)
    judge_prereqs(name, job, steps, bad)
    judge_refresher(name, steps, d, bad)
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
        paths = [str((c.get("with", {}) or {}).get("path", "")) for c in cos]
        if paths != ["", "release-docs"]:
            bad.append(f"{name}: the two checkouts must be, in this order, the repository ROOT (no path: today's tested driver) and path: release-docs (the released docs): {paths}")
        for c in cos:
            if not str((c.get("with", {}) or {}).get("path", "")) and ("ref" in (c.get("with", {}) or {}) or "repository" in (c.get("with", {}) or {})):
                bad.append(f"{name}: the root checkout must be today's main (no ref): an old release has no driver")
    boots = [s for s in steps if re.fullmatch(r"python3 -m pip install --quiet --break-system-packages --require-hashes --only-binary=:all: -r " + re.escape(pre) + r"bin/persona-uat-requirements\.txt\s*", str(s.get("run", "")).strip())]
    harness_co = [c for c in cos if not str((c.get("with", {}) or {}).get("path", ""))]
    if len(boots) != 1 or (harness_co and steps.index(boots[0]) < steps.index(harness_co[0])) or steps.index(boots[0]) > di:
        bad.append(f"{name}: expected exactly one hash-pinned SDK install, after the harness checkout and before the driver")
    pins = [s for s in steps if is_pin_pip(s)]
    if len(pins) != 1 or (len(boots) == 1 and steps.index(pins[0]) > steps.index(boots[0])):
        bad.append(f"{name}: expected exactly one pinned-pip step (the hash-checked pip from the pinned requirement file, then its version logged), before the SDK install")
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
        if not outdir or path != outdir.group(1).strip("\"'").rstrip("/") + "/*.cms":
            bad.append(f"{name}: the upload path {path!r} is not exactly <the driver's --out directory>/*.cms: only the encrypted artifacts may ever be uploaded, never a plaintext file")
        un = u.get("with", {}).get("name")
        if un is None:
            bad.append(f"{name}: the upload has no artifact name (the action's default is 'artifact', which the decrypt script does not download): set name: <the script's name>")
        else:
            un = str(un)
            if "${{" in un or not re.fullmatch(r"persona-uat-[a-z0-9-]+", un):
                bad.append(f"{name}: the artifact name {un!r} is not a fixed literal persona-uat-<words> (artifact names are public: they carry no result)")
            judge_script_artifact(DECRYPT_TEXT, un, name, bad)
        if str(u.get("with", {}).get("if-no-files-found", "")) != "error":
            bad.append(f"{name}: the upload must fail on missing files (if-no-files-found: error)")
    for s in steps:
        if s is not d and s not in ups and str(s.get("run", "")).strip() != CLEANUP_RUN and "if" in s and "persona" in json.dumps(s).lower():
            bad.append(f"{name}: a persona step has an if: {s.get('if')!r}")
    return d

def run_resolver(script):
    """EXECUTE the weekly resolver against recording gh/crane stubs (docker fails): it must ask gh for the latest release's tag in THIS repository (GH_REPO),
    read the digest of <registry>/<owner>/cache:<tag without the leading v> (the published image tags are unprefixed) with `crane digest`, and
    write tag=<the release tag, with its v> and image=<registry>/<owner>/cache@<that digest> to GITHUB_OUTPUT."""
    import subprocess
    out = []
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(d + "/bin")
        open(d + "/bin/gh", "w").write("#!/bin/sh\n[ -n \"$GH_REPO\" ] || { echo 'no repo' >&2; exit 1; }\n"
                                       "echo \"gh $*\" >> \"$REC\"\n"
                                       "case \"$*\" in 'release view --json tagName -q .tagName'|'release view --json tagName --jq .tagName') echo v0.2.1;; *) echo \"unexpected gh call: $*\" >&2; exit 1;; esac\n")
        open(d + "/bin/crane", "w").write("#!/bin/sh\necho \"crane $*\" >> \"$REC\"\n"
                                          "[ \"$1\" = 'digest' ] && [ $# -eq 2 ] || { echo 'unexpected crane call' >&2; exit 1; }\n"
                                          "[ \"$2\" = 'ghcr.io/own/cache:0.2.1' ] || { echo \"wrong image reference: $2\" >&2; exit 1; }\n"
                                          "echo sha256:" + "d" * 64 + "\n")
        open(d + "/bin/docker", "w").write("#!/bin/sh\necho 'docker is not used by the resolver' >&2\nexit 1\n")
        for f in ("gh", "crane", "docker"):
            os.chmod(d + "/bin/" + f, 0o755)
        open(d + "/script.sh", "w").write(script)
        env = {"PATH": d + "/bin:" + os.environ["PATH"], "GH_REPO": "own/cache", "REGISTRY_OWNER": "own", "GITHUB_OUTPUT": d + "/out", "REC": d + "/rec", "HOME": d}
        open(d + "/out", "w").close(); open(d + "/rec", "w").close()
        r = subprocess.run(["bash", "-e", d + "/script.sh"], env=env, capture_output=True, text=True)
        outs = open(d + "/out").read()
        if r.returncode != 0:
            out.append("weekly persona-uat's resolver failed against recording gh/crane (wrong repository, wrong image reference, or a bad call): " + r.stderr.strip()[:200])
        elif "tag=v0.2.1" not in outs.splitlines() or ("image=ghcr.io/own/cache@sha256:" + "d" * 64) not in outs.splitlines():
            out.append("weekly persona-uat's resolver does not write tag=<release tag> and image=<registry>/<owner>/cache@<inspected digest> to GITHUB_OUTPUT: " + repr(outs))
    return out

CLAIM_ALLOWLIST = ["sub", "aud", "ref", "job_workflow_ref", "environment", "repository", "repository_owner_id", "event_name", "iss"]

def run_identity(step):
    """EXECUTE the identity step's script in node against a fake core and a capturing console, twice: with a JWT-shaped token (carrying claims that are NOT on the allowlist and a
    signature) and with a token that cannot be decoded. The token is minted (awaited), the TOKEN ITSELF is registered for masking, written to RUNNER_TEMP/anthropic-identity-token
    with mode 0600, nothing is exported to later steps and no timer is started; and the job log gets exactly ONE line of non-secret claims (the allowlist, nothing else: never the
    token, its signature or any other claim), and a decode failure only warns."""
    import subprocess, shutil
    if not shutil.which("node"):
        return ["node is required to execute the identity step's script (the proof must not be skipped)"]
    body = str((step.get("with", {}) or {}).get("script", ""))
    probs = []
    for mode in ("jwt", "bad"):
        with tempfile.TemporaryDirectory() as d:
            open(d + "/s.js", "w").write(body)
            open(d + "/run.js", "w").write("""
const fs = require('fs'); const body = fs.readFileSync(process.argv[2], 'utf8');
const calls = {exported: {}, masked: [], logs: [], timers: 0};
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const PAYLOAD = {sub: 'repo:o/r:environment:persona-uat', aud: 'https://api.anthropic.com', ref: 'refs/tags/v1.0.0-rc.1', job_workflow_ref: 'o/r/.github/workflows/release.yml@refs/tags/v1.0.0-rc.1',
                 environment: 'persona-uat', repository: 'o/r', repository_owner_id: '42', event_name: 'push', iss: 'https://token.actions.githubusercontent.com',
                 jti: 'SECRET-JTI', actor: 'SECRET-ACTOR', sha: 'SECRET-SHA', run_id: 'SECRET-RUN'};
const TOK = process.argv[4] === 'bad' ? 'not-a-jwt-SECRETTOKEN' : b64({alg: 'RS256'}) + '.' + b64(PAYLOAD) + '.SIGNATURESECRET';
const core = { getIDToken: (aud) => new Promise((res) => setTimeout(() => res(TOK), 5)), setSecret: (t) => calls.masked.push(t),
               exportVariable: (k, v) => { calls.exported[k] = v; }, setFailed: () => {}, info: (m) => calls.logs.push(String(m)), debug: (m) => calls.logs.push(String(m)),
               warning: (m) => calls.logs.push('WARNING ' + String(m)) };
const cons = { log: (...a) => calls.logs.push(a.join(' ')), info: (...a) => calls.logs.push(a.join(' ')), warn: (...a) => calls.logs.push(a.join(' ')), error: (...a) => calls.logs.push(a.join(' ')) };
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const f = process.env.RUNNER_TEMP + '/anthropic-identity-token';
const read = (p) => { try { return fs.readFileSync(p, 'utf8'); } catch (e) { return null; } };
const mode = (p) => { try { return (fs.statSync(p).mode & 0o777).toString(8); } catch (e) { return null; } };
new AsyncFunction('core', 'require', 'process', 'console', 'setInterval', 'setTimeout', body)(core, require, process, cons, () => { calls.timers++; return {unref() {}}; }, () => { calls.timers++; return {unref() {}}; }).then(() => {
  fs.writeFileSync(process.argv[3], JSON.stringify({token: TOK, payload: PAYLOAD, content: read(f), mode: mode(f), masked: calls.masked, exported: calls.exported, timers: calls.timers, logs: calls.logs}));
}).catch((e) => fs.writeFileSync(process.argv[3], JSON.stringify({error: String(e), token: TOK, logs: calls.logs})));
""")
            env = dict(os.environ, RUNNER_TEMP=d)
            subprocess.run(["node", d + "/run.js", d + "/s.js", d + "/res.json", mode], env=env, capture_output=True, text=True)
            try:
                res = json.load(open(d + "/res.json"))
            except Exception:
                return ["the identity step's script could not be executed"]
        tok = res.get("token", "")
        logs = res.get("logs", [])
        if res.get("error"):
            if mode == "jwt":
                return ["the identity step does not mint (await), mask THE TOKEN and write it to RUNNER_TEMP/anthropic-identity-token: %s" % res.get("error")[:120]]
            probs.append("the identity step throws when the token cannot be decoded (a decode failure may only warn): %s" % res.get("error")[:120])
            continue
        if res.get("content") != tok or tok not in (res.get("masked") or []):
            return [f"the identity step does not mint (await), mask THE TOKEN and write it to RUNNER_TEMP/anthropic-identity-token: {res}"]
        sig = tok.split(".")[-1]
        if any(tok in l or (mode == "jwt" and (sig in l or tok.split(".")[1] in l)) for l in logs):
            return ["the identity step logs the token"]
        if mode == "jwt":
            lines = [l for l in logs if l.startswith("OIDC identity claims (federation-rule inputs): ")]
            if len(lines) != 1:
                probs.append(f"the identity step does not print the allowlisted non-secret token claims exactly once (found {len(lines)}): a token-exchange 401 is undiagnosable without them")
            else:
                try:
                    claims = json.loads(lines[0].split(": ", 1)[1])
                except ValueError:
                    claims = None
                if claims is None or sorted(claims) != sorted(CLAIM_ALLOWLIST) or any(claims[k] != res["payload"][k] for k in CLAIM_ALLOWLIST):
                    probs.append(f"the identity step's claims line is not exactly the allowlist {CLAIM_ALLOWLIST} with their values: {lines[0][:200]}")
            if any(w in l for l in logs for w in ("SECRET-JTI", "SECRET-ACTOR", "SECRET-SHA", "SECRET-RUN", "SIGNATURESECRET")):
                probs.append("the identity step prints a claim or part of the token that is not on the allowlist")
            if res.get("mode") != "600":
                probs.append(f"the identity token file is created with mode {res.get('mode')}, not 0600 (it is a credential: the owner only)")
            if res.get("exported") or res.get("timers"):
                probs.append(f"the identity step exports {sorted(res.get('exported') or {})} or starts a timer ({res.get('timers')}): the path reaches the driver step's env only, and a timer dies with the github-script step")
        else:
            if not [l for l in logs if l.startswith("WARNING ")] or any("OIDC identity claims" in l for l in logs):
                probs.append("a token that cannot be decoded must produce a warning and no claims line")
    return probs

def judge_refresher(name, steps, d, bad):
    """the federated assertion lives about five minutes and a persona job runs up to two hours, every model call a new process. The refresher is its OWN step that starts a
    DETACHED process (nohup, output redirected, disowned) which re-mints from the runner's OIDC endpoint into the 0600 token file until the file is removed (the always() cleanup
    step) - after the identity step wrote the file, before the driver. The script body is EXECUTED (run_refresher), not read."""
    refs = [(i, x) for i, x in enumerate(steps) if step_kind(x, "", name.startswith("weekly")) == "refresher"]
    if len(refs) != 1:
        bad.append(f"{name}: expected exactly one identity refresher step (a detached process that re-mints the token), found {len(refs)}"); return
    i, x = refs[0]
    ids = [k for k, y in enumerate(steps) if "actions/github-script" in str(y.get("uses", "")) and "getIDToken" in json.dumps(y)]
    if not ids or i < ids[0]:
        bad.append(f"{name}: the identity refresher runs BEFORE the identity step wrote the token file (it must come after the mint and before the driver)")
    if i > steps.index(d):
        bad.append(f"{name}: the identity refresher runs after the driver")
    cl = [y for y in steps if step_kind(y, "", name.startswith("weekly")) == "cleanup"]
    bad.extend(f"{name}: {p}" for p in run_refresher(str(x.get("run", "")), str(cl[0].get("run", "")) if len(cl) == 1 else CLEANUP_RUN))
    if len(cl) != 1 or steps[-1] is not cl[0] or norm(cl[0].get("if", "")) != "always()":
        bad.append(f"{name}: the job must end with exactly one `if: always()` step that removes RUNNER_TEMP/anthropic-identity-token (the token file is deleted at the end)")

_REFRESH_CACHE = {}

def run_refresher(script, cleanup):
    if (script, cleanup) not in _REFRESH_CACHE:         # most mutations leave the refresher untouched: execute each distinct body once
        _REFRESH_CACHE[(script, cleanup)] = _run_refresher(script, cleanup)
    return list(_REFRESH_CACHE[(script, cleanup)])

def _run_refresher(script, cleanup):
    """RUN the refresher step's body under bash with a FAKE token source (a local server answering the runner's OIDC request), a sub-second interval and a pre-seeded STALE token
    file: the step returns promptly although a child is left behind (stdout is a pipe: a child that kept it open would block it), the child OUTLIVES its parent and replaces the stale
    file, keeps replacing it (a tampered/stale file is overwritten again), the file stays mode 0600, a missing token file is refused, and removing the file ends the loop without
    recreating it. The default interval is at most five minutes."""
    import subprocess, threading, time, http.server, signal
    probs = []
    m = re.search(r"PERSONA_UAT_REFRESH_SECONDS:-([0-9]+)", script)
    if not m or not 10 <= int(m.group(1)) <= 300:
        probs.append("the identity refresher's default interval is not between 10 seconds and five minutes (an assertion expires after about five)")
    if not re.search(r'python3 bin/persona-uat\.py --mint-identity "\$f" \|\| \{ \[ "\$\?" -eq 3 \] && break; continue; \}', script) or re.search(r"\bcurl\b|\bwget\b|python3? -c", script):
        probs.append("the identity refresher's token fetch is not the driver's committed --mint-identity mode (no other downloader and no inline python -c): the pin checker reads no inline code and a stalled request must not stop the refreshing")
    state = {"n": 0, "auth": [], "inflight": 0}
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            state["auth"].append((self.headers.get("Authorization"), self.path))
            if self.headers.get("Authorization") != "bearer REQ-TOKEN" or "audience=https://api.anthropic.com" not in self.path:
                self.send_response(403); self.send_header("Content-Length", "0"); self.end_headers(); return
            state["inflight"] += 1
            time.sleep(0.6)            # a request in flight: the file can be removed while the refresher waits for its answer
            state["n"] += 1
            b = json.dumps({"value": "FIXTURE-REFRESH-%d" % state["n"]}).encode()
            self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    with tempfile.TemporaryDirectory() as d:
        f = os.path.join(d, "anthropic-identity-token")
        env = dict(os.environ, RUNNER_TEMP=d, ACTIONS_ID_TOKEN_REQUEST_URL="http://127.0.0.1:%d/token?api-version=2.0" % srv.server_address[1],
                   ACTIONS_ID_TOKEN_REQUEST_TOKEN="REQ-TOKEN", PERSONA_UAT_REFRESH_SECONDS="0.3")
        # a refusal: the file does not exist yet
        r0 = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, timeout=30, cwd=root)
        if r0.returncode == 0:
            probs.append("the identity refresher starts although the token file does not exist yet (the step must fail: the mint comes first)")
        with open(f, "w") as fh:
            fh.write("STALE-0")
        os.chmod(f, 0o600)
        t0 = time.time()
        p = subprocess.Popen(["bash", "-c", script], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, text=True, cwd=root)
        try:
            p.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            probs.append("the identity refresher step does not return: the detached process keeps the step's output open (redirect it) or runs in the foreground")
            try: os.killpg(p.pid, signal.SIGKILL)
            except OSError: pass
            srv.shutdown(); return probs
        if p.returncode != 0:
            probs.append(f"the identity refresher step failed (exit {p.returncode}) with a token file present")
        read = lambda: open(f).read() if os.path.exists(f) else None
        def wait_for(pred, secs=12):
            end = time.time() + secs
            while time.time() < end:
                v = read()
                if pred(v): return v
                time.sleep(0.2)
            return read()
        v1 = wait_for(lambda v: v and v.startswith("FIXTURE-REFRESH-"))
        if not (v1 and v1.startswith("FIXTURE-REFRESH-")):
            probs.append(f"the detached refresher did not replace the stale token file after its parent step exited (the process dies with its step, or writes elsewhere): {v1!r}")
        else:
            v2 = wait_for(lambda v: v and v != v1)
            if v2 == v1:
                probs.append("the detached refresher re-minted only once: it must keep renewing the file until the job ends")
            if oct(os.stat(f).st_mode & 0o777) != "0o600":
                probs.append(f"the refreshed token file has mode {oct(os.stat(f).st_mode & 0o777)}, not 0600")
            with open(f, "w") as fh:
                fh.write("STALE-AGAIN")
            v3 = wait_for(lambda v: v and v != "STALE-AGAIN")
            if v3 == "STALE-AGAIN":
                probs.append("a stale token file was not replaced by the refresher")
            if not [a for a in state["auth"] if a[0] == "bearer REQ-TOKEN"]:
                probs.append("the refresher never presented the runner's request token to the OIDC endpoint")
        end = time.time() + 6
        seen = state["inflight"]
        while time.time() < end and state["inflight"] == seen:      # a fetch is IN FLIGHT: remove the file now (the always() cleanup), the refresher must not write it back
            time.sleep(0.05)
        cr = subprocess.run(["bash", "-c", cleanup], env=env, capture_output=True, text=True, timeout=30, cwd=root)       # the job's always() step, while the refresher waits for its answer
        if cr.returncode != 0:
            probs.append(f"the job's cleanup step failed (exit {cr.returncode}) with a fetch in flight: {cr.stderr.strip()[:120]}")
        time.sleep(2.2)
        left = sorted(x for x in os.listdir(d) if x.startswith("anthropic-identity-token") and not x.endswith(".lock"))
        if left:
            probs.append(f"the token file or a temporary copy is still there after the cleanup step ran during a fetch (the refresher recreated it, or left it): {left}")
        try: os.killpg(p.pid, signal.SIGKILL)
        except OSError: pass
    srv.shutdown()
    return probs

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

def mode_value(run):
    """the value of the driver's --mode option, parsed (comments dropped, continuations joined); None unless exactly one"""
    import shlex
    try:
        argv = shlex.split(str(run).replace("\\\n", " "), comments=True)
    except ValueError:
        return None
    vals = [argv[i + 1] for i, t in enumerate(argv[:-1]) if t == "--mode"] + [t.split("=", 1)[1] for t in argv if t.startswith("--mode=")]
    return vals[0] if len(vals) == 1 else None

GATE = "vars.PERSONA_UAT_ENABLED=='true'"
# the rc job's load step, exactly (comments and blank lines dropped): a closed grammar, so a disabled or weakened digest check cannot pass (review of #428 round 1)
LOAD_RUN_EXPECTED = ('set -euo pipefail\nwant=$(jq -er \'.["image-production"]\' <<<"$DIGESTS")\ncrane push candidate/images/production localhost:5000/cache:rc\n'
                     'got=$(crane digest localhost:5000/cache:rc)\n[ "$got" = "$want" ] || { echo "::error::the pushed digest ${got} is not the one Build attested (${want})"; exit 1; }')

def _atom(a, ctx):
    """one atom of a job `if:` conjunction, evaluated on a context {vars, schedule, ref, ref_name}. The model is GitHub's own: `==` on strings IGNORES CASE, so 'true' and
    'TRUE' are both on. Enabling the personas by a differently cased value is the owner's act and is accepted; unset, empty, 'false' and '1' are off."""
    if re.fullmatch(r"vars\.PERSONA_UAT_ENABLED=='true'", a):
        return str(ctx["vars"].get("PERSONA_UAT_ENABLED", "")).lower() == "true"
    if a == "!inputs.dry-run":
        return not ctx.get("dry_run")
    m = re.fullmatch(r"github\.event\.schedule=='([^']*)'", a)
    if m: return ctx.get("schedule") == m.group(1)
    m = re.fullmatch(r"startsWith\(github\.ref,'([^']*)'\)", a)
    if m: return str(ctx.get("ref", "")).startswith(m.group(1))
    m = re.fullmatch(r"contains\(github\.ref_name,'([^']*)'\)", a)
    if m: return m.group(1) in str(ctx.get("ref_name", ""))
    raise ValueError("unknown atom " + a)

def job_runs(j, ctx):
    """True when the job's `if:` (a conjunction of known atoms) holds in ctx"""
    return all(_atom(a, ctx) for a in norm(j.get("if", "true")).split("&&"))

def judge_gate_others(name, wf, bad):
    """no job other than persona-uat enters the persona-uat environment or mints/uses the model identity token (also when the workflow has no persona-uat job at all)"""
    for jn, oj in (wf.get("jobs") or {}).items():
        if jn == "persona-uat":
            continue
        dumped = json.dumps(oj)
        if "persona-uat" in str(oj.get("environment", "")) or "api.anthropic.com" in dumped or "ANTHROPIC_IDENTITY_TOKEN" in dumped:
            bad.append(f"{name} persona-uat gate: job {jn} enters the persona-uat environment or mints/uses the model identity token outside the gated job")

def judge_gate(name, wf, j, bad):
    """the PERSONA_UAT_ENABLED gate (owner): the job runs only for the exact string 'true' (unset = off), on every trigger, and nothing mints a token or enters the persona-uat
    environment when it is off: the condition is the JOB's own `if:`, and no other job of the workflow names the environment, mints an identity token or holds id-token: write"""
    if name == "release":
        trig = {"tag push": {"ref": "refs/tags/v1.2.3-rc.1", "ref_name": "v1.2.3-rc.1"}, "workflow_dispatch": {"ref": "refs/heads/main", "ref_name": "main"}}
    else:
        trig = {"schedule": {"schedule": "43 6 * * 1", "ref": "refs/heads/main", "ref_name": "main"}, "workflow_dispatch": {"ref": "refs/heads/main", "ref_name": "main"}}
    try:
        for tn, base in trig.items():
            trigger_ok = tn in ("tag push", "schedule")           # a dispatch never satisfies a trigger conjunct; the gate is a separate conjunct that no trigger overrides
            for label, v in (("unset", None), ("empty", ""), ("false", "false"), ("TRUE", "TRUE"), ("True", "True"), ("1", "1"), ("true", "true"), (" true", " true"), ("yes", "yes")):
                ctx = dict(base, vars={} if v is None else {"PERSONA_UAT_ENABLED": v})
                got, want = job_runs(j, ctx), (str(v).lower() == "true" and trigger_ok)
                if got != want:
                    bad.append(f"{name} persona-uat gate: on {tn} with PERSONA_UAT_ENABLED {label} the job {'runs' if got else 'is off'}, expected {'on' if want else 'off'}")
        if name == "release":
            dry = {"ref": "refs/tags/v1.2.3-rc.1", "ref_name": "v1.2.3-rc.1", "dry_run": True, "vars": {"PERSONA_UAT_ENABLED": "true"}}
            if job_runs(j, dry):
                bad.append("release persona-uat gate: a dry run on an rc tag with the gate on runs the job (an rc dry run publishes nothing and must not enter the persona-uat environment)")
            final = {"ref": "refs/tags/v1.2.3", "ref_name": "v1.2.3", "vars": {"PERSONA_UAT_ENABLED": "true"}}
            if job_runs(j, final):
                bad.append("release persona-uat gate: a final tag with the gate on runs the job (only a release candidate does)")
    except ValueError as e:
        bad.append(f"{name} persona-uat gate: the job's if has an expression this judge cannot evaluate ({e})")
    if not norm(j.get("if", "")).startswith(GATE + "&&"):
        bad.append(f"{name} persona-uat gate: the gate is not the job-level `if:` (it must be vars.PERSONA_UAT_ENABLED == 'true' on the job itself)")
    for sid, s_ in enumerate(j.get("steps", [])):
        if "PERSONA_UAT_ENABLED" in json.dumps(s_):
            bad.append(f"{name} persona-uat gate: step {sid} tests the gate: a step-level gate would let the job (and its environment) start first")
    judge_gate_others(name, wf, bad)

def judge_release(r, bad):
    workflow_defaults(r, "release.yml", bad)
    judge_workflow_env(r, "release.yml", bad)
    push = (r.get("on", {}).get("push", {}) or {}) if isinstance(r.get("on"), dict) else {}
    tags = push.get("tags", [])
    if (tags if isinstance(tags, list) else [tags]) != ["v*"] or "tags-ignore" in push:
        bad.append("release.yml's push tags are not exactly ['v*'] (a negation or tags-ignore could disable the release-candidate trigger)")
    pf = r.get("jobs", {}).get("patch-failed", {}) or {}
    pfn = pf.get("needs", [])
    if "persona-uat" in ([pfn] if isinstance(pfn, str) else pfn):
        bad.append("release.yml's patch-failed lists persona-uat in needs: a failed persona run would then open a public issue (results stay private: it only fails the job)")
    j = r.get("jobs", {}).get("persona-uat")
    if not j:
        bad.append("release.yml has no persona-uat job: the release candidate's persona run (REQ-UAT-001-AC1) is missing")
        judge_gate_others("release", r, bad)
        return
    d = common("release persona-uat", j, bad)
    for s_ in j.get("steps", []):
        if "actions/github-script" in str(s_.get("uses", "")):
            bad.extend(run_identity(s_))
    needs = j.get("needs", [])
    needs = [needs] if isinstance(needs, str) else needs
    if sorted(needs) != ["build"]:
        bad.append(f"release persona-uat's needs are not exactly build (it tests the candidate Build made; it never waits for, or runs after, a stage that publishes): {sorted(needs)}")
    if norm(j.get("if", "")) != GATE + "&&startsWith(github.ref,'refs/tags/v')&&contains(github.ref_name,'-rc')&&!inputs.dry-run":
        bad.append(f"release persona-uat does not run only for a release-candidate tag, outside a dry run, behind the PERSONA_UAT_ENABLED gate (if: {j.get('if')!r})")
    judge_gate("release", r, j, bad)
    env = j.get("environment")
    if (env if isinstance(env, str) else (env or {}).get("name")) != "persona-uat":
        bad.append("release persona-uat does not run in the persona-uat environment")
    p = j.get("permissions", {})
    want = {"contents": "read", "id-token": "write"}
    if p != want:
        bad.append(f"release persona-uat permissions are not exactly {want}: no packages, no write of any kind (found {p})")
    judge_rc_registry(j, bad)
    if j.get("env"):
        bad.append(f"release persona-uat declares no env of its own is the rule (found {sorted(j['env'])}): an inherited variable (BASH_FUNC_*, PATH, BASH_ENV) could change what the closed load script runs")
    if r.get("env"):
        bad.append(f"release.yml declares a workflow-level env ({sorted(r['env'])}): the closed rc load script would inherit it; the chain jobs name what they need on the step")
    if d is not None:
        run = str(d.get("run", ""))
        envimg = str((d.get("env") or {}).get("PERSONA_UAT_IMAGE", ""))
        arg = run.replace("\\\n", " ").split("--image", 1)[-1].split(" --", 1)[0]
        if arg.strip() != '"$PERSONA_UAT_IMAGE"' or not re.fullmatch(r"localhost:5000/cache@\$\{\{\s*fromJSON\(\s*needs\.build\.outputs\.digests\s*\)\[\s*'image-production'\s*\]\s*\}\}", envimg.strip()):
            bad.append("release persona-uat takes the image from something other than Build's own image-production digest on the runner's registry (localhost:5000/cache@fromJSON(needs.build.outputs.digests)['image-production'])")
        if mode_value(run) != "rc":
            bad.append(f"release persona-uat does not run the driver with --mode rc exactly (parsed value {mode_value(run)!r})")
        steps = j.get("steps", [])
        loads = [s_ for s_ in steps if "crane push" in str(s_.get("run", ""))]
        if loads and steps.index(loads[0]) > steps.index(d):
            bad.append("release persona-uat loads the registry AFTER running the driver")

REG_IMG = re.compile(r"registry:2@sha256:[0-9a-f]{64}")
DL_ACTION = re.compile(r"actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c")

def judge_rc_registry(j, bad):
    """REQ-UAT-001-AC1 (advisor reading Oct 17): the rc job tests Build's own image from a registry that lives on the runner and nothing else. One registry:2 service pinned by digest and
    published on the loopback only; Build's images artifact; crane pushes only to localhost:5000; the pushed digest must equal the one Build attested; no registry credential, no other registry."""
    svc = j.get("services")
    if not isinstance(svc, dict) or list(svc) != ["registry"] or not isinstance(svc["registry"], dict):
        bad.append(f"release persona-uat must declare exactly one service, registry (found {svc!r})")
    else:
        sv = svc["registry"]
        if not REG_IMG.fullmatch(str(sv.get("image", ""))):
            bad.append(f"release persona-uat's registry service is not registry:2 pinned by a full sha256 digest ({sv.get('image')!r})")
        if sv.get("ports") != ["127.0.0.1:5000:5000"]:
            bad.append(f"release persona-uat's registry service is not published on the loopback only (ports must be exactly ['127.0.0.1:5000:5000'], found {sv.get('ports')!r})")
        if set(sv) - {"image", "ports"}:
            bad.append(f"release persona-uat's registry service has keys beyond image and ports (env, options, credentials or volumes): {sorted(set(sv) - {'image', 'ports'})}")
    steps = j.get("steps", [])
    dl = [s_ for s_ in steps if "actions/download-artifact" in str(s_.get("uses", ""))]
    if len(dl) != 1 or not DL_ACTION.search(str(dl[0].get("uses", ""))) or (dl[0].get("with") or {}) != {"name": "images", "path": "candidate/images"}:
        bad.append("release persona-uat must download exactly Build's `images` artifact (the allowlisted download-artifact digest, name images, path candidate/images)")
    elif set(dl[0]) - {"uses", "with"}:
        bad.append("release persona-uat's download step is not exactly uses + with (no if, continue-on-error or other key: a skipped download must fail the job, not pass it)")
    loads = [s_ for s_ in steps if "crane push" in str(s_.get("run", ""))]
    if len(loads) != 1:
        bad.append(f"release persona-uat must load Build's layout with exactly one crane push step (found {len(loads)})")
    else:
        ld = loads[0]
        lrun = "\n".join(l for l in str(ld.get("run", "")).splitlines() if not l.strip().startswith("#"))
        if dl and steps.index(dl[0]) > steps.index(ld):
            bad.append("release persona-uat loads the layout BEFORE it downloads it")
        ci = [s_ for s_ in steps if re.fullmatch(r"\./bin/install-scanner\.sh crane\s*", str(s_.get("run", "")).strip())]
        if len(ci) != 1 or steps.index(ci[0]) > steps.index(ld):
            bad.append("release persona-uat does not install the pinned crane (bin/install-scanner.sh crane) once, before the load step")
        lnorm = "\n".join(l.rstrip() for l in str(ld.get("run", "")).splitlines() if l.strip() and not l.strip().startswith("#"))
        if set(ld) - {"name", "env", "run"} or lnorm != LOAD_RUN_EXPECTED:
            bad.append("release persona-uat's load step is not exactly the closed load script (keys name, env, run only: no if, continue-on-error, shell or timeout; the script verbatim, fatal on a digest mismatch)")
        if not expr_is((ld.get("env") or {}).get("DIGESTS", ""), "needs.build.outputs.digests"):
            bad.append("release persona-uat's load step does not take the attested digests from needs.build.outputs.digests")
        if "image-production" not in lrun or not re.search(r'\[ "\$got" = "\$want" \]', lrun):
            bad.append("release persona-uat's load step does not compare the pushed digest with Build's image-production digest ([ \"$got\" = \"$want\" ] after crane digest)")
        if set((ld.get("env") or {})) - {"DIGESTS"}:
            bad.append(f"release persona-uat's load step takes env beyond DIGESTS: {sorted(set(ld.get('env') or {}) - {'DIGESTS'})}")
        if "candidate/images/production" not in lrun:
            bad.append("release persona-uat's load step does not push Build's production layout (candidate/images/production)")
    for si, st in enumerate(steps):
        run_ = "\n".join(l for l in str(st.get("run", "")).splitlines() if not l.strip().startswith("#"))
        for m in re.finditer(r"\bcrane\s+(\S+)([^\n;&|]*)", run_):
            sub, rest = m.group(1), m.group(2).split()
            targets = [t.strip("\"'") for t in rest if not t.startswith("-")]
            if sub not in ("push", "digest") or not targets or not targets[-1].startswith("localhost:5000/"):
                bad.append(f"release persona-uat step {si}: crane {sub} {' '.join(rest)} is not a push/digest to localhost:5000 (nothing leaves the runner)")
        if re.search(r"\b(?:docker|buildx|skopeo|regctl|oras)\b", run_) and "persona-uat.py" not in run_:
            bad.append(f"release persona-uat step {si} runs a container or registry client other than crane")
    dumped = json.dumps(j)
    for needle, why in (("ghcr.io", "another registry"), ("GITHUB_TOKEN", "the job token"), ("github.token", "the job token"), ("crane auth", "a registry login"), ("docker login", "a registry login"),
                        ("--insecure", "an insecure flag")):
        if needle in dumped:
            bad.append(f"release persona-uat names {needle} ({why}): it reads no registry credential and pushes nowhere but localhost")
    for m in re.finditer(r"secrets\.(\w+)", dumped):
        if m.group(1) not in set(MODEL_SECRETS) | set(CREDS):
            bad.append(f"release persona-uat reads secrets.{m.group(1)}: only the model names and the federation identifiers")

def judge_weekly(f, bad):
    workflow_defaults(f, "go-freshness.yml", bad)
    judge_workflow_env(f, "go-freshness.yml", bad)
    j = f.get("jobs", {}).get("persona-uat")
    if not j:
        bad.append("go-freshness.yml has no persona-uat job"); return
    d = common("weekly persona-uat", j, bad)
    for s_ in j.get("steps", []):
        if "actions/github-script" in str(s_.get("uses", "")):
            bad.extend(run_identity(s_))
    cron = [c.get("cron") for c in (f.get("on", {}).get("schedule") or [])] if isinstance(f.get("on"), dict) else []
    if norm(j.get("if", "")) != GATE + "&&" + norm("github.event.schedule == '43 6 * * 1'") or "43 6 * * 1" not in cron:
        bad.append(f"weekly persona-uat does not run only on the Monday cron behind the PERSONA_UAT_ENABLED gate (if: {j.get('if')!r})")
    judge_gate("weekly", f, j, bad)
    if "needs" in j:
        bad.append("weekly persona-uat has needs: a skipped dependency (the daily check job is skipped on the Monday cron) would skip every persona")
    env_ = j.get("environment")
    if (env_ if isinstance(env_, str) else (env_ or {}).get("name")) != "persona-uat":
        bad.append("weekly persona-uat does not run in the persona-uat environment")
    p = j.get("permissions", {})
    want = {"contents": "read", "id-token": "write", "packages": "read"}
    if any(p.get(k) != v for k, v in want.items()) or set(p) - set(want):
        bad.append(f"weekly persona-uat permissions are not exactly {want} (found {p})")
    steps = j.get("steps", [])
    res = [s for s in steps if "gh release view" in str(s.get("run", ""))]
    if len(res) != 1:
        bad.append("weekly persona-uat does not resolve the LATEST release's image digest (expected exactly one gh release view step)")
    else:
        r = res[0]; rrun = "\n".join(l for l in str(r.get("run", "")).splitlines() if not l.strip().startswith("#"))
        if not expr_is((r.get("env", {}) or {}).get("GH_REPO", ""), "github.repository") or not expr_is((r.get("env", {}) or {}).get("REGISTRY_OWNER", ""), "github.repository_owner"):
            bad.append("weekly persona-uat's resolver step needs env GH_REPO = github.repository and REGISTRY_OWNER = github.repository_owner (it runs after the root checkout and the crane install, before the docs checkout)")
        if not isinstance(r.get("env"), dict) or set(r["env"]) != {"GH_REPO", "REGISTRY_OWNER", "GH_TOKEN"}:
            bad.append(f"weekly persona-uat's resolver step's env must be exactly GH_REPO, REGISTRY_OWNER and GH_TOKEN (found {sorted(r['env']) if isinstance(r.get('env'), dict) else repr(r.get('env'))})")
        bad.extend(run_resolver(rrun))
        m = re.search(r"(\w+)=\$\(\s*gh release view\s+--json tagName\s+(?:-q|--jq)\s+\.tagName\s*\)", rrun)
        if not m:
            bad.append("weekly persona-uat does not resolve the LATEST release's image digest (gh release view --json tagName -q .tagName, no fixed tag)")
        else:
            var = m.group(1)
            if "if" in r or not literal_false(r.get("continue-on-error")):
                bad.append("weekly persona-uat's resolver step is conditional or non-fatal: the weekly run could go on without an image")
            insp = [l for l in rrun.splitlines() if re.search(r"\bcrane digest\b", l)]
            if not insp or not re.search(r"\$\{?" + re.escape(var) + r"\}?(?![\w])", insp[0]):
                bad.append("weekly persona-uat does not read the digest of the release it just resolved (`crane digest` must use the resolved tag)")
            dm = re.search(r"(\w+)=\$\(\s*crane digest [^\n]*\)", rrun)
            if not dm:
                bad.append("weekly persona-uat's resolver does not capture the digest with `crane digest <registry>/<owner>/cache:<tag>` (the chain's pinned tool; no buildx, no docker)")
            # the resolver is EXACTLY these five lines, in this order (no other line, no second output line, nothing inside the quotes but the fixed references): a closed list
            RESOLVER_EXACT = (r'set -euo pipefail\n(\w+)=\$\(\s*gh release view\s+--json tagName\s+(?:-q|--jq)\s+\.tagName\s*\)\n'
                              r'(\w+)=\$\(crane digest "ghcr\.io/\$\{REGISTRY_OWNER\}/cache:\$\{\1#v\}"\)\n'
                              r'echo "tag=\$(?:\{\1\}|\1(?!\w))" >> "\$GITHUB_OUTPUT"\n'
                              r'echo "image=ghcr\.io/\$\{REGISTRY_OWNER\}/cache@\$(?:\{\2\}|\2(?!\w))" >> "\$GITHUB_OUTPUT"')
            rlines = [l.strip() for l in rrun.splitlines() if l.strip()]
            if not re.fullmatch(RESOLVER_EXACT, "\n".join(rlines)):
                bad.append("weekly persona-uat's resolver is not one of the five allowed shapes, exactly and in this order (set -euo pipefail; the gh release view read; the one crane digest read of ghcr.io/${REGISTRY_OWNER}/cache:${tag#v}; the tag= output; the image= output built from that digest): any extra, repeated or altered line is refused")
            if any(not re.fullmatch(r'\s*\w+=\$\(crane digest "[^"\n]*"\)\s*', l) for l in insp):
                bad.append("weekly persona-uat's digest line must be one `crane digest` with no pipe or fallback, the whole line exactly NAME=$(crane digest \"<ref>\") (a failing crane must fail the step, never hand the driver another digest)")
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
            if not r.get("id") or arg.strip() != '"$PERSONA_UAT_IMAGE"' or not re.fullmatch(r"\$\{\{\s*steps\." + re.escape(str(r.get("id"))) + r"\.outputs\.image\s*\}\}", str((d.get("env") or {}).get("PERSONA_UAT_IMAGE", "")).strip()):
                bad.append("weekly persona-uat does not hand the resolved latest-release image digest to --image")
    if d is not None and mode_value(d.get("run", "")) != "weekly":
        bad.append(f"weekly persona-uat does not run the driver with --mode weekly exactly (parsed value {mode_value(d.get('run', ''))!r})")

TOOL_KEYS = ["capture", "cosign", "gitlab-runner", "gradle", "jenkins", "kind", "kubectl", "maven", "shell"]
# each key's official image repository, as docker normalises it (docker.io/ and library/ stripped); an exact match, never a suffix match
OFFICIAL = {"capture": {"nicolaka/netshoot"}, "cosign": {"gcr.io/projectsigstore/cosign", "ghcr.io/sigstore/cosign/cosign"}, "gitlab-runner": {"gitlab/gitlab-runner"}, "gradle": {"gradle"},
            "jenkins": {"jenkins/jenkins"}, "kind": {"kindest/node"}, "kubectl": {"registry.k8s.io/kubectl"}, "maven": {"maven"}, "shell": {"curlimages/curl"}}

def repo_of(ref):
    r = str(ref).split("@")[0]
    r = re.sub(r":[A-Za-z0-9._-]+$", "", r)
    for pre in ("docker.io/", "index.docker.io/", "registry-1.docker.io/"):
        if r.startswith(pre): r = r[len(pre):]
    return r[len("library/"):] if r.startswith("library/") else r

def judge_tools(t, bad):
    if not isinstance(t, dict) or sorted(t) != TOOL_KEYS:
        bad.append(f"the persona tools file must hold exactly the keys {', '.join(TOOL_KEYS)} (found {sorted(t) if isinstance(t, dict) else t})")
        return
    for k, v in t.items():
        if not PIN_IMG.match(str(v)):
            bad.append(f"tool {k} is not pinned by digest ({v!r})")
    for k, repos in OFFICIAL.items():
        if repo_of(t.get(k, "")) not in repos:
            bad.append(f"tool {k} does not name its own official image (expected one of {sorted(repos)}): {t.get(k)!r}")
    if len({repo_of(v) for v in t.values()}) != len(TOOL_KEYS) or len({str(v).split("@")[-1] for v in t.values()}) != len(TOOL_KEYS):
        bad.append("the persona tools are not distinct images (nine different repositories and digests)")

SRC_OVER = {}

def judge_source(bad):
    for p in SRC:
        try:
            src = SRC_OVER[p] if p in SRC_OVER else open(p).read()
        except OSError:
            bad.append(f"{os.path.relpath(p, root)} is missing"); continue
        code = "\n".join(l for l in src.splitlines() if not l.lstrip().startswith("#"))
        if re.search(r"--privileged|[\"']privileged[\"']\s*[:=]\s*True|privileged\s*=\s*True", code):
            bad.append(f"{os.path.relpath(p, root)} starts a privileged container: the kind cluster is created by the job's kind binary, never by docker run --privileged")
        if re.search(r"[\"']--net(?:work)?[\"']\s*,\s*[\"']host[\"']|--net(?:work)?[= ]host\b|network_mode\s*[:=]\s*[\"']host", code):
            bad.append(f"{os.path.relpath(p, root)} puts a container on the host's network: a persona's containers are on the persona's own network only")
        cmd = re.search(r"[\"'](?:terraform|tofu|pulumi|eksctl|doctl|aws|gcloud|az|ibmcloud|oci|linode-cli|vultr-cli)(?:\s|[\"'])", code)
        if cmd:
            bad.append(f"{os.path.relpath(p, root)} runs a cloud CLI: {cmd.group(0)}")
        for m in re.finditer(r"[\"']((?:[a-z0-9.-]+/)+[a-z0-9._-]+(?::[\w.-]+)?)[\"']", code):
            if re.search(r"(docker\.io|ghcr\.io|quay\.io|gcr\.io|registry\.k8s\.io|library|jenkins|gitlab|kindest|sigstore|cosign|kubectl|gradle|maven)", m.group(1)) and "@sha256:" not in m.group(1):
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

# a known-good nine-entry tools file, so the tools mutations test the JUDGE and do not depend on the file in the tree
TGOOD = {"capture": "docker.io/nicolaka/netshoot@sha256:" + "b" * 64, "cosign": "gcr.io/projectsigstore/cosign@sha256:" + "5" * 64, "gitlab-runner": "docker.io/gitlab/gitlab-runner@sha256:" + "2" * 64,
         "gradle": "docker.io/library/gradle@sha256:" + "7" * 64, "jenkins": "docker.io/jenkins/jenkins@sha256:" + "1" * 64,
         "kind": "docker.io/kindest/node@sha256:" + "3" * 64, "kubectl": "registry.k8s.io/kubectl@sha256:" + "6" * 64,
         "maven": "docker.io/library/maven@sha256:" + "8" * 64, "shell": "docker.io/curlimages/curl@sha256:" + "4" * 64}
CLEAN_SRC = {p: "x = 1\n" for p in SRC}

# the same two judges on the REAL files alone, so a delta-1/2 failure is not hidden behind the workflow wiring (which lands with commit 2)
good = []
judge_tools(T if T is not None else "missing", good)
result(not good, "the real tools file (bin/persona-uat-tools.json) is the nine official digest-pinned images" + ("" if not good else ": " + "; ".join(good)))
good = []
judge_source(good)
result(not good, "the real driver, agent and provider run no privileged container, no cloud CLI and name no image without a digest" + ("" if not good else ": " + "; ".join(good)))
good = []
judge_tools(TGOOD, good)
result(not good, "the in-test known-good nine-entry tools file is accepted by the judge" + ("" if not good else ": " + "; ".join(good)))
good = []
SRC_OVER.update(CLEAN_SRC); judge_source(good); SRC_OVER.clear()
result(not good, "a clean source set is accepted by the source judge" + ("" if not good else ": " + "; ".join(good)))

def synth_steps(weekly):
    pre = ""
    cos = [{"uses": "actions/checkout@" + "0" * 40}, {"uses": "actions/checkout@" + "0" * 40, "with": {"path": "release-docs"}}] if weekly else [{"uses": "actions/checkout@" + "0" * 40}]
    words = ["python3", "-m", "pip", "install", "--quiet", "--break-system-packages", "--require-hashes",
             "--only-binary=:all:", "-r", pre + "bin/persona-uat-requirements.txt"]
    pip = " ".join(words)
    return pre, cos + [{"run": KIND_RUN}, {"run": PIN_PIP_RUN}, {"run": pip},
                       {"run": "python3 " + pre + "bin/persona-uat.py --mode rc"}]
for weekly in (False, True):
    pre, st = synth_steps(weekly)
    bd = []
    judge_install("synth", st, st[-1], pre, bd)
    which = "weekly" if weekly else "rc"
    result(not bd, f"the install judge accepts the kind check step ({which})"
           + ("" if not bd else ": " + "; ".join(bd)))
def ins(st):
    return next(x for x in st if "install-scanner" in str(x.get("run", "")) or re.search(r"\bkind\b", str(x.get("run", ""))))

def imutate(name, expect, fn, weekly=False):
    pre, st = synth_steps(weekly)
    fn(st)
    bd = []
    judge_install("synth", st, next(x for x in st if "persona-uat.py" in str(x.get("run", "")) and not re.search(r"--(?:mint|remove)-identity", str(x.get("run", "")))), pre, bd)
    result(any(expect in b for b in bd), f"caught: {name} (reason: {expect!r})" + ("" if any(expect in b for b in bd) else f"; saw {bd}"))

for weekly in (False, True):
    w = " (weekly)" if weekly else ""
    imutate("kind check missing" + w, "exactly one step", lambda st: st.remove(ins(st)), weekly)
    imutate("kind install by curl | sh" + w, "exactly one step", lambda st: ins(st).update(run="curl -sSL https://kind.sigs.k8s.io/dl/v0.30.0/kind-linux-amd64 | sh"), weekly)
    imutate("kind download without checksum" + w, "exactly one step", lambda st: ins(st).update(run="curl -Lo /usr/local/bin/kind https://kind.sigs.k8s.io/dl/v0.30.0/kind-linux-amd64 && chmod +x /usr/local/bin/kind"), weekly)
    imutate("kind installed by go install" + w, "exactly one step", lambda st: ins(st).update(run="make install-kind"), weekly)
    imutate("kind install after the driver" + w, "AFTER the driver", lambda st: st.append(st.pop(st.index(ins(st)))), weekly)
    imutate("kind install conditional" + w, "conditional or non-fatal", lambda st: ins(st).update({"if": "github.event_name == 'push'"}), weekly)
    imutate("kind install continue-on-error" + w, "conditional or non-fatal", lambda st: ins(st).update({"continue-on-error": "true"}), weekly)
    imutate("kind install piped" + w, "exactly one step", lambda st: ins(st).update(run=ins(st)["run"] + " | sh"), weekly)
    imutate("kind installed twice" + w, "exactly one step", lambda st: st.insert(st.index(ins(st)), dict(ins(st))), weekly)
    imutate("kind install with a custom shell" + w, "custom shell", lambda st: ins(st).update(shell="pwsh"), weekly)
    imutate("kind install with env" + w, "custom shell, working-directory or env", lambda st: ins(st).update(env={"KIND_BASE_URL": "https://evil.example"}), weekly)

# --- a COMPLETE known-good synthetic release.yml and go-freshness.yml, run through the REAL entry point judge() -> judge_release/judge_weekly -> common() ----------
H40 = "a" * 40
CLAIMS_JS = "// Print ONLY the identity claims the Anthropic federation rule matches on (never the token, which stays masked): a token-exchange 401 is then diagnosable.\ntry {\n  const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));\n  const claims = {};\n  for (const k of ['sub', 'aud', 'ref', 'job_workflow_ref', 'environment', 'repository', 'repository_owner_id', 'event_name', 'iss']) {\n    claims[k] = payload[k];\n  }\n  core.info('OIDC identity claims (federation-rule inputs): ' + JSON.stringify(claims));\n} catch (e) {\n  core.warning('could not decode OIDC claims for logging');\n}\n"
IDENT = ("const fs = require('fs');\nconst token = await core.getIDToken('https://api.anthropic.com');\ncore.setSecret(token);\n"
         "const f = process.env.RUNNER_TEMP + '/anthropic-identity-token';\nfs.writeFileSync(f, token, { mode: 0o600 });\n" + CLAIMS_JS)
REFRESHER = 'set -euo pipefail\nf="${RUNNER_TEMP}/anthropic-identity-token"\n[ -f "$f" ] || { echo "::error::the identity token file does not exist yet: mint it first"; exit 1; }\nnohup bash -c \'\n  f="$1"; every="$2"\n  while [ -e "$f" ] && sleep "$every"; do\n    [ -e "$f" ] || break\n    python3 bin/persona-uat.py --mint-identity "$f" || { [ "$?" -eq 3 ] && break; continue; }\n  done\n\' identity-refresher "$f" "${PERSONA_UAT_REFRESH_SECONDS:-60}" </dev/null >/dev/null 2>&1 &\ndisown\n'
CLEANUP = CLEANUP_RUN
RC_LOAD_RUN = LOAD_RUN_EXPECTED
def synth_driver(weekly):
    pre = ""
    env = {v: ("${{ secrets.%s }}" if v in MODEL_SECRETS else "${{ vars.%s }}") % v for v in VARS}
    env.update({c: "${{ secrets.%s }}" % c for c in CREDS})
    env["ANTHROPIC_IDENTITY_TOKEN_FILE"] = "${{ runner.temp }}/anthropic-identity-token"
    env["PERSONA_UAT_IMAGE"] = "${{ steps.resolve.outputs.image }}" if weekly else "localhost:5000/cache@${{ fromJSON(needs.build.outputs.digests)['image-production'] }}"
    img = '"$PERSONA_UAT_IMAGE"'
    return {"env": env, "run": f'python3 {pre}bin/persona-uat.py --mode {"weekly" if weekly else "rc"} --image {img} --repo {"release-docs" if weekly else "."} --out persona-uat-out '
                                f'--tools {pre}bin/persona-uat-tools.json --recipient {pre}bin/persona-uat-recipient.pem --agent "python3 {pre}bin/persona-uat-agent.py"' + ("" if weekly else " --allow-listen 5000")}
def synth_persona_job(weekly):
    pre = ""
    co = ([{"uses": "actions/checkout@" + H40, "with": {"persist-credentials": "false"}},
           {"uses": "actions/checkout@" + H40, "with": {"path": "release-docs", "ref": "${{ steps.resolve.outputs.tag }}", "persist-credentials": "false"}}] if weekly
          else [{"uses": "actions/checkout@" + H40, "with": {"persist-credentials": "false"}}])
    resolver = [{"id": "resolve", "env": {"GH_REPO": "${{ github.repository }}", "REGISTRY_OWNER": "${{ github.repository_owner }}", "GH_TOKEN": "${{ github.token }}"},
                 "run": 'set -euo pipefail\ntag=$(gh release view --json tagName -q .tagName)\nd=$(crane digest "ghcr.io/${REGISTRY_OWNER}/cache:${tag#v}")\n'
                        'echo "tag=$tag" >> "$GITHUB_OUTPUT"\necho "image=ghcr.io/${REGISTRY_OWNER}/cache@$d" >> "$GITHUB_OUTPUT"'}] if weekly else []
    # the weekly job: the root checkout (it provides bin/install-scanner.sh), the pinned crane, the resolver, then the docs checkout; the rc job has the one checkout
    rc_load = [{"uses": "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c", "with": {"name": "images", "path": "candidate/images"}},
               {"run": "./" + pre + "bin/install-scanner.sh crane"},
               {"name": "load", "env": {"DIGESTS": "${{ needs.build.outputs.digests }}"}, "run": RC_LOAD_RUN}]
    head = ([co[0], {"run": "./" + pre + "bin/install-scanner.sh crane"}] + resolver + [co[1]]) if weekly else co + rc_load
    steps = (head + [{"run": KIND_RUN},
             {"run": PIN_PIP_RUN},
             {"run": "python3 -m pip install --quiet --break-system-packages --require-hashes --only-binary=:all: -r " + pre + "bin/persona-uat-requirements.txt"},
             {"uses": "actions/github-script@" + H40, "with": {"script": IDENT}}, {"run": REFRESHER}, synth_driver(weekly),
             {"if": "${{ always() }}", "uses": "actions/upload-artifact@" + H40, "with": {"name": "persona-uat-encrypted", "path": "persona-uat-out/*.cms", "if-no-files-found": "error"}},
             {"if": "${{ always() }}", "run": CLEANUP}])
    j = {"runs-on": "ubuntu-24.04", "timeout-minutes": "120", "environment": "persona-uat", "permissions": {"contents": "read", "id-token": "write", "packages": "read"}, "steps": steps}
    if not weekly:
        j["permissions"] = {"contents": "read", "id-token": "write"}
        j["services"] = {"registry": {"image": "registry:2@sha256:" + "b" * 64, "ports": ["127.0.0.1:5000:5000"]}}
    if weekly:
        j["if"] = "${{ vars.PERSONA_UAT_ENABLED == 'true' && github.event.schedule == '43 6 * * 1' }}"
    else:
        j["needs"] = ["build"]
        j["if"] = "${{ vars.PERSONA_UAT_ENABLED == 'true' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') && !inputs.dry-run }}"
    return j
RS = {"on": {"push": {"tags": ["v*"]}}, "jobs": {
    "build": {"steps": [{"run": "true"}]}, "release": {"needs": ["build"], "steps": [{"run": "true"}]},
    "patch-failed": {"needs": ["build", "release"], "if": "${{ failure() }}", "steps": [{"run": 'gh issue create --title "auditor: release failed" --body "$RUN_URL"'}]},
    "persona-uat": synth_persona_job(False)}}
FS = {"on": {"schedule": [{"cron": "43 6 * * 1"}]}, "jobs": {
    "check": {"if": "${{ github.event.schedule != '43 6 * * 1' }}", "steps": [{"run": 'gh issue create --title "go freshness" --body x'}]},
    "persona-uat": synth_persona_job(True)}}
SRC_OVER.update(CLEAN_SRC)
bd = judge(RS, FS, TGOOD)
SRC_OVER.clear()
result(not bd, "a COMPLETE known-good synthetic release.yml and go-freshness.yml pass the real entry point judge() (judge_release, judge_weekly, common, judge_prereqs, judge_install, the tools and source judges): a NameError or an ordering defect fails here" + ("" if not bd else ": " + "; ".join(bd)))

# the prerequisite judge on small jobs (named as the weekly or the rc job)
def synth_job(weekly):
    j = synth_persona_job(weekly)
    return ("weekly synth" if weekly else "rc synth"), j
for weekly in (False, True):
    nm, j = synth_job(weekly); bd = []
    judge_prereqs(nm, j, j["steps"], bd)
    result(not bd, f"the prerequisite judge accepts the known-good job ({'weekly' if weekly else 'rc'})" + ("" if not bd else ": " + "; ".join(bd)))
    def pm(name, expect, fn, weekly=weekly):
        nm, j = synth_job(weekly); fn(j); bd = []
        judge_prereqs(nm, j, j["steps"], bd)
        result(any(expect in b for b in bd), f"caught: {name}{' (weekly)' if weekly else ''} (reason: {expect!r})" + ("" if any(expect in b for b in bd) else f"; saw {bd}"))
    co0 = lambda j: next(x for x in j["steps"] if "actions/checkout" in str(x.get("uses", "")))
    boot = lambda j: next(x for x in j["steps"] if "persona-uat-requirements" in str(x.get("run", "")))
    pm("checkout with if: false", "checkout step is conditional", lambda j: co0(j).update({"if": "false"}))
    pm("checkout continue-on-error", "checkout step is conditional", lambda j: co0(j).update({"continue-on-error": "true"}))
    pm("SDK install continue-on-error: true", "SDK install step is conditional", lambda j: boot(j).update({"continue-on-error": "true"}))
    pm("SDK install with if: false", "SDK install step is conditional", lambda j: boot(j).update({"if": "false"}))
    pm("runs-on windows-latest", "not an ubuntu runner", lambda j: j.update({"runs-on": "windows-latest"}))
    pm("runs-on macos-latest", "not an ubuntu runner", lambda j: j.update({"runs-on": "macos-latest"}))
    pm("runs-on a self-hosted runner", "not an ubuntu runner", lambda j: j.update({"runs-on": "self-hosted"}))
    pm("a matrix duplicating the job", "strategy/matrix", lambda j: j.update({"strategy": {"matrix": {"n": ["1", "2"]}}}))
    pm("a one-entry matrix", "strategy/matrix", lambda j: j.update({"strategy": {"matrix": {"n": ["1"]}}}))
    pm("checkout with sparse-checkout (no docs/)", "options outside its allowlist", lambda j: co0(j)["with"].update({"sparse-checkout": "bin\nREADME.md", "sparse-checkout-cone-mode": "false"}))
    pm("checkout with a cone-mode sparse checkout", "options outside its allowlist", lambda j: co0(j)["with"].update({"sparse-checkout": "bin", "sparse-checkout-cone-mode": "true"}))
    pm("checkout with a partial-clone filter", "options outside its allowlist", lambda j: co0(j)["with"].update({"filter": "tree:0"}))
    pm("checkout with fetch-depth 1", "options outside its allowlist", lambda j: co0(j)["with"].update({"fetch-depth": "1"}))
    pm("checkout with lfs", "options outside its allowlist", lambda j: co0(j)["with"].update({"lfs": "true"}))
    pm("checkout of another repository", "options outside its allowlist", lambda j: co0(j)["with"].update({"repository": "evil/cache"}))
    pm("checkout with a working-directory", "carries keys outside its allowlist", lambda j: co0(j).update({"working-directory": "/tmp"}))
    pm("SDK install with a working-directory", "carries keys outside its allowlist", lambda j: boot(j).update({"working-directory": "/tmp"}))
    pm("SDK install with a custom shell", "carries keys outside its allowlist", lambda j: boot(j).update({"shell": "pwsh"}))
    pm("SDK install with an env", "carries keys outside its allowlist", lambda j: boot(j).update({"env": {"PIP_INDEX_URL": "https://evil.example/simple"}}))
    kind_step = lambda j: next(x for x in j["steps"] if x.get("run") == KIND_RUN)
    pm("kind check with a working-directory", "carries keys outside its allowlist",
       lambda j: kind_step(j).update({"working-directory": "/tmp"}))
    pm("identity step with a working-directory", "carries keys outside its allowlist", lambda j: next(x for x in j["steps"] if "github-script" in str(x.get("uses", ""))).update({"working-directory": "/tmp"}))
    pm("identity step with another option", "options outside its allowlist", lambda j: next(x for x in j["steps"] if "github-script" in str(x.get("uses", ""))).setdefault("with", {}).update({"github-token": "${{ secrets.X }}"}))
    pm("upload with a working-directory", "carries keys outside its allowlist", lambda j: next(x for x in j["steps"] if "upload-artifact" in str(x.get("uses", ""))).update({"working-directory": "/tmp"}))

BASES = [("synthetic", RS, FS)]
REAL_REL_JOB = bool(R.get("jobs", {}).get("persona-uat"))
REAL_JOBS = bool(F.get("jobs", {}).get("persona-uat"))      # the weekly job is in the real go-freshness.yml; the rc job in release.yml is out until D (see judge_release)
if REAL_JOBS:
    BASES.append(("real", R, F))
else:
    result(False, "the real go-freshness.yml has no persona-uat job: every workflow mutation below ran against the synthetic known-good workflows only")
result(REAL_REL_JOB, "the real release.yml has the persona-uat job (the release candidate's persona run, REQ-UAT-001-AC1, option D of the advisor ruling Oct 17)")
def mutate(name, expect, fn, which="rel"):
    for label, BR, BF in BASES:
        if label == "real" and which in ("rel", "rel_patchfailed") and not BR.get("jobs", {}).get("persona-uat"):
            continue      # the real release.yml has no rc job (option B): nothing there to mutate; the synthetic base still carries every mutation
        if which in ("tools", "src") and label != "synthetic":
            continue
        _mutate(f"[{label}] {name}", expect, fn, which, BR, BF)

def _mutate(name, expect, fn, which, BR, BF):
    r, f, t = copy.deepcopy(BR), copy.deepcopy(BF), copy.deepcopy(TGOOD if (which == "tools" or BR is RS) else T)
    srcs = copy.deepcopy(CLEAN_SRC)
    try:
        if which == "rel_top":
            r["on"]["push"]["tags"] = ["x*"]
        elif which == "rel_tags":
            r["on"]["push"]["tags"] = ["v*", "!v*-rc.*"]
        elif which == "rel_defaults":
            r["defaults"] = {"run": {"working-directory": "release-docs"}}
        elif which == "fresh_defaults":
            f["defaults"] = {"run": {"working-directory": "release-docs"}}
        elif which == "rel_defaults_shell":
            r["defaults"] = {"run": {"shell": "pwsh"}}
        elif which == "rel_patchfailed":
            r["jobs"]["patch-failed"]["needs"] = [n for n in r["jobs"]["patch-failed"]["needs"] if n != "persona-uat"]
        elif which == "rel_wf":
            fn(r)
        elif which == "fresh_wf":
            fn(f)
        else:
            {"rel": lambda: fn(r["jobs"]["persona-uat"]), "fresh": lambda: fn(f["jobs"]["persona-uat"]), "tools": lambda: fn(t), "src": lambda: fn(srcs)}[which]()
    except Exception as e:     # the base lacks the thing being mutated
        result(False, f"mutation could not be applied ({name}): {type(e).__name__}: {e}"); return
    # round-trip through YAML text so the mutated document is valid YAML, not just a dict
    for doc in (r, f):
        yaml.safe_load(yaml.safe_dump(doc))
    if (r, f, srcs) == (BR, BF, CLEAN_SRC) and (which != "tools" or t == TGOOD):
        result(False, f"mutation changed nothing ({name})"); return
    SRC_OVER.clear()
    if which == "src" or BR is RS:
        SRC_OVER.update(srcs)
    found = judge(r, f, t)
    SRC_OVER.clear()
    result(any(expect in b for b in found), f"caught: {name} (reason: {expect!r})" + ("" if any(expect in b for b in found) else f"; saw {found}"))

def set_image(job, value):
    """replace the driver's whole --image argument (quoted or not, spaces inside allowed), whatever its formatting"""
    d = next(s for s in job["steps"] if "persona-uat.py" in str(s.get("run", "")) and not re.search(r"--(?:mint|remove)-identity", str(s.get("run", ""))))
    new, n = re.subn(r"--image\s+(\"[^\"]*\"|'[^']*'|\S+)", lambda m: "--image " + value, d["run"].replace("\\\n", " "), count=1)
    assert n == 1 and new != d["run"], "set_image changed nothing"
    d["run"] = new

def drv(job): return next(s for s in job["steps"] if "persona-uat.py" in str(s.get("run", "")) and not re.search(r"--(?:mint|remove)-identity", str(s.get("run", ""))))
def up(job): return next(s for s in job["steps"] if "upload-artifact" in str(s.get("uses", "")))

# release job
mutate("rc job no longer waits for build", "needs are not exactly build", lambda j: j.update(needs=[]))
mutate("rc job runs for every tag", "does not run only for a release-candidate tag", lambda j: j.update({"if": "${{ startsWith(github.ref, 'refs/tags/v') }}"}))
mutate("rc job's predicate gains && false", "does not run only for a release-candidate tag", lambda j: j.update({"if": str(j["if"]).rstrip("} ") + " && false }}"}))
mutate("rc job continue-on-error", "continue-on-error on the job", lambda j: j.update({"continue-on-error": "true"}))
mutate("rc driver step continue-on-error", "the driver step has continue-on-error", lambda j: drv(j).update({"continue-on-error": "true"}))
mutate("rc driver step if: false", "the driver step has an if", lambda j: drv(j).update({"if": "false"}))
mutate("rc driver step is piped through tee", "not exactly one bare driver command", lambda j: drv(j).update(run=drv(j)["run"].rstrip() + " | tee persona.log"))
mutate("rc driver step is backgrounded", "not exactly one bare driver command", lambda j: drv(j).update(run=drv(j)["run"].rstrip() + " &"))
mutate("rc driver step wrapped in if !", "not exactly one bare driver command", lambda j: drv(j).update(run="if ! " + drv(j)["run"].strip() + "; then echo no; fi"))
mutate("rc driver continue-on-error is an expression", "the driver step has continue-on-error", lambda j: drv(j).update({"continue-on-error": "${{ always() }}"}))
mutate("rc job has no timeout", "no timeout-minutes", lambda j: j.pop("timeout-minutes"))
mutate("rc job uses a kind action", "is not on the persona job's allowlist", lambda j: j["steps"].insert(0, {"uses": "helm/kind-action@" + "a" * 40}))
mutate("rc job runs docker itself", "uses docker or buildx", lambda j: j["steps"].insert(0, {"run": "docker run -d jenkins/jenkins:lts"}))
mutate("rc secrets set at job level", "set at job level", lambda j: j.setdefault("env", {}).update(ANTHROPIC_WORKSPACE_ID="${{ secrets.ANTHROPIC_WORKSPACE_ID }}"))
mutate("rc image argument is the raw digests JSON", "takes the image from something other than Build's own image-production digest",
       lambda j: drv(j)["env"].update(PERSONA_UAT_IMAGE=re.sub(r"fromJSON\(needs\.build\.outputs\.digests\)\['image-production'\]", "needs.build.outputs.digests", drv(j)["env"]["PERSONA_UAT_IMAGE"])))
mutate("rc driver run interpolates an expression", "interpolates an expression into its run script", lambda j: drv(j).update(run=drv(j)["run"].replace('"$PERSONA_UAT_IMAGE"', '"${{ github.ref_name }}"')))
mutate("weekly driver run interpolates an expression", "interpolates an expression into its run script", lambda j: drv(j).update(run=drv(j)["run"].replace('"$PERSONA_UAT_IMAGE"', '"${{ steps.resolve.outputs.image }}"')), "fresh")
mutate("rc other step interpolates an expression", "interpolates an expression into its run script", lambda j: j["steps"].insert(0, {"run": 'echo "${{ github.event.head_commit.message }}"'}))
mutate("weekly other step interpolates an expression", "interpolates an expression into its run script", lambda j: j["steps"].insert(0, {"run": 'echo "${{ github.head_ref }}"'}), "fresh")
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
mutate("rc driver step gets a tag, not the chain's digests", "takes the image from something other than Build's own image-production digest",
       lambda j: drv(j)["env"].update(PERSONA_UAT_IMAGE=re.sub(r"fromJSON\(needs\.build\.outputs\.digests\)\['image-production'\]", "github.ref_name", drv(j)["env"]["PERSONA_UAT_IMAGE"])))
mutate("rc job leaves the persona-uat environment", "persona-uat environment", lambda j: j.update(environment="release"))
mutate("rc model id hard-coded", "PERSONA_UAT_MODEL is not exactly secrets.PERSONA_UAT_MODEL", lambda j: drv(j).setdefault("env", {}).update(PERSONA_UAT_MODEL="m-1"))
mutate("rc owner variables moved off the driver step onto the upload step", "is not exactly secrets.PERSONA_UAT_MODEL",
       lambda j: (up(j).update(env={v: drv(j)["env"].pop(v) for v in VARS if v in drv(j).get("env", {})})))
mutate("rc budget variable dropped", "PERSONA_UAT_TOKEN_BUDGET is not exactly vars.PERSONA_UAT_TOKEN_BUDGET", lambda j: drv(j)["env"].pop("PERSONA_UAT_TOKEN_BUDGET"))
mutate("rc compliance model replaced by the default one", "PERSONA_UAT_COMPLIANCE_MODEL is not exactly secrets.PERSONA_UAT_COMPLIANCE_MODEL",
       lambda j: drv(j)["env"].update(PERSONA_UAT_COMPLIANCE_MODEL="${{ secrets.PERSONA_UAT_MODEL }}"))
mutate("rc federation secret dropped", "ANTHROPIC_WORKSPACE_ID is not exactly secrets.ANTHROPIC_WORKSPACE_ID", lambda j: drv(j)["env"].pop("ANTHROPIC_WORKSPACE_ID"))
mutate("rc upload path is not the driver's output", "not exactly", lambda j: up(j)["with"].update(path="/tmp/unrelated"))
mutate("rc upload skipped on failure", "must run always()", lambda j: up(j).update({"if": "${{ always() && false }}"}))
mutate("rc upload tolerates no files", "if-no-files-found: error", lambda j: up(j)["with"].update({"if-no-files-found": "ignore"}))
mutate("rc job provisions a cloud instance (plain form)", "names a cloud CLI",
       lambda j: j["steps"].insert(0, {"run": "aws --region us-east-1 ec2 run-instances --image-id ami-1"}))
mutate("rc job declares an unpinned job container", "declares container", lambda j: j.update(container="jenkins/jenkins:lts"))
mutate("rc job declares an unpinned service", "must declare exactly one service", lambda j: j.update(services={"jenkins": {"image": "jenkins/jenkins:lts"}}))
mutate("rc registry service by tag, not digest", "not registry:2 pinned by a full sha256 digest", lambda j: j["services"]["registry"].update(image="registry:2"))
mutate("rc registry service by a short digest", "not registry:2 pinned by a full sha256 digest", lambda j: j["services"]["registry"].update(image="registry:2@sha256:abc"))
mutate("rc registry service of another image", "not registry:2 pinned by a full sha256 digest", lambda j: j["services"]["registry"].update(image="evil/registry@sha256:" + "b" * 64))
mutate("rc registry service published on every interface", "not published on the loopback only", lambda j: j["services"]["registry"].update(ports=["5000:5000"]))
mutate("rc registry service on 0.0.0.0", "not published on the loopback only", lambda j: j["services"]["registry"].update(ports=["0.0.0.0:5000:5000"]))
mutate("rc registry service with a credential env", "keys beyond image and ports", lambda j: j["services"]["registry"].update(env={"REGISTRY_AUTH": "x"}))
mutate("rc registry service with options (host network)", "keys beyond image and ports", lambda j: j["services"]["registry"].update(options="--network host"))
mutate("rc job with a second service", "must declare exactly one service", lambda j: j["services"].update(extra={"image": "registry:2@sha256:" + "b" * 64}))
mutate("rc job without the registry service", "must declare exactly one service", lambda j: j.pop("services"))
mutate("rc job pushes to ghcr.io", "is not a push/digest to localhost:5000", lambda j: next(x for x in j["steps"] if "crane push" in str(x.get("run", ""))).update(run="crane push candidate/images/production ghcr.io/fosterstack/cache:rc"))
mutate("rc job copies to another registry", "is not a push/digest to localhost:5000", lambda j: j["steps"].insert(0, {"run": "crane copy localhost:5000/cache:rc ghcr.io/fosterstack/cache:rc"}))
mutate("rc job logs in to a registry", "is not a push/digest to localhost:5000", lambda j: j["steps"].insert(0, {"run": "crane auth login ghcr.io -u x -p y"}))
mutate("rc job pushes to localhost on another port", "is not a push/digest to localhost:5000", lambda j: next(x for x in j["steps"] if "crane push" in str(x.get("run", ""))).update(run="crane push candidate/images/production localhost:5001/cache:rc"))
mutate("rc job compares nothing after the push", "does not compare the pushed digest", lambda j: next(x for x in j["steps"] if "crane push" in str(x.get("run", ""))).update(run='crane push candidate/images/production localhost:5000/cache:rc\necho image-production'))
mutate("rc job takes the digests from somewhere else", "does not take the attested digests from needs.build.outputs.digests", lambda j: next(x for x in j["steps"] if "crane push" in str(x.get("run", ""))).update(env={"DIGESTS": "${{ needs.check.outputs.digests }}"}))
mutate("rc job pushes a different layout (fips)", "does not push Build's production layout", lambda j: next(x for x in j["steps"] if "crane push" in str(x.get("run", ""))).update(run=next(x for x in j["steps"] if "crane push" in str(x.get("run", "")))["run"].replace("candidate/images/production", "candidate/images/fips")))
mutate("rc job downloads another artifact", "must download exactly Build's `images` artifact", lambda j: next(x for x in j["steps"] if "download-artifact" in str(x.get("uses", ""))).update({"with": {"name": "dist", "path": "candidate/images"}}))
mutate("rc job downloads with an unlisted digest", "must download exactly Build's `images` artifact", lambda j: next(x for x in j["steps"] if "download-artifact" in str(x.get("uses", ""))).update({"uses": "actions/download-artifact@" + "d" * 40}))
mutate("rc job has no download", "must download exactly Build's `images` artifact", lambda j: j.update(steps=[x for x in j["steps"] if "download-artifact" not in str(x.get("uses", ""))]))
LOADSTEP = lambda j: next(x for x in j["steps"] if "crane push" in str(x.get("run", "")))
DLSTEP = lambda j: next(x for x in j["steps"] if "download-artifact" in str(x.get("uses", "")))
mutate("rc load step if: false", "is not exactly the closed load script", lambda j: LOADSTEP(j).update({"if": "${{ false }}"}))
mutate("rc load step continue-on-error", "is not exactly the closed load script", lambda j: LOADSTEP(j).update({"continue-on-error": "true"}))
mutate("rc load step mismatch exits 0", "is not exactly the closed load script", lambda j: LOADSTEP(j).update(run=LOADSTEP(j)["run"].replace("exit 1", "true")))
mutate("rc load step compares nothing fatal (|| true)", "is not exactly the closed load script", lambda j: LOADSTEP(j).update(run=LOADSTEP(j)["run"] + " || true"))
mutate("rc load step drops pipefail", "is not exactly the closed load script", lambda j: LOADSTEP(j).update(run=LOADSTEP(j)["run"].replace("set -euo pipefail", "set -eu")))
mutate("rc load step with a custom shell", "is not exactly the closed load script", lambda j: LOADSTEP(j).update({"shell": "bash {0}"}))
mutate("rc download step if: false", "download step is not exactly uses + with", lambda j: DLSTEP(j).update({"if": "${{ false }}"}))
mutate("rc download step continue-on-error", "download step is not exactly uses + with", lambda j: DLSTEP(j).update({"continue-on-error": "true"}))
mutate("rc job env defines a shell function the load script would call", "declares no env of its own", lambda j: j.update(env={"BASH_FUNC_crane%%": "() { true; }"}))
mutate("release.yml workflow env defines a shell function", "workflow-level env", lambda r: r.update(env={"BASH_FUNC_crane%%": "() { true; }"}), "rel_wf")
mutate("rc driver is not told about the registry listener", "must be given --allow-listen 5000", lambda j: drv(j).update(run=drv(j)["run"].replace(" --allow-listen 5000", "")))
mutate("rc driver allows another listener port", "must be given --allow-listen 5000", lambda j: drv(j).update(run=drv(j)["run"].replace("--allow-listen 5000", "--allow-listen 5001")))
mutate("rc driver allows a second listener port", "must be given --allow-listen 5000", lambda j: drv(j).update(run=drv(j)["run"] + " --allow-listen 22"))
mutate("weekly driver allows a listener", "outside the contract", lambda j: drv(j).update(run=drv(j)["run"] + " --allow-listen 5000"), "fresh")
mutate("rc job grants packages read", "permissions are not exactly", lambda j: j["permissions"].update(packages="read"))
mutate("rc job reads the job token", "names github.token", lambda j: next(x for x in j["steps"] if "crane push" in str(x.get("run", ""))).setdefault("env", {}).update(DIGESTS="${{ needs.build.outputs.digests }}", T="${{ github.token }}"))
mutate("rc job reads a registry secret", "reads secrets.GHCR_TOKEN", lambda j: next(x for x in j["steps"] if "crane push" in str(x.get("run", ""))).setdefault("env", {}).update(P="${{ secrets.GHCR_TOKEN }}"))
mutate("rc job needs release as well", "needs are not exactly build", lambda j: j.update(needs=["build", "release"]))
mutate("rc job runs in a dry run", "gate: a dry run on an rc tag", lambda j: j.update({"if": "${{ vars.PERSONA_UAT_ENABLED == 'true' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}"}))
mutate("rc job also runs on a final tag", "a final tag with the gate on runs the job", lambda j: j.update({"if": "${{ vars.PERSONA_UAT_ENABLED == 'true' && startsWith(github.ref, 'refs/tags/v') && !inputs.dry-run }}"}))
mutate("rc checkout keeps credentials", "persist-credentials must be false", lambda j: j["steps"].insert(0, {"uses": "actions/checkout@" + "a" * 40, "with": {}}))
mutate("rc image is a literal, not an expression", "takes the image from something other than Build's own image-production digest",
       lambda j: set_image(j, "localhost:5000/cache@fromJSON(needs.build.outputs.digests)['image-production']"))
mutate("rc image is a fixed digest", "takes the image from something other than Build's own image-production digest",
       lambda j: set_image(j, "ghcr.io/x/cache@sha256:" + "c" * 64))
mutate("rc gains a skipped dependency (decide)", "needs are not exactly build", lambda j: j.update(needs=list(j["needs"]) + ["decide"]))
mutate("rc upload may fail without failing the job", "without retaining its transcripts", lambda j: up(j).update({"continue-on-error": "true"}))
mutate("rc driver step carries an extra credential", "outside the contract", lambda j: drv(j).setdefault("env", {}).update(AWS_SECRET_ACCESS_KEY="x"))
mutate("rc identity step writes one file and the driver reads another", "which is the file the driver step reads",
       lambda j: next(s for s in j["steps"] if "github-script" in str(s.get("uses", ""))).setdefault("with", {}).update(script="const p='/a'; const q='/b'; fs.writeFileSync(p, token); core.exportVariable('ANTHROPIC_IDENTITY_TOKEN_FILE', q)"))
mutate("rc job has no checkout", "actions/checkout step(s) before the driver", lambda j: j.update(steps=[s for s in j["steps"] if "actions/checkout" not in str(s.get("uses", ""))]))
mutate("rc job checks out after the driver", "actions/checkout step(s) before the driver",
       lambda j: (lambda c: (j["steps"].remove(c), j["steps"].insert(j["steps"].index(drv(j)) + 1, c)))(next(s for s in j["steps"] if "actions/checkout" in str(s.get("uses", "")))))
mutate("release tags gain a negation", "push tags are not exactly", lambda j: None, "rel_tags")
mutate("rc job loses its SDK install", "expected exactly one hash-pinned SDK install", lambda j: j.update(steps=[s for s in j["steps"] if "persona-uat-requirements" not in str(s.get("run", ""))]))
mutate("rc job loses its pinned-pip step", "expected exactly one pinned-pip step", lambda j: j.update(steps=[s for s in j["steps"] if not is_pin_pip(s)]))
mutate("rc pinned-pip step runs after the SDK install", "expected exactly one pinned-pip step",
       lambda j: (lambda b: (j["steps"].remove(b), j["steps"].insert(j["steps"].index(next(s for s in j["steps"] if "persona-uat-requirements" in str(s.get("run", "")))) + 1, b)))(next(s for s in j["steps"] if is_pin_pip(s))))
mutate("rc pinned-pip step can be skipped (if)", "carries keys outside its allowlist", lambda j: next(s for s in j["steps"] if is_pin_pip(s)).update({"if": "false"}))
mutate("rc pinned-pip step loses --require-hashes", "expected exactly one pinned-pip step",
       lambda j: next(s for s in j["steps"] if is_pin_pip(s)).update(run=PIN_PIP_RUN.replace(" --require-hashes", "")))
mutate("rc SDK install runs before the checkout", "expected exactly one hash-pinned SDK install",
       lambda j: (lambda b: (j["steps"].remove(b), j["steps"].insert(0, b)))(next(s for s in j["steps"] if "persona-uat-requirements" in str(s.get("run", "")))))
mutate("persona-uat is added to patch-failed.needs (a persona failure would open a public issue)", "lists persona-uat in needs", lambda d: d["jobs"]["patch-failed"].update(needs=["image", "promotion", "persona-uat"]), "rel_wf")
def _tokvar(script):
    m = re.search(r"(?:const|let|var)\s+(\w+)\s*=\s*await\s+core\.getIDToken", script)
    return m.group(1) if m else "token"
def _id_step(j): return next(s for s in j["steps"] if "github-script" in str(s.get("uses", "")))
mutate("rc identity step prints the token", "logs the token",
       lambda j: _id_step(j)["with"].update(script=_id_step(j)["with"]["script"] + "\nconsole.log(" + _tokvar(_id_step(j)["with"]["script"]) + ")"))
mutate("rc identity step masks a literal, not the token", "mask THE TOKEN",
       lambda j: _id_step(j)["with"].update(script=re.sub(r"core\.setSecret\(\s*\w+\s*\)", "core.setSecret('x')", _id_step(j)["with"]["script"])))
mutate("rc driver's --recipient is commented out", "is not run with --recipient exactly once", lambda j: drv(j).update(run=drv(j)["run"].replace("--recipient", "# --recipient")))
mutate("rc driver step gets a working-directory", "a working-directory on the driver step", lambda j: drv(j).update({"working-directory": "release-docs"}))
mutate("rc job default working-directory", "a working-directory on the driver step", lambda j: j.update(defaults={"run": {"working-directory": "x"}}))
mutate("release.yml gets a workflow-level working-directory", "workflow-level working-directory", lambda j: None, which="rel_defaults")
mutate("go-freshness.yml gets a workflow-level working-directory", "workflow-level working-directory", lambda j: None, which="fresh_defaults")
mutate("release.yml gets a workflow-level default shell", "workflow-level default shell", lambda j: None, which="rel_defaults_shell")
mutate("weekly driver script is a .py.bak copy and gets a stray argument", "is not exactly `python3 bin/persona-uat.py", lambda j: drv(j).update(run=drv(j)["run"].replace("persona-uat.py", "persona-uat.py.bak", 1).rstrip() + " extra"), which="fresh")
mutate("rc driver script is a .py.bak copy", "is not exactly `python3 bin/persona-uat.py", lambda j: drv(j).update(run=drv(j)["run"].replace("persona-uat.py", "persona-uat.py.bak", 1)))
mutate("rc driver gets a stray positional token", "tokens that are no option or option value", lambda j: drv(j).update(run=drv(j)["run"].rstrip() + " extra"))
mutate("rc job uses an action by tag", "is not pinned to a commit digest", lambda j: j["steps"].insert(0, {"uses": "actions/checkout@v4"}))
mutate("rc driver step gains --publish (an issue would be opened)", "outside the contract", lambda j: drv(j).update(run=drv(j)["run"].rstrip() + " --publish"))
mutate("rc driver step drops --recipient", "--recipient", lambda j: drv(j).update(run=re.sub(r"--recipient\s+\S+", "", drv(j)["run"])))
mutate("rc job permissions gain contents: write", "permissions are not exactly", lambda j: j["permissions"].update(contents="write"))
mutate("rc job gains issues: write (an issue could be opened)", "permissions are not exactly", lambda j: j["permissions"].update(issues="write"))
mutate("rc job mints no model identity token", "mints the model identity token", lambda j: j.update(steps=[s for s in j["steps"] if "getIDToken" not in json.dumps(s)]))
# weekly job
mutate("weekly job runs on every cron", "does not run only on the Monday cron", lambda j: j.update({"if": "${{ github.event_name == 'schedule' }}"}), "fresh")
# the PERSONA_UAT_ENABLED gate (owner): each is caught for the reason named
RCIF = "${{ startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc.') }}"
WKIF = "${{ github.event.schedule == '43 6 * * 1' }}"
GATEST = {"if": "${{ vars.PERSONA_UAT_ENABLED == 'true' }}"}
mutate("rc job without the gate", "behind the PERSONA_UAT_ENABLED gate", lambda j: j.update({"if": RCIF}))
mutate("weekly job without the gate", "behind the PERSONA_UAT_ENABLED gate", lambda j: j.update({"if": WKIF}), "fresh")
mutate("rc gate compares another value", "behind the PERSONA_UAT_ENABLED gate", lambda j: j.update({"if": str(j["if"]).replace("== 'true'", "!= 'false'")}))
mutate("weekly gate compares another value", "behind the PERSONA_UAT_ENABLED gate", lambda j: j.update({"if": str(j["if"]).replace("== 'true'", "!= 'false'")}), "fresh")
mutate("rc gate OR-ed with the trigger", "behind the PERSONA_UAT_ENABLED gate", lambda j: j.update({"if": str(j["if"]).replace("' && startsWith", "' || startsWith")}))
mutate("rc gate moved to a step (the environment would be entered first)", "behind the PERSONA_UAT_ENABLED gate", lambda j: (j.update({"if": RCIF}), j["steps"][0].update(GATEST)))
mutate("weekly gate moved to a step (the environment would be entered first)", "behind the PERSONA_UAT_ENABLED gate", lambda j: (j.update({"if": WKIF}), j["steps"][0].update(GATEST)), "fresh")
mutate("rc gate also tested in a step", "tests the gate", lambda j: j["steps"][0].update(GATEST))
mutate("weekly gate also tested in a step", "tests the gate", lambda j: j["steps"][0].update(GATEST), "fresh")
mutate("rc workflow: another job enters the persona-uat environment", "outside the gated job", lambda d: d["jobs"].update(other={"environment": "persona-uat", "steps": [{"run": "true"}]}), "rel_wf")
mutate("weekly workflow: another job enters the persona-uat environment", "outside the gated job", lambda d: d["jobs"].update(other={"environment": "persona-uat", "steps": [{"run": "true"}]}), "fresh_wf")
mutate("rc workflow: another job mints the model identity token", "outside the gated job", lambda d: d["jobs"].update(other={"steps": [{"uses": "actions/github-script@" + "a" * 40, "with": {"script": "await core.getIDToken('https://api.anthropic.com')"}}]}), "rel_wf")
mutate("weekly workflow: another job mints the model identity token", "outside the gated job", lambda d: d["jobs"].update(other={"steps": [{"uses": "actions/github-script@" + "a" * 40, "with": {"script": "await core.getIDToken('https://api.anthropic.com')"}}]}), "fresh_wf")
mutate("weekly job resolves a fixed release tag", "does not resolve the LATEST release's image digest",
       lambda j: next(s for s in j["steps"] if "gh release view" in str(s.get("run", ""))).update(run="gh release view v0.2.0 --json tagName; crane digest x"), "fresh")
mutate("weekly driver is handed a fixed image", "does not hand the resolved latest-release image digest",
       lambda j: drv(j).update(run=re.sub(r"--image\s+\S+", "--image ghcr.io/x/cache@sha256:" + "a" * 64, drv(j)["run"])), "fresh")
mutate("weekly cron literal reformatted", "does not run only on the Monday cron", lambda j: j.update({"if": "${{ github.event.schedule == '436**1' }}"}), "fresh")
mutate("weekly resolver moved after the driver", "AFTER running the driver", lambda j: (lambda r: (j["steps"].remove(r), j["steps"].insert(j["steps"].index(drv(j)) + 1, r)))(next(s for s in j["steps"] if "gh release view" in str(s.get("run", "")))), "fresh")
mutate("weekly resolver uses a fixed tag variable", "does not resolve the LATEST release's image digest",
       lambda j: next(s for s in j["steps"] if "gh release view" in str(s.get("run", ""))).update(run='tag=v0.1.0; gh release view "$tag" --json tagName; d=$(crane digest "ghcr.io/x/cache:$tag"); echo "image=$d" >> "$GITHUB_OUTPUT"'), "fresh")
mutate("weekly resolver inspects an unrelated tag", "does not read the digest of the release it just resolved",
       lambda j: next(s for s in j["steps"] if "gh release view" in str(s.get("run", ""))).update(run=re.sub(r"crane digest \S+", "crane digest ghcr.io/x/cache:latest", next(s for s in j["steps"] if "gh release view" in str(s.get("run", "")))["run"])), "fresh")
mutate("weekly driver image argument fully replaced", "does not hand the resolved latest-release image digest",
       lambda j: set_image(j, "ghcr.io/x/cache@sha256:" + "a" * 64), "fresh")
mutate("weekly image is the literal text, not an expression", "does not hand the resolved latest-release image digest",
       lambda j: set_image(j, "steps." + next(s for s in j["steps"] if "gh release view" in str(s.get("run", "")))["id"] + ".outputs.image"), "fresh")
def _docs_checkout(j): return next(s for s in j["steps"] if "actions/checkout" in str(s.get("uses", "")) and str((s.get("with", {}) or {}).get("path", "")) == "release-docs")
def _harness_checkout(j): return next(s for s in j["steps"] if "actions/checkout" in str(s.get("uses", "")) and not str((s.get("with", {}) or {}).get("path", "")))
def _resolver(j): return next(s for s in j["steps"] if "gh release view" in str(s.get("run", "")))
def _swap_checkouts(j):
    a, b = _harness_checkout(j), _docs_checkout(j)
    ia, ib = j["steps"].index(a), j["steps"].index(b)
    j["steps"][ia], j["steps"][ib] = b, a
mutate("weekly docs checkout is of main, not the resolved tag", "checkout is not of the resolved release's tag", lambda j: _docs_checkout(j)["with"].pop("ref"), "fresh")
mutate("weekly root checkout takes a ref (an old release has no driver)", "root checkout must be today's main", lambda j: _harness_checkout(j)["with"].update(ref="v0.2.1"), "fresh")
mutate("weekly root checkout takes the resolved tag as its ref", "root checkout must be today's main", lambda j: _harness_checkout(j)["with"].update(ref="${{ steps.resolve.outputs.tag }}"), "fresh")
mutate("weekly root checkout is another repository", "root checkout must be today's main", lambda j: _harness_checkout(j)["with"].update(repository="evil/other"), "fresh")
mutate("weekly harness checkout under path: harness (the old layout)", "the two checkouts must be, in this order", lambda j: _harness_checkout(j).setdefault("with", {}).update(path="harness"), "fresh")
mutate("weekly checkouts in the other order (docs first)", "the two checkouts must be, in this order", lambda j: _swap_checkouts(j), "fresh")
mutate("weekly job has a single checkout", "expected exactly 2 actions/checkout", lambda j: j.update(steps=[s for s in j["steps"] if s is not _harness_checkout(j)]), "fresh")
mutate("weekly job gains needs (skipped on the Monday cron)", "has needs", lambda j: j.update(needs=["check"]), "fresh")
mutate("weekly resolver emits tag=main", "does not write tag=<release tag>",
       lambda j: _resolver(j).update(run=re.sub(r"(?m)^.*tag=.*GITHUB_OUTPUT.*$", 'echo "tag=main" >> "$GITHUB_OUTPUT"', _resolver(j)["run"])), "fresh")
mutate("weekly resolver inspects the v-prefixed image tag", "resolver failed against recording gh/crane",
       lambda j: _resolver(j).update(run=_resolver(j)["run"].replace("${tag#v}", "${tag}")), "fresh")
mutate("weekly resolver reads the manifest, not the digest (another crane verb)", "resolver failed against recording gh/crane",
       lambda j: _resolver(j).update(run=_resolver(j)["run"].replace("crane digest", "crane manifest")), "fresh")
def _crane(j): return next(s for s in j["steps"] if "install-scanner.sh crane" in str(s.get("run", "")))
mutate("weekly resolver reads the digest with buildx again (rule 61)", "uses docker or buildx",
       lambda j: _resolver(j).update(run=_resolver(j)["run"].replace('crane digest "ghcr.io/${REGISTRY_OWNER}/cache:${tag#v}"', 'docker buildx imagetools inspect "ghcr.io/${REGISTRY_OWNER}/cache:${tag#v}" --format \'{{.Manifest.Digest}}\'')), "fresh")
mutate("weekly resolver reads the digest with docker manifest inspect", "uses docker or buildx",
       lambda j: _resolver(j).update(run=_resolver(j)["run"].replace('crane digest "ghcr.io/${REGISTRY_OWNER}/cache:${tag#v}"', 'docker manifest inspect "ghcr.io/${REGISTRY_OWNER}/cache:${tag#v}"')), "fresh")
mutate("weekly resolver falls back to a fixed digest when crane fails", "no pipe or fallback",
       lambda j: _resolver(j).update(run=_resolver(j)["run"].replace('crane digest "ghcr.io/${REGISTRY_OWNER}/cache:${tag#v}")', 'crane digest "ghcr.io/${REGISTRY_OWNER}/cache:${tag#v}" || echo sha256:' + "a" * 64 + ')')), "fresh")
mutate("weekly resolver follows the digest with a plain || fallback (no later parenthesis)", "no pipe or fallback",
       lambda j: _resolver(j).update(run=_resolver(j)["run"].replace('crane digest "ghcr.io/${REGISTRY_OWNER}/cache:${tag#v}")', 'crane digest "ghcr.io/${REGISTRY_OWNER}/cache:${tag#v}") || d=sha256:' + "a" * 64)), "fresh")
mutate("weekly resolver wraps the digest read in an if-not", "no pipe or fallback",
       lambda j: _resolver(j).update(run=re.sub(r"(?m)^(\w+)=(\$\(crane digest [^\n]*\))$", r"if ! \1=\2; then \1=sha256:" + "a" * 64 + "; fi", _resolver(j)["run"])), "fresh")
mutate("weekly resolver pipes the output after the substitution", "no pipe or fallback",
       lambda j: _resolver(j).update(run=_resolver(j)["run"].replace('crane digest "ghcr.io/${REGISTRY_OWNER}/cache:${tag#v}")', 'crane digest "ghcr.io/${REGISTRY_OWNER}/cache:${tag#v}") | cat')), "fresh")
mutate("weekly resolver puts the digest read in a group with a fallback after it", "is not one of the five allowed shapes",
       lambda j: _resolver(j).update(run=re.sub(r"(?m)^(\w+=\$\(crane digest [^\n]*\))$", lambda m: "{\n" + m.group(1) + "\n} || " + m.group(1).split("=")[0] + "=sha256:" + "a" * 64, _resolver(j)["run"])), "fresh")
mutate("weekly resolver turns errexit off before the digest read", "is not one of the five allowed shapes",
       lambda j: _resolver(j).update(run=_resolver(j)["run"].replace("tag=$(gh release view", "set +e\ntag=$(gh release view", 1)), "fresh")
mutate("weekly resolver reassigns the digest on a line of its own", "is not one of the five allowed shapes",
       lambda j: _resolver(j).update(run=re.sub(r"(?m)^(\w+)=\$\(crane digest [^\n]*\)$", lambda m: m.group(0) + "\n" + m.group(1) + "=sha256:" + "a" * 64, _resolver(j)["run"])), "fresh")
mutate("weekly resolver does not start with set -euo pipefail", "is not one of the five allowed shapes",
       lambda j: _resolver(j).update(run=_resolver(j)["run"].replace("set -euo pipefail\n", "", 1)), "fresh")
mutate("weekly resolver writes a second image= line after the real one", "is not one of the five allowed shapes",
       lambda j: _resolver(j).update(run=_resolver(j)["run"] + '\necho "image=ghcr.io/evil/cache@sha256:' + "b" * 64 + '" >> "$GITHUB_OUTPUT"'), "fresh")
mutate("weekly resolver writes a second tag= line", "is not one of the five allowed shapes",
       lambda j: _resolver(j).update(run=_resolver(j)["run"] + '\necho "tag=v9.9.9" >> "$GITHUB_OUTPUT"'), "fresh")
mutate("weekly resolver runs a command substitution inside the image text", "is not one of the five allowed shapes",
       lambda j: _resolver(j).update(run=re.sub(r'(?m)^(echo "image=[^"\n]*)(" >> "\$GITHUB_OUTPUT")$', lambda m: m.group(1) + "$(true)" + m.group(2), _resolver(j)["run"])), "fresh")
mutate("weekly resolver runs a backtick command inside the crane reference", "is not one of the five allowed shapes",
       lambda j: _resolver(j).update(run=_resolver(j)["run"].replace('cache:${tag#v}")', 'cache:${tag#v}`true`")')), "fresh")
mutate("weekly resolver rewrites the owner with a parameter expansion", "is not one of the five allowed shapes",
       lambda j: _resolver(j).update(run=_resolver(j)["run"].replace("${REGISTRY_OWNER}/cache:", "${REGISTRY_OWNER/#[!o]*/attacker}/cache:")), "fresh")
mutate("weekly resolver reads a second digest with another crane line", "is not one of the five allowed shapes",
       lambda j: _resolver(j).update(run=re.sub(r'(?m)^(\w+)=\$\(crane digest ([^\n]*)\)$', lambda m: m.group(0) + "\nz=$(crane digest " + m.group(2) + ")", _resolver(j)["run"])), "fresh")
mutate("weekly job-level env exports a shell function (BASH_FUNC_crane%%)", "env must be empty", lambda j: j.update(env={"BASH_FUNC_crane%%": "() { echo sha256:evil; }"}), "fresh")
mutate("weekly job-level env sets OPENSSL_CONF", "env must be empty", lambda j: j.update(env={"OPENSSL_CONF": "/tmp/x"}), "fresh")
mutate("weekly job-level env holds a harmless-looking key", "env must be empty", lambda j: j.update(env={"FOO": "1"}), "fresh")
mutate("rc job-level env sets REQUESTS_CA_BUNDLE", "env must be empty", lambda j: j.update(env={"REQUESTS_CA_BUNDLE": "/tmp/x"}))
mutate("rc job-level env holds a harmless-looking key", "env must be empty", lambda j: j.update(env={"FOO": "1"}))
mutate("weekly job-level env sets BASH_ENV", "env must be empty", lambda j: j.update(env={"BASH_ENV": "$(true)"}), "fresh")
mutate("rc job-level env sets PATH", "env must be empty", lambda j: j.update(env={"PATH": "/tmp/x:/usr/bin"}))
mutate("weekly resolver step env sets BASH_ENV", "resolver step's env must be exactly", lambda j: _resolver(j).setdefault("env", {}).update(BASH_ENV="$(true)"), "fresh")
mutate("weekly resolver step env sets GH_HOST", "resolver step's env must be exactly", lambda j: _resolver(j).setdefault("env", {}).update(GH_HOST="evil.example"), "fresh")
mutate("weekly resolver pipes the digest through another command", "no pipe or fallback",
       lambda j: _resolver(j).update(run=_resolver(j)["run"].replace('crane digest "ghcr.io/${REGISTRY_OWNER}/cache:${tag#v}")', 'crane digest "ghcr.io/${REGISTRY_OWNER}/cache:${tag#v}" | head -n1)')), "fresh")
mutate("weekly job has no crane install", "must install crane with exactly one step", lambda j: j["steps"].remove(_crane(j)), "fresh")
mutate("weekly job installs crane twice", "must install crane with exactly one step", lambda j: j["steps"].insert(j["steps"].index(_crane(j)) + 1, dict(_crane(j))), "fresh")
mutate("weekly crane install into a directory of its own (not the installer's default)", "must install crane with exactly one step", lambda j: _crane(j).update(run="./bin/install-scanner.sh crane /opt/crane-elsewhere"), "fresh")
mutate("weekly crane install runs AFTER the resolver", "AFTER the resolver", lambda j: (lambda c: (j["steps"].remove(c), j["steps"].insert(j["steps"].index(_resolver(j)) + 1, c)))(_crane(j)), "fresh")
mutate("weekly crane install runs BEFORE the root checkout", "BEFORE the checkout that provides bin/install-scanner.sh", lambda j: (lambda c: (j["steps"].remove(c), j["steps"].insert(0, c)))(_crane(j)), "fresh")
mutate("weekly crane install is conditional", "crane install step is conditional or non-fatal", lambda j: _crane(j).update({"if": "false"}), "fresh")
mutate("weekly crane install carries an env", "crane install step has a custom shell, working-directory or env", lambda j: _crane(j).update(env={"X": "1"}), "fresh")
mutate("weekly resolver has no GH_REPO", "needs env GH_REPO", lambda j: _resolver(j)["env"].pop("GH_REPO"), "fresh")
mutate("weekly docs checkout of another repository", "checkout of another repository", lambda j: _docs_checkout(j)["with"].update(repository="evil/cache"), "fresh")
mutate("rc checkout takes ref main", "release-candidate checkout is not of the candidate commit", lambda j: next(s for s in j["steps"] if "actions/checkout" in str(s.get("uses", ""))).setdefault("with", {}).update(ref="main"))
mutate("rc job-level if: false", "does not run only for a release-candidate tag", lambda j: j.update({"if": "false"}))
mutate("rc checkout with if: false", "checkout step is conditional or non-fatal", lambda j: next(x for x in j["steps"] if "actions/checkout" in str(x.get("uses", ""))).update({"if": "false"}))
mutate("rc SDK install continue-on-error: true", "SDK install step is conditional or non-fatal", lambda j: next(x for x in j["steps"] if "persona-uat-requirements" in str(x.get("run", ""))).update({"continue-on-error": "true"}))
mutate("rc runs-on windows-latest", "not an ubuntu runner", lambda j: j.update({"runs-on": "windows-latest"}))
mutate("rc matrix duplicating the job", "strategy/matrix", lambda j: j.update({"strategy": {"matrix": {"n": ["1", "2"]}}}))
mutate("rc kind check missing", "exactly one step",
       lambda j: j["steps"].remove(next(x for x in j["steps"] if "kind version" in str(x.get("run", "")))))
mutate("weekly job-level if: false", "does not run only on the Monday cron", lambda j: j.update({"if": "false"}), "fresh")
mutate("weekly checkout with if: false", "checkout step is conditional or non-fatal", lambda j: next(x for x in j["steps"] if "actions/checkout" in str(x.get("uses", ""))).update({"if": "false"}), "fresh")
mutate("weekly SDK install continue-on-error: true", "SDK install step is conditional or non-fatal", lambda j: next(x for x in j["steps"] if "persona-uat-requirements" in str(x.get("run", ""))).update({"continue-on-error": "true"}), "fresh")
mutate("weekly runs-on windows-latest", "not an ubuntu runner", lambda j: j.update({"runs-on": "windows-latest"}), "fresh")
mutate("weekly matrix duplicating the job", "strategy/matrix", lambda j: j.update({"strategy": {"matrix": {"n": ["1", "2"]}}}), "fresh")
mutate("weekly kind check missing", "exactly one step",
       lambda j: j["steps"].remove(next(x for x in j["steps"] if x.get("run") == KIND_RUN)), "fresh")
mutate("rc checkout of another repository", "checkout of another repository", lambda j: next(s for s in j["steps"] if "actions/checkout" in str(s.get("uses", ""))).setdefault("with", {}).update(repository="evil/cache"))
mutate("rc driver step reads another identity token file", "is not exactly ${{ runner.temp }}/anthropic-identity-token", lambda j: drv(j).setdefault("env", {}).update(ANTHROPIC_IDENTITY_TOKEN_FILE="/missing"))
mutate("rc driver step has no identity token file path", "is not exactly ${{ runner.temp }}/anthropic-identity-token", lambda j: drv(j)["env"].pop("ANTHROPIC_IDENTITY_TOKEN_FILE"))
mutate("rc identity step never awaits the token", "does not mint (await)",
       lambda j: (lambda s_: s_["with"].update(script=s_["with"]["script"].replace("await core.getIDToken", "core.getIDToken")))(next(s for s in j["steps"] if "github-script" in str(s.get("uses", "")))))
mutate("rc SDK install without hashes", "a run step before the driver other than",
       lambda j: next(s for s in j["steps"] if "persona-uat-requirements" in str(s.get("run", ""))).update(run="python3 -m pip install anthropic"))
mutate("tools: all nine point at one image", "not distinct images", lambda t: t.update({k: t["shell"] for k in t}), "tools")
mutate("tools: jenkins names another image", "does not name its own official image", lambda t: t.update(jenkins=t["shell"]), "tools")
mutate("weekly job leaves the persona-uat environment", "does not run in the persona-uat environment", lambda j: j.pop("environment"), "fresh")
mutate("weekly resolver is conditional", "resolver step is conditional or non-fatal",
       lambda j: next(s for s in j["steps"] if "gh release view" in str(s.get("run", ""))).update({"if": "false"}), "fresh")
mutate("weekly resolver does not capture a crane digest (a fixed value instead)", "does not capture the digest",
       lambda j: (lambda r: r.update(run=r["run"].replace('$(crane digest "ghcr.io/${REGISTRY_OWNER}/cache:${tag#v}")', '$(echo sha256:' + "a" * 64 + ')')))(next(s for s in j["steps"] if "gh release view" in str(s.get("run", "")))), "fresh")
mutate("weekly resolver emits an unrelated fixed digest", "built from the digest it inspected",
       lambda j: (lambda r: r.update(run=re.sub(r'image=[^\n]*>>', 'image=ghcr.io/x/cache@sha256:' + 'a' * 64 + ' >>', r["run"])))(next(s for s in j["steps"] if "gh release view" in str(s.get("run", "")))), "fresh")
mutate("rc driver is given a second --mode (last wins)", "--mode exactly once", lambda j: drv(j).update(run=drv(j)["run"].rstrip() + " --mode weekly"))
mutate("rc driver is given a second --image (last wins)", "--image exactly once", lambda j: drv(j).update(run=drv(j)["run"].rstrip() + " --image ghcr.io/x/cache@sha256:" + "b" * 64))
mutate("rc driver --repo points elsewhere", "--repo is not the docs checkout", lambda j: drv(j).update(run=re.sub(r"--repo\s+\S+", "--repo /tmp/empty", drv(j)["run"])))
mutate("rc model id is the literal text of the expression", "is not exactly secrets.PERSONA_UAT_MODEL", lambda j: drv(j)["env"].update(PERSONA_UAT_MODEL="secrets.PERSONA_UAT_MODEL"))
mutate("rc secret is the literal text", "is not exactly secrets.ANTHROPIC_WORKSPACE_ID", lambda j: drv(j)["env"].update(ANTHROPIC_WORKSPACE_ID="secrets.ANTHROPIC_WORKSPACE_ID"))
mutate("rc driver step carries GH_TOKEN (no gh call is made)", "carries a GitHub token", lambda j: drv(j)["env"].update(GH_TOKEN="${{ github.token }}"))
mutate("rc identity step provisions cloud inside github-script", "runs a command or names a cloud CLI",
       lambda j: next(s for s in j["steps"] if "github-script" in str(s.get("uses", ""))).setdefault("with", {}).update(script="await exec.exec('aws', ['ec2','run-instances'])"))
mutate("rc identity step is conditional", "identity step has an if", lambda j: next(s for s in j["steps"] if "github-script" in str(s.get("uses", ""))).update({"if": "false"}))
mutate("rc identity step exports a path it never writes", "does not write the token to a file",
       lambda j: next(s for s in j["steps"] if "github-script" in str(s.get("uses", ""))).setdefault("with", {}).update(script="core.exportVariable('ANTHROPIC_IDENTITY_TOKEN_FILE', '/nonexistent')"))
mutate("release.yml loses its v* tag trigger", "push tags are not exactly", lambda j: None, "rel_top")
mutate("rc driver mode is a prefix, --mode rcoops", "--mode rc exactly", lambda j: drv(j).update(run=drv(j)["run"].replace("--mode rc", "--mode rcoops")))
mutate("rc driver mode in the = form with a suffix", "--mode rc exactly", lambda j: drv(j).update(run=drv(j)["run"].replace("--mode rc", "--mode=rc2")))
mutate("weekly driver mode is a prefix, --mode weekly2", "--mode weekly exactly", lambda j: drv(j).update(run=drv(j)["run"].replace("--mode weekly", "--mode weekly2")), "fresh")
mutate("weekly driver runs in rc mode", "--mode weekly", lambda j: drv(j).update(run=drv(j)["run"].replace("--mode weekly", "--mode rc")), "fresh")
mutate("weekly driver step is non-fatal", "not exactly one bare driver command", lambda j: drv(j).update(run=drv(j)["run"].rstrip() + " || true"), "fresh")
# tools file
mutate("tools: jenkins by tag", "tool jenkins is not pinned by digest", lambda t: t.update(jenkins="docker.io/jenkins/jenkins:lts"), "tools")
mutate("tools: the persona shell by tag", "tool shell is not pinned by digest", lambda t: t.update(shell="docker.io/library/debian:12"), "tools")
mutate("tools: the kind entry is missing", "must hold exactly the keys", lambda t: t.pop("kind"), "tools")
mutate("tools: an extra tool appears", "must hold exactly the keys", lambda t: t.update(terraform="docker.io/hashicorp/terraform@sha256:" + "5" * 64), "tools")
# delta 2 (advisor 0207, and the capture sidecar's image): nine entries, each official, digest-pinned and distinct
for k in ("cosign", "kubectl", "gradle", "maven", "gitlab-runner", "jenkins", "shell"):
    mutate(f"tools: the {k} entry is missing", "must hold exactly the keys", lambda t, k=k: t.pop(k), "tools")
for k in ("cosign", "kubectl", "gradle", "maven", "gitlab-runner", "kind"):
    mutate(f"tools: {k} by tag", f"tool {k} is not pinned by digest", lambda t, k=k: t.update({k: t[k].split("@")[0] + ":latest"}), "tools")
    mutate(f"tools: {k} by a short digest", f"tool {k} is not pinned by digest", lambda t, k=k: t.update({k: t[k].split("@")[0] + "@sha256:abc"}), "tools")
mutate("tools: gradle names the maven image", "tool gradle does not name its own official image", lambda t: t.update(gradle="docker.io/library/maven@sha256:" + "7" * 64), "tools")
mutate("tools: kubectl from a lookalike repository", "tool kubectl does not name its own official image", lambda t: t.update(kubectl="docker.io/evil/kubectl@sha256:" + "6" * 64), "tools")
mutate("tools: kubectl from a third-party packager", "tool kubectl does not name its own official image", lambda t: t.update(kubectl="docker.io/bitnami/kubectl@sha256:" + "6" * 64), "tools")
mutate("tools: kubectl under a lookalike path of the official registry", "tool kubectl does not name its own official image", lambda t: t.update(kubectl="registry.k8s.io/evil/kubectl@sha256:" + "6" * 64), "tools")
mutate("tools: cosign from a lookalike repository", "tool cosign does not name its own official image", lambda t: t.update(cosign="ghcr.io/evil/cosign/cosign@sha256:" + "5" * 64), "tools")
mutate("tools: gradle from an unofficial registry", "tool gradle does not name its own official image", lambda t: t.update(gradle="evil.example/gradle@sha256:" + "7" * 64), "tools")
mutate("tools: maven under a suffix-matching namespace", "tool maven does not name its own official image", lambda t: t.update(maven="docker.io/evil/maven@sha256:" + "8" * 64), "tools")
mutate("tools: the shell is not the curl image", "tool shell does not name its own official image", lambda t: t.update(shell="docker.io/library/debian@sha256:" + "4" * 64), "tools")
mutate("tools: the capture image is a lookalike repository", "tool capture does not name its own official image", lambda t: t.update(capture="docker.io/evil/netshoot@sha256:" + "b" * 64), "tools")
mutate("tools: the capture image is not pinned by digest", "tool capture is not pinned by digest", lambda t: t.update(capture="docker.io/nicolaka/netshoot:latest"), "tools")
mutate("tools: the capture entry is missing", "must hold exactly the keys", lambda t: t.pop("capture"), "tools")
mutate("tools: the capture entry shares the shell's digest", "not distinct images", lambda t: t.update(capture="docker.io/nicolaka/netshoot@sha256:" + "4" * 64), "tools")
mutate("tools: two entries share one digest", "not distinct images", lambda t: t.update(kubectl="registry.k8s.io/kubectl@sha256:" + "8" * 64), "tools")
for variant, key, ref in (("cosign from ghcr", "cosign", "ghcr.io/sigstore/cosign/cosign@sha256:" + "5" * 64), ("gradle without library/", "gradle", "docker.io/gradle@sha256:" + "7" * 64)):
    good = []
    judge_tools({**TGOOD, key: ref}, good)
    result(not good, f"the judge accepts an official spelling ({variant})" + ("" if not good else ": " + "; ".join(good)))
# the host network is a refused vector in every source
mutate("source: a host-network container start in the driver", "puts a container on the host's network", lambda srcs: srcs.update({SRC[0]: 'args = ["run", "-d", "--network", "host"]\n'}), "src")
mutate("source: a host-network container start in the agent", "puts a container on the host's network", lambda srcs: srcs.update({SRC[1]: 'argv = ["docker", "run", "--rm", "--net", "host", img]\n'}), "src")
mutate("source: --network=host", "puts a container on the host's network", lambda srcs: srcs.update({SRC[0]: 'args = ["run", "--network=host"]\n'}), "src")
mutate("source: --net host in a joined string", "puts a container on the host's network", lambda srcs: srcs.update({SRC[2]: 'cmd = "docker run --net host img"\n'}), "src")
# delta 1: nothing in the sources starts a privileged container
mutate("source: a privileged container start in the driver", "starts a privileged container", lambda srcs: srcs.update({SRC[0]: 'args = ["run", "-d", "--privileged"]\n'}), "src")
mutate("source: a privileged flag in the agent", "starts a privileged container", lambda srcs: srcs.update({SRC[1]: 'argv = ["docker", "run", "--privileged", img]\n'}), "src")
mutate("source: privileged=True", "starts a privileged container", lambda srcs: srcs.update({SRC[0]: "d.start(ref, privileged=True)\n"}), "src")

# --- round 3: environment at EVERY scope (workflow, job, step) and the checkout/SDK prerequisites -----------------------------------------------------
VEND = "cla" + "ude-fixture"        # a model name, assembled so no file names one
for lab, w in (("release.yml", "rel_wf"), ("go-freshness.yml", "fresh_wf")):
    mutate(f"{lab}: workflow-level env sets BASH_ENV", "env must be empty", lambda d: d.update(env={"BASH_ENV": "$(true)"}), w)
    mutate(f"{lab}: workflow-level env sets PATH", "env must be empty", lambda d: d.update(env={"PATH": "/tmp/x:/usr/bin"}), w)
    mutate(f"{lab}: workflow-level env sets a proxy", "env must be empty", lambda d: d.update(env={"HTTPS_PROXY": "http://x:1"}), w)
    mutate(f"{lab}: workflow-level env exports a shell function (BASH_FUNC_gh%%)", "env must be empty", lambda d: d.update(env={"BASH_FUNC_gh%%": "() { echo v1.0.0; }"}), w)
    mutate(f"{lab}: workflow-level env sets OPENSSL_CONF", "env must be empty", lambda d: d.update(env={"OPENSSL_CONF": "/tmp/x"}), w)
    mutate(f"{lab}: workflow-level env sets REQUESTS_CA_BUNDLE", "env must be empty", lambda d: d.update(env={"REQUESTS_CA_BUNDLE": "/tmp/x"}), w)
    mutate(f"{lab}: workflow-level env holds a harmless-looking key", "env must be empty", lambda d: d.update(env={"FOO": "1"}), w)
    mutate(f"{lab}: workflow-level env holds the model API key", "workflow-level env", lambda d: d.update(env={"ANTHROPIC_API_KEY": "${{ secrets.ANTHROPIC_API_KEY }}"}), w)
    mutate(f"{lab}: workflow-level env holds a federation secret", "workflow-level env", lambda d: d.update(env={"ANTHROPIC_WORKSPACE_ID": "${{ secrets.ANTHROPIC_WORKSPACE_ID }}"}), w)
    mutate(f"{lab}: workflow-level env aliases a secret under another name", "workflow-level env", lambda d: d.update(env={"HARMLESS": "${{ secrets.ANTHROPIC_WORKSPACE_ID }}"}), w)
    mutate(f"{lab}: workflow-level env holds the owner's model variable", "workflow-level env", lambda d: d.update(env={"PERSONA_UAT_MODEL": "${{ vars.PERSONA_UAT_MODEL }}"}), w)
    mutate(f"{lab}: workflow-level env writes a model name", "workflow-level env", lambda d: d.update(env={"MODEL": VEND}), w)
    mutate(f"{lab}: workflow-level env holds a cloud credential", "workflow-level env", lambda d: d.update(env={"AWS_SECRET_ACCESS_KEY": "${{ secrets.AWS_SECRET_ACCESS_KEY }}"}), w)
    mutate(f"{lab}: workflow-level env carries the job token under another name", "workflow-level env", lambda d: d.update(env={"X": "${{ github.token }}"}), w)
mutate("go-freshness.yml gets a workflow-level default shell", "workflow-level default shell", lambda d: d.update(defaults={"run": {"shell": "pwsh"}}), "fresh_wf")
mutate("rc upload with NO artifact name (the action defaults to 'artifact')", "no artifact name", lambda j: up(j)["with"].pop("name"))
mutate("weekly upload with NO artifact name", "no artifact name", lambda j: up(j)["with"].pop("name"), "fresh")
mutate("rc upload under another fixed name than the decrypt script downloads", "decrypt script downloads", lambda j: up(j)["with"].update(name="persona-uat-results"))
mutate("weekly upload under another fixed name than the decrypt script downloads", "decrypt script downloads", lambda j: up(j)["with"].update(name="persona-uat-results"), "fresh")
for lab_, txt_ in (("without any -n (downloads every artifact, nested)", 'gh run download "$run" -R "$repo" --dir "$art"\n'),
                   ("with two -n (nested again)", 'gh run download "$run" -n persona-uat-encrypted -n other --dir "$art"\n'),
                   ("with another name", 'gh run download "$run" -n persona-uat-results --dir "$art"\n'),
                   ("with --name=", 'gh run download "$run" --name=persona-uat-other --dir "$art"\n')):
    bd_ = []
    judge_script_artifact(txt_, "persona-uat-encrypted", "synth", bd_)
    result(bool(bd_), f"caught: a decrypt script {lab_}" + ("" if bd_ else "; saw nothing"))
for lab_, txt_ in (("with a stray -n elsewhere in the script and none on the download", 'sort -n x\ngh run download "$run" --dir "$art"\n'),
                   ("whose only mention of the right name is a comment", '# gh run download "$run" -n persona-uat-encrypted\ngh run download "$run" --dir "$art"\n'),
                   ("with the right name only in an unrelated command", 'echo -n persona-uat-encrypted\ngh run download "$run" --dir "$art"\n'),
                   ("that downloads twice", 'gh run download "$run" -n persona-uat-encrypted --dir a\ngh run download "$run" -n persona-uat-encrypted --dir b\n'),
                   ("that never downloads", 'echo nothing\n')):
    bd_ = []
    judge_script_artifact(txt_, "persona-uat-encrypted", "synth", bd_)
    result(bool(bd_), f"caught: a decrypt script {lab_}" + ("" if bd_ else "; saw nothing"))
bd_ = []
judge_script_artifact('# fetch\nsort -n x\ngh run download "$run" \\\n  -R "$repo" -n persona-uat-encrypted --dir "$art"\n', "persona-uat-encrypted", "synth", bd_)
result(not bd_, "a decrypt script with a continued download line, a comment and an unrelated -n elsewhere passes the tie when the download's own -n is right" + ("" if not bd_ else ": " + "; ".join(bd_)))
bd_ = []
judge_script_artifact('gh run download "$run" -n persona-uat-encrypted --dir "$art"\n', "persona-uat-encrypted", "synth", bd_)
result(not bd_, "a decrypt script that downloads exactly the upload's name passes the tie" + ("" if not bd_ else ": " + "; ".join(bd_)))
mutate("rc job-level env aliases a secret", "job-level env", lambda j: j.setdefault("env", {}).update(HARMLESS="${{ secrets.ANTHROPIC_WORKSPACE_ID }}"))
mutate("rc job-level env writes a model name", "job-level env", lambda j: j.setdefault("env", {}).update(M=VEND))
mutate("weekly job-level env aliases a secret", "job-level env", lambda j: j.setdefault("env", {}).update(HARMLESS="${{ secrets.ANTHROPIC_WORKSPACE_ID }}"), "fresh")
mutate("rc SDK install step aliases a secret in its env", "step other than the driver", lambda j: next(x for x in j["steps"] if "persona-uat-requirements" in str(x.get("run", ""))).update(env={"X": "${{ secrets.ANTHROPIC_WORKSPACE_ID }}"}))
mutate("rc identity step aliases the owner's variable in its env", "step other than the driver", lambda j: next(x for x in j["steps"] if "github-script" in str(x.get("uses", ""))).update(env={"X": "${{ vars.PERSONA_UAT_MODEL }}"}))
mutate("weekly upload step carries a model name in its env", "step other than the driver", lambda j: next(x for x in j["steps"] if "upload-artifact" in str(x.get("uses", ""))).update(env={"X": VEND}), "fresh")
mutate("rc job default shell is not bash", "default shell is not plain bash", lambda j: j.update(defaults={"run": {"shell": "pwsh"}}))
mutate("weekly job default working-directory", "a working-directory on the driver step", lambda j: j.update(defaults={"run": {"working-directory": "x"}}), "fresh")
for lab, w in (("rc", "rel"), ("weekly", "fresh")):
    co = lambda j: next(x for x in j["steps"] if "actions/checkout" in str(x.get("uses", "")))
    mutate(f"{lab} checkout with sparse-checkout that omits docs/", "options outside its allowlist", lambda j: co(j).setdefault("with", {}).update({"sparse-checkout": "bin\nREADME.md", "sparse-checkout-cone-mode": "false"}), w)
    mutate(f"{lab} checkout with cone-mode sparse-checkout", "options outside its allowlist", lambda j: co(j).setdefault("with", {}).update({"sparse-checkout": "bin", "sparse-checkout-cone-mode": "true"}), w)
    mutate(f"{lab} checkout with a filter", "options outside its allowlist", lambda j: co(j).setdefault("with", {}).update({"filter": "tree:0"}), w)
    mutate(f"{lab} checkout with fetch-depth", "options outside its allowlist", lambda j: co(j).setdefault("with", {}).update({"fetch-depth": "1"}), w)
    mutate(f"{lab} checkout with a working-directory", "carries keys outside its allowlist", lambda j: co(j).update({"working-directory": "/tmp"}), w)
    mutate(f"{lab} SDK install with a working-directory", "carries keys outside its allowlist", lambda j: next(x for x in j["steps"] if "persona-uat-requirements" in str(x.get("run", ""))).update({"working-directory": "/tmp"}), w)
    mutate(f"{lab} SDK install with a shell", "carries keys outside its allowlist", lambda j: next(x for x in j["steps"] if "persona-uat-requirements" in str(x.get("run", ""))).update({"shell": "pwsh"}), w)
mutate("weekly docs checkout with sparse-checkout", "options outside its allowlist", lambda j: _docs_checkout(j).setdefault("with", {}).update({"sparse-checkout": "bin"}), "fresh")

# --- round 4 (amendment 0215): results stay private: ONE encrypted artifact family, no plaintext upload, no private key in CI, no issue ------------------------
for lab, w in (("rc", "rel"), ("weekly", "fresh")):
    mutate(f"{lab} upload of the whole output directory (plaintext reports would go public)", "not exactly", lambda j: up(j)["with"].update(path="persona-uat-out"), w)
    mutate(f"{lab} upload glob of everything in the output directory", "not exactly", lambda j: up(j)["with"].update(path="persona-uat-out/*"), w)
    mutate(f"{lab} upload of the reports as markdown", "not exactly", lambda j: up(j)["with"].update(path="persona-uat-out/*.md"), w)
    mutate(f"{lab} upload of cms AND transcripts (a multi-line path)", "not exactly", lambda j: up(j)["with"].update(path="persona-uat-out/*.cms\npersona-uat-out/*.txt"), w)
    mutate(f"{lab} upload of a recursive glob", "not exactly", lambda j: up(j)["with"].update(path="persona-uat-out/**/*.cms"), w)
    mutate(f"{lab} upload from another directory", "not exactly", lambda j: up(j)["with"].update(path="/tmp/*.cms"), w)
    mutate(f"{lab} an artifact name built from a result", "artifact name", lambda j: up(j)["with"].update(name="persona-uat-${{ steps.driver.outcome }}"), w)
    mutate(f"{lab} an artifact name that names a persona result", "artifact name", lambda j: up(j)["with"].update(name="Persona UAT blocking"), w)
    mutate(f"{lab} a second upload step (plaintext)", "exactly one transcript upload", lambda j: j["steps"].append({"if": "${{ always() }}", "uses": "actions/upload-artifact@" + "b" * 40, "with": {"name": "persona-uat-plain", "path": "persona-uat-out", "if-no-files-found": "error"}}), w)
    mutate(f"{lab} a step reads a secret holding the private key", "private key", lambda j: next(x for x in j["steps"] if "persona-uat-requirements" in str(x.get("run", ""))).update(env={"K": "${{ secrets.PERSONA_UAT_PRIVATE_KEY }}"}), w)
    mutate(f"{lab} a step writes a private key file", "private key", lambda j: j["steps"].insert(0, {"run": 'echo "$K" > persona-uat.key'}), w)
    mutate(f"{lab} a step decrypts in CI", "private key", lambda j: j["steps"].append({"run": "openssl cms -decrypt -inkey persona-uat.key -in persona-uat-out/a.cms"}), w)
    mutate(f"{lab} a step names a private-key block", "private key", lambda j: j["steps"].insert(0, {"run": "printf '%s' '-----BEGIN ' 'PRIVATE KEY-----'; echo PRIVATE KEY"}), w)
    mutate(f"{lab} the job reads any other secret", "private key", lambda j: drv(j).setdefault("env", {}).update(X="${{ secrets.OTHER_TOKEN }}"), w)
    mutate(f"{lab} the driver step is given a plaintext --out of its own", "not exactly", lambda j: drv(j).update(run=re.sub(r"--out\s+\S+", "--out /tmp/plain", drv(j)["run"])), w)
    mutate(f"{lab} --recipient points at another file", "--recipient is not", lambda j: drv(j).update(run=re.sub(r"--recipient\s+\S+", "--recipient /tmp/other.pem", drv(j)["run"])), w)
    mutate(f"{lab} --recipient given twice", "--recipient exactly once", lambda j: drv(j).update(run=drv(j)["run"].rstrip() + " --recipient /tmp/other.pem"), w)
    mutate(f"{lab} the driver gains --gh", "outside the contract", lambda j: drv(j).update(run=drv(j)["run"].rstrip() + " --gh gh"), w)
    mutate(f"{lab} a run step opens an issue after the driver", "after the driver other than the transcript upload", lambda j: j["steps"].append({"run": "gh issue create --title x --body y"}), w)
mutate("rc job opens an issue in a step BEFORE the driver", "a run step before the driver other than", lambda j: j["steps"].insert(0, {"run": "gh issue create --title x --body y"}))

# the committed recipient certificate and the local decryption script (real files; red until they are committed)
good = []
pem = os.path.join(root, "bin/persona-uat-recipient.pem")
dsh = os.path.join(root, "bin/persona-uat-decrypt.sh")
if not os.path.isfile(pem):
    good.append("bin/persona-uat-recipient.pem is not committed")
else:
    t = open(pem).read()
    if "PRIVATE" in t or "BEGIN CERTIFICATE" not in t:
        good.append("bin/persona-uat-recipient.pem is not a plain certificate")
if not (os.path.isfile(dsh) and os.access(dsh, os.X_OK)):
    good.append("bin/persona-uat-decrypt.sh is not committed and executable")
result(not good, "the recipient certificate (bin/persona-uat-recipient.pem, a certificate and no key) and the local decryption script (bin/persona-uat-decrypt.sh) are committed" + ("" if not good else ": " + "; ".join(good)))

# --- model ids are secrets (advisor 0233) ---------------------------------------------------------------------------------------------------------------
# the IDENTITY REFRESHER (step 8 rounds 1 and 2, B1 of both reviewers): the federated assertion lives about five minutes and a persona job runs up to two hours, every model call a
# new process. A timer inside actions/github-script dies with its step (round 2: both reviewers ran it), so the refresher is its OWN step starting a detached process that
# outlives it, re-minting into the 0600 token file until the always() cleanup removes it; the pip install passes --break-system-packages (PEP 668 on the hosted ubuntu runner).
def _idscript(j): return next(x for x in j["steps"] if "github-script" in str(x.get("uses", "")))["with"]
def _refr(j): return next(x for x in j["steps"] if "nohup" in str(x.get("run", "")))
def _sub(j, old, new): _refr(j).update(run=_refr(j)["run"].replace(old, new))
for lab, w in (("rc", "rel"), ("weekly", "fresh")):
    mutate(f"{lab} a setInterval timer inside github-script (the round-1 design: it dies with the step)", "starts a timer", lambda j: _idscript(j).update(script=_idscript(j)["script"] + "setInterval(async () => {}, 4 * 60 * 1000).unref?.();\n"), w)
    mutate(f"{lab} the identity step exports the token path to every later step", "exports the token file's path", lambda j: _idscript(j).update(script=_idscript(j)["script"] + "core.exportVariable('ANTHROPIC_IDENTITY_TOKEN_FILE', f);\n"), w)
    # the mint step prints the allowlisted non-secret claims (advisor request, step 8 round 4): exactly sub, aud, ref, job_workflow_ref, environment, repository, repository_owner_id,
    # event_name and iss, one line, never the token or anything else; a decode failure only warns. Each mutant is made in the rc job and in the weekly job alike.
    mutate(f"{lab} the claims line is widened by one claim (jti)", "not exactly the allowlist", lambda j: _idscript(j).update(script=_idscript(j)["script"].replace("'iss']", "'iss', 'jti']")), w)
    mutate(f"{lab} the claims line prints EVERY claim of the token", "not exactly the allowlist", lambda j: _idscript(j).update(script=re.sub(r"for \(const k of \[[^\]]*\]\)", "for (const k of Object.keys(payload))", _idscript(j)["script"])), w)
    mutate(f"{lab} the whole payload is printed too", "not on the allowlist", lambda j: _idscript(j).update(script=_idscript(j)["script"].replace("const claims = {};", "core.info(JSON.stringify(payload)); const claims = {};")), w)
    mutate(f"{lab} the token itself is printed next to the claims", "logs the token", lambda j: _idscript(j).update(script=_idscript(j)["script"].replace("const claims = {};", "core.info(token); const claims = {};")), w)
    mutate(f"{lab} only the token's signature segment is printed", "logs the token", lambda j: _idscript(j).update(script=_idscript(j)["script"].replace("const claims = {};", "core.info(token.split('.')[2]); const claims = {};")), w)
    mutate(f"{lab} the mint step prints no claims at all", "does not print the allowlisted non-secret token claims exactly once", lambda j: _idscript(j).update(script=_idscript(j)["script"][:_idscript(j)["script"].index("// Print ONLY")]), w)
    mutate(f"{lab} the claims are printed twice", "exactly once", lambda j: _idscript(j).update(script=_idscript(j)["script"].replace("core.info('OIDC identity claims (federation-rule inputs): ' + JSON.stringify(claims));", "core.info('OIDC identity claims (federation-rule inputs): ' + JSON.stringify(claims)); core.info('OIDC identity claims (federation-rule inputs): ' + JSON.stringify(claims));")), w)
    mutate(f"{lab} a claims decode failure throws instead of warning", "throws when the token cannot be decoded", lambda j: _idscript(j).update(script=_idscript(j)["script"].replace("try {", "{", 1).replace("} catch (e) {\n  core.warning('could not decode OIDC claims for logging');\n}", "}")), w)
    mutate(f"{lab} a claims decode failure is silent (no warning)", "must produce a warning", lambda j: _idscript(j).update(script=_idscript(j)["script"].replace("core.warning('could not decode OIDC claims for logging');", "")), w)
    mutate(f"{lab} no refresher step at all (the token expires mid-run)", "expected exactly one identity refresher step", lambda j: j.update(steps=[x for x in j["steps"] if x is not _refr(j)]), w)
    mutate(f"{lab} a second refresher step", "expected exactly one identity refresher step", lambda j: j["steps"].insert(j["steps"].index(_refr(j)) + 1, copy.deepcopy(_refr(j))), w)
    mutate(f"{lab} the refresher runs BEFORE the identity step wrote the file", "BEFORE the identity step wrote", lambda j: (lambda r: (j["steps"].remove(r), j["steps"].insert(0, r)))(_refr(j)), w)
    mutate(f"{lab} the refresher is conditional", "conditional or non-fatal", lambda j: _refr(j).update({"if": "${{ always() }}"}), w)
    mutate(f"{lab} the refresher is not detached from the step's output", "does not return", lambda j: _sub(j, " </dev/null >/dev/null 2>&1 &", " &"), w)
    mutate(f"{lab} the refresher runs in the foreground", "does not return", lambda j: _sub(j, " </dev/null >/dev/null 2>&1 &\ndisown", " </dev/null >/dev/null 2>&1"), w)
    mutate(f"{lab} the refresher process is killed with its step (a timer in a subshell that is waited for and exits)", "did not replace the stale token file", lambda j: _sub(j, "while [ -e \"$f\" ] && sleep \"$every\"; do", "while false; do"), w)
    mutate(f"{lab} the refresher re-mints only once", "re-minted only once", lambda j: _sub(j, "done\n'", "break; done\n'"), w)
    mutate(f"{lab} the refresher renews another file", "did not replace the stale token file", lambda j: _sub(j, '--mint-identity "$f" ||', '--mint-identity "$f.other" ||'), w)
    # (the file's mode, its atomic replacement and the lock are the driver's: bin/persona-uat-test.sh drives --mint-identity and --remove-identity, including a cleanup that runs while a fetch is in flight)
    mutate(f"{lab} the job's cleanup removes the token file without the driver's lock", "must end with exactly one `if: always()` step", lambda j: next(x for x in j["steps"] if x.get("run") == CLEANUP_RUN).update(run='rm -f "${RUNNER_TEMP}/anthropic-identity-token"'), w)
    mutate(f"{lab} the refresher keeps going when the file is gone", "not the driver's committed --mint-identity mode", lambda j: _sub(j, '{ [ "$?" -eq 3 ] && break; continue; }', "continue"), w)
    mutate(f"{lab} the refresher interval defaults to 10 minutes", "default interval is not between", lambda j: _sub(j, "REFRESH_SECONDS:-60", "REFRESH_SECONDS:-600"), w)
    mutate(f"{lab} the refresher starts although no token file exists", "starts although the token file does not exist", lambda j: _sub(j, '[ -f "$f" ] || { echo "::error::the identity token file does not exist yet: mint it first"; exit 1; }\n', ""), w)
    # (the request token is presented by the driver's mode: bin/persona-uat-test.sh drives it against a fake endpoint that refuses any other header)
    mutate(f"{lab} the refresher no longer fetches through the driver's mode", "expected exactly one identity refresher step", lambda j: _sub(j, 'python3 bin/persona-uat.py --mint-identity "$f" || { [ "$?" -eq 3 ] && break; continue; }', "true"), w)
    # (a refresher that fetches with a downloader again is refused by the same judge line as the inline-python mutant below)
    mutate(f"{lab} the refresher fetches the token with inline python again", "expected exactly one identity refresher step", lambda j: _sub(j, "python3 bin/persona-uat.py --mint-identity", "python3 -c 'pass' #"), w)
    # (the audience is asked for by the driver's mode: bin/persona-uat-test.sh drives it against a fake endpoint that refuses any other audience)
    mutate(f"{lab} no token cleanup step at the end", "must end with exactly one `if: always()` step that removes", lambda j: j.update(steps=j["steps"][:-1]), w)
    mutate(f"{lab} the cleanup step is not always()", "must end with exactly one `if: always()` step that removes", lambda j: j["steps"][-1].update({"if": "${{ success() }}"}), w)
    mutate(f"{lab} the cleanup step is not the last step", "must end with exactly one `if: always()` step that removes", lambda j: j["steps"].append({"run": "true"}), w)
    mutate(f"{lab} the cleanup step removes another file", "must end with exactly one `if: always()` step that removes", lambda j: j["steps"][-1].update(run='rm -f "${RUNNER_TEMP}/other"'), w)
    mutate(f"{lab} pip install without --break-system-packages (PEP 668 refuses it on the hosted runner)", "expected exactly one hash-pinned SDK install", lambda j: next(x for x in j["steps"] if "persona-uat-requirements" in str(x.get("run", ""))).update(run=next(x for x in j["steps"] if "persona-uat-requirements" in str(x.get("run", "")))["run"].replace(" --break-system-packages", "")), w)
for lab, w in (("rc", "rel"), ("weekly", "fresh")):
    mutate(f"{lab} the default model id arrives as a VARIABLE (printed in the step header)", "is not exactly secrets.PERSONA_UAT_MODEL", lambda j: drv(j)["env"].update(PERSONA_UAT_MODEL="${{ vars.PERSONA_UAT_MODEL }}"), w)
    mutate(f"{lab} the compliance model id arrives as a VARIABLE", "is not exactly secrets.PERSONA_UAT_COMPLIANCE_MODEL", lambda j: drv(j)["env"].update(PERSONA_UAT_COMPLIANCE_MODEL="${{ vars.PERSONA_UAT_COMPLIANCE_MODEL }}"), w)
    mutate(f"{lab} a literal model id on the driver step", "is not exactly secrets.PERSONA_UAT_MODEL", lambda j: drv(j)["env"].update(PERSONA_UAT_MODEL=VEND), w)
    mutate(f"{lab} a literal model id on the driver step (compliance)", "is not exactly secrets.PERSONA_UAT_COMPLIANCE_MODEL", lambda j: drv(j)["env"].update(PERSONA_UAT_COMPLIANCE_MODEL=VEND), w)
    mutate(f"{lab} the model id missing from the driver step", "is not exactly secrets.PERSONA_UAT_MODEL", lambda j: drv(j)["env"].pop("PERSONA_UAT_MODEL"), w)
    mutate(f"{lab} the token budget delivered as a secret", "is not exactly vars.PERSONA_UAT_TOKEN_BUDGET", lambda j: drv(j)["env"].update(PERSONA_UAT_TOKEN_BUDGET="${{ secrets.PERSONA_UAT_TOKEN_BUDGET }}"), w)
    mutate(f"{lab} the model id also in another step's env", "names a model id", lambda j: next(x for x in j["steps"] if "persona-uat-requirements" in str(x.get("run", ""))).update(env={"M": "${{ secrets.PERSONA_UAT_MODEL }}"}), w)
    mutate(f"{lab} the model id in a run step's text", "names a model id", lambda j: j["steps"].insert(0, {"run": 'echo "${{ secrets.PERSONA_UAT_MODEL }}"'}), w)
    mutate(f"{lab} the model id in the job-level env", "names a model id", lambda j: j.setdefault("env", {}).update(M="${{ secrets.PERSONA_UAT_MODEL }}"), w)
    mutate(f"{lab} the compliance model id in the identity step's script", "names a model id", lambda j: next(x for x in j["steps"] if "github-script" in str(x.get("uses", ""))).setdefault("with", {}).update(script=IDENT + "// ${{ secrets.PERSONA_UAT_COMPLIANCE_MODEL }}"), w)
    mutate(f"{lab} the model id in the driver's command text", "names a model id or a secret", lambda j: drv(j).update(run=drv(j)["run"] + ' --model "${{ secrets.PERSONA_UAT_MODEL }}"'), w)
    mutate(f"{lab} a model id reaches the artifact name", "artifact name", lambda j: up(j)["with"].update(name="persona-uat-${{ secrets.PERSONA_UAT_MODEL }}"), w)
for lab, w in (("release.yml", "rel_wf"), ("go-freshness.yml", "fresh_wf")):
    mutate(f"{lab}: workflow-level env holds the model id as a secret", "workflow-level env", lambda d: d.update(env={"PERSONA_UAT_MODEL": "${{ secrets.PERSONA_UAT_MODEL }}"}), w)
    mutate(f"{lab}: workflow-level env holds the compliance model id", "workflow-level env", lambda d: d.update(env={"PERSONA_UAT_COMPLIANCE_MODEL": "${{ secrets.PERSONA_UAT_COMPLIANCE_MODEL }}"}), w)
    mutate(f"{lab}: workflow-level env aliases a model secret", "workflow-level env", lambda d: d.update(env={"X": "${{ secrets.PERSONA_UAT_MODEL }}"}), w)


# The shard gate of bin/persona-uat-test.sh (the driver suite runs as parallel shards; it fails unless every shard passed and the shards together ran every section of the
# script exactly once). Judged on recorded shard outputs, with the section list counted from the script itself.
import subprocess
SUITE = os.path.join(root, "bin/persona-uat-test.sh")
def gate(script, outs, rcs=None):
    d = tempfile.mkdtemp(); args = []
    for i, o in enumerate(outs):
        open(f"{d}/{i}.out", "w").write(o)
        rl = rcs if rcs is not None else [0] * len(outs)
        if i < len(rl): open(f"{d}/{i}.rc", "w").write(str(rl[i]) + "\n")     # a result with no exit status file is a shard that left nothing
        args += [f"{d}/{i}.out", f"{d}/{i}.rc"]
    r = subprocess.run(["bash", SUITE, "--gate", script, str(len(outs)), *args], capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr
def shard_out(secs, passed_n=5, failed_n=0, fixtures=(0, 0)):
    return f"persona-uat-seg: 0 {fixtures[0]} {fixtures[1]}\n" + "".join(f"persona-uat-seg: {k} 1 0\n" for k in secs) + f"persona-uat: {passed_n} passed, {failed_n} failed\n"
fake = tempfile.mktemp(); open(fake, "w").write('x\nSEG_CASES="5 5"\nseg_begin 1\nseg_on\nseg_begin 2\nseg_begin 3\nseg_begin 4\n')
fake1 = tempfile.mktemp(); open(fake1, "w").write('x\nSEG_CASES="5"\nseg_begin 1\nseg_begin 2\nseg_begin 3\nseg_begin 4\n')
fake0 = tempfile.mktemp(); open(fake0, "w").write("x\nseg_begin 1\nseg_begin 2\nseg_begin 3\nseg_begin 4\n")
rc, o = gate(fake, [shard_out([1, 4]), shard_out([2, 3])])
result(rc == 0 and "4 sections, each once" in o, "shard gate: shards that together ran every section once pass")
rc, o = gate(fake, [shard_out([1, 4]), shard_out([2])])
result(rc == 1 and "section 3 ran in no shard" in o, "shard gate: a section that ran in no shard fails")
rc, o = gate(fake, [shard_out([1, 4]), shard_out([2, 3, 4])])
result(rc == 1 and "section 4 ran in shards [1, 2]" in o, "shard gate: a section that ran in two shards fails")
rc, o = gate(fake, [shard_out([1, 4]), shard_out([2, 3, 9])])
result(rc == 1 and "section 9, which the script does not hold" in o, "shard gate: a section the script does not hold fails")
rc, o = gate(fake, [shard_out([1, 4]), shard_out([2, 3], 5, 2)])
result(rc == 1 and "shard 2 failed 2 case(s)" in o, "shard gate: a shard with a failed case fails")
rc, o = gate(fake, [shard_out([1, 4]), shard_out([2, 3])], [0, 1])
result(rc == 1 and "shard 2 exited 1" in o, "shard gate: a shard that exits non-zero fails even with a clean summary")
rc, o = gate(fake, [shard_out([1, 4]), "persona-uat-seg: 2 1 0\npersona-uat-seg: 3 1 0\n"])
result(rc == 1 and "printed 0 summary lines" in o, "shard gate: a shard that printed no summary (a crash) fails")
rc, o = gate(fake, [shard_out([1, 4], fixtures=(2, 0)), shard_out([2, 3])])
result(rc == 1 and "ran 2 case(s) in the fixtures" in o, "shard gate: a case in the fixtures (which every shard would run) fails")
rc, o = gate(fake1, [shard_out([1, 2, 3, 4])])
result(rc == 0, "shard gate: one shard that ran everything passes")
rc, o = gate(fake, [shard_out([1, 4], 4), shard_out([2, 3])])
result(rc == 1 and "shard 1 passed 4 case(s), SEG_CASES says 5" in o, "shard gate: a shard that passed fewer cases than SEG_CASES says (a case skipped or moved out) fails")
rc, o = gate(fake, [shard_out([1, 4]), shard_out([2, 3], 6)])
result(rc == 1 and "shard 2 passed 6 case(s), SEG_CASES says 5" in o, "shard gate: a shard that passed more cases than SEG_CASES says (a case run twice or added) fails")
rc, o = gate(fake0, [shard_out([1, 4]), shard_out([2, 3])])
result(rc == 1 and "SEG_CASES does not give 2 numbers" in o, "shard gate: a script with no SEG_CASES line fails")
rc, o = gate(fake1, [shard_out([1, 4]), shard_out([2, 3])])
result(rc == 1 and "SEG_CASES does not give 2 numbers" in o, "shard gate: a SEG_CASES line with fewer numbers than shards fails")
rc, o = gate(fake, [shard_out([1, 2, 3, 4]), shard_out([])], [0])
result(rc == 1, "shard gate: a missing shard result fails")
# the real script: the gate reads its section list, and every section is owned by exactly one of the shards
src = open(SUITE).read()
held = [int(x) for x in re.findall(r"^seg_begin ([0-9]+)$", src, re.M)]
result(held == list(range(1, len(held) + 1)) and len(held) > 1, "shard gate: the driver suite numbers its sections 1..n in order")
own = re.search(r"^SEG_OWNER=\(([0-9 ]+)\)$", src, re.M)
shards = int(re.search(r"^SEG_SHARDS=([0-9]+)$", src, re.M).group(1))
owners = [int(x) for x in own.group(1).split()] if own else []
result(len(owners) == len(held) and set(owners) == set(range(1, shards + 1)), "shard gate: SEG_OWNER names an owner among the shards for each of the script's sections")
cases = [int(x) for x in re.search(r'^SEG_CASES="([0-9 ]+)"$', src, re.M).group(1).split()]
result(len(cases) == shards and all(c > 0 for c in cases), "shard gate: SEG_CASES gives a number of cases for each shard")
rc, o = gate(SUITE, [shard_out([k for k, w in zip(held, owners) if w == i], cases[i - 1]) for i in range(1, shards + 1)])
result(rc == 0, "shard gate: the shards each running the sections SEG_OWNER gives them cover every section of the real script once")
# section 34 reads runs made in section 26: moving section 26 to another shard must make the shard that keeps section 34 fail, not skip the check
mv26 = owners[:]; mv26[25] = 2 if owners[25] != 2 else 3
d = tempfile.mkdtemp(); moved = f"{d}/persona-uat-test.sh"
open(moved, "w").write(re.sub(r"^SEG_OWNER=\([0-9 ]+\)$", "SEG_OWNER=(" + " ".join(map(str, mv26)) + ")", src, count=1, flags=re.M))
r = subprocess.run(["bash", moved], capture_output=True, text=True, env={**os.environ, "PERSONA_UAT_SHARD": f"{owners[33]}/{shards}"}, timeout=2400)
result(r.returncode != 0 and "section 34 reads" in r.stdout + r.stderr, "shard gate: section 26 moved away from the shard that keeps section 34 makes that shard fail (section 34 reads its runs)")
# a shard that hangs is killed after its deadline and counts as failed (exit 124); one that ends in time keeps its own exit status and output
import time
d = tempfile.mkdtemp(); t0 = time.time()
subprocess.run(["bash", SUITE, "--run-shard", "1", f"{d}/o", f"{d}/e", f"{d}/rc", "bash", "-c", "sleep 60 & sleep 60"], capture_output=True, timeout=30)
result(open(f"{d}/rc").read().strip() == "124" and time.time() - t0 < 20, "shard run: a shard that is still running at its deadline is killed (with its child processes) and its status is 124")
subprocess.run(["bash", SUITE, "--run-shard", "20", f"{d}/o2", f"{d}/e2", f"{d}/rc2", "sh", "-c", "echo hi; echo err >&2; exit 3"], capture_output=True, timeout=30)
result(open(f"{d}/rc2").read().strip() == "3" and open(f"{d}/o2").read() == "hi\n" and open(f"{d}/e2").read() == "err\n", "shard run: a shard that ends in time keeps its exit status, its output and its error output")
rc, o = gate(fake, [shard_out([1, 4]), shard_out([2, 3])], [0, 124])
result(rc == 1 and "shard 2 exited 124" in o, "shard gate: a shard killed at its deadline fails the gate")
print(f"persona-uat wiring: {passed} passed, {failed} failed")
sys.exit(0 if failed == 0 else 1)
PY
