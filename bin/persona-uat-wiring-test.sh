#!/usr/bin/env bash
# proves: REQ-UAT-001-AC1, REQ-UAT-001-AC2, REQ-UAT-001-AC3, REQ-UAT-001-AC4, REQ-UAT-001-AC5
# Where the persona UAT runs (owner ratified Oct 3 and Oct 4; point 9). The wiring is read from the PARSED workflows, never
# from substrings: a persona-uat job in the release chain that runs only for v*-rc.* tags, after the image and promotion,
# in the persona-uat environment, taking the image by the chain's digests, running the driver as a step that nothing can
# skip or make non-fatal, with the owner's model/budget variables and the model identity on THAT step, uploading the
# driver's output directory (transcripts and reports) even when personas fail; and a persona-uat job in the weekly
# workflow that runs only on its Monday cron, resolves the LATEST release's image digest, and runs the same driver with
# --publish. The pinned CI tools file (advisor 0207, delta 2) holds exactly eight entries, each by digest, distinct, and each naming its own OFFICIAL repository:
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
INST = os.path.join(root, "bin/install-scanner.sh")
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

def install_re(pre):
    """the ONLY accepted way to get `kind` onto the job: the repo's own installer (version and sha256 pinned inside it), from the same tree as the driver"""
    return re.compile(r"^(?:\./)?" + re.escape(pre) + r"bin/install-scanner\.sh kind(?: (\S+))?$")

def judge_install(name, steps, d, pre, bad):
    """advisor ruling: the job installs kind in ONE unconditional run step BEFORE the driver, by ./bin/install-scanner.sh kind (no pipe to a shell, no
    download of its own); the installer itself is judged by judge_installer"""
    di = steps.index(d)
    cands = [(i, s) for i, s in enumerate(steps) if "run" in s and re.search(r"\bkind\b|install-scanner", str(s["run"]))]
    good = [(i, s) for i, s in cands if install_re(pre).match(str(s["run"]).strip())]
    if len(good) != 1 or len(cands) != 1:
        bad.append(f"{name}: the job must install kind with exactly one step `./{pre}bin/install-scanner.sh kind` (version and sha256 pinned in the installer; no other kind download or install step); found {[str(s['run'])[:60] for _, s in cands]}")
        return
    i, s = good[0]
    if i > di:
        bad.append(f"{name}: kind is installed AFTER the driver step: the driver would run without it")
    cos = [(k, x) for k, x in enumerate(steps) if "actions/checkout" in str(x.get("uses", ""))]
    prov = next((k for k, x in cos if str((x.get("with") or {}).get("path", "")) == "harness"), None) if pre else (cos[0][0] if cos else None)
    if prov is None or i < prov:
        bad.append(f"{name}: the kind install step runs BEFORE the checkout that provides bin/install-scanner.sh (or there is none): the installer would not exist yet")
    dest = install_re(pre).match(str(s["run"]).strip()).group(1)
    if dest not in (None, "/usr/local/bin"):
        bad.append(f"{name}: the kind install step installs into {dest!r}, a directory that is not on PATH for the driver step (only the installer's default /usr/local/bin is)")
    if s.get("if") is not None or not literal_false(s.get("continue-on-error")):
        bad.append(f"{name}: the kind install step is conditional or non-fatal: a job without kind must fail, never skip it")
    if str(s.get("shell", "bash")) != "bash" or s.get("working-directory") or s.get("env"):
        bad.append(f"{name}: the kind install step has a custom shell, working-directory or env")

def judge_installer(text, bad):
    """bin/install-scanner.sh knows kind: a pinned version, an allowlisted tool name, a pinned sha256 for both architectures, the release URL of the kind
    project, a kind branch that VERIFIES the download before installing it into ${DEST}/kind, and a verify() that really hashes. (judge_installer reads;
    exercise_installer RUNS the installer: both must pass.)"""
    code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
    code = re.sub(r"\s#[^\n\"']*$", "", code, flags=re.M)         # trailing comments on a line
    if not re.search(r"(?m)^KIND_VER=[0-9]+\.[0-9]+\.[0-9]+$", code):
        bad.append("the installer has no pinned KIND_VER (x.y.z)")
    if not re.search(r'case "\$TOOL" in [^\n]*\bkind\b', code):
        bad.append("the installer does not allow the tool name kind")
    for arch in ("x86_64\\|kind:amd64", "aarch64\\|kind:arm64"):
        if not re.search(r"(?m)^\s*kind:" + arch + r"\) SUM=[0-9a-f]{64}\s*;?;?\s*$", code):
            bad.append("the installer has no pinned 64-hex sha256 for kind on " + arch.split("\\")[0])
    if len(re.findall(r"A_KIND=", code)) < 2:
        bad.append("the installer maps no kind release asset for both architectures (A_KIND)")
    if not re.search(r'(?m)^KIND_BASE="\$\{KIND_BASE_URL:-https://github\.com/kubernetes-sigs/kind/releases/download\}"', code):
        bad.append("the installer's kind download is not from github.com/kubernetes-sigs/kind/releases/download")
    vf = re.search(r"(?ms)^verify\(\)\s*\{(.*?)^\}", code)
    if not vf or "sha256sum" not in vf.group(1) or "SUM" not in vf.group(1):
        bad.append("the installer verifies no sha256: verify() does not hash the file with sha256sum and compare it with the pinned SUM (a comment does not count)")
    if not re.search(r'(?m)^DEST="\$\{2:-/usr/local/bin\}"', code):
        bad.append("the installer's default destination is not /usr/local/bin (the directory on PATH for the driver step)")
    arm = re.search(r"(?ms)^\s*kind\)\s*\n(.*?)^\s*;;", code)
    if not arm:
        bad.append("the installer has no kind branch")
    else:
        a = arm.group(1)
        iv, ii = a.find('verify "$tmp/kind"'), a.find('"${DEST}/kind"')
        if iv < 0 or ii < 0 or iv > ii or not re.search(r"\binstall\b[^\n]*-m 0?755", a):
            bad.append("the kind branch does not verify the download BEFORE installing it as an executable ${DEST}/kind")
        if "curl" not in a or "pipeline_fail" not in a:
            bad.append("the kind branch does not download with curl and fail as a pipeline failure")

import hashlib, http.server, subprocess, tempfile, threading, stat

def exercise_installer(path):
    """RUN the installer for kind against a local fixture server that serves ARCHITECTURE-SPECIFIC bytes at the kind project's real asset paths only
    (/v<KIND_VER>/kind-linux-amd64 and /v<KIND_VER>/kind-linux-arm64; anything else is a 404): good bytes install an executable `kind` into DEST, the request was
    for exactly the right asset, and the sha256 check ran (recorded by a sha256sum on PATH); tampered bytes exit non-zero as a PIPELINE failure and install
    nothing. -> [problems]"""
    probs = []
    try:
        src = open(path).read()
    except OSError as e:
        return ["the installer cannot be read: %s" % e]
    mv = re.search(r"(?m)^KIND_VER=([0-9]+\.[0-9]+\.[0-9]+)$", src)
    ver = mv.group(1) if mv else "0.0.0"
    good = {"x86_64": b"#!/bin/sh\necho kind v0.0.0 amd64\n", "aarch64": b"#!/bin/sh\necho kind v0.0.0 arm64\n"}
    asset = {"x86_64": "/v%s/kind-linux-amd64" % ver, "aarch64": "/v%s/kind-linux-arm64" % ver}
    state = {"tamper": False, "paths": []}
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            state["paths"].append(self.path)
            arch = next((a for a, p in asset.items() if self.path == p), None)
            if arch is None:
                self.send_response(404); self.send_header("Content-Length", "0"); self.end_headers(); return
            body = good[arch] + (b"# tampered\n" if state["tamper"] else b"")
            self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    work = tempfile.mkdtemp(prefix="inst-ex-")
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    copy = os.path.join(work, "install-scanner.sh")
    txt = src
    for a_, pat in (("x86_64", r"(kind:x86_64\|kind:amd64\) SUM=)[0-9a-f]{64}"), ("aarch64", r"(kind:aarch64\|kind:arm64\) SUM=)[0-9a-f]{64}")):
        txt = re.sub(pat, lambda m, a_=a_: m.group(1) + hashlib.sha256(good[a_]).hexdigest(), txt)
    open(copy, "w").write(txt); os.chmod(copy, 0o755)
    rbin = os.path.join(work, "rbin"); os.makedirs(rbin)
    open(os.path.join(rbin, "sha256sum"), "w").write("#!/usr/bin/env python3\nimport hashlib, sys\nfor f in sys.argv[1:]:\n    h = hashlib.sha256(open(f, 'rb').read()).hexdigest()\n    open('%s/sha.log', 'a').write(h + '\\n')\n    print(h + '  ' + f)\n" % work)
    os.chmod(os.path.join(rbin, "sha256sum"), 0o755)
    for arch in ("x86_64", "aarch64"):
        for label in ("good", "tampered"):
            state["tamper"] = label == "tampered"; state["paths"] = []
            dest = os.path.join(work, "dest-%s-%s" % (arch, label)); os.makedirs(dest)
            open(os.path.join(work, "sha.log"), "w").close()
            env = dict(os.environ, PATH=rbin + ":" + os.environ["PATH"], KIND_BASE_URL="http://127.0.0.1:%d" % srv.server_address[1], INSTALL_SCANNER_ARCH=arch)
            r = subprocess.run(["bash", copy, "kind", dest], capture_output=True, text=True, env=env, timeout=60)
            hashed = open(os.path.join(work, "sha.log")).read().split()
            k = os.path.join(dest, "kind")
            if state["paths"] != [asset[arch]]:
                probs.append("%s: the installer requested %s, not exactly the architecture's asset %s" % (arch, state["paths"], asset[arch]))
            if label == "good":
                if r.returncode != 0: probs.append("%s: good bytes did not install (rc %d: %s)" % (arch, r.returncode, r.stderr.strip()[:120]))
                elif not (os.path.isfile(k) and os.access(k, os.X_OK)): probs.append("%s: good bytes left no executable kind in DEST" % arch)
                else:
                    pr = subprocess.run([k], capture_output=True, text=True)
                    if pr.returncode != 0 or ("amd64" if arch == "x86_64" else "arm64") not in pr.stdout: probs.append("%s: the installed kind is not this architecture's binary" % arch)
                if hashlib.sha256(good[arch]).hexdigest() not in hashed: probs.append("%s: the sha256 of the downloaded bytes was never computed (no verification ran)" % arch)
            else:
                if r.returncode == 0: probs.append("%s: TAMPERED bytes were accepted (exit 0)" % arch)
                if "PIPELINE" not in r.stderr: probs.append("%s: a tampered download is not reported as a PIPELINE failure" % arch)
                if os.path.exists(k): probs.append("%s: tampered bytes were installed" % arch)
    srv.shutdown()
    return probs

SYN_INST = r"""#!/usr/bin/env bash
set -euo pipefail
TOOL="${1:-}"
DEST="${2:-/usr/local/bin}"
KIND_VER=0.30.0
pipeline_fail() { echo "::error::scanner installer: $*  (PIPELINE failure - not a scan finding)" >&2; exit 1; }
case "$TOOL" in trivy|kind|gitsign) ;; *) pipeline_fail "unknown tool" ;; esac
arch="${INSTALL_SCANNER_ARCH:-$(uname -m)}"
case "$arch" in
  x86_64|amd64) A_KIND=kind-linux-amd64 ;;
  aarch64|arm64) A_KIND=kind-linux-arm64 ;;
  *) pipeline_fail "unsupported architecture" ;;
esac
case "${TOOL}:${arch}" in
  kind:x86_64|kind:amd64) SUM=""" + "a" * 64 + r""" ;;
  kind:aarch64|kind:arm64) SUM=""" + "b" * 64 + r""" ;;
  *) pipeline_fail "no pinned checksum" ;;
esac
KIND_BASE="${KIND_BASE_URL:-https://github.com/kubernetes-sigs/kind/releases/download}"
tmp=$(mktemp -d)
trap 'rm -rf "${tmp:?}"' EXIT
verify() { # file
  local got
  got=$(sha256sum "$1" | cut -d' ' -f1)
  [ "$got" = "$SUM" ] || pipeline_fail "${TOOL} checksum mismatch (got ${got}, pinned ${SUM})"
}
case "$TOOL" in
  kind)
    url="${KIND_BASE}/v${KIND_VER}/${A_KIND}"
    curl -fsSL -o "$tmp/kind" "$url" || pipeline_fail "download failed: $url"
    verify "$tmp/kind"
    install -m 0755 "$tmp/kind" "${DEST}/kind" || pipeline_fail "install failed for kind"
    "${DEST}/kind" version >/dev/null || pipeline_fail "kind does not run after install"
    ;;
  *)
    pipeline_fail "unknown scanner"
    ;;
esac
echo "installed ${TOOL}"
"""
GOODINST = SYN_INST

# --- prerequisites of the job (defined BEFORE common(), which calls them; the complete-workflow control below runs them through judge()) ----------------
CRED_REF = re.compile(r"secrets\.|vars\.PERSONA_UAT|github\.token|ANTHROPIC_")
STEP_ALLOW = {      # STRUCTURAL rule: a prerequisite step may carry only these keys (and, for checkout and the uploads, only these `with` options); anything else
                    # (if, continue-on-error, working-directory, shell, env, timeout-minutes, sparse-checkout, filter, fetch-depth, lfs, ...) can change what it does
    "checkout": ({"uses", "with", "name", "id"}, {"persist-credentials", "ref", "path"}),
    "install": ({"run", "name", "id"}, None), "sdk": ({"run", "name", "id"}, None),
    "resolver": ({"run", "env", "name", "id"}, None),
    "identity": ({"uses", "with", "name", "id"}, {"script"}),
    "upload": ({"uses", "with", "if", "continue-on-error", "name", "id"}, {"name", "path", "if-no-files-found", "retention-days"}),
}

def step_kind(x, pre, weekly):
    u, r = str(x.get("uses", "")), str(x.get("run", "")).strip()
    if "actions/checkout" in u: return "checkout"
    if "actions/github-script" in u: return "identity"
    if "upload-artifact" in u: return "upload"
    if install_re(pre).match(r): return "install"
    if "pip install" in r and "persona-uat-requirements" in r: return "sdk"
    if weekly and "gh release view" in r: return "resolver"
    return None

def judge_prereqs(name, job, steps, bad):
    weekly = name.startswith("weekly")
    pre = "harness/" if weekly else ""
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
        if kind in ("checkout", "sdk") and (x.get("if") is not None or not literal_false(x.get("continue-on-error"))):
            bad.append(f"{name}: the {'checkout' if kind == 'checkout' else 'SDK install'} step is conditional or non-fatal: the persona UAT could run without it")
        if kind != "upload" and kind != "resolver" and "env" in x:
            bad.append(f"{name}: the {kind} step has an env")
    # the checked-out tree must hold the public docs: the repository under test has them, and no checkout option may thin the tree
    if not (os.path.isdir(os.path.join(root, "docs")) and os.path.isfile(os.path.join(root, "README.md"))):
        bad.append(f"{name}: the repository has no docs/ and README.md for the personas to read")

def judge_workflow_env(doc, label, bad):
    """workflow-level `env` is inherited by every job and step: no credential, owner variable, model name or alias of one may be declared there"""
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
    for flag in ("--mode", "--image", "--repo", "--out", "--tools", "--agent", "--recipient"):
        if opts.count(flag) != 1:
            bad.append(f"{name}: the driver is not run with {flag} exactly once (found {opts.count(flag)}): the last occurrence would win")
    if sorted(set(opts) - {"--mode", "--image", "--repo", "--out", "--tools", "--agent", "--recipient"}):
        bad.append(f"{name}: the driver is given options outside the contract (no --publish, no --gh: results stay private, no issue is opened): {sorted(set(opts) - {'--mode', '--image', '--repo', '--out', '--tools', '--agent', '--recipient'})}")
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
    for k, v in (job.get("env") or {}).items():
        if CRED_REF.search(str(v)) or MODEL.search(str(v)):
            bad.append(f"{name}: the job-level env {k} carries a credential reference or a model name ({v!r}): every step would inherit it")
    for s in steps:
        if s is not d:
            for k, v in (s.get("env") or {}).items():
                if re.search(r"secrets\.|vars\.PERSONA_UAT|ANTHROPIC_", str(v)) or MODEL.search(str(v)) or (CRED_REF.search(str(v)) and not (k == "GH_TOKEN" and expr_is(v, "github.token") and "gh release view" in str(s.get("run", "")))):
                    bad.append(f"{name}: the env {k} of a step other than the driver carries a credential reference or a model name ({v!r})")
    env = d.get("env", {})
    extra_env = sorted(set(env) - set(VARS) - set(CREDS))
    if extra_env:
        bad.append(f"{name}: the driver step carries environment outside the contract (no other credential, and no override of the identity token file the identity step exports): {extra_env}")
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
    for s_ in steps:
        blob = json.dumps(s_)
        if re.search(r"PRIVATE KEY|persona-uat\.key|-inkey|cms\s+-decrypt|PERSONA_UAT_(PRIVATE|KEY)|\.key\b", blob) or re.search(r"secrets\.(?!ANTHROPIC_(FEDERATION_RULE_ID|ORGANIZATION_ID|SERVICE_ACCOUNT_ID|WORKSPACE_ID)\b|PERSONA_UAT_(COMPLIANCE_)?MODEL\b)", blob):
            bad.append(f"{name}: a step writes or reads a private key or a secret that holds one (only the four ANTHROPIC_* identity secrets and the two model-id secrets may reach the job; the decryption key never touches CI)")
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
        is_install = isrun and install_re(pre).match(str(s.get("run", "")).strip()) is not None
        is_boot = isrun and re.fullmatch(r"python3 -m pip install --quiet --require-hashes --only-binary=:all: -r " + re.escape(pre) + r"bin/persona-uat-requirements\.txt\s*",
                                         str(s.get("run", "")).strip()) is not None
        if i > di and "upload-artifact" not in str(s.get("uses", "")):
            bad.append(f"{name}: a step after the driver other than the transcript upload could alter the files before upload")
        if i < di and isrun and not is_resolver and not is_boot and not is_install:
            bad.append(f"{name}: a run step before the driver other than the latest-release resolver, the one hash-pinned SDK install and the one pinned kind install (it could change what the driver sees)")
    judge_install(name, steps, d, pre, bad)
    judge_prereqs(name, job, steps, bad)
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

# every way a step can open, edit, close, lock or comment on an issue or pull request (text forms; a third-party issue ACTION or a reusable workflow is caught by the
# dependent-job allowlist below, since it carries no such text)
ISSUE_STEP = re.compile(r"gh\s+issue\s+\w+|gh\s+pr\s+(comment|review|edit|close|reopen|create|merge|ready)\b|issues\.(create|createComment|update|lock|addLabels|setLabels)|pulls\.(createReview|createReviewComment)"
                        r"|gh\s+api\b[^\n]*(issues|comments|graphql|createIssue|addComment|reviews)|(curl|wget)\b[^\n]*(api\.github\.com|/issues|/comments|graphql)|/issues\b|createIssue|addComment|update-issue|create-issue")
# the ONLY actions a job that depends on persona-uat may use (by commit digest); nothing else in its steps, and no job-level `uses:` (a reusable workflow hides its steps)
DEPENDENT_ACTIONS = re.compile(r"^actions/(checkout|upload-artifact|download-artifact)@[0-9a-f]{40}$")
GH_ISSUE_READONLY = {"list", "view", "status"}
GH_PR_READONLY = {"list", "view", "status", "checks", "diff", "checkout"}
GH_VALUE_OPTS = {"-R", "--repo", "--hostname"}
WRAPPERS = {"env", "sudo", "command", "exec", "time", "nohup", "nice", "builtin"}
def gh_commands(run):
    """PARSE the gh commands in a run block (never a regex over `gh issue <word>`): continuations and line joins normalised, each line tokenized as a shell would (; & | ( ) split commands),
    leading VAR=value words and wrappers skipped, and between `gh`, its group (issue, pr, api) and the subcommand every option skipped, those taking a value (-R, --repo,
    --hostname) together with the value. Returns (violations, unresolved): violations are issue/PR-changing commands, unresolved are forms the parser cannot resolve (a variable or
    substitution as the command, eval, `sh -c`, an unbalanced quote): a caller that must fail closed treats those as findings too."""
    import shlex
    viol, unres = [], []
    text = str(run).replace("\\\r\n", " ").replace("\\\n", " ")
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        try:
            lex = shlex.shlex(line, posix=True, punctuation_chars=";&|()")
            lex.whitespace_split = True; lex.commenters = "#"
            toks = list(lex)
        except ValueError:
            if re.search(r"\bgh\b|\$", line):
                unres.append("unbalanced quoting: " + line.strip()[:50])
            continue
        segs, cur = [], []
        for t in toks:
            if t and all(c in ";&|()" for c in t):
                segs.append(cur); cur = []
            else:
                cur.append(t)
        segs.append(cur)
        for seg in segs:
            i = 0
            while i < len(seg) and (re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", seg[i]) or seg[i] in WRAPPERS or (seg[i].startswith("-") and i > 0 and seg[i - 1] in WRAPPERS)):
                i += 1
            if i >= len(seg):
                continue
            cmd = seg[i]
            base = cmd.rsplit("/", 1)[-1]
            if any(ch in cmd for ch in "$`") :
                unres.append("a variable or substitution as the command: " + cmd[:30]); continue
            if base in ("eval", "source", ".", "xargs") or (base in ("bash", "sh", "zsh", "dash", "ksh") and "-c" in seg[i + 1:]):
                if re.search(r"\bgh\b|\$|`", " ".join(seg)):
                    unres.append("eval / sh -c / xargs: " + " ".join(seg)[:50])
                continue
            if base != "gh":
                continue
            j = i + 1
            def skip_opts(j):
                while j < len(seg) and seg[j].startswith("-"):
                    o = seg[j]
                    j += 1 if ("=" in o or o not in GH_VALUE_OPTS) else 2
                return j
            j = skip_opts(j)
            if j >= len(seg):
                continue
            group = seg[j]
            if "$" in group or "`" in group:
                unres.append("gh with a variable group: " + group[:30]); continue
            j = skip_opts(j + 1)
            rest = seg[j:]
            sub = rest[0] if rest else ""
            if group == "issue" and (not sub or sub not in GH_ISSUE_READONLY):
                viol.append("gh issue " + (sub or "?"))
            elif group == "pr" and (not sub or sub not in GH_PR_READONLY):
                viol.append("gh pr " + (sub or "?"))
            elif group == "api" and re.search(r"issues|comments|graphql|createIssue|addComment|reviews", " ".join(seg[i + 1:]), re.I):
                viol.append("gh api issues/comments/graphql")
            elif group not in ("issue", "pr", "api") and re.search(r"\$", group):
                unres.append("gh with a variable group")
    return viol, unres

def mode_value(run):
    """the value of the driver's --mode option, parsed (comments dropped, continuations joined); None unless exactly one"""
    import shlex
    try:
        argv = shlex.split(str(run).replace("\\\n", " "), comments=True)
    except ValueError:
        return None
    vals = [argv[i + 1] for i, t in enumerate(argv[:-1]) if t == "--mode"] + [t.split("=", 1)[1] for t in argv if t.startswith("--mode=")]
    return vals[0] if len(vals) == 1 else None

def judge_workflow_graph(r, label, bad):
    """results stay private, for ANY outcome of persona-uat (success, friction-only, failure): no job that depends on persona-uat, directly or transitively through
    needs, may open or touch a public issue whatever its `if` says (a `needs: [persona-uat]` job with no `if` runs after success and friction, with `failure()`/`!success()`
    after a failure), and neither may a job that runs under always()/!cancelled() (it runs whatever persona-uat did); persona-uat's own steps never do"""
    jobs = r.get("jobs", {}) or {}
    def needs_of(n):
        v = (jobs.get(n) or {}).get("needs", [])
        return [v] if isinstance(v, str) else list(v or [])
    def ancestors(n, seen=None):
        seen = set() if seen is None else seen
        for m in needs_of(n):
            if m not in seen:
                seen.add(m); ancestors(m, seen)
        return seen
    for n, j in jobs.items():
        j = j or {}
        cond = str(j.get("if", ""))
        always = bool(re.search(r"always\(\)|!\s*cancelled\(\)", cond))
        depends = "persona-uat" in ancestors(n)
        if not (n == "persona-uat" or depends or always):
            continue
        if depends and j.get("uses") is not None:
            bad.append(f"{label}: job {n} depends on persona-uat and is a reusable-workflow call ({str(j.get('uses'))[:50]!r}): it could open an issue from steps nobody here can see")
        for st in j.get("steps", []) or []:
            if depends and st.get("uses") is not None and not DEPENDENT_ACTIONS.match(str(st.get("uses"))):
                bad.append(f"{label}: job {n} depends on persona-uat and uses {str(st.get('uses'))[:60]!r}: a job that follows persona-uat may use only checkout, upload-artifact and download-artifact by digest (a third-party action could open an issue)")
            gv, gu = gh_commands(st.get("run", ""))
            for g_ in gv + (gu if depends else []):
                bad.append(f"{label}: job {n} {'depends on persona-uat (directly or through needs)' if depends else 'runs whatever persona-uat did'} and its run text has a gh command that changes an issue or pull request, or one that cannot be resolved ({g_!r}): a persona result, whatever its outcome, must stay private")
            blob = str(st.get("run", "")) + " " + json.dumps(st.get("with", {}) or {})
            if ISSUE_STEP.search(blob):
                bad.append(f"{label}: job {n} {'depends on persona-uat (directly or through needs)' if depends else 'runs whatever persona-uat did'} and opens or touches a public issue ({blob.strip()[:60]!r}): a persona result, whatever its outcome, must stay private")

def judge_release_graph(r, bad):
    judge_workflow_graph(r, "release.yml", bad)

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
    judge_release_graph(r, bad)
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
    want = {"contents": "read", "id-token": "write", "packages": "read"}
    if any(p.get(k) != v for k, v in want.items()) or set(p) - set(want):
        bad.append(f"release persona-uat permissions are not exactly {want} (found {p})")
    if d is not None:
        run = str(d.get("run", ""))
        m = re.search(r"--image\s+(\S+(?:\s*\"[^\"]*\")?)", run)
        img = m.group(1) if m else ""
        arg = run.replace("\\\n", " ").split("--image", 1)[-1].split(" --", 1)[0]
        if not re.search(r"\$\{\{\s*fromJSON\(\s*needs\.image\.outputs\.digests\s*\)\.production\s*\}\}", arg) or "@" not in arg:
            bad.append("release persona-uat takes the image from something other than the chain's digests (fromJSON(needs.image.outputs.digests).production)")
        if mode_value(run) != "rc":
            bad.append(f"release persona-uat does not run the driver with --mode rc exactly (parsed value {mode_value(run)!r})")

def judge_weekly(f, bad):
    judge_workflow_graph(f, "go-freshness.yml", bad)
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
    if norm(j.get("if", "")) != norm("github.event.schedule == '43 6 * * 1'") or "43 6 * * 1" not in cron:
        bad.append(f"weekly persona-uat does not run only on the Monday cron (if: {j.get('if')!r})")
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
    if d is not None and mode_value(d.get("run", "")) != "weekly":
        bad.append(f"weekly persona-uat does not run the driver with --mode weekly exactly (parsed value {mode_value(d.get('run', ''))!r})")

TOOL_KEYS = ["cosign", "gitlab-runner", "gradle", "jenkins", "kind", "kubectl", "maven", "shell"]
# each key's official image repository, as docker normalises it (docker.io/ and library/ stripped); an exact match, never a suffix match
OFFICIAL = {"cosign": {"gcr.io/projectsigstore/cosign", "ghcr.io/sigstore/cosign/cosign"}, "gitlab-runner": {"gitlab/gitlab-runner"}, "gradle": {"gradle"},
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
        bad.append("the persona tools are not distinct images (eight different repositories and digests)")

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

# a known-good eight-entry tools file, so the tools mutations test the JUDGE and do not depend on the file in the tree
TGOOD = {"cosign": "gcr.io/projectsigstore/cosign@sha256:" + "5" * 64, "gitlab-runner": "docker.io/gitlab/gitlab-runner@sha256:" + "2" * 64,
         "gradle": "docker.io/library/gradle@sha256:" + "7" * 64, "jenkins": "docker.io/jenkins/jenkins@sha256:" + "1" * 64,
         "kind": "docker.io/kindest/node@sha256:" + "3" * 64, "kubectl": "registry.k8s.io/kubectl@sha256:" + "6" * 64,
         "maven": "docker.io/library/maven@sha256:" + "8" * 64, "shell": "docker.io/curlimages/curl@sha256:" + "4" * 64}
CLEAN_SRC = {p: "x = 1\n" for p in SRC}

# the same two judges on the REAL files alone, so a delta-1/2 failure is not hidden behind the workflow wiring (which lands with commit 2)
good = []
judge_tools(T if T is not None else "missing", good)
result(not good, "the real tools file (bin/persona-uat-tools.json) is the eight official digest-pinned images" + ("" if not good else ": " + "; ".join(good)))
good = []
judge_source(good)
result(not good, "the real driver, agent and provider run no privileged container, no cloud CLI and name no image without a digest" + ("" if not good else ": " + "; ".join(good)))
good = []
try:
    judge_installer(open(INST).read(), good)
except OSError:
    good.append("bin/install-scanner.sh is missing")
result(not good, "the real installer (bin/install-scanner.sh) installs kind pinned by version and sha256" + ("" if not good else ": " + "; ".join(good)))
good = []
judge_tools(TGOOD, good)
result(not good, "the in-test known-good eight-entry tools file is accepted by the judge" + ("" if not good else ": " + "; ".join(good)))
good = []
SRC_OVER.update(CLEAN_SRC); judge_source(good); SRC_OVER.clear()
result(not good, "a clean source set is accepted by the source judge" + ("" if not good else ": " + "; ".join(good)))

def synth_steps(weekly):
    pre = "harness/" if weekly else ""
    cos = [{"uses": "actions/checkout@" + "0" * 40, "with": {"path": "harness"}}, {"uses": "actions/checkout@" + "0" * 40, "with": {"path": "release-docs"}}] if weekly else [{"uses": "actions/checkout@" + "0" * 40}]
    return pre, cos + [{"run": "./" + pre + "bin/install-scanner.sh kind"}, {"run": "python3 -m pip install --quiet --require-hashes --only-binary=:all: -r " + pre + "bin/persona-uat-requirements.txt"},
                       {"run": "python3 " + pre + "bin/persona-uat.py --mode rc"}]
for weekly in (False, True):
    pre, st = synth_steps(weekly)
    bd = []
    judge_install("synth", st, st[-1], pre, bd)
    result(not bd, f"the install judge accepts the pinned kind install step ({'weekly, harness/' if weekly else 'rc'})" + ("" if not bd else ": " + "; ".join(bd)))
bd = []
judge_installer(GOODINST, bd)
result(not bd, "the installer judge accepts a installer with kind pinned by version and sha256" + ("" if not bd else ": " + "; ".join(bd)))

def ins(st):
    return next(x for x in st if "install-scanner" in str(x.get("run", "")) or re.search(r"\bkind\b", str(x.get("run", ""))))

def imutate(name, expect, fn, weekly=False):
    pre, st = synth_steps(weekly)
    fn(st)
    bd = []
    judge_install("synth", st, next(x for x in st if "persona-uat.py" in str(x.get("run", ""))), pre, bd)
    result(any(expect in b for b in bd), f"caught: {name} (reason: {expect!r})" + ("" if any(expect in b for b in bd) else f"; saw {bd}"))

def smutate(name, expect, fn):
    t = fn(GOODINST)
    bd = []
    judge_installer(t, bd)
    result(t != GOODINST and any(expect in b for b in bd), f"caught: {name} (reason: {expect!r})" + ("" if any(expect in b for b in bd) else f"; saw {bd}"))

def xmutate(name, expect, fn):
    """the installer is RUN (exercise_installer): a mutant that reads right but behaves wrong must still be caught"""
    t = fn(SYN_INST)
    f = os.path.join(tempfile.mkdtemp(prefix="inst-mut-"), "install-scanner.sh")
    open(f, "w").write(t)
    pr = exercise_installer(f)
    result(t != SYN_INST and any(expect in x for x in pr), f"caught by running it: {name} (reason: {expect!r})" + ("" if any(expect in x for x in pr) else f"; saw {pr}"))

# the synthetic installer is valid shell, is judged clean and RUNS right: the controls
f = os.path.join(tempfile.mkdtemp(prefix="inst-syn-"), "install-scanner.sh"); open(f, "w").write(SYN_INST)
rc = subprocess.run(["bash", "-n", f], capture_output=True, text=True)
result(rc.returncode == 0, "the synthetic reference installer is valid shell (bash -n)" + ("" if rc.returncode == 0 else ": " + rc.stderr.strip()))
pr = exercise_installer(f)
result(not pr, "running the reference installer: good bytes install an executable kind and are hashed, tampered bytes exit non-zero as a PIPELINE failure and install nothing, on both architectures" + ("" if not pr else ": " + "; ".join(pr)))
pr = exercise_installer(INST)
result(not pr, "running the REAL installer (bin/install-scanner.sh kind) against a local fixture with its pinned sums replaced: good bytes install an executable kind, tampered bytes are a PIPELINE failure" + ("" if not pr else ": " + "; ".join(pr)))

for weekly in (False, True):
    w = " (weekly)" if weekly else ""
    imutate("kind install missing" + w, "exactly one step", lambda st: st.remove(ins(st)), weekly)
    imutate("kind install by curl | sh" + w, "exactly one step", lambda st: ins(st).update(run="curl -sSL https://kind.sigs.k8s.io/dl/v0.30.0/kind-linux-amd64 | sh"), weekly)
    imutate("kind download without checksum" + w, "exactly one step", lambda st: ins(st).update(run="curl -Lo /usr/local/bin/kind https://kind.sigs.k8s.io/dl/v0.30.0/kind-linux-amd64 && chmod +x /usr/local/bin/kind"), weekly)
    imutate("kind installed by go install" + w, "exactly one step", lambda st: ins(st).update(run="go install sigs.k8s.io/kind@latest"), weekly)
    imutate("kind install after the driver" + w, "AFTER the driver", lambda st: st.append(st.pop(st.index(ins(st)))), weekly)
    imutate("kind install BEFORE the checkout" + w, "BEFORE the checkout", lambda st: st.insert(0, st.pop(st.index(ins(st)))), weekly)
    imutate("kind install into a directory not on PATH" + w, "not on PATH", lambda st: ins(st).update(run=ins(st)["run"] + " /tmp/not-on-path"), weekly)
    imutate("kind install into /opt/bin" + w, "not on PATH", lambda st: ins(st).update(run=ins(st)["run"] + " /opt/bin"), weekly)
    imutate("kind install conditional" + w, "conditional or non-fatal", lambda st: ins(st).update({"if": "github.event_name == 'push'"}), weekly)
    imutate("kind install continue-on-error" + w, "conditional or non-fatal", lambda st: ins(st).update({"continue-on-error": "true"}), weekly)
    imutate("kind install with another tool name" + w, "exactly one step", lambda st: ins(st).update(run=ins(st)["run"].replace(" kind", " trivy") + "; echo kind"), weekly)
    imutate("kind install from the other tree" + w, "exactly one step", lambda st: ins(st).update(run="./" + ("" if weekly else "harness/") + "bin/install-scanner.sh kind"), weekly)
    imutate("kind install piped" + w, "exactly one step", lambda st: ins(st).update(run=ins(st)["run"] + " | sh"), weekly)
    imutate("kind installed twice" + w, "exactly one step", lambda st: st.insert(st.index(ins(st)), dict(ins(st))), weekly)
    imutate("kind install with a custom shell" + w, "custom shell", lambda st: ins(st).update(shell="pwsh"), weekly)
    imutate("kind install with env" + w, "custom shell, working-directory or env", lambda st: ins(st).update(env={"KIND_BASE_URL": "https://evil.example"}), weekly)
smutate("installer: KIND_VER missing", "no pinned KIND_VER", lambda t: t.replace("KIND_VER=0.30.0\n", ""))
smutate("installer: KIND_VER is latest", "no pinned KIND_VER", lambda t: t.replace("KIND_VER=0.30.0", "KIND_VER=latest"))
smutate("installer: kind not in the allowlist", "does not allow the tool name kind", lambda t: t.replace("trivy|kind|gitsign", "trivy|gitsign"))
smutate("installer: x86_64 checksum missing", "no pinned 64-hex sha256 for kind on x86_64", lambda t: t.replace("  kind:x86_64|kind:amd64) SUM=" + "a" * 64 + " ;;\n", ""))
smutate("installer: x86_64 checksum too short", "no pinned 64-hex sha256 for kind on x86_64", lambda t: t.replace("a" * 64, "a" * 63))
smutate("installer: arm64 checksum missing", "no pinned 64-hex sha256 for kind on aarch64", lambda t: t.replace("  kind:aarch64|kind:arm64) SUM=" + "b" * 64 + " ;;\n", ""))
smutate("installer: checksum is a placeholder", "no pinned 64-hex sha256 for kind on aarch64", lambda t: t.replace("b" * 64, "TODO"))
smutate("installer: asset mapping missing", "maps no kind release asset", lambda t: t.replace("  aarch64|arm64) A_KIND=kind-linux-arm64 ;;\n", ""))
smutate("installer: download from another host", "not from github.com/kubernetes-sigs/kind", lambda t: t.replace("github.com/kubernetes-sigs/kind", "evil.example/kind"))
smutate("installer: checksum only in a comment", "verifies no sha256", lambda t: t.replace('got=$(sha256sum "$1" | cut -d\' \' -f1)', "got=x  # sha256sum"))
smutate("installer: verify() hashes nothing", "verifies no sha256", lambda t: t.replace("sha256sum", "md5sum"))
smutate("installer: the kind branch never verifies", "does not verify the download BEFORE", lambda t: t.replace('    verify "$tmp/kind"\n', ""))
smutate("installer: the kind branch verifies after installing", "does not verify the download BEFORE", lambda t: t.replace('    verify "$tmp/kind"\n', "").replace('    "${DEST}/kind" version', '    verify "$tmp/kind"\n    "${DEST}/kind" version'))
smutate("installer: the kind branch installs elsewhere", "does not verify the download BEFORE", lambda t: t.replace('"${DEST}/kind" || pipeline_fail', '"/opt/kind-bin/kind" || pipeline_fail').replace('"${DEST}/kind" version', '"/opt/kind-bin/kind" version'))
smutate("installer: the default destination is not on PATH", "default destination", lambda t: t.replace('DEST="${2:-/usr/local/bin}"', 'DEST="${2:-/opt/kind-bin}"'))
smutate("installer: no kind branch", "no kind branch", lambda t: t.replace("  kind)\n", "  kindx)\n"))
xmutate("verification removed from the kind branch", "TAMPERED bytes were accepted", lambda t: t.replace('    verify "$tmp/kind"\n', ""))
xmutate("verify() compares nothing (always passes)", "TAMPERED bytes were accepted", lambda t: t.replace('[ "$got" = "$SUM" ] || ', "true || "))
xmutate("verify() only in a comment", "no verification ran", lambda t: t.replace('got=$(sha256sum "$1" | cut -d\' \' -f1)', "got=$SUM  # sha256sum"))
xmutate("wrong destination", "left no executable kind in DEST", lambda t: t.replace('"${DEST}/kind" || pipeline_fail', '"${DEST}/kind-x" || pipeline_fail').replace('"${DEST}/kind" version', '"${DEST}/kind-x" version'))
xmutate("not executable", "left no executable kind in DEST", lambda t: t.replace("install -m 0755", "install -m 0644").replace('    "${DEST}/kind" version >/dev/null || pipeline_fail "kind does not run after install"\n', ""))
xmutate("architecture assets swapped", "did not install", lambda t: t.replace("A_KIND=kind-linux-amd64", "A_KIND=TMP").replace("A_KIND=kind-linux-arm64", "A_KIND=kind-linux-amd64").replace("A_KIND=TMP", "A_KIND=kind-linux-arm64"))
xmutate("the release URL lacks the v prefix", "did not install", lambda t: t.replace("/v${KIND_VER}/", "/${KIND_VER}/"))
xmutate("a wrong version in the URL", "did not install", lambda t: t.replace("/v${KIND_VER}/", "/v0.0.1/"))
xmutate("one asset for both architectures", "did not install", lambda t: t.replace("A_KIND=kind-linux-arm64", "A_KIND=kind-linux-amd64"))
xmutate("a mismatch is not a pipeline failure", "not reported as a PIPELINE failure", lambda t: t.replace("(PIPELINE failure - not a scan finding)", "(scan finding)"))
xmutate("verify() failure ignored", "TAMPERED bytes were accepted", lambda t: t.replace('pipeline_fail "${TOOL} checksum mismatch', 'echo "${TOOL} checksum mismatch'))

# --- a COMPLETE known-good synthetic release.yml and go-freshness.yml, run through the REAL entry point judge() -> judge_release/judge_weekly -> common() ----------
H40 = "a" * 40
IDENT = ("const fs = require('fs');\nconst token = await core.getIDToken('https://api.anthropic.com');\ncore.setSecret(token);\n"
         "const f = process.env.RUNNER_TEMP + '/anthropic-identity-token';\nfs.writeFileSync(f, token);\ncore.exportVariable('ANTHROPIC_IDENTITY_TOKEN_FILE', f);\n")
def synth_driver(weekly):
    pre = "harness/" if weekly else ""
    env = {v: ("${{ secrets.%s }}" if v in MODEL_SECRETS else "${{ vars.%s }}") % v for v in VARS}
    env.update({c: "${{ secrets.%s }}" % c for c in CREDS}); 
    img = '"${{ steps.resolve.outputs.image }}"' if weekly else '"ghcr.io/${{ github.repository }}@${{ fromJSON(needs.image.outputs.digests).production }}"'
    return {"env": env, "run": f'python3 {pre}bin/persona-uat.py --mode {"weekly" if weekly else "rc"} --image {img} --repo {"release-docs" if weekly else "."} --out persona-uat-out '
                                f'--tools {pre}bin/persona-uat-tools.json --recipient {pre}bin/persona-uat-recipient.pem --agent "python3 {pre}bin/persona-uat-agent.py"'}
def synth_persona_job(weekly):
    pre = "harness/" if weekly else ""
    co = ([{"uses": "actions/checkout@" + H40, "with": {"path": "harness", "persist-credentials": "false"}},
           {"uses": "actions/checkout@" + H40, "with": {"path": "release-docs", "ref": "${{ steps.resolve.outputs.tag }}", "persist-credentials": "false"}}] if weekly
          else [{"uses": "actions/checkout@" + H40, "with": {"persist-credentials": "false"}}])
    resolver = [{"id": "resolve", "env": {"GH_REPO": "${{ github.repository }}", "REGISTRY_OWNER": "${{ github.repository_owner }}", "GH_TOKEN": "${{ github.token }}"},
                 "run": 'tag=$(gh release view --json tagName -q .tagName)\nd=$(docker buildx imagetools inspect "ghcr.io/${REGISTRY_OWNER}/cache:${tag#v}" --format \'{{.Manifest.Digest}}\')\n'
                        'echo "tag=$tag" >> "$GITHUB_OUTPUT"\necho "image=ghcr.io/${REGISTRY_OWNER}/cache@$d" >> "$GITHUB_OUTPUT"'}] if weekly else []
    steps = (resolver + co + [{"run": "./" + pre + "bin/install-scanner.sh kind"},
             {"run": "python3 -m pip install --quiet --require-hashes --only-binary=:all: -r " + pre + "bin/persona-uat-requirements.txt"},
             {"uses": "actions/github-script@" + H40, "with": {"script": IDENT}}, synth_driver(weekly),
             {"if": "${{ always() }}", "uses": "actions/upload-artifact@" + H40, "with": {"name": "persona-uat-encrypted", "path": "persona-uat-out/*.cms", "if-no-files-found": "error"}}])
    j = {"runs-on": "ubuntu-24.04", "timeout-minutes": "120", "environment": "persona-uat", "permissions": {"contents": "read", "id-token": "write", "packages": "read"}, "steps": steps}
    if weekly:
        j["if"] = "${{ github.event.schedule == '43 6 * * 1' }}"
    else:
        j["needs"] = ["image", "promotion"]
        j["if"] = "${{ startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc.') }}"
    return j
RS = {"on": {"push": {"tags": ["v*"]}}, "jobs": {
    "image": {"steps": [{"run": "true"}]}, "promotion": {"needs": ["image"], "steps": [{"run": "true"}]},
    "patch-failed": {"needs": ["image", "promotion"], "if": "${{ failure() }}", "steps": [{"run": 'gh issue create --title "auditor: release failed" --body "$RUN_URL"'}]},
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
    boot = lambda j: next(x for x in j["steps"] if "pip install" in str(x.get("run", "")))
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
    pm("kind install with a working-directory", "carries keys outside its allowlist", lambda j: next(x for x in j["steps"] if "install-scanner" in str(x.get("run", ""))).update({"working-directory": "/tmp"}))
    pm("identity step with a working-directory", "carries keys outside its allowlist", lambda j: next(x for x in j["steps"] if "github-script" in str(x.get("uses", ""))).update({"working-directory": "/tmp"}))
    pm("identity step with another option", "options outside its allowlist", lambda j: next(x for x in j["steps"] if "github-script" in str(x.get("uses", ""))).setdefault("with", {}).update({"github-token": "${{ secrets.X }}"}))
    pm("upload with a working-directory", "carries keys outside its allowlist", lambda j: next(x for x in j["steps"] if "upload-artifact" in str(x.get("uses", ""))).update({"working-directory": "/tmp"}))

BASES = [("synthetic", RS, FS)]
REAL_JOBS = bool(R.get("jobs", {}).get("persona-uat")) and bool(F.get("jobs", {}).get("persona-uat"))
if REAL_JOBS:
    BASES.append(("real", R, F))
else:
    result(False, "the real release.yml and go-freshness.yml have no persona-uat jobs yet (commit 2): every workflow mutation below ran against the synthetic known-good workflows only")
def mutate(name, expect, fn, which="rel"):
    for label, BR, BF in BASES:
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
            r["defaults"] = {"run": {"working-directory": "harness"}}
        elif which == "fresh_defaults":
            f["defaults"] = {"run": {"working-directory": "harness"}}
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
mutate("persona-uat is added to patch-failed.needs (a persona failure would open a public issue)", "lists persona-uat in needs", lambda d: d["jobs"]["patch-failed"].update(needs=["image", "promotion", "persona-uat"]), "rel_wf")
for run_ in ("gh issue list --repo o/r", "gh --repo o/r issue view 3", "gh run download 1 -n x --dir d", "gh release list", "echo gh issue create is forbidden", "gh pr --repo o/r view 3",
             "gh api repos/o/r/releases/latest", "sort -n x\ngit status"):
    gv_, gu_ = gh_commands(run_)
    result(not gv_ and not gu_ or run_.startswith("echo gh"), f"the gh parser leaves a harmless command alone: {run_!r}" + ("" if not gv_ and not gu_ or run_.startswith("echo gh") else f": {gv_} {gu_}"))
for run_ in ("gh issue --repo o/r create", "gh --repo o/r issue create", "gh issue \\\n create", "gh \t issue \t create", "gh pr --repo o/r comment 3", "gh api graphql -f query=x"):
    gv_, gu_ = gh_commands(run_)
    result(bool(gv_), f"the gh parser finds the changing command: {run_!r}")
for lab_, w_ in (("release.yml", "rel_wf"), ("go-freshness.yml", "fresh_wf")):
    mutate(f"{lab_}: a successor of persona-uat opens an issue with NO `if` (after success and friction-only)", "depends on persona-uat", lambda d: d["jobs"].update(report={"needs": ["persona-uat"], "steps": [{"run": "gh issue create --title x --body y"}]}), w_)
    mutate(f"{lab_}: a successor opens an issue under `if: ${{{{ !success() }}}}` (after failure)", "depends on persona-uat", lambda d: d["jobs"].update(report={"needs": ["persona-uat"], "if": "${{ !success() }}", "steps": [{"run": "gh issue create --title x --body y"}]}), w_)
    mutate(f"{lab_}: a successor opens an issue under failure()", "depends on persona-uat", lambda d: d["jobs"].update(report={"needs": ["persona-uat"], "if": "${{ failure() }}", "steps": [{"run": "gh issue create --title x --body y"}]}), w_)
    for nm_, run_ in (("gh issue --repo X create", "gh issue --repo fosterstack/cache create --title t --body b"), ("gh --repo X issue create", "gh --repo fosterstack/cache issue create --title t"),
                      ("gh -R X issue -R Y close", "gh -R a/b issue -R c/d close 3"), ("a backslash-continued gh issue create", "gh issue \\\n  create \\\n  --title t"),
                      ("gh   issue\t\tcreate with tabs", "gh  \t issue \t  create --title t"), ("gh issue after an assignment and a pipe", "GH_TOKEN=$T true | gh issue lock 3"),
                      ("gh pr --repo X review", "gh pr --repo o/r review 3 --approve"), ("gh api with options before the endpoint", "gh api --method POST -H 'X: y' repos/o/r/issues -f title=t"),
                      ("gh --hostname H issue transfer", "gh --hostname h.example issue transfer 3 o/r"), ("gh issue in a && list", "echo hi && gh issue --repo o/r delete 3 --yes"),
                      ("gh issue pin", "gh issue pin 3"), ("gh issue with only a repo option and no subcommand", "gh issue --repo o/r")):
        mutate(f"{lab_}: a direct successor runs {nm_}", "depends on persona-uat", lambda d, run_=run_: d["jobs"].update(report={"needs": ["persona-uat"], "steps": [{"run": run_}]}), w_)
        mutate(f"{lab_}: a transitive successor runs {nm_}", "depends on persona-uat", lambda d, run_=run_: d["jobs"].update(first={"needs": ["persona-uat"], "steps": [{"run": "true"}]}, second={"needs": ["first"], "steps": [{"run": run_}]}), w_)
    for nm_, run_ in (("an indirect $GH", "GH=gh\n$GH issue create --title t"), ("eval", "eval \"gh issue create --title t\""), ("bash -c", "bash -c 'gh issue create --title t'"),
                      ("a command substitution", "$(echo gh) issue create"), ("an unbalanced quote", "echo 'gh issue create"), ("xargs", "echo 3 | xargs gh issue close"), ("a variable group", "gh $GRP create")):
        mutate(f"{lab_}: a dependent job has gh in a form the parser cannot resolve ({nm_})", "depends on persona-uat", lambda d, run_=run_: d["jobs"].update(report={"needs": ["persona-uat"], "steps": [{"run": run_}]}), w_)
        mutate(f"{lab_}: a transitive dependent job has gh in a form the parser cannot resolve ({nm_})", "depends on persona-uat", lambda d, run_=run_: d["jobs"].update(first={"needs": ["persona-uat"], "steps": [{"run": "true"}]}, second={"needs": ["first"], "steps": [{"run": run_}]}), w_)
    mutate(f"{lab_}: a successor opens an issue under success()", "depends on persona-uat", lambda d: d["jobs"].update(report={"needs": ["persona-uat"], "if": "${{ success() }}", "steps": [{"run": "gh issue edit 3 --body y"}]}), w_)
    mutate(f"{lab_}: a TRANSITIVE successor (two hops, no `if`) opens an issue", "depends on persona-uat", lambda d: d["jobs"].update(first={"needs": ["persona-uat"], "steps": [{"run": "true"}]}, second={"needs": ["first"], "steps": [{"run": "gh issue create --title x --body y"}]}), w_)
    mutate(f"{lab_}: a transitive successor under failure() opens an issue through the API", "depends on persona-uat", lambda d: d["jobs"].update(first={"needs": ["persona-uat"], "if": "${{ always() }}", "steps": [{"run": "true"}]}, second={"needs": ["first"], "if": "${{ failure() }}", "steps": [{"run": "gh api repos/o/r/issues -f title=x"}]}), w_)
    for nm_, stp_ in (("a third-party issue action", {"uses": "dacbd/create-issue-action@" + "a" * 40, "with": {"title": "t", "body": "b"}}),
                      ("an issue action pinned by tag", {"uses": "peter-evans/create-issue-from-file@v5"}),
                      ("gh issue close", {"run": "gh issue close 3"}), ("gh issue lock", {"run": "gh issue lock 3"}), ("gh issue comment", {"run": "gh issue comment 3 -b x"}),
                      ("gh pr comment", {"run": "gh pr comment 3 -b x"}), ("a GraphQL createIssue", {"run": "gh api graphql -f query='mutation { createIssue(input: {}) { clientMutationId } }'"}),
                      ("a GraphQL addComment", {"run": "gh api graphql -f query=x"}), ("a curl to the issues API", {"run": "curl -X POST -H \"Authorization: Bearer $T\" https://api.github.com/repos/o/r/issues -d '{}'"}),
                      ("github-script", {"uses": "actions/github-script@" + "a" * 40, "with": {"script": "await github.rest.issues.create({})"}}),
                      ("github-script with a quiet script", {"uses": "actions/github-script@" + "a" * 40, "with": {"script": "core.info('x')"}})):
        mutate(f"{lab_}: a direct successor of persona-uat uses {nm_}", "depends on persona-uat", lambda d, stp_=stp_: d["jobs"].update(report={"needs": ["persona-uat"], "steps": [stp_]}), w_)
        mutate(f"{lab_}: a TRANSITIVE successor uses {nm_}", "depends on persona-uat", lambda d, stp_=stp_: d["jobs"].update(first={"needs": ["persona-uat"], "steps": [{"run": "true"}]}, second={"needs": ["first"], "steps": [stp_]}), w_)
    mutate(f"{lab_}: a successor of persona-uat is a reusable-workflow call", "reusable-workflow call", lambda d: d["jobs"].update(report={"needs": ["persona-uat"], "uses": "./.github/workflows/notify.yml"}), w_)
    mutate(f"{lab_}: a transitive successor is a reusable-workflow call in another repository", "reusable-workflow call", lambda d: d["jobs"].update(first={"needs": ["persona-uat"], "steps": [{"run": "true"}]}, second={"needs": ["first"], "uses": "o/r/.github/workflows/x.yml@" + "a" * 40}), w_)
    mutate(f"{lab_}: a successor uses a checkout pinned by tag only", "depends on persona-uat", lambda d: d["jobs"].update(report={"needs": ["persona-uat"], "steps": [{"uses": "actions/checkout@v4"}]}), w_)
    mutate(f"{lab_}: an always() job opens an issue", "runs whatever persona-uat did", lambda d: d["jobs"].update(report={"if": "${{ always() }}", "steps": [{"run": "gh issue create --title x --body y"}]}), w_)
    mutate(f"{lab_}: persona-uat is added to the needs of an existing issue job", "depends on persona-uat", lambda d: d["jobs"].setdefault("patch-failed" if "patch-failed" in d["jobs"] else "check", {}).update(needs=["persona-uat"]), w_)
mutate("a notify job needs persona-uat and opens an issue on failure()", "opens or touches a public issue", lambda d: d["jobs"].update(notify={"needs": ["persona-uat"], "if": "${{ failure() }}", "steps": [{"run": "gh issue create --title x --body y"}]}), "rel_wf")
mutate("a job with always() after persona-uat opens an issue through github-script", "opens or touches a public issue", lambda d: d["jobs"].update(report={"needs": ["persona-uat"], "if": "${{ always() }}", "steps": [{"uses": "actions/github-script@" + "c" * 40, "with": {"script": "await github.rest.issues.create({owner: o, repo: r, title: 't'})"}}]}), "rel_wf")
mutate("patch-failed becomes always() (it then runs when only persona-uat fails)", "opens or touches a public issue", lambda d: d["jobs"]["patch-failed"].update({"if": "${{ always() }}"}), "rel_wf")
mutate("a job that survives cancellation (!cancelled()) comments on an issue", "opens or touches a public issue", lambda d: d["jobs"].update(note={"needs": ["persona-uat"], "if": "${{ !cancelled() }}", "steps": [{"run": "gh issue comment 5 --body x"}]}), "rel_wf")
mutate("a job two hops after persona-uat opens an issue on failure()", "opens or touches a public issue", lambda d: d["jobs"].update(first={"needs": ["persona-uat"], "if": "${{ success() }}", "steps": [{"run": "true"}]}, second={"needs": ["first"], "if": "${{ failure() }}", "steps": [{"run": "gh issue create --title x --body y"}]}), "rel_wf")
mutate("the persona job itself calls gh api issues", "opens or touches a public issue", lambda j: j["steps"].append({"run": "gh api repos/o/r/issues -f title=x"}))
def _tokvar(script):
    m = re.search(r"(?:const|let|var)\s+(\w+)\s*=\s*await\s+core\.getIDToken", script)
    return m.group(1) if m else "token"
def _id_step(j): return next(s for s in j["steps"] if "github-script" in str(s.get("uses", "")))
mutate("rc identity step prints the token", "logs the token",
       lambda j: _id_step(j)["with"].update(script=_id_step(j)["with"]["script"] + "\nconsole.log(" + _tokvar(_id_step(j)["with"]["script"]) + ")"))
mutate("rc identity step masks a literal, not the token", "mask THE TOKEN",
       lambda j: _id_step(j)["with"].update(script=re.sub(r"core\.setSecret\(\s*\w+\s*\)", "core.setSecret('x')", _id_step(j)["with"]["script"])))
mutate("rc driver's --recipient is commented out", "is not run with --recipient exactly once", lambda j: drv(j).update(run=drv(j)["run"].replace("--recipient", "# --recipient")))
mutate("rc driver step gets a working-directory", "a working-directory on the driver step", lambda j: drv(j).update({"working-directory": "harness"}))
mutate("rc job default working-directory", "a working-directory on the driver step", lambda j: j.update(defaults={"run": {"working-directory": "x"}}))
mutate("release.yml gets a workflow-level working-directory", "workflow-level working-directory", lambda j: None, which="rel_defaults")
mutate("go-freshness.yml gets a workflow-level working-directory", "workflow-level working-directory", lambda j: None, which="fresh_defaults")
mutate("release.yml gets a workflow-level default shell", "workflow-level default shell", lambda j: None, which="rel_defaults_shell")
mutate("weekly driver script is a .py.bak copy and gets a stray argument", "is not exactly `python3 harness/bin/persona-uat.py", lambda j: drv(j).update(run=drv(j)["run"].replace("persona-uat.py", "persona-uat.py.bak", 1).rstrip() + " extra"), which="fresh")
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
mutate("rc job-level if: false", "does not run only for v*-rc.* tags", lambda j: j.update({"if": "false"}))
mutate("rc checkout with if: false", "checkout step is conditional or non-fatal", lambda j: next(x for x in j["steps"] if "actions/checkout" in str(x.get("uses", ""))).update({"if": "false"}))
mutate("rc SDK install continue-on-error: true", "SDK install step is conditional or non-fatal", lambda j: next(x for x in j["steps"] if "pip install" in str(x.get("run", ""))).update({"continue-on-error": "true"}))
mutate("rc runs-on windows-latest", "not an ubuntu runner", lambda j: j.update({"runs-on": "windows-latest"}))
mutate("rc matrix duplicating the job", "strategy/matrix", lambda j: j.update({"strategy": {"matrix": {"n": ["1", "2"]}}}))
mutate("rc kind install missing", "exactly one step", lambda j: j["steps"].remove(next(x for x in j["steps"] if "install-scanner" in str(x.get("run", "")))))
mutate("rc kind install before the checkout", "BEFORE the checkout", lambda j: j["steps"].insert(0, j["steps"].pop(j["steps"].index(next(x for x in j["steps"] if "install-scanner" in str(x.get("run", "")))))))
mutate("weekly job-level if: false", "does not run only on the Monday cron", lambda j: j.update({"if": "false"}), "fresh")
mutate("weekly checkout with if: false", "checkout step is conditional or non-fatal", lambda j: next(x for x in j["steps"] if "actions/checkout" in str(x.get("uses", ""))).update({"if": "false"}), "fresh")
mutate("weekly SDK install continue-on-error: true", "SDK install step is conditional or non-fatal", lambda j: next(x for x in j["steps"] if "pip install" in str(x.get("run", ""))).update({"continue-on-error": "true"}), "fresh")
mutate("weekly runs-on windows-latest", "not an ubuntu runner", lambda j: j.update({"runs-on": "windows-latest"}), "fresh")
mutate("weekly matrix duplicating the job", "strategy/matrix", lambda j: j.update({"strategy": {"matrix": {"n": ["1", "2"]}}}), "fresh")
mutate("weekly kind install missing", "exactly one step", lambda j: j["steps"].remove(next(x for x in j["steps"] if "install-scanner" in str(x.get("run", "")))), "fresh")
mutate("rc checkout of another repository", "checkout of another repository", lambda j: next(s for s in j["steps"] if "actions/checkout" in str(s.get("uses", ""))).setdefault("with", {}).update(repository="evil/cache"))
mutate("rc driver step overrides the identity token file", "outside the contract", lambda j: drv(j).setdefault("env", {}).update(ANTHROPIC_IDENTITY_TOKEN_FILE="/missing"))
mutate("rc identity step never awaits the token", "does not mint (await)",
       lambda j: (lambda s_: s_["with"].update(script=s_["with"]["script"].replace("await core.getIDToken", "core.getIDToken")))(next(s for s in j["steps"] if "github-script" in str(s.get("uses", "")))))
mutate("rc SDK install without hashes", "a run step before the driver other than",
       lambda j: next(s for s in j["steps"] if "pip install" in str(s.get("run", ""))).update(run="python3 -m pip install anthropic"))
mutate("tools: all eight point at one image", "not distinct images", lambda t: t.update({k: t["shell"] for k in t}), "tools")
mutate("tools: jenkins names another image", "does not name its own official image", lambda t: t.update(jenkins=t["shell"]), "tools")
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
# delta 2 (advisor 0207): eight entries, each official, digest-pinned and distinct
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
mutate("tools: two entries share one digest", "not distinct images", lambda t: t.update(kubectl="registry.k8s.io/kubectl@sha256:" + "8" * 64), "tools")
for variant, key, ref in (("cosign from ghcr", "cosign", "ghcr.io/sigstore/cosign/cosign@sha256:" + "5" * 64), ("gradle without library/", "gradle", "docker.io/gradle@sha256:" + "7" * 64)):
    good = []
    judge_tools({**TGOOD, key: ref}, good)
    result(not good, f"the judge accepts an official spelling ({variant})" + ("" if not good else ": " + "; ".join(good)))
# delta 1: nothing in the sources starts a privileged container
mutate("source: a privileged docker run in the driver", "starts a privileged container", lambda srcs: srcs.update({SRC[0]: 'args = ["run", "-d", "--privileged"]\n'}), "src")
mutate("source: a privileged flag in the agent", "starts a privileged container", lambda srcs: srcs.update({SRC[1]: 'argv = ["docker", "run", "--privileged", img]\n'}), "src")
mutate("source: privileged=True", "starts a privileged container", lambda srcs: srcs.update({SRC[0]: "d.start(ref, privileged=True)\n"}), "src")

# --- round 3: environment at EVERY scope (workflow, job, step) and the checkout/SDK prerequisites -----------------------------------------------------
VEND = "cla" + "ude-fixture"        # a model name, assembled so no file names one
for lab, w in (("release.yml", "rel_wf"), ("go-freshness.yml", "fresh_wf")):
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
mutate("rc SDK install step aliases a secret in its env", "step other than the driver", lambda j: next(x for x in j["steps"] if "pip install" in str(x.get("run", ""))).update(env={"X": "${{ secrets.ANTHROPIC_WORKSPACE_ID }}"}))
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
    mutate(f"{lab} SDK install with a working-directory", "carries keys outside its allowlist", lambda j: next(x for x in j["steps"] if "pip install" in str(x.get("run", ""))).update({"working-directory": "/tmp"}), w)
    mutate(f"{lab} SDK install with a shell", "carries keys outside its allowlist", lambda j: next(x for x in j["steps"] if "pip install" in str(x.get("run", ""))).update({"shell": "pwsh"}), w)
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
    mutate(f"{lab} a step reads a secret holding the private key", "private key", lambda j: next(x for x in j["steps"] if "pip install" in str(x.get("run", ""))).update(env={"K": "${{ secrets.PERSONA_UAT_PRIVATE_KEY }}"}), w)
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
for lab, w in (("rc", "rel"), ("weekly", "fresh")):
    mutate(f"{lab} the default model id arrives as a VARIABLE (printed in the step header)", "is not exactly secrets.PERSONA_UAT_MODEL", lambda j: drv(j)["env"].update(PERSONA_UAT_MODEL="${{ vars.PERSONA_UAT_MODEL }}"), w)
    mutate(f"{lab} the compliance model id arrives as a VARIABLE", "is not exactly secrets.PERSONA_UAT_COMPLIANCE_MODEL", lambda j: drv(j)["env"].update(PERSONA_UAT_COMPLIANCE_MODEL="${{ vars.PERSONA_UAT_COMPLIANCE_MODEL }}"), w)
    mutate(f"{lab} a literal model id on the driver step", "is not exactly secrets.PERSONA_UAT_MODEL", lambda j: drv(j)["env"].update(PERSONA_UAT_MODEL=VEND), w)
    mutate(f"{lab} a literal model id on the driver step (compliance)", "is not exactly secrets.PERSONA_UAT_COMPLIANCE_MODEL", lambda j: drv(j)["env"].update(PERSONA_UAT_COMPLIANCE_MODEL=VEND), w)
    mutate(f"{lab} the model id missing from the driver step", "is not exactly secrets.PERSONA_UAT_MODEL", lambda j: drv(j)["env"].pop("PERSONA_UAT_MODEL"), w)
    mutate(f"{lab} the token budget delivered as a secret", "is not exactly vars.PERSONA_UAT_TOKEN_BUDGET", lambda j: drv(j)["env"].update(PERSONA_UAT_TOKEN_BUDGET="${{ secrets.PERSONA_UAT_TOKEN_BUDGET }}"), w)
    mutate(f"{lab} the model id also in another step's env", "names a model id", lambda j: next(x for x in j["steps"] if "pip install" in str(x.get("run", ""))).update(env={"M": "${{ secrets.PERSONA_UAT_MODEL }}"}), w)
    mutate(f"{lab} the model id in a run step's text", "names a model id", lambda j: j["steps"].insert(0, {"run": 'echo "${{ secrets.PERSONA_UAT_MODEL }}"'}), w)
    mutate(f"{lab} the model id in the job-level env", "names a model id", lambda j: j.setdefault("env", {}).update(M="${{ secrets.PERSONA_UAT_MODEL }}"), w)
    mutate(f"{lab} the compliance model id in the identity step's script", "names a model id", lambda j: next(x for x in j["steps"] if "github-script" in str(x.get("uses", ""))).setdefault("with", {}).update(script=IDENT + "// ${{ secrets.PERSONA_UAT_COMPLIANCE_MODEL }}"), w)
    mutate(f"{lab} the model id in the driver's command text", "names a model id or a secret", lambda j: drv(j).update(run=drv(j)["run"] + ' --model "${{ secrets.PERSONA_UAT_MODEL }}"'), w)
    mutate(f"{lab} a model id reaches the artifact name", "artifact name", lambda j: up(j)["with"].update(name="persona-uat-${{ secrets.PERSONA_UAT_MODEL }}"), w)
for lab, w in (("release.yml", "rel_wf"), ("go-freshness.yml", "fresh_wf")):
    mutate(f"{lab}: workflow-level env holds the model id as a secret", "workflow-level env", lambda d: d.update(env={"PERSONA_UAT_MODEL": "${{ secrets.PERSONA_UAT_MODEL }}"}), w)
    mutate(f"{lab}: workflow-level env holds the compliance model id", "workflow-level env", lambda d: d.update(env={"PERSONA_UAT_COMPLIANCE_MODEL": "${{ secrets.PERSONA_UAT_COMPLIANCE_MODEL }}"}), w)
    mutate(f"{lab}: workflow-level env aliases a model secret", "workflow-level env", lambda d: d.update(env={"X": "${{ secrets.PERSONA_UAT_MODEL }}"}), w)

print(f"persona-uat wiring: {passed} passed, {failed} failed")
sys.exit(0 if failed == 0 else 1)
PY
