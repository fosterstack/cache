#!/usr/bin/env bash
# proves: REQ-FIPS-002-AC2
# The candidate images by digest are started and asked what they report. Parts:
#   0. the AC and the release note, as parsed (a YAML '#' once cut the AC at "CMVP cert").
#   A. the step is RUN, not read: its run: text is executed with a PATH of logging stub docker, curl and sleep (real jq,
#      a fixture posture script) and the log is judged: which images were pulled and run, with which flags, on which
#      ports, what was inspected, what was cleaned up, and the exit code under every failure. Plus the file-level facts
#      (no new action reference, permission, workflow file or conditional step; every action reference a digest).
#   B. the comparison script, offline, over fake /statusz bodies (and a reference implementation that proves the
#      cases are satisfiable and whose mutants prove the cases are strong).
#   C. mutants of the real comparison script, every one run against ALL B cases.
#
# Contract for the implementation (step 7) this test fixes:
#   step     in the k8s job, named exactly  STEP_NAME  below, run: in the default shell (no shell:, no if:, no
#            continue-on-error, env only DIGESTS: ${{ inputs.digests }}); the only ${{ }} in its run: are
#            github.repository_owner, github.token and github.actor. Tools it may use: docker, curl, jq, python3, sleep
#            and the usual coreutils. Docker subcommands: login, pull, run, inspect (container/image inspect), rm, logs, ps.
#            pull   : docker pull [-q] [--platform linux/amd64] ghcr.io/<owner>/cache-candidates@<digest of THAT variant>
#            run    : only -d --rm --name N -p 127.0.0.1:PORT:8080 --pull=never --platform linux/amd64 and
#                     -e FSCACHE_USERNAME=<literal> / -e FSCACHE_PASSWORD=<literal>, then the same reference, no command;
#                     three distinct names and loopback ports; nothing from the runner environment reaches the container.
#            health : curl on 127.0.0.1/localhost with --fail (or -w '%{http_code}' checked); a bounded wait; the first
#                     /statusz read comes after /healthz answered.
#            identity: docker inspect (by container name or id) of the container's image id or RepoDigests against the
#                     pulled image; the stub supports --format {{.Image}} {{.Id}} {{.Config.Image}} {{json .RepoDigests}}
#                     {{index .RepoDigests 0}} {{.RepoDigests}} {{range .RepoDigests}}{{.}} {{end}} and no format (JSON).
#                     A mismatch, an inspect failure or an empty answer must fail the step.
#            read   : the raw /statusz body of each variant goes to <dir>/<variant>.json.
#            compare: bin/fips-image-posture.py <dir>, once, after all three were tried; the step exits non-zero when
#                     the script does (and when anything before it failed); docker rm -f of every started container
#                     happens on success and on failure.
#   script   bin/fips-image-posture.py   (needs a bin/ allowlist pattern in bin/check-file-allowlist.sh and its test)
#   CLI      python3 bin/fips-image-posture.py <dir>
#            <dir> holds production.json, debug.json, fips.json (raw /statusz bodies). Exit 0 only when fips.json's
#            .fips140_note is exactly   active (Go validated module v1.0.0, CMVP cert #5247)
#            and production.json's and debug.json's are exactly   off   . Everything else exits non-zero and writes
#            "variant <name>: <why>" to stderr for each failing variant: a missing file, a symlink or directory in
#            place of the file, an empty or non-UTF-8 body, a BOM, non-JSON, trailing text, a body that is not a JSON
#            object, a duplicate key in the object, a missing or non-string field, a wrong argument count.
#            Extra files in <dir> are ignored. The two strings appear in the script as literals identical to
#            stage-acceptance-artifacts.yml's. Mutants (part C) need, for the script, only some accepted idiom: a quoted
#            "off", sys.exit(N)/raise SystemExit(N)/exit(N)/return 1, ==/!= comparisons, variant names as constants.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
pylib=$(mktemp -d); work=$(mktemp -d); trap 'rm -rf "$pylib" "$work"' EXIT
ln -s "$root/.github/agent/fixtures/testlib/pyyaml" "$pylib/yaml"
export PYTHONPATH="$pylib${PYTHONPATH:+:$PYTHONPATH}"
python3 - "$root" "$work" <<'PY'
import ast, hashlib, json, os, re, shutil, stat, subprocess, sys, tempfile, yaml
root, work = sys.argv[1], sys.argv[2]
passed = failed = 0
def check(name, ok, got=""):
    global passed, failed
    if ok: passed += 1; print("ok:", name)
    else: failed += 1; print("FAIL:", name, "->", str(got)[:300])
def rd(p): return open(os.path.join(root, p)).read()

GOOD_FIPS = "active (Go validated module v1.0.0, CMVP cert #5247)"
FORCED = "active (fips140 mode forced at runtime; not the validated-module build)"
VARIANTS = ("production", "debug", "fips")

# ---------------------------------------------------------------- 0. the AC and the release note, as parsed
EXPECT = {
 "given": "the three candidate image variants of a release by candidate digest (production, -debug and -fips; linux/amd64 on the hosted runner; linux/arm64 images are not started on the hosted runner, and whether emulation is acceptable is UNVERIFIED)",
 "when": "each is started and /statusz is read",
 "then": "the container started from each variant is the image pulled by that digest (its image id or RepoDigests compared with the pulled image); the -fips image reports 'active (Go validated module v1.0.0, CMVP cert #5247)', the production and -debug images report 'off'; and any other report (including the forced-mode line on a standard image), a variant whose container does not answer /statusz with a successful HTTP status, a container that is not the image pulled by that digest, or a missing variant blocks the release",
}
def find(o, i):
    if isinstance(o, dict):
        if o.get("id") == i: return o
        for v in o.values():
            r = find(v, i)
            if r: return r
    elif isinstance(o, list):
        for v in o:
            r = find(v, i)
            if r: return r
ac = find(yaml.safe_load(rd("requirements/requirements.yaml")), "REQ-FIPS-002-AC2") or {}
for k in ("given", "when", "then"):
    check("the parsed AC2 %s is the ratified text, verbatim" % k, ac.get(k) == EXPECT[k], ac.get(k))
check("the parsed AC2 then keeps '#5247', 'off' and 'blocks the release'",
      all(x in str(ac.get("then")) for x in ("#5247)", "'off'", "blocks the release")), ac.get("then"))
check("AC2 is release-blocking, acceptance-release-artifact, approved",
      ac.get("verification") == {"method": "acceptance-release-artifact", "release_blocking": True} and ac.get("status") == "approved", ac)
trace = rd("docs/quality/traceability.md")
check("the traceability matrix shows the full AC2 text", EXPECT["then"] in trace and "CMVP cert #5247)'" in trace)
paras = [p for p in rd("RELEASING.md").split("\n\n") if "REQ-FIPS-002-AC2" in p]
flat = " ".join(" ".join(paras).split())
check("RELEASING.md says AC2 gates only under a baseline frozen after it merged, v0.2.0 and v0.2.1 lacking it, the job failing blocks anyway",
      "frozen after it merged" in flat and "v0.2.0" in flat and "v0.2.1" in flat and "blocks the release regardless" in flat, flat)

# ---------------------------------------------------------------- A. the step, executed
STEP_NAME = "read the FIPS posture of the three candidate images by digest (REQ-FIPS-002-AC2)"
path = os.path.join(root, ".github/workflows/stage-acceptance-k8s.yml")
text = open(path).read()
wf = yaml.safe_load(text)
ON = wf[True] if True in wf else wf["on"]
job = wf["jobs"]["k8s"]
steps = job["steps"]

for i, s in enumerate(steps):
    n = s.get("name") or s.get("id") or s.get("uses") or i
    check("step %r has no continue-on-error, if: or shell:" % n, not {"continue-on-error", "if", "shell"} & set(s), sorted(s))
check("the job has no if:, continue-on-error, container or services", not {"if", "continue-on-error", "container", "services"} & set(job), sorted(job))
check("the workflow has no defaults or workflow-level env", "defaults" not in wf and "env" not in wf, [str(k) for k in wf])
check("the job env is unchanged (two keys)", set(job.get("env", {})) == {"CLIENT_IMAGE", "CLIENT_LOCAL"}, job.get("env"))
rel = yaml.safe_load(rd(".github/workflows/release.yml"))["jobs"]["acceptance-k8s"]
check("release.yml runs the k8s stage with no if: or continue-on-error", not {"if", "continue-on-error"} & set(rel), rel)
res = [t for t in steps if t.get("id") == "results"]
check("the results step is the last step and the only one with id results", len(res) == 1 and steps[-1] is res[0])
if res:
    r = res[0]["run"]
    m = re.search(r"results=(\[.*\])", r)
    try: ids = sorted((x["ac"], x["result"]) for x in json.loads(m.group(1)))
    except Exception as e: ids = repr(e)
    check("the results output names REQ-DEPLOY-003-AC1 and REQ-FIPS-002-AC2 as pass",
          ids == [("REQ-DEPLOY-003-AC1", "pass"), ("REQ-FIPS-002-AC2", "pass")], ids)
check("the stage's output still carries the results", ON["workflow_call"]["outputs"]["results"]["value"] == "${{ jobs.k8s.outputs.results }}")
uses = sorted(s["uses"] for s in steps if "uses" in s)
check("the stage's action references are the two it had, both commit digests",
      uses == ["actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", "helm/kind-action@06c1ae10762d3b9c1644e7fe69596ae519e015a2"], uses)
every = re.findall(r"^\s*(?:-\s+)?uses:\s*(\S+)", text, re.M)
check("every action reference in the file is a 40-hex commit digest",
      every and all(re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", u) for u in every), every)
check("the job's permissions are unchanged (contents read, packages read)", job["permissions"] == {"contents": "read", "packages": "read"}, job["permissions"])
check("the workflow's permissions are unchanged (contents read)", wf["permissions"] == {"contents": "read"}, wf["permissions"])
check("the stage's inputs are unchanged (digests only)", list(ON["workflow_call"]["inputs"]) == ["digests"])
g = subprocess.run(["git", "-C", root, "rev-parse", "--verify", "-q", "origin/main"], capture_output=True, text=True)
if g.returncode == 0:
    new = subprocess.run(["git", "-C", root, "diff", "--name-status", "--diff-filter=AR", "origin/main", "--", ".github/workflows"],
                         capture_output=True, text=True).stdout.strip()
    check("no workflow file is added or renamed relative to origin/main", new == "", new)
    pred = subprocess.run(["git", "-C", root, "diff", "--stat", "origin/main", "--", ".github/workflows/stage-acceptance-predicate.yml"],
                          capture_output=True, text=True).stdout.strip()
    check("stage-acceptance-predicate.yml is not changed", pred == "", pred)
else:
    print("note: origin/main not available; the no-new-workflow and predicate-unchanged checks are left to the diff review")

OWNER, TOKEN = "fixture-owner", "TOKEN-CANARY-8f3a91"
DIG = {v: "sha256:" + hashlib.sha256(("digest-" + v).encode()).hexdigest() for v in VARIANTS}
REF = {v: "ghcr.io/%s/cache-candidates@%s" % (OWNER, DIG[v]) for v in VARIANTS}
BODY = {"production": json.dumps({"fips140_note": "off", "who": "production"}),
        "debug": json.dumps({"fips140_note": "off", "who": "debug"}),
        "fips": json.dumps({"fips140_note": GOOD_FIPS, "who": "fips"})}

STUBLIB = r'''
import hashlib, json, os, re, sys
D = os.environ["STUB_DIR"]
CFG = json.load(open(D + "/cfg.json"))
ST = D + "/state.json"
OWNER = CFG["owner"]
def load():
    try: return json.load(open(ST))
    except Exception: return {"c": {}, "pulled": [], "health": {}}
def save(s): json.dump(s, open(ST, "w"))
def log(**r): open(D + "/log.jsonl", "a").write(json.dumps(r) + "\n")
def variant_of(ref):
    d = ref.split("@", 1)[1] if "@" in ref else None
    for v, x in CFG["digests"].items():
        if x == d: return v
def img_id(v): return "sha256:" + hashlib.sha256(("img-" + CFG["digests"][v]).encode()).hexdigest()
FOREIGN_ID = "sha256:" + hashlib.sha256(b"foreign").hexdigest()
FOREIGN_REPO = "ghcr.io/%s/cache-candidates@sha256:%s" % (OWNER, hashlib.sha256(b"foreign-digest").hexdigest())
def repo(v): return "ghcr.io/%s/cache-candidates@%s" % (OWNER, CFG["digests"][v])
VALUED = {"--name", "-p", "--publish", "-e", "--env", "--platform", "--entrypoint", "-v", "--volume", "--mount", "--user", "-u",
          "--network", "--net", "--security-opt", "--cap-add", "--cap-drop", "--device", "--userns", "--ipc", "--uts", "--pid",
          "--env-file", "--add-host", "--workdir", "-w", "--label", "-l", "--restart", "--memory", "-m", "--cpus", "--hostname",
          "-h", "--tmpfs", "--pull"}
def render(fmt, o):
    rd = o.get("RepoDigests")
    toks = {"{{.Image}}": o.get("Image"), "{{.Id}}": o.get("Id"), "{{.ID}}": o.get("Id"), "{{.Config.Image}}": o.get("ConfigImage"),
            "{{json .RepoDigests}}": None if rd is None else json.dumps(rd),
            "{{index .RepoDigests 0}}": None if rd is None else (rd[0] if rd else ""),
            "{{.RepoDigests}}": None if rd is None else "[" + " ".join(rd) + "]",
            "{{range .RepoDigests}}{{.}} {{end}}": None if rd is None else "".join(x + " " for x in rd)}
    out = fmt
    for k, v in toks.items():
        if k in out:
            if v is None: return None
            out = out.replace(k, v)
    return None if "{{" in out else out
def docker(a):
    s = load()
    if not a: sys.exit(1)
    sub, rest = a[0], a[1:]
    if sub in ("container", "image") and rest:
        sub, rest = rest[0], rest[1:]
    if sub == "login":
        log(cmd="docker", sub="login", args=rest); sys.stdin.read(); sys.exit(0)
    if sub == "pull":
        pos, i = [], 0
        while i < len(rest):
            if rest[i] == "--platform": i += 2; continue
            if not rest[i].startswith("-"): pos.append(rest[i])
            i += 1
        log(cmd="docker", sub="pull", args=rest, positional=pos)
        if len(pos) != 1 or pos[0] not in [repo(v) for v in CFG["digests"]] or variant_of(pos[0]) in CFG["pull_fail"]:
            sys.stderr.write("Error: pull failed\n"); sys.exit(1)
        s["pulled"].append(pos[0]); save(s); sys.exit(0)
    if sub == "run":
        i, image, name, port = 0, None, None, None
        while i < len(rest):
            x = rest[i]
            if x == "--name" and i + 1 < len(rest): name = rest[i + 1]
            if x.startswith("--name="): name = x.split("=", 1)[1]
            if x in ("-p", "--publish") and i + 1 < len(rest):
                m = re.match(r"(?:[^:]+:)?(\d+):(\d+)$", rest[i + 1]); port = int(m.group(1)) if m else None
            if x.startswith("--publish="):
                m = re.match(r"(?:[^:]+:)?(\d+):(\d+)$", x.split("=", 1)[1]); port = int(m.group(1)) if m else None
            if x in VALUED: i += 2; continue
            if not x.startswith("-"): image = x; break
            i += 1
        v = variant_of(image or "")
        ok = bool(image) and image in s["pulled"] and v not in CFG["run_fail"]
        if ok and str(name) in s["c"]: ok = False
        if ok and port is not None and any(c["port"] == port for c in s["c"].values()): ok = False
        cid = hashlib.md5(str(name).encode()).hexdigest()[:12]
        log(cmd="docker", sub="run", args=rest, image=image, name=name, port=port, variant=v, started=ok, id=cid)
        if not ok:
            sys.stderr.write("docker: run failed\n"); sys.exit(125)
        s["c"][str(name)] = {"id": cid, "image": image, "variant": v, "port": port}
        save(s); print(cid); sys.exit(0)
    if sub == "inspect":
        mode = CFG["inspect"]
        fmt, targets, i = None, [], 0
        while i < len(rest):
            x = rest[i]
            if x in ("-f", "--format") and i + 1 < len(rest): fmt = rest[i + 1]; i += 2; continue
            if x.startswith("--format="): fmt = x.split("=", 1)[1]; i += 1; continue
            if x == "--type": i += 2; continue
            if not x.startswith("-"): targets.append(x)
            i += 1
        log(cmd="docker", sub="inspect", args=rest, targets=targets, fmt=fmt)
        if mode == "fail": sys.stderr.write("Error: No such object\n"); sys.exit(1)
        if mode == "empty": sys.exit(0)
        outs = []
        for t in targets:
            c = next((c for n, c in s["c"].items() if t == n or t == c["id"]), None)
            if c:
                bad = mode == "mismatch:" + str(c["variant"])
                o = {"Id": c["id"], "Image": FOREIGN_ID if bad else img_id(c["variant"]), "ConfigImage": c["image"]}
            else:
                v = next((v for v in CFG["digests"] if t == repo(v) or t == img_id(v)), None)
                if v: o = {"Id": img_id(v), "RepoDigests": [repo(v)]}
                elif t == FOREIGN_ID: o = {"Id": FOREIGN_ID, "RepoDigests": [FOREIGN_REPO]}
                else: sys.stderr.write("Error: No such object: %s\n" % t); sys.exit(1)
            if fmt is None: outs.append(json.dumps([o]))
            else:
                r = render(fmt, o)
                if r is None: sys.stderr.write("stub: unsupported or inapplicable format %r\n" % fmt); sys.exit(1)
                outs.append(r)
        print("\n".join(outs)); sys.exit(0)
    if sub == "rm":
        names = [x for x in rest if not x.startswith("-")]
        log(cmd="docker", sub="rm", args=rest, names=names)
        rc = 0
        for n in names:
            k = next((k for k, c in s["c"].items() if n == k or n == c["id"]), None)
            if k: del s["c"][k]; print(n)
            else: sys.stderr.write("Error: No such container: %s\n" % n); rc = 1
        save(s); sys.exit(rc)
    if sub in ("logs", "ps"):
        log(cmd="docker", sub=sub, args=rest); sys.exit(0)
    log(cmd="docker", sub=sub, args=rest, unexpected=True)
    sys.stderr.write("stub: unexpected docker subcommand %s\n" % sub); sys.exit(1)
def curl(a):
    s = load()
    fail, url, out, wo, i = False, None, None, None, 0
    LV = {"--max-time", "--connect-timeout", "--retry", "--retry-delay", "--retry-max-time", "--output", "--write-out", "--header",
          "--user", "--request", "--data", "--data-binary", "--url", "--resolve", "--interface", "--proxy"}
    while i < len(a):
        x = a[i]
        if x in ("--fail", "--fail-with-body"): fail = True
        elif x in LV or (x.startswith("--") and "=" in x and x.split("=")[0] in LV):
            if "=" in x: k, v = x.split("=", 1)
            else: k, v = x, (a[i + 1] if i + 1 < len(a) else ""); i += 1
            if k == "--output": out = v
            if k == "--write-out": wo = v
            if k == "--url": url = v
        elif x.startswith("--"): pass
        elif x.startswith("-") and len(x) > 1:
            j = 1
            while j < len(x):
                ch = x[j]
                if ch == "f": fail = True
                if ch in "moHuXAdwT":
                    v = x[j + 1:] if x[j + 1:] else (a[i + 1] if i + 1 < len(a) else "")
                    if not x[j + 1:]: i += 1
                    if ch == "o": out = v
                    if ch == "w": wo = v
                    break
                j += 1
        else: url = x
        i += 1
    m = re.match(r"^(?:https?://)?(\[[^\]]+\]|[^/:]+)(?::(\d+))?(/[^?#]*)?", url or "")
    host, port, path = (m.group(1), int(m.group(2) or 80), m.group(3) or "/") if m else (None, None, None)
    rec = dict(cmd="curl", args=a, url=url, fail=fail, wo=wo, host=host, port=port, path=path)
    if host not in ("127.0.0.1", "localhost", "[::1]"):
        log(result="nonloopback", **rec); sys.stderr.write("curl: (7) not loopback\n"); sys.exit(7)
    c = next((c for c in s["c"].values() if c["port"] == port), None)
    if not c:
        log(result="refused", **rec); sys.stderr.write("curl: (7) refused\n"); sys.exit(7)
    v = c["variant"]
    if path == "/healthz":
        n = s["health"].get(c["id"], 0); s["health"][c["id"]] = n + 1; save(s)
        h = CFG["health"].get(v, 0)
        code, body = (503, "unhealthy") if (h == "never" or n < h) else (200, "ok")
    elif path == "/statusz":
        code, body = (500, '{"error":"internal"}') if v in CFG["http_error"] else (200, CFG["bodies"][v])
    else:
        code, body = 404, "not found"
    log(result="ok" if code < 400 else "http_error", code=code, variant=v, **rec)
    if code >= 400 and fail:
        sys.stderr.write("curl: (22) The requested URL returned error: %d\n" % code); sys.exit(22)
    wtxt = (wo or "").replace("%{http_code}", str(code))
    if out and out not in ("-", "/dev/null"):
        open(out, "w").write(body); sys.stdout.write(wtxt)
    elif out == "/dev/null": sys.stdout.write(wtxt)
    else: sys.stdout.write(body + wtxt)
    sys.exit(0)
def main(kind):
    a = sys.argv[1:]
    if kind == "sleep": log(cmd="sleep", args=a); sys.exit(0)
    (docker if kind == "docker" else curl)(a)
'''
POSTURE_FIXTURE = '''import json, os, sys
D = os.environ["STUB_DIR"]
d = sys.argv[1:]
files = {}
if len(d) == 1 and os.path.isdir(d[0]):
    for f in sorted(os.listdir(d[0])): files[f] = open(os.path.join(d[0], f)).read()
open(D + "/log.jsonl", "a").write(json.dumps({"cmd": "posture", "argv": d, "files": files, "script": os.path.realpath(__file__)}) + "\\n")
sys.exit(json.load(open(D + "/cfg.json"))["posture_exit"])
'''
TOOLS = ["bash", "sh", "jq", "python3", "mktemp", "cat", "mkdir", "rm", "seq", "tr", "cut", "head", "tail", "grep", "sed", "awk",
         "printf", "date", "true", "false", "test", "[", "dirname", "basename", "tee", "wc", "sort", "cmp", "diff", "env",
         "readlink", "cp", "mv", "ls", "chmod", "expr", "xargs", "id", "uname", "touch", "echo"]
ALLOWED_EXPR = {"github.repository_owner": OWNER, "github.token": TOKEN, "github.actor": "actor-fixture"}

def build_env(d, sc, step):
    stub, tools, ws, tmp = d + "/stub", d + "/tools", d + "/ws", d + "/tmp"
    for p in (stub, tools, ws + "/bin", tmp, d + "/home"): os.makedirs(p, exist_ok=True)
    open(stub + "/stublib.py", "w").write(STUBLIB)
    json.dump(sc, open(stub + "/cfg.json", "w"))
    for k in ("docker", "curl", "sleep"):
        open(stub + "/" + k, "w").write("#!%s\nimport sys; sys.path.insert(0, %r); import stublib; stublib.main(%r)\n" % (sys.executable, stub, k))
        os.chmod(stub + "/" + k, 0o755)
    for t in TOOLS:
        w = shutil.which(t)
        if w and not os.path.exists(tools + "/" + t): os.symlink(w, tools + "/" + t)
    open(ws + "/bin/fips-image-posture.py", "w").write(POSTURE_FIXTURE)
    env = {"PATH": stub + ":" + tools, "HOME": d + "/home", "STUB_DIR": stub, "GITHUB_WORKSPACE": ws, "RUNNER_TEMP": tmp, "TMPDIR": tmp,
           "GITHUB_TOKEN": TOKEN + "-env", "GH_TOKEN": TOKEN + "-env2", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": TOKEN + "-env3", "LANG": "C"}
    problems = []
    for k, v in (step.get("env") or {}).items():
        if v == "${{ inputs.digests }}": env[k] = json.dumps(DIG)
        else: problems.append("step env %s=%r" % (k, v))
    return env, ws, problems

def run_step(sc, step):
    d = tempfile.mkdtemp(dir=work)
    env, ws, problems = build_env(d, sc, step)
    body = step["run"]
    for m in re.findall(r"\$\{\{\s*([^}]*?)\s*\}\}", body):
        if m not in ALLOWED_EXPR: problems.append("expression ${{ %s }} in run:" % m)
    for k, v in ALLOWED_EXPR.items(): body = re.sub(r"\$\{\{\s*" + re.escape(k) + r"\s*\}\}", v, body)
    open(d + "/step.sh", "w").write(body)
    try:
        p = subprocess.run([shutil.which("bash"), "-e", d + "/step.sh"], cwd=ws, env=env, capture_output=True, text=True, timeout=30)
        rc, err = p.returncode, p.stderr
    except subprocess.TimeoutExpired:
        rc, err = None, "timeout"
    logf = env["STUB_DIR"] + "/log.jsonl"
    log = [json.loads(l) for l in open(logf)] if os.path.exists(logf) else []
    return rc, err, log, problems

def parse_run(args):
    """allowlist parse of docker run args -> (problems, image, name, port)"""
    bad, img, name, port, i = [], None, None, None, 0
    while i < len(args):
        a = args[i]
        nxt = args[i + 1] if i + 1 < len(args) else ""
        if a in ("-d", "--detach", "--rm", "--pull=never"): i += 1
        elif a == "--name" or a.startswith("--name="):
            v = nxt if a == "--name" else a.split("=", 1)[1]; i += 2 if a == "--name" else 1
            name = v
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", v): bad.append("name " + v)
        elif a in ("-p", "--publish") or a.startswith("--publish="):
            v = nxt if a in ("-p", "--publish") else a.split("=", 1)[1]; i += 2 if a in ("-p", "--publish") else 1
            m = re.fullmatch(r"127\.0\.0\.1:(\d{4,5}):8080", v)
            if m: port = int(m.group(1))
            else: bad.append("publish " + v)
        elif a == "--platform" or a == "--platform=linux/amd64":
            v = nxt if a == "--platform" else "linux/amd64"; i += 2 if a == "--platform" else 1
            if v != "linux/amd64": bad.append("platform " + v)
        elif a in ("-e", "--env"):
            if not re.fullmatch(r"FSCACHE_(USERNAME|PASSWORD)=[A-Za-z0-9._-]{1,32}", nxt): bad.append("env " + nxt)
            i += 2
        elif a.startswith("-"): bad.append("flag " + a); i += 1
        else:
            img = a
            if args[i + 1:]: bad.append("arguments after the image: %r" % args[i + 1:])
            break
    return bad, img, name, port

def judge_good(rc, err, log, problems):
    dock = [r for r in log if r.get("cmd") == "docker"]
    check("good run: the step exits 0", rc == 0, (rc, err.strip()[-200:]))
    check("good run: the step uses no other ${{ }} expression and only env DIGESTS", not problems, problems)
    check("good run: no unexpected docker subcommand and no non-loopback or unreachable curl",
          not [r for r in dock if r.get("unexpected")] and not [r for r in log if r.get("cmd") == "curl" and r["result"] in ("refused", "nonloopback")],
          [r for r in log if r.get("unexpected") or r.get("result") in ("refused", "nonloopback")])
    pulls = [r for r in dock if r["sub"] == "pull"]
    badp = []
    for r in pulls:
        a = [x for x in r["args"] if x not in ("-q", "--quiet", "--platform", "linux/amd64", "--platform=linux/amd64")]
        if len(a) != 1: badp.append(r["args"])
    check("good run: every docker pull argument is a known flag or exactly its variant's ghcr.io/OWNER/cache-candidates@digest",
          not badp and sorted(r["positional"][0] for r in pulls if r["positional"]) == sorted(REF.values()), (badp, [r["positional"] for r in pulls]))
    runs = [r for r in dock if r["sub"] == "run"]
    issues, ports = [], []
    for r in runs:
        bad, img, name, port = parse_run(r["args"])
        issues += bad
        if port is None: issues.append("no loopback port")
        ports.append(port)
        if TOKEN in " ".join(r["args"]): issues.append("runner token in docker run")
    check("good run: every docker run flag is on the allowlist, the image is the pulled reference, no runner credential",
          not issues and sorted(str(r["image"]) for r in runs) == sorted(REF.values()), (issues, [r["image"] for r in runs]))
    check("good run: the three containers have distinct names and distinct loopback ports",
          len(runs) == 3 and len({r["name"] for r in runs}) == 3 and len(set(ports)) == 3 and None not in ports, [(r["name"], r["port"]) for r in runs])
    secrets = [r for r in log if r.get("cmd") in ("docker", "curl") and r.get("sub") != "login" and TOKEN in json.dumps(r.get("args"))]
    check("good run: the registry token appears in no pull, run, inspect or curl argument", not secrets, secrets)
    check("good run: a docker login, if any, takes the token on stdin", all(TOKEN not in " ".join(r["args"]) for r in dock if r["sub"] == "login"))
    ins = [r for r in dock if r["sub"] == "inspect"]
    seen = {t for r in ins for t in r["targets"]}
    check("good run: the container's image is compared with the pulled image (docker inspect of each of the three containers)",
          len(runs) == 3 and all(r["name"] in seen or r["id"] in seen for r in runs), [r["targets"] for r in ins])
    cu = [r for r in log if r.get("cmd") == "curl"]
    check("good run: every curl fails on an HTTP error (--fail, or the status code is written out and checked)",
          cu and all(r["fail"] or (r["wo"] and "http_code" in r["wo"]) for r in cu), [r["args"] for r in cu if not r["fail"]])
    order_ok = True
    for v in VARIANTS:
        idx = [k for k, r in enumerate(log) if r.get("cmd") == "curl" and r.get("variant") == v]
        h = [k for k in idx if log[k]["path"] == "/healthz" and log[k]["result"] == "ok"]
        sz = [k for k in idx if log[k]["path"] == "/statusz" and log[k]["result"] == "ok"]
        if not (h and sz and min(sz) > min(h)): order_ok = False
    check("good run: each variant is waited on until /healthz answers (after 2-3 refusals), then /statusz is read", order_ok)
    post = [k for k, r in enumerate(log) if r.get("cmd") == "posture"]
    check("good run: the comparison script is invoked exactly once, as bin/fips-image-posture.py <dir>",
          len(post) == 1 and log[post[0]]["script"].endswith("/ws/bin/fips-image-posture.py") and len(log[post[0]]["argv"]) == 1, [log[k] for k in post])
    lastrun = max([k for k, r in enumerate(log) if r.get("sub") == "run"] or [-1])
    check("good run: the comparison script runs after all three variants were started and read", bool(post) and post[0] > lastrun and
          all(any(k < post[0] and log[k].get("cmd") == "curl" and log[k].get("variant") == v and log[k].get("path") == "/statusz" for k in range(len(log))) for v in VARIANTS))
    if post:
        files = log[post[0]]["files"]
        check("good run: the script is handed each variant's raw /statusz body as <variant>.json",
              all(files.get(v + ".json", "").strip() == BODY[v] for v in VARIANTS), files)
    else:
        check("good run: the script is handed each variant's raw /statusz body as <variant>.json", False, "script not invoked")
    started = [r["name"] for r in runs if r["started"]]
    rms = [r for r in log if r.get("sub") == "rm"]
    ok = all(any(n in r["names"] and ("-f" in r["args"] or "--force" in r["args"]) for r in rms) for n in started)
    check("good run: docker rm -f of every started container", bool(started) and ok, (started, [r["args"] for r in rms]))

def judge_bad(label, sc, step):
    rc, err, log, problems = run_step(sc, step)
    check("%s: the step ends (no hang) and exits non-zero" % label, rc is not None and rc != 0, (rc, err[-150:]))
    runs = [r for r in log if r.get("sub") == "run" and r["started"]]
    rms = [r for r in log if r.get("sub") == "rm"]
    check("%s: every container it started is removed" % label,
          all(any(r["name"] in x["names"] or r["id"] in x["names"] for x in rms) for r in runs), ([r["name"] for r in runs], [x["names"] for x in rms]))
    check("%s: the comparison script ran at most once" % label, len([r for r in log if r.get("cmd") == "posture"]) <= 1)

def base_cfg(**kw):
    c = dict(owner=OWNER, digests=DIG, bodies=BODY, pull_fail=[], run_fail=[], health={"production": 2, "debug": 0, "fips": 3},
             http_error=[], inspect="ok", posture_exit=0)
    c.update(kw); return c

hit = [s for s in steps if s.get("name") == STEP_NAME]
check("exactly one step is named %r" % STEP_NAME, len(hit) == 1, [s.get("name") for s in steps])
check("that step comes before the results step, runs in the default shell, set -euo pipefail",
      len(hit) == 1 and steps.index(hit[0]) < len(steps) - 1 and "shell" not in hit[0] and "set -euo pipefail" in hit[0].get("run", ""))
SC = [("good run", None)] + [("%s pull fails" % v, dict(pull_fail=[v])) for v in VARIANTS] + \
     [("%s run fails" % v, dict(run_fail=[v])) for v in VARIANTS] + \
     [("%s never becomes healthy" % v, dict(health={"production": 0, "debug": 0, "fips": 0, v: "never"})) for v in VARIANTS] + \
     [("%s answers /statusz with HTTP 500" % v, dict(http_error=[v])) for v in VARIANTS] + \
     [("%s container is not the image pulled" % v, dict(inspect="mismatch:" + v)) for v in VARIANTS] + \
     [("docker inspect fails", dict(inspect="fail")), ("docker inspect answers nothing", dict(inspect="empty")),
      ("the comparison script exits 1", dict(posture_exit=1)), ("the comparison script exits 3", dict(posture_exit=3))]
for label, kw in SC:
    if len(hit) != 1: check("%s: the step exists to be run" % label, False, "step missing")
    elif kw is None: judge_good(*run_step(base_cfg(), hit[0]))
    else: judge_bad(label, base_cfg(**kw), hit[0])

# ---------------------------------------------------------------- B. the comparison script
script = os.path.join(root, "bin/fips-image-posture.py")
def body(note): return json.dumps({"fips140_note": note, "version": "x"})
GOOD = {"production": body("off"), "debug": body("off"), "fips": body(GOOD_FIPS)}
def mut(**kw): b = dict(GOOD); b.update(kw); return b
CASES = []
def case(name, bodies, ok, who=(), args=None): CASES.append((name, bodies, ok, tuple(who), args))
case("the exact good strings", GOOD, True)
case("extra fields, whitespace and nesting around the JSON", mut(fips=' {"a":{"fips140_note":"x"}, "fips140_note": "%s"}\n' % GOOD_FIPS, production='{"fips140_note":"off","x":[1]}\n'), True)
case("extra files in the directory are ignored", dict(GOOD, **{"fips.json.bak": body("off"), "other.json": "garbage", "notes.txt": "x"}), True)
for n, b in [("-fips reports off", body("off")), ("-fips reports the wrong certificate", body(GOOD_FIPS.replace("5247", "5248"))),
             ("-fips reports the wrong module version", body(GOOD_FIPS.replace("v1.0.0", "v1.0.1"))),
             ("-fips reports the forced-mode line", body(FORCED)), ("-fips string with a trailing space", body(GOOD_FIPS + " ")),
             ("-fips string in another case", body(GOOD_FIPS.upper())), ("-fips string with a suffix", body(GOOD_FIPS + "; extra")),
             ("-fips string with a prefix", body("x " + GOOD_FIPS))]:
    case(n, mut(fips=b), False, ["fips"])
for v in ("production", "debug"):
    case("%s reports the fips string" % v, mut(**{v: body(GOOD_FIPS)}), False, [v])
    case("%s reports the forced-mode line" % v, mut(**{v: body(FORCED)}), False, [v])
    for s in ("off ", " off", "Off", "OFF", "off (x)", "of", "o", ""):
        case("%s reports %r" % (v, s), mut(**{v: body(s)}), False, [v])
for v in VARIANTS:
    want = GOOD_FIPS if v == "fips" else "off"
    case("the %s variant is missing" % v, mut(**{v: None}), False, [v])
    for n, b in [("empty", ""), ("not JSON", "<html>not json</html>"), ("truncated JSON", '{"fips140_note": "off"'), ("a JSON array", '["off"]'),
                 ("a JSON string", '"off"'), ("JSON true", "true"), ("JSON false", "false"), ("JSON null", "null"), ("a JSON number", "0"),
                 ("without the field", '{"version":"x"}'), ("with a null field", '{"fips140_note": null}'), ("with a numeric field", '{"fips140_note": 0}'),
                 ("with a list field", '{"fips140_note": ["off"]}'), ("with trailing text", body(want) + " x"), ("with two documents", body(want) + body(want)),
                 ("with a UTF-8 BOM", b"\xef\xbb\xbf" + body(want).encode()), ("with non-UTF-8 bytes", b'{"fips140_note":"' + want.encode() + b'","x":"\xff"}'),
                 ("with only whitespace", " \n"), ("with a NUL byte", body(want).encode() + b"\x00")]:
        case("the %s body is %s" % (v, n), mut(**{v: b}), False, [v])
    case("the %s body has a duplicate key (same value)" % v, mut(**{v: '{"fips140_note":"%s","fips140_note":"%s"}' % (want, want)}), False, [v])
    case("the %s body has a duplicate key (wrong first)" % v, mut(**{v: '{"fips140_note":"x","fips140_note":"%s"}' % want}), False, [v])
    case("the %s body has a duplicate key (wrong last)" % v, mut(**{v: '{"fips140_note":"%s","fips140_note":"x"}' % want}), False, [v])
    case("the %s file is a symlink to a good body" % v, mut(**{v: ("symlink", body(want))}), False, [v])
    case("the %s file is a directory" % v, mut(**{v: ("dir",)}), False, [v])
case("a note in a nested object only", mut(fips='{"x":{"fips140_note":"%s"}}' % GOOD_FIPS), False, ["fips"])
case("all three variants are missing", {k: None for k in GOOD}, False)
case("two variants are bad: both are named", mut(production=body(GOOD_FIPS), debug=body(FORCED)), False, ["production", "debug"])
case("no argument", GOOD, False, args=[])
case("an extra argument", GOOD, False, args=["@D", "extra"])
case("a directory that does not exist", GOOD, False, args=["@D/no-such-dir"])

def make_dir(bodies):
    d = tempfile.mkdtemp(dir=work)
    for k, v in bodies.items():
        p = os.path.join(d, k if "." in k else k + ".json")
        if v is None: continue
        if isinstance(v, tuple) and v[0] == "symlink":
            t = tempfile.mkdtemp(dir=work) + "/target"; open(t, "w").write(v[1]); os.symlink(t, p)
        elif isinstance(v, tuple): os.mkdir(p)
        else: open(p, "wb").write(v if isinstance(v, bytes) else v.encode())
    return d
def run_case(sp, c):
    name, bodies, ok, who, args = c
    d = make_dir(bodies)
    a = [d] if args is None else [x.replace("@D", d) for x in args]
    try:
        p = subprocess.run([sys.executable, sp] + a, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return False
    if ok: return p.returncode == 0
    return p.returncode != 0 and all(("variant %s:" % w) in p.stderr for w in who)
def first_failure(sp):
    for c in CASES:
        if not run_case(sp, c): return c[0]
    return None

REFSRC = r'''import json, os, stat, sys
WANT = (("production", "off"), ("debug", "off"), ("fips", "active (Go validated module v1.0.0, CMVP cert #5247)"))
def pairs(p):
    seen = set()
    for k, _ in p:
        if k in seen: raise ValueError("duplicate key " + k)
        seen.add(k)
    return dict(p)
def check(d, name, want):
    path = os.path.join(d, name + ".json")
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode): return "not a regular file"
        raw = open(path, "rb").read()
        if raw.startswith(b"\xef\xbb\xbf"): return "BOM"
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except Exception as e:
        return "unreadable: %s" % e
    if not isinstance(doc, dict): return "not an object"
    got = doc.get("fips140_note")
    if not isinstance(got, str): return "no fips140_note string"
    if got != want: return "reports %r, want %r" % (got, want)
    return None
def main(argv):
    if len(argv) != 1 or not os.path.isdir(argv[0]): return 2
    bad = 0
    for name, want in WANT:
        why = check(argv[0], name, want)
        if why: print("variant %s: %s" % (name, why), file=sys.stderr); bad = 1
    return 1 if bad else 0
sys.exit(main(sys.argv[1:]))
'''
rp = os.path.join(work, "reference.py"); open(rp, "w").write(REFSRC)
ff = first_failure(rp)
check("the %d cases are satisfiable: a reference implementation passes every one" % len(CASES), ff is None, ff)
REFMUT = [
 ("a missing file is accepted", 'if not stat.S_ISREG(os.lstat(path).st_mode): return "not a regular file"',
  'if not os.path.lexists(path): return None\n        if not stat.S_ISREG(os.lstat(path).st_mode): return "not a regular file"'),
 ("an empty body is accepted", 'raw = open(path, "rb").read()', 'raw = open(path, "rb").read()\n        if not raw.strip(): return None'),
 ("a JSON error is swallowed as a pass", 'return "unreadable: %s" % e', "return None"),
 ("a symlink is followed", "os.lstat(path)", "os.stat(path)"),
 ("a BOM is tolerated", 'if raw.startswith(b"\\xef\\xbb\\xbf"): return "BOM"', 'raw = raw.lstrip(b"\\xef\\xbb\\xbf")'),
 ("a duplicate key is tolerated", "raise ValueError", "pass; #"),
 ("matching is by prefix", "if got != want:", "if not got.startswith(want):"),
 ("matching is by containment", "if got != want:", "if want not in got:"),
 ("matching ignores surrounding whitespace", "if got != want:", "if got.strip() != want:"),
 ("matching ignores case", "if got != want:", "if got.lower() != want.lower():"),
 ("the debug variant is skipped", 'WANT = (("production", "off"), ("debug", "off"), ', 'WANT = (("production", "off"), '),
 ("the production variant is skipped", 'WANT = (("production", "off"), ', "WANT = ("),
 ("the fips variant is skipped", ', ("fips", "active (Go validated module v1.0.0, CMVP cert #5247)"))', ")"),
 ("the fips and production expectations are swapped", '(("production", "off"), ("debug", "off"), ("fips", "active (Go validated module v1.0.0, CMVP cert #5247)"))',
  '(("production", "active (Go validated module v1.0.0, CMVP cert #5247)"), ("debug", "off"), ("fips", "off"))'),
 ("production reads debug.json and debug reads production.json", 'os.path.join(d, name + ".json")',
  'os.path.join(d, {"production": "debug", "debug": "production"}.get(name, name) + ".json")'),
 ("the wrong certificate is expected", "#5247", "#5248"),
 ("the exit code is always 0", "return 1 if bad else 0", "return 0"),
 ("an extra argument is tolerated", "if len(argv) != 1 or", "if len(argv) < 1 or"),
 ("the variant is not named in the error", 'print("variant %s: %s" % (name, why)', 'print("%s" % (why,)'),
 ("only the first failing variant is reported", "bad = 1", "bad = 1; break"),
]
for name, a, b in REFMUT:
    if a not in REFSRC: check("reference mutant is applicable: " + name, False, "snippet not found"); continue
    mp = os.path.join(work, "refmut.py"); open(mp, "w").write(REFSRC.replace(a, b, 1))
    try: compile(open(mp).read(), mp, "exec")
    except SyntaxError as e: check("reference mutant is valid Python: " + name, False, e); continue
    check("the cases kill the reference mutant: " + name, first_failure(mp) is not None)

exists = os.path.isfile(script)
check("the comparison script bin/fips-image-posture.py exists", exists)
for c in CASES: check("script: " + c[0], exists and run_case(script, c), "" if exists else "script missing")

art = rd(".github/workflows/stage-acceptance-artifacts.yml")
lit_fips = re.search(r'p_fips\}" = "([^"]*)"', art); lit_off = re.search(r'p_std\}" = "([^"]*)"', art)
check("drift guard: the artifact stage's literals are the ones this test and AC2 use",
      lit_fips and lit_off and lit_fips.group(1) == GOOD_FIPS and lit_off.group(1) == "off", (lit_fips and lit_fips.group(1), lit_off and lit_off.group(1)))
src = open(script).read() if exists else ""
check("drift guard: the script contains the artifact stage's fips literal exactly once and a quoted 'off'",
      bool(exists and lit_fips and lit_fips.group(1) in src and re.search(r"""(["'])off\1""", src) and src.count("active (Go validated") == 1),
      "script missing" if not exists else "")

# ---------------------------------------------------------------- C. mutants of the real script, all cases each
def regex_mut(pairs):
    def f(s):
        t = s
        for pat, rep in pairs: t = re.sub(pat, rep, t)
        return t
    return f
def plain(n):
    return isinstance(n, ast.Constant) and not isinstance(n.value, str) or (isinstance(n, ast.Call) and getattr(n.func, "id", "") == "len")
class EqToIn(ast.NodeTransformer):
    def __init__(self, swap): self.swap = swap
    def visit_Compare(self, n):
        self.generic_visit(n)
        if len(n.ops) == 1 and isinstance(n.ops[0], (ast.Eq, ast.NotEq)) and not plain(n.left) and not plain(n.comparators[0]):
            op = ast.In() if isinstance(n.ops[0], ast.Eq) else ast.NotIn()
            l, r = n.left, n.comparators[0]
            if self.swap: l, r = r, l
            return ast.copy_location(ast.Compare(left=l, ops=[op], comparators=[r]), n)
        return n
class Drop(ast.NodeTransformer):
    def __init__(self, v): self.v = v
    def _is(self, e):
        return (isinstance(e, ast.Constant) and e.value == self.v) or (isinstance(e, (ast.Tuple, ast.List)) and bool(e.elts) and self._is(e.elts[0]))
    def visit_Dict(self, n):
        keep = [(k, v) for k, v in zip(n.keys, n.values) if not (k is not None and self._is(k))]
        n.keys, n.values = [k for k, _ in keep], [v for _, v in keep]
        self.generic_visit(n); return n
    def _seq(self, n):
        n.elts = [e for e in n.elts if not self._is(e)]
        self.generic_visit(n); return n
    visit_Tuple = visit_List = visit_Set = _seq
class Swap(ast.NodeTransformer):
    def visit_Constant(self, n):
        if n.value == "fips": return ast.copy_location(ast.Constant("production"), n)
        if n.value == "production": return ast.copy_location(ast.Constant("fips"), n)
        return n
def ast_mut(t):
    def f(s):
        try: return ast.unparse(ast.fix_missing_locations(t.visit(ast.parse(s))))
        except Exception: return s
    return f
EXIT = regex_mut([(r"sys\.exit\(\s*1\s*\)", "sys.exit(0)"), (r"raise SystemExit\(\s*1\s*\)", "raise SystemExit(0)"),
                  (r"\bexit\(\s*1\s*\)", "exit(0)"), (r"\breturn 1\b", "return 0"), (r"\bsys\.exit\(\s*(?!0\b)[A-Za-z_]\w*\s*\)", "sys.exit(0)")])
MUTANTS = [
 ("the certificate number is changed", lambda s: s.replace("#5247", "#5248")),
 ("the module version is changed", lambda s: s.replace("v1.0.0", "v1.0.1")),
 ("the standard variants expect 'on'", regex_mut([(r"""(["'])off\1""", r"\1on\1")])),
 ("every failing exit becomes a success", EXIT),
 ("equality becomes 'got in want'", ast_mut(EqToIn(False))),
 ("equality becomes 'want in got'", ast_mut(EqToIn(True))),
 ("the debug variant is skipped", ast_mut(Drop("debug"))),
 ("the production variant is skipped", ast_mut(Drop("production"))),
 ("the fips variant is skipped", ast_mut(Drop("fips"))),
 ("production and fips are swapped", ast_mut(Swap())),
]
for name, f in MUTANTS:
    if not exists:
        check("script mutant is caught: " + name, False, "script missing"); continue
    m = f(src)
    if m == src or m.strip() == "":
        check("script mutant is caught: " + name, False, "none of the accepted idioms occurs in the script, so the mutant cannot be applied"); continue
    mp = os.path.join(work, "mutant.py"); open(mp, "w").write(m)
    check("script mutant is caught: " + name, first_failure(mp) is not None)

print("fips-image-check: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
PY
