#!/usr/bin/env bash
# proves: REQ-FIPS-002-AC2
# The candidate images, running as the containers the release-artifact acceptance already starts, are asked what
# they report. Parts:
#   0. the AC and the release note, as parsed (a YAML '#' once cut the AC at "CMVP cert").
#   A. the two existing steps of stage-acceptance-artifacts.yml that start the containers ('exercise the images' on
#      linux/amd64, 'run every variant on arm64 under QEMU (R11)') and the results step are EXECUTED, whole, with their
#      real run: text, under a PATH of logging stub docker, curl, sleep and stat (real jq, a fixture posture script):
#      the stubs model what the steps already do (run, inspect, buildx imagetools, pull, rm, logs, PUT/GET round trips,
#      credentials, shell-lessness probes). Chosen over extracting a marked block because the ordering rules (read after
#      the wait, while the container runs, before the final rm), "no new container is started", and "a failed read
#      stops the step" are only provable on the real step; the price is that the stubs must follow edits to those steps.
#      Plus the file-level pins: the step inventory, the expression set of each step, no step before them touching
#      bin/, PATH, GITHUB_PATH or GITHUB_ENV, every action reference a digest, the k8s workflow and the predicate
#      untouched.
#   B. the comparison script, offline, over fake /statusz bodies (and a reference implementation that proves the
#      cases are satisfiable and whose mutants prove the cases are strong).
#   C. mutants of the real comparison script, every one run against ALL B cases.
#
# Contract for the implementation (step 7) this test fixes:
#   Both steps get, per variant, right after that variant's healthz wait and while its container runs (before the
#   step's docker rm -f), a read of the container's /statusz, with curl --fail (or -w '%{http_code}' checked), on
#   127.0.0.1/localhost only, with -u acc:accpw for fips, the raw body written byte-for-byte to
#   <dir>/<variant>.json (one <dir> per step run, i.e. per architecture); and an identity check: the container's image
#   (docker inspect --format {{.Image}} or {{.Config.Image}}...) is compared with the image the step started it from
#   (docker image inspect --format {{.Id}}/RepoDigests of the same reference), a mismatch, a failed or empty inspect
#   fails the step. The stub supports --format {{.Image}} {{.Id}} {{.Config.Image}} {{.State.Pid}} {{json .RepoDigests}}
#   {{index .RepoDigests 0}} {{.RepoDigests}} {{range .RepoDigests}}{{.}} {{end}} and no format (JSON).
#   After all three variants of that step were read: `python3 bin/fips-image-posture.py <dir>`, once; only when it
#   exits 0, the step appends 'linux/<arch> <variant>' (three lines) to /tmp/posture-matrix.txt; a failed read or a
#   failed comparison exits the step non-zero. No new container is started and no other docker run/pull/rm changes.
#   The results step reports REQ-FIPS-002-AC2 pass only if /tmp/posture-matrix.txt has the three linux/amd64 lines
#   (archives mode) or all six lines (candidates mode), like it derives REQ-PLAT-002 from /tmp/served-matrix.txt; and it
#   fails otherwise. If a read retries on a failing /statusz, it waits at least 20 attempts or 10 s in total.
#   Not allowed in these steps: absolute paths to curl/docker/jq/python3/sleep/stat, shell functions or aliases
#   shadowing them, PATH=, GITHUB_PATH, GITHUB_ENV, and any URL host other than 127.0.0.1 or localhost.
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
 "given": "in candidates mode, the candidate image variants of a release (production, -debug and -fips) by candidate digest, running as the containers the artifact acceptance already starts on linux/amd64 and, under emulation, on linux/arm64 (the emulated arm64 containers are UNVERIFIED until the first run shows they serve /statusz)",
 "when": "/statusz is read from each running container",
 "then": "the -fips containers report 'active (Go validated module v1.0.0, CMVP cert #5247)', the production and -debug containers report 'off', and any other report (including the forced-mode line on a standard image), a container that does not answer /statusz with a successful HTTP status, a container that is not the image pulled by that digest, or a missing variant on either architecture blocks the release",
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
maps = yaml.safe_load(rd("test-evidence/mappings.yaml"))
mm = [m for m in (maps.get("mappings") or []) if m.get("ac") == "REQ-FIPS-002-AC2"]
refs = " ".join(e.get("ref", "") for m in mm for e in m.get("evidence", []))
check("the evidence mapping names the two artifact-acceptance steps and this test, and no k8s stage",
      "stage-acceptance-artifacts.yml" in refs and "exercise the images" in refs and "R11" in refs
      and ".github/agent/tests/fips-image-check-test.sh" in refs and "k8s" not in refs and "only in candidates mode" in refs, refs)
paras = [p for p in rd("RELEASING.md").split("\n\n") if "REQ-FIPS-002-AC2" in p]
flat = " ".join(" ".join(paras).split())
check("RELEASING.md says AC2 gates only under a baseline frozen after it merged, v0.2.0 and v0.2.1 lacking it, the job failing blocks anyway",
      "frozen after it merged" in flat and "v0.2.0" in flat and "v0.2.1" in flat and "blocks the release regardless" in flat, flat)
check("RELEASING.md describes the artifact acceptance (amd64 and arm64), not the Kubernetes stage",
      "linux/amd64" in flat and "linux/arm64" in flat and "candidates mode" in flat and "Kubernetes" not in flat, flat)

# ---------------------------------------------------------------- A. the steps, executed
ART = ".github/workflows/stage-acceptance-artifacts.yml"
path = os.path.join(root, ART)
text = open(path).read()
wf = yaml.safe_load(text)
ON = wf[True] if True in wf else wf["on"]
job = wf["jobs"]["artifacts"]
steps = job["steps"]
EX, ARM, RES = ("exercise the images", "run every variant on arm64 under QEMU (R11)",
                "report the ACs this stage asserted (derived from the served matrix)")
PULL = "pull the exact candidates by digest (candidates mode)"
INV = [  # (name, action, if, id, first 16 hex of sha256(run:)): the step inventory; action digests only need to be 40-hex
 (None, "actions/checkout", None, None, None),
 (None, "actions/download-artifact", None, None, None),
 ("verify the archives against the builder's digests", None, None, None, "e95a5aa23b96dfb9"),
 ("archive set is exactly the six, and binaries execute", None, None, None, "287097a217480a69"),
 ("fips artifact embeds the validated-module selection", None, None, None, "78b93ebda4082ed4"),
 ("fips posture is truthful in all three runtime configurations", None, None, None, "777f48bd8858214d"),
 ("assemble the images from these binaries (archives mode)", None, "inputs.mode != 'candidates'", None, "32371c97f6d9772e"),
 (PULL, None, "inputs.mode == 'candidates'", None, "beb4de03675f3a89"),
 (EX, None, None, None, None),
 ("arm64 production candidate boots and serves (QEMU)", "docker/setup-qemu-action", "inputs.mode == 'candidates'", None, None),
 (ARM, None, "inputs.mode == 'candidates'", None, None),
 (RES, None, None, "results", None),
]
INV_H = {r[0]: r[4] for r in INV if r[4]}
got_inv = [(s.get("name"), (s.get("uses") or "").split("@")[0] or None, s.get("if"), s.get("id"),
            hashlib.sha256(s["run"].encode()).hexdigest()[:16] if INV_H.get(s.get("name")) else None) for s in steps]
check("the step inventory is exactly the pinned one (names, actions, conditions, ids), and the run: text of every step before 'exercise the images' is unchanged",
      got_inv == INV, [g for g, i in zip(got_inv, INV) if g != i] or got_inv)
check("no step has continue-on-error or a shell override", all(not {"continue-on-error", "shell"} & set(s) for s in steps))
check("the job has no job-level if:, continue-on-error, env, container or services", not {"if", "continue-on-error", "env", "container", "services"} & set(job), sorted(job))
check("the workflow has no defaults or workflow-level env", "defaults" not in wf and "env" not in wf, [str(k) for k in wf])
check("permissions are unchanged (workflow contents read; job contents and packages read)",
      wf["permissions"] == {"contents": "read"} and job["permissions"] == {"contents": "read", "packages": "read"}, (wf["permissions"], job["permissions"]))
check("the stage's inputs are unchanged", list(ON["workflow_call"]["inputs"]) == ["dist-artifact", "expected-checksums", "mode", "digests"])
every = re.findall(r"^\s*(?:-\s+)?uses:\s*(\S+)", text, re.M)
check("every action reference in the file is a 40-hex commit digest",
      every and all(re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", u) for u in every), every)
byname = {s.get("name"): s for s in steps}
ex, arm, res = byname.get(EX), byname.get(ARM), byname.get(RES)
idx = {s.get("name"): i for i, s in enumerate(steps)}
before = steps[:idx.get(EX, 0)]
BAD_EARLY = re.compile(r"(?<![\w.-])bin/|GITHUB_PATH|GITHUB_ENV|\bPATH=|PATH\+=|\bsudo\b|/usr/local/bin|\bhash\s+-|fips-image-posture")
check("no step before 'exercise the images' touches bin/, PATH, GITHUB_PATH or GITHUB_ENV",
      not [s.get("name") for s in before if BAD_EARLY.search(s.get("run") or "")], [s.get("name") for s in before if BAD_EARLY.search(s.get("run") or "")])
SHADOW = re.compile(r"^\s*(?:function\s+)?(?:curl|docker|jq|python3|sleep|stat|seq|bash)\s*\(\)|^\s*alias\s|\bPATH=|PATH\+=|\bsudo\b|\bhash\s+-|GITHUB_PATH|GITHUB_ENV|\bexport\s+-f\b", re.M)
ABS = re.compile(r"(?<!--entrypoint )(?<![\w.-])/(?:usr/(?:local/)?)?s?bin/(?:curl|docker|jq|python3?|sleep|stat|seq)\b")
for name, s in ((EX, ex), (ARM, arm), (RES, res)):
    t = (s or {}).get("run", "")
    hosts = {m.split("/")[0].split(":")[0] for m in re.findall(r"https?://([^\s'\"]+)", t)}
    check("%s: no shadowing of tools, no PATH or GITHUB_ENV/PATH edits" % name, s is not None and not SHADOW.search(t), SHADOW.findall(t))
    redir = [l.strip() for l in t.splitlines() if re.search(r"\bcurl\b", l) and re.search(r"(?<![\w-])(?:-[A-Za-z]*L[A-Za-z]*|--location(?:-trusted)?|-K|--config|--proto-redir\S*|--next)(?![\w-])", l)]
    check("%s: no curl follows redirects or reads a config file" % name, s is not None and not redir, redir)
    check("%s: no absolute-path tool invocation" % name, s is not None and not ABS.search(t), ABS.findall(t))
    check("%s: every URL host is 127.0.0.1 or localhost" % name, s is not None and hosts <= {"127.0.0.1", "localhost"}, hosts)
    check("%s: set -euo pipefail, no per-step env: or working-directory:" % name,
          s is not None and "set -euo pipefail" in t and not {"env", "working-directory"} & set(s))
check("the posture script is referenced only by the two container steps and (via the matrix) the results step",
      all(("fips-image-posture" in (s.get("run") or "")) == (s.get("name") in (EX, ARM)) for s in steps))
g = subprocess.run(["git", "-C", root, "rev-parse", "--verify", "-q", "origin/main"], capture_output=True, text=True)
if g.returncode == 0:
    new = subprocess.run(["git", "-C", root, "diff", "--name-status", "--diff-filter=AR", "origin/main", "--", ".github/workflows"],
                         capture_output=True, text=True).stdout.strip()
    check("no workflow file is added or renamed relative to origin/main", new == "", new)
    for f in ("stage-acceptance-k8s.yml", "stage-acceptance-predicate.yml"):
        d = subprocess.run(["git", "-C", root, "diff", "--stat", "origin/main", "--", ".github/workflows/" + f], capture_output=True, text=True).stdout.strip()
        check("%s is untouched relative to origin/main" % f, d == "", d)
else:
    print("SKIPPED (LOUD): origin/main is not resolvable here, so 'no new workflow file' and 'k8s and predicate untouched' were NOT checked; they run (and fail on a difference) wherever origin/main exists")
check("the k8s stage has nothing to do with AC2", "FIPS-002" not in rd(".github/workflows/stage-acceptance-k8s.yml") and "fips-image-posture" not in rd(".github/workflows/stage-acceptance-k8s.yml"))

OWNER, TOKEN = "fixture-owner", "TOKEN-CANARY-8f3a91"
REPO = "ghcr.io/%s/cache-candidates" % OWNER
DIG = {v: "sha256:" + hashlib.sha256(("digest-" + v).encode()).hexdigest() for v in VARIANTS}
CHILD = {v: "sha256:" + hashlib.sha256(("child-" + DIG[v]).encode()).hexdigest() for v in VARIANTS}
def body(arch, v, note=None):
    n = note if note is not None else (GOOD_FIPS if v == "fips" else "off")
    return '{"fips140_note": "%s",\t"arch":  "%s", "who": "%s"}' % (n, arch, v)   # tab, double space, no trailing newline
BODIES = {"%s:%s" % (a, v): body(a, v) for a in ("amd64", "arm64") for v in VARIANTS}
PORT = {"amd64": {"production": 19010, "debug": 19012, "fips": 19011}, "arm64": {v: 19021 + i for i, v in enumerate(VARIANTS)}}

STUBLIB = r'''
import hashlib, json, os, re, sys
D = os.environ["STUB_DIR"]
CFG = json.load(open(D + "/cfg.json"))
ST = D + "/state.json"
OWNER = CFG["owner"]; REPO = "ghcr.io/%s/cache-candidates" % OWNER
DIG = CFG["digests"]
def hx(x): return hashlib.sha256(x.encode()).hexdigest()
def child(v): return "sha256:" + hx("child-" + DIG[v])
def tag(v): return "localhost/fa-" + v
def img_id(v, arch): return "sha256:" + hx("img-%s-%s" % (arch, DIG[v]))
FOREIGN_ID = "sha256:" + hx("foreign")
FOREIGN_REPO = REPO + "@sha256:" + hx("foreign-digest")
def images():
    t = {}
    for v in DIG:
        t[tag(v)] = (v, "amd64", REPO + "@" + DIG[v])
        t[REPO + "@" + DIG[v]] = (v, "amd64", REPO + "@" + DIG[v])
        t[REPO + "@" + child(v)] = (v, "arm64", REPO + "@" + child(v))
    return t
IMG = images()
def load():
    try: return json.load(open(ST))
    except Exception: return {"c": {}, "local": [] if CFG.get("no_local_tags") else [tag(v) for v in DIG], "health": {}, "sz": {}, "n": 0, "tags": {}}
def save(s): json.dump(s, open(ST, "w"))
def log(**r): open(D + "/log.jsonl", "a").write(json.dumps(r) + "\n")
VALUED = {"--name", "-p", "--publish", "-e", "--env", "--platform", "--entrypoint", "-v", "--volume", "--mount", "--user", "-u",
          "--network", "--net", "--security-opt", "--cap-add", "--cap-drop", "--device", "--userns", "--ipc", "--uts", "--pid",
          "--env-file", "--add-host", "--workdir", "-w", "--label", "-l", "--restart", "--memory", "-m", "--cpus", "--hostname",
          "-h", "--tmpfs", "--pull"}
def render(fmt, o):
    rd = o.get("RepoDigests")
    toks = {"{{.Image}}": o.get("Image"), "{{.Id}}": o.get("Id"), "{{.ID}}": o.get("Id"), "{{.Config.Image}}": o.get("ConfigImage"),
            "{{.State.Pid}}": o.get("Pid"),
            "{{json .RepoDigests}}": None if rd is None else json.dumps(rd),
            "{{index .RepoDigests 0}}": None if rd is None else (rd[0] if rd else ""),
            "{{.RepoDigests}}": None if rd is None else "[" + " ".join(rd) + "]",
            "{{range .RepoDigests}}{{.}} {{end}}": None if rd is None else "".join(x + " " for x in rd)}
    out = fmt
    for k, v in toks.items():
        if k in out:
            if v is None: return None
            out = out.replace(k, str(v))
    return None if "{{" in out else out
def docker(a):
    s = load()
    if not a: sys.exit(1)
    sub, rest = a[0], a[1:]
    if sub in ("container", "image") and rest:
        sub, rest = rest[0], rest[1:]
    if sub == "login":
        inp = sys.stdin.read(); log(cmd="docker", sub="login", args=rest, stdin=inp); sys.exit(0)
    if sub == "buildx":
        log(cmd="docker", sub="buildx", args=rest)
        pos = [x for x in rest[3:] if not x.startswith("-")] if rest[:3] == ["imagetools", "inspect", "--raw"] else []
        m = re.fullmatch(re.escape(REPO) + r"@(sha256:[0-9a-f]{64})", pos[0]) if len(pos) == 1 else None
        v = next((v for v in DIG if m and DIG[v] == m.group(1)), None)
        if not v: sys.stderr.write("ERROR: not found\n"); sys.exit(1)
        print(json.dumps({"manifests": [{"platform": {"os": "linux", "architecture": "amd64"}, "digest": "sha256:" + hx("amd-" + DIG[v])},
                                         {"platform": {"os": "linux", "architecture": "arm64"}, "digest": child(v)},
                                         {"platform": {"os": "unknown", "architecture": "unknown"}, "digest": "sha256:" + hx("att-" + DIG[v])}]}))
        sys.exit(0)
    if sub == "pull":
        pos, i = [], 0
        while i < len(rest):
            if rest[i] == "--platform": i += 2; continue
            if not rest[i].startswith("-"): pos.append(rest[i])
            i += 1
        log(cmd="docker", sub="pull", args=rest, positional=pos)
        if len(pos) != 1 or pos[0] not in IMG or pos[0].startswith("localhost/") or IMG[pos[0]][0] in CFG.get("pull_fail", []):
            sys.stderr.write("Error: pull failed\n"); sys.exit(1)
        s["local"].append(pos[0]); save(s); sys.exit(0)
    if sub == "tag":
        log(cmd="docker", sub="tag", args=rest)
        if len(rest) != 2 or rest[0] not in s["local"] or rest[0] not in IMG or not rest[1].startswith("localhost/fa-"):
            sys.stderr.write("Error: No such image\n"); sys.exit(1)
        s["tags"][rest[1]] = rest[0]; s["local"].append(rest[1]); save(s); sys.exit(0)
    if sub == "run":
        i, image, name, port, env, fg, ent = 0, None, None, None, [], "-d" not in rest and "--detach" not in rest, None
        while i < len(rest):
            x = rest[i]
            if x == "--name" and i + 1 < len(rest): name = rest[i + 1]
            if x.startswith("--name="): name = x.split("=", 1)[1]
            if x == "--entrypoint" and i + 1 < len(rest): ent = rest[i + 1]
            if x in ("-e", "--env") and i + 1 < len(rest): env.append(rest[i + 1])
            if x in ("-p", "--publish") and i + 1 < len(rest):
                m = re.match(r"(?:[^:]+:)?(\d+):(\d+)$", rest[i + 1]); port = int(m.group(1)) if m else None
            if x in VALUED: i += 2; continue
            if not x.startswith("-"): image = x; break
            i += 1
        cmdargs = rest[i + 1:] if image else []
        info = IMG.get(image or "")
        if fg:
            log(cmd="docker", sub="run", args=rest, image=image, fg=True, started=False)
            if not info or image not in s["local"]: sys.stderr.write("Unable to find image locally\n"); sys.exit(125)
            if info[0] == "debug" and ent == "/busybox/sh":
                if cmdargs[:1] == ["-c"] and cmdargs[1:2] and cmdargs[1].startswith("echo "): print(cmdargs[1][5:])
                sys.exit(0)
            sys.stderr.write("exec: no such file\n"); sys.exit(127 if ent else 0)
        ok = bool(info) and image in s["local"]
        if ok and str(name) in s["c"]: ok = False
        if ok and port is not None and any(c["port"] == port for c in s["c"].values()): ok = False
        cid = hx(str(name))[:12]
        log(cmd="docker", sub="run", args=rest, image=image, name=name, port=port, variant=info[0] if info else None,
            arch=info[1] if info else None, started=ok, id=cid, fg=False)
        if not ok:
            sys.stderr.write("docker: run failed\n"); sys.exit(125)
        s["n"] += 1
        s["c"][str(name)] = {"id": cid, "image": image, "variant": info[0], "arch": info[1], "port": port, "data": {},
                             "auth": "FSCACHE_USERNAME=acc" in env and "FSCACHE_PASSWORD=accpw" in env, "pid": 4200 + s["n"]}
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
        cont = any(t in s["c"] or any(t == c["id"] for c in s["c"].values()) for t in targets)
        if cont and mode == "fail": sys.stderr.write("Error: No such object\n"); sys.exit(1)
        if cont and mode == "empty": sys.exit(0)
        outs = []
        for t in targets:
            c = next((c for n, c in s["c"].items() if t == n or t == c["id"]), None)
            if c:
                bad = mode == "mismatch:%s:%s" % (c["arch"], c["variant"])
                o = {"Id": c["id"], "Image": FOREIGN_ID if bad else img_id(c["variant"], c["arch"]), "ConfigImage": c["image"], "Pid": c["pid"]}
            else:
                info = IMG.get(t)
                v = next((v for v in DIG for a in ("amd64", "arm64") if t == img_id(v, a)), None)
                if info and t in s["local"]: o = {"Id": img_id(info[0], info[1]), "RepoDigests": [info[2]]}
                elif v: o = {"Id": t, "RepoDigests": [REPO + "@" + DIG[v]]}
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
    follow = False
    fail, url, out, wo, meth, user, data, i = False, None, None, None, None, None, None, 0
    LV = {"--max-time", "--connect-timeout", "--retry", "--retry-delay", "--retry-max-time", "--output", "--write-out", "--header",
          "--user", "--request", "--data", "--data-binary", "--url", "--resolve", "--interface", "--proxy"}
    while i < len(a):
        x = a[i]
        if x in ("--fail", "--fail-with-body"): fail = True
        elif x in ("--location", "--location-trusted"): follow = True
        elif x in LV or (x.startswith("--") and "=" in x and x.split("=")[0] in LV):
            if "=" in x: k, v = x.split("=", 1)
            else: k, v = x, (a[i + 1] if i + 1 < len(a) else ""); i += 1
            if k == "--output": out = v
            if k == "--write-out": wo = v
            if k == "--url": url = v
            if k == "--user": user = v
            if k == "--request": meth = v
            if k in ("--data", "--data-binary"): data = v
        elif x.startswith("--"): pass
        elif x.startswith("-") and len(x) > 1:
            j = 1
            while j < len(x):
                ch = x[j]
                if ch == "f": fail = True
                if ch == "L": follow = True
                if ch in "moHuXAdwT":
                    v = x[j + 1:] if x[j + 1:] else (a[i + 1] if i + 1 < len(a) else "")
                    if not x[j + 1:]: i += 1
                    if ch == "o": out = v
                    if ch == "w": wo = v
                    if ch == "u": user = v
                    if ch == "X": meth = v
                    if ch == "d": data = v
                    break
                j += 1
        else: url = x
        i += 1
    m = re.match(r"^(?:https?://)?(\[[^\]]+\]|[^/:]+)(?::(\d+))?(/[^?#]*)?", url or "")
    host, port, path = (m.group(1), int(m.group(2) or 80), m.group(3) or "/") if m else (None, None, None)
    rec = dict(cmd="curl", args=a, url=url, fail=fail, wo=wo, host=host, port=port, path=path, user=user, method=meth or ("PUT" if data is not None else "GET"))
    if host not in ("127.0.0.1", "localhost", "[::1]"):
        log(result="nonloopback", **rec); sys.stderr.write("curl: (7) not loopback\n"); sys.exit(7)
    cname, c = next(((n, c) for n, c in s["c"].items() if c["port"] == port), (None, None))
    if not c:
        log(result="refused", **rec); sys.stderr.write("curl: (7) refused\n"); sys.exit(7)
    v, arch = c["variant"], c["arch"]
    key = "%s:%s" % (arch, v)
    h = CFG["health"].get(v, 0)
    n = s["health"].get(c["id"], 0)
    never = h == "never"
    if path == "/healthz":
        s["health"][c["id"]] = n + 1; save(s)
        code, rb = (503, "unhealthy") if (never or n < h) else (200, "ok")
    elif never:
        code, rb = 503, "unhealthy"
    elif c["auth"] and user != "acc:accpw":
        code, rb = 401, "unauthorized"
    elif path == "/statusz":
        k = s["sz"].get(c["id"], 0); s["sz"][c["id"]] = k + 1; save(s)
        if key in CFG.get("redirect", []): code, rb = 302, ""
        elif key in CFG["http_error"]: code, rb = 500, '{"error":"internal"}'
        elif k < CFG["statusz_flaky"].get(key, 0): code, rb = 503, "warming up"
        else: code, rb = 200, CFG["bodies"][key]
    elif (meth or "") == "PUT" or data is not None:
        c["data"][path] = data or ""; s["c"][cname] = c; save(s); code, rb = 200, ""
    else:
        code, rb = (200, c["data"][path]) if path in c["data"] else (404, "not found")
    log(result="ok" if code < 400 else "http_error", code=code, variant=v, arch=arch, **rec)
    if code == 302 and follow:   # -L: the answer comes from the redirect target, here another host serving a good-looking body
        log(cmd="curl-redirect", followed=True); code, rb = 200, CFG["bodies"][key]
    if code >= 400 and fail:
        sys.stderr.write("curl: (22) The requested URL returned error: %d\n" % code); sys.exit(22)
    wtxt = (wo or "").replace("%{http_code}", str(code))
    if out and out not in ("-", "/dev/null"):
        open(out, "w").write(rb); sys.stdout.write(wtxt)
    elif out == "/dev/null": sys.stdout.write(wtxt)
    else: sys.stdout.write(rb + wtxt)
    sys.exit(0)
def main(kind):
    a = sys.argv[1:]
    if kind == "sleep": log(cmd="sleep", args=a); sys.exit(0)
    if kind == "stat":
        log(cmd="stat", args=a)
        if a[:2] == ["-c", "%u"] and len(a) == 3 and re.fullmatch(r"/proc/\d+", a[2]): print(CFG.get("uid", 65532)); sys.exit(0)
        sys.stderr.write("stub: unsupported stat\n"); sys.exit(1)
    (docker if kind == "docker" else curl)(a)
'''
POSTURE_FIXTURE = '''import json, os, sys
D = os.environ["STUB_DIR"]
d = sys.argv[1:]
files = {}
if len(d) == 1 and os.path.isdir(d[0]):
    for f in sorted(os.listdir(d[0])):
        p = os.path.join(d[0], f)
        files[f] = open(p, "rb").read().decode("latin-1") if os.path.isfile(p) else None
open(D + "/log.jsonl", "a").write(json.dumps({"cmd": "posture", "argv": d, "files": files, "script": os.path.realpath(__file__)}) + "\\n")
cfg = json.load(open(D + "/cfg.json"))
need = ("production.json", "debug.json", "fips.json")
bad = not all(k in files for k in need) or any(files[k] is None or "WRONG" in files[k] or files[k] not in set(cfg["bodies"].values()) for k in need if k in files)
sys.exit(1 if bad else cfg["posture_exit"])
'''
TOOLS = ["bash", "sh", "jq", "python3", "mktemp", "cat", "mkdir", "rm", "seq", "tr", "cut", "head", "tail", "grep", "sed", "awk",
         "printf", "date", "true", "false", "test", "[", "dirname", "basename", "tee", "wc", "sort", "cmp", "diff", "env",
         "readlink", "cp", "mv", "ls", "chmod", "expr", "xargs", "id", "uname", "touch", "echo"]
ALLOWED = {EX: set(), ARM: {"github.repository_owner", "inputs.digests"}, RES: {"inputs.mode"},
           PULL: {"github.token", "github.actor", "github.repository_owner", "inputs.digests"}}

def run_step(step, cfg, digests=None, mode="candidates", mats=None, tmp_dir=None):
    """Execute a step's run: whole. mats: {file: text} pre-placed in the redirected /tmp."""
    d = tempfile.mkdtemp(dir=work)
    stub, tools, ws, tmp = d + "/stub", d + "/tools", d + "/ws", (tmp_dir or d + "/tmp")
    for p in (stub, tools, ws + "/bin", tmp, d + "/home"): os.makedirs(p, exist_ok=True)
    open(stub + "/stublib.py", "w").write(STUBLIB)
    json.dump(cfg, open(stub + "/cfg.json", "w"))
    for k in ("docker", "curl", "sleep", "stat"):
        open(stub + "/" + k, "w").write("#!%s\nimport sys; sys.path.insert(0, %r); import stublib; stublib.main(%r)\n" % (sys.executable, stub, k))
        os.chmod(stub + "/" + k, 0o755)
    for t in TOOLS:
        w = shutil.which(t)
        if w and not os.path.exists(tools + "/" + t): os.symlink(w, tools + "/" + t)
    open(ws + "/bin/fips-image-posture.py", "w").write(POSTURE_FIXTURE)
    for f, c in (mats or {}).items(): open(tmp + "/" + f, "w").write(c)
    env = {"PATH": stub + ":" + tools, "HOME": d + "/home", "STUB_DIR": stub, "GITHUB_WORKSPACE": ws, "RUNNER_TEMP": tmp, "TMPDIR": tmp,
           "GITHUB_OUTPUT": tmp + "/gh-output", "GITHUB_TOKEN": TOKEN + "-env", "LANG": "C"}
    run = step["run"]
    exprs = set(m for m in re.findall(r"\$\{\{\s*([^}]*?)\s*\}\}", run))
    problems = [] if exprs == ALLOWED[step["name"]] else ["expressions %s, expected %s" % (sorted(exprs), sorted(ALLOWED[step["name"]]))]
    subst = {"github.repository_owner": OWNER, "github.token": TOKEN, "github.actor": "actor-fixture", "inputs.mode": mode,
             "inputs.digests": json.dumps(digests if digests is not None else DIG, separators=(",", ":"))}
    for k, v in subst.items(): run = re.sub(r"\$\{\{\s*" + re.escape(k) + r"\s*\}\}", lambda _m, v=v: v, run)
    run = run.replace("/tmp/", tmp + "/")
    open(d + "/step.sh", "w").write(run)
    h0 = hashlib.sha256(open(ws + "/bin/fips-image-posture.py", "rb").read()).hexdigest()
    try:
        p = subprocess.run([shutil.which("bash"), "-e", d + "/step.sh"], cwd=ws, env=env, capture_output=True, text=True, timeout=30)
        rc, err = p.returncode, p.stderr
    except subprocess.TimeoutExpired:
        rc, err = None, "timeout"
    logf = stub + "/log.jsonl"
    log = [json.loads(l) for l in open(logf)] if os.path.exists(logf) else []
    mf = lambda f: open(tmp + "/" + f).read() if os.path.exists(tmp + "/" + f) else None
    intact = (hashlib.sha256(open(ws + "/bin/fips-image-posture.py", "rb").read()).hexdigest() == h0 and os.listdir(ws + "/bin") == ["fips-image-posture.py"])
    state = json.load(open(stub + "/state.json")) if os.path.exists(stub + "/state.json") else {}
    return dict(state=state, rc=rc, err=err, log=log, problems=problems, tmp=tmp, matrix=mf("posture-matrix.txt"), output=mf("gh-output"), intact=intact)

def arg_lists(log, sub, **kw):
    return [r["args"] for r in log if r.get("cmd") == "docker" and r.get("sub") == sub and all(r.get(k) == v for k, v in kw.items())]
def expected_runs(arch):
    if arch == "amd64":
        return [["--pull=never", "-d", "--name", "fa-prod", "-p", "127.0.0.1:19010:8080", "localhost/fa-production"],
                ["--pull=never", "--rm", "--entrypoint", "/busybox/sh", "localhost/fa-production", "-c", "true"],
                ["--pull=never", "--rm", "--entrypoint", "/busybox/sh", "localhost/fa-fips", "-c", "true"],
                ["--pull=never", "--rm", "--entrypoint", "/busybox/sh", "localhost/fa-debug", "-c", "echo shell-ok"],
                ["--pull=never", "--rm", "--entrypoint", "/bin/sh", "localhost/fa-debug", "-c", "true"],
                ["--pull=never", "-d", "--name", "fa-debugrun", "-p", "127.0.0.1:19012:8080", "localhost/fa-debug"],
                ["--pull=never", "-d", "--name", "fa-fipsrun", "-p", "127.0.0.1:19011:8080", "-e", "FSCACHE_USERNAME=acc", "-e", "FSCACHE_PASSWORD=accpw", "localhost/fa-fips"]]
    return [["-d", "--name", "fa-arm64-" + v, "--platform", "linux/arm64"] + (["-e", "FSCACHE_USERNAME=acc", "-e", "FSCACHE_PASSWORD=accpw"] if v == "fips" else [])
            + ["-p", "127.0.0.1:%d:8080" % PORT["arm64"][v], "%s@%s" % (REPO, CHILD[v])] for v in VARIANTS]

def judge_good(arch, r):
    log = r["log"]; L = "good run (%s)" % arch
    check("%s: the step exits 0" % L, r["rc"] == 0, (r["rc"], r["err"].strip()[-300:]))
    check("%s: the step uses exactly the ${{ }} expressions it had" % L, not r["problems"], r["problems"])
    check("%s: the posture script and its directory are untouched by the step" % L, r["intact"])
    dock = [x for x in log if x.get("cmd") == "docker"]
    check("%s: no docker subcommand beyond run, inspect, rm, logs, ps, pull, buildx, login" % L, not [x for x in dock if x.get("unexpected")], [x for x in dock if x.get("unexpected")])
    check("%s: every curl is on loopback and reaches a running container" % L, not [x for x in log if x.get("cmd") == "curl" and x["result"] in ("refused", "nonloopback")],
          [x["args"] for x in log if x.get("result") in ("refused", "nonloopback")])
    check("%s: no new container is started and none is changed: the docker run commands are exactly the existing ones, in order" % L,
          arg_lists(log, "run") == expected_runs(arch), arg_lists(log, "run"))
    if arch == "arm64":
        check("%s: the pulls and the index lookups are exactly the existing ones" % L,
              arg_lists(log, "pull") == [["-q", "%s@%s" % (REPO, CHILD[v])] for v in VARIANTS]
              and arg_lists(log, "buildx") == [["imagetools", "inspect", "--raw", "%s@%s" % (REPO, DIG[v])] for v in VARIANTS],
              (arg_lists(log, "pull"), arg_lists(log, "buildx")))
        check("%s: each container is removed as before" % L, arg_lists(log, "rm") == [["-f", "fa-arm64-" + v] for v in VARIANTS], arg_lists(log, "rm"))
    else:
        check("%s: the containers are removed as before" % L, arg_lists(log, "rm") == [["-f", "fa-prod", "fa-debugrun", "fa-fipsrun"]], arg_lists(log, "rm"))
    runs = [x for x in dock if x["sub"] == "run" and not x["fg"]]
    seen = {t for x in dock if x["sub"] == "inspect" for t in x["targets"]}
    check("%s: each started container is inspected (its image compared with the image it was started from)" % L,
          len(runs) == 3 and all(x["name"] in seen or x["id"] in seen for x in runs) and any(t not in {x["name"] for x in runs} | {x["id"] for x in runs} for t in seen),
          [x["targets"] for x in dock if x["sub"] == "inspect"])
    sz = [(k, x) for k, x in enumerate(log) if x.get("cmd") == "curl" and x.get("path") == "/statusz"]
    check("%s: every /statusz read fails on an HTTP error (--fail, or the status code written out)" % L,
          sz and all(x["fail"] or (x["wo"] and "http_code" in x["wo"]) for _, x in sz), [x["args"] for _, x in sz if not x["fail"]])
    check("%s: the fips /statusz read carries -u acc:accpw" % L, any(x["variant"] == "fips" and x["user"] == "acc:accpw" and x["result"] == "ok" for _, x in sz))
    ok = True
    for v in VARIANTS:
        c = next((x for x in runs if x["variant"] == v), None)
        if not c: ok = False; continue
        hz = [k for k, x in enumerate(log) if x.get("cmd") == "curl" and x.get("variant") == v and x["path"] == "/healthz" and x["result"] == "ok"]
        rd_ = [k for k, x in sz if x.get("variant") == v and x["result"] == "ok"]
        rm = [k for k, x in enumerate(log) if x.get("sub") == "rm" and (c["name"] in x["names"] or c["id"] in x["names"])]
        if not (hz and rd_ and rm and min(hz) < min(rd_) < min(rm)): ok = False
    check("%s: each variant's /statusz is read after its healthz answered and while its container is running (before its docker rm)" % L, ok)
    post = [k for k, x in enumerate(log) if x.get("cmd") == "posture"]
    check("%s: the comparison script is invoked exactly once, as bin/fips-image-posture.py <dir>" % L,
          len(post) == 1 and log[post[0]]["script"].endswith("/ws/bin/fips-image-posture.py") and len(log[post[0]]["argv"]) == 1, [log[k] for k in post])
    allread = bool(post) and all(any(k < post[0] and x.get("variant") == v and x["result"] == "ok" for k, x in sz) for v in VARIANTS)
    check("%s: the comparison script runs after all three variants were read" % L, allread)
    files = log[post[0]]["files"] if post else {}
    check("%s: the script is handed each variant's /statusz body as <variant>.json, byte for byte" % L,
          all(files.get(v + ".json") == BODIES["%s:%s" % (arch, v)] for v in VARIANTS), files)
    check("%s: the posture matrix has exactly the three lines of this architecture" % L,
          (r["matrix"] or "").split("\n")[:-1] == ["linux/%s %s" % (arch, v) for v in VARIANTS] or
          sorted((r["matrix"] or "").split("\n")[:-1]) == sorted("linux/%s %s" % (arch, v) for v in VARIANTS), r["matrix"])

def sleep_total(log, after):
    t = 0.0
    for x in log[after:]:
        if x.get("cmd") == "sleep":
            try: t += float(x["args"][0])
            except Exception: pass
    return t

def judge_bad(label, arch, step, cfg, digests=None, flaky=None):
    r = run_step(step, cfg, digests)
    log = r["log"]
    if flaky is None:
        check("%s: the step ends (no hang) and exits non-zero" % label, r["rc"] is not None and r["rc"] != 0, (r["rc"], r["err"][-150:]))
        check("%s: nothing is claimed in the posture matrix" % label, not (r["matrix"] or "").strip(), r["matrix"])
    else:   # the retry budget: a read that retries a failing /statusz must keep trying for >= 20 attempts or >= 10 s
        sz = [k for k, x in enumerate(log) if x.get("cmd") == "curl" and x.get("path") == "/statusz" and x.get("variant") == "fips"]
        attempts = len(sz)
        ok = r["rc"] == 0 or attempts <= 1 or attempts >= 20 or sleep_total(log, sz[0]) >= 10
        check("%s: a retrying read does not give up early (attempts %d, sleeps %.1fs)" % (label, attempts, sleep_total(log, sz[0]) if sz else 0), r["rc"] is not None and ok, (r["rc"], attempts))
        if r["rc"] == 0: judge_good(arch, r)

def base_cfg(**kw):
    c = dict(owner=OWNER, digests=DIG, bodies=BODIES, health={"production": 2, "debug": 0, "fips": 3}, http_error=[], statusz_flaky={},
             inspect="ok", posture_exit=0)
    c.update(kw); return c
for arch, step in (("amd64", ex), ("arm64", arm)):
    if step is None:
        check("%s: the step exists to be run" % arch, False, "step missing"); continue
    judge_good(arch, run_step(step, base_cfg()))
    for v in VARIANTS:
        k = "%s:%s" % (arch, v)
        judge_bad("%s %s answers /statusz with HTTP 500" % (arch, v), arch, step, base_cfg(http_error=[k]))
        wrong = dict(BODIES); wrong[k] = body(arch, v, "WRONG-" + v)
        r = run_step(step, base_cfg(bodies=wrong))
        post = [x for x in r["log"] if x.get("cmd") == "posture"]
        check("%s %s reports a wrong posture: the comparator receives exactly the curl bytes, and the step exits non-zero" % (arch, v),
              r["rc"] not in (0, None) and len(post) == 1 and post[0]["files"].get(v + ".json") == wrong[k] and not (r["matrix"] or "").strip(), (r["rc"], post and post[0]["files"]))
        judge_bad("%s %s container is not the image it was started from" % (arch, v), arch, step, base_cfg(inspect="mismatch:%s:%s" % (arch, v)))
        judge_bad("%s %s never becomes healthy" % (arch, v), arch, step, base_cfg(health={"production": 0, "debug": 0, "fips": 0, v: "never"}))
    judge_bad("%s docker inspect of the container fails" % arch, arch, step, base_cfg(inspect="fail"))
    judge_bad("%s docker inspect of the container answers nothing" % arch, arch, step, base_cfg(inspect="empty"))
    judge_bad("%s the comparison script exits 1" % arch, arch, step, base_cfg(posture_exit=1))
    judge_bad("%s fips /statusz fails 18 times, then answers" % arch, arch, step, base_cfg(statusz_flaky={"%s:fips" % arch: 18}), flaky=True)
if arm is not None:
    judge_bad("arm64 the fips digest is null", "arm64", arm, base_cfg(), digests={"production": DIG["production"], "debug": DIG["debug"], "fips": None})
    judge_bad("arm64 the fips digest key is missing", "arm64", arm, base_cfg(), digests={"production": DIG["production"], "debug": DIG["debug"]})
    judge_bad("arm64 the debug digest is null", "arm64", arm, base_cfg(), digests={"production": DIG["production"], "debug": None, "fips": DIG["fips"]})

# the pull step: by digest, nothing else
pull = byname.get(PULL)
def pull_failures(step):
    out = []
    r = run_step(step, base_cfg(no_local_tags=True))
    log = r["log"]
    if r["rc"] != 0: out.append("the good run exits %s (%s)" % (r["rc"], r["err"].strip()[-120:]))
    if r["problems"]: out.append(r["problems"])
    lg = [x for x in log if x.get("cmd") == "docker" and x["sub"] == "login"]
    if len(lg) != 1 or lg[0]["args"] != ["ghcr.io", "-u", "actor-fixture", "--password-stdin"] or lg[0]["stdin"].strip() != TOKEN:
        out.append("login %s" % [x["args"] for x in lg])
    refs = ["%s@%s" % (REPO, DIG[v]) for v in VARIANTS]
    if arg_lists(log, "pull") != [["-q", x] for x in refs]: out.append("pulls %s" % arg_lists(log, "pull"))
    if arg_lists(log, "tag") != [[x, "localhost/fa-" + v] for x, v in zip(refs, VARIANTS)]: out.append("tags %s" % arg_lists(log, "tag"))
    if r["state"].get("tags") != {"localhost/fa-" + v: x for x, v in zip(refs, VARIANTS)}: out.append("recorded tags %s" % r["state"].get("tags"))
    if [x for x in log if x.get("unexpected")]: out.append("unexpected docker subcommand")
    for label, dg in (("null", {"production": DIG["production"], "debug": DIG["debug"], "fips": None}),
                      ("missing", {"debug": DIG["debug"], "fips": DIG["fips"]}), ("empty", {"production": DIG["production"], "debug": "", "fips": DIG["fips"]})):
        r2 = run_step(step, base_cfg(no_local_tags=True), digests=dg)
        if r2["rc"] in (0, None): out.append("a %s digest is accepted" % label)
        if [x for x in arg_lists(r2["log"], "pull") if x[-1] not in refs]: out.append("a pull was attempted for a %s digest" % label)
    r3 = run_step(step, base_cfg(no_local_tags=True, pull_fail=["fips"]))
    if r3["rc"] in (0, None): out.append("a failed pull is accepted")
    return out
if pull is None: check("the pull step exists to be run", False)
else:
    fl = pull_failures(pull)
    check("the pull step, executed: login to ghcr.io on stdin, the three pulls exactly -q <owner>/cache-candidates@<that variant's digest>, the three tags exactly <that ref> localhost/fa-<variant>, null/missing/empty digests and a failed pull fail",
          not fl, fl)
    PM = [("the pull uses a tag, not the digest", lambda t: t.replace('docker pull -q "${repo}@${d}"', 'docker pull -q "${repo}:latest"')),
          ("the tag is made from a tag, not the digest", lambda t: t.replace('docker tag "${repo}@${d}"', 'docker tag "${repo}:latest"')),
          ("another registry is used", lambda t: re.sub(r'repo="[^"]*"', 'repo="docker.io/evil/cache"', t)),
          ("the null-digest guard is deleted", lambda t: "\n".join(l for l in t.split("\n") if "no digest for" not in l)),
          ("the tag is overwritten", lambda t: t.replace('"localhost/fa-${v}"', '"localhost/fa-production"')),
          ("every variant takes the production digest", lambda t: t.replace("'.[$v]'", "'.production'")),
          ("the login goes to another registry", lambda t: t.replace("docker login ghcr.io", "docker login docker.io"))]
    for name, f in PM:
        m = dict(pull); m["run"] = f(pull["run"])
        check("pull-step mutant is caught: " + name, m["run"] != pull["run"] and bool(pull_failures(m)), "not applied" if m["run"] == pull["run"] else "")
for arch, step in (("amd64", ex), ("arm64", arm)):
    for v in VARIANTS:
        if step is not None:
            judge_bad("%s %s /statusz answers a 302 (to another host)" % (arch, v), arch, step, base_cfg(redirect=["%s:%s" % (arch, v)]))
if ex is not None and arm is not None:
    AMD = {BODIES["amd64:" + v] for v in VARIANTS}; ARMB = {BODIES["arm64:" + v] for v in VARIANTS}
    r1 = run_step(ex, base_cfg()); r2 = run_step(arm, base_cfg(), tmp_dir=r1["tmp"])
    post = [x for x in r2["log"] if x.get("cmd") == "posture"]
    check("shared /tmp, amd64 then arm64: the arm64 comparison sees only arm64 bodies",
          r2["rc"] == 0 and len(post) == 1 and all(post[0]["files"].get(v + ".json") == BODIES["arm64:" + v] for v in VARIANTS), (r2["rc"], post and post[0]["files"]))
    r1 = run_step(ex, base_cfg()); r2 = run_step(arm, base_cfg(http_error=["arm64:fips"]), tmp_dir=r1["tmp"])
    check("shared /tmp, amd64 then a failing arm64 read: the step fails and no amd64 file reaches the arm64 comparison",
          r2["rc"] not in (0, None) and not [x for x in r2["log"] if x.get("cmd") == "posture" and AMD & set(x["files"].values())], r2["rc"])
    r1 = run_step(arm, base_cfg()); r2 = run_step(ex, base_cfg(http_error=["amd64:fips"]), tmp_dir=r1["tmp"])
    check("shared /tmp, arm64 then a failing amd64 read: the step fails and no arm64 file reaches the amd64 comparison",
          r2["rc"] not in (0, None) and not [x for x in r2["log"] if x.get("cmd") == "posture" and ARMB & set(x["files"].values())], r2["rc"])

# the results step: AC2 is derived from the posture matrix, like REQ-PLAT-002 from the served matrix
SERVED6 = "".join("linux/%s %s\n" % (a, v) for a in ("amd64", "arm64") for v in VARIANTS)
POST6, POST3 = SERVED6, "".join("linux/amd64 %s\n" % v for v in VARIANTS)
def results_case(label, mode, served, posture, want):
    if res is None: check(label + ": the results step exists", False); return
    mats = {"served-matrix.txt": served}
    if posture is not None: mats["posture-matrix.txt"] = posture
    r = run_step(res, {"owner": OWNER, "digests": DIG, "bodies": {}, "health": {}, "http_error": [], "statusz_flaky": {}, "inspect": "ok", "posture_exit": 0}, mode=mode, mats=mats)
    if want == "fail":
        check(label + ": the stage fails", r["rc"] not in (0, None) and not (r["output"] or "").strip(), (r["rc"], r["err"][-150:], r["output"]))
        return
    try: out = json.loads((r["output"] or "").strip().split("results=", 1)[1])
    except Exception as e: out = repr(e)
    pairs = {(x["ac"], x["result"]) for x in out} if isinstance(out, list) else set()
    base = r["rc"] == 0 and ("REQ-FIPS-002-AC1", "pass") in pairs and ("REQ-PLAT-002-AC1", "pass") in pairs
    if want == "pass":
        check(label + ": the stage passes and reports REQ-FIPS-002-AC2 pass beside the others", base and ("REQ-FIPS-002-AC2", "pass") in pairs, (r["rc"], r["err"][-150:], out))
    else:
        check(label + ": the stage passes but does NOT report REQ-FIPS-002-AC2 as pass", base and ("REQ-FIPS-002-AC2", "pass") not in pairs, (r["rc"], r["err"][-150:], out))
SERVED6 = "".join("linux/%s %s\n" % (a, v) for a in ("amd64", "arm64") for v in VARIANTS)
POST6, POST3 = SERVED6, "".join("linux/amd64 %s\n" % v for v in VARIANTS)
results_case("candidates mode, all six posture lines", "candidates", SERVED6, POST6, "pass")
results_case("archives mode (locally assembled images, no arm64), the three amd64 posture lines", "archives", POST3, POST3, "nopass")
results_case("archives mode, no posture matrix", "archives", POST3, None, "nopass")
results_case("archives mode, even a full six-line posture matrix", "archives", POST3, POST6, "nopass")
for gone in ("linux/arm64 fips", "linux/arm64 production", "linux/amd64 debug"):
    results_case("candidates mode, posture line '%s' missing" % gone, "candidates", SERVED6, POST6.replace(gone + "\n", ""), "fail")
results_case("candidates mode, only the amd64 posture lines", "candidates", SERVED6, POST3, "fail")
results_case("candidates mode, no posture matrix at all", "candidates", SERVED6, None, "fail")
results_case("candidates mode, 'linux/amd64 fips' replaced by 'linux/amd64 fips-extra' (whole-line match)", "candidates", SERVED6, POST6.replace("linux/amd64 fips\n", "linux/amd64 fips-extra\n"), "fail")
results_case("candidates mode, 'linux/arm64 debug' with a trailing space", "candidates", SERVED6, POST6.replace("linux/arm64 debug\n", "linux/arm64 debug \n"), "fail")
results_case("candidates mode, 'linux/arm64 production' as a longer line", "candidates", SERVED6, POST6.replace("linux/arm64 production\n", "xlinux/arm64 production\n"), "fail")

# ---------------------------------------------------------------- B. the comparison script
script = os.path.join(root, "bin/fips-image-posture.py")
def jbody(note): return json.dumps({"fips140_note": note, "version": "x"})
GOOD = {"production": jbody("off"), "debug": jbody("off"), "fips": jbody(GOOD_FIPS)}
def mut(**kw): b = dict(GOOD); b.update(kw); return b
CASES = []
def case(name, bodies, ok, who=(), args=None): CASES.append((name, bodies, ok, tuple(who), args))
case("the exact good strings", GOOD, True)
case("extra fields, whitespace and nesting around the JSON", mut(fips=' {"a":{"fips140_note":"x"}, "fips140_note": "%s"}\n' % GOOD_FIPS, production='{"fips140_note":"off","x":[1]}\n'), True)
case("extra files in the directory are ignored", dict(GOOD, **{"fips.json.bak": jbody("off"), "other.json": "garbage", "notes.txt": "x", "arm64-fips.json": "garbage"}), True)
for n, b in [("-fips reports off", jbody("off")), ("-fips reports the wrong certificate", jbody(GOOD_FIPS.replace("5247", "5248"))),
             ("-fips reports the wrong module version", jbody(GOOD_FIPS.replace("v1.0.0", "v1.0.1"))),
             ("-fips reports the forced-mode line", jbody(FORCED)), ("-fips string with a trailing space", jbody(GOOD_FIPS + " ")),
             ("-fips string in another case", jbody(GOOD_FIPS.upper())), ("-fips string with a suffix", jbody(GOOD_FIPS + "; extra")),
             ("-fips string with a prefix", jbody("x " + GOOD_FIPS))]:
    case(n, mut(fips=b), False, ["fips"])
for v in ("production", "debug"):
    case("%s reports the fips string" % v, mut(**{v: jbody(GOOD_FIPS)}), False, [v])
    case("%s reports the forced-mode line" % v, mut(**{v: jbody(FORCED)}), False, [v])
    for s in ("off ", " off", "Off", "OFF", "off (x)", "of", "o", ""):
        case("%s reports %r" % (v, s), mut(**{v: jbody(s)}), False, [v])
for v in VARIANTS:
    want = GOOD_FIPS if v == "fips" else "off"
    case("the %s variant is missing" % v, mut(**{v: None}), False, [v])
    for n, b in [("empty", ""), ("not JSON", "<html>not json</html>"), ("truncated JSON", '{"fips140_note": "off"'), ("a JSON array", '["off"]'),
                 ("a JSON string", '"off"'), ("JSON true", "true"), ("JSON false", "false"), ("JSON null", "null"), ("a JSON number", "0"),
                 ("without the field", '{"version":"x"}'), ("with a null field", '{"fips140_note": null}'), ("with a numeric field", '{"fips140_note": 0}'),
                 ("with a list field", '{"fips140_note": ["off"]}'), ("with trailing text", jbody(want) + " x"), ("with two documents", jbody(want) + jbody(want)),
                 ("with a UTF-8 BOM", b"\xef\xbb\xbf" + jbody(want).encode()), ("with non-UTF-8 bytes", b'{"fips140_note":"' + want.encode() + b'","x":"\xff"}'),
                 ("with only whitespace", " \n"), ("with a NUL byte", jbody(want).encode() + b"\x00")]:
        case("the %s body is %s" % (v, n), mut(**{v: b}), False, [v])
    case("the %s body has a duplicate key (same value)" % v, mut(**{v: '{"fips140_note":"%s","fips140_note":"%s"}' % (want, want)}), False, [v])
    case("the %s body has a duplicate key (wrong first)" % v, mut(**{v: '{"fips140_note":"x","fips140_note":"%s"}' % want}), False, [v])
    case("the %s body has a duplicate key (wrong last)" % v, mut(**{v: '{"fips140_note":"%s","fips140_note":"x"}' % want}), False, [v])
    case("the %s file is a symlink to a good body" % v, mut(**{v: ("symlink", jbody(want))}), False, [v])
    case("the %s file is a directory" % v, mut(**{v: ("dir",)}), False, [v])
for v in ("production", "fips"):
    case("the %s note holds a newline and ::error::" % v, mut(**{v: json.dumps({"fips140_note": "x\n::error::pwned"})}), False, [v])
    case("the %s note holds a carriage return and ::stop-commands::" % v, mut(**{v: json.dumps({"fips140_note": "x\r::stop-commands::tok"})}), False, [v])
    case("the %s body has a duplicate key holding a newline and ::error::" % v, mut(**{v: '{"a\\n::error::x":1,"a\\n::error::x":2}'}), False, [v])
    case("the %s body is invalid JSON whose text holds ::error::" % v, mut(**{v: '::error::x\n{'}), False, [v])
case("a note in a nested object only", mut(fips='{"x":{"fips140_note":"%s"}}' % GOOD_FIPS), False, ["fips"])
case("all three variants are missing", {k: None for k in GOOD}, False)
case("two variants are bad: both are named", mut(production=jbody(GOOD_FIPS), debug=jbody(FORCED)), False, ["production", "debug"])
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
    lines = (p.stdout + "\n" + p.stderr).replace("\r", "\n").split("\n")
    if any(l.lstrip().startswith("::") for l in lines): return False      # a workflow command smuggled through an echoed value
    if who and not p.stderr.startswith("variant "): return False
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
        return "unreadable: %r" % (e,)
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
 ("a JSON error is swallowed as a pass", 'return "unreadable: %r" % (e,)', "return None"),
 ("the exception text is printed raw", 'return "unreadable: %r" % (e,)', 'return "unreadable: %s" % e'),
 ("the note is printed raw", 'return "reports %r, want %r" % (got, want)', 'return "reports %s, want %r" % (got, want)'),
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

art = rd(ART)
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
 ("echoed input is printed raw", regex_mut([(r"%r", "%s"), (r"!r\b", "!s"), (r"\brepr\(", "str("), (r"json\.dumps\(", "str(")])),
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
