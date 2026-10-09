#!/usr/bin/env bash
# proves: REQ-FIPS-002-AC2
# The candidate images, running as the containers the release-artifact acceptance already starts, are asked what
# they report. The question is asked, and the answer judged, by ONE program, bin/fips-image-posture.py; the workflow
# steps only call it. Parts:
#   0. the AC and the release note, as parsed (a YAML '#' once cut the AC at "CMVP cert").
#   A. the workflow. The two existing steps that start the containers ('exercise the images' on linux/amd64,
#      'run every variant on arm64 under QEMU (R11)'), the pull step and the results step are EXECUTED, whole, with their
#      real run: text, under a PATH of logging stub docker, curl, sleep, stat and python3 (real jq). The stub python3
#      accepts exactly `python3 bin/fips-image-posture.py check ...` (it logs the arguments, models the container behind
#      the port, appends the matrix line on success, exits like the real program) and refuses every other use. Judged:
#      the exact call per variant per architecture, when it happens, retries, the exit code, the pull by digest, the
#      arm64 child chosen by platform whatever the manifest order, no fallback to another image, the results step.
#      Plus the file-level pins: the step inventory and the run: text of every earlier step, expressions, no step before
#      touching bin/, PATH or GITHUB_ENV, every action reference a digest, the k8s workflow and the predicate untouched.
#   B. the program itself against a REAL local HTTP server (and a second server that must never be contacted).
#   C. mutants: of a reference implementation (proves the cases are strong) and of the real program (idiom-based).
#
# Contract for the implementation (step 7) this test fixes:
#   program  bin/fips-image-posture.py  (needs a bin/ allowlist pattern in bin/check-file-allowlist.sh and its test)
#     python3 bin/fips-image-posture.py check --arch <amd64|arm64> --variant <production|debug|fips> --port <n>
#             [--user <u> --password <p>] --matrix <file>
#     GET http://127.0.0.1:<port>/statusz, exactly once, no redirect following (a 3xx is a failure), the status must be
#     exactly 200 (written as a comparison with the literal 200), an overall deadline of at most 3 s (set with a timeout=
#     keyword or settimeout(), covering the whole body read, so a slow-loris body fails), a body cap of 64 KiB (an integer
#     constant >= 4096 in the source), strict JSON (UTF-8, no BOM, one document, an object, no duplicate keys),
#     .fips140_note compared for equality with  active (Go validated module v1.0.0, CMVP cert #5247)  (fips) or  off
#     (production, debug) - both strings as literals identical to stage-acceptance-artifacts.yml's. Basic auth only from
#     --user/--password. On success: append exactly one line 'linux/<arch> <variant>' to the matrix file and exit 0. On
#     anything else: exit non-zero, write NOTHING to the matrix, and print to stderr a first line 'variant <name>: ...'
#     built only from fixed text and repr()-quoted data (never a raw line from the response, never a line starting
#     with '::'). Wrong or missing arguments, an unknown flag, a duplicate flag, user without password: exit non-zero
#     without any request. Strict JSON also means NaN, Infinity and -Infinity are rejected (parse_constant=). A body that is
#     not complete (fewer bytes than its Content-Length, a truncated chunk stream) is a failure. The program ignores
#     proxy settings of the environment, connects to the literal 127.0.0.1 only (never 'localhost' or ::1), never
#     lets an uncaught exception reach the output (every failure is 'variant <name>: ...', exit 1, no traceback), and
#     is called as `python3 -I bin/fips-image-posture.py check ...` (isolated mode). The overall deadline covers every
#     phase: connecting, the status line, the headers, chunk framing and the body (signal.alarm() or a remaining-time
#     socket timeout before every read).
#   job      The artifacts job has timeout-minutes (at most 120). No step issues docker tag, pull (amd64 step), rmi, load,
#     import, build, commit or login; every `docker run` of the two container steps must start; a retry around the check
#     is bounded (at most 120 attempts or 120 s of sleep).
#   escapes  No `command`, `env`, `exec`, `eval`, `sh -c`, `xargs`, `builtin`, `enable`, `source`, backslash-escaped tool name or
#     process wrapper in the container and results steps (they would run a tool around the PATH of the stubs).
#   deadline Every deadline/timeout constant in the program is at most 3 s; the slow cases must fail within 4.5 s, including a
#     response whose three phases (status line, headers, body) take 1.2 s each: the budget is for the whole call.
#   imports  The program imports only the standard modules sys, json, http, urllib, socket, argparse, signal, time, base64, re,
#     stat, errno and os.path; no subprocess, pathlib, shutil, ctypes or importlib, no os.environ/os.system/..., no eval/exec/
#     __import__, no path under ~/.docker.
#   matrix   The amd64 step initialises /tmp/posture-matrix.txt itself (`: > /tmp/posture-matrix.txt`); the arm64 step never
#     truncates it. The program has no string constant naming a path (the matrix comes only from --matrix); an integration
#     case runs the REAL program with the argument form of the steps against real servers on their ports.
#   caller   release.yml calls stage-acceptance-artifacts.yml once, with mode: candidates and the image stage's digests, and the
#     acceptance predicate needs that job and takes its results as artifacts-results.
#   (not checked) The pulled image's RepoDigests are not compared with the candidate digest inside the container steps: the
#     pull step, pinned by hash and executed above, is what ties the local tag to the digest.
#   caveat   The image-identity comparison is UNVERIFIED where Docker uses the containerd image store (the container's
#     .Image and the image's .Id can differ), as arm64 under emulation is UNVERIFIED until the first run.
#   steps    In both container steps, per variant, after that variant's healthz wait and while its container runs (before
#     the step's docker rm): `python3 -I bin/fips-image-posture.py check --arch A --variant V --port P --matrix /tmp/posture-
#     matrix.txt` (+ `--user acc --password accpw` for fips), P being the container's published port, retried around the
#     CALL for at least 20 attempts or 10 s; its failure fails the step. The step must not use curl for /statusz, must not
#     capture, tee, print or echo any response, and uses python3 for nothing else. The container's image is compared with
#     the image the step started it from (docker inspect --format {{.Image}} / {{.Id}} / {{.Config.Image}} /
#     {{.State.Pid}} / {{json .RepoDigests}} / {{index .RepoDigests 0}} / {{.RepoDigests}} /
#     {{range .RepoDigests}}{{.}} {{end}}, or no format); a mismatch or a failed or empty inspect fails the step. The arm64
#     child is chosen by platform.os/platform.architecture from the index, in any order; a failed child pull fails the step
#     with no fallback pull or run of another image. No new container is started and no other docker run/pull/rm changes.
#     The results step reports REQ-FIPS-002-AC2 pass only in candidates mode and only if /tmp/posture-matrix.txt contains
#     each of the six lines 'linux/<arch> <variant>' as a whole line (archives mode never earns it); it fails otherwise.
#     Not allowed in the container and results steps: curl redirect/config options, absolute paths to curl/docker/jq/
#     python3/sleep/stat/seq, shell functions or aliases shadowing them, PATH=, GITHUB_PATH, GITHUB_ENV, URL hosts other
#     than 127.0.0.1 or localhost.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
pylib=$(mktemp -d); work=$(mktemp -d); trap 'rm -rf "$pylib" "$work"' EXIT
ln -s "$root/.github/agent/fixtures/testlib/pyyaml" "$pylib/yaml"
export PYTHONPATH="$pylib${PYTHONPATH:+:$PYTHONPATH}"
python3 - "$root" "$work" <<'PY'
import ast, base64, concurrent.futures, hashlib, http.server, json, os, queue, re, shutil, socket, socketserver, struct, subprocess, sys, tempfile, threading, time, yaml
root, work = sys.argv[1], sys.argv[2]
passed = failed = 0
T0 = time.time()
def par(tasks, workers=6):
    """Run tasks concurrently; their check() calls are replayed here in task order."""
    def run(t):
        _tl.buf = []
        try: t()
        except Exception as e: _tl.buf.append(("task raised", False, repr(e)))
        b, _tl.buf = _tl.buf, None
        return b
    with concurrent.futures.ThreadPoolExecutor(workers) as ex_:
        for b in ex_.map(run, tasks):
            for n, o, g in b: check(n, o, g)
def lap(n): print('timing: %s done at %.0fs' % (n, time.time() - T0))
_tl = threading.local()
def check(name, ok, got=""):
    global passed, failed
    if getattr(_tl, "buf", None) is not None: _tl.buf.append((name, ok, got)); return
    if ok: passed += 1; print("ok:", name)
    else: failed += 1; print("FAIL:", name, "->", str(got)[:300])
def rd(p): return open(os.path.join(root, p)).read()

GOOD_FIPS = "active (Go validated module v1.0.0, CMVP cert #5247)"
FORCED = "active (fips140 mode forced at runtime; not the validated-module build)"
VARIANTS = ("production", "debug", "fips")
NOTE = {"production": "off", "debug": "off", "fips": GOOD_FIPS}

# ---------------------------------------------------------------- 0. the AC and the release note, as parsed
EXPECT = {
 "given": "in candidates mode, the candidate image variants of a release (production, -debug and -fips) by candidate digest, running as the containers the artifact acceptance already starts on linux/amd64 and, under emulation, on linux/arm64 (the emulated arm64 containers are UNVERIFIED until the first run shows they serve /statusz)",
 "when": "/statusz is read from each running container",
 "then": "the -fips containers report 'active (Go validated module v1.0.0, CMVP cert #5247)', the production and -debug containers report 'off', and any other report (including the forced-mode line on a standard image), a container that does not answer /statusz with HTTP status 200, a container that is not the image pulled by that digest, or a missing variant on either architecture blocks the release",
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
check("the evidence mapping names the two artifact-acceptance steps, the program and this test, and no k8s stage",
      "stage-acceptance-artifacts.yml" in refs and "exercise the images" in refs and "R11" in refs and "bin/fips-image-posture.py" in refs
      and ".github/agent/tests/fips-image-check-test.sh" in refs and "k8s" not in refs and "only in candidates mode" in refs, refs)
paras = [p for p in rd("RELEASING.md").split("\n\n") if "REQ-FIPS-002-AC2" in p]
flat = " ".join(" ".join(paras).split())
check("RELEASING.md says AC2 gates only under a baseline frozen after it merged, v0.2.0 and v0.2.1 lacking it, the job failing blocks anyway",
      "frozen after it merged" in flat and "v0.2.0" in flat and "v0.2.1" in flat and "blocks the release regardless" in flat, flat)
check("RELEASING.md describes the artifact acceptance (candidates mode, amd64 and arm64), not the Kubernetes stage",
      "linux/amd64" in flat and "linux/arm64" in flat and "candidates mode" in flat and "Kubernetes" not in flat, flat)
check("RELEASING.md says the posture check also runs in archives mode (the PR chain) and can fail those runs",
      "archives mode" in flat and "PR chain" in flat and "can fail" in flat, flat)

lap('part 0')
# ---------------------------------------------------------------- A. the workflow
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
REL = yaml.safe_load(rd(".github/workflows/release.yml"))["jobs"]
def release_problems(jobs):
    out = []
    callers = [k for k, j in jobs.items() if j.get("uses") == "./.github/workflows/stage-acceptance-artifacts.yml"]
    if len(callers) != 1: return ["callers %s" % callers]
    k = callers[0]; j = jobs[k]; w = j.get("with") or {}
    if w.get("mode") != "candidates": out.append("mode %r" % (w.get("mode"),))
    if w.get("digests") != "${{ needs.image.outputs.digests }}" or "image" not in (j.get("needs") or []): out.append("digests")
    if {"if", "continue-on-error"} & set(j): out.append("conditional")
    pj = [x for x in jobs.values() if x.get("uses") == "./.github/workflows/stage-acceptance-predicate.yml"]
    if len(pj) != 1: out.append("predicate jobs %d" % len(pj))
    else:
        if k not in (pj[0].get("needs") or []): out.append("the predicate does not need the artifacts job")
        if (pj[0].get("with") or {}).get("artifacts-results") != "${{ needs.%s.outputs.results }}" % k: out.append("artifacts-results")
    return out
check("release.yml: the artifacts stage is called once with mode candidates and the image stage's digests, unconditionally, and the predicate needs it and takes its results", not release_problems(REL), release_problems(REL))
import copy
def relmut(f):
    j = copy.deepcopy(REL); f(j); return release_problems(j)
k_ = [k for k, j in REL.items() if j.get("uses") == "./.github/workflows/stage-acceptance-artifacts.yml"][0]
p_ = [k for k, j in REL.items() if j.get("uses") == "./.github/workflows/stage-acceptance-predicate.yml"][0]
for name, f in (("mode removed", lambda j: j[k_]["with"].pop("mode")), ("mode archives", lambda j: j[k_]["with"].update(mode="archives")),
                ("digests removed", lambda j: j[k_]["with"].pop("digests")), ("job made conditional", lambda j: j[k_].update({"if": "false"})),
                ("the predicate no longer needs it", lambda j: j[p_].update(needs=[n for n in j[p_]["needs"] if n != k_])),
                ("the predicate takes another job's results", lambda j: j[p_]["with"].update({"artifacts-results": "${{ needs.acceptance.outputs.maven-results }}"})),
                ("a second caller in archives mode", lambda j: j.update({"again": {"uses": "./.github/workflows/stage-acceptance-artifacts.yml", "with": {"mode": "archives"}}}))):
    check("release.yml pin catches: " + name, bool(relmut(f)), name)
check("no step has continue-on-error or a shell override", all(not {"continue-on-error", "shell"} & set(s) for s in steps))
check("the job has timeout-minutes (a positive integer, at most 120)", isinstance(job.get("timeout-minutes"), int) and 0 < job["timeout-minutes"] <= 120, job.get("timeout-minutes"))
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
CALL = re.compile(r"python3 -I bin/fips-image-posture\.py check\b")
ESC = [(r"\bcommand\b", "command"), (r"(^|[;&|(`\s])env\s", "env"), (r"\bexec\b", "exec"), (r"\beval\b", "eval"), (r"\b(?:ba|z|da)?sh\s+-\w*c\b", "sh -c"),
       (r"\bxargs\b", "xargs"), (r"\bbuiltin\b", "builtin"), (r"(?<![\w$-])\\(?:docker|curl|jq|python3|sleep|stat|seq)\b", "backslash-escaped tool"), (r"\benable\b", "enable"),
       (r"\bsource\b", "source"), (r"(^|[;&|(\s])\.\s+\S", ". file"), (r"\b(?:nohup|setsid|chroot|nsenter|timeout)\s", "wrapper")]
def escapes(t):
    code = [l for l in t.splitlines() if not l.strip().startswith("#")]
    return [n for rx, n in ESC if any(re.search(rx, l) for l in code)]
for name, s in ((EX, ex), (ARM, arm), (RES, res)):
    t = (s or {}).get("run", "")
    check("%s: nothing runs a tool around the PATH stubs (command, env, exec, eval, sh -c, xargs, builtin, escaped names)" % name, s is not None and not escapes(t), escapes(t))
    hosts = {m.split("/")[0].split(":")[0] for m in re.findall(r"https?://([^\s'\"]+)", t)}
    check("%s: no shadowing of tools, no PATH or GITHUB_ENV/PATH edits" % name, s is not None and not SHADOW.search(t), SHADOW.findall(t))
    redir = [l.strip() for l in t.splitlines() if re.search(r"\bcurl\b", l) and re.search(r"(?<![\w-])(?:-[A-Za-z]*L[A-Za-z]*|--location(?:-trusted)?|-K|--config|--proto-redir\S*|--next)(?![\w-])", l)]
    check("%s: no curl follows redirects or reads a config file" % name, s is not None and not redir, redir)
    check("%s: no absolute-path tool invocation" % name, s is not None and not ABS.search(t), ABS.findall(t))
    check("%s: every URL host is 127.0.0.1 or localhost" % name, s is not None and hosts <= {"127.0.0.1", "localhost"}, hosts)
    check("%s: set -euo pipefail, no per-step env: or working-directory:" % name,
          s is not None and "set -euo pipefail" in t and not {"env", "working-directory"} & set(s))
    code = [l for l in t.splitlines() if not l.strip().startswith("#")]
    check("%s: /statusz is not fetched with curl (nor wget or nc)" % name,
          not [l for l in code if "statusz" in l and re.search(r"\b(curl|wget|nc|ncat)\b", l)] and not [l for l in code if re.search(r"\b(wget|nc|ncat)\b", l)],
          [l for l in code if "statusz" in l])
    check("%s: python3 is used for nothing but the posture program's check command" % name,
          s is not None and all(CALL.search(l) for l in code if re.search(r"\bpython\w*\b", l)), [l for l in code if re.search(r"\bpython\w*\b", l)])
    check("%s: no tee, no here-string or pipe feeding a response around" % name,
          s is not None and not [l for l in code if re.search(r"\btee\b", l)], [l for l in code if re.search(r"\btee\b", l)])
for form in ("command -p docker tag localhost/fa-fips x || true", "env docker tag a b", "exec docker tag a b", 'eval "docker tag a b"', "bash -c 'docker tag a b'",
             "sh -c 'docker tag a b'", "echo a | xargs docker tag", "\\docker tag a b", "builtin command -p docker tag a b", "source /tmp/x", ". /tmp/x", "nohup docker tag a b", "timeout 5 docker tag a b",
             "/usr/bin/docker tag a b"):
    check("static scan catches an escape: %s" % form, ex is not None and bool(escapes(ex["run"] + "\n" + form) or ABS.search(form)), form)
check("the amd64 step initialises the matrix file itself and the arm64 step never truncates it",
      ex is not None and arm is not None and re.search(r"^\s*:\s*>\s*/tmp/posture-matrix\.txt\s*$", ex["run"], re.M) is not None
      and not re.search(r"(?<!>)>\s*/tmp/posture-matrix\.txt|truncate[^\n]*posture-matrix|\bcp\b[^\n]*posture-matrix|\bmv\b[^\n]*posture-matrix|\brm\b[^\n]*posture-matrix", arm["run"]))
check("the posture program is referenced only by the two container steps",
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
PORT = {"amd64": {"production": 19010, "debug": 19012, "fips": 19011}, "arm64": {v: 19021 + i for i, v in enumerate(VARIANTS)}}

STUBLIB = r'''
import hashlib, json, os, re, sys
D = os.environ["STUB_DIR"]
CFG = json.load(open(D + "/cfg.json"))
ST = D + "/state.json"
OWNER = CFG["owner"]; REPO = "ghcr.io/%s/cache-candidates" % OWNER
DIG = CFG["digests"]
NOTE = {"production": "off", "debug": "off", "fips": "active (Go validated module v1.0.0, CMVP cert #5247)"}
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
    except Exception: return {"c": {}, "local": [] if CFG.get("no_local_tags") else [tag(v) for v in DIG], "health": {}, "pk": {}, "n": 0, "tags": {}}
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
        e = {"amd": {"platform": {"os": "linux", "architecture": "amd64"}, "digest": "sha256:" + hx("amd-" + DIG[v])},
             "arm": {"platform": {"os": "linux", "architecture": "arm64"}, "digest": child(v)},
             "att": {"platform": {"os": "unknown", "architecture": "unknown"}, "digest": "sha256:" + hx("att-" + DIG[v])}}
        order = {"default": ["amd", "arm", "att"], "arm-first": ["arm", "amd", "att"], "arm-last": ["att", "amd", "arm"]}[CFG.get("manifest_order", "default")]
        print(json.dumps({"manifests": [e[k] for k in order]}))
        sys.exit(0)
    if sub == "pull":
        pos, i = [], 0
        while i < len(rest):
            if rest[i] == "--platform": i += 2; continue
            if not rest[i].startswith("-"): pos.append(rest[i])
            i += 1
        log(cmd="docker", sub="pull", args=rest, positional=pos)
        info = IMG.get(pos[0]) if len(pos) == 1 else None
        if (not info or pos[0].startswith("localhost/") or info[0] in CFG.get("pull_fail", [])
                or (info[1] == "arm64" and info[0] in CFG.get("pull_fail_child", []))):
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
            if x.startswith("--publish="):
                m = re.match(r"(?:[^:]+:)?(\d+):(\d+)$", x.split("=", 1)[1]); port = int(m.group(1)) if m else None
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
        ok = bool(info) and image in s["local"] and ("%s:%s" % (info[1], info[0])) not in CFG.get("run_fail", [])
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
    fail, url, out, wo, meth, user, data, i = False, None, None, None, None, None, None, 0
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
            if k == "--user": user = v
            if k == "--request": meth = v
            if k in ("--data", "--data-binary"): data = v
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
    if path == "/statusz":
        log(result="forbidden", **rec); sys.stderr.write("stub: /statusz must be read by the posture program, not curl\n"); sys.exit(1)
    cname, c = next(((n, c) for n, c in s["c"].items() if c["port"] == port), (None, None))
    if not c:
        log(result="refused", **rec); sys.stderr.write("curl: (7) refused\n"); sys.exit(7)
    v, arch = c["variant"], c["arch"]
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
    elif (meth or "") == "PUT" or data is not None:
        c["data"][path] = data or ""; s["c"][cname] = c; save(s); code, rb = 200, ""
    else:
        code, rb = (200, c["data"][path]) if path in c["data"] else (404, "not found")
    log(result="ok" if code < 400 else "http_error", code=code, variant=v, arch=arch, **rec)
    if code >= 400 and fail:
        sys.stderr.write("curl: (22) The requested URL returned error: %d\n" % code); sys.exit(22)
    wtxt = (wo or "").replace("%{http_code}", str(code))
    if out and out not in ("-", "/dev/null"):
        open(out, "w").write(rb); sys.stdout.write(wtxt)
    elif out == "/dev/null": sys.stdout.write(wtxt)
    else: sys.stdout.write(rb + wtxt)
    sys.exit(0)
def py(a):
    s = load()
    if a[:3] != ["-I", "bin/fips-image-posture.py", "check"]:
        log(cmd="python3", unexpected=True, args=a); sys.stderr.write("stub: unexpected python3 use\n"); sys.exit(1)
    d, i, ok = {}, 3, True
    while i < len(a):
        if a[i].startswith("--") and i + 1 < len(a) and a[i][2:] not in d: d[a[i][2:]] = a[i + 1]; i += 2
        else: ok = False; break
    ok = ok and set(d) in ({"arch", "variant", "port", "matrix"}, {"arch", "variant", "port", "user", "password", "matrix"})
    log(cmd="posture-check", args=a, d=d, wellformed=ok)
    if not ok: sys.stderr.write("usage\n"); sys.exit(2)
    c = next((c for c in s["c"].values() if str(c["port"]) == d["port"]), None)
    def no(why): sys.stderr.write("variant %s: %s\n" % (d["variant"], why)); sys.exit(1)
    if not c:
        if "%s:%s" % (d["arch"], d["variant"]) in CFG.get("stale", []):   # a stale service answers the port
            open(d["matrix"], "a").write("linux/%s %s\n" % (d["arch"], d["variant"])); sys.exit(0)
        no("connection refused")
    key = "%s:%s" % (c["arch"], c["variant"])
    n = s["pk"].get(key, 0); s["pk"][key] = n + 1; save(s)
    if CFG["health"].get(c["variant"]) == "never": no("no answer")
    if n < CFG["check_flaky"].get(key, 0) or key in CFG["check_fail"]: no("scripted failure")
    if c["auth"] and (d.get("user"), d.get("password")) != ("acc", "accpw"): no("HTTP status 401")
    if d["arch"] != c["arch"] or d["variant"] != c["variant"]: no("the container behind this port is %s" % key)
    if CFG["notes"].get(key, NOTE[c["variant"]]) != NOTE[d["variant"]]: no("wrong posture")
    if not CFG.get("nowrite"): open(d["matrix"], "a").write("linux/%s %s\n" % (d["arch"], d["variant"]))
    sys.exit(0)
def main(kind):
    a = sys.argv[1:]
    if kind == "sleep": log(cmd="sleep", args=a); sys.exit(0)
    if kind == "stat":
        log(cmd="stat", args=a)
        if a[:2] == ["-c", "%u"] and len(a) == 3 and re.fullmatch(r"/proc/\d+", a[2]): print(CFG.get("uid", 65532)); sys.exit(0)
        sys.stderr.write("stub: unsupported stat\n"); sys.exit(1)
    {"docker": docker, "curl": curl, "python3": py}[kind](a)
'''
TOOLS = ["bash", "sh", "jq", "mktemp", "cat", "mkdir", "rm", "seq", "tr", "cut", "head", "tail", "grep", "sed", "awk",
         "printf", "date", "true", "false", "test", "[", "dirname", "basename", "wc", "sort", "cmp", "diff", "env",
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
    open(stub + "/sleep", "w").write('#!/bin/sh\nprintf \'{"cmd": "sleep", "args": ["%s"]}\\n\' "$1" >> "$STUB_DIR/log.jsonl"\n'); os.chmod(stub + "/sleep", 0o755)
    for k in ("docker", "curl", "stat", "python3"):
        open(stub + "/" + k, "w").write("#!%s\nimport sys; sys.path.insert(0, %r); import stublib; stublib.main(%r)\n" % (sys.executable, stub, k))
        os.chmod(stub + "/" + k, 0o755)
    for t in TOOLS:
        w = shutil.which(t)
        if w and not os.path.exists(tools + "/" + t): os.symlink(w, tools + "/" + t)
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
    try:
        p = subprocess.run([shutil.which("bash"), "-e", d + "/step.sh"], cwd=ws, env=env, capture_output=True, text=True, timeout=30)
        rc, err, so = p.returncode, p.stderr, p.stdout
    except subprocess.TimeoutExpired:
        rc, err, so = None, "timeout", ""
    logf = stub + "/log.jsonl"
    log = [json.loads(l) for l in open(logf)] if os.path.exists(logf) else []
    mf = lambda f: open(tmp + "/" + f).read() if os.path.exists(tmp + "/" + f) else None
    state = json.load(open(stub + "/state.json")) if os.path.exists(stub + "/state.json") else {}
    return dict(state=state, rc=rc, err=err, out=so, log=log, problems=problems, tmp=tmp, matrix=mf("posture-matrix.txt"), output=mf("gh-output"),
                intact=os.listdir(ws + "/bin") == [])

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
def expected_call(arch, v, tmp):
    d = {"arch": arch, "variant": v, "port": str(PORT[arch][v]), "matrix": tmp + "/posture-matrix.txt"}
    if v == "fips": d.update(user="acc", password="accpw")
    return d

def judge_good(arch, r, L=None, retried=False):
    log = r["log"]; L = L or "good run (%s)" % arch
    check("%s: the step exits 0" % L, r["rc"] == 0, (r["rc"], r["err"].strip()[-300:]))
    check("%s: the step uses exactly the ${{ }} expressions it had; bin/ is untouched" % L, not r["problems"] and r["intact"], r["problems"])
    dock = [x for x in log if x.get("cmd") == "docker"]
    check("%s: no docker subcommand beyond run, inspect, rm, logs, ps, pull, buildx, login; no python3 but the posture check; no curl on /statusz" % L,
          not [x for x in dock if x.get("unexpected")] and not [x for x in log if x.get("cmd") == "python3"] and not [x for x in log if x.get("result") == "forbidden"],
          [x for x in log if x.get("unexpected") or x.get("result") == "forbidden"])
    check("%s: every curl is on loopback and reaches a running container" % L, not [x for x in log if x.get("cmd") == "curl" and x["result"] in ("refused", "nonloopback")],
          [x["args"] for x in log if x.get("result") in ("refused", "nonloopback")])
    check("%s: no new container is started and none is changed: the docker run commands are exactly the existing ones, in order" % L,
          arg_lists(log, "run") == expected_runs(arch), arg_lists(log, "run"))
    if arch == "arm64":
        check("%s: the pulls and the index lookups are exactly the existing ones (the child is chosen by platform)" % L,
              arg_lists(log, "pull") == [["-q", "%s@%s" % (REPO, CHILD[v])] for v in VARIANTS]
              and arg_lists(log, "buildx") == [["imagetools", "inspect", "--raw", "%s@%s" % (REPO, DIG[v])] for v in VARIANTS],
              (arg_lists(log, "pull"), arg_lists(log, "buildx")))
        check("%s: each container is removed as before" % L, arg_lists(log, "rm") == [["-f", "fa-arm64-" + v] for v in VARIANTS], arg_lists(log, "rm"))
    else:
        check("%s: the containers are removed as before" % L, arg_lists(log, "rm") == [["-f", "fa-prod", "fa-debugrun", "fa-fipsrun"]], arg_lists(log, "rm"))
    runs = [x for x in dock if x["sub"] == "run" and not x["fg"]]
    gone = {"tag", "rmi", "load", "import", "build", "commit", "login"} | ({"pull"} if arch == "amd64" else set())
    check("%s: no docker %s" % (L, "/".join(sorted(gone))), not [x["sub"] for x in dock if x["sub"] in gone], [x["sub"] for x in dock if x["sub"] in gone])
    check("%s: every detached docker run started its container" % L, len(runs) == 3 and all(x["started"] for x in runs), [(x["name"], x["started"]) for x in runs])
    seen = {t for x in dock if x["sub"] == "inspect" for t in x["targets"]}
    check("%s: each started container is inspected (its image compared with the image it was started from)" % L,
          len(runs) == 3 and all(x["name"] in seen or x["id"] in seen for x in runs) and any(t not in {x["name"] for x in runs} | {x["id"] for x in runs} for t in seen),
          [x["targets"] for x in dock if x["sub"] == "inspect"])
    calls = [(k, x) for k, x in enumerate(log) if x.get("cmd") == "posture-check"]
    if retried:   # keep the last call of each variant: the earlier ones are the failed attempts
        last = {x["d"].get("variant"): (k, x) for k, x in calls}
        calls = [last[v] for v in VARIANTS if v in last]
    check("%s: exactly one posture check per variant, with exactly the arguments (python3 -I, script, check, arch, variant, port, matrix; user and password only for fips)" % L,
          len(calls) == 3 and all(x["args"][:3] == ["-I", "bin/fips-image-posture.py", "check"] and x["wellformed"] for _, x in calls)
          and [x["d"] for _, x in calls] == [expected_call(arch, v, r["tmp"]) for v in VARIANTS], [x["args"] for _, x in calls])
    ok = True
    for v in VARIANTS:
        c = next((x for x in runs if x["variant"] == v), None)
        if not c: ok = False; continue
        hz = [k for k, x in enumerate(log) if x.get("cmd") == "curl" and x.get("variant") == v and x["path"] == "/healthz" and x["result"] == "ok"]
        pc = [k for k, x in calls if x["d"].get("variant") == v]
        rm = [k for k, x in enumerate(log) if x.get("sub") == "rm" and (c["name"] in x["names"] or c["id"] in x["names"])]
        if not (hz and pc and rm and min(hz) < min(pc) < min(rm)): ok = False
    check("%s: each variant is checked after its healthz answered and while its container is running (before its docker rm)" % L, ok)
    check("%s: the posture matrix has exactly the three lines of this architecture" % L,
          (r["matrix"] or "") == "".join("linux/%s %s\n" % (arch, v) for v in VARIANTS), r["matrix"])

def sleep_total(log, after):
    t = 0.0
    for x in log[after:]:
        if x.get("cmd") == "sleep":
            try: t += float(x["args"][0])
            except Exception: pass
    return t

def base_cfg(**kw):
    c = dict(owner=OWNER, digests=DIG, health={"production": 2, "debug": 0, "fips": 3}, notes={}, check_fail=[], check_flaky={},
             inspect="ok", manifest_order="default")
    c.update(kw); return c

def judge_bad(label, arch, step, cfg, digests=None, absent=None, flaky=False):
    r = run_step(step, cfg, digests)
    log = r["log"]
    if not flaky:
        check("%s: the step ends (no hang) and exits non-zero" % label, r["rc"] is not None and r["rc"] != 0, (r["rc"], r["err"][-150:]))
        if absent:
            check("%s: the failing variant is not claimed in the posture matrix" % label, ("linux/%s %s\n" % (arch, absent)) not in (r["matrix"] or ""), r["matrix"])
            cs = [k for k, x in enumerate(log) if x.get("cmd") == "posture-check" and x["d"].get("variant") == absent]
            check("%s: the check is called at least once" % label, bool(cs), len(cs))
            if cs:
                sl = sleep_total(log, cs[0])
                check("%s: the check is retried (%d attempts, %.0fs of sleep; at least 20 attempts or 10 s)" % (label, len(cs), sl), len(cs) >= 20 or sl >= 10)
                check("%s: the retry around the check is bounded (at most 120 attempts and 120 s)" % label, len(cs) <= 120 and sl <= 120)
    else:   # the retry budget: a call that is retried must be retried for >= 20 attempts or >= 10 s
        calls = [k for k, x in enumerate(log) if x.get("cmd") == "posture-check" and x["d"].get("variant") == "fips"]
        n = len(calls)
        slept = sleep_total(log, calls[0]) if calls else 0
        check("%s: a retried posture check does not give up early (attempts %d, sleeps %.1fs)" % (label, n, slept),
              r["rc"] is not None and (r["rc"] == 0 or n >= 20 or slept >= 10), (r["rc"], n))
        if r["rc"] == 0: judge_good(arch, r, label + " (passed on retry)", retried=True)

TA = []
def child_pull(v):
    r = run_step(arm, base_cfg(pull_fail_child=[v]))
    pulls = arg_lists(r["log"], "pull"); runs = arg_lists(r["log"], "run")
    check("arm64 the %s child pull fails: the step fails, with no pull, tag or run of any other image (no fallback tag or index)" % v,
          r["rc"] not in (0, None) and all(p[-1] in childs for p in pulls) and all(x[-1] in childs for x in runs)
          and not any(x[-1].endswith(CHILD[v]) for x in runs) and not arg_lists(r["log"], "tag"), (r["rc"], pulls, runs))
childs = {"%s@%s" % (REPO, CHILD[v]) for v in VARIANTS}
for arch, step in (("amd64", ex), ("arm64", arm)):
    if step is None:
        check("%s: the step exists to be run" % arch, False, "step missing"); continue
    TA.append(lambda arch=arch, step=step: judge_good(arch, run_step(step, base_cfg())))
    for v in VARIANTS:
        k = "%s:%s" % (arch, v)
        TA.append(lambda arch=arch, step=step, v=v, k=k: judge_bad("%s %s: the posture check fails" % (arch, v), arch, step, base_cfg(check_fail=[k]), absent=v))
        TA.append(lambda arch=arch, step=step, v=v: judge_bad("%s %s container is not the image it was started from" % (arch, v), arch, step, base_cfg(inspect="mismatch:%s:%s" % (arch, v))))
    k = "%s:fips" % arch
    TA.append(lambda arch=arch, step=step, k=k: judge_bad("%s fips reports a wrong posture" % arch, arch, step, base_cfg(notes={k: "WRONG"}), absent="fips"))
    TA.append(lambda arch=arch, step=step: judge_bad("%s fips never becomes healthy" % arch, arch, step, base_cfg(health={"production": 0, "debug": 0, "fips": "never"})))
    for v in VARIANTS:
        TA.append(lambda arch=arch, step=step, v=v: judge_bad("%s %s: the docker run fails and a stale service answers the port" % (arch, v), arch, step,
                                                              base_cfg(run_fail=["%s:%s" % (arch, v)], stale=["%s:%s" % (arch, v)])))
    TA.append(lambda arch=arch, step=step: judge_bad("%s docker inspect of the container fails" % arch, arch, step, base_cfg(inspect="fail")))
    TA.append(lambda arch=arch, step=step: judge_bad("%s docker inspect of the container answers nothing" % arch, arch, step, base_cfg(inspect="empty")))
    TA.append(lambda arch=arch, step=step, k=k: judge_bad("%s fips posture check fails 18 times, then answers" % arch, arch, step, base_cfg(check_flaky={k: 18}), flaky=True))
if arm is not None:
    for order in ("arm-first", "arm-last"):
        TA.append(lambda order=order: judge_good("arm64", run_step(arm, base_cfg(manifest_order=order)), "good run (arm64, manifest order %s)" % order))
    TA.append(lambda: judge_bad("arm64 the fips digest is null", "arm64", arm, base_cfg(), digests={"production": DIG["production"], "debug": DIG["debug"], "fips": None}))
    TA.append(lambda: judge_bad("arm64 the fips digest key is missing", "arm64", arm, base_cfg(), digests={"production": DIG["production"], "debug": DIG["debug"]}))
    TA.append(lambda: judge_bad("arm64 the debug digest is null", "arm64", arm, base_cfg(), digests={"production": DIG["production"], "debug": None, "fips": DIG["fips"]}))
    for v in VARIANTS: TA.append(lambda v=v: child_pull(v))
def chain():
    if ex is None or arm is None or res is None: check("end to end: the three steps exist", False); return
    r1 = run_step(ex, base_cfg())
    r2 = run_step(arm, base_cfg(), tmp_dir=r1["tmp"])
    r3 = run_step(res, base_cfg(), tmp_dir=r1["tmp"])
    try: out = json.loads((r3["output"] or "").strip().split("results=", 1)[1])
    except Exception as e: out = repr(e)
    pairs = {(x["ac"], x["result"]) for x in out} if isinstance(out, list) else set()
    check("end to end, one /tmp: exercise, then arm64, then the results step in candidates mode earns REQ-FIPS-002-AC2 pass (the amd64 step initialises the matrix, the arm64 step does not truncate it)",
          r1["rc"] == 0 and r2["rc"] == 0 and r3["rc"] == 0 and ("REQ-FIPS-002-AC2", "pass") in pairs and ("REQ-PLAT-002-AC1", "pass") in pairs,
          (r1["rc"], r2["rc"], r3["rc"], r3["err"][-150:], out))
def stale():
    if ex is None or arm is None or res is None: check("stale matrix: the three steps exist", False); return
    T = tempfile.mkdtemp(dir=work)
    r1 = run_step(ex, base_cfg(nowrite=True), tmp_dir=T, mats={"posture-matrix.txt": "".join(l + "\n" for l in SIX)})
    r2 = run_step(arm, base_cfg(nowrite=True), tmp_dir=T)
    r3 = run_step(res, base_cfg(), tmp_dir=T)
    check("six stale lines in /tmp/posture-matrix.txt and no real check: the results step must not earn REQ-FIPS-002-AC2 (the amd64 step initialises the file)",
          r3["rc"] not in (0, None) and "REQ-FIPS-002-AC2" not in (r3["output"] or ""), (r1["rc"], r2["rc"], r3["rc"], r3["output"]))
SIX = ["linux/%s %s" % (a, v) for a in ("amd64", "arm64") for v in VARIANTS]
TA.append(stale)
TA.append(chain)
par(TA)
lap('part A, container steps')
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
    def pm(name, f):
        m = dict(pull); m["run"] = f(pull["run"])
        check("pull-step mutant is caught: " + name, m["run"] != pull["run"] and bool(pull_failures(m)), "not applied" if m["run"] == pull["run"] else "")
    par([lambda name=name, f=f: pm(name, f) for name, f in PM])

lap('pull step')
# the results step: AC2 is derived from the posture matrix, like REQ-PLAT-002 from the served matrix
SIX = ["linux/%s %s" % (a, v) for a in ("amd64", "arm64") for v in VARIANTS]
def mat(lines): return "".join(l + "\n" for l in lines)
def results_case(label, mode, served, posture, want):
    if res is None: check(label + ": the results step exists", False); return
    mats = {"served-matrix.txt": served}
    if posture is not None: mats["posture-matrix.txt"] = posture
    r = run_step(res, base_cfg(), mode=mode, mats=mats)
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
results_case("candidates mode, all six posture lines", "candidates", mat(SIX), mat(SIX), "pass")
results_case("archives mode (locally assembled images, no arm64), the three amd64 posture lines", "archives", mat(SIX[:3]), mat(SIX[:3]), "nopass")
results_case("archives mode, no posture matrix", "archives", mat(SIX[:3]), None, "nopass")
results_case("archives mode, even a full six-line posture matrix", "archives", mat(SIX[:3]), mat(SIX), "nopass")
results_case("candidates mode, no posture matrix at all", "candidates", mat(SIX), None, "fail")
results_case("candidates mode, only the amd64 posture lines", "candidates", mat(SIX), mat(SIX[:3]), "fail")
for i, line in enumerate(SIX):
    rest = SIX[:i] + SIX[i + 1:]
    results_case("candidates mode, '%s' deleted" % line, "candidates", mat(SIX), mat(rest), "fail")
    for what, bad in (("with a suffix", line + "-extra"), ("with a trailing space", line + " "), ("with a prefix", "x" + line), ("with the other architecture", line.replace("amd64", "ARCH").replace("arm64", "amd64").replace("ARCH", "arm64")),
                      ("indented", " " + line)):
        results_case("candidates mode, '%s' corrupted %s" % (line, what), "candidates", mat(SIX), mat(SIX[:i] + [bad] + SIX[i + 1:]) if what != "with the other architecture" else mat(rest + [bad]), "fail")

lap('results step')
# ---------------------------------------------------------------- B. the program, against a real HTTP server
script = os.path.join(root, "bin/fips-image-posture.py")
class Srv(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    def handle_error(self, request, client_address): pass
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def do_GET(self):
        S = self.server
        S.hits.append((self.path, {k.lower(): v for k, v in self.headers.items()}))
        c = S.cfg
        if S.name == "other":
            self.reply(200, {}, c.get("body", b"")); return
        if S.name == "decoy":
            self.reply(200, {}, json.dumps({"fips140_note": "DECOY"}).encode()); return
        if self.path != "/statusz": self.reply(404, {}, b"not found"); return
        if c.get("auth") and self.headers.get("Authorization") != c["auth"]:
            self.reply(401, {"WWW-Authenticate": 'Basic realm="x"'}, b"unauthorized"); return
        mode = c.get("mode")
        try:
            if mode == "hang": time.sleep(30); return
            if mode == "raw":     # bytes written as given, each after its delay; "rst" resets the connection
                for it in c["raw"]:
                    if it == "rst":
                        self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)); self.connection.close(); return
                    if it[1]: time.sleep(it[1])
                    self.wfile.write(it[0]); self.wfile.flush()
                self.close_connection = True; return
            if mode == "dribble":
                self.send_response(200); self.send_header("Content-Length", "100000"); self.send_header("Connection", "close"); self.end_headers()
                for _ in range(80):
                    self.wfile.write(b" "); self.wfile.flush(); time.sleep(0.4)
                return
            if mode == "chunked":
                self.send_response(200); self.send_header("Transfer-Encoding", "chunked"); self.send_header("Connection", "close"); self.end_headers()
                b = c["body"]; h = len(b) // 2
                for part in (b[:h], b[h:]): self.wfile.write(b"%x\r\n" % len(part) + part + b"\r\n")
                self.wfile.write(b"0\r\n\r\n"); return
            self.reply(c.get("status", 200), c.get("headers", {}), c.get("body", b""))
        except (BrokenPipeError, ConnectionError, OSError): pass
    def reply(self, status, headers, body):
        self.send_response(status)
        for k, v in headers.items(): self.send_header(k, v)
        if status not in (204, 304): self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if status not in (204, 304): self.wfile.write(body)
        self.close_connection = True
def mk(name):
    s = Srv(("127.0.0.1", 0), H); s.name, s.cfg, s.hits = name, {}, []
    threading.Thread(target=s.serve_forever, daemon=True).start(); return s
class Srv6(Srv): address_family = socket.AF_INET6
def mk6(port):    # a decoy on [::1] at the same port: the answer must come from 127.0.0.1
    try:
        s = Srv6(("::1", port), H); s.name, s.cfg, s.hits = "decoy", {}, []
        threading.Thread(target=s.serve_forever, daemon=True).start(); return s
    except OSError: return None
POOL = queue.Queue()
for _i in range(8):
    _s = mk("statusz"); POOL.put((_s, mk("other"), mk6(_s.server_address[1])))
def closed_port():
    k = socket.socket(); k.bind(("127.0.0.1", 0)); p = k.getsockname()[1]; k.close(); return p
def jb(note, **extra): return json.dumps(dict({"fips140_note": note, "version": "x"}, **extra)).encode()
BASIC = "Basic " + base64.b64encode(b"acc:accpw").decode()

CASES = []   # dict(name, variant, body, status, headers, mode, auth, user, args (None = normal), ok, kind)
def case(name, v="production", body=None, ok=False, status=200, headers=None, mode=None, auth=False, creds=None, args=None, kind="http", arch="amd64", raw=None):
    CASES.append(dict(raw=raw, name=name, v=v, body=jb(NOTE[v]) if body is None else (body.encode() if isinstance(body, str) else body), ok=ok, status=status,
                      headers=headers or {}, mode=mode, auth=auth, creds=(v == "fips") if creds is None else creds, args=args, kind=kind, arch=arch))
for v in VARIANTS:
    case("%s: the exact good answer" % v, v, ok=True, auth=(v == "fips"), arch="arm64" if v == "debug" else "amd64")
case("fips: a chunked good answer", "fips", mode="chunked", ok=True, auth=True)
case("production: a good answer with extra fields and whitespace", body=b' {"a":{"fips140_note":"x"}, "fips140_note": "off", "z":[1]}\n', ok=True)
case("production: a good answer of 60 KiB (under the cap)", body=jb("off", pad="p" * 60000), ok=True)
case("production: credentials given but not needed", creds=True, ok=True)
case("fips: needs credentials and none are given", "fips", auth=True, creds=False)
case("fips: wrong password", "fips", auth=True, creds="wrong")
for v, n, note in [("fips", "off", "off"), ("fips", "the wrong certificate", GOOD_FIPS.replace("5247", "5248")), ("fips", "the wrong module version", GOOD_FIPS.replace("v1.0.0", "v1.0.1")),
                   ("fips", "the forced-mode line", FORCED), ("fips", "a trailing space", GOOD_FIPS + " "), ("fips", "upper case", GOOD_FIPS.upper()),
                   ("fips", "a suffix", GOOD_FIPS + "; extra"), ("fips", "a prefix", "x " + GOOD_FIPS)]:
    case("%s reports %s" % (v, n), v, body=jb(note), auth=True)
for v in ("production", "debug"):
    for n, note in [("the fips string", GOOD_FIPS), ("the forced-mode line", FORCED), ("'off '", "off "), ("' off'", " off"), ("'Off'", "Off"), ("'OFF'", "OFF"),
                    ("'off (x)'", "off (x)"), ("'of'", "of"), ("''", "")]:
        case("%s reports %s" % (v, n), v, body=jb(note))
case("the other variant's answer (production asked, fips answer)", "production", body=jb(GOOD_FIPS))
case("the other variant's answer (fips asked, standard answer)", "fips", body=jb("off"), auth=True)
STAT = (201, 202, 204, 205, 206, 301, 302, 303, 307, 308, 401, 403, 404, 500, 503)
for v in VARIANTS:
    for st in STAT:
        h = {"Location": "http://127.0.0.1:@OTHER@/statusz"} if st in (301, 302, 303, 307, 308) else {}
        case("%s: HTTP %d carrying a good body" % (v, st), v, status=st, headers=h, auth=(v == "fips"))
def RAW(line, headers, body=b""):
    return [((line + "\r\n" + "".join("%s: %s\r\n" % kv for kv in headers) + "\r\n").encode() + body, 0)]
def sized(v, n):
    k = n - len(jb(NOTE[v], pad=""))
    return jb(NOTE[v], pad="p" * k)
for v in VARIANTS:
    G = jb(NOTE[v]); au = (v == "fips")
    case("%s: a 204 that really carries a good body (raw)" % v, v, mode="raw", raw=RAW("HTTP/1.1 204 No Content", [("Content-Length", len(G)), ("Connection", "close")], G), auth=au)
    case("%s: a 204 without a body (raw)" % v, v, mode="raw", raw=RAW("HTTP/1.1 204 No Content", [("Connection", "close")]), auth=au)
    case("%s: a 205 carrying a good body (raw)" % v, v, mode="raw", raw=RAW("HTTP/1.1 205 Reset Content", [("Content-Length", len(G)), ("Connection", "close")], G), auth=au)
    case("%s: a 304 carrying a good body (raw)" % v, v, mode="raw", raw=RAW("HTTP/1.1 304 Not Modified", [("Content-Length", len(G)), ("Connection", "close")], G), auth=au)
    case("%s: Content-Length 5000, the good body, then the connection closes (truncated)" % v, v, mode="raw", raw=RAW("HTTP/1.1 200 OK", [("Content-Length", 5000), ("Connection", "close")], G), auth=au)
    case("%s: Content-Length above the cap with a tiny body" % v, v, mode="raw", raw=RAW("HTTP/1.1 200 OK", [("Content-Length", 1000000), ("Connection", "close")], G), auth=au)
    case("%s: Content-Length smaller than the body" % v, v, mode="raw", raw=RAW("HTTP/1.1 200 OK", [("Content-Length", len(G) - 5), ("Connection", "close")], G), auth=au)
    case("%s: a chunk stream cut short" % v, v, mode="raw", raw=RAW("HTTP/1.1 200 OK", [("Transfer-Encoding", "chunked"), ("Connection", "close")], b"%x\r\n" % len(G) + G[:10]), auth=au)
    case("%s: a good body of exactly 65536 bytes" % v, v, body=sized(v, 65536), ok=True, auth=au)
    case("%s: a body of 65537 bytes" % v, v, body=sized(v, 65537), auth=au)
    case("%s: an oversize body, chunked" % v, v, body=sized(v, 70000), mode="chunked", auth=au)
    case("%s: an oversize body, ended by EOF (no Content-Length)" % v, v, mode="raw", raw=RAW("HTTP/1.1 200 OK", [("Connection", "close")], sized(v, 70000)), auth=au)
    case("%s: a good body ended by EOF (no Content-Length)" % v, v, mode="raw", raw=RAW("HTTP/1.1 200 OK", [("Connection", "close")], G), ok=True, auth=au)
    case("%s: a good body, chunked, with the chunk size in capitals" % v, v, mode="raw", raw=RAW("HTTP/1.1 200 OK", [("Transfer-Encoding", "chunked"), ("Connection", "close")], b"%X\r\n" % len(G) + G + b"\r\n0\r\n\r\n"), ok=True, auth=au)
    for n, t in (("NaN", "NaN"), ("Infinity", "Infinity"), ("-Infinity", "-Infinity"), ("a nested NaN", "[NaN]")):
        case("%s body holds %s" % (v, n), v, body='{"fips140_note":"%s","x":%s}' % (NOTE[v], t), auth=au)
    case("%s: a garbage reply" % v, v, mode="raw", raw=[(b"garbage\r\nnot http\r\n\r\n", 0)], auth=au)
    case("%s: an empty reply (closed at once)" % v, v, mode="raw", raw=[], auth=au)
    case("%s: a reset in the middle of the body" % v, v, mode="raw", raw=RAW("HTTP/1.1 200 OK", [("Content-Length", 5000), ("Connection", "close")], G[:10]) + ["rst"], auth=au)
    case("%s: 150 headers" % v, v, mode="raw", raw=RAW("HTTP/1.1 200 OK", [("X-%d" % i, "v") for i in range(150)] + [("Content-Length", len(G))], G), auth=au)
    case("%s: a header line of 70000 bytes" % v, v, mode="raw", raw=RAW("HTTP/1.1 200 OK", [("X-Long", "a" * 70000), ("Content-Length", len(G))], G), auth=au)
    case("%s reports the third buildinfo state (validated module linked, mode disabled at runtime)" % v, v, body=jb("off (validated module v1.0.0 linked, mode disabled at runtime)"), auth=au)
    case("%s: a good body followed by 70000 spaces" % v, v, body=jb(NOTE[v]) + b" " * 70000, auth=au)
    case("%s: a good body followed by 70000 spaces, chunked" % v, v, body=jb(NOTE[v]) + b" " * 70000, mode="chunked", auth=au)
    case("%s: a good body followed by 70000 spaces, ended by EOF" % v, v, mode="raw", raw=RAW("HTTP/1.1 200 OK", [("Connection", "close")], jb(NOTE[v]) + b" " * 70000), auth=au)
    case("%s body has duplicate keys before the field" % v, v, body='{"a":1,"a":2,"fips140_note":"%s"}' % NOTE[v], auth=au)
    case("%s body has duplicate keys in a nested object" % v, v, body='{"x":{"b":1,"b":2},"fips140_note":"%s"}' % NOTE[v], auth=au)
    case("%s: a body nested 60000 deep (a RecursionError on older Pythons)" % v, v, body=b"[" * 60000, auth=au)
case("production: a redirect loop to itself, with a good body", status=302, headers={"Location": "/statusz"})
case("production: a redirect to another path on the same server, with a good body", status=307, headers={"Location": "/other"})
for n, b in [("empty", ""), ("not JSON", "<html>not json</html>"), ("truncated JSON", '{"fips140_note": "off"'), ("a JSON array", '["off"]'), ("a JSON string", '"off"'),
             ("JSON true", "true"), ("JSON null", "null"), ("a JSON number", "0"), ("without the field", '{"version":"x"}'), ("with a null field", '{"fips140_note": null}'),
             ("with a numeric field", '{"fips140_note": 0}'), ("with a list field", '{"fips140_note": ["off"]}'), ("with trailing text", jb("off").decode() + " x"),
             ("with two documents", jb("off").decode() * 2), ("with a UTF-8 BOM", b"\xef\xbb\xbf" + jb("off")), ("with non-UTF-8 bytes", b'{"fips140_note":"off","x":"\xff"}'),
             ("only whitespace", " \n"), ("with a NUL byte", jb("off") + b"\x00"), ("nested only", '{"x":{"fips140_note":"off"}}'),
             ("with a duplicate key (same value)", '{"fips140_note":"off","fips140_note":"off"}'), ("with a duplicate key (wrong first)", '{"fips140_note":"x","fips140_note":"off"}'),
             ("with a duplicate key (wrong last)", '{"fips140_note":"off","fips140_note":"x"}'), ("over the size cap", jb("off", pad="p" * 70000)),
             ("a very long unterminated string", b'{"fips140_note":"' + b"o" * 100000)]:
    case("production body is %s" % n, body=b)
for n, b in [("a newline and ::error::", jb("x\n::error::pwned")), ("a carriage return and ::stop-commands::", jb("x\r::stop-commands::tok")),
             ("a note that is itself ::error::", jb("::error::pwned")), ("a duplicate key holding a newline and ::error::", '{"a\\n::error::x":1,"a\\n::error::x":2}'),
             ("invalid JSON whose text holds ::error::", '::error::x\n{'), ("a note of 3000 characters", jb("x" * 3000))]:
    case("production body holds %s" % n, body=b)
    case("fips body holds %s" % n, "fips", body=b, auth=True)
for v in ("fips", "debug"):
    case("%s body is not JSON" % v, v, body="<html>", auth=(v == "fips"))
    case("%s body has a duplicate key" % v, v, body='{"fips140_note":"%s","fips140_note":"%s"}' % (NOTE[v], NOTE[v]), auth=(v == "fips"))
case("connection refused", kind="refused")
ARGS = [("no arguments", []), ("only check", ["check"]), ("another command", ["verify", "--arch", "amd64", "--variant", "production", "--port", "@P", "--matrix", "@M"])]
base = ["--arch", "amd64", "--variant", "production", "--port", "@P", "--matrix", "@M"]
for i in range(0, len(base), 2):
    ARGS.append(("the flag %s is missing" % base[i], ["check"] + base[:i] + base[i + 2:]))
ARGS += [("an unknown architecture", ["check", "--arch", "arm", "--variant", "production", "--port", "@P", "--matrix", "@M"]),
         ("an unknown variant", ["check", "--arch", "amd64", "--variant", "prod", "--port", "@P", "--matrix", "@M"]),
         ("a non-numeric port", ["check", "--arch", "amd64", "--variant", "production", "--port", "abc", "--matrix", "@M"]),
         ("port 0", ["check", "--arch", "amd64", "--variant", "production", "--port", "0", "--matrix", "@M"]),
         ("port 70000", ["check", "--arch", "amd64", "--variant", "production", "--port", "70000", "--matrix", "@M"]),
         ("a negative port", ["check", "--arch", "amd64", "--variant", "production", "--port", "-1", "--matrix", "@M"]),
         ("an empty port", ["check", "--arch", "amd64", "--variant", "production", "--port", "", "--matrix", "@M"]),
         ("a user without a password", ["check"] + base + ["--user", "acc"]),
         ("a password without a user", ["check"] + base + ["--password", "accpw"]),
         ("a duplicate flag", ["check"] + base + ["--arch", "arm64"]),
         ("an unknown flag", ["check"] + base + ["--follow", "1"]),
         ("a flag with no value", ["check"] + base + ["--user"]),
         ("an extra positional argument", ["check"] + base + ["extra"])]
for n, a in ARGS: case("arguments: " + n, args=a, kind="args")
case("arguments: a matrix file in a directory that does not exist", args=["check"] + base[:-1] + ["@D/no/such/dir/matrix"], kind="nomatrix")
while len(CASES) % 8: CASES.append(CASES[0])     # the slow cases below fill one whole batch
HDR = b"HTTP/1.1 200 OK\r\nContent-Length: 22\r\n"
case("the server never answers (the program must give up within its deadline)", mode="hang", kind="slow")
case("the server answers headers then dribbles the body for 30 s (an overall deadline)", mode="dribble", kind="slow")
case("the status line arrives at one byte per second", mode="raw", raw=[(bytes([x]), 1.0) for x in HDR + b"\r\n"], kind="slow")
G0 = jb("off")
case("the response arrives in three phases of 1.2 s each (3.6 s in all): the budget is for the whole call", mode="raw",
     raw=[(b"HTTP/1.1 200 OK\r\n", 1.2), (b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(G0), 1.2), (G0, 1.2)], kind="slow")
case("a header arrives at one byte per second", mode="raw", raw=[(b"HTTP/1.1 200 OK\r\n", 0)] + [(bytes([x]), 1.0) for x in b"X-Slow: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"], kind="slow")
case("the chunk-size lines arrive at one byte per second", mode="raw", raw=[(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", 0)] + [(bytes([x]), 1.0) for x in b"16\r\n" + b"0" * 30], kind="slow")

PRE = "linux/amd64 pre-existing\n"
def run_case(sp, c):
    SRV, OTHER, DECOY = POOL.get()
    try: return run_case_on(sp, c, SRV, OTHER, DECOY)
    finally: POOL.put((SRV, OTHER, DECOY))
def run_case_on(sp, c, SRV, OTHER, DECOY):
    SRV.cfg = dict(status=c["status"], headers={k: v.replace("@OTHER@", str(OTHER.server_address[1])) for k, v in c["headers"].items()}, body=c["body"],
                   mode=c["mode"], auth=BASIC if c["auth"] else None, raw=c.get("raw"))
    OTHER.cfg = dict(body=c["body"]); SRV.hits.clear(); OTHER.hits.clear()
    if DECOY: DECOY.hits.clear()
    d = tempfile.mkdtemp(dir=work); matrix = d + "/matrix.txt"; open(matrix, "w").write(PRE)
    port = closed_port() if c["kind"] == "refused" else SRV.server_address[1]
    if c["args"] is None:
        a = ["check", "--arch", c["arch"], "--variant", c["v"], "--port", str(port), "--matrix", matrix]
        if c["creds"]: a[-2:-2] = ["--user", "acc", "--password", "accpw" if c["creds"] is True else "wrong"]
    else:
        a = [x.replace("@P", str(port)).replace("@M", matrix).replace("@D", d) for x in c["args"]]
    env = dict(os.environ)       # every proxy variable points at the trap server: the program must not use any
    for k in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"): env[k] = "http://127.0.0.1:%d" % OTHER.server_address[1]
    env["no_proxy"] = env["NO_PROXY"] = ""
    t0 = time.time()
    try:
        p = subprocess.run([sys.executable, "-I", sp] + a, capture_output=True, text=True, errors="replace", timeout=8 if c["kind"] == "slow" else 15, env=env)
    except subprocess.TimeoutExpired:
        return False
    elapsed = time.time() - t0
    after = open(matrix).read()
    lines = (p.stdout + "\n" + p.stderr).replace("\r", "\n").split("\n")
    if any(l.lstrip().startswith("::") for l in lines) or len(p.stdout) + len(p.stderr) > 4000: return False
    if "Traceback" in p.stdout or "Traceback" in p.stderr: return False
    if OTHER.hits or (DECOY and DECOY.hits): return False
    if c["kind"] == "slow" and elapsed >= 4.5: return False      # the contract says at most 3 s; the rest is process start-up
    if c["ok"]:
        return (p.returncode == 0 and after == PRE + "linux/%s %s\n" % (c["arch"], c["v"]) and len(SRV.hits) == 1 and SRV.hits[0][0] == "/statusz"
                and SRV.hits[0][1].get("authorization") == (BASIC if c["creds"] is True else None))
    if p.returncode == 0 or after != PRE or len(SRV.hits) > 1: return False
    if c["kind"] == "args": return not SRV.hits
    if c["kind"] in ("http", "refused", "slow") and not p.stderr.startswith("variant %s:" % c["v"]): return False
    if c["kind"] == "http" and SRV.hits and SRV.hits[0][0] != "/statusz" and c["status"] != 200: return False
    return True
FOCUS = [("per-phase", r"never answers|dribbl|per second|phases"), ("5 s", r"never answers|dribbl|per second"), ("followed", r"HTTP 30|redirect"), ("any 2xx", r"HTTP 20|204|205|304"), ("3xx", r"HTTP 30"), ("any status", r"HTTP (40|50)"),
         ("size cap", r"oversize|6553|cap"), ("timeout", r"never answers|dribbl|per second"), ("deadline", r"never answers|dribbl|per second"),
         ("NaN", r"NaN|Infinity"), ("truncated", r"truncated|cut short|Content-Length"), ("proxy", r"exact good"), ("nested", r"nested"), ("JSON decoding", r"nested"),
         ("protocol error", r"garbage|150 headers|70000 bytes|empty reply|reset"), ("printed raw", r"newline|carriage|holding|::error::"),
         ("duplicate", r"duplicate|BOM"), ("BOM", r"duplicate|BOM"), ("credentials", r"exact good|needs credentials"), ("connection error", r"refused"),
         ("argument", r"arguments:"), ("password", r"arguments:"), ("exit", r"reports|arguments:"), ("bad arguments", r"arguments:"), ("unknown variant", r"arguments:"),
         ("matching", r"reports"), ("certificate", r"reports|exact good"), ("version", r"reports|exact good"), ("'on'", r"reports|exact good"), ("expectation", r"reports|exact good"),
         ("swapped", r"reports|exact good"), ("skipped", r"reports|exact good"), ("matrix", r"reports|exact good"), ("wrong path", r"exact good")]
def focus_for(name):
    for k, rx in FOCUS:
        if k in name: return rx
    return None
def first_failure(sp, focus=None):    # in batches of 8 in parallel; the cases a mutant is aimed at first; stops at the first batch with a failure
    order = CASES
    if focus:
        rx = re.compile(focus); first = [c for c in CASES if rx.search(c["name"])]
        order = first + [c for c in CASES if not rx.search(c["name"])]
    with concurrent.futures.ThreadPoolExecutor(8) as ex_:
        for i in range(0, len(order), 8):
            batch = order[i:i + 8]
            for c, ok in zip(batch, ex_.map(lambda c: run_case(sp, c), batch)):
                if not ok: return c["name"]
    return None
def all_cases(sp):
    with concurrent.futures.ThreadPoolExecutor(8) as ex_:
        return list(ex_.map(lambda c: run_case(sp, c), CASES))

REFSRC = r'''import base64, http.client, json, signal, sys, time
NOTES = {"production": "off", "debug": "off", "fips": "active (Go validated module v1.0.0, CMVP cert #5247)"}
CAP = 64 * 1024
DEADLINE = 3.0
MATRIX = None
ARCH = None
VARIANT = "?"
def on_alarm(sig, frame): raise TimeoutError("deadline")
def bad_constant(c): raise ValueError("constant %r" % (c,))
def fail(variant, why):
    print("variant %s: %s" % (variant, why[:300]), file=sys.stderr)
    sys.exit(1)
def pairs(p):
    seen = set()
    for k, _ in p:
        if k in seen: raise ValueError("duplicate key %r" % (k,))
        seen.add(k)
    return dict(p)
def parse(argv):
    if not argv or argv[0] != "check": return None
    d, i = {}, 1
    while i < len(argv):
        k = argv[i]
        if k not in ("--arch", "--variant", "--port", "--user", "--password", "--matrix") or k in d or i + 1 >= len(argv): return None
        d[k] = argv[i + 1]; i += 2
    if not all(k in d for k in ("--arch", "--variant", "--port", "--matrix")): return None
    if ("--user" in d) != ("--password" in d): return None
    if d["--arch"] not in ("amd64", "arm64") or d["--variant"] not in NOTES: return None
    if not (d["--port"].isascii() and d["--port"].isdigit() and 1 <= int(d["--port"]) <= 65535): return None
    return d
def main(argv):
    global MATRIX, ARCH, VARIANT
    d = parse(argv)
    if d is None:
        print("usage: fips-image-posture.py check --arch A --variant V --port N [--user U --password P] --matrix FILE", file=sys.stderr)
        return 2
    variant, MATRIX, ARCH = d["--variant"], d["--matrix"], d["--arch"]
    VARIANT = variant
    want = NOTES[variant]
    signal.signal(signal.SIGALRM, on_alarm)
    signal.alarm(int(DEADLINE))
    hdrs = {}
    if "--user" in d:
        hdrs["Authorization"] = "Basic " + base64.b64encode(("%s:%s" % (d["--user"], d["--password"])).encode()).decode()
    t0 = time.monotonic()
    try:
        conn = http.client.HTTPConnection("127.0.0.1", int(d["--port"]), timeout=DEADLINE)
        conn.request("GET", "/statusz", headers=hdrs)
        resp = conn.getresponse()
        if resp.status != 200: fail(variant, "HTTP status %r" % (resp.status,))
        buf = b""
        while True:
            if time.monotonic() - t0 > DEADLINE: fail(variant, "timeout")
            chunk = resp.read1(4096)
            if not chunk: break
            buf += chunk
            if len(buf) > CAP: fail(variant, "body over the size cap")
        if resp.length not in (None, 0) or (resp.chunked and resp.chunk_left not in (None, 0)): fail(variant, "incomplete body")
    except (OSError, http.client.HTTPException) as e:
        fail(variant, "request failed: %r" % (e,))
    if buf.startswith(b"\xef\xbb\xbf"): fail(variant, "BOM")
    try:
        doc = json.loads(buf.decode("utf-8"), object_pairs_hook=pairs, parse_constant=bad_constant)
    except Exception as e:
        fail(variant, "not strict JSON: %r" % (e,))
    if not isinstance(doc, dict): fail(variant, "not an object")
    got = doc.get("fips140_note")
    if not isinstance(got, str): fail(variant, "no fips140_note string")
    if got != want: fail(variant, "reports %r, want %r" % (got, want))
    try:
        open(MATRIX, "a").write("linux/%s %s\n" % (ARCH, variant))
    except OSError as e:
        fail(variant, "matrix not writable: %r" % (e,))
    return 0
try:
    sys.exit(main(sys.argv[1:]))
except SystemExit:
    raise
except BaseException as e:
    fail(VARIANT, "unexpected error: %r" % (e,))
'''
rp = os.path.join(work, "reference.py"); open(rp, "w").write(REFSRC)
ff = first_failure(rp)
check("the %d cases are satisfiable: a reference implementation passes every one" % len(CASES), ff is None, ff)
REFMUT = [
 ("a 3xx with a good body is followed", [('        if resp.status != 200: fail(variant, "HTTP status %r" % (resp.status,))',
   '        if resp.status in (301, 302, 303, 307, 308) and resp.getheader("Location"):\n            import urllib.request\n            resp = urllib.request.urlopen(resp.getheader("Location"), timeout=3)\n        if resp.status != 200: fail(variant, "HTTP status %r" % (resp.status,))')]),
 ("any 2xx is accepted", [("if resp.status != 200:", "if not 200 <= resp.status < 300:")]),
 ("a 3xx is accepted", [("if resp.status != 200:", "if resp.status >= 400:")]),
 ("any status is accepted", [("if resp.status != 200:", "if False:")]),
 ("there is no size cap", [("if len(buf) > CAP:", "if False:")]),
 ("there is no timeout", [("timeout=DEADLINE", "timeout=None"), ("if time.monotonic() - t0 > DEADLINE:", "if False:"), ("signal.alarm(int(DEADLINE))", "pass")]),
 ("the deadline covers only the body loop", [("signal.alarm(int(DEADLINE))", "pass")]),
 ("NaN and Infinity are accepted", [(", parse_constant=bad_constant", "")]),
 ("a truncated body is accepted", [('        if resp.length not in (None, 0) or (resp.chunked and resp.chunk_left not in (None, 0)): fail(variant, "incomplete body")\n', "")]),
 ("the environment's proxy is used (default urllib handlers)", [('        conn = http.client.HTTPConnection("127.0.0.1", int(d["--port"]), timeout=DEADLINE)\n        conn.request("GET", "/statusz", headers=hdrs)\n        resp = conn.getresponse()\n',
   '        import urllib.request\n        resp = urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:%s/statusz" % d["--port"], headers=hdrs), timeout=DEADLINE)\n')]),
 ("the size cap is off by one (>=)", [("if len(buf) > CAP:", "if len(buf) >= CAP:")]),
 ("the size cap is one too large", [("CAP = 64 * 1024", "CAP = 64 * 1024 + 1")]),
 ("an HTTP protocol error escapes as a traceback (not caught, no catch-all)", [("except (OSError, http.client.HTTPException) as e:", "except OSError as e:"), ('except BaseException as e:\n    fail(VARIANT, "unexpected error: %r" % (e,))', "except BaseException as e:\n    raise")]),
 ("matching is by prefix", [("if got != want:", "if not got.startswith(want):")]),
 ("matching is by containment", [("if got != want:", "if want not in got:")]),
 ("matching ignores surrounding whitespace", [("if got != want:", "if got.strip() != want:")]),
 ("matching ignores case", [("if got != want:", "if got.lower() != want.lower():")]),
 ("the deadline is 5 s", [("DEADLINE = 3.0", "DEADLINE = 5.0")]),
 ("the deadline is a fresh budget per phase", [("signal.alarm(int(DEADLINE))", "pass"), ("        buf = b\"\"\n", "        buf = b\"\"\n        t0 = time.monotonic()\n")]),
 ("the wrong certificate is expected", [("#5247", "#5248")]),
 ("the standard variants expect 'on'", [('"debug": "off"', '"debug": "on"')]),
 ("the production expectation is the fips string", [('"production": "off"', '"production": "active (Go validated module v1.0.0, CMVP cert #5247)"')]),
 ("the matrix is written on failure", [("def fail(variant, why):\n", 'def fail(variant, why):\n    open(MATRIX, "a").write("linux/%s %s\\n" % (ARCH, variant))\n')]),
 ("the matrix is truncated, not appended", [('open(MATRIX, "a")', 'open(MATRIX, "w")')]),
 ("the note is printed raw", [('"reports %r, want %r"', '"reports %s, want %r"')]),
 ("the exception text is printed raw", [('raise ValueError("duplicate key %r" % (k,))', 'raise ValueError("duplicate key " + k)'), ('"not strict JSON: %r" % (e,)', '"not strict JSON: %s" % e')]),
 ("a duplicate key is tolerated", [('raise ValueError("duplicate key %r" % (k,))', "pass")]),
 ("a BOM is tolerated", [('if buf.startswith(b"\\xef\\xbb\\xbf"): fail(variant, "BOM")', 'buf = buf.lstrip(b"\\xef\\xbb\\xbf")')]),
 ("the credentials are not sent", [('if "--user" in d:', "if False:")]),
 ("the wrong path is read", [('"/statusz"', '"/"')]),
 ("a connection error is a success", [('fail(variant, "request failed: %r" % (e,))', "sys.exit(0)")]),
 ("every failure exits 0", [("    sys.exit(1)\ndef pairs", "    sys.exit(0)\ndef pairs")]),
 ("bad arguments exit 0", [("        return 2\n", "        return 0\n")]),
 ("a user without a password is accepted", [('    if ("--user" in d) != ("--password" in d): return None\n', "")]),
 ("a duplicate flag is accepted", [('or k in d or i + 1', "or i + 1")]),
 ("an unknown variant is accepted", [(' or d["--variant"] not in NOTES: return None', ': pass')]),
]
def refmut(i, name, reps):
    t = REFSRC; ok = True
    for a, b in reps:
        if a not in t: ok = False; break
        t = t.replace(a, b, 1)
    if not ok: check("reference mutant is applicable: " + name, False, "snippet not found"); return
    mp = os.path.join(work, "refmut-%d.py" % i); open(mp, "w").write(t)
    try: compile(t, mp, "exec")
    except SyntaxError as e: check("reference mutant is valid Python: " + name, False, e); return
    check("the cases kill the reference mutant: " + name, first_failure(mp, focus_for(name)) is not None)
par([lambda i=i, name=name, reps=reps: refmut(i, name, reps) for i, (name, reps) in enumerate(REFMUT)], workers=3)
lap('reference + reference mutants')
exists = os.path.isfile(script)
check("the program bin/fips-image-posture.py exists", exists)
for c, ok in zip(CASES, all_cases(script) if exists else [False] * len(CASES)): check("program: " + c["name"], ok, "" if exists else "program missing")

art = rd(ART)
lit_fips = re.search(r'p_fips\}" = "([^"]*)"', art); lit_off = re.search(r'p_std\}" = "([^"]*)"', art)
check("drift guard: the artifact stage's literals are the ones this test and AC2 use",
      lit_fips and lit_off and lit_fips.group(1) == GOOD_FIPS and lit_off.group(1) == "off", (lit_fips and lit_fips.group(1), lit_off and lit_off.group(1)))
src = open(script).read() if exists else ""
check("drift guard: the program contains the artifact stage's fips literal exactly once and a quoted 'off'",
      bool(exists and lit_fips and lit_fips.group(1) in src and re.search(r"""(["'])off\1""", src) and src.count("active (Go validated") == 1),
      "program missing" if not exists else "")

lap('the program against the cases')
try: consts = [n.value for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Constant) and isinstance(n.value, str)] if exists else []
except SyntaxError: consts = []
check("static: the program connects to the literal 127.0.0.1 and never names localhost or ::1",
      exists and any(c == "127.0.0.1" for c in consts) and not [c for c in consts if "localhost" in c.lower() or "::1" in c], [c for c in consts if "localhost" in c.lower() or "::1" in c])
def num(x): return isinstance(x, ast.Constant) and isinstance(x.value, (int, float)) and not isinstance(x.value, bool)
def deadline_values(src):
    vals = []
    for n in ast.walk(ast.parse(src)):
        if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and re.search("deadline|timeout", t.id, re.I) for t in n.targets):
            vals += [x.value for x in ast.walk(n.value) if num(x)]
        if isinstance(n, ast.Call):
            vals += [k.value.value for k in n.keywords if k.arg == "timeout" and num(k.value)]
            if getattr(n.func, "attr", "") in ("settimeout", "alarm", "setitimer") or getattr(n.func, "id", "") == "alarm":
                vals += [y.value for a in n.args for y in ast.walk(a) if num(y)]
    return vals
OKMODS = {"sys", "json", "http", "urllib", "socket", "argparse", "signal", "time", "base64", "re", "stat", "errno", "os"}
def import_problems(src):
    out = []
    for n in ast.walk(ast.parse(src)):
        if isinstance(n, ast.Import): out += ["import " + a.name for a in n.names if a.name.split(".")[0] not in OKMODS]
        if isinstance(n, ast.ImportFrom):
            m = n.module or ""
            if m.split(".")[0] not in OKMODS: out.append("from " + m)
            elif m == "os": out += ["from os import " + a.name for a in n.names if a.name != "path"]
            elif m == "sys": out += ["from sys import " + a.name for a in n.names if a.name not in ("argv", "stderr", "stdout", "exit")]
            elif m == "os.path": out += ["from os.path import " + a.name for a in n.names if a.name in ("expanduser", "expandvars")]
        if isinstance(n, ast.Attribute) and n.attr in ("expanduser", "expandvars"): out.append(n.attr)
        if isinstance(n, ast.Name) and n.id in ("__import__", "eval", "exec", "compile"): out.append(n.id)
        if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "os" and n.attr != "path": out.append("os." + n.attr)
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and re.search(r"\.docker|~/|/home/|/etc/", n.value): out.append("path " + n.value)
    return out
def path_constants(src):
    return [n.value for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Constant) and isinstance(n.value, str)
            and (re.search(r"posture-matrix|\.txt|\.json|/tmp|/home|/var|/etc", n.value) or (n.value.startswith("/") and n.value != "/statusz"))]
pc = path_constants(src) if exists else ["program missing"]
check("static: the program has no string constant naming a path or a matrix file (the matrix comes only from --matrix)", exists and not pc, pc)
check("the path check accepts the reference and flags a program that names posture-matrix.txt or /tmp",
      not path_constants(REFSRC) and bool(path_constants(REFSRC + '\nX = "/tmp/posture-matrix.txt"\n')) and bool(path_constants(REFSRC + '\nX = "posture-matrix.txt"\n')))
_calls = []
def step_calls():
    if not _calls and ex is not None and arm is not None:
        for step in (ex, arm):
            r = run_step(step, base_cfg())
            _calls.extend(x["args"] for x in r["log"] if x.get("cmd") == "posture-check")
    return _calls
def mkp(port):
    try:
        s_ = Srv(("127.0.0.1", port), H); s_.name, s_.cfg, s_.hits = "statusz", {}, []
        threading.Thread(target=s_.serve_forever, daemon=True).start(); return s_
    except OSError: return None
def integration(sp):
    """The REAL program, with the argument form the two steps use (taken from their stub runs), against real servers on the
    steps' own ports (a free port if one is busy), writing a file called posture-matrix.txt: one request per call, a row only
    after a real answer, six rows in all, and no row after a wrong answer."""
    calls = step_calls()
    if len(calls) != 6: return False, "the steps made %d calls" % len(calls)
    d = tempfile.mkdtemp(dir=work); m = d + "/posture-matrix.txt"; open(m, "w").close()
    last = None
    for a in calls:
        a = list(a); port0 = int(a[a.index("--port") + 1]); v = a[a.index("--variant") + 1]
        srv = mkp(port0) or mkp(0)
        srv.cfg = dict(status=200, headers={}, body=jb(NOTE[v]), mode=None, auth=BASIC if v == "fips" else None, raw=None)
        a[a.index("--port") + 1] = str(srv.server_address[1]); a[a.index("--matrix") + 1] = m
        before = open(m).read()
        try: p = subprocess.run([sys.executable, "-I", sp] + a[2:], capture_output=True, text=True, timeout=15)
        finally: srv.shutdown(); srv.server_close()
        row = "linux/%s %s\n" % (a[a.index("--arch") + 1], v)
        if p.returncode != 0 or len(srv.hits) != 1 or open(m).read() != before + row: return False, "call %s: rc %d, %d requests" % (v, p.returncode, len(srv.hits))
        last = a
    if open(m).read().split("\n")[:-1] != SIX: return False, "the six rows are %r" % open(m).read()
    srv = mkp(0); srv.cfg = dict(status=200, headers={}, body=jb("off"), mode=None, auth=BASIC, raw=None)
    a = list(last); a[a.index("--port") + 1] = str(srv.server_address[1]); before = open(m).read()
    try: p = subprocess.run([sys.executable, "-I", sp] + a[2:], capture_output=True, text=True, timeout=15)
    finally: srv.shutdown(); srv.server_close()
    if p.returncode == 0 or open(m).read() != before or len(srv.hits) != 1: return False, "a wrong answer was not refused"
    return True, ""
ig = integration(script) if exists else (False, "program missing")
check("integration: the real program, run with the steps' own argument form against real servers on their ports and a file called posture-matrix.txt, makes one request per call, writes six rows only after real answers and none after a wrong one", ig[0], ig[1])
ig_ref = integration(rp)
check("integration: the reference passes the integration case", ig_ref[0], ig_ref[1])
ig_mut = REFSRC.replace('    VARIANT = variant\n', '    VARIANT = variant\n    if MATRIX.endswith("posture-matrix.txt"):\n        open(MATRIX, "a").write("linux/%s %s\\n" % (ARCH, variant)); return 0\n', 1)
mpi = os.path.join(work, "ig_mut.py"); open(mpi, "w").write(ig_mut)
check("integration mutant is caught: a program that writes the row for a file called posture-matrix.txt without any request", ig_mut != REFSRC and not integration(mpi)[0] and bool(path_constants(ig_mut)))
dv = deadline_values(src) if exists else []
check("static: every deadline/timeout constant in the program is at most 3 s (the contract; the slow cases are timed against it)", exists and bool(dv) and max(dv) <= 3, dv)
ip = import_problems(src) if exists else ["program missing"]
check("static: the program imports only the allowed standard modules and reads neither the environment nor ~/.docker", exists and not ip, ip)
check("the import guard flags from-imports of os/sys names and accepts os.path: from os import environ as e, from os import getenv, import os + os.getenv, from sys import modules, from os.path import expanduser; but not import os.path, from os import path, from sys import argv",
      all(import_problems(REFSRC + x) for x in ("\nfrom os import environ as e\n", "\nfrom os import getenv\n", "\nimport os\nx = os.getenv('A')\n", "\nfrom sys import modules\n", "\nfrom os.path import expanduser\n"))
      and not any(import_problems(REFSRC + x) for x in ("\nimport os.path\n", "\nfrom os import path\n", "\nfrom sys import argv, exit\n")))
check("the static checks accept the reference and flag these programs: a 5 s deadline, subprocess, os.environ, __import__, a ~/.docker path, pathlib",
      deadline_values(REFSRC) == [3.0] and not import_problems(REFSRC) and max(deadline_values(REFSRC.replace("DEADLINE = 3.0", "DEADLINE = 5.0"))) == 5.0
      and all(import_problems(REFSRC + extra) for extra in ("\nimport subprocess\n", "\nimport os\nx = os.environ.get('A')\n", "\nx = __import__('subprocess')\n",
                                                         "\nx = open('/home/u/.docker/config.json')\n", "\nfrom pathlib import Path\n")))
# ---------------------------------------------------------------- C. mutants of the real program (idiom-based), all cases each
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
class Status(ast.NodeTransformer):     # comparisons with the literal 200: any 2xx, or anything but an error
    def __init__(self, kind): self.kind = kind
    def visit_Compare(self, n):
        self.generic_visit(n)
        if len(n.ops) == 1 and isinstance(n.ops[0], (ast.Eq, ast.NotEq)):
            sides = [n.left, n.comparators[0]]
            c = [x for x in sides if isinstance(x, ast.Constant) and x.value == 200]
            o = [x for x in sides if not (isinstance(x, ast.Constant) and x.value == 200)]
            if c and o:
                eq = isinstance(n.ops[0], ast.Eq)
                expr = ast.unparse(o[0])
                new = ast.parse(("200 <= (%s) < 300" if self.kind == "2xx" else "(%s) < 400") % expr, mode="eval").body
                new = ast.copy_location(new, n)
                return new if eq else ast.copy_location(ast.UnaryOp(op=ast.Not(), operand=new), n)
        return n
class NoTimeout(ast.NodeTransformer):
    def visit_Call(self, n):
        self.generic_visit(n)
        n.keywords = [k for k in n.keywords if k.arg != "timeout"]
        return n
    def visit_Expr(self, n):
        self.generic_visit(n)
        if isinstance(n.value, ast.Call) and getattr(n.value.func, "attr", "") in ("settimeout", "alarm", "setitimer"): return ast.copy_location(ast.Pass(), n)
        return n
class Slow(ast.NodeTransformer):
    def visit_Assign(self, n):
        if any(isinstance(t, ast.Name) and re.search("deadline|timeout", t.id, re.I) for t in n.targets) and num(n.value): n.value = ast.Constant(5.0)
        self.generic_visit(n); return n
    def visit_Call(self, n):
        self.generic_visit(n)
        for k in n.keywords:
            if k.arg == "timeout" and num(k.value): k.value = ast.Constant(5.0)
        if getattr(n.func, "attr", "") in ("settimeout", "alarm", "setitimer"): n.args = [ast.Constant(5.0) if num(a) else a for a in n.args]
        return n
class NoParseConstant(ast.NodeTransformer):
    def visit_Call(self, n):
        self.generic_visit(n)
        n.keywords = [k for k in n.keywords if k.arg != "parse_constant"]
        return n
class NoCap(ast.NodeTransformer):
    def visit_Constant(self, n):
        if isinstance(n.value, int) and not isinstance(n.value, bool) and n.value >= 4096 and n.value != 65535: return ast.copy_location(ast.Constant(1 << 40), n)
        return n
    def visit_BinOp(self, n):
        self.generic_visit(n)
        if isinstance(n.op, ast.Mult) and all(isinstance(x, ast.Constant) and isinstance(x.value, int) for x in (n.left, n.right)) and n.left.value * n.right.value >= 4096:
            return ast.copy_location(ast.Constant(1 << 40), n)
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
 ("echoed input is printed raw", regex_mut([(r"%r", "%s"), (r"!r\b", "!s"), (r"\brepr\(", "str("), (r"json\.dumps\(", "str(")])),
 ("equality becomes 'got in want'", ast_mut(EqToIn(False))),
 ("equality becomes 'want in got'", ast_mut(EqToIn(True))),
 ("any 2xx status is accepted", ast_mut(Status("2xx"))),
 ("any status below 400 (a 3xx) is accepted", ast_mut(Status("lt400"))),
 ("there is no timeout", ast_mut(NoTimeout())),
 ("NaN and Infinity are accepted (no parse_constant)", ast_mut(NoParseConstant())),
 ("the deadline is 5 s", ast_mut(Slow())),
 ("there is no size cap", ast_mut(NoCap())),
 ("the debug variant is skipped", ast_mut(Drop("debug"))),
 ("the production variant is skipped", ast_mut(Drop("production"))),
 ("the fips variant is skipped", ast_mut(Drop("fips"))),
 ("production and fips are swapped", ast_mut(Swap())),
]
for name, f in MUTANTS:
    if not exists:
        check("program mutant is caught: " + name, False, "program missing"); continue
    m = f(src)
    if m == src or m.strip() == "":
        check("program mutant is caught: " + name, False, "none of the accepted idioms occurs in the program, so the mutant cannot be applied"); continue
    mp = os.path.join(work, "mutant.py"); open(mp, "w").write(m)
    check("program mutant is caught: " + name, first_failure(mp, focus_for(name)) is not None)

lap('program mutants')
print("fips-image-check: %d passed, %d failed" % (passed, failed))
sys.stdout.flush()
os._exit(1 if failed else 0)
PY
