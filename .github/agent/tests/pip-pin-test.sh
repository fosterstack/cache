#!/usr/bin/env bash
# proves: REQ-SUP-001-AC13
# The pip that CI runs is pinned (issue #215; owner-ratified rule, advisor handoffs 0281/0282). In every workflow job (and every local
# composite action) that runs `pip install`, an EARLIER step or line installs pip itself at one pinned version from the hash-checked
# requirement file pip-requirements.txt (in this directory's parent), with --require-hashes and --only-binary=:all:, before any other
# pip install of the job, and logs `python3 -m pip --version`. A virtual environment has its OWN pip (the interpreter's bundled one), so the same
# holds PER ENVIRONMENT: every install through a venv (<venv>/bin/pip, <venv>/bin/python -m pip, or pip after `source <venv>/bin/activate`) needs the
# pin installed INTO THAT VENV first (<venv>/bin/python -m pip install ... -r the file, then <venv>/bin/python -m pip --version).
# The requirement file holds exactly one requirement, pip==<version>, with at least one --hash=sha256:. Dependabot watches that file's
# directory under the 7-day cooldown. The required allowlist job in ci.yml runs this test.
#
# Which pin steps pull-request CI actually exercises: ci.yml `coverage` and `allowlist` (every pull request and push to main). The auditor.yml
# `audit` and `panel-probe` jobs and the dependabot-reviewer.yml `review` job run only on schedule / workflow_dispatch, so their pin steps are proven
# here by reading the workflow, and live only on the next scheduled run.
#
# Detection reads each run script as shell tokens (backslash continuations joined, heredoc bodies skipped, ; && || | split): a command is a pip install
# when its program is pip, pip3, pip3.12 ... or python[3[.N]] -m pip, whatever options come before `install`. pipx install, python -m ensurepip and
# uv pip install / uv tool install also need a pin first, unless the job is named in ALLOW_OTHER below with a reason (none today).
# Boundaries (documented, not tested): code that shells out to pip from inside another program (python -c "subprocess..."), third-party actions that
# install packages inside themselves, and the inside of an external reusable workflow. A job-level `uses:` is therefore required to be either a
# local workflow (which is read here like any other) or a digest-pinned external one, and a job that has `uses:` has no steps of its own (case 7).
# Not testable offline: that the pinned version has been public 7 days (the pin age check, REQ-SUP-001-AC2/AC3, measures that on the PR that moves it).
# Everything is read from the PARSED files (vendored PyYAML); the real tree must pass and every mutation (made through the parsed document,
# or on the requirement text) must be rejected FOR THE REASON NAMED. PIPPIN_ROOT points the judge at another tree (the mutant builder's reference).
set -euo pipefail
export PIPPIN_ROOT=${PIPPIN_ROOT:-$(cd "$(dirname "$0")/../../.." && pwd)}
export PIPPIN_LIB=$(cd "$(dirname "$0")/.." && pwd)/fixtures/testlib
python3 - <<'PY'
import copy, glob, os, re, shlex, sys
sys.path.insert(0, os.environ["PIPPIN_LIB"])
import pyyaml as yaml   # the vendored reader, never whatever PyYAML the host has

root = os.environ["PIPPIN_ROOT"]
REQ = ".github/agent/pip-requirements.txt"
GOLDEN = "26.2.1"
PIN_FLAGS_REQUIRED = {"--require-hashes", "--only-binary=:all:"}
PIN_FLAGS_ALLOWED = PIN_FLAGS_REQUIRED | {"--quiet", "--break-system-packages"}
ALLOW_OTHER = {}   # "<file>:<job>" -> reason a pipx / ensurepip / uv install may run without a pin first (none today)

def rd(p):
    try:
        return open(os.path.join(root, p)).read()
    except OSError:
        return None

def load_tree():
    docs = {}
    for p in sorted(glob.glob(os.path.join(root, ".github/workflows/*.y*ml")) + glob.glob(os.path.join(root, ".github/actions/**/action.y*ml"), recursive=True)):
        docs[os.path.relpath(p, root)] = yaml.safe_load(open(p)) or {}
    dep = rd(".github/dependabot.yml")
    return {"docs": docs, "req": rd(REQ), "dep": yaml.safe_load(dep) if dep else None}

# ---------------------------------------------------------------- reading a run script
def norm(s):
    return re.sub(r"\$\{(\w+)\}", r"$\1", s)

def logical_lines(run):
    """backslash continuations joined, comments and heredoc bodies dropped"""
    out, cur, skip = [], "", None
    for raw in str(run).splitlines():
        if skip is not None:
            if raw.strip() == skip:
                skip = None
            continue
        s = raw.rstrip()
        if not cur and s.strip().startswith("#"):
            continue
        if s.endswith("\\"):
            cur += s[:-1] + " "; continue
        line = (cur + s).strip(); cur = ""
        if line:
            out.append(line)
            m = re.search(r"<<-?\s*['\"]?([A-Za-z_]\w*)['\"]?", line)
            if m:
                skip = m.group(1)
    if cur.strip():
        out.append(cur.strip())
    return out

SEP = {";", "&&", "||", "|", "&", "(", ")"}
def commands(line):
    try:
        lx = shlex.shlex(line, posix=True, punctuation_chars=True); lx.whitespace_split = True; lx.commenters = ""
        toks = list(lx)
    except ValueError:
        toks = line.split()
    cmds, cur, i = [], [], 0
    while i < len(toks):
        t = toks[i]
        if t in SEP:
            if cur: cmds.append(cur)
            cur = []
        elif t[:1] in "<>" and set(t) <= set("<>&"):
            i += 1   # a redirection and its target
        else:
            cur.append(t)
        i += 1
    if cur: cmds.append(cur)
    return cmds

def env_of_prog(p, active):
    d = os.path.dirname(p)
    if d.endswith("/bin"):
        return norm(d[:-4])
    return active or "system"

def classify(t, active):
    """-> (kind, env, extra) with kind in install | other | version | venv | activate, or None"""
    while t and (re.match(r"^[A-Za-z_]\w*=", t[0]) or t[0] in ("sudo", "command", "exec", "time", "nohup", "env") or (t[0].startswith("-") and len(t) > 1)):
        t = t[1:]   # env assignments, wrappers and their options (sudo -H, env -i)
    if not t:
        return None
    p, rest = norm(t[0]), t[1:]
    base = os.path.basename(p)
    if base in ("source", ".") and rest and norm(rest[0]).endswith("/bin/activate"):
        return ("activate", norm(rest[0])[: -len("/bin/activate")], None)
    if re.fullmatch(r"pip(\d+(\.\d+)*)?", base):
        env = env_of_prog(p, active)
        if "install" in rest: return ("install", env, None)
        return None
    if re.fullmatch(r"python(\d+(\.\d+)*)?", base):
        env = env_of_prog(p, active)
        lead = []
        for x in rest:
            if x.startswith("-") and x != "-m": lead.append(x)
            else: break
        r2 = rest[len(lead):]
        if len(r2) >= 2 and r2[0] == "-m":
            mod, after = r2[1], r2[2:]
            if mod == "pip":
                if "install" in after: return ("install", env, None)
                if "--version" in after: return ("version", env, None)
                return None
            if mod == "ensurepip": return ("other", env, "ensurepip")
            if mod == "venv" and after: return ("venv", norm(after[-1]), None)
        return None
    if base == "pipx" and "install" in rest:
        return ("other", active or "system", "pipx")
    if base == "uv" and (("pip" in rest and "install" in rest) or ("tool" in rest and "install" in rest)):
        return ("other", active or "system", "uv")
    return None

def events(steps):
    ev = []
    for si, st in enumerate(steps):
        active = None
        for li, line in enumerate(logical_lines((st or {}).get("run", ""))):
            for cmd in commands(line):
                c = classify(cmd, active)
                if not c: continue
                if c[0] == "activate": active = c[1]; continue
                ev.append({"step": si, "line": li, "kind": c[0], "env": c[1], "tok": [norm(x) for x in cmd], "text": line, "what": c[2]})
    return ev

def prog_ok(tok0, env):
    p = norm(tok0)
    return p == "python3" if env == "system" else p in (f"{env}/bin/python", f"{env}/bin/python3")

def is_pin(e):
    t = e["tok"]
    while t and re.match(r"^[A-Za-z_]\w*=", t[0]): t = t[1:]
    if e["kind"] != "install" or len(t) < 6 or not prog_ok(t[0], e["env"]) or t[1:4] != ["-m", "pip", "install"] or t[-2:] != ["-r", REQ]:
        return False
    flags = t[4:-2]
    return len(set(flags)) == len(flags) and PIN_FLAGS_REQUIRED <= set(flags) <= PIN_FLAGS_ALLOWED

def is_log(e):
    t = e["tok"]
    return e["kind"] == "version" and len(t) == 4 and prog_ok(t[0], e["env"]) and t[1:] == ["-m", "pip", "--version"]

def sequences(docs):
    for f, d in docs.items():
        if not isinstance(d, dict):
            continue
        for jn, j in (d.get("jobs") or {}).items():
            yield f"{f}:{jn}", (j or {}).get("steps") or []
        runs = d.get("runs")
        if isinstance(runs, dict) and runs.get("using") == "composite":
            yield f"{f}:(composite)", runs.get("steps") or []

def judge(t):
    r = []   # (case, message)
    n_pip = 0
    for label, steps in sequences(t["docs"]):
        ev = events(steps)
        gate = [e for e in ev if e["kind"] in ("install", "other")]
        if not gate:
            continue
        n_pip += 1
        for env in list(dict.fromkeys(e["env"] for e in gate)):
            mine = [e for e in gate if e["env"] == env]
            first = mine[0]
            where = "the system python" if env == "system" else f"the venv {env}"
            if first["kind"] == "other" and label in ALLOW_OTHER:
                continue
            if not is_pin(first):
                later = any(is_pin(e) for e in mine[1:])
                r.append(("C1", f"{label}: {where}: " + ("another install (" + (first["what"] or "pip install") + f", step {first['step'] + 1}) comes before the pin" if later else "no earlier step installs the pinned pip (-r " + REQ + ", --require-hashes, --only-binary=:all:) into it")))
                if not later:
                    r.append(("C2", f"{label}: {where}: no pin step, so nothing logs the pip version"))
                continue
            pst = steps[first["step"]]
            if str(pst.get("continue-on-error", "false")).lower() not in ("false", ""):
                r.append(("C1", f"{label}: {where}: the pin step has continue-on-error"))
            if pst.get("if") is not None:
                for e in mine[1:]:
                    if (steps[e["step"]] or {}).get("if") != pst.get("if"):
                        r.append(("C1", f"{label}: {where}: the pin step has an `if` that does not cover the install in step {e['step'] + 1}")); break
            if not any(is_log(e) and e["env"] == env and (e["step"], e["line"]) > (first["step"], first["line"]) and e["step"] == first["step"] for e in ev):
                r.append(("C2", f"{label}: {where}: the pin step does not log `python -m pip --version` of that python after installing"))
    if n_pip == 0:
        r.append(("C1", "no job runs pip install (the reader found nothing: the test would pass vacuously)"))
    # case 3: the requirement file
    req = t["req"]
    if req is None:
        r.append(("C3", f"{REQ} does not exist"))
    else:
        logical, cur = [], ""
        for ln in req.splitlines():
            s = ln.split(" #")[0].strip() if not ln.strip().startswith("#") else ""
            if not s:
                continue
            if s.endswith("\\"):
                cur += s[:-1] + " "; continue
            logical.append((cur + s).strip()); cur = ""
        if cur.strip():
            logical.append(cur.strip())
        if len(logical) != 1:
            r.append(("C3", f"{REQ} holds {len(logical)} requirement lines, not exactly one"))
        else:
            m = re.fullmatch(r"pip==(\d+(?:\.\d+){1,2})((?:\s+--hash=sha256:[0-9a-f]{64})+)", logical[0])
            if not m:
                r.append(("C3", f"{REQ}'s requirement is not `pip==<release version>` with at least one --hash=sha256:<64 hex> (no extras, markers, pre-release, other options): {logical[0][:80]}"))
            elif m.group(1) != GOLDEN:
                r.append(("C3", f"{REQ} pins pip=={m.group(1)}, the golden is {GOLDEN} (change the golden here when moving it on purpose)"))
    # case 4: Dependabot
    dep = t["dep"]
    ups = (dep or {}).get("updates") or []
    pips = [u for u in ups if u.get("package-ecosystem") == "pip" and u.get("directory") == "/.github/agent"]
    acts = [u for u in ups if u.get("package-ecosystem") == "github-actions"]
    if not pips:
        r.append(("C4", "dependabot.yml has no pip entry for directory /.github/agent"))
    else:
        want = acts[0].get("cooldown") if acts else None
        for u in pips:
            if u.get("cooldown") != want or u.get("cooldown") != {"default-days": 7}:
                r.append(("C4", f"the pip entry's cooldown is {u.get('cooldown')}, not the neighbours' {{default-days: 7}}"))
    # case 6: the CI wiring
    ci = t["docs"].get(".github/workflows/ci.yml") or {}
    job = (ci.get("jobs") or {}).get("allowlist")
    me = [s for s in ((job or {}).get("steps") or []) if str((s or {}).get("run", "")).strip() == "bash .github/agent/tests/pip-pin-test.sh"]
    if len(me) != 1:
        r.append(("C6", f"ci.yml's required allowlist job runs this test {len(me)} times, not once"))
    elif any(k in me[0] for k in ("if", "continue-on-error", "shell", "working-directory", "env")):
        r.append(("C6", "the step that runs this test has if / continue-on-error / shell / working-directory / env"))
    elif (job or {}).get("if") or str((job or {}).get("continue-on-error", "false")).lower() != "false":
        r.append(("C6", "the allowlist job has an if or continue-on-error"))
    # case 7: job-level `uses:` is a local workflow (read here) or a digest-pinned external one, and the job has no steps of its own
    for f, d in t["docs"].items():
        for jn, j in ((d or {}).get("jobs") or {}).items():
            u = (j or {}).get("uses")
            if u is None:
                continue
            u = str(u)
            if not (re.fullmatch(r"\./\.github/workflows/[A-Za-z0-9._-]+\.ya?ml", u) or re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", u)):
                r.append(("C7", f"{f}:{jn}: job-level uses `{u}` is neither a local workflow nor a full-commit-digest reference"))
            if "steps" in j or "run" in j:
                r.append(("C7", f"{f}:{jn}: a job with `uses:` also has its own steps"))
            elif re.fullmatch(r"\./\.github/workflows/[A-Za-z0-9._-]+\.ya?ml", u) and not os.path.exists(os.path.join(root, u[2:])) and u[2:] not in t["docs"]:
                r.append(("C7", f"{f}:{jn}: the local workflow `{u}` called here does not exist, so its pip installs could not be read"))
    return r

fails = 0
def report(ok, name, why=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else "  -- " + why))
    if not ok:
        fails += 1

# ---- the real tree, one line per case
tree = load_tree()
res = judge(tree)
for case, title in (("C1", "case 1: every pip-installing job pins pip first, in the system python and in every venv it uses (hash-checked, binary-only)"),
                    ("C2", "case 2: the pin step logs `python -m pip --version` of the pinned python"),
                    ("C3", "case 3: the requirement file is exactly one hash-pinned release pip==" + GOLDEN),
                    ("C4", "case 4: Dependabot watches the pin file's directory under the 7-day cooldown"),
                    ("C6", "case 6: ci.yml's required allowlist job runs this test"),
                    ("C7", "case 7: a job-level `uses:` is a local or digest-pinned reusable workflow and the job has no steps of its own")):
    bad = [m for c, m in res if c == case]
    report(not bad, title, "; ".join(bad[:4]))

# ---------------------------------------------------------------- mutants
def pin_sites(t):
    """(label, env, step_index, line_text, steps) for the pin of every environment that installs"""
    out = []
    for label, steps in sequences(t["docs"]):
        ev = events(steps)
        gate = [e for e in ev if e["kind"] in ("install", "other")]
        for env in dict.fromkeys(e["env"] for e in gate):
            first = [e for e in gate if e["env"] == env][0]
            if is_pin(first):
                log = next((e for e in ev if is_log(e) and e["env"] == env and e["step"] == first["step"]), None)
                out.append((label, env, first["step"], first["text"], log["text"] if log else None, steps))
    return out

def site_key(s): return (s[0], s[1])
SITE_KEYS = [site_key(s) for s in pin_sites(tree)]
EXPECT_SITES = 6   # ci coverage + allowlist (system, venv), auditor audit + panel-probe, dependabot-reviewer review
def prog_for(env): return "python3" if env == "system" else f"{env}/bin/python"

def edit_run(st, fn):
    st["run"] = "\n".join(fn(str(st["run"]).splitlines()))

def site_mut(key, kind):
    def fn(t):
        site = next((s for s in pin_sites(t) if site_key(s) == key), None)
        if not site:
            return False
        label, env, si, text, log, steps = site
        st = steps[si]
        idx = next((i for i, l in enumerate(str(st["run"]).splitlines()) if l.strip() == text), None)
        if idx is None:
            return False
        if kind == "missing":
            edit_run(st, lambda L: L[:idx] + L[idx + 1:])
        elif kind == "after":
            edit_run(st, lambda L: L[:idx] + L[idx + 1:])
            steps.append({"name": "late pin", "run": text + ("\n" + log if log else "")})
        elif kind == "other-env":
            other = "$RUNNER_TEMP/other-venv"
            new = text.replace(prog_for(env), prog_for(other), 1) if env == "system" else text.replace(env, other)
            edit_run(st, lambda L: L[:idx] + [new] + L[idx + 1:])
        elif kind in ("no-require-hashes", "no-only-binary", "other-file", "spelled-apart"):
            a, b = {"no-require-hashes": ("--require-hashes ", ""), "no-only-binary": ("--only-binary=:all: ", ""),
                    "other-file": ("pip-requirements.txt", "test-requirements.txt"), "spelled-apart": ("--only-binary=:all:", "--only-binary :all:")}[kind]
            if a not in text: return False
            edit_run(st, lambda L: L[:idx] + [text.replace(a, b, 1)] + L[idx + 1:])
        elif kind == "no-version-log":
            if not log: return False
            edit_run(st, lambda L: [l for l in L if l.strip() != log])
        elif kind == "version-log-before":
            if not log: return False
            edit_run(st, lambda L: [log] + [l for l in L if l.strip() != log])
        elif kind == "continue-on-error":
            st["continue-on-error"] = True
        elif kind == "install-before-pin-same-step":
            edit_run(st, lambda L: L[:idx] + [prog_for(env) + " -m pip install wheel"] + L[idx:])
        elif kind == "install-step-before-pin":
            cmd = "pip3 install requests" if env == "system" else f"{env}/bin/pip install requests"
            steps.insert(si, {"name": "early", "run": cmd})
        else:
            raise SystemExit("bad kind " + kind)
        return True
    return fn

mutants = []   # (name, expected case, fn(tree) -> applied?)
KINDS = (("missing", "C1"), ("after", "C1"), ("other-env", "C1"), ("no-require-hashes", "C1"), ("no-only-binary", "C1"), ("spelled-apart", "C1"),
         ("other-file", "C1"), ("no-version-log", "C2"), ("version-log-before", "C2"), ("continue-on-error", "C1"),
         ("install-before-pin-same-step", "C1"), ("install-step-before-pin", "C1"))
for key in SITE_KEYS:
    for kind, case in KINDS:
        mutants.append((f"{kind} at {key[0]} [{'system python' if key[1] == 'system' else 'venv ' + key[1]}]", case, site_mut(key, kind)))
if len(SITE_KEYS) != EXPECT_SITES:
    mutants.append((f"the tree has {len(SITE_KEYS)} pinned environments, expected {EXPECT_SITES}", "C1", lambda t: False))

# every spelling, in a new job with no pin at all, and placed before the first system pin
SPELLINGS = [
    "pip install requests", "pip3 install requests", "pip3.12 install requests", "python -m pip install requests", "python3.12 -m pip install requests",
    "pip --retries 3 install requests", "pip --index-url https://example.invalid/simple install requests",
    "python3 -m pip --index-url https://example.invalid/simple install requests", "python3 -m pip -q --no-cache-dir install requests",
    "python3 -m pip \\\n  install requests", "VAR=1 pip install requests", "true && pip install requests", "sudo -H pip3 install requests",
    "pipx install requests", "python3 -m ensurepip", "uv pip install requests", "uv tool install requests",
]
def add_job(t, name, steps):
    t["docs"][".github/workflows/ci.yml"]["jobs"][name] = {"runs-on": "ubuntu-latest", "steps": steps}
for sp in SPELLINGS:
    def newjob(t, sp=sp):
        add_job(t, "extra-pip", [{"run": sp}]); return True
    mutants.append((f"a job with `{sp.splitlines()[0]}` and no pin", "C1", newjob))
    def before(t, sp=sp):
        s = next((x for x in pin_sites(t) if x[1] == "system"), None)
        if not s: return False
        s[5].insert(s[2], {"run": sp}); return True
    mutants.append((f"`{sp.splitlines()[0]}` placed before the first pin", "C1", before))
VENV_SPELLINGS = [
    'python3 -m venv "$RUNNER_TEMP/v"\n"$RUNNER_TEMP/v/bin/pip" install requests',
    'python3 -m venv "$RUNNER_TEMP/v"\n"$RUNNER_TEMP/v/bin/python" -m pip install requests',
    'python3 -m venv "$RUNNER_TEMP/v"\nsource "$RUNNER_TEMP/v/bin/activate"\npip install requests',
    'python3 -m venv "$RUNNER_TEMP/v"\n. $RUNNER_TEMP/v/bin/activate\npip3 install requests',
    'python3 -m venv "${RUNNER_TEMP}/v"\n"$RUNNER_TEMP/v/bin/pip" --retries 2 install requests',
]
SYSPIN = lambda t: next(s for s in pin_sites(t) if s[1] == "system")
for sp in VENV_SPELLINGS:
    def vjob(t, sp=sp):
        s = next((x for x in pin_sites(t) if x[1] == "system"), None)
        if not s: return False
        steps = [{"run": s[3] + (("\n" + s[4]) if s[4] else "")}, {"run": sp}]   # the SYSTEM pin is there; the venv still has none
        add_job(t, "extra-venv", steps); return True
    mutants.append((f"a venv install with only the system pin: `{sp.splitlines()[-1]}`", "C1", vjob))

def new_composite(t):
    t["docs"][".github/actions/x/action.yml"] = {"runs": {"using": "composite", "steps": [{"run": "pip install requests", "shell": "bash"}]}}
    return True
mutants.append(("a composite action that pip-installs without a pin step", "C1", new_composite))

def req_edit(fn):
    def m(t):
        if t["req"] is None:
            return False
        t["req"] = fn(t["req"]); return True
    return m
H = "--hash=sha256:" + "a" * 64
for name, case, fn in (
    ("version drift in the requirement file", "C3", lambda s: s.replace("pip==" + GOLDEN, "pip==26.2.0")),
    ("a pre-release pip", "C3", lambda s: s.replace("pip==" + GOLDEN, "pip==26.3rc1")),
    ("pip not pinned with ==", "C3", lambda s: s.replace("pip==", "pip>=")),
    ("the hash missing", "C3", lambda s: re.sub(r"\s*--hash=sha256:[0-9a-f]{64}", "", s)),
    ("a short hash", "C3", lambda s: re.sub(r"(--hash=sha256:[0-9a-f]{63})[0-9a-f]", r"\1", s)),
    ("a non-hex hash", "C3", lambda s: re.sub(r"(--hash=sha256:)[0-9a-f]{64}", r"\1" + "z" * 64, s)),
    ("a second requirement", "C3", lambda s: s.rstrip("\n") + "\nsetuptools==80.0.0 " + H + "\n"),
    ("a second requirement on a continuation line", "C3", lambda s: s.rstrip("\n") + " \\\n  wheel==0.45.0 " + H + "\n"),
    ("an extra option line", "C3", lambda s: "--index-url https://example.invalid/simple\n" + s),
    ("an environment marker", "C3", lambda s: s.replace(" --hash", " ; python_version >= '3.9' --hash", 1)),
    ("extras", "C3", lambda s: s.replace("pip==", "pip[x]==")),
    ("an empty file", "C3", lambda s: "# nothing\n"),
):
    mutants.append((name, case, req_edit(fn)))

def dep_pip(t): return [u for u in t["dep"]["updates"] if u.get("package-ecosystem") == "pip"]
def dep_missing(t):
    t["dep"]["updates"] = [u for u in t["dep"]["updates"] if u.get("package-ecosystem") != "pip"]; return True
def dep_nocool(t):
    for u in dep_pip(t): u.pop("cooldown", None)
    return True
def dep_cool3(t):
    for u in dep_pip(t): u["cooldown"] = {"default-days": 3}
    return True
def dep_dir(t):
    for u in dep_pip(t): u["directory"] = "/"
    return True
mutants += [("the Dependabot pip entry missing", "C4", dep_missing), ("the Dependabot pip entry without cooldown", "C4", dep_nocool),
            ("the Dependabot pip cooldown shortened to 3 days", "C4", dep_cool3), ("the Dependabot pip entry on directory /", "C4", dep_dir)]

def ci_steps(t): return t["docs"][".github/workflows/ci.yml"]["jobs"]["allowlist"]["steps"]
def ci_unwire(t):
    s = ci_steps(t); n = len(s)
    s[:] = [x for x in s if "pip-pin-test.sh" not in str(x.get("run", ""))]
    return len(s) < n
def ci_set(k, v):
    def f(t):
        for x in ci_steps(t):
            if "pip-pin-test.sh" in str(x.get("run", "")): x[k] = v; return True
        return False
    return f
mutants += [("ci.yml's allowlist job no longer runs this test", "C6", ci_unwire), ("the step is conditional", "C6", ci_set("if", "false")),
            ("the step is continue-on-error", "C6", ci_set("continue-on-error", True))]

def jobs_with_uses(t):
    return [(f, jn, j) for f, d in t["docs"].items() for jn, j in ((d or {}).get("jobs") or {}).items() if isinstance(j, dict) and "uses" in j]
def uses_edit(fn):
    def m(t):
        ju = jobs_with_uses(t)
        if not ju: return False
        fn(ju[0][2]); return True
    return m
mutants += [
    ("a job-level uses on a moving tag", "C7", uses_edit(lambda j: j.__setitem__("uses", "someorg/somerepo/.github/workflows/w.yml@v1"))),
    ("a job-level uses on a short digest", "C7", uses_edit(lambda j: j.__setitem__("uses", "someorg/somerepo/.github/workflows/w.yml@abc1234"))),
    ("a job-level uses that also has steps", "C7", uses_edit(lambda j: j.__setitem__("steps", [{"run": "echo hi"}]))),
    ("a job-level uses of a local workflow that does not exist", "C7", uses_edit(lambda j: j.__setitem__("uses", "./.github/workflows/not-there.yml"))),
]

killed = 0
for name, case, fn in mutants:
    m = copy.deepcopy(tree)
    try:
        applied = fn(m)
    except Exception as e:
        applied, name = False, name + f" (mutation error {type(e).__name__})"
    if not applied:
        report(False, "mutant: " + name, "the mutation did not apply (the tree is not in the fixed shape)")
        continue
    got = {c for c, _ in judge(m)}
    ok = case in got
    killed += ok
    report(ok, "mutant: " + name + f" rejected by {case}", f"not rejected for {case} (got {sorted(got)})")

# ---- positive controls: a correctly pinned job may then use every spelling, in the system python and in a venv, without a finding
ctl_ok = True
if SITE_KEYS:
    m = copy.deepcopy(tree)
    s = next((x for x in pin_sites(m) if x[1] == "system"), None)
    if s:
        pin = {"run": s[3] + (("\n" + s[4]) if s[4] else "")}
        vpin = 'python3 -m venv "$RUNNER_TEMP/v"\n"$RUNNER_TEMP/v/bin/python" -m pip install --quiet --require-hashes --only-binary=:all: -r ' + REQ + '\n"$RUNNER_TEMP/v/bin/python" -m pip --version'
        add_job(m, "ctl-system", [pin] + [{"run": sp} for sp in SPELLINGS])
        add_job(m, "ctl-venv", [pin, {"run": vpin}, {"run": '"$RUNNER_TEMP/v/bin/pip" --retries 2 install requests\nsource $RUNNER_TEMP/v/bin/activate\npip install requests'}])
        bad = [x for x in judge(m) if x[0] in ("C1", "C2") and ("ctl-" in x[1])]
        report(not bad, "control: correctly pinned jobs (every spelling, a venv with its own pin) are accepted", "; ".join(b for _, b in bad[:3]))
    else:
        report(False, "control: correctly pinned jobs are accepted", "no system pin to copy")
else:
    report(False, "control: correctly pinned jobs are accepted", "no pin sites")
print(f"{len(mutants)} mutants, {killed} killed; {fails} failure(s)")
sys.exit(1 if fails else 0)
PY
