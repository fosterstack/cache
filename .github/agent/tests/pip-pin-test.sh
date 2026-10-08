#!/usr/bin/env bash
# proves: REQ-SUP-001-AC13
# The pip that CI runs is pinned (issue #215; owner-ratified rule, advisor handoffs 0281/0282). In every workflow job (and every local
# composite action) that runs `pip install`, an EARLIER step installs pip itself at one pinned version from the hash-checked
# requirement file pip-requirements.txt (in this directory's parent), with --require-hashes and --only-binary=:all:, before any other
# pip install of the job, and logs `python3 -m pip --version`. The requirement file holds exactly one requirement, pip==<version>, with at least one
# --hash=sha256:. Dependabot watches that file's directory under the 7-day cooldown. The required allowlist job in ci.yml runs this test.
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

PIPINST = re.compile(r"""(?:^|[\s;&|(`'"])(?:\S*/)?(?:python3?\s+-m\s+)?pip3?["']?\s+(?:-\S+\s+)*install\b""")

def pip_lines(run):
    out = []
    for i, ln in enumerate(str(run).splitlines()):
        s = ln.strip()
        if s.startswith("#"):
            continue
        if PIPINST.search(s):
            out.append((i, s))
    return out

def is_pin_cmd(line):
    try:
        t = shlex.split(line)
    except ValueError:
        return False
    if t[:4] != ["python3", "-m", "pip", "install"] or len(t) < 6 or t[-2:] != ["-r", REQ]:
        return False
    flags = set(t[4:-2])
    return len(flags) == len(t[4:-2]) and PIN_FLAGS_REQUIRED <= flags <= PIN_FLAGS_ALLOWED

def is_version_log(line):
    try:
        return shlex.split(line) == ["python3", "-m", "pip", "--version"]
    except ValueError:
        return False

def sequences(docs):
    """every (label, steps) where steps can run pip: workflow jobs and local composite actions"""
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
    # case 1 and 2: the pin step, before every other pip install, and the version log
    n_pip_jobs = 0
    for label, steps in sequences(t["docs"]):
        first = None
        for i, st in enumerate(steps):
            if pip_lines((st or {}).get("run", "")):
                first = i; break
        if first is None:
            continue
        n_pip_jobs += 1
        pin_idx = None
        for i, st in enumerate(steps):
            lines = pip_lines((st or {}).get("run", ""))
            if any(is_pin_cmd(l) for _, l in lines):
                pin_idx = i; break
        if pin_idx is None:
            r.append(("C1", f"{label} runs pip install but no step installs the pinned pip (-r {REQ}, --require-hashes, --only-binary=:all:)"))
            r.append(("C2", f"{label} has no pin step, so nothing logs the pip version")); continue
        if pin_idx > first:
            r.append(("C1", f"{label}: another pip install (step {first + 1}) comes before the pin step (step {pin_idx + 1})"))
        pst = steps[pin_idx]
        lines = pip_lines(pst["run"])
        if not is_pin_cmd(lines[0][1]):
            r.append(("C1", f"{label}: the pin step runs another pip install before the pin command"))
        if str(pst.get("continue-on-error", "false")).lower() not in ("false", ""):
            r.append(("C1", f"{label}: the pin step has continue-on-error"))
        if pst.get("if") is not None:
            for i, st in enumerate(steps):
                if i != pin_idx and pip_lines((st or {}).get("run", "")) and (st or {}).get("if") != pst.get("if"):
                    r.append(("C1", f"{label}: the pin step has an `if` that does not cover the pip install in step {i + 1}")); break
        raw = str(pst["run"]).splitlines()
        pin_ln = next(i for i, l in pip_lines(pst["run"]) if is_pin_cmd(l))
        if not any(is_version_log(l.strip()) for l in raw[pin_ln + 1:]):
            r.append(("C2", f"{label}: the pin step does not log `python3 -m pip --version` after installing"))
    if n_pip_jobs == 0:
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
for case, title in (("C1", "case 1: every pip-installing job pins pip first (hash-checked, binary-only)"),
                    ("C2", "case 2: the pin step logs `python3 -m pip --version`"),
                    ("C3", "case 3: the requirement file is exactly one hash-pinned release pip==" + GOLDEN),
                    ("C4", "case 4: Dependabot watches the pin file's directory under the 7-day cooldown"),
                    ("C6", "case 6: ci.yml's required allowlist job runs this test")):
    bad = [m for c, m in res if c == case]
    report(not bad, title, "; ".join(bad[:4]))

# ---- mutants: each must be rejected, and for the named case
def pin_idx(steps):
    for i, st in enumerate(steps):
        if any(is_pin_cmd(l) for _, l in pip_lines((st or {}).get("run", ""))):
            return i
    return None

def pip_jobs(t):
    return [(label, steps) for label, steps in sequences(t["docs"]) if any(pip_lines((s or {}).get("run", "")) for s in steps)]

def edit_pin_step(fn):
    def mut(t):
        n = 0
        # applies to ONE job at a time: the caller names which
        return n
    return mut

mutants = []   # (name, expected case, fn(tree) -> applied?)
labels = [l for l, _ in pip_jobs(tree)]
def per_job(label, kind):
    def fn(t):
        steps = dict(sequences(t["docs"]))[label]
        i = pin_idx(steps)
        if i is None:
            return False
        st = steps[i]
        if kind == "missing":
            del steps[i]
        elif kind == "after":
            steps.append(steps.pop(i))
        elif kind == "before-other":
            steps.insert(i, {"name": "x", "run": "pip3 install requests"})
        elif kind == "no-require-hashes":
            st["run"] = st["run"].replace("--require-hashes ", "", 1)
        elif kind == "no-only-binary":
            st["run"] = st["run"].replace("--only-binary=:all: ", "", 1)
        elif kind == "other-file":
            st["run"] = st["run"].replace("pip-requirements.txt", "test-requirements.txt", 1)
        elif kind == "no-version-log":
            st["run"] = "\n".join(l for l in st["run"].splitlines() if "--version" not in l)
        elif kind == "version-log-before":
            st["run"] = "python3 -m pip --version\n" + "\n".join(l for l in st["run"].splitlines() if "--version" not in l)
        elif kind == "continue-on-error":
            st["continue-on-error"] = True
        elif kind == "other-install-in-pin-step-first":
            st["run"] = "python3 -m pip install wheel\n" + st["run"]
        elif kind == "not-binary-flag-spelled-apart":
            st["run"] = st["run"].replace("--only-binary=:all:", "--only-binary :all:", 1)
        else:
            raise SystemExit("bad kind " + kind)
        return True
    return fn
for lb in labels or ["(no pip-installing job found)"]:
    for kind, case in (("missing", "C1"), ("after", "C1"), ("before-other", "C1"), ("no-require-hashes", "C1"), ("no-only-binary", "C1"),
                       ("other-file", "C1"), ("no-version-log", "C2"), ("version-log-before", "C2"), ("continue-on-error", "C1"),
                       ("other-install-in-pin-step-first", "C1"), ("not-binary-flag-spelled-apart", "C1")):
        mutants.append((f"{kind} in {lb}", case, per_job(lb, kind) if labels else (lambda t: False)))
def new_job(t):
    t["docs"][".github/workflows/ci.yml"]["jobs"]["extra-pip"] = {"runs-on": "ubuntu-latest", "steps": [{"run": "python -m pip install requests"}]}
    return True
mutants.append(("a second pip-installing job without a pin step", "C1", new_job))
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
    ("an uppercase-length-correct hash replaced by non-hex", "C3", lambda s: re.sub(r"(--hash=sha256:)[0-9a-f]{64}", r"\1" + "z" * 64, s)),
    ("a second requirement", "C3", lambda s: s.rstrip("\n") + "\nsetuptools==80.0.0 " + H + "\n"),
    ("a second requirement on a continuation line", "C3", lambda s: s.rstrip("\n") + " \\\n  wheel==0.45.0 " + H + "\n"),
    ("an extra option line", "C3", lambda s: "--index-url https://example.invalid/simple\n" + s),
    ("an environment marker", "C3", lambda s: s.replace(" --hash", " ; python_version >= '3.9' --hash", 1)),
    ("extras", "C3", lambda s: s.replace("pip==", "pip[x]==")),
    ("an empty file", "C3", lambda s: "# nothing\n"),
):
    mutants.append((name, case, req_edit(fn)))
def dep_pip(t):
    return [u for u in t["dep"]["updates"] if u.get("package-ecosystem") == "pip"]
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
def ci_if(t):
    for x in ci_steps(t):
        if "pip-pin-test.sh" in str(x.get("run", "")): x["if"] = "false"; return True
    return False
def ci_coe(t):
    for x in ci_steps(t):
        if "pip-pin-test.sh" in str(x.get("run", "")): x["continue-on-error"] = True; return True
    return False
mutants += [("ci.yml's allowlist job no longer runs this test", "C6", ci_unwire), ("the step is conditional", "C6", ci_if), ("the step is continue-on-error", "C6", ci_coe)]

killed = 0
for name, case, fn in mutants:
    m = copy.deepcopy(tree)
    try:
        applied = fn(m)
    except Exception as e:   # a tree too far from the fixed shape cannot be mutated: that is a failure of the real tree to be the fixed shape
        applied, name = False, name + f" (mutation error {type(e).__name__})"
    if not applied:
        report(False, "mutant: " + name, "the mutation did not apply (the tree is not in the fixed shape)")
        continue
    got = {c for c, _ in judge(m)}
    ok = case in got
    killed += ok
    report(ok, "mutant: " + name + f" rejected by {case}", f"not rejected for {case} (got {sorted(got)})")
print(f"{len(mutants)} mutants, {killed} killed; {fails} failure(s)")
sys.exit(1 if fails else 0)
PY
