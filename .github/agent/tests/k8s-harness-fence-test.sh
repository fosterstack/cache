#!/usr/bin/env bash
# proves: REQ-REL-005-AC1
# Advisor 0084 (4): the k8s acceptance harness runs the customer commands of docs/kubernetes.md verbatim (rule 12), so
# the pin checker excludes exactly two generated files of stage-acceptance-k8s.yml (/tmp/pf-forward.sh,
# /tmp/smoke-assert.sh). The fence: both are written by the step's own python ONLY from docs/kubernetes.md at the
# checked-out commit — no environment, no network, no other input — and the exclusion names nothing else; any other
# eval of a variable anywhere is refused by the checker.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
# the vendored pure-Python PyYAML as `yaml` (the coverage job's python has none of its own), like check-action-pins-test.sh
pylib=$(mktemp -d); trap 'rm -rf "$pylib"' EXIT
ln -s "$root/.github/agent/fixtures/testlib/pyyaml" "$pylib/yaml"
export PYTHONPATH="$pylib${PYTHONPATH:+:$PYTHONPATH}"
python3 - "$root" <<'PY'
import ast, importlib.util, os, re, subprocess, sys, tempfile, yaml
root = sys.argv[1]
passed = failed = 0
def check(name, ok, got=""):
    global passed, failed
    if ok: passed += 1; print("ok:", name)
    else: failed += 1; print("FAIL:", name, "->", got)
wf = yaml.safe_load(open(os.path.join(root, ".github/workflows/stage-acceptance-k8s.yml")))
steps = wf["jobs"]["k8s"]["steps"]
gen = [s for s in steps if "/tmp/pf-forward.sh" in (s.get("run") or "") and "python3 - <<'PY'" in (s.get("run") or "")]
check("exactly one step writes the generated scripts", len(gen) == 1, len(gen))
run = gen[0]["run"]
src = re.search(r"python3 - <<'PY'\n(.*?)\nPY", run, re.S).group(1)
tree = ast.parse(src)
opens = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "open"]
reads = [ast.literal_eval(n.args[0]) for n in opens if len(n.args) < 2 or ast.literal_eval(n.args[1]) == "r"]
writes = sorted(ast.literal_eval(n.args[0]) for n in opens if len(n.args) >= 2 and ast.literal_eval(n.args[1]) == "w")
check("its only input file is docs/kubernetes.md", reads == ["docs/kubernetes.md"], reads)
check("it writes the two fenced scripts (and the pod yaml)", {"/tmp/pf-forward.sh", "/tmp/smoke-assert.sh"} <= set(writes), writes)
mods = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))
        for a in (n.names if isinstance(n, ast.Import) else [ast.alias(n.module or "")])}
check("no network or process module", not mods & {"urllib", "http", "socket", "requests", "subprocess", "ftplib"}, mods)
def generate(env, doc):
    d = tempfile.mkdtemp(); os.makedirs(os.path.join(d, "docs"))
    open(os.path.join(d, "docs/kubernetes.md"), "w").write(doc)
    code = src.replace("/tmp/", d + "/out-")
    subprocess.run([sys.executable, "-c", code], cwd=d, env=env, check=True, capture_output=True)
    return {f: open(os.path.join(d, "out-" + f)).read() for f in ("pf-forward.sh", "smoke-assert.sh")}
doc = open(os.path.join(root, "docs/kubernetes.md")).read()
base = dict(PATH=os.environ["PATH"], CLIENT_LOCAL="fscache-client:accept")
a = generate(base, doc)
b = generate(dict(base, PF_CMD="docker run alpine", HOME="/x", FSCACHE_ADDR=":1", HTTPS_PROXY="http://evil"), doc)
check("the environment does not change what the scripts run", a == b)
check("the port-forward script is the doc's own command", "kubectl" in a["pf-forward.sh"] and "port-forward" in a["pf-forward.sh"])
c = generate(base, doc.replace("port-forward", "port-forward --address 127.0.0.1"))
check("a doc change is what changes the scripts", c["pf-forward.sh"] != a["pf-forward.sh"])
# the checker's exclusion names exactly these two paths of that one workflow
spec = importlib.util.spec_from_file_location("p", os.path.join(root, ".github/agent/bin/check-action-pins.py"))
P = importlib.util.module_from_spec(spec); spec.loader.exec_module(P)
check("the exclusion is exactly these two files of stage-acceptance-k8s.yml", set(P.GENERATED_OK) == {
    (".github/workflows/stage-acceptance-k8s.yml", "/tmp/pf-forward.sh"),
    (".github/workflows/stage-acceptance-k8s.yml", "/tmp/smoke-assert.sh")}, set(P.GENERATED_OK))
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
    P.check_runs(".github/workflows/stage-acceptance-k8s.yml.jobs.k8s.steps[0].run",
                 [(".github/workflows/stage-acceptance-k8s.yml.jobs.k8s.steps[0].run", extra, None),
                  (".github/workflows/stage-acceptance-k8s.yml.jobs.k8s.steps[1].run",
                   "bash /tmp/pf-forward.sh; bash /tmp/smoke-assert.sh", None)], bad)
    check("a fenced script that %s also writes is refused (Codex #164 r3, N04)" % name, bool(bad), bad)
bad = []
P.check_runs(".github/workflows/stage-acceptance-k8s.yml.jobs.k8s.steps[0].run",
             [(".github/workflows/stage-acceptance-k8s.yml.jobs.k8s.steps[0].run", "bash /tmp/pf-forward.sh", None)], bad)
check("the fenced script with no other writer passes", not bad, bad)
print("k8s-harness-fence: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
PY
