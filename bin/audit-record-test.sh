#!/usr/bin/env bash
# proves: REQ-REL-012-AC1, REQ-REL-012-AC2, REQ-REL-012-AC3, REQ-REL-012-AC4
# Gate 6 of the release process (owner RATIFIED Oct 23, ops/docs/ratify/2026-10-23-release-process-features-sections-audits.md, rule 6, "a
# pull request into the release carries a passed-audit record for its exact head, or it cannot merge"), offline. The record is the branch
# audit/<the pull request's head sha>: ONE commit whose only parent is that head, verified by GitHub, authored by the writer the policy file
# of the BASE checkout names, changing no file. The judge reads the API answers as data and fails closed on every doubt.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
TMPDIR=$(mktemp -d); export TMPDIR; trap 'rm -rf "$TMPDIR"' EXIT
python3 -I - "$here/audit-record.py" <<'PY'
import copy, importlib.util, json, os, re, subprocess, sys, tempfile
spec = importlib.util.spec_from_file_location("ar", sys.argv[1]); A = importlib.util.module_from_spec(spec); spec.loader.exec_module(A)
passed = failed = 0
def check(name, ok, got=""):
    global passed, failed
    if ok: passed += 1; print("ok:", name)
    else: failed += 1; print("FAIL:", name, "->", got)

HEAD = "a" * 40
REC = "b" * 40
WRITERS = {"schema": 1, "writers": [{"login": "fosterstack-automation[bot]", "id": 333151817}]}
REF = {"ref": "refs/heads/audit/" + HEAD, "object": {"sha": REC, "type": "commit"}}
COMMIT = {"sha": REC, "parents": [{"sha": HEAD}], "files": [],
          "commit": {"message": "audit record", "verification": {"verified": True, "reason": "valid"}},
          "author": {"login": "fosterstack-automation[bot]", "id": 333151817, "type": "Bot"}}
def judge(ref=REF, commit=COMMIT, writers=WRITERS, head=HEAD, base="main"):
    return A.verify_record(head, base, ref, commit, writers)
def mut(src, path, value):
    d = copy.deepcopy(src); cur = d
    for k in path[:-1]: cur = cur[k]
    if value is A: del cur[path[-1]]
    else: cur[path[-1]] = value
    return d

ok, why = judge()
check("a record for the exact head, verified, by the named writer, changing nothing -> passes", ok and why == "", (ok, why))
ok, why = judge(ref=None, commit=None, base="chain-v030")
check("a pull request whose base is not main passes without a read", ok, (ok, why))
ok, why = judge(ref=None, commit=None, base="")
check("an empty base is not 'not main': it fails closed", not ok, (ok, why))
for name, ref, commit in (
    ("no branch for this head (nothing was recorded)", None, COMMIT),
    ("no commit answer", REF, None),
    ("the branch is for another head", mut(REF, ["ref"], "refs/heads/audit/" + "c" * 40), COMMIT),
    ("the ref is a tag, not a branch", mut(REF, ["ref"], "refs/tags/audit/" + HEAD), COMMIT),
    ("the ref points at a tree", mut(REF, ["object", "type"], "tree"), COMMIT),
    ("the commit is not the one the branch points at", REF, mut(COMMIT, ["sha"], "d" * 40)),
    ("the record's parent is not the head (stale)", REF, mut(COMMIT, ["parents"], [{"sha": "c" * 40}])),
    ("the record has two parents", REF, mut(COMMIT, ["parents"], [{"sha": HEAD}, {"sha": "c" * 40}])),
    ("the record has no parent", REF, mut(COMMIT, ["parents"], [])),
    ("the record changes a file", REF, mut(COMMIT, ["files"], [{"filename": "x"}])),
    ("the record has no file list at all", REF, mut(COMMIT, ["files"], A)),
    ("the commit is not verified", REF, mut(COMMIT, ["commit", "verification", "verified"], False)),
    ("verified is the string true", REF, mut(COMMIT, ["commit", "verification", "verified"], "true")),
    ("verification says unsigned", REF, mut(COMMIT, ["commit", "verification", "reason"], "unsigned")),
    ("no verification block", REF, mut(COMMIT, ["commit", "verification"], A)),
    ("the author is someone else", REF, mut(COMMIT, ["author", "login"], "fosterstack-admin")),
    ("the author has the writer's name but another id", REF, mut(COMMIT, ["author", "id"], 1)),
    ("the author has the writer's id but another name", REF, mut(COMMIT, ["author", "login"], "fosterstack-automation")),
    ("the author is not a bot", REF, mut(COMMIT, ["author", "type"], "User")),
    ("the author is unknown to GitHub (null)", REF, mut(COMMIT, ["author"], None)),
    ("a malformed answer", [], COMMIT), ("a malformed commit answer", REF, "x"),
):
    ok, why = judge(ref=ref, commit=commit)
    check("refused: " + name, (not ok) and bool(why), (ok, why))
for name, writers in (("no writers file", None), ("an empty writers list", {"schema": 1, "writers": []}),
                      ("a writer without an id", {"schema": 1, "writers": [{"login": "fosterstack-automation[bot]"}]}),
                      ("a wrong schema", {"schema": 2, "writers": WRITERS["writers"]}),
                      ("the id as a string", {"schema": 1, "writers": [{"login": "fosterstack-automation[bot]", "id": "333151817"}]})):
    ok, why = judge(writers=writers)
    check("refused: " + name, not ok, (ok, why))
for h in ("", "abc", "A" * 40, "a" * 39, "a" * 41, "g" * 40, None, 5):
    ok, why = judge(head=h)
    check("refused: a head that is not 40 lower-case hex (%r)" % (h,), not ok, (ok, why))
check("the record's commit message is the one fixed neutral line", A.RECORD_MESSAGE == "audit record" and re.fullmatch(r"[a-z ]+", A.RECORD_MESSAGE), A.RECORD_MESSAGE)
check("the branch name is audit/ plus the sha", A.record_branch(HEAD) == "audit/" + HEAD, A.record_branch(HEAD))

# the command line: facts as files, one exit code
d = tempfile.mkdtemp()
def w(name, obj):
    p = os.path.join(d, name); open(p, "w").write(json.dumps(obj)); return p
base = os.path.join(d, "base"); os.makedirs(base + "/.github/policy"); open(base + "/.github/policy/audit-writers.json", "w").write(json.dumps(WRITERS))
def cli(*extra, head=HEAD, ref=REF, commit=COMMIT, base_ref="main", root=base):
    cmd = [sys.executable, "-I", sys.argv[1], "verify", "--head", head, "--base-ref", base_ref, "--base-root", root]
    if ref is not None: cmd += ["--ref-json", w("ref.json", ref)]
    if commit is not None: cmd += ["--commit-json", w("commit.json", commit)]
    return subprocess.run(cmd + list(extra), capture_output=True, text=True)
r = cli(); check("cli: a good record exits 0", r.returncode == 0, (r.returncode, r.stdout, r.stderr))
r = cli(ref=None); check("cli: a missing ref file exits 1 and says why", r.returncode == 1 and "audit" in (r.stdout + r.stderr), (r.returncode, r.stdout, r.stderr))
r = cli(root=d + "/nowhere"); check("cli: a missing policy file exits 1", r.returncode == 1, (r.returncode, r.stdout, r.stderr))
r = cli(commit=mut(COMMIT, ["commit", "verification", "verified"], False)); check("cli: an unverified record exits 1", r.returncode == 1, (r.returncode, r.stdout, r.stderr))
r = cli(base_ref="chain-v030", ref=None, commit=None); check("cli: a base that is not main exits 0 without reading", r.returncode == 0, (r.returncode, r.stdout, r.stderr))
open(os.path.join(d, "ref.json"), "w").write("{not json")
r = subprocess.run([sys.executable, "-I", sys.argv[1], "verify", "--head", HEAD, "--base-ref", "main", "--base-root", base, "--ref-json", os.path.join(d, "ref.json"), "--commit-json", w("commit.json", COMMIT)], capture_output=True, text=True)
check("cli: unparseable JSON exits 1", r.returncode == 1, (r.returncode, r.stdout, r.stderr))
r = subprocess.run([sys.executable, "-I", sys.argv[1], "bogus"], capture_output=True, text=True)
check("cli: an unknown command exits 2", r.returncode == 2, r.returncode)

# the job in ci.yml: its text is pinned here (a mutated copy of the job must be refused), as the marker gate's is
import yaml
root = os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[1])))
def job_problems(wf):
    job = (wf.get("jobs") or {}).get("audit-record")
    if not isinstance(job, dict):
        return ["no audit-record job"]
    bad = []
    if job.get("name") != "audit-record" or job.get("runs-on") != "ubuntu-latest":
        bad.append("name or runner")
    if job.get("if") != "github.event_name == 'pull_request'":
        bad.append("the job must run on every pull request (a base other than main passes inside the judge)")
    if job.get("permissions") != {"contents": "read"}:
        bad.append("permissions must be contents: read only")
    if set(job) - {"name", "runs-on", "if", "permissions", "steps"}:
        bad.append("keys beyond name, runs-on, if, permissions, steps (an environment, a matrix, continue-on-error)")
    steps = job.get("steps") or []
    if len(steps) != 2:
        return bad + ["two steps: the BASE checkout and the judge"]
    co, run = steps
    if not str(co.get("uses", "")).startswith("actions/checkout@") or not re.search(r"@[0-9a-f]{40}$", str(co.get("uses", ""))):
        bad.append("the checkout is not an action pinned by digest")
    if co.get("with") != {"ref": "${{ github.event.pull_request.base.sha }}", "persist-credentials": "false"}:
        bad.append("the checkout must be the BASE sha, with no persisted credential")
    if set(co) - {"uses", "with"}:
        bad.append("checkout keys beyond uses and with")
    if run.get("env") != {"GH_TOKEN": "${{ github.token }}", "REPO": "${{ github.repository }}", "HEAD_SHA": "${{ github.event.pull_request.head.sha }}", "BASE_REF": "${{ github.event.pull_request.base.ref }}"}:
        bad.append("the judge step's env must be exactly the job token, the repository, the head sha and the base ref")
    if set(run) - {"name", "env", "run"}:
        bad.append("judge step keys beyond name, env, run (continue-on-error, if)")
    text = str(run.get("run", ""))
    for need in ('python3 -I bin/audit-record.py verify --head "$HEAD_SHA" --base-ref "$BASE_REF" --base-root .', 'repos/${REPO}/git/ref/heads/audit/${HEAD_SHA}', "set -euo pipefail"):
        if need not in text:
            bad.append("the judge step lacks: " + need)
    if re.search(r"\|\|\s*(true|:)|continue-on-error|exit 0\s*$", text.replace('nothing to enforce"; exit 0; }', "")):
        bad.append("the judge step swallows a failure")
    if "secrets." in json.dumps(job):
        bad.append("a secret")
    return bad
wf = yaml.load(open(root + "/.github/workflows/ci.yml"), Loader=yaml.BaseLoader)
check("ci.yml: the audit-record job is the reviewed one", job_problems(wf) == [], job_problems(wf))
def wf_mut(fn):
    d = copy.deepcopy(wf); fn(d["jobs"]["audit-record"]); return d
J = lambda d: d
for name, fn, frag in (
    ("an environment", lambda j: j.update({"environment": "agent"}), "keys beyond"),
    ("write permission", lambda j: j["permissions"].update({"id-token": "write"}), "permissions"),
    ("head checkout", lambda j: j["steps"][0]["with"].update({"ref": "${{ github.event.pull_request.head.sha }}"}), "BASE sha"),
    ("a swallowed failure", lambda j: j["steps"][1].update({"run": j["steps"][1]["run"] + "\n|| true"}), "swallows"),
    ("continue-on-error", lambda j: j["steps"][1].update({"continue-on-error": "true"}), "keys beyond"),
    ("a step condition", lambda j: j["steps"][1].update({"if": "false"}), "keys beyond"),
    ("only on some pull requests", lambda j: j.update({"if": "github.event.pull_request.base.ref == 'main'"}), "every pull request"),
    ("an unpinned checkout", lambda j: j["steps"][0].update({"uses": "actions/checkout@v4"}), "digest"),
    ("a different judge", lambda j: j["steps"][1].update({"run": j["steps"][1]["run"].replace("bin/audit-record.py", "bin/other.py")}), "lacks"),
    ("a secret in the env", lambda j: j["steps"][1]["env"].update({"TOKEN": "${{ secrets.X }}"}), "env must be exactly"),
):
    probs = job_problems(wf_mut(fn))
    check("ci.yml: a copy with %s is refused" % name, any(frag in p for p in probs), probs)

print("audit-record: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
PY
