#!/usr/bin/env bash
# proves: REQ-REL-012-AC1, REQ-REL-012-AC2, REQ-REL-012-AC3, REQ-REL-012-AC4, REQ-REL-012-AC5, REQ-REL-012-AC7, REQ-REL-012-AC8, REQ-REL-012-AC9, REQ-REL-012-AC10
# Gate 6 of the release process (owner RATIFIED Oct 23, ops/docs/ratify/2026-10-23-release-process-features-sections-audits.md, rule 6, "a
# pull request into the release carries a passed-audit record for its exact head, or it cannot merge"), offline. The record is the branch
# audit/<the pull request's head sha>: ONE commit whose only parent is that head, verified by GitHub, authored by the writer the policy file
# of the default branch names (and committed by it or by GitHub's own web-flow), with the fixed message, adding exactly the one file
# audit-record. The judge reads the API answers as data and fails closed on every doubt; bin/audit-record-judge.sh reads them (a fake gh here)
# and the verdict job of agent-review-gate.yml runs it from the default branch, over the head.
# For a pull request Dependabot opened (owner RATIFIED Nov 11 2026) the Dependabot reviewer's success passes the head.
# Those cases are the last section here; they build a small git repository and need git 2.38 or newer.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
TMPDIR=$(mktemp -d); export TMPDIR; trap 'rm -rf "$TMPDIR"' EXIT
python3 -I - "$here/audit-record.py" "$here/audit-record-judge.sh" <<'PY'
import copy, importlib.util, json, os, re, subprocess, sys, tempfile, yaml
spec = importlib.util.spec_from_file_location("ar", sys.argv[1]); A = importlib.util.module_from_spec(spec); spec.loader.exec_module(A)
JUDGE_SH = sys.argv[2]
passed = failed = 0
def check(name, ok, got=""):
    global passed, failed
    if ok: passed += 1; print("ok:", name)
    else: failed += 1; print("FAIL:", name, "->", got)

HEAD = "a" * 40
REC = "b" * 40
WRITERS = {"schema": 1, "writers": [{"login": "fosterstack-automation[bot]", "id": 333151817}], "dispatchers": ["fosterstack-admin"]}
REF = {"ref": "refs/heads/audit/" + HEAD, "object": {"sha": REC, "type": "commit"}}
BOT = {"login": "fosterstack-automation[bot]", "id": 333151817, "type": "Bot"}
COMMIT = {"sha": REC, "parents": [{"sha": HEAD}], "files": [{"filename": "audit-record", "status": "added"}],
          "commit": {"message": "audit record", "verification": {"verified": True, "reason": "valid"}},
          "author": BOT, "committer": {"login": "web-flow", "id": 19864447, "type": "User"}}
def judge(ref=REF, commit=COMMIT, writers=WRITERS, head=HEAD, base="main"):
    return A.verify_record(head, base, ref, commit, writers)
def mut(src, path, value):
    d = copy.deepcopy(src); cur = d
    for k in path[:-1]: cur = cur[k]
    if value is A: del cur[path[-1]]
    else: cur[path[-1]] = value
    return d

ok, why = judge()
check("a record for the exact head, verified, by the named writer, committed by GitHub, one file -> passes", ok and why == "", (ok, why))
ok, why = judge(commit=mut(COMMIT, ["committer"], BOT))
check("a record the writer itself committed passes too", ok, (ok, why))
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
    ("the record changes no file", REF, mut(COMMIT, ["files"], [])),
    ("the record adds another file", REF, mut(COMMIT, ["files"], [{"filename": "x", "status": "added"}])),
    ("the record modifies its file instead of adding it", REF, mut(COMMIT, ["files"], [{"filename": "audit-record", "status": "modified"}])),
    ("the record adds two files", REF, mut(COMMIT, ["files"], [{"filename": "audit-record", "status": "added"}, {"filename": "y", "status": "added"}])),
    ("the record has no file list at all", REF, mut(COMMIT, ["files"], A)),
    ("the record's message is another line", REF, mut(COMMIT, ["commit", "message"], "reviewed by somebody")),
    ("the record has no message", REF, mut(COMMIT, ["commit", "message"], A)),
    ("the commit is not verified", REF, mut(COMMIT, ["commit", "verification", "verified"], False)),
    ("verified is the string true", REF, mut(COMMIT, ["commit", "verification", "verified"], "true")),
    ("verification says unsigned", REF, mut(COMMIT, ["commit", "verification", "reason"], "unsigned")),
    ("no verification block", REF, mut(COMMIT, ["commit", "verification"], A)),
    ("the author is someone else", REF, mut(COMMIT, ["author", "login"], "fosterstack-admin")),
    ("the author has the writer's name but another id", REF, mut(COMMIT, ["author", "id"], 1)),
    ("the author has the writer's id but another name", REF, mut(COMMIT, ["author", "login"], "fosterstack-automation")),
    ("the author is not a bot", REF, mut(COMMIT, ["author", "type"], "User")),
    ("the author is unknown to GitHub (null)", REF, mut(COMMIT, ["author"], None)),
    ("the committer is somebody who signed with their own key", REF, mut(COMMIT, ["committer"], {"login": "someone", "id": 5, "type": "User"})),
    ("the committer is web-flow by name but another id", REF, mut(COMMIT, ["committer", "id"], 5)),
    ("the committer is unknown (null)", REF, mut(COMMIT, ["committer"], None)),
    ("no committer at all", REF, mut(COMMIT, ["committer"], A)),
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
check("the record's commit message is the one fixed neutral line, and the judge enforces it", A.RECORD_MESSAGE == "audit record" and re.fullmatch(r"[a-z ]+", A.RECORD_MESSAGE), A.RECORD_MESSAGE)
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
r = cli(base_ref="", ref=None, commit=None); check("cli: an EMPTY base exits 1 (the judge decides, not the command line)", r.returncode == 1, (r.returncode, r.stdout, r.stderr))
open(os.path.join(d, "ref.json"), "w").write("{not json")
r = subprocess.run([sys.executable, "-I", sys.argv[1], "verify", "--head", HEAD, "--base-ref", "main", "--base-root", base, "--ref-json", os.path.join(d, "ref.json"), "--commit-json", w("commit.json", COMMIT)], capture_output=True, text=True)
check("cli: unparseable JSON exits 1", r.returncode == 1, (r.returncode, r.stdout, r.stderr))
r = subprocess.run([sys.executable, "-I", sys.argv[1], "bogus"], capture_output=True, text=True)
check("cli: an unknown command exits 2", r.returncode == 2, r.returncode)

# the wrapper the verdict job runs: a fake gh answers from files; every path must fail closed, and say which kind of failure it is
fake = os.path.join(d, "fakebin"); os.makedirs(fake)
open(os.path.join(fake, "gh"), "w").write('''#!/usr/bin/env bash
echo "gh $*" >> "$CALLS"
case "$2" in
  repos/o/r/git/ref/heads/audit/*) f="$FAKE/ref"; ;;
  repos/o/r/commits/*/pulls*) echo "[]"; exit 0 ;;
  repos/o/r/commits/*) f="$FAKE/commit"; ;;
  *) echo "UNEXPECTED $*" >> "$CALLS"; exit 9 ;;
esac
if [ -f "$f.err" ]; then cat "$f.err" >&2; exit 1; fi
cat "$f.json"
''')
os.chmod(os.path.join(fake, "gh"), 0o755)
root = os.path.join(d, "repo"); os.makedirs(root + "/bin"); os.makedirs(root + "/.github/policy")
for src, dst in ((sys.argv[1], root + "/bin/audit-record.py"), (JUDGE_SH, root + "/bin/audit-record-judge.sh")):
    open(dst, "w").write(open(src).read()); os.chmod(dst, 0o755)
open(root + "/.github/policy/audit-writers.json", "w").write(json.dumps(WRITERS))
def wrap(head=HEAD, base_ref="main", ref=REF, commit=COMMIT, ref_err=None, commit_err=None, repo="o/r"):
    fk = tempfile.mkdtemp(dir=d)
    for name, obj, err in (("ref", ref, ref_err), ("commit", commit, commit_err)):
        if err is not None: open(os.path.join(fk, name + ".err"), "w").write(err)
        elif obj is not None: open(os.path.join(fk, name + ".json"), "w").write(json.dumps(obj))
        else: open(os.path.join(fk, name + ".err"), "w").write("gh: Not Found (HTTP 404)")
    calls = os.path.join(fk, "calls"); open(calls, "w").close()
    env = dict(os.environ, PATH=fake + ":" + os.environ["PATH"], FAKE=fk, CALLS=calls, GITHUB_REPOSITORY=repo, GH_TOKEN="x")
    r = subprocess.run(["bash", root + "/bin/audit-record-judge.sh", head, base_ref], capture_output=True, text=True, env=env)
    return r, open(calls).read()
r, calls = wrap(); check("wrapper: a good record exits 0 after reading the ref and the commit", r.returncode == 0 and calls.count("gh api") == 2, (r.returncode, r.stdout, r.stderr, calls))
r, calls = wrap(base_ref="chain-v030"); check("wrapper: a base that is not main exits 0 and calls nothing", r.returncode == 0 and calls == "", (r.returncode, calls))
r, calls = wrap(base_ref=""); check("wrapper: an empty base exits 1 and calls nothing", r.returncode == 1 and calls == "", (r.returncode, r.stdout, calls))
r, calls = wrap(head="x; rm -rf /"); check("wrapper: a head that is not 40 hex exits 1 and calls nothing (nothing odd reaches a request path)", r.returncode == 1 and calls == "", (r.returncode, r.stdout, calls))
r, calls = wrap(ref=None); check("wrapper: no record branch (404) exits 1 saying there is no record", r.returncode == 1 and "no passed-audit record" in r.stdout, (r.returncode, r.stdout, r.stderr))
r, calls = wrap(ref_err="gh: HTTP 502: Bad Gateway"); check("wrapper: a GitHub API error on the ref exits 3 and says it is an API error, not a record defect", r.returncode == 3 and "could not read the record" in r.stderr, (r.returncode, r.stdout, r.stderr))
r, calls = wrap(commit_err="gh: HTTP 403: rate limit exceeded"); check("wrapper: a GitHub API error on the commit exits 3 as an API error", r.returncode == 3 and "could not read the record" in r.stderr, (r.returncode, r.stdout, r.stderr))
r, calls = wrap(commit=None); check("wrapper: a commit that is not found exits 1", r.returncode == 1, (r.returncode, r.stdout, r.stderr))
r, calls = wrap(commit=mut(COMMIT, ["commit", "verification", "verified"], False)); check("wrapper: an unverified record exits 1", r.returncode == 1, (r.returncode, r.stdout, r.stderr))
r, calls = wrap(ref={"ref": "refs/heads/audit/" + HEAD, "object": {"sha": "not-a-sha", "type": "commit"}}); check("wrapper: a ref whose object is not a sha exits 1 without a commit request", r.returncode == 1 and "commits/not-a-sha" not in calls, (r.returncode, r.stdout, calls))
r, calls = wrap(repo="o/r; x"); check("wrapper: a repository that is not owner/name exits 1 and calls nothing", r.returncode == 1 and calls == "", (r.returncode, r.stderr, calls))

# the writer's own checks: the pull request must be open, into main, with exactly this head, before anything is written
PR = {"number": 7, "state": "open", "merged": False, "head": {"sha": HEAD}, "base": {"ref": "main"}}
def plan(pr=PR, number=7, head=HEAD, actor="fosterstack-admin", policy=WRITERS):
    return A.plan_record(number, head, pr, actor, policy)
ok, why = plan(); check("plan: an open pull request into main with this head may be recorded", ok and why == "", (ok, why))
for name, pr, number, head in (
    ("a closed pull request", mut(PR, ["state"], "closed"), 7, HEAD),
    ("a merged pull request", mut(PR, ["merged"], True), 7, HEAD),
    ("a head that moved", mut(PR, ["head", "sha"], "c" * 40), 7, HEAD),
    ("another base", mut(PR, ["base", "ref"], "chain-v030"), 7, HEAD),
    ("another number", PR, 8, HEAD),
    ("a number that is not a positive integer", PR, "7", HEAD), ("zero", PR, 0, HEAD), ("a bool", PR, True, HEAD),
    ("a head that is not 40 hex", PR, 7, "abc"), ("no head", PR, 7, None),
    ("no answer", None, 7, HEAD), ("a malformed answer", [], 7, HEAD), ("no head block", mut(PR, ["head"], A), 7, HEAD),
):
    ok, why = plan(pr=pr, number=number, head=head)
    check("plan refused: " + name, (not ok) and bool(why), (ok, why))
for name, kw in (("an actor who is not a dispatcher", dict(actor="someone")), ("no actor", dict(actor=None)), ("an empty actor", dict(actor="")),
                 ("the writer bot itself dispatching", dict(actor="fosterstack-automation[bot]")), ("no policy", dict(policy=None)),
                 ("a policy without dispatchers", dict(policy={"schema": 1, "writers": WRITERS["writers"]})),
                 ("a policy with an empty dispatchers list", dict(policy=mut(WRITERS, ["dispatchers"], []))),
                 ("a policy with a non-string dispatcher", dict(policy=mut(WRITERS, ["dispatchers"], [5])))):
    ok, why = plan(**kw)
    check("plan refused: " + name, (not ok) and bool(why), (ok, why))
open(os.path.join(d, "pr.json"), "w").write(json.dumps(PR))
r = subprocess.run([sys.executable, "-I", sys.argv[1], "plan", "--pr", "7", "--head", HEAD, "--pr-json", os.path.join(d, "pr.json"), "--actor", "fosterstack-admin", "--base-root", base], capture_output=True, text=True)
check("cli plan: an open pull request exits 0", r.returncode == 0, (r.returncode, r.stdout, r.stderr))
r = subprocess.run([sys.executable, "-I", sys.argv[1], "plan", "--pr", "8", "--head", HEAD, "--pr-json", os.path.join(d, "pr.json"), "--actor", "fosterstack-admin", "--base-root", base], capture_output=True, text=True)
check("cli plan: another number exits 1", r.returncode == 1, (r.returncode, r.stdout, r.stderr))
r = subprocess.run([sys.executable, "-I", sys.argv[1], "plan", "--pr", "7", "--head", HEAD, "--pr-json", os.path.join(d, "pr.json"), "--actor", "someone", "--base-root", base], capture_output=True, text=True)
check("cli plan: an actor who is not a dispatcher exits 1", r.returncode == 1, (r.returncode, r.stdout, r.stderr))
r = subprocess.run([sys.executable, "-I", sys.argv[1], "plan", "--pr", "x", "--head", HEAD, "--pr-json", os.path.join(d, "pr.json"), "--actor", "fosterstack-admin", "--base-root", base], capture_output=True, text=True)
check("cli plan: a pull request number that is not a number exits 2", r.returncode == 2, (r.returncode, r.stdout, r.stderr))
# the COMMITTED policy (the repository root, not the in-test WRITERS above): the box's App bot may ask for a record; nobody else is added
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[1])))
def committed_plan(actor):
    return subprocess.run([sys.executable, "-I", sys.argv[1], "plan", "--pr", "7", "--head", HEAD, "--pr-json", os.path.join(d, "pr.json"),
                           "--actor", actor, "--base-root", ROOT], capture_output=True, text=True)
r = committed_plan("fosterstack-harness[bot]")
check("committed policy: the review helper App bot (fosterstack-harness[bot]) may ask for a record (exit 0)", r.returncode == 0, (r.returncode, r.stdout, r.stderr))
r = committed_plan("fosterstack-admin")
check("committed policy: the owner's login may still ask for a record (exit 0)", r.returncode == 0, (r.returncode, r.stdout, r.stderr))
for who in ("fosterstack-automation[bot]", "fosterstack-harness", "someone"):
    r = committed_plan(who)
    check("committed policy: %r may not ask for a record (exit 1)" % who, r.returncode == 1, (r.returncode, r.stdout, r.stderr))
committed = json.load(open(os.path.join(ROOT, ".github/policy/audit-writers.json")))
check("committed policy: the dispatchers are exactly fosterstack-admin and fosterstack-harness[bot]",
      sorted(committed["dispatchers"]) == ["fosterstack-admin", "fosterstack-harness[bot]"], committed["dispatchers"])
check("committed policy: no dispatcher is a writer (the one who asks never writes the record)",
      not set(committed["dispatchers"]) & {w["login"] for w in committed["writers"]}, committed)
check("committed policy: the writers are unchanged (fosterstack-automation[bot], id 333151817)",
      committed["writers"] == [{"login": "fosterstack-automation[bot]", "id": 333151817}], committed["writers"])

# the writer's first half (prepare): a fake gh answers the pull request and the record lookups; it must write only after the plan passes and never over a good record
PREP_SH = os.path.join(os.path.dirname(JUDGE_SH), "audit-record-prepare.sh")
wroot = os.path.join(d, "wrepo"); os.makedirs(wroot + "/bin"); os.makedirs(wroot + "/.github/policy")
for src, dst in ((sys.argv[1], wroot + "/bin/audit-record.py"), (JUDGE_SH, wroot + "/bin/audit-record-judge.sh"), (PREP_SH, wroot + "/bin/audit-record-prepare.sh")):
    open(dst, "w").write(open(src).read()); os.chmod(dst, 0o755)
open(wroot + "/.github/policy/audit-writers.json", "w").write(json.dumps(WRITERS))
open(fake + "/gh", "w").write('''#!/usr/bin/env bash
echo "gh $*" >> "$CALLS"
case "$2" in
  repos/o/r/pulls/*) f="$FAKE/pr" ;;
  repos/o/r/git/ref/heads/audit/*) f="$FAKE/ref" ;;
  repos/o/r/commits/*/pulls*) echo "[]"; exit 0 ;;
  repos/o/r/commits/*) f="$FAKE/commit" ;;
  *) echo "UNEXPECTED $*" >> "$CALLS"; exit 9 ;;
esac
if [ -f "$f.err" ]; then cat "$f.err" >&2; exit 1; fi
cat "$f.json"
''')
def prepare(pr=PR, number="7", head=HEAD, ref=None, commit=None, pr_err=None, repo="o/r", actor="fosterstack-admin"):
    fk = tempfile.mkdtemp(dir=d)
    for name, obj, err in (("pr", pr, pr_err), ("ref", ref, None), ("commit", commit, None)):
        if err is not None: open(os.path.join(fk, name + ".err"), "w").write(err)
        elif obj is not None: open(os.path.join(fk, name + ".json"), "w").write(json.dumps(obj))
        else: open(os.path.join(fk, name + ".err"), "w").write("gh: Not Found (HTTP 404)")
    calls = os.path.join(fk, "calls"); open(calls, "w").close()
    cwd = tempfile.mkdtemp(dir=d)
    for name in ("bin", ".github"): os.symlink(os.path.join(wroot, name), os.path.join(cwd, name))
    env = dict(os.environ, PATH=fake + ":" + os.environ["PATH"], FAKE=fk, CALLS=calls, GITHUB_REPOSITORY=repo, GH_TOKEN="x", AUDIT_ACTOR=actor)
    r = subprocess.run(["bash", "bin/audit-record-prepare.sh", number, head], capture_output=True, text=True, env=env, cwd=cwd)
    f = os.path.join(cwd, "audit-record")
    return r, open(calls).read(), (open(f).read() if os.path.exists(f) else None)
r, calls, f = prepare(); check("prepare: an open pull request into main with no record yet -> proceed, and the file audit-record holds the head",
    r.returncode == 0 and r.stdout.strip().splitlines()[-1] == "proceed" and f == HEAD + "\n", (r.returncode, r.stdout, r.stderr, f))
r, calls, f = prepare(ref=REF, commit=COMMIT); check("prepare: a record that already passes -> present, nothing written", r.returncode == 0 and r.stdout.strip().splitlines()[-1] == "present" and f is None, (r.returncode, r.stdout, f))
r, calls, f = prepare(ref=REF, commit=mut(COMMIT, ["commit", "verification", "verified"], False)); check("prepare: a record that does not pass -> proceed", r.returncode == 0 and r.stdout.strip().splitlines()[-1] == "proceed" and f == HEAD + "\n", (r.returncode, r.stdout, f))
def prepare_api(ref_err=None, commit_err=None):
    # the same as prepare(), with a GitHub API error on the record lookup
    fk = tempfile.mkdtemp(dir=d)
    open(os.path.join(fk, "pr.json"), "w").write(json.dumps(PR))
    if ref_err: open(os.path.join(fk, "ref.err"), "w").write(ref_err)
    else: open(os.path.join(fk, "ref.json"), "w").write(json.dumps(REF))
    if commit_err: open(os.path.join(fk, "commit.err"), "w").write(commit_err)
    else: open(os.path.join(fk, "commit.json"), "w").write(json.dumps(COMMIT))
    calls = os.path.join(fk, "calls"); open(calls, "w").close()
    cwd = tempfile.mkdtemp(dir=d)
    for name in ("bin", ".github"): os.symlink(os.path.join(wroot, name), os.path.join(cwd, name))
    env = dict(os.environ, PATH=fake + ":" + os.environ["PATH"], FAKE=fk, CALLS=calls, GITHUB_REPOSITORY="o/r", GH_TOKEN="x", AUDIT_ACTOR="fosterstack-admin")
    r = subprocess.run(["bash", "bin/audit-record-prepare.sh", "7", HEAD], capture_output=True, text=True, env=env, cwd=cwd)
    return r, os.path.exists(os.path.join(cwd, "audit-record"))
r, wrote = prepare_api(ref_err="gh: HTTP 502: Bad Gateway"); check("prepare: an API error reading the existing record -> exit 1 and nothing written (never over a record it could not read)", r.returncode == 1 and not wrote and "proceed" not in r.stdout, (r.returncode, r.stdout, r.stderr, wrote))
r, wrote = prepare_api(commit_err="gh: HTTP 403: rate limit"); check("prepare: an API error reading the record's commit -> exit 1 and nothing written", r.returncode == 1 and not wrote and "proceed" not in r.stdout, (r.returncode, r.stdout, r.stderr, wrote))
for name, kw in (("an actor who is not a dispatcher", dict(actor="someone")), ("a closed pull request", dict(pr=mut(PR, ["state"], "closed"))), ("a merged pull request", dict(pr=mut(PR, ["merged"], True))),
                 ("a head that moved", dict(pr=mut(PR, ["head", "sha"], "c" * 40))), ("a pull request not into main", dict(pr=mut(PR, ["base", "ref"], "chain-v030"))),
                 ("an API error reading the pull request", dict(pr_err="gh: HTTP 502"))):
    r, calls, f = prepare(**kw); check("prepare refused: %s -> exit 1, nothing written" % name, r.returncode == 1 and f is None and "proceed" not in r.stdout, (r.returncode, r.stdout, r.stderr, f))
for name, kw in (("a pull request number that is not digits", dict(number="7; rm -rf /")), ("a head that is not 40 hex", dict(head="abc")), ("a repository that is not owner/name", dict(repo="o/r x"))):
    r, calls, f = prepare(**kw); check("prepare refused: %s -> exit 1, nothing called" % name, r.returncode == 1 and calls == "" and f is None, (r.returncode, calls, f))

# the request script the lane runs after the review clears: a fake gh answers `pr view` and records `workflow run`
REQ_SH = os.path.join(os.path.dirname(JUDGE_SH), "audit-record-request.sh")
open(fake + "/gh", "w").write('''#!/usr/bin/env bash
echo "gh $*" >> "$CALLS"
case "$1 $2" in
  "pr view") [ -f "$FAKE/view.err" ] && { cat "$FAKE/view.err" >&2; exit 1; }; cat "$FAKE/view.txt" ;;
  "workflow run") [ -n "$WF_FAIL" ] && { echo "HTTP 403" >&2; exit 1; }; exit 0 ;;
  *) echo "UNEXPECTED $*" >> "$CALLS"; exit 9 ;;
esac
''')
def request(view="main %s OPEN" % HEAD, pr="7", head=HEAD, view_err=None, wf_fail=False, repo=None):
    fk = tempfile.mkdtemp(dir=d)
    if view_err: open(os.path.join(fk, "view.err"), "w").write(view_err)
    else: open(os.path.join(fk, "view.txt"), "w").write(view + "\n")
    calls = os.path.join(fk, "calls"); open(calls, "w").close()
    env = dict(os.environ, PATH=fake + ":" + os.environ["PATH"], FAKE=fk, CALLS=calls, WF_FAIL=("1" if wf_fail else ""))
    if repo: env["GITHUB_REPOSITORY"] = repo
    r = subprocess.run(["bash", REQ_SH, pr, head], capture_output=True, text=True, env=env)
    return r, open(calls).read()
r, c = request(); check("request: an open pull request into main at this head -> the record job is started once, with the two inputs, on main",
    r.returncode == 0 and c.count("gh workflow run agent-review-gate.yml -R fosterstack/cache --ref main -f audit_pr=7 -f audit_head=" + HEAD) == 1, (r.returncode, r.stdout, r.stderr, c))
r, c = request(view="chain-v030 %s OPEN" % HEAD); check("request: a pull request not into main -> nothing requested, exit 0", r.returncode == 0 and "workflow run" not in c, (r.returncode, r.stdout, c))
r, c = request(view="main %s OPEN" % ("c" * 40)); check("request: a head that moved -> nothing requested, exit 1", r.returncode == 1 and "workflow run" not in c, (r.returncode, r.stderr, c))
r, c = request(view="main %s CLOSED" % HEAD); check("request: a closed pull request -> nothing requested, exit 1", r.returncode == 1 and "workflow run" not in c, (r.returncode, r.stderr, c))
r, c = request(view_err="gh: HTTP 502"); check("request: an API error reading the pull request -> nothing requested, exit 1", r.returncode == 1 and "workflow run" not in c, (r.returncode, r.stderr, c))
r, c = request(wf_fail=True); check("request: a failing dispatch -> exit 1 saying so", r.returncode == 1 and "could not be started" in r.stderr, (r.returncode, r.stderr))
r, c = request(pr="7; rm -rf /"); check("request: a pull request number that is not digits -> nothing called", r.returncode == 1 and c == "", (r.returncode, c))
r, c = request(head="abc"); check("request: a head that is not 40 hex -> nothing called", r.returncode == 1 and c == "", (r.returncode, c))
r, c = request(repo="o/r x"); check("request: a repository that is not owner/name -> nothing called", r.returncode == 1 and c == "", (r.returncode, c))

# GATE 7 (rule 7): a release tag needs a passed audit of the whole release and the owner's approval of that audit.
# The record is the same audit/<sha> branch, for the TAGGED
# commit; the owner's approval is one line of the owner-signed tag message naming the record commit.
# Patch tags (vX.Y.Z, Z >= 1) need nothing more.
SIG = "-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n"
def tagobj(msg_lines, sig=SIG):
    return "object %s\ntype commit\ntag v0.3.0\ntagger Owner <o@x> 1 +0000\n\n%s\n%s" % (HEAD, "\n".join(msg_lines),
        sig)
APPROVED = tagobj(["Release v0.3.0", "Audit-approved: " + REC])
def rel(tag="v0.3.0", obj=APPROVED, sha=HEAD, ref=REF, commit=COMMIT, policy=WRITERS):
    return A.verify_release(tag, obj, sha, ref, commit, policy)
ok, why = rel()
check("release: an owner-signed v0.3.0 whose message approves the record of the tagged commit -> passes",
    ok and why == "", (ok, why))
ok, why = rel(tag="v0.3.0-rc.1"); check("release: a release candidate tag is held to the same rule", ok, (ok, why))
ok, why = rel(obj=tagobj(["-----BEGIN EXAMPLE SIGNATURE-----", "Release v0.3.0", "-----END EXAMPLE SIGNATURE-----",
    "Audit-approved: " + REC]))
check("release: an example block before the approval line is message text, not the signature: still passes", ok, (ok,
    why))
ok, why = rel(tag="v0.3.1", obj="", ref=None, commit=None)
check("release: a patch tag needs no record and no approval line", ok, (ok, why))
ok, why = rel(tag="v0.3.12", obj=None, ref=None, commit=None)
check("release: a two-digit patch tag is a patch tag too", ok, (ok, why))
for name, kw in (
    ("no approval line", dict(obj=tagobj(["Release v0.3.0"]))),
    ("an approval line for another commit", dict(obj=tagobj(["Audit-approved: " + "d" * 40]))),
    ("two approval lines", dict(obj=tagobj(["Audit-approved: " + REC, "Audit-approved: " + REC]))),
    ("two approval lines naming different commits", dict(obj=tagobj(["Audit-approved: " + REC,
        "Audit-approved: " + "d" * 40]))),
    ("the line in upper case", dict(obj=tagobj(["AUDIT-APPROVED: " + REC]))),
    ("the sha shortened", dict(obj=tagobj(["Audit-approved: " + REC[:12]]))),
    ("trailing text on the line", dict(obj=tagobj(["Audit-approved: " + REC + " ok"]))),
    ("the line indented", dict(obj=tagobj(["  Audit-approved: " + REC]))),
    ("the line inside the signature block", dict(obj=tagobj(["Release v0.3.0"],
        sig="-----BEGIN SSH SIGNATURE-----\nAudit-approved: " + REC + "\n-----END SSH SIGNATURE-----\n"))),
    ("a second approval line inside an example block that is message text, not the signature",
        dict(obj=tagobj(["Audit-approved: " + REC, "-----BEGIN EXAMPLE SIGNATURE-----", "Audit-approved: " + "d" * 40,
        "-----END EXAMPLE SIGNATURE-----"]))),
    ("no tag object", dict(obj=None)), ("an empty tag object", dict(obj="")),
    ("no record branch", dict(ref=None)), ("no record commit", dict(commit=None)),
    ("a record for another tagged commit", dict(sha="c" * 40)),
    ("an unverified record", dict(commit=mut(COMMIT, ["commit", "verification", "verified"], False))),
    ("a record by someone else", dict(commit=mut(COMMIT, ["author", "login"], "someone"))),
    ("a record whose commit is not the approved one", dict(obj=tagobj(["Audit-approved: " + "e" * 40]))),
    ("a missing policy", dict(policy=None)),
    ("a tag that is not a release version", dict(tag="v0.3")), ("a tag with a suffix that is not rc.N",
        dict(tag="v0.3.0-beta")), ("an empty tag", dict(tag="")),
):
    ok, why = rel(**kw); check("release refused: " + name, (not ok) and bool(why), (ok, why))
# the command line and the wrapper in release mode
open(os.path.join(d, "tagobj.txt"), "w").write(APPROVED)
def relcli(tag="v0.3.0", obj="tagobj.txt", ref=REF, commit=COMMIT, sha=HEAD):
    cmd = [sys.executable, "-I", sys.argv[1], "release", "--tag", tag, "--tag-object", os.path.join(d, obj),
        "--tagged-sha", sha, "--base-root", base]
    if ref is not None: cmd += ["--ref-json", w("ref.json", ref)]
    if commit is not None: cmd += ["--commit-json", w("commit.json", commit)]
    return subprocess.run(cmd, capture_output=True, text=True)
r = relcli(); check("cli release: a good approval exits 0", r.returncode == 0, (r.returncode, r.stdout, r.stderr))
r = relcli(ref=None); check("cli release: no record exits 1", r.returncode == 1, (r.returncode, r.stdout, r.stderr))
r = relcli(obj="missing.txt")
check("cli release: an unreadable tag object exits 1", r.returncode == 1, (r.returncode, r.stdout, r.stderr))
r = relcli(tag="v0.3.1", ref=None, commit=None, obj="missing.txt")
check("cli release: a patch tag exits 0 without reading anything", r.returncode == 0, (r.returncode, r.stdout,
    r.stderr))
def wrap_rel(tag="v0.3.0", ref=REF, commit=COMMIT, ref_err=None, obj_text=APPROVED):
    fk = tempfile.mkdtemp(dir=d)
    for name, o, err in (("ref", ref, ref_err), ("commit", commit, None)):
        if err is not None: open(os.path.join(fk, name + ".err"), "w").write(err)
        elif o is not None: open(os.path.join(fk, name + ".json"), "w").write(json.dumps(o))
        else: open(os.path.join(fk, name + ".err"), "w").write("gh: Not Found (HTTP 404)")
    calls = os.path.join(fk, "calls"); open(calls, "w").close()
    tf = os.path.join(fk, "tagobj"); open(tf, "w").write(obj_text)
    open(fake + "/gh", "w").write('''#!/usr/bin/env bash
echo "gh $*" >> "$CALLS"
case "$2" in
  repos/o/r/git/ref/heads/audit/*) f="$FAKE/ref" ;;
  repos/o/r/commits/*) f="$FAKE/commit" ;;
  *) echo "UNEXPECTED $*" >> "$CALLS"; exit 9 ;;
esac
if [ -f "$f.err" ]; then cat "$f.err" >&2; exit 1; fi
cat "$f.json"
''')
    env = dict(os.environ, PATH=fake + ":" + os.environ["PATH"], FAKE=fk, CALLS=calls, GITHUB_REPOSITORY="o/r",
        GH_TOKEN="x")
    r = subprocess.run(["bash", root + "/bin/audit-record-judge.sh", HEAD, "main", "--release", tag, tf],
        capture_output=True, text=True, env=env)
    return r, open(calls).read()
r, c = wrap_rel()
check("wrapper --release: a good approval exits 0 after reading the record",
    r.returncode == 0 and c.count("gh api") == 2, (r.returncode, r.stdout, r.stderr, c))
r, c = wrap_rel(ref=None)
check("wrapper --release: no record exits 1", r.returncode == 1, (r.returncode, r.stdout, r.stderr))
r, c = wrap_rel(ref_err="gh: HTTP 502")
check("wrapper --release: an API error exits 3", r.returncode == 3, (r.returncode, r.stderr))
r, c = wrap_rel(obj_text=tagobj(["no line"]))
check("wrapper --release: a tag without the approval line exits 1", r.returncode == 1, (r.returncode, r.stdout,
    r.stderr))
r, c = wrap_rel(tag="v0.3.2", ref=None)
check("wrapper --release: a patch tag exits 0 and calls nothing", r.returncode == 0 and c == "", (r.returncode, c))

# the writer's release mode: the commit to be tagged must be on main (the whole release is the commit main holds),
# the same dispatcher rule
CMP = {"status": "ahead", "ahead_by": 4, "behind_by": 0}
def plan_rel(cmp=CMP, head=HEAD, actor="fosterstack-admin", policy=WRITERS):
    return A.plan_release(head, cmp, actor, policy)
ok, why = plan_rel()
check("plan release: a commit that main contains (main is ahead of it) may be recorded", ok and why == "", (ok, why))
ok, why = plan_rel(cmp={"status": "identical"})
check("plan release: the tip of main itself may be recorded", ok, (ok, why))
for name, kw in (("a commit main does not contain (diverged)", dict(cmp={"status": "diverged"})),
    ("a commit ahead of main", dict(cmp={"status": "behind"})),
                 ("no answer", dict(cmp=None)), ("a malformed answer", dict(cmp=[])),
                     ("an actor who is not a dispatcher", dict(actor="someone")),
                 ("a head that is not 40 hex", dict(head="abc")), ("no policy", dict(policy=None))):
    ok, why = plan_rel(**kw); check("plan release refused: " + name, (not ok) and bool(why), (ok, why))

# release mode of the prepare and request scripts (fake gh answers `api .../compare/...`)
def gh_cmp(status, fail=False):
    open(fake + "/gh", "w").write('''#!/usr/bin/env bash
echo "gh $*" >> "$CALLS"
case "$1 $2" in
  "api repos/o/r/compare/"*)
    [ -n "$CMP_FAIL" ] && { echo "HTTP 502" >&2; exit 1; }
    if [ "$3" = -q ]; then echo "$CMP_STATUS"; else echo "{\\"status\\": \\"$CMP_STATUS\\"}"; fi ;;
  "api repos/o/r/git/ref/heads/audit/"*) echo "gh: Not Found (HTTP 404)" >&2; exit 1 ;;
  "api repos/o/r/commits/"*"/pulls"*) echo "[]" ;;
  "workflow run") exit 0 ;;
  *) echo "UNEXPECTED $*" >> "$CALLS"; exit 9 ;;
esac
''')
def run_rel(script, args, status="ahead", fail=False, actor="fosterstack-admin"):
    gh_cmp(status)
    fk = tempfile.mkdtemp(dir=d); calls = os.path.join(fk, "calls"); open(calls, "w").close()
    cwd = tempfile.mkdtemp(dir=d)
    for name in ("bin", ".github"): os.symlink(os.path.join(wroot, name), os.path.join(cwd, name))
    env = dict(os.environ, PATH=fake + ":" + os.environ["PATH"], CALLS=calls, CMP_STATUS=status,
        CMP_FAIL=("1" if fail else ""), GITHUB_REPOSITORY="o/r", GH_TOKEN="x", AUDIT_ACTOR=actor)
    r = subprocess.run(["bash", script] + args, capture_output=True, text=True, env=env, cwd=cwd)
    f = os.path.join(cwd, "audit-record")
    return r, open(calls).read(), (open(f).read() if os.path.exists(f) else None)
for name, dst in (("audit-record-request.sh", None),):
    open(wroot + "/bin/" + name, "w").write(open(os.path.join(os.path.dirname(JUDGE_SH), name)).read())
    os.chmod(wroot + "/bin/" + name, 0o755)
open(wroot + "/bin/audit-record-prepare.sh", "w").write(open(PREP_SH).read())
r, c, f = run_rel("bin/audit-record-prepare.sh", ["release", HEAD])
check("prepare release: a commit main contains, a named dispatcher, no record yet -> proceed, file = commit",
    r.returncode == 0 and r.stdout.strip().splitlines()[-1] == "proceed" and f == HEAD + "\n", (r.returncode, r.stdout,
    r.stderr, f))
r, c, f = run_rel("bin/audit-record-prepare.sh", ["release", HEAD], status="identical")
check("prepare release: the tip of main itself -> proceed", r.returncode == 0 and "proceed" in r.stdout, (r.returncode,
    r.stdout, r.stderr))
for name, kw in (("a commit main does not contain", dict(status="diverged")), ("a commit ahead of main",
    dict(status="behind")), ("an actor who is not a dispatcher", dict(actor="someone")), ("an API error comparing",
    dict(fail=True))):
    r, c, f = run_rel("bin/audit-record-prepare.sh", ["release", HEAD], **kw)
    check("prepare release refused: %s -> exit 1, nothing written" % name,
        r.returncode == 1 and f is None and "proceed" not in r.stdout, (r.returncode, r.stdout, r.stderr))
r, c, f = run_rel("bin/audit-record-request.sh", ["release", HEAD])
check("request release: a commit on main -> the record job is started with audit_pr=release",
    r.returncode == 0
    and ("workflow run agent-review-gate.yml -R o/r --ref main -f audit_pr=release -f audit_head=" + HEAD)
    in c.replace("fosterstack/cache", "o/r"), (r.returncode, r.stdout, r.stderr, c))
r, c, f = run_rel("bin/audit-record-request.sh", ["release", HEAD], status="diverged")
check("request release: a commit not on main -> nothing requested, exit 1",
    r.returncode == 1 and "workflow run" not in c, (r.returncode, r.stderr, c))

# the admission step: after the tag's signature and the on-main check, main's copies only,
# the job's own read token, nothing swallowed
def adm_problems(w):
    steps = w["jobs"]["admit"]["steps"]
    names = [x.get("name", "") for x in steps]
    idx = [i for i, n in enumerate(names) if n.startswith("a passed whole-release audit")]
    if len(idx) != 1: return ["the whole-release audit step is not there exactly once"]
    i = idx[0]; bad = []
    if not any("verify the annotated tag signature" in n for n in names[:i]):
        bad.append("it must come after the tag signature check")
    if not any(n == "the tagged commit must be on main" for n in names[:i]):
        bad.append("it must come after the on-main check")
    st = steps[i]
    if st.get("env") != {"GH_TOKEN": "${{ github.token }}"} or set(st) - {"name", "env",
        "run"}: bad.append("env or keys")
    run = re.sub(r" \\\n\s*", " ", st.get("run", ""))     # a line wrapped with a backslash reads as one line
    for need in ("set -euo pipefail", "git show origin/main:bin/audit-record.py",
        "git show origin/main:bin/audit-record-judge.sh", "git show origin/main:.github/policy/audit-writers.json",
                 'bash /tmp/audit-root/bin/audit-record-judge.sh "${GITHUB_SHA}" main '
                 '--release "${GITHUB_REF_NAME}" /tmp/tag-object'):
        if need not in run: bad.append("lacks: " + need)
    if re.search(r"\|\|\s*(true|:)|continue-on-error",
        run) or "${{" in run: bad.append("swallows a failure or interpolates an expression")
    return bad
root_repo = os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[1])))
adm = yaml.load(open(root_repo + "/.github/workflows/stage-admission.yml"), Loader=yaml.BaseLoader)
check("stage-admission.yml: the whole-release audit step is the reviewed one", adm_problems(adm) == [],
    adm_problems(adm))
def adm_mut(fn):
    m = copy.deepcopy(adm); fn(m["jobs"]["admit"]["steps"]); return m
for name, fn, frag in (
    ("the step removed", lambda st: st.pop([i for i, x in enumerate(st) if x.get("name",
        "").startswith("a passed whole-release audit")][0]), "exactly once"),
    ("a swallowed failure", lambda st: [x.update({"run": x["run"] + "\n|| true"}) for x in st if x.get("name",
        "").startswith("a passed whole-release audit")], "swallows"),
    ("a continue-on-error", lambda st: [x.update({"continue-on-error": "true"}) for x in st if x.get("name",
        "").startswith("a passed whole-release audit")], "env or keys"),
    ("the tagged commit's own judge",
        lambda st: [x.update({"run": x["run"].replace("git show origin/main:bin/audit-record.py",
        "cp bin/audit-record.py")}) for x in st if x.get("name", "").startswith("a passed whole-release audit")],
        "lacks"),
    ("a non-release mode", lambda st: [x.update({"run": x["run"].replace(" --release ",
        " --verify ")}) for x in st if x.get("name", "").startswith("a passed whole-release audit")], "lacks"),
):
    probs = adm_problems(adm_mut(fn))
    check("stage-admission.yml: a copy with %s is refused" % name, any(frag in x for x in probs), probs)

# A PULL REQUEST DEPENDABOT OPENED (owner RATIFIED Nov 11 2026): the Dependabot reviewer is its review. With no passing
# record its head passes on the reviewer's success and nothing else; no verdict is no pass, on a patch as on a major.
OURS = {"id": 11, "full_name": "o/r"}
DEP = {"number": 7, "state": "open", "merged": False, "title": "Bump left-pad from 1.2.3 to 1.2.4",
       "body": "Bumps left-pad from 1.2.3 to 1.2.4.", "user": {"login": "dependabot[bot]", "id": 49699333, "type": "Bot"},
       "head": {"sha": HEAD, "ref": "dependabot/pip/left-pad-1.2.4", "repo": OURS}, "base": {"ref": "main", "repo": OURS}}
check("bump: an open pull request into main that Dependabot opened from its own branch of the repository is one",
      A.dependabot_pull(DEP) is True, A.dependabot_pull(DEP))
for name, pr in (
    ("another author", mut(DEP, ["user", "login"], "fosterstack-admin")),
    ("Dependabot's login with another id", mut(DEP, ["user", "id"], 5)),
    ("Dependabot's id with another login", mut(DEP, ["user", "login"], "dependabot")),
    ("an author that is not a bot", mut(DEP, ["user", "type"], "User")),
    ("no author", mut(DEP, ["user"], None)),
    ("a branch that is not dependabot/", mut(DEP, ["head", "ref"], "feat/dependabot/x")),
    ("a branch named dependabot with no slash", mut(DEP, ["head", "ref"], "dependabot-fix")),
    ("no branch name", mut(DEP, ["head", "ref"], A)),
    ("a fork (the head is in another repository)", mut(DEP, ["head", "repo"], {"id": 12, "full_name": "x/r"})),
    ("a head repository that is gone", mut(DEP, ["head", "repo"], None)),
    ("a repository id that is a string", mut(mut(DEP, ["head", "repo"], {"id": "11"}), ["base", "repo"], {"id": "11"})),
    ("another base", mut(DEP, ["base", "ref"], "chain-v030")),
    ("a closed pull request", mut(DEP, ["state"], "closed")),
    ("no head block", mut(DEP, ["head"], A)), ("no base block", mut(DEP, ["base"], A)),
    ("a malformed answer", []), ("no answer", None),
):
    check("bump: not a Dependabot pull request: " + name, A.dependabot_pull(pr) is False, A.dependabot_pull(pr))

# whose head it is: exactly one open pull request, Dependabot's (the check run is the commit's, so every pull request on it would pass)
HUMAN = mut(mut(mut(DEP, ["user"], {"login": "fosterstack-admin", "id": 9, "type": "User"}), ["head", "ref"], "feat/x"), ["number"], 8)
check("bump: the one open pull request on the head, Dependabot's, is the one judged", A.bump_pull(HEAD, [DEP]) == DEP)
check("bump: a closed pull request on the same head changes nothing", A.bump_pull(HEAD, [DEP, mut(HUMAN, ["state"], "closed")]) == DEP)
check("bump: a closed pull request whose head sha cannot be read changes nothing", A.bump_pull(HEAD, [DEP, mut(mut(HUMAN, ["state"], "closed"), ["head", "sha"], None)]) == DEP)
check("bump: a pull request on another head changes nothing", A.bump_pull(HEAD, [DEP, mut(HUMAN, ["head", "sha"], "c" * 40)]) == DEP)
for name, pulls in (
    ("a human pull request shares the head with Dependabot's", [DEP, HUMAN]),
    ("a human pull request into another base shares the head", [DEP, mut(HUMAN, ["base", "ref"], "chain-v030")]),
    ("only a human pull request has the head", [HUMAN]),
    ("two Dependabot pull requests have the head", [DEP, mut(DEP, ["number"], 8)]),
    ("Dependabot's pull request has another head", [mut(DEP, ["head", "sha"], "c" * 40)]),
    ("the answer is a full page of 100", [DEP] + [mut(HUMAN, ["state"], "closed")] * 99),
    ("an item is not a pull request", [DEP, "x"]), ("an item has no state", [DEP, mut(HUMAN, ["state"], A)]),
    ("an item has no head", [DEP, mut(HUMAN, ["head"], None)]),
    ("an item has an empty head", [DEP, mut(HUMAN, ["head"], {})]),
    ("an item's head sha is null", [DEP, mut(HUMAN, ["head", "sha"], None)]),
    ("an item's head sha is not 40 lower-case hex", [DEP, mut(HUMAN, ["head", "sha"], HEAD.upper())]),
    ("another open pull request's head sha is this head and a newline", [DEP, mut(HUMAN, ["head", "sha"], HEAD + "\n")]),
    ("an item's state is neither open nor closed", [DEP, mut(HUMAN, ["state"], "OPEN")]),
    ("no pull request at all", []), ("the answer is not a list", DEP), ("no answer", None),
):
    check("bump: the record rule stands when " + name, A.bump_pull(HEAD, pulls) is None, A.bump_pull(HEAD, pulls))

def run(i, conclusion="success", slug="fosterstack-automation", name="dependabot-reviewer", status="completed"):
    return {"id": i, "name": name, "status": status, "conclusion": conclusion, "app": {"id": 5054756, "slug": slug}}
def runs(*rs):
    return {"total_count": len(rs), "check_runs": list(rs)}
def verdict(answer):
    return A.reviewer_verdict(answer, {"fosterstack-automation[bot]"})
for name, answer, want in (
    ("no check run", runs(), A.NO_RUN),
    ("the reviewer's success", runs(run(1)), "success"),
    ("the reviewer's failure", runs(run(1, "failure")), "failure"),
    ("a neutral check (a re-review that did not finish)", runs(run(1, "neutral")), "neutral"),
    ("a failure after a success: the newest counts", runs(run(1), run(2, "failure")), "failure"),
    ("a success after a failure: the newest counts", runs(run(2), run(1, "failure")), "success"),
    ("a success from another App", runs(run(1, slug="github-actions")), A.NO_RUN),
    ("another App's success after the reviewer's failure", runs(run(1, "failure"), run(2, slug="someone")), "failure"),
    ("a success under another check name", runs(run(1, name="dependabot reviewer")), A.NO_RUN),
    ("a check run still in progress", runs(run(1, None, status="in_progress")), "unfinished"),
    ("a completed run that was cancelled", runs(run(1, "cancelled")), "cancelled"),
    ("a completed run whose conclusion is the word none (not the absence of a run)", runs(run(1, "none")), "none"),
    ("a completed run with no conclusion", runs(run(1, None)), None),
    ("a list GitHub cut (more runs than it returned)", {"total_count": 2, "check_runs": [run(1)]}, None),
    ("an entry with no App", runs(dict(run(1), app=None)), None),
    ("an entry whose App has no slug", runs(dict(run(1), app={"id": 5054756})), None),
    ("an entry whose App slug is not a string", runs(dict(run(1), app={"slug": 5})), None),
    ("a failure whose App slug is empty", runs(dict(run(1, "failure"), app={"id": 5054756, "slug": ""})), None),
    ("an entry with no name", runs({k: v for k, v in run(1).items() if k != "name"}), None),
    ("an entry whose name is not a string", runs(dict(run(1), name=None)), None),
    ("a failure whose name is empty", runs(run(1, "failure", name="")), None),
    ("an entry with no name next to the reviewer's success", runs(run(1), dict(run(2), name=None)), None),
    ("an entry without an id", runs(dict(run(1), id=None)), None),
    ("a malformed entry", runs("x"), None), ("a malformed answer", [], None), ("no answer", None, None),
):
    check("bump: the reviewer's verdict: %s -> %s" % (name, want), verdict(answer) == want, verdict(answer))
check("bump: the word none is not the absence of a run", verdict(runs(run(1, "none"))) is not A.NO_RUN)

# the walk: success on the head, or on a head it only merges main into; nothing else passes, and no verdict is no pass
CHAIN = {"h2": "h1", "h1": "h0"}      # h2 is h1 with main merged in, h1 is h0 with main merged in, h0 is more than a merge
def passes(head="h2", verdicts=None, parents=CHAIN):
    asked = []
    def verdict_of(c):
        asked.append(c); return (verdicts or {}).get(c, A.NO_RUN)
    ok, said = A.bump_passes(head, verdict_of, lambda c: (parents or {}).get(c))
    return ok, said, asked
ok, said, asked = passes()
check("bump: no verdict on the head or on any head it only updates is no pass; each was asked", (not ok) and asked == ["h2", "h1", "h0"] and "no verdict" in said, (ok, said, asked))
for name, kw, want in (
    ("the reviewer's success on the head", dict(verdicts={"h2": "success"}), True),
    ("no verdict on the head, success on the head it only updates", dict(verdicts={"h1": "success"}), True),
    ("success two updates back", dict(verdicts={"h0": "success"}), True),
    ("success on the parent, but the head is not only an update of it", dict(verdicts={"h1": "success"}, parents={}), False),
    ("the reviewer's failure on the head, success on its parent", dict(verdicts={"h2": "failure", "h1": "success"}), False),
    ("a neutral check on the head, success on its parent", dict(verdicts={"h2": "neutral", "h1": "success"}), False),
    ("an unfinished check on the head", dict(verdicts={"h2": "unfinished", "h1": "success"}), False),
    ("an unreadable verdict on the head", dict(verdicts={"h2": None, "h1": "success"}), False),
    ("no verdict on the head, failure on its parent, success before that", dict(verdicts={"h1": "failure", "h0": "success"}), False),
    ("no verdict on the head, a neutral check on its parent", dict(verdicts={"h1": "neutral"}), False),
):
    ok, said, asked = passes(**kw)
    check("bump: %s -> %s" % (name, "passes" if want else "refused"), ok is want and bool(said), (ok, said, asked))
LONG = {"u%d" % i: "u%d" % (i + 1) for i in range(A.MAX_UPDATES + 5)}
ok, said, asked = passes(head="u0", verdicts={"u%d" % A.MAX_UPDATES: "success"}, parents=LONG)
check("bump: a success exactly %d updates back still counts" % A.MAX_UPDATES, ok, (ok, said, len(asked)))
ok, said, asked = passes(head="u0", verdicts={"u%d" % (A.MAX_UPDATES + 1): "success"}, parents=LONG)
check("bump: the judge follows at most %d updates back" % A.MAX_UPDATES, (not ok) and len(asked) == A.MAX_UPDATES + 1, (ok, said, len(asked)))

ok, why = plan(pr=DEP)
check("plan refused: no record is written for a pull request Dependabot opened", (not ok) and "Dependabot" in why, (ok, why))
ok, why = plan(pr=mut(DEP, ["user", "login"], "fosterstack-admin"))
check("plan: the same pull request opened by anyone else may be recorded", ok, (ok, why))
r, c = wrap_rel(ref=None)
check("bump: --release mode asks for no pull request", r.returncode == 1 and "/pulls" not in c, (r.returncode, r.stdout, c))

# the wrapper over a real repository: main, the bump's commit, heads that bring main in, and heads that carry more
G = os.path.join(d, "gate"); os.makedirs(G + "/bin"); os.makedirs(G + "/.github/policy")
BIN = os.path.dirname(JUDGE_SH)
for name in ("audit-record.py", "audit-record-judge.sh", "audit-record-prepare.sh"):
    open(G + "/bin/" + name, "w").write(open(os.path.join(BIN, name)).read())
POLICY = G + "/.github/policy/audit-writers.json"
open(POLICY, "w").write(json.dumps(WRITERS))
genv = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid", GIT_COMMITTER_NAME="t",
            GIT_COMMITTER_EMAIL="t@example.invalid", GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull)
def git(*args):
    return subprocess.run(("git", "-C", G) + args, capture_output=True, text=True, env=genv, check=True).stdout.strip()
def commit(path, text, msg):
    open(os.path.join(G, path), "w").write(text); git("add", "-A"); git("commit", "-q", "-m", msg)
    return git("rev-parse", "HEAD")
git("init", "-q", "-b", "main")
commit("ours.txt", "one\n", "main")
git("checkout", "-q", "-b", "side"); SIDE = commit("side.txt", "not on main\n", "a commit main does not have")
git("checkout", "-q", "-b", "bump", "main"); D = commit("pins.txt", "left-pad==1.2.4\n", "Bump left-pad")
git("checkout", "-q", "main"); M1 = commit("ours.txt", "two\n", "main moves")
git("checkout", "-q", "bump"); git("merge", "-q", "--no-ff", "-m", "Merge branch 'main' into bump", "main"); U1 = git("rev-parse", "HEAD")
git("checkout", "-q", "main"); commit("ours.txt", "three\n", "main moves again")
git("checkout", "-q", "bump"); git("merge", "-q", "--no-ff", "-m", "Merge branch 'main' into bump", "main"); U2 = git("rev-parse", "HEAD")
git("checkout", "-q", "--detach", D); MEND = commit("mend.txt", "ours, mended for 1.2.4\n", "a writer's commit on the bump")
git("merge", "-q", "--no-ff", "-m", "Merge branch 'main' into bump", "main"); MENDUP = git("rev-parse", "HEAD")
git("checkout", "-q", "--detach", D); git("merge", "-q", "--no-ff", "--no-commit", M1)
EVIL = commit("extra.txt", "rides along\n", "Merge branch 'main' into bump")
git("checkout", "-q", "--detach", D); git("merge", "-q", "--no-ff", "-m", "Merge branch 'side' into bump", SIDE); OFF = git("rev-parse", "HEAD")
git("checkout", "-q", "main")
check("bump fixture: the update heads have two parents, the bump and the mend one",
      [len(git("rev-list", "--parents", "-n", "1", c).split()) for c in (D, U1, U2, MEND, MENDUP, EVIL, OFF)] == [2, 3, 3, 2, 3, 3, 3])
open(fake + "/gh", "w").write('''#!/usr/bin/env bash
echo "gh $*" >> "$CALLS"
sha=${2#repos/o/r/commits/}; sha=${sha%%[/?]*}
case "$2" in
  repos/o/r/git/ref/heads/audit/*) f="$FAKE/ref"; none="" ;;
  repos/o/r/commits/*/pulls\\?per_page=100) f="$FAKE/pulls-$sha"; none="[]" ;;
  repos/o/r/commits/*/check-runs\\?check_name=dependabot-reviewer\\&filter=all\\&per_page=100) f="$FAKE/checks-$sha"; none='{"total_count": 0, "check_runs": []}' ;;
  repos/o/r/commits/*) f="$FAKE/commit"; none="" ;;
  repos/o/r/pulls/*) f="$FAKE/pr"; none="" ;;
  *) echo "UNEXPECTED $*" >> "$CALLS"; exit 9 ;;
esac
if [ -f "$f.err" ]; then cat "$f.err" >&2; exit 1; fi
if [ -f "$f.json" ]; then cat "$f.json"; elif [ -n "$none" ]; then echo "$none"; else echo "gh: Not Found (HTTP 404)" >&2; exit 1; fi
''')
def dep(head, **kw):
    pr = mut(DEP, ["head", "sha"], head)
    for k, v in kw.items(): pr[k] = v
    return pr
def gate(head, pulls=None, verdicts=None, files=None, errs=None, script=None, root=G, base_ref="main", policy=WRITERS, more=None):
    fk = tempfile.mkdtemp(dir=d)
    def put(name, obj): open(os.path.join(fk, name), "w").write(obj if isinstance(obj, str) else json.dumps(obj))
    if pulls is not None: put("pulls-%s.json" % head, pulls)
    for sha, rs in (verdicts or {}).items(): put("checks-%s.json" % sha, rs if isinstance(rs, dict) else runs(*rs))
    for name, obj in (files or {}).items(): put(name + ".json", obj)
    for name, text in (errs or {}).items(): put(name + ".err", text)
    calls = os.path.join(fk, "calls"); open(calls, "w").close()
    env = dict(os.environ, PATH=fake + ":" + os.environ["PATH"], FAKE=fk, CALLS=calls, GITHUB_REPOSITORY="o/r", GH_TOKEN="x", AUDIT_ACTOR="fosterstack-admin")
    env.update(more or {})
    cwd = tempfile.mkdtemp(dir=d)
    cmd = ["bash", root + "/bin/audit-record-judge.sh", head, base_ref] if script is None else ["bash", root + "/bin/" + script, "7", head]
    if policy is None: os.remove(POLICY)
    else: open(POLICY, "w").write(policy if isinstance(policy, str) else json.dumps(policy))
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=root if script else cwd)
    finally:
        open(POLICY, "w").write(json.dumps(WRITERS))
    return r, open(calls).read()
def said(r, c): return (r.returncode, r.stdout, r.stderr, c)
def refused(r, why): return r.returncode == 1 and r.stdout.startswith("audit-record: Dependabot pull request #7: ") and why in r.stdout
def stands(r, c): return r.returncode == 1 and "no passed-audit record for this head" in r.stdout and "check-runs" not in c

# the reviewer's success passes; no verdict does not, whatever the bump is
r, c = gate(D, pulls=[dep(D)], verdicts={D: [run(1)]})
check("gate: a bump the reviewer passed on this head passes with no record; GitHub is asked for the record, the pull request and the verdict, and nothing else",
      r.returncode == 0 and "Dependabot pull request #7 needs no passed-audit record: the Dependabot reviewer passed this head" in r.stdout
      and c.count("gh api") == 3 and "check-runs?check_name=dependabot-reviewer&filter=all&per_page=100" in c, said(r, c))
r, c = gate(D, pulls=[dep(D)])
check("gate refused: a plain patch bump the reviewer has not read (no verdict is no pass)", refused(r, "it has no verdict") and c.count("gh api") == 3, said(r, c))
r, c = gate(U2, pulls=[dep(U2)])
check("gate refused: the same bump with main merged in twice and no verdict on any head; each was asked", refused(r, "it has no verdict") and c.count("check-runs") == 3, said(r, c))
r, c = gate(U1, pulls=[dep(U1)], verdicts={D: [run(1)]})
check("gate: a head that is the passed head with main merged in passes at once, with no verdict of its own",
      r.returncode == 0 and ("the Dependabot reviewer passed %s, and this head only merges main into it" % D) in r.stdout, said(r, c))
r, c = gate(U2, pulls=[dep(U2)], verdicts={D: [run(1)]})
check("gate: ... and so does a head two such updates on", r.returncode == 0 and c.count("check-runs") == 3, said(r, c))

# a verdict other than success is never passed over
for name, head, verdicts in (
    ("the reviewer failed the head", D, {D: [run(1, "failure")]}),
    ("the reviewer's re-review of the head did not finish (neutral)", D, {D: [run(1), run(2, "neutral")]}),
    ("the reviewer failed the head this one only updates", U1, {D: [run(1, "failure")]}),
    ("the reviewer failed this head, though it passed the one before", U1, {U1: [run(2, "failure")], D: [run(1)]}),
    ("the head before was passed and then failed", U1, {D: [run(1), run(2, "failure")]}),
    ("a check entry on the head has no name, though the head before was passed", U1, {U1: runs({k: v for k, v in run(3).items() if k != "name"}), D: [run(1)]}),
    ("a failure on the head has an empty name, though the head before was passed", U1, {U1: [run(3, "failure", name="")], D: [run(1)]}),
    ("a failure on the head has an empty App slug, though the head before was passed", U1, {U1: [run(3, "failure", slug="")], D: [run(1)]}),
    ("a check entry on the head has no App, though the head before was passed", U1, {U1: runs(dict(run(3), app=None)), D: [run(1)]}),
    ("the list of check runs on the head is cut", U1, {U1: {"total_count": 2, "check_runs": [run(3, slug="github-actions")]}, D: [run(1)]}),
    ("the reviewer's completed run on the head has the conclusion none, though the head before was passed", U1, {U1: [run(3, "none")], D: [run(1)]}),
):
    r, c = gate(head, pulls=[dep(head)], verdicts=verdicts)
    check("gate refused: " + name, refused(r, "newest verdict on") and "not success" in r.stdout, said(r, c))
r, c = gate(D, pulls=[dep(D)], verdicts={D: [run(1, slug="github-actions")]})
check("gate refused: a bump that only another App passed", refused(r, "it has no verdict"), said(r, c))

# any other commit on the bump needs the reviewer's success on a head that contains it, with only clean merges of main after it
for name, head in (("carries a writer's commit on top of the passed head", MEND), ("carries a writer's commit and then main merged in", MENDUP),
                   ("is a merge with main that carries a file of its own", EVIL), ("merges in a commit that main does not have", OFF)):
    r, c = gate(head, pulls=[dep(head)], verdicts={D: [run(1)]})
    check("gate refused: a head that %s, though the reviewer passed the bump under it" % name, refused(r, "it has no verdict"), said(r, c))
r, c = gate(MEND, pulls=[dep(MEND)], verdicts={MEND: [run(2)]})
check("gate: the head with a writer's commit passes once the reviewer has passed that very head", r.returncode == 0 and "passed this head" in r.stdout, said(r, c))
r, c = gate(MENDUP, pulls=[dep(MENDUP)], verdicts={MEND: [run(2)]})
check("gate: ... and so does that head with main merged in", r.returncode == 0, said(r, c))

# whose head it is
OTHER = dict(number=8, user={"login": "x", "id": 9, "type": "User"})
for name, pulls in (("a human pull request shares the head with Dependabot's", [dep(D), dep(D, **OTHER)]),
                    ("another open pull request's head sha is this head and a newline", [dep(D), mut(dep(D, **OTHER), ["head", "sha"], D + "\n")]),
                    ("another entry has an empty head", [dep(D), mut(dep(D, **OTHER), ["head"], {})]),
                    ("another entry's head sha is null", [dep(D), mut(dep(D, **OTHER), ["head", "sha"], None)]),
                    ("another entry's state is unknown", [dep(D), dep(U1, number=8, state="draft")]),
                    ("somebody else opened it", [dep(D, user={"login": "fosterstack-harness[bot]", "id": 7, "type": "Bot"})]),
                    ("it comes from a fork", [mut(dep(D), ["head", "repo"], {"id": 12, "full_name": "x/r"})]),
                    ("its branch is not dependabot/", [mut(dep(D), ["head", "ref"], "feat/bump")]),
                    ("it is closed", [dep(D, state="closed")]), ("it is into another branch", [mut(dep(D), ["base", "ref"], "chain-v030")]),
                    ("the Dependabot pull request GitHub names has another head", [dep(U1)]),
                    ("two Dependabot pull requests have the head", [dep(D), dep(D, number=8)]),
                    ("GitHub answers a full page of 100 pull requests", [dep(D)] + [dep(D, state="closed")] * 99),
                    ("no pull request has the head", [])):
    r, c = gate(D, pulls=pulls, verdicts={D: [run(1)]})
    check("gate: %s: the record rule stands (exit 1, no record, no verdict asked for)" % name, stands(r, c) and c.count("gh api") == 2, said(r, c))
r, c = gate(D, pulls=[dep(D)], verdicts={D: [run(1, "failure")]}, files={"ref": mut(REF, ["ref"], "refs/heads/audit/" + D), "commit": mut(COMMIT, ["parents"], [{"sha": D}])})
check("gate: a passed-audit record on the exact head also passes the gate, and nothing more is asked (the reviewer's failure is the merger's to refuse)",
      r.returncode == 0 and "passed-audit record found" in r.stdout and c.count("gh api") == 2 and "/pulls" not in c, said(r, c))

# the writers policy comes first: without it nothing is exempt, and GitHub is not asked whose head it is
for name, policy in (("missing", None), ("malformed", "{not json"), ("without writers", {"schema": 1, "writers": [], "dispatchers": ["fosterstack-admin"]})):
    r, c = gate(D, pulls=[dep(D)], verdicts={D: [run(1)]}, policy=policy)
    check("gate refused: a writers policy that is %s exempts nothing, and no pull request is asked for" % name,
          r.returncode == 1 and "audit writers policy" in r.stdout and "/pulls" not in c, said(r, c))

# doubts and errors
r, c = gate(U1, pulls=[dep(U1)], verdicts={D: [run(1)]}, root=root)
check("gate refused: where the head's commits cannot be read (no git objects), a parent's success is not taken", refused(r, "it has no verdict"), said(r, c))
for name, errs in (("the pull request", {"pulls-" + D: "gh: HTTP 502: Bad Gateway"}), ("the reviewer's verdict", {"checks-" + D: "gh: HTTP 403: rate limit exceeded"})):
    r, c = gate(D, pulls=[dep(D)], errs=errs)
    check("gate: a GitHub API error asking for %s exits 3 and says it is an API error" % name, r.returncode == 3 and "GitHub API error" in r.stderr and r.stdout == "", said(r, c))
r, c = gate(D, pulls=[dep(D)], verdicts={D: [run(1)]}, base_ref="chain-v030")
check("gate: a base that is not main still passes without asking anything", r.returncode == 0 and c == "", said(r, c))
r, c = gate(D, pulls=[dep(D)], verdicts={D: [run(1)]}, base_ref="", more={"repo": "o/r"})
check("gate: a repo variable inherited from the caller is not used: an empty base exits 1 and asks nothing", r.returncode == 1 and c == "", said(r, c))

fk = tempfile.mkdtemp(dir=d); open(fk + "/calls", "w").close()
r = subprocess.run([sys.executable, "-I", G + "/bin/audit-record.py", "bump", "--head", D + "\n", "--repo", "o/r", "--base-root", G], capture_output=True, text=True,
                   env=dict(os.environ, PATH=fake + ":" + os.environ["PATH"], FAKE=fk, CALLS=fk + "/calls"))
check("bump cli: a head that is 40 hex and a newline exits 1 with no line and asks nothing", r.returncode == 1 and r.stdout == "" and open(fk + "/calls").read() == "", (r.returncode, r.stdout, r.stderr))

# the writer: no record for a pull request Dependabot opened, whatever the reviewer says of it
for name, verdicts in (("passed by the reviewer", {D: [run(1)]}), ("not read by the reviewer yet", {})):
    r, c = gate(D, pulls=[dep(D)], verdicts=verdicts, files={"pr": dep(D)}, script="audit-record-prepare.sh")
    check("prepare refused: no record is written for a Dependabot pull request %s (exit 1, nothing written)" % name,
          r.returncode == 1 and "proceed" not in r.stdout and "Dependabot opened the pull request" in r.stderr and not os.path.exists(G + "/audit-record"), said(r, c))
r, c = gate(D, files={"pr": dep(D, user={"login": "fosterstack-admin", "id": 9, "type": "User"})}, script="audit-record-prepare.sh")
wrote = os.path.exists(G + "/audit-record")
if wrote: os.remove(G + "/audit-record")
check("prepare: the same pull request opened by anyone else is recorded as before (proceed)", r.returncode == 0 and r.stdout.strip().splitlines()[-1] == "proceed" and wrote, said(r, c))

print("audit-record: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
PY
