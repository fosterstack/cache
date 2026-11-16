#!/usr/bin/env bash
# proves: REQ-CI-001-AC7
# Which run backs a promotion check at stage-admission (the step "every required check green, app-pinned, per its scope"), offline:
# the step's own text runs against a stand-in for gh. A check counts only from a schedule or workflow_dispatch run, of the file that
# produces it, on the tagged commit; every check run of the name is read, and the latest run that qualifies decides;
# a run that cannot be read is an error of its own.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
python3 -I - "$root" "$work" <<'PY'
import json, os, subprocess, sys, yaml
root, work = sys.argv[1], sys.argv[2]
passed = failed = 0
def check(name, ok, got=""):
    global passed, failed
    if ok: passed += 1; print("ok:", name)
    else: failed += 1; print("FAIL:", name, "->", got)
STEP = "every required check green, app-pinned, per its scope"
adm = yaml.load(open(os.path.join(root, ".github/workflows/stage-admission.yml")), Loader=yaml.BaseLoader)
step = [s for s in adm["jobs"]["admit"]["steps"] if s.get("name") == STEP][0]["run"]
# gh api: check runs honour filter=latest (the newest run of each name and app); a workflow run is a file, or answers 403 when marked
FAKE_GH = r'''#!/usr/bin/env python3
import json, os, subprocess, sys
a = sys.argv[1:]
path, _, query = a[1].partition("?")
fx = os.environ["FX"]
def name(p): return os.path.join(fx, p.strip("/").replace("/", "_"))
if os.path.exists(name(path) + ".403"):
    sys.stderr.write("gh: Resource not accessible by integration (HTTP 403)\n"); sys.exit(1)
if not os.path.exists(name(path) + ".json"):
    if path.endswith("/status"): data = {"statuses": []}
    elif path.endswith("/pulls"): data = []
    else: sys.stderr.write("gh: Not Found (HTTP 404) %s\n" % path); sys.exit(1)
else: data = json.load(open(name(path) + ".json"))
if path.endswith("/check-runs") and "filter=latest" in query:
    newest = {}
    for r in data["check_runs"]:
        key = (r["name"], r["app"]["id"])
        if key not in newest or r["id"] > newest[key]["id"]: newest[key] = r
    data = {"check_runs": list(newest.values())}
filt = [a[i + 1] for i, x in enumerate(a) if x in ("--jq", "-q") and i + 1 < len(a)]
if filt:
    r = subprocess.run(["jq", "-c", filt[0]], input=json.dumps(data), capture_output=True, text=True)
    for line in r.stdout.splitlines(): print(json.loads(line) if line.startswith('"') else line)
    sys.stderr.write(r.stderr); sys.exit(r.returncode)
print(json.dumps(data))
'''
TAGGED, OTHER = "1" * 40, "2" * 40
POLICY = {"required_checks": [], "promotion_checks": [{"context": "scan", "integration_id": 15368, "scope": "push"}]}
def scan_run(id, event="workflow_dispatch", status="completed", conclusion="success", sha=TAGGED, path="scan.yml"):
    """one check run of 'scan' and the workflow run behind it"""
    return {"id": id, "event": event, "status": status, "conclusion": conclusion, "sha": sha, "path": ".github/workflows/" + path}
def admission(runs, unreadable=()):
    """run the step for a release-candidate tag; returns (exit code, output)"""
    d = os.path.join(work, "adm%d" % len(os.listdir(work)))
    for sub in ("fake", "fx", "policy"): os.makedirs(os.path.join(d, sub))
    gh = os.path.join(d, "fake/gh"); open(gh, "w").write(FAKE_GH); os.chmod(gh, 0o755)
    json.dump(POLICY, open(d + "/policy/required-checks.json", "w"))
    check_runs = []
    for r in runs:
        run_id = 9000 + r["id"]
        check_runs.append({"name": "scan", "status": r["status"], "conclusion": r["conclusion"], "app": {"id": 15368}, "id": r["id"],
                           "head_sha": TAGGED, "details_url": "https://github.com/o/r/actions/runs/%d/job/%d" % (run_id, r["id"])})
        if r["id"] in unreadable: open(d + "/fx/repos_o_r_actions_runs_%d.403" % run_id, "w").close()
        else: json.dump({"id": run_id, "path": r["path"], "event": r["event"], "head_sha": r["sha"]},
                        open(d + "/fx/repos_o_r_actions_runs_%d.json" % run_id, "w"))
    json.dump({"check_runs": check_runs}, open(d + "/fx/repos_o_r_commits_%s_check-runs.json" % TAGGED, "w"))
    env = dict(os.environ, PATH=d + "/fake:" + os.environ["PATH"], FX=d + "/fx", GITHUB_REPOSITORY="o/r", GITHUB_SHA=TAGGED,
               GITHUB_REF_NAME="v0.3.0-rc.1", GH_TOKEN="tok", GITHUB_OUTPUT=d + "/out")
    r = subprocess.run(["bash", "-e", "-c", step.replace("/tmp/", d + "/")], capture_output=True, text=True, env=env, cwd=d)
    return r.returncode, r.stdout + r.stderr
def admitted(name, runs):
    rc, out = admission(runs); check("admission: " + name + " is admitted", rc == 0, (rc, out[-300:]))
def refused(name, runs, unreadable=()):
    rc, out = admission(runs, unreadable); check("admission: " + name + " is refused, naming scan", rc != 0 and "scan" in out, (rc, out[-300:]))

# the event and the commit of the run behind a check (REQ-CI-001-AC7)
admitted("a scan success from scan.yml's workflow_dispatch run on the tagged commit", [scan_run(1)])
admitted("a scan success from scan.yml's schedule run on the tagged commit", [scan_run(1, event="schedule")])
refused("a scan success from scan.yml's push run (the tag push)", [scan_run(1, event="push")])
refused("a scan success from scan.yml's pull_request run", [scan_run(1, event="pull_request")])
refused("a scan success from a dispatch run of scan.yml on another commit", [scan_run(1, sha=OTHER)])
# every run of the name is read; the latest qualifying run decides
admitted("a running tag-push run of scan beside an earlier green dispatch run",
         [scan_run(1), scan_run(2, event="push", status="in_progress", conclusion=None)])
refused("a later failing dispatch run beside an earlier green one", [scan_run(1), scan_run(2, conclusion="failure")])
refused("a later failing dispatch run, with a tag-push run after it still running",
        [scan_run(1), scan_run(2, conclusion="failure"), scan_run(3, event="push", status="in_progress", conclusion=None)])
admitted("an earlier failing dispatch run before a later green one", [scan_run(1, conclusion="failure"), scan_run(2)])
# a run that cannot be read is no evidence, and says so in words of its own
rc, out = admission([scan_run(1)], unreadable=(1,))
check("admission: a scan run the token cannot read stops it with a message of its own, not 'is not green'",
      rc != 0 and "scan" in out and "is not green" not in out, (rc, out[-300:]))
print("admission-evidence: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
PY
