#!/usr/bin/env bash
# proves: REQ-UAT-001-AC1, REQ-UAT-001-AC2, REQ-UAT-001-AC3, REQ-UAT-001-AC4, REQ-UAT-001-AC5
# The persona UAT driver (owner ratified Oct 3 and Oct 4; ops/docs/ratify/2026-10-02-owner-load.md point 9), proved
# against a STUB agent, a recording `docker` and a recording `gh`, so no model credential, container or GitHub call is
# needed. Each case runs the real driver and inspects what it DID: which containers it started (the image by digest,
# the pinned CI tools only for the persona that needs them, all removed afterwards), what each agent was handed (an
# exact request, a scrubbed environment, a sandbox that holds only the public docs), what it wrote, which issues it
# opened, and whether the run failed. Fail-closed: anything an agent returns that is not exactly the contract counts as
# blocking. Contract (the tests pin it):
#   persona-uat.py --mode rc|weekly --image REF@sha256:... --repo DIR --out DIR --tools FILE --docker CMD --gh CMD
#                  --agent CMD [--port N] [--publish]
#   env PERSONA_UAT_MODEL, PERSONA_UAT_COMPLIANCE_MODEL (required), PERSONA_UAT_TOKEN_BUDGET (default 400000)
#   agent: one JSON request on stdin; one JSON answer on stdout {"findings":[{"kind":"blocking|friction","text":str}],
#          "tokens": int >= 0, "transcript": str}
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
driver="$root/bin/persona-uat.py"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
ok()   { pass=$((pass+1)); echo "ok   $1"; }
bad()  { failn=$((failn+1)); echo "FAIL $1"; }
CASE=""
check() { if "$@" >/dev/null 2>&1; then ok "$CASE"; else bad "$CASE"; fi; }
# none_match <regex> <path...>: every path must EXIST and nothing in them may match (a read error is a failure, never a pass)
none_match() { local re=$1; shift; local p; for p in "$@"; do [ -e "$p" ] || return 2; done; local rc=0; grep -rqE "$re" "$@" || rc=$?; [ "$rc" -eq 1 ]; }

# --- fixtures -------------------------------------------------------------------------------------------------
repo="$work/repo"; mkdir -p "$repo/docs/quality" "$repo/internal" "$repo/cmd"
echo "# fscache README" >"$repo/README.md"
echo "install steps"    >"$repo/docs/install.md"
echo "gradle steps"     >"$repo/docs/gradle.md"
echo "INTERNAL TRACE"   >"$repo/docs/quality/traceability.md"
echo "UNRELEASED NOTES" >"$repo/docs/next-release-notes.md"
echo "package internal // SECRET-SOURCE" >"$repo/internal/x.go"
mkdir -p "$repo/ops/docs" "$repo/docs/dev"
echo "SECRET-OPS-DOC"      >"$repo/ops/docs/plan.md"
echo "SECRET-CLAUDE-MD"    >"$repo/CLAUDE.md"
echo "SECRET-DEV-DOC"      >"$repo/docs/dev/notes.md"
echo "SECRET-RELEASING"    >"$repo/RELEASING.md"
echo "SECRET-DOTFILE"      >"$repo/docs/.hidden.md"
echo '{"SECRET-JSON":1}'   >"$repo/docs/grafana-dashboard.json"
ln -s ../internal/x.go "$repo/docs/leak.md"
IMG="ghcr.io/example/cache@sha256:$(printf 'a%.0s' $(seq 64))"
IMG2="ghcr.io/example/cache@sha256:$(printf 'b%.0s' $(seq 64))"
JEN="docker.io/jenkins/jenkins@sha256:$(printf '1%.0s' $(seq 64))"
GLR="docker.io/gitlab/gitlab-runner@sha256:$(printf '2%.0s' $(seq 64))"
KND="docker.io/kindest/node@sha256:$(printf '3%.0s' $(seq 64))"
SHL="docker.io/library/debian@sha256:$(printf '4%.0s' $(seq 64))"
cat >"$work/tools.json" <<EOF
{"jenkins": "$JEN", "gitlab-runner": "$GLR", "kind": "$KND", "shell": "$SHL"}
EOF
PERSONAS="gradle-platform-engineer maven-jenkins-ci compliance-reviewer readme-evaluator on-call-engineer"

# The stub agent: one request as JSON on stdin, one JSON answer on stdout. It records everything it was given.
cat >"$work/stub.py" <<'PY'
import json, os, sys
raw = sys.stdin.read()
req = json.loads(raw)
plan = json.load(open(os.environ["STUB_PLAN"]))
p = plan.get(req["persona"], {})
seen = sorted(os.path.relpath(os.path.join(d, f), req["docs_dir"]) for d, _, fs in os.walk(req["docs_dir"]) for f in fs)
content = {}
links = []
for f in seen:
    fp = os.path.join(req["docs_dir"], f)
    if os.path.islink(fp):
        links.append(f)
    try:
        content[f] = open(fp, errors="replace").read()
    except OSError as e:
        content[f] = "UNREADABLE " + str(e)
with open(os.environ["STUB_LOG"], "a") as fh:
    fh.write(json.dumps({"persona": req["persona"], "docs": seen, "keys": sorted(req), "request": req,
                         "env": sorted(os.environ), "cwd": os.getcwd(), "raw_len": len(raw), "argv": sys.argv[1:], "content": content, "links": links}) + "\n")
if p.get("crash"):
    sys.exit(7)
if "raw_out" in p:
    sys.stdout.write(p["raw_out"]); sys.exit(0)
if p.get("sleep"):
    import time; time.sleep(p["sleep"])
ans = {"findings": p.get("findings", []), "tokens": p.get("tokens", 1000), "transcript": "TRANSCRIPT for " + req["persona"] + "\n"}
ans.update(p.get("override", {}))
for k in p.get("drop", []):
    ans.pop(k, None)
print(json.dumps(ans))
PY
# A recording docker: `run -d ...` prints a container id and logs the whole line; every other call is only logged.
cat >"$work/docker" <<'SH'
#!/usr/bin/env bash
echo "$*" >>"$DOCKER_LOG"
case "$1" in
  run) n=$(grep -c '^run ' "$DOCKER_LOG"); echo "cid-$n" ;;
esac
exit 0
SH
# A recording gh: `issue list` answers GH_STUB_LIST; every call is logged with its arguments.
cat >"$work/gh" <<'SH'
#!/usr/bin/env bash
echo "$*" >>"$GH_LOG"
case "$1 $2" in
  "issue list") echo "${GH_STUB_LIST:-[]}" ;;
  "issue create") echo "https://github.com/x/y/issues/99" ;;
esac
exit 0
SH
chmod +x "$work/docker" "$work/gh"

# run <name> <plan-json> <mode> [VAR=val ...]  (sets rc; dirs under $work/<name>/)
run() {
  local name=$1 plan=$2 mode=$3; shift 3
  mkdir -p "$work/$name"; echo "$plan" >"$work/$name/plan.json"; : >"$work/$name/log"; : >"$work/$name/docker.log"; : >"$work/$name/gh.log"
  rc=0
  env -u PERSONA_UAT_TOKEN_BUDGET STUB_PLAN="$work/$name/plan.json" STUB_LOG="$work/$name/log" \
      DOCKER_LOG="$work/$name/docker.log" GH_LOG="$work/$name/gh.log" GITHUB_RUN_ID=4242 \
      GITHUB_TOKEN=SECRET-GH-TOKEN GH_TOKEN=SECRET-GH2 AWS_SECRET_ACCESS_KEY=SECRET-AWS-KEY REPO_CHECKOUT="$repo" \
      GITHUB_WORKSPACE="$repo" ACTIONS_ID_TOKEN_REQUEST_TOKEN=SECRET-OIDC ACTIONS_ID_TOKEN_REQUEST_URL=http://oidc.invalid \
      ACTIONS_RUNTIME_TOKEN=SECRET-RT ANTHROPIC_API_KEY=ALLOWED-MODEL-CRED ANTHROPIC_IDENTITY_TOKEN_FILE=/x/token \
      PERSONA_UAT_MODEL=MODEL-DEFAULT-X PERSONA_UAT_COMPLIANCE_MODEL=MODEL-COMPLIANCE-X "$@" \
      bash -c 'cd "$1" && shift && exec "$@"' _ "$repo" python3 "$driver" --mode "$mode" --image "${IMAGE:-$IMG}" --repo "$repo" --out "$work/$name/out" \
        --tools "${TOOLS:-$work/tools.json}" --docker "$work/docker" --gh "$work/gh" --port 18080 \
        --agent "python3 $work/stub.py" ${AGENT_TIMEOUT:+--agent-timeout $AGENT_TIMEOUT} ${PUBLISH+--publish} >"$work/$name/stdout" 2>"$work/$name/stderr" || rc=$?
}
out() { echo "$work/$1/out"; }
nlines() { wc -l <"$1" | tr -d ' '; }

# --- AC1: five personas, exactly these five, one report and one transcript each ----------------------------------
run clean '{}' rc
CASE="rc clean run exits 0"; check test "$rc" -eq 0
for p in $PERSONAS; do
  CASE="clean run writes one report and one transcript for $p"
  check test -s "$(out clean)/$p.report.md" -a -s "$(out clean)/$p.transcript.txt"
done
CASE="exactly the five named personas ran, once each, in their own agent call"
check python3 - "$work/clean/log" "$PERSONAS" <<'PY'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1])]
assert sorted(r["persona"] for r in rows) == sorted(sys.argv[2].split()), [r["persona"] for r in rows]
PY
CASE="each persona gets its own instructions naming its role"
check python3 - "$work/clean/log" <<'PY'
import json, sys
rows = {json.loads(l)["persona"]: json.loads(l)["request"]["instructions"] for l in open(sys.argv[1])}
want = {"gradle-platform-engineer": "gradle", "maven-jenkins-ci": "jenkins", "compliance-reviewer": "sbom",
        "readme-evaluator": "ten minutes", "on-call-engineer": "rollback"}
assert len(set(rows.values())) == 5, "instructions are not distinct"
for p, w in want.items():
    assert w in rows[p].lower(), (p, w)
PY
CASE="a clean run records no friction or blocking issue file"
check test ! -e "$(out clean)/friction-issue.md" -a ! -e "$(out clean)/blocking-issue.md"
CASE="each report states its verdict in the first line"
check test "$(head -1 "$(out clean)/on-call-engineer.report.md")" = "VERDICT: pass"

# --- AC1: the image under test starts BY DIGEST and everything is removed afterwards ------------------------------
CASE="the driver starts the image under test by digest, on loopback only, and hands that endpoint to every agent"
check python3 - "$work/clean/docker.log" "$work/clean/log" "$IMG" <<'PY'
import json, sys
runs = [l for l in open(sys.argv[1]) if l.startswith("run ")]
img = [l for l in runs if sys.argv[3] in l]
assert len(img) == 1, runs
assert "127.0.0.1:18080" in img[0], img[0]
for l in open(sys.argv[2]):
    assert json.loads(l)["request"]["endpoint"] == "http://127.0.0.1:18080"
    assert json.loads(l)["request"]["image"] == sys.argv[3]
PY
CASE="every container started is removed (rm -f) before the driver exits, even after a failure"
run blockrm '{"maven-jenkins-ci":{"findings":[{"kind":"blocking","text":"x"}]}}' rc
check python3 - "$work/clean/docker.log" "$work/blockrm/docker.log" <<'PY'
import sys
for path in sys.argv[1:]:
    lines = open(path).read().splitlines()
    started = [f"cid-{i+1}" for i, l in enumerate(x for x in lines if x.startswith("run "))]
    removed = " ".join(l for l in lines if l.startswith("rm "))
    assert started and all(c in removed for c in started), (path, started, removed)
PY
CASE="an image reference that is not pinned by digest is refused before anything starts (exit 2)"
IMAGE="ghcr.io/example/cache:latest" run tagimg '{}' rc
check test "$rc" -eq 2 -a ! -s "$work/tagimg/docker.log" -a ! -s "$work/tagimg/log"
unset IMAGE

# --- AC4: Jenkins, a GitLab runner, kind: pinned containers, only where needed, and nothing else ------------------
CASE="Jenkins and the GitLab runner start (by their pinned references) only for the Maven persona; kind only for on-call"
check python3 - "$work/clean/docker.log" "$work/clean/log" "$JEN" "$GLR" "$KND" <<'PY'
import json, sys
log = open(sys.argv[1]).read()
jen, glr, knd = sys.argv[3:6]
for ref in (jen, glr, knd):
    assert log.count(ref) == 1, (ref, log)
rows = {json.loads(l)["persona"]: json.loads(l)["request"]["tools"] for l in open(sys.argv[2])}
assert sorted(rows["maven-jenkins-ci"]) == ["gitlab-runner", "jenkins"], rows
assert sorted(rows["on-call-engineer"]) == ["kind"], rows
for p in ("gradle-platform-engineer", "compliance-reviewer", "readme-evaluator"):
    assert rows[p] == {}, (p, rows[p])
PY
CASE="the agent is told to run every shell action in the pinned shell image through the driver's docker, and nothing else"
check python3 - "$work/clean/log" "$work/clean/docker.log" "$SHL" "$work/docker" <<'PY'
import json, sys
for ln in open(sys.argv[1]):
    a = json.loads(ln)["argv"]
    assert a[a.index("--shell-image") + 1] == sys.argv[3], a
    assert a[a.index("--docker") + 1] == sys.argv[4], a
assert sys.argv[3] not in open(sys.argv[2]).read(), "the driver itself must not start the shell image: the agent does, per action"
PY
CASE="a tool in the tools file that is not pinned by digest refuses the whole run (exit 2); nothing starts"
echo '{"jenkins": "docker.io/jenkins/jenkins:lts", "gitlab-runner": "'"$GLR"'", "kind": "'"$KND"'", "shell": "'"$SHL"'"}' >"$work/tools-unpinned.json"
TOOLS="$work/tools-unpinned.json" run unpinned '{}' rc
check test "$rc" -eq 2 -a ! -s "$work/unpinned/docker.log" -a ! -s "$work/unpinned/log"
unset TOOLS
CASE="the driver provisions nothing in a cloud: its docker and gh calls are only run/rm and issue commands"
check python3 - "$work/clean/docker.log" "$work/friction/docker.log" <<'PY'
import sys
for path in sys.argv[1:]:
    for l in open(path):
        assert l.split()[0] in ("run", "rm", "stop", "kill", "logs", "exec", "pull", "inspect"), l
PY

# --- AC1: broken behavior or a failing doc step fails the RC run ------------------------------------------------
run blocking '{"maven-jenkins-ci":{"findings":[{"kind":"blocking","text":"docs/maven.md step 3 fails as written: 404"}]}}' rc
CASE="rc: a blocking finding fails the run"; check test "$rc" -ne 0
CASE="the blocking persona's report says blocking and carries the finding"
check grep -q 'VERDICT: blocking' "$(out blocking)/maven-jenkins-ci.report.md"
check grep -q 'step 3 fails as written' "$(out blocking)/maven-jenkins-ci.report.md"
CASE="the other four personas still ran and wrote reports (one failure does not hide the rest)"
check test "$(nlines "$work/blocking/log")" -eq 5 -a "$(ls "$(out blocking)"/*.report.md | wc -l | tr -d ' ')" -eq 5

# fail closed: anything that is not exactly the contract counts as blocking, "did not run", never a pass
failclosed() { # <case> <persona> <plan-for-persona-json>
  run "fc-$1" "{\"$2\":$3}" rc
  CASE="fail closed ($1): the run fails"; check test "$rc" -ne 0
  CASE="fail closed ($1): that persona's report says blocking and that it did not run"
  check grep -q 'VERDICT: blocking' "$(out "fc-$1")/$2.report.md"
  check grep -qi 'did not run' "$(out "fc-$1")/$2.report.md"
}
failclosed crash        compliance-reviewer '{"crash":true}'
failclosed garbage      readme-evaluator    '{"raw_out":"not json at all"}'
failclosed empty-object readme-evaluator    '{"raw_out":"{}"}'
failclosed truncated    on-call-engineer    '{"raw_out":"{\"findings\": [], \"tokens\": 10, \"transcr"}'
failclosed empty-out    on-call-engineer    '{"raw_out":""}'
failclosed findings-str gradle-platform-engineer '{"override":{"findings":"none"}}'
failclosed kind-bad     gradle-platform-engineer '{"findings":[{"kind":"meh","text":"x"}]}'
failclosed text-missing gradle-platform-engineer '{"findings":[{"kind":"friction"}]}'
failclosed text-notstr  gradle-platform-engineer '{"findings":[{"kind":"friction","text":5}]}'
failclosed tokens-neg   maven-jenkins-ci         '{"override":{"tokens":-1}}'
failclosed tokens-str   maven-jenkins-ci         '{"override":{"tokens":"many"}}'
failclosed tokens-gone  maven-jenkins-ci         '{"drop":["tokens"]}'
failclosed transcript-gone compliance-reviewer   '{"drop":["transcript"]}'
failclosed transcript-notstr compliance-reviewer '{"override":{"transcript":["a"]}}'
failclosed findings-gone readme-evaluator        '{"drop":["findings"]}'
CASE="a failed agent leaves its transcript file present (empty or partial) so the artifact exists for diagnosis"
check test -e "$(out fc-crash)/compliance-reviewer.transcript.txt"

# --- AC3: friction is information, one issue per run, blocks nothing -------------------------------------------
FR='{"gradle-platform-engineer":{"findings":[{"kind":"friction","text":"the proxy URL is easy to mistype"}]},"on-call-engineer":{"findings":[{"kind":"friction","text":"no log level hint"},{"kind":"friction","text":"rollback needs two reads"}]}}'
PUBLISH=1 run friction "$FR" rc
CASE="friction alone does not fail an rc run"; check test "$rc" -eq 0
CASE="friction is in exactly one issue file for the run, naming every finding and its persona"
check test "$(ls "$(out friction)" | grep -c '^friction-issue')" -eq 1
check grep -q 'proxy URL is easy to mistype' "$(out friction)/friction-issue.md"
check grep -q 'no log level hint' "$(out friction)/friction-issue.md"
check grep -q 'rollback needs two reads' "$(out friction)/friction-issue.md"
check grep -q 'on-call-engineer' "$(out friction)/friction-issue.md"
CASE="with --publish the run opens exactly ONE issue for the friction, labelled as information, never as blocking"
check python3 - "$work/friction/gh.log" <<'PY'
import sys
calls = [l.strip() for l in open(sys.argv[1])]
creates = [c for c in calls if c.startswith("issue create")]
assert len(creates) == 1, calls
c = creates[0]
assert "--label persona-uat-friction" in c and "blocking" not in c.replace("persona-uat-friction", ""), c
assert "4242" in c, "the title names the run, so two runs never share an issue: " + c
assert "--body-file" in c and "friction-issue.md" in c, c
assert not [x for x in calls if x.startswith("issue edit") or x.startswith("issue comment")], calls
PY
CASE="friction blocks nothing: a mixed run (blocking in one persona, friction in another) still publishes its friction issue, then fails (rc)"
PUBLISH=1 run mixed '{"maven-jenkins-ci":{"findings":[{"kind":"blocking","text":"jenkins step fails"}]},"gradle-platform-engineer":{"findings":[{"kind":"friction","text":"confusing proxy text"}]}}' rc
check test "$rc" -ne 0
check grep -c '^issue create' "$work/mixed/gh.log"
check python3 - "$work/mixed/gh.log" <<'PY'
import sys
calls = [l.strip() for l in open(sys.argv[1])]
assert len([c for c in calls if c.startswith("issue create") and "persona-uat-friction" in c]) == 1, calls
assert not [c for c in calls if "--label blocking" in c], "an rc run must not publish a blocking issue: " + str(calls)
PY
CASE="without --publish no gh call is made at all"
run nopub "$FR" rc
check test ! -s "$work/nopub/gh.log"
CASE="a friction-only persona's verdict is friction"
check grep -q 'VERDICT: friction' "$(out friction)/gradle-platform-engineer.report.md"

# --- AC2: the weekly run exercises the same five personas on the image it is given, and keeps ONE blocking issue ----
WK='{"maven-jenkins-ci":{"findings":[{"kind":"blocking","text":"jenkins step fails"}]},"compliance-reviewer":{"findings":[{"kind":"blocking","text":"cosign verify fails as written"}]}}'
IMAGE="$IMG2" PUBLISH=1 GH_STUB_LIST='[]' run weekly "$WK" weekly
CASE="weekly: all five personas run, on the latest-release image it was given, and each report is written"
check python3 - "$work/weekly/log" "$PERSONAS" "$IMG2" "$work/weekly/docker.log" <<'PY'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1])]
assert sorted(r["persona"] for r in rows) == sorted(sys.argv[2].split()), [r["persona"] for r in rows]
assert all(r["request"]["image"] == sys.argv[3] for r in rows)
assert sum(1 for l in open(sys.argv[4]) if l.startswith("run ") and sys.argv[3] in l) == 1
PY
check test "$(ls "$(out weekly)"/*.report.md | wc -l | tr -d ' ')" -eq 5 -a "$(ls "$(out weekly)"/*.transcript.txt | wc -l | tr -d ' ')" -eq 5
CASE="weekly with no open blocking issue: the run exits 0 and CREATES exactly one issue labelled blocking with a fixed title"
check test "$rc" -eq 0
check python3 - "$work/weekly/gh.log" <<'PY'
import sys
calls = [l.strip() for l in open(sys.argv[1])]
lists = [c for c in calls if c.startswith("issue list")]
assert lists and "--label blocking" in lists[0] and "--state open" in lists[0], calls
creates = [c for c in calls if c.startswith("issue create") and "--label blocking" in c]
assert len(creates) == 1, calls
assert "Persona UAT: blocking findings (weekly)" in creates[0], creates[0]
assert not [c for c in calls if c.startswith("issue edit")], calls
PY
check grep -q 'jenkins step fails' "$(out weekly)/blocking-issue.md"
check grep -q 'cosign verify fails as written' "$(out weekly)/blocking-issue.md"
CASE="weekly with one already open: it UPDATES that issue (edit + the new body), never opens a second"
IMAGE="$IMG2" PUBLISH=1 GH_STUB_LIST='[{"number":7}]' run weeklyopen "$WK" weekly
check python3 - "$work/weeklyopen/gh.log" <<'PY'
import sys
calls = [l.strip() for l in open(sys.argv[1])]
assert not [c for c in calls if c.startswith("issue create") and "--label blocking" in c], calls
edits = [c for c in calls if c.startswith("issue edit")]
assert len(edits) == 1 and " 7 " in (" " + edits[0] + " ") and "--body-file" in edits[0] and "blocking-issue.md" in edits[0], calls
PY
CASE="weekly with friction too: its friction issue is separate from the blocking one"
IMAGE="$IMG2" PUBLISH=1 run weeklymix '{"maven-jenkins-ci":{"findings":[{"kind":"blocking","text":"b"}]},"gradle-platform-engineer":{"findings":[{"kind":"friction","text":"f"}]}}' weekly
check python3 - "$work/weeklymix/gh.log" <<'PY'
import sys
calls = [l.strip() for l in open(sys.argv[1])]
assert len([c for c in calls if c.startswith("issue create") and "persona-uat-friction" in c]) == 1, calls
assert len([c for c in calls if c.startswith("issue create") and "--label blocking" in c]) == 1, calls
PY
CASE="weekly: a clean run opens no issue and exits 0"
IMAGE="$IMG2" PUBLISH=1 run weeklyclean '{}' weekly
check test "$rc" -eq 0 -a ! -e "$(out weeklyclean)/blocking-issue.md"
check python3 - "$work/weeklyclean/gh.log" <<'PY'
import sys
assert not [l for l in open(sys.argv[1]) if l.startswith("issue create") or l.startswith("issue edit")]
PY

CASE="weekly: an agent that crashes also counts as blocking (it opens the blocking issue naming the persona), never a silent pass"
IMAGE="$IMG2" PUBLISH=1 run weeklycrash '{"on-call-engineer":{"crash":true}}' weekly
check python3 - "$work/weeklycrash/gh.log" "$(out weeklycrash)/blocking-issue.md" <<'PY'
import sys
calls = [l.strip() for l in open(sys.argv[1])]
assert len([c for c in calls if c.startswith("issue create") and "--label blocking" in c]) == 1, calls
b = open(sys.argv[2]).read()
assert "on-call-engineer" in b and "did not run" in b.lower(), b
PY
CASE="an agent that hangs is cut off after --agent-timeout, counts as blocking (did not run), and the other four still run"
AGENT_TIMEOUT=1 run hang '{"readme-evaluator":{"sleep":30}}' rc
check test "$rc" -ne 0 -a "$(nlines "$work/hang/log")" -eq 5
check grep -qi 'did not run' "$(out hang)/readme-evaluator.report.md"
check grep -q 'VERDICT: pass' "$(out hang)/on-call-engineer.report.md"

# --- AC5: the agent reads only the public docs and the endpoint ------------------------------------------------
CASE="the sandbox holds README.md and the top-level docs for four personas, and ONLY README.md for the README evaluator"
check python3 - "$work/clean/log" <<'PY'
import json, sys
for ln in open(sys.argv[1]):
    r = json.loads(ln)
    want = ["README.md"] if r["persona"] == "readme-evaluator" else ["README.md", "docs/gradle.md", "docs/install.md"]
    assert r["docs"] == want, (r["persona"], r["docs"])
PY
CASE="what the agent could READ (every file's content) holds no source, internal doc, dotfile, symlink target or unreleased note"
check python3 - "$work/clean/log" <<'PY'
import json, sys
bad = ("SECRET-", "INTERNAL TRACE", "UNRELEASED NOTES", "package internal")
for ln in open(sys.argv[1]):
    r = json.loads(ln)
    assert r["content"], "the stub read nothing: the assertion would be vacuous"
    for f, c in r["content"].items():
        assert not any(b in c for b in bad), (r["persona"], f)
    assert r["links"] == [], ("symlink in the sandbox", r["links"])
    assert all(not f.startswith(".") and "/." not in f for f in r["content"]), r["content"].keys()
    assert all(f == "README.md" or (f.startswith("docs/") and f.endswith(".md") and f.count("/") == 1) for f in r["content"]), list(r["content"])
PY
CASE="nothing the agent was handed or the driver wrote leaks source, internal docs or unreleased notes"
check none_match 'SECRET-|INTERNAL TRACE|UNRELEASED NOTES|package internal' "$(out clean)"
CASE="the request has EXACTLY the contract's keys and no repository path anywhere in it"
check python3 - "$work/clean/log" "$repo" <<'PY'
import json, sys
for ln in open(sys.argv[1]):
    r = json.loads(ln)
    assert r["keys"] == ["docs_dir", "endpoint", "image", "instructions", "model", "persona", "token_budget", "tools"], r["keys"]
    assert sys.argv[2] not in json.dumps(r["request"]), "repo path leaked into the request"
PY
CASE="the agent runs INSIDE its sandbox (cwd = its docs directory, outside the repository checkout)"
check python3 - "$work/clean/log" "$repo" <<'PY'
import json, os, sys
for ln in open(sys.argv[1]):
    r = json.loads(ln)
    assert os.path.realpath(r["cwd"]) == os.path.realpath(r["request"]["docs_dir"]), r
    assert not os.path.realpath(r["cwd"]).startswith(os.path.realpath(sys.argv[2])), r
PY
CASE="the agent's environment is scrubbed: no GitHub or AWS credentials and no checkout path inherited"
check python3 - "$work/clean/log" <<'PY'
import json, sys
for ln in open(sys.argv[1]):
    env = json.loads(ln)["env"]
    for bad in ("GITHUB_TOKEN", "GH_TOKEN", "AWS_SECRET_ACCESS_KEY", "REPO_CHECKOUT", "GITHUB_WORKSPACE", "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
                "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_RUNTIME_TOKEN", "PERSONA_UAT_MODEL", "PERSONA_UAT_COMPLIANCE_MODEL"):
        assert bad not in env, bad
    # the model identity the provider needs is passed through, and nothing broader
    assert "ANTHROPIC_API_KEY" in env and "ANTHROPIC_IDENTITY_TOKEN_FILE" in env, env
PY

# --- AC5: model and token budget come from owner-set variables ---------------------------------------------------
CASE="four personas get the default model variable's value and the compliance reviewer gets its own"
check python3 - "$work/clean/log" <<'PY'
import json, sys
m = {json.loads(l)["persona"]: json.loads(l)["request"]["model"] for l in open(sys.argv[1])}
assert m["compliance-reviewer"] == "MODEL-COMPLIANCE-X", m
assert all(v == "MODEL-DEFAULT-X" for k, v in m.items() if k != "compliance-reviewer"), m
PY
run swapped '{}' rc PERSONA_UAT_MODEL=OTHER-DEFAULT PERSONA_UAT_COMPLIANCE_MODEL=OTHER-COMPLIANCE
CASE="different owner values flow through (the models are not remembered or hard-coded)"
check python3 - "$work/swapped/log" <<'PY'
import json, sys
m = {json.loads(l)["persona"]: json.loads(l)["request"]["model"] for l in open(sys.argv[1])}
assert len(m) == 5 and m["compliance-reviewer"] == "OTHER-COMPLIANCE", m
assert all(v == "OTHER-DEFAULT" for k, v in m.items() if k != "compliance-reviewer"), m
PY
CASE="the token budget defaults to 400000 per persona, for all five"
check python3 - "$work/clean/log" <<'PY'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1])]
assert len(rows) == 5 and all(r["request"]["token_budget"] == 400000 for r in rows)
PY
run budget '{}' rc PERSONA_UAT_TOKEN_BUDGET=123456
CASE="the owner's budget variable is honored, for all five, and the run succeeded"
check test "$rc" -eq 0
check python3 - "$work/budget/log" <<'PY'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1])]
assert len(rows) == 5 and all(r["request"]["token_budget"] == 123456 for r in rows), rows
PY
for bad in lots 0 -5 1.5 4e5 " 7" ""; do
  run "nobudget-$bad" '{}' rc "PERSONA_UAT_TOKEN_BUDGET=$bad"
  CASE="a budget of '$bad' is refused (exit 2) and nothing starts"
  if [ -z "$bad" ]; then CASE="an EMPTY budget variable falls back to the 400000 default"; check test "$rc" -eq 0
  else check test "$rc" -eq 2 -a ! -s "$work/nobudget-$bad/log" -a ! -s "$work/nobudget-$bad/docker.log"
       check grep -q 'PERSONA_UAT_TOKEN_BUDGET' "$work/nobudget-$bad/stderr"; fi
done
run nomodel '{}' rc PERSONA_UAT_MODEL=
CASE="an unset model variable refuses to run anything (exit 2); there is no built-in default model"
check test "$rc" -eq 2 -a ! -s "$work/nomodel/log" -a ! -s "$work/nomodel/docker.log"
CASE="a model variable that is not set at all (unset, not just empty) also refuses, and stderr names it"
mkdir -p "$work/unsetmodel"; : >"$work/unsetmodel/log"; : >"$work/unsetmodel/docker.log"; echo '{}' >"$work/unsetmodel/plan.json"; rc=0
env -u PERSONA_UAT_MODEL -u PERSONA_UAT_TOKEN_BUDGET STUB_PLAN="$work/unsetmodel/plan.json" STUB_LOG="$work/unsetmodel/log" DOCKER_LOG="$work/unsetmodel/docker.log" \
  GH_LOG="$work/unsetmodel/gh.log" PERSONA_UAT_COMPLIANCE_MODEL=MODEL-COMPLIANCE-X python3 "$driver" --mode rc --image "$IMG" --repo "$repo" \
  --out "$work/unsetmodel/out" --tools "$work/tools.json" --docker "$work/docker" --gh "$work/gh" --port 18080 --agent "python3 $work/stub.py" \
  >/dev/null 2>"$work/unsetmodel/stderr" || rc=$?
check test "$rc" -eq 2 -a ! -s "$work/unsetmodel/log" -a ! -s "$work/unsetmodel/docker.log"
check grep -q 'PERSONA_UAT_MODEL' "$work/unsetmodel/stderr"
run nocomp '{}' rc PERSONA_UAT_COMPLIANCE_MODEL=
CASE="an unset compliance-model variable refuses to run anything (exit 2)"
check test "$rc" -eq 2 -a ! -s "$work/nocomp/log" -a ! -s "$work/nocomp/docker.log"

# --- AC5: transcripts are kept (for every outcome); the cap is flagged; no model name is written ----------------
CASE="every persona's transcript file holds what the agent said, in a clean run"
check grep -q 'TRANSCRIPT for compliance-reviewer' "$(out clean)/compliance-reviewer.transcript.txt"
check grep -q 'TRANSCRIPT for readme-evaluator' "$(out clean)/readme-evaluator.transcript.txt"
CASE="and in a failing run the other personas' transcripts are kept"
check grep -q 'TRANSCRIPT for gradle-platform-engineer' "$(out blocking)/gradle-platform-engineer.transcript.txt"
run capped '{"readme-evaluator":{"tokens":400000},"gradle-platform-engineer":{"tokens":399999},"on-call-engineer":{"tokens":900000}}' rc
CASE="a persona that used its whole budget (or more) is flagged plainly in its report; one under it is not"
check grep -q 'HIT ITS TOKEN CAP' "$(out capped)/readme-evaluator.report.md"
check grep -q 'HIT ITS TOKEN CAP' "$(out capped)/on-call-engineer.report.md"
check bash -c "! grep -q 'HIT ITS TOKEN CAP' '$(out capped)/gradle-platform-engineer.report.md'"
CASE="a capped run does not fail by itself, and the summary names exactly the capped personas"
check test "$rc" -eq 0
check python3 - "$(out capped)/summary.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
assert sorted(s["capped"]) == ["on-call-engineer", "readme-evaluator"], s
PY
CASE="no owner-set model value appears in any report, transcript, summary, issue file, request or docker/gh call"
check none_match 'MODEL-(DEFAULT|COMPLIANCE)-X|OTHER-(DEFAULT|COMPLIANCE)' "$(out clean)" "$(out capped)" "$(out friction)" "$(out weekly)" "$(out blocking)" \
  "$work/clean/docker.log" "$work/friction/gh.log" "$work/weekly/gh.log"
CASE="no model name is written in the driver: neither a vendor family nor a model-version pattern"
check none_match '[Cc]laude|[Oo]pus|[Ss]onnet|[Hh]aiku|[Ff]able|gpt-|[Gg]emini|[Ll]lama|\bo[134]-' "$root/bin/persona-uat.py"

echo "persona-uat: $pass passed, $failn failed"
test "$failn" -eq 0
