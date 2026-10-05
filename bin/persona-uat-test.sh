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
case = sys.argv[1]
plan = json.load(open(os.path.join(case, "plan.json")))
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
with open(os.path.join(case, "log"), "a") as fh:
    fh.write(json.dumps({"persona": req["persona"], "docs": seen, "keys": sorted(req), "request": req,
                         "env": sorted(os.environ), "cwd": os.getcwd(), "raw_len": len(raw), "argv": sys.argv[2:], "content": content, "links": links}) + "\n")
if p.get("crash"):
    sys.stderr.write("PARTIAL-TRANSCRIPT for " + req["persona"] + "\n")
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
cat >"$work/docker.tmpl" <<'SH'
#!/usr/bin/env bash
DOCKER_LOG="__LOG__"
echo "$*" >>"$DOCKER_LOG"
if [ -n "${DOCKER_FAIL_MATCH:-}" ] && [[ "$*" == *"$DOCKER_FAIL_MATCH"* ]]; then echo "docker: simulated failure" >&2; exit 125; fi
if [ "$1" = run ] && [ "$2" = --rm ]; then
  python3 - "$@" <<'PYX'
import subprocess, sys
a = sys.argv[1:]
host = next(x.split(":")[0] for i, x in enumerate(a) if i and a[i - 1] == "-v")
p = subprocess.run(["sh", "-c", a[a.index("-c") + 1]], cwd=host, capture_output=True, text=True, timeout=60)
sys.stdout.write(p.stdout + p.stderr); sys.exit(p.returncode)
PYX
  exit $?
fi
case "$1" in
  run) n=$(grep -c '^run ' "$DOCKER_LOG"); echo "cid-$n" ;;
  inspect) if [ -n "${DOCKER_INSPECT_FALSE:-}" ]; then echo false; else echo true; fi ;;
  exec) printf 'apiVersion: v1\nclusters:\n- cluster:\n    server: https://127.0.0.1:6443\n  name: kind\n' ;;
esac
exit 0
SH
# gh is a python stub that validates ARGV STRUCTURALLY (every token accounted for: a title split into words is refused, as the real gh would),
# validates issue create/edit bodies at the moment of the call, and logs each call both as text and as JSON; GH_FAIL_MATCH simulates a failure
cat >"$work/gh" <<'PY'
#!/usr/bin/env python3
import json, os, sys
a = sys.argv[1:]
line = " ".join(a)
log = open(os.environ["GH_LOG"], "a")
log.write(line + "\n"); log.write("ARGV " + json.dumps(a) + "\n")
fm = os.environ.get("GH_FAIL_MATCH")
def die(msg, rc=1):
    sys.stderr.write("gh: %s\n" % msg); sys.exit(rc)
def parse(rest, opts, multi=(), flags=()):
    """returns ({opt: value or [values]}, positionals); an unknown option or a missing value is an error"""
    got, pos, i = {}, [], 0
    while i < len(rest):
        t = rest[i]
        if t in flags: got[t] = True; i += 1
        elif t in opts:
            if i + 1 >= len(rest): die("flag needs an argument: " + t)
            if t in multi: got.setdefault(t, []).append(rest[i + 1])
            else: got[t] = rest[i + 1]
            i += 2
        elif t.startswith("-"): die("unknown flag: " + t)
        else: pos.append(t); i += 1
    return got, pos
if fm and fm in line:
    die("simulated failure")
cmd = a[:2]
if cmd == ["issue", "create"]:
    o, pos = parse(a[2:], ("--title", "--label", "--body-file"), multi=("--label",))
    if pos or "--title" not in o or "--body-file" not in o: die("accepts 0 arg(s), received %d / missing flags" % len(pos))
    bf = o["--body-file"]
    if not os.path.isfile(bf) or os.path.getsize(bf) == 0:
        log.write("BODY-MISSING " + bf + "\n"); die("body file missing or empty")
    log.write("BODY: " + open(bf).read().replace("\n", " | ") + "\n")
    print("https://github.com/x/y/issues/99")
elif cmd == ["issue", "edit"]:
    o, pos = parse(a[2:], ("--body-file", "--title"))
    if len(pos) != 1 or not pos[0].isdigit() or "--body-file" not in o: die("expects one issue number and --body-file")
    bf = o["--body-file"]
    if not os.path.isfile(bf) or os.path.getsize(bf) == 0:
        log.write("BODY-MISSING " + bf + "\n"); die("body file missing or empty")
    log.write("BODY: " + open(bf).read().replace("\n", " | ") + "\n")
elif cmd == ["issue", "list"]:
    o, pos = parse(a[2:], ("--label", "--state", "--search", "--json", "--limit"))
    if pos or o.get("--json") != "number,title": die("this caller cannot parse a list (needs --json number,title)")
    st = o.get("--state", "open")
    items = json.loads(os.environ.get("GH_STUB_LIST", "[]"))
    if st == "all":
        items += json.loads(os.environ.get("GH_STUB_CLOSED", "[]"))
    print(json.dumps(items))
elif cmd == ["label", "create"]:
    o, pos = parse(a[2:], ("--description", "--color"), flags=("--force",))
    if len(pos) != 1: die("label create takes exactly one name")
else:
    die("unexpected gh call: " + line)
sys.exit(0)
PY
chmod +x "$work/gh"
# the "image under test" and Jenkins as tiny local HTTP servers, so the driver's readiness checks have something to find
python3 -m http.server 18080 --bind 127.0.0.1 --directory "$work" >/dev/null 2>&1 & SRV1=$!
python3 -m http.server 18081 --bind 127.0.0.1 --directory "$work" >/dev/null 2>&1 & SRV2=$!
trap 'kill $SRV1 $SRV2 2>/dev/null; rm -rf "$work"' EXIT
echo ours-18080 >"$work/ours-18080.txt"; echo ours-18081 >"$work/ours-18081.txt"
for _ in 1 2 3 4 5 6 7 8 9 10; do
  python3 - "$work" 2>/dev/null <<'PY' && break
import sys, urllib.request
for p in (18080, 18081):
    assert urllib.request.urlopen("http://127.0.0.1:%d/ours-%d.txt" % (p, p)).read().decode().strip() == "ours-%d" % p
PY
  sleep 0.3
done
python3 - <<'PY' || { echo "the fixture servers did not start, or another process owns ports 18080/18081/18099: refusing to run" >&2; exit 3; }
import socket, sys
s = socket.socket(); s.settimeout(0.5)
assert s.connect_ex(("127.0.0.1", 18099)) != 0, "18099 is in use"
for p in (18080, 18081):
    import urllib.request
    assert urllib.request.urlopen("http://127.0.0.1:%d/ours-%d.txt" % (p, p)).read().decode().strip() == "ours-%d" % p
PY

# run <name> <plan-json> <mode> [VAR=val ...]  (sets rc; dirs under $work/<name>/)
run() {
  local name=$1 plan=$2 mode=$3; shift 3
  mkdir -p "$work/$name"; echo "$plan" >"$work/$name/plan.json"; : >"$work/$name/log"; : >"$work/$name/docker.log"; : >"$work/$name/gh.log"
  sed "s#__LOG__#$work/$name/docker.log#" "$work/docker.tmpl" >"$work/$name/docker"; chmod +x "$work/$name/docker"
  rc=0
  env -u PERSONA_UAT_TOKEN_BUDGET GH_LOG="$work/$name/gh.log" GITHUB_RUN_ID=4242 \
      GITHUB_TOKEN=SECRET-GH-TOKEN GH_TOKEN=SECRET-GH2 AWS_SECRET_ACCESS_KEY=SECRET-AWS-KEY REPO_CHECKOUT="$repo" \
      GITHUB_WORKSPACE="$repo" ACTIONS_ID_TOKEN_REQUEST_TOKEN=SECRET-OIDC ACTIONS_ID_TOKEN_REQUEST_URL=http://oidc.invalid \
      ACTIONS_RUNTIME_TOKEN=SECRET-RT ANTHROPIC_API_KEY=ALLOWED-MODEL-CRED ANTHROPIC_IDENTITY_TOKEN_FILE=/x/token SOME_UNKNOWN_SECRET=SECRET-UNK AWS_SESSION_TOKEN=SECRET-AWS2 \
      ANTHROPIC_FEDERATION_RULE_ID=f1 ANTHROPIC_ORGANIZATION_ID=o1 ANTHROPIC_SERVICE_ACCOUNT_ID=s1 ANTHROPIC_WORKSPACE_ID=w1 \
      GITHUB_REPOSITORY=x/y GITHUB_SERVER_URL=https://github.com RUNNER_TEMP=/r ACTIONS_CACHE_URL=http://c.invalid GH_ENTERPRISE_TOKEN=SECRET-GHE \
      PERSONA_UAT_MODEL=MODEL-DEFAULT-X PERSONA_UAT_COMPLIANCE_MODEL=MODEL-COMPLIANCE-X "$@" \
      bash -c 'cd "$1" && shift && exec "$@"' _ "$repo" python3 "$driver" --mode "$mode" --image "${IMAGE:-$IMG}" --repo "$repo" --out "$work/$name/out" \
        --tools "${TOOLS:-$work/tools.json}" --docker "$work/$name/docker" --gh "$work/gh" --port "${PORT:-18080}" --ready-timeout "${READY_TIMEOUT:-5}" \
        --agent "python3 $work/stub.py $work/$name" ${AGENT_TIMEOUT:+--agent-timeout $AGENT_TIMEOUT} ${PUBLISH+--publish} >"$work/$name/stdout" 2>"$work/$name/stderr" || rc=$?
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
need = {"gradle-platform-engineer": ("first-time", "gradle", "proxy"), "maven-jenkins-ci": ("maven", "jenkins"),
        "compliance-reviewer": ("signature", "sbom", "vex"), "readme-evaluator": ("only the readme", "ten minutes"),
        "on-call-engineer": ("upgrade", "rollback", "logs")}
for p, words in need.items():
    for w in words:
        assert w in rows[p].lower(), (p, w)
for p, text in rows.items():          # every persona is told how to classify what it finds, and what a doc step is
    for w in ("broken behavior", "friction", "as written"):
        assert w in text.lower(), (p, w)
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
    removed = " ".join(l for l in lines if l.startswith("rm -f "))
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
    runs = [l for l in log.splitlines() if l.startswith("run ") and ref in l]
    assert len(runs) == 1, (ref, log)
    assert runs[0].split()[:2] == ["run", "-d"], runs[0]
rows = {json.loads(l)["persona"]: json.loads(l)["request"]["tools"] for l in open(sys.argv[2])}
assert sorted(rows["maven-jenkins-ci"]) == ["gitlab-runner", "jenkins"], rows
assert sorted(rows["on-call-engineer"]) == ["kind"], rows
# the contract: each tool is {container, endpoint}; Jenkins is reachable on loopback, kind also hands over a kubeconfig file
for name, v in {**rows["maven-jenkins-ci"], **rows["on-call-engineer"]}.items():
    assert sorted(v)[:2] == ["container", "endpoint"] and v["container"].startswith("cid-"), (name, v)
assert rows["maven-jenkins-ci"]["jenkins"]["endpoint"] == "http://127.0.0.1:18081", rows
assert rows["on-call-engineer"]["kind"]["kubeconfig"] == "kubeconfig", rows
assert rows["on-call-engineer"]["kind"]["endpoint"] == "https://127.0.0.1:18082", rows
for p in ("gradle-platform-engineer", "compliance-reviewer", "readme-evaluator"):
    assert rows[p] == {}, (p, rows[p])
PY
CASE="the kubeconfig the on-call persona gets points at the PUBLISHED kind port (https://127.0.0.1:18082), not the container's internal 6443"
check python3 - "$work/clean/log" <<'PY'
import json, sys
for l in open(sys.argv[1]):
    r = json.loads(l)
    if r["persona"] == "on-call-engineer":
        assert "kubeconfig" in r["content"], r["content"].keys()
        kc = r["content"]["kubeconfig"]
        assert "server: https://127.0.0.1:18082" in kc and "6443" not in kc, kc
PY
CASE="the agent is told to run every shell action in the pinned shell image through the driver's docker, and nothing else"
check python3 - "$work/clean/log" "$work/clean/docker.log" "$SHL" "x" <<'PY'
import json, sys
for ln in open(sys.argv[1]):
    a = json.loads(ln)["argv"]
    assert a[a.index("--shell-image") + 1] == sys.argv[3], a
    assert a[a.index("--docker") + 1].endswith("/docker"), a
assert sys.argv[3] not in open(sys.argv[2]).read(), "the driver itself must not start the shell image: the agent does, per action"
PY
CASE="every container the driver starts is `run -d` with the pinned image as its LAST argument, only loopback-published ports, no mount, no env, no network override; privileged only for kind"
check python3 - "$work/clean/docker.log" "$IMG" "$JEN" "$GLR" "$KND" <<'PY'
import re, sys
img, jen, glr, knd = sys.argv[2:6]
allowed = {img, jen, glr, knd}
seen = []
for l in open(sys.argv[1]):
    t = l.split()
    if t[0] == "pull":
        raise AssertionError("the driver must not pull explicitly: " + l)
    if t[0] == "run":
        assert t[:2] == ["run", "-d"], ("every container the driver starts is `run -d ...`: " + l)
    if t[:2] != ["run", "-d"]:
        continue
    ref, flags = t[-1], t[2:-1]
    assert ref in allowed, ("the image is the last argument and must be one of the four pinned references", l)
    seen.append(ref)
    i = 0
    while i < len(flags):
        f = flags[i]
        if f in ("--rm",): i += 1
        elif f == "--name": i += 2
        elif f == "-p":
            assert re.fullmatch(r"127\.0\.0\.1:\d+:\d+", flags[i + 1]), ("only loopback publishing", l)
            host, cport = flags[i + 1].split(":")[1:]
            want = {img: ("18080", "8080"), jen: ("18081", "8080"), knd: ("18082", "6443")}.get(ref)
            assert want is None or (host, cport) == want, ("the published port mapping for this image is wrong", ref, flags[i + 1], want)
            i += 2
        elif f == "--privileged": assert ref == knd, ("privileged is for kind only", l); i += 1
        else: raise AssertionError(("a flag outside the allowlist (no -v/--mount/-e/--env/--network/--cap-add/--user ...)", f, l))
assert sorted(seen) == sorted(allowed), seen
PY
for key in jenkins gitlab-runner kind shell; do
  python3 - "$work/tools.json" "$work/tools-unpinned-$key.json" "$key" <<'PY'
import json, sys
t = json.load(open(sys.argv[1])); t[sys.argv[3]] = t[sys.argv[3]].split("@")[0] + ":latest"
json.dump(t, open(sys.argv[2], "w"))
PY
  CASE="the $key entry not pinned by digest refuses the whole run (exit 2); nothing starts and stderr names it"
  TOOLS="$work/tools-unpinned-$key.json" run "unpinned-$key" '{}' rc
  check test "$rc" -eq 2 -a ! -s "$work/unpinned-$key/docker.log" -a ! -s "$work/unpinned-$key/log"
  check grep -q "$key" "$work/unpinned-$key/stderr"
done
for badref in "ghcr.io/example/cache@sha256:abc" "ghcr.io/example/cache@sha256:$(printf 'g%.0s' $(seq 64))" "ghcr.io/example/cache@sha256:$(printf 'a%.0s' $(seq 63))"; do
  IMAGE="$badref" run badimg '{}' rc
  CASE="a malformed digest ($badref) is refused (exit 2) and nothing starts"
  check test "$rc" -eq 2 -a ! -s "$work/badimg/docker.log" -a ! -s "$work/badimg/log"
done
unset TOOLS IMAGE

# --- infrastructure failures fail closed (AC1, AC2): a dead image or tool must never read as a green run
DOCKER_FAIL_MATCH="$IMG" run imgdead '{}' rc
CASE="the image under test cannot start: the run fails, no persona is run against nothing, and every persona is reported did-not-run"
check test "$rc" -ne 0
check test "$(ls "$(out imgdead)"/*.report.md | wc -l | tr -d ' ')" -eq 5
check grep -qi 'did not run' "$(out imgdead)/on-call-engineer.report.md"
check grep -q 'VERDICT: blocking' "$(out imgdead)/gradle-platform-engineer.report.md"
DOCKER_FAIL_MATCH="$JEN" run jendead '{}' rc
CASE="a tool container (Jenkins) cannot start: that persona did not run (blocking), the other four are unaffected"
check test "$rc" -ne 0
check grep -qi 'did not run' "$(out jendead)/maven-jenkins-ci.report.md"
check grep -q 'VERDICT: pass' "$(out jendead)/gradle-platform-engineer.report.md"
DOCKER_FAIL_MATCH="$IMG2" PUBLISH=1 IMAGE="$IMG2" run weekdead '{}' weekly
CASE="weekly: a dead image opens the one blocking issue (naming every persona) instead of passing silently"
check python3 - "$work/weekdead/gh.log" "$(out weekdead)/blocking-issue.md" <<'PY'
import sys
calls = [l.strip() for l in open(sys.argv[1])]
assert len([c for c in calls if c.startswith("issue create") and "--label blocking" in c]) == 1, calls
b = open(sys.argv[2]).read()
assert all(p in b for p in ("gradle-platform-engineer", "maven-jenkins-ci", "compliance-reviewer", "readme-evaluator", "on-call-engineer")), b
PY
CASE="the driver provisions nothing in a cloud: its docker and gh calls are only run/rm and issue commands"
check python3 - "$work/clean/docker.log" <<'PY'
import sys
for path in sys.argv[1:]:
    for l in open(path):
        assert l.split()[0] in ("run", "rm", "inspect", "exec"), l
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
failclosed tokens-bool  maven-jenkins-ci         '{"override":{"tokens":true}}'
failclosed tokens-float maven-jenkins-ci         '{"override":{"tokens":1.5}}'
failclosed extra-key    maven-jenkins-ci         '{"override":{"surprise":1}}'
failclosed tokens-gone  maven-jenkins-ci         '{"drop":["tokens"]}'
failclosed transcript-gone compliance-reviewer   '{"drop":["transcript"]}'
failclosed transcript-notstr compliance-reviewer '{"override":{"transcript":["a"]}}'
failclosed findings-gone readme-evaluator        '{"drop":["findings"]}'
CASE="a failed agent leaves its transcript file present AND holding what it had written to stderr, so the artifact can diagnose it"
check test -e "$(out fc-crash)/compliance-reviewer.transcript.txt"
check grep -q 'PARTIAL-TRANSCRIPT for compliance-reviewer' "$(out fc-crash)/compliance-reviewer.transcript.txt"

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
CASE="a failing gh while publishing FRICTION also fails the run: the information issue is never silently lost"
PUBLISH=1 GH_FAIL_MATCH="issue create" run frictionfail "$FR" rc
check test "$rc" -ne 0
check grep -q '^issue create' "$work/frictionfail/gh.log"
check grep -q '^label create persona-uat-friction' "$work/frictionfail/gh.log"
PUBLISH=1 GH_FAIL_MATCH="issue edit" GH_STUB_LIST='[{"number":55,"title":"Persona UAT friction: rc run 4242"}]' run frictionfail2 "$FR" rc
check test "$rc" -ne 0
PUBLISH=1 GH_FAIL_MATCH="issue list" run frictionfail3 "$FR" rc
check test "$rc" -ne 0
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
CASE="weekly: a failing gh (create) fails the run: losing the only signal is never silent"
IMAGE="$IMG2" PUBLISH=1 GH_FAIL_MATCH="issue create" run weeklyghfail "$WK" weekly
check test "$rc" -ne 0
CASE="weekly: a failing gh (edit of an open issue) also fails the run"
IMAGE="$IMG2" PUBLISH=1 GH_STUB_LIST='[{"number":7,"title":"Persona UAT: blocking findings (weekly)"}]' GH_FAIL_MATCH="issue edit" run weeklyghfail2 "$WK" weekly
check test "$rc" -ne 0
CASE="weekly: an unparseable issue list fails the run and creates no duplicate"
IMAGE="$IMG2" PUBLISH=1 GH_STUB_LIST='<html>rate limited' run weeklygarbage "$WK" weekly
check test "$rc" -ne 0
check python3 - "$work/weeklygarbage/gh.log" <<'PY'
import sys
assert not [l for l in open(sys.argv[1]) if l.startswith("issue create")], "created an issue after an unreadable list"
PY
CASE="the labels the issues use are created first (gh label create --force), so a missing label cannot lose the issue"
check python3 - "$work/weekly/gh.log" "$work/friction/gh.log" <<'PY'
import sys
for path, label in ((sys.argv[1], "blocking"), (sys.argv[2], "persona-uat-friction")):
    calls = [l.strip() for l in open(path)]
    mk = [i for i, c in enumerate(calls) if c.startswith("label create " + label) and "--force" in c]
    cr = [i for i, c in enumerate(calls) if c.startswith("issue create") and label in c]
    assert mk and cr and mk[0] < cr[0], (label, calls)
PY
CASE="the weekly lookup is narrowed by the fixed title: another open issue carrying the label is never overwritten"
IMAGE="$IMG2" PUBLISH=1 GH_STUB_LIST='[{"number":3,"title":"Something unrelated"},{"number":7,"title":"Persona UAT: blocking findings (weekly)"}]' run weeklytwo "$WK" weekly
check python3 - "$work/weeklytwo/gh.log" <<'PY'
import sys
calls = [l.strip() for l in open(sys.argv[1])]
lst = [c for c in calls if c.startswith("issue list")][0]
assert "Persona UAT: blocking findings (weekly)" in lst and "in:title" in lst, lst
edits = [c for c in calls if c.startswith("issue edit")]
assert len(edits) == 1 and " 7 " in (" " + edits[0] + " "), calls
PY
IMAGE="$IMG2" PUBLISH=1 GH_STUB_LIST='[{"number":3,"title":"Something unrelated"}]' run weeklyother "$WK" weekly
CASE="and when the only labelled issue is unrelated, a new one is created, not that one edited"
check python3 - "$work/weeklyother/gh.log" <<'PY'
import sys
calls = [l.strip() for l in open(sys.argv[1])]
assert len([c for c in calls if c.startswith("issue create") and "--label blocking" in c]) == 1 and not [c for c in calls if c.startswith("issue edit")], calls
PY
CASE="weekly with one already open: it UPDATES that issue (edit + the new body), never opens a second"
IMAGE="$IMG2" PUBLISH=1 GH_STUB_LIST='[{"number":7,"title":"Persona UAT: blocking findings (weekly)"}]' run weeklyopen "$WK" weekly
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

CASE="weekly with friction only exits 0 and opens only the friction issue (AC3: friction blocks nothing, on either schedule)"
IMAGE="$IMG2" PUBLISH=1 run weeklyfr '{"gradle-platform-engineer":{"findings":[{"kind":"friction","text":"f"}]}}' weekly
check test "$rc" -eq 0
check python3 - "$work/weeklyfr/gh.log" <<'PY'
import sys
calls = [l.strip() for l in open(sys.argv[1]) if not l.startswith("ARGV ") and not l.startswith("BODY")]
assert len([c for c in calls if c.startswith("issue create")]) == 1 and "persona-uat-friction" in [c for c in calls if c.startswith("issue create")][0], calls
assert not [c for c in calls if "--label blocking" in c], calls
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
    if r["persona"] == "on-call-engineer":
        want = ["README.md", "docs/gradle.md", "docs/install.md", "kubeconfig"]
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
    assert all(f == "README.md" or (f.startswith("docs/") and f.endswith(".md") and f.count("/") == 1) or (r["persona"] == "on-call-engineer" and f == "kubeconfig") for f in r["content"]), list(r["content"])
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
    for bad in ("GITHUB_TOKEN", "GH_TOKEN", "AWS_SECRET_ACCESS_KEY", "SOME_UNKNOWN_SECRET", "AWS_SESSION_TOKEN", "REPO_CHECKOUT", "GITHUB_WORKSPACE", "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
                "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_RUNTIME_TOKEN", "PERSONA_UAT_MODEL", "PERSONA_UAT_COMPLIANCE_MODEL"):
        assert bad not in env, bad
    # an ALLOWLIST: only a minimal shell environment and the model identity the provider needs, nothing else
    ok = {"PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "TMPDIR", "PWD", "SHLVL", "_", "__CF_USER_TEXT_ENCODING", "DOCKER_HOST", "DOCKER_CONFIG"}
    extra = [k for k in env if k not in ok and not k.startswith("ANTHROPIC_")]
    assert not extra, extra
    for need in ("ANTHROPIC_API_KEY", "ANTHROPIC_IDENTITY_TOKEN_FILE", "ANTHROPIC_FEDERATION_RULE_ID", "ANTHROPIC_ORGANIZATION_ID",
                 "ANTHROPIC_SERVICE_ACCOUNT_ID", "ANTHROPIC_WORKSPACE_ID"):
        assert need in env, ("the provider needs", need)
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
sed "s#__LOG__#$work/unsetmodel/docker.log#" "$work/docker.tmpl" >"$work/unsetmodel/docker"; chmod +x "$work/unsetmodel/docker"
env -u PERSONA_UAT_MODEL -u PERSONA_UAT_TOKEN_BUDGET GH_LOG="$work/unsetmodel/gh.log" PERSONA_UAT_COMPLIANCE_MODEL=MODEL-COMPLIANCE-X python3 "$driver" --mode rc --image "$IMG" --repo "$repo" \
  --out "$work/unsetmodel/out" --tools "$work/tools.json" --docker "$work/unsetmodel/docker" --gh "$work/gh" --port 18080 --agent "python3 $work/stub.py $work/unsetmodel" \
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
check none_match 'HIT ITS TOKEN CAP' "$(out capped)/gradle-platform-engineer.report.md"
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

# --- symlinks at the roots: a symlinked README.md or a symlinked docs directory must never carry other bytes into the sandbox
for kind in readme docs; do
  rp="$work/symrepo-$kind"; rm -rf "$rp"; mkdir -p "$rp/internal" "$rp/docs"; echo "SECRET-ROOT-TARGET" >"$rp/internal/secret.md"
  if [ "$kind" = readme ]; then ln -s internal/secret.md "$rp/README.md"; echo "install steps" >"$rp/docs/install.md"
  else echo "# README" >"$rp/README.md"; rm -rf "$rp/docs"; ln -s internal "$rp/docs"; fi
  mkdir -p "$work/sym-$kind"; : >"$work/sym-$kind/log"; : >"$work/sym-$kind/docker.log"; echo '{}' >"$work/sym-$kind/plan.json"
  sed "s#__LOG__#$work/sym-$kind/docker.log#" "$work/docker.tmpl" >"$work/sym-$kind/docker"; chmod +x "$work/sym-$kind/docker"; rc=0
  env -u PERSONA_UAT_TOKEN_BUDGET GH_LOG="$work/sym-$kind/gh.log" PERSONA_UAT_MODEL=M1 PERSONA_UAT_COMPLIANCE_MODEL=M2 python3 "$driver" --mode rc --image "$IMG" --repo "$rp" \
    --out "$work/sym-$kind/out" --tools "$work/tools.json" --docker "$work/sym-$kind/docker" --gh "$work/gh" --port 18080 --agent "python3 $work/stub.py $work/sym-$kind" \
    >/dev/null 2>"$work/sym-$kind/stderr" || rc=$?
  CASE="a symlinked $kind root: its target's bytes never reach any agent or output"
  check none_match 'SECRET-ROOT-TARGET' "$work/sym-$kind/log" "$work/sym-$kind/out"
done
CASE="a symlinked README.md is not a README: the run refuses (non-zero) and starts nothing"
check test -s "$work/sym-readme/stderr" -a ! -s "$work/sym-readme/docker.log"
CASE="a symlinked docs directory contributes nothing: the personas get the README only, and the run still works"
check python3 - "$work/sym-docs/log" <<'PY'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1])]
assert len(rows) == 5 and all(r["docs"] == ["README.md"] for r in rows), [r["docs"] for r in rows]
PY

# --- the docs the personas read must actually be there
mkdir -p "$work/emptyrepo"; : >"$work/emptyrepo/placeholder"
CASE="a --repo with no README.md and no docs: the run refuses (non-zero), every persona is did-not-run, and nothing is started"
mkdir -p "$work/nodocs"; : >"$work/nodocs/log"; : >"$work/nodocs/docker.log"; echo '{}' >"$work/nodocs/plan.json"; sed "s#__LOG__#$work/nodocs/docker.log#" "$work/docker.tmpl" >"$work/nodocs/docker"; chmod +x "$work/nodocs/docker"; rc=0
env -u PERSONA_UAT_TOKEN_BUDGET GH_LOG="$work/nodocs/gh.log" PERSONA_UAT_MODEL=M1 PERSONA_UAT_COMPLIANCE_MODEL=M2 python3 "$driver" --mode rc --image "$IMG" --repo "$work/emptyrepo" \
  --out "$work/nodocs/out" --tools "$work/tools.json" --docker "$work/nodocs/docker" --gh "$work/gh" --port 18080 --agent "python3 $work/stub.py $work/nodocs" >/dev/null 2>"$work/nodocs/stderr" || rc=$?
check test "$rc" -ne 0 -a ! -s "$work/nodocs/log" -a ! -s "$work/nodocs/docker.log"
check grep -qi 'README' "$work/nodocs/stderr"

# --- readiness: a dead image or a container that is not running never reads as a green run --------------------------
PORT=18099 READY_TIMEOUT=1 run notready '{}' rc
CASE="an image that never answers on its endpoint: the run fails, no agent is started against nothing, every persona did not run"
check test "$rc" -ne 0 -a ! -s "$work/notready/log"
check test "$(ls "$(out notready)"/*.report.md | wc -l | tr -d ' ')" -eq 5
check grep -qi 'did not run' "$(out notready)/readme-evaluator.report.md"
DOCKER_INSPECT_FALSE=1 run notrunning '{}' rc
CASE="a container that is not running (docker inspect says false) is a persona that did not run, not a pass"
check test "$rc" -ne 0
check grep -qi 'did not run' "$(out notrunning)/gradle-platform-engineer.report.md"
CASE="readiness is checked with docker inspect on every container the driver started"
check python3 - "$work/clean/docker.log" <<'PY'
import sys
lines = open(sys.argv[1]).read().splitlines()
runs = [l for l in lines if l.startswith("run ")]
insp = [l for l in lines if l.startswith("inspect ")]
assert runs and all(any(f"cid-{i+1}" in l for l in insp) for i in range(len(runs))), (runs, insp)
PY

# --- publication: the issue BODY is what was published, validated at the moment of the call; retries of one run do not duplicate
CASE="every issue create/edit carried a real body file (the stub fails the call otherwise) and the body holds the findings"
check python3 - "$work/friction/gh.log" "$work/weekly/gh.log" <<'PY'
import sys
f, w = (open(p).read() for p in sys.argv[1:3])
assert "BODY-MISSING" not in f + w
assert "BODY: " in f and "no log level hint" in f and "on-call-engineer" in f, f
assert "BODY: " in w and "cosign verify fails as written" in w and "maven-jenkins-ci" in w, w
PY
CASE="a retry of the SAME run (same run id) edits its friction issue instead of opening a second one"
PUBLISH=1 GH_STUB_LIST='[{"number":55,"title":"Persona UAT friction: rc run 4242"}]' run frictionretry "$FR" rc
check test "$rc" -eq 0
check python3 - "$work/frictionretry/gh.log" <<'PY'
import sys
calls = [l.strip() for l in open(sys.argv[1])]
assert not [c for c in calls if c.startswith("issue create") and "persona-uat-friction" in c], calls
edits = [c for c in calls if c.startswith("issue edit")]
assert len(edits) == 1 and " 55 " in (" " + edits[0] + " "), calls
PY
CASE="a retry of the same run AFTER its friction issue was closed still finds and edits it (the lookup spans all states): never a second issue"
PUBLISH=1 GH_STUB_LIST='[]' GH_STUB_CLOSED='[{"number":56,"title":"Persona UAT friction: rc run 4242"}]' run frictionclosed "$FR" rc
check test "$rc" -eq 0
check python3 - "$work/frictionclosed/gh.log" <<'PY'
import json, sys
calls = [l.strip() for l in open(sys.argv[1]) if not l.startswith("ARGV ") and not l.startswith("BODY")]
lst = [c for c in calls if c.startswith("issue list") and "persona-uat-friction" in c]
assert lst and "--state all" in lst[0], calls
assert not [c for c in calls if c.startswith("issue create") and "persona-uat-friction" in c], calls
edits = [c for c in calls if c.startswith("issue edit")]
assert len(edits) == 1 and " 56 " in (" " + edits[0] + " "), calls
PY
CASE="a friction issue of ANOTHER run that carries the label is never edited: a new run opens its own"
PUBLISH=1 GH_STUB_LIST='[{"number":54,"title":"Persona UAT friction: rc run 4100"}]' run frictionother "$FR" rc
check python3 - "$work/frictionother/gh.log" <<'PY'
import sys
calls = [l.strip() for l in open(sys.argv[1])]
assert len([c for c in calls if c.startswith("issue create") and "persona-uat-friction" in c]) == 1 and not [c for c in calls if c.startswith("issue edit")], calls
PY
CASE="the driver provisions nothing in a cloud (a docker log with only run, rm, inspect, exec), also for a friction run"
check python3 - "$work/friction/docker.log" <<'PY'
import sys
for l in open(sys.argv[1]):
    assert l.split()[0] in ("run", "rm", "inspect", "exec"), l
PY

# --- the integrated path: the REAL driver, the REAL agent and the REAL provider (over a fake SDK), workflow-shaped -----
mkdir -p "$work/sdk/anthropic" "$work/pybin"
cat >"$work/sdk/anthropic/__init__.py" <<'PY'
import json, os
LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "sdk.log")
class _Msg:
    def __init__(self, text):
        self.content = [type("B", (), {"type": "text", "text": text})()]
        self.usage = type("U", (), {"input_tokens": 120, "output_tokens": 30})()
class Anthropic:
    def __init__(self, *a, **k):
        tf = os.environ.get("ANTHROPIC_IDENTITY_TOKEN_FILE")
        if not tf or not os.path.isfile(tf) or open(tf).read().strip() != "FIXTURE-OIDC-TOKEN":
            raise RuntimeError("identity token file missing or wrong: federated authentication is not usable")
        open(LOG, "a").write(json.dumps({"init": {"has_key": "ANTHROPIC_API_KEY" in os.environ,
            "token_file": os.environ.get("ANTHROPIC_IDENTITY_TOKEN_FILE"), "fed": [os.environ.get(x) for x in
            ("ANTHROPIC_FEDERATION_RULE_ID", "ANTHROPIC_ORGANIZATION_ID", "ANTHROPIC_SERVICE_ACCOUNT_ID", "ANTHROPIC_WORKSPACE_ID")],
            "leaked": sorted(k for k in os.environ if k in ("GITHUB_TOKEN", "GH_TOKEN", "AWS_SECRET_ACCESS_KEY", "SOME_UNKNOWN_SECRET"))}}) + "\n")
        self.messages = self
    def create(self, **kw):
        open(LOG, "a").write(json.dumps({"model": kw["model"], "turn": len(kw["messages"]), "system": kw.get("system", ""),
            "first": kw["messages"][0]["content"] if isinstance(kw["messages"][0]["content"], str) else json.dumps(kw["messages"][0]["content"])}) + "\n")
        msgs = kw["messages"]
        if len(msgs) == 1:
            return _Msg(json.dumps({"action": "shell", "command": "cat README.md; echo $((6*7))"}))
        last = msgs[-1]["content"] if isinstance(msgs[-1]["content"], str) else json.dumps(msgs[-1]["content"])
        if len(msgs) == 3:
            return _Msg(json.dumps({"action": "shell", "command": "cat docs/documented-step-that-does-not-exist.md"}))
        # the finding is driven by what the failing step REALLY returned: its exit status and its stderr
        if "exit status: 1" in last and "No such file" in last:
            return _Msg(json.dumps({"action": "finish", "findings": [{"kind": "blocking", "text": "documented step failed as written: No such file"}]}))
        return _Msg(json.dumps({"action": "finish", "findings": []}))
PY
# a python3 first on PATH that makes the fake SDK importable WITHOUT any environment variable reaching the scrubbed agent
printf '#!/bin/sh\nPYTHONPATH="%s" exec %s "$@"\n' "$work/sdk" "$(command -v python3)" >"$work/pybin/python3"; chmod +x "$work/pybin/python3"
mkdir -p "$work/integ"; echo FIXTURE-OIDC-TOKEN >"$work/integ/token"; : >"$work/integ/docker.log"; : >"$work/integ/gh.log"; : >"$work/sdk/sdk.log"; rc=0
sed "s#__LOG__#$work/integ/docker.log#" "$work/docker.tmpl" >"$work/integ/docker"; chmod +x "$work/integ/docker"
( cd "$root" && env -u PERSONA_UAT_TOKEN_BUDGET -u ANTHROPIC_API_KEY GH_LOG="$work/integ/gh.log" PATH="$work/pybin:$PATH" GITHUB_RUN_ID=4242 \
    PERSONA_UAT_MODEL=INTEG-DEFAULT PERSONA_UAT_COMPLIANCE_MODEL=INTEG-COMPLIANCE \
    ANTHROPIC_IDENTITY_TOKEN_FILE="$work/integ/token" ANTHROPIC_FEDERATION_RULE_ID=f1 ANTHROPIC_ORGANIZATION_ID=o1 \
    ANTHROPIC_SERVICE_ACCOUNT_ID=s1 ANTHROPIC_WORKSPACE_ID=w1 GITHUB_TOKEN=SECRET-GH-TOKEN GH_TOKEN=SECRET-GH2 \
    AWS_SECRET_ACCESS_KEY=SECRET-AWS-KEY SOME_UNKNOWN_SECRET=SECRET-UNK \
    python3 bin/persona-uat.py --mode rc --image "$IMG" --repo "$repo" --out "$work/integ/out" --tools "$work/tools.json" \
      --docker "$work/integ/docker" --gh "$work/gh" --port 18080 --ready-timeout 5 --agent "python3 bin/persona-uat-agent.py" ) \
  >"$work/integ/stdout" 2>"$work/integ/stderr" || rc=$?
CASE="integrated: the real driver, agent (given by a RELATIVE path) and provider run to completion with five reports, and the run FAILS because a documented step failed as written"
check test "$rc" -ne 0 -a "$(ls "$work/integ/out"/*.report.md | wc -l | tr -d ' ')" -eq 5
CASE="integrated: every persona's blocking finding came from the failing step's REAL exit status and stderr (the fake provider only says so when it saw both)"
check python3 - "$work/integ/out" <<'PY'
import glob, sys
for r in glob.glob(sys.argv[1] + "/*.report.md"):
    c = open(r).read()
    assert "VERDICT: blocking" in c and "No such file" in c, r
PY
CASE="integrated: each persona really ran a shell action in its sandbox, and the COMPUTED output (42, which is not in the command text) came back into its transcript"
check python3 - "$work/integ/out" <<'PY'
import glob, sys
ts = glob.glob(sys.argv[1] + "/*.transcript.txt")
assert len(ts) == 5, ts
for t in ts:
    c = open(t).read()
    assert "# fscache README" in c and "\n42" in c.replace("\r", ""), t
PY
CASE="integrated: every provider call (three per persona) authenticated with the federated identity (four variables and the token file, no key, no leaked credential) and used the owner-set model"
check python3 - "$work/sdk/sdk.log" <<'PY'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1])]
inits = [r["init"] for r in rows if "init" in r]
assert len(inits) == 15, len(inits)
assert all(not i["has_key"] and i["fed"] == ["f1", "o1", "s1", "w1"] and i["token_file"].endswith("integ/token") and i["leaked"] == [] for i in inits), inits
calls = [r for r in rows if "model" in r]
for r in calls:
    ctx = (r["system"] + " " + r["first"]).lower()
    assert "http://127.0.0.1:18080" in ctx, "the persona is never told its endpoint"
    assert "only the public documentation" in ctx and "do not clone" in ctx and "source" in ctx, "the restriction is not in the prompt"
assert any("http://127.0.0.1:18081" in (r["system"] + r["first"]) for r in calls), "Jenkins' endpoint never reaches the Maven persona"
assert any("kubeconfig" in (r["system"] + r["first"]).lower() for r in calls), "the kubeconfig never reaches the on-call persona"
models = [r["model"] for r in rows if "model" in r]
assert len(models) == 15 and models.count("INTEG-COMPLIANCE") == 3 and models.count("INTEG-DEFAULT") == 12, models
PY
CASE="integrated: no GitHub credential reached the shell containers or the provider's environment"
check none_match 'SECRET-GH-TOKEN' "$work/integ/out" "$work/integ/docker.log"

CASE="across every case, the only gh calls ever made are issue create/edit/list and label create (a stray call is a failure, not a quiet success)"
check python3 - "$work" <<'PY'
import glob, sys
seen = 0
for path in glob.glob(sys.argv[1] + "/*/gh.log") + glob.glob(sys.argv[1] + "/integ/gh.log"):
    for l in open(path):
        if l.startswith(("ARGV ", "BODY")):
            continue
        seen += 1
        assert l.startswith(("issue create", "issue edit", "issue list", "label create")), (path, l)
assert seen > 0
PY
echo "persona-uat: $pass passed, $failn failed"
test "$failn" -eq 0
