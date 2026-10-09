#!/usr/bin/env bash
# proves: REQ-UAT-001-AC1, REQ-UAT-001-AC2, REQ-UAT-001-AC4, REQ-UAT-001-AC5
# The persona agent (bin/persona-uat-agent.py) and its model provider (bin/persona-uat-provider.py), proved with a FAKE
# provider and a fake `docker` that really runs the shell action inside the directory it was given: the loop stops at the
# owner's token budget (counted across ALL calls, never calling the model again once reached: a runaway stop, not a
# suggestion); every shell action runs in the digest-pinned shell image with exactly one mount (the sandbox of public
# docs), no privilege, no inherited credentials, so the only thing the sandbox holds is the public docs (the instructions forbid source; host
# networking is accepted, so nothing here ENFORCES it: the driver flags non-doc hosts in the report); a provider that fails or
# answers outside the protocol fails the agent (the driver then counts that persona as blocking); the owner's model
# reaches the provider and no model name is written in the agent or its output.
# Contracts the tests pin:
#   persona-uat-agent.py --docker CMD --tools FILE --label persona-uat=<uuid> [--provider-cmd CMD] [--shell-timeout S] [--max-steps N]
#     stdin: the driver's request JSON; stdout: {"findings":[...],"tokens":N,"transcript":str,"commands":[str]}
#   provider (stdin {"model","system","messages":[{"role","content"}]}) -> stdout {"usage":{"tokens":N},
#     "action":{"type":"shell","command":str} | {"type":"shell","tool":NAME,"command":str} (tool shell only) |
#              {"type":"shell","tool":NAME,"args":[str,...]} (any other tool) | {"type":"finish","findings":[...]}}
#   DELTAS (advisor 0207/0208; step 6, tests first):
#   (2) per-action tool images: the agent reads the tools file (--tools; replaces --shell-image). A shell action may carry `tool`, the NAME of
#       an action tool of that file (shell, cosign, kubectl, gradle, maven; absent = shell). Every action runs as
#       docker run --rm --network container:<holder> -v <sandbox>:/work -w /work <that tool's digest> [sh -c <command> | <args...>] with FIXED options:
#       `command` runs under `sh -c` only for the shell tool, `args` (a list) is exec'd as the image's own arguments for the others; whatever the
#       model types stays AFTER the image. An unknown tool name (not an entry, a digest reference, a different case, a service entry such as
#       kind/jenkins/gitlab-runner) is refused: never executed, the model is told, the persona carries on. A bad tools file fails the agent.
#   (3) the answer carries `commands`: what the persona ran (shell: the command; other tools: the tool name and its args joined by spaces), in
#       order, executed actions only (a refused one was never run); the driver derives the report's outside-hosts line from it.
#   (4) the agent no longer decides whether the endpoint was contacted: that is the driver's metrics proof; no `reached` finding here.
#   persona-uat-provider.py: the real provider, over the Anthropic Python SDK (faked here on PYTHONPATH).
set -euo pipefail
# FIXTURE PORTS are chosen per run (free ones, the endpoint's three consecutive: base, base+1, base+2) so this suite and the others can run side by side: the script rewrites its own
# port literals into a private copy and runs that
if [ -z "${PERSONA_TEST_PORTS:-}" ]; then
  export PERSONA_TEST_ROOT=$(cd "$(dirname "$0")/.." && pwd)
  ports=$(python3 - <<'PYP'
import random, socket
def free(p):
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", p)); return True
    except OSError:
        return False
    finally:
        s.close()
while True:
    b = random.randrange(20000, 29000)
    rest = random.sample(range(29100, 31000), 3)
    if all(free(x) for x in (b, b + 1, b + 2, *rest)):
        print(b, *rest); break
PYP
)
  set -- $ports
  me=$(mktemp "${TMPDIR:-/tmp}/persona-test-XXXXXX")
  perl -pe "s/\\b18080\\b/$1/g; s/\\b18081\\b/$(($1+1))/g; s/\\b18082\\b/$(($1+2))/g; s/\\b18090\\b/$2/g; s/\\b18099\\b/$3/g; s/\\b18123\\b/$4/g; s/PERSONA_TEST_PORTS:-/PERSONA_TEST_PORTS:-/" "$0" >"$me"
  rc=0; PERSONA_TEST_PORTS=1 bash "$me" "$@" || rc=$?
  rm -f "$me"; exit $rc
fi
root=${PERSONA_TEST_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}
agent="$root/bin/persona-uat-agent.py"
provider="$root/bin/persona-uat-provider.py"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
ok()   { pass=$((pass+1)); echo "ok   $1"; }
bad()  { failn=$((failn+1)); echo "FAIL $1"; }
CASE=""
check() { if "$@" >/dev/null 2>&1; then ok "$CASE"; else bad "$CASE"; fi; }
none_match() { local re=$1; shift; local p; for p in "$@"; do [ -e "$p" ] || return 2; done; local rc=0; grep -rqE "$re" "$@" || rc=$?; [ "$rc" -eq 1 ]; }
SHL="docker.io/library/debian@sha256:$(printf '4%.0s' $(seq 64))"
LABEL="persona-uat=11111111-2222-3333-4444-555555555555"      # one fresh uuid per persona, from the driver: every container the agent starts carries it
CSG="gcr.io/projectsigstore/cosign@sha256:$(printf '5%.0s' $(seq 64))"
KCT="registry.k8s.io/kubectl@sha256:$(printf '6%.0s' $(seq 64))"
GRD="docker.io/library/gradle@sha256:$(printf '7%.0s' $(seq 64))"
MVN="docker.io/library/maven@sha256:$(printf '8%.0s' $(seq 64))"
JEN="docker.io/jenkins/jenkins@sha256:$(printf '1%.0s' $(seq 64))"
GLR="docker.io/gitlab/gitlab-runner@sha256:$(printf '2%.0s' $(seq 64))"
KND="docker.io/kindest/node@sha256:$(printf '3%.0s' $(seq 64))"
cat >"$work/tools.json" <<EOF
{"capture": "docker.io/nicolaka/netshoot@sha256:$(printf 'b%.0s' $(seq 64))", "cosign": "$CSG", "gitlab-runner": "$GLR", "gradle": "$GRD", "jenkins": "$JEN", "kind": "$KND", "kubectl": "$KCT", "maven": "$MVN", "shell": "$SHL"}
EOF

# fake provider: pops the next scripted answer; records each call's stdin and the credential it can see
cat >"$work/fp.py" <<'PY'
import json, os, sys
req = json.load(sys.stdin)
case = sys.argv[1]
plan = json.load(open(os.path.join(case, "plan.json")))
log = os.path.join(case, "fp.log")
n = sum(1 for _ in open(log)) if os.path.exists(log) else 0
with open(log, "a") as fh:
    fh.write(json.dumps({"req": req, "key": os.environ.get("ANTHROPIC_API_KEY"), "env": sorted(os.environ)}) + "\n")
step = plan[min(n, len(plan) - 1)]
if step.get("stderr"):
    sys.stderr.write(step["stderr"] + "\n")
if step.get("sleep"):
    import time; time.sleep(step["sleep"])
if step.get("exit"):
    sys.exit(step["exit"])
if "raw" in step:
    sys.stdout.write(step["raw"]); sys.exit(0)
print(json.dumps(step))
PY
# fake docker: logs argv and the environment NAMES it was started with; what follows the image digest decides: `sh -c CMD` runs CMD in the -v
# host directory, anything else is a tool's own arguments (an exec: distroless images have no sh) and is echoed back as TOOLARGS:<json>
cat >"$work/docker.tmpl" <<'PY'
#!/usr/bin/env python3
import json, os, subprocess, sys
a = sys.argv[1:]
LOG = "__LOG__"
open(LOG, "a").write(json.dumps({"argv": a, "env": sorted(os.environ)}) + "\n")
REG = os.path.join(os.path.dirname(LOG), "containers")     # daemon-managed containers: they outlive a killed docker client until rm -f / stop / kill names them
if a[0] == "ps":
    lab = next((x[len("label="):] for x in a if x.startswith("label=")), None)
    if os.path.isdir(REG):
        for f in sorted(os.listdir(REG)):
            if open(os.path.join(REG, f)).read().strip() == lab:
                print(f)
    sys.exit(0)
if a[0] in ("rm", "stop", "kill"):
    for x in a[1:]:
        if os.path.exists(os.path.join(REG, x)):
            os.remove(os.path.join(REG, x))
    sys.exit(0)
host = next(x.split(":")[0] for i, x in enumerate(a) if i and a[i - 1] == "-v")
img = next((i for i, x in enumerate(a) if "@sha256:" in x), None)
rest = a[img + 1:] if img is not None else []
repo = a[img] if img is not None else ""
os.makedirs(REG, exist_ok=True)
cid = "c-%d" % os.getpid()
open(os.path.join(REG, cid), "w").write(a[a.index("--label") + 1] if "--label" in a else "")      # the container exists from here until its client returns normally
def done():
    if os.path.exists(os.path.join(REG, cid)):
        os.remove(os.path.join(REG, cid))
if not (len(rest) == 3 and rest[:2] == ["sh", "-c"]):
    # MODEL of the images' entrypoints (the exact exit status and text of a real digest's failure cannot be checked offline; the program-first convention is what is pinned): gradle (CMD ["gradle"], no ENTRYPOINT) and maven (ENTRYPOINT mvn-entrypoint.sh which exec's "$@", CMD ["mvn"]) take the
    # PROGRAM as the first argument; cosign (ENTRYPOINT ["/ko-app/cosign"]) and kubectl (ENTRYPOINT ["/bin/kubectl"]) take the SUBCOMMAND (a leading
    # program name is an unknown command). Arguments replace CMD, so a first argument that is not the program cannot run.
    for k, v in {"/gradle@": "gradle", "/maven@": "mvn"}.items():
        if k in repo and rest and rest[0] != v:
            sys.stderr.write('docker: Error response from daemon: failed to create task: exec: "%s": executable file not found in $PATH\n' % rest[0]); done(); sys.exit(127)
    for k, v in {"/cosign@": "cosign", "/kubectl@": "kubectl"}.items():
        if k in repo and rest and rest[0] == v:
            sys.stderr.write('Error: unknown command "%s" for "%s"\n' % (v, v)); done(); sys.exit(1)
    if "--fake-write" in rest:          # a tool image creating a file in the shared sandbox (as whatever uid it runs as)
        i = rest.index("--fake-write"); name, content = rest[i + 1], rest[i + 2]
        os.makedirs(os.path.dirname(os.path.join(host, name)) or host, exist_ok=True)
        open(os.path.join(host, name), "w").write(content + "\n"); done(); sys.exit(0)
    if "--fake-read" in rest:           # ... and one reading a file another tool created
        f = os.path.join(host, rest[rest.index("--fake-read") + 1])
        if not os.path.exists(f):
            sys.stderr.write("no such file\n"); done(); sys.exit(1)
        sys.stdout.write(open(f).read()); done(); sys.exit(0)
    sys.stdout.write("TOOLARGS:" + json.dumps(rest) + "\n"); done(); sys.exit(0)
if "/cosign@" in repo or "/kubectl@" in repo:       # distroless images have no shell: a tool run through sh -c fails like the real image
    sys.stderr.write('docker: Error response from daemon: exec: "sh": executable file not found in $PATH\n'); done(); sys.exit(127)
cmd = rest[2]
try:
    p = subprocess.run(["sh", "-c", cmd], cwd=host, capture_output=True, text=True, timeout=60)
    sys.stdout.write(p.stdout); sys.stderr.write(p.stderr); done(); sys.exit(p.returncode)
except subprocess.TimeoutExpired:
    done(); sys.exit(124)
PY
chmod +x "$work/docker.tmpl"

# agent <case> <plan-json> [agent flags...]  (env BUDGET, MODEL); sets rc; per-case dir $work/<case>/{sandbox,out.json}
agent() {
  local name=$1 plan=$2; shift 2
  local d="$work/$name"; mkdir -p "$d/sandbox"; echo "README" >"$d/sandbox/README.md"; echo "$plan" >"$d/plan.json"
  : >"$d/fp.log"; : >"$d/fd.log"; sed "s#__LOG__#$d/fd.log#" "$work/docker.tmpl" >"$d/docker"; chmod +x "$d/docker"
  printf '{"persona":"readme-evaluator","instructions":"You are an evaluator with only the README and ten minutes.","docs_dir":"%s","endpoint":"%s","image":"x@sha256:%s","model":"%s","token_budget":%s,"tools":{}}' \
    "$d/sandbox" "${ENDPOINT:-http://127.0.0.1:18080}" "$(printf 'a%.0s' $(seq 64))" "${MODEL:-MODEL-AGENT-X}" "${BUDGET:-400000}" >"$d/req.json"
  rc=0
  env ANTHROPIC_API_KEY=SECRET-MODEL-KEY GITHUB_TOKEN=SECRET-GH GITHUB_REPOSITORY=x/y RUNNER_TEMP=/r ACTIONS_CACHE_URL=http://c.invalid \
    GH_TOKEN=SECRET-GH2 AWS_SECRET_ACCESS_KEY=SECRET-AWS SOME_UNKNOWN_SECRET=SECRET-UNK AWS_SESSION_TOKEN=SECRET-AWS2 GH_ENTERPRISE_TOKEN=SECRET-GHE \
    python3 "$agent" --docker "$d/docker" --tools "${TOOLSFILE:-$work/tools.json}" --provider-cmd "python3 $work/fp.py $d" ${NOLABEL-"--label"} ${NOLABEL-"${LABELARG-$LABEL}"} --network "${NET-container:persona-uat-0a1b2c3d-holder}" "$@" \
    <"$d/req.json" >"$d/out.json" 2>"$d/err.txt" || rc=$?
}
calls() { wc -l <"$work/$1/fp.log" | tr -d ' '; }

# --- AC5: the budget is a hard, cumulative stop; 15% of it is RESERVED for one forced final `finish` call --------------------
# (step 8 round 1, Sonnet B3): the loop works while used < 85% of the budget, then asks ONCE for a finish ("report your findings so far"). A
# model that finishes then keeps its findings; one that does not (another action, a failing provider) is BLOCKING ("did not finish within its
# budget"), never a quiet pass. The tokens are the provider's own numbers, summed per call (never recomputed from the resent history).
STEPS='[{"usage":{"tokens":400},"action":{"type":"shell","command":"echo step"}}]'
BUDGET=1000 agent cap "$STEPS"
CASE="a model that never finishes is worked until 85% of the budget (3 calls at 400 tokens: 800 < 850, then 1200), asked ONCE more to finish (the 4th, forced call), and never called again"
check test "$rc" -eq 0 -a "$(calls cap)" -eq 4
CASE="the answer reports the provider's own tokens (1600 across the 4 calls), keeps the transcript of the three executed steps (the forced call's non-finish answer is never executed), and is BLOCKING: did not finish within its budget"
check python3 - "$work/cap/out.json" <<'PY'
import json, sys
a = json.load(open(sys.argv[1]))
assert a["tokens"] == 1600, a
assert any(f["kind"] == "blocking" and "did not finish within its budget" in f["text"] for f in a["findings"]), a
assert a["transcript"].count("$ echo step") == 3, a["transcript"]
PY
CASE="the forced call is a request to FINISH: its last message names the token budget and asks for a finish action with the findings so far, and it is the only such message"
check python3 - "$work/cap/fp.log" <<'PY'
import json, sys
calls = [json.loads(l)["req"] for l in open(sys.argv[1])]
last = calls[-1]["messages"][-1]["content"].lower()
assert "token budget" in last and "finish" in last and "findings so far" in last, last
for c in calls[:-1]:
    assert "findings so far" not in json.dumps(c["messages"][-1]).lower()
PY
BUDGET=1200 agent capexact "$STEPS"
CASE="1200 tokens spent against a 1200 budget: no more work calls, exactly one forced finish call (4 in all), never a 5th"
check test "$(calls capexact)" -eq 4
BUDGET=500 agent capone '[{"usage":{"tokens":900},"action":{"type":"shell","command":"echo only"}}]'
CASE="a single call that blows through the budget is followed by exactly one forced finish call (2 calls)"
check test "$(calls capone)" -eq 2
BUDGET=1000 agent capres '[{"usage":{"tokens":450},"action":{"type":"shell","command":"echo step"}}]'
CASE="the reserve is 15%: at 900 of 1000 tokens (past 850) the loop stops working and makes the forced finish call: 2 work calls + 1 forced = 3, not a 3rd work call"
check test "$(calls capres)" -eq 3
check python3 - "$work/capres/out.json" <<'PY'
import json, sys
a = json.load(open(sys.argv[1]))
assert a["transcript"].count("$ echo step") == 2, a["transcript"]
PY
BUDGET=1000 agent capfin '[{"usage":{"tokens":400},"action":{"type":"shell","command":"echo step"}},{"usage":{"tokens":400},"action":{"type":"shell","command":"echo step"}},
               {"usage":{"tokens":400},"action":{"type":"shell","command":"echo step"}},{"usage":{"tokens":100},"action":{"type":"finish","findings":[{"kind":"blocking","text":"step 2 fails as written (seen at step 2)"}]}}]'
CASE="a model that DOES finish when forced keeps what it observed: its findings are returned as they are (no extra 'did not finish' finding), the forced call's tokens are counted (1300), and the transcript marks the forced finish"
check python3 - "$work/capfin/out.json" <<'PY'
import json, sys
a = json.load(open(sys.argv[1]))
assert a["findings"] == [{"kind": "blocking", "text": "step 2 fails as written (seen at step 2)"}], a
assert a["tokens"] == 1300, a
assert "forced" in a["transcript"].lower() and "[finish]" in a["transcript"], a["transcript"]
PY
BUDGET=1000 agent capfail '[{"usage":{"tokens":400},"action":{"type":"shell","command":"echo step"}},{"usage":{"tokens":400},"action":{"type":"shell","command":"echo step"}},
               {"usage":{"tokens":400},"action":{"type":"shell","command":"echo step"}},{"exit":1,"stderr":"provider down"}]'
CASE="a provider that FAILS on the forced call does not crash the agent (rc 0, an answer): the persona is BLOCKING (did not finish within its budget) with the three steps it ran kept"
check python3 - "$work/capfail/out.json" "$work/capfail/err.txt" <<'PY'
import json, sys
a = json.load(open(sys.argv[1]))
assert any(f["kind"] == "blocking" and "did not finish within its budget" in f["text"] for f in a["findings"]), a
assert a["tokens"] == 1200 and a["transcript"].count("$ echo step") == 3, a
PY
CASE="no forced call when the model finishes by itself under the reserve: a finish at call 2 ends the run with 2 calls"
BUDGET=1000 agent capearly '[{"usage":{"tokens":100},"action":{"type":"shell","command":"echo step"}},{"usage":{"tokens":100},"action":{"type":"finish","findings":[]}}]'
check test "$(calls capearly)" -eq 2
agent steplimit '[{"usage":{"tokens":0},"action":{"type":"shell","command":"echo again"}}]' --max-steps 5
CASE="a model that spends no tokens and never finishes is still stopped, by the step limit (5 calls)"
check test "$rc" -eq 0 -a "$(calls steplimit)" -eq 5
check grep -qi 'step limit' "$work/steplimit/out.json"
CASE="a persona stopped by the step limit did NOT finish: that is a blocking finding (did not finish), never a quiet pass"
check python3 - "$work/steplimit/out.json" <<'PY'
import json, sys
a = json.load(open(sys.argv[1]))
assert any(f["kind"] == "blocking" and "did not finish" in f["text"].lower() for f in a["findings"]), a
PY
agent noaction '[{"usage":{"tokens":10},"action":{"type":"finish","findings":[]}}]'
CASE="a persona that finishes without running a single shell action exercised nothing: blocking, never a pass"
check python3 - "$work/noaction/out.json" <<'PY'
import json, sys
a = json.load(open(sys.argv[1]))
assert any(f["kind"] == "blocking" and "without running" in f["text"].lower() for f in a["findings"]), a
PY
agent actions '[{"usage":{"tokens":1},"action":{"type":"shell","command":"exit 3"}},{"usage":{"tokens":1},"action":{"type":"shell","command":"echo ok"}},{"usage":{"tokens":1},"action":{"type":"shell","tool":"nosuchtool","args":["x"]}},{"usage":{"tokens":1},"action":{"type":"shell","tool":"cosign","args":["version"]}},{"usage":{"tokens":1},"action":{"type":"finish","findings":[]}}]'
CASE="the answer's actions record WHAT was executed, in order: the TOOL, the argv and the exit status (shell: sh -c <command>; a tool: its args); a refused action is not among them; commands stay the display labels"
check python3 - "$work/actions/out.json" <<'PY'
import json, sys
a = json.load(open(sys.argv[1]))
assert a["commands"] == ["exit 3", "echo ok", "cosign version"], a
assert a["actions"] == [{"tool": "shell", "argv": ["sh", "-c", "exit 3"], "exit": 3}, {"tool": "shell", "argv": ["sh", "-c", "echo ok"], "exit": 0}, {"tool": "cosign", "argv": ["version"], "exit": 0}], a
assert "exits" not in a, a
PY
# --- the compliance reviewer's PROOF identifies the operation actually executed (advisor 0250, step 8 round 2): a recorded action whose TOOL is cosign, whose first
# argument (the subcommand) is `verify` (the only cosign verification docs/verify-images.md documents for an image; `verify-blob` checks a file, `gh attestation verify`
# is not a cosign command), that names the RC image by its DIGEST as an argument, and exited 0. Words in echo, a comment, a quoted string or a shell action are no proof.
RC="ghcr.io/example/cache@sha256:$(printf 'c%.0s' $(seq 64))"
OTHER="ghcr.io/example/cache@sha256:$(printf 'd%.0s' $(seq 64))"
cat >"$work/proof.py" <<'PY'
import importlib.util, json, os, sys
sp = importlib.util.spec_from_file_location("driver", sys.argv[1]); m = importlib.util.module_from_spec(sp); sp.loader.exec_module(m)
a = json.load(open(sys.argv[2]))
print("PROOF" if m.verified_digest(a, sys.argv[3]) else "NOPROOF")
PY
driver_py="$root/bin/persona-uat.py"
verdict() { python3 "$work/proof.py" "$driver_py" "$work/$1/out.json" "$RC"; }
ISS="https://token.actions.githubusercontent.com"
IDRE="^https://github.com/example/cache/.github/workflows/stage-promote.yml@refs/tags/v1.0.0$"
IDF='"--certificate-identity-regexp='"$IDRE"'","--certificate-oidc-issuer='"$ISS"'"'
PROOFCASES=(
 'px-echo|{"type":"shell","command":"echo verify '"$RC"'"}|NOPROOF'
 'px-comment|{"type":"shell","command":"true # sbom '"$RC"'"}|NOPROOF'
 'px-shellcosign|{"type":"shell","command":"cosign verify '"$RC"'"}|NOPROOF'
 'px-quoted|{"type":"shell","command":"sh -c \"cosign verify '"$RC"'\""}|NOPROOF'
 'px-shelltoolcosign|{"type":"shell","tool":"shell","command":"cosign verify-attestation '"$RC"'"}|NOPROOF'
 'px-version|{"type":"shell","tool":"cosign","args":["version","'"$RC"'"]}|NOPROOF'
 'px-otherdigest|{"type":"shell","tool":"cosign","args":["verify","'"$OTHER"'"]}|NOPROOF'
 'px-flagvalue|{"type":"shell","tool":"cosign","args":["verify","--certificate-identity=x@sha256:'"$(printf 'c%.0s' $(seq 64))"'","ghcr.io/example/cache:1.0"]}|NOPROOF'
 'px-verifyblob|{"type":"shell","tool":"cosign","args":["verify-blob","'"$RC"'"]}|NOPROOF'
 'px-tagonly|{"type":"shell","tool":"cosign","args":["verify","ghcr.io/example/cache:1.0"]}|NOPROOF'
 'px-kubectlverify|{"type":"shell","tool":"kubectl","args":["verify","'"$RC"'"]}|NOPROOF'
 'px-help|{"type":"shell","tool":"cosign","args":["verify","--help","'"$RC"'"]}|NOPROOF'
 'px-h|{"type":"shell","tool":"cosign","args":["verify","-h","'"$RC"'"]}|NOPROOF'
 'px-version2|{"type":"shell","tool":"cosign","args":["verify","--version","'"$RC"'"]}|NOPROOF'
 'px-helpafter|{"type":"shell","tool":"cosign","args":["verify","'"$RC"'","--help"]}|NOPROOF'
 'px-helpfirst|{"type":"shell","tool":"cosign","args":["--help","verify","'"$RC"'"]}|NOPROOF'
 'px-flagvalue-sep|{"type":"shell","tool":"cosign","args":["verify","--certificate-identity","'"$RC"'","ghcr.io/example/cache:1.0"]}|NOPROOF'
 'px-flagvalue-other|{"type":"shell","tool":"cosign","args":["verify","--certificate-identity=x","'"$OTHER"'"]}|NOPROOF'
 'px-twopositionals|{"type":"shell","tool":"cosign","args":["verify","'"$OTHER"'","'"$RC"'"]}|NOPROOF'
 'px-unknownflag|{"type":"shell","tool":"cosign","args":["verify","--mystery","'"$RC"'"]}|NOPROOF'
 'px-att-notype|{"type":"shell","tool":"cosign","args":["verify-attestation","'"$RC"'"]}|NOPROOF'
 'px-att-help|{"type":"shell","tool":"cosign","args":["verify-attestation","--type","slsaprovenance","-h","'"$RC"'"]}|NOPROOF'
 'px-good|{"type":"shell","tool":"cosign","args":["verify",'"$IDF"',"'"$RC"'"]}|PROOF'
 'px-good-exact|{"type":"shell","tool":"cosign","args":["verify","--certificate-identity=https://github.com/example/cache/.github/workflows/stage-promote.yml@refs/tags/v1.0.0","--certificate-oidc-issuer='"$ISS"'","'"$RC"'"]}|PROOF'
 'px-good-sep|{"type":"shell","tool":"cosign","args":["verify","--certificate-identity-regexp","^https://github\\.com/example/cache/\\.github/workflows/stage-promote\\.yml@refs/tags/v1\\.0\\.0$","--certificate-oidc-issuer","'"$ISS"'","'"$RC"'"]}|PROOF'
 'px-good-output|{"type":"shell","tool":"cosign","args":["verify",'"$IDF"',"-o","json","'"$RC"'"]}|PROOF'
 'px-otherrepo-samedigest|{"type":"shell","tool":"cosign","args":["verify",'"$IDF"',"registry.example/other/repo@sha256:'"$(printf 'c%.0s' $(seq 64))"'"]}|NOPROOF'
 'px-evilrepo-samedigest|{"type":"shell","tool":"cosign","args":["verify",'"$IDF"',"ghcr.io/evil/cache@sha256:'"$(printf 'c%.0s' $(seq 64))"'"]}|NOPROOF'
 'px-key|{"type":"shell","tool":"cosign","args":["verify","--key","cosign.pub",'"$IDF"',"'"$RC"'"]}|NOPROOF'
 'px-key-only|{"type":"shell","tool":"cosign","args":["verify","--key=cosign.pub","'"$RC"'"]}|NOPROOF'
 'px-att-only|{"type":"shell","tool":"cosign","args":["verify-attestation","--type","slsaprovenance",'"$IDF"',"'"$RC"'"]}|NOPROOF'
 'px-att-good-flags|{"type":"shell","tool":"cosign","args":["verify-attestation",'"$IDF"',"'"$RC"'"]}|NOPROOF'
 'px-att-typeeq|{"type":"shell","tool":"cosign","args":["verify-attestation","--type=spdxjson","'"$RC"'"]}|NOPROOF'
 'px-noid|{"type":"shell","tool":"cosign","args":["verify","--certificate-oidc-issuer='"$ISS"'","'"$RC"'"]}|NOPROOF'
 'px-noissuer|{"type":"shell","tool":"cosign","args":["verify","--certificate-identity-regexp='"$IDRE"'","'"$RC"'"]}|NOPROOF'
 'px-wrongid-workflow|{"type":"shell","tool":"cosign","args":["verify","--certificate-identity-regexp=^https://github.com/example/cache/.github/workflows/release.yml@refs/tags/v1.0.0$","--certificate-oidc-issuer='"$ISS"'","'"$RC"'"]}|NOPROOF'
 'px-wrongid-repo|{"type":"shell","tool":"cosign","args":["verify","--certificate-identity-regexp=^https://github.com/evil/cache/.github/workflows/stage-promote.yml@refs/tags/v1.0.0$","--certificate-oidc-issuer='"$ISS"'","'"$RC"'"]}|NOPROOF'
 'px-id-alternation|{"type":"shell","tool":"cosign","args":["verify","--certificate-identity-regexp=^https://github.com/example/cache/.github/workflows/stage-promote.yml@refs/tags/v1.0.0$|.*","--certificate-oidc-issuer='"$ISS"'","'"$RC"'"]}|NOPROOF'
 'px-id-tag-wild|{"type":"shell","tool":"cosign","args":["verify","--certificate-identity-regexp=^https://github.com/example/cache/.github/workflows/stage-promote.yml@refs/tags/v.*","--certificate-oidc-issuer='"$ISS"'","'"$RC"'"]}|NOPROOF'
 'px-id-tag-plus|{"type":"shell","tool":"cosign","args":["verify","--certificate-identity-regexp=^https://github.com/example/cache/.github/workflows/stage-promote.yml@refs/tags/v1.0.0.+","--certificate-oidc-issuer='"$ISS"'","'"$RC"'"]}|NOPROOF'
 'px-id-tag-class|{"type":"shell","tool":"cosign","args":["verify","--certificate-identity-regexp=^https://github.com/example/cache/.github/workflows/stage-promote.yml@refs/tags/v1.0.[0-9]","--certificate-oidc-issuer='"$ISS"'","'"$RC"'"]}|NOPROOF'
 'px-id-tag-empty|{"type":"shell","tool":"cosign","args":["verify","--certificate-identity-regexp=^https://github.com/example/cache/.github/workflows/stage-promote.yml@refs/tags/v$","--certificate-oidc-issuer='"$ISS"'","'"$RC"'"]}|NOPROOF'
 'px-id-tag-group|{"type":"shell","tool":"cosign","args":["verify","--certificate-identity-regexp=^https://github.com/example/cache/.github/workflows/stage-promote.yml@refs/tags/v1.0.0(x)?$","--certificate-oidc-issuer='"$ISS"'","'"$RC"'"]}|NOPROOF'
 'px-id-wild|{"type":"shell","tool":"cosign","args":["verify","--certificate-identity-regexp=.*","--certificate-oidc-issuer='"$ISS"'","'"$RC"'"]}|NOPROOF'
 'px-id-two-one-bad|{"type":"shell","tool":"cosign","args":["verify",'"$IDF"',"--certificate-identity=https://github.com/evil/x/.github/workflows/y.yml@refs/heads/main","'"$RC"'"]}|NOPROOF'
 'px-badissuer|{"type":"shell","tool":"cosign","args":["verify","--certificate-identity-regexp='"$IDRE"'","--certificate-oidc-issuer=https://evil.example","'"$RC"'"]}|NOPROOF'
 'px-issuer-regexp|{"type":"shell","tool":"cosign","args":["verify","--certificate-identity-regexp='"$IDRE"'","--certificate-oidc-issuer-regexp=.*","'"$RC"'"]}|NOPROOF'
 'px-offline|{"type":"shell","tool":"cosign","args":["verify","--offline",'"$IDF"',"'"$RC"'"]}|NOPROOF'
 'px-insecure-tlog|{"type":"shell","tool":"cosign","args":["verify","--insecure-ignore-tlog",'"$IDF"',"'"$RC"'"]}|NOPROOF'
 'px-given-cert|{"type":"shell","tool":"cosign","args":["verify","--certificate","cert.pem",'"$IDF"',"'"$RC"'"]}|NOPROOF'
 'px-good-but-unknownflag|{"type":"shell","tool":"cosign","args":["verify","--mystery",'"$IDF"',"'"$RC"'"]}|NOPROOF'
 'px-good-plus-help|{"type":"shell","tool":"cosign","args":["verify",'"$IDF"',"--help=true","'"$RC"'"]}|NOPROOF'
 'px-help-true|{"type":"shell","tool":"cosign","args":["verify","--help=true","'"$RC"'"]}|NOPROOF'
 'px-help-false|{"type":"shell","tool":"cosign","args":["verify","--help=false","'"$RC"'"]}|NOPROOF'
 'px-help-after-true|{"type":"shell","tool":"cosign","args":["verify","'"$RC"'","--help=true"]}|NOPROOF'
 'px-onedash-help|{"type":"shell","tool":"cosign","args":["verify","-help","'"$RC"'"]}|NOPROOF'
 'px-abbrev-hel|{"type":"shell","tool":"cosign","args":["verify","--hel","'"$RC"'"]}|NOPROOF'
 'px-abbrev-he|{"type":"shell","tool":"cosign","args":["verify","--he","'"$RC"'"]}|NOPROOF'
 'px-abbrev-h|{"type":"shell","tool":"cosign","args":["verify","--h","'"$RC"'"]}|NOPROOF'
 'px-help-upper|{"type":"shell","tool":"cosign","args":["verify","--HELP=1","'"$RC"'"]}|NOPROOF'
 'px-version-true|{"type":"shell","tool":"cosign","args":["verify","--version=true","'"$RC"'"]}|NOPROOF'
 'px-onedash-version|{"type":"shell","tool":"cosign","args":["verify","-version","'"$RC"'"]}|NOPROOF'
 'px-abbrev-ver|{"type":"shell","tool":"cosign","args":["verify","--ver","'"$RC"'"]}|NOPROOF'
 'px-cluster-h|{"type":"shell","tool":"cosign","args":["verify","-dh","'"$RC"'"]}|NOPROOF'
 'px-att-help-true|{"type":"shell","tool":"cosign","args":["verify-attestation","--type","slsaprovenance","--help=true","'"$RC"'"]}|NOPROOF'
)
for pc in "${PROOFCASES[@]}"; do
  name=${pc%%|*}; rest=${pc#*|}; act=${rest%|*}; want=${rest##*|}
  agent "$name" "[{\"usage\":{\"tokens\":1},\"action\":$act},{\"usage\":{\"tokens\":1},\"action\":{\"type\":\"finish\",\"findings\":[]}}]"
  CASE="compliance proof via the REAL agent loop ($name): the driver's predicate reads $want (the tool field, the subcommand and the digest argument decide, never keywords in text)"
  check test "$(verdict "$name")" = "$want"
done
CASE="compliance proof: a verification action that FAILED (cosign exit 1) is no proof, whatever it names"
python3 - "$work" <<'PY'
import json, sys
a = {"commands": ["cosign verify x"], "actions": [{"tool": "cosign", "argv": ["verify", "ghcr.io/example/cache@sha256:" + "c" * 64], "exit": 1}], "findings": [], "tokens": 1, "transcript": ""}
json.dump(a, open(sys.argv[1] + "/failedproof.json", "w"))
PY
check test "$(python3 "$work/proof.py" "$driver_py" "$work/failedproof.json" "$RC")" = "NOPROOF"
# --- the transcript is STREAMED to a file after every action (step 8 round 1, Codex B5): a timeout kill keeps the completed actions ------------------------
# --transcript-file PATH (the driver passes a private file OUTSIDE the sandbox, so no shell action can read or delete it): every executed action is appended,
# scrubbed, and flushed and fsynced before the next model call.
agent tfile '[{"usage":{"tokens":10},"action":{"type":"shell","command":"echo first-action-output"}},{"usage":{"tokens":10},"action":{"type":"shell","command":"echo second-action"}},{"usage":{"tokens":10},"action":{"type":"finish","findings":[{"kind":"friction","text":"f"}]}}]' --transcript-file "$work/tfile.log"
CASE="the transcript file holds every executed action and its output, scrubbed, and equals the answer's transcript when the run ends normally"
check python3 - "$work/tfile.log" "$work/tfile/out.json" <<'PY'
import json, sys
f = open(sys.argv[1]).read()
a = json.load(open(sys.argv[2]))
assert "$ echo first-action-output" in f and "first-action-output" in f.split("$ echo first-action-output", 1)[1] and "$ echo second-action" in f, f
assert f.strip() == a["transcript"].strip(), (f, a["transcript"])
PY
BUDGET=1000 MODEL=MODEL-TF-X agent tscrub '[{"usage":{"tokens":10},"action":{"type":"shell","command":"echo MODEL-TF-X ghp_abcdefghijkl"}},{"usage":{"tokens":10},"action":{"type":"finish","findings":[]}}]' --transcript-file "$work/tscrub.log"
CASE="the transcript file is scrubbed like the answer: neither the model name nor a credential-looking string is in it"
check none_match 'MODEL-TF-X|ghp_abcdefghijkl' "$work/tscrub.log"
# a REAL agent subprocess killed after one completed action (the second model call hangs): the file keeps the first action
mkdir -p "$work/tkill/sandbox"; echo README >"$work/tkill/sandbox/README.md"; echo '[{"usage":{"tokens":10},"action":{"type":"shell","command":"echo completed-before-kill"}},{"usage":{"tokens":10},"sleep":300,"action":{"type":"finish","findings":[]}}]' >"$work/tkill/plan.json"
: >"$work/tkill/fp.log"; : >"$work/tkill/fd.log"; sed "s#__LOG__#$work/tkill/fd.log#" "$work/docker.tmpl" >"$work/tkill/docker"; chmod +x "$work/tkill/docker"; rm -f "$work/tkill/t.log"
printf '{"persona":"readme-evaluator","instructions":"x","docs_dir":"%s","endpoint":"http://127.0.0.1:18080","image":"x@sha256:%s","model":"M-K","token_budget":400000,"tools":{}}' "$work/tkill/sandbox" "$(printf 'a%.0s' $(seq 64))" >"$work/tkill/req.json"
python3 - "$agent" "$work" <<'PY'
import os, signal, subprocess, sys, time
agent, w = sys.argv[1:3]
d = w + "/tkill"
p = subprocess.Popen(["python3", agent, "--docker", d + "/docker", "--tools", w + "/tools.json", "--provider-cmd", "python3 %s/fp.py %s" % (w, d), "--label", "persona-uat=11111111-2222-3333-4444-555555555555", "--network", "container:persona-uat-0a1b2c3d-holder",
                      "--transcript-file", d + "/t.log"], stdin=open(d + "/req.json"), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
end = time.time() + 30
while time.time() < end and not (os.path.exists(d + "/t.log") and "completed-before-kill" in open(d + "/t.log").read()):
    time.sleep(0.2)
try:
    os.killpg(p.pid, signal.SIGKILL)
except (ProcessLookupError, PermissionError):
    pass
p.wait()
PY
CASE="a REAL agent process killed (SIGKILL) while its second model call hangs keeps the completed action in the transcript file (written and flushed before the next call)"
check grep -q 'completed-before-kill' "$work/tkill/t.log"
agent tcap '[{"usage":{"tokens":1},"action":{"type":"shell","command":"echo first-line-kept"}},{"usage":{"tokens":1},"action":{"type":"shell","command":"seq 1 400"}},{"usage":{"tokens":1},"action":{"type":"finish","findings":[]}}]' --transcript-file "$work/tcap.log" --transcript-max-bytes 600
CASE="the streamed transcript file is capped (--transcript-max-bytes, 16 MiB by default): the first actions are kept, one explicit marker says the rest was not written, the file never grows past the cap, and the ANSWER's transcript is complete"
check python3 - "$work/tcap.log" "$work/tcap/out.json" <<'PY'
import json, sys
f = open(sys.argv[1]).read()
a = json.load(open(sys.argv[2]))
assert "echo first-line-kept" in f and "first-line-kept" in f.split("echo first-line-kept", 1)[1], f
assert f.count("[... the transcript file reached its cap") == 1, f[-200:]
assert len(f.encode()) <= 600 + 200, len(f.encode())
assert "400" in a["transcript"], "the answer's own transcript must stay complete"
PY
CASE="an unwritable --transcript-file fails the agent closed (non-zero, nothing on stdout): a transcript that cannot be kept is not a run"
agent tbad '[{"usage":{"tokens":10},"action":{"type":"finish","findings":[]}}]' --transcript-file /nonexistent-dir/t.log
check test "$rc" -ne 0 -a ! -s "$work/tbad/out.json"

# --- the JOURNAL (debate round, B2): a structured record BEFORE each command runs, a result record after -----------------------------------------
# --journal-file PATH (private, outside the sandbox, like the transcript file): one JSON object per line. {"t":"action","id","command","started_at"} is written, flushed and fsynced BEFORE the command
# is launched; {"t":"result","id","exit","bytes","truncated"} after. A command killed or timed out before it returned is recoverable from its action record alone.
agent jrn '[{"usage":{"tokens":10},"action":{"type":"shell","command":"echo first-j\necho second-line-j"}},{"usage":{"tokens":10},"action":{"type":"shell","command":"seq 1 5000"}},{"usage":{"tokens":10},"action":{"type":"finish","findings":[]}}]' --journal-file "$work/jrn.log"
CASE="the journal holds an action record then a result record per executed command: the id joins them, a multi-line command is one JSON string, the result has the exit status, byte counts and truncation flags (a 5000-line output is clipped for the model: truncated true)"
check python3 - "$work/jrn.log" <<'PY'
import json, sys
recs = [json.loads(l) for l in open(sys.argv[1])]
kinds = [(r["t"], r["id"]) for r in recs]
assert kinds == [("action", 1), ("result", 1), ("action", 2), ("result", 2)], kinds
assert recs[0]["command"] == "echo first-j\necho second-line-j" and recs[0]["started_at"], recs[0]
assert recs[1]["exit"] == 0 and set(recs[1]["bytes"]) == {"stdout", "stderr"} and recs[1]["truncated"] == {"stdout": False, "stderr": False}, recs[1]
assert recs[3]["truncated"]["stdout"] is True and recs[3]["bytes"]["stdout"] > 8000, recs[3]
assert not any(r.get("command_truncated") for r in recs)
PY
BUDGET=1000 MODEL=MODEL-JR-X agent jscrub '[{"usage":{"tokens":10},"action":{"type":"shell","command":"echo MODEL-JR-X ghp_abcdefghijkl"}},{"usage":{"tokens":10},"action":{"type":"finish","findings":[]}}]' --journal-file "$work/jscrub.log"
CASE="the journal is scrubbed like the transcript: neither the model name nor a credential-looking string is in it"
check none_match 'MODEL-JR-X|ghp_abcdefghijkl' "$work/jscrub.log"
# a REAL agent whose command's docker client kills the agent at execution entry (SIGKILL): the action record is already in the journal and there is no result record
mkdir -p "$work/jkill/sandbox"; echo README >"$work/jkill/sandbox/README.md"; echo '[{"usage":{"tokens":10},"action":{"type":"shell","command":"curl http://killed-before-return.example/\necho more"}},{"usage":{"tokens":10},"action":{"type":"finish","findings":[]}}]' >"$work/jkill/plan.json"
: >"$work/jkill/fp.log"; printf '#!/bin/sh\nkill -9 $PPID\nsleep 5\n' >"$work/jkill/docker"; chmod +x "$work/jkill/docker"; rm -f "$work/jkill/j.log"
printf '{"persona":"readme-evaluator","instructions":"x","docs_dir":"%s","endpoint":"http://127.0.0.1:18080","image":"x@sha256:%s","model":"M-K","token_budget":400000,"tools":{}}' "$work/jkill/sandbox" "$(printf 'a%.0s' $(seq 64))" >"$work/jkill/req.json"
python3 - "$agent" "$work" <<'PY'
import subprocess, sys
agent, w = sys.argv[1:3]
d = w + "/jkill"
p = subprocess.Popen(["python3", agent, "--docker", d + "/docker", "--tools", w + "/tools.json", "--provider-cmd", "python3 %s/fp.py %s" % (w, d), "--label", "persona-uat=11111111-2222-3333-4444-555555555555", "--network", "container:persona-uat-0a1b2c3d-holder",
                      "--journal-file", d + "/j.log", "--transcript-file", d + "/t.log"], stdin=open(d + "/req.json"), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
p.wait(timeout=60)
PY
CASE="an interruption at execution entry (the process is killed as the command is launched) leaves the command in the journal as an action record with no result record, and the multi-line command whole"
check python3 - "$work/jkill/j.log" <<'PY'
import json, sys
recs = [json.loads(l) for l in open(sys.argv[1])]
assert [(r["t"], r["id"]) for r in recs] == [("action", 1)], recs
assert recs[0]["command"] == "curl http://killed-before-return.example/\necho more", recs
PY
agent jline '[{"usage":{"tokens":1},"action":{"type":"shell","command":"echo 0123456789012345678901234567890123456789012345678901234567890123456789"}},{"usage":{"tokens":1},"action":{"type":"finish","findings":[]}}]' --journal-file "$work/jline.log" --journal-line-max 40
CASE="a command longer than the journal's line cap is stored cut to the cap with command_truncated true and its original length, never silently shortened"
check python3 - "$work/jline.log" <<'PY'
import json, sys
recs = [json.loads(l) for l in open(sys.argv[1])]
a = recs[0]
assert a["t"] == "action" and len(a["command"]) <= 40 and a["command_truncated"] is True and a["command_length"] == len("echo 0123456789012345678901234567890123456789012345678901234567890123456789"), a
PY
agent jcap '[{"usage":{"tokens":1},"action":{"type":"shell","command":"echo first-kept"}},{"usage":{"tokens":1},"action":{"type":"shell","command":"echo second-kept-maybe"}},{"usage":{"tokens":1},"action":{"type":"shell","command":"echo third-not-written"}},{"usage":{"tokens":1},"action":{"type":"finish","findings":[]}}]' --journal-file "$work/jcap.log" --journal-max-bytes 400
CASE="the journal is capped (--journal-max-bytes): exactly one journal_cap record says later records are not written, the file never grows past the cap plus that one record, and the answer's own command list stays complete"
check python3 - "$work/jcap.log" "$work/jcap/out.json" <<'PY'
import json, os, sys
raw = open(sys.argv[1]).read()
recs = [json.loads(l) for l in raw.splitlines()]
caps = [r for r in recs if r["t"] == "journal_cap"]
assert len(caps) == 1 and recs[-1]["t"] == "journal_cap", recs
assert "third-not-written" not in raw and "first-kept" in raw, raw
assert len(raw.encode()) <= 400 + 200, len(raw.encode())
a = json.load(open(sys.argv[2]))
assert a["commands"] == ["echo first-kept", "echo second-kept-maybe", "echo third-not-written"], a["commands"]
PY
agent jbad '[{"usage":{"tokens":10},"action":{"type":"finish","findings":[]}}]' --journal-file /nonexistent-dir/j.log
CASE="an unwritable --journal-file fails the agent closed (non-zero, nothing on stdout): commands that cannot be recorded are not run"
check test "$rc" -ne 0 -a ! -s "$work/jbad/out.json"

# --- the loop works: actions run, their output goes back, a finish ends it ----------------------------------------
agent finish '[{"usage":{"tokens":300},"action":{"type":"shell","command":"echo $((6*7)) > made.txt; cat made.txt"}},
               {"usage":{"tokens":250},"action":{"type":"finish","findings":[{"kind":"friction","text":"first step unclear"},{"kind":"blocking","text":"step 2 fails as written"}]}}]'
CASE="the shell action ran (its file exists in the sandbox), its output went back to the model, and the finish ended the run"
check test "$rc" -eq 0 -a "$(calls finish)" -eq 2 -a -s "$work/finish/sandbox/made.txt"
check python3 - "$work/finish/fp.log" "$work/finish/out.json" <<'PY'
import json, sys
calls = [json.loads(l) for l in open(sys.argv[1])]
first_cmd = json.dumps(calls[0]["req"]["messages"])
assert "42" not in first_cmd and "42" in json.dumps(calls[1]["req"]["messages"]), "the action's COMPUTED output never reached the model"
a = json.load(open(sys.argv[2]))
assert a["findings"] == [{"kind": "friction", "text": "first step unclear"}, {"kind": "blocking", "text": "step 2 fails as written"}], a
assert a["tokens"] == 550, a
assert a["commands"] == ["echo $((6*7)) > made.txt; cat made.txt"] and a["actions"] == [{"tool": "shell", "argv": ["sh", "-c", "echo $((6*7)) > made.txt; cat made.txt"], "exit": 0}], ("every executed action has its tool, argv and exit status, in order", a)
assert "42" in a["transcript"] and "step 2 fails" in a["transcript"], a
PY
CASE="the first model call carries the restriction: only the public documentation, do not clone the repository, do not read its source"
check python3 - "$work/finish/fp.log" <<'PY'
import json, sys
r = json.loads(open(sys.argv[1]).readline())["req"]
s = (r["system"] + json.dumps(r["messages"])).lower()
assert "only the public documentation" in s and "do not clone" in s and "source" in s, s
PY
CASE="the first model call carries the persona's instructions and the endpoint"
check python3 - "$work/finish/fp.log" <<'PY'
import json, sys
r = json.loads(open(sys.argv[1]).readline())["req"]
s = r["system"] + json.dumps(r["messages"])
assert "evaluator with only the README" in s and "http://127.0.0.1:18080" in s, s
PY

# --- a FAILING documented step: its exit status and stderr (not merged into stdout) reach the model, and the model's finding is driven by them
agent failcmd '[{"usage":{"tokens":10},"action":{"type":"shell","command":"echo before; echo oops-on-stderr >&2; exit 3"}},{"usage":{"tokens":10},"action":{"type":"finish","findings":[{"kind":"blocking","text":"step failed"}]}}]'
CASE="a command that fails: the model receives its exit status (3), its stdout AND its stderr, labelled, in the next request"
check python3 - "$work/failcmd/fp.log" <<'PY'
import json, sys
calls = [json.loads(l) for l in open(sys.argv[1])]
m = json.dumps(calls[1]["req"]["messages"])
assert "exit status: 3" in m and "before" in m and "oops-on-stderr" in m, m
assert "stderr" in m.lower(), "stderr is not labelled as such"
PY
CASE="and the transcript keeps the failing command's status and stderr too"
check grep -q 'exit status: 3' "$work/failcmd/out.json"
check grep -q 'oops-on-stderr' "$work/failcmd/out.json"

# --- delta 4 (advisor 0207): whether the endpoint was contacted is NO LONGER decided here. The driver proves it with the endpoint's request
# counter before and after the persona's window. The three former cases (an irrelevant action then a clean finish was blocking; naming an
# unreachable endpoint was blocking; reaching it was needed for a clean pass) are CHANGED: the agent adds no finding about the endpoint at all.
agent irrelevant '[{"usage":{"tokens":10},"action":{"type":"shell","command":"true"}},{"usage":{"tokens":10},"action":{"type":"finish","findings":[]}}]'
CASE="an irrelevant action followed by an empty finish: the agent adds NO endpoint finding (contact is proved by the driver's request counter, not guessed here)"
check python3 - "$work/irrelevant/out.json" <<'PY'
import json, sys
a = json.load(open(sys.argv[1]))
assert a["findings"] == [], a
PY
python3 -m http.server 18080 --bind 127.0.0.1 --directory "$work" >/dev/null 2>&1 & SRV=$!
trap 'kill $SRV 2>/dev/null; rm -rf "$work"' EXIT
for _ in 1 2 3 4 5 6 7 8 9 10; do python3 -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:18080')" 2>/dev/null && break; sleep 0.3; done
echo "ok-endpoint" >"$work/healthz"
ENDPOINT=http://127.0.0.1:18099 agent neverreached '[{"usage":{"tokens":10},"action":{"type":"shell","command":"curl -s http://127.0.0.1:18099/healthz || true"}},{"usage":{"tokens":10},"action":{"type":"finish","findings":[]}}]'
CASE="a command naming an endpoint where nothing listens (output empty) no longer earns a finding from the agent either: findings stay empty and none mentions the endpoint (an implementation that kept the old 'reached' rule fails this)"
check python3 - "$work/neverreached/out.json" <<'PY'
import json, sys
a = json.load(open(sys.argv[1]))
assert a["findings"] == [] and "endpoint" not in json.dumps(a["findings"]).lower(), a
PY
agent contacted '[{"usage":{"tokens":10},"action":{"type":"shell","command":"curl -s http://127.0.0.1:18080/healthz"}},{"usage":{"tokens":10},"action":{"type":"finish","findings":[]}}]'
CASE="a persona whose command reached the endpoint (exit 0, a non-empty answer) may finish clean (findings stay empty)"
check python3 - "$work/contacted/out.json" <<'PY'
import json, sys
assert json.load(open(sys.argv[1]))["findings"] == []
PY
CASE="a persona that reports its own findings keeps them, endpoint contact or not"
check python3 - "$work/finish/out.json" <<'PY'
import json, sys
a = json.load(open(sys.argv[1]))
assert a["findings"] == [{"kind": "friction", "text": "first step unclear"}, {"kind": "blocking", "text": "step 2 fails as written"}], a
PY

# --- AC5 (and AC4): the shell is a pinned, unprivileged container that can see ONLY the sandbox -------------------
CASE="every shell action's docker call is EXACTLY: run --rm --network container:<the persona's holder> --label persona-uat=<uuid> -v <sandbox>:/work -w /work <pinned shell image> sh -c <command>"
check python3 - "$work/finish/fd.log" "$work/finish/sandbox" "$SHL" <<'PY'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1])]
assert rows, "no shell action went through docker"
for r in rows:
    a = r["argv"]
    # a full-argv ALLOWLIST: nothing can be added (no --privileged, --mount, --volume, --env=, -eX=Y, --user, --device ...)
    assert a[:12] == ["run", "--rm", "--network", "container:persona-uat-0a1b2c3d-holder", "--label", "persona-uat=11111111-2222-3333-4444-555555555555", "-v", sys.argv[2] + ":/work", "-w", "/work", sys.argv[3], "sh"], a
    assert a[12] == "-c" and len(a) == 14, a
PY
CASE="the endpoint is reachable from the shell by name: every action joins the persona's holder container's network (--network container:<holder>), never the host's"
check python3 - "$work/finish/fd.log" <<'PY'
import json, sys
rows = [json.loads(l)["argv"] for l in open(sys.argv[1])]
assert rows and all(a[a.index("--network") + 1] == "container:persona-uat-0a1b2c3d-holder" for a in rows), rows
PY
# the network is a refused vector unless it is the persona's own holder: the agent exits non-zero and runs nothing
for nv in host bridge none "container:other" "container:persona-uat-0a1b2c3d-holder;x" "container:persona-uat-0a1b2c3d" "container:persona-uat-0a1b2c3d-holder --privileged" "HOST" "x"; do
  NET="$nv" agent "nethost" '[{"usage":{"tokens":10},"action":{"type":"shell","command":"echo ran > ran.txt"}},{"usage":{"tokens":10},"action":{"type":"finish","findings":[]}}]'
  CASE="--network '$nv' is refused: the agent exits non-zero with nothing on stdout and runs no container"
  check test "$rc" -ne 0 -a ! -s "$work/nethost/out.json" -a ! -s "$work/nethost/fd.log" -a ! -e "$work/nethost/sandbox/ran.txt"
done
rm -rf "$work/nonet"; mkdir -p "$work/nonet/sandbox"; echo README >"$work/nonet/sandbox/README.md"; : >"$work/nonet/fp.log"; : >"$work/nonet/fd.log"; echo '[]' >"$work/nonet/plan.json"; sed "s#__LOG__#$work/nonet/fd.log#" "$work/docker.tmpl" >"$work/nonet/docker"; chmod +x "$work/nonet/docker"
printf '{"persona":"readme-evaluator","instructions":"x","docs_dir":"%s","endpoint":"http://endpoint:8080","image":"x@sha256:%s","model":"M","token_budget":1000,"tools":{}}' "$work/nonet/sandbox" "$(printf 'a%.0s' $(seq 64))" >"$work/nonet/req.json"
rc=0; python3 "$agent" --docker "$work/nonet/docker" --tools "$work/tools.json" --provider-cmd "python3 $work/fp.py $work/nonet" --label "$LABEL" <"$work/nonet/req.json" >"$work/nonet/out.json" 2>/dev/null || rc=$?
CASE="a missing --network is refused too (there is no default network): non-zero, nothing on stdout, no container"
check test "$rc" -ne 0 -a ! -s "$work/nonet/out.json" -a ! -s "$work/nonet/fd.log"
CASE="the docker call's environment is an allowlist: PATH, HOME and the docker client's own settings, no model or GitHub credential"
check python3 - "$work/finish/fd.log" <<'PY'
import json, sys
ok = {"PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "TMPDIR", "PWD", "SHLVL", "_", "__CF_USER_TEXT_ENCODING",
      "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT"}
for l in open(sys.argv[1]):
    env = json.loads(l)["env"]
    extra = [k for k in env if k not in ok]
    assert not extra, extra
PY
CASE="the provider (and only the provider) is given the model credential"
check python3 - "$work/finish/fp.log" <<'PY'
import json, sys
assert all(json.loads(l)["key"] == "SECRET-MODEL-KEY" for l in open(sys.argv[1]))
PY
CASE="fence 1: docker flags typed by the model stay INSIDE the command argument: the docker argv is the same fixed shape (12 tokens), never a new option"
agent flags '[{"usage":{"tokens":10},"action":{"type":"shell","command":"--privileged -v /:/host --network host --pid=host -e AWS_SECRET_ACCESS_KEY=x /var/run/docker.sock"}},{"usage":{"tokens":10},"action":{"type":"finish","findings":[]}}]'
check python3 - "$work/flags/fd.log" "$work/flags/sandbox" "$SHL" <<'PY'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1])]
assert len(rows) == 1
a = rows[0]["argv"]
assert a[:12] == ["run", "--rm", "--network", "container:persona-uat-0a1b2c3d-holder", "--label", "persona-uat=11111111-2222-3333-4444-555555555555", "-v", sys.argv[2] + ":/work", "-w", "/work", sys.argv[3], "sh"] and a[12] == "-c" and len(a) == 14, a
assert a.count("-v") == 1 and "--privileged" not in a[:12] and "--pid=host" not in a[:12]
PY
CASE="fence 1: the provider's environment holds the model identity and no job credential (no GitHub, AWS, ACTIONS_* or unknown variable)"
check python3 - "$work/finish/fp.log" <<'PY'
import json, re, sys
bad = re.compile(r"^(AWS_.*|ACTIONS_.*|GITHUB_.*|GH_.*|RUNNER_.*|SOME_UNKNOWN_SECRET)$")
rows = [json.loads(l) for l in open(sys.argv[1])]
assert rows
for r in rows:
    assert not [k for k in r["env"] if bad.match(k)], r["env"]
    assert "ANTHROPIC_API_KEY" in r["env"]
PY
CASE="fence 2: the agent never echoes its transcript or the shell output to its own stderr (the driver captures stderr, but nothing there is a transcript)"
check none_match 'step 2 fails|first step unclear|42' "$work/finish/err.txt"
agent timeout '[{"usage":{"tokens":10},"action":{"type":"shell","command":"sleep 5"}},{"usage":{"tokens":10},"action":{"type":"finish","findings":[]}}]' --shell-timeout 1
CASE="a shell action that runs too long is cut off, the model is told, and the persona carries on"
check test "$rc" -eq 0 -a "$(calls timeout)" -eq 2
check grep -qi 'timed out' "$work/timeout/out.json"
agent bigout '[{"usage":{"tokens":10},"action":{"type":"shell","command":"yes x | head -c 200000"}},{"usage":{"tokens":10},"action":{"type":"finish","findings":[]}}]'
CASE="a huge command output is truncated before it goes back to the model"
check python3 - "$work/bigout/fp.log" <<'PY'
import json, sys
calls = [json.loads(l) for l in open(sys.argv[1])]
assert len(json.dumps(calls[1]["req"]["messages"])) < 40000, len(json.dumps(calls[1]["req"]["messages"]))
PY

# a docker that fails for ITS OWN reasons (exit 125/126/127: the daemon, the image, the command could not be started) is not a command that failed
cat >"$work/docker-dead" <<'SH'
#!/bin/sh
echo "docker: Cannot connect to the Docker daemon" >&2
exit 125
SH
chmod +x "$work/docker-dead"
d="$work/dockerdead"; mkdir -p "$d/sandbox"; echo README >"$d/sandbox/README.md"; : >"$d/fp.log"
echo '[{"usage":{"tokens":10},"action":{"type":"shell","command":"ls"}},{"usage":{"tokens":10},"action":{"type":"finish","findings":[]}}]' >"$d/plan.json"
printf '{"persona":"readme-evaluator","instructions":"You are an evaluator.","docs_dir":"%s","endpoint":"http://127.0.0.1:18080","image":"x@sha256:%s","model":"M","token_budget":400000,"tools":{}}' "$d/sandbox" "$(printf 'a%.0s' $(seq 64))" >"$d/req.json"
rc=0; python3 "$agent" --docker "$work/docker-dead" --tools "$work/tools.json" --label "$LABEL" --provider-cmd "python3 $work/fp.py $d" <"$d/req.json" >"$d/out.json" 2>"$d/err.txt" || rc=$?
CASE="docker's own failure on a shell action (exit 125) fails the agent (the persona did not run); it is never returned to the model as a command error that lets the persona finish with nothing"
check test "$rc" -ne 0 -a ! -s "$d/out.json"
# the default step limit is generous: 150 shell actions then a finish, with the default --max-steps and a large budget, still finishes
python3 - "$work/long.json" <<'PY'
import json, sys
json.dump([{"usage": {"tokens": 1}, "action": {"type": "shell", "command": "echo step"}}] * 150 + [{"usage": {"tokens": 1}, "action": {"type": "finish", "findings": []}}], open(sys.argv[1], "w"))
PY
agent longrun "$(cat "$work/long.json")"
CASE="the DEFAULT step limit does not cut a long but honest persona short (150 actions then a finish): the token budget stays the runaway stop"
check test "$rc" -eq 0 -a "$(calls longrun)" -eq 151
check python3 - "$work/longrun/out.json" <<'PY'
import json, sys
a = json.load(open(sys.argv[1]))
assert not any("did not finish" in f["text"].lower() for f in a["findings"]), a
PY

# --- DELTA 2: per-action tool images, fixed options only --------------------------------------------------------------------------
agent explicitshell '[{"usage":{"tokens":10},"action":{"type":"shell","tool":"shell","command":"echo viash > viash.txt; cat viash.txt"}},{"usage":{"tokens":10},"action":{"type":"finish","findings":[]}}]'
CASE="tool shell, named explicitly: the same fixed argv as the unnamed shell (run --rm --network container:<the persona's holder> --label persona-uat=<uuid> -v SANDBOX:/work -w /work <shell digest> sh -c <command>), and the command ran under sh"
check python3 - "$work/explicitshell/fd.log" "$work/explicitshell/sandbox" "$SHL" <<'PY'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1])]
assert len(rows) == 1, rows
assert rows[0]["argv"] == ["run", "--rm", "--network", "container:persona-uat-0a1b2c3d-holder", "--label", "persona-uat=11111111-2222-3333-4444-555555555555", "-v", sys.argv[2] + ":/work", "-w", "/work", sys.argv[3], "sh", "-c", "echo viash > viash.txt; cat viash.txt"], rows[0]["argv"]
assert open(sys.argv[2] + "/viash.txt").read().strip() == "viash"
PY
for t in cosign kubectl gradle maven; do
  case $t in cosign) img=$CSG; targs='["verify","--key","k.pub","https://example.org/x"]';; kubectl) img=$KCT; targs='["get","pods","--kubeconfig","kubeconfig"]';;
             gradle) img=$GRD; targs='["gradle","--version"]';; maven) img=$MVN; targs='["mvn","-v"]';; esac
  agent "tool-$t" '[{"usage":{"tokens":10},"action":{"type":"shell","tool":"'$t'","args":'"$targs"'}},{"usage":{"tokens":10},"action":{"type":"finish","findings":[]}}]'
  CASE="tool $t: docker is run with the FIXED prefix, THAT tool's own digest, then the args exactly as given ($targs; the image's entrypoint semantics decide what the first one is); the output goes back to the model"
  check python3 - "$work/tool-$t/fd.log" "$work/tool-$t/sandbox" "$img" "$work/tool-$t/fp.log" "$targs" <<'PY'
import json, sys
SANDBOX = sys.argv[2]
rows = [json.loads(l) for l in open(sys.argv[1])]
assert len(rows) == 1, rows
assert rows[0]["argv"] == ["run", "--rm", "--network", "container:persona-uat-0a1b2c3d-holder", "--label", "persona-uat=11111111-2222-3333-4444-555555555555", "-v", SANDBOX + ":/work", "-w", "/work", sys.argv[3]] + json.loads(sys.argv[5]), rows[0]["argv"]
calls = [json.loads(l) for l in open(sys.argv[4])]
m = json.dumps(calls[1]["req"]["messages"])
assert "TOOLARGS" in m and "exit status: 0" in m, m
PY
done
# the program convention: gradle and maven take the program as the first argument (an arg list that is only options cannot run), cosign and kubectl take the subcommand;
# the agent passes the args VERBATIM (it never prepends or strips a program name) and the model sees the real failure
for pair in 'gradle|["--version"]|127|executable file not found' 'maven|["-v"]|127|executable file not found' 'cosign|["cosign","version"]|1|unknown command' 'kubectl|["kubectl","get","pods"]|1|unknown command'; do
  IFS='|' read -r t targs wantrc wanttxt <<<"$pair"
  agent "progneg-$t" '[{"usage":{"tokens":10},"action":{"type":"shell","tool":"'$t'","args":'"$targs"'}},{"usage":{"tokens":10},"action":{"type":"finish","findings":[]}}]'
  case $t in cosign) img=$CSG;; kubectl) img=$KCT;; gradle) img=$GRD;; maven) img=$MVN;; esac
  CASE="tool $t with $targs: passed VERBATIM (no program prepended or stripped); the image cannot run it ($wanttxt), and the model is told the real exit status $wantrc"
  check python3 - "$work/progneg-$t/fd.log" "$work/progneg-$t/sandbox" "$img" "$work/progneg-$t/fp.log" "$targs" "$wantrc" "$wanttxt" <<'PY'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1])]
assert len(rows) == 1 and rows[0]["argv"][11:] == json.loads(sys.argv[5]) and rows[0]["argv"][10] == sys.argv[3], rows
m = json.dumps(json.loads(open(sys.argv[4]).readlines()[1])["req"]["messages"])
assert "exit status: " + sys.argv[6] in m and sys.argv[7] in m, m
PY
done
CASE="the first model call tells the model the program convention: for gradle and maven the FIRST element of args is the program (gradle, mvn), for cosign and kubectl it is the subcommand"
check python3 - "$work/finish/fp.log" <<'PY'
import json, sys
r = json.loads(open(sys.argv[1]).readline())["req"]
s = (r["system"] + json.dumps(r["messages"])).lower()
assert "program" in s and "mvn" in s and "gradle" in s and "subcommand" in s, s
PY
agent toolflags '[{"usage":{"tokens":10},"action":{"type":"shell","tool":"cosign","args":["--privileged","-v","/:/host","--network","none","--pid=host","-e","AWS_SECRET_ACCESS_KEY=x","/var/run/docker.sock"]}},{"usage":{"tokens":10},"action":{"type":"finish","findings":[]}}]'
CASE="fence 1 (args): docker flags typed by the model in args stay ARGUMENTS INSIDE the container: the options before the image are the fixed ten tokens (one -v, one --label), the image is the cosign digest, the typed words come after it verbatim"
check python3 - "$work/toolflags/fd.log" "$work/toolflags/sandbox" "$CSG" <<'PY'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1])]
assert len(rows) == 1
a = rows[0]["argv"]
assert a[:11] == ["run", "--rm", "--network", "container:persona-uat-0a1b2c3d-holder", "--label", "persona-uat=11111111-2222-3333-4444-555555555555", "-v", sys.argv[2] + ":/work", "-w", "/work", sys.argv[3]], a
assert a[11:] == ["--privileged", "-v", "/:/host", "--network", "none", "--pid=host", "-e", "AWS_SECRET_ACCESS_KEY=x", "/var/run/docker.sock"], a
assert a[:11].count("-v") == 1 and "--privileged" not in a[:11] and "none" not in a[:11]
PY
agent toolflags2 '[{"usage":{"tokens":10},"action":{"type":"shell","tool":"shell","command":"--privileged -v /:/host --network none --pid=host -e AWS_SECRET_ACCESS_KEY=x /var/run/docker.sock"}},{"usage":{"tokens":10},"action":{"type":"finish","findings":[]}}]'
CASE="fence 1 (command, tool shell named): the same: the typed flags are inside the sh -c argument, the argv stays the fixed fourteen tokens"
check python3 - "$work/toolflags2/fd.log" "$work/toolflags2/sandbox" "$SHL" <<'PY'
import json, sys
a = [json.loads(l) for l in open(sys.argv[1])][0]["argv"]
assert a[:13] == ["run", "--rm", "--network", "container:persona-uat-0a1b2c3d-holder", "--label", "persona-uat=11111111-2222-3333-4444-555555555555", "-v", sys.argv[2] + ":/work", "-w", "/work", sys.argv[3], "sh", "-c"] and len(a) == 14, a
PY
CASE="every tool action's docker call runs with the allowlisted environment only (PATH, HOME, docker client settings): no model or job credential, for every tool"
check python3 - "$work/tool-cosign/fd.log" "$work/tool-kubectl/fd.log" "$work/tool-gradle/fd.log" "$work/tool-maven/fd.log" "$work/toolflags/fd.log" <<'PY'
import json, sys
ok = {"PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "TMPDIR", "PWD", "SHLVL", "_", "__CF_USER_TEXT_ENCODING", "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT"}
for p in sys.argv[1:]:
    for l in open(p):
        assert not [k for k in json.loads(l)["env"] if k not in ok], (p, json.loads(l)["env"])
PY
# unknown tools: refused (never executed), the model is told, the persona carries on
refplan() { printf '[{"usage":{"tokens":10},"action":{"type":"shell","tool":%s,"args":["http://evil.example/x"]}},{"usage":{"tokens":10},"action":{"type":"finish","findings":[]}}]' "$1"; }
i=0
for tv in '"docker"' '"alpine"' "\"$SHL\"" "\"$CSG\"" '"Cosign"' '"COSIGN"' '"cosign "' '" cosign"' '"../kubectl"' '"--privileged"' '"sh"' '"bash"' '"kind"' '"jenkins"' '"gitlab-runner"' '"capture"' '"cosign;id"' '"co*"'; do
  i=$((i+1)); agent "unk$i" "$(refplan "$tv")"
  CASE="unknown tool $tv: refused, docker is NEVER called, the model is told (a refusal in its next request), the persona carries on and, having run nothing, cannot finish clean"
  check python3 - "$work/unk$i" <<'PY'
import json, re, sys
d = sys.argv[1]
assert open(d + "/fd.log").read() == "", "an unknown tool reached docker"
calls = [json.loads(l) for l in open(d + "/fp.log")]
assert len(calls) == 2, len(calls)
told = calls[1]["req"]["messages"][-1]["content"].lower()
assert re.search(r"refus|unknown|not allowed|not an allowed|no such tool|not a known", told), told
a = json.load(open(d + "/out.json"))
assert any(f["kind"] == "blocking" and "without running" in f["text"].lower() for f in a["findings"]), a
assert a["commands"] == [], ("a refused action is not a command the persona ran", a["commands"])
PY
done
agent unkthenok '[{"usage":{"tokens":10},"action":{"type":"shell","tool":"docker","args":["ps"]}},{"usage":{"tokens":10},"action":{"type":"shell","tool":"gradle","args":["gradle","--version"]}},{"usage":{"tokens":10},"action":{"type":"finish","findings":[]}}]'
CASE="after a refused tool the persona carries on: a valid action then runs (exactly one docker call, for gradle) and the persona may finish clean"
check python3 - "$work/unkthenok" "$GRD" <<'PY'
import json, sys
d = sys.argv[1]
rows = [json.loads(l) for l in open(d + "/fd.log")]
assert len(rows) == 1 and rows[0]["argv"][10] == sys.argv[2] and rows[0]["argv"][11:] == ["gradle", "--version"], rows
a = json.load(open(d + "/out.json"))
assert a["findings"] == [], a
assert len(a["commands"]) == 1 and "gradle" in a["commands"][0] and "--version" in a["commands"][0], a["commands"]
PY
# the ambiguous shapes: a hard failure of the agent or a refusal, but NEVER an execution
n=0
for act in '{"type":"shell","tool":"","args":["x"]}' '{"type":"shell","tool":null,"args":["x"]}' '{"type":"shell","tool":5,"args":["x"]}' '{"type":"shell","tool":["shell"],"command":"id"}' \
           '{"type":"shell","tool":"cosign","command":"cosign version"}' '{"type":"shell","tool":"cosign"}' '{"type":"shell","tool":"kubectl","args":"get pods"}' \
           '{"type":"shell","tool":"kubectl","args":["get",5]}' '{"type":"shell","tool":"kubectl","args":["get"],"command":"id"}' '{"type":"shell","tool":"shell","args":["id"]}' \
           '{"type":"shell","tool":"shell","command":"id","args":["id"]}' '{"type":"shell","command":"id","args":["id"]}' '{"type":"shell","args":["id"]}'; do
  n=$((n+1)); agent "shape$n" "[{\"usage\":{\"tokens\":10},\"action\":$act},{\"usage\":{\"tokens\":10},\"action\":{\"type\":\"finish\",\"findings\":[]}}]"
  CASE="a malformed tool action ($act) is never executed: the agent fails closed or refuses it and tells the model"
  check python3 - "$work/shape$n" "$rc" <<'PY'
import json, re, sys
d, rc = sys.argv[1], int(sys.argv[2])
assert open(d + "/fd.log").read() == "", "a malformed action reached docker"
if rc == 0:
    calls = [json.loads(l) for l in open(d + "/fp.log")]
    assert len(calls) == 2 and re.search(r"refus|unknown|not allowed|invalid|malformed|outside|must", calls[1]["req"]["messages"][-1]["content"].lower()), calls
else:
    assert open(d + "/out.json").read() == ""
PY
done
# the tools file: a bad one fails the agent before the model is called
printf '%s' 'not json' >"$work/tools-badjson.json"
python3 - "$work/tools.json" "$work" <<'PY'
import json, sys
t = json.load(open(sys.argv[1])); w = sys.argv[2]
a = dict(t); del a["shell"]; json.dump(a, open(w + "/tools-noshell.json", "w"))
b = dict(t); b["cosign"] = b["cosign"].split("@")[0] + ":latest"; json.dump(b, open(w + "/tools-tag.json", "w"))
c = dict(t); c["gradle"] = 5; json.dump(c, open(w + "/tools-int.json", "w"))
d = dict(t); d["maven"] = "docker.io/library/maven@sha256:abc"; json.dump(d, open(w + "/tools-short.json", "w"))
json.dump(["shell"], open(w + "/tools-list.json", "w"))
PY
for tf in "$work/tools-badjson.json" "$work/tools-noshell.json" "$work/tools-tag.json" "$work/tools-int.json" "$work/tools-short.json" "$work/tools-list.json" "$work/no-such-tools.json"; do
  nm="badtools-$(basename "$tf" .json)"
  TOOLSFILE="$tf" agent "$nm" '[{"usage":{"tokens":10},"action":{"type":"shell","command":"echo hi"}},{"usage":{"tokens":10},"action":{"type":"finish","findings":[]}}]'
  CASE="a bad tools file ($(basename "$tf")) fails the agent before anything runs: non-zero, no answer, the model is never called, docker never called"
  check test "$rc" -ne 0 -a ! -s "$work/$nm/out.json" -a ! -s "$work/$nm/fp.log" -a ! -s "$work/$nm/fd.log"
done
CASE="the first model call names every action tool (shell, cosign, kubectl, gradle, maven) and tells how to use the tool, command and args fields"
check python3 - "$work/finish/fp.log" <<'PY'
import json, sys
r = json.loads(open(sys.argv[1]).readline())["req"]
s = (r["system"] + json.dumps(r["messages"])).lower()
for w in ("shell", "cosign", "kubectl", "gradle", "maven", '"tool"', "args", "command"):
    assert w in s, w
PY
# --- DELTA 3: the commands the persona ran, for the driver's outside-hosts line ------------------------------------------------------
CASE="the answer carries the commands the persona ran, in order (the shell command text)"
check python3 - "$work/finish/out.json" <<'PY'
import json, sys
a = json.load(open(sys.argv[1]))
assert a["commands"] == ["echo $((6*7)) > made.txt; cat made.txt"], a
PY
agent cmdrec '[{"usage":{"tokens":1},"action":{"type":"shell","command":"echo hi"}},{"usage":{"tokens":1},"action":{"type":"shell","tool":"cosign","args":["verify","https://example.org/a"]}},{"usage":{"tokens":1},"action":{"type":"shell","tool":"docker","args":["https://evil.example/never"]}},{"usage":{"tokens":1},"action":{"type":"shell","command":"echo bad >&2; exit 3"}},{"usage":{"tokens":1},"action":{"type":"finish","findings":[]}}]'
CASE="commands: shell text and a tool's name plus its args (joined by spaces) are recorded in order, a FAILING command too, and a refused action is not"
check python3 - "$work/cmdrec/out.json" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))["commands"]
assert len(c) == 3 and c[0] == "echo hi" and c[2] == "echo bad >&2; exit 3", c
assert "cosign" in c[1] and c[1].index("verify") < c[1].index("https://example.org/a"), c
assert "evil.example" not in json.dumps(c), c
PY
CASE="commands: a command that timed out was run, so it is recorded; a persona that ran nothing still answers with commands == []"
check python3 - "$work/timeout/out.json" "$work/noaction/out.json" <<'PY'
import json, sys
assert json.load(open(sys.argv[1]))["commands"] == ["sleep 5"]
assert json.load(open(sys.argv[2]))["commands"] == []
PY

# --- a failure AFTER successful actions keeps what happened so far (the driver stores the agent's stderr as the failed persona's transcript artifact;
# on the success path nothing is echoed, see fence 2 above)
agent partial '[{"usage":{"tokens":10},"action":{"type":"shell","command":"echo $((6*7))-marker-one"}},{"usage":{"tokens":10},"action":{"type":"shell","command":"echo $((6*8))-marker-two >&2; exit 3"}},{"exit":9}]'
CASE="a provider that fails AFTER two successful actions: the agent fails closed (non-zero, nothing on stdout) AND its stderr keeps the transcript so far (both commands, their outputs and exit status), so the failed persona's artifact can be diagnosed"
check python3 - "$work/partial" <<'PY'
import sys
d = sys.argv[1]
assert open(d + "/out.json").read() == ""
e = open(d + "/err.txt").read()
for w in ("42-marker-one", "48-marker-two", "echo $((6*7))-marker-one", "exit status: 3"):
    assert w in e, (w, e)
PY
check test "$rc" -ne 0

# --- ROUND 2 (review d6r2): container lifecycle and scrubbing -----------------------------------------------------------------------------------
# every container the agent starts carries --label persona-uat=<uuid> (handed in by the driver, one per persona); an agent without a valid label refuses to run
n=0
for lab in "NONE" "persona-uat=" "persona-uat=x" "other=11111111-2222-3333-4444-555555555555" "persona-uat=11111111-2222-3333-4444-55555555555G" "persona-uat=11111111-2222-3333-4444-555555555555 --privileged" "persona-uat=11111111-2222-3333-4444-5555555555555" "PERSONA-UAT=11111111-2222-3333-4444-555555555555"; do
  n=$((n+1))
  if [ "$lab" = NONE ]; then NOLABEL= agent "nolabel$n" '[{"usage":{"tokens":1},"action":{"type":"shell","command":"echo hi"}},{"usage":{"tokens":1},"action":{"type":"finish","findings":[]}}]'
  else LABELARG="$lab" agent "nolabel$n" '[{"usage":{"tokens":1},"action":{"type":"shell","command":"echo hi"}},{"usage":{"tokens":1},"action":{"type":"finish","findings":[]}}]'; fi
  CASE="the agent refuses a missing or malformed --label ('$lab'): non-zero, no answer, nothing started (an unlabelled container could outlive its persona unseen)"
  check test "$rc" -ne 0 -a ! -s "$work/nolabel$n/out.json" -a ! -s "$work/nolabel$n/fd.log" -a ! -s "$work/nolabel$n/fp.log"
done
CASE="a normal run makes only 'run' calls to docker (cleanup by label is for what a TIMEOUT left, never an extra call per action)"
check python3 - "$work/finish/fd.log" "$work/tool-cosign/fd.log" <<'PY'
import json, sys
for p in sys.argv[1:]:
    assert all(json.loads(l)["argv"][0] == "run" for l in open(p)), p
PY
agent shtimeout '[{"usage":{"tokens":1},"action":{"type":"shell","command":"sleep 5"}},{"usage":{"tokens":1},"action":{"type":"finish","findings":[]}}]' --shell-timeout 1
CASE="a shell action that timed out leaves a daemon-managed container behind (the docker client was killed, the container runs on): the agent finds it by label (docker ps --filter label=<its label>) and removes it by id (rm -f / stop / kill), in that order, and none is left"
check python3 - "$work/shtimeout" <<'PY'
import json, os, sys
d = sys.argv[1]
rows = [json.loads(l)["argv"] for l in open(d + "/fd.log")]
ps = [i for i, a in enumerate(rows) if a[0] == "ps"]
rm = [i for i, a in enumerate(rows) if a[0] in ("rm", "stop", "kill")]
assert ps and rm and ps[0] < rm[0], rows
assert "label=persona-uat=11111111-2222-3333-4444-555555555555" in rows[ps[0]], rows[ps[0]]
assert [x for x in rows[rm[0]] if x.startswith("c-")], ("the container was not removed BY ID", rows[rm[0]])
assert not os.listdir(d + "/containers"), os.listdir(d + "/containers")
PY
CASE="the timeout is still reported to the model and the persona carries on after the cleanup"
check test "$rc" -eq 0 -a "$(calls shtimeout)" -eq 2
check grep -qi 'timed out' "$work/shtimeout/out.json"
# scrubbing: the request's model value and a credential-looking marker never reach the answer, the transcript or the failure output
MARK='model=OWNER-MODEL-Q key=ghp_abcdefghij0123456789ABCDEF pat=github_pat_11ABCDEFG0abcdefghijkl_xyz aws=AKIAABCDEFGHIJKLMNOP sk=sk-abcdefghijklmnopqrstuvwx hdr=Bearer-abcdefghijklmnop password=hunter2xyz jwt=eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl'
MODEL=OWNER-MODEL-Q agent scrubok '[{"usage":{"tokens":1},"action":{"type":"shell","command":"echo '"$MARK"'; echo $((6*7))-scrubmark"}},{"usage":{"tokens":1},"action":{"type":"finish","findings":[]}}]'
CASE="scrubbing (success path): the model value and the credential marker that the persona's command and its output carried are in NEITHER the transcript nor the commands of the answer (the transcript still shows what ran: 42-scrubmark)"
check python3 - "$work/scrubok/out.json" <<'PY'
import json, sys
raw = open(sys.argv[1]).read()
for bad in ("OWNER-MODEL-Q", "ghp_abcdefghij0123456789ABCDEF", "github_pat_11ABCDEFG0abcdefghijkl_xyz", "AKIAABCDEFGHIJKLMNOP", "sk-abcdefghijklmnopqrstuvwx", "hunter2xyz", "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0"):
    assert bad not in raw, (bad, raw)
a = json.loads(raw)
assert "42-scrubmark" in a["transcript"] and a["commands"], a
PY
MODEL=OWNER-MODEL-Q agent scrubfail '[{"usage":{"tokens":1},"action":{"type":"shell","command":"echo '"$MARK"'; echo $((6*7))-scrubmark"}},{"stderr":"provider error: model=OWNER-MODEL-Q key=ghp_abcdefghij0123456789ABCDEF","exit":9}]'
CASE="scrubbing (failure path): after a provider failure that carries the model value and a credential marker in ITS stderr, the agent's own stderr (the failed persona's retained transcript) keeps the earlier steps (42-scrubmark) and holds neither secret"
check python3 - "$work/scrubfail" <<'PY'
d = __import__("sys").argv[1]
e = open(d + "/err.txt").read()
assert "42-scrubmark" in e, e
for bad in ("OWNER-MODEL-Q", "ghp_abcdefghij0123456789ABCDEF", "github_pat_11ABCDEFG0abcdefghijkl_xyz", "AKIAABCDEFGHIJKLMNOP", "sk-abcdefghijklmnopqrstuvwx", "hunter2xyz", "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0"):
    assert bad not in e, (bad, e)
assert open(d + "/out.json").read() == ""
PY

# --- ROUND 3: one sandbox shared by every tool (create with one image, read with another, same mount and label) ----------------------------------
agent crosstool '[{"usage":{"tokens":1},"action":{"type":"shell","command":"echo curlfile > data.txt"}},
                  {"usage":{"tokens":1},"action":{"type":"shell","tool":"cosign","args":["--fake-read","data.txt"]}},
                  {"usage":{"tokens":1},"action":{"type":"shell","tool":"gradle","args":["gradle","--fake-write","out/build.txt","built"]}},
                  {"usage":{"tokens":1},"action":{"type":"shell","command":"cat out/build.txt"}},
                  {"usage":{"tokens":1},"action":{"type":"shell","tool":"maven","args":["mvn","--fake-read","out/build.txt"]}},
                  {"usage":{"tokens":1},"action":{"type":"finish","findings":[]}}]'
CASE="cross-tool sandbox: a file the curl image's shell created is read by the cosign image, a file the gradle image wrote is read by the shell and by the maven image: all five containers mounted the SAME sandbox (one -v) and carried the SAME label, and every output reached the model"
check python3 - "$work/crosstool" <<'PY'
import json, sys
d = sys.argv[1]
rows = [json.loads(l)["argv"] for l in open(d + "/fd.log")]
assert len(rows) == 5, rows
assert len({r[r.index("-v") + 1] for r in rows}) == 1 and len({r[r.index("--label") + 1] for r in rows}) == 1, rows
calls = [json.loads(l) for l in open(d + "/fp.log")]
m = json.dumps(calls[-1]["req"]["messages"])
assert "curlfile" in m and m.count("built") >= 2 and "exit status: 0" in m, m
assert "no such file" not in m
PY
# --- fail closed: a provider that fails or leaves the protocol fails the AGENT ---------------------------------
for c in 'crash|[{"exit":9}]' 'not-json|[{"raw":"nope"}]' 'unknown-action|[{"usage":{"tokens":1},"action":{"type":"rm-rf","command":"x"}}]' \
         'no-usage|[{"action":{"type":"finish","findings":[]}}]' 'neg-usage|[{"usage":{"tokens":-5},"action":{"type":"finish","findings":[]}}]' \
         'bad-finding|[{"usage":{"tokens":1},"action":{"type":"finish","findings":[{"kind":"meh","text":"x"}]}}]' \
         'shell-no-command|[{"usage":{"tokens":1},"action":{"type":"shell"}}]'; do
  name=${c%%|*}; plan=${c#*|}
  agent "fc-$name" "$plan"
  CASE="fail closed ($name): the agent exits non-zero and prints no answer the driver could mistake for a pass"
  check test "$rc" -ne 0 -a ! -s "$work/fc-$name/out.json"
done

# --- AC5: the owner's model reaches the provider; no model name is written anywhere -----------------------------
MODEL=OWNER-MODEL-Q agent model '[{"usage":{"tokens":1},"action":{"type":"finish","findings":[]}}]'
CASE="the model named in the request is exactly what the provider is asked to use"
check test "$rc" -eq 0 -a "$(calls model)" -eq 1
check python3 - "$work/model/fp.log" <<'PY'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1])]
assert len(rows) == 1 and all(r["req"]["model"] == "OWNER-MODEL-Q" for r in rows), rows
PY
CASE="the model value never appears in the agent's answer or transcript (and the answer exists)"
check test -s "$work/model/out.json"
check none_match 'OWNER-MODEL-Q' "$work/model/out.json"
CASE="no model name is written in the agent or the provider: neither a vendor family nor a model-version pattern"
check none_match '[Cc]laude|[Oo]pus|[Ss]onnet|[Hh]aiku|[Ff]able|gpt-|[Gg]emini|[Ll]lama|\bo[134]-' "$agent" "$provider"

# --- the real provider, over a FAKE anthropic SDK -----------------------------------------------------------------
mkdir -p "$work/sdk/anthropic"
cat >"$work/sdk/anthropic/__init__.py" <<'PY'
import json, os
class _Msg:
    def __init__(self, text, i, o):
        self.content = [type("B", (), {"type": "text", "text": text})()]
        self.usage = type("U", (), {"input_tokens": i, "output_tokens": o})()
class Anthropic:
    def __init__(self, *a, **k):
        open(os.environ["SDK_LOG"], "a").write(json.dumps({"init": True, "env_has_key": "ANTHROPIC_API_KEY" in os.environ}) + "\n")
        truth = os.environ.get("SDK_TOKEN_TRUTH")      # the identity provider's current assertion: a federated client presents the token file's CURRENT content, a stale one is refused
        if truth:
            tf = os.environ.get("ANTHROPIC_IDENTITY_TOKEN_FILE")
            if not tf or open(tf).read().strip() != open(truth).read().strip():
                raise RuntimeError("federation refused: the identity assertion is expired")
        self.messages = self
    def create(self, **kw):
        open(os.environ["SDK_LOG"], "a").write(json.dumps({"create": {k: v for k, v in kw.items()}}) + "\n")
        return _Msg(os.environ["SDK_TEXT"], int(os.environ.get("SDK_IN", "100")), int(os.environ.get("SDK_OUT", "50")))
PY
prov() { # <case> <model text> <request json>; sets rc; stdout in $work/<case>/out
  local name=$1; mkdir -p "$work/$name"; : >"$work/$name/sdk.log"; rc=0
  SDK_TEXT="$2" SDK_LOG="$work/$name/sdk.log" PYTHONPATH="$work/sdk" ANTHROPIC_API_KEY=SECRET-MODEL-KEY \
    python3 "$provider" <<<"$3" >"$work/$name/out" 2>"$work/$name/err" || rc=$?
}
# the identity token is refreshed in the background by the job (a new file content every few minutes) and every model call is a NEW process: the provider reads
# the token file as it is at THAT call (never a copy made earlier), so a rotated file is used and a stale one is a failure that leaves nothing on stdout
echo TOKEN-ONE >"$work/idfile"; echo TOKEN-ONE >"$work/idtruth"; mkdir -p "$work/p-fresh1" "$work/p-fresh2" "$work/p-stale"
for c in p-fresh1 p-fresh2 p-stale; do : >"$work/$c/sdk.log"; done
SDK_TEXT='{"action":"shell","command":"ls"}' SDK_LOG="$work/p-fresh1/sdk.log" SDK_TOKEN_TRUTH="$work/idtruth" ANTHROPIC_IDENTITY_TOKEN_FILE="$work/idfile" PYTHONPATH="$work/sdk" python3 "$provider" <<<'{"model":"M","system":"s","messages":[{"role":"user","content":"a"}]}' >"$work/p-fresh1/out" 2>/dev/null || true
echo TOKEN-TWO >"$work/idfile"; echo TOKEN-TWO >"$work/idtruth"            # the refresher re-minted: file and provider agree on the new assertion
SDK_TEXT='{"action":"shell","command":"ls"}' SDK_LOG="$work/p-fresh2/sdk.log" SDK_TOKEN_TRUTH="$work/idtruth" ANTHROPIC_IDENTITY_TOKEN_FILE="$work/idfile" PYTHONPATH="$work/sdk" python3 "$provider" <<<'{"model":"M","system":"s","messages":[{"role":"user","content":"a"}]}' >"$work/p-fresh2/out" 2>/dev/null || true
echo TOKEN-THREE >"$work/idtruth"                                         # the provider moved on, the file did NOT (no refresher): the assertion the file holds is stale
rc=0; SDK_TEXT='{"action":"shell","command":"ls"}' SDK_LOG="$work/p-stale/sdk.log" SDK_TOKEN_TRUTH="$work/idtruth" ANTHROPIC_IDENTITY_TOKEN_FILE="$work/idfile" PYTHONPATH="$work/sdk" python3 "$provider" <<<'{"model":"M","system":"s","messages":[{"role":"user","content":"a"}]}' >"$work/p-stale/out" 2>"$work/p-stale/err" || rc=$?
CASE="identity expiry across calls (fake provider that refuses a stale token file): two calls with a file that was ROTATED between them both succeed (the file is read at each call), a call whose file went stale fails closed (non-zero, nothing on stdout, the refusal on stderr)"
check test -s "$work/p-fresh1/out" -a -s "$work/p-fresh2/out" -a "$rc" -ne 0 -a ! -s "$work/p-stale/out"
check grep -q 'expired' "$work/p-stale/err"
REQ='{"model":"SDK-MODEL-Z","system":"be a persona","messages":[{"role":"user","content":"start"}]}'
prov p-shell '{"action":"shell","command":"ls"}' "$REQ"
CASE="provider: asks the SDK for the request's model, passes the system prompt and messages, and bounds max_tokens"
check python3 - "$work/p-shell/sdk.log" <<'PY'
import json, sys
c = [json.loads(l)["create"] for l in open(sys.argv[1]) if '"create"' in l]
assert len(c) == 1 and c[0]["model"] == "SDK-MODEL-Z" and c[0]["system"] == "be a persona", c
assert c[0]["messages"] == [{"role": "user", "content": "start"}], c
assert isinstance(c[0]["max_tokens"], int) and 0 < c[0]["max_tokens"] <= 8192, c
PY
CASE="provider: maps a shell reply to a shell action and counts input + output tokens (150)"
check python3 - "$work/p-shell/out" <<'PY'
import json, sys
a = json.load(open(sys.argv[1]))
assert a == {"usage": {"tokens": 150}, "action": {"type": "shell", "command": "ls"}}, a
PY
prov p-fin 'Here you go: {"action":"finish","findings":[{"kind":"friction","text":"slow"}]} thanks' "$REQ"
CASE="provider: finds the JSON object inside prose and maps a finish reply to findings"
check python3 - "$work/p-fin/out" <<'PY'
import json, sys
a = json.load(open(sys.argv[1]))
assert a["action"] == {"type": "finish", "findings": [{"kind": "friction", "text": "slow"}]}, a
PY
for bad in 'no json at all' '{"action":"shell"}' '{"action":"explode","command":"x"}' '{"action":"finish","findings":"nope"}'; do
  prov "p-bad" "$bad" "$REQ"
  CASE="provider fails closed on a reply outside the protocol: '$bad'"
  check test "$rc" -ne 0 -a ! -s "$work/p-bad/out"
done
prov p-tool '{"action":"shell","tool":"cosign","args":["version","--short"]}' "$REQ"
CASE="provider (delta 2): a tool action with args passes through as {type, tool, args} (the provider does not know the tools file: an unknown name is the agent's to refuse)"
check python3 - "$work/p-tool/out" <<'PY'
import json, sys
assert json.load(open(sys.argv[1])) == {"usage": {"tokens": 150}, "action": {"type": "shell", "tool": "cosign", "args": ["version", "--short"]}}
PY
prov p-toolshell '{"action":"shell","tool":"shell","command":"ls"}' "$REQ"
CASE="provider (delta 2): the shell tool named explicitly passes through as {type, tool, command}; an unnamed shell action keeps its old shape"
check python3 - "$work/p-toolshell/out" "$work/p-shell/out" <<'PY'
import json, sys
assert json.load(open(sys.argv[1]))["action"] == {"type": "shell", "tool": "shell", "command": "ls"}
assert json.load(open(sys.argv[2]))["action"] == {"type": "shell", "command": "ls"}
PY
prov p-toolunk '{"action":"shell","tool":"docker","args":["ps"]}' "$REQ"
CASE="provider (delta 2): a well-formed action for a tool name it cannot know passes through"
check python3 - "$work/p-toolunk/out" <<'PY'
import json, sys
assert json.load(open(sys.argv[1]))["action"] == {"type": "shell", "tool": "docker", "args": ["ps"]}
PY
for bad in '{"action":"shell","tool":"cosign"}' '{"action":"shell","tool":"cosign","args":"version"}' '{"action":"shell","tool":"cosign","args":[1]}' '{"action":"shell","tool":5,"command":"ls"}' \
           '{"action":"shell","tool":"shell","args":["ls"]}' '{"action":"shell","tool":"cosign","command":"cosign version"}' '{"action":"shell","command":"ls","args":["ls"]}'; do
  prov "p-badtool" "$bad" "$REQ"
  CASE="provider (delta 2) fails closed on a malformed tool action: '$bad'"
  check test "$rc" -ne 0 -a ! -s "$work/p-badtool/out"
done
CASE="provider: a request missing its model is refused before the SDK is touched"
prov p-nomodel '{"action":"finish","findings":[]}' '{"system":"s","messages":[]}'
check test "$rc" -ne 0 -a ! -s "$work/p-nomodel/sdk.log"

echo "persona-uat-agent: $pass passed, $failn failed"
test "$failn" -eq 0
