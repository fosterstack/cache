#!/usr/bin/env bash
# proves: REQ-UAT-001-AC1, REQ-UAT-001-AC2, REQ-UAT-001-AC4, REQ-UAT-001-AC5
# The persona agent (bin/persona-uat-agent.py) and its model provider (bin/persona-uat-provider.py), proved with a FAKE
# provider and a fake `docker` that really runs the shell action inside the directory it was given: the loop stops at the
# owner's token budget (counted across ALL calls, never calling the model again once reached: a runaway stop, not a
# suggestion); every shell action runs in the digest-pinned shell image with exactly one mount (the sandbox of public
# docs), no privilege, no inherited credentials, so the persona cannot read the checkout; a provider that fails or
# answers outside the protocol fails the agent (the driver then counts that persona as blocking); the owner's model
# reaches the provider and no model name is written in the agent or its output.
# Contracts the tests pin:
#   persona-uat-agent.py --docker CMD --shell-image REF [--provider-cmd CMD] [--shell-timeout S] [--max-steps N]
#     stdin: the driver's request JSON; stdout: {"findings":[...],"tokens":N,"transcript":str}
#   provider (stdin {"model","system","messages":[{"role","content"}]}) -> stdout {"usage":{"tokens":N},
#     "action":{"type":"shell","command":str} | {"type":"finish","findings":[...]}}
#   persona-uat-provider.py: the real provider, over the Anthropic Python SDK (faked here on PYTHONPATH).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
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

# fake provider: pops the next scripted answer; records each call's stdin and the credential it can see
cat >"$work/fp.py" <<'PY'
import json, os, sys
req = json.load(sys.stdin)
case = sys.argv[1]
plan = json.load(open(os.path.join(case, "plan.json")))
log = os.path.join(case, "fp.log")
n = sum(1 for _ in open(log)) if os.path.exists(log) else 0
with open(log, "a") as fh:
    fh.write(json.dumps({"req": req, "key": os.environ.get("ANTHROPIC_API_KEY")}) + "\n")
step = plan[min(n, len(plan) - 1)]
if step.get("exit"):
    sys.exit(step["exit"])
if "raw" in step:
    sys.stdout.write(step["raw"]); sys.exit(0)
print(json.dumps(step))
PY
# fake docker: logs argv and the environment NAMES it was started with, then runs `sh -c CMD` in the -v host directory
cat >"$work/docker.tmpl" <<'PY'
#!/usr/bin/env python3
import json, os, subprocess, sys
a = sys.argv[1:]
open("__LOG__", "a").write(json.dumps({"argv": a, "env": sorted(os.environ)}) + "\n")
host = next(x.split(":")[0] for i, x in enumerate(a) if i and a[i - 1] == "-v")
cmd = a[a.index("-c") + 1]
try:
    p = subprocess.run(["sh", "-c", cmd], cwd=host, capture_output=True, text=True, timeout=60)
    sys.stdout.write(p.stdout); sys.stderr.write(p.stderr); sys.exit(p.returncode)
except subprocess.TimeoutExpired:
    sys.exit(124)
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
    python3 "$agent" --docker "$d/docker" --shell-image "$SHL" --provider-cmd "python3 $work/fp.py $d" "$@" \
    <"$d/req.json" >"$d/out.json" 2>"$d/err.txt" || rc=$?
}
calls() { wc -l <"$work/$1/fp.log" | tr -d ' '; }

# --- AC5: the budget is a hard, cumulative stop -----------------------------------------------------------------
STEPS='[{"usage":{"tokens":400},"action":{"type":"shell","command":"echo step"}}]'
BUDGET=1000 agent cap "$STEPS"
CASE="a model that never finishes is stopped at the budget: exactly 3 calls at 400 tokens each against 1000, then no more"
check test "$rc" -eq 0 -a "$(calls cap)" -eq 3
CASE="the answer reports the tokens used (1200 across the 3 calls) and keeps the transcript of all three steps"
check python3 - "$work/cap/out.json" <<'PY'
import json, sys
a = json.load(open(sys.argv[1]))
assert a["tokens"] == 1200 and a["findings"] == [], a
assert a["transcript"].count("echo step") == 3, a["transcript"]
PY
BUDGET=1200 agent capexact "$STEPS"
CASE="reaching the budget exactly stops the loop: 400 x 3 = 1200 is the cap, a 4th call is never made"
check test "$(calls capexact)" -eq 3
BUDGET=1201 agent capover "$STEPS"
CASE="one token under the next call's end is still allowed to continue to a 4th call"
check test "$(calls capover)" -eq 4
BUDGET=500 agent capone '[{"usage":{"tokens":900},"action":{"type":"shell","command":"echo only"}}]'
CASE="a single call that blows through the budget ends the run after that one call"
check test "$(calls capone)" -eq 1
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
BUDGET=1000 agent capnote "$STEPS"
CASE="the token cap is only FLAGGED (the owner's rule): it adds no blocking finding of its own"
check python3 - "$work/capnote/out.json" <<'PY'
import json, sys
a = json.load(open(sys.argv[1]))
assert a["findings"] == [] and a["tokens"] >= 1000, a
PY

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

# --- "exercised the persona" is more than "ran a command": a persona that never contacted the endpoint cannot claim a clean pass
agent irrelevant '[{"usage":{"tokens":10},"action":{"type":"shell","command":"true"}},{"usage":{"tokens":10},"action":{"type":"finish","findings":[]}}]'
CASE="an irrelevant action followed by an empty finish is NOT a pass: the persona never contacted the cache endpoint, so a blocking finding says so"
check python3 - "$work/irrelevant/out.json" <<'PY'
import json, sys
a = json.load(open(sys.argv[1]))
assert any(f["kind"] == "blocking" and "endpoint" in f["text"].lower() for f in a["findings"]), a
PY
python3 -m http.server 18080 --bind 127.0.0.1 --directory "$work" >/dev/null 2>&1 & SRV=$!
trap 'kill $SRV 2>/dev/null; rm -rf "$work"' EXIT
for _ in 1 2 3 4 5 6 7 8 9 10; do python3 -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:18080')" 2>/dev/null && break; sleep 0.3; done
echo "ok-endpoint" >"$work/healthz"
ENDPOINT=http://127.0.0.1:18099 agent neverreached '[{"usage":{"tokens":10},"action":{"type":"shell","command":"curl -s http://127.0.0.1:18099/healthz || true"}},{"usage":{"tokens":10},"action":{"type":"finish","findings":[]}}]'
CASE="naming the endpoint is not enough: the CONFIGURED endpoint (18099, where nothing listens) is named exactly by the command, but the connection failed and the output is empty: the persona is left without a clean pass (an implementation that only matches the endpoint string fails this)"
check python3 - "$work/neverreached/out.json" <<'PY'
import json, sys
a = json.load(open(sys.argv[1]))
assert any(f["kind"] == "blocking" and "endpoint" in f["text"].lower() for f in a["findings"]), a
PY
agent contacted '[{"usage":{"tokens":10},"action":{"type":"shell","command":"curl -s http://127.0.0.1:18080/healthz"}},{"usage":{"tokens":10},"action":{"type":"finish","findings":[]}}]'
CASE="a persona whose command reached the endpoint (exit 0, a non-empty answer) may finish clean (findings stay empty)"
check python3 - "$work/contacted/out.json" <<'PY'
import json, sys
assert json.load(open(sys.argv[1]))["findings"] == []
PY
CASE="a persona that reports its own findings keeps them, endpoint contact or not (the rule only guards a clean pass)"
check python3 - "$work/finish/out.json" <<'PY'
import json, sys
a = json.load(open(sys.argv[1]))
assert a["findings"] == [{"kind": "friction", "text": "first step unclear"}, {"kind": "blocking", "text": "step 2 fails as written"}], a
PY

# --- AC5 (and AC4): the shell is a pinned, unprivileged container that can see ONLY the sandbox -------------------
CASE="every shell action's docker call is EXACTLY: run --rm --network host -v <sandbox>:/work -w /work <pinned shell image> sh -c <command>"
check python3 - "$work/finish/fd.log" "$work/finish/sandbox" "$SHL" <<'PY'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1])]
assert rows, "no shell action went through docker"
for r in rows:
    a = r["argv"]
    # a full-argv ALLOWLIST: nothing can be added (no --privileged, --mount, --volume, --env=, -eX=Y, --user, --device ...)
    assert a[:10] == ["run", "--rm", "--network", "host", "-v", sys.argv[2] + ":/work", "-w", "/work", sys.argv[3], "sh"], a
    assert a[10] == "-c" and len(a) == 12, a
PY
CASE="the endpoint is reachable from the shell: --network host puts the container on the runner's loopback where the image and tools listen"
check python3 - "$work/finish/fd.log" <<'PY'
import json, sys
assert all("host" == json.loads(l)["argv"][json.loads(l)["argv"].index("--network") + 1] for l in open(sys.argv[1]))
PY
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
rc=0; python3 "$agent" --docker "$work/docker-dead" --shell-image "$SHL" --provider-cmd "python3 $work/fp.py $d" <"$d/req.json" >"$d/out.json" 2>"$d/err.txt" || rc=$?
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
CASE="provider: a request missing its model is refused before the SDK is touched"
prov p-nomodel '{"action":"finish","findings":[]}' '{"system":"s","messages":[]}'
check test "$rc" -ne 0 -a ! -s "$work/p-nomodel/sdk.log"

echo "persona-uat-agent: $pass passed, $failn failed"
test "$failn" -eq 0
