#!/usr/bin/env bash
# proves: REQ-UAT-001-AC4, REQ-UAT-001-AC5
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
plan = json.load(open(os.environ["FP_PLAN"]))
log = os.environ["FP_LOG"]
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
cat >"$work/docker" <<'PY'
#!/usr/bin/env python3
import json, os, subprocess, sys
a = sys.argv[1:]
open(os.environ["FD_LOG"], "a").write(json.dumps({"argv": a, "env": sorted(os.environ)}) + "\n")
host = next(x.split(":")[0] for i, x in enumerate(a) if i and a[i - 1] == "-v")
cmd = a[a.index("-c") + 1]
try:
    p = subprocess.run(["sh", "-c", cmd], cwd=host, capture_output=True, text=True, timeout=int(os.environ.get("FD_TIMEOUT", "60")))
    sys.stdout.write(p.stdout + p.stderr); sys.exit(p.returncode)
except subprocess.TimeoutExpired:
    sys.exit(124)
PY
chmod +x "$work/docker"

# agent <case> <plan-json> [agent flags...]  (env BUDGET, MODEL); sets rc; per-case dir $work/<case>/{sandbox,out.json}
agent() {
  local name=$1 plan=$2; shift 2
  local d="$work/$name"; mkdir -p "$d/sandbox"; echo "README" >"$d/sandbox/README.md"; echo "$plan" >"$d/plan.json"
  : >"$d/fp.log"; : >"$d/fd.log"
  printf '{"persona":"readme-evaluator","instructions":"You are an evaluator with only the README and ten minutes.","docs_dir":"%s","endpoint":"http://127.0.0.1:18080","image":"x@sha256:%s","model":"%s","token_budget":%s,"tools":{}}' \
    "$d/sandbox" "$(printf 'a%.0s' $(seq 64))" "${MODEL:-MODEL-AGENT-X}" "${BUDGET:-400000}" >"$d/req.json"
  rc=0
  env ANTHROPIC_API_KEY=SECRET-MODEL-KEY GITHUB_TOKEN=SECRET-GH FP_PLAN="$d/plan.json" FP_LOG="$d/fp.log" FD_LOG="$d/fd.log" \
    python3 "$agent" --docker "$work/docker" --shell-image "$SHL" --provider-cmd "python3 $work/fp.py" "$@" \
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

# --- the loop works: actions run, their output goes back, a finish ends it ----------------------------------------
agent finish '[{"usage":{"tokens":300},"action":{"type":"shell","command":"echo marker-7 > made.txt; cat made.txt"}},
               {"usage":{"tokens":250},"action":{"type":"finish","findings":[{"kind":"friction","text":"first step unclear"},{"kind":"blocking","text":"step 2 fails as written"}]}}]'
CASE="the shell action ran (its file exists in the sandbox), its output went back to the model, and the finish ended the run"
check test "$rc" -eq 0 -a "$(calls finish)" -eq 2 -a -s "$work/finish/sandbox/made.txt"
check python3 - "$work/finish/fp.log" "$work/finish/out.json" <<'PY'
import json, sys
calls = [json.loads(l) for l in open(sys.argv[1])]
assert "marker-7" in json.dumps(calls[1]["req"]["messages"]), "the action's output never reached the model"
a = json.load(open(sys.argv[2]))
assert a["findings"] == [{"kind": "friction", "text": "first step unclear"}, {"kind": "blocking", "text": "step 2 fails as written"}], a
assert a["tokens"] == 550, a
assert "marker-7" in a["transcript"] and "step 2 fails" in a["transcript"], a
PY
CASE="the first model call carries the persona's instructions and the endpoint"
check python3 - "$work/finish/fp.log" <<'PY'
import json, sys
r = json.loads(open(sys.argv[1]).readline())["req"]
s = r["system"] + json.dumps(r["messages"])
assert "evaluator with only the README" in s and "http://127.0.0.1:18080" in s, s
PY

# --- AC5 (and AC4): the shell is a pinned, unprivileged container that can see ONLY the sandbox -------------------
CASE="every shell action runs as: docker run --rm ... -v <sandbox>:/work -w /work <pinned shell image> sh -c <command>"
check python3 - "$work/finish/fd.log" "$work/finish/sandbox" "$SHL" <<'PY'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1])]
assert rows, "no shell action went through docker"
for r in rows:
    a = r["argv"]
    assert a[0] == "run" and "--rm" in a, a
    vs = [a[i + 1] for i, x in enumerate(a) if x == "-v"]
    assert vs == [sys.argv[2] + ":/work"], vs                       # exactly ONE mount: the sandbox
    assert a[a.index("-w") + 1] == "/work", a
    assert a[a.index(sys.argv[3]) + 1:a.index(sys.argv[3]) + 3] == ["sh", "-c"], a   # the pinned image, then sh -c
    for forbidden in ("--privileged", "--volumes-from", "--pid", "--cap-add", "--security-opt", "--device", "-e", "--env", "--env-file", "--user", "-u"):
        if forbidden in ("-e", "--env", "--env-file"):
            assert forbidden not in a, (forbidden, a)
        else:
            assert not any(x == forbidden or x.startswith(forbidden + "=") for x in a), (forbidden, a)
    assert not any("docker.sock" in x or x in ("/", "/var", "/Users", "/home") for x in a), a
PY
CASE="the docker call carries no credentials: neither the model key nor a GitHub token is in its environment"
check python3 - "$work/finish/fd.log" <<'PY'
import json, sys
for l in open(sys.argv[1]):
    env = json.loads(l)["env"]
    for bad in ("ANTHROPIC_API_KEY", "GITHUB_TOKEN"):
        assert bad not in env, bad
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
check python3 - "$work/model/fp.log" <<'PY'
import json, sys
assert all(json.loads(l)["req"]["model"] == "OWNER-MODEL-Q" for l in open(sys.argv[1]))
PY
CASE="the model value never appears in the agent's answer or transcript"
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
