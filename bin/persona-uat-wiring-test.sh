#!/usr/bin/env bash
# proves: REQ-UAT-001-AC1, REQ-UAT-001-AC2, REQ-UAT-001-AC3, REQ-UAT-001-AC4, REQ-UAT-001-AC5
# Where the persona UAT runs (owner ratified Oct 3 and Oct 4; point 9): a persona-uat job in the release chain that runs
# only for release-candidate tags, after promotion, by digest, in the persona-uat environment, and fails the run;
# a persona-uat job in the weekly maintenance workflow that runs only on its Monday schedule and hands its blocking
# findings to ONE labelled issue; the model and budget read from owner-set variables (never written in the workflow);
# the CI tools a persona needs (Jenkins, a GitLab runner, kind) named only as digest-pinned images, and nothing in either
# job or the driver that provisions anything in a cloud. The real workflows must pass; each mutated copy must be caught.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
export PERSONA_ROOT="$root"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
judge() { python3 - "$1" "$2" "$3" <<'PY'
import json, re, sys, yaml
rel, fresh, tools = sys.argv[1:4]
bad = []
def load(p): return yaml.load(open(p), Loader=yaml.BaseLoader)
def steps(job): return job.get("steps", [])
def text(job): return "\n".join((s.get("run") or "") + "\n" + json.dumps(s.get("env", {})) + "\n" + json.dumps(s.get("with", {})) for s in steps(job))
CLOUD = re.compile(r"terraform|tofu |pulumi|eksctl|doctl|aws (ec2|ecs|eks|lightsail|cloudformation)|gcloud (compute|container)|az (vm|aks)|kubectl create cluster", re.I)
MODEL = re.compile(r"claude-(opus|sonnet|haiku|fable)|\b(opus|sonnet|haiku)-[0-9]|gpt-[0-9]", re.I)
PIN_USES = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")

def common(name, job, mode):
    t = text(job)
    if "persona-uat.py" not in t or f"--mode {mode}" not in t:
        bad.append(f"{name}: does not run bin/persona-uat.py --mode {mode}")
    if str(job.get("continue-on-error", "false")).lower() == "true":
        bad.append(f"{name}: continue-on-error would let a persona failure pass")
    for v in ("PERSONA_UAT_MODEL", "PERSONA_UAT_COMPLIANCE_MODEL", "PERSONA_UAT_TOKEN_BUDGET"):
        if not re.search(v + r"\W+.*\$\{\{\s*vars\." + v + r"\s*\}\}", t, re.S):
            bad.append(f"{name}: {v} is not read from the owner's variable vars.{v}")
    if MODEL.search(json.dumps(job)):
        bad.append(f"{name}: a model name is written in the workflow")
    if CLOUD.search(t):
        bad.append(f"{name}: provisions something in a cloud")
    for s in steps(job):
        u = str(s.get("uses", ""))
        if u and not PIN_USES.match(u):
            bad.append(f"{name}: action {u} is not pinned to a commit digest")
    for m in re.finditer(r"(?:^|\s)(?:docker run|docker pull|image:|container:)\s+(\S+)", t):
        if "@sha256:" not in m.group(1) and not m.group(1).startswith(("$", "\"$", "'$")):
            bad.append(f"{name}: image {m.group(1)} is not pinned by digest")
    if not any("upload-artifact" in str(s.get("uses", "")) for s in steps(job)):
        bad.append(f"{name}: transcripts are not uploaded as an artifact")
    for s in steps(job):
        if "upload-artifact" in str(s.get("uses", "")) and "always()" not in str(s.get("if", "")):
            bad.append(f"{name}: the transcript upload does not run when personas fail")

# --- the release chain (AC1) ---
r = load(rel); j = r.get("jobs", {}).get("persona-uat")
if not j:
    bad.append("release.yml has no persona-uat job")
else:
    common("release persona-uat", j, "rc")
    needs = j.get("needs", [])
    needs = [needs] if isinstance(needs, str) else needs
    for n in ("image", "promotion"):
        if n not in needs: bad.append(f"release persona-uat does not wait for {n}")
    cond = str(j.get("if", ""))
    if "-rc." not in cond or "refs/tags/v" not in cond:
        bad.append("release persona-uat does not run only for v*-rc.* tags")
    if j.get("environment") != "persona-uat" and (j.get("environment") or {}).get("name") != "persona-uat":
        bad.append("release persona-uat does not run in the persona-uat environment")
    if "needs.image.outputs.digests" not in text(j) and "needs.image.outputs.digests" not in json.dumps(j):
        bad.append("release persona-uat does not take the image by the chain's digests")
    p = j.get("permissions", {})
    if p.get("id-token") != "write" or p.get("contents") != "read":
        bad.append("release persona-uat permissions are not id-token: write + contents: read")
    if "issues" in p and p["issues"] == "write" and "friction" not in text(j):
        bad.append("release persona-uat can write issues but never files the friction issue")
    if "friction-issue.md" not in text(j):
        bad.append("release persona-uat does not file the one friction issue per run (AC3)")
    if "blocking-issue" in text(j):
        bad.append("release persona-uat opens a blocking issue: on a release candidate a blocking finding fails the run")

# --- the weekly workflow (AC2) ---
f = load(fresh); j = f.get("jobs", {}).get("persona-uat")
if not j:
    bad.append("go-freshness.yml has no persona-uat job")
else:
    common("weekly persona-uat", j, "weekly")
    cond = str(j.get("if", ""))
    cron = [c.get("cron") for c in f.get("on", {}).get("schedule", [])] if isinstance(f.get("on"), dict) else []
    if "github.event.schedule" not in cond or "* * 1'" not in cond.replace('"', "'") or "43 6 * * 1" not in cron:
        bad.append("weekly persona-uat does not run only on the Monday schedule")
    t = text(j)
    if "gh issue" not in t or "--label blocking" not in t and "blocking-issue.md" not in t:
        bad.append("weekly persona-uat does not open or update the one blocking issue")
    if "gh issue edit" not in t and "gh issue comment" not in t:
        bad.append("weekly persona-uat never updates an open blocking issue (it would duplicate)")
    if "friction-issue.md" not in t:
        bad.append("weekly persona-uat does not file the one friction issue per run (AC3)")

# --- the pinned CI tools (AC4) ---
try:
    tl = json.load(open(tools))
except Exception as e:
    bad.append(f"the persona tools file is missing or unreadable: {e}"); tl = {}
for k in ("jenkins", "gitlab-runner", "kind"):
    v = tl.get(k, "")
    if not re.search(r"@sha256:[0-9a-f]{64}$", v):
        bad.append(f"tool {k} is not a digest-pinned image ({v!r})")
for k, v in tl.items():
    if not re.search(r"@sha256:[0-9a-f]{64}$", str(v)):
        bad.append(f"tool {k} is not pinned by digest")
import os
for fn in ("persona-uat.py", "persona-uat-agent.py"):
    try:
        src = open(os.path.join(os.environ["PERSONA_ROOT"], "bin", fn)).read()
    except OSError:
        bad.append(f"bin/{fn} is missing"); continue
    if CLOUD.search(src):
        bad.append(f"bin/{fn} provisions something in a cloud")
print("; ".join(bad)); sys.exit(1 if bad else 0)
PY
}
ROOT_REL="$root/.github/workflows/release.yml"
ROOT_FRESH="$root/.github/workflows/go-freshness.yml"
ROOT_TOOLS="$root/bin/persona-uat-tools.json"
expect_ok()  { local m; if m=$(judge "$1" "$2" "$3"); then pass=$((pass+1)); echo "ok   $4"; else failn=$((failn+1)); echo "FAIL $4: $m"; fi; }
expect_bad() { if judge "$1" "$2" "$3" >/dev/null 2>&1; then failn=$((failn+1)); echo "FAIL mutation not caught: $4"; else pass=$((pass+1)); echo "ok   caught: $4"; fi; }

expect_ok "$ROOT_REL" "$ROOT_FRESH" "$ROOT_TOOLS" "the real workflows and tools file satisfy the persona UAT wiring"

# --- mutations: each must be caught ------------------------------------------------------------------------------
mutate() { # <name> <file: rel|fresh|tools> <python expression editing text variable s>
  local name=$1 which=$2 expr=$3
  cp "$ROOT_REL" "$work/rel.yml"; cp "$ROOT_FRESH" "$work/fresh.yml"; cp "$ROOT_TOOLS" "$work/tools.json"
  local target; case "$which" in rel) target="$work/rel.yml";; fresh) target="$work/fresh.yml";; tools) target="$work/tools.json";; esac
  python3 - "$target" "$expr" <<'PY'
import re, sys
p, expr = sys.argv[1], sys.argv[2]
s = open(p).read()
before = s
s = eval(expr)
assert s != before, "mutation changed nothing: " + expr
open(p, "w").write(s)
PY
  expect_bad "$work/rel.yml" "$work/fresh.yml" "$work/tools.json" "$name"
}
mutate "rc job no longer waits for promotion"        rel   're.sub(r"(persona-uat:\n(?:.*\n)*?\s+needs:\s*\[)([^\]]*)(\])", lambda m: m.group(1)+m.group(2).replace(", promotion","").replace("promotion, ","").replace("promotion","")+m.group(3), s, count=1)'
mutate "rc job runs for every tag, not only -rc."    rel   're.sub(r"(persona-uat:\n(?:.*\n)*?\s+if:\s*).*\n", lambda m: m.group(1)+"${{ startsWith(github.ref, \x27refs/tags/v\x27) }}\n", s, count=1)'
mutate "rc job may fail without failing the run"     rel   're.sub(r"(persona-uat:\n)", r"\1    continue-on-error: true\n", s, count=1)'
mutate "rc job leaves the persona-uat environment"   rel   're.sub(r"environment: persona-uat", "environment: release", s)'
mutate "rc job hard-codes a model name"              rel   's.replace("${{ vars.PERSONA_UAT_MODEL }}", "claude-sonnet-5-5", 1)'
mutate "rc job drops the budget variable"            rel   's.replace("${{ vars.PERSONA_UAT_TOKEN_BUDGET }}", "400000", 1)'
mutate "rc job's transcript upload skips failures"   rel   're.sub(r"(persona-uat:\n(?:.*\n)*?)(\s+if: \$\{\{ always\(\) \}\}\n)", r"\1\n", s, count=1)'
mutate "rc job provisions a cloud instance"          rel   're.sub(r"(persona-uat:\n(?:.*\n)*?\s+steps:\n)", r"\1      - run: aws ec2 run-instances --image-id ami-1\n", s, count=1)'
mutate "weekly job runs on every cron, not Mondays"  fresh  're.sub(r"(persona-uat:\n(?:.*\n)*?\s+if:\s*).*\n", lambda m: m.group(1)+"${{ github.event_name == \x27schedule\x27 }}\n", s, count=1)'
mutate "weekly job would duplicate the issue"        fresh  's.replace("gh issue edit", "gh issue create")'
mutate "tools file: jenkins by tag, not digest"      tools  're.sub(r"(\"jenkins\":\s*\"[^\"@]*)@sha256:[0-9a-f]{64}", r"\1", s)'
mutate "tools file: a persona tool is missing"       tools  're.sub(r"\"kind\":[^\n]*\n", "", s)'

echo "persona-uat wiring: $pass passed, $failn failed"
test "$failn" -eq 0
