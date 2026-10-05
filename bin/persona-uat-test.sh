#!/usr/bin/env bash
# proves: REQ-UAT-001-AC1, REQ-UAT-001-AC2, REQ-UAT-001-AC3, REQ-UAT-001-AC5
# The persona UAT driver (owner ratified Oct 3 and Oct 4; ops/docs/ratify/2026-10-02-owner-load.md point 9), proved
# against a STUB agent so no model credential is needed: five fixed personas, one report and one transcript each;
# a broken behavior or failing doc step fails a release-candidate run (fail closed: an agent that crashes or answers
# nonsense counts as blocking); friction becomes one information issue and blocks nothing; the weekly run opens one
# blocking issue instead of failing; the agent sees only the public docs and the endpoint (never source or internal
# docs); its model and token budget come from owner-set variables and no model name is written anywhere in the repo's
# files or the reports; a persona that hit its token cap is flagged in its report.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
driver="$root/bin/persona-uat.py"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
ok()   { pass=$((pass+1)); echo "ok   $1"; }
bad()  { failn=$((failn+1)); echo "FAIL $1"; }
check() { if "$@" >/dev/null 2>&1; then ok "$CASE"; else bad "$CASE"; fi; }

# --- fixtures -------------------------------------------------------------------------------------------------
repo="$work/repo"; mkdir -p "$repo/docs/quality" "$repo/internal" "$repo/cmd"
echo "# fscache README" >"$repo/README.md"
echo "install steps"    >"$repo/docs/install.md"
echo "gradle steps"     >"$repo/docs/gradle.md"
echo "INTERNAL TRACE"   >"$repo/docs/quality/traceability.md"
echo "UNRELEASED NOTES" >"$repo/docs/next-release-notes.md"
echo "package internal // SECRET-SOURCE" >"$repo/internal/x.go"
IMG="ghcr.io/example/cache@sha256:$(printf 'a%.0s' $(seq 64))"
PERSONAS="gradle-platform-engineer maven-jenkins-ci compliance-reviewer readme-evaluator on-call-engineer"

# The stub agent: one request as JSON on stdin, one answer as JSON on stdout. It records what it was given.
cat >"$work/stub.py" <<'PY'
import json, os, sys
req = json.load(sys.stdin)
plan = json.load(open(os.environ["STUB_PLAN"]))
p = plan.get(req["persona"], {})
seen = sorted(os.path.relpath(os.path.join(d, f), req["docs_dir"]) for d, _, fs in os.walk(req["docs_dir"]) for f in fs)
log = os.environ["STUB_LOG"]
with open(log, "a") as fh:
    fh.write(json.dumps({"persona": req["persona"], "docs": seen, "endpoint": req.get("endpoint"),
                         "image": req.get("image"), "model": req.get("model"), "budget": req.get("token_budget"),
                         "keys": sorted(req.keys()), "cwd": os.getcwd()}) + "\n")
if p.get("crash"):
    sys.exit(7)
if p.get("garbage"):
    print("not json at all"); sys.exit(0)
print(json.dumps({"findings": p.get("findings", []), "tokens": p.get("tokens", 1000),
                  "transcript": "TRANSCRIPT for " + req["persona"] + "\n"}))
PY

# run <name> <plan-json> <mode> [extra env as VAR=val ...]  -> $work/<name>/out, $work/<name>.log, sets rc
run() {
  local name=$1 plan=$2 mode=$3; shift 3
  mkdir -p "$work/$name"; echo "$plan" >"$work/$name/plan.json"; : >"$work/$name/log"
  rc=0
  env STUB_PLAN="$work/$name/plan.json" STUB_LOG="$work/$name/log" \
      PERSONA_UAT_MODEL=MODEL-DEFAULT-X PERSONA_UAT_COMPLIANCE_MODEL=MODEL-COMPLIANCE-X "$@" \
      python3 "$driver" --mode "$mode" --image "$IMG" --endpoint http://127.0.0.1:9 --repo "$repo" \
        --out "$work/$name/out" --agent "python3 $work/stub.py" >"$work/$name/stdout" 2>"$work/$name/stderr" || rc=$?
}
out() { echo "$work/$1/out"; }

# --- AC1: five personas, one report and one transcript each, a clean run passes ---------------------------------
run clean '{}' rc
CASE="rc clean run exits 0"; check test "$rc" -eq 0
for p in $PERSONAS; do
  CASE="clean run writes one report and one transcript for $p"
  check test -s "$(out clean)/$p.report.md" -a -s "$(out clean)/$p.transcript.txt"
done
CASE="exactly five personas ran (no more, no fewer)"
check test "$(wc -l <"$work/clean/log")" -eq 5 -a "$(ls "$(out clean)"/*.report.md | wc -l)" -eq 5
CASE="a clean run records no friction or blocking issue"
check test ! -e "$(out clean)/friction-issue.md" -a ! -e "$(out clean)/blocking-issue.md"
CASE="each report states its verdict in the first line"
check grep -qx 'VERDICT: pass' <(head -1 "$(out clean)/on-call-engineer.report.md")

# --- AC1: broken behavior or a failing doc step fails the RC run ------------------------------------------------
run blocking '{"maven-jenkins-ci":{"findings":[{"kind":"blocking","text":"docs/maven.md step 3 fails as written: 404"}]}}' rc
CASE="rc: a blocking finding fails the run"; check test "$rc" -ne 0
CASE="the blocking persona's report says BLOCKING and carries the finding"
check grep -q 'VERDICT: blocking' "$(out blocking)/maven-jenkins-ci.report.md"
check grep -q 'step 3 fails as written' "$(out blocking)/maven-jenkins-ci.report.md"
CASE="the other four personas still ran and wrote reports (one failure does not hide the rest)"
check test "$(ls "$(out blocking)"/*.report.md | wc -l)" -eq 5

# fail closed: an agent that crashes or answers garbage cannot pass the run
run crash '{"compliance-reviewer":{"crash":true}}' rc
CASE="rc: an agent that crashes counts as blocking, not as a pass"
check test "$rc" -ne 0
check grep -q 'VERDICT: blocking' "$(out crash)/compliance-reviewer.report.md"
check grep -qi 'did not run' "$(out crash)/compliance-reviewer.report.md"
run garbage '{"readme-evaluator":{"garbage":true}}' rc
CASE="rc: an agent whose answer is not the contract counts as blocking"
check test "$rc" -ne 0
check grep -q 'VERDICT: blocking' "$(out garbage)/readme-evaluator.report.md"

# --- AC3: friction is information, one issue per run, blocks nothing --------------------------------------------
run friction '{"gradle-platform-engineer":{"findings":[{"kind":"friction","text":"the proxy URL is easy to mistype"}]},"on-call-engineer":{"findings":[{"kind":"friction","text":"no log level hint"},{"kind":"friction","text":"rollback needs two reads"}]}}' rc
CASE="friction alone does not fail an rc run"; check test "$rc" -eq 0
CASE="friction is recorded in exactly one issue file for the run, naming every finding"
check test "$(ls "$(out friction)"/friction-issue.md | wc -l)" -eq 1
check grep -q 'proxy URL is easy to mistype' "$(out friction)/friction-issue.md"
check grep -q 'no log level hint' "$(out friction)/friction-issue.md"
check grep -q 'rollback needs two reads' "$(out friction)/friction-issue.md"
CASE="the friction issue is information: it is not labelled blocking"
check bash -c "! grep -qi 'labels:.*blocking' '$(out friction)/friction-issue.md'"
check test ! -e "$(out friction)/blocking-issue.md"
CASE="a friction-only persona's verdict is friction"
check grep -q 'VERDICT: friction' "$(out friction)/gradle-platform-engineer.report.md"

# --- AC2: the weekly run opens or updates ONE issue labelled blocking -------------------------------------------
run weekly '{"maven-jenkins-ci":{"findings":[{"kind":"blocking","text":"jenkins step fails"}]},"compliance-reviewer":{"findings":[{"kind":"blocking","text":"cosign verify fails as written"}]}}' weekly
CASE="weekly: blocking findings are handed to the workflow as exactly one blocking issue (the run itself exits 0)"
check test "$rc" -eq 0
check test -s "$(out weekly)/blocking-issue.md"
check grep -qx 'labels: blocking' "$(out weekly)/blocking-issue.md"
check grep -q 'jenkins step fails' "$(out weekly)/blocking-issue.md"
check grep -q 'cosign verify fails as written' "$(out weekly)/blocking-issue.md"
CASE="weekly: the issue has a fixed title so an open one is updated, not duplicated"
check grep -qx 'title: Persona UAT: blocking findings (weekly)' "$(out weekly)/blocking-issue.md"
run weeklyclean '{}' weekly
CASE="weekly: a clean run opens no blocking issue"
check test "$rc" -eq 0 -a ! -e "$(out weeklyclean)/blocking-issue.md"

# --- AC5: the agent reads only the public docs and the endpoint --------------------------------------------------
CASE="the agent is given README.md and the top-level docs, and nothing else"
check python3 - "$work/clean/log" <<'PY'
import json, sys
for ln in open(sys.argv[1]):
    r = json.loads(ln)
    assert r["docs"] == ["README.md", "docs/gradle.md", "docs/install.md"], r["docs"]
PY
CASE="source, internal docs and unreleased notes never reach the agent"
check bash -c "! grep -rqE 'SECRET-SOURCE|INTERNAL TRACE|UNRELEASED NOTES' '$work/clean/out'"
CASE="the agent's request carries the image digest and endpoint but no repository path"
check python3 - "$work/clean/log" "$repo" <<'PY'
import json, sys
for ln in open(sys.argv[1]):
    r = json.loads(ln)
    assert r["image"].endswith("sha256:" + "a" * 64) and r["endpoint"] == "http://127.0.0.1:9"
    assert sys.argv[2] not in json.dumps(r) and not r["cwd"].startswith(sys.argv[2]), r
PY

# --- AC5: model and token budget come from owner-set variables ---------------------------------------------------
CASE="four personas use the default model variable and the compliance reviewer uses its own"
check python3 - "$work/clean/log" <<'PY'
import json, sys
m = {json.loads(l)["persona"]: json.loads(l)["model"] for l in open(sys.argv[1])}
assert m["compliance-reviewer"] == "MODEL-COMPLIANCE-X", m
assert all(v == "MODEL-DEFAULT-X" for k, v in m.items() if k != "compliance-reviewer"), m
PY
CASE="the token budget defaults to 400000 per persona"
check python3 - "$work/clean/log" <<'PY'
import json, sys
assert all(json.loads(l)["budget"] == 400000 for l in open(sys.argv[1]))
PY
run budget '{}' rc PERSONA_UAT_TOKEN_BUDGET=123456
CASE="the owner's budget variable is honored"
check python3 - "$work/budget/log" <<'PY'
import json, sys
assert all(json.loads(l)["budget"] == 123456 for l in open(sys.argv[1]))
PY
run nobudget '{}' rc PERSONA_UAT_TOKEN_BUDGET=lots
CASE="a budget that is not a positive whole number refuses to run anything (exit 2)"
check test "$rc" -eq 2 -a ! -s "$work/nobudget/log"
run nomodel '{}' rc PERSONA_UAT_MODEL=
CASE="an unset model variable refuses to run anything (exit 2); there is no built-in default model"
check test "$rc" -eq 2 -a ! -s "$work/nomodel/log"
run nocomp '{}' rc PERSONA_UAT_COMPLIANCE_MODEL=
CASE="an unset compliance-model variable refuses to run anything (exit 2)"
check test "$rc" -eq 2 -a ! -s "$work/nocomp/log"

# --- AC5: the transcript is kept; the cap is flagged; no model name is written anywhere --------------------------
CASE="the transcript file holds what the agent said"
check grep -q 'TRANSCRIPT for compliance-reviewer' "$(out clean)/compliance-reviewer.transcript.txt"
run capped '{"readme-evaluator":{"tokens":400000},"gradle-platform-engineer":{"tokens":399999}}' rc
CASE="a persona that used its whole budget is flagged plainly in its report; one under it is not"
check grep -q 'HIT ITS TOKEN CAP' "$(out capped)/readme-evaluator.report.md"
check bash -c "! grep -q 'HIT ITS TOKEN CAP' '$(out capped)/gradle-platform-engineer.report.md'"
CASE="a capped run does not fail by itself, and the summary names the capped persona"
check test "$rc" -eq 0
check grep -q 'readme-evaluator' "$(out capped)/summary.json"
CASE="no model name appears in any report, transcript, summary or issue file"
check bash -c "! grep -rqE 'MODEL-(DEFAULT|COMPLIANCE)-X' '$(out clean)' '$(out capped)' '$(out friction)' '$(out weekly)'"
CASE="no model name is written in the driver, the agent or the persona job's workflow text"
check bash -c "! grep -nEi 'claude-(opus|sonnet|haiku|fable)|\\b(opus|sonnet|haiku)-[0-9]|gpt-[0-9]' \
  '$root'/bin/persona-uat.py '$root'/bin/persona-uat-agent.py"

echo "persona-uat: $pass passed, $failn failed"
test "$failn" -eq 0
