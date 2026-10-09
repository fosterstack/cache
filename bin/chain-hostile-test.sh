#!/usr/bin/env bash
# proves: REQ-CHAIN-001-AC5
# The hostile Build step (v0.3.0 rules 52a, 59; owner RATIFIED Oct 9; advisor 0328), static half. The runtime half is the
# GitHub dry run, which must be green and linked in the PR before it merges (the AC says so; no script can check that).
#
# The shape this test assumes (the implementer matches it; anything else is a change to this header first):
#   stage-build.yml: a step `run: bash bin/chain-hostile-step.sh`, gated by `if:` mentioning inputs.hostile, in the Build job,
#       followed by an upload of the artifact `hostile-attempts`. The script makes six attempts as six functions
#       (the five of rule 52a plus the advisor's 0334 case): attempt_mint_sign_cert, attempt_read_sign_token,
#       attempt_read_sign_key, attempt_hand_sign_code, attempt_forge_provenance, attempt_call_sign_from_other_workflow
#       (a second workflow calls stage-sign.yml at the tag: it gets Sign's SAN but its Build Config URI is not release.yml;
#       harness spike (b)). The runtime half of that last case needs a second caller workflow, which must NOT be merged
#       (no workflow sprawl; the AC1 test allows only stage-sign.yml as new): it lives in a throwaway commit on the PR branch
#       (.github/workflows/hostile-caller.yml), its record is uploaded as the artifact the script reads, and the commit is
#       removed before the merge. The unit half is chain-verify-test.sh (sign_othercaller). It writes only the RAW MATERIAL of each attempt (a file) under attempts/, and never
#       writes an outcome: the words refused/accepted/outcome do not appear in its code, so it cannot grade itself.
#   release.yml (dry run, workflow_dispatch input dry-run): the build caller passes `hostile: ${{ inputs.dry-run }}`; job
#       `hostile-verify` (needs the sign job; permissions EXACTLY {contents: read}: no id-token, nothing to write) starts with
#       actions/checkout (persist-credentials: false) and actions/download-artifact name `hostile-attempts` path attempts (the
#       raw material each attempt made: without it every verify would read a missing file), then has one step per attempt,
#       each exactly three lines:
#           rc=0
#           python3 bin/chain-verify.py <verify|sign|stage-start|hostile-material> ... || rc=$?
#           python3 bin/chain-verify.py hostile-row --attempt <attempt> --exit-code "$rc" --stderr <file> --out results/<attempt>.json
#       (the verifier's OWN exit code, captured per attempt from its own invocation; `|| true`, `|| echo`, echo/printf/cat
#       writing JSON, or a static row fail the wiring judge). The verifier line is PINNED per attempt (the exact subcommand,
#       --stage and material path; $NOW is the run's verify time, policy.json the per-tag policy):
#         mint_sign_cert    verify --stage sign --record attempts/mint_sign_cert.json --policy policy.json --now "$NOW"
#         read_sign_token   hostile-material --kind token --file attempts/read_sign_token.txt
#         read_sign_key     hostile-material --kind key --file attempts/read_sign_key.txt
#         hand_sign_code    sign --check --signer cosign --digests attempts/hand_sign_code.json --build-record attempts/build-collection.json --policy policy.json --out attempts/out-hand_sign_code
#         forge_provenance  verify --stage sign --record attempts/forge_provenance.json --policy policy.json --now "$NOW"
#         call_sign_from_other_workflow  verify --stage sign --record attempts/call_sign_from_other_workflow.json --policy policy.json --now "$NOW"
#       A refusal only counts when its stage and cause fit the attempt (the verdict checks): mint_sign_cert -> stage sign|release,
#       cause names the identity or stage-sign.yml; read_sign_token / read_sign_key -> stage runner, `nothing usable`;
#       hand_sign_code -> stage sign, cause digest|format; forge_provenance -> stage sign|release, cause provenance|identity|
#       stage-sign.yml; call_sign_from_other_workflow -> stage sign|release, cause release.yml|build config. A refusal whose
#       reason says the material was missing or unreadable NEVER counts (an attempt that never ran must not read as isolation).
#       ERROR vs REFUSAL: a missing or unreadable material file is an ERROR (hostile-material exits 2 with `error: ...`, hostile-row
#       writes NO row for exit 2 or any stderr whose first line is not `refused at <stage>: <reason>`), so the collect step
#       fails and the dry run is red. then one step `python3 bin/chain-verify.py hostile-collect results
#       --out hostile-results.json` and an upload of the artifact `hostile-results`. Job `hostile-verdict` (needs hostile-verify;
#       permissions {contents: read}) downloads that artifact and runs `python3 bin/chain-verify.py hostile-verdict
#       hostile-results/hostile-results.json`. No hostile-results*.json may be a file of the repository tree (it must come from
#       the run). Every dry-run-gated job (the release caller, the `decide` tag job) has an `if:` that has the conjunct
#       `!inputs.dry-run` and no `||`, so a dry run neither tags nor publishes.
#   The runtime half of the sixth case runs from a throwaway commit on a ref matching `hostile-proof/*` (a branch that is
#       never a pull request and never merged); this test makes no exception for it and has no environment-variable bypass.
#   Subcommands (the REAL script is run here; no inline copy):
#       chain-verify.py hostile-row --attempt A --exit-code N --stderr FILE --out OUT.json
#           writes {"attempt","outcome","stage","reason","judged_by":"verifier","exit_code"}: outcome refused when N != 0 and
#           FILE's first line is `refused at <stage>: <reason>` (stage one of runner|build|sign|rebuild|check|release); outcome
#           accepted when N == 0; exit 1 (no row) for a traceback, an empty or unparsable stderr with N != 0, or an unknown attempt.
#       chain-verify.py hostile-collect DIR --out F      merges the six rows; exit 1 naming a missing, duplicate or extra attempt.
#       chain-verify.py hostile-material --kind token|key --file F
#           exit 0 when F holds usable material (a JWT-shaped token; a PEM PRIVATE KEY block), exit 1 with
#           `refused at runner: nothing usable` when F exists and is empty or holds none (the runner VM was isolated, the attempt
#           got nothing); exit 2 with `error: ...` when F is missing or unreadable (no row); an unknown kind exits 2.
#   chain-verify.py hostile-verdict RESULTS.json   (the REAL script is run here; there is no inline copy of it)
# Modelled on: this repo's bin/release-patch-wiring-test.sh (YAML-parsing wiring judge); in-toto-witness cmd/verify.go:211 (a
# verifier's refusal is its exit code and message, not a field the attacker writes); the spike evidence
# 2026-10-09-harness-witness-spikes-a-c.md:83-100 (the five ways a Build step reaches the signing identity).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cv="$root/bin/chain-verify.py"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
ok()  { pass=$((pass + 1)); echo "ok   $1"; }
bad() { failn=$((failn + 1)); echo "FAIL $1"; }
python3 -c 'import yaml' 2> /dev/null || { echo "FAIL python3 needs PyYAML (apt install python3-yaml)"; exit 1; }
attempts="mint_sign_cert read_sign_token read_sign_key hand_sign_code forge_provenance call_sign_from_other_workflow"
python3 - "$work" $attempts <<'PY'
import copy, json, sys
w, att = sys.argv[1], sys.argv[2:]
DEF = {"mint_sign_cert": ("sign", "identity is stage-build.yml, not stage-sign.yml"), "read_sign_token": ("runner", "nothing usable"),
       "read_sign_key": ("runner", "nothing usable"), "hand_sign_code": ("sign", "digest list is not sha256 digests (format)"),
       "forge_provenance": ("release", "provenance signed by stage-build.yml, not stage-sign.yml"),
       "call_sign_from_other_workflow": ("release", "build config URI is scan.yml; release.yml required")}
def row(a, **k):
    r = {"attempt": a, "outcome": "refused", "stage": DEF.get(a, ("release", "x"))[0], "reason": DEF.get(a, ("release", "identity is stage-build.yml"))[1], "judged_by": "verifier", "exit_code": 1}
    r.update(k); return r
good = {"attempts": [row(a) for a in att]}
def save(n, d): json.dump(d, open("%s/%s.json" % (w, n), "w"))
save("good", good)
def mut(n, i, **k):
    m = copy.deepcopy(good); m["attempts"][i].update(k); save(n, m)
mut("accepted_forge", 4, outcome="accepted")
mut("accepted_mint", 0, outcome="accepted")
mut("accepted_call", 5, outcome="accepted")
mut("selfreport", 4, judged_by="hostile-step")
mut("exit0", 1, exit_code=0)
mut("noreason", 0, reason="")
mut("vague", 0, reason="x")
mut("badstage", 2, stage="x")
mut("wrongcause_call", 5, reason="attempt material is missing: attempts/call_sign_from_other_workflow.json (no such file)")
mut("wrongcause_call2", 5, reason="something unrelated went wrong")
mut("wrongcause_forge", 4, reason="digest mismatch")
mut("wrongstage_token", 1, stage="sign")
mut("wrongcause_hand", 3, reason="identity is stage-build.yml")
mut("wrongcause_key", 2, reason="no such file attempts/read_sign_key.txt")
mut("wrongcause_mint", 0, reason="digest mismatch")
mut("nostage", 3, stage="")
m = copy.deepcopy(good); del m["attempts"][1]; save("missing", m)
m = copy.deepcopy(good); m["attempts"].append(row("mint_sign_cert")); save("duplicate", m)
m = copy.deepcopy(good); m["attempts"].append(row("alter_output")); save("extra", m)
m = copy.deepcopy(good); m["attempts"][2]["attempt"] = "read_sign_token"; save("renamed", m)
save("empty", {"attempts": []})
open(w + "/notjson.json", "w").write("{not json")
PY
run() { python3 "$cv" hostile-verdict "$work/$1.json" 2> "$work/err" > "$work/out" || return $?; }
expect() { # ok|refuse LABEL FILE [word]
  local rc=0; run "$3" || rc=$?
  if [ "$1" = ok ]; then if [ "$rc" = 0 ]; then ok "$2"; else bad "$2 (exit $rc; $(head -c 160 "$work/err" | tr '\n' ' '))"; fi
  else
    if [ "$rc" = 1 ] && ! grep -F -q Traceback "$work/err" && tr 'A-Z' 'a-z' < "$work/err" | grep -F -q -- "${4:-}"; then ok "$2"
    else bad "$2 (exit $rc, wanted 1 with '${4:-}'; $(head -c 160 "$work/err" | tr '\n' ' '))"; fi
  fi
}
[ -f "$cv" ] && ok "bin/chain-verify.py exists" || bad "bin/chain-verify.py does not exist (RED: not implemented yet)"
expect ok     "verdict: all six attempts refused by the verifier, each with a stage and a reason" good
expect refuse "verdict: a forged provenance that was ACCEPTED fails the test" accepted_forge "forge_provenance"
expect refuse "verdict: an accepted certificate mint fails the test" accepted_mint "mint_sign_cert"
expect refuse "verdict: a second workflow calling stage-sign.yml that was ACCEPTED fails the test" accepted_call "call_sign_from_other_workflow"
expect refuse "verdict: an outcome the hostile step graded itself is not evidence" selfreport "verifier"
expect refuse "verdict: a 'refused' outcome with exit code 0 is a contradiction" exit0 "read_sign_token"
expect refuse "verdict: a refusal with no reason" noreason "reason"
expect refuse "verdict: a one-character reason" vague "reason"
expect refuse "verdict: a stage that is not a stage" badstage "stage"
expect refuse "verdict: the sixth case refused only because its material was missing does not count" wrongcause_call "cause"
expect refuse "verdict: the sixth case refused for an unrelated reason (not release.yml / build config) does not count" wrongcause_call2 "cause"
expect refuse "verdict: a forged provenance refused for a digest mismatch (not its identity) does not count" wrongcause_forge "cause"
expect refuse "verdict: a token attempt graded at stage sign instead of runner does not count" wrongstage_token "stage"
expect refuse "verdict: hand_sign_code refused for an identity reason (not digest/format) does not count" wrongcause_hand "cause"
expect refuse "verdict: a key attempt refused because the file was missing does not count" wrongcause_key "cause"
expect refuse "verdict: a certificate mint refused for a digest mismatch does not count" wrongcause_mint "cause"
expect refuse "verdict: an empty stage" nostage "stage"
expect refuse "verdict: a missing attempt (read_sign_token)" missing "read_sign_token"
expect refuse "verdict: a duplicated attempt" duplicate "mint_sign_cert"
expect refuse "verdict: an attempt that is not one of the six" extra "alter_output"
expect refuse "verdict: two rows for one attempt and none for another" renamed "read_sign_key"
expect refuse "verdict: no attempts at all" empty "attempt"
expect refuse "verdict: a file that is not JSON" notjson "json"
# ---- hostile-row / hostile-collect / hostile-material (the verifier's own rows; REAL script) -------------------------------
cvx() { local rc=0; python3 "$cv" "$@" 2> "$work/xerr" > "$work/xout" || rc=$?; return $rc; }
xexpect() { # ok|refuse LABEL word -- args...
  local k=$1 l=$2 w=$3; shift 4; local rc=0; cvx "$@" || rc=$?
  if [ "$k" = ok ]; then if [ "$rc" = 0 ]; then ok "$l"; else bad "$l (exit $rc; $(head -c 160 "$work/xerr" | tr '\n' ' '))"; fi
  elif [ "$rc" = 1 ] && ! grep -F -q Traceback "$work/xerr" && tr 'A-Z' 'a-z' < "$work/xerr" | grep -F -q -- "$w"; then ok "$l"
  else bad "$l (exit $rc, wanted 1 with '$w'; $(head -c 160 "$work/xerr" | tr '\n' ' '))"; fi
}
mkdir -p "$work/rows"
printf 'refused at release: identity is stage-build.yml, not stage-sign.yml\n' > "$work/e_ref.txt"
printf 'Traceback (most recent call last):\nValueError: boom\n' > "$work/e_tb.txt"
: > "$work/e_empty.txt"
xexpect ok "hostile-row: exit 1 and 'refused at release: ...' becomes a refused row" - -- hostile-row --attempt forge_provenance --exit-code 1 --stderr "$work/e_ref.txt" --out "$work/rows/forge_provenance.json"
python3 - "$work/rows/forge_provenance.json" <<'PY' && ok "hostile-row: the row names outcome refused, stage release, the reason, judged_by verifier and the captured exit code" || bad "hostile-row: row content"
import json, sys
r = json.load(open(sys.argv[1]))
sys.exit(0 if (r["outcome"], r["stage"], r["judged_by"], r["exit_code"], r["attempt"]) == ("refused", "release", "verifier", 1, "forge_provenance") and "stage-sign.yml" in r["reason"] else 1)
PY
xexpect ok "hostile-row: exit 0 (the system accepted the attempt) becomes an accepted row" - -- hostile-row --attempt mint_sign_cert --exit-code 0 --stderr "$work/e_empty.txt" --out "$work/rows/mint_sign_cert.json"
python3 -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1]))["outcome"]=="accepted" else 1)' "$work/rows/mint_sign_cert.json" && ok "hostile-row: the accepted row says accepted" || bad "hostile-row: accepted row content"
xexpect refuse "hostile-row: a Python traceback is a crash, not a refusal" traceback -- hostile-row --attempt hand_sign_code --exit-code 1 --stderr "$work/e_tb.txt" --out "$work/rows/x1.json"
xexpect refuse "hostile-row: exit 1 with an empty stderr is not a refusal that names a stage and reason" stage -- hostile-row --attempt hand_sign_code --exit-code 1 --stderr "$work/e_empty.txt" --out "$work/rows/x2.json"
xexpect refuse "hostile-row: an attempt that is not one of the six" attempt -- hostile-row --attempt alter_output --exit-code 1 --stderr "$work/e_ref.txt" --out "$work/rows/x3.json"
for a in $attempts; do [ -f "$work/rows/$a.json" ] || python3 "$cv" hostile-row --attempt "$a" --exit-code 1 --stderr "$work/e_ref.txt" --out "$work/rows/$a.json" 2> /dev/null || true; done
xexpect ok "hostile-collect: six rows are merged into one results file" - -- hostile-collect "$work/rows" --out "$work/collected.json"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if sorted(r["attempt"] for r in d["attempts"])==sorted(sys.argv[2:]) else 1)' "$work/collected.json" $attempts && ok "hostile-collect: the merged file has each of the six attempts exactly once" || bad "hostile-collect: content"
mkdir -p "$work/rows5"; cp "$work"/rows/*.json "$work/rows5/" 2> /dev/null || true; rm -f "$work/rows5/read_sign_key.json"
xexpect refuse "hostile-collect: a missing row is named" read_sign_key -- hostile-collect "$work/rows5" --out "$work/c5.json"
mkdir -p "$work/rows7"; cp "$work"/rows/*.json "$work/rows7/" 2> /dev/null || true; cp "$work/rows/mint_sign_cert.json" "$work/rows7/zz-dup.json" 2> /dev/null || true
xexpect refuse "hostile-collect: a duplicate row is named" mint_sign_cert -- hostile-collect "$work/rows7" --out "$work/c7.json"
printf 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJyZXBvIn0.c2lnbmF0dXJl\n' > "$work/tok_yes.txt"; : > "$work/tok_no.txt"
printf -- '-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n' > "$work/key_yes.txt"
xexpect ok "hostile-material: a JWT-shaped token in the file means the attempt got material (exit 0, to be graded accepted)" - -- hostile-material --kind token --file "$work/tok_yes.txt"
xexpect refuse "hostile-material: an empty token file means the runner isolation held" "refused at runner" -- hostile-material --kind token --file "$work/tok_no.txt"
xexpect ok "hostile-material: a PEM private key in the file means the attempt got material" - -- hostile-material --kind key --file "$work/key_yes.txt"
xexpect refuse "hostile-material: no key material" "refused at runner" -- hostile-material --kind key --file "$work/tok_no.txt"
xexpect refuse "hostile-material: an unknown kind" kind -- hostile-material --kind password --file "$work/tok_no.txt"
mrc=0; cvx hostile-material --kind token --file "$work/does-not-exist.txt" || mrc=$?
if [ "$mrc" = 2 ] && tr 'A-Z' 'a-z' < "$work/xerr" | grep -F -q "error" && ! grep -F -q "refused at" "$work/xerr"; then ok "hostile-material: a MISSING file is an error (exit 2, no 'refused at' line), never a refusal"; else bad "hostile-material: missing file must exit 2 with error:, got $mrc: $(head -c 120 "$work/xerr" | tr '\n' ' ')"; fi
printf 'error: cannot read attempts/read_sign_token.txt\n' > "$work/e_err.txt"; printf 'usage: chain-verify.py hostile-material [-h] --kind {token,key} --file FILE\n' > "$work/e_usage.txt"
xexpect refuse "hostile-row: exit 2 with an 'error:' first line writes no row (an attempt that never ran is not isolation)" "refused at" -- hostile-row --attempt read_sign_token --exit-code 2 --stderr "$work/e_err.txt" --out "$work/rows/x9.json"
xexpect refuse "hostile-row: exit 2 with a 'usage:' message (argparse) writes no row" "refused at" -- hostile-row --attempt read_sign_token --exit-code 2 --stderr "$work/e_usage.txt" --out "$work/rows/x10.json"
[ ! -e "$work/rows/x9.json" ] && [ ! -e "$work/rows/x10.json" ] && ok "hostile-row: neither failed call left a row file behind" || bad "hostile-row: a row file exists for an error"
# ---- the wiring, by parsing the YAML and the script (not by grepping for substrings) ---------------------------------
cat > "$work/wiring.py" <<'PY'
import glob, os, re, sys, yaml
root = sys.argv[1]; bad = []
ATT = ["mint_sign_cert", "read_sign_token", "read_sign_key", "hand_sign_code", "forge_provenance", "call_sign_from_other_workflow"]
PIN = {
 "mint_sign_cert": r'python3 bin/chain-verify\.py verify --stage sign --record attempts/mint_sign_cert\.json --policy policy\.json --now "\$NOW"',
 "read_sign_token": r'python3 bin/chain-verify\.py hostile-material --kind token --file attempts/read_sign_token\.txt',
 "read_sign_key": r'python3 bin/chain-verify\.py hostile-material --kind key --file attempts/read_sign_key\.txt',
 "hand_sign_code": r'python3 bin/chain-verify\.py sign --check --signer cosign --digests attempts/hand_sign_code\.json --build-record attempts/build-collection\.json --policy policy\.json --out attempts/out-hand_sign_code',
 "forge_provenance": r'python3 bin/chain-verify\.py verify --stage sign --record attempts/forge_provenance\.json --policy policy\.json --now "\$NOW"',
 "call_sign_from_other_workflow": r'python3 bin/chain-verify\.py verify --stage sign --record attempts/call_sign_from_other_workflow\.json --policy policy\.json --now "\$NOW"',
}
GATE = re.compile(r"^\$\{\{ ?(?:[^|]*&& ?)?!inputs\.dry-run ?\}\}$")
OPEN = {"build", "sign", "rebuild", "check"}
def load(rel):
    p = os.path.join(root, rel)
    return yaml.load(open(p).read(), Loader=yaml.BaseLoader) if os.path.exists(p) else None
sb, rl = load(".github/workflows/stage-build.yml"), load(".github/workflows/release.yml")
if sb is None: bad.append("stage-build.yml missing")
else:
    found = False
    for jn, j in (sb.get("jobs") or {}).items():
        steps = j.get("steps") or []
        for i, s in enumerate(steps):
            if (s.get("run") or "").strip() == "bash bin/chain-hostile-step.sh":
                found = True
                if "inputs.hostile" not in str(s.get("if", "")): bad.append("the hostile step is not gated by inputs.hostile")
                later = [x for x in steps[i + 1:] if "upload-artifact" in str(x.get("uses", "")) and (x.get("with") or {}).get("name") == "hostile-attempts"]
                if not later: bad.append("no upload of the artifact hostile-attempts after the hostile step in the same job")
    if not found: bad.append("no step `bash bin/chain-hostile-step.sh` in the Build job")
if rl is None: bad.append("release.yml missing")
else:
    jobs = rl.get("jobs") or {}
    if "workflow_dispatch" not in (rl.get("on") or {}): bad.append("release.yml has no workflow_dispatch (the dry run)")
    hv, hd = jobs.get("hostile-verify"), jobs.get("hostile-verdict")
    if not hv or not hd: bad.append("jobs hostile-verify and hostile-verdict are required")
    else:
        need = lambda j: [j.get("needs")] if isinstance(j.get("needs"), str) else (j.get("needs") or [])
        sign_jobs = [n for n, j in jobs.items() if "stage-sign.yml" in str(j.get("uses", ""))]
        if not sign_jobs or not set(need(hv)) & set(sign_jobs): bad.append("hostile-verify must need the Sign job")
        if "hostile-verify" not in need(hd): bad.append("hostile-verdict must need hostile-verify")
        if hv.get("permissions") != {"contents": "read"}: bad.append("hostile-verify permissions must be exactly {contents: read} (no id-token, nothing to write): %s" % hv.get("permissions"))
        if hd.get("permissions") != {"contents": "read"}: bad.append("hostile-verdict permissions must be exactly {contents: read}: %s" % hd.get("permissions"))
        hs = hv.get("steps") or []
        co = [s for s in hs if "actions/checkout" in str(s.get("uses", ""))]
        if len(co) != 1 or (co[0].get("with") or {}).get("persist-credentials") != "false": bad.append("hostile-verify must check the repo out once with persist-credentials: false (it runs the repo's verifier)")
        dl = [s for s in hs if "download-artifact" in str(s.get("uses", "")) and (s.get("with") or {}).get("name") == "hostile-attempts" and (s.get("with") or {}).get("path") == "attempts"]
        if len(dl) != 1: bad.append("hostile-verify must download the artifact hostile-attempts into attempts (without it every verify reads a missing file)")
        if hs and not (co and dl and hs.index(co[0]) < hs.index(dl[0]) < min([hs.index(s) for s in hs if "--attempt" in str(s.get("run", ""))] or [99])): bad.append("hostile-verify steps must run checkout, then the download, then the attempts")
        # one three-line step per attempt, the exit code captured from the verifier's own invocation
        seen = {}
        for s in hv.get("steps") or []:
            run = (s.get("run") or "").strip(); lines = [l.strip() for l in run.splitlines() if l.strip()]
            m = re.search(r"--attempt (\w+)", run)
            if not m: continue
            a = m.group(1); seen[a] = seen.get(a, 0) + 1
            ok = (len(lines) == 3 and lines[0] == "rc=0"
                  and a in PIN and re.fullmatch(PIN[a] + r" 2> \S+ \|\| rc=\$\?", lines[1])
                  and re.fullmatch(r"python3 bin/chain-verify\.py hostile-row --attempt %s --exit-code \"\$rc\" --stderr \S+ --out results/%s\.json" % (a, a), lines[2]))
            if not ok: bad.append("hostile-verify step for %s is not the pinned three-line shape (rc=0; the pinned verifier invocation for this attempt 2> FILE || rc=$?; hostile-row ... --exit-code \"$rc\")" % a)
            e1, e2 = re.search(r"2> (\S+) \|\|", run), re.search(r"--stderr (\S+)", run)
            if not e1 or not e2 or e1.group(1) != e2.group(1): bad.append("hostile-verify step for %s: hostile-row must read the stderr file the verifier wrote" % a)
            if re.search(r"\|\|\s*(true|:|echo|exit\s+0)\b|\becho\b|\bprintf\b|\bcat\b|\btee\b|>\s*results|set \+e", run): bad.append("hostile-verify step for %s swallows or writes the outcome by hand" % a)
        for a in ATT:
            if seen.get(a, 0) != 1: bad.append("hostile-verify has %d steps for attempt %s (need exactly one)" % (seen.get(a, 0), a))
        runs = [(s.get("run") or "").strip() for s in hv.get("steps") or []]
        if "python3 bin/chain-verify.py hostile-collect results --out hostile-results.json" not in runs: bad.append("hostile-verify does not run hostile-collect")
        ups = [s for s in hv.get("steps") or [] if "upload-artifact" in str(s.get("uses", "")) and (s.get("with") or {}).get("name") == "hostile-results"]
        if len(ups) != 1: bad.append("hostile-verify must upload the artifact hostile-results exactly once")
        dls = [s for s in hd.get("steps") or [] if "download-artifact" in str(s.get("uses", "")) and (s.get("with") or {}).get("name") == "hostile-results"]
        if len(dls) != 1: bad.append("hostile-verdict must download the artifact hostile-results (the verdict reads the run's rows, not a checked-out file)")
        if not any((s.get("run") or "").strip() == "python3 bin/chain-verify.py hostile-verdict hostile-results/hostile-results.json" for s in hd.get("steps") or []):
            bad.append("hostile-verdict does not run `python3 bin/chain-verify.py hostile-verdict hostile-results/hostile-results.json`")
        for jn, j in jobs.items():
            if jn in OPEN or jn.startswith("hostile-"): continue
            cond = str(j.get("if", ""))
            if not GATE.match(cond): bad.append("the job %s is not skipped in a dry run (its if: must be exactly ${{ !inputs.dry-run }} or have it as an && conjunct, no ||): %r" % (jn, cond))
        bw = (jobs.get("build") or {}).get("with") or {}
        if bw.get("hostile") != "${{ inputs.dry-run }}": bad.append("release.yml's build call must pass `hostile: ${{ inputs.dry-run }}` (else the hostile step never runs): %s" % bw)
        if "decide" not in jobs: bad.append("release.yml has no `decide` tag job to gate (the patch-tag job must not run in a dry run)")
for f in glob.glob(os.path.join(root, "**/hostile-results*.json"), recursive=True):
    if "/.git/" not in f: bad.append("a hostile-results file is part of the tree (%s): the rows must come from the run" % os.path.relpath(f, root))
sc = os.path.join(root, "bin/chain-hostile-step.sh")
if not os.path.exists(sc): bad.append("bin/chain-hostile-step.sh missing")
else:
    code = "\n".join(re.sub(r"(?<=\s)#.*$", "", l) for l in open(sc).read().splitlines() if not l.lstrip().startswith("#"))
    for a in ATT:
        if not re.search(r"^attempt_%s\(\)\s*\{" % a, code, re.M): bad.append("attempt_%s() is not defined" % a)
        if len(re.findall(r"^\s*attempt_%s\s*$" % a, code, re.M)) != 1: bad.append("attempt_%s is not called exactly once" % a)
    if re.search(r"\b(refused|accepted|outcome|judged_by|exit_code|chain-verify)\b", code): bad.append("the hostile step writes or names an outcome or calls the verifier; only the verify job may")
print("; ".join(bad) or "ok"); sys.exit(1 if bad else 0)
PY
wire() { python3 "$work/wiring.py" "$1" 2>&1; }
wexpect() { local o rc=0; o=$(wire "$3") || rc=$?
  if [ "$1" = ok ] && [ "$rc" = 0 ]; then ok "$2"
  elif [ "$1" = caught ] && [ "$rc" != 0 ]; then ok "$2 (caught: ${o:0:140})"
  else bad "$2 -> ${o:0:400}"; fi; }
sha=$(printf 'a%.0s' $(seq 40))
mk() { # a known-good fixture tree
  local d="$work/$1"; rm -rf "$d"; mkdir -p "$d/.github/workflows" "$d/bin"
  cat > "$d/.github/workflows/stage-build.yml" <<EOF
on: {workflow_call: {inputs: {hostile: {type: boolean}}}}
jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      - name: hostile step
        if: \${{ inputs.hostile }}
        run: bash bin/chain-hostile-step.sh
      - uses: actions/upload-artifact@$sha # v7
        with:
          name: hostile-attempts
          path: attempts
EOF
  { cat <<EOF
on: {workflow_dispatch: {inputs: {dry-run: {type: boolean}}}}
jobs:
  decide:
    if: \${{ github.ref == 'refs/heads/main' && !inputs.dry-run }}
    runs-on: ubuntu-24.04
    steps:
      - run: echo tag
  build:
    uses: ./.github/workflows/stage-build.yml
    with: {hostile: "\${{ inputs.dry-run }}"}
  sign: {needs: build, uses: ./.github/workflows/stage-sign.yml}
  hostile-verify:
    needs: sign
    runs-on: ubuntu-24.04
    permissions: {contents: read}
    steps:
      - uses: actions/checkout@$sha # v7
        with: {persist-credentials: false}
      - uses: actions/download-artifact@$sha # v8
        with: {name: hostile-attempts, path: attempts}
EOF
    for a in mint_sign_cert forge_provenance call_sign_from_other_workflow; do
      cat <<EOF
      - run: |
          rc=0
          python3 bin/chain-verify.py verify --stage sign --record attempts/$a.json --policy policy.json --now "\$NOW" 2> err-$a.txt || rc=\$?
          python3 bin/chain-verify.py hostile-row --attempt $a --exit-code "\$rc" --stderr err-$a.txt --out results/$a.json
EOF
    done
    cat <<EOF
      - run: |
          rc=0
          python3 bin/chain-verify.py sign --check --signer cosign --digests attempts/hand_sign_code.json --build-record attempts/build-collection.json --policy policy.json --out attempts/out-hand_sign_code 2> err-hand_sign_code.txt || rc=\$?
          python3 bin/chain-verify.py hostile-row --attempt hand_sign_code --exit-code "\$rc" --stderr err-hand_sign_code.txt --out results/hand_sign_code.json
EOF
    for a in read_sign_token read_sign_key; do
      kind=token; [ "$a" = read_sign_key ] && kind=key
      cat <<EOF
      - run: |
          rc=0
          python3 bin/chain-verify.py hostile-material --kind $kind --file attempts/$a.txt 2> err-$a.txt || rc=\$?
          python3 bin/chain-verify.py hostile-row --attempt $a --exit-code "\$rc" --stderr err-$a.txt --out results/$a.json
EOF
    done
    cat <<EOF
      - run: python3 bin/chain-verify.py hostile-collect results --out hostile-results.json
      - uses: actions/upload-artifact@$sha # v7
        with: {name: hostile-results, path: hostile-results.json}
  hostile-verdict:
    needs: hostile-verify
    runs-on: ubuntu-24.04
    permissions: {contents: read}
    steps:
      - uses: actions/download-artifact@$sha # v8
        with: {name: hostile-results, path: hostile-results}
      - run: python3 bin/chain-verify.py hostile-verdict hostile-results/hostile-results.json
  promotion:
    if: \${{ !inputs.dry-run }}
    needs: [sign, hostile-verdict]
    uses: ./.github/workflows/stage-promote.yml
EOF
  } > "$d/.github/workflows/release.yml"
  { echo "# makes six attempts; writes raw material only"; for a in $attempts; do printf 'attempt_%s() { :; }\n' "$a"; done; for a in $attempts; do printf 'attempt_%s\n' "$a"; done; } > "$d/bin/chain-hostile-step.sh"
  echo "$d"
}
wexpect ok "fixture: the known-good wiring passes the judge" "$(mk w_good)"
rel() { echo "$1/.github/workflows/release.yml"; }
pymut() { python3 - "$1" "$2" "$3" <<'PY'
import sys
t = open(sys.argv[1]).read(); assert sys.argv[2] in t, "mutation target not found: " + sys.argv[2]
open(sys.argv[1], "w").write(t.replace(sys.argv[2], sys.argv[3], 1))
PY
}
d=$(mk w_nogate); sed -i.bak 's/if: .*inputs.hostile.*/if: true/' "$d/.github/workflows/stage-build.yml"; wexpect caught "wiring: the hostile step is not gated by inputs.hostile" "$d"
d=$(mk w_noup); sed -i.bak 's/hostile-attempts/other/' "$d/.github/workflows/stage-build.yml"; wexpect caught "wiring: attempts are not uploaded for the verifier" "$d"
d=$(mk w_verifyneeds); sed -i.bak 's/    needs: sign$/    needs: build/' "$(rel "$d")"; wexpect caught "wiring: hostile-verify does not need Sign" "$d"
d=$(mk w_verdictneeds); sed -i.bak 's/needs: hostile-verify/needs: build/' "$(rel "$d")"; wexpect caught "wiring: the verdict does not need the verifying job" "$d"
d=$(mk w_noverdict); sed -i.bak 's#hostile-verdict hostile-results/hostile-results.json#true#' "$(rel "$d")"; wexpect caught "wiring: the verdict job does not run hostile-verdict" "$d"
d=$(mk w_verifyidtoken); python3 - "$(rel "$d")" <<'PY'
import sys
t = open(sys.argv[1]).read().replace("permissions: {contents: read}", "permissions: {contents: read, id-token: write}", 1)
open(sys.argv[1], "w").write(t)
PY
wexpect caught "wiring: hostile-verify holds id-token: write (a verifier needs no identity)" "$d"
d=$(mk w_write); sed -i.bak 's/permissions: {contents: read}$/permissions: {contents: read, packages: write}/' "$(rel "$d")"; wexpect caught "wiring: the verify and verdict jobs may write packages in a dry run" "$d"
d=$(mk w_true); sed -i.bak 's/ || rc=\$?/ || true/' "$(rel "$d")"; wexpect caught "wiring: a verifier failure is swallowed with || true (no exit code is captured)" "$d"
d=$(mk w_echo); sed -i.bak 's/ || rc=\$?/ || echo "exit=1"/' "$(rel "$d")"; wexpect caught "wiring: the exit code is replaced by an echoed constant" "$d"
d=$(mk w_static); python3 - "$(rel "$d")" <<'PY'
import sys
t = open(sys.argv[1]).read()
t = t.replace('      - run: python3 bin/chain-verify.py hostile-collect results --out hostile-results.json', '      - run: echo \'{"attempts":[]}\' > hostile-results.json')
open(sys.argv[1], "w").write(t)
PY
wexpect caught "wiring: the results file is written by hand (static rows), not collected from the rows" "$d"
d=$(mk w_missingrow); python3 - "$(rel "$d")" <<'PY'
import re, sys
t = open(sys.argv[1]).read()
t = re.sub(r"      - run: \|\n          rc=0\n(?:(?!      - ).*\n)*?.*--attempt read_sign_key(?:(?!      - ).*\n)*", "", t, count=1)
open(sys.argv[1], "w").write(t)
PY
wexpect caught "wiring: one attempt has no verify step (read_sign_key)" "$d"
d=$(mk w_noexitcode); sed -i.bak 's/--exit-code "\$rc"/--exit-code 1/' "$(rel "$d")"; wexpect caught "wiring: the row is given a constant exit code, not the captured one" "$d"
d=$(mk w_nodownload); python3 - "$(rel "$d")" <<'PY'
import sys
t = open(sys.argv[1]).read()
t = t.replace("      - uses: actions/download-artifact@" + "a" * 40 + " # v8\n        with: {name: hostile-results, path: hostile-results}", "      - run: true", 1)
open(sys.argv[1], "w").write(t)
PY
wexpect caught "wiring: the verdict job does not download the run's hostile-results artifact" "$d"
d=$(mk w_noattdl); python3 - "$(rel "$d")" <<'PY'
import sys
t = open(sys.argv[1]).read()
t = t.replace("      - uses: actions/download-artifact@" + "a" * 40 + " # v8\n        with: {name: hostile-attempts, path: attempts}\n", "", 1)
open(sys.argv[1], "w").write(t)
PY
wexpect caught "wiring: hostile-verify never downloads hostile-attempts (every verify would read a missing file and 'refuse')" "$d"
d=$(mk w_nocheckout); python3 - "$(rel "$d")" <<'PY'
import sys
t = open(sys.argv[1]).read()
t = t.replace("      - uses: actions/checkout@" + "a" * 40 + " # v7\n        with: {persist-credentials: false}\n", "", 1)
open(sys.argv[1], "w").write(t)
PY
wexpect caught "wiring: hostile-verify has no checkout (the repo's verifier is not there to run)" "$d"
d=$(mk w_persist); sed -i.bak 's/{persist-credentials: false}/{persist-credentials: true}/' "$(rel "$d")"; wexpect caught "wiring: hostile-verify checks out with persisted credentials" "$d"
d=$(mk w_nohostile); sed -i.bak 's/    with: {hostile: .*}$/    with: {}/' "$(rel "$d")"; wexpect caught "wiring: the build call does not pass hostile (the hostile step never runs in the dry run)" "$d"
d=$(mk w_pinstage); pymut "$(rel "$d")" "--stage sign --record attempts/forge_provenance" "--stage build --record attempts/forge_provenance"; wexpect caught "wiring: the forge attempt is verified as stage build, not as the Sign stage (pinned invocation)" "$d"
d=$(mk w_pinrec); pymut "$(rel "$d")" "--record attempts/call_sign_from_other_workflow.json --policy" "--record attempts/forge_provenance.json --policy"; wexpect caught "wiring: the sixth case verifies another attempt's material (pinned --record)" "$d"
d=$(mk w_pinpol); pymut "$(rel "$d")" "--stage sign --record attempts/mint_sign_cert.json --policy policy.json" "--stage sign --record attempts/mint_sign_cert.json --policy /dev/null"; wexpect caught "wiring: an attempt is verified against a different policy than the tag's" "$d"
d=$(mk w_pinkind); pymut "$(rel "$d")" "--kind key --file attempts/read_sign_key.txt" "--kind token --file attempts/read_sign_key.txt"; wexpect caught "wiring: the key attempt is judged with the token kind (pinned hostile-material)" "$d"
d=$(mk w_stderr); pymut "$(rel "$d")" "--stderr err-mint_sign_cert.txt" "--stderr other.txt"; wexpect caught "wiring: hostile-row reads a different stderr file than the verifier wrote" "$d"
d=$(mk w_other); python3 - "$(rel "$d")" <<'PY'
import sys
t = open(sys.argv[1]).read() + "  patch-notes:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: gh pr create\n"
open(sys.argv[1], "w").write(t)
PY
wexpect caught "wiring: any other job (patch-notes) without the dry-run gate still runs in a dry run" "$d"
d=$(mk w_okjobs); python3 - "$(rel "$d")" <<'PY'
import sys
t = open(sys.argv[1]).read() + "  rebuild:\n    needs: build\n    uses: ./.github/workflows/stage-reproducibility.yml\n  check:\n    needs: build\n    uses: ./.github/workflows/stage-verify.yml\n"
open(sys.argv[1], "w").write(t)
PY
wexpect ok "wiring: the rebuild and check stages run in a dry run (allowlist: build, sign, rebuild, check, hostile-*)" "$d"
d=$(mk w_tracked); echo '{"attempts":[]}' > "$d/hostile-results.json"; wexpect caught "wiring: a hostile-results.json is checked into the tree" "$d"
d=$(mk w_nodry); sed -i.bak 's/if: .*!inputs.dry-run }}$/if: true/' "$(rel "$d")"; wexpect caught "wiring: the release job (or the tag job) still runs in a dry run" "$d"
d=$(mk w_nodrydecide); sed -i.bak "s/ \&\& !inputs.dry-run//" "$(rel "$d")"; wexpect caught "wiring: the decide (tag) job is not gated by !inputs.dry-run" "$d"
d=$(mk w_orgate); sed -i.bak "s/!inputs.dry-run }}/!inputs.dry-run || true }}/" "$(rel "$d")"; wexpect caught "wiring: a dry-run gate with || true" "$d"
d=$(mk w_noscript); rm "$d/bin/chain-hostile-step.sh"; wexpect caught "wiring: the hostile script is missing" "$d"
d=$(mk w_missatt); sed -i.bak '/^attempt_read_sign_key$/d' "$d/bin/chain-hostile-step.sh"; wexpect caught "wiring: one of the attempts is never called" "$d"
d=$(mk w_missother); sed -i.bak '/^attempt_call_sign_from_other_workflow$/d' "$d/bin/chain-hostile-step.sh"; wexpect caught "wiring: the second-workflow-calls-Sign attempt is never made" "$d"
d=$(mk w_selfgrade); echo 'echo "{\"outcome\": \"refused\"}" > results.json' >> "$d/bin/chain-hostile-step.sh"; wexpect caught "wiring: the hostile step grades itself" "$d"
d=$(mk w_callsverifier); echo 'python3 bin/chain-verify.py verify --record x' >> "$d/bin/chain-hostile-step.sh"; wexpect caught "wiring: the hostile step runs the verifier itself" "$d"
d=$(mk w_comment); echo '# a refused attempt is written by the verifier, not here' >> "$d/bin/chain-hostile-step.sh"; wexpect ok "wiring: the word refused in a comment is fine (comments are not code)" "$d"
wexpect ok "the real repository's hostile wiring (RED until PR 1 implements it)" "$root"
EXPECT=80
echo "pass=$pass fail=$failn"
if [ $((pass + failn)) != "$EXPECT" ]; then echo "FAIL case count $((pass + failn)) != expected $EXPECT (a case was skipped or added)"; exit 1; fi
[ "$failn" = 0 ]
