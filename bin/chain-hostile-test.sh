#!/usr/bin/env bash
# proves: REQ-CHAIN-001-AC5
# The hostile Build step (v0.3.0 rules 52a, 59; owner RATIFIED Oct 9; advisor 0328), static half. The runtime half is the
# GitHub dry run, which must be green and linked in the PR before it merges (the AC says so; no script can check that).
#
# The shape this test assumes (the implementer matches it; anything else is a change to this header first):
#   stage-build.yml: a step `run: bash bin/chain-hostile-step.sh`, gated by `if:` mentioning inputs.hostile, in the Build job,
#       followed by an upload of the artifact `hostile-attempts`. The script makes five attempts as five functions
#       (rule 52a): attempt_mint_sign_cert, attempt_read_sign_token, attempt_read_sign_key, attempt_hand_sign_code,
#       attempt_forge_provenance. It writes only the RAW MATERIAL of each attempt (a file) under attempts/, and never
#       writes an outcome: the words refused/accepted/outcome do not appear in its code, so it cannot grade itself.
#   release.yml: job `hostile-verify` (needs the sign job) runs `python3 bin/chain-verify.py verify` on the forged
#       provenance (a path containing "forged") and records the verifier's own exit code per attempt; job `hostile-verdict`
#       (needs hostile-verify) runs `python3 bin/chain-verify.py hostile-verdict hostile-results.json`. Neither job holds
#       a write permission other than id-token (a dry run cannot publish).
#   hostile-results.json: {"attempts":[{"attempt":<one of the five>,"outcome":"refused"|"accepted","stage":
#       "runner|build|sign|rebuild|check|release","reason":"<at least 8 characters naming the cause>",
#       "judged_by":"verifier","exit_code":<int>}]}. The verdict exits 0 only when all five are present exactly once,
#       outcome refused, exit_code non-zero, judged_by "verifier" (never the hostile step's own report), a real stage and
#       a real reason; anything else exits 1 naming the attempt and the cause.
#   chain-verify.py hostile-verdict RESULTS.json   (the REAL script is run here; there is no inline copy of it)
# Modelled on: this repo's bin/release-patch-wiring-test.sh (YAML-parsing wiring judge) and the spike evidence
# 2026-10-09-harness-witness-spikes-a-c.md:83-100 (the five ways a Build step reaches the signing identity).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cv="$root/bin/chain-verify.py"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
ok()  { pass=$((pass + 1)); echo "ok   $1"; }
bad() { failn=$((failn + 1)); echo "FAIL $1"; }
python3 -c 'import yaml' 2> /dev/null || { echo "FAIL python3 needs PyYAML (apt install python3-yaml)"; exit 1; }
attempts="mint_sign_cert read_sign_token read_sign_key hand_sign_code forge_provenance"
python3 - "$work" $attempts <<'PY'
import copy, json, sys
w, att = sys.argv[1], sys.argv[2:]
def row(a, **k):
    r = {"attempt": a, "outcome": "refused", "stage": "release", "reason": "identity is stage-build.yml, not stage-sign.yml", "judged_by": "verifier", "exit_code": 1}
    r.update(k); return r
good = {"attempts": [row(a) for a in att]}
def save(n, d): json.dump(d, open("%s/%s.json" % (w, n), "w"))
save("good", good)
def mut(n, i, **k):
    m = copy.deepcopy(good); m["attempts"][i].update(k); save(n, m)
mut("accepted_forge", 4, outcome="accepted")
mut("accepted_mint", 0, outcome="accepted")
mut("selfreport", 4, judged_by="hostile-step")
mut("exit0", 1, exit_code=0)
mut("noreason", 0, reason="")
mut("vague", 0, reason="x")
mut("badstage", 2, stage="x")
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
expect ok     "verdict: all five attempts refused by the verifier, each with a stage and a reason" good
expect refuse "verdict: a forged provenance that was ACCEPTED fails the test" accepted_forge "forge_provenance"
expect refuse "verdict: an accepted certificate mint fails the test" accepted_mint "mint_sign_cert"
expect refuse "verdict: an outcome the hostile step graded itself is not evidence" selfreport "verifier"
expect refuse "verdict: a 'refused' outcome with exit code 0 is a contradiction" exit0 "read_sign_token"
expect refuse "verdict: a refusal with no reason" noreason "reason"
expect refuse "verdict: a one-character reason" vague "reason"
expect refuse "verdict: a stage that is not a stage" badstage "stage"
expect refuse "verdict: an empty stage" nostage "stage"
expect refuse "verdict: a missing attempt (read_sign_token)" missing "read_sign_token"
expect refuse "verdict: a duplicated attempt" duplicate "mint_sign_cert"
expect refuse "verdict: an attempt that is not one of the five" extra "alter_output"
expect refuse "verdict: two rows for one attempt and none for another" renamed "read_sign_key"
expect refuse "verdict: no attempts at all" empty "attempt"
expect refuse "verdict: a file that is not JSON" notjson "json"
# ---- the wiring, by parsing the YAML and the script (not by grepping for substrings) ---------------------------------
cat > "$work/wiring.py" <<'PY'
import os, re, sys, yaml
root = sys.argv[1]; bad = []
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
        runs = " ".join(str(s.get("run", "")) for s in hv.get("steps") or [])
        if not re.search(r"python3 bin/chain-verify\.py verify\b.*forged", runs): bad.append("hostile-verify does not run chain-verify.py verify on the forged provenance")
        if "exit" not in runs and "$?" not in runs and "||" not in runs: bad.append("hostile-verify does not record the verifier's own exit code")
        if not any(re.fullmatch(r"python3 bin/chain-verify\.py hostile-verdict \S*hostile-results\.json", (s.get("run") or "").strip()) for s in hd.get("steps") or []):
            bad.append("hostile-verdict does not run `python3 bin/chain-verify.py hostile-verdict hostile-results.json`")
        for jn, j in (("hostile-verify", hv), ("hostile-verdict", hd)):
            perm = j.get("permissions")
            if not isinstance(perm, dict) or any(v == "write" for k, v in perm.items() if k != "id-token"):
                bad.append("%s may write something (a dry run cannot publish): %s" % (jn, perm))
        for jn, j in jobs.items():
            if jn in ("hostile-verify", "hostile-verdict") or not str(j.get("uses", "")).endswith("stage-promote.yml"): continue
            if "dry" not in str(j.get("if", "")) and "hostile" not in str(j.get("if", "")): bad.append("the release job %s is not skipped in a dry run" % jn)
sc = os.path.join(root, "bin/chain-hostile-step.sh")
if not os.path.exists(sc): bad.append("bin/chain-hostile-step.sh missing")
else:
    code = "\n".join(l for l in open(sc).read().splitlines() if not l.lstrip().startswith("#"))
    for a in ("mint_sign_cert", "read_sign_token", "read_sign_key", "hand_sign_code", "forge_provenance"):
        if not re.search(r"^attempt_%s\(\)\s*\{" % a, code, re.M): bad.append("attempt_%s() is not defined" % a)
        if len(re.findall(r"^\s*attempt_%s\s*$" % a, code, re.M)) != 1: bad.append("attempt_%s is not called exactly once" % a)
    if re.search(r"\b(refused|accepted|outcome|judged_by)\b", code): bad.append("the hostile step writes or names an outcome; only the verifier may")
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
  cat > "$d/.github/workflows/release.yml" <<EOF
on: {workflow_dispatch: {}}
jobs:
  build: {uses: ./.github/workflows/stage-build.yml}
  sign: {needs: build, uses: ./.github/workflows/stage-sign.yml}
  hostile-verify:
    needs: sign
    runs-on: ubuntu-24.04
    permissions: {contents: read, id-token: write}
    steps:
      - run: python3 bin/chain-verify.py verify --record attempts/forged-provenance.json || echo "exit=\$?" >> hostile-results.txt
  hostile-verdict:
    needs: hostile-verify
    runs-on: ubuntu-24.04
    permissions: {contents: read}
    steps:
      - run: python3 bin/chain-verify.py hostile-verdict hostile-results.json
  promotion:
    if: \${{ !inputs.dry-run }}
    needs: [sign, hostile-verdict]
    uses: ./.github/workflows/stage-promote.yml
EOF
  { echo "# makes five attempts; writes raw material only"; for a in $attempts; do printf 'attempt_%s() { :; }\n' "$a"; done; for a in $attempts; do printf 'attempt_%s\n' "$a"; done; } > "$d/bin/chain-hostile-step.sh"
  echo "$d"
}
wexpect ok "fixture: the known-good wiring passes the judge" "$(mk w_good)"
d=$(mk w_nogate); sed -i.bak 's/if: .*inputs.hostile.*/if: true/' "$d/.github/workflows/stage-build.yml"; wexpect caught "wiring: the hostile step is not gated by inputs.hostile" "$d"
d=$(mk w_noup); sed -i.bak 's/hostile-attempts/other/' "$d/.github/workflows/stage-build.yml"; wexpect caught "wiring: attempts are not uploaded for the verifier" "$d"
d=$(mk w_verifyneeds); sed -i.bak 's/needs: sign/needs: build/' "$d/.github/workflows/release.yml"; wexpect caught "wiring: hostile-verify does not need Sign" "$d"
d=$(mk w_verdictneeds); sed -i.bak 's/needs: hostile-verify/needs: build/' "$d/.github/workflows/release.yml"; wexpect caught "wiring: the verdict does not need the verifying job" "$d"
d=$(mk w_noforge); sed -i.bak 's/forged-provenance/other/' "$d/.github/workflows/release.yml"; wexpect caught "wiring: the verifier is not run on the forged provenance" "$d"
d=$(mk w_noexit); sed -i.bak 's/ || echo "exit=.*"//' "$d/.github/workflows/release.yml"; wexpect caught "wiring: the verifier's own exit code is not recorded" "$d"
d=$(mk w_noverdict); sed -i.bak 's/hostile-verdict hostile-results.json/true/' "$d/.github/workflows/release.yml"; wexpect caught "wiring: the verdict job does not run hostile-verdict" "$d"
d=$(mk w_write); sed -i.bak 's/permissions: {contents: read}/permissions: {contents: read, packages: write}/' "$d/.github/workflows/release.yml"; wexpect caught "wiring: the verdict job may write packages in a dry run" "$d"
d=$(mk w_nodry); sed -i.bak 's/if: .*!inputs.dry-run.*/if: true/' "$d/.github/workflows/release.yml"; wexpect caught "wiring: the release job still runs in a dry run" "$d"
d=$(mk w_noscript); rm "$d/bin/chain-hostile-step.sh"; wexpect caught "wiring: the hostile script is missing" "$d"
d=$(mk w_missatt); sed -i.bak '/^attempt_read_sign_key$/d' "$d/bin/chain-hostile-step.sh"; wexpect caught "wiring: one of the five attempts is never called" "$d"
d=$(mk w_selfgrade); echo 'echo "{\"outcome\": \"refused\"}" > results.json' >> "$d/bin/chain-hostile-step.sh"; wexpect caught "wiring: the hostile step grades itself" "$d"
d=$(mk w_comment); echo '# a refused attempt is written by the verifier, not here' >> "$d/bin/chain-hostile-step.sh"; wexpect ok "wiring: the word refused in a comment is fine (comments are not code)" "$d"
wexpect ok "the real repository's hostile wiring (RED until PR 1 implements it)" "$root"
EXPECT=31
echo "pass=$pass fail=$failn"
if [ $((pass + failn)) != "$EXPECT" ]; then echo "FAIL case count $((pass + failn)) != expected $EXPECT (a case was skipped or added)"; exit 1; fi
[ "$failn" = 0 ]
