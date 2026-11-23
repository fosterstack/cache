#!/usr/bin/env bash
# proves: REQ-CHAIN-001-AC5
# The hostile Build step (v0.3.0 rules 52a, 59), static and offline half. The runtime half is the signed
# release-candidate (rc) tag run on main, cut after the cutover pull request has merged: it must be green and its run linked before any final
# or patch tag is cut (REQ-CHAIN-001-AC5, accepted Oct 12); no script here can check that, and the marker of REQ-CHAIN-001-AC6 records it.
#
# The shape this test assumes (the implementer matches it; anything else is a change to this header first):
#   stage-build.yml: a step `run: bash bin/chain-hostile-step.sh`, gated by `if:` mentioning inputs.hostile, in the Build job,
#       followed by an upload of the artifact `hostile-attempts`. The script makes exactly five attempts as five functions
#       (the five runtime cases of rule 52a as accepted Oct 12): attempt_mint_sign_cert, attempt_read_sign_token,
#       attempt_read_sign_key, attempt_hand_sign_code, attempt_forge_provenance. The sixth case of the older text (a second workflow
#       calls stage-sign.yml at the tag: it gets Sign's SAN but its Build Config URI is not release.yml; harness spike (b)) is not a
#       runtime case: no second workflow file exists (no workflow sprawl; the AC1 test allows only stage-sign.yml as new). It is
#       judged by Sign's caller check in the static judge and by the offline unit half, chain-verify-test.sh (sign_othercaller), a
#       stated limit of the proof. The script writes only the RAW MATERIAL of each attempt (a file) under attempts/, and never
#       writes an outcome: the words refused/accepted/outcome do not appear in its code, so it cannot grade itself.
#   DRY-RUN REF: production `sign --check` makes the per-tag policy from the template only when
#       GITHUB_REF is refs/tags/vX.Y.Z or refs/tags/vX.Y.Z-rcN (not refs/tags/x, not a branch): chain-verify-test.sh pins those refusals.
#       The dry run is a workflow_dispatch on a BRANCH (or the throwaway hostile-proof/* ref), so `sign --check` has ONE more
#       behaviour, chosen by the run, not by a flag the workflow can add (a workflow_dispatch on a TAG is refused outright, step-8
#       SF-4: production tag runs come from a push): when GITHUB_EVENT_NAME is workflow_dispatch and GITHUB_REF is a branch, the policy is made for THAT ref (`policy make --ref "$GITHUB_REF"`), the written provenance carries
#       "dryRun": true in its predicate and a DRY-RUN marker file sits beside it; any other combination is refused. Release's
#       policy is tag-pinned, so a record whose SAN ref is a branch can NEVER be accepted by Release (a chain-verify-test case).
#       The Sign job's pinned command line is therefore the same in a dry run and a release; no step in Sign can differ.
#       The hostile-verify job makes its policy with `policy make --template .github/policy/release-policy.template.json --ref
#       "$GITHUB_REF" --out policy.json` (pinned) for the run's own ref and judges every attempt, and ONE positive control,
#       against that same policy.json.
#   REACHABILITY: admission is no longer a job (it is the first step of Build's apk
#       job), so `build` has no `needs` and carries `if: ${{ (github.event_name == 'push' && (startsWith(github.ref, 'refs/tags/v') || startsWith(github.ref, 'refs/heads/release/v'))) ||
#       inputs.dry-run == true }}` (the same text on sign, judged by bin/chain-build-wiring-test.sh); a v* tag push or a dry-run dispatch runs
#       it, and `mode` is gone (stage-build.yml has no such input). Without a gate every job of a dry run would be skipped, green with no checks.
#   release.yml: the build caller passes `hostile: ${{ github.event_name == 'push' &&
#       startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}` (an rc-tag PUSH only: never a final tag, a branch or a
#       dispatch; admission and Sign accept exactly vX.Y.Z-rcN, so the contains() is only the cheap gate); job
#       `hostile-verify` (needs the sign job; permissions EXACTLY {contents: read}: no id-token, nothing to write) is an ALLOWLIST
#       of steps, in this order and no others: actions/checkout (persist-credentials: false); actions/download-artifact
#       `hostile-attempts` into attempts (the raw material each attempt made: without it every verify would read a missing file);
#       `witness-build` into witness-build (Build's verified record, the --build-record of hand_sign_code, NOT a file the hostile
#       step supplied); `provenance` into provenance (THIS run's genuine Sign output, for the positive control); the pinned
#       `policy make` line above; then one step per attempt (five) and one POSITIVE CONTROL step (verify --stage sign --record
#       provenance/provenance.json --policy policy.json, without --rekor-stub, must exit 0, recorded as its own row positive_control that
#       the verdict requires to be ACCEPTED: a policy that refuses everything, e.g. made for the wrong ref, is caught here), each
#       exactly three lines:
#           rc=0
#           python3 bin/chain-verify.py <verify|sign|stage-start|hostile-material> ... || rc=$?
#           python3 bin/chain-verify.py hostile-row --attempt <attempt> --exit-code "$rc" --stderr <file> --out results/<attempt>.json
#       (the verifier's OWN exit code, captured per attempt from its own invocation; `|| true`, `|| echo`, echo/printf/cat
#       writing JSON, or a static row fail the wiring judge). The verifier line is PINNED per attempt (the exact subcommand,
#       --stage and material path; policy.json is the per-tag policy; there is NO --now: `verify`'s --now is optional and defaults
#       to the current UTC time like `sign`'s, so no job-level env or step feeds it):
#         mint_sign_cert    verify --stage sign --record attempts/mint_sign_cert.json --policy policy.json
#         read_sign_token   hostile-material --kind token --file attempts/read_sign_token.txt
#         read_sign_key     hostile-material --kind key --file attempts/read_sign_key.txt --policy policy.json
#         hand_sign_code    check-build-record --digests attempts/hand_sign_code.json --build-record witness-build/build-collection.json --policy policy.json
#                           (the same refusals as `sign --check`, with no signer in it: this job holds no id-token and installs no cosign, step-8 SF4)
#         positive_control  verify --stage sign --record provenance/provenance.json --policy policy.json   (must be ACCEPTED;
#                           no --rekor-stub: the stub file is not part of the positive control, and adding it is not the pinned shape)
#         forge_provenance  verify --stage sign --record attempts/forge_provenance.json --policy policy.json
#       A refusal only counts when its stage and cause fit the attempt (the verdict checks): mint_sign_cert -> stage sign|release,
#       cause names the identity or stage-sign.yml; read_sign_token / read_sign_key -> stage runner, `nothing usable`;
#       hand_sign_code -> stage sign, cause digest|format; forge_provenance -> stage sign|release, cause identity|stage-sign.yml|
#       signature|root (NOT the bare word `provenance`: it fits every Sign-stage refusal). A refusal whose
#       reason says the material was missing or unreadable NEVER counts (an attempt that never ran must not read as isolation).
#       ERROR vs REFUSAL: a missing, unreadable or TRANSCRIPT-LESS material file is an ERROR (the token and key files must start with
#       a line `# transcript: <what the attempt tried and how>` of at least 20 characters AND at least one more line (the attempt's
#       own output): `# transcript: tried` alone, or a transcript with no output, is an error, not isolation; hostile-material exits 2 with `error: ...`, hostile-row
#       writes NO row for exit 2 or any stderr whose first line is not `refused at <stage>: <reason>`), so the collect step
#       fails and the dry run is red. then one step `python3 bin/chain-verify.py hostile-collect results
#       --out hostile-results.json` and an upload of the artifact `hostile-results`. Job `hostile-verdict` (needs hostile-verify;
#       permissions {contents: read}) downloads that artifact and runs `python3 bin/chain-verify.py hostile-verdict
#       hostile-results/hostile-results.json`. No hostile-results*.json may be a file of the repository tree (it must come from
#       the run). Every dry-run-gated job (the release caller, the promotion job) has an `if:` that has the conjunct
#       `!inputs.dry-run` and no `||`, so a dry run neither tags nor publishes.
#   No throwaway caller workflow exists any more (the sixth case is not a runtime case); this test makes no exception for one and has no
#       environment-variable bypass: a hostile step that reads a record named hostile-caller is a finding of the wiring judge.
#   Token grading: hostile-material --kind token reads the JWT's payload claims. release.yml is the one release workflow, so its
#       job_workflow_ref names every job; Sign's identity is the environment sign. A token whose sub is exactly
#       repo:<repo>:environment:sign AND whose job_workflow_ref is <repo>/.github/workflows/release.yml@refs/... means the attempt
#       really obtained Sign's identity (exit 0, graded accepted). Any other token is `refused at runner: nothing usable for Sign`:
#       another job of release.yml (another environment, or none), environment sign from another workflow, a look-alike file,
#       repository or environment. A JWT with no job_workflow_ref claim, or no sub claim, is an error (exit 2).
#   Dry-run gating: every hostile-* job has `if: ${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}` exactly; every other job that needs Sign
#       (transitively) has BOTH conjuncts `!inputs.dry-run` and `startsWith(github.ref, 'refs/tags/v')`; Release's policy step
#       (stage-promote.yml) is `policy make --tag ...` and never `--ref` (the only `--ref` in the tree is hostile-verify's), and
#       hostile-verify/hostile-verdict have no job `env`/`defaults`/`container`/`strategy`/`services`/`outputs`/`continue-on-error`,
#       their steps no `shell`/`env`/`working-directory`/`continue-on-error`, and release.yml no top-level `env`/`defaults`.
#   Subcommands (the REAL script is run here; no inline copy):
#       chain-verify.py hostile-row --attempt A --exit-code N --stderr FILE --out OUT.json
#           writes {"attempt","outcome","stage","reason","judged_by":"verifier","exit_code"}: outcome refused when N != 0 and
#           FILE's first line is `refused at <stage>: <reason>` (stage one of runner|build|sign|rebuild|check|release); outcome
#           accepted when N == 0; exit 1 (no row) for a traceback, an empty or unparsable stderr with N != 0, or an unknown attempt.
#       chain-verify.py hostile-collect DIR --out F      merges the six rows (five attempts + positive_control); exit 1 naming a missing, duplicate or extra one.
#       chain-verify.py hostile-material --kind token|key --file F [--policy policy.json]
#           exit 0 when F holds a transcript line and usable material (a token whose claims line says sub environment:sign and job_workflow_ref release.yml; a key file whose public key is the key of Sign's certificate: the step lists `pubkey-sha256: <hex>` per key file found and `searched: <N> files`, N above zero), exit 1 with
#           `refused at runner: nothing usable` when F has the transcript line and no material (the runner VM was isolated, the
#           attempt got nothing); exit 2 with `error: ...` when F is missing, unreadable, empty or has no transcript line (no
#           row); an unknown kind exits 2.
#   chain-verify.py hostile-verdict RESULTS.json   (the REAL script is run here; there is no inline copy of it): the five attempts
#       must be refused with their own stage and cause, AND positive_control must be accepted. The hostile step's two material
#       functions write the transcript line (the code contains `transcript:` twice).
# Modelled on: this repo's bin/chain-release-shape.py (YAML-parsing wiring judge); in-toto-witness cmd/verify.go:211 (a
# verifier's refusal is its exit code and message, not a field the attacker writes); the spike evidence
# 2026-10-09-harness-witness-spikes-a-c.md:83-100 (the five ways a Build step reaches the signing identity).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
export CHAIN_ROOT="$root"                 # the wiring judge loads the shared YAML loader from the real bin/chain-test-signers.py
cv="$root/bin/chain-verify.py"
work=$(mktemp -d); strays=(); trap 'kill ${strays[@]+"${strays[@]}"} 2> /dev/null || true; rm -rf "$work"' EXIT
pass=0 failn=0
ok()  { pass=$((pass + 1)); echo "ok   $1"; }
bad() { failn=$((failn + 1)); echo "FAIL $1"; }
python3 -c 'import yaml' 2> /dev/null || { echo "FAIL python3 needs PyYAML (install the python3-yaml package)"; exit 1; }
attempts="mint_sign_cert read_sign_token read_sign_key hand_sign_code forge_provenance"
python3 - "$work" $attempts <<'PY'
import copy, json, sys
w, att = sys.argv[1], sys.argv[2:]
DEF = {"mint_sign_cert": ("sign", "signature is not the manifest key's (manifest key)"), "read_sign_token": ("runner", "nothing usable"),
       "read_sign_key": ("runner", "nothing usable"), "hand_sign_code": ("sign", "digest list is not sha256 digests (format)"),
       "forge_provenance": ("release", "provenance signature is not the manifest key's (manifest key)")}
def row(a, **k):
    r = {"attempt": a, "outcome": "refused", "stage": DEF.get(a, ("release", "x"))[0], "reason": DEF.get(a, ("release", "identity is stage-build.yml"))[1], "judged_by": "verifier", "exit_code": 1}
    r.update(k); return r
POS = {"attempt": "positive_control", "outcome": "accepted", "stage": "sign", "reason": "ok", "judged_by": "verifier", "exit_code": 0}
good = {"attempts": [row(a) for a in att] + [POS]}
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
mut("wrongcause_forge", 4, reason="digest mismatch")
mut("wrongstage_token", 1, stage="sign")
mut("wrongcause_hand", 3, reason="identity is stage-build.yml")
mut("digestcause_hand", 3, reason="digest list differs from the digests Build attested "
    "(its digest does not match the record's product subject)")
mut("wrongcause_key", 2, reason="no such file attempts/read_sign_key.txt")
mut("wrongcause_mint", 0, reason="digest mismatch")
mut("nostage", 3, stage="")
mut("ctl_refused", 5, outcome="refused", stage="sign", reason="identity is stage-build.yml", exit_code=1)
mut("stage_sign_forge", 4, stage="sign", reason="provenance signature is not the manifest key's (manifest key)")
mut("cross_mint_buildconfig", 0, reason="build config URI is scan.yml; release.yml required")
mut("forge_provdigest", 4, reason="provenance digest mismatch")
mut("forge_provrekor", 4, reason="provenance: rekor entry missing")
mut("forge_sig", 4, reason="signature does not verify")
mut("forge_manifest", 4, reason="the signing key is not the manifest's release key (manifest key)")
mut("missing_and_cause", 0, reason="no such file attempts/mint_sign_cert.json (expected identity stage-sign.yml)")
mut("unreadable_and_cause", 4, reason="cannot read attempts/forge_provenance.json: provenance identity")
m = copy.deepcopy(good); del m["attempts"][5]; save("nocontrol", m)
m = copy.deepcopy(good); del m["attempts"][1]; save("missing", m)
m = copy.deepcopy(good); m["attempts"].append(row("mint_sign_cert")); save("duplicate", m)
m = copy.deepcopy(good); m["attempts"].append(row("alter_output")); save("extra", m)
m = copy.deepcopy(good); m["attempts"][2]["attempt"] = "read_sign_token"; save("renamed", m)
# (REQ-CHAIN-001-AC5) the case list is exactly five names; the sixth, call_sign_from_other_workflow, is not a
# runtime case
m = copy.deepcopy(good); m["attempts"].insert(5, row("call_sign_from_other_workflow")); save("sixth_row", m)
m = copy.deepcopy(good); del m["attempts"][4]; save("missing_forge", m)
m = copy.deepcopy(good); del m["attempts"][3]; save("missing_hand", m)
m = copy.deepcopy(good); del m["attempts"][0]; save("missing_mint", m)
m = copy.deepcopy(good); del m["attempts"][2]; save("missing_key", m)
m = copy.deepcopy(good); m["attempts"].append(row("hand_sign_code2")); save("added_other", m)
m = copy.deepcopy(good); m["attempts"][4]["attempt"] = "call_sign_from_other_workflow"; save("forge_renamed_sixth", m)
save("empty", {"attempts": []})
open(w + "/notjson.json", "w").write("{not json")
PY
run() { python3 "$cv" hostile-verdict "$work/$1.json" 2> "$work/err" > "$work/out" || return $?; }
expect() { # ok|refuse LABEL FILE [word]
  local rc=0; run "$3" || rc=$?
  if [ "$1" = ok ]; then if [ "$rc" = 0 ]; then ok "$2"; else bad "$2 (exit $rc; $(head -c 160 "$work/err" | tr '\n' ' '))"; fi
  else
    if [ "$rc" = 1 ] && ! grep -F -q Traceback "$work/err" && grep -F -q -- "${4:-}" <<< "$(tr 'A-Z' 'a-z' < "$work/err")"; then ok "$2"
    else bad "$2 (exit $rc, wanted 1 with '${4:-}'; $(head -c 160 "$work/err" | tr '\n' ' '))"; fi
  fi
}
[ -f "$cv" ] && ok "bin/chain-verify.py exists" || bad "bin/chain-verify.py does not exist (RED: not implemented yet)"
expect ok     "verdict: all five attempts refused by the verifier, each with a stage and a reason, and the positive control accepted" good
expect ok     "verdict: forge_provenance refused AT STAGE sign (the pinned command is 'verify --stage sign', so its first line is 'refused at sign:') counts" stage_sign_forge
expect refuse "verdict: a forged provenance refused with only the bare word 'provenance' (digest mismatch) does not count (round 6)" forge_provdigest "cause"
expect refuse "verdict: a forged provenance refused 'provenance: rekor entry missing' does not count" forge_provrekor "cause"
expect ok     "verdict: a forged provenance refused for its signature is a fine reason for forge_provenance" forge_sig
expect ok     "verdict: a forged provenance refused because its signing key is not the manifest's release key is a fine reason for forge_provenance" forge_manifest
expect refuse "verdict: the positive control REFUSED (a policy that refuses everything proves nothing) fails the test" ctl_refused "positive_control"
expect refuse "verdict: no positive control row" nocontrol "positive_control"
expect refuse "verdict: mint_sign_cert refused with a 'build config'-only reason does not count" cross_mint_buildconfig "cause"
expect refuse "verdict: a reason that says the file is missing AND names a cause word still does not count (mint)" missing_and_cause "missing"
expect refuse "verdict: a reason that says unreadable AND names a cause word still does not count (forge)" unreadable_and_cause "unreadable"
expect refuse "verdict: a forged provenance that was ACCEPTED fails the test" accepted_forge "forge_provenance"
expect refuse "verdict: an accepted certificate mint fails the test" accepted_mint "mint_sign_cert"
expect refuse "verdict: a row for call_sign_from_other_workflow (the dropped sixth case) is an extra row, refused by name (G2)" sixth_row "call_sign_from_other_workflow"
expect refuse "verdict: a missing record for forge_provenance stays an error, not a skip (G2)" missing_forge "forge_provenance"
expect refuse "verdict: a missing record for hand_sign_code stays an error, not a skip (G2)" missing_hand "hand_sign_code"
expect refuse "verdict: a missing record for mint_sign_cert stays an error, not a skip (G2)" missing_mint "mint_sign_cert"
expect refuse "verdict: a missing record for read_sign_key stays an error, not a skip (G2)" missing_key "read_sign_key"
expect refuse "verdict: a row for any other added case name is refused (the list is exactly the five)" added_other "hand_sign_code2"
expect refuse "verdict: the sixth name in place of forge_provenance is refused, and forge_provenance is missing" forge_renamed_sixth "forge_provenance"
expect refuse "verdict: an outcome the hostile step graded itself is not evidence" selfreport "verifier"
expect refuse "verdict: a 'refused' outcome with exit code 0 is a contradiction" exit0 "read_sign_token"
expect refuse "verdict: a refusal with no reason" noreason "reason"
expect refuse "verdict: a one-character reason" vague "reason"
expect refuse "verdict: a stage that is not a stage" badstage "stage"
expect refuse "verdict: a forged provenance refused for a digest mismatch (not its identity) does not count" wrongcause_forge "cause"
expect refuse "verdict: a token attempt graded at stage sign instead of runner does not count" wrongstage_token "stage"
expect refuse "verdict: hand_sign_code refused for an identity reason (not digest/format) does not count" wrongcause_hand "cause"
expect refuse "verdict: hand_sign_code refused at the attestation check (digest mismatch), not at its format check, \
does not count" digestcause_hand "cause"
expect refuse "verdict: a key attempt refused because the file was missing does not count" wrongcause_key "cause"
expect refuse "verdict: a certificate mint refused for a digest mismatch does not count" wrongcause_mint "cause"
expect refuse "verdict: an empty stage" nostage "stage"
expect refuse "verdict: a missing attempt (read_sign_token)" missing "read_sign_token"
expect refuse "verdict: a duplicated attempt" duplicate "mint_sign_cert"
expect refuse "verdict: an attempt that is not one of the five" extra "alter_output"
expect refuse "verdict: two rows for one attempt and none for another" renamed "read_sign_key"
expect refuse "verdict: no attempts at all" empty "attempt"
expect refuse "verdict: a file that is not JSON" notjson "json"
# ---- hostile-row / hostile-collect / hostile-material (the verifier's own rows; REAL script) -------------------------------
cvx() { local rc=0; python3 "$cv" "$@" 2> "$work/xerr" > "$work/xout" || rc=$?; return $rc; }
xexpect() { # ok|refuse LABEL word -- args...
  local k=$1 l=$2 w=$3; shift 4; local rc=0; cvx "$@" || rc=$?
  if [ "$k" = ok ]; then if [ "$rc" = 0 ]; then ok "$l"; else bad "$l (exit $rc; $(head -c 160 "$work/xerr" | tr '\n' ' '))"; fi
  elif [ "$rc" = 1 ] && ! grep -F -q Traceback "$work/xerr" && grep -F -q -- "$w" <<< "$(tr 'A-Z' 'a-z' < "$work/xerr")"; then ok "$l"
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
xexpect refuse "hostile-row: an attempt that is not one of the five" attempt -- hostile-row --attempt alter_output --exit-code 1 --stderr "$work/e_ref.txt" --out "$work/rows/x3.json"
xexpect refuse "hostile-row: call_sign_from_other_workflow is not an attempt any more (G2)" attempt -- hostile-row --attempt call_sign_from_other_workflow --exit-code 1 --stderr "$work/e_ref.txt" --out "$work/rows/x3b.json"
for a in $attempts; do [ -f "$work/rows/$a.json" ] || python3 "$cv" hostile-row --attempt "$a" --exit-code 1 --stderr "$work/e_ref.txt" --out "$work/rows/$a.json" 2> /dev/null || true; done
python3 "$cv" hostile-row --attempt positive_control --exit-code 0 --stderr "$work/e_empty.txt" --out "$work/rows/positive_control.json" 2> /dev/null || true
xexpect ok "hostile-collect: six rows (five attempts and the positive control) are merged into one results file" - -- hostile-collect "$work/rows" --out "$work/collected.json"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if sorted(r["attempt"] for r in d["attempts"])==sorted(sys.argv[2:]) else 1)' "$work/collected.json" $attempts positive_control && ok "hostile-collect: the merged file has each of the five attempts and the positive control exactly once" || bad "hostile-collect: content"
mkdir -p "$work/rows5"; cp "$work"/rows/*.json "$work/rows5/" 2> /dev/null || true; rm -f "$work/rows5/read_sign_key.json"
xexpect refuse "hostile-collect: a missing row is named" read_sign_key -- hostile-collect "$work/rows5" --out "$work/c5.json"
mkdir -p "$work/rows7"; cp "$work"/rows/*.json "$work/rows7/" 2> /dev/null || true; cp "$work/rows/mint_sign_cert.json" "$work/rows7/zz-dup.json" 2> /dev/null || true
xexpect refuse "hostile-collect: a duplicate row is named" mint_sign_cert -- hostile-collect "$work/rows7" --out "$work/c7.json"
mkdir -p "$work/rows8"; cp "$work"/rows/*.json "$work/rows8/" 2> /dev/null || true
printf '{"attempt":"call_sign_from_other_workflow","outcome":"refused","stage":"release","reason":"build config","judged_by":"verifier","exit_code":1}' > "$work/rows8/call_sign_from_other_workflow.json"
xexpect refuse "hostile-collect: a row for the dropped sixth case is an extra row, named (G2)" call_sign_from_other_workflow -- hostile-collect "$work/rows8" --out "$work/c8.json"
b64u() { printf '%s' "$1" | base64 | tr -d '=\n' | tr '+/' '-_'; }
JH=$(b64u '{"alg":"RS256"}')
RW=fosterstack/cache/.github/workflows/release.yml@refs/tags/v0.3.0
TS=$JH.$(b64u '{"sub":"repo:fosterstack/cache:environment:sign","job_workflow_ref":"'$RW'"}').c2ln
TB=$JH.$(b64u '{"sub":"repo:fosterstack/cache:environment:build","job_workflow_ref":"'$RW'"}').c2ln
TN=$JH.$(b64u '{"sub":"repo"}').c2ln
TNS=$JH.$(b64u '{"job_workflow_ref":"'$RW'"}').c2ln
TR='# transcript: curl "$ACTIONS_ID_TOKEN_REQUEST_URL" with the step token and write the response'
printf '%s\nclaims: %s\n' "$TR" "$TS" > "$work/tok_yes.txt"
printf '%s\nclaims: %s\n' "$TR" "$TB" > "$work/tok_build.txt"
printf '%s\nclaims: %s\n' "$TR" "$TN" > "$work/tok_noclaim.txt"
printf '%s\nclaims: %s\n' "$TR" "$TNS" > "$work/tok_nosub.txt"
printf '%s\ncurl: (6) could not resolve host\n' "$TR" > "$work/tok_none.txt"
: > "$work/mat_empty.txt"; printf 'claims: %s\n' "$TS" > "$work/tok_notranscript.txt"
printf '# transcript: tried\nclaims: %s\n' "$TS" > "$work/tok_shorttr.txt"
printf '%s\n' "$TR" > "$work/tok_tronly.txt"
# KEY material (step-8 SF-3): the step records the sha256 of the PUBLIC key of every key file it found and how many files it searched;
# the verifier compares them with the manifest key of the policy (the one release key Sign signs with) (never by the words PRIVATE KEY)
for k in signk otherk; do openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$work/$k.key" 2> /dev/null; openssl pkey -in "$work/$k.key" -pubout -out "$work/$k.pem" 2> /dev/null; done
kh() { openssl pkey -pubin -in "$1" -outform DER | shasum -a 256 | cut -d' ' -f1; }
H1=$(kh "$work/signk.pem"); H2=$(kh "$work/otherk.pem")
python3 -c 'import json,sys; json.dump({"release_key": {"public_key": open(sys.argv[1]).read()}}, open(sys.argv[2],"w"))' "$work/signk.pem" "$work/keypol.json"
KR='# transcript: searched HOME, RUNNER_TEMP, /tmp and /dev/shm for private key files and recorded the sha256 of each one public key'
printf '%s\nsearched: 42 files\npubkey-sha256: %s\n' "$KR" "$H1" > "$work/key_yes.txt"
printf '%s\nsearched: 42 files\npubkey-sha256: %s\n' "$KR" "$H2" > "$work/key_other.txt"
printf '%s\nsearched: 42 files\n' "$KR" > "$work/key_none.txt"
printf '%s\nsearched: 0 files\n' "$KR" > "$work/key_zero.txt"
printf '%s\npubkey-sha256: %s\n' "$KR" "$H1" > "$work/key_nocount.txt"
KB="-----BEGIN PRIVATE"; KE="-----END PRIVATE"      # the fixture's key block is assembled here, so that no tracked file holds a private-key block (bin/persona-uat-test.sh judges the tree)
printf '%s\nsearched: 42 files\n%s KEY-----\nMIIB\n%s KEY-----\n' "$KR" "$KB" "$KE" > "$work/key_text.txt"
xexpect ok "hostile-material: a token of environment sign from release.yml means the attempt got Sign's identity (exit 0, graded accepted)" - -- hostile-material --kind token --file "$work/tok_yes.txt"
xexpect refuse "hostile-material: another job of release.yml (environment build) is nothing usable for Sign: refused at runner" "refused at runner" -- hostile-material --kind token --file "$work/tok_build.txt"
# Sign's token is exactly sub repo:<repo>:environment:sign AND job_workflow_ref <repo>/.github/workflows/release.yml@<ref> (GITHUB_REPOSITORY, default fosterstack/cache)
W=fosterstack/cache/.github/workflows
SG=repo:fosterstack/cache:environment:sign
TJ=$JH.$(b64u '{"sub":"repo:fosterstack/cache:ref:refs/tags/v0.3.0","job_workflow_ref":"'$RW'"}').c2ln
TW=$JH.$(b64u '{"sub":"'$SG'","job_workflow_ref":"'$W'/other.yml@refs/tags/v0.3.0"}').c2ln
TX=$JH.$(b64u '{"sub":"'$SG'","job_workflow_ref":"'$W'/xrelease.yml@refs/tags/v0.3.0"}').c2ln
TO=$JH.$(b64u '{"sub":"'$SG'","job_workflow_ref":"evil/cache/.github/workflows/release.yml@refs/tags/v0.3.0"}').c2ln
TD=$JH.$(b64u '{"sub":"'$SG'","job_workflow_ref":"'$W'/release.yml.evil@refs/tags/v0.3.0"}').c2ln
TG=$JH.$(b64u '{"sub":"'$SG'r","job_workflow_ref":"'$RW'"}').c2ln
TE=$JH.$(b64u '{"sub":"repo:evil/cache:environment:sign","job_workflow_ref":"'$RW'"}').c2ln
for n in TJ:"another job of release.yml with no environment (sub names a tag ref)" TW:"environment sign from ANOTHER workflow (other.yml)" TX:"a file whose name only ends like Sign's (xrelease.yml)" TO:"release.yml of ANOTHER repository" TD:"release.yml.evil" TG:"environment signer (a sub that only starts like sign)" TE:"environment sign of ANOTHER repository"; do
  v=${n%%:*}; printf '%s\nclaims: %s\n' "$TR" "${!v}" > "$work/tok_$v.txt"
  xexpect refuse "hostile-material: a token with ${n#*:} is nothing usable for Sign: refused at runner" "refused at runner" -- hostile-material --kind token --file "$work/tok_$v.txt"
done
mrc=0; GITHUB_REPOSITORY=other/repo cvx hostile-material --kind token --file "$work/tok_yes.txt" || mrc=$?
if [ "$mrc" = 1 ] && grep -F -q "refused at runner" <<< "$(tr 'A-Z' 'a-z' < "$work/xerr")"; then ok "hostile-material: the repository is read from GITHUB_REPOSITORY: Sign's file of another repository is not this repository's Sign"; else bad "hostile-material: GITHUB_REPOSITORY=other/repo must refuse fosterstack/cache's Sign token, got $mrc"; fi
# a Build job with no id-token permission has no token request address (the Witness move): graded isolated, the static permission judge being the proof and this transcript the corroboration (an incomplete transcript is an error, never isolation)
printf '%s\nrequest-env: absent\n' "$TR" > "$work/tok_absent.txt"
printf '%s\na process on this runner holds a token request address: /proc/9/environ\nrequest-env: absent\n' "$TR" > "$work/tok_absenthold.txt"
xexpect refuse "hostile-material: no token request address in the job, with the corroborating lines, is graded isolated (refused at runner), and the refusal names the static permission judge as the proof" "proven by the static permission judge" -- hostile-material --kind token --file "$work/tok_absent.txt"
for f in tok_absenthold; do
  mrc=0; cvx hostile-material --kind token --file "$work/$f.txt" || mrc=$?
  if [ "$mrc" = 2 ] && grep -F -q "error" <<< "$(tr 'A-Z' 'a-z' < "$work/xerr")" && ! grep -F -q "refused at" "$work/xerr"; then ok "hostile-material: $f (a process holds a token request address) is an ERROR (exit 2), never isolation"; else bad "hostile-material: $f is an error" "exit $mrc"; fi
done
# the REAL step's token attempt in a job with no request address: it writes the absence proof and no claims line (functions only: the cut drops the five calls at the end)
mkdir -p "$work/stepnotok" && sed '/^attempt_mint_sign_cert$/,$d' "$root/bin/chain-hostile-step.sh" > "$work/stepnotok/fns.sh"
(cd "$work/stepnotok" && env -i PATH="$PATH" bash -c '. ./fns.sh; attempt_read_sign_token')
if grep -qx 'request-env: absent' "$work/stepnotok/attempts/read_sign_token.txt" && ! grep -q -e '^environ-read:' -e '^environ-unreadable-same-user:' "$work/stepnotok/attempts/read_sign_token.txt" && ! grep -q '^claims:' "$work/stepnotok/attempts/read_sign_token.txt"; then ok "hostile step: with no token request address in the environment the token attempt writes request-env: absent, no environ line and no claims line"; else bad "hostile step: no-token transcript (got: $(cat "$work/stepnotok/attempts/read_sign_token.txt" 2>&1 | head -c 600 | tr '\n' '|'); proc readable: $([ -r /proc/self/environ ] && echo yes || echo no))"; fi
# the REAL step's token fetch: the request token is in no argv, only in the file hostile-work/token-header that the stand-in for bin/loopback-get.sh reads at call time; the file is gone afterwards
mkdir -p "$work/steptok/bin" && cp "$work/stepnotok/fns.sh" "$work/steptok/fns.sh"
cat > "$work/steptok/bin/loopback-get.sh" <<'STUB'
printf '%s\n' "$@" > argv.log
cat hostile-work/token-header > header-at-call.txt
printf '{"value": "aaa.bbb.ccc"}\n'
STUB
(cd "$work/steptok" && env -i PATH="$PATH" ACTIONS_ID_TOKEN_REQUEST_URL="http://127.0.0.1:9/token?x=1" ACTIONS_ID_TOKEN_REQUEST_TOKEN=SECRETREQUESTTOKEN bash -c '. ./fns.sh; attempt_read_sign_token')
if ! grep -q SECRETREQUESTTOKEN "$work/steptok/argv.log" && grep -qx -e '-H' "$work/steptok/argv.log" && grep -qx '@hostile-work/token-header' "$work/steptok/argv.log" && grep -qx 'http://127.0.0.1:9/token?x=1&audience=sigstore' "$work/steptok/argv.log"; then ok "hostile step: the request token is in no argument of the fetch, which gets -H @hostile-work/token-header and the address with &audience=sigstore"; else bad "hostile step: the fetch argv is $(tr '\n' '|' < "$work/steptok/argv.log")"; fi
if [ "$(cat "$work/steptok/header-at-call.txt" 2> /dev/null)" = "Authorization: bearer SECRETREQUESTTOKEN" ]; then ok "hostile step: at the time of the fetch the file held the line Authorization: bearer <token>"; else bad "hostile step: the file at call time held $(head -c 100 "$work/steptok/header-at-call.txt" 2> /dev/null)"; fi
if [ ! -e "$work/steptok/hostile-work/token-header" ]; then ok "hostile step: the token header file is removed after the step"; else bad "hostile step: hostile-work/token-header is still there"; fi
if grep -qx 'claims: aaa.bbb.' "$work/steptok/attempts/read_sign_token.txt" && ! grep -q SECRETREQUESTTOKEN "$work/steptok/attempts/read_sign_token.txt"; then ok "hostile step: the transcript is unchanged (claims line header.payload., no token)"; else bad "hostile step: transcript $(tr '\n' '|' < "$work/steptok/attempts/read_sign_token.txt" | head -c 200)"; fi
# Linux only (/proc/PID/environ): an UNRELATED process of the same user that denies its environ (dumpable off, as hosted runners have) must not change the grade; a non-dumpable
# ANCESTOR of the step must be an error (it could hide a request variable). Skipped, with an ok line, where there is no /proc.
if [ -r /proc/self/environ ]; then
  mkdir -p "$work/stepproc"
  cp "$work/stepnotok/fns.sh" "$work/stepproc/fns.sh"
  python3 -c 'import ctypes, time; ctypes.CDLL(None).prctl(4, 0); time.sleep(40)' & unrel=$!
  # a stray holder of a request address in its own session, outside the step's tree (another job's leftover, or another test on a shared box)
  setsid bash -c 'ACTIONS_ID_TOKEN_REQUEST_TOKEN=x exec sleep 40' & stray=$!; strays+=("$stray")
  sleep 1
  (cd "$work/stepproc" && env -i PATH="$PATH" HOME="$work" bash -c '. ./fns.sh; attempt_read_sign_token')
  kill "$unrel" 2> /dev/null || true
  # grade a copy without the holder lines: the step runs under env -i, so no holder is in this test's tree, and a stray on a shared box must not change the grade (the grading of a holder is covered by tok_absenthold)
  grep -v 'holds a token request address' "$work/stepproc/attempts/read_sign_token.txt" > "$work/stepproc/graded.txt"
  mrc=0; cvx hostile-material --kind token --file "$work/stepproc/graded.txt" || mrc=$?
  # the step keeps the first 5 holder lines (head -5): with 5 or more other holders on a shared box (b) and (c) can be cut off, a false failure and never a false pass
  # (b) the stray is a real holder: the runner scan lists it, so the step's scan is not narrowed
  if grep -qx "a process on this runner holds a token request address: /proc/$stray/environ" "$work/stepproc/attempts/read_sign_token.txt"; then ok "hostile step (Linux): the real scan lists a holder outside the step's tree (the runner scan is not narrowed)"; else bad "hostile step (Linux): the real scan did not list the stray holder /proc/$stray/environ"; fi
  kill "$stray" 2> /dev/null || true
  if [ "$mrc" = 1 ] && grep -F -q "static permission judge" <<< "$(tr 'A-Z' 'a-z' < "$work/xerr")"; then ok "hostile step (Linux): an unrelated same-user process that denies its environ leaves the grade isolated"; else bad "hostile step (Linux): unrelated non-dumpable process: rc $mrc, transcript $(tr '\n' '|' < "$work/stepproc/attempts/read_sign_token.txt" | head -c 400), err $(head -c 200 "$work/xerr")"; fi
  # (c) a holder inside the step's own tree (a child of the step's shell that holds the address in its environment) is listed by its PID and the transcript is an error
  mkdir -p "$work/steptree"; cp "$work/stepnotok/fns.sh" "$work/steptree/fns.sh"
  (cd "$work/steptree" && env -i PATH="$PATH" HOME="$work" bash -c '. ./fns.sh; ACTIONS_ID_TOKEN_REQUEST_URL=x sleep 30 & echo $! > child.pid; sleep 0.5; attempt_read_sign_token; kill $(cat child.pid) 2> /dev/null')
  mrc=0; cvx hostile-material --kind token --file "$work/steptree/attempts/read_sign_token.txt" || mrc=$?
  if [ "$mrc" = 2 ] && grep -qx "a process on this runner holds a token request address: /proc/$(cat "$work/steptree/child.pid")/environ" "$work/steptree/attempts/read_sign_token.txt"; then ok "hostile step (Linux): a holder inside the step's own tree is listed by its PID and the transcript is an error (exit 2)"; else bad "hostile step (Linux): a holder in the step's tree: rc $mrc, transcript $(tr '\n' '|' < "$work/steptree/attempts/read_sign_token.txt" | head -c 200)"; fi
  mkdir -p "$work/stepanc"; cp "$work/stepnotok/fns.sh" "$work/stepanc/fns.sh"
  (cd "$work/stepanc" && env -i PATH="$PATH" HOME="$work" python3 -c 'import ctypes, subprocess; ctypes.CDLL(None).prctl(4, 0); subprocess.run(["bash", "-c", ". ./fns.sh; attempt_read_sign_token"])')
  grep -v 'holds a token request address' "$work/stepanc/attempts/read_sign_token.txt" > "$work/stepanc/graded.txt"
  mrc=0; cvx hostile-material --kind token --file "$work/stepanc/graded.txt" || mrc=$?
  if [ "$mrc" = 1 ] && ! grep -q '^environ' "$work/stepanc/attempts/read_sign_token.txt"; then ok "hostile step (Linux): a non-dumpable ancestor of the step changes nothing (no environ line; the grade stays isolated, the static permission judge being the proof)"; else bad "hostile step (Linux): non-dumpable ancestor: rc $mrc, transcript $(tr '\n' '|' < "$work/stepanc/attempts/read_sign_token.txt" | head -c 400)"; fi
else
  ok "hostile step (Linux fixtures): skipped, this system has no /proc"
  ok "hostile step (Linux fixtures): skipped, this system has no /proc (ancestor case)"
fi
# the REAL step's mint and forge attempts in a job with no token: both leave material (a record signed by a throwaway key), the REAL verifier refuses it at Sign naming stage-sign.yml,
# and hostile-row turns that refusal into a counted row (a missing file would be an error, which is what the old cosign form produced without a token)
mkdir -p "$work/stepsign" && sed '/^attempt_mint_sign_cert$/,$d' "$root/bin/chain-hostile-step.sh" > "$work/stepsign/fns.sh"
printf 'attempt_mint_sign_cert\nattempt_forge_provenance\n' >> "$work/stepsign/fns.sh"
(cd "$work/stepsign" && env -i PATH="$PATH" HOME="$work" bash fns.sh > /dev/null 2>&1)
# the policy needs a key manifest: made here with a throwaway root key and release key, since the committed
# manifest is the owner's
mkdir -p "$work/keys"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$work/keys/root.key" 2> /dev/null && openssl pkey -in "$work/keys/root.key" -pubout -out "$work/keys/release-key-root.pub" \
  && openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$work/keys/rel.key" 2> /dev/null && openssl pkey -in "$work/keys/rel.key" -pubout -out "$work/keys/rel.pub" \
  && python3 - "$work/keys" <<'PY' && openssl dgst -sha256 -sign "$work/keys/root.key" -out "$work/keys/sig.der" "$work/keys/release-key-manifest.json" \
  && python3 -c 'import base64,sys; sys.stdout.write(base64.b64encode(open(sys.argv[1], "rb").read()).decode() + "\n")' "$work/keys/sig.der" > "$work/keys/release-key-manifest.sig" \
  || { bad "hostile step (Sign refusals): the throwaway key manifest could not be made"; }
import hashlib, json, subprocess, sys
d = sys.argv[1]
der = subprocess.run(["openssl", "pkey", "-pubin", "-in", d + "/rel.pub", "-outform", "DER"], capture_output=True, check=True).stdout
json.dump({"public_key": open(d + "/rel.pub").read(), "key_id": hashlib.sha256(der).hexdigest(), "valid_from": "2026-01-01T00:00:00Z"}, open(d + "/release-key-manifest.json", "w"), sort_keys=True, indent=1)
PY
for f in release-policy.template.json sigstore-trust.json rekor.pub; do cp "$root/.github/policy/$f" "$work/keys/$f"; done
prc=0; (cd "$work/stepsign" && python3 "$root/bin/chain-verify.py" policy make --template "$work/keys/release-policy.template.json" --ref refs/tags/v0.3.0-rc1 --out policy.json 2> policy-make.err > /dev/null) || prc=$?
[ "$prc" = 0 ] && [ -s "$work/stepsign/policy.json" ] || bad "hostile step (Sign refusals): policy make failed (exit $prc: $(head -c 200 "$work/stepsign/policy-make.err" 2> /dev/null | tr '\n' ' '))"
for a in mint_sign_cert forge_provenance; do
  vrc=0; (cd "$work/stepsign" && python3 "$root/bin/chain-verify.py" verify --stage sign --record "attempts/$a.json" --policy policy.json 2> "$a.err") || vrc=$?
  hrc=0; (cd "$work/stepsign" && mkdir -p results && python3 "$root/bin/chain-verify.py" hostile-row --attempt "$a" --exit-code "$vrc" --stderr "$a.err" --out "results/$a.json" > /dev/null 2>&1) || hrc=$?
  if [ -s "$work/stepsign/attempts/$a.json" ] && [ "$vrc" = 1 ] && grep -q "refused at sign" "$work/stepsign/$a.err" && grep -q "manifest key" "$work/stepsign/$a.err" && [ "$hrc" = 0 ] && [ -s "$work/stepsign/results/$a.json" ]; then ok "hostile step: the real $a attempt leaves a throwaway-key record without any token, the real verifier refuses it at sign naming stage-sign.yml, and hostile-row counts the refusal"; else bad "hostile step: $a material and refusal" "verify rc $vrc, row rc $hrc, $(head -c 200 "$work/stepsign/$a.err" 2>&1)"; fi
done
xexpect ok "hostile-material: a key found on the runner whose public key IS the policy's release key means the attempt got Sign's key" - -- hostile-material --kind key --file "$work/key_yes.txt" --policy "$work/keypol.json"
xexpect refuse "hostile-material: a key found on the runner that is NOT Sign's key is nothing usable for Sign: refused at runner" "refused at runner" -- hostile-material --kind key --file "$work/key_other.txt" --policy "$work/keypol.json"
xexpect refuse "hostile-material: a search that looked at files and found no key is refused at runner" "refused at runner" -- hostile-material --kind key --file "$work/key_none.txt" --policy "$work/keypol.json"
xexpect refuse "hostile-material: the TEXT 'PRIVATE KEY' proves nothing: text of a key block with no matching public key hash is refused" "refused at runner" -- hostile-material --kind key --file "$work/key_text.txt" --policy "$work/keypol.json"
xexpect refuse "hostile-material: an unknown kind" kind -- hostile-material --kind password --file "$work/tok_none.txt"
for f in mat_empty tok_notranscript tok_noclaim tok_nosub tok_shorttr tok_tronly tok_none; do
  mrc=0; cvx hostile-material --kind token --file "$work/$f.txt" || mrc=$?
  if [ "$mrc" = 2 ] && grep -F -q "error" <<< "$(tr 'A-Z' 'a-z' < "$work/xerr")" && ! grep -F -q "refused at" "$work/xerr"; then ok "hostile-material: $f (empty, no transcript, a one-word transcript, a transcript with no output, no claims line, a JWT without job_workflow_ref, or a JWT without sub) is an ERROR (exit 2), never isolation"; else bad "hostile-material: $f must exit 2 with error:, got $mrc: $(head -c 120 "$work/xerr" | tr '\n' ' ')"; fi
done
for f in key_zero key_nocount mat_empty; do
  mrc=0; cvx hostile-material --kind key --file "$work/$f.txt" --policy "$work/keypol.json" || mrc=$?
  if [ "$mrc" = 2 ] && grep -F -q "error" <<< "$(tr 'A-Z' 'a-z' < "$work/xerr")" && ! grep -F -q "refused at" "$work/xerr"; then ok "hostile-material: key file $f (a search of zero files, no count of files searched, or an empty file) is an ERROR (exit 2): an empty search proves nothing"; else bad "hostile-material: key file $f must exit 2 with error:, got $mrc: $(head -c 120 "$work/xerr" | tr '\n' ' ')"; fi
done
mrc=0; cvx hostile-material --kind key --file "$work/key_yes.txt" || mrc=$?
if [ "$mrc" = 2 ] && grep -F -q "policy" <<< "$(tr 'A-Z' 'a-z' < "$work/xerr")"; then ok "hostile-material: a key cannot be graded without the policy (--policy): an error, exit 2"; else bad "hostile-material: key without --policy must exit 2, got $mrc"; fi
mrc=0; cvx hostile-material --kind key --file "$work/key_yes.txt" --policy "$work/does-not-exist.json" || mrc=$?
if [ "$mrc" = 2 ] && grep -F -q "error" <<< "$(tr 'A-Z' 'a-z' < "$work/xerr")"; then ok "hostile-material: an unreadable policy is an error (exit 2), never a refusal"; else bad "hostile-material: unreadable sign record must exit 2, got $mrc"; fi
mrc=0; cvx hostile-material --kind token --file "$work/does-not-exist.txt" || mrc=$?
if [ "$mrc" = 2 ] && grep -F -q "error" <<< "$(tr 'A-Z' 'a-z' < "$work/xerr")" && ! grep -F -q "refused at" "$work/xerr"; then ok "hostile-material: a MISSING file is an error (exit 2, no 'refused at' line), never a refusal"; else bad "hostile-material: missing file must exit 2 with error:, got $mrc: $(head -c 120 "$work/xerr" | tr '\n' ' ')"; fi
printf 'error: cannot read attempts/read_sign_token.txt\n' > "$work/e_err.txt"; printf 'usage: chain-verify.py hostile-material [-h] --kind {token,key} --file FILE\n' > "$work/e_usage.txt"
xexpect refuse "hostile-row: exit 2 with an 'error:' first line writes no row (an attempt that never ran is not isolation)" "refused at" -- hostile-row --attempt read_sign_token --exit-code 2 --stderr "$work/e_err.txt" --out "$work/rows/x9.json"
xexpect refuse "hostile-row: exit 2 with a 'usage:' message (argparse) writes no row" "refused at" -- hostile-row --attempt read_sign_token --exit-code 2 --stderr "$work/e_usage.txt" --out "$work/rows/x10.json"
[ ! -e "$work/rows/x9.json" ] && [ ! -e "$work/rows/x10.json" ] && ok "hostile-row: neither failed call left a row file behind" || bad "hostile-row: a row file exists for an error"
# (REQ-CHAIN-001-AC5) a refusal because the material was missing or unreadable never counts: hostile-row exits
# non-zero and
# writes NO row, by the same word list the verdict uses (chain_hostile.MISSING / UNREAD, one list)
n=0
for reason in "record missing or unreadable: nonexistent" "cannot read attempts/x.json" "no such file or directory: attempts/x.json" "unreadable record" "attempts/x.json does not exist" "the record was not found" "permission denied: attempts/x.json" "Record MISSING"; do
  n=$((n + 1)); printf 'refused at sign: %s\n' "$reason" > "$work/e_m$n.txt"; rm -f "$work/rows/m$n.json"
  xexpect refuse "hostile-row: a refusal for missing or unreadable material ($reason) is an error" "missing" -- hostile-row --attempt mint_sign_cert --exit-code 1 --stderr "$work/e_m$n.txt" --out "$work/rows/m$n.json"
  [ ! -e "$work/rows/m$n.json" ] && ok "hostile-row: no row file for ($reason)" || bad "hostile-row: a row file was written for ($reason)"
done
rm -f "$work/rows/m_nofile.json"; xexpect refuse "hostile-row: a missing stderr file is an error (exit 1)" "stderr" -- hostile-row --attempt mint_sign_cert --exit-code 1 --stderr "$work/no-such-stderr.txt" --out "$work/rows/m_nofile.json"
[ ! -e "$work/rows/m_nofile.json" ] && ok "hostile-row: no row file for a missing stderr file (exit 1)" || bad "hostile-row: a row file was written for a missing stderr file"
rm -f "$work/rows/m_nofile0.json"; xexpect refuse "hostile-row: a missing stderr file is an error even with exit 0" "stderr" -- hostile-row --attempt positive_control --exit-code 0 --stderr "$work/no-such-stderr.txt" --out "$work/rows/m_nofile0.json"
[ ! -e "$work/rows/m_nofile0.json" ] && ok "hostile-row: no row file for a missing stderr file (exit 0)" || bad "hostile-row: a row file was written for a missing stderr file (exit 0)"
: > "$work/e_m_empty.txt"; rm -f "$work/rows/m_empty.json"
xexpect refuse "hostile-row: an empty stderr with exit 1 is an error" "stage" -- hostile-row --attempt mint_sign_cert --exit-code 1 --stderr "$work/e_m_empty.txt" --out "$work/rows/m_empty.json"
[ ! -e "$work/rows/m_empty.json" ] && ok "hostile-row: no row file for an empty stderr" || bad "hostile-row: a row file was written for an empty stderr"
printf 'refused at sign: identity \xff\xfe is not stage-sign.yml\n' > "$work/e_m_bin.txt"; rm -f "$work/rows/m_bin.json"
xexpect refuse "hostile-row: a stderr that is not UTF-8 is an error" "utf-8" -- hostile-row --attempt mint_sign_cert --exit-code 1 --stderr "$work/e_m_bin.txt" --out "$work/rows/m_bin.json"
[ ! -e "$work/rows/m_bin.json" ] && ok "hostile-row: no row file for a non-UTF-8 stderr" || bad "hostile-row: a row file was written for a non-UTF-8 stderr"
printf 'refused at sign: identity stage-build.yml is not stage-sign.yml\n' > "$work/e_m_good.txt"; rm -f "$work/rows/m_good.json"
xexpect ok "hostile-row: control: a genuine refusal still writes its row" - -- hostile-row --attempt mint_sign_cert --exit-code 1 --stderr "$work/e_m_good.txt" --out "$work/rows/m_good.json"
[ -s "$work/rows/m_good.json" ] && ok "hostile-row: control: the genuine refusal's row file exists" || bad "hostile-row: control: no row for a genuine refusal"
rm -f "$work"/rows/m*.json
# ---- the wiring, by parsing the YAML and the script (not by grepping for substrings) ---------------------------------
cat > "$work/wiring.py" <<'PY'
import glob, os, re, sys, yaml
root = sys.argv[1]; bad = []
ATT = ["mint_sign_cert", "read_sign_token", "read_sign_key", "hand_sign_code", "forge_provenance"]   # exactly five (G2, advisor Oct 12)
PIN = {
 "mint_sign_cert": r'python3 bin/chain-verify\.py verify --stage sign --record attempts/mint_sign_cert\.json --policy policy\.json',
 "read_sign_token": r'python3 bin/chain-verify\.py hostile-material --kind token --file attempts/read_sign_token\.txt',
 "read_sign_key": r'python3 bin/chain-verify\.py hostile-material --kind key --file attempts/read_sign_key\.txt --policy policy\.json',
 "hand_sign_code": r'python3 bin/chain-verify\.py check-build-record --digests attempts/hand_sign_code\.json --build-record witness-build/build-collection\.json --policy policy\.json',
 "positive_control": r'python3 bin/chain-verify\.py verify --stage sign --record provenance/provenance\.json --policy policy\.json',
 "forge_provenance": r'python3 bin/chain-verify\.py verify --stage sign --record attempts/forge_provenance\.json --policy policy\.json',
}
TAGCONJ = "startsWith(github.ref, 'refs/tags/v')"
WFREF = "startsWith(github.workflow_ref, format('{0}/.github/workflows/release.yml@', github.repository))"
PUSHCONJ = "github.event_name == 'push'"
# the hostile proof runs on a PUSH of a release-candidate tag only (REQ-CHAIN-001-AC5): never on a final tag, never on a branch
RC_IF = "${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}"
def conj(cond):
    """The && conjuncts of a `${{ ... }}` condition, whitespace-normalised, or None when it has a `||` (fail closed: an or-joined
    condition proves nothing about either side). A conjunct must be EXACTLY the wanted text: `!startsWith(...)` and
    `startsWith(...) == false` are different conjuncts (Opus r5 SF-B)."""
    m = re.fullmatch(r"\$\{\{\s*(.*?)\s*\}\}", cond.strip(), re.S)
    if not m: return None
    # whitespace is collapsed FIRST, then the text is split on && and every conjunct must be exactly an
    # accepted item: the one grouped or-condition allowed is patch-failed's exact group, and only as a whole
    # conjunct, so `! (group)`, `(group) == false`, `format(group)` and
    # any other `||` or grouping make the whole condition refused
    GRP = "(contains(needs.*.result, 'failure') || needs.release.result == 'cancelled')"
    flat = re.sub(r"\s+", " ", m.group(1)).strip()
    if re.search(r"TAGCALL|FAILCALL|ALWAYSCALL|RCCALL|FAILGRP|WFREFCALL|DASHCALL", flat): return None   # the placeholder words below are never part of a condition
    out = []
    for part in flat.split("&&"):
        part = part.strip()
        if part == GRP: out.append(part); continue
        if "||" in part: return None
        # the ONLY parentheses allowed are those of the exact startsWith(...) call; any other
        # grouping (`!( a && b )`) changes what the conjuncts mean, so it fails closed
        body = re.sub(r"startsWith\(\s*github\.ref\s*,\s*'refs/tags/v'\s*\)", "TAGCALL", part)
        # the exact status functions `failure()` and `always()` (no arguments, no grouping) are also allowed, because
        # patch-failed must run after a failed stage; they are status checks, not groupings, so they cannot negate or hide a conjunct
        body = re.sub(r"(?<![\w.])failure\(\)", "FAILCALL", body)
        body = re.sub(r"(?<![\w.])always\(\)", "ALWAYSCALL", body)
        # the exact rc-tag test is also one allowed call: a jobs's `!contains(github.ref_name, '-rc')`
        # conjunct keeps an rc tag out of the old publishing path
        body = re.sub(r"contains\(\s*github\.ref_name\s*,\s*'-rc'\s*\)", "RCCALL", body)
        # guard S of release.yml (REQ-CHAIN-005-AC5): the exact call that ties a job to release.yml itself, and the candidate rule of the jobs after the signatures
        body = re.sub(r"startsWith\(\s*github\.workflow_ref\s*,\s*format\(\s*'\{0\}/\.github/workflows/release\.yml@'\s*,\s*github\.repository\s*\)\s*\)", "WFREFCALL", body)
        body = re.sub(r"contains\(\s*github\.ref_name\s*,\s*'-'\s*\)", "DASHCALL", body)
        if "(" in body or ")" in body: return None
        out.append(body.replace("TAGCALL", TAGCONJ).replace("FAILCALL", "failure()").replace("ALWAYSCALL", "always()").replace("RCCALL", "contains(github.ref_name, '-rc')").replace("WFREFCALL", WFREF).replace("DASHCALL", "contains(github.ref_name, '-')"))
    return out
# the jobs that may run in a dry run or on a release branch: Build and Rebuild (gate G is on build-freeze), check-govulncheck, check (the tests run on Build's unsigned build, before Sign) and the persona leg (its own condition asks for a push of a release branch); every other job is skipped through its needs or carries its own gate
OPEN = {"build-freeze", "build-apk", "build-assemble", "rebuild-apk", "rebuild-assemble", "check-govulncheck", "check", "persona-uat-rc"}
SIGN_JOBS = ("sign", "sign-rebuild", "sign-check", "sign-release")      # the four jobs of the environment sign (ruling 1 of cache#921); sign-tag is NOT one of them: it is a tag job, below
# the automatic patch release's inline tag jobs (REQ-REL-009): decide runs on main only (a push or the schedule of release.yml itself) and nowhere else; the three after it run only when decide named a tag
DECIDE_IF = "${{ inputs.mode != 'snapshot' && github.ref == 'refs/heads/main' && github.event_name != 'workflow_dispatch' && !inputs.dry-run && " + WFREF + " }}"
TAG_DUE_IF = "${{ needs.decide.outputs.tag != '' }}"
TAG_JOBS = {"decide": ([], DECIDE_IF), "sign-tag": (["decide"], TAG_DUE_IF), "cut": (["decide", "sign-tag"], TAG_DUE_IF), "patch-notes": (["decide", "cut"], TAG_DUE_IF)}
# check-govulncheck has no needs and runs in a dry run: its ref guard keeps it off in a run on main (push or schedule), where only the tag jobs may run
CGV_IF = "${{ inputs.mode != 'snapshot' && ((github.event_name == 'push' && (startsWith(github.ref, 'refs/tags/v') || startsWith(github.ref, 'refs/heads/release/v'))) || inputs.dry-run == true) }}"
norm = lambda s: re.sub(r"\s+", " ", str(s)).strip()
CHECK_IF = "${{ inputs.mode != 'snapshot' }}"      # the Check jobs carry exactly this (REQ-CHAIN-005-AC5)
POLICY_MAKE = r'python3 bin/chain-verify\.py policy make --template \.github/policy/release-policy\.template\.json --ref "\$GITHUB_REF" --out policy\.json'
WITH = lambda s: s.get("with") or {}
import importlib.util as _ilu
_spec = _ilu.spec_from_file_location("chain_test_signers", os.path.join(os.environ["CHAIN_ROOT"], "bin/chain-test-signers.py"))
_cts = _ilu.module_from_spec(_spec); _spec.loader.exec_module(_cts)   # the ONE duplicate-refusing loader of the chain test judges
def load(rel):
    p = os.path.join(root, rel)
    if not os.path.exists(p): return None
    try: return _cts.yload(open(p).read())
    except (yaml.YAMLError, _cts.DuplicateKey) as ex:
        print("%s cannot be judged: %s" % (rel, ex)); sys.exit(1)
rl = load(".github/workflows/release.yml")
# Run lines the judge reads are judged as bash reads them (refuse, never model): a backslash-newline, or
# any character outside printable ASCII (CR, tab, other controls, NBSP, U+200B, ...), would let str.strip() or a line split see text
# that bash does not run. Checked on every step this judge reads: the hostile step of release.yml and the hostile-* jobs of release.yml.
def run_chars(where, steps):
    for st in steps or []:
        r = st.get("run") if isinstance(st, dict) else None
        if not isinstance(r, str): continue
        if "\\\n" in r: bad.append("%s has a run line with a backslash-newline continuation: %r" % (where, r[:80]))
        if re.search(r"[^\x20-\x7e\n]", r): bad.append("%s has a run line with a control, non-ASCII or invisible character: %r" % (where, r[:80]))
for _jn, _j in ((rl or {}).get("jobs") or {}).items():
    run_chars("release.yml job " + _jn, [x for x in (_j or {}).get("steps") or [] if isinstance(x, dict) and "chain-hostile-step" in str(x.get("run", ""))])
for _jn in ("hostile-verify", "hostile-verdict"):
    run_chars("release.yml job " + _jn, (((rl or {}).get("jobs") or {}).get(_jn) or {}).get("steps"))
# REQ-CHAIN-004-AC19: the hostile Build step runs in EVERY build (release candidate, final or patch tag, the pull-request proof build, the nightly build): the one step `bash bin/chain-hostile-step.sh` of the job
# build-assemble, with no condition of any kind, and an upload of hostile-attempts after it in the same job; the outcome is judged by the verifier (REQ-CHAIN-001-AC5), and release.yml has no input hostile
found = False
for jn, j in ((rl or {}).get("jobs") or {}).items():
    steps = j.get("steps") or []
    for i, s in enumerate(steps):
        if (s.get("run") or "").strip() == "bash bin/chain-hostile-step.sh":
            found = True
            if jn != "build-assemble": bad.append("the hostile step is in the job %s: it is the one step of the job build-assemble (the job that makes the build's records)" % jn)
            if "if" in s: bad.append("the hostile step carries an if: (%r): it runs in every build, with no condition (REQ-CHAIN-004-AC19)" % s.get("if"))
            later = [x for x in steps[i + 1:] if "upload-artifact" in str(x.get("uses", "")) and (x.get("with") or {}).get("name") == "hostile-attempts"]
            if not later: bad.append("no upload of the artifact hostile-attempts after the hostile step in the same job")
if rl is not None and not found: bad.append("no step `bash bin/chain-hostile-step.sh` in the job build-assemble")
if rl is not None and ("hostile" in ((((rl.get("on") or {}).get("workflow_call") or {}).get("inputs")) or {}) or "inputs.hostile" in str(rl)):
    bad.append("release.yml has an input `hostile` or reads inputs.hostile: the hostile step runs in every build, a switch for it is a way to turn it off")
if rl is None: bad.append("release.yml missing")
else:
    jobs = rl.get("jobs") or {}
    if "workflow_dispatch" not in (rl.get("on") or {}): bad.append("release.yml has no workflow_dispatch (the dry run)")
    # final batch R-d: among jobs named hostile* or sign* (any case) only sign, sign-rebuild (the Witness move: Sign's second call, for Rebuild's records), sign-check (the third call, for Check's records), sign-release (the fourth, after Release publishes), hostile-verify and hostile-verdict may exist
    for _jn in jobs:
        if str(_jn).lower().startswith(("hostile", "sign")) and _jn not in SIGN_JOBS + ("hostile-verify", "hostile-verdict") + tuple(TAG_JOBS):
            bad.append("release.yml has a job %r: among hostile*/sign* jobs only sign, sign-rebuild, sign-check, sign-release, hostile-verify, hostile-verdict and the tag job sign-tag are allowed" % _jn)
    hv, hd = jobs.get("hostile-verify"), jobs.get("hostile-verdict")
    if not hv or not hd: bad.append("jobs hostile-verify and hostile-verdict are required")
    else:
        need = lambda j: [j.get("needs")] if isinstance(j.get("needs"), str) else (j.get("needs") or [])
        sign_jobs = [n for n in jobs if n in SIGN_JOBS]
        if not sign_jobs or not set(need(hv)) & set(sign_jobs): bad.append("hostile-verify must need the Sign job")
        if "hostile-verify" not in need(hd): bad.append("hostile-verdict must need hostile-verify")
        if hv.get("permissions") != {"contents": "read"}: bad.append("hostile-verify permissions must be exactly {contents: read} (no id-token, nothing to write): %s" % hv.get("permissions"))
        if hd.get("permissions") != {"contents": "read"}: bad.append("hostile-verdict permissions must be exactly {contents: read}: %s" % hd.get("permissions"))
        # the CLOSED key sets are exactly what the real file uses, and runs-on is the hosted set
        JOBKEYS = {"needs", "runs-on", "permissions", "if", "steps"}
        STEPKEYS = {"name", "uses", "with", "run"}
        HOSTED = re.compile(r"ubuntu-(22\.04|24\.04)(-arm)?|ubuntu-latest")
        for jn2, j2 in (("hostile-verify", hv), ("hostile-verdict", hd)):
            if not isinstance(j2.get("runs-on"), str) or not HOSTED.fullmatch(j2["runs-on"]):
                bad.append("%s runs-on %r is not in the closed hosted runner set" % (jn2, j2.get("runs-on")))
        for jn2, j2 in (("hostile-verify", hv), ("hostile-verdict", hd)):
            extra = sorted(set(j2) - JOBKEYS)
            if extra: bad.append("%s has job keys outside the allowlist %s (job env/defaults/container/strategy/services/outputs/continue-on-error can change what the pinned text executes)" % (jn2, extra))
            for s2 in j2.get("steps") or []:
                ex2 = sorted(set(s2) - STEPKEYS)
                if ex2: bad.append("%s has a step with keys outside the allowlist %s (shell/env/working-directory/continue-on-error can change what the pinned text executes): %r" % (jn2, ex2, s2.get("name") or s2.get("run") or s2.get("uses")))
        for k in ("env", "defaults"):
            if k in rl: bad.append("release.yml has a top-level %s (it reaches every job, including the verifier)" % k)
        hs = hv.get("steps") or []
        # ALLOWLIST: checkout, three downloads, one pinned policy make, the attempt/control steps, collect, upload. Nothing else.
        kinds = []
        for s in hs:
            u, run = str(s.get("uses", "")), (s.get("run") or "").strip()
            act = re.fullmatch(r"actions/(checkout|download-artifact|upload-artifact)@[0-9a-f]{40}", u)
            if u and not act:
                kinds.append("other"); bad.append("hostile-verify uses %r; only actions/checkout, download-artifact and upload-artifact at a 40-hex commit" % u); continue
            if act and act.group(1) == "checkout":
                kinds.append("checkout")
                if WITH(s) != {"persist-credentials": "false"}: bad.append("hostile-verify's checkout with: must be exactly {persist-credentials: false} (no repository, ref, token, path, fetch-depth: it runs this repository's verifier): %s" % WITH(s))
            elif act and act.group(1) == "download-artifact":
                nm, pth = WITH(s).get("name"), WITH(s).get("path")
                want = {"hostile-attempts": "attempts", "signed-witness-build": "witness-build", "provenance": "provenance"}
                if want.get(nm) != pth or set(WITH(s)) - {"name", "path"}: bad.append("hostile-verify downloads %s into %s; only hostile-attempts->attempts, signed-witness-build->witness-build, provenance->provenance" % (nm, pth)); kinds.append("download?")
                else: kinds.append("download:" + nm)
            elif act and act.group(1) == "upload-artifact":
                kinds.append("upload")
                if WITH(s) != {"name": "hostile-results", "path": "hostile-results.json"}: bad.append("hostile-verify's upload with: must be exactly {name: hostile-results, path: hostile-results.json}: %s" % WITH(s))
            elif re.fullmatch(POLICY_MAKE, run): kinds.append("policy")
            elif re.search(r"--attempt (\w+)", run): kinds.append("attempt:" + re.search(r"--attempt (\w+)", run).group(1))
            elif run == "python3 bin/chain-verify.py hostile-collect results --out hostile-results.json": kinds.append("collect")
            else:
                kinds.append("other"); bad.append("hostile-verify has a step outside the allowlist (checkout, the three downloads, the pinned `policy make`, the attempt steps and the positive control, collect, upload): %r" % (s.get("name") or run or u))
        if kinds.count("checkout") != 1: bad.append("hostile-verify must check the repo out exactly once")
        for nm in ("hostile-attempts", "signed-witness-build", "provenance"):
            if kinds.count("download:" + nm) != 1: bad.append("hostile-verify must download the artifact %s exactly once (without it every verify reads a missing file and 'refuses')" % nm)
        if kinds.count("policy") != 1: bad.append("hostile-verify must run the pinned `policy make --template .github/policy/release-policy.template.json --ref \"$GITHUB_REF\" --out policy.json` exactly once (a permissive or tracked policy.json proves nothing)")
        if os.path.exists(os.path.join(root, "policy.json")): bad.append("a policy.json is part of the tree: the verify job must make its own")
        try:
            first_att = next(i for i, k in enumerate(kinds) if k.startswith("attempt:"))
            if not (kinds[0] == "checkout" and kinds.index("policy") < first_att and all(kinds.index("download:" + n) < first_att for n in ("hostile-attempts", "signed-witness-build", "provenance"))):
                bad.append("hostile-verify order must be checkout, downloads, policy make, then the attempts")
        except (StopIteration, ValueError): bad.append("hostile-verify has no attempt steps or no policy step")
        # one three-line step per attempt, the exit code captured from the verifier's own invocation
        seen = {}
        for s in hv.get("steps") or []:
            run = (s.get("run") or "").strip(); lines = [l.strip() for l in run.splitlines() if l.strip()]
            m = re.search(r"--attempt (\w+)", run)
            if not m: continue
            a = m.group(1); seen[a] = seen.get(a, 0) + 1
            # every part of the pinned lines is EXACT; the stderr file is /tmp/<attempt>.err, built from the
            # attempt name
            errf = "/tmp/%s.err" % a
            ok = (len(lines) == 3 and lines[0] == "rc=0"
                  and a in PIN and re.fullmatch(PIN[a] + re.escape(" 2> %s || rc=$?" % errf), lines[1])
                  and lines[2] == "python3 bin/chain-verify.py hostile-row --attempt %s --exit-code \"$rc\" --stderr %s --out results/%s.json" % (a, errf, a))
            if not ok: bad.append("hostile-verify step for %s is not the pinned three-line shape (rc=0; the pinned verifier invocation for this attempt 2> FILE || rc=$?; hostile-row ... --exit-code \"$rc\")" % a)
            if run.count(errf) != 2: bad.append("hostile-verify step for %s: the verifier must write, and hostile-row read, exactly %s" % (a, errf))
            if re.search(r"\|\|\s*(true|:|echo|exit\s+0)\b|\becho\b|\bprintf\b|\bcat\b|\btee\b|>\s*results|set \+e", run): bad.append("hostile-verify step for %s swallows or writes the outcome by hand" % a)
        for a in sorted(set(seen) - set(ATT) - {"positive_control"}):
            bad.append("hostile-verify has a step for %s, which is not one of the five runtime cases (the sixth, call_sign_from_other_workflow, is judged by Sign's caller check and the offline test, never by a runtime step)" % a)
        for a in ATT + ["positive_control"]:
            if seen.get(a, 0) != 1: bad.append("hostile-verify has %d steps for %s (need exactly one)" % (seen.get(a, 0), a))
        runs = [(s.get("run") or "").strip() for s in hv.get("steps") or []]
        if "python3 bin/chain-verify.py hostile-collect results --out hostile-results.json" not in runs: bad.append("hostile-verify does not run hostile-collect")
        if kinds and kinds[-2:] != ["collect", "upload"]: bad.append("hostile-verify must end with collect then upload")
        ups = [s for s in hv.get("steps") or [] if "upload-artifact" in str(s.get("uses", "")) and (s.get("with") or {}).get("name") == "hostile-results"]
        if len(ups) != 1 or kinds.count("upload") != 1: bad.append("hostile-verify must upload exactly one artifact, hostile-results")
        dls = [s for s in hd.get("steps") or [] if "download-artifact" in str(s.get("uses", "")) and (s.get("with") or {}).get("name") == "hostile-results"]
        if len(dls) != 1: bad.append("hostile-verdict must download the artifact hostile-results (the verdict reads the run's rows, not a checked-out file)")
        if not any((s.get("run") or "").strip() == "python3 bin/chain-verify.py hostile-verdict hostile-results/hostile-results.json" for s in hd.get("steps") or []):
            bad.append("hostile-verdict does not run `python3 bin/chain-verify.py hostile-verdict hostile-results/hostile-results.json`")
        # the verdict job is a CLOSED sequence: checkout (persist-credentials false), the one download, the verdict line
        def _shape(st):
            u = str(st.get("uses", "")); w = WITH(st)
            if re.fullmatch(r"actions/checkout@[0-9a-f]{40}", u) and w == {"persist-credentials": "false"}: return "checkout"
            if re.fullmatch(r"actions/download-artifact@[0-9a-f]{40}", u) and w == {"name": "hostile-results", "path": "hostile-results"}: return "download"
            if not u and set(st) <= {"name", "run"} and st.get("run") == "python3 bin/chain-verify.py hostile-verdict hostile-results/hostile-results.json": return "verdict"
            return "other"
        vseq = [_shape(st) for st in hd.get("steps") or []]
        if vseq != ["checkout", "download", "verdict"]: bad.append("hostile-verdict must be exactly checkout (persist-credentials: false), download hostile-results, the verdict line: %s" % vseq)
        after_sign, grow = set(), True
        while grow:
            grow = False
            for jn3, j3 in jobs.items():
                if jn3 not in after_sign and (set(need(j3)) & (set(sign_jobs) | after_sign)): after_sign.add(jn3); grow = True
        STATUS = re.compile(r"always\(\)|failure\(\)|cancelled\(\)|success\(\)")
        guarded = set()      # the jobs that cannot run in a dry run or on a branch: their own if carries the push event or the dry-run conjunct and the positive tag conjunct, or they run only after such a job
        for jn, j in jobs.items():
            if jn in TAG_JOBS: continue       # the tag jobs are judged by name below, with their exact needs and if
            if str(j.get("uses", "")).split("/")[-1].startswith("stage-"): bad.append("the job %s calls %s: no stage-*.yml file exists, release.yml is the one file" % (jn, j.get("uses")))
            if jn in OPEN:
                if j.get("uses") and not (jn == "persona-uat-rc" and j.get("uses") == "./.github/workflows/persona-uat.yml"): bad.append("the open job %s may not call a workflow (a job named like a build job that calls anything else is not exempt from the dry-run gate): %r" % (jn, j.get("uses")))
                if STATUS.search(str(j.get("if", ""))): bad.append("the open job %s has a status function in its if: it would run after a failed or skipped job" % jn)
                continue
            if jn.startswith("hostile-"):
                if str(j.get("if", "")).strip() != RC_IF: bad.append("the job %s is a hostile-* job and must have `if: the rc-tag push condition` exactly (only an rc-tag push makes the hostile attempts: on a final tag its hostile-attempts download fails and blocks every release): %r" % (jn, j.get("if")))
                if j.get("uses"): bad.append("the job %s is a hostile-* job and may not call a workflow" % jn)
                if j.get("permissions") != {"contents": "read"}: bad.append("the job %s must have permissions exactly {contents: read}" % jn)
                continue
        # a job is guarded by its own if (explicit, closed form) or, with no if of its own or exactly the Check condition, by a guarded job it needs
        pending = [jn for jn in jobs if jn not in OPEN and not jn.startswith("hostile-") and jn not in TAG_JOBS]
        grow = True
        while grow:
            grow = False
            for jn in list(pending):
                j = jobs[jn]; cond = str(j.get("if", "")); cs = conj(cond) if "if" in j else []
                own = cs is not None and TAGCONJ in cs and ("!inputs.dry-run" in cs or PUSHCONJ in cs) and "if" in j
                inherits = ("if" not in j or cond.strip() == CHECK_IF) and bool(set(need(j)) & guarded)
                if own or inherits: guarded.add(jn); pending.remove(jn); grow = True
        for jn in pending:
            j = jobs[jn]; cond = str(j.get("if", "")); cs = conj(cond) if "if" in j else []
            if "if" not in j: bad.append("the job %s is not skipped in a dry run or on a branch: it has no if: of its own and needs no job that is (its if: must be exactly ${{ !inputs.dry-run }} or have it as an && conjunct, no ||): %r" % (jn, cond))
            elif jn in after_sign and (cs is None or TAGCONJ not in cs): bad.append("the job %s needs Sign (transitively) and its if: must also carry the POSITIVE conjunct startsWith(github.ref, 'refs/tags/v') exactly (not negated, not compared, no ||) so a branch run can never reach it: %r" % (jn, cond))
            else: bad.append("the job %s is not skipped in a dry run (its if: must be exactly ${{ !inputs.dry-run }} or have it as an && conjunct, no ||): %r" % (jn, cond))
        # REACHABILITY: the dry run must be REACHABLE. Admission is the first step of Build's apk job, so the chain hangs off ONE gate, on build-freeze: a v* tag push, a dry-run dispatch on any branch, or a snapshot call
        bj = jobs.get("build-freeze") or {}
        BUILD_IF = "${{ (github.event_name == 'push' && (startsWith(github.ref, 'refs/tags/v') || startsWith(github.ref, 'refs/heads/release/v'))) || inputs.dry-run == true || inputs.mode == 'snapshot' }}"
        if re.sub(r"\s+", "", str(bj.get("if", ""))) != re.sub(r"\s+", "", BUILD_IF): bad.append("the build-freeze job must carry `if: %s` (else a dry run skips it, and with it everything after it, and is green with no checks): %r" % (BUILD_IF, bj.get("if")))
        if need(bj): bad.append("the build-freeze job needs nothing (admission is the first step of build-apk, not a job): %r" % need(bj))
    # ---- the tag jobs of the automatic patch release, by name (REQ-REL-009): decide, sign-tag, cut and patch-notes are release.yml's inline jobs; no job of the chain is among them and they are not Sign jobs ----
    nd = lambda j: [j.get("needs")] if isinstance(j.get("needs"), str) else list(j.get("needs") or [])
    for tn, (tneeds, tif) in TAG_JOBS.items():
        tj = jobs.get(tn)
        if tj is None: bad.append("release.yml has no job %s (the automatic patch release: decide, sign-tag, cut, patch-notes)" % tn); continue
        if tj.get("uses"): bad.append("the tag job %s calls a workflow: it is an inline job of release.yml" % tn)
        if sorted(nd(tj)) != sorted(tneeds): bad.append("the tag job %s must need exactly %s, found %s" % (tn, tneeds, nd(tj)))
        if "if" not in tj or norm(tj.get("if")) != norm(tif): bad.append("the tag job %s must carry exactly `if: %s`, found %r" % (tn, tif, tj.get("if")))
    sj = jobs.get("sign")
    if sj is not None and WFREF not in (conj(str(sj.get("if", ""))) or []): bad.append("the sign job does not carry guard S's workflow_ref text %s: decide's last conjunct must be the same text the sign jobs use" % WFREF)
    if "check-govulncheck" in jobs and norm(jobs["check-govulncheck"].get("if")) != norm(CGV_IF):
        bad.append("check-govulncheck has no needs, so it runs in every run unless its own if keeps it off: it must carry exactly `if: %s`, found %r" % (CGV_IF, jobs["check-govulncheck"].get("if")))
    # every other job stays OFF in a run on main (a push or the daily schedule): the jobs that run are decide and, when decide names a tag, the three after it. The `if:` of each job is evaluated for the run
    # (a missing input is null; a status function lets a job run after skipped needs; the results of other jobs are taken as the worst case), and a job runs only when every job it needs ran.
    class _W:
        def __getattr__(s, k): return s
        def __eq__(s, o): return True
        def __ne__(s, o): return True
        def __bool__(s): return True
    class _Ctx:
        def __init__(s, d, wild=False): s.d, s.wild = d, wild
        def __getattr__(s, k):
            v = s.d.get(k, _W() if s.wild else "")
            return _Ctx(v, s.wild) if isinstance(v, dict) else v
    def evaluate(cond, gh, ins, ran):
        e = re.fullmatch(r"\$\{\{\s*(.*?)\s*\}\}", str(cond).strip(), re.S).group(1)
        parts = re.split(r"('(?:[^']|'')*')", e)
        for i in range(0, len(parts), 2):
            p = parts[i].replace("&&", " and ").replace("||", " or ").replace("inputs.dry-run", "inputs.dry_run").replace("needs.*.result", "needs_all")
            p = re.sub(r"!(?!=)", " not ", p); p = re.sub(r"\bfalse\b", "False", p); p = re.sub(r"\btrue\b", "True", p)
            p = re.sub(r"\b(always|failure|cancelled|success)\(\)", "True", p)
            parts[i] = p
        env = {"github": _Ctx(gh), "inputs": _Ctx({"dry_run": ins.get("dry-run", ""), "mode": ins.get("mode", "")}), "vars": _Ctx({}),
               "needs": _Ctx({"decide": {"outputs": {"tag": "v0.3.1"}}}, True), "needs_all": _W(),
               "startsWith": lambda a, b: str(a).lower().startswith(str(b).lower()), "format": lambda f, *a: f.format(*a),
               "contains": lambda a, b: True if isinstance(a, _W) else str(b) in str(a)}
        return eval("".join(parts), {"__builtins__": {}}, env)
    def which_run(event, ref, wf, mode=None, dry=None):
        gh = {"event_name": event, "ref": ref, "workflow_ref": "fosterstack/cache/.github/workflows/%s@%s" % (wf, ref), "repository": "fosterstack/cache"}
        ins = {k: v for k, v in (("mode", mode), ("dry-run", dry)) if v is not None}
        ran, grow = set(), True
        while grow:
            grow = False
            for jn, j in jobs.items():
                if jn in ran: continue
                cond = j.get("if")
                try: on = True if cond is None else bool(evaluate(cond, gh, ins, ran))
                except Exception as ex: bad.append("the if of the job %s cannot be read as a workflow expression (%s): %r" % (jn, type(ex).__name__, cond)); on = False; ran.add(jn)
                waived = cond is not None and re.search(r"\b(always|failure|cancelled)\(\)", str(cond))
                if on and (waived or all(n in ran for n in nd(j))): ran.add(jn); grow = True
        return ran
    for label, args in (("a push to main", ("push", "refs/heads/main", "release.yml")), ("the daily schedule on main", ("schedule", "refs/heads/main", "release.yml"))):
        ran = which_run(*args)
        extra = sorted(ran - set(TAG_JOBS))
        if extra: bad.append("in a run on main (%s) these jobs run, and only decide and the tag jobs may: %s (a job with no needs and no ref guard runs everywhere)" % (label, extra))
        if "decide" in jobs and "decide" not in ran: bad.append("decide does not run on %s" % label)
    for label, args in (("a v* tag push", ("push", "refs/tags/v0.3.1", "release.yml")), ("a dispatch on main", ("workflow_dispatch", "refs/heads/main", "release.yml", None, False)),
                        ("a dry run", ("workflow_dispatch", "refs/heads/main", "release.yml", None, True)),
                        ("a snapshot call from scan.yml on a main push", ("push", "refs/heads/main", "scan.yml", "snapshot")),
                        ("a snapshot call whose workflow_ref reads release.yml", ("push", "refs/heads/main", "release.yml", "snapshot"))):
        late = sorted(set(which_run(*args)) & set(TAG_JOBS))
        if late: bad.append("the tag jobs %s run on %s: they run on main only" % (late, label))
# Release makes its policy in its first step, bin/release-verify.sh (every Release step is a committed script under Witness)
cands = [os.path.join(root, "bin/release-verify.sh")]
if not os.path.exists(cands[0]): bad.append("bin/release-verify.sh missing (Release makes its policy there)")
else:
    pm = [l for sp in cands if os.path.exists(sp) for l in re.sub(r"\\\n[ \t]*", " ", open(sp).read()).splitlines() if "policy make" in l and not l.lstrip().startswith("#")]
    if not pm: bad.append("Release (bin/release-verify.sh) never runs `policy make` (it must make its own tag-pinned policy)")
    for l in pm:
        if "--ref" in l or "--tag" not in l: bad.append("Release's `policy make` must use --tag and never --ref (a --ref policy accepts a branch dry-run record): %s" % l.strip())
for wf in glob.glob(os.path.join(root, ".github/workflows/*.y*ml")):
    if os.path.basename(wf) == "release.yml": continue
    for l in open(wf).read().splitlines():
        if "policy make" in l and "--ref" in l and not l.lstrip().startswith("#"): bad.append("%s runs `policy make --ref`: only release.yml's hostile-verify may" % os.path.basename(wf))
for f in glob.glob(os.path.join(root, "**/hostile-results*.json"), recursive=True):
    if "/.git/" not in f: bad.append("a hostile-results file is part of the tree (%s): the rows must come from the run" % os.path.relpath(f, root))
sc = os.path.join(root, "bin/chain-hostile-step.sh")
if not os.path.exists(sc): bad.append("bin/chain-hostile-step.sh missing")
else:
    code = "\n".join(re.sub(r"(?<=\s)#.*$", "", l) for l in open(sc).read().splitlines() if not l.lstrip().startswith("#"))
    defined = re.findall(r"^attempt_(\w+)\(\)\s*\{", code, re.M)
    for a in sorted(set(defined) - set(ATT)): bad.append("attempt_%s() is defined: the hostile step makes exactly the five cases" % a)
    for a in sorted(set(re.findall(r"^\s*attempt_(\w+)\s*$", code, re.M)) - set(ATT)): bad.append("attempt_%s is called: the hostile step makes exactly the five cases" % a)
    if re.search(r"hostile-caller", code): bad.append("the hostile step reads a throwaway caller's record (hostile-caller): no second workflow exists")
    for a in ATT:
        if not re.search(r"^attempt_%s\(\)\s*\{" % a, code, re.M): bad.append("attempt_%s() is not defined" % a)
        if len(re.findall(r"^\s*attempt_%s\s*$" % a, code, re.M)) != 1: bad.append("attempt_%s is not called exactly once" % a)
    if re.search(r"\b(refused|accepted|outcome|judged_by|exit_code|chain-verify)\b", code): bad.append("the hostile step writes or names an outcome or calls the verifier; only the verify job may")
    if len(re.findall(r"transcript:", code)) < 2: bad.append("the token and key attempts must each write a `# transcript:` first line into their material file (an empty file is an error, not isolation)")
print("; ".join(bad) or "ok"); sys.exit(1 if bad else 0)
PY
wire() { python3 "$work/wiring.py" "$1" 2>&1; }
wexpect() { local o rc=0; o=$(wire "$3") || rc=$?
  if [ "$1" = ok ] && [ "$rc" = 0 ]; then ok "$2"
  elif [ "$1" = caught ] && [ "$rc" = 1 ] && ! grep -F -q Traceback <<< "$o"; then ok "$2 (caught: ${o:0:140})"
  else bad "$2 -> ${o:0:400}"; fi; }
sha=$(printf 'a%.0s' $(seq 40))
mk() { # a known-good fixture tree
  local d="$work/$1"; rm -rf "$d"; mkdir -p "$d/.github/workflows" "$d/bin"
  { cat <<EOF
on: {workflow_dispatch: {inputs: {dry-run: {type: boolean}}}}
jobs:
  build-freeze:
    if: \${{ (github.event_name == 'push' && (startsWith(github.ref, 'refs/tags/v') || startsWith(github.ref, 'refs/heads/release/v'))) || inputs.dry-run == true || inputs.mode == 'snapshot' }}
    runs-on: ubuntu-24.04
    steps:
      - run: echo freeze
  build-assemble:
    needs: build-freeze
    runs-on: ubuntu-24.04
    steps:
      - name: hostile step
        run: bash bin/chain-hostile-step.sh
      - uses: actions/upload-artifact@$sha # v7
        with:
          name: hostile-attempts
          path: attempts
  sign:
    needs: build-assemble
    if: \${{ inputs.mode != 'snapshot' && github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && startsWith(github.workflow_ref, format('{0}/.github/workflows/release.yml@', github.repository)) }}
    runs-on: ubuntu-24.04
    steps:
      - run: echo sign
  hostile-verify:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}
    needs: sign
    runs-on: ubuntu-24.04
    permissions: {contents: read}
    steps:
      - uses: actions/checkout@$sha # v7
        with: {persist-credentials: false}
      - uses: actions/download-artifact@$sha # v8
        with: {name: hostile-attempts, path: attempts}
      - uses: actions/download-artifact@$sha # v8
        with: {name: signed-witness-build, path: witness-build}
      - uses: actions/download-artifact@$sha # v8
        with: {name: provenance, path: provenance}
      - run: python3 bin/chain-verify.py policy make --template .github/policy/release-policy.template.json --ref "\$GITHUB_REF" --out policy.json
EOF
    for a in mint_sign_cert forge_provenance; do
      cat <<EOF
      - run: |
          rc=0
          python3 bin/chain-verify.py verify --stage sign --record attempts/$a.json --policy policy.json 2> /tmp/$a.err || rc=\$?
          python3 bin/chain-verify.py hostile-row --attempt $a --exit-code "\$rc" --stderr /tmp/$a.err --out results/$a.json
EOF
    done
    cat <<EOF
      - run: |
          rc=0
          python3 bin/chain-verify.py check-build-record --digests attempts/hand_sign_code.json --build-record witness-build/build-collection.json --policy policy.json 2> /tmp/hand_sign_code.err || rc=\$?
          python3 bin/chain-verify.py hostile-row --attempt hand_sign_code --exit-code "\$rc" --stderr /tmp/hand_sign_code.err --out results/hand_sign_code.json
EOF
    for a in read_sign_token read_sign_key; do
      kind=token; extra=; [ "$a" = read_sign_key ] && { kind=key; extra=" --policy policy.json"; }
      cat <<EOF
      - run: |
          rc=0
          python3 bin/chain-verify.py hostile-material --kind $kind --file attempts/$a.txt$extra 2> /tmp/$a.err || rc=\$?
          python3 bin/chain-verify.py hostile-row --attempt $a --exit-code "\$rc" --stderr /tmp/$a.err --out results/$a.json
EOF
    done
    cat <<EOF
      - run: |
          rc=0
          python3 bin/chain-verify.py verify --stage sign --record provenance/provenance.json --policy policy.json 2> /tmp/positive_control.err || rc=\$?
          python3 bin/chain-verify.py hostile-row --attempt positive_control --exit-code "\$rc" --stderr /tmp/positive_control.err --out results/positive_control.json
      - run: python3 bin/chain-verify.py hostile-collect results --out hostile-results.json
      - uses: actions/upload-artifact@$sha # v7
        with: {name: hostile-results, path: hostile-results.json}
  hostile-verdict:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}
    needs: hostile-verify
    runs-on: ubuntu-24.04
    permissions: {contents: read}
    steps:
      - uses: actions/checkout@$sha # v7
        with: {persist-credentials: false}
      - uses: actions/download-artifact@$sha # v8
        with: {name: hostile-results, path: hostile-results}
      - run: python3 bin/chain-verify.py hostile-verdict hostile-results/hostile-results.json
  promotion:
    if: \${{ !inputs.dry-run && startsWith(github.ref, 'refs/tags/v') }}
    needs: [sign, hostile-verdict]
    runs-on: ubuntu-24.04
    steps:
      - run: echo publish
  check-govulncheck:
    if: \${{ inputs.mode != 'snapshot' && ((github.event_name == 'push' && (startsWith(github.ref, 'refs/tags/v') || startsWith(github.ref, 'refs/heads/release/v'))) || inputs.dry-run == true) }}
    runs-on: ubuntu-24.04
    steps:
      - run: echo govulncheck
  decide:
    if: \${{ inputs.mode != 'snapshot' && github.ref == 'refs/heads/main' && github.event_name != 'workflow_dispatch' && !inputs.dry-run && startsWith(github.workflow_ref, format('{0}/.github/workflows/release.yml@', github.repository)) }}
    runs-on: ubuntu-24.04
    steps:
      - run: echo decide
  sign-tag:
    needs: decide
    if: \${{ needs.decide.outputs.tag != '' }}
    runs-on: ubuntu-24.04
    steps:
      - run: echo sign-tag
  cut:
    needs: [decide, sign-tag]
    if: \${{ needs.decide.outputs.tag != '' }}
    runs-on: ubuntu-24.04
    steps:
      - run: echo cut
  patch-notes:
    needs: [decide, cut]
    if: \${{ needs.decide.outputs.tag != '' }}
    runs-on: ubuntu-24.04
    steps:
      - run: echo patch-notes
EOF
  } > "$d/.github/workflows/release.yml"
  { echo "# makes five attempts; writes raw material only"; for a in $attempts; do case $a in read_sign_token|read_sign_key) printf "attempt_%s() { printf '# transcript: tried %s by reading the runner environment and the usual paths\\\\ncurl: (6) could not resolve host\\\\n' > attempts/%s.txt; }\\n" "$a" "$a" "$a" ;; *) printf 'attempt_%s() { :; }\n' "$a" ;; esac; done; for a in $attempts; do printf 'attempt_%s\n' "$a"; done; } > "$d/bin/chain-hostile-step.sh"
  printf 'set -euo pipefail\npython3 bin/chain-verify.py policy make --template .github/policy/release-policy.template.json --tag "$GITHUB_REF_NAME" --out policy.json\n' > "$d/bin/release-verify.sh"
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
d=$(mk w_dupon); printf 'on: push\n' | cat - "$(rel "$d")" > "$d/x" && mv "$d/x" "$(rel "$d")"; wexpect caught "wiring: a duplicate top-level on: key in release.yml is refused, never resolved to the last one (Codex #249 r4 B3a)" "$d"
d=$(mk w_nbsp); pymut "$(rel "$d")" "run: bash bin/chain-hostile-step.sh" "run: bash bin/chain-hostile-step.sh"$'\u00a0'; wexpect caught "wiring: run line: a trailing NBSP after the hostile step (str.strip() would drop it; bash keeps it in the path)" "$d"
d=$(mk w_collectnbsp); pymut "$(rel "$d")" "run: python3 bin/chain-verify.py hostile-collect results --out hostile-results.json" "run: python3 bin/chain-verify.py hostile-collect results --out hostile-results.json"$'\u00a0'; wexpect caught "wiring: run line: a trailing NBSP after the collect step" "$d"
d=$(mk w_collectcont); pymut "$(rel "$d")" "run: python3 bin/chain-verify.py hostile-collect results --out hostile-results.json" 'run: "python3 bin/chain-verify.py hostile-collect results --out hostile-results.json\\\n"'; wexpect caught "wiring: run line: a trailing backslash-newline after the collect step" "$d"
# every pinned line is matched EXACTLY: the stderr file is /tmp/<attempt>.err, and both hostile jobs are
# closed step sequences (an extra step, or an action whose name merely contains checkout/download-artifact/upload-artifact, is refused)
allmut() { python3 - "$1" "$2" "$3" <<'PY'
import sys
t = open(sys.argv[1]).read(); assert sys.argv[2] in t, "mutation target not found: " + sys.argv[2]
open(sys.argv[1], "w").write(t.replace(sys.argv[2], sys.argv[3]))
PY
}
for v in 'subst:/tmp/$(true)mint_sign_cert.err' 'backtick:/tmp/`true`mint_sign_cert.err' 'backslash:/tmp/mint\sign_cert.err' 'semicolon:/tmp/x;true;mint_sign_cert.err' 'var:/tmp/$X.err' 'other:/tmp/other.err' 'relative:mint_sign_cert.err' 'dotdot:/tmp/../tmp/mint_sign_cert.err'; do
  d=$(mk "w_err_${v%%:*}"); allmut "$(rel "$d")" "/tmp/mint_sign_cert.err" "${v#*:}"
  wexpect caught "wiring: the stderr file of mint_sign_cert is ${v#*:}, not exactly /tmp/mint_sign_cert.err (${v%%:*})" "$d"
done
d=$(mk w_err_space); allmut "$(rel "$d")" "/tmp/mint_sign_cert.err" "/tmp/a b.err"; wexpect caught "wiring: the stderr file of mint_sign_cert holds a space" "$d"
d=$(mk w_verdict_extra); pymut "$(rel "$d")" "      - run: python3 bin/chain-verify.py hostile-verdict hostile-results/hostile-results.json" "      - run: python3 bin/chain-verify.py hostile-verdict hostile-results/hostile-results.json
      - run: echo after"; wexpect caught "wiring: an extra run step in the hostile-verdict job" "$d"
d=$(mk w_verdict_pre); pymut "$(rel "$d")" "      - run: python3 bin/chain-verify.py hostile-verdict hostile-results/hostile-results.json" "      - run: touch hostile-results/x
      - run: python3 bin/chain-verify.py hostile-verdict hostile-results/hostile-results.json"; wexpect caught "wiring: an extra run step before the verdict line" "$d"
d=$(mk w_verdict_nocheckout); pymut "$(rel "$d")" "      - uses: actions/checkout@$sha # v7
        with: {persist-credentials: false}
      - uses: actions/download-artifact@$sha # v8
        with: {name: hostile-results, path: hostile-results}" "      - uses: actions/download-artifact@$sha # v8
        with: {name: hostile-results, path: hostile-results}"; wexpect caught "wiring: the hostile-verdict job has no checkout (its verifier is not the repository's)" "$d"
d=$(mk w_verdict_twice); pymut "$(rel "$d")" "      - run: python3 bin/chain-verify.py hostile-verdict hostile-results/hostile-results.json" "      - run: python3 bin/chain-verify.py hostile-verdict hostile-results/hostile-results.json
      - run: python3 bin/chain-verify.py hostile-verdict hostile-results/hostile-results.json"; wexpect caught "wiring: the verdict line twice in the hostile-verdict job" "$d"
d=$(mk w_verify_extrarun); pymut "$(rel "$d")" "      - run: python3 bin/chain-verify.py hostile-collect results --out hostile-results.json" "      - run: echo extra
      - run: python3 bin/chain-verify.py hostile-collect results --out hostile-results.json"; wexpect caught "wiring: an extra run step in the hostile-verify job" "$d"
d=$(mk w_verify_fakeco); pymut "$(rel "$d")" "      - run: python3 bin/chain-verify.py hostile-collect results --out hostile-results.json" "      - uses: evil/actions/checkout-x@$sha
        with: {persist-credentials: false}
      - run: python3 bin/chain-verify.py hostile-collect results --out hostile-results.json"; wexpect caught "wiring: an action whose name merely contains actions/checkout in the hostile-verify job" "$d"
d=$(mk w_verify_upload2); pymut "$(rel "$d")" "      - run: python3 bin/chain-verify.py hostile-collect results --out hostile-results.json" "      - uses: actions/upload-artifact@$sha # v7
        with: {name: other, path: attempts}
      - run: python3 bin/chain-verify.py hostile-collect results --out hostile-results.json"; wexpect caught "wiring: a second upload (another artifact) in the hostile-verify job" "$d"
# both hostile jobs are CLOSED: job keys, step keys, every with: payload and runs-on are exactly the real file's
d=$(mk w9_co_repository); pymut "$(rel "$d")" "      - uses: actions/checkout@$sha # v7
        with: {persist-credentials: false}
      - uses: actions/download-artifact@$sha # v8
        with: {name: hostile-attempts, path: attempts}" "      - uses: actions/checkout@$sha # v7
        with: {persist-credentials: false, repository: other/repo}
      - uses: actions/download-artifact@$sha # v8
        with: {name: hostile-attempts, path: attempts}"; wexpect caught "wiring: the hostile-verify checkout carries repository: (its with: is exactly persist-credentials: false; Codex #249 r8 B1)" "$d"
d=$(mk w9_co_ref); pymut "$(rel "$d")" "      - uses: actions/checkout@$sha # v7
        with: {persist-credentials: false}
      - uses: actions/download-artifact@$sha # v8
        with: {name: hostile-attempts, path: attempts}" "      - uses: actions/checkout@$sha # v7
        with: {persist-credentials: false, ref: main}
      - uses: actions/download-artifact@$sha # v8
        with: {name: hostile-attempts, path: attempts}"; wexpect caught "wiring: the hostile-verify checkout carries ref: (its with: is exactly persist-credentials: false; Codex #249 r8 B1)" "$d"
d=$(mk w9_co_token); pymut "$(rel "$d")" "      - uses: actions/checkout@$sha # v7
        with: {persist-credentials: false}
      - uses: actions/download-artifact@$sha # v8
        with: {name: hostile-attempts, path: attempts}" "      - uses: actions/checkout@$sha # v7
        with: {persist-credentials: false, token: x}
      - uses: actions/download-artifact@$sha # v8
        with: {name: hostile-attempts, path: attempts}"; wexpect caught "wiring: the hostile-verify checkout carries token: (its with: is exactly persist-credentials: false; Codex #249 r8 B1)" "$d"
d=$(mk w9_co_path); pymut "$(rel "$d")" "      - uses: actions/checkout@$sha # v7
        with: {persist-credentials: false}
      - uses: actions/download-artifact@$sha # v8
        with: {name: hostile-attempts, path: attempts}" "      - uses: actions/checkout@$sha # v7
        with: {persist-credentials: false, path: sub}
      - uses: actions/download-artifact@$sha # v8
        with: {name: hostile-attempts, path: attempts}"; wexpect caught "wiring: the hostile-verify checkout carries path: (its with: is exactly persist-credentials: false; Codex #249 r8 B1)" "$d"
d=$(mk w9_co_fetchdepth); pymut "$(rel "$d")" "      - uses: actions/checkout@$sha # v7
        with: {persist-credentials: false}
      - uses: actions/download-artifact@$sha # v8
        with: {name: hostile-attempts, path: attempts}" "      - uses: actions/checkout@$sha # v7
        with: {persist-credentials: false, fetch-depth: 0}
      - uses: actions/download-artifact@$sha # v8
        with: {name: hostile-attempts, path: attempts}"; wexpect caught "wiring: the hostile-verify checkout carries fetch-depth: (its with: is exactly persist-credentials: false; Codex #249 r8 B1)" "$d"
d=$(mk w9_co_submodules); pymut "$(rel "$d")" "      - uses: actions/checkout@$sha # v7
        with: {persist-credentials: false}
      - uses: actions/download-artifact@$sha # v8
        with: {name: hostile-attempts, path: attempts}" "      - uses: actions/checkout@$sha # v7
        with: {persist-credentials: false, submodules: true}
      - uses: actions/download-artifact@$sha # v8
        with: {name: hostile-attempts, path: attempts}"; wexpect caught "wiring: the hostile-verify checkout carries submodules: (its with: is exactly persist-credentials: false; Codex #249 r8 B1)" "$d"
d=$(mk w9_up_path); pymut "$(rel "$d")" "      - uses: actions/upload-artifact@$sha # v7
        with: {name: hostile-results, path: hostile-results.json}" "      - uses: actions/upload-artifact@$sha # v7
        with: {name: hostile-results, path: attempts/mint_sign_cert.json}"; wexpect caught "wiring: the hostile-results upload carries path: attempts/mint_sign_cert.json (its with: is exactly name and path hostile-results.json)" "$d"
d=$(mk w9_up_pathdot); pymut "$(rel "$d")" "      - uses: actions/upload-artifact@$sha # v7
        with: {name: hostile-results, path: hostile-results.json}" "      - uses: actions/upload-artifact@$sha # v7
        with: {name: hostile-results, path: .}"; wexpect caught "wiring: the hostile-results upload carries path: . (its with: is exactly name and path hostile-results.json)" "$d"
d=$(mk w9_up_retentiondays); pymut "$(rel "$d")" "      - uses: actions/upload-artifact@$sha # v7
        with: {name: hostile-results, path: hostile-results.json}" "      - uses: actions/upload-artifact@$sha # v7
        with: {name: hostile-results, path: hostile-results.json, retention-days: 1}"; wexpect caught "wiring: the hostile-results upload carries retention-days: 1 (its with: is exactly name and path hostile-results.json)" "$d"
d=$(mk w9_up_ifnofilesfound); pymut "$(rel "$d")" "      - uses: actions/upload-artifact@$sha # v7
        with: {name: hostile-results, path: hostile-results.json}" "      - uses: actions/upload-artifact@$sha # v7
        with: {name: hostile-results, path: hostile-results.json, if-no-files-found: ignore}"; wexpect caught "wiring: the hostile-results upload carries if-no-files-found: ignore (its with: is exactly name and path hostile-results.json)" "$d"
d=$(mk w9_vd_pattern); pymut "$(rel "$d")" "        with: {name: hostile-results, path: hostile-results}
      - run: python3 bin/chain-verify.py hostile-verdict" "        with: {name: hostile-results, path: hostile-results, pattern: x}
      - run: python3 bin/chain-verify.py hostile-verdict"; wexpect caught "wiring: the verdict download carries pattern: (its with: is exact)" "$d"
d=$(mk w9_vd_path); pymut "$(rel "$d")" "        with: {name: hostile-results, path: hostile-results}
      - run: python3 bin/chain-verify.py hostile-verdict" "        with: {name: hostile-results, path: .}
      - run: python3 bin/chain-verify.py hostile-verdict"; wexpect caught "wiring: the verdict download goes to . (its with: is exact)" "$d"
d=$(mk w9_hv_runner); pymut "$(rel "$d")" "  hostile-verify:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}
    needs: sign
    runs-on: ubuntu-24.04" "  hostile-verify:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}
    needs: sign
    runs-on: self-hosted"; wexpect caught "wiring: hostile-verify runs on self-hosted" "$d"
d=$(mk w9_hv_runner2); pymut "$(rel "$d")" "  hostile-verify:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}
    needs: sign
    runs-on: ubuntu-24.04" "  hostile-verify:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}
    needs: sign
    runs-on: ubuntu-20.04"; wexpect caught "wiring: hostile-verify runs on a runner outside the closed hosted set (ubuntu-20.04)" "$d"
d=$(mk w9_hd_runner); pymut "$(rel "$d")" "  hostile-verdict:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}
    needs: hostile-verify
    runs-on: ubuntu-24.04" "  hostile-verdict:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}
    needs: hostile-verify
    runs-on: self-hosted"; wexpect caught "wiring: hostile-verdict runs on self-hosted" "$d"
d=$(mk w9_hvkey_timeoutminutes); pymut "$(rel "$d")" "  hostile-verify:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}
    needs: sign
    runs-on: ubuntu-24.04" "  hostile-verify:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}
    needs: sign
    runs-on: ubuntu-24.04
    timeout-minutes: 5"; wexpect caught "wiring: hostile-verify job key timeout-minutes: is outside its closed key set" "$d"
d=$(mk w9_hvkey_name); pymut "$(rel "$d")" "  hostile-verify:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}
    needs: sign
    runs-on: ubuntu-24.04" "  hostile-verify:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}
    needs: sign
    runs-on: ubuntu-24.04
    name: x"; wexpect caught "wiring: hostile-verify job key name: is outside its closed key set" "$d"
d=$(mk w9_hvkey_continueonerror); pymut "$(rel "$d")" "  hostile-verify:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}
    needs: sign
    runs-on: ubuntu-24.04" "  hostile-verify:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}
    needs: sign
    runs-on: ubuntu-24.04
    continue-on-error: true"; wexpect caught "wiring: hostile-verify job key continue-on-error: is outside its closed key set" "$d"
d=$(mk w9_hvkey_env); pymut "$(rel "$d")" "  hostile-verify:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}
    needs: sign
    runs-on: ubuntu-24.04" "  hostile-verify:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}
    needs: sign
    runs-on: ubuntu-24.04
    env: {A: b}"; wexpect caught "wiring: hostile-verify job key env: is outside its closed key set" "$d"
d=$(mk w9_hvkey_defaults); pymut "$(rel "$d")" "  hostile-verify:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}
    needs: sign
    runs-on: ubuntu-24.04" "  hostile-verify:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}
    needs: sign
    runs-on: ubuntu-24.04
    defaults: {run: {shell: sh}}"; wexpect caught "wiring: hostile-verify job key defaults: is outside its closed key set" "$d"
d=$(mk w9_hvkey_container); pymut "$(rel "$d")" "  hostile-verify:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}
    needs: sign
    runs-on: ubuntu-24.04" "  hostile-verify:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}
    needs: sign
    runs-on: ubuntu-24.04
    container: alpine"; wexpect caught "wiring: hostile-verify job key container: is outside its closed key set" "$d"
d=$(mk w9_hvkey_services); pymut "$(rel "$d")" "  hostile-verify:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}
    needs: sign
    runs-on: ubuntu-24.04" "  hostile-verify:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}
    needs: sign
    runs-on: ubuntu-24.04
    services: {}"; wexpect caught "wiring: hostile-verify job key services: is outside its closed key set" "$d"
d=$(mk w9_hvkey_strategy); pymut "$(rel "$d")" "  hostile-verify:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}
    needs: sign
    runs-on: ubuntu-24.04" "  hostile-verify:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}
    needs: sign
    runs-on: ubuntu-24.04
    strategy: {fail-fast: false}"; wexpect caught "wiring: hostile-verify job key strategy: is outside its closed key set" "$d"
d=$(mk w9_hvkey_outputs); pymut "$(rel "$d")" "  hostile-verify:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}
    needs: sign
    runs-on: ubuntu-24.04" "  hostile-verify:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}
    needs: sign
    runs-on: ubuntu-24.04
    outputs: {a: b}"; wexpect caught "wiring: hostile-verify job key outputs: is outside its closed key set" "$d"
d=$(mk w9_hdkey_timeoutminutes); pymut "$(rel "$d")" "  hostile-verdict:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}
    needs: hostile-verify
    runs-on: ubuntu-24.04" "  hostile-verdict:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}
    needs: hostile-verify
    runs-on: ubuntu-24.04
    timeout-minutes: 5"; wexpect caught "wiring: hostile-verdict job key timeout-minutes: is outside its closed key set" "$d"
d=$(mk w9_hdkey_continueonerror); pymut "$(rel "$d")" "  hostile-verdict:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}
    needs: hostile-verify
    runs-on: ubuntu-24.04" "  hostile-verdict:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}
    needs: hostile-verify
    runs-on: ubuntu-24.04
    continue-on-error: true"; wexpect caught "wiring: hostile-verdict job key continue-on-error: is outside its closed key set" "$d"
d=$(mk w9_hdkey_env); pymut "$(rel "$d")" "  hostile-verdict:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}
    needs: hostile-verify
    runs-on: ubuntu-24.04" "  hostile-verdict:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}
    needs: hostile-verify
    runs-on: ubuntu-24.04
    env: {A: b}"; wexpect caught "wiring: hostile-verdict job key env: is outside its closed key set" "$d"
d=$(mk w9_stkey_if); pymut "$(rel "$d")" "      - run: |
          rc=0
          python3 bin/chain-verify.py verify --stage sign --record attempts/mint_sign_cert.json" "      - if: always()
        run: |
          rc=0
          python3 bin/chain-verify.py verify --stage sign --record attempts/mint_sign_cert.json"; wexpect caught "wiring: an attempt step key if: is outside the step's closed key set" "$d"
d=$(mk w9_stkey_timeoutminutes); pymut "$(rel "$d")" "      - run: |
          rc=0
          python3 bin/chain-verify.py verify --stage sign --record attempts/mint_sign_cert.json" "      - timeout-minutes: 1
        run: |
          rc=0
          python3 bin/chain-verify.py verify --stage sign --record attempts/mint_sign_cert.json"; wexpect caught "wiring: an attempt step key timeout-minutes: is outside the step's closed key set" "$d"
d=$(mk w9_stkey_continueonerror); pymut "$(rel "$d")" "      - run: |
          rc=0
          python3 bin/chain-verify.py verify --stage sign --record attempts/mint_sign_cert.json" "      - continue-on-error: true
        run: |
          rc=0
          python3 bin/chain-verify.py verify --stage sign --record attempts/mint_sign_cert.json"; wexpect caught "wiring: an attempt step key continue-on-error: is outside the step's closed key set" "$d"
d=$(mk w9_stkey_env); pymut "$(rel "$d")" "      - run: |
          rc=0
          python3 bin/chain-verify.py verify --stage sign --record attempts/mint_sign_cert.json" "      - env: {A: b}
        run: |
          rc=0
          python3 bin/chain-verify.py verify --stage sign --record attempts/mint_sign_cert.json"; wexpect caught "wiring: an attempt step key env: is outside the step's closed key set" "$d"
d=$(mk w9_stkey_shell); pymut "$(rel "$d")" "      - run: |
          rc=0
          python3 bin/chain-verify.py verify --stage sign --record attempts/mint_sign_cert.json" "      - shell: sh
        run: |
          rc=0
          python3 bin/chain-verify.py verify --stage sign --record attempts/mint_sign_cert.json"; wexpect caught "wiring: an attempt step key shell: is outside the step's closed key set" "$d"
d=$(mk w9_stkey_workingdirectory); pymut "$(rel "$d")" "      - run: |
          rc=0
          python3 bin/chain-verify.py verify --stage sign --record attempts/mint_sign_cert.json" "      - working-directory: x
        run: |
          rc=0
          python3 bin/chain-verify.py verify --stage sign --record attempts/mint_sign_cert.json"; wexpect caught "wiring: an attempt step key working-directory: is outside the step's closed key set" "$d"
d=$(mk w9_stkey_id); pymut "$(rel "$d")" "      - run: |
          rc=0
          python3 bin/chain-verify.py verify --stage sign --record attempts/mint_sign_cert.json" "      - id: x
        run: |
          rc=0
          python3 bin/chain-verify.py verify --stage sign --record attempts/mint_sign_cert.json"; wexpect caught "wiring: an attempt step key id: is outside the step's closed key set" "$d"
d=$(mk w9_costkey_if); pymut "$(rel "$d")" "      - uses: actions/checkout@$sha # v7
        with: {persist-credentials: false}
      - uses: actions/download-artifact@$sha # v8
        with: {name: hostile-attempts, path: attempts}" "      - uses: actions/checkout@$sha # v7
        if: always()
        with: {persist-credentials: false}
      - uses: actions/download-artifact@$sha # v8
        with: {name: hostile-attempts, path: attempts}"; wexpect caught "wiring: the checkout step carries if: (closed step key set)" "$d"
d=$(mk w_rd_x); pymut "$(rel "$d")" "  hostile-verdict:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}" "  hostile-x:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}
    needs: hostile-verify
    runs-on: ubuntu-24.04
    permissions: {contents: read}
    steps:
      - run: echo hi
  hostile-verdict:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}"; wexpect caught "wiring: an extra hostile-x job (only hostile-verify and hostile-verdict are allowed; R-d)" "$d"
d=$(mk w_rd_upper); pymut "$(rel "$d")" "  hostile-verdict:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}" "  Hostile-Extra:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}
    needs: hostile-verify
    runs-on: ubuntu-24.04
    permissions: {contents: read}
    steps:
      - run: echo hi
  hostile-verdict:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}"; wexpect caught "wiring: an extra Hostile-Extra job (case-insensitive)" "$d"
d=$(mk w_rd_sign2); pymut "$(rel "$d")" "  hostile-verdict:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}" "  sign-extra:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}
    needs: hostile-verify
    runs-on: ubuntu-24.04
    permissions: {contents: read}
    steps:
      - run: echo hi
  hostile-verdict:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}"; wexpect caught "wiring: an extra sign-extra job" "$d"
d=$(mk w_rd_signrb); pymut "$(rel "$d")" "  hostile-verdict:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}" "  sign-rebuild:
    needs: sign
    if: \${{ inputs.mode != 'snapshot' && github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && startsWith(github.workflow_ref, format('{0}/.github/workflows/release.yml@', github.repository)) }}
    runs-on: ubuntu-24.04
    steps:
      - run: echo hi
  sign-release:
    needs: sign
    if: \${{ inputs.mode != 'snapshot' && github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && startsWith(github.workflow_ref, format('{0}/.github/workflows/release.yml@', github.repository)) && !contains(github.ref_name, '-') }}
    runs-on: ubuntu-24.04
    steps:
      - run: echo hi
  hostile-verdict:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}"; wexpect ok "wiring: the jobs sign-rebuild (Sign's second call, for Rebuild's records) and sign-release (the fourth) are not refused as extra sign* jobs" "$d"
d=$(mk w_signrel_notag); pymut "$(rel "$d")" "  hostile-verdict:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}" "  sign-release:
    needs: sign
    if: \${{ inputs.mode != 'snapshot' && github.event_name == 'push' && !contains(github.ref_name, '-') }}
    runs-on: ubuntu-24.04
    steps:
      - run: echo hi
  hostile-verdict:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}"; wexpect caught "wiring: the job sign-release without the tag conjunct (a branch run could reach the fourth sign job)" "$d"
d=$(mk w_signrel_lax); pymut "$(rel "$d")" "  hostile-verdict:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}" "  sign-release:
    if: \${{ startsWith(github.ref, 'refs/tags/v') || true }}
    needs: sign
    runs-on: ubuntu-24.04
    steps:
      - run: echo hi
  hostile-verdict:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}"; wexpect caught "wiring: the job sign-release whose if is or-joined with true" "$d"
d=$(mk w_rd_signup); pymut "$(rel "$d")" "  hostile-verdict:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}" "  SIGN2:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}
    needs: hostile-verify
    runs-on: ubuntu-24.04
    permissions: {contents: read}
    steps:
      - run: echo hi
  hostile-verdict:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}"; wexpect caught "wiring: an extra SIGN2 job (case-insensitive)" "$d"
d=$(mk w_nogate); pymut "$(rel "$d")" "      - name: hostile step
        run: bash bin/chain-hostile-step.sh" "      - name: hostile step
        if: true
        run: bash bin/chain-hostile-step.sh"; wexpect caught "wiring: the hostile step carries an if (REQ-CHAIN-004-AC19: it runs in every build)" "$d"
d=$(mk w_gaterc); pymut "$(rel "$d")" "      - name: hostile step
        run: bash bin/chain-hostile-step.sh" "      - name: hostile step
        if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}
        run: bash bin/chain-hostile-step.sh"; wexpect caught "wiring: the hostile step runs on a release-candidate push only (it must run in every build)" "$d"
d=$(mk w_gatemode); pymut "$(rel "$d")" "      - name: hostile step
        run: bash bin/chain-hostile-step.sh" "      - name: hostile step
        if: \${{ inputs.mode != 'snapshot' }}
        run: bash bin/chain-hostile-step.sh"; wexpect caught "wiring: the hostile step is skipped in a snapshot build (the nightly and the pull-request proof build run it too)" "$d"
d=$(mk w_hostilejob); pymut "$(rel "$d")" "      - name: hostile step
        run: bash bin/chain-hostile-step.sh
      - uses: actions/upload-artifact@$sha # v7
        with:
          name: hostile-attempts
          path: attempts
" "" ; wexpect caught "wiring: the hostile step is gone from build-assemble" "$d"
d=$(mk w_hostilemoved); pymut "$(rel "$d")" "  sign:
    needs: build-assemble" "  other:
    runs-on: ubuntu-24.04
    steps:
      - run: bash bin/chain-hostile-step.sh
  sign:
    needs: build-assemble"; wexpect caught "wiring: the hostile step is also a step of another job" "$d"
d=$(mk w_noup); pymut "$(rel "$d")" "          name: hostile-attempts
          path: attempts" "          name: other
          path: attempts"; wexpect caught "wiring: attempts are not uploaded for the verifier" "$d"
d=$(mk w_verifyneeds); sed -i.bak 's/    needs: sign$/    needs: build-assemble/' "$(rel "$d")"; wexpect caught "wiring: hostile-verify does not need Sign" "$d"
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
d=$(mk w_hostileinput); pymut "$(rel "$d")" "on: {workflow_dispatch:" "on: {workflow_call: {inputs: {hostile: {type: boolean, default: false}}}, workflow_dispatch:"; wexpect caught "wiring: release.yml takes an input hostile (a switch that turns the hostile step off)" "$d"
d=$(mk w_buildnoif); pymut "$(rel "$d")" "    if: \${{ (github.event_name == 'push' && (startsWith(github.ref, 'refs/tags/v') || startsWith(github.ref, 'refs/heads/release/v'))) || inputs.dry-run == true || inputs.mode == 'snapshot' }}
    runs-on: ubuntu-24.04
    steps:
      - run: echo freeze" "    runs-on: ubuntu-24.04
    steps:
      - run: echo freeze"; wexpect caught "wiring: the build-freeze job has no gate: a dry run (or a push to main) would run the whole chain, or nothing is reachable (step-8 B-2)" "$d"
d=$(mk w_buildneeds); pymut "$(rel "$d")" "  build-freeze:
" "  build-freeze:
    needs: sign
"; wexpect caught "wiring: the build-freeze job needs another job (admission is Build's first step; a skipped needed job would skip the dry run)" "$d"
d=$(mk w_buildtagonly); pymut "$(rel "$d")" "(github.event_name == 'push' && (startsWith(github.ref, 'refs/tags/v') || startsWith(github.ref, 'refs/heads/release/v'))) || inputs.dry-run == true" "startsWith(github.ref, 'refs/tags/v')"; wexpect caught "wiring: the build gate is the tag test alone (a dry run on a branch would never run)" "$d"
d=$(mk w_buildnosnap); pymut "$(rel "$d")" " || inputs.mode == 'snapshot'" ""; wexpect caught "wiring: the build gate leaves out the snapshot call (the callers' snapshot build would never start)" "$d"
d=$(mk w_nosignrec); pymut "$(rel "$d")" " --policy policy.json" ""; wexpect caught "wiring: the key attempt is graded without Sign's record (a key found on the runner would be judged by its text)" "$d"
d=$(mk w_handsign); pymut "$(rel "$d")" "check-build-record --digests" "sign --check --signer cosign --digests"; wexpect caught "wiring: the hand-code attempt runs sign --check again (a signer in a job that must hold no signing right)" "$d"
d=$(mk w_pinstage); pymut "$(rel "$d")" "--stage sign --record attempts/forge_provenance" "--stage build --record attempts/forge_provenance"; wexpect caught "wiring: the forge attempt is verified as stage build, not as the Sign stage (pinned invocation)" "$d"
d=$(mk w_pinrec); pymut "$(rel "$d")" "--record attempts/mint_sign_cert.json --policy" "--record attempts/forge_provenance.json --policy"; wexpect caught "wiring: a case verifies another attempt's material (pinned --record)" "$d"
dupstep() { python3 - "$1" "$2" <<'PY2'
import sys
t = open(sys.argv[1]).read()
i = t.index("      - run: |\n          rc=0\n          python3 bin/chain-verify.py verify --stage sign --record attempts/mint_sign_cert.json")
j = t.index("      - run: |", i + 10)
open(sys.argv[1], "w").write(t[:j] + t[i:j].replace("mint_sign_cert", sys.argv[2]) + t[j:])
PY2
}
d=$(mk w_sixthstep); dupstep "$(rel "$d")" call_sign_from_other_workflow; wexpect caught "wiring: a sixth runtime case step (call_sign_from_other_workflow) in the verify job is refused: the list is exactly the five (G2)" "$d"
d=$(mk w_sixthfn); printf 'attempt_call_sign_from_other_workflow() { :; }\nattempt_call_sign_from_other_workflow\n' >> "$d/bin/chain-hostile-step.sh"; wexpect caught "wiring: the hostile step defines and calls a sixth attempt (G2)" "$d"
d=$(mk w_othersixth); printf 'attempt_sneak() { :; }\nattempt_sneak\n' >> "$d/bin/chain-hostile-step.sh"; wexpect caught "wiring: the hostile step defines and calls any other added attempt" "$d"
d=$(mk w_othersteps); dupstep "$(rel "$d")" extra_case; wexpect caught "wiring: any other added case step in the verify job is refused" "$d"
d=$(mk w_dropmint); python3 - "$(rel "$d")" <<'PY2'
import sys,re
t=open(sys.argv[1]).read()
i=t.index("      - run: |\n          rc=0\n          python3 bin/chain-verify.py verify --stage sign --record attempts/mint_sign_cert.json")
j=t.index("      - run: |",i+10)
open(sys.argv[1],"w").write(t[:i]+t[j:])
PY2
wexpect caught "wiring: dropping the mint_sign_cert step from the verify job is refused (only the sixth may go, by name)" "$d"
d=$(mk w_pinpol); pymut "$(rel "$d")" "--stage sign --record attempts/mint_sign_cert.json --policy policy.json" "--stage sign --record attempts/mint_sign_cert.json --policy /dev/null"; wexpect caught "wiring: an attempt is verified against a different policy than the tag's" "$d"
d=$(mk w_pinkind); pymut "$(rel "$d")" "--kind key --file attempts/read_sign_key.txt --policy policy.json" "--kind token --file attempts/read_sign_key.txt"; wexpect caught "wiring: the key attempt is judged with the token kind (pinned hostile-material)" "$d"
d=$(mk w_stderr); pymut "$(rel "$d")" "--stderr /tmp/mint_sign_cert.err" "--stderr /tmp/other.err"; wexpect caught "wiring: hostile-row reads a different stderr file than the verifier wrote" "$d"
d=$(mk w_other); python3 - "$(rel "$d")" <<'PY'
import sys
t = open(sys.argv[1]).read() + "  extra:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: gh pr create\n"
open(sys.argv[1], "w").write(t)
PY
wexpect caught "wiring: any other job (extra) without the dry-run gate still runs in a dry run" "$d"
d=$(mk w_okjobs); python3 - "$(rel "$d")" <<'PY'
import sys
t = open(sys.argv[1]).read() + "  rebuild-apk:\n    needs: build-assemble\n    runs-on: ubuntu-24.04\n    steps:\n      - run: true\n"
open(sys.argv[1], "w").write(t)
PY
wexpect ok "wiring: the Rebuild job runs in a dry run, as does check-govulncheck with its guard (allowlist: build-freeze, build-apk, build-assemble, rebuild-apk, rebuild-assemble, check-govulncheck, check, persona-uat-rc, hostile-*)" "$d"
d=$(mk w_tracked); echo '{"attempts":[]}' > "$d/hostile-results.json"; wexpect caught "wiring: a hostile-results.json is checked into the tree" "$d"
d=$(mk w_nodry); sed -i.bak "s/if: .*!inputs.dry-run && startsWith(github.ref, 'refs\/tags\/v') }}\$/if: true/" "$(rel "$d")"; wexpect caught "wiring: the release job still runs in a dry run" "$d"
d=$(mk w_orgate); sed -i.bak "s/!inputs.dry-run \&\& startsWith(github.ref/!inputs.dry-run || true \&\& startsWith(github.ref/" "$(rel "$d")"; wexpect caught "wiring: a dry-run gate with || true" "$d"
d=$(mk w_noscript); rm "$d/bin/chain-hostile-step.sh"; wexpect caught "wiring: the hostile script is missing" "$d"
d=$(mk w_missatt); sed -i.bak '/^attempt_read_sign_key$/d' "$d/bin/chain-hostile-step.sh"; wexpect caught "wiring: one of the attempts is never called" "$d"
d=$(mk w_missother); sed -i.bak '/^attempt_forge_provenance$/d' "$d/bin/chain-hostile-step.sh"; wexpect caught "wiring: the forge attempt is never made" "$d"
d=$(mk w_selfgrade); echo 'echo "{\"outcome\": \"refused\"}" > results.json' >> "$d/bin/chain-hostile-step.sh"; wexpect caught "wiring: the hostile step grades itself" "$d"
d=$(mk w_callsverifier); echo 'python3 bin/chain-verify.py verify --record x' >> "$d/bin/chain-hostile-step.sh"; wexpect caught "wiring: the hostile step runs the verifier itself" "$d"
d=$(mk w_comment); echo '# a refused attempt is written by the verifier, not here' >> "$d/bin/chain-hostile-step.sh"; wexpect ok "wiring: the word refused in a comment is fine (comments are not code)" "$d"
d=$(mk w_extra); pymut "$(rel "$d")" "      - run: python3 bin/chain-verify.py policy make" "      - run: ': > attempts/read_sign_token.txt'
      - run: python3 bin/chain-verify.py policy make"; wexpect caught "wiring: an extra step blanks an attempt's material before the verifiers run (allowlist)" "$d"
d=$(mk w_nopolicy); python3 - "$(rel "$d")" <<'PY'
import re, sys
t = open(sys.argv[1]).read(); t = re.sub(r"      - run: python3 bin/chain-verify.py policy make[^\n]*\n", "", t, count=1); open(sys.argv[1], "w").write(t)
PY
wexpect caught "wiring: no policy is made in the verify job (a tracked or permissive policy.json would be used)" "$d"
d=$(mk w_wrongref); pymut "$(rel "$d")" '--ref "$GITHUB_REF"' '--ref refs/tags/v0.0.0'; wexpect caught "wiring: the policy is made for a fixed ref, not the run's own (it would refuse everything)" "$d"
d=$(mk w_tpl); pymut "$(rel "$d")" "--template .github/policy/release-policy.template.json" "--template permissive.json"; wexpect caught "wiring: the policy is made from some other template" "$d"
d=$(mk w_policytracked); echo '{}' > "$d/policy.json"; wexpect caught "wiring: a policy.json is committed to the tree" "$d"
d=$(mk w_nowb); python3 - "$(rel "$d")" <<'PY'
import sys
t = open(sys.argv[1]).read().replace("      - uses: actions/download-artifact@" + "a" * 40 + " # v8\n        with: {name: signed-witness-build, path: witness-build}\n", "", 1)
open(sys.argv[1], "w").write(t)
PY
wexpect caught "wiring: Build's verified record (witness-build) is not downloaded" "$d"
d=$(mk w_unsignedbuild); pymut "$(rel "$d")" "name: signed-witness-build, path: witness-build" "name: witness-build, path: witness-build"; wexpect caught "R1 (row-78 pass): hostile-verify downloads the unsigned witness-build (its .local.json record is refused at stage build, not sign)" "$d"
d=$(mk w_bradv); pymut "$(rel "$d")" "--build-record witness-build/build-collection.json" "--build-record attempts/build-collection.json"; wexpect caught "wiring: hand_sign_code checks against the record the HOSTILE step supplied, not Build's verified one" "$d"
d=$(mk w_noprov); python3 - "$(rel "$d")" <<'PY'
import sys
t = open(sys.argv[1]).read().replace("      - uses: actions/download-artifact@" + "a" * 40 + " # v8\n        with: {name: provenance, path: provenance}\n", "", 1)
open(sys.argv[1], "w").write(t)
PY
wexpect caught "wiring: this run's genuine Sign provenance is not downloaded (no positive control possible)" "$d"
d=$(mk w_noctl); python3 - "$(rel "$d")" <<'PY'
import re, sys
t = open(sys.argv[1]).read()
t = re.sub(r"      - run: \|\n          rc=0\n          python3 bin/chain-verify.py verify --stage sign --record provenance/provenance.json[^\n]*\n[^\n]*positive_control[^\n]*\n", "", t, count=1)
open(sys.argv[1], "w").write(t)
PY
wexpect caught "wiring: the positive control step is missing" "$d"
d=$(mk w_ctlrec); pymut "$(rel "$d")" "--record provenance/provenance.json" "--record attempts/forge_provenance.json"; wexpect caught "wiring: the positive control verifies an attempt's file, not this run's genuine provenance" "$d"
d=$(mk w_indef); pymut "$(rel "$d")" "on: {workflow_dispatch:" "on: {workflow_call: {inputs: {hostile: {type: boolean, default: true}}}, workflow_dispatch:"; wexpect caught "wiring: a hostile input that defaults to true" "$d"
d=$(mk w_opennm); python3 - "$(rel "$d")" <<'PY'
import sys
t = open(sys.argv[1]).read() + "  build-apk:\n    needs: build-freeze\n    uses: ./.github/workflows/stage-promote.yml\n"
open(sys.argv[1], "w").write(t)
PY
wexpect caught "wiring: a job named build-apk that calls a workflow is not exempt from the dry-run gate (open names may call nothing)" "$d"
d=$(mk w_hostilename); python3 - "$(rel "$d")" <<'PY'
import sys
t = open(sys.argv[1]).read() + "  hostile-publish:\n    uses: ./.github/workflows/persona-uat.yml\n"
open(sys.argv[1], "w").write(t)
PY
wexpect caught "wiring: a hostile-* named job that calls a workflow runs in a dry run" "$d"
d=$(mk w_hostileperm); python3 - "$(rel "$d")" <<'PY'
import sys
t = open(sys.argv[1]).read() + "  hostile-x:\n    runs-on: ubuntu-24.04\n    permissions: {contents: write}\n    steps:\n      - run: true\n"
open(sys.argv[1], "w").write(t)
PY
wexpect caught "wiring: a hostile-* named job with write permission" "$d"
d=$(mk w_notrans); sed -i.bak 's/# transcript: //' "$d/bin/chain-hostile-step.sh"; wexpect caught "wiring: the material attempts do not write a transcript line" "$d"
d=$(mk w_nogatedecide2); python3 - "$(rel "$d")" <<'PY'
import sys
t = open(sys.argv[1]).read().replace("!inputs.dry-run && startsWith(github.ref", "inputs.dry-run == false && startsWith(github.ref", 1)
open(sys.argv[1], "w").write(t)
PY
wexpect caught "wiring: the promotion job's gate is a differently-written condition, not the exact !inputs.dry-run conjunct" "$d"
# ---- the tag jobs of the automatic patch release (REQ-REL-009) are known BY NAME: decide, sign-tag, cut and patch-notes are release.yml's inline jobs. sign-tag is not one of the chain's Sign jobs, and cut and
# patch-notes are not pulled into the set of jobs after Sign; decide's if is pinned exactly; every other job stays off in a run on main ---------------------------------------------------------
DEC_SNAP="inputs.mode != 'snapshot' && github.ref == 'refs/heads/main'"
DEC_WFREF="!inputs.dry-run && startsWith(github.workflow_ref, format('{0}/.github/workflows/release.yml@', github.repository)) }}"
DEC_DRY="github.event_name != 'workflow_dispatch' && !inputs.dry-run && "
tjmut() { # tjmut NAME LABEL OLD NEW : the fixture's one text OLD replaced by NEW; the wiring judge must refuse it
  local d; d=$(mk "$1"); pymut "$(rel "$d")" "$3" "$4"; wexpect caught "wiring: $2" "$d"
}
tjmut w_tj_snap "decide's if without the snapshot term (a snapshot call on main would decide)" "$DEC_SNAP" "github.ref == 'refs/heads/main'"
tjmut w_tj_wfref "decide's if without the workflow_ref term (guard S's text: another workflow's call on main would decide)" "$DEC_WFREF" "!inputs.dry-run }}"
tjmut w_tj_dry "decide's if without !inputs.dry-run" "$DEC_DRY" "github.event_name != 'workflow_dispatch' && "
tjmut w_tj_disp "decide's if without the dispatch exclusion" "github.event_name != 'workflow_dispatch' && !inputs.dry-run" "!inputs.dry-run"
tjmut w_tj_main "decide's if without the main ref (a tag push would decide)" "inputs.mode != 'snapshot' && github.ref == 'refs/heads/main' && github.event_name != 'workflow_dispatch'" "inputs.mode != 'snapshot' && github.event_name != 'workflow_dispatch'"
tjmut w_tj_or "decide's if with an || that lets a tag push through" "format('{0}/.github/workflows/release.yml@', github.repository)) }}
    runs-on: ubuntu-24.04
    steps:
      - run: echo decide" "format('{0}/.github/workflows/release.yml@', github.repository)) || startsWith(github.ref, 'refs/tags/v') }}
    runs-on: ubuntu-24.04
    steps:
      - run: echo decide"
tjmut w_tj_decneeds "decide needs another job" "  decide:
    if:" "  decide:
    needs: build-freeze
    if:"
tjmut w_tj_signneeds "sign-tag needs more than decide" "  sign-tag:
    needs: decide" "  sign-tag:
    needs: [decide, build-assemble]"
tjmut w_tj_signnone "sign-tag needs nothing" "  sign-tag:
    needs: decide
" "  sign-tag:
"
tjmut w_tj_cutneeds1 "cut does not need sign-tag (another needs)" "  cut:
    needs: [decide, sign-tag]" "  cut:
    needs: [decide]"
tjmut w_tj_cutneeds2 "cut needs another job beside decide and sign-tag" "  cut:
    needs: [decide, sign-tag]" "  cut:
    needs: [decide, sign-tag, build-freeze]"
tjmut w_tj_pnneeds1 "patch-notes does not need cut (another needs)" "  patch-notes:
    needs: [decide, cut]" "  patch-notes:
    needs: [decide]"
tjmut w_tj_pnneeds2 "patch-notes needs sign-tag instead of cut" "  patch-notes:
    needs: [decide, cut]" "  patch-notes:
    needs: [decide, sign-tag]"
tjmut w_tj_pnneeds3 "patch-notes needs another job beside decide and cut" "  patch-notes:
    needs: [decide, cut]" "  patch-notes:
    needs: [decide, cut, sign]"
tjmut w_tj_cutif1 "cut runs whatever decide said (if: true)" "  cut:
    needs: [decide, sign-tag]
    if: \${{ needs.decide.outputs.tag != '' }}" "  cut:
    needs: [decide, sign-tag]
    if: true"
tjmut w_tj_cutif2 "cut runs after a failed sign-tag (a status function in its if)" "  cut:
    needs: [decide, sign-tag]
    if: \${{ needs.decide.outputs.tag != '' }}" "  cut:
    needs: [decide, sign-tag]
    if: \${{ always() && needs.decide.outputs.tag != '' }}"
tjmut w_tj_cutif3 "cut has no if" "  cut:
    needs: [decide, sign-tag]
    if: \${{ needs.decide.outputs.tag != '' }}
" "  cut:
    needs: [decide, sign-tag]
"
tjmut w_tj_pnif "patch-notes with another if" "  patch-notes:
    needs: [decide, cut]
    if: \${{ needs.decide.outputs.tag != '' }}" "  patch-notes:
    needs: [decide, cut]
    if: \${{ needs.decide.result == 'success' }}"
tjmut w_tj_signif "sign-tag with another if" "  sign-tag:
    needs: decide
    if: \${{ needs.decide.outputs.tag != '' }}" "  sign-tag:
    needs: decide
    if: \${{ needs.decide.outputs.tag == 'x' }}"
tjmut w_tj_signuses "sign-tag is a call of another workflow" "  sign-tag:
    needs: decide" "  sign-tag:
    uses: ./.github/workflows/stage-sign.yml
    needs: decide"
d=$(mk w_tj_gone); python3 - "$(rel "$d")" <<'PY'
import re, sys
t = open(sys.argv[1]).read(); t = re.sub(r"  patch-notes:\n.*\Z", "", t, flags=re.S); open(sys.argv[1], "w").write(t)
PY
wexpect caught "wiring: patch-notes is gone from release.yml (the four tag jobs are known by name)" "$d"
tjmut w_tj_cgv "check-govulncheck without its ref guard (back to inputs.mode != 'snapshot' only: it has no needs and runs on every push to main)" "    if: \${{ inputs.mode != 'snapshot' && ((github.event_name == 'push' && (startsWith(github.ref, 'refs/tags/v') || startsWith(github.ref, 'refs/heads/release/v'))) || inputs.dry-run == true) }}
    runs-on: ubuntu-24.04
    steps:
      - run: echo govulncheck" "    if: \${{ inputs.mode != 'snapshot' }}
    runs-on: ubuntu-24.04
    steps:
      - run: echo govulncheck"
tjmut w_tj_cgv2 "check-govulncheck with no if at all" "    if: \${{ inputs.mode != 'snapshot' && ((github.event_name == 'push' && (startsWith(github.ref, 'refs/tags/v') || startsWith(github.ref, 'refs/heads/release/v'))) || inputs.dry-run == true) }}
    runs-on: ubuntu-24.04
    steps:
      - run: echo govulncheck" "    runs-on: ubuntu-24.04
    steps:
      - run: echo govulncheck"
tjmut w_tj_cgv3 "check-govulncheck with a guard that still lets a main push through (only the dispatch is kept out)" "    if: \${{ inputs.mode != 'snapshot' && ((github.event_name == 'push' && (startsWith(github.ref, 'refs/tags/v') || startsWith(github.ref, 'refs/heads/release/v'))) || inputs.dry-run == true) }}
    runs-on: ubuntu-24.04
    steps:
      - run: echo govulncheck" "    if: \${{ inputs.mode != 'snapshot' && github.event_name != 'workflow_dispatch' }}
    runs-on: ubuntu-24.04
    steps:
      - run: echo govulncheck"
d=$(mk w_tj_newjob1); printf '  scan-main:\n    if: ${{ inputs.mode != '"'"'snapshot'"'"' }}\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo scan\n' >> "$(rel "$d")"
wexpect caught "wiring: a new job whose if has no ref guard (it would run on every push to main)" "$d"
d=$(mk w_tj_newjob2); printf '  scan-main:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo scan\n' >> "$(rel "$d")"
wexpect caught "wiring: a new job with no needs and no if (it would run on every push to main)" "$d"
d=$(mk w_tj_newjob3); printf '  scan-main:\n    if: ${{ !inputs.dry-run }}\n    needs: decide\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo scan\n' >> "$(rel "$d")"
wexpect caught "wiring: a new job after decide whose if only keeps a dry run out (it would run on a push to main)" "$d"
d=$(mk w_tj_newjob4); printf '  sign-notes:\n    needs: decide\n    if: ${{ needs.decide.outputs.tag != '"'"''"'"' }}\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo sign\n' >> "$(rel "$d")"
wexpect caught "wiring: a new sign* job named like a tag job (only sign, sign-rebuild, sign-check, sign-release and the tag job sign-tag may be named sign*)" "$d"
d=$(mk w_tj_open); printf '  rebuild-apk:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo rebuild\n' >> "$(rel "$d")"
wexpect caught "wiring: a job of the dry-run allowlist with no needs and no ref guard (rebuild-apk) would run on every push to main: only the evaluation of the run on main sees it" "$d"
d=$(mk w_tj_after); pymut "$(rel "$d")" "  promotion:
    if: \${{ !inputs.dry-run && startsWith(github.ref, 'refs/tags/v') }}
    needs: [sign, hostile-verdict]" "  promotion:
    if: \${{ !inputs.dry-run && startsWith(github.ref, 'refs/tags/v') }}
    needs: [sign, hostile-verdict, cut]"; wexpect ok "wiring: a chain job that needs cut keeps its own tag guard (cut and patch-notes are not pulled into the set of jobs after Sign; sign-tag is not a Sign job)" "$d"
d=$(mk w_tj_after2); pymut "$(rel "$d")" "  promotion:
    if: \${{ !inputs.dry-run && startsWith(github.ref, 'refs/tags/v') }}
    needs: [sign, hostile-verdict]" "  promotion:
    if: \${{ !inputs.dry-run }}
    needs: [sign, hostile-verdict]"; wexpect caught "wiring: a job after Sign without the positive tag conjunct is still refused with the tag jobs present" "$d"
# ---- key allowlists, dry-run and tag gates, Release's policy step ---------------------------------------------------
d=$(mk w_jobenv); pymut "$(rel "$d")" "    needs: sign
    runs-on: ubuntu-24.04
    permissions: {contents: read}
    steps:
      - uses: actions/checkout" "    needs: sign
    env: {PYTHONPATH: attempts}
    runs-on: ubuntu-24.04
    permissions: {contents: read}
    steps:
      - uses: actions/checkout"; wexpect caught "wiring: hostile-verify has a job env (PYTHONPATH=attempts would run a planted sitecustomize.py instead of the pinned text)" "$d"
d=$(mk w_jobdef); pymut "$(rel "$d")" "    needs: sign
    runs-on: ubuntu-24.04
    permissions: {contents: read}
    steps:
      - uses: actions/checkout" "    needs: sign
    defaults: {run: {shell: 'bash -c \"true; bash {0}\"'}}
    runs-on: ubuntu-24.04
    permissions: {contents: read}
    steps:
      - uses: actions/checkout"; wexpect caught "wiring: hostile-verify has job defaults (a shell that wraps every run step)" "$d"
d=$(mk w_stepenv); pymut "$(rel "$d")" '      - run: python3 bin/chain-verify.py policy make' '      - env: {PYTHONPATH: attempts}
        run: python3 bin/chain-verify.py policy make'; wexpect caught "wiring: a step env on the policy step" "$d"
d=$(mk w_stepshell); pymut "$(rel "$d")" '      - run: python3 bin/chain-verify.py policy make' '      - shell: "bash -c '"'"'true'"'"'"
        run: python3 bin/chain-verify.py policy make'; wexpect caught "wiring: a step shell override" "$d"
d=$(mk w_stepwd); pymut "$(rel "$d")" '      - run: python3 bin/chain-verify.py policy make' '      - working-directory: attempts
        run: python3 bin/chain-verify.py policy make'; wexpect caught "wiring: a step working-directory (the pinned relative paths would resolve elsewhere)" "$d"
d=$(mk w_stepcoe); pymut "$(rel "$d")" '      - run: python3 bin/chain-verify.py policy make' '      - continue-on-error: true
        run: python3 bin/chain-verify.py policy make'; wexpect caught "wiring: a step continue-on-error" "$d"
d=$(mk w_topenv); pymut "$(rel "$d")" "jobs:" "env: {PYTHONPATH: attempts}
jobs:"; wexpect caught "wiring: release.yml has a top-level env" "$d"
d=$(mk w_topdef); pymut "$(rel "$d")" "jobs:" "defaults: {run: {shell: bash}}
jobs:"; wexpect caught "wiring: release.yml has top-level defaults" "$d"
d=$(mk w_hvnoif); python3 - "$(rel "$d")" <<'PY'
import sys
t = open(sys.argv[1]).read().replace("  hostile-verify:\n    if: ${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}\n", "  hostile-verify:\n", 1)
open(sys.argv[1], "w").write(t)
PY
wexpect caught "wiring: hostile-verify has no dry-run gate (a real tag run would fail its download and block the release)" "$d"
d=$(mk w_hvor); pymut "$(rel "$d")" "  hostile-verdict:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}" "  hostile-verdict:
    if: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') || true }}"; wexpect caught "wiring: hostile-verdict's gate is 'inputs.dry-run || true'" "$d"
d=$(mk w_notag); pymut "$(rel "$d")" " && startsWith(github.ref, 'refs/tags/v')" ""; wexpect caught "wiring: a job after Sign (promotion) has no tag conjunct (a branch dispatch with dry-run unchecked could reach it)" "$d"
d=$(mk w_tagor); pymut "$(rel "$d")" "!inputs.dry-run && startsWith(github.ref, 'refs/tags/v')" "!inputs.dry-run || startsWith(github.ref, 'refs/tags/v')"; wexpect caught "wiring: the tag conjunct is joined with || " "$d"
d=$(mk w_tagneg); pymut "$(rel "$d")" "!inputs.dry-run && startsWith(github.ref, 'refs/tags/v')" "!inputs.dry-run && !startsWith(github.ref, 'refs/tags/v')"; wexpect caught "wiring: the tag conjunct is NEGATED (!startsWith): promotion would run on branches only" "$d"
d=$(mk w_tagfalse); pymut "$(rel "$d")" "!inputs.dry-run && startsWith(github.ref, 'refs/tags/v')" "!inputs.dry-run && startsWith(github.ref, 'refs/tags/v') == false"; wexpect caught "wiring: the tag conjunct is compared (== false)" "$d"
d=$(mk w_tagparen); pymut "$(rel "$d")" "!inputs.dry-run && startsWith(github.ref, 'refs/tags/v')" "!(true && !inputs.dry-run && startsWith(github.ref, 'refs/tags/v') && true)"; wexpect caught "wiring: the whole condition is negated by a grouping parenthesis (round 8, Opus R3)" "$d"
d=$(mk w_gateneg); pymut "$(rel "$d")" "!inputs.dry-run && startsWith(github.ref, 'refs/tags/v')" "inputs.dry-run && startsWith(github.ref, 'refs/tags/v')"; wexpect caught "wiring: the dry-run conjunct is not negated (promotion would run ONLY in a dry run)" "$d"
d=$(mk w_pf_ok); pymut "$(rel "$d")" "  promotion:" "  patch-failed:
    if: \${{ always() && (contains(needs.*.result, 'failure') || needs.release.result == 'cancelled') && startsWith(github.ref, 'refs/tags/v') && github.event_name != 'workflow_dispatch' && !inputs.dry-run }}
    needs: [sign]
    runs-on: ubuntu-latest
    steps:
      - run: true
  promotion:"; wexpect ok "wiring: patch-failed with the cache#554 condition (a failed job, or a cancelled release, on a tag run) passes" "$d"
d=$(mk w_pf_notag); pymut "$(rel "$d")" "  promotion:" "  patch-failed:
    if: \${{ always() && (contains(needs.*.result, 'failure') || needs.release.result == 'cancelled') && github.event_name != 'workflow_dispatch' && !inputs.dry-run }}
    needs: [sign]
    runs-on: ubuntu-latest
    steps:
      - run: true
  promotion:"; wexpect caught "wiring: patch-failed in the cache#554 form without the tag conjunct (a branch run could reach it)" "$d"
d=$(mk w_pf_negtag); pymut "$(rel "$d")" "  promotion:" "  patch-failed:
    if: \${{ always() && (contains(needs.*.result, 'failure') || needs.release.result == 'cancelled') && !startsWith(github.ref, 'refs/tags/v') && !inputs.dry-run }}
    needs: [sign]
    runs-on: ubuntu-latest
    steps:
      - run: true
  promotion:"; wexpect caught "wiring: patch-failed in the cache#554 form with the tag conjunct negated" "$d"
d=$(mk w_pf_nodry); pymut "$(rel "$d")" "  promotion:" "  patch-failed:
    if: \${{ always() && (contains(needs.*.result, 'failure') || needs.release.result == 'cancelled') && startsWith(github.ref, 'refs/tags/v') }}
    needs: [sign]
    runs-on: ubuntu-latest
    steps:
      - run: true
  promotion:"; wexpect caught "wiring: patch-failed in the cache#554 form without !inputs.dry-run" "$d"
d=$(mk w_pf_orrest); pymut "$(rel "$d")" "  promotion:" "  patch-failed:
    if: \${{ always() && (contains(needs.*.result, 'failure') || needs.release.result == 'cancelled') && startsWith(github.ref, 'refs/tags/v') && !inputs.dry-run || true }}
    needs: [sign]
    runs-on: ubuntu-latest
    steps:
      - run: true
  promotion:"; wexpect caught "wiring: patch-failed in the cache#554 form with a trailing || true" "$d"
d=$(mk w_pf_orgrp); pymut "$(rel "$d")" "  promotion:" "  patch-failed:
    if: \${{ always() && (contains(needs.*.result, 'failure') || needs.release.result == 'cancelled' || startsWith(github.ref, 'refs/tags/v')) && startsWith(github.ref, 'refs/tags/v') && !inputs.dry-run }}
    needs: [sign]
    runs-on: ubuntu-latest
    steps:
      - run: true
  promotion:"; wexpect caught "wiring: patch-failed whose group has a third or-term (the tag test hidden in the group)" "$d"
d=$(mk w_pf_othergrp); pymut "$(rel "$d")" "  promotion:" "  patch-failed:
    if: \${{ always() && (contains(needs.*.result, 'failure') || true) && startsWith(github.ref, 'refs/tags/v') && !inputs.dry-run }}
    needs: [sign]
    runs-on: ubuntu-latest
    steps:
      - run: true
  promotion:"; wexpect caught "wiring: patch-failed with a different grouped or-condition (|| true)" "$d"
d=$(mk w_pf_negrp); pymut "$(rel "$d")" "  promotion:" "  patch-failed:
    if: \${{ always() && !(contains(needs.*.result, 'failure') || needs.release.result == 'cancelled') && startsWith(github.ref, 'refs/tags/v') && !inputs.dry-run }}
    needs: [sign]
    runs-on: ubuntu-latest
    steps:
      - run: true
  promotion:"; wexpect caught "wiring: patch-failed with the group negated" "$d"
d=$(mk w_pf_negsp2); pymut "$(rel "$d")" "  promotion:" "  patch-failed:
    if: \${{ always() && !  (contains(needs.*.result, 'failure') || needs.release.result == 'cancelled') && startsWith(github.ref, 'refs/tags/v') && !inputs.dry-run }}
    needs: [sign]
    runs-on: ubuntu-latest
    steps:
      - run: true
  promotion:"; wexpect caught "wiring: patch-failed with the group negated by ! and two spaces" "$d"
d=$(mk w_pf_negtab); pymut "$(rel "$d")" "  promotion:" "  patch-failed:
    if: \${{ always() && !	(contains(needs.*.result, 'failure') || needs.release.result == 'cancelled') && startsWith(github.ref, 'refs/tags/v') && !inputs.dry-run }}
    needs: [sign]
    runs-on: ubuntu-latest
    steps:
      - run: true
  promotion:"; wexpect caught "wiring: patch-failed with the group negated by ! and a tab" "$d"
d=$(mk w_pf_cmpfalse); pymut "$(rel "$d")" "  promotion:" "  patch-failed:
    if: \${{ always() && (contains(needs.*.result, 'failure') || needs.release.result == 'cancelled') == false && startsWith(github.ref, 'refs/tags/v') && !inputs.dry-run }}
    needs: [sign]
    runs-on: ubuntu-latest
    steps:
      - run: true
  promotion:"; wexpect caught "wiring: patch-failed with the group compared to false" "$d"
d=$(mk w_pf_format); pymut "$(rel "$d")" "  promotion:" "  patch-failed:
    if: \${{ always() && !format('{0}', (contains(needs.*.result, 'failure') || needs.release.result == 'cancelled')) && startsWith(github.ref, 'refs/tags/v') && !inputs.dry-run }}
    needs: [sign]
    runs-on: ubuntu-latest
    steps:
      - run: true
  promotion:"; wexpect caught "wiring: patch-failed with the group wrapped in format()" "$d"
d=$(mk w_pf_literal); pymut "$(rel "$d")" "  promotion:" "  patch-failed:
    if: \${{ always() && (contains(needs.*.result, 'failure') || needs.release.result == 'cancelled') && TAGCALL && !inputs.dry-run }}
    needs: [sign]
    runs-on: ubuntu-latest
    steps:
      - run: true
  promotion:"; wexpect caught "wiring: a literal placeholder word stands in for the tag test" "$d"
d=$(mk w_pmref); pymut "$d/bin/release-verify.sh" '--tag "$GITHUB_REF_NAME"' '--ref "$GITHUB_REF"'; wexpect caught "wiring: Release makes its policy with --ref (a branch dry-run record would be accepted)" "$d"
d=$(mk w_pmnone); printf 'set -euo pipefail\necho publish\n' > "$d/bin/release-verify.sh"; wexpect caught "wiring: Release never makes a policy" "$d"
d=$(mk w_pmother); printf 'on: {workflow_call: {}}\njobs:\n  x:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: python3 bin/chain-verify.py policy make --template t --ref "$GITHUB_REF" --out p.json\n' > "$d/.github/workflows/ci.yml"; wexpect caught "wiring: another workflow file makes a policy with --ref" "$d"
d=$(mk w_rekorstub); pymut "$(rel "$d")" "--policy policy.json 2> /tmp/positive_control.err" "--policy policy.json --rekor-stub provenance/provenance.rekor.json 2> /tmp/positive_control.err"; wexpect caught "wiring: the positive control given the Rekor stub is not the pinned three-line shape (the stub is not part of the control)" "$d"
d=$(mk w_nowflag); pymut "$(rel "$d")" "--record attempts/forge_provenance.json --policy policy.json" "--record attempts/forge_provenance.json --policy policy.json --now \"\$NOW\""; wexpect caught "wiring: an attempt's verify line takes --now from the environment (the pinned line has none)" "$d"
wexpect ok "the real repository's hostile wiring (RED until PR 1 implements it)" "$root"
# AC5's runtime proof has a fixed place: the rc-tag run is
# cut on main after the cutover pull request has merged, its green run is linked, and no final or patch tag is cut before the marker of REQ-CHAIN-001-AC6 records it;
# the REQ-CHAIN-001 notes carry the CUTOVER CHECKLIST line so it cannot be forgotten
python3 - "$root/requirements/requirements.yaml" <<'PY' 2>&1 && ok "001-AC5 the AC names when its GitHub proof runs (a signed rc-tag run on main after the cutover pull request, before any final or patch tag) and the notes carry the CUTOVER CHECKLIST line" || bad "001-AC5 the AC text or the CUTOVER CHECKLIST note does not place the GitHub proof"
import sys, yaml
reqs = {r["id"]: r for r in yaml.safe_load(open(sys.argv[1]))["requirements"]}
r = reqs["REQ-CHAIN-001"]
then = next(a for a in r["acceptance_criteria"] if a["id"] == "REQ-CHAIN-001-AC5")["then"]
given = next(a for a in r["acceptance_criteria"] if a["id"] == "REQ-CHAIN-001-AC5")["given"]
assert "a run on GitHub of the chain on a signed release-candidate tag (v0.3.0-rcN)" in given, "AC5 given does not name the signed rc-tag run"
when = next(a for a in r["acceptance_criteria"] if a["id"] == "REQ-CHAIN-001-AC5")["when"]
# five runtime cases; the rc-tag run is cut on main AFTER the cutover merge; the marker of AC6 gates every final or patch tag
for words in ("as five separate cases each on its own", "and to forge provenance that Release would accept (the sixth case, getting provenance accepted from a second workflow that calls release.yml, is not a runtime case: scan.yml and main-candidate-rescan.yml call it only in snapshot mode, where every sign job is guarded off, and a called release.yml's token names the caller's file; it is judged by the guard cases of the static judge and by the offline hostile test, which is a stated limit of this proof)"):
    assert words in when, "AC5 when lacks: " + words
assert "six separate cases" not in when and "throwaway commit" not in when, "AC5 when still has the six-case wording"
for words in ("is cut on main after the cutover pull request has merged, must be green and its run linked before any final or patch tag is cut on main",
              "until a recorded green rc-tag run of those same chain files (the workflows, bin/ and .github/policy/ files the chain uses, identical bytes) exists as the committed marker of REQ-CHAIN-001-AC6, no patch decision proceeds",
              "each of the five runtime cases is judged by the verifier invocation pinned for it", "a branch dry run does not satisfy this AC",
              "bin/chain-hostile-test.sh", "the wiring tests judge the files"):
    assert words in then, "AC5 lacks: " + words
assert "before the cutover pull request merges chain-v030 to main" not in then and "each of the six cases" not in then, "AC5 then still has the old order or six cases"
a6 = next(a for a in r["acceptance_criteria"] if a["id"] == "REQ-CHAIN-001-AC6")
assert a6["given"] == "a patch tag to be decided on main", "AC6 given"
assert a6["when"] == "the patch decision reads .github/policy/rc-proof.json (the marker)", "AC6 when"
for words in ("it refuses (naming the marker) unless the marker names an rc tag, the run id of its green chain run, and the sha256 over the exact bytes of the chain files at the tag's commit (the same file set as AC5)",
              "bin/chain-verify.py against the rc tag's own identities", "an rc tag that is not an ancestor of the commit, an unreadable marker, or a missing one is refused, never skipped"):
    assert words in a6["then"], "AC6 lacks: " + words
assert a6["verification"] == {"method": "ci-workflow", "release_blocking": True} and a6["status"] == "approved", "AC6 verification/status"
assert "linked in the pull request before the pull request merges" not in then, "AC5 still ties the proof to this pull request"
assert "CUTOVER CHECKLIST" in r["notes"], "REQ-CHAIN-001 notes lack the CUTOVER CHECKLIST line"
# the cutover merge first with only KR-CUTOVER left, then the maintainers' rc tag on main, then the marker pull request, which removes KR-CUTOVER
for words in ("CUTOVER CHECKLIST (order accepted Oct 12)", "bin/chain-known-red.py empty-except KR-CUTOVER", "it does not wait for an rc run", "the maintainers sign a release-candidate tag vX.Y.Z-rcN on main's merge commit",
              "the marker pull request of REQ-CHAIN-001-AC6", "it removes KR-CUTOVER", "the patch decision refuses every patch tag"):
    assert words in r["notes"], "REQ-CHAIN-001 notes lack the accepted checklist order: " + words
assert "does not merge without a green rc-tag run of the same commit's chain files" not in r["notes"], "REQ-CHAIN-001 notes still say the cutover waits for an rc run"
assert "GitHub dry run is green" not in r["notes"], "REQ-CHAIN-001 notes still make a branch dry run the proof"
PY
# the key attempt is EXECUTED, not only read. The real function is cut out of the hostile step and run in a
# controlled home and runner
# temp directory holding one planted private key; its transcript must carry the number of files it searched and the public-key hash of that planted key,
# and a body that prints a constant transcript (a search that never happens) must be told apart from it.
kd="$work/keyprobe"; rm -rf "$kd"; mkdir -p "$kd/home" "$kd/rt" "$kd/run"
if openssl genpkey -algorithm ed25519 -out "$kd/home/planted.pem" > /dev/null 2>&1; then
  want_h=$(openssl pkey -in "$kd/home/planted.pem" -pubout -outform DER 2> /dev/null | sha256sum | cut -d' ' -f1)
  printf 'plain text\n' > "$kd/rt/other.txt"
  fn_of() { awk '/^attempt_read_sign_key\(\) \{/{p=1} p{print} p&&/^\}/{exit}' "$1"; }
  run_key() { # run_key SCRIPT-TEXT-FILE: the function body of that file, run with the probe directories as its search roots
    rm -rf "$kd/run/attempts"; mkdir -p "$kd/run/attempts"
    ( cd "$kd/run" && bash -c "$(fn_of "$1"); attempt_read_sign_key \"$kd/home\" \"$kd/rt\"" > /dev/null 2>&1 ) || true
    cat "$kd/run/attempts/read_sign_key.txt" 2> /dev/null
  }
  kt=$(run_key "$root/bin/chain-hostile-step.sh")
  n=$(sed -n 's/^searched: \([0-9][0-9]*\) files$/\1/p' <<< "$kt" | head -1)
  if [ -n "$n" ] && [ "$n" -ge 2 ] && grep -F -q "pubkey-sha256: $want_h" <<< "$kt" && [ "$(head -1 <<< "$kt" | cut -c1-13)" = "# transcript:" ]; then
    ok "001-AC5 the real read_sign_key attempt, run against a planted key, records the files it searched (>= 2) and the planted key's public hash"
  else bad "001-AC5 the real read_sign_key attempt did not record the planted key's hash and a real file count: n=$n; $(head -c 200 <<< "$kt" | tr '\n' ' ')"; fi
  cat > "$kd/mutant.sh" <<'MUT'
attempt_read_sign_key() {
  printf "# transcript: claimed search for Sign key material\nsearched: 1 files\n" > attempts/read_sign_key.txt
}
MUT
  mt=$(run_key "$kd/mutant.sh")
  if ! grep -F -q "pubkey-sha256: $want_h" <<< "$mt"; then ok "001-AC5 a key attempt that prints a constant transcript does not record the planted key's hash (the execution check tells it apart)"
  else bad "001-AC5 the execution check accepted a constant transcript"; fi
else
  bad "001-AC5 the key attempt's execution check needs openssl genpkey (ed25519) to plant a key"; bad "001-AC5 the execution check could not plant a key"
fi
# ---- S2 rows: key search (NUL-safe, no truncation, unreadable key), token attempt without the environ corroboration, strict hostile-collect ----
fn_of() { awk "/^$2\\(\\) \\{/{p=1} p{print} p&&/^\\}/{exit}" "$1"; }
sk="$work/s2key"; rm -rf "$sk"; mkdir -p "$sk/home/sp ace" "$sk/rt" "$sk/many" "$sk/bad" "$sk/run"
run_s2() { # run_s2 ROOT...: the real attempt_read_sign_key with those search roots; prints its transcript
  rm -rf "$sk/run/attempts"; mkdir -p "$sk/run/attempts"
  ( cd "$sk/run" && bash -c "$(fn_of "$root/bin/chain-hostile-step.sh" attempt_read_sign_key); attempt_read_sign_key \"\$@\"" _ "$@" > /dev/null 2>&1 ) || true
  cat "$sk/run/attempts/read_sign_key.txt" 2> /dev/null
}
if openssl genpkey -algorithm ed25519 -out "$sk/proto.pem" > /dev/null 2>&1; then
  s2h=$(openssl pkey -in "$sk/proto.pem" -pubout -outform DER 2> /dev/null | sha256sum | cut -d' ' -f1)
  cp "$sk/proto.pem" "$sk/home/sp ace/k.pem"
  st=$(run_s2 "$sk/home")
  if grep -qx "pubkey-sha256: $s2h" <<< "$st" && ! grep -q '^unreadable-key:' <<< "$st"; then ok "S2 key search: a private key file whose path contains a space is found and its public-key sha256 recorded"
  else bad "S2 key search: a key under a path with a space was not recorded: $(head -c 300 <<< "$st" | tr '\n' '|')"; fi
  for i in $(seq 1 60); do cp "$sk/proto.pem" "$sk/many/k$i.pem"; done
  st=$(run_s2 "$sk/many")
  if [ "$(grep -c "^pubkey-sha256: $s2h$" <<< "$st")" = 60 ]; then ok "S2 key search: all 60 key files in the search root appear (no truncation at 50)"
  else bad "S2 key search: 60 key files gave $(grep -c '^pubkey-sha256:' <<< "$st") lines"; fi
  pk='PRIVATE'; printf -- '-----BEGIN %s KEY-----\nnot a key at all\n-----END %s KEY-----\n' "$pk" "$pk" > "$sk/bad/broken.pem"
  st=$(run_s2 "$sk/bad")
  if grep -qxF "unreadable-key: $sk/bad/broken.pem" <<< "$st"; then ok "S2 key search: a key file openssl cannot read is recorded as 'unreadable-key: <path>'"
  else bad "S2 key search: no unreadable-key line for a broken key: $(head -c 300 <<< "$st" | tr '\n' '|')"; fi
  if ! grep -q 'pubkey-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' <<< "$st"; then ok "S2 key search: a failed openssl no longer records the sha256 of the empty string"
  else bad "S2 key search: a failed openssl still records the sha256 of the empty string"; fi
else
  bad "S2 key search needs openssl genpkey (ed25519)"; bad "S2 key search needs openssl genpkey (ed25519)"; bad "S2 key search needs openssl genpkey (ed25519)"; bad "S2 key search needs openssl genpkey (ed25519)"
fi
# REQ-CHAIN-001-AC5: the default search roots (no arguments) are HOME, RUNNER_TEMP, /tmp and /dev/shm and never the repository checkout, even when it sits under HOME
ws_run() { # ws_run HOME RT WORKSPACE: the real attempt with NO arguments, cwd the workspace, a clean environment; prints its transcript
  rm -rf "$3/attempts"; mkdir -p "$3/attempts" "$2"
  ( cd "$3" && env -i PATH="$PATH" HOME="$1" RUNNER_TEMP="$2" GITHUB_WORKSPACE="$3" bash -c "$(fn_of "$root/bin/chain-hostile-step.sh" attempt_read_sign_key); attempt_read_sign_key" > /dev/null 2>&1 ) || true
  cat "$3/attempts/read_sign_key.txt" 2> /dev/null
}
# the probe folders sit in /var/tmp, outside every search root but the ones under test (a folder in /tmp is searched through /tmp); a stray key-shaped file
# elsewhere in /tmp may add an unreadable-key line for ITS path, which ac5_keep drops, so the grade rests on the probe's own files
ac5=$(mktemp -d -p /var/tmp chain-ac5.XXXXXX 2> /dev/null) || ac5=
ac5_keep() { grep -v -e '^unreadable-key: ' -e '^pubkey-sha256: ' <<< "$1"; grep -e "^unreadable-key: $ac5/" -e "^pubkey-sha256: $ac5h1$" -e "^pubkey-sha256: $ac5h2$" <<< "$1" || true; }   # only the probe's own lines
ac5h1=; ac5h2=
if [ -n "$ac5" ] && openssl genpkey -algorithm ed25519 -out "$ac5/k1.pem" > /dev/null 2>&1 && openssl genpkey -algorithm ed25519 -out "$ac5/k2.pem" > /dev/null 2>&1; then
  ac5h1=$(openssl pkey -in "$ac5/k1.pem" -pubout -outform DER 2> /dev/null | sha256sum | cut -d' ' -f1)
  ac5h2=$(openssl pkey -in "$ac5/k2.pem" -pubout -outform DER 2> /dev/null | sha256sum | cut -d' ' -f1)
  pk='PRIVATE'
  # the workspace under HOME holds key-shaped text that is not a key; a real key sits elsewhere under HOME
  wh="$ac5/home"; rm -rf "$wh"; wsp="$wh/work/cache/cache"; mkdir -p "$wsp/bin" "$wh/.ssh"
  printf -- '-----BEGIN RSA %s KEY-----\nnot a key at all\n-----END RSA %s KEY-----\n' "$pk" "$pk" > "$wsp/bin/some-test-fixture.txt"
  cp "$ac5/k1.pem" "$wh/.ssh/id_test"
  st=$(ac5_keep "$(ws_run "$wh" "$wh/rt" "$wsp")")
  if ! grep -q "^unreadable-key: $wsp/" <<< "$st"; then ok "001-AC5 key search: key-shaped text in the checkout, which sits under HOME, is not searched (no unreadable-key line naming it)"
  else bad "001-AC5 key search: the workspace under HOME was searched: $(grep '^unreadable-key:' <<< "$st" | head -3 | tr '\n' '|')"; fi
  if grep -qx "pubkey-sha256: $ac5h1" <<< "$st"; then ok "001-AC5 key search: a real private key elsewhere under HOME is still found and its public-key sha256 recorded"
  else bad "001-AC5 key search: the real key under HOME was not recorded: $(head -c 300 <<< "$st" | tr '\n' '|')"; fi
  printf '%s\nsearched: 42 files\npubkey-sha256: %s\n' "$KR" "$ac5h1" > "$work/ac5_key.txt"   # the header and the probe key's row, as key_other is built
  mrc=0; cvx hostile-material --kind key --file "$work/ac5_key.txt" --policy "$work/keypol.json" || mrc=$?
  if [ "$mrc" = 1 ] && grep -F -q "refused at runner" "$work/xerr"; then ok "001-AC5 hostile-material: that transcript (a found key that is not Sign's) is refused at runner, not an error"
  else bad "001-AC5 hostile-material: wanted exit 1 'refused at runner', got exit $mrc: $(head -c 200 "$work/xerr" | tr '\n' ' ')"; fi
  # a checkout that is not under HOME behaves the same
  wh2="$ac5/home2"; wsp2="$ac5/ws2/cache"; mkdir -p "$wsp2/bin" "$wh2/.ssh"
  cp "$wsp/bin/some-test-fixture.txt" "$wsp2/bin/"; cp "$ac5/k1.pem" "$wh2/.ssh/id_test"
  st=$(ac5_keep "$(ws_run "$wh2" "$wh2/rt" "$wsp2")")
  if ! grep -q "^unreadable-key: $wsp2/" <<< "$st" && grep -qx "pubkey-sha256: $ac5h1" <<< "$st"; then ok "001-AC5 key search: a checkout outside HOME gives the same result (real key found, checkout text not searched)"
  else bad "001-AC5 key search: checkout outside HOME: $(head -c 300 <<< "$st" | tr '\n' '|')"; fi
  # documented limit: a real key inside the checkout is not searched either
  cp "$ac5/k2.pem" "$wsp/bin/inside.pem"
  st=$(ac5_keep "$(ws_run "$wh" "$wh/rt" "$wsp")")
  if ! grep -qx "pubkey-sha256: $ac5h2" <<< "$st" && grep -qx "pubkey-sha256: $ac5h1" <<< "$st"; then ok "001-AC5 key search: a real key inside the checkout is not searched (documented limit); the key under HOME still is"
  else bad "001-AC5 key search: a key inside the checkout was recorded or the HOME key lost: $(head -c 300 <<< "$st" | tr '\n' '|')"; fi
else
  bad "001-AC5 default-roots key search needs openssl genpkey (ed25519)"; bad "001-AC5 default-roots key search needs openssl genpkey (ed25519)"; bad "001-AC5 default-roots key search needs openssl genpkey (ed25519)"; bad "001-AC5 default-roots key search needs openssl genpkey (ed25519)"; bad "001-AC5 default-roots key search needs openssl genpkey (ed25519)"
fi
[ -n "$ac5" ] && [ -d "$ac5" ] && rm -rf -- "$ac5"
# the grader: an unreadable-key line is an ERROR (exit 2), never isolation, whatever else the transcript holds
printf '%s\nsearched: 42 files\nunreadable-key: /home/runner/k.pem\n' "$KR" > "$work/key_unread.txt"
printf '%s\nsearched: 42 files\npubkey-sha256: %s\nunreadable-key: /home/runner/k.pem\n' "$KR" "$H2" > "$work/key_unread2.txt"
for f in key_unread key_unread2; do
  mrc=0; cvx hostile-material --kind key --file "$work/$f.txt" --policy "$work/keypol.json" || mrc=$?
  if [ "$mrc" = 2 ] && grep -F -q "unreadable-key" "$work/xerr" && ! grep -F -q "refused at" "$work/xerr"; then ok "S2 hostile-material: $f (an unreadable-key line) is an ERROR (exit 2) naming it, never isolation"
  else bad "S2 hostile-material: $f must be an error naming unreadable-key, got exit $mrc: $(head -c 160 "$work/xerr" | tr '\n' ' ')"; fi
done
# the token attempt: no environ-read / environ-unreadable-same-user lines any more, and the grader neither requires nor parses them
mkdir -p "$work/s2tok" && sed '/^attempt_mint_sign_cert$/,$d' "$root/bin/chain-hostile-step.sh" > "$work/s2tok/fns.sh"
(cd "$work/s2tok" && env -i PATH="$PATH" bash -c '. ./fns.sh; attempt_read_sign_token')
if grep -qx 'request-env: absent' "$work/s2tok/attempts/read_sign_token.txt" && ! grep -q -e '^environ-read:' -e '^environ-unreadable-same-user:' "$work/s2tok/attempts/read_sign_token.txt"; then ok "S2 hostile step: the token attempt writes request-env: absent and no environ-read or environ-unreadable-same-user line"
else bad "S2 hostile step: the token transcript still has environ lines: $(tr '\n' '|' < "$work/s2tok/attempts/read_sign_token.txt" | head -c 300)"; fi
printf '%s\nrequest-env: absent\n' "$TR" > "$work/tok_s2only.txt"
xexpect refuse "S2 hostile-material: a token transcript of the header and request-env: absent only is graded isolated (refused at runner)" "refused at runner" -- hostile-material --kind token --file "$work/tok_s2only.txt"
printf '%s\na process on this runner holds a token request address: /proc/9/environ\nrequest-env: absent\n' "$TR" > "$work/tok_s2hold.txt"
mrc=0; cvx hostile-material --kind token --file "$work/tok_s2hold.txt" || mrc=$?
if [ "$mrc" = 2 ] && grep -F -q "error" "$work/xerr" && ! grep -F -q "refused at" "$work/xerr"; then ok "S2 hostile-material: a holder line with request-env: absent only is still an ERROR (exit 2)"
else bad "S2 hostile-material: a holder line must be an error, got exit $mrc"; fi
# hostile-collect: a strict reader and a named exit 2 (one line, no traceback) for what cannot be read as a row
s2c() { # s2c NAME: rows dir "$work/s2rows-NAME" = the good rows, copied
  rm -rf "$work/s2rows-$1"; mkdir -p "$work/s2rows-$1"; cp "$work"/rows/*.json "$work/s2rows-$1/"
}
s2expect() { # s2expect LABEL NAME: hostile-collect of that dir exits 2 with one error line naming the file, no traceback
  local rc=0; cvx hostile-collect "$work/s2rows-$2" --out "$work/s2c-$2.json" || rc=$?
  if [ "$rc" = 2 ] && [ "$(wc -l < "$work/xerr")" = 1 ] && grep -q '^error: .*bad\.json' "$work/xerr" && ! grep -q Traceback "$work/xerr"; then ok "$1"
  else bad "$1 (exit $rc, wanted 2 with one 'error:' line naming bad.json; $(head -c 200 "$work/xerr" | tr '\n' ' '))"; fi
}
s2c dup; printf '{"attempt":"mint_sign_cert","attempt":"forge_provenance","outcome":"refused"}' > "$work/s2rows-dup/bad.json"
s2expect "S2 hostile-collect: a row file with a duplicate key is a named error, exit 2" dup
s2c list; printf '[1, 2]' > "$work/s2rows-list/bad.json"
s2expect "S2 hostile-collect: a row file whose JSON is a list is a named error, exit 2, no traceback" list
s2c num; printf '5' > "$work/s2rows-num/bad.json"
s2expect "S2 hostile-collect: a row file whose JSON is a number is a named error, exit 2, no traceback" num
s2c nan; printf '{"attempt":"mint_sign_cert","exit_code":NaN}' > "$work/s2rows-nan/bad.json"
s2expect "S2 hostile-collect: a row file with a non-strict constant (NaN) is a named error, exit 2" nan
s2c dir; mkdir "$work/s2rows-dir/bad.json"
s2expect "S2 hostile-collect: a directory in place of a row file is a named error, exit 2, no traceback" dir
if [ "$(id -u)" != 0 ]; then
  s2c perm; printf '{}' > "$work/s2rows-perm/bad.json"; chmod 000 "$work/s2rows-perm/bad.json"
  s2expect "S2 hostile-collect: an unreadable (permission denied) row file is a named error, exit 2, no traceback" perm
else ok "S2 hostile-collect: permission-denied case skipped, running as root"; fi
echo "pass=$pass fail=$failn"
[ "$failn" = 0 ]
