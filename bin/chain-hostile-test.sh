#!/usr/bin/env bash
# proves: REQ-CHAIN-001-AC5
# The hostile Build step (v0.3.0 rules 52a, 59; owner RATIFIED Oct 9), static half. A dry run on a branch runs
# bin/chain-hostile-step.sh as a Build step; it makes five attempts (certificate in Sign's identity, read Sign's token,
# read Sign's key material, hand Sign code instead of digests, forge provenance Release would accept: rule 52a) and writes one line per attempt to hostile-results.json. The dry-run job must then judge that file with
# bin/chain-verify.py hostile-verdict, which fails if any attempt was accepted. Here: the verdict judge is proven on a
# fixture and mutations (one accepted attempt, a missing attempt, an unnamed refusal), then the real wiring is checked.
# The runtime half is the dry-run on GitHub; its run URL goes in the PR body.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
attempts="mint-sign-cert read-sign-token read-sign-key hand-sign-code forge-provenance"
verdict() { python3 - "$1" $attempts <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); need = sys.argv[2:]; bad = []
by = {r.get("attempt"): r for r in d.get("attempts", [])}
for a in need:
    r = by.get(a)
    if r is None: bad.append("missing attempt " + a)
    elif r.get("outcome") != "refused": bad.append("%s was %s" % (a, r.get("outcome")))
    elif not r.get("stage") or not r.get("reason"): bad.append("%s refusal does not name stage and reason" % a)
print("; ".join(bad) or "ok"); sys.exit(1 if bad else 0)
PY
}
expect() { local out rc=0; out=$(verdict "$3") || rc=$?
  if { [ "$1" = ok ] && [ "$rc" = 0 ]; } || { [ "$1" = caught ] && [ "$rc" != 0 ]; }; then pass=$((pass+1)); echo "ok   $2 ($out)"
  else failn=$((failn+1)); echo "FAIL $2 -> $out"; fi; }
python3 - "$work" $attempts <<'PY'
import json, sys, copy
w, att = sys.argv[1], sys.argv[2:]
good = {"attempts": [{"attempt": a, "outcome": "refused", "stage": "release", "reason": "identity is stage-build.yml, not stage-sign.yml"} for a in att]}
json.dump(good, open(w + "/good.json", "w"))
m = copy.deepcopy(good); m["attempts"][3]["outcome"] = "accepted"; json.dump(m, open(w + "/accepted.json", "w"))
m = copy.deepcopy(good); del m["attempts"][1]; json.dump(m, open(w + "/missing.json", "w"))
m = copy.deepcopy(good); m["attempts"][0]["reason"] = ""; json.dump(m, open(w + "/unnamed.json", "w"))
PY
expect ok "verdict: all five refused with stage and reason" "$work/good.json"
expect caught "verdict: one forged provenance accepted" "$work/accepted.json"
expect caught "verdict: an attempt missing" "$work/missing.json"
expect caught "verdict: refusal names no reason" "$work/unnamed.json"
step="$root/bin/chain-hostile-step.sh"
if [ -f "$step" ] && for a in $attempts; do grep -q -- "$a" "$step" || exit 1; done; then pass=$((pass+1)); echo "ok   the hostile step makes all five attempts"
else failn=$((failn+1)); echo "FAIL bin/chain-hostile-step.sh missing or lacks an attempt"; fi
python3 - "$root" <<'PY' && { pass=$((pass+1)); echo "ok   release.yml dry run wires the hostile step and the verdict"; } || { failn=$((failn+1)); echo "FAIL release.yml dry-run wiring"; }
import re, sys, yaml
t = open(sys.argv[1] + "/.github/workflows/release.yml").read()
d = yaml.load(t, Loader=yaml.BaseLoader)
on = d.get("on") or {}
ok = "workflow_dispatch" in on and "chain-hostile-step.sh" in t and "chain-verify.py hostile-verdict" in t
ok = ok and not re.search(r"dry-run.*packages:\s*write", t, re.S)
sys.exit(0 if ok else 1)
PY
echo "pass=$pass fail=$failn"; [ "$failn" = 0 ]
