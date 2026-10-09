#!/usr/bin/env bash
# proves: REQ-CHAIN-003-AC3
# RED until .github/policy/chain-records.json exists (tests before implementation).
# Every signed record type the workflow files produce has exactly one row in .github/policy/chain-records.json with a
# non-empty claim and a named consumer; a produced type with no row fails; a row nobody produces, a row with no consumer
# and two rows with the same claim fail too (rule 66: a distinct claim and a named consumer, or the record is removed).
# Shape assumed: {"records":[{"type":"<predicate type URI>","claim":"<text>","consumer":"<stage or script>"}]}.
# A workflow produces a type by passing `--predicate-type <URI>` (or `--type <URI>`) to the signing step.
# The judge is proven on a known-good fixture tree and mutated copies, then applied to the real repository.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
judge() { python3 - "$1" <<'PY'
import glob, json, os, re, sys
base = sys.argv[1]
bad = []
rf = os.path.join(base, ".github/policy/chain-records.json")
if not os.path.exists(rf):
    print("missing: .github/policy/chain-records.json"); sys.exit(1)
rows = json.load(open(rf)).get("records") or []
produced = set()
for f in glob.glob(os.path.join(base, ".github/workflows/*.yml")):
    for m in re.finditer(r"--(?:predicate-)?type[ =]+['\"]?(https?://[^\s'\"]+)", open(f).read()):
        produced.add(m.group(1))
types = [r.get("type") for r in rows]
for t in sorted(produced):
    if types.count(t) == 0:
        bad.append("produced type has no row: " + t)
    if types.count(t) > 1:
        bad.append("produced type has more than one row: " + t)
for r in rows:
    if r.get("type") not in produced:
        bad.append("row for a type nothing produces: %s" % r.get("type"))
    if not str(r.get("claim") or "").strip():
        bad.append("row without a claim: %s" % r.get("type"))
    if not str(r.get("consumer") or "").strip():
        bad.append("row without a named consumer: %s" % r.get("type"))
claims = [str(r.get("claim") or "").strip().lower() for r in rows]
for c in set(claims):
    if c and claims.count(c) > 1:
        bad.append("two rows make the same claim: " + c)
print("; ".join(bad) or "ok")
sys.exit(1 if bad else 0)
PY
}
expect() { # expect ok|caught LABEL DIR
  local out rc=0
  out=$(judge "$3") || rc=$?
  if [ "$1" = ok ] && [ "$rc" = 0 ]; then pass=$((pass + 1)); echo "ok   $2"
  elif [ "$1" = caught ] && [ "$rc" != 0 ]; then pass=$((pass + 1)); echo "ok   $2 (caught: $out)"
  else failn=$((failn + 1)); echo "FAIL $2 -> $out"; fi
}
mk() { # mk NAME  -> a known-good tree
  local d="$work/$1"; mkdir -p "$d/.github/workflows" "$d/.github/policy"
  cat > "$d/.github/workflows/stage-sign.yml" <<'EOF'
jobs:
  sign:
    steps:
      - run: python3 bin/chain-verify.py sign --predicate-type https://slsa.dev/provenance/v1 --digests "$D"
EOF
  cat > "$d/.github/workflows/stage-build.yml" <<'EOF'
jobs:
  build:
    steps:
      - run: witness run --type=https://witness.dev/attestation-collections/v0.1 -- ./bin/build.sh
EOF
  cat > "$d/.github/policy/chain-records.json" <<'EOF'
{"records":[
 {"type":"https://slsa.dev/provenance/v1","claim":"how and from what the release was built","consumer":"release"},
 {"type":"https://witness.dev/attestation-collections/v0.1","claim":"what each build step did","consumer":"rebuild"}]}
EOF
  echo "$d"
}
expect ok "fixture: a tree whose every produced type has a row passes" "$(mk good)"
d=$(mk nrow); python3 - "$d" <<'PY'
import json, sys
f = sys.argv[1] + "/.github/policy/chain-records.json"; j = json.load(open(f)); j["records"].pop(); json.dump(j, open(f, "w"))
PY
expect caught "a produced type with no row fails" "$d"
d=$(mk nocons); sed -i.bak 's/"consumer":"rebuild"/"consumer":""/' "$d/.github/policy/chain-records.json"
expect caught "a row with no consumer fails" "$d"
d=$(mk noclaim); sed -i.bak 's/"claim":"what each build step did"/"claim":" "/' "$d/.github/policy/chain-records.json"
expect caught "a row with no claim fails" "$d"
d=$(mk dupclaim); sed -i.bak 's/what each build step did/how and from what the release was built/' "$d/.github/policy/chain-records.json"
expect caught "two rows with the same claim fail" "$d"
d=$(mk extra); python3 - "$d" <<'PY'
import json, sys
f = sys.argv[1] + "/.github/policy/chain-records.json"; j = json.load(open(f))
j["records"].append({"type": "https://example.com/unused/v1", "claim": "nothing", "consumer": "nobody"}); json.dump(j, open(f, "w"))
PY
expect caught "a row for a type nothing produces fails" "$d"
d=$(mk newtype); echo '      - run: x --predicate-type https://example.com/new/v1' >> "$d/.github/workflows/stage-sign.yml"
expect caught "a newly produced type with no row fails" "$d"
expect ok "the real repository: every produced record type has a row with a claim and a consumer" "$root"
echo "pass=$pass fail=$failn"
[ "$failn" = 0 ]
