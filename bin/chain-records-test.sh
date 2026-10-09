#!/usr/bin/env bash
# proves: REQ-CHAIN-003-AC3
# RED until .github/policy/chain-records.json exists and matches what the workflows sign (tests before implementation).
# Rule 66: every signed record type the workflows produce has exactly one row in .github/policy/chain-records.json with a
# non-empty claim and a consumer that is a real stage; a produced type with no row fails; a row nobody produces, a row
# whose consumer is not a stage, a row with no claim and two rows with the same claim fail too.
# Shape: {"records":[{"type":"<predicate type URI or pseudo type>","claim":"<text>","consumer":"build|sign|rebuild|check|release|customer"}]}.
# What a workflow produces is found BY TOOL OR ACTION, not by a flag (Witness has no --type flag):
#   `witness run`                       -> https://witness.testifysec.com/attestation-collection/v0.1  (in-toto-witness
#                                          docs/tutorials/artifact-policy.md:70; the ops spike :36)
#   `witness sign`                      -> the policy payloadType https://witness.testifysec.com/policy/v0.1 unless -t/--datatype
#                                          gives a literal (options/sign.go:36)
#   actions/attest-build-provenance, `chain-verify.py sign`, witness `-a slsa` -> https://slsa.dev/provenance/v1
#   actions/attest                      -> its `predicate-type:` literal
#   `cosign attest --type T`            -> T if a URI, else cosign's short name (slsaprovenance -> .../provenance/v0.2,
#                                          slsaprovenance1 -> .../provenance/v1, spdx/cyclonedx/vuln mapped below)
#   `cosign sign` / `gitsign`           -> pseudo types urn:cosign:signature / urn:gitsign:tag-signature
# FAIL CLOSED: a producing call whose type cannot be resolved (an expression, a shell variable, no --type) is an error
# naming the file. Scanned: .github/workflows/*.yml and *.yaml, .github/actions/**/action.yml|yaml, a root action.yml.
# The judge is proven on a known-good fixture tree and mutated copies, then applied to the real repository.
# Needs python3 (no PyYAML: the scan is by text, comments stripped).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
cat > "$work/judge.py" <<'PY'
import glob, json, os, re, sys
base = sys.argv[1]
STAGES = {"build", "sign", "rebuild", "check", "release", "customer"}
COLL = "https://witness.testifysec.com/attestation-collection/v0.1"
POLT = "https://witness.testifysec.com/policy/v0.1"
PROV = "https://slsa.dev/provenance/v1"
SHORT = {"slsaprovenance": "https://slsa.dev/provenance/v0.2", "slsaprovenance02": "https://slsa.dev/provenance/v0.2", "slsaprovenance1": PROV,
         "spdx": "https://spdx.dev/Document", "spdxjson": "https://spdx.dev/Document", "cyclonedx": "https://cyclonedx.org/bom",
         "vuln": "https://cosign.sigstore.dev/attestation/vuln/v1", "link": "https://in-toto.io/Link/v1"}
bad, produced = [], {}
rf = os.path.join(base, ".github/policy/chain-records.json")
if not os.path.exists(rf):
    bad.append("missing: .github/policy/chain-records.json")
    rows = []
else:
    rows = json.load(open(rf)).get("records") or []
wf = os.path.join(base, ".github/workflows")
files = sorted(glob.glob(wf + "/*.yml") + glob.glob(wf + "/*.yaml") + glob.glob(os.path.join(base, ".github/actions/**/action.y*ml"), recursive=True) + glob.glob(os.path.join(base, "action.y*ml")))
for f in files:
    rel = os.path.relpath(f, base)
    text = "\n".join(l for l in open(f).read().splitlines() if not l.lstrip().startswith("#"))
    def add(t): produced.setdefault(t, set()).add(rel)
    if re.search(r"\bwitness\s+run\b", text): add(COLL)
    if re.search(r"\bwitness\s+run\b[^\n]*(-a\s+slsa|--attestors?[ =]\S*slsa)", text): add(PROV)
    for m in re.finditer(r"\bwitness\s+sign\b[^\n]*", text):
        dt = re.search(r"(?:-t|--datatype)[ =]+(\S+)", m.group(0))
        if not dt: add(POLT)
        elif re.fullmatch(r"https?://[^\s\"'$`]+", dt.group(1).strip("\"'")): add(dt.group(1).strip("\"'"))
        else: bad.append("%s: witness sign with an unresolved datatype %r (fail closed)" % (rel, dt.group(1)))
    if re.search(r"actions/attest-build-provenance@|chain-verify\.py\s+sign\b", text): add(PROV)
    for m in re.finditer(r"actions/attest@[^\n]*", text):
        seg = re.split(r"\n\s*-\s", text[m.end():], 1)[0]
        pt = re.search(r"predicate-type:\s*['\"]?([^\s'\"]+)", seg)
        if pt and re.fullmatch(r"https?://\S+", pt.group(1)): add(pt.group(1))
        else: bad.append("%s: actions/attest with no literal predicate-type (%s) (fail closed)" % (rel, pt.group(1) if pt else "none"))
    for m in re.finditer(r"\bcosign\s+attest(?:-blob)?\b[^\n]*", text):
        ty = re.search(r"--type[ =]+(\S+)", m.group(0))
        v = ty.group(1).strip("\"'") if ty else None
        if v and re.fullmatch(r"https?://\S+", v): add(v)
        elif v and v in SHORT: add(SHORT[v])
        else: bad.append("%s: cosign attest with an unresolved --type (%s) (fail closed)" % (rel, v or "none"))
    if re.search(r"\bcosign\s+sign(-blob)?\b", text): add("urn:cosign:signature")
    if re.search(r"\bgitsign\b", text): add("urn:gitsign:tag-signature")
types = [r.get("type") for r in rows]
for t in sorted(produced):
    if types.count(t) == 0: bad.append("produced type has no row: %s (in %s)" % (t, ", ".join(sorted(produced[t]))))
    if types.count(t) > 1: bad.append("produced type has more than one row: " + t)
for r in rows:
    if r.get("type") not in produced: bad.append("row for a type nothing produces: %s" % r.get("type"))
    if not str(r.get("claim") or "").strip(): bad.append("row without a claim: %s" % r.get("type"))
    if r.get("consumer") not in STAGES: bad.append("row whose consumer is not a stage (%s): %s" % (sorted(STAGES), r.get("type")))
claims = [str(r.get("claim") or "").strip().lower() for r in rows]
for c in set(claims):
    if c and claims.count(c) > 1: bad.append("two rows make the same claim: " + c)
print("; ".join(dict.fromkeys(bad)) or "ok")
sys.exit(1 if bad else 0)
PY
judge() { python3 "$work/judge.py" "$1"; }
expect() { # expect ok|caught LABEL DIR
  local out rc=0
  out=$(judge "$3") || rc=$?
  if [ "$1" = ok ] && [ "$rc" = 0 ]; then pass=$((pass + 1)); echo "ok   $2"
  elif [ "$1" = caught ] && [ "$rc" != 0 ]; then pass=$((pass + 1)); echo "ok   $2 (caught: ${out:0:140})"
  else failn=$((failn + 1)); echo "FAIL $2 -> ${out:0:500}"; fi
}
mk() { # mk NAME  -> a known-good tree
  local d="$work/$1"; rm -rf "$d"; mkdir -p "$d/.github/workflows" "$d/.github/policy"
  printf 'jobs:\n  sign:\n    steps:\n      - run: python3 bin/chain-verify.py sign --check --digests "$D" --build-record b.json\n' > "$d/.github/workflows/stage-sign.yml"
  printf 'jobs:\n  build:\n    steps:\n      - run: witness run --step build -- ./bin/build.sh\n' > "$d/.github/workflows/stage-build.yml"
  cat > "$d/.github/policy/chain-records.json" <<'J'
{"records":[
 {"type":"https://slsa.dev/provenance/v1","claim":"how and from what the release was built","consumer":"release"},
 {"type":"https://witness.testifysec.com/attestation-collection/v0.1","claim":"what each build step did","consumer":"rebuild"}]}
J
  echo "$d"
}
addrow() { python3 - "$1" "$2" "$3" "$4" <<'PY'
import json, sys
f = sys.argv[1] + "/.github/policy/chain-records.json"; j = json.load(open(f))
j["records"].append({"type": sys.argv[2], "claim": sys.argv[3], "consumer": sys.argv[4]}); json.dump(j, open(f, "w"))
PY
}
expect ok "fixture: a tree whose every produced type has a row passes" "$(mk good)"
d=$(mk nrow); python3 - "$d" <<'PY'
import json, sys
f = sys.argv[1] + "/.github/policy/chain-records.json"; j = json.load(open(f)); j["records"].pop(); json.dump(j, open(f, "w"))
PY
expect caught "a produced type with no row fails" "$d"
d=$(mk nocons); sed -i.bak 's/"consumer":"rebuild"/"consumer":""/' "$d/.github/policy/chain-records.json"
expect caught "a row with no consumer fails" "$d"
d=$(mk nobody); sed -i.bak 's/"consumer":"rebuild"/"consumer":"nobody"/' "$d/.github/policy/chain-records.json"
expect caught "a row whose consumer is not a real stage fails" "$d"
d=$(mk noclaim); sed -i.bak 's/"claim":"what each build step did"/"claim":" "/' "$d/.github/policy/chain-records.json"
expect caught "a row with no claim fails" "$d"
d=$(mk dupclaim); sed -i.bak 's/what each build step did/how and from what the release was built/' "$d/.github/policy/chain-records.json"
expect caught "two rows with the same claim fail" "$d"
d=$(mk extra); addrow "$d" "https://example.com/unused/v1" "nothing" "check"
expect caught "a row for a type nothing produces fails" "$d"
d=$(mk dupl); addrow "$d" "https://slsa.dev/provenance/v1" "another claim" "check"
expect caught "two rows for one produced type fail" "$d"
d=$(mk attest); printf 'jobs:\n  c:\n    steps:\n      - uses: actions/attest@%s # v4\n        with:\n          predicate-type: https://example.com/new/v1\n' "$(printf 'a%.0s' $(seq 40))" > "$d/.github/workflows/stage-verify.yml"
expect caught "actions/attest with a new literal predicate-type and no row fails" "$d"
d=$(mk attestx); printf 'jobs:\n  c:\n    steps:\n      - uses: actions/attest@%s # v4\n        with:\n          predicate-type: ${{ inputs.t }}\n' "$(printf 'a%.0s' $(seq 40))" > "$d/.github/workflows/stage-verify.yml"
expect caught "actions/attest with an expression type is unresolved and fails closed" "$d"
d=$(mk cosvar); printf 'jobs:\n  c:\n    steps:\n      - run: cosign attest --yes --type "$T" --predicate p.json "$IMG"\n' > "$d/.github/workflows/stage-verify.yml"
expect caught "cosign attest with a shell-variable type fails closed" "$d"
d=$(mk cosnone); printf 'jobs:\n  c:\n    steps:\n      - run: cosign attest --yes --predicate p.json "$IMG"\n' > "$d/.github/workflows/stage-verify.yml"
expect caught "cosign attest with no --type fails closed" "$d"
d=$(mk cosshort); printf 'jobs:\n  c:\n    steps:\n      - run: cosign attest --yes --type slsaprovenance1 --predicate p.json "$IMG"\n' > "$d/.github/workflows/stage-verify.yml"
expect ok "cosign attest --type slsaprovenance1 resolves to SLSA provenance v1 (already has a row)" "$d"
d=$(mk cossign); printf 'jobs:\n  c:\n    steps:\n      - run: cosign sign --yes "$IMG"\n' > "$d/.github/workflows/stage-verify.yml"
expect caught "cosign sign (an image signature) with no row fails" "$d"
d=$(mk yaml); printf 'jobs:\n  c:\n    steps:\n      - run: witness sign -f policy.json -o policy.signed.json\n' > "$d/.github/workflows/other.yaml"
expect caught "a .yaml workflow signing the policy with no row fails" "$d"
d=$(mk comp); mkdir -p "$d/.github/actions/x"; printf 'runs:\n  using: composite\n  steps:\n    - run: cosign sign "$IMG"\n      shell: bash\n' > "$d/.github/actions/x/action.yml"
expect caught "a composite action that signs with no row fails" "$d"
d=$(mk wsl); printf 'jobs:\n  c:\n    steps:\n      - run: witness run --step c -a slsa -- ./x\n' > "$d/.github/workflows/stage-verify.yml"; sed -i.bak '/slsa.dev/d' "$d/.github/policy/chain-records.json" 2>/dev/null || true
expect caught "witness run -a slsa produces provenance; with its row removed it fails" "$d"
d=$(mk comment); printf '# cosign sign would go here\njobs: {}\n' > "$d/.github/workflows/stage-verify.yml"
expect ok "a signing command inside a comment is not a producer" "$d"
expect ok "the real repository: every produced record type has a row with a claim and a stage consumer" "$root"
EXPECT=19
echo "pass=$pass fail=$failn"
if [ $((pass + failn)) != "$EXPECT" ]; then echo "FAIL case count $((pass + failn)) != expected $EXPECT (a case was skipped or added)"; exit 1; fi
[ "$failn" = 0 ]
