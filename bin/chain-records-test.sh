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
# naming the file. Scanned: .github/workflows/*.yml and *.yaml, .github/actions/**/action.yml|yaml, a root action.yml, and every
# script those files run (bash x.sh, ./x.sh, python3 x.py; bin/chain-verify.py itself excepted: only `chain-verify.py sign` in
# stage-sign.yml reaches its signing calls). Which tools sign is ONE table shared with chain-sign-wiring-test.sh
# (bin/chain-test-signers.json: cosign sign/attest, witness run/sign with every attestor flag form, attest-build-provenance,
# actions/attest, actions/attest-sbom, slsa-github-generator, gitsign, sigstore actions, chain-verify.py sign); a tool in
# the table with no finer resolver needs a row for its pseudo type, so no known signer is invisible. Comments are stripped
# first (full-line and trailing). Exclusions, stated plainly: a signer that is not in the table is not seen by either
# test (add it to the table first); signing done by a binary a script downloads at run time is not seen.
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
TABLE = json.load(open(os.environ["CHAIN_SIGNER_TABLE"]))["signers"]
def strip(text):
    out = []
    for l in text.splitlines():
        if l.lstrip().startswith("#"): continue
        out.append(re.sub(r"(?<=\s)#.*$", "", l))
    return "\n".join(out)
def logical(text): return re.sub(r"\\\n\s*", " ", text)
RUNNER = re.compile(r"(?:\b(?:bash|sh|python3?|source)\s+|(?<![\w/.-])\.\s+|(?<![\w/.-]))(\.?/?(?:[\w.-]+/)*[\w.-]+\.(?:sh|py))\b")
def scan(rel, text):
    def add(t): produced.setdefault(t, set()).add(rel)
    for line in logical(strip(text)).splitlines():
        for e in TABLE:
            if not re.search(e["regex"], line): continue
            n = e["name"]
            if n == "witness run":
                add(COLL)
                if e["prov"].startswith("if:") and re.search(e["prov"][3:], line, re.I): add(PROV)
            elif n == "witness sign":
                dt = re.search(r"(?:-t|--datatype)[ =]+(\S+)", line)
                if not dt: add(POLT)
                elif re.fullmatch(r"https?://[^\s\"'$`]+", dt.group(1).strip("\"'")): add(dt.group(1).strip("\"'"))
                else: bad.append("%s: witness sign with an unresolved datatype %r (fail closed)" % (rel, dt.group(1)))
            elif n == "actions/attest":
                pt = re.search(r"predicate-type:\s*['\"]?([^\s'\"]+)", strip(text).split("actions/attest@", 1)[-1][:400])
                if pt and re.fullmatch(r"https?://\S+", pt.group(1)): add(pt.group(1))
                else: bad.append("%s: actions/attest with no literal predicate-type (%s) (fail closed)" % (rel, pt.group(1) if pt else "none"))
            elif n == "cosign attest":
                ty = re.search(r"--type[ =]+(\S+)", line)
                v = ty.group(1).strip("\"'") if ty else None
                if v and re.fullmatch(r"https?://\S+", v): add(v)
                elif v and v in SHORT: add(SHORT[v])
                else: bad.append("%s: cosign attest with an unresolved --type (%s) (fail closed)" % (rel, v or "none"))
            elif e.get("pseudo"): add(e["pseudo"])
            else: bad.append("%s: signer %s has no resolver and no pseudo type in the table (fail closed)" % (rel, n))
scripts = {}
for f in files:
    rel = os.path.relpath(f, base); txt = open(f).read()
    scan(rel, txt)
    for m in RUNNER.finditer(logical(strip(txt))):
        sp = os.path.normpath(m.group(1))
        scripts.setdefault(sp, set()).add(rel)
for sp in sorted(scripts):
    full = os.path.join(base, sp)
    if sp == "bin/chain-verify.py" or not os.path.isfile(full): continue
    scan(sp, open(full).read())
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
export CHAIN_SIGNER_TABLE="$root/bin/chain-test-signers.json"
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
d=$(mk sbom); printf 'jobs:\n  c:\n    steps:\n      - uses: actions/attest-sbom@%s # v3\n' "$(printf 'a%.0s' $(seq 40))" > "$d/.github/workflows/stage-verify.yml"
expect caught "actions/attest-sbom (a known signer with no finer resolver) with no row fails" "$d"
d=$(mk gen); printf 'jobs:\n  c:\n    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@%s\n' "$(printf 'a%.0s' $(seq 40))" > "$d/.github/workflows/stage-verify.yml"; sed -i.bak '/slsa.dev/d' "$d/.github/policy/chain-records.json" 2>/dev/null || true
expect caught "slsa-github-generator produces provenance; with its row removed it fails" "$d"
for form in '-a=slsa' '-a product,slsa' '--attestations slsa' '--attestor slsa'; do
  d=$(mk "wf_$(printf '%s' "$form" | tr -c 'a-z' _)"); printf 'jobs:\n  c:\n    steps:\n      - run: witness run --step c %s -- ./x\n' "$form" > "$d/.github/workflows/stage-verify.yml"; sed -i.bak '/slsa.dev/d' "$d/.github/policy/chain-records.json" 2>/dev/null || true
  expect caught "witness run $form produces provenance; with its row removed it fails" "$d"
done
d=$(mk trailing); printf 'jobs:\n  c:\n    steps:\n      - run: cosign sign --yes "$IMG" # verify only\n' > "$d/.github/workflows/stage-verify.yml"
expect caught "a trailing comment exempts nothing (cosign sign with no row still fails)" "$d"
d=$(mk script); mkdir -p "$d/bin"; printf 'jobs:\n  c:\n    steps:\n      - run: bash bin/publish.sh\n' > "$d/.github/workflows/stage-verify.yml"; printf '#!/usr/bin/env bash\ncosign sign --yes "$IMG"\n' > "$d/bin/publish.sh"
expect caught "a script a workflow runs signs an image with no row (bin/publish.sh)" "$d"
d=$(mk scriptvar); mkdir -p "$d/bin"; printf 'jobs:\n  c:\n    steps:\n      - run: ./bin/publish.sh\n' > "$d/.github/workflows/stage-verify.yml"; printf '#!/usr/bin/env bash\ncosign attest --yes --type "$T" --predicate p.json "$IMG"\n' > "$d/bin/publish.sh"
expect caught "a script a workflow runs attests with an unresolved type: fails closed" "$d"
d=$(mk cvsign2); printf 'jobs:\n  c:\n    steps:\n      - run: python3 bin/chain-verify.py sign --check --signer cosign --digests d.json --build-record b.json --policy p.json --out provenance\n' > "$d/.github/workflows/stage-verify.yml"
expect ok "chain-verify.py sign resolves to SLSA provenance v1 (already has a row)" "$d"
d=$(mk comment); printf '# cosign sign would go here\njobs: {}\n' > "$d/.github/workflows/stage-verify.yml"
expect ok "a signing command inside a comment is not a producer" "$d"
expect ok "the real repository: every produced record type has a row with a claim and a stage consumer" "$root"
EXPECT=29
echo "pass=$pass fail=$failn"
if [ $((pass + failn)) != "$EXPECT" ]; then echo "FAIL case count $((pass + failn)) != expected $EXPECT (a case was skipped or added)"; exit 1; fi
[ "$failn" = 0 ]
