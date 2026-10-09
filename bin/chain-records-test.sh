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
import importlib.util
_spec = importlib.util.spec_from_file_location("chain_test_signers", os.path.join(os.environ["CHAIN_ROOT"], "bin/chain-test-signers.py"))
_cts = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(_cts)
TABLE = _cts.load_table()
strip, logical = _cts.strip, _cts.logical
def scan(rel, text):
    def add(t): produced.setdefault(t, set()).add(rel)
    for e, ctx in _cts.calls(text, TABLE):
        n = e["name"]
        if n == "witness run":
            add(COLL)
            if _cts.is_prov(e, ctx): add(PROV)
        elif n == "witness sign":
            dt = re.search(r"(?:-t|--datatype)[ =]+(\S+)", ctx)
            if not dt: add(POLT)
            elif re.fullmatch(r"https?://[^\s\"'$`]+", dt.group(1).strip("\"'")): add(dt.group(1).strip("\"'"))
            else: bad.append("%s: witness sign with an unresolved datatype %r (fail closed)" % (rel, dt.group(1)))
        elif n == "actions/attest":
            ty = _cts.attest_action_type(ctx)                      # per match: the type of THIS step, not the first in the file
            if ty: add(ty)
            else: bad.append("%s: actions/attest with no literal predicate-type (fail closed)" % rel)
        elif n == "cosign attest":
            tys = _cts.cosign_types(ctx)
            if not tys: bad.append("%s: cosign attest with no --type (fail closed)" % rel)
            for v in tys:
                if re.fullmatch(r"https?://\S+", v): add(v)
                elif v in SHORT: add(SHORT[v])
                else: bad.append("%s: cosign attest with an unresolved --type (%s) (fail closed)" % (rel, v))
        elif n in ("cosign sign-blob", "sigstore python sign"):
            add(e["pseudo"])
            if _cts.is_prov(e, ctx): add(PROV)
        elif e.get("pseudo"): add(e["pseudo"])
        else: bad.append("%s: signer %s has no resolver and no pseudo type in the table (fail closed)" % (rel, n))
texts = {os.path.relpath(f, base): open(f).read() for f in files}
for rel, txt in texts.items(): scan(rel, txt)
scripts, serrs = _cts.reachable_scripts(base, texts)
bad += ["unresolved script reference (fail closed): " + x for x in serrs]
for sp in sorted(scripts):
    if sp == "bin/chain-verify.py": continue
    scan(sp, open(os.path.join(base, sp), errors="replace").read())
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
export CHAIN_SIGNER_TABLE="$root/bin/chain-test-signers.json" CHAIN_ROOT="$root"
judge() { python3 "$work/judge.py" "$1"; }
expect() { # expect ok|caught LABEL DIR
  local out rc=0
  out=$(judge "$3") || rc=$?
  if [ "$1" = ok ] && [ "$rc" = 0 ]; then pass=$((pass + 1)); echo "ok   $2"
  elif [ "$1" = caught ] && [ "$rc" != 0 ]; then pass=$((pass + 1)); echo "ok   $2 (caught: ${out:0:140})"
  else failn=$((failn + 1)); echo "FAIL $2 -> ${out:0:500}"; fi
}
expect_named() { # expect_named LABEL DIR FILE : the judge fails AND its message names FILE (so the mutation, not the fixture, is what failed)
  local out rc=0
  out=$(judge "$2") || rc=$?
  if [ "$rc" != 0 ] && printf '%s' "$out" | grep -qF -- "$3"; then pass=$((pass + 1)); echo "ok   $1 (caught: ${out:0:140})"
  else failn=$((failn + 1)); echo "FAIL $1 -> rc=$rc, message does not name $3: ${out:0:300}"; fi
}
nosign() { rm -f "$1/.github/workflows/stage-sign.yml"; }
mk() { # mk NAME  -> a known-good tree
  local d="$work/$1"; rm -rf "$d"; mkdir -p "$d/.github/workflows" "$d/.github/policy"
  printf 'jobs:\n  sign:\n    steps:\n      - run: python3 bin/chain-verify.py sign --check --digests "$D" --build-record b.json\n' > "$d/.github/workflows/stage-sign.yml"
  mkdir -p "$d/bin"; printf '#!/usr/bin/env bash\n' > "$d/bin/build.sh"
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
d=$(mk wsl); nosign "$d"; printf 'jobs:\n  c:\n    steps:\n      - run: witness run --step c -a slsa -- ./x\n' > "$d/.github/workflows/stage-verify.yml"; sed -i.bak '/slsa.dev/d' "$d/.github/policy/chain-records.json"
expect_named "witness run -a slsa is the ONLY provenance producer here; with its row removed the judge names stage-verify.yml" "$d" "stage-verify.yml"
d=$(mk sbom); printf 'jobs:\n  c:\n    steps:\n      - uses: actions/attest-sbom@%s # v3\n' "$(printf 'a%.0s' $(seq 40))" > "$d/.github/workflows/stage-verify.yml"
expect caught "actions/attest-sbom (a known signer with no finer resolver) with no row fails" "$d"
d=$(mk gen); nosign "$d"; printf 'jobs:\n  c:\n    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@%s\n' "$(printf 'a%.0s' $(seq 40))" > "$d/.github/workflows/stage-verify.yml"; sed -i.bak '/slsa.dev/d' "$d/.github/policy/chain-records.json"
expect_named "slsa-github-generator is the ONLY provenance producer here; with its row removed the judge names stage-verify.yml" "$d" "stage-verify.yml"
for form in '-a=slsa' '-aslsa' '-a product,slsa' '--attestations slsa' '--attestations=slsa' '--attestor slsa' '-c witness.yaml'; do
  d=$(mk "wf_$(printf '%s' "$form" | tr -c 'a-z' _)"); nosign "$d"; printf 'jobs:\n  c:\n    steps:\n      - run: witness run --step c %s -- ./x\n' "$form" > "$d/.github/workflows/stage-verify.yml"; sed -i.bak '/slsa.dev/d' "$d/.github/policy/chain-records.json"
  expect_named "witness run $form is the only provenance producer; with its row removed the judge names stage-verify.yml" "$d" "stage-verify.yml"
done
d=$(mk gflag); nosign "$d"; printf 'jobs:\n  c:\n    steps:\n      - run: witness --log-level debug run --step c -a slsa -- ./x\n' > "$d/.github/workflows/stage-verify.yml"; sed -i.bak '/slsa.dev/d' "$d/.github/policy/chain-records.json"
expect_named "a global flag before the subcommand does not hide witness run -a slsa" "$d" "stage-verify.yml"
d=$(mk cblob); printf 'jobs:\n  c:\n    steps:\n      - run: cosign attest-blob --yes --statement s.json --bundle b.json\n' > "$d/.github/workflows/stage-verify.yml"
expect_named "cosign attest-blob with no --type is unresolved and fails closed, naming the file" "$d" "stage-verify.yml"
d=$(mk cflag); printf 'jobs:\n  c:\n    steps:\n      - run: cosign --verbose sign --yes "$IMG"\n' > "$d/.github/workflows/stage-verify.yml"
expect_named "cosign --verbose sign (a global flag first) is still an image signature with no row" "$d" "stage-verify.yml"
d=$(mk hashq); printf 'jobs:\n  c:\n    steps:\n      - run: echo "step #1"; cosign sign --yes "$IMG"\n' > "$d/.github/workflows/stage-verify.yml"
expect_named "a '#' inside quotes does not hide a signer on the same line" "$d" "stage-verify.yml"
d=$(mk wra); printf 'jobs:\n  c:\n    steps:\n      - uses: testifysec/witness-run-action@%s # v1\n' "$(printf 'a%.0s' $(seq 40))" > "$d/.github/workflows/stage-verify.yml"; nosign "$d"; sed -i.bak '/slsa.dev/d' "$d/.github/policy/chain-records.json"
expect_named "testifysec/witness-run-action is a provenance producer (fail closed) and needs a row" "$d" "stage-verify.yml"
d=$(mk make); printf 'jobs:\n  c:\n    steps:\n      - run: make publish\n' > "$d/.github/workflows/stage-verify.yml"; printf 'publish:\n\tcosign sign --yes $(IMG)\n' > "$d/Makefile"
expect_named "a Makefile a workflow runs signs an image with no row" "$d" "Makefile"
d=$(mk js); mkdir -p "$d/scripts"; printf 'jobs:\n  c:\n    steps:\n      - run: node scripts/pub.js\n' > "$d/.github/workflows/stage-verify.yml"; printf 'require("child_process").execSync("cosign sign --yes " + process.env.IMG)\n' > "$d/scripts/pub.js"
expect_named "a node script a workflow runs signs an image with no row" "$d" "scripts/pub.js"
d=$(mk trailing); printf 'jobs:\n  c:\n    steps:\n      - run: cosign sign --yes "$IMG" # verify only\n' > "$d/.github/workflows/stage-verify.yml"
expect caught "a trailing comment exempts nothing (cosign sign with no row still fails)" "$d"
d=$(mk script); mkdir -p "$d/bin"; printf 'jobs:\n  c:\n    steps:\n      - run: bash bin/publish.sh\n' > "$d/.github/workflows/stage-verify.yml"; printf '#!/usr/bin/env bash\ncosign sign --yes "$IMG"\n' > "$d/bin/publish.sh"
expect caught "a script a workflow runs signs an image with no row (bin/publish.sh)" "$d"
d=$(mk scriptvar); mkdir -p "$d/bin"; printf 'jobs:\n  c:\n    steps:\n      - run: ./bin/publish.sh\n' > "$d/.github/workflows/stage-verify.yml"; printf '#!/usr/bin/env bash\ncosign attest --yes --type "$T" --predicate p.json "$IMG"\n' > "$d/bin/publish.sh"
expect caught "a script a workflow runs attests with an unresolved type: fails closed" "$d"
d=$(mk cvsign2); printf 'jobs:\n  c:\n    steps:\n      - run: python3 bin/chain-verify.py sign --check --signer cosign --digests d.json --build-record b.json --policy p.json --out provenance\n' > "$d/.github/workflows/stage-verify.yml"
expect ok "chain-verify.py sign resolves to SLSA provenance v1 (already has a row)" "$d"
SH40=$(printf 'a%.0s' $(seq 40))
rmprov() { sed -i.bak '/slsa.dev/d' "$1/.github/policy/chain-records.json"; }
d=$(mk twoatt); printf 'jobs:\n  c:\n    steps:\n      - uses: actions/attest@%s # v4\n        with:\n          predicate-type: https://slsa.dev/provenance/v1\n      - uses: actions/attest@%s # v4\n        with:\n          predicate-type: https://example.com/second/v1\n' "$SH40" "$SH40" > "$d/.github/workflows/stage-verify.yml"; nosign "$d"
expect_named "two actions/attest steps in one file: the SECOND step's own unlisted type is seen (round 5, per-match type)" "$d" "https://example.com/second/v1"
d=$(mk attml); printf 'jobs:\n  c:\n    steps:\n      - uses: actions/attest@%s # v4\n        with:\n          subject-path: dist/x\n          predicate-type: https://slsa.dev/provenance/v1\n' "$SH40" > "$d/.github/workflows/stage-verify.yml"; nosign "$d"; rmprov "$d"
expect_named "actions/attest with the predicate-type on a later line is read: provenance with its row removed names the file" "$d" "stage-verify.yml"
d=$(mk wvar); printf 'jobs:\n  c:\n    steps:\n      - run: witness run --step c -a "$ATT" -- ./x\n' > "$d/.github/workflows/stage-verify.yml"; nosign "$d"; rmprov "$d"
expect_named "witness run -a \"\$ATT\" (a variable attestor list) is unresolved: treated as provenance, fails closed" "$d" "stage-verify.yml"
d=$(mk wexpr); printf 'jobs:\n  c:\n    steps:\n      - run: witness run --step c -a ${{ inputs.att }} -- ./x\n' > "$d/.github/workflows/stage-verify.yml"; nosign "$d"; rmprov "$d"
expect_named "witness run -a \${{ expression }} is unresolved: treated as provenance" "$d" "stage-verify.yml"
d=$(mk wfold); printf 'jobs:\n  c:\n    steps:\n      - run: >-\n          witness run --step c\n          -a slsa -- ./x\n' > "$d/.github/workflows/stage-verify.yml"; nosign "$d"; rmprov "$d"
expect_named "witness run -a slsa on the next line of a folded scalar is read" "$d" "stage-verify.yml"
d=$(mk wnext); printf 'jobs:\n  c:\n    steps:\n      - run: |\n          witness run --step c -a\n          slsa -- ./x\n' > "$d/.github/workflows/stage-verify.yml"; nosign "$d"; rmprov "$d"
expect_named "witness run -a with its value on the next line is read" "$d" "stage-verify.yml"
d=$(mk wcfg2); printf 'jobs:\n  c:\n    steps:\n      - run: witness run --step c -a product -c witness.yaml -- ./x\n' > "$d/.github/workflows/stage-verify.yml"; nosign "$d"; rmprov "$d"
expect_named "witness run -a product -c cfg.yaml is flagged: the config file can add the slsa attestor" "$d" "stage-verify.yml"
d=$(mk twotype); printf 'jobs:\n  c:\n    steps:\n      - run: cosign attest --yes --type spdx --type slsaprovenance1 --predicate p.json "$IMG"\n' > "$d/.github/workflows/stage-verify.yml"; nosign "$d"; rmprov "$d"
expect_named "cosign attest with a repeated --type: the second (slsaprovenance1) is not hidden by the first" "$d" "stage-verify.yml"
d=$(mk blobprov); printf 'jobs:\n  c:\n    steps:\n      - run: cosign sign-blob --yes provenance.intoto.jsonl --bundle b.json\n' > "$d/.github/workflows/stage-verify.yml"; nosign "$d"; rmprov "$d"
expect_named "cosign sign-blob of a provenance blob is provenance" "$d" "stage-verify.yml"
d=$(mk blobplain); printf 'jobs:\n  c:\n    steps:\n      - run: cosign sign-blob --yes checksums.txt --bundle b.json\n' > "$d/.github/workflows/stage-verify.yml"
expect_named "cosign sign-blob of checksums is a signature that needs a row" "$d" "stage-verify.yml"
d=$(mk sigpy); printf 'jobs:\n  c:\n    steps:\n      - run: python3 -m sigstore attest --predicate p.json dist/x\n' > "$d/.github/workflows/stage-verify.yml"; nosign "$d"; rmprov "$d"
expect_named "the python sigstore CLI attest is a provenance signer" "$d" "stage-verify.yml"
d=$(mk notation); printf 'jobs:\n  c:\n    steps:\n      - run: notation sign "$IMG"\n' > "$d/.github/workflows/stage-verify.yml"
expect_named "notation sign is a known signer that needs a row" "$d" "stage-verify.yml"
d=$(mk intoto); printf 'jobs:\n  c:\n    steps:\n      - run: in-toto-run --step-name build -- ./x\n' > "$d/.github/workflows/stage-verify.yml"
expect_named "in-toto-run is a known signer that needs a row" "$d" "stage-verify.yml"
# scripts a workflow reaches: every form resolves, and what cannot be resolved is an error naming the workflow
d=$(mk ws); mkdir -p "$d/bin"; printf 'jobs:\n  c:\n    steps:\n      - run: bash "$GITHUB_WORKSPACE/bin/pub.sh"\n' > "$d/.github/workflows/stage-verify.yml"; printf '#!/usr/bin/env bash\ncosign sign --yes "$IMG"\n' > "$d/bin/pub.sh"
expect_named "bash \"\$GITHUB_WORKSPACE/bin/pub.sh\" is resolved and its signing call seen" "$d" "bin/pub.sh"
d=$(mk ws2); mkdir -p "$d/bin"; printf 'jobs:\n  c:\n    steps:\n      - run: bash ${{ github.workspace }}/bin/pub.sh\n' > "$d/.github/workflows/stage-verify.yml"; printf '#!/usr/bin/env bash\ncosign sign --yes "$IMG"\n' > "$d/bin/pub.sh"
expect_named "bash \${{ github.workspace }}/bin/pub.sh is resolved" "$d" "bin/pub.sh"
d=$(mk cdp); mkdir -p "$d/scripts"; printf 'jobs:\n  c:\n    steps:\n      - run: cd scripts && ./pub.sh\n' > "$d/.github/workflows/stage-verify.yml"; printf '#!/usr/bin/env bash\ncosign sign --yes "$IMG"\n' > "$d/scripts/pub.sh"
expect_named "cd scripts && ./pub.sh is resolved through the cd prefix" "$d" "scripts/pub.sh"
d=$(mk noext); mkdir -p "$d/bin"; printf 'jobs:\n  c:\n    steps:\n      - run: ./bin/publish\n' > "$d/.github/workflows/stage-verify.yml"; printf '#!/usr/bin/env bash\ncosign sign --yes "$IMG"\n' > "$d/bin/publish"; chmod +x "$d/bin/publish"
expect_named "an extensionless script that starts with #! is scanned" "$d" "bin/publish"
d=$(mk pym); mkdir -p "$d/tools"; printf 'jobs:\n  c:\n    steps:\n      - run: python3 -m tools.pub\n' > "$d/.github/workflows/stage-verify.yml"; printf 'import subprocess\nsubprocess.run(["x"])  # cosign sign --yes img\n' > "$d/tools/pub.py"; printf 'cosign sign --yes img\n' >> "$d/tools/pub.py"
expect_named "python3 -m tools.pub is resolved to tools/pub.py" "$d" "tools/pub.py"
d=$(mk trans); mkdir -p "$d/bin"; printf 'jobs:\n  c:\n    steps:\n      - run: bash bin/a.sh\n' > "$d/.github/workflows/stage-verify.yml"; printf '#!/usr/bin/env bash\nbash "$(dirname "$0")/b.sh"\n' > "$d/bin/a.sh"; printf '#!/usr/bin/env bash\ncosign sign --yes "$IMG"\n' > "$d/bin/b.sh"
expect_named "a script that calls another script is followed (bin/a.sh -> bin/b.sh)" "$d" "bin/b.sh"
d=$(mk unres); printf 'jobs:\n  c:\n    steps:\n      - run: bash "$SOME_DIR/pub.sh"\n' > "$d/.github/workflows/stage-verify.yml"
expect_named "a script path in an unknown variable is an error naming the workflow (fail closed)" "$d" "stage-verify.yml"
d=$(mk missing); printf 'jobs:\n  c:\n    steps:\n      - run: bash bin/gone.sh\n' > "$d/.github/workflows/stage-verify.yml"
expect_named "a script reference with no such file is an error naming the workflow (fail closed)" "$d" "stage-verify.yml"
d=$(mk nvar); mkdir -p "$d/bin"; printf 'jobs:\n  c:\n    steps:\n      - run: bash bin/a.sh\n' > "$d/.github/workflows/stage-verify.yml"; printf '#!/usr/bin/env bash\nS=bin/pub\nbash "$S.sh"\n' > "$d/bin/a.sh"; printf '#!/usr/bin/env bash\ncosign attest --type slsaprovenance1 --predicate p.json "$IMG"\n' > "$d/bin/pub.sh"
expect_named "a script that reaches its next script through a variable is an error naming the script, not skipped (round 6)" "$d" "bin/a.sh"
d=$(mk ntest); mkdir -p "$d/bin"; printf 'jobs:\n  c:\n    steps:\n      - run: bash bin/x-test.sh\n' > "$d/.github/workflows/stage-verify.yml"; printf '#!/usr/bin/env bash\nbash "$work/gen.sh"\n' > "$d/bin/x-test.sh"
expect_named "a *-test.sh with an unresolved reference, reached from a stage file, is judged strictly" "$d" "bin/x-test.sh"
d=$(mk ntest2); mkdir -p "$d/bin"; printf 'jobs:\n  c:\n    steps:\n      - run: bash bin/x-test.sh\n' > "$d/.github/workflows/ci.yml"; printf '#!/usr/bin/env bash\nbash "$work/gen.sh"\n' > "$d/bin/x-test.sh"
expect ok "a *-test.sh that builds throw-away scripts and is reached only from ci.yml is not an error" "$d"
d=$(mk comment); printf '# cosign sign would go here\njobs: {}\n' > "$d/.github/workflows/stage-verify.yml"
expect ok "a signing command inside a comment is not a producer" "$d"
expect ok "the real repository: every produced record type has a row with a claim and a stage consumer" "$root"
EXPECT=63
echo "pass=$pass fail=$failn"
if [ $((pass + failn)) != "$EXPECT" ]; then echo "FAIL case count $((pass + failn)) != expected $EXPECT (a case was skipped or added)"; exit 1; fi
[ "$failn" = 0 ]
