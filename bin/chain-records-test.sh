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
# naming the file. Scanned: .github/workflows/*.yml and *.yaml, .github/actions/**/action.yml|yaml, a root action.yml, and the
# scripts LISTED in .github/policy/chain-scripts.json (advisor decision, Oct 9: a stage file may run nothing else, so there is no
# script discovery and no variable/heredoc/glob machinery; bin/chain-verify.py itself is excepted: only `chain-verify.py sign`
# in stage-sign.yml reaches its signing calls). Which tools sign is ONE table shared with chain-sign-wiring-test.sh
# (bin/chain-test-signers.json). Comments are stripped first (full-line and trailing). Exclusions, stated plainly: a signer that
# is not in the table is not seen (add it to the table first); signing done by a binary a script downloads at run time or reached
# through an argv array in script code is not seen.
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
def scan(rel, text, raw=False):
    def add(t): produced.setdefault(t, set()).add(rel)
    for e, ctx in _cts.calls(text, TABLE, not raw):      # a LISTED script is scanned raw: a signer name in a comment, quote or heredoc counts
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
# scripts: ONLY those listed in .github/policy/chain-scripts.json (a stage file may run nothing else: chain-sign-wiring-test.sh
# judges that grammar); a missing chain-scripts.json is that test's finding, not this one's. A listed script is scanned as RAW text
# (the same conservative text scan chain-sign-wiring-test.sh applies, advisor decision b, Oct 9): comments and quoted strings are not
# skipped, so a signer named anywhere in a listed script is a producer that needs a row (it over-reports by design).
if os.path.exists(os.path.join(base, ".github/policy/chain-scripts.json")):
    srows, serrs, _envn = _cts.load_scripts(base)
    bad += ["chain-scripts.json: " + x for x in serrs]
    for sp in sorted(srows):
        if sp == "bin/chain-verify.py": continue
        scan(sp, open(os.path.join(base, sp), errors="replace").read(), True)
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
  if [ "$rc" != 0 ] && grep -qF -- "$3" <<< "$out"; then pass=$((pass + 1)); echo "ok   $1 (caught: ${out:0:140})"
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
d=$(mk trailing); printf 'jobs:\n  c:\n    steps:\n      - run: cosign sign --yes "$IMG" # verify only\n' > "$d/.github/workflows/stage-verify.yml"
expect caught "a trailing comment exempts nothing (cosign sign with no row still fails)" "$d"
listed() { # listed DIR PATH TOOL...: write DIR/.github/policy/chain-scripts.json listing PATH with its real sha256 (a script a stage file may run)
  python3 - "$@" <<'PY'
import hashlib, json, os, sys
d, path, tools = sys.argv[1], sys.argv[2], sys.argv[3:]
f = d + "/.github/policy/chain-scripts.json"
j = json.load(open(f)) if os.path.exists(f) else {"scripts": []}
j["scripts"].append({"path": path, "sha256": hashlib.sha256(open(os.path.join(d, path), "rb").read()).hexdigest(), "tools": tools, "signs": "other", "reason": "x", "runs": []})
json.dump(j, open(f, "w"))
PY
}
d=$(mk lscript); mkdir -p "$d/bin"; printf '#!/usr/bin/env bash\ncosign sign --yes "$IMG"\n' > "$d/bin/publish.sh"; listed "$d" bin/publish.sh cosign
expect_named "a LISTED script that signs an image has no row: the judge names the script" "$d" "bin/publish.sh"
d=$(mk lscriptvar); mkdir -p "$d/bin"; printf '#!/usr/bin/env bash\ncosign attest --yes --type "$T" --predicate p.json "$IMG"\n' > "$d/bin/publish.sh"; listed "$d" bin/publish.sh cosign
expect_named "a LISTED script that attests with an unresolved type fails closed, naming the script" "$d" "bin/publish.sh"
d=$(mk lscriptpy); mkdir -p "$d/bin"; printf 'import subprocess\nsubprocess.run("cosign sign --yes x", shell=True)\n' > "$d/bin/publish.py"; listed "$d" bin/publish.py
expect_named "a LISTED python script is scanned for direct signing calls too" "$d" "bin/publish.py"
d=$(mk lscriptcmt); mkdir -p "$d/bin"; printf '#!/usr/bin/env bash\n# cosign sign the image later\necho nothing\n' > "$d/bin/publish.sh"; listed "$d" bin/publish.sh echo
expect_named "a signer named only in a COMMENT of a LISTED script is a producer that needs a row (raw text scan)" "$d" "bin/publish.sh"
d=$(mk lscriptq); mkdir -p "$d/bin"; printf '#!/usr/bin/env bash\necho "cosign sign --yes x"\n' > "$d/bin/publish.sh"; listed "$d" bin/publish.sh echo
expect_named "a signer named only inside a QUOTED string of a LISTED script is a producer that needs a row" "$d" "bin/publish.sh"
d=$(mk lscriptnoext); mkdir -p "$d/bin"; printf 'cosign sign --yes x\n' > "$d/bin/publish"; listed "$d" bin/publish
expect_named "a LISTED file with no extension and no shebang is scanned too" "$d" "bin/publish"
d=$(mk lscriptok); mkdir -p "$d/bin"; printf '#!/usr/bin/env bash\necho nothing signs here\n' > "$d/bin/ok.sh"; listed "$d" bin/ok.sh echo
expect ok "a listed script that signs nothing is no producer" "$d"
d=$(mk unlisted); mkdir -p "$d/bin"; printf '#!/usr/bin/env bash\ncosign sign --yes "$IMG"\n' > "$d/bin/hidden.sh"
expect ok "an UNLISTED script is not scanned here (a stage file cannot run it: chain-sign-wiring-test.sh refuses the unlisted path)" "$d"
d=$(mk lbadhash); mkdir -p "$d/bin"; printf '#!/usr/bin/env bash\necho a\n' > "$d/bin/ok.sh"; listed "$d" bin/ok.sh echo; printf '#!/usr/bin/env bash\necho changed\n' > "$d/bin/ok.sh"
expect_named "a listed script whose sha256 no longer matches is an error naming chain-scripts.json" "$d" "chain-scripts.json"
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
d=$(mk comment); printf '# cosign sign would go here\njobs: {}\n' > "$d/.github/workflows/stage-verify.yml"
expect ok "a signing command inside a comment is not a producer" "$d"
# KNOWN RED (strict): the real repository stays red on exactly one finding until PR 3 rewrites stage-verify.yml (its actions/attest step names
# no literal predicate-type). So that this suite can be a REQUIRED CI step now, that case is judged as a known red: the judge's whole output
# must be exactly that one finding (any other finding fails), and the day it goes green the case FAILS, so the PR that makes it green turns it
# back into `expect ok` here. The list lives only in this file (no flag or variable can add to it) and must hold exactly one case.
KNOWN_RED_N=0
known_red() {  # known_red LABEL GREEN-WHEN EXACT-OUTPUT DIR
  local out rc=0; KNOWN_RED_N=$((KNOWN_RED_N + 1))
  out=$(judge "$4") || rc=$?
  if [ "$rc" = 0 ]; then failn=$((failn + 1)); echo "FAIL $1 is GREEN now ($2): make it an ordinary expect ok and drop it from the known-red list"
  elif [ "$out" != "$3" ]; then failn=$((failn + 1)); echo "FAIL $1: the findings are not exactly the known one ($3): ${out:0:300}"
  else pass=$((pass + 1)); echo "ok   $1 (known red until $2: $out)"; fi; }
known_red "the real repository: every produced record type has a row with a claim and a stage consumer" "PR 3 rewrites stage-verify.yml" \
  ".github/workflows/stage-verify.yml: actions/attest with no literal predicate-type (fail closed)" "$root"
# the known-red judge is strict: run on a GREEN fixture tree it must report FAIL (so a known red that is fixed cannot linger silently)
if ( pass=0 failn=0; known_red "self-check" "x" "y" "$(mk kr_green)"; [ "$failn" = 1 ] ) > /dev/null; then pass=$((pass + 1)); echo "ok   known_red on a green tree fails (strict)"; else failn=$((failn + 1)); echo "FAIL known_red accepted a green tree"; fi
[ "$KNOWN_RED_N" = 1 ] && { pass=$((pass + 1)); echo "ok   the known-red list holds exactly one case"; } || { failn=$((failn + 1)); echo "FAIL the known-red list holds $KNOWN_RED_N cases, not exactly one"; }
EXPECT=59
echo "pass=$pass fail=$failn"
if [ $((pass + failn)) != "$EXPECT" ]; then echo "FAIL case count $((pass + failn)) != expected $EXPECT (a case was skipped or added)"; exit 1; fi
[ "$failn" = 0 ]
