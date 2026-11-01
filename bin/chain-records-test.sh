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
# the red cases of this suite are the ones listed in test-evidence/known-red.json (KR-RECORDS-1: the cache scripts Release's steps run that are not listed rows
# yet): the run passes only when they are EXACTLY the red cases (bin/chain-known-red.py)
if [ -z "${CHAIN_KNOWN_RED_INNER:-}" ]; then
  _rc=0; _out=$(CHAIN_KNOWN_RED_INNER=1 CHAIN_FINDINGS=1 bash "$0" "$@" 2>&1) || _rc=$?
  printf '%s\n' "$_out"
  printf '%s\n' "$_out" | python3 "$(cd "$(dirname "$0")" && pwd)/chain-known-red.py" judge --suite bin/chain-records-test.sh --inner-rc "$_rc"
  exit $?
fi
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
cat > "$work/judge.py" <<'PY'
import glob, json, os, re, sys
base = sys.argv[1]
import importlib.util
_spec = importlib.util.spec_from_file_location("chain_test_signers", os.path.join(os.environ["CHAIN_ROOT"], "bin/chain-test-signers.py"))
_cts = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(_cts)
STAGES = {"build", "sign", "rebuild", "check", "release", "customer"}
COLL = "https://witness.testifysec.com/attestation-collection/v0.1"
POLT = "https://witness.testifysec.com/policy/v0.1"
PROV = "https://slsa.dev/provenance/v1"
SHORT = {"slsaprovenance": "https://slsa.dev/provenance/v0.2", "slsaprovenance02": "https://slsa.dev/provenance/v0.2", "slsaprovenance1": PROV,
         "spdx": "https://spdx.dev/Document", "spdxjson": "https://spdx.dev/Document", "cyclonedx": "https://cyclonedx.org/bom",
         "vuln": "https://cosign.sigstore.dev/attestation/vuln/v1", "link": "https://in-toto.io/Link/v1"}
bad, produced = [], {}
def frozen_paths():
    """The legacy stage files listed in .github/policy/legacy-stage-files.json whose bytes match: what they produce still counts (their rows
    stay consumed), but their OWN fail-closed findings are left out until PRs 2-4 rewrite them. A changed or missing one is a finding."""
    import hashlib
    lp = os.path.join(base, ".github/policy/legacy-stage-files.json")
    if not os.path.exists(lp): return set()
    out = set()
    try: lrows = _cts.jload(lp)["files"]
    except Exception as ex: bad.append("legacy-stage-files.json is malformed (%s)" % ex); return out
    for r in lrows:
        f = os.path.join(base, r["path"])
        if not os.path.isfile(f): bad.append("legacy file missing: %s" % r["path"])
        elif hashlib.sha256(open(f, "rb").read()).hexdigest() != r["sha256"]: bad.append("legacy file changed (judged in full): %s" % r["path"])
        else: out.add(r["path"])
    return out
FROZEN = frozen_paths()
rf = os.path.join(base, ".github/policy/chain-records.json")
if not os.path.exists(rf):
    bad.append("missing: .github/policy/chain-records.json")
    rows = []
else:
    try: rows = _cts.jload(rf).get("records") or []
    except Exception as ex: bad.append("chain-records.json is malformed (%s)" % ex); rows = []
_bad_utf8 = _cts.non_utf8_yaml(base)        # final batch R-f: named, never a traceback
if _bad_utf8:
    print("; ".join("%s is not valid UTF-8 (it cannot be read, so it cannot be judged)" % x for x in _bad_utf8)); sys.exit(1)
_disc = []
files = _cts.signing_files(base, _disc)   # the ONE discovery routine, shared with chain-sign-wiring-test.sh (Codex #249 r7 B8, r8 B4)
bad += _disc
TABLE = _cts.load_table()
strip, logical = _cts.strip, _cts.logical
def scan(rel, text, raw=False):
    def add(t): produced.setdefault(t, set()).add(rel)
    bad = BAD if rel not in FROZEN else []          # a frozen legacy file's own findings are left out (its products still count)
    for e, ctx in _cts.calls(text, TABLE, not raw):      # a LISTED script is scanned raw: a signer name in a comment, quote or heredoc counts
        n = e["name"]
        why = _cts.unresolved_signing(e, ctx)               # Codex #249 r7 B7: an unresolved call is an explicit error, never an assumption
        if why: bad.append("%s: %s" % (rel, why)); continue
        if n == "witness run":
            add(COLL)
            if _cts.is_prov(e, ctx): add(PROV)
        elif n == "witness sign":
            dt = re.search(r"(?:-t|--datatype)[ =]+(\S+)", ctx)
            if not dt: add(POLT)
            elif re.fullmatch(r"https?://[^\s\"'$`]+", dt.group(1).strip("\"'")): add(dt.group(1).strip("\"'"))
            elif dt.group(1).strip("\"'") == "application/vnd.in-toto+json": add(COLL)   # Sign re-signs a building job's collection payload as it is (the Witness move, Oct 22 2026): the record type is the collection's
            else: bad.append("%s: witness sign with an unresolved datatype %r (fail closed)" % (rel, dt.group(1)))
        elif n == "actions/attest":
            ty = _cts.attest_action_type(ctx)                      # per match: the type of THIS step, not the first in the file
            if ty: add(ty)
            else: bad.append("%s: actions/attest with no literal predicate-type (fail closed)" % rel)
        elif n == "cosign attest":
            tys = _cts.cosign_types(ctx)
            if not tys: bad.append("%s: cosign attest with no --type (fail closed)" % rel)
            for v in tys:
                if re.fullmatch(r"https?://[^\s\"'$`\\]+", v): add(v)
                elif v in SHORT: add(SHORT[v])
                else: bad.append("%s: cosign attest with an unresolved --type (%s) (fail closed)" % (rel, v))
        elif n in ("cosign sign-blob", "sigstore python sign"):
            add(e["pseudo"])
            if _cts.is_prov(e, ctx): add(PROV)
        elif e.get("pseudo"): add(e["pseudo"])
        else: bad.append("%s: signer %s has no resolver and no pseudo type in the table (fail closed)" % (rel, n))
BAD = bad
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
        scan(sp, _cts.read_script(os.path.join(base, sp)), True)
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
ids = list(dict.fromkeys(bad))
if ids and os.environ.get("CHAIN_FINDINGS") == "1":      # output only: the structured ids the known-red judge compares (bin/chain-known-red.py); nothing else changes
    print("FINDINGS-JSON " + json.dumps(ids), file=sys.stderr)
print("; ".join(ids) or "ok")
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
# PR 4 (Release signs the release files keyless, one bundle each): a literal sign-blob has the cosign signature type and needs its row
d=$(mk relblob); printf 'jobs:\n  c:\n    steps:\n      - run: cosign sign-blob --yes --bundle release-files.sha256.bundle release-files.sha256\n' > "$d/.github/workflows/stage-verify.yml"
expect caught "a literal cosign sign-blob of the release file list with no row fails" "$d"
addrow "$d" "urn:cosign:signature" "a signature on the release files, each with a Rekor entry" customer
expect ok "the same sign-blob with the cosign signature row (consumer: customer) passes" "$d"
d=$(mk relrow); printf 'jobs:\n  c:\n    steps:\n      - run: cosign sign-blob --yes --bundle release-policy.bundle policy.json\n' > "$d/.github/workflows/stage-verify.yml"
addrow "$d" "urn:cosign:signature" "a signature on the release policy, with a Rekor entry" release
expect ok "the release policy's sign-blob with a row whose consumer is the release stage passes" "$d"
# S1 (#822 round 1; REQ-CHAIN-003-AC3 stays the AC; no sentence of it is made false): `chain-verify.py sign-record` is the one signing function for
# Witness collections, so it has a row in the signer table (the collection type) and a produced collection needs its row in chain-records.json
d=$(mk srec); printf 'jobs:\n  b:\n    steps:\n      - run: python3 bin/chain-verify.py sign-record --payload p --out o --template t\n' > "$d/.github/workflows/stage-build.yml"
expect ok "S1 a stage file whose only collection producer is chain-verify.py sign-record is seen: the collection row is the one it produces" "$d"
python3 - "$d" <<'PY'
import json, sys
f = sys.argv[1] + "/.github/policy/chain-records.json"; j = json.load(open(f)); j["records"] = [r for r in j["records"] if "attestation-collection" not in r["type"]]; json.dump(j, open(f, "w"))
PY
expect_named "S1 the same tree without the collection row fails: chain-verify.py sign-record produces a type that needs a row" "$d" "produced type has no row: https://witness.testifysec.com/attestation-collection/v0.1"
# (Codex #249 r7 B7, the class closed) a signing call whose type cannot be resolved fails closed BY NAME, even when the rows it would
# need exist: an unresolved attestor list, type, datatype or argument is an explicit error, never an assumption
uncase() { # uncase NAME 'run line' LABEL WORD [ok]: stage-verify.yml with that run line; caught and naming WORD (or ok)
  local d; d=$(mk "$1"); printf 'jobs:\n  c:\n    steps:\n      - run: |\n          ATT=slsa\n          %s\n' "$2" > "$d/.github/workflows/stage-verify.yml"
  if [ "${5:-}" = ok ]; then expect ok "$3" "$d"; else expect_named "$3" "$d" "$4"; fi; }
uncase u_w_var 'witness run -a "$ATTESTOR" -- bin/task.sh' 'witness run -a "$ATTESTOR" with the ordinary rows present is refused (Codex #249 r7 B7)' 'unresolved attestor list'
uncase u_w_bare 'witness run -a $ATT -- bin/task.sh' 'witness run -a $ATT (built on an earlier line) is refused' 'unresolved attestor list'
uncase u_w_subst 'witness run -a $(cat f) -- bin/task.sh' 'witness run -a $(cat f) is refused' 'unresolved attestor list'
uncase u_w_bt 'witness run -a `cat f` -- bin/task.sh' 'witness run -a `cat f` is refused' 'unresolved attestor list'
uncase u_w_config 'witness run --config witness.yaml -- bin/task.sh' 'witness run --config FILE is refused' 'unresolved attestor list'
uncase u_w_c 'witness run -c witness.yaml -- bin/task.sh' 'witness run -c FILE is refused' 'unresolved attestor list'
uncase u_w_env 'WITNESS_ATTESTATIONS=slsa witness run -- bin/task.sh' 'witness run with its attestors in a WITNESS_ environment variable is refused' 'unresolved attestor list'
uncase u_w_trail 'witness run -a product, -- bin/task.sh' 'witness run with a list that ends in a comma is refused' 'unresolved attestor list'
uncase u_w_ok 'witness run -a product,material -- bin/task.sh' 'control: witness run with a literal non-provenance attestor list' '' ok
uncase u_w_ok2 'witness run -a slsa -- bin/task.sh' 'control: witness run with a literal slsa attestor (the provenance row exists)' '' ok
uncase u_c_url 'cosign attest --type https://x.example/$(cat t) --predicate p img' 'cosign attest --type URL with a substitution inside is refused' 'unresolved --type'
uncase u_c_var 'cosign attest --type "$T" --predicate p img' 'cosign attest --type "$T" is refused' 'unresolved --type'
uncase u_ws_var 'witness sign -t "$DT" -f p.json -o s.json' 'witness sign -t "$DT" is refused (already)' 'unresolved datatype'
uncase u_ws_url 'witness sign -t https://x.example/$(cat t) -f p.json -o s.json' 'witness sign -t URL with a substitution inside is refused' 'unresolved datatype'
uncase u_ws_mime 'witness sign -t application/x-anything -f p.json -o s.json' 'witness sign -t with another media type is refused (only the in-toto payload type of a collection is known)' 'unresolved datatype'
uncase u_sb_var 'cosign sign-blob --yes "$F" --bundle b.json' 'cosign sign-blob of a variable blob is refused (its type cannot be known)' 'unresolved argument'
uncase u_sb_subst 'cosign sign-blob --yes $(ls *.json) --bundle b.json' 'cosign sign-blob of a substitution is refused' 'unresolved argument'
uncase u_sp_var 'sigstore sign "$F"' 'sigstore (python) sign of a variable blob is refused' 'unresolved argument'
uncase u_aa_expr 'true' 'control-shaped: a plain run line' '' ok
d=$(mk cossplit); printf 'jobs:\n  c:\n    steps:\n      - run: |\n          cos\\\n          ign sign --yes "$IMG"\n' > "$d/.github/workflows/stage-verify.yml"
expect caught "cos<backslash-newline>ign sign (bash joins the lines with no space: cosign sign) is seen as cosign sign and has no row" "$d"
# (Codex #249 r7 B8) composite actions and workflows ANYWHERE in the tree are scanned (one discovery routine shared with the wiring judge)
for c in 'b8_binreview:bin/review/action.yaml' 'b8_upper:Sub/ACTION.YML' 'b8_root:action.yml' 'b8_actq:.github/actions/q/action.yml'; do
  d=$(mk "${c%%:*}"); f="${c#*:}"; mkdir -p "$d/$(dirname "$f")"
  printf 'runs:\n  using: composite\n  steps:\n    - run: cosign attest --type https://example.invalid/unlisted --predicate p img\n      shell: bash\n' > "$d/$f"
  expect_named "a composite action at $f signing an unlisted type is caught by name (Codex #249 r7 B8)" "$d" "$f"
done
d=$(mk b8_wfout); mkdir -p "$d/tools/ci"; printf 'on: push\njobs:\n  x:\n    steps:\n      - run: cosign attest --type https://example.invalid/unlisted --predicate p img\n' > "$d/tools/ci/extra.yml"
expect_named "a .yml with top-level jobs: outside .github/workflows signing an unlisted type is caught by name (B8)" "$d" "tools/ci/extra.yml"
d=$(mk b8_plainyml); mkdir -p "$d/docs"; printf 'title: not a workflow\nsteps:\n  - cosign attest --type https://example.invalid/unlisted\n' > "$d/docs/notes.yml"
expect ok "control: a .yml with neither jobs: nor runs: at the top is not a workflow (not scanned)" "$d"
# (Codex #249 r8 B4, the class closed) a candidate .yml/.yaml anywhere is classified by its PARSED root mapping (jobs or runs -> scanned);
# a workflow-looking or .github/ candidate that does not parse is an error
d=$(mk b9_ind); mkdir -p "$d/$(dirname 'tools/ci/ind.yml')"; printf '  on: push\n  jobs:\n    x:\n      steps:\n        - run: cosign attest --type https://example.invalid/unlisted --predicate p img\n' > "$d/tools/ci/ind.yml"; expect_named "discovery: an indented root mapping (  jobs:) (Codex #249 r8 B4) is read and caught by name" "$d" "tools/ci/ind.yml"
d=$(mk b9_docstart); mkdir -p "$d/$(dirname 'tools/ci/doc.yml')"; printf -- '---\n# a comment\njobs:\n  x:\n    steps:\n      - run: cosign attest --type https://example.invalid/unlisted --predicate p img\n' > "$d/tools/ci/doc.yml"; expect_named "discovery: a root jobs: after --- and a comment is read and caught by name" "$d" "tools/ci/doc.yml"
d=$(mk b9_crlf); mkdir -p "$d/$(dirname 'tools/ci/crlf.yml')"; printf 'jobs:\r\n  x:\r\n    steps:\r\n      - run: cosign attest --type https://example.invalid/unlisted --predicate p img\r\n' > "$d/tools/ci/crlf.yml"; expect_named "discovery: a jobs: file with CRLF line endings is read and caught by name" "$d" "tools/ci/crlf.yml"
d=$(mk b9_flow); mkdir -p "$d/$(dirname 'tools/ci/flow.yml')"; printf '{"jobs": {"x": {"steps": [{"run": "cosign attest --type https://example.invalid/unlisted --predicate p img"}]}}}\n' > "$d/tools/ci/flow.yml"; expect_named "discovery: a JSON-style flow mapping {\"jobs\": ...} in a .yml file is read and caught by name" "$d" "tools/ci/flow.yml"
d=$(mk b9_runsflow); mkdir -p "$d/$(dirname 'tools/act/flow.yaml')"; printf '{"runs": {"using": "composite", "steps": [{"run": "cosign attest --type https://example.invalid/unlisted --predicate p img", "shell": "bash"}]}}\n' > "$d/tools/act/flow.yaml"; expect_named "discovery: a flow mapping with runs: (a composite) in a .yaml file is read and caught by name" "$d" "tools/act/flow.yaml"
d=$(mk b9_upper); mkdir -p "$d/$(dirname 'tools/ci/WF.YML')"; printf 'jobs:\n  x:\n    steps:\n      - run: cosign attest --type https://example.invalid/unlisted --predicate p img\n' > "$d/tools/ci/WF.YML"; expect_named "discovery: an upper-case .YML extension is read and caught by name" "$d" "tools/ci/WF.YML"
d=$(mk b9_tab); mkdir -p "$d/$(dirname 'tools/ci/tab.yml')"; printf 'jobs:\n\tx:\n\t\tsteps: []\n' > "$d/tools/ci/tab.yml"; expect_named "discovery: a jobs: file indented with tabs (YAML refuses it; fail closed) is read and caught by name" "$d" "tools/ci/tab.yml"
d=$(mk b9_ghbroken); mkdir -p "$d/$(dirname '.github/broken.yml')"; printf 'a: [unclosed\n' > "$d/.github/broken.yml"; expect_named "discovery: an unparsable .yml under .github/ (fail closed) is read and caught by name" "$d" ".github/broken.yml"
d=$(mk b9_dup); mkdir -p "$d/$(dirname 'tools/ci/dup.yml')"; printf 'jobs: {}\njobs:\n  x: {}\n' > "$d/tools/ci/dup.yml"; expect_named "discovery: a jobs: file with a duplicate root key (fail closed) is read and caught by name" "$d" "tools/ci/dup.yml"
d=$(mk b9_ctl); mkdir -p "$d/docs"; printf 'title: x\nsteps:\n  - cosign attest --type https://example.invalid/unlisted --predicate p img\n' > "$d/docs/notes2.yml"; expect ok "control: a parsed .yml with no jobs:/runs: root key is not scanned" "$d"
d=$(mk u_utf8); printf 'jobs:\n  c:\n    steps:\n      - run: echo \xff\xfe\n' > "$d/.github/workflows/stage-verify.yml"; rc=0; out=$(judge "$d" 2>&1) || rc=$?
if [ "$rc" = 1 ] && grep -F -q "stage-verify.yml" <<< "$out" && ! grep -F -q Traceback <<< "$out"; then pass=$((pass + 1)); echo "ok   a workflow that is not UTF-8 is a named error, never a traceback (R-f)"; else failn=$((failn + 1)); echo "FAIL invalid UTF-8 workflow -> rc=$rc ${out:0:240}"; fi
d=$(mk u_utf8a); mkdir -p "$d/bin/q"; printf 'runs:\n  using: composite\n  steps:\n    - run: echo \xff\n      shell: bash\n' > "$d/bin/q/action.yml"; rc=0; out=$(judge "$d" 2>&1) || rc=$?
if [ "$rc" = 1 ] && grep -F -q "bin/q/action.yml" <<< "$out" && ! grep -F -q Traceback <<< "$out"; then pass=$((pass + 1)); echo "ok   a composite action that is not UTF-8 is a named error (R-f)"; else failn=$((failn + 1)); echo "FAIL invalid UTF-8 composite -> rc=$rc ${out:0:240}"; fi
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
# ---- the real repository (no known-red allowance) -------------------------------------------------------------------------------------
# Judged over a copy of the TRACKED files of .github/ and bin/ (as CI sees them). PR 4 rewrote the last legacy stage file and deleted
# .github/policy/legacy-stage-files.json, so the whole tree is judged.
gone=$(cd "$root" && git ls-files --deleted -- .github bin)
if [ -n "$gone" ]; then echo "FAIL tracked file(s) deleted in the working tree, the real-tree cases cannot run: $(echo $gone | head -c 300)"; exit 1; fi
tracked_copy() { local d="$work/tree-$1"; rm -rf "$d"; mkdir -p "$d"; ( cd "$root" && git ls-files -z -- .github bin | tar --null -T - -cf - ) | tar -xf - -C "$d"; echo "$d"; }
expect ok "the real repository: every produced record type has a row with a claim and a stage consumer" "$(tracked_copy real)"
d=$(tracked_copy newattest); printf 'jobs:\n  a:\n    steps:\n      - uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6\n        with:\n          subject-path: x\n' > "$d/.github/workflows/scan-extra.yml"
expect_named "a NEW actions/attest without a literal predicate-type in a non-frozen file fails closed" "$d" "scan-extra.yml: actions/attest with no literal predicate-type"
EXPECT=101
echo "pass=$pass fail=$failn"
if [ $((pass + failn)) != "$EXPECT" ]; then echo "FAIL case count $((pass + failn)) != expected $EXPECT (a case was skipped or added)"; exit 1; fi
[ "$failn" = 0 ]
