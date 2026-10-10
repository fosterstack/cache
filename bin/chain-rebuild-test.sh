#!/usr/bin/env bash
# proves: REQ-CHAIN-005-AC3, REQ-CHAIN-005-AC7 — the comparison. REQ-CHAIN-005-AC1, AC2, AC4, AC5 and AC6 are proven by bin/chain-build-wiring-test.sh
# (the Rebuild stage-file allowlist, the script order, the job graph), which shares its judges with this lane's Build tests.
# Written before bin/chain-verify.py had the rebuild-compare subcommand (tests before implementation, step 4 of the nine-step process).
#
# Rebuild's comparison (v0.3.0 rules 31, 54, 59, 64, 70; advisor read-back 0338). Runs on ubuntu-24.04 or macOS with: bash, python3, jq.
# No network, no keys: the comparison is plain digests. Build's record is NOT re-verified here: chain-verify.py stage-start did that
# immediately before in the same job (the script order is pinned in bin/chain-build-wiring-test.sh), and rebuild-compare only reads
# the product hash Witness recorded for items.json from the record's payload.
#
# THE CLI THIS TEST ASSUMES (the implementer matches it; anything else is a change to this header first):
#   chain-verify.py rebuild-compare [--snapshot] --build-record REC.json --expected ITEMS.json --actual ITEMS2.json --out VERDICT.json
#     REC.json   Build's Witness collection as a DSSE envelope; its Statement holds the product subject
#                https://witness.dev/attestations/product/v0.1/file:items.json with digest {sha256,...}
#                (in-toto-witness docs/tutorials/artifact-policy.md:58-70).
#     ITEMS.json {"<item>":"sha256:<64 lower-case hex>"}: the item names are exactly .github/policy/rebuild-items.json (the committed
#                list; this test's REQUIRED below is the same list, and the real-repo case compares them).
#     exit 1, first line of stderr `refused at rebuild: <cause>: <items>` (the items, and only they, space separated) with cause one of
#       digest        sha256(ITEMS.json bytes) != the product hash in REC.json, or REC.json has no / two file:items.json subjects
#       format        a value is not sha256:<64 lower-case hex> (upper case, sha512:, 63 hex, a number, null), or a duplicate key
#       missing       an item of the committed list is absent from --expected or --actual (the FIRST line names ONLY the item names, space
#                     separated; a later line gives the side)
#       unexpected    an item that is not on the list is present on either side (the line names it)
#       step          (--snapshot only) the collection is not snapshot-build; without --snapshot a snapshot- record is `refused at rebuild: snapshot record`
#       differs       the value differs in --expected and --actual (the line names EVERY differing item)
#     exit 0 only when every listed item is present on both sides and identical. VERDICT.json is written in EVERY case
#     {"equal":bool,"items":[{"name","expected","actual","status":"same|differs|missing-expected|missing-actual|unexpected"}]}
#     (sorted by name) and holds both digests of each differing item. Comparison is of the strings only: no size, time or order.
#     exit 2 (usage / unreadable file) is NOT a refusal and never a pass.
# WHERE THE FILES ARE (fix round 1, Opus B4 / Sonnet B1): the Build stage runs its command from the repo root (no witness -d), writes items.json at the
# repo root, and Witness names a product subject relative to the working directory, so the real subject is file:items.json (and file:digests.json for
# PR 1's sign --check): exactly what this contract names. Rebuild's verdict is written to witness-rebuild/verdict.json, a product of Rebuild's record
# (subject file:witness-rebuild/verdict.json) uploaded in the witness-rebuild artifact: that is how the verdict travels (it is the stage's only output).
# THE ITEMS (29, the list REQUIRED below), from cache-3f's interface note and its UPDATE. What cache's tests fix:
#   - the apk item is `apk-tool.py digest APK` by name, in its output form sha256:<hex> [F L748]. Which sections it covers is cache's to change
#     (control and data, signature excluded), so this test does not name them; bin/chain-bind-test.sh proves, against the real items-apk, that the item
#     differs from the whole-file sha256 and ignores the signature;
#   - the full lock file and the modules SBOM are the sha256 of their bytes [F L744, L894-895];
#   - the image is the OCI INDEX digest as the registry shows it, which assemble-image.sh writes as OUT/<variant>.digest, plus one item per platform
#     manifest from OUT/<variant>.manifests (`<arch> sha256:<hex>`, arch amd64|arm64; bin/oci-digest.py TAR verifies every blob hashes to its name):
#     image-<variant> and image-<variant>-manifest-<arch>.
#   Added in fix round 2 (PROPOSED, advisor to confirm): the four Linux archives archive-linux-amd64, archive-linux-arm64, archive-fips-linux-amd64 and
#   archive-fips-linux-arm64, each the sha256 of the archive file, because rule 54 compares every digest Release will publish and Sign's digests.json
#   covers them (rules 35 and 51).
#   PROPOSED/UNVERIFIED (no cache test fixes them): the apkindex, inputs-manifest, SBOM-directory and binary item layouts.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
CV="$root/bin/chain-verify.py"
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
pass=0 failn=0
ok()  { pass=$((pass + 1)); echo "ok   $1"; }
bad() { failn=$((failn + 1)); echo "FAIL $1"; }
REQUIRED="apk-standard-x86_64 apk-standard-aarch64 apk-fips-x86_64 apk-fips-aarch64 apkindex-x86_64 apkindex-aarch64
  modules-sbom-standard modules-sbom-fips inputs-manifest-standard inputs-manifest-fips lock-production lock-fips
  image-production image-production-manifest-amd64 image-production-manifest-arm64
  image-fips image-fips-manifest-amd64 image-fips-manifest-arm64 sbom-production sbom-fips
  binary-standard-x86_64 binary-standard-aarch64 binary-fips-x86_64 binary-fips-aarch64
  archive-checksums archive-linux-amd64 archive-linux-arm64 archive-fips-linux-amd64 archive-fips-linux-arm64"
python3 - "$W" $REQUIRED <<'PY'
import base64, hashlib, json, sys
w, items = sys.argv[1], sys.argv[2:]
def val(i, salt=""): return "sha256:" + hashlib.sha256((i + salt).encode()).hexdigest()
exp = {i: val(i) for i in items}
def dump(name, obj, raw=None):
    b = raw if raw is not None else (json.dumps(obj, sort_keys=True, indent=1) + "\n").encode()
    open(w + "/" + name, "wb").write(b); return hashlib.sha256(b).hexdigest()
def record(name, subjects, collection="build"):
    st = {"_type": "https://in-toto.io/Statement/v0.1", "predicateType": "https://witness.testifysec.com/attestation-collection/v0.1",
          "subject": subjects, "predicate": {"name": collection, "attestations": []}}
    env = {"payloadType": "application/vnd.in-toto+json", "payload": base64.b64encode(json.dumps(st).encode()).decode(), "signatures": []}
    json.dump(env, open(w + "/" + name, "w"))
def subj(h, name="https://witness.dev/attestations/product/v0.1/file:items.json"):
    return {"name": name, "digest": {"sha256": h, "gitoid:sha1": "gitoid:blob:sha1:" + "0" * 40, "gitoid:sha256": "gitoid:blob:sha256:" + "1" * 64}}
h = dump("exp.json", exp); dump("act.json", exp)
record("rec.json", [subj(h), {"name": "https://witness.dev/attestations/product/v0.1/file:digests.json", "digest": {"sha256": "a" * 64}}])
record("rec-snap.json", [subj(h)], "snapshot-build")      # Build's record in snapshot mode: the collection is named snapshot-build
record("rec-none.json", [{"name": "https://witness.dev/attestations/product/v0.1/file:digests.json", "digest": {"sha256": "a" * 64}}])
record("rec-two.json", [subj(h), subj("b" * 64)])
record("rec-wrongname.json", [subj(h, "https://witness.dev/attestations/product/v0.1/file:items.json.bak")])
record("rec-material.json", [subj(h, "https://witness.dev/attestations/material/v0.1/file:items.json")])
# one-item differences, one file per item (flip the last hex digit: one nibble, the smallest change a digest string can show)
for i in items:
    a = dict(exp); v = a[i]; a[i] = v[:-1] + ("0" if v[-1] != "0" else "1"); dump("act-diff-%s.json" % i, a)
    m = dict(exp); del m[i]; dump("act-miss-%s.json" % i, m)
snap3 = dict(exp)
for i in ("image-fips", "sbom-fips", "apkindex-x86_64"): snap3[i] = snap3[i][:-1] + ("0" if snap3[i][-1] != "0" else "1")
dump("act-diff-snap3.json", snap3)
two = dict(exp)
for i in (items[0], items[7], items[-1]): two[i] = two[i][:-1] + ("0" if two[i][-1] != "0" else "1")
dump("act-diff3.json", two)
x = dict(exp); x["unlisted-item"] = val("x"); dump("act-extra.json", x)
dump("exp-extra.json", x); hx = hashlib.sha256(open(w + "/exp-extra.json", "rb").read()).hexdigest(); record("rec-extra.json", [subj(hx)])
m = dict(exp); del m[items[3]]; hm = dump("exp-miss.json", m); record("rec-miss.json", [subj(hm)])
for k, v in {"upper": exp[items[0]].upper().replace("SHA256:", "sha256:"), "sha512": "sha512:" + "a" * 128, "short": "sha256:" + "a" * 63,
             "long": "sha256:" + "a" * 65, "num": 7, "null": None, "bare": "a" * 64, "ws": "sha256:" + "a" * 64 + "\n"}.items():
    a = dict(exp); a[items[0]] = v; dump("act-fmt-%s.json" % k, a)
dump("act-dupkey.json", None, raw=('{"%s":"%s","%s":"%s"}' % (items[0], exp[items[0]], items[0], "sha256:" + "c" * 64)).encode())
t = dict(exp); t[items[1]] = val("tampered"); dump("exp-tampered.json", t)         # the file changed after Witness recorded its hash
# the committed list, for the real-repo case
json.dump(items, open(w + "/required.json", "w"))
PY
rc_of() { local rc=0; python3 "$CV" "$@" > "$W/out" 2> "$W/err" || rc=$?; echo "$rc"; }
cmp_run() { # cmp_run REC EXPECTED ACTUAL  -> sets RC, verdict in $W/verdict.json
  rm -f "$W/verdict.json"; RC=$(rc_of rebuild-compare --build-record "$W/$1" --expected "$W/$2" --actual "$W/$3" --out "$W/verdict.json"); }
no_crash() { ! grep -q Traceback "$W/err" 2> /dev/null; }
accept() { # accept LABEL REC EXP ACT
  cmp_run "$2" "$3" "$4"; if ! no_crash; then bad "$1 -> a Python traceback is a crash"; return; fi
  [ -f "$CV" ] && [ "$RC" = 0 ] && ok "$1" || bad "$1 -> exit $RC: $(head -c 200 "$W/err" | tr '\n' ' ')"; }
refuse() { # refuse LABEL CAUSE ITEMS REC EXP ACT  (ITEMS: the EXACT set of items the first line names, a|b; empty = no item check)
  cmp_run "$4" "$5" "$6"; if ! no_crash; then bad "$1 -> a Python traceback is a crash, not a refusal"; return; fi
  local first; first=$(head -1 "$W/err" 2> /dev/null || true)
  if [ "$RC" = 1 ] && [[ "$first" == "refused at rebuild: $2: "* ]] && { [ -z "$3" ] || python3 - "$first" "$3" <<'PY'
import re, sys
first, want = sys.argv[1], set(sys.argv[2].split("|"))
rest = first.split(": ", 2)[2]
named = {x for x in re.split(r"[\s,;]+", rest.strip()) if x}
sys.exit(0 if named == want else 1)       # EXACTLY the wanted items: naming an extra item is a fault too
PY
  } && [ -f "$W/verdict.json" ] && jq -e '.equal == false' "$W/verdict.json" > /dev/null 2>&1; then ok "$1"
  else bad "$1 -> exit $RC, first line '$first', verdict=$([ -f "$W/verdict.json" ] && echo present || echo absent)"; fi; }
[ -f "$CV" ] && ok "bin/chain-verify.py exists" || bad "bin/chain-verify.py does not exist (RED: not implemented yet)"
accept "005-AC3 identical items on both sides are accepted" rec.json exp.json act.json
if [ -f "$W/verdict.json" ];
then jq -e '.equal == true and (.items|length == 29) and ([.items[].status]|unique == ["same"]) and (.items == (.items|sort_by(.name)))' \
    "$W/verdict.json" > /dev/null && ok "005-AC3 the accepted verdict lists all 29 items as same, sorted by name" || bad \
    "005-AC3 accepted verdict shape: $(head -c 200 "$W/verdict.json")";
else bad "005-AC3 no verdict written on success (RED)";
fi
for i in $REQUIRED; do
  refuse "005-AC3 one differing nibble in $i blocks and names exactly it" differs "$i" rec.json exp.json "act-diff-$i.json"
  if [ -f "$W/verdict.json" ]; then
    want_exp=$(jq -r --arg i "$i" '.[$i]' "$W/exp.json"); want_act=$(jq -r --arg i "$i" '.[$i]' "$W/act-diff-$i.json")
    jq -e --arg i "$i" --arg e "$want_exp" --arg a "$want_act" '([.items[]|select(.status=="differs")|.name]==[$i])
        and (.items[]|select(.name==$i)|.expected == $e and .actual == $a and $e != $a and ($e|startswith("sha256:")))' \
        "$W/verdict.json" > /dev/null \
      && ok "005-AC3 the verdict marks only $i as differs, with the expected and actual values of the two files" \
      || bad "005-AC3 verdict for $i: $(head -c 160 "$W/verdict.json")"
  else
    bad "005-AC3 no verdict for a difference in $i (RED)"
  fi
done
three=$(set -- $REQUIRED; echo "${1}|${8}|${!#}")      # the first, the eighth and the last item: what act-diff3.json changes
refuse "005-AC3 three differing items are all named, not just the first" differs "$three" rec.json exp.json act-diff3.json
for i in apk-fips-aarch64 image-production binary-standard-x86_64 archive-checksums; do
  refuse "005-AC3 an item missing on the Rebuild side ($i) is a difference" missing "$i" rec.json exp.json "act-miss-$i.json"
done
refuse "005-AC3 an item missing on the Build side is a difference (and is named with its side)" missing "$(echo $REQUIRED | cut -d' ' -f4)" \
    rec-miss.json exp-miss.json act.json
refuse "005-AC3 an item that is not on the committed list, on the Rebuild side, is refused" unexpected unlisted-item rec.json exp.json act-extra.json
refuse "005-AC3 an item that is not on the committed list, on the Build side, is refused" unexpected unlisted-item rec-extra.json exp-extra.json act-extra.json
for k in upper sha512 short long num null bare ws;
do refuse "005-AC3 a malformed digest ($k) is a format refusal, not a quiet difference" format "" rec.json exp.json "act-fmt-$k.json";
done
refuse "005-AC3 a duplicate key in the actual items (last-wins parsing could hide a difference) is a format refusal" format "" rec.json exp.json act-dupkey.json
refuse "005-AC3 Build's items.json changed after Witness recorded its hash is refused" digest "" rec.json exp-tampered.json act.json
refuse "005-AC3 a record with no file:items.json product subject is refused" digest "" rec-none.json exp.json act.json
refuse "005-AC3 a record with two file:items.json subjects is refused" digest "" rec-two.json exp.json act.json
refuse "005-AC3 a subject named file:items.json.bak does not count as the product" digest "" rec-wrongname.json exp.json act.json
refuse "005-AC3 a material subject named file:items.json does not count as the product" digest "" rec-material.json exp.json act.json
rc=$(rc_of rebuild-compare --build-record "$W/does-not-exist.json" --expected "$W/exp.json" --actual "$W/act.json" --out "$W/v2.json");
[ -f "$CV" ] && [ "$rc" = 2 ] && head -1 "$W/err" | grep -qi usage && ok "005-AC3 an unreadable record is a usage error (exit 2), never a pass" || bad \
    "005-AC3 unreadable record -> exit $rc, wanted 2"
rc=$(rc_of rebuild-compare --build-record "$W/rec.json" --expected "$W/exp.json" --out "$W/v3.json");
[ -f "$CV" ] && [ "$rc" = 2 ] && head -1 "$W/err" | grep -qi usage && ok "005-AC3 a missing --actual is a usage error (exit 2)" || bad \
    "005-AC3 missing --actual -> exit $rc, wanted 2"
# REQ-CHAIN-005-AC7: a snapshot Rebuild compares against Build's SNAPSHOT record, and only with --snapshot
snap_run() { # snap_run FLAG REC EXPECTED ACTUAL -> RC; FLAG is --snapshot or empty
  rm -f "$W/verdict.json"; RC=$(rc_of rebuild-compare $1 --build-record "$W/$2" --expected "$W/$3" --actual "$W/$4" --out "$W/verdict.json"); }
# The snapshot verdict (witness-rebuild/snapshot-verdict.json; advisor and cache-3f agreed the shape, Oct 9), written in every case:
#   {"verdict":"identical"|"differs",
#    "images":[{"image":"production","build_digest":"sha256:...","rebuild_digest":"sha256:...","equal":true},{"image":"fips",...}],
#    "items_differing":[item names, sorted]}
# `images` holds the two image INDEX digests (items image-production and image-fips); the per-architecture manifests, apks, binaries, SBOMs and everything else
# appear in items_differing only. The verdict is `differs` if ANY item differs, not only an image, and the command then exits 1 (the job fails).
snap_verdict() { # snap_verdict LABEL ACTUAL-FILE EXPECTED-VERDICT EXPECTED-RC IMAGE-FIPS-EQUAL IMAGE-PRODUCTION-EQUAL DIFFERING-ITEMS(json) -> judged with jq
  local label=$1 act=$2 want=$3 wantrc=$4 fips_eq=$5 prod_eq=$6 differing=$7 exp_fips exp_prod act_fips act_prod
  snap_run --snapshot rec-snap.json exp.json "$act"
  exp_fips=$(jq -r '."image-fips"' "$W/exp.json"); exp_prod=$(jq -r '."image-production"' "$W/exp.json")
  act_fips=$(jq -r '."image-fips"' "$W/$act"); act_prod=$(jq -r '."image-production"' "$W/$act")
  if [ -f "$W/verdict.json" ] && [ "$RC" = "$wantrc" ] \
     && jq -e --arg v "$want" --arg ef "$exp_fips" --arg ep "$exp_prod" --arg af "$act_fips" --arg ap "$act_prod" \
        --argjson fe "$fips_eq" --argjson pe "$prod_eq" --argjson d "$differing" \
        '.verdict == $v and (keys | sort) == ["images", "items_differing", "verdict"] and .items_differing == $d
         and .images == [{"image": "production", "build_digest": $ep, "rebuild_digest": $ap, "equal": $pe},
                         {"image": "fips", "build_digest": $ef, "rebuild_digest": $af, "equal": $fe}]' "$W/verdict.json" > /dev/null 2>&1; then
    ok "$label"
  else
    bad "$label -> exit $RC (want $wantrc), verdict: $(head -c 300 "$W/verdict.json" 2> /dev/null | tr '\n' ' ')"
  fi
}
snap_verdict "005-AC7 identical items: verdict identical, both images equal with both digests, nothing differing, exit 0" act.json identical 0 true true '[]'
snap_verdict "005-AC7 one image differs (fips): verdict differs, the fips row is not equal and shows both digests, items_differing names it, exit 1" \
  "act-diff-image-fips.json" differs 1 false true '["image-fips"]'
snap_verdict "005-AC7 the production image differs: its row is not equal, the fips row is" \
  "act-diff-image-production.json" differs 1 true false '["image-production"]'
snap_verdict "005-AC7 ONLY an SBOM differs: verdict differs, both images equal, items_differing names the SBOM, exit 1 (not only images count)" \
  "act-diff-sbom-production.json" differs 1 true true '["sbom-production"]'
snap_verdict "005-AC7 only a per-architecture manifest differs: the image rows stay equal, items_differing names the manifest, exit 1" \
  "act-diff-image-fips-manifest-arm64.json" differs 1 true true '["image-fips-manifest-arm64"]'
snap_verdict "005-AC7 only a binary differs: verdict differs, exit 1" "act-diff-binary-standard-x86_64.json" differs 1 true true '["binary-standard-x86_64"]'
snap_verdict "005-AC7 only an apk differs: verdict differs, exit 1" "act-diff-apk-fips-aarch64.json" differs 1 true true '["apk-fips-aarch64"]'
snap_verdict "005-AC7 three items differ (image-fips, sbom-fips, apkindex-x86_64): all are named, sorted, exit 1" "act-diff-snap3.json" differs 1 false true \
  '["apkindex-x86_64","image-fips","sbom-fips"]'
snap_run --snapshot rec.json exp.json act.json
if [ "$RC" = 1 ] && head -1 "$W/err" | grep -q '^refused at rebuild: step: build$'; then
  ok "005-AC7 --snapshot refuses a release record named build (a snapshot compare never trusts a release record)"
else
  bad "005-AC7 --snapshot with a release record -> exit $RC: $(head -1 "$W/err")"
fi
snap_run "" rec-snap.json exp.json act.json
if [ "$RC" = 1 ] && [ "$(head -1 "$W/err")" = "refused at rebuild: snapshot record" ]; then
  ok "005-AC7 without --snapshot a snapshot-build record is refused as a snapshot record"
else
  bad "005-AC7 a snapshot record without --snapshot -> exit $RC: $(head -1 "$W/err")"
fi
snap_run --snapshot rec-snap.json exp-tampered.json act.json
if [ "$RC" = 1 ] && head -1 "$W/err" | grep -q '^refused at rebuild: digest: '; then
  ok "005-AC7 --snapshot still binds items.json to the hash the snapshot record holds"
else
  bad "005-AC7 --snapshot with a tampered items.json -> exit $RC: $(head -1 "$W/err")"
fi
# the committed list (the implementation adds .github/policy/rebuild-items.json) is exactly the one the CLI contract names
if [ -f "$root/.github/policy/rebuild-items.json" ]; then
  python3 - "$root/.github/policy/rebuild-items.json" "$W/required.json" <<'PY' \
    && ok "005-AC3 .github/policy/rebuild-items.json is exactly the 29 items this test requires" \
    || bad "005-AC3 rebuild-items.json differs from the contract list"
import json, sys
a, b = json.load(open(sys.argv[1])), json.load(open(sys.argv[2]))
sys.exit(0 if sorted(a) == sorted(b) and len(a) == len(set(a)) else 1)
PY
else bad "005-AC3 .github/policy/rebuild-items.json does not exist (RED: the implementation commits the list)"; fi
# nothing published: the only file rebuild-compare writes is the verdict (rule 64: Release publishes Build's bytes)
rm -rf "$W/clean";
mkdir "$W/clean";
(cd "$W/clean" && python3 "$CV" rebuild-compare --build-record "$W/rec.json" --expected "$W/exp.json" --actual "$W/act.json" --out verdict.json > \
    /dev/null 2>&1 || true)
[ -f "$CV" ] && [ "$(ls "$W/clean" | tr '\n' ' ')" = "verdict.json " ] && ok \
    "005-AC4 rebuild-compare writes nothing but its verdict (no artifact for Release to pick up)" || bad \
    "005-AC4 files written by rebuild-compare: '$(ls "$W/clean" 2> /dev/null | tr '\n' ' ')'"
TOTAL=$((pass + failn)); EXPECT=98
echo "pass=$pass fail=$failn"
if [ "$TOTAL" != "$EXPECT" ]; then echo "FAIL case count $TOTAL != expected $EXPECT (a case was skipped or added)"; exit 1; fi
[ "$failn" = 0 ]
