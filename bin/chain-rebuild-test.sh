#!/usr/bin/env bash
# proves: REQ-CHAIN-005-AC3 (the comparison); REQ-CHAIN-005-AC1, AC2, AC4 and AC5 are proven by bin/chain-build-wiring-test.sh
# (the Rebuild stage-file allowlist, the script order, the job graph), which shares its judges with this lane's Build tests.
# RED until bin/chain-verify.py has the rebuild-compare subcommand (tests before implementation, step 4 of the nine-step process).
#
# Rebuild's comparison (v0.3.0 rules 31, 54, 59, 64, 70; advisor read-back 0338). Runs on ubuntu-24.04 or macOS with: bash, python3, jq.
# No network, no keys: the comparison is plain digests. Build's record is NOT re-verified here: chain-verify.py stage-start did that
# immediately before in the same job (the script order is pinned in bin/chain-build-wiring-test.sh), and rebuild-compare only reads
# the product hash Witness recorded for items.json from the record's payload.
#
# THE CLI THIS TEST ASSUMES (the implementer matches it; anything else is a change to this header first):
#   chain-verify.py rebuild-compare --build-record REC.json --expected ITEMS.json --actual ITEMS2.json --out VERDICT.json
#     REC.json   Build's Witness collection as a DSSE envelope; its Statement holds the product subject
#                https://witness.dev/attestations/product/v0.1/file:items.json with digest {sha256,...}
#                (in-toto-witness docs/tutorials/artifact-policy.md:58-70).
#     ITEMS.json {"<item>":"sha256:<64 lower-case hex>"}: the item names are exactly .github/policy/rebuild-items.json (the committed
#                list; this test's REQUIRED below is the same list, and the real-repo case compares them).
#     exit 1, first line of stderr `refused at rebuild: <cause>: <items>` with cause one of
#       digest        sha256(ITEMS.json bytes) != the product hash in REC.json, or REC.json has no / two file:items.json subjects
#       format        a value is not sha256:<64 lower-case hex> (upper case, sha512:, 63 hex, a number, null), or a duplicate key
#       missing       an item of the committed list is absent from --expected or --actual (the line names it and the side)
#       unexpected    an item that is not on the list is present on either side (the line names it)
#       differs       the value differs in --expected and --actual (the line names EVERY differing item)
#     exit 0 only when every listed item is present on both sides and identical. VERDICT.json is written in EVERY case
#     {"equal":bool,"items":[{"name","expected","actual","status":"same|differs|missing-expected|missing-actual|unexpected"}]}
#     (sorted by name) and holds both digests of each differing item. Comparison is of the strings only: no size, time or order.
#     exit 2 (usage / unreadable file) is NOT a refusal and never a pass.
# THE ITEMS (cache-3f's interface note and its UPDATE): per-architecture apk by apk-tool.py digest [F L748]; the modules SBOM and the
# full lock file by sha256 of the bytes [F L744, L894-895]; the IMAGE is the OCI INDEX digest as the registry shows it, which
# assemble-image.sh writes as OUT/<variant>.digest, plus one item per per-architecture manifest from OUT/<variant>.manifests
# (`<arch> sha256:<hex>`, arch amd64|arm64; bin/oci-digest.py TAR verifies every blob hashes to its name): image-<variant> and
# image-<variant>-manifest-<arch>. PROPOSED/UNVERIFIED (no cache test fixes them): the apkindex, inputs-manifest, SBOM-directory and
# binary item layouts.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
CV="$root/bin/chain-verify.py"
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
pass=0 failn=0
ok()  { pass=$((pass + 1)); echo "ok   $1"; }
bad() { failn=$((failn + 1)); echo "FAIL $1"; }
REQUIRED="apk-standard-x86_64 apk-standard-aarch64 apk-fips-x86_64 apk-fips-aarch64 apkindex-x86_64 apkindex-aarch64 modules-sbom-standard modules-sbom-fips inputs-manifest-standard inputs-manifest-fips lock-production lock-fips image-production image-production-manifest-amd64 image-production-manifest-arm64 image-fips image-fips-manifest-amd64 image-fips-manifest-arm64 sbom-production sbom-fips binary-standard-x86_64 binary-standard-aarch64 binary-fips-x86_64 binary-fips-aarch64 archive-checksums"
python3 - "$W" $REQUIRED <<'PY'
import base64, hashlib, json, sys
w, items = sys.argv[1], sys.argv[2:]
def val(i, salt=""): return "sha256:" + hashlib.sha256((i + salt).encode()).hexdigest()
exp = {i: val(i) for i in items}
def dump(name, obj, raw=None):
    b = raw if raw is not None else (json.dumps(obj, sort_keys=True, indent=1) + "\n").encode()
    open(w + "/" + name, "wb").write(b); return hashlib.sha256(b).hexdigest()
def record(name, subjects):
    st = {"_type": "https://in-toto.io/Statement/v0.1", "predicateType": "https://witness.testifysec.com/attestation-collection/v0.1",
          "subject": subjects, "predicate": {"name": "build", "attestations": []}}
    env = {"payloadType": "application/vnd.in-toto+json", "payload": base64.b64encode(json.dumps(st).encode()).decode(), "signatures": []}
    json.dump(env, open(w + "/" + name, "w"))
def subj(h, name="https://witness.dev/attestations/product/v0.1/file:items.json"):
    return {"name": name, "digest": {"sha256": h, "gitoid:sha1": "gitoid:blob:sha1:" + "0" * 40, "gitoid:sha256": "gitoid:blob:sha256:" + "1" * 64}}
h = dump("exp.json", exp); dump("act.json", exp)
record("rec.json", [subj(h), {"name": "https://witness.dev/attestations/product/v0.1/file:digests.json", "digest": {"sha256": "a" * 64}}])
record("rec-none.json", [{"name": "https://witness.dev/attestations/product/v0.1/file:digests.json", "digest": {"sha256": "a" * 64}}])
record("rec-two.json", [subj(h), subj("b" * 64)])
record("rec-wrongname.json", [subj(h, "https://witness.dev/attestations/product/v0.1/file:items.json.bak")])
record("rec-material.json", [subj(h, "https://witness.dev/attestations/material/v0.1/file:items.json")])
# one-item differences, one file per item (flip the last hex digit: one nibble, the smallest change a digest string can show)
for i in items:
    a = dict(exp); v = a[i]; a[i] = v[:-1] + ("0" if v[-1] != "0" else "1"); dump("act-diff-%s.json" % i, a)
    m = dict(exp); del m[i]; dump("act-miss-%s.json" % i, m)
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
refuse() { # refuse LABEL CAUSE ITEMS-REGEX REC EXP ACT  (ITEMS: the items the first line must name, exact set when given as a|b)
  cmp_run "$4" "$5" "$6"; if ! no_crash; then bad "$1 -> a Python traceback is a crash, not a refusal"; return; fi
  local first; first=$(head -1 "$W/err" 2> /dev/null || true)
  if [ "$RC" = 1 ] && [[ "$first" == "refused at rebuild: $2: "* ]] && { [ -z "$3" ] || python3 - "$first" "$3" <<'PY'
import re, sys
first, want = sys.argv[1], sys.argv[2].split("|")
named = set(re.findall(r"[a-z0-9-]+", first.split(": ", 2)[2]))
sys.exit(0 if all(w in named for w in want) else 1)
PY
  } && [ -f "$W/verdict.json" ] && jq -e '.equal == false' "$W/verdict.json" > /dev/null 2>&1; then ok "$1"
  else bad "$1 -> exit $RC, first line '$first', verdict=$([ -f "$W/verdict.json" ] && echo present || echo absent)"; fi; }
[ -f "$CV" ] && ok "bin/chain-verify.py exists" || bad "bin/chain-verify.py does not exist (RED: not implemented yet)"
accept "005-AC3 identical items on both sides are accepted" rec.json exp.json act.json
if [ -f "$W/verdict.json" ]; then jq -e '.equal == true and (.items|length == 25) and ([.items[].status]|unique == ["same"]) and (.items == (.items|sort_by(.name)))' "$W/verdict.json" > /dev/null && ok "005-AC3 the accepted verdict lists all 25 items as same, sorted by name" || bad "005-AC3 accepted verdict shape: $(head -c 200 "$W/verdict.json")"; else bad "005-AC3 no verdict written on success (RED)"; fi
for i in $REQUIRED; do
  refuse "005-AC3 one differing nibble in $i blocks and names exactly it" differs "$i" rec.json exp.json "act-diff-$i.json"
  if [ -f "$W/verdict.json" ]; then jq -e --arg i "$i" '([.items[]|select(.status=="differs")|.name]==[$i]) and (.items[]|select(.name==$i)|(.expected|startswith("sha256:")) and (.actual|startswith("sha256:")) and .expected != .actual)' "$W/verdict.json" > /dev/null && ok "005-AC3 the verdict marks only $i as differs, with both digests" || bad "005-AC3 verdict for $i: $(head -c 160 "$W/verdict.json")"; else bad "005-AC3 no verdict for a difference in $i (RED)"; fi
done
refuse "005-AC3 three differing items are all named, not just the first" differs "apk-standard-x86_64|lock-fips|archive-checksums" rec.json exp.json act-diff3.json
for i in apk-fips-aarch64 image-production binary-standard-x86_64 archive-checksums; do
  refuse "005-AC3 an item missing on the Rebuild side ($i) is a difference" missing "$i" rec.json exp.json "act-miss-$i.json"
done
refuse "005-AC3 an item missing on the Build side is a difference (and is named with its side)" missing "$(echo $REQUIRED | cut -d' ' -f4)" rec-miss.json exp-miss.json act.json
refuse "005-AC3 an item that is not on the committed list, on the Rebuild side, is refused" unexpected unlisted-item rec.json exp.json act-extra.json
refuse "005-AC3 an item that is not on the committed list, on the Build side, is refused" unexpected unlisted-item rec-extra.json exp-extra.json act-extra.json
for k in upper sha512 short long num null bare ws dupkey; do refuse "005-AC3 a malformed digest ($k) is a format refusal, not a quiet difference" format "" rec.json exp.json "act-fmt-$k.json"; done
refuse "005-AC3 a duplicate key in the actual items (last-wins parsing could hide a difference) is a format refusal" format "" rec.json exp.json act-dupkey.json
refuse "005-AC3 Build's items.json changed after Witness recorded its hash is refused" digest "" rec.json exp-tampered.json act.json
refuse "005-AC3 a record with no file:items.json product subject is refused" digest "" rec-none.json exp.json act.json
refuse "005-AC3 a record with two file:items.json subjects is refused" digest "" rec-two.json exp.json act.json
refuse "005-AC3 a subject named file:items.json.bak does not count as the product" digest "" rec-wrongname.json exp.json act.json
refuse "005-AC3 a material subject named file:items.json does not count as the product" digest "" rec-material.json exp.json act.json
rc=$(rc_of rebuild-compare --build-record "$W/does-not-exist.json" --expected "$W/exp.json" --actual "$W/act.json" --out "$W/v2.json"); [ "$rc" = 2 ] && ok "005-AC3 an unreadable record is a usage error (exit 2), never a pass" || bad "005-AC3 unreadable record -> exit $rc, wanted 2"
rc=$(rc_of rebuild-compare --build-record "$W/rec.json" --expected "$W/exp.json" --out "$W/v3.json"); [ "$rc" = 2 ] && ok "005-AC3 a missing --actual is a usage error (exit 2)" || bad "005-AC3 missing --actual -> exit $rc, wanted 2"
# the committed list (the implementation adds .github/policy/rebuild-items.json) is exactly the one the CLI contract names
if [ -f "$root/.github/policy/rebuild-items.json" ]; then
  python3 - "$root/.github/policy/rebuild-items.json" "$W/required.json" <<'PY' && ok "005-AC3 .github/policy/rebuild-items.json is exactly the 25 items this test requires" || bad "005-AC3 rebuild-items.json differs from the contract list"
import json, sys
a, b = json.load(open(sys.argv[1])), json.load(open(sys.argv[2]))
sys.exit(0 if sorted(a) == sorted(b) and len(a) == len(set(a)) else 1)
PY
else bad "005-AC3 .github/policy/rebuild-items.json does not exist (RED: the implementation commits the list)"; fi
# nothing published: the only file rebuild-compare writes is the verdict (rule 64: Release publishes Build's bytes)
rm -rf "$W/clean"; mkdir "$W/clean"; (cd "$W/clean" && python3 "$CV" rebuild-compare --build-record "$W/rec.json" --expected "$W/exp.json" --actual "$W/act.json" --out verdict.json > /dev/null 2>&1 || true)
[ -f "$CV" ] && [ "$(ls "$W/clean" | tr '\n' ' ')" = "verdict.json " ] && ok "005-AC4 rebuild-compare writes nothing but its verdict (no artifact for Release to pick up)" || bad "005-AC4 files written by rebuild-compare: '$(ls "$W/clean" 2> /dev/null | tr '\n' ' ')'"
TOTAL=$((pass + failn)); EXPECT=80
echo "pass=$pass fail=$failn"
if [ "$TOTAL" != "$EXPECT" ]; then echo "FAIL case count $TOTAL != expected $EXPECT (a case was skipped or added)"; exit 1; fi
[ "$failn" = 0 ]
