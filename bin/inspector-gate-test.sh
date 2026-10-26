#!/usr/bin/env bash
# Offline suite for bin/inspector-gate.py: the PR gate's Inspector verdict.
# What must hold: zero packages or unreadable output is "did not run" (2),
# never clean; any finding blocks (1) unless the published VEX covers it;
# the VEX match is by vulnerability id AND our product AND (when listed) the
# subcomponent name@version — a same-named package at another version, a
# different Go module, or another product's statement never suppresses.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
sut="${here}/inspector-gate.py"
vex="${here}/../test-evidence/vex-scope/busybox.openvex.json"
pass=0; fail=0
w="$(mktemp -d)"; trap 'rm -rf "$w"' EXIT

check() { # name want_rc regex -- args...
  local name="$1" want="$2" re="$3"; shift 3
  local out rc
  out="$(python3 "$sut" "$@" 2>&1)"; rc=$?
  if [ "$rc" -ne "$want" ]; then
    echo "FAIL: ${name}: rc ${rc}, want ${want}"; echo "$out" | sed 's/^/    /'; fail=$((fail+1)); return
  fi
  if ! grep -qE "$re" <<<"$out"; then
    echo "FAIL: ${name}: output did not match /$re/"; echo "$out" | sed 's/^/    /'; fail=$((fail+1)); return
  fi
  echo "ok: ${name}"; pass=$((pass+1))
}

cat > "$w/sbom.json" <<'EOF'
{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
 {"bom-ref":"c1","type":"library","name":"busybox","version":"1.37.0","purl":"pkg:generic/busybox@1.37.0"},
 {"bom-ref":"c2","type":"library","name":"github.com/golang-jwt/jwt/v4","purl":"pkg:golang/github.com/golang-jwt/jwt/v4@v4.5.0"},
 {"bom-ref":"c3","type":"library","name":"tzdata","purl":"pkg:deb/debian/tzdata@2025b-0+deb12u1?distro=debian-12"}]}
EOF
echo '{"bomFormat":"CycloneDX","components":[]}' > "$w/empty.json"
# ScanSbom's real response shape: the CycloneDX document under "sbom".
echo '{"sbom":{"bomFormat":"CycloneDX","specVersion":"1.5"}}' > "$w/clean.json"
f() { printf '{"sbom":{"bomFormat":"CycloneDX","specVersion":"1.5","vulnerabilities":[%s]}}' "$1" > "$w/$2"; }
f '{"id":"CVE-2025-60876","ratings":[{"severity":"medium"}],"affects":[{"ref":"c1"}]}' vexed.json
f '{"id":"CVE-2099-0001","ratings":[{"severity":"low"}],"affects":[{"ref":"c3"}]}' novex.json
f '{"id":"CVE-2025-60876","ratings":[{"severity":"medium"}],"affects":[{"ref":"x9"}]}' otherver.json
cat > "$w/otherver-sbom.json" <<'EOF'
{"components":[{"bom-ref":"x9","name":"busybox","purl":"pkg:generic/busybox@1.36.1"}]}
EOF
f '{"id":"CVE-2024-51744","ratings":[{"severity":"low"}],"affects":[{"ref":"c2"}]}' prodlevel.json
cat > "$w/foreign-vex.json" <<'EOF'
{"statements":[{"vulnerability":{"name":"CVE-2099-0001"},"status":"not_affected",
 "products":[{"@id":"pkg:oci/other?repository_url=ghcr.io/someone/other"}]}]}
EOF
cat > "$w/affected-vex.json" <<'EOF'
{"statements":[{"vulnerability":{"name":"CVE-2099-0001"},"status":"affected",
 "products":[{"@id":"pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache"}]}]}
EOF
cat > "$w/gomod-vex.json" <<'EOF'
{"statements":[{"vulnerability":{"name":"CVE-2099-0002"},"status":"not_affected",
 "products":[{"@id":"pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache",
   "subcomponents":[{"@id":"pkg:golang/github.com/other/jwt/v4@v4.5.0"}]}]}]}
EOF
f '{"id":"CVE-2099-0002","ratings":[{"severity":"high"}],"affects":[{"ref":"c2"}]}' gomod.json

check "clean scan passes with counts"       0 "3 packages, 0 finding"          t "$w/sbom.json" "$w/clean.json" "$vex"
check "zero packages = did not run"         2 "0 packages.*did not run"         t "$w/empty.json" "$w/clean.json" "$vex"
# rc-5a C round 2 (first look): the package count is the components that carry a package URL, as in the grype gate and the panel; files and
# components with an empty, null or non-string purl are not packages
echo '{"bomFormat":"CycloneDX","components":[{"type":"operating-system","name":"debian"},{"type":"file","name":"/usr/lib/f0"}]}' > "$w/filesonly.json"
echo '{"bomFormat":"CycloneDX","components":[{"type":"library","name":"a","purl":""},{"type":"library","name":"b","purl":null},{"type":"library","name":"c","purl":7},{"type":"library","name":"d","purl":{}}]}' > "$w/badpurls.json"
echo '{"bomFormat":"CycloneDX","components":[{"type":"operating-system","name":"debian"},{"type":"library","name":"tzdata","purl":"pkg:deb/debian/tzdata@2025b-0+deb12u1"}]}' > "$w/onepkg.json"
check "a components-without-purl inventory = did not run"      2 "0 packages.*did not run"  t "$w/filesonly.json" "$w/clean.json" "$vex"
check "empty, null, number and object purls are not packages"   2 "0 packages.*did not run"  t "$w/badpurls.json" "$w/clean.json" "$vex"
echo '{"bomFormat":"CycloneDX","components":[{"type":"file","name":"f","purl":"not-a-purl"},{"type":"library","name":"b","purl":"pkg:"},{"type":"library","name":"c","purl":"pkg:/"},{"type":"library","name":"d","purl":"pkg:deb/"},{"type":"library","name":"e","purl":"pkg:?q=/"}]}' > "$w/strpurls.json"
check "string purls that are not package URLs (not-a-purl, pkg:) are not packages"  2 "0 packages.*did not run"  t "$w/strpurls.json" "$w/clean.json" "$vex"
check "an operating-system component plus one package is 1 package" 0 "1 packages"            t "$w/onepkg.json" "$w/clean.json" "$vex"
check "unreadable output = did not run"     2 "could not read.*did not run"     t "$w/sbom.json" "$w/missing.json" "$vex"
check "the busybox fixture VEX covers busybox"        0 "1 covered by the published VEX"  t "$w/sbom.json" "$w/vexed.json" "$vex"
check "unvexed finding blocks"              1 "error::inspector t: CVE-2099-0001 debian/tzdata" t "$w/sbom.json" "$w/novex.json" "$vex"
check "VEX at another version does not suppress" 1 "busybox@1.36.1"             t "$w/otherver-sbom.json" "$w/otherver.json" "$vex"
check "product-level VEX statement covers"  0 "1 covered"                       t "$w/sbom.json" "$w/prodlevel.json" "$vex"
check "another product's VEX does not suppress" 1 "1 finding"                   t "$w/sbom.json" "$w/novex.json" "$w/foreign-vex.json"
check "status affected does not suppress"   1 "1 finding"                       t "$w/sbom.json" "$w/novex.json" "$w/affected-vex.json"
check "different Go module path does not suppress" 1 "golang-jwt/jwt/v4"        t "$w/sbom.json" "$w/gomod.json" "$w/gomod-vex.json"
# The envelope: a finding under "sbom" must block (round-1 blocker: a
# top-level read saw zero findings); an unwrapped document is also read;
# anything else is did-not-run, never zero findings.
printf '{"bomFormat":"CycloneDX","vulnerabilities":[{"id":"CVE-2099-0001","ratings":[{"severity":"critical"}],"affects":[{"ref":"c3"}]}]}' > "$w/bare.json"
echo '{"vulnerabilities":[]}' > "$w/noenv.json"
echo '{"sbom":{"components":[]}}' > "$w/notcdx.json"
echo '[]' > "$w/array.json"
printf '%s' '{"statements":[{"vulnerability":{"name":"CVE-2099-0001"},"status":"not_affected","products":[{"@id":"pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache-candidates"}]}]}' > "$w/mixed-vex.json"
check "finding inside the sbom envelope blocks" 1 "CVE-2099-0001 debian/tzdata.*low" t "$w/sbom.json" "$w/novex.json" "$vex"
check "bare CycloneDX response is read"     1 "1 finding.*|CVE-2099-0001.*critical" t "$w/sbom.json" "$w/bare.json" "$vex"
check "response without CycloneDX = did not run" 2 "not a CycloneDX document"  t "$w/sbom.json" "$w/noenv.json" "$vex"
check "envelope without bomFormat = did not run" 2 "not a CycloneDX document"  t "$w/sbom.json" "$w/notcdx.json" "$vex"
check "non-object response = did not run"   2 "not a CycloneDX document"        t "$w/sbom.json" "$w/array.json" "$vex"
check "mismatched name/url purl does not suppress" 1 "1 finding"               t "$w/sbom.json" "$w/novex.json" "$w/mixed-vex.json"
check "bad usage is did-not-run"           2 "usage"                           t "$w/sbom.json"

# Image scope (REQ-REL-004-AC1, chain-v030 review S2): a statement whose product carries variant= / arch= covers only that image; one with
# neither covers every image (as before); a scoped statement never covers an image whose identity the label does not give.
P='pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache'
scoped() { printf '{"statements":[{"vulnerability":{"name":"CVE-2025-60876"},"status":"not_affected","products":[{"@id":"%s","subcomponents":[{"@id":"pkg:generic/busybox@1.37.0"}]}]}]}' "$1" > "$w/$2"; }
scoped "$P&variant=production&arch=amd64" sc-prod-amd64.json
scoped "$P&variant=production" sc-prod.json
scoped "$P&arch=arm64" sc-arm64.json
scoped "$P" sc-none.json
scoped "$P&variant=production&arch=amd64&arch=arm64" sc-dup.json
check "scoped statement covers its own image"            0 "1 covered"   cand-production-amd64 "$w/sbom.json" "$w/vexed.json" "$w/sc-prod-amd64.json"
check "variant+arch scope does not cover another arch"   1 "1 finding"   cand-production-arm64 "$w/sbom.json" "$w/vexed.json" "$w/sc-prod-amd64.json"
check "variant+arch scope does not cover another variant" 1 "1 finding"  cand-fips-amd64 "$w/sbom.json" "$w/vexed.json" "$w/sc-prod-amd64.json"
check "cross variant and arch both differ"               1 "1 finding"   cand-fips-arm64 "$w/sbom.json" "$w/vexed.json" "$w/sc-prod-amd64.json"
check "variant-only scope covers both arches of it"      0 "1 covered"   cand-production-arm64 "$w/sbom.json" "$w/vexed.json" "$w/sc-prod.json"
check "variant-only scope does not cover the other variant" 1 "1 finding" cand-fips-arm64 "$w/sbom.json" "$w/vexed.json" "$w/sc-prod.json"
check "arch-only scope covers its arch in any variant"   0 "1 covered"   cand-fips-arm64 "$w/sbom.json" "$w/vexed.json" "$w/sc-arm64.json"
check "arch-only scope does not cover the other arch"    1 "1 finding"   cand-fips-amd64 "$w/sbom.json" "$w/vexed.json" "$w/sc-arm64.json"
check "unscoped statement still covers every image"      0 "1 covered"   cand-fips-arm64 "$w/sbom.json" "$w/vexed.json" "$w/sc-none.json"
check "scoped statement, label without identity: blocks" 1 "1 finding"   t "$w/sbom.json" "$w/vexed.json" "$w/sc-prod-amd64.json"
check "unscoped statement, label without identity: covers" 0 "1 covered" t "$w/sbom.json" "$w/vexed.json" "$w/sc-none.json"
check "a repeated qualifier is not read as a match"      1 "1 finding"   cand-production-arm64 "$w/sbom.json" "$w/vexed.json" "$w/sc-dup.json"
check "the busybox fixture VEX still covers a real tag label"  0 "1 covered"   cand-production-amd64 "$w/sbom.json" "$w/vexed.json" "$vex"

# Round-1 rulings (audit orchestrator, cache#548): the label is exactly cand-<variant>-<arch> (no suffix search), and a product's scope is read in
# bin/rescan-statement.py's grammar (raw split on &, no percent-decoding, only repository_url/variant/arch, lowercase, once, non-blank, known values);
# anything else covers nothing, so the finding blocks.
check "label other-production-amd64 has no identity: scoped statement blocks" 1 "1 finding" other-production-amd64 "$w/sbom.json" "$w/vexed.json" "$w/sc-prod-amd64.json"
check "label cand-fips-arm64-production-amd64 has no identity: scoped blocks"  1 "1 finding" cand-fips-arm64-production-amd64 "$w/sbom.json" "$w/vexed.json" "$w/sc-prod-amd64.json"
check "label with a trailing newline has no identity: scoped blocks"           1 "1 finding" $'cand-production-amd64\n' "$w/sbom.json" "$w/vexed.json" "$w/sc-prod-amd64.json"
check "label other-production-amd64: an unscoped statement still covers"       0 "1 covered" other-production-amd64 "$w/sbom.json" "$w/vexed.json" "$w/sc-none.json"
check "label cand-fips-arm64-production-amd64: an unscoped statement covers"   0 "1 covered" cand-fips-arm64-production-amd64 "$w/sbom.json" "$w/vexed.json" "$w/sc-none.json"
i=0
for q in '&VARIANT=production&ARCH=amd64' '&variant=production&ARCH=amd64' '&Arch=amd64' '&architecture=amd64' '&arch=amd64&ARCH=arm64' '&variant=&arch=amd64' '&variant=%70roduction' \
         '&arch=%61md64' '&%61rch=amd64' '&variant=debug' '&arch=riscv64' '&arch' '&arch=amd64&' '&color=red&arch=amd64' '&variant=production&variant=production'; do
  i=$((i+1)); scoped "$P$q" "sc-bad$i.json"
  check "malformed scope $q covers nothing (label cand-production-amd64)" 1 "1 finding" cand-production-amd64 "$w/sbom.json" "$w/vexed.json" "$w/sc-bad$i.json"
  check "malformed scope $q covers nothing (label without identity)"      1 "1 finding" t "$w/sbom.json" "$w/vexed.json" "$w/sc-bad$i.json"
done
for pid in "$P@sha256:abc" "pkg:oci/cache-candidates?repository_url=ghcr.io/fosterstack/cache-candidates@x" "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache-candidates" \
           "pkg:oci/cache?repository_url=ghcr.io/other/cache" "pkg:oci/cache@1?repository_url=ghcr.io/fosterstack/cache" "pkg:oci/cache" 'pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache\n'; do   # (the \n is JSON: the product string ends in a newline)
  i=$((i+1)); scoped "$pid" "sc-bad$i.json"
  check "malformed product $pid covers nothing" 1 "1 finding" cand-production-amd64 "$w/sbom.json" "$w/vexed.json" "$w/sc-bad$i.json"
done
scoped "pkg:golang/github.com/fosterstack/cache@v1.0.0" sc-gover.json
check "a version-pinned Go product covers nothing" 1 "1 finding" cand-production-amd64 "$w/sbom.json" "$w/vexed.json" "$w/sc-gover.json"
scoped 'pkg:golang/github.com/fosterstack/cache\n' sc-gonl.json
check "a Go product ending in a newline covers nothing (fail closed; the rescan reads it as the Go product)" 1 "1 finding" cand-production-amd64 "$w/sbom.json" "$w/vexed.json" "$w/sc-gonl.json"
scoped "pkg:golang/github.com/fosterstack/cache" sc-go.json
check "the plain Go product still covers" 0 "1 covered" cand-production-amd64 "$w/sbom.json" "$w/vexed.json" "$w/sc-go.json"
scoped "pkg:oci/cache-candidates?repository_url=ghcr.io/fosterstack/cache-candidates" sc-cand.json
check "a candidates-only statement does NOT cover (the gate scans the cache repository's images; REQ-REL-004-AC1: a statement suppresses only what it names)" 1 "1 finding" cand-production-amd64 "$w/sbom.json" "$w/vexed.json" "$w/sc-cand.json"
CANDP="pkg:oci/cache-candidates?repository_url=ghcr.io/fosterstack/cache-candidates"
scoped "$CANDP&variant=production&arch=amd64" sc-cand-scoped.json
check "a candidates-only statement scoped to production/amd64 does not cover that image" 1 "1 finding" cand-production-amd64 "$w/sbom.json" "$w/vexed.json" "$w/sc-cand-scoped.json"
scoped "$CANDP@sha256:$(printf 'a%.0s' $(seq 64))" sc-cand-digest.json
check "a candidates-only statement scoped to a digest does not suppress" 1 "1 finding" cand-production-amd64 "$w/sbom.json" "$w/vexed.json" "$w/sc-cand-digest.json"
check "a candidates-only statement does not cover a label without identity either" 1 "1 finding" t "$w/sbom.json" "$w/vexed.json" "$w/sc-cand.json"
python3 - "$w" "$CANDP" "$P" <<'PYX'
import json, sys
w, cand, repo = sys.argv[1:]
d = json.load(open(w + "/sc-none.json")); d["statements"][0]["products"] = [{"@id": cand, "subcomponents": [{"@id": "pkg:generic/busybox@1.37.0"}]}, {"@id": repo, "subcomponents": [{"@id": "pkg:generic/busybox@1.37.0"}]}]
json.dump(d, open(w + "/sc-both.json", "w"))
PYX
check "a statement naming both repositories still covers through the cache product" 0 "1 covered" cand-production-amd64 "$w/sbom.json" "$w/vexed.json" "$w/sc-both.json"
scoped "$P&variant=fips&arch=arm64" sc-fips-arm64.json
check "the exact grammar still scopes: fips/arm64 covers cand-fips-arm64"      0 "1 covered" cand-fips-arm64 "$w/sbom.json" "$w/vexed.json" "$w/sc-fips-arm64.json"
check "the exact grammar still scopes: fips/arm64 does not cover production-amd64" 1 "1 finding" cand-production-amd64 "$w/sbom.json" "$w/vexed.json" "$w/sc-fips-arm64.json"
# one bad statement does not fail the document: a good statement beside it still covers
python3 - "$w" <<'PYX'
import json, sys
w = sys.argv[1]; good = json.load(open(w + "/sc-none.json")); bad = json.load(open(w + "/sc-bad3.json"))
good["statements"] = bad["statements"] + good["statements"]; json.dump(good, open(w + "/sc-mixed.json", "w"))
PYX
check "a malformed statement beside a good one: the good one still covers"     0 "1 covered" cand-production-amd64 "$w/sbom.json" "$w/vexed.json" "$w/sc-mixed.json"

# The index itself (the #564 follow-up, Haiku out-of-diff note): covered() with NO image (the panel's per-image tally, which filters the statements first) must not be
# satisfied by a product whose scope the grammar cannot read or that is not this gate's repository, so vex_index drops such a product at index time.
IDXOUT="$(python3 - "$sut" <<'PYI'
import importlib.util, sys
sp = importlib.util.spec_from_file_location("g", sys.argv[1]); G = importlib.util.module_from_spec(sp); sp.loader.exec_module(G)
OCI = "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache"
def doc(*pids, subs=None):
    prods = [dict({"@id": p}, **({"subcomponents": [{"@id": x} for x in subs]} if subs else {})) for p in pids]
    return {"statements": [{"vulnerability": {"name": "CVE-9999-1"}, "status": "not_affected", "products": prods}]}
PKG = ("busybox", "1.37.0")
def cov(pid, image=None, subs=("pkg:generic/busybox@1.37.0",)):
    return G.covered(G.vex_index(doc(pid, subs=list(subs))), "CVE-9999-1", PKG, image)
def row(name, ok): print(("ok: " if ok else "FAIL: ") + name)
row("index: the cache image product covers, with no image given", cov(OCI) is True)
row("index: a variant/arch-scoped product covers, with no image given", cov(OCI + "&variant=production&arch=amd64") is True)
row("index: the Go product covers, with no image given", cov("pkg:golang/github.com/fosterstack/cache") is True)
row("index: a candidates-only product covers nothing, with no image given", cov("pkg:oci/cache-candidates?repository_url=ghcr.io/fosterstack/cache-candidates") is False)
row("index: a candidates-only product covers nothing, with an image given", cov("pkg:oci/cache-candidates?repository_url=ghcr.io/fosterstack/cache-candidates", G.image_identity("cand-production-amd64")) is False)
for q in ("&variant=debug", "&arch=riscv64", "&VARIANT=production", "&variant=%70roduction", "&variant=production&variant=production", "&arch", "&color=red"):
    row("index: a malformed-scope product %r covers nothing, with no image given" % q, cov(OCI + q) is False)
    row("index: a malformed-scope product %r covers nothing, with an image given" % q, cov(OCI + q, G.image_identity("cand-production-amd64")) is False)
row("index: a malformed product beside a good one: the good one still covers", G.covered(G.vex_index(doc(OCI + "&variant=debug", OCI, subs=["pkg:generic/busybox@1.37.0"])), "CVE-9999-1", PKG, None) is True)
row("index: the dropped product leaves no entry at all", G.vex_index(doc(OCI + "&variant=debug")) == {})
GO = "pkg:golang/github.com/fosterstack/cache"
for suffix in ("&arch=arm64", "&repository_url=ghcr.io/fosterstack/cache-candidates", "&x", "#sub", "/extra"):
    row("index: the Go product with the suffix %r covers nothing (it names another module), with no image" % suffix, cov(GO + suffix, subs=()) is False)
    row("index: the Go product with the suffix %r covers nothing, with an image" % suffix, cov(GO + suffix, G.image_identity("cand-production-amd64"), subs=()) is False)
row("index: the plain Go product with no subcomponent still covers every package", cov(GO, subs=()) is True)
# the @id the gate reads is the rescan's: the key when present (an empty @id is NOT replaced by identifiers.purl)
def idoc(at, purl):
    return {"statements": [{"vulnerability": {"name": "CVE-9999-1"}, "status": "not_affected", "products": [{"@id": at, "identifiers": {"purl": purl}, "subcomponents": [{"@id": "pkg:generic/busybox@1.37.0"}]}]}]}
row("index: an empty @id beside an identifiers.purl of our image covers nothing", G.covered(G.vex_index(idoc("", OCI)), "CVE-9999-1", PKG, None) is False)
row("index: an @id equal to the identifiers.purl covers", G.covered(G.vex_index(idoc(OCI, OCI)), "CVE-9999-1", PKG, None) is True)
# the LATEST statement per (vulnerability id, product, subcomponent set) wins (rc-5a 667 item 4): a later affected retracts an earlier not_affected, by timestamp when both parse, else by document order
def lw(*specs, subs=("pkg:generic/busybox@1.37.0",), prods=None):
    sts = []
    for status, ts in specs:
        s_ = {"vulnerability": {"name": "CVE-9999-1"}, "status": status, "products": [{"@id": p_, "subcomponents": [{"@id": x} for x in subs]} for p_ in (prods or [OCI])]}
        if ts is not None: s_["timestamp"] = ts
        sts.append(s_)
    return G.covered(G.vex_index({"statements": sts}), "CVE-9999-1", PKG, None)
T1, T2 = "2026-01-01T00:00:00Z", "2026-02-01T00:00:00+00:00"
row("latest: not_affected then affected (document order): retracted", lw(("not_affected", None), ("affected", None)) is False)
row("latest: affected then not_affected (document order): covers", lw(("affected", None), ("not_affected", None)) is True)
row("latest: under_investigation after not_affected retracts too", lw(("not_affected", None), ("under_investigation", None)) is False)
row("latest: the timestamps beat the document order (affected is earlier by time, later by position)", lw(("not_affected", T2), ("affected", T1)) is True)
row("latest: ...and the other way (affected is later by time, earlier by position)", lw(("affected", T2), ("not_affected", T1)) is False)
row("latest: an unparseable timestamp falls back to document order for the pair", lw(("not_affected", T1), ("affected", "garbage")) is False)
row("latest: a missing timestamp on one side falls back to document order for the pair", lw(("affected", T2), ("not_affected", None)) is True)
row("latest: equal timestamps: the later in the document wins", lw(("not_affected", T1), ("affected", T1)) is False)
row("latest: a different subcomponent set is another pair and is not retracted", G.covered(G.vex_index({"statements": [
    {"vulnerability": {"name": "CVE-9999-1"}, "status": "not_affected", "products": [{"@id": OCI, "subcomponents": [{"@id": "pkg:generic/busybox@1.37.0"}]}]},
    {"vulnerability": {"name": "CVE-9999-1"}, "status": "affected", "products": [{"@id": OCI, "subcomponents": [{"@id": "pkg:generic/zlib@1.2"}]}]}]}), "CVE-9999-1", PKG, None) is True)
row("latest: a different product is another pair and is not retracted", lw(("not_affected", None), prods=[OCI]) is True and G.covered(G.vex_index({"statements": [
    {"vulnerability": {"name": "CVE-9999-1"}, "status": "not_affected", "products": [{"@id": OCI, "subcomponents": [{"@id": "pkg:generic/busybox@1.37.0"}]}]},
    {"vulnerability": {"name": "CVE-9999-1"}, "status": "affected", "products": [{"@id": OCI + "&variant=fips", "subcomponents": [{"@id": "pkg:generic/busybox@1.37.0"}]}]}]}), "CVE-9999-1", PKG, None) is True)
row("latest: an alias is the same vulnerability (the later affected statement names the alias)", G.covered(G.vex_index({"statements": [
    {"vulnerability": {"name": "CVE-9999-1", "aliases": ["GHSA-x"]}, "status": "not_affected", "products": [{"@id": OCI, "subcomponents": [{"@id": "pkg:generic/busybox@1.37.0"}]}]},
    {"vulnerability": {"name": "GHSA-x"}, "status": "affected", "products": [{"@id": OCI, "subcomponents": [{"@id": "pkg:generic/busybox@1.37.0"}]}]}]}), "CVE-9999-1", PKG, None) is False)
# round 1 (cache#671): the pair is compared by what the readers match on, not by spelling; aliases are one vulnerability across the whole document; the order is one total order per pair
def two(first, second, f_prods=None, s_prods=None, f_subs=("pkg:generic/busybox@1.37.0",), s_subs=("pkg:generic/busybox@1.37.0",), f_name="CVE-9999-1", s_name="CVE-9999-1"):
    def stmt(status, name, prods, subs, extra=None):
        v = {"name": name}
        if extra: v["aliases"] = extra
        return {"vulnerability": v, "status": status, "products": [{"@id": q, "subcomponents": [{"@id": x} for x in subs]} for q in prods]}
    return G.covered(G.vex_index({"statements": [stmt(first, f_name, f_prods or [OCI], f_subs), stmt(second, s_name, s_prods or [OCI], s_subs)]}), "CVE-9999-1", PKG, None)
SC = OCI + "&variant=production&arch=amd64"
SC2 = OCI.replace("?repository_url=ghcr.io/fosterstack/cache", "?repository_url=ghcr.io/fosterstack/cache") + "&arch=amd64&variant=production"
row("latest: the same scope with its qualifiers in another order is the same product (retracted)", two("not_affected", "affected", [SC], [SC2]) is False)
row("latest: the same scope with the qualifiers swapped back (a not_affected after an affected) covers", two("affected", "not_affected", [SC], [SC2]) is True)
row("latest: another scope is another product (not retracted)", two("not_affected", "affected", [SC], [OCI + "&variant=fips&arch=amd64"]) is True)
row("latest: a subcomponent of another purl type is the same package (retracted)", two("not_affected", "affected", f_subs=("pkg:apk/busybox@1.37.0",), s_subs=("pkg:generic/busybox@1.37.0",)) is False)
row("latest: a subcomponent in another case is the same package (retracted)", two("not_affected", "affected", f_subs=("pkg:generic/BusyBox@1.37.0",)) is False)
row("latest: a percent-encoded subcomponent is the same package (retracted)", two("not_affected", "affected", f_subs=("pkg:generic/busybox@1.37.0",), s_subs=("pkg:generic/%62usybox@1.37.0",)) is False)
row("latest: another version is another package (not retracted)", two("not_affected", "affected", s_subs=("pkg:generic/busybox@1.36.0",)) is True)
AL = {"statements": [
    {"vulnerability": {"name": "CVE-9999-1", "aliases": ["GHSA-X"]}, "status": "affected", "products": [{"@id": OCI, "subcomponents": [{"@id": "pkg:generic/busybox@1.37.0"}]}]},
    {"vulnerability": {"name": "CVE-9999-1"}, "status": "not_affected", "products": [{"@id": OCI, "subcomponents": [{"@id": "pkg:generic/busybox@1.37.0"}]}]},
    {"vulnerability": {"name": "GHSA-X"}, "status": "affected", "products": [{"@id": OCI, "subcomponents": [{"@id": "pkg:generic/busybox@1.37.0"}]}]}]}
row("latest: an alias declared by one statement links the others (CVE, alias affected, CVE not_affected, alias affected): retracted", G.covered(G.vex_index(AL), "CVE-9999-1", PKG, None) is False)
def three(*specs):
    return G.covered(G.vex_index({"statements": [dict({"vulnerability": {"name": "CVE-9999-1"}, "status": st_, "products": [{"@id": OCI, "subcomponents": [{"@id": "pkg:generic/busybox@1.37.0"}]}]}, **({"timestamp": ts} if ts else {})) for st_, ts in specs]}), "CVE-9999-1", PKG, None)
row("latest: three not_affected with timestamps [Feb, none, Jan] are not all superseded (one total order)", three(("not_affected", T2), ("not_affected", None), ("not_affected", T1)) is True)
row("latest: a group with one missing timestamp is ordered by position: [not_affected Feb, affected none] retracts", three(("not_affected", T2), ("affected", None)) is False)
row("latest: a group where every statement has a time is ordered by time: [affected Feb, not_affected Jan, not_affected Jan2]", three(("affected", T2), ("not_affected", T1), ("not_affected", "2026-01-15T00:00:00Z")) is False)
TWO = {"statements": [
    {"vulnerability": {"name": "CVE-9999-1"}, "status": "not_affected", "products": [{"@id": OCI, "subcomponents": [{"@id": "pkg:generic/busybox@1.37.0"}]}, {"@id": GO, "subcomponents": [{"@id": "pkg:generic/busybox@1.37.0"}]}]},
    {"vulnerability": {"name": "CVE-9999-1"}, "status": "affected", "products": [{"@id": OCI, "subcomponents": [{"@id": "pkg:generic/busybox@1.37.0"}]}]}]}
IX = G.vex_index(TWO)
row("latest: retracting one product of a two-product statement leaves its sibling covered (the image is retracted, the Go product stays)", G.covered(IX, "CVE-9999-1", PKG, None) is True and G.superseded(TWO["statements"]) == {(0, 0)})
print("index-cases-run")
PYI
)"; idx_rc=$?
echo "$IDXOUT" | sed 's/^/  /'
[ "$idx_rc" = 0 ] && [ "$(grep -c '^\(ok\|FAIL\):' <<<"$IDXOUT")" = 57 ] && grep -qx 'index-cases-run' <<<"$IDXOUT" || { echo "FAIL: the index section ran $(grep -c '^\(ok\|FAIL\):' <<<"$IDXOUT") cases, want 57, or the section exited non-zero (a crash or a skipped case)"; fail=$((fail+1)); }
pass=$((pass + $(grep -c '^ok:' <<<"$IDXOUT"))); fail=$((fail + $(grep -c '^FAIL:' <<<"$IDXOUT")))

# The COMMITTED document (rc-5a G review round 1): the one statement covers the jwt/v4 module at any version, in the image and in the Go product, and nothing else.
live="${here}/../.vex/fosterstack-cache.openvex.json"
cat > "$w/live-sbom.json" <<'EOF'
{"components":[
 {"bom-ref":"j4","name":"github.com/golang-jwt/jwt/v4","purl":"pkg:golang/github.com/golang-jwt/jwt/v4@v4.5.0"},
 {"bom-ref":"j4b","name":"github.com/golang-jwt/jwt/v4","purl":"pkg:golang/github.com/golang-jwt/jwt/v4@v4.0.0"},
 {"bom-ref":"j5","name":"github.com/golang-jwt/jwt/v5","purl":"pkg:golang/github.com/golang-jwt/jwt/v5@v5.2.1"},
 {"bom-ref":"v4","name":"v4","purl":"pkg:generic/v4"},
 {"bom-ref":"bb","name":"busybox","purl":"pkg:generic/busybox@1.37.0"}]}
EOF
f '{"id":"CVE-2024-51744","ratings":[{"severity":"low"}],"affects":[{"ref":"j4"}]}' live-j4.json
f '{"id":"CVE-2024-51744","ratings":[{"severity":"low"}],"affects":[{"ref":"j4b"}]}' live-j4b.json
f '{"id":"CVE-2024-51744","ratings":[{"severity":"low"}],"affects":[{"ref":"j5"}]}' live-j5.json
f '{"id":"CVE-2024-51744","ratings":[{"severity":"low"}],"affects":[{"ref":"v4"}]}' live-v4.json
f '{"id":"CVE-2024-51744","ratings":[{"severity":"low"}],"affects":[{"ref":"bb"}]}' live-bb.json
check "live document: CVE-2024-51744 on jwt/v4 v4.5.0 is covered"          0 "1 covered" cand-production-amd64 "$w/live-sbom.json" "$w/live-j4.json" "$live"
check "live document: ...on jwt/v4 at another version is covered (the subcomponent names none)" 0 "1 covered" cand-fips-arm64 "$w/live-sbom.json" "$w/live-j4b.json" "$live"
check "live document: ...on jwt/v5 is NOT covered (another module)"        1 "1 finding" cand-production-amd64 "$w/live-sbom.json" "$w/live-j5.json" "$live"
check "live document: ...on a bare package named v4 is NOT covered (no last-segment match for a module path)" 1 "1 finding" cand-production-amd64 "$w/live-sbom.json" "$w/live-v4.json" "$live"
check "live document: ...on busybox is NOT covered (scoped to the module, not the image)" 1 "1 finding" cand-production-amd64 "$w/live-sbom.json" "$w/live-bb.json" "$live"

echo "----"
echo "inspector-gate: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
