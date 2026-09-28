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
vex="${here}/../.vex/fosterstack-cache.openvex.json"
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
echo '{"vulnerabilities":[]}' > "$w/clean.json"
f() { printf '{"vulnerabilities":[%s]}' "$1" > "$w/$2"; }
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
check "unreadable output = did not run"     2 "could not read.*did not run"     t "$w/sbom.json" "$w/missing.json" "$vex"
check "published VEX covers busybox"        0 "1 covered by the published VEX"  t "$w/sbom.json" "$w/vexed.json" "$vex"
check "unvexed finding blocks"              1 "error::inspector t: CVE-2099-0001 debian/tzdata" t "$w/sbom.json" "$w/novex.json" "$vex"
check "VEX at another version does not suppress" 1 "busybox@1.36.1"             t "$w/otherver-sbom.json" "$w/otherver.json" "$vex"
check "product-level VEX statement covers"  0 "1 covered"                       t "$w/sbom.json" "$w/prodlevel.json" "$vex"
check "another product's VEX does not suppress" 1 "1 finding"                   t "$w/sbom.json" "$w/novex.json" "$w/foreign-vex.json"
check "status affected does not suppress"   1 "1 finding"                       t "$w/sbom.json" "$w/novex.json" "$w/affected-vex.json"
check "different Go module path does not suppress" 1 "golang-jwt/jwt/v4"        t "$w/sbom.json" "$w/gomod.json" "$w/gomod-vex.json"
check "bad usage is did-not-run"            2 "usage"                           t "$w/sbom.json"

echo "----"
echo "inspector-gate: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
