#!/usr/bin/env bash
# REQ-REL-004-AC1 (ratified Sep 29, row 73): "A test proves that a VEX-covered
# finding is suppressed for both scanners and an uncovered one blocks."
# One finding — BusyBox CVE-2025-60876 in FosterStack's image — is put through
# BOTH gate paths against the committed .vex document:
#   Grype     : bin/grype-scan.sh over a synthetic SBOM (Grype applies VEX natively)
#   Inspector : bin/inspector-gate.py over a CycloneDX SBOM + a ScanSbom-shaped
#               response (the gate applies VEX itself; nothing in AWS)
# busybox 1.37.0 is covered (suppressed, exit 0); 1.36.0 is not (blocks); a
# zero-package inventory fails both. Needs the pinned grype (hygiene installs it).
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; repo="$(cd "$here/.." && pwd)"
vex="$repo/.vex/fosterstack-cache.openvex.json"
base="$repo/test-evidence/vex-scope/busybox-image.sbom.json"
grype="${GRYPE:-$(command -v grype || echo /usr/local/bin/grype)}"
[ -x "$grype" ] || { echo "::error::grype not found — install it (bin/install-scanner.sh grype) before this test" >&2; exit 1; }
"$grype" db update >/dev/null 2>&1 || true
w="$(mktemp -d)"; trap 'rm -rf "$w"' EXIT
pass=0; fail=0
CVE=CVE-2025-60876

ok()  { echo "ok: $1"; pass=$((pass+1)); }
bad() { echo "FAIL: $1"; [ -n "${2:-}" ] && echo "$2" | sed 's/^/    /'; fail=$((fail+1)); }

grype_sbom() { # version out [empty]
  python3 - "$base" "$2" "$1" "${3:-}" <<'PY'
import json,sys
base,out,ver,empty=sys.argv[1:5]
d=json.load(open(base)); m=d['source']['metadata']
d['source']['name']='ghcr.io/fosterstack/cache'
m['userInput']=m['tags'][0]='ghcr.io/fosterstack/cache:cand-debug-amd64'; m['repoDigests']=[]
a=d['artifacts'][0]; a['version']=ver; a['purl']='pkg:generic/busybox@'+ver
a['cpes'][0]['cpe']='cpe:2.3:a:busybox:busybox:%s:*:*:*:*:*:*:*'%ver
if empty: d['artifacts']=[]; d['artifactRelationships']=[]
json.dump(d,open(out,'w'))
PY
}
insp_inputs() { # version prefix [empty]
  local comps='[{"bom-ref":"b1","type":"application","name":"busybox","version":"'"$1"'","purl":"pkg:generic/busybox@'"$1"'"}]'
  [ -n "${3:-}" ] && comps='[]'
  printf '{"bomFormat":"CycloneDX","specVersion":"1.5","components":%s}' "$comps" > "$w/$2.sbom.json"
  printf '{"sbom":{"bomFormat":"CycloneDX","specVersion":"1.5","components":%s,"vulnerabilities":[{"id":"%s","ratings":[{"severity":"medium"}],"affects":[{"ref":"b1"}]}]}}' \
    "$comps" "$CVE" > "$w/$2.resp.json"
}

for case in "1.37.0 covered 0" "1.36.0 uncovered 1"; do
  set -- $case; ver=$1; what=$2; want=$3
  grype_sbom "$ver" "$w/g-$ver.json"
  out="$(GRYPE="$grype" bash "$here/grype-scan.sh" "sbom:$w/g-$ver.json" "busybox-$ver" 2>&1)"; rc=$?
  if [ "$want" = 0 ]; then
    [ "$rc" -eq 0 ] && grep -q "busybox-$ver: [1-9][0-9]* packages, 0 finding" <<<"$out" \
      && ok "grype: VEX-${what} $CVE (busybox $ver) suppressed, exit 0" || bad "grype: VEX-${what} busybox $ver (rc $rc)" "$out"
  else
    [ "$rc" -ne 0 ] && grep -q "$CVE" <<<"$out" \
      && ok "grype: ${what} $CVE (busybox $ver) blocks, exit $rc" || bad "grype: ${what} busybox $ver (rc $rc)" "$out"
  fi
  insp_inputs "$ver" "i-$ver"
  out="$(python3 "$here/inspector-gate.py" "busybox-$ver" "$w/i-$ver.sbom.json" "$w/i-$ver.resp.json" "$vex" 2>&1)"; rc=$?
  if [ "$want" = 0 ]; then
    [ "$rc" -eq 0 ] && grep -q "0 finding(s), 1 covered by the published VEX" <<<"$out" && grep -q "vex: $CVE busybox@$ver" <<<"$out" \
      && ok "inspector: VEX-${what} $CVE (busybox $ver) suppressed, exit 0" || bad "inspector: VEX-${what} busybox $ver (rc $rc)" "$out"
  else
    [ "$rc" -eq 1 ] && grep -q "::error::inspector busybox-$ver: $CVE busybox@$ver" <<<"$out" \
      && ok "inspector: ${what} $CVE (busybox $ver) blocks, exit 1" || bad "inspector: ${what} busybox $ver (rc $rc)" "$out"
  fi
done

grype_sbom 1.37.0 "$w/g-empty.json" empty
out="$(GRYPE="$grype" bash "$here/grype-scan.sh" "sbom:$w/g-empty.json" empty 2>&1)"; rc=$?
[ "$rc" -eq 2 ] && grep -q "0 packages.*did not run" <<<"$out" && ok "grype: zero packages fails (exit 2)" || bad "grype: zero packages (rc $rc)" "$out"
# grype that cannot catalog at all (no output written) is also 0 packages, exit 2 (round-4 blocker).
out="$(GRYPE="$grype" bash "$here/grype-scan.sh" "sbom:$w/does-not-exist.json" crashed 2>&1)"; rc=$?
[ "$rc" -eq 2 ] && grep -q "crashed: 0 packages" <<<"$out" && grep -q "0 packages in crashed.*did not run" <<<"$out" \
  && ok "grype: a catalog failure is 0 packages, exit 2" || bad "grype: catalog failure (rc $rc)" "$out"
insp_inputs 1.37.0 i-empty empty
out="$(python3 "$here/inspector-gate.py" empty "$w/i-empty.sbom.json" "$w/i-empty.resp.json" "$vex" 2>&1)"; rc=$?
[ "$rc" -eq 2 ] && grep -q "0 packages.*did not run" <<<"$out" && ok "inspector: zero packages fails (exit 2)" || bad "inspector: zero packages (rc $rc)" "$out"

echo "----"
echo "vex-both-scanners: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
