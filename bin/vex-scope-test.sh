#!/usr/bin/env bash
# VEX product-SCOPE regression (audit R01). The busybox not_affected statements
# must suppress ONLY FosterStack's cache image — matched by registry+repository
# (candidate/published and the cache-candidates repo) — and MUST NOT suppress
# another vendor's image (even one whose bare basename is "cache"), a different
# busybox version, or an image with no usable identity (no context-free
# package fallback). Runs the pinned Grype over synthetic SBOMs against the
# committed .vex and asserts suppress/flag per case.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; repo="$(cd "$here/.." && pwd)"
vex="$repo/.vex/fosterstack-cache.openvex.json"
base="$repo/test-evidence/vex-scope/busybox-image.sbom.json"
grype="${GRYPE:-$(command -v grype || echo /usr/local/bin/grype)}"
[ -x "$grype" ] || { echo "::error::grype not found — install it (bin/install-scanner.sh grype) before this test" >&2; exit 1; }
"$grype" db update >/dev/null 2>&1 || true
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
pass=0; fail=0
# The three BusyBox CVEs the statements adjudicate.
BUSYBOX_CVES="CVE-2025-60876 CVE-2025-46394 CVE-2024-58251"
check() { # label name tag digest ver want [assert_cves=yes]
  local label="$1" name="$2" tag="$3" digest="$4" ver="$5" want="$6" assert_cves="${7:-yes}"
  local sbom="$work/sbom.json" js f ig got rc rc_ok=1 cve_ok=1
  python3 - "$base" "$sbom" "$name" "$tag" "$digest" "$ver" <<'PY'
import json,sys
base,out,name,tag,digest,ver=sys.argv[1:7]
d=json.load(open(base)); m=d['source']['metadata']
d['source']['name']=name
m['userInput']=tag or name
m['tags']=[tag] if tag else []
m['repoDigests']=[digest] if digest else []
a=d['artifacts'][0]; a['version']=ver; a['purl']='pkg:generic/busybox@'+ver
a['cpes'][0]['cpe']='cpe:2.3:a:busybox:busybox:%s:*:*:*:*:*:*:*'%ver
json.dump(d,open(out,'w'))
PY
  js="$("$grype" "sbom:$sbom" -o json --fail-on negligible --vex "$vex" 2>/dev/null)"; rc=$?
  f=$(jq '.matches|length' <<<"$js" 2>/dev/null || echo -1)
  ig=$(jq '.ignoredMatches|length' <<<"$js" 2>/dev/null || echo -1)
  if [ "$ig" -gt 0 ] && [ "$f" -eq 0 ]; then got=SUPPRESS; else got=FLAG; fi
  # Exit-status cross-check: grype --fail-on exits non-zero (2) when matches
  # remain, 0 when none — a generic count is not enough (audit R01 hardening).
  if [ "$got" = SUPPRESS ] && [ "$rc" -ne 0 ]; then rc_ok=0; fi
  if [ "$got" = FLAG ]     && [ "$rc" -eq 0 ]; then rc_ok=0; fi
  # For the busybox@1.37.0 cases, assert the EXACT three CVEs land in the right
  # bucket, so malformed output or an unrelated finding cannot pass as a match.
  if [ "$assert_cves" = yes ]; then
    local c
    for c in $BUSYBOX_CVES; do
      if [ "$got" = SUPPRESS ]; then
        jq -e --arg c "$c" 'any(.ignoredMatches[]?; .vulnerability.id==$c)' <<<"$js" >/dev/null 2>&1 || cve_ok=0
        jq -e --arg c "$c" 'any(.matches[]?; .vulnerability.id==$c)' <<<"$js" >/dev/null 2>&1 && cve_ok=0
      else
        jq -e --arg c "$c" 'any(.matches[]?; .vulnerability.id==$c)' <<<"$js" >/dev/null 2>&1 || cve_ok=0
      fi
    done
  fi
  if [ "$got" = "$want" ] && [ "$rc_ok" = 1 ] && [ "$cve_ok" = 1 ]; then
    echo "ok: ${label} (${got}, exit ${rc})"; pass=$((pass+1))
  else
    echo "FAIL: ${label} got=${got} want=${want} (find=${f} ign=${ig} exit=${rc} rc_ok=${rc_ok} cve_ok=${cve_ok})"; fail=$((fail+1))
  fi
}
D64="$(printf 'a%.0s' {1..64})"
check "fosterstack candidate (tags-only, no repo-digest)" ghcr.io/fosterstack/cache            ghcr.io/fosterstack/cache:cand-debug-amd64           ""                                              1.37.0 SUPPRESS
check "fosterstack published (tag + repo-digest)"         ghcr.io/fosterstack/cache            ghcr.io/fosterstack/cache:v0.2.1                     "ghcr.io/fosterstack/cache@sha256:${D64}"       1.37.0 SUPPRESS
check "fosterstack release-candidate repository"          ghcr.io/fosterstack/cache-candidates ghcr.io/fosterstack/cache-candidates:snapshot        ""                                              1.37.0 SUPPRESS
check "foreign vendor, different product"                 ghcr.io/another-vendor/downloader    ghcr.io/another-vendor/downloader:1.0                ""                                              1.37.0 FLAG
check "foreign vendor, SAME basename (cache)"             ghcr.io/another-vendor/cache         ghcr.io/another-vendor/cache:1.0                     ""                                              1.37.0 FLAG
check "changed component version (busybox 1.36.0)"        ghcr.io/fosterstack/cache            ghcr.io/fosterstack/cache:v0.2.1                     ""                                              1.36.0 FLAG no
check "missing image identity (no tags, no digests)"      ghcr.io/fosterstack/cache            ""                                                   ""                                              1.37.0 FLAG
echo "----"
echo "vex-scope: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
