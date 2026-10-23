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
grype="${GRYPE:-$(command -v grype || true)}"   # PATH or $GRYPE only: no probing of a fixed system location
[ -n "$grype" ] && [ -x "$grype" ] || { echo "::error::grype not found — install it (bin/install-scanner.sh grype) before this test" >&2; exit 1; }
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
# rc-5a I (handoff 0666, ruling R1): the CHECK stage's own path. Real grype scans each image child of an OCI layout (bin/check-scan.sh, the script Check runs), and a
# VEX statement for the cache image must apply there exactly as it does in the cases above. An oci-dir: layout carries no tag and no repo digest, so grype derives no
# image identity from it and applies no statement (probed on the pinned 0.118.0: ref.name, containerd name, with and without --platform); a docker-archive carrying
# RepoTags ghcr.io/fosterstack/cache:cand-<variant>-<arch> does. The layouts here hold one real apk package (busybox 1.37.0-r0 on alpine 3.21), so the three BusyBox
# findings are real database matches.
chk="$work/check-path"; mkdir -p "$chk"
python3 - "$chk" <<'PY'
import gzip, hashlib, io, json, os, sys, tarfile
W = sys.argv[1]
def mk(variant):
    root = os.path.join(W, "images", variant)
    def blob(b):
        h = hashlib.sha256(b).hexdigest(); os.makedirs(root + "/blobs/sha256", exist_ok=True); open(root + "/blobs/sha256/" + h, "wb").write(b); return "sha256:" + h
    tb = io.BytesIO()
    with tarfile.open(fileobj=tb, mode="w") as t:
        def add(n, c):
            i = tarfile.TarInfo(n); i.size = len(c); t.addfile(i, io.BytesIO(c))
        add("etc/alpine-release", b"3.21.0\n"); add("etc/os-release", b'NAME="Alpine Linux"\nID=alpine\nVERSION_ID=3.21.0\n')
        add("lib/apk/db/installed", b"C:Q1xxxxxxxxxxxxxxxxxxxxxxxxxxx=\nP:busybox\nV:1.37.0-r0\nA:x86_64\nS:1\nI:1\nT:x\nU:x\nL:GPL-2.0-only\no:busybox\nm:x\nt:0\nc:0\n\n")
    layer = tb.getvalue(); ldiff = "sha256:" + hashlib.sha256(layer).hexdigest()
    layer_gz = gzip.compress(layer, mtime=0); ld = blob(layer_gz); kids = []   # the layer is a gzip blob, as the images apko writes are; diff_ids stay the uncompressed digest
    for arch in ("amd64", "arm64"):
        cfg = json.dumps({"architecture": arch, "os": "linux", "rootfs": {"type": "layers", "diff_ids": [ldiff]}, "v": variant}).encode(); cd = blob(cfg)
        man = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": cd, "size": len(cfg)},
                          "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": ld, "size": len(layer_gz)}]}, sort_keys=True).encode()
        kids.append({"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": blob(man), "size": len(man), "platform": {"os": "linux", "architecture": arch}})
    idx = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": kids}, sort_keys=True).encode(); ix = blob(idx)
    open(root + "/oci-layout", "w").write('{"imageLayoutVersion":"1.0.0"}')
    json.dump({"schemaVersion": 2, "manifests": [{"mediaType": "application/vnd.oci.image.index.v1+json", "digest": ix, "size": len(idx)}]}, open(root + "/index.json", "w"))
    return ix
d = {"image-production": mk("production"), "image-fips": mk("fips")}
os.makedirs(W + "/dist"); os.makedirs(W + "/.vex"); os.makedirs(W + "/.github/policy"); os.makedirs(W + "/tools/requirements")
for a in ("amd64", "arm64"):
    for n, k in (("fscache", "archive-linux-"), ("fscache-fips", "archive-fips-linux-")):
        f = "%s/dist/%s_0.3.0_linux_%s.tar.gz" % (W, n, a)
        with tarfile.open(f, "w:gz") as t:
            i = tarfile.TarInfo("f.txt"); c = b"x\n"; i.size = len(c); t.addfile(i, io.BytesIO(c))
        d[k + a] = "sha256:" + hashlib.sha256(open(f, "rb").read()).hexdigest()
json.dump(d, open(W + "/digests.json", "w"))
json.dump({"scanners": ["grype"]}, open(W + "/.github/policy/scanners.json", "w"))
for g in ("go.mod", "tools/requirements/go.mod"): open(W + "/" + g, "w").write("module github.com/fosterstack/cache\n\ngo 1.22\n")
st = [{"vulnerability": {"name": c}, "status": "not_affected", "justification": "vulnerable_code_not_in_execute_path",
       "products": [{"@id": "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache"}]} for c in ("CVE-2025-60876", "CVE-2025-46394", "CVE-2024-58251")]
json.dump({"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://example.test/vex", "author": "t", "timestamp": "2026-10-23T00:00:00Z", "version": 1, "statements": st}, open(W + "/.vex/fosterstack-cache.openvex.json", "w"))
PY
ln -s "$here" "$chk/bin"
run_check() {   # run_check VEXFILE: bin/check-scan.sh in the tree with that document as the published VEX
  cp "$1" "$chk/.vex/fosterstack-cache.openvex.json"; rm -rf "$chk/out"
  ( cd "$chk" && PATH="$(dirname "$grype"):$PATH" bash bin/check-scan.sh --scanners .github/policy/scanners.json --digests digests.json --images images --archives dist --out out > run.log 2>&1 ) || true
}
child_is() {   # child_is production amd64 pass|fail -> 0 when the subject's verdict is that and it inventoried 3 packages
  [ "$(jq -r --arg n "$1/linux/$2" '[.scanners[0].subjects[]? | select(.name == $n)][0] | [.verdict, .packages] | @csv' "$chk/out/scan-results.json" 2>/dev/null)" = "\"$3\",3" ]
}
vex_with() {   # vex_with FILE PRODUCT-ID CVE...: a document excepting those CVEs for that product
  python3 - "$@" <<'PYV'
import json, sys
out, pid = sys.argv[1], sys.argv[2]
st = [{"vulnerability": {"name": c}, "status": "not_affected", "justification": "vulnerable_code_not_in_execute_path", "products": [{"@id": pid}]} for c in sys.argv[3:]]
json.dump({"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://example.test/vex", "author": "t", "timestamp": "2026-10-23T00:00:00Z", "version": 1, "statements": st}, open(out, "w"))
PYV
}
CACHE_IMG="pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache"
vex_with "$work/vex-all.json" "$CACHE_IMG" CVE-2025-60876 CVE-2025-46394 CVE-2024-58251
vex_with "$work/vex-none.json" "$CACHE_IMG" CVE-2099-0001
vex_with "$work/vex-qual.json" "$CACHE_IMG&variant=production&arch=amd64" CVE-2025-60876 CVE-2025-46394 CVE-2024-58251
run_check "$work/vex-all.json"
for v in production fips; do for a in amd64 arm64; do
  if child_is $v $a pass; then echo "PASS check path: the $v image's linux/$a child (gzip layer) is scanned by real grype and the cache VEX applies (3 packages, verdict pass)"; pass=$((pass+1))
  else echo "FAIL check path: the $v image's linux/$a child (want pass over 3 packages): $(tail -2 "$chk/run.log" | cut -c1-200 | tr '\n' ' ')"; fail=$((fail+1)); fi
done; done
# the same layouts under a document that excepts none of their findings must FAIL: otherwise the pass above could be a database that no longer matches (the VEX inert)
run_check "$work/vex-none.json"
for v in production fips; do for a in amd64 arm64; do
  if child_is $v $a fail; then echo "PASS check path control: the $v image's linux/$a child fails when the VEX excepts none of its findings"; pass=$((pass+1))
  else echo "FAIL check path control: the $v image's linux/$a child did not fail without a covering statement ($(tail -1 "$chk/run.log" | cut -c1-160))"; fail=$((fail+1)); fi
done; done
# a statement scoped by variant= / arch= is never applied by grype (it derives no such qualifier from an image): fail-closed, in every child, the documented limit (.vex/README.md)
run_check "$work/vex-qual.json"
for v in production fips; do for a in amd64 arm64; do
  if child_is $v $a fail; then echo "PASS check path: a variant/arch-scoped statement is not applied to the $v image's linux/$a child (grype keeps blocking: fail-closed)"; pass=$((pass+1))
  else echo "FAIL check path: a variant/arch-scoped statement changed the $v image's linux/$a child's verdict"; fail=$((fail+1)); fi
done; done
echo "----"
echo "vex-scope: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
