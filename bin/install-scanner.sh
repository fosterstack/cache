#!/usr/bin/env bash
# Install a vulnerability scanner CLI, pinned by VERSION and by a
# repo-pinned SHA256 (audit follow-up: "scanner installers pinned by
# checksum; a scanner that cannot run is red and labeled as a pipeline
# failure, never as a finding"). Downloading install.sh from a moving
# branch (the old approach) both broke - trivy v0.66.0 was not a real
# release - and was unpinned. This verifies the exact bytes.
#
# Usage: install-scanner.sh <trivy|grype|snyk|osv-scanner|inspector-sbomgen|kind> [dest-dir]
# inspector-sbomgen is Amazon Inspector's SBOM generator (the PR gate's
# second scanner sends its SBOM to inspector-scan:ScanSbom). It is pinned
# here rather than downloaded by the vendor action at run time, so its
# bytes are verified like every other scanner's.
# On any failure (bad arg, unsupported arch, download error, checksum
# mismatch, extract error) it exits non-zero with a ::error:: that names
# it a PIPELINE failure. The caller must treat that as red, never clean.
set -euo pipefail

TOOL="${1:-}"
DEST="${2:-/usr/local/bin}"

# Pinned versions.
TRIVY_VER=0.74.0
GRYPE_VER=0.118.0
SYFT_VER=1.52.0
SNYK_VER=1.1307.0
OSV_VER=2.6.0
SBOMGEN_VER=1.16.0
SCOUT_VER=1.26.0
GITSIGN_VER=0.17.1
KIND_VER=0.33.0

pipeline_fail() { echo "::error::scanner installer: $*  (PIPELINE failure - not a scan finding)" >&2; exit 1; }

case "$TOOL" in trivy|grype|syft|snyk|osv-scanner|inspector-sbomgen|docker-scout|docker-scout-1.25.0|docker-scout-1.24.0|gitsign|kind) ;; *) pipeline_fail "unknown scanner '${TOOL}' (want trivy|grype|syft|snyk|osv-scanner|inspector-sbomgen|docker-scout|gitsign|kind)" ;; esac

arch="${INSTALL_SCANNER_ARCH:-$(uname -m)}"
case "$arch" in
  x86_64|amd64) A_TRIVY=Linux-64bit; A_GRYPE=linux_amd64; A_SNYK=snyk-linux; A_OSV=osv-scanner_linux_amd64; A_SBOMGEN=amd64; A_SCOUT=linux_amd64; A_GITSIGN=linux_amd64; A_KIND=kind-linux-amd64 ;;
  aarch64|arm64) A_TRIVY=Linux-ARM64; A_GRYPE=linux_arm64; A_SNYK=snyk-linux-arm64; A_OSV=osv-scanner_linux_arm64; A_SBOMGEN=arm64; A_SCOUT=linux_arm64; A_GITSIGN=linux_arm64; A_KIND=kind-linux-arm64 ;;
  *) pipeline_fail "unsupported architecture: $arch" ;;
esac

# Repo-pinned SHA256s (arch-specific). Update alongside the version pins.
case "${TOOL}:${arch}" in
  trivy:x86_64|trivy:amd64) SUM=2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a ;;
  trivy:aarch64|trivy:arm64) SUM=b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5 ;;
  grype:x86_64|grype:amd64) SUM=1d444c5e7360471815f7158f71935fcecc68a3c417d85c7344f770854300bba2 ;;
  grype:aarch64|grype:arm64) SUM=32aceeb8ee837244775fcb522372c8b3a47914986385f3148f4ee2c930482a84 ;;
  syft:x86_64|syft:amd64) SUM=caeedb81fb0491615f1ebd1761e4145d41ee86dd2cc7bf80669f9f5ad9d6133d ;;
  syft:aarch64|syft:arm64) SUM=c46d5e4c28e12aa4c5becfaa343ef1c7f89045b6b895f2c21d471c62db09c706 ;;
  snyk:x86_64|snyk:amd64) SUM=65fc01c378bd71f08cff214f7f8f91be907a27aa18b9649296cd8606adce245e ;;
  osv-scanner:x86_64|osv-scanner:amd64) SUM=ca69b3d3cd08f889a49dc0a383122f71cc528b83803671df5fd874d97485b108 ;;
  osv-scanner:aarch64|osv-scanner:arm64) SUM=2c71403eb443d05891c4f268c3ad771cf4f16e5443463fd7851ef8f454d3c7e4 ;;
  inspector-sbomgen:x86_64|inspector-sbomgen:amd64) SUM=2aff31bd5f7f426020a5cdda7a58aaebde72e7dae9bc78f687978ad19ef487b4 ;;
  inspector-sbomgen:aarch64|inspector-sbomgen:arm64) SUM=c0ee096fe6e25123b8420bdd09a14d0dbd15333c017825c6cc815ce68e465d0d ;;
  docker-scout:x86_64|docker-scout:amd64) SUM=47daa9ac442816316c65389f516b847146bb9f45e8d6afdcbb9ce835c4e138bd ;;
  docker-scout:aarch64|docker-scout:arm64) SUM=34282a50d6787eec46e44a377a1ed9e70342adf078135cca8617c9199852725c ;;
  # the two previous minors, for the Scout root-cause round only (advisor 0120/0122; amd64 runners)
  docker-scout-1.25.0:x86_64|docker-scout-1.25.0:amd64) SUM=34971682f9d2507f02d4e0e86ae0416bfe53ad40c644819eaeab348a9bae8602 ;;
  docker-scout-1.24.0:x86_64|docker-scout-1.24.0:amd64) SUM=f4e2814bd61040365153d5b964b144cb2dc6ee536a68b5bac4cadf00fc0ec34b ;;
  gitsign:x86_64|gitsign:amd64) SUM=69213a8a0813a151e5a47d0060862952ff833a845d57309dff76f7ba6600abae ;;
  gitsign:aarch64|gitsign:arm64) SUM=477018736a80b36e703dd58db8d6e158a2c1b8b727af0ab8ffdcce9fdf610ada ;;
  # kind v0.33.0 release assets; sha256 from the release's asset digests (api.github.com/repos/kubernetes-sigs/kind/releases/tags/v0.33.0) and the .sha256sum files
  kind:x86_64|kind:amd64) SUM=aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d ;;
  kind:aarch64|kind:arm64) SUM=20022bee6cfcd5086cb7234d218e3454e6090022f2a8f55d1fa7fcf42c3867a2 ;;
  *) pipeline_fail "no pinned checksum for ${TOOL} on ${arch}" ;;
esac

TRIVY_BASE="${TRIVY_BASE_URL:-https://github.com/aquasecurity/trivy/releases/download}"
GRYPE_BASE="${GRYPE_BASE_URL:-https://github.com/anchore/grype/releases/download}"
SYFT_BASE="${SYFT_BASE_URL:-https://github.com/anchore/syft/releases/download}"
SNYK_BASE="${SNYK_BASE_URL:-https://github.com/snyk/cli/releases/download}"
OSV_BASE="${OSV_BASE_URL:-https://github.com/google/osv-scanner/releases/download}"
SBOMGEN_BASE="${SBOMGEN_BASE_URL:-https://amazon-inspector-sbomgen.s3.amazonaws.com}"
SCOUT_BASE="${SCOUT_BASE_URL:-https://github.com/docker/scout-cli/releases/download}"
GITSIGN_BASE="${GITSIGN_BASE_URL:-https://github.com/sigstore/gitsign/releases/download}"
KIND_BASE="${KIND_BASE_URL:-https://github.com/kubernetes-sigs/kind/releases/download}"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

verify() { # file
  local got
  got=$(sha256sum "$1" | cut -d' ' -f1)
  [ "$got" = "$SUM" ] || pipeline_fail "${TOOL} checksum mismatch (got ${got}, pinned ${SUM}) - refusing to run an unverified scanner"
}

case "$TOOL" in
  trivy)
    url="${TRIVY_BASE}/v${TRIVY_VER}/trivy_${TRIVY_VER}_${A_TRIVY}.tar.gz"
    curl -fsSL -o "$tmp/t.tgz" "$url" || pipeline_fail "download failed: $url"
    verify "$tmp/t.tgz"
    tar -xzf "$tmp/t.tgz" -C "$tmp" trivy || pipeline_fail "extract failed for trivy"
    install -m 0755 "$tmp/trivy" "${DEST}/trivy" || pipeline_fail "install failed for trivy"
    "${DEST}/trivy" --version >/dev/null || pipeline_fail "trivy does not run after install"
    ;;
  grype)
    url="${GRYPE_BASE}/v${GRYPE_VER}/grype_${GRYPE_VER}_${A_GRYPE}.tar.gz"
    curl -fsSL -o "$tmp/g.tgz" "$url" || pipeline_fail "download failed: $url"
    verify "$tmp/g.tgz"
    tar -xzf "$tmp/g.tgz" -C "$tmp" grype || pipeline_fail "extract failed for grype"
    install -m 0755 "$tmp/grype" "${DEST}/grype" || pipeline_fail "install failed for grype"
    "${DEST}/grype" version >/dev/null || pipeline_fail "grype does not run after install"
    ;;
  syft)
    # grype's cataloguer for the auditor, a pinned release binary (Sep 30: building it from source at run time failed
    # on transient sum.golang.org errors, grype then inventoried nothing and the audit stopped short of quorum)
    url="${SYFT_BASE}/v${SYFT_VER}/syft_${SYFT_VER}_${A_GRYPE}.tar.gz"
    curl -fsSL -o "$tmp/s.tgz" "$url" || pipeline_fail "download failed: $url"
    verify "$tmp/s.tgz"
    tar -xzf "$tmp/s.tgz" -C "$tmp" syft || pipeline_fail "extract failed for syft"
    install -m 0755 "$tmp/syft" "${DEST}/syft" || pipeline_fail "install failed for syft"
    "${DEST}/syft" version >/dev/null || pipeline_fail "syft does not run after install"
    ;;
  snyk)
    url="${SNYK_BASE}/v${SNYK_VER}/${A_SNYK}"
    curl -fsSL -o "$tmp/snyk" "$url" || pipeline_fail "download failed: $url"
    verify "$tmp/snyk"
    install -m 0755 "$tmp/snyk" "${DEST}/snyk" || pipeline_fail "install failed for snyk"
    "${DEST}/snyk" version >/dev/null || pipeline_fail "snyk does not run after install"
    ;;
  osv-scanner)
    url="${OSV_BASE}/v${OSV_VER}/${A_OSV}"
    curl -fsSL -o "$tmp/osv-scanner" "$url" || pipeline_fail "download failed: $url"
    verify "$tmp/osv-scanner"
    install -m 0755 "$tmp/osv-scanner" "${DEST}/osv-scanner" || pipeline_fail "install failed for osv-scanner"
    "${DEST}/osv-scanner" --version >/dev/null || pipeline_fail "osv-scanner does not run after install"
    ;;
  inspector-sbomgen)
    url="${SBOMGEN_BASE}/${SBOMGEN_VER}/linux/${A_SBOMGEN}/inspector-sbomgen.zip"
    curl -fsSL -o "$tmp/s.zip" "$url" || pipeline_fail "download failed: $url"
    verify "$tmp/s.zip"
    unzip -q -j "$tmp/s.zip" "inspector-sbomgen-${SBOMGEN_VER}/linux/${A_SBOMGEN}/inspector-sbomgen" -d "$tmp" || pipeline_fail "extract failed for inspector-sbomgen"
    install -m 0755 "$tmp/inspector-sbomgen" "${DEST}/inspector-sbomgen" || pipeline_fail "install failed for inspector-sbomgen"
    "${DEST}/inspector-sbomgen" --version >/dev/null || pipeline_fail "inspector-sbomgen does not run after install"
    ;;
  docker-scout|docker-scout-1.25.0|docker-scout-1.24.0)
    [ "$TOOL" = docker-scout ] || SCOUT_VER="${TOOL#docker-scout-}"
    # a Docker CLI plugin: installed as DEST/docker-scout; the caller links it into ~/.docker/cli-plugins
    url="${SCOUT_BASE}/v${SCOUT_VER}/docker-scout_${SCOUT_VER}_${A_SCOUT}.tar.gz"
    curl -fsSL -o "$tmp/d.tgz" "$url" || pipeline_fail "download failed: $url"
    verify "$tmp/d.tgz"
    tar -xzf "$tmp/d.tgz" -C "$tmp" docker-scout || pipeline_fail "extract failed for docker-scout"
    install -m 0755 "$tmp/docker-scout" "${DEST}/docker-scout" || pipeline_fail "install failed for docker-scout"
    "${DEST}/docker-scout" docker-cli-plugin-metadata >/dev/null || pipeline_fail "docker-scout does not run after install"
    ;;
  gitsign)
    # keyless git signing with the workflow's OIDC identity (automatic patch releases; owner, Oct 2): a single binary
    url="${GITSIGN_BASE}/v${GITSIGN_VER}/gitsign_${GITSIGN_VER}_${A_GITSIGN}"
    curl -fsSL -o "$tmp/gitsign" "$url" || pipeline_fail "download failed: $url"
    verify "$tmp/gitsign"
    install -m 0755 "$tmp/gitsign" "${DEST}/gitsign" || pipeline_fail "install failed for gitsign"
    "${DEST}/gitsign" --version >/dev/null || pipeline_fail "gitsign does not run after install"
    ;;
  kind)
    # the Kubernetes-in-Docker CLI for the persona UAT (on-call persona): a single binary; the driver finds it on PATH
    url="${KIND_BASE}/v${KIND_VER}/${A_KIND}"
    curl -fsSL -o "$tmp/kind" "$url" || pipeline_fail "download failed: $url"
    verify "$tmp/kind"
    install -m 0755 "$tmp/kind" "${DEST}/kind" || pipeline_fail "install failed for kind"
    "${DEST}/kind" version >/dev/null || pipeline_fail "kind does not run after install"
    ;;
  *)
    pipeline_fail "unknown scanner '${TOOL}' (want trivy|grype|syft|snyk|osv-scanner|inspector-sbomgen|docker-scout|gitsign|kind)"
    ;;
esac
echo "installed ${TOOL} (pinned, checksum-verified) to ${DEST}"
