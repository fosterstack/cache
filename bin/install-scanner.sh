#!/usr/bin/env bash
# Install a vulnerability scanner CLI, pinned by VERSION and by a
# repo-pinned SHA256 (audit follow-up: "scanner installers pinned by
# checksum; a scanner that cannot run is red and labeled as a pipeline
# failure, never as a finding"). Downloading install.sh from a moving
# branch (the old approach) both broke - trivy v0.66.0 was not a real
# release - and was unpinned. This verifies the exact bytes.
#
# Usage: install-scanner.sh <trivy|grype|snyk> [dest-dir]
# On any failure (bad arg, unsupported arch, download error, checksum
# mismatch, extract error) it exits non-zero with a ::error:: that names
# it a PIPELINE failure. The caller must treat that as red, never clean.
set -euo pipefail

TOOL="${1:-}"
DEST="${2:-/usr/local/bin}"

# Pinned versions.
TRIVY_VER=0.74.0
GRYPE_VER=0.98.0
SNYK_VER=1.1307.0

pipeline_fail() { echo "::error::scanner installer: $*  (PIPELINE failure - not a scan finding)" >&2; exit 1; }

case "$TOOL" in trivy|grype|snyk) ;; *) pipeline_fail "unknown scanner '${TOOL}' (want trivy|grype|snyk)" ;; esac

arch="${INSTALL_SCANNER_ARCH:-$(uname -m)}"
case "$arch" in
  x86_64|amd64) A_TRIVY=Linux-64bit; A_GRYPE=linux_amd64; A_SNYK=snyk-linux ;;
  aarch64|arm64) A_TRIVY=Linux-ARM64; A_GRYPE=linux_arm64; A_SNYK=snyk-linux-arm64 ;;
  *) pipeline_fail "unsupported architecture: $arch" ;;
esac

# Repo-pinned SHA256s (arch-specific). Update alongside the version pins.
case "${TOOL}:${arch}" in
  trivy:x86_64|trivy:amd64) SUM=2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a ;;
  trivy:aarch64|trivy:arm64) SUM=b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5 ;;
  grype:x86_64|grype:amd64) SUM=2c8769050993a117a20859a7ced8c748f5eb827de31d88c82e1f8c175f6bfe0f ;;
  grype:aarch64|grype:arm64) SUM=e0e274a7d11eb5ec5f4e44b86d9c4faf6cb31ef94f7daaf4b5e150638070f3d7 ;;
  snyk:x86_64|snyk:amd64) SUM=65fc01c378bd71f08cff214f7f8f91be907a27aa18b9649296cd8606adce245e ;;
  *) pipeline_fail "no pinned checksum for ${TOOL} on ${arch}" ;;
esac

TRIVY_BASE="${TRIVY_BASE_URL:-https://github.com/aquasecurity/trivy/releases/download}"
GRYPE_BASE="${GRYPE_BASE_URL:-https://github.com/anchore/grype/releases/download}"
SNYK_BASE="${SNYK_BASE_URL:-https://github.com/snyk/cli/releases/download}"

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
  snyk)
    url="${SNYK_BASE}/v${SNYK_VER}/${A_SNYK}"
    curl -fsSL -o "$tmp/snyk" "$url" || pipeline_fail "download failed: $url"
    verify "$tmp/snyk"
    install -m 0755 "$tmp/snyk" "${DEST}/snyk" || pipeline_fail "install failed for snyk"
    "${DEST}/snyk" version >/dev/null || pipeline_fail "snyk does not run after install"
    ;;
  *)
    pipeline_fail "unknown scanner '${TOOL}' (want trivy|grype|snyk)"
    ;;
esac
echo "installed ${TOOL} (pinned, checksum-verified) to ${DEST}"
