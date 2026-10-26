#!/usr/bin/env bash
# Install a vulnerability scanner CLI, pinned by VERSION and by a
# repo-pinned SHA256 (audit follow-up: "scanner installers pinned by
# checksum; a scanner that cannot run is red and labeled as a pipeline
# failure, never as a finding"). Downloading the vendors' installer from a moving
# branch (the old approach) both broke - trivy v0.66.0 was not a real
# release - and was unpinned. This verifies the exact bytes.
#
# Usage: install-scanner.sh <trivy|grype|syft|snyk|osv-scanner|inspector-sbomgen|docker-scout|gitsign|cosign|witness|go|crane|govulncheck> [dest-dir]
# `go` installs the Go toolchain of the working directory's go.mod (its `toolchain` line, else its `go` line) into <dest-dir>/fscache-go, only when that
# version is the pinned one (GO_VER); admission's freeze check runs it from there (the runner's own Go may be older than go.mod).
# `govulncheck` (the Go source scan of Check, ruling G of Oct 12) is a Go MODULE, not release archives (golang/vuln publishes none): it is built from the committed module
# tools/govulncheck, whose go.sum h1 hashes are the pin, with the pinned toolchain `go` installed (<dest-dir>/fscache-go/bin/go), and installed as <dest-dir>/govulncheck.
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
# cosign signs the release provenance in stage-sign.yml (v0.3.0 rule 52): v3.1.3 linux binaries; the sums below were checked on Oct 9 2026
# with `cosign verify-blob --bundle` against the release's own signatures (identity keyless@projectsigstore.iam.gserviceaccount.com)
COSIGN_VER=3.1.3
# Witness signs every Build and Rebuild step (v0.3.0 rule 68, the Witness wrapper). The two sums are the sha256 of the release tarballs of in-toto/witness
# v0.12.0, equal to the release's witness_0.12.0_checksums.txt; both tarballs were also checked on Oct 9 2026 with `cosign verify-blob --bundle` against
# their .sigstore.json (identity https://github.com/in-toto/witness/.github/workflows/release.yml@refs/tags/v0.12.0, issuer token.actions.githubusercontent.com).
WITNESS_VER=0.12.0
# The Go toolchain admission's verify-freeze needs (Codex A r3 F4; advisor): the exact go<ver>.linux-<arch>.tar.gz, pinned by sha256 per architecture, values
# equal to go.dev's published checksums (https://go.dev/dl/?mode=json), checked Oct 21 2026 for go1.27.3 (main's Go bump, cache#464). GO_VER must equal the version go.mod names.
GO_VER=1.27.3
# crane copies the exact image bytes by digest in the Release stage (rules 16 and 64 of the release rules: the copy tool is pinned by checksum, no build step) and reads the digest of the
# latest release's image in the weekly persona job (rule 61: no image builder). The two sums are the sha256 of the Linux release tarballs of google/go-containerregistry v0.22.1, equal to the
# release's checksums.txt and to the downloaded files (Oct 11 2026). The version is written only in the two literal release URLs of the crane arm below (no version variable): the pin-age scan measures those URLs.

pipeline_fail() { echo "::error::scanner installer: $*  (PIPELINE failure - not a scan finding)" >&2; exit 1; }
die() { pipeline_fail "$@"; }   # the plain-text failure word of the pinned Go fetch line (pin-age honours that line shape, REQ-SUP-001-AC23)

case "$TOOL" in trivy|grype|syft|snyk|osv-scanner|inspector-sbomgen|docker-scout|docker-scout-1.25.0|docker-scout-1.24.0|docker-scout-1.0.9|docker-scout-1.2.2|docker-scout-1.3.0|docker-scout-1.4.1|docker-scout-1.5.2|docker-scout-1.6.4|docker-scout-1.7.0|docker-scout-1.8.0|docker-scout-1.9.3|docker-scout-1.10.0|docker-scout-1.11.0|docker-scout-1.12.0|docker-scout-1.14.0|docker-scout-1.15.1|docker-scout-1.16.3|docker-scout-1.17.1|docker-scout-1.18.4|docker-scout-1.19.0|docker-scout-1.20.4|docker-scout-1.21.0|docker-scout-1.22.0|docker-scout-1.23.1|gitsign|cosign|witness|go|crane|govulncheck) ;; *) pipeline_fail "unknown scanner '${TOOL}' (want trivy|grype|syft|snyk|osv-scanner|inspector-sbomgen|docker-scout|gitsign|cosign|witness|go|crane|govulncheck)" ;; esac

arch="${INSTALL_SCANNER_ARCH:-$(uname -m)}"
case "$arch" in
  x86_64|amd64) A_TRIVY=Linux-64bit; A_GRYPE=linux_amd64; A_SNYK=snyk-linux; A_OSV=osv-scanner_linux_amd64; A_SBOMGEN=amd64; A_SCOUT=linux_amd64; A_GITSIGN=linux_amd64; A_GO=linux-amd64 ;;
  aarch64|arm64) A_TRIVY=Linux-ARM64; A_GRYPE=linux_arm64; A_SNYK=snyk-linux-arm64; A_OSV=osv-scanner_linux_arm64; A_SBOMGEN=arm64; A_SCOUT=linux_arm64; A_GITSIGN=linux_arm64; A_GO=linux-arm64 ;;
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
  # every older Scout minor (its newest patch), amd64 only, for the Scout older-versions sweep (advisor 0520; sha256 from each release's checksums.txt)
  docker-scout-1.0.9:x86_64|docker-scout-1.0.9:amd64) SUM=25c1c8d6fa3f498d488a015c86cf79353358aa85ecff17d1baa009c3c2e70763 ;;
  docker-scout-1.2.2:x86_64|docker-scout-1.2.2:amd64) SUM=6b685afc55202138b1bc18ff83a8c8072cedd9958f0a3aaec2f418ca77aaf3b5 ;;
  docker-scout-1.3.0:x86_64|docker-scout-1.3.0:amd64) SUM=68722f85b29f610b5d38ce2182209dd36a92749b187054400017f6f62b61a2de ;;
  docker-scout-1.4.1:x86_64|docker-scout-1.4.1:amd64) SUM=e4beb047697f88cefda50c5f937083a7aaf1e235a81482cca51abecdf05bb565 ;;
  docker-scout-1.5.2:x86_64|docker-scout-1.5.2:amd64) SUM=dde5ac2819cd6c5068540da2e450b4c36fc6e46a5ed10ff36a5efe09707f2b81 ;;
  docker-scout-1.6.4:x86_64|docker-scout-1.6.4:amd64) SUM=cf7b04b459e0db38d5d88176d55d52818d14a14409183b9ae77e100229f9835b ;;
  docker-scout-1.7.0:x86_64|docker-scout-1.7.0:amd64) SUM=ec38faa6f5f63acf05d09595261f98c127cfee31896f5946eb0121c632d0a3a8 ;;
  docker-scout-1.8.0:x86_64|docker-scout-1.8.0:amd64) SUM=f6448c94b6549431525baefb6d8e856a98a9d910bbf080d14c5cd99ba1d9688a ;;
  docker-scout-1.9.3:x86_64|docker-scout-1.9.3:amd64) SUM=24016d5d80d2c9347d2fcaaf7194e299139283ea24d52371a3ce827ff65746b7 ;;
  docker-scout-1.10.0:x86_64|docker-scout-1.10.0:amd64) SUM=d8ef1e723d12d51255ee52edca8d29181aaeaf59c6f94f13fc703e1bebeb6917 ;;
  docker-scout-1.11.0:x86_64|docker-scout-1.11.0:amd64) SUM=892b1fd5d7259625750aaaa8497f1a146386d8c6a3a67ed4984263cd873dbadc ;;
  docker-scout-1.12.0:x86_64|docker-scout-1.12.0:amd64) SUM=12ee997a8f969979c6eb3d6ecc9703d5233a75298e163f89b2a2f35a454f78e0 ;;
  docker-scout-1.14.0:x86_64|docker-scout-1.14.0:amd64) SUM=f3e79ed43b50155c74d484a50d7a5d62b2a41720392aa141fae755356c5527fc ;;
  docker-scout-1.15.1:x86_64|docker-scout-1.15.1:amd64) SUM=83860e9753eab0ec6f4da0d5a2aae97ec63653b3ec6b9d926d46df5651767ddb ;;
  docker-scout-1.16.3:x86_64|docker-scout-1.16.3:amd64) SUM=bb9ec1bd9049d07a8e57558ee7ace161d77ea93e2c2b2f45dfb056a419f8c428 ;;
  docker-scout-1.17.1:x86_64|docker-scout-1.17.1:amd64) SUM=e59016cde629ab8832763a29d0136a663ed08c7e1753f47cc04ba0d61b945811 ;;
  docker-scout-1.18.4:x86_64|docker-scout-1.18.4:amd64) SUM=eb081bc7584f9b7b9d5f6b7e7147de850f3bfa8706076f4dc10776ead497086c ;;
  docker-scout-1.19.0:x86_64|docker-scout-1.19.0:amd64) SUM=14bbc42086e0ebdc125b98fd33ed0d3252146811031d380d9b403175108d1497 ;;
  docker-scout-1.20.4:x86_64|docker-scout-1.20.4:amd64) SUM=92e20757cf18f4698aec56d32e15cb4435e9dcbfcb1b09708cd97674c70f845e ;;
  docker-scout-1.21.0:x86_64|docker-scout-1.21.0:amd64) SUM=07b075d532efd3ca04893a0a1845cb57df3b367e2c4b4717658e2425caa8e1f8 ;;
  docker-scout-1.22.0:x86_64|docker-scout-1.22.0:amd64) SUM=a3c6c38741153a8477be61eccc9d48490745496bddbd0c5e0fc301c334fdd734 ;;
  docker-scout-1.23.1:x86_64|docker-scout-1.23.1:amd64) SUM=0f778f9d833f28bc6cccff95e33039849c0afcecafa38d9f46fe74bfd0915714 ;;
  gitsign:x86_64|gitsign:amd64) SUM=69213a8a0813a151e5a47d0060862952ff833a845d57309dff76f7ba6600abae ;;
  gitsign:aarch64|gitsign:arm64) SUM=477018736a80b36e703dd58db8d6e158a2c1b8b727af0ab8ffdcce9fdf610ada ;;
  cosign:x86_64|cosign:amd64) SUM=4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71 ;;
  cosign:aarch64|cosign:arm64) SUM=c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a ;;
  witness:x86_64|witness:amd64) SUM=543d05898731fe5b9c176443ec596a0242bd27f0b327d73aff60f6f7398b7dd0 ;;
  witness:aarch64|witness:arm64) SUM=3043bba438276c4c2b1afff7deb97cf1c0301c77515a4b1cff15549b378d2aaf ;;
  crane:x86_64|crane:amd64) SUM=0ab7a1d6932a213aed964ce97666c3077fe691c8606413674a8b3e0b9ec4cda0 ;;
  crane:aarch64|crane:arm64) SUM=898c0cff975f898a33e8c4580bdafb0e7c02c7faa33374e946762f97c4ab7110 ;;
  go:x86_64|go:amd64) SUM=65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40 ;;
  go:aarch64|go:arm64) SUM=a06e99309dbcbdca1a8ccd2282c3ee146e55930886e26b4f1193269587165f49 ;;
  govulncheck:*) SUM="" ;;   # a module: pinned by go.sum (tools/govulncheck), not by the sum of a download
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

tmp=$(mktemp -d)
trap 'chmod -R u+w "$tmp" 2>/dev/null; rm -rf "$tmp"' EXIT   # a Go module cache is read-only: it is writable again before it is removed

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
  docker-scout|docker-scout-1.25.0|docker-scout-1.24.0|docker-scout-1.0.9|docker-scout-1.2.2|docker-scout-1.3.0|docker-scout-1.4.1|docker-scout-1.5.2|docker-scout-1.6.4|docker-scout-1.7.0|docker-scout-1.8.0|docker-scout-1.9.3|docker-scout-1.10.0|docker-scout-1.11.0|docker-scout-1.12.0|docker-scout-1.14.0|docker-scout-1.15.1|docker-scout-1.16.3|docker-scout-1.17.1|docker-scout-1.18.4|docker-scout-1.19.0|docker-scout-1.20.4|docker-scout-1.21.0|docker-scout-1.22.0|docker-scout-1.23.1)
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
  cosign)
    # the release URL below names the pinned version literally (pin-age dates a download from its URL); the install tests fail when COSIGN_VER and that URL disagree
    # the release provenance signer (v0.3.0 rule 52): a single binary; cosign asks for the OIDC token inside its own process
    case "$arch" in
      x86_64|amd64) curl -fsSL -o "$tmp/cosign" "https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-linux-amd64" || pipeline_fail "download failed: cosign v${COSIGN_VER}" ;;
      *) curl -fsSL -o "$tmp/cosign" "https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-linux-arm64" || pipeline_fail "download failed: cosign v${COSIGN_VER}" ;;
    esac
    verify "$tmp/cosign"
    install -m 0755 "$tmp/cosign" "${DEST}/cosign" || pipeline_fail "install failed for cosign"
    "${DEST}/cosign" version >/dev/null || pipeline_fail "cosign does not run after install"
    ;;
  witness)
    # the release URL below names the pinned version literally (pin-age dates a download from its URL); the install tests fail when WITNESS_VER and that URL disagree
    # the step signer of the release chain (rule 68): a release tarball holding the witness binary
    case "$arch" in
      x86_64|amd64) curl -fsSL -o "$tmp/w.tgz" "https://github.com/in-toto/witness/releases/download/v0.12.0/witness_0.12.0_linux_amd64.tar.gz" || pipeline_fail "download failed: witness v${WITNESS_VER}" ;;
      *) curl -fsSL -o "$tmp/w.tgz" "https://github.com/in-toto/witness/releases/download/v0.12.0/witness_0.12.0_linux_arm64.tar.gz" || pipeline_fail "download failed: witness v${WITNESS_VER}" ;;
    esac
    verify "$tmp/w.tgz"
    tar -xzf "$tmp/w.tgz" -C "$tmp" witness || pipeline_fail "extract failed for witness"
    install -m 0755 "$tmp/witness" "${DEST}/witness" || pipeline_fail "install failed for witness"
    "${DEST}/witness" version >/dev/null || pipeline_fail "the installed witness binary does not start"
    ;;
  go)
    # the toolchain go.mod names: its `toolchain` line wins; a file without one is read by its `go` line; it must be the pinned version
    [ -f go.mod ] || pipeline_fail "no go.mod in the working directory: cannot tell which Go toolchain to install"
    want=""; gline=""
    while read -r key val _; do
      case "$key" in
        toolchain) case "$val" in go[0-9]*) want="${val#go}" ;; esac ;;
        go) [ -n "$gline" ] || gline="$val" ;;
      esac
    done < go.mod
    [ -n "$want" ] || want="$gline"
    [ "$want" = "$GO_VER" ] || pipeline_fail "go.mod names go '${want}' but the pinned toolchain is ${GO_VER} (go.mod and GO_VER in bin/install-scanner.sh must agree)"
    gofile="go${GO_VER}.${A_GO}.tar.gz"
    curl -q -fsSL -g -o "$tmp/go.tgz" "https://go.dev/dl/${gofile}" || die "download failed: go toolchain"
    verify "$tmp/go.tgz"
    mkdir -p "$tmp/x" && tar -xzf "$tmp/go.tgz" -C "$tmp/x" || pipeline_fail "extract failed for go"
    gobin="$tmp/x/go/bin"; [ -x "${gobin}/go" ] || pipeline_fail "the toolchain archive holds no go program"
    rm -rf "${DEST}/fscache-go" && mkdir -p "${DEST}" && mv "$tmp/x/go" "${DEST}/fscache-go" || pipeline_fail "install failed for go"
    "${DEST}/fscache-go/bin/go" version | grep -q "go${GO_VER} " || pipeline_fail "the installed go is not go${GO_VER}"
    ;;
  govulncheck)
    # built with the pinned toolchain of `install-scanner.sh go`, in a clean environment: read-only modules (go.sum is the pin), a local toolchain, no cgo, no
    # workspace, fresh caches, the one module proxy named below and nothing Go-related from the caller; the checksum database stays on
    gobin="${DEST}/fscache-go/bin/go"
    [ -x "$gobin" ] || pipeline_fail "no pinned Go toolchain at ${DEST}/fscache-go (run install-scanner.sh go first): govulncheck is built with it"
    "${DEST}/fscache-go/bin/go" version | grep -q "go${GO_VER} " || pipeline_fail "the Go toolchain at ${DEST}/fscache-go is not go${GO_VER}"
    [ -f tools/govulncheck/go.mod ] || pipeline_fail "tools/govulncheck/go.mod is missing: it holds the govulncheck pin"
    [ -s tools/govulncheck/go.sum ] || pipeline_fail "tools/govulncheck/go.sum is missing: its h1 hashes are the govulncheck pin"
    [ ! -e tools/govulncheck/vendor ] || pipeline_fail "tools/govulncheck/vendor exists: vendor mode does not check contents against go.sum, so the build refuses it (go.sum's h1 hashes are the pin)"
    pin=""
    while read -r key val rest; do
      [ "$key" != require ] || { key=$val; val=${rest%% *}; }
      [ "$key" != golang.org/x/vuln ] || { pin=$val; break; }
    done < tools/govulncheck/go.mod
    [[ "$pin" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || pipeline_fail "tools/govulncheck/go.mod does not require golang.org/x/vuln at a version"
    mkdir -p "$tmp/home" "$tmp/gocache" "$tmp/gomod"
    # nothing Go-related from the caller's environment reaches the build: those names are unset, the pinned ones exported, in a subshell; GOFLAGS is among the unset names and none is defined: tools/govulncheck has no vendor/ directory, so Go's own default (read-only modules) applies
    ( unset GOFLAGS GOROOT GOPATH GOPRIVATE GONOPROXY GONOSUMDB GONOSUMCHECK GOSUMDB GOINSECURE GOVCS GOEXPERIMENT GODEBUG GOCACHEPROG GOAUTH GOTOOLDIR GOBIN GOTMPDIR GOMODCACHEPROG GOOS GOARCH GOAMD64 GOARM GO386 GOMIPS GOPPC64 GORISCV64 GOWASM CC CXX CGO_CFLAGS CGO_CPPFLAGS CGO_CXXFLAGS CGO_LDFLAGS
      export HOME="$tmp/home" TMPDIR="$tmp" GOCACHE="$tmp/gocache" GOMODCACHE="$tmp/gomod" GOTOOLCHAIN=local GOPROXY=https://proxy.golang.org CGO_ENABLED=0 GOWORK=off GOENV=off
      cd tools/govulncheck && "${DEST}/fscache-go/bin/go" build -trimpath -o "$tmp/govulncheck" golang.org/x/vuln/cmd/govulncheck ) || pipeline_fail "go build of govulncheck ${pin} failed"
    "$tmp/govulncheck" -version 2>/dev/null | grep -qx "Scanner: govulncheck@${pin}" || pipeline_fail "the built govulncheck does not report version ${pin} (the module's pin)"
    install -m 0755 "$tmp/govulncheck" "${DEST}/govulncheck" || pipeline_fail "install failed for govulncheck"
    ;;
  crane)
    # the digest reader of the weekly persona job (the chain's pinned tool; no image builder): a release tarball holding the crane binary, verified against the pinned sum.
    # each release asset is written out in full, with its version: the pin-age scan measures a literal release URL (no version variable and no base-URL hook)
    case "$arch" in
      x86_64|amd64) curl -fsSL -o "$tmp/c.tgz" "https://github.com/google/go-containerregistry/releases/download/v0.22.1/go-containerregistry_Linux_x86_64.tar.gz" || pipeline_fail "download failed: crane v0.22.1" ;;
      *) curl -fsSL -o "$tmp/c.tgz" "https://github.com/google/go-containerregistry/releases/download/v0.22.1/go-containerregistry_Linux_arm64.tar.gz" || pipeline_fail "download failed: crane v0.22.1" ;;
    esac
    verify "$tmp/c.tgz"
    tar -xzf "$tmp/c.tgz" -C "$DEST" crane || pipeline_fail "extract failed for crane"
    "${DEST}/crane" version >/dev/null || pipeline_fail "the installed crane binary does not start"
    ;;
  *)
    pipeline_fail "unknown scanner '${TOOL}' (want trivy|grype|syft|snyk|osv-scanner|inspector-sbomgen|docker-scout|gitsign|cosign|witness|go|crane|govulncheck)"
    ;;
esac
echo "installed ${TOOL} (pinned, checksum-verified) to ${DEST}"
