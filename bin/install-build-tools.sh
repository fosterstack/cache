#!/usr/bin/env bash
# Install melange or apko from its pinned release (v0.3.0 rule 16: pinned by checksum, verified before first use).
#
#   install-build-tools.sh melange|apko [DEST]      DEST defaults to /usr/local/bin; the tool is installed as DEST/<tool>
#
# The release archive for this machine (Linux, amd64 or arm64) is fetched from the project's GitHub release by exact
# version, its sha256 is compared with the pin below BEFORE anything is unpacked, and only then is the one binary
# extracted. A mismatch installs nothing. No container image is used, so there is no image digest to pin.
# Both versions were public for more than 7 days when pinned (supply-chain rule REQ-SUP-001); re-check at merge time.
# To move a pin: change the version and all of that tool's sha256 values together, from the release's checksums.txt.
# Exit codes: 0 installed | 1 download failed or the sha256 does not match the pin (nothing installed) | 2 refused:
# unknown tool, unsupported architecture or operating system, bad arguments.
set -euo pipefail

MELANGE_VERSION=0.61.2
MELANGE_SHA256_AMD64=9a78ee4bd5bd166b5d358b49249e0e6f25e10efede51cf407262218d8a65d78e
MELANGE_SHA256_ARM64=5f880b955f2482452b901bda39add46548a747501363a65b9868fbb3c795927f
APKO_VERSION=1.4.6
APKO_SHA256_AMD64=bbe51cce228b70aef68f436da4fc11b5d235b06f8fc1d4c35b39116b86895271
APKO_SHA256_ARM64=5a9344fa792fe1ab8454133233a34c044f15aafed03c6621880fb9a58e23674f

die() { echo "install-build-tools.sh: $1" >&2; exit "${2:-2}"; }

tool=${1:-}; dest="${2:-/usr/local/bin}"
[ $# -le 2 ] || die "usage: install-build-tools.sh melange|apko [DEST]"
case $tool in
  melange) ver=$MELANGE_VERSION; want_amd64=$MELANGE_SHA256_AMD64; want_arm64=$MELANGE_SHA256_ARM64; repo=chainguard-dev/melange;;
  apko) ver=$APKO_VERSION; want_amd64=$APKO_SHA256_AMD64; want_arm64=$APKO_SHA256_ARM64; repo=chainguard-dev/apko;;
  *) die "unknown tool '$tool' (melange or apko)";;
esac

[ "$(uname -s)" = Linux ] || die "unsupported operating system $(uname -s): the build tools are installed on Linux only"
case $(uname -m) in
  x86_64|amd64) arch=amd64; want=$want_amd64;;
  aarch64|arm64) arch=arm64; want=$want_arm64;;
  *) die "unsupported architecture $(uname -m) (x86_64 or aarch64)";;
esac

file=${tool}_${ver}_linux_${arch}.tar.gz
tmp=$(mktemp -d)
cleanup() { local rc=$?; set +e; rm -rf "$tmp" 2>/dev/null || true; exit $rc; }   # cleanup never changes the exit status
trap cleanup EXIT
curl -fsSL -o "$tmp/$file" "https://github.com/$repo/releases/download/v$ver/$file" || die "could not download $file" 1

if command -v sha256sum >/dev/null 2>&1; then got=$(sha256sum "$tmp/$file" | cut -d' ' -f1); else got=$(shasum -a 256 "$tmp/$file" | cut -d' ' -f1); fi
[ "$got" = "$want" ] || die "sha256 mismatch for $file: got $got, the pin is $want; nothing installed" 1

mkdir -p "$tmp/x" "$dest"
tar -xzf "$tmp/$file" -C "$tmp/x"
bin=$(find "$tmp/x" -type f -name "$tool" | head -n 1)   # the release unpacks to <tool>_<version>_linux_<arch>/<tool>
[ -n "$bin" ] || die "$file has no $tool binary" 1
# literal destination names (not "$dest/$tool"): a job that runs this installer and then other committed scripts can then be shown
# not to overwrite any of them (the action-pin checker needs the last path component to be a literal)
case $tool in
  melange) install -m 0755 "$bin" "$dest/melange";;
  apko) install -m 0755 "$bin" "$dest/apko";;
esac
echo "installed $tool $ver ($arch) to $dest/$tool"
