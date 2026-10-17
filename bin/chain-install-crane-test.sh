#!/usr/bin/env bash
# proves: REQ-CHAIN-007-AC7
# The copy tool of the Release stage (crane) is pinned by checksum (v0.3.0 rules 16, 64: "the copy tool is pinned by checksum, no build command").
# Failure-path suite for the crane entry of bin/install-scanner.sh, in the style of bin/install-scanner-test.sh: a tool that cannot be installed
# or verified exits NON-ZERO and is LABELED a pipeline failure. The success path pulls a real vendor binary and cannot run offline.
# RED until PR 4 adds the entry. PROPOSED/UNVERIFIED: the version (v0.22.1, the one the old stage-promote.yml went-installed), the asset names
# go-containerregistry_Linux_x86_64.tar.gz and go-containerregistry_Linux_arm64.tar.gz, and the override CRANE_BASE_URL (every other tool has one).
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
sut="${here}/install-scanner.sh"
pass=0; fail=0
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
check() { # name expected_rc regex -- run...
  local name="$1" want_rc="$2" re="$3"; shift 3
  local out rc; out="$("$@" 2>&1)"; rc=$?
  if [ "$rc" -eq 0 ] && [ "$want_rc" -ne 0 ]; then echo "FAIL: ${name}: expected non-zero exit, got 0"; fail=$((fail+1)); return; fi
  if ! grep -qiE "$re" <<<"$out"; then echo "FAIL: ${name}: output did not match /$re/"; echo "$out" | sed 's/^/    /'; fail=$((fail+1)); return; fi
  echo "ok: ${name}"; pass=$((pass+1))
}
ver=$(grep -oE 'v0\.[0-9]+\.[0-9]+' <(grep -i crane "$sut" 2> /dev/null) | head -1)
for arch in x86_64 aarch64; do
  case "$arch" in x86_64) asset=go-containerregistry_Linux_x86_64.tar.gz ;; aarch64) asset=go-containerregistry_Linux_arm64.tar.gz ;; esac
  mkdir -p "$work/rel/${ver:-v0.0.0}"; echo "not the real crane tarball" > "$work/rel/${ver:-v0.0.0}/$asset"
  check "crane checksum mismatch rejected on $arch" 1 "checksum mismatch.*PIPELINE failure" \
    env INSTALL_SCANNER_ARCH=$arch CRANE_BASE_URL="file://$work/rel" bash "$sut" crane "$work/bin-$arch"
  check "crane download failure rejected on $arch" 1 "download failed.*PIPELINE failure" \
    env INSTALL_SCANNER_ARCH=$arch CRANE_BASE_URL="file://$work/nope" bash "$sut" crane "$work/bin-$arch"
done
check "crane unsupported architecture rejected" 1 "unsupported architecture.*PIPELINE failure" env INSTALL_SCANNER_ARCH=mips bash "$sut" crane "$work/bin"
# the pin itself: one version, one 64-hex sha256 per architecture, in the crane entry (a placeholder or a missing sum is a failure)
n=$(grep -ciE 'crane' "$sut" 2> /dev/null); n=${n:-0}
if [ "$n" -gt 0 ] && [ -n "$ver" ] && [ "$(grep -iE 'crane' "$sut" | grep -oE '[0-9a-f]{64}' | sort -u | wc -l | tr -d ' ')" -ge 2 ]; then echo "ok: crane is pinned to $ver with a sha256 for both architectures"; pass=$((pass+1))
else echo "FAIL: crane is not pinned to a version with a 64-hex sha256 for both architectures in $sut"; fail=$((fail+1)); fi
if [ "$n" -eq 0 ]; then echo "FAIL: there is no crane entry in $sut to judge"; fail=$((fail+1))
elif grep -qE 'go install|@latest' <(grep -i crane "$sut" 2> /dev/null); then echo "FAIL: crane is installed by go install or @latest, not by a checksummed download"; fail=$((fail+1)); else echo "ok: crane is not installed by go install or @latest"; pass=$((pass+1)); fi
echo "pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
