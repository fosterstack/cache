#!/usr/bin/env bash
# proves: REQ-CHAIN-004-AC2, REQ-CHAIN-005-AC1 — Witness is installed pinned by checksum before it starts, and the same install in Rebuild
# Written before bin/install-scanner.sh knew `witness` (tests before implementation, step 4).
#
# The failure-path suite for `./bin/install-scanner.sh witness [dest-dir]`, in the style of bin/install-scanner-test.sh (which this file does not edit):
# a Witness that cannot be installed or verified exits NON-ZERO, is LABELED a pipeline failure, and installs NOTHING. Runs on ubuntu-24.04 or macOS with
# bash and sha256sum or shasum. No network: the release is served from a local file:// base.
#
# THE INTERFACE (PROPOSED/UNVERIFIED where marked; it follows the other scanners in bin/install-scanner.sh):
#   WITNESS_VER=0.12.0 (the version the harness spikes verified, ops/handoffs/outbox/2026-10-09-harness-witness-spikes-a-c.md:15), pinned with a repo-pinned
#   sha256 PER ARCHITECTURE inside the script; asset names witness_<ver>_linux_amd64.tar.gz and witness_<ver>_linux_arm64.tar.gz under
#   WITNESS_BASE_URL/v<ver>/ (the release asset names of in-toto/witness v0.12.0: PROPOSED, the implementer confirms them against the release page);
#   INSTALL_SCANNER_ARCH selects the architecture (x86_64|amd64|aarch64|arm64); the default destination is /usr/local/bin (a directory on PATH, so the helper
#   bin/witnessed.sh finds `witness`); failures print `::error::scanner installer: ... (PIPELINE failure - not a scan finding)` and exit 1.
#   There is NO environment override of a checksum: the only test hook is the base URL, as for the other scanners.
# THE amd64 PIN IS the sha256 the harness spike recorded after verifying the tarball with cosign (identity
#   https://github.com/in-toto/witness/.github/workflows/release.yml@refs/tags/v0.12.0): 543d05898731fe5b9c176443ec596a0242bd27f0b327d73aff60f6f7398b7dd0.
#   The linux arm64 pin has no recorded value in any spike: the implementer takes it from the release checksums file, verified the same way, and this test
#   only requires that one exists and is 64 lower-case hex (PROPOSED/UNVERIFIED: the arm64 value).
# STATED GAP: the SUCCESS path (the pinned bytes download, verify, extract and land on PATH) needs the real release asset and cannot run offline without a
#   checksum override, which would weaken the script; the GitHub dry run proves it, and the stage files install Witness on a fresh runner every time.
set -uo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
sut="$root/bin/install-scanner.sh"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
ok()  { pass=$((pass + 1)); echo "ok   $1"; }
bad() { failn=$((failn + 1)); echo "FAIL $1"; }
check() { # check LABEL EXPECTED_RC REGEX -- cmd...  (a failure must be non-zero AND match the label of a pipeline failure)
  local label=$1 want=$2 re=$3; shift 4; local out rc=0
  out=$("$@" 2>&1) || rc=$?
  if [ "$rc" -eq 0 ] && [ "$want" -ne 0 ]; then bad "$label: expected non-zero, got 0"; return; fi
  if grep -qiE "$re" <<< "$out"; then ok "$label"; else bad "$label: output did not match /$re/: ${out:0:160}"; fi
}
if [ ! -f "$sut" ] || ! grep -q 'witness' "$sut"; then
  for l in "an unknown tool is still refused" "witness checksum mismatch (amd64) is a pipeline failure" "witness checksum mismatch (arm64) is a pipeline failure" "a failed download is a pipeline failure" \
           "an unsupported architecture is a pipeline failure" "a failed install leaves no witness binary" "the pins: version, amd64 sha256 equal to the harness spike's, an arm64 sha256" "there is no environment override of a checksum"; do
    bad "$l (bin/install-scanner.sh has no witness: RED until implemented)"
  done
else
  VER=$(sed -n 's/^WITNESS_VER=\([0-9.]*\).*/\1/p' "$sut" | head -1)
  mkdir -p "$work/rel/v${VER:-0.12.0}"
  echo "not the real witness tarball" > "$work/rel/v${VER:-0.12.0}/witness_${VER:-0.12.0}_linux_amd64.tar.gz"
  echo "not the real witness tarball either" > "$work/rel/v${VER:-0.12.0}/witness_${VER:-0.12.0}_linux_arm64.tar.gz"
  check "an unknown tool is still refused" 1 "unknown scanner.*PIPELINE failure" -- bash "$sut" bogus "$work/bin"
  check "witness checksum mismatch (amd64) is a pipeline failure" 1 "checksum mismatch.*PIPELINE failure" -- env INSTALL_SCANNER_ARCH=x86_64 WITNESS_BASE_URL="file://$work/rel" bash "$sut" witness "$work/bin"
  check "witness checksum mismatch (arm64) is a pipeline failure" 1 "checksum mismatch.*PIPELINE failure" -- env INSTALL_SCANNER_ARCH=aarch64 WITNESS_BASE_URL="file://$work/rel" bash "$sut" witness "$work/bin"
  check "a failed download is a pipeline failure" 1 "download failed.*PIPELINE failure" -- env INSTALL_SCANNER_ARCH=x86_64 WITNESS_BASE_URL="file://$work/nope" bash "$sut" witness "$work/bin"
  check "an unsupported architecture is a pipeline failure" 1 "unsupported architecture.*PIPELINE failure" -- env INSTALL_SCANNER_ARCH=mips WITNESS_BASE_URL="file://$work/rel" bash "$sut" witness "$work/bin"
  [ ! -e "$work/bin/witness" ] && ok "a failed install leaves no witness binary" || bad "a failed install left $work/bin/witness"
  amd=$(grep -E 'witness:x86_64\|witness:amd64' "$sut" | grep -oE '[0-9a-f]{64}' | head -1)
  arm=$(grep -E 'witness:aarch64\|witness:arm64' "$sut" | grep -oE '[0-9a-f]{64}' | head -1)
  if [ "${VER:-}" = 0.12.0 ] && [ "$amd" = 543d05898731fe5b9c176443ec596a0242bd27f0b327d73aff60f6f7398b7dd0 ] && [[ "$arm" =~ ^[0-9a-f]{64}$ ]] && [ "$arm" != "$amd" ]; then ok "the pins: version 0.12.0, the amd64 sha256 the harness spike recorded, a different arm64 sha256"; else bad "the pins: version='${VER:-}' amd64='${amd:0:16}' arm64='${arm:0:16}'"; fi
  if grep -Eq 'WITNESS_(SHA256|SUM|CHECKSUM)[^=]*[:-]|\$\{WITNESS_(SHA256|SUM|CHECKSUM)' "$sut"; then bad "the script lets the environment override the witness checksum"; else ok "there is no environment override of a checksum (the only hook is WITNESS_BASE_URL)"; fi
fi
EXPECT=8
echo "pass=$pass fail=$failn"
if [ $((pass + failn)) != "$EXPECT" ]; then echo "FAIL case count $((pass + failn)) != expected $EXPECT (a case was skipped or added)"; exit 1; fi
[ "$failn" = 0 ]
