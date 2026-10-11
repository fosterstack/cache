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
# ---- the Go toolchain (Codex A r3 F4, advisor): `bash bin/install-scanner.sh go [dest-dir]` -----------------------------------------------------------------
# The exact go<ver>.linux-<arch>.tar.gz of go.mod's `toolchain` line (the `go` line only when the file has no toolchain line), pinned by a committed sha256
# PER ARCHITECTURE (values checked against go.dev's published checksums), unpacked to the fixed directory <dest-dir>/fscache-go (default /usr/local/bin/fscache-go),
# refused on any mismatch. Offline: the tarball comes from a local file:// base (GO_BASE_URL). The SUCCESS path needs the real tarball; the dry run proves it.
GOVER=$(sed -n 's/^GO_VER=\([0-9.]*\).*/\1/p' "$sut" | head -1)
GO_AMD=ecbadb99091a3f46e31f5f934b068b1864eafa7995211b39eaddf76996045fe5
GO_ARM=94f3e30b8e374bc285e7dadc11e0865726b9bc6e85b841ccceaabc0214c6b7c8
repo_gomod_ver=$(awk '$1 == "toolchain" {sub(/^go/, "", $2); t = $2} $1 == "go" && g == "" {g = $2} END {print (t != "" ? t : g)}' "$root/go.mod")
gwork="$work/go"; mkdir -p "$gwork/rel" "$gwork/mod-ok" "$gwork/mod-tool" "$gwork/mod-old" "$gwork/mod-none"
printf 'module x\n\ngo 1.27.2\n' > "$gwork/mod-ok/go.mod"
printf 'module x\n\ngo 1.20\n\ntoolchain go1.27.2\n' > "$gwork/mod-tool/go.mod"
printf 'module x\n\ngo 1.27.1\n' > "$gwork/mod-old/go.mod"
echo "not the real go tarball" > "$gwork/rel/go1.27.2.linux-amd64.tar.gz"; echo "not the real go tarball either" > "$gwork/rel/go1.27.2.linux-arm64.tar.gz"
gocheck() { # gocheck LABEL MODDIR REGEX ENV...   run the installer in a directory whose go.mod is MODDIR's
  local label=$1 mod=$2 re=$3; shift 3; local out rc=0
  out=$(cd "$mod" && env "$@" bash "$sut" go "$gwork/bin" 2>&1) || rc=$?
  if [ "$rc" -ne 0 ] && grep -qiE "$re" <<< "$out"; then ok "$label"; else bad "$label: exit $rc: ${out:0:170}"; fi; }
if ! grep -q '^GO_VER=' "$sut" 2> /dev/null; then
  for l in "go: the pins are the repo go.mod's version and go.dev's checksums" "go: a wrong checksum (amd64) is refused" "go: a wrong checksum (arm64) is refused" \
           "go: a go.mod version that is not the pinned one is refused" "go: the toolchain line wins over the go line" "go: the go line is used when there is no toolchain line" \
           "go: an unknown architecture is refused" "go: a failed download is refused" "go: no go.mod is refused" "go: a failed install leaves no toolchain" \
           "go: there is no environment override of a checksum or of the version"; do bad "$l (bin/install-scanner.sh has no go: RED until implemented)"; done
else
  if [ "$GOVER" = "$repo_gomod_ver" ] && grep -q "$GO_AMD" < <(grep -E 'go:x86_64\|go:amd64' "$sut") && grep -q "$GO_ARM" < <(grep -E 'go:aarch64\|go:arm64' "$sut"); then
    ok "go: the pinned version ($GOVER) is the repo go.mod's and the two sha256 values are go.dev's published ones"
  else bad "go: pins: version '$GOVER' vs go.mod '$repo_gomod_ver'; amd64/arm64 values"; fi
  gocheck "go: a wrong checksum (amd64) is refused" "$gwork/mod-ok" "checksum mismatch.*PIPELINE failure" INSTALL_SCANNER_ARCH=x86_64 GO_BASE_URL="file://$gwork/rel"
  gocheck "go: a wrong checksum (arm64) is refused" "$gwork/mod-ok" "checksum mismatch.*PIPELINE failure" INSTALL_SCANNER_ARCH=aarch64 GO_BASE_URL="file://$gwork/rel"
  gocheck "go: a go.mod version that is not the pinned one is refused" "$gwork/mod-old" "go\\.mod.*(1\\.27\\.1).*pinned|pinned.*go\\.mod" INSTALL_SCANNER_ARCH=x86_64 GO_BASE_URL="file://$gwork/rel"
  gocheck "go: the toolchain line wins over the go line (it reaches the checksum, so the version matched)" "$gwork/mod-tool" "checksum mismatch" INSTALL_SCANNER_ARCH=x86_64 GO_BASE_URL="file://$gwork/rel"
  gocheck "go: the go line is used when there is no toolchain line (it reaches the checksum)" "$gwork/mod-ok" "checksum mismatch" INSTALL_SCANNER_ARCH=x86_64 GO_BASE_URL="file://$gwork/rel"
  gocheck "go: an unknown architecture is refused" "$gwork/mod-ok" "unsupported architecture.*PIPELINE failure" INSTALL_SCANNER_ARCH=mips GO_BASE_URL="file://$gwork/rel"
  gocheck "go: a failed download is refused" "$gwork/mod-ok" "download failed.*PIPELINE failure" INSTALL_SCANNER_ARCH=x86_64 GO_BASE_URL="file://$gwork/nope"
  gocheck "go: no go.mod is refused" "$gwork/mod-none" "go\\.mod.*PIPELINE failure|PIPELINE failure.*go\\.mod|no go\\.mod" INSTALL_SCANNER_ARCH=x86_64 GO_BASE_URL="file://$gwork/rel"
  [ ! -e "$gwork/bin/fscache-go" ] && ok "go: a failed install leaves no toolchain" || bad "go: a failed install left $gwork/bin/fscache-go"
  if grep -Eq 'GO_(SHA256|SUM|CHECKSUM)[^=]*[:-]|\$\{GO_(SHA256|SUM|CHECKSUM|VER|VERSION):?[-=]|GOVERSION=|GOTOOLCHAIN=auto' "$sut"; then bad "go: the script lets the environment override the checksum or the version"; else ok "go: there is no environment override of a checksum or of the version (the only hook is GO_BASE_URL)"; fi
fi
EXPECT=19
echo "pass=$pass fail=$failn"
if [ $((pass + failn)) != "$EXPECT" ]; then echo "FAIL case count $((pass + failn)) != expected $EXPECT (a case was skipped or added)"; exit 1; fi
[ "$failn" = 0 ]
