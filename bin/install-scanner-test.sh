#!/usr/bin/env bash
# Failure-path suite for bin/install-scanner.sh. The success path pulls a
# real vendor binary and cannot run offline; what MUST hold offline is the
# contract the audit demanded: a scanner that cannot be installed or
# verified exits NON-ZERO and is LABELED a pipeline failure (never a silent
# clean pass, never mistaken for a finding). Every case here asserts both.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
sut="${here}/install-scanner.sh"
pass=0; fail=0
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT

check() { # name expected_rc regex -- run...
  local name="$1" want_rc="$2" re="$3"; shift 3
  local out rc
  out="$("$@" 2>&1)"; rc=$?
  if [ "$rc" -eq 0 ] && [ "$want_rc" -ne 0 ]; then
    echo "FAIL: ${name}: expected non-zero exit, got 0"; fail=$((fail+1)); return
  fi
  if ! grep -qiE "$re" <<<"$out"; then
    echo "FAIL: ${name}: output did not match /$re/"; echo "$out" | sed 's/^/    /'; fail=$((fail+1)); return
  fi
  echo "ok: ${name}"; pass=$((pass+1))
}

# 1. Unknown scanner is a labeled pipeline failure.
check "unknown scanner rejected" 1 "unknown scanner.*PIPELINE failure" \
  bash "$sut" bogus "$work/bin"

# 2. Unsupported architecture is a labeled pipeline failure.
check "unsupported arch rejected" 1 "unsupported architecture.*PIPELINE failure" \
  env INSTALL_SCANNER_ARCH=mips bash "$sut" trivy "$work/bin"

# 3. Checksum mismatch is a labeled pipeline failure (bytes that do NOT
#    match the pinned sha256). Serve a bogus asset over file://.
mkdir -p "$work/rel/v0.74.0"
echo "not the real trivy tarball" > "$work/rel/v0.74.0/trivy_0.74.0_Linux-64bit.tar.gz"
check "trivy checksum mismatch rejected" 1 "checksum mismatch.*PIPELINE failure" \
  env INSTALL_SCANNER_ARCH=x86_64 TRIVY_BASE_URL="file://$work/rel" bash "$sut" trivy "$work/bin"

# 4. Download failure (asset absent) is a labeled pipeline failure.
check "grype download failure rejected" 1 "download failed.*PIPELINE failure" \
  env INSTALL_SCANNER_ARCH=x86_64 GRYPE_BASE_URL="file://$work/does-not-exist" bash "$sut" grype "$work/bin"

# 4b. osv-scanner checksum mismatch is a labeled pipeline failure.
mkdir -p "$work/rel/v2.6.0"
echo "not the real osv-scanner binary" > "$work/rel/v2.6.0/osv-scanner_linux_amd64"
check "osv-scanner checksum mismatch rejected" 1 "checksum mismatch.*PIPELINE failure" \
  env INSTALL_SCANNER_ARCH=x86_64 OSV_BASE_URL="file://$work/rel" bash "$sut" osv-scanner "$work/bin"

# 4c. osv-scanner download failure is a labeled pipeline failure.
check "osv-scanner download failure rejected" 1 "download failed.*PIPELINE failure" \
  env INSTALL_SCANNER_ARCH=x86_64 OSV_BASE_URL="file://$work/nope" bash "$sut" osv-scanner "$work/bin"

# 5. No arg is a labeled pipeline failure (empty tool).
check "missing scanner arg rejected" 1 "unknown scanner.*PIPELINE failure" \
  bash "$sut"

echo "----"
echo "install-scanner: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
