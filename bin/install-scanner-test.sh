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

# 4s. the two older Scout versions for the root-cause round (advisor 0120/0122) are pinned too: wrong bytes are
#     refused; an unlisted version is not a tool
for v in 1.24.0 1.25.0; do
  mkdir -p "$work/scout/v$v"; echo "not the real docker-scout $v" > "$work/scout/v$v/docker-scout_${v}_linux_amd64.tar.gz"
  check "docker-scout-$v checksum mismatch rejected" 1 "checksum mismatch.*PIPELINE failure" \
    env INSTALL_SCANNER_ARCH=x86_64 SCOUT_BASE_URL="file://$work/scout" bash "$sut" "docker-scout-$v" "$work/bin"
done
check "docker-scout-1.23.0 is not a pinned tool" 1 "(unknown scanner|no pinned checksum).*PIPELINE failure" \
  env INSTALL_SCANNER_ARCH=x86_64 bash "$sut" docker-scout-1.23.0 "$work/bin"
check "docker-scout-1.25.0 has no arm64 pin" 1 "no pinned checksum.*PIPELINE failure" \
  env INSTALL_SCANNER_ARCH=aarch64 bash "$sut" docker-scout-1.25.0 "$work/bin"

# 4d. inspector-sbomgen checksum mismatch is a labeled pipeline failure.
mkdir -p "$work/sg/1.16.0/linux/amd64"
echo "not the real inspector-sbomgen zip" > "$work/sg/1.16.0/linux/amd64/inspector-sbomgen.zip"
check "inspector-sbomgen checksum mismatch rejected" 1 "checksum mismatch.*PIPELINE failure" \
  env INSTALL_SCANNER_ARCH=x86_64 SBOMGEN_BASE_URL="file://$work/sg" bash "$sut" inspector-sbomgen "$work/bin"

# 4e. inspector-sbomgen download failure is a labeled pipeline failure.
check "inspector-sbomgen download failure rejected" 1 "download failed.*PIPELINE failure" \
  env INSTALL_SCANNER_ARCH=arm64 SBOMGEN_BASE_URL="file://$work/nope" bash "$sut" inspector-sbomgen "$work/bin"

# 4f. syft (the auditor's cataloguer; a pinned release binary since Sep 30's run-time build failed on sum.golang.org)
#     checksum mismatch and download failure are labeled pipeline failures.
mkdir -p "$work/syft/v1.52.0"
echo "not the real syft tarball" > "$work/syft/v1.52.0/syft_1.52.0_linux_amd64.tar.gz"
check "syft checksum mismatch rejected" 1 "checksum mismatch.*PIPELINE failure" \
  env INSTALL_SCANNER_ARCH=x86_64 SYFT_BASE_URL="file://$work/syft" bash "$sut" syft "$work/bin"
check "syft download failure rejected" 1 "download failed.*PIPELINE failure" \
  env INSTALL_SCANNER_ARCH=arm64 SYFT_BASE_URL="file://$work/nope" bash "$sut" syft "$work/bin"
# 4g. crane (the chain's pinned tool for digest reads; the weekly persona job installs it, handoff 0490): a literal download URL, no base-URL hook (advisor 2b ruling), so the
#     offline cases use a stub curl on PATH. The tarball is the pinned release of google/go-containerregistry v0.22.1.
mkdir -p "$work/stubcurl"
cat > "$work/stubcurl/curl" <<'STUB'
#!/usr/bin/env bash
# records the URL it is asked for; serves wrong bytes (or fails) as the case needs
out=""; url=""
while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2 ;; -*) shift ;; *) url="$1"; shift ;; esac; done
echo "$url" >> "$STUB_LOG"
[ "${STUB_MODE:-bytes}" = fail ] && exit 22
echo "not the real crane tarball" > "$out"
STUB
chmod +x "$work/stubcurl/curl"
: > "$work/curl.log"
check "crane checksum mismatch rejected" 1 "checksum mismatch.*PIPELINE failure" \
  env INSTALL_SCANNER_ARCH=x86_64 STUB_LOG="$work/curl.log" PATH="$work/stubcurl:$PATH" bash "$sut" crane "$work/bin"
check "crane download failure rejected" 1 "download failed.*PIPELINE failure" \
  env INSTALL_SCANNER_ARCH=arm64 STUB_MODE=fail STUB_LOG="$work/curl.log" PATH="$work/stubcurl:$PATH" bash "$sut" crane "$work/bin"
if [ "$(sed -n 1p "$work/curl.log")" = "https://github.com/google/go-containerregistry/releases/download/v0.22.1/go-containerregistry_Linux_x86_64.tar.gz" ] \
   && [ "$(sed -n 2p "$work/curl.log")" = "https://github.com/google/go-containerregistry/releases/download/v0.22.1/go-containerregistry_Linux_arm64.tar.gz" ]; then
  echo "ok: crane is fetched from the literal release URL of v0.22.1 for both architectures"; pass=$((pass+1))
else echo "FAIL: crane download URLs: $(cat "$work/curl.log" | tr '\n' ' ')"; fail=$((fail+1)); fi
if [ ! -e "$work/bin/crane" ]; then echo "ok: a refused crane leaves no binary behind"; pass=$((pass+1)); else echo "FAIL: crane binary left behind"; fail=$((fail+1)); fi
# no base-URL hook for crane (the chain drops those hooks; a download-source line is a pin-age matter)
if grep -q 'CRANE_BASE' "$sut"; then echo "FAIL: crane has a base-URL hook"; fail=$((fail+1)); else echo "ok: crane has no base-URL hook"; pass=$((pass+1)); fi
# a pinned sum for both architectures (a sum is 64 hex digits), none for anything else
n=$(grep -c -E '^  crane:[a-z0-9_|:]+\) SUM=[0-9a-f]{64} ;;' "$sut")
if [ "$n" = 2 ]; then echo "ok: crane has exactly two pinned sums (amd64, arm64)"; pass=$((pass+1)); else echo "FAIL: crane sums found: $n"; fail=$((fail+1)); fi
# 5. No arg is a labeled pipeline failure (empty tool).
check "missing scanner arg rejected" 1 "unknown scanner.*PIPELINE failure" \
  bash "$sut"

echo "----"
echo "install-scanner: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
