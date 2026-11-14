#!/usr/bin/env bash
# The crane entry of bin/install-scanner.sh: a tool that cannot be installed or verified exits NON-ZERO
# and is labeled a pipeline failure; the success path runs offline against a fixture tarball
# and a COPY of the script whose pinned x86_64 sum is the fixture's sum.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
sut="${here}/install-scanner.sh"
pass=0; fail=0
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
# the installer downloads from fixed https URLs: a stub on PATH serves the local layout STUB_REL
# (the URL after /download/ or /dl/), or fails like a refused download
stubbin="$work/stubbin"; mkdir -p "$stubbin"
cat > "$stubbin/curl" <<'STUB'
#!/usr/bin/env bash
out=""; u=""
while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift ;; https://*) u="$1" ;; esac; shift; done
rel="${u#*/download/}"; [ "$rel" != "$u" ] || rel="${u#*/dl/}"
[ -n "$out" ] && [ -f "${STUB_REL:-/nonexistent}/$rel" ] && cp "${STUB_REL}/$rel" "$out" || exit 22
STUB
chmod +x "$stubbin/curl"
check() { # name expected_rc regex -- run...
  local name="$1" want_rc="$2" re="$3"; shift 3
  local out rc; out="$("$@" 2>&1)"; rc=$?
  if [ "$rc" -ne 0 ] && [ "$want_rc" -eq 0 ]; then
    echo "FAIL: ${name}: expected exit 0, got ${rc}"; echo "$out" | sed 's/^/    /'; fail=$((fail+1)); return
  fi
  if [ "$rc" -eq 0 ] && [ "$want_rc" -ne 0 ]; then echo "FAIL: ${name}: expected non-zero exit, got 0"; fail=$((fail+1)); return; fi
  if ! grep -qiE "$re" <<<"$out"; then echo "FAIL: ${name}: output did not match /$re/"; echo "$out" | sed 's/^/    /'; fail=$((fail+1)); return; fi
  echo "ok: ${name}"; pass=$((pass+1))
}
ver=$(grep -oE 'v0\.[0-9]+\.[0-9]+' <(grep -i crane "$sut" 2> /dev/null) | head -1)
for arch in x86_64 aarch64; do
  case "$arch" in x86_64) asset=go-containerregistry_Linux_x86_64.tar.gz ;; aarch64) asset=go-containerregistry_Linux_arm64.tar.gz ;; esac
  mkdir -p "$work/rel/${ver:-v0.0.0}"; echo "not the real crane tarball" > "$work/rel/${ver:-v0.0.0}/$asset"
  check "crane checksum mismatch rejected on $arch" 1 "checksum mismatch.*PIPELINE failure" \
    env INSTALL_SCANNER_ARCH=$arch PATH="$stubbin:$PATH" STUB_REL="$work/rel" bash "$sut" crane "$work/bin-$arch"
  check "crane download failure rejected on $arch" 1 "download failed.*PIPELINE failure" \
    env INSTALL_SCANNER_ARCH=$arch PATH="$stubbin:$PATH" STUB_REL="$work/nope" bash "$sut" crane "$work/bin-$arch"
done
check "crane unsupported architecture rejected" 1 "unsupported architecture.*PIPELINE failure" env INSTALL_SCANNER_ARCH=mips bash "$sut" crane "$work/bin"
# success path: a fixture tarball with a fake crane,
# and a copy of the script whose pinned x86_64 crane sum is the fixture's real sum
ok_rel="$work/ok-rel/${ver:-v0.0.0}"; ok_src="$work/ok-src"; mkdir -p "$ok_rel" "$ok_src" "$work/ok-bin"
printf '#!/bin/sh\necho "fake crane 0.0.0"\n' > "$ok_src/crane"; chmod +x "$ok_src/crane"
tar -czf "$ok_rel/go-containerregistry_Linux_x86_64.tar.gz" -C "$ok_src" crane
ok_sum=$(sha256sum "$ok_rel/go-containerregistry_Linux_x86_64.tar.gz" | cut -d' ' -f1)
sut_copy="$work/install-scanner-copy.sh"
sed -E "s/^(  crane:x86_64\|crane:amd64\) SUM=)[0-9a-f]{64}/\1${ok_sum}/" "$sut" > "$sut_copy"
if grep -q "crane:x86_64|crane:amd64) SUM=${ok_sum}" "$sut_copy"; then
  echo "ok: the pinned crane sum was replaced in the copy"; pass=$((pass+1))
else echo "FAIL: the pinned crane sum was not replaced in the copy"; fail=$((fail+1)); fi
# the regex matches "installed crane (pinned, checksum-verified) to /bin" and refuses "the installed crane binary does not start"
check "crane install succeeds on x86_64" 0 "^installed crane " \
  env INSTALL_SCANNER_ARCH=x86_64 PATH="$stubbin:$PATH" STUB_REL="$work/ok-rel" bash "$sut_copy" crane "$work/ok-bin"
if [ -x "$work/ok-bin/crane" ]; then echo "ok: crane is installed and executable"; pass=$((pass+1))
else echo "FAIL: $work/ok-bin/crane is missing or not executable"; fail=$((fail+1)); fi
if [[ "$("$work/ok-bin/crane" version 2>&1)" == *"fake crane"* ]]; then
  echo "ok: the installed crane runs"; pass=$((pass+1))
else echo "FAIL: the installed crane does not run"; fail=$((fail+1)); fi
# the pin itself: one version, one 64-hex sha256 per architecture, in the crane entry (a placeholder or a missing sum is a failure)
n=$(grep -ciE 'crane' "$sut" 2> /dev/null); n=${n:-0}
if [ "$n" -gt 0 ] && [ -n "$ver" ] && [ "$(grep -iE 'crane' "$sut" | grep -oE '[0-9a-f]{64}' | sort -u | wc -l | tr -d ' ')" -ge 2 ]; then echo "ok: crane is pinned to $ver with a sha256 for both architectures"; pass=$((pass+1))
else echo "FAIL: crane is not pinned to a version with a 64-hex sha256 for both architectures in $sut"; fail=$((fail+1)); fi
if [ "$n" -eq 0 ]; then echo "FAIL: there is no crane entry in $sut to judge"; fail=$((fail+1))
elif grep -qE 'go install|@latest' <(grep -i crane "$sut" 2> /dev/null); then echo "FAIL: crane is installed by go install or @latest, not by a checksummed download"; fail=$((fail+1)); else echo "ok: crane is not installed by go install or @latest"; pass=$((pass+1)); fi
echo "pass=$pass fail=$fail"
EXPECT=11
if [ $((pass + fail)) != "$EXPECT" ]; then
  echo "FAIL case count $((pass + fail)) != expected $EXPECT (a case was skipped or added)"; exit 1
fi
[ "$fail" -eq 0 ]
