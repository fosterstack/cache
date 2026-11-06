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
# 4g. crane (the chain's pinned tool for digest reads; the weekly persona job installs it, handoff 0490). It has a literal asset address and no base-URL hook (advisor 2b
#     ruling), so there is nothing to point at a local file: the contract is judged on the installer's text, and the shared verify() path is the one the cases above run.
crane_block=$(awk '/^  crane\)$/{f=1} f{print} f&&/^    ;;$/{exit}' "$sut")
if [ -n "$crane_block" ]; then echo "ok: the installer has a crane case"; pass=$((pass+1)); else echo "FAIL: the installer has no crane case"; fail=$((fail+1)); fi
urls=$(grep -o 'https://[^" ]*' <<<"$crane_block")
if [ "$(wc -l <<<"$urls" | tr -d ' ')" = 2 ] && ! grep -v -E '^https://github\.com/google/go-containerregistry/releases/download/v0\.22\.1/go-containerregistry_Linux_(x86_64|arm64)\.tar\.gz$' <<<"$urls" | grep -q .; then
  echo "ok: crane has two literal asset addresses, both of v0.22.1 on its release page, one per architecture"; pass=$((pass+1))
else echo "FAIL: crane addresses: $(tr '\n' ' ' <<<"$urls")"; fail=$((fail+1)); fi
v=$(grep -n 'verify "\$tmp/c.tgz"' <<<"$crane_block" | head -1 | cut -d: -f1); t=$(grep -n 'tar -xzf' <<<"$crane_block" | head -1 | cut -d: -f1)
if [ -n "$v" ] && [ -n "$t" ] && [ "$v" -lt "$t" ]; then echo "ok: crane is checked against the pinned sum before anything is extracted"; pass=$((pass+1)); else echo "FAIL: crane is not verified before extraction"; fail=$((fail+1)); fi
if grep -q 'CRANE_BASE' "$sut"; then echo "FAIL: crane has a base-URL hook"; fail=$((fail+1)); else echo "ok: crane has no base-URL hook"; pass=$((pass+1)); fi
if grep -q -F 'crane:x86_64|crane:amd64) SUM=0ab7a1d6932a213aed964ce97666c3077fe691c8606413674a8b3e0b9ec4cda0 ;;' "$sut" \
   && grep -q -F 'crane:aarch64|crane:arm64) SUM=898c0cff975f898a33e8c4580bdafb0e7c02c7faa33374e946762f97c4ab7110 ;;' "$sut"; then
  echo "ok: crane's two sums are the release tarballs' (amd64 0ab7a1d6..., arm64 898c0cff...)"; pass=$((pass+1)); else echo "FAIL: crane sums differ from the pinned release values"; fail=$((fail+1)); fi
if grep -q -E 'tar -xzf "\$tmp/c\.tgz" -C "\$DEST" crane \|\|' <<<"$crane_block" && ! grep -q -E -- ' -k |--insecure|--cacert|http://' <<<"$crane_block"; then
  echo "ok: crane extracts only its own member and the download keeps TLS verification"; pass=$((pass+1)); else echo "FAIL: crane extraction or TLS flags"; fail=$((fail+1)); fi
n=$(grep -c -E '^  crane:[a-z0-9_|:]+\) SUM=[0-9a-f]{64} ;;' "$sut")
if [ "$n" = 2 ]; then echo "ok: crane has exactly two pinned sums (amd64, arm64)"; pass=$((pass+1)); else echo "FAIL: crane sums found: $n"; fail=$((fail+1)); fi
check "crane on an unsupported architecture is a labeled pipeline failure" 1 "unsupported architecture.*PIPELINE failure" \
  env INSTALL_SCANNER_ARCH=mips bash "$sut" crane "$work/bin"
# 5. No arg is a labeled pipeline failure (empty tool).
check "missing scanner arg rejected" 1 "unknown scanner.*PIPELINE failure" \
  bash "$sut"

# 9. KA-2 p4 group 4: the AWS CLI v2 (the signer's KMS calls), pinned by checksum and installed job-locally under RUNNER_TEMP/aws-cli (no bare path of the runner image).
#    The sha256 below is the one the lane measured on the downloaded zip of 2.39.3, whose detached signature (gpg) is by the AWS CLI Team key, fingerprint
#    FB5D B77F D5C1 18B8 0511 ADA8 A631 0ACC 4672 475C (the fingerprint AWS's install page prints).
AWS_SHA=14cb35809ad7547dd3c69fa9899a3975fbd850b6a6791f3fe264856490cd9a63
AWS_URL=https://awscli.amazonaws.com/awscli-exe-linux-x86_64-2.39.3.zip
check "aws-cli without RUNNER_TEMP is a labeled pipeline failure (it installs under it and takes no destination)" 1 "RUNNER_TEMP.*PIPELINE failure" \
  env -u RUNNER_TEMP INSTALL_SCANNER_ARCH=x86_64 bash "$sut" aws-cli
check "aws-cli is pinned for x86_64 only: aarch64 has no pinned checksum" 1 "no pinned checksum for aws-cli on aarch64.*PIPELINE failure" \
  env INSTALL_SCANNER_ARCH=aarch64 RUNNER_TEMP="$work/rt" bash "$sut" aws-cli
mkdir -p "$work/awsfake"
cat > "$work/awsfake/curl" <<'FAKE'
#!/usr/bin/env bash
# a stand-in curl: records the URL, writes bytes that are not the pinned zip to the -o target
out=; url=
while [ $# -gt 0 ]; do case "$1" in -o) out=$2; shift 2 ;; -*) shift ;; *) url=$1; shift ;; esac; done
echo "$url" >> "$AWSFAKE_LOG"
echo "not the pinned zip" > "$out"
FAKE
chmod +x "$work/awsfake/curl"
check "aws-cli checksum mismatch is a labeled pipeline failure and installs nothing" 1 "checksum mismatch.*PIPELINE failure" \
  env PATH="$work/awsfake:$PATH" AWSFAKE_LOG="$work/awsfake/log" INSTALL_SCANNER_ARCH=x86_64 RUNNER_TEMP="$work/rt2" bash "$sut" aws-cli
if [ "$(cat "$work/awsfake/log" 2>/dev/null)" = "$AWS_URL" ] && [ ! -e "$work/rt2/aws-cli/aws" ]; then
  echo "ok: aws-cli downloads exactly the pinned 2.39.3 zip URL and leaves no aws behind after a mismatch"; pass=$((pass+1))
else echo "FAIL: aws-cli URL or leftovers: $(cat "$work/awsfake/log" 2>/dev/null) / $(ls "$work/rt2/aws-cli" 2>&1 | head -2)"; fail=$((fail+1)); fi
cat > "$work/awsjudge.py" <<'PY'
import re, sys
def judge(t, sha):
    bad = []
    m = re.search(r"^\s*aws-cli:x86_64\|aws-cli:amd64\) SUM=([0-9a-f]{64}) ;;$", t, re.M)
    if not m: bad.append("row missing: no aws-cli:x86_64|aws-cli:amd64 checksum row")
    elif m.group(1) != sha: bad.append("sha mismatch: the row holds %s, not the measured %s" % (m.group(1), sha))
    v = re.search(r"^AWSCLI_VER=(\d+\.\d+\.\d+)$", t, re.M)
    u = re.findall(r"https://awscli\.amazonaws\.com/awscli-exe-linux-x86_64-(\d+\.\d+\.\d+)\.zip", t)
    if not v: bad.append("version mismatch: no AWSCLI_VER line")
    elif u != [v.group(1)]: bad.append("version mismatch: the URL names %s but AWSCLI_VER is %s" % (u, v.group(1)))
    if not re.search(r'case "\$got" in "aws-cli/\$\{AWSCLI_VER\} "\*\) ;; \*\) pipeline_fail', t): bad.append("version mismatch: no check that the installed aws --version is the pinned one")
    if 'test -n "${RUNNER_TEMP:-}" || pipeline_fail "aws-cli needs RUNNER_TEMP' not in t: bad.append("no RUNNER_TEMP check: the install is not job-local")
    return bad
t = open(sys.argv[1]).read(); sha = sys.argv[2]
assert judge(t, sha) == [], judge(t, sha)
muts = {
  "row missing": lambda x: re.sub(r"^\s*aws-cli:x86_64\|aws-cli:amd64\) SUM=.*\n", "", x, flags=re.M),
  "sha mismatch": lambda x: x.replace(sha, sha[:-1] + ("0" if sha[-1] != "0" else "1")),
  "version mismatch (URL)": lambda x: x.replace("x86_64-2.39.3.zip", "x86_64-2.39.2.zip"),
  "version mismatch (AWSCLI_VER)": lambda x: re.sub(r"^AWSCLI_VER=.*$", "AWSCLI_VER=2.39.2", x, flags=re.M),
  "version check dropped": lambda x: re.sub(r'case "\$got" in "aws-cli/\$\{AWSCLI_VER\} "\*\) ;; \*\) pipeline_fail[^\n]*\n', "", x),
  "not job-local": lambda x: x.replace("aws-cli needs RUNNER_TEMP", "aws-cli needs HOME"),
}
for name, f in muts.items():
    print(("ok: aws-cli judge catches: " if judge(f(t), sha) else "FAIL: aws-cli judge missed: ") + name)
PY
while IFS= read -r line; do
  case "$line" in ok:*) echo "$line"; pass=$((pass+1)) ;; *) echo "$line"; fail=$((fail+1)) ;; esac
done < <(python3 "$work/awsjudge.py" "$sut" "$AWS_SHA" 2>&1 || echo "FAIL: aws-cli judge did not accept the real installer")

echo "----"
echo "install-scanner: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
