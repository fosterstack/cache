#!/usr/bin/env bash
# proves: REQ-CHAIN-004-AC2, REQ-CHAIN-005-AC1, REQ-CHAIN-006-AC4, REQ-SUP-001-AC1 — Witness is installed pinned by checksum before it starts, and the same install in Rebuild
# Written before bin/install-scanner.sh knew `witness` (tests before implementation, step 4).
#
# The failure-path suite for `./bin/install-scanner.sh witness [dest-dir]`, in the style of bin/install-scanner-test.sh (which this file does not edit):
# a Witness that cannot be installed or verified exits NON-ZERO, is LABELED a pipeline failure, and installs NOTHING. Runs on ubuntu-24.04 or macOS with
# bash and sha256sum or shasum. No network: the release is served from a local file:// base.
#
# THE INTERFACE (PROPOSED/UNVERIFIED where marked; it follows the other scanners in bin/install-scanner.sh):
#   WITNESS_VER=0.12.0 (the version the harness spikes verified, ops/handoffs/outbox/2026-10-09-harness-witness-spikes-a-c.md:15), pinned with a repo-pinned
#   sha256 PER ARCHITECTURE inside the script; asset names witness_<ver>_linux_amd64.tar.gz and witness_<ver>_linux_arm64.tar.gz under
#   <release URL>/v<ver>/ (the release asset names of in-toto/witness v0.12.0: PROPOSED, the implementer confirms them against the release page);
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
# the download stand-in: the installers fetch from fixed https URLs now, so a curl on PATH serves the local release layout STUB_REL (the part of the URL after /download/ or /dl/), or fails like a refused download
stubbin="$work/stubbin"; mkdir -p "$stubbin"
FXD_2="$stubbin/curl"
cat > "$FXD_2" <<'STUB'
#!/usr/bin/env bash
out=""; u=""
while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift ;; https://*) u="$1" ;; esac; shift; done
rel="${u#*/download/}"; [ "$rel" != "$u" ] || rel="${u#*/dl/}"
[ -n "$out" ] && [ -f "${STUB_REL:-/nonexistent}/$rel" ] && cp "${STUB_REL}/$rel" "$out" || exit 22
STUB
FXD_1="$stubbin/curl"
chmod +x "$FXD_1"
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
  for tool_ in COSIGN WITNESS CRANE; do   # the release URL of each tool names the pinned version literally: the two must agree
    pinned_=$(sed -n "s/^${tool_}_VER=\([0-9.]*\).*/\1/p" "$sut" | head -1)
    # crane has no version variable (main's REQ-SUP-001-AC26: the pin-age scan measures the literal release URLs): its pinned version is the one its first release URL names, and every URL must name that same version
    if [ "$tool_" = CRANE ] && [ -z "$pinned_" ]; then pinned_=$(grep -i 'crane' "$sut" | grep -o 'releases/download/v[0-9.]*/' | head -1 | sed 's|releases/download/v||; s|/||'); fi
    lines_=$(grep -i "${tool_}\|$(printf '%s' "$tool_" | tr 'A-Z' 'a-z')" "$sut" | grep 'releases/download/'); total_=$(grep -c . <<< "$lines_"); good_=$(grep -c "releases/download/v${pinned_}/" <<< "$lines_")
    if [ -n "$pinned_" ] && [ "$total_" -ge 2 ] && [ "$total_" = "$good_" ]; then ok "$tool_: every release URL ($total_, one per architecture) names the pinned version $pinned_"; else bad "$tool_: $good_ of $total_ release URLs name the pinned version '${pinned_}'"; fi
  done
  check "an unknown tool is still refused" 1 "unknown scanner.*PIPELINE failure" -- bash "$sut" bogus "$work/bin"
  check "witness checksum mismatch (amd64) is a pipeline failure" 1 "checksum mismatch.*PIPELINE failure" -- env INSTALL_SCANNER_ARCH=x86_64 PATH="$stubbin:$PATH" STUB_REL="$work/rel" bash "$sut" witness "$work/bin"
  check "witness checksum mismatch (arm64) is a pipeline failure" 1 "checksum mismatch.*PIPELINE failure" -- env INSTALL_SCANNER_ARCH=aarch64 PATH="$stubbin:$PATH" STUB_REL="$work/rel" bash "$sut" witness "$work/bin"
  check "a failed download is a pipeline failure" 1 "download failed.*PIPELINE failure" -- env INSTALL_SCANNER_ARCH=x86_64 PATH="$stubbin:$PATH" STUB_REL="$work/nope" bash "$sut" witness "$work/bin"
  check "an unsupported architecture is a pipeline failure" 1 "unsupported architecture.*PIPELINE failure" -- env INSTALL_SCANNER_ARCH=mips PATH="$stubbin:$PATH" STUB_REL="$work/rel" bash "$sut" witness "$work/bin"
  [ ! -e "$work/bin/witness" ] && ok "a failed install leaves no witness binary" || bad "a failed install left $work/bin/witness"
  amd=$(grep -E 'witness:x86_64\|witness:amd64' "$sut" | grep -oE '[0-9a-f]{64}' | head -1)
  arm=$(grep -E 'witness:aarch64\|witness:arm64' "$sut" | grep -oE '[0-9a-f]{64}' | head -1)
  if [ "${VER:-}" = 0.12.0 ] && [ "$amd" = 543d05898731fe5b9c176443ec596a0242bd27f0b327d73aff60f6f7398b7dd0 ] && [[ "$arm" =~ ^[0-9a-f]{64}$ ]] && [ "$arm" != "$amd" ]; then ok "the pins: version 0.12.0, the amd64 sha256 the harness spike recorded, a different arm64 sha256"; else bad "the pins: version='${VER:-}' amd64='${amd:0:16}' arm64='${arm:0:16}'"; fi
  if grep -Eq 'WITNESS_(SHA256|SUM|CHECKSUM)[^=]*[:-]|\$\{WITNESS_(SHA256|SUM|CHECKSUM)' "$sut"; then bad "the script lets the environment override the witness checksum"; else ok "there is no environment override of a checksum (the release URL is fixed in the script)"; fi
fi
# ---- the Go toolchain (Codex A r3 F4, advisor): `bash bin/install-scanner.sh go [dest-dir]` -----------------------------------------------------------------
# The exact go<ver>.linux-<arch>.tar.gz of go.mod's `toolchain` line (the `go` line only when the file has no toolchain line), pinned by a committed sha256
# PER ARCHITECTURE (values checked against go.dev's published checksums), unpacked to the fixed directory <dest-dir>/fscache-go (default /usr/local/bin/fscache-go),
# refused on any mismatch. Offline: the tarball comes from a stub curl on PATH serving a local layout. The SUCCESS path needs the real tarball; the dry run proves it.
GOVER=$(sed -n 's/^GO_VER=\([0-9.]*\).*/\1/p' "$sut" | head -1)
# the installer's OWN pins are the source (Codex A r5 #3): a Go bump rewrites GO_VER and both sums in bin/install-scanner.sh, and this test then judges THAT
# bump, so no version or sum is typed here; what stays independent is go.mod (the version must equal it) and the structure of the pin
GO_AMD=$(grep -E 'go:x86_64\|go:amd64\) SUM=' "$sut" | grep -oE '[0-9a-f]{64}' | head -1)
GO_ARM=$(grep -E 'go:aarch64\|go:arm64\) SUM=' "$sut" | grep -oE '[0-9a-f]{64}' | head -1)
repo_gomod_ver=$(awk '$1 == "toolchain" {sub(/^go/, "", $2); t = $2} $1 == "go" && g == "" {g = $2} END {print (t != "" ? t : g)}' "$root/go.mod")
gwork="$work/go"; mkdir -p "$gwork/rel" "$gwork/mod-ok" "$gwork/mod-tool" "$gwork/mod-old" "$gwork/mod-none"
printf 'module x\n\ngo %s\n' "${GOVER:-0}" > "$gwork/mod-ok/go.mod"
printf 'module x\n\ngo 1.20\n\ntoolchain go%s\n' "${GOVER:-0}" > "$gwork/mod-tool/go.mod"
printf 'module x\n\ngo 0.0.1\n' > "$gwork/mod-old/go.mod"
echo "not the real go tarball" > "$gwork/rel/go${GOVER:-0}.linux-amd64.tar.gz"; echo "not the real go tarball either" > "$gwork/rel/go${GOVER:-0}.linux-arm64.tar.gz"
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
  tools_gomod_ver=$(awk '$1 == "toolchain" && $2 ~ /^go[0-9]/ {sub(/^go/, "", $2); t = $2} $1 == "go" && g == "" {g = $2} END {print (t != "" ? t : g)}' "$root/tools/requirements/go.mod")
  [ "$tools_gomod_ver" = "$repo_gomod_ver" ] || repo_gomod_ver="$repo_gomod_ver (tools/requirements/go.mod says $tools_gomod_ver)"
  if [ "$GOVER" = "$repo_gomod_ver" ] && [[ "$GO_AMD" =~ ^[0-9a-f]{64}$ ]] && [[ "$GO_ARM" =~ ^[0-9a-f]{64}$ ]] && [ "$GO_AMD" != "$GO_ARM" ]; then
    ok "go: the pinned version ($GOVER) is the repo go.mod's and the two sha256 values are 64-hex and different (go.dev's published values are checked by the bump script, which downloads and compares them)"
  else bad "go: pins: version '$GOVER' vs go.mod '$repo_gomod_ver'; amd64/arm64 values"; fi
  gocheck "go: a wrong checksum (amd64) is refused" "$gwork/mod-ok" "checksum mismatch.*PIPELINE failure" INSTALL_SCANNER_ARCH=x86_64 PATH="$stubbin:$PATH" STUB_REL="$gwork/rel"
  gocheck "go: a wrong checksum (arm64) is refused" "$gwork/mod-ok" "checksum mismatch.*PIPELINE failure" INSTALL_SCANNER_ARCH=aarch64 PATH="$stubbin:$PATH" STUB_REL="$gwork/rel"
  gocheck "go: a go.mod version that is not the pinned one is refused" "$gwork/mod-old" "go\\.mod.*(0\\.0\\.1).*pinned|pinned.*go\\.mod" INSTALL_SCANNER_ARCH=x86_64 PATH="$stubbin:$PATH" STUB_REL="$gwork/rel"
  gocheck "go: the toolchain line wins over the go line (it reaches the checksum, so the version matched)" "$gwork/mod-tool" "checksum mismatch" INSTALL_SCANNER_ARCH=x86_64 PATH="$stubbin:$PATH" STUB_REL="$gwork/rel"
  gocheck "go: the go line is used when there is no toolchain line (it reaches the checksum)" "$gwork/mod-ok" "checksum mismatch" INSTALL_SCANNER_ARCH=x86_64 PATH="$stubbin:$PATH" STUB_REL="$gwork/rel"
  gocheck "go: an unknown architecture is refused" "$gwork/mod-ok" "unsupported architecture.*PIPELINE failure" INSTALL_SCANNER_ARCH=mips PATH="$stubbin:$PATH" STUB_REL="$gwork/rel"
  gocheck "go: a failed download is refused" "$gwork/mod-ok" "download failed.*PIPELINE failure" INSTALL_SCANNER_ARCH=x86_64 PATH="$stubbin:$PATH" STUB_REL="$gwork/nope"
  gocheck "go: no go.mod is refused" "$gwork/mod-none" "go\\.mod.*PIPELINE failure|PIPELINE failure.*go\\.mod|no go\\.mod" INSTALL_SCANNER_ARCH=x86_64 PATH="$stubbin:$PATH" STUB_REL="$gwork/rel"
  [ ! -e "$gwork/bin/fscache-go" ] && ok "go: a failed install leaves no toolchain" || bad "go: a failed install left $gwork/bin/fscache-go"
  if grep -Eq 'GO_(SHA256|SUM|CHECKSUM)[^=]*[:-]|\$\{GO_(SHA256|SUM|CHECKSUM|VER|VERSION):?[-=]|GOVERSION=|GOTOOLCHAIN=auto' "$sut"; then bad "go: the script lets the environment override the checksum or the version"; else ok "go: there is no environment override of a checksum or of the version (the release URL is fixed in the script)"; fi
fi
# ---- govulncheck (advisor Oct 12, ruling G): `bash bin/install-scanner.sh govulncheck [dest-dir]` --------------------------------------------------------------
# golang/vuln publishes no release binaries (its tags carry no assets), so the tool is a Go MODULE pinned by go.sum h1 hashes in the committed module
# tools/govulncheck (go.mod + go.sum), built with the repo's pinned Go (<dest-dir>/fscache-go/bin/go, which `install-scanner.sh go` made) under
# GOTOOLCHAIN=local, CGO_ENABLED=0 and the module proxy named in the script (never one from the caller's environment); the module has no vendor/ directory, so Go's own
# default (read-only modules) applies and the build sets no GOFLAGS at all, and none of the caller's reaches it. Offline: a fake go.
gv="$work/gv"; mkdir -p "$gv/dest/fscache-go/bin" "$gv/repo/tools/govulncheck" "$gv/nogo" "$gv/repo-nosum/tools/govulncheck" "$gv/repo-nomod/tools" "$gv/repo-vendor/tools/govulncheck/vendor"
cp "$root/tools/govulncheck/go.mod" "$root/tools/govulncheck/go.sum" "$gv/repo/tools/govulncheck/" 2> /dev/null || { printf 'module x\n' > "$gv/repo/tools/govulncheck/go.mod"; printf 'x\n' > "$gv/repo/tools/govulncheck/go.sum"; }
cp "$gv/repo/tools/govulncheck/go.mod" "$gv/repo-nosum/tools/govulncheck/"
cp "$gv/repo/tools/govulncheck/go.mod" "$gv/repo/tools/govulncheck/go.sum" "$gv/repo-vendor/tools/govulncheck/"
cat > "$gv/dest/fscache-go/bin/go" <<'EOF'
#!/usr/bin/env bash
. "$(dirname "$0")/.env"      # the installer runs the build in a clean environment (env -i): the test's own settings come from this file
echo "go $* [pwd=${PWD##*/}] [GOFLAGS=${GOFLAGS:-}] [GOTOOLCHAIN=${GOTOOLCHAIN:-}] [GOPROXY=${GOPROXY:-}] [CGO_ENABLED=${CGO_ENABLED:-}] [GOWORK=${GOWORK:-}]" >> "$GV_LOG"
case "$1" in
  version) echo "go version ${GV_GOVER:-go1.27.2} linux/amd64"; exit 0 ;;
  build) [ -z "${GV_BUILD_RC:-}" ] || { echo "build failed" >&2; exit "$GV_BUILD_RC"; }
         while [ $# -gt 0 ]; do [ "$1" = -o ] && o=$2; shift; done
         printf '#!/usr/bin/env bash\n[ "$1" = -version ] && printf "Go: go1.27.2\\nScanner: govulncheck@%s\\nDB: https://vuln.go.dev\\n" "%s"\n' "${GV_REPORTS:-$GV_PIN}" "x" > "$o"; chmod +x "$o" ;;
esac
EOF
chmod +x "$gv/dest/fscache-go/bin/go"
GV_PIN=$(sed -n 's/^[[:space:]]*golang.org\/x\/vuln \(v[0-9][0-9.]*\).*/\1/p' "$root/tools/govulncheck/go.mod" 2> /dev/null | head -1)
gvins() { # gvins LABEL REPO DEST REGEX ENV...: the installer run in REPO; a failure must be a labelled pipeline failure matching REGEX
  local label=$1 repo=$2 dest=$3 re=$4; shift 4; local out rc=0 a envs=()
  : > "$work/gvlog"; { printf 'GV_LOG=%q\nGV_PIN=%q\nGV_GOVER=%q\n' "$work/gvlog" "${GV_PIN:-v0.0.0}" "go${GOVER:-0}"; for a in "$@"; do case "$a" in GV_*) printf '%s\n' "$a" ;; esac; done; } > "$gv/dest/fscache-go/bin/.env"
  for a in "$@"; do case "$a" in GV_*) ;; *) envs+=("$a") ;; esac; done
  out=$(cd "$repo" && env "${envs[@]+"${envs[@]}"}" bash "$sut" govulncheck "$dest" 2>&1) || rc=$?
  if [ "$re" = OK ]; then
    if [ "$rc" = 0 ] && [ -x "$dest/govulncheck" ]; then ok "$label"; else bad "$label: exit $rc: ${out:0:170}"; fi
  elif [ "$rc" -ne 0 ] && grep -qiE "$re" <<< "$out" && [ ! -e "$dest/govulncheck" ]; then ok "$label"; else bad "$label: exit $rc: ${out:0:170}"; fi
}
gvins "govulncheck: built from tools/govulncheck with the pinned Go, no GOFLAGS (read-only modules by default), a local toolchain and no cgo, and installed" "$gv/repo" "$gv/dest" OK
if grep -q 'build .* golang.org/x/vuln/cmd/govulncheck \[pwd=govulncheck\] \[GOFLAGS=\] \[GOTOOLCHAIN=local\] \[GOPROXY=https://proxy.golang.org\] \[CGO_ENABLED=0\]' "$work/gvlog" \
   && grep -q -- '-trimpath' "$work/gvlog"; then ok "govulncheck: the build line is go build -trimpath -o FILE golang.org/x/vuln/cmd/govulncheck in tools/govulncheck with that environment"
else bad "govulncheck: the build call is not the pinned one: $(grep '^go build' "$work/gvlog" | head -1)"; fi
rm -f "$gv/dest/govulncheck"
gvins "govulncheck: a GOFLAGS, GOTOOLCHAIN, GOPROXY, GOWORK or CGO_ENABLED of the caller's environment never reaches the build" "$gv/repo" "$gv/dest" OK \
  GOFLAGS=-mod=mod GOTOOLCHAIN=auto GOPROXY=https://evil.example GOWORK=/tmp/go.work CGO_ENABLED=1
gb=$(grep '^go build' "$work/gvlog" || true)
if grep -q 'GOFLAGS=\] \[GOTOOLCHAIN=local\] \[GOPROXY=https://proxy.golang.org\] \[CGO_ENABLED=0\] \[GOWORK=off\]' <<< "$gb"; then ok "govulncheck: the environment is fixed, workspace mode off"
else bad "govulncheck: the caller's Go environment reached the build: ${gb%%$'\n'*}"; fi
if [ ! -e "$root/tools/govulncheck/vendor" ] && ! git -C "$root" ls-files --error-unmatch tools/govulncheck/vendor > /dev/null 2>&1; then ok "govulncheck: tools/govulncheck holds no vendor/ directory, so the build with no GOFLAGS reads modules read-only (the Go default), as before"
else bad "govulncheck: tools/govulncheck/vendor exists: with no GOFLAGS the build would use it instead of the pinned go.sum"; fi
# Go's own default, proved with a real go when the machine has one: a module whose go.sum lacks an entry is refused and neither file is touched (the read-only behaviour the explicit flag used to name)
if command -v go > /dev/null 2>&1; then
  dm="$work/gomod-default"; mkdir -p "$dm"; printf 'module x\n\ngo 1.21\n\nrequire example.com/none v1.0.0\n' > "$dm/go.mod"; printf 'package main\nimport _ "example.com/none"\nfunc main() {}\n' > "$dm/m.go"
  before=$(cksum < "$dm/go.mod")
  if (cd "$dm" && env -u GOFLAGS GOPROXY=off GOTOOLCHAIN=local GOWORK=off GOENV=off GOCACHE="$work/gocache-default" GOMODCACHE="$work/gomodcache-default" go build ./... > "$work/gdlog" 2>&1); then bad "govulncheck: with no GOFLAGS Go built a module whose go.sum lacks an entry"
  elif grep -q 'missing go.sum entry' "$work/gdlog" && [ "$before" = "$(cksum < "$dm/go.mod")" ] && [ ! -e "$dm/go.sum" ]; then ok "govulncheck: with no GOFLAGS Go itself refuses a go.sum with a missing entry and leaves go.mod and go.sum alone (read-only by default)"
  else bad "govulncheck: Go's default for a missing go.sum entry is not read-only: $(head -c 160 "$work/gdlog")"; fi
else ok "govulncheck: (no go on this machine: Go's read-only default is not exercised here)"; fi
rm -f "$gv/dest/govulncheck"
gvins "govulncheck: no Go toolchain at <dest>/fscache-go is a pipeline failure and installs nothing" "$gv/repo" "$gv/nogo" "fscache-go.*PIPELINE failure|PIPELINE failure.*(go|toolchain)"
gvins "govulncheck: a toolchain that is not the pinned Go version is refused" "$gv/repo" "$gv/dest" "go.*PIPELINE failure|PIPELINE failure.*go" GV_GOVER=go1.26.0
gvins "govulncheck: a missing tools/govulncheck/go.sum is refused (the h1 hashes are the pin)" "$gv/repo-nosum" "$gv/dest" "go\\.sum.*PIPELINE failure|PIPELINE failure.*go\\.sum"
gvins "govulncheck: no tools/govulncheck module at all is refused" "$gv/repo-nomod" "$gv/dest" "tools/govulncheck.*PIPELINE failure|PIPELINE failure.*tools/govulncheck"
gvins "govulncheck: a tools/govulncheck/vendor directory is refused (vendor mode does not check contents against go.sum), and nothing is installed" "$gv/repo-vendor" "$gv/dest" "vendor.*PIPELINE failure|PIPELINE failure.*vendor"
gvins "govulncheck: a failing build is a pipeline failure and installs nothing" "$gv/repo" "$gv/dest" "build.*PIPELINE failure|PIPELINE failure.*build" GV_BUILD_RC=1
gvins "govulncheck: a built binary that reports another version than the module pins is refused" "$gv/repo" "$gv/dest" "version.*PIPELINE failure|PIPELINE failure.*version" GV_REPORTS=v9.9.9
# the pin is ONE version in two places that Dependabot moves separately (it bumps tools/govulncheck/go.mod and go.sum; the install line in ci.yml is by hand): the
# equality is a test, so a bump of either one alone is red (ruling G; the module has its own Dependabot entry)
gvpin_ok() { # gvpin_ok GOMOD GOSUM CIYML: the module pins golang.org/x/vuln at a version, go.sum holds its h1, ci.yml installs that same version, no replace/exclude
  local gm=$1 gs=$2 ci=$3 pin
  [ -f "$gm" ] && [ -f "$gs" ] && [ -f "$ci" ] || return 1
  pin=$(sed -n 's/^[[:space:]]*golang.org\/x\/vuln \(v[0-9][0-9.]*\).*/\1/p' "$gm" | head -1)
  [[ "$pin" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  # the install token must be exactly govulncheck@<pin> as a command word's argument (not a prefix of a longer version, not inside a comment)
  # the install token is taken from the executable text (full-line and inline comments dropped) and compared as a whole string with the module's pin
  local code tok; code=$(mktemp); sed -E '/^[[:space:]]*#/d; s/[[:space:]]+#.*$//' "$ci" > "$code"
  tok=$(grep -Eo 'govulncheck@[^[:space:]"'"'"';]+' "$code" | sort -u)
  rm -f "$code"
  grep -q "golang.org/x/vuln $pin h1:" "$gs" && [ "$tok" = "govulncheck@$pin" ] && ! grep -Eq '^[[:space:]]*(replace|exclude|retract)\b' "$gm"
}
if gvpin_ok "$root/tools/govulncheck/go.mod" "$root/tools/govulncheck/go.sum" "$root/.github/workflows/ci.yml"; then
  ok "govulncheck: the module pins golang.org/x/vuln $GV_PIN with an h1 hash in go.sum, the version ci.yml's govulncheck job installs, and has no replace or exclude"
else bad "govulncheck: tools/govulncheck is missing or does not pin the version ci.yml installs ($GV_PIN)"; fi
mkdir -p "$gv/eq"
sed 's/golang.org\/x\/vuln v[0-9.]*/golang.org\/x\/vuln v9.9.9/' "$root/tools/govulncheck/go.mod" > "$gv/eq/go.mod"
if ! gvpin_ok "$gv/eq/go.mod" "$root/tools/govulncheck/go.sum" "$root/.github/workflows/ci.yml"; then ok "govulncheck: a go.mod bumped without ci.yml (what Dependabot does alone) is red"
else bad "govulncheck: a bumped go.mod alone was accepted"; fi
sed 's/govulncheck@v[0-9.]*/govulncheck@v9.9.9/' "$root/.github/workflows/ci.yml" > "$gv/eq/ci.yml"
if ! gvpin_ok "$root/tools/govulncheck/go.mod" "$root/tools/govulncheck/go.sum" "$gv/eq/ci.yml"; then ok "govulncheck: a ci.yml bumped without the module is red"
else bad "govulncheck: a bumped ci.yml alone was accepted"; fi
sed "s/golang.org\/x\/vuln $GV_PIN h1:/golang.org\/x\/vuln v9.9.9 h1:/" "$root/tools/govulncheck/go.sum" > "$gv/eq/go.sum"
if ! gvpin_ok "$root/tools/govulncheck/go.mod" "$gv/eq/go.sum" "$root/.github/workflows/ci.yml"; then ok "govulncheck: a go.mod whose go.sum holds no h1 for the pin is red"
else bad "govulncheck: a go.sum without the pin's hash was accepted"; fi
# Codex 4b-5 r1 (B B5): the equality is exact: a longer version token (a prerelease suffix) and a version only inside a comment do not satisfy it
sed "s/govulncheck@$GV_PIN/govulncheck@$GV_PIN-rc1/" "$root/.github/workflows/ci.yml" > "$gv/eq/ci-suffix.yml"
if ! gvpin_ok "$root/tools/govulncheck/go.mod" "$root/tools/govulncheck/go.sum" "$gv/eq/ci-suffix.yml"; then ok "govulncheck: a ci.yml that installs $GV_PIN-rc1 while the module pins $GV_PIN is red (the version token is compared whole)"
else bad "govulncheck: a prerelease suffix on the install token was accepted"; fi
{ printf '# the pin: golang.org/x/vuln/cmd/govulncheck@%s\n' "$GV_PIN"; sed "s/govulncheck@$GV_PIN/govulncheck@v9.9.9/" "$root/.github/workflows/ci.yml"; } > "$gv/eq/ci-comment.yml"
if ! gvpin_ok "$root/tools/govulncheck/go.mod" "$root/tools/govulncheck/go.sum" "$gv/eq/ci-comment.yml"; then ok "govulncheck: the pinned version only in a comment while the install runs another is red"
else bad "govulncheck: a comment holding the version satisfied the equality"; fi
sed "s/govulncheck@$GV_PIN/govulncheck@v9.9.9 # govulncheck@$GV_PIN/" "$root/.github/workflows/ci.yml" > "$gv/eq/ci-inline.yml"
if ! gvpin_ok "$root/tools/govulncheck/go.mod" "$root/tools/govulncheck/go.sum" "$gv/eq/ci-inline.yml"; then ok "govulncheck: the pinned version only in an inline comment while the install runs another is red"
else bad "govulncheck: an inline comment holding the version satisfied the equality"; fi
sed "s/govulncheck@$GV_PIN/govulncheck@$(printf '%s' "$GV_PIN" | tr . x)/" "$root/.github/workflows/ci.yml" > "$gv/eq/ci-wild.yml"
if ! gvpin_ok "$root/tools/govulncheck/go.mod" "$root/tools/govulncheck/go.sum" "$gv/eq/ci-wild.yml"; then ok "govulncheck: a version that differs only where the pin has a dot is red (the token is compared as a string, not a pattern)"
else bad "govulncheck: a version token matching the pin as a pattern was accepted"; fi
if ! grep -Eq '\$\{(GOPROXY|GOFLAGS|GOTOOLCHAIN|GOSUMDB|GONOSUMDB|GOPRIVATE|GOWORK)' "$sut" && [ "$(grep -c 'GOPROXY=https://proxy.golang.org' "$sut")" = 1 ] && ! grep -q 'GOSUMDB=off' "$sut"; then
  ok "govulncheck: the proxy is one literal in the script, no Go environment variable is read from the caller, and the checksum database stays on"
else bad "govulncheck: the installer reads the Go environment from the caller, names another proxy or turns the checksum database off"; fi
EXPECT=44
echo "pass=$pass fail=$failn"
if [ $((pass + failn)) != "$EXPECT" ]; then echo "FAIL case count $((pass + failn)) != expected $EXPECT (a case was skipped or added)"; exit 1; fi
[ "$failn" = 0 ]
