#!/usr/bin/env bash
# Build the fscache apk with melange, sealed from the network (v0.3.0 rules 11-17, 19, 20, 23, 24, 38a, 40, 62).
#
#   build-apk.sh --variant standard|fips --arch x86_64|aarch64 --version X.Y.Z|X.Y.Z-rcN|0.0.0-rc.1 --source-dir DIR --repo DIR --keyring FILE
#                --go-archive DIR --melange-lock FILE --out DIR [--recipe FILE (test mode only)] [--render-dir DIR] [--apk-cache-dir DIR]
#   build-apk.sh --print-source-date-epoch --source-dir DIR     (prints the commit time of DIR's HEAD, for SOURCE_DATE_EPOCH)
#
# Run it from the repository root: it names its helpers (bin/apk-tool.py, bin/go-module-sbom.py, bin/net-probe.py,
# bin/build-apk-helper.py) by literal repo-relative paths and refuses (exit 2) anywhere else.
#
# Environment: SOURCE_DATE_EPOCH (digits) is required. Refused: APK_RELEASE_SIGNING_KEY defined (a build never holds the release
# key), GOPROXY other than off, HTTP(S)_PROXY / ALL_PROXY defined. There is no --signing-key: the apk is signed with the committed,
# non-secret assembly key build/keys/assembly.rsa (rule 22) and nothing else.
#
# What it does, in this order (the tests fix the order):
#   1. refuses anything off-spec before any tool runs (exit 2, the message names the thing);
#   2. renders the recipe (build/melange.yaml, or build/melange-fips.yaml for --variant fips) with @VERSION@ replaced;
#   3. pre-seeds the Go tarball from the archive into melange's cache dir as sha256:<hex> after checking its sha256 against
#      the recipe's pin (rule 12), so the recipe's go.dev fetch step finds it offline;
#   4. sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 (rule 62: Ubuntu runners), then
#      sudo env SOURCE_DATE_EPOCH=.. unshare -n melange build ... --runner bubblewrap: melange runs directly on the VM with the
#      network cut at the kernel (rule 38a); sudo's own environment reset keeps every token and key out of the build;
#   5. checks the apk: signed by assembly.rsa.pub, the binary's go version -m is not (devel) and not modified, GOFIPS140=
#      the module build/locks/fips-module.txt names (v1.0.0-c2097c7c today) is recorded exactly in the fips variant (rules 13, 24);
#   6. writes OUT/<arch>/<pkg>-<version>-r0.apk (+ APKINDEX.tar.gz, from melange), OUT/fscache-modules.spdx.json (rule 20,
#      bin/go-module-sbom.py) and OUT/inputs-manifest.json (rule 15, bin/apk-tool.py); the fips variant writes
#      OUT/fscache-modules-fips.spdx.json and OUT/inputs-manifest-fips.json (the chain builds both variants into one OUT).
#
# Exit codes (a failure that shows ENETUNREACH, "network is unreachable", dial tcp, no such host or a name-resolution failure is a network
# attempt): 0 ok | 1 the build or a post-build check failed | 2 refused (the message names the reason; no tool was run)
#             | 4 a network attempt was made inside the sealed melange call (rule 40: melange failed, its output shows a
#               network error, AND bin/net-probe.py run in the same kind of namespace exits 101 = ENETUNREACH). If the probe
#               says the namespace is not sealed the exit is 1, not 4.
set -euo pipefail

die() { echo "build-apk.sh: $1" >&2; exit "${2:-2}"; }

# ---- fixed locations (REQ-BUILDAPK-001-AC3): a production call never resolves python3, git, sudo, unshare or melange through the caller's search path,
# and there is no test hook in this file: bin/build-apk-test.sh runs a COPY in which exactly the lines ending in TEST-SUBST are replaced, and
# checks that the copy differs from this file in no other line.
PY3=/usr/bin/python3            # TEST-SUBST
GIT=/usr/bin/git                # TEST-SUBST
SUDO=/usr/bin/sudo              # TEST-SUBST
UNSHARE=/usr/bin/unshare        # TEST-SUBST
MELANGE=/usr/local/bin/melange  # TEST-SUBST (the chain installs it there)
GO_TOOL=/usr/local/bin/fscache-go/bin/go  # TEST-SUBST (bin/install-scanner.sh go puts the pinned toolchain there)
SHA256SUM=/usr/bin/sha256sum    # TEST-SUBST
ENVBIN=/usr/bin/env             # TEST-SUBST
SEALED_ENV=build/sealed-env.json  # TEST-SUBST
RECIPE_STANDARD=$PWD/build/melange.yaml  # TEST-SUBST
RECIPE_FIPS=$PWD/build/melange-fips.yaml  # TEST-SUBST
FIPS_MODULE=$PWD/build/locks/fips-module.txt  # TEST-SUBST (the module the FIPS build uses; the daily refresh rewrites this one file)

[ -f bin/build-apk.sh ] && [ -f bin/build-apk-helper.py ] && [ -f build/sealed-env.json ] || die "run bin/build-apk.sh from the repository root (its helpers are named by repo-relative paths)" 2

[ "$(uname -s)" = Linux ] || die "refusing to run on $(uname -s): this script uses sudo, unshare and the sealed build tools, which run on Linux only (inside a Linux container or on a GitHub runner), never on the Mac itself" 2

variant= arch= version= src= repo= keyring= goarch_dir= mlock= out= recipe= render= apkcache= print_sde=0 repo_set=0
while [ $# -gt 0 ]; do
  need() { [ $# -ge 2 ] || die "missing value for $1"; }
  case $1 in
    --variant) need "$@"; variant=$2; shift 2;;
    --arch) need "$@"; arch=$2; shift 2;;
    --version) need "$@"; version=$2; shift 2;;
    --source-dir) need "$@"; src=$2; shift 2;;
    --repo) need "$@"; repo=$2; repo_set=1; shift 2;;
    --keyring) need "$@"; keyring=$2; shift 2;;
    --go-archive) need "$@"; goarch_dir=$2; shift 2;;
    --melange-lock) need "$@"; mlock=$2; shift 2;;
    --out) need "$@"; out=$2; shift 2;;
    --render-dir) need "$@"; render=$2; shift 2;;
    --apk-cache-dir) need "$@"; apkcache=$2; shift 2;;
    --print-source-date-epoch) print_sde=1; shift;;
    --signing-key) die "--signing-key is not accepted: the apk is signed with the committed assembly key only";;
    *) die "unknown argument: $1";;
  esac
done

[ -n "$src" ] || die "--source-dir is required"
if [ "$print_sde" = 1 ]; then
  [ -e "$src/.git" ] || die "$src has no .git; there is no commit time to print"
  "$GIT" -C "$src" log -1 --format=%ct 2>/dev/null | grep -E '^[0-9]+$' || die "$src has no git history"
  exit 0
fi

# ---- 1. refusals ----
[ "$(uname -s)" = Linux ] || die "build-apk.sh runs on Linux only (melange's bubblewrap runner and unshare -n)"
case $variant in standard|fips) ;; *) die "--variant must be standard or fips";; esac
case $arch in x86_64|aarch64) ;; *) die "--arch must be an apk architecture name: x86_64 or aarch64 (not '$arch')";; esac
um=$(uname -m)
case $um in x86_64|amd64) host=x86_64;; aarch64|arm64) host=aarch64;; *) host=$um;; esac
[ "$arch" = "$host" ] || die "refusing to build $arch on a $host host: each architecture builds natively on its own runner, no emulation"
# exactly the chain's grammar (the tag minus its v): X.Y.Z, X.Y.Z-rcN (N digits, no leading zero, no dot) and the one fixed snapshot version
# 0.0.0-rc.1 (REQ-CHAIN-004-AC12); anything else is refused before any tool runs
[[ $version =~ ^(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)(-rc[1-9][0-9]*)?$ || $version == 0.0.0-rc.1 ]] || die "--version must be X.Y.Z, X.Y.Z-rcN or the snapshot version 0.0.0-rc.1 (numbers without leading zeros; not '$version')"
apkver=${version/-rc./_rc}; apkver=${apkver/-rc/_rc}   # the apk version syntax for a pre-release: 0.3.0-rc1 -> 0.3.0_rc1, 0.0.0-rc.1 -> 0.0.0_rc1; the Go stamp says v$version

[[ ${SOURCE_DATE_EPOCH:-} =~ ^[0-9]{1,12}$ ]] || die "SOURCE_DATE_EPOCH must hold digits (the commit time, at most 12 digits)"
build_date=$("$PY3" -I -B bin/build-apk-helper.py build-date "$SOURCE_DATE_EPOCH" 2>/dev/null) || die "SOURCE_DATE_EPOCH $SOURCE_DATE_EPOCH is not a date"
[ -z "${APK_RELEASE_SIGNING_KEY:-}" ] || die "the release signing key must not be in a build's environment (APK_RELEASE_SIGNING_KEY is defined)"
if [ -n "${GOPROXY+x}" ] && [ "${GOPROXY}" != off ]; then die "GOPROXY must be off or unset (its value is not printed: it can carry a credential)"; fi
for p in HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy; do
  [ -z "${!p:-}" ] || die "a proxy is defined in the environment ($p); the sealed build has no network"
done
[ "$repo_set" = 1 ] || die "--repo DIR (the local package repository melange installs the build tools from) is required; a cache alone is not an input"
case $repo in *://*) die "--repo must be a local directory, not an address ($repo)";; esac
[ -d "$repo" ] || die "--repo $repo is not a directory"
[ -n "$keyring" ] && [ -f "$keyring" ] || die "--keyring file not found: $keyring"
[ -n "$goarch_dir" ] || die "--go-archive DIR is required"
[ -n "$mlock" ] && [ -f "$mlock" ] || die "--melange-lock file not found: $mlock"
[ -n "$out" ] || die "--out DIR is required"
[ -d "$src/vendor" ] || die "$src/vendor is missing: the build uses only vendored Go code"
[ -e "$src/.git" ] || die "$src has no .git: the binary's stamp would say (devel)"
assembly_key=$PWD/build/keys/assembly.rsa
[ -f "$assembly_key" ] || die "the committed assembly key $assembly_key is missing"
if [ "$variant" = fips ]; then recipe=$RECIPE_FIPS; else recipe=$RECIPE_STANDARD; fi
[ -f "$recipe" ] || die "recipe not found: $recipe"

absd() { (cd "$1" 2>/dev/null && pwd) || echo "$1"; }
absf() { echo "$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"; }
src=$(absd "$src"); repo=$(absd "$repo"); goarch_dir=$(absd "$goarch_dir"); keyring=$(absf "$keyring"); mlock=$(absf "$mlock"); recipe=$(absf "$recipe")
mkdir -p "$out"; out=$(absd "$out"); [ -z "$apkcache" ] || apkcache=$(absd "$apkcache")
if [ -n "$render" ]; then mkdir -p "$render"; render=$(absd "$render"); fi

tmp=$(mktemp -d)
cleanup() { local rc=$?; set +e; rm -rf "$tmp" 2>/dev/null || "$SUDO" rm -rf "$tmp" >/dev/null 2>&1; exit $rc; }   # cleanup never changes the exit status
trap cleanup EXIT

goarch=amd64; [ "$arch" = aarch64 ] && goarch=arm64
# recipe facts: the package name, this arch's Go tarball and pin, and the pinned build environment
"$PY3" -I -B bin/build-apk-helper.py recipe-facts "$recipe" "$goarch" "$tmp/recipe.facts" || die "cannot read the recipe $recipe"
pkg=$(sed -n 's/^name=//p' "$tmp/recipe.facts"); gofile=$(sed -n 's/^file=//p' "$tmp/recipe.facts"); gosha=$(sed -n 's/^sha=//p' "$tmp/recipe.facts")

[ -f "$goarch_dir/$gofile" ] || die "the Go archive $goarch_dir has no $gofile (rule 12: Go comes from the archive)"
[ -x "$SHA256SUM" ] || die "sha256sum is not installed at $SHA256SUM" 1
got=$("$SHA256SUM" "$goarch_dir/$gofile" | cut -d' ' -f1)
[ "$got" = "$gosha" ] || die "sha256 checksum of $gofile ($got) differs from the recipe's pin ($gosha)"

# the recipe's pinned build environment must be in the melange lock (rule 15), name for name and version for version
sed -n 's/^pin=//p' "$tmp/recipe.facts" >"$tmp/pins"
missing=$(grep -Fxv -f "$mlock" "$tmp/pins" | head -n 1 || true)
[ -z "$missing" ] || die "the recipe pins $missing but the melange lock $mlock does not have it; the recipe and the lock must agree"
# ...and the other way round: a lock line the recipe does not pin would be recorded as an input of the build without being one
extra=$(grep -v '^$' "$mlock" | grep -Fxv -f "$tmp/pins" || true)
[ -z "$extra" ] || die "the melange lock $mlock has lines the recipe does not pin ($(printf '%s' "$extra" | head -n 3 | tr '\n' ' ')): the recipe and the lock must agree both ways"

# ---- 2. render ----
rdir=${render:-$tmp/render}; mkdir -p "$rdir"
rendered=$rdir/$(basename "$recipe")
sed "s/@VERSION@/$apkver/g" "$recipe" >"$rendered"

# ---- 3. pre-seed Go ----
mkdir -p "$tmp/cache"; cp "$goarch_dir/$gofile" "$tmp/cache/sha256:$gosha"

mkdir -p "$out"

# ---- 4. the sealed call ----
# tree-exclude begin
# The job's own directories and files are untracked in the checkout melange copies, and Go stamps vcs.modified=true for any untracked file: archive/,
# host-tools/, out/ and witness-apk/ and admission.json (Build), build-in/, witness-build/, witness-rapk/ and policy.json (Rebuild: its downloaded inputs,
# the witness-<step> directory and the policy it writes). These nine paths, anchored at the root, go into the exclude file of the checkout (never committed).
# Every other untracked or modified file still makes the tree dirty, and the dirty-tree checks below and in both recipes are unchanged.
excl=$("$GIT" -C "$src" rev-parse --path-format=absolute --git-path info/exclude 2>/dev/null) || die "cannot locate the exclude file of $src (git rev-parse failed)" 1
exdir=${excl%/*}
mkdir -p "$exdir" 2>/dev/null || true   # a checkout made with an empty template has no info/ directory; if it cannot be made the test below says so
[ -d "$exdir" ] && [ ! -d "$excl" ] || die "the exclude file $excl cannot be used: its directory $exdir is not a directory, or the exclude path itself is a directory" 1
lines=()
[ ! -f "$excl" ] || mapfile -t lines <"$excl"
first=1
for p in /archive/ /host-tools/ /out/ /witness-apk/ /admission.json /build-in/ /witness-build/ /witness-rapk/ /policy.json; do
  seen=0
  for line in "${lines[@]}"; do [ "$line" != "$p" ] || seen=1; done
  if [ "$seen" = 0 ]; then
    [ "$first" = 0 ] || echo >>"$excl"   # a final line with no newline would swallow the pattern
    first=0
    echo "$p" >>"$excl"
  fi
done
# tree-exclude end
margs=(build "$(basename "$rendered")" --arch "$arch" --runner bubblewrap --signing-key "$assembly_key"
  --keyring-append "$keyring" --repository-append "$repo" --build-date "$build_date"
  --cache-dir "$tmp/cache" --source-dir "$src" --out-dir "$out")
[ -z "$apkcache" ] || margs+=(--apk-cache-dir "$apkcache")
melange_bin=$MELANGE; [ -x "$melange_bin" ] || die "melange is not installed (the chain installs it before this step)" 1
# the recipe is passed as a bare file name with the render dir as the working directory: melange records the path as typed in the
# apk's own SBOM, and a random temp path there would make two builds of the same inputs differ (real-run finding). Only this one call
# runs in the render dir (a subshell): everything else runs from the repository root.
# the environment of the privileged melange call is passed EXPLICITLY as a closed list (never whatever sudo's env_reset happens to keep):
# the committed build/sealed-env.json, printed by the helper as NUL-ended items; nothing else survives
sealed=()
while read -r -d '' item; do sealed+=("$item"); done < <("$PY3" -I -B bin/build-apk-helper.py sealed-env "$SEALED_ENV") || true
[ "${#sealed[@]}" -ge 4 ] || die "the sealed environment could not be made (build/sealed-env.json, SOURCE_DATE_EPOCH)" 1
# the call is built ONCE and the pinned helper judges that same array before it runs (sandboxed-build rule 2): a call without the bubblewrap runner, without the cut network
# namespace or with a loose environment stops the stage here, before sysctl, before melange, before anything is produced
call=("$ENVBIN" -i "${sealed[@]}" "$UNSHARE" -n "$melange_bin" "${margs[@]}")
why=$("$PY3" -I -B bin/build-apk-helper.py sealed-call "${call[@]}" 2>&1) || die "refusing the melange call: $why"
"$SUDO" sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 >/dev/null 2>&1 || echo "build-apk.sh: warning: could not relax kernel.apparmor_restrict_unprivileged_userns (not needed off Ubuntu 24.04)" >&2
set +e
( cd "$rdir" && "$SUDO" "${call[@]}" 2>"$tmp/melange.err" )
rc=$?
set -e
cat "$tmp/melange.err" >&2   # complete once the command has exited; no race with a process substitution
if [ $rc -ne 0 ]; then
  if grep -Eqi 'ENETUNREACH|network is unreachable|dial tcp|no such host|name resolution|Name or service not known|could not resolve host' "$tmp/melange.err" 2>/dev/null; then
    set +e; "$SUDO" "$UNSHARE" -n "$PY3" -I -B bin/net-probe.py >/dev/null 2>&1; probe=$?; set -e
    if [ "$probe" = 101 ]; then die "a network attempt was made inside the sealed melange call (the probe confirms the namespace has no route); the build must use only declared inputs" 4; fi
    die "melange failed with a network error, but the probe says the namespace is not sealed (exit $probe); fix the seal first" 1
  fi
  die "melange build failed (exit $rc)" 1
fi

# ---- 5. checks on the apk ----
apk=$out/$arch/$pkg-$apkver-r0.apk
vsfx=; [ "$variant" = fips ] && vsfx=-fips   # standard and fips build into ONE --out: the fips files must not overwrite the standard ones
[ -f "$apk" ] || die "melange did not produce $apk" 1
signer=$("$PY3" -I -B bin/apk-tool.py signer "$apk") || die "cannot read the signer of $apk" 1
[ "$signer" = assembly.rsa.pub ] || die "$apk is signed by '$signer', not assembly.rsa.pub: the assembly key is the only build signer" 1
# the name is only a label: the signature itself must verify against the committed public half of the assembly key (REQ-BUILDAPK-001-AC4)
"$PY3" -I -B bin/apk-tool.py verify "$apk" build/keys/assembly.rsa.pub >/dev/null || die "the signature of $apk does not verify against the committed build/keys/assembly.rsa.pub: the apk is not signed with the assembly key" 1
"$PY3" -I -B bin/apk-tool.py cat "$apk" usr/share/fscache/buildinfo.txt >"$tmp/buildinfo.txt" || die "$apk has no usr/share/fscache/buildinfo.txt" 1
grep -Fq '(devel)' "$tmp/buildinfo.txt" && die "the binary says (devel): the source was not stamped" 1
grep -Eq 'vcs\.modified=true' "$tmp/buildinfo.txt" && die "the binary was built from a modified (dirty) tree (vcs.modified=true)" 1
# rule 24: the main module must carry exactly the version being built (a tag v$version in the workspace), and the revision must be the
# source's HEAD: a pseudo-version, another tag, or a revision from somewhere else is refused
mainver=$(awk -F'\t' '$2=="mod"{print $4; exit}' "$tmp/buildinfo.txt")
[ "$mainver" = "v$version" ] || die "the binary's main module version is '${mainver:-none}', not v$version: the build is not stamped with the version being built (a tag at the source HEAD is needed)" 1
binrev=$(awk -F'\t' '$2=="build" && $3 ~ /^vcs\.revision=/ {sub(/^vcs\.revision=/,"",$3); print $3; exit}' "$tmp/buildinfo.txt")
headrev=$("$GIT" -C "$src" rev-parse HEAD 2>/dev/null) || die "cannot read the source HEAD of $src" 1
[ -n "$binrev" ] && [ "$binrev" = "$headrev" ] || die "the binary's vcs.revision is '${binrev:-none}', not the source HEAD $headrev: the binary is not tied to this source" 1
fipsvals=$(awk -F'\t' '$2=="build" && $3 ~ /^GOFIPS140=/{print $3}' "$tmp/buildinfo.txt")
if [ "$variant" = fips ]; then
  # REQ-BUILDAPK-001-AC4: the module is the one build/locks/fips-module.txt names, read with the grammar the daily refresh reads it with (one line
  # vMAJOR.MINOR.PATCH-<8 lower-case hex>, a plain newline, plain ASCII; a missing file, a symlink or anything else is refused, never guessed)
  [ -f "$FIPS_MODULE" ] && [ ! -L "$FIPS_MODULE" ] || die "build/locks/fips-module.txt is missing, not a regular file or a symlink: the module the fips binary must record is unknown" 1
  fipswant=$("$PY3" -I -B bin/build-apk-helper.py fips-module "$FIPS_MODULE") || die "build/locks/fips-module.txt must hold exactly one line vMAJOR.MINOR.PATCH-<8 hex> and a plain newline; refusing" 1
  [ "$fipsvals" = "$fipswant" ] || die "the fips binary must record exactly one $fipswant (the module build/locks/fips-module.txt names) and nothing else (found: ${fipsvals:-none})" 1
else
  [ -z "$fipsvals" ] || die "the standard binary records GOFIPS140 ($fipsvals); only the fips variant may" 1
fi
# buildinfo.txt is written by the recipe; when a Go toolchain is found it is checked against the packaged binary itself (the toolchain line and the module list)
"$PY3" -I -B bin/apk-tool.py cat "$apk" usr/bin/fscache >"$tmp/fscache.bin" || die "$apk has no usr/bin/fscache" 1
gorc=0; gov=
if [ -x "$GO_TOOL" ]; then gov=$("$ENVBIN" GOTOOLCHAIN=local GOFLAGS= GOENV=off "$GO_TOOL" version -m "$tmp/fscache.bin" 2>"$tmp/go.err") || gorc=$?; else gorc=127; fi
if [ $gorc -eq 0 ]; then
  [ "$(printf '%s\n' "$gov" | head -n 1 | sed 's/^[^:]*: //')" = "$(head -n 1 "$tmp/buildinfo.txt" | sed 's/^[^:]*: //')" ] || die "the Go toolchain in buildinfo.txt ($(head -n 1 "$tmp/buildinfo.txt" | sed 's/^[^:]*: //')) differs from the one go version -m reports for the packaged binary ($(printf '%s\n' "$gov" | head -n 1 | sed 's/^[^:]*: //'))" 1
  [ "$(printf '%s\n' "$gov" | tail -n +2)" = "$(tail -n +2 "$tmp/buildinfo.txt")" ] || die "buildinfo.txt in the apk differs from 'go version -m' of the packaged binary: the recorded build information is not the binary's own" 1
elif [ $gorc -eq 127 ] && [ -n "${GITHUB_ACTIONS:-}" ]; then
  die "no Go toolchain on PATH in CI: the buildinfo.txt cross-check against the packaged binary cannot be skipped there; the runner must have Go (put it on the search path)" 1
elif [ $gorc -eq 127 ]; then
  echo "build-apk.sh: note: buildinfo.txt not verified against the binary (no Go toolchain found); the check is skipped" >&2
else
  die "'go version -m' failed on the packaged binary (exit $gorc: $(head -c 120 "$tmp/go.err")); the build information cannot be checked, refusing" 1
fi

# ---- 6. the module SBOM and the inputs manifest ----
"$PY3" -I -B bin/go-module-sbom.py --modules "$src/vendor/modules.txt" --provenance "$src/dependency-provenance.json" \
  --buildinfo "$tmp/buildinfo.txt" --out "$out/fscache-modules$vsfx.spdx.json" || die "the Go module list does not match the binary (see above)" 1
"$PY3" -I -B bin/apk-tool.py inputs-manifest --apk "$apk" --melange-lock "$mlock" --out "$out/inputs-manifest$vsfx.json" || die "the inputs manifest could not be made (see above)" 1
echo "built $apk"
