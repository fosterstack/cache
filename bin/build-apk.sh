#!/usr/bin/env bash
# Build the fscache apk with melange, sealed from the network (v0.3.0 rules 11-17, 19, 20, 23, 24, 38a, 40, 62).
#
#   build-apk.sh --variant standard|fips --arch x86_64|aarch64 --version X.Y.Z|X.Y.Z-rcN|0.0.0-rc.1 --source-dir DIR
#                --repo DIR --keyring FILE --go-archive DIR --melange-lock FILE --out DIR
#                [--render-dir DIR] [--apk-cache-dir DIR]
#   build-apk.sh --print-source-date-epoch --source-dir DIR
#                (prints the commit time of DIR's HEAD, for SOURCE_DATE_EPOCH)
#
# This file is straight-line text: no case, loop, function or subshell. Every decision (the options, the refusals,
# the checks of the apk) is a subcommand of bin/build-apk-helper.py, which prints the refusal and sets the exit status.
# Run it from the repository root: it names its helpers (bin/apk-tool.py, bin/go-module-sbom.py, bin/net-probe.py,
# bin/build-apk-helper.py) by literal repo-relative paths and refuses (exit 2) anywhere else.
#
# Environment: SOURCE_DATE_EPOCH (digits) is required. Refused: APK_RELEASE_SIGNING_KEY defined (a build never holds
# the release key), GOPROXY other than off, HTTP(S)_PROXY / ALL_PROXY defined. There is no --signing-key: the apk is
# signed with the committed, non-secret assembly key build/keys/assembly.rsa (rule 22) and nothing else.
#
# In this order (the tests fix it):
#   1. refusals, before any tool runs (exit 2, the message names the thing);
#   2. render the recipe (build/melange.yaml, or build/melange-fips.yaml for --variant fips) with @VERSION@ replaced;
#   3. pre-seed the Go tarball from the archive into melange's cache dir as sha256:<hex>, after checking its sha256
#      against the recipe's pin (rule 12), so the recipe's go.dev fetch step finds it offline;
#   4. sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 (rule 62: Ubuntu runners), then
#      sudo env -i <sealed items> unshare -n melange build ... --runner bubblewrap: melange runs directly on the VM with
#      the network cut at the kernel (rule 38a) and with exactly the environment of build/sealed-env.json;
#   5. checks of the apk: signed by assembly.rsa.pub, the binary's go version -m is not (devel) and not modified, and
#      GOFIPS140= is the module build/locks/fips-module.txt names, recorded exactly in the fips variant (rules 13, 24);
#   6. writes OUT/<arch>/<pkg>-<version>-r0.apk (+ APKINDEX.tar.gz, from melange), OUT/fscache-modules.spdx.json
#      (rule 20, bin/go-module-sbom.py) and OUT/inputs-manifest.json (rule 15, bin/apk-tool.py); the fips variant
#      writes OUT/fscache-modules-fips.spdx.json and OUT/inputs-manifest-fips.json (both variants share one OUT).
#
# Exit codes: 0 ok | 1 the build or a post-build check failed
#   | 2 refused (the message names the reason; no tool was run)
#   | 4 a network attempt was made inside the sealed melange call (rule 40: melange failed, its output shows a network
#     error, AND bin/net-probe.py run in the same kind of namespace exits 101 = ENETUNREACH). If the probe says the
#     namespace is not sealed the exit is 1, not 4.
set -euo pipefail

# Fixed locations (REQ-BUILDAPK-001-AC3): a production call never resolves python3, git, sudo, unshare or melange
# through the caller's search path. There is no test hook in this file: bin/build-apk-test.sh runs a COPY in which
# exactly the lines ending in TEST-SUBST are replaced, and checks that the copy differs from this file in no other line.
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
FIPS_MODULE=$PWD/build/locks/fips-module.txt  # TEST-SUBST (the module the FIPS build uses; the daily refresh sets it)

[ -f bin/build-apk.sh ] && [ -f bin/build-apk-helper.py ] && [ -f build/sealed-env.json ] \
  || { echo "build-apk.sh: run bin/build-apk.sh from the repository root" \
    "(its helpers are named by repo-relative paths)" >&2; exit 2; }
root_=$PWD

# ---- 1. refusals ----
mode=$("$PY3" -I -B bin/build-apk-helper.py check-args "$(uname -s)" "$(uname -m)" "$@")
src=$("$PY3" -I -B bin/build-apk-helper.py arg src "$@")
# accepts: the digits of a commit time, nothing else
[ "$mode" != sde ] || "$GIT" -C "$src" log -1 --format=%ct 2>/dev/null | grep -E '^[0-9]+$' \
  || { echo "build-apk.sh: $src has no git history" >&2; exit 2; }
[ "$mode" != sde ] || exit 0
variant=$("$PY3" -I -B bin/build-apk-helper.py arg variant "$@")
arch=$("$PY3" -I -B bin/build-apk-helper.py arg arch "$@")
goarch=$("$PY3" -I -B bin/build-apk-helper.py arg goarch "$@")
version=$("$PY3" -I -B bin/build-apk-helper.py arg version "$@")
apkver=$("$PY3" -I -B bin/build-apk-helper.py arg apkver "$@")
build_date=$("$PY3" -I -B bin/build-apk-helper.py arg build-date "$@")
repo=$("$PY3" -I -B bin/build-apk-helper.py arg repo "$@")
keyring=$("$PY3" -I -B bin/build-apk-helper.py arg keyring "$@")
goarch_dir=$("$PY3" -I -B bin/build-apk-helper.py arg go-archive "$@")
mlock=$("$PY3" -I -B bin/build-apk-helper.py arg melange-lock "$@")
out=$("$PY3" -I -B bin/build-apk-helper.py arg out "$@")
render=$("$PY3" -I -B bin/build-apk-helper.py arg render-dir "$@")
apkcache=$("$PY3" -I -B bin/build-apk-helper.py arg apk-cache-dir "$@")
assembly_key=$PWD/build/keys/assembly.rsa
[ -f "$assembly_key" ] \
  || { echo "build-apk.sh: the committed assembly key $assembly_key is missing" >&2; exit 2; }
if [ "$variant" = fips ]; then recipe=$RECIPE_FIPS; else recipe=$RECIPE_STANDARD; fi
[ -f "$recipe" ] || { echo "build-apk.sh: recipe not found: $recipe" >&2; exit 2; }
recipe=$("$PY3" -I -B bin/build-apk-helper.py abs-file "$recipe")
mkdir -p "$out"
[ -z "$render" ] || mkdir -p "$render"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp" 2>/dev/null || "$SUDO" rm -rf "$tmp" >/dev/null 2>&1 || true' EXIT

# recipe facts: the package name, this arch's Go tarball and pin, and the pinned build environment
"$PY3" -I -B bin/build-apk-helper.py recipe-facts "$recipe" "$goarch" "$tmp/recipe.facts" \
  || { echo "build-apk.sh: cannot read the recipe $recipe" >&2; exit 2; }
pkg=$(sed -n 's/^name=//p' "$tmp/recipe.facts")
gofile=$(sed -n 's/^file=//p' "$tmp/recipe.facts")
gosha=$(sed -n 's/^sha=//p' "$tmp/recipe.facts")

[ -f "$goarch_dir/$gofile" ] \
  || { echo "build-apk.sh: the Go archive $goarch_dir has no $gofile" \
    "(rule 12: Go comes from the archive)" >&2; exit 2; }
[ -x "$SHA256SUM" ] || { echo "build-apk.sh: sha256sum is not installed at $SHA256SUM" >&2; exit 1; }
got=$("$SHA256SUM" "$goarch_dir/$gofile" | cut -d' ' -f1)
[ "$got" = "$gosha" ] \
  || { echo "build-apk.sh: sha256 checksum of $gofile ($got) differs from the recipe's pin ($gosha)" >&2; exit 2; }

# the recipe's pinned build environment must be in the melange lock (rule 15), name for name and version for version
sed -n 's/^pin=//p' "$tmp/recipe.facts" >"$tmp/pins"
missing=$(grep -Fxv -f "$mlock" "$tmp/pins" | head -n 1 || true)
[ -z "$missing" ] || { echo "build-apk.sh: the recipe pins $missing but the melange lock $mlock does not have it;" \
  "the recipe and the lock must agree" >&2; exit 2; }
# ...and the other way round: a lock line the recipe does not pin would be recorded as an input without being one
extra=$(grep -v '^$' "$mlock" | grep -Fxv -f "$tmp/pins" || true)
[ -z "$extra" ] || { echo "build-apk.sh: the melange lock $mlock has lines the recipe does not pin" \
  "($(printf '%s' "$extra" | head -n 3 | tr '\n' ' ')): the recipe and the lock must agree both ways" >&2; exit 2; }

# ---- 2. render ----
rdir=${render:-$tmp/render}; mkdir -p "$rdir"
rendered=$rdir/$(basename "$recipe")
sed "s/@VERSION@/$apkver/g" "$recipe" >"$rendered"

# ---- 3. pre-seed Go ----
mkdir -p "$tmp/cache"; cp "$goarch_dir/$gofile" "$tmp/cache/sha256:$gosha"

# ---- 4. the sealed call ----
# tree-exclude begin
# The job's own directories and files are untracked in the checkout melange copies, and Go stamps vcs.modified=true for
# any untracked file. The helper adds nine paths, anchored at the root, to the exclude file of the checkout (never
# committed): archive/, host-tools/, out/, witness-apk/, admission.json, build-in/, witness-build/, witness-rapk/ and
# policy.json. Every other untracked or modified file still makes the tree dirty, and the dirty-tree checks below stay.
excl=$("$GIT" -C "$src" rev-parse --path-format=absolute --git-path info/exclude 2>/dev/null) \
  || { echo "build-apk.sh: cannot locate the exclude file of $src (git rev-parse failed)" >&2; exit 1; }
exdir=${excl%/*}
mkdir -p "$exdir" 2>/dev/null || true   # a checkout made with an empty template has no info/ directory
"$PY3" -I -B bin/build-apk-helper.py exclude-file "$excl" "$exdir"
# tree-exclude end
margs=(build "$(basename "$rendered")" --arch "$arch" --runner bubblewrap --signing-key "$assembly_key"
  --keyring-append "$keyring" --repository-append "$repo" --build-date "$build_date"
  --cache-dir "$tmp/cache" --source-dir "$src" --out-dir "$out")
[ -z "$apkcache" ] || margs+=(--apk-cache-dir "$apkcache")
melange_bin=$MELANGE; [ -x "$melange_bin" ] \
  || { echo "build-apk.sh: melange is not installed (the chain installs it before this step)" >&2; exit 1; }
# The environment of the privileged melange call is a closed list: the committed build/sealed-env.json, printed by the
# helper as NUL-ended items; nothing else survives.
mapfile -d '' -t sealed < <("$PY3" -I -B bin/build-apk-helper.py sealed-env "$SEALED_ENV")
[ "${#sealed[@]}" -ge 4 ] \
  || { echo "build-apk.sh: the sealed environment could not be made" \
    "(build/sealed-env.json, SOURCE_DATE_EPOCH)" >&2; exit 1; }
# The call is built ONCE and the pinned helper judges that same array before it runs (sandboxed-build rule 2): a call
# without the bubblewrap runner, without the cut network namespace or with a loose environment stops here.
call=("$ENVBIN" -i "${sealed[@]}" "$UNSHARE" -n "$melange_bin" "${margs[@]}")
why=$("$PY3" -I -B bin/build-apk-helper.py sealed-call --sealed-env "$SEALED_ENV" "${call[@]}" 2>&1) \
  || { echo "build-apk.sh: refusing the melange call: $why" >&2; exit 2; }
"$SUDO" sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 >/dev/null 2>&1 ||
  echo "build-apk.sh: warning: could not relax kernel.apparmor_restrict_unprivileged_userns" \
    "(not needed off Ubuntu 24.04)" >&2
# The recipe is passed as a bare file name with the render dir as the working directory: melange records the path as
# typed in the apk's own SBOM, and a random temp path there would make two builds of the same inputs differ.
cd "$rdir"
"$SUDO" "${call[@]}" 2>"$tmp/melange.err" && rc=0 || rc=$?
cd "$root_"
cat "$tmp/melange.err" >&2
# a failed call whose output shows a network error is checked with the probe (rule 40)
probe=
# accepts: any of the phrases a failed network attempt prints (unreachable, dial tcp, no such host, name resolution)
[ "$rc" != 0 ] && grep -Eqi -e 'ENETUNREACH|network is unreachable|dial tcp|no such host|name resolution' \
  -e 'Name or service not known|could not resolve host' "$tmp/melange.err" 2>/dev/null && probe=0 || probe=
[ -z "$probe" ] || "$SUDO" "$UNSHARE" -n "$PY3" -I -B bin/net-probe.py >/dev/null 2>&1 || probe=$?
"$PY3" -I -B bin/build-apk-helper.py melange-verdict "$rc" "$probe"

# ---- 5. checks on the apk ----
apk=$out/$arch/$pkg-$apkver-r0.apk
vsfx=; [ "$variant" = fips ] && vsfx=-fips   # standard and fips build into ONE --out: the fips files must not overwrite
[ -f "$apk" ] || { echo "build-apk.sh: melange did not produce $apk" >&2; exit 1; }
signer=$("$PY3" -I -B bin/apk-tool.py signer "$apk") \
  || { echo "build-apk.sh: cannot read the signer of $apk" >&2; exit 1; }
[ "$signer" = assembly.rsa.pub ] || { echo "build-apk.sh: $apk is signed by '$signer', not assembly.rsa.pub:" \
  "the assembly key is the only build signer" >&2; exit 1; }
# the name is only a label: the signature itself must verify against the committed public half of the assembly key
"$PY3" -I -B bin/apk-tool.py verify "$apk" build/keys/assembly.rsa.pub >/dev/null \
  || { echo "build-apk.sh: the signature of $apk does not verify against the committed build/keys/assembly.rsa.pub:" \
    "the apk is not signed with the assembly key" >&2; exit 1; }
"$PY3" -I -B bin/apk-tool.py cat "$apk" usr/share/fscache/buildinfo.txt >"$tmp/buildinfo.txt" \
  || { echo "build-apk.sh: $apk has no usr/share/fscache/buildinfo.txt" >&2; exit 1; }
# rule 24: not (devel), not modified, and the main module carries exactly the version being built
"$PY3" -I -B bin/build-apk-helper.py check-buildinfo "$tmp/buildinfo.txt" "$version"
headrev=$("$GIT" -C "$src" rev-parse HEAD 2>/dev/null) \
  || { echo "build-apk.sh: cannot read the source HEAD of $src" >&2; exit 1; }
# the revision is the source's HEAD; the fips variant records exactly the module build/locks/fips-module.txt names (AC4)
"$PY3" -I -B bin/build-apk-helper.py check-revision "$tmp/buildinfo.txt" "$headrev" "$variant" "$FIPS_MODULE"
# buildinfo.txt is checked against the packaged binary itself when a Go toolchain is found
"$PY3" -I -B bin/apk-tool.py cat "$apk" usr/bin/fscache >"$tmp/fscache.bin" \
  || { echo "build-apk.sh: $apk has no usr/bin/fscache" >&2; exit 1; }
gorc=127; gov=
[ ! -x "$GO_TOOL" ] || gorc=0
[ "$gorc" != 0 ] || gov=$("$ENVBIN" GOTOOLCHAIN=local GOFLAGS= GOENV=off "$GO_TOOL" version -m "$tmp/fscache.bin" \
  2>"$tmp/go.err") || gorc=$?
printf '%s\n' "$gov" >"$tmp/go.out"
"$PY3" -I -B bin/build-apk-helper.py go-verdict "$gorc" "$tmp/go.out" "$tmp/buildinfo.txt" "$tmp/go.err"

# ---- 6. the module SBOM and the inputs manifest ----
"$PY3" -I -B bin/go-module-sbom.py --modules "$src/vendor/modules.txt" --provenance "$src/dependency-provenance.json" \
  --buildinfo "$tmp/buildinfo.txt" --out "$out/fscache-modules$vsfx.spdx.json" \
  || { echo "build-apk.sh: the Go module list does not match the binary (see above)" >&2; exit 1; }
"$PY3" -I -B bin/apk-tool.py inputs-manifest --apk "$apk" --melange-lock "$mlock" \
  --out "$out/inputs-manifest$vsfx.json" \
  || { echo "build-apk.sh: the inputs manifest could not be made (see above)" >&2; exit 1; }
echo "built $apk"
