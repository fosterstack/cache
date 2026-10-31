#!/usr/bin/env bash
# Build the fscache-baselayout apk with melange, sealed from the network (0710; v0.3.0 rules 11-17, 19, 22, 23, 38a,
# 40).
#
#   build-baselayout-apk.sh --arch x86_64|aarch64 --version X.Y.Z|X.Y.Z-rcN|0.0.0-rc.1 --source-dir DIR --repo DIR
#                           --keyring FILE --melange-lock FILE --out DIR [--render-dir DIR] [--apk-cache-dir DIR]
#
# The sibling of the apk driver for the one package that holds only files. The recipe is
# build/melange-baselayout.yaml (fixed: there is no --recipe option); it builds no Go, so there is no --variant and
# no --go-archive. The sealed call is the same: the helper bin/build-apk-helper.py judges the array before it runs
# (sealed-call: the bubblewrap runner, --namespace fosterstack, the cut network namespace, the closed environment of
# build/sealed-env.json).
#
# This file is straight-line text: no case, loop, function or subshell. Every decision is a subcommand of
# bin/build-apk-helper.py, which prints the refusal and sets the exit status. Run it from the repository root.
#
# Environment: SOURCE_DATE_EPOCH (digits) is required: the commit time of the tagged commit, which the stage script
# gets from the apk driver's --print-source-date-epoch. Refused: APK_RELEASE_SIGNING_KEY defined, GOPROXY other than
# off, HTTP(S)_PROXY / ALL_PROXY defined. There is no --signing-key: the apk is signed with the committed, non-secret
# assembly key build/keys/assembly.rsa and nothing else. The package is assembled into the images only, never released.
#
# In this order:
#   1. refusals, before any build tool runs (exit 2): the options, the environment, the inputs, the assembly key, a
#      recipe that is not the base-layout package, a recipe and a melange lock that disagree;
#   2. render the recipe (@VERSION@ replaced);
#   3. sudo env -i <sealed items> unshare -n melange build ... --runner bubblewrap --namespace fosterstack;
#   4. checks of the apk: signed by assembly.rsa.pub, each file equal to its source under build/baselayout/etc, and no
#      CA bundle file in it;
#   5. writes OUT/<arch>/fscache-baselayout-<version>-r0.apk (+ APKINDEX.tar.gz, from melange) and
#      OUT/inputs-manifest-baselayout.json (bin/apk-tool.py).
#
# Exit codes: 0 ok | 1 the build or a post-build check failed | 2 refused (no build tool was run)
#   | 4 a network attempt was made inside the sealed melange call (rule 40, as the apk driver).
set -euo pipefail

# Fixed locations: a production call never resolves python3, sudo, unshare or melange through the caller's search
# path. There is no test hook in this file: bin/build-baselayout-apk-test.sh runs a COPY in which exactly the lines
# ending in TEST-SUBST are replaced, and checks that the copy differs from this file in no other line.
PY3=/usr/bin/python3            # TEST-SUBST
SUDO=/usr/bin/sudo              # TEST-SUBST
UNSHARE=/usr/bin/unshare        # TEST-SUBST
MELANGE=/usr/local/bin/melange  # TEST-SUBST (the chain installs it there)
ENVBIN=/usr/bin/env             # TEST-SUBST
SEALED_ENV=build/sealed-env.json  # TEST-SUBST
RECIPE=$PWD/build/melange-baselayout.yaml  # TEST-SUBST

[ -f bin/build-baselayout-apk.sh ] && [ -f bin/build-apk-helper.py ] && [ -f build/sealed-env.json ] \
  || { echo "build-baselayout-apk.sh: run bin/build-baselayout-apk.sh from the repository root" \
    "(its helpers are named by repo-relative paths)" >&2; exit 2; }
root_=$PWD

# ---- 1. refusals ----
"$PY3" -I -B bin/build-apk-helper.py baselayout-check-args "$(uname -s)" "$(uname -m)" "$@" >/dev/null
src=$("$PY3" -I -B bin/build-apk-helper.py baselayout-arg src "$@")
arch=$("$PY3" -I -B bin/build-apk-helper.py baselayout-arg arch "$@")
version=$("$PY3" -I -B bin/build-apk-helper.py baselayout-arg version "$@")
apkver=$("$PY3" -I -B bin/build-apk-helper.py baselayout-arg apkver "$@")
build_date=$("$PY3" -I -B bin/build-apk-helper.py baselayout-arg build-date "$@")
repo=$("$PY3" -I -B bin/build-apk-helper.py baselayout-arg repo "$@")
keyring=$("$PY3" -I -B bin/build-apk-helper.py baselayout-arg keyring "$@")
mlock=$("$PY3" -I -B bin/build-apk-helper.py baselayout-arg melange-lock "$@")
out=$("$PY3" -I -B bin/build-apk-helper.py baselayout-arg out "$@")
render=$("$PY3" -I -B bin/build-apk-helper.py baselayout-arg render-dir "$@")
apkcache=$("$PY3" -I -B bin/build-apk-helper.py baselayout-arg apk-cache-dir "$@")
assembly_key=$PWD/build/keys/assembly.rsa
[ -f "$assembly_key" ] \
  || { echo "build-baselayout-apk.sh: the committed assembly key $assembly_key is missing" >&2; exit 2; }
[ -f "$RECIPE" ] || { echo "build-baselayout-apk.sh: recipe not found: $RECIPE" >&2; exit 2; }
recipe=$("$PY3" -I -B bin/build-apk-helper.py abs-file "$RECIPE")
mkdir -p "$out"
[ -z "$render" ] || mkdir -p "$render"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp" 2>/dev/null || "$SUDO" rm -rf "$tmp" >/dev/null 2>&1 || true' EXIT

# the recipe is the base-layout package and only copies files; its pinned build environment must be in the melange lock
# (rule 15), name for name and version for version, and the lock must hold nothing else
"$PY3" -I -B bin/build-apk-helper.py baselayout-facts "$recipe" "$tmp/recipe.facts"
pkg=$(sed -n 's/^name=//p' "$tmp/recipe.facts")
sed -n 's/^pin=//p' "$tmp/recipe.facts" >"$tmp/pins"
missing=$(grep -Fxv -f "$mlock" "$tmp/pins" | head -n 1 || true)
[ -z "$missing" ] || { echo "build-baselayout-apk.sh: the recipe pins $missing but the melange lock $mlock does not" \
  "have it; the recipe and the lock must agree" >&2; exit 2; }
extra=$(grep -v '^$' "$mlock" | grep -Fxv -f "$tmp/pins" || true)
[ -z "$extra" ] || { echo "build-baselayout-apk.sh: the melange lock $mlock has lines the recipe does not pin" \
  "($(printf '%s' "$extra" | head -n 3 | tr '\n' ' ')): the recipe and the lock must agree both ways" >&2; exit 2; }

# ---- 2. render ----
rdir=${render:-$tmp/render}; mkdir -p "$rdir"
rendered=$rdir/$(basename "$recipe")
sed "s/@VERSION@/$apkver/g" "$recipe" >"$rendered"

# ---- 3. the sealed call ----
mkdir -p "$tmp/cache"
margs=(build "$(basename "$rendered")" --arch "$arch" --runner bubblewrap --namespace fosterstack
  --signing-key "$assembly_key"
  --keyring-append "$keyring" --repository-append "$repo" --build-date "$build_date"
  --cache-dir "$tmp/cache" --source-dir "$src" --out-dir "$out")
[ -z "$apkcache" ] || margs+=(--apk-cache-dir "$apkcache")
melange_bin=$MELANGE; [ -x "$melange_bin" ] \
  || { echo "build-baselayout-apk.sh: melange is not installed (the chain installs it before this step)" >&2; exit 1; }
mapfile -d '' -t sealed < <("$PY3" -I -B bin/build-apk-helper.py sealed-env "$SEALED_ENV")
[ "${#sealed[@]}" -ge 4 ] \
  || { echo "build-baselayout-apk.sh: the sealed environment could not be made" \
    "(build/sealed-env.json, SOURCE_DATE_EPOCH)" >&2; exit 1; }
call=("$ENVBIN" -i "${sealed[@]}" "$UNSHARE" -n "$melange_bin" "${margs[@]}")
why=$("$PY3" -I -B bin/build-apk-helper.py sealed-call --sealed-env "$SEALED_ENV" "${call[@]}" 2>&1) \
  || { echo "build-baselayout-apk.sh: refusing the melange call: $why" >&2; exit 2; }
"$SUDO" sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 >/dev/null 2>&1 ||
  echo "build-baselayout-apk.sh: warning: could not relax kernel.apparmor_restrict_unprivileged_userns" \
    "(not needed off Ubuntu 24.04)" >&2
cd "$rdir"
"$SUDO" "${call[@]}" 2>"$tmp/melange.err" && rc=0 || rc=$?
cd "$root_"
cat "$tmp/melange.err" >&2
probe=
[ "$rc" != 0 ] && grep -Eqi -e 'ENETUNREACH|network is unreachable|dial tcp|no such host|name resolution' \
  -e 'Name or service not known|could not resolve host' "$tmp/melange.err" 2>/dev/null && probe=0 || probe=
[ -z "$probe" ] || "$SUDO" "$UNSHARE" -n "$PY3" -I -B bin/net-probe.py >/dev/null 2>&1 || probe=$?
"$PY3" -I -B bin/build-apk-helper.py melange-verdict "$rc" "$probe"

# ---- 4. checks on the apk ----
apk=$out/$arch/$pkg-$apkver-r0.apk
[ -f "$apk" ] || { echo "build-baselayout-apk.sh: melange did not produce $apk" >&2; exit 1; }
signer=$("$PY3" -I -B bin/apk-tool.py signer "$apk") \
  || { echo "build-baselayout-apk.sh: cannot read the signer of $apk" >&2; exit 1; }
[ "$signer" = assembly.rsa.pub ] \
  || { echo "build-baselayout-apk.sh: $apk is signed by '$signer', not assembly.rsa.pub:" \
  "the assembly key is the only build signer" >&2; exit 1; }
"$PY3" -I -B bin/apk-tool.py verify "$apk" build/keys/assembly.rsa.pub >/dev/null \
  || { echo "build-baselayout-apk.sh: the signature of $apk does not verify against the committed" \
    "build/keys/assembly.rsa.pub: the apk is not signed with the assembly key" >&2; exit 1; }
"$PY3" -I -B bin/apk-tool.py cat "$apk" etc/group | cmp -s - "$src/build/baselayout/etc/group" \
  || { echo "build-baselayout-apk.sh: etc/group in $apk differs from build/baselayout/etc/group" >&2; exit 1; }
"$PY3" -I -B bin/apk-tool.py cat "$apk" etc/hosts | cmp -s - "$src/build/baselayout/etc/hosts" \
  || { echo "build-baselayout-apk.sh: etc/hosts in $apk differs from build/baselayout/etc/hosts" >&2; exit 1; }
"$PY3" -I -B bin/apk-tool.py cat "$apk" etc/nsswitch.conf | cmp -s - "$src/build/baselayout/etc/nsswitch.conf" \
  || { echo "build-baselayout-apk.sh: etc/nsswitch.conf in $apk differs from the source" \
    "build/baselayout/etc/nsswitch.conf" >&2; exit 1; }
"$PY3" -I -B bin/apk-tool.py cat "$apk" etc/os-release | cmp -s - "$src/build/baselayout/etc/os-release" \
  || { echo "build-baselayout-apk.sh: etc/os-release in $apk differs from the source" \
    "build/baselayout/etc/os-release" >&2; exit 1; }
"$PY3" -I -B bin/apk-tool.py cat "$apk" etc/passwd | cmp -s - "$src/build/baselayout/etc/passwd" \
  || { echo "build-baselayout-apk.sh: etc/passwd in $apk differs from build/baselayout/etc/passwd" >&2; exit 1; }
"$PY3" -I -B bin/apk-tool.py cat "$apk" etc/protocols | cmp -s - "$src/build/baselayout/etc/protocols" \
  || { echo "build-baselayout-apk.sh: etc/protocols in $apk differs from build/baselayout/etc/protocols" >&2; exit 1; }
"$PY3" -I -B bin/apk-tool.py cat "$apk" etc/services | cmp -s - "$src/build/baselayout/etc/services" \
  || { echo "build-baselayout-apk.sh: etc/services in $apk differs from build/baselayout/etc/services" >&2; exit 1; }
"$PY3" -I -B bin/apk-tool.py members "$apk" >"$tmp/members" \
  || { echo "build-baselayout-apk.sh: cannot list the entries of $apk" >&2; exit 1; }
sed "s/@VERSION@/$apkver/g" "$src/build/baselayout/members.txt" >"$tmp/members.want"
if ! cmp -s "$tmp/members" "$tmp/members.want"; then
  first=$(grep -m1 -Fxv -f "$tmp/members.want" "$tmp/members" || true)
  if [ -z "$first" ]; then
    first=$(grep -m1 -Fxv -f "$tmp/members" "$tmp/members.want" || true)
  fi
  echo "build-baselayout-apk.sh: the entries of $apk differ from build/baselayout/members.txt, first at: ${first:-the order}" >&2
  exit 1
fi

# ---- 5. the inputs manifest ----
"$PY3" -I -B bin/apk-tool.py inputs-manifest --apk "$apk" --melange-lock "$mlock" \
  --out "$out/inputs-manifest-baselayout.json" \
  || { echo "build-baselayout-apk.sh: the inputs manifest could not be made (see above)" >&2; exit 1; }
echo "built $apk"
