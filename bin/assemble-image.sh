#!/usr/bin/env bash
# Assemble the production or FIPS image with apko from the archive alone (v0.3.0 rules 19, 20, 25-34, 36-38b, 40).
#
#   assemble-image.sh --variant production|fips --version X.Y.Z|X.Y.Z-rcN|0.0.0-rc.1 --archive DIR --melange-repo DIR --keyring-dir DIR --out DIR
# It runs from the repository root only (exit 2 elsewhere): every helper is named by its literal repo-root-relative path
# (bin/apko-lock.sh, bin/oci-digest.py, bin/net-probe.py), so the release chain's script judge can list it (handoff 0393).
# The config, the base lock, the index record and the key record are the committed ones of the variant: there is no option for them in any
# mode (REQ-IMAGE-001-AC10), and there is no test hook in this file (REQ-IMAGE-001-AC12): bin/assemble-image-test.sh runs a COPY in which
# exactly the lines ending in TEST-SUBST are replaced, against a fixture repository root.
#
# Environment: SOURCE_DATE_EPOCH (digits) is required. The packages come only from DIR (the archive, rule 26) and the melange
# repository holding our fresh apk; there is no live address anywhere. The keyring dir holds wolfi-signing.rsa.pub and
# assembly.rsa.pub; /work/archive, /work/melange-repo and /work/keyring (the fixed paths the config and the locks name, rule 31)
# are made to point at the three directories with sudo, for the duration of the run only.
#
# In this order (the tests fix it):
#   1. refusals, before any apko call: bad arguments, a live repository in the config, a package or an APKINDEX missing from the
#      archive or a package whose bytes do not match the base lock (bin/apko-lock.sh verify-archive), our apk missing from the
#      melange repository, a keyring dir without the two keys;
#   2. render the config (@FSCACHE_VERSION@ replaced);
#   3. make the FULL lock: sudo unshare -n apko lock (apko lock has no offline flag, so the namespace has no network);
#   4. compare it with the committed base lock: the full lock must be the base lock plus our apk and nothing else, and every
#      package must resolve to the same version on both architectures (bin/apko-lock.sh compare, arch-check); verify the full
#      lock against the archive and the melange repository;
#   5. ONE apko build for both architectures: sudo unshare -n apko build --offline --lockfile FULL --sbom-path SBOM --build-date
#      (the lock's checksum check is the tamper check), into a private temporary tar;
#   6. bin/oci-digest.py unpack reads that tar and writes the image as an OCI layout DIRECTORY OUT/<variant>/ (oci-layout,
#      index.json, blobs/sha256/<hex>; deterministic: fixed modes and order, every blob hashing to its name): OUT/<variant>.digest
#      is the OCI INDEX digest (one line sha256:<hex>), and OUT/<variant>.manifests holds one "<arch> sha256:<hex>" line per
#      architecture manifest.
# OUT gets <variant>/, <variant>.digest, <variant>.manifests, <variant>.full.lock.json and <variant>-sbom/sbom.json; no tarball.
# The production and the fips call may share one OUT: each writes only its own names.
#
# Exit codes: 0 ok | 1 a tool failed, or the image layout is unusable | 2 refused (the message names the reason; the full-lock
#   checks of step 4 also exit 2, after apko lock ran, before apko build) | 4 a network attempt was made inside a sealed apko
#   call (rule 40: the call failed, its output shows a network error, and bin/net-probe.py in the same kind of namespace exits
#   101). A probe that is not 101 means the namespace is not sealed: exit 1, not 4.
set -euo pipefail

# every tool is called by a fixed absolute path held in a variable (REQ-IMAGE-001-AC12); the tests substitute exactly these lines
HOST_OS=${BASH_VERSINFO[5]}          # TEST-SUBST (the running bash's own build host, read-only and not importable from the environment: no tool, no caller input)
PY3=/usr/bin/python3                 # TEST-SUBST
SUDO=/usr/bin/sudo                   # TEST-SUBST
UNSHARE=/usr/bin/unshare             # TEST-SUBST
BASHBIN=/bin/bash                    # TEST-SUBST
APKO=/usr/local/bin/apko             # TEST-SUBST (the chain installs it there)
ENVBIN=/usr/bin/env                  # TEST-SUBST
WORKDIR=/work                        # TEST-SUBST (the fixed path the config and the locks name, rule 31)
RENDER_DIR=                          # TEST-SUBST (empty: a private temporary directory; the tests keep the rendered config)

here_=${BASH_SOURCE[0]%/*}; [ "$here_" != "${BASH_SOURCE[0]}" ] || here_=.   # the script's own directory without running dirname
root=$(cd "$here_/.." && pwd -P)
die() { echo "assemble-image.sh: $1" >&2; exit "${2:-2}"; }
is_empty_dir() { "$PY3" -I -B bin/oci-digest.py is-empty "$1" 2>/dev/null; }   # a directory that cannot be listed is not empty

[[ $HOST_OS == *linux* ]] || die "refusing to run on $HOST_OS: this script uses sudo, unshare and the sealed build tools, which run on Linux only (inside a Linux container or on a GitHub runner), never on the Mac itself" 2
[ "$(pwd -P)" = "$root" ] || die "assemble-image.sh runs from the repository root ($root), not from $(pwd -P): the helpers are named by repo-root-relative paths" 2

variant= version= archive= melrepo= keydir= out= render=$RENDER_DIR
while [ $# -gt 0 ]; do
  [ $# -ge 2 ] || die "missing value for $1"
  case $1 in
    --variant) variant=$2;;
    --version) version=$2;;
    --archive) archive=$2;;
    --melange-repo) melrepo=$2;;
    --keyring-dir) keydir=$2;;
    --out) out=$2;;
    *) die "unknown argument: $1";;
  esac
  shift 2
done

# ---- 1. refusals ----
case $variant in
  production|fips) ;;
  *) die "--variant must be production or fips";;
esac
case $variant in
  production) pkg=fscache; config=build/apko.yaml; baselock=build/locks/apko.base.lock.json;;
  fips) pkg=fscache-fips; config=build/apko-fips.yaml; baselock=build/locks/apko-fips.base.lock.json;;
esac
# a symlink as a ROOT (archive, melange repo, keyring directory, out) is refused: copies and writes would go through it (the config and the base lock are
# committed constants now: no caller value reaches them, so there is nothing to check there)
# the version grammar first, with the shell alone: a bad --version is refused before any tool, python included
[[ $version =~ ^(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)(-rc[1-9][0-9]*)?$ || $version = 0.0.0-rc.1 ]] || die "--version must be X.Y.Z, X.Y.Z-rcN or the snapshot version 0.0.0-rc.1 (numbers without leading zeros; not '$version')"
for pair in "--archive:$archive" "--melange-repo:$melrepo" "--keyring-dir:$keydir" "--out:$out" "--render-dir:$render"; do
  [ "$(printf '%s' "${pair#*:}" | LC_ALL=C tr -d '\040-\176'; printf x)" = x ] || die "${pair%%:*} holds a control character or a byte outside printable ASCII (a newline, a C1 control or any byte >= 0x80); refusing, the path arguments are plain ASCII text"
  [ "${pair%%:*}" = --render-dir ] && [ -z "${pair#*:}" ] && continue   # no render directory given: a private temporary one is used
  [ -n "${pair#*:}" ] || die "${pair%%:*} is empty; refusing (an empty value would silently mean the current directory)"
  p_=${pair#*:}; while [ "${p_%/}" != "$p_" ] && [ "$p_" != / ]; do p_=${p_%/}; done   # a trailing slash would hide the symlink from -L
  "$PY3" -I -B bin/oci-digest.py check-dots "$p_" || die "${pair%%:*} $p_ has a . or .. component after another component (it could hide a symlinked root); give the real path"
  [ ! -L "$p_" ] || die "${pair%%:*} ${pair#*:} is a symlink; refusing (a root of the inputs or the result must be a real directory)"
done
# absolute paths from here on: the sealed calls run with the render directory as their working directory
absd() { (cd -P -- "$1" 2>/dev/null && pwd -P) || echo "$1"; }
absf() { (cd -P -- "$(dirname -- "$1")" 2>/dev/null && echo "$PWD/$(basename -- "$1")") || echo "$1"; }
archive=$(absd "$archive"); melrepo=$(absd "$melrepo"); keydir=$(absd "$keydir"); baselock=$(absf "$baselock"); config=$(absf "$config")
[ -z "$render" ] || render=$(absf "$render")

# exactly the chain's grammar (the tag minus its v): X.Y.Z, X.Y.Z-rcN (N digits, no leading zero, no dot) and the one fixed snapshot version
# 0.0.0-rc.1 (REQ-CHAIN-004-AC12); anything else is refused before any tool runs
"$PY3" -I -B bin/oci-digest.py check-version "$version" || die "--version must be X.Y.Z, X.Y.Z-rcN or the snapshot version 0.0.0-rc.1 (numbers without leading zeros; not '$version')"
apkver=${version/-rc./_rc}; apkver=${apkver/-rc/_rc}   # the apk version syntax for a pre-release: 0.3.0-rc1 -> 0.3.0_rc1, 0.0.0-rc.1 -> 0.0.0_rc1; the image tag keeps the rc form
[[ ${SOURCE_DATE_EPOCH:-} =~ ^[0-9]{1,12}$ ]] || die "SOURCE_DATE_EPOCH must hold digits (the commit time, at most 12 digits)"
build_date=$("$PY3" -I -B bin/oci-digest.py render-date "$SOURCE_DATE_EPOCH" 2>/dev/null) || die "SOURCE_DATE_EPOCH $SOURCE_DATE_EPOCH is not a date"
for d in "$archive" "$melrepo" "$keydir"; do
  case $d in
    *://*) die "the archive, the melange repository and the keyring dir must be local directories, not addresses ($d)";;
  esac
done
[ -d "$archive" ] || die "--archive is not a directory: $archive"
[ -d "$melrepo" ] || die "--melange-repo is not a directory: $melrepo"
[ -n "$out" ] || die "--out DIR is required"
[ -f "$config" ] || die "apko config not found: $config"
[ -f "$baselock" ] || die "base lock not found: $baselock"
"$PY3" -I -B bin/oci-digest.py check-config "$config" || exit 2
for k in wolfi-signing.rsa.pub assembly.rsa.pub; do
  [ -f "$keydir/$k" ] || die "the keyring dir $keydir has no $k: every package is checked against its key (rule 19)"
done
# the keyring directory is pinned by digest: exactly the two recorded keys, with the recorded bytes (they end up as the image's trusted keys)
keyrec=build/locks/archive-keys.sha256
[ -f "$keyrec" ] || die "the key record $keyrec is missing: cannot tell which keys the keyring directory must hold"
"$PY3" -I -B bin/oci-digest.py check-keys "$keyrec" "$keydir" || exit 2
# the archive's package index must be the one the repository recorded (build/locks/archive-index.sha256: one "<arch> sha256:<hex>" line
# per architecture, written by the refresh job), so an old commit never silently resolves against a newer index (rules 31, 47)
idxrec=build/locks/archive-index.sha256
[ -f "$idxrec" ] || die "the index record $idxrec is missing: cannot tell which package index the archive must hold"
"$PY3" -I -B bin/oci-digest.py check-index "$idxrec" "$archive" >/dev/null || exit 2
"$BASHBIN" bin/apko-lock.sh verify-archive --lock "$baselock" --archive "$archive" --index-record "$idxrec" || die "the archive does not satisfy the base lock $baselock (see above)"
for a in x86_64 aarch64; do
  [ -f "$melrepo/$a/$pkg-$apkver-r0.apk" ] || die "the melange repository $melrepo has no $a/$pkg-$apkver-r0.apk (our apk)"
  [ -f "$melrepo/$a/APKINDEX.tar.gz" ] || die "the melange repository $melrepo has no $a/APKINDEX.tar.gz"
done
workdir=$WORKDIR
[ ! -e "$workdir/.assemble.lock" ] || die "another assembly is in progress (the lock $workdir/.assemble.lock exists); wait for it or remove the lock if no run is active"
for l in archive melange-repo keyring; do
  if [ -e "$workdir/$l" ] || [ -L "$workdir/$l" ]; then
    die "$workdir/$l already exists ($( [ -L "$workdir/$l" ] && echo 'a symlink, left by another run or a crashed one' || echo 'not a symlink'))); refusing to replace it: remove it by hand if no other assembly is running"
  fi
done

tmp=$(mktemp -d)
claimed=0
madelinks=()
cleanup() {
  local rc=$?
  set +e
  if [ "$claimed" = 1 ]; then
    [ ${#madelinks[@]} -eq 0 ] || "$SUDO" rm -f "${madelinks[@]}" >/dev/null 2>&1
    "$SUDO" rmdir "$workdir/.assemble.lock" >/dev/null 2>&1
  fi
  rm -rf "$tmp" 2>/dev/null || "$SUDO" rm -rf "$tmp" >/dev/null 2>&1   # apko (run as root) leaves root-owned files in its private cache
  exit $rc   # a cleanup problem never changes the script's own exit status (0, 2, or the confirmed network attempt 4)
}
trap cleanup EXIT

# ---- 2. render ----
if [ -n "$render" ]; then
  [ ! -L "$render" ] || die "--render-dir $render is a symlink; refusing (render files would be written through it)"
  if [ -d "$render" ]; then is_empty_dir "$render" || die "--render-dir $render is not empty or cannot be listed; refusing (a planted file would be used or written through)"; else mkdir -p "$render"; fi
  rdir=$render
else
  rdir=$tmp/render; mkdir -p "$rdir"
fi
rendered=$rdir/$(basename "$config")
"$PY3" -I -B bin/oci-digest.py render-config "$config" "$rendered" "$apkver" || die "cannot render the config $config" 1
# --out may already hold the OTHER variant's result (the chain assembles production and fips into one OUT); this variant's own names must not exist
if [ -e "$out" ] && [ ! -d "$out" ]; then die "--out $out is not a directory"; fi
if [ -d "$out" ]; then
  for n in "$variant" "$variant.digest" "$variant.manifests" "$variant.full.lock.json" "$variant-sbom"; do
    if [ -e "$out/$n" ] || [ -L "$out/$n" ]; then die "--out $out already holds $n; refusing to mix a new result with stale files (it is not empty)"; fi
  done
  ls -A "$out" >/dev/null 2>&1 || die "--out $out cannot be listed; refusing"
fi
mkdir -p "$out"; out=$(absd "$out")

# the archive as apko sees it: every apk of the archive, and as APKINDEX.tar.gz exactly the recorded index (not the pointer)
view=$rdir/archive-view
"$PY3" -I -B bin/oci-digest.py make-view "$idxrec" "$archive" "$view" || exit 2
"$SUDO" mkdir -p "$workdir" || die "cannot create $workdir"
"$SUDO" mkdir "$workdir/.assemble.lock" || die "another assembly is in progress (could not take $workdir/.assemble.lock)"   # atomic claim
claimed=1
# no -f: a link that is already there (another run won the race after the pre-checks) is an error; the cleanup removes only the links THIS run made
for l in archive:"$view" melange-repo:"$melrepo" keyring:"$keydir"; do
  "$SUDO" ln -sT "$(cd "${l#*:}" && pwd)" "$workdir/${l%%:*}" || die "cannot make the link $workdir/${l%%:*} (it exists: another assembly?); stopping" 2
  madelinks+=("$workdir/${l%%:*}")
done
mkdir -p "$tmp/apko-cache"

# a sealed apko call: network cut with unshare -n; a failure that shows a network error is checked with the probe (rule 40)
sealed() {
  local errf=$tmp/apko.err rc
  set +e
  # the working directory is the render directory (apko records the config path as typed, in the lock and in the image: a random temp path would make two builds differ)
  ( cd "$rdir" && "$SUDO" "$ENVBIN" "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" "$UNSHARE" -n "$APKO" "$@" ) >"$errf" 2>&1
  rc=$?
  set -e
  cat "$errf" >&2   # the file is complete when the command has exited; no race with a process substitution
  [ $rc -eq 0 ] && return 0
  [ $rc -ne 127 ] || die "apko is not installed (the chain installs it before this step)" 1
  if grep -Eqi 'ENETUNREACH|network is unreachable|dial tcp|no such host|no route to host|connection refused|network request blocked|name resolution|Name or service not known|could not resolve host' "$errf" 2>/dev/null; then
    local probe
    set +e; "$SUDO" "$UNSHARE" -n "$PY3" -I -B bin/net-probe.py >/dev/null 2>&1; probe=$?; set -e
    if [ "$probe" = 101 ]; then die "a network attempt was made inside the sealed apko call (the probe confirms the namespace has no route); the build must use only declared inputs" 4; fi
    die "apko failed with a network error, but the probe says the namespace is not sealed (exit $probe); fix the seal first" 1
  fi
  die "apko $1 failed (exit $rc)" 1
}

# ---- 3. the full lock ----
full=$tmp/$variant.full.lock.json
sealed lock "$(basename "$rendered")" --cache-dir "$tmp/apko-cache" --output "$full"

# ---- 4. the full lock must be the base lock plus our apk ----
"$BASHBIN" bin/apko-lock.sh compare "$baselock" "$full" --apk "$pkg" || die "the full lock's package entries differ from the base lock (see above); not building" 2
"$BASHBIN" bin/apko-lock.sh arch-check "$full" || die "the full lock resolves different versions per architecture (see above); not building" 2
"$BASHBIN" bin/apko-lock.sh verify-archive --lock "$full" --archive "$archive" --melange-repo "$melrepo" --index-record "$idxrec" || die "the full lock does not verify against the archive and the melange repository (see above)" 2
cp "$full" "$out/$variant.full.lock.json"

# ---- 5. one offline build for both architectures ----
mkdir -p "$tmp/sbom"   # apko renames its SBOMs into --sbom-path and does not create it (real-run finding)
sealed build "$(basename "$rendered")" "$pkg:$version" "$tmp/$variant.tar" --offline --cache-dir "$tmp/apko-cache" --lockfile "$full" --vcs=false --sbom-path "$tmp/sbom" --build-date "$build_date"

# ---- 6. the layout directory, the digests and the SBOM ----
"$PY3" -I -B bin/oci-digest.py unpack "$tmp/$variant.tar" "$out/$variant" "$out/$variant.digest" "$out/$variant.manifests" || die "the image layout is unusable (see above)" 1
# the chain's table has ONE image SBOM per variant, <variant>-sbom/sbom.json: the one file apko wrote, or the multi-architecture index SBOM
# (sbom-index.spdx.json) when it wrote one per architecture too; anything else cannot be told apart, so it is refused
shopt -s nullglob
sbomfiles=("$tmp/sbom"/*)
shopt -u nullglob
if [ "${#sbomfiles[@]}" = 1 ]; then sbomsrc=${sbomfiles[0]}; elif [ -f "$tmp/sbom/sbom-index.spdx.json" ]; then sbomsrc=$tmp/sbom/sbom-index.spdx.json; else sbomsrc=; fi
[ -n "$sbomsrc" ] && [ -f "$sbomsrc" ] || die "apko wrote ${#sbomfiles[@]} SBOM files and none is the image index SBOM (sbom-index.spdx.json); cannot choose the one image SBOM" 1
mkdir -p "$out/$variant-sbom"
cp "$sbomsrc" "$out/$variant-sbom/sbom.json"
echo "assembled $variant $version: $(cat "$out/$variant.digest")"
