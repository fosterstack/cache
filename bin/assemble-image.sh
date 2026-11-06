#!/usr/bin/env bash
# Assemble the production or FIPS image with apko from the archive alone (v0.3.0 rules 19, 20, 25-34, 36-38b, 40).
#
#   assemble-image.sh --variant production|fips --version X.Y.Z|X.Y.Z-rcN|0.0.0-rc.1 --archive DIR --melange-repo DIR
#                     --keyring-dir DIR --out DIR
# The six options come in exactly this order: any other shape is refused (exit 2).
#
# This file is straight-line text: no case, loop, function or subshell. The checks are subcommands of bin/oci-digest.py,
# which print the refusal themselves and choose the exit status.
# It runs from the repository root only (exit 2 elsewhere):
# every helper is named by its literal repo-root-relative path (bin/apko-lock.sh, bin/oci-digest.py, bin/net-probe.py).
# The config, the base lock, the index record and the key record are the committed ones of the variant: there is no
# option for them in any mode (REQ-IMAGE-001-AC10), and there is no test hook in this file (REQ-IMAGE-001-AC12):
# bin/assemble-image-test.sh runs a COPY in which exactly the lines ending in TEST-SUBST are replaced.
#
# Environment: SOURCE_DATE_EPOCH (digits) is required. The packages come only from DIR (the archive, rule 26) and the
# melange repository holding our fresh apk; there is no live address anywhere. The keyring dir holds
# wolfi-signing.rsa.pub and assembly.rsa.pub; /work/archive, /work/melange-repo and /work/keyring (the fixed paths the
# config and the locks name, rule 31) are made to point at the three directories with sudo, for the run only.
#
# In this order (the tests fix it):
#   1. refusals, before any apko call: bad arguments, a live repository in the config, a package or an APKINDEX missing
#      from the archive or a package whose bytes do not match the base lock (bin/apko-lock.sh verify-archive), our apks
#      missing from the melange repository, a keyring dir without the two keys;
#   2. render the config (@FSCACHE_VERSION@ replaced);
#   3. make the FULL lock: sudo unshare -n apko lock (apko lock has no offline flag, so the namespace has no network);
#   4. compare it with the committed base lock: the full lock must be the base lock plus our two apks and nothing
#      else, and every package must resolve to the same version on both architectures (bin/apko-lock.sh compare,
#      arch-check); verify the full lock against the archive and the melange repository;
#   5. ONE apko build for both architectures: sudo unshare -n apko build --offline --lockfile FULL --sbom-path SBOM
#      --build-date (the lock's checksum check is the tamper check), into a private temporary tar;
#   6. bin/oci-digest.py unpack reads that tar and writes the image as an OCI layout DIRECTORY OUT/<variant>/
#      (oci-layout, index.json, blobs/sha256/<hex>; deterministic: fixed modes and order, every blob hashing to its
#      name): OUT/<variant>.digest is the OCI INDEX digest (one line sha256:<hex>), and OUT/<variant>.manifests holds
#      one "<arch> sha256:<hex>" line per architecture manifest.
# OUT gets <variant>/, <variant>.digest, <variant>.manifests, <variant>.full.lock.json and <variant>-sbom/sbom.json; no
# tarball. The production and the fips call may share one OUT: each writes only its own names.
#
# Exit codes: 0 ok | 1 a tool failed, or the image layout is unusable
#   | 2 refused (the message names the reason; the full-lock checks of step 4 also exit 2, after apko lock ran, before
#     apko build)
#   | 4 a network attempt was made inside a sealed apko call (rule 40: the call failed, its output shows a network
#     error, and bin/net-probe.py in the same kind of namespace exits 101). A probe that is not 101 means the namespace
#     is not sealed: exit 1, not 4.
set -euo pipefail

# every tool is called by a fixed absolute path held in a variable (REQ-IMAGE-001-AC12); the tests substitute these
HOST_OS=${BASH_VERSINFO[5]}          # TEST-SUBST (the running bash's own build host: no tool, no caller input)
PY3=/usr/bin/python3                 # TEST-SUBST
SUDO=/usr/bin/sudo                   # TEST-SUBST
UNSHARE=/usr/bin/unshare             # TEST-SUBST
BASHBIN=/bin/bash                    # TEST-SUBST
APKO=/usr/local/bin/apko             # TEST-SUBST (the chain installs it there)
ENVBIN=/usr/bin/env                  # TEST-SUBST
WORKDIR=/work                        # TEST-SUBST (the fixed path the config and the locks name, rule 31)
RENDER_DIR=                          # TEST-SUBST (empty: a private temporary directory)

# ---- 1. refusals: the shell alone first (no tool runs before the host, the directory and the version are judged) ----
here_=${BASH_SOURCE[0]%/*}; [ "$here_" != "${BASH_SOURCE[0]}" ] || here_=.   # the script's own directory, no tool
start_=$PWD
cd -P "$here_/.."
root=$PWD
[[ $HOST_OS == *linux* ]] || { echo "assemble-image.sh: refusing to run on $HOST_OS: this script uses sudo," \
  "unshare and the sealed build tools, which run on Linux only (inside a Linux container or on a GitHub runner)," \
  "never on the Mac itself" >&2; exit 2; }
[ "$start_" -ef "$root" ] || { echo "assemble-image.sh: assemble-image.sh runs from the repository root ($root)," \
  "not from $start_: the helpers are named by repo-root-relative paths" >&2; exit 2; }
[ $# -eq 12 ] && [ "$1" = --variant ] && [ "$3" = --version ] && [ "$5" = --archive ] && [ "$7" = --melange-repo ] \
  && [ "$9" = --keyring-dir ] && [ "${11}" = --out ] \
  || { echo "assemble-image.sh: unknown argument or missing value" >&2; exit 2; }
variant=$2; version=$4; archive=$6; melrepo=$8; keydir=${10}; out=${12}; render=$RENDER_DIR
[ "$variant" = production ] || [ "$variant" = fips ] \
  || { echo "assemble-image.sh: --variant must be production or fips" >&2; exit 2; }
# the version grammar first, with the shell alone: a bad --version is refused before any tool, python included
# accepts: X.Y.Z or X.Y.Z-rcN (numbers without leading zeros), or the one snapshot version 0.0.0-rc.1
# refuses: 0.3 (two numbers), 01.2.3 (a leading zero), 0.3.0-rc.1 (a dot in the suffix), v0.3.0 (a leading v)
[[ $version =~ ^(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)(-rc[1-9][0-9]*)?$ || $version = 0.0.0-rc.1 ]] \
  || { echo "assemble-image.sh: --version must be X.Y.Z, X.Y.Z-rcN or the snapshot version 0.0.0-rc.1" \
    "(numbers without leading zeros; not '$version')" >&2; exit 2; }
pkg=$("$PY3" -I -B bin/oci-digest.py variant-field "$variant" pkg)
config=$("$PY3" -I -B bin/oci-digest.py variant-field "$variant" config)
baselock=$("$PY3" -I -B bin/oci-digest.py variant-field "$variant" baselock)
# a symlink as a ROOT (archive, melange repo, keyring directory, out) is refused: copies and writes would go through it
"$PY3" -I -B bin/oci-digest.py check-roots "$archive" "$melrepo" "$keydir" "$out" "$render"
# absolute paths from here on: the sealed calls run with the render directory as their working directory
archive=$("$PY3" -I -B bin/oci-digest.py abs-dir "$archive")
melrepo=$("$PY3" -I -B bin/oci-digest.py abs-dir "$melrepo")
keydir=$("$PY3" -I -B bin/oci-digest.py abs-dir "$keydir")
baselock=$("$PY3" -I -B bin/oci-digest.py abs-file "$baselock")
config=$("$PY3" -I -B bin/oci-digest.py abs-file "$config")
[ -z "$render" ] || render=$("$PY3" -I -B bin/oci-digest.py abs-file "$render")
apkver=$("$PY3" -I -B bin/oci-digest.py apk-version "$version")
# accepts: 1 to 12 digits, the commit time
# refuses: an empty value, 1.5 (not only digits), 1234567890123 (13 digits)
[[ ${SOURCE_DATE_EPOCH:-} =~ ^[0-9]{1,12}$ ]] \
  || { echo "assemble-image.sh: SOURCE_DATE_EPOCH must hold digits (the commit time, at most 12 digits)" >&2; exit 2; }
build_date=$("$PY3" -I -B bin/oci-digest.py render-date "$SOURCE_DATE_EPOCH" 2>/dev/null) \
  || { echo "assemble-image.sh: SOURCE_DATE_EPOCH $SOURCE_DATE_EPOCH is not a date" >&2; exit 2; }
"$PY3" -I -B bin/oci-digest.py check-inputs "$archive" "$melrepo" "$keydir" "$out" "$config" "$baselock"
"$PY3" -I -B bin/oci-digest.py check-config "$config" || exit 2
"$PY3" -I -B bin/oci-digest.py check-keydir "$keydir"
# the keyring directory is pinned by digest: exactly the two recorded keys, with the recorded bytes
keyrec=build/locks/archive-keys.sha256
[ -f "$keyrec" ] || { echo "assemble-image.sh: the key record $keyrec is missing:" \
  "cannot tell which keys the keyring directory must hold" >&2; exit 2; }
"$PY3" -I -B bin/oci-digest.py check-keys "$keyrec" "$keydir" || exit 2
# the archive's package index must be the one the repository recorded (one "<arch> sha256:<hex>" line per architecture,
# written by the refresh job), so an old commit never silently resolves against a newer index (rules 31, 47)
idxrec=build/locks/archive-index.sha256
[ -f "$idxrec" ] || { echo "assemble-image.sh: the index record $idxrec is missing:" \
  "cannot tell which package index the archive must hold" >&2; exit 2; }
"$PY3" -I -B bin/oci-digest.py check-index "$idxrec" "$archive" >/dev/null || exit 2
"$BASHBIN" bin/apko-lock.sh verify-archive --lock "$baselock" --archive "$archive" --index-record "$idxrec" \
  || { echo "assemble-image.sh: the archive does not satisfy the base lock $baselock (see above)" >&2; exit 2; }
"$PY3" -I -B bin/oci-digest.py check-melrepo "$melrepo" "$pkg" "$apkver"
"$PY3" -I -B bin/oci-digest.py check-melrepo "$melrepo" fscache-baselayout "$apkver"
workdir=$WORKDIR
lock=$workdir/.assemble.lock
[ ! -e "$lock" ] || { echo "assemble-image.sh: another assembly is in progress (the lock $lock exists);" \
  "wait for it or remove the lock if no run is active" >&2; exit 2; }
"$PY3" -I -B bin/oci-digest.py check-workdir "$workdir"

# ---- 2. render ----
tmp=$(mktemp -d)
made=
trap 'rm -rf "$tmp" 2>/dev/null || "$SUDO" rm -rf "$tmp" >/dev/null 2>&1 || true' EXIT
rdir=$("$PY3" -I -B bin/oci-digest.py prepare-render "$render" "$tmp")
rendered=$rdir/$(basename "$config")
"$PY3" -I -B bin/oci-digest.py render-config "$config" "$rendered" "$apkver" \
  || { echo "assemble-image.sh: cannot render the config $config" >&2; exit 1; }
# --out may already hold the OTHER variant's result (the chain assembles production and fips into one OUT)
"$PY3" -I -B bin/oci-digest.py check-out "$out" "$variant"
mkdir -p "$out"
out=$("$PY3" -I -B bin/oci-digest.py abs-dir "$out")

# the archive as apko sees it: every apk of the archive, and as APKINDEX.tar.gz exactly the recorded index
view=$rdir/archive-view
"$PY3" -I -B bin/oci-digest.py make-view "$idxrec" "$archive" "$view" || exit 2
"$SUDO" mkdir -p "$workdir" || { echo "assemble-image.sh: cannot create $workdir" >&2; exit 2; }
"$SUDO" mkdir "$lock" || { echo "assemble-image.sh: another assembly is in progress" \
  "(could not take $lock)" >&2; exit 2; }
# the cleanup now also removes the lock and the links this run made (and only those: $made grows as each link is made)
trap '{ "$SUDO" rm -f $made; "$SUDO" rmdir "$lock"; rm -rf "$tmp" 2>/dev/null || "$SUDO" rm -rf "$tmp"; } || true' EXIT
# no -f: a link that is already there (another run won the race after the pre-checks) is an error
"$SUDO" ln -sT "$view" "$workdir/archive" || { echo "assemble-image.sh: cannot make the link $workdir/archive" \
  "(it exists: another assembly?); stopping" >&2; exit 2; }
made="$made $workdir/archive"
"$SUDO" ln -sT "$melrepo" "$workdir/melange-repo" || { echo "assemble-image.sh: cannot make the link" \
  "$workdir/melange-repo (it exists: another assembly?); stopping" >&2; exit 2; }
made="$made $workdir/melange-repo"
"$SUDO" ln -sT "$keydir" "$workdir/keyring" || { echo "assemble-image.sh: cannot make the link $workdir/keyring" \
  "(it exists: another assembly?); stopping" >&2; exit 2; }
made="$made $workdir/keyring"
mkdir -p "$tmp/apko-cache"

# ---- 3. the full lock ----
# A sealed apko call: network cut with unshare -n, the render directory as the working directory (apko records the
# config path as typed, in the lock and in the image: a random temp path would make two builds differ). A failure that
# shows a network error is checked with the probe (rule 40).
full=$tmp/$variant.full.lock.json
cd "$rdir"
"$SUDO" "$ENVBIN" "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" "$UNSHARE" -n "$APKO" lock "$(basename "$rendered")" \
  --cache-dir "$tmp/apko-cache" --output "$full" >"$tmp/apko.err" 2>&1 && rc=0 || rc=$?
cd "$root"
cat "$tmp/apko.err" >&2
# accepts: any of the phrases a failed network attempt prints (unreachable, no route, dial tcp, name resolution)
# refuses: a failure that prints none of them (for example "permission denied"): that is not a network attempt
[ "$rc" != 0 ] && grep -Eqi -e 'ENETUNREACH|network is unreachable|dial tcp|no such host|no route to host' \
  -e 'connection refused|network request blocked|name resolution|Name or service not known|could not resolve host' \
  "$tmp/apko.err" 2>/dev/null && probe=0 || probe=
[ -z "$probe" ] || "$SUDO" "$UNSHARE" -n "$PY3" -I -B bin/net-probe.py >/dev/null 2>&1 || probe=$?
"$PY3" -I -B bin/oci-digest.py apko-verdict lock "$rc" "$probe"

# ---- 4. the full lock must be the base lock plus our apk ----
"$BASHBIN" bin/apko-lock.sh compare "$baselock" "$full" --apk "$pkg,fscache-baselayout" \
  || { echo "assemble-image.sh: the full lock's package entries differ from the base lock (see above);" \
    "not building" >&2; exit 2; }
"$BASHBIN" bin/apko-lock.sh arch-check "$full" \
  || { echo "assemble-image.sh: the full lock resolves different versions per architecture (see above);" \
    "not building" >&2; exit 2; }
"$BASHBIN" bin/apko-lock.sh verify-archive --lock "$full" --archive "$archive" --melange-repo "$melrepo" \
  --index-record "$idxrec" \
  || { echo "assemble-image.sh: the full lock does not verify against the archive and the melange repository" \
    "(see above)" >&2; exit 2; }
cp "$full" "$out/$variant.full.lock.json"

# ---- 5. one offline build for both architectures ----
mkdir -p "$tmp/sbom"   # apko renames its SBOMs into --sbom-path and does not create it (real-run finding)
cd "$rdir"
"$SUDO" "$ENVBIN" "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" "$UNSHARE" -n "$APKO" build "$(basename "$rendered")" \
  "$pkg:$version" "$tmp/$variant.tar" --offline --cache-dir "$tmp/apko-cache" --lockfile "$full" --vcs=false \
  --sbom-path "$tmp/sbom" --build-date "$build_date" >"$tmp/apko.err" 2>&1 && rc=0 || rc=$?
cd "$root"
cat "$tmp/apko.err" >&2
# accepts: any of the phrases a failed network attempt prints (unreachable, no route, dial tcp, name resolution)
# refuses: a failure that prints none of them (for example "permission denied"): that is not a network attempt
[ "$rc" != 0 ] && grep -Eqi -e 'ENETUNREACH|network is unreachable|dial tcp|no such host|no route to host' \
  -e 'connection refused|network request blocked|name resolution|Name or service not known|could not resolve host' \
  "$tmp/apko.err" 2>/dev/null && probe=0 || probe=
[ -z "$probe" ] || "$SUDO" "$UNSHARE" -n "$PY3" -I -B bin/net-probe.py >/dev/null 2>&1 || probe=$?
"$PY3" -I -B bin/oci-digest.py apko-verdict build "$rc" "$probe"

# ---- 6. the layout directory, the digests and the SBOM ----
"$PY3" -I -B bin/oci-digest.py unpack "$tmp/$variant.tar" "$out/$variant" "$out/$variant.digest" \
  "$out/$variant.manifests" \
  || { echo "assemble-image.sh: the image layout is unusable (see above)" >&2; exit 1; }
# the chain's table has ONE image SBOM per variant, <variant>-sbom/sbom.json: pick-sbom names it or refuses
sbomsrc=$("$PY3" -I -B bin/oci-digest.py pick-sbom "$tmp/sbom")
mkdir -p "$out/$variant-sbom"
cp "$sbomsrc" "$out/$variant-sbom/sbom.json"
echo "assembled $variant $version: $(cat "$out/$variant.digest")"
