#!/usr/bin/env bash
# The sealed build proof (v0.3.0 rules 39-42): the real drivers build inside a namespace that really has no network, only
# declared inputs are used, and the result is recorded.
#
#   sealed-proof.sh --out DIR --probe 'SHELL COMMAND' --source-dir DIR --archive DIR
#                   --build-args 'build-apk.sh arguments' --assemble-args 'assemble-image.sh arguments'
#                   [--digests-out FILE] [--expect FILE]
#
# The probe is a shell command that exits 0 when it can reach outside and exactly 1 when it cannot (rule 40); any other status is
# inconclusive (a killed or unstartable probe proves nothing). Control: it must succeed in the runner and fail
# inside `sudo unshare -n`; a probe that fails outside too proves nothing (exit 1 naming "control"), and one that succeeds inside
# means the seal leaks (exit 1, "reached outside"). Then (rule 39) bin/build-apk.sh and bin/assemble-image.sh run for real
# (--build-args and --assemble-args supply their arguments; this script adds --source-dir, --archive and --out), and their
# digests are written to --digests-out as "<name> <hex>" lines (the apk's contents digest, the image's OCI index digest and
# each architecture manifest). With --expect FILE the digests must equal that file's (a second, independent build: the
# result is reproducible) or the proof fails naming the digest. Rule 41: negatives on throwaway copies. With vendor/ deleted
# the build must fail; with one archived package deleted the image assembly must fail; if either succeeds the proof fails
# (naming "vendor" or "package"). The drivers are the real bin/build-apk.sh and bin/assemble-image.sh, run from the repository root
# (REQ-IMAGE-001-AC7): there is no way to name another driver and no test hook in this file (AC12). The record names the sha256 of the
# archive index it used (the committed record build/locks/archive-index.sha256, which the archive is checked against first).
# OUT/sealed-record.json (rule 42) records how the network was cut, the control result, the runner image version
# (ImageOS, ImageVersion), the digests and the negatives.
# NOTE (rule 41): both negatives are PRE-CHECK refusals (bin/build-apk.sh: vendor/ missing; bin/assemble-image.sh: the archive does not satisfy the base lock). The sealed melange/apko call never runs
# in either negative: they show the guard exists, not that the seal holds. The seal itself is shown by the probe control (rule 40).
# Exit codes: 0 proved | 1 the proof failed | 2 refused (bad arguments).
set -euo pipefail

# every tool is called by a fixed absolute path held in a variable (REQ-IMAGE-001-AC12); the tests substitute exactly these lines
HOST_OS=${BASH_VERSINFO[5]}          # TEST-SUBST (the running bash's own build host, read-only and not importable from the environment: no tool, no caller input)
PY3=/usr/bin/python3                 # TEST-SUBST
SUDO=/usr/bin/sudo                   # TEST-SUBST
UNSHARE=/usr/bin/unshare             # TEST-SUBST
BASHBIN=/bin/bash                    # TEST-SUBST
case ${BASH_SOURCE[0]} in */*) here_=${BASH_SOURCE[0]%/*};; *) here_=.;; esac   # the script's own directory without running dirname
here=$(cd "$here_" && pwd)
die() { echo "sealed-proof.sh: $1" >&2; exit "${2:-1}"; }

[[ $HOST_OS == *linux* ]] || die "refusing to run on $HOST_OS: this script uses sudo, unshare and the sealed build tools, which run on Linux only (inside a Linux container or on a GitHub runner), never on the Mac itself" 2
# the chain runs everything from the repository root, and the drivers it calls refuse anywhere else (exit 2): run it as  bash bin/sealed-proof.sh ...  from there
[ "$(pwd -P)" = "$(cd "$here/.." && pwd -P)" ] || die "usage: run bin/sealed-proof.sh from the repository root ($(cd "$here/.." && pwd -P)), not from $(pwd -P)" 2

out= probe= src= archive= bargs= aargs= digests_out= expect= 
while [ $# -gt 0 ]; do
  [ $# -ge 2 ] || die "missing value for $1" 2
  case $1 in
    --out) out=$2;; --probe) probe=$2;; --source-dir) src=$2;; --archive) archive=$2;; --build-args) bargs=$2;;
    --assemble-args) aargs=$2;; --digests-out) digests_out=$2;; --expect) expect=$2;;
    *) die "unknown argument: $1" 2;;
  esac
  shift 2
done
[ -n "$out" ] && [ -n "$probe" ] && [ -d "$src" ] && [ -d "$archive" ] || die "--out, --probe, --source-dir and --archive are required" 2
for v_ in "$src" "$archive" "$out"; do [ "$(printf '%s' "$v_" | LC_ALL=C tr -d '\040-\176'; printf x)" = x ] || die "$v_ holds a control character or a byte outside printable ASCII; refusing, the path arguments are plain ASCII text" 2; done
for x_ in "$src" "$archive" "$out"; do while [ "${x_%/}" != "$x_" ] && [ "$x_" != / ]; do x_=${x_%/}; done; q_=$x_; while [[ $q_ == ./* ]]; do q_=${q_#./}; done; while [[ $q_ == ../* ]]; do q_=${q_#../}; done; case "/$q_/" in */./*|*/../*) die "$x_ has a . or .. component after another component (a component that could hide a symlinked root); give the real path" 2;; esac; [ ! -L "$x_" ] || die "$x_ is a symlink (--source-dir, --archive and --out must be real directories)" 2; done
[[ ${SOURCE_DATE_EPOCH:-} =~ ^[0-9]{1,12}$ ]] || die "SOURCE_DATE_EPOCH must be set to digits (at most 12)" 2
"$PY3" -I -B -c 'import datetime,sys;datetime.datetime.fromtimestamp(int(sys.argv[1]),datetime.timezone.utc)' "$SOURCE_DATE_EPOCH" 2>/dev/null || die "SOURCE_DATE_EPOCH $SOURCE_DATE_EPOCH is not a date" 2
{ [ -n "${ImageOS:-}" ] && [ -n "${ImageVersion:-}" ] && [ "$ImageOS" != unknown ] && [ "$ImageVersion" != unknown ]; } || die "ImageOS and ImageVersion are not set: the runner image cannot be recorded (rule 42); refusing" 2
bwords=(); while IFS= read -r -d '' w; do bwords+=("$w"); done < <("$PY3" -I -B -c 'import shlex,sys
for w in shlex.split(sys.argv[1]): sys.stdout.write(w+"\0")' "$bargs")
awords=(); while IFS= read -r -d '' w; do awords+=("$w"); done < <("$PY3" -I -B -c 'import shlex,sys
for w in shlex.split(sys.argv[1]): sys.stdout.write(w+"\0")' "$aargs")   # quotes in the argument strings are honoured
# the proof supplies these itself; a forwarded value could be printed back by a failing driver and mistaken for its reason
for ((i = 0; i < ${#bwords[@]}; i++)); do case ${bwords[$i]} in --source-dir|--out|--render-dir|--apk-cache-dir) die "${bwords[$i]} in --build-args: this option is supplied by the proof; refusing" 2;; --recipe) die "--recipe in --build-args: the build uses the committed recipe; refusing" 2;; esac; done
for ((i = 0; i < ${#awords[@]}; i++)); do case ${awords[$i]} in --archive|--out|--render-dir) die "${awords[$i]} in --assemble-args: this option is supplied by the proof; refusing" 2;; --apko-config|--base-lock|--index-record|--key-record) die "${awords[$i]} in --assemble-args: the assembly uses the committed files; refusing" 2;; esac; done
# the victim is a package the image uses: the first package of the BASE LOCK by (name, architecture), the same choice lock-proof makes
bl=
for ((i = 0; i < ${#awords[@]}; i++)); do [ "${awords[$i]}" = --base-lock ] && bl=${awords[$((i + 1))]:-}; done
variant= version= melrepo= keydir=
for ((i = 0; i < ${#awords[@]}; i += 2)); do   # the assembler's four options, each with its value; the assembler takes them in a fixed order
  case ${awords[$i]} in
    --variant) variant=${awords[$((i + 1))]:-};;
    --version) version=${awords[$((i + 1))]:-};;
    --melange-repo) melrepo=${awords[$((i + 1))]:-};;
    --keyring-dir) keydir=${awords[$((i + 1))]:-};;
    *) die "unknown argument in --assemble-args: ${awords[$i]}" 2;;
  esac
done
if [ -z "$bl" ]; then case $variant in production) bl=$here/../build/locks/apko.base.lock.json;; fips) bl=$here/../build/locks/apko-fips.base.lock.json;; esac; fi
[ -f "$bl" ] || die "the base lock for the negative case cannot be found (pass --base-lock in --assemble-args)"
victim=$("$PY3" -I -B - "$bl" "sealed-proof.sh" <<'PY'
import json, re, sys
e = sorted(json.load(open(sys.argv[1]))["contents"]["packages"], key=lambda e: (e["name"], e["architecture"]))[0]
def bad(what, v): print("%s: the base lock's first package has an unacceptable %s %r (closed rule: architecture exactly x86_64 or aarch64; name and version only [A-Za-z0-9._+-], never . or .. and never starting with -); refusing before any copy" % (sys.argv[2], what, v), file=sys.stderr); sys.exit(2)
if e["architecture"] not in ("x86_64", "aarch64"): bad("architecture", e["architecture"])
for k in ("name", "version"):
    v = e[k]
    if not isinstance(v, str) or not re.fullmatch(r"[A-Za-z0-9._+-]+", v) or v in (".", "..") or v.startswith("-") or ".." in v: bad(k, v)
print("%s/%s-%s.apk" % (e["architecture"], e["name"], e["version"]))
PY
) || exit 2
for l_ in sealed-record.json apk image; do [ ! -e "$out/$l_" ] && [ ! -L "$out/$l_" ] || die "$out/$l_ already exists (or is a link): refusing to write through or over it; give an empty --out" 2; done
mkdir -p "$out"
tmp=$(mktemp -d)
cleanup() { local rc=$?; set +e; rm -rf "$tmp" 2>/dev/null || "$SUDO" rm -rf "$tmp" >/dev/null 2>&1; exit $rc; }
trap cleanup EXIT
inside_tmp() { case "$(cd -P -- "$1" && pwd -P)" in "$(cd -P -- "$tmp" && pwd -P)"/*) ;; *) die "internal: $1 is not inside the proof's own temp directory; refusing to modify it" 2;; esac; }   # before any rm or write

# ---- rule 40: the control ----
if ! "$BASHBIN" -c "$probe" >/dev/null 2>&1; then
  die "control failed: the probe does not succeed outside the sealed namespace, so a failure inside proves nothing"
fi
if ! "$SUDO" "$BASHBIN" -c "$probe" >/dev/null 2>&1; then
  die "control failed: the probe works as the user but not under plain 'sudo' (no namespace), so a failure inside 'sudo unshare -n' would prove nothing (sudo)"
fi
# the namespace itself must work: a failing probe inside proves nothing if `unshare -n` could not run a command at all
if ! "$SUDO" "$UNSHARE" -n "$BASHBIN" -c : >/dev/null 2>&1; then
  die "control inconclusive: 'sudo unshare -n' could not run a command at all, so a probe failing inside proves nothing (unshare)"
fi
inside_rc=0; "$SUDO" "$UNSHARE" -n "$BASHBIN" -c "$probe" >/dev/null 2>&1 || inside_rc=$?
if [ "$inside_rc" = 0 ]; then
  die "the probe reached outside from inside 'sudo unshare -n': the network cut leaks (escaped)"
fi
[ "$inside_rc" = 1 ] || die "control inconclusive: inside the namespace the probe exited $inside_rc, not 1 (the status of a probe that could not reach out); a killed, unstartable or erroring probe proves nothing (probe)"

cp -RP "$src" "$tmp/src-copy"; inside_tmp "$tmp/src-copy"   # the throwaway copies and their guards come FIRST, before any driver runs
cp -RP "$archive" "$tmp/arch-nopkg"; inside_tmp "$tmp/arch-nopkg"
[ -f "$tmp/arch-nopkg/$victim" ] && [ ! -L "$tmp/arch-nopkg/$victim" ] || die "the base lock's first package $victim is not a regular file in the archive"
inside_tmp "$(dirname "$tmp/arch-nopkg/$victim")"
# rule 42 (d): the archive must be the one whose package index the repository recorded; the record then names exactly that index
"$PY3" -I -B bin/oci-digest.py check-index build/locks/archive-index.sha256 "$archive" >/dev/null || die "the archive's package index is not the one recorded in build/locks/archive-index.sha256 (archive index)" 1

# ---- rule 39: the real drivers ----
apkdir=$out/apk; imgdir=$out/image
"$BASHBIN" bin/build-apk.sh "${bwords[@]}" --source-dir "$src" --out "$apkdir" >"$tmp/build.log" 2>&1 || { cat "$tmp/build.log" >&2; die "the sealed build failed"; }
"$BASHBIN" bin/assemble-image.sh --variant "$variant" --version "$version" --archive "$archive" --melange-repo "$melrepo" \
  --keyring-dir "$keydir" --out "$imgdir" >"$tmp/assemble.log" 2>&1 || { cat "$tmp/assemble.log" >&2; die "the sealed image assembly failed"; }

[ -n "$(find "$apkdir" -name '*.apk' -type f 2>/dev/null | head -n 1)" ] || die "no digests were produced: the build left no apk in $apkdir"
compgen -G "$imgdir/*.digest" >/dev/null || die "no digests were produced: the image assembly left no *.digest file in $imgdir"
{
  for apk in $(cd "$apkdir" && find . -name '*.apk' -type f | sort); do
    n=$(basename "$apk" .apk)
    d=$("$PY3" -I -B bin/apk-tool.py digest "$apkdir/$apk") || die "the apk digest of $apk could not be computed (see above)"
    d=${d#sha256:}; [[ $d =~ ^[0-9a-f]{64}$ ]] || die "the apk digest of $apk is not 64 hex digits ($d)"
    echo "apk-$n $d"
  done
  for d in "$imgdir"/*.digest; do
    v=$(basename "$d" .digest)
    echo "image-$v.digest $(sed 's/^sha256://' "$d")"
    while read -r arch dig; do echo "image-$v.manifests-$arch ${dig#sha256:}"; done <"$imgdir/$v.manifests"
  done
} >"$tmp/digests.txt"
[ -s "$tmp/digests.txt" ] || die "no digests were produced"
if [ -n "$expect" ]; then
  cmp -s "$tmp/digests.txt" "$expect" || { diff "$expect" "$tmp/digests.txt" >&2 || true; die "the digests differ from the expected ones in $expect: the build is not reproducible"; }
fi
[ -z "$digests_out" ] || [ -z "$expect" ] || { [ ! "$digests_out" -ef "$expect" ] || die "--digests-out and --expect are the same file (or hard links of one): the comparison would be made against the digests just written" 2; }
if [ -n "$digests_out" ]; then
  # the destination is compared by its PHYSICAL location (dot components, doubled slashes, relative spellings and symlinked directories resolve away) and
  # by inode against every regular file the proof wrote
  case $digests_out in */*) dd_dir=${digests_out%/*}; dd_base=${digests_out##*/};; *) dd_dir=.; dd_base=$digests_out;; esac
  [ -n "$dd_dir" ] || dd_dir=/
  dd_phys=$(cd -P -- "$dd_dir" 2>/dev/null && pwd -P) || die "--digests-out $digests_out: its directory does not exist" 2
  out_phys=$(cd -P -- "$out" && pwd -P)
  case $dd_phys/ in "$out_phys"/*) die "--digests-out $digests_out is inside the proof's own output $out: it would overwrite a generated result" 2;; esac
  while IFS= read -r -d '' g_; do
    [ ! "$dd_phys/$dd_base" -ef "$g_" ] || die "--digests-out is the same file as the generated $g_ (or a hard link of it)" 2
  done < <(find "$out_phys" -type f -print0)
  [ ! -L "$digests_out" ] && { [ ! -e "$digests_out" ] || [ -f "$digests_out" ]; } || die "--digests-out $digests_out is a link or not a regular file; refusing to write through it" 2
  cp "$tmp/digests.txt" "$digests_out"
fi

# ---- rule 41: the negatives, on copies ----
rm -rf "$tmp/src-copy/vendor"
if "$BASHBIN" bin/build-apk.sh "${bwords[@]}" --source-dir "$tmp/src-copy" --out "$tmp/neg-build" >"$tmp/neg1.log" 2>&1; then
  die "the build still succeeded with vendor/ deleted: the build is not sealed to its declared inputs (vendor)"
fi
# the builder's OWN refusal: the last line that starts with the builder's name must say vendor is missing
vendor_reason=$(grep -E '^build-apk\.sh: ' "$tmp/neg1.log" | tail -n 1 || true)
case $vendor_reason in *"$tmp/src-copy/vendor is missing"*) ;; *) tail -3 "$tmp/neg1.log" >&2; die "the build failed with vendor/ deleted, but its own last message is not the 'vendor is missing' refusal (got: ${vendor_reason:-none}); an unrelated failure proves nothing about rule 41 (vendor)";; esac
# rule 41, build level: one package the build declares (a line of --melange-lock) is deleted from a copy of the repository the build was given
# (--repo): the real build must fail and say which package it could not select
brepo= block= barch=
for ((i = 0; i + 1 < ${#bwords[@]}; i++)); do
  case ${bwords[$i]} in --repo) brepo=${bwords[$((i + 1))]};; --melange-lock) block=${bwords[$((i + 1))]};; --arch) barch=${bwords[$((i + 1))]};; esac
done
[ -n "$brepo" ] && [ -n "$block" ] && [ -n "$barch" ] || die "--build-args must give --repo, --melange-lock and --arch: the proof removes a declared package from the build repository (rule 41)" 2
bpin=$(grep -E '^[A-Za-z0-9][A-Za-z0-9._+-]*=[A-Za-z0-9][A-Za-z0-9._+~-]*$' "$block" | LC_ALL=C sort | head -n 1) || true
[ -n "$bpin" ] || die "the melange lock $block has no package=version line to remove from the build repository" 2
bvictim=$barch/${bpin%%=*}-${bpin#*=}.apk
[ -f "$brepo/$bvictim" ] && [ ! -L "$brepo/$bvictim" ] || die "the build's first declared package $bvictim is not a regular file in the build repository $brepo"
[ -f "$brepo/$barch/APKINDEX.tar.gz" ] && [ ! -L "$brepo/$barch/APKINDEX.tar.gz" ] && [ -s "$brepo/$barch/APKINDEX.tar.gz" ] || die "the build repository $brepo has no regular, non-empty $barch/APKINDEX.tar.gz: the record must name the index the build used"
build_index=$("$PY3" -I -B -c 'import hashlib,sys;print("sha256:"+hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$brepo/$barch/APKINDEX.tar.gz") || die "cannot hash the build repository index"
cp -RP "$brepo" "$tmp/repo-nopkg"; inside_tmp "$tmp/repo-nopkg"; inside_tmp "$(dirname "$tmp/repo-nopkg/$bvictim")"; rm -f "$tmp/repo-nopkg/$bvictim"
bwords_nopkg=("${bwords[@]}"); for ((i = 0; i + 1 < ${#bwords_nopkg[@]}; i++)); do [ "${bwords_nopkg[$i]}" = --repo ] && bwords_nopkg[$((i + 1))]=$tmp/repo-nopkg; done
if "$BASHBIN" bin/build-apk.sh "${bwords_nopkg[@]}" --source-dir "$src" --out "$tmp/neg-build2" >"$tmp/neg3.log" 2>&1; then
  die "the build still succeeded with the declared package $bvictim deleted from its repository: the build is not sealed to its declared inputs (package)"
fi
# the evidence is the DIFFERENCE, not the wording: the same build with the package in its repository succeeded above (the positive run), fails with
# only that package removed, and succeeds again with a restored copy of the repository (so the failure was neither a transient one nor an unrelated
# one). No diagnostic text is interpreted; the last line the failing build printed is recorded for the reader.
cp -RP "$brepo" "$tmp/repo-restored"; inside_tmp "$tmp/repo-restored"
bwords_restored=("${bwords[@]}"); for ((i = 0; i + 1 < ${#bwords_restored[@]}; i++)); do [ "${bwords_restored[$i]}" = --repo ] && bwords_restored[$((i + 1))]=$tmp/repo-restored; done
"$BASHBIN" bin/build-apk.sh "${bwords_restored[@]}" --source-dir "$src" --out "$tmp/neg-build3" >"$tmp/neg4.log" 2>&1 || { tail -3 "$tmp/neg4.log" >&2; die "the build failed again with the package restored: the failure without $bvictim proves nothing about the package (inconclusive)"; }
build_package_reason="the build succeeds with $bvictim in its repository and fails without it; last output: $(tail -n 1 "$tmp/neg3.log" | cut -c1-200)"
rm -f "$tmp/arch-nopkg/$victim"
if "$BASHBIN" bin/assemble-image.sh --variant "$variant" --version "$version" --archive "$tmp/arch-nopkg" \
  --melange-repo "$melrepo" --keyring-dir "$keydir" --out "$tmp/neg-image" >"$tmp/neg2.log" 2>&1; then
  die "the image assembly still succeeded with an archived package deleted: not sealed to the archive (package)"
fi
package_reason=$(grep -E '^(assemble-image|apko-lock)\.sh: ' "$tmp/neg2.log" | grep -F -- "$(basename "$victim")" | tail -n 1 || true)
[ -n "$package_reason" ] || { tail -3 "$tmp/neg2.log" >&2; die "the image assembly failed with a package deleted, but its message does not name $(basename "$victim") (reason: an unrelated failure proves nothing about rule 41; package)"; }

# ---- rule 42: the record ----
"$PY3" -I -B - "$out/sealed-record.json" "$tmp/digests.txt" bin/build-apk.sh bin/assemble-image.sh build/locks/archive-index.sha256 "$vendor_reason" "$package_reason" "$build_package_reason" "$barch" "$build_index" <<'PY'
import hashlib, json, os, sys
digests = dict(l.split(" ", 1) for l in open(sys.argv[2]).read().splitlines())
bs, as_, idx = sys.argv[3:6]
archive_index = dict(l.split(" ", 1) for l in open(idx).read().splitlines() if l.strip())
json.dump({"cut": "sudo unshare -n (network namespace without a route)",
           "control": {"outside": "reached", "inside": "blocked"},
           "runner": {"ImageOS": os.environ.get("ImageOS", "unknown"), "ImageVersion": os.environ.get("ImageVersion", "unknown")},
           "digests": digests, "archive_index": archive_index, "archive_index_record": idx,
           "build_repository_index": {sys.argv[9]: sys.argv[10]},
           "binding_note": "the image was assembled from the supplied --melange-repo, not from the apk this build wrote to OUT/apk: the release chain's stage graph binds them (this record proves the two sealed steps separately)",
           "build_script": bs, "build_script_sha256": hashlib.sha256(open(bs, "rb").read()).hexdigest(),
           "assemble_script": as_, "assemble_script_sha256": hashlib.sha256(open(as_, "rb").read()).hexdigest(),
           "negatives": {"vendor-deleted": {"result": "failed-as-required", "reason": sys.argv[6]},
                         "package-deleted": {"result": "failed-as-required", "reason": sys.argv[7]},
                         "build-package-deleted": {"result": "failed-as-required", "reason": sys.argv[8]}}},
          open(sys.argv[1], "w"), indent=1, sort_keys=True)
open(sys.argv[1], "a").write("\n")
PY
echo "sealed proof ok; record in $out/sealed-record.json"
