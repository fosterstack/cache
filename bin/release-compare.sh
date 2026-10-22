#!/usr/bin/env bash
# Release's comparison of Build's and Rebuild's apks (REQ-CHAIN-005-AC4 as the owner ratified it on Oct 21 2026,
# ops/docs/ratify/2026-10-21-signer-builder-separate-jobs.md: "the signer and the builder need hardware isolation": a job that holds the signing key or a
# publish credential never receives Rebuild's apks, and the comparison runs in a job with no secrets and no publish permission).
#
# Run by the `compare` job of stage-promote.yml as one plain step: no environment, no secret, no id-token, nothing signed, no key read, no network.
# In:  apks/<runner>/<apk arch>/<file>.apk   Build's apks (artifacts apk-ubuntu-24.04 -> x86_64 and apk-ubuntu-24.04-arm -> aarch64)
#      rapks/<runner>/<apk arch>/<file>.apk  Rebuild's apks, laid out the same (artifacts rapk-...)
# Out: apk-compare/apk-compare.json  {"verdict": "pass", "pairs": [four rows: arch, variant, name, build_sha256, rebuild_sha256, build_digest, rebuild_digest]}
#      written only when all four pairs agree. The verify and release jobs read ONLY this file (bin/release-verify.sh checks it against Build's attested apk digests).
# Each of the four expected pairs (amd64 and arm64, standard and fips) must exist on both sides exactly once; any other .apk, a symlink, a name with a control
# character, an apk that is not a regular file, a signer other than assembly.rsa.pub, or a signature that does not verify against build/keys/assembly.rsa.pub
# is refused (exit 2); apks that differ in their control or data section (bin/apk-tool.py same) exit 1 and name the apk.
set -euo pipefail

die() { echo "release-compare.sh: $1" >&2; exit "${2:-2}"; }
# run from the repository root only: bin/apk-tool.py and the committed assembly public key are named by their literal repo-relative paths
[ -f bin/release-compare.sh ] && [ -f bin/apk-tool.py ] || die "run bin/release-compare.sh from the repository root (bin/apk-tool.py is named by its repo-relative path)" 2
[ -f build/keys/assembly.rsa.pub ] || die "build/keys/assembly.rsa.pub is missing" 2
rm -rf apk-compare
for d in apks rapks; do
  [ -d "$d" ] || die "$d/ is not a directory: the artifacts of Build and Rebuild are missing" 2
  link=$(find "$d" -type l -print -quit)
  [ -z "$link" ] || die "$link is a symlink; refusing (only regular files are compared)" 2
  ctl=$(LC_ALL=C find "$d" -name '*[[:cntrl:]]*' -print -quit | LC_ALL=C tr '\001-\037\177' '?')
  [ -z "$ctl" ] || die "a file name under $d holds a control character (newline or other): $ctl; refusing (a name is never split into two)" 2
  odd=$(find "$d" -name '*.apk' ! -type f -print -quit)
  [ -z "$odd" ] || die "$odd is not a regular file; refusing" 2
  n=$(find "$d" -name '*.apk' -type f | wc -l)
  [ "$n" -gt 0 ] || die "no apk under $d/" 2
done
# the four expected pairs, one fixed table (REQ-CHAIN-007-AC17): artifact (runner) -> apk architecture directory -> short name; variant -> file name pattern
pairs=()
expected=0
for row in ubuntu-24.04:x86_64:amd64 ubuntu-24.04-arm:aarch64:arm64; do
  runner="${row%%:*}"; rest="${row#*:}"; archdir="${rest%%:*}"; short="${rest#*:}"
  for variant in standard fips; do
    case $variant in standard) pat='fscache-[0-9]*-r0.apk' ;; fips) pat='fscache-fips-*-r0.apk' ;; esac
    expected=$((expected + 1))
    bf=("apks/$runner/$archdir"/$pat); rf=("rapks/$runner/$archdir"/$pat)
    [ -f "${bf[0]}" ] || die "Build has no $variant apk for $short (apks/$runner/$archdir/$pat)" 2
    [ "${#bf[@]}" = 1 ] || die "Build has ${#bf[@]} $variant apks for $short, exactly one is expected" 2
    [ -f "${rf[0]}" ] || die "Rebuild has no counterpart for ${bf[0]##*/} ($variant, $short); Build and Rebuild must produce the same apks" 2
    [ "${#rf[@]}" = 1 ] || die "Rebuild has ${#rf[@]} $variant apks for $short, exactly one is expected" 2
    [ "${bf[0]##*/}" = "${rf[0]##*/}" ] || die "Rebuild's $variant apk for $short is named ${rf[0]##*/}, Build's ${bf[0]##*/}" 2
    pairs+=("$short $variant ${bf[0]} ${rf[0]}")
  done
done
# nothing else: an .apk that is none of the four on either side is an extra (fail closed)
for d in apks rapks; do
  while read -r f; do
    ok=0
    for p in "${pairs[@]}"; do
      set -- $p
      if [ "$d" = apks ] && [ "$f" = "$3" ]; then ok=1; fi
      if [ "$d" = rapks ] && [ "$f" = "$4" ]; then ok=1; fi
    done
    [ $ok = 1 ] || die "$f is an extra apk that is none of the four expected (standard and fips, amd64 and arm64); refusing (no counterpart on the other side)" 2
  done < <(LC_ALL=C find "$d" -name '*.apk' -type f | LC_ALL=C sort)
done
# both sides come from the assembly-key build: anything else was signed by somebody else, and a signature name is not a signature
for p in "${pairs[@]}"; do
  set -- $p
  for f in "$3" "$4"; do
    sg=$(python3 -I -B bin/apk-tool.py signer "$f") || die "cannot read the signer of $f" 2
    [ "$sg" = assembly.rsa.pub ] || die "$f is signed by '$sg', not assembly.rsa.pub: Build and Rebuild must both carry the assembly key's signature" 2
    python3 -I -B bin/apk-tool.py verify "$f" build/keys/assembly.rsa.pub >/dev/null || die "the signature of $f does not verify against the committed assembly.rsa.pub: a signature name is not a signature" 2
  done
done
bad=0
for p in "${pairs[@]}"; do
  set -- $p
  python3 -I -B bin/apk-tool.py same "$3" "$4" || { echo "release-compare.sh: ${3##*/} ($2, $1) differs between Build and Rebuild" >&2; bad=1; }
done
[ $bad = 0 ] || die "Build and Rebuild disagree; no pass record was written" 1
args=()
for p in "${pairs[@]}"; do
  set -- $p
  args+=("$1" "$2" "$3" "$4" "$(python3 -I -B bin/apk-tool.py digest "$3")" "$(python3 -I -B bin/apk-tool.py digest "$4")")
done
mkdir apk-compare
python3 -I -B - apk-compare/apk-compare.json "${args[@]}" <<'PY'
import hashlib, json, os, sys
out, rest = sys.argv[1], sys.argv[2:]
def sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()
pairs = []
for i in range(0, len(rest), 6):
    arch, variant, build, rebuild, bdig, rdig = rest[i:i + 6]
    pairs.append({"arch": arch, "variant": variant, "name": os.path.basename(build), "build_sha256": sha(build), "rebuild_sha256": sha(rebuild),
                  "build_digest": bdig, "rebuild_digest": rdig})
tmp = out + ".tmp"
with open(tmp, "w") as fh:
    json.dump({"verdict": "pass", "pairs": pairs}, fh, indent=1, sort_keys=True)
    fh.write("\n")
os.rename(tmp, out)
PY
echo "compared ${#pairs[@]} apk pair(s): Build and Rebuild agree"
