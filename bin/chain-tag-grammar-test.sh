#!/usr/bin/env bash
# proves: REQ-CHAIN-004-AC19, REQ-CHAIN-007-AC14
#
# One tag grammar for every release script and check that reads a release tag (REQ-CHAIN-004-AC19). The grammar is TAG_PATTERN of
# bin/build-admit.py: vX.Y.Z or vX.Y.Z-rcN, no leading zero in any number, an rc number of at least 1, full match only (no trailing
# newline, no prefix). A Python script loads that pattern from bin/build-admit.py; a shell script or workflow step calls
# `python3 bin/build-admit.py tag-ok [--final] TAG` (exit 0 accepted, exit 1 refused; --final also refuses a -rc tag) or reads
# `python3 bin/build-admit.py tag-pattern`; none has a pattern of its own. v01.2.3, v1.2.3-rc0 and v1.2.3-rc.1 are refused by every one.
#
# Parsers, one case group each (all under bin/ unless a path says otherwise):
#   release-apks.sh release-assets.sh release-publish.sh release-sign.sh   final tags only (they read GITHUB_REF_NAME)
#   release-verify.sh                final or rc        release-metadata.py   baseline command (final)
#   release-postverify.py            final only         chain-verify.py       policy make --tag / --ref refs/tags/<tag> (final or rc)
#   marker-pr-gate.py                rc only            chain_items.py        admission-baseline (rc vs final baseline), via chain-verify.py
#   evidence-letter.py, evidence-letter-fetch.sh   final only      admission-tag-signer.py   patch tags and baseline file names
#   chain-release-shape.py           the expected tag line of release-verify.sh
#   install-scanner.sh               the govulncheck pin line
#   .github/workflows/main-candidate-rescan.yml   the jq tag tests (run with jq on sample data, from the file's own text)
# Structural cases: the tag-ok and tag-pattern commands themselves, and a scan that no listed file holds a tag regex of its own.
#
# Every case runs in a scratch folder made with mktemp -d (files are copied in, never linked); nothing is written into the tree under
# test. Fake programs stand in for what a script calls after its tag check: a script that got past the tag check is seen by a fake
# program being called (a "trip"), so a refusal is judged by what did NOT run, not by the wording of a message.
# Needs: bash, python3 with PyYAML, openssl 3, jq.
set -uo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
S=$(mktemp -d -t chain-tag-grammar.XXXXXX)
trap '[ -d "$S" ] && rm -rf -- "$S"' EXIT
pass=0; failn=0
ok()  { pass=$((pass+1)); echo "ok   $1"; }
bad() { failn=$((failn+1)); echo "FAIL $1${2:+ -> $2}"; }
check() { # check NAME STATUS [WHY]: STATUS 0 is a pass
  if [ "$2" = 0 ]; then ok "$1"; else bad "$1" "${3:-}"; fi
}
REALPY=$(command -v python3)
NL=$'\n'

# ------------------------------------------------------------------ A. the two commands of bin/build-admit.py
BA="$root/bin/build-admit.py"
mkdir -p "$S/a/bin"; cp "$BA" "$S/a/bin/build-admit.py"
tagok() { # tagok [--final] TAG: prints the exit code (stdout and stderr of the command go to $S/a/err)
  local rc=0
  (cd "$S/a" && "$REALPY" bin/build-admit.py tag-ok "$@" > /dev/null 2> "$S/a/err") || rc=$?
  echo "$rc"
}
tagcase() { # tagcase TAG WANT_ANY WANT_FINAL
  local t=$1 g
  g=$(tagok "$t");           [ "$g" = "$2" ] && ok "tag-ok accepts/refuses $(printf %q "$t"): exit $2" || bad "tag-ok $(printf %q "$t") exits $2" "exit $g: $(head -c 120 "$S/a/err" | tr '\n' ' ')"
  g=$(tagok --final "$t");   [ "$g" = "$3" ] && ok "tag-ok --final $(printf %q "$t"): exit $3" || bad "tag-ok --final $(printf %q "$t") exits $3" "exit $g: $(head -c 120 "$S/a/err" | tr '\n' ' ')"
}
tagcase v1.2.3 0 0
tagcase v0.0.0 0 0
tagcase v10.20.30 0 0
tagcase v1.2.3-rc1 0 1
tagcase v1.2.3-rc12 0 1
tagcase v01.2.3 1 1
tagcase v1.02.3 1 1
tagcase v1.2.03 1 1
tagcase v1.2.3-rc0 1 1
tagcase v1.2.3-rc01 1 1
tagcase v1.2.3-rc.1 1 1
tagcase v1.2.3-RC1 1 1
tagcase v1.2.3-rc 1 1
tagcase 1.2.3 1 1
tagcase "v1.2.3$NL" 1 1
tagcase "v1.2.3-rc1$NL" 1 1
tagcase " v1.2.3" 1 1
tagcase "xv1.2.3" 1 1
want=$("$REALPY" - "$BA" <<'PY'
import importlib.util, sys
s = importlib.util.spec_from_file_location("ba", sys.argv[1]); m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
sys.stdout.write(m.TAG_PATTERN)
PY
)
got=$(cd "$S/a" && "$REALPY" bin/build-admit.py tag-pattern 2> /dev/null); grc=$?
[ -n "$want" ] && [ "$grc" = 0 ] && [ "$got" = "$want" ] && ok "tag-pattern prints TAG_PATTERN exactly" || bad "tag-pattern prints TAG_PATTERN exactly" "exit $grc, got '$got', want '$want'"
n=$(cd "$S/a" && "$REALPY" bin/build-admit.py tag-pattern 2> /dev/null | wc -l)
[ "$n" = 1 ] && ok "tag-pattern prints one line" || bad "tag-pattern prints one line" "$n lines"

# ------------------------------------------------------------------ B. the shell release scripts (tag read from GITHUB_REF_NAME)
# A case folder holds bin/<script> and bin/build-admit.py only. python3 is a wrapper: a call that names build-admit.py runs for real,
# any other python3 call is a trip. The other programs a script would call next are trips too.
mkcase() { # mkcase NAME FILE...: scratch folder $S/c/NAME with those files of bin/ copied in; the fake programs are in its fake/
  local c=$S/c/$1; shift
  mkdir -p "$c/bin" "$c/fake" "$c/home"
  local f; for f in "$@" build-admit.py; do cp "$root/bin/$f" "$c/bin/$f"; done
  : > "$c/trips"
  printf '#!/bin/bash\nfor a in "$@"; do case "$a" in *build-admit.py) exec %s "$@";; esac; done\necho "python3 $*" >> "%s"\nexit 99\n' "$REALPY" "$c/trips" > "$c/fake/python3"
  local t; for t in crane cosign gh aws melange apk docker curl wget jq; do printf '#!/bin/bash\necho "%s $*" >> "%s"\nexit 99\n' "$t" "$c/trips" > "$c/fake/$t"; done
  chmod 0755 "$c"/fake/*
  echo "$c"
}
shrun() { # shrun CASEDIR SCRIPT TAG [VAR=VALUE...]: runs bin/SCRIPT with GITHUB_REF_NAME=TAG; sets RC, ERR
  local c=$1 sc=$2 tag=$3; shift 3
  RC=0
  (cd "$c" && env -i PATH="$c/fake:/usr/bin:/bin" HOME="$c/home" TMPDIR="$c/home" GITHUB_REF_NAME="$tag" "$@" /usr/bin/bash "bin/$sc" > "$c/out" 2> "$c/err") || RC=$?
  ERR=$(head -c 300 "$c/err" | tr '\n' ' ')
}
refused_sh() { [ "$RC" = 1 ] && [ ! -s "$1/trips" ] && grep -qi tag "$1/err"; }   # exit 1, a message about the tag, and no program of the next step was called
reached_sh() { ! refused_sh "$1"; }                                               # the tag check let the tag through
n=0
shcase() { # shcase SCRIPT KIND(final|any) ENV...: every refusal, and the controls
  local sc=$1 kind=$2 c t; shift 2
  local refuse="v01.2.3 v1.02.3 v1.2.03 v1.2.3-rc0 v1.2.3-rc.1 v1.2.3-rc01 1.2.3 v1.2.3-RC1 v1.2.3-rc"
  [ "$kind" = final ] && refuse="$refuse v1.2.3-rc1"
  for t in $refuse; do
    n=$((n+1)); c=$(mkcase "s$n" "$sc"); shrun "$c" "$sc" "$t" "$@"
    refused_sh "$c" && ok "$sc refuses $t" || bad "$sc refuses $t" "exit $RC, trips: $(tr '\n' ';' < "$c/trips" | head -c 100) err: $ERR"
  done
  n=$((n+1)); c=$(mkcase "s$n" "$sc"); shrun "$c" "$sc" "v1.2.3$NL" "$@"
  refused_sh "$c" && ok "$sc refuses a tag with a trailing newline" || bad "$sc refuses a tag with a trailing newline" "exit $RC, trips: $(tr '\n' ';' < "$c/trips" | head -c 100) err: $ERR"
  local accept="v1.2.3 v0.0.0 v10.20.30"
  [ "$kind" = any ] && accept="$accept v1.2.3-rc1 v1.2.3-rc12"
  for t in $accept; do
    n=$((n+1)); c=$(mkcase "s$n" "$sc"); shrun "$c" "$sc" "$t" "$@"
    reached_sh "$c" && ok "$sc accepts $t" || bad "$sc accepts $t" "exit $RC, the tag check refused it; err: $ERR"
  done
}
KMS='awskms:///arn:aws:kms:us-east-1:123456789012:key/0123abcd'
COMMON=(RELEASE_KMS_KEY_REF="$KMS" GH_TOKEN=g DOCKERHUB_USERNAME=u DOCKERHUB_TOKEN=t RELEASE_ROLE_ARN=arn:aws:iam::123456789012:role/r RELEASE_TOKEN_FILE=/dev/null RUNNER_TEMP="$S/c")
shcase release-apks.sh final "${COMMON[@]}"
shcase release-assets.sh final "${COMMON[@]}"
shcase release-publish.sh final "${COMMON[@]}"
shcase release-sign.sh final "${COMMON[@]}"
shcase release-verify.sh any "${COMMON[@]}"

# ------------------------------------------------------------------ C. chain-verify.py: policy make --tag / --ref (final or rc)
K=$S/keys; mkdir -p "$K"
(
  cd "$K" || exit 1
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out root.key 2> /dev/null
  openssl pkey -in root.key -pubout -out release-key-root.pub
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out rel.key 2> /dev/null
  openssl pkey -in rel.key -pubout -out rel.pub
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out rekor.key 2> /dev/null
  openssl pkey -in rekor.key -pubout -out rekor.pub
  rdig=$(openssl pkey -pubin -in rekor.pub -outform DER | sha256sum | cut -d' ' -f1)
  kid=$(openssl pkey -pubin -in rel.pub -outform DER | sha256sum | cut -d' ' -f1)
  "$REALPY" - "$kid" "$rdig" <<'PY'
import json, sys
kid, rdig = sys.argv[1:3]
json.dump({"public_key": open("rel.pub").read(), "key_id": kid, "valid_from": "2020-01-01T00:00:00Z"}, open("release-key-manifest.json", "w"), sort_keys=True, indent=1)
open("release-key-manifest.json", "a").write("\n")
json.dump({"_note": "throwaway", "rekor_sha256": rdig}, open("sigstore-trust.json", "w"))
json.dump({"repository": "owner/repo", "stages": ["build", "sign", "rebuild", "check", "release"]}, open("template.json", "w"))
PY
  openssl dgst -sha256 -sign root.key -out manifest.sig.bin release-key-manifest.json
  base64 -w0 manifest.sig.bin > release-key-manifest.sig; echo >> release-key-manifest.sig
) > "$S/keys.log" 2>&1
mkdir -p "$S/cv/bin"; cp "$root/bin/chain-verify.py" "$root/bin/chain_common.py" "$root/bin/chain_items.py" "$S/cv/bin/"
for f in "$root"/bin/*; do [ -f "$f" ] && { [ -e "$S/cv/bin/${f##*/}" ] || cp "$f" "$S/cv/bin/"; }; done
mkdir -p "$S/cv/.github/policy"; cp "$root"/.github/policy/* "$S/cv/.github/policy/"
cvrun() { # cvrun ARGS...: chain-verify.py in the scratch copy; sets RC, ERR
  RC=0; rm -f "$S/cv/policy.json"
  (cd "$S/cv" && "$REALPY" bin/chain-verify.py "$@" > "$S/cv/out" 2> "$S/cv/err") || RC=$?
  ERR=$(head -c 300 "$S/cv/err" | tr '\n' ' ')
}
polcase() { # polcase WORD VALUE (--tag | --ref): refused or made
  local how=$1 t=$2 val
  if [ "$how" = tag ]; then val=(--tag "$t"); else val=(--ref "refs/tags/$t"); fi
  cvrun policy make --template "$K/template.json" "${val[@]}" --out "$S/cv/policy.json"
}
cv_refuse() { [ "$RC" = 1 ] && [ ! -e "$S/cv/policy.json" ] && grep -q 'refused at policy' "$S/cv/err"; }
for how in tag ref; do
  for t in v01.2.3 v1.2.3-rc0 v1.2.3-rc.1 v1.02.3 v1.2.3-rc01; do
    polcase "$how" "$t"; cv_refuse && ok "chain-verify policy make --$how refuses $t" || bad "chain-verify policy make --$how refuses $t" "exit $RC: $ERR"
  done
  for t in v1.2.3 v1.2.3-rc1; do
    polcase "$how" "$t"; [ "$RC" = 0 ] && [ -s "$S/cv/policy.json" ] && ok "chain-verify policy make --$how accepts $t" || bad "chain-verify policy make --$how accepts $t" "exit $RC: $ERR"
  done
done

# chain_items.py (through chain-verify.py admission-baseline): the rc-versus-final decision for the baseline
admcase() { # admcase TAG BASELINE_VERSION: both legs agree; sets RC, ERR; $S/cv/adm-out.json is written only when accepted
  local tag=$1 bv=$2 sha=0123456789abcdef0123456789abcdef01234567
  rm -f "$S/cv/adm-out.json"
  "$REALPY" - "$tag" "$sha" "$bv" "$S/cv" <<'PY'
import json, sys
tag, sha, bv, d = sys.argv[1:5]
for n in ("a1", "a2"):
    json.dump({"tag": tag, "sha": sha, "baseline_version": bv, "baseline": "requirements/releases/%s.yaml" % bv}, open("%s/%s.json" % (d, n), "w"))
PY
  cvrun admission-baseline --admission "$S/cv/a1.json" --admission "$S/cv/a2.json" --tag "$tag" --sha "$sha" --out "$S/cv/adm-out.json"
}
for pair in "v01.2.3 v01.2.3" "v1.2.3-rc0 v1.2.3-rc0" "v1.2.3-rc.1 v1.2.3-rc.1" "v1.2.3 v01.2.0" "v1.2.3 v1.2.3-rc1" "v1.2.3-rc1 v1.2.3-rc01"; do
  set -- $pair; admcase "$1" "$2"
  [ "$RC" = 1 ] && [ ! -e "$S/cv/adm-out.json" ] && ok "chain_items admission-baseline refuses tag $1 with baseline $2" || bad "chain_items admission-baseline refuses tag $1 with baseline $2" "exit $RC: $ERR"
done
for pair in "v1.2.3 v1.2.3" "v1.2.3 v1.2.0" "v1.2.3-rc1 v1.2.3-rc1" "v1.2.3-rc12 v1.2.3-rc12" "v0.0.1 v0.0.0"; do
  set -- $pair; admcase "$1" "$2"
  [ "$RC" = 0 ] && [ -s "$S/cv/adm-out.json" ] && ok "chain_items admission-baseline accepts tag $1 with baseline $2" || bad "chain_items admission-baseline accepts tag $1 with baseline $2" "exit $RC: $ERR"
done

# ------------------------------------------------------------------ D. release-metadata.py baseline (final tag, final baseline)
mkdir -p "$S/rm/bin"; cp "$root/bin/release-metadata.py" "$root/bin/build-admit.py" "$S/rm/bin/"
for f in "$root"/bin/*.py; do [ -e "$S/rm/bin/${f##*/}" ] || cp "$f" "$S/rm/bin/"; done
rmcase() { # rmcase TAG BASELINE_VERSION; sets RC, ERR; stdout is the version on acceptance
  local tag=$1 bv=$2 sha=0123456789abcdef0123456789abcdef01234567
  "$REALPY" - "$tag" "$sha" "$bv" "$S/rm" <<'PY'
import json, sys
tag, sha, bv, d = sys.argv[1:5]
json.dump({"tag": tag, "sha": sha, "baseline_version": bv, "baseline": "requirements/releases/%s.yaml" % bv}, open(d + "/adm.json", "w"))
PY
  RC=0
  (cd "$S/rm" && "$REALPY" bin/release-metadata.py baseline --admission adm.json --tag "$tag" --commit "$sha" > out 2> err) || RC=$?
  ERR=$(head -c 300 "$S/rm/err" | tr '\n' ' ')
}
for pair in "v01.2.3 v01.2.3" "v1.2.3 v01.2.0" "v1.2.3 v1.2.03" "v1.2.3-rc1 v1.2.3-rc1"; do
  set -- $pair; rmcase "$1" "$2"
  [ "$RC" = 1 ] && [ ! -s "$S/rm/out" ] && ok "release-metadata baseline refuses tag $1 with baseline $2" || bad "release-metadata baseline refuses tag $1 with baseline $2" "exit $RC: $ERR"
done
for pair in "v1.2.3 v1.2.3" "v1.2.3 v1.2.0" "v0.0.1 v0.0.0"; do
  set -- $pair; rmcase "$1" "$2"
  [ "$RC" = 0 ] && [ "$(cat "$S/rm/out")" = "$2" ] && ok "release-metadata baseline accepts tag $1 with baseline $2" || bad "release-metadata baseline accepts tag $1 with baseline $2" "exit $RC: $ERR"
done
# manifest and list take --version vX.Y.Z; checksums takes X.Y.Z: a version the grammar refuses never gets as far as reading a file
for sub in manifest list checksums; do
  v=v01.2.3; [ "$sub" = checksums ] && v=01.2.3
  RC=0
  case $sub in
    manifest) args=(--digests d --images-dir i --items it --modules-dir m --vex-dir v --baseline-version v1.2.0 --repo-root r --version "$v" --commit 0123456789abcdef0123456789abcdef01234567 --ci-url u --workflow w --out o) ;;
    list) args=(--version "$v" --dir "$S/rm/nodir" --out "$S/rm/o") ;;
    checksums) args=(--version "$v" --digests "$S/rm/nodigests" --dist "$S/rm/nodist" --out "$S/rm/o") ;;
  esac
  (cd "$S/rm" && "$REALPY" bin/release-metadata.py "$sub" "${args[@]}" > out 2> err) || RC=$?
  [ "$RC" = 1 ] && ! grep -qE 'nodir|nodigests|nodist|No such file|is not a file|cannot read|cannot open|missing' "$S/rm/err" && ok "release-metadata $sub refuses version $v before reading any file" || bad "release-metadata $sub refuses version $v before reading any file" "exit $RC: $(head -c 200 "$S/rm/err" | tr '\n' ' ')"
done

# ------------------------------------------------------------------ E. release-postverify.py (final only; GITHUB_REF_NAME)
mkdir -p "$S/pv/bin" "$S/pv/.github/policy" "$S/pv/docs"; cp "$root/bin/release-postverify.py" "$root/bin/build-admit.py" "$S/pv/bin/"
pvcase() { # pvcase TAG: sets RC, ERR
  RC=0
  (cd "$S/pv" && env -i PATH="/usr/bin:/bin" HOME="$S/pv" GITHUB_REF_NAME="$1" "$REALPY" -I bin/release-postverify.py > out 2> err) || RC=$?
  ERR=$(head -c 300 "$S/pv/err" | tr '\n' ' ')
}
for t in v01.2.3 v1.2.3-rc0 v1.2.3-rc.1 v1.2.3-rc1 v1.2.3-rc01 "v1.2.3$NL"; do
  pvcase "$t"; [ "$RC" = 1 ] && grep -qi 'tag' "$S/pv/err" && ok "release-postverify refuses $(printf %q "$t")" || bad "release-postverify refuses $(printf %q "$t")" "exit $RC: $ERR"
done
for t in v1.2.3 v0.0.0; do
  pvcase "$t"; ! grep -qi 'refused at tag' "$S/pv/err" && ok "release-postverify accepts $t (goes on past the tag check)" || bad "release-postverify accepts $t" "exit $RC: $ERR"
done

# ------------------------------------------------------------------ F. marker-pr-gate.py (rc tags only): read_marker
mkdir -p "$S/mg/bin"; cp "$root/bin/marker-pr-gate.py" "$root/bin/build-admit.py" "$S/mg/bin/"
mgcase() { # mgcase TAG: sets RC (0 accepted, 1 refused, 2 other failure)
  mkdir -p "$S/mg/head/.github/policy"
  "$REALPY" - "$1" "$S/mg/head/.github/policy/rc-proof.json" <<'PY'
import json, sys
json.dump({"rc_tag": sys.argv[1], "run_id": "424242"}, open(sys.argv[2], "w"))
PY
  RC=0
  (cd "$S/mg" && "$REALPY" - bin/marker-pr-gate.py head <<'PY' > out 2> err
import importlib.util, sys
s = importlib.util.spec_from_file_location("gate", sys.argv[1]); g = importlib.util.module_from_spec(s); s.loader.exec_module(g)
try:
    m = g.read_marker(sys.argv[2])
except g.Refusal as e:
    print("refused: %s" % e); sys.exit(1)
print(m["rc_tag"])
PY
  ) || RC=$?
  ERR=$(head -c 200 "$S/mg/err" "$S/mg/out" | tr '\n' ' ')
}
for t in v1.2.3-rc0 v01.2.3-rc1 v1.2.3-rc.1 v1.2.3 v1.2.3-rc01 "v1.2.3-rc1$NL"; do
  mgcase "$t"; [ "$RC" = 1 ] && ok "marker-pr-gate refuses the marker tag $(printf %q "$t")" || bad "marker-pr-gate refuses the marker tag $(printf %q "$t")" "exit $RC: $ERR"
done
for t in v1.2.3-rc1 v0.3.0-rc12; do
  mgcase "$t"; [ "$RC" = 0 ] && ok "marker-pr-gate accepts the marker tag $t" || bad "marker-pr-gate accepts the marker tag $t" "exit $RC: $ERR"
done

# ------------------------------------------------------------------ G. evidence-letter.py (final only): the release folders it reads
mkdir -p "$S/el/bin"; cp "$root/bin/evidence-letter.py" "$root/bin/build-admit.py" "$S/el/bin/"
for t in v01.2.3 v1.2.3-rc1 v1.2.3-rc0 v1.2.3 v0.3.1; do
  mkdir -p "$S/el/rel/$t"; printf '{"published_at": "2026-11-04T12:00:00Z"}\n' > "$S/el/rel/$t/release.json"
done
got=$(cd "$S/el" && "$REALPY" - bin/evidence-letter.py rel 2> err <<'PY'
import importlib.util, sys
s = importlib.util.spec_from_file_location("el", sys.argv[1]); m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
print(" ".join(sorted(m.release_dates(sys.argv[2]))))
PY
)
[ "$got" = "v0.3.1 v1.2.3" ] && ok "evidence-letter reads only the final release folders (v01.2.3, v1.2.3-rc1 and v1.2.3-rc0 are not releases)" || bad "evidence-letter reads only the final release folders" "got '$got': $(head -c 150 "$S/el/err")"

# evidence-letter-fetch.sh: the jq test that picks the final releases, run from the script's own text on sample data
fragment() { # fragment FILE START_REGEX END_REGEX: the lines from the first match of START to the first later line matching END
  "$REALPY" - "$@" <<'PY'
import re, sys
f, a, b = sys.argv[1:4]
out, on = [], False
for ln in open(f).read().split("\n"):
    if not on and re.search(a, ln):
        on = True
    if on:
        out.append(ln)
        if re.search(b, ln):
            break
print("\n".join(out) if on and out and re.search(b, out[-1]) else "")
PY
}
fr=$(fragment "$root/bin/evidence-letter-fetch.sh" '^tags=\$\(jq' 'releases\.json"\)')
if [ -z "$fr" ]; then
  bad "evidence-letter-fetch.sh: the final-release jq test is found" "no 'tags=\$(jq ... releases.json\")' command in the file"
else
  mkdir -p "$S/ef/bin" "$S/ef/out"; cp "$root/bin/build-admit.py" "$S/ef/bin/"
  printf '%s\n' '[' \
    '{"tag_name":"v01.2.3","draft":false,"prerelease":false,"published_at":"2026-10-04T00:00:00Z"},' \
    '{"tag_name":"v1.2.3-rc1","draft":false,"prerelease":false,"published_at":"2026-10-05T00:00:00Z"},' \
    '{"tag_name":"v1.2.3-rc0","draft":false,"prerelease":false,"published_at":"2026-10-05T00:00:00Z"},' \
    '{"tag_name":"v1.2.3","draft":false,"prerelease":false,"published_at":"2026-10-06T00:00:00Z"},' \
    '{"tag_name":"v1.2.4","draft":false,"prerelease":false,"published_at":"2026-10-07T00:00:00Z"}' ']' > "$S/ef/out/releases.json"
  { printf 'set -euo pipefail\nmonth=2026-10\nout=%q\n' "$S/ef/out"; printf '%s\n' "$fr" 'printf "%s\n" $tags'; } > "$S/ef/run.sh"
  got=$(cd "$S/ef" && PATH="/usr/bin:/bin" bash run.sh 2> err | tr '\n' ' ')
  [ "$got" = "v1.2.3 v1.2.4 " ] && ok "evidence-letter-fetch picks only final releases (v01.2.3 and the rc tags are out)" || bad "evidence-letter-fetch picks only final releases" "got '$got': $(head -c 150 "$S/ef/err")"
fi

# ------------------------------------------------------------------ H. admission-tag-signer.py: patch tags and baseline file names
mkdir -p "$S/ts/bin" "$S/ts/base"; cp "$root/bin/admission-tag-signer.py" "$root/bin/build-admit.py" "$S/ts/bin/"
for f in v01.2.3.yaml v1.2.3.yaml v1.2.3-rc1.yaml v1.2.03.requirements.yaml v1.2.3.requirements.yaml; do printf 'version: x\n' > "$S/ts/base/$f"; done
got=$(cd "$S/ts" && "$REALPY" - bin/admission-tag-signer.py base 2> err <<'PY'
import importlib.util, sys
s = importlib.util.spec_from_file_location("ts", sys.argv[1]); m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
freeze, reqs = m._load_baselines(sys.argv[2])
print(" ".join(sorted(freeze)) + " | " + " ".join(sorted(reqs)))
PY
)
[ "$got" = "v1.2.3 | v1.2.3" ] && ok "admission-tag-signer reads only baseline files named for a grammar tag (v01.2.3.yaml, v1.2.03.requirements.yaml are skipped)" || bad "admission-tag-signer reads only baseline files named for a grammar tag" "got '$got': $(head -c 150 "$S/ts/err")"
for t in v01.2.3 v1.2.3-rc1 v1.2.3-rc.1 "v1.2.3$NL" "v0.2.1$NL"; do
  got=$(cd "$S/ts" && "$REALPY" - bin/admission-tag-signer.py "$t" 2> err <<'PY'
import importlib.util, sys
s = importlib.util.spec_from_file_location("ts", sys.argv[1]); m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
print(m.baseline(sys.argv[2], {}, {}, b"")[1])
PY
)
  case "$got" in *"not a patch tag"*) ok "admission-tag-signer: $(printf %q "$t") is not a patch tag" ;; *) bad "admission-tag-signer: $(printf %q "$t") is not a patch tag" "got '$got' $(head -c 100 "$S/ts/err")" ;; esac
done
got=$(cd "$S/ts" && "$REALPY" - bin/admission-tag-signer.py v1.2.3 2> err <<'PY'
import importlib.util, sys
s = importlib.util.spec_from_file_location("ts", sys.argv[1]); m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
print(m.baseline(sys.argv[2], {}, {}, b"")[1])
PY
)
case "$got" in *"not a patch tag"*) bad "admission-tag-signer: v1.2.3 is a patch tag" "got '$got'" ;; "") bad "admission-tag-signer: v1.2.3 is a patch tag" "no answer: $(head -c 150 "$S/ts/err")" ;; *) ok "admission-tag-signer: v1.2.3 is a patch tag" ;; esac

# ------------------------------------------------------------------ I. chain-release-shape.py: the expected tag line of release-verify.sh
# The judge's expected first command of release-verify.sh must be a line that the grammar's own command makes true: a release-verify.sh
# whose tag line is exactly the old loose line is refused by `verify`, and the file of the tree under test is accepted.
mkdir -p "$S/sh/bin"; cp "$root/bin/chain-release-shape.py" "$root/bin/build-admit.py" "$S/sh/bin/"
shaperun() { RC=0; (cd "$S/sh" && "$REALPY" bin/chain-release-shape.py verify "$1" > out 2> err) || RC=$?; ERR=$(head -c 250 "$S/sh/out" "$S/sh/err" | tr '\n' ' '); }
cp "$root/bin/release-verify.sh" "$S/sh/rv-tree.sh"
shaperun "$S/sh/rv-tree.sh"
[ "$RC" = 0 ] && ok "chain-release-shape verify accepts this tree's release-verify.sh" || bad "chain-release-shape verify accepts this tree's release-verify.sh" "exit $RC: $ERR"
"$REALPY" - "$root/bin/release-verify.sh" "$S/sh/rv-loose.sh" <<'PY'
import sys
lines = open(sys.argv[1]).read().split("\n")
i = next(k for k, l in enumerate(lines) if "GITHUB_REF_NAME" in l and "refused at tag" in l)
lines[i] = '[[ "${GITHUB_REF_NAME:-}" =~ ^v[0-9]+\\.[0-9]+\\.[0-9]+(-rc[0-9]+)?$ ]] || { echo "refused at tag: ${GITHUB_REF_NAME:-} is not vX.Y.Z or vX.Y.Z-rcN" >&2; exit 1; }'
open(sys.argv[2], "w").write("\n".join(lines))
PY
shaperun "$S/sh/rv-loose.sh"
[ "$RC" = 1 ] && ok "chain-release-shape verify refuses a release-verify.sh whose tag line is the old loose regex" || bad "chain-release-shape verify refuses the old loose tag line" "exit $RC: $ERR"
[ "$(grep -c 'build-admit.py tag-ok' "$root/bin/release-verify.sh")" -ge 1 ] && ok "release-verify.sh's tag line calls build-admit.py tag-ok" || bad "release-verify.sh's tag line calls build-admit.py tag-ok" "no such call in the file"

# ------------------------------------------------------------------ J. install-scanner.sh: the govulncheck pin line
gvcase() { # gvcase PIN: sets RC, and "built" when the fake go was asked to build
  local c=$S/gv/$1; rm -rf "$c"; mkdir -p "$c/bin" "$c/dest/fscache-go/bin" "$c/tools/govulncheck" "$c/fake"
  cp "$root/bin/install-scanner.sh" "$root/bin/build-admit.py" "$c/bin/"
  printf 'module x\n\nrequire golang.org/x/vuln %s\n' "$1" > "$c/tools/govulncheck/go.mod"
  printf 'golang.org/x/vuln h1:x\n' > "$c/tools/govulncheck/go.sum"
  printf '#!/bin/bash\ncase "$1" in version) echo "go version go1.27.4 linux/amd64";; build) echo build >> "%s/built"; exit 7;; esac\n' "$c" > "$c/dest/fscache-go/bin/go"
  chmod 0755 "$c/dest/fscache-go/bin/go"
  RC=0
  (cd "$c" && env PATH="/usr/bin:/bin" HOME="$c" TMPDIR="$c" /usr/bin/bash bin/install-scanner.sh govulncheck "$c/dest" > out 2> err) || RC=$?
  ERR=$(head -c 250 "$c/err" | tr '\n' ' ')
  GV=$c
}
for pin in v01.2.3 v1.02.3 v1.2.3-rc0 v1.2.3-rc.1; do
  gvcase "$pin"; [ "$RC" != 0 ] && [ ! -e "$GV/built" ] && ok "install-scanner refuses the govulncheck pin $pin before building" || bad "install-scanner refuses the govulncheck pin $pin before building" "exit $RC, built: $([ -e "$GV/built" ] && echo yes || echo no): $ERR"
done
for pin in v1.2.3 v0.0.0 v1.24.0; do
  gvcase "$pin"; [ -e "$GV/built" ] && ok "install-scanner accepts the govulncheck pin $pin (goes on to the build)" || bad "install-scanner accepts the govulncheck pin $pin" "exit $RC: $ERR"
done

# ------------------------------------------------------------------ K. main-candidate-rescan.yml: the jq tag tests, run on sample data
WF="$root/.github/workflows/main-candidate-rescan.yml"
mkdir -p "$S/wf/bin"; cp "$root/bin/build-admit.py" "$S/wf/bin/"
# (1) the current-release pick over `gh release list` output
fr=$(fragment "$WF" '^ *current=\$\(jq' 'releases\.json"\)')
if [ -z "$fr" ]; then
  bad "main-candidate-rescan: the current-release jq test is found" "no 'current=\$(jq ... releases.json\")' command in the workflow"
else
  printf '%s\n' '[' \
    '{"tagName":"v01.9.9","isDraft":false,"isPrerelease":false},' \
    '{"tagName":"v1.2.3-rc1","isDraft":false,"isPrerelease":false},' \
    '{"tagName":"v1.2.3-rc0","isDraft":false,"isPrerelease":false},' \
    '{"tagName":"v1.2.3-rc.1","isDraft":false,"isPrerelease":false},' \
    '{"tagName":"v1.2.3","isDraft":false,"isPrerelease":false},' \
    '{"tagName":"v1.2.10","isDraft":false,"isPrerelease":false},' \
    '{"tagName":"v1.3.0","isDraft":true,"isPrerelease":false}' ']' > "$S/wf/releases.json"
  { printf 'set -euo pipefail\nw=%q\n' "$S/wf"; printf '%s\n' "$fr" 'echo "$current"'; } > "$S/wf/cur.sh"
  got=$(cd "$S/wf" && PATH="/usr/bin:/bin" bash cur.sh 2> err)
  [ "$got" = "v1.2.10" ] && ok "main-candidate-rescan picks the current release among grammar finals only" || bad "main-candidate-rescan picks the current release among grammar finals only" "got '$got': $(head -c 150 "$S/wf/err")"
fi
# (2) the shape every rescan target must have
fr=$(fragment "$WF" 'TARGET_SHAPE=' 'jq -e "\$TARGET_SHAPE"')
if [ -z "$fr" ]; then
  bad "main-candidate-rescan: the TARGET_SHAPE jq test is found" "no TARGET_SHAPE assignment followed by jq -e \"\$TARGET_SHAPE\" in the workflow"
else
  # the lines of the fragment after the jq call (its error branch) are cut: only the verdict of the jq call is read
  head_fr=$(printf '%s\n' "$fr" | "$REALPY" -c '
import sys
t = sys.stdin.read()
i = t.index("jq -e \"$TARGET_SHAPE\"")
j = t.index("\n", i)
print(t[:j])')
  shape() { # shape RELEASE: 0 when the target shape accepts a target of that release
    local d="$S/wf/shape"; mkdir -p "$d"
    "$REALPY" - "$1" > "$d/targets.json" <<'PY'
import json, sys
print(json.dumps([{"release": sys.argv[1], "variant": "standard", "digest": "sha256:" + "a" * 64, "scanner": "trivy"}]))
PY
    { printf 'set -u\ntargets=$(cat targets.json)\n'; printf '%s\n' "$head_fr"; } > "$d/run.sh"
    (cd "$S/wf" && cd shape && mkdir -p bin; cp "$root/bin/build-admit.py" bin/; PATH="/usr/bin:/bin" bash run.sh > out 2> err < /dev/null)
  }
  for t in v01.2.3 v1.02.3 v1.2.3-rc0 v1.2.3-rc.1 v1.2.3-rc01 1.2.3; do
    shape "$t" && bad "main-candidate-rescan refuses the target release $t" "accepted" || ok "main-candidate-rescan refuses the target release $t"
  done
  for t in v1.2.3 v1.2.3-rc1 v1.2.3-rc12; do
    shape "$t" && ok "main-candidate-rescan accepts the target release $t" || bad "main-candidate-rescan accepts the target release $t" "refused: $(head -c 150 "$S/wf/shape/err")"
  done
fi

# ------------------------------------------------------------------ L. structure: no listed file holds a tag pattern of its own
# A tag regex of its own looks like v[0-9], ^v[0-9] or ^v(0|, v(0|, v(?:0|, or an rc number class -rc[...]. The files below read
# a tag; each must hold none of them and must name bin/build-admit.py (or TAG_PATTERN) as where the grammar comes from.
LISTED="bin/release-apks.sh bin/release-assets.sh bin/release-publish.sh bin/release-sign.sh bin/release-verify.sh bin/release-metadata.py
bin/release-postverify.py bin/chain-verify.py bin/marker-pr-gate.py bin/chain_items.py bin/evidence-letter.py bin/evidence-letter-fetch.sh
bin/admission-tag-signer.py bin/chain-release-shape.py bin/install-scanner.sh .github/workflows/main-candidate-rescan.yml"
for f in $LISTED; do
  if [ ! -f "$root/$f" ]; then bad "$f holds no tag pattern of its own" "file is missing"; continue; fi
  hits=$(grep -nE -e 'v\[0-9\]' -e '\^v[\[(0-9]' -e 'v\(0\|' -e 'v\(\?:0\|' -e '-rc\\?\[' -e 'rc\[0-9' -e 'rc\[1-9' -e '\[0-9\]\+\\?\.\[0-9\]\+\\?\.\[0-9\]\+' -e '\[0-9\]\+\[\.\]\[0-9\]\+\[\.\]\[0-9\]\+' "$root/$f" | cut -c1-110 | head -3 | tr '\n' ';')
  [ -z "$hits" ] && ok "$f holds no tag pattern of its own" || bad "$f holds no tag pattern of its own" "$hits"
  grep -qE 'build-admit|TAG_PATTERN' "$root/$f" && ok "$f takes the grammar from bin/build-admit.py" || bad "$f takes the grammar from bin/build-admit.py" "no mention of build-admit.py or TAG_PATTERN"
done
# a shell script and a workflow step reach the grammar only by the two commands; a Python script only by loading the file
for f in bin/release-apks.sh bin/release-assets.sh bin/release-publish.sh bin/release-sign.sh bin/release-verify.sh bin/evidence-letter-fetch.sh bin/install-scanner.sh .github/workflows/main-candidate-rescan.yml; do
  grep -qE 'build-admit\.py (tag-ok|tag-pattern)' "$root/$f" && ok "$f calls build-admit.py tag-ok or tag-pattern" || bad "$f calls build-admit.py tag-ok or tag-pattern" "no such call"
done
for f in bin/release-sign.sh bin/release-apks.sh bin/release-assets.sh bin/release-publish.sh; do
  # the final-only shell steps pass --final (the Python scripts refuse a release candidate in code; evidence-letter-fetch.sh may read tag-pattern instead)
  grep -qE 'build-admit\.py tag-ok( -[A-Za-z-]+)* --final|build-admit\.py tag-ok --final' "$root/$f" && ok "$f passes --final" || bad "$f passes --final" "no tag-ok --final call"
done

echo "pass=$pass fail=$failn"
[ "$failn" = 0 ]
