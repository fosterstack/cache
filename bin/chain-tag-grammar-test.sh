#!/usr/bin/env bash
# proves: REQ-CHAIN-004-AC20, REQ-CHAIN-007-AC14
#
# The release tag grammar of the scripts that read a release tag: vX.Y.Z, no leading zero in any number, full match only (no trailing
# newline, no prefix). release-metadata.py, release-postverify.py and marker-pr-gate.py each hold it; chain-verify.py policy make
# takes a --tag as given (only a snapshot version v0.0.0 is refused) and a --ref as refs/tags/<non-empty> or refs/heads/<non-empty>;
# main-candidate-rescan.yml picks the current release with jq tests that are run here on sample data.
#
# Every case runs in a scratch folder made with mktemp -d (files are copied in, never linked); nothing is written into the tree under
# test.
# Needs: bash, python3 with PyYAML, openssl 3, jq.
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


# ------------------------------------------------------------------ C. chain-verify.py: policy make --tag / --ref (no grammar here: the tag is judged before, in release-verify.sh)
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
polref() { cvrun policy make --template "$K/template.json" --ref "$1" --out "$S/cv/policy.json"; }
cv_made() { # cv_made TAG DRY: policy.json exists and holds that tag (and dry_run true only for a branch)
  [ "$RC" = 0 ] && [ -s "$S/cv/policy.json" ] && "$REALPY" - "$S/cv/policy.json" "$1" "$2" <<'PY'
import json, sys
p = json.load(open(sys.argv[1]))
sys.exit(0 if p["tag"] == sys.argv[2] and bool(p.get("dry_run")) == (sys.argv[3] == "dry") else 1)
PY
}
# the grammar is not judged here: a tag is taken as given, well formed or not
for how in tag ref; do
  for t in v1.2.3 v1.2.3-rc1 v01.2.3 v1.2.3-rc0 v1.2.3-rc.1 v1.02.3 v1.2.3-rc01 not-a-tag; do
    polcase "$how" "$t"; cv_made "$t" wet && ok "chain-verify policy make --$how takes $t as given (it judges no grammar)" || bad "chain-verify policy make --$how takes $t as given" "exit $RC: $ERR"
  done
  # what is still refused: a snapshot version, whose policy can never exist (REQ-CHAIN-004-AC15)
  for t in v0.0.0 v0.0.0-rc1 v0.0.0-snapshot; do
    polcase "$how" "$t"; cv_refuse && ok "chain-verify policy make --$how refuses the snapshot version $t" || bad "chain-verify policy make --$how refuses the snapshot version $t" "exit $RC: $ERR"
  done
done
# --ref: refs/tags/<non-empty> or refs/heads/<non-empty> (the dry run); anything else is refused at policy
polref refs/heads/main; cv_made "" dry && ok "chain-verify policy make --ref refs/heads/main is the dry run (no tag)" || bad "chain-verify policy make --ref refs/heads/main is the dry run" "exit $RC: $ERR"
polref refs/heads/feature/x; cv_made "" dry && ok "chain-verify policy make --ref refs/heads/feature/x is the dry run" || bad "chain-verify policy make --ref refs/heads/feature/x is the dry run" "exit $RC: $ERR"
for r in refs/tags/ refs/heads/ refs/heads refs/tags refs/pull/1/merge v1.2.3 main "" refs/notes/v1.2.3 x/refs/tags/v1.2.3; do
  polref "$r"; cv_refuse && ok "chain-verify policy make --ref $(printf %q "$r") is refused at policy" || bad "chain-verify policy make --ref $(printf %q "$r") is refused at policy" "exit $RC: $ERR"
done


# ------------------------------------------------------------------ D. release-metadata.py baseline (the highest requirements/releases file at or below the tag)
mkdir -p "$S/rm/bin" "$S/rm/requirements/releases"; cp "$root/bin/release-metadata.py" "$S/rm/bin/"
for f in "$root"/bin/*.py; do [ -e "$S/rm/bin/${f##*/}" ] || cp "$f" "$S/rm/bin/"; done
for v in v0.2.0 v0.2.1 v1.2.0 v1.3.0; do : > "$S/rm/requirements/releases/$v.yaml"; done
rmcase() { # rmcase TAG; sets RC, ERR; stdout is the version on acceptance
  RC=0
  (cd "$S/rm" && "$REALPY" bin/release-metadata.py baseline --tag "$1" > out 2> err) || RC=$?
  ERR=$(head -c 300 "$S/rm/err" | tr '\n' ' ')
}
for pair in "v1.2.3 v1.2.0" "v1.2.0 v1.2.0" "v0.2.5 v0.2.1" "v9.0.0 v1.3.0"; do
  set -- $pair; rmcase "$1"
  [ "$RC" = 0 ] && [ "$(cat "$S/rm/out")" = "$2" ] && ok "release-metadata baseline for tag $1 is $2" || bad "release-metadata baseline for tag $1 is $2" "exit $RC: $ERR"
done
rmcase v0.1.0
[ "$RC" != 0 ] && [ ! -s "$S/rm/out" ] && ok "release-metadata baseline for a tag below every baseline prints nothing" || bad "release-metadata baseline for a tag below every baseline prints nothing" "exit $RC"

# manifest and list take --version vX.Y.Z; checksums takes X.Y.Z: a version the grammar refuses never gets as far as reading a file
for sub in manifest list checksums; do
  v=v01.2.3; [ "$sub" = checksums ] && v=01.2.3
  RC=0
  case $sub in
    manifest) args=(--digests d --images-dir i --items it --modules-dir m --vex-dir v --baseline-version v1.2.0 --repo-root r --version "$v" --commit 0123456789abcdef0123456789abcdef01234567 --ci-url u --workflow w --published-at 2026-11-04T12:00:00Z --reason r --out o) ;;
    list) args=(--version "$v" --dir "$S/rm/nodir" --out "$S/rm/o") ;;
    checksums) args=(--version "$v" --digests "$S/rm/nodigests" --dist "$S/rm/nodist" --out "$S/rm/o") ;;
  esac
  (cd "$S/rm" && "$REALPY" bin/release-metadata.py "$sub" "${args[@]}" > out 2> err) || RC=$?
  [ "$RC" = 1 ] && ! grep -qE 'nodir|nodigests|nodist|No such file|is not a file|cannot read|cannot open|missing' "$S/rm/err" && ok "release-metadata $sub refuses version $v before reading any file" || bad "release-metadata $sub refuses version $v before reading any file" "exit $RC: $(head -c 200 "$S/rm/err" | tr '\n' ' ')"
done

# ------------------------------------------------------------------ E. release-postverify.py (final only; GITHUB_REF_NAME)
mkdir -p "$S/pv/bin" "$S/pv/.github/policy" "$S/pv/docs"; cp "$root/bin/release-postverify.py" "$S/pv/bin/"
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

# ------------------------------------------------------------------ F. marker-pr-gate.py: read_marker (it refuses every marker tag)
mkdir -p "$S/mg/bin"; cp "$root/bin/marker-pr-gate.py" "$S/mg/bin/"
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

# ------------------------------------------------------------------ G. the helper that reads a command out of a workflow's own text (used by K)
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

# ------------------------------------------------------------------ K. main-candidate-rescan.yml: the jq tag tests, run on sample data
WF="$root/.github/workflows/main-candidate-rescan.yml"
mkdir -p "$S/wf"
# (1) the current-release pick over `gh release list` output
fr=$(fragment "$WF" '^ *current=\$\(jq' 'releases\.json"\)')
if [ -z "$fr" ]; then
  bad "main-candidate-rescan: the current-release jq test is found" "no 'current=\$(jq ... releases.json\")' command in the workflow"
else
  printf '%s\n' '[' \
    '{"tagName":"v1.2.3-rc1","isDraft":false,"isPrerelease":false},' \
    '{"tagName":"v1.2.3-rc0","isDraft":false,"isPrerelease":false},' \
    '{"tagName":"v1.2.3-rc.1","isDraft":false,"isPrerelease":false},' \
    '{"tagName":"v1.2.3","isDraft":false,"isPrerelease":false},' \
    '{"tagName":"v1.2.10","isDraft":false,"isPrerelease":false},' \
    '{"tagName":"v1.3.0","isDraft":true,"isPrerelease":false}' ']' > "$S/wf/releases.json"
  { printf 'set -euo pipefail\nw=%q\n' "$S/wf"; printf '%s\n' "$fr" 'echo "$current"'; } > "$S/wf/cur.sh"
  got=$(cd "$S/wf" && PATH="/usr/bin:/bin" bash cur.sh 2> err)
  [ "$got" = "v1.2.10" ] && ok "main-candidate-rescan picks the current release among the v tags that are no rc" || bad "main-candidate-rescan picks the current release among the v tags that are no rc" "got '$got': $(head -c 150 "$S/wf/err")"
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
    (cd "$S/wf/shape" && PATH="/usr/bin:/bin" bash run.sh > out 2> err < /dev/null)
  }
  for t in 1.2.3 x1.2.3; do
    shape "$t" && bad "main-candidate-rescan refuses the target release $t" "accepted" || ok "main-candidate-rescan refuses the target release $t"
  done
  for t in v1.2.3; do
    shape "$t" && ok "main-candidate-rescan accepts the target release $t" || bad "main-candidate-rescan accepts the target release $t" "refused: $(head -c 150 "$S/wf/shape/err")"
  done
fi

echo "pass=$pass fail=$failn"
[ "$failn" = 0 ]
