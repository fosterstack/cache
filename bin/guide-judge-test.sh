#!/usr/bin/env bash
# proves: REQ-CHAIN-006-AC7, REQ-CHAIN-007-AC14 — Check and Release judge a guide command with ONE judge module
# (bin/guide_plan_judge.py, imported by bin/check-guide-plan.py and bin/release-postverify.py): the same plan gets
# the same verdict from both scripts. Black box: a one-command plan in, accept or refuse out. Check reads the plan
# as a guide plus its cannot-run list; Release reads the list alone and stops at its first step after the judge
# ("release-published/ is not a directory"), so reaching that step is its accept.
# Rule 79 (Oct 10): a command whose subject is a FILE and that Check cannot run is run by Release's postverify on the
# staged copy (release-published/), never listed: the cannot-run list keeps image-reference commands only. Release
# reads the guide (docs/verify-release.md, as Check does) as well as the list.
set -uo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d -t guide-judge.XXXXXX); trap 'rm -rf "$work"' EXIT
pass=0; failn=0
ok()  { pass=$((pass+1)); echo "PASS $1"; }
bad() { failn=$((failn+1)); echo "FAIL $1 -> $2"; }
A=$(printf 'a%.0s' $(seq 64))

# tree: a scratch tree with the real bin/ and policy files and the plan's one command listed (listed=0: not listed)
tree() {
  local t; t=$(mktemp -d "$work/t.XXXXXX")
  ln -s "$root/bin" "$t/bin"; ln -s "$root/.github" "$t/.github"
  mkdir "$t/docs" "$t/witness-build"
  printf '{"image-production":"sha256:%s","image-fips":"sha256:%s"}\n' "$A" "$A" > "$t/witness-build/digests.json"
  printf '%s\n' '- `<IMAGE_REF>`: the image' '- `<IMAGE_REF_FIPS>`: the fips image' '- `<TAG>`: the tag' \
    '- `<RELEASE_KEY>`: the key' '```sh' "$1" '```' > "$t/docs/verify-release.md"
  if [ "${2:-1}" = 1 ]; then
    python3 -c 'import json,sys; print(json.dumps([{"command": sys.argv[1], "reason": "needs a registry"}]))' "$1" \
      > "$t/docs/verify-release.cannot-run.json"
  else echo '[]' > "$t/docs/verify-release.cannot-run.json"; fi
  echo "$t"
}
# check_says / release_says: accept or refuse (a crash is neither: it is reported as the verdict "crash")
check_says() {
  local t=$1 tag=${2:-v0.3.0} out rc=0
  out=$(cd "$t" && GITHUB_REF_NAME=$tag python3 -I bin/check-guide-plan.py docs/verify-release.md \
    docs/verify-release.cannot-run.json "sha256:$A" plan.json "sha256:$A" 2>&1) || rc=$?
  printf '%s' "$out" > "$work/last"
  case $out in *Traceback*) echo crash;; *) [ $rc = 0 ] && echo accept || echo refuse;; esac
}
release_says() {
  local t=$1 tag=${2:-v0.3.0} out rc=0
  out=$(cd "$t" && GITHUB_REF_NAME=$tag GITHUB_REPOSITORY=fosterstack/cache python3 -I bin/release-postverify.py 2>&1) || rc=$?
  case $out in *Traceback*) echo crash;; *"is not a directory"*) echo accept;; *) echo refuse;; esac
}
# both NAME WANT COMMAND [listed]: each script, same plan, must say WANT
both() {
  local name=$1 want=$2 t v
  t=$(tree "$3" "${4:-1}"); v=$(check_says "$t")
  [ "$v" = "$want" ] && ok "check-guide-plan: $name ($want)" || bad "check-guide-plan: $name" "wanted $want, got $v"
  if [ "${4:-1}" = 1 ]; then
    v=$(release_says "$t")
    [ "$v" = "$want" ] && ok "release-postverify: $name ($want)" || bad "release-postverify: $name" "wanted $want, got $v"
  fi
}
K="--key release.rsa.pub"
B="--bundle b.json"

# the shared module is imported by both scripts (name assumed: bin/guide_plan_judge.py)
for s in check-guide-plan release-postverify; do
  grep -q 'guide_plan_judge' "$root/bin/$s.py" && ok "$s names the shared judge guide_plan_judge" \
    || bad "$s names the shared judge guide_plan_judge" "not found"
done
[ -f "$root/bin/guide_plan_judge.py" ] && ok "bin/guide_plan_judge.py exists" || bad "bin/guide_plan_judge.py exists" "missing"

# rows 37, 42: baselines the judge keeps accepting
both "plain image verify" accept "cosign verify <IMAGE_REF> $K"
both "attestation piped to a closed-grammar jq filter on stdin" accept \
  "cosign verify-attestation $K --type https://slsa.dev/provenance/v1 <IMAGE_REF> | jq -e '.payload'"
# a file subject is never listed: unlisted, Check plans it for postverify and accepts
both "check-claims=false on verify-blob-attestation" accept "cosign verify-blob-attestation $K $B --check-claims=false x.txt" 0

# row 37: shlex reads a # inside a word as a comment
both "a # inside a word" refuse "cosign verify-blob $K $B a#b"
both "a # inside a word, after a pipe" refuse "cosign verify-blob $K $B x.txt | jq -e '.ok' a#b"

# row 38: a jq segment of a verify pipe gets the closed jq grammar: no file operand, no file-reading option
V="cosign verify-blob $K $B x.txt"
both "jq with a file operand" refuse "$V | jq -e '.ok' f.json"
both "jq with --rawfile" refuse "$V | jq -e --rawfile a f.json '.ok'"
both "jq with --slurpfile" refuse "$V | jq -e --slurpfile a f.json '.ok'"
both "jq with -f" refuse "$V | jq -f prog.jq"
both "jq with --from-file" refuse "$V | jq --from-file prog.jq"
both "jq filter on stdin" accept "$V | jq -e '.ok'" 0

# row 39: a quoted or backslash-escaped operator character is refused
for q in "'a|b'" 'a\|b' '"a|b"' "'a;b'" "'a&b'" "'a>b'" 'a\;b' 'a\>b'; do
  both "an operator character in a value: $q" refuse "cosign verify <IMAGE_REF> $K --type $q"
done

# row 40: one judge for every command; <RELEASE_KEY> is accepted nowhere
both "--key <RELEASE_KEY>" refuse "cosign verify-blob --key <RELEASE_KEY> $B x.txt"
both "--key=<RELEASE_KEY>" refuse "cosign verify <IMAGE_REF> --key=<RELEASE_KEY>"
# an unlisted command runs at Check, and Check judges it with the same key and flag rules (no listed-only check)
touch "$work/fx.pub"
t=$(tree "cosign verify-blob --key fx.pub $B x.txt" 0); touch "$t/fx.pub" "$t/b.json" "$t/x.txt"
v=$(check_says "$t"); [ "$v" = refuse ] && ok "check-guide-plan: an unlisted command with another key file (refuse)" \
  || bad "check-guide-plan: an unlisted command with another key file" "got $v"
t=$(tree "cosign verify-blob $K $B --insecure-ignore-tlog=true x.txt" 0); touch "$t/release.rsa.pub" "$t/b.json" "$t/x.txt"
v=$(check_says "$t"); [ "$v" = refuse ] && ok "check-guide-plan: an unlisted command with a flag outside the set (refuse)" \
  || bad "check-guide-plan: an unlisted command with a flag outside the set" "got $v"
t=$(tree "cosign verify-blob $K $B x.txt" 0); touch "$t/release.rsa.pub" "$t/b.json" "$t/x.txt"
v=$(check_says "$t"); [ "$v" = accept ] && ok "check-guide-plan: an unlisted runnable command in the closed set (accept)" \
  || bad "check-guide-plan: an unlisted runnable command in the closed set" "got $v"

# row 41: a literal repository that is an image reference (a movable tag) is refused
both "fosterstack/cache:TAG" refuse "cosign verify fosterstack/cache:TAG $K"
both "localhost:5000/x" refuse "cosign verify localhost:5000/x $K"
both "ghcr.io/fosterstack/cache:v0.3.0" refuse "cosign verify ghcr.io/fosterstack/cache:v0.3.0 $K"
both "oci://ghcr.io/fosterstack/cache:latest" refuse "cosign verify oci://ghcr.io/fosterstack/cache:latest $K"

# row 42: --check-claims=false unties a signature from the digest: only verify-blob-attestation may carry it
both "check-claims=false on verify" refuse "cosign verify <IMAGE_REF> $K --check-claims=false"
both "check-claims=false on verify-attestation" refuse \
  "cosign verify-attestation $K --type slsa <IMAGE_REF> --check-claims=false"
both "check-claims=false on verify-blob" refuse "cosign verify-blob $K $B --check-claims=false x.txt"
both "check-claims=false on a later segment of a pipe" refuse \
  "cosign verify-blob-attestation $K $B x.txt | jq -e '.ok'; cosign verify <IMAGE_REF> $K --check-claims=false"

# rows 58, 62: a tag value is matched whole (a trailing newline is refused); the release-candidate form is -rcN
NL=$'v0.3.0\n'
t=$(tree "cosign verify-blob $K --bundle <TAG> <TAG>" 0)
touch "$t/release.rsa.pub" "$t/v0.3.0" "$t/$NL" "$t/v0.3.0-rc1" "$t/v0.3.0-rc.1"
for pair in "v0.3.0:accept" "$NL:refuse" "v0.3.0-rc1:accept" "v0.3.0-rc.1:refuse"; do
  tag=${pair%:*}; want=${pair##*:}; v=$(check_says "$t" "$tag")
  [ "$v" = "$want" ] && ok "check-guide-plan: <TAG> value ${tag@Q} ($want)" \
    || bad "check-guide-plan: <TAG> value ${tag@Q}" "wanted $want, got $v"
done
t=$(tree "cosign verify <IMAGE_REF> $K")
for tag in "$NL" "v0.3.0-rc.1"; do
  v=$(release_says "$t" "$tag")
  [ "$v" = refuse ] && ok "release-postverify: tag ${tag@Q} (refuse)" || bad "release-postverify: tag ${tag@Q}" "got $v"
done
v=$(release_says "$t" v0.3.0); [ "$v" = accept ] && ok "release-postverify: tag v0.3.0 (accept)" \
  || bad "release-postverify: tag v0.3.0" "got $v"

# ---- rule 79: a file-subject command is run by postverify before publishing, an image reference needs the list ----
# setlist TREE COMMAND...: the cannot-run list of the tree holds exactly these commands
setlist() {
  local t=$1; shift
  python3 -c 'import json,sys; print(json.dumps([{"command": c, "reason": "needs a registry"} for c in sys.argv[1:]]))' "$@" \
    > "$t/docs/verify-release.cannot-run.json"
}
# plan_says TREE: every row of plan.json is run null with the postverify reason
plan_says() {
  jq -e -s 'length > 0 and all(.[]; .run == null and (.reason | contains("run by postverify before publishing")))' \
    "$1/plan.json" > /dev/null 2>&1 && echo yes || echo no
}
for c in "cosign verify-blob $K $B x.txt" \
         "cosign verify-blob-attestation $K $B --check-claims=false x.txt" \
         "jq -e '.ok' f.json" \
         "cosign verify-blob $K $B x.txt | jq -e '.ok'"; do
  t=$(tree "$c" 0); v=$(check_says "$t")
  [ "$v" = accept ] && ok "check-guide-plan: unlisted file-subject command, file absent (accept): ${c:0:50}" \
    || bad "check-guide-plan: unlisted file-subject command, file absent: ${c:0:50}" "got $v: $(head -c 120 "$work/last")"
  [ "$(plan_says "$t")" = yes ] && ok "check-guide-plan: its plan row says run by postverify before publishing, run null" \
    || bad "check-guide-plan: plan row of ${c:0:50}" "$(head -c 200 "$t/plan.json" 2>&1)"
done
# an image reference is not a file subject: unlisted, it still fails
for c in "cosign verify <IMAGE_REF> $K" "cosign verify <IMAGE_REF_FIPS> $K" \
         "cosign verify-attestation $K --type slsa <IMAGE_REF>" "cosign verify oci://ghcr.io/fosterstack/cache@sha256:$A $K" \
         "cosign verify ghcr.io/fosterstack/cache@sha256:$A $K"; do
  t=$(tree "$c" 0); v=$(check_says "$t")
  [ "$v" = refuse ] && ok "check-guide-plan: unlisted image-reference command (refuse): ${c:0:50}" \
    || bad "check-guide-plan: unlisted image-reference command: ${c:0:50}" "got $v"
done
# anything else with a non-local operand fails closed
for c in "gh release download <TAG> --pattern x.txt" "curl -sSf x.txt" "cosign sign x.txt" \
         "cosign verify-blob $K $B x.txt | jq -e '.ok' f.json" "cosign verify-blob $K $B --insecure-ignore-tlog x.txt"; do
  t=$(tree "$c" 0); v=$(check_says "$t")
  [ "$v" = refuse ] && ok "check-guide-plan: non-local operand of another kind fails closed: ${c:0:50}" \
    || bad "check-guide-plan: non-local operand of another kind: ${c:0:50}" "got $v"
done
# a guide mixing both kinds: the image command is listed, the file command is planned for postverify
IMG="cosign verify <IMAGE_REF> $K"; FILEC="cosign verify-blob $K $B x.txt"
t=$(tree "$IMG" 0); printf '%s\n' '```sh' "$FILEC" '```' >> "$t/docs/verify-release.md"; setlist "$t" "$IMG"
v=$(check_says "$t"); [ "$v" = accept ] && ok "check-guide-plan: listed image command beside a file command (accept)" \
  || bad "check-guide-plan: listed image command beside a file command" "got $v: $(head -c 120 "$work/last")"
[ "$(jq -s '[.[] | select(.run == null)] | length' "$t/plan.json" 2>/dev/null)" = 2 ] \
  && ok "check-guide-plan: both rows of the mixed guide have run null" || bad "check-guide-plan: mixed guide rows" "not two null rows"

# the list keeps image-reference commands only: a file-subject entry is refused, naming the entry (Check and guidelist)
GL="bin/chain-check-shape.py guidelist docs/verify-release.md"
VB="cosign verify-blob --key release.rsa.pub --bundle x.bundle x"
for c in "$VB" "cosign verify-blob-attestation --key release.rsa.pub --bundle x.bundle --check-claims=false" \
         "jq -e '.ok' x.bundle"; do
  t=$(tree "$c" 1); v=$(check_says "$t")
  [ "$v" = refuse ] && [[ $(cat "$work/last") == *"$c"* ]] && ok "check-guide-plan: a file-subject cannot-run entry is refused by name: ${c:0:50}" \
    || bad "check-guide-plan: a file-subject cannot-run entry: ${c:0:50}" "got $v: $(head -c 160 "$work/last")"
  rc=0; g=$(cd "$t" && python3 -I $GL 2>&1) || rc=$?
  [ "$rc" != 0 ] && [[ $g == *"$c"* ]] && ok "guidelist: a file-subject cannot-run entry is refused by name: ${c:0:50}" \
    || bad "guidelist: a file-subject cannot-run entry: ${c:0:50}" "rc=$rc: ${g:0:160}"
done
for c in "cosign verify <IMAGE_REF> $K" "cosign verify <IMAGE_REF_FIPS> $K"; do
  t=$(tree "$c" 1); rc=0; g=$(cd "$t" && python3 -I $GL 2>&1) || rc=$?
  [ "$rc" = 0 ] && [ "$g" = ok ] && ok "guidelist: an image-reference cannot-run entry is accepted: ${c:0:50}" \
    || bad "guidelist: an image-reference cannot-run entry: ${c:0:50}" "rc=$rc: ${g:0:160}"
done

# the real tree: the real guide with the real list (image-reference commands only) plans with exit 0
rt=$(mktemp -d "$work/real.XXXXXX"); rc=0
(cd "$root" && GITHUB_REF_NAME=v0.3.0 python3 -I bin/check-guide-plan.py docs/verify-release.md docs/verify-release.cannot-run.json \
  "sha256:$A" "$rt/plan.json" "sha256:$A") > "$rt/out" 2>&1 || rc=$?
[ "$rc" = 0 ] && ok "check-guide-plan: the real guide with the real list plans (accept)" \
  || bad "check-guide-plan: the real guide with the real list" "rc=$rc: $(head -c 200 "$rt/out")"
rc=0; g=$(cd "$root" && python3 -I $GL 2>&1) || rc=$?
[ "$rc" = 0 ] && ok "guidelist: the real list is accepted" || bad "guidelist: the real list" "rc=$rc: ${g:0:200}"
jq -e 'length > 0 and all(.[]; .command | test("<IMAGE_REF(_FIPS)?>"))' "$root/docs/verify-release.cannot-run.json" > /dev/null \
  && ok "the real list holds only image-reference commands" || bad "the real list holds only image-reference commands" "a file command is listed"

# release-postverify reads the guide too (docs/verify-release.md in the cwd, beside the list; no new argument) and
# runs EVERY file-subject command of it in the staged copy: a file such a command names that release-published/
# does not hold fails the run (exit 1), naming the file. The list is empty in these cases: the guide alone decides.
for pair in "cosign verify-blob $K $B absent.txt:absent.txt" "cosign verify-blob $K --bundle absent.bundle other.txt:absent.bundle" \
            "jq -e '.ok' absent.json:absent.json"; do
  cmd=${pair%:*}; file=${pair##*:}
  t=$(tree "$cmd" 0); mkdir "$t/release-published"; : > "$t/release-published/other.txt"
  rc=0; out=$(cd "$t" && GITHUB_REF_NAME=v0.3.0 GITHUB_REPOSITORY=fosterstack/cache python3 -I bin/release-postverify.py 2>&1) || rc=$?
  [ "$rc" = 1 ] && [[ $out == *"$file"* ]] && [[ $out != *Traceback* ]] \
    && ok "release-postverify: a guide file absent from release-published/ fails naming it: $file" \
    || bad "release-postverify: absent file $file" "rc=$rc: ${out:0:200}"
done
# an image-only guide with an image-only list behaves as before: it reaches the staged-copy step
t=$(tree "cosign verify <IMAGE_REF> $K" 1); v=$(release_says "$t")
[ "$v" = accept ] && ok "release-postverify: an image-only guide with an image-only list is judged as before (accept)" \
  || bad "release-postverify: image-only guide and list" "got $v"

echo "guide-judge-test: $pass passed, $failn failed"
[ "$failn" = 0 ]
