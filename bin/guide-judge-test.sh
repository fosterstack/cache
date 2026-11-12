#!/usr/bin/env bash
# proves: REQ-CHAIN-006-AC7, REQ-CHAIN-007-AC14 — Check and Release judge a guide command with ONE judge module
# (bin/guide_plan_judge.py, imported by bin/check-guide-plan.py and bin/release-postverify.py): the same plan gets
# the same verdict from both scripts. Black box: a one-command plan in, accept or refuse out. Check reads the plan
# as a guide plus its cannot-run list; Release reads the list alone and stops at its first step after the judge
# ("release-published/ is not a directory"), so reaching that step is its accept.
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
both "check-claims=false on verify-blob-attestation" accept "cosign verify-blob-attestation $K $B --check-claims=false x.txt"

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
both "jq filter on stdin" accept "$V | jq -e '.ok'"

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

echo "guide-judge-test: $pass passed, $failn failed"
[ "$failn" = 0 ]
