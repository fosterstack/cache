#!/usr/bin/env bash
# bin/acceptance-k8s-manifests.py substitutes the candidate image into the documented manifests and refuses unless
# each of its two image placeholders occurs exactly once (else the suite would test the published image,
# not the candidate). The docs are fixtures.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
sut="$here/acceptance-k8s-manifests.py"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
mkdir -p "$work/docs"
PH=ghcr.io/fosterstack/cache:X.Y.Z
CAND=cand:local
pass=0; fail=0
# doc <deployment yaml line(s)> <service yaml line(s)>: the four documented headings, each with one yaml block
doc() {
  printf '## Secret (credentials)\n```yaml\nkind: Secret\n```\n## PersistentVolumeClaim\n```yaml\nkind: PersistentVolumeClaim\n```\n## Deployment\n```yaml\nkind: Deployment\n%s\n```\n## Service\n```yaml\nkind: Service\n%s\n```\n' "$1" "$2" > "$work/docs/kubernetes.md"
}
check() { # name, want_rc (zero|nonzero), text the output must contain
  local out rc
  out=$(cd "$work" && CANDIDATE_LOCAL="$CAND" python3 -I "$sut" 2>&1); rc=$?
  if [ "$2" = zero ] && [ "$rc" -eq 0 ] && grep -qF -- "$3" <<<"$out"; then echo "ok: $1"; pass=$((pass+1))
  elif [ "$2" = nonzero ] && [ "$rc" -ne 0 ] && grep -qF -- "$3" <<<"$out"; then echo "ok: $1"; pass=$((pass+1))
  else echo "FAIL: $1 (rc=$rc, wanted $2 with '$3')"; echo "$out" | sed 's/^/    | /'; fail=$((fail+1)); fi
}
doc "image: $PH" "kind: x"
check "the tag placeholder exactly once passes, the image line gets imagePullPolicy Never" zero "imagePullPolicy: Never"
doc "image: $PH" "kind: x"
check "the candidate replaces the placeholder" zero "image: $CAND"
doc "image: something-else" "kind: x"
check "the tag placeholder zero times is refused" nonzero "the image placeholder must occur exactly once"
doc "image: $PH" "image: $PH"
check "the tag placeholder twice is refused" nonzero "the image placeholder must occur exactly once"
doc "env: $PH" "kind: x"
check "the image line zero times (placeholder not on an image line) is refused" nonzero \
  "the image line must occur exactly once"
doc "image: $PH" "image: $CAND"
check "the image line twice (the candidate already on another image line) is refused" nonzero \
  "the image line must occur exactly once"
echo "acceptance-k8s-manifests: $pass passed, $fail failed"; [ "$fail" -eq 0 ]
