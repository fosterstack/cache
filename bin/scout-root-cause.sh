#!/usr/bin/env bash
# The Docker Scout root-cause round (advisor 0120/0121/0122; REQ-SCAN-004 AC2), dispatch-only, results to OUT/summary.md.
#   1. the attestation path first: copies of the fixture and of the latest release go to a SCRATCH package
#      (PROBE_REPO, never the release package); each gets a VEX attestation; the digests before and after are recorded
#      (rule: attaching must never change a digest customers pull); Scout scans the copies from the registry.
#   2. the matrix (bin/scout-root-cause.py cases): Docker's documented control, one field changed at a time, then our
#      forms — on Scout 1.26.0 (pinned) and the two previous minors (pinned by checksum, bin/install-scanner.sh).
# Usage: scout-root-cause.sh OUT   env: SCOUT_DIR (docker-scout-<version> binaries), PROBE_REPO, RELEASE_TAG
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
RC="$here/scout-root-cause.py"
out=${1:?usage: scout-root-cause.sh OUT}
: "${SCOUT_DIR:?}" "${PROBE_REPO:?}" "${RELEASE_TAG:?}"
mkdir -p "$out"; summ="$out/summary.md"
FIXTURE=docker.io/library/debian@sha256:60774985572749dc3c39147d43089d53e7ce17b844eebcf619d84467160217ab
AUTHOR="author@example.com"; AUTHOR_RE='^author@example\.com$'
PRED=https://openvex.dev/ns/v0.2.0

use() { install -m 0755 "$SCOUT_DIR/docker-scout-$1" "$HOME/.docker/cli-plugins/docker-scout"
        docker scout version 2>&1 | grep -m1 -i version; }
digest() { skopeo inspect --raw "docker://$1" | sha256sum | cut -c1-64; }
children() { skopeo inspect --raw "docker://$1" | jq -r '[.manifests[]? | "\(.digest) \(.annotations["vnd.docker.reference.type"] // .platform.os // "")"] | join(", ")'; }
scan() { local o=$1; shift; docker scout cves --format gitlab "$@" > "$o" 2> "$o.err"; echo $?; }

docker pull -q "$FIXTURE" >/dev/null
docker tag "$FIXTURE" scoutcontrol/app:v1
docker tag "$FIXTURE" ghcr.io/fosterstack/cache:selfcheck

{
  echo "# Docker Scout root-cause round"
  echo
  echo "Fixture: \`$FIXTURE\`. Author \`$AUTHOR\`; --vex-author \`$AUTHOR_RE\` where marked."
} > "$summ"

# --- 1. the attestation path (Scout 1.26.0) ---------------------------------------------------------------------------
use 1.26.0 >> "$summ"
a="$out/attest"; mkdir -p "$a"
echo -e "\n## 1. Attestation path (scratch package \`$PROBE_REPO\`)\n" >> "$summ"
rel_src="ghcr.io/${GITHUB_REPOSITORY:-fosterstack/cache}:${RELEASE_TAG}"
rel_digest="sha256:$(digest "$rel_src")"
skopeo copy -q --all "docker://$FIXTURE" "docker://$PROBE_REPO:control" > "$a/copy.log" 2>&1
skopeo copy -q --all "docker://${rel_src%:*}@$rel_digest" "docker://$PROBE_REPO:release" >> "$a/copy.log" 2>&1
for t in control release; do
  digest "$PROBE_REPO:$t" > "$a/$t.before"; children "$PROBE_REPO:$t" > "$a/$t.children.before"
done
scan "$a/control-before.json" "registry://$PROBE_REPO:control" > "$a/control-before.rc"
read -r cve purl < <(python3 "$RC" pick "$a/control-before.json" 2>"$a/pick.err") || true
echo "- target (control): \`${cve:-none}\` in \`${purl:-?}\`" >> "$summ"
python3 "$RC" doc "$AUTHOR" "pkg:docker/$PROBE_REPO@control" "${cve:-CVE-0000-0000}" "${purl:--}" "$a/control.vex.json"
docker scout attestation add --file "$a/control.vex.json" --predicate-type "$PRED" "$PROBE_REPO:control" > "$a/control-add.log" 2>&1
echo "- attestation add (control): exit $? — \`$(tail -1 "$a/control-add.log" | cut -c1-200)\`" >> "$summ"
scan "$a/release-before.json" "registry://$PROBE_REPO:release" > "$a/release-before.rc"
docker scout attestation add --file "$here/../.vex/fosterstack-cache.openvex.json" --predicate-type "$PRED" \
  "$PROBE_REPO:release" > "$a/release-add.log" 2>&1
echo "- attestation add (release copy, our published VEX as is): exit $? — \`$(tail -1 "$a/release-add.log" | cut -c1-200)\`" >> "$summ"
for t in control release; do
  b=$(cat "$a/$t.before"); n=$(digest "$PROBE_REPO:$t"); children "$PROBE_REPO:$t" > "$a/$t.children.after"
  echo "- $t: index digest before \`$b\`, after \`$n\` — $([ "$b" = "$n" ] && echo unchanged || echo CHANGED)" >> "$summ"
  echo "  - children before: $(cat "$a/$t.children.before")" >> "$summ"
  echo "  - children after: $(cat "$a/$t.children.after")" >> "$summ"
done
b=$(cat "$a/control.before")
for v in "tag:registry://$PROBE_REPO:control" "tag+author:registry://$PROBE_REPO:control" "original digest:registry://$PROBE_REPO@sha256:$b"; do
  k=${v%%:registry*}; ref=${v#*:}; f="$a/control-after-${k//[^a-z]/-}.json"
  extra=(); [ "$k" = "tag+author" ] && extra=(--vex-author "$AUTHOR_RE")
  rc=$(scan "$f" "${extra[@]}" "$ref")
  echo "- scan control from the registry ($k): exit $rc — $(python3 "$RC" judge "$a/control-before.json" "$f" "${cve:-CVE-0000-0000}" 2>&1 | tail -1)" >> "$summ"
done
f="$a/release-after.json"; rc=$(scan "$f" --vex-author '^FosterStack LLC$' "registry://$PROBE_REPO:release")
echo "- scan the release copy from the registry (our author): exit $rc — findings before $(jq '.vulnerabilities|length' "$a/release-before.json" 2>/dev/null), after $(jq '.vulnerabilities|length' "$f" 2>/dev/null)" >> "$summ"

# --- 2. the matrix: control, one field at a time, our forms; three Scout versions --------------------------------------
echo -e "\n## 2. Matrix\n\n| case | Scout | image | location | file | --vex-author | subcomponent | product | result |\n|---|---|---|---|---|---|---|---|---|" >> "$summ"
current=""
while IFS=$'\t' read -r id ver image loc file aflag sub product; do
  if [ "$ver" != "$current" ]; then
    use "$ver" > "$out/version-$ver.txt"; current=$ver
    for img in scoutcontrol/app:v1 ghcr.io/fosterstack/cache:selfcheck; do
      scan "$out/before-$ver-${img//[^a-z0-9]/-}.json" "$img" > /dev/null
    done
  fi
  before="$out/before-$ver-${image//[^a-z0-9]/-}.json"
  read -r cve purl < <(python3 "$RC" pick "$before" 2>/dev/null) || { cve=""; purl=""; }
  d="$out/case/$id"; mkdir -p "$d/vex"
  s="-"; [ "$sub" = 1 ] && s="$purl"
  python3 "$RC" doc "$AUTHOR" "$product" "${cve:-CVE-0000-0000}" "$s" "$d/vex/$file"
  args=(--vex-location "$d/vex"); [ "$loc" = file ] && args=(--vex-location "$d/vex/$file")
  [ "$aflag" = 1 ] && args+=(--vex-author "$AUTHOR_RE")
  rc=$(scan "$d/after.json" "${args[@]}" "$image")
  res=$(python3 "$RC" judge "$before" "$d/after.json" "${cve:-CVE-0000-0000}" 2>&1 | tail -1)
  [ "$rc" = 0 ] || res="scan exit $rc: $(tail -1 "$d/after.json.err" | cut -c1-120)"
  echo "| ${id%@*} | $ver | \`$image\` | $loc | $file | $aflag | $sub | \`$product\` | $res |" >> "$summ"
done < <(python3 "$RC" cases)
cat "$summ"
