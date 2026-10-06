#!/usr/bin/env bash
# The Docker Scout root-cause round (advisor 0120/0121/0122; REQ-SCAN-004 AC2), dispatch-only, results to OUT/summary.md.
#   1. the attestation path first: copies of the fixture and of the latest release go to a SCRATCH package
#      (PROBE_REPO, never the release package); each gets a VEX attestation; the digests before and after are recorded
#      (rule: attaching must never change a digest customers pull); Scout scans the copies from the registry.
#   2. the matrix (bin/scout-root-cause.py cases): Docker's documented control, one field changed at a time, then our
#      forms — on Scout 1.26.0 (pinned) and the two previous minors (pinned by checksum, bin/install-scanner.sh).
# Usage: scout-root-cause.sh OUT   env: SCOUT_DIR (docker-scout-<version> binaries), PROBE_REPO, RELEASE_TAG
set -uo pipefail
# bin/scout-root-cause.py is invoked by its literal, committed path below, not through a $(dirname "$0")-resolved
# variable -- the only caller (main-candidate-rescan.yml) always runs this from the repo root, and a literal path
# is what a static reader (the pin checker; Codex #164) can see without resolving a variable (advisor 0145)
here=$(cd "$(dirname "$0")" && pwd)
out=${1:?usage: pass an output directory as argument 1}
: "${SCOUT_DIR:?}" "${PROBE_REPO:?}" "${RELEASE_TAG:?}"
# the only package this round writes is the scratch one; the release package is read, never written (Sonnet #176 r1, F1)
[ "$PROBE_REPO" = ghcr.io/fosterstack/cache-scout-probe ] || { echo "::error::refusing to write to ${PROBE_REPO}" >&2; exit 2; }
mkdir -p "$out"; summ="$out/summary.md"
FIXTURE=docker.io/library/debian@sha256:60774985572749dc3c39147d43089d53e7ce17b844eebcf619d84467160217ab
AUTHOR="author@example.com"; AUTHOR_RE='^author@example\.com$'
PRED=https://openvex.dev/ns/v0.2.0

use() { install -m 0755 "$SCOUT_DIR/docker-scout-$1" "$HOME/.docker/cli-plugins/docker-scout"
        docker scout version 2>&1 | grep -m1 -i version; }
# Codex #176 r2, B4: a failed read must never produce sha256("") and be mistaken for a real, unchanged digest
digest() { local raw; raw=$(skopeo inspect --raw "docker://$1" 2>/dev/null) && [ -n "$raw" ] \
             && printf '%s' "$raw" | sha256sum | cut -c1-64 || echo READ-FAILED; }
children() { skopeo inspect --raw "docker://$1" | jq -r '[.manifests[]? | "\(.digest) \(.annotations["vnd.docker.reference.type"] // .platform.os // "")"] | join(", ")'; }
# the scan() wrapper this replaced forwarded "$@" into `docker scout cves`, hiding the real image argument from
# every call site behind a function boundary a static reader cannot see through; each call below is now inlined
# instead (advisor 0145: no behavior change, just no wrapper) -- same docker invocation, same redirects, same
# exit-code capture, at the call site where the real image argument is already visible as plain text

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
docker scout cves --format gitlab "registry://$PROBE_REPO:control" > "$a/control-before.json" 2> "$a/control-before.json.err"
echo $? > "$a/control-before.rc"
read -r cve purl < <(python3 bin/scout-root-cause.py pick "$a/control-before.json" 2>"$a/pick.err") || true
[ "$cve" = none ] && cve="" && purl=""
echo "- target (control): \`${cve:-none}\` in \`${purl:-?}\`" >> "$summ"
python3 bin/scout-root-cause.py doc "$AUTHOR" "pkg:docker/$PROBE_REPO@control" "${cve:-CVE-0000-0000}" "${purl:--}" "$a/control.vex.json"
docker scout attestation add --file "$a/control.vex.json" --predicate-type "$PRED" "$PROBE_REPO:control" > "$a/control-add.log" 2>&1
echo "- attestation add (control): exit $? — \`$(tail -1 "$a/control-add.log" | cut -c1-200)\`" >> "$summ"
docker scout cves --format gitlab "registry://$PROBE_REPO:release" > "$a/release-before.json" 2> "$a/release-before.json.err"
echo $? > "$a/release-before.rc"
docker scout attestation add --file "$here/../.vex/fosterstack-cache.openvex.json" --predicate-type "$PRED" \
  "$PROBE_REPO:release" > "$a/release-add.log" 2>&1
echo "- attestation add (release copy, our published VEX as is): exit $? — \`$(tail -1 "$a/release-add.log" | cut -c1-200)\`" >> "$summ"
for t in control release; do
  b=$(cat "$a/$t.before"); n=$(digest "$PROBE_REPO:$t"); children "$PROBE_REPO:$t" > "$a/$t.children.after"
  if [ "$b" = READ-FAILED ] || [ "$n" = READ-FAILED ]; then status="inconclusive (a read failed)"
  elif [ "$b" = "$n" ]; then status=unchanged; else status=CHANGED; fi
  echo "- $t: index digest before \`$b\`, after \`$n\` — $status" >> "$summ"
  echo "  - children before: $(cat "$a/$t.children.before")" >> "$summ"
  echo "  - children after: $(cat "$a/$t.children.after")" >> "$summ"
done
b=$(cat "$a/control.before")
for v in "tag:registry://$PROBE_REPO:control" "tag+author:registry://$PROBE_REPO:control" "original digest:registry://$PROBE_REPO@sha256:$b"; do
  k=${v%%:registry*}; ref=${v#*:}; f="$a/control-after-${k//[^a-z]/-}.json"
  extra=(); [ "$k" = "tag+author" ] && extra=(--vex-author "$AUTHOR_RE")
  docker scout cves --format gitlab "${extra[@]}" "$ref" > "$f" 2> "$f.err"; rc=$?
  echo "- scan control from the registry ($k): exit $rc — $(python3 bin/scout-root-cause.py judge "$a/control-before.json" "$f" "${cve:-CVE-0000-0000}" "${purl:--}" 2>&1 | tail -1)" >> "$summ"
done
f="$a/release-after.json"
docker scout cves --format gitlab --vex-author '^FosterStack LLC$' "registry://$PROBE_REPO:release" > "$f" 2> "$f.err"; rc=$?
echo "- scan the release copy from the registry (our author): exit $rc — findings before $(jq '.vulnerabilities|length' "$a/release-before.json" 2>/dev/null), after $(jq '.vulnerabilities|length' "$f" 2>/dev/null)" >> "$summ"

# --- 1b. OUR statement, attached to a fixture that HAS the target (advisor 0202): the control above proved the attestation path
# applies a statement of the documented shape; this proves it for OUR author and OUR product forms. The target is CVE-2023-4911 in
# the fixture's glibc (the rescan self-check's own target). Each form gets its own scratch tag (an attestation cannot be removed);
# scanned by tag with --vex-author for OUR published author. A fixture without the target records that and tries nothing.
OUR_AUTHOR=$(jq -er .author "$here/../.vex/fosterstack-cache.openvex.json" 2>/dev/null || echo "")
OUR_AUTHOR_RE=$(python3 bin/scout-root-cause.py author-re "$OUR_AUTHOR")
g_purl=$(jq -r '[.vulnerabilities[]? | select(.cve == "CVE-2023-4911") | .location.dependency.package.name][0] // empty' "$a/control-before.json" 2>/dev/null)
echo "- our statement on the fixture's CVE-2023-4911 (author \`${OUR_AUTHOR:-unreadable}\`, package \`${g_purl:-absent from the fixture report}\`):" >> "$summ"
if [ -n "$OUR_AUTHOR" ] && [ -n "$g_purl" ]; then
  for form in "published:pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache" "probe-tag:pkg:docker/$PROBE_REPO@ours-probe-tag"; do
    k=${form%%:*}; prod=${form#*:}; tag="ours-$k"
    skopeo copy -q --all "docker://$FIXTURE" "docker://$PROBE_REPO:$tag" >> "$a/copy.log" 2>&1
    python3 bin/scout-root-cause.py doc "$OUR_AUTHOR" "$prod" CVE-2023-4911 "$g_purl" "$a/$tag.vex.json"
    docker scout attestation add --file "$a/$tag.vex.json" --predicate-type "$PRED" "$PROBE_REPO:$tag" > "$a/$tag-add.log" 2>&1
    echo "  - $k (product \`$prod\`): attestation add exit $? — \`$(tail -1 "$a/$tag-add.log" | cut -c1-160)\`" >> "$summ"
    f="$a/$tag-after.json"
    docker scout cves --format gitlab --vex-author "$OUR_AUTHOR_RE" "registry://$PROBE_REPO:$tag" > "$f" 2> "$f.err"; rc=$?
    echo "  - $k scanned by tag with --vex-author: exit $rc — $(python3 bin/scout-root-cause.py judge "$a/control-before.json" "$f" CVE-2023-4911 "$g_purl" 2>&1 | tail -1)" >> "$summ"
  done
fi

# --- 2. the matrix: control, one field at a time, our forms; three Scout versions --------------------------------------
echo -e "\n## 2. Matrix\n\n| case | Scout | image | location | file | --vex-author | subcomponent | product | result |\n|---|---|---|---|---|---|---|---|---|" >> "$summ"
current=""
while IFS=$'\t' read -r id ver image loc file aflag sub product; do
  if [ "$ver" != "$current" ]; then
    use "$ver" > "$out/version-$ver.txt"; current=$ver
    for img in scoutcontrol/app:v1 ghcr.io/fosterstack/cache:selfcheck; do
      f="$out/before-$ver-${img//[^a-z0-9]/-}.json"
      docker scout cves --format gitlab "$img" > "$f" 2> "$f.err"
    done
  fi
  before="$out/before-$ver-${image//[^a-z0-9]/-}.json"
  read -r cve purl < <(python3 bin/scout-root-cause.py pick "$before" 2>/dev/null) || { cve=""; purl=""; }
  [ "$cve" = none ] && cve="" && purl=""
  d="$out/case/$id"; mkdir -p "$d/vex"
  s="-"; [ "$sub" = 1 ] && s="$purl"
  python3 bin/scout-root-cause.py doc "$AUTHOR" "$product" "${cve:-CVE-0000-0000}" "$s" "$d/vex/$file"
  args=(--vex-location "$d/vex"); [ "$loc" = file ] && args=(--vex-location "$d/vex/$file")
  [ "$aflag" = 1 ] && args+=(--vex-author "$AUTHOR_RE")
  docker scout cves --format gitlab "${args[@]}" "$image" > "$d/after.json" 2> "$d/after.json.err"; rc=$?
  res=$(python3 bin/scout-root-cause.py judge "$before" "$d/after.json" "${cve:-CVE-0000-0000}" "${purl:--}" 2>&1 | tail -1)
  [ "$rc" = 0 ] || res="scan exit $rc: $(tail -1 "$d/after.json.err" | cut -c1-120)"
  echo "| ${id%@*} | $ver | \`$image\` | $loc | $file | $aflag | $sub | \`$product\` | $res |" >> "$summ"
done < <(python3 bin/scout-root-cause.py cases)
cat "$summ"
