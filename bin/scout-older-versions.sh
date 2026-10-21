#!/usr/bin/env bash
# The Docker Scout older-versions sweep (advisor 0520; REQ-SCAN-004 AC2), dispatch-only, results to OUT/summary.md.
# Question: does an older Scout apply a LOCAL VEX file (--vex-location)? Scout 1.24.0 to 1.26.0 do not (bin/scout-root-cause.sh,
# docker/scout-cli#207). Each version in SCOUT_VERSIONS is run against four forms, one row each:
#   control-file    Docker's documented example (vexctl shape, scoutcontrol/app:v1) as a file, with --vex-author
#   control-dir     the same statement as a directory
#   ours-file       OUR statement for CVE-2023-4911 on the pinned debian 12.0 fixture (our product forms), as a file
#   exact-digest    the same fixture scanned from the registry by its exact digest, local file, our statement
# A row reads "applied" (the target finding is gone and every other finding is kept), "not applied", "inconclusive" or
# "scan exit N: ..." (the version cannot run the scan, or has no --vex-location). Read-only: nothing is published.
# Usage: scout-older-versions.sh OUT   env: SCOUT_DIR (docker-scout-<version> binaries), SCOUT_VERSIONS (space-separated)
set -uo pipefail
out=${1:?usage: pass an output directory as argument 1}
: "${SCOUT_DIR:?}" "${SCOUT_VERSIONS:?}"
mkdir -p "$out"; summ="$out/summary.md"
FIXTURE_DIGEST=sha256:60774985572749dc3c39147d43089d53e7ce17b844eebcf619d84467160217ab
FIXTURE=docker.io/library/debian@$FIXTURE_DIGEST
AUTHOR="author@example.com"; AUTHOR_RE='^author@example\.com$'
OUR_AUTHOR=$(jq -er .author .vex/fosterstack-cache.openvex.json 2>/dev/null || echo "")
OUR_AUTHOR_RE=$(python3 bin/scout-root-cause.py author-re "$OUR_AUTHOR")
CONTROL=scoutcontrol/app:v1; CONTROL_PRODUCT=pkg:docker/scoutcontrol/app@v1
OURS=ghcr.io/fosterstack/cache:selfcheck
OUR_PRODUCT="pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache"
DIGEST_PRODUCT="pkg:oci/debian@$FIXTURE_DIGEST?repository_url=docker.io/library/debian"

# the fixture must be in the local store: bin/scout-root-cause.sh pulls it (its one pinned pull) and tags it scoutcontrol/app:v1 and
# ghcr.io/fosterstack/cache:selfcheck, then stops (STAGE_ONLY); the tag-based cases scan it as local:// and never fall back to a registry lookup
STAGE_ONLY=1 PROBE_REPO=ghcr.io/fosterstack/cache-scout-probe RELEASE_TAG=none bash bin/scout-root-cause.sh "$out/stage" >/dev/null \
  || { echo "::error::cannot stage the fixture" >&2; exit 2; }
# the staging script does not stop on a failed pull: both tags must exist in the local store before any scan
docker image inspect scoutcontrol/app:v1 ghcr.io/fosterstack/cache:selfcheck >/dev/null 2>&1 || { echo "::error::the fixture is not in the local store" >&2; exit 2; }
{
  echo "# Docker Scout older-versions sweep"
  echo
  echo "Fixture: \`$FIXTURE\`. Documented author \`$AUTHOR\`; our author \`${OUR_AUTHOR:-unreadable}\`."
  echo
  echo "| Scout | control-file | control-dir | ours-file | exact-digest | local VEX applied |"
  echo "|---|---|---|---|---|---|"
} > "$summ"

for ver in $SCOUT_VERSIONS; do
  d="$out/$ver"; mkdir -p "$d"
  if ! install -m 0755 "$SCOUT_DIR/docker-scout-$ver" "$HOME/.docker/cli-plugins/docker-scout" 2>"$d/install.err" \
     || ! docker scout version > "$d/version.txt" 2>&1; then
    echo "| $ver | does not run | | | | no |" >> "$summ"; continue
  fi
  docker scout cves --format gitlab "local://$CONTROL" > "$d/before-control.json" 2> "$d/before-control.err"; rc1=$?
  docker scout cves --format gitlab "local://$OURS"    > "$d/before-ours.json"    2> "$d/before-ours.err";    rc2=$?
  docker scout cves --format gitlab "registry://$FIXTURE" > "$d/before-digest.json" 2> "$d/before-digest.err"; rc3=$?
  read -r cve purl < <(python3 bin/scout-root-cause.py pick "$d/before-control.json" 2>/dev/null) || { cve=none; purl=-; }
  [ -n "${cve:-}" ] || { cve=none; purl=-; }
  g_purl=$(jq -r '[.vulnerabilities[]? | select(.cve == "CVE-2023-4911") | .location.dependency.package.name][0] // empty' "$d/before-ours.json" 2>/dev/null)
  c1="no report (exit $rc1)"; c2=$c1; c3="no report (exit $rc2)"; c4="no report (exit $rc3)"
  # one inline scan per case (no wrapper function: advisor 0145, the pin checker must see the image argument at the call site)
  # fields: name, image, before report, report exit, author, author regex, product, CVE, package, location
  while IFS=$'\t' read -r name image before brc author are product cve purl loc; do
    res="no report (exit $brc)"; [ "$brc" = 0 ] && res="not tried (the fixture has no target finding)"
    if [ "$brc" = 0 ] && [ "$cve" != none ] && [ "$purl" != - ] && [ "$author" != - ]; then
      mkdir -p "$d/$name/vex"
      python3 bin/scout-root-cause.py doc "$author" "$product" "$cve" "$purl" "$d/$name/vex/x.vex.json"
      arg="$d/$name/vex"; [ "$loc" = file ] && arg="$d/$name/vex/x.vex.json"
      docker scout cves --format gitlab --vex-location "$arg" --vex-author "$are" "$image" > "$d/$name/after.json" 2> "$d/$name/after.err"; rc=$?
      v=$(python3 bin/scout-root-cause.py judge "$before" "$d/$name/after.json" "$cve" "$purl" 2>&1 | tail -1)
      if [ "$rc" != 0 ]; then res="scan exit $rc: $(tail -1 "$d/$name/after.err" | tr '|\n' '/ ' | cut -c1-100)"
      elif [ "$v" = suppressed ]; then res=applied
      elif [ "$v" = "not applied" ]; then res="not applied"
      else res=inconclusive; fi
    fi
    printf '%s\t%s\n' "$name" "$res" >> "$d/results.tsv"
  done < <(printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      control-file "local://$CONTROL" "$d/before-control.json" "$rc1" "$AUTHOR" "$AUTHOR_RE" "$CONTROL_PRODUCT" "$cve" "$purl" file \
      control-dir  "local://$CONTROL" "$d/before-control.json" "$rc1" "$AUTHOR" "$AUTHOR_RE" "$CONTROL_PRODUCT" "$cve" "$purl" dir \
      ours-file    "local://$OURS" "$d/before-ours.json" "$rc2" "${OUR_AUTHOR:--}" "$OUR_AUTHOR_RE" "$OUR_PRODUCT" CVE-2023-4911 "${g_purl:--}" file \
      exact-digest "registry://$FIXTURE" "$d/before-digest.json" "$rc3" "${OUR_AUTHOR:--}" "$OUR_AUTHOR_RE" "$DIGEST_PRODUCT" CVE-2023-4911 "${g_purl:--}" file)
  c1=$(awk -F'\t' '$1=="control-file"{print $2}' "$d/results.tsv"); c2=$(awk -F'\t' '$1=="control-dir"{print $2}' "$d/results.tsv")
  c3=$(awk -F'\t' '$1=="ours-file"{print $2}' "$d/results.tsv");     c4=$(awk -F'\t' '$1=="exact-digest"{print $2}' "$d/results.tsv")
  any=no; for c in "$c1" "$c2" "$c3" "$c4"; do [ "$c" = applied ] && any=YES; done
  echo "| $ver | $c1 | $c2 | $c3 | $c4 | $any |" >> "$summ"
done
cat "$summ"
