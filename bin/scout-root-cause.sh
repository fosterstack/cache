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
# Codex probe r1, B2: the raw manifest bytes are hashed from a FILE; a shell substitution would strip trailing newlines, so a copy that
# appended one would keep the same "digest"
digest() { local t; t=$(mktemp) || { echo READ-FAILED; return; }
  if skopeo inspect --raw "docker://$1" > "$t" 2>/dev/null && [ -s "$t" ]; then sha256sum "$t" | cut -c1-64; else echo READ-FAILED; fi
  rm -f "$t"
}
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

# advisor 0214: the post-attachment index scanned by its EXACT new digest (attaching changes the index digest, so the attestation has
# to be in the index BEFORE signing; the question is whether Scout applies a statement when it is given that digest, not a tag)
for t in control release; do
  nd=$(digest "$PROBE_REPO:$t"); f="$a/$t-after-exact-digest.json"; extra=(--vex-author "$AUTHOR_RE"); [ "$t" = release ] && extra=(--vex-author '^FosterStack LLC$')
  if [ "$nd" = READ-FAILED ]; then echo "- scan $t by its exact post-attachment digest: inconclusive (the digest could not be read)" >> "$summ"; continue; fi
  if [ "$nd" = "$(cat "$a/$t.before")" ]; then echo "- scan $t by its exact post-attachment digest: inconclusive (attaching did not change the index digest, so there is no post-attachment digest to scan)" >> "$summ"; continue; fi
  docker scout cves --format gitlab "${extra[@]}" "registry://$PROBE_REPO@sha256:$nd" > "$f" 2> "$f.err"; rc=$?
  if [ "$t" = control ]; then verdict=$(python3 bin/scout-root-cause.py judge "$a/control-before.json" "$f" "${cve:-CVE-0000-0000}" "${purl:--}" 2>&1 | tail -1)
  else verdict="findings before $(jq '.vulnerabilities|length' "$a/release-before.json" 2>/dev/null), after $(jq '.vulnerabilities|length' "$f" 2>/dev/null)"; fi
  echo "- scan $t by its exact post-attachment digest \`sha256:$nd\` with --vex-author: exit $rc — $verdict" >> "$summ"
done
docker scout attestation list "registry://$PROBE_REPO:release" > "$a/release-attestation-list.txt" 2>&1
echo "- release copy attestation list: \`$(head -c 300 "$a/release-attestation-list.txt" | tr '\n' ' ')\`" >> "$summ"

# --- 1b. OUR statement, attached to a fixture that HAS the target (advisor 0202): the control above proved the attestation path
# applies a statement of the documented shape; this proves it for OUR author and OUR product forms. The target is CVE-2023-4911 in
# the fixture's glibc (the rescan self-check's own target). Each form gets its own scratch tag (an attestation cannot be removed);
# scanned by tag with --vex-author for OUR published author. A fixture without the target records that and tries nothing.
# a missing, null or empty author is "" (jq -er .author would print the string null), which every section below records as not usable
OUR_AUTHOR=$(jq -er 'select((.author | type) == "string" and (.author | length) > 0) | .author' "$here/../.vex/fosterstack-cache.openvex.json" 2>/dev/null || echo "")
OUR_AUTHOR_RE=$(python3 bin/scout-root-cause.py author-re "$OUR_AUTHOR")
g_purl=$(jq -r '[.vulnerabilities[]? | select(.cve == "CVE-2023-4911") | .location.dependency.package.name][0] // empty' "$a/control-before.json" 2>/dev/null)
echo "- our statement on the fixture's CVE-2023-4911 (author \`${OUR_AUTHOR:-unreadable}\`, package \`${g_purl:-absent from the fixture report}\`):" >> "$summ"
if [ -n "$OUR_AUTHOR" ] && [ -n "$g_purl" ]; then
  for form in "published:pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache" "probe-tag:pkg:docker/$PROBE_REPO@ours-probe-tag"; do
    k=${form%%:*}; prod=${form#*:}; tag="ours-$k"
    skopeo copy -q --all "docker://$FIXTURE" "docker://$PROBE_REPO:$tag" >> "$a/copy.log" 2>&1
    before_d=$(digest "$PROBE_REPO:$tag")
    python3 bin/scout-root-cause.py doc "$OUR_AUTHOR" "$prod" CVE-2023-4911 "$g_purl" "$a/$tag.vex.json"
    docker scout attestation add --file "$a/$tag.vex.json" --predicate-type "$PRED" "$PROBE_REPO:$tag" > "$a/$tag-add.log" 2>&1
    echo "  - $k (product \`$prod\`): attestation add exit $? — \`$(tail -1 "$a/$tag-add.log" | cut -c1-160)\`" >> "$summ"
    f="$a/$tag-after.json"
    docker scout cves --format gitlab --vex-author "$OUR_AUTHOR_RE" "registry://$PROBE_REPO:$tag" > "$f" 2> "$f.err"; rc=$?
    echo "  - $k scanned by tag with --vex-author: exit $rc — $(python3 bin/scout-root-cause.py judge "$a/control-before.json" "$f" CVE-2023-4911 "$g_purl" 2>&1 | tail -1)" >> "$summ"
    nd=$(digest "$PROBE_REPO:$tag"); f="$a/$tag-after-exact-digest.json"
    if [ "$nd" = READ-FAILED ] || [ "$before_d" = READ-FAILED ]; then echo "  - $k by its exact post-attachment digest: inconclusive (a digest could not be read)" >> "$summ"
    elif [ "$nd" = "$before_d" ]; then echo "  - $k by its exact post-attachment digest: inconclusive (attaching did not change the index digest)" >> "$summ"
    else
      docker scout cves --format gitlab --vex-author "$OUR_AUTHOR_RE" "registry://$PROBE_REPO@sha256:$nd" > "$f" 2> "$f.err"; rc=$?
      echo "  - $k scanned by its exact post-attachment digest \`sha256:$nd\` with --vex-author: exit $rc — $(python3 bin/scout-root-cause.py judge "$a/control-before.json" "$f" CVE-2023-4911 "$g_purl" 2>&1 | tail -1)" >> "$summ"
    fi
  done
fi

# --- 1c. a MULTI-PLATFORM index with the target (advisor 0214, probe 2): the release is an index, and attaching to one did not change its
# digest (Scout attached to a platform child). Debian 12.0's manifest list: its amd64 child IS the fixture above. A scratch copy gets our
# statement (published product form); the index digest and children are recorded before and after, then the index is scanned by tag and by
# exact digest and the amd64 child by digest, all with our author, and the attestations are listed. A fixture without the target tries nothing.
MULTI=sha256:3d868b5eb908155f3784317b3dda2941df87bbbbaa4608f84881de66d9bb297b
CHILD=sha256:60774985572749dc3c39147d43089d53e7ce17b844eebcf619d84467160217ab
echo -e "\n### 1c. multi-platform index (scratch tag \`multi\`, debian 12.0 manifest list \`$MULTI\`)\n" >> "$summ"
if [ -n "$OUR_AUTHOR" ] && [ -n "$g_purl" ]; then
  skopeo copy -q --all "docker://docker.io/library/debian@$MULTI" "docker://$PROBE_REPO:multi" >> "$a/copy.log" 2>&1
  mb=$(digest "$PROBE_REPO:multi"); children "$PROBE_REPO:multi" > "$a/multi.children.before"
  python3 bin/scout-root-cause.py doc "$OUR_AUTHOR" "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache" CVE-2023-4911 "$g_purl" "$a/multi.vex.json"
  docker scout attestation add --file "$a/multi.vex.json" --predicate-type "$PRED" "$PROBE_REPO:multi" > "$a/multi-add.log" 2>&1
  echo "- multi-platform index: attestation add exit $? — \`$(tail -1 "$a/multi-add.log" | cut -c1-160)\`" >> "$summ"
  mn=$(digest "$PROBE_REPO:multi"); children "$PROBE_REPO:multi" > "$a/multi.children.after"
  if [ "$mb" = READ-FAILED ] || [ "$mn" = READ-FAILED ]; then mstat="inconclusive (a read failed)"; elif [ "$mb" = "$mn" ]; then mstat=unchanged; else mstat=CHANGED; fi
  echo "- multi-platform index digest before \`$mb\`, after \`$mn\` — $mstat" >> "$summ"
  echo "  - children before: $(cat "$a/multi.children.before")" >> "$summ"
  echo "  - children after: $(cat "$a/multi.children.after")" >> "$summ"
  f="$a/multi-after-tag.json"
  docker scout cves --format gitlab --vex-author "$OUR_AUTHOR_RE" "registry://$PROBE_REPO:multi" > "$f" 2> "$f.err"; rc=$?
  echo "- multi-platform index scanned by tag with --vex-author: exit $rc — $(python3 bin/scout-root-cause.py judge "$a/control-before.json" "$f" CVE-2023-4911 "$g_purl" 2>&1 | tail -1)" >> "$summ"
  if [ "$mn" != READ-FAILED ]; then
    f="$a/multi-after-index-digest.json"
    docker scout cves --format gitlab --vex-author "$OUR_AUTHOR_RE" "registry://$PROBE_REPO@sha256:${mn}" > "$f" 2> "$f.err"; rc=$?
    echo "- multi-platform index scanned by its exact digest \`sha256:$mn\` with --vex-author: exit $rc — $(python3 bin/scout-root-cause.py judge "$a/control-before.json" "$f" CVE-2023-4911 "$g_purl" 2>&1 | tail -1)" >> "$summ"
  fi
  f="$a/multi-after-child-digest.json"
  docker scout cves --format gitlab --vex-author "$OUR_AUTHOR_RE" "registry://$PROBE_REPO@$CHILD" > "$f" 2> "$f.err"; rc=$?
  echo "- multi-platform amd64 child scanned by its digest \`$CHILD\` with --vex-author: exit $rc — $(python3 bin/scout-root-cause.py judge "$a/control-before.json" "$f" CVE-2023-4911 "$g_purl" 2>&1 | tail -1)" >> "$summ"
  docker scout attestation list "registry://$PROBE_REPO:multi" > "$a/multi-attestation-list.txt" 2>&1
  echo "- multi-platform attestation list: \`$(head -c 400 "$a/multi-attestation-list.txt" | tr '\n' ' ')\`" >> "$summ"
else
  echo "- not tried: the fixture does not carry CVE-2023-4911" >> "$summ"
fi

# --- 1d. the attestation-manifest child BUILT into a multi-platform index (advisor 0221, probe 3) -----------------------------------
# Scout's own attach to an index stores nothing it can read (1c). Scout DOES rewrite a single image into an index with an
# attestation-manifest child (1/1b), so: attach to a scratch copy of the amd64 child, take that child's attestation-manifest descriptor
# (annotations kept: vnd.docker.reference.type / .digest) and add it to a scratch copy of the original index with
# `docker buildx imagetools create`. The built index is scanned by tag and by exact digest with our author; children and attestations
# are recorded. A fixture without the target tries nothing.
echo -e "\n### 1d. built index (scratch tag \`multi-built\`: the debian 12.0 manifest list plus an attestation-manifest child for amd64)\n" >> "$summ"
if [ -n "$OUR_AUTHOR" ] && [ -n "$g_purl" ]; then
  skopeo copy -q "docker://docker.io/library/debian@$CHILD" "docker://$PROBE_REPO:child-a" >> "$a/copy.log" 2>&1
  python3 bin/scout-root-cause.py doc "$OUR_AUTHOR" "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache" CVE-2023-4911 "$g_purl" "$a/built.vex.json"
  docker scout attestation add --file "$a/built.vex.json" --predicate-type "$PRED" "$PROBE_REPO:child-a" > "$a/built-add.log" 2>&1
  echo "- child copy: attestation add exit $? — \`$(tail -1 "$a/built-add.log" | cut -c1-160)\`" >> "$summ"
  child_ref="$PROBE_REPO:child-a"
  skopeo inspect --raw "docker://$child_ref" 2>/dev/null \
    | jq -c '[.manifests[]? | select(.annotations["vnd.docker.reference.type"] == "attestation-manifest")][0] // empty' > "$a/built-descriptor.json"
  if [ -s "$a/built-descriptor.json" ]; then
    echo "- the child's attestation-manifest descriptor: \`$(cut -c1-300 "$a/built-descriptor.json")\`" >> "$summ"
    built_ref="$PROBE_REPO:multi-built"; built_idx="$PROBE_REPO@$MULTI"
    att_dig=$(jq -r .digest "$a/built-descriptor.json"); att_ref="$PROBE_REPO@$att_dig"
    # buildx treats a descriptor that carries a mediaType as complete and then wants a tag-based source (the ":latest: not found" of probes 3
    # and 3b); without mediaType it resolves the manifest by its digest (the descriptor keeps its digest, size, platform and annotations)
    jq -c 'del(.mediaType)' "$a/built-descriptor.json" > "$a/built-descriptor-nomt.json"
    # two ways to add the child, tried in order; the first run showed the descriptor form (--file with a tag+digest source) failing with
    # "<repo>:latest: not found" (and again with digest-only sources): (1) --file descriptor with the original index by digest only,
    # (2) the original index and the attestation manifest as two sources by digest, the descriptor annotated with buildx's
    # manifest-descriptor[unknown/unknown] annotations (the plain two-source form, tried in probe 3b, kept the child but dropped
    # the annotations). The probe scans whichever variant really built the index.
    for variant in file annot; do
      skopeo copy -q --all "docker://docker.io/library/debian@$MULTI" "docker://$built_ref" >> "$a/copy.log" 2>&1
      if [ "$variant" = file ]; then
        > "$a/built-create-$variant.log" 2>&1 docker buildx imagetools create --tag "$built_ref" --file "$a/built-descriptor-nomt.json" "$built_idx"
      else   # the plain two-source form added the child with NO annotations (probe 3b); buildx can annotate the descriptor by its platform (unknown/unknown)
        > "$a/built-create-$variant.log" 2>&1 docker buildx imagetools create --tag "$built_ref" --annotation "manifest-descriptor[unknown/unknown]:vnd.docker.reference.type=attestation-manifest" --annotation "manifest-descriptor[unknown/unknown]:vnd.docker.reference.digest=$CHILD" "$built_idx" "$att_ref"
      fi
      crc=$?
      echo "- variant $variant: imagetools create exit $crc — \`$(tail -1 "$a/built-create-$variant.log" | cut -c1-200)\`" >> "$summ"
      bb=$(digest "$PROBE_REPO:multi-built"); children "$PROBE_REPO:multi-built" > "$a/built.children"
      echo "  - built index digest \`$bb\` (the original was \`$MULTI\`); children: $(cat "$a/built.children")" >> "$summ"
      # a scan is only interpreted for an index that really was built: create succeeded, the digest changed, and the attestation-manifest
      # child is among its children (a failed create leaves the copied original at the tag, and scanning that would mislabel it)
      if [ "$crc" -ne 0 ] || [ "$bb" = READ-FAILED ] || [ "$bb" = "${MULTI#sha256:}" ] || ! grep -q attestation-manifest "$a/built.children"; then
        echo "  - variant $variant: inconclusive (the create failed, the index did not change, or it carries no attestation-manifest child), so it is not scanned" >> "$summ"
        continue
      fi
      f="$a/built-after-tag.json"
      docker scout cves --format gitlab --vex-author "$OUR_AUTHOR_RE" "registry://$PROBE_REPO:multi-built" > "$f" 2> "$f.err"; rc=$?
      echo "  - variant $variant: built index scanned by tag with --vex-author: exit $rc — $(python3 bin/scout-root-cause.py judge "$a/control-before.json" "$f" CVE-2023-4911 "$g_purl" 2>&1 | tail -1)" >> "$summ"
      f="$a/built-after-digest.json"
      docker scout cves --format gitlab --vex-author "$OUR_AUTHOR_RE" "registry://$PROBE_REPO@sha256:$bb" > "$f" 2> "$f.err"; rc=$?
      echo "  - variant $variant: built index scanned by its exact digest \`sha256:$bb\` with --vex-author: exit $rc — $(python3 bin/scout-root-cause.py judge "$a/control-before.json" "$f" CVE-2023-4911 "$g_purl" 2>&1 | tail -1)" >> "$summ"
      docker scout attestation list "registry://$PROBE_REPO:multi-built" > "$a/built-attestation-list.txt" 2>&1
      echo "  - variant $variant: built index attestation list: \`$(head -c 400 "$a/built-attestation-list.txt" | tr '\n' ' ')\`" >> "$summ"
      break
    done
  else
    echo "- built index not attempted: Scout created no attestation-manifest child on the child copy" >> "$summ"
  fi
else
  echo "- not tried: the fixture does not carry CVE-2023-4911" >> "$summ"
fi

# --- 1e. the FINAL INDEX built by OUR tool (REQ-REL-010 AC6; advisor 0214/0221 follow-up) -----------------------------------------
# 1c/1d used Scout's own attach and a buildx-assembled child. The release will instead carry its VEX in the attestation children of a final
# index F that bin/vex-index.py derives from the built index D and the VEX file (compute, verify, push by digest). This proves Scout applies
# that VEX: a scratch copy of debian 12.0's manifest list is the base (`final-base`, scanned with no VEX as the control); F is built from it
# and OUR statement (our author, the published product form, CVE-2023-4911 not_affected), pushed to the scratch package by digest, copied to
# the scratch tag `final-index` (the digest must not change), then scanned by tag, by exact digest and through its amd64 child, with our
# author; its children and attestations are recorded. vex-index takes only an OCI index, so D is the base's bytes with the mediaType
# relabelled (Docker manifest list -> OCI index; the children are untouched). Every failure is a recorded "inconclusive (...)"; a control
# without the target, or a fixture without it, tries nothing. The registry credentials are the GHCR login already on the runner.
echo -e "\n### 1e. final index built by bin/vex-index.py (scratch tags \`final-base\`, \`final-index\`)\n" >> "$summ"
echo "- What this does NOT prove: the base is debian 12.0's Docker manifest list relabelled as an OCI index (one platform, Docker-typed children, no provenance or SBOM attestation children), NOT the buildx-produced release index D (OCI children, several platforms, existing attestations); it shows Scout applies a VEX carried in OUR attestation child of an index built by OUR tool, not that the release behaves identically." >> "$summ"
sha_re='^sha256:[0-9a-f]{64}$'
while :; do   # one pass: every early exit records its verdict and leaves
  if [ -z "$OUR_AUTHOR" ]; then echo "- 1e verdict: inconclusive (our author could not be read from .vex/fosterstack-cache.openvex.json)" >> "$summ"; break; fi
  if ! jq -e '.vulnerabilities | type == "array"' "$a/control-before.json" >/dev/null 2>&1; then
    echo "- 1e verdict: inconclusive (the fixture report from section 1 is not a valid Scout report, so the target cannot be looked up)" >> "$summ"; break; fi
  if [ -z "$g_purl" ]; then echo "- not tried: the fixture does not carry CVE-2023-4911" >> "$summ"; break; fi
  fi="$a/final"; mkdir -p "$fi"; fbase="$PROBE_REPO:final-base"; findex="$PROBE_REPO:final-index"
  freg=${PROBE_REPO%%/*}; frepo=${PROBE_REPO#*/}; PURL_PUBLISHED="pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache"
  # a failed copy would leave a stale tag that is then scanned and built from: refuse it; the copy must also carry the source's children
  if ! skopeo copy -q --all "docker://docker.io/library/debian@$MULTI" "docker://$fbase" >> "$a/copy.log" 2>&1; then
    echo "- 1e verdict: inconclusive (the copy to final-base failed, so a tag left from an earlier run is not used)" >> "$summ"; break; fi
  src_children=$(children "docker.io/library/debian@$MULTI" 2>/dev/null); base_children=$(children "$fbase" 2>/dev/null)
  if [ -z "$src_children" ] || [ "$src_children" != "$base_children" ]; then
    echo "- 1e verdict: inconclusive (final-base's children differ from the source's or could not be read: source \`$src_children\`, copy \`$base_children\`)" >> "$summ"; break; fi
  docker scout cves --format gitlab "registry://$fbase" > "$fi/control.json" 2> "$fi/control.json.err"; rc=$?
  have=$(jq -r --arg p "$g_purl" '[.vulnerabilities[]? | select(.cve == "CVE-2023-4911" and .location.dependency.package.name == $p)] | length' "$fi/control.json" 2>/dev/null)
  echo "- final-base control scanned with no VEX: exit $rc — CVE-2023-4911 findings: ${have:-unreadable}" >> "$summ"
  if [ "$rc" -ne 0 ] || [ -z "$have" ]; then echo "- 1e verdict: inconclusive (the final-base control scan exited $rc or its report is not valid)" >> "$summ"; break; fi
  if [ "$have" -eq 0 ]; then echo "- not tried: the final-base control does not carry CVE-2023-4911" >> "$summ"; break; fi
  fu=${FSCACHE_REGISTRY_USER:-}; ft=${FSCACHE_REGISTRY_TOKEN:-}
  if [ -n "$fu$ft" ] && { [ -z "$fu" ] || [ -z "$ft" ]; }; then
    echo "- 1e verdict: inconclusive (partial registry credentials: FSCACHE_REGISTRY_USER and FSCACHE_REGISTRY_TOKEN must both be set or both unset)" >> "$summ"; break; fi
  if [ -z "$fu" ]; then   # neither given: the login the runner already did (docker login writes the registry's user:token)
    fa=$(jq -r --arg r "$freg" '.auths[$r].auth // empty' "$HOME/.docker/config.json" 2>/dev/null | base64 -d 2>/dev/null || true)
    case "$fa" in *:*) fu=${fa%%:*}; ft=${fa#*:} ;; *) fu=""; ft="" ;; esac
  fi
  if [ -z "$fu" ] || [ -z "$ft" ]; then echo "- 1e verdict: inconclusive (no registry credentials for $freg: set FSCACHE_REGISTRY_USER and FSCACHE_REGISTRY_TOKEN, or log in)" >> "$summ"; break; fi
  if ! skopeo inspect --raw "docker://$fbase" > "$fi/base.raw" 2> "$fi/base.raw.err" \
     || ! jq -c '.mediaType = "application/vnd.oci.image.index.v1+json"' "$fi/base.raw" > "$fi/base.json" 2>/dev/null || [ ! -s "$fi/base.json" ]; then
    echo "- 1e verdict: inconclusive (the base index could not be read from $fbase)" >> "$summ"; break; fi
  echo "- base index D: read from \`final-base\` (copy of \`$MULTI\`), mediaType relabelled as an OCI index for vex-index (children untouched)" >> "$summ"
  echo "- 1e children of the base: $base_children" >> "$summ"
  if ! python3 bin/scout-root-cause.py doc "$OUR_AUTHOR" "$PURL_PUBLISHED" CVE-2023-4911 "$g_purl" "$fi/final.vex.json" 2> "$fi/doc.err" || [ ! -s "$fi/final.vex.json" ]; then
    echo "- 1e verdict: inconclusive (the VEX document could not be written)" >> "$summ"; break; fi
  rm -rf "$fi/out"
  F=$(python3 bin/vex-index.py compute --index "$fi/base.json" --vex "$fi/final.vex.json" --out-dir "$fi/out" 2> "$fi/compute.err"); crc=$?
  if [ "$crc" -ne 0 ] || [[ ! "$F" =~ $sha_re ]]; then echo "- 1e verdict: inconclusive (vex-index compute failed, exit $crc: \`$(head -c 200 "$fi/compute.err" | tr '\n' ' ')\`), nothing pushed" >> "$summ"; break; fi
  python3 bin/vex-index.py verify --final "$fi/out/index.json" --vex "$fi/final.vex.json" --blobs "$fi/out/blobs" --base "$fi/base.json" > "$fi/verify.out" 2> "$fi/verify.err"; vrc=$?
  if [ "$vrc" -ne 0 ]; then echo "- 1e verdict: inconclusive (vex-index verify failed, exit $vrc: \`$(head -c 200 "$fi/verify.err" | tr '\n' ' ')\`), nothing pushed" >> "$summ"; break; fi
  pushed=$(FSCACHE_REGISTRY_USER="$fu" FSCACHE_REGISTRY_TOKEN="$ft" python3 bin/vex-index.py push --registry "$freg" --repository "$frepo" \
             --dir "$fi/out" --vex "$fi/final.vex.json" --base "$fi/base.json" 2> "$fi/push.err"); prc=$?
  if [ "$prc" -ne 0 ]; then echo "- 1e verdict: inconclusive (vex-index push failed, exit $prc: \`$(head -c 200 "$fi/push.err" | tr '\n' ' ')\`)" >> "$summ"; break; fi
  if [ "$pushed" != "$F" ]; then echo "- 1e verdict: inconclusive (push reported \`$pushed\`, compute \`$F\`)" >> "$summ"; break; fi
  echo "- final index F \`$F\` (computed, verified, pushed by digest to \`$PROBE_REPO\`)" >> "$summ"
  echo "- 1e children of F: $(children "$PROBE_REPO@$F")" >> "$summ"
  skopeo copy -q --all "docker://$PROBE_REPO@$F" "docker://$findex" >> "$a/copy.log" 2>&1; trc=$?
  td=$(digest "$findex")
  tagok=0
  if [ "$trc" -ne 0 ] || [[ ! "sha256:$td" =~ $sha_re ]]; then tstat="inconclusive (the tag copy exited $trc or the tag could not be read)"
  elif [ "sha256:$td" = "$F" ]; then tstat=unchanged; tagok=1; else tstat="CHANGED"; fi
  echo "- tag final-index digest \`sha256:$td\` vs F \`$F\` — $tstat" >> "$summ"
  # a scan counts only when it exited 0 and its report is a valid Scout report; judge then needs the target gone and another finding kept
  jd() { if [ "$2" -ne 0 ]; then echo "inconclusive: the scan exited $2"
         elif ! jq -e '.vulnerabilities | type == "array"' "$1" >/dev/null 2>&1; then echo "inconclusive: the scan produced no valid report"
         else python3 bin/scout-root-cause.py judge "$fi/control.json" "$1" CVE-2023-4911 "$g_purl" 2>&1 | tail -1; fi; }
  tv="not scanned (the tag is not F)"
  if [ "$tagok" -eq 1 ]; then
    f="$fi/f-tag.json"; docker scout cves --format gitlab --vex-author "$OUR_AUTHOR_RE" "registry://$findex" > "$f" 2> "$f.err"; rc=$?
    tv=$(jd "$f" "$rc"); echo "- 1e F scanned with --vex-author, by tag: exit $rc — $tv" >> "$summ"
  fi
  f="$fi/f-digest.json"; docker scout cves --format gitlab --vex-author "$OUR_AUTHOR_RE" "registry://$PROBE_REPO@$F" > "$f" 2> "$f.err"; rc=$?
  dv=$(jd "$f" "$rc"); echo "- 1e F scanned with --vex-author, by its exact digest \`$F\`: exit $rc — $dv" >> "$summ"
  f="$fi/f-noflag.json"; docker scout cves --format gitlab "registry://$PROBE_REPO@$F" > "$f" 2> "$f.err"; rc=$?
  echo "- 1e (information) F scanned without --vex-author, by its exact digest: exit $rc — $(jd "$f" "$rc")" >> "$summ"
  f="$fi/f-child.json"; docker scout cves --format gitlab --vex-author "$OUR_AUTHOR_RE" "registry://$PROBE_REPO@$CHILD" > "$f" 2> "$f.err"; rc=$?
  echo "- 1e F's amd64 child scanned with --vex-author, by its digest \`$CHILD\` (information: the VEX is carried by F's attestation child, not the platform image): exit $rc — $(jd "$f" "$rc")" >> "$summ"
  if [ "$tagok" -eq 1 ]; then
    docker scout attestation list "registry://$findex" > "$fi/f-attestation-list.txt" 2>&1
    echo "- 1e F attestation list: \`$(head -c 400 "$fi/f-attestation-list.txt" | tr '\n' ' ')\`" >> "$summ"
  fi
  if [ "$tv" = suppressed ] && [ "$dv" = suppressed ]; then
    echo "- 1e verdict: PASS — CVE-2023-4911 is present in the final-base control and suppressed in F by tag and by exact digest, with another finding kept" >> "$summ"
  elif [ "$tv" = "not applied" ] || [ "$dv" = "not applied" ]; then
    echo "- 1e verdict: FAIL — Scout did not apply the VEX carried by F (by tag: $tv; by digest: $dv)" >> "$summ"
  else
    echo "- 1e verdict: inconclusive (by tag: $tv; by digest: $dv)" >> "$summ"
  fi
  break
done

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
