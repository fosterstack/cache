#!/usr/bin/env bash
# Repeatable regressions for the daily image rescan's merge, classification
# and platform-enumeration logic (bin/rescan-statement.py) — audit findings
# B04d/B04e/B04f. Exercises the ACTUAL logic the workflow calls against real
# CLI-shaped fixtures (Snyk container test, Trivy image, Grype, and
# imagetools index/manifest JSON). Pure python3 + jq: no network, no gh, no
# scanners, no PyYAML.
#
# Each case asserts the resulting verdict / has_findings / normalized
# finding count, or the enumeration exit code and children set, so a
# regression in any of the three fixes is caught in PR CI rather than by an
# external probe.
set -euo pipefail
cd "$(dirname "$0")/.."

SCRIPT=bin/rescan-statement.py
REPO="ghcr.io/fosterstack/cache"
AMD="sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
ARM="sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
D=$(mktemp -d); trap 'rm -rf "$D"' EXIT

pass=0; fail=0
ok()  { pass=$((pass+1)); }
bad() { fail=$((fail+1)); echo "FAIL: $1"; }

# ---- statement helpers ---------------------------------------------------
# Write one child report file and append its manifest line.
child() { # manifest-file  childno  platform  exit  report-json
  local mf="$1" no="$2" plat="$3" code="$4" body="$5"
  local rp="$D/report-${no}.json"
  printf '%s' "$body" > "$rp"
  jq -nc --arg p "$plat" --arg r "$REPO@x" --argjson e "$code" --arg f "$rp" \
    '{platform:$p, ref:$r, exit:$e, report:$f}' >> "$mf"
}
# A child whose scanner produced NO file at all (operational crash).
child_missing() { # manifest-file  childno  platform  exit
  local mf="$1" plat="$3" code="$4"
  jq -nc --arg p "$plat" --arg r "$REPO@x" --argjson e "$code" \
    '{platform:$p, ref:$r, exit:$e, report:"/tmp/does-not-exist-xyz.json"}' >> "$mf"
}

assert_stmt() { # desc scanner manifest want_verdict want_hasfindings want_count
  local desc="$1" scanner="$2" mf="$3" wv="$4" whf="$5" wc="$6" out v hf c
  out=$(python3 "$SCRIPT" statement --scanner "$scanner" --children "$mf" \
        --raw-out "$D/raw.json" --out "$D/stmt.json" \
        --release v0.2.0 --variant production --digest "$AMD" \
        --image-ref "$REPO@$AMD" --scanned-at 2026-09-14T00:00:00+00:00) || {
    bad "$desc (script exited nonzero)"; return; }
  v=$(jq -r '.verdict' <<<"$out")
  hf=$(jq -r '.has_findings' <<<"$out")
  c=$(jq -r '.count' <<<"$out")
  if [ "$v" = "$wv" ] && [ "$hf" = "$whf" ] && [ "$c" = "$wc" ]; then
    ok
  else
    bad "$desc (got verdict=$v has_findings=$hf count=$c; want $wv/$whf/$wc)"
  fi
}

# ---- CLI-shaped report bodies -------------------------------------------
TRIVY_CLEAN='{"SchemaVersion":2,"ArtifactName":"x","Results":[]}'
TRIVY_FIND='{"SchemaVersion":2,"Results":[{"Target":"x (debian 12)","Class":"os-pkgs","Vulnerabilities":[{"VulnerabilityID":"CVE-2024-0001","PkgName":"openssl","Severity":"HIGH","FixedVersion":"3.0.14"}]}]}'
TRIVY_ERROBJ='{"error":"failed to analyze layer"}'
GRYPE_CLEAN='{"matches":[],"descriptor":{"name":"grype","version":"0.98.0"}}'
GRYPE_FIND='{"matches":[{"vulnerability":{"id":"CVE-2024-0002","severity":"High","fix":{"versions":["1.2.3"]}},"artifact":{"name":"libfoo"}}],"descriptor":{"name":"grype"}}'
GRYPE_ERROBJ='{"errors":["db load failed"]}'
# Snyk: OS findings at top-level .vulnerabilities; application-dependency
# findings under .applications[].vulnerabilities, each app carrying project
# context (targetFile / packageManager) — the official v1.1307.0 shape.
SNYK_CLEAN='{"vulnerabilities":[],"applications":[]}'
SNYK_OS='{"vulnerabilities":[{"id":"SNYK-DEBIAN12-OPENSSL-1","identifiers":{"CVE":["CVE-2024-0003"]},"severity":"high","packageName":"openssl","nearestFixedInVersion":"3.0.14"}],"applications":[]}'
SNYK_APP='{"vulnerabilities":[],"applications":[{"packageManager":"npm","targetFile":"/srv/app/package.json","vulnerabilities":[{"id":"npm:connect:20120107","identifiers":{"ALTERNATIVE":["SNYK-JS-CONNECT-10382"],"CVE":[],"CWE":["CWE-400"]},"severity":"medium","packageName":"connect"}]}]}'
SNYK_MIXED='{"vulnerabilities":[{"id":"SNYK-DEBIAN12-OPENSSL-1","identifiers":{"CVE":["CVE-2024-0003"]},"severity":"high","packageName":"openssl"}],"applications":[{"packageManager":"npm","targetFile":"/srv/app/package.json","vulnerabilities":[{"id":"npm:connect:20120107","identifiers":{"CVE":[]},"severity":"medium","packageName":"connect"}]}]}'
SNYK_ERROBJ='{"ok":false,"error":"authentication failed","path":"x"}'

# ---- Snyk cases ----------------------------------------------------------
mf=$D/m; : >"$mf"
child "$mf" 1 linux/amd64 0 "$SNYK_CLEAN"
child "$mf" 2 linux/arm64 0 "$SNYK_CLEAN"
assert_stmt "snyk clean (both arches)" snyk "$mf" clean false 0

mf=$D/m; : >"$mf"
child "$mf" 1 linux/amd64 1 "$SNYK_OS"
child "$mf" 2 linux/arm64 0 "$SNYK_CLEAN"
assert_stmt "snyk OS-only finding" snyk "$mf" findings true 1

# B04d: application-only finding on arm64 (amd64 clean). Snyk exits 1.
mf=$D/m; : >"$mf"
child "$mf" 1 linux/amd64 0 "$SNYK_CLEAN"
child "$mf" 2 linux/arm64 1 "$SNYK_APP"
assert_stmt "snyk application-only finding (arm64)" snyk "$mf" findings true 1
# and the normalized finding must retain project + platform context.
python3 "$SCRIPT" statement --scanner snyk --children "$mf" \
  --raw-out "$D/raw.json" --out "$D/stmt.json" --digest "$AMD" >/dev/null
if [ "$(jq -r '.findings[0].platform' "$D/stmt.json")" = "linux/arm64" ] \
   && [ "$(jq -r '.findings[0].target' "$D/stmt.json")" = "/srv/app/package.json" ] \
   && [ "$(jq -r '.findings[0].package' "$D/stmt.json")" = "connect" ] \
   && [ "$(jq -r '.findings[0].package_manager' "$D/stmt.json")" = "npm" ]; then
  ok; else bad "snyk app finding lost platform/project context"; fi
# and the retained raw report must carry the application section (B04d).
if [ "$(jq -r '.applications[0].vulnerabilities[0].packageName' "$D/raw.json")" = "connect" ]; then
  ok; else bad "snyk merged raw report dropped .applications[]"; fi

mf=$D/m; : >"$mf"
child "$mf" 1 linux/amd64 1 "$SNYK_MIXED"
child "$mf" 2 linux/arm64 0 "$SNYK_CLEAN"
assert_stmt "snyk mixed OS+application findings" snyk "$mf" findings true 2

# ---- B04e: valid-JSON operational exit is not erased by findings --------
# child1 finding (exit 1), child2 operational failure (exit 2) w/ valid JSON.
mf=$D/m; : >"$mf"
child "$mf" 1 linux/amd64 1 "$SNYK_OS"
child "$mf" 2 linux/arm64 2 "$SNYK_CLEAN"
assert_stmt "snyk finding + valid-JSON exit 2 -> notify AND error" snyk "$mf" error true 1

# Preserve the now-correct case: one child finds, another emits NO report.
mf=$D/m; : >"$mf"
child "$mf" 1 linux/amd64 1 "$SNYK_OS"
child_missing "$mf" 2 linux/arm64 1
assert_stmt "snyk finding + missing report -> notify AND error" snyk "$mf" error true 1

# A snyk operational error object (exit 2) with no findings anywhere.
mf=$D/m; : >"$mf"
child "$mf" 1 linux/amd64 0 "$SNYK_CLEAN"
child "$mf" 2 linux/arm64 2 "$SNYK_ERROBJ"
assert_stmt "snyk operational failure only" snyk "$mf" error false 0

# ---- Trivy cases ---------------------------------------------------------
mf=$D/m; : >"$mf"
child "$mf" 1 linux/amd64 0 "$TRIVY_CLEAN"
child "$mf" 2 linux/arm64 0 "$TRIVY_CLEAN"
assert_stmt "trivy clean" trivy "$mf" clean false 0

mf=$D/m; : >"$mf"
child "$mf" 1 linux/amd64 0 "$TRIVY_CLEAN"
child "$mf" 2 linux/arm64 1 "$TRIVY_FIND"
assert_stmt "trivy finding (arm64, exit 1)" trivy "$mf" findings true 1

# exit 2 = operational error (not the configured finding code).
mf=$D/m; : >"$mf"
child "$mf" 1 linux/amd64 0 "$TRIVY_CLEAN"
child "$mf" 2 linux/arm64 2 "$TRIVY_CLEAN"
assert_stmt "trivy operational exit 2" trivy "$mf" error false 0

# malformed report at the finding exit code -> incomplete, not clean.
mf=$D/m; : >"$mf"
child "$mf" 1 linux/amd64 1 "$TRIVY_ERROBJ"
child "$mf" 2 linux/arm64 0 "$TRIVY_CLEAN"
assert_stmt "trivy malformed report (exit 1)" trivy "$mf" error false 0

# ---- Grype cases ---------------------------------------------------------
mf=$D/m; : >"$mf"
child "$mf" 1 linux/amd64 0 "$GRYPE_CLEAN"
child "$mf" 2 linux/arm64 0 "$GRYPE_CLEAN"
assert_stmt "grype clean" grype "$mf" clean false 0

# Grype v0.98.0: exit 2 = findings, 1 = operational error (B04g).
mf=$D/m; : >"$mf"
child "$mf" 1 linux/amd64 2 "$GRYPE_FIND"
child "$mf" 2 linux/arm64 0 "$GRYPE_CLEAN"
assert_stmt "grype finding (amd64, exit 2)" grype "$mf" findings true 1

mf=$D/m; : >"$mf"
child "$mf" 1 linux/amd64 0 "$GRYPE_CLEAN"
child "$mf" 2 linux/arm64 2 "$GRYPE_FIND"
assert_stmt "grype finding (arm64, exit 2)" grype "$mf" findings true 1

# exit 1 is an OPERATIONAL error for grype, even with valid-shaped JSON.
mf=$D/m; : >"$mf"
child "$mf" 1 linux/amd64 1 "$GRYPE_CLEAN"
child "$mf" 2 linux/arm64 0 "$GRYPE_CLEAN"
assert_stmt "grype operational exit 1 (valid JSON)" grype "$mf" error false 0

mf=$D/m; : >"$mf"
child "$mf" 1 linux/amd64 0 "$GRYPE_CLEAN"
child "$mf" 2 linux/arm64 137 "$GRYPE_CLEAN"
assert_stmt "grype operational exit 137" grype "$mf" error false 0

# finding (exit 2) on one child + operational failure (exit 1) on the
# other: incomplete AND the finding is retained and notified.
mf=$D/m; : >"$mf"
child "$mf" 1 linux/amd64 2 "$GRYPE_FIND"
child "$mf" 2 linux/arm64 1 "$GRYPE_CLEAN"
assert_stmt "grype finding/2 + operational/1" grype "$mf" error true 1

mf=$D/m; : >"$mf"
child "$mf" 1 linux/amd64 1 "$GRYPE_ERROBJ"
child "$mf" 2 linux/arm64 0 "$GRYPE_CLEAN"
assert_stmt "grype malformed report (exit 1)" grype "$mf" error false 0

# ==========================================================================
# B04f — platform-child enumeration validation.
# ==========================================================================
assert_enum() { # desc index-json want_exit [want-children-count]
  local desc="$1" idx="$2" we="$3" wc="${4:-}" got n
  printf '%s' "$idx" > "$D/index.json"
  set +e
  python3 "$SCRIPT" enumerate --index "$D/index.json" --repo "$REPO" \
    --ref "$REPO@$AMD" --out "$D/children.txt" >/dev/null 2>"$D/enum.err"
  got=$?
  set -e
  if [ "$got" != "$we" ]; then
    bad "$desc (enumerate exit $got, want $we): $(cat "$D/enum.err")"; return; fi
  if [ -n "$wc" ]; then
    n=$(grep -c . "$D/children.txt" 2>/dev/null || echo 0)
    if [ "$n" != "$wc" ]; then
      bad "$desc (children $n, want $wc)"; return; fi
  fi
  ok
}

IMG_DESC='{"mediaType":"application/vnd.oci.image.manifest.v1+json","platform":{"os":"linux","architecture":"%s"},"digest":"%s"}'
mkdesc() { printf "$IMG_DESC" "$1" "$2"; }

# valid multi-arch index -> both children.
assert_enum "enum valid multi-arch" \
  "{\"manifests\":[$(mkdesc amd64 "$AMD"),$(mkdesc arm64 "$ARM")]}" 0 2

# null-platform second descriptor (a plain image, no attestation marker) -> FAIL.
assert_enum "enum null-platform child rejected" \
  "{\"manifests\":[$(mkdesc amd64 "$AMD"),{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"platform\":null,\"digest\":\"$ARM\"}]}" 1

# empty architecture string -> FAIL (never becomes "linux/").
assert_enum "enum empty-arch child rejected" \
  "{\"manifests\":[$(mkdesc amd64 "$AMD"),$(mkdesc '' "$ARM")]}" 1

# all descriptors 'unknown' platform, no attestation marker -> FAIL.
assert_enum "enum all-unknown rejected" \
  "{\"manifests\":[$(mkdesc unknown "$AMD"),$(mkdesc unknown "$ARM")]}" 1

# valid single-image manifest (.config + .layers) -> index fallback.
assert_enum "enum single-image fallback" \
  '{"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"sha256:cfg"},"layers":[{"digest":"sha256:l1"}]}' 0 1

# valid image + an EXPLICIT attestation descriptor -> only the image child.
ATT='{"mediaType":"application/vnd.oci.image.manifest.v1+json","platform":{"os":"unknown","architecture":"unknown"},"annotations":{"vnd.docker.reference.type":"attestation-manifest","vnd.docker.reference.digest":"x"},"digest":"sha256:att"}'
assert_enum "enum ignores explicit attestation descriptor" \
  "{\"manifests\":[$(mkdesc amd64 "$AMD"),$ATT]}" 0 1

# unrecognized shape (neither index nor image manifest) -> FAIL.
assert_enum "enum unrecognized shape rejected" '{"foo":"bar"}' 1
# invalid JSON -> FAIL.
assert_enum "enum invalid JSON rejected" 'not json at all' 1

echo "rescan-statement: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
