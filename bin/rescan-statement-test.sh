#!/usr/bin/env bash
# proves: REQ-REL-004-AC6, REQ-REL-004-AC7
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

# An empty (but valid) VEX document: scanners that cannot read the VEX themselves need one, so every statement call gets it unless a case says otherwise.
VEX0=$D/vex-empty.json
printf '%s' '{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://fosterstack.com/vex/cache/openvex","author":"FosterStack LLC","version":1,"statements":[]}' >"$VEX0"
STMT_EXTRA=(--vex "$VEX0")

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
  jq -nc --arg p "$plat" --arg r "$REPO@x" --argjson e "$code" --arg rp "$(dirname "$mf")/does-not-exist-xyz.json" \
    '{platform:$p, ref:$r, exit:$e, report:$rp}' >> "$mf"
}

assert_stmt() { # desc scanner manifest want_verdict want_hasfindings want_count
  local desc="$1" scanner="$2" mf="$3" wv="$4" whf="$5" wc="$6" out v hf c
  out=$(python3 "$SCRIPT" statement --scanner "$scanner" --children "$mf" "${STMT_EXTRA[@]}" \
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
GRYPE_CLEAN='{"matches":[],"descriptor":{"name":"grype","version":"0.118.0"}}'
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
# OSV-Scanner JSON: results[] -> source.path, packages[] -> {package, vulnerabilities[]}.
OSV_CLEAN='{"results":[]}'
OSV_FIND='{"results":[{"source":{"path":"go.mod","type":"lockfile"},"packages":[{"package":{"name":"golang.org/x/net","version":"0.1.0","ecosystem":"Go"},"vulnerabilities":[{"id":"GO-2024-0001","aliases":["CVE-2024-9999"],"database_specific":{"severity":"HIGH"}}]}]}]}'
OSV_ERROBJ='{"error":"could not resolve deps.dev"}'

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
python3 "$SCRIPT" statement --scanner snyk --children "$mf" "${STMT_EXTRA[@]}" \
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

# Grype: exit 2 = findings, 1 = operational error (B04g); contract
# verified unchanged from v0.98.0 through the pinned v0.118.0.
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
# ---- osv-scanner cases ---------------------------------------------------
mf=$D/m; : >"$mf"
child "$mf" 1 linux/amd64 0 "$OSV_CLEAN"
assert_stmt "osv-scanner clean" osv-scanner "$mf" clean false 0

mf=$D/m; : >"$mf"
child "$mf" 1 linux/amd64 1 "$OSV_FIND"
assert_stmt "osv-scanner finding (exit 1)" osv-scanner "$mf" findings true 1
# the normalized finding keeps the CVE alias, package and source path.
python3 "$SCRIPT" statement --scanner osv-scanner --children "$mf" "${STMT_EXTRA[@]}" \
  --raw-out "$D/raw.json" --out "$D/stmt.json" --digest "$AMD" >/dev/null
if [ "$(jq -r '.findings[0].id' "$D/stmt.json")" = "CVE-2024-9999" ] \
   && [ "$(jq -r '.findings[0].package' "$D/stmt.json")" = "golang.org/x/net" ] \
   && [ "$(jq -r '.findings[0].target' "$D/stmt.json")" = "go.mod" ]; then ok; else
  bad "osv-scanner finding did not retain id/package/target"; fi

# operational error: nonzero exit that is not the finding code -> error,
# never clean, even with valid-shaped JSON.
mf=$D/m; : >"$mf"
child "$mf" 1 linux/amd64 127 "$OSV_CLEAN"
assert_stmt "osv-scanner operational error (exit 127)" osv-scanner "$mf" error false 0

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

# ==========================================================================
# REQ-REL-004-AC6 (advisor reading: ratified scanner-panel rule 4): the pipeline filter. A scanner that cannot read the VEX itself has its findings
# removed when the published OpenVEX marks them not_affected or fixed for this image's product; unreadable VEX = operational error.
# ==========================================================================
vexdoc() { # file statements-json: an OpenVEX document of our author
  jq -nc --argjson s "$2" '{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://fosterstack.com/vex/cache/openvex","author":"FosterStack LLC","version":3,"statements":$s}' >"$1"
}
PROD_REPO='{"@id":"pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache"}'
PROD_GO='{"@id":"pkg:golang/github.com/fosterstack/cache"}'
st() { # vulnerability-name aliases-json status products-json [subcomponents]  -> a statement
  jq -nc --arg n "$1" --argjson al "$2" --arg s "$3" --argjson pr "$4" '{"vulnerability":{"name":$n,"aliases":$al},"status":$s,"justification":"component_not_present","products":$pr}'
}
# run the statement for one scanner/report/exit with a given VEX; sets V (verdict) HF (has_findings) C (count) S (suppressed count)
vrun() { # scanner exit report vexfile [variant] [platform] [image-ref]
  local sc="$1" ex="$2" rep="$3" vf="$4" var="${5:-production}" plat="${6:-linux/amd64}" iref="${7:-$REPO@$AMD}" mfv=$D/mv
  : >"$mfv"; child "$mfv" 9 "$plat" "$ex" "$rep"
  local args=(); [ -n "$vf" ] && args=(--vex "$vf")
  out=$(python3 "$SCRIPT" statement --scanner "$sc" --children "$mfv" "${args[@]}" --raw-out "$D/rawv.json" --out "$D/stmtv.json" \
        --release v0.2.0 --variant "$var" --digest "$AMD" --image-ref "$iref" --scanned-at 2026-09-14T00:00:00+00:00 2>"$D/vrun.err") || { V=SCRIPT-FAILED; HF=; C=; S=; return; }
  V=$(jq -r '.verdict' <<<"$out"); HF=$(jq -r '.has_findings' <<<"$out"); C=$(jq -r '.count' <<<"$out"); S=$(jq -r '(.vex_suppressed // []) | length' "$D/stmtv.json")
}
expect() { # desc want-verdict want-has want-count want-suppressed
  if [ "$V" = "$2" ] && [ "$HF" = "$3" ] && [ "$C" = "$4" ] && [ "$S" = "$5" ]; then ok; else bad "$1 (got verdict=$V has_findings=$HF count=$C suppressed=$S; want $2/$3/$4/$5)"; fi
}
mkdir -p "$D/v"
# the finding: CVE-2024-9999 (alias of GO-2024-0001) in golang.org/x/net 0.1.0
vexdoc "$D/v/by-cve.json" "[$(st CVE-2024-9999 '[]' not_affected "[$PROD_REPO]")]"
vrun osv-scanner 1 "$OSV_FIND" "$D/v/by-cve.json"
expect "osv: a not_affected statement for the CVE removes the finding (clean, nothing counts, one suppressed)" clean false 0 1
if [ "$(jq -r '.vex_suppressed[0].id' "$D/stmtv.json")" = "CVE-2024-9999" ] && [ "$(jq -r '.vex_suppressed[0].package' "$D/stmtv.json")" = "golang.org/x/net" ] \
   && [ "$(jq -r '.vex_suppressed[0].vex.document' "$D/stmtv.json")" = "https://fosterstack.com/vex/cache/openvex" ] \
   && [ "$(jq -r '.vex_suppressed[0].vex.statement' "$D/stmtv.json")" = "CVE-2024-9999" ] && [ "$(jq -r '.vex_suppressed[0].vex.status' "$D/stmtv.json")" = "not_affected" ] \
   && [ "$(jq -r '.findings | length' "$D/stmtv.json")" = "0" ]; then ok; else bad "osv: vex_suppressed does not carry the finding and the statement identifier (document, statement, status)"; fi
# by the OSV id when the statement names it as an alias (the report's own id is the GO- id; the CVE is the report's alias)
vexdoc "$D/v/by-alias.json" "[$(st CVE-2024-0000 '["GO-2024-0001"]' not_affected "[$PROD_REPO]")]"
vrun osv-scanner 1 "$OSV_FIND" "$D/v/by-alias.json"
expect "osv: a statement that lists the OSV id as an alias matches" clean false 0 1
# the finding's other id (an alias in the REPORT) matches the statement's name
OSV_GHSA='{"results":[{"source":{"path":"go.mod","type":"lockfile"},"packages":[{"package":{"name":"golang.org/x/net","version":"0.1.0","ecosystem":"Go"},"vulnerabilities":[{"id":"GHSA-aaaa-bbbb-cccc","aliases":["GO-2024-0001"],"database_specific":{"severity":"HIGH"}}]}]}]}'
vexdoc "$D/v/by-ghsa.json" "[$(st GO-2024-0001 '[]' not_affected "[$PROD_GO]")]"
vrun osv-scanner 1 "$OSV_GHSA" "$D/v/by-ghsa.json"
expect "osv: the report's alias (GO-2024-0001) matches the statement's name through the Go module product" clean false 0 1
# fixed suppresses too; affected / under_investigation do not
vexdoc "$D/v/fixed.json" "[$(st CVE-2024-9999 '[]' fixed "[$PROD_REPO]")]"; vrun osv-scanner 1 "$OSV_FIND" "$D/v/fixed.json"
expect "osv: status fixed suppresses" clean false 0 1
for stt in affected under_investigation; do
  vexdoc "$D/v/$stt.json" "[$(st CVE-2024-9999 '[]' $stt "[$PROD_REPO]")]"; vrun osv-scanner 1 "$OSV_FIND" "$D/v/$stt.json"
  expect "osv: status $stt does NOT suppress" findings true 1 0
done
# another product, or another vulnerability, does not suppress ("never by CVE alone across products")
vexdoc "$D/v/other-product.json" "[$(st CVE-2024-9999 '[]' not_affected '[{"@id":"pkg:oci/other?repository_url=ghcr.io/example/other"}]')]"; vrun osv-scanner 1 "$OSV_FIND" "$D/v/other-product.json"
expect "osv: a statement for ANOTHER product does not suppress" findings true 1 0
vexdoc "$D/v/other-cve.json" "[$(st CVE-2024-1111 '[]' not_affected "[$PROD_REPO]")]"; vrun osv-scanner 1 "$OSV_FIND" "$D/v/other-cve.json"
expect "osv: a statement for ANOTHER vulnerability does not suppress" findings true 1 0
vexdoc "$D/v/lookalike.json" "[$(st CVE-2024-9999 '[]' not_affected '[{"@id":"pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache-evil"}]')]"; vrun osv-scanner 1 "$OSV_FIND" "$D/v/lookalike.json"
expect "osv: a look-alike product (cache-evil) does not suppress" findings true 1 0
# variant / arch scoped products (the auditor's per-image statements)
SC_PROD_AMD='{"@id":"pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache&variant=production&arch=amd64"}'
SC_FIPS_AMD='{"@id":"pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache&variant=fips&arch=amd64"}'
vexdoc "$D/v/sc-prod.json" "[$(st CVE-2024-9999 '[]' not_affected "[$SC_PROD_AMD]")]"
vrun osv-scanner 1 "$OSV_FIND" "$D/v/sc-prod.json" production linux/amd64; expect "osv: a production/amd64-scoped statement suppresses the production amd64 finding" clean false 0 1
vrun osv-scanner 1 "$OSV_FIND" "$D/v/sc-prod.json" production linux/arm64; expect "osv: ...but not the same finding on arm64" findings true 1 0
vrun osv-scanner 1 "$OSV_FIND" "$D/v/sc-prod.json" fips linux/amd64; expect "osv: ...nor on the fips variant" findings true 1 0
vexdoc "$D/v/sc-fips.json" "[$(st CVE-2024-9999 '[]' not_affected "[$SC_FIPS_AMD]")]"
vrun osv-scanner 1 "$OSV_FIND" "$D/v/sc-fips.json" production linux/amd64; expect "osv: a fips-scoped statement does not suppress a production finding" findings true 1 0
# a statement that names subcomponents covers only those package versions
SUBP='{"@id":"pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache","subcomponents":[{"@id":"pkg:golang/golang.org/x/net@0.1.0"}]}'
SUBP2='{"@id":"pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache","subcomponents":[{"@id":"pkg:golang/golang.org/x/net@9.9.9"}]}'
SUBP3='{"@id":"pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache","subcomponents":[{"@id":"pkg:golang/golang.org/x/text@0.1.0"}]}'
vexdoc "$D/v/sub-ok.json" "[$(st CVE-2024-9999 '[]' not_affected "[$SUBP]")]"; vrun osv-scanner 1 "$OSV_FIND" "$D/v/sub-ok.json"; expect "osv: a subcomponent statement for this package and version suppresses" clean false 0 1
vexdoc "$D/v/sub-ver.json" "[$(st CVE-2024-9999 '[]' not_affected "[$SUBP2]")]"; vrun osv-scanner 1 "$OSV_FIND" "$D/v/sub-ver.json"; expect "osv: a subcomponent statement for ANOTHER version does not suppress" findings true 1 0
vexdoc "$D/v/sub-pkg.json" "[$(st CVE-2024-9999 '[]' not_affected "[$SUBP3]")]"; vrun osv-scanner 1 "$OSV_FIND" "$D/v/sub-pkg.json"; expect "osv: a subcomponent statement for ANOTHER package does not suppress" findings true 1 0
# every other finding still counts at any severity
OSV_TWO='{"results":[{"source":{"path":"go.mod","type":"lockfile"},"packages":[{"package":{"name":"golang.org/x/net","version":"0.1.0","ecosystem":"Go"},"vulnerabilities":[{"id":"GO-2024-0001","aliases":["CVE-2024-9999"]},{"id":"GO-2024-0002","aliases":["CVE-2024-8888"]}]}]}]}'
vrun osv-scanner 1 "$OSV_TWO" "$D/v/by-cve.json"; expect "osv: with two findings only the covered one is removed (verdict findings, one counts, one suppressed)" findings true 1 1
if [ "$(jq -r '.findings[0].id' "$D/stmtv.json")" = "CVE-2024-8888" ]; then ok; else bad "osv: the remaining finding is not the uncovered one"; fi
# the uncovered finding keeps its severity (unknown stays counted: any severity blocks)
# Snyk cannot read the VEX either: filtered the same way (by its CVE identifier)
vexdoc "$D/v/snyk.json" "[$(st CVE-2024-0003 '[]' not_affected "[$PROD_REPO]")]"
vrun snyk 1 "$SNYK_OS" "$D/v/snyk.json"; expect "snyk: a not_affected statement for its CVE removes the finding too" clean false 0 1
# grype and trivy read the VEX themselves: their findings are NOT filtered a second time
vexdoc "$D/v/grype.json" "[$(st CVE-2024-0002 '[]' not_affected "[$PROD_REPO]")]"
vrun grype 2 "$GRYPE_FIND" "$D/v/grype.json"; expect "grype: its own VEX handling stands; the pipeline filter does not apply (a finding it still reports counts)" findings true 1 0
vrun grype 2 "$GRYPE_FIND" ""; expect "grype: no --vex is fine (it reads the VEX itself)" findings true 1 0
# an unreadable VEX stops the rescan as an operational error, never as "no suppression"
printf 'not json' >"$D/v/garbage.json"; printf '[]' >"$D/v/array.json"; printf '{"statements":"x"}' >"$D/v/badstmts.json"; printf '{"statements":[5]}' >"$D/v/badstmt.json"; : >"$D/v/empty.json"
for f in garbage array badstmts badstmt empty; do
  vrun osv-scanner 1 "$OSV_FIND" "$D/v/$f.json"; expect "osv: an unreadable VEX ($f) is an operational error (verdict error); the finding is still counted, never silently dropped" error true 1 0
done
vrun osv-scanner 1 "$OSV_FIND" "$D/v/does-not-exist.json"; expect "osv: a VEX file that does not exist is an operational error" error true 1 0
vrun osv-scanner 1 "$OSV_FIND" ""; expect "osv: no --vex at all is an operational error (the filter needs the document)" error true 1 0
vrun osv-scanner 0 "$OSV_CLEAN" "$D/v/garbage.json"; expect "osv: a clean scan with an unreadable VEX is STILL an error (the document is part of the contract)" error false 0 0
# exit code 1 (findings) with nothing parsed is still an error; with everything suppressed it is clean
vrun osv-scanner 1 "$OSV_CLEAN" "$D/v/by-cve.json"; expect "osv: exit 1 but no finding in the report is still an error (nothing was suppressed)" error false 0 0
# one child's findings are all covered, another child exits 1 with NOTHING readable: that child is not accounted for, so the run stays an error
mfx=$D/mx; : >"$mfx"; child "$mfx" 7 linux/amd64 1 "$OSV_FIND"; child "$mfx" 8 linux/arm64 1 "$OSV_CLEAN"
out=$(python3 "$SCRIPT" statement --scanner osv-scanner --children "$mfx" --vex "$D/v/by-cve.json" --raw-out "$D/rawx.json" --out "$D/stmtx.json" --variant production --digest "$AMD" --release v0.2.0 --image-ref "$REPO@$AMD" --scanned-at 2026-09-14T00:00:00+00:00)
if [ "$(jq -r .verdict <<<"$out")" = error ]; then ok; else bad "osv: a child that exits 1 with no readable finding must keep the run an error even when another child's findings are all covered (got $(jq -r .verdict <<<"$out"))"; fi
# the statement keeps a VEX section and says which scanners are filtered
if [ "$(jq -r '.vex.filtered_by_pipeline' "$D/stmtv.json")" != "null" ]; then ok; else bad "the statement does not record whether the pipeline filtered"; fi
vrun osv-scanner 1 "$OSV_FIND" "$D/v/by-cve.json"
if [ "$(jq -r '.vex.filtered_by_pipeline' "$D/stmtv.json")" = "true" ] && [ "$(jq -r '.vex.sha256 | length' "$D/stmtv.json")" = "64" ]; then ok; else bad "osv statement: vex.filtered_by_pipeline must be true and the VEX sha256 recorded"; fi
vrun grype 2 "$GRYPE_FIND" "$D/v/grype.json"
if [ "$(jq -r '.vex.filtered_by_pipeline' "$D/stmtv.json")" = "false" ]; then ok; else bad "grype statement: vex.filtered_by_pipeline must be false (it reads the VEX itself)"; fi
# a new scanner cannot bypass the VEX by omission: every scanner of scanners.json must be marked as reading the VEX natively or covered by the pipeline filter
for s in $(jq -r '.scanners[]' .github/policy/scanners.json); do
  if python3 "$SCRIPT" classify --scanner "$s" >"$D/cls.out" 2>&1; then ok; else bad "scanner $s of .github/policy/scanners.json is neither marked as reading the VEX natively nor covered by the pipeline filter ($(cat "$D/cls.out"))"; fi
done
jq '.scanners += ["newscan"]' .github/policy/scanners.json >"$D/scanners-plus.json"
miss=0; for s in $(jq -r '.scanners[]' "$D/scanners-plus.json"); do python3 "$SCRIPT" classify --scanner "$s" >/dev/null 2>&1 || miss=$((miss+1)); done
if [ "$miss" = 1 ]; then ok; else bad "a scanner added to scanners.json without a VEX classification must be caught (missing=$miss, want 1)"; fi
for s in grype trivy; do [ "$(python3 "$SCRIPT" classify --scanner $s)" = native ] && ok || bad "$s should classify as native"; done
for s in osv-scanner snyk; do [ "$(python3 "$SCRIPT" classify --scanner $s)" = filtered ] && ok || bad "$s should classify as filtered"; done
# the same statement with the workflow's real VEX file still parses (the document the pipeline passes)
vrun osv-scanner 1 "$OSV_FIND" ".vex/fosterstack-cache.openvex.json"
if [ "$V" != SCRIPT-FAILED ] && [ "$V" != error ]; then ok; else bad "the published VEX document was rejected by the filter ($V; $(cat "$D/vrun.err"))"; fi

# ==========================================================================
# REQ-REL-004-AC7: the tracking-issue lookup reads EVERY page of the open issues (30 per page by default; a tracking issue past page 1 must be found,
# or a second one is opened every day).
# ==========================================================================
mkdir -p "$D/bin"
cat >"$D/bin/gh" <<'GH'
#!/bin/bash
# a gh stub that serves $GH_ISSUES (a JSON array file) page by page the way `gh api --paginate` does: without --paginate only the first page
echo "gh $*" >>"$GH_CALLS"
[ -z "${GH_FAIL:-}" ] || { echo "gh: HTTP 502" >&2; exit 1; }
[ "$1" = api ] || exit 0
shift; pag=0; url=
for a in "$@"; do case $a in --paginate) pag=1;; -*) ;; *) url=$a;; esac; done
per=$(printf '%s' "$url" | sed -n 's/.*per_page=\([0-9]*\).*/\1/p'); per=${per:-30}
total=$(jq length "$GH_ISSUES"); page=0
while :; do
  jq -c --argjson s $((page*per)) --argjson n "$per" '.[$s:$s+$n]' "$GH_ISSUES"
  page=$((page+1)); [ $pag = 1 ] || break; [ $((page*per)) -lt "$total" ] || break
done
GH
chmod +x "$D/bin/gh"
GH_CALLS=$D/gh.calls; export GH_CALLS
issues() { # out-file target-index target-title : 250 open issues, one of them (at the index) with the title; page 1 holds 30 of them by default
  python3 - "$1" "$2" "$3" <<'P'
import json, sys
out, idx, title = sys.argv[1], int(sys.argv[2]), sys.argv[3]
items = [{"number": 1000 - i, "title": "Daily rescan: findings in other %d" % i, "labels": [{"name": "daily-rescan"}]} for i in range(250)]
if idx >= 0: items[idx]["title"] = title
json.dump(items, open(out, "w"))
P
}
TITLE="Daily rescan: findings in v0.3.0 production @abcdef012345 (osv-scanner)"
issues "$D/issues.json" 230 "$TITLE"      # the 231st: page 8 of 30 per page, page 3 of 100 per page
GH_ISSUES=$D/issues.json PATH="$D/bin:$PATH" GITHUB_REPOSITORY=fosterstack/cache python3 "$SCRIPT" find-issue --title "$TITLE" >"$D/found.out" 2>"$D/found.err" && rc=0 || rc=$?
if [ $rc = 0 ] && [ "$(cat "$D/found.out")" = "$((1000-230))" ]; then ok; else bad "find-issue: an issue on a late page was not found (rc=$rc, out='$(cat "$D/found.out")')"; fi
if grep -q -- '--paginate' "$D/gh.calls" && grep -q 'per_page=100' "$D/gh.calls" && grep -q 'labels=daily-rescan' "$D/gh.calls" && grep -q 'state=open' "$D/gh.calls"; then ok; else bad "find-issue must ask gh api --paginate for open issues with the label at 100 per page ($(cat "$D/gh.calls"))"; fi
issues "$D/issues0.json" -1 "$TITLE"
GH_ISSUES=$D/issues0.json PATH="$D/bin:$PATH" GITHUB_REPOSITORY=fosterstack/cache python3 "$SCRIPT" find-issue --title "$TITLE" >"$D/found.out" 2>/dev/null && rc=0 || rc=$?
if [ $rc = 0 ] && [ ! -s "$D/found.out" ]; then ok; else bad "find-issue: no matching issue must print nothing and exit 0 (rc=$rc)"; fi
# a pull request carries the title too (the issues API lists PRs): it is not a tracking issue
python3 - "$D/issues.json" "$D/issues-pr.json" "$TITLE" <<'P'
import json, sys
items = json.load(open(sys.argv[1])); items[5]["title"] = sys.argv[3]; items[5]["pull_request"] = {"url": "x"}; json.dump(items, open(sys.argv[2], "w"))
P
GH_ISSUES=$D/issues-pr.json PATH="$D/bin:$PATH" GITHUB_REPOSITORY=fosterstack/cache python3 "$SCRIPT" find-issue --title "$TITLE" >"$D/found.out" 2>/dev/null || true
if [ "$(cat "$D/found.out")" = "$((1000-230))" ]; then ok; else bad "find-issue: a pull request with the same title was taken for the tracking issue"; fi
# a gh failure is an error, never "no issue" (that would open a duplicate every day)
GH_FAIL=1 GH_ISSUES=$D/issues.json PATH="$D/bin:$PATH" GITHUB_REPOSITORY=fosterstack/cache python3 "$SCRIPT" find-issue --title "$TITLE" >"$D/found.out" 2>"$D/found.err" && rc=0 || rc=$?
if [ $rc != 0 ] && [ ! -s "$D/found.out" ] && grep -qi 'could not' "$D/found.err"; then ok; else bad "find-issue: a gh failure must exit non-zero and say so (rc=$rc)"; fi
printf 'not json at all' >"$D/garbage-issues.json"
GH_ISSUES=$D/garbage-issues.json PATH="$D/bin:$PATH" GITHUB_REPOSITORY=fosterstack/cache python3 "$SCRIPT" find-issue --title "$TITLE" >"$D/found.out" 2>"$D/found.err" && rc=0 || rc=$?
if [ $rc != 0 ]; then ok; else bad "find-issue: an unreadable reply must be an error, not 'no issue'"; fi
# the panel step of the workflow uses it, and no longer reads a single default page
WF=.github/workflows/main-candidate-rescan.yml
if grep -q 'rescan-statement.py find-issue' "$WF" && ! grep -qE 'gh issue list' "$WF"; then ok; else bad "the panel step must look the tracking issue up with find-issue (every page), not 'gh issue list' (first 30 only)"; fi
# the per-target github-script step: run the REAL script text against a fake github that serves 30 issues per page
python3 - "$WF" "$D/script.js" <<'P'
import re, sys
text = open(sys.argv[1]).read()
i = text.index("name: file/update a tracking issue on findings")
j = text.index("script: |\n", i) + len("script: |\n")
lines = []
for ln in text[j:].split("\n"):
    if ln.strip() and not ln.startswith("            "): break
    lines.append(ln[12:])
open(sys.argv[2], "w").write("\n".join(lines))
P
cat >"$D/run-script.js" <<'JS'
const fs = require('fs');
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const [, , scriptFile, issuesFile] = process.argv;
const all = JSON.parse(fs.readFileSync(issuesFile, 'utf8'));
const calls = { comment: [], create: [], pages: [] };
const listForRepo = async (p) => { const per = p.per_page || 30, page = p.page || 1; calls.pages.push(page); return { data: all.slice((page - 1) * per, page * per) }; };
const github = {
  paginate: async (fn, params) => { let out = [], page = 1; for (;;) { const r = await fn({ ...params, page }); out = out.concat(r.data); if (r.data.length < (params.per_page || 30)) break; page++; } return out; },
  rest: { issues: { listForRepo,
    createComment: async (p) => { calls.comment.push(p.issue_number); }, createLabel: async () => {}, create: async (p) => { calls.create.push(p.title); } } },
};
const context = { repo: { owner: 'fosterstack', repo: 'cache' }, serverUrl: 'https://github.com', runId: 1 };
const t = { release: 'v0.3.0', variant: 'production', digest: 'sha256:abcdef0123456789abcdef', scanner: 'osv-scanner' };
const script = fs.readFileSync(scriptFile, 'utf8').replace(/\$\{\{ toJSON\(matrix\.target\) \}\}/, JSON.stringify(t));
new AsyncFunction('github', 'context', script)(github, context).then(() => { console.log(JSON.stringify(calls)); }, (e) => { console.error(e.stack); process.exit(1); });
JS
issues "$D/issues-js.json" 230 "Daily rescan: findings in v0.3.0 production @abcdef012345 (osv-scanner)"
command -v node >/dev/null || { bad "node is required for the github-script pagination test"; }
node "$D/run-script.js" "$D/script.js" "$D/issues-js.json" >"$D/js.out" 2>"$D/js.err" && rc=0 || rc=$?
if [ $rc = 0 ] && [ "$(jq -c '.comment' "$D/js.out")" = "[$((1000-230))]" ] && [ "$(jq -c '.create' "$D/js.out")" = "[]" ]; then ok; else bad "the tracking-issue step opened a duplicate or failed instead of commenting on the issue on a late page (rc=$rc: $(cat "$D/js.out") $(head -3 "$D/js.err"))"; fi
issues "$D/issues-js0.json" -1 x
node "$D/run-script.js" "$D/script.js" "$D/issues-js0.json" >"$D/js.out" 2>"$D/js.err" || true
if [ "$(jq -c '.comment' "$D/js.out")" = "[]" ] && [ "$(jq '.create | length' "$D/js.out")" = "1" ]; then ok; else bad "the tracking-issue step must create the issue when none matches on any page ($(cat "$D/js.out"))"; fi
python3 - "$D/issues-js.json" "$D/issues-js-pr.json" <<'P'
import json, sys
items = json.load(open(sys.argv[1])); items[3]["title"] = "Daily rescan: findings in v0.3.0 production @abcdef012345 (osv-scanner)"; items[3]["pull_request"] = {"url": "x"}; items[230]["title"] = "other"; json.dump(items, open(sys.argv[2], "w"))
P
node "$D/run-script.js" "$D/script.js" "$D/issues-js-pr.json" >"$D/js.out" 2>"$D/js.err" || true
if [ "$(jq -c '.comment' "$D/js.out")" = "[]" ] && [ "$(jq '.create | length' "$D/js.out")" = "1" ]; then ok; else bad "the tracking-issue step took a pull request for the tracking issue ($(cat "$D/js.out"))"; fi

# ---- round 1 of the review of #268: fail-closed matching (closed rules, not residuals) ----------------------------------------------------------------------------
CAND_REPO="ghcr.io/fosterstack/cache-candidates"
P_CAND='{"@id":"pkg:oci/cache-candidates?repository_url=ghcr.io/fosterstack/cache-candidates&variant=production&arch=amd64"}'
P_CACHE='{"@id":"pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache&variant=production&arch=amd64"}'
vexdoc "$D/v/cand-only.json" "[$(st CVE-2024-9999 '[]' not_affected "[$P_CAND]")]"
vexdoc "$D/v/cache-only.json" "[$(st CVE-2024-9999 '[]' not_affected "[$P_CACHE]")]"
vrun osv-scanner 1 "$OSV_FIND" "$D/v/cand-only.json" production linux/amd64 "$REPO@$AMD"
expect "osv: a cache-candidates-only statement does NOT suppress a finding in the published cache image" findings true 1 0
vrun osv-scanner 1 "$OSV_FIND" "$D/v/cache-only.json" production linux/amd64 "$CAND_REPO@$AMD"
expect "osv: a cache-only statement does NOT suppress a finding in the cache-candidates image" findings true 1 0
vrun osv-scanner 1 "$OSV_FIND" "$D/v/cand-only.json" production linux/amd64 "$CAND_REPO@$AMD"
expect "osv: a cache-candidates statement suppresses a finding in the cache-candidates image (exact product)" clean false 0 1
vrun osv-scanner 1 "$OSV_FIND" "$D/v/cache-only.json" production linux/amd64 "$REPO@$AMD"
expect "osv: a cache statement suppresses a finding in the cache image (exact product)" clean false 0 1
vrun osv-scanner 1 "$OSV_FIND" "$D/v/by-cve.json" production linux/amd64 "not-an-image-reference"
expect "osv: when the scanned image identity cannot be read, no OCI statement applies (only the repository-wide Go product could)" findings true 1 0
vexdoc "$D/v/go-only.json" "[$(st CVE-2024-9999 '[]' not_affected "[$PROD_GO]")]"
vrun osv-scanner 1 "$OSV_FIND" "$D/v/go-only.json" production linux/amd64 "$CAND_REPO@$AMD"
expect "osv: the explicitly allowed repository-wide Go product covers every image" clean false 0 1
# a version-pinned Go product cannot be tied to this release: it never suppresses (and is not an error)
vexdoc "$D/v/go-versioned.json" "[$(st CVE-2024-9999 '[]' not_affected '[{"@id":"pkg:golang/github.com/fosterstack/cache@v0.0.1"}]')]"
vrun osv-scanner 1 "$OSV_FIND" "$D/v/go-versioned.json"; expect "osv: a version-pinned golang product does not suppress (cannot be tied to this release)" findings true 1 0
# malformed nested shapes: the VEX is unreadable (operational error; the finding stays counted), never "no restriction"
badvex() { # name statement-json
  printf '{"@context":"https://openvex.dev/ns/v0.2.0","@id":"x","version":1,"statements":[%s]}' "$2" >"$D/v/bad-$1.json"
  vrun osv-scanner 1 "$OSV_FIND" "$D/v/bad-$1.json"; expect "osv: a malformed VEX statement ($1) makes the VEX unreadable: operational error, finding still counted" error true 1 0
}
PR='"products":[{"@id":"pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache","subcomponents":%s}]'
for sub in '"bad"' '[null]' '["pkg:golang/golang.org/x/net@0.1.0"]' '5' '{"a":1}' '[{"@id":5}]' '[{}]'; do
  badvex "subcomponents-$(printf '%s' "$sub" | tr -c 'A-Za-z0-9' '_')" "{\"vulnerability\":{\"name\":\"CVE-2024-9999\"},\"status\":\"not_affected\",$(printf "$PR" "$sub")}"
done
badvex status-list '{"vulnerability":{"name":"CVE-2024-9999"},"status":["not_affected"],"products":[{"@id":"pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache"}]}'
badvex name-list '{"vulnerability":{"name":["CVE-2024-9999"]},"status":"not_affected","products":[{"@id":"pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache"}]}'
badvex aliases-int '{"vulnerability":{"name":"CVE-2024-9999","aliases":5},"status":"not_affected","products":[{"@id":"pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache"}]}'
badvex aliases-nonstr '{"vulnerability":{"name":"CVE-2024-9999","aliases":[5]},"status":"not_affected","products":[{"@id":"pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache"}]}'
badvex vulnerability-str '{"vulnerability":"CVE-2024-9999","status":"not_affected","products":[{"@id":"pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache"}]}'
badvex products-dict '{"vulnerability":{"name":"CVE-2024-9999"},"status":"not_affected","products":{"@id":"pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache"}}'
badvex products-int '{"vulnerability":{"name":"CVE-2024-9999"},"status":"not_affected","products":5}'
badvex products-str '{"vulnerability":{"name":"CVE-2024-9999"},"status":"not_affected","products":"pkg:oci/cache"}'
badvex product-str '{"vulnerability":{"name":"CVE-2024-9999"},"status":"not_affected","products":["pkg:oci/cache"]}'
badvex product-id-int '{"vulnerability":{"name":"CVE-2024-9999"},"status":"not_affected","products":[{"@id":5}]}'
badvex identifiers-list '{"vulnerability":{"name":"CVE-2024-9999"},"status":"not_affected","products":[{"identifiers":["x"]}]}'
badvex vulnerability-missing '{"status":"not_affected","products":[{"@id":"pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache"}]}'
# ...and a malformed statement that would NOT apply is still a malformed document
badvex affected-malformed '{"vulnerability":{"name":"CVE-2024-1"},"status":"affected","products":5}'
# product identifier forms that would parse as unscoped or as another product: the VEX is unreadable
for form in "variant=&arch=amd64" "Variant=debug" "variant=debug&variant=production" "repository_url=ghcr.io/fosterstack/cache&repository_url=ghcr.io/evil/x" "repository_url=ghcr.io/fosterstack/cache@sha256:00" "tag=latest" "arch=" "VARIANT=production"; do
  id="pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache&$form"; case $form in repository_url=*) id="pkg:oci/cache?$form";; esac
  badvex "qualifier-$(printf '%s' "$form" | tr -c 'A-Za-z0-9' '_')" "{\"vulnerability\":{\"name\":\"CVE-2024-9999\"},\"status\":\"not_affected\",\"products\":[{\"@id\":\"$id\"}]}"
done
printf '{"@context":"https://openvex.dev/ns/v0.2.0","@id":"x","version":1,"statements":[%s]}' '{"vulnerability":{"name":"CVE-2024-9999"},"status":"not_affected","products":[{"@id":"pkg:oci/cache@sha256:00?repository_url=ghcr.io/fosterstack/cache"}]}' >"$D/v/ign-oci-version.json"; vrun osv-scanner 1 "$OSV_FIND" "$D/v/ign-oci-version.json"
expect "osv: a product that only resembles ours (oci-version) is not ours: ignored, it suppresses nothing" findings true 1 0
printf '{"@context":"https://openvex.dev/ns/v0.2.0","@id":"x","version":1,"statements":[%s]}' '{"vulnerability":{"name":"CVE-2024-9999"},"status":"not_affected","products":[{"@id":"pkg:oci/cache?repository_url=ghcr.io/evil/cache"}]}' >"$D/v/ign-repo-evil.json"; vrun osv-scanner 1 "$OSV_FIND" "$D/v/ign-repo-evil.json"
expect "osv: a product that only resembles ours (repo-evil) is not ours: ignored, it suppresses nothing" findings true 1 0
badvex variant-unknown '{"vulnerability":{"name":"CVE-2024-9999"},"status":"not_affected","products":[{"@id":"pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache&variant=nope"}]}'
# a product that is simply not ours is fine (ignored): it neither suppresses nor breaks the document
vexdoc "$D/v/foreign.json" "[$(st CVE-2024-9999 '[]' not_affected '[{"@id":"pkg:npm/left-pad@1.0.0"}]')]"; vrun osv-scanner 1 "$OSV_FIND" "$D/v/foreign.json"
expect "osv: a statement for a product that is not ours is ignored (finding kept, no error)" findings true 1 0
# Snyk: the advisory's alternative identifier is one of the finding's ids
SNYK_ALT='{"vulnerabilities":[{"id":"SNYK-DEBIAN12-OPENSSL-1","identifiers":{"CVE":[],"ALTERNATIVE":["SNYK-ALT-77"]},"severity":"high","packageName":"openssl","version":"3.0.1"}],"applications":[]}'
vexdoc "$D/v/snyk-alt.json" "[$(st SNYK-ALT-77 '[]' not_affected "[$PROD_REPO]")]"
vrun snyk 1 "$SNYK_ALT" "$D/v/snyk-alt.json"; expect "snyk: a statement naming the advisory's ALTERNATIVE identifier removes the finding" clean false 0 1
# find-issue: a valid first page followed by garbage is an error; an object (not an array) reply is an error
cat >"$D/bin/gh-bad" <<'GH'
#!/bin/bash
case "${GH_MODE}" in page-garbage) echo '[{"number":1,"title":"x"}]'; echo 'not json';; object) echo '{"message":"Not Found"}';; esac
GH
chmod +x "$D/bin/gh-bad"; mkdir -p "$D/bin2"; cp "$D/bin/gh-bad" "$D/bin2/gh"
for mode in page-garbage object; do
  GH_MODE=$mode PATH="$D/bin2:$PATH" GITHUB_REPOSITORY=fosterstack/cache python3 "$SCRIPT" find-issue --title "$TITLE" >"$D/found.out" 2>"$D/found.err" && rc=0 || rc=$?
  if [ $rc = 1 ] && [ ! -s "$D/found.out" ]; then ok; else bad "find-issue ($mode): must be an error (exit 1) with no output (rc=$rc)"; fi
done

echo "rescan-statement: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
