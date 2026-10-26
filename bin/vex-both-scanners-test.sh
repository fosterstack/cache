#!/usr/bin/env bash
# proves: REQ-REL-004-AC1
# REQ-REL-004-AC1 (ratified Sep 29, row 73): "A test proves that a VEX-covered
# finding is suppressed for both scanners and an uncovered one blocks."
# One finding — BusyBox CVE-2025-60876 in FosterStack's image — is put through
# BOTH gate paths against the retired-busybox fixture document (test-evidence/vex-scope/busybox.openvex.json; the committed .vex holds one jwt/v4 statement now):
#   Grype     : bin/grype-scan.sh over a synthetic SBOM (Grype applies VEX natively)
#   Inspector : bin/inspector-gate.py over a CycloneDX SBOM + a ScanSbom-shaped
#               response (the gate applies VEX itself; nothing in AWS)
# busybox 1.37.0 is covered (suppressed, exit 0); 1.36.0 is not (blocks); a
# zero-package inventory fails both. An UNKNOWN-severity finding that survives the VEX blocks too (grype's --fail-on does not fire on it); unreadable
# findings fail closed. Needs the pinned grype (hygiene installs it).
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; repo="$(cd "$here/.." && pwd)"
vex="$repo/test-evidence/vex-scope/busybox.openvex.json"
base="$repo/test-evidence/vex-scope/busybox-image.sbom.json"
grype="${GRYPE:-$(command -v grype || true)}"   # PATH or $GRYPE only: no probing of a fixed system location
[ -n "$grype" ] && [ -x "$grype" ] || { echo "::error::grype not found — install it (bin/install-scanner.sh grype) before this test" >&2; exit 1; }
# The new probes assert real grype behaviour, so they must run against the pinned grype (bin/install-scanner.sh GRYPE_VER), not whatever is first on PATH.
want_ver="$(sed -n 's/^GRYPE_VER=//p' "$repo/bin/install-scanner.sh" | head -1)"
have_ver="$("$grype" version 2>/dev/null | sed -n 's/^Version:[[:space:]]*//p' | head -1)"
[ -n "$want_ver" ] && [ "$have_ver" = "$want_ver" ] || { echo "::error::this test needs the pinned grype $want_ver (bin/install-scanner.sh grype); $grype is ${have_ver:-unknown}" >&2; exit 1; }
"$grype" db update >/dev/null 2>&1 || true
w="$(mktemp -d)"; trap 'rm -rf "$w"' EXIT
# grype-scan.sh reads only the published .vex/fosterstack-cache.openvex.json, with no override (a security boundary): it runs from a temp tree whose .vex file is the fixture.
mkdir -p "$w/tree/bin" "$w/tree/.vex"; cp "$here/grype-scan.sh" "$w/tree/bin/"; cp "$vex" "$w/tree/.vex/fosterstack-cache.openvex.json"; gs="$w/tree/bin/grype-scan.sh"
pass=0; fail=0
CVE=CVE-2025-60876

ok()  { echo "ok: $1"; pass=$((pass+1)); }
bad() { echo "FAIL: $1"; [ -n "${2:-}" ] && echo "$2" | sed 's/^/    /'; fail=$((fail+1)); }

grype_sbom() { # version out [empty]
  python3 - "$base" "$2" "$1" "${3:-}" <<'PY'
import json,sys
base,out,ver,empty=sys.argv[1:5]
d=json.load(open(base)); m=d['source']['metadata']
d['source']['name']='ghcr.io/fosterstack/cache'
m['userInput']=m['tags'][0]='ghcr.io/fosterstack/cache:cand-debug-amd64'; m['repoDigests']=[]
a=d['artifacts'][0]; a['version']=ver; a['purl']='pkg:generic/busybox@'+ver
a['cpes'][0]['cpe']='cpe:2.3:a:busybox:busybox:%s:*:*:*:*:*:*:*'%ver
if empty: d['artifacts']=[]; d['artifactRelationships']=[]
json.dump(d,open(out,'w'))
PY
}
insp_inputs() { # version prefix [empty]
  local comps='[{"bom-ref":"b1","type":"application","name":"busybox","version":"'"$1"'","purl":"pkg:generic/busybox@'"$1"'"}]'
  [ -n "${3:-}" ] && comps='[]'
  printf '{"bomFormat":"CycloneDX","specVersion":"1.5","components":%s}' "$comps" > "$w/$2.sbom.json"
  printf '{"sbom":{"bomFormat":"CycloneDX","specVersion":"1.5","components":%s,"vulnerabilities":[{"id":"%s","ratings":[{"severity":"medium"}],"affects":[{"ref":"b1"}]}]}}' \
    "$comps" "$CVE" > "$w/$2.resp.json"
}

for case in "1.37.0 covered 0" "1.36.0 uncovered 1"; do
  set -- $case; ver=$1; what=$2; want=$3
  grype_sbom "$ver" "$w/g-$ver.json"
  out="$(GRYPE="$grype" bash "$gs" "sbom:$w/g-$ver.json" "busybox-$ver" 2>&1)"; rc=$?
  if [ "$want" = 0 ]; then
    [ "$rc" -eq 0 ] && grep -q "busybox-$ver: [1-9][0-9]* packages, 0 finding" <<<"$out" \
      && ok "grype: VEX-${what} $CVE (busybox $ver) suppressed, exit 0" || bad "grype: VEX-${what} busybox $ver (rc $rc)" "$out"
  else
    [ "$rc" -ne 0 ] && grep -q "$CVE" <<<"$out" \
      && ok "grype: ${what} $CVE (busybox $ver) blocks, exit $rc" || bad "grype: ${what} busybox $ver (rc $rc)" "$out"
  fi
  insp_inputs "$ver" "i-$ver"
  out="$(python3 "$here/inspector-gate.py" "busybox-$ver" "$w/i-$ver.sbom.json" "$w/i-$ver.resp.json" "$vex" 2>&1)"; rc=$?
  if [ "$want" = 0 ]; then
    [ "$rc" -eq 0 ] && grep -q "0 finding(s), 1 covered by the published VEX" <<<"$out" && grep -q "vex: $CVE busybox@$ver" <<<"$out" \
      && ok "inspector: VEX-${what} $CVE (busybox $ver) suppressed, exit 0" || bad "inspector: VEX-${what} busybox $ver (rc $rc)" "$out"
  else
    [ "$rc" -eq 1 ] && grep -q "::error::inspector busybox-$ver: $CVE busybox@$ver" <<<"$out" \
      && ok "inspector: ${what} $CVE (busybox $ver) blocks, exit 1" || bad "inspector: ${what} busybox $ver (rc $rc)" "$out"
  fi
done

grype_sbom 1.37.0 "$w/g-empty.json" empty
out="$(GRYPE="$grype" bash "$gs" "sbom:$w/g-empty.json" empty 2>&1)"; rc=$?
[ "$rc" -eq 2 ] && grep -q "0 packages.*did not run" <<<"$out" && ok "grype: zero packages fails (exit 2)" || bad "grype: zero packages (rc $rc)" "$out"
# grype that cannot catalog at all (no output written) is also 0 packages, exit 2 (round-4 blocker).
out="$(GRYPE="$grype" bash "$gs" "sbom:$w/does-not-exist.json" crashed 2>&1)"; rc=$?
[ "$rc" -eq 2 ] && grep -q "crashed: 0 packages" <<<"$out" && grep -q "0 packages in crashed.*did not run" <<<"$out" \
  && ok "grype: a catalog failure is 0 packages, exit 2" || bad "grype: catalog failure (rc $rc)" "$out"
insp_inputs 1.37.0 i-empty empty
out="$(python3 "$here/inspector-gate.py" empty "$w/i-empty.sbom.json" "$w/i-empty.resp.json" "$vex" 2>&1)"; rc=$?
[ "$rc" -eq 2 ] && grep -q "0 packages.*did not run" <<<"$out" && ok "inspector: zero packages fails (exit 2)" || bad "inspector: zero packages (rc $rc)" "$out"

# REQ-REL-004-AC1 "Both block at any severity": `grype --fail-on negligible` exits 0 on a finding of UNKNOWN severity (grype ranks unknown below
# negligible), so grype-scan.sh must judge the surviving findings itself, as bin/check-scan.sh does for the release Check (register rows 18 and 38).
# The wrapper runs the REAL grype (same arguments, so the VEX is applied by grype itself), then relabels every finding that SURVIVED the VEX to
# severity "unknown" in the CycloneDX file and exits 0, which is what grype does when the only findings are UNKNOWN. Nothing the VEX removed is ever
# put back, so the VEX'd case below passes only because grype's output really leaves VEX-covered findings out.
cat > "$w/grype-unknown" <<'SH'
#!/usr/bin/env bash
"$REAL_GRYPE" "$@" > /dev/null 2>&1
cdx=""; for a in "$@"; do case "$a" in cyclonedx-json=*) cdx="${a#cyclonedx-json=}";; esac; done
python3 - "$cdx" <<'PY'
import json, sys
p = sys.argv[1]; d = json.load(open(p))
for v in d.get("vulnerabilities") or []:
    v["ratings"] = [{"severity": "unknown", "method": "other"}]
json.dump(d, open(p, "w"))
PY
exit 0
SH
chmod +x "$w/grype-unknown"
# Both outputs the script asks for, written by a fake grype that exits 0: $1 is the CycloneDX text, $2 the native JSON text.
fake_grype() { # name cdx-text json-text
  cat > "$w/$1" <<SH
#!/usr/bin/env bash
cdx=""; js=""; for a in "\$@"; do case "\$a" in cyclonedx-json=*) cdx="\${a#cyclonedx-json=}";; json=*) js="\${a#json=}";; esac; done
printf '%s' '$2' > "\$cdx"
[ -n "\$js" ] && printf '%s' '$3' > "\$js"
exit 0
SH
  chmod +x "$w/$1"
}
OKCDX='{"components":[{"name":"busybox","version":"1.36.0","purl":"pkg:generic/busybox@1.36.0"}],"vulnerabilities":[]}'
OKJSON='{"matches":[],"ignoredMatches":[]}'
fake_grype grype-badvulns '{"components":[{"name":"busybox","version":"1.36.0","purl":"pkg:generic/busybox@1.36.0"}],"vulnerabilities":"not a list"}' "$OKJSON"
fake_grype grype-garbage "$OKCDX trailing-garbage" "$OKJSON"
fake_grype grype-jsongarbage "$OKCDX" "$OKJSON trailing-garbage"
fake_grype grype-matchesnolist "$OKCDX" '{"matches":"oops","ignoredMatches":[]}'
fake_grype grype-matchesmissing "$OKCDX" '{"ignoredMatches":[]}'

# (a) the exclusion is real: with --vex, grype's CycloneDX leaves out every VEX-covered finding and lists them as ignored in its own JSON.
grype_sbom 1.37.0 "$w/g-cov.json"
"$grype" "sbom:$w/g-cov.json" --fail-on negligible --vex "$vex" -o "cyclonedx-json=$w/cov.cdx.json" -o json > "$w/cov.json" 2> /dev/null
cv=$(jq '[.vulnerabilities[]?] | length' "$w/cov.cdx.json" 2> /dev/null); ig=$(jq '.ignoredMatches | length' "$w/cov.json" 2> /dev/null)
[ "$cv" = 0 ] && [ "${ig:-0}" -ge 1 ] 2> /dev/null && ok "grype: VEX-covered findings are absent from the CycloneDX output ($ig ignored by the VEX, $cv in the output)" \
  || bad "grype: VEX-covered findings in the CycloneDX output (output $cv, ignored ${ig:-?})"

# (b) the UNKNOWN path: grype exits 0 (its --fail-on does not fire) while a finding that the VEX does not cover survives: the script blocks.
grype_sbom 1.36.0 "$w/g-unc.json"
out="$(REAL_GRYPE="$grype" GRYPE="$w/grype-unknown" bash "$gs" "sbom:$w/g-unc.json" unknown-uncovered 2>&1)"; rc=$?
[ "$rc" -eq 1 ] && grep -q "unknown-uncovered: [1-9][0-9]* packages, [1-9][0-9]* finding" <<<"$out" && grep -q "any severity, UNKNOWN included" <<<"$out" \
  && ok "grype: grype exits 0 with surviving findings (the UNKNOWN path, busybox 1.36.0) blocks, exit 1" || bad "grype: grype exits 0 with surviving findings (rc $rc)" "$out"

# (c) the same finding covered by the VEX passes, because grype leaves it out (see (a)).
out="$(REAL_GRYPE="$grype" GRYPE="$w/grype-unknown" bash "$gs" "sbom:$w/g-cov.json" unknown-covered 2>&1)"; rc=$?
[ "$rc" -eq 0 ] && grep -q "unknown-covered: [1-9][0-9]* packages, 0 finding" <<<"$out" \
  && ok "grype: the same finding covered by the VEX (busybox 1.37.0) passes, exit 0" || bad "grype: VEX-covered UNKNOWN case (rc $rc)" "$out"

# (d) fail closed: a CycloneDX file whose findings cannot be read is exit 2, never a pass.
out="$(GRYPE="$w/grype-badvulns" bash "$gs" "sbom:$w/g-unc.json" badvulns 2>&1)"; rc=$?
[ "$rc" -eq 2 ] && grep -q "the findings in its CycloneDX output cannot be read" <<<"$out" \
  && ok "grype: unreadable findings in the CycloneDX file fail closed, exit 2 (the CycloneDX check, native JSON valid)" || bad "grype: unreadable findings (rc $rc)" "$out"
for c in garbage:"a CycloneDX file with trailing garbage" jsongarbage:"a JSON result with trailing garbage" matchesnolist:"a matches entry that is not a list" matchesmissing:"a JSON result with no matches list"; do
  n=${c%%:*}; what=${c#*:}
  out="$(GRYPE="$w/grype-$n" bash "$gs" "sbom:$w/g-unc.json" "$n" 2>&1)"; rc=$?
  [ "$rc" -eq 2 ] && ok "grype: $what (valid document first) fails closed, exit 2" || bad "grype: $what (rc $rc)" "$out"
done

# (e) Non-VEX suppressions. grype also drops findings through a config file (.grype.yaml ignore:, home or XDG config) and through GRYPE_* settings such as
# GRYPE_ONLY_FIXED; the published VEX is the only exception (REQ-REL-004-AC1). The script pins an empty config with -c, refuses GRYPE_* variables other
# than GRYPE_DB_*, and rejects every ignoredMatches entry that is not a VEX rule (namespace "vex" and a vex-status).
mkdir "$w/cfgdir"
printf 'ignore:\n  - vulnerability: CVE-2022-48174\n  - vulnerability: CVE-2025-60876\n  - vulnerability: CVE-2025-46394\n  - vulnerability: CVE-2024-58251\n' > "$w/cfgdir/.grype.yaml"
out="$(cd "$w/cfgdir" && GRYPE="$grype" bash "$gs" "sbom:$w/g-unc.json" cfg-ignore 2>&1)"; rc=$?
[ "$rc" -ne 0 ] && grep -q "$CVE" <<<"$out" && ! grep -q "not a VEX" <<<"$out" && ok "grype: a .grype.yaml ignore: in the working directory does not hide busybox 1.36.0, exit $rc" \
  || bad "grype: .grype.yaml ignore in the working directory (rc $rc)" "$out"
out="$(GRYPE_ONLY_FIXED=true GRYPE="$grype" bash "$gs" "sbom:$w/g-unc.json" env-only-fixed 2>&1)"; rc=$?
[ "$rc" -eq 2 ] && grep -q "GRYPE_ONLY_FIXED" <<<"$out" && ! grep -q "=true" <<<"$out" \
  && ok "grype: GRYPE_ONLY_FIXED=true blocks busybox 1.36.0 (exit 2, the variable named, no value printed)" || bad "grype: GRYPE_ONLY_FIXED set (rc $rc)" "$out"
out="$(GRYPE_DB_AUTO_UPDATE=false GRYPE="$grype" bash "$gs" "sbom:$w/g-unc.json" db-var 2>&1)"; rc=$?
[ "$rc" -ne 0 ] && ! grep -q "GRYPE_DB_AUTO_UPDATE" <<<"$out" && grep -q "$CVE" <<<"$out" \
  && ok "grype: GRYPE_DB_AUTO_UPDATE is allowed and busybox 1.36.0 still blocks, exit $rc" || bad "grype: GRYPE_DB_* variable (rc $rc)" "$out"
for v in GRYPE_DB_VALIDATE_AGE GRYPE_DB_MAX_ALLOWED_BUILT_AGE GRYPE_DB_UPDATE_URL GRYPE_IGNORE_WONTFIX; do
  out="$(env "$v=false" GRYPE="$grype" bash "$gs" "sbom:$w/g-unc.json" "env-$v" 2>&1)"; rc=$?
  [ "$rc" -eq 2 ] && grep -q "$v" <<<"$out" && grep -q "refusing to run" <<<"$out" && ok "grype: $v is refused (exit 2, the variable named)" || bad "grype: $v set (rc $rc)" "$out"
done
# defence in depth: a grype that DID apply a non-VEX suppression (a wrapper drops -c and sets GRYPE_ONLY_FIXED / uses a config file) exits 0 with the
# findings in ignoredMatches; the script must still block, and name them.
cat > "$w/grype-onlyfixed" <<'SH'
#!/usr/bin/env bash
args=(); skip=0
for a in "$@"; do if [ "$skip" = 1 ]; then skip=0; continue; fi; if [ "$a" = -c ]; then skip=1; continue; fi; args+=("$a"); done
GRYPE_ONLY_FIXED=true exec "$REAL_GRYPE" "${args[@]}"
SH
cat > "$w/grype-cfgfile" <<'SH'
#!/usr/bin/env bash
args=(); skip=0
for a in "$@"; do if [ "$skip" = 1 ]; then skip=0; continue; fi; if [ "$a" = -c ]; then skip=1; continue; fi; args+=("$a"); done
cd "$CFGDIR" && exec "$REAL_GRYPE" "${args[@]}"
SH
chmod +x "$w/grype-onlyfixed" "$w/grype-cfgfile"
for c in onlyfixed:"GRYPE_ONLY_FIXED" cfgfile:"a config-file ignore"; do
  n=${c%%:*}; what=${c#*:}
  out="$(REAL_GRYPE="$grype" CFGDIR="$w/cfgdir" GRYPE="$w/grype-$n" bash "$gs" "sbom:$w/g-unc.json" "ign-$n" 2>&1)"; rc=$?
  [ "$rc" -eq 1 ] && grep -q "$CVE" <<<"$out" && grep -q "not a VEX" <<<"$out" \
    && ok "grype: findings hidden by $what (grype exit 0) block, exit 1, CVE named" || bad "grype: findings hidden by $what (rc $rc)" "$out"
done
# ignoredMatches shapes: absent or null is fine, a list of VEX-only entries is fine, everything else fails closed (exit 2 for a wrong type, 1 for an entry that is not a clean VEX rule).
ENT='{"vulnerability":{"id":"CVE-2099-1"},"artifact":{"name":"pkg","version":"1.0"}'
shape() { # name expected-rc json-text what [text the output must contain]
  fake_grype "grype-shape-$1" "$OKCDX" "$3"
  out="$(GRYPE="$w/grype-shape-$1" bash "$gs" "sbom:$w/g-unc.json" "shape-$1" 2>&1)"; rc=$?
  [ "$rc" -eq "$2" ] && { [ -z "${5:-}" ] || grep -q "$5" <<<"$out"; } && ok "grype: ignoredMatches $4 -> exit $2" || bad "grype: ignoredMatches $4 (rc $rc, want $2)" "$out"
}
shape absent 0 '{"matches":[]}' "absent"
shape null 0 '{"matches":[],"ignoredMatches":null}' "null"
shape vexok 0 "{\"matches\":[],\"ignoredMatches\":[$ENT,\"appliedIgnoreRules\":[{\"namespace\":\"vex\",\"vex-status\":\"not_affected\"}]},$ENT,\"appliedIgnoreRules\":[{\"namespace\":\"vex\",\"vex-status\":\"fixed\"}]}]}" "two VEX-only entries (not_affected, fixed)"
shape notlist 2 '{"matches":[],"ignoredMatches":"oops"}' "a string"
shape statusnum 1 "{\"matches\":[],\"ignoredMatches\":[$ENT,\"appliedIgnoreRules\":[{\"namespace\":\"vex\",\"vex-status\":123}]}]}" "a vex-status that is a number"
shape statusother 1 "{\"matches\":[],\"ignoredMatches\":[$ENT,\"appliedIgnoreRules\":[{\"namespace\":\"vex\",\"vex-status\":\"under_investigation\"}]}]}" "a vex-status that is not not_affected or fixed"
shape objrules 1 "{\"matches\":[],\"ignoredMatches\":[$ENT,\"appliedIgnoreRules\":{\"namespace\":\"vex\",\"vex-status\":\"fixed\"}}]}" "appliedIgnoreRules an object, not an array"
shape norules 1 "{\"matches\":[],\"ignoredMatches\":[$ENT}]}" "an entry with no appliedIgnoreRules"
shape emptyrules 1 "{\"matches\":[],\"ignoredMatches\":[$ENT,\"appliedIgnoreRules\":[]}]}" "an entry with an empty rule list"
shape nonobjrule 1 "{\"matches\":[],\"ignoredMatches\":[$ENT,\"appliedIgnoreRules\":[\"vex\"]}]}" "a rule that is not an object"
shape scalar 1 '{"matches":[],"ignoredMatches":["malformed-entry"]}' "an entry that is a string, not an object" "a malformed entry"
shape nons 1 "{\"matches\":[],\"ignoredMatches\":[$ENT,\"appliedIgnoreRules\":[{\"vex-status\":\"fixed\"}]}]}" "a rule with no namespace"
shape mixed 1 "{\"matches\":[],\"ignoredMatches\":[$ENT,\"appliedIgnoreRules\":[{\"namespace\":\"vex\",\"vex-status\":\"fixed\"},{\"namespace\":\"\",\"fix-state\":\"unknown\"}]}]}" "a VEX rule plus a config rule"
# These two depend on the live vulnerability database (busybox 1.36.0 having exactly these findings, none with a fix version); they fail loudly, never pass falsely.
# the VEX itself still passes with the native JSON present: every ignoredMatches entry of the covered case is a VEX rule.
out="$(GRYPE="$grype" bash "$gs" "sbom:$w/g-cov.json" cov-json 2>&1)"; rc=$?
[ "$rc" -eq 0 ] && ok "grype: VEX-covered busybox 1.37.0 still passes with the native JSON checked (every ignored entry is a VEX rule)" || bad "grype: covered case with the JSON check (rc $rc)" "$out"

# 0674: a scan of a tar made from a layout's child names the config digest of that child as its image ID;
# grype-scan.sh checks it when the caller says which one it expects (EXPECT_IMAGE_ID), so a tar of another
# image can never be scanned in place of the one we ship.
CFG=sha256:$(printf 'a%.0s' $(seq 64))
fake_grype grype-id-ok "$OKCDX" "{\"matches\":[],\"ignoredMatches\":[],\"source\":{\"target\":{\"imageID\":\"$CFG\"}}}"
fake_grype grype-id-other "$OKCDX" '{"matches":[],"ignoredMatches":[],"source":{"target":{"imageID":"sha256:other"}}}'
fake_grype grype-id-none "$OKCDX" "$OKJSON"
out="$(EXPECT_IMAGE_ID=$CFG GRYPE="$w/grype-id-ok" bash "$gs" "sbom:$w/g-cov.json" id-ok 2>&1)"; rc=$?
[ "$rc" -eq 0 ] && ok "grype: the expected image ID is read from the report and passes" \
  || bad "grype: expected image ID (rc $rc)" "$out"
for g in id-other id-none; do
  out="$(EXPECT_IMAGE_ID=$CFG GRYPE="$w/grype-$g" bash "$gs" "sbom:$w/g-cov.json" "$g" 2>&1)"; rc=$?
  [ "$rc" -eq 2 ] && grep -q "image ID" <<<"$out" && ok "grype: $g is not the expected image: exit 2, the IDs named" \
    || bad "grype: $g (rc $rc, want 2 naming the image ID)" "$out"
done
out="$(GRYPE="$w/grype-id-other" bash "$gs" "sbom:$w/g-cov.json" id-unset 2>&1)"; rc=$?
[ "$rc" -eq 0 ] && ok "grype: with no expected image ID nothing is compared (the PR gate's other targets)" \
  || bad "grype: id unset (rc $rc)" "$out"

# rc-5a C (astra B3): the package count is the components that carry a package URL; files, which grype also lists as components (946 of 965 on a real
# image), are not packages. A file-only inventory is 0 packages = did not run (row 53), never a pass.
fake_grype grype-fileonly '{"components":[{"type":"file","name":"/usr/lib/f0"},{"type":"file","name":"/usr/lib/f1"}],"vulnerabilities":[]}' "$OKJSON"
fake_grype grype-emptypurl '{"components":[{"type":"library","name":"busybox","version":"1.36.0","purl":""}],"vulnerabilities":[]}' "$OKJSON"
fake_grype grype-nullpurl '{"components":[{"type":"library","name":"busybox","version":"1.36.0","purl":null}],"vulnerabilities":[]}' "$OKJSON"
fake_grype grype-filesandone '{"components":[{"type":"file","name":"/usr/lib/f0"},{"type":"file","name":"/usr/lib/f1"},{"type":"library","name":"busybox","version":"1.36.0","purl":"pkg:generic/busybox@1.36.0"}],"vulnerabilities":[]}' "$OKJSON"
fake_grype grype-numpurl '{"components":[{"type":"library","name":"busybox","version":"1.36.0","purl":7},{"type":"library","name":"x","purl":{}},{"type":"library","name":"y","purl":[]},{"type":"library","name":"z","purl":true}],"vulnerabilities":[]}' "$OKJSON"
fake_grype grype-strpurl '{"components":[{"type":"file","name":"/usr/lib/f0","purl":"not-a-purl"}],"vulnerabilities":[]}' "$OKJSON"
fake_grype grype-schemeonly '{"components":[{"type":"library","name":"busybox","version":"1.36.0","purl":"pkg:"}],"vulnerabilities":[]}' "$OKJSON"
fake_grype grype-noname '{"components":[{"type":"library","name":"b","purl":"pkg:/"},{"type":"library","name":"c","purl":"pkg:deb/"},{"type":"library","name":"d","purl":"pkg:?q=/"}],"vulnerabilities":[]}' "$OKJSON"
for g in grype-fileonly grype-emptypurl grype-nullpurl grype-numpurl grype-strpurl grype-schemeonly grype-noname; do
  out="$(GRYPE="$w/$g" bash "$here/grype-scan.sh" "sbom:$w/does-not-matter.json" "$g" 2>&1)"; rc=$?
  [ "$rc" -eq 2 ] && grep -q "$g: 0 packages" <<<"$out" && grep -q "0 packages in $g.*did not run" <<<"$out" \
    && ok "grype: $g is 0 packages (components without a package URL are not packages), exit 2" || bad "grype: $g (rc $rc)" "$out"
done
out="$(GRYPE="$w/grype-filesandone" bash "$here/grype-scan.sh" "sbom:$w/does-not-matter.json" filesandone 2>&1)"; rc=$?
[ "$rc" -eq 0 ] && grep -q "filesandone: 1 packages, 0 finding" <<<"$out" \
  && ok "grype: two files and one package are 1 package, and the scan passes" || bad "grype: files and one package (rc $rc)" "$out"

echo "----"
echo "vex-both-scanners: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
