#!/usr/bin/env bash
# proves: REQ-REL-004-AC5
# The daily rescan covers the current release only (owner, Oct 9 2026; scanner-panel rules, "AMENDED ... the daily rescan
# covers the current release only"). The enumeration is the "collect" step of the "enumerate release manifests" job in
# main-candidate-rescan.yml; this test runs that step's own script, offline, with gh stubbed through PATH and a fixture
# release list, and judges the matrix it emits.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
wf="$root/.github/workflows/main-candidate-rescan.yml"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0; failn=0
ok()   { pass=$((pass+1)); echo "PASS $1"; }
bad()  { failn=$((failn+1)); echo "FAIL $1 -> $2"; }

# the collect step's script, exactly as the workflow has it
python3 - "$wf" "$work/collect.sh" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
step = [s for s in d["jobs"]["manifests"]["steps"] if s.get("id") == "collect"][0]
open(sys.argv[2], "w").write(step["run"])
PY

mkdir -p "$work/bin"
cat > "$work/bin/gh" <<'STUB'
#!/usr/bin/env bash
# gh stub: reads $FIX; logs every call to $FIX/calls.log
echo "$*" >> "$FIX/calls.log"
case "$1 $2" in
  "release list")
    [ ! -e "$FIX/list-fails" ] || { echo "HTTP 502" >&2; exit 1; }
    lim=100000; a=("$@"); for i in "${!a[@]}"; do [ "${a[$i]}" = "--limit" ] && lim=${a[$((i+1))]}; done
    jq -c ".[:$lim]" "$FIX/list.json" ;;
  "release view")
    tag=$3; [ -e "$FIX/view-$tag.json" ] || { echo "release not found" >&2; exit 1; }
    jq -r "$(printf '%s\n' "$@" | sed -n '/^--jq$/{n;p;}')" "$FIX/view-$tag.json" ;;
  "release download")
    tag=$3; out=""; while [ $# -gt 0 ]; do [ "$1" = "-O" ] && out=$2; shift; done
    [ -e "$FIX/m-$tag.json" ] || exit 1
    cp "$FIX/m-$tag.json" "$out" ;;
  *) echo "unexpected gh call: $*" >&2; exit 9 ;;
esac
STUB
chmod +x "$work/bin/gh"

dg() { printf 'sha256:%064d' "$1"; }
manifest() { # tag seed
  jq -n --arg d1 "$(dg "$2"1)" --arg d2 "$(dg "$2"2)" --arg d3 "$(dg "$2"3)" \
    '{images:[{variant:"production",digest:$d1},{variant:"debug",digest:$d2},{variant:"fips",digest:$d3}]}' > "$FIX/m-$1.json"
  echo '{"assets":[{"name":"release-manifest.json"}]}' > "$FIX/view-$1.json"
}

# fresh fixture world; $1 = list JSON; remaining args = tags that carry a manifest
setup() {
  FIX="$work/fix"; export FIX; rm -rf "$FIX" "$work/repo" "$work/rt"
  mkdir -p "$FIX" "$work/repo/.github/policy" "$work/rt"
  cp "$root/.github/policy/scanners.json" "$root/.github/policy/legacy-releases.json" "$work/repo/.github/policy/"
  echo "$1" > "$FIX/list.json"; shift
  local n=1; for t in "$@"; do manifest "$t" "$n"; n=$((n+1)); done
  : > "$FIX/calls.log"; : > "$work/out"
}
# run the step; sets rc, msg; outputs in $work/out
run() {
  rc=0
  msg=$(cd "$work/repo" && PATH="$work/bin:$PATH" GITHUB_OUTPUT="$work/out" RUNNER_TEMP="$work/rt" GH_TOKEN=x \
        bash -c "$(cat "$work/collect.sh")" 2>&1) || rc=$?
}
targets() { sed -n 's/^targets=//p' "$work/out"; }
anyv()    { sed -n 's/^any=//p' "$work/out"; }
nscan=$(jq '.scanners | length' "$root/.github/policy/scanners.json")

REL='[{"tagName":"v0.2.2","isDraft":false,"isPrerelease":false},{"tagName":"v0.2.3","isDraft":true,"isPrerelease":false},{"tagName":"v0.3.0-rc.1","isDraft":false,"isPrerelease":true},{"tagName":"v0.3.0","isDraft":false,"isPrerelease":true},{"tagName":"nightly","isDraft":false,"isPrerelease":false},{"tagName":"v0.2.1","isDraft":false,"isPrerelease":false},{"tagName":"v0.2.0","isDraft":false,"isPrerelease":false},{"tagName":"v0.1.0","isDraft":false,"isPrerelease":false}]'

# 1. the fixture list: exactly v0.2.2, its three variants x every scanner, nothing else
setup "$REL" v0.2.0 v0.2.1 v0.2.2 v0.2.3 v0.3.0-rc.1 v0.3.0 nightly
run
t=$(targets)
if [ "$rc" -eq 0 ] && [ "$(jq -c '[.[].release] | unique' <<<"${t:-[]}")" = '["v0.2.2"]' ] \
   && [ "$(jq 'length' <<<"${t:-[]}")" -eq $((3 * nscan)) ] \
   && [ "$(jq -c '[.[].variant] | unique | sort' <<<"${t:-[]}")" = '["debug","fips","production"]' ] \
   && [ "$(anyv)" = true ]; then ok "fixture list: exactly v0.2.2 (3 variants x $nscan scanners)"
else bad "fixture list: exactly v0.2.2" "rc=$rc targets=${t:0:200} msg=${msg:0:200}"; fi

# 2. a superseded, draft, prerelease or non-semver release is never even looked at (no scan, so no issue for it)
if ! grep -E 'release (view|download) (v0\.2\.0|v0\.2\.1|v0\.2\.3|v0\.3\.0-rc\.1|v0\.3\.0|nightly|v0\.1\.0)( |$)' "$FIX/calls.log" >/dev/null; then
  ok "no superseded, draft, prerelease or unsemver release is inspected"
else bad "no superseded release is inspected" "$(tr '\n' ';' < "$FIX/calls.log")"; fi

# 3. the legacy inventory's v0.1.0 is not rescanned once a newer release is current
if [ "$(jq '[.[] | select(.release == "v0.1.0")] | length' <<<"${t:-[]}")" -eq 0 ]; then ok "legacy v0.1.0 is superseded and not rescanned"
else bad "legacy v0.1.0 not rescanned" "present"; fi

# 4. next day a newer published release becomes the only one
NEW='[{"tagName":"v0.2.3","isDraft":false,"isPrerelease":false}]'
setup "$(jq -c ". + $NEW" <<<"$REL" | jq -c 'map(if .tagName=="v0.2.3" then .isDraft=false else . end)')" v0.2.2 v0.2.3 v0.2.1
run; t=$(targets)
if [ "$rc" -eq 0 ] && [ "$(jq -c '[.[].release] | unique' <<<"${t:-[]}")" = '["v0.2.3"]' ]; then ok "a newer published release becomes the only one"
else bad "newer release becomes the only one" "rc=$rc targets=${t:0:200}"; fi

# 5. semantic version, not date and not text: list is newest-first by date, v0.2.9 is dated after v0.2.10
setup '[{"tagName":"v0.2.9","isDraft":false,"isPrerelease":false},{"tagName":"v0.2.10","isDraft":false,"isPrerelease":false},{"tagName":"v0.2.2","isDraft":false,"isPrerelease":false}]' v0.2.9 v0.2.10 v0.2.2
run; t=$(targets)
if [ "$rc" -eq 0 ] && [ "$(jq -c '[.[].release] | unique' <<<"${t:-[]}")" = '["v0.2.10"]' ]; then ok "sorted by semantic version (v0.2.10 beats v0.2.9 and the newest date)"
else bad "semver ordering" "rc=$rc targets=${t:0:200}"; fi

# 6. no published release (empty list, or only drafts and prereleases): empty matrix, a clear message, success
for L in '[]' '[{"tagName":"v0.2.3","isDraft":true,"isPrerelease":false},{"tagName":"v0.3.0-rc.1","isDraft":false,"isPrerelease":true},{"tagName":"nightly","isDraft":false,"isPrerelease":false}]'; do
  setup "$L" v0.2.3 v0.3.0-rc.1
  run
  if [ "$rc" -eq 0 ] && [ "$(targets)" = '[]' ] && [ "$(anyv)" = false ] && grep -qi 'no published release' <<<"$msg"; then ok "no published release: empty matrix, clear message ($(jq -c 'map(.tagName)' <<<"$L"))"
  else bad "no published release" "rc=$rc targets=$(targets) any=$(anyv) msg=${msg:0:200}"; fi
done

# 7. the current release has no manifest and is not in the legacy inventory: fail closed, never a silent empty day
setup '[{"tagName":"v0.2.4","isDraft":false,"isPrerelease":false},{"tagName":"v0.2.2","isDraft":false,"isPrerelease":false}]' v0.2.2
echo '{"assets":[]}' > "$FIX/view-v0.2.4.json"
run
if [ "$rc" -ne 0 ] && [ -z "$(anyv)" ] && grep -q 'v0.2.4' <<<"$msg"; then ok "current release without a manifest fails closed (no matrix)"
else bad "current release without a manifest fails closed" "rc=$rc any=$(anyv) msg=${msg:0:200}"; fi

# 8. a failed release list is an error, never an empty day
setup "$REL" v0.2.2; touch "$FIX/list-fails"
run
if [ "$rc" -ne 0 ] && [ -z "$(anyv)" ]; then ok "a failed gh release list fails the job"
else bad "failed release list" "rc=$rc any=$(anyv)"; fi

# 9. the current release is a legacy-inventory release: its pinned digests are used (the F12 case)
setup '[{"tagName":"v0.1.0","isDraft":false,"isPrerelease":false}]'
run; t=$(targets)
if [ "$rc" -eq 0 ] && [ "$(jq -c '[.[].release] | unique' <<<"${t:-[]}")" = '["v0.1.0"]' ] \
   && [ "$(jq -c '[.[].source] | unique' <<<"$t")" = '["legacy-inventory"]' ]; then ok "a current legacy release is covered from the inventory"
else bad "current legacy release" "rc=$rc targets=${t:0:200}"; fi

# 10. the matrix shape guard is still in front of the matrix
if grep -q 'jq -e "\$TARGET_SHAPE"' "$work/collect.sh"; then ok "every target's shape is still checked before the matrix"
else bad "shape check" "gone"; fi

# 11. the six-image panel (main's candidate) does not read the release list, so one rescanned release leaves its count alone
panel=$(python3 - "$wf" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1])); j = d["jobs"]
print("\n".join(str(v) for k, v in j.items() if k not in ("manifests", "rescan")))
PY
)
if ! grep -q 'gh release' <<<"$panel" && grep -q 'six images' "$wf"; then ok "the panel/tally jobs are independent of the release enumeration (six images of main's candidate)"
else bad "panel independence" "panel jobs read the release list"; fi

# 12. B1 fail-open: a CURRENT release that yields no targets is an error, never a quiet day
CUR='[{"tagName":"v0.2.2","isDraft":false,"isPrerelease":false}]'
setup "$CUR"   # legacy entry with images:[]
jq '.releases += [{"version":"v0.2.2","images":[]}]' "$root/.github/policy/legacy-releases.json" > "$work/repo/.github/policy/legacy-releases.json"
run
if [ "$rc" -ne 0 ] && [ "$(anyv)" != false ] && grep -q 'current release v0.2.2 produced no rescan targets' <<<"$msg"; then ok "B1: legacy entry with images:[] fails closed"
else bad "B1 legacy images:[]" "rc=$rc any=$(anyv) msg=${msg:0:200}"; fi
setup "$CUR" v0.2.2   # scanners.json with .scanners=[]
echo '{"scanners":[]}' > "$work/repo/.github/policy/scanners.json"
run
if [ "$rc" -ne 0 ] && [ "$(anyv)" != false ] && grep -q 'current release v0.2.2 produced no rescan targets' <<<"$msg"; then ok "B1: scanners=[] fails closed"
else bad "B1 scanners=[]" "rc=$rc any=$(anyv) msg=${msg:0:200}"; fi
setup "$CUR" v0.2.2   # manifest with no images
echo '{"images":[]}' > "$FIX/m-v0.2.2.json"
run
if [ "$rc" -ne 0 ] && [ "$(anyv)" != false ] && grep -q 'v0.2.2' <<<"$msg"; then ok "B1: manifest with no images fails closed"
else bad "B1 manifest no images" "rc=$rc any=$(anyv) msg=${msg:0:200}"; fi

# 13. R4: more than 100 releases, the current one the oldest by creation date (last in the newest-first list)
L=$(jq -n -c '[range(1;150) | {tagName:("v0.0."+tostring),isDraft:false,isPrerelease:false}] + [{tagName:"v1.0.0",isDraft:false,isPrerelease:false}]')
setup "$L" v1.0.0
run; t=$(targets)
if [ "$rc" -eq 0 ] && [ "$(jq -c '[.[].release] | unique' <<<"${t:-[]}")" = '["v1.0.0"]' ]; then ok "R4: 150 releases, the oldest-created current release is still found"
else bad "R4 >100 releases" "rc=$rc targets=${t:0:200} msg=${msg:0:200}"; fi

# 14. R3: a tag with leading zeros is not a version (v0.02.9 would equal v0.2.9 and outrank v0.2.0)
setup '[{"tagName":"v0.02.9","isDraft":false,"isPrerelease":false},{"tagName":"v0.2.0","isDraft":false,"isPrerelease":false}]' v0.02.9 v0.2.0
run; t=$(targets)
if [ "$rc" -eq 0 ] && [ "$(jq -c '[.[].release] | unique' <<<"${t:-[]}")" = '["v0.2.0"]' ] && ! grep -q 'v0\.02\.9\|v0.02.9' <(grep 'release \(view\|download\)' "$FIX/calls.log"); then ok "R3: a leading-zero tag is never current and never inspected"
else bad "R3 leading zeros" "rc=$rc targets=${t:0:200}"; fi

echo "passed: $pass failed: $failn"
[ "$failn" -eq 0 ]
