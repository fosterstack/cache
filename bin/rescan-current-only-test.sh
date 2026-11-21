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
# the manifest lands at /tmp/m-<tag>.json; the test points that path at its own RUNNER_TEMP, so no case touches the host's /tmp
run = step["run"].replace('"/tmp/m-', '"$RUNNER_TEMP/m-')
assert '"$RUNNER_TEMP/m-${tag}.json"' in run, "collect no longer downloads to a manifest path under /tmp or RUNNER_TEMP"
open(sys.argv[2], "w").write(run)
# the pattern step (REQ-CHAIN-004-AC20): its own step before collect; absent today means the file is not written
pat = [s for s in d["jobs"]["manifests"]["steps"] if s.get("id") == "pattern"]
if pat:
    open(sys.argv[2].replace("collect.sh", "pattern.sh"), "w").write(pat[0].get("run", ""))
PY

mkdir -p "$work/bin"
cat > "$work/bin/gh" <<'STUB'
#!/usr/bin/env bash
# gh stub: reads $FIX; logs every call to $FIX/calls.log
echo "$*" >> "$FIX/calls.log"
case "$1 $2" in
  "release list")
    [ ! -e "$FIX/list-fails" ] || { echo "HTTP 502" >&2; exit 1; }
    [ ! -e "$FIX/list-raw" ] || { cat "$FIX/list-raw"; exit 0; }
    lim=100000; a=("$@"); for i in "${!a[@]}"; do [ "${a[$i]}" = "--limit" ] && lim=${a[$((i+1))]}; done
    jq -c ".[:$lim]" "$FIX/list.json" ;;
  "release view")
    [ ! -e "$FIX/view-fails" ] || { echo "HTTP 502" >&2; exit 1; }
    tag=$3; [ -e "$FIX/view-$tag.json" ] || { echo "release not found" >&2; exit 1; }
    jq -r "$(printf '%s\n' "$@" | sed -n '/^--jq$/{n;p;}')" "$FIX/view-$tag.json" ;;
  "release download")
    tag=$3; out=""; while [ $# -gt 0 ]; do [ "$1" = "-O" ] && out=$2; shift; done
    [ ! -e "$FIX/dl-fails" ] || { echo "HTTP 502" >&2; exit 1; }
    [ ! -e "$FIX/dl-fails-after-write" ] || { cp "$FIX/m-$tag.json" "$out"; echo "HTTP 502" >&2; exit 1; }
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
  mkdir -p "$work/repo/bin"; cp "$root/bin/build-admit.py" "$work/repo/bin/"
  echo "$1" > "$FIX/list.json"; shift
  local n=1; for t in "$@"; do manifest "$t" "$n"; n=$((n+1)); done
  : > "$FIX/calls.log"; : > "$work/out"
}
# the real grammar, for a harness whose workflow has no pattern step yet (then only the new pattern cases are red)
real_re=$(python3 -I "$root/bin/build-admit.py" tag-pattern)
# run the pattern step as the workflow would (no token, bash -e, cwd = the repo); sets prc, pmsg, and tag_re from its `re=` output
pattern_step() {
  prc=0; : > "$work/pout"
  if [ -f "$work/pattern.sh" ]; then
    pmsg=$(cd "$work/repo" && env -i PATH="$work/bin:$PATH" HOME="$work" GITHUB_OUTPUT="$work/pout" RUNNER_TEMP="$work/rt" bash -e -c "$(cat "$work/pattern.sh")" 2>&1) || prc=$?
    tag_re=$(sed -n 's/^re=//p' "$work/pout")
  else pmsg=""; tag_re="$real_re"; fi
}
# run the collect step with the pattern step's output as TAG_RE; sets rc, msg; outputs in $work/out. TAGRE_OVERRIDE (set, even empty) replaces TAG_RE; TAGRE_UNSET=1 leaves it out.
run() {
  rc=0; [ "${SKIP_PATTERN:-0}" = 1 ] || pattern_step   # SKIP_PATTERN=1: judge the collect step alone (TAGRE_OVERRIDE gives its TAG_RE)
  local tre="$tag_re"; [ -z "${TAGRE_OVERRIDE+x}" ] || tre="$TAGRE_OVERRIDE"
  local -a tenv=(); [ "${TAGRE_UNSET:-0}" = 1 ] || tenv=(TAG_RE="$tre")
  msg=$(cd "$work/repo" && env "${tenv[@]}" PATH="$work/bin:$PATH" GITHUB_OUTPUT="$work/out" RUNNER_TEMP="$work/rt" GH_TOKEN=x \
        bash -c "$(cat "$work/collect.sh")" 2>&1) || rc=$?
}
targets() { sed -n 's/^targets=//p' "$work/out"; }
anyv()    { sed -n 's/^any=//p' "$work/out"; }
nscan=$(jq '.scanners | length' "$root/.github/policy/scanners.json")

REL='[{"tagName":"v0.2.2","isDraft":false,"isPrerelease":false},{"tagName":"v0.2.3","isDraft":true,"isPrerelease":false},{"tagName":"v0.3.0-rc1","isDraft":false,"isPrerelease":true},{"tagName":"v0.3.0","isDraft":false,"isPrerelease":true},{"tagName":"nightly","isDraft":false,"isPrerelease":false},{"tagName":"v0.2.1","isDraft":false,"isPrerelease":false},{"tagName":"v0.2.0","isDraft":false,"isPrerelease":false},{"tagName":"v0.1.0","isDraft":false,"isPrerelease":false}]'

# 1. the fixture list: exactly v0.2.2, its three variants x every scanner, nothing else
setup "$REL" v0.2.0 v0.2.1 v0.2.2 v0.2.3 v0.3.0-rc1 v0.3.0 nightly
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
for L in '[]' '[{"tagName":"v0.2.3","isDraft":true,"isPrerelease":false},{"tagName":"v0.3.0-rc1","isDraft":false,"isPrerelease":true},{"tagName":"nightly","isDraft":false,"isPrerelease":false}]'; do
  setup "$L" v0.2.3 v0.3.0-rc1
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
if ! grep -q 'gh release' <<<"$panel" && grep -q 'four images' "$wf"; then ok "the panel/tally jobs are independent of the release enumeration (four images of main's candidate)"
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

# 15. truncation: a list that reaches the limit may hide the current release - fail closed, never a wrong or empty day
LIMMSG='release list reached the limit of 1000: the current release may be hidden'
for spec in 'exactly 1000 entries, current oldest|[range(1;1000) | {tagName:("v0.0."+tostring),isDraft:false,isPrerelease:false}] + [{tagName:"v1.0.0",isDraft:false,isPrerelease:false}]' \
            '1001 entries, current oldest|[range(1;1001) | {tagName:("v0.0."+tostring),isDraft:false,isPrerelease:false}] + [{tagName:"v1.0.0",isDraft:false,isPrerelease:false}]' \
            '1000 drafts ahead of the current|[range(1;1001) | {tagName:("v0.9."+tostring),isDraft:true,isPrerelease:false}] + [{tagName:"v1.0.0",isDraft:false,isPrerelease:false}]'; do
  setup "$(jq -n -c "${spec#*|}")" v1.0.0
  run
  if [ "$rc" -ne 0 ] && [ -z "$(targets)" ] && [ -z "$(anyv)" ] && grep -qF "$LIMMSG" <<<"$msg"; then ok "truncation: ${spec%%|*} fails closed with the limit message"
  else bad "truncation: ${spec%%|*}" "rc=$rc targets=$(targets | head -c 100) msg=${msg:0:200}"; fi
done

# 16. the shape guard stops a malformed target BEFORE anything is written to GITHUB_OUTPUT
for how in 'a missing digest|del(.images[0].digest)' 'a newline in the variant|.images[0].variant = "pro\nduction"' 'a bad digest|.images[0].digest = "sha256:xyz"'; do
  setup '[{"tagName":"v0.2.2","isDraft":false,"isPrerelease":false}]' v0.2.2
  jq -c "${how#*|}" "$FIX/m-v0.2.2.json" > "$FIX/m.tmp" && mv "$FIX/m.tmp" "$FIX/m-v0.2.2.json"
  run
  if [ "$rc" -ne 0 ] && ! grep -q 'targets=' "$work/out" && ! grep -q 'any=' "$work/out" && grep -q 'malformed' <<<"$msg"; then ok "shape guard: ${how%%|*} fails before any output is written"
  else bad "shape guard: ${how%%|*}" "rc=$rc out=$(head -c 120 "$work/out") msg=${msg:0:200}"; fi
done

# 17. every operational failure on the current release fails closed: exit 1, a NAMED error, and NOTHING written to GITHUB_OUTPUT
nothing_out() { ! grep -qE '^(targets|any)=' "$work/out"; }
CURL='[{"tagName":"v0.2.2","isDraft":false,"isPrerelease":false}]'
chk() { # <name> <expected message fragment>
  if [ "$rc" -eq 1 ] && nothing_out && grep -qF "$2" <<<"$msg"; then ok "fail closed: $1"
  else bad "fail closed: $1" "rc=$rc out=$(head -c 100 "$work/out") msg=${msg:0:200}"; fi
}
setup "$CURL" v0.2.2; echo '{"message":"API rate limit exceeded"}' > "$FIX/list-raw"; run
chk "a non-array release list response" 'did not return a JSON array'
setup "$CURL" v0.2.2; touch "$FIX/view-fails"; run
chk "a failed gh release view" 'could not read the assets of release v0.2.2'
setup "$CURL" v0.2.2; touch "$FIX/dl-fails"; run
chk "a failed manifest download" 'could not be downloaded'
setup "$CURL" v0.2.2; touch "$FIX/dl-fails-after-write"; run   # gh writes a VALID manifest, then exits non-zero
chk "a download that fails AFTER writing a valid manifest" 'could not be downloaded'
setup "$CURL" v0.2.2; touch "$FIX/dl-fails"; cp "$FIX/m-v0.2.2.json" "$work/rt/m-v0.2.2.json"; run   # a stale valid file is already at the path collect downloads to
chk "a failed download with a stale valid manifest already at the path" 'could not be downloaded'
setup "$CURL" v0.2.2; printf 'not json {' > "$FIX/m-v0.2.2.json"; run
chk "an invalid manifest (not JSON)" 'is not valid JSON'
setup "$CURL" v0.2.2; : > "$FIX/m-v0.2.2.json"; run
chk "an empty (unreadable) manifest" 'is not valid JSON'
setup "$CURL" v0.2.2; echo '{"images":[]}' > "$FIX/m-v0.2.2.json"; run
chk "a manifest with no images" 'lists no images'
setup "$CURL"; jq '.releases += [{"version":"v0.2.2","images":[]}]' "$root/.github/policy/legacy-releases.json" > "$work/repo/.github/policy/legacy-releases.json"; run
chk "zero targets for the current release (legacy images:[])" 'produced no rescan targets'
setup "$CURL" v0.2.2; echo '{"scanners":[]}' > "$work/repo/.github/policy/scanners.json"; run
chk "zero targets for the current release (scanners=[])" 'produced no rescan targets'

# 18. REQ-CHAIN-004-AC20: the tag pattern is computed by its own tokenless step; collect (which holds GH_TOKEN) only receives it
python3 - "$wf" > "$work/struct.out" <<'PY'
import re, sys, json, yaml
d = yaml.safe_load(open(sys.argv[1])); TOK = re.compile(r"GH_TOKEN|GITHUB_TOKEN|github\.token|secrets\.", re.I)
def dump(x): return json.dumps(x, sort_keys=True)
res = {}
for jn, job in d["jobs"].items():
    for i, st in enumerate(job.get("steps", [])):
        held = TOK.search(dump(st.get("env", {})) + dump(st.get("with", {})) + str(st.get("run", "")) + dump(job.get("env", {})) + dump(d.get("env", {})))
        if held and re.search(r"build[-_]admit", dump(st)): res["tokenholder-" + jn + "-" + str(i)] = "a step with a token mentions build-admit"
steps = d["jobs"]["manifests"]["steps"]
ids = [s.get("id") for s in steps]
if "pattern" not in ids: res["nopattern"] = "no step with id: pattern in job manifests"
else:
    p = steps[ids.index("pattern")]; c = steps[ids.index("collect")]
    if ids.index("pattern") > ids.index("collect"): res["order"] = "pattern step is not before collect"
    if TOK.search(dump(p.get("env", {})) + dump(p.get("with", {})) + str(p.get("run", "")) + dump(d["jobs"]["manifests"].get("env", {})) + dump(d.get("env", {}))): res["tokenpattern"] = "pattern step holds a token"
    if "tag-pattern" not in p.get("run", "") or "build-admit.py" not in p.get("run", ""): res["nocall"] = "pattern step does not call build-admit.py tag-pattern"
    if "GITHUB_OUTPUT" not in p.get("run", "") or not re.search(r"\bre=", p.get("run", "")): res["nooutput"] = "pattern step does not write re= to GITHUB_OUTPUT"
    if (c.get("env") or {}).get("TAG_RE") != "${{ steps.pattern.outputs.re }}": res["tagre"] = "collect env TAG_RE is %r" % (c.get("env") or {}).get("TAG_RE")
if re.search(r"build[-_]admit", str(next(s for s in steps if s.get("id") == "collect").get("run", "")) + dump(next(s for s in steps if s.get("id") == "collect").get("env", {}))): res["collect"] = "collect mentions build-admit"
print(json.dumps(res))
PY
sres=$(cat "$work/struct.out")
for spec in 'tokenholder|no step that holds a token (any job of main-candidate-rescan.yml) mentions build-admit.py' 'collect|the collect step does not mention build-admit' \
            'nopattern|the pattern step exists (id: pattern)' 'order|the pattern step comes before collect' 'tokenpattern|the pattern step holds no token' \
            'nocall|the pattern step calls build-admit.py tag-pattern' 'nooutput|the pattern step writes re= to GITHUB_OUTPUT' 'tagre|collect receives TAG_RE from steps.pattern.outputs.re'; do
  k=${spec%%|*}; n=${spec#*|}
  if [ "$(jq --arg k "$k" '[keys[] | select(startswith($k))] | length' <<<"$sres")" -eq 0 ]; then ok "structure: $n"
  else bad "structure: $n" "$(jq -c . <<<"$sres" | head -c 250)"; fi
done

# 19. collect checks TAG_RE before use: unset or empty is an error, never "no published release" with any=false
setup "$REL" v0.2.2
TAGRE_OVERRIDE="" run
if [ "$rc" -ne 0 ] && grep -q '::error::' <<<"$msg" && ! grep -q 'any=' "$work/out" && ! grep -qi 'no published release' <<<"$msg"; then ok "collect with an empty TAG_RE fails with ::error:: and emits no any="
else bad "collect with an empty TAG_RE fails closed" "rc=$rc out=$(head -c 100 "$work/out") msg=${msg:0:200}"; fi
setup "$REL" v0.2.2
TAGRE_UNSET=1 run
if [ "$rc" -ne 0 ] && grep -q '::error::' <<<"$msg" && ! grep -q 'any=' "$work/out" && ! grep -qi 'no published release' <<<"$msg"; then ok "collect with TAG_RE unset fails with ::error:: and emits no any="
else bad "collect with TAG_RE unset fails closed" "rc=$rc out=$(head -c 100 "$work/out") msg=${msg:0:200}"; fi
unset TAGRE_OVERRIDE TAGRE_UNSET

# 20. collect uses the TAG_RE it is given, and never runs build-admit.py itself
setup '[{"tagName":"v0.2.10","isDraft":false,"isPrerelease":false},{"tagName":"v0.2.2","isDraft":false,"isPrerelease":false}]' v0.2.2 v0.2.10
TAGRE_OVERRIDE='v0\.2\.2' run; t=$(targets)
if [ "$rc" -eq 0 ] && [ "$(jq -c '[.[].release] | unique' <<<"${t:-[]}")" = '["v0.2.2"]' ]; then ok "collect picks the current release and checks the shape with the TAG_RE it was given"
else bad "collect uses the given TAG_RE" "rc=$rc targets=${t:0:200} msg=${msg:0:200}"; fi
unset TAGRE_OVERRIDE
setup "$REL" v0.2.2; printf 'open("%s/admit-ran", "w").close()\nprint("x")\n' "$work" > "$work/repo/bin/build-admit.py"; rm -f "$work/admit-ran"
SKIP_PATTERN=1 TAGRE_OVERRIDE="$real_re" run
if [ ! -e "$work/admit-ran" ] && [ "$rc" -eq 0 ]; then ok "collect never runs bin/build-admit.py (a planted one is not executed)"
else bad "collect never runs build-admit.py" "ran=$([ -e "$work/admit-ran" ] && echo yes || echo no) rc=$rc msg=${msg:0:200}"; fi
unset TAGRE_OVERRIDE

# 21. the pattern step fails, and writes no empty re, when tag-pattern fails or prints nothing
pcase() { # <label> <stub build-admit.py body>
  setup "$REL" v0.2.2; printf '%s\n' "$2" > "$work/repo/bin/build-admit.py"; pattern_step
  if [ -f "$work/pattern.sh" ] && [ "$prc" -ne 0 ] && ! grep -q '^re=' "$work/pout"; then ok "pattern step: $1 fails the step and writes no re"
  else bad "pattern step: $1" "have_step=$([ -f "$work/pattern.sh" ] && echo yes || echo no) rc=$prc out=$(head -c 80 "$work/pout") msg=${pmsg:0:150}"; fi
}
pcase "a failing tag-pattern" 'import sys; sys.exit(1)'
pcase "a tag-pattern that prints nothing" 'import sys; sys.exit(0)'
pcase "a tag-pattern that prints only a newline" 'print()'
setup "$REL" v0.2.2; pattern_step
if [ -f "$work/pattern.sh" ] && [ "$prc" -eq 0 ] && [ "$(sed -n 's/^re=//p' "$work/pout")" = "$real_re" ] && [ -n "$real_re" ]; then ok "pattern step: with the real build-admit.py it writes re=<the grammar's pattern>"
else bad "pattern step writes the real pattern" "rc=$prc out=$(head -c 120 "$work/pout") msg=${pmsg:0:150}"; fi
# the whole chain: a failing tag-pattern must never reach "no published release / any=false / exit 0" through collect
setup "$REL" v0.2.2; printf 'import sys; sys.exit(1)\n' > "$work/repo/bin/build-admit.py"; run
if [ -f "$work/pattern.sh" ] && [ "$prc" -ne 0 ] && ! grep -q 'any=false' "$work/out" && { [ "$rc" -ne 0 ] || [ "$prc" -ne 0 ]; }; then ok "a failing tag-pattern ends in a red pattern step and never in any=false"
else bad "a failing tag-pattern is never a quiet day" "prc=$prc rc=$rc out=$(head -c 80 "$work/out")"; fi

echo "passed: $pass failed: $failn"
[ "$failn" -eq 0 ]
