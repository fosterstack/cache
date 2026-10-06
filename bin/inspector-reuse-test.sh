#!/usr/bin/env bash
# proves: REQ-REL-004-AC5
# Same-day reuse of Amazon Inspector results (REQ-REL-004-AC5). Offline; bash on macOS and Linux.
#   A. bin/inspector-reuse.py: key (the SBOM's package names and versions, never a timestamp, serial number or
#      our own module's version), decide (reuse only a valid stored result for the same UTC day and key),
#      store (atomic, only a valid result).
#   B. SIMULATED RUNS: the real call-site step of scan.yml and of main-candidate-rescan.yml is extracted, its
#      /tmp paths moved into a sandbox, and run against a fake inspector-sbomgen and a fake aws that record
#      their calls: reuse on a match, a fresh call on each of the three ways it can differ, the gate/tally
#      input present in every case.
#   C. WIRING over the two workflow files, with mutations that must each be caught.
set -uo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
prog="$root/bin/inspector-reuse.py"
w=$(mktemp -d); trap 'rm -rf "$w"' EXIT
pass=0 failn=0
ok()   { pass=$((pass+1)); echo "PASS $1"; }
bad()  { failn=$((failn+1)); echo "FAIL $1"; }
expect() { # name want got
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want '$2', got '$3')"; fi
}

# ---------------------------------------------------------------------------------------------------------------
# A. the program
mksbom() { # out serial timestamp ourversion pkg@ver...
  python3 - "$@" <<'PY'
import json, sys
out, serial, ts, ours = sys.argv[1:5]
comps = []
for p in sys.argv[5:]:
    n, v = p.rsplit("@", 1)
    if n.startswith("np:"):   # a component with no purl (name@version is its identifier)
        comps.append({"type": "library", "name": n[3:], "version": v})
    else:
        comps.append({"type": "library", "name": n, "version": v, "purl": "pkg:generic/%s@%s" % (n, v)})
if ours != "-":
    comps.append({"type": "library", "name": "github.com/fosterstack/cache", "version": ours,
                  "purl": "pkg:golang/github.com/fosterstack/cache@" + ours})
doc = {"bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": serial,
       "metadata": {"timestamp": ts, "component": {"name": "img", "version": ts}}, "components": comps}
json.dump(doc, open(out, "w"))
PY
}
mkfind() { printf '%s' '{"sbom":{"bomFormat":"CycloneDX","specVersion":"1.5","components":[],"vulnerabilities":[]}}' > "$1"; }

mksbom "$w/a.json"  urn:uuid:1 2026-10-06T01:00:00Z v1 busybox@1.37.0 libc6@2.36 np:zlib@1.3
mksbom "$w/a2.json" urn:uuid:2 2026-10-07T09:00:00Z v2 np:zlib@1.3 libc6@2.36 busybox@1.37.0   # same inventory, other order
mksbom "$w/a3.json" urn:uuid:3 2026-10-08T09:00:00Z -  busybox@1.37.0 libc6@2.36 np:zlib@1.3  # no module component at all
mksbom "$w/b.json"  urn:uuid:1 2026-10-06T01:00:00Z v1 busybox@1.37.1 libc6@2.36 np:zlib@1.3  # a package version differs
mksbom "$w/c.json"  urn:uuid:1 2026-10-06T01:00:00Z v1 busybox@1.37.0 libc6@2.36 np:zlib@1.3 curl@8.0  # a package added
mksbom "$w/d.json"  urn:uuid:1 2026-10-06T01:00:00Z v1 busybox@1.37.0 libc6@2.36 np:zlib@1.4  # name@version fallback differs

ka=$(python3 "$prog" key "$w/a.json") ; rc=$?
expect "key: exits 0" 0 "$rc"
case "$ka" in [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ok "key: 16 hex" ;; *) bad "key: 16 hex ('$ka')" ;; esac
expect "key: another serial number, timestamp, our module version and component order: same key" "$ka" "$(python3 "$prog" key "$w/a2.json")"
expect "key: no module component at all: same key (our module is excluded)" "$ka" "$(python3 "$prog" key "$w/a3.json")"
for n in b c d; do
  k=$(python3 "$prog" key "$w/$n.json"); [ -n "$k" ] && [ "$k" != "$ka" ] && ok "key: inventory $n differs: different key" || bad "key: inventory $n differs: different key"
done
# a sub-package of our module and the name form are also excluded; a look-alike module is NOT
python3 - "$w" <<'PY'
import json, sys
w = sys.argv[1]
d = json.load(open(w + "/a.json"))
d["components"].append({"type": "library", "name": "github.com/fosterstack/cache/internal/x", "version": "v9", "purl": "pkg:golang/github.com/fosterstack/cache/internal/x@v9"})
d["components"].append({"type": "library", "name": "github.com/fosterstack/cache", "version": "v77"})
json.dump(d, open(w + "/a-sub.json", "w"))
d = json.load(open(w + "/a.json"))
d["components"].append({"type": "library", "name": "github.com/fosterstack/cache-other", "version": "v1", "purl": "pkg:golang/github.com/fosterstack/cache-other@v1"})
json.dump(d, open(w + "/a-look.json", "w"))
PY
expect "key: our module's sub-package and a purl-less entry of it are excluded" "$ka" "$(python3 "$prog" key "$w/a-sub.json")"
[ "$(python3 "$prog" key "$w/a-look.json")" != "$ka" ] && ok "key: a look-alike module (cache-other) is an ordinary package" || bad "key: a look-alike module (cache-other) is an ordinary package"
# metadata and timestamps are never read: break them and the key must not move
python3 - "$w" <<'PY'
import json, sys
w = sys.argv[1]
d = json.load(open(w + "/a.json")); d["metadata"] = "garbage"; d["serialNumber"] = 12; d["extra"] = {"timestamp": 1}
json.dump(d, open(w + "/a-meta.json", "w"))
PY
expect "key: metadata and serialNumber are never read" "$ka" "$(python3 "$prog" key "$w/a-meta.json")"
# malformed SBOMs exit non-zero and print no key
printf 'not json' > "$w/m1.json"; printf '[]' > "$w/m2.json"; printf '{}' > "$w/m3.json"; : > "$w/m4.json"
printf '{"components":{}}' > "$w/m5.json"; printf '{"components":[]}' > "$w/m6.json"; printf '{"components":[5]}' > "$w/m7.json"
printf '{"components":[{"type":"library"}]}' > "$w/m8.json"
for n in m1 m2 m3 m4 m5 m6 m7 m8 nonexistent; do
  out=$(python3 "$prog" key "$w/$n.json" 2>/dev/null); rc=$?
  if [ "$rc" -ne 0 ] && [ -z "$out" ]; then ok "key: malformed SBOM ($n) exits non-zero, prints no key"; else bad "key: malformed SBOM ($n) (rc=$rc out='$out')"; fi
done

D="2026-10-06"; Y="2026-10-05"; K="$ka"
cdir="$w/cache"
mkfind "$w/f.json"
python3 "$prog" store "$cdir" "$D" "$K" "$w/f.json" > "$w/so.txt"; rc=$?
expect "store: a valid result is stored (exit 0)" 0 "$rc"
expect "store: prints nothing on success" "" "$(cat "$w/so.txt")"
[ -f "$cdir/$D/$K.findings.json" ] && cmp -s "$w/f.json" "$cdir/$D/$K.findings.json" && ok "store: copied byte for byte to DIR/DATE/KEY.findings.json" || bad "store: copied byte for byte"
expect "store: no temp file left behind" "$K.findings.json" "$(ls -A "$cdir/$D")"
out=$(python3 "$prog" decide "$cdir" "$D" "$K"); rc=$?
expect "decide: a match reuses (exit 0)" 0 "$rc"
expect "decide: reuse, then the path as the second line" "reuse
$cdir/$D/$K.findings.json" "$out"
printf '%s' '{"bomFormat":"CycloneDX","specVersion":"1.5","vulnerabilities":[]}' > "$w/f-bare.json"
python3 "$prog" store "$cdir" "$D" "0123456789abcdef" "$w/f-bare.json"; rc=$?
expect "store: a bare CycloneDX document is valid too" 0 "$rc"
expect "decide: a bare CycloneDX document is reused" reuse "$(python3 "$prog" decide "$cdir" "$D" 0123456789abcdef | head -1)"

expect "decide: a different hash calls" call "$(python3 "$prog" decide "$cdir" "$D" fedcba9876543210)"
expect "decide: a different UTC day (an entry from yesterday) calls" call "$(python3 "$prog" decide "$cdir" "$Y" "$K")"
mkdir -p "$cdir/$Y"; cp "$cdir/$D/$K.findings.json" "$cdir/$Y/$K.findings.json"
expect "decide: yesterday's entry exists, today asked: today has none, calls" call "$(python3 "$prog" decide "$cdir" "2026-10-07" "$K")"
expect "decide: yesterday's entry is only reused for yesterday" reuse "$(python3 "$prog" decide "$cdir" "$Y" "$K" | head -1)"
bd="$w/badcache"; mkdir -p "$bd/$D"
dec() { python3 "$prog" decide "$bd" "$D" "$K" 2>/dev/null; }
rm -f "$bd/$D/$K.findings.json"
expect "decide: a missing file calls" call "$(dec)"
: > "$bd/$D/$K.findings.json";                 expect "decide: an empty file calls" call "$(dec)"
printf '{"bomFormat":' > "$bd/$D/$K.findings.json"; expect "decide: invalid JSON calls" call "$(dec)"
printf '[]' > "$bd/$D/$K.findings.json";        expect "decide: a JSON array calls" call "$(dec)"
printf '"CycloneDX"' > "$bd/$D/$K.findings.json"; expect "decide: a JSON string calls" call "$(dec)"
printf '{"vulnerabilities":[]}' > "$bd/$D/$K.findings.json"; expect "decide: a JSON object that is not CycloneDX calls" call "$(dec)"
printf '{"bomFormat":"SPDX"}' > "$bd/$D/$K.findings.json"; expect "decide: another bomFormat calls" call "$(dec)"
printf '{"sbom":{"bomFormat":"nope"}}' > "$bd/$D/$K.findings.json"; expect "decide: an envelope around a non-CycloneDX object calls" call "$(dec)"
printf '{"sbom":[]}' > "$bd/$D/$K.findings.json"; expect "decide: an envelope around a non-object calls" call "$(dec)"
rm -f "$bd/$D/$K.findings.json"; mkdir "$bd/$D/$K.findings.json"; expect "decide: a directory in its place calls" call "$(dec)"
rmdir "$bd/$D/$K.findings.json"
cp "$w/f.json" "$w/target.json"; ln -s "$w/target.json" "$bd/$D/$K.findings.json"; expect "decide: a symbolic link calls" call "$(dec)"
rm -f "$bd/$D/$K.findings.json"
printf '\377\376' > "$bd/$D/$K.findings.json"; expect "decide: unreadable bytes call" call "$(dec)"
chmod 000 "$bd/$D/$K.findings.json" 2>/dev/null; expect "decide: an unreadable file calls" call "$(dec)"
chmod 600 "$bd/$D/$K.findings.json"; rm -f "$bd/$D/$K.findings.json"
expect "decide: a DIR that does not exist calls" call "$(python3 "$prog" decide "$w/nope" "$D" "$K" 2>/dev/null)"
for pair in "../x $K" "$D ../../x" "20261006 $K" "$D ABCDEF0123456789" "$D abc" "'' $K"; do
  eval set -- "$pair"
  expect "decide: a malformed date or key ($pair) calls" call "$(python3 "$prog" decide "$cdir" "$1" "$2" 2>/dev/null)"
done
expect "decide: too few arguments calls (never raises)" call "$(python3 "$prog" decide 2>/dev/null)"
expect "decide: no arguments at all calls" call "$(python3 "$prog" decide "$cdir" 2>/dev/null)"

# store refuses anything that is not a valid result and writes nothing
sd="$w/storecache"
st() { python3 "$prog" store "$sd" "$D" "$K" "$1" > "$w/so.txt" 2>/dev/null; echo "$?"; }
tryinv() { # name content
  printf '%s' "$2" > "$w/inv.json"
  rc=$(st "$w/inv.json")
  if [ "$rc" -ne 0 ] && [ ! -e "$sd" ] && [ ! -s "$w/so.txt" ]; then ok "store: $1 exits non-zero and writes nothing"; else bad "store: $1 (rc=$rc, dir: $(ls -A "$sd" 2>&1))"; fi
}
tryinv "an empty file" ""
tryinv "invalid JSON" '{"bomFormat":'
tryinv "a JSON array" '[]'
tryinv "a JSON object that is not CycloneDX" '{"vulnerabilities":[]}'
rc=$(st "$w/nonexistent.json")
if [ "$rc" -ne 0 ] && [ ! -e "$sd" ]; then ok "store: a missing file exits non-zero and writes nothing"; else bad "store: a missing file"; fi
rc=$(python3 "$prog" store "$sd" "../x" "$K" "$w/f.json" >/dev/null 2>&1; echo $?)
if [ "$rc" -ne 0 ] && [ ! -e "$sd" ]; then ok "store: a malformed date exits non-zero and writes nothing"; else bad "store: a malformed date"; fi
rc=$(python3 "$prog" store "$sd" "$D" "../../x" "$w/f.json" >/dev/null 2>&1; echo $?)
if [ "$rc" -ne 0 ] && [ ! -e "$sd" ] && [ ! -e "$w/x.findings.json" ]; then ok "store: a malformed key exits non-zero and writes nothing"; else bad "store: a malformed key"; fi
# a bad store never damages an existing valid entry
python3 "$prog" store "$sd" "$D" "$K" "$w/f.json"
printf 'garbage' > "$w/inv.json"; rc=$(st "$w/inv.json")
[ "$rc" -ne 0 ] && cmp -s "$w/f.json" "$sd/$D/$K.findings.json" && ok "store: an invalid file leaves the existing valid entry intact" || bad "store: an invalid file leaves the existing entry intact"
# a second store of the same key keeps a valid file
printf '%s' '{"sbom":{"bomFormat":"CycloneDX","specVersion":"1.5","vulnerabilities":[{"id":"CVE-1"}]}}' > "$w/f2.json"
python3 "$prog" store "$sd" "$D" "$K" "$w/f2.json"; rc=$?
expect "store: a second store of the same key exits 0" 0 "$rc"
expect "store: ...and the stored file is still valid (reuse)" reuse "$(python3 "$prog" decide "$sd" "$D" "$K" | head -1)"
expect "store: ...no temp file left" "$K.findings.json" "$(ls -A "$sd/$D")"

# ---------------------------------------------------------------------------------------------------------------
# B. simulated runs of the real call-site steps
extract() { # workflow job step-name-substring -> prints the run script
  python3 - "$root/.github/workflows/$1" "$2" "$3" <<'PY'
import sys, yaml
d = yaml.load(open(sys.argv[1]), Loader=yaml.BaseLoader)
hits = [s for s in d["jobs"][sys.argv[2]]["steps"] if sys.argv[3] in (s.get("name") or "") and s.get("run")]
if len(hits) != 1:
    sys.exit("expected exactly one step matching %r, found %d" % (sys.argv[3], len(hits)))
print(hits[0]["run"])
PY
}
sim="$w/sim"; mkdir -p "$sim/bin" "$sim/sboms"
cat > "$sim/bin/inspector-sbomgen" <<'EOF'
#!/usr/bin/env bash
ref=""; out=""
while [ $# -gt 0 ]; do case "$1" in --image) ref=$2; shift ;; --outfile) out=$2; shift ;; esac; shift; done
cp "$FAKE_SBOMS/${ref##*:}.json" "$out"
EOF
cat > "$sim/bin/aws" <<'EOF'
#!/usr/bin/env bash
# aws inspector-scan scan-sbom --sbom file://PATH --output-format CYCLONE_DX_1_5
[ "$1 $2" = "inspector-scan scan-sbom" ] || { echo "unexpected aws call: $*" >&2; exit 9; }
sbom=""; while [ $# -gt 0 ]; do [ "$1" = --sbom ] && sbom=${2#file://}; shift; done
echo "scan-sbom $sbom" >> "$FAKE_AWS_LOG"
[ -n "${FAKE_AWS_FAIL:-}" ] && exit 1
python3 - "$sbom" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(json.dumps({"sbom": {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": d["components"], "vulnerabilities": []}}))
PY
EOF
printf '#!/usr/bin/env bash\nexit 0\n' > "$sim/bin/sudo"; cp "$sim/bin/sudo" "$sim/bin/skopeo"
chmod +x "$sim/bin/"*
# the images: the two platform children of a variant carry the same inventory (different stamp); the variants differ
mksbom "$sim/sboms/cand-production-amd64.json" urn:uuid:p1 2026-10-06T01:00:00Z v1 busybox@1.37.0 libc6@2.36
mksbom "$sim/sboms/cand-production-arm64.json" urn:uuid:p2 2026-10-06T01:00:09Z v1 busybox@1.37.0 libc6@2.36
mksbom "$sim/sboms/cand-debug-amd64.json"      urn:uuid:d1 2026-10-06T01:00:00Z v1 busybox@1.37.0 libc6@2.36 gdb@13
mksbom "$sim/sboms/cand-debug-arm64.json"      urn:uuid:d2 2026-10-06T01:00:09Z v1 busybox@1.37.0 libc6@2.36 gdb@13
mksbom "$sim/sboms/cand-fips-amd64.json"       urn:uuid:f1 2026-10-06T01:00:00Z v1 busybox@1.37.0 libc6@2.36 openssl@3
mksbom "$sim/sboms/cand-fips-arm64.json"       urn:uuid:f2 2026-10-06T01:00:09Z v1 busybox@1.37.0 libc6@2.36 openssl@3

# run <script-file> <day> [fail]: the extracted step, /tmp moved into the sandbox, in the repository root
run_step() {
  : > "$sim/aws.log"; : > "$sim/summary.md"; : > "$sim/out.txt"
  ( cd "$root" && PATH="$sim/bin:$PATH" FAKE_SBOMS="$sim/sboms" FAKE_AWS_LOG="$sim/aws.log" FAKE_AWS_FAIL="${3:-}" \
      INSPECTOR_DAY="$2" GITHUB_STEP_SUMMARY="$sim/summary.md" GITHUB_OUTPUT="$sim/out.txt" bash "$1" ) > "$sim/log.txt" 2>&1
}
calls() { wc -l < "$sim/aws.log" | tr -d ' '; }
fresh() { sed -n 's/^fresh=//p' "$sim/out.txt" | tail -1; }
sandbox() { sed "s#/tmp/#$sim/tmp/#g" ; }

# --- scan.yml: the PR gate
extract scan.yml scanner "Amazon Inspector scan every loaded image" | sandbox > "$sim/scan-step.sh" || { bad "extract scan.yml's Inspector step"; }
reset_scan() { rm -rf "$sim/tmp"; mkdir -p "$sim/tmp"; printf 'ghcr.io/fosterstack/cache:cand-production-amd64\nghcr.io/fosterstack/cache:cand-production-arm64\nghcr.io/fosterstack/cache:cand-debug-amd64\n' > "$sim/tmp/refs.txt"; }
gate_lines() { grep -c '^- ' "$sim/summary.md" | tr -d ' '; }  # one verdict line per image, plus the "SBOMs assessed" line
reset_scan
run_step "$sim/scan-step.sh" 2026-10-06; rc=$?
expect "scan.yml run 1: step succeeds (the gate returned clean for every image)" 0 "$rc"
expect "scan.yml run 1: two distinct inventories call ScanSbom twice (the second platform child reuses the first)" 2 "$(calls)"
expect "scan.yml run 1: the gate got a findings file for all three images (3 verdicts + the assessed line)" 4 "$(gate_lines)"
expect "scan.yml run 1: fresh=2 reported" 2 "$(fresh)"
expect "scan.yml run 1: the in-run duplicate was assessed once (summary says 2)" 1 "$(grep -c 'SBOMs assessed: 2' "$sim/summary.md")"
run_step "$sim/scan-step.sh" 2026-10-06; rc=$?
expect "scan.yml run 2 (same day, restored cache): step succeeds" 0 "$rc"
expect "scan.yml run 2: a match reuses, NO ScanSbom call" 0 "$(calls)"
expect "scan.yml run 2: the gate still got a findings file for all three images" 4 "$(gate_lines)"
expect "scan.yml run 2: fresh=0 (nothing to save)" 0 "$(fresh)"
run_step "$sim/scan-step.sh" 2026-10-07; rc=$?
expect "scan.yml different UTC day: calls Inspector for each distinct inventory" 2 "$(calls)"
expect "scan.yml different UTC day: gate still fed" 4 "$(gate_lines)"
# a different hash: change one image's inventory
mksbom "$sim/sboms/cand-debug-amd64.json" urn:uuid:d9 2026-10-06T01:00:00Z v1 busybox@1.37.0 libc6@2.36 gdb@14
run_step "$sim/scan-step.sh" 2026-10-06; rc=$?
expect "scan.yml a different hash: exactly that image calls Inspector" 1 "$(calls)"
expect "scan.yml a different hash: gate still fed" 4 "$(gate_lines)"
# a corrupted stored result
for f in "$sim"/tmp/inspector-cache/2026-10-06/*.findings.json; do printf 'garbage' > "$f"; done
run_step "$sim/scan-step.sh" 2026-10-06; rc=$?
expect "scan.yml corrupted stored results: each distinct inventory in use calls again" 2 "$(calls)"
expect "scan.yml corrupted stored results: step succeeds and the gate is fed" "0 4" "$rc $(gate_lines)"
run_step "$sim/scan-step.sh" 2026-10-06
expect "scan.yml corrupted stored results: the fresh results replaced them (next run reuses, no call)" 0 "$(calls)"
# a ScanSbom failure is a pipeline failure and stores nothing
reset_scan
run_step "$sim/scan-step.sh" 2026-10-06 1; rc=$?
expect "scan.yml ScanSbom fails: the step fails (rc 2, not a clean pass)" 2 "$rc"
expect "scan.yml ScanSbom fails: nothing stored" "" "$(ls -A "$sim/tmp/inspector-cache" 2>/dev/null)"
expect "scan.yml ScanSbom fails: fresh=0" 0 "$(fresh)"

# --- main-candidate-rescan.yml: the daily panel
extract main-candidate-rescan.yml panel-inspector "Amazon Inspector every image" | sandbox > "$sim/rescan-step.sh" || { bad "extract the rescan's Inspector step"; }
reset_rescan() { rm -rf "$sim/tmp"; mkdir -p "$sim/tmp"; }
scans() { ls "$sim"/tmp/panel/inspector/*/scan.json 2>/dev/null | wc -l | tr -d ' '; }
valid_scans() { for f in "$sim"/tmp/panel/inspector/*/scan.json; do python3 -c "import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d['sbom']['bomFormat']=='CycloneDX' else 1)" "$f" && echo y; done | wc -l | tr -d ' '; }
mksbom "$sim/sboms/cand-debug-amd64.json" urn:uuid:d1 2026-10-06T01:00:00Z v1 busybox@1.37.0 libc6@2.36 gdb@13
reset_rescan
run_step "$sim/rescan-step.sh" 2026-10-06; rc=$?
expect "rescan run 1: step exits 0" 0 "$rc"
expect "rescan run 1: three inventories, three ScanSbom calls (the other three images reuse them)" 3 "$(calls)"
expect "rescan run 1: the tally has a findings file for all six images" "6 6" "$(scans) $(valid_scans)"
expect "rescan run 1: fresh=3" 3 "$(fresh)"
run_step "$sim/rescan-step.sh" 2026-10-06; rc=$?
expect "rescan same day again: no ScanSbom call at all" 0 "$(calls)"
expect "rescan same day again: the tally still has a findings file for all six" "6 6" "$(scans) $(valid_scans)"
expect "rescan same day again: fresh=0" 0 "$(fresh)"
run_step "$sim/rescan-step.sh" 2026-10-07
expect "rescan a different UTC day: calls for each distinct inventory" 3 "$(calls)"
mksbom "$sim/sboms/cand-fips-amd64.json" urn:uuid:f1 2026-10-06T01:00:00Z v1 busybox@1.37.0 libc6@2.36 openssl@4
mksbom "$sim/sboms/cand-fips-arm64.json" urn:uuid:f2 2026-10-06T01:00:09Z v1 busybox@1.37.0 libc6@2.36 openssl@4
run_step "$sim/rescan-step.sh" 2026-10-06
expect "rescan a different hash: one fresh call (both fips children share the new inventory)" 1 "$(calls)"
expect "rescan a different hash: the tally still has all six" "6 6" "$(scans) $(valid_scans)"
for f in "$sim"/tmp/inspector-cache/2026-10-06/*.findings.json; do : > "$f"; done
run_step "$sim/rescan-step.sh" 2026-10-06
expect "rescan corrupted (emptied) stored results: every distinct inventory calls again" 3 "$(calls)"
expect "rescan corrupted stored results: the tally still has all six" "6 6" "$(scans) $(valid_scans)"
reset_rescan
run_step "$sim/rescan-step.sh" 2026-10-06 1
expect "rescan ScanSbom fails: nothing stored, fresh=0, no findings file left to be mistaken for a result" "|0|0" "$(ls -A "$sim/tmp/inspector-cache" 2>/dev/null)|$(fresh)|$(scans)"

# ---------------------------------------------------------------------------------------------------------------
# C. wiring
judge() { python3 - "$1" "$2" <<'PY'
import json, re, sys, yaml
path, which = sys.argv[1], sys.argv[2]
raw = open(path).read()
d = yaml.load(raw, Loader=yaml.BaseLoader)
bad = []
FORK = "github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository"
PIN = "55cc8345863c7cc4c66a329aec7e433d2d1c52a9"
if which == "scan":
    job, scan_name, marker = "scanner", "Amazon Inspector scan every loaded image", "python3 bin/inspector-gate.py"
    perms = {"top": {"contents": "read"}, "build": {"contents": "read", "id-token": "write", "attestations": "write", "packages": "write"},
             "assemble": {"contents": "read", "id-token": "write", "attestations": "write", "packages": "write"},
             "assemble-b": {"contents": "read", "id-token": "write", "attestations": "write", "packages": "write"},
             "artifact-acceptance": {"contents": "read", "packages": "read"}, "reproducibility": None, "scanners": None,
             "scanner": {"contents": "read", "id-token": "write"}, "scan": None}
else:
    job, scan_name, marker = "panel-inspector", "Amazon Inspector every image", None
    perms = {"top": {"contents": "read"}, "build": {"contents": "read", "id-token": "write", "attestations": "write"},
             "assemble": {"contents": "read", "packages": "write", "id-token": "write", "attestations": "write"},
             "panel-grype": {"contents": "read"}, "panel-scout": {"contents": "read"},
             "scout-root-cause": {"contents": "read", "packages": "write"}, "panel-inspector": {"contents": "read", "id-token": "write"},
             "panel-google": {"contents": "read", "id-token": "write"}, "panel": {"contents": "read", "issues": "write"},
             "scanner-reports": {"contents": "read"}, "manifests": None, "rescan": {"contents": "read", "issues": "write", "packages": "read"}}
# permissions: unchanged, and nothing anywhere grants actions
got = {"top": d.get("permissions")}
got.update({j: v.get("permissions") for j, v in d["jobs"].items()})
if got != perms:
    bad.append("permissions changed: %s" % json.dumps(got))
if re.search(r"^\s*actions\s*:\s*(write|read)", raw, re.M):
    bad.append("an actions: permission is granted")
# the stock actions/cache restore and save only: exactly one of each, in the call-site job, nothing else cache-like
uses_all = re.findall(r"uses:\s*(\S+)", raw)
cache_uses = [u for u in uses_all if "actions/cache" in u]
if sorted(cache_uses) != sorted(["actions/cache/restore@" + PIN, "actions/cache/save@" + PIN]):
    bad.append("the cache actions used are not exactly the pinned restore and save: %s" % cache_uses)
for pat in ("actions/cache@", "enableCrossOsArchive", "lookup-only", "fail-on-cache-miss", "upload-chunk-size"):
    if pat in raw:
        bad.append("forbidden %s" % pat)
for pat, label in (("actions/cache/restore@" + PIN + " # v6.1.0\n", "restore"), ("actions/cache/save@" + PIN + " # v6.1.0\n", "save")):
    if ("uses: " + pat) not in raw:
        bad.append("%s is not pinned by digest with the '# v6.1.0' comment" % label)
steps = d["jobs"][job]["steps"]
def idx(pred):
    return [i for i, s in enumerate(steps) if pred(s)]
dates = idx(lambda s: s.get("id") == "insp-date")
rest = idx(lambda s: str(s.get("uses", "")).startswith("actions/cache/restore@"))
save = idx(lambda s: str(s.get("uses", "")).startswith("actions/cache/save@"))
scan = idx(lambda s: scan_name in (s.get("name") or "") and s.get("run"))
if len(dates) != 1 or len(rest) != 1 or len(save) != 1 or len(scan) != 1:
    bad.append("the call-site job lacks exactly one date step, restore, scan step and save: %s" % [dates, rest, save, scan])
    print("; ".join(bad)); sys.exit(1)
dt, rs, sv, sc = steps[dates[0]], steps[rest[0]], steps[save[0]], steps[scan[0]]
if not (dates[0] < rest[0] < scan[0] < save[0]):
    bad.append("order must be date, restore, scan, save")
if "echo \"date=$(date -u +%F)\" >> \"$GITHUB_OUTPUT\"" not in (dt.get("run") or ""):
    bad.append("the date step does not write the UTC date to its output")
DATE = "${{ steps.insp-date.outputs.date }}"
rw, sw = rs.get("with") or {}, sv.get("with") or {}
if rw.get("path") != "/tmp/inspector-cache" or sw.get("path") != "/tmp/inspector-cache":
    bad.append("the cache path is not /tmp/inspector-cache on both")
if rw.get("key") != "inspector-%s-${{ github.run_id }}-miss" % DATE:
    bad.append("restore key is not the never-matching inspector-<date>-<run>-miss: %r" % rw.get("key"))
if rw.get("restore-keys") != "inspector-%s-" % DATE:
    bad.append("restore-keys is not the same-day prefix: %r" % rw.get("restore-keys"))
if sw.get("key") != "inspector-%s-${{ github.run_id }}" % DATE:
    bad.append("save key is not inspector-<date>-<run>: %r" % sw.get("key"))
if set(rw) - {"path", "key", "restore-keys"} or set(sw) - {"path", "key"}:
    bad.append("unexpected inputs on restore/save: %s %s" % (sorted(rw), sorted(sw)))
for nm, s in (("restore", rs), ("save", sv)):
    if FORK not in (s.get("if") or ""):
        bad.append("%s lacks the same-repo condition" % nm)
sif = sv.get("if") or ""
if "always()" not in sif or "steps.insp-scan.outputs.fresh != '0'" not in sif or "steps.insp-scan.outputs.fresh != ''" not in sif:
    bad.append("save is not conditioned on always() and a fresh result: %r" % sif)
if sc.get("id") != "insp-scan":
    bad.append("the scan step id is not insp-scan")
if (sc.get("env") or {}).get("INSPECTOR_DAY") != DATE:
    bad.append("the scan step does not take the day from the date step")
# the reuse program runs before any ScanSbom call, which is the only one; the store follows it; the gate/tally follows
run = sc.get("run") or ""
tot = len(re.findall(r"aws inspector-scan scan-sbom", raw))
if tot != 1 or len(re.findall(r"aws inspector-scan scan-sbom", run)) != 1:
    bad.append("ScanSbom must be called exactly once in the whole file, inside the scan step (found %d)" % tot)
else:
    pos = lambda s: run.find(s)
    k, dc, call, st = pos("inspector-reuse.py key"), pos("inspector-reuse.py decide"), pos("aws inspector-scan scan-sbom"), pos("inspector-reuse.py store")
    if not (0 <= k < dc < call < st):
        bad.append("the order key < decide < ScanSbom < store is not held: %s" % [k, dc, call, st])
    if marker and not (call < pos(marker)):
        bad.append("the gate does not run after the call site")
    if "$GITHUB_OUTPUT" not in run or "fresh=" not in run:
        bad.append("the scan step does not report fresh=N")
if which == "rescan":
    pj = d["jobs"]["panel"]
    if "panel-inspector" not in pj.get("needs", []) and "panel-inspector" not in str(pj.get("needs")):
        bad.append("the tally no longer needs panel-inspector")
    if "bin/panel.py tally" not in "\n".join(s.get("run") or "" for s in pj["steps"]):
        bad.append("the panel tally step is gone")
    if "pattern: panel-*" not in raw:
        bad.append("the tally no longer reads the panel-* artifacts")
if bad:
    print("; ".join(bad)); sys.exit(1)
print("wired")
PY
}
wf() { # file which name want mutation-python (acts on string t)
  local f="$w/wf-$3.yml"; cp "$root/.github/workflows/$1" "$f"
  if [ -n "$5" ]; then
    python3 - "$f" "$5" <<'PY'
import re, sys
p = sys.argv[1]
t = open(p).read()
t0 = t
exec(sys.argv[2])
if t == t0:
    sys.exit("the mutation did not apply")
open(p, "w").write(t)
PY
    [ $? -eq 0 ] || { bad "wiring $1:$3 (the mutation did not apply)"; return; }
  fi
  if out=$(judge "$f" "$2"); then got=ok; else got=bad; fi
  if [ "$got" = "$4" ]; then ok "wiring $1:$3 -> $got"; else bad "wiring $1:$3 -> $got, want $4 ($out)"; fi
}
FORKX="github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository"
PINX="55cc8345863c7cc4c66a329aec7e433d2d1c52a9"
for pair in "scan.yml scan" "main-candidate-rescan.yml rescan"; do
  set -- $pair; f=$1; k=$2
  wf "$f" "$k" real ok ""
  wf "$f" "$k" restore-fork-condition-dropped bad "t = t.replace(\"$FORKX\", 'true', 1)"
  wf "$f" "$k" save-fork-condition-dropped bad "i = t.rfind(\"$FORKX\"); t = t[:i] + 'true' + t[i+len(\"$FORKX\"):]"
  wf "$f" "$k" call-moved-before-decide bad "t = t.replace('inspector-sbomgen container', 'aws inspector-scan scan-sbom --sbom x; inspector-sbomgen container', 1)"
  wf "$f" "$k" save-every-run bad "t = re.sub(r\" && steps\\.insp-scan\\.outputs\\.fresh != '0'\", '', t)"
  wf "$f" "$k" save-ignores-fresh-entirely bad "t = re.sub(r\" && steps\\.insp-scan\\.outputs\\.fresh != '[0]?'\", '', t)"
  wf "$f" "$k" restore-without-date-prefix bad "t = t.replace('restore-keys: inspector-\${{ steps.insp-date.outputs.date }}-', 'restore-keys: inspector-', 1)"
  wf "$f" "$k" restore-key-can-match-exactly bad "t = t.replace('github.run_id }}-miss', 'github.run_id }}', 1)"
  wf "$f" "$k" save-key-without-date bad "t = t.replace('key: inspector-\${{ steps.insp-date.outputs.date }}-\${{ github.run_id }}\n', 'key: inspector-\${{ github.run_id }}\n', 1)"
  wf "$f" "$k" actions-write-added bad "t = re.sub(r'(?m)^( +)id-token: write', lambda m: m.group(0) + '\n' + m.group(1) + 'actions: write', t, count=1)"
  wf "$f" "$k" call-site-contents-write bad "i = t.index('  ' + ('scanner' if '$k' == 'scan' else 'panel-inspector') + ':\n'); j = t.index('contents: read', i); t = t[:j] + 'contents: write' + t[j+14:]"
  wf "$f" "$k" restore-pinned-by-tag bad "t = t.replace('actions/cache/restore@$PINX # v6.1.0', 'actions/cache/restore@v6', 1)"
  wf "$f" "$k" save-pinned-by-tag bad "t = t.replace('actions/cache/save@$PINX # v6.1.0', 'actions/cache/save@v6', 1)"
  wf "$f" "$k" restore-wrong-version-comment bad "t = t.replace('actions/cache/restore@$PINX # v6.1.0', 'actions/cache/restore@$PINX # v6.0.0', 1)"
  wf "$f" "$k" cross-os-archive-set bad "t = re.sub(r'(?m)^( +)(path: /tmp/inspector-cache)', lambda m: m.group(0) + '\n' + m.group(1) + 'enableCrossOsArchive: true', t, count=1)"
  wf "$f" "$k" lookup-only-set bad "t = re.sub(r'(?m)^( +)(path: /tmp/inspector-cache)', lambda m: m.group(0) + '\n' + m.group(1) + 'lookup-only: true', t)"
  wf "$f" "$k" path-outside-the-cache-dir bad "t = t.replace('path: /tmp/inspector-cache', 'path: /tmp', 1)"
  wf "$f" "$k" a-different-cache-action bad "t = t.replace('uses: actions/cache/save@$PINX # v6.1.0', 'uses: actions/cache@$PINX # v6.1.0', 1)"
  wf "$f" "$k" restore-step-removed bad "t = re.sub(r'(?s)      - name: [^\n]*restore[^\n]*\n.*?restore-keys: [^\n]*\n', '', t, count=1)"
  wf "$f" "$k" date-from-the-run-start bad "t = t.replace('date -u +%F', 'date +%F', 1)"
  wf "$f" "$k" store-removed bad "t = t.replace('inspector-reuse.py store', 'true', 1)"
done
# the gate is still fed after the call site, and the tally still reads the result
wf scan.yml scan gate-before-call bad "t = t.replace('python3 bin/inspector-gate.py', 'true bin/inspector-gate.py', 1) + '\n# python3 bin/inspector-gate.py'"

echo "inspector-reuse: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
