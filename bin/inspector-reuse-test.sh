#!/usr/bin/env bash
# proves: REQ-REL-004-AC5
# Same-day reuse of Amazon Inspector results (REQ-REL-004-AC5). Offline; bash on macOS and Linux.
#   A. bin/inspector-reuse.py: key (the SBOM's package names and versions, never a timestamp, serial number, purl
#      qualifier or our own module's version; the full sha256), decide / store (the stored file must be Inspector's
#      ScanSbom ENVELOPE and its own inventory must equal the requested SBOM's; same UTC day; no links; atomic, fsync).
#   B. SIMULATED RUNS: the real call-site step of scan.yml and of main-candidate-rescan.yml is extracted, its
#      /tmp paths moved into a sandbox, and run against a fake inspector-sbomgen, a fake aws that answers with a
#      realistic envelope (echoing the components, plus findings when told to) and a fake date: reuse on a match,
#      a fresh call on each of the three ways it can differ, findings carried by a REUSED result into the real gate
#      and the real panel tally (with and without VEX), a run that crosses UTC midnight, and mutations of the
#      reuse branch that must be caught.
#   C. WIRING over the two workflow files (triggers, the whole `if:` strings, keys, order), with mutations that
#      must each be caught.
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
is_root=0; [ "$(id -u)" = 0 ] && is_root=1

# ---------------------------------------------------------------------------------------------------------------
# A. the program
mksbom() { # out serial timestamp ourversion pkg@ver...
  python3 - "$@" <<'PY'
import json, sys
out, serial, ts, ours = sys.argv[1:5]
comps = []
for p in sys.argv[5:]:
    n, v = p.rsplit("@", 1)
    if n.startswith("go:"):   # a Go module: purl pkg:golang/<path>@<ver>, name = the full path
        comps.append({"type": "library", "name": n[3:], "version": v, "purl": "pkg:golang/%s@%s" % (n[3:], v), "bom-ref": "ref-%s-%s" % (n[3:], v)})
    elif n.startswith("np:"):   # a component with no purl (name@version is its identifier)
        comps.append({"type": "library", "name": n[3:], "version": v, "bom-ref": "ref-%s-%s" % (n[3:], v)})
    else:
        comps.append({"type": "library", "name": n, "version": v, "purl": "pkg:generic/%s@%s" % (n, v), "bom-ref": "ref-%s-%s" % (n, v)})
if ours != "-":
    comps.append({"type": "library", "name": "github.com/fosterstack/cache", "version": ours,
                  "purl": "pkg:golang/github.com/fosterstack/cache@" + ours})
doc = {"bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": serial,
       "metadata": {"timestamp": ts, "component": {"name": "img", "version": ts}}, "components": comps}
json.dump(doc, open(out, "w"))
PY
}
# shape.py: the ScanSbom answer in the shape the real service gives (verified on CI run 37479078522): Go module names cut to
# their LAST path segment, bom-refs renumbered comp-N, a properties list added, a component that was not submitted added,
# the purl kept as it was. FAKE_VULN style argument CVE:pkgname adds one vulnerability affecting that package.
cat > "$w/shape.py" <<'PY'
import json, sys
sbom, vuln = sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 else "")
comps = json.load(open(sbom))["components"]
out = []
for i, c in enumerate(comps):
    n = dict(c); n["bom-ref"] = "comp-%d" % (i + 1)
    if (c.get("purl") or "").startswith("pkg:golang/") and c.get("name"):
        n["name"] = c["name"].rsplit("/", 1)[-1]
    n["properties"] = [{"name": "amazon:inspector:sbom_scanner:info", "value": "Component skipped: no supported rules found."}]
    out.append(n)
out.append({"bom-ref": "comp-%d" % (len(out) + 1), "type": "library", "name": "extra", "version": None,
            "purl": "pkg:golang/example.com/only-in-the-response?unresolved=true"})
vs = []
if vuln:
    vid, pkg = vuln.split(":")
    vs = [{"id": vid, "ratings": [{"severity": "high"}], "affects": [{"ref": n["bom-ref"]} for n, c in zip(out, comps) if c.get("name") == pkg]}]
print(json.dumps({"sbom": {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": out, "vulnerabilities": vs}}))
PY
mkenv() { python3 "$w/shape.py" "$2" "${3:-}" > "$1"; }   # out sbom.json [CVE:pkgname]

mksbom "$w/a.json"  urn:uuid:1 2026-10-06T01:00:00Z v1 busybox@1.37.0 libc6@2.36 np:zlib@1.3
mksbom "$w/a2.json" urn:uuid:2 2026-10-07T09:00:00Z v2 np:zlib@1.3 libc6@2.36 busybox@1.37.0   # same inventory, other order
mksbom "$w/a3.json" urn:uuid:3 2026-10-08T09:00:00Z -  busybox@1.37.0 libc6@2.36 np:zlib@1.3  # no module component at all
mksbom "$w/b.json"  urn:uuid:1 2026-10-06T01:00:00Z v1 busybox@1.37.1 libc6@2.36 np:zlib@1.3  # a package version differs
mksbom "$w/c.json"  urn:uuid:1 2026-10-06T01:00:00Z v1 busybox@1.37.0 libc6@2.36 np:zlib@1.3 curl@8.0  # a package added
mksbom "$w/d.json"  urn:uuid:1 2026-10-06T01:00:00Z v1 busybox@1.37.0 libc6@2.36 np:zlib@1.4  # name@version fallback differs
mksbom "$w/only-ours.json" urn:uuid:1 2026-10-06T01:00:00Z v1                                   # nothing but our own module

ka=$(python3 "$prog" key "$w/a.json") ; rc=$?
expect "key: exits 0" 0 "$rc"
if [[ "$ka" =~ ^[0-9a-f]{64}$ ]]; then ok "key: the full sha256 (64 hex)"; else bad "key: the full sha256 (64 hex) ('$ka')"; fi
expect "key: another serial number, timestamp, our module version and component order: same key" "$ka" "$(python3 "$prog" key "$w/a2.json")"
expect "key: no module component at all: same key (our module is excluded)" "$ka" "$(python3 "$prog" key "$w/a3.json")"
for n in b c d; do
  k=$(python3 "$prog" key "$w/$n.json"); [ -n "$k" ] && [ "$k" != "$ka" ] && ok "key: inventory $n differs: different key" || bad "key: inventory $n differs: different key"
done
# a sub-package of our module and the name form are also excluded; a look-alike module is NOT
python3 - "$w" <<'PY'
import json, sys
w = sys.argv[1]
def var(name, fn):
    d = json.load(open(w + "/a.json")); fn(d); json.dump(d, open(w + "/" + name, "w"))
def sub(d):
    d["components"].append({"type": "library", "name": "github.com/fosterstack/cache/internal/x", "version": "v9", "purl": "pkg:golang/github.com/fosterstack/cache/internal/x@v9"})
    d["components"].append({"type": "library", "name": "github.com/fosterstack/cache", "version": "v77"})
    d["components"].append({"type": "library", "name": "github.com/fosterstack/cache", "version": "v78", "purl": "pkg:golang/github.com/fosterstack/cache@v78?type=module"})
def look(d):
    d["components"].append({"type": "library", "name": "github.com/fosterstack/cache-other", "version": "v1", "purl": "pkg:golang/github.com/fosterstack/cache-other@v1"})
def generic(d, f):
    for c in d["components"]:
        if c.get("purl", "").startswith("pkg:generic/"):
            f(c)
def q(suffix):
    def f(d): generic(d, lambda c: c.__setitem__("purl", c["purl"] + suffix))
    return f
def ver(d): generic(d, lambda c: c.__setitem__("version", "9.9.9"))
def meta(d): d["metadata"] = "garbage"; d["serialNumber"] = 12; d["extra"] = {"timestamp": 1}
var("a-sub.json", sub); var("a-look.json", look); var("a-meta.json", meta)
var("a-amd64.json", q("?arch=amd64")); var("a-arm64.json", q("?arch=arm64"))
var("a-qual.json", q("?arch=amd64&distro=debian-12&epoch=1")); var("a-subpath.json", q("#usr/bin/x")); var("a-both.json", q("?arch=arm64#sub"))
var("a-ver.json", ver)   # the explicit version field changes, the purl does not
def retype(typ):
    def f(d): generic(d, lambda c: c.__setitem__("purl", c["purl"].replace("pkg:generic/", "pkg:%s/" % typ, 1)))
    return f
def nopurl(d): generic(d, lambda c: c.pop("purl"))
def ns(d): generic(d, lambda c: c.__setitem__("purl", c["purl"].replace("pkg:generic/", "pkg:deb/debian/", 1)))
var("a-apk.json", retype("apk")); var("a-deb.json", retype("deb")); var("a-nopurl.json", nopurl)
# purl-only components (no name, no version field): name and version come from the purl, whatever its type
def purlonly(typ, fmt="pkg:%s/%s@%s%s"):
    def f(d):
        for c in d["components"]:
            if c.get("purl", "").startswith("pkg:generic/"):
                n, v = c["name"], c["version"]
                c.pop("name"); c.pop("version"); c["purl"] = fmt % (typ, n, v, "?arch=arm64&distro=x#sub")
    return f
var("a-po-apk.json", purlonly("apk")); var("a-po-deb.json", purlonly("deb"))
var("a-po-enc.json", purlonly("deb", "pkg:%s/%s@%s%s"))
def vdiff(d):
    for c in d["components"]:
        if c["name"] == "busybox": c["version"] = "9.9.9"; c["purl"] = "pkg:generic/busybox@9.9.9"
def ndiff(d):
    for c in d["components"]:
        if c["name"] == "busybox": c["name"] = "busybox2"; c["purl"] = "pkg:generic/busybox2@1.37.0"
var("a-vdiff.json", vdiff); var("a-ndiff.json", ndiff)
PY
expect "key: our module's sub-package and a purl-less entry of it are excluded" "$ka" "$(python3 "$prog" key "$w/a-sub.json")"
[ "$(python3 "$prog" key "$w/a-look.json")" != "$ka" ] && ok "key: a look-alike module (cache-other) is an ordinary package" || bad "key: a look-alike module (cache-other) is an ordinary package"
expect "key: metadata and serialNumber are never read" "$ka" "$(python3 "$prog" key "$w/a-meta.json")"
expect "key: an arch-only purl qualifier (amd64 child vs arm64 child): the SAME key" "$(python3 "$prog" key "$w/a-amd64.json")" "$(python3 "$prog" key "$w/a-arm64.json")"
expect "key: a purl qualifier does not move the key" "$ka" "$(python3 "$prog" key "$w/a-amd64.json")"
expect "key: several qualifiers (distro, epoch, arch) do not move the key" "$ka" "$(python3 "$prog" key "$w/a-qual.json")"
expect "key: a purl subpath does not move the key" "$ka" "$(python3 "$prog" key "$w/a-subpath.json")"
expect "key: qualifier and subpath together do not move the key" "$ka" "$(python3 "$prog" key "$w/a-both.json")"
expect "key: the purl wins when there is one: the explicit name/version fields (which the real service rewrites) are not read" "$ka" "$(python3 "$prog" key "$w/a-ver.json")"
expect "key: the same name and version under purl type apk (pkg:apk/busybox@1 = pkg:generic/busybox@1): the same key" "$ka" "$(python3 "$prog" key "$w/a-apk.json")"
expect "key: the same name and version under purl type deb: the same key" "$ka" "$(python3 "$prog" key "$w/a-deb.json")"
expect "key: the same name and version with NO purl: the same key" "$ka" "$(python3 "$prog" key "$w/a-nopurl.json")"
expect "key: purl-only components (no name/version fields), type apk, with qualifiers and subpath: name and version parsed from the purl, the same key" "$ka" "$(python3 "$prog" key "$w/a-po-apk.json")"
expect "key: purl-only components, type deb: the same key as type apk" "$ka" "$(python3 "$prog" key "$w/a-po-deb.json")"
[ "$(python3 "$prog" key "$w/a-vdiff.json")" != "$ka" ] && ok "key: a different version differs" || bad "key: a different version differs"
[ "$(python3 "$prog" key "$w/a-ndiff.json")" != "$ka" ] && ok "key: a different name differs" || bad "key: a different name differs"
python3 - "$w" <<'PY'
import json, sys
w = sys.argv[1]
# our own module by purl alone (no name field) is still excluded
d = json.load(open(w + "/a.json")); d["components"].append({"purl": "pkg:golang/github.com/fosterstack/cache@v5?type=module"}); json.dump(d, open(w + "/a-ours-purl.json", "w"))
# a purl-only component with an encoded version (%2B) and a namespace
d = json.load(open(w + "/a.json")); d["components"].append({"purl": "pkg:deb/debian/tzdata@2026c%2Bdeb12?arch=all"}); json.dump(d, open(w + "/a-enc1.json", "w"))
d = json.load(open(w + "/a.json")); d["components"].append({"name": "debian/tzdata", "version": "2026c+deb12"}); json.dump(d, open(w + "/a-enc2.json", "w"))
PY
expect "key: our own module named only by a purl is excluded" "$ka" "$(python3 "$prog" key "$w/a-ours-purl.json")"
expect "key: a purl-only component's namespace/name and decoded version equal the explicit fields" "$(python3 "$prog" key "$w/a-enc2.json")" "$(python3 "$prog" key "$w/a-enc1.json")"
# malformed SBOMs exit non-zero and print no key
printf 'not json' > "$w/m1.json"; printf '[]' > "$w/m2.json"; printf '{}' > "$w/m3.json"; : > "$w/m4.json"
printf '{"components":{}}' > "$w/m5.json"; printf '{"components":[]}' > "$w/m6.json"; printf '{"components":[5]}' > "$w/m7.json"
printf '{"components":[{"type":"library"}]}' > "$w/m8.json"
cp "$w/only-ours.json" "$w/m9.json"
for n in m1 m2 m3 m4 m5 m6 m7 m8 m9 nonexistent; do
  out=$(python3 "$prog" key "$w/$n.json" 2>/dev/null); rc=$?
  if [ "$rc" -ne 0 ] && [ -z "$out" ]; then ok "key: malformed or empty inventory ($n) exits non-zero, prints no key"; else bad "key: malformed or empty inventory ($n) (rc=$rc out='$out')"; fi
done

D="2026-10-06"; Y="2026-10-05"; K="$ka"
kb=$(python3 "$prog" key "$w/b.json")
mkenv "$w/f.json" "$w/a.json"                       # the answer for inventory a
mkenv "$w/f-vuln.json" "$w/a.json" CVE-2099-0001:busybox
mkenv "$w/f-b.json" "$w/b.json"                     # the answer for inventory b (one version differs)
mkenv "$w/f-c.json" "$w/c.json"                     # the answer for inventory c (a package ADDED to a: a superset of a)
mkenv "$w/f-d.json" "$w/d.json"                     # the answer for inventory d (zlib 1.4 instead of 1.3: a different inventory)
python3 - "$w" <<'PY'
import json, sys
w = sys.argv[1]
d = json.load(open(w + "/f.json")); d["sbom"]["components"] = [c for c in d["sbom"]["components"] if c.get("name") != "libc6"]; json.dump(d, open(w + "/f-missing.json", "w"))
PY
cdir="$w/cache"
python3 "$prog" store "$cdir" "$D" "$w/a.json" "$w/f.json" > "$w/so.txt"; rc=$?
expect "store: the envelope for the requested inventory is stored (exit 0)" 0 "$rc"
expect "store: prints nothing on success" "" "$(cat "$w/so.txt")"
[ -f "$cdir/$D/$K.findings.json" ] && cmp -s "$w/f.json" "$cdir/$D/$K.findings.json" && ok "store: copied byte for byte to DIR/DATE/KEY.findings.json" || bad "store: copied byte for byte"
expect "store: no temp file left behind" "$K.findings.json" "$(ls -A "$cdir/$D")"
out=$(python3 "$prog" decide "$cdir" "$D" "$w/a.json"); rc=$?
expect "decide: a match reuses (exit 0)" 0 "$rc"
expect "decide: reuse, then the path as the second line" "reuse
$cdir/$D/$K.findings.json" "$out"
expect "decide: the same inventory, other serial/timestamp/order, reuses" reuse "$(python3 "$prog" decide "$cdir" "$D" "$w/a2.json" | head -1)"
expect "decide: the same inventory with other purl qualifiers reuses" reuse "$(python3 "$prog" decide "$cdir" "$D" "$w/a-arm64.json" | head -1)"
expect "decide: a different inventory (one version differs) calls" call "$(python3 "$prog" decide "$cdir" "$D" "$w/b.json")"
expect "decide: a different UTC day (an entry from yesterday) calls" call "$(python3 "$prog" decide "$cdir" "$Y" "$w/a.json")"
mkdir -p "$cdir/$Y"; cp "$cdir/$D/$K.findings.json" "$cdir/$Y/$K.findings.json"
expect "decide: yesterday's entry exists, tomorrow asked: calls" call "$(python3 "$prog" decide "$cdir" "2026-10-07" "$w/a.json")"
expect "decide: yesterday's entry is only reused for yesterday" reuse "$(python3 "$prog" decide "$cdir" "$Y" "$w/a.json" | head -1)"

# validate SBOM FILE: exit 0 only for the envelope bound to the SBOM's key; never writes
vtry() { # name want-nonzero(0|1) file
  python3 "$prog" validate "$w/a.json" "$3" > "$w/v.out" 2>/dev/null; rc=$?
  if [ "$2" = 0 ]; then expect "validate: $1 (exit 0, prints nothing)" "0|" "$rc|$(cat "$w/v.out")"; else [ "$rc" -ne 0 ] && ok "validate: $1 exits non-zero" || bad "validate: $1 exits non-zero"; fi
}
vtry "the envelope for this inventory" 0 "$w/f.json"
vtry "an envelope carrying findings" 0 "$w/f-vuln.json"
printf '%s' '{"bomFormat":"CycloneDX"}' > "$w/v-bare.json"
vtry "a bare CycloneDX marker" 1 "$w/v-bare.json"
vtry "the unscanned SBOM itself" 1 "$w/a.json"
vtry "an envelope for another inventory" 1 "$w/f-b.json"
vtry "an envelope missing one requested component" 1 "$w/f-missing.json"
vtry "a superset envelope (extra components are ignored)" 0 "$w/f-c.json"
vtry "a missing file" 1 "$w/nonexistent.json"
vtry "an empty file" 1 "$w/m4.json"
ls "$w" | grep -q "findings" && bad "validate: wrote something" || ok "validate: writes nothing"

# --- a TRIMMED REAL pair: nine components copied from inspector-sbomgen's SBOM and ScanSbom's answer for production-amd64
# (CI run 37479078522): the OS component without a purl, two deb packages with qualifiers, a generic purl without a version,
# Go modules whose NAME the service cut to the last path segment (perks, v2, sys), an unresolved module (no version), and
# our own module stamped with a commit-derived version. The response also renumbers bom-refs and adds properties.
cat > "$w/real-sbom.json" <<'REALSBOM'
{
 "bomFormat": "CycloneDX",
 "specVersion": "1.5",
 "serialNumber": "urn:uuid:real-trimmed",
 "metadata": {
  "timestamp": "2026-10-06T12:35:00Z"
 },
 "components": [
  {
   "bom-ref": "comp-2",
   "type": "operating-system",
   "name": "Debian GNU/Linux",
   "version": "13"
  },
  {
   "bom-ref": "comp-3",
   "type": "application",
   "name": "ca-certificates",
   "version": "20250419",
   "purl": "pkg:deb/debian/ca-certificates@20250419?arch=all&distro=13"
  },
  {
   "bom-ref": "comp-8",
   "type": "application",
   "name": "base-files",
   "version": "13.8+deb13u7",
   "purl": "pkg:deb/debian/base-files@13.8%2Bdeb13u7?arch=amd64&distro=13"
  },
  {
   "bom-ref": "comp-9",
   "type": "application",
   "name": "fscache",
   "hashes": [
    {
     "alg": "SHA-256",
     "content": "61ca2fc84cba1574c70481527c8c0dae6c6d716534add07a23e4a127ec5049a1"
    }
   ],
   "purl": "pkg:generic/fscache?distro=linux&go_toolchain=1.27.1",
   "properties": [
    {
     "name": "amazon:inspector:sbom_generator:source_path",
     "value": "/usr/local/bin/fscache"
    }
   ]
  },
  {
   "bom-ref": "comp-10",
   "type": "library",
   "name": "github.com/beorn7/perks",
   "version": "v1.0.1",
   "purl": "pkg:golang/github.com/beorn7/perks@v1.0.1",
   "properties": [
    {
     "name": "amazon:inspector:sbom_generator:source_path",
     "value": "/usr/local/bin/fscache"
    }
   ]
  },
  {
   "bom-ref": "comp-11",
   "type": "library",
   "name": "github.com/cespare/xxhash/v2",
   "version": "v2.3.0",
   "purl": "pkg:golang/github.com/cespare/xxhash/v2@v2.3.0",
   "properties": [
    {
     "name": "amazon:inspector:sbom_generator:source_path",
     "value": "/usr/local/bin/fscache"
    }
   ]
  },
  {
   "bom-ref": "comp-12",
   "type": "library",
   "name": "github.com/munnerz/goautoneg",
   "purl": "pkg:golang/github.com/munnerz/goautoneg?unresolved=true",
   "properties": [
    {
     "name": "amazon:inspector:sbom_generator:source_path",
     "value": "/usr/local/bin/fscache"
    },
    {
     "name": "amazon:inspector:sbom_generator:unresolved_version",
     "value": "v0.0.0-20191010083416-a7dc8b61c822"
    }
   ]
  },
  {
   "bom-ref": "comp-18",
   "type": "library",
   "name": "golang.org/x/sys",
   "version": "v0.47.0",
   "purl": "pkg:golang/golang.org/x/sys@v0.47.0",
   "properties": [
    {
     "name": "amazon:inspector:sbom_generator:source_path",
     "value": "/usr/local/bin/fscache"
    }
   ]
  },
  {
   "bom-ref": "comp-20",
   "type": "library",
   "name": "github.com/fosterstack/cache",
   "version": "v0.2.2-0.20261006123452-5d3616aa0907",
   "purl": "pkg:golang/github.com/fosterstack/cache@v0.2.2-0.20261006123452-5d3616aa0907",
   "properties": [
    {
     "name": "amazon:inspector:sbom_generator:source_path",
     "value": "/usr/local/bin/fscache"
    }
   ]
  }
 ]
}
REALSBOM
cat > "$w/real-scan.json" <<'REALSCAN'
{
 "sbom": {
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:real-trimmed-resp",
  "metadata": {
   "timestamp": "2026-10-06T12:36:00Z"
  },
  "components": [
   {
    "bom-ref": "comp-1",
    "name": "Debian GNU/Linux",
    "type": "operating-system",
    "version": "13"
   },
   {
    "bom-ref": "comp-2",
    "name": "ca-certificates",
    "purl": "pkg:deb/debian/ca-certificates@20250419?arch=all&distro=13",
    "type": "application",
    "version": "20250419",
    "properties": [
     {
      "name": "amazon:inspector:sbom_scanner:info",
      "value": "Component skipped: no supported rules found."
     }
    ]
   },
   {
    "bom-ref": "comp-7",
    "name": "base-files",
    "purl": "pkg:deb/debian/base-files@13.8%2Bdeb13u7?arch=amd64&distro=13",
    "type": "application",
    "version": "13.8+deb13u7",
    "properties": [
     {
      "name": "amazon:inspector:sbom_scanner:info",
      "value": "Component skipped: no supported rules found."
     }
    ]
   },
   {
    "bom-ref": "comp-8",
    "name": "fscache",
    "purl": "pkg:generic/fscache?distro=linux&go_toolchain=1.27.1",
    "type": "application",
    "properties": [
     {
      "name": "amazon:inspector:sbom_scanner:path",
      "value": "/usr/local/bin/fscache"
     },
     {
      "name": "amazon:inspector:sbom_scanner:info",
      "value": "Component scanned: no known vulnerabilities."
     }
    ]
   },
   {
    "bom-ref": "comp-9",
    "name": "perks",
    "purl": "pkg:golang/github.com/beorn7/perks@v1.0.1",
    "type": "library",
    "version": "v1.0.1",
    "properties": [
     {
      "name": "amazon:inspector:sbom_scanner:path",
      "value": "/usr/local/bin/fscache"
     },
     {
      "name": "amazon:inspector:sbom_scanner:info",
      "value": "Component skipped: no supported rules found."
     }
    ]
   },
   {
    "bom-ref": "comp-10",
    "name": "v2",
    "purl": "pkg:golang/github.com/cespare/xxhash/v2@v2.3.0",
    "type": "library",
    "version": "v2.3.0",
    "properties": [
     {
      "name": "amazon:inspector:sbom_scanner:path",
      "value": "/usr/local/bin/fscache"
     },
     {
      "name": "amazon:inspector:sbom_scanner:info",
      "value": "Component skipped: no supported rules found."
     }
    ]
   },
   {
    "bom-ref": "comp-11",
    "name": "goautoneg",
    "purl": "pkg:golang/github.com/munnerz/goautoneg?unresolved=true",
    "type": "library",
    "properties": [
     {
      "name": "amazon:inspector:sbom_scanner:path",
      "value": "/usr/local/bin/fscache"
     },
     {
      "name": "amazon:inspector:sbom_scanner:unresolved_version",
      "value": "v0.0.0-20191010083416-a7dc8b61c822"
     },
     {
      "name": "amazon:inspector:sbom_scanner:warning",
      "value": "Component skipped: unresolved version provided."
     }
    ]
   },
   {
    "bom-ref": "comp-17",
    "name": "sys",
    "purl": "pkg:golang/golang.org/x/sys@v0.47.0",
    "type": "library",
    "version": "v0.47.0",
    "properties": [
     {
      "name": "amazon:inspector:sbom_scanner:path",
      "value": "/usr/local/bin/fscache"
     },
     {
      "name": "amazon:inspector:sbom_scanner:info",
      "value": "Component scanned: no known vulnerabilities."
     }
    ]
   },
   {
    "bom-ref": "comp-19",
    "name": "cache",
    "purl": "pkg:golang/github.com/fosterstack/cache@v0.2.2-0.20261006123452-5d3616aa0907",
    "type": "library",
    "version": "v0.2.2-0.20261006123452-5d3616aa0907",
    "properties": [
     {
      "name": "amazon:inspector:sbom_scanner:path",
      "value": "/usr/local/bin/fscache"
     },
     {
      "name": "amazon:inspector:sbom_scanner:info",
      "value": "Component skipped: no supported rules found."
     }
    ]
   }
  ]
 }
}
REALSCAN
kr=$(python3 "$prog" key "$w/real-sbom.json"); rcr=$?
expect "real pair: the key of the real SBOM is computed (exit 0, 64 hex)" "0 64" "$rcr ${#kr}"
python3 "$prog" validate "$w/real-sbom.json" "$w/real-scan.json"; expect "real pair: validate passes (truncated Go names, renumbered refs, properties)" 0 "$?"
rd="$w/realcache"; python3 "$prog" store "$rd" "$D" "$w/real-sbom.json" "$w/real-scan.json"; expect "real pair: store accepts it" 0 "$?"
expect "real pair: decide reuses it" "reuse
$rd/$D/$kr.findings.json" "$(python3 "$prog" decide "$rd" "$D" "$w/real-sbom.json")"
python3 - "$w" <<'PY'
import json, sys
w = sys.argv[1]
s = json.load(open(w + "/real-sbom.json")); s["serialNumber"] = "urn:uuid:other"; s["metadata"] = {"timestamp": "2030-01-01T00:00:00Z"}
for c in s["components"]:
    if c["name"] == "github.com/fosterstack/cache": c["version"] = "v0.2.3-0.20271231000000-ffffffffffff"; c["purl"] = "pkg:golang/github.com/fosterstack/cache@v0.2.3-0.20271231000000-ffffffffffff"
s["components"].reverse(); json.dump(s, open(w + "/real-sbom-next.json", "w"))
r = json.load(open(w + "/real-scan.json")); r["sbom"]["components"] = [c for c in r["sbom"]["components"] if c["name"] != "perks"]; json.dump(r, open(w + "/real-scan-missing.json", "w"))
r = json.load(open(w + "/real-scan.json")); r["sbom"]["components"] = [c for c in r["sbom"]["components"] if c["name"] != "sys"]; json.dump(r, open(w + "/real-scan-missing2.json", "w"))
s = json.load(open(w + "/real-sbom.json"))
for c in s["components"]:
    if c["name"] == "github.com/beorn7/perks": c["purl"] = "pkg:golang/github.com/beorn7/perks@v1.0.2"; c["version"] = "v1.0.2"
json.dump(s, open(w + "/real-sbom-other.json", "w"))
PY
expect "real pair: the next commit's SBOM (new serial, timestamp, our module's stamp, other order) has the same key" "$kr" "$(python3 "$prog" key "$w/real-sbom-next.json")"
expect "real pair: ...and the stored answer is reused for it" reuse "$(python3 "$prog" decide "$rd" "$D" "$w/real-sbom-next.json" | head -1)"
python3 "$prog" validate "$w/real-sbom.json" "$w/real-scan-missing.json" 2>/dev/null; [ $? -ne 0 ] && ok "real pair: a response missing a requested Go module (perks) is refused" || bad "real pair: response missing perks"
python3 "$prog" validate "$w/real-sbom.json" "$w/real-scan-missing2.json" 2>/dev/null; [ $? -ne 0 ] && ok "real pair: a response missing another requested Go module (sys) is refused" || bad "real pair: response missing sys"
python3 "$prog" validate "$w/real-sbom-other.json" "$w/real-scan.json" 2>/dev/null; [ $? -ne 0 ] && ok "real pair: the response for another inventory (perks v1.0.1, asked v1.0.2) is refused" || bad "real pair: other inventory"
expect "real pair: ...and decide calls for that other inventory" call "$(python3 "$prog" decide "$rd" "$D" "$w/real-sbom-other.json")"
python3 "$prog" validate "$w/real-sbom.json" "$w/real-sbom.json" 2>/dev/null; [ $? -ne 0 ] && ok "real pair: the unscanned SBOM in place of the answer is refused" || bad "real pair: unscanned SBOM accepted"
# the real downloaded pairs of CI run 37479078522, when present locally (a local proof, not a CI dependency)
if ls /tmp/lbl3/insp/inspector/*/scan.json >/dev/null 2>&1; then
  nreal=0; nok=0
  for dd in /tmp/lbl3/insp/inspector/*/; do
    nreal=$((nreal+1)); python3 "$prog" validate "${dd}sbom.cdx.json" "${dd}scan.json" 2>/dev/null && nok=$((nok+1)) || echo "  real pair rejected: $dd"
  done
  expect "real pairs (/tmp/lbl3/insp/inspector/*): every one validates" "$nreal" "$nok"
else
  echo "NOTE: /tmp/lbl3/insp/inspector is absent: the local proof over the real pairs is skipped"
fi

# a name containing "@" cannot collide with another name/version split: identifiers are structured pairs
python3 - "$w" <<'PY'
import json, sys
w = sys.argv[1]
base = [{"name": "libc6", "version": "2.36", "purl": "pkg:generic/libc6@2.36"}]
def sb(name, filename, comp):
    json.dump({"bomFormat": "CycloneDX", "components": base + [comp]}, open("%s/%s" % (w, filename), "w"))
sb("c1", "col1.json", {"name": "alpha@beta", "version": "1"})
sb("c2", "col2.json", {"name": "alpha", "version": "beta@1"})
sb("c3", "col3.json", {"purl": "pkg:generic/alpha%40beta@1"})
sb("c4", "col4.json", {"purl": "pkg:generic/alpha@beta%401"})
PY
for n in 1 2 3 4; do mkenv "$w/fcol$n.json" "$w/col$n.json"; done
[ "$(python3 "$prog" key "$w/col1.json")" != "$(python3 "$prog" key "$w/col2.json")" ] && ok "collision: name 'alpha@beta' version '1' and name 'alpha' version 'beta@1' have DIFFERENT keys" || bad "collision: keys equal"
[ "$(python3 "$prog" key "$w/col3.json")" != "$(python3 "$prog" key "$w/col4.json")" ] && ok "collision: the same pair split differently inside a purl: different keys" || bad "collision: purl keys equal"
expect "collision: an explicit pair and its purl form (alpha%40beta@1) are the same identifier" "$(python3 "$prog" key "$w/col1.json")" "$(python3 "$prog" key "$w/col3.json")"
for pair in "1 2" "2 1" "3 4" "4 3"; do
  set -- $pair
  python3 "$prog" validate "$w/col$1.json" "$w/fcol$2.json" 2>/dev/null; [ $? -ne 0 ] && ok "collision: validate refuses the envelope of col$2 for col$1" || bad "collision: validate accepted col$2's envelope for col$1"
  cc="$w/colcache$1$2"; python3 "$prog" store "$cc" "$D" "$w/col$1.json" "$w/fcol$2.json" 2>/dev/null; [ $? -ne 0 ] && [ ! -e "$cc" ] && ok "collision: store refuses the envelope of col$2 for col$1 and writes nothing" || bad "collision: store accepted col$2 for col$1"
  mkdir -p "$cc/$D"; cp "$w/fcol$2.json" "$cc/$D/$(python3 "$prog" key "$w/col$1.json").findings.json"
  expect "collision: decide calls for col$1 when the stored answer is col$2's" call "$(python3 "$prog" decide "$cc" "$D" "$w/col$1.json")"
done
python3 "$prog" validate "$w/col1.json" "$w/fcol1.json"; expect "collision: ...while an envelope for its own inventory validates" 0 "$?"

# decide reads the stored file and keeps it only when it is Inspector's answer for THIS inventory
bd="$w/badcache"; mkdir -p "$bd/$D"
dec() { python3 "$prog" decide "$bd" "$D" "$w/a.json" 2>"$w/dec.err"; }
put() { rm -rf "$bd/$D/$K.findings.json"; printf '%s' "$1" > "$bd/$D/$K.findings.json"; }
rm -f "$bd/$D/$K.findings.json"
expect "decide: a missing file calls" call "$(dec)"
: > "$bd/$D/$K.findings.json";                 expect "decide: an empty file calls" call "$(dec)"
put '{"bomFormat":'; expect "decide: invalid JSON calls" call "$(dec)"
put '[]';            expect "decide: a JSON array calls" call "$(dec)"
put '"CycloneDX"';   expect "decide: a JSON string calls" call "$(dec)"
put '{"bomFormat":"CycloneDX"}'; expect "decide: a bare CycloneDX marker calls" call "$(dec)"
put '{"bomFormat":"CycloneDX","specVersion":"1.5","components":[],"vulnerabilities":[]}'; expect "decide: a bare CycloneDX document with no envelope calls" call "$(dec)"
cp "$w/a.json" "$bd/$D/$K.findings.json";    expect "decide: the unscanned SBOM itself (no envelope) calls" call "$(dec)"
put '{"vulnerabilities":[]}'; expect "decide: a JSON object that is not CycloneDX calls" call "$(dec)"
put '{"sbom":{"bomFormat":"nope","components":[]}}'; expect "decide: an envelope around a non-CycloneDX object calls" call "$(dec)"
put '{"sbom":[]}';   expect "decide: an envelope around a non-object calls" call "$(dec)"
python3 - "$w" <<'PY'
import json, sys
w = sys.argv[1]
d = json.load(open(w + "/f.json"))
d["sbom"].pop("components"); json.dump(d, open(w + "/f-nocomp.json", "w"))
d = json.load(open(w + "/f.json")); d["sbom"]["components"] = []; json.dump(d, open(w + "/f-emptycomp.json", "w"))
d = json.load(open(w + "/f.json")); d["sbom"]["components"] = {}; json.dump(d, open(w + "/f-dictcomp.json", "w"))
PY
cp "$w/f-nocomp.json" "$bd/$D/$K.findings.json";    expect "decide: an envelope with no components calls" call "$(dec)"
cp "$w/f-emptycomp.json" "$bd/$D/$K.findings.json"; expect "decide: an envelope with an empty component list calls" call "$(dec)"
cp "$w/f-dictcomp.json" "$bd/$D/$K.findings.json";  expect "decide: an envelope whose components are not a list calls" call "$(dec)"
cp "$w/f-d.json" "$bd/$D/$K.findings.json";  expect "decide: an envelope for a DIFFERENT inventory (zlib 1.4 instead of 1.3) calls" call "$(dec)"
cp "$w/f-missing.json" "$bd/$D/$K.findings.json"; expect "decide: an envelope missing one requested component (libc6) calls" call "$(dec)"
cp "$w/f-c.json" "$bd/$D/$K.findings.json";  expect "decide: a SUPERSET envelope (the requested components plus one more) is reused" reuse "$(dec | head -1)"
cp "$w/f-b.json" "$bd/$D/$K.findings.json";  expect "decide: an envelope whose components differ by one version calls" call "$(dec)"
cp "$w/f.json" "$bd/$D/$kb.findings.json";   expect "decide: a valid envelope under a DIFFERENT key name (asked for b) calls" call "$(python3 "$prog" decide "$bd" "$D" "$w/b.json")"
cp "$w/f.json" "$bd/$D/$K.findings.json";    expect "decide: the valid envelope for this inventory reuses" reuse "$(dec | head -1)"
cp "$w/f-vuln.json" "$bd/$D/$K.findings.json"; expect "decide: an envelope carrying findings is reused as it is" reuse "$(dec | head -1)"
rm -f "$bd/$D/$K.findings.json"; mkdir "$bd/$D/$K.findings.json"; expect "decide: a directory in its place calls" call "$(dec)"
rmdir "$bd/$D/$K.findings.json"
cp "$w/f.json" "$w/target.json"; ln -s "$w/target.json" "$bd/$D/$K.findings.json"; expect "decide: a symbolic link (to a valid envelope) calls" call "$(dec)"
rm -f "$bd/$D/$K.findings.json"
printf '\377\376' > "$bd/$D/$K.findings.json"; expect "decide: unreadable bytes call" call "$(dec)"
expect "decide: unreadable bytes never raise" 0 "$(grep -c Traceback "$w/dec.err")"
if [ "$is_root" = 1 ]; then
  echo "NOTE: running as root, chmod 000 does not deny reads: the permission-denied cases are skipped"
else
  cp "$w/f.json" "$bd/$D/$K.findings.json"; chmod 000 "$bd/$D/$K.findings.json"
  expect "decide: a VALID envelope that is unreadable (chmod 000) calls" call "$(dec)"
  expect "decide: ...and never raises" 0 "$(grep -c Traceback "$w/dec.err")"
  chmod 600 "$bd/$D/$K.findings.json"
  expect "decide: ...readable again, the same file reuses (the denial was the only reason)" reuse "$(dec | head -1)"
  # a DATE directory that cannot be entered
  chmod 000 "$bd/$D"; expect "decide: an unreadable DATE directory calls" call "$(dec)"; chmod 700 "$bd/$D"
  # store into a read-only DIR: non-zero, never a traceback
  mkdir -p "$w/ro"; chmod 500 "$w/ro"
  python3 "$prog" store "$w/ro/c" "$D" "$w/a.json" "$w/f.json" 2>"$w/st.err"; rc=$?
  if [ "$rc" -ne 0 ] && ! grep -q Traceback "$w/st.err"; then ok "store: a DIR that cannot be written exits non-zero without a traceback"; else bad "store: unwritable DIR (rc=$rc)"; fi
  chmod 700 "$w/ro"
  # store of an unreadable answer
  cp "$w/f.json" "$w/f-denied.json"; chmod 000 "$w/f-denied.json"
  python3 "$prog" store "$w/cd2" "$D" "$w/a.json" "$w/f-denied.json" 2>"$w/st.err"; rc=$?
  if [ "$rc" -ne 0 ] && [ ! -e "$w/cd2" ] && ! grep -q Traceback "$w/st.err"; then ok "store: an unreadable answer exits non-zero, writes nothing, no traceback"; else bad "store: unreadable answer (rc=$rc)"; fi
  chmod 600 "$w/f-denied.json"
fi
rm -f "$bd/$D/$K.findings.json"
expect "decide: a DIR that does not exist calls" call "$(python3 "$prog" decide "$w/nope" "$D" "$w/a.json" 2>/dev/null)"
expect "decide: an SBOM that does not exist calls" call "$(python3 "$prog" decide "$cdir" "$D" "$w/nonexistent.json" 2>/dev/null)"
expect "decide: an SBOM with no inventory (only our module) calls" call "$(python3 "$prog" decide "$cdir" "$D" "$w/only-ours.json" 2>/dev/null)"
for d in "../x" "20261006" "" "2026-10-06
" "2026-10-6"; do
  expect "decide: a malformed date ($(printf %s "$d" | tr '\n' '$')) calls" call "$(python3 "$prog" decide "$cdir" "$d" "$w/a.json" 2>/dev/null)"
done
expect "decide: a 16-hex key argument is not an SBOM: calls" call "$(python3 "$prog" decide "$cdir" "$D" 0123456789abcdef 2>/dev/null)"
expect "decide: too few arguments calls (never raises)" call "$(python3 "$prog" decide 2>/dev/null)"
expect "decide: no arguments at all calls" call "$(python3 "$prog" decide "$cdir" 2>/dev/null)"
# links: DIR/DATE a symlink, an ancestor symlink: refused for decide and store
mkdir -p "$w/elsewhere" "$w/anc"; cp "$w/f.json" "$w/elsewhere/$K.findings.json"; ln -s "$w/elsewhere" "$w/anc/$D"
expect "decide: DIR/DATE is a symlink (to a directory holding a valid answer) calls" call "$(python3 "$prog" decide "$w/anc" "$D" "$w/a.json" 2>/dev/null)"
python3 "$prog" store "$w/anc" "$D" "$w/a.json" "$w/f-vuln.json" >/dev/null 2>&1; rc=$?
if [ "$rc" -ne 0 ] && cmp -s "$w/f.json" "$w/elsewhere/$K.findings.json" && [ "$(ls -A "$w/elsewhere")" = "$K.findings.json" ]; then ok "store: DIR/DATE is a symlink: refused, nothing written through it"; else bad "store: DIR/DATE is a symlink (rc=$rc)"; fi
mkdir -p "$w/anc2/$D"; ln -s "$w/target.json" "$w/anc2/$D/$K.findings.json"
python3 "$prog" store "$w/anc2" "$D" "$w/a.json" "$w/f-vuln.json" >/dev/null 2>&1; rc=$?
if [ "$rc" -ne 0 ] && [ -L "$w/anc2/$D/$K.findings.json" ] && cmp -s "$w/f.json" "$w/target.json"; then ok "store: the stored file is a symlink: refused, not followed or replaced"; else bad "store: the stored file is a symlink (rc=$rc)"; fi

# store refuses anything that is not Inspector's answer for the requested inventory, and writes nothing
sd="$w/storecache"
st() { python3 "$prog" store "$sd" "$D" "$w/a.json" "$1" > "$w/so.txt" 2>/dev/null; echo "$?"; }
tryinv() { # name content
  printf '%s' "$2" > "$w/inv.json"
  rc=$(st "$w/inv.json")
  if [ "$rc" -ne 0 ] && [ ! -e "$sd" ] && [ ! -s "$w/so.txt" ]; then ok "store: $1 exits non-zero and writes nothing"; else bad "store: $1 (rc=$rc, dir: $(ls -A "$sd" 2>&1))"; fi
}
tryfile() { # name file
  rc=$(st "$2")
  if [ "$rc" -ne 0 ] && [ ! -e "$sd" ] && [ ! -s "$w/so.txt" ]; then ok "store: $1 exits non-zero and writes nothing"; else bad "store: $1 (rc=$rc, dir: $(ls -A "$sd" 2>&1))"; fi
}
tryinv "an empty file" ""
tryinv "invalid JSON" '{"bomFormat":'
tryinv "a JSON array" '[]'
tryinv "a JSON object that is not CycloneDX" '{"vulnerabilities":[]}'
tryinv "a bare CycloneDX marker" '{"bomFormat":"CycloneDX"}'
tryinv "a bare CycloneDX document (no envelope)" '{"bomFormat":"CycloneDX","specVersion":"1.5","components":[],"vulnerabilities":[]}'
tryfile "the unscanned SBOM itself" "$w/a.json"
tryfile "an envelope for a different inventory (zlib 1.4 instead of 1.3)" "$w/f-d.json"
tryfile "an envelope missing one requested component" "$w/f-missing.json"
tryfile "an envelope whose components differ by one version" "$w/f-b.json"
tryfile "an envelope with no components" "$w/f-nocomp.json"
tryfile "an envelope with an empty component list" "$w/f-emptycomp.json"
rc=$(st "$w/nonexistent.json")
if [ "$rc" -ne 0 ] && [ ! -e "$sd" ]; then ok "store: a missing file exits non-zero and writes nothing"; else bad "store: a missing file"; fi
python3 "$prog" store "$sd" "../x" "$w/a.json" "$w/f.json" >/dev/null 2>&1; rc=$?
if [ "$rc" -ne 0 ] && [ ! -e "$sd" ]; then ok "store: a malformed date exits non-zero and writes nothing"; else bad "store: a malformed date"; fi
python3 "$prog" store "$sd" "$D" "$w/only-ours.json" "$w/f.json" >/dev/null 2>&1; rc=$?
if [ "$rc" -ne 0 ] && [ ! -e "$sd" ]; then ok "store: an SBOM with no inventory exits non-zero and writes nothing"; else bad "store: an SBOM with no inventory"; fi
python3 "$prog" store "$sd" "$D" "$w/a.json" "$w/f.json" 0123456789abcdef >/dev/null 2>&1; rc=$?
[ "$rc" -ne 0 ] && ok "store: the old KEY-argument form (extra argument) is refused" || bad "store: the old form is refused"
# a bad store never damages an existing valid entry
python3 "$prog" store "$sd" "$D" "$w/a.json" "$w/f.json"
printf 'garbage' > "$w/inv.json"; rc=$(st "$w/inv.json")
[ "$rc" -ne 0 ] && cmp -s "$w/f.json" "$sd/$D/$K.findings.json" && ok "store: an invalid file leaves the existing valid entry intact" || bad "store: an invalid file leaves the existing entry intact"
rc=$(st "$w/f-d.json")
[ "$rc" -ne 0 ] && cmp -s "$w/f.json" "$sd/$D/$K.findings.json" && ok "store: another inventory's answer leaves the existing entry intact" || bad "store: another inventory's answer leaves the entry intact"
# a second store of the same key keeps a valid file
python3 "$prog" store "$sd" "$D" "$w/a.json" "$w/f-vuln.json"; rc=$?
expect "store: a second store of the same key exits 0" 0 "$rc"
cmp -s "$w/f-vuln.json" "$sd/$D/$K.findings.json" && ok "store: ...and holds the newer answer" || bad "store: ...and holds the newer answer"
expect "store: ...and the stored file is still reused" reuse "$(python3 "$prog" decide "$sd" "$D" "$w/a.json" | head -1)"
expect "store: ...no temp file left" "$K.findings.json" "$(ls -A "$sd/$D")"
# the write is flushed to disk: the file and its directory are fsynced
python3 - "$prog" "$w" "$D" <<'PY'
import os, runpy, sys
prog, w, day = sys.argv[1:4]
calls = []
real = os.fsync
def spy(fd):
    calls.append(os.fstat(fd).st_mode)
    return real(fd)
os.fsync = spy
sys.argv = [prog, "store", w + "/fsync-cache", day, w + "/a.json", w + "/f.json"]
try:
    runpy.run_path(prog, run_name="__main__")
except SystemExit as e:
    assert not e.code, e.code
import stat
kinds = {"file" if stat.S_ISREG(m) else "dir" if stat.S_ISDIR(m) else "other" for m in calls}
sys.exit(0 if kinds == {"file", "dir"} else 1)
PY
expect "store: fsyncs the file and its directory" 0 "$?"

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
sim="$w/sim"; mkdir -p "$sim/bin" "$sim/sboms" "$sim/repo/.vex"
ln -s "$root/bin" "$sim/repo/bin"
python3 - "$root" "$sim" <<'PY'
import json, sys
root, sim = sys.argv[1:3]
# the real VEX document's shape, with no statements: nothing is covered unless a case adds a statement
d = json.load(open(root + "/.vex/fosterstack-cache.openvex.json")); d["statements"] = []
json.dump(d, open(sim + "/repo/.vex/fosterstack-cache.openvex.json", "w"))
PY
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
# FAKE_FLIP_FLAG: the call completes, then the clock moves on (UTC midnight between the response and the store)
[ -n "${FAKE_FLIP_FLAG:-}" ] && : > "$FAKE_FLIP_FLAG"
case "${FAKE_AWS_MODE:-}" in
  bare)  echo '{"bomFormat":"CycloneDX"}'; exit 0 ;;
  sbom)  cat "$sbom"; exit 0 ;;
  other) python3 -c 'import json,sys; print(json.dumps({"sbom":{"bomFormat":"CycloneDX","components":[{"name":"someone-else","version":"1","bom-ref":"x"}],"vulnerabilities":[]}}))'; exit 0 ;;
esac
# the answer in the real service's shape (shape.py above); FAKE_VULN=CVE:pkgname adds one vulnerability
exec python3 "$FAKE_SHAPE" "$sbom" "${FAKE_VULN:-}"
EOF
# the clock: FAKE_DAY, or FAKE_NEXT_DAY once any result has been stored (a run that crosses UTC midnight mid-loop)
cat > "$sim/bin/date" <<'EOF'
#!/usr/bin/env bash
if [ "$*" = "-u +%F" ]; then
  if [ -n "${FAKE_FLIP_FLAG:-}" ] && [ -e "$FAKE_FLIP_FLAG" ]; then echo "$FAKE_NEXT_DAY"
  elif [ -n "${FAKE_NEXT_DAY:-}" ] && ls "$FAKE_CACHE"/*/*.findings.json >/dev/null 2>&1; then echo "$FAKE_NEXT_DAY"; else echo "$FAKE_DAY"; fi
  exit 0
fi
exec /bin/date "$@"
EOF
printf '#!/usr/bin/env bash\nexit 0\n' > "$sim/bin/sudo"; cp "$sim/bin/sudo" "$sim/bin/skopeo"
chmod +x "$sim/bin/"*
# the images: the two platform children of a variant carry the same inventory (different stamp); the variants differ
mksbom "$sim/sboms/cand-production-amd64.json" urn:uuid:p1 2026-10-06T01:00:00Z v1 busybox@1.37.0 libc6@2.36 go:github.com/beorn7/perks@v1.0.1
mksbom "$sim/sboms/cand-production-arm64.json" urn:uuid:p2 2026-10-06T01:00:09Z v1 busybox@1.37.0 libc6@2.36 go:github.com/beorn7/perks@v1.0.1
mksbom "$sim/sboms/cand-debug-amd64.json"      urn:uuid:d1 2026-10-06T01:00:00Z v1 busybox@1.37.0 libc6@2.36 go:github.com/beorn7/perks@v1.0.1 gdb@13
mksbom "$sim/sboms/cand-debug-arm64.json"      urn:uuid:d2 2026-10-06T01:00:09Z v1 busybox@1.37.0 libc6@2.36 go:github.com/beorn7/perks@v1.0.1 gdb@13
mksbom "$sim/sboms/cand-fips-amd64.json"       urn:uuid:f1 2026-10-06T01:00:00Z v1 busybox@1.37.0 libc6@2.36 go:github.com/beorn7/perks@v1.0.1 openssl@3
mksbom "$sim/sboms/cand-fips-arm64.json"       urn:uuid:f2 2026-10-06T01:00:09Z v1 busybox@1.37.0 libc6@2.36 go:github.com/beorn7/perks@v1.0.1 openssl@3

# run_step <script-file> <day> [fail] [next-day]: the extracted step, /tmp moved into the sandbox, in a repo-shaped dir
run_step() {
  : > "$sim/aws.log"; : > "$sim/summary.md"; : > "$sim/out.txt"
  ( cd "$sim/repo" && PATH="$sim/bin:$PATH" FAKE_SBOMS="$sim/sboms" FAKE_AWS_LOG="$sim/aws.log" FAKE_AWS_FAIL="${3:-}" \
      FAKE_DAY="$2" FAKE_NEXT_DAY="${4:-}" FAKE_CACHE="$sim/tmp/inspector-cache" FAKE_VULN="${FAKE_VULN:-}" \
      FAKE_SHAPE="$w/shape.py" FAKE_AWS_MODE="${FAKE_AWS_MODE:-}" FAKE_FLIP_FLAG="${FAKE_FLIP_FLAG:-}" \
      GITHUB_STEP_SUMMARY="$sim/summary.md" GITHUB_OUTPUT="$sim/out.txt" bash "$1" ) > "$sim/log.txt" 2>&1
}
calls() { wc -l < "$sim/aws.log" | tr -d ' '; }
fresh() { sed -n 's/^fresh=//p' "$sim/out.txt" | tail -1; }
sandbox() { sed "s#/tmp/#$sim/tmp/#g" ; }
# mutate <python-statements acting on t>: edits the script on stdin (the mutation must apply)
mutate() { python3 -c '
import sys
t = sys.stdin.read(); t0 = t
exec(sys.argv[1])
if t == t0:
    sys.exit("the mutation did not apply")
sys.stdout.write(t)' "$1"; }
CLEAN='{"sbom":{"bomFormat":"CycloneDX","components":[],"vulnerabilities":[]}}'

# --- scan.yml: the PR gate
extract scan.yml scanner "Amazon Inspector scan every loaded image" > "$sim/scan-raw.sh" || { bad "extract scan.yml's Inspector step"; }
sandbox < "$sim/scan-raw.sh" > "$sim/scan-step.sh"
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
cp "$sim/sboms/cand-debug-amd64.json" "$sim/debug-amd64.keep"
mksbom "$sim/sboms/cand-debug-amd64.json" urn:uuid:d9 2026-10-06T01:00:00Z v1 busybox@1.37.0 libc6@2.36 go:github.com/beorn7/perks@v1.0.1 gdb@14
run_step "$sim/scan-step.sh" 2026-10-06; rc=$?
expect "scan.yml a different hash: exactly that image calls Inspector" 1 "$(calls)"
expect "scan.yml a different hash: gate still fed" 4 "$(gate_lines)"
cp "$sim/debug-amd64.keep" "$sim/sboms/cand-debug-amd64.json"
# a corrupted stored result
for f in "$sim"/tmp/inspector-cache/2026-10-06/*.findings.json; do printf 'garbage' > "$f"; done
run_step "$sim/scan-step.sh" 2026-10-06; rc=$?
expect "scan.yml corrupted stored results: each distinct inventory in use calls again" 2 "$(calls)"
expect "scan.yml corrupted stored results: step succeeds and the gate is fed" "0 4" "$rc $(gate_lines)"
run_step "$sim/scan-step.sh" 2026-10-06
expect "scan.yml corrupted stored results: the fresh results replaced them (next run reuses, no call)" 0 "$(calls)"
# a stored result that is valid JSON of the right kind but answers ANOTHER inventory is not reused
cdirs="$sim/tmp/inspector-cache/2026-10-06"
kp=$(python3 "$prog" key "$sim/sboms/cand-production-amd64.json"); kdb=$(python3 "$prog" key "$sim/sboms/cand-debug-amd64.json")
cp "$cdirs/$kp.findings.json" "$cdirs/$kdb.findings.json"   # production's answer lacks gdb: not a cover of debug
run_step "$sim/scan-step.sh" 2026-10-06; rc=$?
expect "scan.yml an answer that does not cover this inventory, under this key: not reused (one call), and replaced" "0 1" "$rc $(calls)"
python3 "$prog" decide "$sim/tmp/inspector-cache" 2026-10-06 "$sim/sboms/cand-debug-amd64.json" | head -1 | { read -r v; expect "scan.yml ...the replaced entry is reused next time" reuse "$v"; }
# a ScanSbom failure is a pipeline failure and stores nothing
reset_scan
run_step "$sim/scan-step.sh" 2026-10-06 1; rc=$?
expect "scan.yml ScanSbom fails: the step fails (rc 2, not a clean pass)" 2 "$rc"
expect "scan.yml ScanSbom fails: nothing stored" "" "$(ls -A "$sim/tmp/inspector-cache" 2>/dev/null)"
expect "scan.yml ScanSbom fails: fresh=0" 0 "$(fresh)"

# --- scan.yml: a UTC midnight in the middle of the loop. production-amd64 is scanned and stored at day D; the clock
# then reads D+1: production-arm64 (the SAME inventory) must NOT reuse day D's entry, and its answer is stored under D+1
reset_scan
run_step "$sim/scan-step.sh" 2026-10-06 "" 2026-10-07; rc=$?
expect "scan.yml midnight: the step succeeds" 0 "$rc"
expect "scan.yml midnight: the second image does not reuse the earlier day's entry (production-amd64 at D; production-arm64 and debug-amd64 at D+1 = 3 calls)" 3 "$(calls)"
expect "scan.yml midnight: the first image's answer is stored under day D, the later ones under D+1" "1 2" "$(ls "$sim/tmp/inspector-cache/2026-10-06" | wc -l | tr -d ' ') $(ls "$sim/tmp/inspector-cache/2026-10-07" | wc -l | tr -d ' ')"

# --- scan.yml: the clock moves on between the ScanSbom response and the store (the day read before the call no longer holds)
daycross_scan() { # script -> "rc calls stored-D stored-D+1 gate-finding-lines"
  reset_scan; rm -f "$sim/flip"
  FAKE_VULN="CVE-2099-0001:busybox" FAKE_FLIP_FLAG="$sim/flip" run_step "${SCRIPT:-$1}" 2026-10-06 "" 2026-10-07; r=$?
  echo "$r $(calls) $(ls "$sim/tmp/inspector-cache/2026-10-06" 2>/dev/null | wc -l | tr -d ' ') $(ls "$sim/tmp/inspector-cache/2026-10-07" 2>/dev/null | wc -l | tr -d ' ') $(grep -c '::error::inspector .*CVE-2099-0001 busybox@1.37.0' "$sim/log.txt" | tr -d ' ')"
}
DAYCROSS_SCAN="1 3 0 2 3"
expect "scan.yml day crossing: the first image's response is NOT stored (the day changed), the next same-inventory image calls AWS again, the fresh findings still reach the gate (rc 1, 3 findings), only D+1 holds entries" "$DAYCROSS_SCAN" "$(daycross_scan "$sim/scan-step.sh")"

# --- scan.yml: a ScanSbom answer that is not the envelope for this inventory is a pipeline failure, never a clean pass
bad_answer_scan() { # mode -> "rc gate-lines findings-files stored"
  reset_scan; FAKE_AWS_MODE="$1" run_step "${SCRIPT:-$sim/scan-step.sh}" 2026-10-06; r=$?
  echo "$r $(gate_lines) $(ls "$sim"/tmp/insp/*.findings.json 2>/dev/null | wc -l | tr -d ' ') $(ls -A "$sim/tmp/inspector-cache" 2>/dev/null | wc -l | tr -d ' ')"
}
for m in bare sbom other; do
  expect "scan.yml a rejected ScanSbom answer ($m): the step exits 2, no verdict reaches the gate (only the assessed line), no findings file is left, nothing stored" "2 1 0 0" "$(bad_answer_scan $m)"
done

# --- scan.yml: findings carried by a REUSED result reach the REAL gate, with and without our VEX
scan_case() { # script-file -> "rc1 rc2 calls2 identical findinglines2"
  reset_scan
  FAKE_VULN="CVE-2099-0001:busybox" run_step "$1" 2026-10-06; r1=$?
  run_step "$1" 2026-10-06; r2=$?
  c2=$(calls); same=yes
  for img in production-amd64 debug-amd64; do
    k=$(python3 "$prog" key "$sim/sboms/cand-$img.json")
    cmp -s "$sim/tmp/insp/$k.findings.json" "$sim/tmp/inspector-cache/2026-10-06/$k.findings.json" || same=no
    grep -q CVE-2099-0001 "$sim/tmp/insp/$k.findings.json" 2>/dev/null || same=no
  done
  echo "$r1 $r2 $c2 $same $(grep -c '::error::inspector .*CVE-2099-0001 busybox@1.37.0' "$sim/log.txt" | tr -d ' ')"
}
expect "scan.yml findings: run 1 (fresh, a vulnerability) exits 1; run 2 (REUSED, no call) exits 1 with the finding reported on every image, the gate's file byte-identical to the stored one" "1 1 0 yes 3" "$(scan_case "$sim/scan-step.sh")"
python3 - "$sim" <<'PY'
import json, sys
p = sys.argv[1] + "/repo/.vex/fosterstack-cache.openvex.json"
d = json.load(open(p))
d["statements"] = [{"vulnerability": {"@id": "https://nvd.nist.gov/vuln/detail/CVE-2099-0001", "name": "CVE-2099-0001", "aliases": []},
                    "timestamp": "2026-10-06T00:00:00-04:00", "products": [{"@id": "pkg:golang/github.com/fosterstack/cache"}, {"@id": "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache"}],
                    "status": "not_affected", "justification": "component_not_present"}]
json.dump(d, open(p, "w"))
PY
run_step "$sim/scan-step.sh" 2026-10-06; rc=$?
expect "scan.yml findings + VEX: the REUSED findings are covered by the published VEX: exit 0, no call, the gate says so" "0 0 3" "$rc $(calls) $(grep -c 'covered by the published VEX' "$sim/log.txt" | tr -d ' ')"
expect "scan.yml findings + VEX: ...and the covered count is 1 per image" 3 "$(grep -c '1 covered by the published VEX' "$sim/log.txt" | tr -d ' ')"
python3 - "$sim" <<'PY'
import json, sys
p = sys.argv[1] + "/repo/.vex/fosterstack-cache.openvex.json"
d = json.load(open(p)); d["statements"] = []; json.dump(d, open(p, "w"))
PY
# mutations of the reuse branch and of the gate's input must be caught by that case
mscan() { # name python-mutation
  mutate "$2" < "$sim/scan-raw.sh" | sandbox > "$sim/scan-mut.sh" || { bad "scan.yml mutation $1 did not apply"; return; }
  got=$(scan_case "$sim/scan-mut.sh")
  if [ "$got" != "1 1 0 yes 3" ]; then ok "scan.yml mutation caught by the findings case: $1 ($got)"; else bad "scan.yml mutation NOT caught: $1"; fi
}
mut_def() { read -r -d '' "$1"; }
export CLEAN
mut_def M_FIXED_CLEAN <<'EOF'
import os, re
t = re.sub(r'&& cp "\$\{verdict[^}]*\}"', lambda m: "&& printf '%s' '" + os.environ["CLEAN"] + "' >", t)
EOF
mut_def M_SBOM_SCAN <<'EOF'
import re
t = re.sub(r'&& cp "\$\{verdict[^}]*\}"', lambda m: '&& cp "/tmp/insp/${tag}.sbom.json"', t)
EOF
mut_def M_SBOM_RESCAN <<'EOF'
import re
t = re.sub(r'&& cp "\$\{verdict[^}]*\}"', lambda m: '&& cp "${d}/sbom.cdx.json"', t)
EOF
mut_def M_GATE_SBOM <<'EOF'
t = t.replace('"/tmp/insp/${key}.findings.json" .vex', '"/tmp/insp/${tag}.sbom.json" .vex')
EOF
mut_def M_GATE_CLEAN <<'EOF'
import os
t = t.replace('"/tmp/insp/${key}.findings.json" .vex', '"$(printf %s \'' + os.environ["CLEAN"] + '\' > /tmp/insp/clean.json; echo /tmp/insp/clean.json)" .vex')
EOF
mut_def M_NO_VALIDATE <<'EOF'
import re
t = re.sub(r'if ! python3 bin/inspector-reuse\.py validate', 'if ! true', t, count=1)
EOF
mut_def M_NO_RECHECK <<'EOF'
t = t.replace('[ "$(date -u +%F)" != "${day}" ]', 'false', 1)
EOF
mscan "the reuse branch writes a fixed clean document" "$M_FIXED_CLEAN"
mscan "the reuse branch hands the gate the SBOM instead of the findings" "$M_SBOM_SCAN"
mscan "the gate is fed the unscanned SBOM as the findings" "$M_GATE_SBOM"
mscan "the gate is fed a fixed clean document" "$M_GATE_CLEAN"
mscan2() { # name mutation function-and-args... (the unmutated script's answer is the reference; the mutant must differ)
  local name=$1 mut=$2; shift 2
  mutate "$mut" < "$sim/scan-raw.sh" | sandbox > "$sim/scan-mut.sh" || { bad "scan.yml mutation $name did not apply"; return; }
  want=$(SCRIPT="$sim/scan-step.sh" "$@"); got=$(SCRIPT="$sim/scan-mut.sh" "$@")
  if [ "$got" != "$want" ]; then ok "scan.yml mutation caught: $name ($got)"; else bad "scan.yml mutation NOT caught: $name"; fi
}
mscan2 "no validation before the gate (a rejected answer reaches it)" "$M_NO_VALIDATE" bad_answer_scan bare
mscan2 "no validation before the gate (the unscanned SBOM reaches it)" "$M_NO_VALIDATE" bad_answer_scan sbom
mscan2 "the store happens without the day re-check" "$M_NO_RECHECK" daycross_scan

# --- main-candidate-rescan.yml: the daily panel
extract main-candidate-rescan.yml panel-inspector "Amazon Inspector every image" > "$sim/rescan-raw.sh" || { bad "extract the rescan's Inspector step"; }
sandbox < "$sim/rescan-raw.sh" > "$sim/rescan-step.sh"
reset_rescan() { rm -rf "$sim/tmp"; mkdir -p "$sim/tmp"; }
scans() { ls "$sim"/tmp/panel/inspector/*/scan.json 2>/dev/null | wc -l | tr -d ' '; }
valid_scans() { for f in "$sim"/tmp/panel/inspector/*/scan.json; do python3 -c "import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d['sbom']['bomFormat']=='CycloneDX' else 1)" "$f" && echo y; done | wc -l | tr -d ' '; }
mksbom "$sim/sboms/cand-debug-amd64.json" urn:uuid:d1 2026-10-06T01:00:00Z v1 busybox@1.37.0 libc6@2.36 go:github.com/beorn7/perks@v1.0.1 gdb@13
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
mksbom "$sim/sboms/cand-fips-amd64.json" urn:uuid:f1 2026-10-06T01:00:00Z v1 busybox@1.37.0 libc6@2.36 go:github.com/beorn7/perks@v1.0.1 openssl@4
mksbom "$sim/sboms/cand-fips-arm64.json" urn:uuid:f2 2026-10-06T01:00:09Z v1 busybox@1.37.0 libc6@2.36 go:github.com/beorn7/perks@v1.0.1 openssl@4
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

# --- the rescan: the clock moves on between the response and the store
daycross_rescan() { # -> "rc calls stored-D stored-D+1 scans tally"
  reset_rescan; rm -f "$sim/flip"
  FAKE_VULN="CVE-2099-0001:busybox" FAKE_FLIP_FLAG="$sim/flip" run_step "${SCRIPT:-$sim/rescan-step.sh}" 2026-10-06 "" 2026-10-07; r=$?
  echo "$r $(calls) $(ls "$sim/tmp/inspector-cache/2026-10-06" 2>/dev/null | wc -l | tr -d ' ') $(ls "$sim/tmp/inspector-cache/2026-10-07" 2>/dev/null | wc -l | tr -d ' ') $(scans) $(tally_count)"
}
bad_answer_rescan() { # mode -> "rc scans stored"
  reset_rescan; FAKE_AWS_MODE="$1" run_step "${SCRIPT:-$sim/rescan-step.sh}" 2026-10-06; r=$?
  echo "$r $(scans) $(ls -A "$sim/tmp/inspector-cache" 2>/dev/null | wc -l | tr -d ' ')"
}
# --- the rescan across UTC midnight: after the first stored result the clock reads D+1
reset_rescan
run_step "$sim/rescan-step.sh" 2026-10-06 "" 2026-10-07; rc=$?
expect "rescan midnight: step exits 0, the later images do not reuse day D's entry (production x2, debug x1, fips x1 = 4 calls)" "0 4" "$rc $(calls)"
expect "rescan midnight: day D holds the first image's answer only; D+1 the rest" "1 3" "$(ls "$sim/tmp/inspector-cache/2026-10-06" | wc -l | tr -d ' ') $(ls "$sim/tmp/inspector-cache/2026-10-07" | wc -l | tr -d ' ')"
expect "rescan midnight: the tally has all six" "6 6" "$(scans) $(valid_scans)"

# --- the rescan: findings carried by a REUSED result reach the REAL panel tally
tally_count() { # -> number of findings (CVE-2099-0001) the tally attributes to Inspector
  python3 - "$root/bin/panel.py" "$root/.vex/fosterstack-cache.openvex.json" "$sim/tmp/panel" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("panel", sys.argv[1]); P = importlib.util.module_from_spec(spec); spec.loader.exec_module(P)
v = P.tally(sys.argv[3], P.load_vex(sys.argv[2]))
print(sum(1 for f in v["findings"] if f["id"] == "CVE-2099-0001" and "inspector" in f["seen_by"]))
PY
}
rescan_case() { # script-file -> "rc1 rc2 calls2 tally-findings-after-reuse"
  reset_rescan
  FAKE_VULN="CVE-2099-0001:busybox" run_step "$1" 2026-10-06; r1=$?
  t1=$(tally_count)
  run_step "$1" 2026-10-06; r2=$?
  echo "$r1 $r2 $(calls) $t1 $(tally_count)"
}
expect "rescan findings: a fresh run and a REUSED run (no call) both put the vulnerability into the tally for all six images" "0 0 0 6 6" "$(rescan_case "$sim/rescan-step.sh")"
mresc() { # name python-mutation
  mutate "$2" < "$sim/rescan-raw.sh" | sandbox > "$sim/rescan-mut.sh" || { bad "rescan mutation $1 did not apply"; return; }
  got=$(rescan_case "$sim/rescan-mut.sh")
  if [ "$got" != "0 0 0 6 6" ]; then ok "rescan mutation caught by the findings case: $1 ($got)"; else bad "rescan mutation NOT caught: $1"; fi
}
mresc "the reuse branch writes a fixed clean document" "$M_FIXED_CLEAN"
mresc "the reuse branch copies the SBOM instead of the findings" "$M_SBOM_RESCAN"

expect "rescan day crossing: the first response is NOT stored, the next images call again and store under D+1 only; every image still has its fresh findings in the tally (4 calls)" "0 4 0 3 6 6" "$(daycross_rescan)"
for m in bare sbom other; do
  expect "rescan a rejected ScanSbom answer ($m): no scan.json is left for the tally (did not run), nothing stored" "0 0 0" "$(bad_answer_rescan $m)"
done
mresc2() { # name mutation function-and-args...
  local name=$1 mut=$2; shift 2
  mutate "$mut" < "$sim/rescan-raw.sh" | sandbox > "$sim/rescan-mut.sh" || { bad "rescan mutation $name did not apply"; return; }
  want=$(SCRIPT="$sim/rescan-step.sh" "$@"); got=$(SCRIPT="$sim/rescan-mut.sh" "$@")
  if [ "$got" != "$want" ]; then ok "rescan mutation caught: $name ($got)"; else bad "rescan mutation NOT caught: $name"; fi
}
mut_def M_NO_VALIDATE_R <<'EOF'
import re
t = re.sub(r'if ! python3 bin/inspector-reuse\.py validate', 'if ! true', t, count=1)
EOF
mut_def M_NO_RECHECK_R <<'EOF'
t = t.replace('[ "$(date -u +%F)" != "${day}" ]', 'false', 1)
EOF
mresc2 "no validation (a rejected answer stays as scan.json)" "$M_NO_VALIDATE_R" bad_answer_rescan bare
mresc2 "the store happens without the day re-check" "$M_NO_RECHECK_R" daycross_rescan

# --- a name containing "@" cannot make one image reuse another's answer: both real call sites
python3 - "$sim" <<'PY'
import json, sys
sim = sys.argv[1]
base = [{"name": "libc6", "version": "2.36", "purl": "pkg:generic/libc6@2.36", "bom-ref": "b1"}]
for fn, comp in (("col1", {"name": "alpha@beta", "version": "1", "bom-ref": "b2"}), ("col2", {"name": "alpha", "version": "beta@1", "bom-ref": "b2"})):
    json.dump({"bomFormat": "CycloneDX", "components": base + [comp]}, open("%s/%s.json" % (sim, fn), "w"))
PY
kcol1=$(python3 "$prog" key "$sim/col1.json"); kcol2=$(python3 "$prog" key "$sim/col2.json")
collide_scan() { # script -> "rc calls"
  reset_scan; printf 'ghcr.io/fosterstack/cache:cand-production-amd64\n' > "$sim/tmp/refs.txt"
  cp "$sim/col1.json" "$sim/sboms/cand-production-amd64.json"
  run_step "${SCRIPT:-$sim/scan-step.sh}" 2026-10-06
  mkdir -p "$sim/tmp/inspector-cache/2026-10-06"; cp "$sim/tmp/inspector-cache/2026-10-06/$kcol1.findings.json" "$sim/tmp/inspector-cache/2026-10-06/$kcol2.findings.json"
  cp "$sim/col2.json" "$sim/sboms/cand-production-amd64.json"
  run_step "${SCRIPT:-$sim/scan-step.sh}" 2026-10-06; r=$?
  echo "$r $(calls)"
}
expect "scan.yml collision: col1's stored answer planted under col2's key is NOT reused for col2 (one ScanSbom call)" "0 1" "$(collide_scan)"
collide_rescan() {
  reset_rescan
  for img in production-amd64 production-arm64 debug-amd64 debug-arm64 fips-amd64 fips-arm64; do cp "$sim/col1.json" "$sim/sboms/cand-$img.json"; done
  run_step "${SCRIPT:-$sim/rescan-step.sh}" 2026-10-06
  mkdir -p "$sim/tmp/inspector-cache/2026-10-06"; cp "$sim/tmp/inspector-cache/2026-10-06/$kcol1.findings.json" "$sim/tmp/inspector-cache/2026-10-06/$kcol2.findings.json"
  for img in production-amd64 production-arm64 debug-amd64 debug-arm64 fips-amd64 fips-arm64; do cp "$sim/col2.json" "$sim/sboms/cand-$img.json"; done
  run_step "${SCRIPT:-$sim/rescan-step.sh}" 2026-10-06; r=$?
  echo "$r $(calls) $(scans)"
}
expect "rescan collision: col1's stored answer planted under col2's key is NOT reused for col2 (one call, then the other five reuse the fresh one; six scan.json)" "0 1 6" "$(collide_rescan)"
mksbom "$sim/sboms/cand-production-amd64.json" urn:uuid:p1 2026-10-06T01:00:00Z v1 busybox@1.37.0 libc6@2.36 go:github.com/beorn7/perks@v1.0.1
mksbom "$sim/sboms/cand-production-arm64.json" urn:uuid:p2 2026-10-06T01:00:09Z v1 busybox@1.37.0 libc6@2.36 go:github.com/beorn7/perks@v1.0.1
mksbom "$sim/sboms/cand-debug-amd64.json"      urn:uuid:d1 2026-10-06T01:00:00Z v1 busybox@1.37.0 libc6@2.36 go:github.com/beorn7/perks@v1.0.1 gdb@13
mksbom "$sim/sboms/cand-debug-arm64.json"      urn:uuid:d2 2026-10-06T01:00:09Z v1 busybox@1.37.0 libc6@2.36 go:github.com/beorn7/perks@v1.0.1 gdb@13
mksbom "$sim/sboms/cand-fips-amd64.json"       urn:uuid:f1 2026-10-06T01:00:00Z v1 busybox@1.37.0 libc6@2.36 go:github.com/beorn7/perks@v1.0.1 openssl@4
mksbom "$sim/sboms/cand-fips-arm64.json"       urn:uuid:f2 2026-10-06T01:00:09Z v1 busybox@1.37.0 libc6@2.36 go:github.com/beorn7/perks@v1.0.1 openssl@4

# --- the save step's day is read at save time: the extracted day step prints the clock's day at that moment
extract scan.yml scanner "Amazon Inspector - the UTC day at save time" > "$sim/saveday-raw.sh" 2>/dev/null || { bad "scan.yml has no save-time day step"; : > "$sim/saveday-raw.sh"; }
sandbox < "$sim/saveday-raw.sh" > "$sim/saveday.sh"
: > "$sim/out.txt"; ( cd "$sim/repo" && PATH="$sim/bin:$PATH" FAKE_DAY=2026-10-07 FAKE_CACHE="$sim/none" GITHUB_OUTPUT="$sim/out.txt" bash "$sim/saveday.sh" ) >/dev/null 2>&1
expect "scan.yml save-time day step: outputs the clock's day at that moment" "date=2026-10-07" "$(cat "$sim/out.txt")"
extract main-candidate-rescan.yml panel-inspector "Amazon Inspector - the UTC day at save time" > "$sim/saveday-raw.sh" 2>/dev/null || { bad "the rescan has no save-time day step"; : > "$sim/saveday-raw.sh"; }
sandbox < "$sim/saveday-raw.sh" > "$sim/saveday.sh"
: > "$sim/out.txt"; ( cd "$sim/repo" && PATH="$sim/bin:$PATH" FAKE_DAY=2026-10-07 FAKE_CACHE="$sim/none" GITHUB_OUTPUT="$sim/out.txt" bash "$sim/saveday.sh" ) >/dev/null 2>&1
expect "rescan save-time day step: outputs the clock's day at that moment" "date=2026-10-07" "$(cat "$sim/out.txt")"

# ---------------------------------------------------------------------------------------------------------------
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
norm = lambda s: " ".join((s or "").split())
FORKP = "(" + FORK + ")"
if which == "scan":
    triggers = {"pull_request": "", "push": {"branches": ["main"], "tags": ["v*"]}}
    IF_SCAN = "matrix.scanner == 'inspector'"
    IF_REST = IF_SCAN + " && " + FORKP
    IF_SDAY = "always() && matrix.scanner == 'inspector'"
    IF_SAVE = "always() && matrix.scanner == 'inspector' && steps.insp-scan.outputs.fresh != '' && steps.insp-scan.outputs.fresh != '0' && " + FORKP
    job, scan_name, marker = "scanner", "Amazon Inspector scan every loaded image", "python3 bin/inspector-gate.py"
    perms = {"top": {"contents": "read"}, "build": {"contents": "read", "id-token": "write", "attestations": "write", "packages": "write"},
             "assemble": {"contents": "read", "id-token": "write", "attestations": "write", "packages": "write"},
             "assemble-b": {"contents": "read", "id-token": "write", "attestations": "write", "packages": "write"},
             "artifact-acceptance": {"contents": "read", "packages": "read"}, "reproducibility": None, "scanners": None,
             "scanner": {"contents": "read", "id-token": "write"}, "scan": None}
else:
    triggers = {"schedule": [{"cron": "41 7 * * *"}], "workflow_dispatch": {}}
    IF_SCAN = None
    IF_REST = FORK
    IF_SDAY = "always()"
    IF_SAVE = "always() && steps.insp-scan.outputs.fresh != '' && steps.insp-scan.outputs.fresh != '0' && " + FORKP
    job, scan_name, marker = "panel-inspector", "Amazon Inspector every image", None
    perms = {"top": {"contents": "read"}, "build": {"contents": "read", "id-token": "write", "attestations": "write"},
             "assemble": {"contents": "read", "packages": "write", "id-token": "write", "attestations": "write"},
             "panel-grype": {"contents": "read"}, "panel-scout": {"contents": "read"},
             "scout-root-cause": {"contents": "read", "packages": "write"}, "panel-inspector": {"contents": "read", "id-token": "write"},
             "panel-google": {"contents": "read", "id-token": "write"}, "panel": {"contents": "read", "issues": "write"},
             "scanner-reports": {"contents": "read"}, "manifests": None, "rescan": {"contents": "read", "issues": "write", "packages": "read"}}
# the triggers, exactly: a PR's saved entry is never restored by a main or tag run (the cache scope is the ref)
if d.get("on") != triggers:
    bad.append("the workflow triggers changed: %s" % json.dumps(d.get("on")))
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
sdays = idx(lambda s: s.get("id") == "insp-save-day")
rest = idx(lambda s: str(s.get("uses", "")).startswith("actions/cache/restore@"))
save = idx(lambda s: str(s.get("uses", "")).startswith("actions/cache/save@"))
scan = idx(lambda s: scan_name in (s.get("name") or "") and s.get("run"))
if len(sdays) != 1:
    bad.append("there is not exactly one save-time day step")
    print("; ".join(bad)); sys.exit(1)
if len(dates) != 1 or len(rest) != 1 or len(save) != 1 or len(scan) != 1:
    bad.append("the call-site job lacks exactly one date step, restore, scan step and save: %s" % [dates, rest, save, scan])
    print("; ".join(bad)); sys.exit(1)
dt, rs, sv, sc, sd = steps[dates[0]], steps[rest[0]], steps[save[0]], steps[scan[0]], steps[sdays[0]]
if not (dates[0] < rest[0] < scan[0] < sdays[0] < save[0] and sdays[0] == save[0] - 1):
    bad.append("order must be date, restore, scan, save-time day (just before the save), save")
DAYRUN = "echo \"date=$(date -u +%F)\" >> \"$GITHUB_OUTPUT\""
if norm(sd.get("run")) != norm(DAYRUN) or norm(sd.get("if")) != norm(IF_SDAY) or sd.get("uses"):
    bad.append("the save-time day step is not exactly the UTC day under %r: %r %r" % (IF_SDAY, sd.get("if"), sd.get("run")))
if norm(dt.get("run")) != norm(DAYRUN) or (dt.get("if") is None) != (IF_SCAN is None) or (IF_SCAN is not None and norm(dt.get("if")) != norm(IF_SCAN)):
    bad.append("the start-of-run day step changed: %r %r" % (dt.get("if"), dt.get("run")))
if norm(sc.get("if")) != norm(IF_SCAN) and not (IF_SCAN is None and sc.get("if") is None):
    bad.append("the scan step's if changed: %r" % sc.get("if"))
if norm(rs.get("if")) != norm(IF_REST):
    bad.append("restore's whole if is not exactly %r: %r" % (IF_REST, rs.get("if")))
if norm(sv.get("if")) != norm(IF_SAVE):
    bad.append("save's whole if is not exactly %r: %r" % (IF_SAVE, sv.get("if")))
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
SDATE = "${{ steps.insp-save-day.outputs.date }}"
if sw.get("key") != "inspector-%s-${{ github.run_id }}" % SDATE:
    bad.append("save key is not inspector-<day at save time>-<run>: %r" % sw.get("key"))
if set(rw) - {"path", "key", "restore-keys"} or set(sw) - {"path", "key"}:
    bad.append("unexpected inputs on restore/save: %s %s" % (sorted(rw), sorted(sw)))
if sc.get("id") != "insp-scan":
    bad.append("the scan step id is not insp-scan")
if "INSPECTOR_DAY" in (sc.get("env") or {}) or "INSPECTOR_DAY" in (sc.get("run") or ""):
    bad.append("the scan step takes a day fixed before the loop; the day is read at each decision and each store")
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
    # the day is read from the clock at each decision, used for the store only if the clock still reads it after the call
    if len(re.findall(r'(?m)^\s*day=\$\(date -u \+%F\)\s*$', run)) != 1:
        bad.append("the day is not read from the clock exactly once per image, at the decision")
    if not re.search(r'inspector-reuse\.py decide \S+ "\$\{day\}" ', run):
        bad.append("decide does not use the day read at this decision")
    if not re.search(r'inspector-reuse\.py store \S+ "\$\{day\}" ', run):
        bad.append("store does not use the day read at the decision")
    vpos, rpos = run.find('inspector-reuse.py validate'), run.find('[ "$(date -u +%F)" != "${day}" ]')
    dpos = run.find('day=$(date -u +%F)')
    if run.count('inspector-reuse.py validate') != 1 or run.count('[ "$(date -u +%F)" != "${day}" ]') != 1:
        bad.append("validate and the day re-check must each appear exactly once")
    elif not (dpos < dc < call < vpos < rpos < st):
        bad.append("the order day < decide < ScanSbom < validate < day re-check < store is not held: %s" % [dpos, dc, call, vpos, rpos, st])
    elif not re.search(r'if ! python3 bin/inspector-reuse\.py validate "[^"]+" "[^"]+"; then', run):
        bad.append("validate is not an if ! guard")
    if marker and ('python3 bin/inspector-gate.py "${tag}" "/tmp/insp/${tag}.sbom.json" "/tmp/insp/${key}.findings.json" .vex/fosterstack-cache.openvex.json') not in run:
        bad.append("the gate is not fed the SBOM and this inventory's findings file")
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
export FORKX
mut_def W_RESTORE_OR_TRUE <<'EOF'
import os
f = os.environ["FORKX"]; t = t.replace(f, f + " || true", 1)
EOF
mut_def W_SAVE_OR_TRUE <<'EOF'
import os
f = os.environ["FORKX"]; i = t.rfind(f); t = t[:i + len(f)] + " || true" + t[i + len(f):]
EOF
mut_def W_SAVE_NO_PARENS <<'EOF'
import os
f = os.environ["FORKX"]; i = t.rfind("&& (" + f + ")"); t = t[:i] + "&& " + f + t[i + len(f) + 5:]
EOF
mut_def W_RESTORE_NO_SCANNER <<'EOF'
t = t.replace("if: matrix.scanner == 'inspector' && (github.event_name", "if: (github.event_name", 1)
EOF
mut_def W_SAVE_ALWAYS_OR <<'EOF'
import re
t = re.sub(r"if: always\(\) && ((?:matrix\.scanner == 'inspector' && )?steps\.insp-scan\.outputs\.fresh)", r"if: always() || \1", t, count=1)
EOF
mut_def W_PR_TARGET_TRIGGER <<'EOF'
import re
t = re.sub(r"(?m)^  pull_request:", "  pull_request_target:", t, count=1)
EOF
mut_def W_PUSH_TRIGGER_ADDED <<'EOF'
t = t.replace("  workflow_dispatch: {}", "  workflow_dispatch: {}\n  push:\n    branches: [main]", 1)
EOF
mut_def W_PR_TARGET_IN_IF <<'EOF'
t = t.replace("github.event_name != 'pull_request' ||", "github.event_name != 'pull_request_target' ||", 1)
EOF
mut_def W_GATE_UNSCANNED <<'EOF'
t = t.replace('"/tmp/insp/${key}.findings.json" .vex', '"/tmp/insp/${tag}.sbom.json" .vex', 1)
EOF
mut_def W_DECIDE_DAY_ONCE <<'EOF'
t = t.replace('day=$(date -u +%F)', 'day=2000-01-01', 1)
EOF
mut_def W_STORE_DAY_ONCE <<'EOF'
import re
t = re.sub(r'(inspector-reuse\.py store \S+ )"\$\{day\}"', r'\1"$(date -u +%F)"', t, count=1)
EOF
mut_def W_NO_RECHECK <<'EOF'
t = t.replace('[ "$(date -u +%F)" != "${day}" ]', 'false', 1)
EOF
mut_def W_NO_VALIDATE <<'EOF'
t = t.replace('inspector-reuse.py validate', 'true', 1)
EOF
mut_def W_VALIDATE_AFTER_STORE <<'EOF'
import re
t = t.replace('inspector-reuse.py validate', 'inspector-reuse.py store /tmp/x /tmp/y z w; python3 bin/inspector-reuse.py validate', 1)
EOF
mut_def W_SAVE_KEY_START_DAY <<'EOF'
t = t.replace("key: inspector-${{ steps.insp-save-day.outputs.date }}-${{ github.run_id }}", "key: inspector-${{ steps.insp-date.outputs.date }}-${{ github.run_id }}", 1)
EOF
mut_def W_SAVE_DAY_STEP_GONE <<'EOF'
t = t.replace("id: insp-save-day", "id: insp-save-dayx", 1)
EOF
mut_def W_INSPECTOR_DAY_BACK <<'EOF'
t = t.replace("      - name: Amazon Inspector scan every loaded image\n", "      - name: Amazon Inspector scan every loaded image\n        env:\n          INSPECTOR_DAY: x\n", 1) if "scan every loaded" in t else t.replace("        id: insp-scan\n", "        id: insp-scan\n        env:\n          INSPECTOR_DAY: x\n", 1)
EOF
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
  wf "$f" "$k" save-key-without-date bad "t = t.replace('key: inspector-\${{ steps.insp-save-day.outputs.date }}-\${{ github.run_id }}\n', 'key: inspector-\${{ github.run_id }}\n', 1)"
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
  wf "$f" "$k" restore-if-or-true bad "$W_RESTORE_OR_TRUE"
  wf "$f" "$k" save-if-or-true bad "$W_SAVE_OR_TRUE"
  wf "$f" "$k" save-fork-parentheses-removed bad "$W_SAVE_NO_PARENS"
  wf "$f" "$k" save-if-always-or bad "$W_SAVE_ALWAYS_OR"
  wf "$f" "$k" pull-request-target-in-the-if bad "$W_PR_TARGET_IN_IF"
  wf "$f" "$k" day-not-read-at-the-decision bad "$W_DECIDE_DAY_ONCE"
  wf "$f" "$k" day-recheck-removed bad "$W_NO_RECHECK"
  wf "$f" "$k" validate-removed bad "$W_NO_VALIDATE"
  wf "$f" "$k" a-store-before-validate bad "$W_VALIDATE_AFTER_STORE"
  wf "$f" "$k" store-day-captured-once bad "$W_STORE_DAY_ONCE"
  wf "$f" "$k" save-key-uses-the-start-of-run-day bad "$W_SAVE_KEY_START_DAY"
  wf "$f" "$k" save-day-step-gone bad "$W_SAVE_DAY_STEP_GONE"
  wf "$f" "$k" a-fixed-day-env-back bad "$W_INSPECTOR_DAY_BACK"
  wf "$f" "$k" trigger-added-or-changed bad "$([ "$k" = scan ] && echo "$W_PR_TARGET_TRIGGER" || echo "$W_PUSH_TRIGGER_ADDED")"
  if [ "$k" = scan ]; then
    wf "$f" "$k" restore-without-the-inspector-condition bad "$W_RESTORE_NO_SCANNER"
    wf "$f" "$k" gate-fed-the-unscanned-sbom bad "$W_GATE_UNSCANNED"
  fi
done
# the gate is still fed after the call site, and the tally still reads the result
wf scan.yml scan gate-before-call bad "t = t.replace('python3 bin/inspector-gate.py', 'true bin/inspector-gate.py', 1) + '\n# python3 bin/inspector-gate.py'"

echo "inspector-reuse: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
