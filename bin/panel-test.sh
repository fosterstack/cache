#!/usr/bin/env bash
# proves: REQ-SCAN-003-AC1, REQ-SCAN-003-AC2, REQ-SCAN-003-AC3, REQ-SCAN-004-AC2, REQ-SCAN-005-AC1, REQ-SCAN-005-AC2, REQ-SCAN-006-AC1, REQ-SCAN-009-AC5, REQ-SCAN-010-AC3, REQ-REL-004-AC3
# The scanner panel's tally (bin/panel.py; scanner-panel rules 3-6, ratified Oct 2), offline: each scanner's
# real output shape per image, written as fixtures. Asserts the package counts (zero = did not run), the quorum
# per image, VEX filtering for Inspector and Google, the merge into one finding "seen by N of M", reporting
# only at two or more scanners, and that unique findings are only listed for the auditor (rule 9, Oct 3).
set -euo pipefail
TMPDIR=$(mktemp -d); export TMPDIR; trap 'rm -rf "$TMPDIR"' EXIT  # python tempfile and mktemp dirs all live under this one, removed on exit
here=$(cd "$(dirname "$0")" && pwd)
python3 - "$here/panel.py" "$here/../.vex/fosterstack-cache.openvex.json" <<'PY'
import importlib.util, json, os, shutil, sys, tempfile
spec = importlib.util.spec_from_file_location("panel", sys.argv[1]); P = importlib.util.module_from_spec(spec); spec.loader.exec_module(P)
VEX = sys.argv[2]
passed = failed = 0
def check(name, ok, got=""):
    global passed, failed
    if ok: passed += 1; print("ok:", name)
    else: failed += 1; print("FAIL:", name, "->", got)

IMAGES = ["%s-%s" % (v, a) for v in ("production", "fips") for a in ("amd64", "arm64")]
def W(d, name, obj):
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "w") as f:
        f.write(obj if isinstance(obj, str) else json.dumps(obj))

def grype(d, pkgs, vulns):     # CycloneDX from `grype --vex ... -o cyclonedx-json` (VEX already applied by grype)
    comps = [{"bom-ref": "r%d" % i, "name": n, "version": v, "purl": "pkg:generic/%s@%s" % (n, v)} for i, (n, v) in enumerate(pkgs)]
    ref = {(c["name"], c["version"]): c["bom-ref"] for c in comps}
    files = [{"bom-ref": "f%d" % i, "type": "file", "name": "/usr/lib/f%d" % i} for i in range(5)] if pkgs else []
    W(d, "result.cdx.json", {"bomFormat": "CycloneDX", "components": comps + files,
      "vulnerabilities": [{"id": c, "affects": [{"ref": ref[(n, v)]}]} for c, n, v in vulns]})
def scout(d, pkgs, vulns):     # `docker scout sbom --format json` + `docker scout cves --format gitlab --vex-location`
    W(d, "sbom.json", {"artifacts": [{"name": n, "version": v, "purl": "pkg:generic/%s@%s" % (n, v)} for n, v in pkgs]})
    W(d, "cves.json", {"vulnerabilities": [{"identifiers": [{"type": "cve", "value": c}],
      "location": {"dependency": {"package": {"name": n}, "version": v}}} for c, n, v in vulns]})
def inspector(d, pkgs, vulns): # inspector-sbomgen CycloneDX + the ScanSbom answer (no VEX: our pipeline filters)
    comps = [{"bom-ref": "c%d" % i, "name": n, "version": v, "purl": "pkg:generic/%s@%s" % (n, v)} for i, (n, v) in enumerate(pkgs)]
    ref = {(c["name"], c["version"]): c["bom-ref"] for c in comps}
    W(d, "sbom.cdx.json", {"bomFormat": "CycloneDX", "components": comps})
    W(d, "scan.json", {"sbom": {"bomFormat": "CycloneDX", "components": comps,
      "vulnerabilities": [{"id": c, "affects": [{"ref": ref[(n, v)]}]} for c, n, v in vulns]}})
def google(d, pkgs, vulns):    # the package list gcloud sent + `list-vulnerabilities` (no VEX: our pipeline filters)
    W(d, "packages.json", [{"package": n, "version": v, "packageType": "OS"} for n, v in pkgs])
    W(d, "vulns.json", [{"noteName": "projects/goog-vulnz/notes/" + c, "vulnerability": {"shortDescription": c,
      "packageIssue": [{"affectedPackage": n, "affectedVersion": {"fullName": v}}]}} for c, n, v in vulns])
WRITE = {"grype": grype, "scout": scout, "inspector": inspector, "google": google}

BASE = [("tzdata", "2026c"), ("busybox", "1.37.0"), ("golang.org/x/sys", "0.47.0")]
def tree(spec=None, skip=()):
    """spec: {(scanner, image): [vulns]}; every expected (scanner, image) gets BASE packages unless skipped."""
    root = tempfile.mkdtemp()
    for s, imgs in P.EXPECTED.items():
        for img in imgs:
            if (s, img) in skip or s in skip:
                continue
            WRITE[s](os.path.join(root, s, img), BASE, (spec or {}).get((s, img), []))
    return root
def judge(root):
    return P.tally(root, P.load_vex(VEX))

# --- rule 1 shape the judge expects (the workflow wiring test checks the jobs)
check("the expected set: Grype, Scout, Inspector on all four images (production and fips, each on both architectures); Google on the two amd64 images only",
      all(sorted(P.EXPECTED[s]) == sorted(IMAGES) for s in ("grype", "scout", "inspector"))
      and sorted(P.EXPECTED["google"]) == sorted(i for i in IMAGES if i.endswith("amd64")), P.EXPECTED)

# --- rule 3: package counts; zero / empty / unparsable = did not run
r = tree(); v = judge(r)
check("package counts are reported per scanner per image, packages only (Grype's file components are not packages)", v["images"]["production-amd64"]["counts"] == {"google": 3, "grype": 3, "inspector": 3, "scout": 3}, v["images"]["production-amd64"])
r = tree(); W(os.path.join(r, "grype", "production-amd64"), "result.cdx.json", {"bomFormat": "CycloneDX",
    "components": [{"bom-ref": "f1", "type": "file", "name": "/etc/passwd"}]})   # files but no package: did not run
W(os.path.join(r, "scout", "production-amd64"), "sbom.json", "")
W(os.path.join(r, "inspector", "production-amd64"), "scan.json", "{not json")
os.remove(os.path.join(r, "google", "production-amd64", "vulns.json"))
v = judge(r)
check("zero packages, an empty file, an unparsable file and a missing answer are 'did not run', never clean",
      sorted(v["images"]["production-amd64"]["did_not_run"]) == ["google", "grype", "inspector", "scout"], v["images"]["production-amd64"])
# --- rule 3: quorum
check("an amd64 image with no scanner left does not count", v["images"]["production-amd64"]["counts_for_day"] is False)
r = tree(skip={("google", "production-amd64")}); v = judge(r)
check("an amd64 image with 3 of 4 counts", v["images"]["production-amd64"]["counts_for_day"] is True)
check("a scanner that did not run fails the run (exit 2) even when the image keeps its quorum",
      v["exit"] == 2 and v["scanner_failures"] == ["google on production-amd64"] and not v["not_counted"], (v["exit"], v["scanner_failures"]))
r = tree(); W(os.path.join(r, "scout", "fips-amd64"), "cves.json", {})
W(os.path.join(r, "grype", "fips-amd64"), "result.cdx.json", {"components": [{"purl": "pkg:generic/a@1", "name": "a"}]})
W(os.path.join(r, "inspector", "fips-amd64"), "sbom.cdx.json", {"components": [{"purl": "pkg:generic/a@1", "name": "a"}]})
W(os.path.join(r, "google", "fips-amd64"), "packages.json", [{}, {"package": ""}])
v = judge(r)
check("structurally incomplete answers (no bomFormat, empty package records) are did not run",
      v["images"]["fips-amd64"]["did_not_run"] == ["google", "grype", "inspector", "scout"], v["images"]["fips-amd64"])
check("an incomplete Scout answer (no vulnerabilities list) is did not run", "scout" in v["images"]["fips-amd64"]["did_not_run"], v["images"]["fips-amd64"])
r = tree(skip={("scout", "production-arm64")}); v = judge(r)
check("an arm64 image with 2 of its 3 does not count (all three must run)", v["images"]["production-arm64"]["counts_for_day"] is False, v["images"]["production-arm64"])
check("an image that does not count fails the run (exit 2), never clean", v["exit"] == 2 and "production-arm64" in v["not_counted"], (v["exit"], v.get("not_counted")))
r = tree(); v = judge(r)
check("all four images counted and no finding -> clean (exit 0)", v["exit"] == 0 and not v["not_counted"], v["exit"])

# --- rule 4: Inspector and Google results are filtered against the VEX; Grype and Scout arrive filtered
covered = ("CVE-2025-60876", "busybox", "1.37.0")      # covered by our published VEX
r = tree({("inspector", "production-amd64"): [covered, ("CVE-2099-0001", "tzdata", "2026c")],
          ("google", "production-amd64"): [covered, ("CVE-2099-0001", "tzdata", "2026c")]}); v = judge(r)
ids = sorted((f["id"], f["seen_by"] and tuple(f["seen_by"])) for f in v["findings"])
check("Inspector's and Google's VEX-covered finding is dropped; the uncovered one remains, seen by both",
      ids == [("CVE-2099-0001", ("google", "inspector"))], ids)
check("the dropped finding is recorded as covered by the VEX", any(c["id"] == "CVE-2025-60876" for c in v["vex_covered"]), v["vex_covered"])

# --- rule 4 with the auditor's per-image statements: a statement scoped to one image filters only that image, and
# its encoded purl version (%2B) matches the decoded version the scanner reports
vexf = os.path.join(tempfile.mkdtemp(), "v.json")
json.dump({"@context": "x", "statements": [{"vulnerability": {"name": "CVE-2099-0009"}, "status": "not_affected",
    "products": [{"@id": "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache&variant=production&arch=amd64",
                  "subcomponents": [{"@id": "pkg:deb/debian/tzdata@2026%63?arch=all"}]}]}]}, open(vexf, "w"))   # %63 = c
row = ("CVE-2099-0009", "tzdata", "2026c")
r = tree({(s_, img): [row] for s_ in ("inspector", "google") for img in ("production-amd64", "fips-amd64")})
v = P.tally(r, P.load_vex(vexf))
check("a per-image statement filters only its own image (Codex r2 B2) and matches the decoded version (r2 R9)",
      [f["image"] for f in v["findings"]] == ["fips-amd64"] and [c["image"] for c in v["vex_covered"]] == ["production-amd64", "production-amd64"],
      ([f["image"] for f in v["findings"]], v["vex_covered"]))

# --- rules 5 and 6: merge, seen by N of M, report at two or more
r = tree({("inspector", "production-amd64"): [covered, ("CVE-2099-0001", "tzdata", "2026c")],
          ("google", "production-amd64"): [covered, ("CVE-2099-0001", "tzdata", "2026c")]}); v = judge(r)
f = v["findings"][0]
check("a finding carries the exact package identity a scanner gave (for a VEX statement scoped to it)",
      f["purls"] == ["pkg:generic/tzdata@2026c"], f.get("purls"))
check("one finding per CVE + package + version per image, 'seen by 2 of 4'", f["seen_by"] == ["google", "inspector"] and f["of"] == 4 and f["image"] == "production-amd64", f)
check("seen by two or more -> reported (the tracking issue), exit 1", f["status"] == "report" and v["exit"] == 1 and "CVE-2099-0001" in v["issue"], (f["status"], v["exit"]))
# the same package named the way each scanner names it is one finding: Grype's purl carries the distro
# namespace and an escaped version (pkg:deb/debian/libc-bin@2.36-9%2Bdeb12u1), Google names libc-bin 2.36-9+deb12u1
r = tree()
d = os.path.join(r, "grype", "production-amd64")
W(d, "result.cdx.json", {"bomFormat": "CycloneDX", "components": [
    {"bom-ref": "a", "name": "libc-bin", "version": "2.36-9+deb12u1", "purl": "pkg:deb/debian/libc-bin@2.36-9%2Bdeb12u1?arch=amd64&distro=debian-12"},
    {"bom-ref": "b", "name": "golang.org/x/net", "version": "v0.1.0", "purl": "pkg:golang/golang.org/x/net@v0.1.0"}],
    "vulnerabilities": [{"id": "CVE-2023-4911", "affects": [{"ref": "a"}]}, {"id": "GO-2099-0001", "affects": [{"ref": "b"}]}]})
google(os.path.join(r, "google", "production-amd64"), BASE, [("CVE-2023-4911", "libc-bin", "2.36-9+deb12u1"), ("go-2099-0001", "golang.org/x/net", "0.1.0")])
v = judge(r)
check("one finding across scanners' namings (distro namespace, escaped version, v-prefix, id case) -> seen by 2",
      sorted((f["id"], len(f["seen_by"])) for f in v["findings"]) == [("CVE-2023-4911", 2), ("GO-2099-0001", 2)], [(f["id"], f["package"], f["seen_by"]) for f in v["findings"]])
lib = [f for f in v["findings"] if f["id"] == "CVE-2023-4911"][0]
check("each scanner keeps its OWN package URL in its details; a scanner that reported none has none (handoff 0601: never borrowed)",
      lib["details"]["grype"].get("purl") == "pkg:deb/debian/libc-bin@2.36-9%2Bdeb12u1?arch=amd64&distro=debian-12" and "purl" not in lib["details"]["google"]
      and lib["purls"] == [lib["details"]["grype"]["purl"]], (lib["details"], lib["purls"]))
# one scanner naming one finding twice with two package URLs: its details keep the FIRST it reported, the finding keeps both
r = tree(); d = os.path.join(r, "grype", "debug-amd64")
W(d, "result.cdx.json", {"bomFormat": "CycloneDX", "components": [
    {"bom-ref": "a", "name": "libc-bin", "version": "2.36-9", "purl": "pkg:deb/debian/libc-bin@2.36-9?arch=amd64"},
    {"bom-ref": "b", "name": "libc-bin", "version": "2.36-9", "purl": "pkg:deb/debian/libc-bin@2.36-9?arch=all"}],
    "vulnerabilities": [{"id": "CVE-2023-4911", "affects": [{"ref": "a"}, {"ref": "b"}]}]})
v = judge(r); lib2 = [f for f in v["findings"] if f["id"] == "CVE-2023-4911"][0]
check("a scanner that names one finding with two package URLs keeps the first in its details; the finding lists both",
      lib2["details"]["grype"].get("purl") == "pkg:deb/debian/libc-bin@2.36-9?arch=amd64" and len(lib2["purls"]) == 2, (lib2["details"], lib2["purls"]))
# a scanner's package URL the verdict's grammar refuses is dropped (the finding still counts), so the tally never writes a verdict the auditor cannot read
r = tree(); d = os.path.join(r, "grype", "debug-amd64")
W(d, "result.cdx.json", {"bomFormat": "CycloneDX", "components": [
    {"bom-ref": "a", "name": "openssl", "version": "3.0.1", "purl": "pkg:deb/debian/openssl@3.0.1?arch="}],
    "vulnerabilities": [{"id": "CVE-2099-0777", "affects": [{"ref": "a"}]}]})
v = judge(r); bad = [f for f in v["findings"] if f["id"] == "CVE-2099-0777"][0]
check("a package URL outside the grammar is dropped from the finding and from the scanner's details; the finding is still reported",
      "purl" not in bad["details"]["grype"] and bad["purls"] == [] and bad["seen_by"] == ["grype"], (bad["details"], bad["purls"]))
BADPURL_ROOT = r
r = tree({("scout", "fips-arm64"): [("CVE-2099-0002", "tzdata", "2026c")]}); v = judge(r)
f = v["findings"][0]
check("a unique finding never reaches the issue; it is listed for the auditor, and alone does not fail the run",
      f["unique"] and f["of"] == 3 and f["status"] == "unique" and v["unique"] == [f] and not v["issue"] and v["exit"] == 0, (f, v["issue"], v["exit"]))
check("the rescan judges no unique finding (rule 9, owner Oct 3): no audit, no verdict, no history",
      not any(k in f for k in ("audits", "why", "path")) and not any(k in v for k in ("judgments", "misses", "log", "vex_proposals", "audit_errors")), sorted(v))

# --- rule 3 for Google: its package count is the list gcloud sent (from the --log-http request body)
log = """==== request start ====
uri: https://ondemandscanning.googleapis.com/v1/projects/p/locations/us/scans:analyzePackages?alt=json
Authorization: --- Token Redacted ---
== body start ==
{"packages": [{"os": "debian", "osVersion": "12", "package": "tzdata", "version": "2026c", "packageType": "OS"},
 {"package": "stdlib", "version": "go1.26.4", "packageType": "GO_STDLIB"}], "resourceUri": "x"}
== body end ==
==== request end ====
---- response start ----
{"name": "op"}
"""
got = P.google_packages(log)
check("Google's package count is read from the AnalyzePackages request it was sent", [p["package"] for p in got] == ["tzdata", "stdlib"], got)
check("a log with no request body gives no packages (did not run)", P.google_packages("==== request start ====\nnothing") == [], "")

# --- 0600 option A (PR 2a): each scanner's own severity, fixed version and aliases travel in the verdict, per scanner, and a field the
# scanner does not report is ABSENT, never guessed. Shapes follow the vendors' documented schemas (CycloneDX 1.4+ ratings/references/
# affects.versions; GitLab dependency-scanning for Scout; Container Analysis PackageIssue for Google); no retained run has a finding, so
# the first real finding is the live proof of the key names.
check("severity names are normalised and an unknown one is absent", [P.norm_severity(x) for x in ("HIGH", "Critical", "moderate", "MINIMAL", "Info", "unknown", "", None, 3)]
      == ["high", "critical", "medium", "negligible", "negligible", None, None, None, None], "")
def put(d, name, obj):
    W(d, name, obj)
rich = {"id": "CVE-2099-0100", "ratings": [{"severity": "medium"}, {"severity": "high"}, {"severity": "info"}],
        "references": [{"id": "GHSA-aaaa-bbbb-cccc", "source": {"name": "GitHub"}}, {"id": "CVE-2099-0100"}],
        "affects": [{"ref": "r0", "versions": [{"version": "2026c", "status": "affected"}, {"version": "2026d", "status": "unaffected"}]}]}
bare = {"id": "CVE-2099-0101", "affects": [{"ref": "r0"}]}
gd = os.path.join(tempfile.mkdtemp(), "g")
put(gd, "result.cdx.json", {"bomFormat": "CycloneDX", "components": [{"bom-ref": "r0", "name": "tzdata", "version": "2026c", "purl": "pkg:generic/tzdata@2026c"}],
                            "vulnerabilities": [rich, bare]})
n_, found_ = P.read_grype(gd)
ex = {t[0]: t[4] for t in found_}
check("Grype's CycloneDX: highest rating and reference ids other than its own; a bare vulnerability has no details",
      ex["CVE-2099-0100"] == {"severity": "high", "aliases": ["GHSA-aaaa-bbbb-cccc"]} and ex["CVE-2099-0101"] == {}, ex)
check("Grype: a CycloneDX 'unaffected' version says which versions are not affected, not that it is the fix, so no fixed version is recorded",
      "fixed_version" not in ex["CVE-2099-0100"], ex)
idir = os.path.join(tempfile.mkdtemp(), "i")
put(idir, "sbom.cdx.json", {"bomFormat": "CycloneDX", "components": [{"bom-ref": "r0", "name": "tzdata", "version": "2026c", "purl": "pkg:generic/tzdata@2026c"}]})
put(idir, "scan.json", {"sbom": {"bomFormat": "CycloneDX", "components": [{"bom-ref": "r0", "name": "tzdata", "version": "2026c", "purl": "pkg:generic/tzdata@2026c"}],
                                 "vulnerabilities": [rich, bare]}})
kevv = {"id": "CVE-2099-0108", "ratings": [{"severity": "high"}, {"source": {"name": "CISA KEV Catalog", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"}, "score": 1, "method": "other", "justification": "Listed in CISA KEV"}], "affects": [{"ref": "r0"}]}
negv = {"id": "CVE-2099-0109", "ratings": [{"severity": "none"}], "affects": [{"ref": "r0"}]}
nokev = {"id": "CVE-2099-0110", "ratings": [{"severity": "low"}, {"source": {"name": "CISA KEV Catalog"}, "method": "other", "justification": "something else"}], "affects": [{"ref": "r0"}]}
put(gd, "result.cdx.json", {"bomFormat": "CycloneDX", "components": [{"bom-ref": "r0", "name": "tzdata", "version": "2026c", "purl": "pkg:generic/tzdata@2026c"}],
                            "vulnerabilities": [rich, bare, kevv, negv, nokev]})
ex = {t[0]: t[4] for t in P.read_grype(gd)[1]}
check("Grype: its CISA KEV rating (method other, 'Listed in CISA KEV') is known-exploited; a different CISA justification is not; CycloneDX 'none' is negligible",
      ex["CVE-2099-0108"] == {"severity": "high", "known_exploited": True} and ex["CVE-2099-0109"] == {"severity": "negligible"}
      and ex["CVE-2099-0110"] == {"severity": "low"}, (ex["CVE-2099-0108"], ex["CVE-2099-0109"], ex["CVE-2099-0110"]))
misv = {"id": "CVE-2099-0111", "ratings": [{}, {"severity": None}, {"severity": "unknown"}, {"method": "EPSS", "score": 0.2}], "affects": [{"ref": "r0"}]}
negk = {"id": "CVE-2099-0112", "ratings": [{"severity": "low"}, {"source": {"name": "CISA KEV Catalog"}, "method": "other", "severity": "critical", "justification": "Not listed in CISA KEV"}], "affects": [{"ref": "r0"}]}
srck = {"id": "CVE-2099-0113", "ratings": [{"severity": "low"}, {"source": {"name": "someone"}, "method": "other", "severity": "critical", "justification": "Listed in CISA KEV"}], "affects": [{"ref": "r0"}]}
put(gd, "result.cdx.json", {"bomFormat": "CycloneDX", "components": [{"bom-ref": "r0", "name": "tzdata", "version": "2026c", "purl": "pkg:generic/tzdata@2026c"}],
                            "vulnerabilities": [rich, bare, kevv, negv, nokev, misv, negk, srck]})
ex = {t[0]: t[4] for t in P.read_grype(gd)[1]}
check("Grype: a missing, null or unknown severity (and an EPSS rating without one) is ABSENT, not negligible",
      ex["CVE-2099-0111"] == {}, ex["CVE-2099-0111"])
check("Grype: the KEV marker is exactly 'Listed in CISA KEV' from source 'CISA KEV Catalog' (Grype v0.118.0's emitter, read from its source); 'Not listed in CISA KEV' or another source is not a marker (its rating then counts as a rating)",
      ex["CVE-2099-0112"] == {"severity": "critical"} and ex["CVE-2099-0113"] == {"severity": "critical"}, (ex["CVE-2099-0112"], ex["CVE-2099-0113"]))
inspv = {"id": "CVE-2099-0106", "ratings": [{"severity": "high"}], "affects": [{"ref": "r0"}],
         "properties": [{"name": "amazon:inspector:sbom_scanner:fixed_version:r0", "value": "2026d"},
                        {"name": "amazon:inspector:sbom_scanner:fixed_version:other", "value": "9.9"},
                        {"name": "amazon:inspector:sbom_scanner:cisa_kev_date_added", "value": "2026-01-01"}]}
put(idir, "scan.json", {"sbom": {"bomFormat": "CycloneDX", "components": [{"bom-ref": "r0", "name": "tzdata", "version": "2026c", "purl": "pkg:generic/tzdata@2026c"}],
                                 "vulnerabilities": [rich, bare, inspv]}})
ex = {t[0]: t[4] for t in P.read_inspector(idir)[1]}
check("Inspector's documented properties: the fixed version scoped to the affected component (another component's is ignored) and the CISA KEV flag",
      ex["CVE-2099-0106"] == {"severity": "high", "fixed_version": "2026d", "known_exploited": True}, ex["CVE-2099-0106"])
check("Inspector's ScanSbom (CycloneDX) is read the same way", ex["CVE-2099-0100"]["severity"] == "high" and ex["CVE-2099-0101"] == {}, ex)
sd = os.path.join(tempfile.mkdtemp(), "s")
put(sd, "sbom.json", {"artifacts": [{"name": "tzdata", "version": "2026c", "purl": "pkg:generic/tzdata@2026c"}]})
put(sd, "cves.json", {"vulnerabilities": [
    {"severity": "Medium", "identifiers": [{"type": "cve", "value": "CVE-2099-0102"}, {"type": "ghsa", "value": "GHSA-dddd-eeee-ffff"}],
     "location": {"dependency": {"package": {"name": "tzdata"}, "version": "2026c"}}},
    {"severity": "Unknown", "identifiers": [{"type": "cve", "value": "CVE-2099-0103"}],
     "location": {"dependency": {"package": {"name": "tzdata"}, "version": "2026c"}}}]})
ex = {t[0]: t[4] for t in P.read_scout(sd)[1]}
check("Scout's GitLab-format report: severity and the other identifiers as aliases; Unknown severity is absent",
      ex["CVE-2099-0102"] == {"severity": "medium", "aliases": ["GHSA-dddd-eeee-ffff"]} and ex["CVE-2099-0103"] == {}, ex)
gd2 = os.path.join(tempfile.mkdtemp(), "g2")
put(gd2, "packages.json", [{"package": "tzdata", "version": "2026c", "packageType": "OS"}])
put(gd2, "vulns.json", [{"noteName": "projects/goog-vulnz/notes/CVE-2099-0104", "vulnerability": {"shortDescription": "CVE-2099-0104", "severity": "CRITICAL",
    "packageIssue": [{"affectedPackage": "tzdata", "affectedVersion": {"fullName": "2026c"}, "fixedVersion": {"fullName": "2026d"}, "fixAvailable": True}]}},
    {"noteName": "projects/goog-vulnz/notes/CVE-2099-0105", "vulnerability": {"shortDescription": "CVE-2099-0105",
    "packageIssue": [{"affectedPackage": "tzdata", "affectedVersion": {"fullName": "2026c"}}]}}])
put(gd2, "vulns.json", [{"noteName": "projects/goog-vulnz/notes/CVE-2099-0104", "vulnerability": {"shortDescription": "CVE-2099-0104", "severity": "CRITICAL",
    "packageIssue": [{"affectedPackage": "tzdata", "affectedVersion": {"fullName": "2026c"}, "fixedVersion": {"fullName": "2026d"}, "fixAvailable": True}]}},
    {"noteName": "projects/goog-vulnz/notes/CVE-2099-0105", "vulnerability": {"shortDescription": "CVE-2099-0105",
    "packageIssue": [{"affectedPackage": "tzdata", "affectedVersion": {"fullName": "2026c"}}]}},
    {"noteName": "projects/goog-vulnz/notes/CVE-2099-0107", "vulnerability": {"shortDescription": "CVE-2099-0107", "severity": "CRITICAL", "risk": {"cisaKev": {}},
    "packageIssue": [{"affectedPackage": "tzdata", "affectedVersion": {"fullName": "2026c"}, "effectiveSeverity": "LOW"}]}}])
ex = {t[0]: t[4] for t in P.read_google(gd2)[1]}
check("Google: the package issue's effectiveSeverity wins over the occurrence severity (LOW, not CRITICAL), and risk.cisaKev is known-exploited",
      ex["CVE-2099-0107"] == {"severity": "low", "known_exploited": True}, ex["CVE-2099-0107"])
check("Google's PackageIssue: severity and the fixed version; no severity and no fix is absent",
      ex["CVE-2099-0104"] == {"severity": "critical", "fixed_version": "2026d"} and ex["CVE-2099-0105"] == {}, ex)
# the tally keeps each reporting scanner's own record; the same finding keeps both (the auditor takes the highest and the report shows each)
r = tree({("grype", "production-amd64"): [("CVE-2099-0200", "tzdata", "2026c")], ("google", "production-amd64"): [("CVE-2099-0200", "tzdata", "2026c")]})
W(os.path.join(r, "grype", "production-amd64"), "result.cdx.json", {"bomFormat": "CycloneDX",
  "components": [{"bom-ref": "r0", "name": "tzdata", "version": "2026c", "purl": "pkg:generic/tzdata@2026c"}] + [{"bom-ref": "p%d" % i, "name": "p%d" % i, "version": "1", "purl": "pkg:generic/p%d@1" % i} for i in range(3)],
  "vulnerabilities": [{"id": "CVE-2099-0200", "ratings": [{"severity": "high"}], "affects": [{"ref": "r0"}]}]})
W(os.path.join(r, "google", "production-amd64"), "vulns.json", [{"noteName": "projects/goog-vulnz/notes/CVE-2099-0200", "vulnerability": {"shortDescription": "CVE-2099-0200",
  "severity": "CRITICAL", "packageIssue": [{"affectedPackage": "tzdata", "affectedVersion": {"fullName": "2026c"}, "fixedVersion": {"fullName": "2026d"}}]}}])
v = judge(r)
f = [x for x in v["findings"] if x["id"] == "CVE-2099-0200"][0]
check("the verdict finding carries a details record per reporting scanner (Grype high, Google critical + fix), nothing for a scanner that did not report it; each scanner's own package URL where it reported one",
      f["details"] == {"grype": {"severity": "high", "purl": "pkg:generic/tzdata@2026c"}, "google": {"severity": "critical", "fixed_version": "2026d"}}, f.get("details"))
def rep(order):
    rr = tree({("grype", "production-amd64"): [("CVE-2099-0300", "tzdata", "2026c")]})
    comps = [{"bom-ref": "r0", "name": "tzdata", "version": "2026c", "purl": "pkg:generic/tzdata@2026c"}] + [{"bom-ref": "p%d" % i, "name": "p%d" % i, "version": "1", "purl": "pkg:generic/p%d@1" % i} for i in range(3)]
    vs = [{"id": "CVE-2099-0300", "ratings": [{"severity": sv}], "references": [{"id": al}], "affects": [{"ref": "r0"}]} for sv, al in order]
    W(os.path.join(rr, "grype", "production-amd64"), "result.cdx.json", {"bomFormat": "CycloneDX", "components": comps, "vulnerabilities": vs})
    return [x for x in judge(rr)["findings"] if x["id"] == "CVE-2099-0300"][0]["details"]["grype"]
a_ = rep([("low", "GHSA-1111-2222-3333"), ("critical", "GHSA-4444-5555-6666")]); b_ = rep([("critical", "GHSA-4444-5555-6666"), ("low", "GHSA-1111-2222-3333")])
check("a scanner that reports the same finding twice keeps the HIGHEST severity in either order and the union of its aliases",
      a_["severity"] == b_["severity"] == "critical" and a_["aliases"] == b_["aliases"] == ["GHSA-1111-2222-3333", "GHSA-4444-5555-6666"] or sorted(a_["aliases"]) == sorted(b_["aliases"]) == ["GHSA-1111-2222-3333", "GHSA-4444-5555-6666"] and a_["severity"] == b_["severity"] == "critical", (a_, b_))
check("every verdict finding has details for exactly its seen_by scanners", all(sorted(x["details"]) == sorted(x["seen_by"]) for x in v["findings"]), "")

# --- the auditor reads this verdict through one strict, closed validator (auditorlib/parsers.py, cache#466): it must accept every
# shape the tally really writes, or a real day would turn red; the opposite direction (refusals) is tested in auditor-matrix-test.sh
sys.path.insert(0, os.path.join(os.path.dirname(sys.argv[1]), "..", ".github", "agent", "bin"))
from auditorlib import parsers as PL
SCEN = {"clean": tree(), "two scanners report one finding": tree({("grype", "production-amd64"): [("CVE-2099-1", "tzdata", "2026c")],
                                                                   ("scout", "production-amd64"): [("CVE-2099-1", "tzdata", "2026c")]}),
        "one scanner only (unique)": tree({("inspector", "fips-arm64"): [("CVE-2099-2", "busybox", "1.37.0")]}),
        "google did not run": tree(skip=("google",)), "an image short of its quorum": tree(skip=("grype", "scout")),
        "a scanner's package URL outside the grammar": BADPURL_ROOT}
for name, root in SCEN.items():
    try:
        PL.validate_panel_verdict(json.loads(json.dumps(judge(root))))
        bad = ""
    except PL.ParseError as e:
        bad = str(e)
    check("the auditor's strict verdict validator accepts the tally's real output: %s" % name, bad == "", bad)

print("panel: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
PY
