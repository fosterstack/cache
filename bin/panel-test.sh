#!/usr/bin/env bash
# proves: REQ-SCAN-003-AC1, REQ-SCAN-003-AC2, REQ-SCAN-003-AC3, REQ-SCAN-004-AC2, REQ-SCAN-005-AC1, REQ-SCAN-005-AC2, REQ-SCAN-006-AC1, REQ-SCAN-009-AC5, REQ-SCAN-010-AC3, REQ-REL-004-AC3
# The scanner panel's tally (bin/panel.py; scanner-panel rules 3-6, ratified Oct 2), offline: each scanner's
# real output shape per image, written as fixtures. Asserts the package counts (zero = did not run), the quorum
# per image, VEX filtering for Inspector and Google, the merge into one finding "seen by N of M", reporting
# only at two or more scanners, and that unique findings are only listed for the auditor (rule 9, Oct 3).
set -euo pipefail
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

IMAGES = ["%s-%s" % (v, a) for v in ("production", "debug", "fips") for a in ("amd64", "arm64")]
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
check("the expected set: Grype, Scout, Inspector on all six images; Google on the three amd64 images only",
      all(sorted(P.EXPECTED[s]) == sorted(IMAGES) for s in ("grype", "scout", "inspector"))
      and sorted(P.EXPECTED["google"]) == sorted(i for i in IMAGES if i.endswith("amd64")), P.EXPECTED)

# --- rule 3: package counts; zero / empty / unparsable = did not run
r = tree(); v = judge(r)
check("package counts are reported per scanner per image, packages only (Grype's file components are not packages)", v["images"]["debug-amd64"]["counts"] == {"google": 3, "grype": 3, "inspector": 3, "scout": 3}, v["images"]["debug-amd64"])
r = tree(); W(os.path.join(r, "grype", "debug-amd64"), "result.cdx.json", {"bomFormat": "CycloneDX",
    "components": [{"bom-ref": "f1", "type": "file", "name": "/etc/passwd"}]})   # files but no package: did not run
W(os.path.join(r, "scout", "debug-amd64"), "sbom.json", "")
W(os.path.join(r, "inspector", "debug-amd64"), "scan.json", "{not json")
os.remove(os.path.join(r, "google", "debug-amd64", "vulns.json"))
v = judge(r)
check("zero packages, an empty file, an unparsable file and a missing answer are 'did not run', never clean",
      sorted(v["images"]["debug-amd64"]["did_not_run"]) == ["google", "grype", "inspector", "scout"], v["images"]["debug-amd64"])
# --- rule 3: quorum
check("an amd64 image with no scanner left does not count", v["images"]["debug-amd64"]["counts_for_day"] is False)
r = tree(skip={("google", "debug-amd64")}); v = judge(r)
check("an amd64 image with 3 of 4 counts", v["images"]["debug-amd64"]["counts_for_day"] is True)
check("a scanner that did not run fails the run (exit 2) even when the image keeps its quorum",
      v["exit"] == 2 and v["scanner_failures"] == ["google on debug-amd64"] and not v["not_counted"], (v["exit"], v["scanner_failures"]))
r = tree(); W(os.path.join(r, "scout", "fips-amd64"), "cves.json", {})
W(os.path.join(r, "grype", "fips-amd64"), "result.cdx.json", {"components": [{"purl": "pkg:generic/a@1", "name": "a"}]})
W(os.path.join(r, "inspector", "fips-amd64"), "sbom.cdx.json", {"components": [{"purl": "pkg:generic/a@1", "name": "a"}]})
W(os.path.join(r, "google", "fips-amd64"), "packages.json", [{}, {"package": ""}])
v = judge(r)
check("structurally incomplete answers (no bomFormat, empty package records) are did not run",
      v["images"]["fips-amd64"]["did_not_run"] == ["google", "grype", "inspector", "scout"], v["images"]["fips-amd64"])
check("an incomplete Scout answer (no vulnerabilities list) is did not run", "scout" in v["images"]["fips-amd64"]["did_not_run"], v["images"]["fips-amd64"])
r = tree(skip={("scout", "debug-arm64")}); v = judge(r)
check("an arm64 image with 2 of its 3 does not count (all three must run)", v["images"]["debug-arm64"]["counts_for_day"] is False, v["images"]["debug-arm64"])
check("an image that does not count fails the run (exit 2), never clean", v["exit"] == 2 and "debug-arm64" in v["not_counted"], (v["exit"], v.get("not_counted")))
r = tree(); v = judge(r)
check("all six images counted and no finding -> clean (exit 0)", v["exit"] == 0 and not v["not_counted"], v["exit"])

# --- rule 4: Inspector and Google results are filtered against the VEX; Grype and Scout arrive filtered
covered = ("CVE-2025-60876", "busybox", "1.37.0")      # covered by our published VEX
r = tree({("inspector", "debug-amd64"): [covered, ("CVE-2099-0001", "tzdata", "2026c")],
          ("google", "debug-amd64"): [covered, ("CVE-2099-0001", "tzdata", "2026c")]}); v = judge(r)
ids = sorted((f["id"], f["seen_by"] and tuple(f["seen_by"])) for f in v["findings"])
check("Inspector's and Google's VEX-covered finding is dropped; the uncovered one remains, seen by both",
      ids == [("CVE-2099-0001", ("google", "inspector"))], ids)
check("the dropped finding is recorded as covered by the VEX", any(c["id"] == "CVE-2025-60876" for c in v["vex_covered"]), v["vex_covered"])

# --- rule 4 with the auditor's per-image statements: a statement scoped to one image filters only that image, and
# its encoded purl version (%2B) matches the decoded version the scanner reports
vexf = os.path.join(tempfile.mkdtemp(), "v.json")
json.dump({"@context": "x", "statements": [{"vulnerability": {"name": "CVE-2099-0009"}, "status": "not_affected",
    "products": [{"@id": "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache&variant=debug&arch=amd64",
                  "subcomponents": [{"@id": "pkg:deb/debian/tzdata@2026%63?arch=all"}]}]}]}, open(vexf, "w"))   # %63 = c
row = ("CVE-2099-0009", "tzdata", "2026c")
r = tree({(s_, img): [row] for s_ in ("inspector", "google") for img in ("debug-amd64", "fips-amd64")})
v = P.tally(r, P.load_vex(vexf))
check("a per-image statement filters only its own image (Codex r2 B2) and matches the decoded version (r2 R9)",
      [f["image"] for f in v["findings"]] == ["fips-amd64"] and [c["image"] for c in v["vex_covered"]] == ["debug-amd64", "debug-amd64"],
      ([f["image"] for f in v["findings"]], v["vex_covered"]))

# --- rules 5 and 6: merge, seen by N of M, report at two or more
r = tree({("inspector", "debug-amd64"): [covered, ("CVE-2099-0001", "tzdata", "2026c")],
          ("google", "debug-amd64"): [covered, ("CVE-2099-0001", "tzdata", "2026c")]}); v = judge(r)
f = v["findings"][0]
check("a finding carries the exact package identity a scanner gave (for a VEX statement scoped to it)",
      f["purls"] == ["pkg:generic/tzdata@2026c"], f.get("purls"))
check("one finding per CVE + package + version per image, 'seen by 2 of 4'", f["seen_by"] == ["google", "inspector"] and f["of"] == 4 and f["image"] == "debug-amd64", f)
check("seen by two or more -> reported (the tracking issue), exit 1", f["status"] == "report" and v["exit"] == 1 and "CVE-2099-0001" in v["issue"], (f["status"], v["exit"]))
# the same package named the way each scanner names it is one finding: Grype's purl carries the distro
# namespace and an escaped version (pkg:deb/debian/libc-bin@2.36-9%2Bdeb12u1), Google names libc-bin 2.36-9+deb12u1
r = tree()
d = os.path.join(r, "grype", "debug-amd64")
W(d, "result.cdx.json", {"bomFormat": "CycloneDX", "components": [
    {"bom-ref": "a", "name": "libc-bin", "version": "2.36-9+deb12u1", "purl": "pkg:deb/debian/libc-bin@2.36-9%2Bdeb12u1?arch=amd64&distro=debian-12"},
    {"bom-ref": "b", "name": "golang.org/x/net", "version": "v0.1.0", "purl": "pkg:golang/golang.org/x/net@v0.1.0"}],
    "vulnerabilities": [{"id": "CVE-2023-4911", "affects": [{"ref": "a"}]}, {"id": "GO-2099-0001", "affects": [{"ref": "b"}]}]})
google(os.path.join(r, "google", "debug-amd64"), BASE, [("CVE-2023-4911", "libc-bin", "2.36-9+deb12u1"), ("go-2099-0001", "golang.org/x/net", "0.1.0")])
v = judge(r)
check("one finding across scanners' namings (distro namespace, escaped version, v-prefix, id case) -> seen by 2",
      sorted((f["id"], len(f["seen_by"])) for f in v["findings"]) == [("CVE-2023-4911", 2), ("GO-2099-0001", 2)], [(f["id"], f["package"], f["seen_by"]) for f in v["findings"]])
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

print("panel: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
PY
