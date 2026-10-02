#!/usr/bin/env bash
# proves: REQ-SCAN-003-AC1, REQ-SCAN-003-AC2, REQ-SCAN-003-AC3, REQ-SCAN-004-AC2, REQ-SCAN-005-AC1, REQ-SCAN-005-AC2, REQ-SCAN-006-AC1, REQ-SCAN-007-AC1, REQ-SCAN-008-AC1, REQ-SCAN-008-AC2, REQ-SCAN-008-AC4, REQ-SCAN-008-AC6, REQ-SCAN-009-AC2, REQ-SCAN-009-AC3, REQ-SCAN-009-AC4, REQ-REL-004-AC3
# The scanner panel's judge (bin/panel.py; scanner-panel rules 3-9, ratified Oct 2), offline: each scanner's
# real output shape per image, written as fixtures; stand-in audits for rule 8. Asserts the package counts
# (zero = did not run), the quorum per image, VEX filtering for Inspector and Google, the merge into one
# finding "seen by N of M", reporting only at two or more scanners, the rule-8 paths and votes, the rule-9
# outcomes, the audit-miss reversal, and the profile validator.
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
    W(d, "result.cdx.json", {"bomFormat": "CycloneDX", "components": comps,
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
def judge(root, audit=None, prior=None, profiles=None):
    return P.judge(root, P.load_vex(VEX), profiles or {"entries": []}, audit or P.no_auditor, prior or {"false": []})

# --- rule 1 shape the judge expects (the workflow wiring test checks the jobs)
check("the expected set: Grype, Scout, Inspector on all six images; Google on the three amd64 images only",
      all(sorted(P.EXPECTED[s]) == sorted(IMAGES) for s in ("grype", "scout", "inspector"))
      and sorted(P.EXPECTED["google"]) == sorted(i for i in IMAGES if i.endswith("amd64")), P.EXPECTED)

# --- rule 3: package counts; zero / empty / unparsable = did not run
r = tree(); v = judge(r)
check("package counts are reported per scanner per image", v["images"]["debug-amd64"]["counts"] == {"google": 3, "grype": 3, "inspector": 3, "scout": 3}, v["images"]["debug-amd64"])
r = tree(); grype(os.path.join(r, "grype", "debug-amd64"), [], [])
W(os.path.join(r, "scout", "debug-amd64"), "sbom.json", "")
W(os.path.join(r, "inspector", "debug-amd64"), "scan.json", "{not json")
v = judge(r)
check("zero packages, an empty file and an unparsable file are 'did not run', never clean",
      sorted(v["images"]["debug-amd64"]["did_not_run"]) == ["grype", "inspector", "scout"], v["images"]["debug-amd64"])
# --- rule 3: quorum
check("an amd64 image with only Google left (1 of 4) does not count", v["images"]["debug-amd64"]["counts_for_day"] is False)
r = tree(skip={("google", "debug-amd64")}); v = judge(r)
check("an amd64 image with 3 of 4 counts", v["images"]["debug-amd64"]["counts_for_day"] is True)
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

# --- rules 5 and 6: merge, seen by N of M, report at two or more
f = v["findings"][0]
check("one finding per CVE + package + version per image, 'seen by 2 of 4'", f["seen_by"] == ["google", "inspector"] and f["of"] == 4 and f["image"] == "debug-amd64", f)
check("seen by two or more -> reported (the tracking issue), exit 1", f["status"] == "report" and v["exit"] == 1 and "CVE-2099-0001" in v["issue"], (f["status"], v["exit"]))
r = tree({("scout", "fips-arm64"): [("CVE-2099-0002", "tzdata", "2026c")]}); v = judge(r)
f = v["findings"][0]
check("a unique finding never reaches the issue directly", f["unique"] and f["of"] == 3 and f["status"] != "report" and not v["issue"], (f, v["issue"]))

# --- rule 8: no auditor configured (PR 1) -> each audit errors -> no evidence -> false by default
check("no auditor: the audit error counts as no evidence -> false by default, error reported (rule 8 b)",
      f["status"] == "false-default" and all(a.get("error") for a in f["audits"]) and len(f["audits"]) == 2 and v["audit_errors"], f)
check("false by default: logged, no alarm, no public statement (rule 9)", v["exit"] == 0 and not v["vex_proposals"] and f in v["log"], v["exit"])

def audits(votes):
    """votes: {vendor: (verdict, evidence)} or {vendor: 'error'}"""
    def a(vendor, finding, image):
        x = votes[vendor]
        return {"error": "stand-in failure"} if x == "error" else {"verdict": x[0], "evidence": x[1], "why": "reads the binary" if x[0] == "real" else None}
    return a
U = {("scout", "fips-arm64"): [("CVE-2099-0002", "tzdata", "2026c")]}
for votes, want in [
    ({"vendor_a": ("real", "dpkg status lists tzdata 2026c"), "vendor_b": ("real", "/usr/share/zoneinfo shows 2026c")}, "report"),
    ({"vendor_a": ("real", "dpkg status lists tzdata 2026c"), "vendor_b": ("false", "not present")}, "false-evidence"),
    ({"vendor_a": ("real", "dpkg status lists tzdata 2026c"), "vendor_b": ("real", None)}, "false-default"),
    ({"vendor_a": ("real", "dpkg status lists tzdata 2026c"), "vendor_b": "error"}, "false-default"),
    ({"vendor_a": ("false", None), "vendor_b": ("false", None)}, "false-default")]:
    v = judge(tree(U), audit=audits(votes)); f = v["findings"][0]
    check("rule 8 b votes %s -> %s" % ({k: (x if x == "error" else x[0] + ("+ev" if x[1] else "")) for k, x in votes.items()}, want),
          f["status"] == want and len(f["audits"]) == 2, (f["status"], f["audits"]))
v = judge(tree(U), audit=audits({"vendor_a": ("real", "e"), "vendor_b": ("real", "e")}))
check("a unique finding confirmed real is reported under rule 5 with the audit's why", v["findings"][0]["status"] == "report" and v["exit"] == 1 and v["findings"][0]["why"], v["findings"][0])
v = judge(tree(U), audit=audits({"vendor_a": ("false", "tzdata 2026c is not in the package database"), "vendor_b": ("real", "e")}))
check("false with evidence -> a not_affected VEX proposal citing it (rule 9)",
      v["vex_proposals"] and v["vex_proposals"][0]["status"] == "not_affected" and "not in the package database" in v["vex_proposals"][0]["justification_evidence"], v["vex_proposals"])
check("every judged finding is logged with each audit's reasoning (rule 9)", v["log"] and all("audits" in x for x in v["log"]), v["log"])

# --- rule 8 a: a recorded behavior -> one audit; real only with evidence from the image
prof = {"entries": [{"scanner": "scout", "kind": "sees_alone", "match": {"package": "^tzdata$"},
                     "behavior": "reads /usr/share/zoneinfo", "finding": "CVE-2099-0002 on fips-arm64", "evidence": "zoneinfo 2026c in the image"}]}
v = judge(tree(U), audit=audits({"vendor_a": ("real", "dpkg status lists tzdata 2026c"), "vendor_b": ("false", None)}), profiles=prof)
f = v["findings"][0]
check("a profile match takes one audit, and it decides (rule 8 a; a merged entry -> one audit)", len(f["audits"]) == 1 and f["status"] == "report", f)
v = judge(tree(U), audit=audits({"vendor_a": ("real", None), "vendor_b": ("real", "e")}), profiles=prof)
check("rule 8 a: real without evidence from the image is false", v["findings"][0]["status"] == "false-default", v["findings"][0])

# --- rule 9: a finding judged false earlier, now seen by two -> real, an audit miss
prior = {"false": [{"image": "fips-arm64", "id": "CVE-2099-0002", "package": "tzdata", "version": "2026c"}]}
v = judge(tree({("scout", "fips-arm64"): [("CVE-2099-0002", "tzdata", "2026c")], ("grype", "fips-arm64"): [("CVE-2099-0002", "tzdata", "2026c")]}), prior=prior)
check("a finding judged false earlier and now seen by two is real: issue, and an audit miss reported",
      v["findings"][0]["status"] == "report" and v["misses"] and "audit miss" in v["issue"], (v["misses"], v["issue"][:80]))
check("today's false judgments are carried for tomorrow's comparison", "false" in v["judgments"], v["judgments"])

# --- rule 7: profile validator
check("a profile entry without a cited finding or image evidence fails validation",
      P.validate_profiles({"entries": [{"scanner": "google", "kind": "blind_spot", "behavior": "b", "finding": "", "evidence": "e"}]})
      and P.validate_profiles({"entries": [{"scanner": "google", "kind": "blind_spot", "behavior": "b", "finding": "f"}]})
      and P.validate_profiles({"entries": [{"scanner": "nope", "kind": "blind_spot", "behavior": "b", "finding": "f", "evidence": "e"}]}), "")
check("the committed profiles validate", P.validate_profiles(json.load(open(os.path.join(os.path.dirname(sys.argv[1]), "..", ".github", "policy", "scanner-profiles.json")))) == [], "")
print("panel: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
PY
