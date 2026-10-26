"""bin/check-osv-vex.py --vex FILE --report FILE [--variant production|fips] [--platform linux/ARCH]

Apply the published VEX document to osv-scanner's findings (REQ-CHAIN-006-AC4, REQ-REL-004-AC1; PR 3 round 1 F3).
grype reads the VEX itself (--vex); osv-scanner cannot, so its report is filtered here with the same
decision the daily rescan makes (bin/rescan-statement.py, which uses the PR gate's matcher).

A finding is excepted by a not_affected or fixed statement when all of these hold:
  - the statement's vulnerability name or an alias equals one of the finding's ids;
  - its product is the release image repository (scoped to nothing or to this variant) or the Go product;
  - if it names subcomponents, they include the finding's package with its version.

--platform is the platform child that was scanned. A statement scoped to one architecture excepts a finding
on that architecture only; without --platform it excepts nothing.

Exit 0: the report holds one finding or more and every one is excepted.
Exit 1, saying why: a finding no statement covers, a report with no parseable finding (nothing to except),
a malformed entry, or a VEX document that cannot be read (a document that cannot be read excepts nothing).

When the report was readable, one JSON line {"findings": N, "excepted": N, "uncovered": [ids]} is printed,
on exit 0 and on exit 1 alike."""
import argparse, importlib.util, json, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# The repository a release is published to. The VEX names it and cache-candidates; Check holds no registry reference.
IMAGE_REPO = "ghcr.io/fosterstack/cache"


def load_matcher():
    spec = importlib.util.spec_from_file_location("rescan_statement", os.path.join(ROOT, "bin/rescan-statement.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def fail(message):
    print("check-osv-vex: " + message, file=sys.stderr)
    sys.exit(1)


def main():
    ap = argparse.ArgumentParser(prog="check-osv-vex.py")
    ap.add_argument("--vex", required=True)
    ap.add_argument("--report", required=True)
    ap.add_argument("--variant", default="")
    ap.add_argument("--platform", default="")
    a = ap.parse_args()
    if a.platform not in ("", "linux/amd64", "linux/arm64"):
        fail("the platform %r is not linux/amd64, linux/arm64 or empty: an architecture-scoped statement "
             "is not matched against a platform that is not one of them" % a.platform)
    m = load_matcher()
    try:
        doc = m._vex_load(a.vex)
    except (OSError, ValueError, TypeError, AttributeError, KeyError, RecursionError) as e:
        fail("the VEX document %s cannot be used (%s): nothing is excepted by it" % (a.vex, e))
    try:
        with open(a.report, encoding="utf-8") as f:
            report = json.load(f)
    except (OSError, ValueError) as e:
        fail("osv-scanner's report %s is not readable JSON (%s)" % (a.report, e))
    if not m._shape_ok("osv-scanner", report):
        fail("osv-scanner's report has a shape the matcher does not read")
    bad = []
    findings = m._normalize("osv-scanner", report, a.platform, bad)
    if bad:
        fail("%d malformed entries in osv-scanner's report" % len(bad))
    if not findings:
        fail("osv-scanner failed with no finding to except (nothing parseable in its report)")
    uncovered = []
    for f in findings:
        try:
            hit = m._vex_match(doc, f, a.variant or None, IMAGE_REPO)
        except (TypeError, AttributeError, KeyError, ValueError, RecursionError) as e:
            fail("a finding could not be matched against the VEX (%s)" % e)
        if not hit:
            uncovered.append("%s (%s %s)" % (f.get("id"), f.get("package"), f.get("version")))
    print(json.dumps({"findings": len(findings), "excepted": len(findings) - len(uncovered), "uncovered": uncovered}))
    if uncovered:
        fail("osv-scanner found %d vulnerabilities the VEX document does not except: %s"
             % (len(uncovered), "; ".join(uncovered)))


main()
