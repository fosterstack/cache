"""bin/check-osv-vex.py --vex FILE --report FILE [--variant production|fips]: the published VEX document applied to osv-scanner's findings (REQ-CHAIN-006-AC4,
REQ-REL-004-AC1; PR 3 round 1 F3). grype reads the document itself (--vex); osv-scanner cannot, so its machine output is filtered here with the
decision the daily rescan makes (bin/rescan-statement.py, which uses the PR gate's matcher): a not_affected or fixed statement whose vulnerability name or
alias equals one of the finding's ids, whose product is the release image repository (scoped to nothing or to this variant) or the Go product, and
whose subcomponents, when it names any, include the finding's package with its version.
Exit 0: osv-scanner's report holds one finding or more and every one is excepted. Exit 1, naming why: a finding no statement covers, a report with no
parseable finding (nothing to except), a malformed entry, or a VEX document that cannot be read (nothing is excepted by a document that cannot be read).
Prints one JSON line {"findings": N, "excepted": N, "uncovered": [ids]} on exit 0 and exit 1 alike when the report was readable."""
import argparse, importlib.util, json, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMAGE_REPO = "ghcr.io/fosterstack/cache"   # the repository a release is published to (the VEX names it and cache-candidates; Check holds no registry reference)


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
    a = ap.parse_args()
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
    findings = m._normalize("osv-scanner", report, "", bad)
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
        fail("osv-scanner found %d vulnerabilities the VEX document does not except: %s" % (len(uncovered), "; ".join(uncovered)))


main()
