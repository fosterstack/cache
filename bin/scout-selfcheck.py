#!/usr/bin/env python3
"""Scanner-panel rule 4 / REQ-SCAN-004-AC2, for Docker Scout: judge the rescan's self-check. Two GitLab reports of the
same fixture — `before` with a VEX file of our author that does not cover the target, `after` with one not_affected statement for
the target CVE. Passes only when the target is in `before`, gone from `after`, and every other finding of `before`
remains in `after` (an uncovered finding is kept). An empty or malformed report is refused, never read as suppression.
Usage: scout-selfcheck.py <before.json> <after.json> <CVE>"""
import json, sys


def cves(path):
    try:
        doc = json.load(open(path))
    except (OSError, ValueError) as e:
        raise ValueError("%s: not a Scout report (%s)" % (path, e))
    if not isinstance(doc, dict) or not isinstance(doc.get("vulnerabilities"), list):
        raise ValueError("%s: Scout's report has no vulnerabilities list" % path)
    out = set()
    for v in doc["vulnerabilities"]:
        ids = [i.get("value") for i in (v.get("identifiers") or []) if isinstance(i, dict) and i.get("value")] \
            if isinstance(v, dict) else []
        if not ids:
            raise ValueError("%s: a finding without an identifier" % path)
        out.add(ids[0])
    return out


def judge(before, after, target):
    if target not in before:
        return "the fixture's %s is not in Scout's report without a statement" % target
    if not before - {target}:
        return "no uncovered finding to prove the rest is kept"
    if target in after:
        return "Scout kept %s although our statement covers it" % target
    if after != before - {target}:
        return "Scout changed findings our statement does not cover: lost %s, gained %s" % (
            sorted(before - {target} - after), sorted(after - before))
    return None


def main(argv):
    try:
        why = judge(cves(argv[1]), cves(argv[2]), argv[3])
    except ValueError as e:
        why = str(e)
    if why:
        print("::error::Scout self-check: %s" % why, file=sys.stderr)
        return 1
    print("Scout applies our VEX: %s dropped, every other finding kept" % argv[3])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
