#!/usr/bin/env python3
"""Scanner-panel rule 4 / REQ-SCAN-004-AC2, for Docker Scout: judge the rescan's self-check. Two GitLab reports of the
same fixture — `before` with a VEX file of our author that does not cover the target, `after` with one not_affected statement for
the target CVE. Passes only when the target is in `before`, gone from `after`, and every other finding of `before`
remains in `after` — the same (CVE, package, version), as often (an uncovered finding is kept). An empty or malformed report is refused, never read as suppression.
Usage: scout-selfcheck.py <before.json> <after.json> <CVE>"""
import json, sys
from collections import Counter


def findings(path):
    """The report's findings as a multiset of (CVE, package, version) — the identity bin/panel.py reads — never names
    alone (Codex #168 r2, B2: another package or version under a kept CVE is not the finding kept)."""
    try:
        doc = json.load(open(path))
    except (OSError, ValueError) as e:
        raise ValueError("%s: not a Scout report (%s)" % (path, e))
    if not isinstance(doc, dict) or not isinstance(doc.get("vulnerabilities"), list):
        raise ValueError("%s: Scout's report has no vulnerabilities list" % path)
    out = Counter()
    for v in doc["vulnerabilities"]:
        ids = [i.get("value") for i in (v.get("identifiers") or []) if isinstance(i, dict) and i.get("value")] \
            if isinstance(v, dict) else []
        dep = ((v.get("location") or {}).get("dependency") or {}) if isinstance(v, dict) else {}
        name, ver = ((dep.get("package") or {}).get("name"), dep.get("version")) if isinstance(dep, dict) else (None, None)
        if not ids or not isinstance(name, str) or not name or not isinstance(ver, str) or not ver:
            raise ValueError("%s: a finding without its CVE, package or version" % path)
        out[(ids[0], name, ver)] += 1
    return out


def judge(before, after, target):
    covered = Counter({k: n for k, n in before.items() if k[0] == target})
    if not covered:
        return "the fixture's %s is not in Scout's report without a statement" % target
    rest = before - covered
    if not rest:
        return "no uncovered finding to prove the rest is kept"
    if any(k[0] == target for k in after):
        return "Scout kept %s although our statement covers it" % target
    if after != rest:
        return "Scout changed findings our statement does not cover: lost %s, gained %s" % (
            sorted((rest - after).elements()), sorted((after - rest).elements()))
    return None


def main(argv):
    try:
        why = judge(findings(argv[1]), findings(argv[2]), argv[3])
    except ValueError as e:
        why = str(e)
    if why:
        print("::error::Scout self-check: %s" % why, file=sys.stderr)
        return 1
    print("Scout applies our VEX: %s dropped, every other finding kept" % argv[3])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
