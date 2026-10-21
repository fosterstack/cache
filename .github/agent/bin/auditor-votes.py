#!/usr/bin/env python3
"""Votes by lineage (REQ-AUD-4 AC3/AC4). Each of the panel's four scanners (Grype, Scout, Inspector,
Google) keeps its own advisory data and is its own vote, as is the Go vuln DB. A finding reported by
exactly one scanner is suspect and investigated, never auto-closed."""
import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auditorlib import cli, policy
from auditorlib import parsers as P


def scanners_reporting(manifest, cve):
    """(scanners reporting the CVE, whether every scanner's evidence was readable): a scanner that did not run, or whose report cannot
    be read, is unavailable evidence, never a vote against."""
    m = json.load(open(manifest))
    hit, complete, any_read = set(), True, False
    for name, fn, path in P.manifest_readers(m):
        try:
            found = fn(path) if path else None
        except (P.ParseError, OSError):
            found = None
        if found is None:
            complete = False
            continue
        any_read = True
        for f in found:
            if cve == f["finding_id"] or cve in f["aliases"]:
                hit.add(name)
    return hit, (any_read and (complete or bool(hit)))


def main():
    out = cli.opt("--out"); cve = cli.opt("--cve")
    sc, readable = scanners_reporting(cli.opt("--manifest"), cve)
    lineages = {policy.lineage_of(s) for s in sc}
    unique = len(sc) == 1
    cli.writej(os.path.join(out, "votes.json"), {"cve": cve, "scanners": sorted(sc),
                     "lineage_votes": {l: 1 for l in lineages},
                     "distinct_lineages": len(lineages), "unique": unique,
                     "auto_closed": False,
                     "handling": ("evidence_unavailable" if not readable else "suspect_investigated" if unique else "corroborated")})


if __name__ == "__main__":
    main()
