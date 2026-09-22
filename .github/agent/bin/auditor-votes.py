#!/usr/bin/env python3
"""Votes by lineage (REQ-AUD-4 AC3/AC4). Grype and Trivy share the Anchore/Aqua
lineage and count as ONE vote; OSV, Snyk and the Go vuln DB are their own. A finding
reported by exactly one scanner is suspect and investigated, never auto-closed."""
import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auditorlib import cli, policy
from auditorlib import parsers as P


def scanners_reporting(manifest, cve):
    m = json.load(open(manifest)); r = m["scanner_reports"]
    reps = {"grype": P.parse_grype, "trivy": P.parse_trivy,
            "osv-scanner": P.parse_osv, "snyk": P.parse_snyk}
    hit = set()
    for name, fn in reps.items():
        for f in fn(r[name]):
            if cve == f["finding_id"] or cve in f["aliases"]:
                hit.add(name)
    return hit


def main():
    out = cli.opt("--out"); cve = cli.opt("--cve")
    sc = scanners_reporting(cli.opt("--manifest"), cve)
    lineages = {policy.lineage_of(s) for s in sc}
    unique = len(sc) == 1
    cli.writej(os.path.join(out, "votes.json"), {"cve": cve, "scanners": sorted(sc),
                     "lineage_votes": {l: 1 for l in lineages},
                     "distinct_lineages": len(lineages), "unique": unique,
                     "auto_closed": False,
                     "handling": "suspect_investigated" if unique else "corroborated"})


if __name__ == "__main__":
    main()
