#!/usr/bin/env python3
"""Every-run suppression consistency check (REQ-AUD-4 AC5): every VEX statement must answer a
live finding. The OpenVEX file is the only exception there is (scanner-panel rule 4), so there are
no per-scanner ignore files to cross-check."""
import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auditorlib import cli
from auditorlib import parsers as P


def live_cves(manifest):
    """Every id the panel's four scanners carry for a live finding, read from the rescan's verdict.json."""
    m = json.load(open(manifest))
    cves = set()
    path = (m.get("panel") or {}).get("verdict")
    if not path:                                    # no verdict (the panel did not report): nothing is live
        return cves
    for sc in P.PANEL_SCANNERS:
        for f in P.parse_panel(path, sc):
            # every id the finding carries is 'live' — CVE, GO-, GHSA-, DEBIAN-CVE-, TEMP-*,
            # DLA-* — so a carried VEX for a non-CVE id is NOT false-flagged stale (R1 round-4).
            cves.update(f["aliases"]); cves.add(f["finding_id"])
    return cves


def main():
    d = cli.opt("--suppression-dir"); out = cli.opt("--out")
    live = live_cves(cli.opt("--live-findings"))
    problems = []
    vexf = os.path.join(d, "fosterstack-cache.openvex.json")
    vex_cves = set()
    if os.path.exists(vexf):
        for s in json.load(open(vexf)).get("statements", []):
            cve = (s.get("vulnerability") or {}).get("name")
            vex_cves.add(cve)
            if cve not in live:
                problems.append({"type": "stale_vex", "cve": cve})
    cli.writej(out, {"consistent": not problems, "problems": problems})


if __name__ == "__main__":
    main()
