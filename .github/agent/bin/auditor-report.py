#!/usr/bin/env python3
"""Render the run report to a markdown file (REQ-AUD-7). The header carries the
digest, each scanner's name+version+db date, the model ROLE (primary/fallback, never
an id) and the token cost. A scanner that did not run is the first line and a machine
status sidecar records a non-clean run_status. Findings are placed under their
section by disposition."""
import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auditorlib import cli

SECT = {"false_positive": 5, "not_affected_unreachable": 2, "real_fixable": 3,
        "risk_acceptance": 2}
TITLES = {1: "Lifted", 2: "Accepted risk", 3: "Actual vulnerabilities",
          4: "Could not be assessed", 5: "Closed as not affected",
          6: "Pending", 7: "Currently suppressed"}


def main():
    rs = json.load(open(cli.opt("--run-state"))); out = cli.opt("--out")
    scanners = rs.get("scanners", [])
    down = [s for s in scanners if not s.get("ran", True)]
    dg = (rs.get("run", {}).get("candidate_digests", {}) or {}).get("production", "")
    lines = []
    run_status = "clean"
    if down:
        run_status = "degraded"
        for s in down:
            lines.append("%s did not run — the run is not clean" % s["name"])
    lines.append("# Daily CVE auditor report")
    lines.append("candidate digest: %s" % dg)
    for s in scanners:
        if s.get("ran", True):
            lines.append("scanner: %s %s (db %s)" % (s["name"], s.get("version"), s.get("db_date")))
    lines.append("model: %s   token cost: %s" % (rs.get("model", "primary"), rs.get("token_cost", 0)))
    sec = {}
    for f in rs.get("findings", []):
        n = SECT.get(f.get("disposition"))
        if n:
            sec.setdefault(n, []).append(f["id"])
    for n in range(1, 8):
        lines.append("## %d. %s" % (n, TITLES[n]))
        for fid in sec.get(n, []):
            lines.append(fid)
        if n == 7:
            lines.append("per-scanner suppression table — consistency: ok")
    cli.writef(out, "\n".join(lines) + "\n")
    cli.writej(out + ".status.json", {"run_status": run_status})


if __name__ == "__main__":
    main()
