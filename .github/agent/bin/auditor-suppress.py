#!/usr/bin/env python3
"""One verified disposition -> four per-scanner suppressions (REQ-AUD-4 AC1). The VEX is
OpenVEX-conformant (evidence in a sidecar); it REFUSES a disposition whose `evidence` is not
an object with {check, source_file, detail}."""
import os, sys, json, datetime
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auditorlib import cli, policy, vex


def main():
    d = json.load(open(cli.opt("--disposition"))); out = cli.opt("--out")
    cve = d["cve"]; vid = policy.stmt_id(cve); status = d["status"]; expiry = d.get("expiry", "2026-10-22")
    today = cli.opt("--today", "2026-09-22"); ts = today + "T00:00:00Z"
    if status not in ("not_affected", "affected"):
        sys.exit("suppress: invalid status")
    ev = d.get("evidence")
    if not (isinstance(ev, dict) and all(k in ev for k in ("check", "source_file", "detail"))):
        sys.exit("suppress: evidence must be an object with check, source_file, detail")
    document = vex.doc(cve, status, ts,
                       justification=(d.get("justification") if status == "not_affected" else None),
                       action=(None if status == "not_affected" else d.get("action_statement", "tracked; re-checked daily")))
    vex.validate(document)
    cli.writej(os.path.join(out, ".vex", "fosterstack-cache.openvex.json"), document)
    cli.writej(os.path.join(out, "evidence", cve + ".evidence.json"),
               {"statement_id": vid, "vulnerability": cve, "evidence": ev, "expiry": expiry})
    cli.writef(os.path.join(out, ".snyk"),
               "version: v1.5.0\nignore:\n  %s:\n    - '*':\n        reason: '%s; %s'\n"
               "        expires: %sT00:00:00.000Z\n        vex: '%s'\n" % (cve, status, vid, expiry, vid))
    cli.writef(os.path.join(out, "osv-scanner.toml"),
               '[[IgnoredVulns]]\nid = "%s"\nreason = "%s; governed by %s"\n' % (cve, status, vid))


if __name__ == "__main__":
    main()
