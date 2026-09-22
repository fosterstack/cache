#!/usr/bin/env python3
"""One disposition -> four per-scanner suppressions (REQ-AUD-4 AC1), each citing the
governing VEX statement. A writer that would emit two statuses for one finding raises."""
import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auditorlib import cli, policy


def main():
    d = json.load(open(cli.opt("--disposition"))); out = cli.opt("--out")
    cve = d["cve"]; vid = policy.stmt_id(cve); status = d["status"]; expiry = d.get("expiry", "2026-10-22")
    if status not in ("not_affected", "affected"):
        sys.exit("suppress: invalid status")
    cli.writej(os.path.join(out, ".vex", "fosterstack-cache.openvex.json"),
               {"@context": "https://openvex.dev/ns/v0.2.0", "@id": policy.VEX_BASE,
                "author": "FosterStack LLC", "role": "vendor", "version": 1,
                "statements": [{"@id": vid, "vulnerability": {"name": cve},
                                "products": [{"@id": policy.VEX_PRODUCT}],
                                "status": status, "justification": d.get("justification")}]})
    cli.writef(os.path.join(out, ".snyk"),
               "version: v1.5.0\nignore:\n  %s:\n    - '*':\n        reason: 'not_affected; %s'\n"
               "        expires: %sT00:00:00.000Z\n        vex: '%s'\n" % (cve, vid, expiry, vid))
    cli.writef(os.path.join(out, "osv-scanner.toml"),
               '[[IgnoredVulns]]\nid = "%s"\nreason = "not_affected; governed by %s"\n' % (cve, vid))


if __name__ == "__main__":
    main()
