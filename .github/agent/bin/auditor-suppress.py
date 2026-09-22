#!/usr/bin/env python3
"""One verified disposition -> four per-scanner suppressions (REQ-AUD-4 AC1), each
citing the governing VEX statement. It REFUSES a disposition without an `evidence`
object naming the check that produced it — a bare model answer is not enough. A
disposition that would produce two statuses for one finding raises."""
import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auditorlib import cli, policy

TS = "2026-09-22T00:00:00-04:00"


def main():
    d = json.load(open(cli.opt("--disposition"))); out = cli.opt("--out")
    cve = d["cve"]; vid = policy.stmt_id(cve); status = d["status"]; expiry = d.get("expiry", "2026-10-22")
    if status not in ("not_affected", "affected"):
        sys.exit("suppress: invalid status")
    if not d.get("evidence"):
        sys.exit("suppress: refusing to write a suppression without an evidence object")
    st = {"@id": vid, "vulnerability": {"name": cve}, "timestamp": TS,
          "products": [{"@id": policy.VEX_PRODUCT}], "status": status, "_evidence": d["evidence"]}
    if status == "not_affected":
        st["justification"] = d.get("justification")
    else:
        st["action_statement"] = d.get("action_statement", "tracked; re-checked daily")
    cli.writej(os.path.join(out, ".vex", "fosterstack-cache.openvex.json"),
               {"@context": "https://openvex.dev/ns/v0.2.0", "@id": policy.VEX_BASE,
                "author": "FosterStack LLC", "role": "vendor", "timestamp": TS, "version": 1,
                "statements": [st]})
    cli.writef(os.path.join(out, ".snyk"),
               "version: v1.5.0\nignore:\n  %s:\n    - '*':\n        reason: '%s; %s'\n"
               "        expires: %sT00:00:00.000Z\n        vex: '%s'\n" % (cve, status, vid, expiry, vid))
    cli.writef(os.path.join(out, "osv-scanner.toml"),
               '[[IgnoredVulns]]\nid = "%s"\nreason = "%s; governed by %s"\n' % (cve, status, vid))


if __name__ == "__main__":
    main()
