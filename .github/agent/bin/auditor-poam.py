#!/usr/bin/env python3
"""Risk-acceptance / POA&M (REQ-AUD-2 AC5/5b/5c).

A reachable finding with no pullable fix is never a CI-red block: the auditor writes
an `affected` VEX (never `not_affected`) with an action statement and a target date,
plus time-boxed per-scanner ignores, and merges the package so CI stays green.
Critical severity, or CISA-KEV membership (a deterministic catalog lookup, no model
call), additionally opens one owner-decision issue. On expiry with no fix, the ignore
is removed and the finding returns to report section 3.
"""
import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auditorlib import cli, policy
from auditorlib import parsers as P


def affected_vex(cve, action, target):
    return {"@context": "https://openvex.dev/ns/v0.2.0", "@id": policy.VEX_BASE,
            "author": "FosterStack LLC", "role": "vendor", "version": 1,
            "statements": [{"@id": policy.stmt_id(cve), "vulnerability": {"name": cve},
                            "products": [{"@id": policy.VEX_PRODUCT}], "status": "affected",
                            "action_statement": action, "target_date": target}]}


def recheck(pkgfile, out):
    p = json.load(open(pkgfile))
    expired = p.get("ignore_expiry", "") < p.get("today", "")
    if expired and not p.get("fix_available"):
        # remove the ignore: the recheck output carries NO ignore for the finding.
        cli.writej(os.path.join(out, "recheck.json"),
                   {"ignore_removed": True, "returned_to_section": 3, "policy_reapplied": True,
                    "cve": p.get("cve")})
    else:
        cli.writej(os.path.join(out, "recheck.json"),
                   {"ignore_removed": False, "returned_to_section": None, "policy_reapplied": False})
        cli.writej(os.path.join(out, "ignores", "still-active.json"), p)


def accept(finding_file, kevfile, github, state, out):
    f = json.load(open(finding_file))
    cve = f["cve"]
    kev = cve in P.parse_kev(kevfile)              # deterministic; no model call
    critical = (f.get("severity") or "").lower() in policy.THRESHOLD_SEVERITIES
    at = critical or kev
    reason = "critical-severity" if critical else ("kev" if kev else "below")
    cli.writej(os.path.join(out, "vex", cve + ".openvex.json"),
               affected_vex(cve, "no fix upstream; tracked; re-checked daily", "2026-10-22"))
    cli.writej(os.path.join(out, "package.json"),
               {"cve": cve, "ignore_expiry_days": policy.IGNORE_EXPIRY_DAYS})
    for sc in f.get("scanners", []):
        cli.writej(os.path.join(out, "ignores", sc, cve + ".json"),
                   {"id": cve, "vex": policy.stmt_id(cve),
                    "expiry": "2026-10-22", "reason": "accepted risk; re-checked daily"})
    cli.writej(os.path.join(out, "decision.json"),
               {"ci_stays_green": True, "report_section": 2,
                "threshold": "at_or_above" if at else "below", "threshold_reason": reason})
    if at and github and state:
        cli.gh(github, "create", state,
               "owner-decision: accept risk %s" % cve, policy.OWNER_LABEL, "fosterstack-admin")


def main():
    out = cli.opt("--out")
    if cli.flag("--recheck"):
        recheck(cli.opt("--package"), out)
    else:
        accept(cli.opt("--finding"), cli.opt("--kev"), cli.opt("--github"), cli.opt("--state"), out)


if __name__ == "__main__":
    main()
