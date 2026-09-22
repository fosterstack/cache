#!/usr/bin/env python3
"""Owner notification (REQ-AUD-9). Notifies a human only for the five owner-decision triggers,
via exactly one owner-decision issue (updated, never duplicated). Nothing else notifies."""
import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auditorlib import cli, policy
from auditorlib import parsers as P

def is_trigger(f, kevpath):
    if not (f.get("reachable") and not f.get("fix_pullable")):
        return False
    if (f.get("severity") or "").lower() == "critical":
        return True
    if f.get("known_exploited"):
        return True
    try:
        return f["cve"] in P.parse_kev(kevpath)
    except Exception:
        return False


def main():
    out = cli.opt("--out")
    if cli.flag("--list-triggers"):
        cli.writej(os.path.join(out, "triggers.json"),
                   {"triggers": policy.NOTIFY_TRIGGERS, "only_channel": policy.NOTIFY_CHANNEL})
        return
    f = json.load(open(cli.opt("--finding"))); cve = f["cve"]
    github = cli.opt("--github"); state = cli.opt("--state"); artifact = cli.opt("--artifact", "")
    kev = cli.opt("--kev", os.environ.get("AUDITOR_KEV_CATALOG"))
    if not is_trigger(f, kev):
        cli.writej(os.path.join(out, "notify.json"), {"notified": False, "cve": cve})
        return
    title = "owner-decision: risk acceptance %s" % cve
    existing = cli.gh(github, "find", state, title)
    if existing:
        cli.gh(github, "comment", state, existing, "re-check: %s still open %s" % (cve, artifact))
    else:
        num = cli.gh(github, "create", state, title, policy.OWNER_LABEL, "fosterstack-admin")
        cli.gh(github, "comment", state, num, "Accept risk for %s? evidence attached; artifact %s" % (cve, artifact))
    cli.writej(os.path.join(out, "notify.json"), {"notified": True, "cve": cve})


if __name__ == "__main__":
    main()
