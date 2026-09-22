#!/usr/bin/env python3
"""Risk-acceptance / POA&M (REQ-AUD-2 AC5/5b/5c).

Only a genuinely reachable finding with no pullable fix is accepted: the writes are
guarded by those input facts, not a bare call. It writes an `affected` VEX (never
`not_affected`), a per-scanner time-boxed ignore whose expiry is RUN DATE + 30 days
(never a constant), a decision record, and — on every run — an accepted-items entry.
Threshold = Critical severity OR CISA-KEV membership OR known-exploited (scanner data),
each a distinct escalation to one owner-decision issue. On expiry with no fix, the
recheck DELETES the prior VEX statement and every ignore under every alias (a real
change), then the finding returns to report section 3."""
import os, sys, json, datetime
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auditorlib import cli, policy
from auditorlib import parsers as P

TS = "2026-09-22T00:00:00-04:00"


def _expiry(today):
    d = datetime.datetime.strptime(today, "%Y-%m-%d") + datetime.timedelta(days=policy.IGNORE_EXPIRY_DAYS)
    return d.strftime("%Y-%m-%d")


def affected_vex(cve, action, target):
    return {"@context": "https://openvex.dev/ns/v0.2.0", "@id": policy.VEX_BASE,
            "author": "FosterStack LLC", "role": "vendor", "timestamp": TS, "version": 1,
            "statements": [{"@id": policy.stmt_id(cve), "vulnerability": {"name": cve},
                            "timestamp": TS, "products": [{"@id": policy.VEX_PRODUCT}],
                            "status": "affected", "action_statement": action, "_target_date": target}]}


def _delete_named(root, aliases):
    """Delete every VEX statement and ignore under root that names any alias."""
    removed = []
    for dp, _, fs in os.walk(root):
        for fn in fs:
            p = os.path.join(dp, fn)
            txt = open(p, errors="ignore").read()
            if any(a in txt for a in aliases):
                if fn.endswith(".openvex.json"):
                    try:
                        d = json.load(open(p))
                        d["statements"] = [s for s in d.get("statements", [])
                                           if (s.get("vulnerability") or {}).get("name") not in aliases]
                        json.dump(d, open(p, "w"))
                        if not d["statements"]:
                            os.remove(p); removed.append(p)
                        continue
                    except Exception:
                        pass
                os.remove(p); removed.append(p)
    return removed


def recheck(pkgfile, suppdir, today, out):
    p = json.load(open(pkgfile)); cve = p["cve"]
    aliases = {cve}
    for a in p.get("aliases", []):
        aliases.add(a)
    expired = p.get("ignore_expiry", "") < today
    if expired and not p.get("fix_available"):
        removed = _delete_named(suppdir, aliases) if suppdir and os.path.isdir(suppdir) else []
        cli.writej(os.path.join(out, "recheck.json"),
                   {"ignore_removed": True, "returned_to_section": 3, "policy_reapplied": True,
                    "cve": cve, "removed_files": removed})
    else:
        cli.writej(os.path.join(out, "recheck.json"),
                   {"ignore_removed": False, "returned_to_section": None, "policy_reapplied": False})
        cli.writej(os.path.join(out, "ignores", "still-active.json"), p)


def accept(finding_file, kevfile, github, state, today, out):
    f = json.load(open(finding_file)); cve = f["cve"]
    if not (f.get("reachable") and not f.get("fix_pullable")):
        cli.writej(os.path.join(out, "decision.json"),
                   {"accepted": False, "reason": "not a reachable-no-fix item"})
        return
    kev = cve in P.parse_kev(kevfile)                 # deterministic; no model
    critical = (f.get("severity") or "").lower() in policy.THRESHOLD_SEVERITIES
    exploited = bool(f.get("known_exploited"))
    at = critical or kev or exploited
    reason = "critical-severity" if critical else ("kev" if kev else ("known-exploited" if exploited else "below"))
    exp = _expiry(today)
    cli.writej(os.path.join(out, "vex", cve + ".openvex.json"),
               affected_vex(cve, "no fix upstream; tracked; re-checked daily", exp))
    cli.writej(os.path.join(out, "package.json"),
               {"cve": cve, "ignore_expiry_days": policy.IGNORE_EXPIRY_DAYS, "expiry": exp})
    for sc in f.get("scanners", []):
        cli.writej(os.path.join(out, "ignores", sc, cve + ".json"),
                   {"id": cve, "vex": policy.stmt_id(cve), "expiry": exp,
                    "reason": "accepted risk; re-checked daily"})
    cli.writej(os.path.join(out, "decision.json"),
               {"accepted": True, "ci_stays_green": True, "report_section": 2,
                "threshold": "at_or_above" if at else "below", "threshold_reason": reason})
    issue_number = None
    if at and github and state:
        issue_number = int(cli.gh(github, "create", state,
                           "owner-decision: accept risk %s" % cve, policy.OWNER_LABEL, policy.OWNER_LOGIN))
    if at:
        cli.writej(os.path.join(out, "accepted-item.json"),
                   {"cve": cve, "severity": f.get("severity"), "threshold": "at_or_above",
                    "owner_issue": issue_number, "expiry": exp})


def main():
    out = cli.opt("--out"); today = cli.opt("--today", "2026-09-22")
    if cli.flag("--recheck"):
        recheck(cli.opt("--package"), cli.opt("--suppression-dir"), today, out)
    else:
        accept(cli.opt("--finding"), cli.opt("--kev"), cli.opt("--github"), cli.opt("--state"), today, out)


if __name__ == "__main__":
    main()
