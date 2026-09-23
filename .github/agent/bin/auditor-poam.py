#!/usr/bin/env python3
"""Risk-acceptance / POA&M (REQ-AUD-2 AC5/5b/5c). Guarded by reachable + no-pullable-fix
facts. Writes a conformant `affected` VEX (evidence + target date in a sidecar), a
per-scanner ignore with a run-date + 30 day expiry, a decision, and an accepted-item entry.
Threshold = Critical OR CISA-KEV OR known-exploited. On expiry with no fix, the recheck
SURGICALLY removes only the finding's statements and ignore entries (matched by id or
vulnerability.aliases), never whole shared files."""
import os, sys, json, datetime, glob
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auditorlib import cli, policy, vex


def _expiry(today):
    d = datetime.datetime.strptime(today, "%Y-%m-%d") + datetime.timedelta(days=policy.IGNORE_EXPIRY_DAYS)
    return d.strftime("%Y-%m-%d")


def _remove_from_vex(path, aliases):
    try:
        d = json.load(open(path))
    except Exception:
        return False
    if "statements" not in d:
        return False
    kept = []
    for s in d["statements"]:
        v = s.get("vulnerability") or {}
        names = {v.get("name")} | set(v.get("aliases") or [])
        if names & aliases:
            continue
        kept.append(s)
    if len(kept) == len(d["statements"]):
        return False
    d["statements"] = kept
    if kept:
        json.dump(d, open(path, "w"), indent=1)
    else:
        os.remove(path)
    return True


def _edit_snyk(path, aliases):
    """Structurally remove ONLY the ignore entries whose top-level key is EXACTLY one of the
    aliases (R11 rank 8). Keyed on the exact 2-space-indented `<id>:` line — a prefix
    collision (CVE-...-33740 vs ...-3374) and unrelated entries survive; no regex substring
    matching. The auditor authors this file, so its shape (ignore: {<id>: [ {'*': {...}} ]})
    is known and parsed by indentation."""
    import re as _re
    text = open(path).read(); lines = text.splitlines(); out = []; i = 0; n = len(lines)
    while i < n:
        m = _re.match(r"^  ([^\s].*?):\s*$", lines[i])         # a top-level ignore key
        if m and m.group(1).strip().strip("'\"") in aliases:
            i += 1
            while i < n and (lines[i].strip() == "" or _re.match(r"^   ", lines[i])):
                i += 1                                          # drop its indented children
            continue
        out.append(lines[i]); i += 1
    new = "\n".join(out) + ("\n" if text.endswith("\n") else "")
    open(path, "w").write(new)


def _remove_ignores(root, aliases):
    removed = []
    for dp, _, fs in os.walk(root):
        for fn in fs:
            p = os.path.join(dp, fn)
            if fn.endswith(".openvex.json"):
                if _remove_from_vex(p, aliases):
                    removed.append(p)
            elif fn.endswith(".json"):
                try:
                    d = json.load(open(p))
                except Exception:
                    continue
                if d.get("id") in aliases:          # a per-finding ignore for this id
                    os.remove(p); removed.append(p)
            elif fn == ".snyk":
                _edit_snyk(p, aliases)
            elif fn == "osv-scanner.toml":
                import re
                blocks = open(p).read().split("[[IgnoredVulns]]")
                keep = [blocks[0]] + [b for b in blocks[1:] if not any(('"%s"' % a) in b for a in aliases)]
                open(p, "w").write("[[IgnoredVulns]]".join(keep))
    return removed


def recheck(pkgfile, suppdir, today, out):
    p = json.load(open(pkgfile)); cve = p["cve"]
    aliases = {cve} | set(p.get("aliases", []))
    expired = p.get("ignore_expiry", "") <= today          # R11 rank 8: expiry date itself expires
    if expired and not p.get("fix_available"):
        removed = _remove_ignores(suppdir, aliases) if suppdir and os.path.isdir(suppdir) else []
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
        cli.writej(os.path.join(out, "decision.json"), {"accepted": False, "reason": "not a reachable-no-fix item"})
        return
    kev = cve in P_kev(kevfile)
    critical = (f.get("severity") or "").lower() in policy.THRESHOLD_SEVERITIES
    exploited = bool(f.get("known_exploited"))
    at = critical or kev or exploited
    reason = "critical-severity" if critical else ("kev" if kev else ("known-exploited" if exploited else "below"))
    exp = _expiry(today); ts = today + "T00:00:00Z"
    vex.write(out, cve, "affected", ts, action="no fix upstream; tracked; re-checked daily",
              evidence={"check": "reachable-no-fix", "source_file": finding_file,
                        "detail": "reachable=%s fix_pullable=%s" % (f.get("reachable"), f.get("fix_pullable"))},
              target_date=exp)
    cli.writej(os.path.join(out, "package.json"), {"cve": cve, "ignore_expiry_days": policy.IGNORE_EXPIRY_DAYS, "expiry": exp})
    for sc in f.get("scanners", []):
        cli.writej(os.path.join(out, "ignores", sc, cve + ".json"),
                   {"id": cve, "vex": policy.stmt_id(cve), "expiry": exp, "reason": "accepted risk; re-checked daily"})
    cli.writej(os.path.join(out, "decision.json"),
               {"accepted": True, "ci_stays_green": True, "report_section": 2,
                "threshold": "at_or_above" if at else "below", "threshold_reason": reason})
    issue_number = None
    if at and github and state:
        issue_number = int(cli.gh(github, "create", state, "owner-decision: accept risk %s" % cve,
                                  policy.OWNER_LABEL, policy.OWNER_LOGIN))
    if at:
        cli.writej(os.path.join(out, "accepted-item.json"),
                   {"cve": cve, "severity": f.get("severity"), "threshold": "at_or_above",
                    "owner_issue": issue_number, "expiry": exp})


def P_kev(path):
    from auditorlib import parsers as P
    return P.parse_kev(path)


def main():
    out = cli.opt("--out"); today = cli.opt("--today", "2026-09-22")
    if cli.flag("--recheck"):
        recheck(cli.opt("--package"), cli.opt("--suppression-dir"), today, out)
    else:
        accept(cli.opt("--finding"), cli.opt("--kev"), cli.opt("--github"), cli.opt("--state"), today, out)


if __name__ == "__main__":
    main()
