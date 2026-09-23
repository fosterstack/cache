#!/usr/bin/env python3
"""Release authorization gate (REQ-AUD-11). The whole decision lives here so the
workflow step is three lines (R4: no embedded Python in the YAML).

  * Missing inventory + any `affected` statement in the candidate VEX  -> HOLD (fail closed).
  * Inventory present: COMPLETENESS — every `affected` CVE in the candidate VEX must appear
    in the inventory as an at-or-above item with an owner-decision issue number, else HOLD.
  * Each at-or-above item needs the owner's recorded acceptance on its issue: the first line
    of a comment by the owner login reads `ACCEPT <id> until <YYYY-MM-DD>`, the id
    token-equal, the date a REAL calendar date in the future. The LATEST owner comment wins,
    so a later `REJECT <id>` / `DO NOT ACCEPT <id>` revokes. An unknown threshold string HOLDs.
"""
import os, sys, re, json, datetime, glob
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auditorlib import cli, policy

ACCEPT = re.compile(r"^ACCEPT\s+(\S+)\s+until\s+(\d{4}-\d{2}-\d{2})\s*$")
REJECT = re.compile(r"^(?:REJECT|DO NOT ACCEPT)\s+(\S+)\b")


def _valid_future(datestr, today):
    try:
        d = datetime.datetime.strptime(datestr, "%Y-%m-%d").date()
    except ValueError:
        return False
    return d > datetime.datetime.strptime(today, "%Y-%m-%d").date()


def acceptance_verdict(issues, owner, number, cve, today):
    verdict = "none"
    for i in issues.get("issues", []):
        if i.get("number") != number:
            continue
        for c in i.get("comments", []):          # chronological; the latest owner decision wins
            if not isinstance(c, dict) or c.get("author") != owner:
                continue
            first = (c.get("body", "").splitlines() or [""])[0].strip()
            m = ACCEPT.match(first)
            if m and m.group(1) == cve and _valid_future(m.group(2), today):
                verdict = "accept"; continue
            r = REJECT.match(first)
            if r and r.group(1) == cve:
                verdict = "reject"
    return verdict == "accept"


def affected_cves(vex_dir):
    """Return (affected_cve_set, malformed_files). A malformed VEX is NOT silently ignored
    (R11 rank 7): it is a named hold reason."""
    cves = set(); malformed = []
    if vex_dir and os.path.isdir(vex_dir):
        for f in glob.glob(os.path.join(vex_dir, "*.json")):
            try:
                for s in json.load(open(f)).get("statements", []):
                    if s.get("status") == "affected":
                        n = (s.get("vulnerability") or {}).get("name")
                        if n:
                            cves.add(n)
            except Exception as e:
                malformed.append("%s (%s)" % (os.path.basename(f), e))
    return cves, malformed


def main():
    out = cli.opt("--out"); today = cli.opt("--today", "2026-09-22")
    owner = cli.opt("--owner", policy.OWNER_LOGIN)
    vex_dir = cli.opt("--vex-dir")
    aff, malformed = affected_cves(vex_dir)
    candpath = cli.opt("--candidate")
    if malformed:
        cli.writej(out, {"decision": "hold", "reasons": ["malformed candidate VEX: " + "; ".join(malformed)]}); return
    if not candpath or not os.path.exists(candpath):
        decision = "hold" if aff else "promote"
        cli.writej(out, {"decision": decision,
                         "reasons": (["affected VEX but no inventory (fail closed)"] if aff else [])})
        return
    cand = json.load(open(candpath))
    issues = json.load(open(cli.opt("--issues"))) if cli.opt("--issues") else {"issues": []}
    items = cand.get("accepted_items")
    decision = "promote"; reasons = []
    if items is None:
        cli.writej(out, {"decision": "hold", "reasons": ["no accepted_items field (fail closed)"]}); return
    by_cve = {it.get("cve"): it for it in items}
    # completeness (R11 rank 7): every affected CVE must appear in the inventory. An
    # at-or-above item additionally needs an owner issue + recorded acceptance (below); a
    # below-threshold item is exempt from acceptance and does NOT hold the release.
    for cve in sorted(aff):
        it = by_cve.get(cve)
        if not it:
            decision = "hold"; reasons.append("affected %s not in the candidate inventory" % cve)
        elif it.get("threshold") == "at_or_above" and not it.get("owner_issue"):
            decision = "hold"; reasons.append("affected at-or-above %s has no owner-decision issue" % cve)
    for it in items:
        if "cve" not in it or "threshold" not in it:
            decision = "hold"; reasons.append("item missing cve/threshold (fail closed)"); continue
        if it["threshold"] not in ("at_or_above", "below"):
            decision = "hold"; reasons.append("unknown threshold %r" % it["threshold"]); continue
        if it["threshold"] == "at_or_above":
            if not acceptance_verdict(issues, owner, it.get("owner_issue"), it["cve"], today):
                decision = "hold"; reasons.append("no current owner acceptance for %s" % it["cve"])
    cli.writej(out, {"decision": decision, "reasons": reasons})


if __name__ == "__main__":
    main()
