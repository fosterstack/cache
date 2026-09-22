#!/usr/bin/env python3
"""Release authorization (REQ-AUD-11). Holds a tag whose candidate carries an
at-or-above-threshold accepted item unless the OWNER's acceptance is recorded on the
owner-decision ISSUE in the exact form:

    ACCEPT <finding-id> until <YYYY-MM-DD>

as the first line of a comment by the owner login, the id token-equal to the item and
the date in the future at authorization time. `DO NOT ACCEPT ...`, a mismatched id,
and a past date are holds. A PR review alone does not satisfy the gate. Missing fields
fail closed; below-threshold items never hold."""
import os, sys, re, json, datetime
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auditorlib import cli, policy

FORM = re.compile(r"^ACCEPT\s+(\S+)\s+until\s+(\d{4}-\d{2}-\d{2})\s*$")


def accepted_on_issue(issues, owner, number, cve, today):
    for i in issues.get("issues", []):
        if i.get("number") != number:
            continue
        for c in i.get("comments", []):
            if not isinstance(c, dict) or c.get("author") != owner:
                continue
            first = (c.get("body", "").splitlines() or [""])[0].strip()
            m = FORM.match(first)
            if m and m.group(1) == cve and m.group(2) > today:
                return True
    return False


def main():
    cand = json.load(open(cli.opt("--candidate")))
    issues = json.load(open(cli.opt("--issues")))
    owner = cli.opt("--owner", policy.OWNER_LOGIN)
    today = cli.opt("--today", "2026-09-22")
    out = cli.opt("--out")
    decision = "promote"; reasons = []
    items = cand.get("accepted_items")
    if items is None:
        decision = "hold"; reasons.append("no accepted_items field (fail closed)")
    for item in items or []:
        if "threshold" not in item or "cve" not in item:
            decision = "hold"; reasons.append("item missing threshold/cve (fail closed)"); continue
        if item["threshold"] == "at_or_above":
            if not accepted_on_issue(issues, owner, item.get("owner_issue"), item["cve"], today):
                decision = "hold"; reasons.append("no recorded owner acceptance for %s" % item["cve"])
    cli.writej(out, {"decision": decision, "reasons": reasons})


if __name__ == "__main__":
    main()
