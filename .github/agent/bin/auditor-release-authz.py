#!/usr/bin/env python3
"""Release authorization (REQ-AUD-11). Holds a tag whose candidate carries an
at-or-above-threshold accepted item unless the OWNER's acceptance is recorded on the
owner-decision ISSUE (a comment by the owner login on that issue number matching the
acceptance form). A PR review alone does not satisfy the gate; below-threshold items
never hold."""
import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auditorlib import cli


def accepted_on_issue(issues, owner, number, cve):
    for i in issues.get("issues", []):
        if i.get("number") == number:
            for c in i.get("comments", []):
                if isinstance(c, dict) and c.get("author") == owner and "ACCEPT" in c.get("body", "") and cve in c.get("body", ""):
                    return True
    return False


def main():
    cand = json.load(open(cli.opt("--candidate")))
    issues = json.load(open(cli.opt("--issues")))
    owner = cli.opt("--owner", issues.get("owner_login", "fosterstack-admin"))
    out = cli.opt("--out")
    decision = "promote"
    for item in cand.get("accepted_items", []):
        if item.get("threshold") == "at_or_above":
            if not accepted_on_issue(issues, owner, item.get("owner_issue"), item["cve"]):
                decision = "hold"
    cli.writej(out, {"decision": decision})


if __name__ == "__main__":
    main()
