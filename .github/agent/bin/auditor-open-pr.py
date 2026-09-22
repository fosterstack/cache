#!/usr/bin/env python3
"""Every change is a branch PR (REQ-AUD-5). VEX/.vex changes route to the audit lane,
version pins to auto-merge. Never a direct push to main, never a tag, never a public
post. Actions are recorded through a git/gh shim ledger."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auditorlib import cli


def shim(line):
    log = os.environ.get("AUDITOR_GIT_SHIM_LOG")
    if log:
        with open(log, "a") as f:
            f.write(line + "\n")


def main():
    change = cli.opt("--change", "vex"); out = cli.opt("--out")
    lane = "audit" if change in ("vex", "ignore") else "auto-merge"
    branch = "auditor/%s-update" % change
    shim("git checkout -b %s" % branch)
    shim("git commit -m auditor:%s" % change)
    shim("gh pr create --head %s --base main --label %s-lane" % (branch, lane))
    cli.writej(os.path.join(out, "pr.json"),
               {"via_branch_pr": True, "lane": lane, "branch": branch,
                "direct_to_main": False, "creates_tag": False, "public_post": False})


if __name__ == "__main__":
    main()
