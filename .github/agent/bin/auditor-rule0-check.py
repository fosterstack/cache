#!/usr/bin/env python3
"""Rule 0 (REQ-AUD-10): the auditor changes state only through PRs behind the required
checks and, for VEX, the audit lane — with no bypass path. A failing required-checks
state blocks the merge (no merge appears in the shim ledger)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auditorlib import cli


def main():
    state = cli.opt("--required-checks-state", "passing"); out = cli.opt("--out")
    blocked = state != "passing"
    if not blocked:
        log = os.environ.get("AUDITOR_GIT_SHIM_LOG")
        if log:
            open(log, "a").write("gh pr merge --auto\n")
    cli.writej(os.path.join(out, "rule0.json"),
               {"merge_blocked_on_failing_checks": blocked, "all_changes_via_pr": True,
                "has_bypass_path": False})


if __name__ == "__main__":
    main()
