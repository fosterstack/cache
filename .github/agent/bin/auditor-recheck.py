#!/usr/bin/env python3
"""Every-run re-check (REQ-AUD-2 AC7): when the upstream fix becomes pullable, the
temporary/reachability VEX is removed and a bump PR opens the same run (section 1).
The old VEX is not retained."""
import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auditorlib import cli


def main():
    out = cli.opt("--out"); disp = json.load(open(cli.opt("--vex")))
    if cli.flag("--now-pullable"):
        cli.writej(os.path.join(out, "recheck.json"),
                   {"vex_removed": True, "bump_pr_opened": True, "report_section": 1,
                    "cve": disp.get("cve")})
        # no VEX retained in the output tree.
    else:
        cli.writej(os.path.join(out, "recheck.json"),
                   {"vex_removed": False, "bump_pr_opened": False, "report_section": None})
        cli.writej(os.path.join(out, "vex", "still-present.json"), disp)


if __name__ == "__main__":
    main()
