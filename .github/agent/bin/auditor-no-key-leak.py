#!/usr/bin/env python3
"""No key material is printed, committed, or written anywhere by the auditor
(REQ-AUD-6 AC4). The scan reports any credential-shaped material found under the
sealed directory; it never echoes a secret."""
import os, re, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auditorlib import cli

PAT = re.compile(r"sk-ant-[A-Za-z0-9-]{6,}")


def main():
    scan = cli.opt("--scan", "."); out = cli.opt("--out"); leaks = []
    for dp, _, fs in os.walk(scan):
        for fn in fs:
            p = os.path.join(dp, fn)
            try:
                if PAT.search(open(p, errors="ignore").read()):
                    leaks.append(p)
            except Exception:
                pass
    cli.writej(os.path.join(out, "leak.json"), {"leaks": leaks})


if __name__ == "__main__":
    main()
