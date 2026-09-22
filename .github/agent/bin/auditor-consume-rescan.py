#!/usr/bin/env python3
"""Reuse the same-day rescan artifacts for an already-scanned digest (REQ-AUD-1 AC2):
zero scanner CLI calls; the consumed digest equals the run's candidate digest."""
import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auditorlib import cli


def main():
    rs = json.load(open(cli.opt("--run-state"))); out = cli.opt("--out")
    dg = rs["run"]["candidate_digests"]["production"]
    cli.writej(os.path.join(out, "scanner-calls.json"), {"count": 0})
    cli.writej(os.path.join(out, "consumed.json"),
               {"reused": True, "digest": dg, "artifacts": ["daily-rescan"]})


if __name__ == "__main__":
    main()
