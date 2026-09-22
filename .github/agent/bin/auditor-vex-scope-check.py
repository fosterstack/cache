#!/usr/bin/env python3
"""Authored VEX products must be repository_url-scoped (REQ-AUD-4 AC2)."""
import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auditorlib import cli, policy


def main():
    src = cli.positional(0); out = cli.opt("--out"); authored = cli.opt("--authored-out")
    d = json.load(open(src)); prods = []
    for s in d.get("statements", []):
        for p in s.get("products", []):
            prods.append(p.get("@id", ""))
    all_scoped = bool(prods) and all("repository_url=%s" % policy.REPO_URL in p for p in prods)
    if authored:
        cli.writej(authored, d)
    cli.writej(out, {"all_scoped": all_scoped,
                     "offenders": [p for p in prods if "repository_url=%s" % policy.REPO_URL not in p]})


if __name__ == "__main__":
    main()
