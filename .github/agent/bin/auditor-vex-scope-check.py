#!/usr/bin/env python3
"""Authored VEX products must be repository_url-scoped (REQ-AUD-4 AC2)."""
import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auditorlib import cli, policy


def main():
    src = cli.positional(0); out = cli.opt("--out"); authored = cli.opt("--authored-out")
    import urllib.parse as up
    d = json.load(open(src)); prods = []
    for st in d.get("statements", []):
        for pr in st.get("products", []):
            prods.append(pr.get("@id", ""))
    def scoped(pid):
        q = up.parse_qs(up.urlsplit(pid).query)
        return q.get("repository_url", [None])[0] in (policy.REPO_URL, policy.REPO_URL + "-candidates")
    all_scoped = bool(prods) and all(scoped(pid) for pid in prods)
    offenders = [pid for pid in prods if not scoped(pid)]
    if authored and all_scoped:
        cli.writej(authored, d)   # only re-emit a properly scoped document
    cli.writej(out, {"all_scoped": all_scoped, "offenders": offenders})


if __name__ == "__main__":
    main()
