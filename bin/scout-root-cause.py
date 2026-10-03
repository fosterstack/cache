#!/usr/bin/env python3
"""The Docker Scout root-cause round (advisor 0120/0121/0122; REQ-SCAN-004 AC2): why Scout applied none of our VEX forms.

  vex_doc   an OpenVEX document as vexctl writes it (Docker's documented path).
  cases     the matrix: Docker's documented control, then one field changed at a time (the --vex-author flag, a file path
            instead of a directory, our file name instead of *.vex.json, no subcomponent), then our forms on our image
            name — each on Scout 1.26.0 (pinned) and the two previous minors.
  pick      the target finding: one whose package carries exactly one CVE in the before report (deterministic).
  judge     suppressed only when the target is gone and every other finding is kept.

CLI (for bin/scout-root-cause.sh): doc, cases, pick, judge.
"""
import json
import sys
from collections import Counter

import importlib.util

_spec = importlib.util.spec_from_file_location("scout_selfcheck", __file__.rsplit("/", 1)[0] + "/scout-selfcheck.py")
_sc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_sc)
findings = _sc.findings          # one parser for Scout's GitLab report

VERSIONS = ("1.26.0", "1.25.0", "1.24.0")
CONTROL_IMAGE = "scoutcontrol/app:v1"
CONTROL_PRODUCT = "pkg:docker/scoutcontrol/app@v1"
OUR_IMAGE = "ghcr.io/fosterstack/cache:selfcheck"
OUR_BEST = "pkg:docker/ghcr.io/fosterstack/cache@selfcheck"
OUR_PUBLISHED = "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache"
STAMP = "2026-10-03T00:00:00Z"


def vex_doc(author, product, cve, sub):
    p = {"@id": product}
    if sub:
        p["subcomponents"] = [{"@id": sub}]
    return {"@context": "https://openvex.dev/ns/v0.2.0",
            "@id": "https://openvex.dev/docs/public/vex-scout-root-cause", "author": author, "timestamp": STAMP,
            "version": 1, "statements": [{"vulnerability": {"name": cve}, "timestamp": STAMP, "products": [p],
                                          "status": "not_affected",
                                          "justification": "vulnerable_code_not_in_execute_path"}]}


def cases():
    out = []
    for v in VERSIONS:
        doc = {"location": "dir", "file": "x.vex.json", "author_flag": False, "sub": True, "product": CONTROL_PRODUCT,
               "image": CONTROL_IMAGE}
        auth = dict(doc, author_flag=True)
        rows = [("control-doc", doc), ("control-author", auth), ("control-file", dict(auth, location="file")),
                ("control-openvex-name", dict(auth, file="x.openvex.json")), ("control-no-sub", dict(auth, sub=False)),
                ("ours-best-dir", dict(auth, product=OUR_BEST, image=OUR_IMAGE)),
                ("ours-published-dir", dict(auth, product=OUR_PUBLISHED, image=OUR_IMAGE)),
                ("ours-best-openvex-file", dict(auth, product=OUR_BEST, image=OUR_IMAGE, location="file",
                                                file="x.openvex.json"))]
        out += [dict(c, id="%s@%s" % (k, v), version=v) for k, c in rows]
    return out


def pick(before):
    per_pkg = Counter(pkg for (_cve, pkg, _ver) in before)
    one = sorted((cve, pkg) for (cve, pkg, _ver) in before if per_pkg[pkg] == 1)
    if not one:
        raise ValueError("no package with exactly one CVE in the before report")
    return one[0]


def judge(before, after, cve):
    if not any(k[0] == cve for k in before):
        return "inconclusive: the target is not in the before report"
    rest_b = Counter({k: n for k, n in before.items() if k[0] != cve})
    rest_a = Counter({k: n for k, n in after.items() if k[0] != cve})
    if rest_a != rest_b:
        return "inconclusive: findings other than the target changed"
    return "suppressed" if not any(k[0] == cve for k in after) else "not applied"


def main(argv):
    cmd = argv[0]
    if cmd == "doc":                       # doc AUTHOR PRODUCT CVE SUB|- OUT
        author, product, cve, sub, out = argv[1:6]
        json.dump(vex_doc(author, product, cve, None if sub == "-" else sub), open(out, "w"), indent=1)
    elif cmd == "cases":                   # one TSV row per case
        for c in cases():
            print("\t".join([c["id"], c["version"], c["image"], c["location"], c["file"],
                             "1" if c["author_flag"] else "0", "1" if c["sub"] else "0", c["product"]]))
    elif cmd == "pick":                    # pick BEFORE.json -> "CVE PURL"
        print("%s %s" % pick(findings(argv[1])))
    elif cmd == "judge":                   # judge BEFORE AFTER CVE
        print(judge(findings(argv[1]), findings(argv[2]), argv[3]))
    else:
        print("unknown command %s" % cmd, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
