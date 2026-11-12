#!/usr/bin/env python3
"""Known-defect log (REQ-AUD-3): EXACT dictionary lookup keyed verbatim by
(scanner, finding_id, purl). No normalization, no version-range comparison. A hit
closes with no model call; a miss may be adjudicated once, and the model's answer is
recorded as a new exact key on the row so the next run is a code-only hit. The
finding-set hash is content-derived (sha256 of the sorted key set), independent of
any filename.
"""
import os, sys, json, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auditorlib import cli
from auditorlib import reviewed
from auditorlib import parsers as P


def index(log):
    idx = {}
    for row in log.get("defects", []):
        for k in row["keys"]:
            idx[(k["scanner"], k["finding_id"], k["purl"])] = row
    return idx


def load(path):
    """A run-internal file (the findings): a plain JSON read."""
    return json.load(open(path))


def load_log(path):
    """The known-defect log through the shared required-content reader: a missing or keyless log is a stop, never an empty history (cache#701)."""
    try:
        log = reviewed.read(path, as_name="known-defect-log.json")
    except reviewed.ReviewedInputInvalid as e:
        sys.exit("defectlog: %s" % e)
    if log is None:
        sys.exit("defectlog: the log %s does not exist" % path)
    return log


def set_hash(findings):
    keys = sorted("%s|%s|%s" % (f["scanner"], f["finding_id"], f["purl"]) for f in findings)
    return hashlib.sha256("\n".join(keys).encode()).hexdigest()


def do_probe(out):
    log = load_log(cli.opt("--log")); idx = index(log)
    a = cli.ARGS
    hs, hi, hp = a[a.index("--hit") + 1:a.index("--hit") + 4]
    hitrow = idx.get((hs, hi, hp))
    result = {"hit": hitrow is not None,
              "hit_disposition": hitrow["disposition"] if hitrow else None,
              "hit_product": (hitrow.get("package") if hitrow else None)}
    if "--miss" in a:
        ms, mi, mp = a[a.index("--miss") + 1:a.index("--miss") + 4]
        result["miss"] = (ms, mi, mp) in idx
    else:
        result["miss"] = False
    cli.writej(os.path.join(out, "probe.json"), result)


def do_run(out):
    logpath = cli.opt("--log"); log = load_log(logpath); idx = index(log)
    findings = load(cli.opt("--findings"))["findings"]
    adjudicator = cli.opt("--adjudicator"); append = cli.flag("--append")
    closed, misses, model_calls = [], [], 0
    for f in findings:
        key = (f["scanner"], f["finding_id"], f["purl"])
        row = idx.get(key)
        if row:                                    # code-only hit
            closed.append({"finding_id": f["finding_id"], "disposition": row["disposition"]})
        else:
            misses.append(dict(f))
            if append:
                ans = cli.ask_model(adjudicator, f["finding_id"]); model_calls += 1
                log["defects"].append({"keys": [{"scanner": f["scanner"],
                                                  "finding_id": f["finding_id"], "purl": f["purl"]}],
                                       "package": f.get("finding_id"),
                                       "affected_version_range": "evidence only",
                                       "disposition": "proposed", "model_suggestion": ans.get("category"),
                                       "vex_id": None, "evidence": "adjudicated on miss",
                                       "date": "2026-09-22"})
    if append:
        json.dump(log, open(logpath, "w"), indent=1)
    cli.writej(os.path.join(out, "result.json"),
               {"closed": closed, "misses": misses, "finding_set_hash": set_hash(findings),
                "total_model_calls": model_calls})


def do_reconcile(out):
    logpath = cli.opt("--log"); log = load_log(logpath)
    a = cli.ARGS; sc, fid, purl = a[a.index("--finding") + 1:a.index("--finding") + 4]
    adjudicator = cli.opt("--adjudicator"); manifest = cli.opt("--manifest")
    readers = {}
    if manifest:                                             # no readable report is "unavailable", decided before any model is asked
        readers = {n: (fn, path) for n, fn, path in P.manifest_readers(json.load(open(manifest)))}
        fn, rpt = readers.get(sc, (None, None))
        try:
            records = fn(rpt) if (fn and rpt) else None
        except (P.ParseError, OSError):
            records = None
        if records is None:
            cli.writej(os.path.join(out, "reconcile.json"), {"added": False, "reason": "scanner report unavailable (it did not run, or its report cannot be read)"})
            return
    ans = cli.ask_model(adjudicator, fid)                    # PROPOSAL: same defect?
    if not ans.get("same_defect"):
        cli.writej(os.path.join(out, "reconcile.json"), {"added": False, "reason": "model: not the same defect"})
        return
    # the scanner must actually report this exact (id/alias, purl).
    reported = False
    for f in (records if manifest else []):
        if (fid == f["finding_id"] or fid in f["aliases"]) and f["purl"] == purl:
            reported = True
    if not reported:
        cli.writej(os.path.join(out, "reconcile.json"), {"added": False, "reason": "scanner does not report this purl"})
        return
    target = None
    for row in log["defects"]:
        if any(k["finding_id"] == fid or fid in [x for k2 in row["keys"] for x in (k2["finding_id"],)] for k in row["keys"]):
            target = row; break
    if target is None:
        cli.writej(os.path.join(out, "reconcile.json"), {"added": False, "reason": "no row names this finding"})
        return
    target["keys"].append({"scanner": sc, "finding_id": fid, "purl": purl})
    json.dump(log, open(logpath, "w"), indent=1)
    cli.writej(os.path.join(out, "reconcile.json"), {"added": {"scanner": sc, "finding_id": fid, "purl": purl}})


def main():
    op = cli.positional(0); out = cli.opt("--out")
    if op == "probe": do_probe(out)
    elif op == "run": do_run(out)
    elif op == "reconcile": do_reconcile(out)
    else: sys.exit("defectlog: unknown op %r" % op)


if __name__ == "__main__":
    main()
