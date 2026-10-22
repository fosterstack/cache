"""Panel-verdict fixtures that follow the panel's image set (bin/panel.py VARIANTS), not a literal six-image list.

The committed run fixtures (fixtures/run/panel-*/verdict.json) were written for one VARIANTS set. Main ships v0.2.2 with the debug variant
(six images); chain-v030 drops it (four). A verdict names the panel's fixed image set exactly, so a fixture written for one set is refused
under the other. `adapt` turns a fixture verdict into a valid one for the CURRENT set: images the set does not have are dropped with their
findings; an image the fixture lacks is filled with every expected scanner having run; the derived lists (not_counted, scanner_failures,
unique, issue, exit) are recomputed. Under the set the fixture was written for, `adapt` changes nothing.

`materialize <dir>` adapts every <dir>/panel-*/verdict.json in place and repoints every <dir>/manifest-*.json at the adapted copy (the
manifest's panel block is rebuilt from it, so the per-scanner image counts follow too). The matrix suite runs it on a copy of the run
fixtures; the Python tests use `fixture_verdict` for a temporary adapted copy of one verdict.
"""
import copy, glob, importlib.util, json, os, sys, tempfile

BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FIX = os.path.abspath(os.path.join(BIN, "..", "fixtures"))
sys.path.insert(0, BIN)
from auditorlib import parsers as P  # noqa: E402


def adapt(d):
    pm = P._panel_module()
    want = sorted(P.panel_images())
    out = copy.deepcopy(d)
    images = {}
    for im in want:
        if im in d["images"]:
            images[im] = copy.deepcopy(d["images"][im])
        else:                                            # an image the fixture never had: every scanner expected there ran
            ran = sorted(s for s in P.PANEL_SCANNERS if P.panel_expected(s, im))
            images[im] = {"counts": {s: 10 for s in ran}, "did_not_run": [], "ran": ran, "counts_for_day": len(ran) >= pm.QUORUM}
    out["images"] = images
    out["findings"] = [f for f in out["findings"] if f["image"] in images]
    out["vex_covered"] = [c for c in out["vex_covered"] if c["image"] in images]
    out["not_counted"] = sorted(i for i, st in images.items() if not st["counts_for_day"])
    out["scanner_failures"] = sorted("%s on %s" % (s, i) for i, st in images.items() for s in st["did_not_run"])
    out["unique"] = [f for f in out["findings"] if f["unique"]]
    reported = [f for f in out["findings"] if f["status"] == "report"]
    out["issue"] = pm.render_issue(reported)
    out["exit"] = 2 if (out["not_counted"] or out["scanner_failures"]) else (1 if reported else 0)
    return out


def fixture_verdict(name, keep):
    """A temporary adapted copy of fixtures/run/<name>/verdict.json; `keep` is a list the caller's cleanup owns."""
    d = adapt(json.load(open(os.path.join(FIX, "run", name, "verdict.json"))))
    fd, path = tempfile.mkstemp(suffix=".json"); os.close(fd)
    with open(path, "w") as fh:
        json.dump(d, fh)
    keep.append(path)
    return path


def materialize(rundir):
    rundir = os.path.abspath(rundir)
    spec = importlib.util.spec_from_file_location("auditor_manifest_fx", os.path.join(BIN, "auditor-manifest.py"))
    M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)
    for vp in sorted(glob.glob(os.path.join(rundir, "panel-*", "verdict.json"))):
        with open(vp) as fh:
            d = adapt(json.load(fh))
        with open(vp, "w") as fh:
            json.dump(d, fh, indent=1, sort_keys=True)
    for mp in sorted(glob.glob(os.path.join(rundir, "manifest-*.json"))):
        with open(mp) as fh:
            m = json.load(fh)
        tag = os.path.basename(mp)[len("manifest-"):-len(".json")]
        pdir = os.path.join(rundir, "panel-" + tag)
        if os.path.exists(os.path.join(pdir, "verdict.json")):
            m["panel"] = M.panel_block(pdir)
            m["scanner_reports"] = m["panel"]["scanner_reports"]; m["scanner_status"] = m["panel"]["scanner_status"]
        with open(mp, "w") as fh:
            json.dump(m, fh, indent=1)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "materialize":
        materialize(sys.argv[2])
    else:
        sys.exit("usage: verdict_fixture.py materialize <run fixtures dir>")
