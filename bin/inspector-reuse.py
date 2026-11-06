#!/usr/bin/env python3
# Same-day reuse of Amazon Inspector results (REQ-REL-004-AC8).
#
#   key SBOM.json                  print the key (full sha256, 64 hex) of the SBOM's package inventory
#   decide DIR DATE SBOM.json      print "reuse" and the stored path, or "call"
#   validate SBOM.json FILE        exit 0 only if FILE is the ScanSbom envelope for that SBOM; writes nothing
#   store DIR DATE SBOM.json FILE  keep FILE as DIR/DATE/<key of SBOM>.findings.json; refuse otherwise
#
# Why the SBOM and not the image digest: every commit stamps its id into the
# binary, so image digests never repeat; the package inventory does.
#
# The key is the sha256 of the sorted component identifiers of the REQUEST SBOM.
# An identifier is the structured pair [name, version] (never a joined string, so
# a name containing "@" cannot collide): parsed from the purl when the component
# has one (namespace kept in the name, type, qualifiers and subpath dropped,
# percent-decoded), since the ScanSbom service rewrites the name and version
# fields of Go modules; else its name and version fields (version "" if absent).
# Our own module (github.com/fosterstack/cache, any version, any sub-package) is
# left out so it never depends on our build stamp. Metadata, serial numbers and
# timestamps are never read. An SBOM with no identifiers has no key.
#
# A stored or fresh answer is accepted only when it is Inspector's ScanSbom
# envelope {"sbom": <CycloneDX object with a "components" list>} (the shape
# bin/inspector-gate.py and bin/panel.py read) whose component identifiers
# INCLUDE every identifier of the request SBOM (a superset: the service adds
# components; an extra can only add identifiers, never hide a finding for the
# requested set). It is a regular file (never a link) at
# DIR/DATE/<key of the request>.findings.json whose real path lies under DIR.
# `store` verifies FILE the same way before it copies anything.
#
# DATE is an argument (the workflow reads the UTC clock at each decision and
# each store), so this program never reads the clock.
# Pure python3, stdlib only, no network.
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import re
import sys
import tempfile
import urllib.parse

OURS_NAME = re.compile(r"^github\.com/fosterstack/cache($|/)")
OURS_PURL = re.compile(r"^pkg:golang/github\.com/fosterstack/cache($|[@?#/])")
DATE_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
KEY_RE = re.compile(r"[0-9a-f]{64}")


def purl_name_version(purl):
    """pkg:<type>/<namespace>/<name>@<version>?q#sub -> ("<namespace>/<name>", "<version>"), percent-decoded;
    the type, qualifiers and subpath are dropped, the namespace stays in the name part."""
    s = re.split(r"[?#]", purl, maxsplit=1)[0]
    if s.startswith("pkg:"):
        s = s[4:]
    s = s.split("/", 1)[1] if "/" in s else s     # drop the type
    name, _, ver = s.rpartition("@") if "@" in s else (s, "", "")
    name, ver = urllib.parse.unquote(name), urllib.parse.unquote(ver)
    if not name:
        raise ValueError("purl without a name")
    return (name, ver)


def component_pairs(comps, strict):
    """The identifiers of a component list: STRUCTURED (name, version) pairs, never a joined string (a name containing "@"
    cannot collide with another name/version split). A component with a purl is identified by the pair parsed from the
    purl (the service rewrites the name and version fields of Go modules); one without, by its name and version fields
    (version "" when absent). Our own module is left out. strict: an unusable component is an error (the request SBOM);
    otherwise it is skipped (the response: an unreadable extra can only make the binding fail, never pass)."""
    if not isinstance(comps, list):
        raise ValueError("no components")
    pairs = []
    for c in comps:
        try:
            if not isinstance(c, dict):
                raise ValueError("component is not an object")
            purl, name, ver = c.get("purl"), c.get("name"), c.get("version")
            if purl is not None and not isinstance(purl, str):
                raise ValueError("purl is not a string")
            if (purl and OURS_PURL.match(purl)) or (isinstance(name, str) and OURS_NAME.match(name)):
                continue
            if purl:
                pairs.append(purl_name_version(purl))
            elif isinstance(name, str) and name:
                pairs.append((name, ver if isinstance(ver, str) else ""))
            else:
                raise ValueError("component without purl or name")
        except ValueError:
            if strict:
                raise
    return pairs


def request_pairs(comps):
    pairs = component_pairs(comps, True)
    if not pairs:
        raise ValueError("no package identifiers: an empty inventory has no key")
    return pairs


def pairs_key(pairs):
    return hashlib.sha256(json.dumps(sorted([list(p) for p in pairs]), separators=(",", ":")).encode()).hexdigest()


def read_json(path):
    with open(path, "rb") as f:
        return json.loads(f.read().decode("utf-8"))


def inventory_pairs(path):
    doc = read_json(path)
    return request_pairs(doc.get("components") if isinstance(doc, dict) else None)


def _finding_ok(v):
    """A finding both readers can use: an id, a NON-empty list of affected components each naming its bom-ref (the gate reads affects[].ref, the panel drops
    a finding with no affects, so a missing or empty list would read as clean there), and ratings, when present, as objects."""
    if not (isinstance(v, dict) and isinstance(v.get("id"), str) and v["id"]):
        return False
    aff = v.get("affects")
    if not (isinstance(aff, list) and aff and all(isinstance(a, dict) and isinstance(a.get("ref"), str) and a["ref"] for a in aff)):
        return False
    return "ratings" not in v or (isinstance(v["ratings"], list) and all(isinstance(r, dict) and ("severity" not in r or isinstance(r["severity"], str)) for r in v["ratings"]))


def _load_sibling(name, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(os.path.dirname(os.path.abspath(__file__)), filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _readers_consume(sbom_path, answer_path, doc):
    """The readers are the judge: the answer is reusable only if bin/inspector-gate.py and bin/panel.py both consume it without an exception and neither drops a
    finding (each (finding, affected component) pair becomes one row in the gate and one in the panel). Shape rules above stay as the reasons that are named; this
    closes the class of shapes they cannot list one by one. The gate runs with an empty VEX document held in memory (nothing is read or written)."""
    sbom = read_json(sbom_path)
    scan = doc["sbom"]
    for what in (sbom, doc):   # text the readers print must be encodable: a lone surrogate parses as JSON but cannot be written out
        try:
            json.dumps(what, ensure_ascii=False).encode("utf-8")
        except UnicodeEncodeError:
            raise ValueError("the document holds text that cannot be written out")
    want = sum(len(v["affects"]) for v in scan.get("vulnerabilities") or [])
    try:
        panel = _load_sibling("_panel_probe", "panel.py")
        comps = [c for c in sbom.get("components") or [] if isinstance(c, dict)]
        # the panel's own request-side reading (read_inspector): a CycloneDX envelope and a positive package count, else it discards the findings ("did not run")
        if sbom.get("bomFormat") != "CycloneDX" or not panel._cdx_packages(sbom):
            raise ValueError("the request SBOM is not one the panel reads")
        rows = panel._cdx_findings(scan, comps)
        for r in rows:
            panel.key_of("probe", r[0], r[1], r[2])   # the panel's own per-finding key (tally): the step that reads a version as text
        gate = _load_sibling("_gate_probe", "inspector-gate.py")
        real_load = gate.load
        gate.load = lambda p: {"@context": "https://openvex.dev/ns/v0.2.0", "statements": []} if p == "<empty-vex>" else real_load(p)
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            rc = gate.main(["inspector-gate.py", "probe", sbom_path, answer_path, "<empty-vex>"])
    except Exception as e:
        raise ValueError("a reader cannot consume the answer: %s" % type(e).__name__)
    m = re.search(r", (\d+) finding\(s\)", out.getvalue())
    if len(rows) != want or rc != (1 if want else 0) or not m or int(m.group(1)) != want:
        raise ValueError("a reader would drop or miscount a finding")


def check_answer(path, req_pairs, sbom_path=None):
    """FILE must be the ScanSbom envelope {"sbom": <CycloneDX with a components list>} that carries EVERY identifier of the
    request SBOM (a superset: the service adds components of its own). An extra response component only adds
    identifiers; it can never hide a finding for the requested set, because a finding is read from the component it
    affects and every requested component is present."""
    doc = read_json(path)
    sbom = doc.get("sbom") if isinstance(doc, dict) else None
    if not isinstance(sbom, dict) or sbom.get("bomFormat") != "CycloneDX" or not isinstance(sbom.get("components"), list):
        raise ValueError("not a ScanSbom envelope")
    if not set(req_pairs) <= set(component_pairs(sbom["components"], True)):
        raise ValueError("the answer does not cover the requested inventory")
    # a findings field that is present must be a list of objects that each carry an id: anything else would read as "no findings" in the gate
    # (`or []`), so it is refused here (fail closed); an absent field is the service's answer for an image without findings
    if "vulnerabilities" in sbom:
        vs = sbom["vulnerabilities"]
        if not isinstance(vs, list) or not all(_finding_ok(v) for v in vs):
            raise ValueError("the findings field is not a list of well-formed findings")
        # reference integrity: both readers look a finding's component up by bom-ref in a dictionary where the last duplicate wins, so the references of the
        # answer's components must be non-empty unique strings and every affected ref must resolve to exactly one of them
        refs = [c["bom-ref"] for c in sbom["components"] if isinstance(c, dict) and "bom-ref" in c]
        if not all(isinstance(r, str) and r for r in refs) or len(set(refs)) != len(refs):
            raise ValueError("the component references are not non-empty unique strings")
        known = set(refs)
        if not all(a["ref"] in known for v in vs for a in v["affects"]):
            raise ValueError("a finding names a component the answer does not carry")
    if sbom_path is not None:
        _readers_consume(sbom_path, path, doc)


def stored_path(d, date, key):
    if not (DATE_RE.fullmatch(date) and KEY_RE.fullmatch(key)):
        raise ValueError("malformed date or key")
    dest = os.path.join(d, date, key + ".findings.json")
    # no link anywhere between DIR and the file: the real path is exactly DIR/DATE/KEY
    if os.path.islink(os.path.join(d, date)) or os.path.islink(dest):
        raise ValueError("a link in the cache path")
    if os.path.join(os.path.realpath(d), date, key + ".findings.json") != os.path.realpath(dest):
        raise ValueError("the cache path leaves the cache directory")
    return dest


def cmd_decide(args):
    try:
        d, date, sbom = args
        pairs = inventory_pairs(sbom)
        p = stored_path(d, date, pairs_key(pairs))
        if os.path.isfile(p):
            check_answer(p, pairs, sbom)
            return "reuse\n" + p
    except Exception:
        pass
    return "call"


def cmd_validate(args):
    sbom, src = args
    check_answer(src, inventory_pairs(sbom), sbom)


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def cmd_store(args):
    d, date, sbom, src = args
    pairs = inventory_pairs(sbom)
    key = pairs_key(pairs)
    dest = stored_path(d, date, key)
    check_answer(src, pairs, sbom)
    with open(src, "rb") as f:
        data = f.read()
    ddir = os.path.dirname(dest)
    os.makedirs(ddir, exist_ok=True)
    stored_path(d, date, key)   # again, now that the directory exists
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=ddir)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, dest)
        fsync_dir(ddir)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def main(argv):
    cmd, args = (argv[1] if len(argv) > 1 else ""), argv[2:]
    if cmd == "decide":
        print(cmd_decide(args) if len(args) == 3 else "call")
        return 0
    try:
        if cmd == "key" and len(args) == 1:
            print(pairs_key(inventory_pairs(args[0])))
            return 0
        if cmd == "validate" and len(args) == 2:
            cmd_validate(args)
            return 0
        if cmd == "store" and len(args) == 4:
            cmd_store(args)
            return 0
    except Exception as e:
        print("inspector-reuse %s: %s" % (cmd, e), file=sys.stderr)
        return 1
    print("usage: inspector-reuse.py key SBOM | decide DIR DATE SBOM | store DIR DATE SBOM FILE | validate SBOM FILE", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
