#!/usr/bin/env python3
# Same-day reuse of Amazon Inspector results (REQ-REL-004-AC5).
#
#   key SBOM.json                 print a 16-hex key for the SBOM's inventory
#   decide DIR DATE KEY           print "reuse" and the stored path, or "call"
#   store DIR DATE KEY FILE       keep FILE as DIR/DATE/KEY.findings.json
#
# Why the SBOM and not the image digest: every commit stamps its id into the
# binary, so image digests never repeat; the package inventory does.
#
# The key is the sha256 of the sorted component identifiers (purl, else
# name@version) of .components[]. Our own module (github.com/fosterstack/cache,
# any version, any sub-package) is left out so it never depends on our build
# stamp. Metadata, serial numbers and timestamps are never read.
#
# DATE is an argument (the workflow passes the UTC date), so this program never
# reads the clock: the day boundary is UTC midnight at the time of the check.
# A stored result is reused only when it parses as JSON and is a CycloneDX
# document, bare or in ScanSbom's {"sbom": <document>} envelope (the shape
# bin/inspector-gate.py and bin/panel.py read). Anything else is "call".
# Pure python3, stdlib only, no network.
import hashlib
import json
import os
import re
import sys
import tempfile

OURS_NAME = re.compile(r"^github\.com/fosterstack/cache($|/)")
OURS_PURL = re.compile(r"^pkg:golang/github\.com/fosterstack/cache($|[@?#/])")
DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
KEY_RE = re.compile(r"^[0-9a-f]{16}$")


def inventory_key(path):
    with open(path, "rb") as f:
        doc = json.loads(f.read().decode("utf-8"))
    comps = doc.get("components") if isinstance(doc, dict) else None
    if not isinstance(comps, list) or not comps:
        raise ValueError("no components")
    ids = []
    for c in comps:
        if not isinstance(c, dict):
            raise ValueError("component is not an object")
        purl, name, ver = c.get("purl"), c.get("name"), c.get("version")
        if purl is not None and not isinstance(purl, str):
            raise ValueError("purl is not a string")
        if (purl and OURS_PURL.match(purl)) or (isinstance(name, str) and OURS_NAME.match(name)):
            continue
        if purl:
            ids.append(purl)
        elif isinstance(name, str) and name:
            ids.append(name + "@" + (ver if isinstance(ver, str) else ""))
        else:
            raise ValueError("component without purl or name")
    return hashlib.sha256(json.dumps(sorted(ids), separators=(",", ":")).encode()).hexdigest()[:16]


def valid_result(path):
    """A regular file (not a link) holding a CycloneDX document, bare or in the ScanSbom envelope."""
    if os.path.islink(path) or not os.path.isfile(path):
        return False
    with open(path, "rb") as f:
        doc = json.loads(f.read().decode("utf-8"))
    if isinstance(doc, dict) and isinstance(doc.get("sbom"), dict):
        doc = doc["sbom"]
    return isinstance(doc, dict) and doc.get("bomFormat") == "CycloneDX"


def stored_path(d, date, key):
    if not (DATE_RE.match(date) and KEY_RE.match(key)):
        raise ValueError("malformed date or key")
    return os.path.join(d, date, key + ".findings.json")


def cmd_decide(args):
    try:
        p = stored_path(*args[:3]) if len(args) == 3 else None
        if p and valid_result(p):
            return "reuse\n" + p
    except Exception:
        pass
    return "call"


def cmd_store(args):
    d, date, key, src = args
    dest = stored_path(d, date, key)
    if not valid_result(src):
        raise ValueError("not a CycloneDX result: nothing stored")
    ddir = os.path.dirname(dest)
    os.makedirs(ddir, exist_ok=True)
    with open(src, "rb") as f:
        data = f.read()
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=ddir)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, dest)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def main(argv):
    cmd, args = (argv[1] if len(argv) > 1 else ""), argv[2:]
    if cmd == "decide":
        print(cmd_decide(args))
        return 0
    try:
        if cmd == "key" and len(args) == 1:
            print(inventory_key(args[0]))
            return 0
        if cmd == "store" and len(args) == 4:
            cmd_store(args)
            return 0
    except Exception as e:
        print("inspector-reuse %s: %s" % (cmd, e), file=sys.stderr)
        return 1
    print("usage: inspector-reuse.py key SBOM | decide DIR DATE KEY | store DIR DATE KEY FILE", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
