#!/usr/bin/env python3
# Same-day reuse of Amazon Inspector results (REQ-REL-004-AC5).
#
#   key SBOM.json                  print the key (full sha256, 64 hex) of the SBOM's package inventory
#   decide DIR DATE SBOM.json      print "reuse" and the stored path, or "call"
#   store DIR DATE SBOM.json FILE  keep FILE as DIR/DATE/<key of SBOM>.findings.json; refuse otherwise
#
# Why the SBOM and not the image digest: every commit stamps its id into the
# binary, so image digests never repeat; the package inventory does.
#
# The key is the sha256 of the sorted component identifiers of .components[]:
# the purl with its qualifiers and subpath stripped (everything from "?" or
# "#") when there is one, else name@version. Our own module
# (github.com/fosterstack/cache, any version, any sub-package) is left out so
# it never depends on our build stamp. Metadata, serial numbers and timestamps
# are never read. An SBOM with no identifiers has no key (never a constant).
#
# A stored file is reused only when it is Inspector's ScanSbom answer for THIS
# inventory: a JSON object {"sbom": <CycloneDX object with a "components" list>}
# (the envelope bin/inspector-gate.py and bin/panel.py read) whose own
# components give the same key as the requested SBOM. It must be a regular file
# (never a link) at DIR/DATE/KEY.findings.json whose real path lies under DIR.
# `store` verifies FILE the same way before it copies anything.
#
# DATE is an argument (the workflow reads the UTC clock at each decision and
# each store), so this program never reads the clock.
# Pure python3, stdlib only, no network.
import hashlib
import json
import os
import re
import sys
import tempfile

OURS_NAME = re.compile(r"^github\.com/fosterstack/cache($|/)")
OURS_PURL = re.compile(r"^pkg:golang/github\.com/fosterstack/cache($|[@?#/])")
DATE_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
KEY_RE = re.compile(r"[0-9a-f]{64}")


def component_key(comps):
    """The key of a component list; ValueError when it has no usable inventory."""
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
            ids.append(re.split(r"[?#]", purl, maxsplit=1)[0])
        elif isinstance(name, str) and name:
            ids.append(name + "@" + (ver if isinstance(ver, str) else ""))
        else:
            raise ValueError("component without purl or name")
    if not ids:
        raise ValueError("no package identifiers: an empty inventory has no key")
    return hashlib.sha256(json.dumps(sorted(ids), separators=(",", ":")).encode()).hexdigest()


def read_json(path):
    with open(path, "rb") as f:
        return json.loads(f.read().decode("utf-8"))


def inventory_key(path):
    doc = read_json(path)
    return component_key(doc.get("components") if isinstance(doc, dict) else None)


def envelope_key(doc):
    """The inventory key of a ScanSbom envelope, or ValueError when it is not one."""
    sbom = doc.get("sbom") if isinstance(doc, dict) else None
    if not isinstance(sbom, dict) or sbom.get("bomFormat") != "CycloneDX":
        raise ValueError("not a ScanSbom envelope")
    return component_key(sbom.get("components"))


def check_answer(path, key):
    """FILE must be the ScanSbom envelope for the inventory with this key."""
    if envelope_key(read_json(path)) != key:
        raise ValueError("the answer is for another inventory")


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
        key = inventory_key(sbom)
        p = stored_path(d, date, key)
        if os.path.isfile(p):
            check_answer(p, key)
            return "reuse\n" + p
    except Exception:
        pass
    return "call"


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def cmd_store(args):
    d, date, sbom, src = args
    key = inventory_key(sbom)
    dest = stored_path(d, date, key)
    check_answer(src, key)
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
            print(inventory_key(args[0]))
            return 0
        if cmd == "store" and len(args) == 4:
            cmd_store(args)
            return 0
    except Exception as e:
        print("inspector-reuse %s: %s" % (cmd, e), file=sys.stderr)
        return 1
    print("usage: inspector-reuse.py key SBOM | decide DIR DATE SBOM | store DIR DATE SBOM FILE", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
