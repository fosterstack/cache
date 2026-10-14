#!/usr/bin/env python3
"""Dependency provenance for the vendored tree (REQ-VEND-001): check and build dependency-provenance.json, and write the evidence file
the release assembles.

  vendor-provenance.py check    --vendor-dir DIR --go-sum FILE --provenance FILE
  vendor-provenance.py build    --vendor-dir DIR --go-sum FILE --sumdb-record FILE --origins FILE --licenses FILE [--recorded-origins FILE] --out FILE
  vendor-provenance.py evidence --out DIR --provenance FILE --govulncheck FILE --date EPOCH

Run from the repository root. Every input is a file; nothing here reaches the network, reads the environment, runs another program or
signs anything (the release job signs vendor-evidence.json afterwards). The records `build` reads (the checksum-log record, the origins,
the reviewed licenses file) are produced by a separate CI step; the licence id comes from the committed, reviewed licenses file. A module
the module cache has no Origin for takes its origin from the committed, reviewed --recorded-origins file (test-evidence/dependency-origins.yaml,
JSON text: one entry per such module with module, version, url, commit and the command that produced it); an entry for any other module is refused.
Exit codes: 0 done | 2 refused (a bad argument, an unreadable or malformed input, a gap in the records; naming the cause) | 1 internal.
check and build write nothing on a refusal; evidence writes nothing, not even its directory, on a refusal.
"""
import datetime
import hashlib
import json
import os
import re
import stat
import sys

SCHEMA = "fosterstack/dependency-provenance/v1"
EVIDENCE_SCHEMA = "fosterstack/vendor-evidence/v1"
MAX_BYTES = 16 * 1024 * 1024
MAX_EPOCH = 253402300799
H1 = re.compile(r"h1:[A-Za-z0-9+/]{43}=")
PSEUDO = re.compile(r"-[0-9]{14}-[0-9a-f]{12}$")
COMMIT = re.compile(r"[0-9a-f]{40}")
EPOCH = re.compile(r"0|[1-9][0-9]*")
MODULE_KEYS = {"path", "version", "go_sum_hash", "checksum_log", "origin", "license"}


class Refused(Exception):
    pass


def refuse(msg):
    raise Refused(msg)


def read_regular(path, what):
    """the bytes of a regular, non-empty file within the size bound (a link, a directory or a device is refused)"""
    try:
        st = os.lstat(path)
    except OSError as e:
        refuse("%s %s: %s" % (what, path, e.strerror))
    if not stat.S_ISREG(st.st_mode):
        refuse("%s %s is not a regular file" % (what, path))
    if st.st_size == 0:
        refuse("%s %s is empty" % (what, path))
    if st.st_size > MAX_BYTES:
        refuse("%s %s is over 16 MiB" % (what, path))
    with open(path, "rb") as fh:
        return fh.read()


def _no_dup(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            refuse("repeated key %r" % k)
        d[k] = v
    return d


def load_json(raw, what):
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_no_dup)
    except (UnicodeDecodeError, ValueError) as e:
        refuse("%s is not valid JSON: %s" % (what, e))


def parse_args(argv, flags, optional=()):
    """--flag VALUE pairs, each of FLAGS exactly once and each of OPTIONAL at most once, nothing else"""
    got = {}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a not in flags and a not in optional:
            refuse("unknown argument %r" % a)
        if a in got:
            refuse("%s given twice" % a)
        if i + 1 >= len(argv):
            refuse("%s needs a value" % a)
        got[a] = argv[i + 1]
        i += 2
    missing = [f for f in flags if f not in got]
    if missing:
        refuse("missing %s" % ", ".join(missing))
    return got


def modules_txt(vendor_dir):
    """{(path, version)} of vendor/modules.txt: the '# path version' lines; a replacement is refused"""
    raw = read_regular(os.path.join(vendor_dir, "modules.txt"), "vendor/modules.txt")
    mods = set()
    for n, line in enumerate(raw.decode("utf-8", "replace").split("\n"), 1):
        if not line.startswith("# "):
            continue
        parts = line[2:].split(" ")
        if "=>" in parts:
            refuse("vendor/modules.txt:%d: a replaced module (%s)" % (n, line[2:]))
        if len(parts) != 2 or not parts[1].startswith("v"):
            refuse("vendor/modules.txt:%d: not a module line: %r" % (n, line))
        mods.add((parts[0], parts[1]))
    if not mods:
        refuse("vendor/modules.txt lists no module")
    return mods


def go_sum(path):
    """{(path, version): h1 hash of the module's code}; the /go.mod lines are not the module hash"""
    out = {}
    for n, line in enumerate(read_regular(path, "go.sum").decode("utf-8", "replace").split("\n"), 1):
        if not line.strip():
            continue
        parts = line.split(" ")
        if len(parts) != 3:
            refuse("go.sum:%d: not a go.sum line" % n)
        mod, ver, h = parts
        if ver.endswith("/go.mod"):
            continue
        out[(mod, ver)] = h
    return out


def module_gap(m, where):
    """the first reason a provenance entry is not complete and well formed, else None"""
    if not isinstance(m, dict) or set(m) != MODULE_KEYS:
        return "%s: not exactly the fields %s" % (where, sorted(MODULE_KEYS))
    for k in ("path", "version", "go_sum_hash", "license"):
        if not isinstance(m[k], str) or not m[k]:
            return "%s: %s is empty" % (where, k)
    if not H1.fullmatch(m["go_sum_hash"]):
        return "%s: go_sum_hash is not an h1: hash" % where
    log = m["checksum_log"]
    if not isinstance(log, dict) or set(log) != {"included", "log"} or log["included"] is not True \
            or not isinstance(log["log"], str) or not log["log"]:
        return "%s: the checksum-log entry is not {included: true, log: <name>}" % where
    o = m["origin"]
    pseudo = bool(PSEUDO.search(m["version"]))
    want = {"url", "commit"} if pseudo else {"url", "tag"}
    if not isinstance(o, dict) or set(o) != want:
        return "%s: origin must hold exactly %s for a %s" % (where, sorted(want), "pseudo-version" if pseudo else "tagged version")
    if not isinstance(o["url"], str) or not o["url"].startswith("https://") or len(o["url"]) <= len("https://"):
        return "%s: the origin url is not an https address" % where
    if pseudo and not (isinstance(o["commit"], str) and COMMIT.fullmatch(o["commit"])):
        return "%s: the origin commit is not 40 hex characters" % where
    if not pseudo and not (isinstance(o["tag"], str) and o["tag"]):
        return "%s: the origin tag is empty" % where
    return None


def read_provenance(raw, what):
    doc = load_json(raw, what)
    if not isinstance(doc, dict) or set(doc) != {"schema", "modules"} or doc["schema"] != SCHEMA:
        refuse("%s is not schema %s" % (what, SCHEMA))
    if not isinstance(doc["modules"], list) or not doc["modules"]:
        refuse("%s lists no module" % what)
    seen = set()
    for i, m in enumerate(doc["modules"]):
        where = "%s: modules[%d]" % (what, i)
        gap = module_gap(m, where)
        if gap:
            refuse(gap)
        key = (m["path"], m["version"])
        if key in seen:
            refuse("%s lists %s %s twice" % (what, key[0], key[1]))
        seen.add(key)
    return doc, seen


def cmd_check(argv):
    a = parse_args(argv, ["--vendor-dir", "--go-sum", "--provenance"])
    want = modules_txt(a["--vendor-dir"])
    sums = go_sum(a["--go-sum"])
    doc, have = read_provenance(read_regular(a["--provenance"], "provenance"), a["--provenance"])
    for p, v in sorted(want - have):
        refuse("module %s %s is in vendor/modules.txt but not in the provenance" % (p, v))
    for p, v in sorted(have - want):
        refuse("module %s %s is in the provenance but not in vendor/modules.txt (or in another version)" % (p, v))
    for m in doc["modules"]:
        h = sums.get((m["path"], m["version"]))
        if h is None:
            refuse("module %s %s has no go.sum hash" % (m["path"], m["version"]))
        if m["go_sum_hash"] != h:
            refuse("module %s %s: go_sum_hash differs from go.sum" % (m["path"], m["version"]))
    return 0


def recorded_origins(path, want, origins):
    """{module@version: origin} from the reviewed file; refused: a malformed entry, an entry for a module that is not in the build list or
    that the module cache has an Origin for, a commit that is not 40 hex or does not start with the pseudo-version's hash"""
    doc = load_json(read_regular(path, "recorded origins"), "recorded origins")
    if not isinstance(doc, list):
        refuse("recorded origins is not a list of entries")
    out = {}
    for i, e in enumerate(doc):
        where = "recorded origins[%d]" % i
        if not isinstance(e, dict) or set(e) != {"module", "version", "url", "commit", "command"}:
            refuse("%s (%s): not exactly the fields module, version, url, commit, command" % (where, e.get("module") if isinstance(e, dict) else "?"))
        mod, ver = e["module"], e["version"]
        name = "%s %s" % (mod, ver)
        for k in ("module", "version", "url", "commit", "command"):
            if not isinstance(e[k], str) or not e[k]:
                refuse("%s: module %s: %s is empty" % (where, name, k))
        key = "%s@%s" % (mod, ver)
        if key in out:
            refuse("module %s is recorded twice" % name)
        if (mod, ver) not in want:
            refuse("module %s is recorded but is not in the build list (vendor/modules.txt)" % name)
        if key in origins:
            refuse("module %s is recorded but the module cache has an Origin for it: only a module without one is filled from the file" % name)
        if not e["url"].startswith("https://") or len(e["url"]) <= len("https://"):
            refuse("module %s: the recorded url is not an https address" % name)
        if not COMMIT.fullmatch(e["commit"]):
            refuse("module %s: the recorded commit is not 40 hex characters" % name)
        m = PSEUDO.search(ver)
        if m and not e["commit"].startswith(ver[-12:]):
            refuse("module %s: the recorded commit does not match the pseudo-version's hash prefix %s" % (name, ver[-12:]))
        out[key] = {"url": e["url"], "commit": e["commit"]} if m else {"url": e["url"], "tag": ver}
    return out


def cmd_build(argv):
    a = parse_args(argv, ["--vendor-dir", "--go-sum", "--sumdb-record", "--origins", "--licenses", "--out"], ["--recorded-origins"])
    want = modules_txt(a["--vendor-dir"])
    sums = go_sum(a["--go-sum"])
    sumdb = load_json(read_regular(a["--sumdb-record"], "sumdb record"), "sumdb record")
    origins = load_json(read_regular(a["--origins"], "origins"), "origins")
    licenses = load_json(read_regular(a["--licenses"], "licenses"), "licenses")
    for name, d in (("sumdb record", sumdb), ("origins", origins), ("licenses", licenses)):
        if not isinstance(d, dict):
            refuse("%s is not an object" % name)
    recorded = {}
    if "--recorded-origins" in a:
        recorded = recorded_origins(a["--recorded-origins"], want, origins)
    out = []
    for p, v in sorted(want):
        key = "%s@%s" % (p, v)
        h = sums.get((p, v))
        if h is None:
            refuse("module %s: no go.sum hash" % key)
        rec = sumdb.get(key)
        if not isinstance(rec, dict) or rec.get("included") is not True or not rec.get("log"):
            refuse("module %s: no checksum-log record marked included" % key)
        if rec.get("hash") != h:
            refuse("module %s: the checksum-log hash differs from go.sum" % key)
        org = origins.get(key) or recorded.get(key)
        if not isinstance(org, dict):
            refuse("module %s: no origin" % key)
        lic = licenses.get(key)
        entry = {"path": p, "version": v, "go_sum_hash": h, "checksum_log": {"included": True, "log": rec["log"]},
                 "origin": org, "license": lic if isinstance(lic, str) else ""}
        gap = module_gap(entry, "module %s" % key)
        if gap:
            refuse(gap)
        out.append(entry)
    text = json.dumps({"schema": SCHEMA, "modules": out}, indent=2, sort_keys=True) + "\n"
    if os.path.lexists(a["--out"]):
        refuse("--out %s already exists" % a["--out"])
    with open(a["--out"], "x", encoding="utf-8") as fh:      # nothing is written unless every module resolved
        fh.write(text)
    return 0


def cmd_evidence(argv):
    a = parse_args(argv, ["--out", "--provenance", "--govulncheck", "--date"])
    date = a["--date"]
    if not EPOCH.fullmatch(date) or int(date) > MAX_EPOCH:
        refuse("--date must be epoch digits (0 to %d), not %r" % (MAX_EPOCH, date))
    out_dir = a["--out"]
    if os.path.lexists(out_dir) and not os.path.isdir(out_dir):
        refuse("--out %s exists and is not a directory" % out_dir)
    praw = read_regular(a["--provenance"], "provenance")
    _, mods = read_provenance(praw, a["--provenance"])
    graw = read_regular(a["--govulncheck"], "govulncheck result")
    load_json(graw, "govulncheck result")
    day = datetime.datetime.fromtimestamp(int(date), datetime.timezone.utc).strftime("%Y-%m-%d")
    doc = {"schema": EVIDENCE_SCHEMA, "mode": "vendor",
           "provenance": {"sha256": hashlib.sha256(praw).hexdigest(), "modules": len(mods)},
           "govulncheck": {"sha256": hashlib.sha256(graw).hexdigest()},
           "date": {"epoch": int(date), "utc": day}}
    text = json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n"
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "vendor-evidence.json"), "w", encoding="utf-8") as fh:
        fh.write(text)
    return 0


def main(argv):
    if not os.path.isfile("bin/vendor-provenance.py"):
        print("vendor-provenance: refused: run it from the repository root", file=sys.stderr)
        return 2
    cmds = {"check": cmd_check, "build": cmd_build, "evidence": cmd_evidence}
    if not argv or argv[0] not in cmds:
        print("vendor-provenance: refused: the subcommand is check, build or evidence", file=sys.stderr)
        return 2
    try:
        return cmds[argv[0]](argv[1:])
    except Refused as e:
        print("vendor-provenance: refused: %s" % e, file=sys.stderr)
        return 2
    except OSError as e:
        print("vendor-provenance: %s" % e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
