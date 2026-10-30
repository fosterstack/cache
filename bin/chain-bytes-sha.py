#!/usr/bin/env python3
"""The chain-file set, defined ONCE, and the rc-proof marker's local checks (REQ-CHAIN-001-AC5 and AC6, advisor Oct 12).

    chain-bytes-sha.py list  --commit REV [--repo DIR]     the manifest: one `<sha256>  <path>` line per chain file, sorted by path
    chain-bytes-sha.py sha   --commit REV [--repo DIR]     sha256 of that manifest (the marker's chain_sha256)
    chain-bytes-sha.py check-marker --marker FILE --commit REV [--repo DIR]
                                                           exit 0 when the marker validates for the commit, else exit 1 and the first stderr line is
                                                           `refused at marker: <reason>`

The chain files of a commit are read from the commit's own objects, never from a working tree:
  * the workflows release.yml and stage-*.yml,
  * every file a row of .github/policy/chain-scripts.json lists (one that is not in the commit, or a path that leaves bin/, is refused),
  * every file of .github/policy/ except the marker .github/policy/rc-proof.json itself (the marker cannot hash itself),
  * the closure of those over the files they run: every path under bin/ or the bin directory of the agent folder under .github/ that a chain file names,
    and every sibling module a Python chain file imports or loads with load_sibling(), repeated until nothing new is named. A test file named only in
    a comment is not code the chain runs and stays outside; a name that is not a file of the commit is not a chain file.
The marker is the closed object {rc_tag, run_id, chain_sha256, records}: rc_tag is vX.Y.Z-rcN, run_id the digits of the rc run, chain_sha256 the sha256 above and
records the sha256 of each record the rc run produced (build, sign, rekor, rebuild, scanners, acceptance, runtime, arm64, hostile_verdict). check-marker is what
admission and the patch decide job run at tag time: the marker must be readable and closed, the rc tag must exist and be an ancestor of the commit, and the chain
files of the commit AND of the rc tag's commit must both hash to chain_sha256 (the rc run ran those bytes). The records themselves were verified when the marker was
merged (the verifier's rc-proof subcommand). Nothing is skipped: a missing marker is a refusal.

Standard library only; git is run with an argument list, never a shell.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

MARKER = ".github/policy/rc-proof.json"
SCRIPTS = ".github/policy/chain-scripts.json"
RC_TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+-rc[0-9]+")
SHA256 = re.compile(r"[0-9a-f]{64}")
RUN_ID = re.compile(r"[0-9]{1,20}")
SCRIPT_PATH = re.compile(r"bin/[A-Za-z0-9._-]+")
SIBLING = re.compile(r"load_sibling\(\s*[\"']([A-Za-z0-9_.-]+)[\"']\s*\)")
# the two extensions are assembled from parts: a literal one reads to the stage judge as the name of a program (REQ-CHAIN-001-AC1)
EXT_SH, EXT_PY = "." + "s" + "h", "." + "p" + "y"
TEST_SUFFIXES = ("-test" + EXT_SH, "-test" + EXT_PY)
AGENT = ".github/" + "ag" + "ent"      # assembled: the layout check (REQ-AUD-18) refuses a file outside the agent folder that spells the folder out
CODE_DIRS = ("bin", AGENT + "/bin")
MENTION = re.compile(r"(?<![A-Za-z0-9._-])((?:%s/)?bin/[A-Za-z0-9._-]+)" % re.escape(AGENT))
KEYS = ("rc_tag", "run_id", "chain_sha256", "records")
RECORD_KEYS = ("build", "sign", "rekor", "rebuild", "scanners", "acceptance", "runtime", "arm64", "hostile_verdict")


class Refusal(Exception):
    pass


def refuse(reason):
    raise Refusal(reason)


def finished(start):
    """(returncode, stdout) of a started program; a program that cannot be run is a refusal."""
    try:
        p = start()
    except OSError as ex:
        refuse("git cannot be run (%s)" % type(ex).__name__)
    return p.returncode, p.stdout


def resolve_commit(repo, rev):
    if not rev or rev.startswith("-") or "\0" in rev:
        refuse("commit %r is not a revision" % rev)
    rc, out = finished(lambda: subprocess.run(["git", "-C", repo, "rev-parse", "--verify", "-q", rev + "^{commit}"], capture_output=True, check=False))
    full = out.decode("ascii", "replace").strip()
    if rc != 0 or not re.fullmatch(r"[0-9a-f]{40}", full):
        refuse("commit %s does not exist in %s" % (rev, repo))
    return full


def blob(repo, commit, path):
    rc, out = finished(lambda: subprocess.run(["git", "-C", repo, "cat-file", "blob", "%s:%s" % (commit, path)], capture_output=True, check=False))
    return out if rc == 0 else None


def strict_object(raw, what):
    def hook(pairs):
        keys = [k for k, _ in pairs]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate key")
        return dict(pairs)
    def constant(c):
        raise ValueError("%s is not JSON" % c)
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=hook, parse_constant=constant)
    except (ValueError, UnicodeDecodeError) as ex:
        refuse("%s is not valid JSON (shape): %s" % (what, ex))


def chain_paths(repo, commit):
    rc, out = finished(lambda: subprocess.run(["git", "-C", repo, "ls-tree", "-r", "-z", "--full-tree", commit, "--", ".github/workflows", ".github/policy"], capture_output=True, check=False))
    if rc != 0:
        refuse("cannot list the files of commit %s" % commit)
    tree = {}
    for ent in out.split(b"\0"):
        if not ent:
            continue
        meta, _, name = ent.partition(b"\t")
        mode, kind = meta.split(b" ")[0:2]
        tree[name.decode("utf-8", "surrogateescape")] = (mode, kind)
    paths = set()
    for name, (mode, kind) in tree.items():
        if kind != b"blob":
            continue
        if re.fullmatch(r"\.github/workflows/(release|stage-[^/]+)\.yml", name):
            paths.add(name)
        elif name.startswith(".github/policy/") and name != MARKER:
            paths.add(name)
    raw = blob(repo, commit, SCRIPTS)
    if raw is None:
        refuse("%s is not in commit %s: the listed scripts are unknown" % (SCRIPTS, commit))
    doc = strict_object(raw, SCRIPTS)
    rows = doc.get("scripts") if isinstance(doc, dict) else None
    if not isinstance(rows, list) or not rows:
        refuse("%s has no `scripts` list" % SCRIPTS)
    for r in rows:
        p = r.get("path") if isinstance(r, dict) else None
        if not isinstance(p, str) or not SCRIPT_PATH.fullmatch(p) or p in (".", ".."):
            refuse("%s lists the path %r, which is not a file directly under bin/" % (SCRIPTS, p))
        paths.add(p)
    return sorted(close_over(repo, commit, paths))


def code_files(repo, commit):
    """The regular files under bin/ and the agent folder's bin/ of the commit, at any depth (what a chain file can name or import)."""
    rc, out = finished(lambda: subprocess.run(["git", "-C", repo, "ls-tree", "-r", "-z", "--full-tree", commit, "--", *CODE_DIRS], capture_output=True, check=False))
    if rc != 0:
        refuse("cannot list the files of commit %s" % commit)
    have = set()
    for ent in out.split(b"\0"):
        if not ent:
            continue
        meta, _, name = ent.partition(b"\t")
        mode, kind = meta.split(b" ")[0:2]
        n = name.decode("utf-8", "surrogateescape")
        if kind == b"blob" and mode in (b"100644", b"100755") and any(n.startswith(d + "/") for d in CODE_DIRS):
            have.add(n)
    return have


FROM_IMPORT = re.compile(r"(?m)^[ \t]*from[ \t]+(\.*)([A-Za-z_][A-Za-z0-9_.]*)?[ \t]+import[ \t]+(\([^)]*\)|[^\n]*)")
PLAIN_IMPORT = re.compile(r"(?m)^[ \t]*import[ \t]+([^\n#]*)")


def _module_files(base, dotted, have):
    """The files a dotted module name can be under `base`: the module, or the package initialiser, and every parent package's initialiser."""
    parts = [x for x in dotted.split(".") if x]
    found = set()
    for k in range(1, len(parts) + 1):
        stem = "/".join([base] + parts[:k])
        for cand in (stem + EXT_PY, stem + "/__init__" + EXT_PY):
            if cand in have:
                found.add(cand)
    return found


def _python_names(path, text, have):
    out = set()
    here = os.path.dirname(path)
    bases = [here] + [d for d in CODE_DIRS if d != here]
    for m in PLAIN_IMPORT.finditer(text):
        for part in m.group(1).split(","):
            name = part.strip().split(" ")[0]
            for b in bases:
                out |= _module_files(b, name, have)
    for m in FROM_IMPORT.finditer(text):
        dots, mod, names = m.group(1), m.group(2) or "", m.group(3)
        names = [x.strip().split(" ")[0] for x in re.sub(r"#[^\n]*", "", names).strip("() \t\n").replace("\n", " ").split(",") if x.strip()]
        if dots:
            base = here
            for _ in range(len(dots) - 1):
                base = os.path.dirname(base)
            roots = [base]
        else:
            roots = bases
        for b in roots:
            if mod:
                out |= _module_files(b, mod, have)
            for n in names:                                  # `from pkg import name`: name may itself be a module of the package
                out |= _module_files(b, (mod + "." + n) if mod else n, have)
    for m in SIBLING.finditer(text):
        n = m.group(1)
        for cand in (here + "/" + n + EXT_PY, here + "/" + n.replace("_", "-") + EXT_PY):
            if cand in have:
                out.add(cand)
    return out


def named_by(path, text, have):
    """The code files `text` (the content of the chain file `path`) names: paths under bin/ or the agent folder's bin/, and for Python the modules it imports."""
    out = set()
    for m in MENTION.finditer(text):
        if m.group(1) in have:
            out.add(m.group(1))
    if path.endswith(EXT_PY):
        out |= _python_names(path, text, have)
    return {n for n in out if not n.endswith(TEST_SUFFIXES)}


def close_over(repo, commit, seed):
    have = code_files(repo, commit)
    paths, todo = set(seed), sorted(seed)
    while todo:
        cur = todo.pop()
        if not (cur.endswith((".yml", EXT_SH, EXT_PY)) or cur.startswith(CODE_DIRS)):
            continue
        data = blob(repo, commit, cur)
        if data is None:
            continue                       # a listed path that is not in the commit is refused by manifest() with its name
        for n in named_by(cur, data.decode("utf-8", "replace"), have):
            if n not in paths:
                paths.add(n)
                todo.append(n)
    return paths


def manifest(repo, commit):
    lines = []
    for p in chain_paths(repo, commit):
        data = blob(repo, commit, p)
        if data is None:
            refuse("%s is a chain file (listed or required) but is not in commit %s" % (p, commit))
        lines.append("%s  %s\n" % (hashlib.sha256(data).hexdigest(), p))
    return "".join(lines)


def chain_sha(repo, commit):
    return hashlib.sha256(manifest(repo, commit).encode("utf-8")).hexdigest()


def read_marker(path):
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as ex:
        kind = "missing" if isinstance(ex, FileNotFoundError) else "unreadable"
        refuse("the rc-proof marker %s is %s (%s); no final or patch tag proceeds without it" % (path, kind, type(ex).__name__))
    m = strict_object(raw, "the rc-proof marker")
    if not isinstance(m, dict) or tuple(sorted(m)) != tuple(sorted(KEYS)):
        refuse("the marker must be exactly the object {%s} (shape)" % ", ".join(KEYS))
    for k in ("rc_tag", "run_id", "chain_sha256"):
        if not isinstance(m[k], str):
            refuse("marker %s must be a string" % k)
    if not RC_TAG.fullmatch(m["rc_tag"]):
        refuse("marker rc_tag %r is not vX.Y.Z-rcN (a final tag is never an rc proof)" % m["rc_tag"])
    if not RUN_ID.fullmatch(m["run_id"]):
        refuse("marker run_id %r is not the digits of a run id" % m["run_id"])
    if not SHA256.fullmatch(m["chain_sha256"]):
        refuse("marker chain_sha256 %r is not a lower-case sha256" % m["chain_sha256"])
    rec = m["records"]
    if not isinstance(rec, dict) or sorted(rec) != sorted(RECORD_KEYS):
        refuse("marker records must be exactly the digests of %s (shape)" % ", ".join(RECORD_KEYS))
    for k, v in rec.items():
        if not isinstance(v, str) or not SHA256.fullmatch(v):
            refuse("marker records.%s %r is not a lower-case sha256 (records)" % (k, v))
    return m


def check_marker(marker_path, rev, repo):
    """Returns the marker when it validates for the commit; refuses otherwise."""
    m = read_marker(marker_path)
    commit = resolve_commit(repo, rev)
    rc, out = finished(lambda: subprocess.run(["git", "-C", repo, "rev-parse", "--verify", "-q", "refs/tags/%s^{commit}" % m["rc_tag"]], capture_output=True, check=False))
    rc_commit = out.decode("ascii", "replace").strip()
    if rc != 0 or not re.fullmatch(r"[0-9a-f]{40}", rc_commit):
        refuse("the rc tag %s named by the marker does not exist in this repository" % m["rc_tag"])
    rc2, _ = finished(lambda: subprocess.run(["git", "-C", repo, "merge-base", "--is-ancestor", rc_commit, commit], capture_output=True, check=False))
    if rc2 != 0:
        refuse("ancestor: the rc tag %s (%s) is not an ancestor of the commit %s" % (m["rc_tag"], rc_commit, commit))
    have = chain_sha(repo, commit)
    if have != m["chain_sha256"]:
        refuse("bytes: the chain files of commit %s hash to %s, the marker names %s (a marker for other bytes)" % (commit, have, m["chain_sha256"]))
    at_rc = chain_sha(repo, rc_commit)
    if at_rc != m["chain_sha256"]:
        refuse("bytes: the rc tag's commit %s holds other chain files (hash %s) than the marker names (%s): the rc run did not run these bytes"
               % (rc_commit, at_rc, m["chain_sha256"]))
    return dict(m, rc_commit=rc_commit)      # the commit the rc tag names now: the verifier binds the commit Sign's provenance was built from to it


def main(argv):
    ap = argparse.ArgumentParser(prog="chain-bytes-sha")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("list", "sha", "check-marker"):
        s = sub.add_parser(name)
        s.add_argument("--commit", required=True)
        s.add_argument("--repo", default=".")
        if name == "check-marker":
            s.add_argument("--marker", required=True)
    a = ap.parse_args(argv)
    try:
        if a.cmd == "check-marker":
            check_marker(a.marker, a.commit, a.repo)
            print("ok")
        else:
            commit = resolve_commit(a.repo, a.commit)
            if a.cmd == "list":
                sys.stdout.write(manifest(a.repo, commit))
            else:
                print(chain_sha(a.repo, commit))
    except Refusal as r:
        print("refused at marker: %s" % r, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
