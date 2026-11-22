#!/usr/bin/env python3
"""The coverage gate of the release assets (REQ-CHAIN-007-AC13), run by the Release steps that stage and attach them.

  release-gate.py --dir DIR [--same-as STAGED_DIR]
        every file of the release assets directory is covered; see GATE below

It stands alone and loads no other file of bin/: the scripts that hold the release secrets run it (REQ-CHAIN-004-AC20).
Every refusal exits 1 and names the file. Offline."""
import argparse, hashlib, os, re, sys


def refuse(msg):
    print("release-gate: " + msg, file=sys.stderr)
    sys.exit(1)


def sha256_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def meta_names(version):
    return ["release-manifest.json", "fosterstack-cache.openvex.json", "fosterstack-cache-%s.csaf.json" % version,
            "fosterstack-cache-%s.inspector-filters.json" % version]


def parse_sums(path, what):
    out = []
    try:
        text = open(path).read()
    except OSError:
        refuse("%s is missing" % what)
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()                      # the one final newline; a second one is a blank line
    for l in lines:
        if not l:
            refuse("%s: a blank line (the list is exactly one `<sha256>  <name>` line per file)" % what)
        m = re.fullmatch(r"([0-9a-f]{64})  ([^/\s]+)", l)
        if not m:
            refuse("%s: a line that is not `<sha256>  <name>`: %r" % (what, l))
        out.append((m.group(2), m.group(1)))
    return out


def bundle_of(name):
    return "release-policy.bundle" if name == "policy.json" else name + ".bundle"


def signed_by(bundle):
    return "policy.json" if bundle == "release-policy.bundle" else bundle[:-len(".bundle")]


def same_as(a):
    """--same-as DIR: what the release stores equals what was staged, name for name and byte for byte."""
    staged = sorted(os.listdir(a.same_as))
    for n in staged:
        if not os.path.isfile(os.path.join(a.dir, n)):
            refuse("%s is staged but the release does not store it" % n)
        if sha256_file(os.path.join(a.dir, n)) != sha256_file(os.path.join(a.same_as, n)):
            refuse("%s as the release stores it differs from the staged file" % n)
    for n in sorted(os.listdir(a.dir)):
        if n not in staged:
            refuse("%s is stored by the release but was not staged" % n)


# signed by the offline root key, checked by Check after a publish (REQ-CHAIN-008)
KEY_MANIFEST = ("release-key-manifest.json", "release-key-manifest.sig")
# Sign's three files: the record the Sign stage signed; the bundle carries its signature (AC9, REQ-CHAIN-007-AC19)
PROVENANCE = ("provenance.json", "provenance.rekor.json", "provenance.bundle.json")
# Build's products of its signed record
BUILD_FILES = ("digests.json", "items.json", "admission-baseline.json")


def gate(a):
    """GATE (REQ-CHAIN-007-AC13): the directory holds checksums.txt with its bundle and release-files.sha256 with its
    bundle, and the four metadata files; checksums.txt lists existing files with their hashes; release-files.sha256
    lists exactly the four metadata files with theirs; and every asset is covered: it is in checksums.txt or in
    release-files.sha256, or it is a bundle whose signed file is an asset, or it has its own bundle, or it is an apk
    (signed by the release key inside the file), a Witness record (`*-collection.json`, a signed envelope the stages
    verified, with exactly one `*-collection.rekor.json` entries file beside it and none without its record) or Build's
    digests.json, items.json or admission-baseline.json (products of Build's signed record) or Sign's provenance.json,
    provenance.rekor.json and provenance.bundle.json (all three are required) or the key manifest and its signature
    (signed by the root key). A symlink, a directory, or anything else is refused by name."""
    names = sorted(os.listdir(a.dir))
    for n in names:
        p = os.path.join(a.dir, n)
        if os.path.islink(p):
            refuse("%s is a symlink" % n)
        if not os.path.isfile(p):
            refuse("%s is not a regular file" % n)
    have = set(names)
    for need in ("checksums.txt", "checksums.txt.bundle", "release-files.sha256", "release-files.sha256.bundle"):
        if need not in have:
            refuse("%s is missing (a release is not published without it)" % need)
    for need in PROVENANCE:
        if need not in have:
            refuse("%s is missing (Sign's provenance is part of every release)" % need)
    covered = set()
    for n, h in parse_sums(os.path.join(a.dir, "checksums.txt"), "checksums.txt"):
        if n not in have:
            refuse("checksums.txt lists %s, which is not an asset" % n)
        if sha256_file(os.path.join(a.dir, n)) != h:
            refuse("%s does not match its hash in checksums.txt" % n)
        covered.add(n)
    lst = parse_sums(os.path.join(a.dir, "release-files.sha256"), "release-files.sha256")
    if not lst:
        refuse("release-files.sha256 is empty")
    versions = {m.group(1) for n in have for m in [re.fullmatch(r"fosterstack-cache-(v[0-9.]+)\.csaf\.json", n)] if m}
    if len(versions) != 1:
        refuse("the CSAF file of exactly one version is required, found %s" % (sorted(versions) or "none"))
    want = meta_names(versions.pop())
    for n in want:
        if n not in have:
            refuse("%s is missing (the four metadata files are release-blocking)" % n)
    if len(lst) > len(want):
        refuse("release-files.sha256 has an extra line: %s  %s" % (lst[len(want)][1], lst[len(want)][0]))
    if [n for n, _ in lst] != want:
        refuse("release-files.sha256 must list exactly %s, in this order" % ", ".join(want))
    for n, h in lst:
        if sha256_file(os.path.join(a.dir, n)) != h:
            refuse("%s does not match its hash in release-files.sha256" % n)
        covered.add(n)
    for n in names:
        # a Witness record and its entries file belong together: exactly one <stem>.rekor.json beside each
        # *-collection.json, and none without its record; this holds for every name, also one that checksums.txt or
        # release-files.sha256 already covers (a hash does not pair an orphan)
        if n.endswith("-collection.rekor.json"):
            if n[:-len(".rekor.json")] + ".json" not in have:
                refuse("%s is an entries file with no record beside it (%s)" % (n, n[:-len(".rekor.json")] + ".json"))
            continue
        if n.endswith("-collection.json") and n[:-len(".json")] + ".rekor.json" not in have:
            refuse("%s has no entries file beside it (%s is missing)" % (n, n[:-len(".json")] + ".rekor.json"))
    for n in names:
        if n in covered:
            continue
        if n.endswith("-collection.rekor.json"):
            continue
        if n.endswith(".bundle"):
            if signed_by(n) not in have:
                refuse("%s signs %s, which is not an asset" % (n, signed_by(n)))
            continue
        known = BUILD_FILES + PROVENANCE + KEY_MANIFEST
        if bundle_of(n) in have or n.endswith((".apk", "-collection.json")) or n in known:
            continue
        refuse("%s is covered by nothing: not in checksums.txt, not in release-files.sha256, and no bundle signs it"
               % n)
    if a.same_as:
        same_as(a)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--dir", required=True)
    p.add_argument("--same-as")
    gate(p.parse_args())
