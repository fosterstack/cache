#!/usr/bin/env python3
"""bin/release-layout.py ROOT DIGEST: the OCI image layout directory ROOT is the image Build attested (REQ-CHAIN-007-AC7; round 1 B4).

index.json holds exactly one descriptor, the attested digest; every blob under blobs/sha256 hashes to its name; the index blob and every manifest,
config and layer it reaches are present. Exit 1 with one line naming ROOT and the reason otherwise; nothing is written. Release runs it before any
registry login or push."""
import hashlib, json, os, sys
root, want = sys.argv[1], sys.argv[2]
def die(why):
    print("release-publish: %s: %s: refusing to publish it" % (root, why), file=sys.stderr); sys.exit(1)
try:
    d = json.load(open(os.path.join(root, "index.json")))["manifests"]
except (OSError, ValueError, KeyError, TypeError):
    die("index.json is not an OCI index")
if not isinstance(d, list) or len(d) != 1 or not isinstance(d[0], dict) or d[0].get("digest") != want:
    die("index.json does not hold exactly one descriptor, the attested digest %s" % want)
blobs = os.path.join(root, "blobs", "sha256")
try:
    names = os.listdir(blobs)
except OSError:
    die("it has no blobs/sha256 directory")
for n in names:
    p = os.path.join(blobs, n)
    if os.path.islink(p) or not os.path.isfile(p):
        die("blob %s is not a regular file" % n)
    if hashlib.sha256(open(p, "rb").read()).hexdigest() != n:
        die("blob %s does not hash to its name" % n)
have = set(names)
def need(dg, what):
    if not isinstance(dg, str) or not dg.startswith("sha256:") or dg[7:] not in have:
        die("the %s blob %s is missing" % (what, dg))
    return open(os.path.join(blobs, dg[7:]), "rb").read()
try:
    kids = json.loads(need(want, "index"))["manifests"]
    for k in kids:
        m = json.loads(need(k.get("digest"), "manifest"))
        need(m["config"]["digest"], "config")
        for layer in m["layers"]:
            need(layer["digest"], "layer")
except (ValueError, KeyError, TypeError):
    die("the index blob is not an OCI image index of manifests with config and layers")
