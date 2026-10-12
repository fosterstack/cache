"""bin/check-image-platforms.py IMAGE: the platforms an OCI image carries (REQ-PLAT-002-AC1: both platform entries exist). IMAGE is an OCI layout
DIRECTORY (PR 2's images/<variant>/: oci-layout, index.json, blobs/sha256/) or, for a tool that still holds a tarball, an OCI archive of it.
Reads index.json; a descriptor with a platform names it, an image index descriptor is followed to its blob and read the same way.
Prints one os/architecture per line, sorted, and nothing else; an image that has no readable index.json, or no platform at all, exits 1."""
import json, os, sys, tarfile

def platforms(opener, index, depth=0):
    found = set()
    for m in index.get("manifests", []) if isinstance(index, dict) else []:
        p = m.get("platform") if isinstance(m, dict) else None
        if isinstance(p, dict) and p.get("os") and p.get("architecture"):
            found.add("%s/%s" % (p["os"], p["architecture"]))
        elif isinstance(m, dict) and "index" in str(m.get("mediaType", "")) and depth < 3:
            algo, _, hexd = str(m.get("digest", "")).partition(":")
            if not algo.isalnum() or not hexd.isalnum():
                continue
            try:
                found |= platforms(opener, json.load(opener("blobs/%s/%s" % (algo, hexd))), depth + 1)
            except (KeyError, ValueError, OSError, AttributeError):
                pass
    return found

try:
    if os.path.isdir(sys.argv[1]):
        root = sys.argv[1]
        opener = lambda n: open(os.path.join(root, n), "rb")
        found = platforms(opener, json.load(opener("index.json")))
    else:
        with tarfile.open(sys.argv[1]) as t:
            opener = t.extractfile
            found = platforms(opener, json.load(opener("index.json")))
except (OSError, KeyError, ValueError, tarfile.TarError, IndexError) as e:
    print("check-image-platforms: %s is not a readable OCI image (%s)" % (sys.argv[1:2], e), file=sys.stderr)
    sys.exit(1)
if not found:
    print("check-image-platforms: %s names no platform" % sys.argv[1], file=sys.stderr)
    sys.exit(1)
print("\n".join(sorted(found)))
