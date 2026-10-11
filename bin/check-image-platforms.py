"""bin/check-image-platforms.py TAR: the platforms an OCI image archive carries (REQ-PLAT-002-AC1: both platform entries exist).
Reads index.json of the archive; a descriptor with a platform names it, an image index descriptor is followed to its blob and read the same way.
Prints one os/architecture per line, sorted, and nothing else; an archive that has no readable index.json, or no platform at all, exits 1."""
import json, sys, tarfile

def platforms(t, index, depth=0):
    found = set()
    for m in index.get("manifests", []) if isinstance(index, dict) else []:
        p = m.get("platform") if isinstance(m, dict) else None
        if isinstance(p, dict) and p.get("os") and p.get("architecture"):
            found.add("%s/%s" % (p["os"], p["architecture"]))
        elif isinstance(m, dict) and "index" in str(m.get("mediaType", "")) and depth < 3:
            algo, _, hexd = str(m.get("digest", "")).partition(":")
            try:
                found |= platforms(t, json.load(t.extractfile("blobs/%s/%s" % (algo, hexd))), depth + 1)
            except (KeyError, ValueError, AttributeError):
                pass
    return found

try:
    with tarfile.open(sys.argv[1]) as t:
        found = platforms(t, json.load(t.extractfile("index.json")))
except (OSError, KeyError, ValueError, tarfile.TarError, IndexError) as e:
    print("check-image-platforms: %s is not a readable image archive (%s)" % (sys.argv[1:2], e), file=sys.stderr)
    sys.exit(1)
if not found:
    print("check-image-platforms: %s names no platform" % sys.argv[1], file=sys.stderr)
    sys.exit(1)
print("\n".join(sorted(found)))
