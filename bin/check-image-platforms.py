"""bin/check-image-platforms.py IMAGE: the platforms an OCI image carries (REQ-PLAT-002-AC1: both platform entries exist). IMAGE is an OCI layout
DIRECTORY (PR 2's images/<variant>/: oci-layout, index.json, blobs/sha256/) or, for a tool that still holds a tarball, an OCI archive of it.
Reads index.json; an image index descriptor is followed to its blob; a descriptor with a platform is an image manifest, and it counts only when
the manifest blob it names is present and hashes to its name, names a config blob that is present, hashes to its name and says the same os and
architecture (PR 3 round 1 F1: an entry that merely says linux/arm64 is not an arm64 image).
Prints one os/architecture per line, sorted, and nothing else; an image that has no readable index.json, no platform at all, or a platform entry
the blobs do not bear out, exits 1 naming it."""
import hashlib, json, os, re, sys, tarfile


class Bad(Exception):
    pass


def blob(opener, digest, what):
    algo, _, hexd = str(digest).partition(":")
    if algo != "sha256" or not re.fullmatch(r"[0-9a-f]{64}", hexd):
        raise Bad("%s digest %r is not a sha256 digest" % (what, digest))
    try:
        data = opener("blobs/sha256/" + hexd).read()
    except (KeyError, OSError, AttributeError):
        raise Bad("%s blob %s is missing" % (what, digest))
    if hashlib.sha256(data).hexdigest() != hexd:
        raise Bad("%s blob %s does not hash to its name" % (what, digest))
    return data


def platforms(opener, index, depth=0):
    found = set()
    for m in index.get("manifests", []) if isinstance(index, dict) else []:
        if not isinstance(m, dict):
            continue
        p = m.get("platform")
        if isinstance(p, dict) and p.get("os") and p.get("architecture"):
            name = "%s/%s" % (p["os"], p["architecture"])
            try:
                manifest = json.loads(blob(opener, m.get("digest", ""), "the %s manifest" % name))
                config = json.loads(blob(opener, manifest["config"]["digest"], "the %s config" % name))
            except (ValueError, KeyError, TypeError) as e:
                raise Bad("the %s entry's manifest is not a readable image manifest (%s)" % (name, e))
            if not isinstance(config, dict) or (config.get("os"), config.get("architecture")) != (p["os"], p["architecture"]):
                raise Bad("the %s entry's config says %s/%s" % (name, config.get("os") if isinstance(config, dict) else None,
                                                                 config.get("architecture") if isinstance(config, dict) else None))
            found.add(name)
        elif "index" in str(m.get("mediaType", "")) and depth < 3:
            try:
                found |= platforms(opener, json.loads(blob(opener, m.get("digest", ""), "the image index")), depth + 1)
            except ValueError as e:
                raise Bad("the image index is not readable JSON (%s)" % e)
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
except Bad as e:
    print("check-image-platforms: %s: %s" % (sys.argv[1], e), file=sys.stderr)
    sys.exit(1)
except (OSError, KeyError, ValueError, tarfile.TarError, IndexError, AttributeError) as e:
    print("check-image-platforms: %s is not a readable OCI image (%s)" % (sys.argv[1:2], e), file=sys.stderr)
    sys.exit(1)
if not found:
    print("check-image-platforms: %s names no platform" % sys.argv[1], file=sys.stderr)
    sys.exit(1)
print("\n".join(sorted(found)))
