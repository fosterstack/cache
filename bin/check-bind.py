"""bin/check-bind.py --digests FILE --images DIR [--archives DIR] [--members-out DIR]: Check reads the bytes Build recorded (REQ-CHAIN-006-AC4, AC5, AC6; PR 3 round 1 F1).

stage-start authenticates digests.json (Build's signed record names its digest). What Check then DOWNLOADS is not the record: an image directory that
merely holds oci-layout and index.json, or an archive that merely has the right name, may be anything. Before any scan, load or run, this file
binds each file Check is about to judge to the digest Build recorded:
  - DIR/production and DIR/fips: the layout is re-derived from digests.json' image-production / image-fips with Build's own layout check
    (bin/chain_items.py check_layout: oci-layout 1.0.0, index.json with exactly one descriptor, that digest, the index blob a real OCI image index
    hashing to its name, its linux/amd64 and linux/arm64 child manifests present and hashing to theirs); then EVERY file under blobs/sha256 is
    re-hashed (a layer or config changed under its name is a layout that is not the digest), and every config and layer the child manifests name
    must be one of those blobs;
  - DIR/archives (with --archives): exactly the four Linux archives (fscache and fscache-fips, amd64 and arm64, of one version), each hashing to the
    digest the list holds under archive-linux-ARCH / archive-fips-linux-ARCH.
With --members-out DIR (REQ-SUP-001-AC33) it also writes DIR/production.members and DIR/fips.members: oci-layout, index.json and the blobs the index and
the child manifests name, one path per line. The caller archives those files only, never the whole directory: a root manifest.json, a stray archive
or an unreferenced blob in the layout stays out of what the container engine reads.
Any difference exits 1 naming the item; nothing is written (but the member lists, after a layout has been bound)."""
import argparse, hashlib, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import chain_items                      # noqa: E402  (Build's layout check, the one definition of "this layout is that digest")
from chain_common import Refuse         # noqa: E402

DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
ARCHIVE = re.compile(r"(fscache|fscache-fips)_([^_/]+)_linux_(amd64|arm64)\.tar\.gz")
ARCHES = ("amd64", "arm64")


def fail(message):
    print("check-bind: " + message, file=sys.stderr)
    sys.exit(1)


def sha256_path(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def bind_layout(images, variant, digest, members_out=None):
    key = "image-" + variant
    try:
        children = chain_items.check_layout(images, variant, digest)
    except Refuse as e:
        fail("%s: the layout %s/%s is not the image Build recorded (%s): %s" % (key, images, variant, digest, e.reason))
    for own in ("oci-layout", "index.json"):    # REQ-SUP-001-AC33: the two top-level files are the layout's own regular files, not links
        if os.path.islink(os.path.join(images, variant, own)) or not os.path.isfile(os.path.join(images, variant, own)):
            fail("%s: %s/%s is not a regular file of the layout" % (key, variant, own))
    blobs = os.path.join(images, variant, "blobs", "sha256")
    names = set()
    try:
        entries = list(os.scandir(blobs))
    except OSError as e:
        fail("%s: the layout has no readable blobs/sha256 directory (%s)" % (key, e))
    for e in entries:
        if e.is_symlink() or not e.is_file(follow_symlinks=False) or not re.fullmatch(r"[0-9a-f]{64}", e.name):
            fail("%s: blobs/sha256/%s is not a regular file named by a sha256" % (key, e.name))
        if sha256_path(e.path) != e.name:
            fail("%s: the blob %s does not hash to its name (the layout is not the digest Build recorded)" % (key, e.name))
        names.add(e.name)
    members = {digest}
    # REQ-SUP-001-AC33: a descriptor beyond the two linux children (buildkit's provenance manifest, say) is judged by the scan, not here; what is archived for it is its
    # manifest blob and that manifest's config and layers, and the layout must hold each of them (the blobs the index points to)
    try:
        with open(os.path.join(blobs, digest.split(":", 1)[1]), "rb") as f:
            listed = json.loads(f.read())["manifests"]
        extras = [m["digest"] for m in listed if isinstance(m, dict) and m.get("digest") not in children.values()]
    except (OSError, ValueError, KeyError, TypeError) as e:
        fail("%s: the index %s cannot be read for its descriptors (%s)" % (key, digest, e))
    for d in extras:
        if not isinstance(d, str) or not DIGEST.fullmatch(d):
            if members_out:             # the caller will load this layout: an index descriptor without a canonical sha256 digest is refused, never skipped
                fail("%s: the index names a descriptor whose digest %r is not sha256:<64 lowercase hex>" % (key, d))
            continue                    # not a digest: nothing to archive for it (the scan names it)
        if d.split(":", 1)[1] not in names:
            fail("%s: the index names a descriptor %s whose blob the layout does not hold" % (key, d))
        members.add(d)
        try:
            with open(os.path.join(blobs, d.split(":", 1)[1]), "rb") as f:
                man = json.loads(f.read())
            refs = [man["config"]["digest"]] + [layer["digest"] for layer in man["layers"]]
        except (OSError, ValueError, KeyError, TypeError) as e:
            if members_out:             # the caller will load this layout: a manifest that cannot be read as one is refused, never skipped
                fail("%s: the descriptor %s is not a readable image manifest (%s)" % (key, d, e))
            continue                    # the scan names it; its blob alone is archived
        for r in refs:
            if isinstance(r, str) and DIGEST.fullmatch(r):
                if r.split(":", 1)[1] not in names:
                    fail("%s: the descriptor %s names %s, which the layout does not hold" % (key, d, r))
                members.add(r)
            elif members_out:
                fail("%s: the descriptor %s names %r, which is not a sha256 digest" % (key, d, r))
    for arch, child in sorted(children.items()):
        try:
            with open(os.path.join(blobs, child.split(":", 1)[1]), "rb") as f:
                manifest = json.loads(f.read())
            wanted = [manifest["config"]["digest"]] + [layer["digest"] for layer in manifest["layers"]]
            if not wanted or not all(isinstance(d, str) and DIGEST.fullmatch(d) for d in wanted):
                raise ValueError("a config or layer digest is not a sha256 digest")
        except (OSError, ValueError, KeyError, TypeError) as e:
            fail("%s: the linux/%s manifest %s is not a readable image manifest (%s)" % (key, arch, child, e))
        for d in wanted:
            if d.split(":", 1)[1] not in names:
                fail("%s: the linux/%s manifest names %s, which the layout does not hold" % (key, arch, d))
        members.update([child] + wanted)
    if members_out:                     # REQ-SUP-001-AC33: the files of the layout the caller may archive, and nothing else of it
        listing = ["oci-layout", "index.json"] + ["blobs/sha256/" + d.split(":", 1)[1] for d in sorted(members)]
        try:
            with open(os.path.join(members_out, variant + ".members"), "w") as f:
                f.write("".join(m + "\n" for m in listing))
        except OSError as e:
            fail("%s: the member list could not be written (%s)" % (key, e))


def bind_archives(archives, digests):
    try:
        names = sorted(os.listdir(archives))
    except OSError as e:
        fail("the archive directory %s is not readable (%s)" % (archives, e))
    found, versions = {}, set()
    for name in names:
        m = ARCHIVE.fullmatch(name)
        path = os.path.join(archives, name)
        if not m or os.path.islink(path) or not os.path.isfile(path):
            fail("%s in %s is not one of the four Linux archives Build recorded" % (name, archives))
        key = "archive-%slinux-%s" % ("fips-" if m.group(1) == "fscache-fips" else "", m.group(3))
        if key in found:
            fail("%s is the second archive for %s" % (name, key))
        found[key] = path
        versions.add(m.group(2))
    wanted = ["archive-linux-%s" % a for a in ARCHES] + ["archive-fips-linux-%s" % a for a in ARCHES]
    if len(versions) > 1:
        fail("the archives in %s are of more than one version: %s" % (archives, sorted(versions)))
    for key in wanted:
        want = digests.get(key)
        if not isinstance(want, str) or not DIGEST.fullmatch(want):
            fail("the digest list has no %s digest" % key)
        if key not in found:
            fail("the archive for %s is missing from %s" % (key, archives))
        got = "sha256:" + sha256_path(found[key])
        if got != want:
            fail("%s (%s) is not the archive Build recorded: it hashes to %s, the digest list holds %s" % (os.path.basename(found[key]), key, got, want))


def main():
    ap = argparse.ArgumentParser(prog="check-bind.py")
    ap.add_argument("--digests", required=True)
    ap.add_argument("--images", required=True)
    ap.add_argument("--archives")
    ap.add_argument("--members-out", help="a directory (it must exist): writes VARIANT.members, the files of each layout the caller may archive")
    a = ap.parse_args()
    try:
        with open(a.digests, "rb") as f:
            digests = json.loads(f.read())
        if not isinstance(digests, dict):
            raise ValueError("not an object")
    except (OSError, ValueError) as e:
        fail("the digest list %s is not readable JSON (%s)" % (a.digests, e))
    for variant in ("production", "fips"):
        d = digests.get("image-" + variant)
        if not isinstance(d, str) or not DIGEST.fullmatch(d):
            fail("the digest list has no image-%s digest" % variant)
        bind_layout(a.images, variant, d, a.members_out)
    if a.archives:
        bind_archives(a.archives, digests)
    print("check-bind: the layouts%s are the digests Build recorded" % (" and archives" if a.archives else ""))


main()
