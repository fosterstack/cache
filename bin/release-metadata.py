#!/usr/bin/env python3
"""The release metadata of Release (REQ-CHAIN-007-AC13; v0.3.0 rules 53, 56, 63, 64, 69; owner Oct 10: v0.3.0 matches CISA secure by design).

  release-metadata.py images   --digests D --images-dir I --items ITEMS --out F
        the image input of vex-forms, {variant: {index, children}}, made ONLY from Build's verified digest list and Build's
        images/<variant>.digest and images/<variant>.manifests; never from a registry
  release-metadata.py manifest --digests D --images-dir I --items ITEMS --vex-dir DIR --baseline-version V --repo-root DIR --version V --commit SHA --ci-url U --workflow W --out F
        release-manifest.json, deterministic (no clock): the images (`.images[].variant`, `.images[].digest` and both registry references,
        the shape the daily rescan reads), the archives and the apks as Build attested them
  release-metadata.py list     --version V --dir DIR --out F
        release-files.sha256: `<sha256>  <name>` for exactly release-manifest.json, the OpenVEX file, the CSAF file and the inspector-filters
        file of this version, in this order
  release-metadata.py gate     --dir DIR [--same-as STAGED_DIR]
        every file of the release assets directory is covered; see GATE below

Every refusal exits 1 and names the file or the key; an output file is written only after every check passed. Offline."""
import argparse, hashlib, json, os, re, sys

REPO_GHCR, REPO_HUB = "ghcr.io/fosterstack/cache", "docker.io/fosterstack/cache"
VARIANTS = ("production", "fips")
ARCHES = ("amd64", "arm64")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
FINAL = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+")


def refuse(msg):
    print("release-metadata: " + msg, file=sys.stderr)
    sys.exit(1)


def strict_json(path):
    def hook(pairs):
        d = {}
        for k, v in pairs:
            if k in d:
                refuse("%s: duplicate key %r" % (path, k))
            d[k] = v
        return d
    try:
        with open(path, "rb") as f:
            return json.loads(f.read().decode("utf-8"), object_pairs_hook=hook)
    except (OSError, ValueError) as e:
        refuse("%s: unreadable or not JSON (%s)" % (path, e))


def sha256_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def write_atomic(path, text):
    tmp = path + ".part"
    with open(tmp, "w") as f:
        f.write(text)
    os.replace(tmp, path)


def digests_of(path):
    d = strict_json(path)
    if not isinstance(d, dict):
        refuse("%s is not a JSON object" % path)
    for k, v in d.items():
        if not isinstance(v, str) or not DIGEST.fullmatch(v):
            refuse("%s: the value of %s is not sha256:<64 lower-case hex>" % (path, k))
    images = sorted(k for k in d if k.startswith("image-"))
    if images != sorted("image-" + v for v in VARIANTS):
        extra = [k for k in images if k not in ("image-" + v for v in VARIANTS)]
        missing = [("image-" + v) for v in VARIANTS if ("image-" + v) not in d]
        refuse("%s: the image keys must be exactly image-production and image-fips (missing: %s; not allowed: %s)" % (path, ", ".join(missing) or "none", ", ".join(extra) or "none"))
    return d


def children_of(images_dir, variant, index):
    dig = os.path.join(images_dir, variant + ".digest")
    try:
        have = open(dig).read().strip()
    except OSError:
        refuse("%s is missing" % dig)
    if have != index:
        refuse("%s is %s, which is not the digest Build attested for image-%s (%s)" % (dig, have, variant, index))
    man = os.path.join(images_dir, variant + ".manifests")
    try:
        lines = [l for l in open(man).read().split("\n") if l.strip()]
    except OSError:
        refuse("%s is missing" % man)
    seen = {}
    for l in lines:
        parts = l.split()
        if len(parts) != 2 or parts[0] not in ARCHES or parts[0] in seen or not DIGEST.fullmatch(parts[1]):
            refuse("%s: a malformed, unknown or repeated line: %r" % (man, l))
        seen[parts[0]] = parts[1]
    if sorted(seen) != sorted(ARCHES):
        refuse("%s: an architecture is missing (want %s)" % (man, ", ".join(ARCHES)))
    return {"linux/" + a: seen[a] for a in ARCHES}


def items_of(path):
    d = strict_json(path)
    if not isinstance(d, dict):
        refuse("%s is not a JSON object" % path)
    return d


def image_input(digests, images_dir, items_path):
    """Every digest that goes into the VEX forms and the manifest must be one Build verified: the index is Build's digests.json entry and its item image-<variant>,
    each child is Build's item image-<variant>-manifest-<arch>, and the lock and SBOM files are the bytes of Build's items lock-<variant> and sbom-<variant>."""
    items = items_of(items_path)
    out = {}
    for v in VARIANTS:
        index = digests["image-" + v]
        kids = children_of(images_dir, v, index)
        if items.get("image-" + v) != index:
            refuse("%s: image-%s is %s, not the attested %s" % (items_path, v, items.get("image-" + v), index))
        for a in ARCHES:
            key = "image-%s-manifest-%s" % (v, a)
            if items.get(key) != kids["linux/" + a]:
                refuse("%s: %s is %s, but %s/%s.manifests names %s" % (items_path, key, items.get(key), images_dir, v, kids["linux/" + a]))
        for key, rel in (("lock-" + v, v + ".full.lock.json"), ("sbom-" + v, os.path.join(v + "-sbom", "sbom.json"))):
            path = os.path.join(images_dir, rel)
            try:
                have = "sha256:" + sha256_file(path)
            except OSError:
                refuse("%s is missing" % path)
            if items.get(key) != have:
                refuse("%s: %s is %s, but %s hashes to %s" % (items_path, key, items.get(key), path, have))
        out[v] = {"index": index, "children": kids}
    return out


def cmd_images(a):
    doc = image_input(digests_of(a.digests), a.images_dir, a.items)
    write_atomic(a.out, json.dumps(doc, indent=2, sort_keys=True) + "\n")


def cmd_manifest(a):
    if not FINAL.fullmatch(a.version or ""):
        refuse("version %r is not vX.Y.Z (a release candidate has no release manifest)" % a.version)
    if not re.fullmatch(r"[0-9a-f]{40}", a.commit or ""):
        refuse("commit %r is not 40 lower-case hex" % a.commit)
    d = digests_of(a.digests)
    apks = sorted(k for k in d if k.startswith("apk-"))
    want = sorted("apk-%s-%s" % (v, ar) for v in ("standard", "fips") for ar in ARCHES)
    if apks != want:
        refuse("%s: the apk keys must be exactly %s (missing: %s)" % (a.digests, ", ".join(want), ", ".join(k for k in want if k not in d) or "none"))
    if not FINAL.fullmatch(a.baseline_version or ""):
        refuse("baseline version %r is not vX.Y.Z" % a.baseline_version)
    base = {}
    for key, rel in (("requirements_baseline", "requirements/releases/%s.yaml" % a.baseline_version), ("test_evidence", "test-evidence/mappings.yaml")):
        p = os.path.join(a.repo_root, rel)
        if os.path.islink(p):
            refuse("%s is a symlink" % rel)
        if not os.path.isfile(p):
            refuse("%s is missing: the manifest records it" % rel)
        base[key] = {"path": rel, "sha256": sha256_file(p)}
    base["requirements_baseline"] = {"path": base["requirements_baseline"]["path"], "version": a.baseline_version, "sha256": base["requirements_baseline"]["sha256"]}
    img = image_input(d, a.images_dir, a.items)
    vex = []
    for form, name in (("openvex", "fosterstack-cache.openvex.json"), ("inspector-suppression-rules", "fosterstack-cache-%s.inspector-filters.json" % a.version),
                       ("csaf-2.0-vex", "fosterstack-cache-%s.csaf.json" % a.version)):
        p = os.path.join(a.vex_dir, name)
        if not os.path.isfile(p) or os.path.islink(p):
            refuse("%s is missing: the VEX forms are made before the manifest" % name)
        vex.append({"file": name, "form": form, "sha256": sha256_file(p)})
    doc = {
        "version": a.version, "commit": a.commit,
        "run": {"url": a.ci_url, "workflow": a.workflow},
        "images": [{"variant": v, "digest": img[v]["index"], "children": img[v]["children"],
                    "refs": ["%s@%s" % (REPO_GHCR, img[v]["index"]), "%s@%s" % (REPO_HUB, img[v]["index"])]} for v in VARIANTS],
        "archives": [{"name": k, "digest": d[k]} for k in sorted(d) if k.startswith("archive-")],
        "apks": [{"name": k, "digest": d[k]} for k in apks],
        "requirements_baseline": base["requirements_baseline"],
        "test_evidence": base["test_evidence"],
        "vex": vex,
    }
    write_atomic(a.out, json.dumps(doc, indent=2) + "\n")


def meta_names(version):
    return ["release-manifest.json", "fosterstack-cache.openvex.json", "fosterstack-cache-%s.csaf.json" % version, "fosterstack-cache-%s.inspector-filters.json" % version]


def cmd_list(a):
    if not FINAL.fullmatch(a.version or ""):
        refuse("version %r is not vX.Y.Z (a release candidate has no list)" % a.version)
    lines = []
    for n in meta_names(a.version):
        p = os.path.join(a.dir, n)
        if os.path.islink(p):
            refuse("%s is a symlink" % n)
        if not os.path.isfile(p):
            refuse("%s is missing" % n)
        if os.path.getsize(p) == 0:
            refuse("%s is empty" % n)
        lines.append("%s  %s\n" % (sha256_file(p), n))
    write_atomic(a.out, "".join(lines))


def parse_sums(path, what):
    out = []
    try:
        text = open(path).read()
    except OSError:
        refuse("%s is missing" % what)
    for l in text.split("\n"):
        if not l:
            continue
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


def cmd_gate(a):
    """GATE (REQ-CHAIN-007-AC13): the directory holds checksums.txt with its bundle and release-files.sha256 with its bundle, and the four
    metadata files; checksums.txt lists existing files with their hashes; release-files.sha256 lists exactly the four metadata files with theirs;
    and every asset is covered: it is in checksums.txt or in release-files.sha256, or it is a bundle whose signed file is an asset, or it has its
    own bundle, or it is an apk (signed by the release key inside the file), a Witness record (`*-collection.json`, a signed envelope the stages
    verified) or Build's digests.json or items.json (products of Build's signed record). A symlink, a directory, or anything else is refused by name."""
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
        if n in covered:
            continue
        if n.endswith(".bundle"):
            if signed_by(n) not in have:
                refuse("%s signs %s, which is not an asset" % (n, signed_by(n)))
            continue
        if bundle_of(n) in have or n.endswith(".apk") or n.endswith("-collection.json") or n in ("digests.json", "items.json"):
            continue
        refuse("%s is covered by nothing: not in checksums.txt, not in release-files.sha256, and no bundle signs it" % n)
    if a.same_as:
        same_as(a)


def cmd_bind_archives(a):
    """BIND (REQ-CHAIN-007-AC9, round 1 B3): DIST holds exactly the four Linux archives Build recorded, each hashing to the digest of Build's digests.json
    (item archive-linux-ARCH / archive-fips-linux-ARCH for fscache_VER_linux_ARCH.tar.gz / fscache-fips_VER_linux_ARCH.tar.gz). Nothing is written."""
    ver = a.version
    try:
        with open(a.digests) as f:
            digests = json.load(f)
    except (OSError, ValueError):
        refuse("%s is not readable JSON" % a.digests)
    want = {}
    for arch in ("amd64", "arm64"):
        want["archive-linux-" + arch] = "fscache_%s_linux_%s.tar.gz" % (ver, arch)
        want["archive-fips-linux-" + arch] = "fscache-fips_%s_linux_%s.tar.gz" % (ver, arch)
    have = sorted(n for n in os.listdir(a.dist) if n.endswith(".tar.gz"))
    if have != sorted(want.values()):
        gone = sorted(i for i, n in want.items() if n not in have)
        extra = sorted(n for n in have if n not in want.values())
        refuse("%s does not hold exactly the four archives Build recorded (missing: %s; not recorded: %s)" % (a.dist, ", ".join(gone) or "none", ", ".join(extra) or "none"))
    for item, name in sorted(want.items()):
        p = os.path.join(a.dist, name)
        if os.path.islink(p) or not os.path.isfile(p):
            refuse("%s is not a regular file" % p)
        got = "sha256:" + sha256_file(p)
        if digests.get(item) != got:
            refuse("%s (%s) is %s, Build's digests.json records %s: refusing to attach it" % (name, item, got, digests.get(item)))


def main(argv):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("images"); i.add_argument("--digests", required=True); i.add_argument("--images-dir", required=True); i.add_argument("--items", required=True); i.add_argument("--out", required=True)
    m = sub.add_parser("manifest")
    for k in ("digests", "images-dir", "items", "vex-dir", "baseline-version", "repo-root", "version", "commit", "ci-url", "workflow", "out"):
        m.add_argument("--" + k, required=True)
    l = sub.add_parser("list"); l.add_argument("--version", required=True); l.add_argument("--dir", required=True); l.add_argument("--out", required=True)
    g = sub.add_parser("gate"); g.add_argument("--dir", required=True); g.add_argument("--same-as")
    b = sub.add_parser("bind-archives"); b.add_argument("--version", required=True); b.add_argument("--digests", required=True); b.add_argument("--dist", required=True)
    a = p.parse_args(argv)
    {"images": cmd_images, "manifest": cmd_manifest, "list": cmd_list, "gate": cmd_gate, "bind-archives": cmd_bind_archives}[a.cmd](a)


if __name__ == "__main__":
    main(sys.argv[1:])
