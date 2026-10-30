#!/usr/bin/env python3
"""Print the digests of an OCI image layout tarball (v0.3.0 rules 30, 31, 37).

  oci-digest.py TAR                       print the digests of the tar
  oci-digest.py unpack TAR DIR DIGEST MANIFESTS   write the image as an OCI layout DIRECTORY at DIR (deterministic), the index
                                          digest (one line) to DIGEST and "<arch> sha256:<hex>" lines to MANIFESTS
  oci-digest.py make-view REC ARCHIVE VIEW        link the archive's apks and its recorded index into VIEW/<arch>/
  oci-digest.py render-config CONFIG OUT VERSION  CONFIG with @FSCACHE_VERSION@ replaced
  oci-digest.py check-dots NAME           exit 1 for a . or .. component after another component
  oci-digest.py check-version V           exit 1 unless V is X.Y.Z, X.Y.Z-rcN or 0.0.0-rc.1
  oci-digest.py lock compare|arch-check|verify-archive|evidence ...   the lock-file checks of the image build
  oci-digest.py check-keys REC DIR        the keyring directory holds exactly the recorded keys
  oci-digest.py check-index REC ARCHIVE   print "<arch><TAB><path>" of the recorded package index per architecture
  oci-digest.py render-date EPOCH         print EPOCH as YYYY-MM-DDTHH:MM:SSZ
  oci-digest.py is-empty DIR              exit 0 when DIR can be listed and is empty

The decisions of the image assembler (so that its script is straight-line text). Each prints its answer, or the refusal
"<script name>: <reason>" on standard error with the exit status the script had for it:
  oci-digest.py variant-field V FIELD     pkg, config or baselock of the variant V (production or fips)
  oci-digest.py check-roots ARCHIVE MELREPO KEYDIR OUT RENDER   the five path arguments: plain ASCII, not empty, no hidden dots, no symlink
  oci-digest.py abs-dir DIR               DIR as an absolute physical path when it is a directory, else as typed
  oci-digest.py abs-file FILE             FILE with its directory made absolute and physical, else as typed
  oci-digest.py apk-version V             the apk version syntax of V: 0.3.0-rc1 -> 0.3.0_rc1, 0.0.0-rc.1 -> 0.0.0_rc1
  oci-digest.py check-inputs ARCHIVE MELREPO KEYDIR OUT CONFIG BASELOCK   no address, and the directories and files are there
  oci-digest.py check-keydir DIR          DIR holds the two key files
  oci-digest.py check-melrepo DIR PKG APKVER      our apk and an APKINDEX.tar.gz for both architectures are in the melange repository
  oci-digest.py check-workdir DIR         none of the three links of the run exists yet in DIR
  oci-digest.py prepare-render RENDER TMP   prints the render directory: RENDER (made, or empty and not a link) or TMP/render
  oci-digest.py check-out OUT VARIANT     OUT is a directory that can be listed and holds none of the variant's own names
  oci-digest.py apko-verdict KIND RC PROBE   the status of a sealed apko call (KIND lock or build) and of the probe: 0, 1 or 4
  oci-digest.py pick-sbom DIR             prints the one image SBOM in DIR

apko writes the image as an OCI layout. The image digest a customer pulls is the digest of the OCI INDEX (the blob that
lists the per-architecture manifests), not the sha256 of the tar file. This reads oci-layout, index.json, the index blob
and the per-architecture manifest blobs, requires every blob it reads to hash to its own name, and prints

    index sha256:<hex>
    <arch> sha256:<hex>      (one line per per-architecture manifest, in index order: amd64, arm64)

Two layouts are read. (1) A standard OCI layout: oci-layout and index.json, where index.json names one index blob under
blobs/sha256/ that lists the per-architecture manifests. (2) The tar real apko (v1.4.6) writes: no oci-layout, blobs are
top-level members named sha256:<hex>, and index.json is the multi-architecture index itself; its digest is the sha256 of
the index.json bytes. Every manifest blob is checked against its name in both.

Exit codes: 0 ok | 1 the layout is unusable: a missing oci-layout, index.json or blob, or a blob whose bytes do not hash to
its name (the message names the file or blob) | 2 usage.
"""
import base64
import datetime
import hashlib
import os
import re
import json
import shutil
import sys
import tarfile


ASSEMBLER = "assemble-image.sh"   # the name every refusal of the assembler's checks carries (the tests and the proofs read it)
LOCKER = "apko-lock.sh"           # and of the lock checks
ARCHS = ("amd64", "arm64")
INDEX_MT = "application/vnd.oci.image.index.v1+json"
MANIFEST_MT = "application/vnd.oci.image.manifest.v1+json"


def fail(msg):
    print("oci-digest: " + msg, file=sys.stderr)
    sys.exit(1)


def norm(name):
    return name[2:] if name.startswith("./") else name


def read_members(t):
    """name (without a leading ./) -> bytes, regular files only; two members with the same normalised name are refused (no last-one-wins)"""
    out = {}
    for m in t.getmembers():
        if m.isfile():
            n = norm(m.name)
            if n in out:
                fail("the tar holds the member %s twice (duplicate member names are refused)" % n)
            out[n] = t.extractfile(m).read()
    return out


def check_manifests(mans, where):
    if not isinstance(mans, list) or not mans or not all(isinstance(m, dict) for m in mans):
        fail("%s: manifests must be a non-empty list of objects (exactly one amd64 and one arm64 manifest, each with a platform architecture)" % where)
    """exactly one linux/amd64 and one linux/arm64 manifest, each a manifest of the OCI manifest media type with a platform architecture and os linux"""
    archs = []
    for m in mans:
        need(m, "digest", where + " entry")
        if not isinstance(m.get("platform"), dict):
            fail("%s: manifest %s has no platform object" % (where, m.get("digest")))
        if m.get("mediaType") != MANIFEST_MT:
            fail("%s: manifest %s has the media type %r, not %s" % (where, m.get("digest"), m.get("mediaType"), MANIFEST_MT))
        if (m.get("platform") or {}).get("os") != "linux":
            fail("%s: manifest %s has platform.os %r, not linux" % (where, m.get("digest"), (m.get("platform") or {}).get("os")))
        arch = (m.get("platform") or {}).get("architecture")
        if arch is not None and not isinstance(arch, str):
            fail("%s: manifest %s has a platform.architecture that is not a string" % (where, m.get("digest")))
        if not arch:
            fail("%s: manifest %s has no platform.architecture" % (where, m.get("digest")))
        archs.append(arch)
    digs = [m["digest"] for m in mans]
    if len(set(digs)) != len(digs):
        fail("%s: two manifest entries name the same manifest blob (%s); amd64 and arm64 must be different manifests" % (where, digs[0]))
    if sorted(archs) != sorted(ARCHS):
        fail("%s must list exactly one amd64 and one arm64 manifest, not %s" % (where, archs or "none"))


def need(entry, key, what):
    if not isinstance(entry, dict) or not isinstance(entry.get(key), str):
        fail("%s has no %s (a malformed entry)" % (what, key))
    return entry[key]


def sha256_hex(digest, what):
    """the digest must be exactly sha256:<64 lowercase hex>: another algorithm label with the same hex text is a different claim"""
    if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        fail("the digest of %s is %r, not sha256:<64 lowercase hex digits>" % (what, digest))
    return digest[7:]


def check_manifest_blob(members, raw, layout, what, platform_arch=None):
    """the manifest's config and layer blobs, where the tar carries them, must hash to their names; a config blob must be present"""
    try:
        man = json.loads(raw)
    except ValueError:
        fail("%s is not JSON" % what)
    cfg = man.get("config") if isinstance(man, dict) else None
    cdig = need(cfg, "digest", what + " config")
    want_arch = None if platform_arch is None else platform_arch
    hexd = sha256_hex(cdig, what + " config")
    if cfg.get("mediaType") != CONFIG_MT:
        fail("the config descriptor of %s has the media type %r, not %s" % (what, cfg.get("mediaType"), CONFIG_MT))
    cname = ("sha256:" + hexd) if layout == "apko" else ("blobs/sha256/" + hexd)
    if cname not in members:
        fail("the config blob %s of %s is missing from the tar" % (cname, what))
    if hashlib.sha256(members[cname]).hexdigest() != hexd:
        fail("the config blob %s of %s does not hash to its name" % (cname, what))
    if cfg.get("size") != len(members[cname]):
        fail("the config descriptor of %s says size %r but the blob %s holds %d bytes" % (what, cfg.get("size"), cname, len(members[cname])))
    try:
        cfg_arch = json.loads(members[cname]).get("architecture")
    except (ValueError, AttributeError):
        fail("the config blob %s of %s is not JSON" % (cname, what))
    cfg_os = json.loads(members[cname]).get("os")
    if want_arch is not None and cfg_arch != want_arch:
        fail("the config of %s says architecture %r but the index lists the manifest as %r (the config must name its architecture)" % (what, cfg_arch, want_arch))
    if cfg_os != "linux":
        fail("the config of %s says os %r, not linux" % (what, cfg_os))
    if man.get("schemaVersion") != 2:
        fail("the manifest blob of %s has schemaVersion %r, not 2" % (what, man.get("schemaVersion")))
    if man.get("mediaType", MANIFEST_MT) != MANIFEST_MT:
        fail("the manifest blob of %s has the media type %r, not %s (its own media type must agree with its index entry)" % (what, man.get("mediaType"), MANIFEST_MT))
    layers = man.get("layers")   # an empty list is allowed (valid OCI); a missing or non-list value is not
    if not isinstance(layers, list):
        fail("the layers of %s are missing or not a list (a malformed manifest)" % what)
    for layer in layers:
        lhex = sha256_hex(need(layer, "digest", what + " layer"), what + " layer")
        found = [n for n in ((("sha256:" + lhex), lhex + ".tar.gz", lhex) if layout == "apko" else (("blobs/sha256/" + lhex),)) if n in members]
        if not found:
            fail("the layer blob %s of %s is missing from the tar" % (lhex, what))
        if hashlib.sha256(members[found[0]]).hexdigest() != lhex:
            fail("the layer blob %s of %s does not hash to its name" % (found[0], what))
        if layer.get("mediaType") not in LAYER_MTS:
            fail("the layer descriptor %s of %s has the media type %r, not an OCI layer type" % (lhex, what, layer.get("mediaType")))
        if layer.get("size") != len(members[found[0]]):
            fail("the layer descriptor %s of %s says size %r but the blob holds %d bytes" % (lhex, what, layer.get("size"), len(members[found[0]])))


def blob_in(members, digest, what):
    algo, _, hexd = digest.partition(":")
    if algo != "sha256" or len(hexd) != 64:
        fail("%s: unsupported digest %r" % (what, digest))
    return hexd


def apko_layout(members, path):
    raw = members["index.json"]
    try:
        top = json.loads(raw)
        mans = top["manifests"]
    except (ValueError, KeyError, TypeError):
        fail("index.json in %s is not an OCI index" % path)
    if top.get("schemaVersion") != 2:
        fail("index.json in %s has schemaVersion %r, not 2" % (path, top.get("schemaVersion")))
    if top.get("mediaType") != INDEX_MT:
        fail("index.json in %s has the media type %r, not %s" % (path, top.get("mediaType"), INDEX_MT))
    check_manifests(mans, "index.json")
    lines = ["index sha256:" + hashlib.sha256(raw).hexdigest()]
    for m in mans:
        hexd = blob_in(members, need(m, "digest", "a manifest entry in index.json"), "a per-architecture manifest")
        name = "sha256:" + hexd
        if name not in members:
            fail("%s is missing from the image tar (a per-architecture manifest)" % name)
        if hashlib.sha256(members[name]).hexdigest() != hexd:
            fail("%s does not hash to its name (sha256:%s, a per-architecture manifest)" % (name, hashlib.sha256(members[name]).hexdigest()))
        if m.get("size") != len(members[name]):
            fail("the manifest descriptor %s says size %r but the blob holds %d bytes" % (name, m.get("size"), len(members[name])))
        check_manifest_blob(members, members[name], "apko", name, m["platform"]["architecture"])
        lines.append("%s %s" % (m["platform"]["architecture"], m["digest"]))
    return lines


def standard_layout(members, path):
    try:
        top = json.loads(members["index.json"])
        entries = top["manifests"]
    except (ValueError, KeyError, TypeError):
        fail("index.json must name exactly one index blob")
    if not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], dict):
        fail("index.json must name exactly one index blob")
    idx_digest = need(entries[0], "digest", "the index entry in index.json")
    if entries[0].get("mediaType") != INDEX_MT:
        fail("the index entry in index.json has the media type %r, not %s" % (entries[0].get("mediaType"), INDEX_MT))
    name = "blobs/sha256/" + blob_in(members, idx_digest, "the index")
    if name not in members:
        fail("%s is missing from the layout (the index)" % name)
    if hashlib.sha256(members[name]).hexdigest() != idx_digest.split(":")[1]:
        fail("%s does not hash to its name (the index)" % name)
    if entries[0].get("size") != len(members[name]):
        fail("the index descriptor in index.json says size %r but the index blob holds %d bytes" % (entries[0].get("size"), len(members[name])))
    try:
        idx = json.loads(members[name]); mans = idx["manifests"]
    except (ValueError, KeyError, TypeError):
        fail("the index blob %s is not an OCI index" % idx_digest)
    if idx.get("schemaVersion") != 2 or top.get("schemaVersion") != 2:
        fail("index.json or the index blob %s has a schemaVersion other than 2" % idx_digest)
    if idx.get("mediaType") != INDEX_MT:
        fail("the index blob %s has the media type %r, not %s" % (idx_digest, idx.get("mediaType"), INDEX_MT))
    check_manifests(mans, "the index blob")
    lines = ["index " + idx_digest]
    for m in mans:
        if m.get("mediaType") != MANIFEST_MT:
            fail("manifest %s has the media type %r, not %s" % (m.get("digest"), m.get("mediaType"), MANIFEST_MT))
        mn = "blobs/sha256/" + blob_in(members, m["digest"], "a per-architecture manifest")
        if mn not in members:
            fail("%s is missing from the layout (a per-architecture manifest)" % mn)
        if hashlib.sha256(members[mn]).hexdigest() != m["digest"].split(":")[1]:
            fail("%s does not hash to its name (a per-architecture manifest)" % mn)
        if m.get("size") != len(members[mn]):
            fail("the manifest descriptor %s says size %r but the blob holds %d bytes" % (m["digest"], m.get("size"), len(members[mn])))
        check_manifest_blob(members, members[mn], "standard", mn, m["platform"]["architecture"])
        lines.append("%s %s" % (m["platform"]["architecture"], m["digest"]))
    return lines


def check_keys(rec, kd):
    """the keyring directory holds exactly the two recorded keys with the recorded bytes (exit 2 on any refusal)"""
    def refuse(m): print(ASSEMBLER + ": " + m, file=sys.stderr); sys.exit(2)
    want = {}
    _t = open(rec, newline="").read()
    if "\r" in _t or (_t and not _t.endswith("\n")):
        refuse("the key record %s is malformed: lines must end in a plain newline (no carriage return, no missing final newline)" % rec)
    for l in [l for l in _t.splitlines() if l.strip()]:
        m = re.fullmatch(r"(wolfi-signing\.rsa\.pub|assembly\.rsa\.pub) sha256:([0-9a-f]{64})", l)
        if not m or m.group(1) in want:
            refuse("key record %s has a malformed or repeated line: %r" % (rec, l))
        want[m.group(1)] = m.group(2)
    if sorted(want) != ["assembly.rsa.pub", "wolfi-signing.rsa.pub"]:
        refuse("key record %s must list exactly wolfi-signing.rsa.pub and assembly.rsa.pub" % rec)
    have = sorted(os.listdir(kd))
    if have != sorted(want):
        refuse("the keyring directory %s must hold exactly %s; found %s (an extra or missing key file, e.g. %s)" % (kd, ", ".join(sorted(want)), ", ".join(have), next((h for h in have if h not in want), "none")))
    for k in sorted(want):
        if os.path.islink(os.path.join(kd, k)) or not os.path.isfile(os.path.join(kd, k)):
            refuse("%s in %s is a symlink or not a regular file (symlink); the keyring files must be regular files in the directory" % (k, kd))
        got = hashlib.sha256(open(os.path.join(kd, k), "rb").read()).hexdigest()
        if got != want[k]:
            refuse("%s in %s hashes to sha256:%s, not the recorded sha256:%s" % (k, kd, got, want[k]))


def check_index(rec, arch_dir):
    """{arch: path} of the archive's recorded package index of each architecture (exit 2 on any refusal)"""
    found = {}
    def refuse(msg):
        print(ASSEMBLER + ": " + msg, file=sys.stderr); sys.exit(2)
    _t = open(rec, newline="").read()
    if "\r" in _t or (_t and not _t.endswith("\n")):
        refuse("the index record %s is malformed: lines must end in a plain newline (no carriage return, no missing final newline)" % rec)
    lines = [l for l in _t.splitlines() if l.strip()]
    want = {}
    for l in lines:
        m = re.fullmatch(r"(x86_64|aarch64) sha256:([0-9a-f]{64})", l)
        if not m:
            refuse("index record %s has a malformed line (expected '<arch> sha256:<64 hex>'): %r" % (rec, l))
        if m.group(1) in want:
            refuse("index record %s has two lines for %s (twice); exactly one per architecture" % (rec, m.group(1)))
        want[m.group(1)] = m.group(2)
    for a in ("x86_64", "aarch64"):
        if a not in want:
            refuse("index record %s has no line for %s" % (rec, a))
        # the index a build uses is the one the record names: index/APKINDEX-<recorded sha256>.tar.gz, a regular file inside the archive
        # (never whatever APKINDEX.tar.gz points at today: a rebuild of an old tag must see the old index). A plain APKINDEX.tar.gz is
        # accepted only when it is a regular file holding exactly those bytes.
        for comp in (os.path.join(arch_dir, a), os.path.join(arch_dir, a, "index")):
            if os.path.islink(comp):
                refuse("%s is a symlink (every directory on the way to the index must be a real directory inside the archive)" % comp)
        named = os.path.join(arch_dir, a, "index", "APKINDEX-%s.tar.gz" % want[a])
        plain = os.path.join(arch_dir, a, "APKINDEX.tar.gz")
        if os.path.lexists(named):
            if os.path.islink(named) or not os.path.isfile(named):
                refuse("%s is a symlink or not a regular file (outside the archive's own files); the recorded index for %s must be a regular file in the archive" % (named, a))
            chosen = named
        elif os.path.isfile(plain) and not os.path.islink(plain):
            chosen = plain
        else:
            refuse("the archive has no %s (the recorded index for %s) and no plain regular APKINDEX.tar.gz holding it; a symlink pointer alone is not accepted" % (named, a))
        if not os.path.realpath(chosen).startswith(os.path.realpath(arch_dir) + os.sep):
            refuse("%s resolves outside the archive (symlink); refusing" % chosen)
        got = hashlib.sha256(open(chosen, "rb").read()).hexdigest()
        if got != want[a]:
            refuse("the package index for %s in the archive (%s) hashes to sha256:%s, not the recorded sha256:%s (index digest does not match its name or the record)" % (a, chosen, got, want[a]))
        found[a] = os.path.realpath(chosen)
    return found


CONFIG_MT = "application/vnd.oci.image.config.v1+json"
LAYER_MTS = ("application/vnd.oci.image.layer.v1.tar", "application/vnd.oci.image.layer.v1.tar+gzip", "application/vnd.oci.image.layer.v1.tar+zstd")
BLOB_NAME = re.compile(r"(?:sha256:)?([0-9a-f]{64})(?:\.tar\.gz)?")


def make_view(rec, archive, view):
    """the archive as apko sees it: every apk of the archive linked under VIEW/<arch>/, and as APKINDEX.tar.gz
    exactly the recorded index (not the pointer); a file name holding a control character is refused (exit 2)"""
    idx = check_index(rec, archive)
    for a in ("x86_64", "aarch64"):
        for root, dirs, files in os.walk(os.path.join(archive, a)):
            for n in dirs + files:
                if any(ord(c) < 32 or ord(c) == 127 for c in n):
                    bad = "".join("?" if (ord(c) < 32 or ord(c) == 127) else c for c in n)
                    print("%s: a file name under %s/%s holds a control character: %s; refusing" % (ASSEMBLER, archive, a, bad), file=sys.stderr)
                    sys.exit(2)
        os.makedirs(os.path.join(view, a), exist_ok=True)
        d = os.path.join(archive, a)
        for n in sorted(os.listdir(d)):
            if n.endswith(".apk") and os.path.exists(os.path.join(d, n)):
                os.symlink(os.path.join(d, n), os.path.join(view, a, n))
        os.symlink(idx[a], os.path.join(view, a, "APKINDEX.tar.gz"))


def render_config(config, out, version):
    """the apko config with @FSCACHE_VERSION@ replaced by the apk version"""
    with open(config, newline="") as fh:
        text = fh.read()
    with open(out, "w", newline="") as fh:
        fh.write(text.replace("@FSCACHE_VERSION@", version))


def check_version(v):
    """exit 1 unless V is exactly the chain's grammar: X.Y.Z, X.Y.Z-rcN (N digits, no leading zero, no dot) or the snapshot version 0.0.0-rc.1"""
    if not (re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-rc[1-9][0-9]*)?", v) or v == "0.0.0-rc.1"):
        sys.exit(1)


def has_hidden_dots(path):
    """True when PATH has a . or .. component after another component (it could hide a symlinked root); leading ./ and ../ are allowed"""
    q = path
    while q.startswith("./"):
        q = q[2:]
    while q.startswith("../"):
        q = q[3:]
    parts = ("/" + q + "/")
    return "/./" in parts or "/../" in parts


def check_dots(path):
    """exit 1 when NAME has a . or .. component after another component"""
    if has_hidden_dots(path):
        sys.exit(1)


def write_layout(members, standard, dest):
    """write the image as an OCI layout DIRECTORY: oci-layout, index.json, blobs/sha256/<hex> and nothing else, every blob
    hashing to its name, regular files with mode 0644 in directories 0755, written in sorted order (the same image gives the
    same bytes and the same listing). A standard layout is copied as it is; the tar real apko writes (blobs named sha256:<hex>,
    index.json the multi-architecture index itself, no oci-layout) gets a canonical oci-layout and a one-descriptor index.json
    naming the index blob (the sha256 of apko's index.json)."""
    blobs = {}
    for name in sorted(members):
        if standard:
            m = re.fullmatch(r"blobs/sha256/([0-9a-f]{64})", name)
        else:
            m = BLOB_NAME.fullmatch(name)
        if m:
            if hashlib.sha256(members[name]).hexdigest() != m.group(1):
                fail("%s does not hash to its name (not written)" % name)
            blobs[m.group(1)] = members[name]
    files = {}
    if standard:
        files["oci-layout"] = members["oci-layout"]
        files["index.json"] = members["index.json"]
    else:
        raw = members["index.json"]
        h = hashlib.sha256(raw).hexdigest()
        blobs[h] = raw
        files["oci-layout"] = b'{"imageLayoutVersion":"1.0.0"}'
        files["index.json"] = json.dumps({"schemaVersion": 2, "manifests": [{"mediaType": INDEX_MT, "digest": "sha256:" + h, "size": len(raw)}]},
                                         sort_keys=True, separators=(",", ":")).encode()
    if os.path.lexists(dest) and (os.path.islink(dest) or not os.path.isdir(dest) or os.listdir(dest)):
        fail("%s exists and is not an empty directory (the layout is written into a fresh directory)" % dest)
    os.makedirs(os.path.join(dest, "blobs", "sha256"), exist_ok=True)
    for d in (dest, os.path.join(dest, "blobs"), os.path.join(dest, "blobs", "sha256")):
        os.chmod(d, 0o755)
    for name in sorted(files):
        _put(os.path.join(dest, name), files[name])
    for h in sorted(blobs):
        _put(os.path.join(dest, "blobs", "sha256", h), blobs[h])


def _put(path, data):
    with open(path, "wb") as fh:
        fh.write(data)
    os.chmod(path, 0o644)


def read_digests(path):
    """the validated digest lines of the tar NAME, the member map and whether the layout is the standard one"""
    try:
        with tarfile.open(path) as t:
            members = read_members(t)
    except (OSError, tarfile.TarError) as e:
        fail("cannot read %s: %s" % (path, e))
    if "index.json" not in members:
        fail("%s has no index.json" % path)
    for name in sorted(members):   # a blob nothing refers to is still a blob: every one must hash to its name (the unpack path checks the same)
        if name.startswith("blobs/") and not re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", name):
            fail("%s: %s is in the blob namespace but is not blobs/sha256/<64 lowercase hex digits>" % (path, name))
        if name.startswith("sha256:") and not re.fullmatch(r"sha256:[0-9a-f]{64}", name):
            fail("%s: %s is named like a blob but is not sha256:<64 lowercase hex digits>" % (path, name))
        m = re.fullmatch(r"blobs/sha256/([0-9a-f]{64})", name) or BLOB_NAME.fullmatch(name)
        if m and hashlib.sha256(members[name]).hexdigest() != m.group(1):
            fail("%s: %s does not hash to its name" % (path, name))
    if "oci-layout" in members:
        try:
            lay = json.loads(members["oci-layout"])
        except ValueError:
            lay = None
        if lay != {"imageLayoutVersion": "1.0.0"}:
            fail("%s: oci-layout is not exactly {\"imageLayoutVersion\": \"1.0.0\"}" % path)
        return standard_layout(members, path), members, True
    return apko_layout(members, path), members, False


# ---- the lock-file checks of the image build (the lock tool's entry script calls lock_main) --------------------------------------------

ARCH_ERR = 2
KINDS = {"sha1": hashlib.sha1, "sha256": hashlib.sha256}   # the checksum kinds a lock section may use


class Check(ValueError):
    pass


def ok(cond):
    """an explicit check (python -O would drop an assert)"""
    if not cond:
        raise Check("check failed")


def die(msg, code=1):
    print(LOCKER + ": " + msg, file=sys.stderr)
    sys.exit(code)


def load(path, allow_dup=None):
    try:
        d = json.load(open(path))
        pk = d["contents"]["packages"]
        ok(d.get("version") == "v1" and isinstance(pk, list))
    except (OSError, ValueError, KeyError) as e:
        die("cannot read lock file %s: %s" % (path, e), 2)
    for i, e in enumerate(pk):
        try:
            ok(all(isinstance(e[k], str) and e[k] for k in ("name", "version", "architecture")))
            ok(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", e["name"]) and ".." not in e["name"])
            ok(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+~-]*", e["version"]) and ".." not in e["version"])
            ok(re.fullmatch(r"[a-z0-9_]+", e["architecture"]))
            ok(all(isinstance(e[p]["checksum"], str) for p in ("control", "data")))
        except (KeyError, TypeError, ValueError):
            die("malformed lock entry %d in %s (%s): name, version, architecture and the control and data checksums are required" % (i, path, e.get("name", "?") if isinstance(e, dict) else "?"), 2)
    seen = {}
    for e in pk:   # a set comparison would silently merge a repeated entry: a lock names each (package, version, architecture) once
        k = (e["name"], e["version"], e["architecture"])
        if k in seen and e["name"] != allow_dup:   # allow_dup: compare counts the entries of OUR apk itself and names "exactly one" (the checks that follow)
            die("the lock file %s lists %s %s (%s) more than once" % (path, k[0], k[1], k[2]), 2)
        seen[k] = True
    return d, pk


def key(e):
    sig = (e.get("signature") or {}).get("checksum", "")
    return (e["name"], e["version"], e["architecture"], e["control"]["checksum"], e["data"]["checksum"], sig, e.get("checksum", ""))


def b64(raw): return base64.b64encode(raw).decode()


def opts(argv, names):
    out, i = {}, 0
    while i < len(argv):
        if argv[i] in names and i + 1 < len(argv):
            out[argv[i]] = argv[i + 1]; i += 2   # a repeated flag: the last one wins
        else:
            die("unknown or incomplete argument: %s" % argv[i], 2)
    return out


def compare(argv):
    if len(argv) < 2:
        die("usage: compare BASE FULL --apk NAME", 2)
    base_p, full_p, o = argv[0], argv[1], opts(argv[2:], ("--apk",))
    apk = o.get("--apk") or die("--apk NAME is required", 2)
    _, bpk = load(base_p)
    _, fpk = load(full_p, allow_dup=apk)
    if any(e["name"] == apk for e in bpk):
        die("the base lock %s already holds %s; the base lock must not hold our apk" % (base_p, apk), 2)
    ours = [e for e in fpk if e["name"] == apk]
    if not ours:
        die("the full lock has no entry for our apk %s" % apk)
    archs = sorted({e["architecture"] for e in bpk})
    for a in archs:
        n = sum(1 for e in ours if e["architecture"] == a)
        if n == 0:
            die("our apk %s is missing for architecture %s in the full lock" % (apk, a))
        if n != 1:
            die("the full lock has %d entries for our apk %s on %s; exactly one is expected" % (n, apk, a))
    extra = sorted({e["architecture"] for e in ours} - set(archs))
    if extra:
        die("the full lock holds our apk %s for architecture(s) %s that the base lock does not have" % (apk, ", ".join(extra)))
    if len({e["version"] for e in ours}) != 1:
        die("the full lock holds our apk %s at more than one version" % apk)
    rest = {key(e) for e in fpk if e["name"] != apk}
    base = {key(e) for e in bpk}
    msgs = []
    for k in sorted(base - rest):
        msgs.append("%s %s (%s) is in the base lock but not, or not identically, in the full lock" % (k[0], k[1], k[2]))
    for k in sorted(rest - base):
        msgs.append("%s %s (%s) is in the full lock but not, or not identically, in the base lock" % (k[0], k[1], k[2]))
    if msgs:
        die("the full lock is not the base lock plus %s:\n  %s" % (apk, "\n  ".join(msgs)))


def arch_check(argv):
    if len(argv) != 1:
        die("usage: arch-check LOCK", 2)
    _, pk = load(argv[0])
    archs = {e["architecture"] for e in pk}
    if archs != {"x86_64", "aarch64"}:
        die("the lock must cover exactly the architectures x86_64 and aarch64; it covers %s" % (", ".join(sorted(archs)) or "none"), ARCH_ERR)
    per = {}
    for e in pk:
        per.setdefault(e["name"], {}).setdefault(e["architecture"], set()).add(e["version"])
    bad = []
    for n, by_arch in sorted(per.items()):
        vers = {a: v for a, v in by_arch.items()}
        if set(vers) != archs:
            bad.append("%s is locked for %s only" % (n, ", ".join(sorted(vers))))
        elif any(len(v) != 1 for v in vers.values()) or len({next(iter(v)) for v in vers.values()}) != 1:
            bad.append("%s resolves to different or several versions (%s)" % (n, "; ".join("%s: %s" % (a, ",".join(sorted(v))) for a, v in sorted(vers.items()))))
    if bad:
        die("these packages do not resolve identically on both architectures: " + "; ".join(bad), 1)


def verify_apk(path, e):
    """Every byte of the apk must be covered by the lock: contiguous signature (optional, Wolfi's apks have none), control and data
    ranges that end exactly at the end of the file, each with its checksum, and the data stream hashes to the datahash in the control."""
    raw = open(path, "rb").read()
    fname = os.path.basename(path)
    spans = []
    for part in ("signature", "control", "data"):
        p = e.get(part) or {}
        if not p.get("range"):
            if part == "signature":
                continue
            die("%s: the lock has no %s range; an entry with nothing to check is not accepted" % (fname, part))
        m = re.fullmatch(r"bytes=([0-9]+)-([0-9]+)", p["range"])
        kind, _, want = p.get("checksum", "").partition("-")
        if not m or kind not in KINDS:
            die("%s: cannot read the %s range or checksum in the lock" % (fname, part))
        lo, hi = int(m.group(1)), int(m.group(2))
        got = b64(KINDS[kind](raw[lo:hi + 1]).digest())
        if got != want:
            die("%s: %s section does not match the lock (%s-%s, lock says %s-%s)" % (fname, part, kind, got, kind, want))
        spans.append((part, lo, hi))
    pos = 0
    for part, lo, hi in spans:
        if lo != pos:
            die("%s: the %s range starts at byte %d but the previous section ends at %d; the lock's ranges must be contiguous" % (fname, part, lo, pos))
        pos = hi + 1
    if pos != len(raw):
        die("%s: the lock's ranges end at byte %d but the file has %d bytes; bytes after the last range (or a short file) are not accepted: size/length mismatch, the end of the file is not covered" % (fname, pos, len(raw)))
    ctl = [(n, lo, hi) for n, lo, hi in spans if n == "control"][0]; dat = [(n, lo, hi) for n, lo, hi in spans if n == "data"][0]
    try:
        import io, tarfile, zlib
        pk = tarfile.open(fileobj=io.BytesIO(zlib.decompressobj(31).decompress(raw[ctl[1]:ctl[2] + 1], 16 * 1024 * 1024))).extractfile(".PKGINFO").read().decode()
        dhs = re.findall(r"^datahash = ([0-9a-f]{64})$", pk, re.M)
        ok(len(dhs) == 1)
        dh = dhs[0]
    except Exception:
        die("%s: the control section has no readable .PKGINFO datahash (exactly one datahash line is required)" % fname)
    if hashlib.sha256(raw[dat[1]:dat[2] + 1]).hexdigest() != dh:
        die("%s: the data stream does not hash to the datahash in its control section" % fname)


def verify_archive(argv):
    o = opts(argv, ("--lock", "--archive", "--melange-repo", "--index-record"))
    if "--lock" not in o or "--archive" not in o:
        die("usage: verify-archive --lock L --archive DIR [--melange-repo DIR] [--index-record REC]", 2)
    _, pk = load(o["--lock"])
    if not pk:
        die("the lock file %s lists no package; an empty lock proves nothing about the archive" % o["--lock"], 2)
    repos = [o["--archive"]] + ([o["--melange-repo"]] if "--melange-repo" in o else [])
    for r in repos:
        if not os.path.isdir(r):
            die("%s is not a directory (the archive and the melange repository must exist)" % r, 2)
    used = set()
    for e in sorted(pk, key=lambda e: (e["architecture"], e["name"], e["version"])):
        rel = "%s/%s-%s.apk" % (e["architecture"], e["name"], e["version"])
        for r in repos:
            if os.path.isfile(os.path.join(r, rel)):
                verify_apk(os.path.join(r, rel), e)
                used.add((r, e["architecture"]))
                break
        else:
            die("%s is not in the archive%s (needed by the lock)" % (rel, " or the melange repository" if len(repos) > 1 else ""))
    recorded = check_index(o["--index-record"], o["--archive"]) if "--index-record" in o else {}   # the archive's index is the RECORDED one (a moved pointer is not consulted)
    for r, a in sorted(used):
        ix = recorded[a] if (r == o["--archive"] and a in recorded) else os.path.join(r, a, "APKINDEX.tar.gz")
        if not os.path.isfile(ix):
            die("%s/%s/APKINDEX.tar.gz is missing; assembly needs the package index" % (r, a))
        if os.path.getsize(ix) == 0:
            die("%s/%s/APKINDEX.tar.gz is empty; assembly needs the package index" % (r, a))


def evidence(argv):
    o = opts(argv, ("--lock", "--archive", "--out"))
    if not all(k in o for k in ("--lock", "--archive", "--out")):
        die("usage: evidence --lock L --archive DIR --out DIR", 2)
    _, pk = load(o["--lock"])
    if not os.path.isdir(o["--archive"]):
        die("the archive %s is not a directory" % o["--archive"])
    for e in pk:   # evidence of a release must describe an archive that holds everything the lock needs
        rel = "%s/%s-%s.apk" % (e["architecture"], e["name"], e["version"])
        if not os.path.isfile(os.path.join(o["--archive"], rel)):
            die("%s is in the lock but not in the archive" % rel)
    os.makedirs(o["--out"], exist_ok=True)
    shutil.copyfile(o["--lock"], os.path.join(o["--out"], os.path.basename(o["--lock"])))
    rows = []
    for root, _, files in os.walk(o["--archive"]):
        for f in files:
            p = os.path.join(root, f)
            rows.append((os.path.relpath(p, o["--archive"]).replace(os.sep, "/"), hashlib.sha256(open(p, "rb").read()).hexdigest()))
    if not rows:
        die("the archive %s is empty" % o["--archive"])
    with open(os.path.join(o["--out"], "archive-checksums.txt"), "w") as f:
        for p, h in sorted(rows, key=lambda r: r[0].encode()):
            f.write("%s  %s\n" % (h, p))


def _lock_dispatch(argv):
    cmds = {"compare": compare, "arch-check": arch_check, "verify-archive": verify_archive, "evidence": evidence}
    if len(argv) < 1 or argv[0] not in cmds:
        die("usage: " + LOCKER + " compare|arch-check|verify-archive|evidence ...", 2)
    cmds[argv[0]](argv[1:])


def lock_main(argv):
    """compare|arch-check|verify-archive|evidence ... (the lock-file checks of the image build)"""
    try:
        _lock_dispatch(argv)
    except (KeyError, TypeError, AttributeError) as exc:
        die("malformed lock entry (missing or mistyped key %s)" % exc, 2)


def check_config(path):
    """the apko config is read as a CLOSED line grammar, so no YAML decoding can differ from the text this check reads: blank lines, comments, 'key:',
    'key: plain-scalar', '- plain-scalar' and '- key: plain-scalar', where a plain scalar is [A-Za-z0-9_./@=+-]+ (no quote, backslash, bracket, brace,
    block-scalar indicator, anchor or tag). Anything else is refused (fail closed). Within that grammar: no '://' anywhere, no key that names a
    repository other than 'repositories', and exactly one such list holding exactly /work/archive and /work/melange-repo. Exit 2 on any refusal."""
    try:
        text = open(path, newline="").read()
    except OSError as e:
        print(ASSEMBLER + ": cannot read the config %s: %s" % (path, e), file=sys.stderr); sys.exit(2)
    def refuse(msg):
        print(ASSEMBLER + ": the config %s %s; packages come only from the archive and the local melange repository" % (path, msg), file=sys.stderr); sys.exit(2)
    if re.search(r"[^\x20-\x7e\n]", text):   # pure printable ASCII and LF: YAML also breaks lines at U+0085, U+2028 and U+2029, tabs and CR are not plain
        refuse("holds a character outside printable ASCII and newline (a tab, a carriage return or a Unicode line break is not part of the plain grammar)")
    PLAIN = r"[A-Za-z0-9_./@=+-]+"
    KEY = r"[A-Za-z0-9_-]+"
    forms = (r"\s*", r"\s*#.*", r"\s*%s:\s*" % KEY, r"\s*%s:\s+%s\s*" % (KEY, PLAIN), r"\s*- %s\s*" % PLAIN, r"\s*- %s:\s+%s\s*" % (KEY, PLAIN))
    repos, in_block, indent, blocks = [], False, None, 0
    for n, ln in enumerate(text.split("\n"), 1):
        if "://" in ln and not re.match(r"\s*#", ln):
            refuse("line %d names a live repository or address" % n)
        if not any(re.fullmatch(f, ln) for f in forms):
            refuse("line %d is outside the closed plain grammar (no quoting, escapes, brackets, block scalars or other YAML constructs): %r" % (n, ln.strip()[:60]))
        if re.match(r"\s*#", ln) or not ln.strip():
            continue
        if "://" in ln:
            refuse("line %d names a live repository or address" % n)
        km = re.match(r"\s*(?:- )?(%s):" % KEY, ln)
        if km and "repositor" in km.group(1).lower() and km.group(1) != "repositories":
            refuse("line %d has a repository-like key other than 'repositories'" % n)
        m = re.match(r"^(\s*)repositories:\s*$", ln)
        if m:
            blocks += 1; in_block, indent = True, len(m.group(1)); continue
        if in_block:
            if len(ln) - len(ln.lstrip()) <= indent and not ln.lstrip().startswith("- "):
                in_block = False
            else:
                repos.append(ln.strip())
    if blocks != 1 or repos != ["- /work/archive", "- /work/melange-repo"]:
        refuse("does not list exactly one repositories block of /work/archive and /work/melange-repo")


# ---- the decisions of the image assembler -----------------------------------------------------------------------------------------------------

VARIANTS = {"production": {"pkg": "fscache", "config": "build/apko.yaml", "baselock": "build/locks/apko.base.lock.json"},
            "fips": {"pkg": "fscache-fips", "config": "build/apko-fips.yaml", "baselock": "build/locks/apko-fips.base.lock.json"}}
ROOT_NAMES = ("--archive", "--melange-repo", "--keyring-dir", "--out", "--render-dir")
ARCH_NAMES = ("x86_64", "aarch64")
KEY_FILES = ("wolfi-signing.rsa.pub", "assembly.rsa.pub")
LINK_NAMES = ("archive", "melange-repo", "keyring")


class Refused(Exception):
    def __init__(self, message, code=2):
        super().__init__(message)
        self.code = code


def variant_field(variant, field):
    return VARIANTS[variant][field]


def check_roots(*values):
    """The five path arguments, one after the other: plain printable ASCII, not empty (the render directory may be), no hidden dots, no symlink."""
    for name, value in zip(ROOT_NAMES, values):
        if re.search(r"[^\x20-\x7e]", value):
            raise Refused("%s holds a control character or a byte outside printable ASCII (a newline, a C1 control or any byte >= 0x80); "
                          "refusing, the path arguments are plain ASCII text" % name)
        if name == "--render-dir" and not value:
            continue   # no render directory given: a private temporary one is used
        if not value:
            raise Refused("%s is empty; refusing (an empty value would silently mean the current directory)" % name)
        path = value
        while path.endswith("/") and path != "/":   # a trailing slash would hide the symlink from the link test
            path = path[:-1]
        if has_hidden_dots(path):
            raise Refused("%s %s has a . or .. component after another component (it could hide a symlinked root); give the real path"
                          % (name, path))
        if os.path.islink(path):
            raise Refused("%s %s is a symlink; refusing (a root of the inputs or the result must be a real directory)" % (name, value))


def abs_dir(path):
    return os.path.realpath(path) if os.path.isdir(path) else path


def abs_file(path):
    folder = os.path.dirname(path) or "."
    return os.path.join(os.path.realpath(folder), os.path.basename(path)) if os.path.isdir(folder) else path


def apk_version(version):
    return version.replace("-rc.", "_rc", 1).replace("-rc", "_rc", 1)


def check_inputs(archive, melrepo, keydir, out, config, baselock):
    for path in (archive, melrepo, keydir):
        if "://" in path:
            raise Refused("the archive, the melange repository and the keyring dir must be local directories, not addresses (%s)" % path)
    if not os.path.isdir(archive):
        raise Refused("--archive is not a directory: " + archive)
    if not os.path.isdir(melrepo):
        raise Refused("--melange-repo is not a directory: " + melrepo)
    if not os.path.isfile(config):
        raise Refused("apko config not found: " + config)
    if not os.path.isfile(baselock):
        raise Refused("base lock not found: " + baselock)


def check_keydir(keydir):
    for key_file in KEY_FILES:
        if not os.path.isfile(os.path.join(keydir, key_file)):
            raise Refused("the keyring dir %s has no %s: every package is checked against its key (rule 19)" % (keydir, key_file))


def check_melrepo(melrepo, pkg, apkver):
    for arch in ARCH_NAMES:
        if not os.path.isfile("%s/%s/%s-%s-r0.apk" % (melrepo, arch, pkg, apkver)):
            raise Refused("the melange repository %s has no %s/%s-%s-r0.apk (our apk)" % (melrepo, arch, pkg, apkver))
        if not os.path.isfile("%s/%s/APKINDEX.tar.gz" % (melrepo, arch)):
            raise Refused("the melange repository %s has no %s/APKINDEX.tar.gz" % (melrepo, arch))


def check_workdir(workdir):
    for name in LINK_NAMES:
        path = "%s/%s" % (workdir, name)
        if os.path.lexists(path):
            what = "a symlink, left by another run or a crashed one" if os.path.islink(path) else "not a symlink"
            raise Refused("%s already exists (%s)); refusing to replace it: remove it by hand if no other assembly is running" % (path, what))


def prepare_render(render, tmp):
    """The directory the config is rendered in: the given one (made if it is not there) or a private one under TMP."""
    if not render:
        render = tmp + "/render"
        os.makedirs(render, exist_ok=True)
        return render
    if os.path.islink(render):
        raise Refused("--render-dir %s is a symlink; refusing (render files would be written through it)" % render)
    if not os.path.isdir(render):
        os.makedirs(render, exist_ok=True)
        return os.path.abspath(render)   # the sealed calls change directory: the path must not depend on where we are
    try:
        empty = not os.listdir(render)
    except OSError:
        empty = False   # a directory that cannot be listed is not empty
    if not empty:
        raise Refused("--render-dir %s is not empty or cannot be listed; refusing (a planted file would be used or written through)" % render)
    return render


def check_out(out, variant):
    """--out may hold the OTHER variant's result; this variant's own names must not exist."""
    if os.path.exists(out) and not os.path.isdir(out):
        raise Refused("--out %s is not a directory" % out)
    if not os.path.isdir(out):
        return
    for name in (variant, variant + ".digest", variant + ".manifests", variant + ".full.lock.json", variant + "-sbom"):
        if os.path.lexists(out + "/" + name):
            raise Refused("--out %s already holds %s; refusing to mix a new result with stale files (it is not empty)" % (out, name))
    try:
        os.listdir(out)
    except OSError:
        raise Refused("--out %s cannot be listed; refusing" % out)


def apko_verdict(kind, rc, probe):
    """rc: the exit status of the sealed apko call; probe: the exit status of the network probe, empty when it did not run."""
    if rc == "0":
        return
    if rc == "127":
        raise Refused("apko is not installed (the chain installs it before this step)", 1)
    if probe == "":
        raise Refused("apko %s failed (exit %s)" % (kind, rc), 1)
    if probe == "101":
        raise Refused("a network attempt was made inside the sealed apko call (the probe confirms the namespace has no route); "
                      "the build must use only declared inputs", 4)
    raise Refused("apko failed with a network error, but the probe says the namespace is not sealed (exit %s); fix the seal first" % probe, 1)


def pick_sbom(folder):
    """apko's one SBOM, or the multi-architecture index SBOM when it wrote one per architecture too; anything else is refused."""
    names = sorted(n for n in os.listdir(folder) if not n.startswith("."))
    index = folder + "/sbom-index.spdx.json"
    if len(names) == 1:
        chosen = folder + "/" + names[0]
    elif os.path.isfile(index):
        chosen = index
    else:
        chosen = ""
    if not chosen or not os.path.isfile(chosen):
        raise Refused("apko wrote %d SBOM files and none is the image index SBOM (sbom-index.spdx.json); "
                      "cannot choose the one image SBOM" % len(names), 1)
    return chosen


# name -> (function, fewest words, most words); the answer a function returns is printed
DECISIONS = {
    "variant-field": (variant_field, 2, 2),
    "check-roots": (check_roots, 5, 5),
    "abs-dir": (abs_dir, 1, 1),
    "abs-file": (abs_file, 1, 1),
    "apk-version": (apk_version, 1, 1),
    "check-inputs": (check_inputs, 6, 6),
    "check-keydir": (check_keydir, 1, 1),
    "check-melrepo": (check_melrepo, 3, 3),
    "check-workdir": (check_workdir, 1, 1),
    "prepare-render": (prepare_render, 2, 2),
    "check-out": (check_out, 2, 2),
    "apko-verdict": (apko_verdict, 3, 3),
    "pick-sbom": (pick_sbom, 1, 1),
}


def decide(name, words):
    function, fewest, most = DECISIONS[name]
    if len(words) < fewest or len(words) > most:
        print("usage: oci-digest.py %s: wrong number of words" % name, file=sys.stderr)
        sys.exit(2)
    try:
        answer = function(*words)
    except Refused as e:
        print(ASSEMBLER + ": " + str(e), file=sys.stderr)
        sys.exit(e.code)
    if answer is not None:
        print(answer)


def main():
    a = sys.argv[1:]
    if a and a[0] in DECISIONS:
        decide(a[0], a[1:])
    elif len(a) == 5 and a[0] == "unpack":
        for side in (a[3], a[4]):   # the two result files: never through a link, never inside the layout directory, never the same file
            if os.path.islink(side) or (os.path.lexists(side) and not os.path.isfile(side)):
                fail("%s is a link or not a regular file; refusing to write through it" % side)
        if os.path.realpath(a[3]) == os.path.realpath(a[4]) or (os.path.exists(a[3]) and os.path.exists(a[4]) and os.path.samefile(a[3], a[4])):
            fail("the digest file and the manifests file are the same file (or hard links of one)")
        for side in (a[3], a[4]):
            if os.path.realpath(side).startswith(os.path.realpath(a[2]) + os.sep):
                fail("%s is inside the layout directory %s (it would be mixed into the image)" % (side, a[2]))
        lines, members, standard = read_digests(a[1])
        write_layout(members, standard, a[2])
        with open(a[3], "w") as fh:
            fh.write("".join(l.split(" ", 1)[1] + "\n" for l in lines if l.startswith("index ")))
        with open(a[4], "w") as fh:
            fh.write("".join(l + "\n" for l in lines if not l.startswith("index ")))
    elif len(a) == 4 and a[0] == "make-view":
        make_view(a[1], a[2], a[3])
    elif len(a) == 4 and a[0] == "render-config":
        render_config(a[1], a[2], a[3])
    elif len(a) == 2 and a[0] == "check-config":
        check_config(a[1])
    elif len(a) == 2 and a[0] == "check-dots":
        check_dots(a[1])
    elif len(a) >= 1 and a[0] == "lock":
        lock_main(a[1:])
    elif len(a) == 2 and a[0] == "check-version":
        check_version(a[1])
    elif len(a) == 3 and a[0] == "check-keys":
        check_keys(a[1], a[2])
    elif len(a) == 3 and a[0] == "check-index":
        for arch, path in sorted(check_index(a[1], a[2]).items()):
            print("%s\t%s" % (arch, path))
    elif len(a) == 2 and a[0] == "render-date":
        try:
            print(datetime.datetime.fromtimestamp(int(a[1]), datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
        except (ValueError, OverflowError, OSError):
            sys.exit(2)
    elif len(a) == 2 and a[0] == "is-empty":
        try:
            sys.exit(0 if not os.listdir(a[1]) else 1)
        except OSError:
            sys.exit(1)
    elif len(a) == 1:
        print("\n".join(read_digests(a[0])[0]))
    else:
        print("usage: oci-digest.py TAR | unpack TAR DIR DIGEST MANIFESTS | make-view REC ARCHIVE VIEW | render-config CONFIG OUT VERSION | check-dots NAME | check-version V | check-keys REC DIR | check-index REC ARCHIVE | render-date EPOCH | is-empty DIR | " + " | ".join(sorted(DECISIONS)) + " ...", file=sys.stderr)
        sys.exit(2)


main()
