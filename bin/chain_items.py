"""The Build and Rebuild subcommands of bin/chain-verify.py that deal with the files a stage produces (v0.3.0 rules 54, 58, 59;
REQ-CHAIN-004-AC3, AC8, AC9; REQ-CHAIN-005-AC1, AC3):

  bind             every file of a downloaded artifact directory is the product the verified Witness record holds for it
  items-apk        one native apk job's items fragment (the apk, its binary, the SBOM and the index digests)
  items-merge      both fragments plus the images and archives become items.json (Rebuild's comparison) and digests.json (Sign's input)
  rebuild-compare  Build's items.json against Rebuild's, item by item, bound to the hash Build's record holds for it
  record-env       a Witness record holds no token variable and no token value

None of them checks a signature: the `verify` or `stage-start` line that runs right before in the stage script does that. They are
tested against the REAL code by bin/chain-bind-test.sh and bin/chain-rebuild-test.sh, and the layout of the items is documented in
bin/chain-test-harness.py (PROPOSED/UNVERIFIED; cache's apk-tool.py and assemble-image.sh fix the apk digest and the image digest).
A refusal is `refused at <stage>: <cause>: <names>` on stderr and exit 1; a usage problem is `usage: ...` and exit 2.
"""
import hashlib
import json
import os
import re
import subprocess
import sys

from chain_common import b64d, refuse, strict_json

PRODUCT = "https://witness.dev/attestations/product/v0.1/file:"
HERE = os.path.dirname(os.path.abspath(__file__))
ITEM_LIST = os.path.join(HERE, "..", ".github", "policy", "rebuild-items.json")     # the committed list of the 29 items
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
ARCHES = {"x86_64": "amd64", "aarch64": "arm64"}            # the apk architecture name -> the image and archive name
IMAGES = {"production": "standard", "fips": "fips"}         # image -> apk variant
TOKEN_NAMES = ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_RUNTIME_TOKEN", "ACTIONS_RUNTIME_URL",
               "GH_TOKEN", "GITHUB_TOKEN")


# ---- the names a record may carry (REQ-CHAIN-004-AC13 and AC15; REQ-CHAIN-005-AC7) ----------------------------------------------------------
# A snapshot build (the proof workflows' mode) is signed by Witness like a release build, so the verifiers must tell them apart. Two rules, both made BEFORE any
# certificate, signature or timestamp is looked at, and both early protection against honest confusion and lookalikes: the security boundary is the Build Config URI
# pin of check_identity (the calling workflow must be release.yml at the tag).
SNAPSHOT_NAME = re.compile(r"snapshot-[a-z0-9_-]*")                    # exactly this is "a snapshot record"
RELEASE_NAMES = {"build": ("apk", "build"), "rebuild": ("rapk", "rebuild")}      # the collection names a stage reads; other stages' records are not collections
SNAPSHOT_VERSION_FILE = re.compile(r"fscache(-fips)?[-_]0\.0\.0[_-]")           # fscache-0.0.0_rc1-r0.apk, fscache_0.0.0-rc.1_linux_amd64.tar.gz; not 10.0.0 or 0.10.0


def check_collection_name(stage, name):
    """AC13, one rule: exactly snapshot-[a-z0-9_-]* is a snapshot record; any other name that is not a release name of this stage is refused by name."""
    if isinstance(name, str) and SNAPSHOT_NAME.fullmatch(name):
        refuse(stage, "snapshot record")
    allowed = RELEASE_NAMES.get(stage)
    if allowed and name not in allowed:
        refuse(stage, "collection name %r is not a release name of this stage (%s)" % (name, " or ".join(allowed)))


def check_snapshot_version(stage, names):
    """AC15: a record, or a digests.json, that names a file of the snapshot version 0.0.0 is refused, whatever it is called. Names only, never digest values."""
    if any(isinstance(n, str) and SNAPSHOT_VERSION_FILE.search(n) for n in names):
        refuse(stage, "snapshot version")


def check_record_names(stage, payload):
    """Called by chain-verify.py for every record a stage reads: applies both rules to a Witness collection (a provenance statement is left alone)."""
    try:
        statement = strict_json(payload)
    except ValueError:
        return
    if not isinstance(statement, dict) or statement.get("predicateType") != "https://witness.testifysec.com/attestation-collection/v0.1":
        return
    predicate = statement.get("predicate")
    check_collection_name(stage, predicate.get("name") if isinstance(predicate, dict) else None)
    subjects = statement.get("subject")
    check_snapshot_version(stage, [s.get("name") for s in subjects if isinstance(s, dict)] if isinstance(subjects, list) else [])


def check_digest_names(stage, path):
    """AC15 for a digests.json: its keys (never its values) must not name a 0.0.0 file. An unreadable file is left to the schema check that follows."""
    try:
        with open(path, "rb") as f:
            keys = list(strict_json(f.read()))
    except (OSError, ValueError, TypeError):
        return
    check_snapshot_version(stage, keys)


def usage(message):
    print("usage: " + message, file=sys.stderr)
    sys.exit(2)


def sha256_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def read_collection(path):
    """(collection name, product subjects) of a Witness record: a DSSE envelope whose payload is an in-toto Statement."""
    try:
        with open(path, "rb") as f:
            envelope = strict_json(f.read())
    except (OSError, ValueError):
        usage("%s is not a readable JSON file" % path)
    try:
        statement = strict_json(b64d(envelope["payload"]))
        return statement["predicate"]["name"], statement["subject"]
    except (KeyError, TypeError, ValueError):
        return None, None


def product_hashes(subjects):
    """{path: [sha256, ...]} of the product subjects (a material subject of the same name does not count)."""
    products = {}
    for subject in subjects:
        name = subject.get("name", "")
        if name.startswith(PRODUCT):
            products.setdefault(name[len(PRODUCT):], []).append((subject.get("digest") or {}).get("sha256"))
    return products


def check_relative(*paths):
    for p in paths:
        if os.path.isabs(p) or ".." in p.split("/"):
            usage("%s must be a relative path without .." % p)


def hidden_paths(root):
    found = []
    for here, dirs, files in os.walk(root):
        found += [os.path.join(here, n) for n in dirs + files if n.startswith(".")]
    return sorted(found)


# ---- bind -------------------------------------------------------------------------------------------------------------------------
BIND_STAGE = {"apk": "build", "rapk": "rebuild", "snapshot-apk": "build", "snapshot-rapk": "rebuild"}     # --step -> the stage whose record it is


def cmd_bind(a):
    if a.step not in BIND_STAGE:
        usage("--step must be one of %s" % ", ".join(BIND_STAGE))
    check_relative(a.dir, a.prefix)
    stage = BIND_STAGE[a.step]
    name, subjects = read_collection(a.record)
    if name is None:
        refuse(stage, "record: not a DSSE envelope of a Witness collection")
    if name != a.step:
        refuse(stage, "step: " + name)    # the record is for another step: name it
    files, links = {}, []
    for here, dirs, names in os.walk(a.dir):
        for n in dirs + names:
            path = os.path.join(here, n)
            if os.path.islink(path):
                links.append(a.prefix + "/" + os.path.relpath(path, a.dir))
        for n in names:
            path = os.path.join(here, n)
            if not os.path.islink(path):
                files[a.prefix + "/" + os.path.relpath(path, a.dir)] = sha256_file(path)
    if links:
        refuse(stage, "symlink: " + " ".join(sorted(links)))
    hidden = hidden_paths(a.dir)
    if hidden:
        refuse(stage, "hidden: " + " ".join(a.prefix + "/" + os.path.relpath(p, a.dir) for p in hidden))
    if not files:
        refuse(stage, "empty: " + a.dir)
    products = {p: h for p, h in product_hashes(subjects).items() if p.startswith(a.prefix + "/")}
    wrong = {n for n, h in files.items() if products.get(n) != [h]} | {n for n in products if n not in files}
    if wrong:
        refuse(stage, "digest: " + " ".join(sorted(wrong)))
    print("ok")


# ---- items-apk --------------------------------------------------------------------------------------------------------------------
def apk_tool(*args):
    result = subprocess.run(["python3", "bin/apk-tool.py"] + list(args), capture_output=True)
    if result.returncode:
        refuse("build", "apk-tool: %s failed" % args[0])
    return result.stdout


def one_apk(out_dir, variant):
    pattern = r"fscache-[0-9][^/]*-r0\.apk" if variant == "standard" else r"fscache-fips-[^/]*-r0\.apk"
    found = [n for n in sorted(os.listdir(out_dir)) if re.fullmatch(pattern, n)]
    if len(found) != 1:
        refuse("build", "apk: expected exactly one %s apk in %s, found %d" % (variant, out_dir, len(found)))
    return os.path.join(out_dir, found[0])


def read_input(path):
    if not os.path.isfile(path):
        refuse("build", "missing: " + path)
    return "sha256:" + sha256_file(path)


def cmd_items_apk(a):
    out_dir = a.out_dir.rstrip("/")
    arch, parent = os.path.basename(out_dir), os.path.dirname(out_dir) or "."
    hidden = hidden_paths(parent)
    if hidden:
        refuse("build", "hidden: " + " ".join(hidden))
    items = {}
    for variant, suffix in (("standard", ""), ("fips", "-fips")):
        apk = one_apk(out_dir, variant)
        items["apk-%s-%s" % (variant, arch)] = apk_tool("digest", apk).decode().strip()
        items["binary-%s-%s" % (variant, arch)] = "sha256:" + hashlib.sha256(apk_tool("cat", apk, "usr/bin/fscache")).hexdigest()
        items["modules-sbom-" + variant] = read_input("%s/fscache-modules%s.spdx.json" % (parent, suffix))
        items["inputs-manifest-" + variant] = read_input("%s/inputs-manifest%s.json" % (parent, suffix))
    items["apkindex-" + arch] = read_input(out_dir + "/APKINDEX.tar.gz")
    with open(a.result, "w") as f:
        json.dump({"arch": arch, "items": items}, f, sort_keys=True, indent=1)
        f.write("\n")


# ---- items-merge ------------------------------------------------------------------------------------------------------------------
def committed_items():
    with open(ITEM_LIST) as f:
        return strict_json(f.read())


def merge_fragments(paths):
    arches, items = [], {}
    for path in paths:
        with open(path) as f:
            fragment = strict_json(f.read())
        arches.append(fragment["arch"])
        for name, value in fragment["items"].items():
            if name in items and items[name] != value:
                refuse("build", "digest: " + name)
            items[name] = value
    if sorted(arches) != sorted(ARCHES):
        missing = sorted(set(ARCHES) - set(arches))
        refuse("build", "arch: " + " ".join(missing or sorted(a for a in set(arches) if arches.count(a) > 1)))
    return items


def read_bytes(directory, name, what=None):
    path = os.path.join(directory, name)
    if not os.path.isfile(path):
        refuse("build", "missing: " + (what or name))
    with open(path, "rb") as f:
        return f.read()


def image_items(images_dir):
    items = {}
    for image in IMAGES:
        items["image-" + image] = read_bytes(images_dir, image + ".digest").decode().strip()
        for line in read_bytes(images_dir, image + ".manifests").decode().split("\n"):
            if line.strip():
                arch, digest = line.split()
                items["image-%s-manifest-%s" % (image, arch)] = digest
        items["lock-" + image] = "sha256:" + hashlib.sha256(read_bytes(images_dir, image + ".full.lock.json")).hexdigest()
        items["sbom-" + image] = "sha256:" + hashlib.sha256(read_bytes(images_dir, image + "-sbom/sbom.json")).hexdigest()
    return items


def archive_items(archives_dir, version):
    """The four Linux archives under goreleaser's names (PROPOSED): fscache_VER_linux_ARCH.tar.gz, fscache-fips_VER_linux_ARCH.tar.gz."""
    items = {}
    for arch in ARCHES.values():
        for item, file in (("archive-linux-" + arch, "fscache_%s_linux_%s.tar.gz" % (version, arch)),
                           ("archive-fips-linux-" + arch, "fscache-fips_%s_linux_%s.tar.gz" % (version, arch))):
            items[item] = "sha256:" + hashlib.sha256(read_bytes(archives_dir, file, item)).hexdigest()
    return items


def archive_checksums(archive_dir):
    """sha256 of the sorted `<sha256>  <path>` lines of every file of the pinned upstream archive directory."""
    lines = []
    for here, _, names in os.walk(archive_dir):
        for n in names:
            path = os.path.join(here, n)
            lines.append("%s  %s" % (sha256_file(path), os.path.relpath(path, archive_dir)))
    return "sha256:" + hashlib.sha256("\n".join(sorted(lines)).encode()).hexdigest()


def digests_of(items):
    """digests.json (PR 1's schema): the two images, the four apks named by amd64/arm64, the four archives; each equal to its item."""
    digests = {k: v for k, v in items.items() if k in ("image-production", "image-fips") or k.startswith(("archive-linux", "archive-fips-linux"))}
    for variant in ("standard", "fips"):
        for arch, short in ARCHES.items():
            digests["apk-%s-%s" % (variant, short)] = items["apk-%s-%s" % (variant, arch)]
    return digests


def cmd_items_merge(a):
    items = merge_fragments(a.fragment)
    committed = set(committed_items())
    unexpected = sorted(set(items) - committed)
    if unexpected:
        refuse("build", "unexpected: " + " ".join(unexpected))
    items.update(image_items(a.images))
    items.update(archive_items(a.archives, a.version))
    items["archive-checksums"] = archive_checksums(a.archive)
    if set(items) != committed:
        refuse("build", "missing: " + " ".join(sorted(committed - set(items))))
    with open(a.items, "w") as f:
        json.dump(items, f, sort_keys=True, indent=1)
        f.write("\n")
    if a.digests:
        with open(a.digests, "w") as f:
            json.dump(digests_of(items), f, sort_keys=True, indent=1)
            f.write("\n")


# ---- rebuild-compare --------------------------------------------------------------------------------------------------------------
def load_items(path, what):
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError:
        usage("%s is not a readable file" % path)
    try:
        return raw, strict_json(raw)
    except ValueError:
        return raw, "format"        # not JSON, or a repeated key: a format refusal, decided after the verdict is written


def status_of(name, expected, actual):
    if name not in expected:
        return "missing-expected"
    if name not in actual:
        return "missing-actual"
    return "same" if expected[name] == actual[name] else "differs"


def compare_problem(subjects, raw_expected, expected, actual, rows, both_ok):
    """The first thing wrong with the comparison as `<cause>: <names>`, or None when every listed item is present and identical."""
    hashes = product_hashes(subjects or []).get("items.json", [])
    if subjects is None or hashes != [hashlib.sha256(raw_expected).hexdigest()]:
        return "digest: items.json is not the file Build's record holds"
    if not both_ok:
        return "format: the items are not a JSON object with no repeated key"
    bad = sorted({n for side in (expected, actual) for n, v in side.items() if not (isinstance(v, str) and DIGEST.fullmatch(v))})
    if bad:
        return "format: " + " ".join(bad)
    for kind in ("unexpected", "missing-expected", "missing-actual", "differs"):
        named = [r["name"] for r in rows if r["status"] == kind]
        if named:
            return "%s: %s" % ("missing" if kind.startswith("missing") else kind, " ".join(named))
    return None


def snapshot_verdict(rows, identical):
    """witness-rebuild/snapshot-verdict.json (agreed with cache-3f, approved by the advisor): the two image index digests of both builds, and every item that is
    not the same. The verdict is differs if ANY item differs (an SBOM alone is enough), a missing image digest is null."""
    by_name = {r["name"]: r for r in rows}
    images = []
    for image in ("production", "fips"):
        row = by_name.get("image-" + image, {})
        images.append({"image": image, "build_digest": row.get("expected"), "rebuild_digest": row.get("actual"), "equal": row.get("status") == "same"})
    return {"verdict": "identical" if identical else "differs", "images": images,
            "items_differing": sorted(r["name"] for r in rows if r["status"] != "same")}


def check_compare_record_name(name, snapshot):
    """Build's record for rebuild-compare is named build; with --snapshot it is named snapshot-build and nothing else (REQ-CHAIN-005-AC7)."""
    if snapshot:
        if name != "snapshot-build":
            refuse("rebuild", "step: %s" % (name,))
        return
    if isinstance(name, str) and SNAPSHOT_NAME.fullmatch(name):
        refuse("rebuild", "snapshot record")
    if name != "build":
        refuse("rebuild", "collection name %r is not build (Build's record)" % (name,))


def cmd_rebuild_compare(a):
    name, subjects = read_collection(a.build_record)
    check_compare_record_name(name, a.snapshot)
    raw_expected, expected = load_items(a.expected, "--expected")
    _, actual = load_items(a.actual, "--actual")
    listed = committed_items()
    both_ok = isinstance(expected, dict) and isinstance(actual, dict)
    rows = []
    if both_ok:
        for item in sorted(set(listed) | set(expected) | set(actual)):
            row = {"name": item, "expected": expected.get(item), "actual": actual.get(item), "status": status_of(item, expected, actual)}
            if item not in listed:
                row["status"] = "unexpected"
            rows.append(row)
    problem = compare_problem(subjects, raw_expected, expected, actual, rows, both_ok)
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    verdict = snapshot_verdict(rows, problem is None) if a.snapshot else {"equal": problem is None, "items": rows}
    with open(a.out, "w") as f:
        json.dump(verdict, f, sort_keys=True, indent=1)
        f.write("\n")
    if problem:
        refuse("rebuild", problem)
    print("ok")


# ---- record-env -------------------------------------------------------------------------------------------------------------------
def cmd_record_env(a):
    try:
        with open(a.record, "rb") as f:
            envelope = strict_json(f.read())
    except (OSError, ValueError):
        usage("%s is not a readable JSON file" % a.record)
    if not isinstance(envelope, dict) or "payload" not in envelope:
        refuse("build", "env: the record is not a DSSE envelope (Witness -o writes {payloadType, payload, signatures})")
    try:
        statement = strict_json(b64d(envelope["payload"]))
        predicate = statement.get("predicate") if isinstance(statement, dict) else None
        name = predicate.get("name") if isinstance(predicate, dict) else None
    except (ValueError, TypeError):
        name = None
    if isinstance(name, str) and SNAPSHOT_NAME.fullmatch(name):
        refuse("build", "snapshot record")          # nothing can token-check a snapshot record; nothing consumes one (REQ-CHAIN-004-AC13)
    try:
        text = json.dumps(envelope) + "\n" + b64d(envelope["payload"]).decode("utf-8", "replace")
    except ValueError:
        refuse("build", "env: the DSSE payload is not base64")
    found = [n for n in TOKEN_NAMES if n in text]
    if found:
        refuse("build", "env: the record names " + " ".join(found))
    if re.search(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*", text):
        refuse("build", "env: the record holds a compact JWT")
    if re.search(r"\bgh[pousr]_[A-Za-z0-9]{20,}", text):
        refuse("build", "env: the record holds a GitHub token")
    print("ok")


# ---- the command line -------------------------------------------------------------------------------------------------------------
def add_parsers(sub):
    b = sub.add_parser("bind")
    b.add_argument("--step", required=True)
    b.add_argument("--record", required=True)
    b.add_argument("--dir", required=True)
    b.add_argument("--as", dest="prefix", required=True)
    i = sub.add_parser("items-apk")
    i.add_argument("--out-dir", required=True)
    i.add_argument("--result", required=True)
    m = sub.add_parser("items-merge")
    m.add_argument("--fragment", action="append", required=True)
    for name in ("images", "archives", "version", "archive", "items"):
        m.add_argument("--" + name, required=True)
    m.add_argument("--digests")
    c = sub.add_parser("rebuild-compare")
    for name in ("build-record", "expected", "actual", "out"):
        c.add_argument("--" + name, required=True)
    c.add_argument("--snapshot", action="store_true")
    e = sub.add_parser("record-env")
    e.add_argument("--record", required=True)


COMMANDS = {"bind": cmd_bind, "items-apk": cmd_items_apk, "items-merge": cmd_items_merge, "rebuild-compare": cmd_rebuild_compare,
            "record-env": cmd_record_env}
