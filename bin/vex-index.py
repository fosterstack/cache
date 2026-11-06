#!/usr/bin/env python3
"""vex-index: derive and check the final image index that carries the release's VEX (REQ-REL-010-AC1: the attestation carries the VEX in the form Docker Scout applies, owner-ratified Oct 24 2026).

The final index F is the built index D plus one attestation-manifest child per platform; every child carries the
release's OpenVEX document, in the form Docker Scout applies (scout_form), as an in-toto statement whose subject is that platform's own digest. F is a pure function
of the bytes of D and of the VEX file: nothing signed or promoted ever names D.

  compute       --index D.json --vex VEX.json --out-dir DIR           (the pieces, into an empty directory)
  verify        --final F.json --vex VEX.json --blobs DIR/blobs --base D.json
  layout        --layout DIR --vex VEX.json                           (in place: DIR is an OCI image layout whose index.json names D;
                                                                       afterwards it names F, every new blob is in blobs/sha256)
  verify-layout --layout DIR --vex VEX.json --base-digest sha256:.. (F is in the layout, canonical, with its attestations)
  sidecar       --layout DIR --vex VEX.json --digest-file OUT/V.digest (the digest file Build records follows the layout: D's digest becomes F's)

verify always performs the full validation. There is no network code at all: nothing is pushed, nothing is read from a
registry. Standard library only; nothing in the environment (CI variables, locale, time zone, clock) influences any output.

Layout commands: the layout is Build's own directory, owned by the user that runs the tool and not writable by anyone else (refused
otherwise). The tool checks the whole layout before writing, writes only what it owns and removes it again on failure, and checks the
layout's exact state before and after the commit; a change by another process fails the run. A process of the same user that writes
into the layout while the tool runs is outside what the tool can exclude; the chain runs verify-layout as a separate read-only step.

Exit status: 0 success, 2 the input was refused (a plain reason on stderr), 1 an unexpected error.
"""
import argparse
import base64
import binascii
import datetime
import hashlib
import json
import math
import os
import re
import stat
import sys

ATTESTATION = "attestation-manifest"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
INTOTO = "application/vnd.in-toto+json"
PREDICATE_TYPE = "https://openvex.dev/ns/v0.2.0"
STATEMENT_TYPE = "https://in-toto.io/Statement/v0.1"
SUBJECT_NAME = "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache"

MAX_INDEX_BYTES = 1 << 20      # the built index and the VEX file
MAX_FINAL_BYTES = 2 << 20      # the final index (the built index plus the attestation descriptors)
MAX_DEPTH = 32
MAX_PLATFORMS = 64
MAX_INT = 2 ** 53
MAX_STATEMENT_BYTES = 2 << 20  # an attestation statement (it embeds the VEX)
MAX_CONFIG_BYTES = 16 << 20  # an image config read while checking a layout
MAX_SMALL_BLOB_BYTES = 64 << 10  # an attestation manifest or config

# every digest, port and name below is ASCII only: [0-9] and explicit classes, never \d or \w
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
# RFC 3339 section 5.6: T and Z in either case, seconds up to 60 (leap second), at least one fractional digit
TIMESTAMP = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]+)?([Zz]|[+-]([01][0-9]|2[0-3]):[0-5][0-9])")


class Refuse(Exception):
    """the input, the DIR or the registry is not acceptable: a plain reason, exit status 2"""


# ---------------------------------------------------------------- canonical JSON and strict parsing
def canonical(obj):
    """the one serialisation of every document this tool writes: sorted keys, compact, raw UTF-8, no newline"""
    text = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError:
        raise Refuse("a string contains a lone surrogate")


def digest_of(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def hex_of(digest):
    return digest.split(":", 1)[1]


def depth_of(obj):
    deepest, stack = 0, [(obj, 1)]
    while stack:
        item, depth = stack.pop()
        if isinstance(item, (dict, list)):
            deepest = max(deepest, depth)
            for child in (item.values() if isinstance(item, dict) else item):
                stack.append((child, depth + 1))
    return deepest


def load_json(data, what, max_bytes=MAX_INDEX_BYTES, limits=False):
    """strict JSON: UTF-8 without a byte-order mark, no duplicate keys, no float or non-finite number, integers
    within +-2**53, no lone surrogate; with limits also a size and nesting bound"""
    if limits and len(data) > max_bytes:
        raise Refuse("%s: larger than %d bytes" % (what, max_bytes))

    def no_duplicates(pairs):
        found = {}
        for key, value in pairs:
            if key in found:
                raise Refuse("%s: duplicate key %r" % (what, key))
            found[key] = value
        return found

    def constant(_name):
        raise Refuse("%s: not a finite number" % what)

    def real(_text):
        raise Refuse("%s: only integers are accepted (a float is not canonical)" % what)

    def integer(text):
        value = int(text)
        if abs(value) > MAX_INT:
            raise Refuse("%s: an integer beyond 2**53" % what)
        return value
    try:
        obj = json.loads(data.decode("utf-8"), object_pairs_hook=no_duplicates, parse_constant=constant,
                         parse_float=real, parse_int=integer)
    except Refuse:
        raise
    except Exception as err:
        raise Refuse("%s: not valid JSON (%s)" % (what, type(err).__name__))
    canonical(obj)  # refuses a lone surrogate anywhere
    if limits and depth_of(obj) > MAX_DEPTH:
        raise Refuse("%s: nested deeper than %d" % (what, MAX_DEPTH))
    return obj


def is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def non_empty(value):
    return isinstance(value, str) and value != ""


# ---------------------------------------------------------------- OpenVEX v0.2.0, closed to the published schema
JUSTIFICATIONS = ("component_not_present", "vulnerable_code_not_present", "vulnerable_code_not_in_execute_path",
                  "vulnerable_code_cannot_be_controlled_by_adversary", "inline_mitigations_already_exist")
STATUSES = ("not_affected", "affected", "fixed", "under_investigation")
IDENTIFIER_KEYS = ("purl", "cpe22", "cpe23")
HASH_KEYS = ("md5", "sha1", "sha-256", "sha-384", "sha-512", "sha3-224", "sha3-256", "sha3-384", "sha3-512",
             "blake2s-256", "blake2b-256", "blake2b-512")
# property -> type, per object; any property not listed is refused (fail closed)
VEX_SCHEMA = {
    "document": {"@context": "context", "@id": "string", "author": "string", "role": "string", "timestamp": "time",
                 "last_updated": "time", "version": "version", "tooling": "string", "statements": "statements"},
    "statement": {"@id": "string", "version": "version", "vulnerability": "vulnerability", "timestamp": "time",
                  "last_updated": "time", "products": "products", "status": "status", "supplier": "string",
                  "status_notes": "string", "justification": "justification", "impact_statement": "string",
                  "action_statement": "string", "action_statement_timestamp": "time"},
    "vulnerability": {"@id": "string", "name": "string", "description": "string", "aliases": "aliases"},
    "product": {"@id": "string", "identifiers": "identifiers", "hashes": "hashes", "subcomponents": "subcomponents"},
    "subcomponent": {"@id": "string", "identifiers": "identifiers", "hashes": "hashes"},
}


def is_timestamp(value):
    match = TIMESTAMP.fullmatch(value) if isinstance(value, str) else None
    if not match:
        return False
    hour, minute, second = int(match.group(4)), int(match.group(5)), int(match.group(6))
    if hour > 23 or minute > 59 or second > 60:
        return False
    try:
        datetime.datetime(int(match.group(1)), int(match.group(2)), int(match.group(3)), hour, minute, min(second, 59))
    except ValueError:
        return False
    return True


def reject_unknown(obj, allowed, where):
    for key in obj:
        if key not in allowed:
            raise Refuse("vex: %s: property %r is not in the OpenVEX v0.2.0 schema" % (where, key))


def reject_duplicates(items, where):
    seen = set()
    for item in items:
        key = json.dumps(item, sort_keys=True)
        if key in seen:
            raise Refuse("vex: %s must not contain duplicates" % where)
        seen.add(key)


def check_typed(level, key, value):
    kind = VEX_SCHEMA[level][key]
    where = "%s.%s" % (level, key)
    if kind == "string":
        if not isinstance(value, str):
            raise Refuse("vex: %s must be a string" % where)
    elif kind == "time":
        if not is_timestamp(value):
            raise Refuse("vex: %s must be an RFC 3339 timestamp" % where)
    elif kind == "version":
        if not is_int(value) or value < 1:
            raise Refuse("vex: %s must be an integer >= 1" % where)
    elif kind == "identifiers":
        if not isinstance(value, dict) or not value:
            raise Refuse("vex: %s must be an object with at least one identifier" % where)
        reject_unknown(value, IDENTIFIER_KEYS, where)
        if not all(non_empty(item) for item in value.values()):
            raise Refuse("vex: %s must hold non-empty strings" % where)
    elif kind == "hashes":
        if not isinstance(value, dict):
            raise Refuse("vex: %s must be an object" % where)
        reject_unknown(value, HASH_KEYS, where)
        if not all(non_empty(item) for item in value.values()):
            raise Refuse("vex: %s must hold non-empty strings" % where)
    elif kind == "aliases":
        if not isinstance(value, list) or not all(non_empty(item) for item in value):
            raise Refuse("vex: %s must be a list of non-empty strings" % where)
        reject_duplicates(value, where)
    elif kind == "subcomponents":
        if not isinstance(value, list):
            raise Refuse("vex: %s must be a list" % where)
        reject_duplicates(value, where)
        for item in value:
            check_component(item, "subcomponent")


def check_component(component, level):
    if not isinstance(component, dict):
        raise Refuse("vex: a product or subcomponent is not an object")
    reject_unknown(component, VEX_SCHEMA[level], level)
    for key, value in component.items():
        check_typed(level, key, value)
    if "@id" in component:
        if not non_empty(component["@id"]):
            raise Refuse("vex: %s @id must not be empty" % level)
    elif "identifiers" not in component:
        raise Refuse("vex: a %s needs an @id or identifiers" % level)


def check_statement(statement):
    if not isinstance(statement, dict):
        raise Refuse("vex: a statement is not an object")
    reject_unknown(statement, VEX_SCHEMA["statement"], "statement")
    vulnerability = statement.get("vulnerability")
    if not isinstance(vulnerability, dict) or not non_empty(vulnerability.get("name")):
        raise Refuse("vex: a statement needs a vulnerability object with a name")
    reject_unknown(vulnerability, VEX_SCHEMA["vulnerability"], "vulnerability")
    for key, value in vulnerability.items():
        if key != "name":
            check_typed("vulnerability", key, value)
    for key, value in statement.items():
        if key not in ("vulnerability", "products", "status", "justification"):
            check_typed("statement", key, value)
    products = statement.get("products")
    if not isinstance(products, list) or not products:
        raise Refuse("vex: a statement needs a non-empty products list")
    reject_duplicates(products, "products")
    for product in products:
        check_component(product, "product")
    status = statement.get("status")
    if status not in STATUSES:
        raise Refuse("vex: status must be one of %s" % ", ".join(STATUSES))
    if "justification" in statement and statement["justification"] not in JUSTIFICATIONS:
        raise Refuse("vex: justification is not one the schema defines")
    if status == "not_affected" and not (non_empty(statement.get("justification")) or non_empty(statement.get("impact_statement"))):
        raise Refuse("vex: not_affected needs a justification or an impact_statement")
    if status == "affected" and not non_empty(statement.get("action_statement")):
        raise Refuse("vex: affected needs an action_statement")


def check_vex(data):
    """parse and validate a VEX file (the bytes) as an OpenVEX v0.2.0 document; returns the parsed document"""
    doc = load_json(data, "vex", limits=True)
    if not isinstance(doc, dict):
        raise Refuse("vex: not a JSON object")
    reject_unknown(doc, VEX_SCHEMA["document"], "document")
    for key in ("@context", "@id", "author", "timestamp", "version", "statements"):
        if key not in doc:
            raise Refuse("vex: missing %s" % key)
    if doc["@context"] != PREDICATE_TYPE:
        raise Refuse("vex: @context must be %s" % PREDICATE_TYPE)
    for key, value in doc.items():
        if key not in ("@context", "statements"):
            check_typed("document", key, value)
    statements = doc["statements"]
    if not isinstance(statements, list) or not statements:
        raise Refuse("vex: statements must be a non-empty list")
    reject_duplicates(statements, "statements")
    for statement in statements:
        check_statement(statement)
    return doc


# ---------------------------------------------------------------- the index
def is_string_map(value):
    return isinstance(value, dict) and all(isinstance(key, str) and isinstance(item, str) for key, item in value.items())


def is_string_list(value):
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def check_descriptor_fields(entry, where):
    """the OCI descriptor fields this tool knows are type-checked (unknown extension fields are kept untouched)"""
    if not isinstance(entry, dict):
        raise Refuse("%s is not an object" % where)
    if not isinstance(entry.get("digest"), str) or not DIGEST.fullmatch(entry["digest"]):
        raise Refuse("%s: the digest is not sha256:<64 lowercase hex>" % where)
    size = entry.get("size")
    if not is_int(size) or not 1 <= size <= 2 ** 31:
        raise Refuse("%s: the size is not an integer between 1 and 2**31" % where)
    if not non_empty(entry.get("mediaType")):
        raise Refuse("%s: the mediaType is not a non-empty string" % where)
    if "annotations" in entry and not is_string_map(entry["annotations"]):
        raise Refuse("%s: annotations must be an object of strings" % where)
    if "artifactType" in entry and not non_empty(entry["artifactType"]):
        raise Refuse("%s: artifactType must be a non-empty string" % where)
    if "urls" in entry and not (is_string_list(entry["urls"]) and all(entry["urls"])):
        raise Refuse("%s: urls must be a list of non-empty strings" % where)
    if "data" in entry:
        try:
            content = base64.b64decode(entry["data"], validate=True) if isinstance(entry["data"], str) else None
        except (binascii.Error, ValueError):
            content = None
        if content is None or len(content) != size or digest_of(content) != entry["digest"]:
            raise Refuse("%s: data must be base64 of exactly the content the descriptor names" % where)


def check_descriptor(entry, position):
    where = "manifests[%d]" % position
    check_descriptor_fields(entry, where)
    if entry["mediaType"] not in (OCI_MANIFEST, DOCKER_MANIFEST):
        raise Refuse("%s: the mediaType is not an image manifest" % where)


def is_attestation(entry):
    annotations = entry.get("annotations") or {}
    return annotations.get("vnd.docker.reference.type") == ATTESTATION or "vnd.docker.reference.digest" in annotations


def platform_key(entry, position):
    platform = entry.get("platform")
    if not isinstance(platform, dict):
        raise Refuse("manifests[%d]: no platform" % position)
    os_name, arch, variant = platform.get("os"), platform.get("architecture"), platform.get("variant")
    if not non_empty(os_name) or not non_empty(arch) or ("variant" in platform and not isinstance(variant, str)):
        raise Refuse("manifests[%d]: the platform is unreadable" % position)
    if "os.version" in platform and not isinstance(platform["os.version"], str):
        raise Refuse("manifests[%d]: platform os.version must be a string" % position)
    for key in ("os.features", "features"):
        if key in platform and not is_string_list(platform[key]):
            raise Refuse("manifests[%d]: platform %s must be a list of strings" % (position, key))
    return os_name, arch, variant


def load_index(data, final):
    """parse an OCI image index (the built index, or with final=True a final index); returns it and its platforms"""
    index = load_json(data, "index", MAX_FINAL_BYTES if final else MAX_INDEX_BYTES, limits=True)
    if not isinstance(index, dict) or not isinstance(index.get("manifests"), list) or not index["manifests"]:
        raise Refuse("index: needs a non-empty manifests list")
    if not is_int(index.get("schemaVersion")) or index["schemaVersion"] != 2:
        raise Refuse("index: schemaVersion must be 2")
    if index.get("mediaType") != OCI_INDEX:
        raise Refuse("index: mediaType must be %s" % OCI_INDEX)
    if "annotations" in index and not is_string_map(index["annotations"]):
        raise Refuse("index: annotations must be an object of strings")
    if "artifactType" in index and not non_empty(index["artifactType"]):
        raise Refuse("index: artifactType must be a non-empty string")
    if "subject" in index:
        check_descriptor_fields(index["subject"], "index subject")
    platforms, names, digests = [], set(), set()
    for position, entry in enumerate(index["manifests"]):
        check_descriptor(entry, position)
        if is_attestation(entry):
            if not final:
                raise Refuse("index: already carries an attestation child")
            continue
        os_name, arch, variant = platform_key(entry, position)
        if (os_name == "unknown") != (arch == "unknown"):
            raise Refuse("manifests[%d]: a half-unknown platform" % position)
        if os_name == "unknown":
            continue
        name = "%s/%s" % (os_name, arch) + ("/" + variant if variant else "")
        if name in names or entry["digest"] in digests:
            raise Refuse("index: duplicate platform %s" % name)
        names.add(name)
        digests.add(entry["digest"])
        platforms.append((name, entry))
    if not platforms:
        raise Refuse("index: no platform")
    if len(platforms) > MAX_PLATFORMS:
        raise Refuse("index: more than %d platforms" % MAX_PLATFORMS)
    return index, platforms


# ---------------------------------------------------------------- the attestation of one platform
def scout_form(vex):
    """the VEX file in the form Docker Scout applies, which is what every attestation carries as its predicate. Scout's own attestation command stores a statement whose
    products are the vulnerable PACKAGES (the image is the in-toto subject, so the image purl is not repeated): a product that names the attested image (SUBJECT_NAME, as @id
    or identifiers.purl) and lists subcomponents is replaced by them, in order, once each; every other product stays whole, so a claim about another image is never
    carried onto this one. Scout read our attestation when it held the VEX file as it is (a product = the image purl, the package as its subcomponent) and did not
    apply it (rescan run 39978435878, Oct 23 2026; the fixture is Scout's own output, held in the test file). The published VEX file itself is not changed;
    this is a pure function of its bytes, like everything else here."""
    out = json.loads(json.dumps(vex))
    for statement in out.get("statements", []):
        products, seen = [], set()
        for product in statement.get("products", []):
            subcomponents = product.get("subcomponents")
            names_image = SUBJECT_NAME in (product.get("@id"), (product.get("identifiers") or {}).get("purl"))
            for item in (subcomponents if names_image and isinstance(subcomponents, list) and subcomponents else [product]):
                key = canonical(item)
                if key not in seen:
                    seen.add(key)
                    products.append(item)
        statement["products"] = products
    return out


def build_attestation(platform_digest, vex):
    """(index descriptor, {digest: bytes}) of the attestation manifest, config and statement for one platform"""
    statement = canonical({
        "_type": STATEMENT_TYPE, "predicateType": PREDICATE_TYPE, "predicate": vex,
        "subject": [{"name": SUBJECT_NAME, "digest": {"sha256": hex_of(platform_digest)}}]})
    layer = {"mediaType": INTOTO, "digest": digest_of(statement), "size": len(statement),
             "annotations": {"in-toto.io/predicate-type": PREDICATE_TYPE}}
    config = canonical({"architecture": "unknown", "created": "1970-01-01T00:00:00Z", "os": "unknown",
                        "rootfs": {"diff_ids": [layer["digest"]], "type": "layers"}})
    config_descriptor = {"mediaType": OCI_CONFIG, "digest": digest_of(config), "size": len(config)}
    manifest = canonical({"schemaVersion": 2, "mediaType": OCI_MANIFEST, "config": config_descriptor, "layers": [layer]})
    descriptor = {
        "mediaType": OCI_MANIFEST, "digest": digest_of(manifest), "size": len(manifest),
        "annotations": {"vnd.docker.reference.digest": platform_digest, "vnd.docker.reference.type": ATTESTATION},
        "platform": {"architecture": "unknown", "os": "unknown"}}
    return descriptor, {digest_of(config): config, digest_of(statement): statement, digest_of(manifest): manifest}



# ---------------------------------------------------------------- files and directories
# Every directory is opened once (no symlink on its last component) and everything inside it is reached through that
# descriptor, so a path cannot be swapped for a symlink between being checked and being used. Files are opened without
# following symlinks and without blocking, must be regular files, and are read at most limit + 1 bytes.
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


def clean_path(path):
    """drop trailing separators (a dot segment never gets here: check_path refuses it first)"""
    return path.rstrip("/") or "/" if len(path) > 1 else path


def check_path(path):
    """a path argument has no symlink at any level and no '.' or '..' segment: what is named is what is reached"""
    if any(part in (".", "..") for part in path.split("/")):
        raise Refuse("%s has a '.' or '..' segment" % path)
    path = clean_path(path)
    if os.path.realpath(path) != os.path.abspath(path):
        raise Refuse("%s goes through a symlink (at some level of the path)" % path)
    return path


def require_trusted_ancestors(path):
    """every directory above path is owned by this user or by root and cannot be used by others to rename or replace what is below it
    (not writable by group or others, or sticky)"""
    here = os.path.dirname(os.path.abspath(path))
    while True:
        info = os.stat(here)
        if info.st_uid not in (os.geteuid(), 0) or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX):
            raise Refuse("%s, above the layout, could be used by another account to replace it (it must be owned by this user or root and not writable by group or others, or sticky)" % here)
        parent = os.path.dirname(here)
        if parent == here:
            return
        here = parent


def open_directory(path, dir_fd=None):
    try:
        return os.open(check_path(path) if dir_fd is None else path, DIR_FLAGS, dir_fd=dir_fd)
    except OSError as err:
        raise Refuse("%s is not a readable directory (a symlink is refused): %s" % (path, err.strerror))


def open_parent(path):
    """the directory that holds path (its own symlinks, if any, are followed) and the name of path inside it"""
    parent, name = os.path.split(check_path(path))
    try:
        return os.open(parent or ".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC), name
    except OSError as err:
        raise Refuse("cannot open the directory of %s: %s" % (path, err.strerror))


def read_regular(dir_fd, name, limit, what, private=False):
    """the bytes of a regular file inside an open directory, refusing anything else and anything above limit (with private: and a file
    that another account could change)"""
    if name in ("", ".", ".."):
        raise Refuse("%s is not a file name" % what)
    try:
        fd = os.open(name, FILE_FLAGS, dir_fd=dir_fd)
    except OSError as err:
        raise Refuse("cannot open %s: %s" % (what, err.strerror))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise Refuse("%s is not a regular file" % what)
        if private:
            require_private(fd, what)
        chunks, total = [], 0
        while True:
            try:
                chunk = os.read(fd, min(1 << 20, limit + 1 - total))
            except OSError as err:
                raise Refuse("cannot read %s: %s" % (what, err.strerror))
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise Refuse("%s is larger than %d bytes" % (what, limit))
    finally:
        os.close(fd)


def read_path(path, limit):
    parent_fd, name = open_parent(path)
    try:
        require_trusted_ancestors(path)      # an input file is read only when no other account could have written it or replaced it on the way
        return read_regular(parent_fd, name, limit, path, private=True)
    finally:
        os.close(parent_fd)


def list_directory(dir_fd, what):
    """{name: file type bits} of every entry (hidden ones too), or a refusal when the directory cannot be listed"""
    try:
        return {name: stat.S_IFMT(os.stat(name, dir_fd=dir_fd, follow_symlinks=False).st_mode) for name in os.listdir(dir_fd)}
    except OSError as err:
        raise Refuse("cannot list %s: %s" % (what, err.strerror))


def create_file(dir_fd, name, data):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644, dir_fd=dir_fd)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
    except BaseException:
        try:
            os.unlink(name, dir_fd=dir_fd)       # this call created the file (O_EXCL): a partial one is never left
        except OSError:
            pass
        raise


# ---------------------------------------------------------------- compute
def compute(index_bytes, vex_bytes):
    vex = check_vex(vex_bytes)
    index, platforms = load_index(index_bytes, final=False)
    if hex_of(digest_of(index_bytes)).encode() in canonical(vex):
        raise Refuse("the VEX mentions the built index's digest")
    descriptors, blobs, summary = [], {}, {}
    attested = scout_form(vex)
    try:
        check_vex(canonical(attested))   # verify runs this same check on the attested predicate: refuse here what verify would refuse
    except Refuse as e:
        raise Refuse("the VEX in the form Docker Scout applies is not a valid VEX (two statements that name the image in two forms are identical there): %s" % e)
    for name, entry in platforms:
        descriptor, parts = build_attestation(entry["digest"], attested)
        descriptors.append(descriptor)
        blobs.update(parts)
        summary[name] = {"platform_digest": entry["digest"], "attestation_digest": descriptor["digest"]}
    final = dict(index)
    final["manifests"] = list(index["manifests"]) + descriptors
    final_bytes = canonical(final)
    result = {"base_digest": digest_of(index_bytes), "final_digest": digest_of(final_bytes), "platforms": summary,
              "vex_sha256": hashlib.sha256(vex_bytes).hexdigest()}
    return final_bytes, blobs, result


def open_output(path):
    """the empty out-dir, opened without following a symlink; created when it does not exist"""
    path = check_path(path)
    parent_fd, name = open_parent(path)
    try:
        if name in ("", ".", ".."):
            return open_directory(path)
        try:
            fd = os.open(name, DIR_FLAGS, dir_fd=parent_fd)
        except FileNotFoundError:
            os.mkdir(name, 0o777, dir_fd=parent_fd)
            fd = os.open(name, DIR_FLAGS, dir_fd=parent_fd)
        except OSError as err:
            raise Refuse("the out-dir is not a directory (a symlink is refused): %s" % err.strerror)
        return fd
    finally:
        os.close(parent_fd)


def command_compute(args):
    final_bytes, blobs, result = compute(read_path(args.index, MAX_INDEX_BYTES), read_path(args.vex, MAX_INDEX_BYTES))
    out_fd = open_output(args.out_dir)
    try:
        if list_directory(out_fd, "the out-dir"):
            raise Refuse("the out-dir is not empty")
        os.mkdir("blobs", 0o777, dir_fd=out_fd)
        blobs_fd = open_directory("blobs", out_fd)
        try:
            os.mkdir("sha256", 0o777, dir_fd=blobs_fd)
            sha_fd = open_directory("sha256", blobs_fd)
            try:
                for digest, data in blobs.items():
                    create_file(sha_fd, hex_of(digest), data)
            finally:
                os.close(sha_fd)
        finally:
            os.close(blobs_fd)
        create_file(out_fd, "index.json", final_bytes)
        create_file(out_fd, "result.json", canonical(result) + b"\n")
    finally:
        os.close(out_fd)
    print(result["final_digest"])


# ---------------------------------------------------------------- the structure of a final index and its blobs
BLOB_CAPS = {"manifest": MAX_SMALL_BLOB_BYTES, "config": MAX_SMALL_BLOB_BYTES, "statement": MAX_STATEMENT_BYTES}


class Blobs:
    """a blobs directory (holding sha256/<hex>) opened once; every blob is read bounded and checked against its digest"""

    def __init__(self, path, dir_fd=None):
        self.root_fd = open_directory(path, dir_fd)
        try:
            self.sha_fd = open_directory("sha256", self.root_fd)
        except Refuse:
            os.close(self.root_fd)
            raise

    def close(self):
        os.close(self.sha_fd)
        os.close(self.root_fd)

    def read(self, digest, size, kind):
        if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
            raise Refuse("a blob digest is not sha256:<64 lowercase hex>")
        if not is_int(size) or not 0 < size <= BLOB_CAPS[kind]:
            raise Refuse("an attestation %s of %r bytes is outside the allowed size" % (kind, size))
        data = read_regular(self.sha_fd, hex_of(digest), size, "blob " + digest)
        if digest_of(data) != digest or len(data) != size:
            raise Refuse("a blob does not match its digest or size: %s" % digest)
        return data

    def check_inventory(self, needed):
        """exactly the blobs the attestations need: nothing else, nothing hidden, nothing nested"""
        if list_directory(self.root_fd, "the blobs directory") != {"sha256": stat.S_IFDIR}:
            raise Refuse("the blobs directory must hold only sha256/")
        found = list_directory(self.sha_fd, "blobs/sha256")
        wanted = {hex_of(digest): stat.S_IFREG for digest in needed}
        if found != wanted:
            raise Refuse("blobs/sha256 does not hold exactly the blobs the attestations need")


def check_final(final_bytes, blobs, vex, forbidden):
    """Validate a final index completely: its shape and order, every attestation rebuilt from its predicate and
    compared byte for byte, the predicates equal to scout_form(vex) and to each other, and no digest of D or F inside a blob.
    Returns the parsed final index, its attestation descriptors and the digests of the blobs they need."""
    final, platforms = load_index(final_bytes, final=True)
    if final_bytes != canonical(final):
        raise Refuse("the final index bytes are not the canonical serialisation")
    entries = final["manifests"]
    attestations = [entry for entry in entries if is_attestation(entry)]
    first = min([i for i, entry in enumerate(entries) if is_attestation(entry)] or [len(entries)])
    if any(not is_attestation(entry) for entry in entries[first:]):
        raise Refuse("attestation children must come after all original entries")
    platform_digests = [entry["digest"] for _, entry in platforms]
    references = []
    for entry in attestations:
        annotations = entry["annotations"]
        if set(annotations) != {"vnd.docker.reference.digest", "vnd.docker.reference.type"}:
            raise Refuse("attestation annotations are not exactly the two keys")
        if annotations["vnd.docker.reference.type"] != ATTESTATION:
            raise Refuse("attestation annotations are wrong")
        if (set(entry) != {"mediaType", "digest", "size", "annotations", "platform"} or entry["mediaType"] != OCI_MANIFEST
                or entry["platform"] != {"architecture": "unknown", "os": "unknown"}):
            raise Refuse("an attestation descriptor is not in the canonical shape")
        reference = annotations["vnd.docker.reference.digest"]
        if reference not in platform_digests:
            raise Refuse("an attestation names no platform of this index: %s" % reference)
        if reference in references:
            raise Refuse("two attestations for %s" % reference)
        references.append(reference)
    if references != platform_digests:
        raise Refuse("the platforms and their attestations do not match, in this order")
    needed = set()
    for entry in attestations:
        reference = entry["annotations"]["vnd.docker.reference.digest"]
        manifest = load_json(blobs.read(entry["digest"], entry["size"], "manifest"), "attestation manifest", limits=False)
        try:
            layer = manifest["layers"][0]
            statement = load_json(blobs.read(layer["digest"], layer["size"], "statement"), "statement", limits=False)
            predicate = statement["predicate"]
        except (KeyError, IndexError, TypeError):
            raise Refuse("an attestation manifest or its statement is malformed")
        check_vex(canonical(predicate))
        if canonical(predicate) != canonical(scout_form(vex)):
            raise Refuse("a statement's predicate is not the VEX file in Scout's applied form")
        expected, parts = build_attestation(reference, predicate)
        if expected != entry:
            raise Refuse("the attestation for %s does not have the canonical shape" % reference)
        for digest, data in parts.items():
            kind = "manifest" if digest == entry["digest"] else ("statement" if digest == layer["digest"] else "config")
            if blobs.read(digest, len(data), kind) != data:
                raise Refuse("a blob is not canonical: %s" % digest)
            for other in forbidden:
                if hex_of(other).encode() in data:
                    raise Refuse("a built-index or final-index digest appears inside an attestation blob")
            needed.add(digest)
    return final, attestations, needed


def verify_all(final_bytes, blobs, vex_bytes, base_bytes):
    """the one validation that verify and push both run; returns what push needs to send"""
    vex = check_vex(vex_bytes)
    forbidden = [digest_of(final_bytes)]
    if base_bytes is not None:
        forbidden.append(digest_of(base_bytes))
    final, attestations, needed = check_final(final_bytes, blobs, vex, forbidden)
    blobs.check_inventory(needed)
    if base_bytes is not None:
        base, _ = load_index(base_bytes, final=False)
        stripped = dict(final)
        stripped["manifests"] = [entry for entry in final["manifests"] if not is_attestation(entry)]
        if canonical(stripped) != canonical(base):  # canonical forms: 1 and true, or 0 and false, are different
            raise Refuse("the final index minus its attestations differs from the built index")
    return final, attestations


def command_verify(args):
    final_bytes = read_path(args.final, MAX_FINAL_BYTES)
    vex_bytes = read_path(args.vex, MAX_INDEX_BYTES)
    base_bytes = read_path(args.base, MAX_INDEX_BYTES) if args.base else None
    blobs = Blobs(args.blobs)
    try:
        verify_all(final_bytes, blobs, vex_bytes, base_bytes)
    finally:
        blobs.close()
    print("ok")


# ---------------------------------------------------------------- an OCI image layout, in place
LAYOUT_TOP = {"oci-layout": stat.S_IFREG, "index.json": stat.S_IFREG, "blobs": stat.S_IFDIR}


def open_layout(layout):
    """(dir_fd, blobs, top-level index.json, its one descriptor, the bytes of oci-layout and index.json as read) of an OCI image layout directory, or a refusal; the caller closes both"""
    layout_fd = open_directory(layout)
    try:
        require_private(layout_fd, "the layout directory")
        require_trusted_ancestors(layout)
        if list_directory(layout_fd, "the layout") != LAYOUT_TOP:
            raise Refuse("the layout must hold exactly oci-layout, index.json and blobs/ (regular files and a directory, no links)")
        marker_bytes = read_regular(layout_fd, "oci-layout", 1024, "oci-layout", private=True)
        marker = load_json(marker_bytes, "oci-layout")
        if marker != {"imageLayoutVersion": "1.0.0"}:
            raise Refuse("oci-layout is not exactly imageLayoutVersion 1.0.0")
        top_bytes = read_regular(layout_fd, "index.json", MAX_INDEX_BYTES, "index.json", private=True)      # read once: what is parsed is what is compared later
        top = load_json(top_bytes, "the layout's index.json")
        entries = top.get("manifests") if isinstance(top, dict) else None
        if not isinstance(top, dict) or top.get("schemaVersion") != 2 or not isinstance(entries, list) or len(entries) != 1:
            raise Refuse("the layout's index.json must have schemaVersion 2 and exactly one descriptor")
        if set(top) - {"schemaVersion", "mediaType", "manifests", "annotations"} or top.get("mediaType", OCI_INDEX) != OCI_INDEX \
                or ("annotations" in top and not is_string_map(top["annotations"])):
            raise Refuse("the layout's index.json has fields this tool does not handle (mediaType must be the OCI index, annotations strings)")
        entry = entries[0]
        if (not isinstance(entry, dict) or set(entry) - {"mediaType", "digest", "size", "annotations"} or entry.get("mediaType") != OCI_INDEX
                or not isinstance(entry.get("digest"), str) or not DIGEST.fullmatch(entry["digest"]) or not is_int(entry.get("size"))
                or not 0 < entry["size"] <= MAX_FINAL_BYTES or ("annotations" in entry and not is_string_map(entry["annotations"]))):
            raise Refuse("the layout's one descriptor must be an OCI image index (mediaType, digest, size, annotations as strings)")
        blobs = Blobs("blobs", layout_fd)
        try:
            require_private(blobs.root_fd, "blobs/")
            require_private(blobs.sha_fd, "blobs/sha256")
            if list_directory(blobs.root_fd, "blobs/") != {"sha256": stat.S_IFDIR}:
                raise Refuse("the layout's blobs/ must hold only sha256/")
        except BaseException:
            blobs.close()
            raise
        return layout_fd, blobs, top, entry, {"oci-layout": marker_bytes, "index.json": top_bytes}
    except BaseException:
        os.close(layout_fd)
        raise


def require_private(fd, what):
    """only this user may change what is at fd: owned by the effective user and not writable by group or others (a layout another account can
    write to cannot be checked by looking at it, so it is refused)"""
    info = os.fstat(fd)
    if info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise Refuse("%s is not private to this user (it must be owned by the effective user and not writable by group or others)" % what)


def hash_blobs(blobs):
    """{hex name: size} of every blob in blobs/sha256: each a regular file named by its own sha256 (streamed, any size)"""
    found = {}
    for name, kind in list_directory(blobs.sha_fd, "blobs/sha256").items():
        if kind != stat.S_IFREG or not re.fullmatch(r"[0-9a-f]{64}", name):
            raise Refuse("blobs/sha256 holds %r, which is not a regular file named by a sha256" % name)
        fd = os.open(name, FILE_FLAGS, dir_fd=blobs.sha_fd)
        try:
            require_private(fd, "blob " + name)
            digest, size = hashlib.sha256(), 0
            while True:
                chunk = os.read(fd, 1 << 20)
                if not chunk:
                    break
                digest.update(chunk)
                size += len(chunk)
        finally:
            os.close(fd)
        if digest.hexdigest() != name:
            raise Refuse("blob %s does not hash to its name" % name)
        found[name] = size
    return found


def reach_image(blobs, found, entry, where):
    """names of an image manifest's blobs and its config and layers, each present with the size its descriptor names"""
    names = set()

    def present(descriptor, what):
        check_descriptor_fields(descriptor, what)
        name = hex_of(descriptor["digest"])
        if found.get(name) != descriptor["size"]:
            raise Refuse("%s: the blob %s is missing or not the size its descriptor names" % (what, descriptor["digest"]))
        names.add(name)
    present(entry, where)
    manifest = load_json(read_regular(blobs.sha_fd, hex_of(entry["digest"]), MAX_SMALL_BLOB_BYTES, where), where, limits=False)
    if (not isinstance(manifest, dict) or manifest.get("schemaVersion") != 2 or manifest.get("mediaType") not in (OCI_MANIFEST, DOCKER_MANIFEST)
            or manifest["mediaType"] != entry["mediaType"] or not isinstance(manifest.get("layers"), list)):
        raise Refuse("%s is not an image manifest (schemaVersion 2, the media type its descriptor names, a config and layers)" % where)
    present(manifest.get("config"), where + " config")
    config = load_json(read_regular(blobs.sha_fd, hex_of(manifest["config"]["digest"]), MAX_CONFIG_BYTES, where + " config"), where + " config", limits=False)
    if not isinstance(config, dict):
        raise Refuse("%s config is not a JSON object" % where)
    for position, layer in enumerate(manifest["layers"]):
        present(layer, "%s layer %d" % (where, position))
    return names


def retained_children(index_bytes, final):
    """[(label, descriptor)] of every child that is not an attestation (also one without a platform): each is an image that must be whole"""
    index, _ = load_index(index_bytes, final=final)
    return [("child %d" % position, entry) for position, entry in enumerate(index["manifests"]) if not is_attestation(entry)]


def check_layout_blobs(blobs, children, extra_names):
    """every blob of the layout is a regular file hashing to its name, every platform's image graph is present and exact,
    and nothing else is in the directory beyond extra_names (which must also be present)"""
    found = hash_blobs(blobs)
    reach = set(extra_names)
    for label, entry in children:
        reach |= reach_image(blobs, found, entry, label)
    if set(found) != reach:
        raise Refuse("blobs/sha256 does not hold exactly the blobs of the images and the indexes")
    return found


def read_index_blob(blobs, entry, limit):
    data = read_regular(blobs.sha_fd, hex_of(entry["digest"]), limit, "the index blob " + entry["digest"])
    if digest_of(data) != entry["digest"] or len(data) != entry["size"]:
        raise Refuse("the index blob does not match the digest and size its descriptor names")
    return data


def same_directory(fd, parent_fd, name):
    """the directory entry name of parent_fd (no symlink followed) is the very directory fd holds open"""
    try:
        now, held = os.stat(name, dir_fd=parent_fd, follow_symlinks=False), os.fstat(fd)
    except OSError:
        return False
    return stat.S_ISDIR(now.st_mode) and (now.st_dev, now.st_ino) == (held.st_dev, held.st_ino)


def directories_held(layout_fd, blobs, root_path):
    """the layout, its blobs/ and blobs/sha256/ are still, by name, the directories this run holds open"""
    parent_fd, name = open_parent(root_path)
    try:
        root_ok = same_directory(layout_fd, parent_fd, name)
    finally:
        os.close(parent_fd)
    return root_ok and same_directory(blobs.root_fd, layout_fd, "blobs") and same_directory(blobs.sha_fd, blobs.root_fd, "sha256")


def layout_state_problem(layout_fd, blobs, files, blob_sizes, root_path):
    """why the layout is not exactly the expected state (top-level files by name with their bytes, blobs with their sizes), or None;
    the blobs are hashed first and every listing and file is read after that, so a change during the hashing is seen too"""
    if not directories_held(layout_fd, blobs, root_path):
        return "a directory of the layout was replaced while it was open"
    if hash_blobs(blobs) != blob_sizes:
        return "the blobs are not the expected ones"
    if list_directory(layout_fd, "the layout") != dict({name: stat.S_IFREG for name in files}, blobs=stat.S_IFDIR):
        return "the layout's files are not the expected ones"
    if list_directory(blobs.root_fd, "blobs/") != {"sha256": stat.S_IFDIR}:
        return "blobs/ is not the expected directory"
    if {name: stat.S_IFREG for name in blob_sizes} != list_directory(blobs.sha_fd, "blobs/sha256"):
        return "blobs/sha256 is not the expected directory"
    for name, data in files.items():
        if read_regular(layout_fd, name, MAX_INDEX_BYTES, name, private=True) != data:
            return "%s is not the expected file" % name
    if not directories_held(layout_fd, blobs, root_path):      # once more after the hashing and reading
        return "a directory of the layout was replaced while it was open"
    return None


def unlink_quiet(dir_fd, name):
    try:
        os.unlink(name, dir_fd=dir_fd)
    except OSError:
        pass


def command_layout(args):
    vex_bytes = read_path(args.vex, MAX_INDEX_BYTES)
    layout_fd, blobs, top, entry, snapshot = open_layout(args.layout)
    created, tmp, tmp_made = [], "index.json.vex-index.tmp", False
    try:
        d_bytes = read_index_blob(blobs, entry, MAX_INDEX_BYTES)
        final_bytes, new_blobs, result = compute(d_bytes, vex_bytes)
        before = check_layout_blobs(blobs, retained_children(d_bytes, False), {hex_of(entry["digest"])})   # the whole layout, before anything is written
        planned = dict(new_blobs)
        planned[digest_of(final_bytes)] = final_bytes
        for digest, data in planned.items():
            if hex_of(digest) in before and read_regular(blobs.sha_fd, hex_of(digest), len(data), "blob " + digest) != data:
                raise Refuse("a blob this run would write already exists with other content: %s" % digest)
        final_top = dict(top)
        descriptor = {"mediaType": OCI_INDEX, "digest": digest_of(final_bytes), "size": len(final_bytes)}
        if "annotations" in entry:
            descriptor["annotations"] = entry["annotations"]
        final_top["manifests"] = [descriptor]
        top_out = canonical(final_top) + b"\n"
        create_file(layout_fd, tmp, top_out)   # claimed first: if it exists, nothing else is written
        tmp_made = True
        for digest, data in planned.items():
            if hex_of(digest) not in before:
                create_file(blobs.sha_fd, hex_of(digest), data)
                created.append(hex_of(digest))
        sizes = dict(before, **{hex_of(d): len(planned[d]) for d in planned})
        problem = layout_state_problem(layout_fd, blobs, dict(snapshot, **{tmp: top_out}), sizes, args.layout)
        if problem:
            raise Refuse("the layout changed while this run was working (%s); nothing was committed" % problem)
        os.rename(tmp, "index.json", src_dir_fd=layout_fd, dst_dir_fd=layout_fd)
        tmp_made = False
        problem = layout_state_problem(layout_fd, blobs, {"oci-layout": snapshot["oci-layout"], "index.json": top_out}, sizes, args.layout)
        if problem:
            raise Refuse("the layout changed during the commit (%s); it is not trustworthy" % problem)
    except BaseException:
        for name in (created if tmp_made else []):
            unlink_quiet(blobs.sha_fd, name)
        if tmp_made:
            unlink_quiet(layout_fd, tmp)
        raise
    finally:
        blobs.close()
        os.close(layout_fd)
    sys.stdout.buffer.write(canonical(result) + b"\n")


def verify_layout_state(layout, vex_bytes, base_digest):
    """check that the layout holds the canonical final index of the built index base_digest and the VEX file; returns the final index's digest"""
    if not DIGEST.fullmatch(base_digest):
        raise Refuse("the built index's digest is not sha256:<64 lowercase hex>")
    layout_fd, blobs, top, entry, _snapshot = open_layout(layout)
    try:
        final_bytes = read_index_blob(blobs, entry, MAX_FINAL_BYTES)
        vex = check_vex(vex_bytes)
        base = read_regular(blobs.sha_fd, hex_of(base_digest), MAX_INDEX_BYTES, "the built index blob")
        if digest_of(base) != base_digest:
            raise Refuse("the built index blob does not match the built index's digest")
        final, attestations, needed = check_final(final_bytes, blobs, vex, [digest_of(final_bytes), base_digest])
        built, _ = load_index(base, final=False)
        stripped = dict(final)
        stripped["manifests"] = [e for e in final["manifests"] if not is_attestation(e)]
        if canonical(stripped) != canonical(built):
            raise Refuse("the final index minus its attestations differs from the built index")
        check_layout_blobs(blobs, retained_children(final_bytes, True), {hex_of(entry["digest"]), hex_of(base_digest)} | {hex_of(d) for d in needed})
        return entry["digest"]
    finally:
        blobs.close()
        os.close(layout_fd)


def command_verify_layout(args):
    verify_layout_state(args.layout, read_path(args.vex, MAX_INDEX_BYTES), args.base_digest)
    print("ok")


SIDECAR_LINE = re.compile(rb"sha256:[0-9a-f]{64}\n")


def command_sidecar(args):
    """OUT/<variant>.digest names the built index until layout has run; this moves it to the final index, after checking the layout is the final index of
    exactly that built index and the VEX file (the one writer of that file besides the image assembly)"""
    vex_bytes = read_path(args.vex, MAX_INDEX_BYTES)
    parent_fd, name = open_parent(args.digest_file)
    tmp, tmp_made = name + ".vex-index.tmp", False
    try:
        require_trusted_ancestors(args.digest_file)
        current = read_regular(parent_fd, name, 128, args.digest_file, private=True)
        if not SIDECAR_LINE.fullmatch(current):
            raise Refuse("%s must hold one line, sha256:<64 lowercase hex> and a newline, and nothing else" % args.digest_file)
        final_digest = verify_layout_state(args.layout, vex_bytes, current[:-1].decode())
        try:
            create_file(parent_fd, tmp, final_digest.encode() + b"\n")      # claimed exclusively; a temporary file that exists already is refused
        except FileExistsError:
            raise Refuse("%s.vex-index.tmp exists already; it is not this run's to remove" % args.digest_file)
        tmp_made = True
        if read_regular(parent_fd, name, 128, args.digest_file, private=True) != current:
            raise Refuse("%s changed while this run was working; nothing was committed" % args.digest_file)
        os.rename(tmp, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        tmp_made = False
    except BaseException:
        if tmp_made:
            unlink_quiet(parent_fd, tmp)
        raise
    finally:
        os.close(parent_fd)
    print(final_digest)


def build_parser():
    parser = argparse.ArgumentParser(prog="vex-index", description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    compute_parser = commands.add_parser("compute", help="derive the final index from the built index and the VEX file")
    compute_parser.add_argument("--index", required=True)
    compute_parser.add_argument("--vex", required=True)
    compute_parser.add_argument("--out-dir", required=True)
    verify_parser = commands.add_parser("verify", help="check a final index (and, with --blobs, its attestations)")
    verify_parser.add_argument("--final", required=True)
    verify_parser.add_argument("--vex", required=True)
    verify_parser.add_argument("--blobs", required=True, help="the blobs directory written by compute (holds sha256/<hex>)")
    verify_parser.add_argument("--base", required=True, help="the built index file (the exclusion of its digest from the attestations is checked against it)")
    layout_parser = commands.add_parser("layout", help="turn the built index of an OCI image layout into the final index, in place")
    layout_parser.add_argument("--layout", required=True)
    layout_parser.add_argument("--vex", required=True)
    verify_layout = commands.add_parser("verify-layout", help="check that an OCI image layout holds a canonical final index with its attestations")
    verify_layout.add_argument("--layout", required=True)
    verify_layout.add_argument("--vex", required=True)
    sidecar_parser = commands.add_parser("sidecar", help="move OUT/<variant>.digest from the built index's digest to the final index's, after checking the layout")
    sidecar_parser.add_argument("--layout", required=True)
    sidecar_parser.add_argument("--vex", required=True)
    sidecar_parser.add_argument("--digest-file", required=True)
    verify_layout.add_argument("--base-digest", required=True, help="the built index's digest: the final index minus its attestations must equal that blob")
    return parser


def main():
    args = build_parser().parse_args()
    try:
        {"compute": command_compute, "verify": command_verify, "layout": command_layout, "verify-layout": command_verify_layout,
         "sidecar": command_sidecar}[args.command](args)
    except Refuse as err:
        sys.stderr.write("vex-index: refused: %s\n" % err)
        sys.exit(2)
    except Exception as err:  # a plain one-line reason, never a traceback and never a request header
        sys.stderr.write("vex-index: error: %s\n" % type(err).__name__)
        sys.exit(1)


if __name__ == "__main__":
    main()
