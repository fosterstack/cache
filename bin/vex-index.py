#!/usr/bin/env python3
"""vex-index: derive, check and push the final image index that carries the release's VEX (REQ-REL-010).

The final index F is the built index D plus one attestation-manifest child per platform; every child carries the
release's OpenVEX document as an in-toto statement whose subject is that platform's own digest. F is a pure function
of the bytes of D and of the VEX file: nothing signed or promoted ever names D.

  compute --index D.json --vex VEX.json --out-dir DIR
  verify  --final F.json --vex VEX.json --blobs DIR/blobs [--base D.json]
  push    --registry HOST[:PORT] --repository NAME --dir DIR --vex VEX.json --base D.json

verify always performs the full validation. push re-runs exactly that validation over DIR, and checks result.json
against a recomputation from --base and --vex, before it sends anything.

Standard library only. compute and verify never touch the network. push talks the distribution API and reads
FSCACHE_REGISTRY_USER, FSCACHE_REGISTRY_TOKEN and FSCACHE_REGISTRY_TIMEOUT from the environment (proxy variables are
ignored); nothing else in the environment (CI variables, locale, time zone, clock) influences any output.

Exit status: 0 success, 2 the input or the registry was refused (a plain reason on stderr), 1 an unexpected error.
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
import threading
import urllib.error
import urllib.parse
import urllib.request

ATTESTATION = "attestation-manifest"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
INTOTO = "application/vnd.in-toto+json"
PREDICATE_TYPE = "https://openvex.dev/ns/v0.2.0"
STATEMENT_TYPE = "https://in-toto.io/Statement/v0.1"
SUBJECT_NAME = "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache"
ACCEPT = ", ".join((OCI_INDEX, OCI_MANIFEST, DOCKER_MANIFEST))

MAX_INDEX_BYTES = 1 << 20      # the built index and the VEX file
MAX_FINAL_BYTES = 2 << 20      # the final index (the built index plus the attestation descriptors)
MAX_DEPTH = 32
MAX_PLATFORMS = 64
MAX_INT = 2 ** 53
DEFAULT_TIMEOUT = 30           # seconds, for each registry request (documented in `push --help`)
MAX_RESULT_BYTES = 64 << 10    # result.json
MAX_STATEMENT_BYTES = 2 << 20  # an attestation statement (it embeds the VEX)
MAX_SMALL_BLOB_BYTES = 64 << 10  # an attestation manifest or config
MAX_BODY_BYTES = 64 << 10      # a registry response body (token, upload start, ...)
MAX_MANIFEST_BODY_BYTES = 4 << 20  # the read-back of the final index

# every digest, port and name below is ASCII only: [0-9] and explicit classes, never \d or \w
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
HOST = re.compile(r"[A-Za-z0-9.-]+(:[0-9]{1,5})?|\[[0-9a-f:]+\](:[0-9]{1,5})?")
REPOSITORY = re.compile(r"[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*")
# RFC 3339 section 5.6: T and Z in either case, seconds up to 60 (leap second), at least one fractional digit
TIMESTAMP = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]+)?([Zz]|[+-]([01][0-9]|2[0-3]):[0-5][0-9])")
LOCAL_HOSTS = ("localhost", "127.0.0.1")
DOCKER_HUB = ("registry-1.docker.io", "docker.io")


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


# ---------------------------------------------------------------- compute
def compute(index_bytes, vex_bytes):
    vex = check_vex(vex_bytes)
    index, platforms = load_index(index_bytes, final=False)
    if hex_of(digest_of(index_bytes)).encode() in canonical(vex):
        raise Refuse("the VEX mentions the built index's digest")
    descriptors, blobs, summary = [], {}, {}
    for name, entry in platforms:
        descriptor, parts = build_attestation(entry["digest"], vex)
        descriptors.append(descriptor)
        blobs.update(parts)
        summary[name] = {"platform_digest": entry["digest"], "attestation_digest": descriptor["digest"]}
    final = dict(index)
    final["manifests"] = list(index["manifests"]) + descriptors
    final_bytes = canonical(final)
    result = {"base_digest": digest_of(index_bytes), "final_digest": digest_of(final_bytes), "platforms": summary,
              "vex_sha256": hashlib.sha256(vex_bytes).hexdigest()}
    return final_bytes, blobs, result


# ---------------------------------------------------------------- files and directories
# Every directory is opened once (no symlink on its last component) and everything inside it is reached through that
# descriptor, so a path cannot be swapped for a symlink between being checked and being used. Files are opened without
# following symlinks and without blocking, must be regular files, and are read at most limit + 1 bytes.
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


def clean_path(path):
    """drop trailing separators and '/.' so that link/ and link/. cannot hide a symlink named link"""
    while True:
        if len(path) > 1 and path.endswith("/"):
            path = path.rstrip("/") or "/"
        elif path.endswith("/."):
            path = path[:-2] or "/"
        else:
            return path


def open_directory(path, dir_fd=None):
    try:
        return os.open(clean_path(path) if dir_fd is None else path, DIR_FLAGS, dir_fd=dir_fd)
    except OSError as err:
        raise Refuse("%s is not a readable directory (a symlink is refused): %s" % (path, err.strerror))


def open_parent(path):
    """the directory that holds path (its own symlinks, if any, are followed) and the name of path inside it"""
    parent, name = os.path.split(clean_path(path))
    try:
        return os.open(parent or ".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC), name
    except OSError as err:
        raise Refuse("cannot open the directory of %s: %s" % (path, err.strerror))


def read_regular(dir_fd, name, limit, what):
    """the bytes of a regular file inside an open directory, refusing anything else and anything above limit"""
    if name in ("", ".", ".."):
        raise Refuse("%s is not a file name" % what)
    try:
        fd = os.open(name, FILE_FLAGS, dir_fd=dir_fd)
    except OSError as err:
        raise Refuse("cannot open %s: %s" % (what, err.strerror))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise Refuse("%s is not a regular file" % what)
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
        return read_regular(parent_fd, name, limit, path)
    finally:
        os.close(parent_fd)


def list_directory(dir_fd, what):
    """{name: file type bits} of every entry (hidden ones too), or a refusal when the directory cannot be listed"""
    try:
        return {name: stat.S_IFMT(os.stat(name, dir_fd=dir_fd, follow_symlinks=False).st_mode) for name in os.listdir(dir_fd)}
    except OSError as err:
        raise Refuse("cannot list %s: %s" % (what, err.strerror))


def create_file(dir_fd, name, data):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o666, dir_fd=dir_fd)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


# ---------------------------------------------------------------- compute
def compute(index_bytes, vex_bytes):
    vex = check_vex(vex_bytes)
    index, platforms = load_index(index_bytes, final=False)
    if hex_of(digest_of(index_bytes)).encode() in canonical(vex):
        raise Refuse("the VEX mentions the built index's digest")
    descriptors, blobs, summary = [], {}, {}
    for name, entry in platforms:
        descriptor, parts = build_attestation(entry["digest"], vex)
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
    path = clean_path(path)
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
    compared byte for byte, the predicates equal to vex and to each other, and no digest of D or F inside a blob.
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
        if canonical(predicate) != canonical(vex):
            raise Refuse("a statement's predicate is not the VEX file")
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


# ---------------------------------------------------------------- the registry client
def registry_scheme(registry):
    """http only for localhost and 127.0.0.1 (the tests); https for every other bare host[:port]"""
    if not HOST.fullmatch(registry or ""):
        raise Refuse("the registry must be a bare host[:port]")
    return "http" if registry.split(":")[0].lower() in LOCAL_HOSTS else "https"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


class Registry:
    """Distribution API client. Never follows a redirect; never leaves the registry's origin (scheme, host, port);
    sends the Basic credentials only to a token endpoint on the registry's own host (or auth.docker.io for Docker
    Hub), always over https except for localhost; applies one total deadline to every request."""

    def __init__(self, registry, repository, timeout):
        self.scheme = registry_scheme(registry)
        self.host = registry.lower()
        self.repository = repository
        self.timeout = timeout
        self.user = os.environ.get("FSCACHE_REGISTRY_USER")
        self.secret = os.environ.get("FSCACHE_REGISTRY_TOKEN")
        self.bearer = None
        self.basic = False
        # no proxy handler at all: proxy variables in the environment are never consulted
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)
        parts = self.host.rsplit(":", 1)
        self.name = parts[0] if len(parts) == 2 and parts[1].isascii() and parts[1].isdigit() else self.host
        self.port = int(parts[1]) if self.name != self.host else (80 if self.scheme == "http" else 443)

    def basic_header(self):
        return "Basic " + base64.b64encode(("%s:%s" % (self.user, self.secret)).encode()).decode()

    def own(self, url):
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != self.scheme or parts.netloc.lower() != self.host:
            raise Refuse("a URL leaves the registry's origin")

    def send(self, method, url, body=None, headers=None, max_body=MAX_BODY_BYTES):
        """one request under the total deadline: (status, lower-cased headers, body)"""
        outcome = {}

        def work():
            try:
                outcome["result"] = self.send_once(method, url, body, headers, max_body)
            except BaseException as err:  # handed to the caller below
                outcome["error"] = err
        thread = threading.Thread(target=work, daemon=True)
        thread.start()
        thread.join(self.timeout)
        if thread.is_alive():
            raise Refuse("a request timed out after %g s" % self.timeout)
        if "error" in outcome:
            raise outcome["error"]
        return outcome["result"]

    def send_once(self, method, url, body, headers, max_body):
        headers = dict(headers or {})
        if self.bearer:
            headers["Authorization"] = "Bearer " + self.bearer
        elif self.basic:
            headers["Authorization"] = self.basic_header()
        request = urllib.request.Request(url, data=body, method=method, headers=headers)
        try:
            response = self.opener.open(request, timeout=self.timeout)
            data = read_body(response, max_body)
            if data is None:
                raise Refuse("a response body is larger than %d bytes" % max_body)
            return response.status, lowered(response.headers), data
        except urllib.error.HTTPError as err:
            if 300 <= err.code < 400:
                raise Refuse("the registry answered %d: redirects are never followed" % err.code)
            read_body(err, MAX_BODY_BYTES)  # an error body is only a hint: read a little of it, drop the rest
            return err.code, lowered(err.headers), b""

    def realm_allowed(self, realm):
        """the token realm names the registry's own host and port over the registry's scheme (https, or http for
        localhost), or for Docker Hub exactly auth.docker.io:443; ASCII only, no user information"""
        parts = urllib.parse.urlsplit(realm)
        if not realm.isascii() or "@" in parts.netloc or not parts.hostname:
            return False
        try:
            port = parts.port or (443 if parts.scheme == "https" else 80)
        except ValueError:
            return False
        host = parts.hostname.lower()
        docker = self.name in DOCKER_HUB and host == "auth.docker.io" and parts.scheme == "https" and port == 443
        same = host == self.name and port == self.port and (
            parts.scheme == "https" or (parts.scheme == "http" and self.scheme == "http" and host in LOCAL_HOSTS))
        return docker or same

    def token(self, challenge):
        """fetch a bearer token for the challenge; the tool always asks for pull and push on its own repository"""
        found = dict(re.findall(r'([A-Za-z]+)="([^"]*)"', challenge))
        realm = found.get("realm", "")
        if not self.realm_allowed(realm):
            raise Refuse("the token realm is not on the registry's own host")
        query = {"scope": "repository:%s:pull,push" % self.repository}
        if "service" in found:
            query["service"] = found["service"]
        headers = {}
        if self.user and self.secret:
            headers["Authorization"] = self.basic_header()
        status, _, body = self.send("GET", realm + ("&" if "?" in realm else "?") + urllib.parse.urlencode(query), None, headers)
        if status != 200:
            raise Refuse("the token endpoint refused the request (%d)" % status)
        try:
            issued = json.loads(body)
            bearer = issued.get("token") or issued.get("access_token")
        except (ValueError, AttributeError):
            bearer = None
        if not non_empty(bearer):
            raise Refuse("the token endpoint returned no token")
        self.bearer = bearer

    def request(self, method, path, body=None, headers=None, max_body=MAX_BODY_BYTES):
        url = path if path.startswith("http") else "%s://%s%s" % (self.scheme, self.host, path)
        self.own(url)
        status, response, data = self.send(method, url, body, headers, max_body)
        if status == 401 and not self.bearer and not self.basic:
            challenge = response.get("www-authenticate", "")
            if challenge.lower().startswith("bearer"):
                self.token(challenge)
                status, response, data = self.send(method, url, body, headers, max_body)
            elif challenge.lower().startswith("basic") and self.user and self.secret:
                self.basic = True
                status, response, data = self.send(method, url, body, headers, max_body)
        return status, response, data

    def upload_url(self, location):
        """the registry's own answer to starting an upload, accepted only in its one expected shape:
        /v2/<repository>/blobs/uploads/<session>[?_state=<opaque>] on this very origin (absolute or relative),
        so a registry can never aim an authenticated PUT at a manifest, a tag or another repository"""
        candidate = self.scheme + "://" + self.host + location if location.startswith("/") else location
        expected = re.compile(re.escape("%s://%s/v2/%s/blobs/uploads/" % (self.scheme, self.host, self.repository))
                              + r"([A-Za-z0-9_.~=-]+)(\?_state=[A-Za-z0-9_.~=-]+)?")
        match = expected.fullmatch(candidate)
        if not match or match.group(1).strip(".") == "":
            raise Refuse("the registry's upload location is not an upload session of this repository")
        return candidate


def read_body(response, limit):
    """the body in chunks, or None when it is longer than limit (the rest is never read)"""
    chunks, total = [], 0
    while True:
        chunk = response.read(min(65536, limit + 1 - total))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            return None


def lowered(headers):
    return {key.lower(): value for key, value in headers.items()}


# ---------------------------------------------------------------- push
def request_timeout():
    text = os.environ.get("FSCACHE_REGISTRY_TIMEOUT", str(DEFAULT_TIMEOUT))
    try:
        seconds = float(text)
    except ValueError:
        seconds = float("nan")
    if not math.isfinite(seconds) or seconds <= 0:
        raise Refuse("FSCACHE_REGISTRY_TIMEOUT must be a positive number of seconds")
    return seconds


def load_for_push(args):
    """everything push will send, decided before the first request: DIR must hold exactly index.json, result.json and
    blobs/; the full verification runs over it with --vex and --base; result.json must say what compute(--base, --vex)
    says; returns the final index bytes, its parsed form, the manifests and the blobs to upload"""
    dir_fd = open_directory(args.dir)
    try:
        if list_directory(dir_fd, "DIR") != {"index.json": stat.S_IFREG, "result.json": stat.S_IFREG, "blobs": stat.S_IFDIR}:
            raise Refuse("DIR must hold exactly index.json, result.json and blobs/")
        index_bytes = read_regular(dir_fd, "index.json", MAX_FINAL_BYTES, "index.json")
        result_bytes = read_regular(dir_fd, "result.json", MAX_RESULT_BYTES, "result.json")
        vex_bytes = read_path(args.vex, MAX_INDEX_BYTES)
        base_bytes = read_path(args.base, MAX_INDEX_BYTES)
        blobs = Blobs("blobs", dir_fd)
        try:
            final, attestations = verify_all(index_bytes, blobs, vex_bytes, base_bytes)
            expected_final, _, expected_result = compute(base_bytes, vex_bytes)
            result = load_json(result_bytes, "result.json", limits=False)
            if index_bytes != expected_final or canonical(result) != canonical(expected_result):
                raise Refuse("index.json or result.json is not what compute produces from --base and --vex")
            manifests, uploads = [], []
            for entry in attestations:
                manifest_bytes = blobs.read(entry["digest"], entry["size"], "manifest")
                manifests.append((entry["digest"], manifest_bytes))
                manifest = json.loads(manifest_bytes)
                for part, kind in ((manifest["config"], "config"), (manifest["layers"][0], "statement")):
                    if part["digest"] not in [digest for digest, _ in uploads]:
                        uploads.append((part["digest"], blobs.read(part["digest"], part["size"], kind)))
        finally:
            blobs.close()
    finally:
        os.close(dir_fd)
    return index_bytes, final, manifests, uploads


def command_push(args):
    if not REPOSITORY.fullmatch(args.repository):
        raise Refuse("the repository name is not a valid distribution name")
    timeout = request_timeout()
    index_bytes, final, manifests, blobs = load_for_push(args)
    children = [entry["digest"] for entry in final["manifests"]]
    final_digest = digest_of(index_bytes)

    registry = Registry(args.registry, args.repository, timeout)
    name = args.repository
    manifest_headers = {"Accept": ACCEPT}
    uploaded = []
    for digest, data in blobs:
        status, _, _ = registry.request("HEAD", "/v2/%s/blobs/%s" % (name, digest))
        if status == 200:
            continue
        if status != 404:
            raise Refuse("a blob HEAD answered %d" % status)
        status, response, _ = registry.request("POST", "/v2/%s/blobs/uploads/" % name)
        if status != 202 or "location" not in response:
            raise Refuse("starting an upload failed (%d)" % status)
        location = registry.upload_url(response["location"])
        location += ("&" if "?" in location else "?") + "digest=" + digest
        status, _, _ = registry.request("PUT", location, data, {"Content-Type": "application/octet-stream"})
        if status not in (200, 201):
            raise Refuse("a blob upload failed (%d)" % status)
        uploaded.append(digest)
    for digest in uploaded:
        status, _, _ = registry.request("HEAD", "/v2/%s/blobs/%s" % (name, digest))
        if status != 200:
            raise Refuse("a blob is not there after its upload: %s (%d)" % (digest, status))

    def put_manifest(reference, data, media_type):
        status, _, _ = registry.request("PUT", "/v2/%s/manifests/%s" % (name, reference), data, {"Content-Type": media_type})
        if status not in (200, 201):
            raise Refuse("a manifest write failed (%d)" % status)
    for digest, data in manifests:
        put_manifest(digest, data, OCI_MANIFEST)
    for digest in children:  # platform children and the attestation manifests just written: all must be there before F
        status, _, _ = registry.request("HEAD", "/v2/%s/manifests/%s" % (name, digest), None, manifest_headers)
        if status != 200:
            raise Refuse("a child manifest is not in the repository: %s (%d)" % (digest, status))
    put_manifest(final_digest, index_bytes, OCI_INDEX)
    status, response, data = registry.request("GET", "/v2/%s/manifests/%s" % (name, final_digest), None, manifest_headers, MAX_MANIFEST_BODY_BYTES)
    media_type = response.get("content-type", "").split(";")[0].strip(" \t")
    if status != 200 or data != index_bytes or media_type != OCI_INDEX:
        raise Refuse("the read-back of the final index differs from what was pushed")
    print(final_digest)


# ---------------------------------------------------------------- command line
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
    verify_parser.add_argument("--base", help="the built index file")
    push_parser = commands.add_parser(
        "push", help="push a computed DIR to a registry, by digest only",
        epilog="Environment: FSCACHE_REGISTRY_USER and FSCACHE_REGISTRY_TOKEN are the registry credentials. "
               "FSCACHE_REGISTRY_TIMEOUT is the total deadline in seconds for each request (default %d)." % DEFAULT_TIMEOUT)
    push_parser.add_argument("--registry", required=True, help="a bare host[:port]; http only for localhost")
    push_parser.add_argument("--repository", required=True)
    push_parser.add_argument("--dir", required=True, help="the directory written by compute")
    push_parser.add_argument("--vex", required=True, help="the release's VEX file the DIR was computed from")
    push_parser.add_argument("--base", required=True, help="the built index file the DIR was computed from")
    return parser


def main():
    args = build_parser().parse_args()
    try:
        {"compute": command_compute, "verify": command_verify, "push": command_push}[args.command](args)
    except Refuse as err:
        sys.stderr.write("vex-index: refused: %s\n" % err)
        sys.exit(2)
    except Exception as err:  # a plain one-line reason, never a traceback and never a request header
        sys.stderr.write("vex-index: error: %s\n" % type(err).__name__)
        sys.exit(1)


if __name__ == "__main__":
    main()
