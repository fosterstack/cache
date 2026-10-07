#!/usr/bin/env python3
"""vex-index: derive, check and push the final image index that carries the release's VEX (REQ-REL-010).

The final index F is the built index D plus one attestation-manifest child per platform; every child carries the
release's OpenVEX document as an in-toto statement whose subject is that platform's own digest. F is a pure function
of the bytes of D and of the VEX file: nothing signed or promoted ever names D.

  compute --index D.json --vex VEX.json --out-dir DIR
  verify  --final F.json --vex VEX.json [--base D.json] [--blobs DIR/blobs]
  push    --registry HOST[:PORT] --repository NAME --dir DIR [--base-digest sha256:...]

Standard library only. compute and verify never touch the network. push talks the distribution API and reads
FSCACHE_REGISTRY_USER, FSCACHE_REGISTRY_TOKEN and FSCACHE_REGISTRY_TIMEOUT from the environment; nothing else in the
environment (CI variables, locale, time zone, clock) influences any output.

Exit status: 0 success, 2 the input or the registry was refused (a plain reason on stderr), 1 an unexpected error.
"""
import argparse
import base64
import datetime
import hashlib
import json
import math
import os
import re
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
def check_descriptor(entry, position):
    where = "manifests[%d]" % position
    if not isinstance(entry, dict):
        raise Refuse("%s is not an object" % where)
    if not isinstance(entry.get("digest"), str) or not DIGEST.fullmatch(entry["digest"]):
        raise Refuse("%s: the digest is not sha256:<64 lowercase hex>" % where)
    size = entry.get("size")
    if not is_int(size) or not 1 <= size <= 2 ** 31:
        raise Refuse("%s: the size is not an integer between 1 and 2**31" % where)
    if entry.get("mediaType") not in (OCI_MANIFEST, DOCKER_MANIFEST):
        raise Refuse("%s: the mediaType is not an image manifest" % where)
    if entry.get("annotations") is not None and not isinstance(entry["annotations"], dict):
        raise Refuse("%s: annotations is not an object" % where)


def is_attestation(entry):
    annotations = entry.get("annotations") or {}
    return annotations.get("vnd.docker.reference.type") == ATTESTATION or "vnd.docker.reference.digest" in annotations


def platform_key(entry, position):
    platform = entry.get("platform")
    if not isinstance(platform, dict):
        raise Refuse("manifests[%d]: no platform" % position)
    os_name, arch, variant = platform.get("os"), platform.get("architecture"), platform.get("variant")
    if not non_empty(os_name) or not non_empty(arch) or (variant is not None and not isinstance(variant, str)):
        raise Refuse("manifests[%d]: the platform is unreadable" % position)
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


def blob_path(blobs_dir, digest):
    """where a digest lives in a blobs directory; the digest is checked first so that it can never be a path"""
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        raise Refuse("a blob digest is not sha256:<64 lowercase hex>")
    return os.path.join(blobs_dir, "sha256", hex_of(digest))


def read_file(path):
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except OSError as err:
        raise Refuse("cannot read %s (%s)" % (path, err.strerror))


def write_file(path, data):
    with open(path, "xb") as handle:
        handle.write(data)


def command_compute(args):
    final_bytes, blobs, result = compute(read_file(args.index), read_file(args.vex))
    out = args.out_dir
    if os.path.islink(out):
        raise Refuse("the out-dir is a symlink")
    if os.path.exists(out):
        if not os.path.isdir(out):
            raise Refuse("the out-dir is not a directory")
        if os.listdir(out):
            raise Refuse("the out-dir is not empty")
    else:
        os.mkdir(out)
    os.makedirs(os.path.join(out, "blobs", "sha256"))
    for digest, data in blobs.items():
        write_file(os.path.join(out, "blobs", "sha256", hex_of(digest)), data)
    write_file(os.path.join(out, "index.json"), final_bytes)
    write_file(os.path.join(out, "result.json"), canonical(result) + b"\n")
    print(result["final_digest"])


# ---------------------------------------------------------------- the structure of a final index and its blobs
def check_final(final_bytes, read_blob, vex, forbidden):
    """Validate a final index completely. read_blob(digest, size) returns verified bytes, or is None to check the
    index alone. vex is the VEX document to compare the statements with (None: only require them to be equal to each
    other and valid). forbidden: digests that must not appear inside any attestation blob. Returns the parsed final
    index, the attestation descriptors and the set of blob digests an attestation needs."""
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
        if annotations["vnd.docker.reference.type"] != ATTESTATION or not isinstance(annotations["vnd.docker.reference.digest"], str):
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
    needed, first_predicate = set(), None
    if read_blob is None:
        return final, attestations, needed
    for entry in attestations:
        reference = entry["annotations"]["vnd.docker.reference.digest"]
        manifest_bytes = read_blob(entry["digest"], entry["size"])
        manifest = load_json(manifest_bytes, "attestation manifest", limits=False)
        try:
            layer = manifest["layers"][0]
            statement = load_json(read_blob(layer["digest"], layer["size"]), "statement", limits=False)
            predicate = statement["predicate"]
        except (KeyError, IndexError, TypeError):
            raise Refuse("an attestation manifest or its statement is malformed")
        check_vex(canonical(predicate))
        if vex is not None and predicate != vex:
            raise Refuse("a statement's predicate is not the VEX file")
        if first_predicate is not None and predicate != first_predicate:
            raise Refuse("the attestations carry different predicates")
        first_predicate = predicate
        expected, parts = build_attestation(reference, predicate)
        if expected != entry:
            raise Refuse("the attestation for %s does not have the canonical shape" % reference)
        for digest, data in parts.items():
            if read_blob(digest, len(data)) != data:
                raise Refuse("a blob is not canonical: %s" % digest)
            for other in forbidden:
                if hex_of(other).encode() in data:
                    raise Refuse("a built-index or final-index digest appears inside an attestation blob")
            needed.add(digest)
    return final, attestations, needed


def command_verify(args):
    if args.base and DIGEST.fullmatch(args.base):
        raise Refuse("--base takes the built index file; a digest cannot be checked offline")
    final_bytes = read_file(args.final)
    vex = check_vex(read_file(args.vex))
    forbidden = [digest_of(final_bytes)]
    base_bytes = None
    if args.base:
        base_bytes = read_file(args.base)
        forbidden.append(digest_of(base_bytes))
    reader = None
    if args.blobs:
        def reader(digest, size):
            path = blob_path(args.blobs, digest)
            if os.path.islink(path) or not os.path.isfile(path):
                raise Refuse("blob missing: %s" % digest)
            data = read_file(path)
            if digest_of(data) != digest or len(data) != size:
                raise Refuse("blob does not match its digest or size: %s" % digest)
            return data
    final, _, _ = check_final(final_bytes, reader, vex, forbidden)
    if base_bytes is not None:
        base, _ = load_index(base_bytes, final=False)
        stripped = dict(final)
        stripped["manifests"] = [entry for entry in final["manifests"] if not is_attestation(entry)]
        if stripped != base:
            raise Refuse("the final index minus its attestations differs from the built index")
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
        self.opener = urllib.request.build_opener(NoRedirect)
        parts = self.host.rsplit(":", 1)
        self.name = parts[0] if len(parts) == 2 and parts[1].isascii() and parts[1].isdigit() else self.host
        self.port = int(parts[1]) if self.name != self.host else (80 if self.scheme == "http" else 443)

    def basic_header(self):
        return "Basic " + base64.b64encode(("%s:%s" % (self.user, self.secret)).encode()).decode()

    def own(self, url):
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != self.scheme or parts.netloc.lower() != self.host:
            raise Refuse("a URL leaves the registry's origin")

    def send(self, method, url, body=None, headers=None):
        """one request under the total deadline: (status, lower-cased headers, body)"""
        outcome = {}

        def work():
            try:
                outcome["result"] = self.send_once(method, url, body, headers)
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

    def send_once(self, method, url, body, headers):
        headers = dict(headers or {})
        if self.bearer:
            headers["Authorization"] = "Bearer " + self.bearer
        elif self.basic:
            headers["Authorization"] = self.basic_header()
        request = urllib.request.Request(url, data=body, method=method, headers=headers)
        try:
            response = self.opener.open(request, timeout=self.timeout)
            return response.status, lowered(response.headers), response.read()
        except urllib.error.HTTPError as err:
            if 300 <= err.code < 400:
                raise Refuse("the registry answered %d: redirects are never followed" % err.code)
            return err.code, lowered(err.headers), err.read()

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

    def request(self, method, path, body=None, headers=None):
        url = path if path.startswith("http") else "%s://%s%s" % (self.scheme, self.host, path)
        self.own(url)
        status, response, data = self.send(method, url, body, headers)
        if status == 401 and not self.bearer and not self.basic:
            challenge = response.get("www-authenticate", "")
            if challenge.lower().startswith("bearer"):
                self.token(challenge)
                status, response, data = self.send(method, url, body, headers)
            elif challenge.lower().startswith("basic") and self.user and self.secret:
                self.basic = True
                status, response, data = self.send(method, url, body, headers)
        return status, response, data


def lowered(headers):
    return {key.lower(): value for key, value in headers.items()}


# ---------------------------------------------------------------- push
def load_dir(directory):
    if os.path.islink(directory) or not os.path.isdir(directory):
        raise Refuse("DIR is not a directory")
    index_bytes = read_file(os.path.join(directory, "index.json"))
    result = load_json(read_file(os.path.join(directory, "result.json")), "result.json", limits=False)
    if not isinstance(result, dict) or digest_of(index_bytes) != result.get("final_digest"):
        raise Refuse("index.json does not match the final_digest in result.json")
    if not isinstance(result.get("base_digest"), str) or not DIGEST.fullmatch(result["base_digest"]):
        raise Refuse("result.json: base_digest is not a digest")
    return index_bytes, result


def check_dir_contents(directory, needed):
    """DIR holds exactly index.json, result.json and the blobs the attestations need: nothing else"""
    allowed = {"index.json", "result.json"} | {"blobs/sha256/" + hex_of(digest) for digest in needed}
    for base, directories, files in os.walk(directory):
        for name in directories:
            path = os.path.join(base, name)
            relative = os.path.relpath(path, directory)
            if os.path.islink(path) or relative not in ("blobs", "blobs/sha256"):
                raise Refuse("an unexpected entry in DIR: %s" % relative)
        for name in files:
            path = os.path.join(base, name)
            relative = os.path.relpath(path, directory)
            if os.path.islink(path) or relative not in allowed:
                raise Refuse("an unexpected file in DIR: %s" % relative)


def request_timeout():
    text = os.environ.get("FSCACHE_REGISTRY_TIMEOUT", str(DEFAULT_TIMEOUT))
    try:
        seconds = float(text)
    except ValueError:
        seconds = float("nan")
    if not math.isfinite(seconds) or seconds <= 0:
        raise Refuse("FSCACHE_REGISTRY_TIMEOUT must be a positive number of seconds")
    return seconds


def command_push(args):
    if not REPOSITORY.fullmatch(args.repository):
        raise Refuse("the repository name is not a valid distribution name")
    timeout = request_timeout()
    # everything about DIR is decided before the first request
    index_bytes, result = load_dir(args.dir)
    if args.base_digest and args.base_digest != result["base_digest"]:
        raise Refuse("--base-digest does not match result.json")

    def reader(digest, size):
        path = blob_path(os.path.join(args.dir, "blobs"), digest)
        if os.path.islink(path) or not os.path.isfile(path):
            raise Refuse("a blob is missing locally: %s" % digest)
        data = read_file(path)
        if digest_of(data) != digest or (size is not None and len(data) != size):
            raise Refuse("a local blob does not match its digest or size: %s" % digest)
        return data
    final, attestations, needed = check_final(index_bytes, reader, None, [digest_of(index_bytes), result["base_digest"]])
    check_dir_contents(args.dir, needed)
    manifests, blobs = [], []
    for entry in attestations:
        manifest_bytes = reader(entry["digest"], None)
        manifests.append((entry["digest"], manifest_bytes))
        manifest = json.loads(manifest_bytes)
        for part in [manifest["config"]] + manifest["layers"]:
            if part["digest"] not in [digest for digest, _ in blobs]:
                blobs.append((part["digest"], reader(part["digest"], None)))
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
        location = urllib.parse.urljoin("%s://%s/v2/%s/blobs/uploads/" % (registry.scheme, registry.host, name), response["location"])
        registry.own(location)
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
    status, response, data = registry.request("GET", "/v2/%s/manifests/%s" % (name, final_digest), None, manifest_headers)
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
    verify_parser.add_argument("--base", help="the built index file")
    verify_parser.add_argument("--blobs", help="the blobs directory written by compute (holds sha256/<hex>)")
    push_parser = commands.add_parser(
        "push", help="push a computed DIR to a registry, by digest only",
        epilog="Environment: FSCACHE_REGISTRY_USER and FSCACHE_REGISTRY_TOKEN are the registry credentials. "
               "FSCACHE_REGISTRY_TIMEOUT is the total deadline in seconds for each request (default %d)." % DEFAULT_TIMEOUT)
    push_parser.add_argument("--registry", required=True, help="a bare host[:port]; http only for localhost")
    push_parser.add_argument("--repository", required=True)
    push_parser.add_argument("--dir", required=True)
    push_parser.add_argument("--base-digest")
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
