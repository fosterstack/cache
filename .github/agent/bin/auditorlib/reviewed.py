"""The one reader of the reviewed and run-written JSON inputs (rc-5b fix 13; Fable ruling of cache#701).

A PRESENT file must be a JSON object that carries its required key(s) with the right shape: {} , a null list and a missing key are a stop (ReviewedInputInvalid), never "nothing":
an empty file read as "no statements", "no removals" or "no defects" would delete every statement, keep every expired acceptance or trust an empty history. An ABSENT file is the first
run (None). Which keys a file must carry is the table below, by file name; the readers in auditor-run.py, auditor-release-authz.py, auditor-consistency.py, auditor-classify.py and
auditor-knowledge.py all read through `read`, and test_reviewed_inputs.py checks every json file name the agent programs mention against the table."""
import json
import os


class ReviewedInputInvalid(Exception):
    """A reviewed file (the published VEX, the accepted-items inventory, the reopened-expired ledger, the consistency result, the known-defect log) is present but unreadable or not the
    JSON object it must be: the run stops (exit 3) rather than guess an empty one, which would delete every statement or renew every time box (REQ-AUD-13 AC3/AC6, REQ-AUD-2 AC5c)."""


# (key, kind): kind objects = a list of JSON objects, lists = a list of lists (a row), bool = a JSON true/false
_OPENVEX = (("statements", "objects"),)
_TABLE = {
    "accepted-items.json": (("accepted_items", "objects"),),
    "reopened-expired.json": (("reopened", "lists"),),
    "consistency.json": (("problems", "objects"), ("consistent", "bool")),
    "known-defect-log.json": (("defects", "objects"),),
}


def spec_for(name):
    """The required keys of the file called `name` (its basename): () for a file this reader has no rule for."""
    base = os.path.basename(name)
    if base.endswith(".openvex.json"):
        return _OPENVEX
    return _TABLE.get(base, ())


def _shaped(value, kind):
    if isinstance(kind, tuple):
        tag, arg = kind
        if tag == "int":                              # exactly this integer (a schema version); True is not 1
            return type(value) is int and value == arg
        if tag == "choice":
            return isinstance(value, str) and value in arg
        return isinstance(value, dict) and set(value) == set(arg) and all(type(v) is int for v in value.values())      # "ints": integers of any sign (a wrong vote costs points)
    if kind == "bool":
        return isinstance(value, bool)
    return isinstance(value, list) and all(isinstance(x, dict if kind == "objects" else list) for x in value)


def _expected(kind):
    if isinstance(kind, tuple):
        tag, arg = kind
        if tag == "int":
            return "the integer %s" % arg
        if tag == "choice":
            return "one of %s" % ", ".join(arg)
        return "an object with the integers %s" % ", ".join(arg)
    return {"bool": "true or false", "objects": "a list of objects"}.get(kind, "a list of rows")


def check(doc, path, as_name=None, spec=None):
    """doc (already a JSON object) against the rules of the file's name (or of `as_name`), or against an explicit `spec` ((key, kind) pairs: the scanner panel brings the rules of
    its own files, so this library never names them); raises ReviewedInputInvalid."""
    for key, kind in (spec if spec is not None else spec_for(as_name or path)):
        if key not in doc or not _shaped(doc[key], kind):
            raise ReviewedInputInvalid("%s: %r is missing or is not %s" % (path, key, _expected(kind)))
    return doc


def present(path):
    """True when the file exists (lstat: a dangling symlink and a file in an unreachable folder are PRESENT), False when it is absent (the first run); any other failure to look is a stop."""
    try:
        os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError as ex:
        raise ReviewedInputInvalid("%s cannot be looked at (%s)" % (path, type(ex).__name__))
    return True


def parse(data, label, as_name=None):
    """The same rules for a document already in hand (the bytes of a git object read with `git show`, or text): decoded
    as UTF-8, then the parsed JSON object carrying its required keys,
    or ReviewedInputInvalid. `label` names it in the stop."""
    try:
        doc = json.loads(data.decode("utf-8") if isinstance(data, (bytes, bytearray)) else data)
    except (ValueError, UnicodeError) as ex:
        raise ReviewedInputInvalid("%s cannot be read as JSON (%s)" % (label, type(ex).__name__))
    if not isinstance(doc, dict):
        raise ReviewedInputInvalid("%s is not a JSON object" % label)
    return check(doc, label, as_name)


def read(path, as_name=None, spec=None):
    """The parsed JSON object of a reviewed file, or None when the file does not exist (the first run). Anything else that is not a readable JSON object carrying its required keys
    is a stop. `as_name` reads a file under the rules of another name (the release gate's per-finding VEX files)."""
    if not present(path):
        return None                                # absent (the first run); any other failure to look (EACCES on a parent, EIO) is a stop, not "missing"
    try:
        with open(path) as f:
            doc = json.load(f)
    except (OSError, ValueError, UnicodeError) as ex:
        raise ReviewedInputInvalid("%s is present but cannot be read as JSON (%s)" % (path, type(ex).__name__))
    if not isinstance(doc, dict):
        raise ReviewedInputInvalid("%s is not a JSON object" % path)
    return check(doc, path, as_name, spec)
