"""No-change day (REQ-AUD-3 AC3): reuse yesterday's model verdicts only when nothing a verdict depends on changed.

The daily run keeps a small state file (the artifact `auditor-state`): the finding-set hash, each model verdict keyed by a
hash of the exact context the model was given, and the narrative with the hash of the structured record it was written for.
A run reads yesterday's file only through load(), which returns None for anything unusable, and only uses it through
matching(), which answers only an EXACT finding-set hash match. A missing, malformed, oversized, forged or different-hash
file therefore changes nothing: the run behaves as it always did (model calls). Nothing here decides a disposition; the
deterministic checks after a verdict (evidence verification, reachability, expiry, carried statements) run on a reused
verdict exactly as on a fresh one.
"""
import hashlib
import json
import os
import re
import stat

SCHEMA = "fosterstack/auditor-state/v1"
MAX_BYTES = 1 << 20
MAX_NARRATIVE = 20000
MAX_FIELD = 2000
CATEGORIES = ("false_positive", "not_affected_unreachable", "real_fixable", "risk_acceptance", "under_investigation")
PULL_KEYS = ("pullable", "lift_trigger", "hold", "component_fixed", "candidate_release", "bump_attempted", "bump_result",
             "repo_version", "base_release", "evidence")
STATE_KEYS = {"schema", "run_date", "finding_set_hash", "verdicts", "pullability", "narrative"}
HEX64 = re.compile(r"[0-9a-f]{64}")
DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


def _digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")).hexdigest()


def finding_set_hash(groups, context):
    """sha256 over everything a verdict depends on: every group's aliases and every finding record (all fields, any
    order), plus `context` (the image, the knowledge document, reachability facts and the like)."""
    body = {c: {"aliases": sorted(g["aliases"]),
                "findings": sorted(json.dumps(f, sort_keys=True, default=str) for f in g["findings"])}
            for c, g in groups.items()}
    return _digest({"groups": body, "context": context})


def call_key(kind, ctx):
    """the key of one model call: its kind and the exact context the model is given"""
    return _digest([kind, ctx])


def _scalar(v):
    return v is None or isinstance(v, (bool, int)) or (isinstance(v, str) and len(v) <= MAX_FIELD)


def _valid(doc):
    if not isinstance(doc, dict) or set(doc) != STATE_KEYS or doc["schema"] != SCHEMA:
        return False
    if not (isinstance(doc["finding_set_hash"], str) and HEX64.fullmatch(doc["finding_set_hash"])):
        return False
    if not (isinstance(doc["run_date"], str) and DATE.fullmatch(doc["run_date"])):
        return False
    v = doc["verdicts"]
    if not isinstance(v, dict) or not all(HEX64.fullmatch(k) and c in CATEGORIES for k, c in v.items()):
        return False
    p = doc["pullability"]
    if not isinstance(p, dict):
        return False
    for k, d in p.items():
        if not (HEX64.fullmatch(k) and isinstance(d, dict) and set(d) <= set(PULL_KEYS) and all(_scalar(x) for x in d.values())):
            return False
    n = doc["narrative"]
    if n is None:
        return True
    return (isinstance(n, dict) and set(n) == {"key", "text", "date"} and isinstance(n["key"], str) and bool(HEX64.fullmatch(n["key"]))
            and isinstance(n["text"], str) and 0 < len(n["text"]) <= MAX_NARRATIVE
            and isinstance(n["date"], str) and bool(DATE.fullmatch(n["date"])))


def load(path):
    """yesterday's state, or None for anything unusable (never raises)"""
    if not path:
        return None
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode):
            return None
        with open(path, "rb") as fh:
            raw = fh.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            return None
        doc = json.loads(raw.decode("utf-8"), parse_constant=lambda name: (_ for _ in ()).throw(ValueError(name)))
    except (OSError, ValueError):
        return None
    return doc if _valid(doc) else None


def matching(state, fs_hash):
    """the state when it was written for exactly this finding set, else None"""
    return state if state is not None and state["finding_set_hash"] == fs_hash else None


def verdict(state, key):
    return None if state is None else state["verdicts"].get(key)


def pullability(state, key):
    d = None if state is None else state["pullability"].get(key)
    return None if d is None else dict(d)


def narrative(state, key):
    n = None if state is None else state["narrative"]
    return (n["text"], n["date"]) if n is not None and n["key"] == key else None


def pull_record(ans):
    """the part of a pullability answer worth keeping: only the keys the router reads, only plain short values"""
    return {k: ans[k] for k in PULL_KEYS if k in ans and _scalar(ans[k])}


def dump(today, fs_hash, verdicts, pull, narr):
    return {"schema": SCHEMA, "run_date": today, "finding_set_hash": fs_hash, "verdicts": dict(verdicts),
            "pullability": {k: dict(v) for k, v in pull.items()}, "narrative": narr}
