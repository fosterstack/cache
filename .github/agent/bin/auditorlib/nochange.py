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
from datetime import date

from auditorlib import policy

SCHEMA = "fosterstack/auditor-state/v1"
MAX_BYTES = 1 << 20
MAX_NARRATIVE = 20000
MAX_FIELD = 2000
CATEGORIES = ("false_positive", "not_affected_unreachable", "real_fixable", "risk_acceptance", "under_investigation")
SETTLED = ("false_positive", "not_affected_unreachable", "real_fixable", "risk_acceptance")      # the model gave a disposition; anything else is unsettled
HOLDS = ("policy-held", "upstream-held")
PULL_KEYS = ("pullable", "lift_trigger", "hold", "component_fixed", "candidate_release", "bump_attempted", "bump_result",
             "repo_version", "base_release", "evidence")
STATE_KEYS = {"schema", "run_date", "finding_set_hash", "verdicts", "pullability", "narrative", "unsettled"}
UNSETTLED_MAX = 5000
FINDING_ID = policy.FINDING_ID
HEX64 = re.compile(r"[0-9a-f]{64}")
DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
RUNS_MAX = 1000


def _calendar(s):
    """a real calendar date written YYYY-MM-DD"""
    try:
        date.fromisoformat(s)
    except ValueError:
        return False
    return True


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


def _text(v):
    return v is None or (isinstance(v, str) and len(v) <= MAX_FIELD)


def _flag(v):
    return v is None or isinstance(v, bool)


def _evidence(v):
    if _text(v):
        return True
    return (isinstance(v, dict) and len(v) <= 20 and all(isinstance(k, str) and len(k) <= 100 for k in v)
            and all(x is None or isinstance(x, (bool, int)) or (isinstance(x, str) and len(x) <= MAX_FIELD) for x in v.values()))


PULL_CHECKS = {"pullable": _flag, "bump_attempted": _flag, "hold": lambda v: v in (None,) + HOLDS, "evidence": _evidence,
               "lift_trigger": _evidence, "component_fixed": _text, "candidate_release": _text, "bump_result": _text,
               "repo_version": _text, "base_release": _text}


def valid_pull(d):
    """a pullability record the router can read without error: every key a known one, each of its own type, hold one of the
    two supported holds"""
    return isinstance(d, dict) and set(d) <= set(PULL_CHECKS) and all(PULL_CHECKS[k](v) for k, v in d.items())


class CounterInvalid(ValueError):
    """the unsettled-run counts in a state file that IS present cannot be trusted: the run stops (never resets the counts to zero)"""


def _valid_unsettled(u, today=None):
    if not isinstance(u, dict) or len(u) > UNSETTLED_MAX:
        return False
    for k, d in u.items():
        if not (isinstance(k, str) and FINDING_ID.fullmatch(k) and isinstance(d, dict) and set(d) == {"runs", "last"}):
            return False
        r = d["runs"]
        if not (isinstance(r, int) and not isinstance(r, bool) and 1 <= r <= RUNS_MAX):
            return False
        if not (isinstance(d["last"], str) and DATE.fullmatch(d["last"]) and _calendar(d["last"]) and (today is None or d["last"] <= today)):
            return False
    return True


def _valid(doc):
    if not isinstance(doc, dict) or set(doc) != STATE_KEYS or doc["schema"] != SCHEMA:
        return False
    if not (isinstance(doc["finding_set_hash"], str) and HEX64.fullmatch(doc["finding_set_hash"])):
        return False
    if not (isinstance(doc["run_date"], str) and DATE.fullmatch(doc["run_date"]) and _calendar(doc["run_date"])):
        return False
    v = doc["verdicts"]
    if not isinstance(v, dict) or not all(HEX64.fullmatch(k) and c in CATEGORIES for k, c in v.items()):
        return False
    p = doc["pullability"]
    if not isinstance(p, dict):
        return False
    for k, d in p.items():
        if not (HEX64.fullmatch(k) and valid_pull(d)):
            return False
    if not _valid_unsettled(doc["unsettled"]):
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
    """the pullability answer as it is kept: only the keys the router reads. An answer that cannot be kept whole and valid is
    not kept at all (None): a lossy record would route differently on reuse than the fresh answer did."""
    rec = {k: ans[k] for k in PULL_KEYS if k in ans}
    return rec if valid_pull(rec) else None


def settle(verdicts, pull, narr, incomplete):
    """what a run may leave for tomorrow. A run where any attempted model call ended without a cacheable result (a refusal, an error,
    an answer outside the five categories or one the router cannot read, a token-budget stop, a narrative that was empty or
    disagreed with the record) is incomplete: it leaves nothing reusable, so the next run repeats its calls instead of treating a
    partial state as 'nothing to ask' (REQ-AUD-3 AC3, zero calls only on a complete state)."""
    return ({}, {}, None) if incomplete else (verdicts, pull, narr)


def dump(today, fs_hash, verdicts, pull, narr, unsettled=None):
    return {"schema": SCHEMA, "run_date": today, "finding_set_hash": fs_hash, "verdicts": dict(verdicts),
            "pullability": {k: dict(v) for k, v in pull.items()}, "narrative": narr,
            "unsettled": {k: dict(v) for k, v in (unsettled or {}).items()}}


def load_unsettled(path, today):
    """The per-finding count of consecutive runs left unsettled (REQ-AUD-9 AC3, "a five-iteration stop"), from the carrier of the no-change day's state.
    ("missing", {}) when there is no usable state: no file (the first run, or the artifact expired), a file that is not an auditor state at all (not JSON, another schema, not a
    regular file, too large: REQ-AUD-3 AC3 ignores such a file) or a state written before the counts existed. The counts restart and the run says so.
    ("ok", counts) for a valid file. Raises CounterInvalid for a state that IS an auditor state (right schema) whose counts cannot be trusted (malformed, a date that is not a
    calendar date, or a date after `today`): the caller stops the run, before any model call or mutating call."""
    if not path or not os.path.lexists(path):
        return "missing", {}
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode):
            return "missing", {}
        with open(path, "rb") as fh:
            raw = fh.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            return "missing", {}
        doc = json.loads(raw.decode("utf-8"), parse_constant=lambda name: (_ for _ in ()).throw(ValueError(name)))
    except (OSError, ValueError):
        return "missing", {}
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        return "missing", {}
    if set(doc) == STATE_KEYS - {"unsettled"}:
        return "missing", {}
    if set(doc) != STATE_KEYS or not _valid(dict(doc, unsettled={})):
        return "missing", {}                      # not a state the no-change day would accept either: its counts are not trusted or carried, they restart
    if doc["run_date"] > today:
        raise CounterInvalid("the state is dated after today")
    if not _valid_unsettled(doc["unsettled"], today):
        raise CounterInvalid("the unsettled-run counts are malformed")
    return "ok", doc["unsettled"]


def advance(prev, now_ids, today):
    """today's counts: a finding unsettled today is one more than its previous count (the same day again counts once); a finding not unsettled today is dropped, so
    its count restarts. A count never passes RUNS_MAX (saturates). The previous counts were checked by load_unsettled (no date after today)."""
    out = {}
    for fid in sorted(now_ids):
        p = prev.get(fid)
        if p is None:
            runs = 1
        elif p["last"] == today:
            runs = p["runs"]
        else:
            runs = min(p["runs"] + 1, RUNS_MAX)
        out[fid] = {"runs": runs, "last": today}
    if len(out) > UNSETTLED_MAX:
        raise CounterInvalid("more than %d unsettled findings" % UNSETTLED_MAX)
    return out


def at_limit(counts, limit):
    """[(finding, runs)] for the findings unsettled for at least `limit` consecutive runs, sorted by finding id"""
    return sorted((k, v["runs"]) for k, v in counts.items() if v["runs"] >= limit)
