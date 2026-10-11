#!/usr/bin/env python3
"""REQ-AUD-18 AC3: every change under .github/agent/ clears the independent second review's
stop rule before merge — enforced as a check, not a habit.

A pull request whose change touches .github/agent/ must carry a REVIEW RECORD at
.github/agent/reviews/<tree>.json, where <tree> is the sha256 of the exact .github/agent/
content under review (every tracked path, mode and blob id, plus the allowlist guard's own files
listed in GUARDED; the review records themselves —
reviews/<64-hex>.json — excluded, and nothing else). The
content is what is bound: any later change to the auditor — a fix commit, or a rebase that
brings in other auditor changes — changes <tree>, the old record no longer matches, and the
check fails until the review loop's confirmation round is recorded for the new content.

A record is read as strict JSON (load_record): UTF-8 without a byte order mark, at most MAX_RECORD_BYTES, one value
and nothing after it, nested at most MAX_DEPTH deep, no repeated key at any level (an ordinary reader keeps the last of two equal keys, so an
earlier substitute, blocker or stop verdict would vanish before judging), no NaN or Infinity. Anything else fails, saying
which. Reading takes time linear in the record's size (the depth is counted by one pass that skips strings).

Every diagnostic is plain ASCII and bounded: a value from the record is shown by _show (a string escaped and cut to
SHOW_CHARS, a list or object by its kind and size, never rendered), at most MAX_PROBLEMS problems are kept and the rest
counted, every line is written ASCII-escaped, and a failure to judge is a named refusal (exit 1), never a pass.

A record clears the gate (REQ-AUD-018 AC5, AC6) when its schema is auditor-review-record/v2, it binds <tree>, and
it holds only the permitted fields at every level: the record RECORD_REQUIRED (+ RECORD_OPTIONAL), every round
ROUND_REQUIRED with round numbers positive and increasing, and every seat entry exactly FIELDS.
Its FINAL round's reviewers hold exactly two entries, codex_a and codex_b, and nothing else: each an object with
exactly the fields reviewer (codex), vendor (openai), seat (A or B, matching its key), model and effort (each on the
gate's own lists below), blockers_open (exactly the integer 0) and evidence_sha256 (64 lowercase hex: the sha256 of
that seat's raw output, kept in the private audit tree). The two seats name two different models (SAME_MODEL
below says which list entries count as one model); the two evidence hashes differ; the stop block holds exactly
codex_a clear and codex_b clear. An earlier round holds one or both seats, each with the same fields and values
except that blockers_open may be any non-negative integer. Every missing, extra, mistyped or malformed field fails
with a message naming it. The record is an attestation by the agent that ran the loop (owner decision, option C,
Sep 27): the gate checks its shape, never that a review ran or which model ran; the evidence hash lets a holder of
the raw output check its header.

No substitute (AC4): an entry under any other key in any round, any field outside the permitted sets (whatever its
name: allowlist_entry, exception, waiver, change, label, ...), and any key or string value anywhere in the record that
contains "substitut" (any case) fails, naming it and saying no substitute is accepted. The record holds no free text
that could name an allow-list entry: every string field is an exact value from the gate's lists or a fixed hex form,
except residuals, whose strings must be plain descriptive text (_plain_problem: the characters of _PLAIN, at most
RESIDUAL_CHARS, no run of 4 or more digits and no run of 7 or more hex characters holding a digit, so no entry id,
commit or hash); anything else fails, naming it and saying no substitute is accepted. The gate reads no allow-list and no
clock and no environment; an outage of the reviewer leaves the change waiting for both reviews.

Records merged before the schema v2 gate (AC7): the identity check comes first: when the PR's diff does not add, change
or remove the record path and the same regular-file blob is at that path on the trusted revision, the merge base
(--base) and the PR head, the TRUSTED revision's copy is read (never the head's bytes before that check). A strictly
read schema v2 copy is judged by AC5; an old-schema copy is read as the old gate read it (an ordinary JSON reader: a
repeated key or NaN in a merged file is history) and is not re-judged by any rule; a copy whose schema cannot be told,
or that claims schema v2 without being strict JSON, fails closed. Otherwise the head's record is read strictly, and a
record that is not schema v2 fails. Every record file the PR adds or changes, whether or not
the PR changes anything else, must be a strictly read schema v2 record, so a PR (a record-only one included) can
never introduce an old-schema record. What this proves: the old record was on the default branch before this PR and
this PR did not touch it. What it does not prove: how it got there; a record merged before this gate, or merged by
anyone past the gate, is history and is not re-judged. A trusted revision that cannot be read fails closed.

It runs from .github/workflows/agent-review-gate.yml on pull_request_target (AC8): the workflow checks
out the BASE branch — so this file is always main's copy, never the PR's — fetches the PR head as
git objects only (never checked out, never executed), reads the record with `git show`, and runs this script
with `python3 -I` (isolated: no script directory on sys.path, no PYTHON* env).

  --base REV       the base to diff against (the merge base of the PR with its base branch); a commit
  --head REV       the reviewed commit (the PR head); default HEAD; a commit (anything else is refused, exit 2)
  --print-tree     print <tree> for --head and exit (used to name the record)
  --pr N           the pull request's number (checked to be a positive integer; it changes no verdict)
  --subs-rev REV   the TRUSTED revision, a default-branch commit, for AC7 (default: --base). The workflow passes
                   the checked-out default branch; nothing of the PR is read from it.
"""
import hashlib, json, re, subprocess, sys

AGENT = ".github/agent/"
REVIEWS = AGENT + "reviews/"
# The allowlist guard's own files live outside .github/agent/ but are review-gated like it: the
# guard decides what a public-repo PR may contain, so changing it needs the same independent review.
# (ci.yml is NOT listed: its allowlist job is judged by this gate's workflow from main's copies.)
GUARDED = ("bin/check-file-allowlist.sh", "bin/check-file-allowlist-test.sh",
           ".github/workflows/agent-review-gate.yml")
SCHEMA = "auditor-review-record/v2"
SEATS = {"codex_a": "A", "codex_b": "B"}
# The permitted fields (AC5): nothing else is read, and anything else fails.
RECORD_REQUIRED = ("schema", "tree", "rounds", "stop")
RECORD_OPTIONAL = ("reviewed_commit", "residuals")      # no free-text change or label: nothing reads them (AC4)
ROUND_REQUIRED = ("round", "reviewers")
ROUND_OPTIONAL = ()
FIELDS = ("reviewer", "vendor", "seat", "model", "effort", "blockers_open", "evidence_sha256")
MAX_RECORD_BYTES = 1 << 20
MAX_DEPTH = 16      # a permitted record nests 5 deep; the depth is counted before parsing, so no depth can raise
# The gate's own lists (AC5). SAME_MODEL maps a model to the one it counts as when the two seats are compared.
CODEX_MODELS = ("gpt-6-luna", "gpt-6-sol", "gpt-6.1-sol", "gpt-6-astra")
SAME_MODEL = {"gpt-6.1-sol": "gpt-6-sol"}
EFFORTS = ("medium", "high", "xhigh")
NO_SUBSTITUTE = "no substitute is accepted"
PERMITTED_ONLY = "only the permitted fields are read, and " + NO_SUBSTITUTE
V2_REQUIRED = "a schema v2 record is required"
_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX40 = re.compile(r"[0-9a-f]{40}")
_SUBSTITUTE = re.compile(r"substitut", re.I)
# residuals: plain descriptive text only (AC4): these characters, no digit run of 4+, no 7+ hex run holding a digit
_PLAIN = re.compile(r"[A-Za-z0-9 .,;:!?'\"()/_+=%&*<>-]*")
_DIGITS4 = re.compile(r"[0-9]{4}")
_HEXRUN = re.compile(r"[0-9A-Fa-f]{7,}")
RESIDUAL_CHARS = 1000
SHOW_CHARS = 80
MAX_PROBLEMS = 100
_KEY = re.compile(r"[A-Za-z0-9_-]{1,64}")


def _show(v):
    """A record value as plain ASCII of bounded length, without recursion: a string escaped and cut to SHOW_CHARS, a
    list or an object by its kind and size, an integer of more than 64 bits by its size."""
    if isinstance(v, str):
        return ascii(v[:SHOW_CHARS]) + ("... (%d characters)" % len(v) if len(v) > SHOW_CHARS else "")
    if isinstance(v, list):
        return "<a list of length %d>" % len(v)
    if isinstance(v, dict):
        return "<an object with %d field(s)>" % len(v)
    if isinstance(v, int) and not isinstance(v, bool) and v.bit_length() > 64:
        return "<an integer of %d bits>" % v.bit_length()
    return ascii(v)


def _key(k):
    """A record key for a field path: as is when it is a short plain name, else shown by _show."""
    return k if _KEY.fullmatch(k) else _show(k)


class _Problems(list):
    """The problems of one record: at most MAX_PROBLEMS are kept, the rest counted, so no record can grow its own
    diagnostics. done() is the list to report."""
    def __init__(self, ps=()):
        super().__init__()
        self.more = 0
        self.extend(ps)

    def append(self, p):
        if len(self) < MAX_PROBLEMS:
            super().append(p)
        else:
            self.more += 1

    def extend(self, ps):
        for p in ps:
            self.append(p)

    def __iadd__(self, ps):
        self.extend(ps)
        return self

    def done(self):
        return list(self) + (["... and %d more problem(s) not shown" % self.more] if self.more else [])


def _git(*a, raw=False):
    r = subprocess.run(["git", *a], capture_output=True)
    if r.returncode != 0:
        raise RuntimeError("git %s: %s" % (" ".join(a), r.stderr.decode("utf-8", "replace").strip()))
    return r.stdout if raw else r.stdout.decode("utf-8", "surrogateescape")


_RECORD = re.compile(re.escape(REVIEWS) + r"[0-9a-f]{64}\.json")


def _is_record(path):
    """Only a review record itself is outside the reviewed content — any other file under
    reviews/ is an ordinary auditor change (round-1 review: the directory is not a free zone)."""
    return bool(_RECORD.fullmatch(path))


def tree_hash(head):
    # -z: NUL-delimited, unquoted paths (a quoted non-ASCII name cannot slip past _is_record)
    lines = [ln for ln in _git("ls-tree", "-r", "-z", "--full-tree", head, "--", AGENT, *GUARDED).split("\0")
             if ln and not _is_record(ln.split("\t", 1)[-1])]
    return hashlib.sha256(("\n".join(lines) + "\n").encode()).hexdigest()


def auditor_changes(base, head):
    # --no-renames: a rename out of .github/agent/ must show its OLD path too, never only the new.
    return [p for p in _git("diff", "--no-renames", "--name-only", "-z", base, head, "--").split("\0")
            if (p.startswith(AGENT) or p in GUARDED) and not _is_record(p)]


def _dupless(pairs):
    keys = set()
    for k, _ in pairs:
        if k in keys:
            raise ValueError("the record repeats the key %s" % _show(k))
        keys.add(k)
    return dict(pairs)


def _no_constant(c):
    raise ValueError("the record holds the non-standard constant %s" % c)


def _depth(text):
    """The deepest nesting of brackets and braces in `text` outside JSON strings: one pass, linear in its length."""
    depth = deepest = 0
    in_str = esc = False
    for ch in text:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "[{":
            depth += 1
            deepest = max(deepest, depth)
        elif ch in "]}":
            depth -= 1
    return deepest


def load_record(raw):
    """The record in the bytes `raw`, read as strict JSON; raises ValueError saying why it cannot be read."""
    if len(raw) > MAX_RECORD_BYTES:
        raise ValueError("the record is larger than %d bytes" % MAX_RECORD_BYTES)
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ValueError("the record starts with a byte order mark")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("the record is not UTF-8") from None
    if _depth(text) > MAX_DEPTH:
        raise ValueError("the record nests too deeply to read (more than %d levels)" % MAX_DEPTH)
    try:
        return json.loads(text, object_pairs_hook=_dupless, parse_constant=_no_constant)
    except json.JSONDecodeError as e:
        raise ValueError("the record is not valid JSON (%s)" % e) from None


def _path(frame):
    """The field path of a walk frame (parent frame, path component), built only when a problem names it."""
    parts = []
    while frame is not None:
        frame, part = frame
        parts.append(part)
    return "".join(reversed(parts))


def _substitute_marks(v, where):
    """Every key and string value anywhere under `v` that marks or names a substitute (AC4), walked without
    recursion so that no depth can raise; a field path is shared by its children, never copied per element."""
    stack = [(v, (None, where))]
    while stack:
        x, frame = stack.pop()
        if isinstance(x, dict):
            for k, y in x.items():
                child = (frame, "." + _key(k))
                if _SUBSTITUTE.search(k):
                    yield "record field %s marks a substitute: %s" % (_path(child), NO_SUBSTITUTE)
                stack.append((y, child))
        elif isinstance(x, list):
            stack.extend((y, (frame, "[%d]" % i)) for i, y in enumerate(x))
        elif isinstance(x, str) and _SUBSTITUTE.search(x):
            yield "record field %s names a substitute (%s): %s" % (_path(frame), _show(x), NO_SUBSTITUTE)


def _plain_problem(where, s):
    """Why the residual string `s` is not plain descriptive text (AC4), or None when it is (the caller has checked
    that residuals is a list of strings)."""
    if len(s) > RESIDUAL_CHARS or not _PLAIN.fullmatch(s) or _DIGITS4.search(s) or any(
            any(c.isdigit() for c in m.group()) for m in _HEXRUN.finditer(s)):
        return ("%s %s is not plain descriptive text (letters, digits, spaces and . , ; : ! ? ' \" ( ) / _ + = %% & * "
                "< > -, at most %d characters, no run of 4 or more digits and no run of 7 or more hex characters "
                "holding a digit, so no entry id, commit or hash): %s" % (where, _show(s), RESIDUAL_CHARS, NO_SUBSTITUTE))
    return None


def _extras(where, obj, permitted):
    """An 'extra field' problem for every key of `obj` outside `permitted` (a key marking a substitute is already
    named by _substitute_marks)."""
    return ("%s has an extra field %s: %s" % (where, _show(k), PERMITTED_ONLY)
            for k in obj if k not in permitted and not _SUBSTITUTE.search(k))


def _seat_problems(name, r, final=True):
    """Every reason the seat entry `name` (codex_a or codex_b, prefixed with its round when not final) is not a
    clear review (AC5, AC6). In an earlier round, blockers_open may be any non-negative integer."""
    key = name.rsplit(".", 1)[-1]
    if not isinstance(r, dict):
        return ["%s entry is not an object (%s)" % (name, _show(r))]
    probs = _Problems("%s has no %s field" % (name, f) for f in FIELDS if f not in r)
    probs += _extras(name, r, FIELDS)
    if "reviewer" in r and r["reviewer"] != "codex":
        probs.append("%s reviewer is %s, want 'codex'" % (name, _show(r["reviewer"])))
    if "vendor" in r and r["vendor"] != "openai":
        probs.append("%s vendor is %s, want 'openai'" % (name, _show(r["vendor"])))
    if "seat" in r and r["seat"] != SEATS[key]:
        probs.append("%s seat is %s, want %r" % (name, _show(r["seat"]), SEATS[key]))
    if "model" in r and (not isinstance(r["model"], str) or r["model"] not in CODEX_MODELS):
        probs.append("%s model %s is not on the gate's list of Codex models" % (name, _show(r["model"])))
    if "effort" in r and (not isinstance(r["effort"], str) or r["effort"] not in EFFORTS):
        probs.append("%s effort %s is not on the gate's list of efforts" % (name, _show(r["effort"])))
    b = r.get("blockers_open", 0)
    if final and (type(b) is not int or b != 0):      # exactly the integer 0: not False, not 0.0
        probs.append("%s blockers_open is %s, want the integer 0" % (name, _show(b)))
    if not final and (type(b) is not int or b < 0):
        probs.append("%s blockers_open is %s, want a non-negative integer" % (name, _show(b)))
    if "evidence_sha256" in r and not (isinstance(r["evidence_sha256"], str) and _HEX64.fullmatch(r["evidence_sha256"])):
        probs.append("%s evidence_sha256 is not 64 lowercase hex characters" % name)
    return probs.done()


def _rounds_problems(rounds, probs):
    """Adds to `probs` the problems of the fields of every round (AC5): round (a positive integer, greater than the
    round before), reviewers, nothing else; and of every seat entry of every round but the final one (judged in
    record_problems)."""
    last = None
    for i, rd in enumerate(rounds):
        at = "rounds[%d]" % i
        if not isinstance(rd, dict):
            if i < len(rounds) - 1:      # a final round that is not an object is "final round names no reviewers"
                probs.append("%s is not an object" % at)
            continue
        probs += _extras(at, rd, ROUND_REQUIRED + ROUND_OPTIONAL)
        n = rd.get("round")
        if "round" not in rd:
            probs.append("%s has no round field" % at)
        elif type(n) is not int or n < 1:
            probs.append("%s round is %s, want a positive integer" % (at, _show(n)))
        else:
            if last is not None and n <= last:
                probs.append("%s round %d does not follow round %d" % (at, n, last))
            last = n
        if i == len(rounds) - 1:
            continue
        rv = rd.get("reviewers")
        if not isinstance(rv, dict) or not rv:
            probs.append("%s reviewers is not a non-empty object" % at)
            continue
        for k, entry in rv.items():
            if k not in SEATS:
                probs.append("%s entry %s is not a seat (only codex_a and codex_b take a seat): %s" % (at, _show(k), NO_SUBSTITUTE))
            else:
                probs += _seat_problems("%s.%s" % (at, k), entry, final=False)


def record_problems(rec, tree):
    """Every reason the schema v2 record `rec` does not clear the gate for content `tree` (empty = clears)."""
    if not isinstance(rec, dict):
        return ["record is not a JSON object"]
    probs = _Problems(_substitute_marks(rec, "record"))
    probs += _extras("record", rec, RECORD_REQUIRED + RECORD_OPTIONAL)
    if rec.get("schema") != SCHEMA:
        probs.append("schema is %s, not %s: %s" % (_show(rec.get("schema")), SCHEMA, V2_REQUIRED))
    if rec.get("tree") != tree:
        t = rec.get("tree")
        probs.append("record binds tree %s, the change is %s" % (
            t if isinstance(t, str) and _HEX64.fullmatch(t) else _show(t), tree))
    if "reviewed_commit" in rec and not (isinstance(rec["reviewed_commit"], str) and _HEX40.fullmatch(rec["reviewed_commit"])):
        probs.append("record reviewed_commit is not 40 lowercase hex characters")
    if "residuals" in rec and not (isinstance(rec["residuals"], list) and all(isinstance(x, str) for x in rec["residuals"])):
        probs.append("record residuals is not a list of strings")
    elif "residuals" in rec:
        probs += (p for p in (_plain_problem("record residuals[%d]" % i, x) for i, x in enumerate(rec["residuals"])) if p)
    rounds = rec.get("rounds")
    if not isinstance(rounds, list) or not rounds:
        probs.append("no review rounds recorded")
        return probs.done()
    _rounds_problems(rounds, probs)
    final = rounds[-1].get("reviewers") if isinstance(rounds[-1], dict) else None
    if not isinstance(final, dict):
        probs.append("final round names no reviewers")
        return probs.done()
    probs += ("final round entry %s is not a seat (only codex_a and codex_b take a seat): %s" % (_show(k), NO_SUBSTITUTE)
              for k in final if k not in SEATS)
    for name in SEATS:
        if name not in final:
            probs.append("final round has no %s entry" % name)
        else:
            probs += _seat_problems(name, final[name])
    a, b = final.get("codex_a"), final.get("codex_b")
    if isinstance(a, dict) and isinstance(b, dict):
        ma, mb = a.get("model"), b.get("model")      # compared only as strings: no value is compared deeply
        if isinstance(ma, str) and isinstance(mb, str) and ma in CODEX_MODELS and mb in CODEX_MODELS \
                and SAME_MODEL.get(ma, ma) == SAME_MODEL.get(mb, mb):
            probs.append("codex_a and codex_b name the same model (%s and %s): the two seats run two different models" % (ma, mb))
        ea, eb = a.get("evidence_sha256"), b.get("evidence_sha256")
        if isinstance(ea, str) and isinstance(eb, str) and ea == eb:
            probs.append("codex_a and codex_b have the same evidence_sha256: a copied entry is not an independent review")
    stop = rec.get("stop")
    if not isinstance(stop, dict):
        probs.append("stop is missing or not an object")
        return probs.done()
    probs += ("stop holds an extra key %s: %s" % (_show(k), PERMITTED_ONLY) for k in stop if k not in SEATS and not _SUBSTITUTE.search(k))
    for name in SEATS:
        if stop.get(name) != "clear":
            probs.append("stop verdict for %s is %s, want 'clear'" % (name, _show(stop.get(name))))
    return probs.done()


def _blob(rev, path):
    """The blob id of `path` at `rev`, or None when the revision has no such file. A revision that is not a readable
    commit raises RuntimeError (the caller fails closed); so does one that git could read as an option."""
    if rev.startswith("-"):
        raise RuntimeError("not a revision")
    _git("rev-parse", "--verify", "--quiet", "%s^{commit}" % rev)
    out = _git("ls-tree", "-z", rev, "--", path).split("\0")[0]
    meta = out.split("\t", 1)[0].split()      # mode type id: a regular file only (never a link or a submodule)
    return meta[2] if len(meta) == 3 and meta[1] == "blob" and meta[0] in ("100644", "100755") else None


class _Pairs(list):
    """A JSON object read as the old gate read it, kept as its (key, value) pairs (repeated keys included)."""


def _merged_blob(base, head, trusted, path, touched):
    """AC7, the identity check, made before any byte of the record is read: the blob id at `path` on the trusted
    revision when the PR's diff does not touch `path` (`touched`: the record paths it adds, changes or removes) and the
    same regular-file blob is there on the trusted revision, the merge base `base` and the PR head; else None. Raises
    RuntimeError when the trusted revision cannot be read. This proves the file was on the default branch before this
    PR and the PR did not touch it; it does not prove how the file got there (history, not re-judged; every record a PR
    adds or changes must be schema v2, see added_record_problems)."""
    want = _blob(trusted, path)
    if path in touched or want is None:
        return None
    return want if want == _blob(base, path) == _blob(head, path) else None


def classify_merged(raw):
    """AC7: the merged file's bytes `raw` (read from the trusted revision) as ("v2", record) when they are a strictly
    read schema v2 record (judged by AC5); ("old", None) when they are an old-schema record as the old gate read it (an
    ordinary JSON reader: a repeated key or NaN is history), never re-judged; ("refused", why) when the schema cannot
    be told, or the file claims schema v2 without being strict JSON (fail closed)."""
    try:
        rec = load_record(raw)
    except ValueError as e:
        strict = str(e)
    else:
        return ("v2", rec) if isinstance(rec, dict) and rec.get("schema") == SCHEMA else ("old", None)
    try:
        if len(raw) > MAX_RECORD_BYTES or _depth(raw.decode("utf-8")) > MAX_DEPTH:
            raise ValueError
        top = json.loads(raw.decode("utf-8"), object_pairs_hook=_Pairs)
    except ValueError:      # not UTF-8, too large or deep, or not JSON at all (a decode error is a ValueError)
        return "refused", "it cannot be read (%s), so its schema cannot be told: %s" % (strict, V2_REQUIRED)
    if isinstance(top, _Pairs) and any(k == "schema" and v == SCHEMA for k, v in top):
        return "refused", ("it claims schema v2 but is not strict JSON (%s): a schema v2 record is read as strict JSON, "
                           "and %s" % (strict, V2_REQUIRED))
    return "old", None


def touched_records(base, head):
    """Every review-record path the PR's diff adds, changes or removes, as {path: still present at head}."""
    out = _git("diff", "--no-renames", "--name-status", "-z", base, head, "--", REVIEWS).split("\0")
    pairs = zip(out[0::2], out[1::2])
    return {p: st != "D" for st, p in pairs if _is_record(p)}


def _read_record(head, path):
    """The record at `path` on `head`, strictly read; RuntimeError when it is not a regular file there, ValueError
    when it cannot be read as strict JSON."""
    b = _blob(head, path)
    if b is None:
        raise RuntimeError("not a regular file at %s" % head)
    return load_record(_git("cat-file", "blob", b, raw=True))


def added_record_problems(head, touched, skip):
    """AC7: every record the PR adds or changes (except `skip`, the head's own record, judged on its own) must be a
    strictly read schema v2 record, even when the PR changes nothing else: no PR can introduce an old-schema record."""
    probs = []
    for path in sorted(p for p, present in touched.items() if present and p != skip):
        try:
            rec = _read_record(head, path)
        except (RuntimeError, ValueError) as e:
            probs.append((path, "record %s is added or changed by this pull request and cannot be read (%s): %s"
                          % (path, str(e).splitlines()[0], V2_REQUIRED)))
            continue
        if not (isinstance(rec, dict) and rec.get("schema") == SCHEMA):
            probs.append((path, "record %s is added or changed by this pull request and its schema is %s, not %s: %s"
                          % (path, _show(rec.get("schema") if isinstance(rec, dict) else None), SCHEMA, V2_REQUIRED)))
    return probs


def _say(line, err=False):
    """Write one line ASCII-escaped: no record value or path can make the output raise."""
    print(line.encode("ascii", "backslashreplace").decode("ascii"), file=sys.stderr if err else sys.stdout)


def _is_commit(rev):
    """True when `rev` names a commit git can read (never one git could read as an option)."""
    if not rev or rev.startswith("-"):
        return False
    try:
        _git("rev-parse", "--verify", "--quiet", "%s^{commit}" % rev)
    except RuntimeError:
        return False
    return True


def main(argv):
    """The gate (see the module text); a failure to judge is a named refusal, exit 1, never a pass."""
    try:
        return _main(argv)
    except Exception as e:      # any failure to judge (git, memory, an unforeseen value) refuses, naming it
        _say("::error::review gate: the change could not be judged (%s: %s): it does not clear (REQ-AUD-18 AC3)"
             % (type(e).__name__, _show((str(e).splitlines() or [""])[0])))
        return 1


def _main(argv):
    def opt(k, d=None):
        if k not in argv:
            return d
        i = argv.index(k) + 1
        return argv[i] if i < len(argv) else None      # a flag without a value is missing
    head = opt("--head", "HEAD")
    if not _is_commit(head):
        _say("::error::auditor-review-gate: --head %s is not a commit the gate can read" % _show(head), err=True)
        return 2
    tree = tree_hash(head)
    if "--print-tree" in argv:
        _say(tree)
        return 0
    if "--pr" in argv:      # accepted because the workflow passes it; it changes no verdict
        raw = opt("--pr")
        if raw is None or not re.fullmatch(r"[1-9][0-9]*", raw):
            _say("::error::auditor-review-gate: --pr must be a positive integer", err=True)
            return 2
    base = opt("--base")
    if not base:
        _say("::error::auditor-review-gate: --base is required", err=True)
        return 2
    if not _is_commit(base):
        _say("::error::auditor-review-gate: --base %s is not a commit the gate can read" % _show(base), err=True)
        return 2
    trusted = base
    if "--subs-rev" in argv:
        trusted = opt("--subs-rev")
        if not trusted:
            _say("::error::auditor-review-gate: --subs-rev needs the trusted revision", err=True)
            return 2
    changed = auditor_changes(base, head)
    path = REVIEWS + tree + ".json"
    touched = touched_records(base, head)
    added = added_record_problems(head, touched, path if changed else None)
    for where, p in added:
        _say("::error file=%s::review gate: %s (REQ-AUD-18 AC7)" % (where, p))
    if not changed:
        if added:
            return 1
        _say("review gate: no change under %s: nothing to clear" % AGENT)
        return 0
    try:
        merged, unreadable = _merged_blob(base, head, trusted, path, touched), None
    except RuntimeError as e:
        merged, unreadable = None, (str(e).splitlines() or ["git"])[0]
    if merged:      # the identity check passed: read the TRUSTED revision's copy (by its blob id), never the head's
        kind, got = classify_merged(_git("cat-file", "blob", merged, raw=True))
        if kind == "old" and not added:
            _say("review gate: %d auditor path(s) changed; %s is the old-schema record already at the merge base "
                 "and on the trusted revision %s (the same file, unchanged): honoured as merged, not re-judged"
                 % (len(changed), path, _show(trusted)))
            return 0
        rec = got
        probs = record_problems(rec, tree) if kind == "v2" else [] if kind == "old" else [
            "record %s is the merged file (the same at the merge base and on the trusted revision %s) but %s"
            % (path, _show(trusted), got)]
    else:
        try:
            rec = _read_record(head, path)
        except (RuntimeError, ValueError) as e:
            why = (str(e).splitlines() or [type(e).__name__])[0]
            _say("::error::review gate: %d auditor path(s) changed (e.g. %s) but no valid review "
                 "record at %s (%s). Run both Codex reviews (seat A and seat B, two different models) on this exact "
                 "content and commit its record (REQ-AUD-18 AC3)." % (len(changed), changed[0], path, why))
            return 1
        if isinstance(rec, dict) and rec.get("schema") == SCHEMA:
            probs = record_problems(rec, tree)
        elif unreadable is not None:
            probs = ["the trusted revision %s cannot be read (%s): an old-schema record cannot be honoured"
                     % (_show(trusted), unreadable)]
        else:
            probs = ["record %s has schema %s and is not the same file, unchanged by this pull request, at the merge "
                     "base %s and on the trusted revision %s: %s" % (
                         path, _show(rec.get("schema") if isinstance(rec, dict) else None), base, _show(trusted),
                         V2_REQUIRED)]
    for p in probs:
        _say("::error file=%s::review gate: %s (REQ-AUD-18 AC3)" % (path, p))
    if probs or added:
        return 1
    _say("review gate: %d auditor path(s) changed; %s clears the stop rule (%d round(s))"
         % (len(changed), path, len(rec["rounds"])))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
