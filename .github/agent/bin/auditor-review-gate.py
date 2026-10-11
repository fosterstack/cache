#!/usr/bin/env python3
"""REQ-AUD-18 AC3: every change under .github/agent/ clears the independent second review's
stop rule before merge — enforced as a check, not a habit.

A pull request whose change touches .github/agent/ must carry a REVIEW RECORD at
.github/agent/reviews/<tree>.json, where <tree> is the sha256 of the exact .github/agent/
content under review (every tracked path, mode and blob id, plus the allowlist guard's own files
listed in GUARDED; the review records themselves —
reviews/<64-hex>.json — excluded, and nothing else). The serialization is unambiguous (round 3): TREE_PREFIX, then
every `git ls-tree -r -z` entry ("mode type id<TAB>path", its raw bytes) followed by one NUL. No entry can hold a NUL (git
refuses a NUL in a path; mode, type and id never hold one), so splitting the hashed bytes after the prefix at each NUL
gives back exactly the entry list: two different listings never share hashed bytes, and two different contents share
<tree> only through a sha256 collision. TREE_PREFIX holds a NUL and no legacy serialization does, so no legacy hashed
bytes equal these either. The
content is what is bound: any later change to the auditor — a fix commit, or a rebase that
brings in other auditor changes — changes <tree>, the old record no longer matches, and the
check fails until the review loop's confirmation round is recorded for the new content.

A record is read as strict JSON (load_record): UTF-8 without a byte order mark, at most MAX_RECORD_BYTES, one value
and nothing after it, nested at most MAX_DEPTH deep, no repeated key at any level (an ordinary reader keeps the last of two equal keys, so an
earlier substitute, blocker or stop verdict would vanish before judging), no NaN or Infinity. Anything else fails, saying
which; so does a number token longer than MAX_NUMBER_CHARS, refused before it is converted (a long decimal takes time
out of proportion to its length on the oldest supported Python). Reading takes time linear in the record's size (the
depth is counted by one pass that skips strings).

Every diagnostic is plain ASCII and bounded: a value from the record and a path from the change are shown by _show (a
string escaped, then cut to SHOW_CHARS written characters, a list or object by its kind and size, never rendered, an
integer of more than 64 bits by its size), at most MAX_PROBLEMS problems are written in all (every added record and the
record under judgement together, every problem of a seat entry added to the one shared count; past that, the rest are
counted exactly and no further added record is read), every line is
written with every control character and every non-ASCII character escaped (one line, never a forged second one) and
then cut to SAY_CHARS (the bound applies after escaping, which writes one character as up to ten), and a failure to
judge is a named refusal (exit 1), never a pass.

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
name: allowlist_entry, exception, waiver, change, label, residuals, ...), and any key or string value anywhere in the
record that contains "substitut" (any case) fails, naming it and saying no substitute is accepted. So does every other
refusal of a key or a value the gate does not permit (round 5): a former allow-list id or a model alias in any string
field, a value of the wrong type, a record that is not an object, an old-schema record; the statement is written by the
one helper _no_substitute. Only a missing field or seat, an integer out of range and a relation between permitted values
(the same model, the same evidence, round order, a well-formed tree that is another tree) are stated plainly. The record holds no
free text at all (round 3: no pattern on free text tells an entry id from a word): every string field is an exact value
from the gate's lists (schema, reviewer, vendor, seat, model, effort, the stop verdicts) or a fixed hex form (tree,
reviewed_commit, evidence_sha256), and every key is from a closed set. Residuals live in the pull request body and the
outbox, never in the record. The gate reads no allow-list and no clock and no environment; an outage of the reviewer
leaves the change waiting for both reviews.

Records merged before the schema v2 gate (AC7): every one is named by the LEGACY tree hash (legacy_tree_hash: the same
entries joined with newlines, as the old gate hashed them), so it keeps clearing exactly the content it cleared. The
legacy hash is computed only to find such a record, and only for a tree no hashed path of which holds a control
character or a byte that is not UTF-8 (otherwise there is no legacy name and no old record can clear it): with no
newline in any entry, splitting the legacy bytes at each newline gives back exactly the entry list, so the legacy hash is
unambiguous over the trees it names. The record at the <tree> path comes first: when the head holds a file there, it is
the record judged (a schema v2 record by AC5; an old-schema file at a <tree> path fails, an old-schema record being
named by the legacy hash). Only when the head holds nothing at the <tree> path is the legacy path looked at. At either
path the head's entry is told three ways apart (round 4): a regular file, nothing, or a non-regular object (a symbolic
link, a submodule entry, a directory); a non-regular object at either path fails closed, naming the path, and one at
the <tree> path fails before any legacy record is looked at, so it is never taken for an absent record. At either
path the identity check comes first: when the PR's diff does not add, change or remove the record path and the same
regular-file blob is at that path on the trusted revision, the merge base (--base) and the PR head, the TRUSTED
revision's copy is read (never the head's bytes before that check). At the <tree> path a strictly read schema v2 copy
is judged by AC5; at the legacy path an old-schema copy is read as the old gate read it (an ordinary JSON reader: a
repeated key or NaN in a merged file is history) and is not re-judged by any rule; a copy whose schema cannot be told,
or that claims schema v2 without being strict JSON, or a schema v2 copy at the legacy path, fails closed. A legacy-path
file that fails the identity check fails; with no file at either path, the change has no record and fails. A head record
at the <tree> path that is not a merged file is read strictly, and fails unless it is schema v2. Every record file
the PR adds or changes, whether or not the PR changes anything else, is judged as the selected record is (round 4): a
regular file, read strictly, of schema v2, that clears by AC5 for the tree its own file name names; so a PR (a
record-only one included) can never introduce an old-schema record, a record with a missing or extra field, or a
substitute. What this proves: the old record was on the default branch before this PR and this PR did not touch it. What it does not prove: how it got there; a record merged before this gate, or merged by
anyone past the gate, is history and is not re-judged. A trusted revision that is not a readable commit is refused
before anything is judged (exit 2), whatever the record.

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
RECORD_OPTIONAL = ("reviewed_commit",)      # no free text (change, label, residuals): nothing reads them (AC4)
ROUND_REQUIRED = ("round", "reviewers")
ROUND_OPTIONAL = ()
FIELDS = ("reviewer", "vendor", "seat", "model", "effort", "blockers_open", "evidence_sha256")
MAX_RECORD_BYTES = 1 << 20
MAX_DEPTH = 16      # a permitted record nests 5 deep; the depth is counted before parsing, so no depth can raise
MAX_NUMBER_CHARS = 20      # every 64-bit integer fits; a longer number token is refused before it is converted
TREE_PREFIX = b"auditor-tree/v2\0"      # the hashed bytes' version; it holds a NUL, so no legacy hashed bytes equal them
# The gate's own lists (AC5). SAME_MODEL maps a model to the one it counts as when the two seats are compared.
CODEX_MODELS = ("gpt-6-luna", "gpt-6-sol", "gpt-6.1-sol", "gpt-6-astra")
SAME_MODEL = {"gpt-6.1-sol": "gpt-6-sol"}
EFFORTS = ("medium", "high", "xhigh")
NO_SUBSTITUTE = "no substitute is accepted"      # read only by _no_substitute (round 5: no refusal spells its own)
PERMITTED = "only the permitted fields are read, and "      # a reason given to _no_substitute
V2_REQUIRED = "a schema v2 record is required, and "        # a reason given to _no_substitute
_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX40 = re.compile(r"[0-9a-f]{40}")
_SUBSTITUTE = re.compile(r"substitut", re.I)
SHOW_CHARS = 80
SAY_CHARS = 2000
MAX_PROBLEMS = 100
_KEY = re.compile(r"[A-Za-z0-9_-]{1,64}")


def _show(v):
    """A record value as plain ASCII of bounded length, without recursion: a string escaped, then cut to SHOW_CHARS
    written characters (round 4: an escape writes one character as up to ten, so the bound applies after escaping; only
    the first SHOW_CHARS characters are ever escaped), a list or an object by its kind and size, an integer of more
    than 64 bits by its size."""
    if isinstance(v, str):
        shown = ascii(v[:SHOW_CHARS])
        cut = len(v) > SHOW_CHARS or len(shown) > SHOW_CHARS + 2      # + 2: the quotes ascii() adds
        return shown[:SHOW_CHARS] + "... (%d characters)" % len(v) if cut else shown
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


def _no_substitute(line, why=""):
    """The one place a refusal says that no substitute is accepted (AC4, round 5): `line` names the key or value refused,
    `why` (PERMITTED or V2_REQUIRED, each ending ", and ") what else holds; the statement always ends the refusal."""
    return "%s: %s%s" % (line, why, NO_SUBSTITUTE)


class _Problems(list):
    """The problems of one record: at most MAX_PROBLEMS are kept, the rest counted, so no record can grow its own
    diagnostics. done() is the list to report."""
    def __init__(self, ps=()):
        super().__init__()
        self.more = 0
        self.unread = 0      # added records not read once MAX_PROBLEMS problems are kept (the command line only)
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
_RECORD_B = re.compile(re.escape(REVIEWS.encode()) + rb"[0-9a-f]{64}\.json")
_CONTROL_B = re.compile(rb"[\x00-\x1f\x7f]")


def _is_record(path):
    """Only a review record itself is outside the reviewed content — any other file under
    reviews/ is an ordinary auditor change (round-1 review: the directory is not a free zone)."""
    return bool(_RECORD.fullmatch(path))


def _entries(head):
    """The hashed entries of `head`, each the raw bytes "mode type id<TAB>path" of one `git ls-tree -r -z` line (-z:
    NUL-delimited, unquoted paths, so a quoted name cannot slip past the record test); review records excluded."""
    out = _git("ls-tree", "-r", "-z", "--full-tree", head, "--", AGENT, *GUARDED, raw=True)
    return [e for e in out.split(b"\0") if e and not _RECORD_B.fullmatch(e.split(b"\t", 1)[-1])]


def tree_hash(head):
    """<tree>: the sha256 of TREE_PREFIX and every entry followed by a NUL (unambiguous: no entry holds a NUL)."""
    return hashlib.sha256(TREE_PREFIX + b"".join(e + b"\0" for e in _entries(head))).hexdigest()


def legacy_tree_hash(head):
    """The tree hash the gate computed before schema v2 (the entries joined with newlines), which names every record
    merged before it (AC7); None when a hashed path holds a control character or a byte that is not UTF-8. Read only to
    find such a record: without a newline in any entry the newline-joined bytes give back exactly the entry list."""
    lines = []
    for e in _entries(head):
        if _CONTROL_B.search(e.split(b"\t", 1)[-1]):      # the path (the TAB before it is the entry's own separator)
            return None
        try:
            lines.append(e.decode("utf-8"))
        except UnicodeDecodeError:
            return None
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


def _number(convert):
    """A JSON number reader that refuses a token longer than MAX_NUMBER_CHARS before converting it."""
    def read(token):
        if len(token) > MAX_NUMBER_CHARS:
            raise ValueError("the record holds a number longer than %d characters" % MAX_NUMBER_CHARS)
        return convert(token)
    return read


_INT, _FLOAT = _number(int), _number(float)


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
        return json.loads(text, object_pairs_hook=_dupless, parse_constant=_no_constant, parse_int=_INT,
                          parse_float=_FLOAT)
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
                    yield _no_substitute("record field %s marks a substitute" % _path(child))
                stack.append((y, child))
        elif isinstance(x, list):
            stack.extend((y, (frame, "[%d]" % i)) for i, y in enumerate(x))
        elif isinstance(x, str) and _SUBSTITUTE.search(x):
            yield _no_substitute("record field %s names a substitute (%s)" % (_path(frame), _show(x)))


def _extras(where, obj, permitted):
    """An 'extra field' problem for every key of `obj` outside `permitted` (a key marking a substitute is already
    named by _substitute_marks)."""
    return (_no_substitute("%s has an extra field %s" % (where, _show(k)), PERMITTED)
            for k in obj if k not in permitted and not _SUBSTITUTE.search(k))


def _seat_problems(name, r, probs, final=True):
    """Adds to `probs` (the record's one bounded list, so every problem is counted once, round 5) every reason the seat
    entry `name` (codex_a or codex_b, prefixed with its round when not final) is not a clear review (AC5, AC6). In an
    earlier round, blockers_open may be any non-negative integer."""
    key = name.rsplit(".", 1)[-1]
    if not isinstance(r, dict):
        probs.append(_no_substitute("%s entry is not an object (%s)" % (name, _show(r))))
        return
    probs += ("%s has no %s field" % (name, f) for f in FIELDS if f not in r)
    probs += _extras(name, r, FIELDS)
    for f, want in (("reviewer", "codex"), ("vendor", "openai"), ("seat", SEATS[key])):
        if f in r and r[f] != want:
            probs.append(_no_substitute("%s %s is %s, want %r" % (name, f, _show(r[f]), want)))
    if "model" in r and (not isinstance(r["model"], str) or r["model"] not in CODEX_MODELS):
        probs.append(_no_substitute("%s model %s is not on the gate's list of Codex models" % (name, _show(r["model"]))))
    if "effort" in r and (not isinstance(r["effort"], str) or r["effort"] not in EFFORTS):
        probs.append(_no_substitute("%s effort %s is not on the gate's list of efforts" % (name, _show(r["effort"]))))
    b = r.get("blockers_open", 0)
    line = "%s blockers_open is %s, want %s" % (name, _show(b), "the integer 0" if final else "a non-negative integer")
    if type(b) is not int:      # exactly an integer: not False, not 0.0, not a string
        probs.append(_no_substitute(line))
    elif (b != 0) if final else (b < 0):      # an integer out of range is stated plainly
        probs.append(line)
    if "evidence_sha256" in r and not (isinstance(r["evidence_sha256"], str) and _HEX64.fullmatch(r["evidence_sha256"])):
        probs.append(_no_substitute("%s evidence_sha256 is not 64 lowercase hex characters" % name))


def _rounds_problems(rounds, probs):
    """Adds to `probs` the problems of the fields of every round (AC5): round (a positive integer, greater than the
    round before), reviewers, nothing else; and of every seat entry of every round but the final one (judged in
    record_problems)."""
    last = None
    for i, rd in enumerate(rounds):
        at = "rounds[%d]" % i
        if not isinstance(rd, dict):
            if i < len(rounds) - 1:      # a final round that is not an object is "final round names no reviewers"
                probs.append(_no_substitute("%s is not an object" % at))
            continue
        probs += _extras(at, rd, ROUND_REQUIRED + ROUND_OPTIONAL)
        n = rd.get("round")
        if "round" not in rd:
            probs.append("%s has no round field" % at)
        elif type(n) is not int:
            probs.append(_no_substitute("%s round is %s, want a positive integer" % (at, _show(n))))
        elif n < 1:
            probs.append("%s round is %s, want a positive integer" % (at, _show(n)))
        else:
            if last is not None and n <= last:
                probs.append("%s round %s does not follow round %s" % (at, _show(n), _show(last)))
            last = n
        if i == len(rounds) - 1:
            continue
        rv = rd.get("reviewers")
        if not isinstance(rv, dict) or not rv:
            line = "%s reviewers is not a non-empty object" % at
            probs.append(_no_substitute(line) if "reviewers" in rd else line)
            continue
        for k, entry in rv.items():
            if k not in SEATS:
                probs.append(_no_substitute("%s entry %s is not a seat (only codex_a and codex_b take a seat)" % (at, _show(k))))
            else:
                _seat_problems("%s.%s" % (at, k), entry, probs, final=False)


def record_problems(rec, tree):
    """Every reason the schema v2 record `rec` does not clear the gate for content `tree` (empty = clears)."""
    return _judge(rec, tree).done()


def _judge(rec, tree):
    """record_problems as the bounded _Problems itself (its count of problems not kept included)."""
    if not isinstance(rec, dict):
        return _Problems([_no_substitute("record is not a JSON object")])
    probs = _Problems(_substitute_marks(rec, "record"))
    probs += _extras("record", rec, RECORD_REQUIRED + RECORD_OPTIONAL)
    if rec.get("schema") != SCHEMA:
        probs.append(_no_substitute("schema is %s, not %s" % (_show(rec.get("schema")), SCHEMA), V2_REQUIRED))
    if rec.get("tree") != tree:
        t = rec.get("tree")
        hex64 = isinstance(t, str) and _HEX64.fullmatch(t)
        line = "record binds tree %s, the change is %s" % (t if hex64 else _show(t), tree)
        probs.append(line if hex64 or "tree" not in rec else _no_substitute(line))      # another tree, or none: plainly
    if "reviewed_commit" in rec and not (isinstance(rec["reviewed_commit"], str) and _HEX40.fullmatch(rec["reviewed_commit"])):
        probs.append(_no_substitute("record reviewed_commit is not 40 lowercase hex characters"))
    rounds = rec.get("rounds")
    if not isinstance(rounds, list) or not rounds:
        probs.append(_no_substitute("no review rounds recorded") if "rounds" in rec else "no review rounds recorded")
        return probs
    _rounds_problems(rounds, probs)
    final = rounds[-1].get("reviewers") if isinstance(rounds[-1], dict) else None
    if not isinstance(final, dict):
        absent = isinstance(rounds[-1], dict) and "reviewers" not in rounds[-1]      # a missing field: plainly
        probs.append("final round names no reviewers" if absent else _no_substitute("final round names no reviewers"))
        return probs
    probs += (_no_substitute("final round entry %s is not a seat (only codex_a and codex_b take a seat)" % _show(k))
              for k in final if k not in SEATS)
    for name in SEATS:
        if name not in final:
            probs.append("final round has no %s entry" % name)
        else:
            _seat_problems(name, final[name], probs)
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
        probs.append(_no_substitute("stop is missing or not an object") if "stop" in rec else "stop is missing or not an object")
        return probs
    probs += (_no_substitute("stop holds an extra key %s" % _show(k), PERMITTED)
              for k in stop if k not in SEATS and not _SUBSTITUTE.search(k))
    for name in SEATS:
        if stop.get(name) != "clear":
            line = "stop verdict for %s is %s, want 'clear'" % (name, _show(stop.get(name)))
            probs.append(_no_substitute(line) if name in stop else line)
    return probs


NOT_REGULAR = type("NotRegular", (), {"__repr__": lambda self: "NOT_REGULAR"})()      # see _blob


def _blob(rev, path):
    """What `rev` holds at `path`, three ways apart (round 4): the blob id of a regular file; None when it holds nothing
    there; NOT_REGULAR when it holds something else (a symbolic link, a submodule entry, a directory), which every
    caller refuses and never takes for an absent file. Every `rev` is one _main has checked to be a readable commit
    (never one git could read as an option); a git failure raises RuntimeError (refused)."""
    out = _git("ls-tree", "-z", rev, "--", path).split("\0")[0]
    if not out:
        return None
    meta = out.split("\t", 1)[0].split()      # mode type id
    return meta[2] if len(meta) == 3 and meta[1] == "blob" and meta[0] in ("100644", "100755") else NOT_REGULAR


NON_REGULAR = "a symbolic link, a submodule entry or a directory, not a regular file: it fails closed"


class _Pairs(list):
    """A JSON object read as the old gate read it, kept as its (key, value) pairs (repeated keys included)."""


def _merged_blob(base, head, trusted, path, touched):
    """AC7, the identity check, made before any byte of the record is read: the blob id at `path` on the trusted
    revision when the PR's diff does not touch `path` (`touched`: the record paths it adds, changes or removes) and the
    same regular-file blob is there on the trusted revision, the merge base `base` and the PR head; else None (the three
    revisions are commits _main has checked). This proves the file was on the default branch before this
    PR and the PR did not touch it; it does not prove how the file got there (history, not re-judged; every record a PR
    adds or changes must be schema v2, see added_record_problems)."""
    want = _blob(trusted, path)
    if path in touched or want is None or want is NOT_REGULAR:
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
        top = json.loads(raw.decode("utf-8"), object_pairs_hook=_Pairs, parse_int=_INT, parse_float=_FLOAT)
    except ValueError:      # not UTF-8, too large or deep, a number too long, or not JSON (a decode error is one)
        return "refused", _no_substitute("it cannot be read (%s), so its schema cannot be told" % strict, V2_REQUIRED)
    if isinstance(top, _Pairs) and any(k == "schema" and v == SCHEMA for k, v in top):
        return "refused", _no_substitute("it claims schema v2 but is not strict JSON (%s); a schema v2 record is read as "
                                         "strict JSON" % strict, V2_REQUIRED)
    return "old", None


def touched_records(base, head):
    """Every review-record path the PR's diff adds, changes or removes, as {path: still present at head}."""
    out = _git("diff", "--no-renames", "--name-status", "-z", base, head, "--", REVIEWS).split("\0")
    pairs = zip(out[0::2], out[1::2])
    return {p: st != "D" for st, p in pairs if _is_record(p)}


def _read_record(head, path):
    """The record at `path` on `head`, strictly read; RuntimeError when there is no regular file there, ValueError
    when it cannot be read as strict JSON."""
    b = _blob(head, path)
    if b is None or b is NOT_REGULAR:
        raise RuntimeError("%s at %s" % ("no file" if b is None else NON_REGULAR, _show(head)))
    return load_record(_git("cat-file", "blob", b, raw=True))


def _tree_named(path):
    """The tree hash a record path names (reviews/<tree>.json)."""
    return path[len(REVIEWS):-len(".json")]


def added_record_problems(head, touched, skip, probs):
    """AC4, AC5, AC7: every record the PR adds or changes (except `skip`, the head's own record, judged on its own) is
    judged as the selected record is, even when the PR changes nothing else (round 4): it must be a regular file, read
    strictly, of schema v2, and clear by _judge for the tree its own file name names; so no PR can introduce an
    old-schema record, a record with a missing or extra field, or a substitute. Adds to `probs` its failing lines;
    once `probs` holds MAX_PROBLEMS, the rest are counted, and no further record is read."""
    for path in sorted(p for p, present in touched.items() if present and p != skip):
        if len(probs) >= MAX_PROBLEMS:
            probs.unread += 1
            continue
        at = "::error file=%s::review gate: record %s is added or changed by this pull request and " % (path, path)
        try:
            rec = _read_record(head, path)
        except (RuntimeError, ValueError) as e:
            why = "cannot be read (%s)" % (str(e).splitlines() or [type(e).__name__])[0]
        else:
            if isinstance(rec, dict) and rec.get("schema") == SCHEMA:
                judged = _judge(rec, _tree_named(path))
                probs.extend(at + "does not clear: %s (REQ-AUD-18 AC4, AC5)" % p for p in judged)
                probs.more += judged.more
                continue
            why = "its schema is %s, not %s" % (_show(rec.get("schema") if isinstance(rec, dict) else None), SCHEMA)
        probs.append(at + _no_substitute(why, V2_REQUIRED) + " (REQ-AUD-18 AC7)")


_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_NAMED = {"\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _say(line, err=False):
    """Write one line of plain ASCII: every control character escaped (so no value or path can start a second line or an
    escape sequence) and every non-ASCII character escaped (so nothing can make the output raise), THEN cut to
    SAY_CHARS (round 4: an escape writes one character as up to ten, so the bound applies to the escaped line)."""
    line = _CONTROL.sub(lambda m: _NAMED.get(m.group(), "\\x%02x" % ord(m.group())), line)
    line = line.encode("ascii", "backslashreplace").decode("ascii")
    if len(line) > SAY_CHARS:
        line = line[:SAY_CHARS] + "... (%d characters)" % len(line)
    print(line, file=sys.stderr if err else sys.stdout)


def _emit(report):
    """Write every kept problem line of `report`, and one line counting the rest; returns 1 (the change does not clear)."""
    for line in report:
        _say(line)
    if report.more or report.unread:
        _say("::error::review gate: ... and %d more problem(s) not shown%s" % (report.more, (
            "; %d more added record(s) not read (the gate stops reading at %d problems)" % (report.unread, MAX_PROBLEMS)
            if report.unread else "")))
    return 1


def _no_record(report, changed, path, why):
    """The change has no valid record at `path`: one more problem line, then everything is written; returns 1."""
    report.append("::error::review gate: %d auditor path(s) changed (e.g. %s) but no valid review record at %s (%s). Run "
                  "both Codex reviews (seat A and seat B, two different models) on this exact content and commit its "
                  "record (REQ-AUD-18 AC3)." % (len(changed), _show(changed[0]), path, why))
    return _emit(report)


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
    trusted = opt("--subs-rev") if "--subs-rev" in argv else base
    if not _is_commit(trusted):      # refused before anything is judged, whatever the record (AC7: fails closed)
        _say("::error::auditor-review-gate: --subs-rev %s is not a commit the gate can read" % _show(trusted), err=True)
        return 2
    changed = auditor_changes(base, head)
    path = REVIEWS + tree + ".json"
    touched = touched_records(base, head)
    report = _Problems()      # every problem line written, bounded in all
    added_record_problems(head, touched, path if changed else None, report)
    if not changed:
        if report:
            return _emit(report)
        _say("review gate: no change under %s: nothing to clear" % AGENT)
        return 0
    rec, where, probs = None, path, []
    here = _blob(head, path)
    if here is NOT_REGULAR:      # refused before any legacy record is looked at (AC7: never taken for an absent file)
        return _no_record(report, changed, path, NON_REGULAR)
    merged = _merged_blob(base, head, trusted, path, touched)
    if merged:      # the identity check passed: read the TRUSTED revision's copy (by its blob id), never the head's
        kind, got = classify_merged(_git("cat-file", "blob", merged, raw=True))
        if kind == "v2":
            rec = got
        else:
            probs = ["record %s is the merged file (the same at the merge base and on the trusted revision %s) but %s"
                     % (path, _show(trusted), got if kind == "refused" else _no_substitute(
                         "it is an old-schema record at the path the tree hash names (an old-schema record is named by "
                         "the legacy tree hash)", V2_REQUIRED))]
    elif here is None:      # nothing at the tree's path: an old record merged for this content?
        legacy = legacy_tree_hash(head)
        where = REVIEWS + legacy + ".json" if legacy else path
        old = _merged_blob(base, head, trusted, where, touched) if legacy else None
        if old:
            kind, got = classify_merged(_git("cat-file", "blob", old, raw=True))
            if kind == "old" and not report:
                _say("review gate: %d auditor path(s) changed; %s is the old-schema record already at the merge base "
                     "and on the trusted revision %s (the same file, unchanged): honoured as merged, not re-judged"
                     % (len(changed), where, _show(trusted)))
                return 0
            probs = [] if kind == "old" else [
                "record %s is the merged file (the same at the merge base and on the trusted revision %s) but %s" % (
                    where, _show(trusted), got if kind == "refused" else _no_substitute(
                        "it is a schema v2 record at the path the legacy tree hash names (a schema v2 record is named "
                        "by the tree hash, %s)" % path, V2_REQUIRED))]
        elif legacy and _blob(head, where) is NOT_REGULAR:
            return _no_record(report, changed, where, NON_REGULAR)
        elif legacy and _blob(head, where) is not None:
            probs = [_no_substitute("record %s, named by the legacy tree hash, is not the same file, unchanged by this "
                                    "pull request, at the merge base %s and on the trusted revision %s"
                                    % (where, _show(base), _show(trusted)), V2_REQUIRED)]
        else:
            return _no_record(report, changed, path, "no regular file there")
    else:
        try:
            rec = _read_record(head, path)
        except (RuntimeError, ValueError) as e:
            return _no_record(report, changed, path, (str(e).splitlines() or [type(e).__name__])[0])
        if not (isinstance(rec, dict) and rec.get("schema") == SCHEMA):
            probs = [_no_substitute("record %s has schema %s, not %s" % (
                path, _show(rec.get("schema") if isinstance(rec, dict) else None), SCHEMA), V2_REQUIRED)]
            rec = None
    if rec is not None:
        judged = _judge(rec, tree)
        probs = list(judged)
        report.more += judged.more
    report.extend("::error file=%s::review gate: %s (REQ-AUD-18 AC3)" % (where, p) for p in probs)
    if report:
        return _emit(report)
    _say("review gate: %d auditor path(s) changed; %s clears the stop rule (%d round(s))"
         % (len(changed), path, len(rec["rounds"])))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
