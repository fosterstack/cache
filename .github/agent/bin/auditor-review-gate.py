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
which.

A record clears the gate (REQ-AUD-018 AC5, AC6) when its schema is auditor-review-record/v2, it binds <tree>, and
it holds only the permitted fields at every level: the record RECORD_REQUIRED (+ RECORD_OPTIONAL), every round
ROUND_REQUIRED (+ ROUND_OPTIONAL) with round numbers positive and increasing, and every seat entry exactly FIELDS.
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
name: allowlist_entry, exception, waiver, ...), and any key or string value anywhere in the record that contains
"substitut" (any case) fails, naming it and saying no substitute is accepted. The gate reads no allow-list and no
clock and no environment; an outage of the reviewer leaves the change waiting for both reviews.

Records merged before the schema v2 gate (AC7): a record whose schema is not v2 clears only when it is the same blob
at its path on the merge base (--base), on the PR head and on the trusted revision, and the PR's diff does not add,
change or remove it; it is then not re-judged by any rule. Every record file the PR adds or changes, whether or not
the PR changes anything else, must be a strictly read schema v2 record, so a PR (a record-only one included) can
never introduce an old-schema record. What this proves: the old record was on the default branch before this PR and
this PR did not touch it. What it does not prove: how it got there; a record merged before this gate, or merged by
anyone past the gate, is history and is not re-judged. A trusted revision that cannot be read fails closed.

It runs from .github/workflows/agent-review-gate.yml on pull_request_target (AC8): the workflow checks
out the BASE branch — so this file is always main's copy, never the PR's — fetches the PR head as
git objects only (never checked out, never executed), reads the record with `git show`, and runs this script
with `python3 -I` (isolated: no script directory on sys.path, no PYTHON* env).

  --base REV       the base to diff against (the merge base of the PR with its base branch)
  --head REV       the reviewed commit (the PR head); default HEAD
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
RECORD_OPTIONAL = ("change", "reviewed_commit", "residuals")
ROUND_REQUIRED = ("round", "reviewers")
ROUND_OPTIONAL = ("label",)
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
_JSON_STRING = re.compile(r'"(?:[^"\\]|\\.)*"', re.S)
_SUBSTITUTE = re.compile(r"substitut", re.I)


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
            raise ValueError("the record repeats the key %r" % k)
        keys.add(k)
    return dict(pairs)


def _no_constant(c):
    raise ValueError("the record holds the non-standard constant %s" % c)


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
    depth = deepest = 0
    for ch in re.findall(r"[\[\]{}]", _JSON_STRING.sub("", text)):      # brackets outside strings only
        depth += 1 if ch in "[{" else -1
        deepest = max(deepest, depth)
    if deepest > MAX_DEPTH:
        raise ValueError("the record nests too deeply to read (more than %d levels)" % MAX_DEPTH)
    try:
        return json.loads(text, object_pairs_hook=_dupless, parse_constant=_no_constant)
    except json.JSONDecodeError as e:
        raise ValueError("the record is not valid JSON (%s)" % e) from None


def _substitute_marks(v, where):
    """Every key and string value anywhere under `v` that marks or names a substitute (AC4), walked without
    recursion so that no depth can raise."""
    found, stack = [], [(v, where)]
    while stack:
        x, at = stack.pop()
        if isinstance(x, dict):
            for k, y in x.items():
                if _SUBSTITUTE.search(k):
                    found.append("record field %s.%s marks a substitute: %s" % (at, k, NO_SUBSTITUTE))
                stack.append((y, "%s.%s" % (at, k)))
        elif isinstance(x, list):
            stack += [(y, "%s[%d]" % (at, i)) for i, y in enumerate(x)]
        elif isinstance(x, str) and _SUBSTITUTE.search(x):
            found.append("record field %s names a substitute (%r): %s" % (at, x[:80], NO_SUBSTITUTE))
    return sorted(found)


def _extras(where, obj, permitted):
    """An 'extra field' problem for every key of `obj` outside `permitted` (a key marking a substitute is already
    named by _substitute_marks)."""
    return ["%s has an extra field %r: %s" % (where, k, PERMITTED_ONLY)
            for k in obj if k not in permitted and not _SUBSTITUTE.search(k)]


def _seat_problems(name, r, final=True):
    """Every reason the seat entry `name` (codex_a or codex_b, prefixed with its round when not final) is not a
    clear review (AC5, AC6). In an earlier round, blockers_open may be any non-negative integer."""
    key = name.rsplit(".", 1)[-1]
    if not isinstance(r, dict):
        return ["%s entry is not an object (%r)" % (name, r)]
    probs = ["%s has no %s field" % (name, f) for f in FIELDS if f not in r]
    probs += _extras(name, r, FIELDS)
    if "reviewer" in r and r["reviewer"] != "codex":
        probs.append("%s reviewer is %r, want 'codex'" % (name, r["reviewer"]))
    if "vendor" in r and r["vendor"] != "openai":
        probs.append("%s vendor is %r, want 'openai'" % (name, r["vendor"]))
    if "seat" in r and r["seat"] != SEATS[key]:
        probs.append("%s seat is %r, want %r" % (name, r["seat"], SEATS[key]))
    if "model" in r and (not isinstance(r["model"], str) or r["model"] not in CODEX_MODELS):
        probs.append("%s model %r is not on the gate's list of Codex models" % (name, r["model"]))
    if "effort" in r and (not isinstance(r["effort"], str) or r["effort"] not in EFFORTS):
        probs.append("%s effort %r is not on the gate's list of efforts" % (name, r["effort"]))
    b = r.get("blockers_open", 0)
    if final and (type(b) is not int or b != 0):      # exactly the integer 0: not False, not 0.0
        probs.append("%s blockers_open is %r, want the integer 0" % (name, b))
    if not final and (type(b) is not int or b < 0):
        probs.append("%s blockers_open is %r, want a non-negative integer" % (name, b))
    if "evidence_sha256" in r and not (isinstance(r["evidence_sha256"], str) and _HEX64.fullmatch(r["evidence_sha256"])):
        probs.append("%s evidence_sha256 is not 64 lowercase hex characters" % name)
    return probs


def _rounds_problems(rounds):
    """The fields of every round (AC5): round (a positive integer, greater than the round before), reviewers, an
    optional label, nothing else; and every seat entry of every round but the final one (judged in record_problems)."""
    probs, last = [], None
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
            probs.append("%s round is %r, want a positive integer" % (at, n))
        else:
            if last is not None and n <= last:
                probs.append("%s round %d does not follow round %d" % (at, n, last))
            last = n
        if "label" in rd and not isinstance(rd["label"], str):
            probs.append("%s label is not a string" % at)
        if i == len(rounds) - 1:
            continue
        rv = rd.get("reviewers")
        if not isinstance(rv, dict) or not rv:
            probs.append("%s reviewers is not a non-empty object" % at)
            continue
        for k, entry in rv.items():
            if k not in SEATS:
                probs.append("%s entry %r is not a seat (only codex_a and codex_b take a seat): %s" % (at, k, NO_SUBSTITUTE))
            else:
                probs += _seat_problems("%s.%s" % (at, k), entry, final=False)
    return probs


def record_problems(rec, tree):
    """Every reason the schema v2 record `rec` does not clear the gate for content `tree` (empty = clears)."""
    if not isinstance(rec, dict):
        return ["record is not a JSON object"]
    probs = _substitute_marks(rec, "record")
    probs += _extras("record", rec, RECORD_REQUIRED + RECORD_OPTIONAL)
    if rec.get("schema") != SCHEMA:
        probs.append("schema is %r, not %s: %s" % (rec.get("schema"), SCHEMA, V2_REQUIRED))
    if rec.get("tree") != tree:
        probs.append("record binds tree %s, the change is %s" % (
            rec.get("tree") if isinstance(rec.get("tree"), str) or rec.get("tree") is None else repr(rec.get("tree")), tree))
    if "change" in rec and not isinstance(rec["change"], str):
        probs.append("record change is not a string")
    if "reviewed_commit" in rec and not (isinstance(rec["reviewed_commit"], str) and _HEX40.fullmatch(rec["reviewed_commit"])):
        probs.append("record reviewed_commit is not 40 lowercase hex characters")
    if "residuals" in rec and not (isinstance(rec["residuals"], list) and all(isinstance(x, str) for x in rec["residuals"])):
        probs.append("record residuals is not a list of strings")
    rounds = rec.get("rounds")
    if not isinstance(rounds, list) or not rounds:
        return probs + ["no review rounds recorded"]
    probs += _rounds_problems(rounds)
    final = rounds[-1].get("reviewers") if isinstance(rounds[-1], dict) else None
    if not isinstance(final, dict):
        return probs + ["final round names no reviewers"]
    probs += ["final round entry %r is not a seat (only codex_a and codex_b take a seat): %s" % (k, NO_SUBSTITUTE)
              for k in final if k not in SEATS]
    for name in SEATS:
        if name not in final:
            probs.append("final round has no %s entry" % name)
        else:
            probs += _seat_problems(name, final[name])
    a, b = final.get("codex_a"), final.get("codex_b")
    if isinstance(a, dict) and isinstance(b, dict):
        ma, mb = a.get("model"), b.get("model")
        if ma in CODEX_MODELS and mb in CODEX_MODELS and SAME_MODEL.get(ma, ma) == SAME_MODEL.get(mb, mb):
            probs.append("codex_a and codex_b name the same model (%s and %s): the two seats run two different models" % (ma, mb))
        if "evidence_sha256" in a and a["evidence_sha256"] == b.get("evidence_sha256"):
            probs.append("codex_a and codex_b have the same evidence_sha256: a copied entry is not an independent review")
    stop = rec.get("stop")
    if not isinstance(stop, dict):
        return probs + ["stop is missing or not an object"]
    probs += ["stop holds an extra key %r: %s" % (k, PERMITTED_ONLY) for k in stop if k not in SEATS and not _SUBSTITUTE.search(k)]
    for name in SEATS:
        if stop.get(name) != "clear":
            probs.append("stop verdict for %s is %r, want 'clear'" % (name, stop.get(name)))
    return probs


def _blob(rev, path):
    """The blob id of `path` at `rev`, or None when the revision has no such file. A revision that is not a readable
    commit raises RuntimeError (the caller fails closed); so does one that git could read as an option."""
    if rev.startswith("-"):
        raise RuntimeError("not a revision")
    _git("rev-parse", "--verify", "--quiet", "%s^{commit}" % rev)
    out = _git("ls-tree", "-z", rev, "--", path).split("\0")[0]
    meta = out.split("\t", 1)[0].split()      # mode type id: a regular file only (never a link or a submodule)
    return meta[2] if len(meta) == 3 and meta[1] == "blob" and meta[0] in ("100644", "100755") else None


def legacy_problems(base, head, trusted, path, rec, touched):
    """AC7: a record that is not schema v2 clears only when the PR's diff does not touch `path` (`touched` is the set
    of record paths it adds, changes or removes) and the same regular-file blob is at `path` on the merge base `base`,
    the PR head and the trusted revision; it is then never re-judged. The path names the head's tree, so the record
    can only be the one for this exact content. This proves the file was on the default branch before this PR and the
    PR did not touch it; it does not prove how the file got there (history, not re-judged; every record a PR adds or
    changes must be schema v2, see added_record_problems). Returns the reasons it does not clear (empty = it does)."""
    try:
        want = _blob(trusted, path)
    except RuntimeError as e:
        return ["the trusted revision %r cannot be read (%s): an old-schema record cannot be honoured"
                % (trusted, (str(e).splitlines() or ["git"])[0])]
    if path not in touched and want is not None and want == _blob(base, path) == _blob(head, path):
        return []
    schema = rec.get("schema") if isinstance(rec, dict) else None
    return ["record %s has schema %r and is not the same file, unchanged by this pull request, at the merge base %s "
            "and on the trusted revision %s: %s" % (path, schema, base, trusted, V2_REQUIRED)]


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
            probs.append((path, "record %s is added or changed by this pull request and its schema is %r, not %s: %s"
                          % (path, rec.get("schema") if isinstance(rec, dict) else None, SCHEMA, V2_REQUIRED)))
    return probs


def main(argv):
    def opt(k, d=None):
        if k not in argv:
            return d
        i = argv.index(k) + 1
        return argv[i] if i < len(argv) else None      # a flag without a value is missing
    head = opt("--head", "HEAD")
    tree = tree_hash(head)
    if "--print-tree" in argv:
        print(tree)
        return 0
    if "--pr" in argv:      # accepted because the workflow passes it; it changes no verdict
        raw = opt("--pr")
        if raw is None or not re.fullmatch(r"[1-9][0-9]*", raw):
            print("::error::auditor-review-gate: --pr must be a positive integer", file=sys.stderr)
            return 2
    base = opt("--base")
    if not base:
        print("::error::auditor-review-gate: --base is required", file=sys.stderr)
        return 2
    trusted = base
    if "--subs-rev" in argv:
        trusted = opt("--subs-rev")
        if not trusted:
            print("::error::auditor-review-gate: --subs-rev needs the trusted revision", file=sys.stderr)
            return 2
    changed = auditor_changes(base, head)
    path = REVIEWS + tree + ".json"
    touched = touched_records(base, head)
    added = added_record_problems(head, touched, path if changed else None)
    for where, p in added:
        print("::error file=%s::review gate: %s (REQ-AUD-18 AC7)" % (where, p))
    if not changed:
        if added:
            return 1
        print("review gate: no change under %s — nothing to clear" % AGENT)
        return 0
    try:
        rec = _read_record(head, path)
    except (RuntimeError, ValueError) as e:
        why = (str(e).splitlines() or [type(e).__name__])[0]
        print("::error::review gate: %d auditor path(s) changed (e.g. %s) but no valid review "
              "record at %s (%s). Run both Codex reviews (seat A and seat B, two different models) on this exact "
              "content and commit its record (REQ-AUD-18 AC3)." % (len(changed), changed[0], path, why))
        return 1
    if isinstance(rec, dict) and rec.get("schema") == SCHEMA:
        probs = record_problems(rec, tree)
    else:
        probs = legacy_problems(base, head, trusted, path, rec, touched)
        if not probs and not added:
            print("review gate: %d auditor path(s) changed; %s is the old-schema record already at the merge base "
                  "and on the trusted revision %s (the same file, unchanged): honoured as merged, not re-judged"
                  % (len(changed), path, trusted))
            return 0
    for p in probs:
        print("::error file=%s::review gate: %s (REQ-AUD-18 AC3)" % (path, p))
    if probs or added:
        return 1
    print("review gate: %d auditor path(s) changed; %s clears the stop rule (%d round(s))"
          % (len(changed), path, len(rec["rounds"])))
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
