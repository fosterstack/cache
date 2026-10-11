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

A record clears the gate (REQ-AUD-018 AC5, AC6) when its schema is auditor-review-record/v2, it binds <tree>, and
its FINAL round's reviewers hold exactly two entries, codex_a and codex_b, and nothing else: each an object with
exactly the fields reviewer (codex), vendor (openai), seat (A or B, matching its key), model and effort (each on the
gate's own lists below), blockers_open (exactly the integer 0) and evidence_sha256 (64 lowercase hex: the sha256 of
that seat's raw output, kept in the private audit tree). The two seats name two different models (SAME_MODEL
below says which list entries count as one model); the two evidence hashes differ; the stop block holds exactly
codex_a clear and codex_b clear. Every missing, extra, mistyped or malformed field fails with a message naming it. The record is an
attestation by the agent that ran the loop (owner decision, option C, Sep 27): the gate checks its shape, never that
a review ran or which model ran; the evidence hash lets a holder of the raw output check its header.

No substitute (AC4): an entry under any other key in the final round, and any field anywhere in the record whose
name marks a substitute, fails, saying no substitute is accepted. The gate reads no allow-list and no clock and
no environment; a Codex outage leaves the change waiting for both Codex reviews.

Records merged before the dual-Codex gate (AC7): a record whose schema is not v2 clears only when the trusted
revision holds the same record path with the same blob (same bytes); it is then not re-judged by any rule. Any other
such record fails, saying a schema v2 record is required; a trusted revision that cannot be read fails closed.

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
FIELDS = ("reviewer", "vendor", "seat", "model", "effort", "blockers_open", "evidence_sha256")
# The gate's own lists (AC5). SAME_MODEL maps a model to the one it counts as when the two seats are compared.
CODEX_MODELS = ("gpt-6-luna", "gpt-6-sol", "gpt-6.1-sol", "gpt-6-astra")
SAME_MODEL = {"gpt-6.1-sol": "gpt-6-sol"}
EFFORTS = ("medium", "high", "xhigh")
NO_SUBSTITUTE = "no substitute is accepted"
V2_REQUIRED = "a schema v2 record is required"
_HEX64 = re.compile(r"[0-9a-f]{64}")
_SUBSTITUTE = re.compile(r"substitut", re.I)


def _git(*a):
    r = subprocess.run(["git", *a], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError("git %s: %s" % (" ".join(a), r.stderr.strip()))
    return r.stdout


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


def _substitute_marks(v, where):
    """Every field name anywhere under `v` that marks a substitute (AC4), as 'where.field' paths."""
    found = []
    if isinstance(v, dict):
        for k, x in v.items():
            if _SUBSTITUTE.search(k):
                found.append("%s.%s" % (where, k))
            found += _substitute_marks(x, "%s.%s" % (where, k))
    elif isinstance(v, list):
        for i, x in enumerate(v):
            found += _substitute_marks(x, "%s[%d]" % (where, i))
    return found


def _seat_problems(name, r):
    """Every reason the seat entry `name` (codex_a or codex_b) is not a clear Codex review (AC5, AC6)."""
    if not isinstance(r, dict):
        return ["%s entry is not an object (%r)" % (name, r)]
    probs = ["%s has no %s field" % (name, f) for f in FIELDS if f not in r]
    probs += ["%s has an extra field %r" % (name, k) for k in r if k not in FIELDS and not _SUBSTITUTE.search(k)]
    if "reviewer" in r and r["reviewer"] != "codex":
        probs.append("%s reviewer is %r, want 'codex'" % (name, r["reviewer"]))
    if "vendor" in r and r["vendor"] != "openai":
        probs.append("%s vendor is %r, want 'openai'" % (name, r["vendor"]))
    if "seat" in r and r["seat"] != SEATS[name]:
        probs.append("%s seat is %r, want %r" % (name, r["seat"], SEATS[name]))
    if "model" in r and (not isinstance(r["model"], str) or r["model"] not in CODEX_MODELS):
        probs.append("%s model %r is not on the gate's list of Codex models" % (name, r["model"]))
    if "effort" in r and (not isinstance(r["effort"], str) or r["effort"] not in EFFORTS):
        probs.append("%s effort %r is not on the gate's list of efforts" % (name, r["effort"]))
    b = r.get("blockers_open", 0)
    if type(b) is not int or b != 0:      # exactly the integer 0: not False, not 0.0
        probs.append("%s blockers_open is %r, want the integer 0" % (name, b))
    if "evidence_sha256" in r and not (isinstance(r["evidence_sha256"], str) and _HEX64.fullmatch(r["evidence_sha256"])):
        probs.append("%s evidence_sha256 is not 64 lowercase hex characters" % name)
    return probs


def record_problems(rec, tree):
    """Every reason the schema v2 record `rec` does not clear the gate for content `tree` (empty = clears)."""
    if not isinstance(rec, dict):
        return ["record is not a JSON object"]
    probs = ["record field %s marks a substitute: %s" % (m, NO_SUBSTITUTE) for m in _substitute_marks(rec, "record")]
    if rec.get("schema") != SCHEMA:
        probs.append("schema is %r, not %s: %s" % (rec.get("schema"), SCHEMA, V2_REQUIRED))
    if rec.get("tree") != tree:
        probs.append("record binds tree %s, the change is %s" % (rec.get("tree"), tree))
    rounds = rec.get("rounds")
    if not isinstance(rounds, list) or not rounds:
        return probs + ["no review rounds recorded"]
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
    probs += ["stop holds an extra key %r" % k for k in stop if k not in SEATS and not _SUBSTITUTE.search(k)]
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


def legacy_problems(head, trusted, path, rec):
    """AC7: a record that is not schema v2 clears only as the same blob already at `path` on the trusted revision,
    and is then never re-judged. Returns the reasons it does not (empty = it is that merged file)."""
    try:
        want = _blob(trusted, path)
    except RuntimeError as e:
        return ["the trusted revision %r cannot be read (%s): an old-schema record cannot be honoured"
                % (trusted, (str(e).splitlines() or ["git"])[0])]
    if want is not None and want == _blob(head, path):
        return []
    schema = rec.get("schema") if isinstance(rec, dict) else None
    return ["record %s has schema %r and is not the same file already on the trusted revision %s: %s"
            % (path, schema, trusted, V2_REQUIRED)]


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
    if not changed:
        print("review gate: no change under %s — nothing to clear" % AGENT)
        return 0
    path = REVIEWS + tree + ".json"
    try:
        rec = json.loads(_git("show", "%s:%s" % (head, path)))
    except (RuntimeError, ValueError) as e:
        why = (str(e).splitlines() or [type(e).__name__])[0]
        print("::error::review gate: %d auditor path(s) changed (e.g. %s) but no valid review "
              "record at %s (%s). Run both Codex reviews (seat A and seat B, two different models) on this exact "
              "content and commit its record (REQ-AUD-18 AC3)." % (len(changed), changed[0], path, why))
        return 1
    if isinstance(rec, dict) and rec.get("schema") == SCHEMA:
        probs = record_problems(rec, tree)
    else:
        probs = legacy_problems(head, trusted, path, rec)
        if not probs:
            print("review gate: %d auditor path(s) changed; %s is the old-schema record already on the trusted "
                  "revision %s (the same file): honoured as merged, not re-judged" % (len(changed), path, trusted))
            return 0
    for p in probs:
        print("::error file=%s::review gate: %s (REQ-AUD-18 AC3)" % (path, p))
    if probs:
        return 1
    print("review gate: %d auditor path(s) changed; %s clears the stop rule (%d round(s))"
          % (len(changed), path, len(rec["rounds"])))
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
