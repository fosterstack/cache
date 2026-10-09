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

A record clears the gate when it names both vendors (codex = OpenAI, sonnet = Anthropic),
its final round leaves each with zero open merge blockers and a sha256 of that reviewer's raw
output (the evidence, kept in the private audit tree), and its stop verdict is "clear" for
both. The record is an attestation by the agent that ran the loop (owner decision, option C,
Sep 27: self-attested); the gate makes a missing, stale or non-clear one impossible to merge past.

It runs from .github/workflows/agent-review-gate.yml on pull_request_target: the workflow checks
out the BASE branch — so this file is always main's copy, never the PR's — fetches the PR head as
git objects only (never checked out, never executed), and reads the record with `git show`.

  --base REV       the base to diff against (the merge base of the PR with its base branch)
  --head REV       the reviewed commit (the PR head); default HEAD
  --print-tree     print <tree> for --head and exit (used to name the record)
  --pr N           the pull request's number; needed only by a substitute whose scope is pr:N
  --subs-rev REV   the TRUSTED revision whose reviews/substitutes.json is read (default: --base). The
                   workflow passes the checked-out default branch, so a substitute merged after the PR
                   branched still counts; the PR's own copy of the file is never read.

REQ-AUD-018 AC4 (recorded second-seat substitute): while the owner has stopped the second vendor, the
final round may carry an `opus` entry (vendor anthropic, model opus, effort medium, substitute_for
codex, substitute_id, blockers_open 0, evidence_sha256) in place of `codex`, and the round a
`completed_at` (YYYY-MM-DDTHH:MM:SSZ). It counts only if substitute_id names an entry of
.github/agent/reviews/substitutes.json as read from the trusted revision (never the PR's copy: a PR
cannot add or extend its own substitute; its edit of the file only changes <tree>), the entry is
unexpired by the gate's own UTC clock (GATE_NOW overrides it, for tests) AND by completed_at, and its
scope (`all`, or `pr:N` with N equal to --pr) fits. Sonnet is never substitutable. A record with a
codex entry is judged on codex alone. Anything malformed fails closed with a message naming it.
"""
import datetime, hashlib, json, os, re, subprocess, sys

AGENT = ".github/agent/"
REVIEWS = AGENT + "reviews/"
# The allowlist guard's own files live outside .github/agent/ but are review-gated like it: the
# guard decides what a public-repo PR may contain, so changing it needs the same independent review.
# (ci.yml is NOT listed: its allowlist job is judged by this gate's workflow from main's copies.)
GUARDED = ("bin/check-file-allowlist.sh", "bin/check-file-allowlist-test.sh",
           ".github/workflows/agent-review-gate.yml")
VENDORS = {"codex": "openai", "sonnet": "anthropic"}
SCHEMA = "auditor-review-record/v1"
SUBS_PATH = REVIEWS + "substitutes.json"
SUBS_SCHEMA = "review-substitutes/v1"
_TIME = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_SCOPE = re.compile(r"^(all|pr:[1-9][0-9]*)$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _git(*a):
    r = subprocess.run(["git", *a], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError("git %s: %s" % (" ".join(a), r.stderr.strip()))
    return r.stdout


_RECORD = re.compile(r"^" + re.escape(REVIEWS) + r"[0-9a-f]{64}\.json$")


def _is_record(path):
    """Only a review record itself is outside the reviewed content — any other file under
    reviews/ is an ordinary auditor change (round-1 review: the directory is not a free zone)."""
    return bool(_RECORD.match(path))


def tree_hash(head):
    # -z: NUL-delimited, unquoted paths (a quoted non-ASCII name cannot slip past _is_record)
    lines = [ln for ln in _git("ls-tree", "-r", "-z", "--full-tree", head, "--", AGENT, *GUARDED).split("\0")
             if ln and not _is_record(ln.split("\t", 1)[-1])]
    return hashlib.sha256(("\n".join(lines) + "\n").encode()).hexdigest()


def auditor_changes(base, head):
    # --no-renames: a rename out of .github/agent/ must show its OLD path too, never only the new.
    return [p for p in _git("diff", "--no-renames", "--name-only", "-z", base, head, "--").split("\0")
            if (p.startswith(AGENT) or p in GUARDED) and not _is_record(p)]


def _time(v):
    """A strict UTC instant YYYY-MM-DDTHH:MM:SSZ, or None."""
    if not isinstance(v, str) or not _TIME.match(v):
        return None
    try:
        return datetime.datetime.strptime(v, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        return None


def _reviewer_problems(name, vendor, r, stop):
    probs = []
    if name != "opus" and ("substitute_for" in r or "substitute_id" in r):
        probs.append("%s is marked as a substitute; only the codex seat can be substituted, and only by opus" % name)
    if r.get("vendor") != vendor:
        probs.append("%s vendor is %r, want %r" % (name, r.get("vendor"), vendor))
    b = r.get("blockers_open")
    if type(b) is not int or b != 0:      # exactly the integer 0 — not False, not 0.0
        probs.append("%s has %r open merge blocker(s)" % (name, r.get("blockers_open")))
    if not _HEX64.match(str(r.get("evidence_sha256", ""))):
        probs.append("%s evidence_sha256 is not a sha256" % name)
    if stop.get(name) != "clear":
        probs.append("%s stop verdict is %r, want 'clear'" % (name, stop.get(name)))
    return probs


def _substitute_entry(subs, sid):
    """(entry, problems): the substitutes.json entry `sid` names, validated field by field."""
    if subs is None:
        return None, ["opus substitute: no readable %s on the trusted revision" % SUBS_PATH]
    try:
        doc = json.loads(subs)
    except ValueError:
        return None, ["opus substitute: %s is not valid JSON" % SUBS_PATH]
    if not isinstance(doc, dict) or doc.get("schema") != SUBS_SCHEMA:
        return None, ["opus substitute: %s schema is not %s" % (SUBS_PATH, SUBS_SCHEMA)]
    entries = doc.get("substitutes")
    if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
        return None, ["opus substitute: %s substitutes is not a list of objects" % SUBS_PATH]
    if not isinstance(sid, str) or not sid:
        return None, ["opus substitute: substitute_id is missing or not a string"]
    hits = [e for e in entries if e.get("id") == sid]
    if len(hits) != 1:
        return None, ["opus substitute: substitute_id %r names %d entries of %s, want exactly 1" % (sid, len(hits), SUBS_PATH)]
    e = hits[0]
    probs = []
    if e.get("for") != "codex":
        probs.append("opus substitute: entry %s `for` is %r, want 'codex'" % (sid, e.get("for")))
    if e.get("by") != "opus":
        probs.append("opus substitute: entry %s `by` is %r, want 'opus'" % (sid, e.get("by")))
    if e.get("vendor") != "anthropic":
        probs.append("opus substitute: entry %s vendor is %r, want 'anthropic'" % (sid, e.get("vendor")))
    q = e.get("owner_quote")
    if not isinstance(q, str) or not q.strip():
        probs.append("opus substitute: entry %s owner_quote is empty or not a string" % sid)
    if _time(e.get("effective_until")) is None:
        probs.append("opus substitute: entry %s effective_until %r is not YYYY-MM-DDTHH:MM:SSZ" % (sid, e.get("effective_until")))
    if not isinstance(e.get("scope"), str) or not _SCOPE.match(e["scope"]):
        probs.append("opus substitute: entry %s scope %r is not 'all' or 'pr:N'" % (sid, e.get("scope")))
    return (None if probs else e), probs


def _substitute_problems(final, rnd, stop, subs, pr, now):
    """Every reason the final round's `opus` entry cannot stand in for `codex` (empty = it can)."""
    r = final.get("opus")
    if not isinstance(r, dict):
        return ["final round has no codex review"]
    probs = _reviewer_problems("opus", "anthropic", r, stop)
    if r.get("substitute_for") != "codex":
        probs.append("opus substitute_for is %r, want 'codex'" % (r.get("substitute_for"),))
    if r.get("model") != "opus":
        probs.append("opus model is %r, want 'opus'" % (r.get("model"),))
    if r.get("effort") != "medium":
        probs.append("opus effort is %r, want 'medium'" % (r.get("effort"),))
    done = _time(rnd.get("completed_at"))
    if done is None:
        probs.append("final round completed_at %r is missing or not YYYY-MM-DDTHH:MM:SSZ (required with a substitute)"
                     % (rnd.get("completed_at"),))
    if now is None:
        raw = os.environ.get("GATE_NOW")
        now = datetime.datetime.now(datetime.timezone.utc) if raw is None else _time(raw)
        if now is None:
            probs.append("GATE_NOW %r is not YYYY-MM-DDTHH:MM:SSZ" % raw)
    entry, bad = _substitute_entry(subs, r.get("substitute_id"))
    probs += bad
    if entry is None:
        return probs
    sid, until = entry["id"], _time(entry["effective_until"])
    if now is not None and now >= until:
        probs.append("opus substitute %s expired at %s (the gate's clock is %s)" % (sid, entry["effective_until"], now.strftime("%Y-%m-%dT%H:%M:%SZ")))
    if done is not None:
        if done >= until:
            probs.append("final round completed_at %s is not before substitute %s expiry %s" % (rnd["completed_at"], sid, entry["effective_until"]))
        if now is not None and done > now:
            probs.append("final round completed_at %s is in the future of the gate's clock" % rnd["completed_at"])
    if entry["scope"] != "all":
        want = int(entry["scope"][3:])
        if pr is None:
            probs.append("opus substitute %s scope %s needs --pr, none given" % (sid, entry["scope"]))
        elif pr != want:
            probs.append("opus substitute %s scope %s does not cover PR #%s" % (sid, entry["scope"], pr))
    return probs


def record_problems(rec, tree, subs=None, pr=None, now=None):
    """Every reason `rec` does not clear the gate for content `tree` (empty = clears).
    subs: the text of reviews/substitutes.json from the trusted revision (None = none); pr: the PR
    number or None; now: the gate's clock (default: GATE_NOW, else the real UTC time)."""
    if not isinstance(rec, dict):
        return ["record is not a JSON object"]
    probs = []
    if rec.get("schema") != SCHEMA:
        probs.append("schema is not %s" % SCHEMA)
    if rec.get("tree") != tree:
        probs.append("record binds tree %s, the change is %s" % (rec.get("tree"), tree))
    rounds = rec.get("rounds")
    if not isinstance(rounds, list) or not rounds:
        return probs + ["no review rounds recorded"]
    final = rounds[-1].get("reviewers") if isinstance(rounds[-1], dict) else None
    if not isinstance(final, dict):
        return probs + ["final round names no reviewers"]
    stop = rec.get("stop") if isinstance(rec.get("stop"), dict) else {}
    for name, vendor in sorted(VENDORS.items()):
        r = final.get(name)
        if not isinstance(r, dict):
            if name == "codex":      # the one seat a recorded owner decision may fill with `opus`
                probs += _substitute_problems(final, rounds[-1], stop, subs, pr, now)
            else:
                probs.append("final round has no %s review" % name)
            continue
        probs += _reviewer_problems(name, vendor, r, stop)
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
    pr = None
    if "--pr" in argv:
        raw = opt("--pr")
        if raw is None or not re.fullmatch(r"[1-9][0-9]*", raw):
            print("::error::auditor-review-gate: --pr must be a positive integer", file=sys.stderr)
            return 2
        pr = int(raw)
    base = opt("--base")
    if not base:
        print("::error::auditor-review-gate: --base is required", file=sys.stderr)
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
              "record at %s (%s). Run the second-vendor review loop on this exact content and "
              "commit its record (REQ-AUD-18 AC3)." % (len(changed), changed[0], path, why))
        return 1
    try:
        subs = _git("show", "%s:%s" % (opt("--subs-rev") or base, SUBS_PATH))
    except RuntimeError:
        subs = None
    probs = record_problems(rec, tree, subs=subs, pr=pr)
    for p in probs:
        print("::error file=%s::review gate: %s (REQ-AUD-18 AC3)" % (path, p))
    if probs:
        return 1
    print("review gate: %d auditor path(s) changed; %s clears the stop rule (%d round(s))"
          % (len(changed), path, len(rec["rounds"])))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
