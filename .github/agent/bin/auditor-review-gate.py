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
"""
import hashlib, json, os, re, subprocess, sys

AGENT = ".github/agent/"
REVIEWS = AGENT + "reviews/"
# The allowlist guard's own files live outside .github/agent/ but are review-gated like it: the
# guard decides what a public-repo PR may contain, so changing it needs the same independent review.
# (ci.yml is NOT listed: its allowlist job is judged by this gate's workflow from main's copies.)
GUARDED = ("bin/check-file-allowlist.sh", "bin/check-file-allowlist-test.sh",
           ".github/workflows/agent-review-gate.yml")
VENDORS = {"codex": "openai", "sonnet": "anthropic"}
SCHEMA = "auditor-review-record/v1"
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


def record_problems(rec, tree):
    """Every reason `rec` does not clear the gate for content `tree` (empty = clears)."""
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
            probs.append("final round has no %s review" % name)
            continue
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
    probs = record_problems(rec, tree)
    for p in probs:
        print("::error file=%s::review gate: %s (REQ-AUD-18 AC3)" % (path, p))
    if probs:
        return 1
    print("review gate: %d auditor path(s) changed; %s clears the stop rule (%d round(s))"
          % (len(changed), path, len(rec["rounds"])))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
