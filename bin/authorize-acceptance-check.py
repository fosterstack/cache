#!/usr/bin/env python3
"""Strict acceptance-content policy for the release authorization stage.

Usage: authorize-acceptance-check.py <tag> <ac_results.json> <variant-label>

Given a verified acceptance predicate's ac_results (already
signature/digest-bound by the caller), enforce that it attests a COMPLETE
pass against the FROZEN, owner-approved baseline for <tag>. Exits non-zero
with a ::error:: on any violation. Extracted from stage-authorize.yml so
it runs identically for EVERY image variant (B02b) and is exercised by a
committed regression test (bin/authorize-acceptance-check-test.sh) instead
of only ad-hoc audit probes.

Reads requirements/releases/<tag>.yaml (the required set) and
requirements/requirements.yaml (the allowed AC universe) relative to the
current directory.
"""
import json
import sys

try:
    import yaml
except ImportError:
    sys.stderr.write("PyYAML required (present on ubuntu-latest system Python)\n")
    sys.exit(2)


def fail(msg):
    sys.stderr.write("::error::" + msg + "\n")
    sys.exit(1)


def main():
    if len(sys.argv) != 4:
        sys.stderr.write("usage: authorize-acceptance-check.py <tag> <ac_results.json> <variant-label>\n")
        sys.exit(2)
    tag, acfile, variant = sys.argv[1], sys.argv[2], sys.argv[3]
    who = f"acceptance:{variant}"

    frozen_path = f"requirements/releases/{tag}.yaml"
    try:
        frozen = yaml.safe_load(open(frozen_path))
    except FileNotFoundError:
        fail(f"frozen baseline {frozen_path} missing - cannot authorize")

    blocking = frozen.get("release_blocking_acs") or []
    candidate_required = {
        b["id"] for b in blocking
        if b.get("phase") == "candidate" and str(b.get("method", "")).startswith("acceptance")
    }
    publication_acs = {b["id"] for b in blocking if b.get("phase") == "publication"}
    if not candidate_required:
        fail("no candidate-phase acceptance-method blocking ACs in the frozen baseline - the gate would enforce nothing")

    reqs = yaml.safe_load(open("requirements/requirements.yaml"))
    allowed = set(publication_acs)
    for r in reqs.get("requirements", []):
        if r.get("deprecated"):
            continue
        for ac in r.get("acceptance_criteria", []):
            m = (ac.get("verification") or {}).get("method", "")
            if m.startswith("acceptance"):
                allowed.add(ac["id"])

    try:
        rows = json.load(open(acfile))
    except (OSError, ValueError) as e:
        fail(f"{who} ac_results unreadable: {e}")
    if not isinstance(rows, list) or not rows:
        fail(f"{who} predicate carries an empty ac_results - refusing to authorize")

    valid_tokens = {"pass", "fail", "skip", "not-run", "deferred-to-publication"}
    seen = {}
    for rec in rows:
        if not isinstance(rec, dict):
            fail(f"{who} has a malformed ac_results entry: {rec!r}")
        ac_id = rec.get("ac")
        res = rec.get("result")
        if ac_id is None:
            fail(f"{who} has an ac_results entry with no ac id: {rec!r}")
        if res not in valid_tokens:
            fail(f"{who} reports an invalid result for {ac_id}: {res!r}")
        if ac_id in seen:
            fail(f"{who} reports {ac_id} more than once")
        if ac_id not in allowed:
            fail(f"{who} reports an AC not in the {tag} baseline: {ac_id}")
        seen[ac_id] = res

    missing = sorted(candidate_required - set(seen))
    if missing:
        fail(f"{who} predicate is missing required candidate ACs: {', '.join(missing)}")
    notpass = sorted(f"{a}={seen[a]}" for a in candidate_required if seen[a] != "pass")
    if notpass:
        fail(f"{who} predicate carries non-passing candidate ACs: {', '.join(notpass)}")
    badpub = sorted(f"{a}={seen[a]}" for a in publication_acs if a in seen and seen[a] not in ("pass", "deferred-to-publication"))
    if badpub:
        fail(f"{who} predicate has invalid publication-phase outcomes: {', '.join(badpub)}")
    print(f"{who} content verified: {len(candidate_required)} required candidate ACs present and passing")


if __name__ == "__main__":
    main()
