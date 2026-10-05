#!/usr/bin/env python3
"""Which verifier source admission runs for a release tag (automatic patch releases rule 3; REQ-REL-009-AC6).

Read by stage-admission.yml from protected main (never from the tagged commit). It only ROUTES: the chosen verifier
must still pass. "ssh": the owner's signature, checked against .github/policy/allowed_signers, on any tag. "gitsign":
the release workflow's keyless identity, accepted only on a patch tag (vX.Y.Z, Z >= 1, whose previous patch vX.Y.(Z-1)
is already released, so a line always starts from an owner-signed tag). Everything else is refused: an unsigned tag (an
App-pushed tag carries no signature of its own), a PGP signature, two signature blocks, or the CI identity on a minor,
major or rc tag or on a tag that already exists.
"""
import argparse, datetime, hashlib, os, re, subprocess, sys

BLOCKS = {"SSH SIGNATURE": "ssh", "SIGNED MESSAGE": "x509", "PGP SIGNATURE": "pgp"}
PATCH = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.([1-9][0-9]*)$")


def kind(tag_object):
    """The signature format of an annotated tag object: ssh, x509 (gitsign), pgp, none, or ambiguous. A signature is a
    PEM-style block with a signature label (BLOCKS) that git appends at the END of the object; any other PEM-style block
    (a key or certificate quoted in the notes) is message text (Codex #163 r1, B03). Two signature-labelled blocks, or one
    that is not at the end, are ambiguous."""
    lines = tag_object.rstrip("\n").split("\n")
    begins = [i for i, ln in enumerate(lines)
              if re.fullmatch(r"-----BEGIN [A-Z0-9 ]+-----", ln) and ln[len("-----BEGIN "):-len("-----")] in BLOCKS]
    if len(begins) > 1:
        return "ambiguous"
    if not begins:
        return "none"
    label = lines[begins[0]][len("-----BEGIN "):-len("-----")]
    if lines[-1] != "-----END %s-----" % label:
        return "ambiguous"
    return BLOCKS[label]


def route(tag, tag_object, released):
    """(route, why) with route in ssh / gitsign / refuse."""
    k = kind(tag_object)
    if k == "ssh":
        return "ssh", "an SSH signature: the owner's allowed-signers list decides"
    if k != "x509":
        return "refuse", {"none": "the tag is unsigned", "pgp": "a PGP signature is not an accepted signer",
                          "ambiguous": "the tag object carries an ambiguous signature"}[k]
    m = PATCH.match(tag)
    if not m:
        return "refuse", "the CI identity signs patch tags only (vX.Y.Z with Z >= 1); %s is the owner's" % tag
    if tag in released:
        return "refuse", "%s is already released" % tag
    prev = "v%s.%s.%d" % (m.group(1), m.group(2), int(m.group(3)) - 1)
    if prev not in released:
        return "refuse", "the CI identity cuts only the next patch: %s is not released" % prev
    return "gitsign", "a patch tag signed keylessly: the release workflow's identity on main decides"


# REQ-REL-009-AC13 (owner RATIFIED amendment, Oct 2) + the owner's 0126 amendment (Oct 3) + advisor 0150's
# validated classification table, amended again by the owner (Oct 4, handoff 0155): REQ-SCAN-010 (ships
# OpenVEX/Inspector/CSAF) and REQ-SCAN-011 (the customer guide) may ride automatic patches after all (Codex
# #163 r1, B02's concern considered and overruled by the owner). A requirement ID whose changes since a
# baseline never need the owner's fresh review to cut an automatic patch. Mirrors tools/requirements/main.go's
# publicationACs/blockingSet treatment in spirit, not by import (this module has no Go dependency) — keep the
# two lists in sync by hand; a REQ id not on this list, or not yet introduced at all, is product by default
# (fail-closed).
PIPELINE_ONLY = frozenset([
    "REQ-REL-004", "REQ-REL-005", "REQ-REL-006", "REQ-REL-007", "REQ-REL-008", "REQ-REL-009",
    "REQ-DEP-001", "REQ-DEP-002", "REQ-DEP-003", "REQ-DEP-004",
    "REQ-UAT-001",   # persona UAT (owner ratified Oct 4; advisor 0161 step 5): governs CI testing only
] + ["REQ-SCAN-%03d" % n for n in range(1, 15)])
# mirrors tools/requirements/main.go's own publicationACs (kept in sync by hand, same reason)
PUBLICATION_ACS = frozenset(["REQ-REL-001-AC1", "REQ-REL-002-AC1"])


def _parse_requirements(raw):
    """requirements/requirements.yaml bytes to (full, blocking): full maps every non-deprecated requirement's AC
    id to (its REAL parent requirement's own id, a comparable tuple) — the parent id comes from the YAML
    structure (r["id"]), never re-derived by splitting the AC's own id string (Sonnet #163 r1, Finding 1: an
    AC's id is just text an author chose; nothing stops a product AC being named REQ-SCAN-001-AC1, which
    would otherwise be classified pipeline-only by string shape alone — a separate Go validator enforces the
    ac.ID-starts-with-r.ID+"-AC" invariant in CI, but this function must not assume that ran). "Changed since
    the baseline" means ANY field in the tuple differs, the same fail-closed reading verify-freeze's byte-for-
    byte sha256 already gave non-pipeline content. blocking is the release-blocking subset as {(id, method,
    phase)}, the same shape release_blocking_acs already records."""
    import yaml
    d = yaml.safe_load(raw) or {}
    full, blocking = {}, set()
    for r in d.get("requirements") or []:
        if not isinstance(r, dict):
            continue
        # a deprecated requirement's ACs still enter `full` (Codex #163 r1, R02: a brand-new AC born
        # deprecated, or an existing one BECOMING deprecated, must still be seen as a change needing pipeline-
        # only classification under rule (b) — only the BLOCKING set, below, drops deprecated requirements
        deprecated, req_id = bool(r.get("deprecated")), r.get("id")
        for ac in r.get("acceptance_criteria") or []:
            v = ac.get("verification") or {}
            key = (ac.get("given"), ac.get("when"), ac.get("then"), v.get("method"), v.get("release_blocking"),
                   ac.get("status"), deprecated)
            full[ac["id"]] = (req_id, key)
            if deprecated:
                continue
            if v.get("release_blocking"):
                phase = "publication" if ac["id"] in PUBLICATION_ACS else "candidate"
                blocking.add((ac["id"], v.get("method"), phase))
    return full, blocking


def baseline(tag, baselines, baseline_requirements, requirements):
    """REQ-REL-009-AC13 (owner RATIFIED amendment, Oct 2) + 0126/0150: the approved ACs baseline a CI-signed
    patch tag uses. baselines: {version: the parsed requirements/releases/<version>.yaml} as owner_baselines()
    collects them — each read from an owner-SSH-signed release tag's own tree, never from the tagged commit
    (Codex #163 r1, B01); baseline_requirements: {version: requirements/requirements.yaml bytes at that SAME
    tag's own tree}; requirements: the bytes of requirements/requirements.yaml at the tagged commit. Returns
    (version, why) or (None, why): the LATEST owner-approved baseline of the tag's own X.Y line below the tag
    (an unapproved one is skipped, not a blocker: B02), and only if (a) the release-blocking AC set is
    identical to the baseline's AND (b) every AC added, removed or changed since the baseline belongs to a
    PIPELINE_ONLY requirement — both required (advisor 0150); otherwise no patch, it waits for the owner."""
    m = PATCH.match(tag)
    if not m:
        return None, "%s is not a patch tag" % tag
    line = []
    for v, d in baselines.items():
        b = PATCH.match(v) or re.match(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0)$", v)
        if not b or not isinstance(d, dict) or d.get("version") != v or b.group(1, 2) != m.group(1, 2):
            continue
        if int(b.group(3)) >= int(m.group(3)) or d.get("approved") is not True:
            continue
        try:
            datetime.date.fromisoformat(str(d.get("approved_on")))
        except ValueError:
            continue
        line.append((int(b.group(3)), v, d))
    if not line:
        return None, "no owner-approved ACs baseline on the v%s.%s line below %s: the patch waits for the owner" % (
            m.group(1), m.group(2), tag)
    _, v, d = max(line)
    # the content admission requires (Codex #163 pin pass, B03): decide's pre-check and admission refuse the same
    # baselines; a malformed latest one is no patch, never a fallback to an older one
    acs = d.get("release_blocking_acs")
    if not isinstance(acs, list) or not acs or not re.fullmatch(r"[0-9a-f]{40}", str(d.get("fixed_at"))):
        return None, "%s, the latest owner-approved baseline, is malformed (no blocking ACs or no fixed_at commit)" % v
    try:
        approved_blocking = {(e["id"], e["method"], e["phase"]) for e in acs}
    except (TypeError, KeyError):
        return None, "%s's release_blocking_acs entries are malformed" % v
    base_req = baseline_requirements.get(v)
    if base_req is None:
        return None, "%s's requirements/requirements.yaml at its own tag could not be read: no fallback" % v
    base_full, base_blocking = _parse_requirements(base_req)
    have_full, have_blocking = _parse_requirements(requirements)
    # rule (a) compares the CANDIDATE against the owner's APPROVED, verify-freeze-checked set (Codex #163 r1,
    # B01) -- never a fresh re-derivation from the baseline's own tree, which this function must not assume
    # already matches what was actually approved. The re-derivation (base_blocking) is still checked against
    # it as a sanity bound: a freeze whose own commit disagrees with what it claims is malformed, not a baseline.
    if base_blocking != approved_blocking:
        return None, "%s's approved release_blocking_acs does not match its own tag's requirements.yaml: malformed" % v
    if have_blocking != approved_blocking:
        return None, ("the release-blocking AC set changed since %s (%d ACs then, %d now): no automatic "
                      "patch; it waits for the owner" % (v, len(approved_blocking), len(have_blocking)))
    changed = [acid for acid in set(base_full) | set(have_full) if base_full.get(acid) != have_full.get(acid)]
    # the owning requirement comes from whichever side actually has this AC (its real parent in the YAML
    # structure, per _parse_requirements -- never re-derived from the AC's own id string, Sonnet #163 r1 F1)
    not_pipeline = sorted((acid, (have_full.get(acid) or base_full.get(acid))[0]) for acid in changed
                          if (have_full.get(acid) or base_full.get(acid))[0] not in PIPELINE_ONLY)
    if not_pipeline:
        acid, req_id = not_pipeline[0]
        return None, ("%s (requirement %s) changed since %s and is not on the pipeline-only list: no "
                      "automatic patch; it waits for the owner" % (acid, req_id, v))
    return v, "%s's approved ACs baseline; blocking set unchanged, every other change is pipeline-only" % v


def owner_baselines(tag, repo, allowed_signers, out):
    """Write <out>/<v>.yaml and <out>/<v>.requirements.yaml for every release tag v of the tag's X.Y line below
    it that is an annotated tag carrying the owner's SSH signature, verified by git verify-tag against
    allowed_signers (main's copy), each file read from THAT tag's own tree (git show
    v:requirements/releases/v.yaml and v:requirements/requirements.yaml — the second lets baseline() compare
    the full AC set, not just its blocking subset, advisor 0150). A CI-signed, unsigned, lightweight or
    other-key tag, and the tagged commit itself, never supply a baseline (Codex #163 r1, B01)."""
    m = PATCH.match(tag)
    os.makedirs(out, exist_ok=True)
    if not m:
        return []

    def git(*a):
        return subprocess.run(["git", "-C", repo, "-c", "gpg.ssh.allowedSignersFile=" + allowed_signers] + list(a),
                              capture_output=True, text=True)
    got = []
    for v in git("tag", "-l", "v%s.%s.*" % m.group(1, 2)).stdout.split():
        b = PATCH.match(v) or re.match(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0)$", v)
        if not b or b.group(1, 2) != m.group(1, 2) or int(b.group(3)) >= int(m.group(3)):
            continue
        if git("cat-file", "-t", "refs/tags/" + v).stdout.strip() != "tag":
            continue
        if kind(git("cat-file", "tag", "refs/tags/" + v).stdout) != "ssh" or git("verify-tag", v).returncode != 0:
            continue
        f = git("show", "%s:requirements/releases/%s.yaml" % (v, v))
        if f.returncode != 0:
            continue
        with open(os.path.join(out, v + ".yaml"), "w") as fh:
            fh.write(f.stdout)
        got.append(v)
        # the requirements.yaml write is independent (Codex #163 r1, B03): if IT fails while the freeze file
        # itself reads fine, this version must still appear as a candidate -- so baseline(), if it picks this
        # as the latest approved one, correctly refuses outright (no requirements to compare) rather than
        # silently falling back to an older, fully-readable baseline instead
        req = git("show", "%s:requirements/requirements.yaml" % v)
        if req.returncode == 0:
            with open(os.path.join(out, v + ".requirements.yaml"), "w") as fh:
                fh.write(req.stdout)
    return got


def _load_baselines(directory):
    """(freeze_dicts, requirements_bytes) — the two dicts baseline() needs, both keyed by version."""
    import yaml
    freeze, reqs = {}, {}
    for f in sorted(os.listdir(directory)):
        if re.match(r"^v[0-9]+\.[0-9]+\.[0-9]+\.yaml$", f):
            with open(os.path.join(directory, f)) as fh:
                freeze[f[:-len(".yaml")]] = yaml.safe_load(fh)
        elif re.match(r"^v[0-9]+\.[0-9]+\.[0-9]+\.requirements\.yaml$", f):
            with open(os.path.join(directory, f), "rb") as fh:
                reqs[f[:-len(".requirements.yaml")]] = fh.read()
    return freeze, reqs


def main(argv=None):
    ap = argparse.ArgumentParser(prog="admission-tag-signer")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("route")
    r.add_argument("--tag", required=True)
    r.add_argument("--tag-object", required=True, help="file holding `git cat-file tag <tag>`")
    r.add_argument("--tags", required=True, help="file listing the released tags, one per line (excluding this one)")
    b = sub.add_parser("baseline")
    b.add_argument("--tag", required=True)
    b.add_argument("--owner-baselines", required=True, help="the directory owner-baselines wrote")
    b.add_argument("--requirements", required=True, help="requirements/requirements.yaml at the tagged commit")
    o = sub.add_parser("owner-baselines")
    o.add_argument("--tag", required=True)
    o.add_argument("--repo", default=".")
    o.add_argument("--allowed-signers", required=True, help="main's .github/policy/allowed_signers")
    o.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    if a.cmd == "owner-baselines":
        got = owner_baselines(a.tag, a.repo, a.allowed_signers, a.out)
        print("owner-signed baselines: %s" % (" ".join(got) or "none"))
        return 0
    if a.cmd == "baseline":
        freeze, reqs = _load_baselines(a.owner_baselines)
        v, why = baseline(a.tag, freeze, reqs, open(a.requirements, "rb").read())
        print(("use %s" % v) if v else "no", why)
        return 0
    released = [t.strip() for t in open(a.tags) if t.strip() and t.strip() != a.tag]
    r, why = route(a.tag, open(a.tag_object).read(), released)
    print(r, why)
    return 0


if __name__ == "__main__":
    sys.exit(main())
