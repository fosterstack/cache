#!/usr/bin/env bash
# proves: REQ-REL-009-AC6, REQ-REL-009-AC13
# Which signer source admission accepts for a release tag (automatic patch releases rule 3; advisor 0057): the owner's
# SSH signature (allowed-signers) on any tag; the release.yml-on-main gitsign identity on a PATCH tag only (vX.Y.Z,
# Z >= 1, the previous patch vX.Y.(Z-1) already released); an unsigned tag, any other signature format, an ambiguous
# tag object, or the CI identity on a minor, major or rc tag is refused. The route only picks the verifier; the
# verifier (git verify-tag against allowed-signers, or gitsign verify-tag with the identity pinned) still has to pass.
# The second half of this file judged the wiring of stage-admission.yml (policy from protected main; gitsign verify-tag pinning the identity,
# issuer, repository, ref and tagged commit; the baseline rules). PR 2 of the v0.3.0 chain removed that workflow: admission is the first step of
# Build's apk job (bin/build-admit.py) and the same properties are judged by bin/chain-build-admit-test.sh (REQ-CHAIN-004-AC4, AC5).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd); root=$(cd "$here/.." && pwd)
python3 - "$here/admission-tag-signer.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("ts", sys.argv[1]); T = importlib.util.module_from_spec(spec); spec.loader.exec_module(T)
passed = failed = 0
def check(name, ok, got=""):
    global passed, failed
    if ok: passed += 1; print("ok:", name)
    else: failed += 1; print("FAIL:", name, "->", got)
HEAD = "object 0123\ntype commit\ntag v0.2.2\ntagger x <x> 1 +0000\n\nautomatic patch release v0.2.2\n"
SSH = HEAD + "-----BEGIN SSH SIGNATURE-----\nU1NIU0lH\n-----END SSH SIGNATURE-----\n"
X509 = HEAD + "-----BEGIN SIGNED MESSAGE-----\nMIIF\n-----END SIGNED MESSAGE-----\n"
PGP = HEAD + "-----BEGIN PGP SIGNATURE-----\niQ\n-----END PGP SIGNATURE-----\n"
for obj, want in [(SSH, "ssh"), (X509, "x509"), (PGP, "pgp"), (HEAD, "none"),
                  (HEAD + "-----BEGIN SSH SIGNATURE-----\nA\n-----END SSH SIGNATURE-----\n-----BEGIN SIGNED MESSAGE-----\nB\n-----END SIGNED MESSAGE-----\n", "ambiguous"),
                  (HEAD.replace("automatic patch release v0.2.2", "notes quoting -----BEGIN SIGNED MESSAGE----- inline") , "none"),
                  # Codex #163 r1 B03: a PEM-style block that is not a signature (release notes quoting a key or a
                  # certificate example) is message text; the owner's signature after it still routes to ssh
                  (HEAD + "-----BEGIN EXAMPLE-----\nmessage text\n-----END EXAMPLE-----\n" + SSH[len(HEAD):], "ssh"),
                  (HEAD + "-----BEGIN CERTIFICATE-----\nMII\n-----END CERTIFICATE-----\n" + X509[len(HEAD):], "x509"),
                  # a second SIGNATURE-labelled block anywhere is still ambiguous (git would read the first as the signature)
                  (HEAD + "-----BEGIN PGP SIGNATURE-----\nx\n-----END PGP SIGNATURE-----\nmore\n" + SSH[len(HEAD):], "ambiguous"),
                  (HEAD + "-----BEGIN EXAMPLE-----\nmessage text\n-----END EXAMPLE-----\n", "none")]:
    got = T.kind(obj)
    check("kind -> %s" % want, got == want, got)
REL = ["v0.1.0", "v0.2.0", "v0.2.1"]
for tag, obj, tags, want, why in [
    ("v0.2.2", X509, REL, "gitsign", "the CI identity on the next patch"),
    ("v0.3.0", X509, REL, "refuse", "the CI identity on a minor tag"),
    ("v1.0.0", X509, REL, "refuse", "the CI identity on a major tag"),
    ("v0.2.3", X509, REL, "refuse", "the CI identity skipping a patch (v0.2.2 not released)"),
    ("v0.2.2-rc.1", X509, REL, "refuse", "the CI identity on an rc"),
    ("v0.4.1", X509, REL, "refuse", "the CI identity on a line with no owner release"),
    ("v0.2.2", SSH, REL, "ssh", "the owner on a patch"),
    ("v0.3.0", SSH, REL, "ssh", "the owner on a minor"),
    ("v0.2.2", HEAD, REL, "refuse", "an unsigned tag (the App pushed it unsigned)"),
    ("v0.2.2", PGP, REL, "refuse", "a PGP signature"),
    ("v0.2.2", SSH + "-----BEGIN SIGNED MESSAGE-----\nB\n-----END SIGNED MESSAGE-----\n", REL, "refuse", "two signatures"),
    ("v0.2.1", X509, REL, "refuse", "the CI identity re-signing an existing tag"),
]:
    got = T.route(tag, obj, tags)
    check("route: %s -> %s" % (why, want), got[0] == want, got)
import hashlib, json, os, tempfile, io, contextlib
d = tempfile.mkdtemp(); o = os.path.join(d, "obj"); open(o, "w").write(X509); t = os.path.join(d, "tags"); open(t, "w").write("\n".join(REL) + "\n")
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    rc = T.main(["route", "--tag", "v0.2.2", "--tag-object", o, "--tags", t])
check("CLI prints the route first", rc == 0 and buf.getvalue().split()[0] == "gitsign", buf.getvalue())

# --- REQ-REL-009-AC13 (owner RATIFIED, Oct 2) + 0126/0150: which approved ACs baseline a CI patch uses
def req_yaml(entries):
    """entries: [(req_id, ac_id, blocking)] -- req_id may be a plain string, or (req_id, deprecated_bool) to
    mark the WHOLE requirement deprecated. A minimal, real requirements.yaml _parse_requirements can read:
    one requirement per distinct req_id, one AC per entry, given/when/then/status fixed (irrelevant here
    except as "did this AC's content change")."""
    by_req = {}
    deprecated = {}
    for req_id, ac_id, blocking in entries:
        if isinstance(req_id, tuple):
            req_id, dep = req_id
            deprecated[req_id] = dep
        by_req.setdefault(req_id, []).append((ac_id, blocking))
    lines = ["requirements:"]
    for req_id, acs in by_req.items():
        lines.append("  - id: %s" % req_id)
        if deprecated.get(req_id):
            lines.append("    deprecated: true")
        lines.append("    acceptance_criteria:")
        for ac_id, blocking in acs:
            lines += ["      - id: %s" % ac_id, "        given: g", "        when: w", "        then: t",
                      "        verification: {method: unit, release_blocking: %s}" % ("true" if blocking else "false"),
                      "        status: approved"]
    return ("\n".join(lines) + "\n").encode()
def blocking_acs(entries):
    return [{"id": a, "method": "unit", "phase": "candidate"} for _, a, blocking in entries if blocking]
BASE = [("REQ-X-001", "REQ-X-001-AC1", True)]
REQ = req_yaml(BASE)
ACS = blocking_acs(BASE)
def bl(v, approved=True, acs=ACS, fixed="a" * 40):
    return {"version": v, "approved": approved, "approved_on": "2026-09-29", "release_blocking_acs": acs, "fixed_at": fixed}
PIPE = T.PIPELINE_ONLY
not_pipe_req = next(r for r in ["REQ-X-001", "REQ-Y-002"] if r not in PIPE)       # any product-classified id
pipe_req = next(iter(PIPE))                                                       # any pipeline-only id
for tag, bls, breqs, req, want, why in [
    ("v0.2.2", [bl("v0.2.0"), bl("v0.2.1")], {"v0.2.1": REQ}, REQ, "v0.2.1", "v0.2.2 uses v0.2.1's baseline"),
    ("v0.2.3", [bl("v0.2.0"), bl("v0.2.1")], {"v0.2.1": REQ}, REQ, "v0.2.1", "the latest approved of its line, even two patches back"),
    # advisor 0150: rule (a), the release-blocking AC set must be identical -- a product AC's method changing breaks it
    ("v0.2.2", [bl("v0.2.0"), bl("v0.2.1")], {"v0.2.1": REQ},
     req_yaml([("REQ-X-001", "REQ-X-001-AC1", False)]), None, "a blocking AC became non-blocking: the set changed"),
    # rule (b): a NEW product AC (not on PIPELINE_ONLY) refuses, even though it's non-blocking and (a) still holds
    ("v0.2.2", [bl("v0.2.0"), bl("v0.2.1")], {"v0.2.1": REQ},
     req_yaml(BASE + [(not_pipe_req, not_pipe_req + "-AC1", False)]), None,
     "a new product AC since the baseline: no automatic patch"),
    # Sonnet #163 r1, F1: classification must come from the AC's REAL parent requirement (the YAML structure),
    # never from re-deriving it by splitting the AC's own id string -- a product AC spelled to LOOK
    # pipeline-only (nested under a product requirement, but named "<pipeline-only-id>-AC1") must still refuse
    ("v0.2.2", [bl("v0.2.0"), bl("v0.2.1")], {"v0.2.1": REQ},
     req_yaml(BASE + [(not_pipe_req, pipe_req + "-AC1", False)]), None,
     "an AC spelled like a pipeline-only id but really under a product requirement: still refused"),
    # Codex #163 r1, R02: a NEW, non-blocking product AC born deprecated must still be seen as a change
    # needing pipeline-only classification -- deprecated requirements are excluded only from the BLOCKING
    # set, never from the full AC comparison rule (b) runs. Codex #163 r2c, R01: this must use a DISTINCT
    # requirement/AC id from BASE's own, or the fixture accidentally clobbers BASE's blocking AC (same id,
    # overwritten by dict assignment) and rule (a) refuses first, never exercising rule (b) at all
    ("v0.2.2", [bl("v0.2.0"), bl("v0.2.1")], {"v0.2.1": REQ},
     req_yaml(BASE + [((not_pipe_req + "-NEW", True), not_pipe_req + "-NEW-AC1", False)]), None,
     "a new AC born deprecated under a DIFFERENT product requirement: still a change, still refused"),
    # rule (b): a new PIPELINE-ONLY AC is fine, blocking set (a) still holds
    ("v0.2.2", [bl("v0.2.0"), bl("v0.2.1")], {"v0.2.1": REQ},
     req_yaml(BASE + [(pipe_req, pipe_req + "-AC1", False)]), "v0.2.1",
     "a new pipeline-only AC since the baseline: still an automatic patch"),
    # advisor 0175 (REQ-SUP-001): the actions supply-chain checks govern CI, not the server, the image or a doc
    ("v0.2.2", [bl("v0.2.0"), bl("v0.2.1")], {"v0.2.1": REQ},
     req_yaml(BASE + [("REQ-SUP-001", "REQ-SUP-001-AC1", False), ("REQ-SUP-001", "REQ-SUP-001-AC10", False)]), "v0.2.1",
     "REQ-SUP-001 (actions supply-chain checks) is pipeline-only: its ACs appearing since the baseline still allow an automatic patch"),
    # a CHANGED pipeline-only AC (same id, different wording/method) is also fine under (b)
    ("v0.2.2", [bl("v0.2.0"), bl("v0.2.1", acs=blocking_acs(BASE + [(pipe_req, pipe_req + "-AC1", False)]))],
     {"v0.2.1": req_yaml(BASE + [(pipe_req, pipe_req + "-AC1", False)])},
     req_yaml(BASE + [(pipe_req, pipe_req + "-AC1", True)]), None,
     "a pipeline-only AC BECOMING blocking changes the set (a): still refused"),
    ("v0.2.2", [bl("v0.2.0"), bl("v0.2.1")], {}, REQ, None, "the baseline's own requirements.yaml could not be read: no fallback"),
    # Codex #163 r1, B01: rule (a) must compare the CANDIDATE against the owner's APPROVED, verified
    # release_blocking_acs -- never a fresh re-derivation from the baseline's own tree, which might not match
    # what was actually approved (a stale or forged freeze). Here the approved list claims a method the
    # baseline's own requirements.yaml does not actually have: malformed, not usable, even if the candidate
    # matches the baseline's tree exactly
    ("v0.2.2", [bl("v0.2.0"), bl("v0.2.1", acs=[{"id": "REQ-X-001-AC1", "method": "WRONG", "phase": "candidate"}])],
     {"v0.2.1": REQ}, REQ, None, "the approved baseline's release_blocking_acs disagrees with its own tree: malformed"),
    # Codex #163 r1 B02: the latest OWNER-APPROVED baseline (an unapproved newer one is skipped, never a blocker)
    ("v0.2.2", [bl("v0.2.0"), bl("v0.2.1", approved=False)], {"v0.2.0": REQ, "v0.2.1": REQ}, REQ, "v0.2.0",
     "an unapproved newer baseline is skipped: the latest approved is used"),
    ("v0.2.2", [bl("v0.2.1", approved=False)], {"v0.2.1": REQ}, REQ, None, "no approved baseline on the line: no cut, it waits for the owner"),
    ("v0.2.2", [bl("v0.2.1", approved="true")], {"v0.2.1": REQ}, REQ, None, "approved must be boolean true"),
    ("v0.2.2", [bl("v0.1.9"), bl("v0.3.0")], {"v0.1.9": REQ, "v0.3.0": REQ}, REQ, None, "no baseline on its own X.Y line"),
    ("v0.2.2", [bl("v0.2.1"), bl("v0.2.4")], {"v0.2.1": REQ, "v0.2.4": REQ}, REQ, "v0.2.1", "a baseline above the tag is never used"),
    # Codex #163 pin pass B03: the content admission requires is checked here too, and a malformed latest approved
    # baseline is no patch — never a fallback to an older one
    ("v0.2.2", [bl("v0.2.0"), bl("v0.2.1", acs=[])], {"v0.2.0": REQ, "v0.2.1": REQ}, REQ, None, "an empty release_blocking_acs: no patch, no fallback"),
    ("v0.2.2", [bl("v0.2.0"), bl("v0.2.1", acs=None)], {"v0.2.0": REQ, "v0.2.1": REQ}, REQ, None, "no release_blocking_acs list"),
    ("v0.2.2", [bl("v0.2.0"), bl("v0.2.1", fixed="main")], {"v0.2.0": REQ, "v0.2.1": REQ}, REQ, None, "fixed_at is not a full commit id"),
    ("v0.3.0", [bl("v0.2.1")], {"v0.2.1": REQ}, REQ, None, "a minor is not a CI patch"),
    ("v0.2.2", [dict(bl("v0.2.1"), version="v0.2.0")], {"v0.2.1": REQ}, REQ, None, "a file whose version is not its name is ignored"),
]:
    bmap = {b["version"]: b for b in bls} if "not its name" not in why else {"v0.2.1": bls[0]}
    got = T.baseline(tag, bmap, breqs, req)
    check("baseline: %s -> %s" % (why, want), got[0] == want, got)
rd = os.path.join(d, "releases"); os.makedirs(rd)
for v in ("v0.2.0", "v0.2.1"):
    open(os.path.join(rd, v + ".yaml"), "w").write("version: %s\napproved: true\napproved_on: 2026-09-29\n"
        "fixed_at: %s\nrelease_blocking_acs:\n  - {id: REQ-X-001-AC1, method: unit, phase: candidate}\n" % (v, "a" * 40))
    with open(os.path.join(rd, v + ".requirements.yaml"), "wb") as fh:
        fh.write(REQ)
open(os.path.join(rd, "README.md"), "w").write("not a baseline\n")
rq = os.path.join(d, "req.yaml"); open(rq, "wb").write(REQ)
for req_bytes, want in ((REQ, "use v0.2.1"), (req_yaml(BASE + [(not_pipe_req, not_pipe_req + "-AC1", False)]), "no")):
    open(rq, "wb").write(req_bytes)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = T.main(["baseline", "--tag", "v0.2.2", "--owner-baselines", rd, "--requirements", rq])
    check("baseline CLI -> %s" % want, rc == 0 and buf.getvalue().startswith(want + (" " if want == "no" else "")), buf.getvalue())
# --- Codex #163 r1 B01: a baseline counts only from an owner-signed release tag, read from that tag's own tree
import subprocess, tempfile
def run(*a, cwd=None, inp=None):
    return subprocess.run(list(a), cwd=cwd, input=inp, capture_output=True, text=True,
                          env=dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@x", GIT_COMMITTER_NAME="t",
                                   GIT_COMMITTER_EMAIL="t@x", GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_SYSTEM="/dev/null"))
g = tempfile.mkdtemp(); keys = tempfile.mkdtemp()
for k in ("owner", "other"):
    run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", k, "-f", os.path.join(keys, k))
allowed = os.path.join(keys, "allowed_signers")
open(allowed, "w").write("owner@x " + open(os.path.join(keys, "owner.pub")).read())
run("git", "init", "-q", "-b", "main", cwd=g)
def commit_baselines(vs, approved=True, req=REQ, acs=ACS):
    os.makedirs(os.path.join(g, "requirements", "releases"), exist_ok=True)
    open(os.path.join(g, "requirements", "requirements.yaml"), "wb").write(req)
    acs_yaml = "".join("  - {id: %s, method: %s, phase: %s}\n" % (a["id"], a["method"], a["phase"]) for a in acs)
    for v in vs:
        open(os.path.join(g, "requirements", "releases", v + ".yaml"), "w").write(
            "version: %s\napproved: %s\napproved_on: 2026-09-29\nrequirements_sha256: %s\nfixed_at: %s\n"
            "release_blocking_acs:\n%s" % (v, "true" if approved else "false", hashlib.sha256(req).hexdigest(),
                                           "a" * 40, acs_yaml))
    run("git", "add", "-A", cwd=g); run("git", "commit", "-qm", "c", cwd=g)
def tag(v, key=None):
    if key:
        run("git", "-c", "gpg.format=ssh", "-c", "user.signingkey=" + os.path.join(keys, key), "tag", "-s", "-m", v, v, cwd=g)
    else:
        run("git", "tag", "-a", "-m", v, v, cwd=g)
commit_baselines(["v0.2.0"]); tag("v0.2.0", "owner")
commit_baselines(["v0.2.0", "v0.2.1"]); tag("v0.2.1", "other")            # signed by a key not in allowed_signers
commit_baselines(["v0.2.0", "v0.2.1", "v0.2.3"]); tag("v0.2.3")           # annotated, unsigned
commit_baselines(["v0.2.0", "v0.2.1", "v0.2.3", "v0.2.4"]); run("git", "tag", "v0.2.4", cwd=g)   # lightweight
commit_baselines(["v0.2.0", "v0.2.1", "v0.2.3", "v0.2.4", "v0.2.5"])     # the tagged commit's own, self-approved
out = os.path.join(g, "owner-baselines")
rc = T.main(["owner-baselines", "--tag", "v0.2.5", "--repo", g, "--allowed-signers", allowed, "--out", out])
got = sorted(os.listdir(out)) if os.path.isdir(out) else None
check("B01 only owner-SSH-signed tags of the line, below the tag, supply a baseline (v0.2.0)",
      rc == 0 and got == sorted(["v0.2.0.yaml", "v0.2.0.requirements.yaml"]), got)
check("B01 the baseline is read from the owner tag's own tree", open(os.path.join(out, "v0.2.0.yaml")).read().startswith("version: v0.2.0"))
freeze, reqs = T._load_baselines(out)
v, why = T.baseline("v0.2.5", freeze, reqs, open(os.path.join(g, "requirements", "requirements.yaml"), "rb").read())
check("B01 the tagged commit's self-approved baselines are never used: v0.2.5 -> v0.2.0", v == "v0.2.0", (v, why))
commit_baselines(["v0.2.0"], req=req_yaml(BASE + [(not_pipe_req, not_pipe_req + "-AC1", False)]))
rc = T.main(["owner-baselines", "--tag", "v0.2.6", "--repo", g, "--allowed-signers", allowed, "--out", out + "2"])
freeze2, reqs2 = T._load_baselines(out + "2")
v, why = T.baseline("v0.2.6", freeze2, reqs2, open(os.path.join(g, "requirements", "requirements.yaml"), "rb").read())
check("B01 requirements changed since the owner's baseline: no patch", v is None and "not on the pipeline-only list" in why, (v, why))
# Codex #163 r1, B03: the latest approved tag's requirements.yaml missing at its OWN commit (freeze file still
# readable) must not silently fall back to an older, fully-readable baseline -- it must appear as a candidate
# so baseline() refuses outright ("no fallback")
g2 = tempfile.mkdtemp(); run("git", "init", "-q", "-b", "main", cwd=g2)
os.makedirs(os.path.join(g2, "requirements", "releases"), exist_ok=True)
open(os.path.join(g2, "requirements", "requirements.yaml"), "wb").write(REQ)
open(os.path.join(g2, "requirements", "releases", "v0.2.0.yaml"), "w").write(
    "version: v0.2.0\napproved: true\napproved_on: 2026-09-29\nfixed_at: %s\nrelease_blocking_acs:\n%s"
    % ("a" * 40, "".join("  - {id: %s, method: %s, phase: %s}\n" % (a["id"], a["method"], a["phase"]) for a in ACS)))
run("git", "add", "-A", cwd=g2); run("git", "commit", "-qm", "c0", cwd=g2); tag_v020 = run("git", "rev-parse", "HEAD", cwd=g2)
run("git", "-c", "gpg.format=ssh", "-c", "user.signingkey=" + os.path.join(keys, "owner"), "tag", "-s", "-m", "v0.2.0", "v0.2.0", cwd=g2)
open(os.path.join(g2, "requirements", "releases", "v0.2.1.yaml"), "w").write(
    "version: v0.2.1\napproved: true\napproved_on: 2026-09-29\nfixed_at: %s\nrelease_blocking_acs:\n%s"
    % ("a" * 40, "".join("  - {id: %s, method: %s, phase: %s}\n" % (a["id"], a["method"], a["phase"]) for a in ACS)))
os.remove(os.path.join(g2, "requirements", "requirements.yaml"))   # v0.2.1's own commit has NO requirements.yaml
run("git", "add", "-A", cwd=g2); run("git", "commit", "-qm", "c1", cwd=g2)
run("git", "-c", "gpg.format=ssh", "-c", "user.signingkey=" + os.path.join(keys, "owner"), "tag", "-s", "-m", "v0.2.1", "v0.2.1", cwd=g2)
open(os.path.join(g2, "requirements", "requirements.yaml"), "wb").write(REQ)   # the tagged (v0.2.2) commit's own copy
run("git", "add", "-A", cwd=g2); run("git", "commit", "-qm", "c2", cwd=g2)
out3 = os.path.join(g2, "owner-baselines")
rc = T.main(["owner-baselines", "--tag", "v0.2.2", "--repo", g2, "--allowed-signers", allowed, "--out", out3])
got3 = sorted(os.listdir(out3)) if os.path.isdir(out3) else None
check("B03 a readable freeze with an unreadable requirements.yaml still appears as a candidate",
      got3 == ["v0.2.0.requirements.yaml", "v0.2.0.yaml", "v0.2.1.yaml"], got3)
freeze3, reqs3 = T._load_baselines(out3)
v, why = T.baseline("v0.2.2", freeze3, reqs3, REQ)
check("B03 the latest approved baseline's unreadable requirements refuses outright, no fallback to v0.2.0",
      v is None and "could not be read" in why, (v, why))
try:
    T.main(["baseline", "--tag", "v0.2.2", "--releases-dir", rd, "--requirements", rq]); got = "accepted"
except SystemExit:
    got = "refused"
check("B01 the old --releases-dir (a directory of any origin) is gone", got == "refused", got)
print("admission-tag-signer: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
PY
