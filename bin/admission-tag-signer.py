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


def baseline(tag, baselines, requirements):
    """REQ-REL-009-AC13 (owner RATIFIED amendment, Oct 2): the approved ACs baseline a CI-signed patch tag uses.
    baselines: {version: the parsed requirements/releases/<version>.yaml} as owner_baselines() collects them — each read
    from an owner-SSH-signed release tag's own tree, never from the tagged commit (Codex #163 r1, B01); requirements:
    the bytes of requirements/requirements.yaml at the tagged commit. Returns (version, why) or (None, why): the LATEST
    owner-approved baseline of the tag's own X.Y line below the tag (an unapproved one is skipped, not a blocker: B02),
    and only if the requirements are byte-for-byte unchanged since it (same requirements_sha256); otherwise no patch."""
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
    have = hashlib.sha256(requirements).hexdigest()
    if d.get("requirements_sha256") != have:
        return None, ("the requirements changed since %s (%s, now %s): no automatic patch; it waits for the owner"
                      % (v, str(d.get("requirements_sha256"))[:12], have[:12]))
    return v, "%s's approved ACs baseline, requirements unchanged since it" % v


def owner_baselines(tag, repo, allowed_signers, out):
    """Write <out>/<v>.yaml for every release tag v of the tag's X.Y line below it that is an annotated tag carrying
    the owner's SSH signature, verified by git verify-tag against allowed_signers (main's copy), each file read from
    THAT tag's own tree (git show v:requirements/releases/v.yaml). A CI-signed, unsigned, lightweight or other-key tag,
    and the tagged commit itself, never supply a baseline (Codex #163 r1, B01)."""
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
        if f.returncode == 0:
            with open(os.path.join(out, v + ".yaml"), "w") as fh:
                fh.write(f.stdout)
            got.append(v)
    return got


def _load_baselines(directory):
    import yaml
    out = {}
    for f in sorted(os.listdir(directory)):
        if f.endswith(".yaml") and re.match(r"^v[0-9]+\.[0-9]+\.[0-9]+\.yaml$", f):
            with open(os.path.join(directory, f)) as fh:
                out[f[:-len(".yaml")]] = yaml.safe_load(fh)
    return out


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
        v, why = baseline(a.tag, _load_baselines(a.owner_baselines), open(a.requirements, "rb").read())
        print(("use %s" % v) if v else "no", why)
        return 0
    released = [t.strip() for t in open(a.tags) if t.strip() and t.strip() != a.tag]
    r, why = route(a.tag, open(a.tag_object).read(), released)
    print(r, why)
    return 0


if __name__ == "__main__":
    sys.exit(main())
