#!/usr/bin/env bash
# proves: REQ-REL-009-AC5, REQ-REL-009-AC6, REQ-REL-009-AC13, REQ-REL-009-AC8
# The words that say who signs an automatic patch tag (ops docs/ratify/2026-10-02-automatic-patch-releases.md and 2026-10-28-kms-signing-key-and-one-step-build.md):
# the CI deciding job creates, signs and pushes no tag; the one release KMS key signs the patch tag in the sign-tag job; the cut job alone pushes it; source admission
# accepts the owner's SSH signature on any tag and the release key's on a patch tag only; nothing keyless. This suite reads requirements/requirements.yaml (REQ-REL-009),
# docs/patch-releases.md and the shape of .github/policy/release_tag_signer. It never requires the shipped release_tag_signer to hold a real key: that file waits for a human
# to commit the real public key (REQ-BUILDAPK-001-AC8); when it exists it must be exactly one ssh-rsa line of allowed-signers format.
# Needs: bash, python3 + PyYAML.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
python3 -c 'import yaml' 2> /dev/null || { echo "FAIL PyYAML is required (apt: python3-yaml)"; exit 1; }
python3 -I - "$root" <<'PY'
import os, re, sys, yaml

root = sys.argv[1]
passed = failed = 0


def check(cond, msg):
    global passed, failed
    if cond:
        passed += 1
        print("ok   " + msg)
    else:
        failed += 1
        print("FAIL " + msg)


reqs = {r["id"]: r for r in yaml.safe_load(open(os.path.join(root, "requirements/requirements.yaml")))["requirements"]}
r9 = reqs["REQ-REL-009"]
ac = {a["id"]: a for a in r9["acceptance_criteria"]}
text = lambda a: " ".join(str(a.get(k, "")) for k in ("given", "when", "then"))
KMS = re.compile(r"KMS|release (signing )?key", re.I)
statement = " ".join(r9["statement"].split())
check(KMS.search(statement) is not None, "REQ-REL-009's statement says the release KMS key signs the patch tag")
check("keyless" not in re.sub(r"never by a keyless identity", "", statement), "REQ-REL-009's statement names keyless signing only to refuse it")
src = r9.get("source") or []
check(".github/workflows/release.yml" in src and not any("stage-sign" in x for x in src),
      "REQ-REL-009's source names release.yml (the decide, sign-tag, cut and patch-notes jobs are inline jobs of it) and no stage-sign.yml")
check("stage-sign" not in yaml.safe_dump(r9), "REQ-REL-009 names no stage-sign.yml anywhere (the file does not exist: there is no stage split)")
check(not any("stage-admission" in x for x in src), "REQ-REL-009's source no longer names stage-admission.yml (the file is gone: bin/build-admit.py admits)")
a5 = " ".join(text(ac["REQ-REL-009-AC5"]).split())
check(re.search(r"creates, signs and pushes no tag", a5) is not None, "AC5: the deciding job creates, signs and pushes no tag")
check("sign-tag" in a5 and re.search(r"\bcut\b", a5) is not None, "AC5 names the jobs by their names in release.yml: decide (deciding), sign-tag (signing) and cut (pushing)")
check("`tagged` is false" not in a5 and "until a signer" not in a5, "AC5 no longer says the output `tagged` is false until a signer exists (a signer exists: the release KMS key)")
check(KMS.search(a5) is not None and re.search(r"\bcut\b|\bcuts\b", a5) is not None and "admission" in a5,
      "AC5 says the release KMS key signs the tag, the cut job pushes it and source admission accepts it")
check("keyless" in a5 and "unsigned" in a5, "AC5 keeps the refusals: no keyless signing tool, an unsigned tag is never cut")
a6 = " ".join(text(ac["REQ-REL-009-AC6"]).split())
check(re.search(r"SSH", a6) is not None and KMS.search(a6) is not None and "patch" in a6,
      "AC6 names both signers: the owner's SSH signature and the release KMS key, and says the key signs patch tags")
check(re.search(r"any tag", a6) is not None, "AC6 says the owner's SSH signature is accepted for any tag")
check("keyless" in a6 and re.search(r"refused", a6) is not None, "AC6 says any other signer, a keyless identity included, is refused")
check("accepts only the maintainer's SSH signature" not in a6, "AC6 no longer says the owner's SSH signature is the only one accepted")
a13 = text(ac["REQ-REL-009-AC13"])
check("CI-signed" in a13, "AC13 speaks of a CI-signed patch tag")
check("gitsign" not in " ".join(str(r9.get("notes", "")).split()), "REQ-REL-009's notes name no gitsign signature (a generated patch tag's last signature is the SSH one)")
doc = open(os.path.join(root, "docs/patch-releases.md")).read().split("\n")
line3 = doc[2]
check("keyless" not in line3.lower(), "docs/patch-releases.md line 3 no longer says the patch tag is signed keylessly")
check(re.search(r"release signing key", line3) is not None, "docs/patch-releases.md line 3 says the one release signing key signs the patch tag")
rts = os.path.join(root, ".github/policy/release_tag_signer")
if os.path.exists(rts):
    raw = open(rts).read()
    lines = [l for l in raw.split("\n") if l.strip()]
    check(len(lines) == 1 and re.fullmatch(r"\S+ ssh-rsa [A-Za-z0-9+/]+=*( \S.*)?", lines[0]) is not None and "PRIVATE" not in raw,
          ".github/policy/release_tag_signer is exactly one `PRINCIPAL ssh-rsa KEY` line (allowed-signers format), never a private key")
else:
    check(True, ".github/policy/release_tag_signer is not committed yet (it waits for a human to commit the real public key: REQ-BUILDAPK-001-AC8)")
check(not os.path.exists(os.path.join(root, ".github/workflows/stage-admission.yml")), "stage-admission.yml stays gone")
check(not os.path.exists(os.path.join(root, ".github/workflows/stage-sign.yml")), "stage-sign.yml stays gone (the signing jobs are jobs of release.yml)")
# ---- bin/release-assets.sh posts the notes of a generated patch tag (the output of python3 -I -B bin/patch-decide.py tag-notes) with --notes-file, and the fixed text on every other tag ----
import shutil, subprocess, tempfile
ra = open(os.path.join(root, "bin/release-assets.sh")).read()
check("python3 -I -B bin/patch-decide.py tag-notes" in ra and "--notes-file" in ra, "release-assets.sh reads the notes with python3 -I -B bin/patch-decide.py tag-notes and passes them with --notes-file")
FIXED = "Evidence: see docs/verify-release.md for the verification commands of this release."
NOTES = "## v0.3.1 \u2014 patch release\n\n### Fixes\n- none (dependency or VEX maintenance only)\n\n### VEX\n- no change\n"
SIGBLOCK = "-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n"
TAGGER = "fosterstack release <release@users.noreply.github.com>"
scratch = tempfile.mkdtemp(prefix="patch-tag-texts.")
ENV = {"PATH": os.environ["PATH"], "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
       "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com", "HOME": scratch}
def git(cwd, *a, inp=None): return subprocess.run(["git", *a], cwd=cwd, env=ENV, input=inp, capture_output=True, text=True, check=True).stdout.strip()
def release_run(name, tagger, notes, signed=True, tag_object=True, script=None):
    """run the real bin/release-assets.sh in a scratch repository whose tag v0.3.1 is the given object, with a stub gh that logs its arguments (and keeps the --notes-file bytes); returns (exit, log, notes file text)"""
    r = os.path.join(scratch, name); os.makedirs(r + "/bin"); os.makedirs(r + "/release-upload"); os.makedirs(r + "/stub")
    open(r + "/bin/release-assets.sh", "w").write(ra if script is None else script); shutil.copy(os.path.join(root, "bin/patch-decide.py"), r + "/bin/")
    open(r + "/bin/release-metadata.py", "w").write("import sys\n"); open(r + "/release-upload/a.json", "w").write("{}")
    open(r + "/stub/gh", "w").write("""#!/usr/bin/env bash
echo "gh $*" >> "$LOGF"
case "$1 $2" in
  "release view") echo "release not found" >&2; exit 1 ;;
  "release create") while [ $# -gt 0 ]; do [ "$1" = --notes-file ] && cp "$2" "$LOGF.notes"; shift; done ;;
  "release download") mkdir -p "$4" ;;
esac
exit 0
""")
    os.chmod(r + "/stub/gh", 0o755)
    git(r, "init", "-q"); git(r, "commit", "-q", "--allow-empty", "-m", "c"); sha = git(r, "rev-parse", "HEAD")
    if tag_object:
        body = "object %s\ntype commit\ntag v0.3.1\ntagger %s 1700000000 +0000\n\n%s%s" % (sha, tagger, notes, SIGBLOCK if signed else "")
        git(r, "update-ref", "refs/tags/v0.3.1", git(r, "hash-object", "-t", "tag", "-w", "--stdin", inp=body))
    else:
        git(r, "tag", "v0.3.1")
    e = dict(ENV, PATH=r + "/stub:" + ENV["PATH"], GH_TOKEN="x", GITHUB_REF_NAME="v0.3.1", LOGF=r + "/log")
    p = subprocess.run(["bash", "bin/release-assets.sh"], cwd=r, env=e, capture_output=True, text=True)
    log = open(r + "/log").read() if os.path.exists(r + "/log") else ""
    nf = open(r + "/log.notes").read() if os.path.exists(r + "/log.notes") else None
    return p.returncode, log, nf, p.stderr
creates = lambda log: [l for l in log.splitlines() if l.startswith("gh release create")]
rc, log, nf, err = release_run("gen", TAGGER, NOTES)
def gen_ok(rc, log, nf): return rc == 0 and len(creates(log)) == 1 and "--notes-file" in creates(log)[0] and FIXED not in log and nf is not None and nf.rstrip("\n") == NOTES.rstrip("\n")
def other_ok(rc, log, nf): return rc == 0 and len(creates(log)) == 1 and FIXED in creates(log)[0] and "--notes-file" not in log and nf is None
check(gen_ok(rc, log, nf), "release-assets.sh on a generated patch tag creates the release with --notes-file holding the notes the tag carries, not the fixed text (exit %s)" % rc)
rc, log, nf, err = release_run("owner", "Some Owner <owner@example.com>", NOTES)
check(other_ok(rc, log, nf),
      "release-assets.sh on a tag signed by someone else (the owner's tag) keeps the fixed notes text and no --notes-file (exit %s)" % rc)
rc, log, nf, err = release_run("unsigned", TAGGER, NOTES, signed=False)
check(rc == 0 and len(creates(log)) == 1 and FIXED in creates(log)[0] and "--notes-file" not in log,
      "release-assets.sh on a tag object without a signature keeps the fixed notes text (exit %s)" % rc)
rc, log, nf, err = release_run("light", TAGGER, NOTES, tag_object=False)
check(rc == 0 and len(creates(log)) == 1 and FIXED in creates(log)[0] and "--notes-file" not in log,
      "release-assets.sh on a lightweight tag (no tag object) keeps the fixed notes text (exit %s)" % rc)
rc, log, nf, err = release_run("refused", TAGGER, NOTES.replace("no change", "-----BEGIN x"))
check(rc != 0 and not creates(log), "release-assets.sh on a generated tag whose notes hold a refused form stops with no release created (exit %s)" % rc)
# a check that cannot fail shows nothing: a copy of the script that always posts the fixed text, and one that posts the notes file on every tag, are both refused by the cases above
m1 = ra.replace('0) gh release create "$rel" --title "fscache $rel" --notes-file "$notes" --verify-tag ;;', '0) gh release create "$rel" --title "fscache $rel" --notes "' + FIXED + '" --verify-tag ;;')
m2 = ra.replace('1) gh release create "$rel" --title "fscache $rel" --notes "Evidence: see docs/verify-release.md for the verification commands of this release." --verify-tag ;;', '1) gh release create "$rel" --title "fscache $rel" --notes-file "$notes" --verify-tag ;;')
check(m1 != ra and not gen_ok(*release_run("mut1", TAGGER, NOTES, script=m1)[:3]), "a release-assets.sh that always posts the fixed text is refused by the generated-tag case")
check(m2 != ra and not other_ok(*release_run("mut2", "Some Owner <owner@example.com>", NOTES, script=m2)[:3]), "a release-assets.sh that posts the notes file on every tag is refused by the other-tag case")
shutil.rmtree(scratch)
print("pass=%d fail=%d" % (passed, failed))
sys.exit(1 if failed else 0)
PY
