#!/usr/bin/env bash
# proves: REQ-REL-009-AC5
# Handoff 0713 P8 (orchestrator ruling R6, owner's Oct 28 rule 2 "no keyless signing anywhere"): the keyless tag
# signers of the automatic patch release are out. The words below name them: gitsign, smimesign, and the git settings
# that make git sign with an X.509 certificate (gpg.format=x509, gpg.x509.program). No tracked file that is code, a
# workflow or policy names one (the two detectors below excepted): not an installer entry, a pinned version, a
# workflow step, a policy row, a verifier route or a tool list. Tests and documents may still say the words (this
# test, the tests that prove a keyless signature is refused, the history in docs/). Who creates, signs and pushes a tag is the
# release judges' job (bin/chain-release-shape.py, bin/chain-tag-jobs-test.sh); here: the deciding job names no signing tool,
# and the one job that signs a tag (sign-tag, a job of release.yml: there is no stage-sign.yml) names no keyless one.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
python3 -I - "$root" <<'PY'
import json
import os
import re
import subprocess
import sys

root = sys.argv[1]
listing = subprocess.run(["git", "-C", root, "ls-files", "-z"], capture_output=True, check=True)
files = listing.stdout.decode().split("\0")
# not scanned: documents and history, evidence, and every test (a test may name what it proves is refused)
SKIP = re.compile(r"^(docs/|requirements/|results/|test-evidence/)|(^|/)tests?/|-test\.(sh|py)$"
                  r"|(^|/)test_[^/]*\.py$|\.md$")
WORDS = re.compile(r"gitsign|smimesign|gpg\.format[\s=]+x509|gpg\.x509\.program", re.I)
passed = failed = 0


def unquote(text):
    """Quotes are dropped first, so a quoted value (gpg.format 'x509') cannot hide the word."""
    return text.replace("'", "").replace('"', "")


def names_signer(text):
    return WORDS.search(unquote(text))


def check(cond, msg):
    global passed, failed
    if cond:
        passed += 1
        print("ok   " + msg)
    else:
        failed += 1
        print("FAIL " + msg)


# the word list itself: each word is found in any case, and ordinary text is not
for word in ("gitsign", "smimesign", "gpg.format=x509", "gpg.x509.program"):
    check(names_signer("run: " + word + " sign") and names_signer("run: " + word.upper() + " sign") and
          names_signer("run: " + word.title() + " sign"), "the scan finds %s in lower, upper and title case" % word)
check(names_signer("git -c gpg.format = x509 tag -s v1"),
      "the scan finds gpg.format = x509 with spaces around the equals sign")
check(names_signer("git config gpg.format x509"),
      "the scan finds the config form git config gpg.format x509 (a space, no equals sign)")
for form in ("git config gpg.format 'x509'", 'git config gpg.format "x509"', "git -c gpg.format=x509 tag -s v1",
             "git -c 'gpg.format=x509' tag -s v1", 'git -c "gpg.format=x509" tag -s v1'):
    check(names_signer(form), "the scan finds the quoted or -c form: %s" % form)
check(not names_signer("git tag -s v1 with gpg.format=ssh and a signing key"),
      "the scan does not flag an SSH-signed tag")

# three files keep the words on purpose, because they DETECT them: the signer table that makes any use of gitsign in
# a chain file an unlisted signer (bin/chain-test-signers.json), the shape judge's list of signing words
# (bin/chain-check-shape.py) and the tag-jobs judge, whose regexes refuse any tag job that uses them
# (bin/chain-tag-jobs-judge.py)
DETECTORS = {"bin/chain-test-signers.json", "bin/chain-check-shape.py", "bin/chain-tag-jobs-judge.py"}
hits = {}
for f in files:
    if not f or SKIP.search(f) or f in DETECTORS:
        continue
    try:
        text = open(root + "/" + f, errors="ignore").read()
    except OSError:
        continue
    n = len(WORDS.findall(unquote(text)))
    if n:
        hits[f] = n
check(not hits, "no tracked code, workflow or policy file names a keyless tag signer%s"
      % ("" if not hits else ": " + ", ".join("%s (%d)" % kv for kv in sorted(hits.items()))))
inst = open(root + "/bin/install-scanner.sh").read()
check(not re.search(r"GITSIGN|sigstore/gitsign", inst, re.I), "bin/install-scanner.sh installs no gitsign")
import yaml
KEYLESS = re.compile(r"cosign|fulcio|sigstore|keyless|gitsign|smimesign|identity-token|oidc", re.I)
SIGN_TAG_KEYLESS = re.compile(r"fulcio|sigstore|keyless|gitsign|smimesign|identity-token|cosign (sign|attest)|gpg\.format|gpg\.x509", re.I)


def tag_job_faults(rel):
    """the faults of the tag jobs of release.yml (its text): decide names no signing tool, key, role, id-token or App token and makes no tag; the one job that signs a tag, sign-tag
    (a job of release.yml: there is no stage-sign.yml), names no keyless tool and at most one KMS key; the text itself signs no tag"""
    bad = []
    if re.search(r"tag -s|keylessly|ssh-keygen -Y sign", rel):
        bad.append("release.yml signs a tag itself: `tag -s`, an ssh-keygen signing or a keyless signing")
    jobs = (yaml.safe_load(rel) or {}).get("jobs") or {}
    decide = json.dumps(jobs.get("decide", {}))
    if "decide" not in jobs: bad.append("release.yml has no job `decide`")
    elif KEYLESS.search(decide) or re.search(r"kms|AWS_|id-token|create-github-app-token|AUDITOR_APP", decide, re.I):
        bad.append("the decide job names a keyless signing tool, a KMS key or role, an id-token or an App token")
    if "decide" in jobs and re.search(r"git\s+(tag|push)\b|tag -s|git/(refs|tags)|verify-tag", decide):
        bad.append("the decide job creates, signs, verifies or pushes a tag")
    st = json.dumps(jobs.get("sign-tag", {}))
    if "sign-tag" not in jobs: bad.append("release.yml has no job `sign-tag` (the one job that signs a tag)")
    else:
        if SIGN_TAG_KEYLESS.search(st): bad.append("the sign-tag job names a keyless signing tool or an x509 setting")
        if len(re.findall(r"alias/", st)) > 1: bad.append("the sign-tag job names more than one KMS key")
    for n in ("cut", "patch-notes"):
        if n in jobs and SIGN_TAG_KEYLESS.search(json.dumps(jobs[n])): bad.append("the %s job names a keyless signing tool or an x509 setting" % n)
    return bad


rel = open(root + "/.github/workflows/release.yml").read()
f = tag_job_faults(rel)
check(not f, "release.yml: decide names no keyless tool, key, role, id-token or App token and makes no tag; sign-tag (the one KMS key signs in release.yml, no stage-sign.yml) names no keyless tool and at most one key; "
      "no tag is signed outside it%s" % ("" if not f else ": " + "; ".join(f)))
check(os.path.exists(root + "/.github/workflows/release.yml") and not os.path.exists(root + "/.github/workflows/stage-sign.yml"), "there is no stage-sign.yml: the signing jobs are jobs of release.yml")
# a check that cannot fail shows nothing: the same checks refuse a mutated copy of the real file
def after(text, anchor, add): return text.replace(anchor, anchor + add, 1)
MUT = (("decide names gitsign", after(rel, "  decide:\n", "    env:\n      X: gitsign\n")),
       ("decide names the release role", after(rel, "  decide:\n", "    env:\n      AWS_ROLE_ARN: x\n")),
       ("decide pushes a tag", rel.replace("      - name: decide (bin/patch-decide.py)\n", "      - run: git push origin refs/tags/v9.9.9\n      - name: decide (bin/patch-decide.py)\n", 1)),
       ("decide mints the App token", after(rel, "  decide:\n", "    env:\n      X: create-github-app-token\n")),
       ("sign-tag names cosign sign", rel.replace("      - name: put the signature into the tag object\n", "      - run: cosign sign --identity-token x y\n      - name: put the signature into the tag object\n", 1)),
       ("sign-tag sets gpg.format x509", rel.replace("      - name: put the signature into the tag object\n", "      - run: git config gpg.format x509\n      - name: put the signature into the tag object\n", 1)),
       ("sign-tag names a second key", rel.replace("          name: signed-tag\n          path: tag-work/tag.signed\n", "          name: signed-tag\n          path: tag-work/tag.signed\n          x: alias/other-key\n", 1)),
       ("cut names smimesign", after(rel, "\n  cut:\n", "    env:\n      X: smimesign\n")),
       ("a step signs the tag with tag -s", rel.replace("      - name: decide (bin/patch-decide.py)\n", "      - run: git tag -s v9.9.9 -m x\n      - name: decide (bin/patch-decide.py)\n", 1)),
       ("a step signs with ssh-keygen -Y sign", rel.replace("      - name: decide (bin/patch-decide.py)\n", "      - run: ssh-keygen -Y sign -f k x\n      - name: decide (bin/patch-decide.py)\n", 1)))
for label, text in MUT:
    f = tag_job_faults(text) if text != rel else []
    check(f, "the tag job checks refuse a copy of release.yml where %s (%s)" % (label, f[0][:70] if f else "NOT REFUSED, or the mutation did not apply"))
print("pass=%d fail=%d" % (passed, failed))
sys.exit(1 if failed else 0)
PY
