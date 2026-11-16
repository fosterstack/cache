#!/usr/bin/env bash
# proves: REQ-REL-009-AC5
# Handoff 0713 P8 (orchestrator ruling R6, owner's Oct 28 rule 2 "no keyless signing anywhere"): the keyless tag
# signers of the automatic patch release are out. The words below name them: gitsign, smimesign, and the git settings
# that make git sign with an X.509 certificate (gpg.format=x509, gpg.x509.program). No tracked file that is code, a
# workflow or policy names one (the two detectors below excepted): not an installer entry, a pinned version, a
# workflow step, a policy row, a verifier route or a tool list. Tests and documents may still say the words (this
# test, the tests that prove a keyless signature is refused, the history in docs/). Admission refuses a keyless
# signature on every tag, accepts the owner's SSH signature on every tag and the one release KMS key's SSH signature on a
# patch tag only (bin/admission-tag-signer-test.sh, bin/chain-build-admit-test.sh). Who creates, signs and pushes a tag is the
# release judges' job (bin/chain-release-shape.py, bin/chain-tag-jobs-test.sh); here: the deciding job names no signing tool,
# and the one job that signs a tag names no keyless one.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
python3 -I - "$root" <<'PY'
import json
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

# two files keep the words on purpose, because they DETECT them: the signer table that makes any use of gitsign in
# a chain file an unlisted signer (bin/chain-test-signers.json) and the shape judge's list of signing words
# (bin/chain-check-shape.py)
DETECTORS = {"bin/chain-test-signers.json", "bin/chain-check-shape.py"}
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
rel = open(root + "/.github/workflows/release.yml").read()
check(not re.search(r"tag -s|keylessly|ssh-keygen -Y sign", rel), "release.yml signs no tag itself: no `tag -s`, no ssh-keygen signing, no keyless signing (the one KMS key signs, in stage-sign.yml)")
import yaml
KEYLESS = re.compile(r"cosign|fulcio|sigstore|keyless|gitsign|smimesign|identity-token|oidc", re.I)
rjobs = (yaml.safe_load(rel) or {}).get("jobs") or {}
decide = json.dumps(rjobs.get("decide", {}))
check("decide" in rjobs, "release.yml has the deciding job `decide`")
check("decide" in rjobs and not KEYLESS.search(decide) and not re.search(r"kms|AWS_|id-token|create-github-app-token|AUDITOR_APP", decide, re.I),
      "the decide job names no keyless signing tool, no KMS key or role, no id-token and no App token")
check("decide" in rjobs and not re.search(r"git\s+(tag|push)\b|tag -s|git/(refs|tags)|verify-tag", decide),
      "the decide job creates, signs, verifies and pushes no tag")
sjobs = (yaml.safe_load(open(root + "/.github/workflows/stage-sign.yml").read()) or {}).get("jobs") or {}
st = json.dumps(sjobs.get("sign-tag", {}))
check("sign-tag" in sjobs, "stage-sign.yml has the job sign-tag (the one job that signs a tag)")
check("sign-tag" in sjobs and not re.search(r"fulcio|sigstore|keyless|gitsign|smimesign|identity-token|cosign (sign|attest)|gpg\.format|gpg\.x509", st, re.I),
      "the sign-tag job names no keyless signing tool and no x509 setting")
check("sign-tag" in sjobs and len(re.findall(r"alias/", st)) <= 1, "the sign-tag job names at most one KMS key (no second key)")
print("pass=%d fail=%d" % (passed, failed))
sys.exit(1 if failed else 0)
PY
