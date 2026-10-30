#!/usr/bin/env bash
# proves: REQ-REL-009-AC6
# Handoff 0713 P8 (orchestrator ruling R6, owner's Oct 28 rule 2 "no keyless signing anywhere"): the keyless tag
# signers of the automatic patch release are out. The words below name them: gitsign, smimesign, and the git settings
# that make git sign with an X.509 certificate (gpg.format=x509, gpg.x509.program). No tracked file that is code, a
# workflow or policy names one (the two detectors below excepted): not an installer entry, a pinned version, a
# workflow step, a policy row, a verifier route or a tool list. Tests and documents may still say the words (this
# test, the tests that prove a keyless signature is refused, the history in docs/). Admission refuses a keyless
# signature on every tag and accepts the owner's SSH signature on every tag, patch tags included
# (bin/admission-tag-signer-test.sh, bin/chain-build-admit-test.sh). Creating a tag at all is the release judges'
# job (bin/chain-release-shape.py, bin/release-patch-wiring-test.sh).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
python3 -I - "$root" <<'PY'
import re
import subprocess
import sys

root = sys.argv[1]
listing = subprocess.run(["git", "-C", root, "ls-files", "-z"], capture_output=True, check=True)
files = listing.stdout.decode().split("\0")
# not scanned: documents and history, evidence, and every test (a test may name what it proves is refused)
SKIP = re.compile(r"^(docs/|requirements/|results/|test-evidence/)|(^|/)tests?/|-test\.(sh|py)$"
                  r"|(^|/)test_[^/]*\.py$|\.md$")
WORDS = re.compile(r"gitsign|smimesign|gpg\.format\s*=\s*x509|gpg\.x509\.program", re.I)
passed = failed = 0


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
    check(WORDS.search("run: " + word + " sign") and WORDS.search("run: " + word.upper() + " sign") and
          WORDS.search("run: " + word.title() + " sign"), "the scan finds %s in lower, upper and title case" % word)
check(WORDS.search("git -c gpg.format = x509 tag -s v1"),
      "the scan finds gpg.format = x509 with spaces around the equals sign")
check(not WORDS.search("git tag -s v1 with gpg.format=ssh and a signing key"),
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
    n = len(WORDS.findall(text))
    if n:
        hits[f] = n
check(not hits, "no tracked code, workflow or policy file names a keyless tag signer%s"
      % ("" if not hits else ": " + ", ".join("%s (%d)" % kv for kv in sorted(hits.items()))))
inst = open(root + "/bin/install-scanner.sh").read()
check(not re.search(r"GITSIGN|sigstore/gitsign", inst, re.I), "bin/install-scanner.sh installs no gitsign")
rel = open(root + "/.github/workflows/release.yml").read()
check(not re.search(r"tag -s|verify-tag|keylessly", rel), "release.yml signs and verifies no tag")
print("pass=%d fail=%d" % (passed, failed))
sys.exit(1 if failed else 0)
PY
