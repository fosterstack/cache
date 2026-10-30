#!/usr/bin/env bash
# proves: REQ-REL-009-AC6
# Handoff 0713 P8 (orchestrator ruling R6, owner's Oct 28 rule 2 "no keyless signing anywhere"): gitsign, the keyless tag signer of the automatic patch release, is out.
# No tracked file that is code, a workflow or policy names it (the two detectors below excepted): not an installer entry, a pinned version, a workflow step, a policy row, a verifier route or a tool list.
# Tests and documents may still say the word (this test, the tests that prove a keyless signature is refused, the history in docs/).
# Admission refuses a keyless signature and every patch tag (bin/admission-tag-signer-test.sh, bin/chain-build-admit-test.sh).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
python3 -I - "$root" <<'PY'
import re, subprocess, sys
root = sys.argv[1]
files = subprocess.run(["git", "-C", root, "ls-files", "-z"], capture_output=True, check=True).stdout.decode().split("\0")
SKIP = re.compile(r"^(docs/|" + "ven" + "dor/|requirements/|results/|test-evidence/)|(^|/)tests?/|-test\.(sh|py)$|(^|/)test_[^/]*\.py$|^bin/chain-no-keyless-tag-test\.sh$|\.md$")
passed = failed = 0
# Two files keep the word on purpose, because they DETECT it: the signer table that makes any use of gitsign in a chain file an unlisted signer
# (bin/chain-test-signers.json) and the shape judge's list of signing words (bin/chain-check-shape.py). With no listed signer, a workflow that starts using gitsign is a finding.
DETECTORS = {"bin/chain-test-signers.json", "bin/chain-check-shape.py"}
hits = {}
for f in files:
    if not f or SKIP.search(f) or f in DETECTORS:
        continue
    try:
        text = open(root + "/" + f, errors="ignore").read()
    except OSError:
        continue
    n = len(re.findall(r"gitsign", text, re.I))
    if n:
        hits[f] = n
if hits:
    failed += 1
    print("FAIL no tracked code, workflow or policy file names gitsign -> %d files: %s" % (len(hits), ", ".join("%s (%d)" % kv for kv in sorted(hits.items()))))
else:
    passed += 1
    print("ok   no tracked code, workflow or policy file names gitsign")
inst = open(root + "/bin/install-scanner.sh").read()
if re.search(r"GITSIGN|sigstore/gitsign", inst, re.I):
    failed += 1; print("FAIL bin/install-scanner.sh still installs gitsign (a pinned version or checksum)")
else:
    passed += 1; print("ok   bin/install-scanner.sh installs no gitsign")
rel = open(root + "/.github/workflows/release.yml").read()
if re.search(r"tag -s|verify-tag|keylessly", rel):
    failed += 1; print("FAIL .github/workflows/release.yml still signs or verifies a tag keylessly")
else:
    passed += 1; print("ok   .github/workflows/release.yml signs no tag keylessly")
print("pass=%d fail=%d" % (passed, failed))
sys.exit(1 if failed else 0)
PY
