#!/usr/bin/env bash
# proves: REQ-REL-009-AC5, REQ-REL-009-AC6, REQ-REL-009-AC13
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
check(".github/workflows/release.yml" in src and ".github/workflows/stage-sign.yml" in src,
      "REQ-REL-009's source names release.yml and stage-sign.yml (the decide, sign-tag and cut jobs)")
check(not any("stage-admission" in x for x in src), "REQ-REL-009's source no longer names stage-admission.yml (the file is gone: bin/build-admit.py admits)")
a5 = " ".join(text(ac["REQ-REL-009-AC5"]).split())
check(re.search(r"creates, signs and pushes no tag", a5) is not None, "AC5: the deciding job creates, signs and pushes no tag")
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
print("pass=%d fail=%d" % (passed, failed))
sys.exit(1 if failed else 0)
PY
