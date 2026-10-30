#!/usr/bin/env bash
# proves: REQ-CHAIN-002-AC2
# Ratify B (owner, Oct 29): the release is signed with the KMS key and every signature keeps its Rekor entry; keyless signing is gone. So the
# trust files in .github/policy/ are exactly the ones the key plus Rekor path reads:
#   rekor.pub                    STAYS   read by the Rekor entry check in bin/chain-verify.py (it checks each entry's signed timestamp)
#   sigstore-trust.json          STAYS   read by bin/chain-verify.py; it pins rekor.pub by sha256 and holds nothing else about Sigstore
#   cosign-signing-config.json   STAYS   read by the cosign calls (bin/release-*.sh); it names Rekor v1 and no certificate authority,
#                                        no sign-in service and no timestamp authority, so cosign asks for none of them
#   fulcio-chain.pem             GOES    only the certificate path read it, and that path is gone
#   tsa-chain.pem                GOES    the Rekor entry carries the integrated time; no kept reader needs a timestamp authority
# Until the deletions are made this test is red. It reads the committed policy files and the code that names them; it opens no network connection.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
python3 -I - "$root" <<'PY'
import hashlib, json, os, re, subprocess, sys

root = sys.argv[1]
pol = os.path.join(root, ".github", "policy")
passed = failed = 0


def check(cond, msg):
    global passed, failed
    if cond:
        passed += 1
        print("ok   " + msg)
    else:
        failed += 1
        print("FAIL " + msg)


def load(name):
    with open(os.path.join(pol, name)) as f:
        return json.load(f)


def code_files():
    """Every file under bin/ and .github/ except the policy trust files themselves and this test (which names them to judge them)."""
    for top in ("bin", ".github"):
        for d, _dirs, names in os.walk(os.path.join(root, top)):
            for n in names:
                p = os.path.join(d, n)
                if os.path.dirname(p) == pol and n.endswith((".pem", ".pub")):
                    continue
                if n == os.path.basename(__file__) or n == "chain-trust-files-test.sh":
                    continue
                yield p


for gone in ("fulcio-chain.pem", "tsa-chain.pem"):
    check(not os.path.exists(os.path.join(pol, gone)), "%s is deleted (no kept reader needs it)" % gone)
    readers = []
    for p in code_files():
        try:
            with open(p, "r", errors="ignore") as f:
                if gone in f.read():
                    readers.append(os.path.relpath(p, root))
        except OSError:
            pass
    check(not readers, "no file under bin/ or .github/ still names %s%s" % (gone, " (readers: %s)" % ", ".join(sorted(readers)[:4]) if readers else ""))

check(os.path.isfile(os.path.join(pol, "rekor.pub")), "rekor.pub stays (the Rekor entry check verifies each entry against it)")
trust = load("sigstore-trust.json")
check("fulcio_root_sha256" not in trust, "sigstore-trust.json holds no Fulcio root pin")
check("tsa_root_sha256" not in trust, "sigstore-trust.json holds no timestamp authority root pin")
check(set(trust) <= {"_note", "rekor_sha256"} and "rekor_sha256" in trust, "sigstore-trust.json holds only the Rekor pin (and its note): keys %s" % sorted(trust))
der = subprocess.run(["openssl", "pkey", "-pubin", "-in", os.path.join(pol, "rekor.pub"), "-outform", "DER"], capture_output=True).stdout
check(trust.get("rekor_sha256") == hashlib.sha256(der).hexdigest(), "the pinned rekor_sha256 is the sha256 of rekor.pub's DER")

cfg = load("cosign-signing-config.json")
check(cfg.get("caUrls") == [], "cosign-signing-config.json names no certificate authority (caUrls is empty)")
check(cfg.get("oidcUrls") == [], "cosign-signing-config.json names no sign-in service (oidcUrls is empty)")
check(cfg.get("tsaUrls") == [], "cosign-signing-config.json names no timestamp authority (tsaUrls is empty)")
rek = cfg.get("rekorTlogUrls")
check(isinstance(rek, list) and len(rek) == 1 and rek[0].get("url") == "https://rekor.sigstore.dev" and rek[0].get("majorApiVersion") == 1,
      "cosign-signing-config.json names exactly one Rekor, v1")
check(cfg.get("rekorTlogConfig", {}).get("count") == 1, "cosign-signing-config.json asks for exactly one Rekor entry")

verify_py = open(os.path.join(root, "bin", "chain-verify.py")).read()
check("rekor.pub" in verify_py or "rekor-key" in verify_py or "rekor_public_key" in verify_py, "a kept reader exists for rekor.pub: bin/chain-verify.py names the Rekor key")
check("sigstore-trust.json" in verify_py or "sigstore-trust" in verify_py, "a kept reader exists for sigstore-trust.json: bin/chain-verify.py names it")
signers = [p for p in code_files() if os.path.basename(p).startswith("release-") and p.endswith(".sh")]
check(any("cosign-signing-config.json" in open(p, errors="ignore").read() for p in signers), "a kept reader exists for cosign-signing-config.json: a bin/release-*.sh script passes it to cosign")

print("pass=%d fail=%d" % (passed, failed))
sys.exit(1 if failed else 0)
PY
