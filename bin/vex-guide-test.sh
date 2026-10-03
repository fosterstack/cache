#!/usr/bin/env bash
# proves: REQ-SCAN-011-AC2, REQ-SCAN-011-AC4
# Scanner-panel rule 11 (owner RATIFIED Oct 2; read-back approved, advisor 0097): docs/using-our-vex.md gives, per
# scanner, the file, where it lives, how to check it is ours with the release's existing signing, the exact command —
# the generator's own GUIDE_* constants, copy-pasteable, never a hand copy that can drift — what it does in the
# customer's account, how to stay current, and what to do for an unlisted scanner; it names no competitor.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
python3 - "$root" <<'PY'
import importlib.util, os, re, sys
root = sys.argv[1]
passed = failed = 0
def check(name, ok, got=""):
    global passed, failed
    if ok: passed += 1; print("ok:", name)
    else: failed += 1; print("FAIL:", name, "->", got)
path = os.path.join(root, "docs/using-our-vex.md")
doc = open(path).read() if os.path.exists(path) else ""
check("the guide exists", bool(doc))
blocks = re.findall(r"```sh\n(.*?)```", doc, re.S)
code = "\n".join(blocks)
spec = importlib.util.spec_from_file_location("vf", os.path.join(root, "bin/vex-forms.py"))
V = importlib.util.module_from_spec(spec); spec.loader.exec_module(V)
openvex, insp, csaf = ("fosterstack-cache.openvex.json", "fosterstack-cache-v${VER}.inspector-filters.json",
                       "fosterstack-cache-v${VER}.csaf.json")
# which file, where it lives (the release page of each version)
for f in (openvex, insp, csaf):
    check("names and downloads %s from the release page" % f,
          re.search(r"releases/download/v\$\{VER\}/" + re.escape(f), code) is not None)
# how to check it is ours: the signed release manifest (pinned like docs/verify-images.md), then its sha256 of each file
check("verifies the release manifest attestation, pinned to the promotion workflow and the tag",
      "cosign verify-attestation" in code and "--type https://fosterstack.com/attestations/release-manifest/v1" in code
      and "stage-promote.yml@refs/tags/v${VER}$" in code and "token.actions.githubusercontent.com" in code)
check("checks each file against the manifest's sha256", ".vex[]" in code and "sha256sum -c" in code)
check("no new key or signature is introduced", "--key" not in code and "sign-blob" not in code)
# the exact commands: the generator's constants, with <file> bound to the named file (copy-pasteable, run verbatim by
# the rule-12 live test)
check("the Inspector command is GUIDE_INSPECTOR_COMMAND verbatim",
      V.GUIDE_INSPECTOR_COMMAND.replace("<file>", '"%s"' % insp) in code)
check("the Google command is GUIDE_GOOGLE_COMMAND verbatim",
      V.GUIDE_GOOGLE_COMMAND.replace("<file>", '"%s"' % csaf) in code)
check("the Google step sets every variable it reads", all(re.search(r"(?m)^%s=" % v, code) for v in ("VER", "IMAGE", "DIGEST")))
check("Grype reads the OpenVEX file", re.search(r"grype \S+ --vex %s" % re.escape(openvex), code) is not None)
check("Docker Scout reads the OpenVEX file", re.search(r"docker scout cves --vex-location \S+ ", code) is not None)
# Scout applies only statements whose author matches --vex-author (default <.*@docker.com>; Sonnet #167 r1): the
# guide's flag must match our file's author exactly, anchored
import json
author = json.load(open(os.path.join(root, ".vex/fosterstack-cache.openvex.json")))["author"]
m = re.search(r"--vex-author '([^']+)'", code)
check("Docker Scout is told to accept our file's author", m is not None and re.fullmatch(m.group(1), author) is not None
      and m.group(1).startswith("^") and m.group(1).endswith("$"), (m and m.group(1), author))
# Grype applies repository_url-qualified products from 0.118.0 (0.117 ignores them; the pin is 0.118.0)
check("names the minimum Grype version the file works with", re.search(r"Grype 0\.118\.0 or later", doc) is not None)
# what each does in the customer's account
check("says the Inspector rules match only our exact image digests", re.search(r"only[^.]*exact[^.]*digest", doc, re.I) is not None)
check("says the Google upload is a preview feature", re.search(r"preview", doc, re.I) is not None)
# staying current: reload every release; a statement turned affected — remove the old suppression, and how
check("reload on every release", re.search(r"every release", doc, re.I) is not None)
check("removes our old Inspector suppressions by name", "aws inspector2 delete-filter" in code and "fosterstack-cache-" in code
      and "aws inspector2 list-filters" in code)
check("says what to do when a statement turns affected", re.search(r"turns? .?affected", doc, re.I) is not None)
# unlisted scanners
check("unlisted scanners: the OpenVEX file, otherwise ask us", re.search(r"OpenVEX[^.]*otherwise[^.]*ask us", doc, re.I | re.S) is not None)
# AC4: no competitor named
COMPETITORS = ["chainguard", "bitnami", "docker hardened", "minimus", "rapidfort", "root.io", "echo.ai", "wolfi",
               "iron bank", "prisma", "cortex", "wiz", "sysdig", "aqua", "jfrog", "anchore enterprise", "orca", "lacework"]
hits = [c for c in COMPETITORS if re.search(r"\b%s\b" % re.escape(c), doc, re.I)]
check("names no competitor", not hits, hits)
check("no command is a placeholder the reader must guess", "<file>" not in code and "TODO" not in doc, re.findall(r"<[a-z-]+>", code))
print("vex-guide: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
PY
