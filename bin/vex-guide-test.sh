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
# a failed cosign must stop the reader in any shell (Codex #169 r1, SEC-169-03): its output is saved to a file by the
# command itself, never piped onward, so the command's own exit status is what the reader sees
verify = next((b for b in blocks if "cosign verify-attestation" in b), "")
check("cosign's output goes to a file, not into a pipe", re.search(r"cosign verify-attestation[^|]*?> \S+\n", verify, re.S) is not None
      and not re.search(r"cosign verify-attestation[^>]*\|", verify, re.S), verify)
check("no head/tail truncation that could hide a failure or a second attestation", not re.search(r"\| *(head|tail)\b", verify))
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
# Codex #167 r1: no claim beyond what ships, and every runnable command checked
check("R1-01 never claims the three files carry the same statements",
      not re.search(r"all three carry the same statements", doc, re.I), re.findall(r"[^.]*same statements[^.]*", doc))
check("R1-01 says the Inspector file carries only the suppressing statements",
      re.search(r"Inspector[^.]*only[^.]*(not affected|suppress)", doc, re.I | re.S) is not None)
check("R1-02 says Google's loader reads only whole-image statements",
      re.search(r"Google[^.]*(loader|upload)[^.]*whole-image", doc, re.I | re.S) is not None)
rm = next((b for b in blocks if "delete-filter" in b), "")
check("R1-03 the removal command fails when listing fails (pipefail)", rm.lstrip().startswith("(set -o pipefail;"), rm)
check("R1-04 the Inspector command appears once, and only as the constant",
      code.count("create-filter") == 1 and V.GUIDE_INSPECTOR_COMMAND.replace("<file>", '"%s"' % insp) in code)
check("R1-04 the Google command appears once, and only as the constant",
      code.count("load-vex") == 1 and V.GUIDE_GOOGLE_COMMAND.replace("<file>", '"%s"' % csaf) in code)
# Sonnet #167 r3 (R3-01): a pasted command never ends the reader's shell. zsh (the macOS default) runs a pipeline's last
# stage in the current shell, so `| while …; do … || exit 1; done` would close the terminal. Each looping command runs in
# its own ( … ) subshell: it reports the failure and the reader's shell — and its options (pipefail) — are untouched.
import shutil, subprocess, tempfile
stub = ('aws() { case "$*" in *list-filters*) printf "arn:a\\tarn:b\\n" ;; *delete-filter*|*create-filter*) echo denied >&2; return 1 ;; esac; }\n'
        'jq() { printf "%s\\n" "{}"; }\n')
for name, cmd in (("Inspector load", next(l for b in blocks for l in b.splitlines() if "create-filter" in l).strip()),
                  ("filter removal", next(l for b in blocks for l in b.splitlines() if "delete-filter" in l).strip())):
    check("R3-01 the %s command is one ( … ) subshell" % name, cmd.startswith("(") and cmd.endswith(")"), cmd)
    shells = [("bash with lastpipe (zsh's semantics)", ["bash", "-c", "shopt -s lastpipe; set +m; " + stub + cmd + '; echo "NEXT rc=$?"; set -o | grep -c "pipefail *on"'])]
    if shutil.which("zsh"):
        shells.append(("zsh", ["zsh", "-c", stub + cmd + '; echo "NEXT rc=$?"; [[ -o pipefail ]] && echo 1 || echo 0']))
    for sname, argv in shells:
        with tempfile.TemporaryDirectory() as t:
            open(os.path.join(t, "fosterstack-cache-vX.Y.Z.inspector-filters.json"), "w").write("{}")
            r = subprocess.run(argv, cwd=t, capture_output=True, text=True, env=dict(os.environ, VER="X.Y.Z"))
        out = r.stdout.split()
        check("R3-01 under %s, a failed %s call is reported and the shell goes on, its options unchanged" % (sname, name),
              "NEXT" in r.stdout and "rc=0" not in r.stdout and out[-1:] == ["0"], (r.returncode, r.stdout, r.stderr[-200:]))
print("vex-guide: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
PY
