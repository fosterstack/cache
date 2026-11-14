#!/usr/bin/env bash
# proves: REQ-SCAN-011-AC2, REQ-SCAN-011-AC4
# Scanner-panel rule 11 (owner RATIFIED Oct 2; read-back approved, advisor 0097): docs/using-our-vex.md gives, per
# scanner, the file, where it lives, how to check it is ours with the release's existing signing, the exact command —
# the generator's own GUIDE_* constants, copy-pasteable, never a hand copy that can drift — what it does in the
# customer's account, how to stay current, and what to do for an unlisted scanner; it names no competitor.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
python3 - "$root" <<'PY'
import glob, importlib.util, os, re, shutil, sys, tempfile
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
check("verifies the release manifest attestation with the release key (v0.3.0+: --key release.rsa.pub, no certificate identity or issuer)",
      "cosign verify-attestation" in code and "--type https://fosterstack.com/attestations/release-manifest/v1" in code
      and "--key release.rsa.pub" in code and "--certificate-identity" not in code
      and "--certificate-oidc-issuer" not in code)
check("fetches release.rsa.pub from the release's tag in the one-line form of docs/verify-images.md",
      'curl -fsSLO "https://raw.githubusercontent.com/fosterstack/cache/v${VER}/build/keys/release.rsa.pub"' in code)
check("checks each file against the manifest's sha256", ".vex[]" in code and "sha256sum -c" in code)
# a failed cosign must stop the reader in any shell (Codex #169 r1, SEC-169-03): its output is saved to a file by the
# command itself, never piped onward, so the command's own exit status is what the reader sees
verify = next((b for b in blocks if "cosign verify-attestation" in b), "")
check("cosign's output goes to a file, not into a pipe", re.search(r"cosign verify-attestation[^|]*?> \S+\n", verify, re.S) is not None
      and not re.search(r"cosign verify-attestation[^>]*\|", verify, re.S), verify)
check("no head/tail truncation that could hide a failure or a second attestation", not re.search(r"\| *(head|tail)\b", verify))
check("no new key or signature is introduced: no sign-blob, and no --key other than release.rsa.pub",
      "sign-blob" not in code and all(k == "release.rsa.pub" for k in re.findall(r"--key[= ]+(\S+)", code)))
mut = code.replace("--key release.rsa.pub", '--certificate-identity="x" --certificate-oidc-issuer=\'y\'')
check("mutant: the identity and issuer flags put back in place of --key are caught by the key check",
      not ("--key release.rsa.pub" in mut and "--certificate-identity" not in mut))
# the exact commands: the generator's constants, with <file> bound to the named file (copy-pasteable, run verbatim by
# the rule-12 live test)
check("the Inspector command is GUIDE_INSPECTOR_COMMAND verbatim",
      V.GUIDE_INSPECTOR_COMMAND.replace("<file>", '"%s"' % insp) in code)
check("the Google command is GUIDE_GOOGLE_COMMAND verbatim",
      V.GUIDE_GOOGLE_COMMAND.replace("<file>", '"%s"' % csaf) in code)
check("the Google step sets every variable it reads", all(re.search(r"(?m)^%s=" % v, code) for v in ("VER", "IMAGE", "DIGEST")))
check("Grype reads the OpenVEX file", re.search(r"grype \S+ --vex %s" % re.escape(openvex), code) is not None)
# Docker Scout (REQ-REL-010, PR-C): the section is DRAFT and GATED. It makes no claim a customer can rely on until a live scan of the real published index has shown Scout applying
# our attestation (REQ-REL-010-AC6; owner Oct 3: "the guide leads with it only after the live test"): it carries the gate marker, and the commit that removes the marker is the one that
# follows that passing run. Scout's local-file flag (--vex-location) applies nothing on Scout 1.24 to 1.26 (rules.md:158-160), so it never appears.
import json
sc = re.search(r"(?ms)^### Docker Scout\n(.*?)(?=^## |^### |\Z)", doc)
check("the page has a Docker Scout section", sc is not None)
scout_sec = sc.group(1) if sc else ""
check("the Scout section carries the gate marker until AC6 has passed", "<!-- gated: REQ-REL-010-AC6 -->" in scout_sec)
check("the gate is VISIBLE to a reader of the rendered page: a draft notice in a blockquote says the section is not yet verified on a published release (Codex #416 r1)",
      re.search(r"(?m)^> \*\*Draft, not yet verified on a published release\.\*\*", scout_sec) is not None and re.search(r"(?i)do not rely on it", scout_sec) is not None)
scout_blocks = [b for b in blocks if "docker scout" in b]
check("the page has exactly one Scout command, inside the Scout section", len(scout_blocks) == 1 and scout_blocks[0] in scout_sec, len(scout_blocks))
author = json.loads(open(os.path.join(root, ".vex/fosterstack-cache.openvex.json")).read())["author"] if os.path.exists(os.path.join(root, ".vex/fosterstack-cache.openvex.json")) else ""
pattern = "^" + re.sub(r"([\[\]\\.*^$+?(){}|/])", r"\\\1", author) + "$"
check("the Scout command names our author as the anchored, escaped pattern (Scout applies only statements of an author the scan names) and the image by digest",
      scout_blocks and scout_blocks[0] == "docker scout cves --vex-author '%s' \"registry://ghcr.io/fosterstack/cache@${DIGEST}\"\n" % pattern, scout_blocks)
check("no Scout local-file flag anywhere", "--vex-location" not in doc)
check("the Scout section says nothing is loaded (the attestation is on the image) and why the author is named", "needs no file" in scout_sec and "author" in scout_sec)
check("the stay-current part says there is nothing to reload for Scout", re.search(r"(?i)docker scout:\*\* nothing to (load|reload)", doc) is not None)
# the blocks that need a published release or a registry are listed by exact text for the live test (rule 79 precedent: docs/verify-release.cannot-run.json)
import json
cr = json.load(open(os.path.join(root, "docs/using-our-vex.cannot-run.json")))
blocks_all = re.findall(r"```sh\n(.*?)```", doc, re.S)
check("the cannot-run list holds blocks of the page, each exactly once", all(blocks_all.count(b) == 1 for b in cr["blocks"]) and len(set(cr["blocks"])) == len(cr["blocks"]))
need = [b for b in blocks_all if "imagetools inspect" in b or ("cu" + "rl -fsSLO") in b or "cosign verify-attestation" in b or re.search(r"grype \"ghcr\.io/", b) or "docker scout cves" in b]
check("the cannot-run list is exactly the blocks that read a release or a registry (digest, download, verify, and the Grype and Scout scans of the published image)", cr["blocks"] == need, (len(cr["blocks"]), len(need)))
# Codex #381 r2: the page serves the FIPS image too (its tag is X.Y.Z-fips, RELEASING.md) and a macOS reader (shasum for sha256sum; base64 -D before macOS 14)
check("the page tells a FIPS reader to use the -fips tag of the image", re.search(r"\$\{VER\}-fips", doc) is not None)
check("the page gives the macOS alternatives for the checksum and base64 commands", "shasum -a 256 -c" in doc and "base64 -D" in doc)
# Codex #381 r3 (AC4): the page claims only what the published statements cover, not every vulnerability a scanner might report
check("the opening claims statements only for the vulnerabilities we have assessed", "each known vulnerability that a scanner reports" not in doc and "we have assessed" in doc)
# Grype applies repository_url-qualified products from 0.118.0 (0.117 ignores them; the pin is 0.118.0)
check("names the minimum Grype version the file works with", re.search(r"Grype 0\.118\.0 or later", doc) is not None)
# what each does in the customer's account
check("says the Inspector rules match only our exact image digests", re.search(r"only[^.]*exact[^.]*digest", doc, re.I) is not None)
check("says the Google upload is a preview feature", re.search(r"preview", doc, re.I) is not None)
# staying current: reload every release; a statement turned affected — remove the old suppression, and how
check("reload on every release", re.search(r"every release", doc, re.I) is not None)
check("removes our old Inspector suppressions by name", "aws inspector2 delete-filter" in code and "fosterstack-cache-" in code
      and "aws inspector2 list-filters" in code)
check("says what to do when a statement changes (a loaded suppression must go)", re.search(r"statement changes.{0,80}suppression you loaded earlier must go", doc, re.S) is not None)
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
import subprocess
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
# Codex #167 r3 (R3-02): pasted in order, a failed cosign stops the verification — nothing after it runs
vstub = ('cosign() { echo verifier_error >&2; return 7; }\njq() { printf "%s\\n" "{}"; }\nbase64() { cat; }\n'
         'sha256sum() { echo REACHED_CHECKSUM; return 0; }\n')
for sname, argv0 in (("bash", ["bash", "-c"]), ("zsh", ["zsh", "-c"])):
    if not shutil.which(argv0[0]):
        continue
    with tempfile.TemporaryDirectory() as t:
        r = subprocess.run(argv0 + [vstub + verify + '\necho "AFTER rc=$?"'], cwd=t, capture_output=True, text=True,
                           env=dict(os.environ, VER="1.2.3", DIGEST="sha256:" + "a" * 64))
    check("R3-02 under %s a failed cosign stops the verification and reports it" % sname,
          "REACHED_CHECKSUM" not in r.stdout and "AFTER rc=0" not in r.stdout and "AFTER" in r.stdout,
          (r.stdout[-200:], r.stderr[-200:]))
# residual R1-04: the runnable line IS the constant, nothing appended or prepended
lines = [l.strip() for b in blocks for l in b.splitlines()]
check("R1-04 the Inspector line is exactly the constant",
      [l for l in lines if "create-filter" in l] == [V.GUIDE_INSPECTOR_COMMAND.replace("<file>", '"%s"' % insp)])
check("R1-04 the Google line is exactly the constant",
      [l for l in lines if "load-vex" in l] == [V.GUIDE_GOOGLE_COMMAND.replace("<file>", '"%s"' % csaf)])
# owner Oct 16 (handoff 0482): the page explains every VEX status our published statements use (it may explain no others)
used = {x["status"] for x in json.load(open(os.path.join(root, ".vex/fosterstack-cache.openvex.json")))["statements"]}
said = {"not_affected": "not affected", "fixed": "fixed", "affected": "affected", "under_investigation": "under investigation"}
check("the page explains each status our VEX uses", all("*%s*" % said[u] in doc for u in used), sorted(u for u in used if "*%s*" % said[u] not in doc))
word = {"not_affected": r"\bnot affected\b", "fixed": r"\bfixed\b", "affected": r"(?<!not )(?<!known )\baffected\b", "under_investigation": r"\bunder investigation\b"}
check("the page mentions no status our VEX does not use, emphasized or not", all(k in used or not re.search(word[k], doc, re.I) for k in word),
      [k for k in word if k not in used and re.search(word[k], doc, re.I)])
check("…and the guard sees an unused status explained in plain text (Codex #381 r5)", re.search(word["fixed"], doc + "\nA fixed status means it was fixed.\n", re.I) is not None and "fixed" not in used)
# R3: the OpenVEX file keeps every statement; the CSAF file may omit one (a Go standard library version the release is not built with)
OLD_SENT = "The OpenVEX and CSAF files carry every statement."
def old_sentence_gone(text):
    return OLD_SENT not in text
check("R3 the old sentence 'The OpenVEX and CSAF files carry every statement.' is gone", old_sentence_gone(doc))
check("R3 the guide says the OpenVEX file keeps every statement",
      re.search(r"OpenVEX file[^.]*(keeps|carries|holds)[^.]*every statement", doc, re.I | re.S) is not None)
check("R3 the guide says the CSAF file may omit a statement, for example a Go standard library version the release is not built with",
      re.search(r"CSAF file[^.]*may (omit|leave out)[^.]*Go standard library", doc, re.I | re.S) is not None
      or re.search(r"CSAF file may (omit|leave out)", doc, re.I) is not None and "Go standard library" in doc)
check("R3 mutant: the old sentence put back is caught by the sentence check",
      old_sentence_gone(doc + "\nThe OpenVEX and CSAF files carry every statement.\n") is False)
# R4: no text still says the three forms carry exactly the same statements or that the CSAF file carries every OpenVEX statement
def text_of(rel):
    q = os.path.join(root, rel)
    return open(q).read() if os.path.exists(q) else None
for rel in (".vex/README.md", "bin/vex-forms.py", "docs/release-notes-draft.md", "docs/scanning.md",
            "requirements/requirements.yaml"):
    t = text_of(rel)
    check("R4 %s exists" % rel, t is not None)
    check("R4 %s does not claim 'exactly the same statements'" % rel, t is not None and "exactly the same statements" not in t.replace("\n", " "))
for rel in (".vex/README.md", "bin/vex-forms.py", "docs/release-notes-draft.md",
            "docs/scanning.md"):
    t = text_of(rel) or ""
    check("R4 %s does not say the CSAF file carries every OpenVEX statement" % rel,
          not re.search(r"CSAF file (carries|carrying|holds|has) every\s+OpenVEX\s+statement", t.replace("\n", " ")) and "carrying every OpenVEX statement" not in t.replace("\n", " "))
# the scanning page owns up to the one omission: no CSAF statement for a Go stdlib version the release is not built with
scan = (text_of("docs/scanning.md") or "").replace("\n", " ")
check("R4 docs/scanning.md says the CSAF file leaves out Go standard library versions the release is not built with",
      re.search(r"CSAF file[^.]*(omit|leave out|leaves out|without|not (carry|include|contain))[^.]*Go standard library",
                scan, re.I) is not None, scan[:200])
# R8: a customer doc sentence that mentions a CA bundle (the images carry none) fails unless it is listed as reviewed
# matches "CA bundle", "CA certificate bundle", "ca-certificates"; refuses "a bundle of root certificates"
CA_BUNDLE = re.compile(r"\bca[-\s]+(certificates?[-\s]+)?bundle|\bca-certificates?\b", re.I)
REVIEWED_CA = [
    ("README.md",
        'Both images hold only the `fscache` binary and the few packages it needs (base layout, '
        'time zone data): there is no base image, no CA certificate bundle, no shell to exec into '
        'and no package manager.'),
    ("docs/docker-deploy.md",
        'The image has no CA certificate bundle, so the server cannot verify any outside '
        'certificate;'),
    ("docs/install.md",
        '**The container images carry no CA certificate bundle.** The server makes no outbound '
        'connection and verifies no certificate;'),
    ("docs/quality/traceability.md",
        'then the configs declare only our base-layout package fscache-baselayout, tzdata and our '
        'apk, no CA bundle, no base image and no shell, take packages only from /work/archive and '
        '/work/melange-repo, carry the Wolfi and assembly keys, build x86_64 and aarch64, run as '
        'nonroot 65532 with /home/nonroot and the entrypoint /usr/bin/fscache, and differ only in '
        'the apk name;'),
    ("docs/quality/traceability.md",
        'so the cache needs no CA bundle;'),
    ("docs/quality/traceability.md",
        'then the package has no dependency and no provides, holds only the files of '
        'build/baselayout/ (passwd, group, hosts, nsswitch.conf, os-release, protocols, services), '
        'names no shell path and no network address, and ships no CA bundle file | unit | | '
        'approved | 1 item(s) |'),
    ("docs/quality/traceability.md",
        'when it builds fscache-baselayout, or is given another option, another recipe, no assembly'
        ' key, a melange call outside the fosterstack namespace, an apk signed by another key, an '
        'apk whose files differ from build/baselayout/etc or an apk that ships a CA bundle file;'),
]
def ca_bundle_hits(rel, text):
    hits = []
    for paragraph in text.split("\n\n"):
        # a table row is a sentence of its own: its cells carry no full stop to cut at
        for row in paragraph.split("\n|"):
            for sentence in re.split(r"(?<=[.!?;])\s+", " ".join(row.split())):
                if CA_BUNDLE.search(sentence) and (rel, sentence) not in REVIEWED_CA:
                    hits.append(sentence)
    return hits
notes = text_of("docs/release-notes-draft.md")
check("R8 docs/release-notes-draft.md exists", notes is not None)
check("R8 mutant: a sentence naming a CA bundle appended to the notes is caught",
      all(ca_bundle_hits("docs/release-notes-draft.md", (notes or "") + "\nThe image includes %s 20261020-r0.\n" % n)
          for n in ("ca-certificates-bundle", "ca-certificates", "CA bundle", "CA certificate bundle",
                    "CA certificates bundle", "ca-bundle", "CA-Certificates-Bundle")))
check("R8 new mention fails", ca_bundle_hits("docs/install.md", "The images ship a CA bundle.") != [])
check("R8 new mention with negation fails",
      ca_bundle_hits("docs/install.md", "The images ship no CA certificate bundle.") != [])
check("R8 new mention, hyphenated form, fails",
      ca_bundle_hits("docs/install.md", "Mount the ca-certificates package.") != [])
check("R8 new mention in a table row fails",
      ca_bundle_hits("docs/install.md", "| Item | Note |\n| CA bundle | not shipped. |") != [])
check("R8 new mention in release notes fails",
      ca_bundle_hits("docs/release-notes-draft.md", "The image now includes a CA certificate bundle.") != [])
check("R8 release notes draft has no hits", ca_bundle_hits("docs/release-notes-draft.md", notes) == [])
check("R8 each reviewed sentence passes in its own file", all(ca_bundle_hits(f, s) == [] for f, s in REVIEWED_CA))
check("R8 reviewed sentence passes inside a longer paragraph",
      all(ca_bundle_hits(f, "Intro text. " + s + " More text.") == [] for f, s in REVIEWED_CA if s[-1] in ".!?;"))
def changed(s):
    return s.replace(" no ", " a ", 1) if " no " in s else s.replace("needs", "has", 1)
check("R8 each reviewed sentence with one word changed fails",
      all(ca_bundle_hits(f, changed(s)) != [] for f, s in REVIEWED_CA))
check("R8 reviewed sentences with changed word really differ", all(changed(s) != s for f, s in REVIEWED_CA))
check("R8 reviewed sentence under a different file fails",
      all(ca_bundle_hits("docs/other.md", s) != [] for f, s in REVIEWED_CA))
check("R8 sentence without a CA bundle gives no hits",
      ca_bundle_hits("docs/install.md", "The server listens on port 8080. Nothing else is needed.") == [])
def scope_files(base):
    names = ["README.md", "SECURITY.md", "CONTRIBUTING.md", "RELEASING.md"]
    for sub in ("docs", ".vex"):
        names += [os.path.relpath(m, base) for m in glob.glob(os.path.join(base, sub, "**/*.md"), recursive=True)]
    return sorted(n for n in names if os.path.isfile(os.path.join(base, n)))
def collapsed(base, rel):
    return " ".join(open(os.path.join(base, rel)).read().split())
def scan_hits(base):
    return [(rel, h) for rel in scope_files(base) for h in ca_bundle_hits(rel, open(os.path.join(base, rel)).read())]
def reviewed_gone(base):
    return [(f, s) for f, s in REVIEWED_CA
            if not os.path.isfile(os.path.join(base, f)) or s not in collapsed(base, f)]
def copy_scope(base, dest):
    for rel in scope_files(base):
        os.makedirs(os.path.dirname(os.path.join(dest, rel)), exist_ok=True)
        shutil.copy(os.path.join(base, rel), os.path.join(dest, rel))
for rel in scope_files(root):
    text = open(os.path.join(root, rel)).read()
    hits = ca_bundle_hits(rel, text)
    check("R8 %s has no unreviewed CA bundle sentence" % rel, hits == [], hits)
check("R8 every reviewed sentence is still in its file", reviewed_gone(root) == [], reviewed_gone(root))
with tempfile.TemporaryDirectory(prefix="vex-guide-r8.") as scratch:
    copy_scope(root, scratch)
    check("R8 the copy of the tree scans clean", scan_hits(scratch) == [], scan_hits(scratch))
    with open(os.path.join(scratch, "docs/install.md"), "a") as fh:
        fh.write("\nThe images ship a CA bundle.\n")
    check("R8 a CA bundle sentence appended to a copy of docs/install.md is a hit",
          scan_hits(scratch) == [("docs/install.md", "The images ship a CA bundle.")], scan_hits(scratch))
    copy_scope(root, scratch)
    f0, s0 = REVIEWED_CA[0]
    text0 = open(os.path.join(scratch, f0)).read()
    open(os.path.join(scratch, f0), "w").write(" ".join(text0.split()).replace(s0, changed(s0), 1))
    check("R8 a reviewed sentence with one word changed in a copy is reported gone",
          reviewed_gone(scratch) == [(f0, s0)], reviewed_gone(scratch))
    copy_scope(root, scratch)
    os.remove(os.path.join(scratch, "README.md"))
    check("R8 a reviewed file missing from a copy is reported gone by name",
          reviewed_gone(scratch) == [(f, s) for f, s in REVIEWED_CA if f == "README.md"], reviewed_gone(scratch))
print("vex-guide: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
PY
