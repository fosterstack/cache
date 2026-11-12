#!/usr/bin/env bash
# proves: REQ-CHAIN-008-AC9
# Docs drift guard (REQ-CHAIN-008-AC9 covers only its release key pointer cases; docs drift guard, advisor handoffs 0309 and 0310) the Gradle and Maven snippets documented in docs/ have the
# same STRUCTURE as the client configuration the acceptance jobs run (not identical text: ids, URLs, the schema version and how uploads
# are switched on differ), and the Kubernetes reset runs in the right order. It does not run Gradle or Maven.
# Gradle: the documented local snippet addresses the cache by the loopback address 127.0.0.1 (Gradle refuses plain http for the NAME
#   localhost), no documented fenced block or prose line uses http://localhost for Gradle, every documented http (non-https) remote
#   sets isAllowInsecureProtocol = true unless it is the loopback address, and every documented remote sets push, as the
#   acceptance sample (bench/gradle-sample/settings.gradle.kts) does.
# Maven: the documented .mvn/maven-build-cache-config.xml has <remote> INSIDE <configuration>, with saveToRemote="true", enabled="true",
#   a <url> and an id that the documented settings.xml <server><id> repeats; the acceptance config
#   (bench/maven-sample/.mvn/maven-build-cache-config.xml) has the same structure (remote inside configuration, enabled, id, url) and the
#   acceptance workflow turns uploading on with maven.build.cache.remote.save.enabled=true, which is what saveToRemote="true" states in the file.
# Mutants (host back to localhost, saveToRemote missing, remote outside configuration, push missing, opt-in missing) must each be caught.
# Paths are overridable by environment so the mutants run against edited copies.
set -uo pipefail
cd "$(dirname "$0")/../../.."
export DEPLOY_DOC="${DEPLOY_DOC:-docs/docker-deploy.md}" GRADLE_DOC="${GRADLE_DOC:-docs/gradle.md}" MAVEN_DOC="${MAVEN_DOC:-docs/maven.md}"
export GRADLE_SAMPLE="${GRADLE_SAMPLE:-bench/gradle-sample/settings.gradle.kts}"
export VERIFY_DOCS="${VERIFY_DOCS:-docs/install.md docs/using-our-vex.md docs/verify-images.md RELEASING.md}"
export KEYLESS_UNTIL_DOCS_FOLD="${KEYLESS_UNTIL_DOCS_FOLD-}"
export VERIFY_ONE="${VERIFY_ONE:-docs/verify-images.md}"
export INSTALL_DOC="${INSTALL_DOC:-docs/install.md}" OFFLINE_DOC="${OFFLINE_DOC:-docs/offline-install.md}" VEX_DOC="${VEX_DOC:-docs/using-our-vex.md}"
export VERIFY_RELEASE_DOC="${VERIFY_RELEASE_DOC:-docs/verify-release.md}" VERIFY_CANNOT_RUN="${VERIFY_CANNOT_RUN:-docs/verify-release.cannot-run.json}"
export MAVEN_SAMPLE="${MAVEN_SAMPLE:-bench/maven-sample/.mvn/maven-build-cache-config.xml}"
export ACCEPTANCE="${ACCEPTANCE:-bin/acceptance-maven.sh}"   # the Maven suite, moved unchanged from acceptance.yml (REQ-CHAIN-006-AC5, Q7)

check() {  # prints one "ok:"/"FAIL:" line per assertion; exit code = number of failures
python3 - <<'PY'
import os, re, sys
import xml.etree.ElementTree as ET
fails = 0
def ok(c, m):
    global fails
    print(("ok:   " if c else "FAIL: ") + m)
    if not c: fails += 1
def blocks(path, lang):
    txt = re.sub(r"(?m)^> ?", "", open(path).read())  # fenced blocks inside a blockquote count too
    return re.findall(r"^```" + lang + r"\n(.*?)^```", txt, re.S | re.M)
def strip_c(t):  # drop comments, normalise whitespace
    t = re.sub(r"(?m)^\s*(//|#).*$", "", t)
    return re.sub(r"\s+", " ", t).strip()

# ---------------- Gradle
gdoc = re.sub(r"(?m)^> ?", "", open(os.environ["GRADLE_DOC"]).read())
samp = strip_c(open(os.environ["GRADLE_SAMPLE"]).read())
ok("isPush = true" in samp and "isAllowInsecureProtocol = true" in samp, "acceptance sample sets isPush and isAllowInsecureProtocol")
kt = [strip_c(b) for b in blocks(os.environ["GRADLE_DOC"], "kotlin") if "HttpBuildCache" in b]
ok(len(kt) >= 3, "gradle.md documents at least three Kotlin remote snippets (found %d)" % len(kt))
ok(not re.search(r"https?://localhost", "\n".join(re.findall(r"^```.*?^```", gdoc, re.S | re.M))), "no fenced Gradle block uses localhost as the cache host")
ok(not re.search(r"localhost\s+is exempt|exempt from Gradle", gdoc), "gradle.md no longer claims localhost is exempt from the plain-HTTP guard")
loop = [b for b in kt if "127.0.0.1" in b]
ok(len(loop) == 1, "exactly one documented snippet addresses the loopback address 127.0.0.1 (found %d)" % len(loop))
for i, b in enumerate(kt):
    m = re.search(r'uri\("(https?)://([^/:"]+)', b)
    ok(m is not None, "snippet %d has a url" % i)
    if not m: continue
    scheme, host = m.groups()
    ok("isPush = true" in b, "snippet %d (%s) sets isPush = true" % (i, host))
    if scheme == "http" and host != "127.0.0.1":
        ok("isAllowInsecureProtocol = true" in b, "snippet %d (plain http, %s) sets isAllowInsecureProtocol = true" % (i, host))
    if host == "127.0.0.1":
        ok(scheme == "http", "loopback snippet %d is plain http on 127.0.0.1" % i)

# ---------------- Maven
NS = "{http://maven.apache.org/BUILD-CACHE-CONFIG/%s}"
def parse(txt, label):
    root = ET.fromstring(txt)
    ns = root.tag[:root.tag.index("}") + 1]
    conf = root.find(ns + "configuration")
    ok(conf is not None, label + ": has <configuration>")
    stray = root.find(ns + "remote")
    ok(stray is None, label + ": <remote> is not a sibling of <configuration>")
    rem = conf.find(ns + "remote") if conf is not None else None
    if rem is None: rem = stray  # still judge the remote's attributes when it sits in the wrong place
    ok(conf is not None and conf.find(ns + "remote") is not None, label + ": <remote> sits inside <configuration>")
    en = conf.find(ns + "enabled") if conf is not None else None
    ok(en is not None and en.text.strip() == "true", label + ": <configuration><enabled>true")
    if rem is not None:
        ok(rem.get("enabled") == "true", label + ": remote enabled=\"true\"")
        ok(bool(rem.get("id")), label + ": remote has an id")
        u = rem.find(ns + "url")
        ok(u is not None and u.text.strip().startswith("http"), label + ": remote has a <url>")
    return rem
mblocks = blocks(os.environ["MAVEN_DOC"], "xml")
cfg = [b for b in mblocks if "<cache" in b]
ok(len(cfg) == 1, "maven.md documents exactly one cache config block (found %d)" % len(cfg))
if cfg:
    drem = parse(cfg[0], "doc")
    arem = parse(open(os.environ["MAVEN_SAMPLE"]).read(), "acceptance config")
    if drem is not None:
        ok(drem.get("saveToRemote") == "true", "doc: remote saveToRemote=\"true\" (uploads happen)")
        sv = [b for b in mblocks if "<server>" in b]
        ids = re.findall(r"<id>([^<]+)</id>", "\n".join(sv))
        ok(drem.get("id") in ids, "doc: settings.xml <server><id> repeats the remote id %r" % drem.get("id"))
wf = open(os.environ["ACCEPTANCE"]).read()
ok("-Dmaven.build.cache.remote.save.enabled=true" in wf, "acceptance-maven turns uploading on (remote.save.enabled=true), the behaviour saveToRemote=\"true\" states")
# Kubernetes reset (docs/docker-deploy.md): a Deployment does not recreate a deleted claim, so the documented order must be
# scale 0, delete the PVC, re-apply the PVC manifest, scale 1.
dd = open(os.environ["DEPLOY_DOC"]).read()
rb = [b for b in re.findall(r"```sh\n(.*?)```", dd, re.S) if "delete pvc fscache-data" in b]
ok(len(rb) == 1, "docker-deploy.md has exactly one Kubernetes reset block (found %d)" % len(rb))
if rb:
    cmds = [l.split("#")[0].strip() for l in rb[0].splitlines() if l.strip()]
    def idx(sub):
        return next((i for i, c in enumerate(cmds) if sub in c), -1)
    i0, i1, i2, i3 = idx("--replicas=0"), idx("delete pvc fscache-data"), idx("kubectl apply"), idx("--replicas=1")
    ok(-1 < i0 < i1 < i2 < i3, "reset order is scale 0, delete the claim, re-apply the claim, scale 1 (positions %s)" % [i0, i1, i2, i3])
# Verify steps (rule 6 of the simplest-correct-form rules; KA-2 p4 r2 C2): v0.3.0 and later are signed with the release key, so every verify doc holds a fenced `--key release.rsa.pub` step, and a fenced
# `--certificate-identity` step (exact, never a regexp) is allowed only under a heading or in a paragraph that names the releases before v0.3.0. The docs fold (FU-2) is done: RELEASING.md is judged like the
# other docs, KEYLESS_UNTIL_DOCS_FOLD is empty, and an assertion pins it empty.
fold = os.environ["KEYLESS_UNTIL_DOCS_FOLD"].split()
ok(fold == [], "KEYLESS_UNTIL_DOCS_FOLD is empty: no doc is judged the old way (found %r)" % fold)
def pre_v030_context(text, start):   # the nearest heading and the paragraph before a fence (fenced blocks dropped, so a shell comment is no heading)
    before = re.sub(r"^```.*?^```", "", text[:start], flags=re.S | re.M)
    heads = [l for l in before.splitlines() if re.match(r"#{1,6} ", l)]
    para = before.rstrip().split("\n\n")[-1]
    return (heads[-1] if heads else "") + "\n" + para
for path in os.environ["VERIFY_DOCS"].split():
    text = open(path).read()
    # a fenced block, as in "```sh\ncosign verify ...\n```"; text between two blocks is not matched
    fences = list(re.finditer(r"^```.*?^```", text, re.S | re.M))
    fenced = "\n".join(m.group(0) for m in fences)
    ok("--certificate-identity-regexp" not in fenced,
       "%s: no fenced step matches the signing identity with a regexp" % path)
    ok("--insecure-ignore-tlog" not in fenced,
       "%s: no fenced step turns the transparency-log check off" % path)
    if path in fold:
        ok("--certificate-identity=" in fenced or "--certificate-identity " in fenced,
           "%s: (until the docs fold) a fenced step names the exact signing identity" % path)
        continue
    ok("--key release.rsa.pub" in fenced,
       "%s: a fenced step verifies with the release key" % path)
    bad_id = [m.start() for m in fences if re.search(r"--certificate-identity[= ]", m.group(0))
              and not re.search(r"before v0\.3\.0", pre_v030_context(text, m.start()), re.I)]
    ok(not bad_id, "%s: a fenced identity step sits only under a heading or paragraph that names the releases before v0.3.0 (%d outside)" % (path, len(bad_id)))
# The image steps of the release-key form (KA-2): the signature and the release-manifest attestation of v0.3.0 and later are
# verified against the release public key, in a fenced step each.
fenced_one = "\n".join(re.findall(r"^```.*?^```", open(os.environ["VERIFY_ONE"]).read(), re.S | re.M))
ok("cosign verify --key release.rsa.pub " in fenced_one,
   "%s: a fenced step verifies the image signature with the release key" % os.environ["VERIFY_ONE"])
ok(re.search(r"cosign verify-attestation --key release\.rsa\.pub \\\n\s+--type https://fosterstack\.com/attestations/release-manifest/v1", fenced_one) is not None,
   "%s: a fenced step verifies the release-manifest attestation with the release key" % os.environ["VERIFY_ONE"])
# The release guide (v0.3.0 and later: every image and file of it is signed with the release key) and the list of its commands that cannot run before release (KA-2 p4 r2 C4): each cosign step of the guide
# verifies with the release public key and names no certificate identity, no OIDC issuer and no switch that turns the transparency-log check off; both image steps (production and -fips) are such steps; and every cosign
# command of the cannot-run list is a command of the guide (the list is what the release post-verify skips, so a command in the list that the guide does not hold is a drift).
import json
def commands(text):      # the logical commands of the fenced blocks: continued lines joined, comment lines dropped
    out, cur = [], ""
    for ln in text.splitlines():
        if ln.startswith("```"):
            continue
        if not cur and ln.lstrip().startswith("#"):
            continue
        cur += (" " if cur else "") + ln.strip().rstrip("\\").strip()
        if not ln.rstrip().endswith("\\"):
            out.append(re.sub(r"\s+", " ", cur)); cur = ""
    return [c for c in out if c]
rel_doc, cnr_file = os.environ["VERIFY_RELEASE_DOC"], os.environ["VERIFY_CANNOT_RUN"]
rel_cmds = commands("\n".join(re.findall(r"^```.*?^```", open(rel_doc).read(), re.S | re.M)))
rel_cos = [c for c in rel_cmds if c.startswith("cosign ")]
CLEAN = lambda c: "--key release.rsa.pub" in c and not re.search(r"--certificate-identity|--certificate-oidc-issuer|--insecure-ignore-tlog", c)
ok(len(rel_cos) >= 3 and all(CLEAN(c) for c in rel_cos), "%s: each cosign step (%d found) verifies with --key release.rsa.pub and names no certificate identity, no OIDC issuer and no switch that turns the log check off" % (rel_doc, len(rel_cos)))
ok(any(c.startswith("cosign verify ") and "<IMAGE_REF>" in c and CLEAN(c) for c in rel_cos) and any(c.startswith("cosign verify ") and "<IMAGE_REF_FIPS>" in c and CLEAN(c) for c in rel_cos),
   "%s: the production and the -fips image steps are `cosign verify` with the release key" % rel_doc)
cnr_cos = [e["command"] for e in json.load(open(cnr_file)) if str(e.get("command", "")).startswith("cosign ")]
ok(len(cnr_cos) >= 3 and all(CLEAN(c) for c in cnr_cos), "%s: each cosign command of the cannot-run list (%d found) verifies with --key release.rsa.pub and names no certificate identity, no OIDC issuer and no switch that turns the log check off" % (cnr_file, len(cnr_cos)))
ok(all(c in rel_cmds for c in cnr_cos), "%s: every cosign command of the cannot-run list is a command of %s" % (cnr_file, rel_doc))
# Release key pointer (REQ-CHAIN-008-AC9): next to each release key step (a fenced curl of build/keys/release.rsa.pub) of install.md (1),
# offline-install.md (2) and using-our-vex.md (1) there is one plain line outside any fence, within 6 lines of that fence, that links to
# verify-key.md; no other such line; and the fenced text of each file is the text it had before the pointer (a hash), so no command changed.
import hashlib
POINTER = re.compile(r"\]\((?:\./|docs/)?verify-key\.md(#[^)]*)?\)")
for var, steps, digest in (("INSTALL_DOC", 1, "8693fd7ace7dc0be"), ("OFFLINE_DOC", 2, "fcc1055c6fc8f6c4"), ("VEX_DOC", 1, "78465f536ebd9e2d")):
    path = os.environ[var]
    text = open(path).read()
    lines = text.split("\n")
    fences, start = [], None          # (first line, last line) of each fence, 0-based
    for i, l in enumerate(lines):
        if l.startswith("```"):
            if start is None: start = i
            else: fences.append((start, i)); start = None
    infence = {k for a, b in fences for k in range(a, b + 1)}
    ptrs = [i for i, l in enumerate(lines) if POINTER.search(l) and i not in infence]   # a link inside a fence is no pointer
    keysteps = [(a, b) for a, b in fences if any("build/keys/release.rsa.pub" in lines[k] and lines[k].startswith("curl") for k in range(a, b))]
    ok(len(keysteps) == steps, "%s: %d fenced release key step(s) (found %d)" % (path, steps, len(keysteps)))
    ok(len(ptrs) == steps, "%s: %d pointer line(s) to verify-key.md outside a fence (found %d)" % (path, steps, len(ptrs)))
    ok(all(re.match(r"[A-Za-z]", lines[i]) for i in ptrs), "%s: each pointer is a plain line (starts with a letter, no list, quote, heading or table)" % path)
    for a, b in keysteps:
        near = [i for i in ptrs if a - 6 <= i <= b + 6]
        ok(len(near) == 1, "%s: one pointer within 6 lines of the release key step at line %d (found %d)" % (path, a + 1, len(near)))
    ok(hashlib.sha256("\n".join(re.findall(r"^```.*?^```", text, re.S | re.M)).encode()).hexdigest()[:16] == digest, "%s: its fenced commands are unchanged" % path)
# Archive checksum step must fail loudly: no fenced `sha256sum -c` line hides or filters its result, and each page
# (install, offline-install, verify-images) holds the agreed grep -F + sha256sum -c - form.
AGREED = re.compile(r'LINE=\$\(grep -F "[^"]*" checksums\.txt\) && echo "\$LINE" \| sha256sum -c -')
for path in (os.environ["INSTALL_DOC"], os.environ["OFFLINE_DOC"], os.environ["VERIFY_ONE"]):
    fenced = "\n".join(re.findall(r"^```.*?^```", open(path).read(), re.S | re.M)).split("\n")
    checks = [l for l in fenced if "sha256sum -c" in l]
    ok(not [l for l in checks if "2>/dev/null" in l or "grep OK" in l], "%s: no fenced sha256sum -c line hides its errors or filters for OK" % path)
    ok(any(AGREED.search(l) for l in fenced), "%s: a fence holds the agreed grep -F checksums.txt && sha256sum -c - step" % path)
sys.exit(fails)
PY
}
check; rc=$?
echo "doc snippet assertions failed: $rc"
[ "${DOCS_SNIPPETS_NO_MUTANTS:-}" = 1 ] && exit $((rc>0))

# ---------------- mutants: each must make check() fail
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
mut=0; caught=0
mutant() {  # name, file var, python expression applied to text s (a mutation that changes nothing is a failure, never a vacuous catch)
  mut=$((mut+1)); rm -f "$tmp/m"
  if ! python3 - "${!2}" "$tmp/m" "$3" <<'PY'
import sys, os
s = open(sys.argv[1]).read(); orig = s; exec(sys.argv[3])
if s == orig: sys.exit("the mutation changed nothing")
open(sys.argv[2], "w").write(s)
PY
  then echo "FAIL: mutant did not apply: $1"; return 0; fi
  if ( export "$2=$tmp/m"; DOCS_SNIPPETS_NO_MUTANTS=1 bash "$0" >/dev/null 2>&1 ); then echo "FAIL: mutant not caught: $1"; else caught=$((caught+1)); echo "ok:   mutant caught: $1"; fi
}
mutant "gradle host back to localhost"      GRADLE_DOC 's=s.replace("http://127.0.0.1:8080/","http://localhost:8080/")'
mutant "gradle test-rig opt-in missing"     GRADLE_DOC 's=s.replace("        isAllowInsecureProtocol = true\n","",1)'
mutant "gradle push missing (loopback)"     GRADLE_DOC 's=s.replace("        isPush = true\n    }\n}\n```\n\nUse the address","    }\n}\n```\n\nUse the address")'
mutant "maven saveToRemote missing"         MAVEN_DOC  's=s.replace(" saveToRemote=\"true\"","")'
mutant "maven remote before configuration" MAVEN_DOC 'i=s.index("    <!-- FosterStack Cache"); j=s.index("</remote>")+len("</remote>"); blk=s[i:j]; s=s[:i]+s[j:]; s=s.replace("  <configuration>\n","  "+blk.strip()+"\n  <configuration>\n",1)'
mutant "maven remote sibling of configuration" MAVEN_DOC 'i=s.index("    <!-- FosterStack Cache"); j=s.index("</remote>")+len("</remote>"); blk=s[i:j]; s=s[:i]+s[j:]; s=s.replace("  </configuration>\n","  </configuration>\n"+blk+"\n",1)'
mutant "k8s reset without the re-apply"    DEPLOY_DOC 'import re; s=re.sub(r"kubectl apply -f fscache-pvc.yaml[^\n]*\n","",s)'
mutant "maven server id mismatch"           MAVEN_DOC  's=s.replace("<id>fosterstack-cache</id>","<id>other</id>")'
envmutant() {  # name, variable, value: the check run with that variable set (a list pinned by an assertion)
  mut=$((mut+1))
  if ( export "$2=$3"; DOCS_SNIPPETS_NO_MUTANTS=1 bash "$0" >/dev/null 2>&1 ); then echo "FAIL: mutant not caught: $1"; else caught=$((caught+1)); echo "ok:   mutant caught: $1"; fi
}
VERIFY_DOCS="docs/install.md" mutant "install.md: the release key step dropped" VERIFY_DOCS 's=s.replace("--key release.rsa.pub","")'
VERIFY_DOCS="$VERIFY_ONE" mutant "verify-images.md: the identity step moved outside the pre-v0.3.0 paragraph" VERIFY_DOCS 's=s.replace("A release before v0.3.0 carries","A release carries",1)'
envmutant "a second file added to KEYLESS_UNTIL_DOCS_FOLD" KEYLESS_UNTIL_DOCS_FOLD "RELEASING.md docs/install.md"
REVERT='s=s.replace("--certificate-identity=","--certificate-identity-regexp=",1)'
REVERT="$REVERT"'.replace("--certificate-identity ","--certificate-identity-regexp ",1)'
VERIFY_DOCS="$VERIFY_ONE" mutant "verify step back to an identity regexp" VERIFY_DOCS "$REVERT"
VERIFY_DOCS="$VERIFY_ONE" mutant "image signature step without the release key" VERIFY_ONE 's=s.replace("cosign verify --key release.rsa.pub ","cosign verify ",1)'
VERIFY_DOCS="$VERIFY_ONE" mutant "manifest attestation step without the release key" VERIFY_ONE 's=s.replace("verify-attestation --key release.rsa.pub","verify-attestation",1)'
VERIFY_DOCS="$VERIFY_ONE" mutant "verify step with the transparency-log check off" VERIFY_DOCS 's=s.replace("cosign verify --key release.rsa.pub ","cosign verify --key release.rsa.pub --insecure-ignore-tlog=true ",1)'
KEYF='--key release.rsa.pub'
IDENT='--certificate-identity https://github.com/fosterstack/cache/.github/workflows/stage-promote.yml@refs/tags/<TAG> --certificate-oidc-issuer https://token.actions.githubusercontent.com'
mutant "release guide: the first image step back to the keyless identity" VERIFY_RELEASE_DOC 's=s.replace("'"$KEYF"'","'"$IDENT"'",1)'
mutant "release guide: the first cosign step without the release key" VERIFY_RELEASE_DOC 's=s.replace("'"$KEYF"'","",1)'
mutant "release guide: the first cosign step with the transparency-log check off" VERIFY_RELEASE_DOC 's=s.replace("'"$KEYF"'","'"$KEYF"' --insecure-ignore-tlog=true",1)'
mutant "release guide: the last cosign step without the release key" VERIFY_RELEASE_DOC 'i=s.rindex("'"$KEYF"'"); s=s[:i]+s[i+len("'"$KEYF"'"):]'
mutant "cannot-run list: the first cosign command back to the keyless identity" VERIFY_CANNOT_RUN 's=s.replace("'"$KEYF"'","'"$IDENT"'",1)'
mutant "cannot-run list: the first cosign command without the release key" VERIFY_CANNOT_RUN 's=s.replace("'"$KEYF"'","",1)'
mutant "cannot-run list: a command the release guide does not hold" VERIFY_CANNOT_RUN 's=s.replace("<IMAGE_REF>","<IMAGE_REF_X>",1)'
# Release key pointer mutants (REQ-CHAIN-008-AC9): each file loses its pointer, has it moved far away, has it moved into the fence, or has the command of its release key step changed.
PTR='import re; P=re.compile(r"^.*\]\((?:\./|docs/)?verify-key\.md[^)]*\).*\n",re.M)'
for v in INSTALL_DOC OFFLINE_DOC VEX_DOC; do
  mutant "$v: the pointer to verify-key.md missing" "$v" "$PTR"'; s=P.sub("",s)'
  mutant "$v: the pointer moved to the end of the file" "$v" "$PTR"'; m=P.search(s); s=P.sub("",s)+m.group(0)'
  mutant "$v: the pointer moved into the fence as a comment" "$v" "$PTR"'; s=P.sub("",s,count=1); s=s.replace("build/keys/release.rsa.pub\"\n","build/keys/release.rsa.pub\"\n# see [the key page](verify-key.md)\n",1)'
  mutant "$v: the release key command changed, its key name kept" "$v" 's=s.replace("-fsSLO","-fsSL",1)'
done
mutant "offline-install.md: only the second pointer missing" OFFLINE_DOC "$PTR"'; ms=list(P.finditer(s)); s=s[:ms[-1].start()]+s[ms[-1].end():]'
echo "mutants caught: $caught/$mut"
[ "$rc" -eq 0 ] && [ "$caught" -eq "$mut" ]
