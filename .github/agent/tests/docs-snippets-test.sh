#!/usr/bin/env bash
# Docs drift guard (no requirement covers it, so there is no AC declaration; docs drift guard, advisor handoffs 0309 and 0310) the Gradle and Maven snippets documented in docs/ have the
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
export MAVEN_SAMPLE="${MAVEN_SAMPLE:-bench/maven-sample/.mvn/maven-build-cache-config.xml}"
export ACCEPTANCE="${ACCEPTANCE:-.github/workflows/acceptance.yml}"

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
sys.exit(fails)
PY
}
check; rc=$?
echo "doc snippet assertions failed: $rc"
[ "${DOCS_SNIPPETS_NO_MUTANTS:-}" = 1 ] && exit $((rc>0))

# ---------------- mutants: each must make check() fail
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
mut=0; caught=0
mutant() {  # name, file var, python expression applied to text s
  mut=$((mut+1))
  python3 - "${!2}" "$tmp/m" "$3" <<'PY'
import sys, os
s = open(sys.argv[1]).read(); exec(sys.argv[3]); open(sys.argv[2], "w").write(s)
PY
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
echo "mutants caught: $caught/$mut"
[ "$rc" -eq 0 ] && [ "$caught" -eq "$mut" ]
