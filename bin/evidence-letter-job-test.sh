#!/usr/bin/env bash
# proves: REQ-REL-013-AC9, REQ-REL-013-AC10
# The jobs of the monthly evidence letter (owner Oct 27; the ruling of Oct 29): .github/workflows/evidence-letter.yml, bin/evidence-letter-fetch.sh and
# bin/evidence-letter-publish.sh. Offline: cosign and gh are stand-ins that record their arguments; nothing is signed or uploaded.
set -euo pipefail
TMPDIR=$(mktemp -d); export TMPDIR; trap 'rm -rf "$TMPDIR"' EXIT
here=$(cd "$(dirname "$0")" && pwd); root=$(cd "$here/.." && pwd)
python3 - "$root" <<'PY'
import json, os, re, stat, subprocess, sys, tempfile
ROOT = sys.argv[1]
passed = failed = 0
def check(name, ok, got=""):
    global passed, failed
    if ok: passed += 1; print("ok:", name)
    else: failed += 1; print("FAIL:", name, "->", got)
def read(rel): return open(os.path.join(ROOT, rel)).read()

# ---- the workflow file
WF = ".github/workflows/evidence-letter.yml"
wf = read(WF)
import yaml
doc = yaml.safe_load(wf)
triggers = doc.get(True, doc.get("on"))
check("AC9: the workflow is evidence-letter.yml and starts only on a monthly schedule or by hand", sorted(triggers) == ["schedule", "workflow_dispatch"]
      and len(triggers["schedule"]) == 1 and re.fullmatch(r"\d+ \d+ \d+ \* \*", triggers["schedule"][0]["cron"]), triggers)
check("AC9: the token of the workflow can only read", doc["permissions"] == {"contents": "read"}, doc["permissions"])
jobs = doc["jobs"]
check("AC9: two jobs, draft and sign", list(jobs) == ["draft", "sign"], list(jobs))
check("AC9: only the sign job holds an identity token", "id-token" not in jobs["draft"]["permissions"] and jobs["sign"]["permissions"].get("id-token") == "write", jobs)
check("AC9: the draft job writes nothing and the sign job is the only one that writes releases", jobs["draft"]["permissions"] == {"contents": "read"}
      and jobs["sign"]["permissions"]["contents"] == "write")
uses = re.findall(r"uses:\s*(\S+)", wf)
check("AC9: every action is pinned to a full commit id", uses and all(re.fullmatch(r".+@[0-9a-f]{40}", u) for u in uses), uses)
check("AC9: no secrets and no pull-request trigger", "secrets." not in wf and "pull_request" not in wf)
check("AC9: the sign job signs only through the publish script, after cosign is installed by checksum", "bash bin/install-scanner.sh cosign" in wf
      and "bash bin/evidence-letter-publish.sh" in wf and "cosign sign" not in wf)
check("AC10: the draft job fetches, then makes the letter without --draft", "bash bin/evidence-letter-fetch.sh" in wf and "bin/evidence-letter.py" in wf
      and "--draft" not in wf)
check("AC9: the identity customers verify is named in the workflow header and in the verify guide", all(
      "https://github.com/fosterstack/cache/.github/workflows/evidence-letter.yml@refs/heads/main" in read(f) for f in (WF, "docs/verify-release.md")))
rs = read("bin/release-sign.sh")
pub = read("bin/evidence-letter-publish.sh")
check("AC9: the signing call and config are release-sign.sh's", "cosign sign-blob --yes --signing-config .github/policy/cosign-signing-config.json --bundle" in rs
      and "cosign sign-blob --yes --signing-config .github/policy/cosign-signing-config.json --bundle" in pub)
check("AC9: no upload may overwrite", "--clobber" not in pub and "--clobber" not in wf)

# ---- the placeholder: the committed signatory text refuses a real letter
with tempfile.TemporaryDirectory() as t:
    for name, text in (("advisories.json", "[]"), ("controls.md", "| 1 | 2026-10-20 | first |\n")):
        open(os.path.join(t, name), "w").write(text)
    os.makedirs(os.path.join(t, "rel"))
    p = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "bin/evidence-letter.py"), "--month", "2026-11", "--releases", t + "/rel",
                        "--advisories", t + "/advisories.json", "--controls", t + "/controls.md",
                        "--signatory", os.path.join(ROOT, "docs/evidence-letter-signatory.txt"), "--out", t + "/out"], capture_output=True, text=True)
    check("AC10: the committed signatory text is the placeholder and the script refuses it", p.returncode == 3 and "placeholder" in p.stderr.lower(), p.stderr)

# ---- stand-ins for cosign and gh
def stand_in(binroot, log, tlog=True, latest="v0.9.9", refuse_upload=False, releases="[]", advisories="[]"):
    os.makedirs(binroot, exist_ok=True)
    def w(name, body):
        p = os.path.join(binroot, name); open(p, "w").write(body); os.chmod(p, 0o755)
    w("cosign", '#!/bin/sh\necho "cosign $*" >> "%s"\nwhile [ $# -gt 0 ]; do [ "$1" = --bundle ] && b=$2; shift; done\n'
      'echo \'{"verificationMaterial":{"tlogEntries":%s}}\' > "$b"\n' % (log, "[{}]" if tlog else "[]"))
    w("gh", '#!/bin/sh\necho "gh $*" >> "%s"\ncase "$1 $2" in\n  "release view") echo %s ;;\n  "release upload") %s ;;\n'
      '  "release list") cat "%s/releases.json" ;;\n  "api repos/fosterstack/cache/releases/tags/"*) echo \'{"assets":[{"id":11,"name":"release-manifest.json"},{"id":12,"name":"fosterstack-cache.openvex.json"},{"id":13,"name":"check-collection.json"},{"id":14,"name":"checksums.txt"}]}\' ;;\n'
      '  "api repos/fosterstack/cache/releases/assets/"*) echo "asset ${2##*/}" ;;\n'
      '  "api repos/fosterstack/cache/security-advisories?state=published&per_page=100") cat "%s/advisories.json" ;;\n  api*) echo "{}" ;;\nesac\n'
      % (log, latest, "exit 1" if refuse_upload else "exit 0", binroot, binroot))
    open(os.path.join(binroot, "releases.json"), "w").write(releases)
    open(os.path.join(binroot, "advisories.json"), "w").write(advisories)

def publish(**kw):
    t = tempfile.mkdtemp(); log = t + "/log"; open(log, "w").close()
    stand_in(t + "/bin", log, **kw)
    letter = t + "/evidence-letter-2026-11.md"; open(letter, "w").write("a letter\n")
    env = dict(os.environ, PATH=t + "/bin:" + os.environ["PATH"], GH_TOKEN="x")
    p = subprocess.run(["bash", os.path.join(ROOT, "bin/evidence-letter-publish.sh"), letter], cwd=ROOT, env=env, capture_output=True, text=True)
    return p, open(log).read().splitlines(), letter

p, log, letter = publish()
check("AC9: a good run signs, then uploads the letter and its bundle to the latest release", p.returncode == 0
      and any(l.startswith("cosign sign-blob --yes --signing-config .github/policy/cosign-signing-config.json --bundle " + letter + ".bundle") for l in log)
      and any(l == "gh release upload v0.9.9 %s %s.bundle --repo fosterstack/cache" % (letter, letter) for l in log), (p.stderr, log))
check("AC9: the upload does not overwrite", not any("--clobber" in l for l in log), log)
p, log, _l = publish(tlog=False)
check("AC9: a bundle with no Rekor entry publishes nothing", p.returncode == 1 and not any("release upload" in l for l in log) and "Rekor" in p.stderr, (p.stderr, log))
p, log, _l = publish(refuse_upload=True)
check("AC9: a refused upload fails closed with one plain line", p.returncode == 1 and len(p.stderr.strip().splitlines()) == 1 and "not published" in p.stderr, p.stderr)

# ---- the fetch script
t = tempfile.mkdtemp(); log = t + "/log"; open(log, "w").close()
rel = json.dumps([{"tagName": "v0.4.0", "publishedAt": "2026-11-20T12:00:00Z"}, {"tagName": "v0.3.1", "publishedAt": "2026-11-04T12:00:00Z"},
                  {"tagName": "v0.3.0", "publishedAt": "2026-10-30T12:00:00Z"}, {"tagName": "v0.2.0", "publishedAt": "2026-09-01T12:00:00Z"},
                  {"tagName": "v0.5.0-rc1", "publishedAt": "2026-11-21T12:00:00Z"}, {"tagName": "v0.6.0", "publishedAt": "2026-12-03T12:00:00Z"}])
stand_in(t + "/bin", log, releases=rel, advisories=json.dumps([[{"ghsa_id": "GHSA-a", "published_at": "2026-11-09T00:00:00Z", "summary": "x"}]]))
env = dict(os.environ, PATH=t + "/bin:" + os.environ["PATH"], GH_TOKEN="x")
p = subprocess.run(["bash", os.path.join(ROOT, "bin/evidence-letter-fetch.sh"), "2026-11", t + "/out"], cwd=ROOT, env=env, capture_output=True, text=True)
got = sorted(os.listdir(t + "/out/rel")) if os.path.isdir(t + "/out/rel") else []
check("AC10: the fetch takes the month's final releases and the latest one before it, no candidate and no later release", p.returncode == 0
      and got == ["v0.3.0", "v0.3.1", "v0.4.0"], (p.stderr, got))
check("AC10: it writes release.json for each and the advisories as one list", all(os.path.isfile(t + "/out/rel/%s/release.json" % g) for g in got)
      and json.load(open(t + "/out/advisories.json")) == [{"ghsa_id": "GHSA-a", "published_at": "2026-11-09T00:00:00Z", "summary": "x"}])
check("AC10: it fetches the three evidence files of each release through the API and no other asset, and never `gh release download` (the pin-age check cannot measure that form)",
      all(sorted(os.listdir(t + "/out/rel/" + g)) == ["check-collection.json", "fosterstack-cache.openvex.json", "release-manifest.json", "release.json"] for g in got)
      and open(t + "/out/rel/v0.3.0/release-manifest.json").read() == "asset 11\n" and not any("release download" in l for l in open(log).read().splitlines()))
check("AC10: it only reads: no upload, no write call", not any(("upload" in l or "-X" in l or "--method" in l) for l in open(log).read().splitlines()))
p = subprocess.run(["bash", os.path.join(ROOT, "bin/evidence-letter-fetch.sh"), "2026-13", t + "/o2"], cwd=ROOT, env=env, capture_output=True, text=True)
check("AC10: a bad month is refused", p.returncode == 2, p.stderr)
print("%d passed, %d failed" % (passed, failed)); sys.exit(1 if failed else 0)
PY
