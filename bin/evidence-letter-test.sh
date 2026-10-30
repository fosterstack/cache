#!/usr/bin/env bash
# proves: REQ-REL-013-AC1, REQ-REL-013-AC2, REQ-REL-013-AC3, REQ-REL-013-AC4, REQ-REL-013-AC5, REQ-REL-013-AC6, REQ-REL-013-AC7, REQ-REL-013-AC8
# The monthly signed evidence letter (owner Oct 27; ops/docs/ratify/2026-10-27-monthly-evidence-letter.md):
# bin/evidence-letter.py makes the letter from a template out of the release assets. Offline: no network, no signing here.
set -euo pipefail
TMPDIR=$(mktemp -d); export TMPDIR; trap 'rm -rf "$TMPDIR"' EXIT
here=$(cd "$(dirname "$0")" && pwd)
python3 - "$here/evidence-letter.py" <<'PY'
import hashlib, json, os, subprocess, sys, tempfile
SCRIPT = sys.argv[1]
passed = failed = 0


def check(name, ok, got=""):
    global passed, failed
    if ok:
        passed += 1
        print("ok:", name)
    else:
        failed += 1
        print("FAIL:", name, "->", got)


if not os.path.isfile(SCRIPT):
    print("FAIL: script missing:", SCRIPT)
    sys.exit(1)

RECORDS = ("scanners-collection.json", "acceptance-collection.json", "runtime-collection.json", "arm64-collection.json")
LINK = "https://github.com/fosterstack/cache/releases/tag/"


def sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def release(root, tag, published, body, statements=(), commit=None, records=RECORDS, vex_hash=None, version=None):
    d = os.path.join(root, tag)
    os.makedirs(d)
    json.dump({"tag_name": tag, "published_at": published, "html_url": LINK + tag, "body": body},
              open(d + "/release.json", "w"))
    vex = {"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://fosterstack.com/vex/cache/openvex", "version": 1,
           "statements": [{"vulnerability": {"name": n}, "timestamp": ts, "status": "not_affected"}
                          for n, ts in statements]}
    json.dump(vex, open(d + "/fosterstack-cache.openvex.json", "w"), sort_keys=True)
    for r in records:
        json.dump({"record": r, "tag": tag}, open(os.path.join(d, r), "w"))
    entry = {"file": "fosterstack-cache.openvex.json", "form": "openvex",
             "sha256": vex_hash or sha(d + "/fosterstack-cache.openvex.json")}
    json.dump({"version": version or tag[1:], "commit": commit or ("ab" * 20), "vex": [entry]},
              open(d + "/release-manifest.json", "w"))
    return d


CONTROLS = "# Controls document\n\n| Version | Signed | Change |\n|---|---|---|\n| 1 | 2026-10-20 | first version |\n"
SIGNATORY = "Ada Example, Chief Example Officer"


def world(releases, advisories="[]", controls=CONTROLS, signatory=SIGNATORY):
    root = tempfile.mkdtemp(prefix="el-")
    rel = os.path.join(root, "rel")
    os.makedirs(rel)
    for args, kw in releases:
        release(rel, *args, **kw)
    if advisories is not None:
        open(root + "/advisories.json", "w").write(advisories)
    if controls is not None:
        open(root + "/controls.md", "w").write(controls)
    open(root + "/signatory.txt", "w").write(signatory + "\n")
    return root


def run(root, month="2026-11", *extra):
    out = os.path.join(root, "out")
    cmd = [sys.executable, "-I", SCRIPT, "--month", month, "--releases", root + "/rel",
           "--advisories", root + "/advisories.json", "--controls", root + "/controls.md",
           "--signatory", root + "/signatory.txt", "--out", out, *extra]
    p = subprocess.run(cmd, capture_output=True, text=True)
    files = sorted(os.listdir(out)) if os.path.isdir(out) else []
    return p, out, files


def letter(root, month="2026-11", **kw):
    """(process, text of the letter or '')."""
    p, out, files = run(root, month)
    name = "evidence-letter-%s.md" % month
    return p, (open(os.path.join(out, name)).read() if name in files else "")


NOV = [(("v0.3.1", "2026-11-04T12:00:00Z", "Fix: a parser crash on a long header.\n\nMore text."),
        {"statements": [("CVE-2026-1111", "2026-11-03T12:00:00-04:00"), ("CVE-2026-0001", "2026-10-02T12:00:00-04:00")]}),
       (("v0.4.0", "2026-11-20T12:00:00Z", "A new minor release."), {"statements": []}),
       (("v0.2.9", "2026-10-28T12:00:00Z", "Fix: an October patch."), {"statements": []})]

# AC1: exactly the releases published in the month
r = world(NOV)
p, text = letter(r)
check("AC1: a letter is made", p.returncode == 0 and bool(text), p.stderr)
check("AC1: both November releases are listed with date, link and commit", all(x in text for x in
      ("v0.3.1", "2026-11-04", LINK + "v0.3.1", "ab" * 20, "v0.4.0", "2026-11-20")), text)
check("AC1: the October release is not listed", "v0.2.9" not in text)
p0, _o0, files0 = run(world([]))
check("AC1: before any release exists there is no letter, and it says so",
      p0.returncode == 0 and files0 == [] and "no release" in (p0.stdout + p0.stderr).lower(), p0.stdout + p0.stderr)
pq, tq = letter(world([(("v0.2.9", "2026-10-28T12:00:00Z", "Fix: an October patch."), {})]))
check("AC1: a month with no release still gets a letter, from the latest release",
      pq.returncode == 0 and "none published this month" in tq and "Records of v0.2.9, the latest release" in tq
      and "scanners-collection.json" in tq, (pq.stderr, tq))
check("AC1: that letter has the controls line", "unchanged this month" in tq, tq)
# a release from before the v0.3 chain (its manifest says "v0.2.2", it has no Check records) is not read when the month has a release
old = (("v0.2.2", "2026-10-09T19:10:28Z", "Fix: an old patch."), {"version": "v0.2.2", "records": ()})
po, to = letter(world([NOV[0], old]))
check("AC1: an older release without v0.3 records does not stop a month that has its own release",
      po.returncode == 0 and "v0.3.1" in to and "v0.2.2" not in to, po.stderr)
pold, told = letter(world([old]))
check("AC1: with only such a release before the month the letter refuses, in one line",
      pold.returncode == 1 and told == "" and len(pold.stderr.strip().splitlines()) == 1, pold.stderr)

# AC2: patch release and why
check("AC2: the patch release and its reason, verbatim", "v0.3.1" in text and "Fix: a parser crash on a long header." in text)
check("AC2: the minor release is not called a patch", "A new minor release." not in text)
pp, tp = letter(world([(("v0.3.2", "2026-11-05T12:00:00Z", "\n\n"), {})]))
check("AC2: a patch release with no notes line refuses", pp.returncode == 1 and tp == "", pp.stderr)
ph, th = letter(world([(("v0.3.2", "2026-11-05T12:00:00Z", "## Fix: heading marks go."), {})]))
check("AC2: leading heading marks are dropped from the reason", ph.returncode == 0 and "v0.3.2: Fix: heading marks go." in th, th)

# AC3: VEX statements of the month
check("AC3: the November statement is listed with its date", "CVE-2026-1111" in text and "2026-11-03" in text)
check("AC3: the October statement is not listed", "CVE-2026-0001" not in text)
pv, tv = letter(world([(("v0.3.3", "2026-11-06T12:00:00Z", "Fix: x."), {"vex_hash": "0" * 64})]))
check("AC3: an OpenVEX file whose hash differs from the manifest refuses", pv.returncode == 1 and tv == "", pv.stderr)

# AC4: Check records and advisories
check("AC4: each Check record is listed by name and hash", all(n in text for n in RECORDS)
      and sha(os.path.join(r, "rel", "v0.3.1", "scanners-collection.json")) in text)
check("AC4: no advisory is said so", "no advisory" in text.lower())
pm, tm = letter(world([(("v0.3.4", "2026-11-07T12:00:00Z", "Fix: y."), {"records": RECORDS[:3]})]))
check("AC4: a missing Check record refuses", pm.returncode == 1 and tm == "", pm.stderr)
pa, ta = letter(world(NOV, advisories=None))
check("AC4: a missing advisories file refuses", pa.returncode == 1 and ta == "", pa.stderr)
ADV = [{"ghsa_id": "GHSA-aaaa-bbbb-cccc", "published_at": "2026-11-09T00:00:00Z", "summary": "A thing"},
       {"ghsa_id": "GHSA-dddd-eeee-ffff", "published_at": "2026-10-09T00:00:00Z", "summary": "Old"}]
pb, tb = letter(world(NOV, advisories=json.dumps(ADV)))
check("AC4: an advisory of the month is listed, one of another month is not",
      "GHSA-aaaa-bbbb-cccc" in tb and "GHSA-dddd-eeee-ffff" not in tb, tb)

# AC5: every fact is read from the assets, nothing else moves
r2 = world(NOV)
manifest = r2 + "/rel/v0.3.1/release-manifest.json"
swapped = open(manifest).read().replace("ab" * 20, "cd" * 20)
open(manifest, "w").write(swapped)
_p, t2 = letter(r2)
diff = [(a, b) for a, b in zip(text.splitlines(), t2.splitlines()) if a != b]
check("AC5: a changed commit in an asset changes the letter in that one line and no other",
      len(diff) == 1 and "cd" * 20 in diff[0][1] and len(text.splitlines()) == len(t2.splitlines()), diff)
r3 = world(NOV)
rj = r3 + "/rel/v0.3.1/release.json"
moved = open(rj).read().replace("2026-11-04", "2026-11-05")
open(rj, "w").write(moved)
_p, t3 = letter(r3)
check("AC5: a changed date in an asset changes the letter where the date is read",
      "published 2026-11-05" in t3 and "published 2026-11-04" not in t3)
pg, tg = letter(world([(("v0.3.5", "2026-11-08T12:00:00Z", "Fix: z."), {"version": "9.9.9"})]))
check("AC5: a manifest whose version is not the tag refuses", pg.returncode == 1 and tg == "", pg.stderr)
rj2 = world(NOV)
open(rj2 + "/rel/v0.3.1/release-manifest.json", "w").write("{not json")
pj, tj = letter(rj2)
check("AC5: a malformed asset refuses, in one line",
      pj.returncode == 1 and tj == "" and len(pj.stderr.strip().splitlines()) == 1, pj.stderr)
check("AC5: the module has no read-back (the assets are checked by the fetch step, not re-read here)",
      "read_back" not in open(SCRIPT).read())

# AC6: the controls line
check("AC6: the binding line, unchanged", "version 1, signed on 2026-10-20, unchanged this month" in text, text)
TWO = CONTROLS + "| 2 | 2026-11-10 | a row changed |\n"
pc, tc = letter(world(NOV, controls=TWO))
check("AC6: a version change names both versions and the releases under each",
      pc.returncode == 0 and "version 1" in tc and "version 2" in tc
      and "v0.3.1" in tc.split("version 2")[0] and "v0.4.0" in tc.split("version 2")[-1], tc)
only_v1 = [(("v0.3.1", "2026-11-04T12:00:00Z", "Fix: a crash."), {})]
pa1, ta1 = letter(world(only_v1, controls=CONTROLS + "| 2 | 2026-11-20 | a row changed |\n"))
check("AC6: a version signed after the month's last release is named, with the release under the old one",
      pa1.returncode == 0 and "signed on 2026-10-20: v0.3.1" in ta1 and "version 2, signed on 2026-11-20" in ta1, ta1)
quiet = [(("v0.2.9", "2026-10-22T12:00:00Z", "Fix: an October patch."), {})]
pq2, tq2 = letter(world(quiet, controls=CONTROLS + "| 2 | 2026-10-25 | a row changed |\n"))
check("AC6: a quiet month binds the images to their own release's version and names the later one separately",
      pq2.returncode == 0 and "signed on 2026-10-20: v0.2.9" in tq2 and "version 2, signed on 2026-10-25" in tq2
      and "unchanged this month" not in tq2, tq2)
pn, tn = letter(world(NOV, controls=None))
check("AC6: no controls document refuses", pn.returncode == 1 and tn == "", pn.stderr)

# AC7: words and data
check("AC7: none of the forbidden words", not any(w in text.lower() for w in
      ("warranty", "certified", "compliant", "guarantee", "soc 2")), text)
check("AC7: no address or email", "@" not in text)


def reason(note, signatory=SIGNATORY):
    return letter(world([(("v0.3.6", "2026-11-09T12:00:00Z", note), {})], signatory=signatory))


for label, note in (("a forbidden word", "Fix: now certified compliant."),
                    ("an entity-encoded letter", "Fix: cert&#105;fied now."),
                    ("an emphasis mark inside the word", "Fix: certi**fi**ed now."),
                    ("an HTML comment inside the word", "Fix: war<!---->ranty now."),
                    ("a link", "Fix: see [here](http://example.test/a)."),
                    ("SOC2 without a space", "Fix: SOC2 now."),
                    ("SOC 2 with two spaces", "Fix: SOC  2 now."),
                    ("an address", "Fix: write to a@b.test now.")):
    pw, tw = reason(note)
    check("AC7: a quoted reason with %s refuses" % label, pw.returncode == 1 and tw == "", pw.stderr)
pws, tws = reason("Fix: a crash.", signatory="Ada Example, Compliant Officer")
check("AC7: a forbidden word in the signatory refuses", pws.returncode == 1 and tws == "", pws.stderr)
pwa, twa = reason("Fix: a crash.", signatory="Ada Example, ada@example.test")
check("AC7: an address in the signatory refuses", pwa.returncode == 1 and twa == "", pwa.stderr)
pwo, two_ = reason("Fix: a crash (rare), see 1/2: ok; it's fine - really.")
check("AC7: the allowed characters pass", pwo.returncode == 0 and "Fix: a crash (rare), see 1/2: ok; it's fine - really." in two_,
      pwo.stderr)

# AC8: the placeholder
rph = world(NOV, signatory="PLACEHOLDER: owner name and title (the advisor supplies the words)")
pph, oph, fph = run(rph)
check("AC8: the placeholder refuses and writes no letter",
      pph.returncode == 3 and fph == [] and "placeholder" in pph.stderr.lower(), pph.stderr)
pd, od, fd = run(rph, "2026-11", "--draft")
dt = open(os.path.join(od, fd[0])).read() if fd else ""
check("AC8: --draft writes one file marked DRAFT", pd.returncode == 0 and len(fd) == 1 and "DRAFT" in fd[0] and "DRAFT" in dt,
      (pd.stderr, fd))
check("AC8: a real signatory is printed in the letter", SIGNATORY in text)

# determinism and offline
_p, text_again = letter(world(NOV))
check("same inputs, same bytes", text_again == text)
src = open(SCRIPT).read()
check("offline: no network or process module is imported",
      not any(m in src for m in ("urllib", "socket", "http.client", "subprocess", "requests")))
print("%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
PY
