#!/usr/bin/env bash
# proves: REQ-REL-013-AC1, REQ-REL-013-AC2, REQ-REL-013-AC3, REQ-REL-013-AC4, REQ-REL-013-AC5, REQ-REL-013-AC6, REQ-REL-013-AC7, REQ-REL-013-AC8
# The monthly signed evidence letter (owner Oct 27; ops/docs/ratify/2026-10-27-monthly-evidence-letter.md):
# bin/evidence-letter.py makes the letter from a template out of the release assets and reads every fact back from
# them. Offline: no network, no signing here.
set -euo pipefail
TMPDIR=$(mktemp -d); export TMPDIR; trap 'rm -rf "$TMPDIR"' EXIT
here=$(cd "$(dirname "$0")" && pwd)
python3 - "$here/evidence-letter.py" <<'PY'
import hashlib, json, os, subprocess, sys, tempfile
SCRIPT = sys.argv[1]
passed = failed = 0
def check(name, ok, got=""):
    global passed, failed
    if ok: passed += 1; print("ok:", name)
    else: failed += 1; print("FAIL:", name, "->", got)
if not os.path.isfile(SCRIPT):
    print("FAIL: script missing:", SCRIPT); sys.exit(1)

RECORDS = ("scanners-collection.json", "acceptance-collection.json", "runtime-collection.json", "arm64-collection.json")
def sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()

def release(root, tag, published, body, statements=(), commit=None, records=RECORDS, vex_hash=None, version=None):
    d = os.path.join(root, tag); os.makedirs(d)
    json.dump({"tag_name": tag, "published_at": published,
        "html_url": "https://github.com/fosterstack/cache/releases/tag/" + tag,
               "body": body}, open(d + "/release.json", "w"))
    vex = {"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://fosterstack.com/vex/cache/openvex",
        "version": 1,
           "statements": [{"vulnerability": {"name": n}, "timestamp": ts, "status": "not_affected"} for n,
               ts in statements]}
    json.dump(vex, open(d + "/fosterstack-cache.openvex.json", "w"), sort_keys=True)
    for r in records:
        json.dump({"record": r, "tag": tag}, open(os.path.join(d, r), "w"))
    json.dump({"version": version or tag[1:], "commit": commit or ("ab" * 20),
               "vex": [{"file": "fosterstack-cache.openvex.json", "form": "openvex",
                        "sha256": vex_hash or sha(d + "/fosterstack-cache.openvex.json")}]},
                            open(d + "/release-manifest.json", "w"))
    return d

CONTROLS = "# Controls document\n\n| Version | Signed | Change |\n|---|---|---|\n| 1 | 2026-10-20 | first version |\n"
SIGNATORY = "Ada Example, Chief Example Officer"
def world(releases, advisories="[]", controls=CONTROLS, signatory=SIGNATORY):
    root = tempfile.mkdtemp(prefix="el-")
    rel = os.path.join(root, "rel"); os.makedirs(rel)
    for args, kw in releases:
        release(rel, *args, **kw)
    if advisories is not None: open(root + "/advisories.json", "w").write(advisories)
    if controls is not None: open(root + "/controls.md", "w").write(controls)
    open(root + "/signatory.txt", "w").write(signatory + "\n")
    return root

def run(root, month="2026-11", *extra):
    out = os.path.join(root, "out")
    p = subprocess.run([sys.executable, "-I", SCRIPT, "--month", month, "--releases", root + "/rel", "--advisories",
        root + "/advisories.json",
                        "--controls", root + "/controls.md", "--signatory", root + "/signatory.txt", "--out", out,
                            *extra],
                       capture_output=True, text=True)
    files = sorted(os.listdir(out)) if os.path.isdir(out) else []
    return p, out, files

NOV = [(("v0.3.1", "2026-11-04T12:00:00Z", "Fix: a parser crash on a long header.\n\nMore text."),
    {"statements": [("CVE-2026-1111", "2026-11-03T12:00:00-04:00"), ("CVE-2026-0001", "2026-10-02T12:00:00-04:00")]}),
       (("v0.4.0", "2026-11-20T12:00:00Z", "A new minor release."), {"statements": []}),
       (("v0.2.9", "2026-10-28T12:00:00Z", "Fix: an October patch."), {"statements": []})]

# AC1: exactly the releases published in the month
r = world(NOV); p, out, files = run(r)
text = open(os.path.join(out, "evidence-letter-2026-11.md")).read() if "evidence-letter-2026-11.md" in files else ""
check("AC1: a letter is made", p.returncode == 0 and bool(text), p.stderr)
check("AC1: both November releases are listed with date, link and commit", all(x in text for x in
      ("v0.3.1", "2026-11-04", "https://github.com/fosterstack/cache/releases/tag/v0.3.1", "ab" * 20, "v0.4.0",
          "2026-11-20")), text)
check("AC1: the October release is not listed", "v0.2.9" not in text)
r0 = world([]); p0, out0, files0 = run(r0)
check("AC1: a month with no release makes no letter and says so",
    p0.returncode == 0 and files0 == [] and "no release" in (p0.stdout + p0.stderr).lower(), p0.stdout + p0.stderr)
# AC2: patch release and why
check("AC2: the patch release and its reason, verbatim",
    "v0.3.1" in text and "Fix: a parser crash on a long header." in text)
check("AC2: the minor release is not called a patch", "A new minor release." not in text)
rp = world([(("v0.3.2", "2026-11-05T12:00:00Z", "\n\n"), {})]); pp, _o, fp = run(rp)
check("AC2: a patch release with no notes line refuses", pp.returncode == 1 and fp == [], pp.stderr)
# AC3: VEX statements of the month
check("AC3: the November statement is listed with its date", "CVE-2026-1111" in text and "2026-11-03" in text)
check("AC3: the October statement is not listed", "CVE-2026-0001" not in text)
rv = world([(("v0.3.3", "2026-11-06T12:00:00Z", "Fix: x."), {"vex_hash": "0" * 64})]); pv, _o, fv = run(rv)
check("AC3: an OpenVEX file whose hash differs from the manifest refuses", pv.returncode == 1 and fv == [], pv.stderr)
# AC4: Check records and advisories
check("AC4: each Check record is listed by name and hash", all(n in text for n in RECORDS) and
      sha(os.path.join(r, "rel", "v0.3.1", "scanners-collection.json")) in text)
check("AC4: no advisory is said so", "no advisory" in text.lower())
rm = world([(("v0.3.4", "2026-11-07T12:00:00Z", "Fix: y."), {"records": RECORDS[:3]})]); pm, _o, fm = run(rm)
check("AC4: a missing Check record refuses", pm.returncode == 1 and fm == [], pm.stderr)
ra = world(NOV, advisories=None); pa, _o, fa = run(ra)
check("AC4: a missing advisories file refuses", pa.returncode == 1 and fa == [], pa.stderr)
rb = world(NOV, advisories=json.dumps([{"ghsa_id": "GHSA-aaaa-bbbb-cccc", "published_at": "2026-11-09T00:00:00Z",
    "summary": "A thing"},
                                       {"ghsa_id": "GHSA-dddd-eeee-ffff", "published_at": "2026-10-09T00:00:00Z",
                                           "summary": "Old"}]))
pb, ob, fb = run(rb); tb = open(os.path.join(ob, "evidence-letter-2026-11.md")).read() if fb else ""
check("AC4: an advisory of the month is listed, one of another month is not",
    "GHSA-aaaa-bbbb-cccc" in tb and "GHSA-dddd-eeee-ffff" not in tb, tb)
# AC5: the read-back
import importlib.util
spec = importlib.util.spec_from_file_location("el",
    SCRIPT); el = importlib.util.module_from_spec(spec); spec.loader.exec_module(el)
check("AC5: the module has a read-back that accepts its own letter", hasattr(el, "read_back"))
if hasattr(el, "read_back"):
    ok = True
    try: el.read_back(text, os.path.join(r, "rel"), "2026-11", json.load(open(r + "/advisories.json")),
        open(r + "/controls.md").read())
    except Exception as e: ok = False; print("   ", e)
    check("AC5: its own letter reads back clean", ok)
    for label, bad in (("a changed commit", text.replace("ab" * 20, "cd" * 20)), ("a changed date",
        text.replace("2026-11-04", "2026-11-05")),
                       ("an invented statement", text + "\n- v0.3.1: CVE-2026-9999 (2026-11-03)\n")):
        try:
            el.read_back(bad, os.path.join(r, "rel"), "2026-11", [], open(r + "/controls.md").read()); caught = False
        except Exception: caught = True
        check("AC5: read-back catches " + label, caught)
rg = world([(("v0.3.5", "2026-11-08T12:00:00Z", "Fix: z."), {"version": "9.9.9"})]); pg, _o, fg = run(rg)
check("AC5: a manifest whose version is not the tag refuses", pg.returncode == 1 and fg == [], pg.stderr)
rj = world(NOV); open(rj + "/rel/v0.3.1/release-manifest.json", "w").write("{not json"); pj, _o, fj = run(rj)
check("AC5: a malformed asset refuses, in one line",
    pj.returncode == 1 and fj == [] and len(pj.stderr.strip().splitlines()) == 1, pj.stderr)
# AC6: the controls line
check("AC6: the binding line, unchanged", "version 1, signed on 2026-10-20, unchanged this month" in text, text)
two = CONTROLS + "| 2 | 2026-11-10 | a row changed |\n"
rc = world(NOV, controls=two); pc, oc, fc = run(rc); tc = open(os.path.join(oc,
    "evidence-letter-2026-11.md")).read() if fc else ""
check("AC6: a version change names both versions and the releases under each",
    pc.returncode == 0 and "version 1" in tc and "version 2" in tc
      and "v0.3.1" in tc.split("version 2")[0] and "v0.4.0" in tc.split("version 2")[-1], tc)
rn = world(NOV, controls=None); pn, _o, fn = run(rn)
check("AC6: no controls document refuses", pn.returncode == 1 and fn == [], pn.stderr)
# AC7: words and data
low = text.lower()
check("AC7: none of the forbidden words", not any(w in low for w in ("warranty", "certified", "compliant",
    "guarantee", "soc 2")), text)
check("AC7: no address or email", "@" not in text)
rw = world([(("v0.3.6", "2026-11-09T12:00:00Z", "Fix: now certified compliant."), {})]); pw, _o, fw = run(rw)
check("AC7: a quoted reason holding a forbidden word refuses", pw.returncode == 1 and fw == [], pw.stderr)
# AC8: the placeholder
rph = world(NOV, signatory="PLACEHOLDER: owner name and title (the advisor supplies the words)")
pph, oph, fph = run(rph)
check("AC8: the placeholder refuses and writes no letter",
    pph.returncode == 3 and fph == [] and "placeholder" in pph.stderr.lower(), pph.stderr)
pd, od, fd = run(rph, "2026-11", "--draft")
dt = open(os.path.join(od, fd[0])).read() if fd else ""
check("AC8: --draft writes one file marked DRAFT",
    pd.returncode == 0 and len(fd) == 1 and "DRAFT" in fd[0] and "DRAFT" in dt, (pd.stderr, fd))
check("AC8: a real signatory is printed in the letter", SIGNATORY in text)
# determinism and offline
p2, o2, f2 = run(world(NOV))
check("same inputs, same bytes", open(os.path.join(o2, "evidence-letter-2026-11.md")).read() == text)
src = open(SCRIPT).read()
check("offline: no network or process module is imported", not any(m in src for m in ("urllib", "socket",
    "http.client", "subprocess", "requests")))
print("%d passed, %d failed" % (passed, failed)); sys.exit(1 if failed else 0)
PY
