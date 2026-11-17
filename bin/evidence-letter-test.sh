#!/usr/bin/env bash
# proves: REQ-REL-013-AC1, REQ-REL-013-AC2, REQ-REL-013-AC3, REQ-REL-013-AC4
# proves: REQ-REL-013-AC5, REQ-REL-013-AC6, REQ-REL-013-AC7, REQ-REL-013-AC8, REQ-REL-013-AC11
# The monthly signed evidence letter (owner Oct 27; ops/docs/ratify/2026-10-27-monthly-evidence-letter.md):
# bin/evidence-letter.py makes the letter from a template out of the release assets.
# Offline: no network, no signing here.
set -euo pipefail
TMPDIR=$(mktemp -d); export TMPDIR; trap 'rm -rf "$TMPDIR"' EXIT
here=$(cd "$(dirname "$0")" && pwd)
python3 - "$here/evidence-letter.py" <<'PY'
import base64, calendar, hashlib, json, os, shutil, subprocess, sys, tempfile, time
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
    # release.json is unsigned: it holds decoys, so a letter that reads it shows the wrong date, link or reason
    json.dump({"tag_name": tag, "published_at": "2020-01-01T00:00:00Z", "html_url": "https://example.test/" + tag,
               "body": "## " + tag + " \u2014 patch release"}, open(d + "/release.json", "w"))
    vex = {"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://fosterstack.com/vex/cache/openvex",
           "version": 1,
           "statements": [{"vulnerability": {"name": n}, "timestamp": ts, "status": "not_affected"}
                          for n, ts in statements]}
    json.dump(vex, open(d + "/fosterstack-cache.openvex.json", "w"), sort_keys=True)
    for r in records:
        json.dump({"record": r, "tag": tag}, open(os.path.join(d, r), "w"))
    entry = {"file": "fosterstack-cache.openvex.json", "form": "openvex",
             "sha256": vex_hash or sha(d + "/fosterstack-cache.openvex.json")}
    # the signed release metadata (release-manifest.json) holds the date and the reason
    json.dump({"version": version or tag[1:], "commit": commit or ("ab" * 20), "vex": [entry],
               "published_at": published, "reason": body}, open(d + "/release-manifest.json", "w"))
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
        {"statements": [("CVE-2026-1111", "2026-11-03T12:00:00-04:00"),
                        ("CVE-2026-0001", "2026-10-02T12:00:00-04:00")]}),
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
# a release from before the v0.3 chain (its manifest says "v0.2.2", it has no Check records) is not read when the
# month has a release
old = (("v0.2.2", "2026-10-09T19:10:28Z", "Fix: an old patch."), {"version": "v0.2.2", "records": ()})
po, to = letter(world([NOV[0], old]))
check("AC1: an older release without v0.3 records does not stop a month that has its own release",
      po.returncode == 0 and "v0.3.1" in to and "v0.2.2" not in to, po.stderr)
pold, told = letter(world([old]))
check("AC1: with only such a release before the month the letter refuses, in one line",
      pold.returncode == 1 and told == "" and len(pold.stderr.strip().splitlines()) == 1, pold.stderr)

# AC2: patch release and why
check("AC2: the patch release and its reason, verbatim",
      "v0.3.1" in text and "Fix: a parser crash on a long header." in text)
check("AC2: the minor release is not called a patch", "A new minor release." not in text)
pp, tp = letter(world([(("v0.3.2", "2026-11-05T12:00:00Z", "\n\n"), {})]))
check("AC2: a patch release with no notes line refuses", pp.returncode == 1 and tp == "", pp.stderr)
ph, th = letter(world([(("v0.3.2", "2026-11-05T12:00:00Z", "Fix: the signed reason."), {})]))
check("AC2: the reason is the signed metadata's, not the em-dash heading of the unsigned notes",
      ph.returncode == 0 and "v0.3.2: Fix: the signed reason." in th and "patch release" not in th, th)

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
rm = r3 + "/rel/v0.3.1/release-manifest.json"
moved_manifest = open(rm).read().replace("2026-11-04", "2026-11-05")
open(rm, "w").write(moved_manifest)
_p, t3 = letter(r3)
check("AC5: a changed date in the signed metadata changes the letter where the date is read",
      "published 2026-11-05" in t3 and "published 2026-11-04" not in t3)
r4 = world(NOV)
rj = r4 + "/rel/v0.3.1/release.json"
json.dump({"tag_name": "v0.3.1", "published_at": "2026-11-27T12:00:00Z", "html_url": "https://example.test/x",
           "body": "Fix: a forged reason."}, open(rj, "w"))
_p, t4 = letter(r4)
check("AC5: a tampered release.json (date, link, body) does not change the letter", t4 == text, t4)
check("AC5: the release link is built from the tag", LINK + "v0.3.1" in text and "example.test" not in text, text)
r5 = world(NOV)
os.remove(r5 + "/rel/v0.3.1/release.json")
_p, t5 = letter(r5)
check("AC5: release.json is not needed at all", t5 == text, t5)
pe = letter(world([(("v0.3.2", "2026-11-05T12:00:00Z", ""), {})]))
check("AC5: a patch release whose signed metadata holds no reason refuses even if release.json has a body",
      pe[0].returncode == 1 and pe[1] == "", pe[0].stderr)
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
                    ("SOC-2 with a hyphen", "Fix: SOC-2 now."),
                    ("S.O.C. 2 with full stops", "Fix: S.O.C. 2 now."),
                    ("an address", "Fix: write to a@b.test now.")):
    pw, tw = reason(note)
    check("AC7: a quoted reason with %s refuses" % label, pw.returncode == 1 and tw == "", pw.stderr)
pws, tws = reason("Fix: a crash.", signatory="Ada Example, Compliant Officer")
check("AC7: a forbidden word in the signatory refuses", pws.returncode == 1 and tws == "", pws.stderr)
pwc, twc = reason("Fix: a crash.", signatory="Ada Example, {{customer_name}}")
check("AC7: the email side's customer-name mark in the letter refuses (the bytes are sent as they are)",
      pwc.returncode == 1 and twc == "" and "customer_name" in pwc.stderr, pwc.stderr)
pwa, twa = reason("Fix: a crash.", signatory="Ada Example, ada@example.test")
check("AC7: an address in the signatory refuses", pwa.returncode == 1 and twa == "", pwa.stderr)
pwo, two_ = reason("Fix: a crash (rare), see 1/2: ok; it's fine - really.")
check("AC7: the allowed characters pass",
      pwo.returncode == 0 and "Fix: a crash (rare), see 1/2: ok; it's fine - really." in two_,
      pwo.stderr)

# AC8: the placeholder
rph = world(NOV, signatory="PLACEHOLDER: owner name and title (the advisor supplies the words)")
pph, oph, fph = run(rph)
check("AC8: the placeholder refuses and writes no letter",
      pph.returncode == 3 and fph == [] and "placeholder" in pph.stderr.lower(), pph.stderr)
pd, od, fd = run(rph, "2026-11", "--draft")
dt = open(os.path.join(od, fd[0])).read() if fd else ""
check("AC8: --draft writes one file marked DRAFT",
      pd.returncode == 0 and len(fd) == 1 and "DRAFT" in fd[0] and "DRAFT" in dt,
      (pd.stderr, fd))
check("AC8: a real signatory is printed in the letter", SIGNATORY in text)

# determinism and offline
_p, text_again = letter(world(NOV))
check("same inputs, same bytes", text_again == text)
src = open(SCRIPT).read()
check("offline: no network or process module is imported",
      not any(m in src for m in ("urllib", "socket", "http.client", "subprocess", "requests")))

# ---- the cases of the scripts the evidence letter's jobs run (bin/evidence-letter-fetch.sh, -verify.sh, -present.sh)
# They run in a sandbox: a copy of bin/ and the policy folder with a root key and a release key made here, and
# stand-ins (cosign, gh, date, the Check-record verifier) that record their arguments; nothing is signed or uploaded.
# Each case below keeps the label it had in the job suite.
ROOT = os.path.dirname(os.path.dirname(SCRIPT))
STUBS = {
    "cosign": """#!/bin/sh
echo "cosign $*" >> "$LOG"
prev=""
for a in "$@"; do
  # the file that follows --key is the key: log what it holds
  if [ "$prev" = --key ] && [ -f "$a" ]; then echo "key-file: $(cat "$a")" >> "$LOG"; fi
  prev=$a
done
case "$1" in
  verify-blob)
    n=$(grep -c "^cosign verify-blob" "$LOG")
    [ ! -e "$FIX/bad-signature" ] && [ -z "$FAIL_VERIFY" ] && { [ -z "$FAIL_VERIFY_AFTER" ] || [ "$n" -lt 2 ]; } ;;
esac
""",
    "date": """#!/bin/sh
case "$*" in *%Y-%m-%d*) cat "$FIX/today_full" ;; *%Y-%m*) cat "$FIX/today" ;; *) exec /bin/date "$@" ;; esac
""",
    "python3": """#!/bin/sh
case "$*" in
  *chain-verify.py*policy*make*) echo "python3 $*" >> "$LOG" ;;
  *chain-verify.py*check-list*)
    [ -z "$REAL_CHECKLIST" ] || exec "$REAL_PYTHON" "$@"
    echo "python3 $*" >> "$LOG"
    if [ -e "$FIX/bad-records" ]; then echo "refused at check: the scanners record is not signed" >&2; exit 1; fi
    exit 0 ;;
esac
exec "$REAL_PYTHON" "$@"
""",
    "gh": """#!/bin/sh
echo "gh $*" >> "$LOG"
case "$1 $2" in
  "api --paginate") for a in "$@"; do path=$a; done
    case "$path" in
      *security-advisories*)
        [ ! -e "$FIX/no-advisories" ] || { echo "gh: Not Found (HTTP 404)" >&2; exit 1; }
        cat "$FIX/advisories.json" ;;
      *) cat "$FIX/pages.json" ;;
    esac ;;
  "api repos/"*) cat "$FIX/assets/${2##*/}" ;;
esac
""",
}


def openssl(*args):
    return subprocess.run(["openssl", *args], check=True, capture_output=True).stdout


def sha_of(data):
    return hashlib.sha256(data).hexdigest()


def throwaway_repo(tmp):
    """A copy of the scripts and the policy folder with a root key, a release key and a manifest made here: the real
    `chain-verify.py policy make` runs on it, so no case needs a stand-in for the tool under test."""
    repo = os.path.join(tmp, "repo")
    shutil.copytree(os.path.join(ROOT, "bin"), os.path.join(repo, "bin"))
    shutil.copytree(os.path.join(ROOT, ".github/policy"), os.path.join(repo, ".github/policy"))
    keys = os.path.join(tmp, "keys")
    os.makedirs(keys)
    for name in ("root", "rel"):
        openssl("genpkey", *(("-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256") if name == "root" else ("-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:4096")), "-out", keys + "/%s.key" % name)
        openssl("pkey", "-in", keys + "/%s.key" % name, "-pubout", "-out", keys + "/%s.pub" % name)
    pub = open(keys + "/rel.pub").read()
    der = openssl("pkey", "-pubin", "-in", keys + "/rel.pub", "-outform", "DER")
    when = "2026-11-01T00:00:00Z"  # fixed, before the fixed signing time of 3 December (SIGNED_DEC3), whatever today is
    body = json.dumps({"public_key": pub, "key_id": hashlib.sha256(der).hexdigest(), "valid_from": when},
                      sort_keys=True, indent=1).encode() + b"\n"
    pol = os.path.join(repo, ".github/policy")
    open(pol + "/release-key-root.pub", "w").write(open(keys + "/root.pub").read())
    open(pol + "/release-key-manifest.json", "wb").write(body)
    open(keys + "/m.json", "wb").write(body)
    sig = openssl("dgst", "-sha256", "-sign", keys + "/root.key", keys + "/m.json")
    open(pol + "/release-key-manifest.sig", "w").write(base64.b64encode(sig).decode() + "\n")
    return repo, pub.splitlines()[1]


def sandbox(tmp):
    fix, bins = os.path.join(tmp, "fix"), os.path.join(tmp, "bin")
    os.makedirs(os.path.join(fix, "assets"))
    os.makedirs(bins)
    repo, key_line = throwaway_repo(tmp)
    for name, body in STUBS.items():
        path = os.path.join(bins, name)
        open(path, "w").write(body)
        os.chmod(path, 0o755)
    open(os.path.join(tmp, "log"), "w").write("throwaway-key: %s\n" % key_line)
    open(os.path.join(fix, "today"), "w").write("2026-12\n")
    open(os.path.join(fix, "today_full"), "w").write("2026-12-10\n")
    open(os.path.join(fix, "advisories.json"), "w").write(
        json.dumps([[{"ghsa_id": "GHSA-a"}], [{"ghsa_id": "GHSA-b"}]]))
    env = dict(os.environ, PATH=bins + ":" + os.environ["PATH"], FIX=fix, LOG=os.path.join(tmp, "log"), GH_TOKEN="x",
               REAL_PYTHON=sys.executable, REAL_CHECKLIST="", REPO_DIR=repo, FAIL_VERIFY="", FAIL_VERIFY_AFTER="")
    return fix, env


def put_releases(fix, releases, signed=None, manifests=None):
    """releases: [(tag, published, draft, prerelease, page)]; every one gets the assets the fetch needs,
    ids from 100, and a JSON release-manifest.json. signed: {tag: the published_at its signed manifest holds}
    (else the listed published date). manifests: {tag: the raw bytes of its manifest, or None for no manifest
    asset at all}."""
    pages, next_id = {}, 100
    for tag, published, draft, pre, page in releases:
        vex = ("vex of " + tag).encode()
        manifest = json.dumps({"version": tag[1:], "published_at": (signed or {}).get(tag, published)}).encode()
        if manifests and tag in manifests:
            manifest = manifests[tag]
        files = {} if manifest is None else {"release-manifest.json": manifest}
        listing = "" if manifest is None else "%s  release-manifest.json\n" % sha_of(manifest)
        files.update({"fosterstack-cache.openvex.json": vex,
                 "release-files.sha256": (listing + "%s  fosterstack-cache.openvex.json\n" % sha_of(vex)).encode(),
                 "release-files.sha256.bundle": b'{"verificationMaterial":{"tlogEntries":[{}]}}',
                 "digests.json": json.dumps({"image-production": "sha256:" + "a" * 64}).encode()})
        for step in ("scanners", "acceptance", "runtime", "arm64"):
            files["%s-collection.json" % step] = ("record %s of %s" % (step, tag)).encode()
        assets = []
        for name, data in files.items():
            open(os.path.join(fix, "assets", str(next_id)), "wb").write(data)
            assets.append({"id": next_id, "name": name})
            next_id += 1
        pages.setdefault(page, []).append({"tag_name": tag, "published_at": published, "draft": draft,
                                           "prerelease": pre, "assets": assets})
    json.dump([pages[k] for k in sorted(pages)], open(os.path.join(fix, "pages.json"), "w"))



RELEASES = [("v0.4.0", "2026-11-20T12:00:00Z", False, False, 1), ("v0.6.0", "2027-02-03T12:00:00Z", False, False, 1),
            ("v0.3.1", "2026-11-04T12:00:00Z", False, False, 2), ("v0.3.0", "2026-10-30T12:00:00Z", False, False, 2),
            ("v0.5.0-rc1", "2026-11-21T12:00:00Z", False, True, 2), ("v0.4.5", "2026-11-22T12:00:00Z", True, False, 2)]


def fetch(month, edit=None, today=None, release_list=RELEASES, real_verifier=False, signed=None, manifests=None):
    tmp = tempfile.mkdtemp()
    fix, env = sandbox(tmp)
    put_releases(fix, release_list, signed, manifests)
    if today:
        open(os.path.join(fix, "today"), "w").write(today + "\n")
    if edit:
        edit(fix)
    if real_verifier:
        env["REAL_CHECKLIST"] = "1"
    out = os.path.join(tmp, "work")
    p = subprocess.run(["bash", os.path.join(env["REPO_DIR"], "bin/evidence-letter-fetch.sh"), month, out], cwd=env["REPO_DIR"], env=env,
                       capture_output=True, text=True)
    # every final release from v0.3.0 on is verified (its list and manifest are fetched) before its date is read, so rel/ holds a folder for each of them;
    # the releases the fetch took for the letter are the ones whose files were fetched in full (digests.json is one of them)
    got = sorted(d for d in os.listdir(out + "/rel") if os.path.isfile(out + "/rel/%s/digests.json" % d)) if os.path.isdir(out + "/rel") else []
    return p, got, open(os.path.join(tmp, "log")).read().splitlines(), out, fix


def one_line(p):
    return p.returncode == 1 and len(p.stderr.strip().splitlines()) == 1


def key_of(log):
    """The public key line of the throwaway release key this sandbox made (the first line the log holds)."""
    return next(l for l in log if l.startswith("throwaway-key: ")).split(": ", 1)[1]



# ---- the fetch: which releases, from all pages
p, got, log, out, fix = fetch("2026-11")
check("AC10: the fetch takes the month's final releases from every page, no candidate, draft or other month",
      p.returncode == 0 and got == ["v0.3.1", "v0.4.0"], (p.stderr, got))
p2, got2, _l, _o, _f = fetch("2027-01", today="2027-03")
check("AC10: a month with no release gets the newest release before it, and only that one",
      p2.returncode == 0 and got2 == ["v0.4.0"], (p2.stderr, got2))
p3, got3, _l, _o, _f = fetch("2026-10")
check("AC10: a month with a release does not fetch the release before it", got3 == ["v0.3.0"], got3)
check("AC10: it writes release.json for each and the advisories as one list from every page",
      all(os.path.isfile(out + "/rel/%s/release.json" % g) for g in got)
      and json.load(open(out + "/advisories.json")) == [{"ghsa_id": "GHSA-a"}, {"ghsa_id": "GHSA-b"}])
check("AC10: it only reads: no upload, no write call",
      not any(("upload" in l or "-X" in l or "--method" in l) for l in log))
check("AC10: it fetches the files the verification needs and no release is downloaded by the subcommand",
      os.path.isfile(out + "/rel/v0.3.1/release-files.sha256.bundle")
      and os.path.isfile(out + "/rel/v0.3.1/digests.json")
      and os.path.isfile(out + "/rel/v0.3.1/witness-check/witness-arm64/arm64-collection.json")
      and not any("release download" in l for l in log))
check("AC10: a bad month is refused", fetch("2026-13")[0].returncode == 2)
check("AC9: a month that is not over is refused, in one line", one_line(fetch("2026-12", today="2026-12")[0]))
check("AC9: a future month is refused", one_line(fetch("2027-05", today="2026-12")[0]))

def no_advisories(fix):
    open(os.path.join(fix, "no-advisories"), "w").close()


pn = fetch("2026-11", no_advisories)
check("F15: advisories the token cannot read (a 403 or 404) refuse the letter, in one line that names them",
      one_line(pn[0]) and "advisories" in pn[0].stderr and "HTTP 404" in pn[0].stderr, pn[0].stderr)


# ---- the checks on what was fetched
def list_verifies(log, tag):
    bundle = "/rel/%s/release-files.sha256.bundle" % tag
    return [l for l in log if l.startswith("cosign verify-blob --key ") and bundle in l]


ROOT_FLAG = "--trusted-root .github/policy/rekor-trusted-root.json"
check("F1 1: each release's list is verified through the helper with the key and the pinned log, no identity",
      all(len(list_verifies(log, t)) == 1 and ROOT_FLAG in list_verifies(log, t)[0]
          and "--certificate" not in list_verifies(log, t)[0] for t in ("v0.3.1", "v0.4.0")), log)
check("F1 5: each fetched release gets its own policy made for its tag, never for a branch",
      sum("policy make" in l and "--tag v0.3.1" in l for l in log) == 1
      and sum("policy make" in l and "--tag v0.4.0" in l for l in log) == 1
      and not any("policy make" in l and "--ref" in l for l in log), log)
check("F1 9: the list is verified with the key of the policy that check-list then gets (the key the manifest holds)",
      log.count(key_of(log)) == 4 and log.count("key-file: -----BEGIN PUBLIC KEY-----") == 4
      and all(any("check-list --policy " in l and "/rel/%s/policy.json" % t in l for l in log)
              for t in ("v0.3.1", "v0.4.0")), log)
check("AC10: the Check records are verified with the same command Release runs, under a policy made for the tag",
      sum("check-list --policy" in l for l in log) == 2 and os.path.isfile(out + "/rel/v0.3.1/policy.json"), log)


def find(log, *needles):
    return next((i for i, l in enumerate(log) if all(n in l for n in needles)), 10 ** 6)


order_ok = True
for t in ("v0.3.1", "v0.4.0"):
    made = find(log, "policy make", "--tag " + t)
    listed = find(log, "cosign verify-blob", "/rel/%s/release-files.sha256.bundle" % t)
    checked = find(log, "check-list --policy", "/rel/%s/policy.json" % t)
    order_ok = order_ok and made < listed < checked
check("F1 7: per release the policy is made, then the list is verified, then check-list runs", order_ok, log)


def helper(edit=None, tag=None, bundle='{"verificationMaterial":{"tlogEntries":[{}]}}'):
    """The shared check on an UNMODIFIED policy made by the real `chain-verify.py policy make` (a branch ref, or a tag)."""
    tmp = tempfile.mkdtemp()
    fix, env = sandbox(tmp)
    pol, letter = os.path.join(tmp, "policy.json"), os.path.join(tmp, "evidence-letter-2026-11.md")
    which = ["--tag", tag] if tag else ["--ref", "refs/heads/main"]
    subprocess.run(["python3", "-I", "bin/chain-verify.py", "policy", "make", "--template",
                    ".github/policy/release-policy.template.json", *which, "--out", pol],
                   cwd=env["REPO_DIR"], env=env, check=True, capture_output=True)
    if edit:
        doc = json.load(open(pol))
        edit(doc)
        json.dump(doc, open(pol, "w"))
    open(letter, "w").write("a letter\n")
    open(letter + ".bundle", "w").write(bundle)
    p = subprocess.run(["bash", "bin/evidence-letter-verify.sh", pol, letter], cwd=env["REPO_DIR"], env=env,
                       capture_output=True, text=True)
    return p, open(os.path.join(tmp, "log")).read().splitlines()


for label, tag in (("a branch ref", None), ("a tag", "v0.3.1")):
    ph, lh = helper(tag=tag)
    check("R1 a: the helper on the real policy for %s finds the manifest's key and verifies with it" % label,
          ph.returncode == 0 and lh.count(key_of(lh)) == 1, (ph.stderr, lh))
ph, lh = helper(lambda d: d.pop("release_key"))
check("F1 5b: a policy with no release key ends the helper in one line before any verify",
      one_line(ph) and "release key" in ph.stderr and not any("verify-blob" in l for l in lh), (ph.stderr, lh))
for field in ("certificate", "x509CertificateChain"):
    cert = '{"verificationMaterial":{"%s":{"x":"y"},"tlogEntries":[{}]}}' % field
    ph, lh = helper(bundle=cert)
    check("F-cert: a bundle whose verificationMaterial holds %s is refused in one line, before any verify" % field,
          one_line(ph) and "certificate" in ph.stderr and not any("verify-blob" in l for l in lh), (ph.stderr, lh))
check("R1 c: the pinned log root the helper names is a file in the tree",
      os.path.isfile(os.path.join(ROOT, ".github/policy/rekor-trusted-root.json")))


def list_without_rekor(fix):
    for name in os.listdir(os.path.join(fix, "assets")):
        path = os.path.join(fix, "assets", name)
        if open(path).read() == '{"verificationMaterial":{"tlogEntries":[{}]}}':
            open(path, "w").write('{"verificationMaterial":{"tlogEntries":[]}}')


pr_ = fetch("2026-11", list_without_rekor)
check("F1 8: a release-files bundle with no Rekor entry ends the fetch, in one line",
      one_line(pr_[0]) and "Rekor" in pr_[0].stderr, pr_[0].stderr)


def unsigned(fix):
    open(os.path.join(fix, "bad-signature"), "w").close()


pu = fetch("2026-11", unsigned)
check("AC10: a release-files list whose signature does not verify ends the fetch, in one line",
      one_line(pu[0]), pu[0].stderr)


def other_manifest(fix):
    for name in os.listdir(os.path.join(fix, "assets")):
        path = os.path.join(fix, "assets", name)
        body = open(path, "rb").read()
        if body.startswith(b'{"version": "0.3.1"'):
            open(path, "wb").write(body[:-1] + b', "replaced": true}')


pm = fetch("2026-11", other_manifest)
check("AC10: a manifest that is not the file the signed list names ends the fetch, in one line",
      one_line(pm[0]) and "release-manifest.json" in pm[0].stderr, pm[0].stderr)


def bad_records(fix):
    open(os.path.join(fix, "bad-records"), "w").close()


pr = fetch("2026-11", bad_records)
check("AC10: Check records the verifier refuses end the fetch, in one line, with the verifier's first line",
      one_line(pr[0]) and "the scanners record is not signed" in pr[0].stderr, pr[0].stderr)
pv = fetch("2026-11", real_verifier=True)
check("AC10: with the real verifier, a record that is not JSON is refused",
      one_line(pv[0]) and "the scanners record" in pv[0].stderr, pv[0].stderr)


def replaced_record(fix):
    for name in os.listdir(os.path.join(fix, "assets")):
        path = os.path.join(fix, "assets", name)
        if open(path, "rb").read().startswith(b"record scanners of v0.3.1"):
            open(path, "wb").write(b'{"payloadType": "x", "payload": "e30=", "signatures": []}')


pv2 = fetch("2026-11", replaced_record, real_verifier=True)
check("AC10: with the real verifier, a replaced record that is JSON but signed by no one is refused",
      one_line(pv2[0]) and "record" in pv2[0].stderr, pv2[0].stderr)


def no_digests(fix):
    pages = json.load(open(os.path.join(fix, "pages.json")))
    for page in pages:
        for rel in page:
            rel["assets"] = [a for a in rel["assets"] if a["name"] != "digests.json"]
    json.dump(pages, open(os.path.join(fix, "pages.json"), "w"))


pd = fetch("2026-11", no_digests)
check("AC10: a release without one of the needed assets ends the fetch, in one line",
      one_line(pd[0]) and "digests.json" in pd[0].stderr, pd[0].stderr)



# ---- the daily presence check: bin/evidence-letter-present.sh
SIGNED_DEC3 = calendar.timegm((2026, 12, 3, 12, 0, 0))


def present(pages, today="2026-12-10", old_manifest=None, without=None, signed=SIGNED_DEC3, published=None, promise=True, current=None, entries=None, **extra):
    """pages: [[(tag, draft, [asset name, or (name, 'norekor')])]]; every asset gets an id from 500 and a body.
    A release with a letter bundle also gets the key manifest and its signature (today's, or old_manifest's),
    except the asset named by without. signed: the unix time the letter was signed, which the bundle's Rekor integratedTime
    carries (3 December unless given; None: the entry has no integratedTime). published: the release's listed published_at when it is not that."""
    tmp = tempfile.mkdtemp()
    fix, env = sandbox(tmp)
    env.update(extra)
    open(os.path.join(fix, "today_full"), "w").write(today + "\n")
    out, next_id = [], 500
    for page in pages:
        rels = []
        for tag, draft, assets in page:
            listed = []
            for a in assets:
                name, kind = (a, "ok") if isinstance(a, str) else a
                # a Rekor entry as the log returns it: the inclusionPromise (the signed entry timestamp) is what signs integratedTime; the inclusionProof alone does not
                entry = '{"integratedTime":"%s"%s,"inclusionProof":{"logIndex":"1"}}' % (
                    signed, ',"inclusionPromise":{"signedEntryTimestamp":"c2V0"}' if promise else "")
                tlog = "[]" if kind == "norekor" else "[{}]" if signed is None else "[%s]" % entry
                if entries is not None and kind != "norekor":     # entries: the integratedTimes of several Rekor entries
                    tlog = "[%s]" % ",".join(entry.replace('"integratedTime":"%s"' % signed, '"integratedTime":"%s"' % t) for t in entries)
                body = "a letter\n"
                if name.endswith(".bundle"):
                    body = '{"verificationMaterial":{"tlogEntries":%s}}' % tlog
                open(os.path.join(fix, "assets", str(next_id)), "w").write(body)
                listed.append({"id": next_id, "name": name})
                next_id += 1
            if any(a["name"].endswith(".md.bundle") for a in listed):
                for name, data in zip(("release-key-manifest.json", "release-key-manifest.sig"),
                                      (old_manifest or today_manifest)(tmp)):
                    if name == without:
                        continue
                    open(os.path.join(fix, "assets", str(next_id)), "wb").write(data)
                    listed.append({"id": next_id, "name": name})
                    next_id += 1
            rels.append({"tag_name": tag, "draft": draft, "prerelease": False, "assets": listed})
            if published is not None:
                rels[-1]["published_at"] = published
            elif signed is not None:
                rels[-1]["published_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(signed))
        out.append(rels)
    json.dump(out, open(os.path.join(fix, "pages.json"), "w"))
    if current is not None:       # current(tmp) installs the repository's own (current) key manifest before the run
        current(tmp)
    script = os.path.join(env["REPO_DIR"], "bin/evidence-letter-present.sh")
    p = subprocess.run(["bash", script], cwd=env["REPO_DIR"], env=env, capture_output=True, text=True)
    return p, open(os.path.join(tmp, "log")).read().splitlines()


def today_manifest(tmp):
    """The (manifest, signature) of the sandbox's own release key, root-signed, as the repository commits them."""
    pol = os.path.join(tmp, "repo/.github/policy")
    return (open(pol + "/release-key-manifest.json", "rb").read(), open(pol + "/release-key-manifest.sig", "rb").read())


def pair(m):
    return ["evidence-letter-%s.md" % m, "evidence-letter-%s.md.bundle" % m]


def verifies(log):
    return sum("cosign verify-blob" in l for l in log)



V4 = ("v0.4.0", False, pair("2026-10") + pair("2026-11"))
pr, lr = present([[V4]])
check("F7 1: a good pair for last month, with the key and the pinned log, passes", pr.returncode == 0 and any(
    l.startswith("cosign verify-blob --key ") and "--trusted-root .github/policy/rekor-trusted-root.json" in l
    for l in lr), (pr.stderr, lr))
pr, lr = present([[V4]], today="2026-12-02")
check("F7 2: before the 3rd of the month nothing is checked",
      pr.returncode == 0 and not any(l.startswith("gh api") for l in lr), (pr.stderr, lr))
pr, lr = present([[("v0.4.0", False, ["release-manifest.json"])]])
check("F7 3: no letter was ever published: quiet", pr.returncode == 0 and verifies(lr) == 0, (pr.stderr, lr))
pr, lr = present([[("v0.4.0", False, pair("2026-10"))]])
check("F7 4: last month's letter is missing: one line naming the month",
      one_line(pr) and "2026-11" in pr.stderr, pr.stderr)
pr, lr = present([[("v0.4.0", False, pair("2026-10") + ["evidence-letter-2026-11.md"])]])
check("F7 5: the bundle is missing: one line naming the month", one_line(pr) and "2026-11" in pr.stderr, pr.stderr)
pr, lr = present([[V4]])
check("F7 6: a good pair on a published release is verified once and exits 0",
      pr.returncode == 0 and verifies(lr) == 1, (pr.stderr, lr))
pr, lr = present([[("v0.4.0", False, pair("2026-11"))]], today="2027-01-05")
check("F7 7: in January the month checked is the December before", one_line(pr) and "2026-12" in pr.stderr, pr.stderr)
pr, lr = present([[V4]], FAIL_VERIFY="1")
# F7 8 is the wiring case in supply-chain-wiring-test.sh (the agent tests) (the job reads only), not a case here
check("F7 9: a pair whose signature does not verify fails, in one line",
      one_line(pr) and pr.returncode == 1, (pr.stderr, lr))
split = [("v0.4.0", False, pair("2026-10") + ["evidence-letter-2026-11.md"]),
         ("v0.4.1", False, ["evidence-letter-2026-11.md.bundle"])]
pr, lr = present([split])
check("F7 10: the .md on one release and the .bundle on another is a missing pair, in one line",
      one_line(pr) and "2026-11" in pr.stderr, pr.stderr)
pr, lr = present([[("v0.5.0", False, ["release-manifest.json"])], [V4]])
check("F7 11: a letter on the second page of releases is found",
      pr.returncode == 0 and any(l.startswith("gh api --paginate") for l in lr), (pr.stderr, lr))
pr, lr = present([[("v0.4.0", False, pair("2026-10")), ("v0.4.1", True, pair("2026-11"))]])
check("F7 12: a draft release carrying the pair does not count", one_line(pr) and "2026-11" in pr.stderr, pr.stderr)
norekor = pair("2026-10") + [("evidence-letter-2026-11.md", "ok"), ("evidence-letter-2026-11.md.bundle", "norekor")]
pr, lr = present([[("v0.4.0", False, norekor)]])
check("F7 13: a bundle with no Rekor entry fails in the job too", one_line(pr) and "Rekor" in pr.stderr, pr.stderr)
pr, lr = present([[("v0.4.0", False, ["evidence-letter-x.md", "evidence-letter-2026-1.md"])]])
check("F7 14: a name that is only a prefix of a letter does not start the check",
      pr.returncode == 0 and verifies(lr) == 0, (pr.stderr, lr))
twice = [V4, ("v0.4.1", False, pair("2026-11"))]
pr, lr = present([twice], FAIL_VERIFY_AFTER="1")
check("F7 15: every copy of last month's pair is verified (the second one fails)",
      pr.returncode == 1 and verifies(lr) == 2, (pr.stderr, lr))



# F7 16: last month's letter is checked with the key the root-signed manifest lists for the letter's date, which is
# the manifest published on the release that carries it, not the key of today's checkout
def old_key_manifest(root_signed=True):
    """A function of the sandbox folder: the (manifest, signature) of an older release key, valid in November."""
    def make(tmp):
        keys = os.path.join(tmp, "keys")
        openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:4096", "-out", keys + "/old.key")
        openssl("pkey", "-in", keys + "/old.key", "-pubout", "-out", keys + "/old.pub")
        pub = open(keys + "/old.pub").read()
        der = openssl("pkey", "-pubin", "-in", keys + "/old.pub", "-outform", "DER")
        body = json.dumps({"public_key": pub, "key_id": sha_of(der), "valid_from": "2026-11-01T00:00:00Z",
                           "valid_to": "2027-01-01T00:00:00Z"}, sort_keys=True, indent=1).encode() + b"\n"
        open(keys + "/old-m.json", "wb").write(body)
        signer = keys + ("/root.key" if root_signed else "/old.key")
        sig = openssl("dgst", "-sha256", "-sign", signer, keys + "/old-m.json")
        open(os.path.join(tmp, "old-line"), "w").write(pub.splitlines()[1])
        return body, base64.b64encode(sig) + b"\n"
    return make


pr, lr = present([[V4]], old_manifest=old_key_manifest())
cur = key_of(lr)
check("F7 16: the letter is verified with the key its date lists in the root-signed manifest, not today's key",
      pr.returncode == 0 and verifies(lr) == 1 and lr.count(cur) == 0
      and lr.count("key-file: -----BEGIN PUBLIC KEY-----") == 1, (pr.stderr, lr))
pr, lr = present([[V4]], old_manifest=old_key_manifest(root_signed=False))
check("F7 17: a manifest the root did not sign lists no key: one line, nothing verified",
      one_line(pr) and "manifest" in pr.stderr and verifies(lr) == 0, (pr.stderr, lr))
for asset, n in (("release-key-manifest.json", 18), ("release-key-manifest.sig", 19)):
    pr, lr = present([[V4]], without=asset)
    check("F7 %d: a release with the letter and its bundle but no %s: one line naming the month, the tag and the asset, "
          "nothing verified" % (n, asset),
          one_line(pr) and "2026-11" in pr.stderr and "v0.4.0" in pr.stderr
          and "the release carries no " + asset in pr.stderr and verifies(lr) == 0, (pr.stderr, lr))
pr, lr = present([[V4]], without="release-key-manifest.json")
check("F7 20: with the manifest missing the .json is named first, and today's key is not used",
      "release-key-manifest.sig" not in pr.stderr and not any("policy make" in l for l in lr), (pr.stderr, lr))
# the key's window is met at the date the letter was SIGNED (the next month's early days), not by the letter's month
def window_manifest(valid_from, valid_to):
    """A function of the sandbox folder: the (manifest, signature) of a release key valid from valid_from to
    valid_to, root-signed."""
    def make(tmp):
        keys = os.path.join(tmp, "keys")
        openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:4096", "-out", keys + "/win.key")
        openssl("pkey", "-in", keys + "/win.key", "-pubout", "-out", keys + "/win.pub")
        pub = open(keys + "/win.pub").read()
        der = openssl("pkey", "-pubin", "-in", keys + "/win.pub", "-outform", "DER")
        m = {"public_key": pub, "key_id": sha_of(der), "valid_from": valid_from}
        if valid_to is not None:      # an open-ended window leaves the field out; "valid_to": null is not a valid value
            m["valid_to"] = valid_to
        body = json.dumps(m, sort_keys=True, indent=1).encode() + b"\n"
        open(keys + "/win-m.json", "wb").write(body)
        sig = openssl("dgst", "-sha256", "-sign", keys + "/root.key", keys + "/win-m.json")
        open(os.path.join(tmp, "old-line"), "w").write(pub.splitlines()[1])
        return body, base64.b64encode(sig) + b"\n"
    return make


pr, lr = present([[V4]], old_manifest=window_manifest("2026-12-01T00:00:00Z", None), signed=SIGNED_DEC3)
check("F7 R8a: a key whose window opens on 1 December signed the November letter on 3 December: it is the usable key",
      pr.returncode == 0 and verifies(lr) == 1, (pr.stderr, lr))
ENDED_NOV20 = window_manifest("2026-11-01T00:00:00Z", "2026-11-20T00:00:00Z")
pr, lr = present([[V4]], old_manifest=ENDED_NOV20, signed=SIGNED_DEC3)
check("F7 R8b: a key that ended on 20 November met the month but not the signing date of 3 December: "
      "one line, nothing verified",
      one_line(pr) and "key" in pr.stderr and verifies(lr) == 0, (pr.stderr, lr))
# the unsigned publication date of the API decides nothing: the letter's releases are the ones whose SIGNED
# manifest says they were published in the month
SIGNED_DECOYS = [("v0.4.0", "2026-12-05T12:00:00Z", False, False, 1),
                 ("v0.3.1", "2026-11-04T12:00:00Z", False, False, 1)]
pd_, gotd, _l, _o, _f = fetch("2026-11", release_list=SIGNED_DECOYS,
                              signed={"v0.4.0": "2026-11-20T12:00:00Z", "v0.3.1": "2026-12-02T12:00:00Z"})
check("R9 the fetch selects by the signed manifest's date: the release the API dates in December but the "
      "manifest dates 20 November is taken, the one the API dates 4 November but the manifest dates 2 December "
      "is not", pd_.returncode == 0 and gotd == ["v0.4.0"], (pd_.stderr, gotd))
# R9: the month comes from the signed manifest only; a final release whose manifest cannot give a signed date
# refuses the letter, in one line, and the API date is never a fallback
one_rel = [("v0.4.0", "2026-11-20T12:00:00Z", False, False, 1)]
for what, mf in (("has no release-manifest.json asset", None), ("is not JSON", b"not json at all\n"),
                 ("holds no published_at", b'{"version": "0.4.0"}'),
                 ("holds a published_at that is not a string", b'{"version": "0.4.0", "published_at": 20261120}')):
    pm, gotm, _l, _o, _f = fetch("2026-11", release_list=one_rel, manifests={"v0.4.0": mf})
    check("AC5 / R9 a final release whose manifest %s refuses the fetch in one line naming the tag and "
          "release-manifest.json, no fallback to the API date" % what,
          one_line(pm) and "v0.4.0" in pm.stderr and "release-manifest.json" in pm.stderr and gotm == [],
          (pm.returncode, pm.stderr, gotm))
pm, gotm, _l, _o, _f = fetch("2026-11", release_list=one_rel + [("v0.3.0", "2026-10-30T12:00:00Z", False, True, 1),
                                                              ("v0.3.5", "2026-11-04T12:00:00Z", True, False, 1)],
                             manifests={"v0.3.0": None, "v0.3.5": None})
check("AC5 / R9 a draft or a prerelease with no manifest does not refuse the fetch",
      pm.returncode == 0 and gotm == ["v0.4.0"], (pm.stderr, gotm))
pm, gotm, _l, _o, _f = fetch("2026-11", release_list=[("v0.4.0", "2026-12-05T12:00:00Z", False, False, 1)],
                             manifests={"v0.4.0": b"not json"})
check("AC5 / R9 a bad manifest refuses even when the API date lies outside the month",
      one_line(pm) and "v0.4.0" in pm.stderr and "release-manifest.json" in pm.stderr, (pm.returncode, pm.stderr))
OCT_AND_DECOY = [("v0.4.0", "2026-11-20T12:00:00Z", False, False, 1), ("v0.3.0", "2026-10-30T12:00:00Z", False, False, 1)]
pm, gotm, _l, _o, _f = fetch("2026-11", release_list=OCT_AND_DECOY, signed={"v0.4.0": "2026-12-02T12:00:00Z"})
check("AC5 / R9 the API dates a release in the month but its manifest dates it after: it is not the month's "
      "release, the newest release before the month is taken instead",
      pm.returncode == 0 and gotm == ["v0.3.0"], (pm.stderr, gotm))
pm, gotm, _l, _o, _f = fetch("2026-10", release_list=OCT_AND_DECOY, signed={"v0.4.0": "2026-10-15T12:00:00Z"})
check("AC5 / R9 the API dates a release in November but its manifest dates it in October: October takes it",
      pm.returncode == 0 and gotm == ["v0.3.0", "v0.4.0"], (pm.stderr, gotm))
# R8: the key's window is met at the bundle's integratedTime only
WIN_DEC = window_manifest("2026-12-01T00:00:00Z", None)
pr, lr = present([[V4]], old_manifest=window_manifest("2026-11-01T00:00:00Z", "2026-12-01T00:00:00Z"),
                 signed=None, published="2026-11-25T12:00:00Z")
check("AC5 / R8 a bundle with no integratedTime is refused in one line, nothing verified, although the "
      "release's published_at fits the key window", one_line(pr) and "Rekor" in pr.stderr and verifies(lr) == 0,
      (pr.returncode, pr.stderr, lr))
pr, lr = present([[V4]], signed=None, published="2026-11-25T12:00:00Z")
check("AC5 / R8 a bundle with no integratedTime is refused although the reporting month is the key's month",
      one_line(pr) and verifies(lr) == 0, (pr.returncode, pr.stderr, lr))
pr, lr = present([[("v0.4.0", False, norekor)]], signed=None, published="2026-11-25T12:00:00Z")
check("AC5 / R8 a bundle with no tlogEntries is refused in one line", one_line(pr) and verifies(lr) == 0,
      (pr.returncode, pr.stderr, lr))
pr, lr = present([[V4]], old_manifest=WIN_DEC, signed=SIGNED_DEC3, published="2026-11-25T12:00:00Z")
check("AC5 / R8 the signing date of the integratedTime (3 December) selects the key whose window opens on "
      "1 December, whatever the release's published_at says", pr.returncode == 0 and verifies(lr) == 1,
      (pr.stderr, lr))
pr, lr = present([[V4]], old_manifest=ENDED_NOV20, signed=SIGNED_DEC3, published="2026-11-15T12:00:00Z")
check("AC5 / R8 a key that was valid at the release's published_at but ended before the integratedTime is "
      "refused in one line", one_line(pr) and "key" in pr.stderr and verifies(lr) == 0, (pr.stderr, lr))

# ---- S2 code fixes: findings 4, 4b, 6a, 6b
def tamper(tag, old, new):
    """An edit for fetch(): the tag's manifest asset is changed AFTER the signed release-files list was made, so it no longer matches it."""
    def edit(fix):
        for name in os.listdir(os.path.join(fix, "assets")):
            path = os.path.join(fix, "assets", name)
            body = open(path, "rb").read()
            if body.startswith(b'{"version": "%s"' % tag[1:].encode()) and old in body:
                open(path, "wb").write(body.replace(old, new))
    return edit


# row 4: the selection date is read only from a manifest verified against the signed release-files.sha256
two_rel = [("v0.4.0", "2026-11-20T12:00:00Z", False, False, 1), ("v0.3.1", "2026-11-04T12:00:00Z", False, False, 1)]
pd_, gotd, _l, _o, _f = fetch("2026-11", tamper("v0.4.0", b"2026-11-20", b"2026-10-20"), release_list=two_rel)
check("S2 row 4: a decoy v0.4.0 manifest (replaced after signing, its date moved out of the month) refuses the fetch in one line naming the tag and release-manifest.json, the unsigned date selects nothing",
      one_line(pd_) and "v0.4.0" in pd_.stderr and "release-manifest.json" in pd_.stderr, (pd_.returncode, pd_.stderr, gotd))
pd_, gotd, _l, _o, _f = fetch("2026-11", tamper("v0.3.1", b"2026-11-04", b"2026-12-04"), release_list=two_rel)
check("S2 row 4: v0.3.1 whose manifest date was moved to 4 December (not the signed file's hash) refuses the fetch in one line naming the tag and release-manifest.json, it is not silently left out",
      one_line(pd_) and "v0.3.1" in pd_.stderr and "release-manifest.json" in pd_.stderr, (pd_.returncode, pd_.stderr, gotd))

# row 4b: below v0.3.0 the letter does not need a manifest date; v0.3.0 and later always do
pre = [("v0.4.0", "2026-11-20T12:00:00Z", False, False, 1), ("v0.2.3", "2026-09-01T12:00:00Z", False, False, 1)]
pd_, gotd, _l, _o, _f = fetch("2026-11", release_list=pre, manifests={"v0.2.3": b'{"version":"0.2.3"}'})
check("S2 row 4b: a v0.2.3 release whose manifest is {\"version\":\"0.2.3\"} does not stop the letter",
      pd_.returncode == 0 and "v0.4.0" in gotd, (pd_.returncode, pd_.stderr, gotd))
for tag, mf, what in (("v0.2.9", b'{"version":"0.3.1"}', "a tag named v0.2.9 whose verified manifest says version 0.3.1"),
                      ("v0.3.0", b'{"version":"0.2.0"}', "a v0.3.0 tag whose manifest says version 0.2.0"),
                      ("v0.3.0", b'{"version":"0.3.0"}', "a v0.3.0 release with no manifest date (the API date is never the fallback)")):
    pd_, gotd, _l, _o, _f = fetch("2026-11", release_list=[("v0.4.0", "2026-11-20T12:00:00Z", False, False, 1), (tag, "2026-11-05T12:00:00Z", False, False, 1)],
                                  manifests={tag: mf})
    check("S2 row 4b: %s is not pre-v0.3: the fetch refuses in one line naming the tag" % what,
          one_line(pd_) and tag in pd_.stderr, (pd_.returncode, pd_.stderr, gotd))


# row 6a: the key manifest of the release gets the checks of bin/chain-verify.py check_manifest, besides the Rekor-time window
def custom_manifest(change=None, bits=4096):
    """A function of the sandbox folder: a root-signed manifest of a fresh key valid from 1 November, changed by change(dict, der)."""
    def make(tmp):
        keys = os.path.join(tmp, "keys")
        openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:%d" % bits, "-out", keys + "/c.key")
        openssl("pkey", "-in", keys + "/c.key", "-pubout", "-out", keys + "/c.pub")
        pub = open(keys + "/c.pub").read()
        der = openssl("pkey", "-pubin", "-in", keys + "/c.pub", "-outform", "DER")
        m = {"public_key": pub, "key_id": sha_of(der), "valid_from": "2026-11-01T00:00:00Z"}
        if change:
            change(m)
        body = json.dumps(m, sort_keys=True, indent=1).encode() + b"\n"
        open(keys + "/c-m.json", "wb").write(body)
        sig = openssl("dgst", "-sha256", "-sign", keys + "/root.key", keys + "/c-m.json")
        return body, base64.b64encode(sig) + b"\n"
    return make


pr, lr = present([[V4]], old_manifest=custom_manifest())
check("S2 row 6a: the control, a well formed RSA-4096 manifest with the right key_id passes", pr.returncode == 0 and verifies(lr) == 1, (pr.stderr, lr))
pr, lr = present([[V4]], old_manifest=custom_manifest(lambda m: m.update(revoked_at="2099-01-01T00:00:00Z")))
check("S2 row 6a: a key whose revoked_at is LATER than the signing time still fails (a letter signed by a revoked key is not accepted), one line, nothing verified",
      one_line(pr) and verifies(lr) == 0, (pr.returncode, pr.stderr, lr))
pr, lr = present([[V4]], old_manifest=custom_manifest(lambda m: m.update(key_id="0" * 64)))
check("S2 row 6a: a manifest whose key_id is not the hash of its key is refused in one line, nothing verified",
      one_line(pr) and verifies(lr) == 0, (pr.returncode, pr.stderr, lr))
pr, lr = present([[V4]], old_manifest=custom_manifest(bits=2048))
check("S2 row 6a: a manifest whose key is RSA-2048, not RSA-4096, is refused in one line, nothing verified",
      one_line(pr) and verifies(lr) == 0, (pr.returncode, pr.stderr, lr))
pr, lr = present([[V4]], old_manifest=custom_manifest(lambda m: m.update(note="x")))
check("S2 row 6a: a manifest with a field outside the closed list is refused in one line, nothing verified",
      one_line(pr) and verifies(lr) == 0, (pr.returncode, pr.stderr, lr))

# row 6b: only the inclusionPromise signs integratedTime
pr, lr = present([[V4]], promise=False)
check("S2 row 6b: a bundle with an inclusion proof but no inclusionPromise is refused in one line, nothing verified",
      one_line(pr) and "inclusionPromise" in pr.stderr and verifies(lr) == 0, (pr.returncode, pr.stderr, lr))
pr, lr = present([[V4]])
check("S2 row 6b: the control, a bundle with the inclusionPromise passes", pr.returncode == 0 and verifies(lr) == 1, (pr.stderr, lr))


# F7 P1 / R5: the key of a copy is looked up in the CURRENT manifest (the repository's root-signed one); a revoked_at
# at or before now there fails the copy even when the manifest on the release is older and carries none
def current_manifest(revoked_at, same_key=True):
    """A function of the sandbox folder: commits a root-signed current manifest into the sandbox repo. same_key: it is
    the key of old_key_manifest() (the attached one); otherwise the sandbox's own release key. revoked_at is added."""
    def install(tmp):
        keys = os.path.join(tmp, "keys")
        pol = os.path.join(tmp, "repo/.github/policy")
        src = keys + "/old-m.json" if same_key else pol + "/release-key-manifest.json"
        m = json.loads(open(src, "rb").read())
        m["revoked_at"] = revoked_at
        body = json.dumps(m, sort_keys=True, indent=1).encode() + b"\n"
        open(keys + "/cur-m.json", "wb").write(body)
        sig = openssl("dgst", "-sha256", "-sign", keys + "/root.key", keys + "/cur-m.json")
        open(pol + "/release-key-manifest.json", "wb").write(body)
        open(pol + "/release-key-manifest.sig", "w").write(base64.b64encode(sig).decode() + "\n")
    return install


pr, lr = present([[V4]], old_manifest=old_key_manifest(), current=current_manifest("2026-11-10T00:00:00Z"))
check("F7 P1 a1: the current manifest revokes the key (past revoked_at) that the older attached manifest lists without "
      "revoked_at: one line, nothing verified", one_line(pr) and pr.returncode == 1 and verifies(lr) == 0, (pr.stderr, lr))
pr, lr = present([[V4]], old_manifest=old_key_manifest(), current=current_manifest("2027-06-01T00:00:00Z"))
check("F7 P1 a2: a revoked_at in the future in the current manifest does not revoke yet: passes",
      pr.returncode == 0 and verifies(lr) == 1, (pr.stderr, lr))
pr, lr = present([[V4]], old_manifest=old_key_manifest(), current=current_manifest("2026-11-10T00:00:00Z", same_key=False))
check("F7 P1 a3: a current manifest of another key_id, revoked, does not touch this key: passes",
      pr.returncode == 0 and verifies(lr) == 1, (pr.stderr, lr))
# F7 R5: exactly one transparency-log entry, whose integratedTime decides the key window
pr, lr = present([[V4]], entries=[SIGNED_DEC3, SIGNED_DEC3])
check("F7 R5 b2: a bundle with two Rekor entries fails in one line, nothing verified",
      one_line(pr) and pr.returncode == 1 and verifies(lr) == 0, (pr.stderr, lr))
pr, lr = present([[V4]], old_manifest=window_manifest("2026-11-01T00:00:00Z", "2026-12-05T00:00:00Z"),
                 entries=[SIGNED_DEC3, SIGNED_DEC3 + 5 * 86400])
check("F7 R5 b3: two entries, the first inside the key window and the second outside it: fails, not passed on entry 0",
      one_line(pr) and pr.returncode == 1 and verifies(lr) == 0, (pr.stderr, lr))

# the number of cases this file runs: a case that silently stops running must turn the file red
EXPECT = 136
print("%d passed, %d failed (expected %d)" % (passed, failed, EXPECT))
sys.exit(1 if failed or passed != EXPECT else 0)
PY
