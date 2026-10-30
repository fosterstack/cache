#!/usr/bin/env bash
# proves: REQ-REL-013-AC9, REQ-REL-013-AC10
# The jobs of the monthly evidence letter (owner Oct 27): .github/workflows/evidence-letter.yml, bin/evidence-letter-fetch.sh
# and bin/evidence-letter-publish.sh. Offline: cosign, gh, date and the Check-record verifier are stand-ins that record their
# arguments; nothing is signed or uploaded. A mutation of the workflow must turn its own check red.
set -euo pipefail
TMPDIR=$(mktemp -d); export TMPDIR; trap 'rm -rf "$TMPDIR"' EXIT
here=$(cd "$(dirname "$0")" && pwd); root=$(cd "$here/.." && pwd)
python3 - "$root" <<'PY'
import copy, hashlib, json, os, re, stat, subprocess, sys, tempfile
import yaml
ROOT = sys.argv[1]
passed = failed = 0


def check(name, ok, got=""):
    global passed, failed
    if ok:
        passed += 1
        print("ok:", name)
    else:
        failed += 1
        print("FAIL:", name, "->", got)


def read(rel):
    return open(os.path.join(ROOT, rel)).read()


# ---- the workflow file, judged; each mutation below must make the judge say something
WF = ".github/workflows/evidence-letter.yml"
IDENTITY = "https://github.com/fosterstack/cache/.github/workflows/evidence-letter.yml@refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"
MAIN = "github.ref == 'refs/heads/main'"


def steps_text(job):
    return [str(s.get("run", "")) + str(s.get("uses", "")) for s in job["steps"]]


def judge(doc, text):
    """Everything the workflow must keep; the list of what it does not."""
    bad = []
    on = doc.get(True, doc.get("on"))
    if sorted(on) != ["schedule", "workflow_dispatch"] or len(on["schedule"]) != 1:
        bad.append("it must start only on one monthly schedule or by hand")
    if doc["permissions"] != {"contents": "read"}:
        bad.append("the workflow token must only read")
    jobs = doc["jobs"]
    if list(jobs) != ["draft", "sign"]:
        return bad + ["the jobs must be draft and sign"]
    draft, sign = jobs["draft"], jobs["sign"]
    if draft["permissions"] != {"contents": "read"}:
        bad.append("draft must only read, with no identity token")
    if sign["permissions"] != {"contents": "write", "id-token": "write"}:
        bad.append("sign must hold exactly contents: write and id-token: write")
    for name, job in jobs.items():
        if MAIN not in str(job.get("if", "")):
            bad.append("%s must run only from main" % name)
    if sign.get("needs") not in ("draft", ["draft"]):
        bad.append("sign must need draft")
    if "needs.draft.outputs.made == 'true'" not in str(sign.get("if", "")):
        bad.append("sign must run only when draft made a letter")
    up = [s for s in draft["steps"] if "upload-artifact" in str(s.get("uses", ""))]
    down = [s for s in sign["steps"] if "download-artifact" in str(s.get("uses", ""))]
    if len(up) != 1 or len(down) != 1 or up[0]["with"]["name"] != down[0]["with"]["name"]:
        bad.append("sign must take the letter from the artifact draft uploaded")
    dtext, stext = steps_text(draft), steps_text(sign)
    install = [i for i, t in enumerate(dtext) if "bash bin/install-scanner.sh cosign" in t]
    fetch = [i for i, t in enumerate(dtext) if "bash bin/evidence-letter-fetch.sh" in t]
    if not install or not fetch or install[0] > fetch[0]:
        bad.append("draft must install cosign (checksummed) before the fetch that verifies with it")
    if not any("bin/evidence-letter.py" in t and "--draft" not in t for t in dtext):
        bad.append("draft must make the letter without --draft")
    if not (any("bash bin/install-scanner.sh cosign" in t for t in stext)
            and any("bash bin/evidence-letter-publish.sh" in t for t in stext)):
        bad.append("sign must install cosign and sign only through the publish script")
    if "cosign sign" in text or "--clobber" in text:
        bad.append("no signing call and no --clobber in the workflow")
    uses = re.findall(r"uses:\s*(\S+)", text)
    if not uses or not all(re.fullmatch(r".+@[0-9a-f]{40}", u) for u in uses):
        bad.append("every action must be pinned to a full commit id")
    if "secrets." in text or "pull_request" in text:
        bad.append("no secrets and no pull-request trigger")
    return bad


wf = read(WF)
doc = yaml.safe_load(wf)
check("AC9: the workflow keeps everything the judge lists", judge(doc, wf) == [], judge(doc, wf))


def mutated(label, change, text_change=None):
    d = copy.deepcopy(doc)
    change(d)
    t = text_change(wf) if text_change else wf
    check("AC9: mutation, %s: the judge objects" % label, judge(d, t) != [])


mutated("sign does not need draft", lambda d: d["jobs"]["sign"].pop("needs"))
mutated("sign no longer waits for a letter", lambda d: d["jobs"]["sign"].update({"if": MAIN}))
mutated("draft runs from any ref", lambda d: d["jobs"]["draft"].pop("if"))
mutated("sign runs from any ref", lambda d: d["jobs"]["sign"].update({"if": "needs.draft.outputs.made == 'true'"}))
mutated("draft no longer installs cosign", lambda d: d["jobs"]["draft"].update(
    {"steps": [s for s in d["jobs"]["draft"]["steps"] if "install-scanner" not in str(s.get("run", ""))]}))
mutated("sign downloads another artifact", lambda d: [s["with"].update(name="other") for s in d["jobs"]["sign"]["steps"]
                                                      if "download-artifact" in str(s.get("uses", ""))])
mutated("draft gets an identity token", lambda d: d["jobs"]["draft"]["permissions"].update({"id-token": "write"}))
mutated("an upload may overwrite", lambda d: None, lambda t: t + "\n# gh release upload --clobber\n")
mutated("a third job", lambda d: d["jobs"].update({"extra": {}}))

check("AC9: the identity customers verify is named in the workflow header and in the verify guide",
      all(IDENTITY in read(f) for f in (WF, "docs/verify-release.md")))
rs, pub = read("bin/release-sign.sh"), read("bin/evidence-letter-publish.sh")
CALL = ("cosign sign-blob --yes --key awskms:///alias/fosterstack-release-signing"
        " --signing-config .github/policy/cosign-signing-config.json --bundle")
check("AC9: the signing call is Sign's KMS shape and the config is release-sign.sh's", CALL in pub
      and "--signing-config .github/policy/cosign-signing-config.json" in rs)
for banned in ("--certificate-identity", "--certificate-oidc-issuer", "--insecure-ignore-tlog", "@refs/heads/main", "keyless",
               "--identity-token", "--fulcio-url", "--oidc-"):
    check("F2: the publish script holds no " + banned, banned not in pub, banned)
check("AC9: no upload may overwrite", "--clobber" not in pub)


# ---- stand-ins: plain scripts that write what they were asked into a log
STUBS = {
    "cosign": """#!/bin/sh
echo "cosign $*" >> "$LOG"
for a in "$@"; do [ "$k" = 1 ] && [ -f "$a" ] && echo "key-file: $(cat "$a")" >> "$LOG"; k=0; [ "$a" = --key ] && k=1; done
case "$1" in
  verify-blob) [ ! -e "$FIX/bad-signature" ] ;;
  sign-blob)
    while [ $# -gt 0 ]; do [ "$1" = --bundle ] && bundle=$2; shift; done
    echo '{"verificationMaterial":{"tlogEntries":'"$TLOG"'}}' > "$bundle" ;;
esac
""",
    "date": """#!/bin/sh
case "$*" in *%Y-%m*) cat "$FIX/today" ;; *) exec /bin/date "$@" ;; esac
""",
    "python3": """#!/bin/sh
case "$*" in
  *chain-verify.py*policy*make*--ref*)
    echo "python3 $*" >> "$LOG"
    if [ -e "$FIX/bad-manifest" ]; then echo "refused: the key manifest is not signed by the offline root" >&2; exit 1; fi
    while [ $# -gt 0 ]; do [ "$1" = --out ] && out=$2; shift; done
    echo '{"release_key":{"public_key":"MANIFEST-KEY"}}' > "$out"; exit 0 ;;
  *chain-verify.py*check-list*)
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
      *security-advisories*) cat "$FIX/advisories.json" ;;
      *) cat "$FIX/pages.json" ;;
    esac ;;
  "api repos/"*) cat "$FIX/assets/${2##*/}" ;;
  "release view") echo "$LATEST" ;;
  "release upload")
    kind=letter; case "$4" in *.bundle) kind=bundle ;; esac
    if [ "$kind" = "$FAIL_UPLOAD" ]; then echo "HTTP 422: Validation Failed (already_exists)" >&2; echo "second line" >&2; exit 1; fi
    echo "${4##*/}" >> "$FIX/uploaded" ;;
  "release delete-asset")
    [ -z "$FAIL_DELETE" ] || exit 1
    grep -vxF "$4" "$FIX/uploaded" > "$FIX/uploaded.new" || true; mv "$FIX/uploaded.new" "$FIX/uploaded" ;;
esac
""",
}


def sandbox(tmp):
    fix, bins = os.path.join(tmp, "fix"), os.path.join(tmp, "bin")
    os.makedirs(os.path.join(fix, "assets"))
    os.makedirs(bins)
    for name, body in STUBS.items():
        path = os.path.join(bins, name)
        open(path, "w").write(body)
        os.chmod(path, 0o755)
    for name in ("log", "uploaded"):
        open(os.path.join(fix if name == "uploaded" else tmp, name), "w").close()
    open(os.path.join(fix, "today"), "w").write("2026-12\n")
    open(os.path.join(fix, "advisories.json"), "w").write(json.dumps([[{"ghsa_id": "GHSA-a"}], [{"ghsa_id": "GHSA-b"}]]))
    env = dict(os.environ, PATH=bins + ":" + os.environ["PATH"], FIX=fix, LOG=os.path.join(tmp, "log"), GH_TOKEN="x",
               REAL_PYTHON=sys.executable, TLOG="[{}]", LATEST="v0.9.9", FAIL_UPLOAD="", FAIL_DELETE="")
    return fix, env


def sha(data):
    return hashlib.sha256(data).hexdigest()


def put_releases(fix, releases):
    """releases: [(tag, published, draft, prerelease, page)]; every one gets the assets the fetch needs, ids from 100."""
    pages, next_id = {}, 100
    for tag, published, draft, pre, page in releases:
        manifest, vex = ("manifest of " + tag).encode(), ("vex of " + tag).encode()
        files = {"release-manifest.json": manifest, "fosterstack-cache.openvex.json": vex,
                 "release-files.sha256": ("%s  release-manifest.json\n%s  fosterstack-cache.openvex.json\n"
                                          % (sha(manifest), sha(vex))).encode(),
                 "release-files.sha256.bundle": b"{}",
                 "digests.json": json.dumps({"image-production": "sha256:" + "a" * 64}).encode()}
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


def fetch(month, edit=None, today=None, release_list=RELEASES, real_verifier=False):
    tmp = tempfile.mkdtemp()
    fix, env = sandbox(tmp)
    put_releases(fix, release_list)
    if today:
        open(os.path.join(fix, "today"), "w").write(today + "\n")
    if edit:
        edit(fix)
    if real_verifier:
        os.remove(os.path.join(tmp, "bin", "python3"))
    out = os.path.join(tmp, "work")
    p = subprocess.run(["bash", os.path.join(ROOT, "bin/evidence-letter-fetch.sh"), month, out], cwd=ROOT, env=env,
                       capture_output=True, text=True)
    got = sorted(os.listdir(out + "/rel")) if os.path.isdir(out + "/rel") else []
    return p, got, open(os.path.join(tmp, "log")).read().splitlines(), out, fix


def one_line(p):
    return p.returncode == 1 and len(p.stderr.strip().splitlines()) == 1


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
check("AC10: it only reads: no upload, no write call", not any(("upload" in l or "-X" in l or "--method" in l) for l in log))
check("AC10: it fetches the files the verification needs and no release is downloaded by the subcommand",
      os.path.isfile(out + "/rel/v0.3.1/release-files.sha256.bundle") and os.path.isfile(out + "/rel/v0.3.1/digests.json")
      and os.path.isfile(out + "/rel/v0.3.1/witness-check/witness-arm64/arm64-collection.json")
      and not any("release download" in l for l in log))
check("AC10: a bad month is refused", fetch("2026-13")[0].returncode == 2)
check("AC9: a month that is not over is refused, in one line", one_line(fetch("2026-12", today="2026-12")[0]))
check("AC9: a future month is refused", one_line(fetch("2027-05", today="2026-12")[0]))

# ---- the checks on what was fetched
ID = "--certificate-identity https://github.com/fosterstack/cache/.github/workflows/stage-promote.yml@refs/tags/"
check("AC10: each release's list is verified against its bundle under stage-promote.yml at its own tag",
      all(any(l.startswith("cosign verify-blob --bundle ") and ID + t in l and ISSUER in l for l in log)
          for t in ("v0.3.1", "v0.4.0")), log)
check("AC10: the Check records are verified with the same command Release runs, under a policy made for the tag",
      sum("check-list --policy" in l for l in log) == 2 and os.path.isfile(out + "/rel/v0.3.1/policy.json"), log)


def unsigned(fix):
    open(os.path.join(fix, "bad-signature"), "w").close()


pu = fetch("2026-11", unsigned)
check("AC10: a release-files list whose signature does not verify ends the fetch, in one line", one_line(pu[0]), pu[0].stderr)


def other_manifest(fix):
    for name in os.listdir(os.path.join(fix, "assets")):
        path = os.path.join(fix, "assets", name)
        if open(path, "rb").read().startswith(b"manifest of v0.3.1"):
            open(path, "wb").write(b"a replaced manifest")


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


# ---- the publish script
def publish(**extra):
    tmp = tempfile.mkdtemp()
    fix, env = sandbox(tmp)
    env.update(extra)
    letter = os.path.join(tmp, "evidence-letter-2026-11.md")
    open(letter, "w").write("a letter\n")
    p = subprocess.run(["bash", os.path.join(ROOT, "bin/evidence-letter-publish.sh"), letter], cwd=ROOT, env=env,
                       capture_output=True, text=True)
    return (p, open(os.path.join(tmp, "log")).read().splitlines(),
            open(os.path.join(fix, "uploaded")).read().split(), letter)


p, log, up, letter = publish()
names = ["evidence-letter-2026-11.md.bundle", "evidence-letter-2026-11.md"]
SIGN = ("cosign sign-blob --yes --key awskms:///alias/fosterstack-release-signing --signing-config "
        ".github/policy/cosign-signing-config.json --bundle " + letter + ".bundle " + letter)
VERIFY = ("cosign verify-blob --key ", " --trusted-root .github/policy/rekor-trusted-root.json --bundle " + letter + ".bundle " + letter)
verifies = [l for l in log if l.startswith("cosign verify-blob")]
check("F2: a good run takes the key from the root-checked manifest (policy make for main), signs with exactly Sign's argv, "
      "verifies, then uploads", p.returncode == 0 and SIGN in log
      and any("chain-verify.py policy make --template .github/policy/release-policy.template.json --ref refs/heads/main" in l
              for l in log)
      and len(verifies) == 1 and verifies[0].startswith(VERIFY[0]) and verifies[0].endswith(VERIFY[1]), (p.stderr, log))
check("F2: the verify reads the manifest's key file", "key-file: MANIFEST-KEY" in log, log)
check("F2: the verify names no identity, issuer or ignored log",
      len(verifies) == 1 and not any(x in verifies[0] for x in ("--certificate-identity", "--certificate-oidc-issuer",
                                                              "--insecure-ignore-tlog")), verifies)
idx = lambda needle: next((i for i, l in enumerate(log) if needle in l), -1)
check("F2: the order is manifest key, sign, verify, upload",
      0 <= idx("policy make") < idx("sign-blob") < idx("verify-blob") < idx("release upload"), log)
check("AC9: the bundle is uploaded first, the letter second, no overwrite",
      [os.path.basename(u) for u in up] == names and not any("--clobber" in l for l in log), (up, log))
pp, lp, upp, _l = publish(TLOG="[]")
check("AC9: a bundle with no Rekor entry publishes nothing", pp.returncode == 1 and upp == [] and "Rekor" in pp.stderr, pp.stderr)


def refused_signature():
    tmp = tempfile.mkdtemp()
    fix, env = sandbox(tmp)
    open(os.path.join(fix, "bad-signature"), "w").close()
    lt = os.path.join(tmp, "evidence-letter-2026-11.md")
    open(lt, "w").write("a letter\n")
    q = subprocess.run(["bash", os.path.join(ROOT, "bin/evidence-letter-publish.sh"), lt], cwd=ROOT, env=env,
                       capture_output=True, text=True)
    return q, open(os.path.join(fix, "uploaded")).read().split()


pq, upq = refused_signature()
check("F2: a signature that does not verify against the manifest key and the pinned log publishes nothing, in one line",
      one_line(pq) and upq == [], pq.stderr)


def refused_manifest():
    tmp = tempfile.mkdtemp()
    fix, env = sandbox(tmp)
    open(os.path.join(fix, "bad-manifest"), "w").close()
    lt = os.path.join(tmp, "evidence-letter-2026-11.md")
    open(lt, "w").write("a letter\n")
    q = subprocess.run(["bash", os.path.join(ROOT, "bin/evidence-letter-publish.sh"), lt], cwd=ROOT, env=env,
                       capture_output=True, text=True)
    return q, open(os.path.join(fix, "uploaded")).read().split(), open(os.path.join(tmp, "log")).read().splitlines()


pm, upm, lm = refused_manifest()
check("F2: a manifest the offline root does not vouch for (or a revoked one) refuses before anything is signed or uploaded, in one line",
      one_line(pm) and upm == [] and not any("sign-blob" in l or "release upload" in l for l in lm), (pm.stderr, lm))
pb, lb, upb, _l = publish(FAIL_UPLOAD="bundle")
check("AC9: a refused bundle upload fails closed with one line that carries gh's first line, and leaves nothing",
      one_line(pb) and "HTTP 422" in pb.stderr and "second line" not in pb.stderr and upb == [], (pb.stderr, upb))
pl, ll, upl, _l = publish(FAIL_UPLOAD="letter")
check("AC9: a refused letter upload removes the bundle again, fails closed with one line, and leaves nothing",
      one_line(pl) and "HTTP 422" in pl.stderr and upl == [] and any("delete-asset" in x for x in ll), (pl.stderr, upl))
pk, lk, upk, _l = publish(FAIL_UPLOAD="letter", FAIL_DELETE="1")
check("AC9: if the bundle cannot be removed the one line says so",
      one_line(pk) and "could not be removed" in pk.stderr, pk.stderr)
print("%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
PY
