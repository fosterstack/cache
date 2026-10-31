"""Release's comparison of Build's and Rebuild's apks (REQ-CHAIN-005-AC4 as the owner ratified it on Oct 21 2026, ops/docs/ratify/2026-10-21-signer-builder-separate-jobs.md:
the signer and the builder never share a machine). A job that holds the signing key or a publish credential never receives Rebuild's apks, and the comparison runs in a job
with no secrets and no publish permission. It runs in the compare job of stage-promote.yml as one plain step: no environment, no secret, no id-token, nothing signed, no key
read, no network.

In:  witness-rapk-<runner>/rapk-collection.json   the records Sign signed for Rebuild's apk legs (artifacts signed-witness-rapk-<runner>)
     apks/<runner>/<apk arch>/<file>.apk   Build's apks (artifacts apk-ubuntu-24.04, x86_64, and apk-ubuntu-24.04-arm, aarch64)
     rapks/<runner>/<apk arch>/<file>.apk  Rebuild's apks, laid out the same (artifacts rapk-...)
Out: apk-compare/apk-compare.json  {"verdict": "pass", "pairs": [four rows: arch, variant, name, build_sha256, rebuild_sha256, build_digest, rebuild_digest]}
     written only when all four pairs agree. The verify and release jobs read only this file; the release-verify step checks it against Build's attested apk digests.
Each of the four expected pairs (amd64 and arm64, standard and fips) must exist on both sides exactly once. So must the one image-only apk per runner (the base layout,
fscache-baselayout-*): it is checked like a pair (signer, signature, equal control and data) but has no row in the record, because no release ships it. Any other .apk, a symlink, a name with a control character, an apk
that is not a regular file, a signer other than assembly.rsa.pub, or a signature that does not verify against build/keys/assembly.rsa.pub is refused (exit 2). Apks that differ
in their control or data section exit 1 and name the apk; the signature section is not compared, only checked against the committed key."""
import hashlib, json, os, re, shutil, stat, subprocess, sys

ROOT_MSG = "run the comparison from the repository root (the helpers are named by their repo-relative paths)"
TOOL = [sys.executable, "-I", "-B", "bin/apk-tool.py"]
CHAIN = [sys.executable, "-I", "-B", "bin/chain-verify.py"]
# the four expected pairs, one fixed table (REQ-CHAIN-007-AC17): artifact (runner) -> apk architecture directory -> short name; variant -> file name pattern
RUNNERS = (("ubuntu-24.04", "x86_64", "amd64"), ("ubuntu-24.04-arm", "aarch64", "arm64"))
VARIANTS = (("standard", re.compile(r"fscache-[0-9][^/]*-r0\.apk")), ("fips", re.compile(r"fscache-fips-[^/]+-r0\.apk")))
# apks the images use and no release ships (0710): per runner exactly one on each side, the same signer, signature and bytes, but no row in apk-compare.json
IMAGE_ONLY = (("baselayout", re.compile(r"fscache-baselayout-[^/]+-r0\.apk")),)


def die(msg, code=2):
    print("release-compare: " + msg, file=sys.stderr)
    sys.exit(code)


def tool(*args):
    return subprocess.run(TOOL + list(args), capture_output=True, text=True, stdin=subprocess.DEVNULL)


def bind_rebuild_apks():
    """Rebuild's apks are bound to the record Sign signed for them (the building jobs hold no identity token, so the record is only as good as Sign's check):
    the signed record of each rapk leg must verify under the Sign identity (stage rebuild) and every file of rapks/<runner> must be the product it names.
    Sign never receives these apks (the owner's separation rule), so THIS job, which holds both builds' apks and no key, is where the product digests are checked."""
    ref = os.environ.get("GITHUB_REF", "")
    if not ref:
        die("GITHUB_REF is not set; the release policy cannot be made")
    res = subprocess.run(CHAIN + ["policy", "make", "--template", ".github/policy/release-policy.template.json", "--ref", ref, "--out", "policy.json"],
                         capture_output=True, text=True, stdin=subprocess.DEVNULL)
    if res.returncode != 0:
        die("cannot make the release policy: %s" % res.stderr.strip()[:300])
    for runner, _arch, _short in RUNNERS:
        rec = "witness-rapk-%s/rapk-collection.json" % runner
        for args in (["verify", "--policy", "policy.json", "--stage", "rebuild", "--record", rec],
                     ["bind", "--step", "rapk", "--record", rec, "--dir", "rapks/" + runner, "--as", "out"]):
            res = subprocess.run(CHAIN + args, capture_output=True, text=True, stdin=subprocess.DEVNULL)
            if res.returncode != 0:
                die("%s of Rebuild's %s record failed: %s" % (args[0], runner, (res.stderr.strip() or res.stdout.strip())[:300]))


def walk(top):
    """every .apk under top (relative path, full path); a symlink, a control character in a name, or an apk that is not a regular file is refused first"""
    found = []
    if os.path.islink(top):
        die("%s is a symlink; refusing (a link used as the root would let one side stand in for the other)" % top)
    for dp, dn, fn in os.walk(top, followlinks=False):
        for name in dn + fn:
            full = os.path.join(dp, name)
            if os.path.islink(full):
                die("%s is a symlink; refusing (only regular files are compared)" % full)
            if re.search(r"[\x00-\x1f\x7f]", name):
                die("a file name under %s holds a control character (newline or other): %r; refusing (a name is never split into two)" % (top, name))
        for name in dn:
            if name.endswith(".apk"):
                die("%s is not a regular file; refusing" % os.path.join(dp, name))
        for name in fn:
            full = os.path.join(dp, name)
            if name.endswith(".apk"):
                if not stat.S_ISREG(os.lstat(full).st_mode):
                    die("%s is not a regular file; refusing" % full)
                found.append(full)
    return sorted(found)


def sha256(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def main():
    if not (os.path.isfile("bin/release-compare.py") and os.path.isfile("bin/apk-tool.py")):
        die(ROOT_MSG)
    if not os.path.isfile("build/keys/assembly.rsa.pub"):
        die("build/keys/assembly.rsa.pub is missing")
    shutil.rmtree("apk-compare", ignore_errors=True)
    bind_rebuild_apks()
    listed = {}
    for top in ("apks", "rapks"):
        if not os.path.isdir(top):
            die("%s/ is not a directory: the artifacts of Build and Rebuild are missing" % top)
        listed[top] = walk(top)
        if not listed[top]:
            die("no apk under %s/" % top)
    pairs, image_only = [], []
    for runner, archdir, short in RUNNERS:
        for variant, pat in VARIANTS + IMAGE_ONLY:
            sides = {}
            for top, label in (("apks", "Build"), ("rapks", "Rebuild")):
                d = os.path.join(top, runner, archdir)
                hits = sorted(f for f in (os.listdir(d) if os.path.isdir(d) else []) if pat.fullmatch(f) and os.path.isfile(os.path.join(d, f)))
                if not hits:
                    other = "Build has no %s apk for %s (%s/%s)" % (variant, short, d, pat.pattern) if label == "Build" else \
                            "Rebuild has no counterpart for the %s apk of %s (missing under %s); Build and Rebuild must produce the same apks" % (variant, short, d)
                    die(other)
                if len(hits) != 1:
                    die("%s has %d %s apks for %s, exactly one is expected" % (label, len(hits), variant, short))
                sides[label] = os.path.join(d, hits[0])
            if os.path.basename(sides["Build"]) != os.path.basename(sides["Rebuild"]):
                die("Rebuild's %s apk for %s is named %s, Build's %s" % (variant, short, os.path.basename(sides["Rebuild"]), os.path.basename(sides["Build"])))
            (image_only if (variant, pat) in IMAGE_ONLY else pairs).append((short, variant, sides["Build"], sides["Rebuild"]))
    # nothing else: an .apk that is none of the four (or the image-only ones) on either side is an extra (fail closed)
    for top, idx in (("apks", 2), ("rapks", 3)):
        known = {p[idx] for p in pairs + image_only}
        for f in listed[top]:
            if f not in known:
                die("%s is an extra apk that is none of the four expected (standard and fips, amd64 and arm64); refusing (no counterpart on the other side)" % f)
    # both sides come from the assembly-key build: anything else was signed by somebody else, and a signature name is not a signature
    for short, variant, b, r in pairs + image_only:
        for f in (b, r):
            res = tool("signer", f)
            if res.returncode != 0:
                die("cannot read the signer of %s" % f)
            if res.stdout.strip() != "assembly.rsa.pub":
                die("%s is signed by '%s', not assembly.rsa.pub: Build and Rebuild must both carry the assembly key's signature" % (f, res.stdout.strip()))
            if tool("verify", f, "build/keys/assembly.rsa.pub").returncode != 0:
                die("the signature of %s does not verify against the committed assembly.rsa.pub: a signature name is not a signature" % f)
    bad = False
    for short, variant, b, r in pairs + image_only:
        if tool("same", b, r).returncode != 0:
            print("release-compare: %s (%s, %s) differs between Build and Rebuild" % (os.path.basename(b), variant, short), file=sys.stderr)
            bad = True
    if bad:
        die("Build and Rebuild disagree; no pass record was written", 1)
    rows = []
    for short, variant, b, r in pairs:
        digs = []
        for f in (b, r):
            res = tool("digest", f)
            if res.returncode != 0:
                die("cannot compute the digest of %s" % f)
            digs.append(res.stdout.strip())
        rows.append({"arch": short, "variant": variant, "name": os.path.basename(b), "build_sha256": sha256(b), "rebuild_sha256": sha256(r),
                     "build_digest": digs[0], "rebuild_digest": digs[1]})
    os.mkdir("apk-compare")
    tmp = "apk-compare/apk-compare.json.tmp"
    with open(tmp, "w") as fh:
        json.dump({"verdict": "pass", "pairs": rows}, fh, indent=1, sort_keys=True)
        fh.write("\n")
    os.rename(tmp, "apk-compare/apk-compare.json")
    print("compared %d apk pair(s): Build and Rebuild agree" % len(rows))


main()
