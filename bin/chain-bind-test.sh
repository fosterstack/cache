#!/usr/bin/env bash
# proves: REQ-CHAIN-004-AC12, REQ-CHAIN-004-AC13, REQ-CHAIN-004-AC3, REQ-CHAIN-004-AC9, REQ-CHAIN-005-AC1, REQ-CHAIN-005-AC7 — the assemble job binds every file it uses to the verified record (rule 58); digests.json and items.json are what an honest merge writes; Rebuild binds the same way
# Written before the bind, items-apk and items-merge subcommands existed (tests before implementation, step 4); they are bin/chain_items.py now.
#
# The REAL chain-verify.py subcommands that bin/chain-test-harness.py only fakes. Needs: python3, ubuntu-24.04 or macOS. No network, no keys.
# Records are DSSE envelopes built here (the shape of bin/chain-rebuild-test.sh): `bind` and `items-*` never check a signature, because the
# `verify` line that runs right before `bind` in the stage script does that (the script order is pinned in bin/chain-build-wiring-test.sh).
# Every command runs from the repository root of a throw-away tree with RELATIVE paths, as the stage scripts do.
#
# THE CLI THIS TEST ASSUMES (the implementer matches it; anything else is a change to this header first):
#   chain-verify.py bind --step apk|rapk|snapshot-apk|snapshot-rapk --record REC.json --dir DIR --as PREFIX      (--dir and --as are relative paths)
#     REC.json   the Witness collection of the apk matrix job (step apk, Build) or of the Rebuild apk job (step rapk). Its Statement holds product
#                subjects https://witness.dev/attestations/product/v0.1/file:PREFIX/<path relative to DIR> with digests {sha256, gitoid...}.
#                Witness runs from the repo root, so the artifact DIR is the job's `out` and PREFIX is out (in-toto-witness
#                docs/tutorials/artifact-policy.md:58-70).
#     exit 0 only when EVERY regular file under DIR is the product the record holds under PREFIX/<its path> with the same sha256, and the record
#     holds no product under PREFIX/ that has no file in DIR. Exit 1, first stderr line `refused at <build|rebuild>: <cause>: <paths>` (the paths
#     it names, space separated, as PREFIX/<path>), cause one of
#       digest   a file's sha256 differs from the product's; a file has no product; a product has no file; two products for one name;
#                a subject of another kind (material) for the name does not count; a product with no sha256 key
#       step     the record's collection name is not the --step (an apk record of Rebuild given to Build, and the reverse)
#       empty    DIR holds no file
#       symlink  DIR holds a symbolic link, to a file or to a directory, dangling or not (what it points at is not what the record covers)
#       hidden   DIR holds a file or directory whose name starts with a dot. upload-artifact leaves hidden files out of an artifact by default, so a
#                dotfile in out/ would be a product with no file after the upload: refused here instead of relied on
#       record   the file is not a DSSE envelope of a Witness collection
#     Exit 2 (usage, never a pass): an unreadable record, a missing option, --dir or --as absolute or holding `..`, an unknown --step.
#   chain-verify.py bind --local --step apk|rapk --record STEP-collection.local.json --dir DIR --as PREFIX      (the Witness move, owner Oct 22)
#     Build and Rebuild's Witness records are made inside the building job with a throwaway key, so they are UNTRUSTED until Sign re-signs them
#     keyless. The building jobs' assemble steps still bind their files to the record they just made: --local says the record is such a file. It is a
#     DSSE envelope of a Witness collection whose NAME ends in .local.json (the throwaway-key form: signatures [{keyid, sig}], no certificate), and the
#     product binding is the same as without --local; no signature or identity is checked (there is nothing to check). WITHOUT --local a record whose name
#     ends in .local.json is refused (cause record: an unsigned local record is not a trusted record), and WITH --local a record whose name does not end in
#     .local.json is refused (cause record) too, so a signed record can never pass as a local one nor the reverse. Step names, snapshot steps and the other
#     causes are as without --local.
#   chain-verify.py sign-records --stage build|rebuild --template T.json --digests FILE --out DIR --record-dir D... [--artifacts-dir A]      (the Witness move)
#     Sign's check-and-stage step. Each --record-dir D holds exactly one <step>-collection.local.json (step apk or build for --stage build, rapk or rebuild for
#     --stage rebuild; a snapshot- step, another step, a record whose name is not <step>-collection.local.json, two records, or a file that is not a record or one of
#     digests.json / items.json / admission-baseline.json / verdict.json is refused) and those data files. The record is a DSSE envelope of a Witness collection (the
#     throwaway-key form) whose name is the step, whose attestors are EXACTLY environment, git, material and product, which names no token variable or value
#     (record-env), whose git commit is the run's commit ($GITHUB_SHA, a 40-hex), and which is not a snapshot record or version. The per-tag policy is made from --template
#     and $GITHUB_REF / $GITHUB_EVENT_NAME exactly as `sign --check` does (a pushed tag, or a workflow_dispatch on a branch for the dry run). Every artifact file Sign
#     RECEIVES (the files under A/<D-name>/ and the data files of D) must be a product of the record with the same sha256: no received file the record does not name,
#     no different byte; a product the record names that Sign does not hold is NOT refused, except the required names (build: digests.json items.json
#     admission-baseline.json; rebuild: verdict.json), which a record of the assembling step must receive. For --stage rebuild the record's material file:witness-build/digests.json
#     must equal --digests (Build's attested list). On success it writes, per record, OUT/<D-name>/<step>-collection.payload (the DSSE payload, byte for byte) and the
#     data files unchanged, and prints one line per record `OUT/<D-name>/<step>-collection.payload<TAB>signed/<D-name>/<step>-collection.json`. Any refusal: exit 1,
#     `refused at <build|rebuild>: <reason>`, and OUT is not created. Exit 2: --out exists, a usage error.
#   chain-verify.py items-apk --out-dir out/ARCH --result FILE
#     reads the apks in out/ARCH by their names (fscache-VERSION-r0.apk for standard, fscache-fips-VERSION-r0.apk for fips; exactly one each) and
#     writes the fragment {"arch","items"}. The apk item is `python3 bin/apk-tool.py digest APK`, run from the working directory (cache's tool, by
#     name: the sections it covers are cache's to change; this test only needs it to differ from the whole-file sha256 and to ignore the signature).
#     The binary item is the sha256 of the stdout of `python3 bin/apk-tool.py cat APK usr/bin/fscache`. The modules SBOM and the inputs manifest
#     items are read from out/ (the parent of --out-dir), and the index item from out/ARCH/APKINDEX.tar.gz. A file or directory whose name starts
#     with a dot under out/ is refused (exit 1, cause hidden), like bind.
#   chain-verify.py items-merge --fragment F... --images DIR --archives DIR --version V --archive DIR [--digests FILE] --items FILE
#     merges the fragments and adds the image, manifest, lock and SBOM items from DIR (the files assemble-image.sh writes), the archive items from
#     --archives (the four Linux archives, goreleaser's names) and archive-checksums from --archive; writes --items and (optionally) --digests.
#     Exit 1 with nothing written, first line `refused at build: <cause>: <names>`: digest (two fragments naming one item with different values),
#     arch (the fragments are not exactly one for x86_64 and one for aarch64: a missing or a doubled architecture is named), missing (an input file
#     is missing), unexpected (a fragment names an item the committed list does not have).
# PROPOSED/UNVERIFIED: the items layout (bin/chain-test-harness.py documents the oracle) and the file names of the archives.
exec python3 - "$(cd "$(dirname "$0")/.." && pwd)" <<'PY'
import atexit, base64, hashlib, importlib.util, json, os, shutil, subprocess, sys, tempfile

root = sys.argv[1]
CV = root + "/bin/chain-verify.py"
spec = importlib.util.spec_from_file_location("h", root + "/bin/chain-test-harness.py")
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)
work = tempfile.mkdtemp()
atexit.register(shutil.rmtree, work, ignore_errors=True)      # a failing or aborted run leaves nothing in TMPDIR
passed = failed = 0
PRODUCT = "https://witness.dev/attestations/product/v0.1/file:"
MATERIAL = "https://witness.dev/attestations/material/v0.1/file:"
FILES = {"x86_64/fscache-0.3.0-r0.apk": b"SIG:assembly\napk-x", "x86_64/APKINDEX.tar.gz": b"index", "items-apk.json": b"{}"}


def check(label, ok, detail=""):
    global passed, failed
    if ok:
        passed += 1
        print("ok   " + label)
    else:
        failed += 1
        print("FAIL %s %s" % (label, detail))


def run(args, cwd):
    if not os.path.exists(CV):
        return 127, "", "bin/chain-verify.py does not exist (RED)"
    try:
        p = subprocess.run([sys.executable, CV] + args, capture_output=True, text=True, cwd=cwd, timeout=60)
    except subprocess.TimeoutExpired:
        return 124, "", "timed out after 60 seconds"
    return p.returncode, p.stdout, p.stderr


def record(path, subjects, name="apk"):
    statement = {"_type": "https://in-toto.io/Statement/v0.1", "predicateType": "https://witness.testifysec.com/attestation-collection/v0.1",
                 "subject": subjects, "predicate": {"name": name, "attestations": []}}
    payload = base64.b64encode(json.dumps(statement).encode()).decode()
    json.dump({"payloadType": "application/vnd.in-toto+json", "payload": payload, "signatures": []}, open(path, "w"))


def subject(name, data, kind=PRODUCT, sha_key=True):
    digest = {"gitoid:sha1": "gitoid:blob:sha1:" + "0" * 40}
    if sha_key:
        digest["sha256"] = hashlib.sha256(data).hexdigest()
    return {"name": kind + name, "digest": digest}


def tree(name, files=FILES):
    """A throw-away repository root with the artifact in dir/ and the record in rec.json."""
    d = "%s/%s" % (work, name)
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d + "/dir")
    for rel, data in files.items():
        os.makedirs(os.path.dirname("%s/dir/%s" % (d, rel)), exist_ok=True)
        open("%s/dir/%s" % (d, rel), "wb").write(data)
    return d


def good_subjects(files=FILES):
    return [subject("out/" + rel, data) for rel, data in files.items()]


def bind(label, d, want_rc, cause=None, names=None, step="apk", flags=(), **override):
    """Run bind from the root d with relative paths, and judge the exit code, the first line and the exact set of paths it names."""
    args = {"--step": step, "--record": "rec.json", "--dir": "dir", "--as": "out"}
    args.update({"--" + k: v for k, v in override.items()})
    rc, out, err = run(["bind"] + list(flags) + [x for kv in args.items() for x in kv], d)
    first = err.split("\n", 1)[0]
    ok = rc == want_rc and "Traceback" not in err
    if want_rc == 1:
        ok = ok and first.startswith("refused at %s: %s: " % ("rebuild" if step in ("rapk", "snapshot-rapk") else "build", cause))
        ok = ok and (names is None or set(first.split(": ", 2)[2].split()) == set(names))
    check(label, ok, "exit %s, first line %r" % (rc, first[:160]))


check("bin/chain-verify.py exists", os.path.exists(CV), "(RED: not implemented yet; every case below needs it)")
# ---- bind ----------------------------------------------------------------------------------------------------------------------------
APK, INDEX, FRAG = "out/x86_64/fscache-0.3.0-r0.apk", "out/x86_64/APKINDEX.tar.gz", "out/items-apk.json"
d = tree("ok")
record(d + "/rec.json", good_subjects())
bind("bind: every file is the product the record holds", d, 0)

d = tree("flip")
record(d + "/rec.json", good_subjects())
open(d + "/dir/x86_64/fscache-0.3.0-r0.apk", "ab").write(b"x")
bind("bind: one changed byte in a file is refused and names it", d, 1, "digest", [APK])

d = tree("nosubject")
record(d + "/rec.json", [s for s in good_subjects() if not s["name"].endswith("items-apk.json")])
bind("bind: a file with no product in the record is refused", d, 1, "digest", [FRAG])

d = tree("nofile")
record(d + "/rec.json", good_subjects() + [subject("out/x86_64/extra.apk", b"e")])
bind("bind: a product with no file in the artifact is refused", d, 1, "digest", ["out/x86_64/extra.apk"])

d = tree("material")
record(d + "/rec.json", [subject("out/" + r, b, MATERIAL if r == "items-apk.json" else PRODUCT) for r, b in FILES.items()])
bind("bind: a material subject of the right name is not the product", d, 1, "digest", [FRAG])

d = tree("two")
record(d + "/rec.json", good_subjects() + [subject("out/items-apk.json", b"other")])
bind("bind: two products for one name are refused", d, 1, "digest", [FRAG])

d = tree("bak")
record(d + "/rec.json", [subject("out/" + r + (".bak" if r == "items-apk.json" else ""), b) for r, b in FILES.items()])
bind("bind: a product named items-apk.json.bak does not cover items-apk.json", d, 1, "digest", [FRAG, FRAG + ".bak"])

d = tree("nosha")
record(d + "/rec.json", [subject("out/" + r, b, sha_key=(r != "items-apk.json")) for r, b in FILES.items()])
bind("bind: a product with a gitoid digest and no sha256 is refused", d, 1, "digest", [FRAG])

d = tree("wrongstep")
record(d + "/rec.json", good_subjects(), name="rapk")
bind("bind: a Rebuild apk record (step rapk) given to Build (--step apk) is refused", d, 1, "step", ["rapk"])
d = tree("wrongstep2")
record(d + "/rec.json", good_subjects(), name="apk")
bind("bind: a Build apk record given to Rebuild (--step rapk) is refused", d, 1, "step", ["apk"], step="rapk")
d = tree("rapk")
record(d + "/rec.json", good_subjects(), name="rapk")
bind("bind: the Rebuild step accepts its own record", d, 0, step="rapk")

# REQ-CHAIN-004-AC12 / REQ-CHAIN-005-AC7: a snapshot build's record is named snapshot-apk, a snapshot Rebuild's snapshot-rapk; bind takes each
# under its own step only
d = tree("snapok")
record(d + "/rec.json", good_subjects(), name="snapshot-apk")
bind("bind: the snapshot step accepts its own record (snapshot-apk)", d, 0, step="snapshot-apk")
# the 0.0.0 refusal belongs to the VERIFIERS only: bind must ACCEPT the files of a real snapshot run, which are all 0.0.0 (a wrong implementation
# that refused the version in the shared record reader would break every snapshot run while every refusal test stayed green)
FILES_SNAP = {"x86_64/fscache-0.0.0_rc1-r0.apk": b"SIG:assembly\napk-s", "x86_64/fscache-fips-0.0.0_rc1-r0.apk": b"SIG:assembly\napk-sf",
              "x86_64/APKINDEX.tar.gz": b"index", "items-apk.json": b"{}"}
for step, name in (("snapshot-apk", "snapok0"), ("snapshot-rapk", "snaprapk0")):
    d = tree(name, FILES_SNAP)
    record(d + "/rec.json", good_subjects(FILES_SNAP), name=step)
    bind("bind: --step %s accepts a record whose files are fscache-0.0.0_rc1-r0.apk (the version refusal is the verifiers')" % step, d, 0, step=step)
d = tree("snapwrong1")
record(d + "/rec.json", good_subjects(), name="apk")
bind("bind: a release apk record given to the snapshot step is refused as another step", d, 1, "step", ["apk"], step="snapshot-apk")
d = tree("snapwrong2")
record(d + "/rec.json", good_subjects(), name="snapshot-apk")
bind("bind: a snapshot record given to the release step (--step apk) is refused as another step", d, 1, "step", ["snapshot-apk"])
d = tree("snaprapk")
record(d + "/rec.json", good_subjects(), name="snapshot-rapk")
bind("bind: the snapshot Rebuild step accepts its own record (snapshot-rapk)", d, 0, step="snapshot-rapk")
d = tree("snaprapk2")
record(d + "/rec.json", good_subjects(), name="snapshot-rapk")
bind("bind: a snapshot-rapk record given to the release Rebuild step (--step rapk) is refused as another step", d, 1, "step", ["snapshot-rapk"], step="rapk")
d = tree("snaprapk3")
record(d + "/rec.json", good_subjects(), name="rapk")
bind("bind: a release rapk record given to the snapshot Rebuild step is refused as another step", d, 1, "step", ["rapk"], step="snapshot-rapk")
d = tree("snapevil")
record(d + "/rec.json", good_subjects(), name="snapshot-evil")
bind("bind: snapshot-evil is not a step (the snapshot names are a closed list): a usage error", d, 2, step="snapshot-evil")

d = tree("prefix")
record(d + "/rec.json", [subject("other/" + r, b) for r, b in FILES.items()])
bind("bind: the same bytes under another prefix are not the files of --as out", d, 1, "digest", [APK, INDEX, FRAG])

d = tree("empty", {})
record(d + "/rec.json", good_subjects())
bind("bind: an empty artifact directory is refused", d, 1, "empty")

d = tree("link")
record(d + "/rec.json", good_subjects())
os.symlink("/etc/passwd", d + "/dir/x86_64/link")
bind("bind: a symbolic link to a file is refused", d, 1, "symlink", ["out/x86_64/link"])
d = tree("dirlink")
record(d + "/rec.json", good_subjects())
os.symlink("/etc", d + "/dir/x86_64/etc")
bind("bind: a symbolic link to a directory is refused (it is not walked into)", d, 1, "symlink", ["out/x86_64/etc"])
d = tree("dangling")
record(d + "/rec.json", good_subjects())
os.symlink("/nonexistent/target", d + "/dir/x86_64/gone")
bind("bind: a dangling symbolic link is refused", d, 1, "symlink", ["out/x86_64/gone"])

HIDDEN = dict(FILES, **{".secret": b"s"})
d = tree("hidden", HIDDEN)
record(d + "/rec.json", good_subjects(HIDDEN))
bind("bind: a dotfile in the artifact is refused even when the record holds it (upload-artifact would drop it)", d, 1, "hidden", ["out/.secret"])
HIDDIR = dict(FILES, **{"x86_64/.cache/x": b"s"})
d = tree("hiddendir", HIDDIR)
record(d + "/rec.json", good_subjects(HIDDIR))
bind("bind: a dot directory in the artifact is refused", d, 1, "hidden", ["out/x86_64/.cache"])

d = tree("bare")
json.dump({"_type": "x", "predicate": {}}, open(d + "/rec.json", "w"))
bind("bind: a record that is not a DSSE envelope is refused", d, 1, "record")
d = tree("unreadable")
bind("bind: an unreadable record is a usage error, never a pass", d, 2)
d = tree("abs")
record(d + "/rec.json", good_subjects())
bind("bind: an absolute --as is a usage error", d, 2, **{"as": "/out"})
d = tree("absdir")
record(d + "/rec.json", good_subjects())
bind("bind: an absolute --dir is a usage error", d, 2, dir=d + "/dir")
d = tree("dots")
record(d + "/rec.json", good_subjects())
bind("bind: a --dir holding .. is a usage error", d, 2, dir="dir/../dir")
d = tree("step")
record(d + "/rec.json", good_subjects())
bind("bind: an unknown --step is a usage error", d, 2, step="build")


# ---- items-apk: the apk digest is cache's `apk-tool.py digest`, not the whole-file sha256 ---------------------------------------------------
def apk_tree(name, tag="v0.3.0", key="assembly", edit=None):
    """A throw-away root with out/x86_64 laid out as the apk job leaves it, and the fake apk-tool in bin/."""
    d = "%s/%s" % (work, name)
    shutil.rmtree(d, ignore_errors=True)
    for rel, data in h.out_files("x86_64", tag).items():
        if rel.endswith(".apk"):
            data = h.apk_bytes("fips" if "fips" in rel else "standard", "x86_64", tag, key)
        h.write("%s/out/%s" % (d, rel), data)
    h.write(d + "/bin/apk-tool.py", h.FAKE_APKTOOL, 0o755)
    if edit:
        edit(d)
    return d


def fragment_of(d):
    rc, out, err = run(["items-apk", "--out-dir", "out/x86_64", "--result", "frag.json"], d)
    return rc, (json.load(open(d + "/frag.json")) if rc == 0 and os.path.exists(d + "/frag.json") else None), err


def flip_a_byte(d):
    open(d + "/out/x86_64/fscache-0.3.0-r0.apk", "ab").write(b"!")


def add_second_apk(d):
    h.write(d + "/out/x86_64/fscache-0.3.1-r0.apk", h.apk_bytes("standard", "x86_64", "v0.3.1"))


def add_dotfile(d):
    h.write(d + "/out/.cache/x", b"s")


d1 = apk_tree("apk1")
rc, frag1, err = fragment_of(d1)
whole = hashlib.sha256(open(d1 + "/out/x86_64/fscache-0.3.0-r0.apk", "rb").read()).hexdigest()
check("items-apk: the items are exactly the oracle's (apk by apk-tool digest, binary by apk-tool cat), and the apk item is not the whole-file sha256",
      rc == 0 and frag1 == h.fragment("x86_64", "v0.3.0") and frag1["items"]["apk-standard-x86_64"] != "sha256:" + whole, "exit %s %s" % (rc, err[:120]))
rc, frag2, err = fragment_of(apk_tree("apk2", key="release"))
check("items-apk: the same apk re-signed with another key has the same apk and binary items (the signature is not covered)",
      rc == 0 and frag1 and frag2 and frag1["items"] == frag2["items"], "exit %s" % rc)
rc, frag3, err = fragment_of(apk_tree("apk3", edit=flip_a_byte))
check("items-apk: one changed byte outside the signature changes the apk and the binary item",
      rc == 0 and frag1 and frag3 and all(frag1["items"][k] != frag3["items"][k] for k in ("apk-standard-x86_64", "binary-standard-x86_64")), "exit %s" % rc)
rc, frag4, err = fragment_of(apk_tree("apk4", tag="v0.3.0-rc1"))
check("items-apk: a release candidate's apk (fscache-0.3.0_rc1-r0.apk, PROPOSED) is found by its variant",
      rc == 0 and frag4 == h.fragment("x86_64", "v0.3.0-rc1"), "exit %s %s" % (rc, err[:120]))
rc, frag4b, err = fragment_of(apk_tree("apk4b", tag="v0.0.0-rc.1"))
check("items-apk: a SNAPSHOT build's apks (fscache-0.0.0_rc1-r0.apk and the fips one) are found and itemized (the 0.0.0 refusal is the verifiers')",
      rc == 0 and frag4b == h.fragment("x86_64", "v0.0.0-rc.1"), "exit %s %s" % (rc, err[:120]))
rc, frag5, err = fragment_of(apk_tree("apk5", edit=add_second_apk))
check("items-apk: two standard apks in one directory are refused (exactly one per variant)",
      rc == 1 and err.startswith("refused at build"), "exit %s %s" % (rc, err[:100]))
rc, frag6, err = fragment_of(apk_tree("apk6", edit=add_dotfile))
check("items-apk: a dot directory under out/ is refused (upload-artifact would drop it)",
      rc == 1 and err.startswith("refused at build: hidden: "), "exit %s %s" % (rc, err[:100]))


# ---- items-merge ---------------------------------------------------------------------------------------------------------------------------
def merge_tree(name, tag="v0.3.0"):
    d = "%s/%s" % (work, name)
    shutil.rmtree(d, ignore_errors=True)
    for runner, arch, _ in h.RUNNERS:
        h.write("%s/apk/%s/items-apk.json" % (d, runner), json.dumps(h.fragment(arch, tag)))
    for image in h.IMAGES:
        o = h.image_outputs(image, tag)
        for rel, data in h.layout_files(image, tag).items():
            h.write("%s/out/%s/%s" % (d, image, rel), data)
        h.write("%s/out/%s.digest" % (d, image), o["digest"] + "\n")
        h.write("%s/out/%s.manifests" % (d, image), "\n".join(o["manifests"]) + "\n")
        h.write("%s/out/%s.full.lock.json" % (d, image), o["lock"])
        h.write("%s/out/%s-sbom/sbom.json" % (d, image), o["sbom"])
    for _, (file, data) in h.archive_files(tag).items():
        h.write("%s/dist/%s" % (d, file), data)
    h.write(d + "/archive/keys/wolfi-signing.rsa.pub", "w")
    h.write(d + "/archive/x86_64/pkg-1.apk", "p1")
    return d


def do_merge(d, fragments=None, tag="v0.3.0"):
    fragments = fragments or ["apk/%s/items-apk.json" % runner for runner, _, _ in h.RUNNERS]
    args = ["items-merge"] + [x for f in fragments for x in ("--fragment", f)]
    args += ["--images", "out", "--archives", "dist", "--version", tag[1:], "--archive", "archive", "--digests", "digests.json", "--items", "items.json"]
    return run(args, d)


def refused(label, d, result, cause, name=None):
    rc, out, err = result
    first = err.split("\n", 1)[0]
    written = [f for f in ("items.json", "digests.json") if os.path.exists(d + "/" + f)]
    ok = rc == 1 and first.startswith("refused at build: %s: " % cause) and (name is None or name in first.split()) and not written and "Traceback" not in err
    check(label, ok, "exit %s, first line %r, files written: %s" % (rc, first[:120], written))


d = merge_tree("m1")
rc, out, err = do_merge(d)
expected_items, expected_digests = h.expected(d, "assemble", "items", "v0.3.0", vex=False), h.expected(d, "assemble", "digests", "v0.3.0", vex=False)
got_items = json.load(open(d + "/items.json")) if os.path.exists(d + "/items.json") else None
got_digests = json.load(open(d + "/digests.json")) if os.path.exists(d + "/digests.json") else None
check("items-merge: items.json is exactly the oracle's 29 items",
      rc == 0 and got_items == expected_items and len(expected_items) == 29, "exit %s %s" % (rc, err[:120]))
check("items-merge: digests.json is exactly the oracle's: 2 images, 4 apks, 4 archives, each equal to its item",
      rc == 0 and got_digests == expected_digests and len(expected_digests) == 10, "exit %s" % rc)


# B1 (Codex B r2): Build's stage output is `jq -c . digests.json` through a command substitution, and Sign writes that text with printf '%s'. The file the
# Witness product hashes must therefore BE those bytes (compact, no trailing newline), or Sign's byte binding refuses every release. The test hashes what Sign
# actually receives and runs the REAL verifier comparison on it.
original = open(d + "/digests.json", "rb").read() if os.path.exists(d + "/digests.json") else b""
transported = subprocess.run(["jq", "-c", "."], input=original, capture_output=True).stdout.rstrip(b"\n")      # the stage output text, as Sign's printf writes it
check("items-merge: digests.json is byte-identical to what the stage output transports to Sign (compact JSON, no trailing newline)",
      rc == 0 and original != b"" and original == transported, "%d bytes written, %d transported" % (len(original), len(transported)))
_cv = importlib.util.spec_from_file_location("cv", root + "/bin/chain-verify.py"); cv = importlib.util.module_from_spec(_cv)
sys.path.insert(0, root + "/bin"); _cv.loader.exec_module(cv)
stmt = {"subject": [{"name": cv.PRODUCT, "digest": {"sha256": hashlib.sha256(original).hexdigest()}}]}      # the product the Witness record holds for the file
try:
    cv.digest_compare("build", stmt, transported, json.loads(transported)); bound = True
except cv.Refuse:
    bound = False
check("items-merge: Sign's byte binding (digest_compare, the real verifier) accepts the text the stage output carries", bound, "refused")


def edit_fragment(d, runner, edit):
    path = "%s/apk/%s/items-apk.json" % (d, runner)
    fragment = json.load(open(path))
    edit(fragment)
    h.write(path, json.dumps(fragment))


d = merge_tree("m2")
edit_fragment(d, "ubuntu-24.04-arm", lambda f: f["items"].update({"modules-sbom-standard": "sha256:" + "0" * 64}))
refused("items-merge: two fragments with different values for one item are refused and nothing is written", d, do_merge(d), "digest", "modules-sbom-standard")
d = merge_tree("m3")
edit_fragment(d, "ubuntu-24.04", lambda f: f["items"].update({"unlisted-item": "sha256:" + "0" * 64}))
refused("items-merge: an item that is not on the committed list is refused", d, do_merge(d), "unexpected", "unlisted-item")
d = merge_tree("m4")
os.remove(d + "/out/fips.manifests")
refused("items-merge: a missing image file is refused", d, do_merge(d), "missing", "fips.manifests")
def edit_manifests(d, image, edit):
    path = "%s/out/%s.manifests" % (d, image)
    lines = [l for l in open(path).read().split("\n") if l.strip()]
    h.write(path, "\n".join(edit(lines)) + "\n")


d = merge_tree("m4a")
edit_manifests(d, "production", lambda L: [L[0].split()[0] + " sha256:" + "9" * 64] + L)
refused("items-merge: an architecture repeated in <image>.manifests is refused (a later line must not overwrite the first digest)", d, do_merge(d), "manifests", "production.manifests")
d = merge_tree("m4b")
edit_manifests(d, "fips", lambda L: L[:1])
refused("items-merge: an architecture missing from <image>.manifests is refused", d, do_merge(d), "manifests", "fips.manifests")
d = merge_tree("m4c")
edit_manifests(d, "fips", lambda L: L + ["s390x sha256:" + "8" * 64])
refused("items-merge: an architecture outside amd64 and arm64 in <image>.manifests is refused", d, do_merge(d), "manifests", "fips.manifests")
d = merge_tree("m4d")
edit_manifests(d, "production", lambda L: [L[0] + " extra"] + L[1:])
refused("items-merge: a malformed line in <image>.manifests is refused, never a traceback", d, do_merge(d), "manifests", "production.manifests")
# Build's images artifact ships each variant as an OCI LAYOUT directory out/<variant>/ (oci-layout, index.json, blobs/), so the digest does not change between
# Build and a push (real crane runs: a docker-format tarball push changes the digest, a layout directory keeps it). PROPOSED/UNVERIFIED: cache P5 decides the
# shape of assemble-image.sh's output; the judge pins this one.
def layout_refused(label, edit, fragment):
    dd = merge_tree("lay-" + label.split()[0])
    edit(dd)
    refused("items-merge: " + label, dd, do_merge(dd), "layout", fragment)


def child_digest(image, arch):
    return h.image_outputs(image, "v0.3.0")["children"][arch][0]


def flip_sidecar(dd):          # the sidecar names another amd64 child than the index blob does
    p = dd + "/out/production.manifests"; lines = open(p).read().split("\n")
    lines[0] = "amd64 sha256:" + "5" * 64; open(p, "w").write("\n".join(lines))


def drop_child(dd):
    os.remove("%s/out/production/blobs/sha256/%s" % (dd, child_digest("production", "arm64").split(":")[1]))


def corrupt_child(dd):
    open("%s/out/fips/blobs/sha256/%s" % (dd, child_digest("fips", "amd64").split(":")[1]), "ab").write(b" ")


def non_json_index(dd):
    # an index blob that is not JSON (the old test oracle's shape), with a descriptor and a name that match
    blob = b"image|production|not json"; dg = hashlib.sha256(blob).hexdigest()
    shutil.rmtree(dd + "/out/production/blobs"); h.write("%s/out/production/blobs/sha256/%s" % (dd, dg), blob)
    h.write(dd + "/out/production/index.json", json.dumps({"manifests": [{"digest": "sha256:" + dg}]}))
    h.write(dd + "/out/production.digest", "sha256:" + dg + "\n")


def drop_layout(dd, image="production"):
    shutil.rmtree("%s/out/%s" % (dd, image))


d = merge_tree("lay-ok")
rc, out, err = do_merge(d)
check("items-merge: the digest Build records equals the descriptor of the image index in the uploaded layout (production and fips)",
      rc == 0 and json.load(open(d + "/items.json"))["image-production"] == h.image_outputs("production", "v0.3.0")["digest"], "exit %s %s" % (rc, err[:120]))
layout_refused("a docker-save tarball shape (manifest.json at the root, no oci-layout) is refused", lambda dd: (os.remove(dd + "/out/production/oci-layout"),
               h.write(dd + "/out/production/manifest.json", "[]")), "production")
layout_refused("a layout directory missing for a variant (only the old <variant>.tar file) is refused", lambda dd: (drop_layout(dd), h.write(dd + "/out/production.tar", "tar")), "production")
def other_digest(dd):
    p = dd + "/out/fips/index.json"; ix = json.load(open(p)); ix["manifests"][0]["digest"] = "sha256:" + "7" * 64; open(p, "w").write(json.dumps(ix))
layout_refused("an index.json whose descriptor is not the recorded digest is refused", other_digest, "fips")
def two_descriptors(dd):
    p = dd + "/out/fips/index.json"; ix = json.load(open(p)); ix["manifests"] = ix["manifests"] * 2; open(p, "w").write(json.dumps(ix))
layout_refused("an index.json with two descriptors is refused", two_descriptors, "fips")
def no_blob(dd):
    hexd = h.image_outputs("production", "v0.3.0")["digest"].split(":", 1)[1]; os.remove("%s/out/production/blobs/sha256/%s" % (dd, hexd))
layout_refused("a layout whose index blob is missing is refused", no_blob, "production")
def bad_blob(dd):
    hexd = h.image_outputs("production", "v0.3.0")["digest"].split(":", 1)[1]; open("%s/out/production/blobs/sha256/%s" % (dd, hexd), "ab").write(b"x")
layout_refused("a layout whose blob does not hash to its name is refused", bad_blob, "production")
def bad_version(dd):
    open(dd + "/out/production/oci-layout", "w").write('{"imageLayoutVersion": "2.0.0"}')
layout_refused("an oci-layout file of another version is refused", bad_blob if False else bad_version, "production")
# Codex A r3 F3: the sidecar digests are bound to the platform descriptors of the parsed index blob, and the child blobs exist and hash to their names
d = merge_tree("idx-ok")
rc, out, err = do_merge(d)
ix = json.loads(open("%s/out/production/blobs/sha256/%s" % (d, h.image_outputs("production", "v0.3.0")["digest"].split(":")[1])).read())
check("items-merge: the oracle's image index is real OCI JSON with a linux/amd64 and a linux/arm64 descriptor equal to the sidecar",
      rc == 0 and sorted((m["platform"]["architecture"], m["platform"]["os"]) for m in ix["manifests"]) == [("amd64", "linux"), ("arm64", "linux")]
      and sorted(m["digest"] for m in ix["manifests"]) == sorted(l.split()[1] for l in h.image_outputs("production", "v0.3.0")["manifests"]), "exit %s" % rc)
layout_refused("a sidecar digest that is not the index's platform descriptor is refused", flip_sidecar, "production")
layout_refused("a child manifest blob that is missing is refused", drop_child, "production")
layout_refused("a child manifest blob that does not hash to its name is refused", corrupt_child, "fips")
layout_refused("an index blob that is not JSON is refused", non_json_index, "production")
d = merge_tree("m5")
os.remove(d + "/dist/" + h.archive_files("v0.3.0")["archive-fips-linux-arm64"][0])
refused("items-merge: a missing archive is refused", d, do_merge(d), "missing", "archive-fips-linux-arm64")
d = merge_tree("m6")
refused("items-merge: the same architecture twice (aarch64 missing) is refused and the missing architecture is named", d,
        do_merge(d, ["apk/ubuntu-24.04/items-apk.json"] * 2), "arch", "aarch64")
d = merge_tree("m6b")
refused("items-merge: one architecture only (aarch64 missing) is refused and named", d, do_merge(d, ["apk/ubuntu-24.04/items-apk.json"]), "arch", "aarch64")
d = merge_tree("m8", "v0.0.0-rc.1")
rc, out, err = do_merge(d, tag="v0.0.0-rc.1")
check("items-merge: a snapshot build's files (version 0.0.0-rc.1, archives fscache_0.0.0-rc.1_linux_*) merge to the oracle's items",
      rc == 0 and os.path.exists(d + "/items.json") and json.load(open(d + "/items.json")) == h.expected(d, "assemble", "items", "v0.0.0-rc.1", vex=False),
      "exit %s %s" % (rc, err[:100]))
d = merge_tree("m7", "v0.3.0-rc1")
rc, out, err = do_merge(d, tag="v0.3.0-rc1")
check("items-merge: a release candidate's files merge to the oracle's items (PROPOSED names)",
      rc == 0 and os.path.exists(d + "/items.json") and json.load(open(d + "/items.json")) == h.expected(d, "assemble", "items", "v0.3.0-rc1", vex=False),
      "exit %s %s" % (rc, err[:100]))

# ---- admission-baseline (REQ-CHAIN-007-AC19, advisor ruling B, Oct 12): the baseline admission chose, as a file of Build's own record ----------------------
# chain-verify.py admission-baseline --admission A.json --admission B.json --tag T --sha S --out F   (run by the assemble job right after both legs are bound)
#   A and B are the admission.json of the two apk legs, already verified by `bind` (each is a product of its leg's record). Exit 0 writes F, canonical
#   (sorted keys, indent 1): exactly {baseline, baseline_version, sha, tag}, taken from the legs, which must agree on those four fields (their evidence
#   fields may differ). Exit 1, first line `refused at build: <cause>: <detail>`: missing (a file), shape (not a JSON object with those fields as strings),
#   disagree (the legs differ), tag (not --tag), sha (not --sha), baseline (version not vX.Y.Z, or path not requirements/releases/<version>.yaml),
#   count (not exactly two --admission). Nothing is written on a refusal. Exit 2: a missing option.
ADM = {"tag": "v0.3.1", "sha": "c" * 40, "baseline_version": "v0.3.0", "baseline": "requirements/releases/v0.3.0.yaml",
       "required_checks": [{"context": "ci", "id": 11}], "informational_statuses": [], "run": {"id": 1, "attempt": 1}}
def adm_tree(name, a=None, b=None):
    d = "%s/%s" % (work, name)
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    json.dump(a if a is not None else ADM, open(d + "/a.json", "w"))
    json.dump(b if b is not None else dict(ADM, required_checks=[{"context": "ci", "id": 99}], run={"id": 2, "attempt": 1}), open(d + "/b.json", "w"))
    return d
def adm(label, d, want_rc, cause=None, tag="v0.3.1", sha="c" * 40, extra=None, files=("a.json", "b.json")):
    args = ["admission-baseline"] + [x for f in files for x in ("--admission", f)] + ["--tag", tag, "--sha", sha, "--out", "out.json"] + (extra or [])
    if os.path.exists(d + "/out.json"):
        os.remove(d + "/out.json")
    rc, out, err = run(args, d)
    first = err.split("\n", 1)[0]
    ok = rc == want_rc and "Traceback" not in err
    if want_rc == 1:
        ok = ok and first.startswith("refused at build: %s: " % cause) and not os.path.exists(d + "/out.json")
    if want_rc == 0:
        ok = ok and os.path.exists(d + "/out.json")
    check(label, ok, "exit %s, first line %r" % (rc, first[:160]))
d = adm_tree("adm1")
adm("admission-baseline: two legs that agree make the baseline file", d, 0)
want = {"baseline": "requirements/releases/v0.3.0.yaml", "baseline_version": "v0.3.0", "sha": "c" * 40, "tag": "v0.3.1"}
check("admission-baseline: the file holds exactly tag, sha, baseline_version and baseline, canonical (the evidence fields stay out)",
      os.path.exists(d + "/out.json") and json.load(open(d + "/out.json")) == want and open(d + "/out.json").read() == json.dumps(want, sort_keys=True, indent=1) + "\n")
adm("admission-baseline: an owner-signed tag's own baseline (version = tag) is accepted", adm_tree("adm2", dict(ADM, tag="v0.3.0", baseline_version="v0.3.0"), dict(ADM, tag="v0.3.0", baseline_version="v0.3.0")), 0, tag="v0.3.0")
adm("admission-baseline: a leg that is missing is refused", adm_tree("adm3"), 1, "missing", files=("a.json", "nope.json"))
adm("admission-baseline: one leg only is refused (count)", adm_tree("adm4"), 1, "count", files=("a.json",))
adm("admission-baseline: three legs are refused (count)", adm_tree("adm5"), 1, "count", files=("a.json", "b.json", "a.json"))
d = adm_tree("adm6"); open(d + "/b.json", "w").write("{not json")
adm("admission-baseline: a leg that is not JSON is refused (shape)", d, 1, "shape")
adm("admission-baseline: a leg that is a list is refused (shape)", adm_tree("adm7", None, []), 1, "shape")
adm("admission-baseline: a leg without baseline_version is refused (shape)", adm_tree("adm8", None, {k: v for k, v in ADM.items() if k != "baseline_version"}), 1, "shape")
adm("admission-baseline: a leg whose baseline_version is not a string is refused (shape)", adm_tree("adm9", None, dict(ADM, baseline_version=3)), 1, "shape")
adm("admission-baseline: legs that name different baselines are refused (disagree)", adm_tree("adm10", None, dict(ADM, baseline_version="v0.2.0", baseline="requirements/releases/v0.2.0.yaml")), 1, "disagree")
adm("admission-baseline: legs for different commits are refused (disagree)", adm_tree("adm11", None, dict(ADM, sha="d" * 40)), 1, "disagree")
adm("admission-baseline: a leg for another tag than the run's is refused (tag)", adm_tree("adm12"), 1, "tag", tag="v0.3.2")
adm("admission-baseline: a leg for another commit than the run's is refused (sha)", adm_tree("adm13"), 1, "sha", sha="e" * 40)
for label, ver, path in (("a version that is not vX.Y.Z", "0.3.0", "requirements/releases/0.3.0.yaml"), ("a version with a path in it", "../v0.3.0", "requirements/releases/../v0.3.0.yaml"),
                         ("a release candidate version", "v0.3.0-rc1", "requirements/releases/v0.3.0-rc1.yaml"), ("a path that is not the version's file", "v0.3.0", "requirements/releases/v0.2.0.yaml"),
                         ("an absolute path", "v0.3.0", "/etc/passwd")):
    adm("admission-baseline: %s is refused (baseline)" % label, adm_tree("adm14", dict(ADM, baseline_version=ver, baseline=path), dict(ADM, baseline_version=ver, baseline=path)), 1, "baseline")
# Codex 4b-2 r1 (A B1): a release candidate tag is admitted with its OWN baseline (version = tag, rc spelling) and the transfer must accept exactly that
RCA = dict(ADM, tag="v0.3.0-rc1", baseline_version="v0.3.0-rc1", baseline="requirements/releases/v0.3.0-rc1.yaml")
adm("admission-baseline: a release candidate tag's own baseline (version = the rc tag) is accepted", adm_tree("adm20", RCA, dict(RCA, run={"id": 2, "attempt": 1})), 0, tag="v0.3.0-rc1")
adm("admission-baseline: a release candidate tag with a baseline that is not its own (v0.3.0) is refused (baseline)", adm_tree("adm21", dict(RCA, baseline_version="v0.3.0", baseline="requirements/releases/v0.3.0.yaml"), dict(RCA, baseline_version="v0.3.0", baseline="requirements/releases/v0.3.0.yaml")), 1, "baseline", tag="v0.3.0-rc1")
adm("admission-baseline: a release candidate tag with another rc's baseline (v0.3.0-rc2) is refused (baseline)", adm_tree("adm22", dict(RCA, baseline_version="v0.3.0-rc2", baseline="requirements/releases/v0.3.0-rc2.yaml"), dict(RCA, baseline_version="v0.3.0-rc2", baseline="requirements/releases/v0.3.0-rc2.yaml")), 1, "baseline", tag="v0.3.0-rc1")
adm("admission-baseline: a final tag with a release candidate baseline stays refused (baseline)", adm_tree("adm23", dict(ADM, tag="v0.3.0", baseline_version="v0.3.0-rc1", baseline="requirements/releases/v0.3.0-rc1.yaml"), dict(ADM, tag="v0.3.0", baseline_version="v0.3.0-rc1", baseline="requirements/releases/v0.3.0-rc1.yaml")), 1, "baseline", tag="v0.3.0")
for label, ver in (("v0.3.0-rc", "v0.3.0-rc"), ("v0.3.0-RC1", "v0.3.0-RC1"), ("v0.3.0-rc.1", "v0.3.0-rc.1")):
    adm("admission-baseline: the malformed candidate spelling %s is refused (baseline)" % label, adm_tree("adm24", dict(RCA, tag=ver, baseline_version=ver, baseline="requirements/releases/%s.yaml" % ver), dict(RCA, tag=ver, baseline_version=ver, baseline="requirements/releases/%s.yaml" % ver)), 1, "baseline", tag=ver)
rc, out, err = run(["admission-baseline", "--admission", "a.json", "--admission", "b.json", "--tag", "v0.3.1", "--out", "out.json"], adm_tree("adm15"))
check("admission-baseline: a missing --sha is a usage error (exit 2)", rc == 2 and "Traceback" not in err, "exit %s" % rc)
# ---- bind --local (the Witness move: a Build/Rebuild record made with a throwaway key, untrusted until Sign) ---------------------------------------------
def local_record(path, subjects, name="apk"):
    """The throwaway-key form Witness 0.12.0 writes with a file key: signatures [{keyid, sig}], no certificate (pipeline-cc's probe)."""
    record(path, subjects, name)
    env = json.load(open(path))
    env["signatures"] = [{"keyid": "ab" * 32, "sig": base64.b64encode(b"x" * 64).decode()}]
    json.dump(env, open(path, "w"))


d = tree("loc1")
local_record(d + "/apk-collection.local.json", good_subjects())
bind("bind --local: a throwaway-key record named *.local.json binds the files as without --local", d, 0, flags=["--local"], record="apk-collection.local.json")
d = tree("loc2")
local_record(d + "/rapk-collection.local.json", good_subjects(), "rapk")
bind("bind --local: the Rebuild step (rapk) accepts its own local record", d, 0, flags=["--local"], step="rapk", record="rapk-collection.local.json")
d = tree("loc3")
local_record(d + "/apk-collection.local.json", good_subjects(), "rapk")
bind("bind --local: a rapk local record given to the apk step is refused as another step", d, 1, "step", ["rapk"], flags=["--local"], record="apk-collection.local.json")
d = tree("loc4")
local_record(d + "/apk-collection.local.json", good_subjects())
open(d + "/dir/" + "x86_64/fscache-0.3.0-r0.apk", "ab").write(b"!")
bind("bind --local: a changed file is refused by digest exactly as without --local", d, 1, "digest", [APK], flags=["--local"], record="apk-collection.local.json")
d = tree("loc5")
local_record(d + "/apk-collection.local.json", good_subjects())
bind("bind WITHOUT --local: a record named *.local.json is refused (an unsigned local record is not a trusted record)", d, 1, "record", None, record="apk-collection.local.json")
d = tree("loc6")
local_record(d + "/rec.json", good_subjects())
bind("bind --local: a record whose name does not end in .local.json is refused (a signed record cannot pass as a local one)", d, 1, "record", None, flags=["--local"])
d = tree("loc7")
local_record(d + "/apk-collection.local.json", good_subjects())
j = json.load(open(d + "/apk-collection.local.json")); j["payload"] = base64.b64encode(json.dumps({"_type": "https://in-toto.io/Statement/v0.1", "predicateType": "https://slsa.dev/provenance/v1", "subject": [], "predicate": {}}).encode()).decode(); json.dump(j, open(d + "/apk-collection.local.json", "w"))
bind("bind --local: a *.local.json whose payload is not a Witness collection (a provenance statement) is refused", d, 1, "record", None, flags=["--local"], record="apk-collection.local.json")
d = tree("loc8")
open(d + "/apk-collection.local.json", "w").write("not json at all")
rc, out, err = run(["bind", "--local", "--step", "apk", "--record", "apk-collection.local.json", "--dir", "dir", "--as", "out"], d)
check("bind --local: a *.local.json that is not JSON is a usage error, never a pass", rc == 2 and "Traceback" not in err, "exit %s" % rc)
# ---- sign-records (the Witness move: Sign checks the building jobs' local records, then re-signs the payloads keyless) ------------------------------------------
import re as _re
TAGSHA = "f" * 40
ATT = ["environment", "git", "material", "command-run", "product"]      # the five kinds pinned Witness 0.12.0 `run` writes, in its order
GOODENV = {"GITHUB_REF": "refs/tags/v0.3.0", "GITHUB_EVENT_NAME": "push", "GITHUB_SHA": TAGSHA}


def run_env(args, cwd, env):
    if not os.path.exists(CV):
        return 127, "", "bin/chain-verify.py does not exist (RED)"
    e = {"PATH": os.environ["PATH"], "HOME": work}
    e.update(env)
    p = subprocess.run([sys.executable, CV] + args, capture_output=True, text=True, cwd=cwd, timeout=120, env=e)
    return p.returncode, p.stdout, p.stderr


SR_REF = "refs/tags/v0.3.0"        # the ref the environment attestor of a made record carries (Sign's own, unless a case sets another)


def coll_record(path, name, products, material=(), commit=TAGSHA, attestors=ATT, ptype="application/vnd.in-toto+json", env_vars=None, signed=False, ref=None, stdout="built\n", env_raw=None):
    """A Witness collection, the throwaway-key form: {payloadType, payload, signatures:[{keyid,sig}]}; products {relative name: bytes}."""
    ref = ref or SR_REF
    subs = [subject(n, d) for n, d in products.items()] + [subject(n, d, MATERIAL) for n, d in material]
    if commit:
        subs.append({"name": "https://witness.dev/attestations/git/v0.1/commithash:" + commit, "digest": {"gitoid:sha1": "gitoid:commit:sha1:" + commit}})
    def attestation(k):
        if k == "environment":
            if env_raw is not None:      # variables that are not an object (a list or a string): the check must refuse, never fail with a traceback
                return {"variables": env_raw}
            return {"variables": dict({"GITHUB_REF": ref}, **(env_vars or {}))}
        if k == "command-run":      # the real shape (pinned Witness 0.12.0): the command, its whole output and its exit code
            return {"cmd": ["bash", "bin/build-stage.sh"], "stdout": stdout, "stderr": "", "exitcode": 0}
        return {}
    atts = [dict({"type": "https://witness.dev/attestations/%s/v0.1" % k, "attestation": attestation(k)}, **({"starttime": "2026-10-31T00:00:00Z", "endtime": "2026-10-31T00:00:01Z"} if k == "command-run" else {})) for k in attestors]
    statement = {"_type": "https://in-toto.io/Statement/v0.1", "predicateType": "https://witness.testifysec.com/attestation-collection/v0.1",
                 "subject": subs, "predicate": {"name": name, "attestations": atts}}
    payload = json.dumps(statement).encode()
    json.dump({"payloadType": ptype, "payload": base64.b64encode(payload).decode(), "signatures": [{"keyid": "ab" * 32, "sig": base64.b64encode(b"x" * 64).decode()}]}, open(path, "w"))
    return payload


BUILD_DATA = {"digests.json": b'{"apk":"sha256:' + b"c" * 64 + b'"}', "items.json": b'{"items":1}', "admission-baseline.json": b'{"baseline":"v0.3.0"}'}
BUILD_ART = {"dist/fscache_0.3.0_linux_amd64.tar.gz": b"archive-bytes", "out/production/index.json": b"{}"}   # Sign downloads Build's images to artifacts/witness-build/out and dist to artifacts/witness-build/dist (stage-sign.yml)


CHECK_PRODS = {"scanners": {"govulncheck.json": b'{"vulns":[]}', "grype/production.json": b"grype-out"}, "acceptance": {"acceptance.json": b'{"ok":true}'},
               "runtime": {"runtime/summary.txt": b"strace summary"}, "arm64": {"arm64.json": b'{"arch":"arm64"}'}}


def put(root, rel, data):
    os.makedirs(os.path.dirname(os.path.join(root, rel)), exist_ok=True)
    open(os.path.join(root, rel), "wb").write(data)


def sr_tree(name, stage="build"):
    """A Sign job's working tree: record dirs, received artifacts, Build's digests.json. Returns (root, payloads by dir)."""
    root = "%s/%s" % (work, name)
    shutil.rmtree(root, ignore_errors=True)
    os.makedirs(root)
    put(root, "digests.json", BUILD_DATA["digests.json"])
    pays = {}
    if stage == "build":
        prods = dict(BUILD_DATA); prods.update(BUILD_ART); prods["admission.json"] = b"not an artifact: a product Sign never receives"
        pays["witness-build"] = coll_record(root + "/witness-build.rec", "build", prods)
        os.makedirs(root + "/witness-build"); os.rename(root + "/witness-build.rec", root + "/witness-build/build-collection.local.json")
        for n, d in BUILD_DATA.items():
            put(root, "witness-build/" + n, d)
        for n, d in BUILD_ART.items():
            put(root, "artifacts/witness-build/" + n, d)
        os.makedirs(root + "/witness-apk-ubuntu-24.04")
        pays["witness-apk-ubuntu-24.04"] = coll_record(root + "/witness-apk-ubuntu-24.04/apk-collection.local.json", "apk", {"out/x86_64/fscache-0.3.0-r0.apk": b"apk-x", "out/x86_64/APKINDEX.tar.gz": b"idx", "admission.json": b"{}"})
        put(root, "artifacts/witness-apk-ubuntu-24.04/out/x86_64/fscache-0.3.0-r0.apk", b"apk-x"); put(root, "artifacts/witness-apk-ubuntu-24.04/out/x86_64/APKINDEX.tar.gz", b"idx")
    elif stage == "check":
        mat = [("witness-build/digests.json", BUILD_DATA["digests.json"])]
        for folder, step, prods, art in (("witness-scanners", "scanners", CHECK_PRODS["scanners"], "check-results"), ("witness-acceptance", "acceptance", CHECK_PRODS["acceptance"], "check-results"),
                                         ("witness-runtime", "runtime", CHECK_PRODS["runtime"], "check-results"), ("witness-arm64", "arm64", CHECK_PRODS["arm64"], "check-results-arm64")):
            os.makedirs(root + "/" + folder)
            pays[folder] = coll_record(root + "/" + folder + "/" + step + "-collection.local.json", step, {"check-results/" + n: d for n, d in prods.items()}, mat)
            for n, d in prods.items():
                put(root, "artifacts/" + art + "/" + n, d)
    else:
        mat = [("witness-build/digests.json", BUILD_DATA["digests.json"])]
        os.makedirs(root + "/witness-rebuild"); os.makedirs(root + "/witness-rapk-ubuntu-24.04")
        pays["witness-rebuild"] = coll_record(root + "/witness-rebuild/rebuild-collection.local.json", "rebuild", {"witness-rebuild/verdict.json": b'{"verdict":"pass"}'}, mat)
        put(root, "witness-rebuild/verdict.json", b'{"verdict":"pass"}')
        pays["witness-rapk-ubuntu-24.04"] = coll_record(root + "/witness-rapk-ubuntu-24.04/rapk-collection.local.json", "rapk", {"out/x86_64/fscache-0.3.0-r0.apk": b"apk-x", "admission.json": b"{}"}, mat)
    return root, pays


def sr_expect(tree, name="expected-records.json"):
    """The Rebuild assemble job's list of its records, made by the REAL bin/rebuild-records-digests.sh from the tree as it is now (its rec-rapk/<runner> folders are the
    witness-rapk-<runner> folders Sign receives). Returns the file's name."""
    rr = tree + "/rec-rapk-listing"
    shutil.rmtree(rr, ignore_errors=True)
    legs = sorted(x[len("witness-rapk-"):] for x in os.listdir(tree) if x.startswith("witness-rapk-"))
    for leg in legs:
        shutil.copytree(tree + "/witness-rapk-" + leg, rr + "/" + leg)
    out = subprocess.run(["bash", REPO_ROOT + "/bin/rebuild-records-digests.sh", tree + "/witness-rebuild"] + [rr + "/" + leg for leg in legs], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    open(tree + "/" + name, "w").write(out.stdout)
    return name


def sr_expect_check(root, groups=(("check-records.json", ("witness-scanners", "witness-acceptance", "witness-runtime")), ("check-records-arm64.json", ("witness-arm64",)))):
    """Check's two lists as the producing jobs print them: {folder: {file: sha256:hex}} for the folders of each job (the checkout of the tree as it is now). Returns the file names."""
    names = []
    for fname, folders in groups:
        lst = {f: {n: "sha256:" + hashlib.sha256(open(root + "/" + f + "/" + n, "rb").read()).hexdigest() for n in os.listdir(root + "/" + f)} for f in folders if os.path.isdir(root + "/" + f)}
        open(root + "/" + fname, "w").write(json.dumps(lst, sort_keys=True))
        names.append(fname)
    return names


def sr_args(stage, root, dirs=None, out="staged", artifacts=True, expect=True):
    dirs = dirs or (["witness-build", "witness-apk-ubuntu-24.04"] if stage == "build" else ["witness-scanners", "witness-acceptance", "witness-runtime", "witness-arm64"] if stage == "check" else ["witness-rapk-ubuntu-24.04", "witness-rebuild"])
    a = ["sign-records", "--stage", stage, "--template", REPO_TEMPLATE, "--digests", "digests.json", "--out", out]
    if stage == "rebuild" and expect:
        a += ["--expect-digests", expect if isinstance(expect, str) else sr_expect(root)]
    if stage == "check" and expect:
        for x in (expect if isinstance(expect, list) else sr_expect_check(root)):
            a += ["--expect-digests", x]
    if artifacts and stage in ("build", "check"):
        a += ["--artifacts-dir", "artifacts"]
    elif artifacts and os.path.isdir(root + "/artifacts"):
        a += ["--artifacts-dir", "artifacts"]
    for x in dirs:
        a += ["--record-dir", x]
    return a


REPO_ROOT = root
REPO_TEMPLATE = root + "/.github/policy/release-policy.template.json"


def make_keys_dir():
    """A key manifest made here (handoff 0713): an offline root key and a release key from openssl, the manifest signed by the root key. The
    committed manifest does not exist yet (the owner makes the root key), and sign-records checks one before it reads a record."""
    d = work + "/keys"
    os.makedirs(d)
    def ssl(*a, **kw):
        return subprocess.run(("openssl",) + a, check=True, capture_output=True, **kw).stdout
    for n in ("root", "rel"):
        ssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", "%s/%s.key" % (d, n))
        ssl("pkey", "-in", "%s/%s.key" % (d, n), "-pubout", "-out", "%s/%s.pub" % (d, n))
    der = ssl("pkey", "-pubin", "-in", d + "/rel.pub", "-outform", "DER")
    body = json.dumps({"public_key": open(d + "/rel.pub").read(), "key_id": hashlib.sha256(der).hexdigest(), "valid_from": "2026-01-01T00:00:00Z"}, sort_keys=True, indent=1).encode() + b"\n"
    open(d + "/release-key-manifest.json", "wb").write(body)
    sig = ssl("dgst", "-sha256", "-sign", d + "/root.key", d + "/release-key-manifest.json")
    open(d + "/release-key-manifest.sig", "w").write(base64.b64encode(sig).decode() + "\n")
    shutil.copy(d + "/root.pub", d + "/release-key-root.pub")
    return d


KEYS_DIR = make_keys_dir()
for _f in ("release-policy.template.json", "sigstore-trust.json", "rekor.pub"):      # the key files sit beside the template: no flag points elsewhere
    shutil.copy(root + "/.github/policy/" + _f, KEYS_DIR + "/" + _f)
REPO_TEMPLATE = KEYS_DIR + "/release-policy.template.json"


def sr(label, root, stage, want_rc, words=(), env=None, args=None, at=None):
    rc, out, err = run_env(args or sr_args(stage, root), root, dict(GOODENV, **(env or {})))
    first = err.split("\n", 1)[0].lower()
    ok = rc == want_rc and "Traceback" not in err
    if want_rc == 1:
        ok = ok and first.startswith("refused at %s: " % (at or stage)) and all(w.lower() in first for w in words) and not os.path.exists(root + "/staged")
    check(label, ok, "exit %s, first line %r, stdout %r" % (rc, first[:200], out[:80]))
    return rc, out, err


d, pays = sr_tree("sr1")
rc, out, err = sr("sign-records build: a valid set (Build's record and one apk leg) is accepted", d, "build", 0)
lines = [l.split("\t") for l in out.strip().split("\n") if l]
check("sign-records build: one `payload<TAB>final` line per record, the final name is signed/<dir>/<step>-collection.json",
      sorted(lines) == sorted([["staged/witness-build/build-collection.payload", "signed/witness-build/build-collection.json"],
                               ["staged/witness-apk-ubuntu-24.04/apk-collection.payload", "signed/witness-apk-ubuntu-24.04/apk-collection.json"]]), repr(lines))
check("sign-records build: OUT/plan.txt is the printed list, line for line (the signing step signs exactly it)", rc == 0 and open(d + "/staged/plan.txt").read() == out.strip("\n") + "\n")
check("sign-records build: the staged payload is the record's payload byte for byte", rc == 0 and open(d + "/staged/witness-build/build-collection.payload", "rb").read() == pays["witness-build"])
check("sign-records build: the data files are copied unchanged and no *.local.json is staged",
      rc == 0 and all(open(d + "/staged/witness-build/" + n, "rb").read() == v for n, v in BUILD_DATA.items())
      and not [f for r, _, fs in os.walk(d + "/staged") for f in fs if f.endswith(".local.json")])
d, _ = sr_tree("sr2"); put(d, "artifacts/witness-build/dist/fscache_0.3.0_linux_amd64.tar.gz", b"changed-after-the-record")
sr("sign-records build: a received file whose bytes differ from the record's product is refused", d, "build", 1, ["dist/fscache_0.3.0_linux_amd64.tar.gz"])
d, _ = sr_tree("sr3"); put(d, "artifacts/witness-build/dist/extra.txt", b"x")
sr("sign-records build: a received file the record does not name is refused", d, "build", 1, ["dist/extra.txt"])
d, _ = sr_tree("sr4"); os.remove(d + "/witness-build/items.json")
sr("sign-records build: a required name the record holds but Sign did not receive (items.json) is refused", d, "build", 1, ["items.json"])
d, _ = sr_tree("sr5"); put(d, "witness-build/digests.json", b'{"apk":"sha256:' + b"d" * 64 + b'"}')
sr("sign-records build: a data file whose bytes differ from the record's product is refused", d, "build", 1, ["digests.json"])
for _st, _label in (("build", "Build"), ("rebuild", "Rebuild"), ("check", "Check")):
    d, _ = sr_tree("sr6-" + _st, _st)
    sr("sign-records %s: a real-shaped record (environment, git, material, command-run, product, as Witness 0.12.0 writes it) is accepted" % _st, d, _st, 0)
d, _ = sr_tree("sr6a"); coll_record(d + "/witness-build/build-collection.local.json", "build", dict(BUILD_DATA, **BUILD_ART), attestors=["environment", "git", "material", "product"])
sr("sign-records build: a record without command-run is refused (every record comes from `witness run -- command`; the attestors are exactly the five)", d, "build", 1, ["command-run"])
d, _ = sr_tree("sr6c"); coll_record(d + "/witness-build/build-collection.local.json", "build", dict(BUILD_DATA, **BUILD_ART), attestors=ATT + ["command-run"])
sr("sign-records build: command-run twice is refused (a repeated attestor)", d, "build", 1, ["repeated"])
for _extra in ("github", "slsa"):
    d, _ = sr_tree("sr6-" + _extra); coll_record(d + "/witness-build/build-collection.local.json", "build", dict(BUILD_DATA, **BUILD_ART), attestors=ATT + [_extra])
    sr("sign-records build: an added %s attestor is refused" % _extra, d, "build", 1, [_extra])
d, _ = sr_tree("sr6b"); coll_record(d + "/witness-build/build-collection.local.json", "build", dict(BUILD_DATA, **BUILD_ART), attestors=["environment", "git", "command-run", "product"])
sr("sign-records build: a record without the material attestor is refused (the attestors are exactly the five)", d, "build", 1, ["material"])
d, _ = sr_tree("sr6d"); coll_record(d + "/witness-build/build-collection.local.json", "build", dict(BUILD_DATA, **BUILD_ART), stdout="log line\nGITHUB_TOKEN=ghp_" + "a" * 36 + "\n")
sr("sign-records build: a GitHub token printed in command-run's stdout is refused (the record scan covers the new attestor)", d, "build", 1, ["env"])
# the REAL records: made by the pinned Witness 0.12.0 through bin/witnessed-local.sh (steps build and apk, one commit, GITHUB_REF refs/tags/v0.3.0, a clean
# environment), committed under test-evidence/witness-real/; their products are the bytes of the fixture tree (BUILD_DATA, BUILD_ART, the apk leg)
REAL_SHA = "5a3e9d23730aaa052794e767258134daba956e54"
def write_real(step, dest):
    """Rebuild the DSSE envelope of a committed real record (test-evidence/witness-real/<step>-collection.real.txt: header lines, then the base64 payload wrapped)."""
    fields, payload, in_payload = {}, [], False
    for line in open(REPO_ROOT + "/test-evidence/witness-real/%s-collection.real.txt" % step).read().split("\n"):
        if line.startswith("#") or not line:
            continue
        if line == "payload:":
            in_payload = True
        elif in_payload:
            payload.append(line)
        else:
            key, _, value = line.partition(": ")
            fields[key] = value
    json.dump({"payload": "".join(payload), "payloadType": fields["payloadType"], "signatures": [{"keyid": fields["keyid"], "sig": fields["sig"]}]}, open(dest, "w"))


def real_tree(name):
    d, _ = sr_tree(name)
    write_real("build", d + "/witness-build/build-collection.local.json")
    write_real("apk", d + "/witness-apk-ubuntu-24.04/apk-collection.local.json")
    return d
d = real_tree("srreal1")
sr("sign-records build: the records the pinned Witness really writes (environment, git, material, command-run, product) are accepted", d, "build", 0, env={"GITHUB_SHA": REAL_SHA})
d = real_tree("srreal2")
sr("sign-records build: the same real records at another tag (GITHUB_REF refs/tags/v0.3.1) are refused by the ref in their environment attestor", d, "build", 1, ["ref"], env={"GITHUB_SHA": REAL_SHA, "GITHUB_REF": "refs/tags/v0.3.1"})
d = real_tree("srreal3")
sr("sign-records build: the same real records at another commit than Sign's are refused", d, "build", 1, ["commit"], env={"GITHUB_SHA": "e" * 40})
d, _ = sr_tree("sr7"); coll_record(d + "/witness-build/build-collection.local.json", "build", dict(BUILD_DATA, **BUILD_ART), env_vars={"GITHUB_TOKEN": "x"})
sr("sign-records build: a record that names a token variable is refused (record-env)", d, "build", 1, ["env", "GITHUB_TOKEN"])
d, _ = sr_tree("sr7l"); coll_record(d + "/witness-build/build-collection.local.json", "build", dict(BUILD_DATA, **BUILD_ART), env_raw=["GITHUB_REF=refs/tags/v0.3.0"])
sr("sign-records build: environment variables that are a list are refused (no traceback)", d, "build", 1, ["ref"])
d, _ = sr_tree("sr7s"); coll_record(d + "/witness-build/build-collection.local.json", "build", dict(BUILD_DATA, **BUILD_ART), env_raw="GITHUB_REF=refs/tags/v0.3.0")
sr("sign-records build: environment variables that are a string are refused (no traceback)", d, "build", 1, ["ref"])
d, _ = sr_tree("sr8"); os.rename(d + "/witness-apk-ubuntu-24.04/apk-collection.local.json", d + "/witness-apk-ubuntu-24.04/snapshot-apk-collection.local.json")
sr("sign-records build: a snapshot step file name is refused", d, "build", 1, ["snapshot"])
d, _ = sr_tree("sr9"); coll_record(d + "/witness-apk-ubuntu-24.04/apk-collection.local.json", "build", {"out/x86_64/fscache-0.3.0-r0.apk": b"apk-x", "out/x86_64/APKINDEX.tar.gz": b"idx"})
sr("sign-records build: a record whose collection name is not the file's step is refused", d, "build", 1, ["step"])
d, _ = sr_tree("sr10"); coll_record(d + "/witness-apk-ubuntu-24.04/apk-collection.local.json", "snapshot-apk", {"out/x86_64/fscache-0.3.0-r0.apk": b"apk-x", "out/x86_64/APKINDEX.tar.gz": b"idx"})
sr("sign-records build: a snapshot collection name is refused", d, "build", 1, ["snapshot"])
d, _ = sr_tree("sr11")
sr("sign-records build: a git commit that is not the run's commit is refused", d, "build", 1, ["commit"], env={"GITHUB_SHA": "e" * 40})
d, _ = sr_tree("sr12"); coll_record(d + "/witness-build/build-collection.local.json", "build", dict(BUILD_DATA, **BUILD_ART), commit=None)
sr("sign-records build: a record with no git commit subject is refused", d, "build", 1, ["commit"])
d, _ = sr_tree("sr13"); put(d, "witness-build/build-collection.json", b"{}")
sr("sign-records build: a signed-looking record file beside the local one is refused (only <step>-collection.local.json)", d, "build", 1, ["build-collection.json"])
d, _ = sr_tree("sr14"); put(d, "witness-build/notes.txt", b"x")
sr("sign-records build: a file in a record directory that is neither the record nor a known data file is refused", d, "build", 1, ["notes.txt"])
d, _ = sr_tree("sr15"); shutil.copy(d + "/witness-build/build-collection.local.json", d + "/witness-build/apk-collection.local.json")
sr("sign-records build: two records in one directory are refused", d, "build", 1, ["one"])
d, _ = sr_tree("sr16"); coll_record(d + "/witness-build/build-collection.local.json", "build", dict(BUILD_DATA, **BUILD_ART), ptype="text/plain")
sr("sign-records build: a payloadType other than application/vnd.in-toto+json is refused", d, "build", 1, ["payloadtype"])
d, _ = sr_tree("sr17"); os.symlink("/etc/passwd", d + "/artifacts/witness-build/link")
sr("sign-records build: a symlink among the received files is refused", d, "build", 1, ["symlink"])
d, _ = sr_tree("sr18"); os.makedirs(d + "/staged")
rc, out, err = run_env(sr_args("build", d), d, GOODENV)
check("sign-records: an existing --out is a usage error (exit 2), nothing overwritten", rc == 2 and "Traceback" not in err and os.listdir(d + "/staged") == [], "exit %s" % rc)
d, _ = sr_tree("sr19")
sr("sign-records: GITHUB_REF that is neither a pushed tag nor a dispatch on a branch is refused", d, "build", 1, ["github_ref"], env={"GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "push"}, at="sign")
SR_REF = "refs/heads/dry"
d, _ = sr_tree("sr20")
SR_REF = "refs/tags/v0.3.0"
sr("sign-records: a dry run (workflow_dispatch on a branch) is accepted", d, "build", 0, env={"GITHUB_REF": "refs/heads/dry", "GITHUB_EVENT_NAME": "workflow_dispatch"})
for _lab, _r in (("the rc tag", "refs/tags/v0.3.0-rc1"), ("another tag", "refs/tags/v0.3.1"), ("a branch", "refs/heads/v0.3.0")):
    SR_REF = _r
    d, _ = sr_tree("sr20x")
    SR_REF = "refs/tags/v0.3.0"
    sr("sign-records: a record made at %s is refused at Sign's tag (the KMS key never signs a collection of another ref)" % _lab, d, "build", 1, ["ref"])
d, _ = sr_tree("sr21", "rebuild")
rc, out, err = sr("sign-records rebuild: a valid set (Rebuild's record and one rapk leg) is accepted without Rebuild's apks or images", d, "rebuild", 0)
check("sign-records rebuild: the final names are rebuild-collection.json and rapk-collection.json", rc == 0 and sorted(l.split("\t")[1] for l in out.strip().split("\n")) == ["signed/witness-rapk-ubuntu-24.04/rapk-collection.json", "signed/witness-rebuild/rebuild-collection.json"], out)
d, _ = sr_tree("sr21b", "rebuild"); shutil.rmtree(d + "/artifacts", ignore_errors=True)
sr("sign-records rebuild: without --artifacts-dir the data files of the record directories are the received files (sign-rebuild passes none)", d, "rebuild", 0, args=sr_args("rebuild", d, artifacts=False))
d, _ = sr_tree("sr22", "rebuild"); put(d, "witness-rebuild/verdict.json", b'{"verdict":"fail"}')
sr("sign-records rebuild: a verdict.json whose bytes differ from the record's product is refused", d, "rebuild", 1, ["verdict.json"])
d, _ = sr_tree("sr23", "rebuild"); put(d, "digests.json", b'{"apk":"sha256:' + b"9" * 64 + b'"}')
sr("sign-records rebuild: a record whose material digests.json is not Build's attested list (--digests) is refused", d, "rebuild", 1, ["material", "digests"])
d, _ = sr_tree("sr24", "rebuild"); os.remove(d + "/witness-rebuild/verdict.json")
sr("sign-records rebuild: Rebuild's record without the verdict.json it names is refused", d, "rebuild", 1, ["verdict.json"])
# the Rebuild job's list of the records it made (--expect-digests): Sign's second call refuses any record folder that differs from it (row-78 pass, R2)
d, _ = sr_tree("sr32", "rebuild"); ex = sr_expect(d)
rc, out, err = sr("sign-records rebuild: the folders match the Rebuild job's list (made by the real bin/rebuild-records-digests.sh) -> accepted", d, "rebuild", 0, args=sr_args("rebuild", d, expect=ex))
d, _ = sr_tree("sr33", "rebuild"); ex = sr_expect(d); put(d, "witness-rebuild/verdict.json", b'{"verdict":"swapped after the job listed it"}')
sr("sign-records rebuild: a verdict.json swapped after the Rebuild job listed its records is refused", d, "rebuild", 1, ["expect-digests", "verdict.json"], args=sr_args("rebuild", d, expect=ex))
d, _ = sr_tree("sr34", "rebuild"); ex = sr_expect(d); coll_record(d + "/witness-rebuild/rebuild-collection.local.json", "rebuild", {"witness-rebuild/verdict.json": b'{"verdict":"pass"}', "other": b"x"}, [("witness-build/digests.json", BUILD_DATA["digests.json"])])
sr("sign-records rebuild: a rebuild record other than the one the Rebuild job listed (a forged record under the artifact name) is refused", d, "rebuild", 1, ["expect-digests", "rebuild-collection.local.json"], args=sr_args("rebuild", d, expect=ex))
d, _ = sr_tree("sr35", "rebuild"); ex = sr_expect(d); coll_record(d + "/witness-rapk-ubuntu-24.04/rapk-collection.local.json", "rapk", {"out/x86_64/evil.apk": b"evil"}, [("witness-build/digests.json", BUILD_DATA["digests.json"])])
sr("sign-records rebuild: a rapk record other than the one the Rebuild job listed is refused", d, "rebuild", 1, ["expect-digests", "rapk-collection.local.json"], args=sr_args("rebuild", d, expect=ex))
d, _ = sr_tree("sr36", "rebuild"); ex = sr_expect(d); put(d, "witness-rebuild/items.json", b"{}")
sr("sign-records rebuild: an extra file in a record folder is refused", d, "rebuild", 1, ["expect-digests", "items.json"], args=sr_args("rebuild", d, expect=ex))
d, _ = sr_tree("sr37", "rebuild"); ex = sr_expect(d); os.remove(d + "/witness-rebuild/verdict.json")
sr("sign-records rebuild: a file the Rebuild job listed but the folder lacks is refused", d, "rebuild", 1, ["expect-digests", "verdict.json"], args=sr_args("rebuild", d, expect=ex))
d, _ = sr_tree("sr38", "rebuild"); ex = sr_expect(d); shutil.copytree(d + "/witness-rapk-ubuntu-24.04", d + "/witness-rapk-ubuntu-24.04-arm")
sr("sign-records rebuild: an extra record folder the Rebuild job did not list is refused", d, "rebuild", 1, ["expect-digests", "folders"], args=sr_args("rebuild", d, dirs=["witness-rapk-ubuntu-24.04", "witness-rapk-ubuntu-24.04-arm", "witness-rebuild"], expect=ex))
d, _ = sr_tree("sr39", "rebuild"); ex = sr_expect(d)
sr("sign-records rebuild: a folder the Rebuild job listed but Sign was not given is refused", d, "rebuild", 1, ["expect-digests", "folders"], args=sr_args("rebuild", d, dirs=["witness-rebuild"], expect=ex))
d, _ = sr_tree("sr40", "rebuild")
sr("sign-records rebuild: without --expect-digests the rebuild stage is refused", d, "rebuild", 1, ["expect-digests", "required"], args=sr_args("rebuild", d, expect=False))
d, _ = sr_tree("sr41", "rebuild"); open(d + "/bad.json", "w").write("{not json")
sr("sign-records rebuild: a list that is not JSON is refused", d, "rebuild", 1, ["expect-digests"], args=sr_args("rebuild", d, expect="bad.json"))
d, _ = sr_tree("sr42", "rebuild"); open(d + "/bad.json", "w").write('{"witness-rebuild":{"verdict.json":"abc"}}')
sr("sign-records rebuild: a list whose digest is not sha256:<64 hex> is refused", d, "rebuild", 1, ["expect-digests"], args=sr_args("rebuild", d, expect="bad.json"))
# the apk legs' own lists and the assemble job's --check (row-78 round 6, A1): each rapk job prints its folder's list after its Witness step, and the assemble job refuses any record
# folder that changed between that upload and its own start
RRD = REPO_ROOT + "/bin/rebuild-records-digests.sh"
def rrd(args, cwd, env=None):
    e = {"PATH": os.environ["PATH"], "HOME": work}
    e.update(env or {})
    p = subprocess.run(["bash", RRD] + args, capture_output=True, text=True, cwd=cwd, env=e, timeout=60)
    return p.returncode, p.stdout.strip(), p.stderr
def rrd_tree(name):
    t = "%s/%s" % (work, name)
    shutil.rmtree(t, ignore_errors=True)
    for leg, body in (("ubuntu-24.04", b"x86 record"), ("ubuntu-24.04-arm", b"arm record")):
        put(t, "rec-rapk/%s/rapk-collection.local.json" % leg, body)
    put(t, "witness-rebuild/verdict.json", b"{}"); put(t, "witness-rebuild/rebuild-collection.local.json", b"rec")
    outs = {leg: rrd(["--rapk", leg, "rec-rapk/" + leg], t)[1] for leg in ("ubuntu-24.04", "ubuntu-24.04-arm")}
    return t, outs
def rrd_check(t, outs, **kw):
    x = kw["x86"] if "x86" in kw else outs["ubuntu-24.04"]
    a = kw["arm"] if "arm" in kw else outs["ubuntu-24.04-arm"]
    return rrd(["--check", x, a], t)
def rrd_case(label, rc_want, words, res):
    rc, out, err = res
    ok = (rc == 0) if rc_want == 0 else (rc == rc_want and "Traceback" not in err and all(w in err for w in words))
    check(label, ok, "exit %s, stderr %r" % (rc, err[:240]))
t, outs = rrd_tree("rrd1")
whole = json.loads(rrd(["witness-rebuild", "rec-rapk/ubuntu-24.04", "rec-rapk/ubuntu-24.04-arm"], t)[1])
check("rebuild-records-digests --rapk: each leg's list is that folder's entry of the assemble job's whole list (same format)",
      all(json.loads(outs[leg]) == {"witness-rapk-" + leg: whole["witness-rapk-" + leg]} for leg in outs) and list(json.loads(outs["ubuntu-24.04"])) == ["witness-rapk-ubuntu-24.04"], repr(outs))
rrd_case("rebuild-records-digests --check: both legs match the folders -> accepted", 0, (), rrd_check(t, outs))
t, outs = rrd_tree("rrd2"); put(t, "rec-rapk/ubuntu-24.04/rapk-collection.local.json", b"swapped after the upload")
rrd_case("rebuild-records-digests --check: the ubuntu-24.04 record swapped after its upload is refused, naming the leg and the file", 1, ("ubuntu-24.04:", "rapk-collection.local.json"), rrd_check(t, outs))
t, outs = rrd_tree("rrd3"); put(t, "rec-rapk/ubuntu-24.04-arm/rapk-collection.local.json", b"swapped after the upload")
rrd_case("rebuild-records-digests --check: the ubuntu-24.04-arm record swapped after its upload is refused, naming the leg and the file", 1, ("ubuntu-24.04-arm:", "rapk-collection.local.json"), rrd_check(t, outs))
t, outs = rrd_tree("rrd4"); put(t, "rec-rapk/ubuntu-24.04/extra.json", b"x")
rrd_case("rebuild-records-digests --check: an extra file in a leg's folder is refused, naming it", 1, ("ubuntu-24.04:", "extra.json"), rrd_check(t, outs))
t, outs = rrd_tree("rrd5"); os.remove(t + "/rec-rapk/ubuntu-24.04-arm/rapk-collection.local.json")
rrd_case("rebuild-records-digests --check: a leg's folder with no file is refused", 1, ("no file in",), rrd_check(t, outs))
t, outs = rrd_tree("rrd6"); shutil.rmtree(t + "/rec-rapk/ubuntu-24.04")
t, outs = rrd_tree("rrd4b"); put(t, "rec-rapk/ubuntu-24.04/.hidden", b"x")
rrd_case("rebuild-records-digests --check: a hidden extra file in a leg's folder is refused (it is a file of the folder)", 1, ("ubuntu-24.04:", ".hidden"), rrd_check(t, outs))
rrd_case("rebuild-records-digests --rapk lists a hidden file too", 0, (), (lambda r: (0 if ".hidden" in r[1] else 1, r[1], r[2]))(rrd(["--rapk", "ubuntu-24.04", "rec-rapk/ubuntu-24.04"], t)))
t, outs = rrd_tree("rrd5b"); os.remove(t + "/rec-rapk/ubuntu-24.04-arm/rapk-collection.local.json")
rrd_case("rebuild-records-digests --check: an EMPTY leg folder is refused with 'no file in'", 1, ("no file in",), rrd_check(t, outs))
t, outs = rrd_tree("rrd6b"); shutil.rmtree(t + "/rec-rapk/ubuntu-24.04")
rrd_case("rebuild-records-digests --check: a missing leg folder is refused", 1, ("not a plain folder",), rrd_check(t, outs))
t, outs = rrd_tree("rrd7")
rrd_case("rebuild-records-digests --check: an empty job output is refused, naming the leg", 1, ("ubuntu-24.04:", "empty"), rrd_check(t, outs, x86=""))
rrd_case("rebuild-records-digests --check: an empty arm output is refused, naming the leg", 1, ("ubuntu-24.04-arm:", "empty"), rrd_check(t, outs, arm=""))
rrd_case("rebuild-records-digests --check: an output that is not JSON is refused", 1, ("ubuntu-24.04:", "not a JSON object"), rrd_check(t, outs, x86="{not json"))
rrd_case("rebuild-records-digests --check: an output that is JSON but not an object is refused", 1, ("ubuntu-24.04:", "not a JSON object"), rrd_check(t, outs, x86="[]"))
rrd_case("rebuild-records-digests --check: the other runner's output given for this leg (it names the other runner) is refused", 1, ("ubuntu-24.04:", "changed"), rrd_check(t, outs, x86=outs["ubuntu-24.04-arm"]))
rrd_case("rebuild-records-digests --check: the legs' outputs swapped between the two variables are refused", 1, ("changed",), rrd_check(t, outs, x86=outs["ubuntu-24.04-arm"], arm=outs["ubuntu-24.04"]))
rrd_case("rebuild-records-digests --check: an output that names a folder besides the leg's own is refused", 1, ("changed",), rrd_check(t, outs, x86=json.dumps(dict(json.loads(outs["ubuntu-24.04"]), **{"witness-rebuild": {"verdict.json": "sha256:" + "0" * 64}}))))
rrd_case("rebuild-records-digests --check takes exactly the two outputs (one, none or three arguments: exit 2)", 2, ("usage",), rrd(["--check", "x"], t, {}))
rrd_case("rebuild-records-digests --check with no argument at all (exit 2)", 2, ("usage",), rrd(["--check"], t, {}))
rrd_case("rebuild-records-digests --check with a third argument (exit 2)", 2, ("usage",), rrd(["--check", "a", "b", "c"], t, {}))
rrd_case("rebuild-records-digests --check does not read the environment (the old variables alone do not pass)", 2, ("usage",), rrd(["--check"], t, {"RAPK_RECORDS": outs["ubuntu-24.04"], "RAPK_ARM_RECORDS": outs["ubuntu-24.04-arm"]}))
rrd_case("rebuild-records-digests --rapk takes a plain runner name (exit 2)", 2, ("usage",), rrd(["--rapk", "../x", "rec-rapk/ubuntu-24.04"], t, {}))

# Check's records (the Check-stage no-token PR): the four folders, the check-results products matched to the received files, two expect-digests lists
d, pays = sr_tree("ck1", "check")
rc, out, err = sr("sign-records check: a valid set (four records, their results, two lists) is accepted", d, "check", 0)
lines = [l.split("\t") for l in out.strip().split("\n") if l]
check("sign-records check: one `payload<TAB>final` line per record, final names signed/<folder>/<step>-collection.json",
      sorted(l[1] for l in lines) == ["signed/witness-acceptance/acceptance-collection.json", "signed/witness-arm64/arm64-collection.json", "signed/witness-runtime/runtime-collection.json", "signed/witness-scanners/scanners-collection.json"], repr(lines))
check("sign-records check: the staged payloads are the records' payloads byte for byte", rc == 0 and all(open(d + "/staged/%s/%s-collection.payload" % (f, f[len("witness-"):]), "rb").read() == pays[f] for f in pays))
d, _ = sr_tree("ck2", "check"); ex = sr_expect_check(d); put(d, "artifacts/check-results/govulncheck.json", b'{"vulns":["changed after the record"]}')
sr("sign-records check: a result whose bytes differ from the record's product is refused", d, "check", 1, ["check-results/govulncheck.json"], args=sr_args("check", d, expect=ex))
d, _ = sr_tree("ck3", "check"); put(d, "artifacts/check-results/extra.txt", b"x")
sr("sign-records check: a received file no record names is refused", d, "check", 1, ["check-results/extra.txt"])
d, _ = sr_tree("ck4", "check"); os.remove(d + "/artifacts/check-results/acceptance.json")
sr("sign-records check: a check-results product a record names but Sign did not receive is refused", d, "check", 1, ["check-results/acceptance.json"])
d, _ = sr_tree("ck5", "check"); coll_record(d + "/witness-acceptance/acceptance-collection.local.json", "acceptance", {"check-results/govulncheck.json": CHECK_PRODS["scanners"]["govulncheck.json"], "check-results/acceptance.json": CHECK_PRODS["acceptance"]["acceptance.json"]}, [("witness-build/digests.json", BUILD_DATA["digests.json"])])
sr("sign-records check: a product named by two records of the same group is refused", d, "check", 1, ["named twice"])
d, _ = sr_tree("ck6", "check"); put(d, "artifacts/check-results-arm64/arm64.json", b'{"arch":"arm64"}'); put(d, "artifacts/check-results/arm64.json", b'{"arch":"arm64"}')
sr("sign-records check: arm64's result inside the check artifact (not named by the check group's records) is refused", d, "check", 1, ["check-results/arm64.json"])
d, _ = sr_tree("ck7", "check"); shutil.rmtree(d + "/artifacts/check-results-arm64")
sr("sign-records check: a missing check-results-arm64 artifact is refused", d, "check", 1, ["check-results-arm64"])
d, _ = sr_tree("ck8", "check"); os.symlink("/etc/passwd", d + "/artifacts/check-results/link")
sr("sign-records check: a symlink among the received results is refused", d, "check", 1, ["symlink"])
d, _ = sr_tree("ck9", "check"); os.makedirs(d + "/artifacts/check-results/locked"); put(d, "artifacts/check-results/locked/f", b"x"); os.chmod(d + "/artifacts/check-results/locked", 0)
sr("sign-records check: an unreadable results folder is refused, not counted as empty", d, "check", 1, ["unreadable"]); os.chmod(d + "/artifacts/check-results/locked", 0o755)
d, _ = sr_tree("ck10", "check")
sr("sign-records check: without --expect-digests the check stage is refused", d, "check", 1, ["expect-digests", "required"], args=sr_args("check", d, expect=False))
d, _ = sr_tree("ck11", "check"); ex = sr_expect_check(d); put(d, "witness-runtime/runtime-collection.local.json.bak", b"x")
sr("sign-records check: an extra file in a record folder (not on the producing job's list) is refused", d, "check", 1, ["expect-digests"], args=sr_args("check", d, expect=ex))
d, _ = sr_tree("ck12", "check"); ex = sr_expect_check(d); coll_record(d + "/witness-runtime/runtime-collection.local.json", "runtime", {"check-results/runtime/summary.txt": b"forged summary"})
sr("sign-records check: a runtime record swapped after the job listed it is refused", d, "check", 1, ["expect-digests", "runtime-collection.local.json"], args=sr_args("check", d, expect=ex))
d, _ = sr_tree("ck13", "check"); ex = sr_expect_check(d, (("check-records.json", ("witness-scanners", "witness-acceptance", "witness-runtime", "witness-arm64")), ("check-records-arm64.json", ("witness-arm64",))))
sr("sign-records check: the same folder on both lists is refused (the lists must be disjoint)", d, "check", 1, ["expect-digests", "witness-arm64"], args=sr_args("check", d, expect=ex))
d, _ = sr_tree("ck14", "check"); ex = sr_expect_check(d, (("check-records.json", ("witness-scanners", "witness-acceptance")), ("check-records-arm64.json", ("witness-arm64",))))
sr("sign-records check: a record folder on no list (witness-runtime) is refused", d, "check", 1, ["expect-digests", "folders"], args=sr_args("check", d, expect=ex))
d, _ = sr_tree("ck15", "check")
sr("sign-records check: only three of Check's four record folders given is refused", d, "check", 1, ["record", "witness-"], args=sr_args("check", d, dirs=["witness-scanners", "witness-acceptance", "witness-arm64"], expect=sr_expect_check(d, (("check-records.json", ("witness-scanners", "witness-acceptance")), ("check-records-arm64.json", ("witness-arm64",))))))
d, _ = sr_tree("ck16", "check"); os.rename(d + "/witness-runtime/runtime-collection.local.json", d + "/witness-runtime/scanners-collection.local.json")
sr("sign-records check: a scanners record in the runtime folder is refused (the folder names its step)", d, "check", 1, ["step"])
d, _ = sr_tree("ck17", "check"); os.rename(d + "/witness-runtime/runtime-collection.local.json", d + "/witness-runtime/rebuild-collection.local.json")
sr("sign-records check: a Rebuild record (rebuild-collection.local.json) passed off as Check's is refused", d, "check", 1, ["step"])
d, _ = sr_tree("ck18", "check"); os.rename(d + "/witness-runtime/runtime-collection.local.json", d + "/witness-runtime/build-collection.local.json")
sr("sign-records check: a Build record passed off as Check's is refused", d, "check", 1, ["step"])
d, _ = sr_tree("ck19", "check"); coll_record(d + "/witness-scanners/scanners-collection.local.json", "scanners", {"check-results/" + n: dd for n, dd in CHECK_PRODS["scanners"].items()}, [("witness-build/digests.json", b"another list")])
sr("sign-records check: a scanners record whose material is not Build's attested digests.json is refused", d, "check", 1, ["material"])
d, _ = sr_tree("ck20", "check"); coll_record(d + "/witness-acceptance/acceptance-collection.local.json", "acceptance", {"check-results/acceptance.json": CHECK_PRODS["acceptance"]["acceptance.json"]}, env_vars={"GH_TOKEN": "x"})
sr("sign-records check: a Check record that names a token variable is refused (record-env)", d, "check", 1, ["env", "GH_TOKEN"])
d, _ = sr_tree("ck21", "check"); coll_record(d + "/witness-arm64/arm64-collection.local.json", "arm64", {"check-results/arm64.json": CHECK_PRODS["arm64"]["arm64.json"]}, env_vars={"X": "github_pat_" + "A" * 30})
sr("sign-records check: a Check record that holds a github_pat_ token value is refused (record-env)", d, "check", 1, ["env", "token"])
d, _ = sr_tree("ck22", "check"); put(d, "witness-runtime/digests.json", b"{}")
sr("sign-records check: a data file in a Check record folder (digests.json) is refused: the folder holds only its record", d, "check", 1, ["witness-runtime", "digests.json"])
for step_, prods_ in (("acceptance", CHECK_PRODS["acceptance"]), ("runtime", CHECK_PRODS["runtime"]), ("arm64", CHECK_PRODS["arm64"])):
    d, _ = sr_tree("ck23" + step_, "check"); coll_record(d + "/witness-%s/%s-collection.local.json" % (step_, step_), step_, {"check-results/" + n: dd for n, dd in prods_.items()}, [("witness-build/digests.json", b"another list")])
    sr("sign-records check: the %s record's material must be Build's attested digests.json as well (not only scanners)" % step_, d, "check", 1, ["material", step_])
d, _ = sr_tree("ck24", "check"); coll_record(d + "/witness-acceptance/acceptance-collection.local.json", "acceptance", {"check-results/acceptance.json": CHECK_PRODS["acceptance"]["acceptance.json"]})
sr("sign-records check: a Check record with no material at all is refused", d, "check", 1, ["material"])
d, _ = sr_tree("sr25", "rebuild"); coll_record(d + "/witness-rebuild/rebuild-collection.local.json", "rebuild", {"verdict.json": b'{"verdict":"pass"}'}, [("witness-build/digests.json", BUILD_DATA["digests.json"])])
sr("sign-records rebuild: a record that names the verdict by its bare file name is refused (the product is witness-rebuild/verdict.json, matched in full)", d, "rebuild", 1, ["witness-rebuild/verdict.json"])
d, _ = sr_tree("sr26"); os.makedirs(d + "/artifacts/witness-build/dist/locked"); put(d, "artifacts/witness-build/dist/locked/f", b"x"); os.chmod(d + "/artifacts/witness-build/dist/locked", 0)
sr("sign-records build: an unreadable folder among the received files is refused, not counted as empty", d, "build", 1, ["unreadable"]); os.chmod(d + "/artifacts/witness-build/dist/locked", 0o755)
d, _ = sr_tree("sr27"); coll_record(d + "/witness-build/build-collection.local.json", "build", dict(BUILD_DATA, **BUILD_ART), env_vars={"X": "github_pat_" + "A" * 30})
sr("sign-records build: a record that holds a fine-grained github_pat_ token value is refused (record-env)", d, "build", 1, ["env", "token"])
d, _ = sr_tree("sr28"); coll_record(d + "/witness-build/build-collection.local.json", "build", dict(BUILD_DATA, **BUILD_ART, **{"out/never-received.tar": b"z"}))
sr("sign-records build: a Build product under out/ that Sign did not receive is refused", d, "build", 1, ["out/never-received.tar"])
d, _ = sr_tree("sr29", "rebuild"); os.rename(d + "/witness-rebuild/rebuild-collection.local.json", d + "/witness-rebuild/build-collection.local.json")
sr("sign-records rebuild: a Build record (build-collection.local.json) passed off as Rebuild's is refused", d, "rebuild", 1, ["step"])
d, _ = sr_tree("sr30"); os.rename(d + "/witness-build/build-collection.local.json", d + "/witness-build/rebuild-collection.local.json")
sr("sign-records build: a Rebuild record (rebuild-collection.local.json) passed off as Build's is refused", d, "build", 1, ["step"])
d, _ = sr_tree("sr31"); os.rename(d + "/witness-apk-ubuntu-24.04/apk-collection.local.json", d + "/witness-apk-ubuntu-24.04/rapk-collection.local.json")
sr("sign-records build: a rapk record (Rebuild's apk leg) passed off as Build's apk leg is refused", d, "build", 1, ["step"])
d, _ = sr_tree("sr25");
open(d + "/own-list.json", "w").write(json.dumps({x: {f: "sha256:" + hashlib.sha256(open(d + "/" + x + "/" + f, "rb").read()).hexdigest() for f in os.listdir(d + "/" + x)} for x in ("witness-build", "witness-apk-ubuntu-24.04")}))
sr("sign-records: --stage rebuild given Build's apk/build records (listed as they are) is refused (a record's step must be a step of the stage)", d, "rebuild", 1, ["step"], args=sr_args("rebuild", d, ["witness-build", "witness-apk-ubuntu-24.04"], expect="own-list.json"))
d, _ = sr_tree("sr26", "rebuild"); put(d, "artifacts/witness-rapk-ubuntu-24.04/out/x86_64/fscache-0.3.0-r0.apk", b"apk-x")
sr("sign-records rebuild: Rebuild's apks must never reach Sign: an artifact dir for a rapk record is refused", d, "rebuild", 1, ["rapk"])
shutil.rmtree(work, ignore_errors=True)
EXPECT = 221
print("pass=%d fail=%d" % (passed, failed))
if passed + failed != EXPECT:
    print("FAIL case count %d != expected %d (a case was skipped or added)" % (passed + failed, EXPECT))
    sys.exit(1)
sys.exit(1 if failed else 0)
PY
