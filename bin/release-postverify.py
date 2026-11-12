"""Release's post-publish verification (v0.3.0 rule 79 as amended by the owner, Oct 10; REQ-CHAIN-007-AC20).

Reads docs/verify-release.cannot-run.json (rows {command, reason}, the exact-text list Check also reads) and runs
each command against what was just published, in BOTH registries (ghcr.io/fosterstack/cache, then
docker.io/fosterstack/cache; the same digests). A command naming <IMAGE_REF> or <IMAGE_REF_FIPS> runs once per
registry, with the image-production / image-fips digest of witness-build/digests.json filled in; any other command
runs once. <TAG> = $GITHUB_REF_NAME, which must be vX.Y.Z (a release candidate publishes nothing to verify).

Every command is judged before any runs (a refusal runs nothing) by bin/guide_plan_judge.py, the judge Check
uses: a pipe of the verify forms and jq in a closed grammar, no other shell syntax, no literal image reference,
no placeholder left unfilled. Every verify form carries exactly one key flag whose value is release.rsa.pub (the
public key of the release key manifest, placed by place_release_key). Before any command runs, the release's key
manifest (release-key-manifest.json and .sig in release-published/) is checked with the committed root key by the
verifier's check_manifest (REQ-CHAIN-008-AC3); release.rsa.pub is written from the manifest's public_key only
(AC5), and a manifest that does not pass runs nothing (AC4). A command that fails fails the run (exit 1) after all
have run. The step holds no token and no registry credential.

Every command runs with release-published/ (the assets just downloaded from the published release) as its working
directory, so the guide's bare file names resolve as a customer's do. A command made only of jq is accepted only
when every file it reads is named by an EARLIER command of the same list that is a verify form, and at run time
only after that verify exited 0. Every command runs without a shell: the words the judge read are the argv, so
nothing is expanded after the check.
"""
import collections, hashlib, json, os, re, shlex, shutil, subprocess, sys, tempfile, types
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import guide_plan_judge   # noqa: E402
from guide_plan_judge import JQ_FILE, MARK, PH   # noqa: E402

LIST = "docs/verify-release.cannot-run.json"
ASSETS = "release-published"   # gh release download -D release-published: the files a customer downloads
VERIFIER = "bin/chain-verify.py"   # holds the bundle and manifest checks
ROOT_KEY = ".github/policy/release-key-root.pub"   # the committed offline root public key that signs the manifest
LISTED = ".github/policy/chain-scripts.json"   # the sha256 of every file of the chain that runs
DIGESTS = "witness-build/digests.json"
# Constants: releases publish identical digests to both, and no input names a repository.
REPOSITORIES = ("ghcr.io/fosterstack/cache", "docker.io/fosterstack/cache")
# v0.3.0 yes, v0.3.0-rc1 and "v0.3.0\n" no
TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+")
# sha256: and 64 lowercase hex digits yes; sha256:abc and an upper-case digest no
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
# a command the judge accepted: its pipe segments filled for this registry, the files a jq-only command reads
# (None for a verify command), the names its verify forms name, and their --bundle files
Run = collections.namedtuple("Run", "registry command argvs files names bundles")


def refuse(msg):
    print("release-postverify: " + msg, file=sys.stderr)
    sys.exit(1)


def run_pipe(argvs):
    """Runs the argv of each segment of a pipe WITHOUT a shell: the words the judge read are the argv, so nothing
    can change them after the check. Every command of the pipe must exit 0 (pipefail); a command that cannot start
    fails the run."""
    procs, prev = [], subprocess.DEVNULL
    try:
        for n, argv in enumerate(argvs):
            last = n == len(argvs) - 1
            p = subprocess.Popen(argv, stdin=prev, stdout=None if last else subprocess.PIPE, cwd=ASSETS)
            if prev is not subprocess.DEVNULL:
                prev.close()
            prev = p.stdout
            procs.append(p)
    except OSError as e:
        print("release-postverify: %s cannot be started (%s)" % (argvs[len(procs)][0], type(e).__name__),
              file=sys.stderr)
        for p in procs:
            p.kill()
        for p in procs:
            p.wait()
        return 127
    codes = [p.wait() for p in procs]
    return next((rc for rc in codes if rc != 0), 0)


def read_commands():
    """The commands of the list, each once, from rows of exactly {command, reason}."""
    if not os.path.exists(LIST):
        refuse("the list %s is missing: the post-publish verification has nothing to run "
               "(a missing list is a failed release)" % LIST)
    try:
        with open(LIST) as f:
            rows = json.load(f)
    except ValueError as e:
        refuse("the list %s is not JSON: %s" % (LIST, e))
    if not isinstance(rows, list):
        refuse("the list %s is not a list" % LIST)
    cmds = []
    for r in rows:
        whole = (isinstance(r, dict) and set(r) == {"command", "reason"}
                 and all(isinstance(r[k], str) and r[k].strip() for k in r))
        if not whole:
            refuse("a row of %s must be exactly {command, reason}, both non-empty: %r" % (LIST, r))
        if r["command"] in cmds:
            refuse("%s lists `%s` twice" % (LIST, r["command"]))
        cmds.append(r["command"])
    return cmds


def read_digests():
    try:
        with open(DIGESTS) as f:
            digests = json.load(f)
    except (OSError, ValueError) as e:
        refuse("the digest list %s cannot be read: %s" % (DIGESTS, e))
    for key in ("image-production", "image-fips"):
        d = digests.get(key) if isinstance(digests, dict) else None
        if not (isinstance(d, str) and DIGEST.fullmatch(d)):
            refuse("the digest list %s has no valid %s digest (sha256:<64 lowercase hex>): nothing is run"
                   % (DIGESTS, key))
    return digests


def verify_names(segs):
    """(the names the verify forms of a judged command name as files, their --bundle files), placeholders as markers."""
    names, bundles = set(), []
    for s in segs:
        if s[0] != "jq":
            flags, operands, _ = guide_plan_judge.read_verify(s)
            bundles += [v for f, v in flags if f == "--bundle"]
            names |= set(operands) | set(bundles)
    return names, bundles


def judge(c, verified):
    """Refuses the command unless the shared judge accepts it; returns (segments, files a jq-only command reads
    or None, names its verify forms name, their --bundle files). `verified` are the name sets of the verify
    forms before it in the list: a jq-only command may read only files they name."""
    segs, files, why = guide_plan_judge.judge(c)
    if why:
        refuse("`%s` is not an allowed verify form (%s)" % (c, why))
    if files is None:
        return (segs, None) + verify_names(segs)
    if not files:
        refuse("`%s` is not an allowed verify form (it reads no file: stdin is not a verified input)" % c)
    for f in files:
        if not any(f in names for names in verified):
            refuse("`%s` is not an allowed verify form (no verify form in it): "
                   "no earlier command of the list is a verify form that names %s" % (c, f))
    return segs, files, set(), []


def make_plan(cmds, digests, tag):
    """[Run]: one pass per registry, in order. Each command is judged once."""
    judged, verified = [], []
    for c in cmds:
        segs, files, names, bundles = judge(c, verified)
        verified.append(names)
        judged.append((c, segs, files, names, bundles))
    plan = []
    for reg in REPOSITORIES:
        values = {"TAG": tag, "IMAGE_REF": "%s@%s" % (reg, digests["image-production"]),
                  "IMAGE_REF_FIPS": "%s@%s" % (reg, digests["image-fips"])}

        def fill(word, c):
            def value(m):
                if m.group(1) not in values:
                    refuse("`%s` uses <%s>, which the post-publish step cannot fill (unsubstituted placeholder)"
                           % (c, m.group(1)))
                return values[m.group(1)]
            return MARK.sub(value, word)
        for c, segs, files, names, bundles in judged:
            if reg != REPOSITORIES[0] and not set(PH.findall(c)) & {"IMAGE_REF", "IMAGE_REF_FIPS"}:
                continue   # no image placeholder: the same command, run once
            argvs = [[fill(w, c) for w in s] for s in segs]
            plan.append(Run(reg, c, argvs, files, names, [fill(b, c) for b in bundles]))
    return plan


def run_plan(plan):
    """Runs the plan; returns [(registry, command, exit code)] of the runs that failed."""
    failed = []
    passed = set()   # files named by the verify forms that have exited 0 so far: a jq-only command may read only these
    for r in plan:
        if r.files is not None and not all(f in passed for f in r.files):
            failed.append((r.registry, r.command, 1))
            print("::error::post-publish verification failed against %s: `%s` was not run: "
                  "the earlier verify of %s did not pass" % (r.registry, r.command, ", ".join(r.files)),
                  file=sys.stderr, flush=True)
            continue
        print("release-postverify: [%s] $ %s" % (r.registry, " | ".join(shlex.join(a) for a in r.argvs)), flush=True)
        rc = run_pipe(r.argvs)
        if rc != 0:
            failed.append((r.registry, r.command, rc))
            print("::error::post-publish verification failed against %s: `%s` exited %d" % (r.registry, r.command, rc),
                  file=sys.stderr, flush=True)
        elif r.files is None:
            passed |= r.names
    return failed


def load_verifier():
    """bin/chain-verify.py as a module, never run as a program. It decides which key signs every listed command, so
    its bytes must carry the sha256 listed for it in .github/policy/chain-scripts.json (an edited verifier that
    accepts any manifest is refused), and those same bytes are compiled and run (no bytecode cache stands in)."""
    try:
        with open(VERIFIER, "rb") as f:
            src = f.read()
        with open(LISTED, "rb") as f:
            listed = {r["path"]: r["sha256"] for r in json.load(f)["scripts"]}
    except (OSError, ValueError, KeyError, TypeError) as e:
        refuse("%s cannot be loaded (%s)" % (VERIFIER, type(e).__name__))
    if listed.get(VERIFIER) != hashlib.sha256(src).hexdigest():
        refuse("%s does not match its sha256 in %s: refusing to run it" % (VERIFIER, LISTED))
    mod = types.ModuleType("chain_verify")
    mod.__file__ = os.path.abspath(VERIFIER)
    try:
        exec(compile(src, mod.__file__, "exec"), mod.__dict__)
    except (Exception, SystemExit) as e:
        # SystemExit: the verifier's own helper loader exits when a helper fails its sha256
        refuse("%s cannot be loaded (%s: %s)" % (VERIFIER, type(e).__name__, e))
    return mod


# what a bundle signed with a key holds at the top, and in its verificationMaterial
# (no certificate, whatever the spelling)
BUNDLE_KEYS = {"mediaType", "verificationMaterial", "messageSignature", "dsseEnvelope"}
MATERIAL_KEYS = {"publicKey", "tlogEntries", "timestampVerificationData"}


def refuse_certificate_bundles(plan, check):
    """Every --bundle operand of the filled commands must be a plain file name. A named file that is present is read as
    strict JSON and refused unless it is a bundle signed with a key: a certificate is refused by the check
    bin/chain-verify.py holds, then any key outside the two allowed sets. A named file that is absent is not read:
    the command that names it fails the run (REQ-CHAIN-007-AC20)."""
    names = []
    for r in plan:
        names += [n for n in r.bundles if n not in names]
    root = os.path.realpath(ASSETS)
    present = []
    for n in names:
        if not JQ_FILE.fullmatch(n):
            refuse("%s: not a plain file name in %s/ (letters, digits, . _ - only)" % (n, ASSETS))
        path = os.path.realpath(os.path.join(ASSETS, n))
        if os.path.commonpath([root, path]) != root:   # a plain name that is a link out
            refuse("%s: resolves outside %s/" % (n, ASSETS))
        if os.path.lexists(path):
            present.append((n, path))
    for n, path in present:
        try:
            with open(path, "rb") as f:
                bundle = check.strict_json(f.read())
        except (OSError, ValueError) as e:
            refuse("%s: cannot be read as strict JSON (%s)" % (n, type(e).__name__))
        material = bundle.get("verificationMaterial") if isinstance(bundle, dict) else None
        if not isinstance(material, dict):
            refuse("%s: not a bundle: an object with an object verificationMaterial is required" % n)
        why = check.bundle_certificate_why(material)
        if why:
            refuse("%s: %s" % (n, why))
        for key in sorted(set(material) - MATERIAL_KEYS):
            refuse("%s: verificationMaterial.%s is not allowed (a bundle signed with a key holds %s)"
                   % (n, key, ", ".join(sorted(MATERIAL_KEYS))))
        for key in sorted(set(bundle) - BUNDLE_KEYS):
            refuse("%s: %s is not allowed at the top of a bundle (%s)" % (n, key, ", ".join(sorted(BUNDLE_KEYS))))


def copy_keeping_links(src, dst):
    """Copies a file; a link is copied as a link and a directory as an empty directory, so the verifier refuses each
    as it would in place. A missing file is left missing, for the verifier to name."""
    if os.path.islink(src):
        os.symlink(os.readlink(src), dst)
    elif os.path.isdir(src):
        os.mkdir(dst)
    elif os.path.exists(src):
        shutil.copyfile(src, dst)


def place_release_key(check):
    key_file = ASSETS + "/release.rsa.pub"
    if os.path.lexists(key_file):
        refuse("%s exists: a published asset must not stand in for the key of the manifest" % key_file)
    with tempfile.TemporaryDirectory() as keys_dir:
        for name, src in zip(check.MANIFEST_FILES, (ROOT_KEY, ASSETS + "/" + check.MANIFEST_FILES[1],
                                                   ASSETS + "/" + check.MANIFEST_FILES[2])):
            copy_keeping_links(src, os.path.join(keys_dir, name))
        try:
            key = check.check_manifest(keys_dir)
        except check.Refuse as r:
            refuse("the release key manifest is refused: %s" % r.reason)
    with open(key_file, "w") as f:
        f.write(key["public_key"])


def main():
    tag = os.environ.get("GITHUB_REF_NAME", "")
    if not TAG.fullmatch(tag):
        refuse("refused at tag: %r is not vX.Y.Z" % tag)
    cmds = read_commands()
    plan = make_plan(cmds, read_digests(), tag)
    if not os.path.isdir(ASSETS):
        refuse("%s/ is not a directory: the assets of the published release are not here, so no listed command can "
               "resolve its files; nothing is run" % ASSETS)
    check = load_verifier()
    refuse_certificate_bundles(plan, check)
    place_release_key(check)
    failed = run_plan(plan)
    if failed:
        refuse("post-publish verification failed: %d of %d runs failed: %s"
               % (len(failed), len(plan), "; ".join("[%s] `%s` exited %d" % f for f in failed)))
    print("release-postverify: all %d post-publish verification runs passed (%d commands, %d registries)"
          % (len(plan), len(cmds), len(REPOSITORIES)))


main()
