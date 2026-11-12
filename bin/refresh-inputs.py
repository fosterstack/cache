#!/usr/bin/env python3
"""The Python half of bin/refresh-inputs.sh (REQ-REFRESH-001): the shell runs the tools and the downloads, this file makes
every check and every file. Run as `python3 -I -B refresh-inputs.py MODE REPO ARGS...`; the modes and their arguments:

  key-check REPO LIVE_KEY                          the live Wolfi key is the pinned one (prints it)
  pinned-key REPO LIVE_KEY                         the same, silent
  archive-key-check REPO LIVE_KEY ARCHIVE          the live key is also the key the archive holds
  bootstrap REPO LIVE_KEY ARCHIVE                  seed an empty archive with the pinned key
  check-paths REPO PATH...                         every path is a regular file of the repository
  commit-input REPO SLUG OUT BRANCH BASE HEADLINE BODY PATH...   write the API request that creates the commit
  guard REPO PR_AUTHOR BRANCH                      exit 4 when an open pull request stops a new one on BRANCH
  open-pr-plan REPO PLAN_DIR ARCHIVE DIGEST TMP    validate the staged plans, write TMP/p<N>.* and TMP/ncount
  prepare REPO TMP                                 read the package lists, locks and kernel row before any network call
  configs REPO TMP                                 write the apko configs that resolve against live Wolfi
  refresh REPO PR_AUTHOR ARCHIVE TMP               the refresh itself (exit 75: the shell must download what TMP/want-* lists)
  fips-module REPO PR_AUTHOR GOROOT MODFILE TMP STAGED

Exit codes: 0 ok, 1 verification failed, 2 refused (bad input), 3 the Wolfi signing key changed, 4 guard: a pull request
is open, 75 downloads wanted.
"""
import base64, hashlib, io, json, os, re, secrets, shutil, subprocess, sys, tarfile, urllib.parse, zlib

mode, repo = sys.argv[1:3]
BINDIR = os.path.dirname(os.path.abspath(__file__))
ARCHS = ["x86_64", "aarch64"]
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*")
VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~-]*")
KEY_FILE = "kernel-key-6165ee59.rsa.pub"
KEY_SHA256 = "207e4696d3c05f7cb05966aee557307151f1f00217af4143c1bcaf33b8df733f"
PR_AUTHOR = ""
HINT = ""   # appended to a failure while a file that was already in the archive is being checked


def fail(msg, code=1):
    print("refresh-inputs.sh: " + msg + HINT, file=sys.stderr)
    sys.exit(code)


def stop(msg):
    print("refresh-inputs.sh: %s; stopping, a human must look" % msg, file=sys.stderr)
    sys.exit(3)


def pinned_live_key(live):
    """The live Wolfi key must be the one pinned in build/locks/archive-keys.sha256, else exit 3. Returns the key's bytes."""
    try:
        rows = [l for l in open(repo + "/build/locks/archive-keys.sha256", "rb").read().decode("utf-8", "strict").split("\n") if l.strip()]
    except (OSError, UnicodeError):
        stop("build/locks/archive-keys.sha256 is missing or unreadable, so there is no pinned Wolfi key to check the live one against")
    mine = [l for l in rows if l.split(" ")[0] == "wolfi-signing.rsa.pub"]
    # matches "wolfi-signing.rsa.pub sha256:" and 64 lower-case hex digits; refuses the same row with 63 digits or an upper-case digit
    if len(mine) != 1 or not re.fullmatch(r"wolfi-signing\.rsa\.pub sha256:[0-9a-f]{64}", mine[0]):
        stop("build/locks/archive-keys.sha256 must hold exactly one line 'wolfi-signing.rsa.pub sha256:<64 hex>'")
    raw = open(live, "rb").read()
    if hashlib.sha256(raw).hexdigest() != mine[0].split("sha256:")[1]:
        stop("the live Wolfi signing key is not the key pinned in build/locks/archive-keys.sha256")
    return raw


def key_check(live):
    pinned_live_key(live)
    print("key-check: the live Wolfi signing key is the pinned one")


def archive_key_check(live, archive):
    raw = pinned_live_key(live)
    try:
        archived = open(archive + "/keys/wolfi-signing.rsa.pub", "rb").read()
    except OSError:
        stop("the archive holds no keys/wolfi-signing.rsa.pub")
    if archived != raw:
        stop("the live Wolfi signing key differs from the key in the archive")
    print("archive-key-check: the live Wolfi signing key is the pinned one and the archive's key")


def bootstrap(live, archive):
    raw = pinned_live_key(live)
    os.makedirs(archive + "/keys", exist_ok=True)
    with open(archive + "/keys/wolfi-signing.rsa.pub", "xb") as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())
    print("bootstrap: the archive was seeded with the pinned Wolfi signing key")


def bad_paths(paths, outcome):
    """REQ-REFRESH-001-AC34: every planned path must be a regular file of the repository (no symlink, nothing real-pathed outside it,
    not under .git). Prints each refused path with what happens instead; returns how many."""
    root = os.path.realpath(repo)
    bad = 0
    for p in paths:
        full = repo + "/" + p
        n_ = os.path.normpath(p)
        if p.startswith("/") or ".." in p.split("/") or n_ == ".git" or n_.startswith((".git/", "../")) or os.path.islink(full) or not os.path.isfile(full) or os.path.commonpath([root, os.path.realpath(full)]) != root:
            print("refresh-inputs.sh: %r is not a regular file of the repository (a symlink, a path outside it or its .git is refused); %s" % (p, outcome), file=sys.stderr)
            bad += 1
    return bad


def check_paths(*paths):
    sys.exit(1 if bad_paths(paths, "no branch was pushed") else 0)


def commit_input(slug, out, branch, base, headline, body, *paths):
    """The GraphQL request that creates the one commit through the API: the paths are checked again here, then read."""
    if bad_paths(paths, "no commit was made"):
        sys.exit(1)
    adds, seen = [], set()
    for p in paths:
        if p in seen:
            continue                                   # the API refuses a path twice: the plan may already name build/archive.json when open-pr adds the pointer
        seen.add(p)
        adds.append({"path": p, "contents": base64.b64encode(open(repo + "/" + p, "rb").read()).decode()})
    q = "mutation($input: CreateCommitOnBranchInput!){createCommitOnBranch(input:$input){commit{oid}}}"
    inp = {"branch": {"repositoryNameWithOwner": slug, "branchName": branch}, "message": {"headline": headline, "body": body},
           "fileChanges": {"additions": adds}, "expectedHeadOid": base}
    json.dump({"query": q, "variables": {"input": inp}}, open(out, "w"))


def norm_login(x):
    """lower case (GitHub logins are not case-sensitive), then strip the decorations until none is left: app/bot, bot[bot], app/bot[bot]"""
    y = x.lower()
    while True:
        z = y[4:] if y.startswith("app/") else (y[:-5] if y.endswith("[bot]") else y)
        if z == y:
            return y
        y = z


def find_open_refresh_pr(own_fips):
    """(number, head) of the first open pull request on a refresh/ branch that is ours (this repository, not a fork, and authored by the
    job's identity when one is given), else None. If the list cannot be read the job fails (an unknown state is not "no PR").
    A FIPS-module pull request does not count against an input refresh (REQ-REFRESH-001-AC15); the FIPS-module change itself (own_fips)
    is held by it, so the daily check opens one such pull request, not one a day."""
    r = subprocess.run(["/usr/bin/gh", "pr", "list", "--state", "open", "--limit", "1000", "--json", "number,headRefName,isCrossRepository,author"],
                       cwd=repo, capture_output=True, text=True)
    if r.returncode != 0:
        fail("cannot list the open pull requests (gh pr list failed); changing nothing, pushing nothing, opening nothing")
    try:
        prs = json.loads(r.stdout)
    except ValueError:
        fail("cannot read the open pull request list (not JSON); changing nothing")
    for pr in prs:
        who = ((pr.get("author") or {}).get("login") or "")
        if pr.get("isCrossRepository") or (PR_AUTHOR and norm_login(who) != norm_login(PR_AUTHOR)):
            continue
        head = pr.get("headRefName", "")
        if head.startswith("refresh/") and (own_fips or not head.startswith("refresh/fips-module-")):
            return pr.get("number"), head
    return None


def open_prs_guard(kind, own_fips=False, code=0):
    """Looked up before the FIRST archive or repository change: if an earlier pull request is open, nothing more is done (no change, no
    push, no second PR) and the stall is visible: the log and the job summary name it."""
    found = find_open_refresh_pr(own_fips)
    if found:
        msg = "an earlier pull request (#%s, %s) of this kind is still open (already open); changing nothing, pushing nothing and opening no second one (it is merged or closed first)" % found
        print(msg)
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            open(os.environ["GITHUB_STEP_SUMMARY"], "a").write("- %s: %s\n" % (kind, msg))
        sys.exit(code)


def guard(pr_author, branch):
    global PR_AUTHOR
    PR_AUTHOR = pr_author
    open_prs_guard("open-pr", branch.startswith("refresh/fips-module-"), 4)


def write_atomic(path, text):
    """a repository file: O_EXCL temp name, fsync, rename"""
    t = "%s.tmp-%s" % (path, secrets.token_hex(8))
    with open(t, "xb") as d_:
        shutil.copyfileobj(io.BytesIO(text.encode()), d_)
        d_.flush()
        os.fsync(d_.fileno())
    os.replace(t, path)


def open_pr_plan(plan_dir, archive, digest, tmp):
    plans = []
    for name in sorted(os.listdir(plan_dir), key=lambda n: (int(n.split("-")[0]) if n.split("-")[0].isdigit() else 10**9, n)):
        d = plan_dir + "/" + name
        if not os.path.isdir(d): fail("plan %s is not a directory" % name, 2)
        try:
            branch, title, body = (open(d + "/" + f).read().rstrip("\n") for f in ("branch", "title", "body"))
            paths = [l for l in open(d + "/paths").read().split("\n") if l]
        except OSError as e:
            fail("plan %s is incomplete (%s)" % (name, e), 2)
        if not re.fullmatch(r"refresh/[A-Za-z0-9._-]+", branch): fail("plan %s names the branch %r, not one under refresh/" % (name, branch), 2)
        if not paths: fail("plan %s names no file" % name, 2)
        for p in paths:
            if p.startswith("/") or ".." in p.split("/") or not os.path.isfile(repo + "/" + p): fail("plan %s names %r, which is not a file of the repository" % (name, p), 2)
        plans.append((branch, title, body, paths, branch.startswith("refresh/fips-module-")))
    if not plans:
        print("open-pr: nothing planned, nothing opened"); open(tmp + "/ncount", "w").write("0\n"); return
    if digest and not any(not p[4] for p in plans):
        print("open-pr: the plan holds no refresh pull request, so the pointer is not written")
    for n, (branch, title, body, paths, fips) in enumerate(plans, 1):
        if digest and not fips:
            r = subprocess.run(["/usr/bin/python3", "-I", "-B", BINDIR + "/archive-verify.py", "make-pointer", "--dir", archive, "--digest", digest,
                                "--out", repo + "/build/archive.json"], capture_output=True, text=True)
            if r.returncode != 0: fail("the pointer for %s could not be made: %s" % (digest, (r.stderr or r.stdout).strip()), 1)
            paths = paths + ["build/archive.json"]
            body += "\n\nThe archive was stored in our registry at %s; this pull request moves build/archive.json to it." % digest
        open("%s/p%d.branch" % (tmp, n), "w").write(branch)
        open("%s/p%d.title" % (tmp, n), "w").write(title)
        open("%s/p%d.body" % (tmp, n), "w").write(body)
        open("%s/p%d.paths" % (tmp, n), "w").write("\n".join(paths) + "\n")
    open(tmp + "/ncount", "w").write("%d\n" % len(plans))


def prepare(tmp):
    import yaml
    # REQ-REFRESH-001-AC35 and AC39: the lists of packages that run on the runner itself (bubblewrap) or for the VM build
    # (the emulator, the guest), resolved like melange's build tools
    def refuse(msg):
        print("refresh-inputs.sh: refused: %s" % msg, file=sys.stderr); sys.exit(2)
    def read_list(yaml_rel, lock_rel):
        """The names in a package list file, after the strict reading of the file and of its committed lock."""
        class StrictLoader(yaml.SafeLoader):
            pass
        def _no_dup(loader, node, deep=False):
            seen = set()
            for k, _ in node.value:
                key = loader.construct_object(k, deep=True)
                if not isinstance(key, str):
                    refuse("%s has a key that is not a plain string: %r" % (yaml_rel, key))
                if key in seen:
                    refuse("%s has the key %r twice" % (yaml_rel, key))
                seen.add(key)
            return yaml.SafeLoader.construct_mapping(loader, node, deep)
        StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _no_dup)
        try:
            h = yaml.load(open(repo + "/" + yaml_rel), Loader=StrictLoader)
        except yaml.YAMLError as e:
            refuse("%s is not valid YAML (%s)" % (yaml_rel, str(e).splitlines()[0]))
        # a closed shape: exactly one key, packages, a non-empty list of unique plain package names
        # (no version, no path: the lock pins the versions)
        if not isinstance(h, dict) or set(h) != {"packages"}:
            refuse("%s must hold exactly one key, packages" % yaml_rel)
        names = h["packages"]
        plain = isinstance(names, list) and all(isinstance(n, str) and NAME_RE.fullmatch(n) and ".." not in n for n in names)
        if not plain or not names or len(set(names)) != len(names):
            refuse("%s packages must be a non-empty list of unique plain package names (no version, no path)" % yaml_rel)
        # the committed lock: name=version rows in the closed grammar, each name once
        seen_n = set()
        text = open(repo + "/" + lock_rel, newline="").read()   # no newline translation: a CR is a bad row, not a line end
        if text and not text.endswith("\n"):
            refuse("%s must end with a line end" % lock_rel)
        for row in (text.split("\n")[:-1] if text else []):
            n, eq, v = row.partition("=")
            if not eq or not NAME_RE.fullmatch(n) or not VERSION_RE.fullmatch(v) or ".." in n or ".." in v or n in seen_n:
                refuse("%s has a row that is not a name=version of the closed grammar, or a name twice: %r"
                       % (lock_rel, row))
            seen_n.add(n)
        return names
    hnames = read_list("build/host-tools.yaml", "build/locks/host-tools.lock")
    yaml.safe_dump({"contents": {"repositories": [], "keyring": [], "packages": hnames}, "archs": ["x86_64", "aarch64"]},
                   open(tmp + "/host/host-tools-env.yaml", "w"))
    for vm in ("vm-host", "vm-guest"):
        vnames = read_list("build/%s.yaml" % vm, "build/locks/%s.lock" % vm)
        yaml.safe_dump({"contents": {"repositories": [], "keyring": [], "packages": vnames}, "archs": ["x86_64"]},
                       open("%s/%s/%s-env.yaml" % (tmp, vm, vm), "w"))
    # REQ-REFRESH-001-AC40: the kernel lock is read whole, before the first network call of the run
    k_text = open(repo + "/build/locks/vm-kernel.lock", newline="").read()
    k_rows = k_text.split("\n")[:-1] if k_text.endswith("\n") else []
    m = re.fullmatch(r"(linux-virt)=(%s) sha256:([0-9a-f]{64})" % VERSION_RE.pattern, k_rows[0]) if len(k_rows) == 1 else None
    if not m or ".." in m.group(2):
        refuse("build/locks/vm-kernel.lock must end with a line end and hold exactly one row, "
               "'linux-virt=<version> sha256:<64 lower-case hex>': %r" % k_text[:200])
    open(tmp + "/vm-kernel.rows", "w").write("%s %s %s\n" % m.groups())
    # REQ-REFRESH-001-AC41: the committed kernel package key is the pinned one before anything is checked with it
    if hashlib.sha256(open(repo + "/build/vm-keys/" + KEY_FILE, "rb").read()).hexdigest() != KEY_SHA256:
        print("refresh-inputs.sh: build/vm-keys/%s is not the key whose sha256 this script states (%s); "
              "stopping, a human must look" % (KEY_FILE, KEY_SHA256), file=sys.stderr); sys.exit(3)
    # REQ-REFRESH-001-AC42: every VM lock is written inside the repository (the file and its temporary sibling's directory)
    root = os.path.realpath(repo)
    for vm in ("vm-host", "vm-guest"):
        lock_path = "%s/build/locks/%s.lock" % (repo, vm)
        for real in (os.path.realpath(os.path.dirname(lock_path)), os.path.realpath(lock_path)):
            if os.path.commonpath([root, real]) != root:
                refuse("%s resolves to %s, outside the repository; nothing was written" % (lock_path, real))


def configs(tmp):
    import yaml
    for src, out in (("apko.yaml", "production/apko.yaml"), ("apko-fips.yaml", "fips/apko-fips.yaml")):
        d = yaml.safe_load(open("%s/build/%s" % (repo, src)))
        c = d.setdefault("contents", {})
        c["repositories"] = []; c["keyring"] = []
        c["packages"] = [p for p in c.get("packages", []) if not str(p).startswith("fscache")]
        yaml.safe_dump(d, open("%s/%s" % (tmp, out), "w"))
    m = yaml.safe_load(open(repo + "/build/melange.yaml"))
    names = [str(p).split("=")[0] for p in m["environment"]["contents"]["packages"]]
    yaml.safe_dump({"contents": {"repositories": [], "keyring": [], "packages": names}, "archs": ["x86_64", "aarch64"]},
                   open(tmp + "/melange/melange-env.yaml", "w"))


def fips_module(pr_author, goroot, modfile, tmp, staged):
    global PR_AUTHOR
    PR_AUTHOR = pr_author
    STAGED = staged == "1"   # a plan is already staged: the checks below run, then the answer is only pending / nothing pending
    cert = os.path.join(goroot, "lib", "fips140", "certified.txt")


    def fail(msg, code=2): print("refresh-inputs.sh: " + msg, file=sys.stderr); sys.exit(code)


    if not os.path.isfile(cert):
        fail("%s is missing; cannot tell which Go Cryptographic Module is certified" % cert)
    NUM = r"(0|[1-9][0-9]*)"   # no leading zeros: v1.0.00 is not another spelling of v1.0.0
    PAT = re.compile(r"^v%s\.%s\.%s-[0-9a-f]{8}$" % (NUM, NUM, NUM))
    mods = []
    try:
        cert_text = open(cert, "rb").read().decode("utf-8")
    except (OSError, UnicodeDecodeError) as e:
        fail("%s is not readable as UTF-8 text (%s); cannot tell which Go Cryptographic Module is certified" % (cert, e))
    for ln in cert_text.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        m = PAT.match(ln)
        if not m:
            fail("%s: unreadable module value %r (expected vMAJOR.MINOR.PATCH-<8 hex>)" % (cert, ln))
        mods.append((tuple(int(x) for x in m.groups()), ln))
    if not mods:
        fail("%s is empty; cannot tell which Go Cryptographic Module is certified" % cert)
    if len(mods) != 1:
        fail("%s must hold exactly one module line (found %d); which one counts is a human decision" % (cert, len(mods)))
    newest = mods[0][1]
    # the module the FIPS build uses now is DATA (build/locks/fips-module.txt), read with the same closed grammar the certified file is
    try:
        raw_cur = open(modfile, "rb").read().decode("ascii")
    except (OSError, UnicodeDecodeError):
        fail("%s is not readable as plain ASCII text" % modfile)
    if not raw_cur.endswith("\n") or "\r" in raw_cur or raw_cur.count("\n") != 1 or not PAT.match(raw_cur[:-1]):
        fail("%s must hold exactly one line vMAJOR.MINOR.PATCH-<8 hex> and a plain newline; refusing" % modfile)
    cur = raw_cur[:-1]
    cm = PAT.match(cur)
    if tuple(int(x) for x in cm.groups()) > mods[0][0]:
        fail("%s names %s, older than the %s the FIPS build uses; refusing to move backward" % (cert, newest, cur))
    if cm.groups() == PAT.match(newest).groups() and cur != newest:
        fail("%s names %s, the SAME version as the %s the FIPS build uses with a different hash; refusing, a human must look" % (cert, newest, cur))
    if STAGED:
        if cur != newest:
            print("fips-module: pending: Go's certified module file names %s, the FIPS build uses %s; its pull request is staged on the next run without a staged refresh" % (newest, cur))
        else:
            print("fips-module: nothing pending: the certified module is the one the FIPS build uses (%s)" % cur)
        sys.exit(0)
    if cur == newest:
        print("up to date: Go's certified module %s is the one the FIPS build already uses; no pull request" % cur)
        open(tmp + "/new", "w").write("")
        sys.exit(0)
    open_prs_guard("fips-module", True)   # before any file is changed
    # only the DATA file changes; the recipes are what the generator makes of it (the template and its pin are never touched by an automated change)
    gen_dir = tmp + "/gen"
    os.makedirs(gen_dir, exist_ok=True)
    open(tmp + "/fips-module.new", "w").write(newest + "\n")
    r_ = subprocess.run(["/usr/bin/python3", "-I", "-B", BINDIR + "/gen-recipes.py", "--template", repo + "/build/melange.yaml.tmpl", "--baselayout-template", repo + "/build/melange-baselayout.yaml.tmpl", "--melange-lock", repo + "/build/locks/melange.lock",
                         "--fips-module", tmp + "/fips-module.new", "--emit", gen_dir], capture_output=True, text=True)
    if r_.returncode != 0:
        fail("the recipe generator refused (%s): %s" % (r_.returncode, r_.stderr.strip()[:300]), 1)
    writes = []
    for rf in ("melange.yaml", "melange-fips.yaml", "melange-baselayout.yaml"):
        path = "%s/build/%s" % (repo, rf)
        out = open("%s/%s" % (gen_dir, rf)).read()
        if out != open(path).read():
            writes.append((path, out))
    writes.append((modfile, newest + "\n"))   # the DATA file last: a run killed half-way leaves the old data, so the next run does the whole job again
    for path, _ in writes:
        pdir = os.path.dirname(path)
        if os.path.isdir(path) or not os.access(pdir, os.W_OK | os.X_OK):   # each file is replaced by a rename: the DIRECTORY must take it
            fail("%s cannot be written: its directory %s is not writable; changing nothing" % (path, pdir), 1)
    for path, content in writes:
        write_atomic(path, content)   # a kill leaves the old file whole
    open(tmp + "/paths", "w").write("".join(os.path.relpath(p_, repo) + "\n" for p_, _ in writes))
    open(tmp + "/new", "w").write(newest + "\n" + cur + "\n")
    print("a newer certified module: %s (the FIPS build uses %s)" % (newest, cur))


MODES = {"key-check": key_check, "pinned-key": pinned_live_key, "archive-key-check": archive_key_check, "bootstrap": bootstrap,
         "check-paths": check_paths, "commit-input": commit_input, "guard": guard, "open-pr-plan": open_pr_plan,
         "prepare": prepare, "configs": configs, "fips-module": fips_module}
if mode != "refresh":
    MODES[mode](*sys.argv[3:])
    sys.exit(0)

# ---- refresh: the rest of this file ----
import yaml
PR_AUTHOR, archive, tmp = sys.argv[3:6]
INFLATE_CAP = 128 * 1024 * 1024   # the live index is about 42 MiB decompressed today


def inflate(rest, what, cap=None):
    """one gzip stream from the front of rest, decompressed to at most cap (default 128 MiB): (compressed bytes, data, remaining bytes)"""
    cap = INFLATE_CAP if cap is None else cap
    d = zlib.decompressobj(31)
    data = d.decompress(rest, cap + 1)
    if len(data) > cap or d.unconsumed_tail:
        fail("%s decompresses to more than 128 MiB (too large; refusing before anything is checked)" % what)
    if not d.eof:
        fail("%s is not a complete gzip stream (its trailer is missing); a human must look" % what)
    used = len(rest) - len(d.unused_data) - len(d.unconsumed_tail)
    return rest[:used], data, d.unused_data


def b64(raw): return base64.b64encode(raw).decode()


def digest(kind, raw):
    return {"sha1": hashlib.sha1, "sha256": hashlib.sha256}[kind](raw).digest()


def verify(path, e):
    """The bytes must match every checksum the lock records for this package; control and data ranges are REQUIRED (a package with
    nothing to check is not accepted), and the datahash in the control section must equal the sha256 of the data stream."""
    raw = open(path, "rb").read()
    for part in ("signature", "control", "data"):
        p = e.get(part) or {}
        if not p.get("range"):
            if part == "signature":
                continue   # Wolfi's individual apks carry no per-package signature (the signed index does)
            fail("the lock has no %s range for %s-%s (%s); refusing a package with nothing to check" % (part, e["name"], e["version"], e["architecture"]))
        m = re.fullmatch(r"bytes=([0-9]+)-([0-9]+)", p["range"])
        kind, _, want = p["checksum"].partition("-")
        if not m or kind not in ("sha1", "sha256"):
            fail("cannot read the %s checksum of %s" % (part, e["name"]), 2)
        got = b64(digest(kind, raw[int(m.group(1)):int(m.group(2)) + 1]))
        if got != want:
            fail("checksum mismatch: %s-%s.apk (%s) %s section is %s-%s, the lock says %s-%s"
                 % (e["name"], e["version"], e["architecture"], part, kind, got, kind, want))
    spans = []
    for part in ("signature", "control", "data"):
        pr = e.get(part) or {}
        if pr.get("range"):
            mm = re.fullmatch(r"bytes=([0-9]+)-([0-9]+)", pr["range"])
            spans.append((part, int(mm.group(1)), int(mm.group(2))))
    pos = 0
    for part, lo, hi in spans:
        if lo != pos:
            fail("%s-%s.apk (%s): the %s range starts at byte %d, the previous section ends at %d (ranges must be contiguous)" % (e["name"], e["version"], e["architecture"], part, lo, pos))
        pos = hi + 1
    if pos != len(raw):
        fail("%s-%s.apk (%s): the lock's ranges end at byte %d but the file has %d bytes (bytes after the last range, or a short file: the end of the file is not covered)" % (e["name"], e["version"], e["architecture"], pos, len(raw)))
    ctrl = e["control"]; m = re.fullmatch(r"bytes=([0-9]+)-([0-9]+)", ctrl["range"])
    cbytes = raw[int(m.group(1)):int(m.group(2)) + 1]
    if "Q1" + b64(hashlib.sha1(cbytes).digest()) != e["checksum"]:
        fail("checksum mismatch: %s-%s.apk (%s) package identity differs from the lock" % (e["name"], e["version"], e["architecture"]))
    dm = re.fullmatch(r"bytes=([0-9]+)-([0-9]+)", e["data"]["range"])
    try:
        pk = tarfile.open(fileobj=io.BytesIO(inflate(cbytes, "the control section")[1])).extractfile(".PKGINFO").read().decode()
        dhs = re.findall(r"^datahash = ([0-9a-f]{64})$", pk, re.M)
        if len(dhs) != 1:
            fail("%s-%s.apk (%s): the control section must hold exactly one datahash line (found %d)" % (e["name"], e["version"], e["architecture"], len(dhs)))
        dh = dhs[0]
    except SystemExit:
        raise
    except Exception:
        fail("%s-%s.apk (%s): the control section has no readable .PKGINFO datahash" % (e["name"], e["version"], e["architecture"]))
    if hashlib.sha256(raw[int(dm.group(1)):int(dm.group(2)) + 1]).hexdigest() != dh:
        fail("%s-%s.apk (%s): the data stream does not hash to the datahash in its (checksummed) control section" % (e["name"], e["version"], e["architecture"]))


def ident(e):
    # every field a lock records about the bytes: the package identity checksum, the signature, control and data checksums and their ranges
    sig = e.get("signature") or {}
    return (e["name"], e["version"], e["architecture"], e.get("checksum"), sig.get("checksum"), sig.get("range"),
            e["control"]["checksum"], e["control"].get("range"), e["data"]["checksum"], e["data"].get("range"))


WOLFI_URL = "https://packages.wolfi.dev/os/"


def check_entry(e, where):
    """Names, versions and architectures become archive paths: nothing with a slash, a dot-dot or an unknown architecture gets that far."""
    for k, rx in (("name", NAME_RE), ("version", VERSION_RE)):
        if not isinstance(e.get(k), str) or not rx.fullmatch(e[k]) or ".." in e[k]:
            fail("refused: invalid package %s %r in %s" % (k, e.get(k), where), 2)
    if e.get("architecture") not in ARCHS:
        fail("refused: invalid architecture %r for %s in %s" % (e.get("architecture"), e.get("name"), where), 2)
    u = str(e.get("url", ""))
    if not re.fullmatch(r"https://packages\.wolfi\.dev/os/[A-Za-z0-9._+~/-]+", u):
        fail("refused: the url of %s in %s holds a character outside the plain set (letters, digits and . _ + ~ - /) or is not a packages.wolfi.dev/os address" % (e.get("name"), where), 2)
    try:
        pu = urllib.parse.urlsplit(u)
        port = pu.port
    except ValueError:
        pu, port = None, 0
    if (pu is None or pu.scheme != "https" or pu.hostname != "packages.wolfi.dev" or port is not None or pu.username or pu.password or "@" in u
            or "\\" in u or not pu.path.startswith("/os/") or ".." in pu.path.split("/") or pu.query or pu.fragment or not u.startswith(WOLFI_URL)):
        fail("refused: the url of %s in %s is not a plain https://packages.wolfi.dev/os/ address (host check before anything is fetched)" % (e.get("name"), where), 2)


def load_live(path, archs=ARCHS):
    pk = json.load(open(path))["contents"]["packages"]
    for e in pk:
        check_entry(e, os.path.basename(path))
    pk = [e for e in pk if e["architecture"] in archs]
    per = {a: {e["name"]: e["version"] for e in pk if e["architecture"] == a} for a in ARCHS}
    for a in archs:
        if not per[a]:
            fail("the live lock %s has no package for %s" % (os.path.basename(path), a))
    if len(archs) == len(ARCHS) and per["x86_64"] != per["aarch64"]:
        diff = sorted(n for n in set(per["x86_64"]) | set(per["aarch64"]) if per["x86_64"].get(n) != per["aarch64"].get(n))
        fail("the live lock %s resolves different versions on the two architectures (%s)" % (os.path.basename(path), ", ".join(diff)))
    return pk


def local_url(e): return "/work/archive/%s/%s-%s.apk" % (e["architecture"], e["name"], e["version"])


# ---- what the repository holds now ----
base = {}
for kind, f in (("production", "apko.base.lock.json"), ("fips", "apko-fips.base.lock.json")):
    path = "%s/build/locks/%s" % (repo, f)
    base[kind] = {"path": path, "doc": json.load(open(path))}
old_mel = [l for l in open(repo + "/build/locks/melange.lock").read().splitlines() if l]
old_host = [l for l in open(repo + "/build/locks/host-tools.lock").read().splitlines() if l]
old_vm = {}
for _k in ("vm-host", "vm-guest"):
    old_vm[_k] = [l for l in open("%s/build/locks/%s.lock" % (repo, _k)).read().splitlines() if l]

live = {"production": load_live(tmp + "/production.lock.json"), "fips": load_live(tmp + "/fips.lock.json")}
live_mel = load_live(tmp + "/melange.lock.json")
live_host = load_live(tmp + "/host-tools.lock.json")
live_vm = {k: load_live("%s/%s.lock.json" % (tmp, k), ("x86_64",)) for k in ("vm-host", "vm-guest")}

# ---- the archive's index is re-checked on EVERY run against build/locks/archive-index.sha256 ----
# Damage is unconditional: a stored index that does not hash to its own name, a pointer file that is not the recorded index, or a missing
# pointer stops the job (a human must look). A pointer that is intact but NEWER than the record is the normal state while a refresh PR waits (the archive
# is outside git, so it is always ahead of main until that PR is merged): then an open refresh PR of ours means "wait" (the guard below, nothing changed),
# and with no such PR (it was closed unmerged) the run reconciles: it stores the verified live index and rewrites the record in a new PR.
stage = tmp + "/dl"
archived_key = archive + "/keys/wolfi-signing.rsa.pub"

def check_signature(path, arch, what):
    """an apk index is exactly TWO gzip members (the signature stream, then the index stream), inflated within ONE cumulative limit; a third member is refused
    before it is inflated. The signature is checked against the ARCHIVED Wolfi key. Returns the two decompressed streams' (compressed, data) parts."""
    raw = open(path, "rb").read()
    parts, rest, budget = [], raw, INFLATE_CAP
    try:
        while rest:
            if len(parts) == 2:
                fail("the %s %s package index has more than two gzip members (refused before the rest is inflated)" % (what, arch))
            comp, data, rest = inflate(rest, "the %s %s package index" % (what, arch), budget)
            budget -= len(data)
            parts.append((comp, data))
        tf = tarfile.open(fileobj=io.BytesIO(parts[0][1])); m = tf.getmembers()[0]; sig = tf.extractfile(m).read()
        if len(parts) != 2:
            raise ValueError("an apk index is a signature stream and an index stream")
    except SystemExit:
        raise
    except Exception:
        fail("the %s %s package index is not a signed apk index (a signature stream, then the index stream); signature not verified" % (what, arch))
    mm = re.fullmatch(r"\.SIGN\.RSA(256|512)\.(.+)", m.name)
    if not mm:
        fail("the %s %s package index signature %s is not an RSA-256/512 signature; refused" % (what, arch, m.name))
    alg = "sha" + mm.group(1)
    sp, ip = "%s/index-%s.sig" % (stage, arch), "%s/index-%s.stream" % (stage, arch)
    os.makedirs(stage, exist_ok=True)
    open(sp, "wb").write(sig); open(ip, "wb").write(parts[1][0])
    r = subprocess.run(["/usr/bin/openssl", "dgst", "-" + alg, "-verify", archived_key, "-signature", sp, ip], capture_output=True)
    if r.returncode != 0:
        fail("the %s %s package index signature does not verify against the archived Wolfi key; refused" % (what, arch))
    return parts


def verify_integrity(path, what):
    """For a package that only a committed lock without checksums names (build/locks/melange.lock is name=version): the file must exist and be whole. Every gzip stream
    inflates (the gzip CRC catches truncation and bit flips), there are two or three streams, and the control section's datahash equals the sha256 of the data stream.
    (Authenticity against a checksum is the job of the apko locks; this is the integrity floor for what has none.)"""
    raw = open(path, "rb").read()
    parts, rest, budget = [], raw, INFLATE_CAP
    try:
        while rest:
            if len(parts) == 3:
                raise ValueError("more than three gzip streams")
            comp, data, rest = inflate(rest, what, budget)
            budget -= len(data)
            parts.append((comp, data))
        if len(parts) not in (2, 3):
            raise ValueError("an apk has two or three gzip streams")
        pk = tarfile.open(fileobj=io.BytesIO(parts[-2][1])).extractfile(".PKGINFO").read().decode()
        dhs = re.findall(r"^datahash = ([0-9a-f]{64})$", pk, re.M)
        if len(dhs) != 1 or hashlib.sha256(parts[-1][0]).hexdigest() != dhs[0]:
            raise ValueError("the data stream does not hash to the datahash of the control section")
    except SystemExit:
        raise
    except Exception as ex:
        fail("checksum mismatch: %s is damaged, truncated or not an apk (%s)%s" % (what, str(ex)[:120], HINT))


# the key name written in a package's signature header
HEADER_KEY = "alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub"


def verify_kernel(path, name, ver, want_sha):
    """REQ-REFRESH-001-AC41: an Alpine kernel package is kept only when the whole file hashes to the lock's sha256,
    its signature header names the committed Alpine key and verifies over the control segment, its control segment
    names the lock's package, and its datahash is the sha256 of its data segment. Alpine's package format is not
    read by bin/apk-tool.py, so this is its own step."""
    what = "%s-%s.apk" % (name, ver)
    if os.path.islink(path) or not os.path.isfile(path):
        fail("%s (%s) is a symlink or not a regular file; delete it and run again" % (what, path))
    raw = open(path, "rb").read()
    if hashlib.sha256(raw).hexdigest() != want_sha:
        fail("checksum mismatch: %s does not have the sha256 build/locks/vm-kernel.lock records (hash mismatch)" % what)
    parts, rest, budget = [], raw, INFLATE_CAP
    try:
        while rest:
            if len(parts) == 3:
                raise ValueError("more than three gzip streams")
            comp, data, rest = inflate(rest, what, budget)
            budget -= len(data)
            parts.append((comp, data))
        if len(parts) != 3:
            raise ValueError("a signed Alpine package has a signature, a control and a data stream")
        sig_tar = tarfile.open(fileobj=io.BytesIO(parts[0][1]))
        sig_member = sig_tar.getmembers()[0]
        sig = sig_tar.extractfile(sig_member).read()
        pkginfo = tarfile.open(fileobj=io.BytesIO(parts[1][1])).extractfile(".PKGINFO").read().decode()
    except SystemExit:
        raise
    except Exception as ex:
        fail("%s is not a signed Alpine package (%s)" % (what, str(ex)[:120]))
    m = re.fullmatch(r"\.SIGN\.RSA(256)?\.(.+)", sig_member.name)
    if not m or m.group(2) != HEADER_KEY:
        fail("the signature header of %s (%s) does not name the committed kernel key %s"
             % (what, sig_member.name, HEADER_KEY))
    sp, cp = "%s/kernel.sig" % stage, "%s/kernel.control" % stage
    os.makedirs(stage, exist_ok=True)
    open(sp, "wb").write(sig)
    open(cp, "wb").write(parts[1][0])
    alg = "-sha256" if m.group(1) else "-sha1"
    key_path = "%s/build/vm-keys/%s" % (repo, KEY_FILE)
    if hashlib.sha256(open(key_path, "rb").read()).hexdigest() != KEY_SHA256:
        fail("the committed kernel key %s is not the key whose sha256 this script states; refused" % KEY_FILE)
    cmd = ["/usr/bin/openssl", "dgst", alg, "-verify", key_path, "-signature", sp, cp]
    r = subprocess.run(cmd, capture_output=True)
    if r.returncode != 0:
        fail("the signature of %s does not verify against the committed kernel key %s; refused" % (what, KEY_FILE))
    lines = pkginfo.splitlines()
    for field in ("pkgname", "pkgver", "datahash"):
        if sum(1 for l in lines if l.startswith(field + " = ")) != 1:
            fail("%s: its control segment must hold exactly one %s line" % (what, field))
    info = dict(l.split(" = ", 1) for l in lines if " = " in l)
    if info.get("pkgname") != name or info.get("pkgver") != ver:
        fail("%s: its control segment names %s-%s, the lock row is %s-%s"
             % (what, info.get("pkgname"), info.get("pkgver"), name, ver))
    if info.get("datahash") != hashlib.sha256(parts[2][0]).hexdigest():
        fail("%s: the sha256 of its data segment is not the datahash its control segment records" % what)


# ---- whatever the record says (even when there is none yet): every index file in the archive hashes to its own name, a pointer is a plain file or a link to such a file ----
for _a in ARCHS:
    _idir, _cur = "%s/%s/index" % (archive, _a), "%s/%s/APKINDEX.tar.gz" % (archive, _a)
    if os.path.islink(_idir) or os.path.islink("%s/%s" % (archive, _a)):
        fail("%s/%s (or its index/ directory) is a symlink; every directory on the way into the archive must be a real directory (symlink)" % (archive, _a))
    if os.path.isdir(_idir):
        for _f in sorted(os.listdir(_idir)):
            _mm = re.fullmatch(r"APKINDEX-([0-9a-f]{64})\.tar\.gz", _f)
            if _mm:
                _p = "%s/%s" % (_idir, _f)
                if os.path.islink(_p) or not os.path.isfile(_p) or hashlib.sha256(open(_p, "rb").read()).hexdigest() != _mm.group(1):
                    fail("the index file %s is a link, not a regular file, or does not hash to its own name (hash mismatch); restore it or delete it and run again" % _p)
    if os.path.islink(_cur):   # the pointer is a regular-file COPY of index/APKINDEX-<sha256>.tar.gz (REQ-REFRESH-001-AC13); a link is never followed
        fail("the archive's %s pointer %s is a symlink; it must be a regular-file copy of its index/APKINDEX-<sha256>.tar.gz (symlink)" % (_a, _cur))
    if os.path.isfile(_cur):
        check_signature(_cur, _a, "legacy archived")   # the pointer must be a SIGNED index, whatever the record says and before any early exit
_rec_path = repo + "/build/locks/archive-index.sha256"
ahead = False
ahead_info = []
if os.path.exists(_rec_path):
    _text = open(_rec_path, newline="").read()   # newline="" keeps a carriage return visible: the record is exactly what the job writes
    if not _text.endswith("\n") or "\r" in _text:
        fail("build/locks/archive-index.sha256 is malformed: it must be exactly two lines, each ending in a plain newline (no carriage return, no missing final newline)", 2)
    _lines = _text[:-1].split("\n")
    _rec = {}
    for _l in _lines:
        _mm = re.fullmatch(r"(x86_64|aarch64) sha256:([0-9a-f]{64})", _l)
        if not _mm or _mm.group(1) in _rec:
            fail("build/locks/archive-index.sha256 is malformed (line %r): exactly one 'x86_64 sha256:<hex>' and one 'aarch64 sha256:<hex>' line are expected" % _l, 2)
        _rec[_mm.group(1)] = _mm.group(2)
    if sorted(_rec) != sorted(ARCHS):
        fail("build/locks/archive-index.sha256 is malformed: it must have exactly the two lines x86_64 and aarch64", 2)
    for _a in ARCHS:
        _cur = "%s/%s/APKINDEX.tar.gz" % (archive, _a)
        _idir = "%s/%s/index" % (archive, _a)
        if os.path.islink(_idir) or os.path.islink("%s/%s" % (archive, _a)):
            fail("%s/%s (or its index/ directory) is a symlink; every directory on the way into the archive must be a real directory (symlink)" % (archive, _a))
        # the recorded index itself (what assembly uses) is checked whatever the pointer is: if the file is there it must be a regular file that hashes to its name;
        # if it is absent only a plain pointer that IS the recorded index (the legacy state before the first versioned file) is accepted
        _rf = "%s/APKINDEX-%s.tar.gz" % (_idir, _rec[_a])
        if os.path.lexists(_rf):
            if os.path.islink(_rf) or not os.path.isfile(_rf) or hashlib.sha256(open(_rf, "rb").read()).hexdigest() != _rec[_a]:
                fail("the recorded %s package index %s is a symlink, not a regular file, or does not hash to its name (hash mismatch); assembly would refuse it: a human must look" % (_a, _rf))
        elif os.path.islink(_cur) or not os.path.isfile(_cur) or hashlib.sha256(open(_cur, "rb").read()).hexdigest() != _rec[_a]:
            fail("the recorded %s package index %s is missing (missing index) and the pointer is not a plain file holding it (hash mismatch); restore it from backup: a human must look" % (_a, _rf))
        if os.path.isfile(_cur):
            _ps = hashlib.sha256(open(_cur, "rb").read()).hexdigest()
            if _ps != _rec[_a]:
                # a copy that is not the record is the normal "ahead" state while a refresh PR waits, but only when it is the copy of a stored version
                # (index/APKINDEX-<its sha256>.tar.gz exists; the directory scan above proved it hashes to its name)
                if os.path.isfile("%s/APKINDEX-%s.tar.gz" % (_idir, _ps)) and not os.path.islink("%s/APKINDEX-%s.tar.gz" % (_idir, _ps)):
                    ahead = True
                    ahead_info.append((_a, _ps, _rec[_a]))
                else:
                    fail("the archive's %s package index %s is a plain file that is not the one recorded in build/locks/archive-index.sha256 (hash mismatch); it was replaced or damaged: a human must look" % (_a, _cur))
        else:
            fail("the archive has no %s package index at %s although a record exists (missing index); restore it from index/ and run again" % (_a, _cur))
if ahead:
    print("note: the archive's package index is ahead of build/locks/archive-index.sha256 (a refresh PR is waiting, or one was closed unmerged); looking for an open refresh PR, otherwise reconciling")

# ---- every package any live lock names: verify the archived copy, or fetch the missing one ----
# The archive is checked on EVERY run, for production, FIPS and melange alike: a damaged or truncated file under an unchanged lock is found here
# (a human stop naming the file), not later at build time. The locks must agree with each other about the same package.
groups = {}
for lk in (live["production"], live["fips"], live_mel, live_host, live_vm["vm-host"], live_vm["vm-guest"]):
    for e in lk:
        groups.setdefault((e["name"], e["version"], e["architecture"]), []).append(e)
seen_file = {}
for (n_, v_, a_) in groups:
    f_ = ("%s/%s-%s.apk" % (a_, n_, v_)).lower()   # compared case-insensitively: some file systems would merge them
    if f_ in seen_file and seen_file[f_] != (n_, v_):
        fail("two different packages map to the same archive file %s (%s %s and %s %s); refusing" % (f_.split("/")[1], seen_file[f_][0], seen_file[f_][1], n_, v_))
    seen_file[f_] = (n_, v_)
fresh = {}
for k, es in groups.items():
    if len({ident(e) for e in es}) != 1:
        fail("the production, FIPS, melange and host-tools locks disagree about %s-%s (%s): the same package has different checksums; refusing" % k)
    fresh[k] = es[0]

# the archived inputs the COMMITTED locks (main's) require are checked too: damage to an old version that an upgrade PR leaves behind is found before any guard can return
committed = {}
for kind in ("production", "fips"):
    for e in base[kind]["doc"]["contents"]["packages"]:
        committed.setdefault((e["name"], e["version"], e["architecture"]), []).append(e)
# REQ-REFRESH-001-AC32, the first fill: an archive that holds nothing but the pinned key and a main with no pointer cannot already hold the versions the committed
# locks name, so the ones Wolfi still serves are fetched below and verified before they are archived. Any other state keeps the rule: a missing version stops the job.
def first_fill_state():
    """exactly the key and nothing else: a real archive directory holding one real keys directory that holds one regular file, the pinned key (any other entry,
    whatever its type, a symlinked archive or keys directory, or a listing that cannot be read is not the first-fill state)"""
    if os.path.lexists(repo + "/build/archive.json"):
        return False
    try:
        if os.path.islink(archive) or not os.path.isdir(archive) or os.listdir(archive) != ["keys"]:
            return False
        kd = archive + "/keys"
        if os.path.islink(kd) or not os.path.isdir(kd) or os.listdir(kd) != ["wolfi-signing.rsa.pub"]:
            return False
        return (os.lstat(archived_key).st_mode & 0o170000) == 0o100000
    except OSError:
        return False


FIRST_FILL = first_fill_state()
ff_locked = {}   # (name, version, arch) -> the committed lock entry (checksums): verified like any package
ff_mel = []      # (name, version, arch) named only by the committed melange.lock (name=version): verified against the signed live index
ff_host = []     # the same for the committed host-tools.lock (REQ-REFRESH-001-AC35, AC36)
ff_vm = []       # the same for the committed vm-host.lock and vm-guest.lock (REQ-REFRESH-001-AC39), x86_64 only
for k, es in sorted(committed.items()):
    if len({ident(e) for e in es}) != 1:
        fail("the committed production and FIPS locks disagree about %s-%s (%s): the same package has different checksums; refusing" % k)
    if k in fresh:
        if ident(fresh[k]) != ident(es[0]):
            fail("the committed lock and the live resolution disagree about %s-%s (%s): the same version has different checksums; refusing" % k)
        continue   # also checked below, from the live entry
    dest = "%s/%s/%s-%s.apk" % (archive, k[2], k[0], k[1])
    if not os.path.exists(dest) and FIRST_FILL:
        if not NAME_RE.fullmatch(k[0]) or not VERSION_RE.fullmatch(k[1]) or ".." in k[0] or ".." in k[1] or k[2] not in ARCHS:
            fail("refused: invalid package name, version or architecture %r in the committed lock" % (k,), 2)
        ff_locked[k] = es[0]
        continue
    if not os.path.exists(dest):
        fail("the committed lock names %s-%s.apk (%s), which the archive does not hold; an older version the archive must keep (restore it from backup): a human must look" % k)
    HINT = " (%s is in the archive but is wrong or truncated: delete that file and run again, or find out how it got damaged)" % dest
    verify(dest, es[0])
    HINT = ""
# the committed melange.lock and host-tools.lock (name=version, no checksums) name archived packages too: while an upgrade PR waits, the OLD versions they name are still what main builds from
for _lockname, _old, _ff, _archs in (("melange.lock", old_mel, ff_mel, ARCHS),
                                     ("host-tools.lock", old_host, ff_host, ARCHS),
                                     ("vm-host.lock", old_vm["vm-host"], ff_vm, ["x86_64"]),
                                     ("vm-guest.lock", old_vm["vm-guest"], ff_vm, ["x86_64"])):
  for _l in _old:
    _n, _, _v = _l.partition("=")
    for _a in _archs:
        if (_n, _v, _a) in committed or (_n, _v, _a) in fresh:
            continue   # checked against its lock checksums
        dest = "%s/%s/%s-%s.apk" % (archive, _a, _n, _v)
        if not os.path.exists(dest) and FIRST_FILL:
            if not NAME_RE.fullmatch(_n) or not VERSION_RE.fullmatch(_v) or ".." in _n or ".." in _v:
                fail("refused: invalid package name or version %r in the committed %s" % (_l, _lockname), 2)
            _ff.append((_n, _v, _a))
            continue
        if not os.path.exists(dest):
            fail("the committed %s names %s-%s.apk (%s), which the archive does not hold; an older version the archive must keep (restore it from backup): a human must look" % (_lockname, _n, _v, _a))
        HINT = " (%s is in the archive but is wrong or truncated: delete that file and run again, or find out how it got damaged)" % dest
        verify_integrity(dest, "%s-%s.apk (%s)" % (_n, _v, _a))
        HINT = ""
# the archived files are checked on EVERY run, also while a refresh PR waits (REQ-REFRESH-001-AC17): a damaged file stops the job, whatever else is going on
for (name, ver, arch), e in sorted(fresh.items()):
    dest = "%s/%s/%s-%s.apk" % (archive, arch, name, ver)
    if os.path.exists(dest):
        HINT = " (%s is in the archive but is wrong or truncated: delete that file and run again, or find out how it got damaged)" % dest
        verify(dest, e)
        HINT = ""
# REQ-REFRESH-001-AC33 (rule 12: Go is kept in the archive): the Go tarballs that the committed recipes pin. A pin is the go.dev file name and its sha256; the recipes must agree.
GO_FILE = re.compile(r"go[0-9]+(?:\.[0-9]+){1,2}\.linux-(?:amd64|arm64)\.tar\.gz")
GO_URL = "https://go.dev/dl/"


def go_pins():
    """{file: sha256} of the Go tarballs pinned by build/melange.yaml and build/melange-fips.yaml; every fetch step must be a go.dev/dl uri with a 64-hex pin, and the two
    recipes may not pin one file with two checksums (a pin that is missing, malformed or in conflict stops the job)"""
    pins, seen_in = {}, {}
    for rf in ("melange.yaml", "melange-fips.yaml"):
        try:
            doc = yaml.safe_load(open("%s/build/%s" % (repo, rf)))
            steps = [st for st in (doc.get("pipeline") or []) if isinstance(st, dict) and st.get("uses") == "fetch"]
        except Exception as e_:
            fail("build/%s cannot be read for its Go pins: %s" % (rf, e_), 2)
        for st in steps:
            w_ = st.get("with") if isinstance(st.get("with"), dict) else {}
            uri, sha = str(w_.get("uri", "")), w_.get("expected-sha256")
            if not uri.startswith(GO_URL) or not GO_FILE.fullmatch(uri[len(GO_URL):]):
                fail("build/%s: a fetch step names %r, which is not %s followed by a Go tarball file name; refusing" % (rf, uri, GO_URL), 2)
            f_ = uri[len(GO_URL):]
            if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
                fail("build/%s: the Go fetch of %s has no valid expected-sha256 pin (64 lower-case hex); refusing" % (rf, f_), 2)
            if f_ in pins and pins[f_] != sha:
                fail("build/%s and build/%s pin %s with two different sha256 values; refusing" % (seen_in[f_], rf, f_), 1)
            pins[f_], seen_in[f_] = sha, rf
    return pins


def sha256_file(path):
    h_ = hashlib.sha256()
    with open(path, "rb") as fh_:
        for chunk in iter(lambda: fh_.read(1 << 20), b""):
            h_.update(chunk)
    return h_.hexdigest()


go_pin = go_pins()
go_dir = archive + "/go"
if os.path.lexists(go_dir) and (os.path.islink(go_dir) or not os.path.isdir(go_dir)):
    fail("%s is a symlink or not a directory; the archive's Go directory must be a real directory (nothing was written)" % go_dir, 1)
go_missing = []
for f_, sha_ in sorted(go_pin.items()):
    dest_ = "%s/%s" % (go_dir, f_)
    if os.path.lexists(dest_):
        if os.path.islink(dest_) or not os.path.isfile(dest_) or sha256_file(dest_) != sha_:
            fail("go/%s is in the archive but does not have the sha256 its recipe pins (%s): delete that file and run again, or find out how it got damaged" % (f_, sha_), 1)
    else:
        go_missing.append(f_)
# REQ-REFRESH-001-AC41: an archived kernel package is checked on every run, also while a refresh pull request waits
kernel_missing = []   # (name, version, sha256) of the kernel packages the archive does not hold yet
for _row in open(tmp + "/vm-kernel.rows").read().splitlines():
    k_name, k_ver, k_sha = _row.split(" ")
    k_dest = "%s/x86_64/%s-%s.apk" % (archive, k_name, k_ver)
    if os.path.lexists(k_dest):
        HINT = " (%s is in the archive but is wrong or truncated: delete that file and run again)" % k_dest
        verify_kernel(k_dest, k_name, k_ver, k_sha)
        HINT = ""
        print("checked the archived kernel package %s-%s.apk (sha256, signature, datahash)" % (k_name, k_ver))
    else:
        kernel_missing.append((k_name, k_ver, k_sha))
# only now, before any download: a waiting refresh PR means "wait" (a missing package is fetched by that PR's own run), so a flaky download can never turn a wait into a red run
pkg_missing = any(not os.path.exists("%s/%s/%s-%s.apk" % (archive, a_, n_, v_)) for (n_, v_, a_) in fresh)
if ahead or go_missing or kernel_missing or pkg_missing:
    open_prs_guard("refresh")


def check_dirs():
    """every directory on the way into the archive is a real directory, nothing sits where a temporary name goes"""
    if os.path.islink(archive.rstrip("/") or archive):
        fail("%s is a symlink; the archive directory itself must be a real directory (nothing was written)" % archive)
    for arch in ARCHS:
        for comp in ("%s/%s" % (archive, arch), "%s/%s/index" % (archive, arch)):
            if os.path.islink(comp):
                fail("%s is a symlink; every directory on the way into the archive must be a real directory (nothing was written)" % comp)
        pointer_tmp = "%s/%s/APKINDEX.tar.gz.new" % (archive, arch)
        if os.path.isdir(pointer_tmp) and not os.path.islink(pointer_tmp):
            fail("%s is a directory where the pointer's temporary name goes; remove it (nothing was written)" % pointer_tmp)


def writable(path):
    """every file is written under a temp name in its directory and renamed over its final name: what matters is the DIRECTORY (write and search),
    not the file (a read-only file is simply replaced). A path that is itself a directory cannot be written."""
    if os.path.isdir(path) and not os.path.islink(path):
        return False
    d = os.path.dirname(path)
    while not os.path.exists(d):
        d = os.path.dirname(d)
    return os.path.isdir(d) and os.access(d, os.W_OK | os.X_OK)


def preflight(targets):
    check_dirs()
    for t_ in targets:
        if not writable(t_):
            fail("%s cannot be written: its directory %s is not writable; refusing before anything is changed (nothing was written)" % (t_, os.path.dirname(t_)))


# ---- download, verify, and only then keep ----
stage = tmp + "/dl"
keep = []
want_pk = []
for (name, ver, arch), e in sorted(list(fresh.items()) + list(ff_locked.items())):
    dest = "%s/%s/%s-%s.apk" % (archive, arch, name, ver)
    if os.path.exists(dest):
        HINT = " (%s is in the archive but is wrong or truncated: delete that file and run again, or find out how it got damaged)" % dest
        verify(dest, e)   # same name and version already archived: the bytes must be the same bytes
        HINT = ""
        continue
    part = "%s/%s/%s-%s.apk" % (stage, arch, name, ver)
    os.makedirs(os.path.dirname(part), exist_ok=True)
    if not os.path.exists(part):   # the shell fetches it (download lines of the ruled grammar), then runs this program again
        want_pk.append("%s/%s-%s.apk %s/%s-%s.apk" % (arch, name, ver, arch, name, ver))   # name, version and architecture passed the plain-set check above
        continue
    verify(part, e)
    keep.append((part, dest, name, ver, arch))
ff_mel_parts = []
for (name, ver, arch) in sorted(set(ff_mel) | set(ff_host) | set(ff_vm)):
    part = "%s/%s/%s-%s.apk" % (stage, arch, name, ver)
    os.makedirs(os.path.dirname(part), exist_ok=True)
    if not os.path.exists(part):
        want_pk.append("%s/%s-%s.apk %s/%s-%s.apk" % (arch, name, ver, arch, name, ver))
        continue
    verify_integrity(part, "%s-%s.apk (%s)" % (name, ver, arch))
    ff_mel_parts.append((part, "%s/%s/%s-%s.apk" % (archive, arch, name, ver), name, ver, arch))
if want_pk:
    open(tmp + "/want-packages", "w").write("".join(l + "\n" for l in want_pk))
    sys.exit(75)
# REQ-REFRESH-001-AC41: a kernel package the archive lacks is fetched, checked and kept
want_kn, kernel_added = [], []
for k_name, k_ver, k_sha in kernel_missing:
    k_file = "%s-%s.apk" % (k_name, k_ver)
    k_part = "%s/x86_64/%s" % (stage, k_file)
    os.makedirs(os.path.dirname(k_part), exist_ok=True)
    if not os.path.exists(k_part):
        want_kn.append(k_file)   # the name passed the plain-set grammar of the lock reader
        continue
    verify_kernel(k_part, k_name, k_ver, k_sha)
    print("checked the downloaded kernel package %s (sha256, signature, datahash)" % k_file)
    keep.append((k_part, "%s/x86_64/%s" % (archive, k_file), k_name, k_ver, "x86_64"))
    kernel_added.append(k_file)
if want_kn:
    open(tmp + "/want-kernel", "w").write("".join(f + "\n" for f in want_kn))
    sys.exit(75)
keep_go, want_go = [], []
for f_ in go_missing:
    part = "%s/go/%s" % (stage, f_)
    os.makedirs(os.path.dirname(part), exist_ok=True)
    if not os.path.exists(part):
        want_go.append(f_)       # the file name passed GO_FILE above
        continue
    if sha256_file(part) != go_pin[f_]:
        fail("checksum mismatch: %s fetched from go.dev does not have the sha256 its recipe pins (%s); nothing was stored" % (f_, go_pin[f_]), 1)
    keep_go.append((part, "%s/%s" % (go_dir, f_), f_))
if want_go:
    open(tmp + "/want-go", "w").write("".join(f + "\n" for f in want_go))
    sys.exit(75)


def place(src, dest):
    """copy to an exclusively created temp name (unpredictable, in the destination directory), fsync, then rename: nothing ever appears under
    a final name half-written, and a planted symlink at the temp name is never followed"""
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    t = "%s.tmp-%s" % (dest, secrets.token_hex(8))
    with open(src, "rb") as s_, open(t, "xb") as d_:   # "x" = O_CREAT|O_EXCL
        shutil.copyfileobj(s_, d_)
        d_.flush()
        os.fsync(d_.fileno())
    os.replace(t, dest)


# the archive's package index is the ORIGINAL Wolfi-signed index (apko reads it from the archive without re-signing). It is kept
# IMMUTABLE and VERSIONED by its sha256 (index/APKINDEX-<sha256>.tar.gz) and never overwritten; APKINDEX.tar.gz is a regular-file COPY (never a symlink) of
# the newest one, and the digests are recorded in build/locks/archive-index.sha256. Each index must verify against the ARCHIVED key.
def verify_index(path, arch):
    parts = check_signature(path, arch, "live")
    # the signed index must back the locks: every locked package (name, version, Q1 checksum) of this architecture must be listed in it
    try:
        text = tarfile.open(fileobj=io.BytesIO(parts[1][1])).extractfile("APKINDEX").read().decode()
    except Exception:
        fail("the live %s package index has no readable APKINDEX member" % arch)
    listed = set()
    for st in text.split("\n\n"):
        f = dict(l.split(":", 1) for l in st.split("\n") if len(l) > 2 and l[1] == ":")
        if "P" in f and "V" in f and "C" in f:
            listed.add((f["P"], f["V"], f["C"]))
    index_listed[arch] = listed
    for (_n, _v, _a), _e in sorted(ff_locked.items()):   # a committed version fetched by the first fill is backed by the signed index like every locked package
        if _a == arch and (_n, _v, _e["checksum"]) not in listed:
            fail("the signed %s package index does not list the committed package %s-%s (%s); it cannot be checked against the index, a human must look" % (arch, _n, _v, _e["checksum"]))
    for lockpk in (live["production"], live["fips"], live_mel, live_host, live_vm["vm-host"], live_vm["vm-guest"]):
        for e in lockpk:
            if e["architecture"] == arch and (e["name"], e["version"], e["checksum"]) not in listed:
                fail("the signed %s package index does not list the locked package %s-%s (%s); the lock is not backed by the index, refused" % (arch, e["name"], e["version"], e["checksum"]))


index_parts = {}
index_listed = {}


def fetch_indexes():
    """The live signed index of each architecture, verified against the archived key and the locks; the shell downloads what is missing (exit 75)."""
    want_ix = []
    for arch in ARCHS:
        part = "%s/index/%s/APKINDEX.tar.gz" % (stage, arch)
        os.makedirs(os.path.dirname(part), exist_ok=True)
        if not os.path.exists(part):
            want_ix.append("%s/APKINDEX.tar.gz index/%s/APKINDEX.tar.gz" % (arch, arch))
            continue
        verify_index(part, arch)
        index_parts[arch] = (part, hashlib.sha256(open(part, "rb").read()).hexdigest())
    if want_ix:
        open(tmp + "/want-index", "w").write("".join(l + "\n" for l in want_ix))
        sys.exit(75)


# ---- the new locks ----
changed = []
notes = []
for kind in ("production", "fips"):
    doc = base[kind]["doc"]
    old_pk = doc["contents"]["packages"]
    new_pk = []
    for e in live[kind]:
        e = dict(e); e["url"] = local_url(e); new_pk.append(e)
    if sorted(map(ident, old_pk)) != sorted(map(ident, new_pk)):
        doc["contents"]["packages"] = new_pk
        changed.append(base[kind]["path"])
        newset = {(e["name"], e["version"]) for e in new_pk}
        for e in old_pk:
            if (e["name"], e["version"]) not in newset and e["architecture"] == "x86_64":
                notes.append("%s %s is no longer in live Wolfi's resolution (%s lock); the archived copy is kept" % (e["name"], e["version"], kind))
mel_names = {e["name"]: e["version"] for e in live_mel if e["architecture"] == "x86_64"}
new_mel = sorted("%s=%s" % p for p in mel_names.items())
mel_path = repo + "/build/locks/melange.lock"
host_names = {e["name"]: e["version"] for e in live_host if e["architecture"] == "x86_64"}
new_host = sorted("%s=%s" % p for p in host_names.items())
host_path = repo + "/build/locks/host-tools.lock"
if sorted(old_host) != new_host:
    changed.append(host_path)
    for n, v in sorted(dict(l.split("=", 1) for l in old_host).items()):
        if host_names.get(n) != v:
            notes.append("%s %s is no longer in live Wolfi's resolution (host tools); the archived copy is kept" % (n, v))
vm_new = {}
for _k in ("vm-host", "vm-guest"):
    _names = {e["name"]: e["version"] for e in live_vm[_k] if e["architecture"] == "x86_64"}
    _path = "%s/build/locks/%s.lock" % (repo, _k)
    vm_new[_path] = sorted("%s=%s" % p for p in _names.items())
    if sorted(old_vm[_k]) != vm_new[_path]:
        changed.append(_path)
        for n, v in sorted(dict(l.split("=", 1) for l in old_vm[_k]).items()):
            if _names.get(n) != v:
                notes.append("%s %s is no longer in live Wolfi's resolution (%s); the archived copy is kept"
                             % (n, v, _k))
recipes = {}
if sorted(old_mel) != new_mel:
    changed.append(mel_path)
    old_names = dict(l.split("=", 1) for l in old_mel)
    for n, v in sorted(old_names.items()):
        if mel_names.get(n) != v:
            notes.append("%s %s is no longer in live Wolfi's resolution (melange build tools); the archived copy is kept" % (n, v))
# the recipes are regenerated and compared on EVERY run, whether or not the lock changed: a run interrupted between the lock write and the recipe writes is
# repaired by the next one (the lock is already current, the recipes are not)
# the recipes are GENERATED from the template and the two data files (the melange lock and the FIPS module file): the job edits only the lock, then asks the
# generator what the recipes become. The template and its pin are never touched by an automated change.
gen_dir = tmp + "/gen"
os.makedirs(gen_dir, exist_ok=True)
open(tmp + "/melange.lock.new", "w").write("".join(l + "\n" for l in new_mel))
r_ = subprocess.run(["/usr/bin/python3", "-I", "-B", BINDIR + "/gen-recipes.py", "--template", repo + "/build/melange.yaml.tmpl", "--baselayout-template", repo + "/build/melange-baselayout.yaml.tmpl", "--melange-lock", tmp + "/melange.lock.new",
                     "--fips-module", repo + "/build/locks/fips-module.txt", "--emit", gen_dir], capture_output=True, text=True)
if r_.returncode != 0:
    fail("the recipe generator refused (%s): %s" % (r_.returncode, r_.stderr.strip()[:300]), 1)
for rf in ("melange.yaml", "melange-fips.yaml", "melange-baselayout.yaml"):
    path = "%s/build/%s" % (repo, rf)
    out = open("%s/%s" % (gen_dir, rf)).read()
    if out != open(path).read():
        recipes[path] = out
        changed.append(path)

for n in notes:
    print("note: " + n)
gains = []
if go_missing:
    notes.append("the archive gains the Go toolchain tarball(s) the recipes pin: %s" % ", ".join(go_missing))
    gains.append("Go tarballs")
if kernel_added:
    notes.append("the archive gains the kernel package(s) the VM build boots: %s" % ", ".join(kernel_added))
    gains.append("the kernel package")
if gains:
    _ptr = repo + "/build/archive.json"
    if os.path.exists(_ptr):
        if _ptr not in changed:
            changed.append(_ptr)      # the pointer is rewritten by open-pr once the archive is stored; the pull request exists because the archive gained files
    elif not changed and go_missing:   # a kernel package alone, with no pointer yet, is just put into the archive
        fail("the archive gains Go tarballs but there is no pointer and nothing else changes, so no pull request could carry it; "
             "a human must look", 1)
record_path = repo + "/build/locks/archive-index.sha256"
if not changed and os.path.exists(record_path) and not ahead:
    if keep:
        preflight([dest for _, dest, *_ in keep])
        open_prs_guard("refresh")
        fetch_indexes()   # what was fetched again is kept only after the signed index backs the locks, as on the changing path
    for part, dest, *_ in keep:   # archived packages that were missing are put back (the archive is not in git: there is nothing to commit)
        place(part, dest)
    print("nothing changed against live Wolfi; no commit, no pull request" + ("; %d missing archived package(s) were fetched again" % len(keep) if keep else ""))
    open(tmp + "/changed", "w").write("")
    sys.exit(0)

open_prs_guard("refresh")   # something will change: a waiting refresh PR means "wait", decided BEFORE the live index is downloaded and checked

fetch_indexes()
# the first fill of a version only the committed melange.lock names (it has no checksums): the package's identity checksum (Q1 + sha1 of its control section) must be
# the one the SIGNED live index lists for that name, version and architecture (the signature was checked against the archived key above)
for part, dest, name, ver, arch in ff_mel_parts:
    wants = {c_ for (p_, v_, c_) in index_listed[arch] if p_ == name and v_ == ver}
    if not wants:
        fail("the signed %s package index has no entry for %s-%s, which only a committed melange.lock or host-tools.lock names; it cannot be checked, a human must look" % (arch, name, ver))
    raw_ = open(part, "rb").read(); parts_, rest_, budget_ = [], raw_, INFLATE_CAP
    while rest_:
        comp_, data_, rest_ = inflate(rest_, "%s-%s.apk" % (name, ver), budget_)
        budget_ -= len(data_)
        parts_.append((comp_, data_))
    if "Q1" + b64(hashlib.sha1(parts_[-2][0]).digest()) not in wants:
        fail("checksum mismatch: %s-%s.apk (%s) does not have the package checksum the signed live index lists for it" % (name, ver, arch))
    keep.append((part, dest, name, ver, arch))
# an existing file under a digest name is trusted only if it hashes to that name (a garbage or truncated file from an earlier run fails closed)
for arch in ARCHS:
    vdir, cur = "%s/%s/index" % (archive, arch), "%s/%s/APKINDEX.tar.gz" % (archive, arch)
    cands = ["%s/APKINDEX-%s.tar.gz" % (vdir, index_parts[arch][1])]
    if os.path.exists(cur):
        check_signature(cur, arch, "legacy archived")   # a plain pointer is kept under its own digest only if it is a signed index (the archived Wolfi key)
        cands.append("%s/APKINDEX-%s.tar.gz" % (vdir, hashlib.sha256(open(cur, "rb").read()).hexdigest()))
    for c in cands:
        if os.path.lexists(c):
            named = os.path.basename(c)[len("APKINDEX-"):-len(".tar.gz")]
            if os.path.islink(c) or not os.path.isfile(c) or hashlib.sha256(open(c, "rb").read()).hexdigest() != named:
                fail("the existing index file %s does not hash to its name (garbage, truncated or replaced); refusing, nothing changed" % c)
record_text = "".join("%s sha256:%s\n" % (a, index_parts[a][1]) for a in ARCHS)
if not os.path.exists(record_path) or open(record_path).read() != record_text:
    changed.append(record_path)

# before ANY change: directories, temp names and writability (the same checks the re-fetch path ran)
targets = list(changed) + [dest for _, dest, *_ in keep] + [dest for _, dest, _f in keep_go]
for arch in ARCHS:
    targets += ["%s/%s/APKINDEX.tar.gz" % (archive, arch), "%s/%s/index/APKINDEX-%s.tar.gz" % (archive, arch, index_parts[arch][1])]
preflight(targets)

# everything verified: now the archive and the repository change (each file is written under a temp name and renamed)
for part, dest, *_ in keep:
    place(part, dest)
for part, dest, _f in keep_go:
    place(part, dest)
for arch in ARCHS:
    part, sha = index_parts[arch]
    vdir, cur = "%s/%s/index" % (archive, arch), "%s/%s/APKINDEX.tar.gz" % (archive, arch)
    os.makedirs(vdir, exist_ok=True)
    if os.path.exists(cur):   # the old pointer copy: keep it under its own digest first (a no-op when that version is already stored)
        keepold = "%s/APKINDEX-%s.tar.gz" % (vdir, hashlib.sha256(open(cur, "rb").read()).hexdigest())
        if not os.path.exists(keepold):
            place(cur, keepold)
    dest = "%s/APKINDEX-%s.tar.gz" % (vdir, sha)
    if not os.path.exists(dest):   # absent: write it atomically (a temp file in the same directory, then rename); an existing one was hashed above
        place(part, dest)
    place(dest, cur)   # the pointer is a regular-file COPY of the versioned index (same sha256), written atomically; never a symlink
if record_path in changed:
    write_atomic(record_path, record_text)
for kind in ("production", "fips"):
    if base[kind]["path"] in changed:
        write_atomic(base[kind]["path"], json.dumps(base[kind]["doc"], indent=2) + "\n")
if mel_path in changed:
    write_atomic(mel_path, "".join(l + "\n" for l in new_mel))
if host_path in changed:
    write_atomic(host_path, "".join(l + "\n" for l in new_host))
for _path, _rows in vm_new.items():
    if _path in changed:
        write_atomic(_path, "".join(l + "\n" for l in _rows))
for path, out in recipes.items():
    write_atomic(path, out)

lines = ["- archived go/%s (the Go toolchain a recipe pins, checked against that pin)" % f for _, _, f in keep_go] + ["- archived %s-%s.apk (%s)" % (n, v, a) for _, _, n, v, a in keep] + ["- stored the live signed package index (%s) as index/APKINDEX-%s.tar.gz" % (a, index_parts[a][1]) for a in ARCHS]
supersedes = []
if ahead:   # the reconcile PR says why the index record jumps: it supersedes a refresh PR that was closed unmerged
    prev = None
    r_ = subprocess.run(["/usr/bin/gh", "pr", "list", "--state", "closed", "--limit", "1000", "--json", "number,headRefName,mergedAt,isCrossRepository,author"], cwd=repo, capture_output=True, text=True)
    if r_.returncode == 0:
        try:
            cands = [p_ for p_ in json.loads(r_.stdout) if not p_.get("isCrossRepository") and not p_.get("mergedAt")
                     and str(p_.get("headRefName", "")).startswith("refresh/") and not str(p_.get("headRefName", "")).startswith("refresh/fips-module-")
                     and (not PR_AUTHOR or norm_login((p_.get("author") or {}).get("login") or "") == norm_login(PR_AUTHOR))]
            if cands:
                prev = max(cands, key=lambda p_: int(p_["number"]))
                prev = {"number": int(prev["number"]), "headRefName": str(prev["headRefName"])}
        except (ValueError, TypeError, KeyError, AttributeError):   # any reply shape we do not understand: fall back to the generic sentence
            prev = None
    digs = "; ".join("%s: the record named sha256:%s, the archive held sha256:%s" % (a_, rec_, arch_) for a_, arch_, rec_ in ahead_info)
    if prev:
        supersedes = ["No open refresh pull request was found. The previous refresh pull request #%d (%s) was closed unmerged; this one supersedes it, which is why the index record jumps (%s)." % (prev["number"], prev["headRefName"], digs), ""]
    else:
        supersedes = ["No open refresh pull request was found. A previous refresh pull request was closed unmerged (its number could not be determined); this one supersedes it, which is why the index record jumps (%s)." % digs, ""]
body = "\n".join(["The daily input refresh found changes against live Wolfi.", ""] + supersedes + lines + [""] + ["- " + n for n in notes] + [""] +
                 ["Files: " + ", ".join(os.path.relpath(p, repo) for p in changed), "",
                  "This pull request was only opened, not merged. It goes through all the normal checks and the rebuild-from-archive test; there is no shortcut."])
sig = hashlib.sha256("".join(open(p).read() for p in sorted(changed)).encode()).hexdigest()[:8]
open(tmp + "/changed", "w").write(("\n".join(os.path.relpath(p, repo) for p in changed) + "\n") if changed else "")   # nothing to commit: no PR
open(tmp + "/sig", "w").write(sig)
open(tmp + "/body", "w").write(body)
