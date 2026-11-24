#!/usr/bin/env python3
"""Source admission, Build's first action (REQ-CHAIN-004-AC4, AC5).

    python3 bin/build-admit.py run [--out admission.json]   run from the root of the checkout of the tagged commit, or of a release branch
    python3 bin/build-admit.py list-checks                  one check name per line, in the order they run
    python3 bin/build-admit.py tag-ok [--final] TAG         exit 0 when TAG is a release tag vX.Y.Z, else 1 (--final: the same, kept for its callers)
    python3 bin/build-admit.py tag-pattern                  print TAG_PATTERN, for a step that matches it itself (jq)

The tag, ref and sha come ONLY from the runner environment (GITHUB_REF, GITHUB_REF_NAME, GITHUB_SHA, GITHUB_REPOSITORY, GITHUB_RUN_ID,
GITHUB_RUN_ATTEMPT); an argument naming one is a usage error. They are never put in a shell: every command is an argument list.
On a push of a release/vX.Y.Z branch the branch name without "release/" is used wherever the tag is, and the checks of a tag object
(annotated, signature) do not run.
Policy (allowed signers, the pinned web-flow key, the required checks, the signer router) is read from
origin/main, never from the tagged commit, because the tagged commit is the thing being admitted. GitHub is read with `gh api`
(GET only, no -X / -f / -F / --input) and the JSON is parsed here. The token (GH_TOKEN) is inherited by `gh` and never printed.

Exit 0: admission.json written. Exit 1: the first line of stderr is "admission refused at <check>: <reason>" and no admission.json
is left. Exit 2: usage or environment error.
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile

# The eleven checks, in order. Each is the counterpart of a step of the old stage-admission.yml (bin/chain-admission-old-steps.txt).
CHECKS = [
    "tag-ref", "tag-syntax", "policy-from-main", "tag-annotated", "tag-signature",
    "commit-signature", "ancestor-of-main", "owner-decision", "required-checks", "baseline",
    "admission-evidence",
]

# Fixed program paths: admission runs first, so it cannot trust a PATH an earlier step set.
GIT = "/usr/bin/git"            # TEST-SUBST
GH = "/usr/bin/gh"              # TEST-SUBST
GPG = "/usr/bin/gpg"            # TEST-SUBST
GPGCONF = "/usr/bin/gpgconf"    # TEST-SUBST
SSH_KEYGEN = "/usr/bin/ssh-keygen"  # TEST-SUBST
PYTHON3 = "/usr/bin/python3"    # TEST-SUBST

# The one tag grammar: vX.Y.Z, no leading zeros.
# v1.2.3 matches; v01.2.3 and v1.2.3-rc1 do not.
TAG_PATTERN = r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
TAG_SYNTAX = re.compile(TAG_PATTERN)  # fullmatch: no trailing newline slips through
SHA_SYNTAX = re.compile(r"[0-9a-f]{40}")
SSH_GOOD = re.compile(r'^Good "git" signature for (\S+) with .* key (SHA256:\S+)$', re.M)
OWNER_SSH = "owner-ssh"
RELEASE_BRANCH = "release/"         # a release is built on the branch release/vX.Y.Z before its tag exists: the rest of the name is its version
KMS_RELEASE = "kms-release"         # the one release KMS key, admitted on a patch tag only (REQ-REL-009-AC6)
PATCH_TAG = re.compile(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.[1-9][0-9]*")
# The freeze check (the requirements tool, Go code of the tagged commit) runs in the `freeze` job before Build, not
# here. That job writes this file, one `freeze-ok COMMIT BASE` line per baseline file that passed, and Build's apk job
# downloads it. Admission starts no Go: it reads the file and prints what it trusted.
FREEZE_FILE = "freeze/freeze.txt"
FREEZE_CAP = 65536
FREEZE_LINE = re.compile(r"freeze-ok ([0-9a-f]{40}) (%s)" % TAG_PATTERN)
SIGNER = "bin/admission-tag-signer.py"
# owner-decision (REQ-AUD-17-AC5): main's open-item logic and, when main has it, its items file, read from origin/main into a scratch
# root and never taken from the commit being admitted
AUDIT_RECORD = "bin/audit-record.py"
AUDIT_ITEMS = ".auditor/accepted-items.json"
# the policy inputs read from origin/main, each copied into the policy directory under its file name
RELEASE_SIGNER = ".github/policy/release_tag_signer"    # one ssh-rsa line, the release KMS public key; absent until a human commits it
POLICY_FILES = (".github/policy/allowed_signers", ".github/policy/github-web-flow.gpg", ".github/policy/required-checks.json",
                SIGNER, "bin/build-admit.py",   # the signer loads the tag grammar from the copy beside it
                RELEASE_SIGNER)


class Refusal(Exception):
    """A check refused the tag: exit 1, `admission refused at <step>: <reason>`."""

    def __init__(self, step, reason):
        super().__init__(reason)
        self.step = step
        self.reason = reason


class EnvError(Exception):
    """The environment is wrong (a variable or a tool is missing): exit 2."""


# ---------------------------------------------------------------- small helpers

def text(raw):
    return raw.decode("utf-8", "replace")


def one_line(s, limit=300):
    return " ".join(s.split())[:limit]


def run(argv, env=None):
    """Run one program as an argument list (never a shell): (returncode, stdout bytes, stderr bytes)."""
    try:
        p = subprocess.run(argv, capture_output=True, check=False, env=env)
    except FileNotFoundError as e:
        raise EnvError("required tool not found: %s" % e.filename)
    return p.returncode, p.stdout, p.stderr


def git_show(rev_path):
    """The bytes of `git show REV:PATH`, or None when it does not exist."""
    rc, out, _ = run([GIT, "show", rev_path])
    return out if rc == 0 else None


class Context:
    """What the run knows: the environment, the policy directory, and the evidence the checks collect."""

    def __init__(self, tmp):
        env = os.environ
        self.ref = env["GITHUB_REF"]
        name = env["GITHUB_REF_NAME"]
        self.branch = name if self.ref == "refs/heads/" + name and name.startswith(RELEASE_BRANCH) else None
        self.tag = name[len(RELEASE_BRANCH):] if self.branch else name     # on a release branch: the version its name carries
        self.sha = env["GITHUB_SHA"]
        self.repo = env["GITHUB_REPOSITORY"]
        self.run_id = env["GITHUB_RUN_ID"]
        self.run_attempt = env["GITHUB_RUN_ATTEMPT"]
        self.tmp = tmp
        self.policy = os.path.join(tmp, "policy")
        self.allowed = os.path.join(self.policy, "allowed_signers")
        self.release_signer = os.path.join(self.policy, os.path.basename(RELEASE_SIGNER))
        self.method = None
        self.tag_object = None
        self.principal = None
        self.fingerprint = None
        self.commit_signer = None
        self.verified = []
        self.statuses = []
        self.base = None


# ---------------------------------------------------------------- 1-2. tag-ref, tag-syntax (REQ-CHAIN-004-AC4)

def check_tag_ref(ctx):
    """The ref is a tag ref and GITHUB_REF_NAME is the tag in it, or the ref is a release branch (Context)."""
    if not ctx.branch and (not ctx.ref.startswith("refs/tags/") or ctx.ref != "refs/tags/" + ctx.tag):
        raise Refusal("tag-ref", "admission runs only for tag pushes and pushes of a release/vX.Y.Z branch (got ref %r, name %r)" % (ctx.ref, ctx.tag))


def check_tag_syntax(ctx):
    """The strict release-version syntax, before anything else looks at the tag."""
    if not TAG_SYNTAX.fullmatch(ctx.tag):
        raise Refusal("tag-syntax", "tag %r does not match vMAJOR.MINOR.PATCH" % ctx.tag)


def check_tag_points_at_sha(ctx):
    """The re-tag race: the tag (or the release branch) as it is now must still point at the event's commit (part of tag-ref)."""
    if not SHA_SYNTAX.fullmatch(ctx.sha):
        raise Refusal("tag-ref", "GITHUB_SHA %r is not a full lower-case commit sha" % ctx.sha)
    what = "branch %s" % ctx.branch if ctx.branch else "tag %s" % ctx.tag
    rc, out, _ = run([GIT, "rev-parse", "--verify", "-q", ctx.ref + "^{commit}"])
    if rc != 0:
        raise Refusal("tag-ref", "%s does not exist in the checkout (or does not point at a commit)" % what)
    if text(out).strip() != ctx.sha:
        raise Refusal("tag-ref", "%s points at %s, not at GITHUB_SHA %s (moved after the event)" % (what, text(out).strip(), ctx.sha))


# ---------------------------------------------------------------- 3. policy-from-main

def check_policy_from_main(ctx):
    """Fetch origin/main and copy the policy inputs out of IT, never out of the tagged commit."""
    os.makedirs(ctx.policy)
    rc, _, err = run([GIT, "fetch", "--no-tags", "origin", "main"])
    if rc != 0:
        raise Refusal("policy-from-main", "cannot fetch origin main: %s" % one_line(text(err)))
    for path in POLICY_FILES:
        data = git_show("origin/main:" + path)
        if data is None and path == RELEASE_SIGNER:
            data = b""      # not committed yet: no tag is admitted by that key
        if data is None:
            raise Refusal("policy-from-main", "%s is not on origin/main" % path)
        with open(os.path.join(ctx.policy, os.path.basename(path)), "wb") as fh:
            fh.write(data)


# ---------------------------------------------------------------- 4. tag-annotated

def check_tag_annotated(ctx):
    """A lightweight tag carries no signature: only an annotated tag object is admitted."""
    rc, out, _ = run([GIT, "cat-file", "-t", "refs/tags/" + ctx.tag])
    if rc != 0 or text(out).strip() != "tag":
        raise Refusal("tag-annotated", "%s is not an annotated tag" % ctx.tag)


# ---------------------------------------------------------------- 5. tag-signature (REQ-REL-009-AC6)

def route_tag(ctx):
    """Ask main's bin/admission-tag-signer.py whether an SSH signature decides ('ssh'); anything else is refused:
    a keyless signature on any tag, an unsigned tag, a PGP signature. The owner's SSH signature is accepted on every
    tag; the release KMS key's (also an SSH signature) on a patch tag only (check_tag_signature)."""
    rc, obj, _ = run([GIT, "cat-file", "tag", "refs/tags/" + ctx.tag])
    if rc != 0:
        raise Refusal("tag-signature", "cannot read the tag object of %s" % ctx.tag)
    obj_file = os.path.join(ctx.tmp, "tag-object")
    with open(obj_file, "wb") as fh:
        fh.write(obj)
    ctx.tag_object = obj_file
    signer = os.path.join(ctx.policy, os.path.basename(SIGNER))
    rc, out, err = run([PYTHON3, "-I", signer, "route", "--tag-object", obj_file])
    if rc != 0:
        raise Refusal("tag-signature", "the signer router failed: %s" % one_line(text(err)))
    answer = text(out).strip()
    route = answer.split(" ", 1)[0]
    if route != "ssh":
        raise Refusal("tag-signature", "tag %s refused: %s" % (ctx.tag, answer.partition(" ")[2] or answer))
    return route, obj


def verify_ssh(ctx, verb, ref, signers=None):
    """git verify-tag or verify-commit against one allowed-signers file (default: main's allowed_signers). Returns
    (principal, fingerprint) of the Good "git"
    line, or None. GNUPGHOME is empty, so an OpenPGP signature in the runner's own keyring never counts."""
    home = tempfile.mkdtemp(prefix="gnupg-", dir=ctx.tmp)
    rc, out, err = run([GIT, "-c", "gpg.format=ssh", "-c", "gpg.ssh.program=" + SSH_KEYGEN, "-c", "gpg.program=" + GPG,
        "-c", "gpg.ssh.allowedSignersFile=" + (signers or ctx.allowed), verb, ref],
        env=dict(os.environ, LC_ALL="C", GNUPGHOME=home))
    m = SSH_GOOD.search(text(out + err))
    return m.groups() if rc == 0 and m else None


def verify_tag_ssh(ctx, signers=None):
    """The SSH signature against one allowed-signers file (default: the owner's, main's allowed_signers). Returns
    (principal, fingerprint)."""
    signer = verify_ssh(ctx, "verify-tag", "refs/tags/" + ctx.tag, signers)
    if not signer:
        raise Refusal("tag-signature",
                      "the signature of %s is not a Good git signature of main's allowed signers" % ctx.tag)
    return signer


def check_tag_signature(ctx):
    route_tag(ctx)      # the router refuses everything but an SSH signature
    try:
        ctx.method = OWNER_SSH
        ctx.principal, ctx.fingerprint = verify_tag_ssh(ctx)
    except Refusal:     # the release KMS key signs a patch tag only; no other signer reads its file
        if not PATCH_TAG.fullmatch(ctx.tag) or not os.path.getsize(ctx.release_signer):
            raise
        ctx.method = KMS_RELEASE
        ctx.principal, ctx.fingerprint = verify_tag_ssh(ctx, ctx.release_signer)


# ---------------------------------------------------------------- 6. commit-signature

def verify_commit_web_flow(ctx):
    """GitHub signs UI squash merges with its own GPG key: accept only the key pinned on main. Returns the key id."""
    home = tempfile.mkdtemp(prefix="gnupg-", dir="/tmp")  # a short path: gpg-agent's socket path has a length limit
    env = {"GNUPGHOME": home}
    try:
        key_file = os.path.join(ctx.policy, "github-web-flow.gpg")
        rc, _, err = run([GPG, "--batch", "--quiet", "--import", key_file], env=dict(os.environ, **env))
        if rc != 0:
            raise Refusal("commit-signature", "the pinned web-flow key cannot be imported: %s" % one_line(text(err)))
        rc, _, _ = run([GIT, "-c", "gpg.format=openpgp", "-c", "gpg.program=" + GPG, "verify-commit", ctx.sha],
            env=dict(os.environ, **env))
        if rc != 0:
            raise Refusal("commit-signature", "commit %s verifies against neither the allowed signers nor the pinned web-flow key" % ctx.sha)
        _, out, _ = run([GIT, "log", "-1", "--format=%GK", ctx.sha], env=dict(os.environ, **env))
        return text(out).strip()
    finally:
        run([GPGCONF, "--homedir", home, "--kill", "gpg-agent"])
        shutil.rmtree(home, ignore_errors=True)


def check_commit_signature(ctx):
    if verify_ssh(ctx, "verify-commit", ctx.sha):
        ctx.commit_signer = OWNER_SSH
        return
    ctx.commit_signer = "github-web-flow:" + verify_commit_web_flow(ctx)


# ---------------------------------------------------------------- 7. ancestor-of-main

def check_ancestor_of_main(ctx):
    rc, _, _ = run([GIT, "merge-base", "--is-ancestor", ctx.sha, "origin/main"])
    if rc != 0:
        raise Refusal("ancestor-of-main", "the tagged commit %s is not an ancestor of origin/main" % ctx.sha)


# ---------------------------------------------------------------- 8. owner-decision (REQ-AUD-17-AC5)

def is_on_main(path):
    """True when origin/main has the file; only a path that is not in its tree is absent, any git error refuses."""
    rc, out, err = run([GIT, "ls-tree", "--name-only", "origin/main", "--", path])
    if rc != 0:
        raise Refusal("owner-decision", "git could not list origin/main: %s" % one_line(text(err), 300))
    return out.strip() != b""


def copy_into(root, path, data):
    os.makedirs(os.path.dirname(os.path.join(root, path)), exist_ok=True)
    with open(os.path.join(root, path), "wb") as fh:
        fh.write(data)


def check_owner_decision(ctx):
    """An open owner-decision item (a Critical or KEV acceptance waiting on the owner) holds every release, a patch too, on a tag and
    on a release branch. Whether one is open is decided by main's bin/audit-record.py (held: the open-item logic of its release
    check, with no record and no tag read) over main's .auditor/accepted-items.json. No such file on main: nothing is open; a file
    main lists but that cannot be read refuses. Exit 0 passes; any other exit refuses."""
    root = os.path.join(ctx.tmp, "audit-root")
    data = git_show("origin/main:" + AUDIT_RECORD)
    if data is None:
        raise Refusal("owner-decision", "%s is not on origin/main, so the owner-decision items cannot be judged" % AUDIT_RECORD)
    copy_into(root, AUDIT_RECORD, data)
    if is_on_main(AUDIT_ITEMS):
        data = git_show("origin/main:" + AUDIT_ITEMS)
        if data is None:
            raise Refusal("owner-decision", "%s is on origin/main but cannot be read, so the owner-decision items cannot be judged" % AUDIT_ITEMS)
        copy_into(root, AUDIT_ITEMS, data)
    rc, out, err = run([PYTHON3, "-I", os.path.join(root, AUDIT_RECORD), "held", "--base-root", root])
    why = one_line(text(out) or text(err), 300)
    if rc != 0:
        raise Refusal("owner-decision", why or "main's %s held exited %d" % (AUDIT_RECORD, rc))


# ---------------------------------------------------------------- 9. required-checks (audit F03)

def decode_json_stream(raw):
    """gh api --paginate prints the pages one after the other: decode every JSON value in the stream."""
    values, dec, pos, s = [], json.JSONDecoder(), 0, text(raw)
    while True:
        while pos < len(s) and s[pos].isspace():
            pos += 1
        if pos >= len(s):
            return values
        value, pos = dec.raw_decode(s, pos)
        values.append(value)


def gh_get(path, paginate=False):
    """GET one GitHub API path with `gh api`; returns the list of decoded JSON pages. A failure refuses at required-checks."""
    if paginate:
        rc, out, err = run([GH, "api", path, "--paginate"])
    else:
        rc, out, err = run([GH, "api", path])
    if rc != 0:
        raise Refusal("required-checks", "gh api %s failed: %s" % (path.split("?")[0], one_line(text(err), 120)))
    try:
        return decode_json_stream(out)
    except ValueError:
        raise Refusal("required-checks", "gh api %s returned unreadable JSON" % path.split("?")[0])


def fetch_check_runs(ctx):
    """The check runs of the commit (all pages; the latest of each name) as {name, conclusion, app_id, id, head_sha}."""
    runs = []
    for page in gh_get("repos/%s/commits/%s/check-runs?filter=latest&per_page=100" % (ctx.repo, ctx.sha), paginate=True):
        if not isinstance(page, dict) or not isinstance(page.get("check_runs"), list):
            raise Refusal("required-checks", "the check-runs answer for %s has no check_runs list" % ctx.sha)
        for r in page["check_runs"]:
            app = r.get("app") if isinstance(r.get("app"), dict) else {}
            runs.append({"name": r.get("name"), "conclusion": r.get("conclusion"), "app_id": app.get("id"),
                         "id": r.get("id"), "head_sha": r.get("head_sha")})
    return runs


def fetch_statuses(ctx):
    """Commit statuses: recorded as information only, they never satisfy an app-pinned check."""
    pages = gh_get("repos/%s/commits/%s/status" % (ctx.repo, ctx.sha))
    if len(pages) != 1 or not isinstance(pages[0], dict) or not isinstance(pages[0].get("statuses"), list):
        raise Refusal("required-checks", "the commit status answer has no statuses list")
    return [{"context": s.get("context"), "state": s.get("state"), "id": s.get("id")} for s in pages[0]["statuses"]]


def every_run_green(runs, req, sha):
    """The check run of this name and app on this exact sha that a required check passes on: at least one run, and every run
    completed and success (several green runs pass; any red, cancelled or unfinished one, or none, returns (None, why)). Returns the newest."""
    mine = [r for r in runs if r["name"] == req["context"] and r["app_id"] == req["integration_id"] and r["head_sha"] == sha]
    if not mine or any(r["conclusion"] != "success" or not isinstance(r["id"], int) for r in mine):
        return None, "(app %s) is not green on %s" % (req["integration_id"], sha)
    return max(mine, key=lambda r: r["id"]), None


def read_required_policy(ctx):
    """Main's required-checks.json, validated: an empty list or an unknown scope is a policy error, not a skipped check."""
    try:
        with open(os.path.join(ctx.policy, "required-checks.json"), encoding="utf-8") as fh:
            reqs = json.load(fh)["required_checks"]
    except (ValueError, KeyError, TypeError, OSError) as e:
        raise Refusal("required-checks", "main's required-checks.json is unreadable: %s" % one_line(str(e), 100))
    if not isinstance(reqs, list) or not reqs:
        raise Refusal("required-checks", "main's required-checks.json required_checks is not a non-empty list")
    for r in reqs:
        if not isinstance(r, dict) or not isinstance(r.get("context"), str) or not isinstance(r.get("integration_id"), int):
            raise Refusal("required-checks", "a required check entry in main's policy is malformed: %s" % one_line(json.dumps(r), 100))
        if r.get("scope", "push") != "push":
            raise Refusal("required-checks", "unknown scope %r for required check %r: policy error" % (r["scope"], r["context"]))
    return reqs


def check_required_checks(ctx):
    reqs = read_required_policy(ctx)
    runs = fetch_check_runs(ctx)
    ctx.statuses = fetch_statuses(ctx)
    for req in reqs:
        hit, why = every_run_green(runs, req, ctx.sha)
        if not hit:
            raise Refusal("required-checks", "required check '%s' %s" % (req["context"], why))
        ctx.verified.append({"context": req["context"], "source": "check-run-on-tagged-sha", "evidence_sha": ctx.sha, "id": hit["id"],
                             "conclusion": "success"})


# ---------------------------------------------------------------- 10. baseline (REQ-REL-009-AC13)

def baseline_problems(d, base, tag):
    """Structural validation of an approved baseline: version match, boolean approval, a real date, a non-empty blocking set."""
    if not isinstance(d, dict):
        return ["baseline is not a mapping"]
    errs = []
    if d.get("version") != base:
        errs.append("version is %r, the baseline used is %r (tag %r)" % (d.get("version"), base, tag))
    if d.get("approved") is not True:
        errs.append("approved is %r, not boolean true" % (d.get("approved"),))
    try:
        datetime.date.fromisoformat(str(d.get("approved_on")))
    except (ValueError, TypeError):
        errs.append("approved_on %r is not a real date" % (d.get("approved_on"),))
    acs = d.get("release_blocking_acs")
    if not isinstance(acs, list) or not acs:
        errs.append("release_blocking_acs is empty: an empty required set is not a release baseline")
    return errs


def check_freeze(ctx, base):
    """The freeze job's file has a line for the tagged commit and this base. The prints are log lines; the Build
    record binds the file itself, which Witness hashes as a material before the wrapped step runs."""
    try:
        st = os.lstat(FREEZE_FILE)
    except OSError:
        raise Refusal("baseline", "%s is missing: the freeze job did not run, or its result was not "
            "downloaded" % FREEZE_FILE)
    if not stat.S_ISREG(st.st_mode) or st.st_size > FREEZE_CAP:
        raise Refusal("baseline", "%s is not a regular file of at most %d bytes" % (FREEZE_FILE, FREEZE_CAP))
    with open(FREEZE_FILE, "rb") as fh:
        raw = fh.read()
    lines = text(raw).split("\n")
    found = [FREEZE_LINE.fullmatch(line) for line in lines[:-1]]
    if lines[-1] != "" or not all(found):
        raise Refusal("baseline", "%s holds a line that is not exactly `freeze-ok COMMIT BASE`, or does not end in "
            "a newline" % FREEZE_FILE)
    if (ctx.sha, base) not in [m.groups() for m in found]:
        raise Refusal("baseline", "%s has no freeze-ok for commit %s and baseline %s" % (FREEZE_FILE, ctx.sha, base))
    print("freeze-file-sha256 %s" % hashlib.sha256(raw).hexdigest())
    print("freeze-ok %s %s" % (ctx.sha, base))


def inherited_baseline(ctx):
    """A CI patch uses its line's latest owner-approved baseline, chosen as decide chooses it (REQ-REL-009-AC13).
    Returns the version and that baseline's bytes from the owner's signed tag."""
    signer = os.path.join(ctx.policy, os.path.basename(SIGNER))
    signed = os.path.join(ctx.tmp, "owner-baselines")
    rc, _, err = run([PYTHON3, "-I", signer, "owner-baselines", "--tag", ctx.tag,
        "--allowed-signers", ctx.allowed, "--out", signed])
    if rc != 0:
        raise Refusal("baseline", "the owner-signed baselines cannot be read: %s" % one_line(text(err)))
    requirements = git_show("%s:requirements/requirements.yaml" % ctx.sha)
    if requirements is None:
        raise Refusal("baseline", "requirements/requirements.yaml does not exist at the tagged commit")
    requirements_file = os.path.join(ctx.tmp, "requirements.yaml")
    with open(requirements_file, "wb") as fh:
        fh.write(requirements)
    rc, out, err = run([PYTHON3, "-I", signer, "baseline", "--tag", ctx.tag, "--owner-baselines", signed,
        "--requirements", requirements_file])
    answer = text(out).split()
    if rc != 0 or answer[:1] != ["use"]:
        raise Refusal("baseline", "no owner-approved baseline for %s: %s" % (ctx.tag, one_line(text(out + err), 200)))
    with open(os.path.join(signed, answer[1] + ".yaml"), "rb") as fh:
        return answer[1], fh.read()


def check_baseline(ctx):
    try:
        import yaml
    except ImportError:
        raise EnvError("PyYAML is required")
    base, signed = ctx.tag, None
    # a release branch has no tag signature to choose by: there a patch version takes its line's baseline
    if PATCH_TAG.fullmatch(ctx.tag) if ctx.branch else ctx.method == KMS_RELEASE:
        base, signed = inherited_baseline(ctx)
    ctx.base = base
    path = "requirements/releases/%s.yaml" % base
    tagged = git_show("%s:%s" % (ctx.sha, path))
    if tagged is None:
        raise Refusal("baseline", "%s does not exist at the tagged commit: freeze the release baseline first" % path)
    if signed is not None and tagged != signed:
        raise Refusal("baseline", "%s differs from the owner-signed %s" % (path, base))
    # The freeze job ran the requirements tool: exact requirements hash and complete blocking set (R07). Approval is
    # checked below.
    check_freeze(ctx, base)
    try:
        d = yaml.safe_load(tagged)
    except yaml.YAMLError as e:
        raise Refusal("baseline", "%s is not valid YAML: %s" % (path, one_line(str(e), 100)))
    errs = baseline_problems(d, base, ctx.tag)
    if errs:
        raise Refusal("baseline", "release baseline invalid: " + "; ".join(errs))


# ---------------------------------------------------------------- 11. admission-evidence

def check_admission_evidence(ctx, out_path):
    """Write the canonical admission.json (sorted keys, jq -S layout) so its digest is stable."""
    doc = {
        "tag": ctx.tag,
        "sha": ctx.sha,
        "tag_signature": {"method": ctx.method, "principal": ctx.principal, "key_fingerprint": ctx.fingerprint},
        "commit_signature": ctx.commit_signer,
        "required_checks": ctx.verified,
        "informational_statuses": ctx.statuses,
        "baseline": "requirements/releases/%s.yaml" % ctx.base,
        "baseline_version": ctx.base,
        "run": {"id": int(ctx.run_id), "attempt": int(ctx.run_attempt)},
    }
    if ctx.branch:
        del doc["tag_signature"]
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


# ---------------------------------------------------------------- driver

def read_environment():
    """The tag, ref, sha and run come only from these variables. A variable that is not set at all is an environment error."""
    names = ["GITHUB_REF", "GITHUB_REF_NAME", "GITHUB_SHA", "GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"]
    missing = [n for n in names if n not in os.environ]
    if missing:
        raise EnvError("environment variables not set: %s" % " ".join(missing))
    if not os.environ.get("GH_TOKEN"):      # the token the apk step hands this script (REQ-CHAIN-004-AC8); gh inherits it, it is never printed
        raise EnvError("environment variable not set: GH_TOKEN")
    for n in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        if not re.fullmatch(r"[0-9]+", os.environ[n]):
            raise EnvError("%s is not a number" % n)


def admit(out_path):
    read_environment()
    if os.path.exists(out_path):
        os.remove(out_path)  # a stale file must never survive a refusal
    tmp = tempfile.mkdtemp(prefix="build-admit-")
    try:
        ctx = Context(tmp)
        check_tag_ref(ctx)
        check_tag_syntax(ctx)
        check_tag_points_at_sha(ctx)
        check_policy_from_main(ctx)
        if not ctx.branch:      # a branch has no tag object
            check_tag_annotated(ctx)
            check_tag_signature(ctx)
        check_commit_signature(ctx)
        check_ancestor_of_main(ctx)
        check_owner_decision(ctx)
        check_required_checks(ctx)
        check_baseline(ctx)
        check_admission_evidence(ctx, out_path)
        signer = "" if ctx.branch else " signed by %s (%s)," % (ctx.principal, ctx.method)
        print("admitted %s (%s):%s %d required checks green, baseline %s" % (ctx.tag, ctx.sha, signer, len(ctx.verified), ctx.base))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv):
    ap = argparse.ArgumentParser(prog="build-admit")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list-checks")
    r = sub.add_parser("run")
    r.add_argument("--out", default="admission.json")
    t = sub.add_parser("tag-ok")
    t.add_argument("--final", action="store_true")
    t.add_argument("tag")
    sub.add_parser("tag-pattern")
    args, extra = ap.parse_known_args(argv)
    if extra:
        print("usage error: the tag, ref and sha come only from the environment (GITHUB_REF, GITHUB_REF_NAME, GITHUB_SHA), not from "
              "arguments: %s" % " ".join(extra), file=sys.stderr)
        return 2
    if args.cmd == "list-checks":
        print("\n".join(CHECKS))
        return 0
    if args.cmd == "tag-pattern":
        print(TAG_PATTERN)
        return 0
    if args.cmd == "tag-ok":
        return 0 if TAG_SYNTAX.fullmatch(args.tag) else 1
    try:
        admit(args.out)
    except Refusal as e:
        if os.path.exists(args.out):
            os.remove(args.out)
        print("admission refused at %s: %s" % (e.step, one_line(e.reason, 400)), file=sys.stderr)
        return 1
    except EnvError as e:
        print("environment error: %s" % e, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
