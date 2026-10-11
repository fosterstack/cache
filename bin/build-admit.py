#!/usr/bin/env python3
"""Source admission, Build's first action (REQ-CHAIN-004-AC4, AC5): every check the old stage-admission.yml made, none dropped.

    python3 bin/build-admit.py run [--out admission.json]   run from the root of the checkout of the tagged commit
    python3 bin/build-admit.py list-checks                  one check name per line, in the order they run

The tag, ref and sha come ONLY from the runner environment (GITHUB_REF, GITHUB_REF_NAME, GITHUB_SHA, GITHUB_REPOSITORY, GITHUB_RUN_ID,
GITHUB_RUN_ATTEMPT); an argument naming one is a usage error. They are never put in a shell: every command is an argument list.
Policy (allowed signers, the pinned web-flow key, the required checks, the signer router, the gitsign installer) is read from
origin/main, never from the tagged commit, because the tagged commit is the thing being admitted. GitHub is read with `gh api`
(GET only, no -X / -f / -F / --input) and the JSON is parsed here. The token (GH_TOKEN) is inherited by `gh` and never printed.

Exit 0: admission.json written. Exit 1: the first line of stderr is "admission refused at <check>: <reason>" and no admission.json
is left. Exit 2: usage or environment error.
"""
import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

# The ten checks, in order. Each is the counterpart of a step of the old stage-admission.yml (bin/chain-admission-old-steps.txt).
CHECKS = [
    "tag-ref", "tag-syntax", "policy-from-main", "tag-annotated", "tag-signature",
    "commit-signature", "ancestor-of-main", "required-checks", "baseline", "admission-evidence",
]

TAG_SYNTAX = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?")  # fullmatch: no trailing newline slips through
SHA_SYNTAX = re.compile(r"[0-9a-f]{40}")
BASE_SYNTAX = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+")
SSH_GOOD = re.compile(r'^Good "git" signature for (\S+) with .* key (SHA256:\S+)$', re.M)
KEYLESS = "release-workflow-keyless"
OWNER_SSH = "owner-ssh"
ISSUER = "https://token.actions.githubusercontent.com"
POLICY_FILES = {
    "allowed_signers": ".github/policy/allowed_signers",
    "github-web-flow.gpg": ".github/policy/github-web-flow.gpg",
    "required-checks.json": ".github/policy/required-checks.json",
    "admission-tag-signer.py": "bin/admission-tag-signer.py",
    "install-scanner.sh": "bin/install-scanner.sh",
}


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


def run_cmd(argv, env_extra=None, input_bytes=None):
    """Run an argument list (never a shell). Returns (returncode, stdout bytes, stderr bytes)."""
    env = dict(os.environ)
    env.update(env_extra or {})
    try:
        p = subprocess.run(argv, input=input_bytes, capture_output=True, env=env, check=False)
    except FileNotFoundError:
        raise EnvError("required tool not found: %s" % argv[0])
    return p.returncode, p.stdout, p.stderr


def git_show(rev_path):
    """The bytes of `git show REV:PATH`, or None when it does not exist."""
    rc, out, _ = run_cmd(["git", "show", rev_path])
    return out if rc == 0 else None


class Context:
    """What the run knows: the environment, the policy directory, and the evidence the checks collect."""

    def __init__(self, tmp):
        env = os.environ
        self.ref = env["GITHUB_REF"]
        self.tag = env["GITHUB_REF_NAME"]
        self.sha = env["GITHUB_SHA"]
        self.repo = env["GITHUB_REPOSITORY"]
        self.run_id = env["GITHUB_RUN_ID"]
        self.run_attempt = env["GITHUB_RUN_ATTEMPT"]
        self.tmp = tmp
        self.policy = os.path.join(tmp, "policy")
        self.allowed = os.path.join(self.policy, "allowed_signers")
        self.method = None
        self.principal = None
        self.fingerprint = None
        self.commit_signer = None
        self.verified = []
        self.statuses = []
        self.base = None


# ---------------------------------------------------------------- 1-2. tag-ref, tag-syntax (REQ-CHAIN-004-AC4)

def check_tag_ref(ctx):
    """The ref is a tag ref and GITHUB_REF_NAME is the tag in it."""
    if not ctx.ref.startswith("refs/tags/") or ctx.ref != "refs/tags/" + ctx.tag:
        raise Refusal("tag-ref", "admission runs only for tag pushes (got ref %r, name %r)" % (ctx.ref, ctx.tag))


def check_tag_syntax(ctx):
    """The strict release-version syntax, before anything else looks at the tag."""
    if not TAG_SYNTAX.fullmatch(ctx.tag):
        raise Refusal("tag-syntax", "tag %r does not match vMAJOR.MINOR.PATCH[-rc.N]" % ctx.tag)


def check_tag_points_at_sha(ctx):
    """The re-tag race: the tag as it is now must still point at the event's commit (part of tag-ref)."""
    if not SHA_SYNTAX.fullmatch(ctx.sha):
        raise Refusal("tag-ref", "GITHUB_SHA %r is not a full lower-case commit sha" % ctx.sha)
    rc, out, _ = run_cmd(["git", "rev-parse", "--verify", "-q", "refs/tags/%s^{commit}" % ctx.tag])
    if rc != 0:
        raise Refusal("tag-ref", "tag %s does not exist in the checkout (or does not point at a commit)" % ctx.tag)
    if text(out).strip() != ctx.sha:
        raise Refusal("tag-ref", "tag %s points at %s, not at GITHUB_SHA %s (moved after the event)" % (ctx.tag, text(out).strip(), ctx.sha))


# ---------------------------------------------------------------- 3. policy-from-main

def check_policy_from_main(ctx):
    """Fetch origin/main and copy the policy inputs out of IT, never out of the tagged commit."""
    os.makedirs(ctx.policy)
    rc, _, err = run_cmd(["git", "fetch", "--no-tags", "origin", "main"])
    if rc != 0:
        raise Refusal("policy-from-main", "cannot fetch origin main: %s" % one_line(text(err)))
    for name, path in POLICY_FILES.items():
        data = git_show("origin/main:" + path)
        if data is None:
            raise Refusal("policy-from-main", "%s is not on origin/main" % path)
        with open(os.path.join(ctx.policy, name), "wb") as fh:
            fh.write(data)


# ---------------------------------------------------------------- 4. tag-annotated

def check_tag_annotated(ctx):
    """A lightweight tag carries no signature: only an annotated tag object is admitted."""
    rc, out, _ = run_cmd(["git", "cat-file", "-t", "refs/tags/" + ctx.tag])
    if rc != 0 or text(out).strip() != "tag":
        raise Refusal("tag-annotated", "%s is not an annotated tag" % ctx.tag)


# ---------------------------------------------------------------- 5. tag-signature (REQ-REL-009-AC6)

def route_tag(ctx):
    """Ask main's bin/admission-tag-signer.py which verifier applies: 'ssh' or 'gitsign'. Anything else is refused."""
    rc, obj, _ = run_cmd(["git", "cat-file", "tag", "refs/tags/" + ctx.tag])
    if rc != 0:
        raise Refusal("tag-signature", "cannot read the tag object of %s" % ctx.tag)
    obj_file = os.path.join(ctx.tmp, "tag-object")
    tags_file = os.path.join(ctx.tmp, "released-tags")
    with open(obj_file, "wb") as fh:
        fh.write(obj)
    _, tags, _ = run_cmd(["git", "tag", "-l", "v*"])
    with open(tags_file, "wb") as fh:
        fh.write(tags)
    rc, out, err = run_cmd(["python3", os.path.join(ctx.policy, "admission-tag-signer.py"), "route", "--tag", ctx.tag,
                            "--tag-object", obj_file, "--tags", tags_file])
    if rc != 0:
        raise Refusal("tag-signature", "the signer router failed: %s" % one_line(text(err)))
    answer = text(out).strip()
    route = answer.split(" ", 1)[0]
    if route not in ("ssh", "gitsign"):
        raise Refusal("tag-signature", "tag %s refused: %s" % (ctx.tag, answer.partition(" ")[2] or answer))
    return route, obj


def verify_tag_ssh(ctx):
    """The owner's SSH signature against main's allowed signers. Returns (principal, fingerprint)."""
    rc, out, err = run_cmd(["git", "-c", "gpg.ssh.allowedSignersFile=" + ctx.allowed, "verify-tag", "refs/tags/" + ctx.tag],
                           {"LC_ALL": "C"})
    if rc != 0:
        raise Refusal("tag-signature", "the signature of %s does not verify against main's allowed signers" % ctx.tag)
    m = SSH_GOOD.search(text(out + err))
    if not m:
        raise Refusal("tag-signature", "signature verified but signer metadata could not be extracted: refusing to admit with empty evidence")
    return m.group(1), m.group(2)


def x509_fingerprint(tag_object):
    """sha256 fingerprint of the certificate in the gitsign block of the tag object, or '' when it cannot be read."""
    m = re.search(r"^-----BEGIN SIGNED MESSAGE-----\n.*?^-----END SIGNED MESSAGE-----$", text(tag_object), re.S | re.M)
    if not m:
        return ""
    pem = m.group(0).replace("SIGNED MESSAGE", "PKCS7").encode()
    rc, certs, _ = run_cmd(["openssl", "pkcs7", "-print_certs"], input_bytes=pem)
    if rc != 0 or not certs.strip():
        return ""
    rc, out, _ = run_cmd(["openssl", "x509", "-noout", "-fingerprint", "-sha256"], input_bytes=certs)
    f = re.search(r"^sha256 Fingerprint=(\S+)$", text(out), re.I | re.M)
    return "x509-sha256:" + f.group(1) if rc == 0 and f else ""


def verify_tag_keyless(ctx, tag_object):
    """The release workflow's keyless identity on a patch tag, via gitsign. Returns (principal, fingerprint)."""
    rc, _, err = run_cmd(["bash", os.path.join(ctx.policy, "install-scanner.sh"), "gitsign"])
    if rc != 0:
        raise Refusal("tag-signature", "installing gitsign failed: %s" % one_line(text(err)))
    identity = "https://github.com/%s/.github/workflows/release.yml@refs/heads/main" % ctx.repo
    rc, _, err = run_cmd(["gitsign", "verify-tag", ctx.tag, "--certificate-identity", identity, "--certificate-oidc-issuer", ISSUER,
                          "--certificate-github-workflow-repository", ctx.repo, "--certificate-github-workflow-ref", "refs/heads/main",
                          "--certificate-github-workflow-sha", ctx.sha])
    if rc != 0:
        raise Refusal("tag-signature", "gitsign verify-tag refused %s: %s" % (ctx.tag, one_line(text(err))))
    return identity, x509_fingerprint(tag_object)


def check_tag_signature(ctx):
    route, tag_object = route_tag(ctx)
    if route == "ssh":
        ctx.method = OWNER_SSH
        ctx.principal, ctx.fingerprint = verify_tag_ssh(ctx)
    else:
        ctx.method = KEYLESS
        ctx.principal, ctx.fingerprint = verify_tag_keyless(ctx, tag_object)
    if not ctx.principal or not ctx.fingerprint:
        raise Refusal("tag-signature", "tag signature verified but signer metadata could not be extracted: no empty evidence is admitted")


# ---------------------------------------------------------------- 6. commit-signature

def verify_commit_web_flow(ctx):
    """GitHub signs UI squash merges with its own GPG key: accept only the key pinned on main. Returns the key id."""
    home = tempfile.mkdtemp(prefix="gnupg-", dir="/tmp")  # a short path: gpg-agent's socket path has a length limit
    os.chmod(home, 0o700)
    env = {"GNUPGHOME": home}
    try:
        rc, _, err = run_cmd(["gpg", "--batch", "--quiet", "--import", os.path.join(ctx.policy, "github-web-flow.gpg")], env)
        if rc != 0:
            raise Refusal("commit-signature", "the pinned web-flow key cannot be imported: %s" % one_line(text(err)))
        rc, _, _ = run_cmd(["git", "-c", "gpg.format=openpgp", "verify-commit", ctx.sha], env)
        if rc != 0:
            raise Refusal("commit-signature", "commit %s verifies against neither the allowed signers nor the pinned web-flow key" % ctx.sha)
        _, out, _ = run_cmd(["git", "log", "-1", "--format=%GK", ctx.sha], env)
        keyid = text(out).strip()
        _, keys, _ = run_cmd(["gpg", "--list-keys", "--with-colons"], env)
        if not keyid or not re.search(r"^(pub|sub):.*:%s:" % re.escape(keyid), text(keys), re.M):
            raise Refusal("commit-signature", "commit %s is signed by %s, which is not in the pinned web-flow keyring" % (ctx.sha, keyid))
        return keyid
    finally:
        run_cmd(["gpgconf", "--homedir", home, "--kill", "gpg-agent"])
        shutil.rmtree(home, ignore_errors=True)


def check_commit_signature(ctx):
    rc, _, _ = run_cmd(["git", "-c", "gpg.ssh.allowedSignersFile=" + ctx.allowed, "verify-commit", ctx.sha])
    if rc == 0:
        ctx.commit_signer = OWNER_SSH
        return
    ctx.commit_signer = "github-web-flow:" + verify_commit_web_flow(ctx)


# ---------------------------------------------------------------- 7. ancestor-of-main

def check_ancestor_of_main(ctx):
    rc, _, _ = run_cmd(["git", "merge-base", "--is-ancestor", ctx.sha, "origin/main"])
    if rc != 0:
        raise Refusal("ancestor-of-main", "the tagged commit %s is not an ancestor of origin/main" % ctx.sha)


# ---------------------------------------------------------------- 8. required-checks (audit F02, F03)

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
    argv = ["gh", "api", path] + (["--paginate"] if paginate else [])
    rc, out, err = run_cmd(argv)
    if rc != 0:
        raise Refusal("required-checks", "gh api %s failed: %s" % (path.split("?")[0], one_line(text(err), 120)))
    try:
        return decode_json_stream(out)
    except ValueError:
        raise Refusal("required-checks", "gh api %s returned unreadable JSON" % path.split("?")[0])


def fetch_check_runs(ctx, sha):
    """Every latest check run of a commit (all pages) as {name, conclusion, app_id, id, head_sha}."""
    runs = []
    for page in gh_get("repos/%s/commits/%s/check-runs?filter=latest&per_page=100" % (ctx.repo, sha), paginate=True):
        if not isinstance(page, dict) or not isinstance(page.get("check_runs"), list):
            raise Refusal("required-checks", "the check-runs answer for %s has no check_runs list" % sha)
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


def find_merged_pr(ctx):
    """The merged PR whose squash produced exactly this commit (merge_commit_sha equal, base main, merged), or None."""
    pages = gh_get("repos/%s/commits/%s/pulls" % (ctx.repo, ctx.sha))
    prs = [p for page in pages if isinstance(page, list) for p in page if isinstance(p, dict)]
    for p in prs:
        base = p.get("base") if isinstance(p.get("base"), dict) else {}
        head = p.get("head") if isinstance(p.get("head"), dict) else {}
        if p.get("merge_commit_sha") == ctx.sha and base.get("ref") == "main" and p.get("merged_at") and SHA_SYNTAX.fullmatch(str(head.get("sha"))):
            return {"number": p.get("number"), "head_sha": head["sha"]}
    return None


def one_green_run(runs, req, sha):
    """The ONE successful check run of this name and app on this exact sha; none, several or a failure returns (None, why)."""
    mine = [r for r in runs if r["name"] == req["context"] and r["app_id"] == req["integration_id"] and r["head_sha"] == sha]
    if len(mine) > 1:
        return None, "is ambiguous: %d runs of it (app %s) on %s" % (len(mine), req["integration_id"], sha)
    if not mine or mine[0]["conclusion"] != "success" or not isinstance(mine[0]["id"], int):
        return None, "(app %s) is not green on %s" % (req["integration_id"], sha)
    return mine[0], None


def read_required_policy(ctx):
    """Main's required-checks.json, validated: an unknown scope is a policy error, not a skipped check."""
    try:
        with open(os.path.join(ctx.policy, "required-checks.json"), encoding="utf-8") as fh:
            reqs = json.load(fh)["required_checks"]
    except (ValueError, KeyError, TypeError, OSError) as e:
        raise Refusal("required-checks", "main's required-checks.json is unreadable: %s" % one_line(str(e), 100))
    if not isinstance(reqs, list):
        raise Refusal("required-checks", "main's required_checks is not a list")
    out = []
    for r in reqs:
        if not isinstance(r, dict) or not isinstance(r.get("context"), str) or not isinstance(r.get("integration_id"), int):
            raise Refusal("required-checks", "a required check entry in main's policy is malformed: %s" % one_line(json.dumps(r), 100))
        scope = r.get("scope", "push")
        if scope not in ("push", "pull_request"):
            raise Refusal("required-checks", "unknown scope %r for required check %r: policy error" % (scope, r["context"]))
        out.append({"context": r["context"], "integration_id": r["integration_id"], "scope": scope})
    return out


def check_required_checks(ctx):
    reqs = read_required_policy(ctx)
    sha_runs = fetch_check_runs(ctx, ctx.sha)
    ctx.statuses = fetch_statuses(ctx)
    pr = find_merged_pr(ctx)
    pr_runs = fetch_check_runs(ctx, pr["head_sha"]) if pr and any(r["scope"] == "pull_request" for r in reqs) else []
    for req in reqs:
        ctx_name = req["context"]
        if req["scope"] == "push":
            hit, why = one_green_run(sha_runs, req, ctx.sha)
            if not hit:
                raise Refusal("required-checks", "required check '%s' %s" % (ctx_name, why))
            ctx.verified.append({"context": ctx_name, "source": "check-run-on-tagged-sha", "evidence_sha": ctx.sha, "id": hit["id"],
                                 "conclusion": "success"})
        else:
            if not pr:
                raise Refusal("required-checks", "required check '%s' is pull_request-scoped but no merged PR produced this exact commit" % ctx_name)
            hit, why = one_green_run(pr_runs, req, pr["head_sha"])
            if not hit:
                raise Refusal("required-checks", "required check '%s' %s (head of merged PR #%s)" % (ctx_name, why, pr["number"]))
            ctx.verified.append({"context": ctx_name, "source": "check-run-on-merged-pr-head", "pr": pr["number"],
                                 "evidence_sha": pr["head_sha"], "id": hit["id"], "conclusion": "success"})
    if len(ctx.verified) != len(reqs):
        raise Refusal("required-checks", "verified %d of %d required checks" % (len(ctx.verified), len(reqs)))


# ---------------------------------------------------------------- 9. baseline (REQ-REL-009-AC13)

def patch_baseline_version(ctx):
    """A CI-signed patch tag uses the latest OWNER-signed baseline of its line, by main's signer script. Returns the version."""
    script = os.path.join(ctx.policy, "admission-tag-signer.py")
    owner_dir = os.path.join(ctx.tmp, "owner-baselines")
    rc, _, err = run_cmd(["python3", script, "owner-baselines", "--tag", ctx.tag, "--allowed-signers", ctx.allowed, "--out", owner_dir])
    if rc != 0:
        raise Refusal("baseline", "owner-baselines failed: %s" % one_line(text(err)))
    tagged_req = git_show("%s:requirements/requirements.yaml" % ctx.sha)
    if tagged_req is None:
        raise Refusal("baseline", "requirements/requirements.yaml does not exist at the tagged commit")
    req_file = os.path.join(ctx.tmp, "tagged-requirements.yaml")
    with open(req_file, "wb") as fh:
        fh.write(tagged_req)
    rc, out, err = run_cmd(["python3", script, "baseline", "--tag", ctx.tag, "--owner-baselines", owner_dir, "--requirements", req_file])
    answer = text(out).strip()
    parts = answer.split(" ", 2)
    if rc != 0 or len(parts) < 2 or parts[0] != "use" or not BASE_SYNTAX.fullmatch(parts[1]):
        why = answer[3:].strip() if answer.startswith("no ") else (answer or one_line(text(err)))
        raise Refusal("baseline", "%s has no usable ACs baseline: %s" % (ctx.tag, why))
    return parts[1]


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


def check_baseline(ctx):
    try:
        import yaml
    except ImportError:
        raise EnvError("PyYAML is required")
    base = patch_baseline_version(ctx) if ctx.method == KEYLESS else ctx.tag
    ctx.base = base
    path = "requirements/releases/%s.yaml" % base
    tagged = git_show("%s:%s" % (ctx.sha, path))
    if tagged is None:
        raise Refusal("baseline", "%s does not exist at the tagged commit: freeze the release baseline first" % path)
    if ctx.method == KEYLESS:
        owner_copy = git_show("refs/tags/%s:%s" % (base, path))
        if owner_copy != tagged:
            raise Refusal("baseline", "%s at the tagged commit differs from the copy in the owner-signed %s" % (path, base))
    # The requirements tool proves the exact requirements hash and the complete blocking set (R07); approval is checked below.
    rc, _, err = run_cmd(["go", "-C", "tools/requirements", "run", ".", "verify-freeze", base], {"GOTOOLCHAIN": "local"})
    if rc != 0:
        raise Refusal("baseline", "the freeze check (verify-freeze %s) failed: %s" % (base, one_line(text(err), 200)))
    try:
        d = yaml.safe_load(tagged)
    except yaml.YAMLError as e:
        raise Refusal("baseline", "%s is not valid YAML: %s" % (path, one_line(str(e), 100)))
    errs = baseline_problems(d, base, ctx.tag)
    if errs:
        raise Refusal("baseline", "release baseline invalid: " + "; ".join(errs))


# ---------------------------------------------------------------- 10. admission-evidence

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
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


# ---------------------------------------------------------------- driver

def read_environment():
    """The tag, ref, sha and run come only from these variables. A variable that is not set at all is an environment error."""
    names = ["GITHUB_REF", "GITHUB_REF_NAME", "GITHUB_SHA", "GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"]
    missing = [n for n in names if n not in os.environ]
    if missing:
        raise EnvError("environment variables not set: %s" % " ".join(missing))
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
        check_tag_annotated(ctx)
        check_tag_signature(ctx)
        check_commit_signature(ctx)
        check_ancestor_of_main(ctx)
        check_required_checks(ctx)
        check_baseline(ctx)
        check_admission_evidence(ctx, out_path)
        print("admitted %s (%s): signed by %s (%s), %d required checks green, baseline %s" %
              (ctx.tag, ctx.sha, ctx.principal, ctx.method, len(ctx.verified), ctx.base))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv):
    ap = argparse.ArgumentParser(prog="build-admit")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list-checks")
    r = sub.add_parser("run")
    r.add_argument("--out", default="admission.json")
    args, extra = ap.parse_known_args(argv)
    if extra:
        print("usage error: the tag, ref and sha come only from the environment (GITHUB_REF, GITHUB_REF_NAME, GITHUB_SHA), not from "
              "arguments: %s" % " ".join(extra), file=sys.stderr)
        return 2
    if args.cmd == "list-checks":
        print("\n".join(CHECKS))
        return 0
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
