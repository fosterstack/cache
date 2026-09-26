#!/usr/bin/env python3
"""Auditor entrypoint (REQ-AUD-12; called by .github/workflows/auditor.yml).

Round 13: the report must let the owner know what happened, and §3 is never a resting place.
Routing is DETERMINISTIC from scanner data before any model call:
  * a trusted known-defect-log row -> closed not_affected (§5), no model call;
  * a Go module (we build) that govulncheck proves imported-but-not-called -> not_affected
    unreachable (§5), no model call;
  * a fix that exists in something we build (a Go module, or the base image digest we pin)
    -> a bump / base-rebuild PR (§3), each row carrying its action;
  * no upstream fix (Debian no-dsa / unfixed / TEMP-* / DLA) -> a POA&M: affected VEX +
    time-boxed ignores + expiry (§2), at/above threshold (Critical / KEV / known-exploited)
    -> an owner-decision issue as well.
The model is consulted ONLY for false-positive suspicion (a finding unique to one scanner
lineage) and for reachability where govulncheck applies. §4 holds only model refusals after
the fallback chain and evidence conflicts, each with its reason.

Every row explains itself on one line. The header says what was audited, each scanner's
package + finding counts with database dates, dry_run and adjudicator mode, and a run-status
line: AUDIT COMPLETE, or AUDIT INCOMPLETE (which FAILS the job). A dry run lists in §6 every
PR and issue it would have opened.
"""
import os, sys, json, re, shlex, subprocess, importlib.util
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from auditorlib import cli, policy
from auditorlib import vex
from auditorlib import knowledge as K

_spec = importlib.util.spec_from_file_location("auditor_classify", os.path.join(HERE, "auditor-classify.py"))
C = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(C)
IMAGE_SCANNERS = ("grype", "trivy", "osv-scanner", "snyk")

# Identifiers/tokens that must never reach the uploaded report. We surface the REAL adjudicator
# error (class, HTTP status, message) so a failure is diagnosable, but with these values redacted.
_SECRET_ENVS = ("ANTHROPIC_FEDERATION_RULE_ID", "ANTHROPIC_ORGANIZATION_ID",
                "ANTHROPIC_SERVICE_ACCOUNT_ID", "ANTHROPIC_WORKSPACE_ID",
                "AUDITOR_MODEL_PRIMARY", "AUDITOR_MODEL_FALLBACK", "SNYK_TOKEN",
                "AUDITOR_APP_PRIVATE_KEY", "ANTHROPIC_API_KEY")


def _mask(s):
    """Redact secret values and any model-id/token shapes from text before it is printed or
    written into the report (REQ-AUD-6: identifiers never leak; R-live fix 1: surface the error)."""
    s = str(s or "")
    for k in _SECRET_ENVS:
        v = os.environ.get(k)
        if v and len(v) >= 4:
            s = s.replace(v, "<%s>" % k)
    s = re.sub(r"claude-[A-Za-z0-9._-]+", "<model-id>", s)
    s = re.sub(r"sk-[A-Za-z0-9._-]{6,}", "<redacted-key>", s)
    s = re.sub(r"(?i)bearer\s+[A-Za-z0-9._-]{6,}", "Bearer <redacted>", s)
    return s.strip()


def _sub_purl(sc):
    """A subcomponent's package-URL, from either `@id` or `identifiers.purl` (the OpenVEX
    schema permits both), so the scope key is representation-invariant (R1 refactor round-1 #2)."""
    return sc.get("@id") or ((sc.get("identifiers") or {}).get("purl"))


def _scope_key(statement):
    """The canonical scope of a VEX statement (REQ-AUD-13 AC1): (sorted product @ids, the sorted
    SET of subcomponent package-URLs). Order- and representation-insensitive and de-duplicated;
    any difference in either member is a distinct scope."""
    prods = tuple(sorted((p.get("@id") or "") for p in statement.get("products", [])))
    subs = tuple(sorted({_sub_purl(sc)
                         for p in statement.get("products", []) for sc in (p.get("subcomponents") or [])
                         if _sub_purl(sc)}))
    return (prods, subs)


def _real_gh_allowed():
    """Real git/gh side effects run ONLY when the workflow explicitly opts in
    (AUDITOR_ALLOW_REAL_GH=1). Otherwise a non-dry run outside the test shim prints what it
    would do and executes nothing — so running the driver locally (a probe, a manual test)
    can never create branches, commits, PRs, or issues by accident."""
    return os.environ.get("AUDITOR_ALLOW_REAL_GH") == "1"


def _emit_create(cmd, dry, would):
    """A create action. dry-run records it in the §6 would-open list and PRINTS it; a real
    run writes to the test-only shim ledger when AUDITOR_GIT_SHIM_LOG is set (the suite),
    else runs real `gh`."""
    if dry:
        would.append(cmd)
        print("dry-run would create: " + cmd)
        return
    log = os.environ.get("AUDITOR_GIT_SHIM_LOG")
    if log:
        open(log, "a").write(cmd + "\n")
    elif not _real_gh_allowed():
        print("would (real gh disabled): " + cmd)
    else:
        try:
            subprocess.run(shlex.split(cmd), check=False)
        except Exception as e:
            print("create failed (%s): %s" % (cmd, e))


def _issue_pending_note(ref):
    """Honest action wording when an owner issue was NOT actually delivered but did not fail:
    a dry-run preview ("dry") or a real run with gh delivery disabled ("skipped"). Never say
    "opened" for these — the row must not contradict the PR list's "would open" (Codex R3 blk)."""
    return "would open (dry run)" if ref == "dry" else "delivery disabled (gh off)"


def log_index(logpath):
    idx = {}
    if logpath and os.path.exists(logpath):
        for row in json.load(open(logpath)).get("defects", []):
            for k in row.get("keys", []):
                idx[(k["scanner"], k["finding_id"], k["purl"])] = row
    return idx


def _open_pr(branch, title, lane, dry, would, commit_msg):
    """Open a branch PR the RIGHT way: create the branch, commit, push, THEN gh pr create —
    so the PR never targets a branch that was never made (R1 round-4). dry records only the
    pr-create in the §6 would-open list; a real run (or the test shim) records/executes the
    full git sequence. NOTE: a real push needs contents:write on the job — see the report
    header when that is absent."""
    seq = ["git checkout -b %s" % branch, "git add -A",
           "git commit --allow-empty -m %s" % shlex.quote(commit_msg),
           "git push -u origin %s" % branch,
           "gh pr create --head %s --base main --label %s --title %s" % (branch, lane, shlex.quote(title))]
    if dry:
        would.append(seq[-1]); print("dry-run would open PR on %s: %s" % (branch, title)); return
    log = os.environ.get("AUDITOR_GIT_SHIM_LOG")
    if log:
        open(log, "a").write("\n".join(seq) + "\n")
        return
    # The driver does NOT shell out to git/gh to open a PR. It cannot: the job holds
    # contents:read, so a push fails; and a driver that ran real git is what oscillated
    # across rounds 3-5 (silent push failure + a lying "opened" line, files written outside
    # the checkout so the commit was empty, branches stacking). Instead it RECORDS the
    # proposal (the branch, the commit, the exact PR) into out/pr-proposals.jsonl; an
    # authorized delivery step (owner decision: a contents:write job or a PAT) opens it.
    print("PR proposed (driver does not deliver; needs an authorized step): %s" % seq[-1])


def _emit_owner_issue(title, body, dry, would):
    """Open OR update the single owner-decision issue (REQ-AUD-9). Returns (ok, ref): ok is
    False on a create/update FAILURE so the caller marks the run INCOMPLETE — never a false
    'opened' (R1 outer round-1 #5); ref is the issue number/url when known (R1 outer round-1
    #7). The body carries the evidence, the artifact, and the yes/no question (AC1). Uses the
    JOB token (issues:write), never the App delivery token (Contents + PRs only)."""
    cmd = "gh issue create --title %s --label %s --assignee %s" % (shlex.quote(title), policy.OWNER_LABEL, policy.OWNER_LOGIN)
    if dry:
        would.append(cmd); print("dry-run would create: " + cmd); return True, "dry"
    log = os.environ.get("AUDITOR_GIT_SHIM_LOG")
    if log:
        prior = open(log).read() if os.path.exists(log) else ""
        if ("issue create --title %s" % shlex.quote(title)) in prior:
            open(log, "a").write("gh issue comment --title %s --body %s\n" % (shlex.quote(title), shlex.quote(body)))
            return True, "shim-updated"
        open(log, "a").write(cmd + " --body " + shlex.quote(body) + "\n")
        return (not os.environ.get("AUDITOR_SHIM_ISSUE_FAIL")), ("shim-created" if not os.environ.get("AUDITOR_SHIM_ISSUE_FAIL") else None)
    if not _real_gh_allowed():
        print("would open/update owner issue (real gh disabled): " + title); return True, "skipped"
    ienv = dict(os.environ)
    ienv["GH_TOKEN"] = os.environ.get("AUDITOR_ISSUES_TOKEN") or os.environ.get("GH_TOKEN", "")
    try:
        r = subprocess.run(["gh", "issue", "list", "--search", title, "--state", "open", "--json", "number,title"],
                           capture_output=True, text=True, env=ienv)
        if r.returncode != 0:
            # a FAILED discovery must NOT fall through to a duplicate create that abandons the
            # existing acceptance pointer (R1 outer round-3 #2): abort as a failure.
            print("owner-issue discovery FAILED: %s" % (r.stderr or "").strip()); return False, None
        found = [i for i in json.loads(r.stdout or "[]") if i.get("title") == title]
        if found:
            num = found[0]["number"]
            c = subprocess.run(["gh", "issue", "comment", str(num), "--body", body], capture_output=True, text=True, env=ienv)
            return (c.returncode == 0), num
        c = subprocess.run(["gh", "issue", "create", "--title", title, "--label", policy.OWNER_LABEL,
                            "--assignee", policy.OWNER_LOGIN, "--body", body], capture_output=True, text=True, env=ienv)
        if c.returncode != 0:
            print("owner-issue create FAILED: %s" % (c.stderr or "").strip()); return False, None
        url = (c.stdout or "").strip().splitlines()[-1] if c.stdout else ""
        num = url.rstrip("/").split("/")[-1] if url else None
        return True, (int(num) if (num or "").isdigit() else url)
    except Exception as e:
        print("owner-issue open/update failed: %s" % e); return False, None


_PROMPT_PATH = ".github/agent/prompts/"


def _automerge_on():
    """REQ-AUD-17 AC3: the repo variable that flips the auditor's PRs from draft to auto-merge
    once the owner turns it on (drafts through the dry week and the first live week)."""
    return (os.environ.get("AUDITOR_AUTOMERGE") or "").strip().lower() in ("on", "true", "1", "yes")


def _automerge_allowed(paths):
    """Auto-merge is enabled ONLY when the owner turned it on (AC3) AND the change touches NO
    prompt file — the model's standing instructions are human-merged always (AC4). The records
    the auditor delivers (VEX, ignores, inventory, proposals, knowledge) never include the prompt
    file, so this both permits records and hard-guards the instructions."""
    return _automerge_on() and not any((p or "").startswith(_PROMPT_PATH) for p in (paths or []))


def _deliver_suppression_pr(out, supp, nstmt, today, commit, dry, would, is_test=False):
    """Deliver the consolidated suppressions (R16) as ONE non-stacked draft PR against main,
    carrying .vex/fosterstack-cache.openvex.json + .snyk + osv-scanner.toml in a single commit
    by the App bot identity. Returns (pr_url, error). A dry run only proposes. A push/PR
    failure returns (None, stderr) so the caller marks the run AUDIT INCOMPLETE — never a
    false 'opened'. No vendor/model name appears in the branch, commit, or PR text.

    A TEST-IMAGE run opens NO PR (a VEX for an image we do not ship is not a proposal, and a
    test image always forces dry_run — REQ-AUD-15 AC9)."""
    # nstmt==0 with NO removals means nothing to deliver. But an expiry reopen (AC5c) produces
    # zero NEW statements yet must still REMOVE a carried statement/ignore — deliver that.
    has_removals = False
    try:
        has_removals = bool(json.load(open(os.path.join(out, ".auditor", "reopened-expired.json"))).get("reopened"))
    except Exception:
        has_removals = False
    # A run that produced ONLY model proposals (no statements, no removals) still opens the draft
    # PR so the proposals reach audit-lane review (REQ-AUD-16 AC4; Codex round-1 P2).
    has_proposals = os.path.exists(os.path.join(out, ".auditor", "proposals", "adjudicator-proposals.json"))
    if nstmt == 0 and not has_removals and not has_proposals:
        return None, None
    if is_test:
        would.append("test-image run: no PR (not a shipped image)")
        print("test-image run: no suppression PR (not a shipped image)")
        return None, None
    short = (commit or "unknown")[:12]
    branch = "auditor/%s-%s" % (today, short)          # <date>-<short-sha>, off main, non-stacked
    title = policy.subject("update suppressions (%d statements)" % nstmt)
    body = "Automated suppression update from the daily CVE auditor. Draft for audit-lane review."
    # REQ-AUD-16 AC4/AC3: carry model PROPOSALS and the generated knowledge doc in the same draft
    # PR (proposals take effect only after the owner merges + an audit-lane reviewer promotes them).
    extra = [p for p in (".auditor/proposals/adjudicator-proposals.json", ".auditor/knowledge.md")
             if os.path.exists(os.path.join(out, p))]
    staged = [".vex/fosterstack-cache.openvex.json", ".snyk", "osv-scanner.toml",
              ".auditor/accepted-items.json"] + extra
    # AC3/AC4: draft unless the owner turned auto-merge on AND the change touches no prompt file.
    automerge = _automerge_allowed(staged)
    draft = "" if automerge else "--draft "
    if dry:
        would.append("gh pr create %s--base main --head %s --title %s" % (draft, branch, shlex.quote(title)))
        if automerge:
            would.append("gh pr merge --auto --squash %s" % branch)
        print("dry-run would open %sPR on %s" % ("auto-merge " if automerge else "draft ", branch))
        return None, None
    log = os.environ.get("AUDITOR_GIT_SHIM_LOG")
    if log:
        seq = ["git checkout -B %s origin/main" % branch,
               "git add " + " ".join(staged),
               "git commit -m %s" % shlex.quote(title),
               "git push -u origin %s" % branch,
               "gh pr create %s--base main --head %s --title %s" % (draft, branch, shlex.quote(title))]
        if automerge:
            seq.append("gh pr merge --auto --squash %s" % branch)
        open(log, "a").write("\n".join(seq) + "\n")
        if os.environ.get("AUDITOR_SHIM_PR_FAIL"):
            return None, "simulated: push to origin/%s rejected" % branch
        url = "https://github.com/OWNER/REPO/pull/SHIM-%s" % short
        open(log, "a").write("PR_URL %s\n" % url)
        return url, None
    if not _real_gh_allowed():
        return None, None
    import shutil
    ws = os.environ.get("GITHUB_WORKSPACE", os.getcwd())

    def _git(*a):
        return subprocess.run(["git", *a], cwd=ws, capture_output=True, text=True)
    r = _git("fetch", "origin", "main")
    if r.returncode != 0:
        return None, ("git fetch: " + (r.stderr or "").strip())
    r = _git("checkout", "-B", branch, "origin/main")     # off main => not stacked
    if r.returncode != 0:
        return None, ("git checkout: " + (r.stderr or "").strip())
    try:
        # MERGE into the existing reviewed suppressions, do NOT overwrite them (R1 outer
        # round-4 #3): a statement this run does not touch (e.g. a debug-variant suppression
        # absent from a production scan) must survive, and the document version continues.
        # _merge_suppressions merges the VEX, the .snyk/osv-scanner.toml ignores AND the
        # coupled .auditor/accepted-items.json (retained affected statements keep their
        # inventory entry, R1 outer round-5 #2) — no wholesale copy of the run's inventory.
        _merge_suppressions(ws, supp)
        # copy the run's proposals + generated knowledge into the checkout so they ride the PR.
        for p in extra:
            s = os.path.join(out, p); d = os.path.join(ws, p)
            os.makedirs(os.path.dirname(d), exist_ok=True)
            shutil.copyfile(s, d)
    except Exception as e:
        return None, "stage files: %s" % e
    _git("add", ".vex/fosterstack-cache.openvex.json", ".snyk", "osv-scanner.toml", ".auditor/accepted-items.json", *extra)
    r = _git("commit", "-m", title)
    if r.returncode != 0:
        return None, ("git commit: " + (r.stderr or "").strip())
    r = _git("push", "-u", "origin", branch, "--force-with-lease")
    if r.returncode != 0:
        return None, ("git push: " + (r.stderr or "").strip())
    # idempotence (R1 outer round-4 #5): if a PR for this head already exists, reconcile with
    # it (no duplicate, no false failure) instead of a second `gh pr create`.
    def _existing_pr():
        q = subprocess.run(["gh", "pr", "list", "--head", branch, "--state", "open", "--json", "url",
                            "--jq", ".[0].url // \"\""], cwd=ws, capture_output=True, text=True)
        return (q.stdout or "").strip() if q.returncode == 0 else ""
    ex = _existing_pr()
    if ex:
        if automerge:
            subprocess.run(["gh", "pr", "merge", "--auto", "--squash", ex], cwd=ws, capture_output=True, text=True)
        return ex, None
    create = ["gh", "pr", "create", "--base", "main", "--head", branch, "--title", title, "--body", body]
    if not automerge:
        create.insert(3, "--draft")   # after "create": `gh pr create --draft ...`
    r = subprocess.run(create, cwd=ws, capture_output=True, text=True)
    if r.returncode != 0:
        if "already exists" in (r.stderr or "").lower():   # race: reuse the existing one
            ex = _existing_pr()
            if ex:
                if automerge:
                    subprocess.run(["gh", "pr", "merge", "--auto", "--squash", ex], cwd=ws, capture_output=True, text=True)
                return ex, None
        return None, ("gh pr create: " + (r.stderr or "").strip())
    url = r.stdout.strip()
    # AC3: enable auto-merge (squash). The merge still waits on all required checks + the main
    # rulesets — the App has no bypass — so this arms the merge, it does not force it.
    if automerge and url:
        subprocess.run(["gh", "pr", "merge", "--auto", "--squash", url], cwd=ws, capture_output=True, text=True)
    return url, None


def _deliver_fix_pr(row, today, commit, dry, would, is_test=False):
    """Deliver ONE Go-module bump as a DRAFT PR on a fresh auditor/ branch by the App bot
    (decision 2): `go get <module>@<fixed>` + `go mod tidy`, committing ONLY go.mod and go.sum
    — no source edits, no vendor directory, no version guessing. The PR body names the CVE,
    the module, the from/to versions, and links the run's report; CI on the draft proves the
    bump compiles, which is what the draft is for. Base rebuilds are NOT delivered here (an OS
    fix defers to Dependabot's docker PR, REQ-AUD-2 AC3).

    Returns (pr_url, err, status). status is one of: 'delivered' (draft PR opened/reused),
    'would' (dry run), 'unresolvable' (the fixed version does not resolve from the module
    proxy, or the bump is a no-op — the row stays in §3, never a broken PR), 'pending' (no
    authorized delivery step this run), 'skipped-test' (test image), 'error'
    (a git/gh/tidy failure — the caller marks the run INCOMPLETE). No vendor/model name
    appears in the branch, commit, or PR text."""
    fb = row.get("fix_bump") or {}
    module = fb.get("module"); to = fb.get("to"); frm = fb.get("from"); cve = fb.get("cve") or row["id"]
    short = (commit or "unknown")[:12]
    branch = "auditor/bump-%s-%s" % (cve, short)
    title = policy.subject("bump %s %s -> %s (%s)" % (module, frm, to, cve))
    server = os.environ.get("GITHUB_SERVER_URL"); repo = os.environ.get("GITHUB_REPOSITORY"); rid = os.environ.get("GITHUB_RUN_ID")
    runlink = ("%s/%s/actions/runs/%s" % (server, repo, rid)) if (server and repo and rid) else "the daily CVE auditor run report"
    body = ("Automated dependency bump from the daily CVE auditor. Draft for review; auto-merge is a later switch.\n\n"
            "- Vulnerability: %s\n- Module: %s\n- From: %s\n- To: %s\n\nRun report: %s" % (cve, module, frm, to, runlink))
    if is_test:                                 # a test image is not shipped and always dry (AC9)
        would.append("test-image run: no bump PR (not a shipped image)")
        return None, None, "skipped-test"
    # AC3/AC4: a bump PR touches only go.mod/go.sum (no prompt file), so it auto-merges when the
    # owner turned auto-merge on; otherwise draft.
    automerge = _automerge_allowed(["go.mod", "go.sum"])
    draft = "" if automerge else "--draft "
    if dry:
        would.append("gh pr create %s--base main --head %s --title %s" % (draft, branch, shlex.quote(title)))
        if automerge:
            would.append("gh pr merge --auto --squash %s" % branch)
        print("dry-run would open %sbump PR on %s" % ("auto-merge " if automerge else "draft ", branch))
        return None, None, "would"
    log = os.environ.get("AUDITOR_GIT_SHIM_LOG")
    if log:
        seq = ["git checkout -B %s origin/main" % branch,
               "go get %s@%s" % (module, to),
               "go mod tidy",
               "git add go.mod go.sum",
               "git commit -m %s" % shlex.quote(title),
               "git push -u origin %s" % branch,
               "gh pr create %s--base main --head %s --title %s" % (draft, branch, shlex.quote(title))]
        if automerge:
            seq.append("gh pr merge --auto --squash %s" % branch)
        open(log, "a").write("\n".join(seq) + "\n")
        if os.environ.get("AUDITOR_SHIM_PR_FAIL"):
            return None, "simulated: push to origin/%s rejected" % branch, "error"
        url = "https://github.com/OWNER/REPO/pull/SHIM-bump-%s" % short
        open(log, "a").write("PR_URL %s\n" % url)
        return url, None, "delivered"
    if not _real_gh_allowed():
        print("bump PR pending: no authorized delivery step (real gh disabled): %s" % title)
        return None, None, "pending"
    ws = os.environ.get("GITHUB_WORKSPACE", os.getcwd())

    def _git(*a):
        return subprocess.run(["git", *a], cwd=ws, capture_output=True, text=True)

    def _go(*a):
        return subprocess.run(["go", *a], cwd=ws, capture_output=True, text=True)
    _git("reset", "--hard")                                # clean base; each bump is off origin/main
    r = _git("fetch", "origin", "main")
    if r.returncode != 0:
        return None, ("git fetch: " + (r.stderr or "").strip()), "error"
    r = _git("checkout", "-B", branch, "origin/main")
    if r.returncode != 0:
        return None, ("git checkout: " + (r.stderr or "").strip()), "error"
    g = _go("get", "%s@%s" % (module, to))
    if g.returncode != 0:
        # the fixed version does not resolve from the module proxy — NOT a broken PR (stays §3)
        _git("reset", "--hard", "origin/main")
        return None, None, "unresolvable"
    t = _go("mod", "tidy")
    if t.returncode != 0:
        _git("reset", "--hard", "origin/main")
        return None, ("go mod tidy: " + (t.stderr or "").strip()), "error"
    _git("add", "go.mod", "go.sum")
    if _git("diff", "--cached", "--quiet").returncode == 0:
        # the bump changed nothing (already at/after the fixed version) — nothing to deliver
        _git("reset", "--hard", "origin/main")
        return None, None, "unresolvable"
    r = _git("commit", "-m", title)
    if r.returncode != 0:
        return None, ("git commit: " + (r.stderr or "").strip()), "error"
    r = _git("push", "-u", "origin", branch, "--force-with-lease")
    if r.returncode != 0:
        return None, ("git push: " + (r.stderr or "").strip()), "error"

    def _existing():
        q = subprocess.run(["gh", "pr", "list", "--head", branch, "--state", "open", "--json", "url",
                            "--jq", ".[0].url // \"\""], cwd=ws, capture_output=True, text=True)
        return (q.stdout or "").strip() if q.returncode == 0 else ""
    def _arm(u):
        if automerge and u:
            subprocess.run(["gh", "pr", "merge", "--auto", "--squash", u], cwd=ws, capture_output=True, text=True)
    ex = _existing()
    if ex:
        _arm(ex); return ex, None, "delivered"
    create = ["gh", "pr", "create", "--base", "main", "--head", branch, "--title", title, "--body", body]
    if not automerge:
        create.insert(3, "--draft")
    r = subprocess.run(create, cwd=ws, capture_output=True, text=True)
    if r.returncode != 0:
        if "already exists" in (r.stderr or "").lower():
            ex = _existing()
            if ex:
                _arm(ex); return ex, None, "delivered"
        return None, ("gh pr create: " + (r.stderr or "").strip()), "error"
    url = r.stdout.strip(); _arm(url)
    return url, None, "delivered"


def _ignores_from_statements(statements, expiry_map):
    """Build (.snyk text, osv-scanner.toml text) from a set of VEX statements: ONE ignore per
    CVE, citing EVERY one of that CVE's statement ids (base id first, so `vex:` anchors on the
    primary scope), with the carried time box. Deriving the ignores from the final statements
    keeps every citation resolvable to a real merged id (R1 outer round-8 #6)."""
    by_cve = {}
    for s in statements:
        cve = (s.get("vulnerability") or {}).get("name")
        if not cve:
            continue
        info = by_cve.setdefault(cve, {"statuses": set(), "vids": [], "purls": set()})
        info["statuses"].add(s.get("status"))
        sid = s.get("@id")
        if sid and sid not in info["vids"]:
            info["vids"].append(sid)
        for p in s.get("products", []):
            for sc in (p.get("subcomponents") or []):
                if _sub_purl(sc):
                    info["purls"].add(_sub_purl(sc))
    def _exp_for(cve, sel):
        # a deadline is applied ONLY to the exact (cve, package) scope that has one — never a
        # CVE-wide fallback, so a permanent (not_affected) or longer-dated sibling scope does not
        # acquire another scope's box (R1 refactor round-2 #4, round-3 #4).
        return expiry_map.get((cve, sel))
    snyk = ["version: v1.5.0", "ignore:"]
    toml = []
    for cve in sorted(by_cve):
        info = by_cve[cve]
        vids = sorted(info["vids"], key=lambda x: ("~" in x, x)) or [policy.stmt_id(cve)]
        st = "+".join(sorted(x for x in info["statuses"] if x))
        allids = " ".join(vids)
        # Scope the Snyk ignore to exactly the surviving statements' packages, so a scope that
        # was reopened/removed on expiry is NOT still suppressed by a CVE-wide `'*'` selector
        # (R1 refactor round-1 #4), and each selector carries ITS OWN deadline (round-2 #4).
        # (OSV IgnoredVulns has no package field — it is CVE-level by format; the packages and
        # their deadlines are named in its reason and the VEX carries the truth.)
        selectors = sorted(info["purls"]) or ["*"]
        snyk += ["  %s:" % cve]
        for sel in selectors:
            exp = _exp_for(cve, sel)
            snyk += ["    - '%s':" % sel, "        reason: '%s; governed by %s'" % (st, allids)]
            if exp:
                snyk += ["        expires: %sT00:00:00.000Z" % exp]
            snyk += ["        vex: '%s'" % vids[0]]
        scope_note = "; ".join("%s until %s" % (sel, _exp_for(cve, sel) or "n/a") for sel in selectors)
        rsn = "%s; governed by %s; scopes: %s" % (st, allids, scope_note)
        toml += ['[[IgnoredVulns]]', 'id = "%s"' % cve, 'reason = "%s"' % rsn]
        cexp = max((_exp_for(cve, sel) for sel in selectors if _exp_for(cve, sel)), default=None)
        if cexp:
            toml += ['expires = "%sT00:00:00Z"' % cexp]
    return "\n".join(snyk) + "\n", "\n".join(toml) + "\n"


def _merge_suppressions(ws, supp):
    """Merge this run's consolidated suppressions INTO the existing reviewed files in the
    checkout, preserving statements/entries this run does not touch and continuing the VEX
    document version (R1 outer round-4 #3). Statements are keyed by @id (this run replaces a
    same-@id statement, adds new ones, keeps the rest); .snyk/osv-scanner.toml entries are
    unioned by CVE (this run wins on a conflict)."""
    import shutil
    vp = os.path.join(ws, ".vex", "fosterstack-cache.openvex.json")
    os.makedirs(os.path.dirname(vp), exist_ok=True)
    newdoc = json.load(open(os.path.join(supp, "fosterstack-cache.openvex.json")))
    existing = {}
    if os.path.exists(vp):
        try:
            existing = json.load(open(vp))
        except Exception:
            existing = {}
    # Merge statements by the CANONICAL scope key (vulnerability, scope) (REQ-AUD-13 AC1/AC3).
    # Statements now arrive with scope-deterministic @ids (generation-time, AC2), so a
    # same-scope statement — this run's or a carried one — has the same key and the incoming
    # one replaces it; DISTINCT scopes are both retained and, by construction, carry distinct
    # @ids. Foreign statement ids (a reviewer's `…#review~…`) are their own scope and kept as-is.
    def _key(s):
        return ((s.get("vulnerability") or {}).get("name"), _scope_key(s))
    by_id = {}
    for s in existing.get("statements", []):
        by_id[_key(s)] = s
    for s in newdoc.get("statements", []):
        by_id[_key(s)] = s                        # this run replaces same-scope / adds new
    survivors = list(by_id.values())
    # Per-SCOPE expiry removal (REQ-AUD-13 AC6): drop only the statements whose OWN scope
    # reopened this run because its time box expired (identified by statement @id); sibling
    # scopes and permanent statements of the same vulnerability are retained.
    reopened = set()
    try:
        for sc in json.load(open(os.path.join(os.path.dirname(supp), ".auditor",
                                              "reopened-expired.json"))).get("reopened", []):
            reopened.add((sc[0], tuple(sc[1]), tuple(sc[2])))     # (cve, products, purls)
    except Exception:
        reopened = set()
    if reopened:
        survivors = [s for s in survivors
                     if ((s.get("vulnerability") or {}).get("name"), _scope_key(s)[0], _scope_key(s)[1]) not in reopened]
    # AC2 safety net: never deliver two statements sharing an @id.
    seen = {}
    for s in survivors:
        sid = s.get("@id") or ""
        while sid in seen and seen[sid] is not s:
            sid += "0"
        seen[sid] = s
        s["@id"] = sid
    merged = dict(existing) if existing else dict(newdoc)
    merged["statements"] = survivors
    merged["version"] = int(existing.get("version", 0)) + 1 if existing else newdoc.get("version", 1)
    for k in ("@context", "@id", "author", "role"):
        merged.setdefault(k, newdoc.get(k))
    merged["timestamp"] = newdoc.get("timestamp", merged.get("timestamp"))
    cli.writej(vp, merged)

    # accepted-items.json is COUPLED to the VEX: an affected statement that survives the VEX
    # merge but this run did not re-assess must keep its inventory entry, or release-authz
    # rejects the package as inconsistent (R1 outer round-5 #2). Merge like the VEX — this
    # run's items win; carry an old item forward for any affected CVE still in the merged
    # document; drop acceptances whose statement is no longer affected.
    def _loadj(p):
        try:
            return json.load(open(p))
        except Exception:
            return None
    aip = os.path.join(ws, ".auditor", "accepted-items.json")
    new_ai = _loadj(os.path.join(os.path.dirname(supp), ".auditor", "accepted-items.json"))
    old_ai = _loadj(aip)
    out_ai = {}
    if new_ai is not None or old_ai is not None:
        def _cve(it):
            return (it or {}).get("cve") or (it or {}).get("id")
        # Key items by their FULL scope identity, not by cve (R1 outer round-6 #1) nor by
        # (cve, package, threshold) alone (R1 outer round-7 #1): two scopes of one CVE can share
        # package AND threshold yet carry DIFFERENT owner obligations (distinct owner-decision
        # issues, distinct governing VEX statements). Keying on any subset lets the last write
        # erase another scope's obligation and promote past a rejected owner. Include the
        # governing statement id and the owner issue so every distinct obligation survives; this
        # run replaces only the SAME scope.
        # Inventory keys on the FULL canonical scope, never a hash-derived @id (R1 refactor
        # round-1 #1/#2/#6). An item carries its own scope (product + purls); a legacy item
        # without one resolves its scope through its @id against the merged statements; only a
        # truly unresolvable legacy item falls back to the coarse (cve,package,threshold,issue).
        id_to_scope = {s.get("@id"): _scope_key(s) for s in merged.get("statements", [])}
        # for a legacy item with no scope AND no resolvable @id, try its package: if exactly one
        # surviving affected scope names that package, resolve to it (R1 refactor round-1 #6).
        pkg_to_scopes = {}
        for s in merged.get("statements", []):
            if s.get("status") != "affected":
                continue
            for purl in {_sub_purl(sc) for p in s.get("products", []) for sc in (p.get("subcomponents") or []) if _sub_purl(sc)}:
                pkg_to_scopes.setdefault(purl, set()).add(_scope_key(s))

        def _scope_of(it):
            it = it or {}
            if it.get("scope_purls") is not None:
                return ((it.get("product") or policy.VEX_PRODUCT,), tuple(sorted(set(it["scope_purls"]))))
            if it.get("vex_id") in id_to_scope:
                return id_to_scope[it["vex_id"]]
            pkg = it.get("package")
            if pkg:
                hits = {sc for purl, scs in pkg_to_scopes.items() if pkg in purl for sc in scs}
                if len(hits) == 1:
                    return next(iter(hits))
            return None

        def _ikey(it):
            sc = _scope_of(it)
            if sc is not None:
                return (_cve(it), sc)             # same scope -> replace; distinct scope -> keep both
            # unresolvable legacy: keep the coarse identity AND the deadline, so two ambiguous
            # same-package obligations are surfaced, never silently collapsed (R1 refactor #6).
            return (_cve(it), it.get("package"), it.get("threshold"), it.get("owner_issue"), it.get("expiry"))
        # retain an old obligation only if THIS SCOPE's affected statement survived the merge:
        # a scope reopened/removed on expiry drops its obligation too, a sibling live scope keeps
        # its own; an unresolvable legacy item falls back to CVE-level retention.
        # retain per (VULNERABILITY, scope): an item is kept only if ITS OWN CVE is still
        # affected at ITS OWN scope — a sibling CVE that keeps the same package scope alive does
        # NOT keep an expired CVE's obligation (R1 refactor round-2 #1).
        affected = {((s.get("vulnerability") or {}).get("name"), _scope_key(s))
                    for s in merged.get("statements", []) if s.get("status") == "affected"}
        affected_cves = {cve for cve, _ in affected}
        final = {}
        for it in ((old_ai or {}).get("accepted_items") or []):
            sc = _scope_of(it)
            keep = ((_cve(it), sc) in affected) if sc is not None else (_cve(it) in affected_cves)
            if keep:
                final[_ikey(it)] = it              # retained scope keeps its acceptance
        for it in ((new_ai or {}).get("accepted_items") or []):
            if _cve(it):
                final[_ikey(it)] = it              # this run wins on the same scope
        out_ai = dict(new_ai or old_ai or {})
        out_ai["accepted_items"] = list(final.values())
        # reconcile each pointer to the FINAL statement @id for ITS (cve, scope) (R1 refactor
        # round-2 #2), so a collision-suffixed or foreign id never leaves an item pointing at
        # another statement that merely shares its scope.
        cvescope_to_id = {}
        for s in merged.get("statements", []):
            cvescope_to_id.setdefault(((s.get("vulnerability") or {}).get("name"), _scope_key(s)), s.get("@id"))
        for it in out_ai["accepted_items"]:
            sc = _scope_of(it)
            if (_cve(it), sc) in cvescope_to_id:
                it["vex_id"] = cvescope_to_id[(_cve(it), sc)]
        os.makedirs(os.path.dirname(aip), exist_ok=True)
        cli.writej(aip, out_ai)

    # Regenerate .snyk and osv-scanner.toml FROM the merged VEX (not a text union of the two
    # files) so every ignore cites a real merged statement id and no stale pre-merge citation
    # survives (R1 outer round-8 #6). Deadlines come per-(cve, package) from the MERGED
    # inventory, so each scope carries its OWN box, never a sibling's (R1 refactor round-2 #4).
    expiry = {}
    for it in out_ai.get("accepted_items", []):
        cve = it.get("cve") or it.get("id"); exp = it.get("expiry")
        if cve and exp:
            for purl in (it.get("scope_purls") or []):
                expiry[(cve, purl)] = exp
            expiry.setdefault(cve, exp)                   # CVE-level fallback for a purl-less item
    otoml = os.path.join(ws, "osv-scanner.toml")
    sp = os.path.join(ws, ".snyk")
    snyk_text, toml_text = _ignores_from_statements(merged.get("statements", []), expiry)
    open(sp, "w").write(snyk_text)
    open(otoml, "w").write(toml_text)


def _consolidate(out, ts):
    """Merge every per-CVE VEX this run wrote into ONE canonical
    suppressions/fosterstack-cache.openvex.json (the file scan/rescan/release-authz read),
    plus .snyk and osv-scanner.toml that CITE each statement's VEX id. Returns
    (suppression_dir, statement_count). (R1 round-3: the auditor's VEX must reach the
    canonical file, and the consistency check must read the layout the run actually writes.)"""
    import glob
    statements = []
    for vf in sorted(glob.glob(os.path.join(out, "vex", "*.openvex.json"))):
        try:
            statements.extend(json.load(open(vf)).get("statements", []))
        except Exception:
            pass
    supp = os.path.join(out, "suppressions")
    document = {"@context": "https://openvex.dev/ns/v0.2.0", "@id": policy.VEX_BASE,
                "author": "FosterStack LLC", "role": "vendor", "timestamp": ts, "version": 1,
                "statements": statements}
    vex.validate(document)
    cli.writej(os.path.join(supp, "fosterstack-cache.openvex.json"), document)
    # ONE ignore entry per CVE (R1 round-4): a split CVE has two statements but the scanner
    # ignore is CVE-keyed, so collapse by CVE — no duplicate YAML keys / TOML blocks — and
    # cite the governing VEX statement-id base. A CVE with any affected statement is recorded
    # as governed-by-VEX (the VEX's subcomponents carry the per-package truth).
    # the time box must survive consolidation (R1 outer round-1 #6): carry each affected CVE's
    # expiry from its per-scanner ignore JSON (or evidence sidecar target_date) into .snyk's
    # `expires` and osv-scanner.toml, so the delivered package is time-bounded and the next run
    # can enforce it.
    # per-(cve, package) deadlines from this run's ignore JSONs (scoped_purls) + evidence
    # sidecars, so the STAGED artifact carries the same scoped, per-package rules the delivery
    # merge produces — never a CVE-wide wildcard (R1 refactor round-2 #4).
    expiry_map = {}
    for jf in glob.glob(os.path.join(out, "ignores", "*", "*.json")):
        try:
            d = json.load(open(jf))
            if d.get("id") and d.get("expiry"):
                for purl in (d.get("scoped_purls") or []):
                    expiry_map[(d["id"], purl)] = d["expiry"]
                expiry_map.setdefault(d["id"], d["expiry"])
        except Exception:
            pass
    for ef in glob.glob(os.path.join(out, "evidence", "*.evidence.json")):
        try:
            d = json.load(open(ef))
            if d.get("vulnerability") and d.get("target_date"):
                expiry_map.setdefault(d["vulnerability"], d["target_date"])
        except Exception:
            pass
    snyk_text, toml_text = _ignores_from_statements(statements, expiry_map)
    cli.writef(os.path.join(supp, ".snyk"), snyk_text)
    cli.writef(os.path.join(supp, "osv-scanner.toml"), toml_text)
    return supp, len(statements)


def adjudicate(adjudicator, ctx, state):
    """primary -> rephrase -> fallback for ONE finding, bounded PER FINDING by the five-iteration
    stop and globally by the token budget. Returns the category, 'refused' (a genuine refusal the
    model WAS reachable for), or 'adjudicator_error' (every attempt errored — the model was
    UNAVAILABLE). On an error, surface the REAL cause (exception class + HTTP status + message,
    secrets MASKED) ONCE per distinct error into state['adj_errors'] so the header, §4 and the
    status line can name it, and it is not repeated per finding (R-live fix 1)."""
    iters = 0; errored = False; refused = False
    for attempt, role in (("primary", "primary"), ("rephrase", "primary"), ("fallback", "fallback")):
        if state["tokens"] >= policy.TOKEN_BUDGET or iters >= policy.MAX_ITERATIONS:
            state["stops"] = state.get("stops", 0) + 1
            return "adjudicator_error" if (errored and not refused) else "refused"
        iters += 1; state["calls"] = state.get("calls", 0) + 1
        try:
            ans = cli.ask_model(adjudicator, ctx["finding_id"], attempt=attempt, model=role, context=ctx)
        except cli.Refused as e:
            state["tokens"] += int(getattr(e, "token_usage", 0) or 0)   # a refusal is still billed
            refused = True
            continue
        except Exception as e:
            errored = True
            msg = "%s: %s" % (type(e).__name__, _mask(str(e)))    # class + masked message/status
            # Dedup by a NORMALIZED key that strips volatile per-call ids (e.g. request_id), so N
            # identical failures (one per finding/attempt) collapse to ONE recorded error instead
            # of flooding the header/status; store the first FULL message as the representative.
            key = re.sub(r"\s*\[?request[_-]?id[=:]\s*[^\]\s]+\]?", "", msg, flags=re.I)
            errs = state.setdefault("adj_errors", {})
            if key not in errs:                                   # print/record ONCE per distinct error
                print("adjudicator error (%s): %s" % (attempt, msg))
                errs[key] = msg                                   # representative full message
            continue
        state["tokens"] += int(ans.get("token_usage") or 0)
        state.setdefault("roles_used", set()).add(role)
        # REQ-AUD-16 AC4: a model-proposed defect-log/knowledge entry is collected (with its
        # finding + evidence) for delivery in the draft PR; it is NEVER applied to the live records
        # this run — it takes effect only after the owner merges the audit-lane PR. A proposal is
        # kept ONLY when it names a recognized kind AND carries evidence (AC4 "with evidence"); a
        # malformed / evidence-free / unsupported-kind proposal is dropped, never forwarded.
        _pr = ans.get("propose")
        if isinstance(_pr, dict) and _pr.get("kind") in ("defect_log", "knowledge") and _pr.get("evidence"):
            state.setdefault("proposals", []).append(
                {"finding_id": ctx["finding_id"], "package": ctx.get("package"), "propose": _pr})
        return ans.get("category") or "unknown"
    return "adjudicator_error" if (errored and not refused) else "refused"


def _carrier_for(carriers, purls):
    """The manifest carrier record (from the SBOM) that carries one of these component purls,
    or None. `carriers` is the normalized list the manifest builder extracts from syft's
    relationships (REQ-AUD-14 AC2: evidence from the SBOM)."""
    if not carriers:
        return None
    ps = set(p for p in (purls or []) if p)
    for cr in carriers:
        if cr.get("component_purl") in ps:
            return cr
    return None


def _pullability(adjudicator, ctx, state):
    """ONE model call: is a NAMED fix actually PULLABLE, or is the vulnerable component carried
    inside another artifact / held by the base pin (REQ-AUD-14)? Returns the verdict dict, or
    None when the model was unavailable / refused / over budget — the caller then keeps the
    existing routing, so a model outage never fabricates a not-pullable acceptance (fail toward
    the actionable class). The call is billed like any other; an error is recorded (masked) once
    so the header can name it, exactly as adjudicate() does."""
    if state["tokens"] >= policy.TOKEN_BUDGET or state.get("iters", 0) >= policy.MAX_ITERATIONS:
        return None
    state["calls"] = state.get("calls", 0) + 1
    try:
        ans = cli.ask_model(adjudicator, ctx["finding_id"], attempt="pullability", model="primary", context=ctx)
    except cli.Refused as e:
        state["tokens"] += int(getattr(e, "token_usage", 0) or 0)
        return None
    except Exception as e:
        msg = "%s: %s" % (type(e).__name__, _mask(str(e)))
        key = re.sub(r"\s*\[?request[_-]?id[=:]\s*[^\]\s]+\]?", "", msg, flags=re.I)
        errs = state.setdefault("adj_errors", {})
        if key not in errs:
            print("pullability error: %s" % msg); errs[key] = msg
        return None
    state["tokens"] += int(ans.get("token_usage") or 0)
    state.setdefault("roles_used", set()).add("primary")
    return ans


# ---- deterministic facts from scanner data ----

def _eco(purl):
    m = re.match(r"pkg:([^/]+)/", purl or "")
    return (m.group(1) if m else "").lower()


def _ver_from_purl(purl):
    m = re.search(r"@([^?]+)", purl or "")
    return m.group(1) if m else None


def _trace_covers(purl, ev):
    """True iff a Go `purl` is at exactly a module@version the govulncheck trace supports
    (REQ-AUD-13 AC5). A version is REQUIRED on both sides: a trace that names no version does
    not authorize closing an arbitrary installed version."""
    mv = _go_modver(purl)
    if mv is None or mv.endswith("@"):
        return False
    return mv in set(ev.get("trace_modules") or [])


def _go_covered(findings, ev):
    """Split Go findings into (covered, uncovered): non-lineage findings the trace supports at
    their exact version vs. everything else (unsupported versions AND lineage records), so an
    uncovered sibling version is routed on its own instead of vanishing (R1 refactor round-1 #3)."""
    covered = [f for f in findings if f.get("purl") and not f.get("_lineage_only") and _trace_covers(f["purl"], ev)]
    cset = {id(f) for f in covered}
    uncovered = [f for f in findings if id(f) not in cset]
    return covered, uncovered


def _go_modver(purl):
    """`pkg:golang/<module>@<version>` -> `<module>@<version>` with the version's leading `v`
    normalized away (a purl may write `0.3.0` where govulncheck writes `v0.3.0`); None for a
    non-Go purl. Used to scope a Go closure to the version the trace supports."""
    if not purl or not purl.startswith("pkg:golang/"):
        return None
    body = purl[len("pkg:golang/"):].split("?")[0]
    mod, _, ver = body.partition("@")
    ver = ver[1:] if ver.startswith("v") else ver
    return "%s@%s" % (mod, ver)


SEV_ORDER = ["negligible", "low", "medium", "high", "critical"]


def _max_sev(findings):
    best = None; bi = -1
    for f in findings:
        s = (f.get("severity") or "").lower()
        if s in SEV_ORDER and SEV_ORDER.index(s) > bi:
            bi = SEV_ORDER.index(s); best = f.get("severity")
    return best or "unknown"


def _nofix_reason(findings):
    for f in findings:
        st = (f.get("extra") or {}).get("status") or (f.get("extra") or {}).get("fix_state")
        if st and str(st).lower() in ("will_not_fix", "wont-fix", "end_of_life", "not-fixed", "affected"):
            return str(st)
    return "no upstream fix"


def _group_facts(c, grp):
    findings = grp["findings"]
    # Per-CVE EVIDENCE comes only from findings that name this CVE as their own identity;
    # a lineage-only advisory record (it names this CVE only via a multi-CVE bundle) counts
    # toward scanner inventory/agreement but NEVER supplies fix/package/version/severity or
    # reachability for this CVE (REQ-AUD-13 AC4).
    nonlineage = [f for f in findings if not f.get("_lineage_only")]
    ev = nonlineage or findings                      # display falls back to lineage; evidence never
    f0 = ev[0]
    ecos = {_eco(f.get("purl")) for f in ev}
    installed = (f0.get("extra") or {}).get("installed_version") or _ver_from_purl(f0.get("purl")) or "?"
    # fix/severity/known-exploited are EVIDENCE — only from non-lineage records; a pure-bundle
    # group (lineage only) has no per-CVE fix and unknown severity, so it is surfaced no-fix and
    # below threshold rather than acting on an advisory's data for another CVE (REQ-AUD-13 AC4).
    fixed = next((f.get("fixed_version") for f in nonlineage if f.get("fixed_version")), None)
    return {
        "package": f0.get("package") or "unknown",
        "installed": installed,
        "fixed": fixed,
        "severity": _max_sev(nonlineage) if nonlineage else None,
        "is_go": any(e in ("golang", "go") for e in ecos),
        "known_exploited": any((f.get("extra") or {}).get("known_exploited") for f in nonlineage),
        "lineages": {policy.lineage_of(f["scanner"]) for f in findings},   # lineage votes: ALL
        "nofix_reason": _nofix_reason(ev),
    }


def _row_line(r):
    """One self-explaining line per row (R13 item 2)."""
    reach = r.get("reachability") or "n/a (OS package)"
    fix = r.get("fixed") or "none"
    line = ("%s — %s@%s — %s — fix: %s — reachability: %s — %s — action: %s — %s"
            % (r["id"], r["package"], r["installed"], r["severity"], fix, reach,
               r["disposition"], r["action"], r["reason"]))
    if r["section"] in (2, 5) and r.get("vex_id"):
        line += " — vex: %s — ignores: %s" % (r["vex_id"], ",".join(r.get("ignore_files", [])) or "none")
    if r["section"] == 4 and r.get("cause"):
        line += " — cause: %s" % r["cause"]
    return line


def _dispose_split(c, findings, aliases, env, would, base=None):
    """Route a finding set, SPLIT BY ECOSYSTEM (R1 outer round-4 #1): Go findings and OS
    (non-Go) findings for the same CVE are dispositioned separately with distinct VEX names,
    so a Go reachability closure never closes an OS finding (and vice versa)."""
    import hashlib
    base = base or c
    ids = sorted(aliases) + [c]
    # Route the NON-lineage findings, split by (ecosystem, package, INSTALLED VERSION): a fixed
    # version and an unfixed version of the same package are distinct scopes and must not share a
    # fix (R1 refactor round-3 #2), and a lineage-only advisory record never forms its own
    # disposition (R1 refactor round-3 #5) — it stays a quorum/lineage signal at the group level.
    nonlineage = [f for f in findings if not f.get("_lineage_only")]
    lineage = [f for f in findings if f.get("_lineage_only")]
    if not nonlineage:
        # a PURE lineage-only CVE: reported only through an advisory bundle, with no per-CVE
        # scanner record establishing a package. Surface it for assessment; do NOT build a
        # product-wide acceptance/VEX from the advisory's package metadata (R1 refactor round-4
        # #3). Its lineage stays an agreement signal, not a disposition.
        gf = _group_facts(c, {"findings": findings, "aliases": aliases})
        row = {"id": c, "package": gf["package"], "installed": gf["installed"], "fixed": None,
               "severity": gf["severity"] or "Unknown", "section": 4,
               "aliases": sorted(set(sorted(aliases) + [c])),
               "disposition": "under investigation", "reachability": "n/a",
               "action": "advisory-only: reported via a co-report bundle, no per-CVE scanner record",
               "reason": "no per-CVE scanner record establishes an affected package",
               "cause": "advisory/bundle lineage only"}
        return [row], 0
    by_scope = {}
    for f in nonlineage:
        eco = "go" if _eco(f.get("purl")) in ("golang", "go") else "os"
        by_scope.setdefault((eco, f.get("package") or "?", _ver_from_purl(f.get("purl")) or "?"), []).append(f)
    subsets = []   # list of (tag, findings)
    for key in sorted(by_scope, key=str):
        eco = key[0]; fs = by_scope[key]
        if eco == "go":
            verdict, ev = C.gvc_verdict(env["gvc"], ids, env["module"], env["gvc_usable"])
            if verdict == "unreachable":
                covered, uncovered = _go_covered(fs, ev)
                if covered:
                    subsets.append(("go", covered))
                if uncovered:
                    subsets.append(("go-live", uncovered))
            else:
                subsets.append(("go", fs))
        else:
            subsets.append(("os", fs))
    subsets = [(tag, s) for tag, s in subsets if s]
    out_rows = []; mc = 0
    for tag, sub in subsets:
        # collision-free VEX/ignore file name: base + tag + a hash of the subset's exact purls,
        # so two distinct scopes never share a basename (R1 refactor round-3 #3). The statement
        # @id is scope-derived independently.
        if len(subsets) == 1:
            nm = base
        else:
            h = hashlib.sha1("\n".join(sorted(f.get("purl") or "" for f in sub)).encode()).hexdigest()[:12]
            nm = "%s-%s-%s" % (base, tag, h)
        # attach the group's lineage-only records so this subset's agreement/lineage vote is
        # counted (excluded from evidence by _group_facts) — a real finding backed by an advisory
        # is not mistaken for unique-lineage (R1 refactor round-4 #5).
        row, mi = _dispose(c, sub + lineage, aliases, env, would, name=nm)
        out_rows.append(row); mc += mi
    return out_rows, mc


def _dispose(c, findings, aliases, env, would, name=None):
    """Route one finding subset deterministically (steps 2-4). Returns (row, m_calls_inc).
    The model is consulted ONLY for false-positive suspicion (unique lineage, no fix); a
    FP it cannot verify FALLS THROUGH to deterministic fix/POA&M routing (so a real finding
    is never left in §4 for a mere unverified suspicion); only a fallback-exhausted refusal
    lands in §4. `name` is the VEX/ignore file basename (defaults to the CVE id); a distinct
    name keeps a split CVE's second disposition from overwriting the first's files."""
    vn = name or c
    gf = _group_facts(c, {"findings": findings, "aliases": aliases})
    ids = sorted(aliases) + [c]
    # A not_affected closure clears ONLY the packages its evidence names (R11 rank 1); scope
    # every closure to this subset's exact PURLs so a Go unreachability never suppresses a
    # sibling OS package product-wide (R1 outer round-8 #2 — the -go name alone did not scope).
    subs = sorted({f["purl"] for f in findings if f.get("purl") and not f.get("_lineage_only")}) or None
    row = {"id": c, "package": gf["package"], "installed": gf["installed"], "fixed": gf["fixed"],
           "severity": gf["severity"], "reachability": "n/a (OS package)", "section": None,
           "disposition": None, "action": None, "reason": None,
           "aliases": sorted(set(ids)),               # every identifier this scope was grouped under
           "is_os": not gf["is_go"],                  # 3A (OS) vs 3B (SCA) split keys on ecosystem, not a delivery flag
           "scope_purls": sorted(set(subs or []))}   # this row's scope, for per-scope table mapping
    out = env["out"]; ts = env["ts"]; exp = env["exp"]; dry = env["dry"]
    _purls = sorted(set(subs or []))
    this_scope = ((policy.VEX_PRODUCT,), tuple(_purls))
    this_scope_id = policy.scope_id(c, policy.VEX_PRODUCT, subs)
    _carried = (c, this_scope) in env.get("carried_scopes", set())
    # the disposition PUBLISHED on main for this exact scope (None if none). The display flag
    # `carried` ("in force (main)") is set only when THIS run writes the SAME disposition; the
    # membership flag `_carried` still drives AC7 lift logic regardless of the prior status.
    _cstat = env.get("carried_status", {}).get((c, this_scope))
    # 2) reachability for Go modules — deterministic govulncheck.
    if gf["is_go"]:
        verdict, ev = C.gvc_verdict(env["gvc"], ids, env["module"], env["gvc_usable"])
        row["reachability"] = "govulncheck: %s" % verdict
        # a FRESH unreachable finding closes §5 even if a fix exists (unreachable => not
        # exploitable); only a CARRIED reachability suppression defers to the fix so it can be
        # LIFTED and bumped (REQ-AUD-13 AC7; R1 refactor round-4 #4).
        if verdict == "unreachable" and not (gf["fixed"] and _carried):
            # scope the closure to EXACTLY the module@version the trace supports, from the
            # NON-lineage Go findings only; a sibling version the evidence does not cover, or a
            # group whose only records are lineage, gets NO closure (REQ-AUD-13 AC5).
            go_subs = sorted({f["purl"] for f in _go_covered(findings, ev)[0]})
            if go_subs:
                vex.write(out, c, "not_affected", ts, justification="vulnerable_code_not_in_execute_path",
                          evidence=ev, vex_name=vn, subcomponents=go_subs)
                row.update(section=5, disposition="not_affected (unreachable)", action="closed",
                           reason="govulncheck: imported, not called",
                           vex_id=policy.scope_id(c, policy.VEX_PRODUCT, go_subs),
                           ignore_files=["vex", "evidence"], carried=(_cstat == "not_affected"))
                return row, 1
            # evidence covers no scanned version (or only lineage) — do not close; route below.
    m_inc = 0
    # An expired carried acceptance for THIS scope reopens the finding into §3 BEFORE any FP
    # suspicion — a model refusal must never hide the lapsed time box (REQ-AUD-13 AC6). A now-
    # fixable finding falls through to the bump instead (its box is moot).
    _cexp = env.get("carried_expiry", {}).get((c, this_scope))
    if not gf["fixed"] and _cexp and _cexp <= env.get("today", ts[:10]):
        row.update(section=3, disposition="reopened: prior acceptance expired",
                   action="time box lapsed %s — ignore removed; policy re-applied from scratch" % _cexp,
                   reason="acceptance expired %s (no upstream fix)" % _cexp,
                   reopened_expired=_cexp, vex_id=this_scope_id, scope_purls=_purls,
                   reopened_scope=[c, list(this_scope[0]), list(this_scope[1])])
        return row, m_inc
    # 3) false-positive suspicion — ONLY for a unique-lineage, no-fix finding.
    if len(gf["lineages"]) == 1 and not gf["fixed"]:
        ctx = {"finding_id": c, "aliases": aliases, "package": gf["package"],
               "purl": findings[0].get("purl"), "installed_version": gf["installed"],
               "fixed_version": gf["fixed"], "scanners": sorted({f["scanner"] for f in findings}),
               "severity": gf["severity"], "reachability": row["reachability"], "candidate_digest": env["digest"],
               "knowledge": env.get("knowledge")}   # REQ-AUD-16 AC3: generated patterns, for judgment
        cat = adjudicate(env["adjudicator"], ctx, env["state"]); m_inc = 1
        if cat == "false_positive":
            fev = C.fp_verified(ids, env["logpath"], findings)
            if fev:
                vex.write(out, c, "not_affected", ts, justification="vulnerable_code_not_present", evidence=fev, vex_name=vn, subcomponents=subs)
                row.update(section=5, disposition="not_affected (false positive)", action="closed",
                           reason="model FP, evidence-verified",
                           vex_id=policy.scope_id(c, policy.VEX_PRODUCT, subs),
                           ignore_files=["vex", "evidence"], carried=(_cstat == "not_affected"))
                return row, m_inc
            # a FP the code cannot verify is NOT a disposition — fall through and route it.
        elif cat == "adjudicator_error":
            # the model was UNAVAILABLE — every attempt errored (not a refusal). Do NOT open a
            # per-finding owner issue; run() opens ONE aggregate "adjudicator unavailable — N
            # findings unassessed" issue and marks the run INCOMPLETE (R-live fix 3). §4, cause named.
            row.update(section=4, disposition="under investigation",
                       action="unassessed: adjudicator unavailable",
                       reason="adjudicator unavailable (model calls failed)",
                       cause="adjudicator unavailable", adjudicator_error=True)
            return row, m_inc
        elif cat == "refused":
            # unassessed after the fallback chain -> owner-decision issue (REQ-AUD-9 AC3),
            # not a silent §4 (R1 outer round-1 #4). A stub run cannot escalate; say so.
            is_stub = "stub" in os.path.basename(env["adjudicator"]).lower()
            cause = "stub: no canned answer" if is_stub else "model refused after fallback"
            if is_stub:
                row.update(section=4, disposition="under investigation", action="none (stub: no owner escalation)",
                           reason="adjudication exhausted", cause=cause)
                return row, m_inc
            # genuine refusal (the model was reachable) -> owner-decision issue, deduped per
            # (CVE, package) with every scope listed in the body, emitted after routing (fix 4).
            row.update(section=4, disposition="under investigation",
                       action="escalation pending (owner-decision issue)",
                       reason="unassessed after fallback", cause=cause)
            row["owner_issue_intent"] = {
                "cve": c, "package": gf["package"], "kind": "unassessed",
                "reason_key": "unassessed-after-fallback",
                "scope": "%s@%s (severity %s, reachability %s)"
                         % (gf["package"], gf["installed"], gf["severity"], row["reachability"])}
            return row, m_inc
    # 4) deterministic fix routing.
    if gf["fixed"]:
        # REQ-AUD-14: a NAMED fix may not be PULLABLE — the vulnerable component is carried inside
        # another artifact (upstream-held) or the base pin holds it under the reproducibility policy
        # (policy-held). Consult the model ONLY when there is a signal (an SBOM carrier for this
        # component, or the manifest marks the base policy-held for this scope); a module WE build is
        # always pullable by our own bump, so it is never this class. Route the not-pullable case to
        # §2B — never §3 "fix not resolvable", never §2A "no fix exists" (AC1). When the model reports
        # the fix has BECOME pullable, control falls through to the lift/bump path below (AC4).
        carrier = _carrier_for(env.get("carriers"), _purls)
        base_hold = bool(env.get("base_policy_held"))
        pull = None
        if (carrier or base_hold) and not gf["is_go"]:
            pctx = {"kind": "pullability", "finding_id": c, "component": gf["package"],
                    "installed_version": gf["installed"], "component_fixed": gf["fixed"],
                    "purl": (subs or [None])[0], "carrier": carrier, "base": env.get("base"),
                    "candidate_digest": env["digest"]}
            pull = _pullability(env["adjudicator"], pctx, env["state"])
            if pull is not None:
                m_inc = 1
        # An acceptance requires ACTIONABLE evidence: a not-pullable verdict is written as accepted
        # risk ONLY when it carries a machine-checkable lift trigger (AC3). An incomplete verdict
        # ({"pullable": false} with no lift trigger) must NOT create a silent suppression — it falls
        # through to the normal fixable routing, so the finding stays visible (Codex R1 residual 3).
        _not_pullable = bool(pull and pull.get("pullable") is False and (pull.get("lift_trigger") or "").strip())
        if _not_pullable:
            hold = pull.get("hold") or ("policy-held" if (base_hold and not carrier) else "upstream-held")
            # An expired carried acceptance for THIS scope reopens into §3 BEFORE re-accepting — a
            # lapsed time box is never silently renewed just because the fix is still not pullable
            # (REQ-AUD-2 AC5c; parity with the no-fix expiry path, which skipped a fixed finding).
            if _cexp and _cexp <= env.get("today", ts[:10]):
                row.update(section=3, disposition="reopened: prior acceptance expired",
                           action="time box lapsed %s — ignore removed; policy re-applied from scratch" % _cexp,
                           reason="acceptance expired %s (fix exists but was not pullable)" % _cexp,
                           reopened_expired=_cexp, vex_id=this_scope_id, scope_purls=_purls,
                           is_os=not gf["is_go"], not_pullable=None,
                           reopened_scope=[c, list(this_scope[0]), list(this_scope[1])])
                return row, m_inc
            this_exp2 = _cexp or exp
            lift_trigger = pull.get("lift_trigger") or ""
            comp_fixed = pull.get("component_fixed") or gf["fixed"]
            ev = {"check": "fix-not-pullable", "hold": hold, "carrier": carrier,
                  "component": gf["package"], "installed": gf["installed"], "component_fixed": comp_fixed,
                  "candidate_release": pull.get("candidate_release"),
                  "bump_attempted": pull.get("bump_attempted"), "bump_result": pull.get("bump_result"),
                  "repo_version": pull.get("repo_version"), "base_release": pull.get("base_release"),
                  "evidence": pull.get("evidence")}
            vex.write(out, c, "affected", ts,
                      action="fix exists but is not pullable (%s); tracked; re-checked daily" % hold,
                      evidence=ev, target_date=this_exp2, lift_trigger=lift_trigger, vex_name=vn, subcomponents=subs)
            scanners = sorted({f["scanner"] for f in findings})
            for sc in scanners:
                cli.writej(os.path.join(out, "ignores", sc, vn + ".json"),
                           {"id": c, "vex": this_scope_id, "expiry": this_exp2, "scoped_purls": _purls,
                            "reason": "fix not pullable (%s); re-checked daily" % hold})
            if hold == "policy-held":
                case = ("fix exists in %s as %s; not pullable: policy-held — our base pin %s predates it; "
                        "lifts on base release >= %s"
                        % ((env.get("base") or {}).get("repo") or gf["package"],
                           pull.get("repo_version") or comp_fixed,
                           pull.get("base_release") or (env.get("base") or {}).get("release") or "base",
                           pull.get("candidate_release") or pull.get("repo_version") or "R"))
            else:
                cr_name = (carrier or {}).get("carrier") or (carrier or {}).get("carrier_purl") or "the carrier"
                cr_ver = (carrier or {}).get("carrier_version") or "?"
                case = ("fix exists in %s >= %s; not pullable: carried by %s at %s; lifts when %s"
                        % (gf["package"], comp_fixed, cr_name, cr_ver,
                           lift_trigger or ("%s embeds %s >= %s" % (cr_name, gf["package"], comp_fixed))))
            in_kev = c in env["kev_ids"] or bool(set(aliases) & env["kev_ids"])
            reason = policy.threshold_reason(gf["severity"], in_kev, gf["known_exploited"])
            at = reason != "below"
            if not at and not env.get("kev_ok", True):
                at = True; reason = "kev-unavailable (fail-closed)"
            row.update(section=2, not_pullable=hold, disposition="carried (fix not pullable)",
                       action="POA&M: affected VEX + ignores + lift trigger, expiry %s" % this_exp2,
                       vex_id=this_scope_id, scope_purls=_purls, reason=case, fixed=comp_fixed,
                       ignore_files=[os.path.join("ignores", sc, vn + ".json") for sc in scanners] + [".snyk", "osv-scanner.toml"],
                       threshold=("at_or_above" if at else "below"), expiry=this_exp2,
                       carried=(_cstat == "affected"), lift_trigger=lift_trigger, is_os=not gf["is_go"],
                       reachability="n/a (OS package)")
            if at:
                row["action"] += "; owner-decision issue pending"
                row["owner_issue_intent"] = {
                    "cve": c, "package": gf["package"], "kind": "risk_acceptance", "reason_key": reason,
                    "scope": "%s@%s (severity %s, %s)" % (gf["package"], gf["installed"], gf["severity"], case)}
            return row, m_inc
        # A scope carried AS NOT-PULLABLE (§2B) must NEVER lift without POSITIVE confirmation the fix
        # became pullable. A model outage, a refusal, an incomplete verdict, or a vanished carrier
        # signal on a later recheck must RE-CARRY the suppression — never fabricate "lifted (fix now
        # pullable)" and delete the VEX with no evidence (Sonnet round-1 blocker 1). Only a confirmed
        # pullable=True verdict falls through to the lift below.
        confirmed_pullable = bool(pull and pull.get("pullable") is True)
        if (c, this_scope) in env.get("carried_not_pullable", set()) and not confirmed_pullable:
            if _cexp and _cexp <= env.get("today", ts[:10]):
                row.update(section=3, disposition="reopened: prior acceptance expired",
                           action="time box lapsed %s — ignore removed; policy re-applied from scratch" % _cexp,
                           reason="acceptance expired %s (fix exists but not pullable; recheck deferred)" % _cexp,
                           reopened_expired=_cexp, vex_id=this_scope_id, scope_purls=_purls,
                           is_os=not gf["is_go"], reopened_scope=[c, list(this_scope[0]), list(this_scope[1])])
                return row, m_inc
            hold = "policy-held" if (base_hold and not carrier) else "upstream-held"
            this_exp3 = _cexp or exp
            cause = "adjudicator unavailable" if (carrier or base_hold) and pull is None else "carrier signal absent this run"
            # preserve the CONCRETE machine-checkable lift trigger from the prior acceptance rather
            # than a generic placeholder, so a deferred recheck does not lose the condition (Codex
            # round-2 P2). Falls back to a note only if none was carried.
            prior_trigger = env.get("carried_lift_trigger", {}).get((c, this_scope))
            deferred_trigger = (prior_trigger if prior_trigger
                                else "prior lift trigger stands (recheck deferred: %s)" % cause)
            ev = {"check": "fix-not-pullable", "hold": hold, "recheck": "deferred", "cause": cause,
                  "component": gf["package"], "installed": gf["installed"], "component_fixed": gf["fixed"],
                  "lift_trigger": deferred_trigger}
            vex.write(out, c, "affected", ts,
                      action="fix exists but is not pullable (%s); recheck deferred (%s); suppression retained" % (hold, cause),
                      evidence=ev, target_date=this_exp3, lift_trigger=deferred_trigger,
                      vex_name=vn, subcomponents=subs)
            _scn = sorted({f["scanner"] for f in findings})
            for sc in _scn:
                cli.writej(os.path.join(out, "ignores", sc, vn + ".json"),
                           {"id": c, "vex": this_scope_id, "expiry": this_exp3, "scoped_purls": _purls,
                            "reason": "fix not pullable (%s); recheck deferred; re-checked daily" % hold})
            # A deferred recheck NEVER downgrades the policy threshold: recompute it and preserve
            # the owner-acceptance requirement, or the release gate silently drops a Critical/KEV
            # finding's owner-decision hold when a later recheck merely could not confirm the fix
            # (Codex round-2 P1). The owner-issue dedup means re-asserting it updates the standing
            # issue, it does not spam a new one.
            _in_kev = c in env["kev_ids"] or bool(set(aliases) & env["kev_ids"])
            _reason = policy.threshold_reason(gf["severity"], _in_kev, gf["known_exploited"])
            _at = _reason != "below"
            if not _at and not env.get("kev_ok", True):
                _at = True; _reason = "kev-unavailable (fail-closed)"
            row.update(section=2, not_pullable=hold, disposition="carried (fix not pullable) — recheck deferred",
                       action="POA&M: affected VEX + ignores retained, expiry %s; recheck deferred (%s)" % (this_exp3, cause),
                       vex_id=this_scope_id, scope_purls=_purls, fixed=gf["fixed"],
                       reason="fix exists but not pullable; recheck could not confirm a lift (%s)" % cause,
                       ignore_files=[os.path.join("ignores", sc, vn + ".json") for sc in _scn] + [".snyk", "osv-scanner.toml"],
                       threshold=("at_or_above" if _at else "below"), expiry=this_exp3, lift_trigger=deferred_trigger,
                       carried=(_cstat == "affected"), is_os=not gf["is_go"], reachability="n/a (OS package)")
            if _at:
                row["action"] += "; owner-decision issue pending"
                row["owner_issue_intent"] = {
                    "cve": c, "package": gf["package"], "kind": "risk_acceptance", "reason_key": _reason,
                    "scope": "%s@%s (severity %s, %s; recheck deferred: %s)"
                             % (gf["package"], gf["installed"], gf["severity"], hold, cause)}
            return row, m_inc
        # AC7: a fix that is now pullable LIFTS a suppression this scope was carrying — the old
        # affected/temporary VEX, ignore and inventory for this exact scope are removed this run
        # (delivery drops them) and the row is §1 lifted; otherwise a fresh fixable finding is §3.
        lifted = _carried or bool(env.get("carried_expiry", {}).get((c, this_scope)))
        lift_note = "; prior suppression lifted (VEX/ignore/inventory removed)" if lifted else ""
        # REQ-AUD-14 AC4: when a NOT-PULLABLE carried scope lifts because the model reports the fix
        # has become pullable, name the carrier/base release that reached the trigger — never drop it
        # (Codex round-1 residual 5). The bump itself follows the ecosystem path below.
        if lifted and pull and pull.get("pullable") and pull.get("candidate_release"):
            lift_note += "; lift trigger met: %s embeds the fix" % pull.get("candidate_release")
        if gf["is_go"]:
            # A module WE BUILD: the auditor delivers the bump itself as a DRAFT PR through the
            # App path (go get module@fixed + go mod tidy, go.mod/go.sum only) — the actual
            # delivery + honest action text are set in run() after routing (decision 2). Record
            # the bump intent here; an unresolvable fixed version stays in §3, never a broken PR.
            row["fix_bump"] = {"cve": c, "module": gf["package"], "from": gf["installed"], "to": gf["fixed"]}
            row["lift_note"] = lift_note
            row.update(section=(1 if lifted else 3),
                       disposition=("lifted (fix now pullable)" if lifted else "real, fixable (we build it)"),
                       action="bump pending delivery" + lift_note,
                       fixed=gf["fixed"], reason="pullable fix in a module we build")
        else:
            # An OS PACKAGE fix comes with the base image: defer to Dependabot's docker PR
            # (REQ-AUD-2 AC3). The base is digest-pinned on purpose and the auditor never edits
            # a base digest or races Dependabot over the network — the Dependabot docker
            # ecosystem runs daily (.github/dependabot.yml). POA&M shape: stays in §3 awaiting
            # the base rebuild.
            row.update(section=(1 if lifted else 3),
                       disposition=("lifted (fix now pullable)" if lifted else "real, fixable (base rebuild)"),
                       action=("awaiting base rebuild %s — defer to Dependabot's docker PR "
                               "(base is digest-pinned; the auditor does not edit it)" % gf["fixed"]) + lift_note,
                       fixed="base-image %s" % gf["fixed"], reachability="n/a (OS package)",
                       reason="awaiting base rebuild %s (Dependabot docker ecosystem, daily)" % gf["fixed"],
                       base_rebuild=True)
        if lifted:
            row["reopened_scope"] = [c, list(this_scope[0]), list(this_scope[1])]
        return row, m_inc
    # Expiry is keyed by this disposition's SCOPE (REQ-AUD-13 AC6): the carried time box for
    # exactly this scope. If it has PASSED, only THIS scope reopens into §3 and only its
    # statement/ignore/inventory are removed (delivery); if it is still open, the ORIGINAL
    # deadline is preserved — an ordinary run never renews it; only a NEW acceptance (no
    # carried box for this scope) gets a fresh 30-day box.
    this_exp = _cexp or exp                   # preserve the ORIGINAL box; new box only for a new scope
    # no upstream fix -> POA&M (§2), at/above threshold -> owner issue.
    in_kev = c in env["kev_ids"] or bool(set(aliases) & env["kev_ids"])
    reason = policy.threshold_reason(gf["severity"], in_kev, gf["known_exploited"])
    at = reason != "below"
    if not at and not env.get("kev_ok", True):
        # KEV membership could not be checked -> do not downgrade; escalate (fail closed).
        at = True; reason = "kev-unavailable (fail-closed)"
    vex.write(out, c, "affected", ts, action="no fix upstream; tracked; re-checked daily",
              evidence={"check": "reachable-no-fix", "source_file": "manifest", "detail": gf["nofix_reason"]},
              target_date=this_exp, vex_name=vn, subcomponents=subs)
    _ig_scanners = sorted({f["scanner"] for f in findings})
    for sc in _ig_scanners:
        cli.writej(os.path.join(out, "ignores", sc, vn + ".json"),
                   {"id": c, "vex": this_scope_id, "expiry": this_exp, "scoped_purls": _purls,
                    "reason": "accepted risk; re-checked daily"})
    action = "POA&M: affected VEX + ignores, expiry %s" % this_exp
    # name the ignore artifacts this acceptance actually writes so the row line is honest — a
    # §2 POA&M without ignore_files defaulted _row_line to "ignores: none" (Codex round-2 P2).
    _ig_files = [os.path.join("ignores", sc, vn + ".json") for sc in _ig_scanners] + [".snyk", "osv-scanner.toml"]
    row.update(section=2, disposition="carried (POA&M)", action=action, vex_id=this_scope_id,
               scope_purls=_purls, reason="%s; %s" % (gf["nofix_reason"], reason), ignore_files=_ig_files,
               threshold=("at_or_above" if at else "below"), expiry=this_exp, carried=(_cstat == "affected"))
    if at:
        # at/above threshold -> owner-decision issue, deduped per (CVE, package) with every scope
        # listed in the body and emitted after routing (fix 4) — never one issue per binary that
        # vendors the same package. run() sets the final action / owner_issue / issue_failed.
        row["action"] = action + "; owner-decision issue pending"
        row["owner_issue_intent"] = {
            "cve": c, "package": gf["package"], "kind": "risk_acceptance", "reason_key": reason,
            "scope": "%s@%s (severity %s, threshold %s, no fix: %s)"
                     % (gf["package"], gf["installed"], gf["severity"], reason, gf["nofix_reason"])}
    return row, m_inc


def run(manifest_path, dry, out, today, kevpath=None, adjudicator=None):
    m, groups = C.manifest_findings(manifest_path)
    # A test image is never shipped, so no statement on `main` applies and nothing is delivered:
    # a test image ALWAYS forces dry_run regardless of the dispatch input (REQ-AUD-15 AC9).
    if (m.get("provenance") or {}).get("source") == "test-image":
        dry = True
    gvc, module, gvc_usable = C.manifest_gvc(m)
    logpath = m.get("known_defect_log"); ts = today + "T00:00:00Z"
    idx = log_index(logpath)
    # REQ-AUD-16 AC3: generate the knowledge document the model reads for pattern judgment from the
    # structured records (the known-defect log), deterministically and with no model call, and
    # carry it in the run output. Only TRUSTED rows contribute (a model-proposed row is excluded).
    _klog = {}
    if logpath and os.path.exists(logpath):
        try:
            _klog = json.load(open(logpath))
        except Exception:
            _klog = {}
    knowledge_doc = K.generate(_klog)
    cli.writef(os.path.join(out, ".auditor", "knowledge.md"), knowledge_doc)
    adjudicator = adjudicator or cli.opt("--adjudicator", os.path.join(HERE, "auditor-adjudicator-client.py"))
    # KEV availability is threshold EVIDENCE: an unavailable/malformed catalog is NOT the same
    # as "checked, not a member" (R1 outer round-3 #1). kev_ok=False fails threshold closed
    # (a below-threshold no-fix finding is escalated to at_or_above) so risk is never silently
    # downgraded when CISA is unreachable.
    kev_ids = set(); kev_ok = True
    if kevpath is not None:
        if os.path.exists(kevpath):
            try:
                from auditorlib import parsers as P
                kev_ids = P.parse_kev(kevpath)
            except Exception:
                kev_ok = False
        else:
            kev_ok = False
    exp = _expiry(today)
    state = {"tokens": 0, "iters": 0, "roles_used": set()}
    # Carried acceptances from the checkout: when a time box has passed, the finding must
    # REOPEN (§3) this run and its ignore be removed, never silently renewed (REQ-AUD-2 AC5c;
    # R1 outer round-8 #4). Read the delivered inventory the previous run left in the workspace.
    carried_expiry = {}; carried_scopes = set(); carried_status = {}; carried_not_pullable = set()
    carried_lift_trigger = {}
    ws0 = os.environ.get("GITHUB_WORKSPACE")
    if ws0:
        # resolve each carried item to its statement's canonical SCOPE (REQ-AUD-13 AC6), so a
        # foreign/legacy @id is matched by the scope it addresses, not its literal id spelling
        # (R1 refactor round-1 #5). Keyed by scope, per scope — never CVE-wide.
        prev_id_to_scope = {}
        try:
            pv = json.load(open(os.path.join(ws0, ".vex", "fosterstack-cache.openvex.json")))
            for s in pv.get("statements", []):
                if s.get("@id"):
                    prev_id_to_scope[s["@id"]] = _scope_key(s)
                nm = (s.get("vulnerability") or {}).get("name")
                if nm:
                    # every carried (cve, scope) — including a reachability not_affected that has
                    # NO time box — so a pullable fix can lift it (REQ-AUD-13 AC7; R1 refactor #4)
                    carried_scopes.add((nm, _scope_key(s)))
                    # the PUBLISHED status for this exact scope, so the "in force (main)" display
                    # tag is only applied when THIS run writes the SAME disposition already on main:
                    # a scope carried as `affected` but re-dispositioned `not_affected` this run
                    # (e.g. new unreachability evidence) is NOT yet published as not_affected, so it
                    # must render "proposed", not "in force (main)" (Codex round-2 residual #3).
                    carried_status[(nm, _scope_key(s))] = s.get("status")
        except Exception:
            prev_id_to_scope = {}
        try:
            prev = json.load(open(os.path.join(ws0, ".auditor", "accepted-items.json")))
            for it in prev.get("accepted_items", []):
                if not it.get("expiry"):
                    continue
                cve = it.get("cve") or it.get("id")
                if it.get("scope_purls") is not None:
                    sc = ((it.get("product") or policy.VEX_PRODUCT,), tuple(sorted(set(it["scope_purls"]))))
                elif it.get("vex_id") in prev_id_to_scope:
                    sc = prev_id_to_scope[it["vex_id"]]
                else:
                    continue
                key = (cve, sc)                          # per (vulnerability, scope) (R1 refactor round-2 #1)
                carried_expiry[key] = min(it["expiry"], carried_expiry.get(key, it["expiry"]))
                if it.get("not_pullable"):               # REQ-AUD-14: this scope was carried as §2B
                    carried_not_pullable.add(key)
                    if it.get("lift_trigger"):           # preserve the machine-checkable condition
                        carried_lift_trigger[key] = it["lift_trigger"]
        except Exception:
            carried_expiry = {}
    env = {"gvc": gvc, "module": module, "gvc_usable": gvc_usable, "idx": idx, "logpath": logpath,
           "adjudicator": adjudicator, "state": state, "kev_ids": kev_ids, "kev_ok": kev_ok, "exp": exp, "out": out,
           "ts": ts, "dry": dry, "digest": (m.get("candidate_digests") or {}).get("production"),
           "carried_expiry": carried_expiry, "carried_scopes": carried_scopes,
           "carried_status": carried_status, "today": today, "knowledge": knowledge_doc,
           # REQ-AUD-14: SBOM carrier relationships and base-pin evidence for the pullability class.
           "carriers": m.get("carriers") or [], "base": m.get("base") or {},
           "carried_not_pullable": carried_not_pullable, "carried_lift_trigger": carried_lift_trigger,
           # policy-held routing fires when the base is KNOWN to hold a fix: an explicit flag, or a
           # base pin flagged behind its repository's fix by more than the threshold (AC7). On a
           # current base, OS fixes stay on the existing base-rebuild path.
           "base_policy_held": bool((m.get("base") or {}).get("policy_held")) or
           (isinstance((m.get("base") or {}).get("days_behind"), int)
            and (m.get("base") or {})["days_behind"] > (m.get("base") or {}).get("behind_threshold_days", 30))}
    rows = []; would = []; h_count = 0; m_count = 0
    for c, grp in sorted(groups.items()):
        # 1) trusted log FP closes ONLY the PACKAGES the log names (R11 rank 1) — every
        #    finding for one of those packages, across scanners/arches, not just the exact
        #    key. A sibling PACKAGE's finding for the same CVE is NOT closed with it (R1
        #    round-1) and is routed on its own; because that second disposition is a
        #    DIFFERENT package it writes to a DISTINCT VEX/ignore name, so it cannot
        #    overwrite the not_affected one (R1 round-2).
        # coverage is scoped to package AND version (R1 outer round-1 #1): a log FP for
        # libfoo@1 covers every arch/scanner of libfoo@1 (the round-2 same-package fix) but
        # NOT libfoo@2 — a name match cannot establish version applicability without evidence.
        # a trusted-log FP covers only the same package in the same ECOSYSTEM at the same
        # version — never a different ecosystem's package of the same name/version (a Debian
        # backport does not patch an independently installed PyPI dist) (R1 refactor round-4 #2).
        fp_keys = set()   # (ecosystem, package, version)
        for f in grp["findings"]:
            if f.get("_lineage_only"):     # an advisory's defect-log FP is about ITS OWN
                continue                   # vulnerability, not a different bundled CVE (round-8 #1)
            r = idx.get((f["scanner"], f["finding_id"], f["purl"]))
            if r and r.get("disposition") == "false_positive":
                fp_keys.add((_eco(f.get("purl")), (r.get("package") or f.get("package")), _ver_from_purl(f["purl"])))
        def _cov(f):
            return not f.get("_lineage_only") and (_eco(f.get("purl")), f.get("package"), _ver_from_purl(f["purl"])) in fp_keys
        covered = [f for f in grp["findings"] if _cov(f)]
        if covered:
            subs = sorted({f["purl"] for f in covered if f["purl"]})
            covpkgs = sorted({"%s@%s" % (p, v or "?") for (_e, p, v) in fp_keys})
            ev = {"check": "known-defect-log", "source_file": logpath,
                  "detail": "trusted false_positive for %s" % covpkgs}
            vex.write(out, c, "not_affected", ts, justification="vulnerable_code_not_present", evidence=ev, subcomponents=subs or None)
            igf = os.path.join("ignores", "grype", c + ".json")
            _fp_sid = policy.scope_id(c, policy.VEX_PRODUCT, subs or None)
            cli.writej(os.path.join(out, igf), {"vex": _fp_sid, "id": c, "evidence": ev, "scoped_purls": subs})
            # carried: this exact scope's not_affected is already in force on main (unchanged
            # from a prior day) -> "in force (main)" with its published link; a fresh FP, or a
            # scope whose published statement is `affected`, is proposed (Codex round-2 residual #3).
            _fp_carried = carried_status.get((c, ((policy.VEX_PRODUCT,), tuple(subs or [])))) == "not_affected"
            rows.append({"id": c, "package": ",".join(covpkgs) or "?",
                         "installed": (covered[0].get("extra") or {}).get("installed_version") or _ver_from_purl(covered[0].get("purl")) or "?",
                         "fixed": None, "severity": _max_sev(covered), "section": 5,
                         "aliases": sorted(set(sorted(grp["aliases"]) + [c])),
                         "scope_purls": subs or [],
                         "disposition": "not_affected (false positive)", "action": "closed",
                         "reachability": "n/a (OS package)", "reason": "known-defect-log FP for %s" % (",".join(covpkgs)),
                         "vex_id": _fp_sid, "ignore_files": [igf, ".snyk", "osv-scanner.toml", "vex"],
                         "carried": _fp_carried, "is_os": True})
            h_count += 1
            uncovered = [f for f in grp["findings"] if not _cov(f)]
            if uncovered:
                # distinct VEX/ignore name so the sibling's disposition never clobbers the FP one
                rs, mi = _dispose_split(c, uncovered, sorted(grp["aliases"]), env, would, base=c + "-sibling")
                rows.extend(rs); m_count += mi
            continue
        rs, mi = _dispose_split(c, grp["findings"], sorted(grp["aliases"]), env, would)
        rows.extend(rs); m_count += mi

    # after routing: per-scanner tables to the job log + reports/scanner-tables.txt (report item 1)
    try:
        _scanner_tables(m, rows, out)
    except Exception as e:
        print("scanner-tables emit failed: %s" % e)
    # sections + status
    sections = {n: [] for n in range(1, 8)}
    for r in rows:
        sections[r["section"]].append(r)
    # §7 "Currently suppressed": the VEX statements in force this run (every not_affected/
    # affected disposition), so the section reflects real state instead of always claiming
    # none (R1 round-4). A cross-cutting view — the same rows also appear in §5/§2.
    for r in rows:
        if r["section"] in (2, 5):
            sections[7].append(dict(r, action="suppression in force (%s)" % (r.get("vex_id") or "VEX")))
    # findings_without_action is computed AFTER delivery (below), once every §1/§3 row's action
    # is final and the dry-run `would` list is populated (decision 2 moved fix delivery there).
    # A Go-module fix (a module WE build) is DELIVERED as its own draft bump PR through the App
    # path below; a base rebuild defers to Dependabot's daily docker PR. §6 pending flags and the
    # honest action text are set by that delivery loop — not proposed-only here.
    # ---- owner-decision issues, emitted AFTER routing ----
    # (a) A GLOBAL adjudicator outage: if any finding was unassessed because the model was
    # UNAVAILABLE, open exactly ONE issue naming the count and the (masked) cause — never one per
    # finding (R-live fix 3) — and mark the run INCOMPLETE (below).
    adj_unavailable = [r for r in rows if r.get("adjudicator_error")]
    adj_err_msgs = sorted((state.get("adj_errors") or {}).values())
    adjudicator_down = bool(adj_unavailable)
    adj_cause = "; ".join(adj_err_msgs) or "model calls failed"
    if adjudicator_down:
        n = len(adj_unavailable)
        ids = ", ".join(sorted({r["id"] for r in adj_unavailable}))
        title = policy.subject("owner-decision: adjudicator unavailable — %d findings unassessed" % n)
        body = ("The adjudicator was unavailable this run: %d finding(s) could not be assessed "
                "(primary/rephrase/fallback all failed). Cause: %s. The run is INCOMPLETE; no "
                "disposition was inferred for these findings. Findings: %s"
                % (n, adj_cause, ids[:1500]))
        ok, ref = _emit_owner_issue(title, body, dry, would)
        _delivered = ok and ref not in ("dry", "skipped")
        for r in adj_unavailable:
            r["owner_issue"] = ref if ok else None
            if _delivered:
                r["action"] = "unassessed: adjudicator unavailable; one owner-decision issue opened"
            elif ok:
                r["action"] = "unassessed: adjudicator unavailable; one owner-decision issue " + _issue_pending_note(ref)
            else:
                r["action"] = "unassessed: adjudicator unavailable; OWNER ISSUE FAILED"
            r["issue_failed"] = (not ok)
    # (b) Genuine per-finding escalations, DEDUPED per (CVE, package) with every scope listed in the
    # body (R-live fix 4): one issue per (CVE, package), never one per binary that vendors it.
    _intents = {}
    for r in rows:
        it = r.get("owner_issue_intent")
        if it:
            _intents.setdefault((it["cve"], it["package"]), []).append((r, it))
    for (cve, pkg), group in _intents.items():
        kind = group[0][1]["kind"]; reason_key = group[0][1]["reason_key"]
        scopes = sorted({it["scope"] for _r, it in group})
        title = policy.owner_issue_title(cve, pkg, reason_key)
        if kind == "risk_acceptance":
            body = ("Accept risk for %s in %s? No pullable upstream fix; an affected VEX + %d-day "
                    "ignores are carried in this run's suppression package (the artifact/PR). "
                    "Scope(s) (%d):\n- %s\n\nReply on this issue: `ACCEPT %s until YYYY-MM-DD` or "
                    "`REJECT %s`." % (cve, pkg, policy.IGNORE_EXPIRY_DAYS, len(scopes),
                                      "\n- ".join(scopes), cve, cve))
        else:
            body = ("Finding %s in %s could not be assessed after the primary/rephrase/fallback "
                    "chain. Owner decision needed. Scope(s) (%d):\n- %s\n\nAccept, reject, or "
                    "provide guidance." % (cve, pkg, len(scopes), "\n- ".join(scopes)))
        ok, ref = _emit_owner_issue(title, body, dry, would)
        _delivered = ok and ref not in ("dry", "skipped")
        for r, _it in group:
            r["owner_issue"] = ref if ok else None
            r["issue_failed"] = (not ok)
            if kind == "risk_acceptance":
                base = r["action"].replace("; owner-decision issue pending", "")
                if _delivered:
                    r["action"] = base + "; owner-decision issue opened/updated (issues:write)"
                elif ok:
                    r["action"] = base + "; owner-decision issue " + _issue_pending_note(ref)
                else:
                    r["action"] = base + "; OWNER ISSUE FAILED"
            else:
                if _delivered:
                    r["action"] = "escalated to owner-decision issue"
                elif ok:
                    r["action"] = "owner-decision issue " + _issue_pending_note(ref)
                else:
                    r["action"] = "OWNER ESCALATION FAILED"
    # a failed owner escalation (POA&M at-threshold, or §4 unassessed-after-fallback) is a
    # real gap: the required human decision was not delivered (R1 outer round-1 #4/#5).
    issue_failures = sum(1 for r in rows if r.get("issue_failed"))
    # Build the acceptance inventory AFTER the owner-decision emission above, so each item records
    # the REAL owner_issue reference the emission set on its row. Built earlier, it captured
    # owner_issue=None for every at-or-above item, and the release gate then HELD every such
    # release ("has no owner-decision issue") even after the owner accepted the risk — a wrong,
    # fail-closed hold of a legitimately-authorized tag (owner review, Sep 26).
    accepted = [{"cve": r["id"], "severity": r["severity"], "package": r["package"],
                 "threshold": r.get("threshold", "at_or_above" if r.get("owner_issue") else "below"),
                 "owner_issue": r.get("owner_issue"), "expiry": r.get("expiry", exp),
                 "vex_id": r.get("vex_id"),                       # the governing statement id
                 "product": policy.VEX_PRODUCT,                   # the FULL canonical scope, so
                 "scope_purls": r.get("scope_purls") or [],       # inventory keys on scope, not a hash
                 "not_pullable": r.get("not_pullable"),           # REQ-AUD-14: the §2B hold kind, if any
                 "lift_trigger": r.get("lift_trigger")}           # the machine-checkable lift condition
                for r in sections[2]]
    # write the acceptance inventory BEFORE delivery so the suppression PR can carry it — the
    # release gate reads .auditor/accepted-items.json from the checkout (R1 outer round-1 #7).
    cli.writej(os.path.join(out, ".auditor", "accepted-items.json"),
               {"accepted_items": accepted, "run_date": today, "candidate_commit": m.get("commit")})
    # REQ-AUD-16 AC4: model-proposed defect-log/knowledge entries are delivered in the draft PR as
    # PROPOSALS only — never applied to the live known-defect log or knowledge doc this run. They
    # take effect only after the owner merges the audit-lane PR that reviews them.
    if state.get("proposals"):
        cli.writej(os.path.join(out, ".auditor", "proposals", "adjudicator-proposals.json"),
                   {"proposals": state["proposals"], "run_date": today,
                    "candidate_commit": m.get("commit"),
                    "note": ("MODEL PROPOSALS — not applied. Each entry is a model suggestion for a "
                             "new known-defect-log entry or knowledge note; it takes effect only "
                             "after this PR is merged and an audit-lane reviewer promotes it to a "
                             "trusted row. The auditor never applies these itself (REQ-AUD-16 AC4).")})
    # Scopes whose carried acceptance expired and were reopened this run — delivery drops those
    # exact statements/ignores by canonical SCOPE (never CVE-wide), never renewing them
    # (REQ-AUD-13 AC6). Serialized as [[products], [purls]] pairs.
    _seen = set(); reopened = []
    for r in rows:
        rs = r.get("reopened_scope")
        if rs:
            k = (rs[0], tuple(rs[1]), tuple(rs[2]))     # (cve, products, purls)
            if k not in _seen:
                _seen.add(k); reopened.append(rs)
    cli.writej(os.path.join(out, ".auditor", "reopened-expired.json"), {"reopened": reopened})
    # Inventory quorum (R12 (b)): the candidate must be inventoried by at least THREE image
    # scanners whose OS package counts agree within tolerance. A fourth scanner that cannot
    # read this image (osv-scanner does not read a distroless dpkg status.d) is RECORDED as
    # 'did not run' but does not by itself fail the audit when three others agree.
    st = m.get("scanner_status") or {}
    def _os(s):
        return (st.get(s) or {}).get("os_package_count") or 0
    def _inv(s):
        # Inventoried the OS layer for the QUORUM: ran AND reported > 0 OS packages AND not an
        # excluded outlier. A scanner reporting 0 OS packages did NOT inventory the OS layer for
        # this image (osv-scanner on a distroless dpkg status.d; grype/osv on a Go-only image) —
        # it ABSTAINS from the OS-package quorum, it is not a disagreeing vote (R-live fix 2).
        info = st.get(s) or {}
        return bool(info.get("ran")) and _os(s) > 0 and info.get("quorum_ok", True)
    def _ran_os(s):
        info = st.get(s) or {}
        return bool(info.get("ran")) and _os(s) > 0
    ran_image = [s for s in IMAGE_SCANNERS if _inv(s)]     # scanners that inventoried OS packages
    excluded = [s for s in IMAGE_SCANNERS if _ran_os(s) and not (st.get(s) or {}).get("quorum_ok", True)]
    not_ran = [s for s in IMAGE_SCANNERS if not _ran_os(s)]    # did not inventory the OS layer
    oscounts = [_os(s) for s in ran_image]
    agree = bool(oscounts) and max(oscounts) > 0 and (min(oscounts) >= 0.5 * max(oscounts))
    quorum = len(ran_image) >= 3 and agree
    # the honest quorum for the header uses THIS agreement decision, not per-scanner default
    # flags (R1 refactor round-4 #8): when the inventorying scanners' OS counts do not agree
    # numerically, none is labelled "agreed".
    _mx = max(oscounts) if oscounts else 0
    quorum_info = {"agreed": [s for s in ran_image if agree and _mx and _os(s) >= 0.5 * _mx],
                   "disagreed": [s for s in ran_image if not (agree and _mx and _os(s) >= 0.5 * _mx)],
                   "not_ran": not_ran, "excluded": excluded,
                   # the exact per-scanner OS counts the quorum compared, so the status/header line
                   # is credible: "3 of 4 inventoried" is shown against the real 0/53/0/53 (fix 2)
                   "os_counts": {s: _os(s) for s in IMAGE_SCANNERS}}
    # consolidate every per-CVE VEX into the canonical suppression files, run the consistency
    # check over THAT layout, then DELIVER the suppressions as one draft PR via the App token
    # (R16). A push/PR failure is AUDIT INCOMPLETE with the git/gh stderr — never "opened".
    supp, nstmt = _consolidate(out, ts)
    consistency = _consistency(out, supp, manifest_path)
    cons_failed = any(p.get("type", "").startswith("consistency-check-") for p in (consistency or {}).get("problems", []))
    is_test = (m.get("provenance") or {}).get("source") == "test-image"
    pr_url, pr_err = _deliver_suppression_pr(out, supp, nstmt, today, m.get("commit"), dry, would, is_test=is_test)
    # Decision 2: the auditor DELIVERS its own Go-module bumps as draft PRs through the App path
    # (go get + go mod tidy, go.mod/go.sum only). Each §1/§3 row carrying a fix_bump gets one
    # draft PR; an unresolvable fixed version stays in §3 (never a broken PR); a git/gh/tidy
    # failure marks the run INCOMPLETE. Base rebuilds are NOT delivered here — they defer to
    # Dependabot's daily docker PR (REQ-AUD-2 AC3). The honest action text is set from the
    # delivery status, replacing the pre-delivery placeholder.
    fix_errs = []
    for r in rows:
        if not r.get("fix_bump"):
            continue
        fb = r["fix_bump"]; lift = r.get("lift_note", "")
        furl, ferr, fstatus = _deliver_fix_pr(r, today, m.get("commit"), dry, would, is_test=is_test)
        if fstatus == "delivered":
            r["action"] = ("opened draft bump PR: %s" % (furl or "(App bot)")) + lift
            r["fix_pr_url"] = furl
        elif fstatus == "would":
            r["action"] = ("dry run: would open draft bump PR %s %s -> %s" % (fb["module"], fb["from"], fb["to"])) + lift
        elif fstatus == "unresolvable":
            r["action"] = ("fix not resolvable: %s@%s did not resolve from the module proxy — stays in section 3" % (fb["module"], fb["to"])) + lift
        elif fstatus == "skipped-test":
            r["action"] = "test-image run: no bump PR (not a shipped image)" + lift
        elif fstatus == "pending":
            r["action"] = "bump PR pending: no authorized delivery step this run" + lift
            r["pending_delivery"] = True
        else:  # 'error'
            r["action"] = ("bump PR delivery FAILED (run INCOMPLETE): %s" % ferr) + lift
            r["pending_delivery"] = True
            fix_errs.append(ferr)
    # Now every §1/§3 row action is final: a §2/§3 row still lacking an action is a real gap. In
    # a dry run that surfaced NO would-open work at all for its §3 rows, count them as unactioned.
    findings_without_action = sum(1 for r in rows if r["section"] in (2, 3) and (not r["action"] or r["action"] == "none"))
    if dry and sections[3] and not would:
        findings_without_action += len(sections[3])
    complete = ((findings_without_action == 0) and quorum and (pr_err is None)
                and (issue_failures == 0) and not cons_failed and not fix_errs
                and not adjudicator_down)
    if complete:
        status = "AUDIT COMPLETE"
    else:
        bits = []
        # Name the ACTUAL cause first: an unavailable adjudicator leaves findings unassessed
        # (R-live fix 2) — this is the primary failure of a run whose model calls all errored.
        if adjudicator_down:
            bits.append("%d findings unassessed: adjudicator unavailable (%s)"
                        % (len(adj_unavailable), adj_cause))
        if findings_without_action:
            bits.append("%d findings without an action" % findings_without_action)
        if not quorum:
            # show the exact per-scanner OS counts the quorum compared, so "N of 4 inventoried"
            # is credible against the real numbers (fix 2). A 0 means that scanner did not
            # inventory the OS layer (it abstains; it is not a disagreeing vote).
            counts = ", ".join("%s(%d)" % (s, quorum_info["os_counts"].get(s, 0)) for s in IMAGE_SCANNERS)
            bits.append("OS-package quorum not met: %d of 4 inventoried the OS layer [OS counts: %s] "
                        "(need 3 agreeing within 50%%); agreed: %s; did not inventory OS: %s; excluded: %s"
                        % (len(ran_image), counts, ", ".join(quorum_info["agreed"]) or "none",
                           ", ".join(not_ran) or "none", ", ".join(excluded) or "none"))
        if pr_err:
            bits.append("suppression PR delivery failed: %s" % pr_err)
        if issue_failures:
            bits.append("%d owner-decision issue(s) failed to open" % issue_failures)
        if cons_failed:
            bits.append("consistency check did not complete")
        if fix_errs:
            bits.append("%d bump PR(s) failed to deliver: %s" % (len(fix_errs), "; ".join(fix_errs)))
        status = "AUDIT INCOMPLETE: " + "; ".join(bits)
    fs_hash = _persist(out, rows, today)
    conclusion = _conclusion(adjudicator, sections, m, state)
    # REQ-AUD-17 AC2: drive the single standing "needs a human" issue from the same §0 list the
    # report shows — comment it (find-or-create) while §0 is non-empty; close it when §0 is empty.
    needs = _needs_human(rows, sections, dry, pr_url, status)
    _standing_ok, _standing_ref = _standing_issue(needs, dry, would)
    report = _render(m, rows, sections, would, status, dry, adjudicator, consistency, fs_hash, conclusion, pr_url, pr_err, quorum_info, state)
    cli.writef(os.path.join(out, "report.md"), report)
    cli.writej(os.path.join(out, ".auditor", "accepted-items.json"),
               {"accepted_items": accepted, "run_date": today, "candidate_commit": m.get("commit")})
    cli.writej(os.path.join(out, "classification.json"),
               {"findings": [{"id": r["id"], "section": r["section"], "disposition": r["disposition"],
                              "action": r["action"]} for r in rows],
                "status": status, "complete": complete})
    print(status)
    return complete


def _expiry(today):
    import datetime
    return (datetime.datetime.strptime(today, "%Y-%m-%d") + datetime.timedelta(days=policy.IGNORE_EXPIRY_DAYS)).strftime("%Y-%m-%d")


def _consistency(out, supp, manifest_path):
    # A FAILED consistency check is NOT "clean" (R1 outer round-4 #4): a nonzero exit or a
    # missing result is recorded as a problem so the run is not reported verified-and-complete.
    cj = os.path.join(out, "consistency.json")
    try:
        r = subprocess.run([sys.executable, os.path.join(HERE, "auditor-consistency.py"),
                            "--suppression-dir", supp, "--live-findings", manifest_path,
                            "--out", cj], capture_output=True, text=True)
        if r.returncode == 0 and os.path.exists(cj):
            return json.load(open(cj))
        return {"problems": [{"type": "consistency-check-failed",
                              "detail": "rc=%d %s" % (r.returncode, (r.stderr or "").strip()[:200])}]}
    except Exception as e:
        return {"problems": [{"type": "consistency-check-error", "detail": str(e)}]}


def _persist(out, rows, today):
    import hashlib
    payload = json.dumps(sorted((r["id"], r["disposition"]) for r in rows)).encode()
    h = hashlib.sha256(payload).hexdigest()
    cli.writej(os.path.join(out, ".auditor", "run-state.json"),
               {"run_date": today, "finding_set_hash": h,
                "dispositions": {r["id"]: r["disposition"] for r in rows}})
    return h


# forbidden vendor/model identifiers that must never reach the persisted report (R1 outer
# round-1 #9). The federation audience/import elsewhere is separately acknowledged; a model
# narrative must not name a provider or model.
FORBIDDEN_NAMES = re.compile(r"anthropic|claude|openai|chatgpt|gpt-|codex|sonnet|opus|gemini|llama|private-model|canary", re.I)


def _configured_model_values():
    """The model identifiers this run is actually configured with (AUDITOR_MODEL_*). The
    report must not disclose them even when they carry no vendor substring the fixed
    vocabulary knows (R1 outer round-8 #7)."""
    out = []
    for k, v in os.environ.items():
        if k.startswith("AUDITOR_MODEL") and v and len(v.strip()) >= 3:
            out.append(re.escape(v.strip()))
    return out


def _narrative_ok(text, sections):
    if FORBIDDEN_NAMES.search(text):     # no vendor/model attribution in the report
        return False
    cfg = _configured_model_values()
    if cfg and re.search("|".join(cfg), text, re.I):   # nor the configured model identifiers
        return False
    ids_in = {r["id"] for lst in sections.values() for r in lst}
    named = set(re.findall(r"(?:CVE-\d{4}-\d+|GO-\d{4}-\d+)", text))
    if named - ids_in:
        return False
    s3 = {r["id"] for r in sections[3]}; s5 = {r["id"] for r in sections[5]}; low = text.lower()
    for fid in named:
        for mt in re.finditer(re.escape(fid), text):
            w = low[max(0, mt.start() - 80):mt.end() + 80]
            if fid in s3 and re.search(r"not affected|closed|false positive", w):
                return False
            if fid in s5 and re.search(r"reachable|must fix|exploitable", w):
                return False
    return True


def _conclusion(adjudicator, sections, m, state=None):
    if "stub" in os.path.basename(adjudicator or "").lower():
        return "stub: no narrative — §4 reflects the stub, not the model. The real picture needs the real adjudicator on main."
    if state and state.get("tokens", 0) >= policy.TOKEN_BUDGET:
        return "conclusion withheld: token budget reached before the narrative."
    st = m.get("scanner_status") or {}
    structured = {"image": (m.get("candidate_digests") or {}).get("production"), "commit": m.get("commit"),
                  "package_counts": {s: (st.get(s) or {}).get("package_count") for s in IMAGE_SCANNERS},
                  "sections": {C.TITLES[n]: [r["id"] for r in sections[n]] for n in range(1, 8)}}
    try:
        ans = cli.ask_model(adjudicator, "CONCLUSION", attempt="narrative", model="primary",
                            context={"mode": "narrative", "structured": structured})
        text = (ans.get("narrative") or "").strip()
        if state is not None:
            state["tokens"] += int(ans.get("token_usage") or 0)   # narrative counts against the budget too
            state.setdefault("roles_used", set()).add("primary")
    except Exception:
        # Never echo the exception text into the report: it can carry the model id from an
        # SDK error. A generic withheld line only.
        return "conclusion withheld: the narrative could not be produced this run."
    if not text or not _narrative_ok(text, sections):
        return "conclusion withheld: narrative disagreed with the record."
    return text


def _scanner_tables(m, rows, out):
    """After routing, emit ONE collapsible job-log group per image scanner titled
    '<scanner> — <n> packages, <n> findings' with a fixed-width table (package, installed
    version, vulnerability id, severity, fixed version, disposition = the §1-§7 section it
    landed in). A clean scanner prints a one-line group. The same text is written to
    reports/scanner-tables.txt in the artifact (R1 report item 1). Scanner-agnostic: it
    iterates whatever image scanners the manifest records."""
    from auditorlib import parsers as P
    st = m.get("scanner_status") or {}
    reports = m.get("scanner_reports") or {}
    # map disposition by (identifier, package purl) — the ROUTED scope — not by CVE alone, so two
    # versions of a package that landed in different sections are not both shown for each row
    # (R1 refactor round-4 #6). Index by EVERY identifier the router grouped the scope under
    # (canonical id + all aliases), so an advisory/alias record (e.g. a DSA co-reporting several
    # CVEs) that the router placed in a section is mapped through the router's completed identity
    # rather than an independent re-canonicalization that may pick a different representative
    # (R1 refactor round-5 #4). Fall back to any-purl match on those identifiers if the exact
    # (id, purl) is unmatched.
    sec_by_scope = {}; sec_by_id = {}
    for r in rows:
        for rid in set([r["id"]] + list(r.get("aliases") or [])):
            sec_by_id.setdefault(rid, set()).add(r["section"])
            for purl in (r.get("scope_purls") or []):
                sec_by_scope.setdefault((rid, purl), set()).add(r["section"])

    def _disp(fid, aliases, purl):
        cands = set([fid] + list(aliases or []))
        cands.add(C.canon(fid, aliases))          # also try the record's own canonical form
        secs = set()
        for rid in cands:
            secs |= sec_by_scope.get((rid, purl), set())
        if not secs:                              # purl unmatched: fall back to identifier alone
            for rid in cands:
                secs |= sec_by_id.get(rid, set())
        secs = {x for x in secs if x is not None}
        return ("§" + ",".join(str(x) for x in sorted(secs))) if secs else "-"
    PARSERS = [("grype", P.parse_grype), ("trivy", P.parse_trivy),
               ("osv-scanner", lambda p: P.parse_osv(p, "osv-scanner")), ("snyk", P.parse_snyk)]
    lines = []
    for name, fn in PARSERS:
        info = st.get(name) or {}
        path = reports.get(name)
        pc = info.get("package_count"); fc = info.get("findings")
        title = "%s — %s packages, %s findings" % (name, pc if pc is not None else "?", fc if fc is not None else "?")
        lines.append("::group::" + title)
        if not path or not info.get("ran"):
            lines.append("  did not inventory: %s" % info.get("reason", "no report"))
            lines.append("::endgroup::"); continue
        try:
            findings = fn(path)
        except Exception as e:
            findings = []; lines.append("  (could not parse report: %s)" % e)
        if not findings:
            lines.append("  clean — no findings"); lines.append("::endgroup::"); continue
        table = []
        for f in findings:
            inst = (f.get("extra") or {}).get("installed_version") or _ver_from_purl(f.get("purl")) or "-"
            table.append([f.get("package") or "-", inst, f.get("finding_id") or "-",
                          (f.get("severity") or "-"), (f.get("fixed_version") or "-"),
                          _disp(f.get("finding_id"), f.get("aliases") or [], f.get("purl"))])
        hdr = ["package", "installed", "vulnerability id", "severity", "fixed", "disposition"]
        widths = [max(len(hdr[i]), max(len(str(r[i])) for r in table)) for i in range(len(hdr))]
        fmt = "  " + "  ".join("%-" + str(w) + "s" for w in widths)
        lines.append(fmt % tuple(hdr))
        lines.append("  " + "  ".join("-" * w for w in widths))
        for r in sorted(table):
            lines.append(fmt % tuple(r))
        lines.append("::endgroup::")
    text = "\n".join(lines) + "\n"
    print(text)                                  # the job log
    cli.writef(os.path.join(out, "reports", "scanner-tables.txt"), text)


def _needs_human(rows, sections, dry, pr_url, status):
    """The §0 'Needs a human' item list — owner-decision items awaiting acceptance, draft PRs
    awaiting merge, and failures that made the run INCOMPLETE. Shared by the report's §0 and the
    standing 'needs a human' issue (REQ-AUD-17 AC2), so the two never diverge."""
    needs = []
    for r in rows:
        if r.get("owner_issue") and r.get("owner_issue") not in ("dry", "skipped") and not r.get("adjudicator_error"):
            needs.append("owner-decision needed: %s — %s" % (r["id"], r.get("owner_issue")))
        if r.get("issue_failed"):
            needs.append("owner-decision issue FAILED to open: %s" % r["id"])
        if r.get("adjudicator_error"):
            needs.append("unassessed — adjudicator unavailable: %s" % r["id"])
    if not dry:
        for r in (sections[1] + sections[3]):
            if r.get("fix_pr_url"):
                needs.append("draft PR awaiting merge: %s — %s" % (r["id"], r["fix_pr_url"]))
        if pr_url:
            needs.append("suppression draft PR awaiting merge: %s" % pr_url)
    if "INCOMPLETE" in status:
        needs.append("run INCOMPLETE — %s" % status.split("INCOMPLETE:", 1)[-1].strip()[:240])
    return list(dict.fromkeys(needs))


def _standing_issue(needs, dry, would):
    """The single standing 'needs a human' issue (REQ-AUD-17 AC2): created once and commented
    every run whose §0 is non-empty (listing §0, so an unanswered item re-emails daily); closed
    by the first run that finds §0 empty. Uses the JOB token (issues:write), the same shim/dry/
    real-gh contract as _emit_owner_issue."""
    title = policy.STANDING_ISSUE_TITLE
    if needs:
        body = ("The daily CVE auditor needs a human on %d item(s) this run:\n- %s\n\nThis issue "
                "re-comments every run while any item is open, and closes automatically on the "
                "first run with nothing waiting." % (len(needs), "\n- ".join(needs)))
        return _emit_owner_issue(title, body, dry, would)   # find-or-create + comment
    # §0 empty -> close the standing issue if it is open.
    if dry:
        would.append("gh issue close --title %s (if open)" % shlex.quote(title)); return True, "dry"
    log = os.environ.get("AUDITOR_GIT_SHIM_LOG")
    if log:
        open(log, "a").write("gh issue close --title %s\n" % shlex.quote(title)); return True, "shim-closed"
    if not _real_gh_allowed():
        print("would close standing issue (real gh disabled): " + title); return True, "skipped"
    ienv = dict(os.environ)
    ienv["GH_TOKEN"] = os.environ.get("AUDITOR_ISSUES_TOKEN") or os.environ.get("GH_TOKEN", "")
    try:
        r = subprocess.run(["gh", "issue", "list", "--search", title, "--state", "open", "--json", "number"],
                           capture_output=True, text=True, env=ienv)
        nums = [str(x.get("number")) for x in json.loads(r.stdout or "[]")] if r.returncode == 0 else []
        for n in nums:
            subprocess.run(["gh", "issue", "close", n, "--comment",
                            "Nothing needs a human this run; closing the standing issue."],
                           capture_output=True, text=True, env=ienv)
        return True, ("closed:%s" % ",".join(nums) if nums else "none-open")
    except Exception as e:
        return False, "standing-issue close failed: %s" % _mask(str(e))


def _render(m, rows, sections, would, status, dry, adjudicator, consistency, fs_hash, conclusion, pr_url=None, pr_err=None, quorum_info=None, state=None):
    st = m.get("scanner_status") or {}
    test = (m.get("provenance") or {}).get("source") == "test-image"
    digest = (m.get("candidate_digests") or {}).get("production", "unknown")
    what = ("TEST IMAGE %s (dispatch override)" % (m.get("test_image") or digest)) if test \
        else ("candidate production %s commit %s" % (digest, m.get("commit")))
    ran_lines = []; notrun_lines = []; down_ac2 = []
    reports = m.get("scanner_reports") or {}
    for s in IMAGE_SCANNERS + ("osv-scanner-gomod",):
        info = st.get(s) or {}
        pc = info.get("package_count"); fn = info.get("findings")
        ran = bool(info.get("ran")) and (info.get("package_count") or 0) > 0
        if reports.get(s) and ran:
            # a scanner that publishes no database date says so — never a bare dash
            db = info.get("db_date") or "no db date published"
            ran_lines.append("%s %s db=%s packages=%s os_packages=%s findings=%s"
                             % (s, info.get("version") or "-", db, pc, info.get("os_package_count"), fn))
        else:
            reason = info.get("reason", "no report")
            notrun_lines.append("%s — %s" % (s, reason))
            if reason != "ok":                    # a scanner that genuinely did not inventory
                down_ac2.append("%s (%s)" % (s, reason))
    # A scanner that did not run is the report's FIRST line and the report is never labelled a
    # clean bill (REQ-AUD-7 AC2, R1 refactor round-5 #6): an empty result while a scanner is
    # down is NOT "all clear". Precede the title so a reader sees it before the conclusion.
    L = []
    if down_ac2:
        L += ["> SCANNER DID NOT RUN — assessment is NOT clean: " + "; ".join(down_ac2), ""]
    L += ["# Daily CVE auditor report", "", "## Conclusion", "", conclusion, "",
          "## Run header", "", "**Audited:** %s" % what]
    L.append("**Scanners:** " + "; ".join(ran_lines) if ran_lines else "**Scanners:** none inventoried")
    if notrun_lines:
        L.append("**Did not run:** " + "; ".join(notrun_lines))
    # Inventory quorum honesty: name which image scanners' OS inventories AGREED (the quorum
    # basis), which were excluded as outliers, and which did not inventory — with the OS counts,
    # so a total-package figure is never mistaken for the agreement (R1 report item 3).
    def _osc(s):
        return (st.get(s) or {}).get("os_package_count")
    # use the run's ACTUAL agreement decision (round-4 #8), falling back to a local recompute
    qi = quorum_info or {}
    agreed = qi.get("agreed") or []
    excl = list(dict.fromkeys((qi.get("disagreed") or []) + (qi.get("excluded") or [])))
    noinv = qi.get("not_ran") or [s for s in IMAGE_SCANNERS if s not in agreed and s not in excl]
    parts = ["agreed on OS packages: " + (", ".join("%s(%s)" % (s, _osc(s)) for s in agreed) or "none")]
    if excl:
        parts.append("did not agree / excluded: " + ", ".join("%s(%s)" % (s, _osc(s)) for s in excl))
    if noinv:
        parts.append("did not inventory: " + ", ".join("%s (%s)" % (s, (st.get(s) or {}).get("reason", "no report")) for s in noinv))
    L.append("**Inventory quorum:** " + "; ".join(parts))
    g = m.get("govulncheck")
    L.append("**Reachability:** " + ("govulncheck symbol @ %s (complete=%s)" % (g.get("commit"), g.get("complete")) if isinstance(g, dict) else "not run"))
    # REQ-AUD-14 AC6/AC7: maintenance flags, INDEPENDENT of any CVE — a carrier on a maintenance-
    # LTS or end-of-life line (endoflife.date, computed at manifest-build time), and a base pin more
    # than N days behind its repository's fix. Stated in the header before the sections.
    _flags = []
    for e in (m.get("eol") or []):
        stt = e.get("status"); nm = e.get("carrier") or "?"; cyc = e.get("cycle") or "?"
        if stt == "eol":
            _flags.append("carrier %s %s is END-OF-LIFE (per endoflife.date, EOL %s)" % (nm, cyc, e.get("eol_date") or "?"))
        elif stt == "maintenance":
            _flags.append("carrier %s %s is on a maintenance/LTS line (per endoflife.date, EOL %s)" % (nm, cyc, e.get("eol_date") or "?"))
    _base = m.get("base") or {}
    _thr = _base.get("behind_threshold_days", 30)
    if isinstance(_base.get("days_behind"), int) and _base["days_behind"] > _thr:
        _flags.append("base pin %s is %d days behind its repository's fix (threshold %d)"
                      % (_base.get("release") or "base", _base["days_behind"], _thr))
    if _flags:
        L.append("**Maintenance flags:** " + "; ".join(_flags))
    is_stub = "stub" in os.path.basename(adjudicator or "").lower()
    roles = sorted((state or {}).get("roles_used") or [])
    model_ran = "stub (no real model called)" if is_stub else ("+".join(roles) if roles else "none called")
    tok = int((state or {}).get("tokens") or 0)
    # If the adjudicator was UNAVAILABLE, the header NAMES the cause (masked) — not a silent
    # "none called" (R-live fix 1). The messages are already masked by adjudicate().
    adj_errs = sorted(((state or {}).get("adj_errors") or {}).values())
    adj_field = "real" if not is_stub else "stub"
    if adj_errs and not is_stub:
        adj_field = "real (UNAVAILABLE: %s)" % "; ".join(adj_errs)
    L.append("**dry_run:** %s   **adjudicator:** %s   **model:** %s   **token cost:** %d" %
             ("yes" if dry else "no", adj_field, model_ran, tok))
    probs = (consistency or {}).get("problems", [])
    L.append("**Consistency:** %s   **Finding-set hash:** `%s`" % ("clean" if not probs else "%d problems" % len(probs), fs_hash))
    L.append("")
    L.append("**%s**" % status)
    L.append("")
    ctx = {"n": 0, "p": max([(st.get(s) or {}).get("package_count") or 0 for s in IMAGE_SCANNERS] + [0]),
           "k": sum(1 for s in ("grype", "trivy", "osv-scanner", "snyk") if (st.get(s) or {}).get("ran")),
           "h": len(sections[5]), "m": len([r for r in sections[5]]), "consistency": "clean" if not probs else "%d problems" % len(probs),
           "down": ", ".join("%s (%s)" % (d["scanner"], d["reason"]) for d in C.scanners_down(m))}

    # --- report structure v2 (REQ-AUD-15) ---
    def _tag(r):
        """Status tag on a VEX-backed row, naming its actual state/reason (AC9)."""
        if test:
            return "proposed, not delivered (test image)"   # no statement on main applies
        if r.get("carried"):
            # already published on main (same disposition) — a dry run does not change that, so
            # this is checked BEFORE `dry` (Sonnet D). `carried` is set only when THIS run's
            # disposition matches the one on main (see _cstat), so it can never over-claim.
            return "in force (main)"
        if dry:
            return "proposed, not delivered (dry run)"
        # freshly written this run — NEVER "in force (main)" without evidence it is on main (AC9).
        if r.get("section") == 1 and r.get("fix_pr_url"):
            # a lifted row's delivery is its BUMP PR, not the suppression PR — name the PR its own
            # action text names, never a different one (Sonnet C).
            return "proposed (PR #%s)" % r["fix_pr_url"].rstrip("/").split("/")[-1]
        if pr_url:
            return "proposed (PR #%s)" % pr_url.rstrip("/").split("/")[-1]
        if pr_err:
            return "proposed, not delivered (delivery failed)"
        return "proposed, not delivered (no suppression PR)"

    def _tagged(r):
        tag = _tag(r)
        line = _row_line(r)
        if tag != "in force (main)":
            # AC9: the fosterstack.com VEX link is printed ONLY for in-force (published) statements.
            # A proposed / not-yet-delivered statement shows its id (the #stmt fragment) without the
            # published link, so a reader is never pointed at a link that does not resolve yet.
            line = re.sub(r"vex: https?://[^\s]*?(#stmt-[^\s]+)", r"vex: \1", line)
        return line + " — status: " + tag

    def _emit(title, rows_, empty, tagged=False, sub=None, downnote=False):
        L.append("## " + title); L.append("")
        if sub is not None:
            for subtitle, subrows in sub:
                L.append("**%s**" % subtitle)
                if subrows:
                    for r in subrows:
                        L.append(_tagged(r) if tagged else _row_line(r))
                else:
                    L.append("None.")
                L.append("")
            return
        if rows_:
            for r in rows_:
                L.append(_tagged(r) if tagged else _row_line(r))
        else:
            sentence = empty
            if downnote and ctx.get("down"):
                sentence += " Not a complete assessment: %s did not run." % ctx["down"]
            L.append(sentence)
        L.append("")

    # PRs and issues this run — above the sections (AC1).
    L.append("## PRs and issues this run"); L.append("")
    prlist = []
    if pr_url:
        prlist.append("Suppression draft PR (App): %s" % pr_url)
    elif pr_err:
        prlist.append("Suppression PR delivery FAILED (run INCOMPLETE): %s" % pr_err)
    for r in (sections[1] + sections[3]):
        if r.get("fix_pr_url"):
            prlist.append("Bump draft PR (App): %s — %s" % (r["id"], r["fix_pr_url"]))
    _seen_iss = set()
    for r in rows:
        oi = r.get("owner_issue")
        # the dry sentinel is already represented by the "would open (dry run)" entries below —
        # listing it here too double-counts it (AC1). "skipped" (a real run with gh disabled) has
        # NO would-open line, so keep it visible here rather than dropping the issue (Sonnet B).
        # A real issue ref is shared across the rows of one issue -> dedup by ref (one line); the
        # "skipped" sentinel is shared across DISTINCT would-be issues -> dedup by (id, ref) so two
        # different CVEs are not collapsed into one line (Codex R3 P3).
        _isskey = (r["id"], oi) if oi == "skipped" else oi
        if oi and oi != "dry" and _isskey not in _seen_iss:
            _seen_iss.add(_isskey); prlist.append("owner-decision issue: %s (%s)" % (r["id"], oi))
    if dry:
        for w in would:
            prlist.append("would open (dry run): `%s`" % w)
    for x in (prlist or ["No PRs or issues this run."]):
        L.append("- " + x)
    L.append("")

    # §0 Needs a human (AC2): owner items awaiting acceptance, draft PRs awaiting merge, and
    # failures that made the run INCOMPLETE — duplicated from the sections below.
    needs = _needs_human(rows, sections, dry, pr_url, status)
    L.append("## 0. Needs a human"); L.append("")
    for x in (needs or ["Nothing needs a human this run."]):
        L.append("- " + x if needs else x)
    L.append("")

    # §1 Lifted
    _emit("1. Lifted", sections[1], C.EMPTY[1].format(**ctx), tagged=True)
    # §2 Accepted risk: 2A no fix exists; 2Ba upstream-held; 2Bb policy-held (REQ-AUD-14 fills 2B).
    s2 = sections[2]
    twoBa = [r for r in s2 if r.get("not_pullable") == "upstream-held"]
    twoBb = [r for r in s2 if r.get("not_pullable") == "policy-held"]
    twoA = [r for r in s2 if r not in twoBa and r not in twoBb]
    _emit("2. Accepted risk: real vulnerabilities with no fix available to us", s2,
          C.EMPTY[2].format(**ctx), tagged=True,
          sub=([("2A — no fix exists", twoA),
                ("2Ba — fix exists, not pullable: upstream-held", twoBa),
                ("2Bb — fix exists, not pullable: policy-held", twoBb)] if s2 else None))
    # §3 Real vulnerabilities that are fixable: 3A OS/base; 3B libraries (SCA).
    s3 = sections[3]
    # 3A vs 3B keys on ECOSYSTEM, not the base_rebuild delivery flag: an expired OS acceptance
    # reopened into §3 carries no base_rebuild flag yet is still an OS finding (Codex/Sonnet AC5).
    threeA = [r for r in s3 if r.get("base_rebuild") or r.get("is_os")]
    threeB = [r for r in s3 if r not in threeA]
    if s3:
        _emit("3. Real vulnerabilities that are fixable", s3, "",
              sub=[("3A — OS / system packages (fix via base-image bump)", threeA),
                   ("3B — libraries (SCA)", threeB)])
    else:
        _emit("3. Real vulnerabilities that are fixable", s3, C.EMPTY[3].format(**ctx), downnote=True)
    # §4 Could not be assessed
    _emit("4. Could not be assessed", sections[4], C.EMPTY[4].format(**ctx))
    # §5 Closed as not affected: 5A not reachable; 5B false positive.
    s5 = sections[5]
    fiveA = [r for r in s5 if "unreachable" in (r.get("disposition") or "")]
    fiveB = [r for r in s5 if r not in fiveA]
    _emit("5. Closed as not affected", s5, C.EMPTY[5].format(**ctx), tagged=True,
          sub=([("5A — not reachable", fiveA), ("5B — false positive", fiveB)] if s5 else None))
    return "\n".join(L) + "\n"


def main():
    dry = cli.opt("--dry-run", "true") != "false"
    manifest = cli.opt("--manifest"); out = cli.opt("--out", os.path.join(os.environ.get("RUNNER_TEMP", "/tmp"), "auditor-out"))
    today = cli.opt("--today", "2026-09-22"); kev = cli.opt("--kev")
    if not manifest:
        print("daily CVE auditor: no manifest supplied"); return 2
    try:
        complete = run(manifest, dry, out, today, kevpath=kev)
    except ValueError as e:
        print("daily CVE auditor: manifest invalid — %s" % e)
        return 3
    finally:
        cli.close_adjudicators()       # shut the run's single adjudicator client process down
    print("daily CVE auditor: dry_run=%s, out=%s" % (dry, out))
    return 0 if complete else 1        # AUDIT INCOMPLETE fails the job (R13 item 3)


if __name__ == "__main__":
    sys.exit(main())
