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


def _deliver_suppression_pr(out, supp, nstmt, today, commit, dry, would, is_test=False):
    """Deliver the consolidated suppressions (R16) as ONE non-stacked draft PR against main,
    carrying .vex/fosterstack-cache.openvex.json + .snyk + osv-scanner.toml in a single commit
    by the App bot identity. Returns (pr_url, error). A dry run only proposes. A push/PR
    failure returns (None, stderr) so the caller marks the run AUDIT INCOMPLETE — never a
    false 'opened'. No vendor/model name appears in the branch, commit, or PR text.

    A TEST-IMAGE run opens NO PR (a VEX for an image we do not ship is not a proposal),
    EXCEPT the one-off proof (AUDITOR_PROOF_PR=1), whose PR title is prefixed
    'proof — do not merge'."""
    # nstmt==0 with NO removals means nothing to deliver. But an expiry reopen (AC5c) produces
    # zero NEW statements yet must still REMOVE a carried statement/ignore — deliver that.
    has_removals = False
    try:
        has_removals = bool(json.load(open(os.path.join(out, ".auditor", "reopened-expired.json"))).get("reopened"))
    except Exception:
        has_removals = False
    if nstmt == 0 and not has_removals:
        return None, None
    proof = os.environ.get("AUDITOR_PROOF_PR") in ("1", "true", "True")
    if is_test and not proof:
        would.append("test-image run: no PR (not a shipped image)")
        print("test-image run: no suppression PR (not a shipped image)")
        return None, None
    short = (commit or "unknown")[:12]
    branch = "auditor/%s-%s" % (today, short)          # <date>-<short-sha>, off main, non-stacked
    title = "auditor: update suppressions (%d statements)" % nstmt
    if is_test and proof:
        branch = "auditor/proof-%s-%s" % (today, short)
        title = "proof — do not merge: " + title
    body = "Automated suppression update from the daily CVE auditor. Draft for audit-lane review."
    if dry:
        would.append("gh pr create --draft --base main --head %s --title %s" % (branch, shlex.quote(title)))
        print("dry-run would open draft PR on %s" % branch)
        return None, None
    log = os.environ.get("AUDITOR_GIT_SHIM_LOG")
    if log:
        seq = ["git checkout -B %s origin/main" % branch,
               "git add .vex/fosterstack-cache.openvex.json .snyk osv-scanner.toml .auditor/accepted-items.json",
               "git commit -m %s" % shlex.quote(title),
               "git push -u origin %s" % branch,
               "gh pr create --draft --base main --head %s --title %s" % (branch, shlex.quote(title))]
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
    except Exception as e:
        return None, "stage files: %s" % e
    _git("add", ".vex/fosterstack-cache.openvex.json", ".snyk", "osv-scanner.toml", ".auditor/accepted-items.json")
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
        return ex, None
    r = subprocess.run(["gh", "pr", "create", "--draft", "--base", "main", "--head", branch,
                        "--title", title, "--body", body], cwd=ws, capture_output=True, text=True)
    if r.returncode != 0:
        if "already exists" in (r.stderr or "").lower():   # race: reuse the existing one
            ex = _existing_pr()
            if ex:
                return ex, None
        return None, ("gh pr create: " + (r.stderr or "").strip())
    return r.stdout.strip(), None


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
    authorized delivery step this run), 'skipped-test' (test image, not the proof), 'error'
    (a git/gh/tidy failure — the caller marks the run INCOMPLETE). No vendor/model name
    appears in the branch, commit, or PR text."""
    fb = row.get("fix_bump") or {}
    module = fb.get("module"); to = fb.get("to"); frm = fb.get("from"); cve = fb.get("cve") or row["id"]
    short = (commit or "unknown")[:12]
    branch = "auditor/bump-%s-%s" % (cve, short)
    title = "auditor: bump %s %s -> %s (%s)" % (module, frm, to, cve)
    server = os.environ.get("GITHUB_SERVER_URL"); repo = os.environ.get("GITHUB_REPOSITORY"); rid = os.environ.get("GITHUB_RUN_ID")
    runlink = ("%s/%s/actions/runs/%s" % (server, repo, rid)) if (server and repo and rid) else "the daily CVE auditor run report"
    body = ("Automated dependency bump from the daily CVE auditor. Draft for review; auto-merge is a later switch.\n\n"
            "- Vulnerability: %s\n- Module: %s\n- From: %s\n- To: %s\n\nRun report: %s" % (cve, module, frm, to, runlink))
    proof = os.environ.get("AUDITOR_PROOF_PR") in ("1", "true", "True")
    if is_test and not proof:
        would.append("test-image run: no bump PR (not a shipped image)")
        return None, None, "skipped-test"
    if is_test and proof:
        branch = "auditor/proof-bump-%s-%s" % (cve, short)
        title = "proof — do not merge: " + title
    if dry:
        would.append("gh pr create --draft --base main --head %s --title %s" % (branch, shlex.quote(title)))
        print("dry-run would open draft bump PR on %s" % branch)
        return None, None, "would"
    log = os.environ.get("AUDITOR_GIT_SHIM_LOG")
    if log:
        seq = ["git checkout -B %s origin/main" % branch,
               "go get %s@%s" % (module, to),
               "go mod tidy",
               "git add go.mod go.sum",
               "git commit -m %s" % shlex.quote(title),
               "git push -u origin %s" % branch,
               "gh pr create --draft --base main --head %s --title %s" % (branch, shlex.quote(title))]
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
    ex = _existing()
    if ex:
        return ex, None, "delivered"
    r = subprocess.run(["gh", "pr", "create", "--draft", "--base", "main", "--head", branch,
                        "--title", title, "--body", body], cwd=ws, capture_output=True, text=True)
    if r.returncode != 0:
        if "already exists" in (r.stderr or "").lower():
            ex = _existing()
            if ex:
                return ex, None, "delivered"
        return None, ("gh pr create: " + (r.stderr or "").strip()), "error"
    return r.stdout.strip(), None, "delivered"


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
        return ans.get("category") or "unknown"
    return "adjudicator_error" if (errored and not refused) else "refused"


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
    if r["section"] == 5 and r.get("vex_id"):
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
           "scope_purls": sorted(set(subs or []))}   # this row's scope, for per-scope table mapping
    out = env["out"]; ts = env["ts"]; exp = env["exp"]; dry = env["dry"]
    _purls = sorted(set(subs or []))
    this_scope = ((policy.VEX_PRODUCT,), tuple(_purls))
    this_scope_id = policy.scope_id(c, policy.VEX_PRODUCT, subs)
    _carried = (c, this_scope) in env.get("carried_scopes", set())
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
                           ignore_files=["vex", "evidence"])
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
               "severity": gf["severity"], "reachability": row["reachability"], "candidate_digest": env["digest"]}
        cat = adjudicate(env["adjudicator"], ctx, env["state"]); m_inc = 1
        if cat == "false_positive":
            fev = C.fp_verified(ids, env["logpath"], findings)
            if fev:
                vex.write(out, c, "not_affected", ts, justification="vulnerable_code_not_present", evidence=fev, vex_name=vn, subcomponents=subs)
                row.update(section=5, disposition="not_affected (false positive)", action="closed",
                           reason="model FP, evidence-verified",
                           vex_id=policy.scope_id(c, policy.VEX_PRODUCT, subs),
                           ignore_files=["vex", "evidence"])
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
        # AC7: a fix that is now pullable LIFTS a suppression this scope was carrying — the old
        # affected/temporary VEX, ignore and inventory for this exact scope are removed this run
        # (delivery drops them) and the row is §1 lifted; otherwise a fresh fixable finding is §3.
        lifted = _carried or bool(env.get("carried_expiry", {}).get((c, this_scope)))
        lift_note = "; prior suppression lifted (VEX/ignore/inventory removed)" if lifted else ""
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
    for sc in sorted({f["scanner"] for f in findings}):
        cli.writej(os.path.join(out, "ignores", sc, vn + ".json"),
                   {"id": c, "vex": this_scope_id, "expiry": this_exp, "scoped_purls": _purls,
                    "reason": "accepted risk; re-checked daily"})
    action = "POA&M: affected VEX + ignores, expiry %s" % this_exp
    row.update(section=2, disposition="carried (POA&M)", action=action, vex_id=this_scope_id,
               scope_purls=_purls, reason="%s; %s" % (gf["nofix_reason"], reason),
               threshold=("at_or_above" if at else "below"), expiry=this_exp)
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
    gvc, module, gvc_usable = C.manifest_gvc(m)
    logpath = m.get("known_defect_log"); ts = today + "T00:00:00Z"
    idx = log_index(logpath)
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
    carried_expiry = {}; carried_scopes = set()
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
        except Exception:
            carried_expiry = {}
    env = {"gvc": gvc, "module": module, "gvc_usable": gvc_usable, "idx": idx, "logpath": logpath,
           "adjudicator": adjudicator, "state": state, "kev_ids": kev_ids, "kev_ok": kev_ok, "exp": exp, "out": out,
           "ts": ts, "dry": dry, "digest": (m.get("candidate_digests") or {}).get("production"),
           "carried_expiry": carried_expiry, "carried_scopes": carried_scopes, "today": today}
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
            rows.append({"id": c, "package": ",".join(covpkgs) or "?",
                         "installed": (covered[0].get("extra") or {}).get("installed_version") or _ver_from_purl(covered[0].get("purl")) or "?",
                         "fixed": None, "severity": _max_sev(covered), "section": 5,
                         "aliases": sorted(set(sorted(grp["aliases"]) + [c])),
                         "scope_purls": subs or [],
                         "disposition": "not_affected (false positive)", "action": "closed",
                         "reachability": "n/a (OS package)", "reason": "known-defect-log FP for %s" % (",".join(covpkgs)),
                         "vex_id": _fp_sid, "ignore_files": [igf, ".snyk", "osv-scanner.toml", "vex"]})
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
    accepted = [{"cve": r["id"], "severity": r["severity"], "package": r["package"],
                 "threshold": r.get("threshold", "at_or_above" if r.get("owner_issue") else "below"),
                 "owner_issue": r.get("owner_issue"), "expiry": r.get("expiry", exp),
                 "vex_id": r.get("vex_id"),                       # the governing statement id
                 "product": policy.VEX_PRODUCT,                   # the FULL canonical scope, so
                 "scope_purls": r.get("scope_purls") or []}       # inventory keys on scope, not a hash
                for r in sections[2]]
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
        title = "owner-decision: adjudicator unavailable — %d findings unassessed" % n
        body = ("The adjudicator was unavailable this run: %d finding(s) could not be assessed "
                "(primary/rephrase/fallback all failed). Cause: %s. The run is INCOMPLETE; no "
                "disposition was inferred for these findings. Findings: %s"
                % (n, adj_cause, ids[:1500]))
        ok, ref = _emit_owner_issue(title, body, dry, would)
        for r in adj_unavailable:
            r["owner_issue"] = ref if ok else None
            r["action"] = ("unassessed: adjudicator unavailable; one owner-decision issue opened"
                           if ok else "unassessed: adjudicator unavailable; OWNER ISSUE FAILED")
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
        for r, _it in group:
            r["owner_issue"] = ref if ok else None
            r["issue_failed"] = (not ok)
            if kind == "risk_acceptance":
                base = r["action"].replace("; owner-decision issue pending", "")
                r["action"] = base + ("; owner-decision issue opened/updated (issues:write)" if ok else "; OWNER ISSUE FAILED")
            else:
                r["action"] = ("escalated to owner-decision issue" if ok else "OWNER ESCALATION FAILED")
    # a failed owner escalation (POA&M at-threshold, or §4 unassessed-after-fallback) is a
    # real gap: the required human decision was not delivered (R1 outer round-1 #4/#5).
    issue_failures = sum(1 for r in rows if r.get("issue_failed"))
    # write the acceptance inventory BEFORE delivery so the suppression PR can carry it — the
    # release gate reads .auditor/accepted-items.json from the checkout (R1 outer round-1 #7).
    cli.writej(os.path.join(out, ".auditor", "accepted-items.json"),
               {"accepted_items": accepted, "run_date": today, "candidate_commit": m.get("commit")})
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
    for n in range(1, 8):
        L.append("## %d. %s" % (n, C.TITLES[n]))
        if n == 6:
            if pr_url:
                L.append("Suppression draft PR opened by the delivery App: %s" % pr_url)
            elif pr_err:
                L.append("Suppression PR delivery FAILED (run is INCOMPLETE): %s" % pr_err)
            if would:
                for w in would:
                    L.append("dry run: would run `%s`" % w)
            # Go-module bumps DELIVERED as draft PRs by the App this run (decision 2).
            delivered = [r for r in (sections[3] + sections[1]) if r.get("fix_pr_url")]
            for r in delivered:
                L.append("Bump draft PR opened by the delivery App: %s — %s" % (r["id"], r["fix_pr_url"]))
            # Base rebuilds defer to Dependabot's daily docker PR (REQ-AUD-2 AC3) — awaiting, not ours.
            awaiting = [r for r in (sections[3] + sections[1]) if r.get("base_rebuild")]
            for r in awaiting:
                L.append("Awaiting base rebuild (deferred to Dependabot's docker PR): %s — %s" % (r["id"], r.get("fixed")))
            # Fix PRs we could not deliver this run (no authorized step, or a delivery failure).
            pend = [r for r in (sections[3] + sections[1]) if r.get("pending_delivery")]
            for r in pend:
                L.append("Fix PR NOT delivered: %s — %s" % (r["id"], r.get("action")))
            if not pr_url and not pr_err and not would and not delivered and not awaiting and not pend:
                L.append(C.EMPTY[6].format(**ctx) if not dry
                         else "Nothing to open: no §3 fix PR or owner issue was warranted this run.")
            L.append(""); continue
        if sections[n]:
            for r in sections[n]:
                L.append(_row_line(r))
        else:
            sentence = C.EMPTY[n].format(**ctx)
            if n in (3, 7) and ctx.get("down"):
                sentence += " Not a complete assessment: %s did not run." % ctx["down"]
            L.append(sentence)
        L.append("")
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
