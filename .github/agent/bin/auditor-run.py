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
    """primary -> rephrase -> fallback for ONE finding, bounded PER FINDING by the
    five-iteration stop and globally by the token budget. Returns the category (or
    'refused' if the fallback chain is exhausted)."""
    iters = 0
    for attempt, role in (("primary", "primary"), ("rephrase", "primary"), ("fallback", "fallback")):
        if state["tokens"] >= policy.TOKEN_BUDGET or iters >= policy.MAX_ITERATIONS:
            state["stops"] = state.get("stops", 0) + 1
            return "refused"
        iters += 1; state["calls"] = state.get("calls", 0) + 1
        try:
            ans = cli.ask_model(adjudicator, ctx["finding_id"], attempt=attempt, model=role, context=ctx)
        except cli.Refused as e:
            state["tokens"] += int(getattr(e, "token_usage", 0) or 0)   # a refusal is still billed
            continue
        except Exception:
            # never echo the exception text: an adjudicator's stderr can name the model id.
            print("adjudicator error for %s (%s): call failed" % (ctx["finding_id"], attempt))
            continue
        state["tokens"] += int(ans.get("token_usage") or 0)
        return ans.get("category") or "unknown"
    return "refused"


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
    by_scope = {}
    for f in nonlineage:
        eco = "go" if _eco(f.get("purl")) in ("golang", "go") else "os"
        by_scope.setdefault((eco, f.get("package") or "?", _ver_from_purl(f.get("purl")) or "?"), []).append(f)
    if not by_scope and lineage:
        # a pure-bundle CVE (only advisory lineage) still needs one disposition
        f0 = lineage[0]
        by_scope[("os", f0.get("package") or "?", _ver_from_purl(f0.get("purl")) or "?")] = lineage
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
        row, mi = _dispose(c, sub, aliases, env, would, name=nm)
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
           "disposition": None, "action": None, "reason": None}
    out = env["out"]; ts = env["ts"]; exp = env["exp"]; dry = env["dry"]
    # 2) reachability for Go modules — deterministic govulncheck.
    if gf["is_go"]:
        verdict, ev = C.gvc_verdict(env["gvc"], ids, env["module"], env["gvc_usable"])
        row["reachability"] = "govulncheck: %s" % verdict
        if verdict == "unreachable":
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
    _purls = sorted(set(subs or []))
    this_scope = ((policy.VEX_PRODUCT,), tuple(_purls))
    this_scope_id = policy.scope_id(c, policy.VEX_PRODUCT, subs)
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
        elif cat == "refused":
            # unassessed after the fallback chain -> owner-decision issue (REQ-AUD-9 AC3),
            # not a silent §4 (R1 outer round-1 #4). A stub run cannot escalate; say so.
            is_stub = "stub" in os.path.basename(env["adjudicator"]).lower()
            cause = "stub: no canned answer" if is_stub else "model refused after fallback"
            if is_stub:
                row.update(section=4, disposition="under investigation", action="none (stub: no owner escalation)",
                           reason="adjudication exhausted", cause=cause)
                return row, m_inc
            it = policy.owner_issue_title(c, gf["package"], "unassessed-after-fallback")
            body = ("Finding %s (%s@%s, severity %s) could not be assessed after the "
                    "primary/rephrase/fallback chain. Owner decision needed. Evidence: adjudication "
                    "exhausted; reachability %s. Accept, reject, or provide guidance."
                    % (c, gf["package"], gf["installed"], gf["severity"], row["reachability"]))
            ok, ref = _emit_owner_issue(it, body, dry, would)
            row.update(section=4, disposition="under investigation",
                       action=("escalated to owner-decision issue" if ok else "OWNER ESCALATION FAILED"),
                       reason="unassessed after fallback", cause=cause,
                       owner_issue=(ref if ok else None), issue_failed=(not ok))
            return row, m_inc
    # 4) deterministic fix routing.
    if gf["fixed"]:
        # AC7: a fix that is now pullable LIFTS a suppression this scope was carrying — the old
        # affected/temporary VEX, ignore and inventory for this exact scope are removed this run
        # (delivery drops them) and the row is §1 lifted; otherwise a fresh fixable finding is §3.
        lifted = bool(env.get("carried_expiry", {}).get((c, this_scope)))
        if gf["is_go"]:
            title = "auditor/bump-%s: %s %s -> %s" % (c, gf["package"], gf["installed"], gf["fixed"])
            _open_pr("auditor/bump-%s" % c, title, "auto-merge-lane", dry, would, "auditor: bump %s" % c)
            act = ("dry run: would open PR '%s'" % title) if dry else "proposed bump PR (auto-merge lane; delivery pending)"
            row.update(section=3, disposition="real, fixable (we build it)", action=act,
                       fixed=gf["fixed"], reason="pullable fix in a module we build")
        else:
            title = "auditor/base-rebuild-%s: base image -> %s (%s)" % (c, gf["fixed"], gf["package"])
            _open_pr("auditor/base-rebuild-%s" % c, title, "base-bump", dry, would, "auditor: base rebuild %s" % c)
            act = ("dry run: would open PR '%s'" % title) if dry else "proposed base-rebuild PR (delivery pending)"
            row.update(section=3, disposition="real, fixable (base rebuild)", action=act,
                       fixed="base-image %s" % gf["fixed"], reachability="n/a (OS package)",
                       reason="awaiting base rebuild %s" % gf["fixed"])
        if lifted:
            row.update(section=1, disposition="lifted (fix now pullable)",
                       action=row["action"] + "; prior suppression lifted (VEX/ignore/inventory removed)",
                       reopened_scope=[c, list(this_scope[0]), list(this_scope[1])])
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
    owner_issue = None; issue_failed = False
    if at:
        it = policy.owner_issue_title(c, gf["package"], reason)
        body = ("Accept risk for %s (%s@%s, severity %s, threshold %s)? No pullable upstream fix "
                "(%s); an affected VEX + %d-day ignores are carried in this run's suppression "
                "package (the artifact/PR). Reply on this issue: `ACCEPT %s until YYYY-MM-DD` or "
                "`REJECT %s`."
                % (c, gf["package"], gf["installed"], gf["severity"], reason, gf["nofix_reason"],
                   policy.IGNORE_EXPIRY_DAYS, c, c))
        ok, ref = _emit_owner_issue(it, body, dry, would)   # find-or-update, never a duplicate; failure propagates
        if ok:
            action += "; owner-decision issue opened/updated (issues:write)"; owner_issue = ref
        else:
            action += "; OWNER ISSUE FAILED"; issue_failed = True
    row.update(section=2, disposition="carried (POA&M)", action=action, vex_id=this_scope_id,
               scope_purls=_purls, reason="%s; %s" % (gf["nofix_reason"], reason), owner_issue=owner_issue,
               threshold=("at_or_above" if at else "below"), expiry=this_exp, issue_failed=issue_failed)
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
    state = {"tokens": 0, "iters": 0}
    # Carried acceptances from the checkout: when a time box has passed, the finding must
    # REOPEN (§3) this run and its ignore be removed, never silently renewed (REQ-AUD-2 AC5c;
    # R1 outer round-8 #4). Read the delivered inventory the previous run left in the workspace.
    carried_expiry = {}
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
           "carried_expiry": carried_expiry, "today": today}
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
        fp_keys = set()   # (package, version)
        for f in grp["findings"]:
            if f.get("_lineage_only"):     # an advisory's defect-log FP is about ITS OWN
                continue                   # vulnerability, not a different bundled CVE (round-8 #1)
            r = idx.get((f["scanner"], f["finding_id"], f["purl"]))
            if r and r.get("disposition") == "false_positive":
                fp_keys.add(((r.get("package") or f.get("package")), _ver_from_purl(f["purl"])))
        def _cov(f):
            return not f.get("_lineage_only") and (f.get("package"), _ver_from_purl(f["purl"])) in fp_keys
        covered = [f for f in grp["findings"] if _cov(f)]
        if covered:
            subs = sorted({f["purl"] for f in covered if f["purl"]})
            covpkgs = sorted({"%s@%s" % (p, v or "?") for (p, v) in fp_keys})
            ev = {"check": "known-defect-log", "source_file": logpath,
                  "detail": "trusted false_positive for %s" % covpkgs}
            vex.write(out, c, "not_affected", ts, justification="vulnerable_code_not_present", evidence=ev, subcomponents=subs or None)
            igf = os.path.join("ignores", "grype", c + ".json")
            _fp_sid = policy.scope_id(c, policy.VEX_PRODUCT, subs or None)
            cli.writej(os.path.join(out, igf), {"vex": _fp_sid, "id": c, "evidence": ev, "scoped_purls": subs})
            rows.append({"id": c, "package": ",".join(covpkgs) or "?",
                         "installed": (covered[0].get("extra") or {}).get("installed_version") or _ver_from_purl(covered[0].get("purl")) or "?",
                         "fixed": None, "severity": _max_sev(covered), "section": 5,
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
    findings_without_action = sum(1 for r in rows if r["section"] in (2, 3) and (not r["action"] or r["action"] == "none"))
    if dry and sections[3] and not would:
        findings_without_action += len(sections[3])
    # A non-dry run PROPOSES fix PRs (bump / base-rebuild) but does not deliver them — the
    # driver holds contents:read and only the App-token SUPPRESSION PR is delivered. Those
    # proposals are real PENDING work; the report must say so rather than claim completion
    # with nothing pending (R1 outer round-8 #3). Each such row is flagged for §6.
    fix_pending = [r for r in sections[3] if not dry and "delivery pending" in (r.get("action") or "")]
    for r in fix_pending:
        r["pending_delivery"] = True
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
    def _ran(s):
        # A scanner counts as run ONLY if the manifest records it ran AND it inventoried
        # packages. Path-presence is NOT enough (R1 round-1): a manifest without a
        # scanner_status block, or one reporting zero packages, fails the quorum closed.
        info = st.get(s) or {}
        # counts for QUORUM only if it ran, inventoried packages, and was not excluded as an
        # inventory outlier (whose findings are still parsed and dispositioned).
        return bool(info.get("ran")) and (info.get("package_count") or 0) > 0 and info.get("quorum_ok", True)
    def _scanned(s):
        info = st.get(s) or {}
        return bool(info.get("ran")) and (info.get("package_count") or 0) > 0
    ran_image = [s for s in ("grype", "trivy", "osv-scanner", "snyk") if _ran(s)]
    excluded = [s for s in ("grype", "trivy", "osv-scanner", "snyk") if _scanned(s) and not (st.get(s) or {}).get("quorum_ok", True)]
    not_ran = [s for s in ("grype", "trivy", "osv-scanner", "snyk") if not _scanned(s)]
    oscounts = [(st.get(s) or {}).get("os_package_count") or 0 for s in ran_image]
    agree = bool(oscounts) and max(oscounts) > 0 and (min(oscounts) >= 0.5 * max(oscounts))
    quorum = len(ran_image) >= 3 and agree
    # consolidate every per-CVE VEX into the canonical suppression files, run the consistency
    # check over THAT layout, then DELIVER the suppressions as one draft PR via the App token
    # (R16). A push/PR failure is AUDIT INCOMPLETE with the git/gh stderr — never "opened".
    supp, nstmt = _consolidate(out, ts)
    consistency = _consistency(out, supp, manifest_path)
    cons_failed = any(p.get("type", "").startswith("consistency-check-") for p in (consistency or {}).get("problems", []))
    is_test = (m.get("provenance") or {}).get("source") == "test-image"
    pr_url, pr_err = _deliver_suppression_pr(out, supp, nstmt, today, m.get("commit"), dry, would, is_test=is_test)
    # NOTE: proposed-but-undelivered fix PRs are surfaced in §6 (honest reporting) but do NOT
    # by themselves mark the run INCOMPLETE — the ratified design (REQ-AUD-12 AC2, REQ-AUD-7
    # AC3; tests req12-ac2, il13) is that the driver PROPOSES fix PRs and an authorized step
    # delivers them; proposing is the complete driver behavior. (R1 outer round-8 #3 asked for
    # completion to reflect delivery, which would change that ratified AC — surfaced to owner.)
    complete = ((findings_without_action == 0) and quorum and (pr_err is None)
                and (issue_failures == 0) and not cons_failed)
    if complete:
        status = "AUDIT COMPLETE"
    else:
        bits = []
        if findings_without_action:
            bits.append("%d findings without an action" % findings_without_action)
        if not quorum:
            bits.append("scanner quorum %d/4 (need 3 agreeing); did not run: %s; excluded as outliers: %s"
                        % (len(ran_image), ", ".join(not_ran) or "none", ", ".join(excluded) or "none"))
        if pr_err:
            bits.append("suppression PR delivery failed: %s" % pr_err)
        if issue_failures:
            bits.append("%d owner-decision issue(s) failed to open" % issue_failures)
        if cons_failed:
            bits.append("consistency check did not complete")
        status = "AUDIT INCOMPLETE: " + "; ".join(bits)
    fs_hash = _persist(out, rows, today)
    conclusion = _conclusion(adjudicator, sections, m, state)
    report = _render(m, rows, sections, would, status, dry, adjudicator, consistency, fs_hash, conclusion, pr_url, pr_err)
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
    sec_by_cve = {}
    for r in rows:
        sec_by_cve.setdefault(r["id"], set()).add(r["section"])

    def _disp(fid, aliases):
        cve = C.canon(fid, aliases)
        secs = sec_by_cve.get(cve)
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
                          _disp(f.get("finding_id"), f.get("aliases") or [])])
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


def _render(m, rows, sections, would, status, dry, adjudicator, consistency, fs_hash, conclusion, pr_url=None, pr_err=None):
    st = m.get("scanner_status") or {}
    test = (m.get("provenance") or {}).get("source") == "test-image"
    digest = (m.get("candidate_digests") or {}).get("production", "unknown")
    what = ("TEST IMAGE %s (dispatch override)" % (m.get("test_image") or digest)) if test \
        else ("candidate production %s commit %s" % (digest, m.get("commit")))
    L = ["# Daily CVE auditor report", "", "## Conclusion", "", conclusion, "",
         "## Run header", "", "**Audited:** %s" % what]
    ran_lines = []; notrun_lines = []
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
            notrun_lines.append("%s — %s" % (s, info.get("reason", "no report")))
    L.append("**Scanners:** " + "; ".join(ran_lines) if ran_lines else "**Scanners:** none inventoried")
    if notrun_lines:
        L.append("**Did not run:** " + "; ".join(notrun_lines))
    # Inventory quorum honesty: name which image scanners' OS inventories AGREED (the quorum
    # basis), which were excluded as outliers, and which did not inventory — with the OS counts,
    # so a total-package figure is never mistaken for the agreement (R1 report item 3).
    def _osc(s):
        return (st.get(s) or {}).get("os_package_count")
    agreed = [s for s in IMAGE_SCANNERS
              if (st.get(s) or {}).get("ran") and (_osc(s) or 0) > 0 and (st.get(s) or {}).get("quorum_ok", True)]
    excl = [s for s in IMAGE_SCANNERS
            if (st.get(s) or {}).get("ran") and (_osc(s) or 0) > 0 and not (st.get(s) or {}).get("quorum_ok", True)]
    noinv = [s for s in IMAGE_SCANNERS if s not in agreed and s not in excl]
    parts = ["agreed on OS packages: " + (", ".join("%s(%s)" % (s, _osc(s)) for s in agreed) or "none")]
    if excl:
        parts.append("excluded as outliers: " + ", ".join("%s(%s)" % (s, _osc(s)) for s in excl))
    if noinv:
        parts.append("did not inventory: " + ", ".join("%s (%s)" % (s, (st.get(s) or {}).get("reason", "no report")) for s in noinv))
    L.append("**Inventory quorum:** " + "; ".join(parts))
    g = m.get("govulncheck")
    L.append("**Reachability:** " + ("govulncheck symbol @ %s (complete=%s)" % (g.get("commit"), g.get("complete")) if isinstance(g, dict) else "not run"))
    L.append("**dry_run:** %s   **adjudicator:** %s" % ("yes" if dry else "no",
             "stub" if "stub" in os.path.basename(adjudicator or "").lower() else "real"))
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
            pend = [r for r in sections[3] if r.get("pending_delivery")]
            for r in pend:
                L.append("Fix PR PROPOSED but NOT delivered (needs an authorized delivery step): %s — %s"
                         % (r["id"], r.get("action")))
            if not pr_url and not pr_err and not would and not pend:
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
    print("daily CVE auditor: dry_run=%s, out=%s" % (dry, out))
    return 0 if complete else 1        # AUDIT INCOMPLETE fails the job (R13 item 3)


if __name__ == "__main__":
    sys.exit(main())
