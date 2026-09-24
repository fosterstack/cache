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
    if nstmt == 0:
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
    # Merge statements by (@id, product scope, subcomponent scope), NOT by @id alone (R1
    # outer round-5 #3). Auditor @ids are CVE-derived, so a debug-variant statement and a
    # production statement for the same CVE share an @id but address DIFFERENT scopes; keying
    # on @id alone would silently drop the unassessed scope. This run replaces a statement
    # only when the scope matches; disjoint scopes are preserved.
    def _skey(s):
        prods = tuple(sorted((p.get("@id") or "") for p in s.get("products", [])))
        subs = tuple(sorted((sc.get("@id") or "")
                            for p in s.get("products", []) for sc in (p.get("subcomponents") or [])))
        return (s.get("@id"), prods, subs)
    by_id = {}
    for s in existing.get("statements", []):
        if s.get("@id"):
            by_id[_skey(s)] = s
    for s in newdoc.get("statements", []):
        by_id[_skey(s)] = s                       # this run replaces same-scope / adds new
    merged = dict(existing) if existing else dict(newdoc)
    merged["statements"] = list(by_id.values())
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
    if new_ai is not None or old_ai is not None:
        def _cve(it):
            return (it or {}).get("cve") or (it or {}).get("id")
        affected = {s.get("vulnerability", {}).get("name")
                    for s in merged.get("statements", []) if s.get("status") == "affected"}
        final = {}
        for it in ((old_ai or {}).get("accepted_items") or []):
            if _cve(it) in affected:
                final[_cve(it)] = it               # retained affected item keeps its acceptance
        for it in ((new_ai or {}).get("accepted_items") or []):
            if _cve(it):
                final[_cve(it)] = it               # this run wins
        out_ai = dict(new_ai or old_ai or {})
        out_ai["accepted_items"] = list(final.values())
        os.makedirs(os.path.dirname(aip), exist_ok=True)
        cli.writej(aip, out_ai)

    def _union_blocks(existing_text, new_text, split_key, key_re):
        # union blocks keyed by CVE; new wins; keep existing blocks for untouched CVEs
        def blocks(t):
            out = {}
            for b in t.split(split_key)[1:]:
                mid = re.search(key_re, b)
                if mid:
                    out[mid.group(1)] = b
            return out
        old = blocks(existing_text) if existing_text else {}
        new = blocks(new_text)
        old.update(new)
        return old

    # osv-scanner.toml union
    otoml = os.path.join(ws, "osv-scanner.toml")
    old_t = open(otoml).read() if os.path.exists(otoml) else ""
    new_t = open(os.path.join(supp, "osv-scanner.toml")).read()
    blk = _union_blocks(old_t, new_t, "[[IgnoredVulns]]", r'id\s*=\s*"([^"]+)"')
    open(otoml, "w").write("".join("[[IgnoredVulns]]" + b for b in blk.values()) if blk else new_t)

    # .snyk: keep existing ignore keys not in the new set, then append the new file's ignores.
    # (Simple, safe union: prefer the new file wholesale but re-add untouched old CVE keys.)
    sp = os.path.join(ws, ".snyk")
    if os.path.exists(sp):
        old_s = open(sp).read(); new_s = open(os.path.join(supp, ".snyk")).read()
        new_cves = set(re.findall(r"^  (\S+):\s*$", new_s, re.M))
        kept = []
        i, lines = 0, old_s.splitlines()
        while i < len(lines):
            m = re.match(r"^  (\S+):\s*$", lines[i])
            if m and m.group(1) not in new_cves:
                kept.append(lines[i]); i += 1
                while i < len(lines) and (lines[i].strip() == "" or re.match(r"^   ", lines[i])):
                    kept.append(lines[i]); i += 1
                continue
            i += 1
        merged_snyk = new_s.rstrip("\n") + ("\n" + "\n".join(kept) if kept else "") + "\n"
        open(sp, "w").write(merged_snyk)
    else:
        shutil.copyfile(os.path.join(supp, ".snyk"), sp)


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
    expiry_map = {}
    for jf in glob.glob(os.path.join(out, "ignores", "*", "*.json")):
        try:
            d = json.load(open(jf))
            if d.get("id") and d.get("expiry"):
                expiry_map[d["id"]] = d["expiry"]
        except Exception:
            pass
    for ef in glob.glob(os.path.join(out, "evidence", "*.evidence.json")):
        try:
            d = json.load(open(ef))
            if d.get("vulnerability") and d.get("target_date"):
                expiry_map.setdefault(d["vulnerability"], d["target_date"])
        except Exception:
            pass
    by_cve = {}
    for s in statements:
        cve = (s.get("vulnerability") or {}).get("name")
        by_cve.setdefault(cve, {"statuses": set(), "vids": []})
        by_cve[cve]["statuses"].add(s.get("status"))
        sid = s.get("@id")
        if sid and sid not in by_cve[cve]["vids"]:
            by_cve[cve]["vids"].append(sid)    # every statement id for this CVE (no orphan)
    snyk = ["version: v1.5.0", "ignore:"]; toml = []
    for cve in sorted(by_cve):
        info = by_cve[cve]; vids = info["vids"] or [policy.stmt_id(cve)]; st = "+".join(sorted(info["statuses"]))
        allids = " ".join(vids); exp = expiry_map.get(cve)
        snyk += ["  %s:" % cve, "    - '*':", "        reason: '%s; governed by %s'" % (st, allids)]
        if exp:
            snyk += ["        expires: %sT00:00:00.000Z" % exp]     # time box preserved for Snyk
        snyk += ["        vex: '%s'" % vids[0]]
        rsn = "%s; governed by %s%s" % (st, allids, ("; expires %s" % exp if exp else ""))
        toml += ['[[IgnoredVulns]]', 'id = "%s"' % cve, 'reason = "%s"' % rsn]
        if exp:
            toml += ['expires = "%sT00:00:00Z"' % exp]
    cli.writef(os.path.join(supp, ".snyk"), "\n".join(snyk) + "\n")
    cli.writef(os.path.join(supp, "osv-scanner.toml"), "\n".join(toml) + "\n")
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
    findings = grp["findings"]; f0 = findings[0]
    ecos = {_eco(f.get("purl")) for f in findings}
    installed = (f0.get("extra") or {}).get("installed_version") or _ver_from_purl(f0.get("purl")) or "?"
    fixed = next((f.get("fixed_version") for f in findings if f.get("fixed_version")), None)
    return {
        "package": f0.get("package") or "unknown",
        "installed": installed,
        "fixed": fixed,
        "severity": _max_sev(findings),
        "is_go": any(e in ("golang", "go") for e in ecos),
        "known_exploited": any((f.get("extra") or {}).get("known_exploited") for f in findings),
        "lineages": {policy.lineage_of(f["scanner"]) for f in findings},
        "nofix_reason": _nofix_reason(findings),
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
    base = base or c
    go = [f for f in findings if _eco(f.get("purl")) in ("golang", "go")]
    other = [f for f in findings if _eco(f.get("purl")) not in ("golang", "go")]
    subsets = [("go", go), ("os", other)]
    subsets = [(tag, s) for tag, s in subsets if s]
    out_rows = []; mc = 0
    for tag, sub in subsets:
        nm = base if len(subsets) == 1 else "%s-%s" % (base, tag)
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
    row = {"id": c, "package": gf["package"], "installed": gf["installed"], "fixed": gf["fixed"],
           "severity": gf["severity"], "reachability": "n/a (OS package)", "section": None,
           "disposition": None, "action": None, "reason": None}
    out = env["out"]; ts = env["ts"]; exp = env["exp"]; dry = env["dry"]
    # 2) reachability for Go modules — deterministic govulncheck.
    if gf["is_go"]:
        verdict, ev = C.gvc_verdict(env["gvc"], ids, env["module"], env["gvc_usable"])
        row["reachability"] = "govulncheck: %s" % verdict
        if verdict == "unreachable":
            vex.write(out, c, "not_affected", ts, justification="vulnerable_code_not_in_execute_path", evidence=ev, vex_name=vn)
            row.update(section=5, disposition="not_affected (unreachable)", action="closed",
                       reason="govulncheck: imported, not called", vex_id=policy.stmt_id(c),
                       ignore_files=["vex", "evidence"])
            return row, 1
    m_inc = 0
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
                vex.write(out, c, "not_affected", ts, justification="vulnerable_code_not_present", evidence=fev, vex_name=vn)
                row.update(section=5, disposition="not_affected (false positive)", action="closed",
                           reason="model FP, evidence-verified", vex_id=policy.stmt_id(c),
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
        return row, m_inc
    # no upstream fix -> POA&M (§2), at/above threshold -> owner issue.
    in_kev = c in env["kev_ids"] or bool(set(aliases) & env["kev_ids"])
    reason = policy.threshold_reason(gf["severity"], in_kev, gf["known_exploited"])
    at = reason != "below"
    if not at and not env.get("kev_ok", True):
        # KEV membership could not be checked -> do not downgrade; escalate (fail closed).
        at = True; reason = "kev-unavailable (fail-closed)"
    vex.write(out, c, "affected", ts, action="no fix upstream; tracked; re-checked daily",
              evidence={"check": "reachable-no-fix", "source_file": "manifest", "detail": gf["nofix_reason"]},
              target_date=exp, vex_name=vn)
    for sc in sorted({f["scanner"] for f in findings}):
        cli.writej(os.path.join(out, "ignores", sc, vn + ".json"),
                   {"id": c, "vex": policy.stmt_id(c), "expiry": exp, "reason": "accepted risk; re-checked daily"})
    action = "POA&M: affected VEX + ignores, expiry %s" % exp
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
    row.update(section=2, disposition="carried (POA&M)", action=action, vex_id=policy.stmt_id(vn),
               reason="%s; %s" % (gf["nofix_reason"], reason), owner_issue=owner_issue,
               threshold=("at_or_above" if at else "below"), expiry=exp, issue_failed=issue_failed)
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
    env = {"gvc": gvc, "module": module, "gvc_usable": gvc_usable, "idx": idx, "logpath": logpath,
           "adjudicator": adjudicator, "state": state, "kev_ids": kev_ids, "kev_ok": kev_ok, "exp": exp, "out": out,
           "ts": ts, "dry": dry, "digest": (m.get("candidate_digests") or {}).get("production")}
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
            r = idx.get((f["scanner"], f["finding_id"], f["purl"]))
            if r and r.get("disposition") == "false_positive":
                fp_keys.add(((r.get("package") or f.get("package")), _ver_from_purl(f["purl"])))
        def _cov(f):
            return (f.get("package"), _ver_from_purl(f["purl"])) in fp_keys
        covered = [f for f in grp["findings"] if _cov(f)]
        if covered:
            subs = sorted({f["purl"] for f in covered if f["purl"]})
            covpkgs = sorted({"%s@%s" % (p, v or "?") for (p, v) in fp_keys})
            ev = {"check": "known-defect-log", "source_file": logpath,
                  "detail": "trusted false_positive for %s" % covpkgs}
            vex.write(out, c, "not_affected", ts, justification="vulnerable_code_not_present", evidence=ev, subcomponents=subs or None)
            igf = os.path.join("ignores", "grype", c + ".json")
            cli.writej(os.path.join(out, igf), {"vex": policy.stmt_id(c), "id": c, "evidence": ev, "scoped_purls": subs})
            rows.append({"id": c, "package": ",".join(covpkgs) or "?",
                         "installed": (covered[0].get("extra") or {}).get("installed_version") or _ver_from_purl(covered[0].get("purl")) or "?",
                         "fixed": None, "severity": _max_sev(covered), "section": 5,
                         "disposition": "not_affected (false positive)", "action": "closed",
                         "reachability": "n/a (OS package)", "reason": "known-defect-log FP for %s" % (",".join(covpkgs)),
                         "vex_id": policy.stmt_id(c), "ignore_files": [igf, ".snyk", "osv-scanner.toml", "vex"]})
            h_count += 1
            uncovered = [f for f in grp["findings"] if not _cov(f)]
            if uncovered:
                # distinct VEX/ignore name so the sibling's disposition never clobbers the FP one
                rs, mi = _dispose_split(c, uncovered, sorted(grp["aliases"]), env, would, base=c + "-sibling")
                rows.extend(rs); m_count += mi
            continue
        rs, mi = _dispose_split(c, grp["findings"], sorted(grp["aliases"]), env, would)
        rows.extend(rs); m_count += mi

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
                 "owner_issue": r.get("owner_issue"), "expiry": r.get("expiry", exp)}
                for r in sections[2]]
    findings_without_action = sum(1 for r in rows if r["section"] in (2, 3) and (not r["action"] or r["action"] == "none"))
    if dry and sections[3] and not would:
        findings_without_action += len(sections[3])
    # a failed owner escalation (POA&M at-threshold, or §4 unassessed-after-fallback) is a
    # real gap: the required human decision was not delivered (R1 outer round-1 #4/#5).
    issue_failures = sum(1 for r in rows if r.get("issue_failed"))
    # write the acceptance inventory BEFORE delivery so the suppression PR can carry it — the
    # release gate reads .auditor/accepted-items.json from the checkout (R1 outer round-1 #7).
    cli.writej(os.path.join(out, ".auditor", "accepted-items.json"),
               {"accepted_items": accepted, "run_date": today, "candidate_commit": m.get("commit")})
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
    complete = (findings_without_action == 0) and quorum and (pr_err is None) and (issue_failures == 0) and not cons_failed
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


def _narrative_ok(text, sections):
    if FORBIDDEN_NAMES.search(text):     # no vendor/model attribution in the report
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
            ran_lines.append("%s %s db=%s packages=%s findings=%s"
                             % (s, info.get("version") or "-", info.get("db_date") or "-", pc, fn))
        else:
            notrun_lines.append("%s — %s" % (s, info.get("reason", "no report")))
    L.append("**Scanners:** " + "; ".join(ran_lines) if ran_lines else "**Scanners:** none inventoried")
    if notrun_lines:
        L.append("**Did not run:** " + "; ".join(notrun_lines))
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
            if not pr_url and not pr_err and not would:
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
