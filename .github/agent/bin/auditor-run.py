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
import os, sys, json, re, shlex, subprocess, importlib.util, urllib.parse
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from auditorlib import cli, policy
from auditorlib import vex
from auditorlib import reviewed
from auditorlib import signed_commit
from auditorlib import knowledge as K
from auditorlib import nochange

_spec = importlib.util.spec_from_file_location("auditor_classify", os.path.join(HERE, "auditor-classify.py"))
C = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(C)
from auditorlib import parsers as PARS


def _panel_verdict(pn):
    """The panel's verdict, re-read and re-validated from the path the manifest names; None when there is none or it does not validate."""
    try:
        return PARS.validate_panel_verdict(PARS.load_panel_verdict(pn["verdict"])) if (pn or {}).get("verdict") else None
    except (PARS.ParseError, OSError, ValueError):
        return None


def _scanners(m):
    """The image scanners a manifest records: the scanner panel's four."""
    return PARS.PANEL_SCANNERS

# Identifiers/tokens that must never reach the uploaded report. We surface the REAL adjudicator
# error (class, HTTP status, message) so a failure is diagnosable, but with these values redacted.
_SECRET_ENVS = ("ANTHROPIC_FEDERATION_RULE_ID", "ANTHROPIC_ORGANIZATION_ID",
                "ANTHROPIC_SERVICE_ACCOUNT_ID", "ANTHROPIC_WORKSPACE_ID",
                "AUDITOR_MODEL_PRIMARY", "AUDITOR_MODEL_FALLBACK",
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


def _resolve_carried(groups, carried_stmts):
    """rc-5b fix 5: the panel's vex_covered entries arrive as findings flagged `carried` with a generic package URL (parsers.parse_panel). Resolve each to the scope of the carried
    statement that names the same CVE (or one of its aliases: the panel's coverage predicate indexes both) and the same package and version, so the statement is re-judged this
    run like any visible finding; a flagged entry no carried statement matches is dropped (nothing carries it). Returns the CVE ids of the carried statements that NO scanner
    (visible or hidden-by-our-VEX) reports this run, by any of the statement's ids."""
    by_id, primaries = {}, []
    for s in carried_stmts:
        v = s.get("vulnerability") or {}
        nm = v.get("name")
        if not nm:
            continue
        ids = {nm} | {a for a in (v.get("aliases") or []) if isinstance(a, str)}
        primaries.append((nm, ids))
        for i in ids:
            by_id.setdefault(i, []).append(sorted(_scope_key(s)[1]))
    for cid in list(groups):
        grp = groups[cid]
        keep = []
        for f in grp["findings"]:
            if not (f.get("extra") or {}).get("carried"):
                keep.append(f)
                continue
            for cve in {cid} | set(grp["aliases"]) | set(f.get("aliases") or []):
                for purls in by_id.get(cve, []):
                    for p in purls:
                        pn, pv = PARS._panel_module()._purl_name_version(p)
                        if pn == f.get("package") and pv == (f.get("extra") or {}).get("version"):
                            keep.append(PARS._finding(f["scanner"], f["finding_id"], p, f.get("aliases") or (), f.get("package"), None, None,
                                                      dict(f["extra"], carried=True)))
        grp["findings"] = keep
        if not keep:
            del groups[cid]
    seen_ids = set()
    for grp in groups.values():
        seen_ids |= set(grp["aliases"]) | {grp["id"]}
    return sorted({nm for nm, ids in primaries if not (ids & seen_ids)})


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


def _issue_pending_note(ref):
    """Honest action wording when an owner issue was NOT actually delivered but did not fail:
    a dry-run preview ("dry") or a real run with gh delivery disabled ("skipped"). Never say
    "opened" for these — the row must not contradict the PR list's "would open" (Codex R3 blk)."""
    return "would open (dry run)" if ref == "dry" else "delivery disabled (gh off)"


ReviewedInputInvalid = reviewed.ReviewedInputInvalid       # the exception and the reader are shared (auditorlib/reviewed.py): the release gate and the consistency check use them too
_read_reviewed_json = reviewed.read


def _workspace():
    """The one checkout the run reads and delivers against: GITHUB_WORKSPACE, else the current directory (what delivery always did)."""
    return os.environ.get("GITHUB_WORKSPACE") or os.getcwd()


def _read_reopened(path):
    """The scopes this run reopened (reopened-expired.json, written by the run itself): a list of [cve, products, purls]. Absent = none; present and unreadable or mis-shaped means the run
    is broken, so it stops (exit 3) rather than deliver without the removals (rc-5b fix 13, item 6)."""
    doc = _read_reviewed_json(path)
    rows = [] if doc is None else doc["reopened"]                 # a present ledger without its key was refused by the reader
    if not isinstance(rows, list) or not all(isinstance(x, list) and len(x) == 3 and isinstance(x[0], str) and all(isinstance(y, list) and all(isinstance(z, str) for z in y) for y in x[1:]) for x in rows):
        raise ReviewedInputInvalid("%s: 'reopened' is not a list of [cve, [products], [purls]] with strings" % path)
    return rows


class DefectLogInvalid(Exception):
    """The known-defect log exists but is not a JSON object — a log problem, never reported as
    a manifest problem, and never a traceback."""


def load_defect_log(logpath):
    """The known-defect log as a dict ({} when there is none); DefectLogInvalid when unreadable."""
    if not logpath:
        return {}
    try:
        if not reviewed.present(logpath):          # the reader owns existence (lstat): a dangling link or a log in an unreachable folder is present, and a stop
            return {}
    except reviewed.ReviewedInputInvalid as e:
        raise DefectLogInvalid(str(e))
    try:
        with open(logpath) as fh:
            d = json.load(fh)
    except (OSError, ValueError) as e:
        raise DefectLogInvalid("%s: %s" % (logpath, e))
    if not isinstance(d, dict):
        raise DefectLogInvalid("%s: top level is %s, want an object" % (logpath, type(d).__name__))
    try:
        return reviewed.check(d, logpath, "known-defect-log.json")        # a present log must carry "defects" (a list of objects): {} is not an empty history
    except reviewed.ReviewedInputInvalid as e:
        raise DefectLogInvalid(str(e))


def log_index(log):
    idx = {}
    for row in log.get("defects", []):
        for k in row.get("keys", []):
            idx[(k["scanner"], k["finding_id"], k["purl"])] = row
    return idx


def _plan(would, kind, target, cves=(), cmd="", note="", key=None):
    """Record one PR or issue this run would open (dry run) or skipped (test image) — one entry
    per PR/issue, never per finding, carrying what makes it unique: its kind, its target and the
    CVE IDs it covers (REQ-AUD-18 follow-up, owner's test Sep 27). The report renders from these."""
    would.append({"kind": kind, "target": target, "cves": sorted({c for c in cves if c}),
                  "cmd": cmd, "note": note, "key": key or (kind, target)})


def _supp_cves(supp):
    """The CVE IDs the consolidated suppression package carries (its VEX statements)."""
    doc = _read_reviewed_json(os.path.join(supp, "fosterstack-cache.openvex.json")) or {}
    return sorted({(s.get("vulnerability") or {}).get("name") for s in doc.get("statements", [])} - {None})


def _supp_removed(supp):
    """The scopes the suppression PR REMOVES this run — expired, or lifted because a fix became
    pullable (the record does not say which): (cve ids, scope count)."""
    sc = _read_reopened(os.path.join(os.path.dirname(supp), ".auditor", "reopened-expired.json"))
    return sorted({x[0] for x in sc}), len(sc)


def _supp_target(supp, nstmt):
    """What the suppression PR carries, named: its statements and the scopes it removes."""
    rm_ids, rm_n = _supp_removed(supp)
    t = "suppressions (%d statements" % nstmt + (", %d scope(s) removed" % rm_n if rm_n else "") + ")"
    return t, sorted(set(_supp_cves(supp)) | set(rm_ids))


def _emit_owner_issue(title, body, dry, would, cves=(), target=None):
    """Open OR update the single owner-decision issue (REQ-AUD-9). Returns (ok, ref): ok is
    False on a create/update FAILURE so the caller marks the run INCOMPLETE — never a false
    'opened' (R1 outer round-1 #5); ref is the issue number/url when known (R1 outer round-1
    #7). The body carries the evidence, the artifact, and the yes/no question (AC1). Uses the
    JOB token (issues:write), never the App delivery token (Contents + PRs only)."""
    cmd = "gh issue create --title %s --label %s --assignee %s" % (shlex.quote(title), policy.OWNER_LABEL, policy.OWNER_LOGIN)
    if dry:
        _plan(would, "owner-decision issue", target or title, cves, cmd)
        print("dry-run would create: " + cmd); return True, "dry"
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
        subprocess.run(policy.label_create_cmd(policy.OWNER_LABEL), capture_output=True, text=True, env=ienv)  # a missing label would lose the issue; "already exists" is fine
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


def _arm_automerge(target, ws):
    """Arm native GitHub auto-merge (squash) on a PR. A pre-ramp DRAFT PR reused after the owner
    turns auto-merge on cannot auto-merge while still a draft, so mark it ready first; then enable
    auto-merge. The merge still waits on all required checks + the main rulesets — the App has no
    bypass. Prints a warning (never silent) if arming fails; a failure is non-fatal (the PR is
    delivered and a human can still merge)."""
    subprocess.run(["gh", "pr", "ready", target], cwd=ws, capture_output=True, text=True)
    r = subprocess.run(["gh", "pr", "merge", "--auto", "--squash", target], cwd=ws, capture_output=True, text=True)
    if r.returncode != 0:
        print("warning: could not arm auto-merge on %s: %s" % (target, _mask((r.stderr or "").strip())))
    return r.returncode == 0


def _automerge_allowed(paths):
    """Auto-merge is enabled ONLY when the owner turned it on (AC3) AND the change touches NO
    prompt file — the model's standing instructions are human-merged always (AC4). The records
    the auditor delivers (VEX, ignores, inventory, proposals, knowledge) never include the prompt
    file, so this both permits records and hard-guards the instructions."""
    return _automerge_on() and not any((p or "").startswith(_PROMPT_PATH) for p in (paths or []))


_DAILY_BRANCH = re.compile(r"^auditor/\d{4}-\d{2}-\d{2}-[0-9a-f]{4,40}$")


def _close_superseded(branch, url, ws):
    """Each day's suppression PR is a fresh branch off main (auditor/<date>-<sha>); the day before's, if still open, is behind main and will never
    merge under strict checks, so it is closed with a pointer to today's (advisor 0187). Only older daily branches: never today's, auditor/panel or
    a bump branch. Best effort: a failure here is reported and never fails the delivery."""
    try:
        # only PRs the App itself opened from a branch of THIS repository and that are not drafts (a draft waits for the owner; a fork's or a human's PR is never ours to close)
        q = subprocess.run(["gh", "api", "repos/{owner}/{repo}/pulls?state=open&per_page=100", "--paginate", "--jq",
                            '.[] | select(.head.repo.fork == false and .base.ref == "main" and .draft == false and .user.type == "Bot") | "\\(.number) \\(.head.ref)"'],
                           cwd=ws, capture_output=True, text=True)
        if q.returncode != 0:
            print("note: could not list open PRs to close superseded suppression PRs")
            return
        for line in (q.stdout or "").splitlines():
            num, _, ref = line.strip().partition(" ")
            if num.isdigit() and ref != branch and _DAILY_BRANCH.match(ref) and ref[len("auditor/"):len("auditor/") + 10] < branch[len("auditor/"):len("auditor/") + 10]:
                r = subprocess.run(["gh", "pr", "close", num, "--comment", "Superseded by %s (a fresh branch off the current main; this one is behind main and cannot merge)." % url],
                                   cwd=ws, capture_output=True, text=True)
                if r.returncode != 0:
                    print("note: could not close superseded PR #%s" % num)
    except Exception as e:   # never fails the delivery
        print("note: superseded-PR cleanup skipped: %s" % type(e).__name__)


def _signed_delivery(ws, branch, base_sha, title, paths):
    """ONE commit on `branch`, rebuilt on base_sha, made through the GitHub API with the App's token so GitHub signs it (the live branch moves only
    after the signed commit exists). Returns (oid, None) or (None, the failure text)."""
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not repo:
        return None, "signed commit: GITHUB_REPOSITORY is not set; cannot make the signed delivery commit"
    notes = []
    try:
        oid = signed_commit.commit_via_api(repo, branch, base_sha, title, signed_commit.read_changes(ws, paths), notes=notes)
    except signed_commit.CommitError as e:
        return None, str(e)
    for n in notes:
        print("warning: " + n)
    return oid, None


def _disarm_before_replace(ws, pr):
    """An armed PR must never carry new content that auto-merge was not armed for (the panel's rule): disarm BEFORE the branch is replaced. None, or the failure text."""
    if not pr:
        return None
    v = subprocess.run(["gh", "pr", "view", pr, "--json", "autoMergeRequest", "--jq", ".autoMergeRequest != null"], cwd=ws, capture_output=True, text=True)
    if v.returncode != 0:
        return "gh pr view: " + (v.stderr or "").strip()
    if (v.stdout or "").strip() == "true":
        d = subprocess.run(["gh", "pr", "merge", "--disable-auto", pr], cwd=ws, capture_output=True, text=True)
        if d.returncode != 0:
            return "could not disable auto-merge on %s before replacing its branch: %s" % (pr, (d.stderr or "").strip())
    return None


def _hold_as_draft(ws, pr):
    """A held major's PR is a draft with auto-merge off, whatever an earlier run (or a person) left it as. None, or the
    failure text."""
    if not pr:
        return None
    err = _disarm_before_replace(ws, pr)
    if err:
        return err
    v = subprocess.run(["gh", "pr", "view", pr, "--json", "isDraft", "--jq", ".isDraft"], cwd=ws, capture_output=True,
        text=True)
    if v.returncode != 0:
        return "gh pr view (isDraft): " + (v.stderr or "").strip()
    if (v.stdout or "").strip() != "true":
        r = subprocess.run(["gh", "pr", "ready", "--undo", pr], cwd=ws, capture_output=True, text=True)
        if r.returncode != 0:
            return "could not make %s a draft: %s" % (pr, (r.stderr or "").strip())
    return None


def _head_is(ws, pr, oid):
    """Arm only the head THIS run wrote: another run's later replacement must never inherit this run's arming. None, or the failure text."""
    h = subprocess.run(["gh", "pr", "view", pr, "--json", "headRefOid", "--jq", ".headRefOid"], cwd=ws, capture_output=True, text=True)
    now = (h.stdout or "").strip() if h.returncode == 0 else ""
    if now != oid:
        return "the PR's head is %s, not the verified %s (head changed since it was verified, or it could not be read): not arming auto-merge" % (now[:12] or "unknown", oid[:12])
    return None


def _find_pr(ws, branch):
    """(url, None) for the open same-repo PR from `branch` into main, ("", None) when the lookup SUCCEEDED and found none, ("", error) when it failed:
    a failed lookup is never "no PR" (the caller would replace the branch under a PR it could not see, armed)."""
    q = subprocess.run(["gh", "pr", "list", "--head", branch, "--state", "open", "--json", "url,isCrossRepository,baseRefName",
                        "--jq", '[.[] | select(.isCrossRepository == false and .baseRefName == "main")][0].url // ""'], cwd=ws, capture_output=True, text=True)
    if q.returncode != 0:
        return "", "gh pr list: " + ((q.stderr or q.stdout or "").strip() or "failed")
    return (q.stdout or "").strip(), None


# the two reviewed files the delivery merges into
BASE_VEX, BASE_ITEMS = ".vex/fosterstack-cache.openvex.json", ".auditor/accepted-items.json"


def _fetch_base(ws):
    """(sha, None) or (None, the failure text): ONE `git fetch origin main` (it changes no ref the workspace stands on)
    and the sha origin/main resolved to. The sha is what the base is read
    at, what the delivery branch is cut from and what the signed commit is built on, so the validated bytes are the
    bytes merged into (cache#708 rulings 1, 2). A failure is handed down to the
    delivery, which reports it and acquires nothing again: a second acquisition could find a base the first never
    validated, after an owner issue exists."""
    r = subprocess.run(["git", "fetch", "origin", "main"], cwd=ws, capture_output=True, text=True)
    if r.returncode != 0:
        return None, "git fetch: " + (r.stderr or "").strip()
    s = subprocess.run(["git", "rev-parse", "origin/main"], cwd=ws, capture_output=True, text=True)
    sha = (s.stdout or "").strip()
    if s.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}", sha):
        return None, "git rev-parse: " + ((s.stderr or "").strip() or sha)
    return sha, None


def _base_file(ws, sha, rel):
    """The reviewed file `rel` as the delivery base (commit `sha`) holds it, read as a git object so the workspace is
    not touched: the parsed JSON object the reader requires, None when the
    base does not hold it (the first run; a file git reports as existing on disk but not in the base is absent at the
    base too: the workspace copy is never the base), or
    ReviewedInputInvalid. git runs in the C locale because its messages are matched."""
    r = subprocess.run(["git", "show", sha + ":" + rel], cwd=ws, capture_output=True, env=dict(os.environ, LC_ALL="C"))
    if r.returncode != 0:
        err = r.stderr.decode("utf-8", "replace") if isinstance(r.stderr, bytes) else (r.stderr or "")
        if "does not exist in" in err or "exists on disk, but not in" in err:
            return None
        raise ReviewedInputInvalid("%s:%s cannot be read (%s)" % (sha[:12], rel, err.strip()[:200]))
    return reviewed.parse(r.stdout, "%s:%s" % (sha[:12], rel), as_name=rel)


def _base_docs(ws, sha):
    """Both reviewed files of the delivery base, parsed and validated: {path: document or None}."""
    return {BASE_VEX: _base_file(ws, sha, BASE_VEX), BASE_ITEMS: _base_file(ws, sha, BASE_ITEMS)}


def _preflight_delivery(out, supp):
    """What _merge_suppressions reads of the files THIS run wrote (the consolidated VEX, the reopened-expired ledger,
    the accepted-items inventory), validated BEFORE
    `git checkout -B` touches the workspace (cache#701 ruling F3/B3: exit 3 never follows a mutating call)."""
    # absent is the staging error _merge_suppressions reports; present must be the VEX object
    _read_reviewed_json(os.path.join(supp, "fosterstack-cache.openvex.json"))
    _read_reopened(os.path.join(out, ".auditor", "reopened-expired.json"))
    _read_reviewed_json(os.path.join(out, ".auditor", "accepted-items.json"))


def _deliver_suppression_pr(out, supp, nstmt, today, commit, dry, would, is_test=False, base_sha=None, base_err=None):
    """Deliver the consolidated suppressions (R16) as ONE non-stacked draft PR against main,
    carrying .vex/fosterstack-cache.openvex.json (the only exception there is, rule 4) in a single commit
    by the App bot identity. Returns (pr_url, error). A dry run only proposes. A push/PR
    failure returns (None, stderr) so the caller marks the run AUDIT INCOMPLETE — never a
    false 'opened'. No vendor/model name appears in the branch, commit, or PR text.

    A TEST-IMAGE run opens NO PR (a VEX for an image we do not ship is not a proposal, and a
    test image always forces dry_run — REQ-AUD-15 AC9)."""
    # nstmt==0 with NO removals means nothing to deliver. But an expiry reopen (AC5c) produces
    # zero NEW statements yet must still REMOVE a carried statement/ignore — deliver that.
    has_removals = bool(_read_reopened(os.path.join(out, ".auditor", "reopened-expired.json")))
    # A run that produced ONLY model proposals (no statements, no removals) still opens the draft
    # PR so the proposals reach audit-lane review (REQ-AUD-16 AC4; Codex round-1 P2).
    has_proposals = os.path.exists(os.path.join(out, ".auditor", "proposals", "adjudicator-proposals.json"))
    if nstmt == 0 and not has_removals and not has_proposals:
        return None, None
    if is_test:
        _plan(would, "suppression PR", *_supp_target(supp, nstmt), note="skipped: test image")
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
    staged = [".vex/fosterstack-cache.openvex.json", ".auditor/accepted-items.json"] + extra
    # AC3/AC4: draft unless the owner turned auto-merge on AND the change touches no prompt file.
    automerge = _automerge_allowed(staged)
    draft = "" if automerge else "--draft "
    if dry:
        _plan(would, "suppression PR", *_supp_target(supp, nstmt),
              cmd="gh pr create %s--base main --head %s --title %s" % (draft, branch, shlex.quote(title)),
              note="auto-merge" if automerge else "draft")
        print("dry-run would open %sPR on %s" % ("auto-merge " if automerge else "draft ", branch))
        return None, None
    log = os.environ.get("AUDITOR_GIT_SHIM_LOG")
    if log:
        seq = ["git checkout -B %s origin/main" % branch,
               "gh api graphql createCommitOnBranch %s -- %s" % (branch, " ".join(staged)),   # a signed commit made through the API: no git commit, no git push
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
        _plan(would, "suppression PR", *_supp_target(supp, nstmt), note="not delivered: delivery disabled (no authorized delivery step)")
        return None, None
    import shutil
    ws = _workspace()

    def _git(*a):
        return subprocess.run(["git", *a], cwd=ws, capture_output=True, text=True)
    # run() tried to acquire the base before the first owner issue and failed: that failure is the delivery's, and
    # nothing is acquired again
    if base_err:
        return None, base_err
    # run() hands the validated sha down; a direct caller (neither given) acquires it here
    if base_sha is None:
        base_sha, base_err = _fetch_base(ws)
        if base_err:
            return None, base_err
    # the belt: the base read again at the sha, with the run's own outputs, before anything touches the workspace
    base_docs = _base_docs(ws, base_sha)
    _preflight_delivery(out, supp)
    r = _git("checkout", "-B", branch, base_sha)          # off main => not stacked
    if r.returncode != 0:
        return None, ("git checkout: " + (r.stderr or "").strip())
    try:
        # MERGE into the existing reviewed suppressions, do NOT overwrite them (R1 outer
        # round-4 #3): a statement this run does not touch (e.g. a debug-variant suppression
        # absent from a production scan) must survive, and the document version continues.
        # _merge_suppressions merges the VEX AND the coupled .auditor/accepted-items.json (retained affected statements keep their
        # inventory entry, R1 outer round-5 #2) — no wholesale copy of the run's inventory.
        _merge_suppressions(ws, supp, base=base_docs)
        # copy the run's proposals + generated knowledge into the checkout so they ride the PR.
        for p in extra:
            s = os.path.join(out, p); d = os.path.join(ws, p)
            os.makedirs(os.path.dirname(d), exist_ok=True)
            shutil.copyfile(s, d)
    except ReviewedInputInvalid:
        raise                                       # a reviewed file of the delivery checkout that does not parse stops the run (exit 3), it is not a staging error to carry on from
    except Exception as e:
        return None, "stage files: %s" % e
    # the files THIS run changed against main (as `git add` + `git commit` once found them: a path that is absent and untracked is skipped)
    r = _git("status", "--porcelain", "-z", "--untracked-files=all", "--", *staged)
    if r.returncode != 0:
        return None, ("git status: " + (r.stderr or "").strip())
    changed = [e[3:] for e in (r.stdout or "").split("\0") if len(e) > 3]
    if not changed:
        return None, "signed commit: nothing to commit (the run changed none of the suppression files)"
    # idempotence (R1 outer round-4 #5): if a PR for this head already exists, reconcile with
    # it (no duplicate, no false failure) instead of a second `gh pr create`.
    def _arm_head(u):
        err = _head_is(ws, u, oid)
        if err:
            return None, err
        _arm_automerge(u, ws)
        return u, None
    ex, err = _find_pr(ws, branch)
    if err:
        return None, err                         # a discovery failure aborts BEFORE any ref write
    err = _disarm_before_replace(ws, ex)         # the existing PR is found and DISARMED first, then its branch is replaced
    if err:
        return None, err
    # the commit is made THROUGH THE API so GitHub signs it (main requires signed commits; a `git commit` is unsigned and left the PR BLOCKED)
    # built on the validated sha, never on a ref that may have moved since
    oid, err = _signed_delivery(ws, branch, base_sha, title, changed)
    if err:
        return None, err
    if ex:
        _close_superseded(branch, ex, ws)
        return _arm_head(ex) if automerge else (ex, None)
    create = ["gh", "pr", "create", "--base", "main", "--head", branch, "--title", title, "--body", body]
    if not automerge:
        create.insert(3, "--draft")   # after "create": `gh pr create --draft ...`
    r = subprocess.run(create, cwd=ws, capture_output=True, text=True)
    if r.returncode != 0:
        if "already exists" in (r.stderr or "").lower():   # race: reuse the existing one
            ex, _ = _find_pr(ws, branch)
            if ex:
                _close_superseded(branch, ex, ws)
                return _arm_head(ex) if automerge else (ex, None)
        return None, ("gh pr create: " + (r.stderr or "").strip())
    url = r.stdout.strip()
    # AC3: enable auto-merge (squash). The merge still waits on all required checks + the main
    # rulesets — the App has no bypass — so this arms the merge, it does not force it.
    if url:
        _close_superseded(branch, url, ws)
    if automerge and url:
        return _arm_head(url)                    # a new PR is bound to the verified head too
    return url, None


# rc-5b R1 (REQ-AUD-14 AC3/AC4): the lift trigger is {carrier, min_version, component, component_min_version} ("carrier
# >= X embeds component >= Y"), validated by shape and compared with the SBOM's carrier version on
# the daily recheck before the model is asked. A free-text trigger is no acceptance (the finding stays visible), exactly
# like a missing one.
_LIFT_KEYS = {"carrier", "min_version", "component", "component_min_version"}
# matches 20.2, v1.1.1n, 3.0.9-1+deb12u1, 20.2~rc1; refuses soon, 20.2; rm, an Arabic-Indic digit string
_LIFT_VERSION = re.compile(r"^v?[0-9]+(?:\.[0-9]+)*[0-9A-Za-z.+~:-]*$")


def _lift_trigger(t):
    """The normalized {carrier, min_version, component, component_min_version} of a well-formed trigger, else None."""
    if not isinstance(t, dict) or set(t) != _LIFT_KEYS or not all(isinstance(v, str) for v in t.values()):
        return None
    out = {k: v.strip() for k, v in t.items()}
    for name in ("carrier", "component"):
        if not out[name] or len(out[name]) > 200 or any(ord(ch) < 32 for ch in out[name]):
            return None
    for ver in ("min_version", "component_min_version"):
        if not out[ver] or len(out[ver]) > 64 or not _LIFT_VERSION.match(out[ver]):
            return None
    return out


def _trigger_for(trigger, package):
    """The well-formed trigger, only when it names the finding's own component (a trigger about another component is no
    acceptance: the finding stays visible)."""
    t = _lift_trigger(trigger)
    return t if t and t["component"].lower() == str(package or "").strip().lower() else None


def _version_key(v):
    """(numbers, tail) for a version the trigger can order, else None. The tail is empty for a plain version,
    ("l", n) for a lone letter (OpenSSL 1.1.1n) and ("r", rev, deb, u) for a Debian revision (3.0.9-1 or
    3.0.9-1+deb12u1). Any other suffix (~rc1, +dfsg, a second letter) is not ordered here."""
    m = re.match(r"^v?([0-9]+(?:\.[0-9]+)*)(.*)$", str(v or "").strip())
    if not m:
        return None
    numbers, rest = tuple(int(x) for x in m.group(1).split(".")), m.group(2)
    if not rest:
        return numbers, ()
    if re.fullmatch(r"[a-z]", rest):                       # matches n; refuses N, nn, 1
        return numbers, ("l", ord(rest))
    rev = re.fullmatch(r"-([0-9]+)(?:\+deb([0-9]+)u([0-9]+))?", rest)      # matches -1, -1+deb12u1; refuses -1~rc1, -a
    return (numbers, ("r",) + tuple(int(x or 0) for x in rev.groups())) if rev else None


def _version_ge(a, b):
    """True/False when a >= b (20.10 > 20.2; 1.1.1n < 1.1.1w; 3.0.9-1 < 3.0.9-1+deb12u1), None when either is not a
    version it can order: the model is asked then, as for an unreadable one."""
    x, y = _version_key(a), _version_key(b)
    if x is None or y is None:
        return None
    if x[1] and y[1] and x[1][0] != y[1][0]:               # a letter against a Debian revision has no order
        return None
    n = max(len(x[0]), len(y[0]))
    pad = lambda numbers: numbers + (0,) * (n - len(numbers))
    return (pad(x[0]), x[1]) >= (pad(y[0]), y[1])


def _carrier_name(c):
    """A carrier by its plain lower-case name, from `nodejs` or `pkg:deb/debian/nodejs@20.1?arch=amd64`."""
    c = str(c or "").strip()
    if c.startswith("pkg:"):
        c = c.split("?", 1)[0].split("@", 1)[0].rsplit("/", 1)[-1]
    return c.lower()


def _trigger_state(trigger, carrier):
    """'met' / 'unmet' when a well-formed trigger and the SBOM's record of the SAME carrier let the version be
    compared, else 'unknown' (a legacy text trigger, another carrier, an unreadable version: nothing is
    concluded and the model is asked as before)."""
    t = _lift_trigger(trigger)
    if t is None or not carrier:
        return "unknown"
    names = {_carrier_name(carrier.get("carrier")), _carrier_name(carrier.get("carrier_purl"))} - {""}
    if _carrier_name(t["carrier"]) not in names:
        return "unknown"
    ge = _version_ge(carrier.get("carrier_version"), t["min_version"])
    return "unknown" if ge is None else ("met" if ge else "unmet")


def _trigger_text(t):
    return "%s >= %s embeds %s >= %s" % (t["carrier"], t["min_version"], t["component"], t["component_min_version"])


# dot-separated identifiers of a semantic version's prerelease or build part. Matches "rc.1", "incompatible",
# "0.20200101000000-abc"; refuses "" (a bare "-" or "+"), "a..b" and "x y"
_SEMVER_IDS = r"[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*"


def _vmajor(v):
    """The major number of a Go version (`v1.2.3`, `0.3.0`, a prerelease, `+incompatible`), None when it is not a
    readable semantic version."""
    m = re.match(r"^v?(\d+)\.(\d+)\.(\d+)(?:-%s)?(?:\+%s)?$" % (_SEMVER_IDS, _SEMVER_IDS), str(v or ""))
    return int(m.group(1)) if m else None


def _is_major_bump(module, frm, to):
    """rc-5b A6 (agent-remediation-rules: "a major bump means an API changed"): the transition changes the major number
    (v0.9 -> v1.0 included), the
    module path's /vN suffix disagrees with the target's major, or either version is unreadable (fail safe: held, never
    auto-treated as a patch)."""
    f, t = _vmajor(frm), _vmajor(to)
    if f is None or t is None or f != t:
        return True
    pm = re.search(r"/v(\d+)$", str(module or ""))
    return bool(pm) and int(pm.group(1)) != t


_DEPENDABOT_TITLE = re.compile(r"\b[Bb]ump (\S+) from \S+ to (\S+)")


def _dependabot_match(prs, module, tkey):
    """The open Dependabot PR (number, url) whose title is `Bump <module> from X to <tkey>` for exactly this module and
    version, else None."""
    for pr in prs or []:
        title = str(pr.get("title") or "")
        m = _DEPENDABOT_TITLE.search(title)
        # a Dependabot PR for another directory says so ("... in /tools/govulncheck"): it bumps that module's go.mod,
        # never ours
        if m and m.group(1) == module and m.group(2).lstrip("v").rstrip(".,;") == tkey and not re.search(r" in /\S",
            title):
            return pr.get("number"), pr.get("url") or ""
    return None


def _open_dependabot_prs(ws):
    """(list of {number,title,url}, None) of the open Dependabot PRs, or (None, the failure text). Row 47 (owner, Sep
    21): the auditor performs bumps
    "deferring to an open Dependabot PR where one exists"."""
    log = os.environ.get("AUDITOR_GIT_SHIM_LOG")
    if log:
        if os.environ.get("AUDITOR_SHIM_DEPENDABOT_FAIL"):
            return None, "simulated lookup failure"
        return json.loads(os.environ.get("AUDITOR_SHIM_DEPENDABOT_PRS") or "[]"), None
    r = subprocess.run(["gh", "pr", "list", "--state", "open", "--author", "app/dependabot", "--json",
        "number,title,url", "--limit", "200"],
                       cwd=ws, capture_output=True, text=True)
    if r.returncode != 0:
        return None, "gh pr list: " + (r.stderr or "").strip()
    try:
        return json.loads(r.stdout or "[]"), None
    except ValueError:
        return None, "gh pr list: unreadable answer"


def _emit_held_issue(title, body, dry, would, cves=(), target=None):
    """Open OR update the issue that hands a held MAJOR bump to a harness lane as a task (rc-5b A6: a major is judged
    by a machine, never by the owner). NOT an owner-decision issue: no owner label, no assignee. Returns (ok, ref)
    like _emit_owner_issue."""
    cmd = "gh issue create --title %s" % shlex.quote(title)
    if dry:
        _plan(would, "held-major issue", target or title, cves, cmd)
        print("dry-run would create: " + cmd); return True, "dry"
    log = os.environ.get("AUDITOR_GIT_SHIM_LOG")
    if log:
        prior = open(log).read() if os.path.exists(log) else ""
        if ("issue create --title %s" % shlex.quote(title)) in prior:
            open(log, "a").write("gh issue comment --title %s --body %s\n" % (shlex.quote(title), shlex.quote(body)))
            return True, "shim-updated"
        open(log, "a").write(cmd + " --body " + shlex.quote(body) + "\n")
        failing = bool(os.environ.get("AUDITOR_SHIM_ISSUE_FAIL"))
        return (not failing), (None if failing else "shim-created")
    if not _real_gh_allowed():
        print("would open/update held-major issue (real gh disabled): " + title); return True, "skipped"
    ienv = dict(os.environ)
    ienv["GH_TOKEN"] = os.environ.get("AUDITOR_ISSUES_TOKEN") or os.environ.get("GH_TOKEN", "")
    try:
        r = subprocess.run(["gh", "issue", "list", "--search", title, "--state", "open", "--json", "number,title"],
            capture_output=True, text=True, env=ienv)
        if r.returncode != 0:
            print("held-major issue discovery FAILED: %s" % (r.stderr or "").strip()); return False, None
        found = [i for i in json.loads(r.stdout or "[]") if i.get("title") == title]
        if found:
            c = subprocess.run(["gh", "issue", "comment", str(found[0]["number"]), "--body", body], capture_output=True,
                text=True, env=ienv)
            return (c.returncode == 0), found[0]["number"]
        c = subprocess.run(["gh", "issue", "create", "--title", title, "--body", body], capture_output=True, text=True,
            env=ienv)
        if c.returncode != 0:
            print("held-major issue create FAILED: %s" % (c.stderr or "").strip()); return False, None
        url = (c.stdout or "").strip().splitlines()[-1] if c.stdout else ""
        num = url.rstrip("/").split("/")[-1] if url else None
        return True, (int(num) if (num or "").isdigit() else url)
    except Exception as e:
        print("held-major issue open/update failed: %s" % e); return False, None


def _bump_target(fb):
    """The delivery TARGET of a bump: (module, version) — one PR per target, never per CVE
    (LR-32; owner, Sep 28: "one PR per bump, listing every CVE it fixes"). `0.22.0` and `v0.22.0`
    are the same target; Go resolves the `v` form."""
    to = str(fb.get("to") or "")
    return (fb.get("module"), to[1:] if to.startswith("v") else to)


def _branch_slug(s):
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", str(s)).strip("-.")
    return re.sub(r"\.{2,}", ".", s) or "x"


def _deliver_bumps(rows, today, commit, dry, would, is_test=False):
    """Deliver every §1/§3 bump: ONE delivery per (module, version) target carrying all its CVEs
    (LR-32), then set each row's honest action from its target's delivery status. A MAJOR transition
    (rc-5b A6) is delivered as the same draft and also opens one issue, a task for a harness lane; a target an open
    Dependabot PR already covers (A7) is deferred to. Returns the delivery errors (each makes the run INCOMPLETE)."""
    fix_errs = []
    targets = {}                                   # LR-32: ONE delivery per (module, version) target
    for r in rows:
        if r.get("fix_bump"):
            targets.setdefault(_bump_target(r["fix_bump"]), []).append(r)
    delivered = {}
    held = {}                                      # target -> (ok, issue ref) for a delivered major
    for tk, group in targets.items():
        delivered[tk] = _deliver_fix_pr(group, today, commit, dry, would, is_test=is_test)
        fb0 = group[0]["fix_bump"]
        # MAJOR-HELD
        if delivered[tk][2] in ("delivered", "delivered-unchecked", "would") and _is_major_bump(fb0.get("module"),
            fb0.get("from"), fb0.get("to")):
            cves = sorted({g["fix_bump"].get("cve") or g["id"] for g in group})
            title = policy.subject("major bump %s -> %s held as a harness lane task" % (fb0["module"], fb0["to"]))
            body = ("The daily CVE auditor found a fixed version of %s that is a MAJOR transition (%s -> %s). "
                    "A major bump means an API changed (judged by a machine, not by the repository owner), "
                    "so the auditor opened the draft PR but did not arm it; a harness lane makes the change on our "
                    "side.\n\n- Vulnerabilities: %s\n- Draft PR: %s\n"
                    % (fb0["module"], fb0.get("from"), fb0["to"], ", ".join(cves), delivered[tk][0] or "(dry run)"))
            held[tk] = _emit_held_issue(title, body, dry, would, cves=cves, target="%s %s -> %s" % (fb0["module"],
                fb0.get("from"), fb0["to"]))
    for r in rows:
        if not r.get("fix_bump"):
            continue
        fb = r["fix_bump"]; lift = r.get("lift_note", "")
        furl, ferr, fstatus = delivered[_bump_target(fb)]
        hold = held.get(_bump_target(fb))
        held_note = ""
        if hold is not None:
            if hold[0]:
                if hold[1] == "dry":
                    held_note = "; MAJOR transition: the held-major issue would be opened (dry run)"
                elif hold[1] == "skipped":
                    held_note = "; MAJOR transition: held as a harness lane task, issue NOT opened (delivery disabled)"
                else:
                    ref = hold[1] if hold[1] not in (None, "shim-created", "shim-updated") else "opened"
                    held_note = "; MAJOR transition: held as a harness lane task (issue %s)" % ref
            else:
                held_note = "; MAJOR transition: the held-major issue FAILED to open (run INCOMPLETE)"
                r["pending_delivery"] = True
                if "held-major issue" not in fix_errs:
                    fix_errs.append("held-major issue")
        if fstatus in ("delivered", "delivered-unchecked"):
            r["action"] = ("opened draft bump PR: %s" % (furl or "(App bot)")) + held_note + lift
            if fstatus == "delivered-unchecked":
                r["action"] += "; could not look at Dependabot PRs (lookup failed), delivered without the check"
            r["fix_pr_url"] = furl
        elif fstatus == "deferred":
            r["action"] = ("deferred to Dependabot PR %s: it already carries this bump" % furl) + lift
        elif fstatus == "would":
            r["action"] = ("dry run: would open draft bump PR %s %s -> %s" % (fb["module"], fb["from"],
                fb["to"])) + held_note + lift
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
            if ferr not in fix_errs:
                fix_errs.append(ferr)
    return fix_errs


def _deliver_fix_pr(rows, today, commit, dry, would, is_test=False):
    """Deliver ONE Go-module bump TARGET (module, version) as one PR carrying every CVE it fixes
    (LR-32), on a stable branch named after the target — never after a CVE or a commit — so a
    later run updates that PR (or leaves it alone when nothing changed) instead of opening a
    duplicate or overwriting another target's branch. `go get <module>@<version>` + `go mod tidy`,
    committing ONLY go.mod and go.sum. `rows` are the §1/§3 rows sharing the target (a single row
    dict is accepted). Base rebuilds are NOT delivered here (REQ-AUD-2 AC3).

    Returns (pr_url, err, status). status is one of: 'delivered' (PR opened, updated or already
    current), 'would' (dry run), 'unresolvable' (the version does not resolve, or the bump is a
    no-op — rows stay in §3, never a broken PR), 'pending' (no authorized delivery step),
    'skipped-test' (test image), 'error' (a git/gh/tidy failure — the run is INCOMPLETE)."""
    rows = [rows] if isinstance(rows, dict) else list(rows)
    fbs = [r.get("fix_bump") or {} for r in rows]
    module, tkey = _bump_target(fbs[0])
    to = "v" + tkey if (tkey[:1].isdigit()) else tkey            # Go resolves the v form
    _v = lambda x: ("v" + x) if x[:1].isdigit() else x              # one spelling per version
    frms = sorted({_v(str(f.get("from"))) for f in fbs if f.get("from")})
    frm = ", ".join(frms)
    cves = sorted({f.get("cve") or r["id"] for f, r in zip(fbs, rows)})
    cvs = ", ".join(cves) if len(cves) <= 3 else "%s, +%d more" % (", ".join(cves[:3]), len(cves) - 3)
    branch = "auditor/bump-%s-%s" % (_branch_slug(module), _branch_slug(tkey))
    title = policy.subject("bump %s -> %s (%s)" % (module, to, cvs))
    server = os.environ.get("GITHUB_SERVER_URL"); repo = os.environ.get("GITHUB_REPOSITORY"); rid = os.environ.get("GITHUB_RUN_ID")
    runlink = ("%s/%s/actions/runs/%s" % (server, repo, rid)) if (server and repo and rid) else "the daily CVE auditor run report"
    body = ("Automated dependency bump from the daily CVE auditor. One PR per bump target, listing every "
            "vulnerability it fixes.\n\n- Module: %s\n- From: %s\n- To: %s\n- Vulnerabilities (%d): %s\n\n"
            "Run report: %s" % (module, frm, to, len(cves), ", ".join(cves), runlink))
    target = "%s %s -> %s" % (module, frm, to)
    if is_test:                                 # a test image is not shipped and always dry (AC9)
        _plan(would, "bump PR", target, cves, note="skipped: test image", key=branch)
        return None, None, "skipped-test"
    log = os.environ.get("AUDITOR_GIT_SHIM_LOG")
    ws0 = os.environ.get("GITHUB_WORKSPACE", os.getcwd())
    if log or _real_gh_allowed():
        prs, lerr = _open_dependabot_prs(ws0)
        hit = _dependabot_match(prs, module, tkey) if prs is not None else None
        # row 47: defer to the open Dependabot PR that carries this bump; open nothing (a dry run says so too)
        if hit:
            if dry:
                _plan(would, "bump PR", target, cves, note="deferred to Dependabot PR #%s" % hit[0], key=branch)
            print("bump %s -> %s deferred to Dependabot PR #%s" % (module, to, hit[0]))
            return (hit[1] or "#%s" % hit[0]), None, "deferred"
        unchecked = lerr is not None
        if unchecked:
            print("warning: could not look at Dependabot PRs (%s); delivering without the check" % lerr)
    else:
        unchecked = False
    # AC3/AC4: a bump PR touches only go.mod/go.sum (no prompt file), so it auto-merges when the
    # owner turned auto-merge on; otherwise draft. A MAJOR transition is held (rc-5b A6): always a draft, never armed.
    major = _is_major_bump(module, frm, to)
    automerge = _automerge_allowed(["go.mod", "go.sum"]) and not major
    draft = "" if automerge else "--draft "
    if dry:
        _plan(would, "bump PR", target, cves,
              cmd="gh pr create %s--base main --head %s --title %s" % (draft, branch, shlex.quote(title)),
              note="auto-merge" if automerge else "draft", key=branch)
        print("dry-run would open %sbump PR on %s" % ("auto-merge " if automerge else "draft ", branch))
        return None, None, "would"
    if log:
        # test shim: the log is the remote. A target already delivered with the same CVE set is
        # left alone; a changed CVE set updates the SAME PR (AC2); a new target gets its own branch.
        prior = open(log).read() if os.path.exists(log) else ""
        url = "https://github.com/OWNER/REPO/pull/SHIM-%s" % branch.split("/", 1)[1]
        mark = "SHIM_TARGET %s %s" % (branch, ",".join(cves))
        if mark in prior.splitlines():
            open(log, "a").write("UNCHANGED %s\n" % branch)
            return url, None, ("delivered-unchecked" if unchecked else "delivered")
        seq = ["git checkout -B %s origin/main" % branch,
               "go get %s@%s" % (module, to),
               "go mod tidy",
               "gh api graphql createCommitOnBranch %s -- go.mod go.sum" % branch]   # a signed commit made through the API: no git commit, no git push
        if ("SHIM_TARGET %s " % branch) in prior:
            seq.append("gh pr edit %s --title %s" % (branch, shlex.quote(title)))       # same PR, updated
        else:
            seq.append("gh pr create %s--base main --head %s --title %s" % (draft, branch, shlex.quote(title)))
            if automerge:
                seq.append("gh pr merge --auto --squash %s" % branch)
        open(log, "a").write("\n".join(seq) + "\n")
        if os.environ.get("AUDITOR_SHIM_PR_FAIL"):
            return None, "simulated: push to origin/%s rejected" % branch, "error"
        open(log, "a").write("%s\nPR_URL %s\n" % (mark, url))
        return url, None, ("delivered-unchecked" if unchecked else "delivered")
    if not _real_gh_allowed():
        print("bump PR pending: no authorized delivery step (real gh disabled): %s" % title)
        _plan(would, "bump PR", target, cves, note="not delivered: delivery disabled (no authorized delivery step)", key=branch)
        return None, None, "pending"
    ws = _workspace()

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
    staged = [f for f in ("go.mod", "go.sum") if os.path.exists(os.path.join(ws, f))]   # a module with no dependencies has no go.sum
    if "go.mod" not in staged:
        return None, "go.mod is missing after go get / go mod tidy: nothing to stage", "error"
    r = _git("add", *staged)
    if r.returncode != 0:                        # a staging failure is an error, never "nothing changed"
        return None, ("git add: " + (r.stderr or "").strip()), "error"
    if _git("diff", "--cached", "--quiet").returncode == 0:
        # the bump changed nothing (already at/after the fixed version) — nothing to deliver
        _git("reset", "--hard", "origin/main")
        return None, None, "unresolvable"
    # AC2: the target's branch may already carry an open PR from an earlier run. Unchanged
    # go.mod/go.sum (this run's tree against that branch) AND a head that GitHub verifies as signed,
    # on today's main -> no commit (the PR is left alone). Anything else (changed files, an unsigned
    # legacy head, a head on an older main, a lookup that fails) -> the branch is rebuilt on main
    # and ONE signed commit is made on it, through the API.
    remote_same = (_git("fetch", "origin", branch).returncode == 0
                   and _git("diff", "--quiet", "FETCH_HEAD", "--", "go.mod", "go.sum").returncode == 0)
    sha = _git("rev-parse", "origin/main")
    if sha.returncode != 0:
        return None, ("git rev-parse: " + (sha.stderr or "").strip()), "error"
    base_sha = sha.stdout.strip()
    ex, err = _find_pr(ws, branch)
    if err:
        return None, err, "error"                # a discovery failure aborts BEFORE any ref write
    files = [f for f in ("go.mod", "go.sum") if os.path.exists(os.path.join(ws, f))]    # a module with no dependencies has no go.sum
    oid = None
    if remote_same:                              # reuse = ONE verified commit on main changing only these files, with these exact bytes
        # the App's login is its slug plus [bot]: reuse only what the App itself made
        slug = os.environ.get("AUDITOR_APP_SLUG")
        want = signed_commit.read_changes(ws, files)
        oid = signed_commit.branch_reusable(os.environ.get("GITHUB_REPOSITORY"), branch, base_sha, want,
                                            app_login=slug + "[bot]" if slug else None)
    if oid is None:
        # the existing PR is found and DISARMED first (a held major is made a draft too), then its branch is replaced
        err = _hold_as_draft(ws, ex) if major else _disarm_before_replace(ws, ex)
        if err:
            return None, err, "error"
        oid, err = _signed_delivery(ws, branch, base_sha, title, files)
        if err:
            return None, err, "error"

    def _arm(u):
        if automerge and u:
            err = _head_is(ws, u, oid)           # EVERY path: the PR's actual head must be the verified one (made, or reused-and-verified)
            if err:
                return err
            _arm_automerge(u, ws)
        return None
    def _reuse(u):
        # the open PR is updated to this run's CVE list; a failed edit is a failed delivery (never
        # armed, never reported delivered) — whichever discovery path found the PR
        # a held major stays a draft with auto-merge off, even a PR an earlier run armed
        if major:
            err = _hold_as_draft(ws, u)
            if err:
                return None, err, "error"
        e = subprocess.run(["gh", "pr", "edit", u, "--title", title, "--body", body], cwd=ws,
                           capture_output=True, text=True)
        if e.returncode != 0:
            return None, ("gh pr edit: " + (e.stderr or "").strip()), "error"
        err = _arm(u)
        return (None, err, "error") if err else (u, None, ("delivered-unchecked" if unchecked else "delivered"))
    if ex:
        return _reuse(ex)
    create = ["gh", "pr", "create", "--base", "main", "--head", branch, "--title", title, "--body", body]
    if not automerge:
        create.insert(3, "--draft")
    r = subprocess.run(create, cwd=ws, capture_output=True, text=True)
    if r.returncode != 0:
        if "already exists" in (r.stderr or "").lower():
            ex, _ = _find_pr(ws, branch)
            if ex:
                return _reuse(ex)
        return None, ("gh pr create: " + (r.stderr or "").strip()), "error"
    url = r.stdout.strip()
    err = _arm(url)
    return (None, err, "error") if err else (url, None, ("delivered-unchecked" if unchecked else "delivered"))


def _merge_suppressions(ws, supp, base=None):
    """Merge this run's consolidated suppressions INTO the existing reviewed files in the
    checkout, preserving statements/entries this run does not touch and continuing the VEX
    document version (R1 outer round-4 #3). Statements are keyed by @id (this run replaces a
    same-@id statement, adds new ones, keeps the rest)."""
    import shutil
    vp = os.path.join(ws, ".vex", "fosterstack-cache.openvex.json")
    newdoc = _read_reviewed_json(os.path.join(supp, "fosterstack-cache.openvex.json"))
    if newdoc is None:                              # the run's own consolidated VEX must exist (as before: a missing file is a staging error)
        raise FileNotFoundError(os.path.join(supp, "fosterstack-cache.openvex.json"))
    # the delivery hands down the base documents it validated at the sha: the tree is not read again
    existing = (base[BASE_VEX] if base is not None else _read_reviewed_json(vp)) or {}
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
    for sc in _read_reopened(os.path.join(os.path.dirname(supp), ".auditor", "reopened-expired.json")):
        reopened.add((sc[0], tuple(sc[1]), tuple(sc[2])))     # (cve, products, purls)
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
    old_ai = base[BASE_ITEMS] if base is not None else _read_reviewed_json(os.path.join(ws, ".auditor", "accepted-items.json"))   # read (and so validated) BEFORE the working tree is touched: an unreadable inventory stops the run with the VEX unwritten
    new_ai = _read_reviewed_json(os.path.join(os.path.dirname(supp), ".auditor", "accepted-items.json"))     # the run's own inventory too
    os.makedirs(os.path.dirname(vp), exist_ok=True)       # the working tree is touched only after every read above has passed
    cli.writej(vp, merged)

    # accepted-items.json is COUPLED to the VEX: an affected statement that survives the VEX
    # merge but this run did not re-assess must keep its inventory entry, or release-authz
    # rejects the package as inconsistent (R1 outer round-5 #2). Merge like the VEX — this
    # run's items win; carry an old item forward for any affected CVE still in the merged
    # document; drop acceptances whose statement is no longer affected.
    aip = os.path.join(ws, ".auditor", "accepted-items.json")
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



def _collect_vex(out, ts):
    """Read every per-CVE VEX this run wrote and validate the merged document; writes nothing. Returns (document,
    statements). run() calls it BEFORE the first owner-decision issue
    so a damaged per-finding VEX stops the run (exit 3) while nothing outside the run's own directory has been touched
    (cache#701 ruling F3/B3); _consolidate does the same read."""
    vdir = os.path.join(out, "vex")
    try:
        names = sorted(n for n in os.listdir(vdir) if n.endswith(".openvex.json") and not n.startswith("."))
    except FileNotFoundError:
        names = []                                    # the run wrote no per-finding VEX
    # unreadable, or not a directory: a stop, never "no statements" (glob turned it into an empty list)
    except OSError as ex:
        raise ReviewedInputInvalid("%s cannot be listed (%s)" % (vdir, type(ex).__name__))
    statements = []
    for n in names:
        # a per-finding VEX this run wrote that does not parse: the run is broken, it stops
        statements.extend((_read_reviewed_json(os.path.join(vdir, n)) or {}).get("statements", []))
    document = {"@context": "https://openvex.dev/ns/v0.2.0", "@id": policy.VEX_BASE,
                "author": "FosterStack LLC", "role": "vendor", "timestamp": ts, "version": 1,
                "statements": statements}
    try:
        vex.validate(document)
    except ValueError as ex:
        raise ReviewedInputInvalid("the per-finding VEX the run wrote does not make a valid statement set (%s)" % ex)
    return document, statements


def _consolidate(out, ts):
    """Merge every per-CVE VEX this run wrote into ONE canonical
    suppressions/fosterstack-cache.openvex.json (the file scan/rescan/release-authz read),
    Returns
    (suppression_dir, statement_count). (R1 round-3: the auditor's VEX must reach the
    canonical file, and the consistency check must read the layout the run actually writes.)"""
    document, statements = _collect_vex(out, ts)
    supp = os.path.join(out, "suppressions")
    cli.writej(os.path.join(supp, "fosterstack-cache.openvex.json"), document)
    return supp, len(statements)


def adjudicate(adjudicator, ctx, state):
    """primary -> rephrase -> fallback for ONE finding, bounded by the
    three attempts and globally by the token budget. Returns the category, 'refused' (a genuine refusal the
    model WAS reachable for), or 'adjudicator_error' (every attempt errored — the model was
    UNAVAILABLE). On an error, surface the REAL cause (exception class + HTTP status + message,
    secrets MASKED) ONCE per distinct error into state['adj_errors'] so the header, §4 and the
    status line can name it, and it is not repeated per finding (R-live fix 1)."""
    # REQ-AUD-3 AC3: the exact same context judged by yesterday's run (state valid, finding-set hash identical) is not asked again.
    nc_key = nochange.call_key("adjudicate", ctx)
    reused = nochange.verdict(state.get("nc_prev"), nc_key)
    if reused is not None:
        state.setdefault("nc_verdicts", {})[nc_key] = reused
        state["nc_reused"] = state.get("nc_reused", 0) + 1
        return reused
    errored = False; refused = False
    for attempt, role in (("primary", "primary"), ("rephrase", "primary"), ("fallback", "fallback")):
        if state["tokens"] >= policy.TOKEN_BUDGET:
            state["stops"] = state.get("stops", 0) + 1
            state["nc_incomplete"] = True                       # REQ-AUD-3 AC3: a stop is an attempted call without a cacheable result
            state.setdefault("stopped", []).append({"finding_id": ctx["finding_id"], "why": "token budget"})
            return "budget_stop"     # not a genuine refusal: section 4 with no issue
        state["calls"] = state.get("calls", 0) + 1
        try:
            ans = cli.ask_model(adjudicator, ctx["finding_id"], attempt=attempt, model=role, context=ctx)
        except cli.Refused as e:
            state["tokens"] += int(getattr(e, "token_usage", 0) or 0)   # a refusal is still billed
            refused = True
            state.setdefault("roles_used", set()).add(role)          # a refused call still ran that model
            state.setdefault("refusals", []).append({"finding_id": ctx["finding_id"], "attempt": attempt, "role": role})     # logged for the report (REQ-AUD-8 AC3): finding, attempt, model role, never a model id
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
        _pr = _valid_proposal(ans.get("propose"))
        if _pr is not None:
            state.setdefault("proposals", []).append(
                {"finding_id": ctx["finding_id"], "package": ctx.get("package"), "propose": _pr})
        elif ans.get("propose") is not None:
            state["proposals_refused"] = state.get("proposals_refused", 0) + 1      # the proposal is refused, not the run (rc-5b R4)
        category = ans.get("category") or "unknown"
        if category in nochange.CATEGORIES:
            state.setdefault("nc_verdicts", {})[nc_key] = category
        else:
            state["nc_incomplete"] = True                       # an answer outside the five categories is not cached, so the run is incomplete
        return category
    state["nc_incomplete"] = True                               # every attempt was refused or errored: nothing cacheable
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
    nc_key = nochange.call_key("pullability", ctx)
    reused = nochange.pullability(state.get("nc_prev"), nc_key)
    if reused is not None:                                      # REQ-AUD-3 AC3: the same context, judged yesterday
        state.setdefault("nc_pull", {})[nc_key] = reused
        state["nc_reused"] = state.get("nc_reused", 0) + 1
        return reused
    if state["tokens"] >= policy.TOKEN_BUDGET:
        state["nc_incomplete"] = True                           # REQ-AUD-3 AC3: a stop leaves a call unanswered, so the run is incomplete
        return None
    state["calls"] = state.get("calls", 0) + 1
    try:
        ans = cli.ask_model(adjudicator, ctx["finding_id"], attempt="pullability", model="primary", context=ctx)
    except cli.Refused as e:
        state["tokens"] += int(getattr(e, "token_usage", 0) or 0)
        state["nc_incomplete"] = True
        state.setdefault("roles_used", set()).add("primary")
        state.setdefault("refusals", []).append({"finding_id": ctx["finding_id"], "attempt": "pullability", "role": "primary"})      # REQ-AUD-8 AC3: every refusal is logged
        return None
    except Exception as e:
        state["nc_incomplete"] = True
        msg = "%s: %s" % (type(e).__name__, _mask(str(e)))
        key = re.sub(r"\s*\[?request[_-]?id[=:]\s*[^\]\s]+\]?", "", msg, flags=re.I)
        errs = state.setdefault("adj_errors", {})
        if key not in errs:
            print("pullability error: %s" % msg); errs[key] = msg
        return None
    state["tokens"] += int(ans.get("token_usage") or 0)
    state.setdefault("roles_used", set()).add("primary")
    rec = nochange.pull_record(ans)
    if rec is None:
        state["nc_incomplete"] = True
        return None          # an answer the router cannot read safely is as good as none: the finding stays on the actionable route
    state.setdefault("nc_pull", {})[nc_key] = rec
    return ans


# ---- deterministic facts from scanner data ----

def _eco(purl):
    m = re.match(r"pkg:([^/]+)/", purl or "")
    return (m.group(1) if m else "").lower()


def _ver_from_purl(purl):
    """The version a package URL names, decoded (3.0.1%2Bdeb12u1 is 3.0.1+deb12u1) and without any qualifier or subpath."""
    m = re.search(r"@([^?#]+)", purl or "")
    return urllib.parse.unquote(m.group(1)) if m else None


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
    """Why a finding has no fix. The panel's verdict carries no fix-state words (a fix is a version or absent), so it is the one reason."""
    return "no upstream fix"


def _sev_by_scanner(findings):
    """Each scanner's own severity for a finding group, so the report shows each (the policy uses the highest): {scanner: severity}."""
    out = {}
    for f in findings:
        sv = (f.get("severity") or "")
        if not f.get("scanner"):
            continue
        if not sv:
            out.setdefault(f["scanner"], "not rated")       # it reported the finding but gave no severity: shown, never guessed or dropped
            continue
        cur = out.get(f["scanner"])
        if cur is None or cur == "not rated" or (sv.lower() in SEV_ORDER and (cur.lower() not in SEV_ORDER or SEV_ORDER.index(sv.lower()) > SEV_ORDER.index(cur.lower()))):
            out[f["scanner"]] = sv
    return out


def _seen_by_images(findings):
    """The panel's corroboration per image: {image: (scanners that saw it, scanners that ran there)}, from the verdict's own numbers."""
    out = {}
    for f in findings:
        for im, v in ((f.get("extra") or {}).get("by_image") or {}).items():
            out[im] = (len(v.get("seen_by") or []), v.get("of"))
    return out


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


# Markdown safety (owner's test, Sep 27): GitHub pairs stray `~` into strikethrough ACROSS lines,
# and `*`/`_`/`<`/`|` can turn into emphasis, HTML or table cells. An identifier or path that can
# carry such a character goes into a code span; free text is backslash-escaped.
_MD_SPECIAL = re.compile(r"[~*_<>|`\\\[\]#]")


def _one_line(s):
    """A report line is ONE line: tool stderr (git/gh) spans several — join them (round-1 blocker:
    a `#`-led stderr line rendered as a heading in the middle of the report)."""
    return re.sub(r"\s*[\r\n]+\s*", " ↵ ", "" if s is None else str(s)).strip()


def _ident(s):
    """An identifier/path, verbatim: bare when it has nothing Markdown could read, else a code span."""
    s = _one_line(s)
    if not _MD_SPECIAL.search(s):
        return s
    fence = "`" * (max((len(m) for m in re.findall(r"`+", s)), default=0) + 1)
    pad = " " if (s.startswith("`") or s.endswith("`")) else ""
    return "%s%s%s%s%s" % (fence, pad, s, pad, fence)


def _text(s):
    """Free text with every inline-significant character escaped (renders as the same text)."""
    s = _one_line(s)
    for ch in ("\\", "`", "~", "*", "<", "|", "[", "]"):
        s = s.replace(ch, "\\" + ch)
    # `_` only at a word boundary: intraword underscores (not_affected) never emphasise in GFM
    s = re.sub(r"(?<![A-Za-z0-9])_|_(?![A-Za-z0-9])", r"\\_", s)
    # a free-text line that STARTS a line could open a heading/quote/list/rule: escape the marker
    s = re.sub(r"^([#>+=-])", r"\\\1", s)
    return re.sub(r"^(\d+)([.)])(?=\s|$)", r"\1\\\2", s)


def _row_line(r):
    """One self-explaining line per row (R13 item 2), Markdown-safe."""
    reach = r.get("reachability") or "n/a (OS package)"
    fix = r.get("fixed") or "none"
    line = ("%s — %s — %s — fix: %s — reachability: %s — %s — action: %s — %s"
            % (_ident(r["id"]), _ident("%s@%s" % (r["package"], r["installed"])), _text(r["severity"]),
               _ident(fix), _text(reach), _text(r["disposition"]), _text(r["action"]), _text(r["reason"])))
    sbs = r.get("sev_by_scanner") or {}
    if sbs:                       # each scanner's own severity, always (policy uses the highest)
        line += " — severity by scanner: " + ", ".join("%s %s" % (_ident(sc), _text(sv)) for sc, sv in sorted(sbs.items()))
    sbi = r.get("seen_by_images") or {}
    if sbi:                       # the panel's own corroboration, per image ("seen by N of M")
        line += " — seen by: " + ", ".join("%s %s of %s" % (_ident(im), n, of) for im, (n, of) in sorted(sbi.items()))
    if r["section"] in (2, 5) and r.get("vex_id"):
        line += " — vex: %s — ignores: %s" % (_ident(r["vex_id"]),
                                               ",".join(_ident(f) for f in r.get("ignore_files", [])) or "none")
    if r["section"] == 4 and r.get("cause"):
        line += " — cause: %s" % _text(r["cause"])
    return line


def _unique(lines):
    """A list section never repeats a line (owner's rule): identical lines collapse to one, marked
    with how many rows it stands for — two indistinguishable rows are one thing to read."""
    counts = {}
    for x in lines:
        counts[x] = counts.get(x, 0) + 1
    return [x if counts[x] == 1 else "%s (×%d identical rows)" % (x, counts[x]) for x in dict.fromkeys(lines)]


def _pr_list(would, rows, sections, dry, pr_url, pr_err, is_test, standing=None):
    """'PRs and issues this run': one line per PR or issue opened or that would open — never one
    per finding — each naming its kind, its target and the CVE IDs it carries (owner's rule)."""
    def cv(ids):
        ids = sorted({i for i in ids if i})
        return ("CVEs: " + ", ".join(_ident(i) for i in ids)) if ids else "no CVE"
    raw = [w if isinstance(w, dict) else {"kind": "other", "target": str(w), "cves": [], "cmd": "", "note": ""}
           for w in would]
    # closing the standing issue opens nothing — it is not a line in "PRs and issues opened"
    raw = [p for p in raw if not (p["kind"] == "standing issue" and "close if open" in p["target"])]
    # ONE entry per delivery (its branch / its issue), however many rows fed it (round-1 blocker:
    # several installed versions of one CVE share one bump branch)
    plans, byk = [], {}
    for p in raw:
        k = str(p.get("key") or (p["kind"], p["target"]))
        if k in byk:
            q = byk[k]
            if p["target"] not in q["_targets"]:
                q["_targets"].append(p["target"])
            q["cves"] = sorted(set(q["cves"]) | set(p["cves"]))
        else:
            q = dict(p); q["_targets"] = [p["target"]]; byk[k] = q; plans.append(q)
    for q in plans:
        q["target"] = "; ".join(q["_targets"])
    if is_test:
        prs = {str(p.get("key") or (p["kind"], p["target"])) for p in plans if p["kind"].endswith("PR")}
        ncve = len({c for p in plans if p["kind"].endswith("PR") for c in p["cves"]})
        iss = {(p["kind"], p["target"]) for p in plans if p["kind"] == "owner-decision issue"}
        nb = len({str(p.get("key")) for p in plans if p["kind"] == "bump PR"})
        ns = len(prs) - nb
        line = ("Test image — nothing opened (not a shipped image); on a shipped image %d finding(s) "
                "would have produced %d PR(s) (%d bump target(s), %d suppression)" % (ncve, len(prs), nb, ns))
        if iss:
            line += " and %d owner-decision issue(s)" % len(iss)
        return [line + "."]
    out = []
    if pr_url:
        out.append("suppression PR (App): %s — %s" % (pr_url, cv((standing or {}).get("supp_cves")
                                                                  or [r["id"] for r in rows if r.get("vex_id")])))
    elif pr_err:
        out.append("suppression PR delivery FAILED (run INCOMPLETE): %s" % _text(pr_err))
    bumps = {}
    for r in (sections[1] + sections[3]):
        if r.get("fix_pr_url"):
            fb = r.get("fix_bump") or {}
            b = bumps.setdefault(r["fix_pr_url"], {"targets": [], "cves": set()})
            t = "%s %s -> %s" % (_ident(fb.get("module")), _ident(fb.get("from")), _ident(fb.get("to")))
            if t not in b["targets"]:
                b["targets"].append(t)
            b["cves"].add(r["id"])
    for url, b in bumps.items():                       # one line per bump PR, every CVE it carries
        out.append("bump PR (App): %s — %s — %s" % ("; ".join(b["targets"]), cv(b["cves"]), url))
    issues = {}
    for r in rows:
        oi = r.get("owner_issue")
        # the dry sentinel is represented by the 'would open' entries below; a real ref is shared by
        # the rows of one issue (one line, EVERY CVE and target it covers — round-1 blocker);
        # "skipped" (gh disabled) is per CVE (Codex R3 P3).
        if not oi or oi == "dry":
            continue
        # an undelivered ("skipped") issue is keyed by ITS identity — the one adjudicator-outage
        # issue, or one issue per (CVE, package) — never per row (review round 5)
        if oi == "skipped":
            key = ("skipped", "outage") if r.get("adjudicator_error") else ("skipped", r["id"], r.get("package"))
        else:
            key = oi
        it = issues.setdefault(key, {"ref": oi, "cves": set(), "targets": []})
        it["cves"].add(r["id"])
        t = ("adjudicator unavailable" if r.get("adjudicator_error") else _ident(r.get("package")))
        if t and t not in it["targets"]:
            it["targets"].append(t)
    for it in issues.values():
        out.append("owner-decision issue: %s — %s — %s" % (it["ref"], "; ".join(it["targets"]) or "—", cv(it["cves"])))
    if standing and standing.get("ref") not in (None, "dry", "skipped") and standing.get("needs"):
        out.append("standing issue: %s — %s — %d item(s) needing a human — %s" % (
            _text(policy.STANDING_ISSUE_TITLE), _text(standing["ref"]), standing["needs"], cv(standing.get("cves") or [])))
    if not dry:
        # a live run whose delivery step is disabled: say what was NOT delivered and why — never
        # "no actionable findings" (review round 4)
        for p in plans:
            if (p.get("note") or "").startswith("not delivered"):
                out.append("NOT delivered (delivery disabled — no authorized delivery step): %s — %s — %s"
                           % (p["kind"], _text(p["target"]), cv(p["cves"])))
    if dry:
        for p in plans:
            note = p.get("note") or ""
            extra = (" — " + _text(note)) if note and note != "draft" else ""
            out.append("would open (dry run): %s — %s — %s%s" % (p["kind"], _text(p["target"]), cv(p["cves"]), extra))
    if not out:
        return ["Nothing opened this run — %s; 0 finding(s) would have produced a PR." % (
            "dry run with no actionable findings" if dry else "no actionable findings")]
    return _unique(out)


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
        row["sev_by_scanner"] = _sev_by_scanner(sub); row["seen_by_images"] = _seen_by_images(sub)
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
        # LIFTED and bumped (REQ-AUD-2 AC7; REQ-AUD-13 AC3; R1 refactor round-4 #4).
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
        if cat not in nochange.SETTLED:
            env["state"].setdefault("unsettled_now", set()).add(c)        # no disposition from the model today: one more run unsettled (REQ-AUD-9 AC3)
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
        elif cat == "budget_stop":
            # the token budget stopped the model: NOT a refusal and not one of the five named conditions per finding; a budget stop notifies no one (nothing else notifies anyone).
            # Section 4, no per-finding issue. (The repeated-unsettled case, REQ-AUD-9 AC3 "a five-iteration stop", is the run counter's one aggregate issue below.)
            row.update(section=4, disposition="under investigation",
                       action="none (token budget reached)",
                       reason="adjudication stopped", cause="token budget reached")
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
        # rc-5b R1: a carried structured trigger the SBOM's carrier version has not reached needs no model call (and no
        # new verdict): the suppression is re-carried
        carried_trig = _trigger_for(env.get("carried_lift_trigger", {}).get((c, this_scope)), gf["package"])
        # a base-held scope can also lift through a base release the carrier says nothing about
        trig_unmet = ((c, this_scope) in env.get("carried_not_pullable",
            set()) and carrier is not None and not base_hold
                      and _trigger_state(carried_trig, carrier) == "unmet")
        if (carrier or base_hold) and not gf["is_go"] and not trig_unmet:
            pctx = {"kind": "pullability", "finding_id": c, "component": gf["package"],
                    "installed_version": gf["installed"], "component_fixed": gf["fixed"],
                    "purl": (subs or [None])[0], "carrier": carrier, "base": _stable_base(env.get("base")),
                    "candidate_digest": env["digest"]}
            pull = _pullability(env["adjudicator"], pctx, env["state"])
            if pull is not None:
                m_inc = 1
        # An acceptance requires ACTIONABLE evidence: a not-pullable verdict is written as accepted
        # risk ONLY when it carries a machine-checkable lift trigger (AC3). An incomplete verdict
        # ({"pullable": false} with no lift trigger) must NOT create a silent suppression — it falls
        # through to the normal fixable routing, so the finding stays visible (Codex R1 residual 3).
        _lt = _trigger_for(pull.get("lift_trigger"), gf["package"]) if pull else None
        # a trigger the SBOM's carrier ALREADY meets contradicts "not pullable": no acceptance (the finding stays
        # visible), never a suppression that reads "lifts when X" beside "carried at X or later"
        _not_pullable = bool(pull and pull.get("pullable") is False and _lt and _trigger_state(_lt, carrier) != "met")
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
            lift_trigger = _lt
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
                           _trigger_text(lift_trigger)))
            in_kev = c in env["kev_ids"] or bool(set(aliases) & env["kev_ids"])
            reason = policy.threshold_reason(gf["severity"], in_kev, gf["known_exploited"])
            at = reason != "below"
            if not at and not env.get("kev_ok", True):
                at = True; reason = "kev-unavailable (fail-closed)"
            row.update(section=2, not_pullable=hold, disposition="carried (fix not pullable)",
                       action="POA&M: affected VEX + ignores + lift trigger, expiry %s" % this_exp2,
                       vex_id=this_scope_id, scope_purls=_purls, reason=case, fixed=comp_fixed,
                       ignore_files=["vex"],
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
            if trig_unmet:
                cause = "lift trigger not met: %s at %s, below %s" % (
                    _carrier_name(carrier.get("carrier") or carrier.get("carrier_purl")),
                    carrier.get("carrier_version"), carried_trig["min_version"])
            elif (carrier or base_hold) and pull is None:
                cause = "adjudicator unavailable"
            else:
                cause = "carrier signal absent this run"
            # preserve the CONCRETE machine-checkable lift trigger from the prior acceptance rather
            # than a generic placeholder, so a deferred recheck does not lose the condition (Codex
            # round-2 P2). Falls back to a note only if none was carried.
            prior_trigger = env.get("carried_lift_trigger", {}).get((c, this_scope))
            if _lift_trigger(prior_trigger) and not _trigger_for(prior_trigger, gf["package"]):
                prior_trigger = None             # a structured trigger about another component is not carried on
            deferred_trigger = (prior_trigger if prior_trigger
                                else "prior lift trigger stands (recheck deferred: %s)" % cause)
            ev = {"check": "fix-not-pullable", "hold": hold, "recheck": "deferred", "cause": cause,
                  "component": gf["package"], "installed": gf["installed"], "component_fixed": gf["fixed"],
                  "lift_trigger": deferred_trigger}
            vex.write(out, c, "affected", ts,
                      action="fix exists but is not pullable (%s); recheck deferred (%s); suppression retained" % (hold, cause),
                      evidence=ev, target_date=this_exp3, lift_trigger=deferred_trigger,
                      vex_name=vn, subcomponents=subs)
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
                       ignore_files=["vex"],
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
    action = "POA&M: affected VEX + ignores, expiry %s" % this_exp
    # name the ignore artifacts this acceptance actually writes so the row line is honest — a
    # §2 POA&M without ignore_files defaulted _row_line to "ignores: none" (Codex round-2 P2).
    row.update(section=2, disposition="carried (POA&M)", action=action, vex_id=this_scope_id,
               scope_purls=_purls, reason="%s; %s" % (gf["nofix_reason"], reason), ignore_files=["vex"],
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


def _stable_base(base):
    """the base block without its day counter: days_behind moves every day with no finding changing, so it would end every
    no-change day. What the decisions use of it is whether it is beyond the threshold, which stays."""
    b = dict(base or {})
    if "days_behind" in b:
        days = b.pop("days_behind")
        b["behind_beyond_threshold"] = isinstance(days, int) and days > b.get("behind_threshold_days", 30)
    return b


def _adjudication_fingerprint(adjudicator):
    """a digest of what the model's answers depend on besides the question: the standing prompt, the adjudicator client itself and
    the configured model identifiers (hashed; the identifiers never leave the process)"""
    import hashlib
    h = hashlib.sha256()
    for path in (os.path.join(HERE, "..", "prompts", "adjudicator.md"), adjudicator):
        try:
            h.update(open(path, "rb").read())
        except OSError:
            h.update(("unreadable:%s" % path).encode("utf-8"))
        h.update(b"\0")
    for k, v in sorted((k, v.strip()) for k, v in os.environ.items() if k.startswith("AUDITOR_MODEL") and v and len(v.strip()) >= 3):
        h.update(("%s=%s" % (k, v)).encode("utf-8")); h.update(b"\0")       # the role name with its value: swapping primary and fallback is a change
    return h.hexdigest()


def run(manifest_path, dry, out, today, kevpath=None, adjudicator=None):
    m, groups = C.manifest_findings(manifest_path)
    # A test image is never shipped, so no statement on `main` applies and nothing is delivered:
    # a test image ALWAYS forces dry_run regardless of the dispatch input (REQ-AUD-15 AC9).
    if (m.get("provenance") or {}).get("source") == "test-image":
        dry = True
    gvc, module, gvc_usable = C.manifest_gvc(m)
    logpath = m.get("known_defect_log"); ts = today + "T00:00:00Z"
    _klog = load_defect_log(logpath)
    idx = log_index(_klog)
    # REQ-AUD-16 AC3: generate the knowledge document the model reads for pattern judgment from the
    # structured records (the known-defect log), deterministically and with no model call, and
    # carry it in the run output. Only TRUSTED rows contribute (a model-proposed row is excluded).
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
    state = {"tokens": 0, "roles_used": set()}
    # REQ-AUD-3 AC3 (no-change day): yesterday's verdicts and narrative are usable only when yesterday's state file is valid AND its
    # finding-set hash equals today's exactly; anything else leaves the run exactly as it was (model calls).
    import hashlib
    nc_hash = nochange.finding_set_hash(groups, {
        "digests": m.get("candidate_digests"), "knowledge": hashlib.sha256(knowledge_doc.encode("utf-8")).hexdigest(),
        "gvc": [gvc, module, gvc_usable], "carriers": m.get("carriers") or [], "base": _stable_base(m.get("base")),
        "adjudication": _adjudication_fingerprint(adjudicator)})
    prev_path = cli.opt("--prev-state") or os.environ.get("AUDITOR_PREV_STATE")
    state.update(nc_verdicts={}, nc_pull={}, nc_narr=None, nc_today=today, nc_prev=nochange.matching(nochange.load(prev_path), nc_hash))
    # REQ-AUD-9 AC3 "a five-iteration stop" (register row 38; advisor reading, Oct 24: a five-iteration loop = five CONSECUTIVE runs with the same finding unsettled): the counts ride in the
    # same state file. A missing state (the first run, or the artifact expired) restarts them and the run SAYS so; a present state that cannot be trusted stops the run.
    state["counter_status"], state["unsettled_prev"] = nochange.load_unsettled(prev_path, today)
    state["unsettled_now"] = set()
    if state["counter_status"] == "missing":
        print("daily CVE auditor: counter state missing, counts restart")
    # Carried acceptances from the checkout: when a time box has passed, the finding must
    # REOPEN (§3) this run and its ignore be removed, never silently renewed (REQ-AUD-2 AC5c;
    # R1 outer round-8 #4). Read the delivered inventory the previous run left in the workspace.
    carried_expiry = {}; carried_scopes = set(); carried_status = {}; carried_not_pullable = set()
    carried_lift_trigger = {}
    carried_stmts = []
    ws0 = _workspace()
    if ws0:
        # resolve each carried item to its statement's canonical SCOPE (REQ-AUD-13 AC6), so a
        # foreign/legacy @id is matched by the scope it addresses, not its literal id spelling
        # (R1 refactor round-1 #5). Keyed by scope, per scope — never CVE-wide.
        prev_id_to_scope = {}
        pv = _read_reviewed_json(os.path.join(ws0, ".vex", "fosterstack-cache.openvex.json"))
        try:
            carried_stmts = list((pv or {}).get("statements", []))
            for s in (pv or {}).get("statements", []):
                if s.get("@id"):
                    prev_id_to_scope[s["@id"]] = _scope_key(s)
                nm = (s.get("vulnerability") or {}).get("name")
                if nm:
                    # every carried (cve, scope) — including a reachability not_affected that has
                    # NO time box — so a pullable fix can lift it (REQ-AUD-2 AC7; REQ-AUD-13 AC3; R1 refactor #4)
                    carried_scopes.add((nm, _scope_key(s)))
                    # the PUBLISHED status for this exact scope, so the "in force (main)" display
                    # tag is only applied when THIS run writes the SAME disposition already on main:
                    # a scope carried as `affected` but re-dispositioned `not_affected` this run
                    # (e.g. new unreachability evidence) is NOT yet published as not_affected, so it
                    # must render "proposed", not "in force (main)" (Codex round-2 residual #3).
                    carried_status[(nm, _scope_key(s))] = s.get("status")
        except Exception as ex:
            raise ReviewedInputInvalid("the published VEX has a statement the run cannot read (%s): it stops rather than guess a partial state" % type(ex).__name__)
        prev = _read_reviewed_json(os.path.join(ws0, ".auditor", "accepted-items.json"))
        try:
            for it in (prev or {}).get("accepted_items", []):
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
        except Exception as ex:
            raise ReviewedInputInvalid("accepted-items.json has an entry the run cannot read (%s): it stops rather than renew or drop a time box" % type(ex).__name__)
    state["not_rechecked"] = _resolve_carried(groups, carried_stmts)      # carried statements no scanner reports: listed in the report, never kept silently
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
            _fp_sid = policy.scope_id(c, policy.VEX_PRODUCT, subs or None)
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
                         "vex_id": _fp_sid, "ignore_files": ["vex"],
                         "carried": _fp_carried, "is_os": True, "sev_by_scanner": _sev_by_scanner(covered),
                         "seen_by_images": _seen_by_images(covered)})
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
    # every per-finding VEX the run wrote is read and validated BEFORE the first owner-decision issue: exit 3 never
    # follows a mutating call (cache#701 ruling F3/B3)
    _collect_vex(out, ts)
    # ...and so is the delivery base: ONE fetch of origin/main, its two reviewed files read at that sha, before any gh
    # call (cache#708 ruling 1); the delivery cuts its branch from this sha
    base_sha = base_err = None
    if not dry and not os.environ.get("AUDITOR_GIT_SHIM_LOG") and _real_gh_allowed() and (m.get("provenance") or {}).get("source") != "test-image":
        base_sha, base_err = _fetch_base(_workspace())
        if base_sha:
            _base_docs(_workspace(), base_sha)
    if adjudicator_down:
        n = len(adj_unavailable)
        ids = ", ".join(sorted({r["id"] for r in adj_unavailable}))
        title = policy.subject("owner-decision: adjudicator unavailable — findings unassessed")      # stable, so the next run finds and updates this issue (REQ-AUD-9 AC2); the count is in the body
        body = ("The adjudicator was unavailable this run: %d finding(s) could not be assessed "
                "(primary/rephrase/fallback all failed). Cause: %s. The run is INCOMPLETE; no "
                "disposition was inferred for these findings. Findings: %s"
                % (n, adj_cause, ids[:1500]))
        ok, ref = _emit_owner_issue(title, body, dry, would, cves=[r["id"] for r in adj_unavailable],
                                    target="adjudicator unavailable — findings unassessed")
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
    # (a2) "a five-iteration stop" (REQ-AUD-9 AC3, register row 38): findings left unsettled by the model in policy.UNSETTLED_RUNS consecutive runs are named in ONE owner-decision
    # issue, never one per finding. The title is stable (the next run updates the open issue, AC2); the findings and their run counts are in the body.
    state["unsettled_counts"] = nochange.advance(state["unsettled_prev"], state["unsettled_now"], today)
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
        ok, ref = _emit_owner_issue(title, body, dry, would, cves=[cve], target="%s — %s" % (cve, pkg))
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
    # (a3) the five-iteration stop's aggregate issue, emitted AFTER the per-finding escalations above so it names only the findings that are in no owner-decision issue this run (the
    # outage issue and the per-finding issues already carry the others). The counts above still advance for every unsettled finding.
    _in_issue = {r["id"] for r in rows if r.get("owner_issue") or r.get("issue_failed") or r.get("adjudicator_error")}
    _stuck = [x for x in nochange.at_limit(state["unsettled_counts"], policy.UNSETTLED_RUNS) if x[0] not in _in_issue]
    if _stuck:
        title = policy.subject("owner-decision: the model left findings unsettled for %d consecutive runs" % policy.UNSETTLED_RUNS)
        body = ("The adjudicator left %d finding(s) without a disposition in %d or more consecutive runs (primary, rephrase and fallback without a settled answer, or no answer at all). "
                "No disposition was inferred; each stays open for a human decision. Findings (consecutive runs): %s"
                % (len(_stuck), policy.UNSETTLED_RUNS, ", ".join("%s (%d)" % x for x in _stuck)[:1500]))
        ok, ref = _emit_owner_issue(title, body, dry, would, cves=[x[0] for x in _stuck], target="unsettled for %d consecutive runs on %d finding(s)" % (policy.UNSETTLED_RUNS, len(_stuck)))
        state["unsettled_issue"] = ref if ok else "FAILED"
    # a failed owner escalation (POA&M at-threshold, or §4 unassessed-after-fallback) is a
    # real gap: the required human decision was not delivered (R1 outer round-1 #4/#5).
    issue_failures = sum(1 for r in rows if r.get("issue_failed")) + (1 if state.get("unsettled_issue") == "FAILED" else 0)
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
    # Inventory quorum (scanner-panel rule 3, 0600 option A): the panel decides whether an image counts (at least three scanners ran
    # on it); the auditor takes that decision, it does not recompute OS-package agreement (Google scans amd64 only, so its counts
    # differ). An unknown verdict (None) can never be a quorum.
    st = m.get("scanner_status") or {}
    SCN = _scanners(m)
    pn = m.get("panel") or {}
    # completion comes from the VERDICT, re-read and re-validated here, never from the manifest's copied summary lists: a manifest
    # that says "nothing uncounted, no failures" with no (or a different) verdict must not make a complete day
    _vd = _panel_verdict(pn)
    unc = _vd["not_counted"] if _vd else None
    fails = _vd["scanner_failures"] if _vd else None
    ran_image = [s for s in SCN if (st.get(s) or {}).get("ran")]
    not_ran = [s for s in SCN if s not in ran_image]
    # a scanner that did not run where it was expected is a pipeline failure even when every image keeps its quorum (rule 3, and the
    # panel's own exit 2): the day is complete only with every image counted AND no scanner failure
    quorum = isinstance(unc, list) and not unc and isinstance(fails, list) and not fails
    quorum_info = {"agreed": ran_image, "not_ran": not_ran, "uncounted": unc, "scanner_failures": fails,
                   "os_counts": {s: (st.get(s) or {}).get("package_count") or 0 for s in SCN}}
    # consolidate every per-CVE VEX into the canonical suppression files, run the consistency
    # check over THAT layout, then DELIVER the suppressions as one draft PR via the App token
    # (R16). A push/PR failure is AUDIT INCOMPLETE with the git/gh stderr — never "opened".
    supp, nstmt = _consolidate(out, ts)
    consistency = _consistency(out, supp, manifest_path)
    cons_failed = any(p.get("type", "").startswith("consistency-check-") for p in (consistency or {}).get("problems", []))
    is_test = (m.get("provenance") or {}).get("source") == "test-image"
    pr_url, pr_err = _deliver_suppression_pr(out, supp, nstmt, today, m.get("commit"), dry, would, is_test=is_test, base_sha=base_sha, base_err=base_err)
    # Decision 2: the auditor DELIVERS its own Go-module bumps as draft PRs through the App path
    # (go get + go mod tidy, go.mod/go.sum only). Each §1/§3 row carrying a fix_bump gets one
    # draft PR; an unresolvable fixed version stays in §3 (never a broken PR); a git/gh/tidy
    # failure marks the run INCOMPLETE. Base rebuilds are NOT delivered here — they defer to
    # Dependabot's daily docker PR (REQ-AUD-2 AC3). The honest action text is set from the
    # delivery status, replacing the pre-delivery placeholder.
    fix_errs = _deliver_bumps(rows, today, m.get("commit"), dry, would, is_test=is_test)
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
            bits.append("scanner panel quorum not met: " + (
                "the panel's verdict is missing or invalid, so no image counts" if unc is None else
                ("image(s) not counted (fewer than three scanners ran on them): " + ", ".join(unc) if unc else
                 "scanner failure(s): " + ", ".join(quorum_info.get("scanner_failures") or [])))
                + "; did not run: " + (", ".join(not_ran) or "none"))
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
    cli.writej(os.path.join(out, ".auditor", "auditor-state.json"),
               nochange.dump(today, nc_hash, *nochange.settle(state["nc_verdicts"], state["nc_pull"], state["nc_narr"], state.get("nc_incomplete")), state["unsettled_counts"]))
    if state.get("nc_reused"):
        print("daily CVE auditor: no-change inputs — reused %d model verdict(s) from the last run" % state["nc_reused"])
    # REQ-AUD-17 AC2: drive the single standing "needs a human" issue from the same §0 list the
    # report shows — comment it (find-or-create) while §0 is non-empty; close it when §0 is empty.
    needs = _needs_human(rows, sections, dry, pr_url, status, (state or {}).get("unsettled_issue"))
    _supp_ids = (sorted(set(_supp_cves(supp)) | set(_supp_removed(supp)[0])) if pr_url else [])
    _nids = _needs_ids(rows, sections, dry, _supp_ids)
    _standing_ok, _standing_ref = _standing_issue(needs, dry, would, _nids)
    # A failed standing-issue update is a real gap (the daily re-email did not go out): mark the
    # run INCOMPLETE rather than reporting a false success (Codex round-1 P2 blocker).
    if not _standing_ok:
        _sf = "standing needs-a-human issue update failed (%s)" % _standing_ref
        status = ("AUDIT INCOMPLETE: " + _sf) if "INCOMPLETE" not in status else (status + "; " + _sf)
        complete = False                                  # fail the job, not a false success
    state = dict(state or {}); state["standing_issue"] = {"ref": _standing_ref, "needs": len(needs),
                                                          "cves": _nids, "supp_cves": _supp_ids}
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
            return reviewed.read(cj)       # a result without "problems" and "consistent" is not a clean check
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


_PROP_KEYS = {"kind", "package", "keys", "note", "evidence"}
_PROP_REQUIRED = {"kind", "evidence", "note"}
_PROP_KEY_KEYS = {"scanner", "finding_id", "purl"}
_PROP_MAX = 2000
# lookalike letters (Cyrillic, Greek) folded to Latin, so a vendor name written with one of them is still a vendor name
_LOOKALIKE = str.maketrans({"\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0441": "c", "\u0440": "p", "\u0456": "i", "\u0455": "s", "\u0443": "y", "\u0445": "x", "\u0501": "d",
                            "\u03bf": "o", "\u03bd": "v", "\u03b9": "i", "\u03c1": "p", "\u03b1": "a", "\u03b5": "e", "\u03ba": "k", "\u043d": "h", "\u0442": "t", "\u043c": "m"})


def _fold(x):
    """NFKC, format characters (zero-width and the like) removed, lookalikes folded, lower-cased."""
    import unicodedata
    y = unicodedata.normalize("NFKC", x)
    y = "".join(c for c in y if unicodedata.category(c) not in ("Cf", "Cc") or c in "\n\t")
    return y.lower().translate(_LOOKALIKE)


_FORBIDDEN_LITERALS = [re.sub(r"[^a-z0-9]", "", w.lower()) for w in FORBIDDEN_NAMES.pattern.split("|")]       # the same names with every separator removed


def _split_across(lit, squashed):
    """True when `lit` can be read off the squashed fields laid end to end in SOME order: a suffix of one field, then whole fields, then a prefix of another. A field may be
    reused, which makes the search a walk over positions in `lit` (at most len(lit) x fields steps, never exponential) and only widens what is refused: fail-closed (it may refuse
    an innocent proposal, never pass a split name)."""
    fields = [f for f in set(squashed) if f]
    reach = set()
    for f in fields:
        for a in range(len(f)):
            suf = f[a:]
            if len(suf) < len(lit) and lit.startswith(suf):
                reach.add(len(suf))
    seen = set(reach)
    while reach:
        pos = reach.pop()
        r = lit[pos:]
        for f in fields:
            if f.startswith(r):
                return True
            if r.startswith(f) and pos + len(f) not in seen:
                seen.add(pos + len(f)); reach.add(pos + len(f))
    return False


def _scrubbed_all(texts):
    """True when no string, taken alone, joined with the others, or split across them in any order (separators removed), holds a vendor/model name or any configured model
    identifier of this run (row 48: the public repo names none). No minimum length for the configured identifiers. A character outside ASCII after folding refuses the proposal."""
    folded = [_fold(t) for t in texts]
    if any(not f.isascii() for f in folded):
        return False                                               # fail closed: a letter outside ASCII after folding cannot be judged a lookalike or not
    squashed = [re.sub(r"[^a-z0-9]", "", f) for f in folded]
    joined = "".join(squashed)
    cfg = [re.sub(r"[^a-z0-9]", "", _fold(v)) for k, v in os.environ.items() if k.startswith("AUDITOR_MODEL") and v and v.strip()]
    lits = [w for w in _FORBIDDEN_LITERALS if w] + [c for c in cfg if c]
    if any(FORBIDDEN_NAMES.search(h) for h in folded + [" ".join(folded)]) or any(w in sq for w in lits for sq in squashed + [joined]):
        return False
    return not any(_split_across(w, squashed) for w in lits)


def _valid_proposal(pr):
    """A model-proposed defect-log/knowledge entry, validated by SHAPE (rc-5b R4; REQ-AUD-17 AC4 "code validation"): the keys are within kind/package/keys/note/evidence and
    kind and evidence are present; kind is defect_log|knowledge; evidence a non-empty string; the other fields strings (keys: a list of objects with exactly scanner, finding_id
    and purl, all strings); each at most 2000 characters; and no string, alone or joined with the others, names a vendor or model. Anything else returns None: the proposal
    is refused (and counted), never forwarded, and the run goes on."""
    if not isinstance(pr, dict) or set(pr) - _PROP_KEYS or _PROP_REQUIRED - set(pr) or pr.get("kind") not in ("defect_log", "knowledge"):
        return None
    ev = pr.get("evidence")
    if not isinstance(ev, str) or not ev.strip():
        return None
    texts = [pr["kind"], ev]
    if not isinstance(pr["note"], str) or not pr["note"].strip():
        return None
    for k in ("package", "note"):
        if k in pr:
            if not isinstance(pr[k], str):
                return None
            texts.append(pr[k])
    if pr["kind"] == "defect_log" and not pr.get("keys"):
        return None                                                # a defect-log entry names the findings it is about
    if "keys" in pr:
        if not isinstance(pr["keys"], list) or len(pr["keys"]) > 20:
            return None
        for kk in pr["keys"]:
            if not isinstance(kk, dict) or set(kk) != _PROP_KEY_KEYS or not all(isinstance(v, str) for v in kk.values()):
                return None
            texts += [kk["scanner"], kk["finding_id"], kk["purl"]]
    if any(len(t) > _PROP_MAX for t in texts) or not _scrubbed_all(texts):
        return None
    return pr


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


def _narrative_structured(sections, m):
    st = m.get("scanner_status") or {}
    return {"image": (m.get("candidate_digests") or {}).get("production"),
            "package_counts": {s: (st.get(s) or {}).get("package_count") for s in _scanners(m)},
            "sections": {C.TITLES[n]: [r["id"] for r in sections[n]] for n in range(1, 8)}}


def _narrative_key(sections, m):
    """the key of a narrative: exactly the structured record the model is given. That record carries no commit: a new commit that
    changes no finding is still a no-change day (REQ-AUD-3 AC3), and the narrative never needed one."""
    return nochange.call_key("narrative", _narrative_structured(sections, m))


def _conclusion(adjudicator, sections, m, state=None):
    if "stub" in os.path.basename(adjudicator or "").lower():
        return "stub: no narrative — §4 reflects the stub, not the model. The real picture needs the real adjudicator on main."
    nc_key = _narrative_key(sections, m)
    prev = nochange.narrative((state or {}).get("nc_prev"), nc_key)
    if prev is not None and _narrative_ok(prev[0], sections):     # yesterday's text, still consistent with today's record
        state["nc_narr"] = {"key": nc_key, "text": prev[0], "date": prev[1]}
        state["nc_reused"] = state.get("nc_reused", 0) + 1
        return "%s\n\n(unchanged since %s)" % (prev[0], prev[1])
    if state and state.get("tokens", 0) >= policy.TOKEN_BUDGET:
        state["nc_incomplete"] = True
        return "conclusion withheld: token budget reached before the narrative."
    structured = _narrative_structured(sections, m)
    try:
        ans = cli.ask_model(adjudicator, "CONCLUSION", attempt="narrative", model="primary",
                            context={"mode": "narrative", "structured": structured})
        text = (ans.get("narrative") or "").strip()
        if state is not None:
            state["tokens"] += int(ans.get("token_usage") or 0)   # narrative counts against the budget too
            state.setdefault("roles_used", set()).add("primary")
    except cli.Refused as e:
        if state is not None:                                      # a refusal is billed and logged like any other (REQ-AUD-8 AC3)
            state["tokens"] += int(getattr(e, "token_usage", 0) or 0)
            state.setdefault("roles_used", set()).add("primary")
            state.setdefault("refusals", []).append({"finding_id": "CONCLUSION", "attempt": "narrative", "role": "primary"})
            state["nc_incomplete"] = True                          # REQ-AUD-3 AC3: a refused narrative is an attempted call without a cacheable result
        return "conclusion withheld: the narrative could not be produced this run."
    except Exception:
        # Never echo the exception text into the report: it can carry the model id from an
        # SDK error. A generic withheld line only.
        if state is not None:
            state["nc_incomplete"] = True
        return "conclusion withheld: the narrative could not be produced this run."
    if not text or not _narrative_ok(text, sections):
        if state is not None:
            state["nc_incomplete"] = True
        return "conclusion withheld: narrative disagreed with the record."
    if state is not None:
        state["nc_narr"] = {"key": nc_key, "text": text, "date": state.get("nc_today") or "1970-01-01"}
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
    PARSERS = [(sc, (lambda p, sc=sc: P.parse_panel(p, sc))) for sc in P.PANEL_SCANNERS]
    lines = []
    for name, fn in PARSERS:
        info = st.get(name) or {}
        path = (m.get("panel") or {}).get("verdict")      # a partial miss keeps the findings the scanner did report
        pc = info.get("package_count"); fc = info.get("findings")
        pre = err = None
        if path:                                    # the verdict has no per-scanner findings count: it is what the scanner's own records number
            try:
                pre = fn(path); fc = len(pre)
            except Exception as e:
                err = e
        title = "%s — %s packages, %s findings" % (name, pc if pc is not None else "?", fc if fc is not None else "?")
        lines.append("::group::" + title)
        if not path:
            lines.append("  did not inventory: %s" % info.get("reason", "no report"))
            lines.append("::endgroup::"); continue
        if not info.get("ran"):
            lines.append("  did not run (%s); what it did report follows" % info.get("reason", "no report"))
        try:
            if err:
                raise err
            findings = pre if pre is not None else fn(path)
        except Exception as e:
            findings = []; lines.append("  (could not parse report: %s)" % e)
        if not findings:
            if not info.get("ran"):                # a scanner that did not run has no "clean": it only reported nothing
                lines.append("  no findings reported; scan incomplete (did not run: %s)" % info.get("reason", "no report"))
            else:
                lines.append("  clean — no findings")
            lines.append("::endgroup::"); continue
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


def _needs_ids(rows, sections, dry, supp_ids=()):
    """The advisory ids behind §0 (same row conditions as _needs_human): the CVEs the standing
    'needs a human' issue carries."""
    ids = set()
    for r in rows:
        if (r.get("owner_issue") and r.get("owner_issue") not in ("dry", "skipped")) or r.get("issue_failed") \
                or r.get("adjudicator_error"):
            ids.add(r["id"])
    if not dry:
        ids |= {r["id"] for r in (sections[1] + sections[3]) if r.get("fix_pr_url")}
        ids |= set(supp_ids)                  # §0 names the suppression draft PR awaiting merge
    return sorted(ids)


def _needs_human(rows, sections, dry, pr_url, status, unsettled_issue=None):
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
    if unsettled_issue == "FAILED":
        needs.append("owner-decision issue FAILED to open: findings unsettled for %d consecutive runs" % policy.UNSETTLED_RUNS)
    elif unsettled_issue and unsettled_issue not in ("dry", "skipped"):
        needs.append("owner-decision needed: findings unsettled for %d consecutive runs — %s" % (policy.UNSETTLED_RUNS, unsettled_issue))
    if "INCOMPLETE" in status:
        needs.append("run INCOMPLETE — %s" % status.split("INCOMPLETE:", 1)[-1].strip()[:240])
    return list(dict.fromkeys(needs))


def _standing_issue(needs, dry, would, cves=()):
    """The single standing 'needs a human' issue (REQ-AUD-17 AC2): created once and commented
    every run whose §0 is non-empty (listing §0, so an unanswered item re-emails daily); closed
    by the first run that finds §0 empty. Uses the JOB token (issues:write), the same shim/dry/
    real-gh contract as _emit_owner_issue."""
    title = policy.STANDING_ISSUE_TITLE
    body = ("The daily CVE auditor needs a human on %d item(s) this run:\n- %s\n\nThis issue "
            "re-comments every run while any item is open, and closes automatically on the first "
            "run with nothing waiting." % (len(needs), "\n- ".join(_text(x) for x in needs))) if needs else None
    if dry:
        _plan(would, "standing issue", ("%s — comment (%d item(s))" % (title, len(needs))) if needs
              else ("%s — close if open" % title), cves,
              cmd=("gh issue comment/create --title %s" if needs else "gh issue close --title %s (if open)")
              % shlex.quote(title))
        return True, "dry"
    log = os.environ.get("AUDITOR_GIT_SHIM_LOG")
    if log:
        prior = open(log).read() if os.path.exists(log) else ""
        if needs:
            if ("issue create --title %s" % shlex.quote(title)) in prior:
                open(log, "a").write("gh issue comment --title %s --body %s\n" % (shlex.quote(title), shlex.quote(body)))
                return True, "shim-commented"
            open(log, "a").write("gh issue create --title %s --label %s --assignee %s --body %s\n"
                                 % (shlex.quote(title), policy.OWNER_LABEL, policy.OWNER_LOGIN, shlex.quote(body)))
            return (not os.environ.get("AUDITOR_SHIM_ISSUE_FAIL")), ("shim-created" if not os.environ.get("AUDITOR_SHIM_ISSUE_FAIL") else None)
        open(log, "a").write("gh issue close --title %s\n" % shlex.quote(title))
        return True, "shim-closed"
    if not _real_gh_allowed():
        print("would %s standing issue (real gh disabled): %s" % ("update" if needs else "close", title))
        if needs:
            _plan(would, "standing issue", "%s — comment (%d item(s))" % (title, len(needs)), cves, note="not delivered: delivery disabled (no authorized delivery step)")
        return True, "skipped"
    ienv = dict(os.environ)
    ienv["GH_TOKEN"] = os.environ.get("AUDITOR_ISSUES_TOKEN") or os.environ.get("GH_TOKEN", "")

    def _sh(*a):
        return subprocess.run(["gh", "issue", *a], capture_output=True, text=True, env=ienv)
    # Discover across ALL states so the standing issue is CREATED ONCE (a closed one is reopened,
    # never re-created) and a FAILED discovery is a real failure, never a silent success.
    r = _sh("list", "--search", title, "--state", "all", "--limit", "100", "--json", "number,state,title")
    if r.returncode != 0:
        return False, "standing-issue discovery failed: %s" % _mask((r.stderr or "").strip())
    try:
        found = [x for x in json.loads(r.stdout or "[]") if x.get("title") == title]
    except Exception as e:
        return False, "standing-issue discovery parse failed: %s" % _mask(str(e))
    openrows = [x for x in found if str(x.get("state", "")).upper() == "OPEN"]
    closedrows = [x for x in found if str(x.get("state", "")).upper() == "CLOSED"]
    if needs:
        if openrows:
            c = _sh("comment", str(openrows[0]["number"]), "--body", body)
            return (c.returncode == 0), ("commented:%s" % openrows[0]["number"] if c.returncode == 0
                                         else "standing comment failed: %s" % _mask((c.stderr or "").strip()))
        if closedrows:                                   # reopen the SAME issue — created once
            n = str(closedrows[0]["number"])
            ro = _sh("reopen", n); c = _sh("comment", n, "--body", body)
            ok = ro.returncode == 0 and c.returncode == 0
            return ok, ("reopened:%s" % n if ok else "standing reopen/comment failed")
        subprocess.run(policy.label_create_cmd(policy.OWNER_LABEL), capture_output=True, text=True, env=ienv)  # create the label first (not forced)
        cr = _sh("create", "--title", title, "--label", policy.OWNER_LABEL, "--assignee", policy.OWNER_LOGIN, "--body", body)
        return (cr.returncode == 0), ("created" if cr.returncode == 0 else "standing create failed: %s" % _mask((cr.stderr or "").strip()))
    ok = True
    for x in openrows:
        c = _sh("close", str(x["number"]), "--comment", "Nothing needs a human this run; closing the standing issue.")
        ok = ok and (c.returncode == 0)
    if not openrows:
        return True, "none-open"
    nums = ",".join(str(x["number"]) for x in openrows)
    return ok, (("closed:%s" if ok else "close-failed:%s") % nums)


def _render(m, rows, sections, would, status, dry, adjudicator, consistency, fs_hash, conclusion, pr_url=None, pr_err=None, quorum_info=None, state=None):
    st = m.get("scanner_status") or {}
    test = (m.get("provenance") or {}).get("source") == "test-image"
    digest = (m.get("candidate_digests") or {}).get("production", "unknown")
    what = ("TEST IMAGE %s (dispatch override)" % (m.get("test_image") or digest)) if test \
        else ("candidate production %s commit %s" % (digest, m.get("commit")))
    ran_lines = []; notrun_lines = []; down_ac2 = []
    reports = m.get("scanner_reports") or {}
    for s in _scanners(m):
        info = st.get(s) or {}
        pc = info.get("package_count")
        ran = bool(info.get("ran")) and (info.get("package_count") or 0) > 0
        if reports.get(s) and ran:
            ran_lines.append("%s ran on %s of %s images, %s packages" % (s, info.get("images_ran"), info.get("images_expected"), pc))
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
    L += ["# Daily CVE auditor report", "", "## Conclusion", "", _text(conclusion), "",
          "## Run header", "", "**Audited:** %s" % what]
    L.append("**Scanners:** " + "; ".join(ran_lines) if ran_lines else "**Scanners:** none inventoried")
    if notrun_lines:
        L.append("**Did not run:** " + "; ".join(notrun_lines))
    if (state or {}).get("not_rechecked"):       # a carried statement no scanner reports this run (our VEX hides it from every scanner): kept as it is, never re-judged, and said so
        L.append("**Not re-checkable (hidden from all scanners):** " + ", ".join(state["not_rechecked"]))
    # each scanner's version and database date (REQ-AUD-7 AC1): what the manifest recorded, else "not recorded by <scanner>" - never a blank
    vparts = []
    for sc_ in _scanners(m):
        info_ = st.get(sc_) or {}
        vparts.append("%s %s, database %s" % (_text(sc_), _text(info_.get("version") or "not recorded by %s" % sc_), _text(info_.get("db_date") or "not recorded by %s" % sc_)))
    L.append("**Scanner versions:** " + "; ".join(vparts))
    # the model's refusals and loop stops this run (REQ-AUD-8 AC3 "logging every refusal"): finding, attempt, role - no model identifier. Both lines print the FULL count; the
    # list is capped at 60 entries and says so.
    _refs = (state or {}).get("refusals") or []
    _stops = (state or {}).get("stopped") or []
    L.append("**Model refusals:** " + (("%d: " % len(_refs)) + "; ".join("%s (%s, %s)" % (_text(x["finding_id"]), x["attempt"], x["role"]) for x in _refs[:60]) + ("; ..." if len(_refs) > 60 else "") if _refs else "none"))
    if _stops:
        L.append("**Model stops:** %d: " % len(_stops) + "; ".join("%s (%s)" % (_text(x["finding_id"]), x["why"]) for x in _stops[:60]) + ("; ..." if len(_stops) > 60 else ""))
    # the unsettled-run counts (REQ-AUD-9 AC3): a missing state is said, never silent
    _uc = (state or {}).get("unsettled_counts") or {}
    if (state or {}).get("counter_status") == "missing":
        L.append("**Unsettled-run counts:** counter state missing, counts restart")
    elif _uc:
        L.append("**Unsettled-run counts:** %d finding(s) unsettled, longest %d consecutive run(s)" % (len(_uc), max(v["runs"] for v in _uc.values()))
                 + ("; owner-decision issue: %s" % _text(str((state or {}).get("unsettled_issue"))) if (state or {}).get("unsettled_issue") else ""))
    # Inventory quorum honesty (scanner-panel rule 3): which images counted, which scanners ran everywhere, which did not run.
    qi = quorum_info or {}
    agreed = qi.get("agreed") or []
    noinv = qi.get("not_ran") or [s for s in _scanners(m) if s not in agreed]
    unc = qi.get("uncounted")
    parts = ["scanner panel (rule 3: an image counts when at least three scanners ran on it): " + (
             "the verdict is missing or invalid, no image counts" if unc is None else
             ("every image counted" if not unc else "not counted: " + ", ".join(unc)))]
    parts.append("ran everywhere: " + (", ".join(agreed) or "none"))
    if noinv:
        parts.append("did not run: " + ", ".join("%s (%s)" % (s, (st.get(s) or {}).get("reason", "no report")) for s in noinv))
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
             ("yes" if dry else "no", _text(adj_field), _text(model_ran), tok))
    probs = (consistency or {}).get("problems", [])
    L.append("**Consistency:** %s   **Finding-set hash:** `%s`" % ("clean" if not probs else "%d problems" % len(probs), fs_hash))
    L.append("")
    L.append("**%s**" % _text(status))
    L.append("")
    ctx = {"n": 0, "p": max([(st.get(s) or {}).get("package_count") or 0 for s in _scanners(m)] + [0]),
           "k": sum(1 for s in _scanners(m) if (st.get(s) or {}).get("ran")),
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
            line = re.sub(r"vex: `https?://[^`]*?(#stmt-[^`]+)`", r"vex: `\1`", line)
            line = re.sub(r"vex: https?://[^\s]*?(#stmt-[^\s]+)", r"vex: \1", line)
        return line + " — status: " + tag

    def _emit(title, rows_, empty, tagged=False, sub=None, downnote=False):
        L.append("## " + title); L.append("")
        if sub is not None:
            for subtitle, subrows in sub:
                L.append("**%s**" % subtitle); L.append("")
                if subrows:
                    for x in _unique([_tagged(r) if tagged else _row_line(r) for r in subrows]):
                        L.append("- " + x)
                else:
                    L.append("None.")
                L.append("")
            return
        if rows_:
            for x in _unique([_tagged(r) if tagged else _row_line(r) for r in rows_]):
                L.append("- " + x)
        else:
            sentence = empty
            if downnote and ctx.get("down"):
                sentence += " Not a complete assessment: %s did not run." % ctx["down"]
            L.append(sentence)
        L.append("")

    # PRs and issues this run — above the sections (AC1): one line per PR/issue, never per finding.
    L.append("## PRs and issues this run"); L.append("")
    is_test = (m.get("provenance") or {}).get("source") == "test-image"
    for x in _pr_list(would, rows, sections, dry, pr_url, pr_err, is_test, (state or {}).get("standing_issue")):
        L.append("- " + x)
    L.append("")

    # §0 Needs a human (AC2): owner items awaiting acceptance, draft PRs awaiting merge, and
    # failures that made the run INCOMPLETE — duplicated from the sections below.
    needs = _needs_human(rows, sections, dry, pr_url, status, (state or {}).get("unsettled_issue"))
    L.append("## 0. Needs a human"); L.append("")
    for x in (_unique([_text(n) for n in needs]) or ["Nothing needs a human this run."]):
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
    except nochange.CounterInvalid as e:
        print("daily CVE auditor: unsettled-run counts invalid, the run stops — %s" % e)
        return 3
    except DefectLogInvalid as e:
        print("daily CVE auditor: known-defect log invalid — %s" % e)
        return 3
    except ReviewedInputInvalid as e:
        print("daily CVE auditor: a reviewed input is unreadable, the run stops — %s" % e)
        return 3
    except ValueError as e:
        print("daily CVE auditor: manifest invalid — %s" % e)
        return 3
    finally:
        cli.close_adjudicators()       # shut the run's single adjudicator client process down
    print("daily CVE auditor: dry_run=%s, out=%s" % (dry, out))
    return 0 if complete else 1        # AUDIT INCOMPLETE fails the job (R13 item 3)


if __name__ == "__main__":
    sys.exit(main())
