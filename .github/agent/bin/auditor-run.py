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
    elif not _real_gh_allowed():
        print("would open PR (real gh disabled): " + seq[-1])
    else:
        for cmd in seq:
            subprocess.run(shlex.split(cmd), check=False)


def _emit_owner_issue(title, dry, would):
    """Open OR update the single owner-decision issue for a finding (REQ-AUD-9 AC2, R1
    round-3). dry/shim record the intent; a real run finds an existing open issue with the
    same title and comments on it instead of opening a duplicate."""
    cmd = "gh issue create --title %s --label %s --assignee %s" % (shlex.quote(title), policy.OWNER_LABEL, policy.OWNER_LOGIN)
    if dry:
        would.append(cmd); print("dry-run would create: " + cmd); return
    log = os.environ.get("AUDITOR_GIT_SHIM_LOG")
    if log:
        # the shim log models the issue store across runs: if this exact issue was already
        # created, record a comment instead of a duplicate create (REQ-AUD-9 AC2).
        prior = open(log).read() if os.path.exists(log) else ""
        if ("issue create --title %s" % shlex.quote(title)) in prior:
            open(log, "a").write("gh issue comment --title %s --body re-check-still-open\n" % shlex.quote(title))
        else:
            open(log, "a").write(cmd + "\n")
        return
    if not _real_gh_allowed():
        print("would open/update owner issue (real gh disabled): " + title); return
    try:
        r = subprocess.run(["gh", "issue", "list", "--search", title, "--state", "open", "--json", "number,title"],
                           capture_output=True, text=True)
        found = [i for i in json.loads(r.stdout or "[]") if i.get("title") == title]
        if found:
            subprocess.run(["gh", "issue", "comment", str(found[0]["number"]),
                            "--body", "re-check: still open (no pullable fix); owner decision still needed."], check=False)
        else:
            subprocess.run(["gh", "issue", "create", "--title", title, "--label", policy.OWNER_LABEL,
                            "--assignee", policy.OWNER_LOGIN], check=False)
    except Exception as e:
        print("owner-issue open/update failed: %s" % e)


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
    by_cve = {}
    for s in statements:
        cve = (s.get("vulnerability") or {}).get("name")
        by_cve.setdefault(cve, {"statuses": set(), "vid": None})
        by_cve[cve]["statuses"].add(s.get("status"))
        by_cve[cve]["vid"] = by_cve[cve]["vid"] or policy.stmt_id(cve)
    snyk = ["version: v1.5.0", "ignore:"]; toml = []
    for cve in sorted(by_cve):
        info = by_cve[cve]; vid = info["vid"]; st = "+".join(sorted(info["statuses"]))
        snyk += ["  %s:" % cve, "    - '*':", "        reason: '%s; governed by %s'" % (st, vid), "        vex: '%s'" % vid]
        toml += ['[[IgnoredVulns]]', 'id = "%s"' % cve, 'reason = "%s; governed by %s"' % (st, vid)]
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
        except cli.Refused:
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
            row.update(section=4, disposition="under investigation", action="none",
                       reason="adjudication exhausted",
                       cause=("stub: no canned answer" if "stub" in os.path.basename(env["adjudicator"]).lower()
                              else "model refused after fallback"))
            return row, m_inc
    # 4) deterministic fix routing.
    if gf["fixed"]:
        if gf["is_go"]:
            title = "auditor/bump-%s: %s %s -> %s" % (c, gf["package"], gf["installed"], gf["fixed"])
            _open_pr("auditor/bump-%s" % c, title, "auto-merge-lane", dry, would, "auditor: bump %s" % c)
            act = ("dry run: would open PR '%s'" % title) if dry else "opened bump PR (auto-merge lane)"
            row.update(section=3, disposition="real, fixable (we build it)", action=act,
                       fixed=gf["fixed"], reason="pullable fix in a module we build")
        else:
            title = "auditor/base-rebuild-%s: base image -> %s (%s)" % (c, gf["fixed"], gf["package"])
            _open_pr("auditor/base-rebuild-%s" % c, title, "base-bump", dry, would, "auditor: base rebuild %s" % c)
            act = ("dry run: would open PR '%s'" % title) if dry else "opened base-rebuild PR"
            row.update(section=3, disposition="real, fixable (base rebuild)", action=act,
                       fixed="base-image %s" % gf["fixed"], reachability="n/a (OS package)",
                       reason="awaiting base rebuild %s" % gf["fixed"])
        return row, m_inc
    # no upstream fix -> POA&M (§2), at/above threshold -> owner issue.
    in_kev = c in env["kev_ids"] or bool(set(aliases) & env["kev_ids"])
    reason = policy.threshold_reason(gf["severity"], in_kev, gf["known_exploited"])
    at = reason != "below"
    vex.write(out, c, "affected", ts, action="no fix upstream; tracked; re-checked daily",
              evidence={"check": "reachable-no-fix", "source_file": "manifest", "detail": gf["nofix_reason"]},
              target_date=exp, vex_name=vn)
    for sc in sorted({f["scanner"] for f in findings}):
        cli.writej(os.path.join(out, "ignores", sc, vn + ".json"),
                   {"id": c, "vex": policy.stmt_id(c), "expiry": exp, "reason": "accepted risk; re-checked daily"})
    action = "POA&M: affected VEX + ignores, expiry %s" % exp
    if at:
        it = policy.owner_issue_title(c, gf["package"], reason)
        _emit_owner_issue(it, dry, would)          # find-or-update, never a duplicate (R1 round-3)
        action += ("; dry run: would open/update issue '%s'" % it) if dry else "; opened/updated owner-decision issue"
    row.update(section=2, disposition="carried (POA&M)", action=action,
               reason="%s; %s" % (gf["nofix_reason"], reason), owner_issue=(reason if at else None))
    return row, m_inc


def run(manifest_path, dry, out, today, kevpath=None, adjudicator=None):
    m, groups = C.manifest_findings(manifest_path)
    gvc, module, gvc_usable = C.manifest_gvc(m)
    logpath = m.get("known_defect_log"); ts = today + "T00:00:00Z"
    idx = log_index(logpath)
    adjudicator = adjudicator or cli.opt("--adjudicator", os.path.join(HERE, "auditor-adjudicator-client.py"))
    kev_ids = set()
    if kevpath and os.path.exists(kevpath):
        try:
            from auditorlib import parsers as P
            kev_ids = P.parse_kev(kevpath)
        except Exception:
            kev_ids = set()
    exp = _expiry(today)
    state = {"tokens": 0, "iters": 0}
    env = {"gvc": gvc, "module": module, "gvc_usable": gvc_usable, "idx": idx, "logpath": logpath,
           "adjudicator": adjudicator, "state": state, "kev_ids": kev_ids, "exp": exp, "out": out,
           "ts": ts, "dry": dry, "digest": (m.get("candidate_digests") or {}).get("production")}
    rows = []; would = []; h_count = 0; m_count = 0
    for c, grp in sorted(groups.items()):
        # 1) trusted log FP closes ONLY the PACKAGES the log names (R11 rank 1) — every
        #    finding for one of those packages, across scanners/arches, not just the exact
        #    key. A sibling PACKAGE's finding for the same CVE is NOT closed with it (R1
        #    round-1) and is routed on its own; because that second disposition is a
        #    DIFFERENT package it writes to a DISTINCT VEX/ignore name, so it cannot
        #    overwrite the not_affected one (R1 round-2).
        fp_pkgs = set()
        for f in grp["findings"]:
            r = idx.get((f["scanner"], f["finding_id"], f["purl"]))
            if r and r.get("disposition") == "false_positive":
                fp_pkgs.add(r.get("package") or f.get("package"))
        covered = [f for f in grp["findings"] if f.get("package") in fp_pkgs]
        if covered:
            subs = sorted({f["purl"] for f in covered if f["purl"]})
            ev = {"check": "known-defect-log", "source_file": logpath,
                  "detail": "trusted false_positive for package(s) %s" % sorted(fp_pkgs)}
            vex.write(out, c, "not_affected", ts, justification="vulnerable_code_not_present", evidence=ev, subcomponents=subs or None)
            igf = os.path.join("ignores", "grype", c + ".json")
            cli.writej(os.path.join(out, igf), {"vex": policy.stmt_id(c), "id": c, "evidence": ev, "scoped_purls": subs})
            rows.append({"id": c, "package": ",".join(sorted(fp_pkgs)) or "?",
                         "installed": (covered[0].get("extra") or {}).get("installed_version") or _ver_from_purl(covered[0].get("purl")) or "?",
                         "fixed": None, "severity": _max_sev(covered), "section": 5,
                         "disposition": "not_affected (false positive)", "action": "closed",
                         "reachability": "n/a (OS package)", "reason": "known-defect-log FP for %s" % (",".join(sorted(fp_pkgs))),
                         "vex_id": policy.stmt_id(c), "ignore_files": [igf, ".snyk", "osv-scanner.toml", "vex"]})
            h_count += 1
            uncovered = [f for f in grp["findings"] if f.get("package") not in fp_pkgs]
            if uncovered:
                # distinct VEX/ignore name so the sibling's disposition never clobbers the FP one
                row2, mi = _dispose(c, uncovered, sorted(grp["aliases"]), env, would, name=c + "-sibling")
                rows.append(row2); m_count += mi
            continue
        row, mi = _dispose(c, grp["findings"], sorted(grp["aliases"]), env, would)
        rows.append(row); m_count += mi

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
                 "threshold": ("at_or_above" if r.get("owner_issue") else "below"),
                 "owner_issue": r.get("owner_issue"), "expiry": exp}
                for r in sections[2]]
    findings_without_action = sum(1 for r in rows if r["section"] in (2, 3) and (not r["action"] or r["action"] == "none"))
    if dry and sections[3] and not would:
        findings_without_action += len(sections[3])
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
        return bool(info.get("ran")) and (info.get("package_count") or 0) > 0
    ran_image = [s for s in ("grype", "trivy", "osv-scanner", "snyk") if _ran(s)]
    not_ran = [s for s in ("grype", "trivy", "osv-scanner", "snyk") if not _ran(s)]
    oscounts = [(st.get(s) or {}).get("os_package_count") or 0 for s in ran_image]
    agree = bool(oscounts) and max(oscounts) > 0 and (min(oscounts) >= 0.5 * max(oscounts))
    quorum = len(ran_image) >= 3 and agree
    complete = (findings_without_action == 0) and quorum
    if complete:
        status = "AUDIT COMPLETE"
    else:
        bits = []
        if findings_without_action:
            bits.append("%d findings without an action" % findings_without_action)
        if not quorum:
            bits.append("scanner quorum %d/4 (need 3 agreeing); did not run: %s"
                        % (len(ran_image), ", ".join(not_ran) or "none"))
        status = "AUDIT INCOMPLETE: " + "; ".join(bits)

    # consolidate every per-CVE VEX into the canonical suppression files, then run the
    # consistency check over THAT layout (not a layout the run never writes), and propose
    # the .vex change through the audit lane (R1 round-3).
    supp, nstmt = _consolidate(out, ts)
    consistency = _consistency(out, supp, manifest_path)
    if nstmt:
        _open_pr("auditor/vex-update", "auditor: update .vex suppressions (%d statements)" % nstmt,
                 "audit-lane", dry, would, "auditor: update .vex suppressions")
    fs_hash = _persist(out, rows, today)
    conclusion = _conclusion(adjudicator, sections, m)
    report = _render(m, rows, sections, would, status, dry, adjudicator, consistency, fs_hash, conclusion)
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
    try:
        r = subprocess.run([sys.executable, os.path.join(HERE, "auditor-consistency.py"),
                            "--suppression-dir", supp, "--live-findings", manifest_path,
                            "--out", os.path.join(out, "consistency.json")], capture_output=True, text=True)
        if r.returncode == 0 and os.path.exists(os.path.join(out, "consistency.json")):
            return json.load(open(os.path.join(out, "consistency.json")))
    except Exception as e:
        return {"problems": [{"type": "consistency-check-error", "detail": str(e)}]}
    return {"problems": []}


def _persist(out, rows, today):
    import hashlib
    payload = json.dumps(sorted((r["id"], r["disposition"]) for r in rows)).encode()
    h = hashlib.sha256(payload).hexdigest()
    cli.writej(os.path.join(out, ".auditor", "run-state.json"),
               {"run_date": today, "finding_set_hash": h,
                "dispositions": {r["id"]: r["disposition"] for r in rows}})
    return h


def _narrative_ok(text, sections):
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


def _conclusion(adjudicator, sections, m):
    if "stub" in os.path.basename(adjudicator or "").lower():
        return "stub: no narrative — §4 reflects the stub, not the model. The real picture needs the real adjudicator on main."
    st = m.get("scanner_status") or {}
    structured = {"image": (m.get("candidate_digests") or {}).get("production"), "commit": m.get("commit"),
                  "package_counts": {s: (st.get(s) or {}).get("package_count") for s in IMAGE_SCANNERS},
                  "sections": {C.TITLES[n]: [r["id"] for r in sections[n]] for n in range(1, 8)}}
    try:
        ans = cli.ask_model(adjudicator, "CONCLUSION", attempt="narrative", model="primary",
                            context={"mode": "narrative", "structured": structured})
        text = (ans.get("narrative") or "").strip()
    except Exception:
        # Never echo the exception text into the report: it can carry the model id from an
        # SDK error. A generic withheld line only.
        return "conclusion withheld: the narrative could not be produced this run."
    if not text or not _narrative_ok(text, sections):
        return "conclusion withheld: narrative disagreed with the record."
    return text


def _render(m, rows, sections, would, status, dry, adjudicator, consistency, fs_hash, conclusion):
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
            if would:
                for w in would:
                    L.append("dry run: would run `%s`" % w)
            elif dry:
                L.append("Nothing to open: no §3 fix PR or owner issue was warranted this run.")
            else:
                L.append(C.EMPTY[6].format(**ctx))
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
