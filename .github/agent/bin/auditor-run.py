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
        except Exception as e:
            print("adjudicator error for %s (%s): %s" % (ctx["finding_id"], attempt, e))
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
    rows = []; would = []; h_count = 0; m_count = 0
    for c, grp in sorted(groups.items()):
        ids = sorted(grp["aliases"]); ids.append(grp["id"])
        gf = _group_facts(c, grp)
        row = {"id": c, "package": gf["package"], "installed": gf["installed"], "fixed": gf["fixed"],
               "severity": gf["severity"], "reachability": None, "disposition": None,
               "action": None, "reason": None, "section": None, "needs_action": True}
        # 1) trusted log FP -> closed (§5), no model call.
        covered = [f for f in grp["findings"]
                   if (idx.get((f["scanner"], f["finding_id"], f["purl"])) or {}).get("disposition") == "false_positive"]
        if covered:
            subs = sorted({f["purl"] for f in covered if f["purl"]})
            ev = {"check": "known-defect-log", "source_file": logpath,
                  "detail": "trusted false_positive rows; scoped to %s" % subs}
            vex.write(out, c, "not_affected", ts, justification="vulnerable_code_not_present", evidence=ev, subcomponents=subs or None)
            igf = os.path.join("ignores", "grype", c + ".json")
            cli.writej(os.path.join(out, igf), {"vex": policy.stmt_id(c), "id": c, "evidence": ev, "scoped_purls": subs})
            row.update(section=5, disposition="not_affected (false positive)", action="closed", needs_action=False,
                       reachability="n/a (OS package)", reason="known-defect-log exact-key hit",
                       vex_id=policy.stmt_id(c), ignore_files=[igf, ".snyk", "osv-scanner.toml", "vex"])
            rows.append(row); h_count += 1; continue
        # 2) reachability for Go modules — deterministic govulncheck (no model call).
        if gf["is_go"]:
            verdict, ev = C.gvc_verdict(gvc, ids, module, gvc_usable)
            row["reachability"] = ("govulncheck: %s" % verdict)
            if verdict == "unreachable":
                vex.write(out, c, "not_affected", ts, justification="vulnerable_code_not_in_execute_path", evidence=ev)
                row.update(section=5, disposition="not_affected (unreachable)", action="closed", needs_action=False,
                           reason="govulncheck: imported, not called", vex_id=policy.stmt_id(c),
                           ignore_files=["vex", "evidence"])
                rows.append(row); m_count += 1; continue
        else:
            row["reachability"] = "n/a (OS package)"
        # 3) false-positive suspicion — ONLY for a finding unique to one scanner lineage.
        if len(gf["lineages"]) == 1 and not gf["fixed"]:
            ctx = {"finding_id": c, "aliases": sorted(grp["aliases"]), "package": gf["package"],
                   "purl": grp["findings"][0].get("purl"), "installed_version": gf["installed"],
                   "fixed_version": gf["fixed"], "scanners": sorted({f["scanner"] for f in grp["findings"]}),
                   "severity": gf["severity"], "reachability": row["reachability"],
                   "candidate_digest": (m.get("candidate_digests") or {}).get("production")}
            cat = adjudicate(adjudicator, ctx, state)
            if cat == "false_positive":
                fev = C.fp_verified(ids, logpath, grp["findings"])
                if fev:
                    vex.write(out, c, "not_affected", ts, justification="vulnerable_code_not_present", evidence=fev)
                    row.update(section=5, disposition="not_affected (false positive)", action="closed", needs_action=False,
                               reason="model FP, evidence-verified", vex_id=policy.stmt_id(c),
                               ignore_files=["vex", "evidence"])
                    rows.append(row); m_count += 1; continue
                row.update(section=4, disposition="under investigation", action="none", needs_action=False,
                           reason="model FP without evidence", cause="evidence conflict: no FP evidence")
                rows.append(row); continue
            if cat in ("refused", "unknown"):
                row.update(section=4, disposition="under investigation", action="none", needs_action=False,
                           reason="unique finding, not adjudicated",
                           cause=("stub: no canned answer" if "stub" in os.path.basename(adjudicator).lower()
                                  else "model refused after fallback"))
                rows.append(row); continue
        # 4) deterministic fix routing.
        if gf["fixed"]:
            if gf["is_go"]:
                title = "auditor/bump-%s: %s %s -> %s" % (c, gf["package"], gf["installed"], gf["fixed"])
                _emit_create("gh pr create --head auditor/bump-%s --base main --label auto-merge-lane --title %s"
                             % (c, shlex.quote(title)), dry, would)
                act = ("dry run: would open PR '%s'" % title) if dry else "opened bump PR (auto-merge lane)"
                row.update(section=3, disposition="real, fixable (we build it)", action=act,
                           fixed=gf["fixed"], reason="pullable fix in a module we build")
            else:
                title = "auditor/base-rebuild-%s: base image -> %s (%s)" % (c, gf["fixed"], gf["package"])
                _emit_create("gh pr create --head auditor/base-rebuild-%s --base main --label base-bump --title %s"
                             % (c, shlex.quote(title)), dry, would)
                act = ("dry run: would open PR '%s'" % title) if dry else "opened base-rebuild PR"
                row.update(section=3, disposition="real, fixable (base rebuild)",
                           action=act, fixed="base-image %s" % gf["fixed"],
                           reachability="n/a (OS package)", reason="awaiting base rebuild %s" % gf["fixed"])
            rows.append(row); continue
        # no upstream fix -> POA&M (§2), at/above threshold -> owner issue.
        in_kev = c in kev_ids or bool(set(grp["aliases"]) & kev_ids)
        reason = policy.threshold_reason(gf["severity"], in_kev, gf["known_exploited"])
        at = reason != "below"
        vex.write(out, c, "affected", ts, action="no fix upstream; tracked; re-checked daily",
                  evidence={"check": "reachable-no-fix", "source_file": "manifest", "detail": gf["nofix_reason"]},
                  target_date=exp)
        for sc in sorted({f["scanner"] for f in grp["findings"]}):
            cli.writej(os.path.join(out, "ignores", sc, c + ".json"),
                       {"id": c, "vex": policy.stmt_id(c), "expiry": exp, "reason": "accepted risk; re-checked daily"})
        action = "POA&M: affected VEX + ignores, expiry %s" % exp
        if at:
            it = policy.owner_issue_title(c, gf["package"], reason)
            _emit_create("gh issue create --title %s --label %s --assignee %s"
                         % (shlex.quote(it), policy.OWNER_LABEL, policy.OWNER_LOGIN), dry, would)
            action += ("; dry run: would open issue '%s'" % it) if dry else "; opened owner-decision issue"
        row.update(section=2, disposition="carried (POA&M)", action=action,
                   reason=("%s; %s" % (gf["nofix_reason"], reason)),
                   owner_issue=(reason if at else None))
        rows.append(row)

    # sections + status
    sections = {n: [] for n in range(1, 8)}
    for r in rows:
        sections[r["section"]].append(r)
    accepted = [{"cve": r["id"], "severity": r["severity"], "package": r["package"],
                 "threshold": ("at_or_above" if r.get("owner_issue") else "below"),
                 "owner_issue": r.get("owner_issue"), "expiry": exp}
                for r in sections[2]]
    down = C.scanners_down(m)
    findings_without_action = sum(1 for r in rows if r["section"] in (2, 3) and (not r["action"] or r["action"] == "none"))
    if dry and sections[3] and not would:
        findings_without_action += len(sections[3])
    scanners_not_run = [d for d in down if d["scanner"] in IMAGE_SCANNERS]
    complete = (findings_without_action == 0) and (len(scanners_not_run) == 0)
    status = ("AUDIT COMPLETE" if complete else
              "AUDIT INCOMPLETE: %d findings without an action, %d scanners did not run"
              % (findings_without_action, len(scanners_not_run)))

    consistency = _consistency(out, manifest_path)
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


def _consistency(out, manifest_path):
    try:
        r = subprocess.run([sys.executable, os.path.join(HERE, "auditor-consistency.py"),
                            "--suppression-dir", out, "--live-findings", manifest_path,
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
    except Exception as e:
        return "conclusion withheld: narrative could not be produced (%s)" % e
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
        ran = info.get("ran") if "ran" in info else bool(reports.get(s))
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
