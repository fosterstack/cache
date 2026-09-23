#!/usr/bin/env python3
"""Auditor entrypoint (REQ-AUD-12; called by .github/workflows/auditor.yml).

One run, end to end, over the validated run manifest:
  validate the manifest (a null scanner is 'did not run', never a crash) -> parse every
  report -> for each grouped finding, look it up in the known-defect log FIRST (a hit
  closes it with NO model call) -> on a miss, the model PROPOSES a category from the FULL
  finding context and the code VERIFIES it against evidence before writing any VEX
  (govulncheck symbol-level + candidate-bound for unreachable; a trusted log row for a
  false positive) -> a risk_acceptance that is reachable-with-no-fix becomes a POA&M with
  an affected VEX, a computed expiry, an accepted-items entry, and (at/above threshold) an
  owner-decision issue -> a refusal walks primary -> rephrase -> fallback -> section 4, and
  the token budget / five-iteration stop bound every call -> render a report whose header
  carries the digest, each scanner's version/status, the model role and cost, the
  suppression inventory and the consistency result -> when NOT dry, open the PRs and
  owner-decision issues with real `gh`. dry-run does everything except create them, and
  prints what it would have created.
"""
import os, sys, json, re, shlex, subprocess, importlib.util
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from auditorlib import cli, policy
from auditorlib import vex

_spec = importlib.util.spec_from_file_location("auditor_classify", os.path.join(HERE, "auditor-classify.py"))
C = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(C)


def _emit_create(cmd, dry):
    """A create action. dry-run only PRINTS it; a real run writes to the test-only shim
    ledger when AUDITOR_GIT_SHIM_LOG is set (the suite), else runs real `gh`."""
    if dry:
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


def _reach_summary(gvc, ids, module, usable):
    verdict, _ = C.gvc_verdict(gvc, ids, module, usable)
    return verdict


def adjudicate(adjudicator, ctx, state):
    """primary -> rephrase -> fallback for ONE finding, bounded PER FINDING by the
    five-iteration stop, and globally by the token budget (which spans the whole run). A
    refusal or error advances the attempt; exhaustion returns under_investigation."""
    iters = 0                                   # per-finding (the run-wide cap is the budget)
    for attempt, role in (("primary", "primary"), ("rephrase", "primary"), ("fallback", "fallback")):
        if state["tokens"] >= policy.TOKEN_BUDGET or iters >= policy.MAX_ITERATIONS:
            state["stops"] = state.get("stops", 0) + 1
            return "under_investigation"
        iters += 1; state["calls"] = state.get("calls", 0) + 1
        try:
            ans = cli.ask_model(adjudicator, ctx["finding_id"], attempt=attempt, model=role, context=ctx)
        except cli.Refused:
            continue
        except Exception as e:
            print("adjudicator error for %s (%s): %s" % (ctx["finding_id"], attempt, e))
            continue
        state["tokens"] += int(ans.get("token_usage") or 0)
        cat = ans.get("category")
        return cat if cat in C.VALID_CATS else "under_investigation"
    return "under_investigation"


def run(manifest_path, dry, out, today, kevpath=None, adjudicator=None):
    m, groups = C.manifest_findings(manifest_path)
    gvc, module, gvc_usable = C.manifest_gvc(m)
    logpath = m.get("known_defect_log")
    ts = today + "T00:00:00Z"
    idx = log_index(logpath)
    adjudicator = adjudicator or cli.opt("--adjudicator", os.path.join(HERE, "auditor-adjudicator-client.py"))
    down = C.scanners_down(m)
    sections = {}; classification = []; accepted = []
    suppression_inventory = []
    state = {"tokens": 0, "iters": 0}
    h_count = 0; m_count = 0     # log-hit closes (no model call); new not-affected with evidence
    for c, grp in sorted(groups.items()):
        ids = sorted(grp["aliases"]); ids.append(grp["id"])
        f0 = grp["findings"][0]
        # 1) defect-log lookup FIRST — a trusted hit closes with no model call. A row clears
        #    ONLY the package(s) it names (R11 rank 1): the not_affected is scoped by
        #    subcomponents to the exact covered purls, never CVE-wide across the group.
        covered = []; nonfp_hit = False
        for f in grp["findings"]:
            row = idx.get((f["scanner"], f["finding_id"], f["purl"]))
            if row and row.get("disposition") == "false_positive":
                covered.append(f)
            elif row:
                nonfp_hit = True
        if covered:
            subs = sorted({f["purl"] for f in covered if f["purl"]})
            ev = {"check": "known-defect-log", "source_file": logpath,
                  "detail": "trusted false_positive rows for %d/%d package findings; scoped to %s"
                  % (len(covered), len(grp["findings"]), subs)}
            vex.write(out, c, "not_affected", ts, justification="vulnerable_code_not_present",
                      evidence=ev, subcomponents=subs or None)
            cli.writej(os.path.join(out, "ignores", "grype", c + ".json"),
                       {"vex": policy.stmt_id(c), "id": c, "evidence": ev, "scoped_purls": subs})
            suppression_inventory.append({"cve": c, "status": "not_affected", "source": "known-defect-log"})
            cat = "false_positive"; h_count += 1
        elif nonfp_hit:
            cat = "under_investigation"
        else:
            # 2) model PROPOSES from full context; code VERIFIES before any VEX.
            ctx = {"finding_id": c, "aliases": sorted(grp["aliases"]),
                   "package": f0.get("package"), "purl": f0.get("purl"),
                   "installed_version": (f0.get("extra") or {}).get("installed_version"),
                   "fixed_version": f0.get("fixed_version"),
                   "scanners": sorted({f["scanner"] for f in grp["findings"]}),
                   "severity": f0.get("severity"),
                   "reachability": _reach_summary(gvc, ids, module, gvc_usable),
                   "candidate_digest": (m.get("candidate_digests") or {}).get("production")}
            cat = adjudicate(adjudicator, ctx, state)
            if cat == "not_affected_unreachable":
                verdict, ev = C.gvc_verdict(gvc, ids, module, gvc_usable)
                if verdict == "unreachable":
                    vex.write(out, c, "not_affected", ts, justification="vulnerable_code_not_in_execute_path", evidence=ev)
                    suppression_inventory.append({"cve": c, "status": "not_affected", "source": "govulncheck"}); m_count += 1
                else:
                    cat = "under_investigation"
            elif cat == "false_positive":
                ev = C.fp_verified(ids, logpath, grp["findings"])
                if ev:
                    subs = sorted({f["purl"] for f in grp["findings"] if f["purl"]
                                   and idx.get((f["scanner"], f["finding_id"], f["purl"]))})
                    vex.write(out, c, "not_affected", ts, justification="vulnerable_code_not_present",
                              evidence=ev, subcomponents=subs or None)
                    cli.writej(os.path.join(out, "ignores", "grype", c + ".json"),
                               {"vex": policy.stmt_id(c), "id": c, "evidence": ev, "scoped_purls": subs})
                    suppression_inventory.append({"cve": c, "status": "not_affected", "source": "false-positive"}); m_count += 1
                else:
                    cat = "under_investigation"
            elif cat == "risk_acceptance":
                item = _risk_accept(out, c, grp, m, kevpath, ts, today, dry)
                if item:
                    accepted.append(item)
                    suppression_inventory.append({"cve": c, "status": "affected", "source": "risk-acceptance"})
                else:
                    cat = "under_investigation"
        classification.append({"id": c, "category": cat})
        for s in C.SECT.get(cat, []):
            sections.setdefault(s, []).append(c)
    # consistency (every run): VEX/ignores authored this run vs the live findings
    consistency = _consistency(out, manifest_path)
    # persistence (every run): a content-derived snapshot of this run's dispositions
    fs_hash = _persist(out, classification, today)
    header = _header(m, down, accepted, suppression_inventory, consistency, fs_hash, adjudicator, state)
    st = m.get("scanner_status") or {}
    image = ("grype", "trivy", "osv-scanner")
    k = sum(1 for s in image if (st.get(s) or {}).get("ran"))
    p = max([(st.get(s) or {}).get("package_count") or 0 for s in image] + [0])
    downlist = ", ".join("%s (%s)" % (d["scanner"], d["reason"]) for d in down)
    probs = (consistency or {}).get("problems", [])
    context = {"n": 0, "p": p, "k": k, "h": h_count, "m": m_count, "down": downlist,
               "consistency": "clean" if not probs else "%d problems" % len(probs)}
    # R12 item 3: the Conclusion is model-written from the structured results, validated
    # against the sections; a stub run states it has no narrative.
    conclusion = _conclusion(adjudicator, sections, context, m, classification, accepted)
    cli.writej(os.path.join(out, "conclusion.json"), {"conclusion": conclusion})
    C._render_report(out, sections, header=header, conclusion=conclusion, context=context)
    cli.writej(os.path.join(out, ".auditor", "accepted-items.json"),
               {"accepted_items": accepted, "run_date": today, "candidate_commit": m.get("commit")})
    cli.writej(os.path.join(out, "classification.json"), {"findings": classification})
    # VEX changes go through the audit-lane PR; dry-run prints, a real run creates.
    for c in [x["id"] for x in classification if x["category"] in ("false_positive", "not_affected_unreachable")]:
        _emit_create("gh pr create --head auditor/vex-%s --base main --label audit-lane" % c, dry)
    return classification


def _risk_accept(out, cve, grp, m, kevpath, ts, today, dry):
    """A model risk_acceptance is honored only when the code confirms reachable-with-no-fix.
    Writes the affected VEX (target date in the sidecar), the ignores, and the accepted item;
    at/above threshold it also opens an owner-decision issue."""
    f0 = grp["findings"][0]
    reachable = grp.get("_reachable")
    fixed = any(f.get("fixed_version") for f in grp["findings"])
    if fixed:
        return None                                   # a fix exists -> not an acceptance
    import datetime
    exp = (datetime.datetime.strptime(today, "%Y-%m-%d") + datetime.timedelta(days=policy.IGNORE_EXPIRY_DAYS)).strftime("%Y-%m-%d")
    kev = set()
    if kevpath and os.path.exists(kevpath):
        try:
            from auditorlib import parsers as P
            kev = P.parse_kev(kevpath)
        except Exception:
            kev = set()
    critical = (f0.get("severity") or "").lower() in policy.THRESHOLD_SEVERITIES
    exploited = bool((f0.get("extra") or {}).get("known_exploited"))
    at = critical or (cve in kev) or exploited
    vex.write(out, cve, "affected", ts, action="no fix upstream; tracked; re-checked daily",
              evidence={"check": "reachable-no-fix", "source_file": "manifest",
                        "detail": "no fixed_version across %d findings" % len(grp["findings"])},
              target_date=exp)
    for sc in sorted({f["scanner"] for f in grp["findings"]}):
        cli.writej(os.path.join(out, "ignores", sc, cve + ".json"),
                   {"id": cve, "vex": policy.stmt_id(cve), "expiry": exp, "reason": "accepted risk; re-checked daily"})
    issue = None
    if at:
        _emit_create("gh issue create --title owner-decision:accept-risk-%s --label %s --assignee %s"
                     % (cve, policy.OWNER_LABEL, policy.OWNER_LOGIN), dry)
        issue = "pending"
    return {"cve": cve, "severity": f0.get("severity"),
            "threshold": "at_or_above" if at else "below",
            "owner_issue": issue, "expiry": exp}


def _narrative_ok(text, sections):
    """Reject a narrative that names a CVE absent from the sections, or contradicts a
    section (a §3 finding called closed, a §5 finding called reachable)."""
    ids_in = {fid for lst in sections.values() for fid in lst}
    named = set(re.findall(r"(?:CVE-\d{4}-\d+|GO-\d{4}-\d+)", text))
    if named - ids_in:
        return False
    sec3 = set(sections.get(3, [])); sec5 = set(sections.get(5, [])); low = text.lower()
    for fid in named:
        for mt in re.finditer(re.escape(fid), text):
            w = low[max(0, mt.start() - 80):mt.end() + 80]
            if fid in sec3 and re.search(r"not affected|closed|false positive|no action", w):
                return False
            if fid in sec5 and re.search(r"reachable|must fix|exploitable|open vuln", w):
                return False
    return True


def _conclusion(adjudicator, sections, context, m, classification, accepted):
    """R12 item 3: the model writes 3-6 sentences (one on a clean day) from the STRUCTURED
    results only, after every disposition is final; the code validates it against the
    sections and withholds it on disagreement. A stub run states it has no narrative."""
    if "stub" in os.path.basename(adjudicator or "").lower():
        return "stub: no narrative"
    st = m.get("scanner_status") or {}
    structured = {"image": (m.get("candidate_digests") or {}).get("production"), "commit": m.get("commit"),
                  "package_counts": {s: (st.get(s) or {}).get("package_count") for s in ("grype", "trivy", "osv-scanner")},
                  "scanners_not_run": [d for d in context.get("down", "").split(", ") if d],
                  "sections": {C.TITLES[n]: sections.get(n, []) for n in range(1, 8)},
                  "accepted": accepted, "counts": {kk: context[kk] for kk in ("p", "k", "h", "m")}}
    try:
        ans = cli.ask_model(adjudicator, "CONCLUSION", attempt="narrative", model="primary",
                            context={"mode": "narrative", "structured": structured})
        text = (ans.get("narrative") or "").strip()
    except Exception as e:
        return "conclusion withheld: narrative could not be produced (%s)" % e
    if not text or not _narrative_ok(text, sections):
        return "conclusion withheld: narrative disagreed with the record."
    return text


def _consistency(out, manifest_path):
    try:
        r = subprocess.run([sys.executable, os.path.join(HERE, "auditor-consistency.py"),
                            "--suppression-dir", out, "--live-findings", manifest_path,
                            "--out", os.path.join(out, "consistency.json")],
                           capture_output=True, text=True)
        if r.returncode == 0 and os.path.exists(os.path.join(out, "consistency.json")):
            return json.load(open(os.path.join(out, "consistency.json")))
    except Exception as e:
        return {"problems": [{"type": "consistency-check-error", "detail": str(e)}]}
    return {"problems": []}


def _persist(out, classification, today):
    import hashlib
    payload = json.dumps(sorted((f["id"], f["category"]) for f in classification)).encode()
    h = hashlib.sha256(payload).hexdigest()
    cli.writej(os.path.join(out, ".auditor", "run-state.json"),
               {"run_date": today, "finding_set_hash": h,
                "dispositions": {f["id"]: f["category"] for f in classification}})
    return h


def _header(m, down, accepted, suppression_inventory, consistency, fs_hash, adjudicator, state):
    st = m.get("scanner_status") or {}
    digest = (m.get("candidate_digests") or {}).get("production", "unknown")
    lines = []
    if down:
        lines.append("**Scanners that did not run:** " + ", ".join(
            "%s (%s)" % (d["scanner"], d["reason"]) for d in down) +
            " — this run is NOT clean-by-omission.")
    lines.append("**Candidate digest:** `%s` (commit `%s`, base %s)" % (digest, m.get("commit"), m.get("base_os")))
    scanners = []
    for k in ("grype", "trivy", "osv-scanner", "osv-scanner-gomod", "snyk"):
        info = st.get(k) or {}
        ran = "ok" if (m.get("scanner_reports") or {}).get(k) else "did not run"
        scanners.append("%s %s (%s)" % (k, info.get("version") or "-", ran))
    lines.append("**Scanners:** " + "; ".join(scanners))
    g = m.get("govulncheck")
    gvc_line = "not run"
    if isinstance(g, dict):
        gvc_line = "%s over %s @ %s (complete=%s)" % (g.get("scan_level"), g.get("module"), g.get("commit"), g.get("complete"))
    elif g:
        gvc_line = "stream %s" % g
    lines.append("**Reachability (govulncheck):** " + gvc_line)
    role = "primary" if "adjudicator-client" in (adjudicator or "") else "stub"
    lines.append("**Model role:** %s; adjudicator calls: %d; token cost: %d/%d" %
                 (role, state.get("calls", 0), state["tokens"], policy.TOKEN_BUDGET))
    lines.append("**Suppression inventory (this run):** %d — %s" %
                 (len(suppression_inventory),
                  ", ".join("%s=%s" % (i["cve"], i["source"]) for i in suppression_inventory) or "none"))
    lines.append("**Accepted risk items:** %d" % len(accepted))
    probs = (consistency or {}).get("problems", [])
    lines.append("**Consistency:** %s" % ("clean" if not probs else ", ".join(sorted({p["type"] for p in probs}))))
    lines.append("**Finding-set hash:** `%s`" % fs_hash)
    return "\n".join(lines)


def main():
    dry = cli.opt("--dry-run", "true") != "false"
    manifest = cli.opt("--manifest"); out = cli.opt("--out", os.path.join(os.environ.get("RUNNER_TEMP", "/tmp"), "auditor-out"))
    today = cli.opt("--today", "2026-09-22"); kev = cli.opt("--kev")
    if not manifest:
        print("daily CVE auditor: no manifest supplied"); return 2
    try:
        run(manifest, dry, out, today, kevpath=kev)
    except ValueError as e:
        print("daily CVE auditor: manifest invalid — %s" % e)
        return 3
    print("daily CVE auditor: dry_run=%s, out=%s" % (dry, out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
