#!/usr/bin/env python3
# Extracted, testable core of the daily image rescan (.github/workflows/
# daily-rescan.yml): the platform-child enumeration validation, the
# per-child merge/normalization of scanner findings, and the exit-code
# classification that decides the durable statement's verdict.
#
# It lives in bin/ (not inline in the workflow) so the merge/classify/
# enumerate logic can be exercised by bin/rescan-statement-test.sh against
# real CLI-shaped fixtures on every PR, instead of only by an external
# probe. Pure python3 + json — no PyYAML, no network, no gh, no scanners —
# so it runs identically in CI and locally.
#
# Three audit defects this encodes the fix for:
#
#   B04d  Snyk places OS findings at top-level `.vulnerabilities` AND
#         application-dependency findings under `.applications[]
#         .vulnerabilities` (each carrying project context, e.g.
#         `.targetFile`). Both are normalized, and each finding keeps its
#         platform + project so an arm64 application-only finding still
#         reaches the statement and the notification.
#
#   B04e  Completeness is classified from each scanner's OWN exit-code
#         contract, INDEPENDENTLY of whether the JSON parsed. A child that
#         exits with an operational-failure code (Snyk 2/3; Trivy/Grype any
#         nonzero that is not the configured finding code) makes the run
#         incomplete (verdict=error) even when its JSON is well-shaped and
#         even when another child legitimately found a CVE — the finding is
#         still notified, and the run still fails.
#
#   B04f  EVERY expected image descriptor in a multi-platform index must
#         carry a usable `.platform.os`/`.platform.architecture` (not null,
#         empty, or "unknown"). A descriptor without one is only tolerated
#         when it is EXPLICITLY a non-image attestation/referrer descriptor
#         (Docker `vnd.docker.reference.type` attestation annotation, an OCI
#         `artifactType`, or a cosign/in-toto/sbom mediaType). A plain image
#         descriptor missing its platform FAILS the job.
import argparse
import hashlib
import json
import os
import sys

# Each scanner's exit-code contract. `clean` = completed, no findings;
# `finding` = completed WITH findings (the configured finding exit code).
# ANY other nonzero exit is an operational failure, independent of whether
# the tool also managed to emit parseable JSON.
#
#   snyk container test : 0 clean, 1 findings, 2/3 operational failure.
#     https://docs.snyk.io/developer-tools/snyk-cli/commands/container-test
#   trivy image --exit-code 1 : 0 clean, 1 findings, other nonzero = error.
#   grype --fail-on negligible : 0 clean, 1 findings, other nonzero = error.
CONTRACTS = {
    "snyk": {"clean": {0}, "finding": {1}},
    "trivy": {"clean": {0}, "finding": {1}},
    "grype": {"clean": {0}, "finding": {1}},
}


def err(msg):
    """Emit a GitHub-annotated error to stderr."""
    sys.stderr.write("::error::" + msg + "\n")


# --------------------------------------------------------------------------
# B04f — platform-child enumeration validation.
# --------------------------------------------------------------------------

def _platform_usable(platform):
    """A child platform is usable only with a real os AND architecture."""
    if not isinstance(platform, dict):
        return False
    os_ = platform.get("os")
    arch = platform.get("architecture")
    for v in (os_, arch):
        if not isinstance(v, str) or v.strip() == "" or v == "unknown":
            return False
    return True


def _is_non_image_descriptor(desc):
    """True only when a descriptor is EXPLICITLY a non-image
    attestation/referrer (so its missing platform is intentional, not a
    malformed image entry). Everything else is treated as an expected image
    descriptor that MUST carry a usable platform."""
    ann = desc.get("annotations") or {}
    if not isinstance(ann, dict):
        ann = {}
    # Docker BuildKit attestation manifest (SBOM/provenance) child.
    if ann.get("vnd.docker.reference.type") == "attestation-manifest":
        return True
    # OCI referrers artifact descriptor.
    if isinstance(desc.get("artifactType"), str) and desc.get("artifactType"):
        return True
    # cosign signatures/attestations carried in annotations.
    for k in ann:
        if k.startswith("dev.cosign") or k.startswith("vnd.dev.cosign"):
            return True
    mt = desc.get("mediaType") or ""
    if not isinstance(mt, str):
        mt = ""
    mt_l = mt.lower()
    for marker in ("in-toto", "cosign", "vnd.dev.cosign", "spdx", "sbom",
                   "vnd.in-toto"):
        if marker in mt_l:
            return True
    return False


def cmd_enumerate(args):
    try:
        with open(args.index) as fh:
            index = json.load(fh)
    except FileNotFoundError:
        err("index file %s not found — refusing to guess the platform "
            "inventory" % args.index)
        return 1
    except json.JSONDecodeError:
        err("imagetools inspect for %s did not return valid JSON — refusing "
            "to guess the platform inventory" % args.ref)
        return 1

    if not isinstance(index, dict):
        err("%s inspect result is not a JSON object — refusing to guess the "
            "platform inventory" % args.ref)
        return 1

    lines = []
    manifests = index.get("manifests")
    if isinstance(manifests, list):
        # A multi-platform index: EVERY expected image descriptor must carry
        # a usable platform. A descriptor without one is tolerated only when
        # it is explicitly a non-image attestation/referrer; a plain image
        # descriptor missing its platform fails the whole job (B04f).
        for i, desc in enumerate(manifests):
            if not isinstance(desc, dict):
                err("%s: manifest descriptor #%d is not an object — refusing "
                    "to rescan a malformed inventory" % (args.ref, i))
                return 1
            digest = desc.get("digest")
            if _platform_usable(desc.get("platform")):
                p = desc["platform"]
                lines.append("%s/%s\t%s@%s" % (
                    p["os"], p["architecture"], args.repo, digest))
                continue
            if _is_non_image_descriptor(desc):
                # An intentionally-ignored attestation/referrer descriptor.
                continue
            err("%s: image descriptor %s has no usable .platform.os/"
                ".platform.architecture (null, empty, or 'unknown') and is "
                "not an identified attestation/referrer descriptor — refusing "
                "to silently drop an expected platform"
                % (args.ref, digest))
            return 1
        if not lines:
            err("index %s lists no usable platform children (empty, all "
                "'unknown', or only attestation descriptors) — refusing to "
                "rescan an empty inventory" % args.ref)
            return 1
    elif index.get("config") is not None and isinstance(
            index.get("layers"), list):
        # A RECOGNIZED single-image manifest (.config + .layers, not an
        # index): scan it as itself.
        lines.append("index\t%s" % args.ref)
    else:
        err("%s is neither a recognized multi-platform index (.manifests[] "
            "with real platforms) nor a single-image manifest (.config + "
            ".layers) — refusing to guess the platform inventory" % args.ref)
        return 1

    body = "".join(line + "\n" for line in lines)
    if args.out:
        with open(args.out, "w") as fh:
            fh.write(body)
    else:
        sys.stdout.write(body)
    return 0


# --------------------------------------------------------------------------
# B04d — per-child finding normalization (OS + application).
# --------------------------------------------------------------------------

def _shape_ok(scanner, report):
    if not isinstance(report, dict):
        return False
    if scanner == "trivy":
        return isinstance(report.get("Results"), list) \
            or report.get("SchemaVersion") is not None
    if scanner == "grype":
        return isinstance(report.get("matches"), list) \
            and report.get("descriptor") is not None
    if scanner == "snyk":
        return isinstance(report.get("vulnerabilities"), list)
    return False


def _normalize(scanner, report, platform):
    """Normalize a single child's report into a flat finding list, keeping
    the platform and project (targetFile / Target) context on each one."""
    out = []
    if scanner == "trivy":
        for res in report.get("Results") or []:
            target = res.get("Target")
            for v in res.get("Vulnerabilities") or []:
                out.append({
                    "id": v.get("VulnerabilityID"),
                    "severity": (v.get("Severity") or "").lower(),
                    "package": v.get("PkgName"),
                    "fixed_in": v.get("FixedVersion") or None,
                    "platform": platform,
                    "target": target,
                })
    elif scanner == "grype":
        for m in report.get("matches") or []:
            vuln = m.get("vulnerability") or {}
            out.append({
                "id": vuln.get("id"),
                "severity": (vuln.get("severity") or "").lower(),
                "package": (m.get("artifact") or {}).get("name"),
                "fixed_in": (vuln.get("fix") or {}).get("versions") or None,
                "platform": platform,
                "target": None,
            })
    elif scanner == "snyk":
        # OS/distro findings live at the top level.
        for v in report.get("vulnerabilities") or []:
            out.append(_snyk_finding(v, platform, target=None, pkg_mgr=None))
        # Application-dependency findings live under applications[]; each app
        # entry carries its own project context (targetFile / packageManager)
        # — B04d: these were previously dropped entirely.
        for app in report.get("applications") or []:
            if not isinstance(app, dict):
                continue
            target = app.get("targetFile") or app.get("path")
            pkg_mgr = app.get("packageManager")
            for v in app.get("vulnerabilities") or []:
                out.append(_snyk_finding(v, platform, target, pkg_mgr))
    return out


def _snyk_finding(v, platform, target, pkg_mgr):
    cve = (v.get("identifiers") or {}).get("CVE") or []
    ident = cve[0] if cve else v.get("id")
    f = {
        "id": ident,
        "severity": (v.get("severity") or "").lower(),
        "package": v.get("packageName"),
        "fixed_in": v.get("nearestFixedInVersion") or None,
        "platform": platform,
        "target": target,
    }
    if pkg_mgr:
        f["package_manager"] = pkg_mgr
    return f


def _merge_raw(scanner, valid_reports):
    """Merge the valid per-child reports into one scanner-shaped aggregate
    for the retained raw-report evidence. For Snyk, BOTH the OS-level
    vulnerabilities AND the application sections are carried through."""
    if scanner == "trivy":
        results = []
        for r in valid_reports:
            results.extend(r.get("Results") or [])
        return {"Results": results}
    if scanner == "grype":
        matches = []
        for r in valid_reports:
            matches.extend(r.get("matches") or [])
        return {"matches": matches}
    if scanner == "snyk":
        vulns, apps = [], []
        for r in valid_reports:
            vulns.extend(r.get("vulnerabilities") or [])
            apps.extend(r.get("applications") or [])
        return {"vulnerabilities": vulns, "applications": apps}
    return {}


# --------------------------------------------------------------------------
# B04d + B04e — statement assembly and classification.
# --------------------------------------------------------------------------

def cmd_statement(args):
    scanner = args.scanner
    if scanner not in CONTRACTS:
        err("unknown scanner %r" % scanner)
        return 2
    contract = CONTRACTS[scanner]

    children = []
    with open(args.children) as fh:
        for line in fh:
            line = line.strip()
            if line:
                children.append(json.loads(line))

    findings = []
    valid_reports = []
    scanned_platforms = []
    op_fail = False
    max_rc = 0

    for child in children:
        platform = child.get("platform")
        code = int(child.get("exit", 0))
        report_path = child.get("report")
        if code > max_rc:
            max_rc = code
        if platform:
            scanned_platforms.append(platform)

        report = None
        if report_path and os.path.exists(report_path) \
                and os.path.getsize(report_path) > 0:
            try:
                with open(report_path) as rf:
                    report = json.load(rf)
            except (json.JSONDecodeError, OSError):
                report = None
        valid = report is not None and _shape_ok(scanner, report)

        completed = code in contract["clean"] or code in contract["finding"]
        if not completed:
            # An operational-failure exit code: incomplete coverage, even if
            # the tool still emitted well-shaped JSON (B04e). Do NOT harvest
            # findings from a child the scanner said it could not finish.
            op_fail = True
            continue
        if not valid:
            # The exit code says it completed, but there is no usable report —
            # a crash dump or an error object. Incomplete coverage.
            op_fail = True
            continue
        valid_reports.append(report)
        findings.extend(_normalize(scanner, report, platform))

    if not children:
        # Enumeration should have failed before this; treat as incomplete.
        op_fail = True

    has_findings = len(findings) > 0
    all_clean_exit = bool(children) and all(
        int(c.get("exit", 0)) in contract["clean"] for c in children)

    # Findings and completeness are INDEPENDENT (B04e): an incomplete run is
    # always verdict=error even when a real CVE was also found; the CVE is
    # still notified via has_findings, and the run still fails.
    if op_fail:
        outcome = "error"
    elif has_findings:
        outcome = "findings"
    elif all_clean_exit:
        outcome = "clean"
    else:
        outcome = "error"

    raw = _merge_raw(scanner, valid_reports)
    with open(args.raw_out, "w") as fh:
        json.dump(raw, fh)

    meta = {}
    if args.meta and os.path.exists(args.meta):
        for line in open(args.meta):
            if "=" in line:
                k, v = line.rstrip("\n").split("=", 1)
                meta[k] = v

    scope_limitation = None
    if args.scope_file and os.path.exists(args.scope_file):
        try:
            scope_limitation = json.load(open(args.scope_file))
        except (json.JSONDecodeError, OSError):
            scope_limitation = None

    statement = {
        "schema": "https://fosterstack.com/rescan-statement/v1",
        "scanned_at": args.scanned_at,
        "release": args.release,
        "variant": args.variant,
        "digest": args.digest,
        "image_ref": args.image_ref,
        "scanner": scanner,
        "scanner_version": meta.get("version", "unknown"),
        "scanner_database": meta.get("db", "unknown"),
        "scanned_platforms": scanned_platforms,
        "coverage_scope_limitation": scope_limitation,
        "policy": ("block at any severity; the published VEX document is the "
                   "only exception"),
        "verdict": outcome,
        "findings": findings,
        "raw_report": {
            "path": "findings-raw.json",
            "sha256": hashlib.sha256(
                open(args.raw_out, "rb").read()).hexdigest(),
        },
    }

    if args.vex and os.path.exists(args.vex):
        vex = json.load(open(args.vex))
        short = args.digest.split(":")[-1]
        applicable = [
            st for st in vex.get("statements", [])
            if any(str(p.get("@id", "")).endswith(short)
                   or args.digest in json.dumps(p)
                   for p in (st.get("products") or []))
        ]
        statement["vex"] = {
            "document": args.vex,
            "sha256": hashlib.sha256(open(args.vex, "rb").read()).hexdigest(),
            "applicable_statements": applicable,
            "document_statement_count": len(vex.get("statements", [])),
        }

    with open(args.out, "w") as fh:
        json.dump(statement, fh, indent=1)

    print(json.dumps({"verdict": outcome, "count": len(findings),
                      "has_findings": has_findings,
                      "platforms": scanned_platforms}))

    if args.github_output:
        with open(args.github_output, "a") as gh:
            gh.write("outcome=%s\n" % outcome)
            gh.write("has_findings=%s\n" % ("true" if has_findings else "false"))
    return 0


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    pe = sub.add_parser("enumerate", help="validate & emit platform children")
    pe.add_argument("--index", required=True)
    pe.add_argument("--repo", required=True)
    pe.add_argument("--ref", default="index")
    pe.add_argument("--out")
    pe.set_defaults(func=cmd_enumerate)

    ps = sub.add_parser("statement", help="merge, classify, write statement")
    ps.add_argument("--scanner", required=True)
    ps.add_argument("--children", required=True)
    ps.add_argument("--meta")
    ps.add_argument("--vex")
    ps.add_argument("--scope-file")
    ps.add_argument("--release", default="")
    ps.add_argument("--variant", default="")
    ps.add_argument("--digest", default="")
    ps.add_argument("--image-ref", default="")
    ps.add_argument("--scanned-at", default="")
    ps.add_argument("--raw-out", required=True)
    ps.add_argument("--out", required=True)
    ps.add_argument("--github-output")
    ps.set_defaults(func=cmd_statement)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
