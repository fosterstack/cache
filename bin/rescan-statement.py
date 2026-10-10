#!/usr/bin/env python3
# Extracted, testable core of the daily image rescan (.github/workflows/
# main-candidate-rescan.yml's rescan job, merged from daily-rescan.yml): the platform-child enumeration validation, the
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
import importlib.util
import json
import os
import re
import sys
import urllib.parse

# The VEX matcher is the one the PR gate uses (bin/inspector-gate.py): one definition of "this statement covers this finding".
_spec = importlib.util.spec_from_file_location("inspector_gate", os.path.join(os.path.dirname(os.path.abspath(__file__)), "inspector-gate.py"))
_gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_gate)

# Each scanner's exit-code contract. `clean` = completed, no findings;
# `finding` = completed WITH findings (the configured finding exit code).
# ANY other nonzero exit is an operational failure, independent of whether
# the tool also managed to emit parseable JSON.
#
#   snyk container test : 0 clean, 1 findings, 2/3 operational failure.
#     https://docs.snyk.io/developer-tools/snyk-cli/commands/container-test
#   trivy image --exit-code 1 : 0 clean, 1 findings, other nonzero = error.
#   grype --fail-on negligible : 0 clean, 2 findings, 1 (and other
#     nonzero) = operational error. Grype returns 2 for a
#     vulnerability-match failure and 1 for a runtime error - the
#     opposite of the misleading --help text; confirmed against
#     cmd/grype/cli/cli.go, verified unchanged at the pinned v0.118.0.
CONTRACTS = {
    "snyk": {"clean": {0}, "finding": {1}},
    "trivy": {"clean": {0}, "finding": {1}},
    "grype": {"clean": {0}, "finding": {2}},
    # osv-scanner scan image/source : 0 clean, 1 findings, 127/128 (and any
    #   other nonzero) = operational failure (no packages / general error).
    #   https://google.github.io/osv-scanner/output/#return-codes
    "osv-scanner": {"clean": {0}, "finding": {1}},
}


# Rule 4 (ratified scanner-panel rules): the published OpenVEX file is the only exception. A scanner that reads it itself (Grype --vex, Trivy --vex) has already
# applied it; every other scanner of .github/policy/scanners.json has its findings filtered HERE, against the same document. A scanner in neither list
# cannot be classified, so it cannot bypass the VEX by omission: `classify` (and the test over scanners.json) fail for it.
NATIVE_VEX = ("grype", "trivy")
PIPELINE_FILTERED = ("osv-scanner", "snyk")


def vex_class(scanner):
    if scanner in NATIVE_VEX:
        return "native"
    if scanner in PIPELINE_FILTERED:
        return "filtered"
    return None


def cmd_classify(args):
    c = vex_class(args.scanner)
    if c is None:
        err("scanner %r is neither marked as reading the VEX natively (NATIVE_VEX) nor covered by the pipeline filter (PIPELINE_FILTERED); "
            "a scanner must not bypass the VEX by omission" % args.scanner)
        return 2
    print(c)
    return 0


def cmd_find_issue(args):
    """The number of the open issue (a pull request is not one) of this repository that carries the label and has exactly this title, or nothing. EVERY page is read
    (`gh api --paginate`, 100 per page): a single default page of 30 would miss a tracking issue on a later page and open a duplicate every day. Any failure to
    read the list is an error (exit 1), never "no issue"."""
    import subprocess
    repo = args.repo or os.environ.get("GITHUB_REPOSITORY", "")
    if not repo:
        err("find-issue: no repository (--repo or GITHUB_REPOSITORY)")
        return 2
    url = "repos/%s/issues?state=open&labels=%s&per_page=100" % (repo, urllib.parse.quote(args.label))
    r = subprocess.run(["gh", "api", "--paginate", url], capture_output=True, text=True)
    if r.returncode != 0:
        err("find-issue: could not list the open issues (gh api failed: %s); refusing to guess that none exists" % r.stderr.strip()[:200])
        return 1
    dec, pos, text, found, pages = json.JSONDecoder(), 0, r.stdout, None, 0
    while True:
        while pos < len(text) and text[pos].isspace():
            pos += 1
        if pos >= len(text):
            break
        try:
            page, pos = dec.raw_decode(text, pos)
        except ValueError:
            err("find-issue: the issue list could not be read (not JSON); refusing to guess that none exists")
            return 1
        if not isinstance(page, list):
            err("find-issue: the issue list is not an array of issues; refusing to guess that none exists")
            return 1
        pages += 1
        for it in page:
            if isinstance(it, dict) and "pull_request" not in it and it.get("title") == args.title and found is None:
                if not isinstance(it.get("number"), int) or isinstance(it.get("number"), bool):
                    err("find-issue: the matching issue has no integer number; refusing to guess")
                    return 1
                found = it["number"]
    if pages == 0:
        err("find-issue: gh returned no page at all (an empty reply is not '[]'); refusing to guess that none exists")
        return 1
    if found is not None:
        print(found)
    return 0


OUR_OCI_REPOS = ("ghcr.io/fosterstack/cache", "ghcr.io/fosterstack/cache-candidates")
VEX_VARIANTS = ("production", "debug", "fips")
VEX_ARCHS = ("amd64", "arm64")


def _parse_product(pid):
    """None when the product is not ours; ValueError when it LOOKS like ours but is not in the exact form we accept (a blank, duplicate, upper-case or unknown
    qualifier, a version or digest on an OCI product, a repository other than the one named by the product, an unknown variant or architecture): a form that
    could parse as unscoped or as another product makes the whole document unreadable. Otherwise ("go",), ("go-versioned",) or ("oci", repository, variant|None, arch|None)."""
    if not isinstance(pid, str):
        raise ValueError("a product identifier that is not a string")
    if not _gate.OUR_PRODUCTS.match(pid):
        return None
    base, _, query = pid.partition("?")
    if base.startswith("pkg:golang/"):
        if "?" in pid:
            raise ValueError("a qualifier on the Go product %r" % pid)
        if "@" in base:
            return ("go-versioned",)   # a version-pinned module cannot be tied to the release being scanned: it never applies
        return ("go",)
    names = {"pkg:oci/cache": OUR_OCI_REPOS[0], "pkg:oci/cache-candidates": OUR_OCI_REPOS[1]}
    if base not in names:
        raise ValueError("the OCI product %r has a version or digest, or an unknown name" % pid)
    q = {}
    for part in query.split("&"):
        k, eq, v = part.partition("=")
        if not eq or not k or not v or k not in ("repository_url", "variant", "arch") or k in q:
            raise ValueError("the product %r has a blank, duplicate, upper-case or unknown qualifier" % pid)
        q[k] = v
    if q.get("repository_url") != names[base]:
        raise ValueError("the product %r names another repository than its own" % pid)
    if q.get("variant") not in (None,) + VEX_VARIANTS or q.get("arch") not in (None,) + VEX_ARCHS:
        raise ValueError("the product %r names an unknown variant or architecture" % pid)
    return ("oci", q["repository_url"], q.get("variant"), q.get("arch"))


def _vex_validate(doc):
    """every nested shape the matcher reads, checked up front: anything else is ValueError (the VEX is unreadable), so a malformed statement can never be read as
    'no restriction'. Returns nothing."""
    if not isinstance(doc, dict) or not isinstance(doc.get("statements"), list):
        raise ValueError("not an OpenVEX document (an object with a list of statements)")
    for st in doc["statements"]:
        if not isinstance(st, dict) or not isinstance(st.get("status"), str):
            raise ValueError("a statement that is not an object with a string status")
        v = st.get("vulnerability")
        if not isinstance(v, dict) or not isinstance(v.get("name"), str) or not v["name"]:
            raise ValueError("a statement without a vulnerability name")
        al = v.get("aliases", [])
        if not isinstance(al, list) or not all(isinstance(a, str) for a in al):
            raise ValueError("vulnerability aliases that are not a list of strings")
        prods = st.get("products")
        if not isinstance(prods, list):
            raise ValueError("statement products that are not a list")
        for p in prods:
            if not isinstance(p, dict):
                raise ValueError("a product that is not an object")
            idf = p.get("identifiers", {})
            if not isinstance(idf, dict) or ("purl" in idf and not isinstance(idf["purl"], str)):
                raise ValueError("product identifiers that are not an object with a string purl")
            if "@id" in p and "purl" in idf and p["@id"] != idf["purl"]:
                raise ValueError("a product whose @id and identifiers.purl differ")
            pid = p.get("@id") if "@id" in p else idf.get("purl")
            _parse_product(pid)
            subs = p.get("subcomponents", [])
            if not isinstance(subs, list) or not all(isinstance(x, dict) and isinstance(x.get("@id"), str) for x in subs):
                raise ValueError("subcomponents that are not a list of objects with a string @id")
            for x in subs:
                if not x["@id"].startswith("pkg:") or not _gate.name_version(urllib.parse.unquote(x["@id"]))[0].strip():
                    raise ValueError("a subcomponent that is not a package URL with a usable package name (%r)" % x["@id"])


def _vex_load(path):
    """the published OpenVEX document, or ValueError/OSError: unreadable, not JSON, or any shape the matcher reads is wrong"""
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    _vex_validate(doc)
    return doc


def _image_repo(image_ref):
    """ghcr.io/fosterstack/cache from ghcr.io/fosterstack/cache@sha256:<64 hex> (or :tag); None when it is not one of our two repositories or the digest is not a sha256"""
    r, at, dig = str(image_ref or "").partition("@")
    if at and not re.fullmatch(r"sha256:[0-9a-f]{64}", dig):
        return None
    head, sep, tail = r.rpartition(":")
    if sep and "/" not in tail:
        r = head
    return r if r in OUR_OCI_REPOS else None


def _vex_match(doc, finding, variant, image_repo):
    """the first statement that removes this finding, or None: status not_affected or fixed, the vulnerability name or an alias equal to one of the finding's
    ids, a product that is EXACTLY this image's repository (cache or cache-candidates, never the other) scoped to nothing or to this variant and platform, or the
    repository-wide Go product, and (when the product names subcomponents) the finding's package name@version among them. The document was validated first."""
    ids = {i for i in (finding.get("ids") or [finding.get("id")]) if i}
    pkg = ((finding.get("package") or "").lower(), finding.get("version") or "")
    arch = (finding.get("platform") or "").rpartition("/")[2]
    if not isinstance(finding.get("package") or "", str):
        raise ValueError("a package name that is not a string")
    for st in doc["statements"]:
        if st["status"] not in _gate.SUPPRESSING:
            continue
        v = st["vulnerability"]
        if not ({v["name"]} | set(v.get("aliases", []))) & ids:
            continue
        for p in st["products"]:
            idf = p.get("identifiers", {})
            pp = _parse_product(p.get("@id") if "@id" in p else idf.get("purl"))
            if pp is None or pp[0] == "go-versioned":
                continue
            if pp[0] == "oci" and not (image_repo is not None and pp[1] == image_repo and pp[2] in (None, variant) and pp[3] in (None, arch)):
                continue
            subs = [_gate.name_version(urllib.parse.unquote(x["@id"])) for x in p.get("subcomponents", [])]
            if subs and not pkg[0]:
                continue   # a finding with no package identity never matches a statement that names packages
            if not subs or any(_gate.same_pkg(pkg, sub) for sub in subs):
                return {"document": doc.get("@id"), "version": doc.get("version"), "statement": v["name"], "status": st["status"], "product": p.get("@id")}
    return None


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
    if scanner == "osv-scanner":
        return isinstance(report.get("results"), list)
    return False


def _normalize(scanner, report, platform, bad=None):
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
            _guard(out, bad, lambda: _snyk_finding(v, platform, target=None, pkg_mgr=None))
        # Application-dependency findings live under applications[]; each app
        # entry carries its own project context (targetFile / packageManager)
        # — B04d: these were previously dropped entirely.
        for app in report.get("applications") or []:
            if not isinstance(app, dict):
                continue
            target = app.get("targetFile") or app.get("path")
            pkg_mgr = app.get("packageManager")
            for v in app.get("vulnerabilities") or []:
                _guard(out, bad, lambda: _snyk_finding(v, platform, target, pkg_mgr))
    elif scanner == "osv-scanner":
        # OSV.dev JSON: results[] -> source.path, packages[] ->
        # {package:{name,...}, vulnerabilities:[{id, aliases, ...}]}.
        for res in report.get("results") or []:
            if not isinstance(res, dict):
                _bad(bad)
                continue
            src = (res.get("source") or {}).get("path") if isinstance(res.get("source") or {}, dict) else None
            for pkg in res.get("packages") or []:
                if not isinstance(pkg, dict):
                    _bad(bad)
                    continue
                for v in pkg.get("vulnerabilities") or []:
                    _guard(out, bad, lambda: _osv_finding(v, pkg, src, platform))
    return out


def _bad(bad):
    if bad is not None:
        bad.append(1)


def _guard(out, bad, make):
    """one scanner entry: a malformed one is counted (the run becomes an operational error) and skipped; the valid ones around it still count"""
    try:
        f = make()
        if not isinstance(f.get("id"), str) and f.get("id") is not None:
            raise ValueError("an identifier that is not a string")
        if not all(isinstance(x, str) for x in f.get("ids", [])):
            raise ValueError("identifiers that are not strings")
        if not isinstance(f.get("package"), (str, type(None))) or not isinstance(f.get("version"), (str, type(None))):
            raise ValueError("a package name or version that is not a string")
        out.append(f)
    except (TypeError, AttributeError, KeyError, ValueError):
        _bad(bad)


def _osv_finding(v, pkg, src, platform):
    vid, aliases = v.get("id"), v.get("aliases") or []
    if not isinstance(vid, str) or not isinstance(aliases, list) or not all(isinstance(a, str) for a in aliases):
        raise ValueError("a vulnerability whose id is not a string or whose aliases are not a list of strings")
    pk = pkg.get("package") or {}
    if not isinstance(pk, dict):
        raise ValueError("a package entry that is not an object")
    cve = next((a for a in aliases if a.startswith("CVE-")), None)
    return {
        "id": cve or vid,
        "ids": [vid] + list(aliases),
        "severity": _osv_severity(v),
        "package": pk.get("name"),
        "version": pk.get("version"),
        "fixed_in": None,
        "platform": platform,
        "target": src,
    }


def _osv_severity(v):
    """OSV records severity inconsistently; prefer a database_specific label,
    fall back to a CVSS vector's presence, else unknown."""
    ds = v.get("database_specific") or {}
    if isinstance(ds, dict) and isinstance(ds.get("severity"), str) and ds.get("severity").strip():
        return ds["severity"].lower()
    if v.get("severity"):
        return "unknown"
    return "unknown"


def _snyk_finding(v, platform, target, pkg_mgr):
    cve = (v.get("identifiers") or {}).get("CVE") or []
    ident = cve[0] if cve else v.get("id")
    f = {
        "id": ident,
        "ids": [x for x in list(cve) + list((v.get("identifiers") or {}).get("ALTERNATIVE") or []) + [v.get("id")] if isinstance(x, str)],
        "version": v.get("version"),
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
    consistent = True   # every child exited clean, or exited with the findings code AND the report really held findings
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
        bad = []
        got = _normalize(scanner, report, platform, bad)
        if bad:
            err("%d malformed entries in the %s report of %s; the rescan is incomplete (the valid findings still count)" % (len(bad), scanner, platform))
            op_fail = True
        if code in contract["finding"] and not got:
            consistent = False   # the scanner says "findings" but none could be read: never clean
        findings.extend(got)

    if not children:
        # Enumeration should have failed before this; treat as incomplete.
        op_fail = True

    # Rule 4: for a scanner that cannot read the VEX itself, remove the findings the published VEX covers. An unreadable VEX (missing, not JSON, wrong shape,
    # or no --vex at all) is an operational error, never "no suppression": the findings stay counted and the run is red.
    klass = vex_class(scanner)
    suppressed, vex_error, vex_doc = [], None, None
    if klass == "filtered":
        try:
            if not args.vex:
                raise ValueError("no VEX document was given (--vex)")
            vex_doc = _vex_load(args.vex)
        except (OSError, ValueError, TypeError, AttributeError, KeyError, RecursionError) as e:
            vex_error = "the VEX document cannot be used (%s); the rescan is incomplete" % e
            err(vex_error)
            op_fail = True
        if vex_doc is not None:
            kept = []
            for f in findings:
                try:
                    m = _vex_match(vex_doc, f, args.variant, _image_repo(args.image_ref))
                except (TypeError, AttributeError, KeyError, ValueError, RecursionError) as e:
                    vex_error = "a finding could not be matched against the VEX (%s); the rescan is incomplete" % e
                    err(vex_error)
                    op_fail = True
                    m = None
                if m:
                    suppressed.append(dict(f, vex=m))
                else:
                    kept.append(f)
            findings = kept

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
    elif suppressed and consistent:
        outcome = "clean"   # every finding the scanner reported is covered by the published VEX
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
        "vex_suppressed": suppressed,
        "raw_report": {
            "path": "findings-raw.json",
            "sha256": hashlib.sha256(
                open(args.raw_out, "rb").read()).hexdigest(),
        },
    }

    if args.vex and os.path.exists(args.vex) and vex_error is None:
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
            "filtered_by_pipeline": klass == "filtered",
        }
    elif klass == "filtered":
        statement["vex"] = {"document": args.vex or None, "error": vex_error, "filtered_by_pipeline": True}

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

    pf = sub.add_parser("find-issue", help="print the number of the open tracking issue with this title (every page), or nothing")
    pf.add_argument("--title", required=True)
    pf.add_argument("--label", default="daily-rescan")
    pf.add_argument("--repo")
    pf.set_defaults(func=cmd_find_issue)

    pc = sub.add_parser("classify", help="print native or filtered; fail for a scanner with no VEX classification")
    pc.add_argument("--scanner", required=True)
    pc.set_defaults(func=cmd_classify)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
