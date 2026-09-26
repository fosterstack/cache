#!/usr/bin/env python3
"""Build the run manifest the scheduled workflow consumes (REQ-AUD-1).

ONE schema, written here and validated by the driver on load. Every key the driver reads
is produced, or set explicitly to null with a recorded reason in `scanner_status`.

Round 12 — a scanner that inventories ZERO packages DID NOT RUN. The producer reads each
scanner's OWN package inventory (grype `artifacts`, trivy `Results[].Packages`, osv-scanner
`results[].packages`); an empty inventory is `ran: false, reason: "0 packages inventoried"`,
never a clean pass because a file exists. The three image scanners must agree on the OS
package count within a tolerance, or the outliers are recorded "did not run (inventory
disagreement)". Each scanner's package count and database build date go into the manifest
(and thence the report header), and one line per scanner is printed to the job log:
    grype 0.118.0 db=2026-09-22 packages=18 findings=0

Scanning is off a CONTAINER ARCHIVE, not a daemon ref: the candidate tag lives only in the
runner's daemon, so `osv-scanner scan image <ref>` pulled from a registry and found nothing,
and grype catalogued nothing off the daemon-loaded distroless image. We convert the OCI
archive once to a docker-save tar with skopeo (no daemon) and point all three scanners at it.
"""
import json, os, re, subprocess, sys, glob
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auditorlib import cli

TAG = "ghcr.io/fosterstack/cache:cand-production"
DATE_RE = re.compile(r"(\d{4}-\d{2}-\d{2})")


def _run(cmd, out_path=None, timeout=1500):
    try:
        if out_path:
            with open(out_path, "w") as fh:
                r = subprocess.run(cmd, stdout=fh, stderr=subprocess.PIPE, timeout=timeout)
            return r.returncode, (r.stderr.decode() if r.stderr else "")
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout
    except Exception as e:
        return 255, str(e)


def _version(tool, args=("--version",)):
    rc, out = _run([tool, *args])
    return (out.strip().splitlines()[0] if (rc == 0 and out.strip()) else None)


def _module(source_dir):
    gm = os.path.join(source_dir, "go.mod")
    if os.path.exists(gm):
        for line in open(gm):
            if line.strip().startswith("module "):
                return line.strip().split(None, 1)[1].strip()
    return None


# ---- per-scanner inventory readers: (total_packages, os_packages, db_date) ----

# An OS-layer package is any distro package manager's package — deb (Debian/Ubuntu), apk
# (Alpine), or rpm (RHEL/Fedora/SUSE). Counting only "deb" made grype report 0 OS packages on
# an Alpine image while trivy/snyk saw the apk layer, sinking the quorum on every Alpine base.
_OS_PKG_TYPES = ("deb", "apk", "rpm")
_OS_PURL_PREFIXES = ("pkg:deb", "pkg:apk", "pkg:rpm")
_OS_OSV_ECOSYSTEMS = ("debian", "ubuntu", "alpine", "rhel", "red hat", "rocky", "almalinux", "suse", "opensuse")


def _is_os_pkg(a):
    """True if a grype/syft artifact is an OS-layer package (deb | apk | rpm), by type or purl."""
    t = (a.get("type") or "").lower()
    purl = str(a.get("purl") or "")
    return t in _OS_PKG_TYPES or purl.startswith(_OS_PURL_PREFIXES)


def _inv_grype(path):
    # grype 0.118.0 `-o json` emits `matches`, not a full package catalogue, so the package
    # inventory is the distinct set of matched artifacts (the vulnerable packages). A distro
    # image with zero matched packages is treated as "did not inventory" (the distroless
    # status.d case), which is exactly the silent-empty scan Round 12 is guarding against.
    d = json.load(open(path))
    matches = d.get("matches") or []
    seen = set(); osseen = set()
    for mt in matches:
        a = mt.get("artifact") or {}
        key = (a.get("name"), a.get("version"), a.get("type"))
        seen.add(key)
        if _is_os_pkg(a):
            osseen.add(key)
    dbfrom = ((d.get("descriptor") or {}).get("db") or {}).get("status", {}).get("from", "") or ""
    m = DATE_RE.search(dbfrom)
    return len(seen), len(osseen), (m.group(1) if m else None), len(matches)


def _inv_trivy(path):
    d = json.load(open(path))
    res = d.get("Results") or []
    total = sum(len(r.get("Packages") or []) for r in res)
    osp = sum(len(r.get("Packages") or []) for r in res if r.get("Class") == "os-pkgs")
    findings = sum(len(r.get("Vulnerabilities") or []) for r in res)
    return total, osp, None, findings


def _inv_osv(path):
    d = json.load(open(path))
    total = 0; osp = 0; findings = 0
    for r in d.get("results") or []:
        for p in r.get("packages") or []:
            total += 1
            eco = ((p.get("package") or {}).get("ecosystem") or "").lower()
            if any(x in eco for x in _OS_OSV_ECOSYSTEMS):
                osp += 1
            findings += len(p.get("vulnerabilities") or [])
    return total, osp, None, findings


def _inv_syft(path):
    """syft is grype's own cataloguer; unlike grype's match-JSON it emits the FULL package
    inventory, including a distroless image's /var/lib/dpkg/status.d packages (R12 (b))."""
    d = json.load(open(path)); arts = d.get("artifacts") or []
    total = len(arts); osp = sum(1 for a in arts if _is_os_pkg(a))
    return total, osp


# ONLY the "contains" relationship is a genuine carrier signal — the parent artifact BUNDLES the
# child (e.g. a binary that embeds a library). syft's "dependency-of" links ordinary,
# independently-upgradable packages (apt deps, Go stdlib) and is NOT carrying — including it
# inverted every real relationship (dpkg "carried by" zlib1g); "ownership-by-file-overlap" is
# likewise not embedding. Both are excluded (Sonnet round-1 blocker 2).
_CARRY_RELS = {"contains": "bundled"}


def _carriers(path):
    """Candidate carrier relationships from the syft SBOM (REQ-AUD-14 AC2): a vulnerable-capable
    component (a package with a purl) that is CARRIED inside another artifact — the parent artifact
    `contains` (bundles) the child. This is a SAFE over-approximation: it only decides which findings
    get a pullability model call — a wrong candidate returns pullable and falls through to normal
    routing, so a false carrier costs one call, never a wrong disposition. The model does the
    authoritative carrier analysis."""
    try:
        d = json.load(open(path))
    except Exception:
        return []
    by_id = {a.get("id"): a for a in (d.get("artifacts") or []) if a.get("id")}
    out = []; seen = set()
    for rel in (d.get("artifactRelationships") or []):
        how = _CARRY_RELS.get(rel.get("type"))
        if not how:
            continue
        parent = by_id.get(rel.get("parent")); child = by_id.get(rel.get("child"))
        if not parent or not child:
            continue
        cpurl = child.get("purl"); ppurl = parent.get("purl")
        # the child must be a real, vulnerable-capable package with a purl, distinct from the
        # carrier; a package "containing" its own files is not a carrier relationship.
        if not cpurl or parent.get("id") == child.get("id") or cpurl == ppurl:
            continue
        key = (cpurl, ppurl)
        if key in seen:
            continue
        seen.add(key)
        out.append({"component": child.get("name"), "component_purl": cpurl,
                    "component_version": child.get("version"), "carrier": parent.get("name"),
                    "carrier_purl": ppurl, "carrier_version": parent.get("version"), "how": how})
    return out


# endoflife.date product ids for the carriers/base we recognize (REQ-AUD-14 AC6/AC7).
_EOL_PRODUCT = {"debian": "debian", "ubuntu": "ubuntu", "alpine": "alpine",
                "nodejs": "nodejs", "node": "nodejs", "python": "python",
                "openssl": "openssl", "postgresql": "postgresql", "postgres": "postgresql",
                "nginx": "nginx", "go": "go", "golang": "go"}


def _eol_fetch(product):
    """Best-effort endoflife.date lookup; None on any failure (offline, 404, timeout). The runner
    has network; a failure simply produces no maintenance flag rather than blocking the manifest."""
    import urllib.request
    try:
        with urllib.request.urlopen("https://endoflife.date/api/%s.json" % product, timeout=10) as r:
            return json.loads(r.read().decode())
    except Exception:
        return None


def _major(ver):
    m = re.match(r"(\d+(?:\.\d+)?)", str(ver or ""))
    return m.group(1) if m else None


def _days_between(a, b):
    from datetime import date
    try:
        return (date.fromisoformat(b) - date.fromisoformat(a)).days
    except Exception:
        return None


def _cycle_status(cyc, today):
    """endoflife cycle -> 'eol' | 'maintenance' | 'active' at `today`. A dated eol in the past is
    end-of-life; an active LTS/maintenance window is 'maintenance'."""
    def _passed(v):
        return isinstance(v, str) and len(v) == 10 and v <= today
    if _passed(cyc.get("eol")):
        return "eol"
    lts = cyc.get("lts")
    if lts is True or _passed(lts):
        return "maintenance"
    return "active"


def _match_cycle(data, ver):
    maj = _major(ver)
    if maj:
        c = next((c for c in data if str(c.get("cycle")) == maj), None)
        if c:
            return c
        c = next((c for c in data if str(c.get("cycle")) == maj.split(".")[0]), None)
        if c:
            return c
    return None


def _lifecycle(base_os, carriers, fetch, today):
    """The `eol` maintenance-flag list and the `base` pin-lag block for the manifest header
    (REQ-AUD-14 AC6/AC7), from endoflife.date via `fetch`. Pure given `fetch` and `today`, so the
    suite injects canned endoflife data and never hits the network."""
    eol = []; base = {}; seen = set()

    def _add(product, cyc):
        st = _cycle_status(cyc, today)
        if st in ("eol", "maintenance") and product not in seen:
            seen.add(product)
            eol.append({"carrier": product, "cycle": str(cyc.get("cycle")), "status": st,
                        "eol_date": cyc.get("eol") if isinstance(cyc.get("eol"), str) else None})

    parts = (base_os or "").split()
    bprod = _EOL_PRODUCT.get(parts[0].lower()) if parts else None
    bver = parts[-1] if len(parts) > 1 else ""
    bdata = fetch(bprod) if bprod else None
    if bdata:
        cyc = _match_cycle(bdata, bver) or (bdata[0] if bdata else None)
        if cyc:
            _add(bprod, cyc)
            lrd = cyc.get("latestReleaseDate"); latest = str(cyc.get("latest") or "")
            base = {"release": base_os, "behind_threshold_days": 30}
            if isinstance(lrd, str) and len(lrd) == 10 and latest and latest != bver:
                d = _days_between(lrd, today)
                if d is not None:
                    base["days_behind"] = d; base["latest"] = latest
    for cr in (carriers or []):
        nm = (cr.get("carrier") or "").lower(); prod = _EOL_PRODUCT.get(nm)
        if not prod:
            continue
        d = fetch(prod)
        if not d:
            continue
        cyc = _match_cycle(d, cr.get("carrier_version"))
        if cyc:
            _add(prod, cyc)
    return eol, base


def _inv_snyk(path):
    d = json.load(open(path))
    docs = d if isinstance(d, list) else [d]
    total = 0; findings = 0
    for doc in docs:
        total = max(total, int(doc.get("dependencyCount") or 0))
        findings += len(doc.get("vulnerabilities") or [])
    return total, total, None, findings


INV = {"grype": _inv_grype, "trivy": _inv_trivy, "osv-scanner": _inv_osv, "osv-scanner-gomod": _inv_osv}


def _skopeo(src, dst):
    """skopeo copy, host arch, printing stderr on failure."""
    r = subprocess.run(["skopeo", "copy", "--override-arch", "amd64", "--override-os", "linux", src, dst],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print("skopeo %s -> %s FAILED (rc %d): %s" % (src, dst, r.returncode, (r.stderr or "").strip()[:400]))
    return r.returncode == 0


def _norm_ref(ref):
    """debian:12.0@sha256:X -> debian@sha256:X (the digest is authoritative; the tag+digest
    form is not universally accepted, and the digest is a multi-arch index)."""
    if "@sha256:" in ref:
        name, digest = ref.split("@", 1)
        name = name.split(":", 1)[0]
        return "%s@%s" % (name, digest)
    return ref


def _archives(rescan_dir, test_image, oci, tar):
    """Produce BOTH an oci-archive and a docker-save tar (no daemon). grype reads the
    oci-archive directly (R12 item 2); trivy/osv read the docker-save tar. Returns
    (source_desc, err)."""
    if test_image:
        ref = "docker://" + _norm_ref(test_image)
        ok1 = _skopeo(ref, "oci-archive:%s:%s" % (oci, TAG))
        ok2 = _skopeo(ref, "docker-archive:%s:%s" % (tar, TAG))
        return (("test_image=%s" % test_image, None) if (ok1 or ok2) else (None, "skopeo could not pull %s" % ref))
    named = glob.glob(os.path.join(rescan_dir, "**", "production.oci"), recursive=True)
    if not named:
        return None, "no production.oci in the rescan artifacts"
    # production.oci is a multi-arch index; select amd64 into a single-arch OCI archive that
    # grype can catalogue, and a docker-save tar for trivy/osv.
    src = "oci-archive:%s" % named[0]
    ok1 = _skopeo(src, "oci-archive:%s:%s" % (oci, TAG))
    ok2 = _skopeo(src, "docker-archive:%s:%s" % (tar, TAG))
    return (os.path.basename(named[0]), None) if (ok1 or ok2) else (None, "skopeo convert failed")


def _scan(name, cmd, reports, ok=(0, 1)):
    path = os.path.join(reports, name + ".json")
    r = subprocess.run(cmd, capture_output=True, text=True)
    open(path, "w").write(r.stdout or "")
    if r.returncode not in ok:
        print("%s scan rc=%d stderr: %s" % (name, r.returncode, (r.stderr or "").strip().splitlines()[-3:] if r.stderr else ""))
    elif r.stderr and r.stderr.strip():
        print("%s stderr: %s" % (name, " | ".join((r.stderr or "").strip().splitlines()[-2:])))
    return path, r.returncode


def main():
    rescan = cli.opt("--rescan-dir"); reports = cli.opt("--reports")
    source = cli.opt("--source-dir", os.getcwd()); out = cli.opt("--out")
    commit = cli.opt("--commit", os.environ.get("GITHUB_SHA", "unknown"))
    test_image = cli.opt("--test-image") or os.environ.get("AUDITOR_TEST_IMAGE") or ""
    kdl = cli.opt("--known-defect-log", ".github/agent/known-defect-log.json")
    tol = float(cli.opt("--os-inventory-tolerance", "0.5"))
    os.makedirs(reports, exist_ok=True)

    tar = os.path.join(reports, "candidate.tar"); oci = os.path.join(reports, "candidate.oci")
    src, err = _archives(rescan, test_image, oci, tar)
    if not src:
        sys.exit("auditor-manifest: cannot ingest the candidate — %s" % err)
    have_oci = os.path.exists(oci) and os.path.getsize(oci) > 0
    have_tar = os.path.exists(tar) and os.path.getsize(tar) > 0
    print("archives: oci=%s tar=%s" % (have_oci, have_tar))

    # scan the ARCHIVE (no daemon, no registry pull). grype reads the OCI archive directly
    # (the review's simplest path); trivy/osv read the docker-save tar.
    grype_src = ("oci-archive:" + oci) if have_oci else ("docker-archive:" + tar)
    plans = {
        "grype": ["grype", grype_src, "-o", "json"],
        "trivy": ["trivy", "image", "--input", tar, "--quiet", "--format", "json"],
        "osv-scanner": ["osv-scanner", "scan", "image", "--archive", tar, "--format", "json"],
    }
    scanner_reports = {}; status = {}; counts = {}
    for name, cmd in plans.items():
        path, rc = _scan(name, cmd, reports)
        ver = _version(name if name != "osv-scanner" else "osv-scanner")
        total = osp = findings = 0; db = None
        try:
            total, osp, db, findings = INV[name](path)
        except Exception as e:
            rc = rc if rc not in (0, 1) else 255
        scan_ok = rc in (0, 1)
        ran = scan_ok and total > 0
        reason = "ok" if ran else ("0 packages inventoried (scanner produced no package inventory)"
                                   if scan_ok else "scan failed (rc %d)" % rc)
        scanner_reports[name] = path if ran else None
        status[name] = {"ran": ran, "scan_ok": scan_ok, "quorum_ok": ran, "version": ver, "reason": reason,
                        "package_count": total, "os_package_count": osp,
                        "db_date": db, "findings": findings}
        counts[name] = osp if ran else None
        print("%s %s db=%s packages=%s os_packages=%s findings=%s ran=%s"
              % (name, ver or "-", db or "-", total, osp, findings, ran))

    # grype's match-JSON has no full catalogue, so take grype's package inventory from syft
    # (its own cataloguer), which reads distroless status.d. grype still supplies the matches.
    syft_src = ("oci-archive:" + oci) if have_oci else ("docker-archive:" + tar)
    syft_path = os.path.join(reports, "syft.json")
    carriers = []
    rc, _ = _run(["syft", syft_src, "-o", "syft-json"], out_path=syft_path)
    if rc == 0 and os.path.exists(syft_path) and os.path.getsize(syft_path) > 0:
        try:
            carriers = _carriers(syft_path)   # REQ-AUD-14: SBOM carrier relationships
            stot, sos = _inv_syft(syft_path)
            gfind = status["grype"]["findings"]
            # syft supplies grype's package INVENTORY, but grype still counts as run only if
            # grype's OWN vulnerability scan completed (scan_ok) — syft cannot vouch for grype
            # (R1 outer round-1 #3). A failed grype scan stays not-run even if syft inventoried.
            gran = bool(status["grype"].get("scan_ok")) and stot > 0
            status["grype"].update(ran=gran, quorum_ok=gran, package_count=stot, os_package_count=sos,
                                   reason=("ok" if gran else (status["grype"]["reason"] if not status["grype"].get("scan_ok")
                                           else "0 packages inventoried")))
            scanner_reports["grype"] = os.path.join(reports, "grype.json") if gran else None
            counts["grype"] = sos if gran else None
            print("grype(syft) packages=%s os_packages=%s findings=%s scan_ok=%s ran=%s"
                  % (stot, sos, gfind, status["grype"].get("scan_ok"), gran))
        except Exception as e:
            print("syft inventory parse failed: %s" % e)
    else:
        print("syft did not run (rc %d); grype inventory falls back to matched packages" % rc)

    # Snyk container test (SNYK_TOKEN is an agent secret; GitHub masks it — never printed).
    if os.environ.get("SNYK_TOKEN"):
        snyk_path = os.path.join(reports, "snyk.json")
        r = subprocess.run(["snyk", "container", "test", "docker-archive:" + tar,
                            "--json", "--org=fosterstack-admin"], capture_output=True, text=True)
        open(snyk_path, "w").write(r.stdout or "")
        blob = (r.stdout or "") + (r.stderr or "")
        quota = re.search(r"reached your monthly limit|not authori|authentication error", blob, re.I)
        stot = sos = sfind = 0
        try:
            stot, sos, _, sfind = _inv_snyk(snyk_path)
        except Exception:
            pass
        sran = (r.returncode in (0, 1)) and not quota and stot > 0
        scanner_reports["snyk"] = snyk_path if sran else None
        status["snyk"] = {"ran": sran, "version": _version("snyk"),
                          "reason": "ok" if sran else ("quota/auth: could not run" if quota else "0 packages inventoried"),
                          "package_count": stot, "os_package_count": sos, "db_date": None, "findings": sfind}
        counts["snyk"] = sos if sran else None
        print("snyk %s packages=%s findings=%s ran=%s" % (_version("snyk") or "-", stot, sfind, sran))
    else:
        scanner_reports["snyk"] = None
        status["snyk"] = {"ran": False, "version": None, "reason": "no SNYK_TOKEN available; Snyk did not run",
                          "package_count": None, "db_date": None}

    # OS package inventory AGREEMENT across the image scanners (±Go modules): an outlier
    # below tolerance*max is excluded from the QUORUM (quorum_ok=False) — but its report is
    # KEPT so its actual findings are still parsed and dispositioned (R1 outer round-1 #2:
    # three inventories agreeing does not disprove the fourth scanner's real finding).
    # Exclude an outlier vs the MEDIAN, not the max (R1 outer round-2 #3): one scanner that
    # OVER-counts must not disqualify three that agree. A scanner outside [tol*median,
    # median/tol] is excluded from the quorum (its findings are still assessed).
    live = {k: v for k, v in counts.items() if v is not None and v > 0}
    if len(live) >= 2:
        import statistics
        med = statistics.median(sorted(live.values()))
        lo, hi = tol * med, (med / tol if tol else med)
        for k, v in list(live.items()):
            if v < lo or v > hi:
                status[k]["quorum_ok"] = False
                status[k]["reason"] = "excluded from quorum: inventory outlier (os_packages=%d vs median %g); findings still assessed" % (v, med)
                print("%s QUORUM-EXCLUDED (findings kept): os_packages=%d outside [%.1f, %.1f]" % (k, v, lo, hi))

    # OSV Go-module source scan of the checked-out tree.
    gomod = os.path.join(reports, "osv-gomod.json")
    rc, _ = _run(["osv-scanner", "scan", "source", "--format", "json", os.path.join(source, "go.mod")], out_path=gomod)
    gomod_ok = rc in (0, 1) and os.path.exists(gomod) and os.path.getsize(gomod) > 0
    scanner_reports["osv-scanner-gomod"] = gomod if gomod_ok else None
    status["osv-scanner-gomod"] = {"ran": gomod_ok, "version": _version("osv-scanner"),
                                   "reason": "ok" if gomod_ok else "did not run (rc %d)" % rc,
                                   "package_count": None, "db_date": None}

    # govulncheck -json over the checked-out tree, bound to module + commit.
    module = _module(source); gvc = None
    gvc_path = os.path.join(reports, "govulncheck.json")
    have_gvc = bool(_version("govulncheck", ("-version",)) or _version("govulncheck"))
    rc, _ = _run(["govulncheck", "-json", "./..."], out_path=gvc_path, timeout=1500) if have_gvc else (255, "")
    if os.path.exists(gvc_path) and os.path.getsize(gvc_path) > 0 and rc in (0, 3):
        gvc = {"path": gvc_path, "module": module, "commit": commit, "complete": True, "scan_level": "symbol"}

    digest = ""
    for transport in (("docker-archive:" + tar) if have_tar else None, ("oci-archive:" + oci) if have_oci else None):
        if not transport:
            continue
        rc, out_i = _run(["skopeo", "inspect", "--format", "{{.Digest}}", transport])
        if rc == 0 and out_i.strip():
            digest = out_i.strip(); break
    if not digest:
        digest = test_image.split("@")[-1] if "@" in test_image else "sha256:unknown"

    # REQ-AUD-14 AC6/AC7: endoflife.date maintenance flags for the base + carriers, and the base
    # pin-lag block (best-effort; empty when endoflife.date is unreachable).
    from datetime import date
    try:
        _today_iso = os.environ.get("AUDITOR_TODAY") or date.today().isoformat()
    except Exception:
        _today_iso = "1970-01-01"
    try:
        _eol_list, _base_block = _lifecycle("debian", carriers, _eol_fetch, _today_iso)
    except Exception as e:
        print("lifecycle lookup failed: %s" % e); _eol_list, _base_block = [], {}

    manifest = {
        "commit": commit, "module": module, "base_os": "debian",
        "candidate_variant": "production", "candidate_digests": {"production": digest},
        "scanner_reports": scanner_reports, "scanner_status": status,
        "govulncheck": gvc, "known_defect_log": kdl if os.path.exists(kdl) else None,
        "kev_catalog": cli.opt("--kev"),
        # REQ-AUD-14: SBOM carrier relationships (candidate not-pullable carriers) + the
        # endoflife.date maintenance flags (carriers/base on LTS/EOL lines) and the base pin-lag
        # block. `eol`/`base` are best-effort (empty when endoflife.date is unreachable).
        "carriers": carriers, "eol": _eol_list, "base": _base_block,
        "provenance": {"source": ("test-image" if test_image else "own-scan"), "candidate": src,
                       "scanned": "docker-archive"},
    }
    # If three scanners inventoried packages but osv-scanner found none, name the known
    # cause (osv-scanner reads /var/lib/dpkg/status, not a distroless status.d directory).
    others = [k for k in ("grype", "trivy", "snyk") if (status.get(k) or {}).get("ran")]
    if not (status.get("osv-scanner") or {}).get("ran") and len(others) >= 2:
        status["osv-scanner"]["reason"] = "0 packages (osv-scanner does not read distroless dpkg status.d)"
    cli.writej(out, manifest)
    ran = [k for k in ("grype", "trivy", "osv-scanner", "snyk") if (status.get(k) or {}).get("ran")]
    print("auditor-manifest: wrote %s (digest %s; image scanners that ran: %s)" % (out, digest, ran or "NONE"))


if __name__ == "__main__":
    main()
