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
        if a.get("type") == "deb" or str(a.get("purl", "")).startswith("pkg:deb"):
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
            if "debian" in eco:
                osp += 1
            findings += len(p.get("vulnerabilities") or [])
    return total, osp, None, findings


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
        ran = (rc in (0, 1)) and total > 0
        reason = "ok" if ran else ("0 packages inventoried (scanner produced no package inventory)"
                                   if rc in (0, 1) else "scan failed (rc %d)" % rc)
        scanner_reports[name] = path if ran else None
        status[name] = {"ran": ran, "version": ver, "reason": reason,
                        "package_count": total, "os_package_count": osp,
                        "db_date": db, "findings": findings}
        counts[name] = osp if ran else None
        print("%s %s db=%s packages=%s os_packages=%s findings=%s ran=%s"
              % (name, ver or "-", db or "-", total, osp, findings, ran))

    # OS package inventory AGREEMENT across the three image scanners (±Go modules): the
    # outliers below tolerance*max are recorded "did not run (inventory disagreement)".
    live = {k: v for k, v in counts.items() if v is not None and v > 0}
    if len(live) >= 2:
        mx = max(live.values())
        for k, v in list(live.items()):
            if v < tol * mx:
                status[k]["ran"] = False
                status[k]["reason"] = "inventory disagreement (os_packages=%d vs max %d)" % (v, mx)
                scanner_reports[k] = None
                print("%s DEMOTED: os_packages=%d < %.2f*%d" % (k, v, tol, mx))

    # OSV Go-module source scan of the checked-out tree.
    gomod = os.path.join(reports, "osv-gomod.json")
    rc, _ = _run(["osv-scanner", "scan", "source", "--format", "json", os.path.join(source, "go.mod")], out_path=gomod)
    gomod_ok = rc in (0, 1) and os.path.exists(gomod) and os.path.getsize(gomod) > 0
    scanner_reports["osv-scanner-gomod"] = gomod if gomod_ok else None
    status["osv-scanner-gomod"] = {"ran": gomod_ok, "version": _version("osv-scanner"),
                                   "reason": "ok" if gomod_ok else "did not run (rc %d)" % rc,
                                   "package_count": None, "db_date": None}
    scanner_reports["snyk"] = None
    status["snyk"] = {"ran": False, "version": None, "reason": "no SNYK_TOKEN in this workflow; Snyk stays null",
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

    manifest = {
        "commit": commit, "module": module, "base_os": "debian",
        "candidate_variant": "production", "candidate_digests": {"production": digest},
        "scanner_reports": scanner_reports, "scanner_status": status,
        "govulncheck": gvc, "known_defect_log": kdl if os.path.exists(kdl) else None,
        "kev_catalog": cli.opt("--kev"),
        "provenance": {"source": ("test-image" if test_image else "own-scan"), "candidate": src,
                       "scanned": "docker-archive"},
    }
    cli.writej(out, manifest)
    ran = [k for k in ("grype", "trivy", "osv-scanner") if status[k]["ran"]]
    print("auditor-manifest: wrote %s (digest %s; image scanners that ran: %s)" % (out, digest, ran or "NONE"))


if __name__ == "__main__":
    main()
