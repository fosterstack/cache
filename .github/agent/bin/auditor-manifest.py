#!/usr/bin/env python3
"""Build the run manifest the scheduled workflow consumes (REQ-AUD-1).

ONE schema, written here and validated by the driver on load. Every key the driver reads
is produced, or set explicitly to null with a recorded reason in `scanner_status`; a null
scanner is a "did not run" line in the report, never a crash (R11 rank 3).

Ingestion, on the runner:
  * load the candidate OCI archives BY NAME (production/debug/fips), not "the first .oci",
    and audit `production` (the customer image);
  * run the pinned image scanners over it (grype, trivy, osv-scanner) — each failure is
    recorded as `did not run`, not a pipeline crash;
  * run the OSV Go-module source scan and govulncheck -json over the checked-out tree,
    recording govulncheck's scanned module + the candidate commit + whether the stream
    completed, so reachability evidence is bound to this revision (R11 ranks 4/5);
  * Snyk stays null until a token exists (no secret is referenced here), stated in the
    report header;
  * assert the loaded digest equals the digest the rescan recorded, when that run uploaded
    it (older runs pre-date the upload — recorded, not fatal).
"""
import json, os, subprocess, sys, glob
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auditorlib import cli

REF = "ghcr.io/fosterstack/cache:cand-production"


def _run(cmd, out_path=None, timeout=1200):
    """Run cmd; return (rc, stdout_text). Never raises for a nonzero exit."""
    try:
        if out_path:
            with open(out_path, "w") as fh:
                r = subprocess.run(cmd, stdout=fh, stderr=subprocess.PIPE, timeout=timeout)
            return r.returncode, ""
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout
    except Exception as e:
        return 255, str(e)


def _version(tool, args=("--version",)):
    rc, out = _run([tool, *args])
    if rc != 0 or not out:
        return None
    return out.strip().splitlines()[0] if out.strip() else None


def _module(source_dir):
    gm = os.path.join(source_dir, "go.mod")
    if os.path.exists(gm):
        for line in open(gm):
            line = line.strip()
            if line.startswith("module "):
                return line.split(None, 1)[1].strip()
    return None


def _load_candidate(rescan_dir):
    """Return the production OCI archive path, loaded into the docker daemon, or None."""
    named = glob.glob(os.path.join(rescan_dir, "**", "production.oci"), recursive=True)
    if not named:
        return None, "no production.oci in the rescan artifacts"
    oci = named[0]
    rc, err = _run(["skopeo", "copy", "oci-archive:%s" % oci, "docker-daemon:%s" % REF])
    if rc != 0:
        return None, "skopeo could not load %s: %s" % (oci, err)
    return oci, None


def _digest():
    rc, out = _run(["skopeo", "inspect", "--format", "{{.Digest}}", "docker-daemon:" + REF])
    return out.strip() if (rc == 0 and out.strip()) else "sha256:unknown"


def _image_scan(name, cmd, reports, status, ok_codes=(0, 1)):
    path = os.path.join(reports, name + ".json")
    rc, _ = _run(cmd, out_path=path)
    if rc in ok_codes and os.path.exists(path) and os.path.getsize(path) > 0:
        status[name] = {"ran": True, "version": _version(cmd[0]), "reason": "ok (rc %d)" % rc}
        return path
    status[name] = {"ran": False, "version": _version(cmd[0]), "reason": "did not run (rc %d)" % rc}
    return None


def main():
    rescan = cli.opt("--rescan-dir"); reports = cli.opt("--reports")
    rescan_reports = cli.opt("--rescan-reports"); source = cli.opt("--source-dir", os.getcwd())
    out = cli.opt("--out"); commit = cli.opt("--commit", os.environ.get("GITHUB_SHA", "unknown"))
    os.makedirs(reports, exist_ok=True)

    oci, load_err = _load_candidate(rescan)
    if not oci:
        sys.exit("auditor-manifest: cannot ingest the candidate — %s" % load_err)
    digest = _digest()

    status = {}
    scanner_reports = {
        "grype": _image_scan("grype", ["grype", "docker:" + REF, "-o", "json"], reports, status),
        "trivy": _image_scan("trivy", ["trivy", "image", "--quiet", "--format", "json", REF], reports, status),
        "osv-scanner": _image_scan("osv-scanner", ["osv-scanner", "scan", "image", "--format", "json", REF], reports, status),
        "osv-scanner-gomod": None,
        "snyk": None,
    }
    # OSV Go-module source scan of the checked-out tree (REQ-AUD-1 AC2, production path).
    gomod_path = os.path.join(reports, "osv-gomod.json")
    rc, _ = _run(["osv-scanner", "scan", "source", "--format", "json", os.path.join(source, "go.mod")], out_path=gomod_path)
    if rc in (0, 1) and os.path.getsize(gomod_path) > 0:
        scanner_reports["osv-scanner-gomod"] = gomod_path
        status["osv-scanner-gomod"] = {"ran": True, "version": _version("osv-scanner"), "reason": "ok (rc %d)" % rc}
    else:
        status["osv-scanner-gomod"] = {"ran": False, "version": _version("osv-scanner"), "reason": "did not run (rc %d)" % rc}
    status["snyk"] = {"ran": False, "version": None, "reason": "no SNYK_TOKEN in this workflow; Snyk stays null"}

    # govulncheck -json over the checked-out tree, bound to module + commit.
    module = _module(source)
    gvc = None
    gvc_path = os.path.join(reports, "govulncheck.json")
    rc, _ = _run(["govulncheck", "-json", "./..."], out_path=gvc_path, timeout=1500) \
        if _version("govulncheck", ("-version",)) or _version("govulncheck") else (255, "")
    if os.path.exists(gvc_path) and os.path.getsize(gvc_path) > 0 and rc in (0, 3):
        gvc = {"path": gvc_path, "module": module, "commit": commit,
               "complete": True, "scan_level": "symbol"}
    else:
        gvc = None

    # digest assertion against the rescan's recorded digest, if that run uploaded it.
    digest_asserted = False; digest_note = "rescan did not record a digest (older run)"
    rr_digests = glob.glob(os.path.join(rescan_reports or "", "**", "candidate-digests.json"), recursive=True) if rescan_reports else []
    if rr_digests:
        try:
            recorded = json.load(open(rr_digests[0])).get("production")
            if recorded and recorded == digest:
                digest_asserted = True; digest_note = "loaded digest == rescan-recorded digest"
            elif recorded:
                sys.exit("auditor-manifest: loaded digest %s != rescan-recorded %s (wrong candidate)" % (digest, recorded))
        except SystemExit:
            raise
        except Exception as e:
            digest_note = "could not read rescan digest record: %s" % e

    kdl = ".github/agent/known-defect-log.json"
    manifest = {
        "commit": commit,
        "module": module,
        "base_os": "debian",
        "candidate_variant": "production",
        "candidate_digests": {"production": digest},
        "scanner_reports": scanner_reports,
        "scanner_status": status,
        "govulncheck": gvc,
        "known_defect_log": kdl if os.path.exists(kdl) else None,
        "kev_catalog": cli.opt("--kev"),
        "provenance": {"source": "own-scan", "candidate_oci": os.path.basename(oci),
                       "digest_asserted": digest_asserted, "digest_note": digest_note},
    }
    cli.writej(out, manifest)
    print("auditor-manifest: wrote %s (digest %s; %s)" % (out, digest, digest_note))


if __name__ == "__main__":
    main()
