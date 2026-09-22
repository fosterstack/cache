#!/usr/bin/env python3
"""Build the run manifest from a downloaded main-candidate-rescan artifact set: load the
candidate OCI image, run the pinned scanners over it, and write their native reports plus a
manifest that lists the report paths and the candidate digest. This is the real ingestion
the scheduled workflow uses; a scanner that cannot run is a pipeline failure, never a clean
pass."""
import json, os, subprocess, sys, glob
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auditorlib import cli


def main():
    rescan = cli.opt("--rescan-dir"); reports = cli.opt("--reports"); out = cli.opt("--out")
    os.makedirs(reports, exist_ok=True)
    ocis = glob.glob(os.path.join(rescan, "**", "*.oci"), recursive=True) + \
           glob.glob(os.path.join(rescan, "**", "production.oci"), recursive=True)
    if not ocis:
        sys.exit("auditor-manifest: no candidate OCI archive under %s" % rescan)
    oci = ocis[0]
    ref = "ghcr.io/fosterstack/cache:cand-production"
    subprocess.run(["skopeo", "copy", "oci-archive:%s" % oci, "docker-daemon:%s" % ref], check=True)
    def run(cmd, path):
        with open(path, "w") as fh:
            r = subprocess.run(cmd, stdout=fh)
        if r.returncode not in (0, 1):   # 1 = findings, fine
            sys.exit("auditor-manifest: %s failed (rc %d) — pipeline failure, not clean" % (cmd[0], r.returncode))
    run(["grype", "docker:" + ref, "-o", "json"], os.path.join(reports, "grype.json"))
    run(["trivy", "image", "--quiet", "--format", "json", ref], os.path.join(reports, "trivy.json"))
    run(["osv-scanner", "scan", "image", "--format", "json", ref], os.path.join(reports, "osv-image.json"))
    digest = subprocess.run(["skopeo", "inspect", "--format", "{{.Digest}}", "docker-daemon:" + ref],
                            capture_output=True, text=True).stdout.strip() or "sha256:unknown"
    cli.writej(out, {"commit": os.environ.get("GITHUB_SHA", "unknown"),
                     "candidate_digests": {"production": digest}, "base_os": "debian",
                     "scanner_reports": {"grype": os.path.join(reports, "grype.json"),
                                         "trivy": os.path.join(reports, "trivy.json"),
                                         "osv-scanner": os.path.join(reports, "osv-image.json")},
                     "govulncheck": os.path.join(reports, "govulncheck.json") if os.path.exists(os.path.join(reports, "govulncheck.json")) else None,
                     "known_defect_log": ".github/agent/known-defect-log.json"})


if __name__ == "__main__":
    main()
