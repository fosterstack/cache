#!/usr/bin/env python3
"""Build the run manifest the scheduled workflow consumes (REQ-AUD-1).

ONE schema, written here and validated by the driver on load. Every key the driver reads
is produced, or set explicitly to null with a recorded reason in `scanner_status`.

The auditor runs NO scanner of its own (0600 option A, scanner-panel rules): the four panel
scanners' results are read from the rescan's verdict.json (`--panel-dir`), and a scanner that
did not run is recorded "did not run" with its reason, never clean. What this program still
produces itself: the candidate's SBOM carriers and base OS (syft), govulncheck over the source,
the endoflife.date lookups, and the candidate digest, all taken off a CONTAINER ARCHIVE
converted once with skopeo (no daemon).
"""
import hashlib, json, os, re, subprocess, sys, glob
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auditorlib import cli
from auditorlib import parsers as P
from auditorlib.parsers import PANEL_SCANNERS as PARSERS_PANEL_SCANNERS

TAG = "ghcr.io/fosterstack/cache:cand-production"
DATE_RE = re.compile(r"(\d{4}-\d{2}-\d{2})")


def _run(cmd, out_path=None, timeout=1500, cwd=None, env=None):
    try:
        if out_path:
            with open(out_path, "w") as fh:
                r = subprocess.run(cmd, stdout=fh, stderr=subprocess.PIPE, timeout=timeout, cwd=cwd, env=env)
            return r.returncode, (r.stderr.decode() if r.stderr else "")
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd, env=env)
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

PANEL_SCANNERS = PARSERS_PANEL_SCANNERS


def panel_inventory(verdict_path):
    """(scanner_reports, scanner_status) for the four panel scanners, from a STRICTLY validated verdict (ParseError
    otherwise). A scanner RAN only if, on every image the rule expects it on (Google: amd64 only), it is listed as ran
    WITH a package count above zero; an image where it is listed as did-not-run, not listed at all, or has no count
    makes it 'did not run', named with the image: never clean. The report is the verdict path for a scanner that ran,
    null for one that did not. The quorum (three scanners per image) is the panel's own decision, not recomputed."""
    d = P.validate_panel_verdict(P.load_panel_verdict(verdict_path))
    imgs = d["images"]
    reports, status = {}, {}
    for s in PANEL_SCANNERS:
        want = sorted(i for i in imgs if P.panel_expected(s, i))
        good = [i for i in want if s in imgs[i]["ran"]]          # the validator guarantees a positive integer count for each
        missed = [i for i in want if i not in good]
        ok = bool(want) and not missed
        reason = "ok" if ok else ("did not run on: %s" % ", ".join(missed) if missed else "no image reported this scanner")
        status[s] = {"ran": ok, "scan_ok": ok, "quorum_ok": ok, "version": None, "reason": reason,
                     "images_ran": len(good), "images_expected": len(want),
                     "package_count": sum(imgs[i]["counts"][s] for i in good)}
        reports[s] = verdict_path if ok else None
    return reports, status


def panel_block(panel_dir):
    """The manifest's 'panel' block. A missing directory, or one without verdict.json, records all four panel scanners
    'did not run' with that reason: the panel's audits cannot run, the day is incomplete, and nothing is reported clean
    because a file is missing."""
    vp = os.path.join(panel_dir, "verdict.json") if panel_dir else None
    if vp and os.path.exists(vp) and os.path.getsize(vp) > 0:
        try:
            reports, status = panel_inventory(vp)
            d = P.load_panel_verdict(vp)             # already validated by panel_inventory
            return {"verdict": vp, "scanner_reports": reports, "scanner_status": status,
                    "not_counted": d["not_counted"], "scanner_failures": d["scanner_failures"]}
        except (ValueError, OSError, AttributeError, TypeError, KeyError) as e:
            why = "panel-evidence verdict.json is unreadable: %s" % e
    else:
        why = "panel-evidence has no verdict.json" if panel_dir else "no panel-evidence directory was given"
    return {"verdict": None, "not_counted": None, "scanner_failures": None,       # unknown, so the day can never be called complete
            "scanner_reports": {s: None for s in PANEL_SCANNERS},
            "scanner_status": {s: {"ran": False, "scan_ok": False, "quorum_ok": False, "version": None, "reason": why,
                                   "images_ran": 0, "images_expected": 0, "package_count": 0} for s in PANEL_SCANNERS}}


def _base_os(path):
    """The base OS release from syft's `distro` block (e.g. 'debian 12.0') — REQ-AUD-14 AC7 needs
    the PINNED release, not a hardcoded 'debian', so the endoflife.date lookup matches the right
    cycle. None if syft did not report a distro."""
    try:
        dist = (json.load(open(path)).get("distro") or {})
        did = (dist.get("id") or "").strip().lower()
        ver = (dist.get("versionID") or "").strip()
    except Exception:                          # unreadable, or not an SBOM-shaped document
        return None
    if did and ver:
        return "%s %s" % (did, ver)
    return did or None


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
        by_id = {a.get("id"): a for a in (d.get("artifacts") or []) if a.get("id")}
        rels = list(d.get("artifactRelationships") or [])
        rels = [r for r in rels if r.get("type") in _CARRY_RELS]
    except (OSError, ValueError, AttributeError, TypeError):           # unreadable, or not an SBOM-shaped document: no carriers
        return []
    out = []; seen = set()
    for rel in rels:
        how = _CARRY_RELS[rel["type"]]
        parent = by_id.get(rel.get("parent")); child = by_id.get(rel.get("child"))
        if not parent or not child:
            continue
        cpurl = child.get("purl"); ppurl = parent.get("purl")
        # BOTH must be real, vulnerable-capable packages with a purl, and distinct: an image (no
        # purl) "contains" packages, and a package "contains" its own files (no purl) — neither is
        # a carrier relationship. Only a package that bundles another package counts.
        if not cpurl or not ppurl or parent.get("id") == child.get("id") or cpurl == ppurl:
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
        head, _, last = name.rpartition("/")        # a registry port (host:5000/...) is not a tag
        last = last.split(":", 1)[0]
        return "%s@%s" % ((head + "/" + last) if head else last, digest)
    return ref


def _archives(rescan_dir, test_image, oci, tar):
    """Produce BOTH an oci-archive and a docker-save tar (no daemon). grype reads the
    oci-archive directly (R12 item 2); the docker-save tar is the digest source. Returns
    (source_desc, err)."""
    if test_image:
        # the input says ref@digest; it is held to it — a tag-only reference could fetch any bytes the tag points at
        # (Codex #164 adversarial r2, N02: the non-shell boundary's own review question)
        if "@sha256:" not in test_image:
            return None, "test image %s is not pinned by digest (ref@sha256:…); refused" % test_image
        ref = "docker://" + _norm_ref(test_image)
        ok1 = _skopeo(ref, "oci-archive:%s:%s" % (oci, TAG))
        ok2 = _skopeo(ref, "docker-archive:%s:%s" % (tar, TAG))
        return (("test_image=%s" % test_image, None) if (ok1 or ok2) else (None, "skopeo could not pull %s" % ref))
    # Build's images artifact: one OCI layout DIRECTORY per variant (images/production/ with oci-layout, index.json, blobs/): the digest is the one Build
    # recorded. An archive file or a docker-save shape is not a candidate.
    named = [p for p in glob.glob(os.path.join(rescan_dir, "**", "production"), recursive=True)
             if os.path.isdir(p) and not os.path.islink(p) and os.path.isfile(os.path.join(p, "oci-layout"))]
    if not named:
        return None, "no production OCI layout directory (images/production) in the rescan artifacts"
    # every blob of the layout is re-hashed against its file name before skopeo reads it (fail closed): the candidate's identity is the digest Build recorded
    blobs = os.path.join(named[0], "blobs", "sha256")
    try:
        for n in os.listdir(blobs):
            p = os.path.join(blobs, n)
            with open(p, "rb") as fh:
                if os.path.islink(p) or hashlib.sha256(fh.read()).hexdigest() != n:
                    return None, "blob %s of the production layout does not hash to its name" % n[:12]
    except OSError as e:
        return None, "the production layout's blobs cannot be read (%s)" % type(e).__name__
    # production is a multi-arch index; select amd64 into a single-arch OCI archive that
    # syft can catalogue, and a docker-save tar for the digest lookup.
    src = "oci:%s" % named[0]
    ok1 = _skopeo(src, "oci-archive:%s:%s" % (oci, TAG))
    ok2 = _skopeo(src, "docker-archive:%s:%s" % (tar, TAG))
    return (os.path.basename(named[0]), None) if (ok1 or ok2) else (None, "skopeo convert failed")


def main():
    rescan = cli.opt("--rescan-dir"); reports = cli.opt("--reports")
    source = cli.opt("--source-dir"); out = cli.opt("--out")
    commit = cli.opt("--commit", "unknown")          # never the run's own sha: the field says which head the scanned image was built from; absent = "unknown"
    if cli.flag("--commit") and not re.fullmatch(r"[0-9a-f]{40}", commit or ""):   # a supplied value is 40-hex, whatever it is ("unknown" included)
        sys.exit("auditor-manifest: --commit must be a 40-hex commit id (the head the scanned image was built from) or absent, got %r" % (commit,))
    test_image = cli.opt("--test-image") or os.environ.get("AUDITOR_TEST_IMAGE") or ""
    kdl = cli.opt("--known-defect-log", ".github/agent/known-defect-log.json")
    os.makedirs(reports, exist_ok=True)

    tar = os.path.join(reports, "candidate.tar"); oci = os.path.join(reports, "candidate.oci")
    src, err = _archives(rescan, test_image, oci, tar)
    if not src:
        sys.exit("auditor-manifest: cannot ingest the candidate — %s" % err)
    have_oci = os.path.exists(oci) and os.path.getsize(oci) > 0
    have_tar = os.path.exists(tar) and os.path.getsize(tar) > 0
    print("archives: oci=%s tar=%s" % (have_oci, have_tar))

    panel_dir = cli.opt("--panel-dir")
    pblock = panel_block(panel_dir)           # 0600 option A: the auditor READS the panel's four scanners and runs none of its own
    scanner_reports = dict(pblock["scanner_reports"]); status = dict(pblock["scanner_status"])

    syft_src = ("oci-archive:" + oci) if have_oci else ("docker-archive:" + tar)
    syft_path = os.path.join(reports, "syft.json")
    carriers = []; base_os = "debian"
    rc, _ = _run(["syft", syft_src, "-o", "syft-json"], out_path=syft_path)
    if rc == 0 and os.path.exists(syft_path) and os.path.getsize(syft_path) > 0:
        carriers = _carriers(syft_path)   # REQ-AUD-14: SBOM carrier relationships (syft supplies the carriers and the base OS only)
        base_os = _base_os(syft_path) or base_os
    else:
        print("syft did not run (rc %d); the carriers and base OS stay unknown" % rc)

    # govulncheck -json over the checked-out tree, bound to module + commit.
    # The tree is the selected rescan's head (auditor.yml checks it out; it is DATA, never built or run by us beyond govulncheck's own
    # package loading): no toolchain download and no module fetch (GOTOOLCHAIN=local, -mod=vendor); with no such tree the scan is
    # recorded 'did not run', never run on the auditor's own checkout (rc-5b fix 4, ruling A2).
    has_tree = bool(source) and os.path.isdir(source) and commit != "unknown"   # a tree with no head to stamp it with is not bound to anything: not scanned
    module = _module(source) if has_tree else None; gvc = None
    gvc_path = os.path.join(reports, "govulncheck.json")
    have_gvc = has_tree and bool(_version("govulncheck", ("-version",)) or _version("govulncheck"))
    if not has_tree:
        print("govulncheck did not run: no source tree (or no head to bind it to) of the scanned image was given")
    genv = dict(os.environ, GOTOOLCHAIN="local", GOFLAGS="-mod=vendor", GOPROXY="off", CGO_ENABLED="0", GOENV="off")
    rc, gerr = _run(["govulncheck", "-json", "./..."], out_path=gvc_path, timeout=1500, cwd=source, env=genv) if have_gvc else (255, "")
    if has_tree and not have_gvc:
        print("govulncheck did not run: the tool is not installed")
    if os.path.exists(gvc_path) and os.path.getsize(gvc_path) > 0 and rc in (0, 3):
        gvc = {"path": gvc_path, "module": module, "commit": commit, "complete": True, "scan_level": "symbol"}
    elif have_gvc:
        print("govulncheck did not complete (rc %d) on %s: %s" % (rc, commit, " ".join(str(gerr).split())[-600:]))

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
        _eol_list, _base_block = _lifecycle(base_os, carriers, _eol_fetch, _today_iso)
    except Exception as e:
        print("lifecycle lookup failed: %s" % e); _eol_list, _base_block = [], {}

    manifest = {
        "commit": commit, "module": module, "base_os": base_os,
        "candidate_variant": "production", "candidate_digests": {"production": digest},
        "scanner_reports": scanner_reports, "scanner_status": status,
        "govulncheck": gvc, "known_defect_log": kdl if os.path.exists(kdl) else None,
        "kev_catalog": cli.opt("--kev"),
        # REQ-AUD-14: SBOM carrier relationships (candidate not-pullable carriers) + the
        # endoflife.date maintenance flags (carriers/base on LTS/EOL lines) and the base pin-lag
        # block. `eol`/`base` are best-effort (empty when endoflife.date is unreachable).
        "carriers": carriers, "eol": _eol_list, "base": _base_block,
        "panel": pblock,                                  # the scanner panel's four, from the rescan's verdict.json
        "scanner_set": "panel",
        "provenance": {"source": ("test-image" if test_image else "own-scan"), "candidate": src,
                       "scanned": "docker-archive"},
    }
    names = PANEL_SCANNERS
    cli.writej(out, manifest)
    ran = [k for k in names if (status.get(k) or {}).get("ran")]
    print("auditor-manifest: wrote %s (digest %s; image scanners that ran: %s)" % (out, digest, ran or "NONE"))


if __name__ == "__main__":
    main()
