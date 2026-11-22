#!/usr/bin/env bash
# proves: REQ-REL-010-AC1, REQ-REL-010-AC3, REQ-SCAN-001-AC1, REQ-SCAN-001-AC2, REQ-SCAN-001-AC3, REQ-SCAN-002-AC1, REQ-SCAN-004-AC1, REQ-SCAN-004-AC2, REQ-SCAN-009-AC5, REQ-REL-004-AC3
# The scanner panel's wiring in the daily rescan (scanner-panel rules 1, 2, 4, 9; ratified Oct 2): which
# scanner runs on which images (fixed in the workflow, never computed), Google only through the federation
# with repository variables, the VEX as the only exception (Grype and Scout given the file, no ignore
# options anywhere), Trivy and Snyk gone from the panel, and no audit in the rescan (the auditor judges unique findings). The
# real workflow must pass; each mutated copy must be caught.
set -euo pipefail
TMPDIR=$(mktemp -d); export TMPDIR; trap 'rm -rf "$TMPDIR"' EXIT  # python tempfile and mktemp dirs all live under this one, removed on exit
root=$(cd "$(dirname "$0")/.." && pwd)
export PANEL_ROOT="$root"
work=$(mktemp -d); mkdir "$work/memo"; export PANEL_MEMO="$work/memo"; trap 'rm -rf "$work" "$TMPDIR"' EXIT
pass=0 failn=0
judge() { python3 - "$1" <<'PY'
import re, sys, yaml
d = yaml.load(open(sys.argv[1]), Loader=yaml.BaseLoader)
jobs = d.get("jobs", {})
bad = []
def text(j): return "\n".join((s.get("run") or "") for s in jobs.get(j, {}).get("steps", []))
def uses(j): return [str(s.get("uses", "")) for s in jobs.get(j, {}).get("steps", [])]
VAR = ("production", "fips")
for j in ("panel-grype", "panel-scout", "panel-inspector", "panel-google", "panel"):
    if j not in jobs:
        bad.append(f"no {j} job")
if bad:
    print("; ".join(bad)); sys.exit(1)
# rule 1: the fixed image set, written in the workflow
for j in ("panel-grype", "panel-scout", "panel-inspector"):
    t = text(j)
    if "for v in production fips" not in t or "for arch in amd64 arm64" not in t:
        bad.append(f"{j} does not scan the four images (production and fips, each on both architectures), fixed in the workflow")
tg = text("panel-google")
if "for v in production fips" not in tg or "arm64" in tg or "for arch" in tg \
        or "layout-archive.sh \"/tmp/oci/${v}\" amd64" not in tg or 'cand-${v}-amd64"' not in tg:
    bad.append("panel-google does not scan exactly the two variants on linux/amd64 (and never arm64)")
for j in jobs:
    # manifests/rescan are the PUBLISHED-release rescan (merged from daily-rescan.yml, consolidation 3 of 4;
    # REQ-REL-003), which runs only the scanners in .github/policy/scanners.json — neither is the scanner panel.
    # The old scanner-reports job (trivy/osv-scanner reports for the auditor) is gone: the auditor reads the panel
    if any(x in (text(j) + " ".join(uses(j))).lower() for x in ("trivy", "snyk", "osv-scanner")) and j not in ("manifests", "rescan"):
        bad.append(f"{j} runs Trivy, Snyk or OSV-Scanner")
for gone in ("scan-main", "trivy-main", "snyk-main", "scanner-reports"):
    if gone in jobs:
        bad.append(f"the retired {gone} job is still there")
# rule 2: Google through the federation, identifiers from repository variables, no secrets, no keys
gj = jobs["panel-google"]
if (gj.get("permissions") or {}).get("id-token") != "write":
    bad.append("panel-google lacks id-token: write")
auth = [s for s in gj.get("steps", []) if str(s.get("uses", "")).startswith("google-github-actions/auth@")]
w = (auth[0].get("with") or {}) if auth else {}
if not auth or w.get("workload_identity_provider") != "${{ vars.CACHE_SCANNER_PROVIDER }}" \
        or w.get("service_account") != "${{ vars.CACHE_SCANNER_SERVICE_ACCOUNT }}" or "credentials_json" in w:
    bad.append("panel-google does not authenticate through the federation with the two repository variables")
if "secrets." in str(gj) or "GOOGLE_APPLICATION_CREDENTIALS" in tg:
    bad.append("panel-google uses a secret or a key file")
# rule 4: the VEX is the only exception
if "--vex .vex/fosterstack-cache.openvex.json" not in text("panel-grype"):
    bad.append("Grype is not given the VEX file")
# REQ-REL-010 on the rescan (release audit row C1, ruled, security): the rescan stays mechanical. VEX reaches the image only in a release, never changing a digest
# customers pull or a signature names; no rule gives a rescan job a write. So there is no vex-attach job, no registry write in any job of this file, and
# panel-scout scans the candidate layouts it downloads from Build's artifact `images` (the input panel-grype uses) as images loaded into the runner's Docker (by image id), given our OpenVEX file.
import json, os, shlex, subprocess, tempfile
ROOT = os.environ.get("PANEL_ROOT", ".")
OPENVEX = ".vex/fosterstack-cache.openvex.json"
if (d.get("concurrency") or {}).get("group") != "main-candidate-rescan" or str((d.get("concurrency") or {}).get("cancel-in-progress")).lower() != "false":
    bad.append("the rescan is not serialized without cancelling")
# 1. no vex-attach, and no registry write anywhere in the file (build is the caller of release.yml in snapshot mode: its grant is the callee's ceiling)
if "vex-attach" in jobs:
    bad.append("the vex-attach job is still there (a rescan job has no write)")
for name, jb in [("the top level", d)] + list(jobs.items()):
    perms = jb.get("permissions")
    if name != "build" and (perms == "write-all" or (isinstance(perms, dict) and str(perms.get("packages")) == "write")):
        bad.append("%s holds packages: write" % name)
if jobs.get("build", {}).get("uses") != "./.github/workflows/release.yml" or (jobs["build"].get("with") or {}).get("mode") != "snapshot" or jobs["build"].get("steps"):
    bad.append("build is not exactly the caller of release.yml in snapshot mode")
for name, jb in jobs.items():
    jt = text(name) + "\n" + " ".join(uses(name))
    if re.search(r"\bskopeo\s+copy\b|\bdocker\s+(image\s+)?push\b|\b(crane|oras)\s+(push|copy|cp|append|mutate|tag)\b|\bregctl\b[^\n]*\b(copy|push)\b|docker/login-action", jt):
        bad.append("%s runs a registry write or a login action" % name)
    if name != "build" and re.search(r"login[^\n]*ghcr\.io|ghcr\.io[^\n]*login", jt) and (jb.get("permissions") or {}).get("packages") not in (None, "read"):
        bad.append("%s logs in to ghcr.io with more than packages: read" % name)
if "cache-scout-probe" in str(d.get("jobs")):
    bad.append("a job names the scratch package ghcr.io/fosterstack/cache-scout-probe")
# 2. panel-scout: needs exactly build; exactly contents: read; keeps environment agent; no attach artifact, no ghcr.io login, no registry scan, no fixture digests
ps = jobs.get("panel-scout", {})
scout_steps = ps.get("steps", [])
pneeds = ps.get("needs", []); pneeds = pneeds if isinstance(pneeds, list) else [pneeds]
if pneeds != ["build"]:
    bad.append("panel-scout does not wait for exactly the build: %s" % pneeds)
if ps.get("permissions") != {"contents": "read"}:
    bad.append("panel-scout must hold exactly contents: read: %s" % ps.get("permissions"))
if ps.get("environment") != "agent":
    bad.append("panel-scout is not in the agent environment (the read-only Docker Hub token for Scout lives there)")
st_text = text("panel-scout")
all_scout = str(ps)
if re.search(r"login[^\n]*ghcr\.io|ghcr\.io[^\n]*login", st_text) or re.search(r"docker/login-action", " ".join(uses("panel-scout"))):
    bad.append("panel-scout logs in to ghcr.io")
if "registry://" in all_scout:
    bad.append("panel-scout scans or names a registry:// reference")
if re.search(r"digests\.json|fixture|/attach\b|\bskopeo\b", all_scout):
    bad.append("panel-scout reads fixture digests or an attach folder, or runs skopeo")
sdl = [x for x in scout_steps if str(x.get("uses", "")).startswith("actions/download-artifact@")]
if len(sdl) != 1 or sdl[0].get("with") != {"name": "images", "path": "/tmp/oci/"}:
    bad.append("panel-scout does not download exactly Build's artifact images into /tmp/oci/ (the input panel-grype uses): %s" % [x.get("with") for x in sdl])
hub = [x for x in scout_steps if "log in to Docker Hub for Scout" in (x.get("name") or "")]
if len(hub) != 1 or "docker login docker.io" not in hub[0].get("run", "") or "DOCKERHUB_SCOUT_TOKEN" not in str(hub[0].get("env")) or "$DOCKERHUB_SCOUT_TOKEN" not in hub[0].get("run", "") or "--password-stdin" not in hub[0].get("run", ""):
    bad.append("panel-scout does not log in to Docker Hub with the read-only Scout token")
# 3. the scan: one step, each downloaded layout's child made into a tar, loaded into Docker and scanned by image id, our OpenVEX as a file, our author; run it against a stub docker
if not os.path.isfile(os.path.join(ROOT, "bin", "scout-selfcheck.py")):
    bad.append("bin/scout-selfcheck.py is gone")
scans = [x for x in scout_steps if "docker scout cves" in (x.get("run") or "")]
if len(scans) != 1:
    bad.append("panel-scout has not exactly one step that runs docker scout cves: %d" % len(scans))
else:
    scan = scans[0]
    if hub and scout_steps.index(hub[0]) > scout_steps.index(scan):
        bad.append("the Scout scan runs before the Docker Hub log-in")
    def run_scan(failing):
        with tempfile.TemporaryDirectory() as t0:
            t = os.path.realpath(t0)
            os.makedirs(os.path.join(t, "stub"))
            with open(os.path.join(t, "stub", "docker"), "w") as fh:
                fh.write("#!/usr/bin/env bash\n" + ("exit 23\n" if failing else
                         '{ printf docker; printf \' %q\' "$@"; printf \'\\n\'; } >> "$STUB_LOG"\n'
                         'if [ "$1 $2" = "image inspect" ]; then t=${!#}; printf "sha256:%s" "${t##*:}"; exit 0; fi\n'
                         'if [ "$1 $2" = "scout cves" ]; then printf \'{"vulnerabilities":[]}\'; else printf \'{"artifacts":[]}\'; fi\n'))
            os.chmod(os.path.join(t, "stub", "docker"), 0o755)
            with open(os.path.join(t, "stub", "layout-archive.sh"), "w") as fh:
                fh.write('#!/usr/bin/env bash\n{ printf layout-archive; printf \' %q\' "$@"; printf \'\\n\'; } >> "$STUB_LOG"\n: > "$3"\n')
            os.chmod(os.path.join(t, "stub", "layout-archive.sh"), 0o755)
            log = os.path.join(t, "log"); open(log, "w").close()
            env = dict(os.environ, PATH=os.path.join(t, "stub") + ":" + os.environ["PATH"], STUB_LOG=log, RUNNER_TEMP=t)
            r = subprocess.run(["bash", "-e", "-c", scan["run"].replace("/tmp/panel/", t + "/panel/").replace("./bin/layout-archive.sh", t + "/stub/layout-archive.sh").replace("/tmp/arc", t + "/arc")], cwd=ROOT, env=env, capture_output=True, text=True)
            made = {(v, a): os.path.isfile(os.path.join(t, "panel", "scout", "%s-%s" % (v, a), "cves.json")) for v in VAR for a in ("amd64", "arm64")}
            gone = {(v, a): not os.path.exists(os.path.join(t, "panel", "scout", "%s-%s" % (v, a))) for v in VAR for a in ("amd64", "arm64")}
            return r.returncode, r.stdout + r.stderr, [shlex.split(l) for l in open(log).read().splitlines()], made, gone
    rc, out, calls, made, _ = run_scan(False)
    if rc != 0:
        bad.append("the Scout scan step fails on a clean day: %s" % out[-300:])
    cves = [c for c in calls if c[1:3] == ["scout", "cves"]]
    sboms = [c for c in calls if c[1:3] == ["scout", "sbom"]]
    def opt(c, flag):
        return c[c.index(flag) + 1] if flag in c[:-1] else None
    def ref_of(c):   # the stub's image id names the tag the scan inspected: sha256:cand-<variant>-<arch>
        m = re.fullmatch(r"local://sha256:cand-(production|fips)-(amd64|arm64)", c[-1])
        return (m.group(1), m.group(2)) if m else (None, None)
    seen = []
    for c in cves:
        v, ia = ref_of(c)
        a = (opt(c, "--platform") or "").replace("linux/", "")
        seen.append((v, a))
        if ia != a:
            bad.append("a Scout scan is given the image of another architecture than its --platform: %s" % " ".join(c))
        if opt(c, "--format") != "gitlab" or opt(c, "--vex-location") != OPENVEX or opt(c, "--vex-author") != "^FosterStack LLC$" or a not in ("amd64", "arm64"):
            bad.append("a Scout scan is not given --format gitlab, our OpenVEX file as --vex-location, our author and a linux/<arch> platform: %s" % " ".join(c))
    if sorted(seen, key=str) != sorted([(v, a) for v in VAR for a in ("amd64", "arm64")], key=str):
        bad.append("Scout does not scan the four loaded images (local://<image id>, production and fips, amd64 and arm64) once each: %s" % seen)
    for c in sboms:
        if ref_of(c)[0] is None or ref_of(c)[1] != opt(c, "--platform").replace("linux/", ""):
            bad.append("a Scout sbom call does not use the local image id of its own variant and architecture: %s" % " ".join(c))
    made_from = sorted((c[1], c[2]) for c in calls if c[0] == "layout-archive")
    if made_from != sorted(("/tmp/oci/" + v, a) for v in VAR for a in ("amd64", "arm64")):
        bad.append("the Scout scan does not make each tar from the downloaded layout /tmp/oci/<variant> and its architecture: %s" % made_from)
    loads = [c for c in calls if c[1:2] == ["load"]]
    if len(loads) != 4 or not all(c[2] == "-i" and c[3].endswith(".tar") for c in loads):
        bad.append("the Scout scan does not load each of the four image tars into Docker once: %s" % loads)
    if not all(made.values()):
        bad.append("the Scout scan does not leave /tmp/panel/scout/<variant>-<arch>/cves.json for each image: %s" % made)
    rc, out, calls, _, gone = run_scan(True)
    if rc != 0 or not all(gone.values()) or "::warning::" not in out:
        bad.append("a Scout scan that fails does not remove its output directory and warn (rc %s)" % rc)
for j in ("panel-grype", "panel-scout", "panel-inspector", "panel-google"):
    if re.search(r"--(ignore|only-fixed|exclude|ignore-base|only-severity|severity)\b|\.grype\.yaml|suppress", text(j)):
        bad.append(f"{j} carries an ignore or severity option")
# rc-5a D1 (Fable R4, astra B4): Grype runs with an empty config file and refuses GRYPE_* variables (as bin/grype-scan.sh does), and a failed Grype or Scout
# command removes that image's output directory, so a readable partial report can never count as "ran" (the contract: fewer outputs = did not run)
tg_ = text("panel-grype")
if not re.search(r'grype "docker-archive:/tmp/arc/\$\{v\}-\$\{arch\}\.tar" -c "\$RUNNER_TEMP/empty-grype\.yaml"', tg_) or not re.search(r': > "\$RUNNER_TEMP/empty-grype\.yaml"', tg_):
    bad.append("panel-grype does not run grype with -c on an empty file made in the step")
if "grype db update -c \"$RUNNER_TEMP/empty-grype.yaml\"" not in tg_ or len(re.findall(r"\bgrype (?:db update|\"docker(?:-archive)?:)", tg_)) != len(re.findall(r"\bgrype (?:db update -c|\"docker-archive:[^\"]*\" -c) \"\$RUNNER_TEMP/empty-grype\.yaml\"", tg_)):
    bad.append("panel-grype runs a grype command (the database update or a scan) without -c on the empty config")
if "grep -vx 'GRYPE_DB_CACHE_DIR\\|GRYPE_DB_AUTO_UPDATE'" not in tg_:
    bad.append("panel-grype's GRYPE_* refusal does not allow the two cache variables bin/grype-scan.sh allows")
if not re.search(r"compgen -e \| grep '\^GRYPE_'", tg_) or "exit 2" not in tg_.split("compgen -e", 1)[-1].split("done", 1)[0]:
    bad.append("panel-grype does not refuse a GRYPE_* variable in the environment before it runs")
if not re.search(r'\|\| \{[^}]*rm -rf "\$\{d\}"', tg_):
    bad.append("panel-grype does not remove the image's output directory when grype fails")
ts_ = text("panel-scout")
if not re.search(r'\|\| \{[^}]*rm -rf "\$\{d\}"', ts_):
    bad.append("panel-scout does not remove the image's output directory when docker scout fails")
# rc-5a D2 (astra B6, Fable R3 and R4): the published-release rescan holds to the same rules as the gates. Grype reads an empty config, refuses GRYPE_*, and also writes
# a CycloneDX inventory; osv-scanner reads an empty config, refuses OSV_SCANNER_*, and lists every package and every vulnerability; each child's package count
# (components with a purl; osv's results[].packages[]) goes into children-scanned.jsonl, and bin/rescan-statement.py refuses a completed child without one.
rs_ = (jobs.get("rescan") or {}).get("steps", [])
gs_ = [x.get("run") or "" for x in rs_ if x.get("id") == "grype"]
os_ = [x.get("run") or "" for x in rs_ if x.get("id") == "osv"]
if len(gs_) != 1 or len(os_) != 1:
    bad.append("the rescan job lacks its one grype step or its one osv-scanner step")
else:
    g_, o_ = gs_[0], os_[0]
    if not re.search(r'grype "registry:\$\{ref\}" \$plat_arg\s+-c /tmp/empty-grype\.yaml', g_) or not re.search(r': > /tmp/empty-grype\.yaml', g_):
        bad.append("the published grype step does not run with -c on an empty file made in the step")
    if not re.search(r"compgen -e \| grep '\^GRYPE_'", g_) or "exit 2" not in g_.split("compgen -e", 1)[-1].split("install-scanner", 1)[0]:
        bad.append("the published grype step does not refuse a GRYPE_* variable before it runs")
    if '-o "json=${out}"' not in g_ or '-o "cyclonedx-json=${sbom}"' not in g_:
        bad.append("the published grype step does not write both its JSON report and a CycloneDX inventory")
    if "[[ \"${pk}\" =~ ^[0-9]+$ ]] || pk=0" not in g_ or "[[ \"${pk}\" =~ ^[0-9]+$ ]] || pk=0" not in o_:
        bad.append("a published step records a package count that is not a plain integer (an empty or odd jq result would stop the loop before the child's record is written)")
    st_ = [x.get("run") or "" for x in rs_ if x.get("id") == "statement"]
    if len(st_) != 1 or '--expect-children "$(grep -c . /tmp/children.txt)"' not in st_[0]:
        bad.append("the statement step does not pass the number of enumerated children (--expect-children): a shorter manifest must be an error")
    if "grep -vx 'GRYPE_DB_CACHE_DIR\\|GRYPE_DB_AUTO_UPDATE'" not in g_:
        bad.append("the published grype step's GRYPE_* refusal does not allow the two cache variables bin/grype-scan.sh allows")
    pk_lines = [ln for ln in g_.splitlines() if ln.strip().startswith("pk=$(jq ")]   # a comment that quotes the line is not the line
    pk_ = re.fullmatch(r"pk=\$\(jq '([^']+)' \"\$\{sbom\}\" 2>/dev/null\) \|\| pk=0", pk_lines[0].strip()) if len(pk_lines) == 1 else None
    if not pk_ or "packages:$k" not in g_.replace(" ", ""):
        bad.append("the published grype step does not record the child's package count (components with a package URL) in children-scanned.jsonl")
    else:   # the count runs on inventories: only a package URL (pkg:<type>/<name>) is a package, never a file, a number or not-a-purl
        real, junk = "pkg:deb/debian/glibc@2.36", ["not-a-purl", "pkg:", "pkg:/", "pkg:deb/", 7, None, "pkg:golang/"]
        for want, purls in ((0, []), (1, [real]), (0, junk), (2, [real, "pkg:golang/github.com/a/b@v1"] + junk)):
            inv = {"components": [{"purl": x} for x in purls] + [{"type": "file", "name": "/x"}]}
            run = subprocess.run(["jq", pk_.group(1)], input=json.dumps(inv), capture_output=True, text=True)
            if run.returncode != 0 or run.stdout.strip() != str(want):
                bad.append("the grype step's count is %r (exit %d), not %d, on %d package URLs among %d components"
                           % (run.stdout.strip(), run.returncode, want, want, len(inv["components"])))
    if not re.search(r"osv-scanner scan image --config /tmp/empty-osv\.toml --all-packages --all-vulns --format json", o_) or not re.search(r': > /tmp/empty-osv\.toml', o_):
        bad.append("the published osv-scanner step does not run with an empty config, --all-packages and --all-vulns")
    if not re.search(r"compgen -e \| grep '\^OSV_SCANNER_'", o_) or "exit 2" not in o_.split("compgen -e", 1)[-1].split("install-scanner", 1)[0]:
        bad.append("the published osv-scanner step does not refuse an OSV_SCANNER_* variable before it runs")
    if "results[]?.packages[]?" not in o_ or "packages:$k" not in o_.replace(" ", ""):
        bad.append("the published osv-scanner step does not record the child's package count in children-scanned.jsonl")
# rule 9 (owner, Oct 3): the AI judging lives in the auditor; the rescan's panel job tallies and cannot audit
pj = jobs["panel"]
if "id-token" in (pj.get("permissions") or {}) or pj.get("environment") or re.search(r"profiles|audit|--prior", text("panel")):
    bad.append("the rescan's panel job can audit (identity, environment, profiles or history): the auditor judges unique findings")
# the tally step (one step, the verdict the auditor reads)
pj = jobs["panel"]
judge_steps = [s for s in pj.get("steps", []) if "bin/panel.py tally" in (s.get("run") or "")]
if len(judge_steps) != 1 or "if" in judge_steps[0] and "always()" not in judge_steps[0]["if"]:
    bad.append("no single step runs `bin/panel.py tally`")
if any(re.search(r"\b(schedule|workflow_run|repository_dispatch)\b", str(s)) for s in pj.get("steps", [])):
    bad.append("the panel defers audits to another workflow")
needs = pj.get("needs", [])
if sorted(needs if isinstance(needs, list) else [needs]) != ["panel-google", "panel-grype", "panel-inspector", "panel-scout"] or "always()" not in pj.get("if", ""):
    bad.append("the panel does not wait for all four scanners whatever their outcome")
# the run is daily, and nothing in the panel is switched off or allowed to fail quietly
crons = [c.get("cron", "") for c in ((d.get("on") or {}).get("schedule") or []) if isinstance(c, dict)]
if not any(re.fullmatch(r"\d{1,2} \d{1,2} \* \* \*", c.split("#")[0].strip()) for c in crons):
    bad.append("the rescan has no daily schedule")
# the exact scan commands: each architecture once, Google's package count from its request log
for j in ("panel-grype", "panel-inspector"):
    t = text(j)
    # panel-inspector makes its tars in a step of their own, before the cache restore, then scans each: two loops
    loops = 2 if j == "panel-inspector" else 1
    if not re.search(r"for arch in amd64 arm64; do", t) or t.count("for arch in") != loops \
            or 'layout-archive.sh "/tmp/oci/${v}" "${arch}"' not in t or 'cand-${v}-${arch}' not in t:
        bad.append(f"{j} does not load each architecture once by the loop variable")
t = text("panel-scout")      # Scout names the platform of an attested index, each architecture once
if not re.search(r"for arch in amd64 arm64; do", t) or "for v in production fips" not in t:
    bad.append("panel-scout does not scan each variant on each architecture once by the loop variables")
if "--log-http" not in tg or "bin/panel.py google-packages" not in tg or "list-vulnerabilities" not in tg:
    bad.append("panel-google does not take its package count from the request log and its findings from list-vulnerabilities")
if jobs["panel-google"].get("environment") != "agent":
    bad.append("panel-google is not in the main-only agent environment (its identity admits a scheduled main run only there)")
for j in ("panel-grype", "panel-scout", "panel-inspector", "panel-google", "panel"):
    if "if" in jobs[j] and j != "panel":
        bad.append(f"{j} is conditional")
    for st in jobs[j].get("steps", []):
        cond = str(st.get("if", "")).replace(" ", "")
        # REQ-REL-004-AC8: the Inspector job's two same-day-reuse cache steps (stock actions/cache restore and save, pinned) carry the
        # same-repo condition; bin/inspector-reuse-test.sh pins their exact form. No other step of any job may be conditional.
        cache = j == "panel-inspector" and re.match(r"actions/cache/(restore|save)@[0-9a-f]{40}$", str(st.get("uses", ""))) \
            and "github.event_name!='pull_request'||github.event.pull_request.head.repo.full_name==github.repository" in cond
        # the save-time UTC day step (midnight fix) runs under plain always(), like the save it feeds
        saveday = j == "panel-inspector" and st.get("id") == "insp-save-day" and cond == "always()"
        # the panel job's four downloads by artifact id carry exactly the non-empty-id guard (checked in full by the artifact section below)
        dlguard = j == "panel" and str(st.get("uses", "")).startswith("actions/download-artifact@") and re.fullmatch(r"\$\{\{needs\.panel-(grype|scout|inspector|google)\.outputs\.artifact-id!=''\}\}", cond)
        if cond and not cache and not saveday and not dlguard and not cond.startswith("${{always()") and cond != "${{!cancelled()}}" and "steps.judge" not in cond:
            bad.append(f"{j}: step {st.get('name')!r} is conditional ({st.get('if')})")
        if str(st.get("continue-on-error", "false")) != "false" and "download-artifact" not in str(st.get("uses", "")):
            bad.append(f"{j}: step {st.get('name')!r} may fail quietly")
issue = [st for st in pj.get("steps", []) if "gh issue create" in (st.get("run") or "") and "gh issue comment" in (st.get("run") or "")]
if len(issue) != 1 or "refs/heads/main" not in str(issue[0].get("if", "")) or "issue.md" not in issue[0].get("run", ""):
    bad.append("no step opens or updates the tracking issue from main with the tally's issue text")
elif re.search(r"^\s*exit 0\s*$", issue[0]["run"], re.M) or issue[0]["run"].count("exit 0") != 1:
    bad.append("the issue step can exit before filing")
js = judge_steps[0].get("run", "") if judge_steps else ""
if 'echo "rc=$?" >> "$GITHUB_OUTPUT"' not in js or not re.search(r"bin/panel\.py tally[^\n]*(\\\n[^\n]*)*\n\s*echo \"rc=\$\?\"", js):
    bad.append("the tally's exit code is not what the panel exports")
last = pj.get("steps", [])[-1] if pj.get("steps") else {}
if "steps.judge.outputs.rc != '0'" not in str(last.get("if", "")) or "exit 1" not in (last.get("run") or ""):
    bad.append("the panel's last step does not fail the run when the judge's verdict is not clean")
# one folder per scanner artifact (the Witness adversarial pass, cache#602): each scanner job uploads exactly one artifact panel-<scanner> from /tmp/panel/ and exposes its id; the
# panel job downloads each of the four BY ARTIFACT ID (not by name or pattern, so one artifact can never stand for another) into its own fixed folder, only when the id is not empty
# (an empty id would download every artifact), and each scanner job writes only its own scanner's folder under /tmp/panel/
PANEL_SC = ("grype", "scout", "inspector", "google")
for sc in PANEL_SC:
    jb = jobs["panel-" + sc]
    ups = [st for st in jb.get("steps", []) if str(st.get("uses", "")).startswith("actions/upload-artifact@")]
    if len(ups) != 1 or (ups[0].get("with") or {}).get("name") != "panel-" + sc or (ups[0].get("with") or {}).get("path") != "/tmp/panel/" or ups[0].get("id") != "upload":
        bad.append(f"panel-{sc} does not upload exactly one artifact panel-{sc} from /tmp/panel/ with the step id upload")
    if jb.get("outputs") != {"artifact-id": "${{ steps.upload.outputs.artifact-id }}"}:
        bad.append(f"panel-{sc} does not expose exactly the artifact-id of its upload: {jb.get('outputs')}")
    tops = set(re.findall(r"/tmp/panel/([A-Za-z0-9_-]+)", text("panel-" + sc)))
    if tops - {sc}:
        bad.append(f"panel-{sc} writes under /tmp/panel/ outside its own folder: {sorted(tops - {sc})}")
dls = [st for st in jobs["panel"].get("steps", []) if str(st.get("uses", "")).startswith("actions/download-artifact@")]
want = {"panel-" + sc: sc for sc in PANEL_SC}
seen = []
for st in dls:
    w = st.get("with") or {}
    ids = w.get("artifact-ids", "")
    m = re.fullmatch(r"\$\{\{ needs\.panel-(grype|scout|inspector|google)\.outputs\.artifact-id \}\}", ids)
    if not m or set(w) != {"artifact-ids", "path"} or w.get("path") != "/tmp/panel/panel-" + m.group(1) \
            or (st.get("if") or "").replace(" ", "") != "${{needs.panel-%s.outputs.artifact-id!=''}}" % m.group(1):
        bad.append(f"a panel download is not exactly artifact-ids of one scanner job into its own /tmp/panel/panel-<scanner> folder, guarded by a non-empty id: {w} if {st.get('if')}")
    else:
        seen.append(m.group(1))
if sorted(seen) != sorted(PANEL_SC):
    bad.append(f"the panel job does not download each of grype, scout, inspector and google exactly once by artifact id: {seen}")
print("; ".join(bad) or "ok")
sys.exit(1 if bad else 0)
PY
}
case_() {
  local f="$work/$1.yml"
  cp "$root/.github/workflows/main-candidate-rescan.yml" "$f"
  if [ -n "$3" ]; then python3 - "$f" "$3" <<'PY'
import sys, yaml
p, edit = sys.argv[1], sys.argv[2]
d = yaml.load(open(p), Loader=yaml.BaseLoader)
exec(edit)
yaml.safe_dump(d, open(p, "w"), sort_keys=False)
PY
  fi
  if out=$(judge "$f"); then got=ok; else got=bad; fi
  if [ "$got" = "$2" ]; then pass=$((pass+1)); echo "PASS $1 → $got ($out)"
  else failn=$((failn+1)); echo "FAIL $1 → $got, want $2 ($out)"; fi
}
J='d["jobs"]'
step_of() { echo "[s for s in $J['$1']['steps'] if '$2' in (s.get('run') or '')][0]"; }
# Codex #168 r2 (B2): the self-check's judge compares findings (CVE, package, version), not CVE names
judge_case() {   # name want before after
  local d; d=$(mktemp -d "$work/j.XXXX"); printf '%s' "$3" > "$d/b"; printf '%s' "$4" > "$d/a"
  if python3 "$root/bin/scout-selfcheck.py" "$d/b" "$d/a" CVE-2023-4911 >/dev/null 2>&1; then got=ok; else got=bad; fi
  if [ "$got" = "$2" ]; then pass=$((pass+1)); echo "PASS judge-$1 → $got"; else failn=$((failn+1)); echo "FAIL judge-$1 → $got, want $2"; fi
}
F() { printf '{"identifiers":[{"value":"%s"}],"location":{"dependency":{"package":{"name":"%s"},"version":"%s"}}}' "$1" "$2" "$3"; }
T=$(F CVE-2023-4911 libc6 2.36); A=$(F CVE-1 libalpha 1.0); B=$(F CVE-1 libbeta 1.0); A2=$(F CVE-1 libalpha 2.0)
judge_case kept-exactly      ok  "{\"vulnerabilities\":[$T,$A,$B]}" "{\"vulnerabilities\":[$A,$B]}"
judge_case lost-a-package    bad "{\"vulnerabilities\":[$T,$A,$B]}" "{\"vulnerabilities\":[$A]}"
judge_case other-package     bad "{\"vulnerabilities\":[$T,$A]}"    "{\"vulnerabilities\":[$B]}"
judge_case other-version     bad "{\"vulnerabilities\":[$T,$A]}"    "{\"vulnerabilities\":[$A2]}"
judge_case gained-a-finding  bad "{\"vulnerabilities\":[$T,$A]}"    "{\"vulnerabilities\":[$A,$B]}"
judge_case target-kept       bad "{\"vulnerabilities\":[$T,$A]}"    "{\"vulnerabilities\":[$T,$A]}"
judge_case id-number         bad "{\"vulnerabilities\":[$T,$(F 123 libalpha 1.0 | sed 's/"123"/123/')]}" "{\"vulnerabilities\":[$(F 123 libalpha 1.0 | sed 's/"123"/123/')]}"
judge_case id-true           bad "{\"vulnerabilities\":[$T,$(F x libalpha 1.0 | sed 's/"x"/true/')]}" "{\"vulnerabilities\":[$(F x libalpha 1.0 | sed 's/"x"/true/')]}"
judge_case id-blank          bad "{\"vulnerabilities\":[$T,$(F ' ' libalpha 1.0)]}" "{\"vulnerabilities\":[$(F ' ' libalpha 1.0)]}"
judge_case no-location       bad "{\"vulnerabilities\":[$T,{\"identifiers\":[{\"value\":\"CVE-1\"}]}]}" "{\"vulnerabilities\":[{\"identifiers\":[{\"value\":\"CVE-1\"}]}]}"
# advisor 0106: the Scout product-form probe — one statement per candidate form, each on a different fixture CVE; it
# reports which forms Scout applied and never decides the job (the self-check does)
probe_case() {   # name want-substring before after
  local d; d=$(mktemp -d "$work/p.XXXX"); printf '%s' "$3" > "$d/b"; printf '%s' "$4" > "$d/a"
  python3 "$root/bin/scout-selfcheck.py" probe-doc "$d/b" "FosterStack LLC" "$d/v.json" >/dev/null 2>&1 || { failn=$((failn+1)); echo "FAIL probe-$1: no document"; return; }
  out=$(python3 "$root/bin/scout-selfcheck.py" probe-report "$d/b" "$d/a" "$d/v.json.map" 2>&1); rc=$?
  if [ "$rc" = 0 ] && grep -q -- "$2" <<<"$out"; then pass=$((pass+1)); echo "PASS probe-$1"; else failn=$((failn+1)); echo "FAIL probe-$1 → rc=$rc: $out"; fi
}
PB="{\"vulnerabilities\":[$(F CVE-2001-0001 a 1),$(F CVE-2001-0002 b 1),$(F CVE-2001-0003 c 1),$(F CVE-2001-0004 d 1),$(F CVE-2001-0005 e 1),$(F CVE-2001-0006 f 1),$(F CVE-2001-0007 g 1)]}"
probe_case none-applied "applied: none" "$PB" "$PB"
d0=$(mktemp -d "$work/p.XXXX"); printf '%s' "$PB" > "$d0/b"; python3 "$root/bin/scout-selfcheck.py" probe-doc "$d0/b" "FosterStack LLC" "$d0/v.json" >/dev/null
first=$(python3 -c 'import json,sys; m=json.load(open(sys.argv[1])); print(m["pkg:docker/ghcr.io/fosterstack/cache@selfcheck"])' "$d0/v.json.map")
PA=$(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); d["vulnerabilities"]=[v for v in d["vulnerabilities"] if v["identifiers"][0]["value"]!=sys.argv[2]]; print(json.dumps(d))' "$PB" "$first")
probe_case all-vanished "inconclusive" "$PB" '{"vulnerabilities":[]}'
PC=$(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); drop={sys.argv[2], "CVE-2001-0007"}; d["vulnerabilities"]=[v for v in d["vulnerabilities"] if v["identifiers"][0]["value"] not in drop]; print(json.dumps(d))' "$PB" "$first")
probe_case control-lost "inconclusive" "$PB" "$PC"
probe_case unc-pkg-lost "uncovered findings lost: \[\[\"CVE-2001-0007\", \"g2\"" "{\"vulnerabilities\":[$(F CVE-2001-0001 a 1),$(F CVE-2001-0002 b 1),$(F CVE-2001-0003 c 1),$(F CVE-2001-0004 d 1),$(F CVE-2001-0005 e 1),$(F CVE-2001-0006 f 1),$(F CVE-2001-0007 g 1),$(F CVE-2001-0007 g2 1)]}" "{\"vulnerabilities\":[$(F CVE-2001-0002 b 1),$(F CVE-2001-0003 c 1),$(F CVE-2001-0004 d 1),$(F CVE-2001-0005 e 1),$(F CVE-2001-0006 f 1),$(F CVE-2001-0007 g 1)]}"
probe_case gained-only "uncovered findings lost: none" "$PB" "$(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); d["vulnerabilities"].append({"identifiers":[{"value":"CVE-2009-0009"}],"location":{"dependency":{"package":{"name":"z"},"version":"1"}}}); print(json.dumps(d))' "$PB")"
# advisor 0109: probe 3 — statements that name the finding's package (a subcomponent from Scout's own SBOM), the
# platform-qualified image, and a registry image; each form on a different CVE with exactly one package
d3=$(mktemp -d "$work/p3.XXXX")
printf '%s' "$PB" > "$d3/b"
python3 -c 'import json; print(json.dumps({"artifacts": [{"name": n, "version": "1", "purl": "pkg:deb/debian/%s@1?arch=amd64" % n} for n in "abcdefg"]}))' > "$d3/sbom"
if python3 "$root/bin/scout-selfcheck.py" probe-doc3 "$d3/b" "$d3/sbom" "FosterStack LLC" ghcr.io/fosterstack/cache selfcheck "$d3/v.json" >/dev/null 2>&1 \
   && python3 -c '
import json, sys
d = json.load(open(sys.argv[1])); m = json.load(open(sys.argv[1] + ".map")); s = d["statements"]
subs = [x for x in s if x["products"][0].get("subcomponents")]
plat = [x for x in s if "platform=linux%2Famd64" in x["products"][0]["@id"]]
assert d["author"] == "FosterStack LLC" and len({x["vulnerability"]["name"] for x in s}) == len(s) == len(m) >= 5
assert subs and all(c["@id"].startswith("pkg:deb/debian/") for x in subs for c in x["products"][0]["subcomponents"])
assert plat and any(x["products"][0]["@id"].startswith("pkg:oci/cache") for x in subs)
' "$d3/v.json"; then pass=$((pass+1)); echo "PASS probe3-document: subcomponents from the SBOM, platform forms, one CVE each"
else failn=$((failn+1)); echo "FAIL probe3-document"; fi
# probe 3 run 1 found no (name, version) match between Scout's report and its SBOM: fall back to a unique name
d3b=$(mktemp -d "$work/p3b.XXXX"); printf '%s' "$PB" > "$d3b/b"
python3 -c 'import json; print(json.dumps({"artifacts": [{"name": n, "version": "1:1-deb12u1", "purl": "pkg:deb/debian/%s@1:1-deb12u1" % n} for n in "abcdefg"]}))' > "$d3b/sbom"
if python3 "$root/bin/scout-selfcheck.py" probe-doc3 "$d3b/b" "$d3b/sbom" "FosterStack LLC" ghcr.io/fosterstack/cache selfcheck "$d3b/v.json" >/dev/null 2>&1; then
  pass=$((pass+1)); echo "PASS probe3-name-fallback"; else failn=$((failn+1)); echo "FAIL probe3-name-fallback"; fi
# advisor 0110: Scout's GitLab report puts the package purl in "name" (run 37126697443) — use it as the purl
d3c=$(mktemp -d "$work/p3c.XXXX")
python3 -c '
import json
f = lambda c, n: {"identifiers": [{"value": c}], "location": {"dependency": {"package": {"name": "pkg:deb/debian/%s@1?os_distro=bookworm" % n}, "version": "1"}}}
print(json.dumps({"vulnerabilities": [f("CVE-2001-000%d" % i, n) for i, n in enumerate("abcdefg", 1)]}))' > "$d3c/b"
echo '{"artifacts": []}' > "$d3c/sbom"
if python3 "$root/bin/scout-selfcheck.py" probe-doc3 "$d3c/b" "$d3c/sbom" "FosterStack LLC" ghcr.io/fosterstack/cache selfcheck "$d3c/v.json" >/dev/null 2>&1 \
   && grep -q '"pkg:deb/debian/a@1?os_distro=bookworm"' "$d3c/v.json"; then pass=$((pass+1)); echo "PASS probe3-name-is-purl"
else failn=$((failn+1)); echo "FAIL probe3-name-is-purl"; fi
probe_case one-applied "applied: pkg:docker/ghcr.io/fosterstack/cache@selfcheck" "$PB" "$PA"
if python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); s=d["statements"]; assert d["author"]=="FosterStack LLC" and len(s)==len({x["vulnerability"]["name"] for x in s})>=5 and all(x["status"]=="not_affected" for x in s) and any(p["@id"]=="pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache" for x in s for p in x["products"])' "$d0/v.json"; then
  pass=$((pass+1)); echo "PASS probe-document: our author, one CVE per form, our published form among them"
else failn=$((failn+1)); echo "FAIL probe-document"; fi
case_ real                    ok  ""
case_ grype-keeps-partial     bad "s=$(step_of panel-grype 'for v in'); s['run'] = s['run'].replace('rm -rf \"\${d}\"; ', '')"
case_ scout-keeps-partial     bad "s=$(step_of panel-scout 'docker scout cves'); s['run'] = s['run'].replace('rm -rf \"\${d}\"; ', '')"
case_ grype-repo-config       bad "s=$(step_of panel-grype 'for v in'); s['run'] = s['run'].replace(' -c \"\$RUNNER_TEMP/empty-grype.yaml\"', '')"
case_ grype-update-repo-config bad "s=$(step_of panel-grype 'for v in'); s['run'] = s['run'].replace('grype db update -c \"\$RUNNER_TEMP/empty-grype.yaml\"', 'grype db update')"
case_ grype-extra-archive-scan bad "s=$(step_of panel-grype 'for v in'); \
  s['run'] = s['run'] + chr(10) + 'grype \"docker-archive:/tmp/arc/x.tar\" -o json'"
case_ grype-no-env-refusal    bad "s=$(step_of panel-grype 'for v in'); s['run'] = s['run'].replace(\"compgen -e | grep '^GRYPE_'\", 'echo')"
case_ pub-grype-repo-config   bad "s=$(step_of rescan 'grype "registry:'); s['run'] = s['run'].replace(' -c /tmp/empty-grype.yaml', '')"
case_ pub-grype-no-env-refusal bad "s=$(step_of rescan 'grype "registry:'); s['run'] = s['run'].replace(\"compgen -e | grep '^GRYPE_'\", 'echo')"
case_ pub-grype-no-inventory  bad "s=$(step_of rescan 'grype "registry:'); s['run'] = s['run'].replace(' -o \"cyclonedx-json=\${sbom}\"', '')"
case_ pub-grype-no-count      bad "s=$(step_of rescan 'grype "registry:'); s['run'] = s['run'].replace(' --argjson k \"\${pk}\"', '').replace(', packages:\$k', '')"
case_ pub-osv-all-packages-off bad "s=$(step_of rescan 'osv-scanner scan image'); s['run'] = s['run'].replace(' --all-packages', '')"
case_ pub-osv-all-vulns-off   bad "s=$(step_of rescan 'osv-scanner scan image'); s['run'] = s['run'].replace(' --all-vulns', '')"
case_ pub-osv-repo-config     bad "s=$(step_of rescan 'osv-scanner scan image'); s['run'] = s['run'].replace(' --config /tmp/empty-osv.toml', '')"
case_ pub-osv-no-env-refusal  bad "s=$(step_of rescan 'osv-scanner scan image'); s['run'] = s['run'].replace(\"compgen -e | grep '^OSV_SCANNER_'\", 'echo')"
case_ pub-pk-not-checked      bad "s=$(step_of rescan 'grype \"registry:'); s['run'] = s['run'].replace('[[ \"\${pk}\" =~ ^[0-9]+\$ ]] || pk=0', 'true')"
case_ pub-no-expect-children  bad "s=$(step_of rescan 'rescan-statement.py statement'); s['run'] = s['run'].replace(' --expect-children \"\$(grep -c . /tmp/children.txt)\"', '')"
case_ pub-osv-no-count        bad "s=$(step_of rescan 'osv-scanner scan image'); s['run'] = s['run'].replace(', packages:\$k', '')"
case_ panel-dl-same-id        bad "s=[x for x in $J['panel']['steps'] if 'panel-scout' in str((x.get('with') or {}).get('path'))][0]; s['with']['artifact-ids'] = '\${{ needs.panel-grype.outputs.artifact-id }}'"
case_ panel-dl-by-name        bad "s=[x for x in $J['panel']['steps'] if 'panel-scout' in str((x.get('with') or {}).get('path'))][0]; s['with'] = {'name': 'panel-scout', 'path': '/tmp/panel/panel-scout'}"
case_ panel-dl-pattern        bad "s=[x for x in $J['panel']['steps'] if 'panel-scout' in str((x.get('with') or {}).get('path'))][0]; s['with'] = {'pattern': 'panel-*', 'path': '/tmp/panel/'}"
case_ panel-dl-missing        bad "$J['panel']['steps'] = [x for x in $J['panel']['steps'] if 'panel-google' not in str((x.get('with') or {}).get('path'))]"
case_ panel-dl-no-guard       bad "s=[x for x in $J['panel']['steps'] if 'panel-inspector' in str((x.get('with') or {}).get('path'))][0]; s.pop('if')"
case_ panel-dl-wrong-folder   bad "s=[x for x in $J['panel']['steps'] if 'panel-google' in str((x.get('with') or {}).get('path'))][0]; s['with']['path'] = '/tmp/panel/panel-grype'"
case_ panel-job-no-output     bad "$J['panel-scout'].pop('outputs')"
case_ panel-upload-wrong-name bad "[x for x in $J['panel-grype']['steps'] if x.get('id') == 'upload'][0]['with']['name'] = 'panel-scout'"
case_ panel-writes-other      bad "s=$(step_of panel-grype 'for v in'); s['run'] = s['run'] + chr(10) + 'mkdir -p /tmp/panel/scout/x'"
case_ google-arm64            bad "s=$(step_of panel-google 'for v in'); s['run'] = s['run'].replace('\"/tmp/oci/\${v}\" amd64', '\"/tmp/oci/\${v}\" arm64')"
case_ grype-three-images      bad "s=$(step_of panel-grype 'for v in'); s['run'] = s['run'].replace('for v in production fips', 'for v in production')"
case_ computed-images         bad "s=$(step_of panel-scout 'for v in'); s['run'] = s['run'].replace('for arch in amd64 arm64', 'for arch in \$ARCHES')"
case_ scanner-reports-back    bad "$J['scanner-reports'] = {'runs-on': 'ubuntu-latest', 'steps': [{'run': 'osv-scanner scan image x'}]}"
case_ osv-in-panel            bad "s=$(step_of panel-grype 'for v in'); s['run'] = s['run'] + '\\nosv-scanner scan image x'"
case_ trivy-back              bad "$J['trivy-main'] = {'runs-on': 'ubuntu-latest', 'steps': [{'run': 'trivy image x'}]}"
case_ google-secret           bad "[s.__setitem__('with', {'credentials_json': '\${{ secrets.GCP_KEY }}'}) for s in $J['panel-google']['steps'] if str(s.get('uses','')).startswith('google-github-actions/auth@')]"
case_ google-literal-provider bad "[s['with'].__setitem__('workload_identity_provider', 'projects/1/locations/global/workloadIdentityPools/p/providers/q') for s in $J['panel-google']['steps'] if str(s.get('uses','')).startswith('google-github-actions/auth@')]"
case_ google-no-idtoken       bad "$J['panel-google']['permissions'].pop('id-token')"
case_ grype-no-vex            bad "s=$(step_of panel-grype 'for v in'); s['run'] = s['run'].replace('--vex .vex/fosterstack-cache.openvex.json', '')"
case_ rescan-concurrent       bad "d.pop('concurrency', None)"
SCAN="$(step_of panel-scout 'docker scout cves')"
SC='d["jobs"]["panel-scout"]'
case_ vex-attach-readded      bad "$J['vex-attach'] = {'runs-on': 'ubuntu-latest', 'needs': ['build'], 'permissions': {'contents': 'read'}, 'steps': [{'run': 'true'}]}"
case_ vex-attach-readded-write bad "$J['vex-attach'] = {'runs-on': 'ubuntu-latest', 'needs': ['build'], 'permissions': {'contents': 'read', 'packages': 'write'}, 'steps': [{'run': 'true'}]}"
case_ write-on-grype          bad "$J['panel-grype']['permissions']['packages'] = 'write'"
case_ write-on-inspector      bad "$J['panel-inspector']['permissions']['packages'] = 'write'"
case_ write-on-google         bad "$J['panel-google']['permissions']['packages'] = 'write'"
case_ write-on-panel          bad "$J['panel']['permissions']['packages'] = 'write'"
case_ write-on-rescan         bad "$J['rescan']['permissions']['packages'] = 'write'"
case_ write-on-manifests      bad "$J['manifests']['permissions'] = {'contents': 'read', 'packages': 'write'}"
case_ write-on-scout          bad "$SC['permissions']['packages'] = 'write'"
case_ write-top-level         bad "d['permissions']['packages'] = 'write'"
case_ write-all-on-grype      bad "$J['panel-grype']['permissions'] = 'write-all'"
case_ build-not-snapshot      bad "$J['build']['with']['mode'] = 'release'"
case_ skopeo-copy-in-grype    bad "s=$(step_of panel-grype 'for v in'); s['run'] = s['run'] + chr(10) + 'skopeo copy --all oci:/tmp/oci/production docker://ghcr.io/fosterstack/cache:x'"
case_ docker-push-in-panel    bad "s=$(step_of panel 'bin/panel.py tally'); s['run'] = s['run'] + chr(10) + 'docker push ghcr.io/fosterstack/cache:x'"
case_ crane-push-in-rescan    bad "s=$(step_of rescan 'grype \"registry:'); s['run'] = s['run'] + chr(10) + 'crane push /tmp/oci/production ghcr.io/fosterstack/cache:x'"
case_ scratch-package-named   bad "s=$(step_of panel-grype 'for v in'); s['run'] = s['run'] + chr(10) + 'echo ghcr.io/fosterstack/cache-scout-probe'"
case_ scratch-package-in-scout bad "s=$SCAN; s['run'] = s['run'] + chr(10) + 'echo ghcr.io/fosterstack/cache-scout-probe'"
case_ scout-needs-more        bad "$SC['needs'] = ['build', 'panel-grype']"
case_ scout-needs-vex-attach  bad "$SC['needs'] = ['build', 'vex-attach']"
case_ scout-needs-none        bad "$SC['needs'] = []"
case_ scout-perms-packages-read bad "$SC['permissions']['packages'] = 'read'"
case_ scout-perms-contents-write bad "$SC['permissions']['contents'] = 'write'"
case_ scout-perms-id-token    bad "$SC['permissions']['id-token'] = 'write'"
case_ scout-no-environment    bad "$SC.pop('environment')"
case_ scout-other-environment bad "$SC['environment'] = 'release'"
case_ scout-downloads-attach  bad "$SC['steps'].insert(1, {'uses': 'actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333', 'with': {'name': 'vex-attach', 'path': '/tmp/attach'}})"
case_ scout-no-images-download bad "$SC['steps'] = [x for x in $SC['steps'] if not str(x.get('uses', '')).startswith('actions/download-artifact@')]"
case_ scout-images-other-path bad "[x for x in $SC['steps'] if str(x.get('uses', '')).startswith('actions/download-artifact@')][0]['with']['path'] = '/tmp/other/'"
case_ scout-ghcr-login        bad "$SC['steps'].insert(1, {'name': 'log in to GHCR', 'run': 'printf x | docker login ghcr.io -u me --password-stdin'})"
case_ scout-ghcr-login-action bad "$SC['steps'].insert(1, {'uses': 'docker/login-action@0000000000000000000000000000000000000000', 'with': {'registry': 'ghcr.io'}})"
case_ scout-registry-scan     bad "s=$SCAN; s['run'] = s['run'] + chr(10) + 'docker scout cves registry://ghcr.io/fosterstack/cache:x > /dev/null'"
case_ scout-registry-ref      bad "s=$SCAN; s['run'] = s['run'].replace('local://', 'registry://')"
case_ scout-fixture-digests   bad "$SC['steps'].insert(3, {'name': 'read fixture digests', 'run': 'jq -er . \"\$RUNNER_TEMP/attach/digests.json\"'})"
case_ scout-registry-selfcheck bad "$SC['steps'].insert(3, {'name': 'Scout applies our attestation to a fixture index', 'run': 'docker scout cves --vex-author x registry://ghcr.io/fosterstack/cache-scout-probe@sha256:1'})"
case_ scout-skopeo            bad "s=$SCAN; s['run'] = chr(10).join(['skopeo copy oci:/tmp/oci/production docker-daemon:x', s['run']])"
case_ scout-no-vex-location   bad "import re; s=$SCAN; s['run'] = re.sub('--vex-location +[^ ]+ *', '', s['run'])"
case_ scout-vex-other-file    bad "import re; s=$SCAN; s['run'] = re.sub('--vex-location +[^ ]+', '--vex-location /tmp/other.json', s['run'])"
case_ scout-no-author         bad "import re; s=$SCAN; s['run'] = re.sub('--vex-author +.[^ ]+ [^ ]+ *', '', s['run'])"
case_ scout-other-author      bad "s=$SCAN; s['run'] = s['run'].replace('FosterStack LLC', 'Docker Inc')"
case_ scout-one-arch          bad "s=$SCAN; s['run'] = s['run'].replace('for arch in amd64 arm64', 'for arch in amd64')"
case_ scout-one-variant       bad "s=$SCAN; s['run'] = s['run'].replace('for v in production fips', 'for v in production')"
case_ scout-scan-other-input  bad "s=$SCAN; s['run'] = s['run'].replace('/tmp/oci/', '/tmp/other/')"
case_ scout-scan-conditional  bad "s=$SCAN; s['if'] = 'false'"
case_ scout-scan-soft         bad "s=$SCAN; s['continue-on-error'] = 'true'"
case_ scout-keeps-partial-dir bad "s=$SCAN; s['run'] = s['run'].replace('rm -rf \"\${d}\"; ', '')"
case_ scout-fails-quietly     bad "s=$SCAN; s['run'] = s['run'].replace('::warning::', '::notice::').replace('rm -rf \"\${d}\"', 'true')"
case_ scout-hub-login-gone    bad "$SC['steps'] = [x for x in $SC['steps'] if 'Docker Hub' not in (x.get('name') or '')]"
case_ scout-hub-other-token   bad "s=[x for x in $SC['steps'] if 'Docker Hub' in (x.get('name') or '')][0]; s['run'] = s['run'].replace('DOCKERHUB_SCOUT_TOKEN', 'DOCKERHUB_TOKEN')"
case_ scout-hub-login-after-scan bad "st = $SC['steps']; k = [i for i, x in enumerate(st) if 'Docker Hub' in (x.get('name') or '')][0]; st.append(st.pop(k))"
case_ scout-no-vex            bad "s=$(step_of panel-scout 'for v in'); s['run'] = s['run'].replace('--format gitlab', '--format sarif')"
case_ grype-only-fixed        bad "s=$(step_of panel-grype 'for v in'); s['run'] = s['run'].replace('grype ', 'grype --only-fixed ', 1)"
case_ audits-elsewhere        bad "s=$(step_of panel 'bin/panel.py tally'); s['run'] = s['run'].replace('bin/panel.py tally', 'bin/panel.py collect')"
case_ google-amd64-gone        bad "s=$(step_of panel-google 'for v in'); s['run'] = s['run'].replace('cand-\${v}-amd64', 'cand-\${v}')"
case_ no-schedule             bad "d['on'].pop('schedule')"
case_ scan-disabled           bad "s=$(step_of panel-inspector 'for v in'); s['if'] = 'false'"
case_ scan-may-fail           bad "s=$(step_of panel-grype 'for v in'); s['continue-on-error'] = 'true'"
case_ job-disabled            bad "$J['panel-scout']['if'] = 'false'"
case_ no-issue-step           bad "$J['panel']['steps'] = [s for s in $J['panel']['steps'] if 'gh issue' not in (s.get('run') or '')]"
case_ issue-from-any-branch   bad "[s.__setitem__('if', '\${{ always() }}') for s in $J['panel']['steps'] if 'gh issue' in (s.get('run') or '')]"
case_ no-final-failure        bad "$J['panel']['steps'] = $J['panel']['steps'][:-1]"
case_ yearly-schedule         bad "d['on']['schedule'][0]['cron'] = '41 7 1 1 *'"
case_ google-no-environment   bad "$J['panel-google'].pop('environment')"
case_ grype-amd64-twice       bad "s=$(step_of panel-grype 'for v in'); s['run'] = s['run'].replace('for arch in amd64 arm64', 'for arch in amd64 amd64')"
case_ issue-exits-early       bad "[s.__setitem__('run', 'exit 0\n' + s['run']) for s in $J['panel']['steps'] if 'gh issue' in (s.get('run') or '')]"
case_ rc-forced-zero          bad "s=$(step_of panel 'bin/panel.py tally'); s['run'] = s['run'].replace('echo \"rc=\$?\"', 'echo \"rc=0\"')"
case_ google-no-log-http      bad "s=$(step_of panel-google 'for v in'); s['run'] = s['run'].replace(' --log-http', '')"
case_ panel-audits             bad "$J['panel']['permissions']['id-token'] = 'write'"
case_ panel-reads-history     bad "s=$(step_of panel 'bin/panel.py tally'); s['run'] = s['run'].replace('--out', '--prior /tmp/prior/judgments.json --out')"
case_ panel-skips-on-failure  bad "$J['panel']['if'] = 'success()'"
# The auditor (auditor.yml) runs no scanner of its own: it reads the panel's verdict (handoffs 0518/0600, owner:
# "the auditor reads the four"). No Trivy, Snyk or OSV-Scanner install or token, no copy of the retired scanner reports.
aud_case() {
  local f="$work/aud-$1.yml"
  cp "$root/.github/workflows/auditor.yml" "$f"
  [ -n "$3" ] && python3 - "$f" "$3" <<'PY'
import sys
p, edit = sys.argv[1], sys.argv[2]
t = open(p).read()
old, new = edit.split("=>", 1)
assert old in t or old == "", "mutation target missing"
open(p, "w").write(t.replace(old, new) if old else t + new)
PY
  if out=$(python3 - "$f" <<'PY'
import re, sys
t = open(sys.argv[1]).read()
bad = []
for w in ("trivy", "osv-scanner", "snyk", "SNYK_TOKEN", "rescan-scanner-reports", "--rescan-reports"):
    if w.lower() in t.lower():
        bad.append(f"auditor.yml still mentions {w}")
# Grype's name stays in comments (the panel's Grype is the rescan's job), but no executable text may name it: not an
# install, a run, a loop variable or a quoted target. Shell comments (whole-line, or after whitespace outside quotes) are dropped first.
def strip_comment(l):
    q = None; esc = False
    for k, c in enumerate(l):
        if esc: esc = False; continue                      # the character after a backslash is literal (outside single quotes)
        if c == "\\" and q != "'": esc = True
        elif q:
            if c == q: q = None
        elif c in "'\"": q = c
        elif c == "#" and (k == 0 or l[k - 1].isspace()): return l[:k]
    return l
for l in t.splitlines():
    if re.search(r"\bgrype\b", strip_comment(l), re.I):
        bad.append("auditor.yml names grype outside a comment: " + l.strip()[:60])
if "--panel-dir" not in t:
    bad.append("auditor.yml does not hand the panel evidence to the manifest")
print("; ".join(bad) or "clean"); sys.exit(1 if bad else 0)
PY
  ); then got=ok; else got=bad; fi
  if [ "$got" = "$2" ]; then pass=$((pass+1)); echo "PASS auditor-$1 → $got ($out)"
  else failn=$((failn+1)); echo "FAIL auditor-$1 → $got, want $2 ($out)"; fi
}
aud_case real           ok  ""
aud_case trivy-install  bad "=>
          ./bin/install-scanner.sh trivy
"
aud_case osv-install    bad "=>
          ./bin/install-scanner.sh osv-scanner
"
aud_case snyk-token     bad '=>
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
'
aud_case grype-install  bad "=>
          ./bin/install-scanner.sh grype
"
aud_case grype-run      bad "=>
          grype docker:x -o json > g.json
"
aud_case grype-comment  ok  "=>
          # grype is the rescan panel's job, not the auditor's
"
aud_case grype-inline-comment ok "=>
          true # grype docker:x -o json
"
aud_case grype-after-escaped-quote bad '=>
          echo "say \" # still inside the string"; grype docker:x -o json
'
aud_case grype-loop     bad "=>
          for s in grype syft; do sudo ./bin/install-scanner.sh \"\$s\"; done
"
aud_case grype-quoted   bad "=>
          grype \"docker:\${ref}\" -o json
"
aud_case grype-bare-ref bad "=>
          grype ghcr.io/fosterstack/cache:latest -o json
"
aud_case reports-download bad '=>
          gh run download "$rid" -n rescan-scanner-reports -D x
'
aud_case reports-option bad "=>
            --rescan-reports x
"
aud_case no-panel-dir   bad "--panel-dir =>--panel-evidence "
echo "panel-wiring: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
