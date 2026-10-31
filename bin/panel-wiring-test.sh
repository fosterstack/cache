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
# REQ-REL-010 on the rescan (handoff 0521): Scout applies our statements only through an attestation in the image index, and an
# attestation lives in a registry. Build gave each candidate index its attestation children; the vex-attach job pushes them as built and
# pushes it to the SCRATCH package only; panel-scout scans those registry refs by exact index digest with our author.
import json, os, subprocess, tempfile
ROOT = os.environ.get("PANEL_ROOT", ".")
SCRATCH = "ghcr.io/fosterstack/cache-scout-probe"
FIXTURE_DIGEST = "sha256:60774985572749dc3c39147d43089d53e7ce17b844eebcf619d84467160217ab"
DIG = {"fixture-before": "sha256:" + "1" * 64, "fixture-ours": "sha256:" + "2" * 64, "fixture-docker": "sha256:" + "6" * 64,
       "production": "sha256:" + "3" * 64, "fips": "sha256:" + "5" * 64}
STUB = r"""#!/usr/bin/env bash
{ printf '%s' "$(basename "$0")"; printf ' %q' "$@"; printf '\n'; } >> "$STUB_LOG"
if [ "$(basename "$0")" = docker ] && [ "$1 $2" = "scout cves" ]; then
  ref=""; for a in "$@"; do case "$a" in registry://*) ref=$a;; esac; done
  T='{"identifiers":[{"value":"CVE-2023-4911"}],"location":{"dependency":{"package":{"name":"libc6"},"version":"2.36-9"}}}'
  O='{"identifiers":[{"value":"CVE-2099-0001"}],"location":{"dependency":{"package":{"name":"libalpha"},"version":"1.0"}}}'
  case "$ref" in
    *@sha256:2222*) case "$STUB_MODE" in
        applies) printf '{"vulnerabilities":[%s]}' "$O" ;;
        ignores) printf '{"vulnerabilities":[%s,%s]}' "$T" "$O" ;;
        drops-all) printf '{"vulnerabilities":[]}' ;;
        empty) printf '{}' ;;
      esac ;;
    *) printf '{"vulnerabilities":[%s,%s]}' "$T" "$O" ;;
  esac
elif [ "$(basename "$0")" = docker ] && [ "$1 $2" = "scout sbom" ]; then
  printf '%s' '{"artifacts":[]}'
fi
exit 0
"""
author = json.load(open(os.path.join(ROOT, ".vex/fosterstack-cache.openvex.json")))["author"]
def memo(key, compute):
    """One shell run of a run: block is the slow part, and many mutants leave a block as it was: the answer (status, log
    lines) is kept for the rest of this test run, under the hash of everything the run reads."""
    import hashlib
    path = os.path.join(os.environ["PANEL_MEMO"], hashlib.sha256(json.dumps(key, sort_keys=True).encode()).hexdigest())
    if os.path.exists(path):
        rc, log = json.load(open(path))
        return rc, log
    rc, log = compute()
    json.dump([rc, log], open(path + ".tmp", "w")); os.replace(path + ".tmp", path)
    return rc, log
def run_block(block, mode, failing=None):
    return memo(["run_block", block, mode, failing, STUB, DIG], lambda: _run_block(block, mode, failing))
def _run_block(block, mode, failing=None):
    with tempfile.TemporaryDirectory() as t:
        os.makedirs(os.path.join(t, "stub")); os.makedirs(os.path.join(t, "attach"))
        json.dump(DIG, open(os.path.join(t, "attach", "digests.json"), "w"))
        for tool in ("docker", "skopeo", "sudo"):
            with open(os.path.join(t, "stub", tool), "w") as fh:
                fh.write("#!/usr/bin/env bash\nexit 23\n" if tool == failing else STUB)
            os.chmod(os.path.join(t, "stub", tool), 0o755)
        log = os.path.join(t, "log")
        open(log, "w").close()
        env = dict(os.environ, PATH=os.path.join(t, "stub") + ":" + os.environ["PATH"], STUB_LOG=log, STUB_MODE=mode,
                   RUNNER_TEMP=t, GITHUB_STEP_SUMMARY=os.path.join(t, "sum"), GITHUB_RUN_ID="42")
        r = subprocess.run(["bash", "-e", "-c", block], cwd=ROOT, env=env, capture_output=True, text=True)
        return r.returncode, open(log).read().splitlines()
if (d.get("concurrency") or {}).get("group") != "main-candidate-rescan" or str((d.get("concurrency") or {}).get("cancel-in-progress")).lower() != "false":
    bad.append("the rescan is not serialized without cancelling (the scratch package prune and pushes must not interleave)")
va = jobs.get("vex-attach")
if not va:
    bad.append("no vex-attach job (the attestation children and the push to the scratch package)")
else:
    perms = va.get("permissions") or {}
    if perms != {"contents": "read", "packages": "write"} or va.get("environment") or va.get("if"):
        bad.append("vex-attach must hold exactly contents: read and packages: write, no environment, no identity token, no condition: %s" % perms)
    vneeds = va.get("needs", []); vneeds = vneeds if isinstance(vneeds, list) else [vneeds]
    if vneeds != ["build"]:
        bad.append("vex-attach does not wait for exactly the build (the chain's candidate images are Build's snapshot artifact)")
    vt = text("vex-attach")
    vsteps = va.get("steps", [])
    att = [x for x in vsteps if "push each candidate index as Build attested it" in (x.get("name") or "")]
    fxs = [x for x in vsteps if "self-check fixtures" in (x.get("name") or "")]
    prn = [x for x in vsteps if "prune the scratch package" in (x.get("name") or "")]
    if len(att) != 1 or len(fxs) != 1 or len(prn) != 1:
        bad.append("vex-attach lacks one of its three steps (prune; attach and push the candidates; build the self-check fixtures)")
    else:
        if not (vsteps.index(prn[0]) < vsteps.index(att[0]) and vsteps.index(prn[0]) < vsteps.index(fxs[0])):
            bad.append("the prune must run before this run's pushes (nothing it pushes can lose its version to it)")
        # the prune is strict, and confined to the scratch package: run it against a stub gh (approval condition b)
        GHSTUB = r"""#!/usr/bin/env bash
{ printf 'gh'; printf ' %q' "$@"; printf '\n'; } >> "$STUB_LOG"
jqx=""; prev=""; for a in "$@"; do [ "$prev" = "--jq" ] && jqx="$a"; prev="$a"; done
case "$*" in
  *"-X DELETE"*) if [ "$STUB_MODE" = del-fail ]; then echo "HTTP 403" >&2; exit 1; fi
    R5000="gh: Publicly visible package versions with more than 5000 downloads cannot be deleted. Contact GitHub support for further assistance. (HTTP 400)"
    case "$STUB_MODE:$*" in
      del-5000:*) echo "$R5000" >&2; exit 1 ;;
      del-5000-then-fail:*versions/11) echo "$R5000" >&2; exit 1 ;;
      del-5000-then-fail:*) echo "HTTP 403" >&2; exit 1 ;;
    esac
    exit 0 ;;
  *"--paginate"*) case "$STUB_MODE" in
      list-404) echo "gh: Not Found (HTTP 404)" >&2; exit 1 ;;
      list-fail) echo "gh: boom (HTTP 500)" >&2; exit 1 ;;
      *) printf '[{"id":11,"updated_at":"2000-01-01T00:00:00Z"},{"id":12,"updated_at":"2999-01-01T00:00:00Z"},{"id":13,"updated_at":"2001-01-01T00:00:00Z"}]' | jq -r "$jqx" ;;
    esac ;;
  *"--jq .visibility"*) case "$STUB_MODE" in
      pkg-404) echo "gh: Not Found (HTTP 404)" >&2; exit 1 ;;
      pkg-fail) echo "gh: boom (HTTP 500)" >&2; exit 1 ;;
      *) echo private ;;
    esac ;;
esac
exit 0
"""
        def run_prune(mode):
            return memo(["run_prune", prn[0].get("run", ""), mode, GHSTUB], lambda: _run_prune(mode))
        def _run_prune(mode):
            with tempfile.TemporaryDirectory() as t:
                os.makedirs(os.path.join(t, "stub"))
                with open(os.path.join(t, "stub", "gh"), "w") as fh:
                    fh.write(GHSTUB)
                os.chmod(os.path.join(t, "stub", "gh"), 0o755)
                log = os.path.join(t, "log")
                open(log, "w").close()
                env = dict(os.environ, PATH=os.path.join(t, "stub") + ":" + os.environ["PATH"], STUB_LOG=log, STUB_MODE=mode, RUNNER_TEMP=t,
                           GITHUB_STEP_SUMMARY=os.path.join(t, "sum"), GITHUB_REPOSITORY_OWNER="fosterstack", GH_TOKEN="x")
                r = subprocess.run(["bash", "-e", "-c", prn[0].get("run", "")], cwd=ROOT, env=env, capture_output=True, text=True)
                return r.returncode, open(log).read().splitlines()
        rc, calls = run_prune("ok")
        dels = [l for l in calls if "-X DELETE" in l]
        want = ["orgs/fosterstack/packages/container/cache-scout-probe/versions/11", "orgs/fosterstack/packages/container/cache-scout-probe/versions/13"]
        if rc != 0 or sorted(l.split()[-1] for l in dels) != want:
            bad.append("the prune does not delete exactly the old versions (11, 13) and keep the fresh one (12): rc=%s %s" % (rc, calls))
        if any("packages/container/cache-scout-probe" not in l for l in calls if "api" in l):
            bad.append("the prune reaches a package other than the scratch package")
        rc, calls = run_prune("pkg-404")
        if rc != 0 or any("-X DELETE" in l for l in calls):
            bad.append("the prune treats a missing package as an error or deletes something (rc=%s)" % rc)
        for mode in ("pkg-fail", "list-fail", "list-404"):
            if run_prune(mode)[0] == 0:
                bad.append("the prune goes green when the %s lookup fails" % mode)
        rc, calls = run_prune("del-fail")
        if rc == 0 or len([l for l in calls if "-X DELETE" in l]) != 2:
            bad.append("the prune goes green when a delete fails, or stops at the first failure (rc=%s)" % rc)
        # GitHub's own refusal (public version over 5000 downloads) is kept with a named warning; any other delete failure beside it still fails (REQ-REL-010)
        rc, calls = run_prune("del-5000")
        if rc != 0 or len([l for l in calls if "-X DELETE" in l]) != 2:
            bad.append("the prune fails on a public version GitHub will not delete (over 5000 downloads), or stops at it (rc=%s)" % rc)
        rc, calls = run_prune("del-5000-then-fail")
        if rc == 0 or len([l for l in calls if "-X DELETE" in l]) != 2:
            bad.append("the prune goes green when another delete fails beside a kept 5000-download version (rc=%s)" % rc)
        # Build's assemble already gave each layout its attestation children (ruling, cache#561 B1): the candidates are pushed as built, checked against Build's own digest file, and the tool is NOT run on them again (it refuses a second run)
        for need in ('final=$(jq -er', '[ "$(cat "/tmp/oci/${v}.digest")" = "${final}" ]',
                     'python3 bin/release-layout.py "${d}" "${final}"', 'tag="cand-${GITHUB_RUN_ID}-${v}"', "chmod -R go-w", "skopeo copy --all",
                     '--digestfile "/tmp/attach/${v}.pushed"', '[ "${pushed}" = "${final}" ]', "for v in production fips", 'cp -R "/tmp/oci/${v}" "${d}"'):
            if need not in att[0].get("run", ""):
                bad.append("the attach step lacks %s" % need)
        if "vex-index" in att[0].get("run", ""):
            bad.append("the push step runs the attestation tool again on Build's layouts (they are already attested; the tool refuses a second run)")
        # every plain assignment form of `tag` in the whole job (cache#561 ruling A1: tag=, tag+=, declare/local/export/readonly/typeset ... tag, read ... tag, printf -v tag, after ; & | ( { do then else): exactly one, the approved one. Regex count only, no shell parser; a deliberately hidden form is for the reviewers (owner, Oct 3)
        TAG_ASSIGN = r"(?:^|[;&|(){!]|\b(?:do|then|else|if|elif|while|until|time)\b|\b\w+\+?=\S*[ \t])[ \t]*(?:(?:declare|local|export|readonly|typeset)[ \t]+(?:-[A-Za-z]+[ \t]+)*)?tag\+?=|\b(?:read|mapfile|readarray)\b[^\n;|&]*\btag\b|\bprintf[ \t]+-v[ \t]+tag\b|\b(?:declare|local|export|readonly|typeset)[ \t]+(?:-[A-Za-z]+[ \t]+)*tag(?![\w=])"
        if len(re.findall(TAG_ASSIGN, vt, re.M)) != 1 or not re.search(r'^\s*tag="cand-\$\{GITHUB_RUN_ID\}-\$\{v\}"$', att[0].get("run", ""), re.M):
            bad.append("the job assigns a tag in any way but the one candidate tag cand-${GITHUB_RUN_ID}-${v}")
        if len(re.findall(r"\bskopeo copy\b", att[0].get("run", ""))) != 1:
            bad.append("the push step is not exactly one skopeo copy")
        for need in ("python3 bin/vex-index.py layout --layout", "python3 bin/vex-index.py verify-layout --layout", "--base-digest",
                     ".vex/fosterstack-cache.openvex.json", "CVE-2023-4911", "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache", "chmod -R go-w",
                     "--digestfile /tmp/attach/before.pushed", "--digestfile /tmp/attach/ours.pushed", '[ "$(cat /tmp/attach/ours.pushed)" = "${final}" ]', '[ "$(cat /tmp/attach/before.pushed)" = "${before}" ]', "selfcheck-before-${GITHUB_RUN_ID}", "selfcheck-ours-${GITHUB_RUN_ID}"):
            if need not in fxs[0].get("run", ""):
                bad.append("the fixture step lacks %s" % need)
    # no other push tool in the job: the scratch package is written by skopeo copy to docker://<scratch>:<tag> and nothing else
    if re.search(r"\b(crane|oras|regctl|cosign|buildx)\b|\bdocker\s+(push|buildx|image\s+push)\b|\bgh\s+api\b[^\n]*(-X|--method)\s+(PUT|POST|PATCH)|\bcurl\b[^\n]*(-X\s*(PUT|POST|PATCH)|--upload)", vt):
        bad.append("vex-attach carries a push tool other than skopeo copy to the scratch package")
    # the fixture step, RUN: skopeo lays the pinned digest out as a single IMAGE manifest (it is debian 12.0's linux/amd64 manifest, not its index);
    # the step must wrap it into a one-child index so that the attestation tool's layout check (unchanged, strict) accepts it, and then push it by digest
    if len(fxs) == 1:
        SKOPEO = r"""#!/usr/bin/env python3
import hashlib, json, os, sys
a = sys.argv[1:]
if a[0] != "copy": sys.exit(0)
a = a[1:]; df = None
while a and a[0].startswith("--"):
    if a[0] == "--digestfile": df = a[1]; a = a[2:]
    else: a = a[1:]
src, dst = a[0], a[1]
def blob(root, data):
    h = hashlib.sha256(data).hexdigest(); d = os.path.join(root, "blobs", "sha256"); os.makedirs(d, exist_ok=True)
    open(os.path.join(d, h), "wb").write(data); return "sha256:" + h, len(data)
if src.startswith("docker://") and dst.startswith("oci:"):
    root = dst[4:]; os.makedirs(root, exist_ok=True)
    open(os.path.join(root, "oci-layout"), "w").write('{"imageLayoutVersion":"1.0.0"}')
    layer, ls = blob(root, b"layer"); cfg, cs = blob(root, json.dumps({"architecture": "amd64", "os": "linux", "rootfs": {"type": "layers", "diff_ids": [layer]}}).encode())
    man, ms = blob(root, json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": cfg, "size": cs},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": layer, "size": ls}]}).encode())
    json.dump({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
               "manifests": [{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": man, "size": ms}]}, open(os.path.join(root, "index.json"), "w"))
elif dst.startswith("docker://") and df:
    open(df, "w").write(json.load(open(os.path.join(src[4:], "index.json")))["manifests"][0]["digest"])
"""
        def fixture_problems(run_text):
            out = []
            with tempfile.TemporaryDirectory() as t0:
                t = os.path.realpath(t0)      # the attestation tool refuses any path through a symlink (macOS /var)
                os.makedirs(os.path.join(t, "stub")); os.makedirs(os.path.join(t, "attach"))
                with open(os.path.join(t, "stub", "skopeo"), "w") as fh:
                    fh.write(SKOPEO)
                os.chmod(os.path.join(t, "stub", "skopeo"), 0o755)
                json.dump({k: v for k, v in DIG.items() if not k.startswith("fixture-")}, open(os.path.join(t, "attach", "digests.json"), "w"))   # the step must RECORD the two fixture digests itself
                env = dict(os.environ, PATH=os.path.join(t, "stub") + ":" + os.environ["PATH"], RUNNER_TEMP=t, GITHUB_RUN_ID="42")
                r = subprocess.run(["bash", "-e", "-c", run_text.replace("/tmp/", t + "/")], cwd=ROOT, env=env, capture_output=True, text=True)
                if r.returncode != 0:
                    return ["the fixture step does not run to the end on a single-image layout (rc %d): %s" % (r.returncode, (r.stdout + r.stderr)[-400:])]
                dig = json.load(open(os.path.join(t, "attach", "digests.json")))
                for name, key in (("fixture", "fixture-before"), ("fixture-ours", "fixture-ours")):
                    top = json.load(open(os.path.join(t, "layout", name, "index.json")))["manifests"]
                    if len(top) != 1 or top[0]["mediaType"] != "application/vnd.oci.image.index.v1+json":
                        out.append("the %s layout's one descriptor is not an OCI index after the step: %s" % (name, top))
                    elif dig.get(key) != top[0]["digest"]:
                        out.append("the recorded %s (%s) is not the digest of the %s layout's index (%s)" % (key, dig.get(key), name, top[0]["digest"]))
                if dig.get("fixture-before") == dig.get("fixture-ours"):
                    out.append("the two fixture digests are the same")
                # every statement Scout applied in the root-cause round (Oct 23 run 39945154746) named the package as a subcomponent of the product; the self-check statement named none and the
                # self-check failed (Scout kept the finding)
                GLIBC = "pkg:deb/debian/glibc@2.36-9?os_distro=bookworm&os_name=debian&os_version=12"
                try:
                    stm = json.load(open(os.path.join(t, "attach", "selfcheck-ours.json")))["statements"]
                except (OSError, ValueError, KeyError) as e:
                    return out + ["the step does not write attach/selfcheck-ours.json (%s)" % e]
                want = [{"@id": "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache", "subcomponents": [{"@id": GLIBC}]}]
                if len(stm) != 1 or (stm[0].get("vulnerability") or {}).get("name") != "CVE-2023-4911" or stm[0].get("products") != want:
                    out.append("the self-check statement is not CVE-2023-4911 on our published product with the fixture's glibc package as its subcomponent (Scout keeps a finding whose package the statement does not name): %s" % (stm,))
            return out
        bad.extend(fixture_problems(fxs[0]["run"]))
        lines_ = fxs[0]["run"].rstrip("\n").split("\n")
        if not lines_[-1].lstrip().startswith("jq --arg b"):
            bad.append("the fixture step no longer ends with the jq line that records fixture-before and fixture-ours")
        elif not fixture_problems("\n".join(lines_[:-1])):
            bad.append("the fixture test does not notice when the step never records the fixture digests (a vacuous check)")
        elif "subcomponents" not in fxs[0]["run"] or not fixture_problems(fxs[0]["run"].replace("subcomponents", "subcomps")):
            bad.append("the fixture test does not notice when the self-check statement drops the subcomponent (a vacuous check)")
    for need in ("docker login ghcr.io", "-X DELETE", "14 days ago"):
        if need not in vt:
            bad.append("vex-attach lacks %s" % need)
    # the only registry name the job writes or reads is the scratch package (plus the pinned debian fixture): never the release package
    stripped = re.sub(r"repository_url=ghcr\.io/fosterstack/cache(?![-\w])", "", vt)
    if re.search(r"ghcr\.io/fosterstack/cache(?![-\w])", stripped) or re.search(r"cache-candidates|ghcr\.io/\$\{?GITHUB_REPOSITORY", stripped):
        bad.append("vex-attach names a package other than the scratch package")
    for m in re.finditer(r"docker://(\S+)", vt):
        ref = m.group(1).strip('"\\')
        if not (ref.startswith(SCRATCH + ":") or ref == "docker.io/library/debian@" + FIXTURE_DIGEST):
            bad.append("vex-attach touches the registry reference %s" % ref)
    for m in re.finditer(re.escape(SCRATCH) + r":([^\s\")]+)", vt):
        if not re.fullmatch(r"cand-\$\{GITHUB_RUN_ID\}-\$\{v\}|\$\{tag\}|selfcheck-(before|ours)-\$\{GITHUB_RUN_ID\}", m.group(1).rstrip('"')):
            bad.append("vex-attach pushes a tag that is not an attested candidate or a self-check fixture: %s" % m.group(1))
    if re.findall(r"packages/container/([A-Za-z0-9._-]+)", vt) != ["cache-scout-probe"]:
        bad.append("vex-attach prunes or reads a package other than the scratch package")
    for st in va.get("steps", []):
        if st.get("if") or str(st.get("continue-on-error", "false")) != "false":
            bad.append("vex-attach: step %r is conditional or may fail quietly" % st.get("name"))
ps = jobs.get("panel-scout", {})
scout_steps = ps.get("steps", [])
def step(name_part):
    hit = [x for x in scout_steps if name_part in (x.get("name") or "")]
    return hit[0] if len(hit) == 1 else None
pneeds = ps.get("needs", []); pneeds = pneeds if isinstance(pneeds, list) else [pneeds]
if "vex-attach" not in pneeds:
    bad.append("panel-scout does not wait for the attested candidates")
if (ps.get("permissions") or {}) != {"contents": "read", "packages": "read"}:
    bad.append("panel-scout must hold contents: read and packages: read only")
st_text = text("panel-scout")
if re.search(r"--vex-location|local://|docker-daemon:|skopeo", st_text):
    bad.append("panel-scout reads a local image or a local VEX file (Scout applies our statements only through the index's attestation)")
sc, scan, diag = step("rule 4 self-check"), step("Docker Scout every image"), step("attestation diagnostics")
if not sc or not scan or scout_steps.index(sc) > scout_steps.index(scan):
    bad.append("no Scout self-check before the scan")
else:
    if sc.get("continue-on-error") or sc.get("if"):
        bad.append("the Scout self-check can be skipped or softened")
    AUTHOR = r"--vex-author \\\^FosterStack\\ LLC\\\$"
    for mode in ("applies",):
        rc, log = run_block(sc.get("run", ""), mode)
        scouts = [l for l in log if l.startswith("docker scout cves")]
        if rc != 0:
            bad.append("the Scout self-check fails when Scout applies our attestation")
        want = ["docker scout cves --format gitlab --vex-author \\^FosterStack\\ LLC\\$ --platform linux/amd64 registry://%s@%s" % (SCRATCH, DIG[k])
                for k in ("fixture-before", "fixture-ours")]
        if scouts != want:
            bad.append("the self-check does not scan the fixture plain and attested, by exact digest, with our author: %s" % scouts)
    for mode in ("ignores", "drops-all", "empty"):
        if run_block(sc.get("run", ""), mode)[0] == 0:
            bad.append("the Scout self-check passes when Scout %s" % mode)
    rc, log = run_block(scan.get("run", ""), "applies")
    scouts = [l for l in log if l.startswith("docker scout cves")]
    sboms = [l for l in log if l.startswith("docker scout sbom")]
    want = ["docker scout cves --format gitlab --vex-author \\^FosterStack\\ LLC\\$ --platform linux/%s registry://%s@%s" % (a, SCRATCH, DIG[v])
            for v in ("production", "fips") for a in ("amd64", "arm64")]
    wsbom = ["docker scout sbom --format json --platform linux/%s registry://%s@%s" % (a, SCRATCH, DIG[v])
             for v in ("production", "fips") for a in ("amd64", "arm64")]
    if scouts != want or sboms != wsbom:
        bad.append("Scout's scan does not run on our four attested candidates by exact digest with our author: %s" % scouts)
    if rc != 0:
        bad.append("the Scout scan step fails on a clean day")
if not diag:
    bad.append("no Scout attestation diagnostics (read-back 5a/5b)")
else:
    # unconditional means it runs after a failed self-check too: a step without an `if` is skipped once an earlier step failed, which hid the 5a/5b data on the Oct 23 runs
    if str(diag.get("if", "")).strip() != "${{ !cancelled() }}" or diag.get("continue-on-error"):
        bad.append("the Scout diagnostics must carry exactly `if: ${{ !cancelled() }}` (they run after a failed self-check, where a step with no if is skipped, but not when the run is cancelled) and be contained inside the step, not continue-on-error")
    if str(diag.get("timeout-minutes", "")) != "10":
        bad.append("the Scout diagnostics must carry timeout-minutes: 10 (five Scout scans of a scratch image; a hung one must not hold the run)")
    if sc and scout_steps.index(diag) < scout_steps.index(sc):
        bad.append("the Scout diagnostics come before the self-check")
    for failing in ("docker", "skopeo", "sudo"):   # a diagnostic failure never fails the step
        if run_block(diag.get("run", ""), "applies", failing)[0] != 0:
            bad.append("the diagnostics step fails the job when %s fails" % failing)
    for need in ("GITHUB_STEP_SUMMARY", "ours-amd64", "ours-arm64", "ours-noplatform", "ours-tag", "exit 0"):
        if need not in diag.get("run", ""):
            bad.append("the diagnostics lack %s" % need)
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
if not re.search(r'\|\| \{[^}]*rm -rf "\$\{d\}"', ts_.split("docker scout sbom", 1)[-1]):
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
if not re.search(r"for arch in amd64 arm64; do", t) or '--platform "linux/${arch}"' not in t or "for v in production fips" not in t:
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
# (an empty id would download every artifact), and each scanner job writes only its own scanner's folder under /tmp/panel/ (scout also its scout-diag)
PANEL_SC = ("grype", "scout", "inspector", "google")
PANEL_EXTRA = {"scout": {"scout-diag"}}
for sc in PANEL_SC:
    jb = jobs["panel-" + sc]
    ups = [st for st in jb.get("steps", []) if str(st.get("uses", "")).startswith("actions/upload-artifact@")]
    if len(ups) != 1 or (ups[0].get("with") or {}).get("name") != "panel-" + sc or (ups[0].get("with") or {}).get("path") != "/tmp/panel/" or ups[0].get("id") != "upload":
        bad.append(f"panel-{sc} does not upload exactly one artifact panel-{sc} from /tmp/panel/ with the step id upload")
    if jb.get("outputs") != {"artifact-id": "${{ steps.upload.outputs.artifact-id }}"}:
        bad.append(f"panel-{sc} does not expose exactly the artifact-id of its upload: {jb.get('outputs')}")
    tops = set(re.findall(r"/tmp/panel/([A-Za-z0-9_-]+)", text("panel-" + sc)))
    if tops - ({sc} | PANEL_EXTRA.get(sc, set())):
        bad.append(f"panel-{sc} writes under /tmp/panel/ outside its own folder: {sorted(tops - ({sc} | PANEL_EXTRA.get(sc, set())))}")
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
case_ scout-keeps-partial     bad "s=$(step_of panel-scout 'docker scout sbom'); s['run'] = s['run'].replace('rm -rf \"\${d}\"; ', '')"
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
case_ scout-no-author         bad "s = [s for s in $J['panel-scout']['steps'] if 'self-check' in (s.get('name') or '')][0]; s['run'] = s['run'].replace(\"--vex-author '^FosterStack LLC\$' \", '')"
case_ scout-no-selfcheck      bad "$J['panel-scout']['steps'] = [s for s in $J['panel-scout']['steps'] if 'self-check' not in (s.get('name') or '')]"
case_ scout-selfcheck-soft    bad "[s for s in $J['panel-scout']['steps'] if 'self-check' in (s.get('name') or '')][0]['continue-on-error'] = 'true'"
case_ scout-selfcheck-exit0   bad "s = [s for s in $J['panel-scout']['steps'] if 'self-check' in (s.get('name') or '')][0]; s['run'] = 'exit 0\n' + s['run']"
case_ scout-selfcheck-nojudge bad "s = [s for s in $J['panel-scout']['steps'] if 'self-check' in (s.get('name') or '')][0]; s['run'] = s['run'].replace('python3 bin/scout-selfcheck.py', 'true')"
case_ scout-selfcheck-same    bad "s = [s for s in $J['panel-scout']['steps'] if 'self-check' in (s.get('name') or '')][0]; s['run'] = s['run'].replace('.\"fixture-ours\"', '.\"fixture-before\"')"
case_ scout-selfcheck-other-repo bad "s = [s for s in $J['panel-scout']['steps'] if 'self-check' in (s.get('name') or '')][0]; s['run'] = s['run'].replace('ghcr.io/fosterstack/cache-scout-probe', 'ghcr.io/another-vendor/cache-scout-probe')"
case_ scout-scan-other-repo   bad "s = $(step_of panel-scout 'for v in'); s['run'] = s['run'].replace('ghcr.io/fosterstack/cache-scout-probe', 'ghcr.io/fosterstack/cache')"
case_ scout-scan-local-vex    bad "s = $(step_of panel-scout 'for v in'); s['run'] = s['run'].replace('--vex-author', '--vex-location .vex/fosterstack-cache.openvex.json --vex-author')"
case_ scout-scan-no-author    bad "s = $(step_of panel-scout 'for v in'); s['run'] = s['run'].replace(\"--vex-author '^FosterStack LLC\$' \", '')"
case_ scout-scan-wrong-digest bad "s = $(step_of panel-scout 'for v in'); s['run'] = s['run'].replace('.[\$v]', '.production')"
case_ scout-no-attach-need    bad "$J['panel-scout']['needs'] = ['build']"
case_ scout-perms-write       bad "$J['panel-scout']['permissions']['packages'] = 'write'"
case_ scout-diag-fails        bad "s = [s for s in $J['panel-scout']['steps'] if 'diagnostics' in (s.get('name') or '')][0]; s['run'] = s['run'].replace('exit 0', 'exit \$rc')"
case_ scout-diag-always       bad "s = [s for s in $J['panel-scout']['steps'] if 'diagnostics' in (s.get('name') or '')][0]; s['if'] = '\${{ always() }}'"
case_ scout-diag-always-and   bad "s = [s for s in $J['panel-scout']['steps'] if 'diagnostics' in (s.get('name') or '')][0]; s['if'] = '\${{ always() && success() }}'"
case_ scout-diag-no-timeout   bad "s = [s for s in $J['panel-scout']['steps'] if 'diagnostics' in (s.get('name') or '')][0]; s.pop('timeout-minutes', None)"
case_ scout-diag-no-always    bad "s = [s for s in $J['panel-scout']['steps'] if 'diagnostics' in (s.get('name') or '')][0]; s.pop('if', None)"
case_ scout-diag-success-only bad "s = [s for s in $J['panel-scout']['steps'] if 'diagnostics' in (s.get('name') or '')][0]; s['if'] = '\${{ success() }}'"
case_ scout-diag-failure-only bad "s = [s for s in $J['panel-scout']['steps'] if 'diagnostics' in (s.get('name') or '')][0]; s['if'] = '\${{ failure() }}'"
case_ scout-diag-coe          bad "s = [s for s in $J['panel-scout']['steps'] if 'diagnostics' in (s.get('name') or '')][0]; s['continue-on-error'] = True"
case_ scout-diag-gone         bad "$J['panel-scout']['steps'] = [s for s in $J['panel-scout']['steps'] if 'diagnostics' not in (s.get('name') or '')]"
case_ attach-gone             bad "$J.pop('vex-attach')"
case_ attach-perms-id-token   bad "$J['vex-attach']['permissions']['id-token'] = 'write'"
case_ attach-perms-wide       bad "$J['vex-attach']['permissions']['contents'] = 'write'"
case_ attach-environment      bad "$J['vex-attach']['environment'] = 'agent'"
case_ attach-conditional      bad "$J['vex-attach']['if'] = \"github.ref == 'refs/heads/main'\""
case_ attach-needs-more       bad "$J['vex-attach']['needs'] = ['build', 'panel-grype']"
case_ attach-needs-none       bad "$J['vex-attach']['needs'] = []"
case_ attach-release-package  bad "s = $(step_of vex-attach 'release-layout.py'); s['run'] = s['run'].replace('docker://ghcr.io/fosterstack/cache-scout-probe:', 'docker://ghcr.io/fosterstack/cache:')"
case_ attach-candidates-package bad "s = $(step_of vex-attach 'release-layout.py'); s['run'] = s['run'].replace('docker://ghcr.io/fosterstack/cache-scout-probe:', 'docker://ghcr.io/fosterstack/cache-candidates:')"
case_ attach-other-tag        bad "s = $(step_of vex-attach 'release-layout.py'); s['run'] = s['run'].replace('tag=\"cand-\${GITHUB_RUN_ID}-\${v}\"', 'tag=\"latest\"')"
case_ attach-reattests        bad "s = $(step_of vex-attach 'release-layout.py'); s['run'] = s['run'].replace('python3 bin/release-layout.py', 'python3 bin/vex-index.py layout --layout \"\${d}\" --vex .vex/fosterstack-cache.openvex.json\\npython3 bin/release-layout.py')"
case_ attach-no-build-digest  bad "s = $(step_of vex-attach 'release-layout.py'); s['run'] = s['run'].replace('[ \"\$(cat \"/tmp/oci/\${v}.digest\")\" = \"\${final}\" ]', 'true')"
case_ attach-push-tool        bad "s = $(step_of vex-attach 'release-layout.py'); s['run'] = s['run'] + '\\ncrane push \"\${d}\" ghcr.io/fosterstack/cache-scout-probe:x'"
case_ attach-second-tag       bad "s = $(step_of vex-attach 'release-layout.py'); s['run'] = s['run'] + '\\ntag=latest'"
case_ attach-tag-append       bad "s = $(step_of vex-attach 'release-layout.py'); s['run'] = s['run'].replace('skopeo copy', 'tag+=\\\"-x\\\"\\nskopeo copy', 1)"
case_ attach-tag-declare      bad "s = $(step_of vex-attach 'release-layout.py'); s['run'] = s['run'].replace('skopeo copy', 'declare tag=latest\\nskopeo copy', 1)"
case_ attach-tag-export       bad "s = $(step_of vex-attach 'release-layout.py'); s['run'] = s['run'].replace('skopeo copy', 'export tag=latest\\nskopeo copy', 1)"
case_ attach-tag-printf       bad "s = $(step_of vex-attach 'release-layout.py'); s['run'] = s['run'].replace('skopeo copy', 'printf -v tag %s latest\\nskopeo copy', 1)"
case_ attach-tag-read         bad "s = $(step_of vex-attach 'release-layout.py'); s['run'] = s['run'].replace('skopeo copy', 'read -r tag < /tmp/t\\nskopeo copy', 1)"
case_ attach-tag-local        bad "s = $(step_of vex-attach 'release-layout.py'); s['run'] = s['run'].replace('skopeo copy', 'local -r tag=latest\\nskopeo copy', 1)"
case_ attach-tag-semicolon    bad "s = $(step_of vex-attach 'release-layout.py'); s['run'] = s['run'].replace('skopeo copy', 'true; tag=\\\"x\\\" skopeo copy', 1)"
case_ attach-tag-case-arm         bad "s = $(step_of vex-attach 'release-layout.py'); s['run'] = s['run'].replace('skopeo copy', 'case x in x) tag=latest;; esac\\nskopeo copy', 1)"
case_ attach-tag-negated          bad "s = $(step_of vex-attach 'release-layout.py'); s['run'] = s['run'].replace('skopeo copy', '! tag=latest\\nskopeo copy', 1)"
case_ attach-tag-if               bad "s = $(step_of vex-attach 'release-layout.py'); s['run'] = s['run'].replace('skopeo copy', 'if tag=latest; then :; fi\\nskopeo copy', 1)"
case_ attach-tag-while            bad "s = $(step_of vex-attach 'release-layout.py'); s['run'] = s['run'].replace('skopeo copy', 'while tag=latest; do break; done\\nskopeo copy', 1)"
case_ attach-tag-prefix-assign    bad "s = $(step_of vex-attach 'release-layout.py'); s['run'] = s['run'].replace('skopeo copy', 'a=1 tag=latest\\nskopeo copy', 1)"
case_ attach-tag-lookalike-ok     ok "s = $(step_of vex-attach 'release-layout.py'); s['run'] = s['run'].replace('skopeo copy', 'a=btag=x\\nskopeo copy', 1)"
case_ attach-two-copies       bad "s = $(step_of vex-attach 'release-layout.py'); s['run'] = s['run'] + '\\nskopeo copy --all oci:\"\${d}\" docker://ghcr.io/fosterstack/cache-scout-probe:other'"
case_ attach-no-layout-check  bad "s = $(step_of vex-attach 'release-layout.py'); s['run'] = s['run'].replace('python3 bin/release-layout.py', 'true')"
case_ attach-no-digest-check  bad "s = $(step_of vex-attach 'release-layout.py'); s['run'] = s['run'].replace('[ \"\${pushed}\" = \"\${final}\" ]', 'true')"
case_ attach-step-soft        bad "s = $(step_of vex-attach 'release-layout.py'); s['continue-on-error'] = 'true'"
case_ prune-gone              bad "$J['vex-attach']['steps'] = [s for s in $J['vex-attach']['steps'] if 'prune' not in (s.get('name') or '')]"
case_ prune-other-package     bad "s = $(step_of vex-attach 'DELETE'); s['run'] = s['run'].replace('packages/container/cache-scout-probe', 'packages/container/cache')"
case_ prune-forever           bad "s = $(step_of vex-attach 'DELETE'); s['run'] = s['run'].replace('14 days ago', '3650 days ago')"
case_ prune-list-masked       bad "s = $(step_of vex-attach 'DELETE'); s['run'] = s['run'].replace('exit 1\nfi\nn=0', 'ids=\"\"\nfi\nn=0')"
case_ prune-filter-gone       bad "s = $(step_of vex-attach 'DELETE'); s['run'] = s['run'].replace('select(.updated_at < ', 'select(true or ')"
case_ prune-filter-reversed   bad "s = $(step_of vex-attach 'DELETE'); s['run'] = s['run'].replace('.updated_at < ', '.updated_at > ')"
case_ prune-404-anywhere      bad "s = $(step_of vex-attach 'DELETE'); s['run'] = s['run'].replace('if ! ids=\$(', 'if false; ids=\$(')"
case_ rescan-concurrent       bad "d.pop('concurrency', None)"
case_ prune-delete-soft       bad "s = $(step_of vex-attach 'DELETE'); s['run'] = s['run'].replace('[ \"\${failed}\" -eq 0 ] ||', 'true ||')"
case_ prune-after-pushes      bad "st = $J['vex-attach']['steps']; k = [i for i, x in enumerate(st) if 'prune' in (x.get('name') or '')][0]; st.append(st.pop(k))"
case_ fixture-extra-tag       bad "s = [s for s in $J['vex-attach']['steps'] if 'self-check fixtures' in (s.get('name') or '')][0]; s['run'] = s['run'] + '\nskopeo copy --all oci:/tmp/layout/fixture docker://ghcr.io/fosterstack/cache-scout-probe:selfcheck-docker-1\n'"
case_ fixture-no-digest-check bad "s = [s for s in $J['vex-attach']['steps'] if 'self-check fixtures' in (s.get('name') or '')][0]; s['run'] = s['run'].replace('--digestfile /tmp/attach/ours.pushed ', '')"
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
