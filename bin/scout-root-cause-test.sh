#!/usr/bin/env bash
# proves: REQ-SCAN-004-AC2
# The Docker Scout root-cause round (advisor 0120/0121/0122): the documents are vexctl's shape; the matrix holds Docker's
# documented control and changes one field at a time (author flag, directory vs file, *.vex.json vs our file name,
# subcomponent), then our forms, on Scout 1.26.0 and the two previous minors; the judge needs the target finding in the
# before report and none after, with every other finding kept.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
python3 - "$here/scout-root-cause.py" <<'PY'
import importlib.util, json, os, sys, tempfile
spec = importlib.util.spec_from_file_location("rc", sys.argv[1]); R = importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
passed = failed = 0
def check(name, ok, got=""):
    global passed, failed
    if ok: passed += 1; print("ok:", name)
    else: failed += 1; print("FAIL:", name, "->", got)
d = R.vex_doc("author@example.com", "pkg:docker/scoutcontrol/app@v1", "CVE-2099-1", "pkg:deb/debian/libc6@2.36-9")
st = d["statements"][0]
check("doc: OpenVEX v0.2.0 with author, timestamp, version 1", d["@context"] == "https://openvex.dev/ns/v0.2.0"
      and d["author"] == "author@example.com" and d["version"] == 1 and d["timestamp"] and d["@id"].startswith("https://"))
check("doc: one not_affected statement as vexctl writes it", st == {
    "vulnerability": {"name": "CVE-2099-1"}, "timestamp": d["timestamp"],
    "products": [{"@id": "pkg:docker/scoutcontrol/app@v1", "subcomponents": [{"@id": "pkg:deb/debian/libc6@2.36-9"}]}],
    "status": "not_affected", "justification": "vulnerable_code_not_in_execute_path"}, st)
check("doc: no subcomponent when none is given", "subcomponents" not in R.vex_doc("a", "p", "C", None)["statements"][0]["products"][0])
cases = R.cases()
ids = [c["id"] for c in cases]
check("author-re: an anchored, escaped regex (a dot and a space stay literal)", R.main(["author-re", "FosterStack LLC"]) == 0)
check("cases: unique ids", len(ids) == len(set(ids)), ids)
for v in ("1.26.0", "1.25.0", "1.24.0"):
    vc = {c["id"].split("@")[0]: c for c in cases if c["version"] == v}
    check("cases %s: Docker's documented control (directory, *.vex.json, no --vex-author)" % v,
          vc.get("control-doc", {}).get("location") == "dir" and vc["control-doc"]["file"].endswith(".vex.json")
          and vc["control-doc"]["author_flag"] is False and vc["control-doc"]["product"] == "pkg:docker/scoutcontrol/app@v1")
    F = ("location", "file", "author_flag", "sub", "product", "image")
    def changed(a, b):
        return {f for f in F if a[f] != b[f]}
    check("cases %s: control-author changes only the author flag" % v,
          "control-author" in vc and vc["control-author"]["author_flag"] is True and changed(vc["control-doc"], vc["control-author"]) == {"author_flag"})
    for k, field, val in [("control-file", "location", "file"), ("control-openvex-name", "file", "x.openvex.json"), ("control-no-sub", "sub", False)]:
        c = vc.get(k)
        check("cases %s: %s changes only %s from control-author" % (v, k, field),
              c is not None and c[field] == val and changed(vc["control-author"], c) == {field}, c)
    for k in ("ours-best-dir", "ours-published-dir", "ours-best-openvex-file"):
        check("cases %s: %s scans our image name" % (v, k), vc.get(k, {}).get("image") == "ghcr.io/fosterstack/cache:selfcheck")
check("cases: our published form is the product we publish", [c["product"] for c in cases if c["id"].startswith("ours-published-dir@")][0]
      == "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache")
check("cases: our failing condition reproduced (file path, .openvex.json)", all(c["location"] == "file" and c["file"].endswith(".openvex.json")
      for c in cases if c["id"].startswith("ours-best-openvex-file@")))
before = {("CVE-1", "pkg:deb/debian/a@1", "1"): 1, ("CVE-2", "pkg:deb/debian/b@2", "2"): 1}
check("judge: target gone, the rest kept: suppressed",
      R.judge(before, {("CVE-2", "pkg:deb/debian/b@2", "2"): 1}, "CVE-1", "pkg:deb/debian/a@1") == "suppressed")
check("judge: target kept: not applied", R.judge(before, dict(before), "CVE-1", "pkg:deb/debian/a@1") == "not applied")
check("judge: another finding lost too: inconclusive", R.judge(before, {}, "CVE-1", "pkg:deb/debian/a@1").startswith("inconclusive"))
check("judge: target absent before: inconclusive", R.judge(before, before, "CVE-9", "pkg:deb/debian/x@1").startswith("inconclusive"))
# Codex #176 r2, B3: judge() must match the exact (cve, package) identity, not every finding sharing the target CVE —
# otherwise a scoped suppression that leaves a different package's SAME CVE untouched looks unchanged (correctly not
# applied), but removing BOTH packages' findings for that CVE looks like scoped suppression (wrongly "suppressed")
before3 = {("CVE-1", "pkg:deb/debian/a@1", "1"): 1, ("CVE-1", "pkg:deb/debian/b@2", "2"): 1, ("CVE-2", "pkg:deb/debian/c@3", "3"): 1}
check("judge: removing only the target package is suppressed", R.judge(before3, {k: n for k, n in before3.items() if k[1] != "pkg:deb/debian/a@1"}, "CVE-1", "pkg:deb/debian/a@1") == "suppressed")
check("judge: removing a DIFFERENT package sharing the target CVE is inconclusive, not suppressed",
      R.judge(before3, {k: n for k, n in before3.items() if k[1] != "pkg:deb/debian/b@2"}, "CVE-1", "pkg:deb/debian/a@1").startswith("inconclusive"))
check("pick: requires an uncovered control finding to remain (so judge has something to prove unchanged)",
      R.pick({("CVE-1", "pkg:deb/debian/a@1", "1"): 1, ("CVE-1", "pkg:deb/debian/b@2", "2"): 1}) is None)
check("pick: a finding whose package has exactly one CVE, deterministic",
      R.pick({("CVE-3", "pkg:deb/debian/c@3", "3"): 1, ("CVE-1", "pkg:deb/debian/a@1", "1"): 1, ("CVE-2", "pkg:deb/debian/a@1", "1"): 1})
      == ("CVE-3", "pkg:deb/debian/c@3"))
print("scout-root-cause: %d passed, %d failed" % (passed, failed)); sys.exit(1 if failed else 0)
PY
# the runner writes only the scratch package: any other target is refused before anything runs, and the workflow names it
pass=0; fail=0
scratch=$(mktemp -d); e2e=; e4=; trap 'rm -rf "$scratch" "${e2e:-}" "${e4:-}"' EXIT
for target in ghcr.io/fosterstack/cache ghcr.io/fosterstack/cache-scout-probe2 docker.io/fosterstack/cache; do
  if out=$(SCOUT_DIR=/nonexistent PROBE_REPO="$target" RELEASE_TAG=x bash "$here/scout-root-cause.sh" "$scratch" 2>&1); then
    echo "FAIL: $target accepted"; fail=$((fail+1))
  elif grep -q "refusing to write to $target" <<<"$out"; then echo "ok: $target refused"; pass=$((pass+1))
  else echo "FAIL: $target: $out"; fail=$((fail+1)); fi
done
# Codex #176 r2, B2: install-scanner.sh never creates DEST; a fresh runner's install step must mkdir each
# per-iteration destination before calling it (passing a different, uncreated dir per docker-scout version)
out=$(python3 - "$here/../.github/workflows/main-candidate-rescan.yml" <<'PY'
import sys, yaml, re
d = yaml.safe_load(open(sys.argv[1]))
run = next(s["run"] for j in d["jobs"].values() for s in j.get("steps") or [] if "install docker-scout 1.26.0" in (s.get("name") or ""))
loop = re.search(r"for t in ([^;]+); do\n(.*?)\ndone", run, re.S).group(0)
ok = 'mkdir -p "$RUNNER_TEMP/$t"' in loop or 'mkdir -p "$RUNNER_TEMP/${t}"' in loop
print("ok" if ok else "BAD")
PY
)
if [ "$out" = ok ]; then echo "ok: the install loop creates each per-iteration destination"; pass=$((pass+1))
else echo "FAIL: the install loop never creates each per-iteration destination"; fail=$((fail+1)); fi
if grep -q "PROBE_REPO: ghcr.io/fosterstack/cache-scout-probe$" "$here/../.github/workflows/main-candidate-rescan.yml"; then
  echo "ok: the workflow targets the scratch package"; pass=$((pass+1))
else echo "FAIL: the workflow's PROBE_REPO is not the scratch package"; fail=$((fail+1)); fi
# Codex #176 r2, B4: digest() must never mistake a failed read for a real, unchanged digest (sha256 of empty input)
skopeo() { return 1; }   # a function shadows the real binary for this call only
source <(sed -n '/^digest() {/,+1p' "$here/scout-root-cause.sh")
out=$(digest "ghcr.io/x/y:z")
if [ "$out" = READ-FAILED ]; then echo "ok: a failed registry read reports READ-FAILED, not a digest"; pass=$((pass+1))
else echo "FAIL: a failed read produced $out"; fail=$((fail+1)); fi
unset -f skopeo
# advisor 0145: the scan() wrapper (forwarded "$@" into `docker scout cves`, hiding the real image argument from a
# static reader) was inlined at every call site -- same docker invocations, same redirects, same exit-code capture.
# Run the real script end to end (every external tool stubbed; bin/scout-root-cause.py runs for real, pure stdlib)
# and prove every expected `docker scout cves`/`attestation add` invocation still happens, with the same arguments.
e2e=$(mktemp -d); LOG="$e2e/docker.log"
cat > "$e2e/docker" <<'STUB'
#!/usr/bin/env bash
echo "docker $*" >> "$LOG"
case "$1 $2" in
  "scout cves") echo '{"vulnerabilities": []}' ;;
  "scout attestation") echo "attestation added" ;;
  "scout version") echo "v1.26.0" ;;
esac
STUB
cat > "$e2e/skopeo" <<'STUB'
#!/usr/bin/env bash
echo "skopeo $*" >> "$LOG"
case "$1" in
  inspect) echo "{\"manifests\": [], \"attached\": $(grep -c '^docker scout attestation add' "$LOG" 2>/dev/null || echo 0)}" ;;   # the index changes once an attestation was attached
esac
STUB
cat > "$e2e/install" <<'STUB'
#!/usr/bin/env bash
: > "${@: -1}"
STUB
chmod +x "$e2e/docker" "$e2e/skopeo" "$e2e/install"
SCOUT_DIR="$e2e" PROBE_REPO=ghcr.io/fosterstack/cache-scout-probe RELEASE_TAG=0.1.0 LOG="$LOG" HOME="$e2e/home" \
  PATH="$e2e:$PATH" bash "$here/scout-root-cause.sh" "$e2e/out" > "$e2e/run.log" 2>&1
rc=$?
if [ "$rc" -eq 0 ]; then echo "ok: the inlined script still runs end to end, exit 0"; pass=$((pass+1))
else echo "FAIL: the inlined script exited $rc: $(tail -5 "$e2e/run.log")"; fail=$((fail+1)); fi
no_scan=$(grep -c '^scan(' "$here/scout-root-cause.sh" || true)
if [ "$no_scan" -eq 0 ]; then echo "ok: the scan() wrapper is gone"; pass=$((pass+1))
else echo "FAIL: scan() wrapper still defined"; fail=$((fail+1)); fi
cves=$(grep -c '^docker scout cves' "$LOG" 2>/dev/null || true)
if [ "${cves:-0}" -eq 38 ]; then echo "ok: 38 docker scout cves invocations (2 attestation-path + 3 control-after + 1 control exact post-attachment digest + 1 release-author + 1 release exact post-attachment digest + 6 version warm-up + 24 matrix)"; pass=$((pass+1))
else echo "FAIL: expected 38 docker scout cves invocations, got ${cves:-0}"; fail=$((fail+1)); fi
# advisor 0214: the attestation path is judged on the POST-attachment index scanned by its EXACT new digest with --vex-author
# (the index digest changes when the attestation is attached, so signing must come after attaching): the control and the release copy
n_exact=$(grep -cE '^docker scout cves --format gitlab --vex-author .* registry://ghcr.io/fosterstack/cache-scout-probe@sha256:[0-9a-f]{64}$' "$LOG" || true)
if [ "${n_exact:-0}" -eq 2 ]; then echo "ok: the control and the release copy are each scanned by their exact post-attachment digest with --vex-author"; pass=$((pass+1))
else echo "FAIL: expected 2 exact-digest scans with --vex-author, got ${n_exact:-0}"; fail=$((fail+1)); fi
if grep -qF 'docker scout attestation list registry://ghcr.io/fosterstack/cache-scout-probe:release' "$LOG"; then echo "ok: the release copy's attestations are listed (why it got no attestation child)"; pass=$((pass+1))
else echo "FAIL: the release copy's attestation list is not recorded"; fail=$((fail+1)); fi
# the exact-digest scan names the digest AFTER attaching, never the pre-attach one (the stub's index changes once an attestation is added)
for t in control release; do
  b=$(cat "$e2e/out/attest/$t.before"); x=$(grep -o "scan $t by its exact post-attachment digest \`sha256:[0-9a-f]*" "$e2e/out/summary.md" | grep -o '[0-9a-f]\{64\}$')
  # and the digest in the ACTUAL scout command equals the one reported (a script reporting the new digest while scanning the old one fails)
  if [ "$t" = control ]; then va='^author@example\.com$'; else va='^FosterStack LLC$'; fi
  c=$(grep -F -- "--vex-author $va registry://ghcr.io/fosterstack/cache-scout-probe@sha256:" "$LOG" | grep -o '[0-9a-f]\{64\}$' | tail -1)
  if [ -n "$x" ] && [ "$x" != "$b" ] && [ "$c" = "$x" ]; then echo "ok: the $t exact-digest scan names, in the command itself, a digest different from the pre-attach one"; pass=$((pass+1))
  else echo "FAIL: the $t exact-digest scan is missing or names the pre-attach digest ($x vs $b)"; fail=$((fail+1)); fi
done
for want in "control-after-exact-digest" "release-after-exact-digest"; do
  if [ -e "$e2e/out/attest/$want.json" ]; then echo "ok: $want.json recorded"; pass=$((pass+1)); else echo "FAIL: $want.json missing"; fail=$((fail+1)); fi
done
if grep -qF 'docker scout cves --format gitlab registry://ghcr.io/fosterstack/cache-scout-probe:control' "$LOG"; then
  echo "ok: the control-before scan still names the scratch package over the registry"; pass=$((pass+1))
else echo "FAIL: the control-before scan invocation is missing or changed"; fail=$((fail+1)); fi
if grep -qF 'docker scout cves --format gitlab --vex-author ^author@example\.com$ registry://ghcr.io/fosterstack/cache-scout-probe:control' "$LOG"; then
  echo "ok: the tag+author control-after scan still carries --vex-author"; pass=$((pass+1))
else echo "FAIL: the tag+author control-after scan is missing or changed"; fail=$((fail+1)); fi
if grep -qF "docker scout attestation add --file $e2e/out/attest/control.vex.json --predicate-type https://openvex.dev/ns/v0.2.0 ghcr.io/fosterstack/cache-scout-probe:control" "$LOG"; then
  echo "ok: the control attestation add still runs with the same flags"; pass=$((pass+1))
else echo "FAIL: the control attestation add is missing or changed"; fail=$((fail+1)); fi
# advisor 0202: a fixture that HAS CVE-2023-4911: our statement is attached in two product forms (each on its own scratch tag)
# and scanned by tag with --vex-author for OUR published author; a fixture without the target tries nothing (above: 36, unchanged)
e4=$(mktemp -d); LOG4="$e4/docker.log"
cat > "$e4/docker" <<'STUB'
#!/usr/bin/env bash
echo "docker $*" >> "$LOG"
case "$1 $2" in
  "scout cves") echo '{"vulnerabilities": [{"id": "x1", "cve": "CVE-2023-4911", "identifiers": [{"type": "cve", "name": "CVE-2023-4911", "value": "CVE-2023-4911"}], "location": {"dependency": {"package": {"name": "pkg:deb/debian/glibc@2.36-9?os_distro=bookworm"}, "version": "2.36-9"}}}]}' ;;
  "scout attestation") echo "attestation added" ;;
  "scout version") echo "v1.26.0" ;;
  "buildx imagetools") [ -z "${FAIL_CREATE:-}" ] || { echo "ERROR: boom"; exit 1; }
                       case "$*" in *--file*) [ -z "${FAIL_FILE:-}" ] || { echo "ERROR: not found"; exit 1; } ;; esac ;;
esac
STUB
cp "$e2e/skopeo" "$e4/skopeo" 2>/dev/null || true
cat > "$e4/skopeo" <<'STUB'
#!/usr/bin/env bash
echo "skopeo $*" >> "$LOG"
case "$1" in
  inspect)
    att=$(grep -c '^docker scout attestation add' "$LOG" 2>/dev/null || true); att=${att:-0}
    case "$*" in
      *:child-a*) if grep -q 'attestation add .*:child-a' "$LOG"; then
                    echo '{"manifests": [{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":567,"annotations":{"vnd.docker.reference.type":"attestation-manifest","vnd.docker.reference.digest":"sha256:60774985572749dc3c39147d43089d53e7ce17b844eebcf619d84467160217ab"},"platform":{"architecture":"unknown","os":"unknown"}}, {"digest":"sha256:60774985572749dc3c39147d43089d53e7ce17b844eebcf619d84467160217ab","platform":{"os":"linux","architecture":"amd64"}}]}'
                  else echo '{"manifests": []}'; fi ;;
      *:multi-built*) b=$(grep -c 'imagetools create' "$LOG" 2>/dev/null || true)
                      if [ "${b:-0}" -gt 0 ]; then echo "{\"manifests\": [{\"digest\":\"sha256:aaaa\",\"annotations\":{\"vnd.docker.reference.type\":\"attestation-manifest\"}}], \"built\": $b}"
                      else echo "{\"manifests\": [], \"built\": 0, \"attached\": $att}"; fi ;;
      *) echo "{\"manifests\": [], \"attached\": $att}" ;;
    esac ;;
esac
STUB
cp "$e2e/install" "$e4/install" 2>/dev/null || printf '#!/usr/bin/env bash\n: > "${@: -1}"\n' > "$e4/install"
chmod +x "$e4/docker" "$e4/skopeo" "$e4/install"
mkdir -p "$e4/home"
SCOUT_DIR="$e4" PROBE_REPO=ghcr.io/fosterstack/cache-scout-probe RELEASE_TAG=0.1.0 LOG="$LOG4" HOME="$e4/home" \
  PATH="$e4:$PATH" bash "$here/scout-root-cause.sh" "$e4/out" > "$e4/run.log" 2>&1 || true
for k in published probe-tag; do
  if grep -qF "docker scout attestation add --file $e4/out/attest/ours-$k.vex.json --predicate-type https://openvex.dev/ns/v0.2.0 ghcr.io/fosterstack/cache-scout-probe:ours-$k" "$LOG4" \
     && grep -qF 'docker scout cves --format gitlab --vex-author ^FosterStack\ LLC$ registry://ghcr.io/fosterstack/cache-scout-probe:ours-'"$k" "$LOG4"; then
    echo "ok: our statement ($k form) is attached to its own scratch tag and scanned by tag with our author"; pass=$((pass+1))
  else echo "FAIL: our statement ($k form) is not attached or not scanned with our author"; fail=$((fail+1)); fi
done
if grep -qF 'pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache' "$e4/out/attest/ours-published.vex.json" && grep -qF 'pkg:docker/ghcr.io/fosterstack/cache-scout-probe@ours-probe-tag' "$e4/out/attest/ours-probe-tag.vex.json" \
   && grep -qF 'CVE-2023-4911' "$e4/out/attest/ours-published.vex.json"; then echo "ok: the two documents carry our product forms and the target CVE"; pass=$((pass+1))
else echo "FAIL: the probe documents are wrong"; fail=$((fail+1)); fi
n_ours=$(grep -cF -- '--vex-author ^FosterStack\ LLC$ registry://ghcr.io/fosterstack/cache-scout-probe@sha256:' "$LOG4" || true)
if [ "${n_ours:-0}" -eq 5 ]; then echo "ok: our statement is also scanned by an exact digest: once per form, plus the multi-platform index, its amd64 child and the built index"; pass=$((pass+1))
else echo "FAIL: expected 5 exact-digest scans with our author (2 forms + multi index + child + built index), got ${n_ours:-0}"; fail=$((fail+1)); fi
if grep -q 'ghcr.io/fosterstack/cache-scout-probe:ours-' "$LOG4" && ! grep -E 'skopeo copy .*docker://ghcr.io/fosterstack/cache:' "$LOG4" | grep -qE 'docker://ghcr.io/fosterstack/cache:[0-9a-z.-]+$'; then
  echo "ok: only the scratch package is written to"; pass=$((pass+1)); else echo "FAIL: a write outside the scratch package"; fail=$((fail+1)); fi
# advisor 0214 (probe 2): a MULTI-PLATFORM index (debian 12.0's manifest list; its amd64 child is the fixture) that HAS the target: our
# statement is attached to a scratch copy; index digest/children recorded before and after, the index scanned by tag and by exact digest
# and the amd64 child scanned by digest, all with our author; the attestations listed. The default run (no target) tries nothing.
MULTI=sha256:3d868b5eb908155f3784317b3dda2941df87bbbbaa4608f84881de66d9bb297b
if grep -qF "skopeo copy -q --all docker://docker.io/library/debian@$MULTI docker://ghcr.io/fosterstack/cache-scout-probe:multi" "$LOG4" \
   && grep -qF "docker scout attestation add --file $e4/out/attest/multi.vex.json --predicate-type https://openvex.dev/ns/v0.2.0 ghcr.io/fosterstack/cache-scout-probe:multi" "$LOG4"; then
  echo "ok: the multi-platform index is copied to its own scratch tag and our statement attached"; pass=$((pass+1))
else echo "FAIL: the multi-platform copy or attachment is missing"; fail=$((fail+1)); fi
if grep -qF 'docker scout cves --format gitlab --vex-author ^FosterStack\ LLC$ registry://ghcr.io/fosterstack/cache-scout-probe:multi' "$LOG4" \
   && grep -qE '^docker scout cves --format gitlab --vex-author \^FosterStack\\ LLC\$ registry://ghcr.io/fosterstack/cache-scout-probe@sha256:[0-9a-f]{64}$' "$LOG4" \
   && grep -qF 'docker scout cves --format gitlab --vex-author ^FosterStack\ LLC$ registry://ghcr.io/fosterstack/cache-scout-probe@sha256:60774985572749dc3c39147d43089d53e7ce17b844eebcf619d84467160217ab' "$LOG4"; then
  echo "ok: the multi-platform index is scanned by tag and by exact digest, and its amd64 child by digest, with our author"; pass=$((pass+1))
else echo "FAIL: the multi-platform scans are missing"; fail=$((fail+1)); fi
if grep -qF 'docker scout attestation list registry://ghcr.io/fosterstack/cache-scout-probe:multi' "$LOG4" && grep -q 'multi-platform index' "$e4/out/summary.md"; then
  echo "ok: the multi-platform attestations are listed and the result is in the summary"; pass=$((pass+1))
else echo "FAIL: the multi-platform attestation list or summary is missing"; fail=$((fail+1)); fi
if [ -e "$e2e/out/attest/multi.vex.json" ] || grep -q 'multi' "$LOG"; then echo "FAIL: a fixture without the target tried the multi-platform probe"; fail=$((fail+1))
else echo "ok: a fixture without the target tries no multi-platform probe"; pass=$((pass+1)); fi
# advisor 0221 (probe 3): the attestation-manifest child BUILT into a multi-platform index (Scout's own attach reports success on an index
# and stores nothing): Scout attaches to a copy of the amd64 child (it rewrites a single image into an index with an attestation-manifest
# child), that child's descriptor (annotations kept) is added to a copy of the original index with `docker buildx imagetools create`, and the
# built index is scanned by tag and by exact digest with our author; its children and attestations are recorded. No target, no attempt.
CHILD_FIX=sha256:60774985572749dc3c39147d43089d53e7ce17b844eebcf619d84467160217ab
if grep -qF "skopeo copy -q docker://docker.io/library/debian@$CHILD_FIX docker://ghcr.io/fosterstack/cache-scout-probe:child-a" "$LOG4" \
   && grep -qF "docker scout attestation add --file $e4/out/attest/built.vex.json --predicate-type https://openvex.dev/ns/v0.2.0 ghcr.io/fosterstack/cache-scout-probe:child-a" "$LOG4"; then
  echo "ok: the amd64 child is copied to its own scratch tag and our statement attached to it"; pass=$((pass+1))
else echo "FAIL: the child copy or its attachment is missing"; fail=$((fail+1)); fi
if grep -qF 'docker buildx imagetools create --tag ghcr.io/fosterstack/cache-scout-probe:multi-built' "$LOG4" \
   && grep -qF -- "--file $e4/out/attest/built-descriptor-nomt.json ghcr.io/fosterstack/cache-scout-probe@sha256:3d868b5eb908155f3784317b3dda2941df87bbbbaa4608f84881de66d9bb297b" "$LOG4" \
   && grep -qF 'vnd.docker.reference.type' "$e4/out/attest/built-descriptor.json" \
   && grep -qF 'vnd.docker.reference.digest' "$e4/out/attest/built-descriptor.json" && grep -qF 'sha256:aaaaaaaa' "$e4/out/attest/built-descriptor.json" \
   && ! grep -qF mediaType "$e4/out/attest/built-descriptor-nomt.json" && grep -qF 'vnd.docker.reference.type' "$e4/out/attest/built-descriptor-nomt.json" && grep -qF 'sha256:aaaaaaaa' "$e4/out/attest/built-descriptor-nomt.json"; then
  echo "ok: the attestation-manifest descriptor (annotations kept) is added to a copy of the original index"; pass=$((pass+1))
else echo "FAIL: the built index step or the descriptor is wrong"; fail=$((fail+1)); fi
if grep -qF 'docker scout cves --format gitlab --vex-author ^FosterStack\ LLC$ registry://ghcr.io/fosterstack/cache-scout-probe:multi-built' "$LOG4" \
   && grep -qF 'docker scout attestation list registry://ghcr.io/fosterstack/cache-scout-probe:multi-built' "$LOG4" && grep -q 'built index' "$e4/out/summary.md"; then
  echo "ok: the built index is scanned by tag with our author, its attestations listed, the result in the summary"; pass=$((pass+1))
else echo "FAIL: the built index scans or summary are missing"; fail=$((fail+1)); fi
bx=$(grep -c 'imagetools create' "$LOG" || true)
if [ "${bx:-0}" -eq 0 ] && ! grep -q 'child-a' "$LOG"; then echo "ok: a fixture without the target builds no index"; pass=$((pass+1))
else echo "FAIL: a fixture without the target tried the built-index probe"; fail=$((fail+1)); fi
# a FAILED create leaves the copied original at the tag: it must be reported inconclusive and never scanned as the built index
LOG5="$e4/docker5.log"
FAIL_CREATE=1 SCOUT_DIR="$e4" PROBE_REPO=ghcr.io/fosterstack/cache-scout-probe RELEASE_TAG=0.1.0 LOG="$LOG5" HOME="$e4/home" \
  PATH="$e4:$PATH" bash "$here/scout-root-cause.sh" "$e4/out5" > "$e4/run5.log" 2>&1 || true
if grep -q 'inconclusive (the create failed' "$e4/out5/summary.md" && ! grep -qF 'registry://ghcr.io/fosterstack/cache-scout-probe:multi-built' "$LOG5" \
   && ! grep -q 'attestation list registry://ghcr.io/fosterstack/cache-scout-probe:multi-built' "$LOG5"; then
  echo "ok: a failed create is inconclusive and the unchanged copy is never scanned as the built index"; pass=$((pass+1))
else echo "FAIL: a failed create was scanned or not reported inconclusive"; fail=$((fail+1)); fi
# the real run (probe 3) showed `--file` with a tag+digest source fail ("<repo>:latest: not found"): the probe then falls back to the
# two-source form with the descriptor annotations given as buildx annotations (a plain two-source form drops them: probe 3b) and scans whichever variant really built the index
LOG6="$e4/docker6.log"
FAIL_FILE=1 SCOUT_DIR="$e4" PROBE_REPO=ghcr.io/fosterstack/cache-scout-probe RELEASE_TAG=0.1.0 LOG="$LOG6" HOME="$e4/home" \
  PATH="$e4:$PATH" bash "$here/scout-root-cause.sh" "$e4/out6" > "$e4/run6.log" 2>&1 || true
if grep -qF 'docker buildx imagetools create --tag ghcr.io/fosterstack/cache-scout-probe:multi-built --annotation manifest-descriptor[unknown/unknown]:vnd.docker.reference.type=attestation-manifest --annotation manifest-descriptor[unknown/unknown]:vnd.docker.reference.digest=sha256:60774985572749dc3c39147d43089d53e7ce17b844eebcf619d84467160217ab ghcr.io/fosterstack/cache-scout-probe@sha256:3d868b5eb908155f3784317b3dda2941df87bbbbaa4608f84881de66d9bb297b ghcr.io/fosterstack/cache-scout-probe@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' "$LOG6" \
   && grep -qF 'registry://ghcr.io/fosterstack/cache-scout-probe:multi-built' "$LOG6" && grep -q 'variant annot' "$e4/out6/summary.md"; then
  echo "ok: when the --file form fails the annotated two-source form is tried and its built index is scanned"; pass=$((pass+1))
else echo "FAIL: the annotated fallback form was not tried or not scanned"; fail=$((fail+1)); fi
rm -rf "$e2e" "$e4"
echo "scout-root-cause guard: $pass passed, $fail failed"; [ "$fail" -eq 0 ]
