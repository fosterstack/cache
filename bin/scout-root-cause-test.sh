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
# Codex probe r1, B1 / Sonnet M5: an EMPTY after-report is not a comparable one, so the target is never called suppressed from it
only_target = {("CVE-1", "pkg:deb/debian/a@1", "1"): 1}
check("judge: an empty after-report is inconclusive, never suppressed (several findings before)", R.judge(before, {}, "CVE-1", "pkg:deb/debian/a@1").startswith("inconclusive"))
check("judge: an empty after-report is inconclusive even when the target was the only finding before",
      R.judge(only_target, {}, "CVE-1", "pkg:deb/debian/a@1").startswith("inconclusive"))
check("judge: the target gone and at least one OTHER finding kept is still suppressed",
      R.judge(before, {("CVE-2", "pkg:deb/debian/b@2", "2"): 1}, "CVE-1", "pkg:deb/debian/a@1") == "suppressed")
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
for target in ghcr.io/fosterstack/cache ghcr.io/fosterstack/cache-scout-probe2 docker.io/fosterstack/cache; do
  if out=$(SCOUT_DIR=/nonexistent PROBE_REPO="$target" RELEASE_TAG=x bash "$here/scout-root-cause.sh" "$(mktemp -d)" 2>&1); then
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
source <(sed -n '/^digest() {/,/^}/p' "$here/scout-root-cause.sh")
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
# REQ-REL-010 AC6 (advisor 0214/0221 follow-up), section 1e: the FINAL INDEX F built by OUR tool (bin/vex-index.py compute, verify, push)
# from a scratch copy of debian 12.0's manifest list plus our statement; F is tagged `final-index` (the digest must survive the tag
# copy) and scanned by tag, by exact digest and through its amd64 child, with our author; the `final-base` control is scanned with no
# VEX. docker/skopeo are stubbed; python3 is a shim that runs bin/vex-index.py compute and verify FOR REAL and stubs only push (it
# needs a registry). The stub scanner answers by what it is asked: F's VEX is applied only when --vex-author names ours (a scan
# without the flag keeps the target), the control holds the target AND another finding, and F's report keeps the other finding.
# Knobs: BAD_BASE, NOCVE_BASE, NOSUP, NOSUP_DIGEST (tag applied, digest not), EMPTY_F (exit 0, empty report), RC_F (exit 1, empty
# report), F_OTHER (F's other finding differs), CONTROL_RC, BAD_1A, FAIL_BASE_COPY (stale tag stays), BASE_DIFF, CHANGE_TAG=1|NL,
# FAIL_PUSH, FAIL_VERIFY, PUSH_WRONG, NOCREDS, and FSCACHE_REGISTRY_USER/TOKEN.
e6=$(mktemp -d); S6="$e6/state"; mkdir -p "$S6"; REALPY=$(command -v python3)
cat > "$S6/base.raw" <<'JSON'
{"manifests":[{"digest":"sha256:60774985572749dc3c39147d43089d53e7ce17b844eebcf619d84467160217ab","mediaType":"application/vnd.docker.distribution.manifest.v2+json","platform":{"architecture":"amd64","os":"linux"},"size":529}],"mediaType":"application/vnd.docker.distribution.manifest.list.v2+json","schemaVersion":2}
JSON
cat > "$e6/docker" <<'STUB'
#!/usr/bin/env bash
echo "docker $*" >> "$LOG"
T='{"id": "x1", "cve": "CVE-2023-4911", "identifiers": [{"type": "cve", "name": "CVE-2023-4911", "value": "CVE-2023-4911"}], "location": {"dependency": {"package": {"name": "pkg:deb/debian/glibc@2.36-9?os_distro=bookworm"}, "version": "2.36-9"}}}'
O='{"id": "x2", "cve": "CVE-2024-0001", "identifiers": [{"type": "cve", "name": "CVE-2024-0001", "value": "CVE-2024-0001"}], "location": {"dependency": {"package": {"name": "pkg:deb/debian/zlib@1.2.13"}, "version": "1.2.13"}}}'
Z='{"id": "x3", "cve": "CVE-2024-0002", "identifiers": [{"type": "cve", "name": "CVE-2024-0002", "value": "CVE-2024-0002"}], "location": {"dependency": {"package": {"name": "pkg:deb/debian/bash@5.2"}, "version": "5.2"}}}'
FULL="{\"vulnerabilities\": [$T, $O]}"; SUP="{\"vulnerabilities\": [$O]}"; EMPTY='{"vulnerabilities": []}'
F=$(cat "$S6/F" 2>/dev/null || true)
auth=0; case "$*" in *"--vex-author ^FosterStack"*) auth=1 ;; esac
fscan() {  # $1 = tag|digest: what Scout answers for F
  [ -z "${RC_F:-}" ] || { echo "$SUP"; exit 1; }   # a report that would be suppressed, but the scan failed
  [ -z "${EMPTY_F:-}" ] || { echo "$EMPTY"; exit 0; }
  [ "$auth" = 1 ] || { echo "$FULL"; exit 0; }
  [ -z "${NOSUP:-}" ] || { echo "$FULL"; exit 0; }
  [ -z "${NOSUP_DIGEST:-}" ] || [ "$1" = tag ] || { echo "$FULL"; exit 0; }
  [ -z "${F_OTHER:-}" ] || { echo "{\"vulnerabilities\": [$Z]}"; exit 0; }
  echo "$SUP"; exit 0; }
case "$1 $2" in
  "scout cves") ref="${@: -1}"
     case "$ref" in
       *:final-base) if [ -n "${CONTROL_RC:-}" ]; then echo "$FULL"; exit "$CONTROL_RC"; fi; if [ -n "${NOCVE_BASE:-}" ]; then echo "$SUP"; else echo "$FULL"; fi ;;
       *:final-index) fscan tag ;;
       *:control) if [ -n "${BAD_1A:-}" ]; then echo 'not json'; else echo "$FULL"; fi ;;
       *) if [ -n "$F" ] && [ "$ref" = "registry://ghcr.io/fosterstack/cache-scout-probe@$F" ]; then fscan digest; else echo "$FULL"; fi ;;
     esac ;;
  "scout attestation") echo "attestation added" ;;
  "scout version") echo "v1.26.0" ;;
esac
STUB
cat > "$e6/skopeo" <<'STUB'
#!/usr/bin/env bash
F=$(cat "$S6/F" 2>/dev/null || true)
case "$*" in
  "inspect --raw docker://docker.io/library/debian@sha256:3d868b5e"*) echo "skopeo $*" >> "$LOG"; cat "$S6/base.raw" ;;
  "inspect --raw docker://"*:final-base) echo "skopeo $*" >> "$LOG"
     if [ -n "${BAD_BASE:-}" ] && [ -e "$S6/basedread" ]; then echo '{"manifests": []}'
     elif [ -n "${BASE_DIFF:-}" ]; then jq -c '.manifests[0].platform.os = "windows"' "$S6/base.raw"
     else cat "$S6/base.raw"; fi; touch "$S6/basedread" ;;
  "inspect --raw docker://"*:final-index) echo "skopeo $*" >> "$LOG"
     if [ "${CHANGE_TAG:-}" = NL ] && [ -e "$S6/tagcopied" ]; then cat "$S6/index.json"; printf '\n'
     elif [ -n "${CHANGE_TAG:-}" ] && [ -e "$S6/tagcopied" ]; then jq -c '.annotations = {"changed": "1"}' "$S6/index.json"
     else cat "$S6/index.json"; fi ;;
  "copy -q --all docker://docker.io/"*":final-base") echo "skopeo $*" >> "$LOG"; [ -z "${FAIL_BASE_COPY:-}" ] || { echo "FATA: boom" >&2; exit 1; } ;;
  "copy -q --all docker://"*"@sha256:"*" docker://"*:final-index) echo "skopeo $*" >> "$LOG"; touch "$S6/tagcopied" ;;
  "inspect --raw docker://"*"@$F") if [ -n "$F" ]; then echo "skopeo $*" >> "$LOG"; cat "$S6/index.json"; else exec "$E4/skopeo" "$@"; fi ;;
  *) exec "$E4/skopeo" "$@" ;;
esac
STUB
cat > "$e6/python3" <<'STUB'
#!/usr/bin/env bash
if [ "${1:-}" = bin/vex-index.py ]; then
  echo "python3 $*" >> "$LOG"
  if [ "${2:-}" = verify ] && [ -n "${FAIL_VERIFY:-}" ]; then echo "vex-index: refused: boom" >&2; exit 2; fi
  if [ "${2:-}" = push ]; then
    echo "push-env user=${FSCACHE_REGISTRY_USER:-unset} token=${FSCACHE_REGISTRY_TOKEN:+set}" >> "$LOG"
    [ -z "${FAIL_PUSH:-}" ] || { echo "vex-index: refused: boom" >&2; exit 2; }
    while [ $# -gt 0 ]; do [ "$1" = --dir ] && d=$2; shift; done
    cp "$d/index.json" "$S6/index.json"; echo "sha256:$(shasum -a 256 "$d/index.json" | cut -c1-64)" > "$S6/F"
    if [ -n "${PUSH_WRONG:-}" ]; then echo "sha256:0000000000000000000000000000000000000000000000000000000000000000"; else cat "$S6/F"; fi; exit 0
  fi
fi
exec "$REALPY" "$@"
STUB
chmod +x "$e6/docker" "$e6/skopeo" "$e6/python3"
cp "$e4/install" "$e6/install"
run6() {  # run6 NAME [ENV=VAL ...]: one stubbed run of the real script; $e6/NAME.log is the command log, $e6/NAME/summary.md the result
  local n=$1; shift; rm -rf "$S6/F" "$S6/index.json" "$S6/tagcopied" "$S6/basedread" "$e6/home-$n"; mkdir -p "$e6/home-$n/.docker"
  printf '{"auths": {"ghcr.io": {"auth": "%s"}}}' "$(printf 'someactor:sometoken' | base64 | tr -d '\n')" > "$e6/home-$n/.docker/config.json"
  case " $* " in *" NOCREDS=1 "*) echo '{}' > "$e6/home-$n/.docker/config.json" ;; esac
  env "$@" S6="$S6" E4="$e4" REALPY="$REALPY" SCOUT_DIR="$e6" PROBE_REPO=ghcr.io/fosterstack/cache-scout-probe RELEASE_TAG=0.1.0 LOG="$e6/$n.log" \
    HOME="$e6/home-$n" PATH="$e6:$PATH" bash "${SCRIPT6:-$here/scout-root-cause.sh}" "$e6/$n" > "$e6/$n.run" 2>&1 || true
}
SUMM() { echo "$e6/$1/summary.md"; }
P=ghcr.io/fosterstack/cache-scout-probe
t6() {  # t6 MESSAGE CMD... [AND CMD...]: passes when every AND-separated command succeeds
  local msg=$1 ok=1; shift; local seg=()
  while [ $# -gt 0 ]; do
    if [ "$1" = AND ]; then "${seg[@]}" || ok=0; seg=(); else seg+=("$1"); fi
    shift
  done
  [ ${#seg[@]} -eq 0 ] || "${seg[@]}" || ok=0
  if [ "$ok" = 1 ]; then echo "ok: $msg"; pass=$((pass+1)); else echo "FAIL: $msg"; fail=$((fail+1)); fi
}
has() { grep -qF -- "$2" "$1"; }          # has FILE TEXT
hasre() { grep -qE -- "$2" "$1"; }
lacks() { ! grep -qF -- "$2" "$1"; }
fchild() { grep '1e children of F' "$1" | grep -q attestation-manifest; }
nopush() { ! grep -q 'vex-index.py push' "$1"; }
run6 ok
t6 "section 1e is in the summary" hasre "$(SUMM ok)" '^### 1e\. '
t6 "1e copies the debian 12.0 manifest list to the scratch tag final-base" has "$e6/ok.log" "skopeo copy -q --all docker://docker.io/library/debian@sha256:3d868b5eb908155f3784317b3dda2941df87bbbbaa4608f84881de66d9bb297b docker://$P:final-base"
t6 "our tool runs compute, then verify, then push, once each, in that order" test "$(grep '^python3 bin/vex-index.py' "$e6/ok.log" | awk '{print $3}' | tr '\n' ' ')" = "compute verify push "
t6 "push targets the scratch repository only" hasre "$e6/ok.log" '^python3 bin/vex-index.py push --registry ghcr.io --repository fosterstack/cache-scout-probe --dir [^ ]+ --vex [^ ]+ --base [^ ]+$'
t6 "push takes its credentials from the registry login (docker config) in the environment" has "$e6/ok.log" 'push-env user=someactor token=set'
vexf="$e6/ok/attest/final/final.vex.json"
t6 "the VEX is ours: our author, one not_affected statement on CVE-2023-4911 for the published product form" jq -e '.author == "FosterStack LLC" and (.statements | length) == 1 and .statements[0].vulnerability.name == "CVE-2023-4911" and .statements[0].status == "not_affected" and .statements[0].products[0]["@id"] == "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache"' "$vexf" >/dev/null
# M8: the relabel changes the mediaType only, and compute AND verify are given that relabelled base
t6 "the relabelled base keeps its children untouched and only its mediaType changes" jq -e -n --slurpfile r "$e6/ok/attest/final/base.raw" --slurpfile b "$e6/ok/attest/final/base.json" '$b[0].manifests == $r[0].manifests and $b[0].mediaType == "application/vnd.oci.image.index.v1+json" and ($b[0] | del(.mediaType)) == ($r[0] | del(.mediaType))' >/dev/null
t6 "compute and verify both read the relabelled base file" test "$(grep -c -- "$e6/ok/attest/final/base.json" <(grep -E '^python3 bin/vex-index.py (compute|verify) ' "$e6/ok.log"))" = 2
F6=$(cat "$S6/F" 2>/dev/null || true)
t6 "F is recorded and copied to the tag final-index" test -n "$F6" AND has "$(SUMM ok)" "final index F \`$F6\`" AND has "$e6/ok.log" "skopeo copy -q --all docker://$P@$F6 docker://$P:final-index"
t6 "the tag copy's digest is asserted unchanged" hasre "$(SUMM ok)" 'tag final-index digest .* — unchanged'
t6 "the children of the base and of F (with attestation-manifest children) are recorded" test "$(grep -c '^- 1e children of' "$(SUMM ok)")" = 2 AND fchild "$(SUMM ok)"
t6 "the control is scanned with no VEX" has "$e6/ok.log" "docker scout cves --format gitlab registry://$P:final-base"
for ref in "$P:final-index" "$P@$F6" "$P@sha256:60774985572749dc3c39147d43089d53e7ce17b844eebcf619d84467160217ab"; do
  t6 "scanned with our author: $ref" has "$e6/ok.log" 'docker scout cves --format gitlab --vex-author ^FosterStack\ LLC$ registry://'"$ref"
done
t6 "the child scan's result line is recorded (M10)" hasre "$(SUMM ok)" "amd64 child scanned with --vex-author, by its digest .*: exit 0 — not applied"
t6 "the author flag is a real negative control: F scanned by digest WITHOUT --vex-author still shows the target" hasre "$(SUMM ok)" "without --vex-author, by its exact digest: exit 0 — not applied"
t6 "F's attestations are listed and recorded" test "$(grep -c "docker scout attestation list registry://$P:final-index" "$e6/ok.log")" = 1 AND hasre "$(SUMM ok)" '1e F attestation list'
t6 "F built and CVE-2023-4911 suppressed by tag and by digest, others kept, gives the pass line" has "$(SUMM ok)" '- 1e verdict: PASS'
t6 "the summary says what the probe does NOT prove" hasre "$(SUMM ok)" 'does NOT prove.*relabelled'
t6 "no registry token anywhere under the artifact directory or the run output" test -z "$(grep -rlF sometoken "$e6/ok" "$e6/ok.run" 2>/dev/null || true)"
run6 nosup NOSUP=1
t6 "F built but not suppressed gives the fail line" has "$(SUMM nosup)" '- 1e verdict: FAIL' AND lacks "$(SUMM nosup)" '- 1e verdict: PASS'
# B1 / M4: tag suppressed, digest not applied is a FAIL, not a pass
run6 halfsup NOSUP_DIGEST=1
t6 "tag suppressed but digest not applied is FAIL (both scans must apply it)" has "$(SUMM halfsup)" '- 1e verdict: FAIL' AND lacks "$(SUMM halfsup)" '- 1e verdict: PASS'
# B1: an empty report is no evidence of suppression
run6 emptyf EMPTY_F=1
t6 "exit 0 with an empty report is inconclusive, not suppressed or PASS" has "$(SUMM emptyf)" '- 1e verdict: inconclusive' AND lacks "$(SUMM emptyf)" '- 1e verdict: PASS' AND lacks "$(SUMM emptyf)" '- 1e verdict: FAIL'
run6 rcf RC_F=1
t6 "a nonzero scan exit is inconclusive even when its report looks suppressed" has "$(SUMM rcf)" '- 1e verdict: inconclusive' AND lacks "$(SUMM rcf)" '- 1e verdict: PASS'
# M5: the judge itself says inconclusive (another finding changed): the verdict is inconclusive, not PASS or FAIL
run6 fother F_OTHER=1
t6 "a changed OTHER finding (judge inconclusive) gives an inconclusive verdict" has "$(SUMM fother)" '- 1e verdict: inconclusive' AND lacks "$(SUMM fother)" '- 1e verdict: PASS' AND lacks "$(SUMM fother)" '- 1e verdict: FAIL'
run6 badbase BAD_BASE=1
t6 "a failed compute is inconclusive and nothing is pushed or tagged" has "$(SUMM badbase)" 'inconclusive (vex-index compute failed' AND nopush "$e6/badbase.log" AND lacks "$e6/badbase.log" ':final-index'
run6 failverify FAIL_VERIFY=1
t6 "a failed verify is inconclusive and nothing is pushed (M2)" has "$(SUMM failverify)" 'inconclusive (vex-index verify failed' AND nopush "$e6/failverify.log"
run6 nopush FAIL_PUSH=1
t6 "a failed push is inconclusive and F is not scanned" has "$(SUMM nopush)" 'inconclusive (vex-index push failed' AND lacks "$e6/nopush.log" "registry://$P:final-index"
run6 pushwrong PUSH_WRONG=1
t6 "a push that reports a digest other than compute's is inconclusive (M3)" has "$(SUMM pushwrong)" 'inconclusive (push reported' AND lacks "$e6/pushwrong.log" "registry://$P:final-index"
run6 ctlrc CONTROL_RC=1
t6 "a failed control scan is inconclusive and builds nothing (M1)" has "$(SUMM ctlrc)" 'inconclusive (the final-base control scan exited 1' AND lacks "$e6/ctlrc.log" 'vex-index.py'
run6 nocreds NOCREDS=1
t6 "without registry credentials 1e is inconclusive and builds and pushes nothing" has "$(SUMM nocreds)" 'inconclusive (no registry credentials' AND lacks "$e6/nocreds.log" 'vex-index.py'
run6 envcreds NOCREDS=1 FSCACHE_REGISTRY_USER=envuser FSCACHE_REGISTRY_TOKEN=envtoken
t6 "credentials from FSCACHE_REGISTRY_USER/TOKEN are used when set (M6)" has "$e6/envcreds.log" 'push-env user=envuser token=set' AND has "$(SUMM envcreds)" '- 1e verdict: PASS'
t6 "the environment token is not in the artifact directory, the summary or the run output" test -z "$(grep -rlF envtoken "$e6/envcreds" "$e6/envcreds.run" 2>/dev/null || true)"
run6 partial FSCACHE_REGISTRY_USER=onlyuser
t6 "a partial credential pair is a clear inconclusive, not a silent fallback to the docker config (R6)" has "$(SUMM partial)" 'inconclusive (partial registry credentials' AND nopush "$e6/partial.log"
t6 "no registry token under any failure run's artifact directory" test -z "$(grep -rlF sometoken "$e6/nopush" "$e6/failverify" "$e6/pushwrong" "$e6/badbase" "$e6/nosup" "$e6/partial" "$e6/nopush.run" 2>/dev/null || true)"
run6 chg CHANGE_TAG=1
t6 "a digest changed by the tag copy is flagged CHANGED and is not a pass" hasre "$(SUMM chg)" 'tag final-index digest .* — CHANGED' AND lacks "$(SUMM chg)" '- 1e verdict: PASS'
run6 chgnl CHANGE_TAG=NL
t6 "a tag whose bytes differ only by a trailing newline is CHANGED (B2: digest() hashes the raw bytes)" hasre "$(SUMM chgnl)" 'tag final-index digest .* — CHANGED' AND lacks "$(SUMM chgnl)" '- 1e verdict: PASS'
run6 stale FAIL_BASE_COPY=1
t6 "a failed final-base copy (stale tag left in place) is inconclusive and nothing is scanned or built (B3)" has "$(SUMM stale)" 'inconclusive (the copy to final-base failed' AND lacks "$e6/stale.log" 'vex-index.py' AND lacks "$e6/stale.log" "registry://$P:final-base"
run6 basediff BASE_DIFF=1
t6 "a final-base whose children differ from the source's is inconclusive and builds nothing (B3)" has "$(SUMM basediff)" 'inconclusive (final-base' AND lacks "$e6/basediff.log" 'vex-index.py'
run6 nocve NOCVE_BASE=1
t6 "a control without the CVE tries nothing" has "$(SUMM nocve)" 'not tried: the final-base control does not carry CVE-2023-4911' AND lacks "$e6/nocve.log" 'vex-index.py' AND lacks "$e6/nocve.log" ':final-index'
run6 bad1a BAD_1A=1; sed -n '/^### 1e\. /,/^## 2/p' "$(SUMM bad1a)" > "$e6/bad1a.1e"
t6 "an unreadable fixture report is inconclusive, not 'not tried'" has "$(SUMM bad1a)" '- 1e verdict: inconclusive (the fixture report' AND lacks "$e6/bad1a.1e" 'not tried: the fixture does not carry' AND lacks "$e6/bad1a.log" 'vex-index.py'
# an unreadable author is inconclusive too: a copy of the script whose ../.vex has no author
mkdir -p "$e6/tree/bin" "$e6/tree/.vex"; cp "$here/scout-root-cause.sh" "$e6/tree/bin/"; echo '{}' > "$e6/tree/.vex/fosterstack-cache.openvex.json"
SCRIPT6="$e6/tree/bin/scout-root-cause.sh" run6 noauthor
t6 "an unreadable author is inconclusive, not 'not tried'" has "$(SUMM noauthor)" '- 1e verdict: inconclusive (our author' AND lacks "$e6/noauthor.log" 'vex-index.py'
t6 "a fixture without the target (the first stub set) tries no section 1e" test -z "$(grep 'final-base\|vex-index' "$LOG" || true)"
t6 "the no-target summary says 1e was not tried" test -n "$(sed -n '/^### 1e\. /,/^## 2/p' "$e2e/out/summary.md" | grep 'not tried: the fixture does not carry CVE-2023-4911')"
[ -z "${KEEP6:-}" ] && rm -rf "$e6" || echo "$e6" > "$KEEP6"
rm -rf "$e2e" "$e4"
echo "scout-root-cause guard: $pass passed, $fail failed"; [ "$fail" -eq 0 ]
