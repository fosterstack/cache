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
source <(sed -n '/^digest() {/,+1p' "$here/scout-root-cause.sh")
out=$(digest "ghcr.io/x/y:z")
if [ "$out" = READ-FAILED ]; then echo "ok: a failed registry read reports READ-FAILED, not a digest"; pass=$((pass+1))
else echo "FAIL: a failed read produced $out"; fail=$((fail+1)); fi
unset -f skopeo
echo "scout-root-cause guard: $pass passed, $fail failed"; [ "$fail" -eq 0 ]
