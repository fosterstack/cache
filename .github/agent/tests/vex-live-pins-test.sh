#!/usr/bin/env bash
# proves: REQ-SCAN-012-AC3
# The live test's page and orchestrator are read by the action-pin checker (scanner-panel rule 12, Codex #387 r1/r2). These cases moved here from
# bin/vex-live-test-test.sh: anything that names the checker lives under this folder (REQ-AUD-18 AC1).
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
python3 - "$root" <<'PY'
import importlib.util, os, shutil, subprocess, sys, tempfile
root = sys.argv[1]
passed = failed = 0
def check(name, ok, got=""):
    global passed, failed
    if ok: passed += 1; print("ok:", name)
    else: failed += 1; print("FAIL:", name, "->", got)
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, os.path.join(root, path))
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
L = load("lt", "bin/vex-live-test.py")
guide = open(os.path.join(root, "docs/using-our-vex.md")).read()

# --- Codex #387 r2: the page's command blocks are read by the pin checker like any script (a plain unpinned pull added to the page must not run with the job's credentials)
def pin_findings(doc_text):
    with tempfile.TemporaryDirectory() as t:
        os.makedirs(os.path.join(t, ".github/workflows")); os.makedirs(os.path.join(t, "bin"))
        shutil.copy(os.path.join(root, "bin/install-scanner.sh"), os.path.join(t, "bin/install-scanner.sh"))
        steps = ""
        for b in L.guide_blocks(doc_text):
            steps += "      - name: block\n        run: |\n" + "".join(("          " + ln if ln.strip() else "") + "\n" for ln in b["text"].rstrip("\n").split("\n"))
        open(os.path.join(t, ".github/workflows/page.yml"), "w").write("name: page\non: push\npermissions:\n  contents: read\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n" + steps)
        r = subprocess.run(["python3", "-I", os.path.join(root, ".github/agent/bin/check-action-pins.py"), "."], cwd=t, capture_output=True, text=True)
        return "\n".join(ln for ln in (r.stdout + r.stderr).split("\n") if "page.yml" in ln)   # the findings about the page's steps (the sandbox tree has no gate workflow)
res = pin_findings(guide)
check("SEC-387 the page's blocks, run as steps, have no pin-checker finding", res == "", res[-400:])
bad = guide.replace("```sh\ngrype ", "```sh\ndocker pull busybox:latest\ngrype ", 1)
check("SEC-387 a plain unpinned pull added to a block of the page is found by the pin checker", bad != guide and pin_findings(bad) != "")

# Codex #387 r1 (P1): the orchestrator runs against real registries, so the action-pin checker must READ it: its name is outside the checker's test-harness exemption, and an
# appended plain unpinned pull is found in the jobs that run it
_cap = importlib.util.spec_from_file_location("cap", os.path.join(root, ".github/agent/bin/check-action-pins.py")); CAP = importlib.util.module_from_spec(_cap); _cap.loader.exec_module(CAP)
check("the orchestrator is not exempt as a test harness", CAP.TEST_HARNESS.search("bin/vex-live-run.sh") is None and CAP.TEST_HARNESS.search("bin/vex-live-test-test.sh") is not None)

print("%d passed, %d failed" % (passed, failed)); sys.exit(1 if failed else 0)
PY
