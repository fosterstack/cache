#!/usr/bin/env bash
# proves: REQ-SCAN-010-AC1, REQ-SCAN-010-AC2, REQ-SCAN-010-AC3
# Scanner-panel rule 10 (owner RATIFIED Oct 2; advisor 0076/0077): every release publishes our VEX three ways, all
# generated from the one OpenVEX file. "The same statements", in the advisor's exact words: the CSAF file carries every
# OpenVEX statement; the Inspector file carries one rule per suppressible statement (not_affected, fixed) and none for
# affected or under_investigation. Offline: no network, no cloud call.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd); root=$(cd "$here/.." && pwd)
python3 - "$here/vex-forms.py" "$root" <<'PY'
import importlib.util, json, os, sys, tempfile
spec = importlib.util.spec_from_file_location("vf", sys.argv[1]); V = importlib.util.module_from_spec(spec); spec.loader.exec_module(V)
root = sys.argv[2]
passed = failed = 0
def check(name, ok, got=""):
    global passed, failed
    if ok: passed += 1; print("ok:", name)
    else: failed += 1; print("FAIL:", name, "->", got)
D = lambda c: "sha256:" + c * 64
IMAGES = {v: {"index": D(a), "children": {"linux/amd64": D(b), "linux/arm64": D(c)}}
          for v, a, b, c in (("production", "1", "2", "3"), ("debug", "4", "5", "6"), ("fips", "7", "8", "9"))}
def st(cve, status, just=None):
    s = {"vulnerability": {"name": cve, "@id": "https://nvd.nist.gov/vuln/detail/" + cve}, "status": status,
         "products": [{"@id": "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache"}],
         "timestamp": "2026-09-07T12:00:00-04:00"}
    if just: s["justification"] = just; s["impact_statement"] = "why " + cve
    if status == "affected": s["action_statement"] = "upgrade"
    return s
VEX = {"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://fosterstack.com/vex/cache/openvex", "author": "FosterStack LLC",
       "timestamp": "2026-09-20T09:00:00-04:00", "version": 6,
       "statements": [st("CVE-2099-1", "not_affected", "component_not_present"), st("CVE-2099-2", "fixed"),
                      st("CVE-2099-3", "affected"), st("CVE-2099-4", "under_investigation"),
                      st("CVE-2099-5", "not_affected", "vulnerable_code_not_in_execute_path")]}
insp = V.inspector(VEX, IMAGES, "v0.3.0")
csaf = V.csaf(VEX, IMAGES, "v0.3.0")
cves = lambda xs: sorted(xs)
# --- AC2, the advisor's words
check("the CSAF file carries every OpenVEX statement", cves(v["cve"] for v in csaf["vulnerabilities"]) == ["CVE-2099-%d" % i for i in range(1, 6)],
      [v["cve"] for v in csaf["vulnerabilities"]])
rules = insp["filters"]
rcves = cves(r["filterCriteria"]["vulnerabilityId"][0]["value"] for r in rules)
check("the Inspector file carries one rule per suppressible statement (not_affected, fixed)", rcves == ["CVE-2099-1", "CVE-2099-2", "CVE-2099-5"], rcves)
check("…and none for affected or under_investigation", not set(rcves) & {"CVE-2099-3", "CVE-2099-4"}, rcves)
check("each CVE has exactly one rule", len(rcves) == len(set(rcves)), rcves)
# statuses map one to one
want = {"CVE-2099-1": "known_not_affected", "CVE-2099-2": "fixed", "CVE-2099-3": "known_affected",
        "CVE-2099-4": "under_investigation", "CVE-2099-5": "known_not_affected"}
got = {v["cve"]: [k for k in v["product_status"]][0] for v in csaf["vulnerabilities"]}
check("CSAF product status mirrors each OpenVEX status", got == want, got)
just = {v["cve"]: v["flags"][0]["label"] for v in csaf["vulnerabilities"] if v.get("flags")}
check("not_affected justifications become CSAF flags with the same label", just == {"CVE-2099-1": "component_not_present",
      "CVE-2099-5": "vulnerable_code_not_in_execute_path"}, just)
# --- AC1: shape
all_digests = sorted(d for v in IMAGES.values() for d in [v["index"]] + list(v["children"].values()))
r1 = rules[0]
check("a rule suppresses, scoped by CVE and by every released image digest",
      r1["action"] == "SUPPRESS" and r1["filterCriteria"]["vulnerabilityId"] == [{"comparison": "EQUALS", "value": r1["filterCriteria"]["vulnerabilityId"][0]["value"]}]
      and sorted(x["value"] for x in r1["filterCriteria"]["ecrImageHash"]) == all_digests
      and all(x["comparison"] == "EQUALS" for x in r1["filterCriteria"]["ecrImageHash"]), r1)
check("each rule is a complete create-filter --cli-input-json document (name, action, filterCriteria, description)",
      all(set(r) == {"name", "action", "filterCriteria", "description", "reason"} and len(r["name"]) <= 128 and r["name"].startswith("fosterstack-cache-v0.3.0-")
          for r in rules), [r["name"] for r in rules])
check("no vendor or model name in any generated text", not any(w in json.dumps([insp, csaf]).lower() for w in ("anthropic", "claude", "openai", "gpt")))
pids = {p["product_id"] for p in csaf["product_tree"]["full_product_names"]}
check("CSAF products are every released image digest, each named by its image reference and purl",
      len(pids) == 9 and all(p["product_identification_helper"]["purl"].startswith("pkg:oci/cache@sha256:") and "ghcr.io/fosterstack/cache@sha256:" in p["name"]
                              for p in csaf["product_tree"]["full_product_names"]), csaf["product_tree"])
check("CSAF is a csaf_vex 2.0 document from the vendor", csaf["document"]["category"] == "csaf_vex" and csaf["document"]["csaf_version"] == "2.0"
      and csaf["document"]["publisher"]["category"] == "vendor" and csaf["document"]["tracking"]["status"] == "final", csaf["document"])
check("every CSAF status lists every product", all(sorted(list(v["product_status"].values())[0]) == sorted(pids) for v in csaf["vulnerabilities"]))
# --- the command the guide will print, tested exactly as written against a stub aws (advisor 0077 check 2)
d = tempfile.mkdtemp(); fp = os.path.join(d, "fosterstack-cache-v0.3.0.inspector-filters.json"); json.dump(insp, open(fp, "w"))
stub = os.path.join(d, "aws"); open(stub, "w").write('#!/bin/sh\necho "$@" >> "%s/calls"\n' % d); os.chmod(stub, 0o755)
import subprocess
cmd = V.GUIDE_INSPECTOR_COMMAND.replace("<file>", fp)
subprocess.run(["bash", "-c", cmd], check=True, env=dict(os.environ, PATH=d + ":" + os.environ["PATH"]))
calls = open(os.path.join(d, "calls")).read().splitlines()
check("the guide's command calls create-filter once per rule, each with one rule's JSON", len(calls) == len(rules)
      and all(c.startswith("inspector2 create-filter --cli-input-json {") for c in calls), calls)
# --- refusal: an unknown status, a missing image digest
try:
    V.inspector({"statements": [st("CVE-2099-9", "maybe")]}, IMAGES, "v0.3.0"); ok = False
except ValueError:
    ok = True
check("an unknown OpenVEX status is refused, never guessed", ok)
try:
    V.csaf(VEX, {"production": IMAGES["production"]}, "v0.3.0"); ok = False
except ValueError:
    ok = True
check("all three variants' digests are required", ok)
# --- the real OpenVEX file generates cleanly
real = json.load(open(os.path.join(root, ".vex/fosterstack-cache.openvex.json")))
check("the real OpenVEX file: CSAF carries all its statements", len(V.csaf(real, IMAGES, "v0.3.0")["vulnerabilities"]) == len(real["statements"]))
# --- AC3: our own pipeline keeps filtering against the OpenVEX file itself, never a derived form
rescan = open(os.path.join(root, ".github/workflows/main-candidate-rescan.yml")).read()
check("the rescan filters grype, docker scout and the tally against the OpenVEX file",
      rescan.count(".vex/fosterstack-cache.openvex.json") >= 3 and "inspector-filters" not in rescan and "csaf" not in rescan.lower())
# --- the release wiring (advisor 0077 check 1): generated BEFORE the signed manifest, which records all three sha256
import yaml
steps = yaml.load(open(os.path.join(root, ".github/workflows/stage-promote.yml")), Loader=yaml.BaseLoader)["jobs"]["promote"]["steps"]
names = [x.get("name", "") for x in steps]
gen = next((i for i, n in enumerate(names) if n.startswith("generate the VEX in three forms")), None)
man = next((i for i, n in enumerate(names) if n.startswith("assemble release-manifest.json")), None)
up = next((i for i, n in enumerate(names) if n.startswith("create the draft release")), None)
check("the three forms are generated before the manifest that the release signs", gen is not None and man is not None and gen < man, (gen, man))
grun = steps[gen]["run"] if gen is not None else ""
check("generated from the one OpenVEX file by bin/vex-forms.py", "python3 bin/vex-forms.py --openvex .vex/fosterstack-cache.openvex.json" in grun)
mrun = steps[man]["run"] if man is not None else ""
check("the manifest records all three files' sha256", all(k in mrun for k in ("vex_openvex_sha", "vex_inspector_sha", "vex_csaf_sha", "vex: [")))
urun = steps[up]["run"] if up is not None else ""
check("the release uploads the three files the manifest hashed", all(f in urun for f in (
    "/tmp/vex/fosterstack-cache.openvex.json", "fosterstack-cache-${ver}.inspector-filters.json", "fosterstack-cache-${ver}.csaf.json")))
print("vex-forms: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
PY
