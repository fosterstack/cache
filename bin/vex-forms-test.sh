#!/usr/bin/env bash
# proves: REQ-SCAN-010-AC1, REQ-SCAN-010-AC2, REQ-SCAN-010-AC3, REQ-REL-001-AC2, REQ-REL-001-AC3
# Scanner-panel rule 10 (owner RATIFIED Oct 2; advisor 0076/0077): every release publishes our VEX three ways, all
# generated from the one OpenVEX file. "The same statements", in the advisor's exact words: the CSAF file carries every
# OpenVEX statement; the Inspector file carries one rule per suppressible statement (not_affected, fixed) and none for
# affected or under_investigation. Offline: no network, no cloud call.
set -euo pipefail
TMPDIR=$(mktemp -d); export TMPDIR; trap 'rm -rf "$TMPDIR"' EXIT  # python tempfile and mktemp dirs all live under this one, removed on exit
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
# Codex #165 r1 SEC-165-02: Google's loader (gcloud 587 vex_util._Validate / ParseVexFile) reads product_tree.branches —
# one per product, its name the image path (>= 3 path parts), its product carrying the product_id the statuses use
br = csaf["product_tree"]["branches"]
pids = {b["product"]["product_id"] for b in br}
check("CSAF branches are every released image digest, each named by the image path, its product by digest and purl",
      len(br) == 9 and all(b["name"] == "ghcr.io/fosterstack/cache" and len(b["name"].split("/")) >= 3 and b["category"] == "product_version"
                           and "ghcr.io/fosterstack/cache@sha256:" in b["product"]["name"]
                           and b["product"]["product_identification_helper"]["purl"].startswith("pkg:oci/cache@sha256:") for b in br), br)
def google_validate(doc):          # the loader's own checks, as gcloud 587.0.0 vex_util._Validate makes them
    bs = (doc.get("product_tree") or {}).get("branches")
    assert bs and all(b.get("name") and len(b["name"].split("/")) >= 3 for b in bs), "branches"
    assert doc.get("vulnerabilities") and all(v.get("product_status") for v in doc["vulnerabilities"]), "vulnerabilities"
    return {b["product"]["product_id"] for b in bs}
try:
    google_validate(csaf); ok = True
except AssertionError as e:
    ok = e
check("the CSAF passes the checks Google's loader makes", ok is True, ok)
try:                                # the real loader's own checks too, when the SDK is installed (not on CI runners)
    import ast, types
    _sdk = os.environ.get("GCLOUD_SDK_LIB")          # opt-in: the SDK's lib dir (no probing of fixed system install locations)
    src = os.path.join(_sdk, "googlecloudsdk/command_lib/artifacts/vex_util.py") if _sdk else None
    if src and not os.path.isfile(src):
        src = None
    if src:
        tree = ast.parse(open(src).read())
        fns = [n for n in tree.body if (isinstance(n, ast.FunctionDef) and n.name in ("_Validate", "_ValidateVulnerability"))
               or (isinstance(n, ast.Assign) and all(isinstance(t, ast.Name) and t.id.isupper() for t in n.targets))]
        class InvalidInputValueError(Exception): pass
        ns = {"ar_exceptions": types.SimpleNamespace(InvalidInputValueError=InvalidInputValueError),
              "log": types.SimpleNamespace(warning=lambda *a: None)}
        exec(compile(ast.Module(body=fns, type_ignores=[]), src, "exec"), ns)
        ns["_Validate"](csaf)
        check("the installed gcloud loader's own _Validate accepts the CSAF", True)
except Exception as e:
    check("the installed gcloud loader's own _Validate accepts the CSAF", False, repr(e))
check("a statement on the whole image lists every released image product", all(sorted(list(v["product_status"].values())[0]) == sorted(pids) for v in csaf["vulnerabilities"]))
# --- Codex #165 r1 SEC-165-01: each statement keeps its product and package scope
def scoped(cve, status, products, just="component_not_present"):
    x = st(cve, status, just if status == "not_affected" else None); x["products"] = products; return x
BB = [{"@id": "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache", "subcomponents": [{"@id": "pkg:generic/busybox@1.37.0"}]}]
FOREIGN = [{"@id": "pkg:oci/other?repository_url=ghcr.io/someone/other"}]
ONE = [{"@id": "pkg:oci/cache@%s?repository_url=ghcr.io/fosterstack/cache" % D("5").replace(":", "%3A")}]
SV = {"statements": [scoped("CVE-2099-10", "not_affected", BB), scoped("CVE-2099-11", "not_affected", FOREIGN),
                     scoped("CVE-2099-12", "not_affected", ONE)]}
ri = {r["filterCriteria"]["vulnerabilityId"][0]["value"]: r["filterCriteria"] for r in V.inspector(SV, IMAGES, "v0.3.0")["filters"]}
check("a package-scoped statement suppresses only that package and version",
      ri.get("CVE-2099-10", {}).get("vulnerablePackages") == [{"name": {"comparison": "EQUALS", "value": "busybox"},
                                                            "version": {"comparison": "EQUALS", "value": "1.37.0"}}], ri.get("CVE-2099-10"))
check("a statement about another repository's product suppresses nothing here", "CVE-2099-11" not in ri, sorted(ri))
check("a statement about one digest suppresses that digest only", [x["value"] for x in ri.get("CVE-2099-12", {}).get("ecrImageHash", [])] == [D("5")], ri.get("CVE-2099-12"))
cs = V.csaf(SV, IMAGES, "v0.3.0")
rel = {r["full_product_name"]["product_id"]: r for r in cs["product_tree"].get("relationships", [])}
v10 = next(v for v in cs["vulnerabilities"] if v["cve"] == "CVE-2099-10")
ids10 = list(v10["product_status"].values())[0]
check("in CSAF a package-scoped statement names the component inside each image (relationships), never the whole image",
      ids10 and all(i in rel and rel[i]["category"] == "default_component_of" for i in ids10)
      and not set(ids10) & {b["product"]["product_id"] for b in cs["product_tree"]["branches"]}, (ids10, list(rel)[:2]))
check("…so Google's loader, which reads branch products only, applies nothing for it (the safe direction)",
      not set(ids10) & google_validate(cs))
check("CSAF leaves out a statement about another repository's product", "CVE-2099-11" not in [v["cve"] for v in cs["vulnerabilities"]])
v12 = next(v for v in cs["vulnerabilities"] if v["cve"] == "CVE-2099-12")
check("CSAF scopes a one-digest statement to that digest's product", len(list(v12["product_status"].values())[0]) == 1)
# conflicting statements for the same image (and package) stop generation: never a suppression of an affected product
for name, sts in [("whole image affected, package not_affected", [scoped("CVE-2099-20", "not_affected", BB), scoped("CVE-2099-20", "affected", [{"@id": "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache"}])]),
                  ("one digest affected, the repo not_affected", [scoped("CVE-2099-21", "affected", ONE), scoped("CVE-2099-21", "not_affected", [{"@id": "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache"}])])]:
    try:
        V.inspector({"statements": sts}, IMAGES, "v0.3.0"); ok = False
    except ValueError:
        ok = True
    check("conflict refused: " + name, ok)
try:
    V.inspector({"statements": [scoped("CVE-2099-22", "not_affected", [{"@id": "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache&arch=amd64"}])]}, IMAGES, "v0.3.0"); ok = False
except ValueError:
    ok = True
check("a product qualifier the forms cannot represent stops generation (fail closed)", ok)
mixed = V.inspector({"statements": [scoped("CVE-2099-23", "affected", ONE), scoped("CVE-2099-23", "not_affected", [{"@id": "pkg:oci/cache@%s?repository_url=ghcr.io/fosterstack/cache" % D("1").replace(":", "%3A")}])]}, IMAGES, "v0.3.0")
check("disjoint scopes are fine: only the not_affected digest is suppressed",
      [x["value"] for r in mixed["filters"] for x in r["filterCriteria"]["ecrImageHash"]] == [D("1")], mixed)
# --- the command the guide will print, tested exactly as written against a stub aws (advisor 0077 check 2)
d = tempfile.mkdtemp(); fp = os.path.join(d, "fosterstack-cache-v0.3.0.inspector-filters.json"); json.dump(insp, open(fp, "w"))
stub = os.path.join(d, "aws"); open(stub, "w").write('#!/bin/sh\necho "$@" >> "%s/calls"\n' % d); os.chmod(stub, 0o755)
import subprocess
cmd = V.GUIDE_INSPECTOR_COMMAND.replace("<file>", fp)
subprocess.run(["bash", "-c", cmd], check=True, env=dict(os.environ, PATH=d + ":" + os.environ["PATH"]))
calls = open(os.path.join(d, "calls")).read().splitlines()
check("the guide's command calls create-filter once per rule, each with one rule's JSON", len(calls) == len(rules)
      and all(c.startswith("inspector2 create-filter --cli-input-json {") for c in calls), calls)
# Codex #165 r1 SEC-165-03: the command fails when the file is missing or a call fails, never reports success
bad = subprocess.run(["bash", "-c", V.GUIDE_INSPECTOR_COMMAND.replace("<file>", os.path.join(d, "missing.json"))],
                     env=dict(os.environ, PATH=d + ":" + os.environ["PATH"]), capture_output=True)
check("…and fails on a missing file", bad.returncode != 0)
open(stub, "w").write("#!/bin/sh\nexit 3\n")
bad = subprocess.run(["bash", "-c", cmd], env=dict(os.environ, PATH=d + ":" + os.environ["PATH"]), capture_output=True)
check("…and fails when a create-filter call fails", bad.returncode != 0)
# the Google step: the loader matches a branch name to --uri, so the guide renames the branches to the customer's image
g = V.GUIDE_GOOGLE_COMMAND
check("the guide's Google command renames the chosen digest's branch to the image it loads, then loads that file at that digest",
      "$DIGEST" in g and "load-vex" in g and '--uri="$IMAGE@$DIGEST"' in g, g)
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
rc = V.csaf(real, IMAGES, "v0.3.0")
check("the real file's CSAF passes the loader's checks; its busybox statements stay scoped to busybox 1.37.0",
      bool(google_validate(rc)) and all(r["product_reference"] == "component-busybox@1.37.0" for r in rc["product_tree"]["relationships"]))
if src:
    ns["_Validate"](rc)
    check("the installed gcloud loader's own _Validate accepts the real file's CSAF", True)
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
# --- Codex #165 r2: SEC-165-01 (version wildcards, qualifiers), SEC-165-07 (component identity), SEC-165-02 (titles),
#     SEC-165-06 (the Google step binds the chosen digest; exactly one branch matches)
def pkgst(cve, status, purl):
    return scoped(cve, status, [{"@id": "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache", "subcomponents": [{"@id": purl}]}])
for name, sts in [("unversioned not_affected vs versioned affected", [pkgst("CVE-2099-30", "not_affected", "pkg:generic/busybox"),
                                                                       pkgst("CVE-2099-30", "affected", "pkg:generic/busybox@1.37.0")]),
                  ("versioned not_affected vs unversioned affected", [pkgst("CVE-2099-31", "not_affected", "pkg:generic/busybox@1.37.0"),
                                                                       pkgst("CVE-2099-31", "affected", "pkg:generic/busybox")])]:
    try:
        V.inspector({"statements": sts}, IMAGES, "v0.3.0"); ok = False
    except ValueError:
        ok = True
    check("SEC-165-01 overlap refused: " + name, ok)
for purl in ("pkg:generic/busybox@1.37.0?arch=amd64", "pkg:generic/busybox@1.37.0#bin/wget"):
    try:
        V.inspector({"statements": [pkgst("CVE-2099-32", "not_affected", purl)]}, IMAGES, "v0.3.0"); ok = False
    except ValueError:
        ok = True
    check("SEC-165-01 an unrepresentable subcomponent restriction stops generation: " + purl, ok)
col = V.csaf({"statements": [pkgst("CVE-2099-33", "not_affected", "pkg:generic/busybox-extra@1.0"),
                             pkgst("CVE-2099-33", "affected", "pkg:generic/busybox@extra-1.0")]}, IMAGES, "v0.3.0")
check("SEC-165-07 distinct packages stay distinct CSAF components", len(col["product_tree"]["full_product_names"]) == 2,
      [p["product_id"] for p in col["product_tree"]["full_product_names"]])
rc = V.csaf(real, IMAGES, "v0.3.0")
check("SEC-165-02 every description note carries the title Google's loader reads",
      all(n.get("title") and n.get("text") for v in rc["vulnerabilities"] for n in v.get("notes", [])))
# the Google step, exactly as the guide prints it: rename only the chosen digest's branch, load with --uri path@digest
gd = tempfile.mkdtemp(); src = os.path.join(gd, "x.csaf.json"); json.dump(rc, open(src, "w"))
IMAGE, DIG = "us-east1-docker.pkg.dev/review-project/review-repo/cache", IMAGES["production"]["index"]
cmd = V.GUIDE_GOOGLE_COMMAND.replace("<file>", src).replace("gcloud artifacts", "echo gcloud artifacts")
out = subprocess.run(["bash", "-c", cmd], cwd=gd, env=dict(os.environ, IMAGE=IMAGE, DIGEST=DIG), capture_output=True, text=True)
mine = json.load(open(os.path.join(gd, "vex-for-my-image.json")))
named = [b for b in mine["product_tree"]["branches"] if b["name"] == IMAGE]
check("SEC-165-06 the guide renames exactly the chosen digest's branch", len(named) == 1
      and DIG in named[0]["product"]["product_identification_helper"]["purl"], [b["name"] for b in mine["product_tree"]["branches"]][:3])
check("SEC-165-06 the guide loads with --uri set to the image path at that digest", ("--uri=%s@%s" % (IMAGE, DIG)) in out.stdout, out.stdout)
try:                                # the installed SDK's own parser, as gcloud runs it, when present (not on CI runners)
    L = os.environ.get("GCLOUD_SDK_LIB")             # opt-in, as above
    L = L if L and os.path.isdir(L) else None
    if L:
        sys.path[:0] = [L, L + "/third_party"]
        from googlecloudsdk.command_lib.artifacts import vex_util as VU
        notes, uri = VU.ParseVexFile(os.path.join(gd, "vex-for-my-image.json"), IMAGE, IMAGE + "@" + DIG)
        whole = [v["cve"] for v in mine["vulnerabilities"] if any(i in {b["product"]["product_id"] for b in named}
                                                                  for ids in v["product_status"].values() for i in ids)]
        uris = {n.value.vulnerabilityAssessment.product.genericUri for n in notes}
        check("the installed gcloud parser makes one note per whole-image statement, bound to the chosen digest",
              len(notes) == len(whole) and uris == {"https://%s@%s" % (IMAGE, DIG)}, (len(notes), whole, uris))
except Exception as e:
    check("the installed gcloud parser loads the guide's file", False, repr(e))
# Sonnet #165 r3 (SEC-165-01, image level): a product naming OUR image in any form must parse exactly, or generation stops
D1 = D("1").replace(":", "%3A")
for pid in ("pkg:oci/cache@%s?repository_url=ghcr.io/fosterstack/cache#bin/foo" % D1,
            "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache#sub",
            "pkg:oci/cache@%s?repository_url=ghcr.io%%2Ffosterstack%%2Fcache#bin/foo" % D1,   # Sonnet r3b: encoded
            "pkg:oci/cache@%s?repository_url=ghcr.io%%2ffosterstack%%2fcache&arch=amd64" % D1,
            "pkg:oci/cache@@x?repository_url=ghcr.io/fosterstack/cache"):
    try:
        V._scopes(scoped("CVE-SUB2", "affected", [{"@id": pid}]), [D("1")]); ok = False
    except ValueError:
        ok = True
    check("SEC-165-01 our image's purl with an unrepresentable part stops generation: " + pid, ok)
check("SEC-165-01 a percent-encoded repository_url without subpath is still our image",
      V._scopes(scoped("CVE-ENC", "affected", [{"@id": "pkg:oci/cache@%s?repository_url=ghcr.io%%2Ffosterstack%%2Fcache" % D1}]), [D("1")]) == [([D("1")], None)])
check("SEC-165-01 a fork whose name extends ours is another repository, not ours",
      V._scopes(scoped("CVE-FORK", "affected", [{"@id": "pkg:oci/cache-fork?repository_url=ghcr.io/fosterstack/cache-fork#x"}]), [D("1")]) == [])
# Codex #165 r3 (SEC-165-01): identity is never discarded — a namespaced package and an identifiers-only product stop
# generation instead of widening a suppression or dropping an affected statement
OURS = "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache"
def refused(prod):
    try:
        V._scopes(scoped("CVE-ID", "affected", [prod]), [D("1")]); return False
    except ValueError:
        return True
for sub in ("pkg:golang/github.com/acme/busybox@1.37.0", "pkg:npm/%40acme/busybox@1.37.0", "pkg:deb/debian/libssl3@3.0.15-1"):
    check("SEC-165-01 a namespaced subcomponent stops generation: " + sub, refused({"@id": OURS, "subcomponents": [{"@id": sub}]}))
for name, prod in [("an IRI @id with our purl in identifiers", {"@id": "https://example.com/x", "identifiers": {"purl": OURS}}),
                   ("@id and identifiers.purl that differ", {"@id": OURS, "identifiers": {"purl": "pkg:oci/other?repository_url=ghcr.io/x/other"}}),
                   ("a CPE identifier", {"@id": OURS, "identifiers": {"purl": OURS, "cpe23": "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"}}),
                   ("a product with no purl at all", {"@id": "https://example.com/our-image"})]:
    check("SEC-165-01 %s stops generation" % name, refused(prod))
check("SEC-165-01 a product known only by identifiers.purl is resolved to our image",
      V._scopes(scoped("CVE-IO", "affected", [{"identifiers": {"purl": OURS}}]), [D("1")]) == [([D("1")], None)])
check("SEC-165-01 a subcomponent known only by identifiers.purl keeps its package",
      V._scopes(scoped("CVE-IS", "affected", [{"@id": OURS, "subcomponents": [{"identifiers": {"purl": "pkg:generic/busybox@1.37.0"}}]}]), [D("1")])
      == [([D("1")], ("busybox", "1.37.0"))])
pair = {"statements": [scoped("CVE-PAIR", "not_affected", [{"@id": OURS}]), scoped("CVE-PAIR", "affected", [{"identifiers": {"purl": OURS}}])]}
try:
    V._check_conflicts(pair, [D("1")]); got = "accepted"
except ValueError:
    got = "refused"
check("SEC-165-01 the reviewer's pair (not_affected by @id, affected by identifiers) is a contradiction: refused", got == "refused", got)
check("SEC-165-01 @id and an equal identifiers.purl (the real file's form) is our image",
      V._scopes(scoped("CVE-EQ", "affected", [{"@id": OURS, "identifiers": {"purl": OURS}}]), [D("1")]) == [([D("1")], None)])
check("SEC-165-01 another repository's image named both ways is still not ours",
      V._scopes(scoped("CVE-OT", "affected", [{"@id": "pkg:oci/x?repository_url=ghcr.io/a/x", "identifiers": {"purl": "pkg:oci/x?repository_url=ghcr.io/a/x"}}]), [D("1")]) == [])
check("SEC-165-01 a Go module product stays out of image scope",
      V._scopes(scoped("CVE-GO", "affected", [{"@id": "pkg:golang/github.com/fosterstack/cache"}]), [D("1")]) == [])
# --- REQ-REL-001-AC2, AC3 (advisor 0362, Oct 10): a signed release-files.sha256 covers the manifest and the three VEX
#     files. Pinned twice: the steps' shape and order in the parsed workflow (judge), and the steps' own run text executed
#     in order (sign, the real upload step against a stub gh that stores and serves the draft's assets, the anonymous
#     check) against fixture files with a stub cosign whose "bundle" binds the blob's sha256 to the signer identity
#     (behaviour). Every mutant below must be caught by one of the two.
import copy, hashlib, re, shutil
WF = os.path.join(root, ".github/workflows/stage-promote.yml")
REL_FILES = ["/tmp/release-manifest.json", "/tmp/vex/fosterstack-cache.openvex.json",
             '"/tmp/vex/fosterstack-cache-${ver}.csaf.json"', '"/tmp/vex/fosterstack-cache-${ver}.inspector-filters.json"']
REL_NAMES = ["release-manifest.json", "fosterstack-cache.openvex.json", "fosterstack-cache-v9.9.9.csaf.json",
             "fosterstack-cache-v9.9.9.inspector-filters.json"]
DRAFT = "/tmp/release-files-draft"
DL_PATTERNS = ["release-files.sha256", "release-files.sha256.bundle", "release-manifest.json", "fosterstack-cache.openvex.json",
               '"fosterstack-cache-${ver}.csaf.json"', '"fosterstack-cache-${ver}.inspector-filters.json"']
GOOD_ID = "https://github.com/fosterstack/cache/.github/workflows/stage-promote.yml@refs/tags/v9.9.9"
STUB_COSIGN = r'''#!/usr/bin/env bash
# test stub: a "bundle" binds the blob's sha256 to the signer identity; verify-blob checks both and the issuer
printf '%s\n' "$*" >> "$STUB_CALLS"
op=$1; shift; blob= bundle= re= id= iss=
while [ $# -gt 0 ]; do case "$1" in
  --bundle) bundle=$2; shift 2;;
  --certificate-identity-regexp) re=$2; shift 2;; --certificate-identity-regexp=*) re=${1#*=}; shift;;
  --certificate-identity) id=$2; shift 2;; --certificate-identity=*) id=${1#*=}; shift;;
  --certificate-oidc-issuer) iss=$2; shift 2;; --certificate-oidc-issuer=*) iss=${1#*=}; shift;;
  --yes) shift;;
  -*) echo "stub cosign: unknown flag $1" >&2; exit 2;;
  *) blob=$1; shift;;
esac; done
h=$(sha256sum "$blob" | cut -d' ' -f1)
case "$op" in
  sign-blob) printf '%s %s\n' "$h" "$STUB_IDENTITY" > "$bundle";;
  verify-blob) [ "${STUB_VERIFY_ALWAYS:-}" = 1 ] && exit 0
    read -r bh bid < "$bundle"
    [ "$bh" = "$h" ] && [ "$iss" = https://token.actions.githubusercontent.com ] || exit 1
    if [ -n "$id" ]; then [ -z "$re" ] && [ "$bid" = "$id" ]; else [ -n "$re" ] && [[ "$bid" =~ $re ]]; fi;;
  *) exit 2;;
esac
'''
STUB_CURL = r'''#!/usr/bin/env bash
# test stub: serves the "published release" from $STUB_PUB by the URL's last path part, as curl -O would save it
for a in "$@"; do case "$a" in -*) ;; *) url=$a;; esac; done
printf '%s\n' "$url" >> "$STUB_URLS"
f=${url##*/}; [ "$f" = "${STUB_CURL_404:-}" ] && exit 22     # STUB_CURL_404: that asset is not (yet) served
[ -f "$STUB_PUB/$f" ] || exit 22
cp "$STUB_PUB/$f" "./$f"
[ "$f" = "${STUB_CURL_CHANGE:-}" ] && printf x >> "./$f"     # STUB_CURL_CHANGE: that asset is served with a byte added
exit 0
'''
STUB_GH = r'''#!/usr/bin/env bash
# test stub: the draft release is $STUB_PUB. upload stores each file by its base name (STUB_UPLOAD_SKIP drops one,
# STUB_UPLOAD_FLIP stores one with a byte appended); download copies the assets whose names match a -p glob into -D.
printf 'gh %s\n' "$*" >> "$STUB_CALLS.gh"
[ "$1" = release ] || exit 2
op=$2; shift 3
case "$op" in
  create|edit) exit 0;;
  upload) for f in "$@"; do b=${f##*/}; [ "$b" = "${STUB_UPLOAD_SKIP:-}" ] && continue
            cp "$f" "$STUB_PUB/$b"; [ "$b" = "${STUB_UPLOAD_FLIP:-}" ] && printf x >> "$STUB_PUB/$b"; done; exit 0;;
  download) dir= pats=()
    while [ $# -gt 0 ]; do case "$1" in -D) dir=$2; shift 2;; -p) pats+=("$2"); shift 2;;
      --repo) [ "$2" = "$GITHUB_REPOSITORY" ] || exit 3; shift 2;; *) exit 2;; esac; done
    n=0; for p in "${pats[@]}"; do for f in "$STUB_PUB"/$p; do [ -f "$f" ] && cp "$f" "$dir/" && n=$((n+1)); done; done
    [ "$n" -gt 0 ];;
  *) exit 2;;
esac
'''
def rel_src(c, n):
    return os.path.join(c, "tmp" if n == "release-manifest.json" else "tmp/vex", n)
def rel_case(missing=(), extra=True, identity=GOOD_ID):
    c = tempfile.mkdtemp()
    for d in ("tmp/vex", "work/dist", "bin", "pub"):
        os.makedirs(os.path.join(c, d))
    for n, body in (("cosign", STUB_COSIGN), ("curl", STUB_CURL), ("gh", STUB_GH), ("git", "#!/bin/sh\nexit 0\n")):
        p = os.path.join(c, "bin", n); open(p, "w").write(body); os.chmod(p, 0o755)
    for n in REL_NAMES:
        if n not in missing:
            open(rel_src(c, n), "w").write('{"f": "%s"}\n' % n)
    if extra:                       # a file beside the four that must NOT be listed
        open(os.path.join(c, "tmp/vex", "fosterstack-cache-v9.9.9.extra.json"), "w").write("{}\n")
    for p in ("work/dist/fscache.tar.gz", "work/dist/checksums.txt", "work/dist/fscache.sbom.json", "tmp/checksums.txt.bundle"):
        open(os.path.join(c, p), "w").write("x\n")
    env = dict(os.environ, PATH=os.path.join(c, "bin") + ":" + os.environ["PATH"], STUB_CALLS=os.path.join(c, "calls"),
               STUB_IDENTITY=identity, STUB_URLS=os.path.join(c, "urls"), STUB_PUB=os.path.join(c, "pub"),
               GITHUB_REF_NAME="v9.9.9", GITHUB_REF="refs/tags/v9.9.9", GITHUB_REPOSITORY="fosterstack/cache")
    return c, env
def rel_run(c, env, script, **extra):
    script = script.replace("/tmp/", c + "/tmp/")
    try:
        return subprocess.run(["bash", "-c", script], cwd=os.path.join(c, "work"), env=dict(env, **extra),
                              capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=60)
    except subprocess.TimeoutExpired:   # an unbounded retry: never ends
        return subprocess.CompletedProcess(script, 124, "", "timeout")
def rel_calls(c):
    p = os.path.join(c, "calls")
    return open(p).read().splitlines() if os.path.exists(p) else []
def rel_steps(steps):
    nm = [x.get("name", "") for x in steps]
    at = lambda p: next((i for i, n in enumerate(nm) if n.startswith(p)), None)
    sg = [i for i, x in enumerate(steps) if "release-files.sha256" in (x.get("run") or "") and "sign-blob" in (x.get("run") or "")]
    return at, sg
def anon_segment(run):              # the signer pin (idflags) and the release-files block of the anonymous step, as written
    L = run.splitlines()
    a = next(i for i, l in enumerate(L) if l.strip().startswith("refescaped="))
    b = next(i for i, l in enumerate(L) if i > a and "certificate-oidc-issuer" in l and l.rstrip().endswith(")"))
    m = next(i for i, l in enumerate(L) if "# release-files.sha256 (REQ-REL-001-AC3)" in l)
    e = next(i for i, l in enumerate(L) if i > m and l.strip().startswith('echo "anonymous cosign image'))
    return "set -euo pipefail\n" + "\n".join(L[a:b + 1] + L[m:e])
flat = lambda s: re.sub(r"\\\n\s*", "", s or "")
def rel_judge(steps):
    bad = []
    at, sg = rel_steps(steps)
    gen, man, up, anon, undraft = (at("generate the VEX in three forms"), at("assemble release-manifest.json"),
                                   at("create the draft release"), at("documented ANONYMOUS customer verification"), at("undraft"))
    if len(sg) != 1:
        return ["not exactly one step signs release-files.sha256: %s" % sg]
    s = sg[0]
    if None in (gen, man, up, anon, undraft) or not gen < man < s < up < anon < undraft:
        bad.append("the signing step is not after the VEX and manifest generation and before the release is created: %s" % ((gen, man, s, up, anon, undraft),))
    run = steps[s]["run"]
    if not run.startswith("set -euo pipefail\n"):
        bad.append("the signing step does not run under set -euo pipefail")
    m = re.search(r"\bfiles=\(\s*(.*?)\s*\)", run, re.S)
    if (m.group(1).split() if m else None) != REL_FILES:
        bad.append("the list does not name exactly the four files, in order: %s" % (m and m.group(1).split()))
    if len(re.findall(r"^\s*cosign sign-blob --yes release-files\.sha256 --bundle release-files\.sha256\.bundle\s*$", flat(run), re.M)) != 1:
        bad.append("release-files.sha256 is not signed by cosign sign-blob --yes ... --bundle release-files.sha256.bundle")
    if 'while IFS= read -r line || [ -n "$line" ]; do' not in run:
        bad.append("the line check skips an unterminated last line")
    urun = flat(steps[up]["run"] if up is not None else "")
    ul = [l.strip() for l in urun.splitlines()]
    ups = [l.split() for l in ul if l.startswith('gh release upload "$ver"')]
    if not ups or not {"release-files.sha256", "release-files.sha256.bundle"} <= set(ups[0]):
        bad.append("the release upload list does not carry release-files.sha256 and its bundle")
    dls = [i for i, l in enumerate(ul) if l.startswith("gh release download")]
    want_dl = 'gh release download "$ver" --repo "$GITHUB_REPOSITORY" -D %s %s' % (DRAFT, " ".join("-p " + p for p in DL_PATTERNS))
    lastup = max([i for i, l in enumerate(ul) if l.startswith("gh release upload")] or [10 ** 6])
    if len(dls) != 1 or ul[dls[0]] != want_dl or dls[0] < lastup:
        bad.append("the draft's six assets are not downloaded by exact name after every upload: %s" % [ul[i] for i in dls])
    if ("mkdir %s" % DRAFT) not in ul:
        bad.append("the draft download directory is not created fresh (mkdir without -p)")
    ps = at(PUBLISHED)
    if ps is None or undraft is None or ps < undraft:
        bad.append("no anonymous check of the PUBLISHED release-files after the undraft step: %s" % ((undraft, ps),))
    else:
        pst = steps[ps]; prun = pst.get("run") or ""
        pc = [l.strip() for l in flat(prun).splitlines() if l.strip() and not l.strip().startswith("#")]
        if pst.get("env") != {"GH_TOKEN": "", "RETRY_SLEEP": "10"} or set(pst) - {"name", "env", "run"} \
                or "secrets." in prun or "github.token" in prun:
            bad.append("the published check is not credential-free (GH_TOKEN empty, no secret, no token): %s" % pst.get("env"))
        if not prun.startswith("set -euo pipefail\n") or 'base="https://github.com/${GITHUB_REPOSITORY}/releases/download/${ver}"' not in pc \
                or 'if (cd "$pub" && curl -fsSLO "${base}/${f}"); then ok=1; break; fi' not in pc:
            bad.append("the published check does not download anonymously from the published release as the docs do")
        if "for _ in 1 2 3 4 5 6; do" not in pc or 'sleep "${RETRY_SLEEP}"' not in pc:
            bad.append("the published download retry is not bounded (6 tries, injectable sleep)")
        if "release-files-draft" in prun or 'pub=$(mktemp -d)' not in pc:
            bad.append("the published check does not run on freshly downloaded public files")
        if "idflags=( --certificate-identity \"https://github.com/${GITHUB_REPOSITORY}/.github/workflows/stage-promote.yml@refs/tags/${ver}\"" not in pc \
                or 'cosign verify-blob --bundle "$pub/release-files.sha256.bundle" "${idflags[@]}" "$pub/release-files.sha256" \\' in pc \
                or not any(l.startswith('cosign verify-blob --bundle "$pub/release-files.sha256.bundle" "${idflags[@]}" "$pub/release-files.sha256"') for l in pc) \
                or not any(l.startswith('(cd "$pub" && sha256sum -c release-files.sha256 --strict)') for l in pc):
            bad.append("the published check does not run the documented verify-blob (exact identity) and sha256sum -c --strict")
        if 'cp "$pub/release-files.sha256" "$neg/release-files.sha256"' not in pc or "printf 'tamper\\n' >> \"$neg/release-files.sha256\"" not in pc \
                or 'if [ ! -f "$neg/release-files.sha256" ] || cmp -s "$pub/release-files.sha256" "$neg/release-files.sha256"; then' not in pc \
                or not any(l.startswith('if cosign verify-blob --bundle "$pub/release-files.sha256.bundle" "${idflags[@]}" "$neg/release-files.sha256"') for l in pc):
            bad.append("the published check has no negative control on a corrupted copy proven made and different")
        if "published release failed the anonymous release-files check: investigate" not in prun:
            bad.append("a published-release failure does not say the release is already public")
    try:
        seg = flat(anon_segment(steps[anon]["run"]))
    except (StopIteration, TypeError, KeyError):
        return bad + ["the anonymous verification has no release-files.sha256 block"]
    code = [l.strip() for l in seg.splitlines() if l.strip() and not l.strip().startswith("#")]
    if "rel=%s" % DRAFT not in code or any(l.startswith("cp ") and "$rel" in l and "release-files.corrupt" not in l for l in code):
        bad.append("the anonymous check does not run on the downloaded draft assets")
    vb = [l for l in code if "verify-blob" in l]
    pos = [l for l in vb if l.startswith('cosign verify-blob "$rel/release-files.sha256" --bundle "$rel/release-files.sha256.bundle" "${idflags[@]}" ||')]
    neg = [l for l in vb if l.startswith('if cosign verify-blob /tmp/release-files.corrupt --bundle "$rel/release-files.sha256.bundle" "${idflags[@]}"') and l.endswith("then")]
    if len(pos) != 1:
        bad.append("no anonymous verify-blob of release-files.sha256 with the pinned identity (idflags)")
    if len(neg) != 1 or 'cp "$rel/release-files.sha256" /tmp/release-files.corrupt' not in code \
            or "printf 'tamper\\n' >> /tmp/release-files.corrupt" not in code \
            or not 'if [ ! -f /tmp/release-files.corrupt ] || cmp -s "$rel/release-files.sha256" /tmp/release-files.corrupt; then' in code:
        bad.append("no negative control on a corrupted copy that is made on its own lines and proven to differ")
    if any("--certificate-identity" in l for l in vb):
        bad.append("a release-files verify-blob names its own identity instead of idflags")
    if not any(l.startswith('(cd "$rel" && sha256sum -c release-files.sha256 --strict)') for l in code):
        bad.append("no sha256sum -c --strict of the downloaded files against release-files.sha256")
    return bad
PUBLISHED = "documented anonymous verification of the PUBLISHED release-files"
def rel_pipeline(steps, identity=GOOD_ID, after_upload=None, before_published=None, pub_extra=None, **extra):
    """sign, upload (the real step, stub gh), anonymous draft check, undraft, anonymous check of the published release
    (stub curl serving what the draft stored); returns the first stage that failed, or ok"""
    at, sg = rel_steps(steps)
    c, env = rel_case(identity=identity)
    env.update(extra)
    if rel_run(c, env, steps[sg[0]]["run"]).returncode:
        return "sign"
    if rel_run(c, env, steps[at("create the draft release")]["run"]).returncode:
        return "upload"
    if after_upload:
        try:
            after_upload(c)
        except OSError:
            return "nothing downloaded to alter"
    if rel_run(c, env, anon_segment(steps[at("documented ANONYMOUS customer verification")]["run"])).returncode:
        return "verify"
    ud, ps = at("undraft"), at(PUBLISHED)
    if ud is None or ps is None or rel_run(c, env, steps[ud]["run"]).returncode:
        return "undraft"
    if before_published:
        before_published(c)
    penv = dict(env, RETRY_SLEEP="0", **(pub_extra or {}))
    penv.update({k: v for k, v in (steps[ps].get("env") or {}).items() if k != "RETRY_SLEEP"})
    if rel_run(c, penv, steps[ps]["run"]).returncode:
        return "published"
    return "ok"
def rel_behaviour(steps):
    bad = []
    at, sg = rel_steps(steps)
    if len(sg) != 1:
        return ["no single signing step to run"]
    srun = steps[sg[0]]["run"]
    # all four present (and an extra file beside them): exactly four lines, in order, hashes of those files; signed once
    c, env = rel_case()
    r = rel_run(c, env, srun)
    lst = os.path.join(c, "work", "release-files.sha256")
    want = ["%s  %s" % (hashlib.sha256(open(rel_src(c, n), "rb").read()).hexdigest(), n) for n in REL_NAMES]
    got = open(lst).read().splitlines() if os.path.exists(lst) else None
    if r.returncode != 0 or got != want:
        bad.append("all four present: the list is not exactly the four files' sha256 lines (rc %d, %s)" % (r.returncode, got))
    if rel_calls(c) != ["sign-blob --yes release-files.sha256 --bundle release-files.sha256.bundle"]:
        bad.append("cosign is not called once as sign-blob --yes release-files.sha256 --bundle release-files.sha256.bundle: %s" % rel_calls(c))
    # a missing file stops the step before signing
    for n in REL_NAMES:
        c2, env2 = rel_case(missing=(n,))
        r2 = rel_run(c2, env2, srun)
        if r2.returncode == 0 or rel_calls(c2) or os.path.exists(os.path.join(c2, "work", "release-files.sha256.bundle")):
            bad.append("a missing %s does not stop the step before signing" % n)
    # a symbolic link in place of a file stops the step too (the list names regular files only)
    c3, env3 = rel_case(missing=("fosterstack-cache.openvex.json",))
    os.symlink(os.path.join(c3, "tmp/vex", "fosterstack-cache-v9.9.9.extra.json"), rel_src(c3, "fosterstack-cache.openvex.json"))
    if rel_run(c3, env3, srun).returncode == 0 or rel_calls(c3):
        bad.append("a symbolic link in place of a listed file does not stop the step before signing")
    # an extra fifth line WITHOUT a trailing newline (sha256sum -c --strict would accept it) is refused before signing
    marker = "# exactly the four lines"
    if marker in srun:
        c4, env4 = rel_case()
        r4 = rel_run(c4, env4, srun.replace(marker, "printf '%s  x' \"$(printf 0%.0s {1..64})\" >> release-files.sha256\n" + marker, 1))
        if r4.returncode == 0 or rel_calls(c4):
            bad.append("an unterminated fifth line is not refused before signing")
    else:
        bad.append("the line check is not where the test expects it")
    # sign -> upload (what the draft stores) -> the anonymous check on the downloaded draft assets
    try:
        anon_segment(steps[at("documented ANONYMOUS customer verification")]["run"])
    except (StopIteration, TypeError, KeyError):
        return bad + ["no anonymous release-files block to run"]
    def edit(p, how="a"):
        return lambda cv: open(os.path.join(cv, p), how).write("x\n")
    def dangling(cv):               # the corrupted copy cannot be made: its path is a link into a directory that is absent
        os.symlink(os.path.join(cv, "absent", "x"), os.path.join(cv, "tmp", "release-files.corrupt"))
    cases = [("the release as signed and uploaded", {}, "ok"),
             ("the draft stores different bytes of the manifest", {"STUB_UPLOAD_FLIP": "release-manifest.json"}, "verify"),
             ("the draft stores different bytes of the list", {"STUB_UPLOAD_FLIP": "release-files.sha256"}, "verify"),
             ("the draft lacks the CSAF file", {"STUB_UPLOAD_SKIP": "fosterstack-cache-v9.9.9.csaf.json"}, "upload"),
             ("the draft lacks the bundle", {"STUB_UPLOAD_SKIP": "release-files.sha256.bundle"}, "upload"),
             ("a downloaded file differs from the list", {"after_upload": edit("tmp/release-files-draft/fosterstack-cache.openvex.json")}, "verify"),
             ("a corrupted downloaded list", {"after_upload": edit("tmp/release-files-draft/release-files.sha256")}, "verify"),
             ("an unsound verifier (accepts anything)", {"STUB_VERIFY_ALWAYS": "1"}, "verify"),
             ("the corrupted copy cannot be made", {"after_upload": dangling}, "verify")]
    for wrong in ("https://github.com/attacker/cache/.github/workflows/stage-promote.yml@refs/tags/v9.9.9",
                  "https://github.com/fosterstack/cache/.github/workflows/stage-image.yml@refs/tags/v9.9.9",
                  "https://github.com/fosterstack/cache/.github/workflows/stage-promote.yml@refs/heads/main"):
        cases.append(("a bundle signed as " + wrong, {"identity": wrong}, "verify"))
    def wrong_bundle(cv):           # the public bundle replaced by one from another workflow, over the same list
        h = hashlib.sha256(open(os.path.join(cv, "pub", "release-files.sha256"), "rb").read()).hexdigest()
        open(os.path.join(cv, "pub", "release-files.sha256.bundle"), "w").write(
            "%s https://github.com/fosterstack/cache/.github/workflows/stage-image.yml@refs/tags/v9.9.9\n" % h)
    cases += [("the published release serves a changed file", {"pub_extra": {"STUB_CURL_CHANGE": "fosterstack-cache.openvex.json"}}, "published"),
              ("the published release never serves the bundle", {"pub_extra": {"STUB_CURL_404": "release-files.sha256.bundle"}}, "published"),
              ("the published bundle is from another workflow", {"before_published": wrong_bundle}, "published"),
              ("an unsound verifier on the published files", {"pub_extra": {"STUB_VERIFY_ALWAYS": "1"}}, "published")]
    for name, kw, want_stage in cases:
        got_stage = rel_pipeline(steps, **kw)
        if got_stage != want_stage:
            bad.append("%s: stops at %s, want %s" % (name, got_stage, want_stage))
    # a missing public asset is retried a bounded number of times (6), then the step fails
    c5, env5 = rel_case()
    urls5 = env5["STUB_URLS"]
    if rel_pipeline_urls(steps, c5, env5, {"STUB_CURL_404": "release-files.sha256.bundle"}) != "published" \
            or sum(1 for u in open(urls5).read().splitlines() if u.endswith("/release-files.sha256.bundle")) != 6:
        bad.append("a missing public asset is not retried exactly 6 times and then failed")
    elif not all(u.startswith("https://github.com/fosterstack/cache/releases/download/v9.9.9/") for u in open(urls5).read().splitlines()):
        bad.append("the published check downloads from somewhere other than this release")
    return bad
def rel_pipeline_urls(steps, c, env, pub_extra):
    """the pipeline on a given case dir (so the caller can read the stub curl's URL log)"""
    at, sg = rel_steps(steps)
    for name in (None, "create the draft release"):
        if rel_run(c, env, steps[sg[0]]["run"] if name is None else steps[at(name)]["run"]).returncode:
            return "before"
    if rel_run(c, env, anon_segment(steps[at("documented ANONYMOUS customer verification")]["run"])).returncode:
        return "verify"
    ud, ps = at("undraft"), at(PUBLISHED)
    if ud is None or ps is None or rel_run(c, env, steps[ud]["run"]).returncode:
        return "undraft"
    penv = dict(env, RETRY_SLEEP="0", **pub_extra)
    penv.update({k: v for k, v in (steps[ps].get("env") or {}).items() if k != "RETRY_SLEEP"})
    return "published" if rel_run(c, penv, steps[ps]["run"]).returncode else "ok"
real_steps = yaml.load(open(WF), Loader=yaml.BaseLoader)["jobs"]["promote"]["steps"]
jb, bb = rel_judge(real_steps), rel_behaviour(real_steps)
check("REQ-REL-001-AC2/AC3 the real workflow: release-files.sha256 is written, signed, uploaded and verified as ruled", not jb and not bb, jb + bb)
def mut_run(pred, old, new):
    def f(st):
        hit = [x for x in st if pred(x.get("run") or "") and old in x["run"]]
        assert hit, "mutation does not apply: %r" % old
        for x in hit:
            x["run"] = x["run"].replace(old, new, 1)
    return f
is_sign = lambda r: "sign-blob" in r and "release-files.sha256" in r
is_up = lambda r: "gh release upload" in r
is_anon = lambda r: "release-files.corrupt" in r
def m_drop(st):
    st[:] = [x for x in st if not is_sign(x.get("run") or "")]
def m_after_publish(st):
    i = next(k for k, x in enumerate(st) if is_sign(x.get("run") or ""))
    x = st.pop(i); st.insert(next(k for k, y in enumerate(st) if is_up(y.get("run") or "")) + 1, x)
def m_drop_neg(st):
    x = next(y for y in st if is_anon(y.get("run") or ""))
    L = x["run"].splitlines(True); a = next(i for i, l in enumerate(L) if "if cosign verify-blob /tmp/release-files.corrupt" in l)
    x["run"] = "".join(L[:a] + L[a + 3:])
def m_old_neg(st):                  # the first form: cp && printf on one line, no proof the copy exists and differs
    x = next(y for y in st if is_anon(y.get("run") or ""))
    L = x["run"].splitlines(True); a = next(i for i, l in enumerate(L) if l.startswith('cp "$rel/release-files.sha256" /tmp/release-files.corrupt'))
    x["run"] = "".join(L[:a] + ['cp "$rel/release-files.sha256" /tmp/release-files.corrupt && printf \'tamper\\n\' >> /tmp/release-files.corrupt\n'] + L[a + 5:])
is_pub = lambda r: "published release failed the anonymous release-files check" in r
def m_pub_before_undraft(st):
    i = next(k for k, x in enumerate(st) if is_pub(x.get("run") or ""))
    x = st.pop(i); st.insert(next(k for k, y in enumerate(st) if (y.get("name") or "").startswith("undraft")), x)
def m_pub_drop_neg(st):
    x = next(y for y in st if is_pub(y.get("run") or ""))
    L = x["run"].splitlines(True); a = next(i for i, l in enumerate(L) if l.startswith('if cosign verify-blob --bundle "$pub/release-files.sha256.bundle" "${idflags[@]}" "$neg/'))
    x["run"] = "".join(L[:a] + L[a + 3:])
def m_pub_token(st):
    next(y for y in st if is_pub(y.get("run") or ""))["env"]["GH_TOKEN"] = "${{ github.token }}"
MUTANTS = [
    ("drop the signing step", m_drop),
    ("sign after the release is created", m_after_publish),
    ("drop one of the four files", mut_run(is_sign, '\n        "/tmp/vex/fosterstack-cache-${ver}.inspector-filters.json"', "")),
    ("add a fifth file", mut_run(is_sign, "files=( /tmp/release-manifest.json", "files=( /tmp/release-manifest.json /tmp/notes.md")),
    ("files in another order", mut_run(is_sign, "files=( /tmp/release-manifest.json\n        /tmp/vex/fosterstack-cache.openvex.json",
                                       "files=( /tmp/vex/fosterstack-cache.openvex.json\n        /tmp/release-manifest.json")),
    ("a missing file silently left out", mut_run(is_sign, 'inspector-filters.json" )\n',
        'inspector-filters.json" )\nkept=(); for f in "${files[@]}"; do [ -f "$f" ] && kept+=("$f"); done; files=("${kept[@]}")\n')),
    ("the existence check dropped", mut_run(is_sign, "[ -f \"$f\" ] && [ ! -L \"$f\" ] ||", "true ||")),
    ("the signing step without set -e", mut_run(is_sign, "set -euo pipefail", "set -uo pipefail")),
    ("an unterminated last line skipped", mut_run(is_sign, 'while IFS= read -r line || [ -n "$line" ]; do', "while IFS= read -r line; do")),
    ("signed with another bundle name", mut_run(is_sign, "--bundle release-files.sha256.bundle", "--bundle /tmp/release-files.bundle")),
    ("drop the bundle from the upload list", mut_run(is_up, " release-files.sha256.bundle", "")),
    ("drop the list from the upload list", mut_run(is_up, " release-files.sha256 ", " ")),
    ("a file modified between signing and upload", mut_run(is_up, "set -euo pipefail\n", "set -euo pipefail\nprintf x >> /tmp/release-manifest.json\n")),
    ("drop the draft download", mut_run(is_up, 'gh release download "$ver"', 'true "$ver"')),
    ("a loose download pattern", mut_run(is_up, "-p release-manifest.json", "-p '*.json'")),
    ("verify the local files instead of the downloaded draft", mut_run(is_anon, "rel=/tmp/release-files-draft",
        'rel=$(mktemp -d)\ncp release-files.sha256 release-files.sha256.bundle /tmp/release-manifest.json /tmp/vex/*.json "$rel/"')),
    ("drop the negative control", m_drop_neg),
    ("the negative control as cp && printf without the copy check", m_old_neg),
    ("verify with a different identity", mut_run(is_anon, 'cosign verify-blob "$rel/release-files.sha256" --bundle "$rel/release-files.sha256.bundle" "${idflags[@]}"',
        'cosign verify-blob "$rel/release-files.sha256" --bundle "$rel/release-files.sha256.bundle" --certificate-identity-regexp \'^https://github\\.com/\' --certificate-oidc-issuer \'https://token.actions.githubusercontent.com\'')),
    ("skip sha256sum -c", mut_run(is_anon, '(cd "$rel" && sha256sum -c release-files.sha256 --strict)', "true")),
    ("sha256sum -c without --strict", mut_run(is_anon, "sha256sum -c release-files.sha256 --strict", "sha256sum -c release-files.sha256")),
    ("the published check before the undraft", m_pub_before_undraft),
    ("the published check without its negative control", m_pub_drop_neg),
    ("the published check verifies the draft copies", mut_run(is_pub, "\ncosign verify-blob", "\npub=/tmp/release-files-draft\ncosign verify-blob")),
    ("the published check retries without bound", mut_run(is_pub, "for _ in 1 2 3 4 5 6; do", "while :; do")),
    ("the published check with a token", m_pub_token),
    ("the published check verifies a loose identity", mut_run(is_pub, '--certificate-identity "https://github.com/${GITHUB_REPOSITORY}/.github/workflows/stage-promote.yml@refs/tags/${ver}"',
        "--certificate-identity-regexp '^https://github\\.com/'")),
]
for name, fn in MUTANTS:
    st = copy.deepcopy(real_steps)
    try:
        fn(st); applied = True
    except (AssertionError, StopIteration) as e:
        applied = e
    caught = rel_judge(st) + (rel_behaviour(st) if applied is True else [])
    check("REQ-REL-001-AC2/AC3 mutant caught: " + name, applied is True and bool(caught), applied if applied is not True else caught)
print("REQ-REL-001-AC2/AC3: %d mutants" % len(MUTANTS))
# --- REQ-REL-001-AC3: the documented commands, run as written against the published files (stub curl and cosign)
doc = open(os.path.join(root, "docs/verify-images.md")).read()
blocks = [b for b in re.findall(r"```sh\n(.*?)```", doc, re.S) if "release-files.sha256" in b]
check("REQ-REL-001-AC3 the docs carry one command block for release-files.sha256", len(blocks) == 1, len(blocks))
dblock = blocks[0] if blocks else "false"
dflat = flat(dblock)
check("REQ-REL-001-AC3 the docs verify-blob names the exact identity (stage-promote.yml at the release tag) and the GitHub issuer",
      re.search(r"cosign verify-blob --bundle release-files\.sha256\.bundle "
                r"--certificate-identity \"https://github\.com/fosterstack/cache/\.github/workflows/stage-promote\.yml@refs/tags/v\$\{VER\}\" "
                r"--certificate-oidc-issuer='https://token\.actions\.githubusercontent\.com' release-files\.sha256", dflat) is not None, dflat)
check("REQ-REL-001-AC3 the docs check every listed file with sha256sum -c release-files.sha256",
      re.search(r"^sha256sum -c release-files\.sha256\b", dflat, re.M) is not None, dflat)
sent = re.search(r"applies from the release after v0\.2\.2.*signed manifest", doc)
check("REQ-REL-001-AC3 the docs say, before the commands, that the list applies from the release after v0.2.2 and how earlier releases are covered",
      sent is not None and blocks and sent.start() < doc.index(dblock))
def docs_run(mutate=None, identity=GOOD_ID):
    c, env = rel_case(identity=identity)
    sg = rel_steps(real_steps)[1]
    if len(sg) != 1 or rel_run(c, env, real_steps[sg[0]]["run"]).returncode != 0:
        return None, []
    pub = os.path.join(c, "pub"); dl = os.path.join(c, "dl"); os.makedirs(dl)
    for n in REL_NAMES:
        shutil.copy(rel_src(c, n), pub)
    for n in ("release-files.sha256", "release-files.sha256.bundle"):
        shutil.copy(os.path.join(c, "work", n), pub)
    if mutate:
        mutate(pub)
    r = subprocess.run(["bash", "-eo", "pipefail", "-c", dblock], cwd=dl, env=dict(env, VER="9.9.9"),
                       capture_output=True, text=True, stdin=subprocess.DEVNULL)
    urls = open(os.path.join(c, "urls")).read().splitlines() if os.path.exists(os.path.join(c, "urls")) else []
    return r.returncode, urls
rc, urls = docs_run()
check("REQ-REL-001-AC3 the documented commands succeed on the published files", rc == 0, rc)
check("REQ-REL-001-AC3 they download the two new assets and the four files anonymously from this release",
      sorted(u.rsplit("/", 1)[-1] for u in urls) == sorted(REL_NAMES + ["release-files.sha256", "release-files.sha256.bundle"])
      and all(u.startswith("https://github.com/fosterstack/cache/releases/download/v9.9.9/") for u in urls), urls)
rc, _ = docs_run(lambda p: open(os.path.join(p, "fosterstack-cache-v9.9.9.csaf.json"), "a").write("x\n"))
check("REQ-REL-001-AC3 the documented commands fail on a changed file", rc not in (0, None), rc)
rc, _ = docs_run(lambda p: open(os.path.join(p, "release-files.sha256"), "a").write("tamper\n"))
check("REQ-REL-001-AC3 the documented commands fail on a corrupted release-files.sha256", rc not in (0, None), rc)
for wrong in ("https://github.com/fosterstack/cache/.github/workflows/stage-image.yml@refs/tags/v9.9.9",
              "https://github.com/fosterstack/cache/.github/workflows/stage-promote.yml@refs/tags/v9.9.9x"):
    rc, _ = docs_run(identity=wrong)
    check("REQ-REL-001-AC3 the documented commands fail on a bundle signed as " + wrong, rc not in (0, None), rc)
print("vex-forms: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
PY
