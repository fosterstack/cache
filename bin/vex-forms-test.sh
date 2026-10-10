#!/usr/bin/env bash
# proves: REQ-SCAN-010-AC1, REQ-SCAN-010-AC2, REQ-SCAN-010-AC3
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
    import glob, ast, types
    src = next(iter(glob.glob("/opt/homebrew/share/google-cloud-sdk/lib/googlecloudsdk/command_lib/artifacts/vex_util.py")
                    + glob.glob("/usr/lib/google-cloud-sdk/lib/googlecloudsdk/command_lib/artifacts/vex_util.py")), None)
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
    L = next((x for x in ("/opt/homebrew/share/google-cloud-sdk/lib", "/usr/lib/google-cloud-sdk/lib") if os.path.isdir(x)), None)
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
print("vex-forms: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
PY
