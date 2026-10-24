#!/usr/bin/env bash
# proves: REQ-SCAN-010-AC1, REQ-SCAN-010-AC2, REQ-SCAN-010-AC3, REQ-SCAN-010-AC5, REQ-SCAN-010-AC6, REQ-SCAN-010-AC7, REQ-SCAN-010-AC8
# Scanner-panel rule 10 (owner RATIFIED Oct 2; advisor 0076/0077): every release publishes our VEX three ways, all
# generated from the one OpenVEX file. "The same statements", in the advisor's exact words: the CSAF file carries every
# OpenVEX statement; the Inspector file carries one rule per suppressible statement (not_affected, fixed) and none for
# affected or under_investigation. Offline: no network, no cloud call.
# AC5-AC8 (advisor step 5, Oct 11, handoff 0389): the digest file holds exactly production and fips (v0.3.0 ships no
# :debug image), is checked for shape and key set only, any other file is refused with nothing written, the same inputs
# give the same bytes, and this test proves the generator alone: it reads no workflow's step names or step order
# (Release's own test proves where the forms are generated, that the signed record covers them, and that the digests
# are Build's verified ones).
set -euo pipefail
TMPDIR=$(mktemp -d); export TMPDIR; trap 'rm -rf "$TMPDIR"' EXIT  # python tempfile and mktemp dirs all live under this one, removed on exit
here=$(cd "$(dirname "$0")" && pwd); root=$(cd "$here/.." && pwd)
python3 - "$here/vex-forms.py" "$root" "$here/vex-forms-test.sh" <<'PY'
import importlib.util, json, os, sys, tempfile
spec = importlib.util.spec_from_file_location("vf", sys.argv[1]); V = importlib.util.module_from_spec(spec); spec.loader.exec_module(V)
root = sys.argv[2]
passed = failed = 0
def check(name, ok, got=""):
    global passed, failed
    if ok: passed += 1; print("ok:", name)
    else: failed += 1; print("FAIL:", name, "->", got)
D = lambda c: "sha256:" + c * 64
# AC5: exactly two variants, production and fips, each an index and its two linux children (6 digests)
IMAGES = {v: {"index": D(a), "children": {"linux/amd64": D(b), "linux/arm64": D(c)}}
          for v, a, b, c in (("production", "1", "2", "3"), ("fips", "7", "8", "9"))}
def st(cve, status, just=None):
    s = {"vulnerability": {"name": cve, "@id": "https://nvd.nist.gov/vuln/detail/" + cve}, "status": status,
         "products": [{"@id": "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache"}],
         "timestamp": "2026-09-07T12:00:00-04:00"}
    if status in ("not_affected", "fixed"):           # a suppressible statement names its package (owner Oct 16: an Inspector rule always does)
        s["products"][0]["subcomponents"] = [{"@id": "pkg:generic/busybox@1.37.0"}]
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
      len(br) == 6 and all(b["name"] == "ghcr.io/fosterstack/cache" and len(b["name"].split("/")) >= 3 and b["category"] == "product_version"
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
check("a statement on the whole image lists every released image product", all(sorted(list(v["product_status"].values())[0]) == sorted(pids) for v in csaf["vulnerabilities"] if v["cve"] in ("CVE-2099-3", "CVE-2099-4")))
# --- Codex #165 r1 SEC-165-01: each statement keeps its product and package scope
def scoped(cve, status, products, just="component_not_present"):
    x = st(cve, status, just if status == "not_affected" else None); x["products"] = products; return x
BB = [{"@id": "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache", "subcomponents": [{"@id": "pkg:generic/busybox@1.37.0"}]}]
FOREIGN = [{"@id": "pkg:oci/other?repository_url=ghcr.io/someone/other"}]
ONE = [{"@id": "pkg:oci/cache@%s?repository_url=ghcr.io/fosterstack/cache" % D("8").replace(":", "%3A")}]   # a fips child
SV = {"statements": [scoped("CVE-2099-10", "not_affected", BB), scoped("CVE-2099-11", "not_affected", FOREIGN),
                     scoped("CVE-2099-12", "not_affected", ONE)]}
ri = {r["filterCriteria"]["vulnerabilityId"][0]["value"]: r["filterCriteria"] for r in V.inspector(SV, IMAGES, "v0.3.0")["filters"]}
check("a package-scoped statement suppresses only that package and version",
      ri.get("CVE-2099-10", {}).get("vulnerablePackages") == [{"name": {"comparison": "EQUALS", "value": "busybox"},
                                                            "version": {"comparison": "EQUALS", "value": "1.37.0"}}], ri.get("CVE-2099-10"))
check("a statement about another repository's product suppresses nothing here", "CVE-2099-11" not in ri, sorted(ri))
check("a statement about one digest and no package has no Inspector rule (owner Oct 16: a rule always names the package)", "CVE-2099-12" not in ri, ri.get("CVE-2099-12"))
# --- owner Oct 16 (handoff 0482): every Inspector rule names the vulnerable package; where a statement names none, the
# file has no rule for it (the finding stays visible); the same CVE in another package is never hidden
REPO_P = "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache"
ONEBB = [{"@id": ONE[0]["@id"], "subcomponents": [{"@id": "pkg:generic/busybox@1.37.0"}]}]
ANYVER = [{"@id": REPO_P, "subcomponents": [{"@id": "pkg:generic/zlib"}]}]
TOY = [{"@id": REPO_P, "subcomponents": [{"@id": "pkg:generic/toybox@0.8"}]}]
PK = {"statements": [scoped("CVE-2099-30", "not_affected", BB), scoped("CVE-2099-31", "not_affected", [{"@id": REPO_P}]),
                     scoped("CVE-2099-32", "fixed", ONEBB), scoped("CVE-2099-33", "not_affected", ANYVER),
                     scoped("CVE-2099-34", "affected", TOY)]}
rp = V.inspector(PK, IMAGES, "v0.3.0")["filters"]
rc = {r["filterCriteria"]["vulnerabilityId"][0]["value"]: r["filterCriteria"] for r in rp}
check("OWNER-3 every Inspector rule carries a vulnerablePackages entry with a name", rp and all(
      r["filterCriteria"].get("vulnerablePackages") and all(p.get("name", {}).get("value") for p in r["filterCriteria"]["vulnerablePackages"]) for r in rp), rp)
check("OWNER-3 a whole-image statement has no rule, so the CVE stays visible in every package", "CVE-2099-31" not in rc, sorted(rc))
check("OWNER-3 a package statement without a version names the package only",
      rc.get("CVE-2099-33", {}).get("vulnerablePackages") == [{"name": {"comparison": "EQUALS", "value": "zlib"}}], rc.get("CVE-2099-33"))
check("OWNER-3 one digest and one package: that digest and that package",
      [x["value"] for x in rc.get("CVE-2099-32", {}).get("ecrImageHash", [])] == [D("8")]
      and rc.get("CVE-2099-32", {}).get("vulnerablePackages", [{}])[0].get("name", {}).get("value") == "busybox", rc.get("CVE-2099-32"))
check("OWNER-3 the rules are exactly the package-named, suppressible statements", sorted(rc) == ["CVE-2099-30", "CVE-2099-32", "CVE-2099-33"], sorted(rc))
# Codex #381 r5/r6: Inspector's package filter has no ecosystem, so an ecosystem-specific package (npm, pypi, ...) would give one rule for two different packages: refused
for kind in ("npm", "pypi", "deb", "golang"):
    try:
        V.inspector({"statements": [scoped("CVE-2099-50", "not_affected", [{"@id": REPO_P, "subcomponents": [{"@id": "pkg:%s/foo@1" % kind}]}])]}, IMAGES, "v0.3.0"); got = "accepted"
    except ValueError:
        got = "refused"
    check("OWNER-3 a pkg:%s package is refused before any rule is made (only pkg:generic and a Go module path name a package these forms can carry; foo@1 has neither a namespace nor is generic)" % kind, got == "refused", got)
# the same CVE in two packages, only one of them not affected: the rule names that package alone
TWO = {"statements": [scoped("CVE-2099-40", "not_affected", BB), scoped("CVE-2099-40", "affected", TOY)]}
r2p = V.inspector(TWO, IMAGES, "v0.3.0")["filters"]
check("OWNER-3 the same CVE in two packages, one not affected: one rule, for that package and version only",
      len(r2p) == 1 and r2p[0]["filterCriteria"]["vulnerablePackages"] == [{"name": {"comparison": "EQUALS", "value": "busybox"},
                                                                          "version": {"comparison": "EQUALS", "value": "1.37.0"}}], r2p)
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
    V.inspector({"statements": [scoped("CVE-2099-22", "not_affected", [{"@id": "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache&tag=latest"}])]}, IMAGES, "v0.3.0"); ok = False
except ValueError:
    ok = True
check("a product qualifier the forms cannot represent stops generation (fail closed)", ok)
mixed = V.inspector({"statements": [scoped("CVE-2099-23", "affected", ONE), scoped("CVE-2099-23", "not_affected", [{"@id": "pkg:oci/cache@%s?repository_url=ghcr.io/fosterstack/cache" % D("1").replace(":", "%3A"), "subcomponents": [{"@id": "pkg:generic/busybox@1.37.0"}]}])]}, IMAGES, "v0.3.0")
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
# Codex #381 r1 (P2): a generated file with NO rule (every statement is affected or under investigation) is valid; the command then does nothing and succeeds
empty = os.path.join(d, "empty.json"); json.dump({"filters": []}, open(empty, "w"))
open(stub, "w").write('#!/bin/sh\necho "$@" >> "%s/calls-empty"\n' % d)
ok0 = subprocess.run(["bash", "-c", V.GUIDE_INSPECTOR_COMMAND.replace("<file>", empty)], env=dict(os.environ, PATH=d + ":" + os.environ["PATH"]), capture_output=True)
check("…and succeeds, calling nothing, for a valid file with no rule", ok0.returncode == 0 and not os.path.exists(os.path.join(d, "calls-empty")), (ok0.returncode, ok0.stderr[-120:]))
nofilters = os.path.join(d, "nofilters.json"); json.dump({}, open(nofilters, "w"))
bad = subprocess.run(["bash", "-c", V.GUIDE_INSPECTOR_COMMAND.replace("<file>", nofilters)], env=dict(os.environ, PATH=d + ":" + os.environ["PATH"]), capture_output=True)
check("…but a file without a filters list is not a generated file and fails", bad.returncode != 0)
# the Google step: the loader matches a branch name to --uri, so the guide renames the branches to the customer's image
g = V.GUIDE_GOOGLE_COMMAND
check("the guide's Google command renames the chosen digest's branch to the image it loads, then loads that file at that digest",
      "$DIGEST" in g and "load-vex" in g and '--uri="$IMAGE@$DIGEST"' in g, g)
# --- refusal: an unknown status, a missing variant
try:
    V.inspector({"statements": [st("CVE-2099-9", "maybe")]}, IMAGES, "v0.3.0"); ok = False
except ValueError:
    ok = True
check("an unknown OpenVEX status is refused, never guessed", ok)
for gone in ("fips", "production"):
    try:
        V.csaf(VEX, {k: v for k, v in IMAGES.items() if k != gone}, "v0.3.0"); ok = False
    except ValueError as e:
        ok = gone in str(e)
    check("AC6 both variants' digests are required: digests without %s are refused, naming it" % gone, ok)
# --- AC5, AC6, AC7: the generator as the release runs it, given a digest FILE by its path
import re as _re
GEN = sys.argv[1]
OPENVEX = os.path.join(root, ".vex/fosterstack-cache.openvex.json")
BBVEX = os.path.join(root, "test-evidence/vex-scope/busybox.openvex.json")   # the retired busybox statements, kept as a fixture: the generator's busybox scoping still has a document to run on
FORMS = ("fosterstack-cache-v0.3.0.inspector-filters.json", "fosterstack-cache-v0.3.0.csaf.json")
SYN = os.path.join(tempfile.mkdtemp(), "synthetic.openvex.json"); json.dump(VEX, open(SYN, "w"))   # every statement on the whole image
def run_gen(images_text, out, env=None, prelude="", openvex=SYN):
    """`vex-forms.py --images <file>`, the digest file written byte for byte as given (so a repeated key survives)"""
    f = os.path.join(tempfile.mkdtemp(), "digests.json"); open(f, "w").write(images_text)
    argv = [GEN, "--openvex", openvex, "--images", f, "--version", "v0.3.0", "--out-dir", out]
    code = prelude + "\nimport runpy, sys\nsys.argv = %r\nrunpy.run_path(%r, run_name='__main__')\n" % (argv, GEN)
    return subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, stdin=subprocess.DEVNULL,
                          env=env or dict(os.environ))
def digests_in(out):
    return {m.replace("%3A", ":") for f in FORMS if os.path.isfile(os.path.join(out, f))
            for m in _re.findall(r"sha\d+(?::|%3A)[0-9a-fA-F]+", open(os.path.join(out, f)).read())}
def six_of(imgs):
    return {d for v in imgs.values() for d in [v["index"]] + list(v["children"].values())}
J = json.dumps
out = tempfile.mkdtemp(); r = run_gen(J(IMAGES), out)
check("AC5 a digest file with exactly production and fips generates both forms",
      r.returncode == 0 and all(os.path.isfile(os.path.join(out, f)) for f in FORMS), (r.returncode, r.stderr[-300:]))
check("AC5 the forms name exactly the file's six digests and no other image digest", digests_in(out) == six_of(IMAGES),
      sorted(digests_in(out) ^ six_of(IMAGES)))
if r.returncode == 0:
    fi, fc = (json.load(open(os.path.join(out, f))) for f in FORMS)
    whole = fi["filters"]                                # every rule names a package; none is digest-limited in SYN
    check("AC5 every Inspector rule's ecrImageHash set is exactly the file's six digests",
          whole and all({c["value"] for c in x["filterCriteria"]["ecrImageHash"]} == six_of(IMAGES) for x in whole))
    check("AC5 the CSAF branches are exactly the file's six digests",
          sorted(b["product"]["product_identification_helper"]["purl"].split("@", 1)[1].split("?")[0] for b in fc["product_tree"]["branches"])
          == sorted(six_of(IMAGES)))
OTHER = {v: {"index": D(a), "children": {"linux/amd64": D(b), "linux/arm64": D(c)}}
         for v, a, b, c in (("production", "a", "b", "c"), ("fips", "d", "e", "f"))}
o2 = tempfile.mkdtemp(); r2 = run_gen(J(OTHER), o2)
check("AC5 other valid digests: exactly those appear (none invented, none kept from the module)",
      r2.returncode == 0 and digests_in(o2) == six_of(OTHER), (r2.returncode, sorted(digests_in(o2) ^ six_of(OTHER))))
# AC6: every other digest file is refused, the error names the key path or the value at fault, and nothing is written
P, F = IMAGES["production"], IMAGES["fips"]
def fips_child(val):
    return J({"production": P, "fips": {"index": F["index"], "children": {"linux/amd64": val, "linux/arm64": F["children"]["linux/arm64"]}}})
BAD = [
    ("a third key debug, well formed", J(dict(IMAGES, debug={"index": D("4"), "children": {"linux/amd64": D("5"), "linux/arm64": D("6")}})), "debug"),
    ("a missing fips", J({"production": P}), "fips"),
    ("a missing production", J({"fips": F}), "production"),
    ("an empty object", "{}", "production"),
    ("children without linux/arm64", J({"production": P, "fips": {"index": F["index"], "children": {"linux/amd64": F["children"]["linux/amd64"]}}}), "fips.children.linux/arm64"),
    ("children with an extra linux/s390x", J({"production": {"index": P["index"], "children": dict(P["children"], **{"linux/s390x": D("4")})}, "fips": F}), "production.children.linux/s390x"),
    ("children that are not an object", J({"production": P, "fips": {"index": F["index"], "children": sorted(F["children"].values())}}), "fips.children"),
    ("a variant with a key beside index and children", J({"production": dict(P, sbom=D("4")), "fips": F}), "production.sbom"),
    ("a variant without its index", J({"production": {"children": P["children"]}, "fips": F}), "production.index"),
    ("a variant value that is not an object", J({"production": P["index"], "fips": F}), "production"),
]
for nm, val in (("sha256: and 63 hex", "sha256:" + "a" * 63), ("upper-case hex", "sha256:" + "A" * 64),
                ("sha512: and 128 hex", "sha512:" + "a" * 128), ("a number", 7), ("null", None), ("an empty string", ""),
                ("a digest and a newline", D("a") + "\n"), ("a digest without its sha256: prefix", "a" * 64)):
    BAD.append(("a digest that is " + nm, fips_child(val), "fips.children.linux/amd64"))
BAD += [
    ("the same digest twice (production.index again as fips.index)", J({"production": P, "fips": dict(F, index=P["index"])}), P["index"]),
    ("the same digest twice within one variant", J({"production": {"index": P["index"], "children": {"linux/amd64": P["index"], "linux/arm64": P["children"]["linux/arm64"]}}, "fips": F}), P["index"]),
    ("a top-level array", J([P, F]), "object"),
    ("a top-level string", J("production"), "object"),
    ("invalid JSON", J(IMAGES)[:-1], "JSON"),
    ("a repeated top-level key", '{"production": %s, "production": %s, "fips": %s}' % (J(P), J(P), J(F)), "production"),
    ("a repeated key inside children", '{"production": %s, "fips": {"index": "%s", "children": {"linux/amd64": "%s", "linux/arm64": "%s", "linux/arm64": "%s"}}}'
     % (J(P), F["index"], F["children"]["linux/amd64"], D("a"), F["children"]["linux/arm64"]), "fips.children.linux/arm64"),
]
for name, text, must in BAD:
    empty = tempfile.mkdtemp(); r = run_gen(text, empty)
    check("AC6 refused with a non-zero exit, the error naming %r: %s" % (must, name),
          r.returncode != 0 and must in r.stderr and "Traceback" not in r.stderr, (r.returncode, r.stderr[-240:]))
    check("AC6 no form file created: " + name, os.listdir(empty) == [], os.listdir(empty))
    full = tempfile.mkdtemp()
    for f in FORMS:
        open(os.path.join(full, f), "w").write("PRE-EXISTING " + f)
    run_gen(text, full)
    check("AC6 a form file already in the output directory is unchanged: " + name,
          sorted(os.listdir(full)) == sorted(FORMS) and all(open(os.path.join(full, f)).read() == "PRE-EXISTING " + f for f in FORMS))
# AC5: no registry read and no network connection; the hook is proven to fire first (a control), so the pass is not vacuous
NONET = """import os, sys
def _deny(ev, args):
    if ev in ("socket.__new__", "socket.connect", "socket.getaddrinfo", "socket.gethostbyname", "urllib.Request",
              "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.fork"):
        os.write(2, ("FORBIDDEN " + ev + "\\n").encode()); os._exit(97)
sys.addaudithook(_deny)
"""
ctl = run_gen(J(IMAGES), tempfile.mkdtemp(), prelude=NONET + "import socket\nsocket.getaddrinfo('localhost', 443)\n")
check("AC5 control: the no-network hook stops a lookup", ctl.returncode == 97 and "FORBIDDEN socket.getaddrinfo" in ctl.stderr, ctl.stderr[-200:])
nn = tempfile.mkdtemp(); r = run_gen(J(IMAGES), nn, prelude=NONET, openvex=OPENVEX)
check("AC5 the generator runs with every socket, lookup and subprocess forbidden, and writes both forms",
      r.returncode == 0 and "FORBIDDEN" not in r.stderr and sorted(os.listdir(nn)) == sorted(FORMS), (r.returncode, r.stderr[-200:]))
# AC7: the same inputs give the same bytes, whatever the clock, time zone, locale, SOURCE_DATE_EPOCH or key order
CLOCK = "import time\ntime.time = lambda: %d.5\ntime.time_ns = lambda: %d * 10**9\n"
runs = []
for env, t in ((dict(os.environ, TZ="UTC", LC_ALL="C", SOURCE_DATE_EPOCH="1"), 1),
               (dict(os.environ, TZ="Pacific/Chatham", LC_ALL="de_DE.UTF-8", SOURCE_DATE_EPOCH="1999999999"), 2000000000)):
    o = tempfile.mkdtemp(); runs.append((o, run_gen(J(IMAGES), o, env=env, prelude=CLOCK % (t, t), openvex=OPENVEX)))
REORDERED = J({"fips": {"children": dict(reversed(list(F["children"].items()))), "index": F["index"]},
               "production": {"children": dict(reversed(list(P["children"].items()))), "index": P["index"]}}, indent=3)
o = tempfile.mkdtemp(); runs.append((o, run_gen(REORDERED, o, openvex=OPENVEX)))
def same(a, b):
    return all(open(os.path.join(a, f), "rb").read() == open(os.path.join(b, f), "rb").read() for f in FORMS)
check("AC7 every run succeeded", all(x.returncode == 0 for _, x in runs), [(x.returncode, x.stderr[-160:]) for _, x in runs])
if all(x.returncode == 0 for _, x in runs):
    check("AC7 two runs at different clocks, time zones, locales and SOURCE_DATE_EPOCH give byte-identical forms", same(runs[0][0], runs[1][0]))
    check("AC7 a digest file with the same content in another key order gives byte-identical forms", same(runs[0][0], runs[2][0]))
import ast
gsrc = ast.parse(open(GEN).read())
mods = {a.name for n in ast.walk(gsrc) if isinstance(n, ast.Import) for a in n.names} | \
       {n.module for n in ast.walk(gsrc) if isinstance(n, ast.ImportFrom)}
env_reads = [n.attr for n in ast.walk(gsrc) if isinstance(n, ast.Attribute) and n.attr in ("environ", "getenv", "environb")]
check("AC7 the generator imports no clock, randomness or network module and reads no environment variable",
      mods <= {"argparse", "json", "os", "re", "sys", "urllib.parse"} and not env_reads, (sorted(mods), env_reads))
# --- AC1, AC2 on the real OpenVEX file. AC2 is read as the advisor's reading (a), handoff 0389: "all statements" means
# every statement that applies to THIS release's images; a statement whose products are images the release does not ship
# does not belong in its forms. "Applies" is computed here from the products alone, independent of the generator.
real = json.load(open(OPENVEX))
WHOLE = "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache"
def applies(s, imgs):
    for p in s.get("products") or []:
        pid = p.get("@id") or (p.get("identifiers") or {}).get("purl", "")
        m = _re.fullmatch(r"pkg:oci/cache@sha256%3A([0-9a-f]{64})\?repository_url=ghcr\.io/fosterstack/cache", pid)
        if pid == WHOLE or (m and "sha256:" + m.group(1) in six_of(imgs)):
            return True
    return False
rc = V.csaf(real, IMAGES, "v0.3.0")
want = sorted(s["vulnerability"]["name"] for s in real["statements"] if applies(s, IMAGES))
check("AC2 the real file: the CSAF carries every statement that applies to this release's images, and no other",
      want and sorted(v["cve"] for v in rc["vulnerabilities"]) == want, (sorted(v["cve"] for v in rc["vulnerabilities"]), want))
named = lambda s: any(p.get("subcomponents") for p in s["products"] if "pkg:oci/cache?" in p["@id"] or "pkg:oci/cache@" in p["@id"])   # owner Oct 16: a rule needs a named package
wsup = sorted({s["vulnerability"]["name"] for s in real["statements"] if applies(s, IMAGES) and s["status"] in ("not_affected", "fixed") and named(s)})
rcv = sorted({r["filterCriteria"]["vulnerabilityId"][0]["value"] for r in V.inspector(real, IMAGES, "v0.3.0")["filters"]})
check("AC2 the real file: the Inspector file has a rule for each suppressible statement that applies and names a package, and no other", rcv == wsup, (rcv, wsup))
check("the real file's CSAF passes the loader's checks; its one statement stays scoped to the jwt/v4 module",
      bool(google_validate(rc)) and rc["product_tree"].get("relationships") and all(r["product_reference"] == "component-github.com%2Fgolang-jwt%2Fjwt%2Fv4@" for r in rc["product_tree"].get("relationships", [])))
if src:
    ns["_Validate"](rc)
    check("the installed gcloud loader's own _Validate accepts the real file's CSAF", True)
# DEFERRED, not weakened: the .vex digest-scoping edit (handoff 0389 (c); a separate PR, ordered after pipeline #299)
# narrows the three busybox statements to the published :debug digests. That PR adds here, on this v0.3.0 fixture:
# the CSAF carries no CVE-2025-60876, CVE-2025-46394 or CVE-2024-58251 and no relationships, and the Inspector file
# has no rule for them. Today's file names the whole repository, so those statements still apply to every digest and
# that assertion would be false today; the AC2 check above already holds the rule and follows the file (`want` drops to
# CVE-2024-51744 alone once the edit lands).
# The published :debug images (GHCR; final AC file C.3): v0.2.2's in the production slot and v0.2.1's in the fips
# slot. The generator's shape names slots, not content; these six images all carry busybox 1.37.0. This holds today
# (whole repository) and after the edit (the statements name exactly these digests, among others).
BUSYBOX = {"CVE-2025-60876", "CVE-2025-46394", "CVE-2024-58251"}
DEBUG = {"production": {"index": "sha256:87887f55ffa41cc63d4aa6f6d9459fd0dbf919491b83f1d3c8b7fc5444b5a081",
                        "children": {"linux/amd64": "sha256:9e8268329d7266b64a1a4258c83b23140ff8f266b283b835ce591deb1e3efad2",
                                     "linux/arm64": "sha256:ecc1d78cb8227f7c0496afc3db453c3e75fccebfa1ac631f54b2d4624ced4cab"}},
         "fips": {"index": "sha256:e2e502f44d8bd9e6967cb160aabeb012e8520ebba0faa88e130143fe534f282e",
                  "children": {"linux/amd64": "sha256:fd52446f5bb30b17c7b20e5d4b381722180f63911f678937e75b16b6f080ac5a",
                               "linux/arm64": "sha256:596adb2363f907a62634a24aeea0295e147bf45e4c4a3bb44b1c75963bad5653"}}}
bbvex = json.load(open(BBVEX))
dc = V.csaf(bbvex, DEBUG, "v0.2.2")
check("the busybox fixture on the published :debug images: each busybox CVE is present", BUSYBOX <= {v["cve"] for v in dc["vulnerabilities"]})
p2d = {b["product"]["product_id"]: b["product"]["product_identification_helper"]["purl"].split("@", 1)[1].split("?")[0]
       for b in dc["product_tree"]["branches"]}
rels = dc["product_tree"].get("relationships", [])
check("…every relationship is busybox 1.37.0 on one of those :debug digests",
      rels and all(x["product_reference"] == "component-busybox@1.37.0" and p2d.get(x["relates_to_product_reference"]) in six_of(DEBUG) for x in rels))
bb = [x for x in V.inspector(bbvex, DEBUG, "v0.2.2")["filters"] if x["filterCriteria"]["vulnerabilityId"][0]["value"] in BUSYBOX]
check("…each busybox Inspector rule carries busybox 1.37.0 and only those digests",
      {x["filterCriteria"]["vulnerabilityId"][0]["value"] for x in bb} == BUSYBOX
      and all(x["filterCriteria"].get("vulnerablePackages") == [{"name": {"comparison": "EQUALS", "value": "busybox"},
                                                                  "version": {"comparison": "EQUALS", "value": "1.37.0"}}]
              and {c["value"] for c in x["filterCriteria"]["ecrImageHash"]} == six_of(DEBUG) for x in bb))
# --- AC3: our own pipeline keeps filtering against the OpenVEX file itself, never a derived form
rescan = open(os.path.join(root, ".github/workflows/main-candidate-rescan.yml")).read()
check("the rescan filters grype, docker scout and the tally against the OpenVEX file",
      rescan.count(".vex/fosterstack-cache.openvex.json") >= 3 and "inspector-filters" not in rescan and "csaf" not in rescan.lower())
# --- AC8: this test proves the generator, not the workflow. It reads no workflow file's step names or step order;
# where the forms are generated, that the signed release record covers them and that the digests are Build's verified
# ones are proven by the release workflow's own test. AC3's contents check of the rescan workflow stays.
me = open(sys.argv[3]).read()
wf = set(_re.findall(r"\.github/workflows/([A-Za-z0-9._-]+)", me))
check("AC8 this test names no workflow file but the rescan's (AC3's contents check)", wf == {"main-candidate-rescan.yml"}, wf)
check("AC8 this test reads no workflow's steps", ('["' + 'steps"]') not in me and ("import " + "yaml") not in me and ("yaml" + ".") not in me)
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
try:
    V._scopes(scoped("CVE-ENC", "affected", [{"@id": "pkg:oci/cache@%s?repository_url=ghcr.io%%2Ffosterstack%%2Fcache" % D1}]), [D("1")]); got = "accepted"
except ValueError:
    got = "refused"
check("SEC-165-01 a percent-encoded repository_url is ours only after decoding, which the other readers do not do: refused, not honoured", got == "refused", got)
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
for sub in ("pkg:generic/acme/busybox@1.37.0", "pkg:npm/%40acme/busybox@1.37.0", "pkg:deb/debian/libssl3@3.0.15-1"):
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
# --- rc-5a H (handoff 0666; ruling R2, astra R8): ONE scope grammar across the readers. vex-forms accepts variant=/arch= (variant filters the digest
#     set, arch maps to the platform digests); the rescan no longer accepts debug; the same table of product forms goes through every reader
OURS_Q = "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache"
def META(images):
    return {d: (v, plat) for v, plat, d in V._digests(images)}
ALL6 = {d for _, _, d in V._digests(IMAGES)}
def digs(pred):
    return {d for v, plat, d in V._digests(IMAGES) if pred(v, plat)}
def sc(q, meta=True):
    st_ = scoped("CVE-H1", "not_affected", [{"@id": OURS_Q + q, "subcomponents": [{"@id": "pkg:generic/busybox@1.37.0"}]}])
    return V._scopes(st_, sorted(ALL6), META(IMAGES) if meta else None)
def covered(q):
    return {d for ds, _ in sc(q) for d in ds}
check("H no qualifier covers every digest of the release", covered("") == ALL6)
check("H variant=production covers the index and both children of production only", covered("&variant=production") == digs(lambda v, p: v == "production"))
check("H variant=fips covers fips only", covered("&variant=fips") == digs(lambda v, p: v == "fips"))
check("H arch=amd64 covers the amd64 children of both variants (an index has no one architecture)", covered("&arch=amd64") == digs(lambda v, p: p == "linux/amd64"))
check("H arch=arm64 covers the arm64 children only", covered("&arch=arm64") == digs(lambda v, p: p == "linux/arm64"))
check("H variant and arch together are the one child", covered("&variant=fips&arch=arm64") == digs(lambda v, p: v == "fips" and p == "linux/arm64") and len(covered("&variant=fips&arch=arm64")) == 1)
check("H the order of the qualifiers does not matter", covered("&arch=arm64&variant=fips") == covered("&variant=fips&arch=arm64"))
check("H the package is kept beside the scope", sc("&variant=fips")[0][1] == ("busybox", "1.37.0"))
try:
    sc("&variant=fips", meta=False); got = "accepted"
except ValueError:
    got = "refused"
check("H a scoped product with no digest map cannot be placed: refused, never widened", got == "refused", got)
ir = V.inspector({"statements": [scoped("CVE-H2", "not_affected", [{"@id": OURS_Q + "&variant=production", "subcomponents": [{"@id": "pkg:generic/busybox@1.37.0"}]}])]}, IMAGES, "v0.3.0")["filters"]
check("H the Inspector rule of a variant-scoped statement carries the digests of that variant only",
      len(ir) == 1 and {c["value"] for c in ir[0]["filterCriteria"]["ecrImageHash"]} == digs(lambda v, p: v == "production"), ir)
cs = V.csaf({"statements": [scoped("CVE-H3", "not_affected", [{"@id": OURS_Q + "&arch=arm64", "subcomponents": [{"@id": "pkg:generic/busybox@1.37.0"}]}])]}, IMAGES, "v0.3.0")
rel = cs["product_tree"].get("relationships", [])
check("H the CSAF relationships of an arch-scoped statement sit on the arm64 children only", len(rel) == 2, rel)
# the grammar table, through every reader: accepted by all or by none
import importlib.util as _iu
def _load(n, f):
    sp = _iu.spec_from_file_location(n, os.path.join(root, "bin", f)); m = _iu.module_from_spec(sp); sys.path.insert(0, os.path.join(root, "bin")); sp.loader.exec_module(m); return m
GATE, RESC = _load("gate_h", "inspector-gate.py"), _load("resc_h", "rescan-statement.py")
PANEL = _load("panel_h", "panel.py")
def r_gate(pid): return GATE.scope_of(pid) is not None
def r_resc(pid):
    try: return RESC._parse_product(pid) not in (None,) and RESC._parse_product(pid)[0] == "oci"
    except ValueError: return False
def r_panel(pid): return any(PANEL._covers(pid, i) for imgs in PANEL.EXPECTED.values() for i in imgs)
def r_forms(pid):
    try: V._scopes(scoped("CVE-H4", "not_affected", [{"@id": pid, "subcomponents": [{"@id": "pkg:generic/busybox@1.37.0"}]}]), sorted(ALL6), META(IMAGES)); return True
    except ValueError: return False
BASE_Q = "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache"
OKQ = ["", "&variant=production", "&variant=fips", "&arch=amd64", "&arch=arm64", "&variant=fips&arch=arm64", "&arch=arm64&variant=production"]
BADQ = ["&variant=debug", "&arch=riscv64", "&variant=", "&arch", "&arch=amd64&", "&color=red&arch=amd64", "&variant=production&variant=production",
        "&Variant=production", "&variant=%70roduction", "&arch=%61md64", "&%61rch=amd64", "&variant=production&arch=amd64&arch=arm64", "&ARCH=arm64", "&variant=Production", "#", "&variant=production#"]
for q in OKQ + BADQ:
    want = q in OKQ
    got = {n: f(BASE_Q + q) for n, f in (("gate", r_gate), ("rescan", r_resc), ("panel", r_panel), ("forms", r_forms))}
    check("H one grammar: %r is %s by every reader" % (q, "accepted" if want else "refused"), set(got.values()) == {want}, got)
# the shared table, whole product ids (confirmation round, finding 2): none of these is accepted by ANY of the four readers (forms: refused or not a scope)
def r_forms_scope(pid):
    try: return bool(V._scopes(scoped("CVE-H7", "not_affected", [{"@id": pid, "subcomponents": [{"@id": "pkg:generic/busybox@1.37.0"}]}]), sorted(ALL6), META(IMAGES)))
    except ValueError: return False
def r_gate_full(pid): return GATE.OUR_PRODUCTS.match(pid) is not None and GATE.scope_of(pid) is not None
for pid in ("pkg:oci/cache?arch=amd64&repository_url=ghcr.io/fosterstack/cache", "pkg:oci/cache?repository_url=ghcr.io%2Ffosterstack%2Fcache&variant=production",
            "pkg:oci/cache?repository_url=ghcr.io%252Ffosterstack%252Fcache", "pkg:oci/ca%63he?repository_url=ghcr.io/fosterstack/cache",
            "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache#", "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache&variant=production#"):
    got = {"gate": r_gate_full(pid), "rescan": r_resc(pid), "panel": r_panel(pid) and GATE.OUR_PRODUCTS.match(pid) is not None, "forms": r_forms_scope(pid)}   # the panel hands its statements to vex_index, whose first filter is OUR_PRODUCTS
    check("H whole-product table: %s is accepted by no reader" % pid, not any(got.values()), got)
# rc-5a H review (round 1, finding 1/2): a product the gate, panel and rescan ignore must never be honoured by the forms. Three outcomes per form: accept / ignore / refuse.
OURS_ENC = "pkg:oci/cache?repository_url=ghcr.io%2Ffosterstack%2Fcache"
for pid in ("pkg:oci/cache?arch=amd64&repository_url=ghcr.io/fosterstack/cache", OURS_ENC + "&variant=production", "pkg:oci/cache?repository_url=ghcr.io%252Ffosterstack%252Fcache",
            "pkg:oci/ca%63he?repository_url=ghcr.io/fosterstack/cache"):
    try:
        got = "honoured" if V._scopes(scoped("CVE-H5", "not_affected", [{"@id": pid, "subcomponents": [{"@id": "pkg:generic/busybox@1.37.0"}]}]), sorted(ALL6), META(IMAGES)) else "ignored"
    except ValueError:
        got = "refused"
    check("H the forms never honour a product the other readers ignore: %s is %s" % (pid, got), got != "honoured", got)
    check("H ...and for %s the gate really ignores it (OUR_PRODUCTS first)" % pid, GATE.OUR_PRODUCTS.match(pid) is None, pid)
try:
    V._scopes(scoped("CVE-H6", "affected", [{"@id": "pkg:oci/cache@%s?repository_url=ghcr.io/fosterstack/cache&variant=fips" % sorted(ALL6)[0].replace(":", "%3A"), "subcomponents": [{"@id": "pkg:generic/busybox@1.37.0"}]}]), sorted(ALL6), META(IMAGES)); got = "accepted"
except ValueError:
    got = "refused"
fips_or_not = META(IMAGES)[sorted(ALL6)[0]][0]
check("H a pinned digest that its own variant qualifier excludes stops generation (%s digest, variant=fips)" % fips_or_not, (got == "refused") == (fips_or_not != "fips"), got)
# --- rc-5a G (handoff 0666; ruling R7/R8): the one statement is scoped to the jwt/v4 module, the busybox statements are retired, and a Go
#     module represents as its FULL module path (Inspector names a Go module by its path; the Codex #165 widening concern was a namespace-less name)
JWT = "pkg:golang/github.com/golang-jwt/jwt/v4"
check("G a Go subcomponent is the package named by its full module path",
      V._scopes(scoped("CVE-G1", "not_affected", [{"@id": OURS, "subcomponents": [{"@id": JWT}]}]), [D("1")]) == [([D("1")], ("github.com/golang-jwt/jwt/v4", ""))])
check("G a versioned Go subcomponent keeps its version",
      V._scopes(scoped("CVE-G2", "not_affected", [{"@id": OURS, "subcomponents": [{"@id": JWT + "@v4.5.0"}]}]), [D("1")]) == [([D("1")], ("github.com/golang-jwt/jwt/v4", "v4.5.0"))])
for sub in ("pkg:golang/jwt", "pkg:golang/jwt@v4.5.0", JWT + "?goos=linux", JWT + "#sub/dir", "pkg:golang/", "pkg:golang//x"):
    check("G a Go subcomponent the forms cannot represent stops generation: " + sub, refused({"@id": OURS, "subcomponents": [{"@id": sub}]}))
check("G a Go module and a generic package of the same last segment stay distinct",
      V._scopes(scoped("CVE-G3", "affected", [{"@id": OURS, "subcomponents": [{"@id": JWT}, {"@id": "pkg:generic/jwt"}]}]), [D("1")])
      == [([D("1")], ("github.com/golang-jwt/jwt/v4", "")), ([D("1")], ("jwt", ""))])
gj = V.inspector({"statements": [scoped("CVE-G4", "not_affected", [{"@id": OURS, "subcomponents": [{"@id": JWT}]}])]}, IMAGES, "v0.3.0")["filters"]
check("G the Inspector rule names the Go module by its full path", [f["filterCriteria"]["vulnerablePackages"] for f in gj] == [[{"name": {"comparison": "EQUALS", "value": "github.com/golang-jwt/jwt/v4"}}]], gj)
sts = real["statements"]
check("G the published document holds exactly one statement, CVE-2024-51744", [s_["vulnerability"]["name"] for s_ in sts] == ["CVE-2024-51744"])
oci = [p_ for s_ in sts for p_ in s_["products"]]
check("G every product of that statement (the image products AND the Go product) names the jwt/v4 module, and nothing else, as its subcomponent",
      oci and all([x["@id"] for x in p_.get("subcomponents", [])] == [JWT] for p_ in oci), oci)
for sub_ in ("pkg:golang/foo/bar", "pkg:golang/foo/bar@v1", "pkg:generic/github.com%2Fgolang-jwt%2Fjwt%2Fv4", "pkg:generic/busybox%401.37.0", "pkg:generic/busybox@1.37.0%2F1", "pkg:golang/github.com/golang-jwt/jwt%40v4"):
    check("G a subcomponent that is not a Go module path nor a plain generic name stops generation: " + sub_, refused({"@id": OURS, "subcomponents": [{"@id": sub_}]}))
check("G a double-encoded delimiter is decoded once and stays a literal name (never the Go module it spells after a second decoding)",
      V._scopes(scoped("CVE-G8", "not_affected", [{"@id": OURS, "subcomponents": [{"@id": "pkg:generic/github.com%252Fgolang-jwt%252Fjwt%252Fv4"}]}]), [D("1")])
      == [([D("1")], ("github.com%2Fgolang-jwt%2Fjwt%2Fv4", ""))])
check("G an encoded dot in the host segment is still a Go module path (decoded once, then judged)",
      V._scopes(scoped("CVE-G10", "not_affected", [{"@id": OURS, "subcomponents": [{"@id": "pkg:golang/github%2Ecom/golang-jwt/jwt/v4"}]}]), [D("1")]) == [([D("1")], ("github.com/golang-jwt/jwt/v4", ""))])
check("G an encoded slash in a Go module path (host or later segment) stops generation",
      all(refused({"@id": OURS, "subcomponents": [{"@id": x}]}) for x in ("pkg:golang/github%2Ecom%2Fgolang-jwt/jwt/v4", "pkg:golang/github.com/golang-jwt%2Fjwt/v4")))
check("G the empty version leaves no stray space in the published text",
      "  " not in V.inspector({"statements": [scoped("CVE-G9", "not_affected", [{"@id": OURS, "subcomponents": [{"@id": JWT}]}])]}, IMAGES, "v0.3.0")["filters"][0]["description"])
check("G the published document no longer describes a :debug image or busybox",
      "busybox" not in json.dumps(real).lower() and ":debug" not in json.dumps(real) and "distroless" not in json.dumps(real).lower())
check("G the document's version moved past the fixture's (6)", real["version"] > json.load(open(BBVEX))["version"], real["version"])
check("G the busybox fixture keeps the three retired statements for the generator's tests",
      sorted(s_["vulnerability"]["name"] for s_ in json.load(open(BBVEX))["statements"]) == ["CVE-2024-51744", "CVE-2024-58251", "CVE-2025-46394", "CVE-2025-60876"])
print("vex-forms: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
PY
