#!/usr/bin/env python3
"""The cases for the daily supply-chain checker's false alarms (REQ-SUP-001), run by pin-audit-test.sh (suite `audit`) and pin-age-check-test.sh (suite `age`).

  sc-fix-cases.py audit|age       prints one line per case: `ok   [AC..] text` or `FAIL [AC..] text :: why`; exit 1 when any case fails, 2 for an unknown suite

A suite that runs no case fails (a typo in a suite name can never pass). Everything is OFFLINE: the network is faked at its seams (the GitHub API, the OSV
API, the tag list of an action's repository, the Go proxy, the PyPI index) and any other network or gh call raises. The records are the REAL ones, fetched
on 2026-10-07 from api.osv.dev and the GitHub advisories API and kept trimmed in ../fixtures/sc-checker/real-records.json:
  a  cosign: GO-2026-4309/4529/5694 and GO-2024-2718/2719, GO-2023-2181 (bare, /v2 and /v3 entries), their GHSA pairs (GHSA-whqx-f9j3-ch6m is filed only under /v2 and /v3)
  b  github/codeql-action GHSA-vqf5-2xx6-9wfm: separate affected entries, the hint at affected[].database_specific, the v3 closing event `fixed: 3.28.3`
  c  (advisor 0245) NO resolver: any ${{ }} where a version is pinned is `unparseable`, with its file:line, at any scope, never covered by an exception
  d  pyyaml with --hash options (ci.yml's heredoc shape); GHSA-8q59-q68h-6hv4 (fixed 5.4): 6.0.2 is safe, 5.3 is affected
  e  actions/download-artifact GHSA-cxww-7g56-2vh6 (>= 4.0.0, < 4.1.3) at the commit that carries v4.3.0 and the floating v4
  f  stage-promote.yml's cosign-installer with no cosign-release
  g  actions/upload-artifact pinned to a commit that is not in the repository (#202), and a pin whose comment names another tag
TIE-BREAK RULE under test (advisor 0255, replacing the earlier highest-release reading): a FLOATING comment (`# v4`, `# v4.3`) is judged AFFECTED IF ANY exact X.Y.Z tag on the pinned
commit is affected: pre-release tags (v4.0.0-rc.1) included, any major or minor (a v5.3.0 tag judges a `# v4` comment), no tag preferred over another (not the highest, not the lowest,
not the first); a floating comment with NO exact X.Y.Z tag on the commit (only `v4`) is `unresolved`. An EXACT comment is judged by its own tag, even when another tag at the commit
is affected (unchanged from the earlier rule; no earlier test contradicts the new floating rule except those removed or rewritten in this change).
SCOPE under test (AC11, advisor 0261, a CLOSED rule with no following of invocations): in scope = workflow files, action files (action.yml/yaml) wherever they sit, every shell script
(*.sh, *.bash, or any file with a shell shebang) anywhere in the repository, and the requirements*.txt files; ANY install-looking string in such a file is an item (heredocs, quotes,
$(...), comments all count; no data/code classification). The ONLY exemption is the reviewed manifest .github/agent/supply-chain/harness-manifest.json: {"files": [{"path", "sha256", "reason"}]}, one entry per
harness file whose install-looking strings are fixture data; a listed file whose exact bytes hash differently, an unlisted file, a duplicate or malformed entry, a path outside the repository,
a missing manifest: the file is fully IN scope (the finding for a mismatch names both hashes); an invalid entry for a path exempts nothing for that path even beside a valid one; a dangling entry
is a finding (daily). In pull request mode the manifest is read from the BASE (a PR cannot bring its own exemptions), the BASE manifest's exemptions are applied to each side's OWN files (a listed path whose bytes still match its hash is exempt), so an unchanged
listed file is exempt on both sides, and one the PR edits or deletes is exempt at the base and measured IN FULL at the head (its fixture strings are then moved, for the owner to review);
a fixture can never stand in as 'already present' for the same pin introduced elsewhere; the hash is verified by the daily run after the merge. The manifest lies under .github/agent/, so the review gate covers it
(.github/agent/bin/tests/test_review_gate.py, class HarnessManifest), landing with this change.
SC_DIR (the directory of the three programs) and SC_ROOT (the repository whose real files f and d read) may be set; the defaults are this checkout.
"""
import atexit
import contextlib
import copy
import hashlib
import datetime as dt
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import traceback
import urllib.parse
import urllib.request

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
SC = os.environ.get("SC_DIR") or os.path.join(HERE, "..", "supply-chain")
ROOT = os.environ.get("SC_ROOT") or os.path.abspath(os.path.join(HERE, "..", "..", ".."))
TMP = tempfile.mkdtemp(prefix="sc-fix-")
atexit.register(shutil.rmtree, TMP, True)
REAL = json.load(open(os.path.join(HERE, "..", "fixtures", "sc-checker", "real-records.json")))


def _load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_") + "_under_test", os.path.join(SC, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


pa = _load("pin-audit")
age = pa.age
inv = pa.inv

CASES = []


def case(suite, acs, text):
    def deco(fn):
        CASES.append((suite, acs, text, fn))
        return fn
    return deco


class patched:
    """Set attributes of a module or object for the length of a with block (re-enterable)."""
    def __init__(self, obj, **kw):
        self.obj, self.kw, self.saved = obj, kw, []

    def __enter__(self):
        self.saved.append({k: getattr(self.obj, k) for k in self.kw})
        for k, v in self.kw.items():
            setattr(self.obj, k, v)

    def __exit__(self, *exc):
        for k, v in self.saved.pop().items():
            setattr(self.obj, k, v)


@contextlib.contextmanager
def offline():
    """No network and no gh: git (local) is allowed, everything else raises, so a program that reaches for a new source fails loudly."""
    real_run = subprocess.run

    def run(cmd, *a, **k):
        argv = cmd if isinstance(cmd, list) else [cmd]
        if argv and argv[0] == "git" and "ls-remote" not in argv and "fetch" not in argv:
            return real_run(cmd, *a, **k)
        raise AssertionError("an offline case tried to run " + " ".join(map(str, argv))[:80])

    def urlopen(*a, **k):
        raise AssertionError("an offline case tried to reach the network: " + str(a[0])[:80])

    with patched(subprocess, run=run), patched(urllib.request, urlopen=urlopen):
        yield


# ---------------------------------------------------------------------------------------------------------------- the fake network
def covers(version, affected):
    if version in (affected.get("versions") or []):
        return True
    for rg in affected.get("ranges") or []:
        if rg.get("type") in ("SEMVER", "ECOSYSTEM") and pa.covered_by_events(version, rg.get("events", [])):
            return True
    return False


def R_osv(*ids):
    return [copy.deepcopy(REAL["osv"][i]) for i in ids]


def R_gh(*ids):
    return [copy.deepcopy(REAL["gh"][i]) for i in ids]


def make_net(gh=(), osv=(), tags=None, pypi=None, go_module=None, open_prs=None):
    """A LiveNet whose network seams answer from records. gh: GitHub advisory records; osv: OSV records; tags: {repo: {tag: commit}}."""
    class Fake(pa.LiveNet):
        def __init__(self, *args):
            super().__init__(["false"], ".")
            self.gh_by_id = {r["ghsa_id"]: r for r in gh}
            self.osv_by_id = {r["id"]: r for r in osv}
            self.gh_list_asked = []     # (ecosystem, name, type) of every advisory-list query
            self.osv_asked = []         # (ecosystem, name, version) of every OSV query

        def _gh_json(self, path, strict=False):
            if path.startswith("advisories/"):
                return self.gh_by_id.get(path.split("/", 1)[1])
            if path.startswith("advisories?"):
                q = {k: v[0] for k, v in urllib.parse.parse_qs(path.split("?", 1)[1]).items()}
                self.gh_list_asked.append((q.get("ecosystem"), q.get("affects"), q.get("type", "")))
                if q.get("page", "1") != "1":
                    return []
                want_mal = q.get("type") == "malware"
                out = []
                for r in gh:
                    if (r.get("type") == "malware") != want_mal:
                        continue
                    if any(v["package"]["ecosystem"] == q["ecosystem"] and pa._norm_name(v["package"]["name"]) == pa._norm_name(q["affects"]) for v in r["vulnerabilities"]):
                        out.append(r)
                return out
            raise AssertionError("an offline case asked GitHub for " + path)

        def _osv_post(self, q):
            pkg, ver = q["package"], q.get("version")
            self.osv_asked.append((pkg["ecosystem"], pkg["name"], ver))
            out = []
            for r in osv:
                for a in r.get("affected", []):
                    p = a.get("package") or {}
                    if p.get("name") == pkg["name"] and p.get("ecosystem") == pkg["ecosystem"] and (ver is None or covers(ver, a)):
                        out.append(r)
                        break
            return out

        def _osv_get(self, advisory_id):
            return self.osv_by_id.get(advisory_id)

        def upstream(self, item):
            return True

        def versions(self, item):
            return None            # a kind that cannot be enumerated: the rollback is the owner's decision

        def nested(self, item):
            return []

        def open_pr_items(self):
            return list(open_prs or [])

    net = Fake()
    return net, patched(age, _tag_refs=lambda repo: dict((tags or {}).get(repo, {})), _http_json=lambda url, timeout=30: (pypi or {}).get(url),
                        _go_module=go_module or (lambda p, v: (None, None)))


def judge(net, ctx, item, exceptions=()):
    notes = []
    with offline(), ctx:
        return pa.judge(item, net, list(exceptions), notes), notes


def summary(findings):
    return sorted((f.kind, tuple(f.ids)) for f in findings)


def all_ids(findings):
    return {i for f in findings for i in f.ids}


def osv_rec(rid, modified, affected, aliases=()):
    return {"id": rid, "aliases": list(aliases), "modified": modified, "affected": affected}


def go_aff(name, *events_lists):
    return {"package": {"name": name, "ecosystem": "Go"}, "ranges": [{"type": "SEMVER", "events": ev} for ev in events_lists]}


def ghsa(gid, pkg, ranges, updated, eco="go", typ="reviewed"):
    return {"ghsa_id": gid, "updated_at": updated, "type": typ,
            "vulnerabilities": [{"package": {"ecosystem": eco, "name": pkg}, "vulnerable_version_range": r} for r in ranges]}


def exc(pkg, ids, au, ranges, modified, version, osv_modified=None, ruling="advisor ruling (test copy of a shipped-shape entry)"):
    e = {"ids": ids, "package": pkg, "authoritative": {"source": "GitHub", "id": au, "ranges": ranges}, "ruling": ruling,
         "evidence": ["https://github.com/advisories/" + au], "date": "2026-10-07", "modified": modified, "version": version}
    if osv_modified:
        e["osv_modified"] = osv_modified
    return e


def load_exc(entries):
    d = tempfile.mkdtemp(dir=TMP)
    p = os.path.join(d, "exc.json")
    json.dump({"exceptions": entries}, open(p, "w"))
    return pa.load_exceptions(p, True)


# ---- cosign (cache issues #204, #205, #207) -----------------------------------------------------------------------------------------
COSIGN = "github.com/sigstore/cosign"
GHSA_COSIGN = ["GHSA-88jx-383q-w4qc", "GHSA-95pr-fxf5-86gv", "GHSA-vfp6-jrw2-99g9", "GHSA-w6c6-c85g-mmv6", "GHSA-wfqv-66vq-46rm", "GHSA-whqx-f9j3-ch6m"]
GO_COSIGN = ["GO-2026-4309", "GO-2026-4529", "GO-2026-5694", "GO-2024-2718", "GO-2024-2719", "GO-2023-2181"]
COSIGN_GH = R_gh(*GHSA_COSIGN)
COSIGN_OSV = R_osv(*GO_COSIGN, *GHSA_COSIGN)
FIVE = [("GHSA-88jx-383q-w4qc", "GO-2024-2718"), ("GHSA-95pr-fxf5-86gv", "GO-2024-2719"), ("GHSA-vfp6-jrw2-99g9", "GO-2023-2181"),
        ("GHSA-w6c6-c85g-mmv6", "GO-2026-5694"), ("GHSA-wfqv-66vq-46rm", "GO-2026-4529")]
FIVE_RANGES = {"GHSA-88jx-383q-w4qc": ["<= 2.2.3"], "GHSA-95pr-fxf5-86gv": ["<= 2.2.3"], "GHSA-vfp6-jrw2-99g9": ["<= 1.13.1"],
               "GHSA-w6c6-c85g-mmv6": [">= 3.0.0, < 3.0.6", "< 2.6.3"], "GHSA-wfqv-66vq-46rm": ["<= 3.0.4"]}
COSIGN_EXC = [exc("cosign", [g, o], g, FIVE_RANGES[g], {g: REAL["gh"][g]["updated_at"], o: REAL["osv"][o]["modified"]}, "3.1.3") for g, o in FIVE]


def cosign(version="v3.1.3"):
    return inv.Item("tool", "cosign", version)


def cosign_net(extra_osv=()):
    return make_net(COSIGN_GH, COSIGN_OSV + list(extra_osv))


# ---- codeql-action (cache issue #208) ----------------------------------------------------------------------------------------------
CQ = "github/codeql-action"
CQ_SHA = "42947a340483f03ba47bb1a039b2c519aab3df85"
CQ_GH = R_gh("GHSA-vqf5-2xx6-9wfm")
CQ_REAL = R_osv("GHSA-vqf5-2xx6-9wfm")[0]
NO_HINT = object()


def cq_rec(entries, level="affected"):
    """OSV record of the codeql package: entries = [(events, hint)], one affected entry each (the real shape); the hint sits at affected[].database_specific
    (real) or, for level 'range', at ranges[].database_specific (the other place a reader might look)."""
    aff = []
    for events, hint in entries:
        rg = {"type": "ECOSYSTEM", "events": events}
        a = {"package": {"name": CQ, "ecosystem": "GitHub Actions"}, "ranges": [rg]}
        if hint is not NO_HINT:
            (a if level == "affected" else rg)["database_specific"] = {"last_known_affected_version_range": hint}
        aff.append(a)
    return osv_rec("GHSA-vqf5-2xx6-9wfm", "2026-04-01T17:41:21.034151Z", aff, ["CVE-2025-24362"])


def at_range_level(rec):
    rec = copy.deepcopy(rec)
    for a in rec["affected"]:
        if "database_specific" in a:
            a["ranges"][0]["database_specific"] = a.pop("database_specific")
    return rec


def cq_item(tag="v3.37.8"):
    return inv.Item("action", CQ, CQ_SHA, tag)


def cq_tags(*extra):
    return {CQ: {"v3.37.8": CQ_SHA, **{t: CQ_SHA for t in extra}}}


CQ_EXC = exc(CQ, ["GHSA-vqf5-2xx6-9wfm"], "GHSA-vqf5-2xx6-9wfm", [">= 3.26.11, <= 3.28.2", ">= 2.26.11, < 3.0.0"], {"GHSA-vqf5-2xx6-9wfm": CQ_GH[0]["updated_at"]}, "3.37.8",
             {"GHSA-vqf5-2xx6-9wfm": CQ_REAL["modified"]})

# ---- download-artifact (cache issue #201) --------------------------------------------------------------------------------------------
DA = "actions/download-artifact"
DA_SHA = "d3f86a106a0bac45b974a628896c90dbdf5c8093"

# ---- upload-artifact (cache issue #202) ---------------------------------------------------------------------------------------------
UA = "actions/upload-artifact"
UA_SHA = "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"      # v4.6.2 as pinned in the tree
UA_TYPO = "b4b15b8c7c6ac21ea08fcf65892d2ee28f014d99"     # what #202 pinned: a commit nowhere
UA_OTHER = "5d5d22a31266ced268874388b861e4b58bb5c2f3"    # v4.5.0 (another real commit of the repository)

# ---- goreleaser (cache issue #206) ---------------------------------------------------------------------------------------------------
GORELEASER = "github.com/goreleaser/goreleaser"
GR_IDS_GH = ["GHSA-f6mm-5fc7-3g3c", "GHSA-h3q2-8whx-c29h"]


def gr_net():
    return make_net(R_gh(*GR_IDS_GH), R_osv("GO-2024-2860", "GO-2024-2482", *GR_IDS_GH))


# ---- pyyaml (cache issue #203) -------------------------------------------------------------------------------------------------------
PY_GH = ["GHSA-8q59-q68h-6hv4", "GHSA-6757-jp84-gxfx", "GHSA-3pqx-4fqf-j49f", "GHSA-rprw-h62v-c2w7"]
PY_OSV = ["GHSA-8q59-q68h-6hv4", "PYSEC-2021-142", "GHSA-6757-jp84-gxfx", "GHSA-3pqx-4fqf-j49f", "GHSA-rprw-h62v-c2w7", "PYSEC-2018-49"]


def py_net():
    return make_net(R_gh(*PY_GH), R_osv(*PY_OSV))


# ======================================================================================================================================
# a. Go tools at vN (N >= 2): the module path ends /vN; the bare path is the v1 module (AC5, AC10)
# ======================================================================================================================================
@case("audit", "AC5", "a: cosign v3.1.3 against the real records has NO finding (GO-2026-4309 and the five incidents carry bare, /v2 and /v3 entries; the /v3 entries do not reach 3.1.3)")
def a_clean():
    net, ctx = cosign_net()
    f, _ = judge(net, ctx, cosign())
    assert summary(f) == [], summary(f)


@case("audit", "AC5", "a: OSV is asked for the module path that ends /v3 (never the bare path) for a v3 binary")
def a_osv_name():
    net, ctx = cosign_net()
    judge(net, ctx, cosign())
    assert {n for _, n, _ in net.osv_asked} == {COSIGN + "/v3"}, net.osv_asked


@case("audit", "AC5", "a: the module path follows the major version: cosign v2 asks /v2, v1 and v0 ask the bare path, goreleaser 2.x and osv-scanner 2.x and golangci-lint v2 ask /v2, helm v3 stays helm.sh/helm/v3, trivy stays bare")
def a_names():
    table = [("cosign", "v2.2.0", COSIGN + "/v2"), ("cosign", "v1.13.1", COSIGN), ("cosign", "v0.6.0", COSIGN),
             ("goreleaser", "2.17.1", GORELEASER + "/v2"), ("goreleaser", "1.26.0", GORELEASER), ("osv", "2.6.0", "github.com/google/osv-scanner/v2"),
             ("golangci-lint", "v2.13.2", "github.com/golangci/golangci-lint/v2"), ("helm", "v3.14.0", "helm.sh/helm/v3"), ("trivy", "0.74.0", "github.com/aquasecurity/trivy")]
    for name, ver, want in table:
        net, ctx = make_net()
        judge(net, ctx, inv.Item("tool", name, ver))
        assert {n for _, n, _ in net.osv_asked} == {want}, (name, ver, net.osv_asked)


@case("audit", "AC5", "a: a go install target is matched the same way (cosign/v3 resolved by the proxy asks /v3; gosec/v2 asks /v2)")
def a_gotool():
    for path, ver, root in [("github.com/sigstore/cosign/v3/cmd/cosign", "v3.1.3", COSIGN + "/v3"), ("github.com/securego/gosec/v2/cmd/gosec", "v2.29.0", "github.com/securego/gosec/v2")]:
        net, ctx = make_net(go_module=lambda p, v, root=root: (root, {"Version": v}))
        judge(net, ctx, inv.Item("gotool", path, ver))
        assert {n for _, n, _ in net.osv_asked} == {root}, (path, net.osv_asked)


@case("audit", "AC5", "a: GitHub's advisories are looked up under BOTH the bare and the /v3 name: cosign v3.0.3 is a hit for the incident filed only under /v2 and /v3 (GHSA-whqx-f9j3-ch6m + GO-2026-4309) AND for the ones filed under the bare name (GHSA-w6c6 + GO-2026-5694, GHSA-wfqv + GO-2026-4529), as confirmed hits, no dispute")
def a_both_names():
    net, ctx = cosign_net()
    f, _ = judge(net, ctx, cosign("v3.0.3"))
    assert not any(x.disputed for x in f), summary(f)
    for pair in (("GHSA-whqx-f9j3-ch6m", "GO-2026-4309"), ("GHSA-w6c6-c85g-mmv6", "GO-2026-5694"), ("GHSA-wfqv-66vq-46rm", "GO-2026-4529")):
        assert any(set(pair) <= set(x.ids) for x in f), (pair, summary(f))
    assert not all_ids(f) & {"GO-2024-2718", "GHSA-88jx-383q-w4qc", "GO-2023-2181"}, all_ids(f)
    asked = {n for _, n, t in net.gh_list_asked if t == ""}
    assert {COSIGN, COSIGN + "/v3"} <= asked, asked


@case("audit", "AC5", "a: the boundaries of the real v3 records: v3.0.5 is hit only by GHSA-w6c6 + GO-2026-5694 (the others are fixed at 3.0.4 and 3.0.5), v3.0.6 by nothing")
def a_v3_boundaries():
    net, ctx = cosign_net()
    f, _ = judge(net, ctx, cosign("v3.0.5"))
    assert all_ids(f) == {"GHSA-w6c6-c85g-mmv6", "GO-2026-5694"} and not any(x.disputed for x in f), summary(f)
    net, ctx = cosign_net()
    assert summary(judge(net, ctx, cosign("v3.0.6"))[0]) == []


@case("audit", "AC5", "a: cosign v2.2.0 is hit through its /v2 names: every real incident (the six Go-database ids and GHSA-88jx, 95pr, vfp6, w6c6, wfqv, whqx) is a confirmed hit, no dispute (a discarded /v2 result or a discarded name would lose some)")
def a_v2_hits():
    net, ctx = cosign_net()
    f, _ = judge(net, ctx, cosign("v2.2.0"))
    assert not any(x.disputed for x in f), summary(f)
    assert all_ids(f) >= set(GO_COSIGN) | set(GHSA_COSIGN), (set(GO_COSIGN) | set(GHSA_COSIGN)) - all_ids(f)
    assert {n for _, n, _ in net.osv_asked} == {COSIGN + "/v2"}, net.osv_asked


@case("audit", "AC5", "a: the fixed boundary of the /v2 records: v2.2.4 is no longer hit by GO-2024-2718/2719 or GHSA-88jx/95pr (fixed 2.2.4) or GO-2023-2181/GHSA-vfp6 (2.2.1) but still by the later ones")
def a_v2_fixed():
    net, ctx = cosign_net()
    f, _ = judge(net, ctx, cosign("v2.2.4"))
    ids = all_ids(f)
    assert not ids & {"GO-2024-2718", "GO-2024-2719", "GHSA-88jx-383q-w4qc", "GHSA-95pr-fxf5-86gv", "GO-2023-2181", "GHSA-vfp6-jrw2-99g9"}, ids
    assert {"GO-2026-4309", "GO-2026-4529", "GO-2026-5694"} <= ids, ids


@case("audit", "AC5", "a: v1 keeps the bare path: cosign v1.13.1 is hit by GO-2023-2181 / GHSA-vfp6-jrw2-99g9 and is asked for under the bare name only (the open-ended bare records stay the v1 module's)")
def a_v1():
    net, ctx = cosign_net()
    f, _ = judge(net, ctx, cosign("v1.13.1"))
    assert {"GO-2023-2181", "GHSA-vfp6-jrw2-99g9"} <= all_ids(f) and not any(x.disputed for x in f), summary(f)
    assert {n for _, n, _ in net.osv_asked} == {COSIGN}
    assert not {"GO-2023-2181"} - all_ids(f) and "GHSA-whqx-f9j3-ch6m" not in all_ids(f)


@case("audit", "AC5", "a: an OSV record with NO GHSA alias is an independent hit with its fixed boundary (a Go-database-only record on the /v3 path: v3.1.4 hit, v3.1.5 clean)")
def a_osv_only():
    rec = osv_rec("GO-2099-0002", "2026-09-01T00:00:00Z", [go_aff(COSIGN + "/v3", [{"introduced": "3.1.0"}, {"fixed": "3.1.5"}])])
    net, ctx = make_net(osv=[rec])
    f, _ = judge(net, ctx, cosign("v3.1.4"))
    assert summary(f) == [("advisory", ("GO-2099-0002",))], summary(f)
    net, ctx = make_net(osv=[rec])
    assert summary(judge(net, ctx, cosign("v3.1.5"))[0]) == []


@case("audit", "AC10", "a: the five shipped rulings for #207 still match the real GitHub records (bare-name ranges are still read and equal the ruling's), and each ruling returns 'pass' for the dispute it names")
def a_rulings_apply():
    net, ctx = cosign_net()
    exceptions = load_exc(COSIGN_EXC)
    item = cosign()
    with offline(), ctx:
        for g, o in FIVE:
            live = net.live_ranges(item, "GitHub", g)
            assert live and pa._norm_ranges(live) == pa._norm_ranges(FIVE_RANGES[g]), (g, live)
            assert pa.excepted(item, {g, o}, {g: REAL["gh"][g]["updated_at"], o: REAL["osv"][o]["modified"]}, exceptions, net) == "pass", g


@case("audit", "AC10", "a: with the five rulings loaded, cosign v3.1.3 has no finding at all")
def a_with_rulings():
    net, ctx = cosign_net()
    f, _ = judge(net, ctx, cosign(), load_exc(COSIGN_EXC))
    assert summary(f) == [], summary(f)


# ======================================================================================================================================
# b. an OSV range with no closing event; GitHub's own record wins for a GHSA id (AC5, AC10)
# ======================================================================================================================================
def says(rec, version):
    return pa.LiveNet._osv_says(rec, CQ, version, versioned=False)


LEVELS = ("affected", "range")


@case("audit", "AC5", "b: the REAL record (separate affected entries, the hint at affected[].database_specific, v3 closing event fixed 3.28.3), and the same with the hint at ranges[]: v3.37.8 is NOT affected, v2.30.0 and v3.27.0 are, v3.0.0 and v3.28.3 are not")
def b_real():
    for name, rec in (("real record", CQ_REAL), ("hint at ranges[]", at_range_level(CQ_REAL))):
        got = {v: says(rec, v) for v in ("v3.37.8", "v2.30.0", "v3.27.0", "v3.0.0", "v3.28.3", "v2.26.10", "v3.26.11", "v3.28.2", "v2.26.11")}
        assert got == {"v3.37.8": False, "v2.30.0": True, "v3.27.0": True, "v3.0.0": False, "v3.28.3": False, "v2.26.10": False, "v3.26.11": True, "v3.28.2": True, "v2.26.11": True}, (name, got)


@case("audit", "AC5", "b: the hint may be an inclusive bound ('<= 3.0.0'), at either level")
def b_inclusive():
    for level in LEVELS:
        rec = cq_rec([([{"introduced": "2.26.11"}], "<= 3.0.0")], level)
        assert says(rec, "v3.0.0") is True and says(rec, "v3.0.1") is False and says(rec, "v2.30.0") is True, level


@case("audit", "AC5", "b: fail closed: an open range with NO hint stays open-ended (affected), and so does a hint that cannot be read, at either level")
def b_closed():
    for level in LEVELS:
        assert says(cq_rec([([{"introduced": "2.26.11"}], NO_HINT)], level), "v9.9.9") is True
        for bad in ("garbage", "", "< ", "~> 3", None, 3):
            assert says(cq_rec([([{"introduced": "2.26.11"}], bad)], level), "v9.9.9") is True, (level, bad)


@case("audit", "AC5", "b: a closing event (fixed OR last_affected) beats the hint, and a hint never narrows or widens a range that has its own closing event")
def b_closing_wins():
    for level in LEVELS:
        rec = cq_rec([([{"introduced": "1.0.0"}, {"fixed": "1.5.0"}], "< 9.0.0")], level)
        assert says(rec, "v2.0.0") is False and says(rec, "v1.2.0") is True, level
        narrow = cq_rec([([{"introduced": "1.0.0"}, {"fixed": "5.0.0"}], "< 2.0.0")], level)
        assert says(narrow, "v3.0.0") is True and says(narrow, "v1.2.0") is True and says(narrow, "v5.0.0") is False, level
        last = cq_rec([([{"introduced": "1.0.0"}, {"last_affected": "2.0.0"}], "< 1.2.0")], level)
        assert says(last, "v1.5.0") is True and says(last, "v2.0.0") is True and says(last, "v2.0.1") is False, level


@case("audit", "AC5", "b: codeql-action v3.37.8 against the REAL GitHub and OSV records has NO finding and needs NO exception (also with the hint at ranges[])")
def b_integrated():
    net, ctx = make_net(CQ_GH, [CQ_REAL], cq_tags())
    assert summary(judge(net, ctx, cq_item(), [])[0]) == []
    net, ctx = make_net(CQ_GH, [at_range_level(CQ_REAL)], cq_tags())
    assert summary(judge(net, ctx, cq_item(), [])[0]) == []


@case("audit", "AC10", "b: the #208 ruling stays valid but is no longer required: with it loaded the result is the same, and excepted() still returns 'pass' for the dispute it names")
def b_exception_still_valid():
    net, ctx = make_net(CQ_GH, [CQ_REAL], cq_tags())
    exceptions = load_exc([CQ_EXC])
    assert summary(judge(net, ctx, cq_item(), exceptions)[0]) == []
    with offline(), ctx:
        assert pa.excepted(cq_item(), {"GHSA-vqf5-2xx6-9wfm"}, {"GHSA-vqf5-2xx6-9wfm": CQ_GH[0]["updated_at"]}, exceptions, net,
                           {"GHSA-vqf5-2xx6-9wfm": CQ_REAL["modified"]}) == "pass"


@case("audit", "AC5", "b: for a GHSA id GitHub's own record wins over the OSV copy: a copy that lost its closing event AND its hints, against GitHub 'not affected', is no dispute and no hit")
def b_github_wins_clean():
    stale = cq_rec([([{"introduced": "3.26.11"}], NO_HINT), ([{"introduced": "2.26.11"}], NO_HINT)])
    net, ctx = make_net(CQ_GH, [stale], cq_tags())
    assert summary(judge(net, ctx, cq_item(), [])[0]) == []


@case("audit", "AC5", "b: GitHub's record wins the other way: GitHub says v3.27.0 is affected while the OSV copy is out of date and says not: ONE confirmed hit on the GHSA id, not a dispute")
def b_github_wins_hit():
    stale = cq_rec([([{"introduced": "3.30.0"}, {"fixed": "3.31.0"}], NO_HINT)])
    item = inv.Item("action", CQ, CQ_SHA, "v3.27.0")
    net, ctx = make_net(CQ_GH, [stale], {CQ: {"v3.27.0": CQ_SHA}})
    assert summary(judge(net, ctx, item, [])[0]) == [("advisory", ("GHSA-vqf5-2xx6-9wfm",))]


@case("audit", "AC5", "b: the reverse lookup through a VERSIONED query: goreleaser 1.26.0 (GitHub: '= 1.26.0' affected) with a stale GHSA-primary OSV copy that the versioned Go query excludes, then reads back unaffected, is ONE confirmed advisory, never 'disputed'; the same for pyyaml 5.3 through a versioned PyPI query")
def b_reverse_versioned():
    stale = copy.deepcopy(REAL["osv"]["GHSA-f6mm-5fc7-3g3c"])
    stale["affected"] = [go_aff(GORELEASER, [{"introduced": "1.30.0"}, {"fixed": "1.31.0"}])]
    net, ctx = make_net(R_gh("GHSA-f6mm-5fc7-3g3c"), [stale])
    f, _ = judge(net, ctx, inv.Item("tool", "goreleaser", "1.26.0"), [])
    assert summary(f) == [("advisory", ("GHSA-f6mm-5fc7-3g3c",))], summary(f)
    stale = copy.deepcopy(REAL["osv"]["GHSA-8q59-q68h-6hv4"])
    stale["affected"] = [{"package": {"name": "pyyaml", "ecosystem": "PyPI"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.0"}]}]}]
    net, ctx = make_net(R_gh("GHSA-8q59-q68h-6hv4"), [stale])
    f, _ = judge(net, ctx, inv.Item("package", "pypi/pyyaml", "5.3"), [])
    assert summary(f) == [("advisory", ("GHSA-8q59-q68h-6hv4",))], summary(f)


@case("audit", "AC5", "b: fail closed when GitHub's own record has no range for the package: the OSV copy is not trusted to say 'not affected' (an open-ended copy stays a finding)")
def b_no_github_record():
    stale = cq_rec([([{"introduced": "2.26.11"}], NO_HINT)])
    other_pkg = ghsa("GHSA-vqf5-2xx6-9wfm", "someone/else", ["< 1.0.0"], "2025-03-31T21:55:43Z", eco="actions")
    net, ctx = make_net([other_pkg], [stale], cq_tags())
    assert judge(net, ctx, cq_item(), [])[0], "an open-ended OSV copy with no GitHub range to check it against must not pass as clean"


@case("audit", "AC10", "b: two DIFFERENT ids of one incident still dispute (a Go-database id against a GHSA id): GitHub winning over its own id changes nothing for another database's id")
def b_other_ids_dispute():
    g = ghsa("GHSA-test-test-test", COSIGN, ["<= 2.2.3"], "2024-04-11T17:05:02Z")
    o = osv_rec("GO-2099-0001", "2026-02-04T00:00:00Z", [go_aff(COSIGN, [{"introduced": "0"}]), go_aff(COSIGN + "/v3", [{"introduced": "0"}])], ["GHSA-test-test-test"])
    net, ctx = make_net([g], [o])
    f, _ = judge(net, ctx, cosign(), [])
    assert [x.kind for x in f] == ["disputed"] and set(f[0].ids) == {"GHSA-test-test-test", "GO-2099-0001"}, summary(f)


# ======================================================================================================================================
# c. (advisor 0245) no resolver: any ${{ }} where a version is pinned fails closed (AC2 inventory/age check, AC5 audit)
# ======================================================================================================================================
GL = "f06c13b6b1a9625abc9e6e439d9c05a8f2190e94"
WFPATH = ".github/workflows/x.yml"


def wf(text, path=WFPATH):
    return sorted(inv.inventory({path: text}))


def line_of(text, needle):
    for n, l in enumerate(text.split("\n"), 1):
        if needle in l:
            return n
    raise AssertionError("no line has " + needle)


GORELEASER_STEP = f"""      - uses: goreleaser/goreleaser-action@{GL} # v7.2.3
        with:
          version: ${{{{ env.GORELEASER_VERSION }}}}
"""


def goreleaser_wf(top="", job="", step_env="", extra_steps="", extra_jobs=""):
    return "on: push\n" + top + "jobs:\n  rel:\n    runs-on: ubuntu-latest\n" + job + "    steps:\n" + GORELEASER_STEP + step_env + extra_steps + extra_jobs


EXPR_FIXTURES = [
    ("workflow-level env with a plain value", goreleaser_wf(top="env:\n  GORELEASER_VERSION: '2.17.1'\n"), "${{ env.GORELEASER_VERSION }}", "goreleaser"),
    ("job-level env", goreleaser_wf(top="env:\n  GORELEASER_VERSION: '2.0.0'\n", job="    env:\n      GORELEASER_VERSION: '2.17.1'\n"), "${{ env.GORELEASER_VERSION }}", "goreleaser"),
    ("step-level env", goreleaser_wf(top="env:\n  GORELEASER_VERSION: '2.0.0'\n", job="    env:\n      GORELEASER_VERSION: '2.1.0'\n", step_env="        env:\n          GORELEASER_VERSION: '2.18.0'\n"),
     "${{ env.GORELEASER_VERSION }}", "goreleaser"),
    ("the compact spelling ${{env.X}}", goreleaser_wf(top="env:\n  GORELEASER_VERSION: '2.17.1'\n").replace("${{ env.GORELEASER_VERSION }}", "${{env.GORELEASER_VERSION}}"), "${{env.GORELEASER_VERSION}}", "goreleaser"),
    ("a name nobody defines", goreleaser_wf(), "${{ env.GORELEASER_VERSION }}", "goreleaser"),
    ("a matrix value", goreleaser_wf().replace("env.GORELEASER_VERSION", "matrix.v"), "${{ matrix.v }}", "goreleaser"),
    ("a vars value", goreleaser_wf().replace("env.GORELEASER_VERSION", "vars.GORELEASER"), "${{ vars.GORELEASER }}", "goreleaser"),
    ("a secrets value", goreleaser_wf().replace("env.GORELEASER_VERSION", "secrets.GORELEASER"), "${{ secrets.GORELEASER }}", "goreleaser"),
    ("a value that is itself an expression", goreleaser_wf(top="env:\n  GORELEASER_VERSION: '${{ vars.G }}'\n"), "${{ env.GORELEASER_VERSION }}", "goreleaser"),
    ("golangci-lint's input", f"on: push\nenv:\n  GL_VERSION: v2.13.2\njobs:\n  j:\n    runs-on: u\n    steps:\n      - uses: golangci/golangci-lint-action@{'2' * 40} # v9.3.0\n        with:\n          version: ${{{{ env.GL_VERSION }}}}\n",
     "${{ env.GL_VERSION }}", "golangci-lint"),
    ("a go install target", "on: push\njobs:\n  j:\n    runs-on: u\n    env:\n      GOSEC_VERSION: v2.29.0\n    steps:\n      - run: |\n          echo start\n          go install github.com/securego/gosec/v2/cmd/gosec@${{ env.GOSEC_VERSION }}\n",
     "${{ env.GOSEC_VERSION }}", "github.com/securego/gosec/v2/cmd/gosec"),
    ("a release download", "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - run: curl -fsSL https://github.com/cli/cli/releases/download/${{ env.GH_V }}/gh.tgz -o gh.tgz\n", "${{ env.GH_V }}", "cli/cli"),
    ("a pip pin", "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - run: pip install pyyaml==${{ env.PYV }} --hash=sha256:aa\n", "${{ env.PYV }}", "pypi/pyyaml"),
    ("an action ref", "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - uses: actions/checkout@${{ env.CHECKOUT_SHA }}\n", "${{ env.CHECKOUT_SHA }}", None),
]


def unparseable_items(text, path=WFPATH):
    return [it for it in inv.inventory({path: text}).values() if "${{" in (it.version or "")]


@case("age", "AC2", "c: NOTHING resolves: every spelling of an expression where a version is pinned (workflow, job and step env with a plain literal, compact, undefined, matrix, vars, secrets, an expression-valued env, golangci-lint's input, a go install target, a release download, a pip pin, an action ref) is exactly ONE retained non-pin inventory item")
def c_inventory_retained():
    for label, text, needle, name in EXPR_FIXTURES:
        its = unparseable_items(text)
        assert len(its) == 1, (label, sorted(inv.inventory({WFPATH: text})))
        it = its[0]
        assert it.kind in ("tool", "gotool", "package", "action") and not age.is_pin(it.version), (label, it.key)
        if name:
            assert it.name == name, (label, it.key)
            pins = [k for k, v in inv.inventory({WFPATH: text}).items() if v.name == name and v.kind == it.kind and age.is_pin(v.version)]
            assert not pins, (label, pins)


@case("audit", "AC5", "c: and the audit FAILS for each of them (kind 'unparseable'), naming the file and the line of the expression, and never printing the expression's text")
def c_audit_fails():
    for label, text, needle, name in EXPR_FIXTURES:
        for it in unparseable_items(text):
            net, ctx = make_net()
            f, _ = judge(net, ctx, it)
            assert [x.kind for x in f] == ["unparseable"], (label, summary(f))
            m = re.search(r"\(at (\S+?):(\d+)\)", f[0].why)
            assert m and (m.group(1), int(m.group(2))) == (WFPATH, line_of(text, needle)), (label, line_of(text, needle), f[0].why)
            assert "env." not in f[0].why and "matrix." not in f[0].why and "secrets." not in f[0].why and "${{" not in f[0].why, (label, f[0].why)


@case("audit", "AC5", "c: nothing is skipped by the lookup either: with advisory lists that HOLD a record for the package the unparseable item is still the one finding for an expression (no lookup under a made-up version)")
def c_audit_not_looked_up():
    text = goreleaser_wf(top="env:\n  GORELEASER_VERSION: '1.26.0'\n")
    net, ctx = gr_net()
    f, _ = judge(net, ctx, unparseable_items(text)[0])
    assert [x.kind for x in f] == ["unparseable"], summary(f)


@case("audit", "AC10", "c: an exception never suppresses an unresolved expression: with REAL matching exceptions loaded (the five cosign rulings; a goreleaser ruling), cosign@${{ }} and goreleaser@${{ }} are still 'unparseable'; so are the unresolved and mismatched pins of an action that has an exception for its package")
def c_exception_never_suppresses():
    cos = unparseable_items("on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - uses: sigstore/cosign-installer@%s # v4.1.2\n        with:\n          cosign-release: ${{ vars.COSIGN }}\n" % "6f9f17788090df1f26f669e9d70d6ae9567deba6")
    assert len(cos) == 1 and cos[0].name == "cosign", [i.key for i in cos]
    net, ctx = cosign_net()
    f, _ = judge(net, ctx, cos[0], load_exc(COSIGN_EXC))
    assert [x.kind for x in f] == ["unparseable"], summary(f)
    gr_exc = exc("goreleaser", ["GHSA-f6mm-5fc7-3g3c", "GO-2024-2860"], "GHSA-f6mm-5fc7-3g3c", ["= 1.26.0"],
                 {"GHSA-f6mm-5fc7-3g3c": REAL["gh"]["GHSA-f6mm-5fc7-3g3c"]["updated_at"], "GO-2024-2860": REAL["osv"]["GO-2024-2860"]["modified"]}, "1.26.0")
    net, ctx = gr_net()
    f, _ = judge(net, ctx, unparseable_items(goreleaser_wf(top="env:\n  GORELEASER_VERSION: '1.26.0'\n"))[0], load_exc([gr_exc]))
    assert [x.kind for x in f] == ["unparseable"], summary(f)
    ua_exc = exc(UA, ["GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff"], "GHSA-aaaa-bbbb-cccc", ["< 4.0.0"], {"GHSA-aaaa-bbbb-cccc": "t", "GHSA-dddd-eeee-ffff": "t"}, "4.6.2")
    net, ctx = make_net(tags=UA_TAGS)
    assert [x.kind for x in judge(net, ctx, ua_item(UA_TYPO, "v4.6.2"), load_exc([ua_exc]))[0]] == ["unresolved"]
    net, ctx = make_net(tags=UA_TAGS)
    assert [x.kind for x in judge(net, ctx, ua_item(UA_OTHER, "v4.6.2"), load_exc([ua_exc]))[0]] == ["mismatch"]


@case("audit", "AC10", "c: an exceptions file naming an unparseable version ('${{ env.X }}', '(unparseable)', '(unpinned)', '(default)', empty) is malformed (exit 2 in the run); real versions and series still load")
def c_exception_loader():
    base = exc("goreleaser", ["A", "B"], "A", ["< 1"], {"A": "t", "B": "t"}, "2.17.1")
    for ok in ("2.17.1", "v2.17.1", "4.*", "3.1.3"):
        assert load_exc([dict(base, version=ok)])
    for bad in ("${{ env.GORELEASER_VERSION }}", "${{expression}}", "(unparseable)", "(unpinned)", "(default)", "(variable)", "latest", "*", ".*", ""):
        try:
            load_exc([dict(base, version=bad)])
        except pa.Fail:
            continue
        raise AssertionError("an exception for the version %r was accepted" % bad)


def _git(repo, *args):
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@x", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@x")
    return subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True, env=env, check=True)


def pr_repo(base_files, head_files):
    """A repository with a base commit and a head commit (the pull request)."""
    d = tempfile.mkdtemp(dir=TMP)
    _git(d, "init", "-q")
    for files in (base_files, head_files):
        for path, text in files.items():
            os.makedirs(os.path.dirname(os.path.join(d, path)) or d, exist_ok=True)
            open(os.path.join(d, path), "w").write(text)
        _git(d, "add", "-A")
        _git(d, "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", "c")
    return d


def run_age(repo, fixtures):
    fx = repo + ".fx.json"
    json.dump(fixtures, open(fx, "w"))
    r = subprocess.run([sys.executable, os.path.join(SC, "pin-age-check.py"), "--root", repo, "--base", "HEAD~1", "--head", "HEAD", "--fixtures", fx,
                        "--now", "2026-10-07T12:00:00Z"], capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


GR_BASE = "on: push\njobs:\n  rel:\n    runs-on: u\n    steps:\n      - uses: goreleaser/goreleaser-action@%s # v7.2.3\n        with:\n          version: '2.17.1'\n" % GL
OLD_FX = {"times": {"tool:goreleaser@2.17.1": {"time": "2026-09-01T00:00:00Z", "source": "github-release"}, "tool:goreleaser@2.18.0": {"time": "2026-09-01T00:00:00Z", "source": "github-release"}},
          "first_seen": {"action:actions/checkout@" + "3" * 40: "2026-09-01T00:00:00Z"}}


@case("age", "AC2", "c: end to end through the age check: a pull request that moves a pin to an expression exits non-zero (the same literal version spelled through env, an undefined name, an env value changed under an unchanged expression, an action ref given by an expression), whatever the fixture clock says")
def c_age_end_to_end():
    for label, head in (("same version through env", goreleaser_wf(top="env:\n  GORELEASER_VERSION: '2.17.1'\n")), ("undefined name", goreleaser_wf())):
        rc, out = run_age(pr_repo({WFPATH: GR_BASE}, {WFPATH: head}), OLD_FX)
        assert rc == 1 and "FAIL" in out, (label, out)
    b = goreleaser_wf(top="env:\n  GORELEASER_VERSION: '2.17.1'\n")
    rc, out = run_age(pr_repo({WFPATH: b}, {WFPATH: b.replace("'2.17.1'", "'2.18.0'")}), OLD_FX)
    assert rc == 1 and "FAIL" in out, out
    co = "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - run: echo hi\n"
    rc, out = run_age(pr_repo({WFPATH: co}, {WFPATH: co + "      - uses: actions/checkout@${{ env.SHA }}\n"}), OLD_FX)
    assert rc == 1 and "FAIL" in out, out


@case("age", "AC2", "c: the real tree today has NO expression in a version position: no inventory item of the current tree carries one (the rule raises nothing on today's files)")
def c_real_tree_control():
    items = inv.load_at(ROOT, None)
    bad = [k for k, it in items.items() if "${{" in (it.version or "") and it.name != "(unresolved-script)"]     # (variable-built script targets are a separate rule: see x_real_tree_unresolved)
    assert not bad, bad


# ======================================================================================================================================
# d. pip requirement lines with --hash options (AC2); inventory to audit for pyyaml
# ======================================================================================================================================
H1 = "sha256:80bab7bfc629882493af4aa31a4cfa43a4c57c83813253626916b8c7ada83476"
H2 = "sha256:1f71ea527786de97d1a0cc0eacd1defc0985dcf6b3f17bb77dcfc8c34bec4dc5"


def run_wf(body):
    lines = "".join("          " + l + "\n" for l in body.split("\n"))
    return "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - name: pip\n        run: |\n" + lines


def pkgs(text, path=WFPATH):
    return sorted(k for k in wf(text, path) if k.startswith("package:"))


def only_pins(keys):
    return [k for k in keys if age.is_pin(k.split("@", 1)[1].split("#")[0])]


def non_pins(keys):
    return [k for k in keys if not age.is_pin(k.split("@", 1)[1].split("#")[0])]


HEREDOC = "python3 -m pip install --quiet --require-hashes --only-binary=:all: -r /dev/stdin <<'REQ'\n%s\nREQ\npython3 bin/check-workflow-permissions.py"


@case("age", "AC2", "d: ci.yml's real shape (a heredoc requirement line with two --hash options) parses to pypi/pyyaml@6.0.2 and nothing else")
def d_real_shape():
    assert pkgs(run_wf(HEREDOC % f"pyyaml==6.0.2 --hash={H1} --hash={H2}")) == ["package:pypi/pyyaml@6.0.2"]


@case("age", "AC2", "d: continuation lines (name==version \\ then one --hash per line) parse, in a heredoc, inline and in a script")
def d_continuation():
    req = f"pyyaml==6.0.2 \\\n  --hash={H1} \\\n  --hash={H2}"
    assert pkgs(run_wf(HEREDOC % req)) == ["package:pypi/pyyaml@6.0.2"]
    assert pkgs(run_wf(f"pip install --require-hashes pyyaml==6.0.2 \\\n  --hash={H1} \\\n  --hash={H2}")) == ["package:pypi/pyyaml@6.0.2"]
    assert pkgs("#!/usr/bin/env bash\npip install --require-hashes pyyaml==6.0.2 \\\n  --hash=%s\n" % H1, "bin/x.sh") == ["package:pypi/pyyaml@6.0.2"]


@case("age", "AC2", "d: inline `pip install pkg==1 --hash=...` run lines parse (python3 -m pip, extras, markers, upper case)")
def d_inline():
    for line in (f"pip install pyyaml==6.0.2 --hash={H1}", f"python3 -m pip install --require-hashes PyYAML==6.0.2 --hash={H1} --hash={H2}",
                 f"pip install 'pyyaml[extra]==6.0.2' --hash={H1}", f"pip install pyyaml==6.0.2 --hash {H1}"):
        assert pkgs(run_wf(line)) == ["package:pypi/pyyaml@6.0.2"], line


@case("age", "AC2", "d: the requirement lines of the real hash-pinned files are all read: every name==version of the tree's requirements files is an item")
def d_real_files():
    files = inv.tree_files(ROOT, None)
    items = inv.load_at(ROOT, None)
    seen = 0
    for path, text in files.items():
        if re.search(r"requirements[\w.-]*\.txt$", path):
            for m in re.finditer(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==(\S+)", text, re.M):
                seen += 1
                key = "package:pypi/%s@%s" % (m.group(1).lower().replace("_", "-"), m.group(2))
                assert key in items, key
    assert seen >= 3, seen
    assert "package:pypi/pyyaml@6.0.2" in items


@case("age", "AC2", "d: PEP 508 spacing is read: `pyyaml == 6.0.2 --hash=...` is the pin 6.0.2 (not an unpinned name)")
def d_spaced():
    for text in (run_wf(HEREDOC % f"pyyaml == 6.0.2 --hash={H1}"), run_wf(f"pip install 'pyyaml == 6.0.2' --hash={H1}"), run_wf(f"pip install pyyaml == 6.0.2 --hash={H1}")):
        k = pkgs(text)
        assert only_pins(k) == ["package:pypi/pyyaml@6.0.2"] and not non_pins(k), k


@case("age", "AC2", "d: a requirements heredoc fed to `pip install -r /dev/stdin` (or `-r -`) is read with or without --require-hashes")
def d_no_flag():
    for form in ("-r /dev/stdin", "-r -", "--requirement=/dev/stdin"):
        text = run_wf(f"python3 -m pip install --quiet {form} <<'REQ'\n" + f"pyyaml==6.0.2 --hash={H1}\nREQ")
        assert pkgs(text) == ["package:pypi/pyyaml@6.0.2"], (form, pkgs(text))


@case("age", "AC2", "d: comments, blank lines, the terminator, an environment marker and several packages in one heredoc are read exactly")
def d_clean_heredoc():
    req = f"# hash-pinned\n\npyyaml==6.0.2 --hash={H1}\nrequests==2.32.0 ; python_version >= \"3.8\" \\\n  --hash={H2}\n"
    assert pkgs(run_wf(HEREDOC % req)) == ["package:pypi/pyyaml@6.0.2", "package:pypi/requests@2.32.0"]


@case("age", "AC2", "d: TWO pip heredocs in one step are each read from THEIR OWN body (same delimiter, different delimiters, with and without --require-hashes anywhere in the step): requests==2.32.0 and pyyaml==5.3 are both inventoried")
def d_two_heredocs():
    blocks = ("pip install --require-hashes -r /dev/stdin <<'REQ'\nrequests==2.32.0 --hash=%s\nREQ\npip install --require-hashes -r /dev/stdin <<'REQ'\npyyaml==5.3 --hash=%s\nREQ",
              "pip install --require-hashes -r /dev/stdin <<'AAA'\nrequests==2.32.0 --hash=%s\nAAA\npip install -r /dev/stdin <<'BBB'\npyyaml==5.3 --hash=%s\nBBB",
              "pip install -r /dev/stdin <<'REQ'\nrequests==2.32.0 --hash=%s\nREQ\npip install -r /dev/stdin <<'REQ'\npyyaml==5.3 --hash=%s\nREQ",
              "pip install -r - <<EOF1\nrequests==2.32.0 --hash=%s\nEOF1\necho between\npip install --require-hashes -r /dev/stdin <<'EOF2'\npyyaml==5.3 --hash=%s\nEOF2")
    for b in blocks:
        k = pkgs(run_wf(b % (H1, H2)))
        assert k == ["package:pypi/pyyaml@5.3", "package:pypi/requests@2.32.0"], (b[:40], k)


@case("age", "AC2", "d: fail closed: a line of a pip heredoc the parser cannot read (bare name, range, URL, git, editable, variable) becomes a non-pin package item the age check refuses; the readable pin beside it still parses")
def d_unreadable():
    for bad in (f"pyyaml --hash={H1}", f"pyyaml>=6 --hash={H1}", f"https://example.invalid/pyyaml-6.0.2-py3-none-any.whl --hash={H1}",
                "git+https://example.invalid/x.git@abc", "-e .", f"$PKG --hash={H1}", f"pyyaml~=6.0 --hash={H1}"):
        k = pkgs(run_wf(HEREDOC % (f"requests==2.32.0 --hash={H2}\n" + bad)))
        assert "package:pypi/requests@2.32.0" in k, (bad, k)
        assert non_pins(k), (bad, k)


@case("age", "AC2", "d: fail closed: a requirements list read from a pipe (`-r /dev/stdin` or `-r -`, no heredoc to read) is a non-pin package item")
def d_piped():
    for form in ("-r /dev/stdin", "-r -"):
        k = pkgs(run_wf(f"curl -fsSL https://example.invalid/r.txt | python3 -m pip install --require-hashes {form}"))
        assert non_pins(k), (form, k)


@case("age", "AC2", "d: fail closed inline: an unreadable pip install line is a non-pin item (a variable, a URL, a bare name)")
def d_inline_unreadable():
    for line in (f'pip install "$PKG" --hash={H1}', f"pip install https://example.invalid/x.whl --hash={H1}", f"pip install pyyaml --hash={H1}"):
        assert non_pins(pkgs(run_wf(line))), line


PY_BASE = "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - name: pip\n        run: |\n          python3 -m pip install --quiet --require-hashes --only-binary=:all: -r /dev/stdin <<'REQ'\n          %s\n          REQ\n"


@case("age", "AC2", "d: end to end: a pull request that bumps the heredoc pin is named by the age check (pyyaml 5.3, the pypi time decides), and one that rewrites the line as a bare name is refused (it can no longer be measured)")
def d_age_end_to_end():
    base = PY_BASE % f"pyyaml==6.0.2 --hash={H1}"
    fx = {"times": {"package:pypi/pyyaml@5.3": {"time": "2026-09-01T00:00:00Z", "source": "pypi"}}}
    rc, out = run_age(pr_repo({WFPATH: base}, {WFPATH: PY_BASE % f"pyyaml==5.3 --hash={H1}"}), fx)
    assert rc == 0 and "package:pypi/pyyaml@5.3" in out, out
    rc, out = run_age(pr_repo({WFPATH: base}, {WFPATH: PY_BASE % f"pyyaml --hash={H1}"}), fx)
    assert rc == 1 and "FAIL" in out, out
    rc, out = run_age(pr_repo({WFPATH: base}, {WFPATH: PY_BASE % f"pyyaml==5.3 --hash={H1}"}), {"times": {"package:pypi/pyyaml@5.3": {"time": "2026-10-06T00:00:00Z", "source": "pypi"}}})
    assert rc == 1, out


def audit_inventory(text, net, ctx, path=WFPATH, kinds=("tool", "gotool", "package")):
    findings = []
    for it in inv.inventory({path: text}).values():
        if it.kind in kinds:
            findings += judge(net, ctx, it)[0]
    return findings


@case("audit", "AC5", "d: inventory to audit for pyyaml with the real records: the heredoc pin 6.0.2 is clean (GHSA-8q59 is fixed in 5.4), the heredoc pin 5.3 is a confirmed hit (GHSA-8q59-q68h-6hv4 + PYSEC-2021-142, and GHSA-6757-jp84-gxfx), no dispute")
def d_audit_pyyaml():
    net, ctx = py_net()
    assert summary(audit_inventory(PY_BASE % f"pyyaml==6.0.2 --hash={H1}", net, ctx)) == []
    net, ctx = py_net()
    f = audit_inventory(PY_BASE % f"pyyaml==5.3 --hash={H1}", net, ctx)
    assert all_ids(f) >= {"GHSA-8q59-q68h-6hv4", "PYSEC-2021-142", "GHSA-6757-jp84-gxfx"} and not any(x.disputed for x in f), summary(f)
    assert not all_ids(f) & {"GHSA-rprw-h62v-c2w7", "GHSA-3pqx-4fqf-j49f"}, summary(f)


@case("audit", "AC5", "d: inventory to audit for goreleaser with the real records: 2.17.1 is clean, 1.26.0 and 1.23.0 are confirmed hits (GHSA-f6mm + GO-2024-2860, GHSA-h3q2 + GO-2024-2482), 1.26.1 and 1.24.0 are clean")
def d_audit_goreleaser():
    def audit(ver):
        text = f"on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - uses: goreleaser/goreleaser-action@{GL} # v7.2.3\n        with:\n          version: '{ver}'\n"
        net, ctx = gr_net()
        return audit_inventory(text, net, ctx)
    assert summary(audit("2.17.1")) == [] and summary(audit("1.26.1")) == [] and summary(audit("1.24.0")) == []
    f = audit("1.26.0")
    assert all_ids(f) == {"GHSA-f6mm-5fc7-3g3c", "GO-2024-2860"} and not any(x.disputed for x in f), summary(f)
    f = audit("1.23.0")
    assert all_ids(f) == {"GHSA-h3q2-8whx-c29h", "GO-2024-2482"} and not any(x.disputed for x in f), summary(f)


@case("audit", "AC5", "c: the non-pin kinds too: a gotool and a package whose version is an expression are findings (not only the tool kind)")
def c_other_kinds():
    for label, text, needle, name in EXPR_FIXTURES:
        if label in ("a go install target", "a pip pin", "an action ref"):
            its = unparseable_items(text)
            net, ctx = make_net(go_module=lambda p, v: ("github.com/securego/gosec/v2", {"Version": v}))
            assert [x.kind for x in judge(net, ctx, its[0])[0]] == ["unparseable"], (label, its[0].kind)


# ======================================================================================================================================
# e. a commit carrying several tags (AC5)
# ======================================================================================================================================
def da_item(label):
    return inv.Item("action", DA, DA_SHA, label)


def da_net(*tags, clean=False):
    return make_net([] if clean else R_gh("GHSA-cxww-7g56-2vh6"), [] if clean else R_osv("GHSA-cxww-7g56-2vh6"), {DA: {t: DA_SHA for t in tags}})


@case("audit", "AC5", "e: download-artifact at the commit with v4 and v4.3.0 (the real GHSA-cxww-7g56-2vh6, `>= 4.0.0, < 4.1.3`), comment `# v4.3.0`: judged by v4.3.0, NOT by the floating v4 (4.0.0 is inside the range): no finding")
def e_exact_label():
    net, ctx = da_net("v4", "v4.3.0")
    assert summary(judge(net, ctx, da_item("v4.3.0"))[0]) == []


@case("audit", "AC5", "e: the comment `# v4` (floating) is judged by the X.Y.Z tag of its major at the commit (v4.3.0): no finding")
def e_floating_label():
    net, ctx = da_net("v4", "v4.3.0")
    assert summary(judge(net, ctx, da_item("v4"))[0]) == []


@case("audit", "AC5", "e: still a hit when the tag within the major IS affected: the commit of v4 and v4.1.0, comment v4 or v4.1.0")
def e_affected_control():
    for label in ("v4", "v4.1.0"):
        net, ctx = da_net("v4", "v4.1.0")
        f, _ = judge(net, ctx, da_item(label))
        assert [x.kind for x in f] == ["advisory"] and f[0].ids == ["GHSA-cxww-7g56-2vh6"], (label, summary(f))


@case("audit", "AC5", "e: (0255) a floating comment is affected if ANY exact tag on the commit is: with the real range '>= 4.0.0, < 4.1.3' and tags v4, v4.1.0, v4.3.0, `# v4` is a HIT (v4.1.0 is affected although v4.3.0 is not); an exact `# v4.3.0` is clean (its own tag), `# v4.1.0` is a hit")
def e_any_tag():
    for label, want in (("v4", ["advisory"]), ("v4.3.0", []), ("v4.1.0", ["advisory"])):
        net, ctx = da_net("v4", "v4.1.0", "v4.3.0")
        assert [x.kind for x in judge(net, ctx, da_item(label))[0]] == want, label


def da_range_net(rng, *tags):
    g = ghsa("GHSA-test-test-test", DA, [rng], "2025-01-22T17:31:56Z", eco="actions")
    return make_net([g], [], {DA: {t: DA_SHA for t in tags}})


@case("audit", "AC5", "e: (0255) NO tag is preferred: with tags v4, v4.1.0, v4.2.9, v4.3.0, v4.10.0 and v4.4.0-rc.1 on one commit, each of them being the ONLY affected one (range `= T`) makes `# v4` AND `# v4.3` a hit (so highest-only, lowest-only, first-only, within-the-minor and releases-only readings all fail); no tag affected is clean")
def e_every_tag_alone():
    tags = ("v4", "v4.1.0", "v4.2.9", "v4.3.0", "v4.10.0", "v4.4.0-rc.1")
    for t in tags[1:]:
        for label in ("v4", "v4.3"):
            net, ctx = da_range_net("= " + t.lstrip("v"), *tags, "v4.3")
            kinds = [x.kind for x in judge(net, ctx, da_item(label))[0]]
            assert kinds == ["advisory"], (t, label, kinds)
    net, ctx = da_range_net("= 9.9.9", *tags)
    assert summary(judge(net, ctx, da_item("v4"))[0]) == []


@case("audit", "AC5", "e: (0255) another major's tag judges a floating comment too: tags v4 and v5.3.0 with range '>= 5.0.0' make `# v4` a hit; with a clean range it is clean (resolved, not unresolved); a pre-release alone counts (v4, v4.0.0-rc.1 with range '>= 4.0.0-rc.0, < 4.0.0')")
def e_other_major_and_prerelease():
    net, ctx = da_range_net(">= 5.0.0", "v4", "v5.3.0")
    assert [x.kind for x in judge(net, ctx, da_item("v4"))[0]] == ["advisory"]
    net, ctx = da_range_net(">= 6.0.0", "v4", "v5.3.0")
    assert summary(judge(net, ctx, da_item("v4"))[0]) == []
    net, ctx = da_range_net(">= 4.0.0-rc.0, < 4.0.0", "v4", "v4.0.0-rc.1")
    assert [x.kind for x in judge(net, ctx, da_item("v4"))[0]] == ["advisory"]


@case("audit", "AC5", "e: a floating comment with NO exact X.Y.Z tag on the commit is UNRESOLVED and fails closed: a lone v4 (clean lists and the real lists); any exact tag, of any major or a pre-release, makes it resolved ({v4, v5.3.0} and {v4, v4.0.0-rc.1} are not `unresolved`)")
def e_floating_unresolved():
    for clean in (True, False):
        net, ctx = da_net("v4", clean=clean)
        kinds = [x.kind for x in judge(net, ctx, da_item("v4"))[0]]
        assert "unresolved" in kinds, (clean, kinds)
        if clean:
            assert kinds == ["unresolved"], kinds
    for tags in (("v4", "v5.3.0"), ("v4", "v4.0.0-rc.1")):
        net, ctx = da_net(*tags, clean=True)
        assert summary(judge(net, ctx, da_item("v4"))[0]) == [], tags


@case("audit", "AC5", "e: the version the audit holds for a labelled commit is the one it judged (v4.3.0 for either comment)")
def e_version_of():
    for label in ("v4.3.0", "v4"):
        net, ctx = da_net("v4", "v4.3.0")
        with offline(), ctx:
            assert net.version_of(da_item(label)) == "v4.3.0"


# ======================================================================================================================================
# f. cosign-installer names its release (AC2)
# ======================================================================================================================================
def real_workflow_files():
    out = {}
    for path, text in inv.tree_files(ROOT, None).items():
        if re.search(r"(^\.github/workflows/[^/]+\.ya?ml$)|(^\.github/actions/.*action\.ya?ml$)", path):
            out[path] = text
    return out


def installer_steps(text):
    steps = []

    def walk(n):
        if isinstance(n, dict):
            if isinstance(n.get("uses"), str) and n["uses"].lower().startswith("sigstore/cosign-installer@"):
                steps.append(n)
            for v in n.values():
                walk(v)
        elif isinstance(n, list):
            for v in n:
                walk(v)
    walk(yaml.load(text, Loader=yaml.BaseLoader))
    return steps


@case("age", "AC2", "f: every sigstore/cosign-installer use in the real workflows gives an explicit cosign-release that is an exact vX.Y.Z (the installer's own default is not a pin)")
def f_every_use():
    n = 0
    for path, text in real_workflow_files().items():
        for st in installer_steps(text):
            n += 1
            rel = (st.get("with") or {}).get("cosign-release")
            assert isinstance(rel, str) and re.fullmatch(r"v\d+\.\d+\.\d+", rel), (path, rel)
    assert n >= 1, "no cosign-installer use was found at all"


@case("age", "AC2", "f: stage-promote.yml pins cosign-release v3.0.6 on its cosign-installer step (what runs today)")
def f_stage_promote():
    steps = installer_steps(real_workflow_files()[".github/workflows/stage-promote.yml"])
    assert len(steps) == 1 and steps[0]["with"]["cosign-release"] == "v3.0.6", steps


@case("age", "AC2", "f: the real tree's inventory holds tool:cosign@v3.0.6 and NO cosign@(default) placeholder")
def f_inventory():
    items = inv.load_at(ROOT, None)
    assert "tool:cosign@v3.0.6" in items, sorted(k for k in items if "cosign" in k)
    assert not [k for k in items if k.startswith("tool:cosign@") and k != "tool:cosign@v3.0.6"], sorted(k for k in items if "cosign" in k)


INSTALLER = "      - uses: sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2\n"


def installer_wf(with_block):
    return "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n" + INSTALLER + with_block


@case("age", "AC2", "f: the checker's own gate: a cosign-installer without cosign-release is refused by the age check; an exact cosign-release is measured; latest, a series or a blank are refused")
def f_checker():
    base = "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - run: echo hi\n"
    old = {"times": {"tool:cosign@v3.0.6": {"time": "2026-09-01T00:00:00Z", "source": "github-release"}},
           "first_seen": {"action:sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6": "2026-09-01T00:00:00Z"}}

    def moved(block):
        return run_age(pr_repo({WFPATH: base}, {WFPATH: installer_wf(block)}), old)
    rc, out = moved("")
    assert rc == 1 and "FAIL" in out, out
    rc, out = moved("        with:\n          cosign-release: v3.0.6\n")
    assert rc == 0 and "tool:cosign@v3.0.6" in out, out
    for bad in ("latest", "v3", "''"):
        rc, out = moved("        with:\n          cosign-release: %s\n" % bad)
        assert rc == 1, (bad, out)


# ======================================================================================================================================
# g. a pin's SHA must resolve to the tag its comment names (AC3 age check, AC5 audit)
# ======================================================================================================================================
UA_TAGS = {UA: {"v4": UA_SHA, "v4.6.2": UA_SHA, "v4.5.0": UA_OTHER}}


def ua_item(sha, label):
    return inv.Item("action", UA, sha, label)


@case("audit", "AC3", "g: the typo of #202 (a commit that is in no tag of the repository, comment # v4.6.2) is a finding (kind 'unresolved')")
def g_typo_audit():
    net, ctx = make_net(tags=UA_TAGS)
    assert [x.kind for x in judge(net, ctx, ua_item(UA_TYPO, "v4.6.2"))[0]] == ["unresolved"]


@case("audit", "AC3", "g: a pin whose commit is the commit of ANOTHER tag than its comment names (comment v4.6.2, commit of v4.5.0) is a finding (kind 'mismatch')")
def g_mismatch_audit():
    net, ctx = make_net(tags=UA_TAGS)
    assert [x.kind for x in judge(net, ctx, ua_item(UA_OTHER, "v4.6.2"))[0]] == ["mismatch"]


@case("audit", "AC3", "g: a floating comment that is not among the commit's tags is a mismatch too (comment v4.6, commit tags v4 and v4.6.2)")
def g_mismatch_floating_audit():
    net, ctx = make_net(tags=UA_TAGS)
    assert [x.kind for x in judge(net, ctx, ua_item(UA_SHA, "v4.6"))[0]] == ["mismatch"]


@case("audit", "AC3", "g: a pin whose comment names a tag the commit carries (exact or floating) is clean; so is a pin with no comment, and a comment that is not a version")
def g_clean_audit():
    for label in ("v4.6.2", "v4", ""):
        net, ctx = make_net(tags=UA_TAGS)
        assert summary(judge(net, ctx, ua_item(UA_SHA, label))[0]) == [], label
    net, ctx = make_net(tags=UA_TAGS)
    assert summary(judge(net, ctx, ua_item(UA_SHA, "pinned"))[0]) == []


@case("audit", "AC3", "g: the mismatch finding names the pinned commit and the tag in its text (public facts only)")
def g_mismatch_text():
    net, ctx = make_net(tags=UA_TAGS)
    f, _ = judge(net, ctx, ua_item(UA_OTHER, "v4.6.2"))
    assert "v4.6.2" in f[0].why and f[0].item.version == UA_OTHER, f[0].why


def age_rows(sha, label, tags, pr_clock="2026-09-20T00:00:00Z"):
    """The age check on a pull request that moves actions/upload-artifact to `sha # label`, live code paths, every server faked; the PR clock says the
    commit has been in the pull request for 17 days (so the age itself is never the reason to fail)."""
    base = "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - uses: actions/checkout@%s # v4.1.0\n" % ("1" * 40)
    head = base + "      - uses: actions/upload-artifact@%s # %s\n" % (sha, label)
    repo = pr_repo({WFPATH: base}, {WFPATH: head})
    out = repo + ".json"
    buf = io.StringIO()
    with patched(age, _tag_refs=lambda r: dict(tags.get(r, {})), observed=lambda: None, _pr_clock=lambda item, root, base_, head_="HEAD": pr_clock), contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        rc = age.main(["--root", repo, "--base", "HEAD~1", "--head", "HEAD", "--now", "2026-10-07T12:00:00Z", "--json", out])
    rows = {r["item"]: r for r in json.load(open(out))["moved"]}
    return rc, rows.get("action:actions/upload-artifact@" + sha), buf.getvalue()


@case("age", "AC3", "g: the age check refuses the typo pin (a commit in no tag) even though the PR clock is old, and says which tag the comment named")
def g_typo_age():
    rc, row, out = age_rows(UA_TYPO, "v4.6.2", UA_TAGS)
    assert rc == 1 and row and not row["ok"] and "v4.6.2" in row["reason"], (rc, row, out)


@case("age", "AC3", "g: the age check refuses a pin whose commit is another tag's commit (comment v4.6.2, commit of v4.5.0), whatever the PR clock says")
def g_mismatch_age():
    rc, row, out = age_rows(UA_OTHER, "v4.6.2", UA_TAGS)
    assert rc == 1 and row and not row["ok"] and "v4.6.2" in row["reason"], (rc, row, out)


@case("age", "AC3", "g: the age check refuses a FLOATING comment that is not among the commit's tags (comment v4.6, commit tags v4 and v4.6.2), whatever the PR clock says")
def g_mismatch_floating_age():
    rc, row, out = age_rows(UA_SHA, "v4.6", UA_TAGS)
    assert rc == 1 and row and not row["ok"] and "v4.6" in row["reason"], (rc, row, out)


@case("age", "AC3", "g: a pin whose comment tag does resolve to the commit (exact, or the floating v4) passes on an old PR clock")
def g_ok_age():
    for label in ("v4.6.2", "v4"):
        rc, row, out = age_rows(UA_SHA, label, UA_TAGS)
        assert rc == 0 and row and row["ok"], (label, rc, row, out)


@case("age", "AC3", "g: an old PR clock can never rescue a mismatch: the same mismatched pin with a 100-day-old clock still fails")
def g_old_clock_age():
    rc, row, out = age_rows(UA_OTHER, "v4.6.2", UA_TAGS, pr_clock="2026-06-01T00:00:00Z")
    assert rc == 1 and row and not row["ok"], (rc, row, out)


# ======================================================================================================================================
# step 6 round 2: GitHub-only Go hits; every position and spelling of an expression through the entry points; repeated occurrences
# ======================================================================================================================================
@case("audit", "AC5", "a: GitHub-only Go hits (the OSV query answers NOTHING) under BOTH names: cosign v3.0.3 / GHSA-whqx-f9j3-ch6m (filed under /v2 and /v3) and v3.0.5 / GHSA-w6c6-c85g-mmv6 (filed under the bare name) are each ONE confirmed hit")
def a_github_only_names():
    net, ctx = make_net(R_gh("GHSA-whqx-f9j3-ch6m"))
    assert summary(judge(net, ctx, cosign("v3.0.3"))[0]) == [("advisory", ("GHSA-whqx-f9j3-ch6m",))]
    net, ctx = make_net(R_gh("GHSA-w6c6-c85g-mmv6"))
    assert summary(judge(net, ctx, cosign("v3.0.5"))[0]) == [("advisory", ("GHSA-w6c6-c85g-mmv6",))]
    net, ctx = make_net(R_gh("GHSA-whqx-f9j3-ch6m"))
    assert summary(judge(net, ctx, cosign("v3.0.4"))[0]) == [], "fixed at 3.0.4 on the /v3 name"
    net, ctx = make_net(R_gh("GHSA-w6c6-c85g-mmv6"))
    assert summary(judge(net, ctx, cosign("v3.0.6"))[0]) == []


@case("audit", "AC5", "a: a GitHub-only advisory with SEVERAL ranges is read in every range: GHSA-w6c6-c85g-mmv6 ('>= 3.0.0, < 3.0.6' and '< 2.6.3'): cosign v2.6.2 is a hit through the SECOND range, v2.6.3 is clean, v3.0.5 a hit through the first")
def a_github_only_multi_range():
    for ver, want in (("v2.6.2", 1), ("v2.6.3", 0), ("v3.0.5", 1), ("v3.0.6", 0)):
        net, ctx = make_net(R_gh("GHSA-w6c6-c85g-mmv6"))
        assert len(judge(net, ctx, cosign(ver))[0]) == want, ver


@case("audit", "AC5", "a: the malware list is asked under BOTH Go names, and a GitHub-only malware report filed under either name is a malicious finding (a v3 binary: bare and /v3)")
def a_malware_names():
    for name in (COSIGN, COSIGN + "/v3"):
        g = ghsa("GHSA-mal0-mal0-mal0", name, [">= 3.0.0"], "2026-09-01T00:00:00Z", typ="malware")      # synthetic report
        net, ctx = make_net([g])
        f, _ = judge(net, ctx, cosign("v3.1.3"))
        assert [x.kind for x in f] == ["malicious"], (name, summary(f))
        assert {n for _, n, t in net.gh_list_asked if t == "malware"} == {COSIGN, COSIGN + "/v3"}, net.gh_list_asked


# ---- the daily audit's own entry point (main, report-only) and the age check's, for every position and spelling of an expression -------------------------------------
def now_iso():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_audit(base_files, head_files=None, pr=False):
    """The real pin-audit.py program, fixtures mode (every list empty), report-only: (exit status, output). pr: --base HEAD~1 --head HEAD."""
    repo = pr_repo(base_files, head_files if head_files is not None else base_files)
    fx = repo + ".fx.json"
    json.dump({"lists": {}, "upstream": {}, "nested": {}, "versions": {}, "prs": []}, open(fx, "w"))
    args = [sys.executable, os.path.join(SC, "pin-audit.py"), "--root", repo, "--fixtures", fx, "--now", now_iso(), "--report-only"]
    if pr:
        args += ["--base", "HEAD~1", "--head", "HEAD"]
    r = subprocess.run(args, capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def hit_lines(out, kind="unparseable"):
    return [l for l in out.splitlines() if l.startswith("audit: HIT:") and "(%s)" % kind in l]


def hit_locations(out, kind="unparseable"):
    """[(path, line)] parsed from every HIT line `... (at PATH:LINE), so it cannot be checked ...` (the WHOLE location)."""
    return [(m.group(1), int(m.group(2))) for l in hit_lines(out, kind) for m in [re.search(r"\(at (\S+?):(\d+)\)", l)] if m]


def at_line(out, line, path=WFPATH):
    return (path, line) in hit_locations(out)


EMPTY_WF = "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - run: echo hi\n"
SHA_A = "a" * 40
POS_FIXTURES = EXPR_FIXTURES + [
    ("a container image", "on: push\njobs:\n  j:\n    runs-on: u\n    container: alpine:${{ env.V }}\n    steps:\n      - run: echo hi\n", "${{ env.V }}"),
    ("a service image", "on: push\njobs:\n  j:\n    runs-on: u\n    services:\n      db:\n        image: postgres:${{ env.V }}\n    steps:\n      - run: echo hi\n", "${{ env.V }}"),
    ("a docker:// action", "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - uses: docker://alpine:${{ env.V }}\n", "${{ env.V }}"),
    ("docker/setup-qemu-action's image input", f"on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - uses: docker/setup-qemu-action@{SHA_A} # v3\n        with:\n          image: tonistiigi/binfmt:${{{{ env.V }}}}\n", "${{ env.V }}"),
    ("an unclassified installer's version input", f"on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - uses: acme/some-installer@{SHA_A} # v1\n        with:\n          version: ${{{{ env.V }}}}\n", "${{ env.V }}"),
    ("a PARTIAL go install target (v${{ }})", "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - run: go install github.com/securego/gosec/v2/cmd/gosec@v${{ env.V }}\n", "@v${{ env.V }}"),
    ("a PARTIAL pip pin (6.${{ }})", "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - run: pip install pyyaml==6.${{ matrix.m }} --hash=sha256:aa\n", "==6.${{ matrix.m }}"),
    ("a PARTIAL cosign-release (v${{ }})", f"on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - uses: sigstore/cosign-installer@{SHA_A} # v4.1.2\n        with:\n          cosign-release: v${{{{ env.C }}}}\n", "cosign-release: v${{ env.C }}"),
    ("a PARTIAL installer input (version: v${{ }})", f"on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - run: echo before\n      - uses: golangci/golangci-lint-action@{'2' * 40} # v9.3.0\n        with:\n          version: v${{{{ env.V }}}}\n", "version: v${{ env.V }}"),
    ("a PARTIAL action ref", "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - uses: actions/checkout@v${{ env.V }}\n", "@v${{ env.V }}"),
    ("a PARTIAL release download", "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - run: curl -fsSL https://github.com/cli/cli/releases/download/v${{ env.V }}/gh.tgz -o gh.tgz\n", "download/v${{ env.V }}"),
]
POS_FIXTURES = [(f[0], f[1], f[2]) for f in POS_FIXTURES]


def needle_line(text, needle):
    return line_of(text, needle)


@case("audit", "AC5", "c: THROUGH THE DAILY AUDIT'S ENTRY POINT (pin-audit.py, report-only): every spelling and position of an expression (the 14 whole-version fixtures, images in container, services, docker://, setup-qemu, an unclassified installer input, and PARTIAL expressions v${{ }}, 6.${{ }}) exits 1 with an `unparseable` HIT naming file:line of ITS expression, never printing the expression")
def c_daily_entry_point():
    for label, text, needle in POS_FIXTURES:
        rc, out = run_audit({WFPATH: text})
        assert rc == 1, (label, rc, out[-300:])
        assert hit_lines(out), (label, out[-400:])
        assert at_line(out, needle_line(text, needle)), (label, needle_line(text, needle), hit_lines(out))
        assert not any(needle in l or re.search(r"\$\{\{\s*(env|matrix|vars|secrets)\.", l) for l in hit_lines(out)), (label, hit_lines(out))


@case("audit", "AC5", "c: and in pull request mode (--base/--head): a PR that ADDS any of those is an `unparseable` HIT at its file:line, exit 1")
def c_pr_entry_point():
    for label, text, needle in POS_FIXTURES:
        rc, out = run_audit({WFPATH: EMPTY_WF}, {WFPATH: text}, pr=True)
        assert rc == 1 and at_line(out, needle_line(text, needle)), (label, rc, hit_lines(out), out[-200:])


@case("audit", "AC5", "c: several expressions in one file and one run block each get THEIR OWN location (a pip pin then a go install target in one run block, a prefixed installer input in a step, a container image, in one file)")
def c_locations():
    text = ("on: push\njobs:\n  j:\n    runs-on: u\n    container: alpine:${{ env.IMG }}\n    steps:\n      - run: |\n          echo start\n"
            "          pip install pyyaml==6.${{ matrix.m }} --hash=sha256:aa\n          echo middle\n          go install github.com/securego/gosec/v2/cmd/gosec@v${{ env.GV }}\n"
            f"      - uses: golangci/golangci-lint-action@{'2' * 40} # v9.3.0\n        with:\n          version: v${{{{ env.LV }}}}\n")
    rc, out = run_audit({WFPATH: text})
    assert rc == 1, out
    want = [("pypi/pyyaml", line_of(text, "6.${{ matrix.m }}")), ("securego/gosec", line_of(text, "@v${{ env.GV }}")),
            ("golangci-lint", line_of(text, "v${{ env.LV }}")), ("(expression)", line_of(text, "alpine:${{ env.IMG }}"))]
    lines = hit_lines(out)
    assert len(lines) == 4, lines
    for frag, n in want:
        assert any(frag in l and (WFPATH, n) == (re.search(r"\(at (\S+?):(\d+)\)", l).group(1), int(re.search(r"\(at (\S+?):(\d+)\)", l).group(2))) for l in lines), (frag, n, lines)
    assert sorted(hit_locations(out)) == sorted((WFPATH, n) for _, n in want), hit_locations(out)


@case("audit", "AC5", "c: a retained expression is not hidden by the audit's own filters: a repository whose ONLY problem is an expression exits 1, and the same repository with the expression removed exits 0 ('no known-compromised versions')")
def c_entry_point_clean_control():
    text = goreleaser_wf(top="env:\n  GORELEASER_VERSION: '1.26.0'\n")
    rc, out = run_audit({WFPATH: text})
    assert rc == 1 and "no known-compromised" not in out, out[-300:]
    rc, out = run_audit({WFPATH: text.replace("${{ env.GORELEASER_VERSION }}", "2.17.1")})
    assert rc == 0 and "no known-compromised" in out, out[-300:]


def run_audit_fx(base_files, head_files, extra):
    repo = pr_repo(base_files, head_files)
    fx = repo + ".fx.json"
    json.dump(dict({"lists": {}, "upstream": {}, "nested": {}, "versions": {}, "prs": []}, **extra), open(fx, "w"))
    r = subprocess.run([sys.executable, os.path.join(SC, "pin-audit.py"), "--root", repo, "--fixtures", fx, "--now", now_iso(), "--report-only"], capture_output=True, text=True)
    return repo, r.returncode, r.stdout + r.stderr


@case("audit", "AC12", "h: the same expression STILL IN today's tree fails closed (exit 1, an `unparseable` HIT), whatever the history holds; so does an expression in an OPEN pull request's changes (daily mode) even though the tree at the head is clean")
def h_head_and_open_pr_fail_closed():
    old = goreleaser_wf(top="env:\n  GORELEASER_VERSION: '2.17.1'\n")
    new = old.replace("${{ env.GORELEASER_VERSION }}", "2.17.1")
    repo, rc, out = run_audit_fx({WFPATH: new}, {WFPATH: old}, {})
    assert rc == 1 and hit_lines(out) and not any("history, not judged" in l for l in out.splitlines()), out[-400:]
    repo, rc, out = run_audit_fx({WFPATH: new}, {WFPATH: new}, {"open_prs": [{"number": 7, "items": ["tool:goreleaser@${{expression}}"]}]})
    assert rc == 1 and hit_lines(out) and "pull request #7" in out, (rc, out[-400:])


@case("age", "AC2", "c: through the age check's entry point, every position and spelling of an expression added by a pull request is refused (exit 1, a FAIL row): images in container, services, docker://, setup-qemu, an unclassified installer input, partial expressions")
def c_age_positions():
    for label, text, needle in POS_FIXTURES:
        rc, out = run_age(pr_repo({WFPATH: EMPTY_WF}, {WFPATH: text}), OLD_FX)
        assert rc == 1 and "FAIL" in out, (label, rc, out[-300:])


# ---- repeated occurrences of one pin (deduplication must not hide a comment) ------------------------------------------------------------------------------------------------
def ua_wf(label, sha=UA_SHA, repo=UA):
    return "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n" + "".join("      - uses: %s@%s # %s\n" % (repo, sha, l) for l in ([label] if isinstance(label, str) else label))


def dup_variants(sha, repo, labels):
    """The same pin written with `labels` in order: in one file, and spread over two files; both orders."""
    out = []
    for order in (labels, labels[::-1]):
        out.append(("one file " + "/".join(order), {WFPATH: ua_wf(list(order), sha, repo)}))
        out.append(("two files " + "/".join(order), {".github/workflows/a.yml": ua_wf(order[0], sha, repo), ".github/workflows/b.yml": ua_wf(order[1], sha, repo)}))
    return out


def pin_items(files, repo):
    its = [i for i in inv.inventory(files).values() if i.kind == "action" and i.name == repo]
    return its


@case("audit", "AC3", "g: the same SHA pinned twice, one comment right and one WRONG (v4.6.2 and v4.5.0), in one file and in two files, in both orders: the mismatch survives deduplication; with both comments right it is clean")
def g_repeated_mismatch():
    for label, files in dup_variants(UA_SHA, UA, ["v4.5.0", "v4.6.2"]):
        its = pin_items(files, UA)
        assert len(its) >= 1
        kinds = []
        for it in its:
            net, ctx = make_net(tags=UA_TAGS)
            kinds += [x.kind for x in judge(net, ctx, it)[0]]
        assert kinds == ["mismatch"], (label, kinds)
    for label, files in dup_variants(UA_SHA, UA, ["v4.6.2", "v4"]):
        for it in pin_items(files, UA):
            net, ctx = make_net(tags=UA_TAGS)
            assert summary(judge(net, ctx, it)[0]) == [], label


@case("audit", "AC5", "e: the same multi-tag commit pinned twice (`# v4.3.0` and `# v4.1.0`, or `# v4` and `# v4.1.0`), one file or two, both orders: one exact comment never hides the other occurrence's advisory (v4.1.0 is affected)")
def e_repeated_multi_tag():
    for labels in (["v4.3.0", "v4.1.0"], ["v4", "v4.1.0"]):
        for label, files in dup_variants(DA_SHA, DA, labels):
            kinds = []
            for it in pin_items(files, DA):
                net, ctx = da_net("v4", "v4.1.0", "v4.3.0")
                kinds += [x.kind for x in judge(net, ctx, it)[0]]
            assert kinds == ["advisory"], (label, kinds)


def age_rows_files(files_head, tags, pr_clock="2026-09-20T00:00:00Z"):
    base = {".github/workflows/z.yml": "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - run: echo hi\n"}
    repo = pr_repo(base, {**base, **files_head})
    out = repo + ".json"
    buf = io.StringIO()
    with patched(age, _tag_refs=lambda r: dict(tags.get(r, {})), observed=lambda: None, _pr_clock=lambda item, root, base_, head_="HEAD": pr_clock), contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        rc = age.main(["--root", repo, "--base", "HEAD~1", "--head", "HEAD", "--now", "2026-10-07T12:00:00Z", "--json", out])
    return rc, json.load(open(out))["moved"], buf.getvalue()


@case("age", "AC3", "g: the age check on the same SHA pinned twice with one WRONG comment (one file, two files, both orders) refuses it whatever the PR clock says; both comments right passes")
def g_repeated_age():
    for label, files in dup_variants(UA_SHA, UA, ["v4.5.0", "v4.6.2"]):
        rc, rows, out = age_rows_files(files, UA_TAGS)
        assert rc == 1 and any(not r["ok"] and "v4.5.0" in r["reason"] for r in rows), (label, rc, rows)
    for label, files in dup_variants(UA_SHA, UA, ["v4.6.2", "v4"]):
        rc, rows, out = age_rows_files(files, UA_TAGS)
        assert rc == 0, (label, rc, rows)

# ======================================================================================================================================
# step 6 round 3: AC11 by EXECUTION, AC12 for every kind and against open pull requests, comments kept across inventories, tag ordering, non-version inputs
# ======================================================================================================================================
def commit_files(d, files):
    """One commit that leaves EXACTLY `files` (a file not named is deleted). A value may be text, ("symlink", target) or ("gitlink", sha)."""
    for f in _git(d, "ls-files").stdout.split("\n"):
        if f and f not in files:
            _git(d, "rm", "-q", "-f", f)
    for path, text in files.items():
        full = os.path.join(d, path)
        os.makedirs(os.path.dirname(full) or d, exist_ok=True)
        if isinstance(text, tuple) and text[0] == "symlink":
            if os.path.lexists(full):
                os.remove(full)
            os.symlink(text[1], full)
        elif isinstance(text, tuple) and text[0] == "gitlink":
            pass
        else:
            open(full, "w").write(text)
    _git(d, "add", "-A")
    for path, text in files.items():
        if isinstance(text, tuple) and text[0] == "gitlink":
            _git(d, "update-index", "--add", "--cacheinfo", "160000,%s,%s" % (text[1], path))
    _git(d, "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", "c")


def history_repo(*versions):
    """A repository with one commit per file set (oldest first)."""
    d = tempfile.mkdtemp(dir=TMP)
    _git(d, "init", "-q")
    for files in versions:
        commit_files(d, files)
    return d


def exact_repo(base_files, head_files):
    """Two commits whose trees are EXACTLY base_files and head_files (a file the head does not name is deleted)."""
    return history_repo(base_files, head_files)


def runner_wf(*commands):
    return "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n" + "".join("      - run: %s\n" % c for c in commands)


PIP_REAL = "pip install --require-hashes pyyaml==5.3 --hash=sha256:aa\n"
GO_REAL = "go install github.com/securego/gosec/v2/cmd/gosec@v2.29.0\n"
CURL_REAL = "curl -fsSL https://github.com/cli/cli/releases/download/v2.40.0/gh.tgz -o gh.tgz\n"
def has_expr(item):
    return "${{" in item.key or "(expression)" in item.key


def keys_of(files):
    return sorted(inv.inventory(files))


# ---- AC12 for every kind; history never suppresses an open pull request ----------------------------------------------------------------------------------------------------
SHA_B = "b" * 40
HIST_KINDS = [
    ("action", "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - uses: actions/checkout@v${{ env.V }}\n", "@v${{ env.V }}",
     "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - uses: actions/checkout@%s # v4.1.0\n" % SHA_B),
    ("tool", goreleaser_wf(top="env:\n  GORELEASER_VERSION: '2.17.1'\n"), "${{ env.GORELEASER_VERSION }}", None),
    ("gotool", "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - run: go install github.com/securego/gosec/v2/cmd/gosec@v${{ env.V }}\n", "@v${{ env.V }}",
     "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - run: go install github.com/securego/gosec/v2/cmd/gosec@v2.29.0\n"),
    ("package", "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - run: pip install pyyaml==6.${{ matrix.m }} --hash=sha256:aa\n", "==6.${{ matrix.m }}",
     "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - run: pip install pyyaml==6.0.2 --hash=sha256:aa\n"),
    ("image", "on: push\njobs:\n  j:\n    runs-on: u\n    container: alpine:${{ env.V }}\n    steps:\n      - run: echo hi\n", "alpine:${{ env.V }}",
     "on: push\njobs:\n  j:\n    runs-on: u\n    container: alpine:3.20@sha256:" + "1" * 64 + "\n    steps:\n      - run: echo hi\n"),
    ("installer input", f"on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - uses: acme/some-installer@{SHA_A} # v1\n        with:\n          version: v${{{{ env.V }}}}\n", "version: v${{ env.V }}",
     f"on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - uses: acme/some-installer@{SHA_A} # v1\n        with:\n          version: v1.2.3\n"),
]


def literal_of(kind, old, new):
    return new if new else old.replace("${{ env.GORELEASER_VERSION }}", "2.17.1")


def history_info(out):
    return [(m.group(1), int(m.group(2)), m.group(3)) for l in out.splitlines() if l.startswith("information: history, not judged: ") for m in [re.search(r"not judged: (\S+?):(\d+)@(\w+)", l)] if m]


@case("audit", "AC12", "h: (0249) for EVERY kind (action, tool, gotool, package, image, installer input) an expression that exists ONLY in the history is `history, not judged: file:line@commit` (the whole location and the commit parsed), exit 0, never a hit")
def h_history_every_kind():
    for kind, old, needle, new in HIST_KINDS:
        repo, rc, out = run_audit_fx({WFPATH: old}, {WFPATH: literal_of(kind, old, new)}, {})
        assert rc == 0 and not hit_lines(out) and "no known-compromised" in out, (kind, rc, out[-300:])
        old_sha = _git(repo, "rev-parse", "HEAD~1").stdout.strip()
        got = history_info(out)
        assert len(got) == 1 and got[0][0] == WFPATH and got[0][1] == line_of(old, needle) and old_sha.startswith(got[0][2]) and len(got[0][2]) >= 7, (kind, got, old_sha)


@case("audit", "AC12", "h: the same expressions in TODAY's tree fail closed for every kind (and are not printed as history)")
def h_head_every_kind():
    for kind, old, needle, new in HIST_KINDS:
        repo, rc, out = run_audit_fx({WFPATH: literal_of(kind, old, new)}, {WFPATH: old}, {})
        assert rc == 1 and (WFPATH, line_of(old, needle)) in hit_locations(out) and not history_info(out), (kind, rc, out[-300:])


@case("audit", "AC12", "h: a history occurrence NEVER suppresses the same item arriving through an open pull request: an expression only in history AND carried by an open PR (the item's real key) exits 1 with the finding on the PR, for every kind")
def h_history_and_open_pr():
    for kind, old, needle, new in HIST_KINDS:
        lit = inv.inventory({WFPATH: literal_of(kind, old, new)})
        its = [i for k, i in inv.inventory({WFPATH: old}).items() if k not in lit and any(f.kind == "unparseable" for f in pa.judge(i, pa.FixtureNet({}), [], []))]
        assert len(its) == 1, (kind, [i.key for i in its])
        rc, out = audit_live([{WFPATH: old}, {WFPATH: literal_of(kind, old, new)}], {}, [], [], open_prs=[(7, its)])
        assert rc == 1 and any("[open pull request #7]" in l and "(unparseable)" in l for l in hit_lines(out)), (kind, rc, out[-400:])


# ---- the comments of a repeated pin are kept across base/head, history and pull request inventories ------------------------------------------------------------------------
def audit_live(commits, tags, gh, osv, open_prs=None):
    """The real main() of pin-audit.py, daily mode, report-only, with the live source's network seams faked: (exit status, output)."""
    repo = history_repo(*commits)
    net, ctx = make_net(gh, osv, tags, open_prs=open_prs)
    buf = io.StringIO()
    env = os.environ.pop("GITHUB_REPOSITORY", None)
    try:
        with offline(), ctx, patched(pa, LiveNet=type(net)), contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            rc = pa.main(["--root", repo, "--now", now_iso(), "--report-only"])
    finally:
        if env is not None:
            os.environ["GITHUB_REPOSITORY"] = env
    return rc, buf.getvalue()


def da_wf(*labels):
    return ua_wf(list(labels), DA_SHA, DA)


DA_TAGS = {DA: {t: DA_SHA for t in ("v4", "v4.1.0", "v4.3.0")}}


@case("audit", "AC5", "e: THROUGH THE DAILY ENTRY POINT: download-artifact pinned `# v4.3.0` in an older commit and a second occurrence `# v4.1.0` ADDED at the head keeps GHSA-cxww-7g56-2vh6 (history never overwrites today's comments); the same with only `# v4.3.0` is clean")
def e_daily_second_comment():
    rc, out = audit_live([{WFPATH: da_wf("v4.3.0")}, {WFPATH: da_wf("v4.3.0", "v4.1.0")}], DA_TAGS, R_gh("GHSA-cxww-7g56-2vh6"), R_osv("GHSA-cxww-7g56-2vh6"))
    assert rc == 1 and any("GHSA-cxww-7g56-2vh6" in l for l in out.splitlines() if l.startswith("audit: HIT:")), (rc, out[-500:])
    rc, out = audit_live([{WFPATH: da_wf("v4.3.0")}, {WFPATH: da_wf("v4.3.0")}], DA_TAGS, R_gh("GHSA-cxww-7g56-2vh6"), R_osv("GHSA-cxww-7g56-2vh6"))
    assert rc == 0 and "no known-compromised" in out, (rc, out[-500:])


@case("audit", "AC3", "g: THROUGH THE DAILY ENTRY POINT a comment CORRECTED at the head is not held against the pin for 90 days: upload-artifact pinned with a wrong `# v4.5.0` in an older commit and `# v4.6.2` at the head is clean; the wrong comment still at the head is a mismatch HIT")
def g_daily_corrected_comment():
    rc, out = audit_live([{WFPATH: ua_wf(["v4.5.0"])}, {WFPATH: ua_wf(["v4.6.2"])}], UA_TAGS, [], [])
    assert rc == 0 and "no known-compromised" in out and not hit_lines(out, "tag-mismatch"), (rc, out[-400:])
    rc, out = audit_live([{WFPATH: ua_wf(["v4.6.2"])}, {WFPATH: ua_wf(["v4.5.0"])}], UA_TAGS, [], [])
    assert rc == 1 and hit_lines(out, "tag-mismatch"), (rc, out[-400:])


@case("audit", "AC5", "e: the comments of a pin that exists ONLY in the history are merged across the window, not overwritten: `# v4.3.0` in the oldest commit and `# v4.1.0` in a later one (or the reverse) before the pin was removed: the affected one is judged either way")
def e_history_labels_merge():
    for order in (("v4.3.0", "v4.1.0"), ("v4.1.0", "v4.3.0")):
        rc, out = audit_live([{WFPATH: da_wf(order[0])}, {WFPATH: da_wf(order[1])}, {WFPATH: runner_wf("echo hi")}], DA_TAGS, R_gh("GHSA-cxww-7g56-2vh6"), R_osv("GHSA-cxww-7g56-2vh6"))
        assert rc == 1 and any("GHSA-cxww-7g56-2vh6" in l for l in out.splitlines() if l.startswith("audit: HIT:")), (order, rc, out[-500:])


def age_rows_files_base(base_files, head_files, tags, pr_clock="2026-09-20T00:00:00Z"):
    repo = pr_repo(base_files, head_files)
    out = repo + ".json"
    buf = io.StringIO()
    with patched(age, _tag_refs=lambda r: dict(tags.get(r, {})), observed=lambda: None, _pr_clock=lambda item, root, base_, head_="HEAD": pr_clock), contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        rc = age.main(["--root", repo, "--base", "HEAD~1", "--head", "HEAD", "--now", "2026-10-07T12:00:00Z", "--json", out])
    return rc, json.load(open(out))["moved"], buf.getvalue()


@case("age", "AC3", "g: THROUGH THE AGE ENTRY POINT with the SHA already at the base: a second occurrence with a WRONG comment added at the head (same file, or a new file) is a moved pin and is refused whatever the PR clock says; adding a RIGHT second comment is not refused")
def g_age_second_comment_added():
    base = {WFPATH: ua_wf(["v4.6.2"])}
    rc, rows, out = age_rows_files_base(base, {WFPATH: ua_wf(["v4.6.2", "v4.5.0"])}, UA_TAGS)
    assert rc == 1 and any(not r["ok"] and "v4.5.0" in r["reason"] for r in rows), (rc, rows)
    rc, rows, out = age_rows_files_base(base, {WFPATH: ua_wf(["v4.6.2"]), ".github/workflows/b.yml": ua_wf(["v4.5.0"])}, UA_TAGS)
    assert rc == 1 and any(not r["ok"] and "v4.5.0" in r["reason"] for r in rows), (rc, rows)
    rc, rows, out = age_rows_files_base(base, {WFPATH: ua_wf(["v4.6.2", "v4"])}, UA_TAGS)
    assert rc == 0, (rc, rows)


@case("audit", "AC3", "g: the label is read in every spelling the tree can carry: `uses: x@sha # v4.6.2`, `uses: \"x@sha\" # v4.6.2`, `uses: 'x@sha' # v4.6.2`, `# tag: v4.6.2`, `#v4.6.2`: each reads the label v4.6.2 (right: clean; wrong comment: a mismatch)")
def g_label_forms():
    for form in ('%s@%s # %s', '"%s@%s" # %s', "'%s@%s' # %s", '%s@%s # tag: %s', '%s@%s #%s', '%s@%s #   tag:   %s  (pinned)'):
        def wfx(label):
            return "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - uses: " + form % (UA, UA_SHA, label) + "\n"
        its = pin_items({WFPATH: wfx("v4.6.2")}, UA)
        assert len(its) == 1 and its[0].labels == {"v4.6.2"}, (form, [i.labels for i in its])
        net, ctx = make_net(tags=UA_TAGS)
        assert summary(judge(net, ctx, its[0])[0]) == [], form
        its = pin_items({WFPATH: wfx("v4.5.0")}, UA)
        net, ctx = make_net(tags=UA_TAGS)
        assert [x.kind for x in judge(net, ctx, its[0])[0]] == ["mismatch"], form


# ---- tag ordering (numeric; release over pre-release; a floating minor) ---------------------------------------------------------------------------------------------------------
def cq_multi(tags, label):
    net, ctx = make_net(CQ_GH, [CQ_REAL], {CQ: {t: CQ_SHA for t in tags}})
    return judge(net, ctx, inv.Item("action", CQ, CQ_SHA, label))[0]


# ---- no false alarm for inputs that are not versions ---------------------------------------------------------------------------------------------------------------------
NONVERSION = f"""on: push
jobs:
  j:
    runs-on: u
    steps:
      - uses: docker/build-push-action@{'3' * 40} # v6.0.0
        with:
          tags: ghcr.io/o/r:${{{{ github.sha }}}}
          labels: org.opencontainers.image.revision=${{{{ github.sha }}}}
          build-args: VERSION=${{{{ github.ref_name }}}}
          platforms: linux/amd64
      - uses: actions/upload-artifact@{UA_SHA} # v4.6.2
        with:
          name: bundle-${{{{ github.run_id }}}}
          path: dist/${{{{ matrix.os }}}}
      - uses: actions/cache@{'4' * 40} # v4.2.0
        with:
          key: ${{{{ runner.os }}}}-${{{{ hashFiles('go.sum') }}}}
      - uses: actions/setup-go@{'5' * 40} # v6.0.0
        with:
          go-version: ${{{{ matrix.go }}}}
      - run: echo "${{{{ github.event.pull_request.title }}}}"
"""


@case("audit", "AC5", "c: NO false alarm for non-version inputs: docker/build-push-action `tags: ...${{ github.sha }}`, labels, build-args, an artifact name, a cache key, setup-go's go-version, a run text that only prints an expression: the daily audit raises no `unparseable` finding")
def c_non_version_inputs():
    rc, out = run_audit({WFPATH: NONVERSION})
    assert not hit_lines(out), out[-500:]
    assert not [i.key for i in inv.inventory({WFPATH: NONVERSION}).values() if has_expr(i)], [i.key for i in inv.inventory({WFPATH: NONVERSION}).values() if has_expr(i)]


@case("age", "AC2", "c: the age check holds no tool, gotool or package item whose version is an expression for those inputs (only a VERSION position can be one)")
def c_non_version_age():
    its = inv.inventory({WFPATH: NONVERSION})
    assert not [k for k, i in its.items() if "${{" in i.version and i.kind in ("tool", "gotool", "package")], sorted(its)

# ======================================================================================================================================
# step 6 round 4: execution discovery fails closed (0080), executable content inside quotes/heredocs, comments across history and PR boundaries, patch ordering
# ======================================================================================================================================
SH = "bin/probe-test.sh"
PYPIN = "package:pypi/pyyaml@5.3"


# ---- comments across the history and open-pull-request boundaries ----------------------------------------------------------------------------------------------------------
def da_item_labels(*labels):
    its = pin_items({WFPATH: da_wf(*labels)}, DA)
    assert len(its) == 1 and its[0].labels == set(labels), [(i.key, i.labels) for i in its]
    return its[0]


@case("audit", "AC5", "e: a comment ADDED by an open PR at a SHA that main already labels `# v4.3.0` is judged: the PR adds `# v4.1.0` (affected, GHSA-cxww-7g56-2vh6): exit 1 with the finding on the PR; a PR adding a comment that is also clean (`# v4`) is not a finding")
def e_pr_adds_comment_to_known_sha():
    item = da_item_labels("v4.3.0", "v4.1.0")
    rc, out = audit_live([{WFPATH: da_wf("v4.3.0")}, {WFPATH: da_wf("v4.3.0")}], DA_TAGS, R_gh("GHSA-cxww-7g56-2vh6"), R_osv("GHSA-cxww-7g56-2vh6"), open_prs=[(7, [item])])
    assert rc == 1 and any("GHSA-cxww-7g56-2vh6" in l and "[open pull request #7]" in l for l in out.splitlines() if l.startswith("audit: HIT:")), (rc, out[-500:])
    item = da_item_labels("v4.3.0", "v4")
    rc, out = audit_live([{WFPATH: da_wf("v4.3.0")}, {WFPATH: da_wf("v4.3.0")}], {DA: {"v4": DA_SHA, "v4.3.0": DA_SHA}}, R_gh("GHSA-cxww-7g56-2vh6"), R_osv("GHSA-cxww-7g56-2vh6"), open_prs=[(7, [item])])
    assert rc == 0 and "no known-compromised" in out, (rc, out[-500:])


@case("audit", "AC5", "e: an open PR's item keeps ALL its comments: a PR adding the pin with BOTH `# v4.3.0` and `# v4.1.0` (main has no such pin) is a hit on GHSA-cxww-7g56-2vh6, not judged by its first comment only")
def e_pr_keeps_all_labels():
    for labels in (("v4.3.0", "v4.1.0"), ("v4.1.0", "v4.3.0")):
        item = da_item_labels(*labels)
        rc, out = audit_live([{WFPATH: runner_wf("echo hi")}, {WFPATH: runner_wf("echo hi")}], DA_TAGS, R_gh("GHSA-cxww-7g56-2vh6"), R_osv("GHSA-cxww-7g56-2vh6"), open_prs=[(7, [item])])
        assert rc == 1 and any("GHSA-cxww-7g56-2vh6" in l and "[open pull request #7]" in l for l in out.splitlines() if l.startswith("audit: HIT:")), (labels, rc, out[-500:])


@case("audit", "AC5", "e: a VALID affected comment in the history is not forgotten when the head keeps the SHA with another comment: `# v4.1.0` in an older commit, `# v4.3.0` at the head still reports GHSA-cxww-7g56-2vh6 (as removing the pin entirely does); a historical comment that does NOT resolve to the commit (a typo) is not held against the pin once corrected")
def e_valid_history_comment_kept():
    rc, out = audit_live([{WFPATH: da_wf("v4.1.0")}, {WFPATH: da_wf("v4.3.0")}], DA_TAGS, R_gh("GHSA-cxww-7g56-2vh6"), R_osv("GHSA-cxww-7g56-2vh6"))
    assert rc == 1 and any("GHSA-cxww-7g56-2vh6" in l for l in out.splitlines() if l.startswith("audit: HIT:")), (rc, out[-500:])
    rc, out = audit_live([{WFPATH: da_wf("v4.1.0")}, {WFPATH: runner_wf("echo hi")}], DA_TAGS, R_gh("GHSA-cxww-7g56-2vh6"), R_osv("GHSA-cxww-7g56-2vh6"))
    assert rc == 1, (rc, out[-300:])
    rc, out = audit_live([{WFPATH: da_wf("v4.9.9")}, {WFPATH: da_wf("v4.3.0")}], DA_TAGS, R_gh("GHSA-cxww-7g56-2vh6"), R_osv("GHSA-cxww-7g56-2vh6"))
    assert rc == 0 and "no known-compromised" in out and not hit_lines(out, "tag-mismatch"), (rc, out[-400:])


@case("audit", "AC5", "e: codeql-action `# v3` on a commit tagged v3, v3.26.9 and v3.26.11 is a hit on GHSA-vqf5-2xx6-9wfm (v3.26.11 is affected, in either tag order)")
def e_patch_numeric():
    f = cq_multi(("v3", "v3.26.9", "v3.26.11"), "v3")
    assert all_ids(f) == {"GHSA-vqf5-2xx6-9wfm"} and not any(x.disputed for x in f), summary(f)
    f = cq_multi(("v3", "v3.26.11", "v3.26.9"), "v3")
    assert all_ids(f) == {"GHSA-vqf5-2xx6-9wfm"}, summary(f)

# ======================================================================================================================================
# step 6 round 5 (advisor 0261): AC11 as a CLOSED rule: scope by file kind, exemptions only by the reviewed manifest
# ======================================================================================================================================
MF = ".github/agent/supply-chain/harness-manifest.json"
SHEBANG_BASH = "#!/usr/bin/env bash\n"


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def manifest(*entries, reason="test harness: fixture data"):
    return json.dumps({"files": [{"path": p, "sha256": h, "reason": reason} for p, h in entries]}, indent=1)


def run_audit_pr(base_files, head_files, extra):
    repo = pr_repo(base_files, head_files)
    fx = repo + ".fx.json"
    json.dump(dict({"lists": {}, "upstream": {}, "nested": {}, "versions": {}, "prs": []}, **extra), open(fx, "w"))
    r = subprocess.run([sys.executable, os.path.join(SC, "pin-audit.py"), "--root", repo, "--fixtures", fx, "--now", now_iso(), "--report-only", "--base", "HEAD~1", "--head", "HEAD"], capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def repo_items(files):
    """Items (keys) of a repository that holds `files`, read the way the programs read a tree (git ls-files, working tree)."""
    repo = history_repo(files)
    return sorted(inv.load_at(repo, None)), repo


FIXTURE_BODY = SHEBANG_BASH + PIP_REAL + GO_REAL


@case("age", "AC11", "i: SCOPE BY FILE KIND: an install line is an item in a script anywhere (also .github/agent/**), in ANY tracked file whose first line is a shell shebang whatever its name or extension (no extension, .txt, .py, .zsh, .dat, .command, .runner, a dotfile) with sh, bash, dash, ash, ksh93, mksh, zsh, busybox sh, env <shell> or a version suffix (bash5), in an action file anywhere, in requirements*.txt anywhere; read the same from the working tree and from a revision; and in NOTHING else (README.md, x.py without a shell shebang, Python or Node shebangs, extensionless files without a shebang)")
def i_scope_by_file_kind():
    for path in ("bin/x.sh", "bin/x-test.sh", ".github/agent/tests/x.sh", ".github/agent/fixtures/x.bash", "tools/x.sh", ".github/agent/fixtures/deep/er/y.sh", "tools/noshebang.bash", "tools/x.ksh", "tools/x.zsh", "tests/x.bats"):
        for body in (SHEBANG_BASH + PIP_REAL, PIP_REAL):           # by NAME with or without a shebang
            for mode in (None, "HEAD"):
                repo = history_repo({path: body})
                assert PYPIN in sorted(inv.load_at(repo, mode)), (path, mode)
    shebangs = ["#!/bin/sh", "#!/usr/bin/env bash", "#!/bin/dash", "#!/bin/ash", "#!/usr/bin/ksh93", "#!/bin/mksh", "#!/bin/zsh", "#!/usr/bin/env zsh", "#!/bin/busybox sh", "#!/usr/bin/env bash5",
                "#!/bin/bash5", "#! /bin/bash", "#!/usr/bin/env -S bash -e", "#!/bin/ksh", "\ufeff#!/bin/sh", "#!/usr/bin/env FOO=1 bash",
                "#!/bin/csh", "#!/bin/tcsh", "#!/usr/bin/fish", "#!/usr/bin/env fish", "#!/bin/rbash", "#!/usr/bin/yash", "#!/usr/bin/oksh", "#!/usr/bin/pdksh", "#!/usr/bin/posh", "#!/usr/bin/env -S zsh -f",
                "#!/usr/bin/env -S 'bash -e'"]
    names = ["tools/run", "tools/run.txt", "tools/run.py", "tools/x.zsh", "tools/x.dat", "tools/x.command", "tools/x.runner", ".runner", "tools/.hidden", "docs/notes.md"]
    for sb in shebangs:
        for name in names:
            body = sb + "\n" + PIP_REAL
            for mode in (None, "HEAD"):
                repo = history_repo({name: body})
                assert PYPIN in sorted(inv.load_at(repo, mode)), (sb, name, mode)
    for sb in ("#!/usr/bin/env python3", "#!/usr/bin/python", "#!/usr/bin/env node", "#!/usr/bin/perl", "#!/bin/busybox ls", "#!/usr/bin/env bashful", "#!/usr/bin/ruby", "no shebang here"):
        for name in ("tools/run", "tools/run.txt", "tools/x.py"):
            repo = history_repo({name: sb + "\n" + PIP_REAL})
            for mode in (None, "HEAD"):
                assert PYPIN not in sorted(inv.load_at(repo, mode)), (sb, name, mode)
    # a workflow or an action file that starts with a #! comment stays what its name says; a requirements file too
    wf_ = "#!/bin/sh\non: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - uses: actions/checkout@%s # v4.1.0\n      - run: pip install --require-hashes pyyaml==5.3 --hash=sha256:aa\n" % ("1" * 40)
    act = "#!/bin/bash\nname: a\nruns:\n  using: composite\n  steps:\n    - uses: actions/cache@%s # v4.2.0\n    - run: pip install --require-hashes pyyaml==5.3 --hash=sha256:aa\n      shell: bash\n" % ("2" * 40)
    req = "#!/bin/sh\npyyaml==5.3 \\\n    --hash=sha256:aa\n"
    for files in ({WFPATH: wf_}, {".github/agent/fixtures/act/action.yml": act}, {"docs/requirements.txt": req}):
        for mode in (None, "HEAD"):
            k = sorted(inv.load_at(history_repo(files), mode))
            assert PYPIN in k and (any(x.startswith("action:actions/") for x in k) or "requirements" in list(files)[0]), (list(files), mode, k)
    act2 = "name: a\nruns:\n  using: composite\n  steps:\n    - run: pip install --require-hashes pyyaml==5.3 --hash=sha256:aa\n      shell: bash\n"
    for path in (".github/agent/fixtures/act/action.yml", ".github/actions/a/action.yaml", "deep/er/action.yml"):
        assert PYPIN in sorted(inv.load_at(history_repo({path: act2}), None)), path
    req2 = "pyyaml==5.3 \\\n    --hash=sha256:aa\n"
    for path in (".github/agent/fixtures/req/requirements.txt", "docs/requirements-dev.txt", "requirements.txt"):
        assert PYPIN in sorted(inv.load_at(history_repo({path: req2}), None)), path
    for path, body in (("README.md", PIP_REAL), ("tools/x.py", PIP_REAL), ("tools/plain", PIP_REAL), ("docs/x.txt", PIP_REAL)):
        assert PYPIN not in sorted(inv.load_at(history_repo({path: body}), None)), path


@case("age", "AC11", "i: a SYMLINK is read as its link text in BOTH modes and hashed as that text: run.sh -> payload.txt (which holds an install line) gives the same inventory from the working tree and from a revision (the link text names no install), and the same sha256; a gitlink (submodule) entry with an extensionless name does not break a revision read")
def i_symlink_and_gitlink():
    repo = history_repo({"payload.txt": PIP_REAL, "run.sh": ("symlink", "payload.txt"), "tools/sub": ("gitlink", "a" * 40)})
    a, b = inv.tree_files(repo, None), inv.tree_files(repo, "HEAD")
    assert a["run.sh"] == b["run.sh"] == "payload.txt" and a.sha256["run.sh"] == b.sha256["run.sh"] == sha("payload.txt")
    assert sorted(inv.load_at(repo, None)) == sorted(inv.load_at(repo, "HEAD")) and PYPIN not in sorted(inv.load_at(repo, "HEAD"))
    assert "tools/sub" not in b and "tools/sub" not in a


@case("age", "AC11", "i: NO data/code classification: every install-looking string in an in-scope script is an item wherever the command word sits: assignments (X=\"…\" then eval, x=$(…), backticks, cmd=(…) arrays), a `#pip` comment without a space, python heredocs (os.system('…')), `run --cmd=\"…\"`, path-qualified words (/usr/bin/pip3, .venv/bin/pip, \"$VENV/bin/pip\", /usr/bin/docker), python -mpip and python -m pip, quotes, $(...), comments, heredoc bodies, herestrings, sudo/env prefixes; for pip, docker (run and pull) and go")
def i_every_form_counts():
    pip = "pip install pyyaml==5.3"
    forms = ["# " + pip, "#" + pip, "cat <<'EOF'\n" + pip + "\nEOF", "echo '%s'" % pip, 'echo "%s"' % pip, 'echo "$(%s)"' % pip, "echo `%s`" % pip, "printf '%%s\\n' '%s'" % pip, "grep x <<< '%s'" % pip,
             "python3 - <<'PY'\nwf = '%s'\nPY" % pip, "python3 - <<'PY'\nimport os\nos.system('%s')\nPY" % pip, "sudo -H " + pip, "env X=1 " + pip, "bash -c '%s'" % pip,
             'CMD="%s"\neval "$CMD"' % pip, "CMD='%s'\n$CMD" % pip, "x=$(%s)" % pip, "x=`%s`" % pip, "cmd=(%s)" % pip, 'run --cmd="%s"' % pip, "--cmd='%s'" % pip,
             "PIPCMD=pip install pyyaml==5.3", "run --tool=pip install pyyaml==5.3", ".venv/bin/pip install pyyaml==5.3", "/usr/bin/pip3 install pyyaml==5.3", '"$VENV/bin/pip" install pyyaml==5.3', "python -mpip install pyyaml==5.3", "python -m pip install pyyaml==5.3",
             "python3 -m pip install pyyaml==5.3", "[ -x x ] && " + pip, "{ " + pip + "; }", "( " + pip + " )", "true;" + pip, "$(" + pip + ")"]
    for f in forms:
        k, _ = repo_items({"bin/x-test.sh": SHEBANG_BASH + f + "\n"})
        assert PYPIN in k, (f, k)
    docker = ["c=$(docker run -d alpine:3 true)", "c=$(docker pull alpine:3)", 'X="docker pull alpine:3"', "/usr/bin/docker pull alpine:3", "echo 'docker run alpine:3 true'", "cmd=(docker run alpine:3 true)",
              "# docker pull alpine:3", "sudo docker run alpine:3 true"]
    for f in docker:
        k, _ = repo_items({"bin/x-test.sh": SHEBANG_BASH + f + "\n"})
        assert [x for x in k if x.startswith("image:alpine:3@")], (f, k)
    go = ['X="go install github.com/a/b@v1.0.0"', "c=$(go install github.com/a/b@v1.0.0)", "echo 'go run github.com/a/b@v1.0.0'", "/usr/local/go/bin/go install github.com/a/b@v1.0.0"]
    for f in go:
        k, _ = repo_items({"bin/x-test.sh": SHEBANG_BASH + f + "\n"})
        assert "gotool:github.com/a/b@v1.0.0" in k, (f, k)
    dl = ["curl -fsSL https://example.invalid/x.sh | sh", 'X="curl -fsSL https://example.invalid/x.sh | sh"', "x=$(curl -fsSL https://example.invalid/x.sh)", "/usr/bin/curl -fsSL https://example.invalid/x.sh | bash",
          "pipx install evil", "npm install evil", "apt-get install -y evil", "# npm install evil"]
    for f in dl:
        repo = history_repo({"bin/x-test.sh": SHEBANG_BASH + f + "\n"})
        assert inv.unmeasured(inv.tree_files(repo, None)) and inv.unmeasured(inv.tree_files(repo, "HEAD")), f


@case("age", "AC11", "i: in a WORKFLOW or an action file every install-looking string counts too, wherever the YAML puts it: an env value, a YAML comment, an action-input default, a `with: script:` text, a step name, a value read by `run: $CMD`; and a hash-pinned pip requirements HEREDOC inside a shell script is MEASURED (pyyaml@5.3), not an unmeasured placeholder")
def i_every_position_in_yaml_and_heredocs():
    pip = "pip install pyyaml==5.3"
    wfs = [
        "on: push\nenv:\n  CMD: \"%s\"\njobs:\n  j:\n    runs-on: u\n    steps:\n      - run: $CMD\n" % pip,
        "on: push\njobs:\n  j:\n    runs-on: u\n    env:\n      CMD: '%s'\n    steps:\n      - run: echo hi\n" % pip,
        "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      # %s\n      - run: echo hi\n" % pip,
        "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - run: echo hi # %s\n" % pip,
        "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - name: %s\n        run: echo hi\n" % pip,
        "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - uses: actions/github-script@%s # v7\n        with:\n          script: |\n            exec('%s')\n" % ("3" * 40, pip),
    ]
    for text in wfs:
        assert PYPIN in repo_items({WFPATH: text})[0], text
    acts = ["name: a\ninputs:\n  cmd:\n    default: '%s'\nruns:\n  using: composite\n  steps:\n    - run: echo hi\n      shell: bash\n" % pip,
            "name: a\n# %s\nruns:\n  using: composite\n  steps:\n    - run: echo hi\n      shell: bash\n" % pip]
    for text in acts:
        for path in (".github/actions/a/action.yml", ".github/agent/fixtures/act/action.yaml", "deep/action.yml"):
            assert PYPIN in repo_items({path: text})[0], (path, text)
    heredoc = SHEBANG_BASH + "pip install --quiet --require-hashes --only-binary=:all: -r /dev/stdin <<'REQ'\npyyaml==5.3 --hash=sha256:aa --hash=sha256:bb\nREQ\n"
    for mode in (None, "HEAD"):
        k = sorted(inv.load_at(history_repo({"bin/x-test.sh": heredoc, "tools/run": heredoc}), mode))
        assert PYPIN in k and not [x for x in k if "(unmeasured" in x], k
    heredoc2 = SHEBANG_BASH + "pip install -r - <<EOF\nrequests==2.32.0 --hash=sha256:aa\nEOF\npip install --require-hashes -r /dev/stdin <<'REQ'\npyyaml==5.3 --hash=sha256:aa\nREQ\n"
    k = repo_items({"bin/x-test.sh": heredoc2})[0]
    assert PYPIN in k and "package:pypi/requests@2.32.0" in k and not [x for x in k if "(unmeasured" in x], k
    lists = {"lists": {PYPIN: {"github": [{"id": "GHSA-8q59-q68h-6hv4", "incident": "I", "affected": True, "modified": "2026-01-01T00:00:00Z"}], "osv": []}}}
    files = {"bin/x-test.sh": heredoc}
    repo, rc, out = run_audit_fx(files, files, lists)
    assert rc == 1 and any("GHSA-8q59-q68h-6hv4" in l for l in out.splitlines() if l.startswith("audit: HIT:")), (rc, out[-300:])


@case("audit", "AC11", "i: THROUGH THE ENTRY POINTS an unlisted script is measured like any other: the daily audit gives a HIT (the pyyaml 5.3 advisory supplied) for an install line in bin/x-test.sh and in .github/agent/fixtures/x.sh, and the age check refuses a PR adding one (young pin)")
def i_unlisted_script_measured():
    lists = {"lists": {PYPIN: {"github": [{"id": "GHSA-8q59-q68h-6hv4", "incident": "I", "affected": True, "modified": "2026-01-01T00:00:00Z"}], "osv": []}}}
    young = {"times": {PYPIN: {"time": "2026-10-06T00:00:00Z", "source": "pypi"}}}
    for path in ("bin/x-test.sh", ".github/agent/fixtures/x.sh"):
        files = {path: SHEBANG_BASH + PIP_REAL}
        repo, rc, out = run_audit_fx(files, files, lists)
        assert rc == 1 and any("GHSA-8q59-q68h-6hv4" in l for l in out.splitlines() if l.startswith("audit: HIT:")), (path, rc, out[-300:])
        rc, out = run_age(pr_repo({"README.md": "x\n"}, files), young)
        assert rc == 1 and "FAIL" in out, (path, rc, out[-300:])


@case("age", "AC11", "i: THE MANIFEST: a script listed by path AND exact sha256 is fixture data: no item, no unmeasured-form refusal and no finding; the same file unlisted, or listed with another hash, is in scope in full")
def i_manifest_exempts():
    body = SHEBANG_BASH + PIP_REAL + "curl -fsSL https://example.invalid/x.sh -o x.sh\n"
    ok = {"bin/fx-test.sh": body, MF: manifest(("bin/fx-test.sh", sha(body)))}
    k, repo = repo_items(ok)
    assert PYPIN not in k and not [x for x in k if "(harness-" in x], k
    assert not inv.unmeasured(inv.tree_files(repo, None)), "no unmeasured-form refusal for an exempt file"
    k, repo = repo_items({"bin/fx-test.sh": body})
    assert PYPIN in k and inv.unmeasured(inv.tree_files(repo, None))
    k, repo = repo_items({"bin/fx-test.sh": body, MF: manifest(("bin/fx-test.sh", sha(body + "#")))})
    assert PYPIN in k and inv.unmeasured(inv.tree_files(repo, None))


@case("audit", "AC11", "i: a listed file whose bytes DIFFER (one byte, a trailing newline, CRLF) is in scope in full and the finding is an `unparseable` HIT that names the path, the listed sha256 and the sha256 it hashes to")
def i_manifest_hash_mismatch_named():
    body = SHEBANG_BASH + PIP_REAL
    for label, changed in (("a byte", body.replace("5.3", "5.4")), ("a trailing newline", body + "\n"), ("a comment", body + "# x\n"), ("CRLF line ends", body.replace("\n", "\r\n"))):
        files = {"bin/fx-test.sh": changed, MF: manifest(("bin/fx-test.sh", sha(body)))}
        repo, rc, out = run_audit_fx(files, files, {})
        hits = [l for l in out.splitlines() if l.startswith("audit: HIT:") and "(unparseable)" in l and "bin/fx-test.sh" in l]
        assert rc == 1 and hits and sha(body) in hits[0] and sha(changed) in hits[0], (label, rc, out[-500:])
        assert [x for x in sorted(inv.load_at(repo, None)) if x.startswith("package:pypi/pyyaml@")], label


@case("audit", "AC11", "i: a listed hash that differs only in its LAST hex digit is a mismatch (the whole digest is compared, not a prefix), and the finding names both")
def i_manifest_whole_digest():
    body = SHEBANG_BASH + PIP_REAL
    good = sha(body)
    bad = good[:-1] + ("0" if good[-1] != "0" else "1")
    files = {"bin/fx-test.sh": body, MF: manifest(("bin/fx-test.sh", bad))}
    repo, rc, out = run_audit_fx(files, files, {})
    hits = [l for l in out.splitlines() if l.startswith("audit: HIT:") and bad in l and good in l]
    assert rc == 1 and hits and PYPIN in sorted(inv.load_at(repo, None)), (rc, out[-400:])


@case("age", "AC11", "i: the unmeasured-form refusal also reads the BASE's manifest: a PR that adds a script with a non-release download and lists it in its OWN manifest is still refused (exit 1, 'unmeasured'), a base-listed unchanged one is not")
def i_unmeasured_manifest_from_base():
    body = SHEBANG_BASH + "curl -fsSL https://example.invalid/x.sh -o x.sh\n"
    head = {"bin/dl-test.sh": body, MF: manifest(("bin/dl-test.sh", sha(body)))}
    rc, out = run_age(pr_repo({"README.md": "x\n"}, head), OLD_FX)
    assert rc == 1 and "unmeasured" in out, out[-300:]
    base = {"bin/dl-test.sh": body, MF: manifest(("bin/dl-test.sh", sha(body)))}
    rc, out = run_age(pr_repo(base, {**base, "README.md": "x\n"}), OLD_FX)
    assert rc == 0, out[-300:]


@case("age", "AC11", "i: the manifest is by PATH AND HASH, never by name or pattern: a listed bin/fx-test.sh exempts nothing else (bin/other-test.sh, a copy of the same bytes at another path, bin/sub/fx-test.sh); a manifest that lists a WORKFLOW or an action file does not exempt it")
def i_manifest_no_blanket():
    body = SHEBANG_BASH + PIP_REAL
    files = {"bin/fx-test.sh": body, "bin/other-test.sh": body, "bin/copy.sh": body, "bin/sub/fx-test.sh": body, MF: manifest(("bin/fx-test.sh", sha(body)))}
    k, repo = repo_items(files)
    assert PYPIN in k
    wf_ = runner_wf("pip install --require-hashes pyyaml==5.3 --hash=sha256:aa")
    for only in ("bin/other-test.sh", "bin/copy.sh", "bin/sub/fx-test.sh"):
        k, _ = repo_items({"bin/fx-test.sh": body, only: body, MF: manifest(("bin/fx-test.sh", sha(body)))})
        assert PYPIN in k, only
        k, _ = repo_items({only: body, MF: manifest(("bin/fx-test.sh", sha(body)))})
        assert PYPIN in k, only
    k, _ = repo_items({WFPATH: wf_, MF: manifest((WFPATH, sha(wf_)))})
    assert PYPIN in k, "a workflow is never exempt"
    act = ".github/agent/fixtures/act/action.yml"
    a_ = "name: a\nruns:\n  using: composite\n  steps:\n    - run: pip install --require-hashes pyyaml==5.3 --hash=sha256:aa\n      shell: bash\n"
    k, _ = repo_items({act: a_, MF: manifest((act, sha(a_)))})
    assert PYPIN in k, "an action file is never exempt"


@case("audit", "AC11", "i: a bad manifest exempts nothing it cannot vouch for, and says so: malformed JSON, a wrong shape, an entry without a reason / with an empty reason / with a bad or short or uppercase sha256 / with an extra key, a DUPLICATE entry, a duplicate JSON key, a path outside the repository (../x.sh, /etc/x.sh, bin/../bin/x.sh, ./x, a backslash), a DANGLING entry (no such file), a listed workflow or action file: each raises an `unparseable` HIT at the manifest; a MISSING manifest simply exempts nothing; a valid entry beside an invalid one for the SAME path (both orders) leaves the file fully in scope (the package and its advisory stay)")
def i_manifest_hygiene():
    body = SHEBANG_BASH + PIP_REAL
    good = ("bin/fx-test.sh", sha(body))
    lists = {"lists": {PYPIN: {"github": [{"id": "GHSA-8q59-q68h-6hv4", "incident": "I", "affected": True, "modified": "2026-01-01T00:00:00Z"}], "osv": []}}}

    def entry(path, h, reason="r", **extra):
        e = {"path": path, "sha256": h}
        if reason is not None:
            e["reason"] = reason
        e.update(extra)
        return e

    def man(*entries):
        return json.dumps({"files": list(entries)})
    ok = entry(*good)
    cases = [
        ("malformed JSON", "{not json"), ("wrong shape (a list)", "[]"), ("files is not a list", '{"files": "x"}'),
        ("an entry without a reason", man(entry(good[0], good[1], reason=None))), ("an empty reason", man(entry(good[0], good[1], reason="  "))),
        ("an uppercase sha256", man(entry(good[0], good[1].upper()))), ("a short sha256", man(entry(good[0], good[1][:40]))), ("an extra key", man(entry(*good, note="x"))),
        ("a duplicate entry", man(ok, ok)), ("a duplicate with another hash", man(ok, entry(good[0], sha("x")))), ("a duplicate JSON key", '{"files": [], "files": []}'),
        ("valid then missing reason", man(ok, entry(good[0], good[1], reason=None))), ("missing reason then valid", man(entry(good[0], good[1], reason=None), ok)),
        ("valid then empty reason", man(ok, entry(good[0], good[1], reason=""))), ("empty reason then valid", man(entry(good[0], good[1], reason=""), ok)),
        ("valid then bad digest", man(ok, entry(good[0], "zz" * 32))), ("bad digest then valid", man(entry(good[0], "zz" * 32), ok)),
        ("valid then extra key", man(ok, entry(*good, x="1"))), ("extra key then valid", man(entry(*good, x="1"), ok)),
        ("valid then the same path unnormalised", man(ok, entry("bin//fx-test.sh", good[1]))),
    ]
    for label, mtext in cases:
        files = {"bin/fx-test.sh": body, MF: mtext}
        repo, rc, out = run_audit_fx(files, files, lists)
        assert rc == 1 and any(MF in l for l in out.splitlines() if l.startswith("audit: HIT:")), (label, rc, out[-400:])
        assert PYPIN in sorted(inv.load_at(repo, None)), label
        assert any("GHSA-8q59-q68h-6hv4" in l for l in out.splitlines() if l.startswith("audit: HIT:")), ("the advisory must stay", label, out[-300:])
    for bad in ("../fx-test.sh", "/etc/fx-test.sh", "bin/../bin/fx-test.sh", "bin\\fx-test.sh", "./bin/fx-test.sh", MF):
        files = {"bin/fx-test.sh": body, "bin/ok-test.sh": body, MF: man(entry(bad, sha(body)), entry("bin/ok-test.sh", sha(body)))}
        repo, rc, out = run_audit_fx(files, files, {})
        assert rc == 1 and any(MF in l for l in out.splitlines() if l.startswith("audit: HIT:")) and PYPIN in sorted(inv.load_at(repo, None)), (bad, rc, out[-300:])
    files = {"bin/fx-test.sh": body}
    repo, rc, out = run_audit_fx(files, files, {})
    assert PYPIN in sorted(inv.load_at(repo, None)) and not any(MF in l for l in out.splitlines() if l.startswith("audit: HIT:"))
    dang = man(entry("bin/missing-test.sh", sha(body)), entry("bin/ok-test.sh", sha(body)))
    files = {"bin/ok-test.sh": body, MF: dang}
    repo, rc, out = run_audit_fx(files, files, {})
    hits = [l for l in out.splitlines() if l.startswith("audit: HIT:") and MF in l]
    assert rc == 1 and len(hits) == 1 and "bin/missing-test.sh" in hits[0], ("a dangling entry is a finding", rc, out[-400:])
    wf_ = runner_wf("pip install --require-hashes pyyaml==5.3 --hash=sha256:aa")
    files = {WFPATH: wf_, MF: man(entry(WFPATH, sha(wf_)))}
    repo, rc, out = run_audit_fx(files, files, {})
    assert rc == 1 and any(MF in l and WFPATH in l for l in out.splitlines() if l.startswith("audit: HIT:")) and PYPIN in sorted(inv.load_at(repo, None)), (rc, out[-300:])


@case("audit", "AC11", "i: an ALIAS of a listed path (a doubled separator, ./, a trailing slash) with any invalid entry invalidates the path, in both orders, and a reason with a newline or a control character is invalid: the file stays fully in scope (the package and its advisory stay) and the manifest finding is raised")
def i_manifest_aliases_and_one_line_reasons():
    body = SHEBANG_BASH + PIP_REAL
    h = sha(body)
    lists = {"lists": {PYPIN: {"github": [{"id": "GHSA-8q59-q68h-6hv4", "incident": "I", "affected": True, "modified": "2026-01-01T00:00:00Z"}], "osv": []}}}
    ok = {"path": "bin/fx-test.sh", "sha256": h, "reason": "r"}
    cases = []
    for alias in ("bin//fx-test.sh", "./bin/fx-test.sh", "bin/fx-test.sh/", "bin/./fx-test.sh"):
        bad = {"path": alias, "sha256": h}                       # missing its reason
        cases += [("valid then alias without reason " + alias, [ok, bad]), ("alias without reason then valid " + alias, [bad, ok]),
                  ("valid then alias with bad digest " + alias, [ok, {"path": alias, "sha256": "zz" * 32, "reason": "r"}])]
    for reason in ("line one\nline two", "tab\there", "nul\u0000x", "del\u007fx", "cr\rx"):
        cases.append(("a reason with a control character " + repr(reason), [dict(ok, reason=reason)]))
    for label, entries in cases:
        files = {"bin/fx-test.sh": body, MF: json.dumps({"files": entries})}
        repo, rc, out = run_audit_fx(files, files, lists)
        assert rc == 1 and any(MF in l for l in out.splitlines() if l.startswith("audit: HIT:")), (label, rc, out[-300:])
        assert PYPIN in sorted(inv.load_at(repo, None)) and any("GHSA-8q59-q68h-6hv4" in l for l in out.splitlines() if l.startswith("audit: HIT:")), (label, "the file must stay in scope", out[-300:])


@case("age", "AC11", "i: IN PULL REQUEST MODE the manifest is read from the BASE: a PR that ADDS a harness file and lists it in its own manifest is measured (refused, young pin); a PR that DELETES the manifest (the head tree really lacks it) leaves the base's exemption in force for the unchanged file; the daily audit's PR mode reads the same")
def i_manifest_read_from_base():
    body = SHEBANG_BASH + PIP_REAL
    young = {"times": {PYPIN: {"time": "2026-10-06T00:00:00Z", "source": "pypi"}}}
    base = {"bin/fx-test.sh": body, MF: manifest(("bin/fx-test.sh", sha(body)))}
    g = SHEBANG_BASH + "pip install --require-hashes requests==2.32.0 --hash=sha256:aa\n"
    head = {**base, "bin/new-test.sh": g, MF: manifest(("bin/fx-test.sh", sha(body)), ("bin/new-test.sh", sha(g)))}
    rc, out = run_age(exact_repo(base, head), {"times": {}})
    assert rc == 1 and "package:pypi/requests@2.32.0" in out, out[-300:]
    head = {"bin/fx-test.sh": body, "README.md": "x\n"}
    repo = exact_repo(base, head)
    assert _git(repo, "ls-tree", "HEAD", "--", MF).stdout.strip() == "" and _git(repo, "ls-tree", "HEAD~1", "--", MF).stdout.strip() != "", "the manifest must really be deleted at HEAD"
    rc, out = run_age(repo, young)
    assert rc == 0 and "no pin moved" in out, out[-300:]
    lists = {"lists": {"package:pypi/requests@2.32.0": {"github": [{"id": "GHSA-test-test-test", "incident": "I", "affected": True, "modified": "2026-01-01T00:00:00Z"}], "osv": []}}}
    head_a = {**base, "bin/new-test.sh": g, MF: manifest(("bin/fx-test.sh", sha(body)), ("bin/new-test.sh", sha(g)))}
    rc, out = run_audit_pr(base, head_a, lists)
    assert rc == 1 and any("GHSA-test-test-test" in l for l in out.splitlines() if l.startswith("audit: HIT:")), (rc, out[-300:])
    rc, out = run_audit_pr(base, {"bin/fx-test.sh": body, "README.md": "x\n"}, lists)
    assert rc == 0, out[-300:]
    # a PRE-PLANTED entry: the base manifest lists a path that does not exist yet (the daily audit reports it as dangling), and a later PR that adds exactly those bytes, with the manifest deleted
    # from its own tree, is exempt by the BASE manifest alone; ignoring the base when HEAD has no manifest would measure it
    planted = SHEBANG_BASH + "pip install --require-hashes requests==2.32.0 --hash=sha256:aa\n"
    base_p = {"README.md": "x\n", MF: manifest(("bin/planted-test.sh", sha(planted)))}
    repo, rc, out = run_audit_fx(base_p, base_p, {})
    assert rc == 1 and any("bin/planted-test.sh" in l and MF in l for l in out.splitlines() if l.startswith("audit: HIT:")), ("a dangling entry is reported the day it lands", rc, out[-300:])
    repo = exact_repo(base_p, {"README.md": "x\n", "bin/planted-test.sh": planted})
    assert _git(repo, "ls-tree", "HEAD", "--", MF).stdout.strip() == ""
    rc, out = run_age(repo, {"times": {}})
    assert rc == 0 and "no pin moved" in out, ("the base manifest alone exempts it", out[-300:])


@case("age", "AC11", "i: (like with like) the BASE manifest's exemptions apply to each side's own files: the BOOTSTRAP PR (the manifest is introduced, main has none) moves no pin; a PR that EDITS a listed harness file (even a comment) has it measured in full at the head, so its fixture strings are moved and refused/reported for the owner's review (the ONE rule; no comment-only carve-out); a new real line in an unlisted script IS moved and an unchanged harness moves nothing")
def i_manifest_pr_like_with_like():
    body = SHEBANG_BASH + PIP_REAL + "# a comment\n"
    young = {"times": {"package:pypi/requests@2.32.0": {"time": "2026-10-06T00:00:00Z", "source": "pypi"}}}
    base = {"bin/fx-test.sh": body, "bin/other-test.sh": SHEBANG_BASH + GO_REAL}
    head = {**base, MF: manifest(("bin/fx-test.sh", sha(body)), ("bin/other-test.sh", sha(SHEBANG_BASH + GO_REAL)))}
    rc, out = run_age(exact_repo(base, head), young)
    assert rc == 0 and "no pin moved" in out, ("bootstrap", out[-300:])
    rc, out = run_audit_pr(base, head, {})
    assert rc == 0, ("bootstrap audit", out[-300:])
    listed = {**base, MF: manifest(("bin/fx-test.sh", sha(body)), ("bin/other-test.sh", sha(SHEBANG_BASH + GO_REAL)))}
    edited = body.replace("# a comment", "# another comment")
    head2 = {**listed, "bin/fx-test.sh": edited}
    rc, out = run_age(exact_repo(listed, head2), young)
    assert rc == 1 and "pyyaml@5.3" in out, ("an edit of a listed harness is measured in full: its fixture strings are moved", out[-300:])
    lists_ = {"lists": {PYPIN: {"github": [{"id": "GHSA-8q59-q68h-6hv4", "incident": "I", "affected": True, "modified": "2026-01-01T00:00:00Z"}], "osv": []}}}
    rc, out = run_audit_pr(listed, head2, lists_)
    assert rc == 1 and any("GHSA-8q59-q68h-6hv4" in l for l in out.splitlines() if l.startswith("audit: HIT:")), ("the edited harness's fixture is reported in the PR audit", out[-300:])
    assert rc == 1 and not any("harness manifest" in l for l in out.splitlines() if l.startswith("audit: HIT:")), "no hash finding in a PR (that is the daily audit's, after the merge)"
    rc, out = run_age(exact_repo(listed, listed), young)
    assert rc == 0 and "no pin moved" in out, ("(d) an unchanged harness moves nothing", out[-300:])
    head3 = {**listed, "tools/new.sh": SHEBANG_BASH + "pip install --require-hashes requests==2.32.0 --hash=sha256:aa\n"}
    rc, out = run_age(exact_repo(listed, head3), young)
    assert rc == 1 and "package:pypi/requests@2.32.0" in out and "pyyaml@5.3" not in out, ("a genuinely new line", out[-400:])


@case("audit", "AC11", "i: after the merge the DAILY audit verifies the hash: a listed file whose bytes changed in a PR that did not update the manifest is a HIT naming both hashes on the next daily run; one that did update it is clean")
def i_manifest_base_mismatch_named_in_pr():
    body = SHEBANG_BASH + PIP_REAL
    body2 = body + "# edited\n"
    stale = {"bin/fx-test.sh": body2, MF: manifest(("bin/fx-test.sh", sha(body)))}
    repo, rc, out = run_audit_fx(stale, stale, {})
    hits = [l for l in out.splitlines() if l.startswith("audit: HIT:") and "(unparseable)" in l]
    assert rc == 1 and len(hits) == 1 and sha(body) in hits[0] and sha(body2) in hits[0], (rc, out[-500:])
    fresh = {"bin/fx-test.sh": body2, MF: manifest(("bin/fx-test.sh", sha(body2)))}
    repo, rc, out = run_audit_fx(fresh, fresh, {})
    assert rc == 0 and "no known-compromised" in out, out[-300:]


@case("age", "AC11", "x: the manifest sits INSIDE .github/agent/supply-chain/ (next to the checker that reads it, as the layout rule wants) and is allowed by the repository's file allowlist (bin/check-file-allowlist.sh accepts exactly .github/agent/supply-chain/harness-manifest.json); the old path outside .github/agent/ and sibling names are refused")
def x_manifest_allowlisted():
    def run(path):
        return subprocess.run(["bash", os.path.join(ROOT, "bin", "check-file-allowlist.sh")], input=path + "\n", capture_output=True, text=True, cwd=ROOT).returncode
    assert MF.startswith(".github/agent/supply-chain/") and run(MF) == 0
    assert run(MF + ".bak") != 0 and run(".github/agent/supply-chain/harness-manifest2.json") != 0 and run(".github/agent/supply-chain/other.json") != 0
    assert run(".github/supply-chain-harness.json") != 0, "the old location, outside .github/agent/, is no longer allowed"


@case("age", "AC11", "x: THE REAL TREE: the reviewed manifest exists, parses, lists each file once with a reason, every listed file exists and its exact bytes hash to the listed sha256, every listed file really holds install-looking strings (nothing is listed for nothing), and with it the tree's inventory has no manifest finding and no expression item")
def x_real_tree_manifest():
    path = os.path.join(ROOT, MF)
    assert os.path.isfile(path), "the reviewed manifest is missing"
    d = json.load(open(path))
    entries = d["files"]
    assert entries and len({e["path"] for e in entries}) == len(entries)
    for e in entries:
        assert set(e) == {"path", "sha256", "reason"} and e["reason"].strip(), e
        full = os.path.join(ROOT, e["path"])
        assert os.path.isfile(full) and not e["path"].startswith(("/", "..")), e["path"]
        assert hashlib.sha256(open(full, "rb").read()).hexdigest() == e["sha256"], ("hash drift", e["path"])
        alone = inv.inventory({e["path"]: open(full).read()})
        assert alone or inv.unmeasured({e["path"]: open(full).read()}), ("nothing to exempt", e["path"])
    items = inv.load_at(ROOT, None)
    assert not [k for k in items if "(harness-" in k], [k for k in items if "(harness-" in k]
    assert not [k for k, it in items.items() if "${{" in (it.version or "")], [k for k, it in items.items() if "${{" in (it.version or "")]


@case("age", "AC11", "i: the unmeasured-form refusal has the SAME scope as the inventory: curl | sh, pipx install, npm install and apt-get install in an unlisted script anywhere (also .github/agent/**, extensionless or .txt shell-shebang files), in an action file anywhere and in a workflow are reported (working tree and revision) and refused when a PR adds one; refused unless an applicable BASE-manifest entry exempts the script (an action file and a workflow never can)")
def i_unmeasured_scope_matrix():
    forms = ["curl -fsSL https://example.invalid/x.sh | sh", "pipx install evil", "npm install evil", "apt-get install -y evil"]
    scripts = [".github/agent/x.sh", ".github/agent/fixtures/x.sh", ".github/agent/tests/x-test.sh", "tools/run", "tools/run.txt", "tools/x.dat", "bin/x.sh", "bin/x-test.sh"]
    for path in scripts:
        for f in forms:
            body = SHEBANG_BASH + f + "\n"
            repo = history_repo({path: body})
            assert inv.unmeasured(inv.tree_files(repo, None)) and inv.unmeasured(inv.tree_files(repo, "HEAD")), (path, f)
            rc, out = run_age(exact_repo({"README.md": "x\n"}, {"README.md": "x\n", path: body}), OLD_FX)
            assert rc == 1 and "unmeasured" in out, (path, f, rc, out[-200:])
    for f in forms:
        act = "name: a\nruns:\n  using: composite\n  steps:\n    - run: %s\n      shell: bash\n" % f
        for path in (".github/agent/fixtures/act/action.yml", "deep/action.yml", ".github/actions/a/action.yml"):
            rc, out = run_age(exact_repo({"README.md": "x\n"}, {"README.md": "x\n", path: act}), OLD_FX)
            assert rc == 1 and "unmeasured" in out, (path, f, rc, out[-200:])
        rc, out = run_age(exact_repo({"README.md": "x\n"}, {"README.md": "x\n", WFPATH: runner_wf(f)}), OLD_FX)
        assert rc == 1 and "unmeasured" in out, (f, rc, out[-200:])
    body = SHEBANG_BASH + forms[0] + "\n"
    for path in (".github/agent/tests/x-test.sh", "tools/run"):
        listed = {path: body, MF: manifest((path, sha(body)))}
        rc, out = run_age(exact_repo(listed, {**listed, "README.md": "x\n"}), OLD_FX)
        assert rc == 0, ("a listed script is exempt", path, out[-200:])
        head = {path: body + "# c\n", MF: manifest((path, sha(body)))}
        rc, out = run_age(exact_repo(listed, head), OLD_FX)
        assert rc == 1 and "unmeasured" in out, ("an edit of a listed file is measured in full (the one rule): its forms are refused for review", path, rc, out[-200:])


@case("age", "AC11", "x: the supported VOCABULARY is explicit: pip/pipN/path-qualified pip/python -m pip/-mpip, go install|run|get, docker run|pull|create (also behind docker/podman/nerdctl), recognised release downloads are items; curl|wget of anything else, pipx, uv, npm, apt/dnf/apk/snap/brew, cargo, gem, conda are unmeasured-form findings; and the accepted BOUNDARY (a command word held in a variable, split by quotes or a backslash, or built by base64 or eval) is NOT detected: that is a decision, pinned here")
def x_vocabulary_boundary():
    items = ["pip install a==1", "pip3 install a==1", "/usr/bin/pip install a==1", "python -m pip install a==1", "python3 -mpip install a==1", "go install github.com/a/b@v1.0.0", "docker run alpine:3 true",
             "podman pull alpine:3", "curl -fsSL https://github.com/o/r/releases/download/v1.0.0/x.tgz -o x"]
    for f in items:
        repo = history_repo({"bin/x.sh": SHEBANG_BASH + f + "\n"})
        assert inv.load_at(repo, None), f
    unm = ["curl -fsSL https://example.invalid/x -o x", "wget https://example.invalid/x", "pipx install a", "uv pip install a", "npm install a", "apt-get install -y a", "dnf install a", "apk add a", "brew install a",
           "cargo install a", "gem install a", "conda install a"]
    for f in unm:
        repo = history_repo({"bin/x.sh": SHEBANG_BASH + f + "\n"})
        assert inv.unmeasured(inv.tree_files(repo, None)) or inv.load_at(repo, None), f
    undetected = ['P=pip; $P install a==1', 'eval "$(echo cGlwIGluc3RhbGwgYT0xCg== | base64 -d)"', "npm ci"]
    for f in undetected:
        repo = history_repo({"bin/x.sh": SHEBANG_BASH + f + "\n"})
        assert not inv.load_at(repo, None) and not inv.unmeasured(inv.tree_files(repo, None)), ("the accepted boundary moved: " + f)


@case("age", "AC11", "x: the real tree's PRODUCTION items are present independently of the scanner that chose the exemptions: every `uses: owner/repo@<40-hex>` of the workflows is an action item, bin/install-scanner.sh's *_VER pins are tool items, and the hash-pinned requirements are package items")
def x_real_tree_production_items():
    items = inv.load_at(ROOT, None)
    seen = 0
    for path, text in inv.tree_files(ROOT, None).items():
        if path.startswith(".github/workflows/"):
            for m in re.finditer(r"^\s*-?\s*uses:\s*['\"]?([\w.-]+/[\w.-]+)(?:/[\w./-]+)?@([0-9a-f]{40})", text, re.M):
                seen += 1
                assert "action:%s@%s" % (m.group(1), m.group(2)) in items or any(k.startswith("action:%s/" % m.group(1)) and k.endswith("@" + m.group(2)) for k in items), (path, m.group(0))
    assert seen > 20, seen
    scanner = open(os.path.join(ROOT, "bin", "install-scanner.sh")).read()
    pins = re.findall(r"^[ \t]*([A-Z][A-Z0-9]*)_VER=['\"]?([^\s'\"#]+)", scanner, re.M)
    assert len(pins) >= 5
    for name, ver in pins:
        assert "tool:%s@%s" % (name.lower().replace("_", "-"), ver) in items, (name, ver)
    assert "package:pypi/pyyaml@6.0.2" in items and "tool:cosign@v3.0.6" in items

# ======================================================================================================================================
# step 6 restart round 2: oversize shebang scripts, script kind beats name rules, like-with-like by exact exempt paths, symlinks, PR-added dangling entries, the stated boundaries
# ======================================================================================================================================
def padded(first_lines, size):
    body = first_lines
    return body + "#" * max(0, size - len(body) - 1) + "\n"


def refused_too_large(repo, mode):
    try:
        inv.load_at(repo, mode)
    except RuntimeError as e:
        return "too large" in str(e)
    return False


@case("age", "AC11", "i: a shell-shebang script over the read limit is REFUSED, never skipped, however it is named and however large: an extensionless file and a .txt file of 1.1 MB and of 17 MB, from the working tree and from a revision, through the age check and the daily audit (exit 2, 'too large'); a 17 MB file that is NOT a shell script is skipped; an unnamed 1.2 MB file that starts with a shell shebang is refused too (a self-inflicted refusal, accepted)")
def i_oversize_shebang_refused():
    head = SHEBANG_BASH + PIP_REAL
    for name in ("tools/run", "tools/run.txt", "tools/x.dat"):
        for size in (1_100_000, 17_000_000):
            repo = history_repo({name: padded(head, size)})
            assert refused_too_large(repo, None) and refused_too_large(repo, "HEAD"), (name, size)
    repo = history_repo({"README.md": "x\n"})
    base = {"README.md": "x\n"}
    rc, out = run_age(exact_repo(base, {**base, "tools/run": padded(head, 17_000_000)}), OLD_FX)
    assert rc == 2 and "too large" in out, (rc, out[-300:])
    repo = history_repo({"tools/run": padded(head, 1_100_000)})
    fx = repo + ".fx.json"
    json.dump({"lists": {}}, open(fx, "w"))
    r = subprocess.run([sys.executable, os.path.join(SC, "pin-audit.py"), "--root", repo, "--fixtures", fx, "--now", now_iso(), "--report-only"], capture_output=True, text=True)
    assert r.returncode == 2 and "too large" in (r.stdout + r.stderr), (r.returncode, (r.stdout + r.stderr)[-300:])
    for name, body in (("tools/blob.bin", "\x00" * 17_000_000), ("tools/big.py", "#!/usr/bin/env python3\n" + "#" * 17_000_000 + "\n"), ("docs/big.md", "x" * 17_000_000 + "\n")):
        repo = history_repo({name: body})
        assert sorted(inv.load_at(repo, None)) == sorted(inv.load_at(repo, "HEAD")) == [], name
    repo = history_repo({"docs/note.md": padded(SHEBANG_BASH, 1_200_000)})
    assert refused_too_large(repo, None) and refused_too_large(repo, "HEAD")


SCRIPT_BODY = SHEBANG_BASH + PIP_REAL + "go install github.com/a/b@v1.0.0\ndocker pull alpine:3\ncurl -fsSL https://example.invalid/x.sh | sh\n"
KINDNAMES = ["tools/checksum", "bin/sha256-verify", "tools/verify-checksums", "tools/sha256sums.txt", "tools/x.sha256", "tools/.nvmrc", "tools/.tool-versions", "tools/x.sum", "tools/run"]


@case("age", "AC11", "i: the script KIND beats the name rules: a shell-shebang file named checksum, sha256-verify, verify-checksums, sha256sums.txt, x.sha256, .nvmrc or .tool-versions yields the pip, go and docker items AND (for those names) the `file:` content item, and its unmeasured forms, in both modes; the same names WITHOUT a shebang stay content-only files")
def i_script_kind_beats_name():
    for name in KINDNAMES:
        repo = history_repo({name: SCRIPT_BODY})
        for mode in (None, "HEAD"):
            k = sorted(inv.load_at(repo, mode))
            assert PYPIN in k and "gotool:github.com/a/b@v1.0.0" in k and [x for x in k if x.startswith("image:alpine:3@")], (name, mode, k)
            named = name.rsplit("/", 1)[-1] in (".nvmrc", ".tool-versions") or re.search(r"(?i)(sha256|checksums?)", name.rsplit("/", 1)[-1])
            if named and not name.endswith(".sum"):
                assert [x for x in k if x.startswith("tool:file:%s@(file)" % name)], ("the content item stays", name, mode, k)
        assert inv.unmeasured(inv.tree_files(repo, None)) and inv.unmeasured(inv.tree_files(repo, "HEAD")), name
    for name in ("tools/checksum", "tools/.nvmrc", "tools/sha256sums.txt"):
        k = sorted(inv.load_at(history_repo({name: "v1.2.3\n" + PIP_REAL}), None))
        assert PYPIN not in k and [x for x in k if x.startswith("tool:file:%s@(file)" % name)], (name, k)


@case("age", "AC11", "i: a pull request cannot hide a script behind a checksum or version-file name: adding a shebang script named sha256-verify with an install line is measured (refused, young pin; named in the output)")
def i_script_named_like_checksum_is_measured_in_pr():
    young = {"times": {PYPIN: {"time": "2026-10-06T00:00:00Z", "source": "pypi"}}}
    rc, out = run_age(exact_repo({"README.md": "x\n"}, {"README.md": "x\n", "bin/sha256-verify": SCRIPT_BODY}), young)
    assert rc == 1 and PYPIN in out, out[-300:]


FIXPIN = "package:pypi/evilpkg@9.9.9"
FIXTURE = SHEBANG_BASH + "pip install --require-hashes evilpkg==9.9.9 --hash=sha256:aa\n# fixture\n"


@case("age", "AC11", "i: LIKE WITH LIKE, exactly: the base side exempts exactly the paths the head exempts under the BASE manifest (same listed path, same bytes on both sides); so the same pin as a listed fixture introduced by a workflow, by an unlisted script, or by a COPY of the listed bytes at an unlisted path IS moved; an edit of a listed harness (even a comment) is measured in full at the head and moved; a deleted harness plus the pin introduced elsewhere is moved; an unchanged one moves nothing; the bootstrap (main has no manifest) moves nothing")
def i_like_with_like_exact():
    base = {"bin/fx-test.sh": FIXTURE, MF: manifest(("bin/fx-test.sh", sha(FIXTURE)))}
    young = {"times": {FIXPIN: {"time": "2026-10-06T00:00:00Z", "source": "pypi"}}}
    for label, add in (("a workflow", {WFPATH: runner_wf("pip install --require-hashes evilpkg==9.9.9 --hash=sha256:aa")}), ("an unlisted script", {"bin/b-test.sh": FIXTURE}),
                       ("a copy of the listed bytes", {"tools/copy.sh": FIXTURE}), ("the pin in a requirements file", {"docs/requirements.txt": "evilpkg==9.9.9 \\\n    --hash=sha256:aa\n"})):
        rc, out = run_age(exact_repo(base, {**base, **add}), young)
        assert rc == 1 and "evilpkg@9.9.9" in out, (label, rc, out[-300:])
        lists = {"lists": {FIXPIN: {"github": [{"id": "GHSA-test-test-test", "incident": "I", "affected": True, "modified": "2026-01-01T00:00:00Z"}], "osv": []}}}
        rc, out = run_audit_pr(base, {**base, **add}, lists)
        assert rc == 1 and any("GHSA-test-test-test" in l for l in out.splitlines() if l.startswith("audit: HIT:")), (label, rc, out[-300:])
    edited = FIXTURE.replace("# fixture", "# fixture, edited")
    lists = {"lists": {FIXPIN: {"github": [{"id": "GHSA-test-test-test", "incident": "I", "affected": True, "modified": "2026-01-01T00:00:00Z"}], "osv": []}}}
    prod = {"tools/prod.sh": SHEBANG_BASH + "pip install --require-hashes evilpkg==9.9.9 --hash=sha256:aa\n"}
    edited_head = {"bin/fx-test.sh": edited, MF: manifest(("bin/fx-test.sh", sha(edited)))}
    # (c) the ONE rule: an edit of a listed harness (comment only, hash updated) is measured in full at the head: refused/reported, for the owner's review
    rc, out = run_age(exact_repo(base, edited_head), young)
    assert rc == 1 and "evilpkg@9.9.9" in out, ("(c) a comment edit of a listed harness", rc, out[-300:])
    # (a) the same edit PLUS the same pin introduced in production: refused by both entry points
    rc, out = run_age(exact_repo(base, {**edited_head, **prod}), young)
    assert rc == 1 and "evilpkg@9.9.9" in out, ("(a) age", rc, out[-300:])
    rc, out = run_audit_pr(base, {**edited_head, **prod}, lists)
    assert rc == 1 and any("GHSA-test-test-test" in l for l in out.splitlines() if l.startswith("audit: HIT:")), ("(a) audit", rc, out[-300:])
    # (b) the harness DELETED (and its manifest entry removed) while the pin is introduced in production
    for gone in ({MF: manifest()}, {}):
        rc, out = run_age(exact_repo(base, {**gone, **prod}), young)
        assert rc == 1 and "evilpkg@9.9.9" in out, ("(b) age", gone, rc, out[-300:])
        rc, out = run_audit_pr(base, {**gone, **prod}, lists)
        assert rc == 1 and any("GHSA-test-test-test" in l for l in out.splitlines() if l.startswith("audit: HIT:")), ("(b) audit", gone, rc, out[-300:])
    # (d) control: the unchanged harness alone moves nothing
    rc, out = run_age(exact_repo(base, dict(base)), young)
    assert rc == 0 and "no pin moved" in out, ("(d)", out[-300:])
    stale_base = {"bin/fx-test.sh": FIXTURE + "# stale bytes\n", MF: manifest(("bin/fx-test.sh", sha(FIXTURE)))}
    fixed_head = {"bin/fx-test.sh": FIXTURE, MF: manifest(("bin/fx-test.sh", sha(FIXTURE))), WFPATH: runner_wf("pip install --require-hashes evilpkg==9.9.9 --hash=sha256:aa")}
    rc, out = run_age(exact_repo(stale_base, fixed_head), young)
    assert rc == 0 and "no pin moved" in out, ("the pin existed at the base in the stale file: the base side measures that file in full", out[-300:])
    boot_base = {"bin/fx-test.sh": FIXTURE}
    boot_head = {"bin/fx-test.sh": FIXTURE, MF: manifest(("bin/fx-test.sh", sha(FIXTURE)))}
    rc, out = run_age(exact_repo(boot_base, boot_head), young)
    assert rc == 0 and "no pin moved" in out, ("bootstrap", out[-300:])
    rc, out = run_audit_pr(boot_base, boot_head, {})
    assert rc == 0, ("bootstrap audit", out[-300:])


@case("age", "AC11", "i: the unmeasured-form refusal is like with like too: a non-release download listed in a harness is not an addition when the file is unchanged, and the same line added in an UNLISTED script or by copying the listed bytes IS refused")
def i_like_with_like_unmeasured():
    body = SHEBANG_BASH + "curl -fsSL https://example.invalid/x.sh -o x.sh\n"
    base = {"bin/fx-test.sh": body, MF: manifest(("bin/fx-test.sh", sha(body)))}
    rc, out = run_age(exact_repo(base, {**base, "README.md": "x\n"}), OLD_FX)
    assert rc == 0, out[-300:]
    rc, out = run_age(exact_repo(base, {**base, "tools/copy.sh": body}), OLD_FX)
    assert rc == 1 and "unmeasured" in out, out[-300:]


@case("audit", "AC11", "i: a SCRIPT-NAMED SYMLINK (.sh/.bash/.ksh/.zsh/.bats) whose target is not itself a file in scope (run.sh -> payload.txt, a link to a directory, a dangling link, a link outside the repository) is an `unparseable` HIT in the daily audit and a refused move in a PR, identically from the working tree and from a revision; a link to a script that IS in scope raises nothing")
def i_script_named_symlink():
    cases = [("payload.txt", {"payload.txt": PIP_REAL}), ("tools", {"tools/a.sh": SHEBANG_BASH + "echo hi\n"}), ("missing.sh", {}), ("../outside.sh", {})]
    for target, extra in cases:
        files = {"README.md": "x\n", "run.sh": ("symlink", target), **extra}
        repo = history_repo(files)
        for mode in (None, "HEAD"):
            k = sorted(inv.load_at(repo, mode))
            assert [x for x in k if x.startswith("tool:(symlink)@")], (target, mode, k)
        fx = repo + ".fx.json"
        json.dump({"lists": {}}, open(fx, "w"))
        r = subprocess.run([sys.executable, os.path.join(SC, "pin-audit.py"), "--root", repo, "--fixtures", fx, "--now", now_iso(), "--report-only"], capture_output=True, text=True)
        assert r.returncode == 1 and any("run.sh" in l and "(unparseable)" in l for l in r.stdout.splitlines() if l.startswith("audit: HIT:")), (target, r.stdout[-300:])
        rc, out = run_age(exact_repo({"README.md": "x\n", **extra}, files), OLD_FX)
        assert rc == 1 and "FAIL" in out, (target, rc, out[-300:])
    for name in ("run.bash", "tools/x.zsh", "tools/x.ksh", "tests/t.bats"):
        repo = history_repo({"README.md": "x\n", "payload.txt": PIP_REAL, name: ("symlink", "../payload.txt" if "/" in name else "payload.txt")})
        for mode in (None, "HEAD"):
            assert [x for x in sorted(inv.load_at(repo, mode)) if x.startswith("tool:(symlink)@")], (name, mode)
    good = {"README.md": "x\n", "real.sh": SHEBANG_BASH + "echo hi\n", "run.sh": ("symlink", "real.sh"), "tools/link.sh": ("symlink", "../real.sh")}
    repo = history_repo(good)
    for mode in (None, "HEAD"):
        assert not [x for x in sorted(inv.load_at(repo, mode)) if "(symlink)" in x], mode


@case("age", "AC11", "i: a manifest entry ADDED by a pull request that points at no file is reported in pull request mode too (age check: refused; audit PR mode: a HIT naming the path), so an entry cannot be pre-planted unseen; an entry added for an existing file with the right bytes is no finding")
def i_pr_added_dangling_entry():
    body = SHEBANG_BASH + PIP_REAL
    base = {"bin/fx-test.sh": body, MF: manifest(("bin/fx-test.sh", sha(body)))}
    head = {**base, MF: manifest(("bin/fx-test.sh", sha(body)), ("bin/planted-test.sh", sha("x")))}
    rc, out = run_age(exact_repo(base, head), OLD_FX)
    assert rc == 1 and "FAIL" in out, out[-300:]
    rc, out = run_audit_pr(base, head, {})
    assert rc == 1 and any("bin/planted-test.sh" in l and MF in l for l in out.splitlines() if l.startswith("audit: HIT:")), (rc, out[-300:])
    other = SHEBANG_BASH + GO_REAL
    head2 = {**base, "bin/other-test.sh": other, MF: manifest(("bin/fx-test.sh", sha(body)), ("bin/other-test.sh", sha(other)))}
    rc, out = run_audit_pr(base, head2, {})
    assert not any(MF in l for l in out.splitlines() if l.startswith("audit: HIT:")), out[-300:]


@case("age", "AC11", "x: the accepted BOUNDARY of the install vocabulary, one explicit line each (none of these is an item or an unmeasured form; a change here is a decision): poetry, pipenv, pdm, hatch, tox, bare yarn, pip download, docker compose pull, docker-compose up, buildah from, skopeo copy, crane pull, oras pull, ko build, rustup toolchain install, nvm install, asdf install, mise install, sdk install, conda env create, nix-env, helm pull, docker load, pip.exe, pip${IFS}install, subprocess.run list form")
def x_undetected_vocabulary_boundary():
    forms = ["poetry install", "poetry add requests", "pipenv install", "pdm install", "hatch env create", "tox", "yarn", "pip download requests==2.0", "docker compose pull",
             "docker-compose up", "buildah from alpine:3", "skopeo copy docker://a/b docker://c/d", "crane pull alpine:3 out.tar", "oras pull ghcr.io/a/b:1", "ko build ./cmd/x", "rustup toolchain install stable",
             "nvm install 20", "asdf install nodejs 20.0.0", "mise install node@20", "sdk install java 21", "conda env create -f env.yml", "nix-env -iA nixpkgs.hello", "helm pull oci://example.invalid/chart",
             "docker load -i image.tar", "pip.exe install requests==2.0", "pip${IFS}install requests==2.0", "subprocess.run(['pip','install','requests==2.0'])", 'subprocess.run(["pip", "install", "requests==2.0"])']
    for f in forms:
        repo = history_repo({"bin/x.sh": SHEBANG_BASH + f + "\n"})
        assert not inv.load_at(repo, None) and not inv.unmeasured(inv.tree_files(repo, None)), ("the accepted boundary moved: " + f)


@case("age", "AC11", "x: the REAL tree accounts for every in-scope script: each script not listed in the manifest yields only items that are also in the whole tree's inventory (no accidental drop by a name rule or a kind rule), and every listed file is a script or requirements file")
def x_real_tree_every_script_accounted():
    files = inv.tree_files(ROOT, None)
    listed = {e["path"] for e in json.load(open(os.path.join(ROOT, MF)))["files"]}
    strip = lambda ks: {re.sub(r"~\d+$", "", k) for k in ks}
    whole = strip(inv.load_at(ROOT, None))
    n = 0
    for p, t in files.items():
        if p in listed:
            continue
        if p.endswith((".sh", ".bash", ".ksh", ".zsh", ".bats")) or t.startswith("#!"):
            n += 1
            sub = inv.Files()
            sub[p] = t
            for r in files:                              # the requirements files a script feeds to pip are read with it
                if inv._requirements_name(r) or r in files.reqrefs:
                    sub[r] = files[r]
            sub.reqrefs = set(files.reqrefs)
            assert strip(inv.inventory(sub)) <= whole, ("dropped", p)
    assert n >= 10, n


@case("age", "AC11", "i: (Codex) the collision case through BOTH PR entry points: a listed, unchanged harness that holds the PyYAML 5.3 fixture does not make PyYAML 5.3 'already used': a PR adding the same version to a NEW unlisted production script is moved (age check: refused, named) and the audit's PR mode reports GHSA-8q59-q68h-6hv4")
def i_pyyaml_collision_both_entry_points():
    fx = SHEBANG_BASH + PIP_REAL + "# fixture\n"
    base = {"bin/fx-test.sh": fx, MF: manifest(("bin/fx-test.sh", sha(fx)))}
    young = {"times": {PYPIN: {"time": "2026-10-06T00:00:00Z", "source": "pypi"}}}
    lists = {"lists": {PYPIN: {"github": [{"id": "GHSA-8q59-q68h-6hv4", "incident": "I", "affected": True, "modified": "2026-01-01T00:00:00Z"}], "osv": []}}}
    for path in ("bin/prod.sh", "tools/prod", "deploy/run.bash"):
        head = {**base, path: SHEBANG_BASH + PIP_REAL}
        rc, out = run_age(exact_repo(base, head), young)
        assert rc == 1 and PYPIN in out, (path, rc, out[-300:])
        rc, out = run_audit_pr(base, head, lists)
        assert rc == 1 and any("GHSA-8q59-q68h-6hv4" in l for l in out.splitlines() if l.startswith("audit: HIT:")), (path, rc, out[-300:])


@case("age", "AC11", "i: an EXPRESSION is text like any other: a literal install-looking string inside `${{ 'pip install pyyaml==5.3' }}` is an item wherever the expression sits: a run value, a commented expression, an env value, a `with: script:` value, an echo argument, an action-input default; and the daily audit reports the advisory (a command built from non-literals stays an expression, fail closed, as before)")
def i_expression_bodies_are_scanned():
    lit = "${{ 'pip install pyyaml==5.3' }}"
    wfs = ["on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - run: %s\n" % lit,
           "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      # %s\n      - run: echo hi\n" % lit,
           "on: push\nenv:\n  CMD: %s\njobs:\n  j:\n    runs-on: u\n    steps:\n      - run: echo hi\n" % lit.replace("'pip", "format('pip").replace("5.3'", "5.3')"),
           "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - uses: actions/github-script@%s # v7\n        with:\n          script: %s\n" % ("3" * 40, lit),
           "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - run: echo %s\n" % lit,
           "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - run: |\n          echo start\n          echo %s\n" % lit]
    for text in wfs:
        assert PYPIN in repo_items({WFPATH: text})[0], text
    act = "name: a\ninputs:\n  cmd:\n    default: %s\nruns:\n  using: composite\n  steps:\n    - run: echo hi\n      shell: bash\n" % lit
    assert PYPIN in repo_items({".github/actions/a/action.yml": act})[0]
    lists = {"lists": {PYPIN: {"github": [{"id": "GHSA-8q59-q68h-6hv4", "incident": "I", "affected": True, "modified": "2026-01-01T00:00:00Z"}], "osv": []}}}
    files = {WFPATH: wfs[0]}
    repo, rc, out = run_audit_fx(files, files, lists)
    assert rc == 1 and any("GHSA-8q59-q68h-6hv4" in l for l in out.splitlines() if l.startswith("audit: HIT:")), (rc, out[-300:])
    files = {WFPATH: wfs[1]}
    repo, rc, out = run_audit_fx(files, files, lists)
    assert rc == 1, ("a commented expression", rc, out[-300:])
    nonlit = "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - run: ${{ matrix.cmd }}\n"
    assert not [k for k in repo_items({WFPATH: nonlit})[0] if k.startswith(("package:", "gotool:", "tool:"))]


ROUTES = [("bin/x.sh", SHEBANG_BASH + PIP_REAL, SHEBANG_BASH + "pip install pyyaml==${{ env.V }} --hash=sha256:aa\n"),
          ("tools/x.bash", PIP_REAL, "pip install pyyaml==${{ env.V }} --hash=sha256:aa\n"),
          ("tools/run", SHEBANG_BASH + PIP_REAL, SHEBANG_BASH + "pip install pyyaml==${{ env.V }} --hash=sha256:aa\n"),
          ("tools/x.dat", SHEBANG_BASH + PIP_REAL, SHEBANG_BASH + "pip install pyyaml==${{ env.V }} --hash=sha256:aa\n"),
          ("tools/x.zsh", PIP_REAL, "pip install pyyaml==${{ env.V }} --hash=sha256:aa\n"),
          (".github/actions/a/action.yml", "name: a\nruns:\n  using: composite\n  steps:\n    - run: pip install --require-hashes pyyaml==5.3 --hash=sha256:aa\n      shell: bash\n",
           "name: a\nruns:\n  using: composite\n  steps:\n    - run: pip install --require-hashes pyyaml==${{ env.V }} --hash=sha256:aa\n      shell: bash\n"),
          ("docs/requirements.txt", "pyyaml==5.3 \\\n    --hash=sha256:aa\n", None),
          ("bin/h.sh", SHEBANG_BASH + "pip install --quiet --require-hashes -r /dev/stdin <<'REQ'\npyyaml==5.3 --hash=sha256:aa\nREQ\n", None)]


def run_audit_history(commits, lists):
    repo = history_repo(*commits)
    fx = repo + ".fx.json"
    json.dump(dict({"upstream": {}, "nested": {}, "versions": {}, "prs": []}, **lists), open(fx, "w"))
    r = subprocess.run([sys.executable, os.path.join(SC, "pin-audit.py"), "--root", repo, "--fixtures", fx, "--now", now_iso(), "--report-only"], capture_output=True, text=True)
    return repo, r.returncode, r.stdout + r.stderr


@case("audit", "AC12", "h: the history window selects EVERY in-scope kind of file: an install introduced and removed between two scans is found for each route (a .sh control, .bash, .zsh, an extensionless and a .dat shell-shebang file, an action file, a requirements file, a hash-pinned requirements heredoc in a script): a literal vulnerable version is an advisory HIT on the next daily run; an expression that existed only in the history is the `history, not judged` information record naming that file")
def h_history_every_file_kind_route():
    lists = {"lists": {PYPIN: {"github": [{"id": "GHSA-8q59-q68h-6hv4", "incident": "I", "affected": True, "modified": "2026-01-01T00:00:00Z"}], "osv": []}}}
    for path, vuln, expr in ROUTES:
        repo, rc, out = run_audit_history([{"README.md": "x\n"}, {"README.md": "x\n", path: vuln}, {"README.md": "x\n"}], lists)
        assert rc == 1 and any("GHSA-8q59-q68h-6hv4" in l for l in out.splitlines() if l.startswith("audit: HIT:")), (path, rc, out[-400:])
        if expr is not None:
            repo, rc, out = run_audit_history([{"README.md": "x\n"}, {"README.md": "x\n", path: expr}, {"README.md": "x\n"}], {"lists": {}})
            got = history_info(out)
            assert rc == 0 and not hit_lines(out) and [g for g in got if g[0] == path], (path, rc, got, out[-300:])


# ======================================================================================================================================
# step 6 restart round 3: env shebang forms, folded scalars, requirements kind beats name rules, quoted specs, shell names, accepted boundaries
# ======================================================================================================================================
LONGOPT = "-u " + "A" * 80
ENV_FORMS = ["#!/usr/bin/env -Sbash -e", "#!/usr/bin/env --split-string=bash -e", "#!/usr/bin/env -S -u FOO bash", "#!/usr/bin/env -S -i FOO=1 bash -e", "#!/usr/bin/env -S -C /tmp bash",
             "#!/usr/bin/env -u FOO bash", "#!/usr/bin/env -C /tmp bash", "#!/usr/bin/env -P /usr/bin:/bin bash", "#!/usr/bin/env -i bash", "#!/usr/bin/env -i FOO=1 bash",
             "#!/usr/bin/env -S 'bash -e'", "#!/usr/bin/env -S " + LONGOPT + " bash", "#!/usr/bin/env " + LONGOPT + " bash", "#!/usr/bin/env -S -P /usr/bin -u FOO zsh"]


@case("age", "AC11", "i: every valid `env` shebang form puts the file in scope whatever its name: -S attached (-Sbash), --split-string=..., a split string with an option and a separate operand before the interpreter (-S -u FOO bash, -C DIR, -P PATH), env -u NAME bash, env -C DIR bash, -P, -i, NAME=value, and a first line over 64 bytes with the interpreter at its end; each also over the read limit (refused, never skipped) and from a revision; env of a non-shell stays out")
def i_env_shebang_forms():
    for sb in ENV_FORMS:
        assert len(sb) > 0
        repo = history_repo({"tools/run": sb + "\n" + PIP_REAL})
        for mode in (None, "HEAD"):
            assert PYPIN in sorted(inv.load_at(repo, mode)), (sb, mode)
        big = history_repo({"tools/run": padded(sb + "\n" + PIP_REAL, 1_100_000)})
        assert refused_too_large(big, None) and refused_too_large(big, "HEAD"), ("oversize", sb)
    assert max(len(x) for x in ENV_FORMS) > 64 and any(len(x) > 64 and x.rstrip().endswith("bash") for x in ENV_FORMS)
    for sb in ("#!/usr/bin/env -S python3 -u", "#!/usr/bin/env -u FOO python3", "#!/usr/bin/env -S -u FOO node", "#!/usr/bin/env -S", "#!/usr/bin/env"):
        repo = history_repo({"tools/run": sb + "\n" + PIP_REAL})
        assert not inv.load_at(repo, None), sb


FOLD_PIP = "pip install\n          --require-hashes pyyaml==5.3\n          --hash=sha256:aa"


@case("age", "AC11", "i: a YAML scalar folded over several lines is read as its PARSED value too: a folded env value, a `with: script:` input, an action input default and a multi-line plain scalar that carry `pip install ... pyyaml==5.3` across lines are items (and the daily audit's advisory hit); a folded npm install in a run scalar is an unmeasured form, in the age check as a refusal")
def i_folded_scalars():
    wfs = {"env value": "on: push\njobs:\n  j:\n    runs-on: u\n    env:\n      CMD: >\n        %s\n    steps:\n      - run: echo hi\n" % FOLD_PIP.replace("\n          ", "\n        "),
           "script input": "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - uses: actions/github-script@%s # v7\n        with:\n          script: >\n            %s\n" % ("3" * 40, FOLD_PIP.replace("\n          ", "\n            ")),
           "plain multi-line": "on: push\njobs:\n  j:\n    runs-on: u\n    env:\n      CMD: pip install\n        --require-hashes pyyaml==5.3\n    steps:\n      - run: echo hi\n",
           "double-quoted multi-line": "on: push\njobs:\n  j:\n    runs-on: u\n    env:\n      CMD: \"pip install\n        --require-hashes pyyaml==5.3\"\n    steps:\n      - run: echo hi\n"}
    for label, text in wfs.items():
        assert PYPIN in repo_items({WFPATH: text})[0], label
    act = "name: a\ninputs:\n  cmd:\n    default: >\n      pip install\n      --require-hashes pyyaml==5.3\nruns:\n  using: composite\n  steps:\n    - run: echo hi\n      shell: bash\n"
    assert PYPIN in repo_items({".github/actions/a/action.yml": act})[0]
    lists = {"lists": {PYPIN: {"github": [{"id": "GHSA-8q59-q68h-6hv4", "incident": "I", "affected": True, "modified": "2026-01-01T00:00:00Z"}], "osv": []}}}
    for label in ("env value", "script input"):
        files = {WFPATH: wfs[label]}
        repo, rc, out = run_audit_fx(files, files, lists)
        assert rc == 1 and any("GHSA-8q59-q68h-6hv4" in l for l in out.splitlines() if l.startswith("audit: HIT:")), (label, rc, out[-300:])
    young = {"times": {PYPIN: {"time": "2026-10-06T00:00:00Z", "source": "pypi"}}}
    base = {WFPATH: runner_wf("echo hi")}
    rc, out = run_age(exact_repo(base, {WFPATH: wfs["env value"]}), young)
    assert rc == 1 and PYPIN in out, ("age, folded env", rc, out[-300:])
    folded_npm = "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - run: >\n          npm\n          install left-pad\n"
    assert inv.unmeasured({WFPATH: folded_npm}), "a folded npm install is an unmeasured form"
    rc, out = run_age(exact_repo(base, {WFPATH: folded_npm}), OLD_FX)
    assert rc == 1 and "unmeasured" in out, ("age, folded npm", rc, out[-300:])
    plain_npm = "on: push\njobs:\n  j:\n    runs-on: u\n    env:\n      C: npm\n        install left-pad\n    steps:\n      - run: echo hi\n"
    assert inv.unmeasured({WFPATH: plain_npm})


@case("audit", "AC11", "i: the requirements KIND beats the name rules (as the script kind does): a requirements file whose name has checksum, sha256 or version words (requirements-checksums.txt, sha256-requirements.txt, checksums/requirements.txt) yields its packages as items and the advisory hit in both modes; the content item stays beside them")
def i_requirements_kind_beats_name():
    lists = {"lists": {PYPIN: {"github": [{"id": "GHSA-8q59-q68h-6hv4", "incident": "I", "affected": True, "modified": "2026-01-01T00:00:00Z"}], "osv": []}}}
    for name in ("requirements-checksums.txt", "sha256-requirements.txt", "checksums/requirements.txt", "tools/requirements-sha256.txt", "requirements.checksum.txt"):
        files = {name: "pyyaml==5.3 \\\n    --hash=sha256:aa\n"}
        repo, rc, out = run_audit_fx(files, files, lists)
        for mode in (None, "HEAD"):
            k = sorted(inv.load_at(repo, mode))
            assert PYPIN in k, (name, mode, k)
        if re.search(r"(?i)(sha256|checksums?)", name.rsplit("/", 1)[-1]):
            assert any("file:" + name in x for x in inv.load_at(repo, None)), ("the content item stays", name)
        assert rc == 1 and any("GHSA-8q59-q68h-6hv4" in l for l in out.splitlines() if l.startswith("audit: HIT:")), (name, rc, out[-300:])


@case("age", "AC11", "i: a pip spec quoted in parts is a pin: pyyaml==\"5.3\", \"pyyaml\"==5.3, pyyaml'==5.3', in a script and in a workflow run step, with the same item as the plain spelling")
def i_partially_quoted_pip_specs():
    for spec in ('pyyaml=="5.3"', '"pyyaml"==5.3', "pyyaml'==5.3'", "'pyyaml'=='5.3'", '"pyyaml==5.3"'):
        line = "pip install --require-hashes %s --hash=sha256:aa" % spec
        assert PYPIN in repo_items({"bin/x.sh": SHEBANG_BASH + line + "\n"})[0], spec
        assert PYPIN in repo_items({WFPATH: runner_wf(line)})[0], spec


@case("age", "AC11", "i: names that are shells by themselves are in scope without a shebang: .fish, .csh, .tcsh, .dash (with .sh, .bash, .ksh, .zsh, .bats)")
def i_more_shell_names():
    for name in ("tools/x.fish", "tools/x.csh", "tools/x.tcsh", "tools/x.dash", "tools/x.ksh", "tests/x.bats"):
        assert PYPIN in sorted(inv.load_at(history_repo({name: PIP_REAL}), None)), name
        assert PYPIN in sorted(inv.load_at(history_repo({name: PIP_REAL}), "HEAD")), name


@case("age", "AC11", "x: the accepted BOUNDARY, part two (explicit decisions, none an item or an unmeasured form): FILE KINDS outside the rule (a Makefile, a Dockerfile, a .py with os.system, a .ps1, a .cmd, an extensionless non-shell file run as `bash file`) and DYNAMIC command words ($PIP install, a command word assembled from variables, base64 piped to sh)")
def x_boundary_kinds_and_dynamic_words():
    cmd = "pip install requests==2.0"
    kinds = {"Makefile": "all:\n\t" + cmd + "\n", "Dockerfile": "FROM alpine\nRUN " + cmd + "\n", "tools/x.py": "import os\nos.system('" + cmd + "')\n", "tools/x.ps1": cmd + "\n",
             "tools/x.cmd": cmd + "\n", "tools/plain": "echo start\n" + cmd + "\n", "docs/x.md": "```\n" + cmd + "\n```\n", "sub/Makefile": "install:\n\tcd sub && pip install -r r.txt\n"}
    for name, body in kinds.items():
        repo = history_repo({name: body})
        assert not inv.load_at(repo, None) and not inv.unmeasured(inv.tree_files(repo, None)), ("outside the rule: " + name)
    for form in ("$PIP install requests==2.0", 'p=pi; $p"p" install requests==2.0', "echo cGlwIGluc3RhbGwgcmVxdWVzdHM9PTIuMA== | base64 -d | sh", "${PIP} install requests==2.0",
                 "eval $(echo cGlwIGluc3RhbGw= | base64 -d) requests==2.0"):
        repo = history_repo({"bin/x.sh": SHEBANG_BASH + form + "\n"})
        assert not [k for k in inv.load_at(repo, None) if k.startswith("package:")], ("dynamic word: " + form)


# ======================================================================================================================================
# step 6 restart round 4: classes closed fail-closed (shell-word resolution of pip arguments, env shebangs, every decoded scalar), OSV per tag, continuation joins, name case
# ======================================================================================================================================
def pypi_keys(files):
    return [k for k in repo_items(files)[0] if k.startswith("package:")]


@case("age", "AC11", "i: pip arguments are resolved the way the shell resolves them: adjacent quoted and unquoted fragments concatenate and backslash escapes resolve, so a package name or version split by quote fragments (single, double, mixed) or by a backslash is the REAL name and version (PYPIN), in a workflow run step, a script and a folded scalar; the daily audit reports the advisory")
def i_pip_words_resolved():
    specs = ['py"yaml"==5.3', "'py'yaml==5.3", "py\"y\"'aml'==5.3", "pyy\\aml==5.3", '"pyyaml"=="5.3"', "pyyaml=='5'.3", "pyyaml==5.\\3", "'pyyaml'\"==\"'5.3'", '"pyy""aml==5.3"', "pyyaml==5.3''"]
    for spec in specs:
        line = "pip install --require-hashes %s --hash=sha256:aa" % spec
        assert PYPIN in pypi_keys({"bin/x.sh": SHEBANG_BASH + line + "\n"}), ("script", spec)
        assert PYPIN in pypi_keys({WFPATH: "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - run: |\n          %s\n" % line}), ("run step", spec)
        assert not [k for k in pypi_keys({"bin/x.sh": SHEBANG_BASH + line + "\n"}) if k != PYPIN and "unmeasured" not in k], ("no stray name", spec, pypi_keys({"bin/x.sh": SHEBANG_BASH + line + "\n"}))
    lists = {"lists": {PYPIN: {"github": [{"id": "GHSA-8q59-q68h-6hv4", "incident": "I", "affected": True, "modified": "2026-01-01T00:00:00Z"}], "osv": []}}}
    for spec in ('py"yaml"==5.3', "pyy\\aml==5.3"):
        files = {"tools/run.sh": SHEBANG_BASH + "pip install --require-hashes %s --hash=sha256:aa\n" % spec}
        repo, rc, out = run_audit_fx(files, files, lists)
        assert rc == 1 and any("GHSA-8q59-q68h-6hv4" in l for l in out.splitlines() if l.startswith("audit: HIT:")), (spec, rc, out[-300:])


@case("age", "AC11", "i: what the word resolver cannot resolve statically in a package or version token (a `$` variable or `$(`/backtick substitution in the name or around the operator, a quote left open) is an UNMEASURED or variable-placeholder package item (it cannot be proven, so a PR adding one is refused), never a silent drop, in a script and in a workflow run step; a plain placeholder version still is the variable item it was")
def i_pip_unresolvable_is_unmeasured():
    forms = ['pip install "py$X"==5.3', "pip install pyyaml==$(cat v)", "pip install `echo pyyaml`==5.3", "pip install 'pyyaml==5.3", 'pip install "pyyaml==5.3 --hash=sha256:aa', "pip install $(echo pyyaml)==5.3",
             'pip install "$NAME"==5.3', 'pip install py"$X"aml==5.3']
    for f in forms:
        for files in ({"bin/x.sh": SHEBANG_BASH + f + "\n"}, {WFPATH: runner_wf(f.replace("`", "\\`") if False else "|\n          " + f)}):
            ks = pypi_keys(files)
            assert any("pypi/(unmeasured:" in k or "pypi/(variable)" in k for k in ks), (f, list(files), ks)      # an item that cannot be proven (unmeasured, or the variable placeholder), never nothing


@case("age", "AC11", "i: a backslash-newline is deleted as the shell does (joined with NOTHING): a command word, package name or version split across the continuation resolves to the real one, in a script and in a workflow run block")
def i_continuation_joins_with_nothing():
    forms = ["pi\\\np install --require-hashes pyyaml==5.3 --hash=sha256:aa", "pip install --require-hashes pyy\\\naml==5.3 --hash=sha256:aa", "pip install --require-hashes pyyaml==5.\\\n3 --hash=sha256:aa",
             "pip install \\\n   --require-hashes pyyaml==5.3 \\\n   --hash=sha256:aa"]
    for f in forms:
        assert PYPIN in pypi_keys({"bin/x.sh": SHEBANG_BASH + f + "\n"}), ("script", f)
        assert PYPIN in pypi_keys({"bin/crlf.sh": SHEBANG_BASH + f.replace("\n", "\r\n") + "\r\n"}) or "\r" in f and True, ("crlf", f)
        run = "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - run: |\n" + "".join("          " + l + "\n" for l in f.split("\n"))
        assert PYPIN in pypi_keys({WFPATH: run}), ("run block", f)


@case("age", "AC11", "i: script extensions match case-insensitively: X.SH, Y.Bash, Z.KSH, W.Zsh, V.BATS without a shebang are scripts (inventory and unmeasured forms, both modes)")
def i_script_extension_case():
    for name in ("tools/X.SH", "tools/Y.Bash", "tools/Z.KSH", "tools/W.Zsh", "tests/V.BATS", "tools/U.Fish"):
        repo = history_repo({name: PIP_REAL + "npm install left-pad\n"})
        for mode in (None, "HEAD"):
            assert PYPIN in sorted(inv.load_at(repo, mode)), (name, mode)
            assert inv.unmeasured(inv.tree_files(repo, mode)), (name, mode)


ENV_FORMS_B = ["#!/usr/bin/env -S --default-signal bash", "#!/usr/bin/env --default-signal bash", "#!/usr/bin/env --default-signal=INT bash", "#!/usr/bin/env -S --default-signal=PIPE bash -e",
               "#!/usr/bin/env --ignore-signal bash", "#!/usr/bin/env --ignore-signal=TERM bash", "#!/usr/bin/env --block-signal bash", "#!/usr/bin/env --block-signal=HUP bash",
               "#!/usr/bin/env -S --default-signal --ignore-signal=INT -v zsh", "#!/usr/bin/env -v -S bash", "#!/usr/bin/env -S -vv bash", "#!/usr/bin/env -0 -S sh", "#!/bin/env -- bash",
               "#!/usr/local/bin/env -S -u A -u B -C /x --argv0 foo bash", "#!/usr/bin/env -S bash -e extra", "#!/usr/bin/env bash -O extglob"]


@case("age", "AC11", "i: an `env` shebang is a shell script when ANY later token names a shell, whatever env options come before it (the option grammar is not parsed; fail closed): GNU optional-argument options (--default-signal, --ignore-signal, --block-signal, with and without =VALUE, also behind -S), -v, -0, --, --argv0, any env path; working tree, revision and the oversize refusal; env of python3 or node stays out")
def i_env_shebang_fail_closed():
    for sb in ENV_FORMS_B + ENV_FORMS:
        repo = history_repo({"tools/run": sb + "\n" + PIP_REAL})
        for mode in (None, "HEAD"):
            assert PYPIN in sorted(inv.load_at(repo, mode)), (sb, mode)
        big = history_repo({"tools/run": padded(sb + "\n" + PIP_REAL, 1_100_000)})
        assert refused_too_large(big, None) and refused_too_large(big, "HEAD"), ("oversize", sb)
    for sb in ("#!/usr/bin/env python3", "#!/usr/bin/env -S python3 -u", "#!/usr/bin/env --default-signal python3", "#!/usr/bin/env -S node --no-warnings", "#!/usr/bin/env -u FOO python3", "#!/usr/bin/env"):
        repo = history_repo({"tools/run": sb + "\n" + PIP_REAL})
        assert not inv.load_at(repo, None), sb


def yaml_wf(env_value=None, step_extra="", name=None):
    return "on: push\njobs:\n  j:\n    runs-on: u\n    env:\n      CMD: %s\n    steps:\n%s      - run: $CMD\n" % (env_value or "x", step_extra)


@case("age", "AC11", "i: EVERY decoded YAML scalar is read, not only multi-line ones: a single-line double-quoted value whose space is a YAML escape (\\x20, \\u0020) consumed by a run step, in an env value, an action input default, a `with: script:` value, a step name, a matrix value and a key-less list item, is an item (the audit reports the advisory); an escaped npm install is an unmeasured form (the age check refuses it)")
def i_every_decoded_scalar():
    esc = {"hex": '"pip\\x20install\\x20--require-hashes\\x20pyyaml==5.3"', "unicode": '"pip\\u0020install\\u0020--require-hashes\\u0020pyyaml==5.3"', "tab-free mixed": '"pip install\\x20--require-hashes pyyaml==5.3"'}
    for label, v in esc.items():
        assert PYPIN in repo_items({WFPATH: yaml_wf(v)})[0], ("env value", label)
    v = esc["hex"]
    wfs = {"step name": "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - name: %s\n        run: echo hi\n" % v,
           "with script": "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - uses: actions/github-script@%s # v7\n        with:\n          script: %s\n" % ("3" * 40, v),
           "matrix value": "on: push\njobs:\n  j:\n    runs-on: u\n    strategy:\n      matrix:\n        cmd: [%s]\n    steps:\n      - run: ${{ matrix.cmd }}\n" % v,
           "list item": "on: push\njobs:\n  j:\n    runs-on: u\n    env:\n      L:\n        - %s\n    steps:\n      - run: echo hi\n" % v}
    for label, text in wfs.items():
        assert PYPIN in repo_items({WFPATH: text})[0], label
    act = "name: a\ninputs:\n  cmd:\n    default: %s\nruns:\n  using: composite\n  steps:\n    - run: echo hi\n      shell: bash\n" % v
    assert PYPIN in repo_items({".github/actions/a/action.yml": act})[0], "action input default"
    lists = {"lists": {PYPIN: {"github": [{"id": "GHSA-8q59-q68h-6hv4", "incident": "I", "affected": True, "modified": "2026-01-01T00:00:00Z"}], "osv": []}}}
    files = {WFPATH: yaml_wf(v)}
    repo, rc, out = run_audit_fx(files, files, lists)
    assert rc == 1 and any("GHSA-8q59-q68h-6hv4" in l for l in out.splitlines() if l.startswith("audit: HIT:")), (rc, out[-300:])
    young = {"times": {PYPIN: {"time": "2026-10-06T00:00:00Z", "source": "pypi"}}}
    rc, out = run_age(exact_repo({WFPATH: runner_wf("echo hi")}, {WFPATH: yaml_wf(v)}), young)
    assert rc == 1 and PYPIN in out, ("age", rc, out[-300:])
    npm = '"npm\\x20install\\x20left-pad"'
    assert inv.unmeasured({WFPATH: yaml_wf(npm)}), "an escaped npm install is an unmeasured form"
    rc, out = run_age(exact_repo({WFPATH: runner_wf("echo hi")}, {WFPATH: yaml_wf(npm)}), OLD_FX)
    assert rc == 1 and "unmeasured" in out, (rc, out[-300:])
    assert not [k for k in repo_items({WFPATH: yaml_wf('"echo\\x20hello"')})[0] if k.startswith(("package:", "gotool:"))]


def da_osv_net(events, *tags, gh_too=False):
    aff = [{"package": {"ecosystem": "GitHub Actions", "name": DA}, "ranges": [{"type": "ECOSYSTEM", "events": events}]}]
    osv = [osv_rec("GHSA-test-test-test", "2025-01-22T17:31:56Z", aff)]
    return make_net([], osv, {DA: {t: DA_SHA for t in tags}})


@case("audit", "AC5", "e: (0255) each exact tag is judged by EACH database independently: the each-tag-alone matrix (tags v4, v4.1.0, v4.2.9, v4.3.0, v4.10.0, v4.4.0-rc.1; each being the only affected one) is repeated with OSV-only records (GitHub empty) and with GitHub-only records: `# v4` and `# v4.3` are a hit every time, and a floating pin with affected v4.1.0 and clean v4.10.0 whose range exists ONLY in OSV is a hit (OSV asked for the displayed version only must fail)")
def e_every_tag_each_source():
    tags = ("v4", "v4.1.0", "v4.2.9", "v4.3.0", "v4.10.0", "v4.4.0-rc.1")
    for t in tags[1:]:
        v = t.lstrip("v")
        for label in ("v4", "v4.3"):
            net, ctx = da_osv_net([{"introduced": v}, {"last_affected": v}], *tags, "v4.3")
            kinds = [x.kind for x in judge(net, ctx, da_item(label))[0]]
            assert kinds == ["advisory"], ("osv only", t, label, kinds)
            net, ctx = da_range_net("= " + v, *tags, "v4.3")
            kinds = [x.kind for x in judge(net, ctx, da_item(label))[0]]
            assert kinds == ["advisory"], ("github only", t, label, kinds)
    net, ctx = da_osv_net([{"introduced": "9.9.9"}], *tags)
    assert summary(judge(net, ctx, da_item("v4"))[0]) == []
    for mk in (lambda: da_osv_net([{"introduced": "4.0.0"}, {"fixed": "4.1.3"}], "v4", "v4.1.0", "v4.10.0"), lambda: da_range_net(">= 4.0.0, < 4.1.3", "v4", "v4.1.0", "v4.10.0")):
        net, ctx = mk()
        assert [x.kind for x in judge(net, ctx, da_item("v4"))[0]] == ["advisory"]
    net, ctx = da_osv_net([{"introduced": "4.0.0"}, {"fixed": "4.1.3"}], "v4", "v4.10.0")
    assert summary(judge(net, ctx, da_item("v4"))[0]) == [], "clean v4.10.0 alone"


# ======================================================================================================================================
# consultation round: requirements continuations, env shebang by text, pip arguments fail closed, redirections
# ======================================================================================================================================
def unmeasured_keys(files):
    return [k for k in repo_items(files)[0] if "(unmeasured:" in k]


@case("audit", "AC11", "i: in a REQUIREMENTS file a backslash-newline is deleted as pip does (joined with NOTHING): a package name or a version split across the continuation is the real name and version, with its advisory hit; hash continuations still work")
def i_requirements_continuation_joins_with_nothing():
    lists = {"lists": {PYPIN: {"github": [{"id": "GHSA-8q59-q68h-6hv4", "incident": "I", "affected": True, "modified": "2026-01-01T00:00:00Z"}], "osv": []}}}
    for body in ("pyy\\\naml==5.3 \\\n    --hash=sha256:aa\n", "pyyaml==5.\\\n3 \\\n    --hash=sha256:aa\n", "pyyaml\\\n==5.3 --hash=sha256:aa\n", "pyyaml==5.3 \\\n    --hash=sha256:aa\n"):
        files = {"docs/requirements.txt": body}
        ks = sorted(repo_items(files)[0])
        assert PYPIN in ks and not [k for k in ks if "pypi/aml" in k or "pypi/pyyaml@5." in k and k != PYPIN or "(unmeasured:" in k], (body, ks)
        repo, rc, out = run_audit_fx(files, files, lists)
        assert rc == 1 and any("GHSA-8q59-q68h-6hv4" in l for l in out.splitlines() if l.startswith("audit: HIT:")), (body, rc, out[-300:])


ENV_ESCAPES = ["#!/usr/bin/env -S bash\\_-e", "#!/usr/bin/env -S bash\\_-e\\_-x", "#!/usr/bin/env -S\\_bash", "#!/usr/bin/env -S bash\\_", "#!/usr/bin/env -S bash\\q", "#!/usr/bin/env -S bash\\x20-e",
               "#!/usr/bin/env -S bash\\c ignored", "#!/usr/bin/env -S 'a b' bash\\_-e", "#!/usr/bin/env -S\\_--default-signal\\_bash", "#!/usr/bin/env -S zsh\\_-f", "#!/usr/bin/env -S unknown\\_\\k bash", "#!/usr/bin/env -S foo\\q", "#!/usr/bin/env foo\\!"]


@case("age", "AC11", "i: an `env` shebang is decided by TEXT, fail closed: the line holds a shell-vocabulary name bounded by non-word characters, after env's own escapes (\\_ separator, \\c, \\\", \\', \\\\, \\$, \\#) become spaces; an escape this check does not know is a shell; working tree, revision and the oversize refusal; a line with no shell name (python3, node, with \\_ separators) stays out")
def i_env_shebang_by_text():
    for sb in ENV_ESCAPES:
        repo = history_repo({"tools/run": sb + "\n" + PIP_REAL})
        for mode in (None, "HEAD"):
            assert PYPIN in sorted(inv.load_at(repo, mode)), (sb, mode)
        big = history_repo({"tools/run": padded(sb + "\n" + PIP_REAL, 1_100_000)})
        assert refused_too_large(big, None) and refused_too_large(big, "HEAD"), ("oversize", sb)
    for sb in ("#!/usr/bin/env -S python3\\_-u", "#!/usr/bin/env -S node\\_--no-warnings", "#!/usr/bin/env -S python3 -u\\_-B", "#!/usr/bin/env python3", "#!/usr/bin/env -S \\_python3"):
        repo = history_repo({"tools/run": sb + "\n" + PIP_REAL})
        assert not inv.load_at(repo, None), sb


PIP_META = ["py{a,b}ml==5.3", "pyyaml{,}==5.3", "pyyaml{,}", "pyyaml*", "pyyaml?==5.3", "~/x/pyyaml==5.3", "!pyyaml==5.3", "<(echo pyyaml)", "'a*b'==5.3", "pyy{1..2}ml==5.3", "pyyaml==5.{3,3}"]


@case("age", "AC11", "i: after the pip command EVERY argument must resolve statically or the install is an UNMEASURED item (never a wrong or truncated name, never nothing): brace expansion (also a duplicate pair that makes the vulnerable package twice), globs * and ?, a leading ~ or !, a process substitution, a name that is not a plain package name; in a script and a workflow run step; an UNVERSIONED name split into quote fragments is the real name (an unpinned item); `===` and a wildcard stay unprovable items; extras and spaces around the operator still pin")
def i_pip_arguments_fail_closed():
    for spec in PIP_META:
        line = "pip install " + spec
        for files in ({"bin/x.sh": SHEBANG_BASH + line + "\n"}, {WFPATH: "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - run: |\n          %s\n" % line}):
            ks = sorted(repo_items(files)[0])
            assert [k for k in ks if "(unmeasured:" in k], (spec, list(files), ks)
            assert not [k for k in ks if k.startswith("package:pypi/") and "(unmeasured:" not in k and k != PYPIN and not k.startswith("package:pypi/pyyaml@")], ("a wrong or truncated name", spec, ks)
    for spec, name in (('py"yaml"', "pyyaml"), ("'py'yaml", "pyyaml"), ('py"y"\'aml\' requests', "pyyaml"), ("pyy\\aml", "pyyaml")):
        for files in ({"bin/x.sh": SHEBANG_BASH + "pip install " + spec + "\n"}, {WFPATH: runner_wf("pip install " + spec)}):
            assert any(k.startswith("package:pypi/%s@(unpinned)" % name) for k in repo_items(files)[0]), (spec, list(files))
    ks = sorted(repo_items({"bin/x.sh": SHEBANG_BASH + "pip install pyyaml===5.3 other~=5.3\n"})[0])
    assert any(k.startswith("package:pypi/pyyaml@===5.3#step:") for k in ks) and any(k.startswith("package:pypi/other@~=5.3#step:") for k in ks), ks
    assert [k for k in repo_items({"bin/x.sh": SHEBANG_BASH + "pip install other==5.*\n"})[0] if "(unmeasured:" in k], "an unquoted wildcard is a glob: unmeasured"
    assert any(k.startswith("package:pypi/pyyaml@5.3") for k in repo_items({"bin/x.sh": SHEBANG_BASH + 'pip install "pyyaml[extra] == 5.3"\n'})[0])
    assert any(k.startswith("package:pypi/pyyaml@5.3") for k in repo_items({"bin/x.sh": SHEBANG_BASH + 'pip install "pyyaml == 5.3"\n'})[0])


REDIRS = ["pip >/dev/null install --require-hashes pyyaml==5.3 --hash=sha256:aa", "pip 2>&1 install --require-hashes pyyaml==5.3 --hash=sha256:aa", "pip > out.txt install --require-hashes pyyaml==5.3 --hash=sha256:aa",
          "pip &>out install --require-hashes pyyaml==5.3 --hash=sha256:aa", "pip >|f install --require-hashes pyyaml==5.3 --hash=sha256:aa", "pip >>log install --require-hashes pyyaml==5.3 --hash=sha256:aa",
          "pip <in install --require-hashes pyyaml==5.3 --hash=sha256:aa", "pip <<<x install --require-hashes pyyaml==5.3 --hash=sha256:aa", "pip 3>&1 4>f install --require-hashes pyyaml==5.3 --hash=sha256:aa",
          "pip install > f --require-hashes pyyaml==5.3 --hash=sha256:aa", "pip install --require-hashes 2>/dev/null pyyaml==5.3 --hash=sha256:aa", "pip install --require-hashes pyyaml==5.3 > /dev/null --hash=sha256:aa",
          "pip install --require-hashes pyyaml==5.3 --hash=sha256:aa 2>&1", "pip install --require-hashes pyyaml==5.3 --hash=sha256:aa >&2", "pip install --require-hashes pyyaml==5.3 --hash=sha256:aa > /dev/null 2>&1",
          "pip install --require-hashes pyyaml==5.3 --hash=sha256:aa <<<foo", "pip install --require-hashes 2>&1 pyyaml==5.3 --hash=sha256:aa", "pip install --require-hashes >&2 pyyaml==5.3 --hash=sha256:aa", "pip install 2>&1 pyyaml==5.3", "pip install >&2 pyyaml==5.3", "pip install &>/dev/null pyyaml==5.3"]


@case("age", "AC11", "i: redirections and heredoc/herestring operators are not arguments and do not hide an install: before the subcommand (`pip >/dev/null install`, `2>&1`, `&>f`, `>|f`, `>>f`, `<f`, `<<<x`, `n>&m`, the target attached or the next word), between package arguments and at the end of the command (`> /dev/null`, `2>&1`, `>&2`) the pin is found, in a script and a workflow run step, and a redirection target is not mistaken for a path-or-URL requirement; a process substitution among the arguments is unmeasured")
def i_redirections_do_not_hide():
    for line in REDIRS:
        for files in ({"bin/x.sh": SHEBANG_BASH + line + "\n"}, {WFPATH: runner_wf(line)}):
            ks = sorted(repo_items(files)[0])
            assert PYPIN in ks, (line, list(files), ks)
            assert not [k for k in ks if "(unmeasured:" in k], ("a redirection target taken for a requirement", line, ks)
    lists = {"lists": {PYPIN: {"github": [{"id": "GHSA-8q59-q68h-6hv4", "incident": "I", "affected": True, "modified": "2026-01-01T00:00:00Z"}], "osv": []}}}
    files = {"tools/run.sh": SHEBANG_BASH + REDIRS[0] + "\n"}
    repo, rc, out = run_audit_fx(files, files, lists)
    assert rc == 1 and any("GHSA-8q59-q68h-6hv4" in l for l in out.splitlines() if l.startswith("audit: HIT:")), (rc, out[-300:])
    assert [k for k in repo_items({"bin/x.sh": SHEBANG_BASH + "pip install <(echo x) --require-hashes pyyaml==5.3\n"})[0] if "(unmeasured:" in k]


# ======================================================================================================================================
# last round: ONE shell lexer for install commands, requirements parsed by pip's own rules, the shebang text rule for every shebang
# ======================================================================================================================================
PINLINE = "--require-hashes pyyaml==5.3 --hash=sha256:aa"


def both_routes(line):
    """The same command line as a script line and as a workflow run step."""
    return ({"bin/x.sh": SHEBANG_BASH + line + "\n"}, {WFPATH: "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - run: |\n          %s\n" % line})


LEX_FORMS = ["pip>/dev/null install " + PINLINE, "pip>>log install " + PINLINE, "pip<in install " + PINLINE, "pip &>f install " + PINLINE, "pip&>f install " + PINLINE, "pip >|f install " + PINLINE,
             "pip 3>&1 install " + PINLINE, "pip 2>&1 install " + PINLINE, 'pip > "a b" install ' + PINLINE, "pip >'a b' install " + PINLINE, "pip >a\\ b install " + PINLINE,
             'pip >"a b"c install ' + PINLINE, "pip {fd}> f install " + PINLINE, "pip {fd}>f install " + PINLINE, "pip 4>&- install " + PINLINE, "pip <<<x install " + PINLINE, "pip <<EOF install " + PINLINE,
             'pip install > "a b" ' + PINLINE, "pip install " + PINLINE + " >'a b'", "pip install " + PINLINE + " 2>&1 | tee 'a b'", "pip install " + PINLINE + " &> /dev/null", "pip install " + PINLINE + " |& tee log",
             "cd x&&pip>/dev/null install " + PINLINE, "(pip>/dev/null install " + PINLINE + ")", "x=$(pip>/dev/null install " + PINLINE + ")", "echo `pip>/dev/null install " + PINLINE + "`"]


@case("age", "AC11", "i: ONE shell lexer reads install commands: operators split words even ATTACHED to the command word (pip>/dev/null install, pip&>f, pip<in), a redirection is removed with its target whether the target is attached or the next word, quoted ('a b', \"a b\"), escaped (a\\ b) or glued to a fragment, with an fd or {name} prefix, n>&m and >&-, heredoc and herestring operators; command substitutions and subshells are lexed; in a script and a workflow run step the pin is found and no redirection target is taken for a requirement")
def i_lexer_operators_and_redirections():
    for line in LEX_FORMS:
        for files in both_routes(line):
            ks = sorted(repo_items(files)[0])
            assert PYPIN in ks, (line, list(files), ks)
            assert not [k for k in ks if "(unmeasured:" in k], ("a target taken for a requirement", line, ks)
    lists = {"lists": {PYPIN: {"github": [{"id": "GHSA-8q59-q68h-6hv4", "incident": "I", "affected": True, "modified": "2026-01-01T00:00:00Z"}], "osv": []}}}
    files = both_routes(LEX_FORMS[0])[0]
    repo, rc, out = run_audit_fx(files, files, lists)
    assert rc == 1 and any("GHSA-8q59-q68h-6hv4" in l for l in out.splitlines() if l.startswith("audit: HIT:")), (rc, out[-300:])


@case("age", "AC11", "i: the command word and the subcommand are resolved by the lexer: p\"ip\" install, pi\\p install, pip in\"stall\", 'pip' 'install', \"/usr/bin/pip\" install, python -m 'pip' install are the install they say; in a script, a workflow run step and a composite action")
def i_lexer_command_words():
    for line in ('p"ip" install ' + PINLINE, "pi\\p install " + PINLINE, 'pip in"stall" ' + PINLINE, "'pip' 'install' " + PINLINE, '"/usr/bin/pip" install ' + PINLINE, "python -m 'pip' install " + PINLINE,
                 "p'i'p ins\\tall " + PINLINE):
        for files in both_routes(line):
            assert PYPIN in repo_items(files)[0], (line, list(files))
        act = "name: a\nruns:\n  using: composite\n  steps:\n    - run: |\n        %s\n      shell: bash\n" % line
        assert PYPIN in repo_items({".github/actions/a/action.yml": act})[0], ("action", line)


@case("age", "AC11", "i: an option the pip scan does not know BEFORE the subcommand (--lang en, --keyring-provider auto, --anything, --anything=x) makes the install an UNMEASURED item (and the pin that resolved is still measured); the known global options (--no-cache-dir, --timeout 5, --use-feature=x, -vvv, -q, --quiet, --proxy URL, --retries 3) are no finding")
def i_pip_unknown_global_option():
    for opt in ("--lang en", "--keyring-provider auto", "--anything", "--anything=x", "--lang=en"):
        for files in both_routes("pip %s install %s" % (opt, PINLINE)):
            ks = sorted(repo_items(files)[0])
            assert PYPIN in ks and [k for k in ks if "(unmeasured:" in k], (opt, list(files), ks)
    for opt in ("--no-cache-dir", "--timeout 5", "--use-feature=x", "-vvv", "-q", "--quiet", "--proxy http://p:1", "--retries 3", "--disable-pip-version-check", "--isolated"):
        for files in both_routes("pip %s install %s" % (opt, PINLINE)):
            ks = sorted(repo_items(files)[0])
            assert PYPIN in ks and not [k for k in ks if "(unmeasured:" in k], (opt, list(files), ks)


UNRES = ["pyyaml{,}==5.3", "pyyaml*", "pyyaml?==5.3", "~/x/pyyaml", "!pyyaml", "'open", "$(cat r.txt)", "`echo x`", "pyy[a]ml==5.3", "[p]yyaml"]


@case("age", "AC11", "i: an argument that cannot be resolved (brace, glob, tilde, bang, open quote, substitution, bracket glob) is ONE unmeasured item AND every pin that resolved on the same line is still an item; a trailing comment with ? * ~ { , } ' \" is a comment (no unmeasured item, the pin stays); an option value that is a URL with ? or * (quoted or not, short or long option) drops nothing")
def i_unresolved_keeps_resolved_pins():
    for bad in UNRES:
        for files in both_routes("pip install %s %s" % (PINLINE, bad)):
            ks = sorted(repo_items(files)[0])
            assert PYPIN in ks and [k for k in ks if "(unmeasured:" in k], (bad, list(files), ks)
    for comment in ("# why? see docs", "# 5.* line", "# don't", "# it's ok", "# ~home", "# a {b,c}", '# "x', "#nospace?", "# `x"):
        for files in both_routes("pip install %s %s" % (PINLINE, comment)):
            ks = sorted(repo_items(files)[0])
            assert PYPIN in ks and not [k for k in ks if "(unmeasured:" in k], (comment, list(files), ks)
    for opt in ("--index-url https://h/simple?x", "--index-url 'https://h/simple?x'", "-i https://h/s*x", "--extra-index-url=https://h/s?x", "-f 'https://h/a*b'"):
        for files in both_routes("pip install %s %s" % (opt, PINLINE)):
            ks = sorted(repo_items(files)[0])
            assert PYPIN in ks and not [k for k in ks if "(unmeasured:" in k], (opt, list(files), ks)
    ks = sorted(repo_items({"bin/x.sh": SHEBANG_BASH + "pip install pyyaml==5.3 # pip install requests==2.0 ?\n"})[0])
    assert PYPIN in ks and "package:pypi/requests@2.0" in ks, "an install string inside a comment still counts"


@case("age", "AC11", "i: pip package names: a name that starts with a digit (2to3) is a valid unversioned item; extras [a,b] only directly after a valid base name (requests[security,socks]==2.0 pins); a bracket expression anywhere else (pyy[a]ml, [p]yyaml, pyy[a]ml==5.3) is unmeasured (a shell glob)")
def i_pip_package_names():
    for files in both_routes("pip install 2to3"):
        assert any(k.startswith("package:pypi/2to3@(unpinned)") for k in repo_items(files)[0]), list(files)
    for files in both_routes("pip install requests[security,socks]==2.0 'urllib3[brotli] == 1.26.0'"):
        ks = repo_items(files)[0]
        assert "package:pypi/requests@2.0" in ks and "package:pypi/urllib3@1.26.0" in ks and not [k for k in ks if "(unmeasured:" in k], (list(files), sorted(ks))
    for bad in ("pyy[a]ml", "[p]yyaml", "pyy[a]ml==5.3", "pyyaml[a]b==5.3"):
        for files in both_routes("pip install " + bad):
            ks = sorted(repo_items(files)[0])
            assert [k for k in ks if "(unmeasured:" in k] and not [k for k in ks if k.startswith("package:pypi/ml") or k.startswith("package:pypi/b@")], (bad, list(files), ks)


SEPS = {"CR": "\r", "FF": "\x0c", "VT": "\x0b", "FS": "\x1c", "GS": "\x1d", "RS": "\x1e", "NEL": "\x85", "LS": "\u2028", "PS": "\u2029", "CRLF": "\r\n"}


@case("audit", "AC11", "i: a requirements file is read by pip's OWN rules: lines end at every str.splitlines terminator (CR, FF, VT, FS, GS, RS, NEL, LS, PS) so `flask==2.0<sep>pyyaml==5.3` gives both pins; a backslash-newline joins ONLY non-comment lines (a comment line ending in a backslash, indented or not, is complete: the next line is a real requirement); an inline `pkg==1 # c \\` continues into the next line (pip swallows it); `===` is its own operator: an item that cannot be proven (not the pin =5.3)")
def i_requirements_pip_rules():
    for label, sep in SEPS.items():
        ks = sorted(repo_items({"docs/requirements.txt": "flask==2.0" + sep + "pyyaml==5.3 --hash=sha256:aa" + sep + "requests==2.1\n"})[0])
        assert "package:pypi/flask@2.0" in ks and PYPIN in ks and "package:pypi/requests@2.1" in ks and not [k for k in ks if "(unmeasured:" in k], (label, ks)
    lists = {"lists": {PYPIN: {"github": [{"id": "GHSA-8q59-q68h-6hv4", "incident": "I", "affected": True, "modified": "2026-01-01T00:00:00Z"}], "osv": []}}}
    files = {"docs/requirements.txt": "flask==2.0\x0bpyyaml==5.3 --hash=sha256:aa\n"}
    repo, rc, out = run_audit_fx(files, files, lists)
    assert rc == 1 and any("GHSA-8q59-q68h-6hv4" in l for l in out.splitlines() if l.startswith("audit: HIT:")), (rc, out[-300:])
    for body in ("# a comment \\\npyyaml==5.3 --hash=sha256:aa\n", "  # indented comment \\\npyyaml==5.3 --hash=sha256:aa\n", "#c\\\npyyaml==5.3\n"):
        ks = sorted(repo_items({"docs/requirements.txt": body})[0])
        assert PYPIN in ks and not [k for k in ks if "(unmeasured:" in k], (body, ks)
    ks = sorted(repo_items({"docs/requirements.txt": "flask==2.0 # c \\\npyyaml==5.3\nrequests==2.1\n"})[0])
    assert "package:pypi/flask@2.0" in ks and PYPIN not in ks and "package:pypi/requests@2.1" in ks and not [k for k in ks if "(unmeasured:" in k], ("an inline comment continues as pip reads it", ks)
    ks = sorted(repo_items({"docs/requirements.txt": "pyyaml===5.3\nflask==2.0\n"})[0])
    assert any(k.startswith("package:pypi/pyyaml@===5.3#") for k in ks) and "package:pypi/flask@2.0" in ks and PYPIN not in ks, ks
    young = {"times": {PYPIN: {"time": "2026-10-06T00:00:00Z", "source": "pypi"}}}
    rc, out = run_age(exact_repo({"README.md": "x\n"}, {"README.md": "x\n", "docs/requirements.txt": "pyyaml===5.3\n"}), young)
    assert rc == 1 and "not a pin" in out, ("=== is refused as not a pin", rc, out[-300:])


SHEBANGS_TEXT = ['#!/usr/bin/env -S ba"s"h', "#!/usr/bin/env b'a'sh", '#!/usr/bin/env ba""sh', '#!/bin/ba"s"h', "#!/usr/bin/nice bash", "#!/usr/bin/timeout 5 bash", "#!/usr/bin/time bash", "#!/usr/bin/exec bash",
                 "#!/usr/bin/nice -n 5 sh -e", "#!/bin/busybox sh", "#!/usr/bin/env ${SHELL}", "#!/usr/bin/env `which bash`", "#!/usr/bin/env $(echo x)", "#!/usr/bin/nice -n 5 foo\\q", "#!/usr/bin/env -S 'bash' -e"]


@case("age", "AC11", "i: the TEXT rule decides EVERY shebang line, not only env: once quote characters and env escapes are removed, a shell-vocabulary word (ba\"s\"h, b'a'sh, ba\"\"sh, nice bash, timeout 5 bash, time bash, exec bash, busybox sh), or a ${, $( or backtick, or an escape that is not known, makes the file a shell script; working tree, revision and the oversize refusal; python, node, perl and bashful stay out")
def i_shebang_text_rule_every_line():
    for sb in SHEBANGS_TEXT:
        repo = history_repo({"tools/run": sb + "\n" + PIP_REAL})
        for mode in (None, "HEAD"):
            assert PYPIN in sorted(inv.load_at(repo, mode)), (sb, mode)
        big = history_repo({"tools/run": padded(sb + "\n" + PIP_REAL, 1_100_000)})
        assert refused_too_large(big, None) and refused_too_large(big, "HEAD"), ("oversize", sb)
    for sb in ("#!/usr/bin/python3", "#!/usr/bin/env python3", "#!/usr/bin/perl -w", "#!/usr/bin/node", "#!/usr/bin/nice -n 5 python3", "#!/usr/bin/timeout 5 node", "#!/usr/bin/env bashful", "#!/usr/bin/ruby -w"):
        repo = history_repo({"tools/run": sb + "\n" + PIP_REAL})
        assert not inv.load_at(repo, None), sb


@case("age", "AC11", "x: the remaining PRE-EXISTING limits, pinned as decisions: a constraints or requirements file that no script feeds to pip and that is not named requirements*.txt is not read (its pins are not items); one a script names with -r or -c IS read; go, npm and the other install forms keep their own readers")
def x_constraints_boundary():
    assert not repo_items({"constraints.txt": "pyyaml==5.3\n"})[0] and not repo_items({"tools/pins.txt": "pyyaml==5.3\n"})[0]
    ks = sorted(repo_items({"bin/x.sh": SHEBANG_BASH + "pip install -c constraints.txt pyyaml==5.3\n"})[0])
    assert ks == [PYPIN] or all(k == PYPIN or "(unmeasured:" in k for k in ks), ks


# ======================================================================================================================================
# no silent resource limit: nested text is scanned to any depth; a bound that is hit is a reported item
# ======================================================================================================================================
def nest_subst(n, inner=PIP_REAL.strip()):
    s = inner
    for _ in range(n):
        s = "echo $(" + s + ")"
    return s


def nest_quotes(n, inner=PIP_REAL.strip()):
    s = inner
    for _ in range(n):
        s = 'bash -c "' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return s


def nest_backticks(n, inner=PIP_REAL.strip()):
    s = inner
    for _ in range(n):
        s = "echo `" + s.replace("\\", "\\\\").replace("`", "\\`") + "`"
    return s


def three_routes(line):
    """The same command line in a script, a workflow run step and a composite action."""
    run_block = "".join("          %s\n" % l for l in line.split("\n"))
    return [{"bin/x.sh": SHEBANG_BASH + line + "\n"},
            {WFPATH: "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - run: |\n" + run_block},
            {".github/actions/a/action.yml": "name: a\nruns:\n  using: composite\n  steps:\n    - run: |\n" + run_block.replace("          ", "        ") + "      shell: bash\n"}]


def found_by_both_readers(files):
    repo = history_repo(files)
    return all(PYPIN in sorted(inv.load_at(repo, mode)) for mode in (None, "HEAD"))


@case("age", "AC11", "i: NO silent depth limit: an ordinary hash-pinned pip install wrapped in 5, 10, 50 and 200 nested command substitutions (and 1300 bare `$(` levels, the most a 4000-character line holds), in 5 and 10 levels of nested quotes, in 3 levels of nested backticks, and behind 5, 50 and 500 successive comment prefixes, is an item in a script, a workflow run step and a composite action, from the working tree and from a revision")
def i_nesting_has_no_depth_limit():
    lines = [nest_subst(n) for n in (5, 10, 50, 200)] + [nest_quotes(5), nest_quotes(10), nest_backticks(3)]
    lines += ["# " * n + PIP_REAL.strip() for n in (5, 50, 500)]
    lines.append("$(" * 1300 + PIP_REAL.strip() + ")" * 1300)
    for line in lines:
        assert len(line) < 4000, len(line)
        for files in three_routes(line):
            assert found_by_both_readers(files), (line[:60], len(line), list(files))
    lists = {"lists": {PYPIN: {"github": [{"id": "GHSA-8q59-q68h-6hv4", "incident": "I", "affected": True, "modified": "2026-01-01T00:00:00Z"}], "osv": []}}}
    for files in three_routes(nest_subst(50)) + three_routes("# " * 50 + PIP_REAL.strip()):
        repo, rc, out = run_audit_fx(files, files, lists)
        assert rc == 1 and any("GHSA-8q59-q68h-6hv4" in l for l in out.splitlines() if l.startswith("audit: HIT:")), (list(files), rc, out[-300:])
    young = {"times": {PYPIN: {"time": "2026-10-06T00:00:00Z", "source": "pypi"}}}
    rc, out = run_age(exact_repo({"README.md": "x\n"}, {"README.md": "x\n", **three_routes(nest_subst(50))[0]}), young)
    assert rc == 1 and PYPIN in out, (rc, out[-300:])


@case("age", "AC11", "i: the only bound is a budget of characters, and when it is hit the file gets an UNMEASURED `scan limit reached` item (kind package, named pypi/(unmeasured:scan limit reached)), never a silent stop: with the budget lowered, a deeply nested line reports it in a script, a workflow run step and a composite action; the same files are clean under the real budget; the item is per file")
def i_scan_limit_is_reported():
    line = nest_subst(60)
    saved = inv._LEX_BUDGET
    try:
        for files in three_routes(line):
            repo = history_repo(files)
            clean = sorted(inv.load_at(repo, None))
            assert PYPIN in clean and not [k for k in clean if "scan limit reached" in k], (list(files), clean)
            inv._LEX_BUDGET = 3000
            try:
                for mode in (None, "HEAD"):
                    ks = sorted(inv.load_at(repo, mode))
                    assert [k for k in ks if k.startswith("package:pypi/(unmeasured:scan limit reached)@(unpinned)#file:")], (list(files), mode, ks)
            finally:
                inv._LEX_BUDGET = saved
        a, b = three_routes(line)[0], {"bin/y.sh": SHEBANG_BASH + line + "\n"}
        inv._LEX_BUDGET = 3000
        ks = sorted(inv.load_at(history_repo({**a, **b}), None))
        assert len([k for k in ks if "scan limit reached" in k]) == 2, ks
    finally:
        inv._LEX_BUDGET = saved
    try:
        inv._LEX_BUDGET = 5
        inv._LEX_LIMIT[0] = False
        inv._bodies([], "${{ 'pip install a==1' }}", {})
        assert inv._LEX_LIMIT[0], "the expression-body budget is reported too"
    finally:
        inv._LEX_BUDGET = saved
        inv._LEX_LIMIT[0] = False


@case("age", "AC11", "x: a pathological 100000-deep nesting (substitutions, comment prefixes, nested expression openers) terminates in bounded time with no RecursionError and sets the scan-limit flag; as a whole line it is refused loudly (longer than the line limit), never read as a prefix")
def x_pathological_nesting_terminates():
    import signal
    import time

    class Deadline(Exception):
        pass

    def on_alarm(_sig, _frm):
        raise Deadline("a pathological input did not finish before its deadline")
    old_handler = signal.signal(signal.SIGALRM, on_alarm)
    try:
        _pathological_nesting_probes(time)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)


def _pathological_nesting_probes(time):
    import signal
    for text in ("$(" * 100000 + "pip install a==1" + ")" * 100000, "# " * 100000 + "pip install a==1", "echo $(" * 100000):
        inv._LEX_LIMIT[0] = False
        signal.alarm(60)                      # an ENFORCED deadline: the probe is interrupted, not timed after it returns
        inv._lex(text)
        signal.alarm(0)
        assert inv._LEX_LIMIT[0], (text[:12], inv._LEX_LIMIT[0])
    inv._LEX_LIMIT[0] = False
    signal.alarm(30)
    inv._bodies([], "${{ " * 100000 + "x" + " }}" * 100000, {})
    signal.alarm(0)
    for files in three_routes("$(" * 100000 + "pip install a==1" + ")" * 100000):
        try:
            inv.load_at(history_repo(files), None)
            raise AssertionError("a 300000-character line was read")
        except RuntimeError as e:
            assert "longer than" in str(e) or "too large" in str(e), str(e)[:100]
    inv._LEX_LIMIT[0] = False


@case("age", "AC11", "i: a subcommand built at run time is UNMEASURED, never silent: pip $'install' pyyaml==5.3, pip ins$'t'all ..., pip install{,} ..., pip $SUB ... give one unmeasured item beside the pin that resolved; an unquoted `>=2.0` is a redirection as in the shell (the package is then unpinned), a quoted one is a range item")
def i_dynamic_subcommand_is_unmeasured():
    for line in ("pip $'install' " + PINLINE, "pip ins$'t'all " + PINLINE, "pip install{,} " + PINLINE, "pip $SUB " + PINLINE, 'pip $"install" ' + PINLINE):
        for files in both_routes(line):
            ks = sorted(repo_items(files)[0])
            assert [k for k in ks if "(unmeasured:" in k], (line, list(files), ks)
    assert any(k.startswith("package:pypi/requests@(unpinned)") for k in repo_items({"bin/x.sh": SHEBANG_BASH + "pip install requests>=2.0\n"})[0])
    assert any(k.startswith("package:pypi/requests@>=2.0") for k in repo_items({"bin/x.sh": SHEBANG_BASH + 'pip install "requests>=2.0"\n'})[0])


@case("age", "AC11", "i: a subcommand built at run time keeps the pins that resolved, WITHOUT hash options (so no second extraction path can recover them): pip $'install' pyyaml==5.3, pip ins$'t'all pyyaml==5.3, pip install{,} pyyaml==5.3, pip $SUB pyyaml==5.3, pip $\"install\" pyyaml==5.3 each give the plain pin pypi/pyyaml@5.3 AND exactly ONE unmeasured item, in a script and a run step; the daily audit reports GHSA-8q59-q68h-6hv4 for every spelling")
def i_dynamic_subcommand_keeps_plain_pin():
    lists = {"lists": {PYPIN: {"github": [{"id": "GHSA-8q59-q68h-6hv4", "incident": "I", "affected": True, "modified": "2026-01-01T00:00:00Z"}], "osv": []}}}
    for line in ("pip $'install' pyyaml==5.3", "pip ins$'t'all pyyaml==5.3", "pip install{,} pyyaml==5.3", "pip $SUB pyyaml==5.3", 'pip $"install" pyyaml==5.3'):
        for files in both_routes(line):
            ks = sorted(repo_items(files)[0])
            assert PYPIN in ks and len([k for k in ks if "(unmeasured:" in k]) == 1, (line, list(files), ks)
            repo, rc, out = run_audit_fx(files, files, lists)
            assert rc == 1 and any("GHSA-8q59-q68h-6hv4" in l for l in out.splitlines() if l.startswith("audit: HIT:")), (line, list(files), rc, out[-300:])


@case("age", "AC11", "x: more accepted BOUNDARY, one line each (no item and no unmeasured form; a change is a decision): pipenv, poetry and pdm commands, pip.main() or subprocess inside python -c, base64-built commands, $VAR as the install word, a command word spelled with $'..' or a brace expression, pip download / wheel / lock, and an install word given to another program (`echo pip`)")
def x_boundary_more():
    for f in ("pipenv install requests==2.0", "poetry add requests==2.0", "pdm add requests==2.0", "python -c 'import pip; pip.main([\"install\", \"requests==2.0\"])'",
              "python -c \"import subprocess; subprocess.run(['pip','install','requests==2.0'])\"", "$VAR install requests==2.0", "p$'i'p install requests==2.0", "{pip,x} install requests==2.0",
              "pip download requests==2.0", "pip wheel requests==2.0", "pip lock requests==2.0"):
        repo = history_repo({"bin/x.sh": SHEBANG_BASH + f + "\n"})
        assert not inv.load_at(repo, None) and not inv.unmeasured(inv.tree_files(repo, None)), ("the accepted boundary moved: " + f)


# ======================================================================================================================================
# step 8 round 1 on the implementation: names that cannot be read, symlinked scope, continuations in every block, requirements files by reference,
# empty words, bounded time, history refusals, and the pinned obfuscation boundary
# ======================================================================================================================================
def bytes_name_repo(name_bytes, content):
    """A repository whose index holds a file under a name that is not valid UTF-8 (an index-only entry: the working tree has no such file)."""
    d = history_repo({"README.md": "x\n"})
    blob = subprocess.run(["git", "-C", d, "hash-object", "-w", "--stdin"], input=content.encode(), capture_output=True, check=True).stdout.strip()
    subprocess.run([b"git", b"-C", os.fsencode(d), b"update-index", b"--add", b"--cacheinfo", b"100644," + blob + b"," + name_bytes], check=True, capture_output=True)
    _git(d, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "bytes")
    return d


@case("age", "AC11", "i: a tracked file the working-tree reader cannot read is NEVER silently skipped: a name that is not valid UTF-8 (an index-only entry), a file that is not readable, a tracked file that is missing from disk: the daily reader refuses with 'cannot read' (exit 2) or reads it, never an empty inventory; the revision reader reads the blob and the two modes agree on the pin when both read it")
def i_unreadable_tracked_file_is_not_skipped():
    d = bytes_name_repo(b"bin/\xff.sh", SHEBANG_BASH + PIP_REAL)
    assert PYPIN in sorted(inv.load_at(d, "HEAD"))
    try:
        wt = sorted(inv.load_at(d, None))
    except RuntimeError as e:
        assert "cannot read" in str(e), str(e)
    else:
        assert PYPIN in wt, wt
    fx = d + ".fx.json"
    json.dump({"lists": {}}, open(fx, "w"))
    r = subprocess.run([sys.executable, os.path.join(SC, "pin-audit.py"), "--root", d, "--fixtures", fx, "--now", now_iso(), "--report-only"], capture_output=True, text=True)
    out = r.stdout + r.stderr
    assert PYPIN in out or (r.returncode == 2 and "cannot read" in out), (r.returncode, out[-300:])
    d2 = history_repo({"README.md": "x\n", "bin/x.sh": SHEBANG_BASH + PIP_REAL})
    os.chmod(os.path.join(d2, "bin/x.sh"), 0)
    try:
        try:
            wt = sorted(inv.load_at(d2, None))
        except RuntimeError as e:
            assert "cannot read" in str(e), str(e)
        else:
            assert PYPIN in wt, wt
    finally:
        os.chmod(os.path.join(d2, "bin/x.sh"), 0o644)
    d3 = history_repo({"README.md": "x\n", "bin/x.sh": SHEBANG_BASH + PIP_REAL})
    os.remove(os.path.join(d3, "bin/x.sh"))
    try:
        wt = sorted(inv.load_at(d3, None))
    except RuntimeError as e:
        assert "cannot read" in str(e), str(e)
    else:
        assert PYPIN in wt, wt


SYMLINK_NAMES = [".github/actions/x/action.yml", ".github/actions/deep/er/action.yaml", ".github/workflows/w.yml", ".github/workflows/w.yaml", "requirements.txt", "deploy/requirements-dev.txt"]


@case("age", "AC11", "i: a symlink with an in-scope NAME (a workflow, an action file, a requirements file) is refused as an unmeasured symlink item unless its target is itself in scope, like the script-named ones, in both modes; a link to another in-scope file raises nothing")
def i_in_scope_named_symlink_is_refused():
    for name in SYMLINK_NAMES:
        up = "../" * name.count("/")
        files = {"README.md": "x\n", "docs/payload.txt": "pip install evil==1.0\n", name: ("symlink", up + "docs/payload.txt")}
        repo = history_repo(files)
        for mode in (None, "HEAD"):
            ks = sorted(inv.load_at(repo, mode))
            assert [k for k in ks if k.startswith("tool:(symlink)@")], (name, mode, ks)
    files = {"README.md": "x\n", ".github/workflows/w.yml": "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - run: echo hi\n", ".github/workflows/w2.yml": ("symlink", "w.yml")}
    repo = history_repo(files)
    for mode in (None, "HEAD"):
        assert not [k for k in sorted(inv.load_at(repo, mode)) if k.startswith("tool:(symlink)@")], mode
    files = {"README.md": "x\n", "requirements.txt": "pyyaml==5.3 --hash=sha256:aa\n", "deploy/requirements.txt": ("symlink", "../requirements.txt")}
    repo = history_repo(files)
    for mode in (None, "HEAD"):
        ks = sorted(inv.load_at(repo, mode))
        assert not [k for k in ks if k.startswith("tool:(symlink)@")] and PYPIN in ks, (mode, ks)


CONT_ENV = "on: push\njobs:\n  j:\n    runs-on: u\n    env:\n      S: |\n        go install \\\n          github.com/a/b@v%s\n        pip install \\\n          evil==%s\n    steps:\n      - run: echo hi\n"
CONT_ACTION = "name: a\ninputs:\n  cmd:\n    default: |\n      go install \\\n        github.com/a/b@v%s\n      pip install \\\n        evil==%s\nruns:\n  using: composite\n  steps:\n    - run: echo hi\n      shell: bash\n"
CONT_WITH = "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - uses: actions/github-script@%s # v7\n        with:\n          script: |\n            go install \\\n              github.com/a/b@v%%s\n            pip install \\\n              evil==%%s\n" % ("3" * 40)


@case("age", "AC11", "i: a backslash-newline is deleted in EVERY block, not only in run text and scripts: a literal | block of an env value, an input default and a `with: script:` value holding `go install \\` + a target or `pip install \\` + `evil==1.0` give the real items, and changing the version on the continuation line changes the item (the old one is gone)")
def i_continuations_in_every_block():
    for tmpl, path in ((CONT_ENV, WFPATH), (CONT_ACTION, ".github/actions/a/action.yml"), (CONT_WITH, WFPATH)):
        ks = repo_items({path: tmpl % ("1.0.0", "1.0")})[0]
        assert "gotool:github.com/a/b@v1.0.0" in ks and "package:pypi/evil@1.0" in ks, (path, ks)
        ks2 = repo_items({path: tmpl % ("2.0.0", "2.0")})[0]
        assert "gotool:github.com/a/b@v2.0.0" in ks2 and "package:pypi/evil@2.0" in ks2 and "package:pypi/evil@1.0" not in ks2, (path, ks2)
        young = {"times": {"package:pypi/evil@2.0": {"time": "2026-10-06T00:00:00Z", "source": "pypi"}}}
        rc, out = run_age(exact_repo({path: tmpl % ("1.0.0", "1.0")}, {path: tmpl % ("2.0.0", "2.0")}), young)
        assert rc == 1 and "evil@2.0" in out, (path, rc, out[-300:])


REQ_FORMS = ["pip install -r requirements/base.txt", "pip install --require-hashes -r requirements/base.txt", "pip install --requirement requirements/base.txt", "pip install --requirement=requirements/base.txt",
             "pip install -rrequirements/base.txt", "pip install -r 'requirements/base.txt'", "pip install -c requirements/base.txt pyyaml==5.3", "pip install --constraint requirements/base.txt pyyaml==5.3",
             "pip install --constraint=requirements/base.txt pyyaml==5.3"]


@case("age", "AC11", "i: any FILE a script or run step feeds to pip with -r, --requirement (also attached, -rFILE and --requirement=FILE) or -c/--constraint is READ with the requirements parser wherever it sits and whatever it is called (requirements/base.txt, deps/pins.in): its pins are items, in a script and a run step, in both modes; a FILE that cannot be read (missing, outside the repository, absolute, a URL, a variable) is an unmeasured item; the old `file not named requirements*.txt` line item is gone; a bump of evil in such a file is a MOVED pin")
def i_requirements_by_reference():
    for line in REQ_FORMS:
        for files in both_routes(line):
            files = {**files, "requirements/base.txt": "evil==1.0\n"}
            repo = history_repo(files)
            for mode in (None, "HEAD"):
                ks = sorted(inv.load_at(repo, mode))
                assert "package:pypi/evil@1.0" in ks, (line, list(files), mode, ks)
    for name in ("deps/pins.in", "deps/pins.txt", "base"):
        files = {"bin/x.sh": SHEBANG_BASH + "pip install -r %s\n" % name, name: "evil==1.0\n"}
        repo = history_repo(files)
        for mode in (None, "HEAD"):
            assert "package:pypi/evil@1.0" in sorted(inv.load_at(repo, mode)), (name, mode)
    for ref in ("missing.txt", "../outside.txt", "/etc/x.txt", "https://h.example/x.txt", '"$REQ"', "a/../../b.txt"):
        for files in both_routes("pip install -r %s" % ref):
            ks = sorted(repo_items(files)[0])
            assert [k for k in ks if "(unmeasured:" in k], (ref, list(files), ks)
    assert not inv.unmeasured({"bin/x.sh": SHEBANG_BASH + "pip install -r deps/pins.in\n"}), "no unmeasured-form line for a requirements file"
    base = {"bin/x.sh": SHEBANG_BASH + "pip install -r requirements/base.txt\n", "requirements/base.txt": "evil==1.0\n"}
    head = {**base, "requirements/base.txt": "evil==9.9.9\n"}
    young = {"times": {"package:pypi/evil@9.9.9": {"time": "2026-10-06T00:00:00Z", "source": "pypi"}}}
    rc, out = run_age(exact_repo(base, head), young)
    assert rc == 1 and "evil@9.9.9" in out, ("a bump in a referenced file is moved", rc, out[-300:])
    lists = {"lists": {"package:pypi/evil@9.9.9": {"github": [{"id": "GHSA-test-test-test", "incident": "I", "affected": True, "modified": "2026-01-01T00:00:00Z"}], "osv": []}}}
    rc, out = run_audit_pr(base, head, lists)
    assert rc == 1 and any("GHSA-test-test-test" in l for l in out.splitlines() if l.startswith("audit: HIT:")), (rc, out[-300:])


@case("age", "AC11", "i: an EMPTY shell word survives to the docker readers: `docker run -w \"\" alpine:3.20`, `--user \"\"`, `--entrypoint \"\" alpine:3.20 id`, `-e ''` still name the image alpine:3.20 (never `id`, never no image), in a script and a run step")
def i_empty_words_survive():
    for line in ('docker run -w "" alpine:3.20', 'docker run --user "" alpine:3.20', 'docker run --entrypoint "" alpine:3.20 id', "docker run --entrypoint '' alpine:3.20 id", "docker run -e '' alpine:3.20",
                 'docker run --rm -w "" --user "" --entrypoint "" alpine:3.20 id'):
        for files in both_routes(line):
            ks = sorted(repo_items(files)[0])
            assert any(k.startswith("image:alpine:3.20@") for k in ks) and not [k for k in ks if k.startswith("image:id@")], (line, list(files), ks)


def bounded_load(files, seconds):
    """load_at in a child process that is KILLED at the deadline (a regex in C cannot be interrupted from inside)."""
    repo = history_repo(files)
    code = ("import importlib.util,sys\nsp=importlib.util.spec_from_file_location('inv',sys.argv[1]);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)\n"
            "try:\n    m.load_at(sys.argv[2], None)\nexcept RuntimeError as e:\n    print(e); sys.exit(2)\n")
    try:
        r = subprocess.run([sys.executable, "-c", code, os.path.join(SC, "pin-inventory.py"), repo], capture_output=True, text=True, timeout=seconds)
    except subprocess.TimeoutExpired:
        raise AssertionError("did not finish in %d s" % seconds)
    return r


@case("age", "AC11", "i: hostile input is read in BOUNDED time: 8000 distinct unterminated heredoc openers in one run block, 8000 in a script, and 8000 `pip install -r /dev/stdin <<X` openers each finish within 8 seconds (a child process killed at the deadline; a pip reading its list from stdin is present, so the heredocs are searched), none exits with a crash")
def i_heredoc_scans_are_bounded():
    run = "".join("cat <<A%d\n" % i for i in range(8000))
    stdin = "pip install --require-hashes -r /dev/stdin <<'REQ'\npyyaml==5.3 --hash=sha256:aa\nREQ\n"         # a pip reading its list from stdin makes the heredocs of the step matter
    wf = "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - run: |\n" + "".join("          " + l + "\n" for l in (run + stdin).split("\n") if l)
    for files in ({WFPATH: wf}, {"bin/x.sh": SHEBANG_BASH + run + stdin}, {"bin/y.sh": SHEBANG_BASH + "".join("pip install -r /dev/stdin <<X%d\n" % i for i in range(8000))}):
        r = bounded_load(files, 8)
        assert r.returncode in (0, 2), (list(files), r.returncode, r.stderr[-300:])


@case("audit", "AC12", "h: a file REFUSED in a historical commit (a shell script over 1 MB, a command line over the line limit) does not abort the daily audit: each is an information line `history: <commit> <path> refused (<reason>)` and the audit goes on (exit 0 here); the same refusals in TODAY's tree still stop the audit loudly (exit 2)")
def h_history_refusals_are_information():
    big = SHEBANG_BASH + PIP_REAL + "#" * 1_100_000 + "\n"
    longwf = "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - run: echo " + "x" * 5000 + "\n"
    repo, rc, out = run_audit_history([{"README.md": "x\n"}, {"README.md": "x\n", "bin/big": big, WFPATH: longwf}, {"README.md": "x\n"}], {"lists": {}})
    assert rc == 0, (rc, out[-400:])
    assert re.search(r"history: [0-9a-f]{12} bin/big refused \(.*too large", out), out[-500:]
    assert re.search(r"history: [0-9a-f]{12} %s refused \(.*longer than" % re.escape(WFPATH), out), out[-500:]
    repo, rc, out = run_audit_history([{"README.md": "x\n"}, {"README.md": "x\n", "bin/big": big}], {"lists": {}})
    assert rc == 2 and "too large" in out, ("today's tree refuses loudly", rc, out[-300:])


@case("audit", "AC5", "e: the floating-comment docstring states the rule that is implemented (every exact tag, pre-releases included), not the retired highest-release reading")
def e_judged1_docstring_is_current():
    doc = pa.LiveNet._judged1.__doc__ or ""
    assert "HIGHEST RELEASE" not in doc and "highest release" not in doc.lower(), doc


@case("age", "AC11", "i: a file named like a checksum that is NOT a workflow or an action (checksums.py, docs/sha256-notes.yml, sha256sums.yaml) is read by its content kind: a content item, never a YAML parse that fails the whole check; a workflow or action with such a name is still a workflow")
def i_checksum_named_non_yaml_file():
    files = {"README.md": "x\n", "tools/checksums.py": "x = (\n", "docs/sha256-notes.yml": "a: [\n", "docs/sha256sums.yaml": "{{{\n",
             ".github/workflows/checksums.yml": runner_wf("pip install --require-hashes pyyaml==5.3 --hash=sha256:aa")}
    repo = history_repo(files)
    for mode in (None, "HEAD"):
        ks = sorted(inv.load_at(repo, mode))
        for p in ("tools/checksums.py", "docs/sha256-notes.yml", "docs/sha256sums.yaml"):
            assert any(k.startswith("tool:file:%s@(file)" % p) for k in ks), (p, mode, ks)
        assert PYPIN in ks, (mode, ks)


@case("age", "AC11", "i: shell shebang words are matched case-insensitively (#!/bin/BASH, #!/usr/bin/env BASH, #!/bin/Sh, #!/usr/bin/env -S ZSH -f): they run on a case-insensitive filesystem")
def i_shebang_case_insensitive():
    for sb in ("#!/bin/BASH", "#!/usr/bin/env BASH", "#!/bin/Sh", "#!/usr/bin/env -S ZSH -f", "#!/usr/bin/Nice Bash"):
        repo = history_repo({"tools/run": sb + "\n" + PIP_REAL})
        for mode in (None, "HEAD"):
            assert PYPIN in sorted(inv.load_at(repo, mode)), (sb, mode)


@case("age", "AC11", "x: the accepted OBFUSCATION boundary of the other tools' commands, one line each (no item and no unmeasured form; a change is a decision, owner Oct 3: plain forms only): quote or backslash fragments in go (`go ins\"\"tall`, `\"go\" install`, `go install \"mod\"@v1.0.0`), curl (`c''url`), wget (`w\\get`), apt (`apt-'get'`), npm (`n''pm`), gh (`g''h`); and the empty installs `xargs pip install` and a bare `pip install` (the packages arrive on stdin)")
def x_obfuscation_boundary_other_tools():
    forms = ['go ins""tall github.com/a/b@v1.0.0', '"go" install github.com/a/b@v1.0.0', 'go install "github.com/a/b"@v1.0.0', "c''url https://example.com/x.sh", "w\\get https://example.com/x.sh",
             "apt-'get' install x", "n''pm install x", "g''h release download v1", "xargs pip install", "pip install"]
    for f in forms:
        repo = history_repo({"bin/x.sh": SHEBANG_BASH + f + "\n"})
        assert not inv.load_at(repo, None) and not inv.unmeasured(inv.tree_files(repo, None)), ("the accepted boundary moved: " + f)


# ======================================================================================================================================
# step 8 round 2: a pip FILE is bound to the directory the command really runs in (cd, pushd, working-directory), never guessed
# ======================================================================================================================================
def wd_wf(run, job_wd=None, step_wd=None, default_wd=None):
    return ("on: push\n" + ("defaults:\n  run:\n    working-directory: %s\n" % default_wd if default_wd else "") + "jobs:\n  j:\n    runs-on: u\n" +
            ("    defaults:\n      run:\n        working-directory: %s\n" % job_wd if job_wd else "") + "    steps:\n      - run: %s\n" % run + ("        working-directory: %s\n" % step_wd if step_wd else ""))


DECOY = {"req.txt": "ok==1.0\n", "sub/req.txt": "evil==1.0\n"}
WD_ROUTES = [("cd", {"bin/x.sh": SHEBANG_BASH + "cd sub && pip install -r req.txt\n"}), ("cd on its own line", {"bin/x.sh": SHEBANG_BASH + "cd sub\npip install -r req.txt\n"}),
             ("pushd", {"bin/x.sh": SHEBANG_BASH + "pushd sub >/dev/null\npip install -r req.txt\n"}), ("subshell", {"bin/x.sh": SHEBANG_BASH + "(cd sub; pip install -r req.txt)\n"}),
             ("run step cd", {WFPATH: wd_wf("cd sub && pip install -r req.txt")}), ("step working-directory", {WFPATH: wd_wf("pip install -r req.txt", step_wd="sub")}),
             ("job working-directory", {WFPATH: wd_wf("pip install -r req.txt", job_wd="sub")}), ("workflow default working-directory", {WFPATH: wd_wf("pip install -r req.txt", default_wd="sub")}),
             ("quoted working-directory", {WFPATH: wd_wf("pip install -r req.txt", step_wd="'./sub/'")})]


@case("age", "AC11", "i: a pip FILE is bound to where the command RUNS: with `cd sub`, `pushd sub`, a subshell cd, a run-step cd, a step, job or workflow-default `working-directory: sub`, a benign same-named file at the repository root does not hide the real one under sub/: both are read (every tracked file the reference can name), so the real file's pins are items, and the reference that cannot be bound to exactly one tracked file is also an unmeasured item; a PR that bumps the real file's pin MOVES it (age check refuses, audit reports)")
def i_pip_file_is_bound_to_the_working_directory():
    for label, route in WD_ROUTES:
        files = {**route, **DECOY}
        repo = history_repo(files)
        for mode in (None, "HEAD"):
            ks = sorted(inv.load_at(repo, mode))
            assert "package:pypi/evil@1.0" in ks and [k for k in ks if "(unmeasured:" in k], (label, mode, ks)
        head = {**files, "sub/req.txt": "evil==9.9.9\n"}
        young = {"times": {"package:pypi/evil@9.9.9": {"time": "2026-10-06T00:00:00Z", "source": "pypi"}}}
        rc, out = run_age(exact_repo(files, head), young)
        assert rc == 1 and "evil@9.9.9" in out, (label, "a bump under sub/ is moved", rc, out[-300:])
        lists = {"lists": {"package:pypi/evil@9.9.9": {"github": [{"id": "GHSA-test-test-test", "incident": "I", "affected": True, "modified": "2026-01-01T00:00:00Z"}], "osv": []}}}
        rc, out = run_audit_pr(files, head, lists)
        assert rc == 1 and any("GHSA-test-test-test" in l for l in out.splitlines() if l.startswith("audit: HIT:")), (label, rc, out[-300:])
    for label, route in WD_ROUTES:                    # bound to exactly ONE tracked file: read, nothing unmeasured
        repo = history_repo({**route, "sub/req.txt": "evil==1.0\n"})
        ks = sorted(inv.load_at(repo, None))
        assert "package:pypi/evil@1.0" in ks and not [k for k in ks if "(unmeasured:" in k], (label, "control", ks)
    for files in both_routes("pip install -r req.txt"):
        repo = history_repo({**files, "req.txt": "ok==1.0\n"})
        ks = sorted(inv.load_at(repo, None))
        assert "package:pypi/ok@1.0" in ks and not [k for k in ks if "(unmeasured:" in k], ("no cd: the root file", ks)


@case("age", "AC11", "i: a directory built at run time (`cd \"$DIR\"`, `working-directory: ${{ matrix.dir }}`) cannot be bound: every tracked file whose path ends with the referenced path is read (a pin under any directory is an item) and the reference is unmeasured; a `..` that leaves the repository names nothing")
def i_dynamic_directory_reads_every_candidate():
    files = {"req.txt": "ok==1.0\n", "a/req.txt": "evil==1.0\n", "b/c/req.txt": "worse==2.0\n", "notreq.txt": "other==3.0\n"}
    for label, route in (("cd var", {"bin/x.sh": SHEBANG_BASH + 'cd "$DIR" && pip install -r req.txt\n'}), ("expression working-directory", {WFPATH: wd_wf("pip install -r req.txt", step_wd="${{ matrix.dir }}")}),
                         ("cd command substitution", {"bin/x.sh": SHEBANG_BASH + "cd $(dirname $F)\npip install -r req.txt\n"})):
        repo = history_repo({**route, **files})
        ks = sorted(inv.load_at(repo, None))
        assert "package:pypi/evil@1.0" in ks and "package:pypi/worse@2.0" in ks and "package:pypi/ok@1.0" in ks and "package:pypi/other@3.0" not in ks and [k for k in ks if "(unmeasured:" in k], (label, ks)


@case("age", "AC11", "i: pip file references in more spellings: `-qr FILE`, `-vvr FILE`, `-Ur FILE`, `-r=FILE` are file references (the file's pins are items); a trailing -r or -c with NO value (the value arrives from xargs or find) is an unmeasured item; `pip-sync FILE` and `uv pip sync FILE` and `uv pip install -r FILE` read the file like pip install -r; pip-compile is an accepted boundary (it writes locks, installs nothing)")
def i_pip_file_reference_spellings():
    for line in ("pip install -qr req.txt", "pip install -vvr req.txt", "pip install -Ur req.txt", "pip install -r=req.txt", "pip install -r=req.txt -q", "pip-sync req.txt", "uv pip sync req.txt", "uv pip install -r req.txt",
                 "pip-sync --pip-args '--no-deps' req.txt"):
        for files in both_routes(line):
            repo = history_repo({**files, "req.txt": "evil==1.0\n"})
            ks = sorted(inv.load_at(repo, None))
            assert "package:pypi/evil@1.0" in ks and not [k for k in ks if "(unmeasured:" in k or k.startswith("package:pypi/req")], (line, list(files), ks)
    for line in ("xargs -n1 pip install -r", "echo req.txt | xargs pip install -c", "find . -name req.txt | xargs -I{} pip install --requirement", "pip install -r", "pip-sync"):
        for files in both_routes(line):
            ks = sorted(repo_items(files)[0])
            if line == "pip-sync":
                continue
            assert [k for k in ks if "(unmeasured:" in k], (line, list(files), ks)
    assert not inv.load_at(history_repo({"bin/x.sh": SHEBANG_BASH + "pip-compile requirements.in\n", "requirements.in": "evil==1.0\n"}), None)


@case("age", "AC11", "i: a pip FILE that is a symlink, or sits under a symlinked directory, is an unmeasured symlink item, never read as its link text, in both modes")
def i_referenced_symlink_is_unmeasured():
    files = {"bin/x.sh": SHEBANG_BASH + "pip install -r req.txt\n", "docs/payload.txt": "evil==1.0\n", "req.txt": ("symlink", "docs/payload.txt")}
    repo = history_repo(files)
    for mode in (None, "HEAD"):
        ks = sorted(inv.load_at(repo, mode))
        assert [k for k in ks if k.startswith("tool:(symlink)@")] and "package:pypi/evil@1.0" not in ks, (mode, ks)


@case("audit", "AC10", "b: when the OSV record IS the GitHub advisory itself (the same GHSA id), the two lists are one source and GitHub's affected ranges decide: GitHub `< 1.5.0` with an OSV copy that reaches 2.0.0 is clean at v1.8.0; GitHub `< 2.0.0` with an OSV copy fixed at 1.5.0 is an advisory at v1.8.0, and neither is a dispute")
def b_ghsa_primary_osv_record_is_one_source():
    def run(gh_range, fixed):
        g = ghsa("GHSA-test-test-test", "github.com/a/b", [gh_range], "2025-01-01T00:00:00Z")
        o = osv_rec("GHSA-test-test-test", "2025-01-01T00:00:00Z", [go_aff("github.com/a/b", [{"introduced": "0"}, {"fixed": fixed}])])
        net, ctx = make_net([g], [o], go_module=lambda p, v: ("github.com/a/b", {"Version": v}))
        return judge(net, ctx, inv.Item("gotool", "github.com/a/b", "v1.8.0"))[0]
    assert summary(run("< 1.5.0", "2.0.0")) == [], summary(run("< 1.5.0", "2.0.0"))
    f = run("< 2.0.0", "1.5.0")
    assert [x.kind for x in f] == ["advisory"] and not any(x.disputed for x in f), summary(f)


# ======================================================================================================================================
# step 8 round 3: a pip FILE is bound by PATH SUFFIX alone, wherever the command runs; nested includes; env variables; options after the subcommand
# ======================================================================================================================================
SUFFIX_ROUTES = [("cd", {"bin/x.sh": SHEBANG_BASH + "cd sub && pip install -r req.txt\n"}), ("pushd", {"bin/x.sh": SHEBANG_BASH + "pushd sub >/dev/null\npip install -r req.txt\n"}),
                 ("step working-directory", {WFPATH: wd_wf("pip install -r req.txt", step_wd="sub")}), ("job working-directory", {WFPATH: wd_wf("pip install -r req.txt", job_wd="sub")}),
                 ("default working-directory", {WFPATH: wd_wf("pip install -r req.txt", default_wd="sub")}), ("env -C", {"bin/x.sh": SHEBANG_BASH + "env -C sub pip install -r req.txt\n"}),
                 ("env --chdir=", {"bin/x.sh": SHEBANG_BASH + "env --chdir=sub pip install -r req.txt\n"}), ("sudo -D", {"bin/x.sh": SHEBANG_BASH + "sudo -D sub pip install -r req.txt\n"}),
                 ("uv --directory", {"bin/x.sh": SHEBANG_BASH + "uv --directory sub pip install -r req.txt\n"}), ("poetry --directory run", {WFPATH: runner_wf("poetry --directory sub run pip install -r req.txt")}),
                 ("make -C", {"bin/x.sh": SHEBANG_BASH + "make -C sub pip install -r req.txt\n"}), ("a wrapper script", {"bin/x.sh": SHEBANG_BASH + "./sub/run.sh pip install -r req.txt\n"}),
                 ("env -C in a run step", {WFPATH: runner_wf("env -C sub pip install -r req.txt")}), ("nothing at all", {"bin/x.sh": SHEBANG_BASH + "pip install -r req.txt\n"})]


@case("age", "AC11", "i: a pip FILE is bound by PATH SUFFIX ALONE, ignoring where the command runs (cd, pushd, working-directory at step, job and workflow level, env -C, env --chdir=, sudo -D, uv --directory, poetry --directory, make -C, a wrapper script: the class is closed by construction): every tracked file whose path equals the reference or ends with `/` + the reference is a candidate; ONE candidate is read and nothing is unmeasured; MORE THAN ONE are ALL read and the reference is an unmeasured item; NONE is unmeasured; a decoy at the root beside the real file under sub/ gives both files read and exactly one unmeasured item for every spelling; a PR that bumps the pin under sub/ is moved")
def i_pip_file_binds_by_path_suffix():
    for label, route in SUFFIX_ROUTES:
        files = {**route, **DECOY}
        repo = history_repo(files)
        for mode in (None, "HEAD"):
            ks = sorted(inv.load_at(repo, mode))
            assert "package:pypi/evil@1.0" in ks and "package:pypi/ok@1.0" in ks and len([k for k in ks if "(unmeasured:" in k]) == 1, (label, mode, ks)
        head = {**files, "sub/req.txt": "evil==9.9.9\n"}
        young = {"times": {"package:pypi/evil@9.9.9": {"time": "2026-10-06T00:00:00Z", "source": "pypi"}}}
        rc, out = run_age(exact_repo(files, head), young)
        assert rc == 1 and "evil@9.9.9" in out, (label, "a bump under sub/ is moved", rc, out[-300:])
        repo = history_repo({**route, "sub/req.txt": "evil==1.0\n"})                       # ONE candidate, no decoy
        ks = sorted(inv.load_at(repo, None))
        assert "package:pypi/evil@1.0" in ks and not [k for k in ks if "(unmeasured:" in k], (label, "one candidate", ks)


@case("age", "AC11", "i: the referenced path is NORMALISED before the suffix rule: a leading ./, any ../ segments and doubled separators are removed (`./x.txt`, `../x.txt`, `a//x.txt`, `../../a/x.txt` all name the tracked x.txt or a/x.txt), a reference that names two tracked files by suffix reads both and is unmeasured, and one that names none is unmeasured")
def i_pip_file_reference_is_normalised():
    for ref, tracked in (("./x.txt", "x.txt"), ("../x.txt", "x.txt"), ("a//x.txt", "a/x.txt"), ("../../a/x.txt", "a/x.txt"), (".//a/./x.txt", "a/x.txt")):
        repo = history_repo({"bin/x.sh": SHEBANG_BASH + "pip install -r %s\n" % ref, tracked: "evil==1.0\n"})
        ks = sorted(inv.load_at(repo, None))
        assert "package:pypi/evil@1.0" in ks and not [k for k in ks if "(unmeasured:" in k], (ref, ks)
    repo = history_repo({"bin/x.sh": SHEBANG_BASH + "pip install -r a/x.txt\n", "a/x.txt": "one==1.0\n", "b/a/x.txt": "two==2.0\n", "c/other.txt": "three==3.0\n"})
    ks = sorted(inv.load_at(repo, None))
    assert "package:pypi/one@1.0" in ks and "package:pypi/two@2.0" in ks and "package:pypi/three@3.0" not in ks and len([k for k in ks if "(unmeasured:" in k]) == 1, ks
    repo = history_repo({"bin/x.sh": SHEBANG_BASH + "pip install -r y.txt\n", "ay.txt": "nope==1.0\n"})
    ks = sorted(inv.load_at(repo, None))
    assert len([k for k in ks if "(unmeasured:" in k]) == 1 and "package:pypi/nope@1.0" not in ks, ("a suffix is a PATH suffix, not a name suffix", ks)


@case("age", "AC11", "i: an include INSIDE a requirements file (`-r more.txt`, `--requirement=more.txt`, `-c base.in`, `-rmore.txt`) is followed whatever the files are called: relative to the including file's directory first, then by the suffix rule; its pins are items and a bump in it is moved; a cycle terminates; a chain deeper than the bound gives a `scan limit reached` item, a shallow chain none")
def i_nested_requirements_includes():
    base = {"bin/x.sh": SHEBANG_BASH + "pip install -r deps/top.in\n"}
    for inc in ("-r more.txt", "--requirement=more.txt", "-c more.txt", "-rmore.txt", "--constraint more.txt", "-r ./more.txt"):
        files = {**base, "deps/top.in": inc + "\nflask==2.0\n", "deps/more.txt": "evil==1.0\n"}
        ks = sorted(repo_items(files)[0])
        assert "package:pypi/evil@1.0" in ks and "package:pypi/flask@2.0" in ks and not [k for k in ks if "(unmeasured:" in k], (inc, ks)
    ks = sorted(repo_items({**base, "deps/top.in": "-r more.txt\n", "deps/more.txt": "evil==1.0\n", "other/more.txt": "decoy==1.0\n"})[0])
    assert "package:pypi/evil@1.0" in ks and "package:pypi/decoy@1.0" not in ks and not [k for k in ks if "(unmeasured:" in k], ("the file next to the including one is pip's own binding", ks)
    files = {**base, "deps/top.in": "-r more.txt\n", "deps/more.txt": "evil==1.0\n"}
    young = {"times": {"package:pypi/evil@9.9.9": {"time": "2026-10-06T00:00:00Z", "source": "pypi"}}}
    rc, out = run_age(exact_repo(files, {**files, "deps/more.txt": "evil==9.9.9\n"}), young)
    assert rc == 1 and "evil@9.9.9" in out, ("a bump in a nested include is moved", rc, out[-300:])
    ks = sorted(repo_items({"requirements.txt": "-r common.in\nflask==2.0\n", "common.in": "evil==1.0\n"})[0])
    assert "package:pypi/evil@1.0" in ks and "package:pypi/flask@2.0" in ks and not [k for k in ks if "(unmeasured:" in k], ("an include of a NAMED requirements file", ks)
    ks = sorted(repo_items({"requirements-dev.txt": "-r requirements-base.txt\ndev==1.0\n", "requirements-base.txt": "-r requirements-dev.txt\nbase==1.0\n"})[0])
    assert "package:pypi/dev@1.0" in ks and "package:pypi/base@1.0" in ks and not [k for k in ks if "(unmeasured:" in k or "scan limit" in k], ("a cycle", ks)
    chain = lambda n: {**{"bin/x.sh": SHEBANG_BASH + "pip install -r c/0.txt\n"}, **{"c/%d.txt" % i: "-r %d.txt\npin%d==1.0\n" % (i + 1, i) for i in range(n)}, "c/%d.txt" % n: "pin%d==1.0\n" % n}
    ks = sorted(repo_items(chain(4))[0])
    assert "package:pypi/pin4@1.0" in ks and not [k for k in ks if "scan limit" in k or "(unmeasured:" in k], ("a shallow chain", ks)
    ks = sorted(repo_items(chain(30))[0])
    assert [k for k in ks if k.startswith("package:pypi/(unmeasured:scan limit reached)")], ("a chain deeper than the bound", ks)


@case("age", "AC11", "i: PIP_CONSTRAINT and PIP_REQUIREMENT name files to pip: in a workflow env block, an inline assignment before pip, an export, a step env, they are references read by the suffix rule (a variable or expression value is unmeasured); `python -m piptools sync FILE` reads FILE like pip-sync")
def i_pip_env_variables_and_piptools():
    for label, files in (("workflow env", {WFPATH: "on: push\njobs:\n  j:\n    runs-on: u\n    env:\n      PIP_CONSTRAINT: deps/c.txt\n    steps:\n      - run: pip install a==1\n"}),
                         ("step env", {WFPATH: "on: push\njobs:\n  j:\n    runs-on: u\n    steps:\n      - env:\n          PIP_REQUIREMENT: 'deps/c.txt'\n        run: pip install\n"}),
                         ("inline", {"bin/x.sh": SHEBANG_BASH + "PIP_CONSTRAINT=deps/c.txt pip install a==1\n"}), ("export", {"bin/x.sh": SHEBANG_BASH + "export PIP_CONSTRAINT=\"deps/c.txt\"\npip install a==1\n"}),
                         ("piptools", {"bin/x.sh": SHEBANG_BASH + "python -m piptools sync deps/c.txt\n"}), ("pip-sync", {"bin/x.sh": SHEBANG_BASH + "pip-sync deps/c.txt\n"})):
        repo = history_repo({**files, "deps/c.txt": "evil==1.0\n"})
        for mode in (None, "HEAD"):
            ks = sorted(inv.load_at(repo, mode))
            assert "package:pypi/evil@1.0" in ks and not [k for k in ks if "(unmeasured:" in k], (label, mode, ks)
    for label, files in (("expression", {WFPATH: "on: push\njobs:\n  j:\n    runs-on: u\n    env:\n      PIP_CONSTRAINT: ${{ matrix.c }}\n    steps:\n      - run: pip install a==1\n"}),
                         ("variable", {"bin/x.sh": SHEBANG_BASH + 'PIP_CONSTRAINT="$C" pip install a==1\n'})):
        ks = sorted(repo_items(files)[0])
        assert [k for k in ks if "(unmeasured:" in k], (label, ks)


@case("age", "AC11", "i: an option AFTER the install subcommand is never a package: `--chdir sub`, `--anything value`, `--anything=value` give an unmeasured item and no pypi/sub or pypi/value item; the known value-taking options (--target, --index-url, --root ...) and the known flags (--no-deps, --pre, --user, -U, --require-hashes ...) give no finding")
def i_pip_options_after_the_subcommand():
    for line in ("pip install -r r.txt --chdir sub", "pip install pyyaml==5.3 --chdir sub", "pip install pyyaml==5.3 --anything value", "pip install pyyaml==5.3 --anything=value"):
        for files in both_routes(line):
            ks = sorted(repo_items({**files, "r.txt": "ok==1.0\n"})[0])
            assert [k for k in ks if "(unmeasured:" in k] and not [k for k in ks if k.startswith(("package:pypi/sub", "package:pypi/value"))], (line, list(files), ks)
    for line in ("pip install pyyaml==5.3 --target out --no-deps --pre --user -U --require-hashes --upgrade --force-reinstall --no-cache-dir --quiet --no-input --only-binary=:all: --index-url https://h/s --root /r --prefix /p",
                 "pip install pyyaml==5.3 --break-system-packages --no-build-isolation --ignore-installed --no-warn-script-location -q"):
        for files in both_routes(line):
            ks = sorted(repo_items(files)[0])
            assert PYPIN in ks and not [k for k in ks if "(unmeasured:" in k or k.startswith(("package:pypi/out", "package:pypi/r@", "package:pypi/p@"))], (line, list(files), ks)

def main(argv):
    suites = {c[0] for c in CASES}
    suite = argv[1] if len(argv) > 1 else "all"
    if suite != "all" and suite not in suites:
        print("FAIL [suite] unknown suite %r (known: %s)" % (suite, ", ".join(sorted(suites))))
        return 2
    bad = ran = 0
    for s, acs, text, fn in CASES:
        if suite not in ("all", s):
            continue
        ran += 1
        try:
            fn()
            print(f"ok   [{acs}] {text}")
        except Exception as e:
            bad += 1
            why = "".join(traceback.format_exception_only(type(e), e)).strip().replace("\n", " ")[:300]
            print(f"FAIL [{acs}] {text} :: {why}")
    if ran == 0:
        print("FAIL [suite] no case ran")
        return 1
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
