#!/usr/bin/env bash
# proves: REQ-SUP-001-AC14
# The Go-module major-path rule of the supply-chain audit (advisor-approved read-back Oct 9, "pin-audit Go major path"; tests first, RED until
# .github/agent/supply-chain/pin-audit.py implements the rule; step-5 rulings, advisor-accepted Oct 9, are built in). Go's own module-path rule: a version
# vN.x with N >= 2 belongs to the module path that ends in /vN; versions 0.x and 1.x belong to the bare path. An OSV `affected` entry for any other path
# says nothing about the pinned version. Without the rule the Go database's bare-path entry "affected from 0, no fix" makes every cosign 3.x a hit.
#
# What the tests pin down (offline: the databases are replaced by recorded live records and a gh stub):
#   * The rule covers OSV `affected` entries ONLY. GitHub's own ranges decide as GitHub files them: GitHub files cosign v3 ranges under the BARE path
#     (GHSA-w6c6-c85g-mmv6, GHSA-wfqv-66vq-46rm), so GitHub's names and its paged list query are matched under BOTH the bare path and the /vMAJOR path.
#   * OSV is queried by the /vMAJOR path as well as the bare path (advisor-accepted at step 5): a record that has ONLY a /v3 entry covering the pin is a hit.
#   * It applies only to a tool in pin-audit.py's committed table GO_TOOLS whose version is a plain MAJOR.MINOR.PATCH (a leading lowercase v allowed).
#     Cases the rule cannot settle FAIL CLOSED, they are a HIT: a table path that is bare while the pinned major is 2 or more or
#     that ends in a different /vN (the audit then queries bare and /vMAJOR and hits if any entry covers the version), a record with no exact entry, a
#     path-less entry next to an exact entry, and a lookalike path (host case, trailing slash). Only these keep the OLD verdict, nothing ignored:
#     an unparsable version, a tool
#     not in the table, other item kinds (gotool, owner/repo), and a /v0 or /v1 entry in a record for a major 0/1 pin (the one exception: a Go major
#     0/1 path has no suffix, so /v0 and /v1 entries are not the exact path and are left to the old filter).
#   * The entry whose path is EXACTLY <bare>/vN (N >= 2) or EXACTLY <bare> (N <= 1) decides; every other entry is ignored and LOGGED. With no exact entry,
#     or with a path-less entry in the record, nothing can be concluded: the verdict stays a HIT.
#   * Logging is part of the interface (PROPOSED names): LiveNet.ignored_entries is a list of {"id", "path", "reason"}, one per ignored entry; judge()
#     adds exactly one note per entry ("ignored advisory entry <id> <path>: <reason>"). An implementation that runs two queries (bare and /vMAJOR) must
#     de-duplicate that list. The notes are printed sanitised and must not be counted in "N disputed hit(s) covered by a checked-in exception".
# Finding recorded for the implementer: with the corrected GO_TOOLS paths the existing code already clears cosign 3.1.3 through the package-name filter of
# LiveNet._osv_says. The real work is (1) the corrected table, (2) GitHub names matched under both paths so the five existing rulings keep working,
# (3) the log of ignored entries, (4) the OSV /vMAJOR query.
# The recorded live data (read 2026-10-09T23:51Z from https://api.osv.dev/v1/vulns/<id> and `gh api advisories/<ghsa>`) is in
# .github/agent/fixtures/pin-audit-go-major/ (six cosign advisories: GO-2026-4309 and the five already ruled on in .github/supply-chain-exceptions.json).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
aud="$here/../supply-chain/pin-audit.py"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0 EXPECT=39
ok()  { pass=$((pass+1)); echo "ok   $1"; }
bad() { failn=$((failn+1)); echo "FAIL $1"; }
check() { if "$@" >"$work/out" 2>&1; then ok "$CASE"; else bad "$CASE"; sed 's/^/       /' "$work/out" | tail -4; fi; }
# py "<case>" <<'PY' ... PY : one case; the script sees the prelude below (exec'd first)
py() {
  CASE="$*"; { echo 'import sys; exec(open(sys.argv[2] + "/pre.py").read())'; cat; } >"$work/case.py"
  check python3 "$work/case.py" "$aud" "$work" "$root"
}
cp "$here/gh-map-stub.py" "$work/ghmap"; chmod +x "$work/ghmap"

cat >"$work/pre.py" <<'PY'
import copy, importlib.util, json, os, re, sys
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
work, root = sys.argv[2], sys.argv[3]
FIX = root + "/.github/agent/fixtures/pin-audit-go-major"
BARE = "github.com/sigstore/cosign"
ADV = "ignored advisory entry"
def load(name): return json.load(open(FIX + "/" + name))
def ent(path, events=(), eco="Go", **more):
    """One OSV `affected` entry: a module path (None: no package at all) and SEMVER events; more: versions=, purl=, ranges=."""
    a = {}
    if path is not None: a["package"] = {"name": path, "ecosystem": eco}
    if more.get("purl"): a["package"] = {"purl": more.pop("purl")}
    a["ranges"] = more.pop("ranges", [{"type": "SEMVER", "events": list(events)}])
    a.update(more)
    return a
def rec(rid, *affected, aliases=()):
    return {"id": rid, "aliases": list(aliases), "modified": "2026-01-01T00:00:00Z", "affected": list(affected)}
def record(rid, entries, aliases=()):
    """A synthetic OSV record: entries = [(module path or None, [events])]."""
    return rec(rid, *[ent(p, ev) for p, ev in entries], aliases=aliases)
def ev(*pairs): return [{k: v} for k, v in pairs]
INTRO0 = ev(("introduced", "0"))
def fixed(v, intro="0"): return ev(("introduced", intro), ("fixed", v))
def ghsa(gid, path, rng):
    return {"ghsa_id": gid, "updated_at": "2026-02-02T00:00:00Z", "type": "reviewed",
            "vulnerabilities": [{"package": {"name": path}, "vulnerable_version_range": rng}]}
def faithful(recs):
    """OSV's own query semantics: a record is returned when an affected entry named exactly like the queried package covers the version. A path-less entry
    cannot be indexed by package; this stub returns the record for it (the pessimistic reading), so the audit must not clear it."""
    def post(q):
        out = []
        for r in recs:
            for a in r["affected"]:
                nm = (a.get("package") or {}).get("name")
                if (nm is None or nm.lower() == q["package"]["name"].lower()) and any(
                        pa.covered_by_events(q["version"], rg["events"]) for rg in a.get("ranges", []) if rg.get("type") in ("SEMVER", "ECOSYSTEM")):
                    out.append(copy.deepcopy(r)); break
        return out
    return post
def mknet(recs, ghsas=(), superset=True, glist=None):
    """superset=True: the OSV query returns every record whatever package was asked (a lookup by alias or purl does), so the audit itself must ignore the
    entries that do not belong to the pinned major; superset=False: OSV answers by the exact package asked. ghsas: fixture GHSA ids or {id: record};
    glist: {module path: [advisory]} served by GitHub's paged list query for that package."""
    m = {}
    for g in (ghsas.items() if isinstance(ghsas, dict) else [(g, load("ghsa-" + g + ".json")) for g in ghsas]):
        m["advisories/" + g[0]] = g[1]
    for path, advs in (glist or {}).items():
        m["advisories?ecosystem=go&affects=%s&per_page=100&page=1" % path] = advs
    json.dump(m, open(work + "/map.json", "w")); os.environ["GH_MAP"] = work + "/map.json"
    net = pa.LiveNet([work + "/ghmap"], ".")
    net._osv_get = lambda i: None
    net._osv_post = (lambda q: copy.deepcopy(recs)) if superset else faithful(recs)
    return net
def run(item, net, exceptions=()):
    notes = []
    return pa.judge(item, net, list(exceptions), notes), notes
def right_path(base, v):
    """The module path Go gives the major of version v for a module whose bare path is base, or None when v is not a plain MAJOR.MINOR.PATCH."""
    m = re.fullmatch(r"v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", v)
    return None if not m else base if int(m.group(1)) <= 1 else base + "/v" + m.group(1)
def cosign(v, table=None):
    """A cosign pin whose table entry is CORRECT for its major unless table= says otherwise (the table-correctness case proves the real table is)."""
    pa.GO_TOOLS["cosign"] = table or right_path(BARE, v) or BARE
    return pa.inv.Item("tool", "cosign", v, "")
def tool(name, v, table):
    pa.GO_TOOLS[name] = table
    return pa.inv.Item("tool", name, v, "")
def ids(finds): return sorted({i for f in finds for i in f.ids})
def ignored(net, strict=False):
    """The log of ignored entries. strict=True: the audit MUST provide it; otherwise an audit that does not know the rule yet counts as having ignored
    nothing, so the cases that say 'the old verdict' pass today and must keep passing."""
    return list(net.ignored_entries) if strict else list(getattr(net, "ignored_entries", []))
def verdicts(ver, recs, sups=(True, False), tables=(None,), ghsas=(), glist=None, mk=None):
    """Judge `ver` (cosign unless mk= builds the item) against recs for each OSV mode and table path; yields (sup, table, finds, notes, net)."""
    for sup in sups:
        for tb in tables:
            net = mknet(recs, ghsas, sup, glist)
            finds, notes = run((mk or cosign)(ver, tb), net)
            yield sup, tb, finds, notes, net
def hit(ver, recs, none_ignored=False, **kw):
    for sup, tb, finds, notes, net in verdicts(ver, recs, **kw):
        assert finds, ("expected a HIT", ver, "superset" if sup else "exact-query", tb)
        assert not none_ignored or ignored(net) == [], ("nothing may be ignored", sup, tb, ignored(net))
def clean(ver, recs, none_ignored=False, **kw):
    for sup, tb, finds, notes, net in verdicts(ver, recs, **kw):
        assert finds == [], ("expected clean", ver, sup, tb, [(f.kind, f.ids) for f in finds])
        assert not none_ignored or ignored(net) == [], ("nothing may be ignored", sup, tb, ignored(net))
G4309 = load("osv-GO-2026-4309.json")
def base(v):
    """The old verdict for an unparsable version against GO-2026-4309 with the /v3 table: only the entry named like the table path counts."""
    only = copy.deepcopy(G4309); only["affected"] = [a for a in only["affected"] if a["package"]["name"] == BARE + "/v3"]
    try: return bool(run(cosign(v, BARE + "/v3"), mknet([only], GG, True))[0])
    except pa.Fail: return True
GG = ["GHSA-whqx-f9j3-ch6m"]
PY

# --- the live case: cosign 3.1.3 against GO-2026-4309 ----------------------------------------------------------------------------------------------------
py "cosign 3.1.3 vs GO-2026-4309 (live: bare from 0 no fix, /v2 fixed 2.6.2, /v3 fixed 3.0.4; GitHub /v3 <= 3.0.3, /v2 <= 2.6.1) is clean in" \
   " both OSV modes" <<'PY'
clean("3.1.3", [G4309], ghsas=GG)
PY
py "nothing is dropped silently: the bare and /v2 entries of GO-2026-4309 are logged by id and path, the reason names major 3 as its own token," \
   " each once" <<'PY'
net = mknet([G4309], GG, True); finds, notes = run(cosign("3.1.3"), net)
ig = ignored(net, True)
assert sorted((e["id"], e["path"]) for e in ig) == [("GO-2026-4309", BARE), ("GO-2026-4309", BARE + "/v2")], ig
for e in ig:
    assert set(e) >= {"id", "path", "reason"} and re.search(r"\bmajor 3\b", e["reason"]), e
    assert sum(1 for n in notes if n.startswith(ADV) and e["id"] in n and (" " + e["path"] + ":") in n) == 1, (e, notes)
assert sum(1 for n in notes if n.startswith(ADV)) == len(ig), notes
assert not any(e["path"] == BARE + "/v3" for e in ig), "the matching path is never logged as ignored"
PY
py "no note and no log entry when nothing is ignored (an exact entry alone, a table-mismatch pin)" <<'PY'
only = record("GO-X-20", [(BARE + "/v3", fixed("3.0.4"))])
net = mknet([only], (), True); finds, notes = run(cosign("3.1.3"), net)
assert finds == [] and ignored(net, True) == [] and not any(n.startswith(ADV) for n in notes), (finds, notes)
net = mknet([G4309], GG, True); finds, notes = run(cosign("3.1.3", BARE), net)
assert ignored(net, True) == [] and not any(n.startswith(ADV) for n in notes), notes
PY
py "cosign 3.0.3 IS a hit (the /v3 entry is fixed 3.0.4 and GitHub lists <= 3.0.3), in both OSV modes" <<'PY'
hit("3.0.3", [G4309], ghsas=GG)
PY
py "a major-2 pin: cosign 2.6.1 is a hit via the /v2 entry (fixed 2.6.2), 2.6.2 is not; the bare and /v3 entries are logged with 'major 2'" <<'PY'
hit("2.6.1", [G4309], ghsas=GG)
net = mknet([G4309], GG, True); finds, notes = run(cosign("2.6.2"), net)
assert finds == [], [(f.kind, f.ids) for f in finds]
ig = ignored(net, True)
assert sorted(e["path"] for e in ig) == [BARE, BARE + "/v3"], ig
assert all(re.search(r"\bmajor 2\b", e["reason"]) and not re.search(r"\bmajor 3\b", e["reason"]) for e in ig), ig
PY
py "a major-1 pin (1.13.0): only the bare entry decides: it covers 1.13.0 so a hit; the /v2 and /v3 entries are logged; fixed on the bare path: clean" <<'PY'
net = mknet([G4309], (), True); finds, _ = run(cosign("1.13.0"), net)
assert finds, "the bare entry (introduced 0, no fix) covers 1.13.0"
assert sorted(e["path"] for e in ignored(net, True)) == [BARE + "/v2", BARE + "/v3"], ignored(net)
clean("1.13.5", [record("GO-X-1", [(BARE, fixed("1.13.2")), (BARE + "/v2", INTRO0)])], sups=(True,))
PY
py "major 0/1 with a /v0 or /v1 entry in the record is ambiguous: the OLD verdict (clean when the bare entry is fixed, hit when it covers)," \
   " nothing ignored" <<'PY'
for name, ver, v1 in (("xtool", "0.5.0", "/v0"), ("ytool", "1.4.0", "/v1")):
    base = "example.com/o/" + name
    mk = lambda v, t=None, n=name, b=base: tool(n, v, b)
    clean(ver, [record("GO-X-2", [(base, fixed("1.0.0" if ver[0] == "1" else "0.1.0")), (base + v1, INTRO0)])], none_ignored=True, sups=(True,), mk=mk)
    hit(ver, [record("GO-X-3", [(base, INTRO0), (base + v1, fixed("9.9.9"))])], none_ignored=True, sups=(True,), mk=mk)
PY
py "a tool NOT in the committed table (owner/repo form) is judged as before: the bare entry makes 3.1.3 a hit, nothing ignored" <<'PY'
assert "sigstore/cosign" not in pa.GO_TOOLS
hit("3.1.3", [G4309], ghsas=GG, none_ignored=True, sups=(True,), mk=lambda v, t=None: pa.inv.Item("tool", "sigstore/cosign", v, ""))
PY
# An unparsable version is never settled by the rule: nothing is ignored and the verdict is the one the audit gave before (BASE: only the /v3 entry
# named like the table path counts). The table is the CORRECT /v3 path, so a loose parser (one that reads "3.1.3-rc.1" or "V3.1.3" as major 3)
# would ignore the bare and /v2 entries and log them; ignored(net) == [] catches it. (With the bare table path the version would be a hit anyway.)
py "versions the rule cannot parse keep the old verdict and ignore nothing, with the right /v3 table: pre-release, short, v3.1, latest, 4 parts," \
   " leading zero, wildcard" <<'PY'
for v in ("3.1.3-rc.1", "3", "v3.1", "latest", "3.1.3.4", "03.1.3", "3.1.x"):
    net = mknet([G4309], GG, True)
    try: finds, _ = run(cosign(v, BARE + "/v3"), net)
    except pa.Fail: finds = ["stopped"]
    assert bool(finds) == base(v) and ignored(net) == [], (v, finds, ignored(net))
PY
py "version parse holes keep the old verdict and ignore nothing, with the right /v3 table: build metadata, +incompatible (a Go major-3" \
   " +incompatible version belongs
   " to the BARE path), newline, space, V, vv, Arabic-Indic, fullwidth" <<'PY'
for v in ("3.1.3+build.1", "3.1.3+incompatible", "3.1.3\n", " 3.1.3", "V3.1.3", "vv3.1.3", "\u0663.\u0661.\u0663", "\uff13.1.3"):
    net = mknet([G4309], GG, True)
    try: finds, _ = run(cosign(v, BARE + "/v3"), net)
    except pa.Fail: finds = ["stopped"]
    assert bool(finds) == base(v) and ignored(net) == [], (repr(v), finds, ignored(net))
PY
py "an empty version is not covered at all and nothing is ignored, as before" <<'PY'
net = mknet([G4309], GG); it = cosign("")
assert net.covered(it) is False and net.lists(it) == ([], []) and ignored(net) == []
PY
py "a leading lowercase v is a plain version: v3.1.3 gets the same verdict as 3.1.3" <<'PY'
clean("v3.1.3", [G4309], ghsas=GG, sups=(True,))
PY

# --- OSV queried by /vMAJOR as well as the bare path; GitHub's own filing (advisor-accepted at step 5) -----------------------------------------------------
py "a record with ONLY a /v3 entry covering the pin is a hit: the audit queries OSV by the /v3 path too (the bare query returns nothing); table" \
   " bare or /v3" <<'PY'
hit("3.1.3", [record("GO-X-11", [(BARE + "/v3", fixed("3.2.0", "3.0.0"))])], tables=(BARE, None))
PY
py "the major-2 analogue: a record with ONLY a /v2 entry covering cosign 2.5.0 is a hit, table bare or /v2" <<'PY'
hit("2.5.0", [record("GO-X-13", [(BARE + "/v2", fixed("2.6.2", "2.0.0"))])], tables=(BARE, None))
PY
py "GitHub files cosign v3 ranges under the BARE path: a GitHub-only advisory on the bare path covering 3.1.3 (paged list) is a hit, table /v3" \
   " or bare; outside the range it is clean" <<'PY'
adv = ghsa("GHSA-syn-0002-xxxx", BARE, ">= 3.0.0, < 3.2.0")
hit("3.1.3", [], tables=(None, BARE), glist={BARE: [adv]})
clean("3.2.0", [], tables=(None,), glist={BARE: [adv]}, sups=(True,))
PY
py "a path-less entry NEXT TO an exact entry stays a hit and nothing is ignored (it may be the very module), both OSV modes" <<'PY'
hit("3.1.3", [record("GO-X-12", [(BARE + "/v3", fixed("3.0.4")), (None, INTRO0)])], none_ignored=True)
PY
py "no exact entry stays a hit and ignores nothing: only bare and /v2 entries (as the three older cosign advisories), or an affected entry with" \
   " no module path at all" <<'PY'
hit("3.1.3", [record("GO-X-4", [(BARE, INTRO0), (BARE + "/v2", fixed("2.2.4"))])], none_ignored=True, sups=(True,))
hit("3.1.3", [record("GO-X-5", [(None, INTRO0)])], none_ignored=True, sups=(True,))
PY

# --- records the rule must not trust ---------------------------------------------------------------------------------------------------------------------
py "paths that only look like /v3 are other modules: /v30, /v3x, /v3/sub, /V3, github.com/evil/cosign/v3: logged next to a real exact entry," \
   " never taken as the exact one" <<'PY'
odd = [BARE + "/v30", BARE + "/v3x", BARE + "/v3/sub", BARE + "/V3", "github.com/evil/cosign/v3"]
net = mknet([record("GO-X-6", [(p, INTRO0) for p in odd])], (), True); finds, _ = run(cosign("3.1.3"), net)
assert finds and not any(e["path"] == BARE + "/v3" for e in ignored(net)), "no exact entry: fail closed"
net2 = mknet([record("GO-X-7", [(BARE + "/v3", fixed("3.0.4"))] + [(p, INTRO0) for p in odd])], (), True); f2, _ = run(cosign("3.1.3"), net2)
assert f2 == [], [(f.kind, f.ids) for f in f2]
assert sorted(e["path"] for e in ignored(net2, True)) == sorted(odd), ignored(net2)
PY
py "lookalikes that carry the FIX with no exact entry beside them stay hits: /v3/, '/v3 ', GitHub.com host case, the same path under npm, a" \
   " purl-only package" <<'PY'
fx = fixed("3.0.4")
looks = {"trailing slash": ent(BARE + "/v3/", fx), "whitespace": ent(BARE + "/v3 ", fx), "host case": ent("GitHub.com/sigstore/cosign/v3", fx),
         "npm ecosystem": ent(BARE + "/v3", fx, eco="npm"), "purl only": ent(None, fx, purl="pkg:golang/github.com/sigstore/cosign/v3")}
for what, lk in looks.items():
    try: hit("3.1.3", [rec("GO-X-15", ent(BARE, INTRO0), lk)], none_ignored=True, tables=(None, BARE))
    except AssertionError as e: raise AssertionError((what,) + e.args)
PY
py "a crafted record cannot make a real hit disappear: the exact /v3 entry covers 3.1.3 next to a bare entry fixed 1.0.0 and a foreign /v3" <<'PY'
hit("3.1.3", [record("GO-X-8", [(BARE, fixed("1.0.0")), (BARE + "/v3", fixed("3.5.0")), ("github.com/evil/cosign/v3", fixed("0.0.1"))])])
PY
py "two records for one pin: ignoring the entries of one never touches the other's verdict (a second advisory on the /v3 path covering 3.1.3 is a hit)" <<'PY'
for sup, tb, finds, notes, net in verdicts("3.1.3", [G4309, record("GO-X-9", [(BARE + "/v3", fixed("3.2.0", "3.0.0"))])], ghsas=GG):
    assert "GO-X-9" in ids(finds) and "GO-2026-4309" not in ids(finds), (sup, [(f.kind, f.ids) for f in finds])
PY
py "two identical non-exact entries (one record, or two queries) are logged once each, not twice" <<'PY'
r = record("GO-X-19", [(BARE + "/v3", fixed("3.0.4")), (BARE, INTRO0), (BARE, INTRO0)])
net = mknet([r], (), True); finds, notes = run(cosign("3.1.3"), net)
assert finds == [] and len([e for e in ignored(net, True) if e["path"] == BARE]) == 1, ignored(net)
assert sum(1 for n in notes if n.startswith(ADV) and (" " + BARE + ":") in n) == 1, notes
PY
py "boundaries: 3.0.4 and 3.0.5 are clean (fixed 3.0.4), last_affected == the pin is a hit and one patch later is clean" <<'PY'
clean("3.0.4", [G4309], ghsas=GG); clean("3.0.5", [G4309], ghsas=GG)
lastaff = [record("GO-X-14", [(BARE + "/v3", ev(("introduced", "0"), ("last_affected", "3.1.3")))])]
hit("3.1.3", lastaff); clean("3.1.4", lastaff)
PY
py "multiple exact entries are OR-ed; an exact entry with only versions ['3.1.3'], GIT-only ranges, or an empty ranges list is a hit; two" \
   " identical fixed entries are clean" <<'PY'
n = BARE + "/v3"
hit("3.1.3", [record("GO-X-16", [(n, fixed("3.0.4")), (n, fixed("3.2.0", "3.0.0"))])])
for what, a in (("versions only", ent(n, ranges=[], versions=["3.1.3"])), ("git only", ent(n, ranges=[{"type": "GIT", "events": ev(("introduced", "0"))}])),
                ("empty ranges", ent(n, ranges=[]))):
    try: hit("3.1.3", [rec("GO-X-17", a)], sups=(True,))
    except AssertionError as e: raise AssertionError((what,) + e.args)
clean("3.1.3", [record("GO-X-18", [(n, fixed("3.0.4")), (n, fixed("3.0.4"))])])
PY

# --- the pin kinds, majors 0/1, the table ----------------------------------------------------------------------------------------------------------------
py "major 0 (trivy 0.74.0): the bare entry decides (fixed 0.70.0: clean) and the /v2 and /v3 entries are logged; bare covering with /v2 fixed: a hit" <<'PY'
P = "github.com/aquasecurity/trivy"
tr = lambda v, t=None: tool("trivy", v, P)
net = mknet([record("GO-X-21", [(P, fixed("0.70.0")), (P + "/v2", INTRO0), (P + "/v3", INTRO0)])], (), True); finds, _ = run(tr("0.74.0"), net)
assert finds == [] and sorted(e["path"] for e in ignored(net, True)) == [P + "/v2", P + "/v3"], (finds, ignored(net))
hit("0.74.0", [record("GO-X-22", [(P, INTRO0), (P + "/v2", fixed("2.0.0"))])], mk=tr, sups=(True,))
hit("0.69.4", [record("GO-X-23", [(P, fixed("0.70.0"))])], mk=tr, sups=(True,))
PY
py "a table entry that does NOT match the pinned major keeps the old verdict: goreleaser 2.5.0 with a bare table path, bare affected + /v2" \
   " fixed: a hit, nothing ignored" <<'PY'
G = "github.com/goreleaser/goreleaser"
hit("2.5.0", [record("GO-X-24", [(G, INTRO0), (G + "/v2", fixed("2.4.0"))])], none_ignored=True, mk=lambda v, t=None: tool("goreleaser", v, G))
PY
py "helm (table path already helm.sh/helm/v3, exact for major 3): an affected exact entry is a hit and nothing is ignored" <<'PY'
H = "helm.sh/helm/v3"
hit("3.14.0", [record("GO-X-25", [(H, INTRO0)])], none_ignored=True, mk=lambda v, t=None: tool("helm", v, H))
PY
py "other kinds keep the OLD verdict and log nothing: a gotool item (module resolved to /v3: clean; resolved to the bare path: a hit)" <<'PY'
for mod, want in ((BARE + "/v3", False), (BARE, True)):
    pa.age._go_module = lambda n, v, m=mod: (m, None)
    net = mknet([G4309], GG, True)
    finds, _ = run(pa.inv.Item("gotool", mod + "/cmd/cosign", "v3.1.3", ""), net)
    assert bool(finds) == want and ignored(net) == [], (mod, finds, ignored(net))
PY
py "a table entry whose path is bare while the pinned major >= 2, or ends in a DIFFERENT /vN, stays a hit even when the record would otherwise" \
   " be ignorable" <<'PY'
for wrong in (BARE, BARE + "/v2", BARE + "/v30"):
    hit("3.1.3", [G4309], ghsas=GG, none_ignored=True, tables=(wrong,))
clean("3.1.3", [G4309], ghsas=GG, tables=(None,))
PY

# --- disagreement between the databases is never cleared --------------------------------------------------------------------------------------------------
py "OSV exact clean while GitHub (bare path) says affected: a DISPUTED finding; OSV affected while GitHub (/v3) says clean: disputed too" <<'PY'
a = rec("GO-SYN-1", ent(BARE + "/v3", fixed("3.0.4")), aliases=["GHSA-syn-0001-xxxx"])
net = mknet([a], {"GHSA-syn-0001-xxxx": ghsa("GHSA-syn-0001-xxxx", BARE, ">= 3.0.0, < 3.2.0")}, True); finds, _ = run(cosign("3.1.3"), net)
assert finds and all(f.disputed for f in finds), [(f.kind, f.ids, f.disputed) for f in finds]
b = rec("GO-SYN-2", ent(BARE + "/v3", fixed("3.2.0", "3.0.0")), aliases=["GHSA-syn-0002-xxxx"])
net = mknet([b], {"GHSA-syn-0002-xxxx": ghsa("GHSA-syn-0002-xxxx", BARE + "/v3", "< 3.0.0")}, True); finds, _ = run(cosign("3.1.3"), net)
assert finds and all(f.disputed for f in finds), [(f.kind, f.ids, f.disputed) for f in finds]
PY
py "the exceptions mechanism: a ruling whose copied ranges equal GitHub's live ranges passes a disputed hit; with other ranges it stays DISPUTED; a" \
   " ruling whose ranges contain the version returns a plain HIT" <<'PY'
def exc(rng):
    return {"ids": ["GHSA-syn-0001-xxxx", "GO-SYN-1"], "package": "cosign", "authoritative": {"source": "GitHub", "id": "GHSA-syn-0001-xxxx", "ranges": [rng]},
            "ruling": "t", "evidence": ["https://x"], "date": "2026-10-09", "version": "3.1.3",
            "modified": {"GO-SYN-1": "2026-01-01T00:00:00Z", "GHSA-syn-0001-xxxx": "2026-02-02T00:00:00Z"}}
def gh(rng): return {"GHSA-syn-0001-xxxx": ghsa("GHSA-syn-0001-xxxx", BARE + "/v3", rng)}
aff = rec("GO-SYN-1", ent(BARE + "/v3", ev(("introduced", "3.1.0"))), aliases=["GHSA-syn-0001-xxxx"])      # OSV: 3.1.3 affected, no fix
finds, _ = run(cosign("3.1.3"), mknet([aff], gh("< 3.0.0"), True), [exc("< 3.0.0")])
assert finds == [], [(f.kind, f.ids, f.disputed) for f in finds]
finds, _ = run(cosign("3.1.3"), mknet([aff], gh("< 3.0.0"), True), [exc("< 3.0.1")])           # copied ranges differ from GitHub's live ones
assert finds and all(f.disputed for f in finds), [(f.kind, f.ids, f.disputed) for f in finds]
clr = rec("GO-SYN-1", ent(BARE + "/v3", fixed("3.0.4")), aliases=["GHSA-syn-0001-xxxx"])         # OSV: clean, GitHub: affected
rng = ">= 3.0.0, < 3.2.0"
finds, _ = run(cosign("3.1.3"), mknet([clr], gh(rng), True), [exc(rng)])
assert finds and not any(f.disputed for f in finds) and finds[0].kind == "advisory", [(f.kind, f.disputed) for f in finds]
PY
py "the five existing cosign 3.1.3 rulings keep working with the live records, with the table as it is today AND corrected to /v3" <<'PY'
exc = pa.load_exceptions(root + "/.github/supply-chain-exceptions.json", True)
pairs = [("GO-2024-2718", "GHSA-88jx-383q-w4qc"), ("GO-2024-2719", "GHSA-95pr-fxf5-86gv"), ("GO-2023-2181", "GHSA-vfp6-jrw2-99g9"),
         ("GO-2026-5694", "GHSA-w6c6-c85g-mmv6"), ("GO-2026-4529", "GHSA-wfqv-66vq-46rm")]
for go, gh in pairs:
    r = load("osv-%s.json" % go); r["aliases"] = sorted(set(r.get("aliases", [])) | {gh})
    for sup in (True, False):
        for table in (BARE, BARE + "/v3"):
            finds, notes = run(cosign("3.1.3", table), mknet([r], [gh], sup), exc)
            assert finds == [], (go, sup, table, [(f.kind, f.ids) for f in finds])
PY
py "a hit on another tool's real advisory is untouched: trivy 0.69.4 with the bare path affected is still a hit (major 0)" <<'PY'
P = "github.com/aquasecurity/trivy"
hit("0.69.4", [record("GO-X-10", [(P, fixed("0.70.0", "0.69.0"))])], sups=(True,), mk=lambda v, t=None: tool("trivy", v, P))
PY

# --- the printed output: the summary line counts exceptions only; paths are printed sanitised -----------------------------------------------------------------
cat >>"$work/pre.py" <<'PY'
import contextlib, io, subprocess, tempfile
def main_out(recs, ghsas, cosign_ver="3.1.3"):
    """Run pin-audit's main() on a one-file repository that pins cosign, with a LiveNet whose OSV and GitHub answers are the given ones."""
    repo = tempfile.mkdtemp(prefix="pa-go-major-")
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@x", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@x")
    os.makedirs(repo + "/bin"); open(repo + "/bin/install-scanner.sh", "w").write("COSIGN_VER=%s\n" % cosign_ver)
    for c in (["init", "-q"], ["add", "-A"], ["commit", "-q", "-m", "pin"]):
        subprocess.run(["git", "-C", repo, *c], env=env, check=True, capture_output=True)
    os.makedirs(repo + "/.github"); subprocess.run(["cp", root + "/.github/supply-chain-exceptions.json", repo + "/.github/"], check=True)
    net = mknet(recs, ghsas, True); net.open_pr_items = lambda: []
    pa.GO_TOOLS["cosign"] = BARE + "/v3"
    pa.LiveNet = lambda gh, r: net
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            rc = pa.main(["--root", repo, "--now", "2026-10-09T12:00:00Z", "--gh", "false", "--report-only"])
    finally:
        subprocess.run(["rm", "-rf", repo])
    return rc, buf.getvalue()
PY
py "the summary counts exceptions only: the five records plus GO-2026-4309 give exit 0 and '(3 disputed hit(s) covered by a checked-in exception)'" \
   " (GO-2026-4529 and -5694 have exact /v3 entries that agree with GitHub, so they are not disputes)" <<'PY'
pairs = [("GO-2024-2718", "GHSA-88jx-383q-w4qc"), ("GO-2024-2719", "GHSA-95pr-fxf5-86gv"), ("GO-2023-2181", "GHSA-vfp6-jrw2-99g9"),
         ("GO-2026-5694", "GHSA-w6c6-c85g-mmv6"), ("GO-2026-4529", "GHSA-wfqv-66vq-46rm")]
recs = [G4309]; ghs = list(GG)
for go, gh in pairs:
    r = load("osv-%s.json" % go); r["aliases"] = sorted(set(r.get("aliases", [])) | {gh}); recs.append(r); ghs.append(gh)
rc, out = main_out(recs, ghs)
assert rc == 0, (rc, out[-600:])
assert "(3 disputed hit(s) covered by a checked-in exception)" in out, out[-600:]
assert any(l.startswith("audit: " + ADV) for l in out.splitlines()), "the ignored entries are printed"
PY
py "a hostile module path is printed sanitised: control characters and a '::error::' injection never start a log line" <<'PY'
r = record("GO-X-30", [(BARE + "/v3", fixed("3.0.4")), (BARE + "/v3\n::error::boom", INTRO0)])
rc, out = main_out([r], ())
assert rc == 0, (rc, out[-500:])
lines = out.splitlines()
assert not any(l.startswith("::error::") for l in lines), [l for l in lines if "::error::" in l]
assert any(l.startswith("audit: " + ADV) and "boom" in l for l in lines), "the ignored entry is logged, on one line"
PY

# --- the table must be right for the versions we pin (advisor ruling, step 5) ---------------------------------------------------------------------------------
py "TABLE CORRECTNESS: every tool in GO_TOOLS that the tree pins has the bare path for major 0/1 and a path ending in /vMAJOR for major >= 2" <<'PY'
items = pa.inv.inventory(pa.inv.tree_files(root, None))     # the tree as the audit reads it (working tree)
plain = re.compile(r"v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
pinned = {}                                                   # tool -> set of (version, where)
for it in items.values():
    if it.kind == "tool" and it.name in pa.GO_TOOLS and plain.fullmatch(it.version):
        pinned.setdefault(it.name, set()).add((it.version, "tool " + it.key))
    if it.kind == "gotool" and plain.fullmatch(it.version):   # go install module/path/cmd/x@vN.M.P: the module path itself names the major
        for name, tp in pa.GO_TOOLS.items():
            bare = re.sub(r"/v[0-9]+$", "", tp)
            if it.name == bare or it.name.startswith(bare + "/"):
                pinned.setdefault(name, set()).add((it.version, "gotool " + it.key))
need = {"trivy", "grype", "syft", "osv", "gitsign", "scout", "goreleaser", "golangci-lint"}
assert need <= set(pinned), ("the check would be vacuous; found only", sorted(pinned))
wrong = []
for name, vs in sorted(pinned.items()):
    tp = pa.GO_TOOLS[name]
    bare = re.sub(r"/v[0-9]+$", "", tp)
    for v, where in sorted(vs):
        want = right_path(bare, v)
        if tp != want:
            wrong.append("%s pinned %s (%s): table path %s, correct path %s" % (name, v, where.split()[0], tp, want))
assert not wrong, "GO_TOOLS entries wrong for the pinned major:\n  " + "\n  ".join(wrong)
PY

# --- the program itself ----------------------------------------------------------------------------------------------------------------------------------
py "GO_TOOLS is the one committed table of Go tools (cosign is in it, rooted at its module), and the audit has no second, hidden table" <<'PY'
assert "cosign" in pa.GO_TOOLS and pa.GO_TOOLS["cosign"].startswith(BARE)
assert len(re.findall(r"^GO_TOOLS\s*=", open(sys.argv[1]).read(), re.M)) == 1
PY
CASE="the audit's own offline suite still passes (pin-audit-test.sh): the new rule changes no existing verdict"
check bash "$here/pin-audit-test.sh"
py "the fixtures record when they were read and from where" <<'PY'
import glob
d = root + "/.github/agent/fixtures/pin-audit-go-major"
assert len(glob.glob(d + "/osv-*.json")) == 6 and len(glob.glob(d + "/ghsa-*.json")) == 6 and "2026-10-09" in open(d + "/README").read()
PY

echo "pass=$pass fail=$failn"
if [ $((pass + failn)) != "$EXPECT" ]; then echo "FAIL case count $((pass + failn)) != expected $EXPECT (a case was skipped or added)"; exit 1; fi
[ "$failn" = 0 ]
