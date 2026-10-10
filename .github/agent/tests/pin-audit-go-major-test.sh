#!/usr/bin/env bash
# proves: REQ-SUP-001-AC14
# The Go-module major-path rule of the supply-chain audit (advisor-approved read-back Oct 9, "pin-audit Go major path"; tests first, RED until
# .github/agent/supply-chain/pin-audit.py implements it). Go's own module-path rule: a version vN.x with N >= 2 belongs to the module path that ends in
# /vN; versions 0.x and 1.x belong to the bare path. An advisory entry (OSV's `affected` list) for any other path says nothing about the pinned version.
# Without the rule, the Go database's bare-path entry "affected from 0, no fix" makes every cosign 3.x a hit (cosign 3.1.3 vs GO-2026-4309).
#
# What the tests pin down (offline: the OSV and GitHub databases are replaced by recorded live records and a gh stub):
#   * the rule applies ONLY to a tool in pin-audit.py's committed table GO_TOOLS, whose version parses as a plain MAJOR.MINOR.PATCH (a leading v is allowed);
#     anything else is judged exactly as before (a hit stays a hit);
#   * for such a tool the entry whose path is EXACTLY <bare>/vN (N >= 2) or EXACTLY <bare> (N <= 1) decides; every other entry is ignored and LOGGED;
#   * when the record has NO entry for the exact path, nothing can be concluded: the verdict is the old one (fail closed: a hit stays a hit);
#   * nothing is dropped silently: LiveNet.ignored_entries is a list of {"id", "path", "reason"}, one per ignored entry, and judge() adds one note per entry
#     ("ignored advisory entry <id> <path>: <reason>"), so a reviewer sees what was skipped. PROPOSED interface: the implementation follows these names.
# The recorded live data (read 2026-10-09T23:51Z from https://api.osv.dev/v1/vulns/<id> and `gh api advisories/<ghsa>`) is in
# .github/agent/fixtures/pin-audit-go-major/ (six cosign advisories: GO-2026-4309 and the five already ruled on in .github/supply-chain-exceptions.json).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
aud="$here/../supply-chain/pin-audit.py"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0 EXPECT=30
ok()  { pass=$((pass+1)); echo "ok   $1"; }
bad() { failn=$((failn+1)); echo "FAIL $1"; }
CASE=""
check() { if "$@" >"$work/out" 2>&1; then ok "$CASE"; else bad "$CASE"; sed 's/^/       /' "$work/out" | tail -4; fi; }
cp "$here/gh-map-stub.py" "$work/ghmap"; chmod +x "$work/ghmap"

# the shared prelude of every case: the audit loaded as a module, a LiveNet with no network, records from the fixtures
cat >"$work/pre.py" <<'PY'
import copy, importlib.util, json, os, sys
spec = importlib.util.spec_from_file_location("pa", sys.argv[1]); pa = importlib.util.module_from_spec(spec); spec.loader.exec_module(pa)
work, root = sys.argv[2], sys.argv[3]
FIX = root + "/.github/agent/fixtures/pin-audit-go-major"
BARE = "github.com/sigstore/cosign"
def load(name): return json.load(open(FIX + "/" + name))
def record(rid, entries, aliases=()):
    """A synthetic OSV record: entries = [(module path or None, [events])]."""
    aff = []
    for path, events in entries:
        a = {"ranges": [{"type": "SEMVER", "events": events}]}
        if path is not None: a["package"] = {"name": path, "ecosystem": "Go"}
        aff.append(a)
    return {"id": rid, "aliases": list(aliases), "modified": "2026-01-01T00:00:00Z", "affected": aff}
def faithful(recs):
    """OSV's own query semantics: a record is returned when an affected entry named exactly like the queried package covers the version."""
    def post(q):
        out = []
        for r in recs:
            for a in r["affected"]:
                if (a.get("package") or {}).get("name", "").lower() == q["package"]["name"].lower() and any(
                        pa.covered_by_events(q["version"], rg["events"]) for rg in a.get("ranges", []) if rg.get("type") in ("SEMVER", "ECOSYSTEM")):
                    out.append(copy.deepcopy(r)); break
        return out
    return post
def mknet(recs, ghsas=(), superset=True):
    """superset=True: the OSV query returns the whole record whatever package was asked (what a lookup by alias or purl does), so the audit itself must
    ignore the entries that do not belong to the pinned major; superset=False: OSV answers by the exact package asked."""
    json.dump({"advisories/" + g: load("ghsa-" + g + ".json") for g in ghsas}, open(work + "/map.json", "w")); os.environ["GH_MAP"] = work + "/map.json"
    net = pa.LiveNet([work + "/ghmap"], ".")
    net._osv_get = lambda i: None
    net._osv_post = (lambda q: copy.deepcopy(recs)) if superset else faithful(recs)
    return net
def run(item, net, exceptions=()):
    notes = []
    finds = pa.judge(item, net, list(exceptions), notes)
    return finds, notes
def right_path(base, v):
    """The module path Go gives the major of version v for a module whose bare path is base, or None when v is not a plain MAJOR.MINOR.PATCH."""
    import re
    m = re.fullmatch(r"v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", v)
    if not m: return None
    return base if int(m.group(1)) <= 1 else base + "/v" + m.group(1)
def cosign(v):
    """A cosign pin whose table entry is CORRECT for its major (the table-correctness case below proves the real table is); the cases that
    test a WRONG table entry set pa.GO_TOOLS themselves."""
    rp = right_path(BARE, v)
    pa.GO_TOOLS["cosign"] = rp or BARE
    return pa.inv.Item("tool", "cosign", v, "")
def ids(finds): return sorted({i for f in finds for i in f.ids})
def ignored(net, strict=False):
    """The log of ignored entries. strict=True: the audit MUST provide it (a rule that applies logs what it skipped); otherwise an audit that does not
    know the rule yet counts as having ignored nothing, so the cases that say 'the verdict is the old one' pass today and must keep passing."""
    return list(net.ignored_entries) if strict else list(getattr(net, "ignored_entries", []))
G4309 = load("osv-GO-2026-4309.json")
PY

# --- the live case: cosign 3.1.3 against GO-2026-4309 -----------------------------------------------------------------------------------------------------
CASE="cosign 3.1.3 vs GO-2026-4309 (live record: bare path from 0 with no fix, /v2 fixed 2.6.2, /v3 fixed 3.0.4; GitHub: /v3 <= 3.0.3, /v2 <= 2.6.1) is NOT a hit when OSV answers with the whole record"
check python3 - "$aud" "$work" "$root" <<'PY'
import sys; exec(open(sys.argv[2] + "/pre.py").read())
finds, notes = run(cosign("3.1.3"), mknet([G4309], ["GHSA-whqx-f9j3-ch6m"], superset=True))
assert finds == [], [(f.kind, f.ids) for f in finds]
PY
CASE="the same when OSV answers by the exact package asked (the audit may query the /v3 path itself): still not a hit"
check python3 - "$aud" "$work" "$root" <<'PY'
import sys; exec(open(sys.argv[2] + "/pre.py").read())
finds, notes = run(cosign("3.1.3"), mknet([G4309], ["GHSA-whqx-f9j3-ch6m"], superset=False))
assert finds == [], [(f.kind, f.ids) for f in finds]
PY
CASE="nothing is dropped silently: the bare-path and /v2 entries of GO-2026-4309 are each logged by id and path with a reason that names the major, in net.ignored_entries and in the judge notes"
check python3 - "$aud" "$work" "$root" <<'PY'
import sys; exec(open(sys.argv[2] + "/pre.py").read())
net = mknet([G4309], ["GHSA-whqx-f9j3-ch6m"], superset=True)
finds, notes = run(cosign("3.1.3"), net)
ig = ignored(net, True)
assert sorted((e["id"], e["path"]) for e in ig) == [("GO-2026-4309", BARE), ("GO-2026-4309", BARE + "/v2")], ig
for e in ig:
    assert set(e) >= {"id", "path", "reason"} and "major" in e["reason"].lower() and "3" in e["reason"], e
for e in ig:
    assert any(n.startswith("ignored advisory entry") and e["id"] in n and e["path"] in n for n in notes), (e, notes)
assert not any(e["path"] == BARE + "/v3" for e in ig), "the matching path must never be logged as ignored"
PY
CASE="cosign 3.0.3 IS a hit (the /v3 entry is fixed 3.0.4 and GitHub lists <= 3.0.3): the real affected version still decides"
check python3 - "$aud" "$work" "$root" <<'PY'
import sys; exec(open(sys.argv[2] + "/pre.py").read())
for sup in (True, False):
    finds, notes = run(cosign("3.0.3"), mknet([G4309], ["GHSA-whqx-f9j3-ch6m"], superset=sup))
    assert finds and not any(f.disputed for f in finds) and ("GO-2026-4309" in ids(finds) or "GHSA-whqx-f9j3-ch6m" in ids(finds)), (sup, [(f.kind, f.ids) for f in finds])
PY
CASE="a major-2 pin: cosign 2.6.1 is a hit via the /v2 entry (fixed 2.6.2), 2.6.2 is not; the bare and /v3 entries are ignored and logged"
check python3 - "$aud" "$work" "$root" <<'PY'
import sys; exec(open(sys.argv[2] + "/pre.py").read())
f1, _ = run(cosign("2.6.1"), mknet([G4309], ["GHSA-whqx-f9j3-ch6m"]))
assert f1, "2.6.1 must be a hit"
net = mknet([G4309], ["GHSA-whqx-f9j3-ch6m"])
f2, _ = run(cosign("2.6.2"), net)
assert f2 == [], [(f.kind, f.ids) for f in f2]
assert sorted(e["path"] for e in ignored(net, True)) == [BARE, BARE + "/v3"], ignored(net)
PY

# --- major 0 and 1: only the bare path counts ---------------------------------------------------------------------------------------------------------------
CASE="a major-1 pin (a tool in the table at 1.13.0): only the bare-path entry decides: affected via the bare entry is a hit; the /v2 and /v3 entries are ignored and logged"
check python3 - "$aud" "$work" "$root" <<'PY'
import sys; exec(open(sys.argv[2] + "/pre.py").read())
net = mknet([G4309])
finds, notes = run(cosign("1.13.0"), net)
assert finds, "the bare entry (introduced 0, no fix) covers 1.13.0"
assert sorted(e["path"] for e in ignored(net, True)) == [BARE + "/v2", BARE + "/v3"], ignored(net)
rec = record("GO-X-1", [(BARE, [{"introduced": "0"}, {"fixed": "1.13.2"}]), (BARE + "/v2", [{"introduced": "0"}])])
f2, _ = run(cosign("1.13.5"), mknet([rec]))
assert f2 == [], "fixed on the bare path; the /v2 entry is another module"
PY
CASE="a major-0 pin with a /v0 entry in the record (not a valid Go module path) is ambiguous: a hit stays a hit, nothing is ignored"
check python3 - "$aud" "$work" "$root" <<'PY'
import sys; exec(open(sys.argv[2] + "/pre.py").read())
pa.GO_TOOLS["xtool"] = "example.com/o/xtool"
rec = record("GO-X-2", [("example.com/o/xtool", [{"introduced": "0"}, {"fixed": "0.1.0"}]), ("example.com/o/xtool/v0", [{"introduced": "0"}])])
net = mknet([rec]); it = pa.inv.Item("tool", "xtool", "0.5.0", "")
finds, _ = run(it, net)
assert finds, "ambiguous: kept as a hit"
assert ignored(net) == [], ignored(net)
PY
CASE="a major-1 pin with a /v1 entry in the record is ambiguous the same way: a hit stays a hit, nothing is ignored"
check python3 - "$aud" "$work" "$root" <<'PY'
import sys; exec(open(sys.argv[2] + "/pre.py").read())
pa.GO_TOOLS["xtool"] = "example.com/o/xtool"
rec = record("GO-X-3", [("example.com/o/xtool", [{"introduced": "0"}, {"fixed": "1.0.0"}]), ("example.com/o/xtool/v1", [{"introduced": "0"}])])
net = mknet([rec]); it = pa.inv.Item("tool", "xtool", "1.4.0", "")
finds, _ = run(it, net)
assert finds and ignored(net) == [], (finds, ignored(net))
PY

# --- the table: a tool that is not known to be a Go module is judged as before -------------------------------------------------------------------------------
CASE="a tool NOT in the committed table (owner/repo form, not in GO_TOOLS) is judged as before: the bare-path entry makes 3.1.3 a hit and nothing is ignored"
check python3 - "$aud" "$work" "$root" <<'PY'
import sys; exec(open(sys.argv[2] + "/pre.py").read())
assert "sigstore/cosign" not in pa.GO_TOOLS
net = mknet([G4309], ["GHSA-whqx-f9j3-ch6m"])
finds, _ = run(pa.inv.Item("tool", "sigstore/cosign", "3.1.3", ""), net)
assert finds, "outside the table the old verdict stands"
assert ignored(net) == [], ignored(net)
PY

# --- versions the rule cannot parse: the old verdict stands ------------------------------------------------------------------------------------------------
for V in "3.1.3-rc.1" "3" "v3.1" "latest" "3.1.3.4" "03.1.3" "3.1.x"; do
  CASE="version '$V' does not parse as a plain MAJOR.MINOR.PATCH: the rule does not apply, nothing is ignored, the verdict is the old one (a hit, or the audit stops)"
  check python3 - "$aud" "$work" "$root" "$V" <<'PY'
import sys; exec(open(sys.argv[2] + "/pre.py").read())
net = mknet([G4309], ["GHSA-whqx-f9j3-ch6m"])
try:
    finds, _ = run(cosign(sys.argv[4]), net)
except pa.Fail:
    finds = ["stopped"]   # the audit refusing to judge is also fail closed
assert finds, "an unparseable version must not be cleared"
assert ignored(net) == [], ignored(net)
PY
done
CASE="an empty version is not covered at all (nothing to compare) and nothing is ignored, as before"
check python3 - "$aud" "$work" "$root" <<'PY'
import sys; exec(open(sys.argv[2] + "/pre.py").read())
net = mknet([G4309], ["GHSA-whqx-f9j3-ch6m"])
it = cosign("")
assert net.covered(it) is False and net.lists(it) == ([], []) and ignored(net) == []
PY
CASE="a leading v is a plain version: v3.1.3 (a pin written like a Go tag) gets the same verdict as 3.1.3"
check python3 - "$aud" "$work" "$root" <<'PY'
import sys; exec(open(sys.argv[2] + "/pre.py").read())
finds, _ = run(cosign("v3.1.3"), mknet([G4309], ["GHSA-whqx-f9j3-ch6m"]))
assert finds == [], [(f.kind, f.ids) for f in finds]
PY

# --- records the rule must not trust: fail closed -----------------------------------------------------------------------------------------------------------
CASE="a record with NO entry for the exact path (only the bare path, as the three older cosign advisories have) is ambiguous: 3.1.3 stays a hit and nothing is ignored"
check python3 - "$aud" "$work" "$root" <<'PY'
import sys; exec(open(sys.argv[2] + "/pre.py").read())
rec = record("GO-X-4", [(BARE, [{"introduced": "0"}]), (BARE + "/v2", [{"introduced": "0"}, {"fixed": "2.2.4"}])])
net = mknet([rec]); finds, _ = run(cosign("3.1.3"), net)
assert finds and ignored(net) == [], (finds, ignored(net))
PY
CASE="an affected entry with NO module path at all is ambiguous: a hit stays a hit, nothing is ignored"
check python3 - "$aud" "$work" "$root" <<'PY'
import sys; exec(open(sys.argv[2] + "/pre.py").read())
rec = record("GO-X-5", [(None, [{"introduced": "0"}])])
net = mknet([rec]); finds, _ = run(cosign("3.1.3"), net)
assert finds and ignored(net) == [], (finds, ignored(net))
PY
CASE="paths that only look like /v3 never match it: /v30, /v3x, /v3/sub, /V3 and a different module ending in /v3 (github.com/evil/cosign/v3) are not the matching path"
check python3 - "$aud" "$work" "$root" <<'PY'
import sys; exec(open(sys.argv[2] + "/pre.py").read())
odd = [BARE + "/v30", BARE + "/v3x", BARE + "/v3/sub", BARE + "/V3", "github.com/evil/cosign/v3"]
# alone: no exact entry, so ambiguous -> a hit
rec = record("GO-X-6", [(p, [{"introduced": "0"}]) for p in odd])
net = mknet([rec]); finds, _ = run(cosign("3.1.3"), net)
assert finds, "no entry for the exact path: fail closed"
assert not any(e["path"] == BARE + "/v3" for e in ignored(net))
# next to a real /v3 entry that does not cover 3.1.3: the odd entries are ignored (and logged), the exact entry decides: clean
rec2 = record("GO-X-7", [(BARE + "/v3", [{"introduced": "0"}, {"fixed": "3.0.4"}])] + [(p, [{"introduced": "0"}]) for p in odd])
net2 = mknet([rec2]); f2, _ = run(cosign("3.1.3"), net2)
assert f2 == [], [(f.kind, f.ids) for f in f2]
assert sorted(e["path"] for e in ignored(net2, True)) == sorted(odd), ignored(net2)
PY
CASE="a crafted record cannot make a real hit disappear: the exact /v3 entry covers 3.1.3 (introduced 0, fixed 3.5.0) next to a bare entry fixed 1.0.0 and a foreign /v3: still a hit"
check python3 - "$aud" "$work" "$root" <<'PY'
import sys; exec(open(sys.argv[2] + "/pre.py").read())
rec = record("GO-X-8", [(BARE, [{"introduced": "0"}, {"fixed": "1.0.0"}]), (BARE + "/v3", [{"introduced": "0"}, {"fixed": "3.5.0"}]), ("github.com/evil/cosign/v3", [{"introduced": "0"}, {"fixed": "0.0.1"}])])
for sup in (True, False):
    finds, _ = run(cosign("3.1.3"), mknet([rec], superset=sup))
    assert finds, ("the exact entry is affected", sup)
PY
CASE="two records for one pin: ignoring the entries of one record never touches the other record's verdict (a second advisory that affects 3.1.3 on the /v3 path is still a hit)"
check python3 - "$aud" "$work" "$root" <<'PY'
import sys; exec(open(sys.argv[2] + "/pre.py").read())
rec2 = record("GO-X-9", [(BARE + "/v3", [{"introduced": "3.0.0"}, {"fixed": "3.2.0"}])])
finds, _ = run(cosign("3.1.3"), mknet([G4309, rec2], ["GHSA-whqx-f9j3-ch6m"]))
assert "GO-X-9" in ids(finds) and "GO-2026-4309" not in ids(finds), [(f.kind, f.ids) for f in finds]
PY

# --- what must keep working -----------------------------------------------------------------------------------------------------------------------------------
CASE="the five existing cosign 3.1.3 rulings in .github/supply-chain-exceptions.json keep working with the live records, with the table as it is today AND as corrected to /v3: every one of the five advisories yields no finding"
check python3 - "$aud" "$work" "$root" <<'PY'
import sys; exec(open(sys.argv[2] + "/pre.py").read())
exc = pa.load_exceptions(root + "/.github/supply-chain-exceptions.json", True)
pairs = [("GO-2024-2718", "GHSA-88jx-383q-w4qc"), ("GO-2024-2719", "GHSA-95pr-fxf5-86gv"), ("GO-2023-2181", "GHSA-vfp6-jrw2-99g9"),
         ("GO-2026-5694", "GHSA-w6c6-c85g-mmv6"), ("GO-2026-4529", "GHSA-wfqv-66vq-46rm")]
for go, gh in pairs:
    for sup in (True, False):
        rec = load("osv-%s.json" % go); rec["aliases"] = sorted(set(rec.get("aliases", [])) | {gh})
        for table in (BARE, BARE + "/v3"):      # the table as it is today (bare) and as step 7 corrects it for the pinned 3.x (the rulings are about the bare path's GitHub ranges: they must still bind)
            net = mknet([rec], [gh], superset=sup)
            it = cosign("3.1.3"); pa.GO_TOOLS["cosign"] = table
            finds, notes = run(it, net, exc)
            assert finds == [], (go, sup, table, [(f.kind, f.ids) for f in finds])
PY
CASE="a hit on another tool's real advisory is untouched: trivy 0.69.4 vs a record that lists the bare path affected is still a hit (major 0 tool, bare path counts)"
check python3 - "$aud" "$work" "$root" <<'PY'
import sys; exec(open(sys.argv[2] + "/pre.py").read())
rec = record("GO-X-10", [("github.com/aquasecurity/trivy", [{"introduced": "0.69.0"}, {"fixed": "0.70.0"}])])
finds, _ = run(pa.inv.Item("tool", "trivy", "0.69.4", ""), mknet([rec]))
assert finds, "an ordinary affected version is a hit"
PY

# --- the table must be right for the versions we pin (advisor ruling, step 5) -----------------------------------------------------------------------------
CASE="TABLE CORRECTNESS: for every tool in GO_TOOLS that the tree pins (tool: items from bin/install-scanner.sh and the installer inputs; gotool: items by module path), the table path is the bare path for major 0/1 and ends in /vMAJOR for major >= 2"
check python3 - "$aud" "$work" "$root" <<'PY'
import re, sys; exec(open(sys.argv[2] + "/pre.py").read())
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
assert {"trivy", "grype", "syft", "osv", "gitsign", "scout", "goreleaser", "golangci-lint"} <= set(pinned), ("the check would be vacuous; found only", sorted(pinned))
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
CASE="a table entry that does NOT match the pinned major stays a HIT even when the record would otherwise be ignorable: cosign 3.1.3 with the table at the bare path, at /v2 or at /v30 is a hit in both OSV answer modes and nothing is ignored; with the right path it is clean"
check python3 - "$aud" "$work" "$root" <<'PY'
import sys; exec(open(sys.argv[2] + "/pre.py").read())
for wrong in (BARE, BARE + "/v2", BARE + "/v30", BARE + "/v3x"):
    for sup in (True, False):
        net = mknet([G4309], ["GHSA-whqx-f9j3-ch6m"], superset=sup)
        it = cosign("3.1.3"); pa.GO_TOOLS["cosign"] = wrong      # after cosign(): the table is now wrong for 3.x
        finds, _ = run(it, net)
        assert finds, ("a mismatching table entry must stay a hit", wrong, sup)
        assert ignored(net) == [], (wrong, sup, ignored(net))
net = mknet([G4309], ["GHSA-whqx-f9j3-ch6m"], superset=True)
it = cosign("3.1.3")                                           # the right entry
finds, _ = run(it, net)
assert finds == [], [(f.kind, f.ids) for f in finds]
PY

# --- the program itself: the table is the one in the source and pin-audit.py still runs --------------------------------------------------------------------
CASE="GO_TOOLS is the one committed table of Go tools (cosign is in it, rooted at its module), and the audit has no second, hidden table"
check python3 - "$aud" "$work" "$root" <<'PY'
import sys; exec(open(sys.argv[2] + "/pre.py").read())
assert "cosign" in pa.GO_TOOLS and pa.GO_TOOLS["cosign"].startswith(BARE)
src = open(sys.argv[1]).read()
import re
assert len(re.findall(r"^GO_TOOLS\s*=", src, re.M)) == 1
PY
CASE="the audit's own offline suite still passes (pin-audit-test.sh): the new rule changes no existing verdict"
check bash "$here/pin-audit-test.sh"
CASE="the fixtures record when they were read and from where"
check python3 - "$root" <<'PY'
import glob, json, sys
d = sys.argv[1] + "/.github/agent/fixtures/pin-audit-go-major"
assert len(glob.glob(d + "/osv-*.json")) == 6 and len(glob.glob(d + "/ghsa-*.json")) == 6
assert "2026-10-09" in open(d + "/README").read()
PY

echo "pass=$pass fail=$failn"
if [ $((pass + failn)) != "$EXPECT" ]; then echo "FAIL case count $((pass + failn)) != expected $EXPECT (a case was skipped or added)"; exit 1; fi
[ "$failn" = 0 ]
