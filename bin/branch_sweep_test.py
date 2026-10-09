#!/usr/bin/env python3
"""Tests for REQ-REPO-001 (branch hygiene without a human). Stdlib plus PyYAML (as the other workflow tests use).

The implementation under test is found under BRANCH_SWEEP_ROOT (default: the repository this file is in):
  bin/branch-sweep.py   plan(branches, prs, keep, now, repo=, default_branch=) -> decisions
                        parse_keep(text, now) -> (kept_names, errors)
                        main(argv, env, runner, now) -> exit code
  bin/local-prune.sh    the lane's local prune
  .github/workflows/reserved-branch-guard.yml, .github/workflows/ci.yml, .github/branch-keep.json

Runner contract (injected into main): runner(method, path) -> (http_status, body_text, headers) where path has no
leading slash ("repos/o/r/branches?per_page=100&page=2") and header names are lower-case.
"""
import base64, contextlib, copy, datetime as dt, hashlib, importlib.util, io, json, os, re, shutil, subprocess
import sys, tempfile, unittest, urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
REAL = os.path.dirname(HERE)
ROOT = os.environ.get("BRANCH_SWEEP_ROOT") or REAL
# the layout rule: this suite must not carry the literal path of the scanner's tree (built, never written)
AUD = ".github/" + "ag" + "ent"

NOW = dt.datetime(2026, 10, 8, 12, 0, 0, tzinfo=dt.timezone.utc)
D = dt.timedelta


def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def sha_of(name):
    return hashlib.sha1(name.encode()).hexdigest()


_MOD = {}


def S():
    if "m" not in _MOD:
        path = os.path.join(ROOT, "bin", "branch-sweep.py")
        spec = importlib.util.spec_from_file_location("branch_sweep_under_test", path)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        _MOD["m"] = m
    return _MOD["m"]


def pr(n, head, base="main", state="open", merged=False, hrepo="o/r", sha=None):
    return {"number": n, "state": state, "merged_at": iso(NOW - D(days=1)) if merged else None,
            "created_at": iso(NOW - D(days=100) + D(hours=n)),
            "head": {"ref": head, "sha": sha or sha_of(head), "repo": ({"full_name": hrepo} if hrepo else None)},
            "base": {"ref": base}}


def B(name, days=30, **kw):
    return {"name": name, "sha": sha_of(name), "committed": iso(NOW - D(days=days)) if days is not None else None}


def plan_map(branches, prs=(), keep=(), **kw):
    out = S().plan(branches, list(prs), set(keep), NOW, **kw)
    return {d["branch"]: d for d in out}


def keepfile(*entries):
    return json.dumps({"keep": list(entries)})


def kentry(branch, days=10, reason="in flight"):
    return {"branch": branch, "expires": (NOW + D(days=days)).strftime("%Y-%m-%d"), "reason": reason}


# --------------------------------------------------------------------------------------------- the fake GitHub
class GH:
    def __init__(self, branches=(), prs=(), keep=None, keep_refs=None, default="main", repo="o/r", cap=None,
                 fail=None, fail_delete=(), bad_commit=(), keep_status=None, protected=(), before=None, delete_status=None,
                 endless=None):
        self.repo, self.default, self.cap = repo, default, cap
        self.branches = [{"name": n, "sha": sha_of(n), "age": a} for n, a in branches]
        self.prs, self.keep, self.keep_refs = list(prs), keep, keep_refs
        self.fail, self.fail_delete, self.bad_commit, self.keep_status = fail, set(fail_delete), set(bad_commit), keep_status
        self.protected = set(protected)
        self.before, self.delete_status, self.endless = before, dict(delete_status or {}), endless
        self.calls = []

    def deletes(self):
        return [p for m, p in self.calls if m == "DELETE"]

    def _page(self, items, q):
        per = min(int(q.get("per_page", ["30"])[0]), 100)
        if self.cap:
            per = min(per, self.cap)
        page = int(q.get("page", ["1"])[0])
        chunk = items[(page - 1) * per: page * per]
        hdr = {"link": '<https://api.github.com/x?page=%d>; rel="next"' % (page + 1)} if page * per < len(items) else {}
        return 200, json.dumps(chunk), hdr

    def __call__(self, method, path):
        self.calls.append((method, path))
        if len(self.calls) > 20000:
            raise RuntimeError("runaway: the sweeper never stopped asking")
        if self.before:
            self.before(self, method, path)
        u = urllib.parse.urlsplit(path)
        q = urllib.parse.parse_qs(u.query)
        p = u.path
        r = "repos/%s" % self.repo
        if self.fail:
            f = self.fail(method, p, q)
            if f:
                return f[0], f[1], {}
        if method == "GET" and p == r:
            return 200, json.dumps({"full_name": self.repo, "default_branch": self.default}), {}
        if method == "GET" and p in (r + "/branches", r + "/pulls") and self.endless:
            kind, mode = self.endless
            if p.endswith(kind):
                pg = int(q.get("page", ["1"])[0])
                n = 1 if mode == "repeat" else pg
                item = ({"name": "feat/e%d" % n, "commit": {"sha": sha_of("e%d" % n)}, "protected": False} if kind == "branches"
                        else pr(n, "feat/e%d" % n, state="closed"))
                return 200, json.dumps([item]), {"link": '<https://api.github.com/x?page=%d>; rel="next"' % (pg + 1)}
        if method == "GET" and p == r + "/branches":
            return self._page([{"name": b["name"], "commit": {"sha": b["sha"]}, "protected": b["name"] in self.protected} for b in self.branches], q)
        if method == "GET" and p == r + "/pulls":
            st = q.get("state", ["open"])[0]
            sel = [x for x in self.prs if st == "all" or x["state"] == st]
            if "head" in q:
                owner, _, ref = q["head"][0].partition(":")
                sel = [x for x in sel if x["head"]["ref"] == ref and ((x["head"].get("repo") or {}).get("full_name") or "/").split("/")[0].casefold() == owner.casefold()]
            if "base" in q:
                sel = [x for x in sel if x["base"]["ref"] == q["base"][0]]
            return self._page(sel, q)
        if method == "GET" and p.startswith(r + "/git/ref/heads/"):
            name = urllib.parse.unquote(p[len(r + "/git/ref/heads/"):])
            for b in self.branches:
                if b["name"] == name:
                    return 200, json.dumps({"ref": "refs/heads/" + name, "object": {"sha": b["sha"], "type": "commit"}}), {}
            return 404, json.dumps({"message": "Not Found"}), {}
        if method == "GET" and p.startswith(r + "/commits/"):
            sha = p.rsplit("/", 1)[1]
            for b in self.branches:
                if b["sha"] == sha and b["name"] not in self.bad_commit:
                    return 200, json.dumps({"sha": sha, "commit": {"committer": {"date": iso(NOW - b["age"])}}}), {}
            return (500 if any(b["sha"] == sha for b in self.branches) else 404), "{}", {}
        if method == "GET" and p == r + "/contents/.github/branch-keep.json":
            if self.keep_status:
                return self.keep_status, "{}", {}
            ref = q.get("ref", [None])[0]
            text = self.keep_refs.get(ref) if self.keep_refs is not None else (self.keep if ref == self.default else None)
            if text is None:
                return 404, json.dumps({"message": "Not Found"}), {}
            return 200, json.dumps({"encoding": "base64", "content": base64.b64encode(text.encode()).decode()}), {}
        if method == "DELETE" and p.startswith(r + "/git/refs/heads/"):
            name = urllib.parse.unquote(p[len(r + "/git/refs/heads/"):])
            if name in self.delete_status:
                return self.delete_status[name], json.dumps({"message": "rate limited"}), {}
            if name in self.fail_delete:
                return 422, json.dumps({"message": "Reference cannot be deleted"}), {}
            for b in self.branches:
                if b["name"] == name:
                    self.branches.remove(b)
                    return 204, "", {}
            return 422, json.dumps({"message": "Reference does not exist"}), {}
        return 404, "{}", {}


def run_main(gh, args=("--apply",), env=None):
    with tempfile.TemporaryDirectory() as td:
        sp = os.path.join(td, "summary.md")
        lp = os.path.join(td, "branch-sweep.log")
        e = {"GITHUB_REPOSITORY": gh.repo, "GITHUB_STEP_SUMMARY": sp, "BRANCH_SWEEP_LOG": lp}
        e.update(env or {})
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = S().main(list(args), e, gh, NOW)
        summary = open(sp).read() if os.path.exists(sp) else ""
        run_main.last_log = open(lp).read() if os.path.exists(lp) else None
    return rc, out.getvalue(), summary


def lines(text, kind):
    return [l for l in text.splitlines() if l.startswith(kind + " ")]


def deleted_names(gh):
    return {urllib.parse.unquote(p.split("/git/refs/heads/", 1)[1]) for p in gh.deletes()}


OLD = D(days=40)

# ------------------------------------------------------------------------------------------------ the planner
class NeverTouched(unittest.TestCase):  # AC1-AC6
    def test_ac1_default_branch(self):
        m = plan_map([B("main"), B("trunk")], [pr(1, "main", base="x", state="closed", merged=True)])
        self.assertEqual((m["main"]["action"], m["main"]["reason"]), ("keep", "default-branch"))
        m = plan_map([B("trunk", 99)], [pr(1, "trunk", state="closed", merged=True)], default_branch="trunk")
        self.assertEqual(m["trunk"]["action"], "keep")

    def test_ac1_only_the_current_default_branch_is_protected(self):
        m = plan_map([B("main", 99), B("trunk", 99)], [pr(1, "main", state="closed", merged=True)], default_branch="trunk")
        self.assertEqual(m["trunk"]["action"], "keep")
        self.assertEqual((m["main"]["action"], m["main"]["reason"]), ("delete", "merged-pr"))
        self.assertEqual(plan_map([B("main", 99)], default_branch="trunk")["main"]["action"], "delete")

    def test_ac1_default_branch_compares_without_case_both_ways(self):
        self.assertEqual(plan_map([B("trunk", 99)], default_branch="Trunk")["trunk"]["action"], "keep")
        self.assertEqual(plan_map([B("TRUNK", 99)], default_branch="trunk")["TRUNK"]["action"], "keep")

    def test_ac1_ac2_ac3_protected_names_compare_without_case(self):
        for name, want in (("MAIN", "default-branch"), ("Main", "default-branch"), ("Release/1", "release"), ("RELEASE/1.2", "release"),
                           ("Dependabot/npm/x", "dependabot"), ("DEPENDABOT/go/y", "dependabot")):
            self.assertEqual(plan_map([B(name, 99)], [pr(1, name, state="closed", merged=True)])[name]["reason"], want, name)

    def test_ac4_repository_names_compare_without_case(self):
        for hrepo in ("O/R", "o/R", "O/r"):
            m = plan_map([B("feat/a", 99)], [pr(1, "feat/a", hrepo=hrepo)], repo="o/r")
            self.assertEqual((m["feat/a"]["action"], m["feat/a"]["reason"]), ("keep", "open-pr"), hrepo)
        m = plan_map([B("feat/a", 99)], [pr(1, "feat/a", hrepo="fosterstack/cache")], repo="FosterStack/Cache")
        self.assertEqual(m["feat/a"]["action"], "keep")
        # and a merged PR from the differently-cased repo still counts for the delete rules
        m = plan_map([B("feat/a", 1)], [pr(1, "feat/a", state="closed", merged=True, hrepo="O/R")], repo="o/r")
        self.assertEqual(m["feat/a"]["reason"], "merged-pr")

    def test_ac2_release_prefix(self):
        for name in ("release/1.2", "release/v3/x"):
            m = plan_map([B(name, 99)], [pr(1, name, state="closed", merged=True)])
            self.assertEqual((m[name]["action"], m[name]["reason"]), ("keep", "release"), name)
        m = plan_map([B("release/1.2", 99)])
        self.assertEqual(m["release/1.2"]["action"], "keep")

    def test_ac2_lookalikes_are_not_release(self):
        for name in ("release", "feat/release/x", "releases/1", "my-release/1"):
            m = plan_map([B(name, 99)])
            self.assertEqual(m[name]["action"], "delete", name)

    def test_ac3_dependabot_prefix(self):
        for name in ("dependabot/npm_and_yarn/x-1.2", "dependabot/github_actions/a/b"):
            for p in ([], [pr(1, name, state="closed", merged=True)], [pr(1, name, state="closed")]):
                m = plan_map([B(name, 99)], p)
                self.assertEqual((m[name]["action"], m[name]["reason"]), ("keep", "dependabot"), name)

    def test_ac3_lookalikes_are_not_dependabot(self):
        for name in ("dependabot-fix", "feat/dependabot/x", "dependabotx/y"):
            self.assertEqual(plan_map([B(name, 99)])[name]["action"], "delete", name)

    def test_ac4_open_pr(self):
        m = plan_map([B("feat/a", 99)], [pr(1, "feat/a")])
        self.assertEqual((m["feat/a"]["action"], m["feat/a"]["reason"]), ("keep", "open-pr"))

    def test_ac4_closed_pr_with_newer_open_pr_from_same_head(self):
        for prs in ([pr(1, "feat/a", state="closed"), pr(2, "feat/a")],
                    [pr(2, "feat/a"), pr(1, "feat/a", state="closed", merged=True)],
                    [pr(1, "feat/a", state="closed", merged=True), pr(2, "feat/a", state="closed"), pr(3, "feat/a")]):
            m = plan_map([B("feat/a", 99)], prs)
            self.assertEqual((m["feat/a"]["action"], m["feat/a"]["reason"]), ("keep", "open-pr"))

    def test_ac4_fork_pr_with_same_branch_name_protects_nothing(self):
        for prs in ([pr(1, "feat/a", hrepo="fork/r")], [pr(1, "feat/a", hrepo=None)]):
            self.assertEqual(plan_map([B("feat/a", 99)], prs)["feat/a"]["action"], "delete")

    def test_ac5_base_of_open_pr_kept_even_if_merged(self):
        prs = [pr(1, "feat/base", state="closed", merged=True), pr(2, "feat/top", base="feat/base")]
        m = plan_map([B("feat/base", 99), B("feat/top", 1)], prs)
        self.assertEqual((m["feat/base"]["action"], m["feat/base"]["reason"]), ("keep", "base-of-open-pr"))

    def test_ac5_base_of_open_pr_kept_when_idle_or_closed_pr(self):
        for prs in ([pr(2, "feat/top", base="feat/base")],
                    [pr(1, "feat/base", state="closed"), pr(2, "feat/top", base="feat/base")],
                    [pr(2, "feat/top", base="feat/base", hrepo="fork/r")]):
            m = plan_map([B("feat/base", 99)], prs)
            self.assertEqual(m["feat/base"]["action"], "keep")

    def test_ac5_once_the_open_pr_is_gone_the_ordinary_rules_apply(self):
        for st, merged in (("closed", True), ("closed", False)):
            prs = [pr(1, "feat/base", state="closed", merged=True), pr(2, "feat/top", base="feat/base", state=st, merged=merged)]
            self.assertEqual(plan_map([B("feat/base", 99)], prs)["feat/base"]["action"], "delete")

    def test_ac6_keep_file_name_protects_exactly(self):
        m = plan_map([B("feat/k", 99), B("feat/x", 99)], [pr(1, "feat/k", state="closed", merged=True)], keep={"feat/k"})
        self.assertEqual((m["feat/k"]["action"], m["feat/k"]["reason"]), ("keep", "keep-file"))
        self.assertEqual(m["feat/x"]["action"], "delete")

    def test_ac25_protected_branch_is_kept(self):
        for prs in ([], [pr(1, "feat/p", state="closed", merged=True)], [pr(1, "feat/p", state="closed")]):
            b = dict(B("feat/p", 99), protected=True)
            d = plan_map([b], prs)["feat/p"]
            self.assertEqual((d["action"], d["reason"]), ("keep", "protected"))
        b = dict(B("feat/q", 99), protected=False)
        self.assertEqual(plan_map([b])["feat/q"]["action"], "delete")

    def test_ac6_no_wildcard(self):
        self.assertEqual(plan_map([B("feat/x", 99)], keep={"feat/*", "*", "feat/"})["feat/x"]["action"], "delete")


class DeleteRules(unittest.TestCase):  # AC7-AC9
    def test_ac7_merged_pr(self):
        m = plan_map([B("feat/a", 1)], [pr(1, "feat/a", state="closed", merged=True)])
        self.assertEqual((m["feat/a"]["action"], m["feat/a"]["reason"]), ("delete", "merged-pr"))

    def test_ac7_newer_merged_beats_an_older_closed_pr(self):
        m = plan_map([B("feat/a", 1)], [pr(1, "feat/a", state="closed"), pr(2, "feat/a", state="closed", merged=True)])
        self.assertEqual(m["feat/a"]["reason"], "merged-pr")

    def test_ac7_ac8_pr_reason_needs_the_tip_to_be_the_pr_head(self):
        other = "e" * 40
        for kw, what in (({"state": "closed", "merged": True}, "merged"), ({"state": "closed"}, "closed")):
            # new commits after the PR: an old branch falls to the idle rule, a recent one is kept
            old = plan_map([B("feat/a", 99)], [pr(1, "feat/a", sha=other, **kw)])["feat/a"]
            self.assertEqual((old["action"], old["reason"]), ("delete", "idle-14d"), what)
            new = plan_map([B("feat/a", 1)], [pr(1, "feat/a", sha=other, **kw)])["feat/a"]
            self.assertEqual((new["action"], new["reason"]), ("keep", "recent"), what)
            # and a PR whose head is the tip still decides
            self.assertEqual(plan_map([B("feat/a", 1)], [pr(1, "feat/a", sha=sha_of("feat/a"), **kw)])["feat/a"]["action"], "delete")

    def test_ac7_ac8_the_newest_pr_at_the_tip_decides_the_reason(self):
        m = plan_map([B("feat/a", 1)], [pr(1, "feat/a", state="closed", merged=True), pr(2, "feat/a", state="closed")])
        self.assertEqual(m["feat/a"]["reason"], "closed-pr")
        m = plan_map([B("feat/a", 1)], [pr(2, "feat/a", state="closed"), pr(1, "feat/a", state="closed", merged=True)])
        self.assertEqual(m["feat/a"]["reason"], "closed-pr")
        m = plan_map([B("feat/a", 1)], [pr(1, "feat/a", state="closed"), pr(2, "feat/a", state="closed", merged=True)])
        self.assertEqual(m["feat/a"]["reason"], "merged-pr")
        # a PR at an older head does not take part in the decision
        m = plan_map([B("feat/a", 1)], [pr(1, "feat/a", state="closed", merged=True), pr(2, "feat/a", state="closed", sha="d" * 40)])
        self.assertEqual(m["feat/a"]["reason"], "merged-pr")

    def test_ac8_closed_pr(self):
        m = plan_map([B("feat/a", 1)], [pr(1, "feat/a", state="closed")])
        self.assertEqual((m["feat/a"]["action"], m["feat/a"]["reason"]), ("delete", "closed-pr"))

    def test_ac9_boundary(self):
        for delta, want in ((D(days=13, hours=23, minutes=59, seconds=59), "keep"), (D(days=13, hours=23), "keep"),
                            (D(days=14), "delete"), (D(days=14, seconds=1), "delete"), (D(days=400), "delete"),
                            (D(0), "keep"), (D(days=-1), "keep")):
            b = {"name": "feat/a", "sha": sha_of("feat/a"), "committed": iso(NOW - delta)}
            d = plan_map([b])["feat/a"]
            self.assertEqual(d["action"], want, delta)
            if want == "delete":
                self.assertEqual(d["reason"], "idle-14d")
            else:
                self.assertEqual(d["reason"], "recent")

    def test_ac9_time_zone_offsets_are_honoured(self):
        # 2026-09-24T14:00:00+02:00 is exactly 14 days before NOW (12:00Z); one hour later is not yet 14 days
        mk = lambda s: {"name": "feat/a", "sha": sha_of("a"), "committed": s}
        self.assertEqual(plan_map([mk("2026-09-24T14:00:00+02:00")])["feat/a"]["action"], "delete")
        self.assertEqual(plan_map([mk("2026-09-24T15:00:00+02:00")])["feat/a"]["action"], "keep")

    def test_ac9_unreadable_date_keeps(self):
        d = plan_map([B("feat/a", None)])["feat/a"]
        self.assertEqual((d["action"], d["reason"]), ("keep", "unknown-age"))

    def test_ac9_a_pr_decides_not_the_age(self):
        self.assertEqual(plan_map([B("feat/a", 1)], [pr(1, "feat/a", state="closed")])["feat/a"]["action"], "delete")

    def test_plan_shape_order_and_purity(self):
        bs = [B("z", 99), B("a", 1), B("release/1", 99)]
        prs = [pr(1, "a")]
        before = copy.deepcopy((bs, prs))
        out = S().plan(bs, prs, set(), NOW)
        self.assertEqual([d["branch"] for d in out], ["z", "a", "release/1"])
        for d, b in zip(out, bs):
            self.assertEqual(d["sha"], b["sha"])
            self.assertIn(d["action"], ("keep", "delete"))
            self.assertTrue(d["reason"])
        self.assertEqual((bs, prs), before)


class KeepFile(unittest.TestCase):  # AC10
    def parse(self, text, now=NOW):
        return S().parse_keep(text, now)

    def test_valid_entry(self):
        kept, errs = self.parse(keepfile(kentry("feat/a", 10), kentry("feat/b", 1)))
        self.assertEqual((kept, errs), ({"feat/a", "feat/b"}, []))

    def test_expiry_today_is_kept_through_the_day(self):
        e = kentry("feat/a", 0)
        self.assertEqual(self.parse(keepfile(e))[0], {"feat/a"})
        late = dt.datetime(2026, 10, 8, 23, 59, 59, tzinfo=dt.timezone.utc)
        self.assertEqual(self.parse(keepfile(e), late)[0], {"feat/a"})
        self.assertEqual(self.parse(keepfile(e), dt.datetime(2026, 10, 9, 0, 0, 0, tzinfo=dt.timezone.utc))[0], set())

    def test_expired_keeps_nothing_and_is_not_malformed(self):
        for days in (-1, -400):
            kept, errs = self.parse(keepfile(kentry("feat/a", days)))
            self.assertEqual((kept, errs), (set(), []))

    def test_cap_60_days(self):
        self.assertEqual(self.parse(keepfile(kentry("feat/a", 60)))[0], {"feat/a"})
        kept, errs = self.parse(keepfile(kentry("feat/a", 61)))
        self.assertEqual(kept, set())
        self.assertTrue(errs and "feat/a" in " ".join(errs))
        kept, errs = self.parse(keepfile(kentry("feat/a", 3650)))
        self.assertEqual(kept, set()); self.assertTrue(errs)

    def test_missing_file_keeps_nothing_without_error(self):
        self.assertEqual(self.parse(None), (set(), []))

    def test_malformed_keeps_nothing_and_errors(self):
        for text in ("{not json", "", "[]", "null", '"x"', "{}", '{"keep": "feat/a"}', '{"keep": {"branch": "a"}}', "\x00\xff"):
            kept, errs = self.parse(text)
            self.assertEqual(kept, set(), text)
            self.assertTrue(errs, text)

    def test_missing_or_mistyped_fields_are_invalid_others_still_count(self):
        good = kentry("feat/good", 5)
        bads = [{"expires": good["expires"], "reason": "r"}, {"branch": "feat/b", "reason": "r"},
                {"branch": "feat/b", "expires": good["expires"]}, {"branch": "feat/b", "expires": 20261201, "reason": "r"},
                {"branch": 7, "expires": good["expires"], "reason": "r"}, {"branch": "", "expires": good["expires"], "reason": "r"},
                "feat/b", None, ["feat/b"]]
        for bad in bads:
            kept, errs = self.parse(keepfile(bad, good))
            self.assertEqual(kept, {"feat/good"}, bad)
            self.assertEqual(len(errs), 1, (bad, errs))

    def test_bad_dates_are_invalid(self):
        for x in ("2026-13-01", "2026-02-30", "10/20/2026", "2026-10-9", "tomorrow", "2026-10-20T00:00:00Z", " 2026-10-20", ""):
            kept, errs = self.parse(keepfile({"branch": "feat/b", "expires": x, "reason": "r"}))
            self.assertEqual((kept, len(errs)), (set(), 1), x)

    def test_duplicate_entries(self):
        kept, errs = self.parse(keepfile(kentry("feat/a", 5), kentry("feat/a", 30), kentry("feat/c", 5)))
        self.assertEqual(kept, {"feat/a", "feat/c"})
        self.assertEqual(len(errs), 1)
        self.assertIn("feat/a", errs[0])

    def test_wildcard_text_is_just_a_name(self):
        kept, _ = self.parse(keepfile(kentry("feat/*", 5)))
        self.assertEqual(kept, {"feat/*"})
        self.assertEqual(plan_map([B("feat/x", 99)], keep=kept)["feat/x"]["action"], "delete")


# -------------------------------------------------------------------------------------------------- main()
def standard():
    old = OLD
    branches = [("main", old), ("release/1.2", old), ("dependabot/npm/x", old), ("feat/open", old), ("feat/base", old),
                ("feat/top", D(days=1)), ("feat/kept", old), ("feat/merged", D(days=1)), ("feat/closed", D(days=1)),
                ("feat/idle", old), ("feat/recent", D(days=3)), ("feat/reopened", old)]
    prs = [pr(1, "feat/open"), pr(2, "feat/base", state="closed", merged=True), pr(3, "feat/top", base="feat/base"),
           pr(4, "feat/merged", state="closed", merged=True), pr(5, "feat/closed", state="closed"),
           pr(6, "feat/reopened", state="closed"), pr(7, "feat/reopened"),
           pr(8, "release/1.2", state="closed", merged=True), pr(9, "dependabot/npm/x", state="closed", merged=True)]
    return GH(branches, prs, keep=keepfile(kentry("feat/kept", 5)))


EXPECT = {"feat/merged", "feat/closed", "feat/idle"}


class MainSweep(unittest.TestCase):
    def test_end_to_end_apply_deletes_exactly_the_right_set(self):
        gh = standard()
        rc, out, summary = run_main(gh)
        self.assertEqual(rc, 0, out)
        self.assertEqual(deleted_names(gh), EXPECT)
        left = {b["name"] for b in gh.branches}
        for keep in ("main", "release/1.2", "dependabot/npm/x", "feat/open", "feat/base", "feat/top", "feat/kept",
                     "feat/recent", "feat/reopened"):
            self.assertIn(keep, left)

    def test_ac25_protected_branches_get_no_delete_call_and_no_failed_line(self):
        gh = GH([("feat/prot", OLD), ("feat/prot2", OLD), ("feat/plain", OLD)], [pr(1, "feat/prot", state="closed", merged=True)],
                protected={"feat/prot", "feat/prot2"}, fail_delete={"feat/prot", "feat/prot2"})
        rc, out, summary = run_main(gh)
        self.assertEqual(rc, 0, out)
        self.assertEqual(deleted_names(gh), {"feat/plain"})
        self.assertEqual(lines(summary, "FAILED"), [])
        looked = {p.rsplit("/", 1)[1] for m, p in gh.calls if "/commits/" in p}
        self.assertNotIn(sha_of("feat/prot2"), looked)

    def test_ac1_ac3_default_branch_other_than_main(self):
        gh = GH([("trunk", OLD), ("main", OLD)], default="trunk", keep=None)
        run_main(gh)
        self.assertNotIn("trunk", deleted_names(gh))
        self.assertIn("main", deleted_names(gh))  # an old default branch is an ordinary branch after a rename

    def test_only_reads_and_ref_deletions(self):
        gh = standard()
        run_main(gh)
        for m, p in gh.calls:
            self.assertIn(m, ("GET", "DELETE"))
            self.assertFalse(p.startswith("/"), p)
            if m == "DELETE":
                self.assertTrue(p.startswith("repos/o/r/git/refs/heads/"), p)

    def test_ac15_ref_api_path_encoding(self):
        names = {"feat/a b": "feat/a%20b", "feat/x#1": "feat/x%231", "fix/ünï": "fix/%C3%BCn%C3%AF", "q?x": "q%3Fx",
                 "p%20q": "p%2520q", "a+b": "a%2Bb", "feat/deep/er/name": "feat/deep/er/name", "日本/語": "%E6%97%A5%E6%9C%AC/%E8%AA%9E"}
        gh = GH([(n, OLD) for n in names])
        rc, out, _ = run_main(gh)
        self.assertEqual(rc, 0, out)
        self.assertEqual(sorted(gh.deletes()), sorted("repos/o/r/git/refs/heads/" + v for v in names.values()))
        self.assertEqual(gh.branches, [])
        for p in gh.deletes():
            self.assertNotRegex(p, r"[ #?]")
        self.assertTrue(all(m == "DELETE" for m, p in gh.calls if "git/refs" in p))

    def test_ac15_never_touches_tags_or_other_refs(self):
        gh = standard()
        run_main(gh)
        for p in gh.deletes():
            self.assertNotIn("refs/tags", p)
        self.assertFalse(any(p.endswith("/heads/main") for p in gh.deletes()))

    def test_ac16_pagination_over_100_branches_and_prs(self):
        names = ["feat/n%03d" % i for i in range(250)]
        branches = [(n, OLD) for n in names] + [("feat/guarded-by-page-3", OLD)]
        prs = [pr(i + 1, "feat/other%03d" % i, state="closed", merged=True) for i in range(230)] + [pr(999, "feat/guarded-by-page-3")]
        gh = GH(branches, prs)
        rc, out, _ = run_main(gh)
        self.assertEqual(rc, 0, out)
        self.assertEqual(deleted_names(gh), set(names))
        self.assertEqual([b["name"] for b in gh.branches], ["feat/guarded-by-page-3"])
        got = [p for m, p in gh.calls if m == "GET" and ("/branches" in p or "/pulls" in p)]
        got = [p for p in got if "state=open" not in p]  # the per-delete re-checks are not listings
        self.assertTrue(all("per_page=100" in p for p in got), got)
        self.assertTrue(any("page=3" in p and "/branches" in p for p in got))
        self.assertTrue(any("page=3" in p and "/pulls" in p for p in got))
        self.assertTrue(all("state=all" in p for p in got if "/pulls" in p))

    def test_ac16_next_link_continues_even_when_the_page_is_short(self):
        names = ["feat/n%02d" % i for i in range(25)]
        gh = GH([(n, OLD) for n in names], cap=7)
        rc, out, _ = run_main(gh)
        self.assertEqual((rc, deleted_names(gh)), (0, set(names)), out)

    def _fail_closed(self, gh):
        S()  # the implementation must exist: an import failure is not a fail-closed pass
        rc, out, summary = run_main(gh)  # a runner exception must come back as an exit code, not escape
        self.assertEqual(gh.deletes(), [], gh.calls)
        self.assertNotEqual(rc, 0)
        return out, summary

    def test_ac16_listing_failures_delete_nothing(self):
        mk = lambda sub, page, status, body="{}": GH([("feat/a", OLD), ("feat/b", OLD)], [pr(1, "feat/c", state="closed")],
                                                    fail=lambda m, p, q: (status, body) if (p.endswith(sub) and (page is None or q.get("page", ["1"])[0] == str(page))) else None)
        for sub, page, status, body in (("/branches", 1, 502, "{}"), ("/pulls", 1, 500, "{}"), ("/pulls", 1, 403, '{"message":"rate limit"}'),
                                        ("/branches", 1, 200, '{"message":"x"}'), ("/pulls", 1, 200, "not json"),
                                        ("/pulls", 1, 200, "null"), ("/branches", 1, 429, "{}"), ("o/r", None, 500, "{}"),
                                        ("/pulls", 1, 502, "[]"), ("/pulls", 1, 403, "[]"),
                                        ("/branches", 1, 404, '{"message":"Not Found"}'), ("/pulls", 1, 404, '{"message":"Not Found"}'),
                                        ("/pulls", 1, 404, "[]"), ("/pulls", 1, 200, "{}")):
            out, summary = self._fail_closed(mk(sub, page, status, body))
            self.assertIn("ERROR", out + summary, (sub, status))

    def test_ac16_failure_on_a_later_page_deletes_nothing(self):
        names = [("feat/n%03d" % i, OLD) for i in range(150)]
        for sub in ("/branches", "/pulls"):
            gh = GH(names, [pr(i + 1, "feat/p%03d" % i, state="closed") for i in range(150)],
                    fail=lambda m, p, q, s=sub: (502, "{}") if (p.endswith(s) and q.get("page") == ["2"]) else None)
            self._fail_closed(gh)

    def test_ac16_runner_exception_deletes_nothing(self):
        def boom(m, p, q):
            raise OSError("network down")
        gh = GH([("feat/a", OLD)], fail=boom)
        self._fail_closed(gh)

    def test_ac12_ac16_runner_exception_at_each_call_class_before_a_delete(self):
        classes = {"repository": lambda m, p: p == "repos/o/r", "branches": lambda m, p: p.endswith("/branches"),
                   "pulls": lambda m, p: p.endswith("/pulls"), "keep-file": lambda m, p: p.endswith("branch-keep.json"),
                   "commit date": lambda m, p: "/commits/" in p}
        for name, pred in classes.items():
            def boom(m, p, q, pred=pred):
                if pred(m, p):
                    raise OSError("network down")
            gh = GH([("feat/a", OLD), ("feat/b", OLD), ("feat/kept", OLD)], [pr(1, "feat/z", state="closed", merged=True)],
                    keep=keepfile(kentry("feat/kept", 5)), fail=boom)
            out, summary = self._fail_closed(gh)
            self.assertIn("ERROR", out + summary, name)

    def test_ac17_runner_exception_on_a_delete_is_a_failed_line_and_the_sweep_continues(self):
        def boom(m, p, q):
            if m == "DELETE" and p.endswith("/feat/b"):
                raise OSError("connection reset")
        gh = GH([("feat/a", OLD), ("feat/b", OLD), ("feat/c", OLD)], fail=boom)
        rc, out, summary = run_main(gh)
        self.assertNotEqual(rc, 0)
        self.assertEqual({b["name"] for b in gh.branches}, {"feat/b"})
        f = lines(summary, "FAILED")
        self.assertEqual(len(f), 1)
        self.assertRegex(f[0], r"FAILED [0-9a-f]{40} idle-14d feat/b$")

    def test_ac16_exact_page_boundaries_and_many_pages(self):
        for n, pages in ((100, 2), (200, 3), (1050, 11)):
            gh = GH([("feat/n%04d" % i, OLD) for i in range(n)])
            rc, out, _ = run_main(gh)
            self.assertEqual((rc, len(gh.deletes()), gh.branches), (0, n, []), (n, out[-300:]))
            asked = [p for m, p in gh.calls if m == "GET" and urllib.parse.urlsplit(p).path.endswith("/branches")]
            self.assertEqual(len(asked), pages, n)

    def test_ac16_a_listing_that_never_ends_or_repeats_fails_closed(self):
        for kind in ("branches", "pulls"):
            for mode in ("endless", "repeat"):
                gh = GH([("feat/a", OLD)], endless=(kind, mode))
                out, summary = self._fail_closed(gh)
                self.assertIn("ERROR", out + summary, (kind, mode))
                listing = [p for m, p in gh.calls if m == "GET" and urllib.parse.urlsplit(p).path.endswith("/" + kind)]
                self.assertLessEqual(len(listing), 205, (kind, mode, len(listing)))
                if mode == "repeat":
                    self.assertLessEqual(len(listing), 5, (kind, mode, len(listing)))  # a repeated page is noticed at once

    def test_ac16_empty_repository_listing_is_not_an_error(self):
        gh = GH([])
        rc, out, summary = run_main(gh)
        self.assertEqual((rc, gh.deletes()), (0, []))
        self.assertNotIn("ERROR", out + summary)

    def test_ac12_keep_file_server_error_fails_closed(self):
        for st in (500, 502, 403, 429):
            out, _ = self._fail_closed(GH([("feat/a", OLD)], keep_status=st))
            self.assertIn("ERROR", out)

    def test_ac10_missing_keep_file_is_normal(self):
        gh = GH([("feat/a", OLD)], keep=None)
        rc, out, summary = run_main(gh)
        self.assertEqual((rc, deleted_names(gh)), (0, {"feat/a"}))
        self.assertNotIn("ERROR", out + summary)

    def test_ac12_malformed_keep_file_still_honours_every_never_touched_rule(self):
        for bad in ("{oops", "[]", '{"keep": 3}', ""):
            gh = standard(); gh.keep = bad
            rc, out, summary = run_main(gh)
            self.assertNotEqual(rc, 0)
            self.assertTrue(lines(summary, "ERROR") and any("keep-file" in l for l in lines(summary, "ERROR")), summary)
            self.assertTrue(any("keep-file" in l for l in lines(out, "ERROR")))
            # the file protected feat/kept before; malformed protects nothing extra, so it is now a plain idle branch
            self.assertEqual(deleted_names(gh), EXPECT | {"feat/kept"}, bad)
            left = {b["name"] for b in gh.branches}
            for keep in ("main", "release/1.2", "dependabot/npm/x", "feat/open", "feat/base", "feat/top", "feat/recent", "feat/reopened"):
                self.assertIn(keep, left, bad)

    def test_ac10_entries_through_main(self):
        text = keepfile(kentry("feat/valid", 5), kentry("feat/expired", -2), kentry("feat/toofar", 90), {"branch": "feat/nofields"},
                        kentry("feat/today", 0))
        gh = GH([(n, OLD) for n in ("feat/valid", "feat/expired", "feat/toofar", "feat/nofields", "feat/today")], keep=text)
        rc, out, summary = run_main(gh)
        self.assertEqual(deleted_names(gh), {"feat/expired", "feat/toofar", "feat/nofields"})
        self.assertNotEqual(rc, 0)
        self.assertEqual(len(lines(summary, "ERROR")), 2, summary)  # toofar and nofields; expired is not an error

    def test_ac11_keep_file_is_read_at_the_default_branch_only(self):
        refs = {"main": keepfile(), "feat/self": keepfile(kentry("feat/self", 5)), "other": keepfile(kentry("feat/self", 5))}
        gh = GH([("feat/self", OLD)], keep_refs=refs)
        run_main(gh)
        self.assertEqual(deleted_names(gh), {"feat/self"})
        reads = [p for m, p in gh.calls if "branch-keep.json" in p]
        self.assertTrue(reads)
        for p in reads:
            self.assertEqual(urllib.parse.parse_qs(urllib.parse.urlsplit(p).query).get("ref"), ["main"], p)
        gh = GH([("feat/x", OLD), ("trunk", OLD)], default="trunk", keep_refs={"trunk": keepfile(kentry("feat/x", 5)), "main": keepfile()})
        run_main(gh)
        self.assertEqual(deleted_names(gh), set())

    def test_ac11_does_not_read_a_checkout(self):
        with tempfile.TemporaryDirectory() as td:
            os.makedirs(os.path.join(td, ".github"))
            open(os.path.join(td, ".github", "branch-keep.json"), "w").write(keepfile(kentry("feat/a", 5)))
            old = os.getcwd(); os.chdir(td)
            try:
                gh = GH([("feat/a", OLD)], keep=None)
                run_main(gh)
            finally:
                os.chdir(old)
        self.assertEqual(deleted_names(gh), {"feat/a"})

    def test_ac13_every_deletion_is_logged_with_sha_and_reason(self):
        gh = standard()
        sha = {b["name"]: b["sha"] for b in gh.branches}
        rc, out, summary = run_main(gh)
        for text in (out, summary):
            got = {}
            for l in lines(text, "DELETE"):
                m = re.fullmatch(r"DELETE ([0-9a-f]{40}) (merged-pr|closed-pr|idle-14d) (.+)", l)
                self.assertTrue(m, l)
                got[m.group(3)] = (m.group(1), m.group(2))
            self.assertEqual(got, {"feat/merged": (sha["feat/merged"], "merged-pr"), "feat/closed": (sha["feat/closed"], "closed-pr"),
                                   "feat/idle": (sha["feat/idle"], "idle-14d")})

    def test_ac13_log_survives_names_with_spaces(self):
        gh = GH([("feat/a b", OLD)])
        _, _, summary = run_main(gh)
        self.assertIn("DELETE %s idle-14d feat/a b" % sha_of("feat/a b"), summary.splitlines())

    def test_ac14_dry_run_is_the_default_and_deletes_nothing(self):
        for args in ((), ("--dry-run",)):
            gh = standard()
            rc, out, summary = run_main(gh, args)
            self.assertEqual(rc, 0, out)
            self.assertEqual(gh.deletes(), [])
            self.assertEqual({m for m, p in gh.calls}, {"GET"})
            self.assertEqual(lines(summary, "DELETE"), [])
            w = {re.fullmatch(r"WOULD-DELETE ([0-9a-f]{40}) (\S+) (.+)", l).group(3) for l in lines(summary, "WOULD-DELETE")}
            self.assertEqual(w, EXPECT)
            for text in (out, summary):
                self.assertIn("dry-run: nothing deleted", text)

    def test_ac14_apply_does_not_claim_dry_run(self):
        _, out, summary = run_main(standard())
        self.assertNotIn("dry-run", out + summary)
        self.assertEqual(lines(summary, "WOULD-DELETE"), [])

    def test_ac17_failed_delete_logs_continues_and_exits_nonzero(self):
        gh = GH([("feat/a", OLD), ("feat/b", OLD), ("feat/c", OLD)], fail_delete={"feat/b"})
        rc, out, summary = run_main(gh)
        self.assertNotEqual(rc, 0)
        self.assertEqual(len(gh.deletes()), 3)
        self.assertEqual({b["name"] for b in gh.branches}, {"feat/b"})
        f = lines(summary, "FAILED")
        self.assertEqual(len(f), 1)
        self.assertRegex(f[0], r"FAILED [0-9a-f]{40} idle-14d feat/b$")
        self.assertEqual(len(lines(summary, "DELETE")), 2)

    def test_ac17_a_branch_that_changed_after_listing_is_skipped(self):
        def before(gh, m, p):
            if m == "GET" and p.startswith("repos/o/r/git/ref/heads/feat/b"):
                for b in gh.branches:
                    if b["name"] == "feat/b":
                        b["sha"] = "f" * 40
        gh = GH([("feat/a", OLD), ("feat/b", OLD), ("feat/c", OLD)], before=before)
        rc, out, summary = run_main(gh)
        self.assertEqual(rc, 0, out)
        self.assertEqual({b["name"] for b in gh.branches}, {"feat/b"})
        self.assertRegex("\n".join(lines(summary, "SKIPPED")), r"SKIPPED changed %s idle-14d feat/b$" % sha_of("feat/b"))
        self.assertEqual(lines(summary, "FAILED"), [])

    def test_ac17_a_pr_opened_after_listing_protects_the_branch(self):
        def before(gh, m, p):
            if m == "GET" and p.startswith("repos/o/r/git/ref/heads/feat/c"):
                gh.prs.append(pr(50, "feat/c"))
            if m == "GET" and p.startswith("repos/o/r/git/ref/heads/feat/d"):
                gh.prs.append(pr(51, "feat/top", base="feat/d"))
        gh = GH([("feat/a", OLD), ("feat/c", OLD), ("feat/d", OLD)], before=before)
        rc, out, summary = run_main(gh)
        self.assertEqual(rc, 0, out)
        self.assertEqual(deleted_names(gh), {"feat/a"})
        self.assertEqual(len(lines(summary, "SKIPPED")), 2)

    def test_ac17_a_branch_already_gone_is_skipped_not_failed(self):
        def before(gh, m, p):
            if m == "GET" and p.startswith("repos/o/r/git/ref/heads/feat/b"):
                gh.branches[:] = [b for b in gh.branches if b["name"] != "feat/b"]
        gh = GH([("feat/a", OLD), ("feat/b", OLD)], before=before)
        rc, out, summary = run_main(gh)
        self.assertEqual((rc, lines(summary, "FAILED")), (0, []))
        self.assertEqual(deleted_names(gh), {"feat/a"})

    def test_ac17_an_unverifiable_recheck_skips_and_fails_the_run(self):
        gh = GH([("feat/a", OLD)], fail=lambda m, p, q: (500, "{}") if (p.endswith("/pulls") and q.get("state") == ["open"]) else None)
        rc, out, summary = run_main(gh)
        self.assertNotEqual(rc, 0)
        self.assertEqual(gh.deletes(), [])

    def test_ac17_any_unusable_open_pr_recheck_answer_skips_as_unverified(self):
        for st, body in ((404, "[]"), (404, '{"message":"Not Found"}'), (500, "[]"), (403, "[]"), (429, "[]"), (200, "{}"), (200, "null")):
            for which in ("head", "base"):
                gh = GH([("feat/a", OLD), ("feat/b", OLD)],
                        fail=lambda m, p, q, st=st, body=body, which=which: (st, body) if (
                            p.endswith("/pulls") and q.get("state") == ["open"] and which in q) else None)
                rc, out, summary = run_main(gh)
                self.assertNotEqual(rc, 0, (st, body, which))
                self.assertEqual(gh.deletes(), [], (st, body, which))
                self.assertTrue(lines(summary, "SKIPPED"), summary)
                for l in lines(summary, "SKIPPED"):
                    self.assertRegex(l, r"SKIPPED unverified [0-9a-f]{40} idle-14d feat/[ab]$")

    def test_ac17_rate_limited_rereads_count_toward_the_stop(self):
        names = ["feat/n%d" % i for i in range(7)]
        for how in ("pulls", "ref"):
            if how == "pulls":
                f = lambda m, p, q: (429, "[]") if (p.endswith("/pulls") and q.get("state") == ["open"]) else None
            else:
                f = lambda m, p, q: (403, "{}") if "/git/ref/heads/" in p else None
            gh = GH([(n, OLD) for n in names], fail=f)
            rc, out, summary = run_main(gh)
            self.assertNotEqual(rc, 0, how)
            self.assertEqual(gh.deletes(), [], how)
            self.assertEqual(len(lines(summary, "SKIPPED")), 3, how)
            self.assertTrue(any("ERROR" in l and "rate" in l for l in summary.splitlines()), summary)
            reread = [p for m, p in gh.calls if "/git/ref/heads/" in p]
            self.assertLessEqual(len(reread), 3, how)

    def test_ac17_a_success_between_rate_limited_rereads_resets_the_count(self):
        names = ["feat/n%d" % i for i in range(5)]
        limited = {"feat/n0", "feat/n1", "feat/n3", "feat/n4"}

        def f(m, p, q):
            if "/git/ref/heads/" in p and urllib.parse.unquote(p.rsplit("/git/ref/heads/", 1)[1]) in limited:
                return 429, "{}"
        gh = GH([(n, OLD) for n in names], fail=f)
        rc, out, summary = run_main(gh)
        self.assertEqual(deleted_names(gh), {"feat/n2"})
        self.assertEqual(len(lines(summary, "SKIPPED")), 4)  # never three in a row

    def test_ac13_each_line_is_in_the_log_before_the_next_api_call(self):
        with tempfile.TemporaryDirectory() as td:
            lp = os.path.join(td, "log")
            seen = []

            def before(gh, m, p):
                if m == "GET" and "/git/ref/heads/" in p or m == "DELETE":
                    seen.append((m, p, open(lp).read().splitlines() if os.path.exists(lp) else []))
            gh = GH([("feat/a", OLD), ("feat/b", OLD), ("feat/c", OLD), ("feat/d", OLD)], fail_delete={"feat/b"}, before=before)

            def skip_c(g, m, p):
                before(g, m, p)
                if m == "GET" and p.startswith("repos/o/r/git/ref/heads/feat/c"):
                    for b in g.branches:
                        if b["name"] == "feat/c":
                            b["sha"] = "f" * 40
            gh.before = skip_c
            run_main(gh, env={"BRANCH_SWEEP_LOG": lp})
        # the call after each outcome already finds that outcome's line in the log
        kinds = [(m, urllib.parse.unquote(re.split(r"/git/refs?/heads/", p)[1]), [l.split(" ")[0] for l in log]) for m, p, log in seen]
        by = {}
        for m, name, log in kinds:
            by.setdefault((m, name), log)
        self.assertEqual(by[("GET", "feat/b")], ["DELETE"])                       # a's DELETE line is there
        self.assertEqual(by[("GET", "feat/c")], ["DELETE", "FAILED"])             # b's FAILED line is there
        self.assertEqual(by[("GET", "feat/d")], ["DELETE", "FAILED", "SKIPPED"])  # c's SKIPPED line is there

    def test_ac13_an_interrupted_sweep_keeps_the_lines_already_written(self):
        class Boom(BaseException):
            pass

        def f(m, p, q):
            if m == "DELETE" and p.endswith("/feat/c"):
                raise Boom()
        names = ["feat/a", "feat/b", "feat/c", "feat/d"]
        gh = GH([(n, OLD) for n in names], fail=f)
        with tempfile.TemporaryDirectory() as td:
            lp = os.path.join(td, "log")
            with self.assertRaises(Boom), contextlib.redirect_stdout(io.StringIO()):
                S().main(["--apply"], {"GITHUB_REPOSITORY": "o/r", "BRANCH_SWEEP_LOG": lp}, gh, NOW)
            got = open(lp).read().splitlines()
        self.assertEqual([l.split(" ")[3] for l in lines("\n".join(got), "DELETE")], ["feat/a", "feat/b"])
        for l in got:
            self.assertRegex(l, r"^(DELETE|SKIPPED|FAILED|WOULD-DELETE|ERROR) ")

    def test_ac17_a_re_read_that_raises_is_unverified_and_the_sweep_carries_on(self):
        probes = {"ref": lambda m, p, q: m == "GET" and p.endswith("/git/ref/heads/feat/a"),
                  "head query": lambda m, p, q: p.endswith("/pulls") and q.get("state") == ["open"] and q.get("head") == ["o:feat/a"],
                  "base query": lambda m, p, q: p.endswith("/pulls") and q.get("state") == ["open"] and q.get("base") == ["feat/a"]}
        for name, hit in probes.items():
            def boom(m, p, q, hit=hit):
                if hit(m, p, q):
                    raise OSError("connection reset")
            gh = GH([("feat/a", OLD), ("feat/b", OLD), ("feat/c", OLD)], fail=boom)
            rc, out, summary = run_main(gh)
            self.assertNotEqual(rc, 0, name)
            self.assertEqual(deleted_names(gh), {"feat/b", "feat/c"}, name)
            self.assertFalse([p for p in gh.deletes() if p.endswith("/feat/a")], name)
            sk = lines(summary, "SKIPPED")
            self.assertEqual(len(sk), 1, (name, summary))
            self.assertEqual(sk[0], "SKIPPED unverified %s idle-14d feat/a" % sha_of("feat/a"), name)

    def test_ac17_a_changed_answer_breaks_the_rate_limit_streak(self):
        names = ["feat/a", "feat/b", "feat/c", "feat/d", "feat/e"]
        limited = {"feat/a", "feat/c", "feat/d"}

        def f(m, p, q):
            if m == "GET" and "/git/ref/heads/" in p and urllib.parse.unquote(p.split("/git/ref/heads/", 1)[1]) in limited:
                return 429, "{}"

        def before(gh, m, p):
            if m == "GET" and p.startswith("repos/o/r/git/ref/heads/feat/b"):
                for b in gh.branches:
                    if b["name"] == "feat/b":
                        b["sha"] = "f" * 40  # b moved: a clean, usable answer that says changed
        gh = GH([(n, OLD) for n in names], fail=f, before=before)
        rc, out, summary = run_main(gh)
        self.assertNotEqual(rc, 0)
        self.assertEqual(deleted_names(gh), {"feat/e"})  # no stop: e was still reached
        self.assertEqual(len(lines(summary, "SKIPPED")), 4)
        self.assertFalse(any("ERROR" in l and "rate" in l for l in summary.splitlines()), summary)

    def test_ac14_a_dry_run_makes_no_recheck_and_no_ref_call(self):
        gh = standard()
        run_main(gh, ())
        self.assertFalse([p for m, p in gh.calls if "/git/ref" in p])

    def test_ac17_three_consecutive_rate_limit_answers_stop_the_run(self):
        names = ["feat/n%d" % i for i in range(7)]
        gh = GH([(n, OLD) for n in names], delete_status={n: 429 for n in names})
        rc, out, summary = run_main(gh)
        self.assertNotEqual(rc, 0)
        self.assertEqual(len(gh.deletes()), 3)
        self.assertEqual(len(lines(summary, "FAILED")), 3)
        self.assertTrue(any("ERROR" in l and "rate" in l for l in summary.splitlines()), summary)

    def test_ac17_a_success_resets_the_rate_limit_count(self):
        names = ["feat/n%d" % i for i in range(7)]
        st = {names[0]: 429, names[1]: 403, names[3]: 403, names[4]: 429, names[5]: 429}
        gh = GH([(n, OLD) for n in names], delete_status=st)
        rc, out, summary = run_main(gh)
        self.assertNotEqual(rc, 0)
        self.assertEqual(len(gh.deletes()), 6)  # n0 n1 ok n3 n4 n5 -> stop before n6
        self.assertNotIn(urllib.parse.quote(names[6]), " ".join(gh.deletes()))

    def test_ac17_other_refusals_do_not_trip_the_rate_limit_stop(self):
        names = ["feat/n%d" % i for i in range(6)]
        gh = GH([(n, OLD) for n in names], delete_status={n: 422 for n in names[:5]})
        run_main(gh)
        self.assertEqual(len(gh.deletes()), 6)

    def test_ac13_the_same_lines_go_to_the_artifact_log(self):
        gh = standard()
        rc, out, summary = run_main(gh)
        self.assertIsNotNone(run_main.last_log)
        self.assertEqual(run_main.last_log.splitlines(), summary.splitlines())
        self.assertTrue(lines(run_main.last_log, "DELETE"))

    def test_ac7_a_tip_that_differs_from_the_pr_head_falls_to_the_idle_rule_end_to_end(self):
        prs = [pr(1, "feat/m", state="closed", merged=True, sha="a" * 40), pr(2, "feat/c", state="closed", sha="b" * 40)]
        gh = GH([("feat/m", OLD), ("feat/c", D(days=1)), ("feat/ok", D(days=1))], prs + [pr(3, "feat/ok", state="closed", merged=True)])
        rc, out, summary = run_main(gh)
        got = {re.fullmatch(r"DELETE \S+ (\S+) (.+)", l).group(2): re.fullmatch(r"DELETE \S+ (\S+) (.+)", l).group(1) for l in lines(summary, "DELETE")}
        self.assertEqual(got, {"feat/m": "idle-14d", "feat/ok": "merged-pr"})
        looked = {p.rsplit("/", 1)[1].split("?")[0] for m, p in gh.calls if "/commits/" in p}
        self.assertIn(sha_of("feat/m"), looked)  # a branch whose PR is not at its tip needs its commit date

    def test_ac17_idempotent(self):
        gh = standard()
        run_main(gh)
        n = len(gh.deletes())
        gh.calls.clear()
        rc, out, summary = run_main(gh)
        self.assertEqual((rc, gh.deletes()), (0, []))
        self.assertEqual(lines(summary, "DELETE"), [])
        self.assertGreater(n, 0)

    def test_commit_lookup_only_for_branches_that_need_an_age(self):
        gh = standard()
        run_main(gh)
        looked = {p.rsplit("/", 1)[1].split("?")[0] for m, p in gh.calls if "/commits/" in p}
        for n in ("main", "release/1.2", "dependabot/npm/x", "feat/open", "feat/base", "feat/top", "feat/merged", "feat/closed", "feat/reopened", "feat/kept"):
            self.assertNotIn(sha_of(n), looked, n)
        self.assertLessEqual(looked, {sha_of("feat/idle"), sha_of("feat/recent")})

    def test_unreadable_commit_date_keeps_that_branch_only(self):
        gh = GH([("feat/a", OLD), ("feat/b", OLD)], bad_commit={"feat/a"})
        rc, out, summary = run_main(gh)
        self.assertEqual(deleted_names(gh), {"feat/b"})
        self.assertNotEqual(rc, 0)

    def test_fork_pr_and_fork_branches_do_not_count(self):
        gh = GH([("feat/a", OLD)], [pr(1, "feat/a", hrepo="fork/r")])
        run_main(gh)
        self.assertEqual(deleted_names(gh), {"feat/a"})

    def test_idle_boundary_through_main(self):
        gh = GH([("feat/old", D(days=14)), ("feat/new", D(days=13, hours=23))])
        run_main(gh)
        self.assertEqual(deleted_names(gh), {"feat/old"})

    def test_unknown_argument_refuses_and_deletes_nothing(self):
        for args in (("--aply",), ("--apply", "--force"), ("apply",)):
            gh = standard()
            rc, out, _ = run_main(gh, args)
            self.assertNotEqual(rc, 0, args)
            self.assertEqual(gh.deletes(), [], args)

    def test_source_uses_no_shell(self):
        src = open(os.path.join(ROOT, "bin", "branch-sweep.py")).read()
        for bad in ("shell=True", "os.system", "os.popen", "git push", "--force"):
            self.assertNotIn(bad, src)
        self.assertNotIn(AUD, src)


# ----------------------------------------------------------------------------------------- workflow wiring
def load_yaml(rel):
    import yaml
    with open(os.path.join(ROOT, rel)) as fh:
        return yaml.load(fh, Loader=yaml.BaseLoader), open(os.path.join(ROOT, rel)).read()


def _truthy(v):
    return v not in (None, False, "", 0)


def _num(v):
    if v is None:
        return 0.0
    if isinstance(v, bool):
        return 1.0 if v else 0.0
    if isinstance(v, str):
        if v.strip() == "":
            return 0.0
        try:
            return float(v)
        except ValueError:
            return float("nan")
    return float(v)


def _gh_eq(a, b):
    if type(a) == type(b):
        return a.casefold() == b.casefold() if isinstance(a, str) else a == b
    return _num(a) == _num(b)


def gh_eval(expr, ctx):
    """A small model of GitHub's expression language (loose == by number coercion, && || returning operands, format())."""
    e = str(expr).strip()
    m = re.fullmatch(r"\$\{\{(.*)\}\}", e, re.S)
    e = (m.group(1) if m else e).strip()
    toks = re.findall(r"'(?:[^']|\'\')*'|==|!=|&&|\|\||[!(),]|[A-Za-z_][A-Za-z_0-9.\-]*|\S", e)
    pos = [0]

    def peek():
        return toks[pos[0]] if pos[0] < len(toks) else None

    def nxt():
        pos[0] += 1
        return toks[pos[0] - 1]

    def p_or():
        v = p_and()
        while peek() == "||":
            nxt(); r = p_and(); v = v if _truthy(v) else r
        return v

    def p_and():
        v = p_eq()
        while peek() == "&&":
            nxt(); r = p_eq(); v = r if _truthy(v) else v
        return v

    def p_eq():
        v = p_un()
        while peek() in ("==", "!="):
            op = nxt(); r = p_un(); res = _gh_eq(v, r); v = res if op == "==" else not res
        return v

    def p_un():
        if peek() == "!":
            nxt(); return not _truthy(p_un())
        return p_prim()

    def p_prim():
        tk = nxt()
        if tk == "(":
            v = p_or()
            assert nxt() == ")", expr
            return v
        if tk.startswith("'"):
            return tk[1:-1].replace("''", "'")
        if tk in ("true", "false"):
            return tk == "true"
        if tk == "null":
            return None
        if peek() == "(":
            nxt(); args = []
            while peek() != ")":
                args.append(p_or())
                if peek() == ",":
                    nxt()
            nxt()
            if tk != "format":
                raise AssertionError("unsupported function %r in %r" % (tk, expr))
            def fmt(v):
                return "" if v is None else "true" if v is True else "false" if v is False else str(v)
            return re.sub(r"\{(\d+)\}", lambda mm: fmt(args[int(mm.group(1)) + 1]), args[0])
        if tk not in ctx:
            raise AssertionError("unsupported context %r in %r" % (tk, expr))
        return ctx[tk]
    v = p_or()
    assert pos[0] == len(toks), "trailing tokens in %r" % expr
    return v


def eval_if(expr, event, ref, default="main"):
    if expr is None:
        return True
    ctx = {"github.event_name": event, "github.ref": ref, "github.event.repository.default_branch": default,
           "github.ref_name": re.sub(r"^refs/(heads|tags)/", "", ref)}
    return _truthy(gh_eval(expr, ctx))


GUARD = "reserved-branch-guard.yml"
CI = "ci.yml"


def wf(name=GUARD):
    return load_yaml(".github/workflows/" + name)


def sweep_job(d):
    cands = [(k, j) for k, j in (d.get("jobs") or {}).items() if any("branch-sweep.py" in (s.get("run") or "") for s in j.get("steps") or [])]
    if len(cands) != 1:
        raise AssertionError("expected exactly one job that runs bin/branch-sweep.py, found %s" % [k for k, _ in cands])
    return cands[0]


class Wiring(unittest.TestCase):  # AC18-AC20
    def test_triggers(self):
        d, _ = wf()
        on = d["on"]
        self.assertEqual(on["push"]["branches"], ["auditor/**"])
        sched = on["schedule"]
        self.assertEqual(len(sched), 1)
        f = sched[0]["cron"].split()
        self.assertEqual(len(f), 5)
        self.assertEqual(f[2:], ["*", "*", "*"], "daily")
        self.assertTrue(f[0].isdigit() and f[1].isdigit())
        inp = on["workflow_dispatch"]["inputs"]["dry-run"]
        self.assertEqual(str(inp["default"]).lower(), "true")

    def test_guard_job_runs_only_on_push(self):
        d, text = wf()
        g = d["jobs"]["guard"]
        self.assertEqual(g["name"], "only-the-app-pushes-auditor-lane")
        for ev, ref, want in (("push", "refs/heads/auditor/x", True), ("push", "refs/heads/main", True), ("schedule", "refs/heads/main", False),
                              ("workflow_dispatch", "refs/heads/main", False), ("workflow_dispatch", "refs/heads/feat/x", False)):
            self.assertEqual(eval_if(g.get("if"), ev, ref), want, (ev, ref))
        run = " ".join(s.get("run", "") for s in g["steps"])
        self.assertIn("fosterstack-automation", run)

    def test_sweep_job_runs_only_on_schedule_or_dispatch_from_the_default_branch(self):
        d, _ = wf()
        _, j = sweep_job(d)
        for ev, ref, want in (("push", "refs/heads/auditor/x", False), ("push", "refs/heads/main", False), ("schedule", "refs/heads/main", True),
                              ("workflow_dispatch", "refs/heads/main", True), ("workflow_dispatch", "refs/heads/feat/x", False),
                              ("workflow_dispatch", "refs/tags/v1", False), ("pull_request", "refs/heads/main", False)):
            self.assertEqual(eval_if(j.get("if"), ev, ref), want, (ev, ref))

    def test_permissions_are_exactly_what_the_sweep_needs(self):
        d, _ = wf()
        self.assertEqual(d["permissions"], {"contents": "read"})
        _, j = sweep_job(d)
        self.assertEqual(j["permissions"], {"contents": "write", "pull-requests": "read"})
        gp = d["jobs"]["guard"].get("permissions")
        self.assertIn(gp, (None, {"contents": "read"}))

    def test_no_secrets(self):
        d, text = wf()
        sweep_job(d)
        self.assertNotRegex(text, r"secrets\.|secrets:\s*inherit|\bvars\.|GITHUB_PAT|ghp_|github_pat_")

    def test_every_action_reference_is_a_full_digest_and_nothing_else_runs_code(self):
        d, text = wf()
        sweep_job(d)
        n = 0
        for ln in text.splitlines():
            m = re.match(r"\s*-?\s*uses:\s*(\S+)(.*)$", ln)
            if m:
                n += 1
                self.assertRegex(m.group(1), r"^[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+@[0-9a-f]{40}$", ln)
                self.assertRegex(m.group(2), r"^\s+#\s*v?\d", ln)
        for j in d["jobs"].values():
            self.assertNotIn("container", j); self.assertNotIn("services", j)
            self.assertNotIn("uses", j)
            for s in j.get("steps") or []:
                self.assertFalse(str(s.get("uses", "")).startswith(("docker://", "./", ".")), s)
        self.assertNotIn("docker://", text)

    def test_checkout_if_any_keeps_no_credentials(self):
        d, _ = wf()
        _, j = sweep_job(d)
        for s in j["steps"]:
            if str(s.get("uses", "")).startswith("actions/checkout@"):
                self.assertEqual(str((s.get("with") or {}).get("persist-credentials")).lower(), "false")

    def test_no_expression_in_any_run_step_of_the_sweep(self):
        d, _ = wf()
        _, j = sweep_job(d)
        for s in j["steps"]:
            self.assertNotIn("${{", s.get("run") or "")

    def test_dry_run_default_is_not_bypassed(self):
        d, text = wf()
        _, j = sweep_job(d)
        conds = [j.get("if")] + [s.get("if") for s in j["steps"]]
        for c in conds:
            self.assertNotRegex(str(c or ""), r"(?i)dry[-_]?run")
        step = [s for s in j["steps"] if "branch-sweep.py" in (s.get("run") or "")][0]
        blob = json.dumps(step)
        if "--apply" in blob:
            self.assertRegex(blob, r"(?i)dry[-_]?run", "--apply must be conditional on the dry-run input")
        self.assertRegex(json.dumps(j), r"(?i)dry[-_]?run")

    def _run_step(self, step, env):
        """run a workflow step's shell text with a fake python3 that records its arguments; returns (rc, args)"""
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "args")
            fb = os.path.join(td, "fb"); os.makedirs(fb)
            open(os.path.join(fb, "python3"), "w").write('#!/bin/sh\necho "$*" > "$ARGS_OUT"\n')
            os.chmod(os.path.join(fb, "python3"), 0o755)
            e = dict(os.environ, PATH=fb + os.pathsep + os.environ["PATH"], ARGS_OUT=out)
            e.update(env)
            p = subprocess.run(["bash", "-c", step["run"]], cwd=td, env=e, capture_output=True, text=True)
            return p.returncode, (open(out).read().split() if os.path.exists(out) else None), p.stderr

    def test_apply_decision_follows_the_trigger_and_the_input(self):
        """only a schedule applies; a dispatch applies only when dry-run is exactly false: every other value is a dry run"""
        d, _ = wf()
        _, j = sweep_job(d)
        step = [s for s in j["steps"] if "branch-sweep.py" in (s.get("run") or "")][0]
        expr = (step.get("env") or {}).get("DRY_RUN")
        self.assertIsNotNone(expr, "the step must receive the mode as env DRY_RUN")
        rows = [("schedule", None, True), ("schedule", True, True),
                ("workflow_dispatch", False, True), ("workflow_dispatch", "false", True), ("workflow_dispatch", "FALSE", True),
                ("workflow_dispatch", True, False), ("workflow_dispatch", "true", False), ("workflow_dispatch", None, False),
                ("workflow_dispatch", "", False), ("workflow_dispatch", "garbage", False), ("workflow_dispatch", "0", False),
                ("workflow_dispatch", " false", False), ("workflow_dispatch", "no", False), ("workflow_dispatch", 0, False),
                ("push", None, False), ("workflow_run", None, False)]
        for ev, inp, want_apply in rows:
            val = gh_eval(expr, {"github.event_name": ev, "inputs.dry-run": inp})
            val = "true" if val is True else "false" if val is False else "" if val is None else str(val)
            rc, args, err = self._run_step(step, {"DRY_RUN": val})
            self.assertEqual(rc, 0, err)
            self.assertIsNotNone(args)
            self.assertIn("bin/branch-sweep.py", args)
            self.assertEqual("--apply" in args, want_apply, (ev, inp, val, args))

    def test_dry_run_unset_or_odd_environment_never_applies(self):
        d, _ = wf()
        _, j = sweep_job(d)
        step = [s for s in j["steps"] if "branch-sweep.py" in (s.get("run") or "")][0]
        for val in ("", "true", "TRUE", "garbage", "False ", "0"):
            rc, args, err = self._run_step(step, {"DRY_RUN": val})
            self.assertEqual(rc, 0, err)
            self.assertNotIn("--apply", args, val)
        env = {k: v for k, v in os.environ.items() if k != "DRY_RUN"}
        with tempfile.TemporaryDirectory() as td:
            fb = os.path.join(td, "fb"); os.makedirs(fb)
            open(os.path.join(fb, "python3"), "w").write('#!/bin/sh\necho "$*" > "$ARGS_OUT"\n')
            os.chmod(os.path.join(fb, "python3"), 0o755)
            env.update(PATH=fb + os.pathsep + env["PATH"], ARGS_OUT=os.path.join(td, "a"))
            subprocess.run(["bash", "-c", step["run"]], env=env, cwd=td, capture_output=True)
            if os.path.exists(os.path.join(td, "a")):
                self.assertNotIn("--apply", open(os.path.join(td, "a")).read())

    def test_sweep_condition_uses_the_repositorys_default_branch(self):
        d, _ = wf()
        _, j = sweep_job(d)
        for ev, ref, default, want in (("workflow_dispatch", "refs/heads/trunk", "trunk", True), ("schedule", "refs/heads/trunk", "trunk", True),
                                       ("workflow_dispatch", "refs/heads/main", "trunk", False), ("schedule", "refs/heads/main", "main", True),
                                       ("workflow_dispatch", "refs/heads/feat/x", "trunk", False), ("workflow_dispatch", "refs/tags/trunk", "trunk", False)):
            self.assertEqual(eval_if(j.get("if"), ev, ref, default), want, (ev, ref, default))

    def test_the_log_is_uploaded_as_a_retained_artifact(self):
        d, _ = wf()
        _, j = sweep_job(d)
        ci = open(os.path.join(ROOT, ".github", "workflows", CI)).read()
        pinned = re.findall(r"actions/upload-artifact@([0-9a-f]{40})", ci)
        self.assertTrue(pinned)
        ups = [s for s in j["steps"] if str(s.get("uses", "")).startswith("actions/upload-artifact@")]
        self.assertEqual(len(ups), 1)
        self.assertEqual(ups[0]["uses"].split("@")[1].split()[0], pinned[0])
        self.assertEqual(ups[0]["with"]["name"], "branch-sweep-log")
        self.assertEqual(str(ups[0]["with"]["retention-days"]), "90")
        self.assertIn("always()", str(ups[0].get("if", "")))
        step = [s for s in j["steps"] if "branch-sweep.py" in (s.get("run") or "")][0]
        self.assertEqual(step["env"]["BRANCH_SWEEP_LOG"], ups[0]["with"]["path"])
        self.assertTrue(j["steps"].index(ups[0]) > j["steps"].index(step))

    def test_guard_step_still_rejects_every_pusher_but_the_app(self):
        d, _ = wf()
        sweep_job(d)  # the guard is judged in the workflow that now also carries the sweep
        step = [s for s in d["jobs"]["guard"]["steps"] if "github.actor" in (s.get("run") or "")][0]
        for actor, ok in (("fosterstack-automation[bot]", True), ("fosterstack-automation", True), ("octocat", False),
                          ("fosterstack-automation-evil", False), ("", False)):
            text = step["run"].replace("${{ github.actor }}", actor)
            p = subprocess.run(["bash", "-c", text], capture_output=True, text=True)
            self.assertEqual(p.returncode == 0, ok, (actor, p.stderr))

    def test_sweep_runs_the_checked_in_script_with_the_job_token(self):
        d, _ = wf()
        _, j = sweep_job(d)
        blob = json.dumps(j)
        self.assertIn("bin/branch-sweep.py", blob)
        self.assertIn("github.token", blob)
        self.assertNotIn("--force", blob)

    def test_ac20_ci_allowlist_job_runs_the_suite(self):
        d, _ = wf(CI)
        steps = d["jobs"]["allowlist"]["steps"]
        hit = [s for s in steps if re.search(r"\bbash bin/branch-sweep-test\.sh\b", s.get("run") or "")]
        self.assertEqual(len(hit), 1)
        self.assertNotIn("if", hit[0])
        self.assertNotEqual(str(hit[0].get("continue-on-error", "false")).lower(), "true")


FAKE_GH = """#!/usr/bin/env python3
import json, os, sys
d = os.environ["FAKE_GH_DIR"]
a = sys.argv[1:]
assert a[:2] == ["api", "-i"], a
method, path = a[a.index("-X") + 1], a[-1]
open(d + "/calls", "a").write(method + " " + path + "\\n")
r = json.load(open(d + "/table.json")).get(method + " " + path, [404, "{}", {}])
if r == "NETWORK":
    sys.stderr.write("error connecting to api.github.com\\n"); sys.exit(1)
st, body, hdr = r
sys.stdout.write("HTTP/2.0 %d %s\\r\\n" % (st, {200: "OK", 204: "No Content", 404: "Not Found"}.get(st, "Error")))
for k, v in hdr.items():
    sys.stdout.write("%s: %s\\r\\n" % (k, v))
sys.stdout.write("\\r\\n" + body)
sys.exit(0 if st < 300 else 1)
"""


class RealRunner(unittest.TestCase):  # AC12, AC16, AC17 through the real gh api -i runner
    def setUp(self):
        self.td = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.td, True)
        os.makedirs(os.path.join(self.td, "bin"))
        g = os.path.join(self.td, "bin", "gh")
        open(g, "w").write(FAKE_GH)
        os.chmod(g, 0o755)
        self.env = dict(PATH=os.path.join(self.td, "bin") + os.pathsep + os.environ["PATH"], FAKE_GH_DIR=self.td)

    def table(self, t):
        json.dump(t, open(os.path.join(self.td, "table.json"), "w"))

    def calls(self):
        f = os.path.join(self.td, "calls")
        return open(f).read().splitlines() if os.path.exists(f) else []

    def real(self, method, path):
        import unittest.mock as um
        with um.patch.dict(os.environ, self.env):
            return S().default_runner(method, path)

    def test_status_headers_and_body_are_parsed(self):
        self.table({"GET repos/o/r/x": [200, "[1, 2]", {"Link": '<https://api.github.com/p?page=2>; rel="next"', "X-Other": "v"}],
                    "GET repos/o/r/missing": [404, '{"message":"Not Found"}', {}], "GET repos/o/r/boom": [502, "<html>", {}],
                    "DELETE repos/o/r/git/refs/heads/a": [204, "", {}], "GET repos/o/r/down": "NETWORK"})
        st, body, hdr = self.real("GET", "repos/o/r/x")
        self.assertEqual((st, json.loads(body)), (200, [1, 2]))
        self.assertIn('rel="next"', hdr.get("link", ""))
        self.assertEqual(self.real("GET", "repos/o/r/missing")[0], 404)
        self.assertEqual(self.real("GET", "repos/o/r/boom")[0], 502)
        self.assertEqual(self.real("DELETE", "repos/o/r/git/refs/heads/a")[0], 204)
        try:
            st = self.real("GET", "repos/o/r/down")[0]
        except Exception:
            st = 599
        self.assertFalse(200 <= st < 300)
        self.assertTrue(all(c.split(" ")[0] in ("GET", "DELETE") for c in self.calls()))

    def _record(self, gh):
        table = {}

        def rec(method, path):
            r = gh(method, path)
            table[method + " " + path] = [r[0], r[1], {"Link": r[2]["link"]} if r[2].get("link") else {}]
            return r
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            S().main(["--apply"], {"GITHUB_REPOSITORY": "o/r"}, rec, NOW)
        return table

    def run_real(self, args=("--apply",)):
        import unittest.mock as um
        with tempfile.TemporaryDirectory() as td2:
            sp = os.path.join(td2, "s.md")
            out = io.StringIO()
            with um.patch.dict(os.environ, self.env), contextlib.redirect_stdout(out):
                rc = S().main(list(args), {"GITHUB_REPOSITORY": "o/r", "GITHUB_STEP_SUMMARY": sp}, None, NOW)
            return rc, out.getvalue(), (open(sp).read() if os.path.exists(sp) else "")

    def scenario(self):
        gh = GH([("feat/a", OLD), ("feat/b", OLD), ("release/1", OLD)], [pr(1, "feat/z", state="closed", merged=True)], keep=None)
        return self._record(gh)

    def test_end_to_end_through_the_real_runner(self):
        self.table(self.scenario())
        rc, out, summary = self.run_real()
        self.assertEqual(rc, 0, out)
        d = [c for c in self.calls() if c.startswith("DELETE")]
        self.assertEqual(sorted(d), ["DELETE repos/o/r/git/refs/heads/feat/a", "DELETE repos/o/r/git/refs/heads/feat/b"])
        self.assertEqual(len(lines(summary, "DELETE")), 2)

    def test_keep_file_404_is_missing_but_5xx_and_network_errors_fail_closed(self):
        base = self.scenario()
        key = [k for k in base if "branch-keep.json" in k][0]
        for label, val, ok in (("404", [404, '{"message":"Not Found"}', {}], True), ("500", [500, "{}", {}], False),
                               ("403", [403, "{}", {}], False), ("network", "NETWORK", False)):
            t = dict(base); t[key] = val
            self.table(t)
            open(os.path.join(self.td, "calls"), "w").write("")
            rc, out, summary = self.run_real()
            dels = [c for c in self.calls() if c.startswith("DELETE")]
            if ok:
                self.assertEqual((rc, len(dels)), (0, 2), label)
            else:
                self.assertNotEqual(rc, 0, label)
                self.assertEqual(dels, [], label)

    def test_a_network_error_on_a_listing_or_a_delete(self):
        base = self.scenario()
        for sub in ("/branches?", "/pulls?"):
            key = [k for k in base if sub in k][0]
            t = dict(base); t[key] = "NETWORK"
            self.table(t)
            open(os.path.join(self.td, "calls"), "w").write("")
            rc, out, _ = self.run_real()
            self.assertNotEqual(rc, 0, sub)
            self.assertEqual([c for c in self.calls() if c.startswith("DELETE")], [], sub)
        t = dict(base); t["DELETE repos/o/r/git/refs/heads/feat/a"] = "NETWORK"
        self.table(t)
        open(os.path.join(self.td, "calls"), "w").write("")
        rc, out, summary = self.run_real()
        self.assertNotEqual(rc, 0)
        self.assertEqual(len(lines(summary, "FAILED")), 1)
        self.assertEqual(len(lines(summary, "DELETE")), 1)


class Layout(unittest.TestCase):  # AC21
    FILES = ["bin/branch-sweep.py", "bin/local-prune.sh", "bin/branch-sweep-test.sh", "bin/branch_sweep_test.py", ".github/branch-keep.json"]

    def test_files_exist_outside_the_scanner_tree_and_do_not_name_it(self):
        for f in self.FILES:
            self.assertTrue(os.path.isfile(os.path.join(ROOT, f)), f)
            self.assertNotIn("auditor", f.lower())
            self.assertFalse(f.startswith(AUD + "/"))
            self.assertNotIn(AUD.encode(), open(os.path.join(ROOT, f), "rb").read(), f)

    def test_layout_check_stays_green(self):
        files = self.FILES + [".github/workflows/reserved-branch-guard.yml", ".github/workflows/ci.yml"]
        chk = os.path.join(REAL, AUD, "bin", "auditor-layout-check.py")
        p = subprocess.run([sys.executable, chk, "--root", ROOT], input="\n".join(files) + "\n", capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertTrue(all(os.path.isfile(os.path.join(ROOT, f)) for f in files))

    def test_requirement_text_does_not_carry_the_scanner_path(self):
        self.assertTrue(os.path.isfile(os.path.join(ROOT, "bin", "branch-sweep.py")))
        t = open(os.path.join(ROOT, "requirements", "requirements.yaml")).read()
        i = t.index("id: REQ-REPO-001")
        j = t.find("\n  - id: REQ-", i + 10)
        self.assertNotIn(AUD, t[i: j if j > 0 else len(t)])

    def test_requirement_loads_and_has_25_mapped_acs(self):
        import yaml
        self.assertTrue(os.path.isfile(os.path.join(ROOT, "bin", "branch-sweep.py")))
        req = yaml.safe_load(open(os.path.join(ROOT, "requirements", "requirements.yaml")))
        mine = [r for r in req["requirements"] if r["id"] == "REQ-REPO-001"]
        self.assertEqual(len(mine), 1)
        ids = [a["id"] for a in mine[0]["acceptance_criteria"]]
        self.assertEqual(ids, ["REQ-REPO-001-AC%d" % i for i in range(1, 26)])
        for a in mine[0]["acceptance_criteria"]:
            for k in ("given", "when", "then"):
                self.assertTrue(isinstance(a[k], str) and a[k].strip(), (a["id"], k))
        maps = yaml.safe_load(open(os.path.join(ROOT, "test-evidence", "mappings.yaml")))["mappings"]
        by = {m["ac"]: m["evidence"] for m in maps}
        for i in ids:
            self.assertIn({"type": "shell-test", "ref": "bin/branch-sweep-test.sh"}, by.get(i, []), i)
        head = open(os.path.join(ROOT, "bin", "branch-sweep-test.sh")).read().splitlines()[1]
        for i in ids:
            self.assertIn(i, head.replace(",", " ").split())

    def test_keep_file_shipped_is_valid(self):
        text = open(os.path.join(ROOT, ".github", "branch-keep.json")).read()
        kept, errs = S().parse_keep(text, dt.datetime.now(dt.timezone.utc))  # the real clock, not the frozen test time
        self.assertEqual(errs, [])
        for e in json.loads(text)["keep"]:
            self.assertTrue(e["reason"])


# ----------------------------------------------------------------------------------------------- local prune
def sh(*a, cwd=None, env=None, check=True):
    e = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@e", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@e",
             GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_SYSTEM="/dev/null")
    e.update(env or {})
    p = subprocess.run(list(a), cwd=cwd, env=e, capture_output=True, text=True)
    if check and p.returncode:
        raise AssertionError("%s -> %s %s" % (a, p.returncode, p.stderr))
    return p


class Prune(unittest.TestCase):  # AC22-AC24
    def setUp(self):
        self.td = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.td, True)
        self.origin = os.path.join(self.td, "origin.git")
        self.w = os.path.join(self.td, "work")
        sh("git", "init", "-q", "--bare", "-b", "main", self.origin)
        sh("git", "clone", "-q", self.origin, self.w)
        sh("git", "checkout", "-q", "-b", "main", cwd=self.w, check=False)
        self.commit("base")
        sh("git", "push", "-q", "-u", "origin", "main", cwd=self.w)
        self.ghdir = os.path.join(self.td, "gh"); os.makedirs(self.ghdir)
        self.bin = os.path.join(self.td, "bin"); os.makedirs(self.bin)
        g = os.path.join(self.bin, "gh")
        open(g, "w").write('#!/usr/bin/env bash\necho "$*" >> "$FAKE_GH_DIR/_calls"\n[ -f "$FAKE_GH_DIR/_down" ] && exit 1\n'
                           'b=""; while [ $# -gt 0 ]; do [ "$1" = --head ] && b=$2; shift; done\n'
                           'f="$FAKE_GH_DIR/${b//\\//__}.json"\nif [ -f "$f" ]; then cat "$f"; else echo "[]"; fi\n')
        os.chmod(g, 0o755)

    def commit(self, msg, cwd=None):
        cwd = cwd or self.w
        open(os.path.join(cwd, msg.replace("/", "_") + ".txt"), "w").write(msg)
        sh("git", "add", "-A", cwd=cwd); sh("git", "commit", "-q", "-m", msg, cwd=cwd)

    def branch(self, name, push=True, merged=False):
        sh("git", "checkout", "-q", "-b", name, "main", cwd=self.w)
        self.commit("work-" + name)
        if push:
            sh("git", "push", "-q", "-u", "origin", name, cwd=self.w)
        sh("git", "checkout", "-q", "main", cwd=self.w)
        if merged:
            sh("git", "merge", "-q", "--no-ff", "-m", "merge " + name, name, cwd=self.w)
            sh("git", "push", "-q", "origin", "main", cwd=self.w)
        return sh("git", "rev-parse", name, cwd=self.w).stdout.strip()

    def gone(self, name):
        sh("git", "push", "-q", "origin", "--delete", name, cwd=self.w)

    def prs(self, name, *states, cross=False, sha=None):
        tip = sha or sh("git", "rev-parse", "refs/heads/" + name, cwd=self.w).stdout.strip()
        open(os.path.join(self.ghdir, name.replace("/", "__") + ".json"), "w").write(
            json.dumps([{"state": s, "headRefOid": tip, "isCrossRepository": cross} for s in states]))

    def prs_raw(self, name, items):
        open(os.path.join(self.ghdir, name.replace("/", "__") + ".json"), "w").write(json.dumps(items))

    def commit_on(self, name, msg):
        sh("git", "checkout", "-q", name, cwd=self.w)
        self.commit(msg)
        sh("git", "checkout", "-q", "main", cwd=self.w)

    def run_prune(self, *args, cwd=None):
        self.assertTrue(os.path.isfile(os.path.join(ROOT, "bin", "local-prune.sh")), "bin/local-prune.sh does not exist")
        env = {"PATH": self.bin + os.pathsep + os.environ["PATH"], "FAKE_GH_DIR": self.ghdir}
        return sh("bash", os.path.join(ROOT, "bin", "local-prune.sh"), *args, cwd=cwd or self.w, env=env, check=False)

    def exists(self, name):
        return sh("git", "rev-parse", "--verify", "-q", "refs/heads/" + name, cwd=self.w, check=False).returncode == 0

    def test_ac22_gone_and_merged_into_main_is_deleted_and_restorable(self):
        sha = self.branch("feat/a", merged=True); self.gone("feat/a")
        p = self.run_prune("--apply")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertFalse(self.exists("feat/a"))
        self.assertRegex(p.stdout, r"deleted branch feat/a %s merged-into-main" % sha)
        sh("git", "branch", "restored", sha, cwd=self.w)  # restorable from the printed sha

    def test_ac22_gone_and_merged_into_main_needs_no_gh(self):
        self.branch("feat/a", merged=True); self.gone("feat/a")
        open(os.path.join(self.ghdir, "_down"), "w").write("")
        self.run_prune("--apply")
        self.assertFalse(self.exists("feat/a"))

    def test_ac22_gone_squash_merged_pr_is_deleted(self):
        sha = self.branch("feat/s"); self.gone("feat/s"); self.prs("feat/s", "MERGED")
        p = self.run_prune("--apply")
        self.assertFalse(self.exists("feat/s"))
        self.assertRegex(p.stdout, r"deleted branch feat/s %s pr-merged" % sha)

    def test_ac22_it_fetches_with_prune_so_a_remote_deletion_made_elsewhere_is_seen(self):
        sha = self.branch("feat/a", merged=True)
        other = os.path.join(self.td, "other")
        sh("git", "clone", "-q", self.origin, other)
        sh("git", "push", "-q", "origin", "--delete", "feat/a", cwd=other)
        self.assertIn("origin/feat/a", sh("git", "branch", "-r", cwd=self.w).stdout)  # not yet known here
        self.run_prune("--apply")
        self.assertFalse(self.exists("feat/a"))

    def test_ac22_a_post_merge_local_commit_keeps_the_branch(self):
        for state in ("MERGED", "CLOSED"):
            b = "feat/" + state.lower()
            self.branch(b); self.prs(b, state); self.gone(b)
            self.commit_on(b, "after-" + state)  # unpushed work the PR never saw
        p = self.run_prune("--apply")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertTrue(self.exists("feat/merged") and self.exists("feat/closed"))
        self.assertNotRegex(p.stdout, r"(?m)^deleted ")

    def test_ac22_a_fork_pr_with_the_same_branch_name_authorises_nothing(self):
        self.branch("fix"); self.gone("fix"); self.prs("fix", "MERGED", cross=True)
        self.branch("patch-1"); self.gone("patch-1"); self.prs("patch-1", "CLOSED", cross=True)
        self.run_prune("--apply")
        self.assertTrue(self.exists("fix") and self.exists("patch-1"))

    def test_ac22_a_fork_pr_is_ignored_next_to_a_real_one(self):
        tip = self.branch("feat/a"); self.gone("feat/a")
        self.prs_raw("feat/a", [{"state": "OPEN", "headRefOid": tip, "isCrossRepository": True},
                                {"state": "MERGED", "headRefOid": tip, "isCrossRepository": False}])
        self.run_prune("--apply")
        self.assertFalse(self.exists("feat/a"))

    def test_ac22_the_pr_lookup_asks_for_the_head_commit_and_the_repository(self):
        self.branch("feat/a"); self.gone("feat/a"); self.prs("feat/a", "MERGED")
        self.run_prune("--apply")
        calls = open(os.path.join(self.ghdir, "_calls")).read()
        self.assertIn("--json state,headRefOid,isCrossRepository", calls)

    def test_ac23_a_branch_being_rebased_in_a_worktree_is_kept(self):
        self.branch("feat/wt"); self.gone("feat/wt")
        sh("git", "checkout", "-q", "-b", "other", "main", cwd=self.w)
        open(os.path.join(self.w, "clash.txt"), "w").write("A"); sh("git", "add", "-A", cwd=self.w); sh("git", "commit", "-q", "-m", "A", cwd=self.w)
        sh("git", "checkout", "-q", "main", cwd=self.w)
        wt = os.path.join(self.td, "wt")
        sh("git", "worktree", "add", "-q", wt, "feat/wt", cwd=self.w)
        open(os.path.join(wt, "clash.txt"), "w").write("B"); sh("git", "add", "-A", cwd=wt); sh("git", "commit", "-q", "-m", "B", cwd=wt)
        self.prs("feat/wt", "MERGED")
        r = sh("git", "rebase", "other", cwd=wt, check=False)
        self.assertNotEqual(r.returncode, 0)  # stopped on the conflict: HEAD is detached
        p = self.run_prune("--apply")
        self.assertEqual(p.stderr, "")
        self.assertTrue(self.exists("feat/wt"))
        self.assertNotRegex(p.stdout, r"(?m)^deleted ")

    def test_ac22_gone_closed_pr_is_deleted(self):
        sha = self.branch("feat/c"); self.gone("feat/c"); self.prs("feat/c", "CLOSED")
        p = self.run_prune("--apply")
        self.assertFalse(self.exists("feat/c"))
        self.assertRegex(p.stdout, r"deleted branch feat/c %s pr-closed" % sha)

    def test_ac22_merged_and_closed_mixed_without_open_is_deleted(self):
        self.branch("feat/c"); self.gone("feat/c"); self.prs("feat/c", "CLOSED", "MERGED")
        self.run_prune("--apply")
        self.assertFalse(self.exists("feat/c"))

    def test_ac22_names_with_slashes_and_spaces_in_the_pr_lookup(self):
        self.branch("feat/deep/name"); self.gone("feat/deep/name"); self.prs("feat/deep/name", "MERGED")
        self.run_prune("--apply")
        self.assertFalse(self.exists("feat/deep/name"))
        calls = open(os.path.join(self.ghdir, "_calls")).read().splitlines()
        self.assertTrue(all(c.startswith("pr list") and "--head feat/deep/name" in c for c in calls), calls)

    def test_ac23_unmerged_with_open_or_unknown_pr_is_kept(self):
        self.branch("feat/open"); self.gone("feat/open"); self.prs("feat/open", "OPEN")
        self.branch("feat/nopr"); self.gone("feat/nopr")
        self.branch("feat/mixed"); self.gone("feat/mixed"); self.prs("feat/mixed", "CLOSED", "OPEN")
        self.branch("feat/unknown"); self.gone("feat/unknown"); self.prs("feat/unknown", "MERGED")
        open(os.path.join(self.ghdir, "_down"), "w").write("")
        self.run_prune("--apply")
        for b in ("feat/open", "feat/nopr", "feat/mixed", "feat/unknown"):
            self.assertTrue(self.exists(b), b)

    def test_ac23_open_pr_is_kept_when_gh_is_up(self):
        self.branch("feat/open"); self.gone("feat/open"); self.prs("feat/open", "OPEN")
        self.branch("feat/mixed"); self.gone("feat/mixed"); self.prs("feat/mixed", "MERGED", "OPEN")
        self.run_prune("--apply")
        self.assertTrue(self.exists("feat/open") and self.exists("feat/mixed"))

    def test_ac23_no_upstream_is_kept_even_if_merged(self):
        sha = self.branch("wip/local", push=False, merged=True)
        self.prs("wip/local", "MERGED")
        self.run_prune("--apply")
        self.assertTrue(self.exists("wip/local"))
        self.assertEqual(sh("git", "rev-parse", "wip/local", cwd=self.w).stdout.strip(), sha)

    def test_ac23_upstream_still_present_is_kept(self):
        self.branch("feat/live", merged=True); self.prs("feat/live", "MERGED")
        self.run_prune("--apply")
        self.assertTrue(self.exists("feat/live"))

    def test_ac23_main_is_kept(self):
        self.run_prune("--apply")
        self.assertTrue(self.exists("main"))

    def test_ac23_current_branch_is_kept(self):
        self.branch("feat/here", merged=True); self.gone("feat/here")
        sh("git", "checkout", "-q", "feat/here", cwd=self.w)
        p = self.run_prune("--apply")
        self.assertEqual(p.stderr, "")
        self.assertNotRegex(p.stdout, r"(?m)^(deleted|would delete) branch feat/here")
        self.assertTrue(self.exists("feat/here"))
        self.assertEqual(sh("git", "symbolic-ref", "--short", "HEAD", cwd=self.w).stdout.strip(), "feat/here")

    def test_ac23_branch_checked_out_in_a_live_worktree_is_kept_and_dirty_work_survives(self):
        self.branch("feat/wt", merged=True); self.gone("feat/wt")
        wt = os.path.join(self.td, "wt")
        sh("git", "worktree", "add", "-q", wt, "feat/wt", cwd=self.w)
        open(os.path.join(wt, "uncommitted.txt"), "w").write("precious")
        open(os.path.join(wt, "feat_wt.txt"), "a").write("edit")
        p = self.run_prune("--apply")
        self.assertEqual(p.stderr, "")
        self.assertNotRegex(p.stdout, r"(?m)^(deleted|would delete) branch feat/wt")
        self.assertTrue(self.exists("feat/wt"))
        self.assertEqual(open(os.path.join(wt, "uncommitted.txt")).read(), "precious")
        self.assertIn("edit", open(os.path.join(wt, "feat_wt.txt")).read())
        self.assertIn(wt, sh("git", "worktree", "list", cwd=self.w).stdout)

    def test_ac23_clean_live_worktree_is_kept_too(self):
        self.branch("feat/wt", merged=True); self.gone("feat/wt")
        wt = os.path.join(self.td, "wt")
        sh("git", "worktree", "add", "-q", wt, "feat/wt", cwd=self.w)
        p = self.run_prune("--apply")
        self.assertEqual(p.stderr, "")
        self.assertNotRegex(p.stdout, r"(?m)^(deleted|would delete) branch feat/wt")
        self.assertTrue(self.exists("feat/wt") and os.path.isdir(wt))

    def test_ac22_worktree_record_with_missing_directory_is_pruned_then_branch_goes(self):
        self.branch("feat/wt", merged=True); self.gone("feat/wt")
        wt = os.path.join(self.td, "wt")
        sh("git", "worktree", "add", "-q", wt, "feat/wt", cwd=self.w)
        shutil.rmtree(wt)
        p = self.run_prune("--apply")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn("wt", sh("git", "worktree", "list", cwd=self.w).stdout.replace("work", ""))
        self.assertFalse(self.exists("feat/wt"))

    def test_ac24_default_is_dry_run_and_changes_nothing(self):
        sha = self.branch("feat/a", merged=True); self.gone("feat/a")
        self.branch("feat/b"); self.gone("feat/b"); self.prs("feat/b", "CLOSED")
        self.branch("feat/wt", merged=True); self.gone("feat/wt")
        wt = os.path.join(self.td, "wt")
        sh("git", "worktree", "add", "-q", wt, "feat/wt", cwd=self.w)
        shutil.rmtree(wt)
        before = (sh("git", "branch", "-a", cwd=self.w).stdout, sh("git", "worktree", "list", cwd=self.w).stdout)
        p = self.run_prune()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual((sh("git", "worktree", "list", cwd=self.w).stdout), before[1])
        for b in ("feat/a", "feat/b", "feat/wt"):
            self.assertTrue(self.exists(b), b)
        self.assertRegex(p.stdout, r"would delete branch feat/a %s merged-into-main" % sha)
        self.assertRegex(p.stdout, r"would delete branch feat/b [0-9a-f]{40} pr-closed")
        self.assertIn("dry-run", p.stdout)
        self.assertNotRegex(p.stdout, r"(?m)^deleted ")

    def test_ac24_unknown_argument_changes_nothing(self):
        self.branch("feat/a", merged=True); self.gone("feat/a")
        p = self.run_prune("--aply")
        self.assertNotEqual(p.returncode, 0)
        self.assertTrue(self.exists("feat/a"))

    def test_ac22_idempotent(self):
        self.branch("feat/a", merged=True); self.gone("feat/a")
        self.run_prune("--apply")
        p = self.run_prune("--apply")
        self.assertEqual(p.returncode, 0)
        self.assertNotRegex(p.stdout, r"(?m)^deleted ")

    def test_ac22_mixed_repo_exact_outcome(self):
        self.branch("feat/del1", merged=True); self.gone("feat/del1")
        self.branch("feat/del2"); self.gone("feat/del2"); self.prs("feat/del2", "MERGED")
        self.branch("feat/keep-open"); self.gone("feat/keep-open"); self.prs("feat/keep-open", "OPEN")
        self.branch("wip/x", push=False)
        self.branch("feat/live")
        self.run_prune("--apply")
        have = {l.strip().lstrip("* ") for l in sh("git", "branch", "--format=%(refname:short)", cwd=self.w).stdout.splitlines()}
        self.assertEqual(have, {"main", "feat/keep-open", "wip/x", "feat/live"})

    def test_local_prune_never_runs_a_mutating_gh_command(self):
        src = open(os.path.join(ROOT, "bin", "local-prune.sh")).read()
        self.assertNotRegex(src, r"gh\s+(pr\s+(close|merge|edit)|api\s+-X|repo\s+delete)")
        self.assertNotIn("push", src.replace("# ", ""))
        self.assertNotIn(AUD, src)
        self.assertEqual(sh("bash", "-n", os.path.join(ROOT, "bin", "local-prune.sh"), check=False).returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=1)
