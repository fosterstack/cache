# (no AC is registered for the auditor's signed-delivery helper: the guarantees are advisor 0209 / REQ-AUD-17, held in ops; this file is covered by the auditor coverage gate)
"""auditorlib.signed_commit: the exact REST and GraphQL calls, the base64 file changes, the create-or-reset branch path, and every way the
delivery must fail closed (an API error, no oid, an unsigned or unverifiable commit, a file over 5 MB, a branch outside auditor/). A recording
fake `gh`; nothing touches the network."""
import base64, json, os, subprocess, sys, tempfile, unittest
from unittest import mock

BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, BIN)
from auditorlib import signed_commit as S  # noqa: E402

BASE = "1" * 40
OID = "2" * 40
REPO = "o/r"
BRANCH = "auditor/panel"
REAL_TMP = getattr(S, "_tmp_branch", None)      # the real naming function, before any test stubs it
OK_SIG = {"isValid": True, "state": "VALID"}


def mutation(oid=OID, signature=OK_SIG, **extra):
    commit = {"oid": oid}
    if signature is not False:
        commit["signature"] = signature
    return json.dumps({"data": {"createCommitOnBranch": {"commit": commit}}, **extra})


H1 = "3" * 40          # the live branch head the run observed
H2 = "4" * 40          # a head some other writer left there
TMP = "auditor/tmp-test0001"


class Gh:
    """A recording fake GitHub with refs state. `refs` maps branch -> sha (the live branch starts at `live`, None = absent). Responses can be
    overridden per kind: get, post, patch, delete, graphql, lookup (each (rc, out, err)); `on_get` runs before the Nth GET of the live branch."""
    def __init__(self, live=H1, mutation=None, lookup=(0, "{}", ""), contents=None, **fail):
        self.contents = {"go.mod": b"module m\n"} if contents is None else contents
        self.refs = {} if live is None else {BRANCH: live}
        self.mutation, self.lookup, self.fail = mutation, lookup, fail
        self.calls, self.stdins, self.live_gets, self.on_live_get = [], [], 0, None

    def writes(self):
        """[(method, branch)] for every ref write, in order."""
        out = []
        for c in self.calls:
            if c[2] == "--method" and c[3] == "POST":
                out.append(("POST", [x for x in c if x.startswith("ref=")][0][len("ref=refs/heads/"):]))
            elif c[2] == "--method":
                out.append((c[3], c[4].split("/git/refs/heads/")[1]))
            elif c[2] == "graphql":
                out.append(("COMMIT", self.stdins[len([1 for k in self.calls[:self.calls.index(c)] if k[2] == "graphql"])]["variables"]["input"]["branch"]["branchName"]))
        return out

    def __call__(self, cmd, **kw):
        cmd = list(cmd); self.calls.append(cmd); assert kw.get("capture_output") and kw.get("text")
        done = lambda r: subprocess.CompletedProcess(cmd, r[0], r[1], r[2])
        if cmd[2] == "graphql":
            doc = json.loads(kw["input"]); self.stdins.append(doc)
            if "graphql" in self.fail:
                return done(self.fail["graphql"])
            inp = doc["variables"]["input"]; br = inp["branch"]["branchName"]
            if self.refs.get(br) != inp["expectedHeadOid"]:
                return done((0, json.dumps({"errors": [{"message": "Expected branch to point to %s" % inp["expectedHeadOid"]}]}), ""))
            if self.mutation is not None:
                return done((0, self.mutation, ""))
            self.refs[br] = OID
            return done((0, mutation(), ""))
        if cmd[2] == "--method":
            kind = cmd[3].lower()
            if kind in self.fail:
                return done(self.fail[kind])
            if kind == "post":
                self.refs[[x for x in cmd if x.startswith("ref=")][0][len("ref=refs/heads/"):]] = [x for x in cmd if x.startswith("sha=")][0][4:]
            elif kind == "patch":
                self.refs[cmd[4].split("/git/refs/heads/")[1]] = [x for x in cmd if x.startswith("sha=")][0][4:]
            else:
                self.refs.pop(cmd[4].split("/git/refs/heads/")[1], None)
            return done((0, "{}", ""))
        if "/git/ref/heads/" in cmd[2]:
            br = cmd[2].split("/git/ref/heads/")[1]
            if br == BRANCH:
                self.live_gets += 1
                if self.on_live_get:
                    self.on_live_get(self, self.live_gets)
            if "get" in self.fail and br == BRANCH:
                return done(self.fail["get"])
            if br not in self.refs:
                return done((1, "", "gh: Not Found (HTTP 404)"))
            return done((0, json.dumps({"ref": "refs/heads/" + br, "object": {"type": "commit", "sha": self.refs[br]}}), ""))
        if "/contents/" in cmd[2]:
            path = cmd[2].split("/contents/")[1].split("?ref=")[0]
            if path in self.contents:
                return done((0, json.dumps({"encoding": "base64", "content": base64.encodebytes(self.contents[path]).decode()}), ""))
            return done((1, "", "gh: Not Found (HTTP 404)"))
        return done(self.lookup)


class Commit(unittest.TestCase):
    CH = {"a/b.json": b'{"x": 1}\n', "c.txt": b"hello"}

    def setUp(self):
        p = mock.patch.object(S, "_tmp_branch", lambda base: TMP); p.start(); self.addCleanup(p.stop)

    def go(self, gh, changes=None, notes=None, **kw):
        return S.commit_via_api(kw.get("repo", REPO), kw.get("branch", BRANCH), kw.get("base", BASE), kw.get("message", "Scanner panel audits, 2026-10-06"),
                                self.CH if changes is None else changes, run=gh, notes=notes)

    def test_the_live_branch_is_touched_only_after_the_signed_commit_exists(self):
        gh = Gh()
        self.assertEqual(self.go(gh), OID)                                           # the returned oid is the new signed commit
        self.assertEqual(gh.calls[0], ["gh", "api", "repos/o/r/git/ref/heads/auditor/panel"])
        self.assertEqual(gh.calls[1], ["gh", "api", "--method", "POST", "repos/o/r/git/refs", "-f", "ref=refs/heads/" + TMP, "-f", "sha=" + BASE])
        self.assertEqual(gh.calls[2], ["gh", "api", "graphql", "--input", "-"])
        self.assertEqual(gh.calls[3], ["gh", "api", "repos/o/r/git/ref/heads/auditor/panel"])        # the lease: the live head is re-read
        self.assertEqual(gh.calls[4], ["gh", "api", "--method", "PATCH", "repos/o/r/git/refs/heads/auditor/panel", "-f", "sha=" + OID, "-F", "force=true"])
        self.assertEqual(gh.calls[5], ["gh", "api", "--method", "DELETE", "repos/o/r/git/refs/heads/" + TMP])
        self.assertEqual(gh.writes(), [("POST", TMP), ("COMMIT", TMP), ("PATCH", BRANCH), ("DELETE", TMP)])
        self.assertEqual(gh.stdins[0]["variables"]["input"]["branch"]["branchName"], TMP)          # the commit is made on the TEMPORARY branch
        self.assertEqual(gh.stdins[0]["variables"]["input"]["expectedHeadOid"], BASE)
        self.assertEqual(gh.refs, {BRANCH: OID})                                    # the live branch holds the new commit; the temp ref is gone

    def test_an_absent_live_branch_is_created_at_the_new_commit(self):
        for err in ("gh: Not Found (HTTP 404)", "HTTP 404: Not Found"):
            gh = Gh(live=None)
            self.assertEqual(self.go(gh), OID)
            self.assertEqual(gh.writes(), [("POST", TMP), ("COMMIT", TMP), ("POST", BRANCH), ("DELETE", TMP)])
            self.assertEqual(gh.calls[4], ["gh", "api", "--method", "POST", "repos/o/r/git/refs", "-f", "ref=refs/heads/auditor/panel", "-f", "sha=" + OID])
            self.assertEqual(gh.refs, {BRANCH: OID})

    def test_the_graphql_query_and_variables_are_exact(self):
        gh = Gh(); self.go(gh, message="Headline here\n\nBody line 1\nBody line 2\n")
        doc = gh.stdins[0]
        self.assertEqual(doc["query"], "mutation($input: CreateCommitOnBranchInput!) { createCommitOnBranch(input: $input) { commit { oid signature { isValid state } } } }")
        self.assertEqual(doc["variables"], {"input": {
            "branch": {"repositoryNameWithOwner": "o/r", "branchName": TMP},
            "message": {"headline": "Headline here", "body": "Body line 1\nBody line 2"},
            "expectedHeadOid": BASE,
            "fileChanges": {"additions": [{"path": "a/b.json", "contents": base64.b64encode(b'{"x": 1}\n').decode()},
                                          {"path": "c.txt", "contents": "aGVsbG8="}], "deletions": []}}})

    def test_a_removed_path_is_a_deletion_and_binary_content_survives(self):
        gh = Gh(); self.go(gh, changes={"gone.txt": None, "bin": bytes(range(256))})
        fc = gh.stdins[0]["variables"]["input"]["fileChanges"]
        self.assertEqual(fc["deletions"], [{"path": "gone.txt"}])
        self.assertEqual(base64.b64decode(fc["additions"][0]["contents"]), bytes(range(256)))
        self.assertEqual(gh.stdins[0]["variables"]["input"]["message"], {"headline": "Scanner panel audits, 2026-10-06", "body": ""})

    def assert_live_untouched(self, gh, live=H1, deleted_temp=True):
        """No write to the live branch at all (so the PR and its pending additions are exactly as they were), and the temp ref is gone."""
        self.assertFalse([w for w in gh.writes() if w[1] == BRANCH], gh.writes())
        self.assertEqual(gh.refs.get(BRANCH), live)
        if deleted_temp:
            self.assertNotIn(TMP, gh.refs)

    def test_every_failure_leaves_the_live_branch_unchanged_and_the_temp_ref_deleted(self):
        bad_sig = json.dumps({"data": {"createCommitOnBranch": {"commit": {"oid": OID, "signature": {"isValid": False, "state": "UNSIGNED"}}}}})
        cases = {
            "mutation gh error": Gh(graphql=(1, "", "HTTP 403")),
            "mutation gh error on stdout": Gh(graphql=(1, "boom", "")),
            "not json": Gh(mutation="<html>"),
            "not an object": Gh(mutation="[1]"),
            "errors": Gh(mutation=json.dumps({"errors": [{"message": "x"}], "data": None})),
            "errors beside data": Gh(mutation=mutation(errors=[{"message": "x"}])),
            "no data": Gh(mutation="{}"),
            "null payload": Gh(mutation=json.dumps({"data": {"createCommitOnBranch": None}})),
            "no commit": Gh(mutation=json.dumps({"data": {"createCommitOnBranch": {"commit": None}}})),
            "no oid": Gh(mutation=json.dumps({"data": {"createCommitOnBranch": {"commit": {"signature": OK_SIG}}}})),
            "short oid": Gh(mutation=mutation(oid="abc")),
            "oid not a string": Gh(mutation=mutation(oid=7)),
            "unsigned": Gh(mutation=bad_sig),
            "no signature and the lookup fails": Gh(mutation=mutation(signature=False), lookup=(1, "", "HTTP 404")),
        }
        for name, gh in cases.items():
            with self.assertRaises(S.CommitError, msg=name):
                self.go(gh)
            self.assert_live_untouched(gh)
            self.assertEqual(gh.writes()[-1], ("DELETE", TMP), name)                  # cleaned up on failure too

    def test_a_lease_miss_overwrites_nothing(self):
        for what, moved in (("moved", H2), ("deleted", None), ("created", "created")):
            live = None if what == "created" else H1
            gh = Gh(live=live)
            def race(g, n, moved=moved, what=what):
                if n == 2:                                                            # another writer, between the first read and the re-read
                    if moved is None:
                        g.refs.pop(BRANCH, None)
                    else:
                        g.refs[BRANCH] = H2
            gh.on_live_get = race
            with self.assertRaises(S.CommitError) as e:
                self.go(gh)
            self.assertIn("lease", str(e.exception)); self.assertIn("nothing was overwritten", str(e.exception))
            self.assertEqual(gh.refs.get(BRANCH), None if moved is None else H2)
            self.assertFalse([w for w in gh.writes() if w[1] == BRANCH], what)         # never written
            self.assertNotIn(TMP, gh.refs)

    def test_a_live_branch_that_cannot_be_read_or_written_fails_closed(self):
        gh = Gh(get=(1, "", "HTTP 500"))
        with self.assertRaises(S.CommitError) as e:
            self.go(gh)
        self.assertIn("reading branch", str(e.exception)); self.assertEqual(gh.writes(), [])        # nothing created, nothing to clean
        for ok_json in ("not json", "[]", json.dumps({"object": {"sha": "abc"}}), json.dumps({"object": None})):
            gh = Gh(); orig = gh.__call__
            gh2 = lambda cmd, **kw: subprocess.CompletedProcess(list(cmd), 0, ok_json, "") if "/git/ref/heads/" in cmd[2] else orig(cmd, **kw)
            with self.assertRaises(S.CommitError, msg=ok_json):
                self.go(gh2)
        gh = Gh(post=(1, "", "HTTP 403 nope"))                                        # the temp ref cannot be created
        with self.assertRaises(S.CommitError) as e:
            self.go(gh)
        self.assertIn("creating temporary branch", str(e.exception)); self.assertEqual(gh.writes(), [("POST", TMP)])
        self.assert_live_untouched(gh)
        gh = Gh(patch=(1, "", "HTTP 422 no"))                                         # the final move fails: live still untouched, temp cleaned
        with self.assertRaises(S.CommitError) as e:
            self.go(gh)
        self.assertIn("moving branch", str(e.exception)); self.assertNotIn(TMP, gh.refs); self.assertEqual(gh.refs[BRANCH], H1)
        gh = Gh(live=None, post=(1, "", "x"))
        with self.assertRaises(S.CommitError):
            self.go(gh)
        gh = Gh(live=None); orig = gh.__call__                                       # absent live branch: creating it at the new commit fails
        def failing_live_post(cmd, **kw):
            if cmd[2] == "--method" and cmd[3] == "POST" and "ref=refs/heads/" + BRANCH in cmd:
                return subprocess.CompletedProcess(list(cmd), 1, "", "HTTP 403")
            return orig(cmd, **kw)
        with self.assertRaises(S.CommitError) as e:
            self.go(failing_live_post)
        self.assertIn("creating branch", str(e.exception))

    def test_a_temp_ref_that_cannot_be_deleted_is_reported_not_fatal(self):
        gh = Gh(delete=(1, "", "HTTP 500")); notes = []
        self.assertEqual(self.go(gh, notes=notes), OID)
        self.assertEqual(len(notes), 1); self.assertIn(TMP, notes[0]); self.assertIn("could not be deleted", notes[0])
        gh = Gh(delete=(1, "", "HTTP 500"), graphql=(1, "", "HTTP 403"))               # on a failure the note rides the error
        with self.assertRaises(S.CommitError) as e:
            self.go(gh)
        self.assertIn("HTTP 403", str(e.exception)); self.assertIn("could not be deleted", str(e.exception))

    def test_an_unsigned_or_invalid_signature_is_never_delivered(self):
        for sig in ({"isValid": False, "state": "UNSIGNED"}, {"isValid": False, "state": "INVALID"}, {"isValid": True, "state": "UNKNOWN_KEY"},
                    {"isValid": True}, {"state": "VALID"}, {}):
            gh = Gh(mutation=mutation(signature=sig))
            with self.assertRaises(S.CommitError) as e:
                self.go(gh)
            self.assertIn("NOT validly signed", str(e.exception)); self.assertIn("unsigned", str(e.exception))
            self.assert_live_untouched(gh)
            self.assertNotIn("/commits/", " ".join(" ".join(c) for c in gh.calls))   # the mutation's own answer is final when it gave one

    def test_without_a_signature_in_the_payload_the_commit_is_looked_up_and_must_be_verified(self):
        for sig in (False, None):
            ok = Gh(mutation=mutation(signature=sig), lookup=(0, json.dumps({"commit": {"verification": {"verified": True, "reason": "valid"}}}), ""))
            self.assertEqual(self.go(ok), OID)
            self.assertEqual(ok.calls[3], ["gh", "api", "repos/o/r/commits/" + OID])
            self.assertEqual(ok.writes()[2], ("PATCH", BRANCH))                       # only after the lookup
        bad_lookups = {"unverified": (0, json.dumps({"commit": {"verification": {"verified": False, "reason": "unsigned"}}}), ""),
                       "verified as a string": (0, json.dumps({"commit": {"verification": {"verified": "true"}}}), ""),
                       "no verification": (0, json.dumps({"commit": {}}), ""),
                       "no commit": (0, "{}", ""),
                       "verification not an object": (0, json.dumps({"commit": {"verification": None}}), ""),
                       "lookup error": (1, "", "HTTP 404"),
                       "lookup not json": (0, "nope", "")}
        for name, lookup in bad_lookups.items():
            gh = Gh(mutation=mutation(signature=False), lookup=lookup)
            with self.assertRaises(S.CommitError, msg=name):
                self.go(gh)
            self.assert_live_untouched(gh)

    def test_a_file_over_five_megabytes_fails_closed_saying_why(self):
        gh = Gh()
        with self.assertRaises(S.CommitError) as e:
            self.go(gh, changes={"big.bin": b"x" * (S.MAX_FILE_BYTES + 1)})
        self.assertIn("big.bin", str(e.exception)); self.assertIn("5242880", str(e.exception)); self.assertIn("unsigned", str(e.exception))
        self.assertEqual(gh.calls, [])                                               # refused before any branch is touched
        self.assertEqual(self.go(Gh(), changes={"ok.bin": b"x" * S.MAX_FILE_BYTES}), OID)   # exactly the limit is allowed

    def test_inputs_that_could_widen_the_write_are_refused_before_any_call(self):
        bad = [dict(repo="o"), dict(repo="o/r/x"), dict(repo=None), dict(branch="main"), dict(branch="auditor/"), dict(branch="auditor/../main"),
               dict(branch="auditor/x.lock"), dict(branch="refs/heads/auditor/x"), dict(branch=None), dict(base="abc123"), dict(base="A" * 40), dict(base=None),
               dict(message=""), dict(message="  \n"), dict(message=None),
               dict(changes={}), dict(changes={os.path.join(tempfile.gettempdir(), "etc", "passwd"): b"x"}), dict(changes={"../x": b"x"}), dict(changes={"a//b": b"x"}), dict(changes={"./x": b"x"}),
               dict(changes={"": b"x"}), dict(changes={"a/": b"x"}), dict(changes={"x": "text"}), dict(changes={3: b"x"})]
        for kw in bad:
            gh = Gh()
            with self.assertRaises(S.CommitError, msg=str(kw)):
                self.go(gh, **kw)
            self.assertEqual(gh.calls, [], str(kw))

    def test_the_temporary_branch_name_is_in_the_reserved_lane_and_unique_per_run(self):
        names = set()
        for run_id, ts in (("1", 1), ("2", 1), ("1", 2)):
            with mock.patch.dict(os.environ, {"GITHUB_RUN_ID": run_id}), mock.patch.object(S.time, "time_ns", lambda ts=ts: ts):
                n = REAL_TMP(BASE); names.add(n)
                self.assertRegex(n, r"^auditor/tmp-[0-9a-f]{8,}$"); S._check(REPO, n, BASE, "m", {"x": b"1"})   # passes the same branch-shape guard
        self.assertEqual(len(names), 3)
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("GITHUB_RUN_ID", None); self.assertRegex(REAL_TMP(BASE), r"^auditor/tmp-")

    def test_the_default_runner_is_subprocess_run_resolved_at_call_time(self):
        gh = Gh()
        with mock.patch.object(S.subprocess, "run", gh):
            self.assertEqual(S.commit_via_api(REPO, BRANCH, BASE, "m", {"x": b"1"}), OID)
        self.assertEqual(len(gh.calls), 6)

    def test_planned_commands_name_the_calls_without_making_any(self):
        self.assertEqual(S.planned_commands(REPO, BRANCH, BASE), [
            ["gh", "api", "repos/o/r/git/ref/heads/auditor/panel"],
            ["gh", "api", "--method", "POST", "repos/o/r/git/refs", "-f", "ref=refs/heads/auditor/tmp-<run>", "-f", "sha=" + BASE],
            ["gh", "api", "graphql", "--input", "-"],
            ["gh", "api", "--method", "PATCH", "repos/o/r/git/refs/heads/auditor/panel", "-f", "sha=<new signed commit>", "-F", "force=true"],
            ["gh", "api", "--method", "DELETE", "repos/o/r/git/refs/heads/auditor/tmp-<run>"]])

    def test_read_changes_reads_bytes_and_marks_missing_paths_for_deletion(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "a"))
            with open(os.path.join(d, "a", "f"), "wb") as fh:
                fh.write(b"\x00\xff")
            self.assertEqual(S.read_changes(d, ["a/f", "missing", "a"]), {"a/f": b"\x00\xff", "missing": None, "a": None})

    def test_read_changes_never_follows_a_symlink_in_any_component(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as out:
            root = os.path.join(d, "repo"); os.makedirs(os.path.join(root, "real"))
            with open(os.path.join(out, "secret.txt"), "wb") as fh:
                fh.write(b"SECRET")
            with open(os.path.join(root, "real", "f.txt"), "wb") as fh:
                fh.write(b"ok")
            os.symlink(out, os.path.join(root, "docs"))                              # a directory link out of the tree
            os.symlink(os.path.join(root, "real"), os.path.join(root, "inner"))      # a directory link that stays inside the tree
            os.symlink(os.path.join(out, "secret.txt"), os.path.join(root, "link.txt"))   # a file link
            os.symlink(os.path.join(out, "nonexistent", "x"), os.path.join(root, "dangling.txt"))         # a dangling file link
            os.symlink(out, os.path.join(root, "real", "deep"))                      # a link below a plain directory
            self.assertEqual(S.read_changes(root, ["real/f.txt", "gone.txt", "real/gone.txt"]), {"real/f.txt": b"ok", "gone.txt": None, "real/gone.txt": None})
            for p in ("docs/secret.txt", "docs/new.txt", "docs", "inner/f.txt", "inner", "link.txt", "dangling.txt", "real/deep/secret.txt", "real/deep"):
                with self.assertRaises(S.CommitError, msg=p) as cm:
                    S.read_changes(root, [p])
                self.assertIn("symlink", str(cm.exception), p)
            with self.assertRaises(S.CommitError) as cm:                             # a path that climbs out of the root resolves outside it
                S.read_changes(root, [".."])
            self.assertIn("outside", str(cm.exception))
            with self.assertRaises(S.CommitError):                                   # one bad path refuses the whole set, before anything is returned
                S.read_changes(root, ["real/f.txt", "docs/secret.txt"])

    def test_a_root_that_is_itself_reached_through_a_symlink_is_fine(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "repo")); os.symlink(os.path.join(d, "repo"), os.path.join(d, "alias"))
            with open(os.path.join(d, "repo", "f"), "wb") as fh:
                fh.write(b"1")
            self.assertEqual(S.read_changes(os.path.join(d, "alias"), ["f"]), {"f": b"1"})


class Reusable(unittest.TestCase):
    """branch_reusable: an existing delivery branch is reused only when its head is ONE verified commit on today's main, changing only the wanted
    files, with exactly the wanted bytes. It returns the verified head oid (the caller binds arming to it), else None."""
    WANT = {"go.mod": b"module m\n", "go.sum": None}

    def lookup(self, verified=True, parents=(BASE,), files=(("go.mod", "modified"),), **extra):
        fs = []
        for f in files:
            d = {"filename": f[0], "status": f[1]}
            d.update(f[2] if len(f) > 2 else {})
            fs.append(d)
        return (0, json.dumps({"parents": [{"sha": p} for p in parents], "files": fs, "commit": {"verification": {"verified": verified}}, **extra}), "")

    def ok(self, **kw):
        return Gh(live=H1, lookup=self.lookup(**kw))

    def test_one_verified_commit_on_main_with_the_wanted_bytes_is_reused_and_nothing_is_written(self):
        gh = self.ok()
        self.assertEqual(S.branch_reusable(REPO, BRANCH, BASE, self.WANT, run=gh), H1)            # the verified head oid
        self.assertEqual(gh.writes(), [])
        self.assertIn(["gh", "api", "repos/o/r/commits/" + H1], gh.calls)
        self.assertIn(["gh", "api", "repos/o/r/contents/go.mod?ref=" + H1], gh.calls)
        both = Gh(live=H1, lookup=self.lookup(files=(("go.mod", "modified"), ("go.sum", "added"))), contents={"go.mod": b"module m\n", "go.sum": b"x\n"})
        self.assertEqual(S.branch_reusable(REPO, BRANCH, BASE, {"go.mod": b"module m\n", "go.sum": b"x\n"}, run=both), H1)

    def test_everything_else_is_not_reusable_so_the_branch_is_rebuilt_through_the_api(self):
        cases = {"unsigned head": self.ok(verified=False),
                 "verified string": Gh(live=H1, lookup=(0, json.dumps({"parents": [{"sha": BASE}], "files": [{"filename": "go.mod", "status": "modified"}], "commit": {"verification": {"verified": "true"}}}), "")),
                 "signed on an old main": self.ok(parents=("9" * 40,)),
                 "two parents, main first (a merge commit)": self.ok(parents=(BASE, "9" * 40)),
                 "two parents, main second": self.ok(parents=("9" * 40, BASE)),
                 "parents is another commit": self.ok(parents=("9" * 40,)),
                 "the head is the base itself": Gh(live=BASE, lookup=self.lookup()),
                 "no parents": self.ok(parents=()),
                 "parents not a list": Gh(live=H1, lookup=(0, json.dumps({"parents": None, "files": [{"filename": "go.mod", "status": "modified"}], "commit": {"verification": {"verified": True}}}), "")),
                 "parent not an object": Gh(live=H1, lookup=(0, json.dumps({"parents": ["x"], "files": [{"filename": "go.mod", "status": "modified"}], "commit": {"verification": {"verified": True}}}), "")),
                 "an extra changed file": self.ok(files=(("go.mod", "modified"), ("README.md", "modified"))),
                 "only another file": self.ok(files=(("README.md", "modified"),)),
                 "a rename": self.ok(files=(("go.mod", "renamed", {"previous_filename": "old.mod"}),)),
                 "a rename status": self.ok(files=(("go.mod", "renamed"),)),
                 "no files": self.ok(files=()),
                 "files not a list": Gh(live=H1, lookup=(0, json.dumps({"parents": [{"sha": BASE}], "files": None, "commit": {"verification": {"verified": True}}}), "")),
                 "a file entry that is not an object": Gh(live=H1, lookup=(0, json.dumps({"parents": [{"sha": BASE}], "files": ["go.mod"], "commit": {"verification": {"verified": True}}}), "")),
                 "the right files, different bytes": Gh(live=H1, lookup=self.lookup(), contents={"go.mod": b"module other\n"}),
                 "a wanted file is missing at the head": Gh(live=H1, lookup=self.lookup(), contents={}),
                 "an unwanted file is present at the head": Gh(live=H1, lookup=self.lookup(), contents={"go.mod": b"module m\n", "go.sum": b"x"}),
                 "contents not base64": Gh(live=H1, lookup=self.lookup(), contents={"go.mod": b"module m\n"}),
                 "no verification": Gh(live=H1, lookup=(0, json.dumps({"parents": [{"sha": BASE}], "files": [{"filename": "go.mod", "status": "modified"}], "commit": {}}), "")),
                 "no commit": Gh(live=H1, lookup=(0, json.dumps({"parents": [{"sha": BASE}], "files": [{"filename": "go.mod", "status": "modified"}]}), "")),
                 "lookup fails": Gh(live=H1, lookup=(1, "", "HTTP 500")),
                 "lookup not json": Gh(live=H1, lookup=(0, "nope", "")),
                 "branch absent": Gh(live=None),
                 "branch unreadable": Gh(live=H1, get=(1, "", "HTTP 500"))}
        orig = cases["contents not base64"].__call__
        cases["contents not base64"] = lambda cmd, **kw: subprocess.CompletedProcess(list(cmd), 0, json.dumps({"encoding": "none", "content": ""}), "") if "/contents/" in cmd[2] else orig(cmd, **kw)
        for name, gh in cases.items():
            self.assertIsNone(S.branch_reusable(REPO, BRANCH, BASE, self.WANT, run=gh), name)
            if hasattr(gh, "writes"):
                self.assertEqual(gh.writes(), [], name)

    def test_an_unreadable_or_malformed_contents_answer_is_not_reusable(self):
        for answer in ((1, "", "HTTP 500"), (0, json.dumps({"encoding": "base64", "content": "abc"}), "")):
            gh = self.ok(); orig = gh.__call__
            run = lambda cmd, answer=answer, orig=orig, **kw: subprocess.CompletedProcess(list(cmd), answer[0], answer[1], answer[2]) if "/contents/" in cmd[2] else orig(cmd, **kw)
            self.assertIsNone(S.branch_reusable(REPO, BRANCH, BASE, self.WANT, run=run), answer)

    def test_the_default_runner_and_input_checks(self):
        gh = self.ok()
        with mock.patch.object(S.subprocess, "run", gh):
            self.assertEqual(S.branch_reusable(REPO, BRANCH, BASE, self.WANT), H1)
        for kw in (dict(repo="o"), dict(branch="main"), dict(base_sha="abc"), dict(want={}), dict(want={"../x": b""}), dict(want={"go.mod": "text"})):
            args = dict(repo=REPO, branch=BRANCH, base_sha=BASE, want=self.WANT); args.update(kw)
            self.assertIsNone(S.branch_reusable(run=Gh(), **args), kw)


class Prefixes(unittest.TestCase):
    """commit_via_api(..., prefixes=...): the release workflow's patch-notes/ lane. The default stays auditor/ only; the strict shape guard stays."""
    PN = "patch-notes/v0.2.9"

    class Rec:
        """A minimal recording fake: the branch is absent, the mutation answers a signed commit, every ref write succeeds."""
        def __init__(self):
            self.calls = []

        def __call__(self, cmd, **kw):
            cmd = list(cmd); self.calls.append(cmd)
            if cmd[2] == "graphql":
                return subprocess.CompletedProcess(cmd, 0, mutation(), "")
            if "/git/ref/heads/" in cmd[2]:
                return subprocess.CompletedProcess(cmd, 1, "", "gh: Not Found (HTTP 404)")
            return subprocess.CompletedProcess(cmd, 0, "{}", "")

    def make(self, branch, **kw):
        rec = self.Rec()
        return rec, S.commit_via_api(REPO, branch, BASE, "Release notes", {"docs/x.md": b"x"}, run=rec, **kw)

    def test_a_patch_notes_branch_is_committed_when_that_prefix_is_allowed(self):
        rec, oid = self.make(self.PN, prefixes=("patch-notes/",))
        self.assertEqual(oid, OID)
        posts = [c for c in rec.calls if "ref=refs/heads/%s" % self.PN in c]
        self.assertEqual(len(posts), 1)                                              # the live branch is created at the signed commit
        self.assertTrue(any(c[2:4] == ["--method", "POST"] and any(x.startswith("ref=refs/heads/auditor/tmp-") for x in c) for c in rec.calls))   # the temp ref stays in auditor/

    def test_the_default_is_unchanged_auditor_only(self):
        for branch in (self.PN, "main", "release/x"):
            rec = self.Rec()
            with self.assertRaises(S.CommitError, msg=branch):
                S.commit_via_api(REPO, branch, BASE, "m", {"x": b"1"}, run=rec)
            self.assertEqual(rec.calls, [], branch)
        self.assertEqual(self.make("auditor/x")[1], OID)

    def test_a_branch_outside_every_allowed_prefix_is_refused_before_any_call(self):
        for branch, prefixes in ((self.PN, ("auditor/",)), ("auditor/x", ("patch-notes/",)), ("auditor/x", ("patch-notes/", "auditor/")),
                                 ("patch-notes/", ("patch-notes/",)), ("patch-notes/../main", ("patch-notes/",)), ("patch-notes/x.lock", ("patch-notes/",)),
                                 ("refs/heads/patch-notes/x", ("patch-notes/",)), ("patch-notesx/y", ("patch-notes/",)), ("release/x", ("release/",))):
            rec = self.Rec()
            if branch == "auditor/x" and "auditor/" in prefixes:
                self.assertEqual(S.commit_via_api(REPO, branch, BASE, "m", {"x": b"1"}, run=self.Rec(), prefixes=prefixes), OID)
                continue
            with self.assertRaises(S.CommitError, msg=(branch, prefixes)):
                S.commit_via_api(REPO, branch, BASE, "m", {"x": b"1"}, run=rec, prefixes=prefixes)
            self.assertEqual(rec.calls, [], (branch, prefixes))

    def test_the_prefixes_themselves_are_held_to_the_two_lanes(self):
        for prefixes in ((), [], None, "auditor/", ("main/",), ("",), ("auditor/", "x/"), ("patch-notes",)):
            rec = self.Rec()
            with self.assertRaises(S.CommitError, msg=repr(prefixes)):
                S.commit_via_api(REPO, self.PN, BASE, "m", {"x": b"1"}, run=rec, prefixes=prefixes)
            self.assertEqual(rec.calls, [], repr(prefixes))

    def test_every_path_component_of_a_contents_lookup_is_url_encoded(self):
        evil = "go.mod?ref=main#"
        gh = Gh(live=H1, lookup=Reusable.lookup(None, files=((evil, "modified"), ("a b/c d.txt", "added"))),
                 contents={"go.mod%3Fref%3Dmain%23": b"x", "a%20b/c%20d.txt": b"y"})
        S.branch_reusable(REPO, BRANCH, BASE, {evil: b"x", "a b/c d.txt": b"y"}, run=gh)
        urls = [c[2] for c in gh.calls if "/contents/" in c[2]]
        self.assertIn("repos/o/r/contents/go.mod%3Fref%3Dmain%23?ref=" + H1, urls)   # the request cannot be altered by the path
        self.assertIn("repos/o/r/contents/a%20b/c%20d.txt?ref=" + H1, urls)          # components encoded, the separators kept
        for u in urls:
            self.assertEqual(u.count("?"), 1, u); self.assertNotIn("#", u)


if __name__ == "__main__":
    unittest.main()
