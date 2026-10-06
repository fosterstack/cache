# proves: REQ-AUD-17, REQ-AUD-15 (the auditor's delivery commits are made through the GitHub API so GitHub signs them)
"""auditorlib.signed_commit: the exact REST and GraphQL calls, the base64 file changes, the create-or-reset branch path, and every way the
delivery must fail closed (an API error, no oid, an unsigned or unverifiable commit, a file over 5 MB, a branch outside auditor/). A recording
fake `gh`; nothing touches the network."""
import base64, json, os, subprocess, sys, unittest

BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, BIN)
from auditorlib import signed_commit as S  # noqa: E402

BASE = "1" * 40
OID = "2" * 40
REPO = "o/r"
BRANCH = "auditor/panel"
OK_SIG = {"isValid": True, "state": "VALID"}


def mutation(oid=OID, signature=OK_SIG, **extra):
    commit = {"oid": oid}
    if signature is not False:
        commit["signature"] = signature
    return json.dumps({"data": {"createCommitOnBranch": {"commit": commit}}, **extra})


class Gh:
    """Records every command (and stdin). Responses by kind: get (the ref lookup), patch, post, graphql, lookup (the commit GET)."""
    def __init__(self, get=(0, "{}", ""), patch=(0, "{}", ""), post=(0, "{}", ""), graphql=(0, None, ""), lookup=(0, "{}", "")):
        self.r = {"get": get, "patch": patch, "post": post, "graphql": graphql, "lookup": lookup}
        self.calls, self.stdins = [], []

    def __call__(self, cmd, **kw):
        cmd = list(cmd); self.calls.append(cmd); assert kw.get("capture_output") and kw.get("text")
        if cmd[2] == "graphql":
            self.stdins.append(json.loads(kw["input"])); kind = "graphql"
        elif cmd[2] == "--method":
            kind = cmd[3].lower()
        elif "/git/ref/heads/" in cmd[2]:
            kind = "get"
        else:
            kind = "lookup"
        rc, out, err = self.r[kind]
        if kind == "graphql" and out is None:
            out = mutation()
        return subprocess.CompletedProcess(cmd, rc, out, err)

    def kinds(self):
        return ["graphql" if c[2] == "graphql" else c[3].lower() if c[2] == "--method" else "get" if "/git/ref/" in c[2] else "lookup" for c in self.calls]


class Commit(unittest.TestCase):
    CH = {"a/b.json": b'{"x": 1}\n', "c.txt": b"hello"}

    def go(self, gh, changes=None, **kw):
        return S.commit_via_api(kw.get("repo", REPO), kw.get("branch", BRANCH), kw.get("base", BASE), kw.get("message", "Scanner panel audits, 2026-10-06"),
                                self.CH if changes is None else changes, run=gh)

    def test_an_existing_branch_is_force_reset_then_one_commit_is_made(self):
        gh = Gh()
        self.assertEqual(self.go(gh), OID)
        self.assertEqual(gh.calls[0], ["gh", "api", "repos/o/r/git/ref/heads/auditor/panel"])
        self.assertEqual(gh.calls[1], ["gh", "api", "--method", "PATCH", "repos/o/r/git/refs/heads/auditor/panel", "-f", "sha=" + BASE, "-F", "force=true"])
        self.assertEqual(gh.calls[2], ["gh", "api", "graphql", "--input", "-"])
        self.assertEqual(gh.kinds(), ["get", "patch", "graphql"])                  # signature came with the mutation: no follow-up lookup

    def test_the_graphql_query_and_variables_are_exact(self):
        gh = Gh(); self.go(gh, message="Headline here\n\nBody line 1\nBody line 2\n")
        doc = gh.stdins[0]
        self.assertEqual(doc["query"], "mutation($input: CreateCommitOnBranchInput!) { createCommitOnBranch(input: $input) { commit { oid signature { isValid state } } } }")
        self.assertEqual(doc["variables"], {"input": {
            "branch": {"repositoryNameWithOwner": "o/r", "branchName": "auditor/panel"},
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

    def test_an_absent_branch_is_created_at_the_base(self):
        for err in ("gh: Not Found (HTTP 404)", "HTTP 404: Not Found"):
            gh = Gh(get=(1, "", err))
            self.assertEqual(self.go(gh), OID)
            self.assertEqual(gh.kinds(), ["get", "post", "graphql"])
            self.assertEqual(gh.calls[1], ["gh", "api", "--method", "POST", "repos/o/r/git/refs", "-f", "ref=refs/heads/auditor/panel", "-f", "sha=" + BASE])
        gh = Gh(get=(1, "Not Found", ""))
        self.assertEqual(self.go(gh), OID)

    def test_any_other_ref_failure_fails_closed_before_a_commit(self):
        for gh, text in ((Gh(get=(1, "", "HTTP 500")), "reading branch"), (Gh(patch=(1, "", "HTTP 422 no")), "resetting branch"),
                         (Gh(get=(1, "", "HTTP 404"), post=(1, "", "HTTP 403 nope")), "creating branch")):
            with self.assertRaises(S.CommitError) as e:
                self.go(gh)
            self.assertIn(text, str(e.exception)); self.assertNotIn("graphql", gh.kinds())

    def test_every_mutation_failure_is_a_failure(self):
        cases = {
            "gh error": Gh(graphql=(1, "", "HTTP 403")),
            "gh error on stdout": Gh(graphql=(1, "boom", "")),
            "not json": Gh(graphql=(0, "<html>", "")),
            "not an object": Gh(graphql=(0, "[1]", "")),
            "errors": Gh(graphql=(0, json.dumps({"errors": [{"message": "Expected branch to point to X"}], "data": None}), "")),
            "errors beside data": Gh(graphql=(0, mutation(errors=[{"message": "x"}]), "")),
            "no data": Gh(graphql=(0, "{}", "")),
            "null payload": Gh(graphql=(0, json.dumps({"data": {"createCommitOnBranch": None}}), "")),
            "no commit": Gh(graphql=(0, json.dumps({"data": {"createCommitOnBranch": {"commit": None}}}), "")),
            "no oid": Gh(graphql=(0, json.dumps({"data": {"createCommitOnBranch": {"commit": {"signature": OK_SIG}}}}), "")),
            "short oid": Gh(graphql=(0, mutation(oid="abc"), "")),
            "oid not a string": Gh(graphql=(0, mutation(oid=7), "")),
        }
        for name, gh in cases.items():
            with self.assertRaises(S.CommitError, msg=name):
                self.go(gh)

    def test_an_unsigned_or_invalid_signature_is_never_delivered(self):
        for sig in ({"isValid": False, "state": "UNSIGNED"}, {"isValid": False, "state": "INVALID"}, {"isValid": True, "state": "UNKNOWN_KEY"},
                    {"isValid": True}, {"state": "VALID"}, {}):
            gh = Gh(graphql=(0, mutation(signature=sig), ""))
            with self.assertRaises(S.CommitError) as e:
                self.go(gh)
            self.assertIn("NOT validly signed", str(e.exception)); self.assertIn("unsigned", str(e.exception))
            self.assertNotIn("lookup", gh.kinds())                                   # the mutation's own answer is final when it gave one

    def test_without_a_signature_in_the_payload_the_commit_is_looked_up_and_must_be_verified(self):
        for sig in (False, None):
            ok = Gh(graphql=(0, mutation(signature=sig), ""), lookup=(0, json.dumps({"commit": {"verification": {"verified": True, "reason": "valid"}}}), ""))
            self.assertEqual(self.go(ok), OID)
            self.assertEqual(ok.kinds()[-2:], ["graphql", "lookup"])
            self.assertEqual(ok.calls[-1], ["gh", "api", "repos/o/r/commits/" + OID])
        bad_lookups = {"unverified": (0, json.dumps({"commit": {"verification": {"verified": False, "reason": "unsigned"}}}), ""),
                       "verified as a string": (0, json.dumps({"commit": {"verification": {"verified": "true"}}}), ""),
                       "no verification": (0, json.dumps({"commit": {}}), ""),
                       "no commit": (0, "{}", ""),
                       "verification not an object": (0, json.dumps({"commit": {"verification": None}}), ""),
                       "lookup error": (1, "", "HTTP 404"),
                       "lookup not json": (0, "nope", "")}
        for name, lookup in bad_lookups.items():
            gh = Gh(graphql=(0, mutation(signature=False), ""), lookup=lookup)
            with self.assertRaises(S.CommitError, msg=name) as e:
                self.go(gh)
            self.assertTrue("unsigned" in str(e.exception) or "could not confirm" in str(e.exception) or "not" in str(e.exception), name)

    def test_a_file_over_five_megabytes_fails_closed_saying_why(self):
        gh = Gh()
        with self.assertRaises(S.CommitError) as e:
            self.go(gh, changes={"big.bin": b"x" * (S.MAX_FILE_BYTES + 1)})
        self.assertIn("big.bin", str(e.exception)); self.assertIn("5242880", str(e.exception)); self.assertIn("unsigned", str(e.exception))
        self.assertEqual(gh.calls, [])                                               # refused before the branch is touched
        self.assertEqual(self.go(Gh(), changes={"ok.bin": b"x" * S.MAX_FILE_BYTES}), OID)   # exactly the limit is allowed

    def test_inputs_that_could_widen_the_write_are_refused_before_any_call(self):
        bad = [dict(repo="o"), dict(repo="o/r/x"), dict(repo=None), dict(branch="main"), dict(branch="auditor/"), dict(branch="auditor/../main"),
               dict(branch="auditor/x.lock"), dict(branch="refs/heads/auditor/x"), dict(branch=None), dict(base="abc123"), dict(base="A" * 40), dict(base=None),
               dict(message=""), dict(message="  \n"), dict(message=None),
               dict(changes={}), dict(changes={"/etc/passwd": b"x"}), dict(changes={"../x": b"x"}), dict(changes={"a//b": b"x"}), dict(changes={"./x": b"x"}),
               dict(changes={"": b"x"}), dict(changes={"a/": b"x"}), dict(changes={"x": "text"}), dict(changes={3: b"x"})]
        for kw in bad:
            gh = Gh()
            with self.assertRaises(S.CommitError, msg=str(kw)):
                self.go(gh, **kw)
            self.assertEqual(gh.calls, [], str(kw))

    def test_the_default_runner_is_subprocess_run_resolved_at_call_time(self):
        import unittest.mock as mock
        gh = Gh()
        with mock.patch.object(S.subprocess, "run", gh):
            self.assertEqual(S.commit_via_api(REPO, BRANCH, BASE, "m", {"x": b"1"}), OID)
        self.assertEqual(len(gh.calls), 3)

    def test_planned_commands_name_the_calls_without_making_any(self):
        self.assertEqual(S.planned_commands(REPO, BRANCH, BASE), [
            ["gh", "api", "repos/o/r/git/ref/heads/auditor/panel"],
            ["gh", "api", "--method", "PATCH", "repos/o/r/git/refs/heads/auditor/panel", "-f", "sha=" + BASE, "-F", "force=true"],
            ["gh", "api", "graphql", "--input", "-"]])

    def test_read_changes_reads_bytes_and_marks_missing_paths_for_deletion(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "a")); open(os.path.join(d, "a", "f"), "wb").write(b"\x00\xff")
            self.assertEqual(S.read_changes(d, ["a/f", "missing", "a"]), {"a/f": b"\x00\xff", "missing": None, "a": None})


if __name__ == "__main__":
    unittest.main()
