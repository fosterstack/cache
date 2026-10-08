"""auditor-review-gate.py (REQ-AUD-18 AC3, option C): every reason a review record fails to clear
the gate, and the CLI's argument and no-change paths, against a real temporary git repository."""
import contextlib, importlib.util, io, json, os, shutil, subprocess, tempfile, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.dirname(HERE)
_spec = importlib.util.spec_from_file_location("auditor_review_gate", os.path.join(BIN, "auditor-review-gate.py"))
G = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(G)

TREE = "ab" * 32
EV = "cd" * 32


def good():
    return {"schema": G.SCHEMA, "tree": TREE,
            "rounds": [{"round": 1, "reviewers": {
                "codex": {"vendor": "openai", "blockers_open": 0, "evidence_sha256": EV},
                "sonnet": {"vendor": "anthropic", "blockers_open": 0, "evidence_sha256": EV}}}],
            "stop": {"codex": "clear", "sonnet": "clear"}}


class RecordProblems(unittest.TestCase):
    def test_a_complete_clear_record_has_no_problems(self):
        self.assertEqual(G.record_problems(good(), TREE), [])

    def test_not_an_object(self):
        self.assertEqual(G.record_problems([good()], TREE), ["record is not a JSON object"])

    def test_wrong_schema_and_stale_tree_are_both_reported(self):
        r = good(); r["schema"] = "v0"
        probs = G.record_problems(r, "ef" * 32)
        self.assertIn("schema is not %s" % G.SCHEMA, probs)
        self.assertIn("record binds tree %s, the change is %s" % (TREE, "ef" * 32), probs)

    def test_no_rounds(self):
        for rounds in (None, [], "r1"):
            r = good(); r["rounds"] = rounds
            self.assertEqual(G.record_problems(r, TREE), ["no review rounds recorded"])

    def test_final_round_without_reviewers(self):
        for final in ("round", {"round": 2}, {"reviewers": ["codex"]}):
            r = good(); r["rounds"].append(final)
            self.assertEqual(G.record_problems(r, TREE), ["final round names no reviewers"])

    def test_only_the_FINAL_round_counts(self):
        r = good()
        r["rounds"].append({"round": 2, "reviewers": {"codex": good()["rounds"][0]["reviewers"]["codex"]}})
        self.assertEqual(G.record_problems(r, TREE), ["final round has no sonnet review"])

    def test_each_vendor_field_is_checked(self):
        r = good(); c = r["rounds"][0]["reviewers"]["codex"]
        c["vendor"] = "anthropic"; c["blockers_open"] = 1; c["evidence_sha256"] = "x"
        r["stop"]["codex"] = "blocked"
        self.assertEqual(G.record_problems(r, TREE), [
            "codex vendor is 'anthropic', want 'openai'",
            "codex has 1 open merge blocker(s)",
            "codex evidence_sha256 is not a sha256",
            "codex stop verdict is 'blocked', want 'clear'"])

    def test_missing_stop_block_is_not_clear(self):
        r = good(); r["stop"] = "clear"
        self.assertEqual(G.record_problems(r, TREE), ["codex stop verdict is None, want 'clear'",
                                                      "sonnet stop verdict is None, want 'clear'"])

    def test_blockers_open_must_be_exactly_zero(self):
        for bad in (None, "0", False, 0.5, 0.0):     # False == 0 and 0.0 == 0 in Python
            r = good(); r["rounds"][0]["reviewers"]["sonnet"]["blockers_open"] = bad
            self.assertEqual(G.record_problems(r, TREE), ["sonnet has %r open merge blocker(s)" % bad])


class Cli(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, self.d)
        self.cwd = os.getcwd(); os.chdir(self.d); self.addCleanup(os.chdir, self.cwd)
        self.git("init", "-q")
        os.makedirs(".github/agent/bin"); os.makedirs("src")
        self.write(".github/agent/bin/x.py", "a\n"); self.write("src/y", "s\n")
        self.git("add", "-A"); self.git("commit", "-qm", "base")
        self.base = self.git("rev-parse", "HEAD").strip()

    def git(self, *a):
        return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false", *a],
                              check=True, capture_output=True, text=True).stdout

    def write(self, p, t):
        with open(p, "w") as fh:
            fh.write(t)

    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = G.main(list(argv))
        return rc, out.getvalue(), err.getvalue()

    def test_base_is_required(self):
        rc, out, err = self.run_main("--head", "HEAD")
        self.assertEqual(rc, 2)
        self.assertIn("--base is required", err)

    def test_a_flag_without_a_value_is_missing_not_a_crash(self):
        rc, out, err = self.run_main("--head", "HEAD", "--base")
        self.assertEqual(rc, 2)
        self.assertIn("--base is required", err)

    def test_print_tree_is_stable_and_ignores_records_only(self):
        rc, t1, _ = self.run_main("--print-tree")
        self.assertEqual(rc, 0); t1 = t1.strip()
        os.makedirs(".github/agent/reviews")
        self.write(".github/agent/reviews/%s.json" % ("0" * 64), "{}")
        self.git("add", "-A"); self.git("commit", "-qm", "record")
        self.assertEqual(self.run_main("--print-tree")[1].strip(), t1)          # a record: same tree
        self.write(".github/agent/reviews/notes.txt", "x")
        self.git("add", "-A"); self.git("commit", "-qm", "not a record")
        self.assertNotEqual(self.run_main("--print-tree")[1].strip(), t1)       # anything else: new tree

    def test_no_auditor_change_needs_no_record(self):
        self.write("src/y", "t\n"); self.git("commit", "-qam", "outside")
        rc, out, _ = self.run_main("--base", self.base, "--head", "HEAD")
        self.assertEqual(rc, 0)
        self.assertIn("no change under .github/agent/", out)

    def test_invalid_record_json_fails_with_its_path(self):
        self.write(".github/agent/bin/x.py", "b\n"); self.git("commit", "-qam", "change")
        tree = self.run_main("--print-tree")[1].strip()
        os.makedirs(".github/agent/reviews")
        self.write(".github/agent/reviews/%s.json" % tree, "{not json")
        self.git("add", "-A"); self.git("commit", "-qm", "broken record")
        rc, out, _ = self.run_main("--base", self.base, "--head", "HEAD")
        self.assertEqual(rc, 1)
        self.assertIn(".github/agent/reviews/%s.json" % tree, out)
        self.assertIn("no valid review record", out)

    def test_a_clear_record_passes_and_names_the_rounds(self):
        self.write(".github/agent/bin/x.py", "b\n"); self.git("commit", "-qam", "change")
        tree = self.run_main("--print-tree")[1].strip()
        rec = good(); rec["tree"] = tree
        os.makedirs(".github/agent/reviews")
        self.write(".github/agent/reviews/%s.json" % tree, json.dumps(rec))
        self.git("add", "-A"); self.git("commit", "-qm", "record")
        rc, out, _ = self.run_main("--base", self.base, "--head", "HEAD")
        self.assertEqual(rc, 0)
        self.assertIn("clears the stop rule (1 round(s))", out)
        rec["stop"]["sonnet"] = "blocked"
        self.write(".github/agent/reviews/%s.json" % tree, json.dumps(rec))
        self.git("commit", "-qam", "not clear")
        rc, out, _ = self.run_main("--base", self.base, "--head", "HEAD")
        self.assertEqual(rc, 1)
        self.assertIn("sonnet stop verdict is 'blocked'", out)


class GuardFiles(Cli):
    """The allowlist guard's own files sit outside .github/agent/ but are review-gated too: a PR that
    changes only one of them needs a record bound to the content, and the tree hash covers them."""
    GUARDS = ("bin/check-file-allowlist.sh", "bin/check-file-allowlist-test.sh", ".github/workflows/agent-review-gate.yml")

    def setUp(self):
        super().setUp()
        os.makedirs("bin"); os.makedirs(".github/workflows")
        for g in self.GUARDS:
            self.write(g, "v1\n")
        self.write(".github/workflows/ci.yml", "ci1\n")
        self.git("add", "-A"); self.git("commit", "-qm", "guards")
        self.base = self.git("rev-parse", "HEAD").strip()

    def record(self):
        tree = self.run_main("--print-tree")[1].strip()
        rec = good(); rec["tree"] = tree
        os.makedirs(".github/agent/reviews", exist_ok=True)
        self.write(".github/agent/reviews/%s.json" % tree, json.dumps(rec))
        self.git("add", "-A"); self.git("commit", "-qm", "record")
        return tree

    def test_each_guard_file_alone_needs_a_record(self):
        for g in self.GUARDS:
            self.git("reset", "-q", "--hard", self.base)
            self.write(g, "v2\n"); self.git("commit", "-qam", "change " + g)
            rc, out, _ = self.run_main("--base", self.base, "--head", "HEAD")
            self.assertEqual(rc, 1, g)
            self.assertIn("no valid review record", out)
            self.assertIn(g, out)

    def test_a_matching_record_clears_a_guard_only_change(self):
        self.write("bin/check-file-allowlist.sh", "v2\n"); self.git("commit", "-qam", "change")
        self.record()
        rc, out, _ = self.run_main("--base", self.base, "--head", "HEAD")
        self.assertEqual(rc, 0, out)
        self.assertIn("clears the stop rule", out)

    def test_a_stale_record_does_not_clear_a_later_guard_change(self):
        self.write("bin/check-file-allowlist.sh", "v2\n"); self.git("commit", "-qam", "change")
        self.record()
        self.write("bin/check-file-allowlist.sh", "v3\n"); self.git("commit", "-qam", "change again")
        rc, out, _ = self.run_main("--base", self.base, "--head", "HEAD")
        self.assertEqual(rc, 1)

    def test_an_old_record_cannot_be_replayed_over_a_guard_change(self):
        # a record exists for the unchanged agent content; changing only a guard file must not reuse it
        self.write(".github/agent/bin/x.py", "b\n"); self.git("commit", "-qam", "agent change")
        self.record()
        mid = self.git("rev-parse", "HEAD").strip()
        self.write("bin/check-file-allowlist-test.sh", "v2\n"); self.git("commit", "-qam", "guard only")
        rc, out, _ = self.run_main("--base", mid, "--head", "HEAD")
        self.assertEqual(rc, 1)

    def test_deleting_a_guard_file_is_a_change(self):
        self.git("rm", "-q", "bin/check-file-allowlist.sh"); self.git("commit", "-qm", "delete")
        rc, out, _ = self.run_main("--base", self.base, "--head", "HEAD")
        self.assertEqual(rc, 1)

    def test_other_files_including_ci_yml_are_unaffected(self):
        self.write(".github/workflows/ci.yml", "ci2\n"); self.write("src/y", "t\n")
        self.git("commit", "-qam", "outside")
        rc, out, _ = self.run_main("--base", self.base, "--head", "HEAD")
        self.assertEqual(rc, 0)
        self.assertIn("nothing to clear", out)
        t = self.run_main("--print-tree")[1].strip()
        self.write(".github/workflows/ci.yml", "ci3\n"); self.git("commit", "-qam", "ci again")
        self.assertEqual(self.run_main("--print-tree")[1].strip(), t)      # ci.yml is not part of the bound content


class HarnessManifest(unittest.TestCase):
    """The reviewed harness manifest (.github/agent/supply-chain/harness-manifest.json, REQ-SUP-001 AC11) lies under .github/agent/, so a change to it needs a current review record, and any
    edit of it invalidates a record made before. It exempts files from the supply-chain checks, so an unreviewed change would silently hide a pin."""
    M = ".github/agent/supply-chain/harness-manifest.json"
    setUp, git, write, run_main = Cli.setUp, Cli.git, Cli.write, Cli.run_main

    def commit_manifest(self, text, msg="manifest"):
        os.makedirs(os.path.dirname(self.M), exist_ok=True)
        self.write(self.M, text)
        self.git("add", "-A"); self.git("commit", "-qm", msg)

    def test_the_manifest_is_under_the_reviewed_prefix(self):
        self.assertTrue(self.M.startswith(G.AGENT))
        self.assertNotIn(self.M, getattr(G, "GUARDED", ()), "the manifest is covered by the reviewed .github/agent/ prefix, not by the list of guard files outside it")

    def test_a_manifest_only_change_needs_a_record(self):
        self.commit_manifest('{"files": []}\n')
        rc, out, _ = self.run_main("--base", self.base, "--head", "HEAD")
        self.assertEqual(rc, 1)
        self.assertIn("no valid review record", out)
        self.assertIn(self.M, out)

    def test_a_manifest_only_change_with_a_current_record_passes(self):
        self.commit_manifest('{"files": []}\n')
        tree = self.run_main("--print-tree")[1].strip()
        rec = good(); rec["tree"] = tree
        os.makedirs(".github/agent/reviews")
        self.write(".github/agent/reviews/%s.json" % tree, json.dumps(rec))
        self.git("add", "-A"); self.git("commit", "-qm", "record")
        rc, out, _ = self.run_main("--base", self.base, "--head", "HEAD")
        self.assertEqual(rc, 0)
        self.assertIn("clears the stop rule", out)

    def test_editing_the_manifest_invalidates_an_existing_record(self):
        self.commit_manifest('{"files": []}\n')
        tree = self.run_main("--print-tree")[1].strip()
        rec = good(); rec["tree"] = tree
        os.makedirs(".github/agent/reviews")
        self.write(".github/agent/reviews/%s.json" % tree, json.dumps(rec))
        self.git("add", "-A"); self.git("commit", "-qm", "record")
        self.assertEqual(self.run_main("--base", self.base, "--head", "HEAD")[0], 0)
        self.commit_manifest('{"files": [{"path": "bin/x-test.sh", "sha256": "%s", "reason": "r"}]}\n' % ("0" * 64), "edited after the review")
        rc, out, _ = self.run_main("--base", self.base, "--head", "HEAD")
        self.assertEqual(rc, 1)
        self.assertNotEqual(self.run_main("--print-tree")[1].strip(), tree)

    def test_the_tree_hash_covers_the_manifest_and_still_ignores_records_only(self):
        t0 = self.run_main("--print-tree")[1].strip()
        self.commit_manifest('{"files": []}\n')
        t1 = self.run_main("--print-tree")[1].strip()
        self.assertNotEqual(t0, t1)
        self.commit_manifest('{"files":   []}\n', "whitespace")
        self.assertNotEqual(self.run_main("--print-tree")[1].strip(), t1)
        os.makedirs(".github/agent/reviews")
        self.write(".github/agent/reviews/%s.json" % ("0" * 64), "{}")
        self.git("add", "-A"); self.git("commit", "-qm", "record")
        self.assertNotEqual(self.run_main("--print-tree")[1].strip(), t0)

    def test_deleting_the_manifest_is_a_guarded_change(self):
        self.commit_manifest('{"files": []}\n')
        mid = self.git("rev-parse", "HEAD").strip()
        self.git("rm", "-q", self.M); self.git("commit", "-qm", "delete")
        rc, out, _ = self.run_main("--base", mid, "--head", "HEAD")
        self.assertEqual(rc, 1)
        self.assertIn(self.M, out)

    def test_an_unchanged_manifest_and_other_outside_changes_need_no_record(self):
        self.commit_manifest('{"files": []}\n')
        mid = self.git("rev-parse", "HEAD").strip()
        self.write("src/y", "t\n"); self.git("commit", "-qam", "outside")
        rc, out, _ = self.run_main("--base", mid, "--head", "HEAD")
        self.assertEqual(rc, 0)
        self.assertIn("nothing to clear", out)

    def test_files_outside_the_prefix_are_not_reviewed(self):
        self.write(".github/supply-chain-harness.json", "x\n"); self.write(".github/supply-chain-exceptions.json", "{}\n")
        self.git("add", "-A"); self.git("commit", "-qm", "siblings")
        rc, out, _ = self.run_main("--base", self.base, "--head", "HEAD")
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
