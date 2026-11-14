# proves: REQ-SUP-001-AC28, REQ-SUP-001-AC31, REQ-SUP-001-AC32
"""Plain-form pins (owner: tool downloads are an exact version plus a checksum; images are pinned by digest).
AC28: the sample project's Gradle wrapper carries distributionSha256Sum, a lowercase sha256 hex.
"""
import os, re, shutil, subprocess, tempfile, unittest

import yaml

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
PROPS = os.path.join(ROOT, "bench/gradle-sample/gradle/wrapper/gradle-wrapper.properties")
JAR = os.path.join(ROOT, "bench/gradle-sample/gradle/wrapper/gradle-wrapper.jar")
WORKFLOW = os.path.join(ROOT, ".github/workflows/acceptance.yml")
# The pin as reviewed: changing the wrapper's sum means changing this line too, and then CI's online test (below) compares the
# new value with the sum Gradle publishes and with the zip itself.
EXPECTED_SUM = "acd53f1edaf02f1a8ff99879f8a34b302661a057d9b063ae9e35b552f804d20a"
JAR_REL = "bench/gradle-sample/gradle/wrapper/gradle-wrapper.jar"
JAR_SUM_REL = ".github/policy/gradle-wrapper-jar-sha256.txt"   # sha256sum format, read by the two Gradle acceptance scripts (REQ-SUP-001-AC32)
JAR_SUM_FILE = os.path.join(ROOT, JAR_SUM_REL)


def wrapper_props():
    out = {}
    with open(PROPS) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                out[k] = v
    return out


def jobs():
    with open(WORKFLOW) as f:
        return yaml.safe_load(f)["jobs"]


class GradleWrapperSum(unittest.TestCase):
    def test_the_wrapper_pins_its_distribution_by_sha256(self):
        p = wrapper_props()
        self.assertIn("distributionSha256Sum", p, "the Gradle wrapper must carry distributionSha256Sum")
        self.assertRegex(p["distributionSha256Sum"], r"^[0-9a-f]{64}$")

    def test_the_sum_is_the_committed_expected_value(self):
        self.assertEqual(wrapper_props()["distributionSha256Sum"], EXPECTED_SUM)

    def test_the_sum_is_for_the_distribution_the_url_names(self):
        p = wrapper_props()
        self.assertRegex(p["distributionUrl"], r"gradle-\d+\.\d+(\.\d+)?-bin\.zip$")
        self.assertEqual(p.get("validateDistributionUrl"), "true")


@unittest.skipUnless(os.environ.get("GRADLE_SUM_ONLINE") == "1", "set GRADLE_SUM_ONLINE=1 (CI does when a pull request changes the wrapper properties)")
class GradleWrapperSumOnline(unittest.TestCase):
    def test_the_sum_is_the_one_gradle_publishes_for_the_zip_the_url_names(self):
        import hashlib, urllib.request
        p = wrapper_props()
        url = p["distributionUrl"].replace("\\:", ":")
        self.assertTrue(url.startswith("https://services.gradle.org/distributions/"))
        with urllib.request.urlopen(url + ".sha256", timeout=60) as r:
            published = r.read().decode().split()[0].strip().lower()
        self.assertRegex(published, r"^[0-9a-f]{64}$")
        self.assertEqual(p["distributionSha256Sum"], published)
        h = hashlib.sha256()
        with urllib.request.urlopen(url, timeout=300) as r:
            for chunk in iter(lambda: r.read(1 << 20), b""):
                h.update(chunk)
        self.assertEqual(p["distributionSha256Sum"], h.hexdigest(), "the sum is not the sha256 of the zip")


def jar_sha256():
    import hashlib
    with open(JAR, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def expected_jar_sum():
    with open(JAR_SUM_FILE) as f:
        line = f.read()
    m = re.fullmatch(r"([0-9a-f]{64})  " + re.escape(JAR_REL) + r"\n", line)
    assert m, "%s must be one sha256sum line: <64 hex>, two spaces, %s" % (JAR_SUM_REL, JAR_REL)
    return m.group(1)


class GradleWrapperJar(unittest.TestCase):
    def test_the_committed_jar_is_the_one_the_expected_file_names(self):
        self.assertEqual(jar_sha256(), expected_jar_sum())

    def test_the_expected_file_is_one_sha256sum_line(self):
        self.assertRegex(open(JAR_SUM_FILE).read(), r"^[0-9a-f]{64}  " + re.escape(JAR_REL) + r"\n$")


@unittest.skipUnless(os.environ.get("GRADLE_SUM_ONLINE") == "1", "set GRADLE_SUM_ONLINE=1 (CI does when a pull request changes the wrapper files)")
class GradleWrapperJarOnline(unittest.TestCase):
    def test_the_jar_is_the_one_gradle_publishes_for_the_version_the_url_names(self):
        import re, urllib.request
        m = re.search(r"gradle-(\d+\.\d+(?:\.\d+)?)-bin\.zip$", wrapper_props()["distributionUrl"])
        self.assertIsNotNone(m)
        url = "https://services.gradle.org/distributions/gradle-%s-wrapper.jar.sha256" % m.group(1)
        with urllib.request.urlopen(url, timeout=60) as r:
            published = r.read().decode().split()[0].strip().lower()
        self.assertRegex(published, r"^[0-9a-f]{64}$")
        self.assertEqual(jar_sha256(), published, "the committed wrapper jar is not the one Gradle publishes")
        self.assertEqual(expected_jar_sum(), published)


SCRIPTS = ("bin/acceptance-gradle.sh", "bin/acceptance-gradle-capped.sh")
SYSTEM_TEMP = os.sep + "tmp"   # the directory the two scripts hardcode


class AcceptanceScriptsCheckTheJar(unittest.TestCase):
    """Each script verifies the wrapper jar against the committed sum before its first ./gradlew, and refuses (exit 1) otherwise."""

    def tree(self, script, jar_bytes=None, sum_text=None, drop_sum=False):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        wrap = os.path.join(d, "bench/gradle-sample/gradle/wrapper")
        shutil.copytree(os.path.join(ROOT, "bench/gradle-sample"), os.path.join(d, "bench/gradle-sample"))   # the capped script copies the whole sample
        os.makedirs(os.path.join(d, "bin"))
        # The scripts name their scratch files under the system temp directory by absolute name. The copy under test points those names into
        # the fixture, so a run never touches (or inherits from) the machine's real temp directory.
        scratch = os.path.join(d, "scratch")
        os.makedirs(scratch)
        with open(os.path.join(ROOT, script)) as f:
            src = f.read().replace(SYSTEM_TEMP + "/", scratch + "/")
        with open(os.path.join(d, script), "w") as f:
            f.write(src)
        os.makedirs(os.path.join(d, ".github/policy"))
        shutil.copy(JAR_SUM_FILE, os.path.join(d, JAR_SUM_REL))
        if drop_sum:
            os.remove(os.path.join(d, JAR_SUM_REL))
        log = os.path.join(d, "gradlew.log")
        gw = os.path.join(d, "bench/gradle-sample/gradlew")
        with open(gw, "w") as f:
            f.write('#!/bin/sh\necho gradlew >> "%s"\nexit 1\n' % log)
        os.chmod(gw, 0o755)
        if jar_bytes is not None:
            with open(os.path.join(wrap, "gradle-wrapper.jar"), "wb") as f:
                f.write(jar_bytes)
        if sum_text is not None:
            with open(os.path.join(d, JAR_SUM_REL), "w") as f:
                f.write(sum_text(d) if callable(sum_text) else sum_text)
        shim = os.path.join(d, "shim")
        os.makedirs(shim)
        try:
            subprocess.run(["sha256sum", "--version"], capture_output=True, timeout=30)
            has_sha256sum = True
        except FileNotFoundError:
            has_sha256sum = False
        if not has_sha256sum:   # a developer machine without GNU coreutils: the same check through shasum
            with open(os.path.join(shim, "sha256sum"), "w") as f:
                f.write('#!/bin/sh\nexec shasum -a 256 "$@"\n')
            os.chmod(os.path.join(shim, "sha256sum"), 0o755)
        return d, log, shim

    def run_script(self, script, **kw):
        d, log, shim = self.tree(script, **kw)
        env = {"PATH": shim + os.pathsep + os.environ.get("PATH", ""), "GITHUB_OUTPUT": os.path.join(d, "out"), "TMPDIR": os.path.join(d, "scratch")}
        r = subprocess.run(["bash", script], cwd=d, env=env, capture_output=True, text=True, timeout=120)
        return r, (os.path.exists(log) and open(log).read() or "")

    def test_a_changed_jar_is_refused_before_gradlew_runs(self):
        for s in SCRIPTS:
            r, ran = self.run_script(s, jar_bytes=b"not the wrapper")
            self.assertEqual(r.returncode, 1, "%s: %s" % (s, r.stderr))
            self.assertIn("gradle-wrapper.jar", r.stderr)
            self.assertEqual(ran, "", "%s ran gradlew behind a changed jar" % s)

    def test_a_missing_expected_file_is_refused_before_gradlew_runs(self):
        for s in SCRIPTS:
            r, ran = self.run_script(s, drop_sum=True)
            self.assertEqual(r.returncode, 1, "%s: %s" % (s, r.stderr))
            self.assertIn("gradle-wrapper.jar", r.stderr)
            self.assertEqual(ran, "", "%s ran gradlew with no expected sum" % s)

    def test_an_expected_file_with_the_wrong_hash_for_the_jar_is_refused(self):
        for s in SCRIPTS:
            r, ran = self.run_script(s, sum_text="%s  %s\n" % ("0" * 64, JAR_REL))
            self.assertEqual(r.returncode, 1, "%s: %s" % (s, r.stderr))
            self.assertIn("gradle-wrapper.jar", r.stderr)
            self.assertEqual(ran, "", "%s ran gradlew against a wrong expected sum" % s)

    def test_an_expected_file_naming_another_file_is_refused_even_when_that_file_verifies(self):
        import hashlib

        def names_gradlew(d):   # the hash of the FIXTURE's gradlew (the fake the test installs), so only the check's refusal can stop the run
            with open(os.path.join(d, "bench/gradle-sample/gradlew"), "rb") as f:
                return "%s  bench/gradle-sample/gradlew\n" % hashlib.sha256(f.read()).hexdigest()
        for s in SCRIPTS:
            r, ran = self.run_script(s, jar_bytes=b"not the wrapper", sum_text=names_gradlew)
            self.assertEqual(r.returncode, 1, "%s: %s" % (s, r.stderr))
            self.assertIn("gradle-wrapper.jar", r.stderr)
            self.assertEqual(ran, "", "%s ran gradlew although the expected file names another file" % s)

    def test_an_expected_file_with_a_second_line_is_refused(self):
        for s in SCRIPTS:
            def with_valid_second_line(d):   # a second line that verifies, so only the one-line rule can refuse
                import hashlib
                with open(os.path.join(d, "bench/gradle-sample/gradlew"), "rb") as f:
                    return open(JAR_SUM_FILE).read() + "%s  bench/gradle-sample/gradlew\n" % hashlib.sha256(f.read()).hexdigest()
            r, ran = self.run_script(s, sum_text=with_valid_second_line)
            self.assertEqual(r.returncode, 1, "%s: %s" % (s, r.stderr))
            self.assertIn("gradle-wrapper.jar", r.stderr)
            self.assertEqual(ran, "", "%s ran gradlew behind a two-line expected file" % s)

    def test_an_expected_file_with_the_jar_line_twice_or_a_blank_line_after_it_is_refused(self):
        line = open(JAR_SUM_FILE).read()
        for name, text in (("the jar line twice", line + line), ("a blank line after it", line + "\n")):
            for s in SCRIPTS:
                r, ran = self.run_script(s, sum_text=text)
                self.assertEqual(r.returncode, 1, "%s with %s: %s" % (s, name, r.stderr))
                self.assertIn("gradle-wrapper.jar", r.stderr)
                self.assertEqual(ran, "", "%s ran gradlew behind an expected file with %s" % (s, name))

    def test_a_long_tail_after_the_jar_line_is_refused(self):
        line = open(JAR_SUM_FILE).read()
        for s in SCRIPTS:   # more than a pipe buffer of tail: an early-exit reader must not turn a broken pipe into "no second line"
            r, ran = self.run_script(s, sum_text=line + "#\n" * 40000)
            self.assertEqual(r.returncode, 1, "%s: %s" % (s, r.stderr[-200:]))
            self.assertIn("gradle-wrapper.jar", r.stderr)
            self.assertEqual(ran, "", "%s ran gradlew behind a long tail" % s)

    def test_the_committed_jar_reaches_gradlew(self):
        for s in SCRIPTS:
            r, ran = self.run_script(s)
            self.assertIn("gradlew", ran, "%s never reached gradlew with the committed jar: %s" % (s, r.stderr[-300:]))


if __name__ == "__main__":
    unittest.main()
