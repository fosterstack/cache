# proves: REQ-SUP-001-AC28, REQ-SUP-001-AC29, REQ-SUP-001-AC31, REQ-SUP-001-AC32
"""Two plain-form pins (owner: tool downloads are an exact version plus a checksum; images are pinned by digest).
AC28: the sample project's Gradle wrapper carries distributionSha256Sum, a lowercase sha256 hex.
AC29: acceptance.yml refuses an image-ref that is not name@sha256:<64 lowercase hex> before any docker run: in every job that
starts an image from IMAGE_REF, an earlier step runs the refusal; the step's own script is run here against hostile refs."""
import os, re, shutil, stat, subprocess, tempfile, unittest

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
DIGEST = "ghcr.io/fosterstack/cache@sha256:" + "a" * 64


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


def uses_image_ref(step):
    return "IMAGE_REF" in (step.get("env") or {})


def refusal_step(job):
    """The first step of the job that runs when an image-ref is given and starts no container."""
    for i, s in enumerate(job["steps"]):
        if "inputs.image-ref != ''" in str(s.get("if", "")) and "docker" not in s.get("run", "").replace("docker login", ""):
            return i, s
    return None, None


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
        if jar_bytes is not None:
            with open(os.path.join(wrap, "gradle-wrapper.jar"), "wb") as f:
                f.write(jar_bytes)
        if sum_text is not None:
            with open(os.path.join(d, JAR_SUM_REL), "w") as f:
                f.write(sum_text)
        log = os.path.join(d, "gradlew.log")
        gw = os.path.join(d, "bench/gradle-sample/gradlew")
        with open(gw, "w") as f:
            f.write('#!/bin/sh\necho gradlew >> "%s"\nexit 1\n' % log)
        os.chmod(gw, 0o755)
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
            self.assertEqual(ran, "", "%s ran gradlew with no expected sum" % s)

    def test_an_expected_file_for_another_jar_is_refused(self):
        for s in SCRIPTS:
            r, ran = self.run_script(s, sum_text="%s  %s\n" % ("0" * 64, JAR_REL))
            self.assertEqual(r.returncode, 1, "%s: %s" % (s, r.stderr))
            self.assertEqual(ran, "", "%s ran gradlew against a wrong expected sum" % s)

    def test_the_committed_jar_reaches_gradlew(self):
        for s in SCRIPTS:
            r, ran = self.run_script(s)
            self.assertIn("gradlew", ran, "%s never reached gradlew with the committed jar: %s" % (s, r.stderr[-300:]))


class ImageRefRefusal(unittest.TestCase):
    def run_step(self, ref, script):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        calls = os.path.join(d, "calls")
        for tool in ("docker", "curl", "sleep"):
            path = os.path.join(d, tool)
            open(path, "w").write('#!/bin/sh\necho "%s $*" >>"%s"\nexit 0\n' % (tool, calls))
            os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
        script = re.sub(r"\$\{\{[^}]*\}\}", "x", script)
        env = {"PATH": d + os.pathsep + os.environ.get("PATH", ""), "IMAGE_REF": ref}
        r = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, timeout=60)
        ran = open(calls).read() if os.path.exists(calls) else ""
        return r, ran

    def test_every_job_that_receives_the_ref_has_the_refusal(self):
        for name, job in jobs().items():
            if "inputs.image-ref" in yaml.safe_dump(job["steps"]).replace("inputs.image-ref == ''", "").replace("inputs.image-ref != ''", ""):
                self.assertIsNotNone(refusal_step(job)[1], "job %s receives inputs.image-ref with no refusal step" % name)

    def test_the_refusal_names_the_ref_it_refused(self):
        for name, job in jobs().items():
            i, step = refusal_step(job)
            if step is None:
                continue
            r, _ = self.run_step("ghcr.io/x/y:latest", step["run"])
            self.assertIn("ghcr.io/x/y", r.stderr)

    def test_every_job_that_starts_an_image_refuses_a_bad_ref_first(self):
        n = 0
        for name, job in jobs().items():
            idx = [i for i, s in enumerate(job["steps"]) if uses_image_ref(s) and "docker run" in s.get("run", "")]
            if not idx:
                continue
            n += 1
            r, step = refusal_step(job)
            self.assertIsNotNone(step, "job %s starts an image from IMAGE_REF with no refusal step" % name)
            self.assertLess(r, idx[0], "job %s: the refusal must come before the first docker run" % name)
            self.assertNotEqual(step.get("continue-on-error"), True)
        self.assertGreater(n, 0)

    def test_the_refusal_script_refuses_everything_but_a_full_lowercase_digest(self):
        for name, job in jobs().items():
            i, step = refusal_step(job)
            if step is None or not any(uses_image_ref(s) and "docker run" in s.get("run", "") for s in job["steps"]):
                continue
            self.assertTrue(uses_image_ref(step), "the refusal step reads IMAGE_REF from env, not inline")
            bad = [
                "ghcr.io/fosterstack/cache:latest",
                "ghcr.io/fosterstack/cache:v0.3.0",
                "ghcr.io/fosterstack/cache",
                "ghcr.io/fosterstack/cache@sha256:" + "a" * 63,
                "ghcr.io/fosterstack/cache@sha256:" + "A" * 64,
                "/@sha256:" + "a" * 64,
                "ghcr.io//fosterstack/cache@sha256:" + "a" * 64,
                "ghcr.io/fosterstack//cache@sha256:" + "a" * 64,
                "ghcr.io/fosterstack/cache..x@sha256:" + "a" * 64,
                "ghcr.io/fosterstack/cache:@sha256:" + "a" * 64,
                "ghcr.io/fosterstack/cache:one:two@sha256:" + "a" * 64,
                "a..b/x@sha256:" + "a" * 64,
                ".ghcr.io/x@sha256:" + "a" * 64,
                "ghcr.io./x@sha256:" + "a" * 64,
                "-ghcr.io/x@sha256:" + "a" * 64,
                "ghcr-.io/x@sha256:" + "a" * 64,
                "ghcr.io:/x@sha256:" + "a" * 64,
                "ghcr.io:port/x@sha256:" + "a" * 64,
                "ghcr.io/fosterstack/cache:v1/child@sha256:" + "a" * 64,
                "ghcr.io/fosterstack/Cache@sha256:" + "a" * 64,
                "ghcr.io/fosterstack/cache:" + "t" * 129 + "@sha256:" + "a" * 64,
                "-v/:/host@sha256:" + "a" * 64,
                "ghcr.io/fosterstack/cache/@sha256:" + "a" * 64,
                "@sha256:" + "a" * 64,
                "ghcr.io/fosterstack/cache@sha256:" + "a" * 64 + "x",
                "ghcr.io/fosterstack/cache:v1@sha256:" + "g" * 64,
                DIGEST + " --privileged",
                DIGEST + "\nextra",
                "",
            ]
            for ref in bad:
                r, ran = self.run_step(ref, step["run"])
                self.assertNotEqual(r.returncode, 0, "job %s accepted %r" % (name, ref))
                self.assertNotIn("docker run", ran, "docker ran for %r" % ref)
            r, ran = self.run_step(DIGEST, step["run"])
            self.assertEqual(r.returncode, 0, r.stderr)

    def test_a_valid_reference_with_a_tag_port_or_underscores_is_accepted(self):
        good = [
            "ghcr.io/fosterstack/cache:v0.3.0@sha256:" + "b" * 64,
            "ghcr.io/fosterstack/cache:RC1@sha256:" + "b" * 64,
            "ghcr.io/fosterstack/cache__release@sha256:" + "b" * 64,
            "localhost:5000/team/app-x.y@sha256:" + "b" * 64,
            "cache@sha256:" + "b" * 64,
            "registry-1.docker.io/library/a-b@sha256:" + "b" * 64,
        ]
        for name, job in jobs().items():
            i, step = refusal_step(job)
            if step is None or not uses_image_ref(step):
                continue
            for ref in good:
                r, _ = self.run_step(ref, step["run"])
                self.assertEqual(r.returncode, 0, "%s refused %r: %s" % (name, ref, r.stderr))

    def test_the_refusal_runs_whenever_the_image_is_started(self):
        for name, job in jobs().items():
            i, step = refusal_step(job)
            if step is None:
                continue
            starts = [s for s in job["steps"] if uses_image_ref(s) and "docker run" in s.get("run", "")]
            self.assertTrue(starts)
            for s in starts:
                self.assertEqual(step["if"], s["if"], "job %s: the refusal's condition must equal the start step's" % name)
            self.assertNotEqual(job.get("continue-on-error"), True)


if __name__ == "__main__":
    unittest.main()
