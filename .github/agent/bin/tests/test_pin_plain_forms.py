# proves: REQ-SUP-001-AC28
"""A plain-form pin (owner: tool downloads are an exact version plus a checksum).
AC28: the sample project's Gradle wrapper carries distributionSha256Sum, a lowercase sha256 hex."""
import os, unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
PROPS = os.path.join(ROOT, "bench/gradle-sample/gradle/wrapper/gradle-wrapper.properties")
# The pin as reviewed: changing the wrapper's sum means changing this line too, and then CI's online test (below) compares the
# new value with the sum Gradle publishes and with the zip itself.
EXPECTED_SUM = "acd53f1edaf02f1a8ff99879f8a34b302661a057d9b063ae9e35b552f804d20a"


def wrapper_props():
    out = {}
    with open(PROPS) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                out[k] = v
    return out


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


if __name__ == "__main__":
    unittest.main()
