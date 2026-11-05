# Scanning FosterStack in your compliance pipeline

Every scanner in [the repo's scanner list](../.github/policy/scanners.json)
runs in the release pipeline's Check stage against the exact image digests of every release from v0.3.0 on, <!-- pinned: historical -->
and the current release's images are rescanned daily; [`RELEASING.md`](../RELEASING.md) states exactly what the
release scan does and does not attach to. This page is about what to expect
when *you* scan our image, since a minimal image scans differently from a
typical distro image in ways that surprise people the first time.

## What to expect

The scanner output for a v0.3 image is not reproduced here. A minimal image
with a handful of packages can report a different operating system, or none,
depending on the scanner, and finds nothing for components it holds no package
record of. Scan the exact digest you pull and read the result against
[the packages the image holds](../build/apko.yaml).

## Package-DB asymmetry — expect this, it isn't a bug

Our images have no package manager and only a handful of packages in the
package database (base layout, CA certificates, time zone data and `fscache`). That has an
asymmetric effect on checks:

- **"Is forbidden package X present?"** checks — pass, as long as X is not one
  of the few packages the image holds.
- **"Is required package X present?"** checks — pass only for the packages the
  image holds (see `build/apko.yaml`) and fail for anything else, such as a
  shell or a package manager.
- A check that needs a package manager to list packages may error: there is
  none in the image, only the package database a scanner can read.

If you run a benchmark or policy pack written for a full-OS image (Debian,
Ubuntu, etc.) against ours, expect confusing partial results — not a
finding, just a mismatch between the benchmark's assumptions and a
minimal image. Scanner content often has no genuine OS/platform gating by
default: a scanner may happily score a minimal image against a full
distro benchmark and produce results that don't mean what they look like
they mean. Don't over-read a minimal image's score against a
Debian-shaped policy without checking what each rule verifies.

## Exit codes: don't gate on the raw process exit code

Scanner exit codes (Grype's among them) conflate "ran and found something above your
threshold" with "could not run at all" in ways that are easy to miss.
**Read per-rule verdicts from the results document (JSON/SARIF), never
gate a pipeline purely on the raw exit code** — a broken scan and a clean
scan can both look like "exit 0" or both look like "exit 1" depending on
flags, and conflating them ships a green gate that checks nothing.

## There is no debug image from v0.3.0 <!-- pinned: historical -->

Releases before v0.3.0 also shipped a `:debug` tag with a busybox shell; it <!-- pinned: historical -->
showed more in a scan than the production image because busybox itself
carries a package surface. From v0.3.0 the release carries two images, <!-- pinned: historical -->
production and `-fips`, and neither contains busybox, so there is no
debug variant to scan or to exclude from a gate. To troubleshoot a running
container use a separate helper container instead; see [troubleshooting
without a shell](docker-deploy.md#troubleshooting-without-a-shell-in-the-image).

## Using our VEX files in your scanner

Each release carries our exceptions as published statements, generated from one
source ([`.vex/`](../.vex/)). Download them from the release page
(`gh release download v${VER} --repo fosterstack/cache -p 'fosterstack-cache*'`) and
check them against the signed release manifest as described in
[Verify our images](verify-images.md). Then apply the form your scanner reads:

| Your scanner | File | How |
|---|---|---|
| Grype | `fosterstack-cache.openvex.json` | `grype IMAGE --vex fosterstack-cache.openvex.json` |
| Trivy | `fosterstack-cache.openvex.json` | `trivy image --vex fosterstack-cache.openvex.json IMAGE` |
| Docker Scout | none yet | Scout does not apply a VEX file given on the command line (see [Docker Scout](#docker-scout)) |
| Amazon Inspector | `fosterstack-cache-<version>.inspector-filters.json` | one suppression rule per statement: `aws inspector2 create-filter`, one rule per call |
| Google Artifact Analysis | `fosterstack-cache-<version>.csaf.json` | `gcloud artifacts vulnerabilities load-vex`, see [`.vex/README.md`](../.vex/README.md) for naming your image path |

The three files are generated from the same statements. The OpenVEX and CSAF files
carry every statement; the Inspector file carries one rule per `not_affected` or
`fixed` statement and none for `affected` or `under_investigation`. Google applies
whole-image statements only. [`.vex/README.md`](../.vex/README.md) has the detail.

## Suppression rules

A suppression rule in your scanner is only as trustworthy as the claim behind it,
so ours work in one direction: **every suppression traces to a published
statement**.

- **Our rules.** We keep no scanner-side ignore that stands alone. A suppression in
  our repository must cite the statement that governs it
  ([`.vex/README.md`](../.vex/README.md)), and the Inspector rules above are
  generated from the statements, never written by hand.
- **Which statements become rules.** `not_affected` and `fixed` statements become
  suppression rules. `affected` and `under_investigation` never do: those findings
  stay visible in your scanner.
- **Scoped to what we shipped.** Each rule is scoped by the CVE and by the digests
  of the release it was written for (and by package and version when the statement
  names one), so it does not hide the same CVE in a different image.
- **Your own rules.** Put the statement ID in the rule's reason or comment, so a
  reviewer on your side can trace it back to our file the same way.

## Docker Scout

Docker Scout does not apply a VEX file you give it on the command line. The
`--vex-location` option is accepted, but our statements are not applied on any Scout
release we tested, from 1.9.3 through 1.26.0 (Docker's open report is
[docker/scout-cli#207](https://github.com/docker/scout-cli/issues/207)). A Scout scan
of our images therefore still lists the findings our statements cover. Read them
against the published OpenVEX file ([above](#using-our-vex-files-in-your-scanner)) by
hand until Scout can apply it; we will say here when it can.

## Reproducing our own gate

Our release pipeline's scan step is public:
[`bin/check-scan.sh`](../bin/check-scan.sh), run by the Check stage
([`.github/workflows/stage-verify.yml`](../.github/workflows/stage-verify.yml)),
is the gate itself. The scanners are the ones in
[the scanner list](../.github/policy/scanners.json): Grype and OSV-Scanner.
Both scan the exact built images by digest (Grype also scans the four Linux
archives, OSV-Scanner the Go modules). The same Check stage also runs
`govulncheck` once on the tagged source, a separate Go source scan with its own
policy that the rest of this section does not describe. Pull requests are
scanned by [`scan.yml`](../.github/workflows/scan.yml) on the candidate images,
with Grype and Amazon Inspector.

The gate's policy is every severity, with the published VEX applied (a finding
of unknown severity fails it too), and the example below uses the same policy.
It is a simplified reproduction, not the exact
invocation: the gate also runs Grype with an empty configuration file and refuses
`GRYPE_*` and `OSV_SCANNER_*` variables (so a local setting cannot hide a finding),
scans each platform of the index separately, and checks that every finding
Grype reports as ignored was ignored by the VEX file. That check does not see
matches Grype's distro exclusions or OSV-Scanner's `linux` filter drop before any
report. Read `bin/check-scan.sh` for the full set. The VEX document ships with each
release as `fosterstack-cache.openvex.json` and lives in-repo at
[`.vex/`](../.vex/):

```sh
# Same severity policy and VEX as the release gate (Grype shown):
grype ghcr.io/fosterstack/cache:X.Y.Z \
  --fail-on negligible --vex fosterstack-cache.openvex.json -o json > result.json
# --fail-on does not fire on a finding of UNKNOWN severity; the gate judges the result instead:
jq -e '(.matches | type) == "array" and (.matches | length) == 0' result.json
```

The example does not run OSV-Scanner, and it uses whatever vulnerability
database your Grype has, where the gate refuses a database built more than 48 hours
before the scan, so a result can differ from ours on a different day. Scanners
outside the release gate, such as Trivy, are useful cross-checks.

Run without `--vex` to see raw findings including the ones we have
publicly dispositioned. Run both scans against the same image and the same
vulnerability database snapshot (do not update the database between them):
the difference is then the set of findings suppressed by the published VEX
statements that apply, which is how you audit them.

## Marketing claim, with the receipt

"Every scanner in the repo's list runs on every release" is not a claim we're
asking you to take on faith. From v0.3.0 the release's signed Check records bind <!-- pinned: historical -->
the scan results file (`scan-results.json`, one file for all scanners), by hash,
to the image digests; the results file itself is not attached to the release.
The records are among the signed evidence files described in
[Verify our images](verify-images.md#the-signed-evidence-files); that page does not
yet give a command for checking the Check records themselves.
