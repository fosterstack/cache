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
flags, and conflating them ships a green gate that checks nothing. This
failure mode has been observed in the field.

## Reproducing our own gate

Our release pipeline's scan step is public:
[`bin/check-scan.sh`](../bin/check-scan.sh), run by the Check stage
([`.github/workflows/stage-verify.yml`](../.github/workflows/stage-verify.yml)),
is the gate itself. The scanners are the ones in
[the scanner list](../.github/policy/scanners.json): Grype and OSV-Scanner.

The gate's policy is every severity, with the published VEX applied, and the
example below uses the same policy. It is a simplified reproduction, not the exact
invocation: the gate also runs Grype with an empty configuration file and refuses
`GRYPE_*` and `OSV_SCANNER_*` variables (so a local setting cannot hide a finding),
scans each platform of the index separately, and checks that every skipped
finding was skipped by the VEX file. Read `bin/check-scan.sh` for the full set. The VEX document ships with each
release as `fosterstack-cache.openvex.json` and lives in-repo at
[`.vex/`](../.vex/):

```sh
# Same severity policy and VEX as the release gate (Grype shown):
grype ghcr.io/fosterstack/cache:X.Y.Z \
  --fail-on negligible --vex fosterstack-cache.openvex.json -o json > result.json
# --fail-on does not fire on a finding of UNKNOWN severity; the gate judges the result instead:
jq -e '(.matches | type) == "array" and (.matches | length) == 0' result.json
```

Run without `--vex` to see raw findings including the ones we have
publicly dispositioned — the difference between the two runs is exactly
the set of published VEX statements, which is how you audit them.

## Marketing claim, with the receipt

"Every scanner in the repo's list runs on every release" is not a claim we're
asking you to take on faith. From v0.3.0 the release's signed Check records bind <!-- pinned: historical -->
the scan results file (`scan-results.json`, one file for all scanners), by hash,
to the image digests; the results file itself is not attached to the release.
The records are among the signed evidence files described in
[Verify our images](verify-images.md#the-signed-evidence-files); that page does not
yet give a command for checking the Check records themselves.
