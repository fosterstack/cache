# Scanning FosterStack in your compliance pipeline

FosterStack Cache's images are scanned by **Trivy AND Grype**, independently,
on every release before it's pushed — never after (see
[`RELEASING.md`](../RELEASING.md)). This page is about what to expect when
*you* scan our image too, since a minimal image scans differently from a
typical distro image in ways that surprise people the first time.

## What to expect

**The production and `-fips` images report as `debian` in scanner OS
detection**, even though there's no shell, no package manager, and no way
to `apt-get` anything. Confirmed directly against a real build:

```
$ trivy image ghcr.io/fosterstack/cache:0.1.0
...
Detected OS   family="debian" version="13.6"
...
┌──────────────────────────────────┬──────────┬─────────────────┐
│              Target               │   Type   │ Vulnerabilities │
├──────────────────────────────────┼──────────┼─────────────────┤
│ ghcr.io/fosterstack/cache (debian)│  debian  │        0        │
├──────────────────────────────────┼──────────┼─────────────────┤
│ ko-app/fscache                    │ gobinary │        0        │
└──────────────────────────────────┴──────────┴─────────────────┘
```

Google's distroless base ships an intact `/etc/os-release` deliberately
(that's exactly what scanners key OS detection on), and we never strip it
— see the scanner-facts source for this page,
`sprint4_scanner_input.md`. The `gobinary` row is our own compiled binary,
scanned by both tools' Go-module vulnerability catalogers directly.

## Package-DB asymmetry — expect this, it isn't a bug

A scratch/distroless image has no package database. That has an
asymmetric effect on checks:

- **"Is forbidden package X present?"** checks — pass vacuously. There's no
  package manager, so nothing is "installed" in the sense those checks
  look for.
- **"Is required package X present?"** checks — fail or error, for the same
  reason.

If you run a benchmark or policy pack written for a full-OS image (Debian,
Ubuntu, etc.) against ours, expect confusing partial results — not a
finding, just a mismatch between the benchmark's assumptions and a
minimal image. `sprint4_scanner_input.md`'s source material for this page
also notes there is often no genuine OS/platform gating in scanner content
by default: a scanner may happily score a scratch image against a full
distro benchmark and produce results that don't mean what they look like
they mean. Don't over-read a scratch image's score against a
Debian-shaped policy without checking what each rule verifies.

## Exit codes: don't gate on the raw process exit code

Trivy and Grype's exit codes conflate "ran and found something above your
threshold" with "could not run at all" in ways that are easy to miss.
**Read per-rule verdicts from the results document (JSON/SARIF), never
gate a pipeline purely on the raw exit code** — a broken scan and a clean
scan can both look like "exit 0" or both look like "exit 1" depending on
flags, and conflating them ships a green gate that checks nothing. This
failure mode has been observed in the field.

## The `-debug` variant is different on purpose

The `:debug` tag adds a busybox shell for interactive troubleshooting —
it is not the image you deploy. Scanning it will show more than the
production image (busybox itself carries a small package surface), and
our own release pipeline documents any known, unfixable findings there as
explicit VEX suppressions in [`.grype.yaml`](../.grype.yaml) rather than
hiding them — see that file for the current reasoning on each entry.
Production and `-fips` images never include busybox.

## Reproducing our own gate

Our release pipeline's scan step is public —
[`.github/workflows/release.yml`](../.github/workflows/release.yml) — so
the exact invocation we gate releases on is not a secret:

```sh
trivy image --scanners vuln \
  --severity CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN \
  ghcr.io/fosterstack/cache:X.Y.Z

grype ghcr.io/fosterstack/cache:X.Y.Z --fail-on medium
```

## Marketing claim, with the receipt

"Scanned by Trivy and Grype on every release, results published" is not a
claim we're asking you to take on faith — every release's scan is the CI
run itself, public, in this repo's Actions tab. See
[Verify our images](verify-images.md) for how to confirm the exact image
you pulled came from that same run.
