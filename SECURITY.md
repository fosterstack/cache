# Security policy

## Reporting a vulnerability

Please use [GitHub's private vulnerability reporting](https://github.com/fosterstack/cache/security/advisories/new)
for this repository rather than a public issue. If that's unavailable, open
an issue asking for a private channel and we'll follow up.

## Patch commitment

Security patches are never withheld from the free tier — the same fix ships
to every user, on the same day, regardless of license. Paid tiers add a
written SLA commitment; the free tier gets the same patches on a
best-effort basis.

**Scope of the target (commercially reasonable efforts, target 48 hours):**

- **Upstream fix exists** (the common case — a dependency ships a patched
  version): remediation is the version bump, shipped within the target
  window.
- **No upstream fix exists**: within the same window we publish an
  assessment (affected / not-affected, with justification — a VEX
  statement) plus a mitigation path (config workaround, feature disable, or
  a vendored patch for small pure-Go dependencies), and track to closure.

This is a target, not a contractual penalty clause, and it does not promise
fix-authorship timelines for code this project doesn't control.

## v0.1.0 and the pre-remediation pipeline <!-- pinned: historical -->

v0.1.0 (tagged Aug 21, 2026) was built and published by the pre-remediation <!-- pinned: historical -->
release pipeline. Its published images were not scanned before publication:
the pipeline scanned a snapshot build and published a separate build of the
same commit. The published v0.1.0 digests have been rescanned since, at <!-- pinned: historical -->
every severity, with the published VEX applied — see the
[rescan runs](https://github.com/fosterstack/cache/actions/workflows/rescan-v010.yml)
for the verdicts. The next release is the first to carry the full evidence
chain: one build, scanned and tested by digest, promoted without a rebuild.

## Nothing ships with a known CVE

The policy: no artifact is published with a known CVE at any severity,
unless a published VEX statement explains why the finding does not apply.
How completely the pipeline enforces that policy today is stated below,
exactly.

Independent scanners with deliberately different vulnerability databases run
in the release workflow, each blocking at every severity including UNKNOWN.
The scanner set is [one list in the repo](.github/policy/scanners.json);
nothing hard-codes a count or a name.

What the release workflow does today, stated exactly: a pre-publish snapshot
build is scanned, and a finding fails the release before the publish job
runs. The published images are a **separate build of the same commit** — the
scanned build and the published build are not the same bytes, so the scan
verdict attaches to the release's source, not to the published digests. That
gap is the subject of the Sep 2026 release-chain rework; until it closes,
the published digests' scan coverage is the daily rescan.

The pairing is deliberate. Grype is best-in-class at finding CVEs in binary
artifacts. Its partner is chosen for a database that disagrees with Grype's —
different sources, low overlap, and a lead of roughly a week over public
feeds — because two scanners that agree with each other only tell you what
one of them already knew. Anti-correlation is the point.

Exceptions are OpenVEX documents in [`.vex/`](.vex/), read by both scanners
and published as a release asset. VEX is the single source of truth: any
tool-specific ignore must cite the statement that governs it and may never
stand alone. No statement, no exception, no push.

Every published image is also rescanned daily — currently at CRITICAL and
HIGH severity, which is softer than the release gate — so a CVE disclosed
against bytes we already shipped raises a tracked issue rather than waiting
for someone to look.

## Approved-only cryptography

Enforcement is delegated to the validated module rather than to a list.

CI runs the full test suite under `GODEBUG=fips140=only` against the FIPS
build, where Go's FIPS 140-3 validated module (CMVP certificate #5247)
refuses any non-approved algorithm at runtime. Any reach for non-approved
cryptography — ours or a dependency's — fails that commit's `fips140-only`
check.

Two limits of that claim, stated so it cannot be over-read: the check proves
the paths the test suite executes, built in FIPS mode — it does not exercise
the released `fscache-fips` binary or image, which no test currently runs;
and its status as a merge-blocking check is set by the repository ruleset,
which is listed in [.github/policy/required-checks.json](.github/policy/required-checks.json).

A `golangci-lint` `depguard` allowlist covers the static side: only
in-boundary crypto imports are permitted, and third-party cryptographic
implementations are denied outright, because `GOFIPS140` does not govern
code outside the module.

**What each half proves, stated plainly.** `fips140=only` proves the paths
the tests execute; it says nothing about a path no test reaches. The
allowlist is a static check: it sees imports, not behaviour. Together they
cover more than either does alone, and neither is a proof of total coverage.

The `-fips` build announces itself at startup, so the property is
observable at runtime rather than taken on trust:

```
"fips140":"active (Go validated module, CMVP cert #5247)"
```

Standard builds report `"fips140":"off"`.

## Data handling

The server sends **no telemetry and requires no FosterStack connection** —
no usage reporting, no licence check, no update ping, ever. Today's free
core initiates no outbound network connections at all, so it behaves
identically on a host with no route to the internet — which is also why the
air-gapped install path is a supported configuration rather than a
workaround. When the paid features ship, traffic that you configure will
exist — an identity provider for SSO, peer replicas for replication — and
those are connections to endpoints you choose; nothing will ever connect to
FosterStack.

This is a mechanical property, not a policy promise, and it is checkable in a
minute against a running server:

```sh
lsof -nP -a -p "$(pgrep -n fscache)" -i
```

Every socket listed should be the listener itself or a connection *accepted* on
the listen port. An outbound connection would appear with an ephemeral local
port and a remote address; there are none, at rest or under load.

The server stores exactly what a build tool sends it: cache keys and the blobs
they address. It has no notion of users, sessions, or identity beyond the single
optional Basic Auth credential shared by all of its clients.

There is no request access log. The only per-request logging is on failure — a
store error or a short write to the client — and those lines carry the HTTP
method and the cache key, never the request body, never credentials, and never a
client address.

## Supported versions

Latest minor release. This section will be updated once a release history
exists.
