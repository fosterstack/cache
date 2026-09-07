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

## Nothing ships with a known CVE

No artifact is published with a known CVE at any severity, unless a
published VEX statement explains why the finding does not apply.

Independent scanners with deliberately different vulnerability databases run
against every image before anything reaches the registry, each blocking at
every severity including UNKNOWN. A finding fails the release; the images
never leave the build runner.

The pairing is deliberate. Grype is best-in-class at finding CVEs in binary
artifacts. Its partner is chosen for a database that disagrees with Grype's —
different sources, low overlap, and a lead of roughly a week over public
feeds — because two scanners that agree with each other only tell you what
one of them already knew. Anti-correlation is the point.

Exceptions are OpenVEX documents in [`.vex/`](.vex/), read by both scanners
and published as a release asset. VEX is the single source of truth: any
tool-specific ignore must cite the statement that governs it and may never
stand alone. No statement, no exception, no push.

Every published image is also rescanned daily, so a CVE disclosed against
bytes we already shipped raises a tracked issue rather than waiting for
someone to look.

## Approved-only cryptography

Enforcement is delegated to the validated module rather than to a list.

CI runs the full test suite under `GODEBUG=fips140=only` against the FIPS
build, where Go's FIPS 140-3 validated module (CMVP certificate #5247)
refuses any non-approved algorithm at runtime. Any reach for non-approved
cryptography — ours or a dependency's — fails CI on that commit.

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

The server makes **no outbound network connections**. There is no telemetry, no
usage reporting, no licence check, and no update ping, so it behaves identically
on a host with no route to the internet — which is also why the air-gapped
install path is a supported configuration rather than a workaround.

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
