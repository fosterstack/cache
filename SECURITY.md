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

## Algorithm discipline

This codebase uses SHA-256 only for anything content- or
integrity-related; `crypto/md5` and `crypto/sha1` are banned imports,
enforced in CI regardless of intended use.

## Supported versions

Latest minor release. This section will be updated once a release history
exists.
