# Automatic patch releases

DRAFT, for the owner's read. The quoted rules are the owner's ratified text (Oct 2 2026, with the amendment of the same day), copied as written.

> **What a patch is.** Fixes only: CVE fixes (dependency bumps, base-image digest bumps), VEX changes, bug fixes with no behavior change. A patch release bumps the patch number: vX.Y.Z → vX.Y.(Z+1), a real semantic-version tag; no build numbers, no suffixes. Minor and major releases stay the owner's, tagged by hand as now.

> **When it is cut.** A fix for a critical or high CVE cuts a patch release as soon as it merges. Anything else that changes shipped bytes is picked up by the auditor's daily run: if main is ahead of the latest tag in shipped bytes, it cuts one patch that day. Never more than one patch per day except for critical/high fixes.

> **Same pipeline, no shortcuts.** A patch runs the full chain: admission, build, assembly, reproducibility, scans, acceptance, authorization, promotion. The tag lands on GHCR and the Docker Hub mirror with identical digests.

> **Release notes, generated.** Per fix: CVE id, package, old → new version, severity, affected image variants; each VEX statement added or changed; a "no behavior change" line. Posted on the GitHub release and in the changelog.

> **Floating tags.** A CI patch release moves :X.Y to itself every time; it moves :X and :latest only when it is the highest released version. Same on GHCR and the Docker Hub mirror, by digest.

How the tags are named and how to pin one: [upgrading and pinning](upgrading.md).
