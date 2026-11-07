# cache4 read-back: gate 7 in bin/build-admit.py (REQ-REL-012 AC7/AC8), one PR into chain-v030

Security tier (a release-admission check; build-admit.py is held by sha256 in chain-scripts.json and chain-test-shape.py).
No test and no code until this is acknowledged. The English rules (requirements text) are the only thing I write before the ack.

## What I will build
1. One new check `audit-approval`, between `ancestor-of-main` and `required-checks` (twelve checks; list-checks says so).
2. It copies main's `bin/audit-record.py`, `bin/audit-record-judge.sh` and `.github/policy/audit-writers.json`
   (`git show origin/main:...`, never the tagged commit's) into a scratch root, then runs
   `bash <root>/bin/audit-record-judge.sh <sha> main --release <tag> <tag-object-file>` as an argument list, no shell string.
   The tag object file is the one `route_tag` already wrote after the signature check, so the approval line is the owner's.
3. build-admit.py holds NO patch-tag rule of its own: it always calls the judge, which reads nothing for a patch tag
   (one rule, in one place; no drift). Exit 0 passes; exit 1 (no or bad record, no or ambiguous Audit-approved line),
   exit 3 (API error) and any other exit or a missing main file are all `admission refused at audit-approval: <first line>`.
   No `|| true`, fail closed. GH_TOKEN is inherited by the judge's `gh api` GET reads (same token, same job permissions: contents read).
4. Tests (tester role, before code): chain-build-admit-test.sh gets the check in CHECKS, the counterpart map and the
   snapshot line, a fake-gh fixture for `git/ref/heads/audit/<sha>` and the record commit, and cases:
   patch tag passes with no record read; non-patch tag with no record refused; with the record but no line refused;
   two lines / wrong sha / API error refused; a good record and line admitted; the tagged commit's own judge is never run
   (a planted judge in the tagged tree); the token is in no output. Mutants on build-admit.py: check removed, `|| true`,
   judge read from the tagged tree, patch rule re-implemented wrongly. The dropped audit-record-test.sh block is restored
   against build-admit.py (static shape: after the signature and ancestor checks, main's copies, no swallow) with its mutants.
5. Wiring that follows from a changed build-admit.py: chain-scripts.json row (tools gain `bash`, `runs` gain the two main scripts as
   data, new sha256), chain-test-shape.py NS_SHA, suite floors, requirements + mappings + traceability (go -C tools/requirements run . check, then generate).
   AC7's text moves from "stage-admission.yml" to "the source admission of the build stage (bin/build-admit.py)"; AC8 stays.

## Found while reading (needs your ruling)
- RC TAGS: the judge (main's audit-record.py `_RELEASE_TAG`) accepts `-rc.N`; the chain admits `-rcN` (TAG_SYNTAX, tests use v0.3.0-rc1).
  Run today: `v0.3.0-rc1` -> not a release version, `v0.3.0-rc.1` -> ok. So with gate 7 on, every chain rc tag would be refused with
  "the tag is not a release version" (AC7 names release candidates as needing the record, so refusing is wrong, not strict).
  My proposal: audit-record.py (and its test) accepts `-rc.N` and `-rcN`, in this same PR; audit-record.py is main's file, so that is a
  change to a file outside build-admit.py. Rule it: (a) yes, in this PR; (b) separate PR first; (c) build-admit maps the tag. I will take (a) unless told otherwise.
- The old-steps snapshot (bin/chain-admission-old-steps.txt) was taken at cutover and lacks main's audit step; I add that step name and its counterpart.

## Not applicable
- Chainguard-first rule (2026-11-04): nothing here builds, isolates, signs, scans or attests an image or package; it gates a tag. Said so, no read done.
- No new workflow file, no permission or secret change, no new network call of its own (gh GET only).

## Process
Branch gate7-admit from origin/chain-v030 (780b7821). Rules, then tests, then code; signed commits; PR into chain-v030; fix every red check;
two seats (gpt-6.1-sol high, gpt-6-astra high) on the head; post /srv/lane-outbox/cache4/gate7.md. Deadline: PR open by 09:00Z.
