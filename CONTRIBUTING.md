# Contributing

Thanks for considering it — this is a small, MIT-licensed project and outside
contributions are welcome. A few things are worth knowing up front so
there are no surprises.

## Every outside PR gets owner review before merge

There's no auto-merge path for external contributors, and there isn't a
bot approving PRs on the maintainer's behalf. A pull request from anyone
outside the org gets read and reviewed by a human before it merges — no
exceptions, regardless of how green the CI checks are.

This isn't distrust of any particular contributor — it's the standing
policy for any code or configuration influenced by input this project
doesn't control: *no code influenced by untrusted input ships without
owner review.* An outside PR is exactly that category, the same as an
unsolicited vulnerability report with a suggested patch. It's also the
concrete version of a documented supply-chain control (NIST SP 800-204D
`PULL-PUSH-REQ-3` — see `ops/docs/cicd-security-baseline.md`, cited from
this repo's CI-hardening notes): outside-collaborator PRs require
approval before any workflow runs against them.

Practically, this means:
- CI won't run automatically on a first-time contributor's PR until a
  maintainer approves the run.
- Fork PRs never get repository secrets, ever — no workflow in this repo
  uses `pull_request_target` with a checkout of PR code, which is the
  standard way that boundary gets accidentally broken. If you see one,
  that's a bug, not a feature.
- Review turnaround has no SLA. This is presently a one-person-plus-CI
  operation; a quiet PR isn't necessarily a rejected one.

## Before opening a PR

- Run the full local check suite — it's the same one CI runs:
  ```sh
  go build ./...
  go vet ./...
  go test -race ./...
  golangci-lint run ./...     # staticcheck, gofmt/goimports, plus a
                               # repo-wide crypto/md5+crypto/sha1 import ban
  govulncheck ./...
  gosec ./...
  ```
- Keep the diff focused. A PR that mixes an unrelated refactor with the
  fix is harder to review and more likely to sit.
- If you're touching `internal/cache`'s eviction logic or anything in the
  release pipeline (`.goreleaser.yaml`, `.ko.yaml`,
  `.github/workflows/release.yml`), say so explicitly in the PR
  description — those are the two places a subtle bug is most expensive
  (the commit history has two examples this project caught in its own
  audit process).

## Docs voice

Documentation here is plain and declarative. Four rules:

- **State it, don't sell it.** "Every release is signed" — not "every
  release is rigorously signed, and you can verify it yourself right now."
  Self-congratulation reads as weakness; a flat claim reads as confidence.
- **No self-congratulation about our own output.** Don't tell the reader
  that a doc is thorough, a command is copy-pasteable, or a design is
  clever. Show the command and let them judge.
- **No sprint numbers, internal milestones, or process vocabulary** in
  public docs. "Sprint 4, in progress" means nothing to a reader deciding
  whether to run this in their CI.
- **Every claim is paired with an executable check.** If a page says the
  image has no shell, it shows the command that demonstrates it. A claim a
  reader cannot reproduce should be cut or moved to the roadmap, clearly
  labeled as unshipped.

Reassurance adverbs are the usual tell: *actually*, *genuinely*, *really*,
*right now*, *truly*. If deleting the word costs nothing, delete it.

## Security issues

Please don't open a public issue for a vulnerability — see
[`SECURITY.md`](SECURITY.md) for the private reporting channel.

## License

By contributing, you agree your contribution is licensed under this
project's [MIT license](LICENSE).
