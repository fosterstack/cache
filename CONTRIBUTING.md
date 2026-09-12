# Contributing

Thanks for being here. This file is short because the policy is simple, and
we'd rather be clear than welcoming-sounding.

## We don't take code contributions right now

Not a judgment of anyone's code — it's how this company is built. The
implementation here is done by AI agents working under automated gates:
requirements first, adversarial review, signed evidence at each step. An
outside diff is the one input that can't go through those gates unreviewed,
and a one-person review operation would either become the bottleneck or
become careless. So we close outside pull requests, kindly, and re-file
what they were trying to do as an issue.

Pull requests stay enabled because our own tooling uses them (Dependabot
and the engineering agents). If you open one, expect a friendly close with
a link back here.

## What we want, and will act on

- **Issues.** Bugs, surprising behavior, docs that misled you, questions
  the docs should have answered. These directly move the roadmap.
- **Reproductions.** A failing case is worth more than a patch: we can act
  on it through the gates, and you'll be credited in the fix.
- **Technical feedback.** On the requirements and acceptance criteria in
  [docs/quality/traceability.md](docs/quality/traceability.md) especially —
  arguing with an acceptance criterion is arguing with the product, in
  exactly the venue where it changes things.
- **Security reports**, through GitHub's private vulnerability reporting —
  see [SECURITY.md](SECURITY.md). Researchers: send the report, not the
  patch, and you'll be credited in the fix.

## Forking

The core is MIT-licensed and you are welcome to fork it. ("The core," not
"fully open source": enterprise code will be source-available under a
commercial license in the same repository when it exists.)

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
*right now*, *simply*, *truly*. If deleting the word costs nothing, delete it.

### The three failure modes

Test every public sentence against all three. They are separate faults and a
sentence can pass two and fail the third:

1. **It sounds weak, or congratulates us.** Hedging and self-praise both
   signal the same thing — that we do not trust the claim to stand alone.
2. **It does not parse for a cold reader.** Someone with zero FosterStack
   context, reading it once, at speed. Internal dialect is the usual culprit:
   a phrase that is perfectly clear to whoever wrote it and opaque to
   everyone else.
3. **Compression has blurred which noun owns which property.** The most
   dangerous of the three, because the sentence reads well. If a paragraph
   moves from "a single static binary" into signing and provenance language,
   a reader cannot tell which of those attach to the binary and which to the
   image — and a reader who assumes wrong has been misled by us, not by their
   own carelessness.

Dense **and** precise. Density is a virtue here and the top of the README is
deliberately a maximum-claim-per-word zone; the fix for a blurred claim is an
ownership marker, never an extra sentence.

## Security issues

Please don't open a public issue for a vulnerability — see
[`SECURITY.md`](SECURITY.md) for the private reporting channel.

## License

By contributing, you agree your contribution is licensed under this
project's [MIT license](LICENSE).
