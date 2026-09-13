# Mutation testing

Statement coverage says the tests *ran* the code. It does not say the
tests would *notice* the code being wrong: a test can execute a line and
assert nothing meaningful about it. Mutation testing closes that gap. It
makes small changes to the product ("mutants" — negate a condition, shift
a boundary, swap an arithmetic operator) and re-runs the suite against
each one. A mutant the suite still passes ("lived") is a spot where the
tests execute the code but would not catch a real defect there.

## Tool: gremlins

We use [gremlins](https://github.com/go-gremlins/gremlins) (pinned
`v0.6.0`), chosen over `go-mutesting` because it is coverage-guided — it
only generates mutants on code the tests execute, so a run is bounded by
coverage rather than by the whole tree — and because its typed mutator
set (conditionals negation/boundary, arithmetic, increment/decrement,
etc.) maps cleanly onto the kinds of defects our tests must catch. The
configuration is in [`.gremlins.yaml`](../../.gremlins.yaml).

## Advisory, not gated

Per `test-strategy.md` §6 the mutation score is **advisory**: it is
published beside statement coverage, not enforced as a release gate,
until the owner agrees a baseline. The thresholds in `.gremlins.yaml` are
therefore `0` (report, never fail). The
[`mutation` workflow](../../.github/workflows/mutation.yml) runs it weekly
and on demand — a full mutation run re-runs the suite once per mutant and
is far heavier than the test suite, so it is not a per-PR check — and
uploads the JSON report and log as artifacts.

Two metrics are reported:

- **Mutant coverage** — the share of mutants placed on covered code. With
  100% statement coverage this is ~100%; it is the honesty check that the
  mutation run is exercising the whole product.
- **Test efficacy** — of the mutants that ran, the share the suite
  killed. This is the assertion-strength number. A lived mutant names a
  file, line, and mutation to inspect.

## Reading and acting on the results

A lived mutant is a to-do, not a failure: inspect it, and either add or
strengthen an assertion so the mutation is caught, or record why the
mutation is semantically equivalent (some mutants change code that cannot
change observable behavior — an "equivalent mutant" — and are not a real
gap). Do not chase 100% efficacy by asserting on incidental
implementation details; the goal is assertions that track the contract.

## Known limitations

- **Timeout sensitivity / non-determinism.** gremlins counts a mutant
  that makes a test hang as killed-by-timeout. On a loaded machine, a
  mutant near a loop can time out in one run and be killed cleanly in the
  next, so the efficacy number moves run to run. The
  `timeout-coefficient` in `.gremlins.yaml` widens the window to reduce
  this; the CI run on a dedicated runner is the reference, and any single
  local number is indicative only.
- **Coverage-guided scope.** Mutants are only placed on covered code, so
  the mutation score is meaningful only where statement coverage is high.
  That is why the coverage gate (zero uncovered statements, both modules)
  comes first: it is the precondition that makes the mutation score mean
  what it claims.
- **Go statement coverage does not cover workflow YAML, shell, or Python
  policy.** Their correctness is established by their own negative tests
  and the release-equivalent rehearsal, not by either number here.

## Sample baseline

Indicative first-run efficacy while the suite was brought to 100%
statement coverage: `internal/buildinfo` 100%, `internal/metadata` ~70%
(the lower figure is dominated by timeout-counted mutants on a loaded
dev machine, per the limitation above). The authoritative, current score
is whatever the latest `mutation` workflow run reports; these are not
pinned numbers.
