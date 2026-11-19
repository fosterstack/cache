# Mutation testing

Statement coverage says the tests *ran* the code. It does not say the
tests would *notice* the code being wrong. Mutation testing closes that
gap: it makes small changes to the code ("mutants" — negate a condition,
shift a boundary) and re-runs the tests against each one. A mutant the
tests still pass is a spot where they would not catch a real defect.

## What runs now

The Go code is not mutation tested. Its gate is statement coverage: the
tests must run every statement, in both Go modules, on every pull request.

Some of our checks are tested with mutants. Each check's own test makes
deliberately broken copies of the check and requires the test to fail on
every one. A check whose test passes a broken copy is itself broken.

Go statement coverage does not cover workflow YAML, shell, or Python
policy. Their correctness is established by their own negative tests and
the release-equivalent rehearsal.
