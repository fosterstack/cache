#!/usr/bin/env bash
# The cold build of bin/acceptance-gradle.sh (step_06) must fail the step when gradle fails: the `|| true` belongs to
# the grep that filters the output, not to the build. The step is read from the committed script, never copied here;
# gradlew is a mock.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
sut="$here/acceptance-gradle.sh"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bench/gradle-sample"
step=$(awk '/^step_06\(\) \($/ {on=1} on {print} on && /^\)$/ {exit}' "$sut")
pass=0; fail=0
# gradlew <mode>: ok prints task lines, quiet prints nothing the grep matches, fail prints a task line and exits 1
mock() {
  printf '#!/usr/bin/env bash\ncase "%s" in\n  ok) echo "> Task :compileJava"; echo "BUILD SUCCESSFUL" ;;\n  quiet) echo "some other line" ;;\n  fail) echo "> Task :compileJava FAILED"; echo "BUILD FAILED"; exit 1 ;;\nesac\n' \
    "$1" > "$work/bench/gradle-sample/gradlew"
  chmod +x "$work/bench/gradle-sample/gradlew"
}
check() { # name, mode, want_rc (zero|nonzero)
  local rc
  mock "$2"
  ( cd "$work" && set -eo pipefail && eval "$step" && step_06 ) >/dev/null 2>&1; rc=$?
  if { [ "$3" = zero ] && [ "$rc" -eq 0 ]; } || { [ "$3" = nonzero ] && [ "$rc" -ne 0 ]; }; then
    echo "ok: $1"; pass=$((pass+1))
  else echo "FAIL: $1 (rc=$rc, wanted $3)"; fail=$((fail+1)); fi
}
[ -n "$step" ] || { echo "FAIL: step_06 not found in acceptance-gradle.sh"; exit 1; }
check "a failing cold build fails the step" fail nonzero
check "a build whose output the grep finds nothing in still passes" quiet zero
check "a passing cold build passes the step" ok zero
# the whole script: the wrapper-jar preamble passes on a fixture, then the failing build stops the suite
mkdir -p "$work/.github/policy" "$work/bench/gradle-sample/gradle/wrapper"
printf 'jar' > "$work/bench/gradle-sample/gradle/wrapper/gradle-wrapper.jar"
printf '%s  bench/gradle-sample/gradle/wrapper/gradle-wrapper.jar\n' "$(printf 'jar' | sha256sum | cut -d' ' -f1)" \
  > "$work/.github/policy/gradle-wrapper-jar-sha256.txt"
mock fail
out=$(cd "$work" && bash "$sut" 2>&1); rc=$?
if [ "$rc" -ne 0 ] && ! grep -q 'does not match' <<<"$out" && ! grep -q 'stored:' <<<"$out"; then
  echo "ok: the whole suite stops at the failed cold build"; pass=$((pass+1))
else echo "FAIL: the whole suite stops at the failed cold build (rc=$rc)"; fail=$((fail+1)); fi
echo "acceptance-gradle: $pass passed, $fail failed"; [ "$fail" -eq 0 ]
