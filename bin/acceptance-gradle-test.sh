#!/usr/bin/env bash
# The cold build of bin/acceptance-gradle.sh (step_06) must fail the step when gradle fails: the `|| true` belongs to the grep that
# filters the output, not to the build. The step is read from the committed script, never copied here; gradlew is a mock.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
sut="$here/acceptance-gradle.sh"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bench/gradle-sample"
step=$(awk '/^step_06\(\) \($/ {on=1} on {print} on && /^\)$/ {exit}' "$sut")
pass=0; fail=0
# gradlew <mode>: ok prints task lines, quiet prints nothing the grep matches, fail prints a task line and exits 1
mock() {
  printf '#!/usr/bin/env bash\ncase "%s" in\n  ok) echo "> Task :compileJava"; echo "BUILD SUCCESSFUL" ;;\n  quiet) echo "some other line" ;;\n  fail) echo "> Task :compileJava FAILED"; echo "BUILD FAILED"; exit 1 ;;\nesac\n' "$1" > "$work/bench/gradle-sample/gradlew"
  chmod +x "$work/bench/gradle-sample/gradlew"
}
check() { # name, mode, want_rc (zero|nonzero)
  local rc
  mock "$2"
  ( cd "$work" && set -eo pipefail && eval "$step" && step_06 ) >/dev/null 2>&1; rc=$?
  if { [ "$3" = zero ] && [ "$rc" -eq 0 ]; } || { [ "$3" = nonzero ] && [ "$rc" -ne 0 ]; }; then echo "ok: $1"; pass=$((pass+1)); else echo "FAIL: $1 (rc=$rc, wanted $3)"; fail=$((fail+1)); fi
}
[ -n "$step" ] || { echo "FAIL: step_06 not found in acceptance-gradle.sh"; exit 1; }
check "a failing cold build fails the step" fail nonzero
check "a build whose output the grep finds nothing in still passes" quiet zero
check "a passing cold build passes the step" ok zero
# the whole script: the wrapper-jar preamble passes on a fixture, then the failing build stops the suite
mkdir -p "$work/.github/policy" "$work/bench/gradle-sample/gradle/wrapper"
printf 'jar' > "$work/bench/gradle-sample/gradle/wrapper/gradle-wrapper.jar"
printf '%s  bench/gradle-sample/gradle/wrapper/gradle-wrapper.jar\n' "$(printf 'jar' | sha256sum | cut -d' ' -f1)" > "$work/.github/policy/gradle-wrapper-jar-sha256.txt"
mock fail
out=$(cd "$work" && bash "$sut" 2>&1); rc=$?
if [ "$rc" -ne 0 ] && ! grep -q 'does not match' <<<"$out" && ! grep -q 'stored:' <<<"$out"; then echo "ok: the whole suite stops at the failed cold build"; pass=$((pass+1)); else echo "FAIL: the whole suite stops at the failed cold build (rc=$rc)"; fail=$((fail+1)); fi
# REQ-SUP-001-AC32: the jar is checked against the policy file before any gradlew runs
msg='gradle-wrapper.jar does not match .github/policy/gradle-wrapper-jar-sha256.txt'
jar_path=bench/gradle-sample/gradle/wrapper/gradle-wrapper.jar
jar_hash=$(printf 'jar' | sha256sum | cut -d' ' -f1)
fixture() { # folder: the jar, the policy folder and a gradlew that leaves a marker file when it runs
  mkdir -p "$1/.github/policy" "$1/bench/gradle-sample/gradle/wrapper"
  printf 'jar' > "$1/$jar_path"
  printf '#!/usr/bin/env bash\ntouch "$(dirname "$0")/gradlew-ran"\n' > "$1/bench/gradle-sample/gradlew"
  chmod +x "$1/bench/gradle-sample/gradlew"
}
nl=$'\n'
zeros=$(head -c 64 /dev/zero | tr '\0' 0)
policy_case() { # script, name, policy file content as plain data (-, no file), want (refuse|accept)
  local dir="$work/policy-$((++cases))" out rc ok=1
  fixture "$dir"
  [ "$3" = - ] || printf '%s' "$3" > "$dir/.github/policy/gradle-wrapper-jar-sha256.txt"
  out=$(cd "$dir" && bash "$here/$1" 2>&1 >/dev/null); rc=$?
  if [ "$4" = refuse ]; then
    [ "$rc" -eq 1 ] || ok=0
    grep -qF "$msg" <<<"$out" || ok=0
    [ ! -e "$dir/bench/gradle-sample/gradlew-ran" ] || ok=0
  else
    ! grep -qF "$msg" <<<"$out" || ok=0
    [ -e "$dir/bench/gradle-sample/gradlew-ran" ] || ok=0
  fi
  if [ "$ok" -eq 1 ]; then echo "ok: $1: $2"; pass=$((pass+1)); else echo "FAIL: $1: $2 (rc=$rc)"; fail=$((fail+1)); fi
}
cases=0
for script in acceptance-gradle.sh acceptance-gradle-capped.sh; do
  policy_case "$script" "a policy hash that is not the jar's hash is refused" "$zeros  $jar_path$nl" refuse
  policy_case "$script" "a second line in the policy file is refused" \
    "$jar_hash  $jar_path$nl$jar_hash  $jar_path$nl" refuse
  policy_case "$script" "a policy line naming another path is refused" \
    "$jar_hash  bench/other/gradle-wrapper.jar$nl" refuse
  policy_case "$script" "an empty policy file is refused" "" refuse
  policy_case "$script" "a missing policy file is refused" - refuse
done
policy_case acceptance-gradle.sh "the correct line without a trailing newline is accepted" "$jar_hash  $jar_path" accept
echo "acceptance-gradle: $pass passed, $fail failed"; [ "$fail" -eq 0 ]
