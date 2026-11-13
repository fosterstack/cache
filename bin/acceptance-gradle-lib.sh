# shellcheck shell=bash
# Both acceptance scripts call this before ./gradlew, which runs the wrapper jar: only the reviewed jar may run.
check_wrapper_jar() {
  local policy=.github/policy/gradle-wrapper-jar-sha256.txt
  local jar=bench/gradle-sample/gradle/wrapper/gradle-wrapper.jar
  if [ "$(grep -c '' "$policy")" != 1 ] || [ "$(sed 's/^[0-9a-f]*//' "$policy")" != "  $jar" ] ||
    ! sha256sum -c --status "$policy"; then
    echo "${0##*/}: gradle-wrapper.jar does not match $policy" >&2
    return 1
  fi
}
