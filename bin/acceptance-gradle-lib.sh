# shellcheck shell=bash
# bin/acceptance-gradle-lib.sh: the check both Gradle acceptance scripts make before they run the sample's ./gradlew.
# The wrapper jar is the reviewed one (REQ-SUP-001-AC32) when the policy file is one line naming the jar and it matches.
check_wrapper_jar() {
  local policy=.github/policy/gradle-wrapper-jar-sha256.txt
  local jar=bench/gradle-sample/gradle/wrapper/gradle-wrapper.jar
  if [ "$(grep -c '' "$policy")" != 1 ] || [ "$(sed 's/^[0-9a-f]*//' "$policy")" != "  $jar" ] ||
    ! sha256sum -c --status "$policy"; then
    echo "${0##*/}: gradle-wrapper.jar does not match $policy" >&2
    return 1
  fi
}
