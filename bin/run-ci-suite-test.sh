#!/usr/bin/env bash
# Tests for bin/run-ci-suite.py (self-contained: needs only bash, git and python3). Proves:
#  - SUITE runs the tracked bin/SUITE and agent/tests/SUITE with bash in the repository root;
#  - the runner exits 0 only if every run exited 0, and names the file of a failing run;
#  - a name with no tracked file fails saying no tracked suite has that name, and an untracked file is not run.
# It prints "run-ci-suite: N passed, M failed" and exits non-zero if any case fails.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
runner="$root/bin/run-ci-suite.py"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0; failn=0
ok()  { pass=$((pass + 1)); echo "ok   $1"; }
bad() { failn=$((failn + 1)); echo "FAIL $1"; }
[ -s "$runner" ] || { echo "FAIL bin/run-ci-suite.py is missing or empty"; echo "run-ci-suite: 0 passed, 1 failed"; exit 1; }

# newrepo NAME : a throwaway git repository holding a copy of the runner; prints its path
newrepo() { local r="$work/$1"; mkdir -p "$r/bin"; cp "$runner" "$r/bin/run-ci-suite.py"
  git -C "$r" init -q .; echo "$r"; }
commit() { git -C "$1" add -A; git -C "$1" -c user.name=t -c user.email=t@x -c commit.gpgsign=false commit -qm c; }
# run REPO SUITE : sets rc and out from the runner started in REPO
run() { rc=0; out=$(cd "$1" && python3 -I bin/run-ci-suite.py "$2" 2>&1 < /dev/null) || rc=$?; }

# 1: a tracked passing suite runs and exits 0
r=$(newrepo c1); printf '#!/usr/bin/env bash\ntouch ran-marker\n' > "$r/bin/ok-test.sh"; commit "$r"
run "$r" ok-test.sh
if [ "$rc" = 0 ] && [ -f "$r/ran-marker" ]; then ok "tracked passing suite: exit 0 and the script ran"; else bad "tracked passing suite -> rc=$rc: ${out:0:160}"; fi

# 2: a tracked failing suite fails and its file is named
r=$(newrepo c2); printf '#!/usr/bin/env bash\nexit 3\n' > "$r/bin/bad-test.sh"; commit "$r"
run "$r" bad-test.sh
if [ "$rc" != 0 ] && grep -Fq 'bad-test.sh' <<< "$out"; then ok "tracked failing suite: non-zero and the file is named"; else bad "tracked failing suite -> rc=$rc: ${out:0:160}"; fi

# 3: a name with no file fails saying no tracked suite has that name
r=$(newrepo c3); echo x > "$r/bin/other.sh"; commit "$r"
run "$r" nothing-test.sh
if [ "$rc" != 0 ] && grep -Fqi 'no tracked suite' <<< "$out"; then ok "unknown name: non-zero and says no tracked suite"; else bad "unknown name -> rc=$rc: ${out:0:160}"; fi

# 4: an untracked file of that name is not run
r=$(newrepo c4); echo x > "$r/bin/other.sh"; commit "$r"
printf '#!/usr/bin/env bash\ntouch untracked-marker\n' > "$r/bin/untracked-test.sh"
run "$r" untracked-test.sh
if [ "$rc" != 0 ] && [ ! -e "$r/untracked-marker" ]; then ok "untracked file: non-zero and not run"; else bad "untracked file -> rc=$rc, marker present? $([ -e "$r/untracked-marker" ] && echo yes || echo no)"; fi

# 5: a suite under the agent tests folder is found and run (the path is spelled in two parts so no file outside it names it, REQ-AUD-18 AC1)
agent=agent/tests
r=$(newrepo c5); mkdir -p "$r/.github/$agent"
printf '#!/usr/bin/env bash\ntouch agent-marker\n' > "$r/.github/$agent/agent-test.sh"; commit "$r"
run "$r" agent-test.sh
if [ "$rc" = 0 ] && [ -f "$r/agent-marker" ]; then ok "agent tests suite: found and run"; else bad "agent tests suite -> rc=$rc: ${out:0:160}"; fi

# 6: the script runs with the repository root as its working directory
r=$(newrepo c6); printf '#!/usr/bin/env bash\npwd > cwd-file\n' > "$r/bin/cwd-test.sh"; commit "$r"
run "$r" cwd-test.sh
if [ "$rc" = 0 ] && [ -f "$r/cwd-file" ] && [ "$(cd "$(cat "$r/cwd-file")" && pwd -P)" = "$(cd "$r" && pwd -P)" ]; then ok "script runs in the repository root"; else bad "working directory -> rc=$rc, got '$(cat "$r/cwd-file" 2>/dev/null)'"; fi

echo "run-ci-suite: $pass passed, $failn failed"
[ "$failn" = 0 ]
