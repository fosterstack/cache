#!/usr/bin/env bash
# The release workflow's patch-notes step commits through the API (signed) by running the REVIEWED helper: the literal path of the
# program it runs is exactly .github/agent/bin/auditor-signed-commit.py, that file is the committed CLI over the signed-commit helper, and
# no other program is run in its place. (bin/release-patch-wiring-test.sh pins the step's shape but, under the layout rule REQ-AUD-18 AC1,
# cannot name this directory; this agent-owned test does.) The real workflow must pass; each mutated copy must be caught.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
mkdir -p "$work/pylib"; ln -s "$here/../fixtures/testlib/pyyaml" "$work/pylib/yaml"
export PYTHONPATH="$work/pylib${PYTHONPATH:+:$PYTHONPATH}"
pass=0 failn=0
judge() { ROOT="$root" python3 - "$1" <<'PY'
import os, re, subprocess, sys, yaml
root = os.environ.get("CLIROOT") or os.environ["ROOT"]      # CLIROOT: a tree whose CLI file is judged instead of the real one
CLI = ".github/agent/bin/auditor-signed-commit.py"
d = yaml.load(open(sys.argv[1]), Loader=yaml.BaseLoader)
bad = []
steps = ((d.get("jobs") or {}).get("patch-notes") or {}).get("steps") or []
progs = []
for st in steps:
    for ln in (st.get("run") or "").splitlines():
        if not ln.lstrip().startswith("#"):
            progs += re.findall(r"\bpython3?\s+(\S+)", ln)      # every `python3 <program>` the job runs
if sorted(progs) != sorted(["bin/patch-decide.py", "bin/patch-decide.py", CLI]):
    bad.append("the patch-notes job runs python programs other than patch-decide.py (twice) and exactly %s: %s" % (CLI, progs))
text = "\n".join(st.get("run") or "" for st in steps)
if len(re.findall(r'^\s*python3 ' + re.escape(CLI) + r' --repo "\$GITHUB_REPOSITORY" --branch "\$branch"', text, re.M)) != 1:
    bad.append("the signed-commit call does not run exactly the literal path %s" % CLI)
full = os.path.join(root, CLI)
if not os.path.isfile(full):
    bad.append("%s is not a file" % CLI)
else:
    src = open(full).read()
    if "signed_commit.commit_via_api(" not in src or "signed_commit.read_changes(" not in src or "from auditorlib import signed_commit" not in src:
        bad.append("%s is not the CLI over the signed-commit helper" % CLI)
    tracked = subprocess.run(["git", "-C", root, "ls-files", "--error-unmatch", CLI], capture_output=True)
    inrepo = subprocess.run(["git", "-C", root, "rev-parse", "--git-dir"], capture_output=True).returncode == 0   # a worktree's .git is a file
    if tracked.returncode != 0 and inrepo:
        bad.append("%s is not a committed file" % CLI)
print("; ".join(bad) or "ok")
sys.exit(1 if bad else 0)
PY
}
case_() {
  local f="$work/$1.yml"; cp "$root/.github/workflows/release.yml" "$f"
  if [ -n "$3" ]; then MO="$3" MN="$4" python3 - "$f" <<'PY'
import os, sys
p = sys.argv[1]; t = open(p).read()
assert os.environ["MO"] in t, "mutation does not apply"
open(p, "w").write(t.replace(os.environ["MO"], os.environ["MN"]))
PY
  fi
  if out=$(judge "$f"); then got=ok; else got=bad; fi
  if [ "$got" = "$2" ]; then pass=$((pass+1)); echo "PASS $1 → $got ($out)"
  else failn=$((failn+1)); echo "FAIL $1 → $got, want $2 ($out)"; fi
}
C=.github/agent/bin/auditor-signed-commit.py
case_ real                 ok  "" ""
case_ other-script         bad "python3 $C" "python3 bin/auditor-signed-commit.py"
case_ dot-slash-path       bad "python3 $C" "python3 ./$C"
case_ other-name           bad "python3 $C" "python3 .github/agent/bin/auditor-signed-commit2.py"
case_ other-dir            bad "python3 $C" "python3 .github/agent/fixtures/auditor-signed-commit.py"
case_ absolute-path        bad "python3 $C" "python3 /tmp/auditor-signed-commit.py"
case_ extra-program        bad "python3 $C" "python3 bin/evil.py; python3 $C"
case_ variable-path        bad "python3 $C" "python3 \$CLI_PATH #"
# the committed CLI itself: a tree whose CLI is empty, missing or another program must fail (the workflow text is the real one)
for name in empty missing other; do
  fake="$work/fake-$name"; mkdir -p "$fake/.github/agent/bin"
  case $name in empty) : > "$fake/$C" ;; other) printf 'print(1)\n' > "$fake/$C" ;; esac
  if out=$(CLIROOT="$fake" judge "$root/.github/workflows/release.yml"); then failn=$((failn+1)); echo "FAIL cli-$name → ok, want bad"
  else pass=$((pass+1)); echo "PASS cli-$name → bad (${out:0:80})"; fi
done
echo "release-notes-signed: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
