#!/usr/bin/env bash
# The screen of dependabot-auto-merge.yml (REQ-DEP-003-AC2): prints flagged=true or flagged=false for the pull request body in PR_BODY, by the is_flagged
# of the dependabot-reviewer.py beside this file. The workflow checks out nothing: it fetches both files from main and runs this one with bash.
set -euo pipefail
cd "$(dirname "$0")"
python3 -I - <<'PY'
import importlib.util, os
spec = importlib.util.spec_from_file_location("reviewer", "dependabot-reviewer.py")
reviewer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reviewer)
print("flagged=" + str(reviewer.is_flagged(os.environ["PR_BODY"])).lower())
PY
