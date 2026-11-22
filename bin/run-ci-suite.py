"""Run one tracked suite: the file named SUITE under bin/ or the agent tests folder, by bash, in the repository root."""
import subprocess
import sys

suite = sys.argv[1]
paths = subprocess.run(["git", "ls-files", "--", f"bin/{suite}", f"*/agent/tests/{suite}"],
                       check=True, capture_output=True, text=True).stdout.split("\n")[:-1]
if not paths:
    sys.exit(f"no tracked suite named {suite}")
for path in paths:
    if subprocess.run(["bash", path]).returncode:
        sys.exit(f"the suite {path} failed")
