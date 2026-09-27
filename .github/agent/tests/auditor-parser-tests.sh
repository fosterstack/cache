#!/usr/bin/env bash
# Parser unit tests (real fixtures + malformed variants). CI: hygiene.yml, required 'allowlist' job.
set -euo pipefail
cd "$(dirname "$0")/../../.."
exec python3 -m unittest discover -s .github/agent/bin/tests -p 'test_*.py' -v
