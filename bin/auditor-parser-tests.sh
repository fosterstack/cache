#!/usr/bin/env bash
# Parser unit tests (real fixtures + malformed variants). Run on demand.
set -euo pipefail
cd "$(dirname "$0")/.."
exec python3 -m unittest discover -s .github/agent/bin/tests -p 'test_*.py' -v
