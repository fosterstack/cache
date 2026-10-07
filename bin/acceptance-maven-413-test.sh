#!/usr/bin/env bash
# proves: REQ-EVICT-002-AC4
# The Maven capped scenario recognises the server's 413 in the build log whichever way the runner's Maven resolver words it:
# older images log "HttpResponseException: status code: 413, reason phrase: Request Entity Too Large (413)", newer ones
# "HttpTransporterException: HTTP Status: 413" (runner image 20261002 vs 20260901; the acceptance-maven job failed on the newer
# wording, alternating with passes as images rolled). The pattern is read from the committed workflow, never copied here.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
wf="$here/../.github/workflows/acceptance.yml"
pat=$(python3 - "$wf" <<'PYX'
import re, sys
t = open(sys.argv[1]).read()
m = re.search(r"grep -Eq '([^']*413[^']*)' /tmp/mvn-capped-a\.log", t)
print(m.group(1) if m else "")
PYX
)
pass=0; fail=0
check() { # name, want (match|nomatch), text
  if [ -z "$pat" ]; then echo "FAIL: $1 (no 413 pattern found in the workflow)"; fail=$((fail+1)); return; fi
  if printf '%s\n' "$3" | grep -Eq "$pat"; then got=match; else got=nomatch; fi
  if [ "$got" = "$2" ]; then echo "ok: $1"; pass=$((pass+1)); else echo "FAIL: $1 (wanted $2)"; fail=$((fail+1)); fi
}
check "older resolver wording" match "org.apache.http.client.HttpResponseException: status code: 413, reason phrase: Request Entity Too Large (413)"
check "newer resolver wording" match "org.eclipse.aether.spi.connector.transport.http.HttpTransporterException: HTTP Status: 413"
check "reason phrase alone" match "Request Entity Too Large"
check "a 404 is not a 413" nomatch "org.eclipse.aether.spi.connector.transport.http.HttpTransporterException: HTTP Status: 404"
check "a 401 is not a 413" nomatch "org.apache.http.client.HttpResponseException: status code: 401, reason phrase: Unauthorized (401)"
check "a bare number is not a 413" nomatch "Saved to remote cache http://localhost:18099/maven/v1.1/com.fosterstack.bench/app/4132a/app.jar"
echo "acceptance-maven-413: $pass passed, $fail failed"; [ "$fail" -eq 0 ]
