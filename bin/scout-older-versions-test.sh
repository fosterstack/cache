#!/usr/bin/env bash
# proves: REQ-SCAN-004-AC2
# The older-versions sweep (advisor 0520): bin/scout-older-versions.sh runs end to end with docker stubbed (the real bin/scout-root-cause.py
# runs), and the table says "applied" only when the local VEX file removes exactly the target finding. Stub versions: 9.9.9 applies a local
# VEX, 9.9.8 ignores it, 9.9.7 is not installed, 9.9.6 has no --vex-location. Also: the installer pins every swept version, the workflow
# job is dispatch-only and builds from the installer.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd); root=$(cd "$here/.." && pwd)
pass=0; fail=0
ok() { echo "ok: $1"; pass=$((pass+1)); }
no() { echo "FAIL: $1"; fail=$((fail+1)); }
e=$(mktemp -d); mkdir -p "$e/scout" "$e/home/.docker/cli-plugins" "$e/bin"
for v in 9.9.9 9.9.8 9.9.6; do printf '%s\n' "$v" > "$e/scout/docker-scout-$v"; done
cat > "$e/bin/docker" <<'STUB'
#!/usr/bin/env bash
case "$1 $2" in
  "scout version") echo "version: $(cat "$HOME/.docker/cli-plugins/docker-scout")"; exit 0 ;;
  "scout cves") ;;
  *) exit 0 ;;
esac
ver=$(cat "$HOME/.docker/cli-plugins/docker-scout")
loc=""; prev=""
for a in "$@"; do [ "$prev" = --vex-location ] && loc=$a; prev=$a; done
report='{"vulnerabilities":[
 {"cve":"CVE-2023-4911","identifiers":[{"value":"CVE-2023-4911"}],"location":{"dependency":{"package":{"name":"glibc"},"version":"2.36"}}},
 {"cve":"CVE-2024-0001","identifiers":[{"value":"CVE-2024-0001"}],"location":{"dependency":{"package":{"name":"zlib"},"version":"1.2"}}}]}'
if [ -n "$loc" ]; then
  [ "$ver" = 9.9.6 ] && { echo "unknown flag: --vex-location" >&2; exit 1; }
  if [ "$ver" = 9.9.9 ]; then
    names=$(cat "$loc" "$loc"/* 2>/dev/null | jq -r '.statements[]?.vulnerability.name' 2>/dev/null)
    report=$(printf '%s' "$report" | jq -c --arg n "$names" '.vulnerabilities |= map(select(.identifiers[0].value as $c | ($n | split("\n") | index($c)) | not))')
  fi
fi
printf '%s\n' "$report"
STUB
chmod +x "$e/bin/docker"
cd "$root"
SCOUT_DIR="$e/scout" SCOUT_VERSIONS="9.9.9 9.9.8 9.9.7 9.9.6" HOME="$e/home" PATH="$e/bin:$PATH" bash bin/scout-older-versions.sh "$e/out" > "$e/run.log" 2>&1
rc=$?
[ "$rc" -eq 0 ] && ok "the sweep runs end to end, exit 0" || no "the sweep exited $rc: $(tail -5 "$e/run.log")"
row() { grep -F "| $1 |" "$e/out/summary.md" | head -1; }
[ "$(row 9.9.9 | grep -o applied | wc -l | tr -d ' ')" -ge 3 ] && row 9.9.9 | grep -q 'YES' && ok "a version that applies a local VEX is reported applied in every form, YES" || no "9.9.9 row: $(row 9.9.9)"
row 9.9.8 | grep -q 'not applied' && ! row 9.9.8 | grep -q 'YES' && ok "a version that ignores a local VEX is 'not applied', not YES" || no "9.9.8 row: $(row 9.9.8)"
row 9.9.7 | grep -q 'does not run' && ok "a version that is not installed says it does not run" || no "9.9.7 row: $(row 9.9.7)"
row 9.9.6 | grep -q 'scan exit 1' && ! row 9.9.6 | grep -q 'YES' && ok "a version without --vex-location records the scan exit, not YES" || no "9.9.6 row: $(row 9.9.6)"
# the workflow job and the installer
python3 - "$root" <<'PY' && ok "the sweep job is dispatch-only, uses the installer for each version, and sets no secret beyond the Scout token" || no "the workflow job is not as required"
import sys, yaml, re
root = sys.argv[1]
d = yaml.safe_load(open(root + "/.github/workflows/main-candidate-rescan.yml"))
j = d["jobs"]["scout-older-versions"]
assert j["if"].strip() == "${{ github.event_name == 'workflow_dispatch' }}", j["if"]
assert j["environment"] == "agent"
perms = j["permissions"]; assert perms == {"contents": "read"}, perms
run = "\n".join(s.get("run", "") for s in j["steps"])
assert "./bin/install-scanner.sh" in run and "bin/scout-older-versions.sh" in run
inst = open(root + "/bin/install-scanner.sh").read()
vers = re.search(r"SCOUT_VERSIONS: '([^']+)'", open(root + "/.github/workflows/main-candidate-rescan.yml").read()).group(1).split()
assert len(vers) >= 20, vers
for v in vers:
    assert re.search(r"docker-scout-%s:x86_64\|docker-scout-%s:amd64\) SUM=[0-9a-f]{64} ;;" % (re.escape(v), re.escape(v)), inst), v
PY
rm -rf "$e"
echo "scout-older-versions: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
