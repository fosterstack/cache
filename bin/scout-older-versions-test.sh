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
  "image inspect") echo sha256:fixtureid; exit 0 ;;
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
[ "$(row 9.9.9)" = "| 9.9.9 | applied | applied | applied | applied | YES |" ] && ok "a version that applies a local VEX has all four cells applied, YES" || no "9.9.9 row: $(row 9.9.9)"
[ "$(row 9.9.8)" = "| 9.9.8 | not applied | not applied | not applied | not applied | no |" ] && ok "a version that ignores a local VEX is 'not applied', not YES" || no "9.9.8 row: $(row 9.9.8)"
row 9.9.7 | grep -q 'does not run' && ok "a version that is not installed says it does not run" || no "9.9.7 row: $(row 9.9.7)"
row 9.9.6 | grep -q 'scan exit 1' && ! row 9.9.6 | grep -q 'YES' && ok "a version without --vex-location records the scan exit, not YES" || no "9.9.6 row: $(row 9.9.6)"
# a fixture that cannot be pulled stops the sweep (exit 2) before any scan: no registry fallback for a mutable tag
cat > "$e/bin/docker.bad" <<'STUB'
#!/usr/bin/env bash
[ "$1" = pull ] && exit 1
[ "$1 $2" = "image inspect" ] && exit 1
echo "$*" >> "$LOGF"; exit 0
STUB
mkdir -p "$e/badbin"; cp "$e/bin/docker.bad" "$e/badbin/docker"; chmod +x "$e/badbin/docker"
LOGF="$e/bad.log" SCOUT_DIR="$e/scout" SCOUT_VERSIONS="9.9.9" HOME="$e/home" PATH="$e/badbin:$PATH" bash bin/scout-older-versions.sh "$e/out2" > "$e/bad.out" 2>&1
[ "$?" -eq 2 ] && ! grep -q 'scout cves' "$e/bad.log" 2>/dev/null && ok "a fixture that cannot be pulled exits 2 before any scan" || no "setup failure: $(tail -2 "$e/bad.out")"
# stale tags from an earlier run (removal fails, pull fails) do not stand in for the fixture: both tags must carry the pinned fixture's image id
mkdir -p "$e/stalebin"
cat > "$e/stalebin/docker" <<'STUB'
#!/usr/bin/env bash
case "$1" in
  pull) exit 1 ;;
  rmi) exit 1 ;;
  image) for a in "$@"; do case "$a" in docker.io/library/debian@*) echo sha256:fixtureid; exit 0 ;; esac; done; echo sha256:staleid; exit 0 ;;
  scout) echo "$*" >> "$LOGF"; exit 0 ;;
  *) exit 0 ;;
esac
STUB
chmod +x "$e/stalebin/docker"
LOGF="$e/stale.log" SCOUT_DIR="$e/scout" SCOUT_VERSIONS="9.9.9" HOME="$e/home" PATH="$e/stalebin:$PATH" bash bin/scout-older-versions.sh "$e/out3" > "$e/stale.out" 2>&1
[ "$?" -eq 2 ] && ! grep -q 'scout cves' "$e/stale.log" 2>/dev/null && ok "surviving stale tags (rmi and pull both fail) are refused by image id: exit 2, no scan" || no "stale tags: $(tail -2 "$e/stale.out")"
grep -q 'local://' bin/scout-older-versions.sh && ! grep -E 'scout cves[^"]*"\$(CONTROL|OURS)"' bin/scout-older-versions.sh >/dev/null && ok "the tag-based cases scan the local store (local://)" || no "a tag-based scan is not local://"
# the installer really dispatches every swept name (past the allowlist and the checksum table; it stops at the download, which has no server)
python3 - "$root" <<'PY' > "$e/vers.txt"
import re, sys
print(re.search(r"SCOUT_VERSIONS: '([^']+)'", open(sys.argv[1] + "/.github/workflows/main-candidate-rescan.yml").read()).group(1))
PY
bad=""
for v in $(cat "$e/vers.txt"); do
  m=$(INSTALL_SCANNER_ARCH=amd64 SCOUT_BASE_URL=file:///nonexistent bash bin/install-scanner.sh "docker-scout-$v" "$e/dest" 2>&1 || true)
  case "$m" in *"unknown scanner"*|*"no pinned checksum"*|"") bad="$bad $v";; esac
done
[ -z "$bad" ] && ok "the installer dispatches all $(wc -w < "$e/vers.txt" | tr -d ' ') swept names (allowlist and checksum table)" || no "installer refuses:$bad"
m=$(INSTALL_SCANNER_ARCH=amd64 SCOUT_BASE_URL=file:///nonexistent bash bin/install-scanner.sh docker-scout-0.0.1 "$e/dest" 2>&1 || true)
case "$m" in *"unknown scanner"*) ok "an unswept version still fails closed";; *) no "docker-scout-0.0.1: $m";; esac
# the workflow block: the job's secrets are exactly the two Docker Hub ones, no packages permission, no GHCR login
python3 - "$root" <<'PY' && ok "the sweep job references exactly the two Docker Hub secrets and no packages or GHCR access" || no "the job's secrets or permissions differ"
import sys, yaml, re, json
d = yaml.safe_load(open(sys.argv[1] + "/.github/workflows/main-candidate-rescan.yml"))
t = json.dumps(d["jobs"]["scout-older-versions"])
assert sorted(set(re.findall(r"secrets\.[A-Z0-9_]+", t))) == ["secrets.DOCKERHUB_SCOUT_TOKEN", "secrets.DOCKERHUB_USERNAME"], re.findall(r"secrets\.[A-Z0-9_]+", t)
assert "packages" not in t and "ghcr.io" not in t and "id-token" not in t
PY
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
