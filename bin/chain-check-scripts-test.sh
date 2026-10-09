#!/usr/bin/env bash
# proves: REQ-CHAIN-006-AC4, REQ-CHAIN-006-AC5 (interface only, see the gap below), REQ-CHAIN-006-AC6, REQ-CHAIN-006-AC7, REQ-CHAIN-006-AC11, REQ-CHAIN-006-AC12
# RED until PR 3 is implemented (bin/check-scan.sh, bin/check-fips.sh, bin/check-acceptance.sh, bin/check-guide.sh, bin/check-stage.sh and PR 2's
# bin/witnessed.sh do not exist): step 4.
#
# The behaviour of the Check scripts (v0.3.0 rules 55, 66, 72, 79; advisor read-back approved Oct 9). Each script is run in a throw-away tree
# with FAKE tools first on PATH (fake grype / osv-scanner / docker / curl, in the way PR 1's tests put a fake cosign on PATH: no test-only code
# path in the production script). No network, no Docker, no secrets, no keys. Needs bash, jq, python3.
#
# THE INTERFACE THIS ASSUMES. Fixed by an existing file [F]; everything else is PROPOSED/UNVERIFIED [P] and may change in the implementation PR:
#   [F] .github/policy/scanners.json {"scanners":[...]}; REQ-REL-004-AC1 (each scanner reports its package count; zero packages fail);
#       /statusz JSON fields "fips140" (bool) and "fips140_note" (string) and the note texts of internal/buildinfo/buildinfo.go:85-97;
#       the digest list's names image-production / image-fips (PR 1 schema); the images are OCI tarballs images/<variant>.tar (cache's
#       assemble-image.sh output, variant = production|fips).
#   [P] bin/check-scan.sh --scanners F --digests D --images DIR --archives DIR --out DIR
#         for each listed scanner S (tool S on PATH): `S ... <tarball>` for each variant, grype also over DIR/archives/*.tar.gz; the tool prints
#         a line `packages: N` (UNVERIFIED how real grype / osv-scanner give the count; the implementation PR decides) and exits 0 (clean),
#         1 (findings not excepted by the VEX document) or other (could not run). Writes OUT/scan-results.json
#         {"listed":N,"ran":N,"scanners":[{"name","version","verdict","subjects":[{"name","digest","packages","verdict"}]}]}.
#         Exit 0 only when ran == listed > 0, every scanner clean with packages > 0 on every subject; otherwise exit 1 with a message naming
#         the scanner. No unlisted scanner runs.
#   [P] bin/check-fips.sh --digests D --images DIR --out DIR: for each variant `docker load -i`, `docker run -d`, `docker port NAME 8080/tcp`,
#         `curl` http://127.0.0.1:PORT/statusz, `docker rm -f NAME` (always, also on failure). Requires fips: fips140 true and a note that starts
#         "active (Go validated module v1.0.0"; production: fips140 false. Exit 1 naming the image otherwise. Writes OUT/fips-result.json with the
#         observed booleans and module text; the certificate number is NOT parsed or reported by the script (it is a documented mapping).
#   [P] bin/check-guide.sh --guide FILE --digests D --images DIR --out DIR: the commands are the ```sh check fenced blocks of the guide; each block
#         is one command, optionally followed by `# expect: REGEX` (output must match) and `# exit: N` (default 0); at least 1 and at most 10;
#         env CANDIDATE_PRODUCTION / CANDIDATE_FIPS carry the digests. Writes OUT/guide-results.json (command, exit, outcome per command).
#   [P] bin/check-acceptance.sh gradle|maven|egress --digests D --images DIR --out DIR: wraps the EXISTING suites (acceptance.yml's gradle and
#         maven jobs, stage-acceptance-egress.yml's trace) unchanged. THE GAP, stated plainly: what those suites need (Docker, Gradle, a running
#         server) cannot be faked here without re-implementing them, so only the interface (unknown kind, missing images) is tested below; that a
#         failing suite fails the script and that a suite which ran no test fails it (REQ-CHAIN-006-AC5) is proven by the implementation PR's
#         dry run on GitHub, and by the review brief which asks the reviewers to read those suites.
#   [P] bin/check-stage.sh PHASE (scanners|acceptance|runtime): verifies Build's record and Sign's provenance FIRST (every phase), then runs only
#         that phase's checks in the order of bin/chain-check-shape.py PHASES; an unknown phase exits 2 naming it; a failed verify runs no check.
#   [P] bin/witnessed.sh STEP SCRIPT [ARGS] (PR 2's helper; the rule 68 cap, as amended by the owner Oct 9): fetches the identity token, runs
#         `witness run --step STEP ... -o witness-records/STEP.json -- timeout 540 bash SCRIPT ARGS`. Fake curl / witness / timeout on PATH below.
#         WHAT IS NOT FIXED: what real `witness run` does with a command that exits non-zero (here: no record is written; the dry run decides) and
#         that a real 9-minute overrun is killed by `timeout` (here a fake timeout that reports expiry as GNU timeout does, exit 124).
# SATISFIABLE: the 40 cases were run against a throw-away reference implementation (not committed) and all pass, so no case is unsatisfiable.
# Modelled on: in-toto-witness docs/tutorials/artifact-policy.md:58-70 (what a product holds), PR 1's fake-cosign approach, the existing
# stage-verify.yml (what a scanner leg does today).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
command -v jq > /dev/null || { echo "FAIL jq is required"; exit 1; }
ok()  { pass=$((pass + 1)); echo "ok   $1"; }
bad() { failn=$((failn + 1)); echo "FAIL $1"; }
D1="sha256:$(printf 'a%.0s' $(seq 64))"; D2="sha256:$(printf 'b%.0s' $(seq 64))"
# ---- the throw-away tree and the fake tools ---------------------------------------------------------------------------------
fx="$work/fx"; mkdir -p "$fx/bin" "$fx/images" "$fx/dist" "$fx/.github/policy" "$fx/out"
cp "$root"/bin/check-*.sh "$fx/bin/" 2> /dev/null || true
printf '{"image-production":"%s","image-fips":"%s","apk":"sha256:%s"}\n' "$D1" "$D2" "$(printf 'c%.0s' $(seq 64))" > "$fx/digests.json"
: > "$fx/images/production.tar"; : > "$fx/images/fips.tar"; : > "$fx/dist/a_linux_amd64.tar.gz"
printf '{"scanners":["grype","osv-scanner"],"pr_gate":["grype","inspector"]}\n' > "$fx/.github/policy/scanners.json"
fake="$work/fake"; mkdir -p "$fake"
mkfake() { # mkfake NAME EXIT PACKAGES   -> a scanner that logs its argv, prints `packages: N` and exits EXIT
  cat > "$fake/$1" <<EOF
#!/usr/bin/env bash
echo "$1 \$*" >> "\$FAKE_LOG"
case "\${1:-}" in --version|version) echo "$1 9.9.9"; exit 0;; esac
echo "packages: $3"
exit $2
EOF
  chmod +x "$fake/$1"
}
mkfake grype 0 120; mkfake osv-scanner 0 80; mkfake trivy 0 5
run() { # run SCRIPT ARGS...  -> sets rc, out; runs in the fake tree with the fakes first on PATH
  local s=$1; shift; : > "$work/log"; rc=0
  out=$( (cd "$fx" && PATH="$fake:$PATH" FAKE_LOG="$work/log" FAKE_DIR="$work/fakedir" bash "bin/$s" "$@") 2>&1) || rc=$?
}
okrun() { run "$@"; }
want_ok() { # want_ok LABEL SCRIPT ARGS...
  local l=$1; shift; run "$@"; if [ "$rc" = 0 ]; then ok "$l"; else bad "$l -> rc=$rc: ${out:0:140}"; fi; }
want_fail() { # want_fail LABEL WORD SCRIPT ARGS...  (a NAMED failure: exit 1 and WORD in the output; a missing script exits 127 and is RED)
  local l=$1 w=$2; shift 2; run "$@"
  if [ "$rc" = 1 ] && grep -Fqi -- "$w" <<< "$out"; then ok "$l (caught: ${out:0:70})"; else bad "$l -> rc=$rc, wanted exit 1 naming '$w': ${out:0:140}"; fi; }
want_rc() { # want_rc LABEL RC SCRIPT ARGS...
  local l=$1 r=$2; shift 2; run "$@"; if [ "$rc" = "$r" ]; then ok "$l"; else bad "$l -> rc=$rc, wanted $r: ${out:0:140}"; fi; }
SCAN=(check-scan.sh --scanners .github/policy/scanners.json --digests digests.json --images images --archives dist --out out)
# ---- REQ-CHAIN-006-AC4: check-scan.sh ---------------------------------------------------------------------------------------
want_ok "AC4 both listed scanners clean with packages: exit 0" "${SCAN[@]}"
if [ -f "$fx/out/scan-results.json" ] && jq -e '.listed == 2 and .ran == 2 and (.scanners | length == 2) and all(.scanners[]; .verdict == "pass" and (.version | length > 0))' "$fx/out/scan-results.json" > /dev/null 2>&1; then ok "AC4 results: listed 2, ran 2, every scanner pass with a version"; else bad "AC4 results file shape (listed/ran/scanners/version)"; fi
if [ -f "$fx/out/scan-results.json" ] && jq -e --arg a "$D1" --arg b "$D2" '[.scanners[].subjects[] | select(.name | test("production|fips"))] | (map(.digest) | unique | sort) == ([$a,$b] | sort)' "$fx/out/scan-results.json" > /dev/null 2>&1; then ok "AC4 every image subject carries the digest from the digest list (not a tag, not a tarball hash)"; else bad "AC4 subject digests are not the candidate digests"; fi
if [ -f "$fx/out/scan-results.json" ] && jq -e 'all(.scanners[].subjects[]; .packages > 0)' "$fx/out/scan-results.json" > /dev/null 2>&1; then ok "AC4 every subject reports a package count above zero"; else bad "AC4 package counts missing or zero in the results"; fi
if grep -q '^trivy' "$work/log" 2>/dev/null || ! grep -q '^grype' "$work/log" 2>/dev/null; then bad "AC4 only listed scanners ran (trivy is on PATH and must not run; grype must)"; else ok "AC4 only the listed scanners ran (a trivy on PATH did not)"; fi
if grep -E '^grype .*dist/' "$work/log" > /dev/null 2>&1 && ! grep -E '^osv-scanner .*dist/' "$work/log" > /dev/null 2>&1; then ok "AC4 the release archives are scanned by grype and only by grype (scanners.json comment, row 45)"; else bad "AC4 archives: grype must scan dist/*.tar.gz and osv-scanner must not"; fi
mkfake grype 1 120
want_fail "AC4 a scanner reports findings: the script fails naming it" grype "${SCAN[@]}"
mkfake grype 0 120; mkfake osv-scanner 1 80
want_fail "AC4 the second scanner reports findings: the script fails naming it" osv-scanner "${SCAN[@]}"
mkfake osv-scanner 0 80; mkfake grype 0 0
want_fail "AC4 zero packages scanned fails (REQ-REL-004-AC1)" packages "${SCAN[@]}"
mkfake grype 0 120; mkfake osv-scanner 2 80
want_fail "AC4 a scanner that could not run (exit 2) fails: nothing is judged behind a scanner that did not run" osv-scanner "${SCAN[@]}"
mkfake osv-scanner 0 80
mv "$fake/osv-scanner" "$fake/osv-scanner.off"
want_fail "AC4 a listed scanner that is not installed fails naming it" osv-scanner "${SCAN[@]}"
mv "$fake/osv-scanner.off" "$fake/osv-scanner"
printf '{"scanners":["grype","osv-scanner","extra-scanner"]}\n' > "$fx/.github/policy/scanners.json"
want_fail "AC4 a third listed scanner with no tool fails: ran must equal listed" extra-scanner "${SCAN[@]}"
printf '{"scanners":[]}\n' > "$fx/.github/policy/scanners.json"
want_fail "AC4 an empty scanner list fails (a vacuous pass is not a pass)" listed "${SCAN[@]}"
printf '{"scanners":["grype","osv-scanner"]}\n' > "$fx/.github/policy/scanners.json"
cp "$fx/digests.json" "$work/dig.bak"; printf '{"image-production":"%s"}\n' "$D1" > "$fx/digests.json"
want_fail "AC4 a digest list without the fips image fails" fips "${SCAN[@]}"
cp "$work/dig.bak" "$fx/digests.json"; mv "$fx/images/fips.tar" "$fx/images/fips.tar.off"
want_fail "AC4 a missing image tarball fails naming it" fips "${SCAN[@]}"
mv "$fx/images/fips.tar.off" "$fx/images/fips.tar"
# ---- REQ-CHAIN-006-AC6: check-fips.sh -----------------------------------------------------------------------------------------
cat > "$fake/docker" <<'EOF'
#!/usr/bin/env bash
echo "docker $*" >> "$FAKE_LOG"; mkdir -p "$FAKE_DIR"
case "$1" in
  load) img=$(basename "${3:-x}" .tar); echo "Loaded image: fscache:$img";;
  run) for a in "$@"; do case "$a" in fscache:production|*production*) v=production;; fscache:fips|*fips*) v=fips;; esac; done
       [ -f "$FAKE_DIR/run-fails" ] && { echo "docker: start failed" >&2; exit 125; }
       echo "cid-$v"; echo "$v" > "$FAKE_DIR/last";;
  port) case "$2" in *production*) echo "127.0.0.1:40001";; *) echo "127.0.0.1:40002";; esac;;
  rm|stop|logs|inspect) echo "$*" >> "$FAKE_DIR/removed";;
esac
exit 0
EOF
cat > "$fake/curl" <<'EOF'
#!/usr/bin/env bash
echo "curl $*" >> "$FAKE_LOG"
for a in "$@"; do case "$a" in *:40001/statusz*) f="$FAKE_DIR/status-production.json";; *:40002/statusz*) f="$FAKE_DIR/status-fips.json";; esac; done
[ -n "${f:-}" ] && [ -f "$f" ] && { cat "$f"; exit 0; }
exit 7
EOF
chmod +x "$fake/docker" "$fake/curl"
st() { mkdir -p "$work/fakedir"; printf '%s\n' "$2" > "$work/fakedir/status-$1.json"; }
GOODF='{"fips140":true,"fips140_note":"active (Go validated module v1.0.0, CMVP cert #5247)"}'
GOODP='{"fips140":false,"fips140_note":"off"}'
FIPS=(check-fips.sh --digests digests.json --images images --out out)
resetf() { rm -rf "$work/fakedir"; mkdir -p "$work/fakedir"; st production "$GOODP"; st fips "$GOODF"; rm -f "$fx/out/fips-result.json"; }
resetf; want_ok "AC6 fips active with the validated module v1.0.0 and production off: exit 0" "${FIPS[@]}"
if [ -f "$fx/out/fips-result.json" ] && jq -e '(.images | length) == 2' "$fx/out/fips-result.json" > /dev/null 2>&1 && ! grep -q 5247 "$fx/out/fips-result.json"; then ok "AC6 the result lists both images and does not report the certificate number (it is a documented mapping, not something a binary reports)"; else bad "AC6 fips-result.json shape, or it reports the certificate number"; fi
if [ "$(grep -c '^docker run' "$work/log" 2> /dev/null || echo 0)" = 2 ] && [ -f "$work/fakedir/removed" ] && [ "$(wc -l < "$work/fakedir/removed")" -ge 2 ]; then ok "AC6 both candidate images were started and both containers removed"; else bad "AC6 each candidate must be started (docker run) and removed"; fi
resetf; st fips '{"fips140":false,"fips140_note":"off"}'
want_fail "AC6 the -fips image reporting off fails naming fips" fips "${FIPS[@]}"
resetf; st fips '{"fips140":true,"fips140_note":"active (fips140 mode forced at runtime; not the validated-module build)"}'
want_fail "AC6 fips mode forced at runtime without the validated module fails" validated "${FIPS[@]}"
resetf; st fips '{"fips140":true,"fips140_note":"active (Go module v1.26.0; certificate status not asserted)"}'
want_fail "AC6 another module version than v1.0.0 fails" v1.0.0 "${FIPS[@]}"
resetf; st production '{"fips140":true,"fips140_note":"active (Go validated module v1.0.0, CMVP cert #5247)"}'
want_fail "AC6 the production image reporting the FIPS mode active fails naming production" production "${FIPS[@]}"
resetf; rm -f "$work/fakedir/status-fips.json"
want_fail "AC6 a status that cannot be read fails naming the image (no silent pass)" fips "${FIPS[@]}"
resetf; echo 'not json' > "$work/fakedir/status-fips.json"
want_fail "AC6 a status that is not JSON fails" fips "${FIPS[@]}"
resetf; touch "$work/fakedir/run-fails"
want_fail "AC6 an image that does not start fails" start "${FIPS[@]}"
resetf; rm -f "$work/fakedir/removed"; st fips '{"fips140":false,"fips140_note":"off"}'; run "${FIPS[@]}"
if [ "$rc" = 1 ] && [ -f "$work/fakedir/removed" ]; then ok "AC6 the containers are removed even when the check fails"; else bad "AC6 cleanup after a failure (rc=$rc, removed file present: $([ -f "$work/fakedir/removed" ] && echo yes || echo no))"; fi
resetf; st fips '{"fips140_note":"active (Go validated module v1.0.0, CMVP cert #5247)"}'
want_fail "AC6 a status without the fips140 field fails" fips "${FIPS[@]}"
# ---- REQ-CHAIN-006-AC7: check-guide.sh ---------------------------------------------------------------------------------------
g() { printf '%s\n' "$1" > "$fx/guide.md"; }
GUIDE=(check-guide.sh --guide guide.md --digests digests.json --images images --out out)
FENCE='```'
g "Verify a release.

${FENCE}sh check
true
${FENCE}

${FENCE}sh check
echo hello-world
# expect: hello-world
${FENCE}

${FENCE}sh check
sh -c 'exit 3'
# exit: 3
${FENCE}

${FENCE}sh check
test \"\$CANDIDATE_PRODUCTION\" = \"$D1\"
${FENCE}"
rm -f "$fx/out/guide-results.json"
want_ok "AC7 every guide command runs: a silent one by exit status, one by its stated output, one by its stated exit code, one reading the candidate digest" "${GUIDE[@]}"
if [ -f "$fx/out/guide-results.json" ] && jq -e '(.commands | length) == 4 and all(.commands[]; .outcome == "pass")' "$fx/out/guide-results.json" > /dev/null 2>&1; then ok "AC7 the results file lists each of the four commands with its outcome"; else bad "AC7 guide-results.json shape"; fi
g "${FENCE}sh check
true
${FENCE}

${FENCE}sh check
false
${FENCE}"
want_fail "AC7 a command that exits non-zero fails the script naming it" false "${GUIDE[@]}"
g "${FENCE}sh check
echo something-else
# expect: hello-world
${FENCE}"
want_fail "AC7 a command whose stated output does not appear fails" hello-world "${GUIDE[@]}"
g "${FENCE}sh check
true
# expect: must-appear
${FENCE}"
want_fail "AC7 a silent command that is stated to print something fails (exit 0 is not enough)" must-appear "${GUIDE[@]}"
g "${FENCE}sh check
sh -c 'exit 0'
# exit: 3
${FENCE}"
want_fail "AC7 a command that exits 0 where the guide states another exit code fails" exit "${GUIDE[@]}"
g "Nothing to run here."
want_fail "AC7 a guide with no extracted command fails (a vacuous pass is not a pass)" command "${GUIDE[@]}"
body=""; for i in $(seq 11); do body="$body${FENCE}sh check
true
${FENCE}

"; done; g "$body"
want_fail "AC7 a guide with more than ten commands fails (rule 78: ten at most)" ten "${GUIDE[@]}"
g "${FENCE}sh
echo not-a-check-block
${FENCE}

${FENCE}sh check
true
${FENCE}"
want_ok "AC7 only the blocks marked check are commands (an unmarked block is prose)" "${GUIDE[@]}"
rm -f "$fx/guide.md"
want_fail "AC7 a missing guide file fails" guide "${GUIDE[@]}"
# ---- REQ-CHAIN-006-AC5: the interface only (the gap is stated in the header) ------------------------------------------------
want_rc "AC5 an unknown suite name is a named refusal (exit 2)" 2 check-acceptance.sh nosuch --digests digests.json --images images --out out
want_rc "AC5 no suite name is a named refusal (exit 2)" 2 check-acceptance.sh --digests digests.json --images images --out out
want_rc "AC5 a missing image directory is a named refusal (exit 2)" 2 check-acceptance.sh gradle --digests digests.json --images /nonexistent --out out
# ---- REQ-CHAIN-006-AC11 (rule 68, amended): the helper bin/witnessed.sh and its 9-minute cap -------------------------------------------
hw="$work/hw"; mkdir -p "$hw/bin" "$hw/fakebin" "$hw/tmp"
cp "$root/bin/witnessed.sh" "$hw/bin/" 2> /dev/null || true
printf '#!/usr/bin/env bash\necho "step $*" >> "$HW_LOG"\n[ -z "${STEP_FAIL:-}" ] || exit 1\n' > "$hw/bin/step.sh"
cat > "$hw/fakebin/curl" <<'EOF'
#!/usr/bin/env bash
while [ $# -gt 0 ]; do [ "$1" = -o ] && { shift; printf '{"value":"fake-token-value"}' > "$1"; }; shift; done
EOF
cat > "$hw/fakebin/timeout" <<'EOF'
#!/usr/bin/env bash
echo "timeout $1" >> "$HW_LOG"
[ -z "${FAKE_OUTLIVE:-}" ] || exit 124
shift; exec "$@"
EOF
cat > "$hw/fakebin/witness" <<'EOF'
#!/usr/bin/env bash
echo "witness $*" >> "$HW_ARGV"
out=""; a=("$@"); for i in "${!a[@]}"; do [ "${a[$i]}" = -o ] && out=${a[$((i + 1))]}; [ "${a[$i]}" = -- ] && { cmd=("${a[@]:$((i + 1))}"); break; }; done
"${cmd[@]}" || exit $?
printf '{"fake":"record"}' > "$out"
EOF
chmod +x "$hw/fakebin/"*
hrun() { # hrun [VAR=val...] -- STEP SCRIPT ARGS...  (runs in the helper tree, fakes first on PATH)
  local env=(); while [ "$1" != -- ]; do env+=("$1"); shift; done; shift; rc=0
  out=$( (cd "$hw" && env "${env[@]}" PATH="$hw/fakebin:$PATH" HW_LOG="$work/hwlog" HW_ARGV="$work/hwargv" RUNNER_TEMP="$hw/tmp" \
          ACTIONS_ID_TOKEN_REQUEST_TOKEN=t ACTIONS_ID_TOKEN_REQUEST_URL="http://x/?a=b" bash bin/witnessed.sh "$@") 2>&1) || rc=$?
}
reset_h() { rm -rf "$hw/witness-records"; : > "$work/hwlog"; : > "$work/hwargv"; }
reset_h; hrun X=1 -- scanners bin/step.sh scanners
h_ok=0; [ "$rc" = 0 ] && [ -f "$hw/witness-records/scanners.json" ] && h_ok=1
if [ "$rc" = 0 ] && [ -f "$hw/witness-records/scanners.json" ] && grep -q '^step scanners' "$work/hwlog"; then ok "AC11 the helper runs the script with its arguments under Witness and writes witness-records/STEP.json"; else bad "AC11 helper normal run -> rc=$rc ${out:0:140}"; fi
if [ "$(grep -c '^timeout ' "$work/hwlog")" = 1 ] && grep -qx 'timeout 540' "$work/hwlog"; then ok "AC11 the wrapped command is run through exactly one timeout of 540 seconds (9 minutes)"; else bad "AC11 the helper must run the command through exactly one 'timeout 540': $(tr '\n' ' ' < "$work/hwlog")"; fi
if grep -q -- '--step scanners' "$work/hwargv" && grep -q -- '-o witness-records/scanners.json' "$work/hwargv" && grep -q -- '-t https://timestamp.sigstore.dev/api/v1/timestamp' "$work/hwargv" \
   && grep -q -- '--env-filter-sensitive-vars' "$work/hwargv" && ! grep -Eq -- '-a [a-z,-]*(github|slsa)' "$work/hwargv"; then ok "AC9 the helper gives Witness the step name, the record path, the Sigstore timestamp authority and the environment filter, and never the github or slsa attestor"; else bad "AC9 witness argv: $(cat "$work/hwargv" | cut -c1-200)"; fi
if [ "$h_ok" = 1 ] && ! grep -rq 'fake-token-value' "$work/hwargv" "$work/hwlog" "$hw/witness-records" 2> /dev/null; then ok "AC9 the token value is in no argument, log or record (only its file path is passed)"; else bad "AC9 the token value leaked into the argv, log or record"; fi
reset_h; hrun FAKE_OUTLIVE=1 -- scanners bin/step.sh scanners
if [ "$h_ok" = 1 ] && [ "$rc" != 0 ] && [ ! -e "$hw/witness-records/scanners.json" ]; then ok "AC11 a command that outlives the cap makes the helper fail (exit $rc) and leaves no record"; else bad "AC11 an overrun must fail with no record: rc=$rc"; fi
reset_h; hrun STEP_FAIL=1 -- acceptance bin/step.sh acceptance
if [ "$h_ok" = 1 ] && [ "$rc" != 0 ] && [ ! -e "$hw/witness-records/acceptance.json" ]; then ok "AC11 a failing script makes the helper fail and leaves no record"; else bad "AC11 a failing script must fail with no record: rc=$rc"; fi
reset_h; hrun X=1 -- '../x' bin/step.sh a
if [ "$h_ok" = 1 ] && [ "$rc" = 2 ] && [ ! -s "$work/hwlog" ]; then ok "AC11 a step name that is not a plain lower-case word is refused (exit 2) before anything runs"; else bad "AC11 bad step name -> rc=$rc, log: $(cat "$work/hwlog")"; fi
reset_h; for s in scanners acceptance runtime; do hrun X=1 -- "$s" bin/step.sh "$s"; done
if [ "$(ls "$hw/witness-records" 2> /dev/null | tr '\n' ' ')" = "acceptance.json runtime.json scanners.json " ]; then ok "AC12 the three steps leave exactly three records in witness-records/, one per step (the next stage verifies the list)"; else bad "AC12 witness-records/ holds: $(ls "$hw/witness-records" 2> /dev/null | tr '\n' ' ')"; fi
# ---- REQ-CHAIN-006-AC3 / AC11: bin/check-stage.sh, the fixed dispatcher (verify first, then only the phase's checks) -------------------
dp="$work/dp"; mkdir -p "$dp/bin"; cp "$root/bin/check-stage.sh" "$dp/bin/" 2> /dev/null || true
printf '#!/usr/bin/env bash\necho "verify $*" >> "$DP_LOG"\nexit "${VERIFY_RC:-0}"\n' > "$dp/bin/chain-verify.py"
for s in check-scan check-fips check-acceptance check-guide; do printf '#!/usr/bin/env bash\necho "%s $*" >> "$DP_LOG"\n' "$s" > "$dp/bin/$s.sh"; done
cat > "$dp/bin/python3" <<'EOF'
#!/usr/bin/env bash
shift; bash "bin/chain-verify.py" "$@"
EOF
chmod +x "$dp/bin/python3"
drun() { rc=0; : > "$work/dplog"; out=$( (cd "$dp" && PATH="$dp/bin:$PATH" DP_LOG="$work/dplog" VERIFY_RC="${VERIFY_RC:-0}" bash bin/check-stage.sh "$@") 2>&1) || rc=$?; }
drun scanners; d_ok=0; [ "$rc" = 0 ] && grep -q '^check-scan' "$work/dplog" && d_ok=1
drun nosuch
if [ "$d_ok" = 1 ] && [ "$rc" = 2 ] && grep -Fq 'unknown phase: nosuch' <<< "$out" && ! grep -q '^check-' "$work/dplog"; then ok "AC3 an unknown phase is refused (exit 2) naming it, and no check runs"; else bad "AC3 unknown phase -> rc=$rc: ${out:0:100}"; fi
VERIFY_RC=1 drun scanners
if [ "$d_ok" = 1 ] && [ "$rc" != 0 ] && ! grep -q '^check-' "$work/dplog"; then ok "AC3 when verifying Build's record fails, no check runs (rule 58)"; else bad "AC3 verify failure -> rc=$rc, log: $(tr '\n' ' ' < "$work/dplog")"; fi
drun scanners
if [ "$rc" = 0 ] && [ "$(grep -c '^verify' "$work/dplog")" = 2 ] && [ "$(grep '^check-' "$work/dplog" | cut -d' ' -f1 | tr '\n' ' ')" = "check-scan " ]; then ok "AC3 phase scanners: both verifications first, then only the scan"; else bad "AC3 phase scanners ran: $(tr '\n' ' ' < "$work/dplog")"; fi
drun acceptance
if [ "$rc" = 0 ] && [ "$(grep '^check-' "$work/dplog" | cut -d' ' -f1,2 | tr '\n' ' ')" = "check-acceptance gradle check-acceptance maven " ]; then ok "AC3 phase acceptance: gradle, then maven, nothing else"; else bad "AC3 phase acceptance ran: $(tr '\n' ' ' < "$work/dplog")"; fi
drun runtime
if [ "$rc" = 0 ] && [ "$(grep '^check-' "$work/dplog" | cut -d' ' -f1,2 | tr '\n' ' ')" = "check-acceptance egress check-fips --digests check-guide --guide " ]; then ok "AC3 phase runtime: egress, fips, guide, in that order"; else bad "AC3 phase runtime ran: $(tr '\n' ' ' < "$work/dplog")"; fi
EXPECT=53
echo "pass=$pass fail=$failn"
if [ $((pass + failn)) != "$EXPECT" ]; then echo "FAIL case count $((pass + failn)) != expected $EXPECT (a case was skipped or added)"; exit 1; fi
[ "$failn" = 0 ]
