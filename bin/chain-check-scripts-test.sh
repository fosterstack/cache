#!/usr/bin/env bash
# proves: REQ-CHAIN-006-AC17, REQ-CHAIN-006-AC16, REQ-PLAT-001-AC1, REQ-PLAT-002-AC1, REQ-PLAT-003-AC1, REQ-FIPS-001-AC1, REQ-FIPS-001-AC2, REQ-FIPS-002-AC1, REQ-CHAIN-006-AC15, REQ-CHAIN-006-AC3, REQ-CHAIN-006-AC4, REQ-CHAIN-006-AC5, REQ-CHAIN-006-AC6, REQ-CHAIN-006-AC7, REQ-CHAIN-006-AC9, REQ-CHAIN-006-AC11, REQ-CHAIN-006-AC12 — AC5 interface only, see the gap below
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
#   [P] bin/check-guide.sh --guide FILE --digests D --images DIR --out DIR (Q10, Oct 10: cache-3f's guide format, rule 79 word for word):
#         every command is a line of a ```sh fenced block (a ` \` continuation joins the next line; `#` lines are comments), unattended, in
#         customer order, at most 10 in all; only cosign, gh and jq, each in its verify form (cosign verify / verify-attestation / verify-blob /
#         verify-blob-attestation, gh attestation verify, jq), joined only by pipes; placeholders are ALL-CAPS in angle brackets, each defined
#         ONCE in a list line before the first fence (`- `<NAME>`: text`). Check substitutes the candidate's values: <IMAGE_REF> =
#         $CANDIDATE_REPOSITORY@<image-production digest> (PROPOSED: Check has the digest from Build's digests.json but NO registry reference,
#         see the report), <TAG> = $GITHUB_REF_NAME, <IDENTITY> = https://github.com/$GITHUB_REPOSITORY/.github/workflows/stage-sign.yml@$GITHUB_REF
#         (Sign's keyless identity). A command that cannot run on a candidate is excused ONLY by an exact entry of the cannot-run list,
#         GUIDE.cannot-run.json next to the guide ([{"command": exact text, "reason": why}]); it is reported as not-run, never skipped silently.
#         Fails closed on: no command, more than ten, another tool or subcommand, any other shell syntax, an undefined, twice-defined or
#         unsubstituted placeholder, a non-zero exit, a cannot-run entry that is runnable or not in the guide. Writes OUT/guide-results.json.
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
#
# STEP-5 REVISIT (advisor rulings Q2, Q3, Q6, Q8, Oct 10), what changed and why:
#   Q6 the scanner fakes print the REAL output shapes recorded in the scanner fixtures of the auditor directory (fixtures/scanners) (grype 0.118.0 `-o json`: descriptor,
#      matches, source; osv-scanner 2.6.0 `--format json`: results[].packages[]); grype's package count is the CycloneDX SBOM it writes
#      with `-o cyclonedx-json=FILE` (components, as bin/grype-scan.sh counts today, REQ-REL-004-AC1), osv's is the packages it lists with
#      --all-packages. The `packages: N` line is gone (no real tool prints it). osv-scanner keeps its Go-module target (go.mod and
#      tools/requirements/go.mod), as today's stage-verify.yml scans them.
#   Q2 the helper cases run PR 2's helper (token through stdout and a process substitution, witness-STEP/STEP-collection.json, the closed
#      step list with PR 3's three steps; a fourth unknown step is refused).
#   AC15 (advisor, Oct 10): each scanner's vulnerability database is fetched fresh from the scanner's own host at scan time and the
#      results record its source URL, build date and digest; stale (> 48 h, `now` injectable as CHECK_SCAN_NOW, epoch seconds), unfetchable,
#      foreign-host, dateless or digestless databases fail closed. grype's database status is read from the shape recorded in
#      the scanner fixtures of the auditor directory (fixtures/scanners)/grype.json (descriptor.db.status: from = the download URL with ?checksum=sha256:..., built, valid);
#      its host there is grype.anchore.io. osv-scanner (advisor, Oct 10, from osv-scanner v2.6.0 docs/offline-mode.md): it runs with
#      --offline-vulnerabilities --download-offline-databases, OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY pointing at an EMPTY directory, so every
#      database is downloaded fresh as <ecosystem>/all.zip from osv-vulnerabilities.storage.googleapis.com; the evidence is read from the
#      files: source URL https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip, digest the zip's sha256, date the newest
#      `modified` among its OSV records, recorded as db_newest_record_modified (it is not a database build date; grype's
#      db_built_or_published is); db_source_basis says "observed" for grype (its status output names the URL) and "documented" for osv (no
#      osv file or output names it: a wrong osv host is a proof-on-GitHub item). A pre-set OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY that is not
#      empty is refused ("cache directory not empty"). The fake writes such a cache (two OSV-schema records with `id` and `modified` per zip; nothing else).
#   Q3/Q8 the dispatcher runs the verifier as python3 -I -B and the runtime phase runs egress, k8s, FIPS, guide.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
command -v jq > /dev/null || { echo "FAIL jq is required"; exit 1; }
ok()  { pass=$((pass + 1)); echo "ok   $1"; }
bad() { failn=$((failn + 1)); echo "FAIL $1"; }
CHECK_SCAN_NOW=$(jq -n '"2026-10-10T00:00:00Z" | fromdateiso8601'); export CHECK_SCAN_NOW   # AC15: the scan's `now`
GDB_SUM=972de542534d3461cc3c3849a37a3f917b823de3b9c367e289db0d163519b42b
GDB_FROM="https://grype.anchore.io/databases/v6/vulnerability-db_v6.1.9_2026-10-09T00:33:02Z_1790058641.tar.zst?checksum=sha256%3A$GDB_SUM"
export FAKE_DB_FROM="$GDB_FROM" FAKE_DB_BUILT=2026-10-09T06:30:41Z FAKE_DB_RC=0
export FAKE_OSV_DB_RC=0 FAKE_OSV_ZIP=ok FAKE_OSV_MODIFIED=2026-10-09T20:00:00Z FAKE_OSV_ECOS="Go Debian:12"
D1="sha256:$(printf 'a%.0s' $(seq 64))"; D2="sha256:$(printf 'b%.0s' $(seq 64))"
# ---- the throw-away tree and the fake tools ---------------------------------------------------------------------------------
fx="$work/fx"; mkdir -p "$fx/bin" "$fx/images" "$fx/dist" "$fx/.github/policy" "$fx/out"
cp "$root"/bin/check-*.sh "$root"/bin/check-*.py "$fx/bin/" 2> /dev/null || true
printf '{"image-production":"%s","image-fips":"%s","apk":"sha256:%s"}\n' "$D1" "$D2" "$(printf 'c%.0s' $(seq 64))" > "$fx/digests.json"
: > "$fx/images/production.tar"; : > "$fx/images/fips.tar"; : > "$fx/dist/fscache_0.3.0_linux_amd64.tar.gz"; : > "$fx/dist/fscache_0.3.0_linux_arm64.tar.gz"; : > "$fx/dist/fscache-fips_0.3.0_linux_amd64.tar.gz"; : > "$fx/dist/fscache-fips_0.3.0_linux_arm64.tar.gz"
mkdir -p "$fx/tools/requirements"; printf 'module example.com/a\n' > "$fx/go.mod"; printf 'module example.com/b\n' > "$fx/tools/requirements/go.mod"
printf '{"scanners":["grype","osv-scanner"],"pr_gate":["grype","inspector"]}\n' > "$fx/.github/policy/scanners.json"
fake="$work/fake"; mkdir -p "$fake"
mkfake() { # mkfake NAME EXIT PACKAGES  -> a scanner that logs its argv and prints its real output shape with PACKAGES packages
  cat > "$fake/$1" <<EOF
#!/usr/bin/env bash
echo "$1 \$*" >> "\$FAKE_LOG"
case "\${1:-}" in --version|version) echo "$1 9.9.9"; exit 0;; esac
[ "\${1:-} \${2:-}" != "db update" ] || exit "\$FAKE_DB_RC"
n=$3; name=$1
for a in "\$@"; do case "\$a" in cyclonedx-json=*) python3 -c 'import json,sys; json.dump({"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"p%d" % i,"version":"1"} for i in range(int(sys.argv[2]))]}, open(sys.argv[1],"w"))' "\${a#cyclonedx-json=}" "\$n";; esac; done
if [ "\$name" = osv-scanner ]; then
  case " \$* " in *" --offline-vulnerabilities "*) ;; *) echo "online scan refused by the fake: no --offline-vulnerabilities" >&2; exit 99;; esac
  case " \$* " in *" --download-offline-databases "*)
    c=\${OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY:?}
    echo "osvcache-before \$(find "\$c" -type f | wc -l | tr -d ' ')" >> "\$FAKE_LOG"
    [ "\$FAKE_OSV_DB_RC" = 0 ] || exit "\$FAKE_OSV_DB_RC"
    [ "\$FAKE_OSV_ZIP" = none ] || python3 - "\$c" "\$FAKE_OSV_ZIP" "\$FAKE_OSV_MODIFIED" \$FAKE_OSV_ECOS <<'PZ'
import json, os, sys, zipfile
c, mode, newest = sys.argv[1:4]
for eco in sys.argv[4:]:
    os.makedirs(os.path.join(c, eco), exist_ok=True)
    p = os.path.join(c, eco, "all.zip")
    if mode == "broken":
        open(p, "w").write("not a zip"); continue
    with zipfile.ZipFile(p, "w") as z:
        if mode == "empty":
            continue
        for i, m in (("1", "2026-01-01T00:00:00Z"), ("2", newest)):
            rec = {"id": "%s-%s" % (eco.split(":")[0].upper(), i)}
            if mode != "nomodified":
                rec["modified"] = m
            z.writestr(rec["id"] + ".json", json.dumps(rec))
PZ
  ;; esac
fi
if [ "\$name" = grype ]; then
  python3 -c 'import json,os; st={"schemaVersion":"v6.1.9","from":os.environ["FAKE_DB_FROM"],"built":os.environ["FAKE_DB_BUILT"],"path":"/.cache/grype/db/6/vulnerability.db","valid":True}; st={k:v for k,v in st.items() if v != ""}; print(json.dumps({"matches":[],"source":{"type":"image","target":{}},"descriptor":{"name":"grype","version":"9.9.9","db":{"status":st,"providers":{}}}}))'
else
  eco=Debian:12; case " \$* " in *go.mod*) eco=Go;; esac
  python3 -c 'import json,sys; print(json.dumps({"results":[{"source":{"path":"/x","type":"os"},"packages":[{"package":{"name":"p%d" % i,"version":"1","ecosystem":sys.argv[2]},"vulnerabilities":[],"groups":[]} for i in range(int(sys.argv[1]))]}]} if int(sys.argv[1]) else {"results":[]}))' "\$n" "\$eco"
fi
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
if [ -f "$fx/out/scan-results.json" ] && jq -e --arg a "$D1" --arg b "$D2" '[.scanners[].subjects[] | select(.name == "production" or .name == "fips")] | (map(.digest) | unique | sort) == ([$a,$b] | sort)' "$fx/out/scan-results.json" > /dev/null 2>&1; then ok "AC4 every image subject carries the digest from the digest list (not a tag, not a tarball hash)"; else bad "AC4 subject digests are not the candidate digests"; fi
if [ -f "$fx/out/scan-results.json" ] && jq -e 'all(.scanners[].subjects[]; .packages > 0)' "$fx/out/scan-results.json" > /dev/null 2>&1; then ok "AC4 every subject reports a package count above zero"; else bad "AC4 package counts missing or zero in the results"; fi
if grep -q '^trivy' "$work/log" 2>/dev/null || ! grep -q '^grype' "$work/log" 2>/dev/null; then bad "AC4 only listed scanners ran (trivy is on PATH and must not run; grype must)"; else ok "AC4 only the listed scanners ran (a trivy on PATH did not)"; fi
if grep -E '^grype .*dist/' "$work/log" > /dev/null 2>&1 && ! grep -E '^osv-scanner .*dist/' "$work/log" > /dev/null 2>&1; then ok "AC4 the release archives are scanned by grype and only by grype (scanners.json comment, row 45)"; else bad "AC4 archives: grype must scan dist/*.tar.gz and osv-scanner must not"; fi
if grep -E '^osv-scanner .*scan source .*go\.mod' "$work/log" > /dev/null 2>&1 && grep -E '^osv-scanner .*tools/requirements/go\.mod' "$work/log" > /dev/null 2>&1 && ! grep -E '^grype .*go\.mod' "$work/log" > /dev/null 2>&1 \
   && jq -e --arg a "sha256:$(python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$fx/go.mod")" '[.scanners[] | select(.name == "osv-scanner") | .subjects[] | select(.name == "go.mod") | .digest] == [$a]' "$fx/out/scan-results.json" > /dev/null 2>&1; then ok "AC4 osv-scanner also scans the Go modules (go.mod, tools/requirements/go.mod), named by their sha256; grype does not (Q6: coverage kept)"; else bad "AC4 the Go-module target: osv-scanner must scan go.mod and tools/requirements/go.mod and name them by sha256"; fi
if grep -E '^grype .*-o json .*-o cyclonedx-json=' "$work/log" > /dev/null 2>&1 && grep -E '^osv-scanner .*--format json .*--all-packages' "$work/log" > /dev/null 2>&1; then ok "AC4 the counts come from each tool's own machine output (grype JSON + CycloneDX SBOM, osv-scanner JSON with every package)"; else bad "AC4 the scanners are not asked for their JSON / SBOM output"; fi
# ---- REQ-PLAT-001-AC1 (Linux only; cache-22's agreement, Oct 11, option B): the archive set is exactly the four Linux archives -------
# "exactly the four Linux archives (fscache and fscache-fips, amd64 and arm64), no darwin or windows archive exists": the scanners phase refuses any other
# set before it scans, so a fifth archive, a darwin or windows file of any kind, a missing one and a doubled platform all fail.
FOUR=(fscache_0.3.0_linux_amd64.tar.gz fscache_0.3.0_linux_arm64.tar.gz fscache-fips_0.3.0_linux_amd64.tar.gz fscache-fips_0.3.0_linux_arm64.tar.gz)
mkdist() { rm -f "$fx"/dist/*; for f in "$@"; do : > "$fx/dist/$f"; done; }
mkdist "${FOUR[@]}"; want_ok "PLAT-001-AC1 exactly the four Linux archives: the scan runs" "${SCAN[@]}"
mkdist "${FOUR[@]}" fscache_0.3.0_linux_riscv64.tar.gz; want_fail "PLAT-001-AC1 a fifth Linux archive fails" "exactly the four" "${SCAN[@]}"
mkdist "${FOUR[@]}" fscache_0.3.0_darwin_arm64.tar.gz; want_fail "PLAT-001-AC1 a darwin archive fails" darwin "${SCAN[@]}"
mkdist "${FOUR[@]}" fscache_0.3.0_windows_amd64.zip; want_fail "PLAT-001-AC1 a windows archive of any kind fails" windows "${SCAN[@]}"
mkdist "${FOUR[@]}" fscache_0.3.0_Darwin_amd64.zip; want_fail "PLAT-001-AC1 a darwin file in any case fails" darwin "${SCAN[@]}"
mkdist "${FOUR[@]:0:3}"; want_fail "PLAT-001-AC1 a missing archive fails" "exactly the four" "${SCAN[@]}"
mkdist "${FOUR[@]:0:3}" fscache-fips_0.4.0_linux_arm64.tar.gz; want_fail "PLAT-001-AC1 four files that are not the four archives of one version fail" "exactly the four" "${SCAN[@]}"
mkdist "${FOUR[@]}"
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
# ---- REQ-CHAIN-006-AC15: fresh vulnerability databases from the scanner's own host --------------------------------------------
printf '{"scanners":["grype"]}\n' > "$fx/.github/policy/scanners.json"; rm -f "$fx/out/scan-results.json"
want_ok "AC15 a fresh grype database (built 17.5 h before now) from grype.anchore.io: the scan proceeds" "${SCAN[@]}"
if [ -f "$fx/out/scan-results.json" ] && jq -e --arg u "$GDB_FROM" --arg s "sha256:$GDB_SUM" '.scanners[0] | .db_source_url == $u and .db_built_or_published == "2026-10-09T06:30:41Z" and .db_digest == $s and .db_source_basis == "observed"' "$fx/out/scan-results.json" > /dev/null 2>&1; then ok "AC15 the results carry grype's database source URL (basis: observed), build date and digest"; else bad "AC15 db fields in scan-results.json: $(jq -c '.scanners[0] | {db_source_url, db_built_or_published, db_digest}' "$fx/out/scan-results.json" 2>&1 | cut -c1-160)"; fi
u=$(grep -n '^grype db update$' "$work/log" | head -1 | cut -d: -f1 || true); s=$(grep -n '^grype .*\(oci-archive\|file\):' "$work/log" | head -1 | cut -d: -f1 || true)
if [ -n "$u" ] && [ -n "$s" ] && [ "$u" -lt "$s" ]; then ok "AC15 the database is fetched fresh (grype db update) before the first scan"; else bad "AC15 db update (line ${u:-none}) must come before the first scan (line ${s:-none})"; fi
FAKE_DB_BUILT=2026-10-07T00:00:00Z want_fail "AC15 a database built 72 h before now fails closed" "older than 48 hours" "${SCAN[@]}"
rm -f "$fx/out/scan-results.json"; FAKE_DB_RC=1 run "${SCAN[@]}"
if [ "$rc" = 1 ] && grep -Fq "could not fetch" <<< "$out" && ! grep -q '^grype .*archive' "$work/log" && ! jq -e 'any(.scanners[]?; .verdict == "pass")' "$fx/out/scan-results.json" > /dev/null 2>&1; then ok "AC15 a database that cannot be fetched fails closed: nothing is scanned and nothing is recorded as clean"; else bad "AC15 fetch failure -> rc=$rc: ${out:0:140}"; fi
FAKE_DB_FROM="https://mirror.example.com/databases/v6/db.tar.zst?checksum=sha256%3A$GDB_SUM" want_fail "AC15 a database from a host that is not grype's own fails closed" "own database host" "${SCAN[@]}"
FAKE_DB_BUILT="" want_fail "AC15 a database status without a build date fails closed" "date" "${SCAN[@]}"
FAKE_DB_FROM="https://grype.anchore.io/databases/v6/vulnerability-db_v6.1.9.tar.zst" want_fail "AC15 a database status without a digest fails closed" "digest" "${SCAN[@]}"
printf '{"scanners":["osv-scanner"]}\n' > "$fx/.github/policy/scanners.json"; rm -f "$fx/out/scan-results.json"
want_ok "AC15 osv-scanner with fresh offline databases (newest record modified 4 h before now): the scan proceeds" "${SCAN[@]}"
O=https://osv-vulnerabilities.storage.googleapis.com
if [ -f "$fx/out/scan-results.json" ] && jq -e --arg o "$O" '[.scanners[] | select(.name == "osv-scanner") | .databases[]] | (map(.ecosystem) | sort) == ["Debian:12", "Go"]
     and all(.[]; .db_source_url == ($o + "/" + .ecosystem + "/all.zip") and .db_source_basis == "documented" and .db_newest_record_modified == "2026-10-09T20:00:00Z"
            and (has("db_built_or_published") | not) and (.db_digest | test("^sha256:[0-9a-f]{64}$")))' "$fx/out/scan-results.json" > /dev/null 2>&1; then ok "AC15 the osv results carry, per ecosystem zip, its documented source URL (basis: documented), its newest record modified (labelled as such, not a build date) and its sha256"; else bad "AC15 osv databases: $(jq -c '[.scanners[] | select(.name == "osv-scanner") | .databases]' "$fx/out/scan-results.json" 2>&1 | cut -c1-200)"; fi
if grep -q '^osvcache-before 0$' "$work/log" && grep -E '^osv-scanner .*--offline-vulnerabilities .*--download-offline-databases' "$work/log" > /dev/null; then ok "AC15 osv-scanner downloads its databases fresh into an empty cache, in offline mode"; else bad "AC15 osv cache not empty at the first download, or not offline mode: $(grep -E '^osv' "$work/log" | head -2 | tr '\n' ' ' | cut -c1-200)"; fi
if jq -e '[.scanners[] | select(.name == "osv-scanner")] | length == 1 and (.[0] | ([keys[] | select(startswith("db_"))] | length == 0) and (.databases | length > 0))' "$fx/out/scan-results.json" > /dev/null 2>&1; then ok "AC15 the osv result entry has no scanner-level db_* keys (its databases are listed in a non-empty databases list)"; else bad "AC15 osv entry keys: $(jq -c '[.scanners[] | select(.name == "osv-scanner") | keys]' "$fx/out/scan-results.json" 2>&1 | cut -c1-160)"; fi
pre="$work/precache"; mkdir -p "$pre/Go"; : > "$pre/Go/all.zip"
OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="$pre" want_fail "AC15 a pre-set osv cache directory that is not empty is refused (the databases must be downloaded fresh in this job)" "cache directory not empty" "${SCAN[@]}"
FAKE_OSV_MODIFIED=2026-10-07T00:00:00Z want_fail "AC15 an osv database whose newest record is 72 h old fails closed (not refreshed)" "older than 48 hours" "${SCAN[@]}"
FAKE_OSV_ZIP=none want_fail "AC15 no osv database zip in the cache after the run fails closed" "no osv database" "${SCAN[@]}"
FAKE_OSV_ZIP=empty want_fail "AC15 an osv database zip without records fails closed" "no record" "${SCAN[@]}"
FAKE_OSV_ZIP=nomodified want_fail "AC15 an osv database whose records carry no modified date fails closed" "modified" "${SCAN[@]}"
FAKE_OSV_ZIP=broken want_fail "AC15 an unreadable osv database zip fails closed" "unreadable" "${SCAN[@]}"
FAKE_OSV_ECOS="Go Debian:12 PyPI" want_fail "AC15 an osv database for an ecosystem the scan does not target fails closed" "not one the scan targets" "${SCAN[@]}"
rm -f "$fx/out/scan-results.json"; FAKE_OSV_DB_RC=3 run "${SCAN[@]}"
if [ "$rc" = 1 ] && grep -Fq "osv-scanner could not run" <<< "$out" && ! jq -e 'any(.scanners[]?; .verdict == "pass")' "$fx/out/scan-results.json" > /dev/null 2>&1; then ok "AC15 an osv database download failure (non-zero exit) fails closed and nothing is recorded as clean"; else bad "AC15 osv download failure -> rc=$rc: ${out:0:140}"; fi
printf '{"scanners":["grype","osv-scanner"]}\n' > "$fx/.github/policy/scanners.json"
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
# ---- the artifact checks ported from stage-acceptance-artifacts.yml (advisor ruling 0384): bin/check-artifacts.sh ----------------------
# artifact checks (each Linux amd64 binary executes: it starts, answers /healthz and round-trips a key), REQ-FIPS-001-AC1 (the module selection is
# read from the binary's build info), REQ-FIPS-001-AC2 and REQ-FIPS-002-AC1 (three runtime postures; the forced-standard build never claims the module),
# REQ-PLAT-003-AC1 (production and -fips run no shell at any probed path), REQ-PLAT-002-AC1 (production and -fips: both platform entries are in the image
# archive and the image serves cache traffic on this runner's architecture). The -debug clause has no subject (owner Oct 9). The arm64 binaries and images
# need an arm64 runner, which the one-job Check does not have (reported in round 2); only the amd64 halves run here.
# The "binaries" are small real HTTP servers (python3) so the script's curl calls are real; GOFIPS140 is read from a fake `go version -m`.
fa="$work/fa"; mkdir -p "$fa/bin" "$fa/images" "$fa/out" "$fa/real"
cat > "$fa/server.py" <<'PYS'
import http.server, json, os, sys
store = {}
name = os.path.basename(sys.argv[0])
kind = os.environ.get("FAKE_KIND", "")
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, code, body=b""):
        self.send_response(code); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        if self.path == "/healthz": return self._send(200, b"ok")
        if self.path == "/statusz":
            forced = "fips140=on" in os.environ.get("GODEBUG", "")
            if name.endswith("fips") or kind == "fips":
                note = os.environ.get("FAKE_FIPS_NOTE", "active (Go validated module v1.0.0, CMVP cert #5247)"); on = True
            elif forced:
                note = os.environ.get("FAKE_FORCED_NOTE", "active (fips140 mode forced at runtime; not the validated-module build)"); on = True
            else:
                note = os.environ.get("FAKE_STD_NOTE", "off"); on = False
            return self._send(200, json.dumps({"fips140": on, "fips140_note": note}).encode())
        self._send(200 if self.path in store else 404, store.get(self.path, b""))
    def do_PUT(self):
        store[self.path] = self.rfile.read(int(self.headers.get("Content-Length", 0))); self._send(200)
addr = os.environ.get("FSCACHE_ADDR", ":8080")
http.server.HTTPServer(("127.0.0.1", int(addr.rsplit(":", 1)[1])), H).serve_forever()
PYS
for b in fscache fscache-fips; do { echo '#!/usr/bin/env python3'; cat "$fa/server.py"; } > "$fa/real/$b"; chmod +x "$fa/real/$b"; done
mkarch() { # mkarch DIR: the four Linux archives, each holding its binary
  rm -rf "$1"; mkdir -p "$1"
  for n in fscache fscache-fips; do for a in amd64 arm64; do tar -czf "$1/${n}_0.3.0_linux_${a}.tar.gz" -C "$fa/real" "$n"; done; done
}
mkarch "$fa/dist"
# OCI image archives: index.json with the platform entries, as Build's tarballs are (PROPOSED layout, read fail-closed)
python3 - "$fa/images" <<'PYO'
import io, json, sys, tarfile
def mk(path, platforms):
    idx = {"schemaVersion": 2, "manifests": [{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:" + "%064x" % (i + 1), "size": 1,
                                              "platform": {"os": p.split("/")[0], "architecture": p.split("/")[1]}} for i, p in enumerate(platforms)]}
    with tarfile.open(path, "w") as t:
        for n, b in (("index.json", json.dumps(idx).encode()), ("oci-layout", b'{"imageLayoutVersion":"1.0.0"}')):
            ti = tarfile.TarInfo(n); ti.size = len(b); t.addfile(ti, io.BytesIO(b))
for v in ("production", "fips"):
    mk(sys.argv[1] + "/" + v + ".tar", ["linux/amd64", "linux/arm64"])
mk(sys.argv[1] + "/fips-amd64only.tar", ["linux/amd64"])
PYO
cp "$fx/digests.json" "$fa/digests.json"
fake2="$work/fake2"; mkdir -p "$fake2"
cat > "$fake2/go" <<'GOEOF'
#!/usr/bin/env bash
# fake `go version -m BINARY`: the build info a binary carries
echo "go $*" >> "$FAKE_LOG"
[ "$1 $2" = "version -m" ] || exit 2
echo "$3: go1.26.0"; echo "	build	CGO_ENABLED=0"
case "$(basename "$3")" in
  fscache-fips) [ -n "${FAKE_GOFIPS_FIPS-v1.0.0}" ] && echo "	build	GOFIPS140=${FAKE_GOFIPS_FIPS-v1.0.0}";;
  fscache) [ -z "${FAKE_GOFIPS_STD:-}" ] || echo "	build	GOFIPS140=${FAKE_GOFIPS_STD}";;
esac
exit 0
GOEOF
cat > "$fake2/docker" <<'DKEOF'
#!/usr/bin/env bash
# fake docker for the artifact checks: load names fscache:VARIANT; `run -d` starts a real fake server; a shell probe fails unless FAKE_SHELL names VARIANT:PATH
echo "docker $*" >> "$FAKE_LOG"; mkdir -p "$FAKE_DIR"
case "$1" in
  load) echo "Loaded image: fscache:$(basename "${3:-x}" .tar)";;
  run)
    ep=""; img=""; detach=0; nm=""
    for ((i=2; i<=$#; i++)); do a=${!i}; j=$((i+1)); case "$a" in --entrypoint) ep=${!j};; --name) nm=${!j};; -d) detach=1;; fscache:*) img=$a;; esac; done
    if [ -n "$ep" ]; then
      case " ${FAKE_SHELL:-} " in *" ${img#fscache:}:$ep "*) exit 0;; esac
      exit 1
    fi
    [ "$detach" = 1 ] || exit 0
    port=$((41000 + $(ls "$FAKE_DIR" | grep -c '^srv-')))
    FSCACHE_ADDR=":$port" FAKE_KIND=${img#fscache:} python3 "$FAKE_DIR/server.py" > /dev/null 2>&1 &
    echo $! > "$FAKE_DIR/srv-$port"; echo "$port" > "$FAKE_DIR/port-$nm"; echo cid;;
  port) echo "127.0.0.1:$(cat "$FAKE_DIR/port-$2" 2> /dev/null || echo 1)";;
  rm|stop)
    for f in "$FAKE_DIR"/srv-*; do [ -f "$f" ] && kill "$(cat "$f")" 2> /dev/null; rm -f "$f"; done; true;;
  logs|inspect|tag) ;;
esac
exit 0
DKEOF
chmod +x "$fake2/go" "$fake2/docker"
ART=(check-artifacts.sh --digests digests.json --images images --archives dist --out out)
arun() { # arun [VAR=val ...] -- SCRIPT ARGS : the artifact check in its own tree with the artifact fakes first on PATH
  local envs=(FAKE_NONE=1); while [ "$1" != "--" ]; do envs+=("$1"); shift; done; shift
  rm -rf "$work/fakedir"; mkdir -p "$work/fakedir"; cp "$fa/server.py" "$work/fakedir/server.py"; : > "$work/log"; rc=0
  cp "$root"/bin/check-artifacts.sh "$root"/bin/check-image-platforms.py "$fa/bin/" 2> /dev/null || true
  out=$( (cd "$fa" && env "${envs[@]}" PATH="$fake2:$PATH" FAKE_LOG="$work/log" FAKE_DIR="$work/fakedir" bash "bin/$1" "${@:2}") 2>&1) || rc=$?
}
aok() { local l=$1; shift; arun "$@"; if [ "$rc" = 0 ]; then ok "$l"; else bad "$l -> rc=$rc: ${out:0:200}"; fi; }
afail() { local l=$1 w=$2; shift 2; arun "$@"; if [ "$rc" = 1 ] && grep -Fqi -- "$w" <<< "$out"; then ok "$l (caught: ${out:0:70})"; else bad "$l -> rc=$rc, wanted exit 1 naming '$w': ${out:0:200}"; fi; }
aok "ART the amd64 binaries execute, the postures are truthful, the images have no shell and serve: exit 0" -- "${ART[@]}"
if [ -f "$fa/out/artifacts-result.json" ] && jq -e '.production.digest and .fips.digest and ([.checks[].ac] | index("REQ-FIPS-002-AC1")) != null and all(.checks[]; .result == "pass")' "$fa/out/artifacts-result.json" > /dev/null 2>&1; then ok "ART the result names both candidate digests and every AC it asserted"; else bad "ART artifacts-result.json missing or incomplete"; fi
if ! grep -q 5247 "$fa/out/artifacts-result.json" 2> /dev/null; then ok "ART the result does not repeat the certificate number (documented mapping only)"; else bad "ART the certificate number is in the result"; fi
if [ "$(grep -c '^docker run -d' "$work/log" 2> /dev/null || echo 0)" = 0 ]; then :; fi
arun -- "${ART[@]}"; if grep -Fq 'FSCACHE_USERNAME' "$work/log" && ls "$work"/fakedir/srv-* > /dev/null 2>&1; then bad "ART containers were left running"; else ok "ART the containers are removed at the end and the -fips image is started with credentials"; fi
mkarch "$fa/dist"; rm "$fa/dist/fscache-fips_0.3.0_linux_amd64.tar.gz"
afail "PLAT-001-AC1 a missing amd64 archive fails naming it" fscache-fips -- "${ART[@]}"
mkarch "$fa/dist"; printf '#!/usr/bin/env bash\nexit 1\n' > "$fa/real/fscache-fips.bad"; mkdir -p "$fa/bad"; cp "$fa/real/fscache-fips.bad" "$fa/bad/fscache-fips"; chmod +x "$fa/bad/fscache-fips"
tar -czf "$fa/dist/fscache-fips_0.3.0_linux_amd64.tar.gz" -C "$fa/bad" fscache-fips
afail "PLAT-001-AC1 a binary that exits at once does not execute: fails naming healthz" healthz -- "${ART[@]}"
# REQ-CHAIN-006-AC17 (advisor 0385): the same checks for the linux/arm64 binaries and images, run by the check-arm64 job on an arm64 runner
mkarch "$fa/dist"
aok "AC17 --arch arm64: the arm64 binaries execute, the postures are truthful, the images have no shell and serve: exit 0" -- "${ART[@]}" --arch arm64
if grep -Fq -- '--platform linux/arm64' "$work/log" && [ -f "$fa/out/artifacts-result-arm64.json" ] && jq -e '.arch == "arm64" and .production.digest and .fips.digest' "$fa/out/artifacts-result-arm64.json" > /dev/null 2>&1; then ok "AC17 the arm64 images run with --platform linux/arm64 and the result names the arch and the same candidate digests"; else bad "AC17 arm64 run: no --platform linux/arm64, or artifacts-result-arm64.json incomplete"; fi
arun -- "${ART[@]}"; if ! grep -Fq -- '--platform' "$work/log"; then ok "AC17 the default (amd64) run passes no --platform"; else bad "AC17 the amd64 run passed --platform"; fi
mkarch "$fa/dist"; rm "$fa/dist/fscache-fips_0.3.0_linux_arm64.tar.gz"
afail "AC17 --arch arm64 with the arm64 -fips archive missing fails naming it" fscache-fips -- "${ART[@]}" --arch arm64
mkarch "$fa/dist"
arun -- "${ART[@]}" --arch riscv64; if [ "$rc" = 2 ] && grep -Fq arch <<< "$out"; then ok "AC17 an architecture other than amd64 and arm64 is a usage error (exit 2)"; else bad "AC17 --arch riscv64 -> rc=$rc: ${out:0:120}"; fi
mkarch "$fa/dist"
afail "AC17 --arch arm64: the fips binary reporting off fails" "fips build" FAKE_FIPS_NOTE=off -- "${ART[@]}" --arch arm64
mkarch "$fa/dist"
mkarch "$fa/dist"
afail "FIPS-001-AC1 the fips binary embeds no module selection fails" GOFIPS140 FAKE_GOFIPS_FIPS= -- "${ART[@]}"
afail "FIPS-001-AC1 another module version than v1.0.0 fails" v1.0.0 FAKE_GOFIPS_FIPS=v1.26.0 -- "${ART[@]}"
afail "FIPS-001-AC1 the standard binary embedding a selection (crossed variants) fails" crossed FAKE_GOFIPS_STD=v1.0.0 -- "${ART[@]}"
afail "FIPS-002-AC1 the fips binary reporting off fails" "fips build" FAKE_FIPS_NOTE=off -- "${ART[@]}"
afail "FIPS-002-AC1 the standard default reporting active fails" "standard" FAKE_STD_NOTE='active (x)' -- "${ART[@]}"
afail "FIPS-001-AC2 the forced-standard build claiming the validated module fails" "forced" FAKE_FORCED_NOTE='active (Go validated module v1.0.0, CMVP cert #5247)' -- "${ART[@]}"
afail "FIPS-002-AC1 the forced-standard build reporting off (not its true state) fails" "forced" FAKE_FORCED_NOTE=off -- "${ART[@]}"
afail "PLAT-003-AC1 a shell at /bin/sh in the production image fails naming production" production FAKE_SHELL="production:/bin/sh" -- "${ART[@]}"
afail "PLAT-003-AC1 a shell at /busybox/sh in the -fips image fails naming fips" fips FAKE_SHELL="fips:/busybox/sh" -- "${ART[@]}"
afail "PLAT-003-AC1 a shell at another path (/usr/bin/bash) fails" shell FAKE_SHELL="production:/usr/bin/bash" -- "${ART[@]}"
cp "$fa/images/fips.tar" "$work/fips.tar.keep"; cp "$fa/images/fips-amd64only.tar" "$fa/images/fips.tar"
afail "PLAT-002-AC1 an image archive without the linux/arm64 platform entry fails naming it" linux/arm64 -- "${ART[@]}"
cp "$work/fips.tar.keep" "$fa/images/fips.tar"
cp "$fa/digests.json" "$work/dig.keep"; printf '{"image-production":"%s"}\n' "$D1" > "$fa/digests.json"
afail "ART a digest list without the -fips image digest fails" image-fips -- "${ART[@]}"
cp "$work/dig.keep" "$fa/digests.json"
mv "$fa/images/production.tar" "$fa/images/production.tar.off"
afail "ART a missing production image fails naming it" production -- "${ART[@]}"
mv "$fa/images/production.tar.off" "$fa/images/production.tar"
# ---- REQ-CHAIN-006-AC7: check-guide.sh (a FIXTURE guide in cache-3f's format; the real docs/verify-release.md does not exist yet) ------
# REVISIT (cache-3f's run on the real draft, Oct 10): a verify command whose subject is an image reference (<IMAGE_REF>,
# <IMAGE_REF_FIPS>, a literal registry reference with `:` or `@`, or oci://...) needs a registry: it is NEVER run, it must be listed
# exactly in the cannot-run list (then not-run, exit 0, covered by Release's post-publish verification, rule 79 amended Oct 10), or the check fails closed ("unlisted command
# needs a registry"). A command runs only when every operand is a local file or a placeholder Check fills with a local value (<TAG>,
# <IDENTITY>). `$` is refused anywhere but inside single quotes ("$TAG", "${TAG}", "$(x)"). The registry text below is in the GUIDE
# FIXTURE only; the check script names no registry. The -fips tag form is cache-3f's to verify (the fixture's `<TAG>-fips` is a guess
# of nothing: it only has to look like a registry reference).
cat > "$fake/cosign" <<'EOF'
#!/usr/bin/env bash
echo "cosign $*" >> "$FAKE_LOG"
case " $* " in *fail-me*) echo "Error: no matching signatures" >&2; exit 1;; esac
echo "Verified OK"
EOF
cat > "$fake/gh" <<'EOF'
#!/usr/bin/env bash
echo "gh $*" >> "$FAKE_LOG"
case " $* " in *fail-me*) exit 1;; esac
echo "Verification succeeded"
EOF
chmod +x "$fake/cosign" "$fake/gh"
printf 'abc  cache_linux_amd64.tar.gz\n' > "$fx/checksums.txt"; printf '{}\n' > "$fx/checksums.txt.bundle"
REPO=registry.example/fosterstack/cache
grun() { # grun SCRIPT ARGS...  like run, with the candidate's environment of a release run
  : > "$work/log"; rc=0
  out=$( (cd "$fx" && PATH="$fake:$PATH" FAKE_LOG="$work/log" CANDIDATE_REPOSITORY="$REPO" GITHUB_REF_NAME=v0.3.0 \
          GITHUB_REPOSITORY=fosterstack/cache GITHUB_REF=refs/tags/v0.3.0 bash "bin/$1" "${@:2}") 2>&1) || rc=$?
}
gwant_ok() { local l=$1; grun "${GUIDE[@]}"; if [ "$rc" = 0 ]; then ok "$l"; else bad "$l -> rc=$rc: ${out:0:160}"; fi; }
gwant_fail() { local l=$1 w=$2; grun "${GUIDE[@]}"; if [ "$rc" = 1 ] && grep -Fqi -- "$w" <<< "$out"; then ok "$l (caught: ${out:0:70})"; else bad "$l -> rc=$rc, wanted exit 1 naming '$w': ${out:0:160}"; fi; }
GUIDE=(check-guide.sh --guide guide.md --digests digests.json --images images --out out)
FENCE='```'
DEFS='# Verify a FosterStack Cache release

- `<IMAGE_REF>`: the image, by digest
- `<IMAGE_REF_FIPS>`: the -fips image, by digest
- `<TAG>`: the release tag, for example v0.3.0
- `<IDENTITY>`: the signing workflow identity
'
g() { printf '%s\n' "$DEFS" "$1" > "$fx/guide.md"; rm -f "$fx/guide.cannot-run.json"; }
lst() { python3 -c 'import json,sys; json.dump([{"command": c, "reason": "needs the candidate image in a registry; Check holds it as a file"} for c in sys.argv[1:]], open(sys.argv[0] if False else "'"$fx"'/guide.cannot-run.json","w"))' "$@"; }
ISS=https://token.actions.githubusercontent.com
L1="cosign verify-blob --certificate-identity <IDENTITY> --certificate-oidc-issuer $ISS --bundle checksums.txt.bundle checksums.txt"
L2="jq -n '\"<TAG>\"'"
R1="cosign verify <IMAGE_REF> --certificate-identity <IDENTITY> --certificate-oidc-issuer $ISS | jq -e '.[0].critical.image'"
R2="gh attestation verify oci://<IMAGE_REF> --owner fosterstack"
R3="cosign verify-attestation --type slsaprovenance1 --certificate-identity <IDENTITY> --certificate-oidc-issuer $ISS <IMAGE_REF>"
RF="cosign verify <IMAGE_REF_FIPS> --certificate-identity <IDENTITY> --certificate-oidc-issuer $ISS"
RL="cosign verify ghcr.io/fosterstack/cache:<TAG>-fips --certificate-identity <IDENTITY> --certificate-oidc-issuer $ISS"
RO="gh attestation verify oci://ghcr.io/fosterstack/cache@sha256:$(printf 'a%.0s' $(seq 64)) --owner fosterstack"
blk() { local b=""; for c in "$@"; do b="$b${FENCE}sh
$c
${FENCE}

"; done; printf '%s' "$b"; }
g "Local checks:

$(blk "$L1" "$L2")
${FENCE}text
cosign sign this-is-prose-not-a-command
${FENCE}"
rm -f "$fx/out/guide-results.json"
gwant_ok "AC7 commands on local files and local placeholders run: cosign verify-blob on the checksums file, jq (a text block is prose)"
if [ -f "$fx/out/guide-results.json" ] && jq -e '(.commands | length) == 2 and all(.commands[]; .outcome == "pass")' "$fx/out/guide-results.json" > /dev/null 2>&1; then ok "AC7 the results file lists each of the two commands with its outcome"; else bad "AC7 guide-results.json shape"; fi
if grep -Fq "cosign verify-blob --certificate-identity https://github.com/fosterstack/cache/.github/workflows/stage-sign.yml@refs/tags/v0.3.0" "$work/log" && ! grep -q '<[A-Z_]*>' "$work/log"; then ok "AC7 Sign's identity is substituted for <IDENTITY> (no placeholder left)"; else bad "AC7 substitution: $(tr '\n' ' ' < "$work/log" | cut -c1-200)"; fi
g "$(blk "$R1" "$R2" "$R3" "$RF" "$RL" "$RO")"; lst "$R1" "$R2" "$R3" "$RF" "$RL" "$RO"; rm -f "$fx/out/guide-results.json"
gwant_ok "AC7 registry commands listed exactly in the cannot-run list are not run and do not fail the check (exit 0; covered by Release's post-publish verification)"
if [ -f "$fx/out/guide-results.json" ] && jq -e '(.commands | length) == 6 and all(.commands[]; .outcome == "not-run" and (.reason | length > 0))' "$fx/out/guide-results.json" > /dev/null 2>&1 && ! grep -Eq '^(cosign|gh) ' "$work/log"; then ok "AC7 each listed registry command is recorded as not-run with its reason and never run"; else bad "AC7 listed registry commands: $(tr '\n' ' ' < "$work/log" | cut -c1-160)"; fi
if [ "$(grep -c 'NOT RUN' <<< "$out")" = 6 ] && [ "$(grep -c 'run right after publishing' <<< "$out")" = 6 ]; then ok "AC7 each not-run line says the command is run right after publishing (Release's post-publish verification), not skipped"; else bad "AC7 not-run lines name the post-publish step: ${out:0:300}"; fi
for c in "$R1" "$R2" "$R3"; do g "$(blk "$c")"; gwant_fail "AC7 an unlisted verify command on <IMAGE_REF> fails closed: ${c:0:40}" "unlisted command needs a registry"; done
g "$(blk "$RF")"; gwant_fail "AC7 an unlisted -fips verify command on <IMAGE_REF_FIPS> fails closed" "unlisted command needs a registry"
g "$(blk "$RL")"; gwant_fail "AC7 an unlisted -fips verify command on a literal registry reference (host/path:tag) fails closed" "unlisted command needs a registry"
g "$(blk "$RO")"; gwant_fail "AC7 an unlisted verify command on an oci:// target fails closed" "unlisted command needs a registry"
g "$(blk "$RL")"; lst "$RL"; gwant_ok "AC7 the literal -fips registry command, listed, is not run (exit 0)"
g "$(blk "cosign verify-blob --certificate-identity fail-me --certificate-oidc-issuer $ISS --bundle checksums.txt.bundle checksums.txt")"
gwant_fail "AC7 a runnable command that exits non-zero fails the script naming it" "fail-me"
g "$(blk "cosign verify-blob --bundle checksums.txt.bundle cache_0.3.0_linux_amd64.tar.gz")"
gwant_fail "AC7 a command on a file that is not local to Check is not runnable and fails unless listed" "not runnable"
g "$(blk "jq -n \"\$TAG\"")"; gwant_fail "AC7 \$ inside double quotes (\"\$TAG\") is refused" "shell syntax"
g "$(blk "jq -n \"\${TAG}\"")"; gwant_fail "AC7 \${...} inside double quotes is refused" "shell syntax"
g "$(blk "jq -n \"\$(id)\"")"; gwant_fail "AC7 a command substitution inside double quotes is refused" "shell syntax"
g "$(blk "jq -n '\"\$x\"'")"; gwant_ok "AC7 a \$ inside single quotes is text and runs"
g "Nothing to run here."
gwant_fail "AC7 a guide with no command fails (a vacuous pass is not a pass)" "command"
g "$(for i in $(seq 11); do blk "jq -n 1"; done)"
gwant_fail "AC7 a guide with more than ten commands fails" "ten"
g "$(blk "curl -sSf https://example.com/x")"
gwant_fail "AC7 a tool other than cosign, gh and jq fails naming it" "curl"
g "$(blk "cosign sign <IMAGE_REF>")"
gwant_fail "AC7 a cosign subcommand that is not a verify fails" "cosign sign"
g "$(blk "jq -n 1; jq -n 2")"
gwant_fail "AC7 shell syntax other than a pipe (;) fails" "shell syntax"
g "$(blk "jq -n '\"<DIGEST_REF>\"'")"
gwant_fail "AC7 a placeholder the guide does not define fails" "undefined"
printf '%s\n' "$DEFS" '- `<TAG>`: again' "${FENCE}sh" "jq -n 1" "$FENCE" > "$fx/guide.md"; rm -f "$fx/guide.cannot-run.json"
gwant_fail "AC7 a placeholder defined twice fails" "twice"
printf '%s\n' "$DEFS" '- `<RELEASE_URL>`: the release page' "${FENCE}sh" "jq -n '\"<RELEASE_URL>\"'" "$FENCE" > "$fx/guide.md"; rm -f "$fx/guide.cannot-run.json"
gwant_fail "AC7 a defined placeholder Check has no local value for fails (unsubstituted)" "unsubstituted"
R4="gh release download <TAG> --repo fosterstack/cache --pattern checksums.txt"
g "$(blk "$L2" "$R4")"
gwant_fail "AC7 a command outside the runnable set fails when the cannot-run list does not name it" "not runnable"
printf '[{"command": "%s", "reason": "needs the published GitHub release, which exists only after Release"}]\n' "$R4" > "$fx/guide.cannot-run.json"
gwant_fail "AC7 a cannot-run entry that is not one of the verify forms fails (Release runs only verify forms from this list; the list is the one exact-text list)" "not a verify form"
g "$(blk "$L2" "jq -n 1")"; printf '[{"command": "jq -n 1", "reason": "x"}]\n' > "$fx/guide.cannot-run.json"
gwant_fail "AC7 a runnable command in the cannot-run list fails (it is run, never excused)" "runnable"
g "$(blk "$L2")"; printf '[{"command": "%s", "reason": "x"}]\n' "$R1" > "$fx/guide.cannot-run.json"
gwant_fail "AC7 a cannot-run entry that is not a command of the guide fails (a stale list)" "not in the guide"
rm -f "$fx/guide.md" "$fx/guide.cannot-run.json"
gwant_fail "AC7 a missing guide file fails" "guide"
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
printf '{"value":"fake-token-value"}'
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
for i in "${!a[@]}"; do [ "${a[$i]}" = --signer-fulcio-token-path ] && { [ "$(cat "${a[$((i + 1))]}")" = fake-token-value ] || exit 9; }; done
"${cmd[@]}" || exit $?
printf '{"fake":"record"}' > "$out"
EOF
chmod +x "$hw/fakebin/"*
hrun() { # hrun [VAR=val...] -- STEP SCRIPT ARGS...  (runs in the helper tree, fakes first on PATH)
  local env=(); while [ "$1" != -- ]; do env+=("$1"); shift; done; shift; rc=0
  out=$( (cd "$hw" && env "${env[@]}" PATH="$hw/fakebin:$PATH" HW_LOG="$work/hwlog" HW_ARGV="$work/hwargv" RUNNER_TEMP="$hw/tmp" \
          ACTIONS_ID_TOKEN_REQUEST_TOKEN=t ACTIONS_ID_TOKEN_REQUEST_URL="http://x/?a=b" bash bin/witnessed.sh "$@") 2>&1) || rc=$?
}
reset_h() { rm -rf "$hw"/witness-*; : > "$work/hwlog"; : > "$work/hwargv"; }
reset_h; hrun X=1 -- scanners bin/step.sh scanners
h_ok=0; [ "$rc" = 0 ] && [ -f "$hw/witness-scanners/scanners-collection.json" ] && h_ok=1
if [ "$rc" = 0 ] && [ -f "$hw/witness-scanners/scanners-collection.json" ] && grep -q '^step scanners' "$work/hwlog"; then ok "AC11 the helper runs the script with its arguments under Witness and writes witness-scanners/scanners-collection.json (PR 2's naming)"; else bad "AC11 helper normal run -> rc=$rc ${out:0:140}"; fi
if [ "$(grep -c '^timeout ' "$work/hwlog")" = 1 ] && grep -qx 'timeout 540' "$work/hwlog"; then ok "AC11 the wrapped command is run through exactly one timeout of 540 seconds (9 minutes)"; else bad "AC11 the helper must run the command through exactly one 'timeout 540': $(tr '\n' ' ' < "$work/hwlog")"; fi
if grep -q -- '--step scanners' "$work/hwargv" && grep -q -- '-o witness-scanners/scanners-collection.json' "$work/hwargv" && grep -q -- '-t https://timestamp.sigstore.dev/api/v1/timestamp' "$work/hwargv" \
   && grep -q -- '--env-filter-sensitive-vars' "$work/hwargv" && ! grep -Eq -- '-a [a-z,-]*(github|slsa)' "$work/hwargv"; then ok "AC9 the helper gives Witness the step name, the record path, the Sigstore timestamp authority and the environment filter, and never the github or slsa attestor"; else bad "AC9 witness argv: $(cat "$work/hwargv" | cut -c1-200)"; fi
if [ "$h_ok" = 1 ] && ! grep -rq 'fake-token-value' "$work/hwargv" "$work/hwlog" "$hw/witness-records" 2> /dev/null; then ok "AC9 the token value is in no argument, log or record (Witness reads it once through a process substitution)"; else bad "AC9 the token value leaked into the argv, log or record"; fi
reset_h; hrun FAKE_OUTLIVE=1 -- scanners bin/step.sh scanners
if [ "$h_ok" = 1 ] && [ "$rc" != 0 ] && [ ! -e "$hw/witness-scanners/scanners-collection.json" ]; then ok "AC11 a command that outlives the cap makes the helper fail (exit $rc) and leaves no record"; else bad "AC11 an overrun must fail with no record: rc=$rc"; fi
reset_h; hrun STEP_FAIL=1 -- acceptance bin/step.sh acceptance
if [ "$h_ok" = 1 ] && [ "$rc" != 0 ] && [ ! -e "$hw/witness-acceptance/acceptance-collection.json" ]; then ok "AC11 a failing script makes the helper fail and leaves no record"; else bad "AC11 a failing script must fail with no record: rc=$rc"; fi
reset_h; hrun X=1 -- '../x' bin/step.sh a
if [ "$h_ok" = 1 ] && [ "$rc" = 2 ] && [ ! -s "$work/hwlog" ]; then ok "AC11 a step name that is not a plain lower-case word is refused (exit 2) before anything runs"; else bad "AC11 bad step name -> rc=$rc, log: $(cat "$work/hwlog")"; fi
reset_h; hrun X=1 -- extra bin/step.sh extra
if [ "$h_ok" = 1 ] && [ "$rc" = 2 ] && [ ! -s "$work/hwlog" ] && [ ! -s "$work/hwargv" ]; then ok "AC11 a fourth step outside the closed list (extra) is refused (exit 2) before anything runs"; else bad "AC11 unknown step extra -> rc=$rc"; fi
reset_h; for s in scanners acceptance runtime; do hrun X=1 -- "$s" bin/step.sh "$s"; done
got=$(cd "$hw" && find . -path './witness-*' -type f | sed 's|^\./||' | sort | tr '\n' ' ')
if [ "$got" = "witness-acceptance/acceptance-collection.json witness-runtime/runtime-collection.json witness-scanners/scanners-collection.json " ]; then ok "AC12 the three steps are accepted and leave exactly three records, one per step (the next stage verifies the list)"; else bad "AC12 the records: $got"; fi
# ---- REQ-CHAIN-006-AC3 / AC11: bin/check-stage.sh, the fixed dispatcher (verify first, then only the phase's checks) -------------------
dp="$work/dp"; mkdir -p "$dp/bin"; cp "$root/bin/check-stage.sh" "$dp/bin/" 2> /dev/null || true
cat > "$dp/bin/chain-verify.py" <<'EOF'
#!/usr/bin/env bash
echo "verify $*" >> "$DP_LOG"
[ "${VERIFY_FAIL:-}" != "$1" ] || exit 1
if [ "${VERIFY_STRICT:-}" = 1 ]; then   # a record that is not there is refused, as the real verifier refuses it
  for a in "$@"; do case "$prev" in --record|--digests) [ -f "$a" ] || { echo "missing $a" >&2; exit 1; };; esac; prev=$a; done
fi
exit "${VERIFY_RC:-0}"
EOF
for s in check-scan check-fips check-artifacts check-acceptance check-guide; do printf '#!/usr/bin/env bash\necho "%s $*" >> "$DP_LOG"\n' "$s" > "$dp/bin/$s.sh"; done
cat > "$dp/bin/python3" <<'EOF'
#!/usr/bin/env bash
[ "$1 $2" = "-I -B" ] || { echo "python3 not isolated: $*" >> "$DP_LOG"; exit 3; }
shift 3; bash "bin/chain-verify.py" "$@"
EOF
chmod +x "$dp/bin/python3"
drun() { rc=0; : > "$work/dplog"; out=$( (cd "$dp" && PATH="$dp/bin:$PATH" DP_LOG="$work/dplog" VERIFY_RC="${VERIFY_RC:-0}" GITHUB_REF_NAME=v0.3.0 bash bin/check-stage.sh "$@") 2>&1) || rc=$?; }   # a release run always has its tag (Q5)
# ---- REQ-CHAIN-006-AC17 and rule 58: the arm64 target verifies Build's record and Sign's provenance BEFORE it loads or runs anything ----------
cp "$root/bin/check-phase-arm64.sh" "$dp/bin/" 2> /dev/null || true
printf '#!/usr/bin/env bash\necho "docker $*" >> "$DP_LOG"\n' > "$dp/bin/docker"; chmod +x "$dp/bin/docker"
mkdir -p "$dp/witness-build" "$dp/provenance"; : > "$dp/witness-build/build-collection.json"; : > "$dp/witness-build/digests.json"; : > "$dp/provenance/provenance.json"; : > "$dp/provenance/provenance.rekor.json"
arun64() { rc=0; : > "$work/dplog"; out=$( (cd "$dp" && env "$@" PATH="$dp/bin:$PATH" DP_LOG="$work/dplog" GITHUB_REF_NAME=v0.3.0 bash bin/check-phase-arm64.sh) 2>&1) || rc=$?; }
arun64 X=1
if [ "$rc" = 0 ] && [ "$(grep '^verify' "$work/dplog" | cut -d' ' -f2 | tr '\n' ' ')" = "policy stage-start verify " ] && [ "$(grep -c '^check-artifacts' "$work/dplog")" = 1 ] \
   && grep -q '^check-artifacts --arch arm64 --digests witness-build/digests.json ' "$work/dplog" && grep -n '' "$work/dplog" | awk -F: '/verify stage-start/{a=$1} /verify verify/{b=$1} /check-artifacts/{c=$1} END{exit !(a<b && b<c)}'; then ok "AC17 the arm64 target makes the policy, verifies Build's record, verifies Sign's provenance, then runs the arm64 artifact checks on the digest file it verified (rule 58)"; else bad "AC17 arm64 target ran: $(tr '\n' '|' < "$work/dplog" | cut -c1-300)"; fi
arm_stops() { # arm_stops LABEL ENV... : the target fails and nothing of the candidate is loaded or run
  local l=$1; shift; arun64 "$@"
  if [ "$rc" != 0 ] && ! grep -Eq '^(check-artifacts|docker)' "$work/dplog"; then ok "$l"; else bad "$l -> rc=$rc, log: $(tr '\n' '|' < "$work/dplog" | cut -c1-200)"; fi; }
arm_stops "rule 58 a forged Build record (stage-start refuses it): no artifact is loaded, no binary runs" VERIFY_FAIL=stage-start
arm_stops "rule 58 a Sign provenance of the wrong identity (verify refuses it): no artifact is loaded, no binary runs" VERIFY_FAIL=verify
arm_stops "rule 58 no policy for the tag: no artifact is loaded, no binary runs" VERIFY_FAIL=policy
rm -f "$dp/witness-build/build-collection.json"
arm_stops "rule 58 a missing Build record: no artifact is loaded, no binary runs" VERIFY_STRICT=1
: > "$dp/witness-build/build-collection.json"; rm -f "$dp/provenance/provenance.json"
arm_stops "rule 58 a missing Sign provenance: no artifact is loaded, no binary runs" VERIFY_STRICT=1
: > "$dp/provenance/provenance.json"
drun scanners; d_ok=0; [ "$rc" = 0 ] && grep -q '^check-scan' "$work/dplog" && d_ok=1
drun nosuch
if [ "$d_ok" = 1 ] && [ "$rc" = 2 ] && grep -Fq 'unknown phase: nosuch' <<< "$out" && ! grep -q '^check-' "$work/dplog"; then ok "AC3 an unknown phase is refused (exit 2) naming it, and no check runs"; else bad "AC3 unknown phase -> rc=$rc: ${out:0:100}"; fi
VERIFY_RC=1 drun scanners
if [ "$d_ok" = 1 ] && [ "$rc" != 0 ] && ! grep -q '^check-' "$work/dplog"; then ok "AC3 when verifying Build's record fails, no check runs (rule 58)"; else bad "AC3 verify failure -> rc=$rc, log: $(tr '\n' ' ' < "$work/dplog")"; fi
drun scanners
if [ "$rc" = 0 ] && [ "$(grep '^verify' "$work/dplog" | cut -d' ' -f2 | tr '\n' ' ')" = "policy stage-start verify " ] && grep -q '^verify policy make .*--tag ' "$work/dplog" && [ "$(grep '^check-' "$work/dplog" | cut -d' ' -f1 | tr '\n' ' ')" = "check-scan " ]; then ok "AC3 phase scanners: the policy made per tag (Q5), both verifications, then only the scan"; else bad "AC3 phase scanners ran: $(tr '\n' ' ' < "$work/dplog")"; fi
drun acceptance
if [ "$rc" = 0 ] && [ "$(grep '^check-' "$work/dplog" | cut -d' ' -f1,2 | tr '\n' ' ')" = "check-acceptance gradle check-acceptance maven " ]; then ok "AC3 phase acceptance: gradle, then maven, nothing else"; else bad "AC3 phase acceptance ran: $(tr '\n' ' ' < "$work/dplog")"; fi
drun runtime
if [ "$rc" = 0 ] && [ "$(grep '^check-' "$work/dplog" | cut -d' ' -f1,2 | tr '\n' ' ')" = "check-acceptance egress check-acceptance k8s check-fips --digests check-artifacts --digests check-guide --guide " ]; then ok "AC3 phase runtime: egress, k8s, fips, guide, in that order"; else bad "AC3 phase runtime ran: $(tr '\n' ' ' < "$work/dplog")"; fi
EXPECT=136
echo "pass=$pass fail=$failn"
if [ $((pass + failn)) != "$EXPECT" ]; then echo "FAIL case count $((pass + failn)) != expected $EXPECT (a case was skipped or added)"; exit 1; fi
[ "$failn" = 0 ]
