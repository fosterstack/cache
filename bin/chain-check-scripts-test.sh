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
#      results record its source URL, build date and digest; stale (> 48 h; `now` is the runner's `date +%s`, given by a fake date on PATH here: round 1 F4), unfetchable,
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
FAKE_NOW=$(jq -n '"2026-10-10T00:00:00Z" | fromdateiso8601'); export FAKE_NOW   # AC15: the scan's `now`, given by a fake `date` first on PATH (round 1 F4: no variable of the stage's environment sets the clock)
GDB_SUM=972de542534d3461cc3c3849a37a3f917b823de3b9c367e289db0d163519b42b
GDB_FROM="https://grype.anchore.io/databases/v6/vulnerability-db_v6.1.9_2026-10-09T00:33:02Z_1790058641.tar.zst?checksum=sha256%3A$GDB_SUM"
export FAKE_DB_FROM="$GDB_FROM" FAKE_DB_BUILT=2026-10-09T06:30:41Z FAKE_DB_RC=0
export FAKE_OSV_DB_RC=0 FAKE_OSV_ZIP=ok FAKE_OSV_MODIFIED=2026-10-09T20:00:00Z FAKE_OSV_ECOS="Go Debian:12"
# REAL OCI image layouts (round 1 F1): an index of linux/amd64 and linux/arm64 child manifests, each with a config blob and a layer blob, every blob
# under the name of its sha256; the digest Build records is the index blob's. SEED makes two layouts valid and different. LIE_ARCH makes every config say
# another architecture than the index's platform entry (a lying descriptor).
cat > "$work/mkoci.py" <<'PYM'
import hashlib, json, os, sys
root, seed = sys.argv[1], sys.argv[2]
plats = sys.argv[3:] or ["linux/amd64", "linux/arm64"]
lie = os.environ.get("LIE_ARCH", "")
def blob(data):
    h = hashlib.sha256(data).hexdigest()
    d = os.path.join(root, "blobs", "sha256"); os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, h), "wb") as f: f.write(data)
    return "sha256:" + h, len(data)
kids = []
names = {}
for p in plats:
    os_, arch = p.split("/")
    layer, ls = blob(("layer %s %s" % (seed, p)).encode())
    cfg, cs = blob(json.dumps({"architecture": lie or arch, "os": os_, "rootfs": {"type": "layers", "diff_ids": [layer]}, "seed": seed}, sort_keys=True).encode())
    man, ms = blob(json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": cfg, "size": cs},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": layer, "size": ls}]}, sort_keys=True).encode())
    kids.append({"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": man, "size": ms, "platform": {"os": os_, "architecture": arch}})
    names[arch] = {"layer": layer.split(":")[1], "config": cfg.split(":")[1], "manifest": man.split(":")[1]}
idx, isz = blob(json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": kids}, sort_keys=True).encode())
with open(os.path.join(root, "index.json"), "w") as f:
    json.dump({"schemaVersion": 2, "manifests": [{"mediaType": "application/vnd.oci.image.index.v1+json", "digest": idx, "size": isz}]}, f)
with open(os.path.join(root, "oci-layout"), "w") as f: f.write('{"imageLayoutVersion":"1.0.0"}')
names["index"] = idx.split(":")[1]
with open(root.rstrip("/") + ".map", "w") as f: json.dump(names, f)   # blob file names by role, next to the layout (not inside it)
print(idx)
PYM
# Build's digest list for a tree: the image index digests of images/production and images/fips and the sha256 of each archive under its item name
cat > "$work/mkdig.py" <<'PYD'
import hashlib, json, os, re, sys
d = sys.argv[1]
out = {"apk": "sha256:" + "c" * 64}
for v in ("production", "fips"):
    try: out["image-" + v] = json.load(open(os.path.join(d, "images", v, "index.json")))["manifests"][0]["digest"]
    except (OSError, ValueError, KeyError, IndexError): pass
for f in sorted(os.listdir(os.path.join(d, "dist"))):
    m = re.fullmatch(r"(fscache|fscache-fips)_[^_]+_linux_(amd64|arm64)\.tar\.gz", f)
    if m:
        out["archive-%slinux-%s" % ("fips-" if m.group(1) == "fscache-fips" else "", m.group(2))] = "sha256:" + hashlib.sha256(open(os.path.join(d, "dist", f), "rb").read()).hexdigest()
json.dump(out, open(os.path.join(d, "digests.json"), "w"))
PYD
mkdig() { python3 "$work/mkdig.py" "$1"; }
# ---- the throw-away tree and the fake tools ---------------------------------------------------------------------------------
fx="$work/fx"; mkdir -p "$fx/bin" "$fx/images" "$fx/dist" "$fx/.github/policy" "$fx/out"
cp "$root"/bin/check-*.sh "$root"/bin/check-*.py "$root"/bin/chain_items.py "$root"/bin/chain_common.py "$root"/bin/rescan-statement.py "$root"/bin/inspector-gate.py "$root"/bin/loopback-get.sh "$fx/bin/" 2> /dev/null || true
mkdir -p "$fx/.vex"; cp "$root/.vex/fosterstack-cache.openvex.json" "$fx/.vex/"
D1=$(python3 "$work/mkoci.py" "$fx/images/production" production); D2=$(python3 "$work/mkoci.py" "$fx/images/fips" fips)   # images/<variant>/ is an OCI layout directory (PR 2's interface, PROPOSED)
for a in amd64 arm64; do printf 'archive fscache %s\n' "$a" > "$fx/dist/fscache_0.3.0_linux_$a.tar.gz"; printf 'archive fscache-fips %s\n' "$a" > "$fx/dist/fscache-fips_0.3.0_linux_$a.tar.gz"; done
mkdig "$fx"
mkdir -p "$fx/tools/requirements"; printf 'module example.com/a\n' > "$fx/go.mod"; printf 'module example.com/b\n' > "$fx/tools/requirements/go.mod"
printf '{"scanners":["grype","osv-scanner"],"pr_gate":["grype","inspector"]}\n' > "$fx/.github/policy/scanners.json"
fake="$work/fake"; mkdir -p "$fake"
cat > "$work/childdigest.py" <<'PYC'
import json, os, sys
# the fake grype's manifestDigest: the digest of the platform child of the oci-dir index it was asked to scan (FAKE_GRYPE_MD=mismatch|missing break it)
mode = os.environ.get("FAKE_GRYPE_MD", "")
if mode == "missing":
    sys.exit(0)
if mode == "mismatch":
    print("sha256:" + "0" * 64); sys.exit(0)
path, plat = sys.argv[1], sys.argv[2]
idx = json.load(open(os.path.join(path, "index.json")))["manifests"][0]["digest"].split(":")[1]
for m in json.load(open(os.path.join(path, "blobs", "sha256", idx)))["manifests"]:
    pl = m.get("platform") or {}
    if "%s/%s" % (pl.get("os"), pl.get("architecture")) == plat:
        print(m["digest"]); break
PYC
cat > "$work/osvout.py" <<'PYO2'
import json, os, sys
# osv-scanner 2.6.0 --format json --all-packages: results[].packages[] of {package, vulnerabilities[{id, aliases}], groups}; FAKE_OSV_VULNS (a JSON list of
# {"pkg": "name@version", "id": ..., "aliases": [...]}) puts those vulnerabilities on the first packages
n, eco = int(sys.argv[1]), sys.argv[2]
vulns = json.loads(os.environ.get("FAKE_OSV_VULNS") or "[]")
pk = []
for i in range(n):
    name, ver, vs = "p%d" % i, "1", []
    if i < len(vulns):
        name, ver = vulns[i]["pkg"].rsplit("@", 1)
        vs = [{"id": vulns[i]["id"], "aliases": vulns[i].get("aliases", [])}]
    pk.append({"package": {"name": name, "version": ver, "ecosystem": eco}, "vulnerabilities": vs, "groups": []})
print(json.dumps({"results": [{"source": {"path": "/x", "type": "os"}, "packages": pk}]} if n else {"results": []}))
PYO2
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
  gpath=""; gplat=""; gprev=""
  for ga in "\$@"; do case "\$ga" in oci-dir:*) gpath=\${ga#oci-dir:};; esac; [ "\$gprev" != --platform ] || gplat=\$ga; gprev=\$ga; done
  FAKE_MD=""; [ -z "\$gpath" ] || FAKE_MD=\$(python3 "$work/childdigest.py" "\$gpath" "\$gplat"); export FAKE_MD
  case " \$* " in *" --platform linux/arm64 "*) export FAKE_GRYPE_MATCHES="\${FAKE_GRYPE_ARM64_MATCHES-\${FAKE_GRYPE_MATCHES:-[]}}";; esac
  python3 -c 'import json,os; st={"schemaVersion":"v6.1.9","from":os.environ["FAKE_DB_FROM"],"built":os.environ["FAKE_DB_BUILT"],"path":"/.cache/grype/db/6/vulnerability.db","valid":True}; st={k:v for k,v in st.items() if v != ""}; print(json.dumps({"matches":json.loads(os.environ.get("FAKE_GRYPE_MATCHES","[]")),"source":{"type":"image","target":({"manifestDigest":os.environ["FAKE_MD"]} if os.environ.get("FAKE_MD") else {})},"descriptor":{"name":"grype","version":"9.9.9","db":{"status":st,"providers":{}}}}))'
else
  eco=Debian:12; case " \$* " in *go.mod*) eco=Go;; esac
  python3 "$work/osvout.py" "\$n" "\$eco"
fi
exit $2
EOF
  chmod +x "$fake/$1"
}
mkfake grype 0 120; mkfake osv-scanner 0 80; mkfake trivy 0 5
printf '#!/usr/bin/env bash\n[ "$*" != "+%%s" ] || { echo "$FAKE_NOW"; exit 0; }\nexec /bin/date "$@"\n' > "$fake/date"; chmod +x "$fake/date"
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
mkdist() { rm -f "$fx"/dist/*; for f in "$@"; do printf 'archive %s\n' "$f" > "$fx/dist/$f"; done; mkdig "$fx"; }
mkdist "${FOUR[@]}"; want_ok "PLAT-001-AC1 exactly the four Linux archives: the scan runs" "${SCAN[@]}"
mkdist "${FOUR[@]}" fscache_0.3.0_linux_riscv64.tar.gz; want_fail "PLAT-001-AC1 a fifth Linux archive fails" "exactly the four" "${SCAN[@]}"
mkdist "${FOUR[@]}" fscache_0.3.0_darwin_arm64.tar.gz; want_fail "PLAT-001-AC1 a darwin archive fails" darwin "${SCAN[@]}"
mkdist "${FOUR[@]}" fscache_0.3.0_windows_amd64.zip; want_fail "PLAT-001-AC1 a windows archive of any kind fails" windows "${SCAN[@]}"
mkdist "${FOUR[@]}" fscache_0.3.0_Darwin_amd64.zip; want_fail "PLAT-001-AC1 a darwin file in any case fails" darwin "${SCAN[@]}"
mkdist "${FOUR[@]:0:3}"; want_fail "PLAT-001-AC1 a missing archive fails" "exactly the four" "${SCAN[@]}"
mkdist "${FOUR[@]:0:3}" fscache-fips_0.4.0_linux_arm64.tar.gz; want_fail "PLAT-001-AC1 four files that are not the four archives of one version fail" "exactly the four" "${SCAN[@]}"
# the platform lines of the documents (factual lines only): the README table lists no darwin or windows binary, the next release's notes say so once with the container-image pointer
docs_root="$(cd "$(dirname "$0")/.." && pwd)"
if ! grep -E '^\| (FIPS binaries|Binaries) .*(darwin|windows)' "$docs_root/README.md" > /dev/null 2>&1; then ok "PLAT-001-AC1 the README binary table lists no darwin or windows platform"; else bad "PLAT-001-AC1 the README binary table lists no darwin or windows platform"; fi
if [ ! -f "$docs_root/docs/next-release-notes.md" ] || [ "$(grep -c 'No macOS or Windows binaries are shipped; use the container image' "$docs_root/docs/next-release-notes.md")" = 1 ]; then ok "PLAT-001-AC1 the next release's notes carry the Linux-only line once (or the release flow has moved it to the changelog)"; else bad "PLAT-001-AC1 the next release's notes carry the Linux-only line once (or the release flow has moved it to the changelog)"; fi
mkdist "${FOUR[@]}"
mkfake grype 1 120
want_fail "AC4 a scanner reports findings: the script fails naming it" grype "${SCAN[@]}"
# REQ-REL-004-AC1 (owner rule, register rows 18 and 38: block at any severity, the published VEX the only exception): grype's own --fail-on negligible does not fail
# on a finding of UNKNOWN severity, so the script judges grype's JSON result: any match that survived the VEX fails, whatever its severity, and a result with no
# readable matches list is a scan that did not run.
mkfake grype 0 120; mkfake osv-scanner 0 80
GM='[{"vulnerability":{"id":"CVE-2099-0001","severity":"Unknown"},"artifact":{"name":"x","version":"1"}}]'
FAKE_GRYPE_MATCHES="$GM" want_fail "AC4 a grype finding of UNKNOWN severity (exit 0, --fail-on negligible does not fire) fails: no VEX statement covers it" "does not except" "${SCAN[@]}"
GM='[{"vulnerability":{"id":"CVE-2099-0002","severity":"Negligible"},"artifact":{"name":"x","version":"1"}}]'
FAKE_GRYPE_MATCHES="$GM" want_fail "AC4 a grype finding of NEGLIGIBLE severity that exits 0 also fails" "does not except" "${SCAN[@]}"
FAKE_GRYPE_MATCHES='"not a list"' want_fail "AC4 a grype result whose matches is not a list is a scan that did not run" "matches" "${SCAN[@]}"
FAKE_GRYPE_MATCHES='[]' want_ok "AC4 grype with no match left after the VEX passes" "${SCAN[@]}"
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
cp "$work/dig.bak" "$fx/digests.json"; mv "$fx/images/fips" "$fx/images/fips.off"
want_fail "AC4 a missing image layout directory fails naming it" fips "${SCAN[@]}"
mv "$fx/images/fips.off" "$fx/images/fips"
rm -rf "$fx/images/fips"; : > "$fx/images/fips.tar"
want_fail "AC4 a docker-save style tarball where the OCI layout directory belongs is refused (PR 2's interface)" layout "${SCAN[@]}"
rm -f "$fx/images/fips.tar"; mkdir -p "$fx/images/fips"; printf '{"schemaVersion":2,"manifests":[]}' > "$fx/images/fips/index.json"
want_fail "AC4 an image directory without oci-layout is not a layout and is refused" layout "${SCAN[@]}"
rm -rf "$fx/images/fips"; python3 "$work/mkoci.py" "$fx/images/fips" fips > /dev/null
want_ok "AC4 grype scans each image layout directory by oci-dir: and osv-scanner a tar made of it" "${SCAN[@]}"
if grep -Eq '^grype oci-dir:images/(production|fips) ' "$work/log" && ! grep -q 'oci-archive' "$work/log" && grep -Eq '^osv-scanner scan image --archive .*\.tar$' "$work/log" 2> /dev/null; then ok "AC4 the scanner argv carries the layout: oci-dir for grype, an archive made of the layout for osv"; else bad "AC4 layout argv: $(grep -E '^(grype|osv)' "$work/log" | head -4 | cut -c1-160 | tr '\n' '|')"; fi
# ---- chain-v030 review S1 (REQ-CHAIN-006-AC4): grype scans each platform child of the multi-platform index, both required --------------
# `grype oci-dir:` on the index with no platform scans only the runner's own platform (linux/amd64): the arm64 child's packages were never scanned while the
# verdict was recorded for the index digest. Each variant is now scanned once per child (--platform linux/amd64, linux/arm64), each child's own manifest
# digest is recorded, and an index that lacks either child fails.
mkfake grype 0 120; mkfake osv-scanner 0 80; : > "$work/log"
want_ok "AC4 S1 the layouts with both children pass" "${SCAN[@]}"
for v in production fips; do for a in amd64 arm64; do
  if grep -Eq "^grype oci-dir:images/$v .*--platform linux/$a( |\$)" "$work/log"; then ok "AC4 S1 grype scanned the $v image's linux/$a child explicitly"; else bad "AC4 S1 no grype call with --platform linux/$a on the $v image"; fi
done; done
if grep -E '^grype oci-dir:' "$work/log" | grep -qv -- '--platform linux/'; then bad "AC4 S1 a grype image scan ran without a platform"; else ok "AC4 S1 no grype image scan runs without a platform"; fi
for v in production fips; do for a in amd64 arm64; do
  cd_=$(jq -r ".$a.manifest" "$fx/images/$v.map")
  if jq -e --arg n "$v/linux/$a" --arg d "sha256:$cd_" '.scanners[] | select(.name == "grype") | .subjects | map(select(.name == $n and .digest == $d and .packages > 0 and .verdict == "pass")) | length == 1' "$fx/out/scan-results.json" > /dev/null 2>&1; then ok "AC4 S1 the results record the $v linux/$a child by its own manifest digest"; else bad "AC4 S1 no grype subject $v/linux/$a with digest sha256:$cd_"; fi
done; done
GA='[{"vulnerability":{"id":"CVE-2099-0777","severity":"High"},"artifact":{"name":"arm-only","version":"1"}}]'
FAKE_GRYPE_ARM64_MATCHES="$GA" FAKE_GRYPE_MATCHES='[]' want_fail "AC4 S1 a vulnerability only in the arm64 child blocks the scan" "does not except" "${SCAN[@]}"
FAKE_GRYPE_ARM64_MATCHES='[]' FAKE_GRYPE_MATCHES="$GA" want_fail "AC4 S1 a vulnerability only in the amd64 child still blocks" "does not except" "${SCAN[@]}"
keepp="$work/keep-prod"; rm -rf "$keepp"; cp -R "$fx/images/production" "$keepp"; cp "$fx/images/production.map" "$work/keep-prod.map"; cp "$fx/digests.json" "$work/dig.s1"
rm -rf "$fx/images/production"; python3 "$work/mkoci.py" "$fx/images/production" production linux/amd64 > /dev/null; mkdig "$fx"
want_fail "AC4 S1 an index with no linux/arm64 child fails naming the platform" "linux/arm64" "${SCAN[@]}"
rm -rf "$fx/images/production"; cp -R "$keepp" "$fx/images/production"; cp "$work/keep-prod.map" "$fx/images/production.map"; cp "$work/dig.s1" "$fx/digests.json"
want_ok "AC4 S1 both children again: the scan passes" "${SCAN[@]}"
# S1 rulings (cache#550): the index holds exactly one linux/amd64 and one linux/arm64 image descriptor, another real platform fails and is named,
# the attestation (unknown/unknown) is allowed; and grype's own report of the manifest it scanned must equal the child digest recorded.
keepq="$work/keep-prod2"; rm -rf "$keepq"; cp -R "$fx/images/production" "$keepq"; cp "$fx/images/production.map" "$work/keep-prod2.map"; cp "$fx/digests.json" "$work/dig.s1b"
restore_prod() { rm -rf "$fx/images/production"; cp -R "$keepq" "$fx/images/production"; cp "$work/keep-prod2.map" "$fx/images/production.map"; cp "$work/dig.s1b" "$fx/digests.json"; }
rm -rf "$fx/images/production"; python3 "$work/mkoci.py" "$fx/images/production" production linux/amd64 linux/arm64 linux/s390x > /dev/null; mkdig "$fx"
want_fail "AC4 S1 an index with amd64, arm64 and s390x fails naming linux/s390x" "linux/s390x" "${SCAN[@]}"
rm -rf "$fx/images/production"; python3 "$work/mkoci.py" "$fx/images/production" production linux/amd64 linux/arm64 unknown/unknown > /dev/null; mkdig "$fx"
want_ok "AC4 S1 an index with amd64, arm64 and an unknown/unknown attestation passes" "${SCAN[@]}"
restore_prod
FAKE_GRYPE_MD=mismatch want_fail "AC4 S1 grype reporting another manifest digest than the child recorded fails" "names manifest digest" "${SCAN[@]}"
FAKE_GRYPE_MD=missing want_fail "AC4 S1 grype reporting no manifest digest fails" "names manifest digest" "${SCAN[@]}"
want_ok "AC4 S1 grype reporting each child's own digest passes" "${SCAN[@]}"
# ---- round 1 F1 (Codex A1, B1): the bytes Check reads are the bytes Build recorded -------------------------------------------------------------
# stage-start authenticates digests.json; the layouts and archives it downloads must be bound to it before any scan, load or run (an index.json that
# merely exists is no binding): the layout is re-derived from the digest (index, child manifests, every blob re-hashed) and each archive re-hashed.
nothing_ran() { ! grep -Eq '^(grype|osv-scanner) (oci-dir|scan|file)|^docker (load|run)' "$work/log"; }
keep="$work/keep-fips"; rm -rf "$keep"; cp -R "$fx/images/fips" "$keep"; cp "$fx/images/fips.map" "$work/keep-fips.map"   # (the .map written by mkoci.py names the blobs by role)
rm -rf "$fx/images/fips"; python3 "$work/mkoci.py" "$fx/images/fips" other > /dev/null
want_fail "AC4 F1 a valid OCI layout that is not the image Build recorded (digests.json intact) is refused naming the image" image-fips "${SCAN[@]}"
if nothing_ran; then ok "AC4 F1 nothing was scanned behind the refused layout"; else bad "AC4 F1 a scanner ran on a layout that is not Build's: $(grep -E '^(grype|osv)' "$work/log" | head -2 | cut -c1-100 | tr '\n' '|')"; fi
rm -rf "$fx/images/fips"; cp -R "$keep" "$fx/images/fips"
printf 'tampered\n' > "$fx/images/fips/blobs/sha256/$(jq -r .arm64.layer "$work/keep-fips.map")"
want_fail "AC4 F1 a layer blob that no longer hashes to its name (every manifest and index blob intact) is refused" image-fips "${SCAN[@]}"
rm -rf "$fx/images/fips"; cp -R "$keep" "$fx/images/fips"
rm -f "$fx/images/fips/blobs/sha256/$(jq -r .arm64.manifest "$work/keep-fips.map")"
want_fail "AC4 F1 a child manifest blob that is missing from the layout is refused" image-fips "${SCAN[@]}"
rm -rf "$fx/images/fips"; cp -R "$keep" "$fx/images/fips"
rm -rf "$fx/images/production"; python3 "$work/mkoci.py" "$fx/images/production" other > /dev/null
want_fail "AC4 F1 the production layout replaced by another valid one is refused naming the image" image-production "${SCAN[@]}"
rm -rf "$fx/images/production"; python3 "$work/mkoci.py" "$fx/images/production" production > /dev/null
want_ok "AC4 F1 the layouts and archives Build recorded still pass the scan" "${SCAN[@]}"
printf 'another archive\n' > "$fx/dist/fscache_0.3.0_linux_amd64.tar.gz"
want_fail "AC4 F1 an archive that is not the one Build recorded (digests.json intact) is refused naming the file" fscache_0.3.0_linux_amd64.tar.gz "${SCAN[@]}"
if nothing_ran; then ok "AC4 F1 no archive was scanned behind the refused one"; else bad "AC4 F1 a scanner ran on an archive that is not Build's"; fi
mkdist "${FOUR[@]}"
cp "$fx/digests.json" "$work/dig.f1"; python3 - "$fx/digests.json" <<'PYX'
import json, sys
d = json.load(open(sys.argv[1])); d.pop("archive-fips-linux-arm64"); json.dump(d, open(sys.argv[1], "w"))
PYX
want_fail "AC4 F1 a digest list without the digest of an archive that is scanned is refused naming it" archive-fips-linux-arm64 "${SCAN[@]}"
cp "$work/dig.f1" "$fx/digests.json"
# ---- round 1 F3 (Codex A2): osv-scanner's findings are held to the published VEX, as the rescan holds them (grype reads it itself) ----
# The decision is the rescan filter's: a not_affected or fixed statement whose vulnerability name or alias equals one of the finding's ids, whose product
# is this image repository (scoped to nothing or to the variant) or the Go product, and whose subcomponents (when it names any) include the finding's
# package at its version. Every finding must be covered; one that is not, an unreadable VEX or a failure with nothing parseable to cover fails.
VBUSY='[{"pkg": "busybox@1.37.0", "id": "CVE-2025-60876"}]'
mkfake grype 0 120; mkfake osv-scanner 1 80
FAKE_OSV_VULNS="$VBUSY" want_ok "AC4 F3 osv-scanner exit 1 on a finding the published VEX excepts (CVE-2025-60876 on busybox 1.37.0) passes" "${SCAN[@]}"
if jq -e '[.scanners[] | select(.name == "osv-scanner") | .subjects[] | select(.name == "production")] | length == 1 and .[0].verdict == "pass" and .[0].vex_suppressed == 1' "$fx/out/scan-results.json" > /dev/null 2>&1; then ok "AC4 F3 the result says how many findings the VEX excepted on the subject"; else bad "AC4 F3 vex_suppressed missing from the osv subject: $(jq -c '[.scanners[] | select(.name == "osv-scanner") | .subjects[0]]' "$fx/out/scan-results.json" 2>&1 | cut -c1-200)"; fi
FAKE_OSV_VULNS='[{"pkg": "github.com/golang-jwt/jwt/v4@v4.5.0", "id": "GHSA-29wx-vh33-7x7r", "aliases": ["CVE-2024-51744", "GO-2024-3250"]}]' \
  want_ok "AC4 F3 a finding whose id differs from the statement's name but whose alias equals it is excepted (the OSV id is the GHSA, the VEX names the CVE)" "${SCAN[@]}"
FAKE_OSV_VULNS='[{"pkg": "busybox@1.36.0", "id": "CVE-2025-60876"}]' want_fail "AC4 F3 the same CVE on another version of the package than the statement's subcomponent is not excepted" osv-scanner "${SCAN[@]}"
FAKE_OSV_VULNS='[{"pkg": "libssl3@3.0.0", "id": "CVE-2025-99999"}]' want_fail "AC4 F3 a finding no statement names is not excepted" osv-scanner "${SCAN[@]}"
FAKE_OSV_VULNS='[{"pkg": "busybox@1.37.0", "id": "CVE-2025-60876"}, {"pkg": "libssl3@3.0.0", "id": "CVE-2025-99999"}]' want_fail "AC4 F3 one excepted and one uncovered finding: the uncovered one fails the scan" osv-scanner "${SCAN[@]}"
printf '{"statements": "not a list"}\n' > "$fx/.vex/fosterstack-cache.openvex.json"
FAKE_OSV_VULNS="$VBUSY" want_fail "AC4 F3 an unreadable VEX document excepts nothing (fail closed)" osv-scanner "${SCAN[@]}"
cp "$root/.vex/fosterstack-cache.openvex.json" "$fx/.vex/"
mkfake osv-scanner 0 80
# ---- REQ-CHAIN-006-AC15: fresh vulnerability databases from the scanner's own host --------------------------------------------
printf '{"scanners":["grype"]}\n' > "$fx/.github/policy/scanners.json"; rm -f "$fx/out/scan-results.json"
want_ok "AC15 a fresh grype database (built 17.5 h before now) from grype.anchore.io: the scan proceeds" "${SCAN[@]}"
if [ -f "$fx/out/scan-results.json" ] && jq -e --arg u "$GDB_FROM" --arg s "sha256:$GDB_SUM" '.scanners[0] | .db_source_url == $u and .db_built_or_published == "2026-10-09T06:30:41Z" and .db_digest == $s and .db_source_basis == "observed"' "$fx/out/scan-results.json" > /dev/null 2>&1; then ok "AC15 the results carry grype's database source URL (basis: observed), build date and digest"; else bad "AC15 db fields in scan-results.json: $(jq -c '.scanners[0] | {db_source_url, db_built_or_published, db_digest}' "$fx/out/scan-results.json" 2>&1 | cut -c1-160)"; fi
u=$(grep -n '^grype db update$' "$work/log" | head -1 | cut -d: -f1 || true); s=$(grep -n '^grype .*\(oci-dir\|file\):' "$work/log" | head -1 | cut -d: -f1 || true)
if [ -n "$u" ] && [ -n "$s" ] && [ "$u" -lt "$s" ]; then ok "AC15 the database is fetched fresh (grype db update) before the first scan"; else bad "AC15 db update (line ${u:-none}) must come before the first scan (line ${s:-none})"; fi
FAKE_DB_BUILT=2026-10-07T00:00:00Z want_fail "AC15 a database built 72 h before now fails closed" "older than 48 hours" "${SCAN[@]}"
# round 1 F4 (Codex A3): the clock is the runner's. A CHECK_SCAN_NOW in the environment (an older `now` makes any database fresh) is refused, never read.
OLD=$(jq -n '"2026-10-07T00:00:00Z" | fromdateiso8601')
CHECK_SCAN_NOW=$OLD FAKE_DB_BUILT=2026-10-07T00:00:00Z want_fail "AC15 F4 an inherited CHECK_SCAN_NOW does not make a 72 h old database fresh: the variable is refused" CHECK_SCAN_NOW "${SCAN[@]}"
CHECK_SCAN_NOW=$OLD want_fail "AC15 F4 an inherited CHECK_SCAN_NOW is refused even beside a fresh database (no silent use of a variable the stage cannot set)" CHECK_SCAN_NOW "${SCAN[@]}"
FAKE_NOW=$(jq -n '"2026-10-12T00:00:00Z" | fromdateiso8601') want_fail "AC15 F4 the runner's clock decides: a database built 2026-10-09 is stale on 2026-10-12" "older than 48 hours" "${SCAN[@]}"
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
echo "docker $* ${DOCKER_DEFAULT_PLATFORM:+--platform $DOCKER_DEFAULT_PLATFORM}" >> "$FAKE_LOG"; mkdir -p "$FAKE_DIR"
case "$1" in
  load) [ "$(tar -tf "${3:-x}" 2> /dev/null | grep -c 'index.json')" -ge 1 ] || { echo "docker: load: not an OCI layout archive" >&2; exit 1; }
        img=$(basename "${3:-x}" .tar); echo "Loaded image: fscache:$img";;
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
# round 1 F5 (Codex A4, B5): the note is compared whole, with the boolean, for both postures; "v1.0.01" is not v1.0.0
for bad_note in "active (Go validated module v1.0.01, CMVP cert #5247)" "active (Go validated module v1.0.0-other, CMVP cert #5247)" "active (Go validated module v1.0.0)" \
                "active (Go validated module v1.0.0, CMVP cert #5247) and more" "active (Go validated module v1.0.0, CMVP cert #5248)" "off (validated module v1.0.0 linked, mode disabled at runtime)"; do
  resetf; st fips "$(jq -nc --arg n "$bad_note" '{fips140: true, fips140_note: $n}')"
  want_fail "AC6 F5 a -fips note that is not exactly the validated-module line fails naming fips: $bad_note" fips "${FIPS[@]}"
done
# round 2 (Codex B): a trailing newline in a note is part of the note (command substitution must not drop it)
resetf; st fips "$(jq -nc '{fips140: true, fips140_note: "active (Go validated module v1.0.0, CMVP cert #5247)\n"}')"
want_fail "AC6 round 2 the exact -fips note plus a trailing newline fails naming fips" fips "${FIPS[@]}"
resetf; st production "$(jq -nc '{fips140: false, fips140_note: "off\n"}')"
want_fail "AC6 round 2 the production note off plus a trailing newline fails naming production" production "${FIPS[@]}"
resetf; st fips '{"fips140":false,"fips140_note":"active (Go validated module v1.0.0, CMVP cert #5247)"}'
want_fail "AC6 F5 the exact -fips note with fips140 false (a contradictory status) fails naming fips" fips "${FIPS[@]}"
resetf; st production '{"fips140":false,"fips140_note":"active (Go validated module v1.0.0, CMVP cert #5247)"}'
want_fail "AC6 F5 production reporting fips140 false but an active validated-module note (contradictory) fails naming production" production "${FIPS[@]}"
resetf; st production '{"fips140":true,"fips140_note":"off"}'
want_fail "AC6 F5 production reporting fips140 true with the note off (contradictory) fails naming production" production "${FIPS[@]}"
resetf; st production '{"fips140":false,"fips140_note":"off (validated module v1.0.0 linked, mode disabled at runtime)"}'
want_fail "AC6 F5 production whose note is not exactly off (the validated module is linked: crossed variants) fails naming production" production "${FIPS[@]}"
resetf; st fips '{"fips140":true,"fips140_note":"active (Go validated module v1.0.0, CMVP cert #5247)"}'; rm -f "$fx/out/fips-result.json"; run "${FIPS[@]}"
if [ "$rc" = 0 ] && jq -e '[.images[] | select(.name == "fips")][0] | .fips140 == true and .validated_module == "v1.0.0"' "$fx/out/fips-result.json" > /dev/null 2>&1 && ! grep -q 5247 "$fx/out/fips-result.json"; then ok "AC6 F5 the exact line passes and the result names the module version and no certificate number"; else bad "AC6 F5 exact -fips line -> rc=$rc: ${out:0:140}"; fi
# round 1 F1: the candidate image is the one Build recorded, checked before it is loaded or started
for v in fips production; do
  resetf; rm -rf "$work/keep-$v"; cp -R "$fx/images/$v" "$work/keep-$v"; rm -rf "$fx/images/$v"; python3 "$work/mkoci.py" "$fx/images/$v" other > /dev/null
  want_fail "AC6 F1 a valid OCI layout that is not Build's $v image (digests.json intact) is refused naming the image" "image-$v" "${FIPS[@]}"
  if ! grep -q '^docker' "$work/log"; then ok "AC6 F1 nothing was loaded or started behind the refused $v layout"; else bad "AC6 F1 docker ran on a layout that is not Build's: $(head -2 "$work/log" | tr '\n' '|')"; fi
  rm -rf "$fx/images/$v"; cp -R "$work/keep-$v" "$fx/images/$v"
done
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
                note = os.environ.get("FAKE_FIPS_NOTE", "active (Go validated module v1.0.0, CMVP cert #5247)"); on = os.environ.get("FAKE_FIPS_BOOL", "true") == "true"
            elif forced:
                note = os.environ.get("FAKE_FORCED_NOTE", "active (fips140 mode forced at runtime; not the validated-module build)"); on = os.environ.get("FAKE_FORCED_BOOL", "true") == "true"
            else:
                note = os.environ.get("FAKE_STD_NOTE", "off"); on = os.environ.get("FAKE_STD_BOOL", "false") == "true"
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
  mkdig "$fa"
}
mkarch "$fa/dist"
# OCI image layout DIRECTORIES as Build writes them (real manifests, configs and layers: mkoci.py above)
python3 "$work/mkoci.py" "$fa/images/production" production > /dev/null; python3 "$work/mkoci.py" "$fa/images/fips" fips > /dev/null
python3 "$work/mkoci.py" "$fa/images/fips-amd64only" fips linux/amd64 > /dev/null
mkdig "$fa"
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
echo "docker $* ${DOCKER_DEFAULT_PLATFORM:+--platform $DOCKER_DEFAULT_PLATFORM}" >> "$FAKE_LOG"; mkdir -p "$FAKE_DIR"
case "$1" in
  load) [ "$(tar -tf "${3:-x}" 2> /dev/null | grep -c 'index.json')" -ge 1 ] || { echo "docker: load: not an OCI layout archive" >&2; exit 1; }
        echo "Loaded image: fscache:$(basename "${3:-x}" .tar)";;
  run)
    ep=""; img=""; detach=0; nm=""
    for ((i=2; i<=$#; i++)); do a=${!i}; j=$((i+1)); case "$a" in --entrypoint) ep=${!j};; --name) nm=${!j};; -d) detach=1;; fscache:*) img=$a;; localhost/fscache-*-image) img=${a#localhost/fscache-}; img=fscache:${img%-image};; esac; done
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
  cp "$root"/bin/check-artifacts.sh "$root"/bin/check-image-platforms.py "$root"/bin/check-bind.py "$root"/bin/chain_items.py "$root"/bin/chain_common.py "$root"/bin/loopback-get.sh "$fa/bin/" 2> /dev/null || true
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
tar -czf "$fa/dist/fscache-fips_0.3.0_linux_amd64.tar.gz" -C "$fa/bad" fscache-fips; mkdig "$fa"
afail "PLAT-001-AC1 a binary that exits at once does not execute: fails naming healthz" healthz -- "${ART[@]}"
# REQ-CHAIN-006-AC17 (advisor 0385): the same checks for the linux/arm64 binaries and images, run by the check-arm64 job on an arm64 runner
mkarch "$fa/dist"
aok "AC17 --arch arm64: the arm64 binaries execute, the postures are truthful, the images have no shell and serve: exit 0" -- "${ART[@]}" --arch arm64
if grep -Fq -- '--platform linux/arm64' "$work/log" && [ -f "$fa/out/artifacts-result-arm64.json" ] && jq -e '.arch == "arm64" and .production.digest and .fips.digest' "$fa/out/artifacts-result-arm64.json" > /dev/null 2>&1; then ok "AC17 the arm64 images run with --platform linux/arm64 and the result names the arch and the same candidate digests"; else bad "AC17 arm64 run: no --platform linux/arm64, or artifacts-result-arm64.json incomplete"; fi
arun -- "${ART[@]}"; if ! grep -Fq -- '--platform' "$work/log"; then ok "AC17 the default (amd64) run passes no --platform"; else bad "AC17 the amd64 run passed --platform"; fi
# round 1 F1: the images and archives are the ones Build recorded, bound before anything is loaded or executed
mkarch "$fa/dist"
rm -rf "$work/keep-fa"; cp -R "$fa/images/fips" "$work/keep-fa"; rm -rf "$fa/images/fips"; python3 "$work/mkoci.py" "$fa/images/fips" other > /dev/null
afail "ART F1 a valid OCI layout that is not Build's -fips image (digests.json intact) is refused naming the image" image-fips -- "${ART[@]}"
if ! grep -Eq '^docker (load|run)' "$work/log"; then ok "ART F1 nothing was loaded or started behind the refused layout"; else bad "ART F1 docker ran on a layout that is not Build's"; fi
rm -rf "$fa/images/fips"; cp -R "$work/keep-fa" "$fa/images/fips"
mkdir -p "$fa/real2"; { cat "$fa/real/fscache"; echo '# not the binary Build recorded'; } > "$fa/real2/fscache"; chmod +x "$fa/real2/fscache"
tar -czf "$fa/dist/fscache_0.3.0_linux_amd64.tar.gz" -C "$fa/real2" fscache
afail "ART F1 an archive that is not the one Build recorded (a runnable binary, digests.json intact) is refused naming the file" fscache_0.3.0_linux_amd64.tar.gz -- "${ART[@]}"
if ! grep -Eq '^docker (load|run)' "$work/log" && ! ls "$work"/fakedir/srv-* > /dev/null 2>&1; then ok "ART F1 the foreign archive's binary was not executed"; else bad "ART F1 something ran behind the refused archive"; fi
mkarch "$fa/dist"
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
# round 1 F5: every posture is compared whole and together with its boolean; "v1.0.01" is not v1.0.0
afail "FIPS-002-AC1 F5 a -fips note with the module version v1.0.01 (a prefix match accepted it) fails" "fips build" FAKE_FIPS_NOTE='active (Go validated module v1.0.01, CMVP cert #5247)' -- "${ART[@]}"
afail "FIPS-002-AC1 F5 a -fips note with the module v1.0.0-other fails" "fips build" FAKE_FIPS_NOTE='active (Go validated module v1.0.0-other, CMVP cert #5247)' -- "${ART[@]}"
afail "FIPS-002-AC1 F5 a -fips note without the certificate line fails" "fips build" FAKE_FIPS_NOTE='active (Go validated module v1.0.0)' -- "${ART[@]}"
afail "FIPS-002-AC1 F5 the exact -fips note with fips140 false (a contradictory status) fails" "fips build" FAKE_FIPS_BOOL=false -- "${ART[@]}"
afail "FIPS-002-AC1 F5 the standard build with the note off but fips140 true (contradictory) fails" "standard" FAKE_STD_BOOL=true -- "${ART[@]}"
afail "FIPS-002-AC1 F5 the standard build whose note is not exactly off fails" "standard" FAKE_STD_NOTE='off (validated module v1.0.0 linked, mode disabled at runtime)' -- "${ART[@]}"
afail "FIPS-002-AC1 F5 the forced build reporting fips140 false with the forced note (contradictory) fails" "forced" FAKE_FORCED_BOOL=false -- "${ART[@]}"
afail "FIPS-002-AC1 F5 the forced build whose note only starts like the forced line fails" "forced" FAKE_FORCED_NOTE='active (fips140 mode forced at runtime; not the validated-module build) and more' -- "${ART[@]}"
afail "FIPS-002-AC1 round 2 the -fips note plus a trailing newline fails" "fips build" FAKE_FIPS_NOTE=$'active (Go validated module v1.0.0, CMVP cert #5247)\n' -- "${ART[@]}"
afail "FIPS-002-AC1 round 2 the standard note off plus a trailing newline fails" "standard" FAKE_STD_NOTE=$'off\n' -- "${ART[@]}"
afail "FIPS-002-AC1 the standard default reporting active fails" "standard" FAKE_STD_NOTE='active (x)' -- "${ART[@]}"
afail "FIPS-001-AC2 the forced-standard build claiming the validated module fails" "forced" FAKE_FORCED_NOTE='active (Go validated module v1.0.0, CMVP cert #5247)' -- "${ART[@]}"
afail "FIPS-002-AC1 the forced-standard build reporting off (not its true state) fails" "forced" FAKE_FORCED_NOTE=off -- "${ART[@]}"
afail "PLAT-003-AC1 a shell at /bin/sh in the production image fails naming production" production FAKE_SHELL="production:/bin/sh" -- "${ART[@]}"
afail "PLAT-003-AC1 a shell at /busybox/sh in the -fips image fails naming fips" fips FAKE_SHELL="fips:/busybox/sh" -- "${ART[@]}"
afail "PLAT-003-AC1 a shell at another path (/usr/bin/bash) fails" shell FAKE_SHELL="production:/usr/bin/bash" -- "${ART[@]}"
mv "$fa/images/fips" "$work/fips.keep"; cp -R "$fa/images/fips-amd64only" "$fa/images/fips"; mkdig "$fa"
afail "PLAT-002-AC1 an image archive without the linux/arm64 platform entry fails naming it" linux/arm64 -- "${ART[@]}"
rm -rf "$fa/images/fips"; mv "$work/fips.keep" "$fa/images/fips"; mkdig "$fa"
cp "$fa/digests.json" "$work/dig.keep"; printf '{"image-production":"%s"}\n' "$D1" > "$fa/digests.json"
afail "ART a digest list without the -fips image digest fails" image-fips -- "${ART[@]}"
cp "$work/dig.keep" "$fa/digests.json"
mv "$fa/images/production" "$fa/images/production.off"
afail "ART a missing production image fails naming it" production -- "${ART[@]}"
mv "$fa/images/production.off" "$fa/images/production"
# round 1 F1: the platform helper reads the manifests and configs the platform entries refer to (a descriptor that merely says linux/arm64 is not an arm64 image)
plat() { local d=$1; rc=0; out=$(python3 "$root/bin/check-image-platforms.py" "$d" 2>&1) || rc=$?; }
plat_want_fail() { local l=$1 w=$2; plat "$3"; if [ "$rc" = 1 ] && grep -Fq -- "$w" <<< "$out"; then ok "$l (caught: ${out:0:70})"; else bad "$l -> rc=$rc, wanted exit 1 naming '$w': ${out:0:140}"; fi; }
pl="$work/pl"; mkdir -p "$pl"
python3 "$work/mkoci.py" "$pl/good" good > /dev/null
plat "$pl/good"; if [ "$rc" = 0 ] && [ "$out" = "$(printf 'linux/amd64\nlinux/arm64')" ]; then ok "PLAT-002-AC1 F1 a real two-platform layout lists linux/amd64 and linux/arm64"; else bad "PLAT-002-AC1 F1 real layout -> rc=$rc: $out"; fi
cp -R "$pl/good" "$pl/nomanifest"; rm -f "$pl/nomanifest/blobs/sha256/$(jq -r .arm64.manifest "$pl/good.map")"
plat_want_fail "PLAT-002-AC1 F1 a platform entry whose manifest blob is missing is not a platform of the image" linux/arm64 "$pl/nomanifest"
cp -R "$pl/good" "$pl/badhash"; printf '{}\n' > "$pl/badhash/blobs/sha256/$(jq -r .arm64.manifest "$pl/good.map")"
plat_want_fail "PLAT-002-AC1 F1 a manifest blob that does not hash to its name is refused" "hash" "$pl/badhash"
LIE_ARCH=amd64 python3 "$work/mkoci.py" "$pl/lie" lie > /dev/null
plat_want_fail "PLAT-002-AC1 F1 a linux/arm64 entry whose config says amd64 is refused naming the platform" linux/arm64 "$pl/lie"
cp -R "$pl/good" "$pl/nocfg"; rm -f "$pl/nocfg/blobs/sha256/$(jq -r .arm64.config "$pl/good.map")"
plat_want_fail "PLAT-002-AC1 F1 a platform entry whose config blob is missing is refused" linux/arm64 "$pl/nocfg"
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
# round 1 F8 (Codex B6): the syntax and the placeholders are judged BEFORE the cannot-run list excuses a command (a listed command is run unattended by
# Release after publishing, so an excused `$(...)`, `;` or unsupported placeholder would be run there)
X1="cosign verify <IMAGE_REF> --certificate-identity \"\$(id)\" --certificate-oidc-issuer $ISS"
X2="cosign verify <IMAGE_REF> --certificate-identity \$IDENT --certificate-oidc-issuer $ISS"
X3="cosign verify <IMAGE_REF> --certificate-identity <IDENTITY> --certificate-oidc-issuer $ISS; jq -n 1"
X4="cosign verify <IMAGE_REF> --certificate-identity <IDENTITY> --certificate-oidc-issuer \`id\`"
for c in "$X1" "$X2" "$X3" "$X4"; do g "$(blk "$c")"; lst "$c"; gwant_fail "AC7 F8 a listed command with shell syntax is refused, not excused: ${c:0:70}" "shell syntax"; done
printf '%s\n' "$DEFS" '- `<RELEASE_URL>`: the release page' "${FENCE}sh" "cosign verify <IMAGE_REF> --certificate-identity <RELEASE_URL> --certificate-oidc-issuer $ISS" "$FENCE" > "$fx/guide.md"
lst "cosign verify <IMAGE_REF> --certificate-identity <RELEASE_URL> --certificate-oidc-issuer $ISS"
gwant_fail "AC7 F8 a listed command with a placeholder Check and Release cannot substitute is refused, not excused" "unsupported placeholder"
g "$(blk "cosign verify-blob --certificate-identity fail-me --certificate-oidc-issuer $ISS --bundle checksums.txt.bundle checksums.txt")"
gwant_fail "AC7 a runnable command that exits non-zero fails the script naming it" "fail-me"
g "$(blk "cosign verify-blob --bundle checksums.txt.bundle cache_0.3.0_linux_amd64.tar.gz")"
gwant_fail "AC7 a command on a file that is not local to Check is not runnable and fails unless listed" "not runnable"
# PR 3 fix7 (found by running the planner read-only on cache's draft docs/verify-release.md):
# (1) the verify-form judgement of a LISTED command splits on `|` outside single and double quotes only (a pipe inside a quoted jq filter is jq's);
#     every F8 check still holds, and a chain to anything that is not a verify form or jq is still refused.
JQF="jq -e --arg ref <IMAGE_REF> '.payload | @base64d | fromjson | .subject[0].digest.sha256 == \$ref'"
Q1="cosign verify-attestation --type slsaprovenance1 --certificate-identity <IDENTITY> --certificate-oidc-issuer $ISS <IMAGE_REF> | $JQF"
g "$(blk "$Q1")"; lst "$Q1"
gwant_ok "AC7 fix7 a listed verify command piped to a jq filter that itself holds pipes inside single quotes is one verify form (not refused as 'not a verify form')"
if jq -e '(.commands | length) == 1 and .commands[0].outcome == "not-run"' "$fx/out/guide-results.json" > /dev/null 2>&1; then ok "AC7 fix7 the quoted-pipe jq command is recorded as not-run"; else bad "AC7 fix7 quoted-pipe results"; fi
g "$(blk "$Q1")"; gwant_fail "AC7 fix7 the same command unlisted still fails closed (it needs a registry)" "unlisted command needs a registry"
g "$(blk "jq -n '\"a\" | length'")"; gwant_ok "AC7 fix7 a runnable jq whose filter holds a quoted pipe runs"
QD="cosign verify <IMAGE_REF> --certificate-identity <IDENTITY> --certificate-oidc-issuer $ISS | jq -e \".[0] | .critical\""
g "$(blk "$QD")"; lst "$QD"; gwant_ok "AC7 fix7 a pipe inside double quotes (no expansion) is jq's too"
for c in "cosign verify <IMAGE_REF> --certificate-identity <IDENTITY> --certificate-oidc-issuer $ISS | sh" \
         "jq -n '.a | .b' | rm -rf x" \
         "jq -n '.a | .b' | jq -n '.c' | curl http://example.com/x" \
         "jq -n \\'.a | rm -rf x" \
         "jq -n '.a | .b"; do
  g "$(blk "$c")"; lst "$c"; gwant_fail "AC7 fix7 a chain to a command that is not a verify form or jq (or an unterminated quote) is still refused: ${c:0:60}" "verify form"
done
for c in "jq -n '.a | .b' ; rm -rf x" \
         "jq -n '.a | .b' \$(id)" \
         "jq -n '.a | .b' \"\$(id)\"" \
         "jq -n \".a | \`id\`\"" \
         "jq -n '.a | .b' && rm -rf x" \
         "jq -n '.a | .b' > /etc/x"; do
  g "$(blk "$c")"; lst "$c"; gwant_fail "AC7 fix7 a quoted pipe cannot smuggle shell syntax past the F8 checks: ${c:0:60}" "shell syntax"
done
# (2) a value of --bundle, --certificate, --cert, --signature, --sig, --key, --certificate-chain, --rekor-url is a file operand unless it is a URL: a command whose
#     only file operand is such a value, not local to Check, is not runnable at Check (it may be listed; Release runs it with the downloaded files).
BA="cosign verify-blob-attestation --type slsaprovenance1 --certificate-identity <IDENTITY> --certificate-oidc-issuer $ISS"
FX2=0
for f in "--bundle X" "--bundle=X" "--certificate X" "--certificate=X" "--cert X" "--cert=X" "--signature X" "--signature=X" "--sig X" "--sig=X" \
         "--key X" "--key=X" "--certificate-chain X" "--certificate-chain=X" "--rekor-url X" "--rekor-url=X"; do
  c="$BA ${f//X/provenance.intoto.jsonl.bundle}"
  g "$(blk "$c")"; gwant_fail "AC7 fix7 a flag value that is a file not local to Check makes the command not runnable (unlisted, refused): ${f%% *}" "not runnable"
  g "$(blk "$c")"; lst "$c"; gwant_ok "AC7 fix7 the same command listed with its reason is not run and is recorded as not-run (exit 0): $f"
  if ! grep -q '^cosign' "$work/log"; then ok "AC7 fix7 the listed flag-value command was not run: $f"; else bad "AC7 fix7 the listed flag-value command ran: $f"; fi
done
c="$BA --bundle=https://example.com/provenance.bundle checksums.txt"
g "$(blk "$c")"; gwant_ok "AC7 fix7 a URL value of --bundle is not a file operand: the command (local blob) runs"
g "$(blk "$c")"; lst "$c"; gwant_fail "AC7 fix7 a runnable command with a URL flag value is still never excused" "runnable"
c="$BA --bundle checksums.txt.bundle checksums.txt"
g "$(blk "$c")"; gwant_ok "AC7 fix7 a --bundle value that is a local file runs"
c="$BA --bundle provenance.intoto.jsonl.bundle"
g "$(blk "$c")"; printf '[{"command": "%s ", "reason": "run after publishing"}]\n' "$c" > "$fx/guide.cannot-run.json"
gwant_fail "AC7 fix7 a flag-value command listed with text that does not match exactly is refused" "not in the guide"
g "$(blk "$c")"; printf '[{"command": "%s", "reason": " "}]\n' "$c" > "$fx/guide.cannot-run.json"
gwant_fail "AC7 fix7 a flag-value command listed without a reason is refused" "cannot-run entry"
g "$(blk "$c")"; rm -f "$fx/guide.cannot-run.json"
gwant_fail "AC7 fix7 a flag-value command neither runnable nor listed is refused" "not runnable"
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
# round 2 (Codex B): a backslash-escaped quote is a literal character, so a $ after it is outside single quotes and is refused
for c in "cosign verify <IMAGE_REF> --certificate-identity \\'x\${HOME}y\\' --certificate-oidc-issuer $ISS" "jq -n \\'\$TAG\\'"; do
  g "$(blk "$c")"; lst "$c"; gwant_fail "AC7 round 2 an escaped quote does not open a quoted region: a \$ after it is refused: ${c:0:70}" "shell syntax"
done
# round 4 (both seats): the command words are compared one word at a time, so a quoted "cosign verify" (one word holding a space) is not the verify form
for c in "\"cosign verify\" | jq ." "'gh attestation' verify | jq ."; do
  g "$(blk "$c")"; lst "$c"; gwant_fail "AC7 round 4 a listed command whose quoted word holds a space is not a verify form (compared word by word): ${c:0:60}" "not a verify form"
done
for c in "cosign verify-evil x" "cosign verifyx y" "gh attestation verify-evil z" "jqx ."; do
  g "$(blk "$L2" "$c")"; printf '[{"command": "%s", "reason": "x"}]\n' "$c" > "$fx/guide.cannot-run.json"
  gwant_fail "AC7 round 2 a cannot-run entry whose first words only START with a verify form is not a verify form (the form is compared by whole words): $c" "not a verify form"
done
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
rm -rf "$work/keep-p"; cp -R "$fx/images/production" "$work/keep-p"; rm -rf "$fx/images/production"; python3 "$work/mkoci.py" "$fx/images/production" other > /dev/null
want_fail "AC5 F1 a valid OCI layout that is not Build's production image (digests.json intact) is refused naming the image before the suite or docker" image-production check-acceptance.sh gradle --digests digests.json --images images --out out
if ! grep -q '^docker' "$work/log"; then ok "AC5 F1 nothing was loaded behind the refused production layout"; else bad "AC5 F1 docker ran: $(head -2 "$work/log" | tr '\n' '|')"; fi
rm -rf "$fx/images/production"; cp -R "$work/keep-p" "$fx/images/production"
# ---- REQ-CHAIN-006-AC11 (rule 68, amended): the helper bin/witnessed.sh and its 9-minute cap -------------------------------------------
hw="$work/hw"; mkdir -p "$hw/bin" "$hw/fakebin" "$hw/tmp"
cp "$root/bin/witnessed.sh" "$root/bin/loopback-get.sh" "$hw/bin/" 2> /dev/null || true
printf '#!/usr/bin/env bash\necho "step $*" >> "$HW_LOG"\n[ -z "${STEP_FAIL:-}" ] || exit 1\n' > "$hw/bin/step.sh"
cat > "$hw/fakebin/curl" <<'EOF'
#!/usr/bin/env bash
printf '{"value":"fake-token-value"}'
EOF
cat > "$hw/fakebin/timeout" <<'EOF'
#!/usr/bin/env bash
if [ "$1" = -k ]; then echo "timeout -k $2 $3" >> "$HW_LOG"; shift 3; else echo "timeout $1" >> "$HW_LOG"; shift; fi
[ -z "${FAKE_OUTLIVE:-}" ] || exit 124
exec "$@"
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
          ACTIONS_ID_TOKEN_REQUEST_TOKEN=t ACTIONS_ID_TOKEN_REQUEST_URL="https://x/?a=b" bash bin/witnessed.sh "$@") 2>&1) || rc=$?
}
reset_h() { rm -rf "$hw"/witness-*; : > "$work/hwlog"; : > "$work/hwargv"; }
reset_h; hrun X=1 -- scanners bin/step.sh scanners
h_ok=0; [ "$rc" = 0 ] && [ -f "$hw/witness-scanners/scanners-collection.json" ] && h_ok=1
if [ "$rc" = 0 ] && [ -f "$hw/witness-scanners/scanners-collection.json" ] && grep -q '^step scanners' "$work/hwlog"; then ok "AC11 the helper runs the script with its arguments under Witness and writes witness-scanners/scanners-collection.json (PR 2's naming)"; else bad "AC11 helper normal run -> rc=$rc ${out:0:140}"; fi
if [ "$(grep -c '^timeout ' "$work/hwlog")" = 1 ] && grep -qx 'timeout -k 20 540' "$work/hwlog"; then ok "AC11 the wrapped command is run through exactly one timeout of 540 seconds (9 minutes) with a kill-after of 20 seconds"; else bad "AC11 the helper must run the command through exactly one 'timeout -k 20 540': $(tr '\n' ' ' < "$work/hwlog")"; fi
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
script=$3; shift 3
case "$script" in bin/check-govulncheck.py) echo "check-govulncheck $*" >> "$DP_LOG" ;; *) bash "bin/chain-verify.py" "$@" ;; esac
EOF
chmod +x "$dp/bin/python3"
drun() { rc=0; : > "$work/dplog"; out=$( (cd "$dp" && PATH="$dp/bin:$PATH" DP_LOG="$work/dplog" VERIFY_RC="${VERIFY_RC:-0}" GITHUB_REF_NAME=v0.3.0 bash bin/check-stage.sh "$@") 2>&1) || rc=$?; }   # a release run always has its tag (Q5)
# ---- REQ-CHAIN-006-AC17 and rule 58: the arm64 target verifies Build's record and Sign's provenance BEFORE it loads or runs anything ----------
cp "$root/bin/check-phase-arm64.sh" "$dp/bin/" 2> /dev/null || true
printf '#!/usr/bin/env bash\necho "docker $*" >> "$DP_LOG"\n' > "$dp/bin/docker"; chmod +x "$dp/bin/docker"
mkdir -p "$dp/witness-build"; : > "$dp/witness-build/build-collection.json"; : > "$dp/witness-build/digests.json"
arun64() { rc=0; : > "$work/dplog"; out=$( (cd "$dp" && env "$@" PATH="$dp/bin:$PATH" DP_LOG="$work/dplog" GITHUB_REF_NAME=v0.3.0 bash bin/check-phase-arm64.sh) 2>&1) || rc=$?; }
arun64 X=1
if [ "$rc" = 0 ] && [ "$(grep '^verify' "$work/dplog" | cut -d' ' -f2 | tr '\n' ' ')" = "policy stage-start " ] && [ "$(grep -c '^check-artifacts' "$work/dplog")" = 1 ] \
   && grep -q '^check-artifacts --arch arm64 --digests witness-build/digests.json ' "$work/dplog" && grep -n '' "$work/dplog" | awk -F: '/verify stage-start/{a=$1} /check-artifacts/{c=$1} END{exit !(a<c)}';  then ok "AC17 the arm64 target makes the policy, verifies Build's record, verifies Sign's provenance, then runs the arm64 artifact checks on the digest file it verified (rule 58)"; else bad "AC17 arm64 target ran: $(tr '\n' '|' < "$work/dplog" | cut -c1-300)"; fi
# (c) the stage-start the arm64 leg runs is the one the dispatcher runs: the same line, naming Build's record only
if [ "$(grep -c 'chain-verify.py stage-start' "$root/bin/check-phase-arm64.sh")" = 1 ] && [ "$(grep 'chain-verify.py stage-start' "$root/bin/check-phase-arm64.sh")" = "$(grep 'chain-verify.py stage-start' "$root/bin/check-stage.sh")" ] \
   && ! grep -q 'provenance' "$root/bin/check-phase-arm64.sh" "$root/bin/check-stage.sh"; then ok "AC17 the arm64 target's stage-start is the dispatcher's own line, and neither script names Sign's provenance"; else bad "AC17 the stage-start lines differ, or a Check script names Sign's provenance"; fi
arm_stops() { # arm_stops LABEL ENV... : the target fails and nothing of the candidate is loaded or run
  local l=$1; shift; arun64 "$@"
  if [ "$rc" != 0 ] && ! grep -Eq '^(check-artifacts|docker)' "$work/dplog"; then ok "$l"; else bad "$l -> rc=$rc, log: $(tr '\n' '|' < "$work/dplog" | cut -c1-200)"; fi; }
arm_stops "rule 58 a forged Build record (stage-start refuses it): no artifact is loaded, no binary runs" VERIFY_FAIL=stage-start
arm_stops "rule 58 no policy for the tag: no artifact is loaded, no binary runs" VERIFY_FAIL=policy
rm -f "$dp/witness-build/build-collection.json"
arm_stops "rule 58 a missing Build record: no artifact is loaded, no binary runs" VERIFY_STRICT=1
: > "$dp/witness-build/build-collection.json"
drun scanners; d_ok=0; [ "$rc" = 0 ] && grep -q '^check-scan' "$work/dplog" && d_ok=1
drun nosuch
if [ "$d_ok" = 1 ] && [ "$rc" = 2 ] && grep -Fq 'unknown phase: nosuch' <<< "$out" && ! grep -q '^check-' "$work/dplog"; then ok "AC3 an unknown phase is refused (exit 2) naming it, and no check runs"; else bad "AC3 unknown phase -> rc=$rc: ${out:0:100}"; fi
VERIFY_RC=1 drun scanners
if [ "$d_ok" = 1 ] && [ "$rc" != 0 ] && ! grep -q '^check-' "$work/dplog"; then ok "AC3 when verifying Build's record fails, no check runs (rule 58)"; else bad "AC3 verify failure -> rc=$rc, log: $(tr '\n' ' ' < "$work/dplog")"; fi
drun scanners
if [ "$rc" = 0 ] && [ "$(grep '^verify' "$work/dplog" | cut -d' ' -f2 | tr '\n' ' ')" = "policy stage-start " ] && grep -q '^verify policy make .*--tag ' "$work/dplog" && [ "$(grep '^check-' "$work/dplog" | cut -d' ' -f1 | tr '\n' ' ')" = "check-scan check-govulncheck " ]; then ok "AC3 phase scanners: the policy made per tag (Q5), both verifications, then only the scan"; else bad "AC3 phase scanners ran: $(tr '\n' ' ' < "$work/dplog")"; fi
drun acceptance
if [ "$rc" = 0 ] && [ "$(grep '^check-' "$work/dplog" | cut -d' ' -f1,2 | tr '\n' ' ')" = "check-acceptance gradle check-acceptance maven " ]; then ok "AC3 phase acceptance: gradle, then maven, nothing else"; else bad "AC3 phase acceptance ran: $(tr '\n' ' ' < "$work/dplog")"; fi
drun runtime
if [ "$rc" = 0 ] && [ "$(grep '^check-' "$work/dplog" | cut -d' ' -f1,2 | tr '\n' ' ')" = "check-acceptance egress check-acceptance k8s check-fips --digests check-artifacts --digests check-guide --guide " ]; then ok "AC3 phase runtime: egress, k8s, fips, guide, in that order"; else bad "AC3 phase runtime ran: $(tr '\n' ' ' < "$work/dplog")"; fi
# ---- ruling G (advisor Oct 12): bin/check-govulncheck.py, the source scan of the product module, whose output Release reads from Check's record -----------------------
# `govulncheck -json ./...` runs once in the scanners step with the pinned Go (the fixed path /usr/local/bin/fscache-go/bin first on PATH, GOTOOLCHAIN=local,
# GOFLAGS=-mod=vendor and GOPROXY=off, so the scan reads the exact bytes the build uses; never a flag or toolchain of the caller's environment); the raw stream is written byte for byte to OUT/govulncheck.json, which the Witness
# record of the step carries as a product. Exit 0 only when the tool ran (a config message of scanner govulncheck, database https://vuln.go.dev) and no finding
# reaches a called symbol (a trace whose first frame has a function); the file is written in every case that ran.
gvt="$work/gv"; mkdir -p "$gvt/bin" "$gvt/.github/policy" "$gvt/fake" "$gvt/out"
cp "$root/bin/check-govulncheck.py" "$gvt/bin/" 2> /dev/null || true
printf 'module example.com/a\n' > "$gvt/go.mod"; mkdir -p "$gvt/vendor"; printf '# example.com/b v1.0.0\n' > "$gvt/vendor/modules.txt"
printf '{"scanners":["grype","osv-scanner"],"source_scanners":["govulncheck"],"pr_gate":["grype","inspector"]}\n' > "$gvt/.github/policy/scanners.json"
cat > "$gvt/fake/govulncheck" <<'EOF'
#!/usr/bin/env bash
# the scan runs with an explicit environment (the caller's variables do not reach it), so the case settings come from a file next to this fake
[ ! -f "$(dirname "$0")/env" ] || . "$(dirname "$0")/env"
echo "govulncheck $*" >> "$GV_LOG"
echo "env GOFLAGS=${GOFLAGS:-} GOTOOLCHAIN=${GOTOOLCHAIN:-} GOPROXY=${GOPROXY:-} PATH1=${PATH%%:*}" >> "$GV_LOG"
echo "pkgdriver GOPACKAGESDRIVER=${GOPACKAGESDRIVER-unset}" >> "$GV_LOG"
echo "goenv GOOS=${GOOS-unset} GOARCH=${GOARCH-unset} CGO_ENABLED=${CGO_ENABLED-unset} GOAMD64=${GOAMD64-unset} GOPATH=${GOPATH-unset} GOCACHE=${GOCACHE-unset} GOMODCACHE=${GOMODCACHE-unset} GOENV=${GOENV-unset}" >> "$GV_LOG"
case "$1" in -version) printf 'Go: go1.27.2\nScanner: govulncheck@v1.7.0\nDB: https://vuln.go.dev\nDB updated: 2026-10-10 00:00:00 +0000 UTC\n'; exit 0 ;; esac
[ "${GV_RC:-0}" = 0 ] || { echo "govulncheck: boom" >&2; exit "$GV_RC"; }
case "${GV_OUT:-clean}" in
  clean) echo '{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck","scanner_version":"v1.7.0","db":"https://vuln.go.dev","db_last_modified":"2026-10-10T00:00:00Z","go_version":"go1.27.2","scan_level":"symbol"}}'
         echo '{"progress":{"message":"Scanning your code and 12 packages across 3 dependent modules for known vulnerabilities..."}}' ;;
  imported) echo '{"config":{"scanner_name":"govulncheck","scanner_version":"v1.7.0","db":"https://vuln.go.dev"}}'
         echo '{"osv":{"id":"GO-2099-0001"}}'; echo '{"finding":{"osv":"GO-2099-0001","trace":[{"module":"example.org/m","version":"v1.0.0","package":"example.org/m/p"}]}}' ;;
  called) echo '{"config":{"scanner_name":"govulncheck","scanner_version":"v1.7.0","db":"https://vuln.go.dev"}}'
         echo '{"osv":{"id":"GO-2099-0002"}}'; echo '{"finding":{"osv":"GO-2099-0002","fixed_version":"v1.0.1","trace":[{"module":"example.org/m","version":"v1.0.0","package":"example.org/m/p","function":"Do"},{"module":"example.com/a","function":"main"}]}}' ;;
  noconfig) echo '{"progress":{"message":"hello"}}' ;;
  otherscanner) echo '{"config":{"scanner_name":"other","scanner_version":"v1.7.0","db":"https://vuln.go.dev"}}' ;;
  otherdb) echo '{"config":{"scanner_name":"govulncheck","scanner_version":"v1.7.0","db":"https://mirror.example.org"}}' ;;
  empty) : ;;
  notjson) echo 'this is not json' ;;
esac
EOF
chmod +x "$gvt/fake/govulncheck"
gvrun() { # gvrun [ENV=V ...] -- ARGS... : runs the script in the throw-away tree with the fake first on PATH
  local envs=(); while [ "$1" != -- ]; do envs+=("$1"); shift; done; shift
  rc=0; : > "$work/gvlog"; rm -rf "$gvt/out"
  { printf 'export GV_LOG=%q\n' "$work/gvlog"; local e; for e in "${envs[@]}"; do case "$e" in GV_*) printf 'export %s=%q\n' "${e%%=*}" "${e#*=}" ;; esac; done; } > "$gvt/fake/env"
  out=$( (cd "$gvt" && env "${envs[@]}" PATH="$gvt/fake:$PATH" python3 -I -B bin/check-govulncheck.py "$@") 2>&1) || rc=$?; }
GVARGS=(--scanners .github/policy/scanners.json --out out)
gvrun GV_OUT=clean -- "${GVARGS[@]}"
if [ "$rc" = 0 ] && [ -f "$gvt/out/govulncheck.json" ] && grep -q '^govulncheck -json ./\.\.\.$' "$work/gvlog" && [ "$(grep -c '^govulncheck ' "$work/gvlog")" = 2 ]; then ok "G a clean source scan: exit 0, the stream is written to OUT/govulncheck.json, and the tool ran once as govulncheck -json ./..."
else bad "G a clean source scan -> rc=$rc $out | $(tr '\n' '|' < "$work/gvlog" | cut -c1-200)"; fi
( cd "$gvt/fake" && : > env && GV_LOG=/dev/null GV_OUT=clean ./govulncheck -json ./... > "$work/gv-expected.bin" ) 2> /dev/null
if [ -f "$gvt/out/govulncheck.json" ] && cmp -s "$gvt/out/govulncheck.json" "$work/gv-expected.bin" && [ -s "$work/gv-expected.bin" ] \
   && [ "$(wc -l < "$gvt/out/govulncheck.json" | tr -d ' ')" = 2 ]; then ok "G the file is the tool's own output, byte for byte (the whole stream, whitespace included; two lines: config, progress)"
else bad "G the written file is not the tool's output"; fi
if grep -q 'GOFLAGS=-mod=vendor GOTOOLCHAIN=local GOPROXY=off ' "$work/gvlog" && grep -q 'PATH1=/usr/local/bin/fscache-go/bin$' "$work/gvlog"; then ok "G the scan runs with GOFLAGS=-mod=vendor, GOPROXY=off, GOTOOLCHAIN=local and the pinned Go first on PATH"
else bad "G the scan environment is not the pinned one: $(grep '^env' "$work/gvlog" | head -1)"; fi
gvrun GOFLAGS=-toolexec=/tmp/evil GOTOOLCHAIN=auto GOPROXY=https://evil.example GV_OUT=clean -- "${GVARGS[@]}"
if [ "$rc" = 0 ] && grep -q 'GOFLAGS=-mod=vendor GOTOOLCHAIN=local GOPROXY=off ' "$work/gvlog" && ! grep -q 'evil' "$work/gvlog"; then ok "G a GOFLAGS, GOTOOLCHAIN or GOPROXY of the caller's environment never reaches the scan"
else bad "G the caller's Go environment reached the scan: $(grep '^env' "$work/gvlog" | head -1) rc=$rc"; fi
gvrun GOPACKAGESDRIVER=/tmp/evil-driver GV_OUT=clean -- "${GVARGS[@]}"
if [ "$rc" = 0 ] && grep -q '^pkgdriver GOPACKAGESDRIVER=off$' "$work/gvlog"; then ok "G the scan sets GOPACKAGESDRIVER=off (no external package driver is searched for on PATH or taken from the caller's environment)"; else bad "G the package-driver setting is not off: $(grep '^pkgdriver' "$work/gvlog" | head -1) rc=$rc"; fi
gvrun GOOS=windows GOARCH=arm64 CGO_ENABLED=0 GOAMD64=v4 GOPATH=/tmp/evil-path GOCACHE=/tmp/evil-cache GOMODCACHE=/tmp/evil-mod GOENV=/tmp/evil-env GV_OUT=clean -- "${GVARGS[@]}"
if [ "$rc" = 0 ] && grep -q '^goenv GOOS=unset GOARCH=unset CGO_ENABLED=unset GOAMD64=unset GOPATH=unset GOCACHE=unset GOMODCACHE=unset GOENV=off$' "$work/gvlog"; then ok "G no Go setting of the caller (GOOS, GOARCH, CGO_ENABLED, GOAMD64, GOPATH, GOCACHE, GOMODCACHE, GOENV) reaches the scan and persisted Go configuration is off (GOENV=off)"
else bad "G the caller's platform or cache settings reached the scan: $(grep '^goenv' "$work/gvlog" | head -1) rc=$rc"; fi
gvrun GV_OUT=called -- "${GVARGS[@]}"
if [ "$rc" != 0 ] && [ "$rc" != 127 ] && grep -q 'GO-2099-0002' <<< "$out" && [ -f "$gvt/out/govulncheck.json" ]; then ok "G a finding that reaches a called symbol fails the scan, naming the advisory, and the file is still written"
else bad "G a called finding -> rc=$rc $out"; fi
gvrun GV_OUT=imported -- "${GVARGS[@]}"
if [ "$rc" = 0 ] && [ -f "$gvt/out/govulncheck.json" ]; then ok "G a finding of an imported package that no called symbol reaches is carried in the file and does not fail (the PR gate's own rule)"
else bad "G an imported-only finding -> rc=$rc $out"; fi
for c in noconfig otherscanner otherdb empty notjson; do
  gvrun GV_OUT=$c -- "${GVARGS[@]}"
  if [ "$rc" != 0 ] && [ "$rc" != 127 ]; then ok "G an output that is not a govulncheck run on its own database ($c) fails"; else bad "G $c was accepted or the script is missing: rc=$rc $out"; fi
done
gvrun GV_RC=3 GV_OUT=clean -- "${GVARGS[@]}"
if [ "$rc" != 0 ] && [ "$rc" != 127 ]; then ok "G a tool exit other than 0 fails (it could not run: nothing is clean behind it)"; else bad "G a failing tool was accepted"; fi
rm -f "$gvt/fake/govulncheck.hide"; mv "$gvt/fake/govulncheck" "$gvt/fake/govulncheck.hide"
gvrun GV_OUT=clean -- "${GVARGS[@]}"
if [ "$rc" != 0 ] && [ "$rc" != 127 ] && grep -q 'govulncheck: \|not installed' <<< "$out"; then ok "G govulncheck listed but not installed fails, naming it"; else bad "G a missing govulncheck: rc=$rc $out"; fi
mv "$gvt/fake/govulncheck.hide" "$gvt/fake/govulncheck"
for lst in '{"scanners":["grype"],"source_scanners":["govulncheck","trivy"]}' '{"scanners":["grype"],"source_scanners":[]}' '{"scanners":["grype"]}' '{"scanners":["grype"],"source_scanners":["snyk"]}'; do
  printf '%s\n' "$lst" > "$gvt/.github/policy/scanners-x.json"
  gvrun GV_OUT=clean -- --scanners .github/policy/scanners-x.json --out out
  if [ "$rc" != 0 ] && [ "$rc" != 127 ] && [ ! -e "$gvt/out/govulncheck.json" ] && [ ! -s "$work/gvlog" ]; then ok "G a source_scanners list that is not exactly [govulncheck] runs nothing: $lst"; else bad "G list $lst accepted: rc=$rc"; fi
done
gvrun GV_OUT=clean -- --scanners .github/policy/scanners.json
if [ "$rc" = 2 ]; then ok "G a missing --out is a usage error (exit 2)"; else bad "G missing --out -> rc=$rc"; fi
gvrun GV_OUT=clean -- --scanners .github/policy/scanners.json --out out --extra x
if [ "$rc" = 2 ]; then ok "G an unknown argument is a usage error (exit 2)"; else bad "G unknown argument -> rc=$rc"; fi
rm -f "$gvt/go.mod"; gvrun GV_OUT=clean -- "${GVARGS[@]}"
if [ "$rc" != 0 ] && [ "$rc" != 127 ]; then ok "G no go.mod in the working directory fails (a source scan of nothing is not a scan)"; else bad "G a tree without go.mod was scanned"; fi
printf 'module example.com/a\n' > "$gvt/go.mod"
mv "$gvt/vendor" "$gvt/vendor.hide"; gvrun GV_OUT=clean -- "${GVARGS[@]}"
if [ "$rc" != 0 ] && [ "$rc" != 127 ] && [ ! -s "$work/gvlog" ] && [ ! -e "$gvt/out/govulncheck.json" ] && grep -q 'vendor' <<< "$out"; then ok "G no vendor/ directory fails before the tool runs, naming it and writing no result file (a scan of modules the build does not use is not a scan)"; else bad "G a tree without vendor/ was scanned: rc=$rc $out"; fi
mv "$gvt/vendor.hide" "$gvt/vendor"
if ! grep -Eq 'cosign|witness|attest|gitsign|docker login|ghcr\.io|secrets|GH_TOKEN|ACTIONS_ID_TOKEN' "$root/bin/check-govulncheck.py" 2> /dev/null && [ -f "$root/bin/check-govulncheck.py" ]; then ok "G the script knows nothing about signing (plain, rule 66)"
else bad "G bin/check-govulncheck.py is missing or names a signing tool or credential"; fi
# the static strace of the egress suite is fetched from its GitHub release (a literal URL the pin-age check dates): the URL names the pinned STRACE_VER
sv_=$(sed -n 's/^STRACE_VER=\([0-9.]*\)$/\1/p' "$root/bin/acceptance-egress.sh" | head -1)
if [ -n "$sv_" ] && grep -q "releases/download/v${sv_}/strace-${sv_}.tar.xz" "$root/bin/acceptance-egress.sh"; then ok "acceptance-egress.sh: the strace release URL names the pinned version $sv_"; else bad "acceptance-egress.sh: the strace release URL does not name the pinned version '${sv_}'"; fi
EXPECT=329
echo "pass=$pass fail=$failn"
if [ $((pass + failn)) != "$EXPECT" ]; then echo "FAIL case count $((pass + failn)) != expected $EXPECT (a case was skipped or added)"; exit 1; fi
[ "$failn" = 0 ]
