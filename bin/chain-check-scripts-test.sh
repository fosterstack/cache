#!/usr/bin/env bash
# proves: REQ-SUP-001-AC30, REQ-SUP-001-AC33, REQ-CHAIN-006-AC18, REQ-CHAIN-006-AC17, REQ-CHAIN-006-AC16, REQ-PLAT-001-AC1, REQ-PLAT-002-AC1, REQ-PLAT-003-AC1, REQ-FIPS-001-AC1, REQ-FIPS-001-AC2, REQ-FIPS-002-AC1, REQ-CHAIN-006-AC15, REQ-CHAIN-006-AC3, REQ-CHAIN-006-AC4, REQ-CHAIN-006-AC5, REQ-CHAIN-006-AC6, REQ-CHAIN-006-AC7, REQ-CHAIN-006-AC9, REQ-CHAIN-006-AC11, REQ-CHAIN-006-AC12 — AC5 interface only, see the gap below
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
#         verify-blob-attestation, jq), joined only by pipes; placeholders are ALL-CAPS in angle brackets, each defined
#         ONCE in a list line before the first fence (`- `<NAME>`: text`). Check substitutes the candidate's values: <IMAGE_REF> =
#         $CANDIDATE_REPOSITORY@<image-production digest> (PROPOSED: Check has the digest from Build's digests.json but NO registry reference,
#         see the report), <TAG> = $GITHUB_REF_NAME; <RELEASE_KEY> is Release's (a listed command only: Check never
# holds the verified key).
#         A command that cannot run on a candidate is excused ONLY by an exact entry of the cannot-run list,
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
export COPYFILE_DISABLE=1   # macOS bsdtar would add AppleDouble ._ members for extended attributes; the archive member lists are asserted exactly
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
    lmt = "application/vnd.in-toto+json" if p == "unknown/unknown" and os.environ.get("ATT_ODD") != "plain-image" else "application/vnd.oci.image.layer.v1.tar"
    cfg, cs = blob(json.dumps({"architecture": lie or arch, "os": os_, "rootfs": {"type": "layers", "diff_ids": [layer]}, "seed": seed}, sort_keys=True).encode())
    man_doc = (json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": cfg, "size": cs},
        "layers": [] if os.environ.get("EMPTY_LAYERS") else [{"mediaType": lmt, "digest": layer, "size": ls}]}, sort_keys=True).encode())
    man_bytes = man_doc.encode() if isinstance(man_doc, str) else man_doc
    if p == "unknown/unknown" and os.environ.get("ATT_ODD") == "two-values":
        first = json.loads(man_bytes); first["layers"][0]["mediaType"] = "application/vnd.oci.image.layer.v1.tar+gzip"
        man_bytes = (json.dumps(first, sort_keys=True) + "\n").encode() + man_bytes
    man, ms = blob(man_bytes)
    kid = {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": man, "size": ms, "platform": {"os": os_, "architecture": arch}}
    if p == "unknown/unknown" and os.environ.get("ATT_ODD") == "array-digest":
        kid["annotations"] = {"vnd.docker.reference.type": "attestation-manifest", "vnd.docker.reference.digest": [kids[0]["digest"]]}
    elif p == "unknown/unknown" and os.environ.get("ATT_ODD") == "case-variant-keys":
        kid["annotations"] = {"vnd.docker.reference.type": "attestation-manifest", "vnd.docker.reference.digest": kids[0]["digest"]}
        kid["Platform"] = {"os": "linux", "architecture": "s390x"}           # Go's decoders read this one, jq the lowercase one
    elif p == "unknown/unknown" and os.environ.get("ATT_ODD") == "unicode-key":
        kid["annotations"] = {"vnd.docker.reference.type": "attestation-manifest", "vnd.docker.reference.digest": kids[0]["digest"]}
        kid["o\u017f"] = "linux"                                              # Go folds U+017F to s: its decoder reads this as os
    elif p == "unknown/unknown" and os.environ.get("ATT_ODD") == "two-values":
        kid["annotations"] = {"vnd.docker.reference.type": "attestation-manifest", "vnd.docker.reference.digest": kids[0]["digest"]}
    elif p == "unknown/unknown" and os.environ.get("ATT_ODD") == "annotations-list":
        kid["annotations"] = []
    elif p == "unknown/unknown" and not os.environ.get("NO_ATT_ANNOTATION"):   # (ATT_ODD=plain-image keeps the annotations on an ordinary image manifest)
        kid["annotations"] = {"vnd.docker.reference.type": "attestation-manifest", "vnd.docker.reference.digest": ("sha256:" + "9" * 64) if os.environ.get("ATT_DIGEST_OTHER") else kids[0]["digest"]}      # buildkit's descriptor for the first child
    if p == "unknown/unknown" and os.environ.get("ATT_DIGEST_PAD") is not None:
        kid["digest"] = kid["digest"] + os.environ["ATT_DIGEST_PAD"]   # the descriptor's digest string carries trailing whitespace; the blob keeps the unpadded name
    kids.append(kid)
    names[arch] = {"layer": layer.split(":")[1], "config": cfg.split(":")[1], "manifest": man.split(":")[1]}
idx, isz = blob(json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": kids}, sort_keys=True).encode())
with open(os.path.join(root, "index.json"), "w") as f:
    json.dump({"schemaVersion": 2, "manifests": [{"mediaType": "application/vnd.oci.image.index.v1+json", "digest": idx, "size": isz}]}, f)
with open(os.path.join(root, "oci-layout"), "w") as f: f.write('{"imageLayoutVersion":"1.0.0"}')
names["index"] = idx.split(":")[1]
with open(root.rstrip("/") + ".map", "w") as f: json.dump(names, f)   # blob file names by role, next to the layout (not inside it)
print(idx)
PYM
# What osv-scanner 2.6.0 `scan image --archive FILE` needs of FILE (probed on the pinned binary against a real OCI layout, Oct 22): a docker-save style tar,
# i.e. a manifest.json naming the config and the layer files that are members of the tar. A bare OCI layout tar fails with
# "file manifest.json not found in tar". The fake reads the archive the same way, refuses the same way, and logs what it was given.
cat > "$work/osvarc.py" <<'PYA'
import json, sys, tarfile
path = sys.argv[1]
def norm(n): return n[2:] if n.startswith("./") else n   # ONE leading "./" (not a character strip: ".x" stays ".x")
try:
    t = tarfile.open(path)
    ms = [m for m in t.getmembers() if norm(m.name) != ""]
    names = [norm(m.name) for m in ms]
    firsts = [m for m in ms if norm(m.name) == "manifest.json"]   # the real reader takes the FIRST member of that name
    if not firsts:
        print('failed to load image from tarball with path "%s": file manifest.json not found in tar' % path, file=sys.stderr); sys.exit(2)
    man = json.load(t.extractfile(firsts[0]))
    if not isinstance(man, list) or len(man) != 1: print("manifest.json is not a one-image list", file=sys.stderr); sys.exit(2)
    e = man[0]
    need = [e["Config"]] + list(e["Layers"])
    miss = [n for n in need if n not in names]
    if miss: print("manifest.json names members the tar lacks: %s" % miss, file=sys.stderr); sys.exit(2)
    print("osv-archive config=%s layers=%s" % (e["Config"].split("/")[-1], ",".join(l.split("/")[-1] for l in e["Layers"])))
    print("osv-members " + ",".join(n for n in names if not n.endswith("/")))
except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as ex:
    print("osv-archive unreadable: %s" % ex, file=sys.stderr); sys.exit(2)
PYA
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
cp "$root"/bin/check-*.sh "$root"/bin/check-*.py "$root"/bin/chain_items.py "$root"/bin/chain_common.py \
  "$root"/bin/rescan-statement.py "$root"/bin/inspector-gate.py "$root"/bin/loopback-get.sh \
  "$root"/bin/layout-archive.sh "$fx/bin/" 2> /dev/null || true
mkdir -p "$fx/.vex"; cp "$root/test-evidence/vex-scope/busybox.openvex.json" "$fx/.vex/fosterstack-cache.openvex.json"
D1=$(python3 "$work/mkoci.py" "$fx/images/production" production); D2=$(python3 "$work/mkoci.py" "$fx/images/fips" fips)   # images/<variant>/ is an OCI layout directory (PR 2's interface, PROPOSED)
for a in amd64 arm64; do printf 'archive fscache %s\n' "$a" > "$fx/dist/fscache_0.3.0_linux_$a.tar.gz"; printf 'archive fscache-fips %s\n' "$a" > "$fx/dist/fscache-fips_0.3.0_linux_$a.tar.gz"; done
mkdig "$fx"
mkdir -p "$fx/tools/requirements"; printf 'module example.com/a\n' > "$fx/go.mod"; printf 'module example.com/b\n' > "$fx/tools/requirements/go.mod"
printf '{"scanners":["grype","osv-scanner"],"pr_gate":["grype","inspector"]}\n' > "$fx/.github/policy/scanners.json"
fake="$work/fake"; mkdir -p "$fake"
cat > "$work/childdigest.py" <<'PYC'
import json, os, sys, tarfile
# the fake grype's imageID and tag: a docker archive's image ID is its config digest (the real grype reports it so), its tag the first RepoTags entry of the archive's
# manifest.json (FAKE_GRYPE_MD=mismatch|missing break the ID). Prints the ID, then the tag.
mode = os.environ.get("FAKE_GRYPE_MD", "")
with tarfile.open(sys.argv[1]) as t:
    man = json.load(t.extractfile("manifest.json"))[0]
tag = (man.get("RepoTags") or [""])[0]
if mode == "missing":
    print(""); print(tag); sys.exit(0)
if mode == "mismatch":
    print("sha256:" + "0" * 64); print(tag); sys.exit(0)
print("sha256:" + man["Config"].split("/")[-1]); print(tag)
PYC
cat > "$work/osvout.py" <<'PYO2'
import json, os, sys
# osv-scanner 2.6.0 --format json --all-packages: results[].packages[] of {package, vulnerabilities[{id, aliases}], groups}; FAKE_OSV_VULNS (a JSON list of
# {"pkg": "name@version", "id": ..., "aliases": [...]}) puts those vulnerabilities on the first packages
n, eco = int(sys.argv[1]), sys.argv[2]
vulns = json.loads(os.environ.get("FAKE_OSV_VULNS") or "[]")
if os.environ.get("FAKE_OSV_ECO_ONLY") and os.environ["FAKE_OSV_ECO_ONLY"] != eco:
    vulns = []                       # this finding belongs to the other ecosystem's scan only
ignored = os.environ.get("FAKE_OSV_IGNORE", "").split()
vulns = [v for v in vulns if v["id"] not in ignored]    # an osv-scanner.toml [[IgnoredVulns]] drops the report entries it lists (probed on 2.6.0)
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
if [ "$1" = grype ]; then
  gcfg=""; gprev2=""
  for ga in "\$@"; do [ "\$gprev2" != -c ] || gcfg=\$ga; gprev2=\$ga; done
  if [ -z "\$gcfg" ]; then echo "grype-config none" >> "\$FAKE_LOG"; elif [ -f "\$gcfg" ] && [ ! -s "\$gcfg" ]; then echo "grype-config empty" >> "\$FAKE_LOG"; else echo "grype-config other" >> "\$FAKE_LOG"; fi
fi
[ "\${1:-} \${2:-}" != "db update" ] || exit "\$FAKE_DB_RC"
n=$3; name=$1
for a in "\$@"; do case "\$a" in cyclonedx-json=*) python3 -c 'import json,os,sys; json.dump({"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"p%d" % i,"version":"1","purl":(7 if os.environ.get("FAKE_GRYPE_BADPURL") else os.environ["FAKE_GRYPE_STRPURL"] if os.environ.get("FAKE_GRYPE_STRPURL") else "pkg:generic/p%d@1" % i)} for i in range(0 if os.environ.get("FAKE_GRYPE_FILES_ONLY") else int(sys.argv[2]))] + [{"type":"file","name":"/usr/lib/f%d" % i} for i in range(int(os.environ.get("FAKE_GRYPE_FILES") or 0))]}, open(sys.argv[1],"w"))' "\${a#cyclonedx-json=}" "\$n";; esac; done
if [ "\$name" = osv-scanner ]; then
  case " \$* " in *" --offline-vulnerabilities "*) ;; *) echo "online scan refused by the fake: no --offline-vulnerabilities" >&2; exit 99;; esac
  ocfg=""; oprev=""
  for oa in "\$@"; do [ "\$oprev" != --config ] || ocfg=\$oa; oprev=\$oa; done
  if [ -z "\$ocfg" ]; then echo "osv-config none" >> "\$FAKE_LOG"; elif [ -f "\$ocfg" ] && [ ! -s "\$ocfg" ]; then echo "osv-config empty" >> "\$FAKE_LOG"; else echo "osv-config other" >> "\$FAKE_LOG"; fi
  if [ -z "\$ocfg" ]; then   # real osv-scanner 2.6.0 (probed): with no --config it reads osv-scanner.toml BESIDE the scanned go.mod and drops the ids it lists; with --config only that file
    ot=\$(dirname "\${@: -1}")/osv-scanner.toml
    if [ -f "\$ot" ]; then FAKE_OSV_IGNORE=\$(sed -n 's/^id = "\(.*\)"\$/\1/p' "\$ot" | tr '\n' ' '); export FAKE_OSV_IGNORE; fi
  fi
  case " \$* " in *" scan image "*) python3 "$work/osvarc.py" "\${@: -1}" >> "\$FAKE_LOG" || exit 2;; esac
  case " \$* " in *" --download-offline-databases "*)
    c=\${OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY:?}
    echo "osvcache-before \$(find "\$c" -type f | wc -l | tr -d ' ')" >> "\$FAKE_LOG"
    [ "\$FAKE_OSV_DB_RC" = 0 ] || exit "\$FAKE_OSV_DB_RC"
    [ "\$FAKE_OSV_ZIP" = none ] || python3 - "\$c" "\$FAKE_OSV_ZIP" "\$FAKE_OSV_MODIFIED" \${FAKE_OSV_ZIP_DIRS:-\$FAKE_OSV_ECOS} <<'PZ'
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
  for ga in "\$@"; do case "\$ga" in docker-archive:*) gpath=\${ga#docker-archive:};; esac; [ "\$gprev" != --platform ] || gplat=\$ga; gprev=\$ga; done
  FAKE_MD=""; if [ -n "\$gpath" ]; then gout=\$(python3 "$work/childdigest.py" "\$gpath"); FAKE_MD=\$(printf '%s\n' "\$gout" | sed -n 1p); echo "grype-tag \$(printf '%s\n' "\$gout" | sed -n 2p)" >> "\$FAKE_LOG"; fi; export FAKE_MD
  case "\$(printf '%s\n' "\${gout:-}" | sed -n 2p)" in *-arm64) export FAKE_GRYPE_MATCHES="\${FAKE_GRYPE_ARM64_MATCHES-\${FAKE_GRYPE_MATCHES:-[]}}";; esac
  python3 -c 'import json,os; st={"schemaVersion":"v6.1.9","from":os.environ["FAKE_DB_FROM"],"built":os.environ["FAKE_DB_BUILT"],"path":"/.cache/grype/db/6/vulnerability.db","valid":True}; st={k:v for k,v in st.items() if v != ""}; print(json.dumps({**({"ignoredMatches":json.loads(os.environ["FAKE_GRYPE_IGNORED"])} if "FAKE_GRYPE_IGNORED" in os.environ else {}),"matches":json.loads(os.environ.get("FAKE_GRYPE_MATCHES","[]")),"source":{"type":"image","target":({"imageID":os.environ["FAKE_MD"]} if os.environ.get("FAKE_MD") else {})},"descriptor":{"name":"grype","version":"9.9.9","db":{"status":st,"providers":{}}}}))'
else
  eco=Debian:12; case " \$* " in *go.mod*) eco=Go;; esac
  if [ -n "\${FAKE_OSV_GARBAGE:-}" ]; then echo "this is not json"; elif [ -n "\${FAKE_OSV_REPORT:-}" ]; then printf '%s\n' "\$FAKE_OSV_REPORT"; else python3 "$work/osvout.py" "\$n" "\$eco"; fi
fi
if [ "\$name" = osv-scanner ] && [ -n "\${FAKE_OSV_RC:-}" ]; then exit "\$FAKE_OSV_RC"; fi
if [ "\$name" = osv-scanner ] && [ -n "\${FAKE_OSV_ECO_ONLY:-}" ] && [ "\$eco" != "\$FAKE_OSV_ECO_ONLY" ]; then exit 0; fi
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
# one definition of the image archive (Fable on #732): check-scan.sh runs bin/layout-archive.sh and defines no
# archive or child lookup of its own
scan="$root/bin/check-scan.sh"
if ! grep -Fq 'osv_archive()' "$scan" && ! grep -Fq 'child_digest()' "$scan" \
  && grep -Fq 'bin/layout-archive.sh' "$scan"; then
  ok "AC4 check-scan.sh builds every image archive with bin/layout-archive.sh, defining no osv_archive or child_digest"
else
  bad "AC4 check-scan.sh still defines its own osv_archive or child_digest, or does not run bin/layout-archive.sh"
fi
want_ok "AC4 both listed scanners clean with packages: exit 0" "${SCAN[@]}"
if [ -f "$fx/out/scan-results.json" ] && jq -e '.listed == 2 and .ran == 2 and (.scanners | length == 2) and all(.scanners[]; .verdict == "pass" and (.version | length > 0))' "$fx/out/scan-results.json" > /dev/null 2>&1; then ok "AC4 results: listed 2, ran 2, every scanner pass with a version"; else bad "AC4 results file shape (listed/ran/scanners/version)"; fi
if [ -f "$fx/out/scan-results.json" ] && jq -e --argjson want "$(jq -s '[.[] | .amd64.manifest, .arm64.manifest | "sha256:" + .] | sort' "$fx/images/production.map" "$fx/images/fips.map")" '[.scanners[].subjects[] | select(.name | test("^(production|fips)/linux/"))] | (map(.digest) | unique | sort) == $want' "$fx/out/scan-results.json" > /dev/null 2>&1; then ok "AC4 every image subject carries a child manifest digest of the layout Build recorded (not a tag, not a tarball hash)"; else bad "AC4 subject digests are not the candidate digests"; fi
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
# "The VEX is the only exception" (register rows 18 and 38), as in cache#580 for the PR gate: grype runs with an EMPTY config file (no repo, home or XDG config), a GRYPE_* setting
# other than GRYPE_DB_CACHE_DIR and GRYPE_DB_AUTO_UPDATE stops the pass, and everything grype left out (ignoredMatches) must come from a VEX rule (namespace vex and a vex-status
# of not_affected or fixed). Real grype 0.118.0 behaviour of these shapes was probed for cache#580.
want_ok "AC4 c grype with no ignored match passes and was run with an empty config on every call" "${SCAN[@]}"
nc_=$(grep -c '^grype-config empty$' "$work/log" || true); nb_=$(grep -c -E '^grype-config (none|other)$' "$work/log" || true); ng_=$(grep -c -E '^grype (docker-archive:|file:|db update)' "$work/log" || true)
if [ "$nb_" = 0 ] && [ "$nc_" = "$ng_" ] && [ "$ng_" -gt 0 ]; then ok "AC4 c every grype call ($ng_: the database update, images and archives) got -c with an empty file"; else bad "AC4 c grype config: $nc_ empty, $nb_ other or none, of $ng_ calls"; fi
IG='{"vulnerability":{"id":"CVE-2099-0100"},"artifact":{"name":"pkgx","version":"1"}'
FAKE_GRYPE_IGNORED='[]' want_ok "AC4 c ignoredMatches empty passes" "${SCAN[@]}"
FAKE_GRYPE_IGNORED='null' want_ok "AC4 c ignoredMatches null passes" "${SCAN[@]}"
FAKE_GRYPE_IGNORED="[$IG,\"appliedIgnoreRules\":[{\"namespace\":\"vex\",\"vex-status\":\"not_affected\"}]},$IG,\"appliedIgnoreRules\":[{\"namespace\":\"vex\",\"vex-status\":\"fixed\"}]}]" want_ok "AC4 c ignored matches that are all VEX rules (not_affected, fixed) pass" "${SCAN[@]}"
FAKE_GRYPE_IGNORED="[$IG,\"appliedIgnoreRules\":[{\"namespace\":\"\",\"fix-state\":\"unknown\"}]}]" want_fail "AC4 c a finding hidden by a config or environment ignore (not a VEX rule) fails and names it" "CVE-2099-0100" "${SCAN[@]}"
FAKE_GRYPE_IGNORED="[$IG,\"appliedIgnoreRules\":[{\"namespace\":\"vex\",\"vex-status\":123}]}]" want_fail "AC4 c a vex-status that is a number fails" "other than the published VEX" "${SCAN[@]}"
FAKE_GRYPE_IGNORED="[$IG,\"appliedIgnoreRules\":[{\"namespace\":\"vex\",\"vex-status\":\"under_investigation\"}]}]" want_fail "AC4 c a vex-status that is not not_affected or fixed fails" "other than the published VEX" "${SCAN[@]}"
FAKE_GRYPE_IGNORED="[$IG,\"appliedIgnoreRules\":{\"namespace\":\"vex\",\"vex-status\":\"fixed\"}}]" want_fail "AC4 c appliedIgnoreRules that is an object, not an array, fails" "other than the published VEX" "${SCAN[@]}"
FAKE_GRYPE_IGNORED="[$IG,\"appliedIgnoreRules\":[]}]" want_fail "AC4 c an ignored match with an empty rule list fails" "other than the published VEX" "${SCAN[@]}"
FAKE_GRYPE_IGNORED="[$IG}]" want_fail "AC4 c an ignored match with no rule list fails" "other than the published VEX" "${SCAN[@]}"
FAKE_GRYPE_IGNORED="[$IG,\"appliedIgnoreRules\":[{\"vex-status\":\"fixed\"}]}]" want_fail "AC4 c a rule with no namespace fails" "other than the published VEX" "${SCAN[@]}"
FAKE_GRYPE_IGNORED="[$IG,\"appliedIgnoreRules\":[{\"namespace\":\"vex\",\"vex-status\":\"fixed\"},{\"namespace\":\"\",\"fix-state\":\"unknown\"}]}]" want_fail "AC4 c a VEX rule plus a config rule fails" "other than the published VEX" "${SCAN[@]}"
FAKE_GRYPE_IGNORED='["a string entry"]' want_fail "AC4 c a scalar ignored entry fails" "a malformed entry" "${SCAN[@]}"
FAKE_GRYPE_IGNORED='"not a list"' want_fail "AC4 c ignoredMatches that is not a list is a scan that did not run" "ignoredMatches" "${SCAN[@]}"
GRYPE_ONLY_FIXED=true want_rc "AC4 c a GRYPE_ONLY_FIXED setting stops the pass (exit 2)" 2 "${SCAN[@]}"
if grep -Fq 'GRYPE_ONLY_FIXED' <<< "$out" && ! grep -Fq 'true' <<< "$out"; then ok "AC4 c the refused variable is named and its value is not printed"; else bad "AC4 c refused variable output: ${out:0:140}"; fi
GRYPE_DB_VALIDATE_AGE=false want_rc "AC4 c a GRYPE_DB_VALIDATE_AGE setting stops the pass (exit 2)" 2 "${SCAN[@]}"
GRYPE_DB_AUTO_UPDATE=false GRYPE_DB_CACHE_DIR="$work/dbcache" want_ok "AC4 c GRYPE_DB_AUTO_UPDATE and GRYPE_DB_CACHE_DIR are allowed" "${SCAN[@]}"
# The same rule for osv-scanner (the owner: "Our published OpenVEX file is the only exception, for all four scanners"): it reads an osv-scanner.toml beside the scanned go.mod and drops the
# vulnerabilities it lists from its report, where check-osv-vex.py never sees them. Probed on osv-scanner 2.6.0: with `--config <empty file>` the toml beside go.mod no longer applies; a toml
# only in the working directory is not read for a source scan either way. Archive mode (`scan image --archive`) is NOT probed: --config is passed there too (harmless if it is ignored).
want_ok "AC4 d osv-scanner clean: every osv-scanner scan call got --config with an empty file" "${SCAN[@]}"
no_=$(grep -c '^osv-scanner scan ' "$work/log" || true); oe_=$(grep -c '^osv-config empty$' "$work/log" || true); ob_=$(grep -c -E '^osv-config (none|other)$' "$work/log" || true)
if [ "$ob_" = 0 ] && [ "$oe_" = "$no_" ] && [ "$no_" -gt 0 ]; then ok "AC4 d all $no_ osv-scanner scan calls (Go modules and image archives) got --config with an empty file"; else bad "AC4 d osv-scanner config: $oe_ empty, $ob_ other or none, of $no_ scan calls"; fi
mkfake osv-scanner 1 80
PAIR='[{"pkg": "busybox@1.37.0", "id": "CVE-2025-60876"}, {"pkg": "libssl3@3.0.0", "id": "CVE-2025-99999"}]'
for t_ in "$fx/osv-scanner.toml" "$fx/tools/requirements/osv-scanner.toml"; do printf '[[IgnoredVulns]]\nid = "CVE-2025-99999"\nreason = "x"\n' > "$t_"; done
FAKE_OSV_ECO_ONLY=Go FAKE_OSV_VULNS="$PAIR" want_fail "AC4 d an osv-scanner.toml beside each go.mod that ignores the uncovered one of two findings does not hide it (the other is excepted by the VEX)" "found vulnerabilities" "${SCAN[@]}"
rm -f "$fx/osv-scanner.toml" "$fx/tools/requirements/osv-scanner.toml"
FAKE_OSV_ECO_ONLY=Go FAKE_OSV_VULNS="$PAIR" want_fail "AC4 d with no toml the same pair fails (the baseline of the two cases above)" "found vulnerabilities" "${SCAN[@]}"
mkfake osv-scanner 0 80
OSV_SCANNER_CONFIG_FILE=x.toml want_rc "AC4 d an OSV_SCANNER_* setting other than the cache directory stops the pass (exit 2)" 2 "${SCAN[@]}"
if grep -Fq 'OSV_SCANNER_CONFIG_FILE' <<< "$out" && ! grep -Fq 'x.toml' <<< "$out"; then ok "AC4 d the refused OSV_SCANNER_* variable is named and its value is not printed"; else bad "AC4 d refused osv variable output: ${out:0:140}"; fi
OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="$work/osvdb-ext" want_rc "AC4 d even OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY is refused (exit 2): the database directory is always a fresh one inside the script's own temporary directory (a symlink to a populated directory passed the emptiness check)" 2 "${SCAN[@]}"
if grep -Fq 'OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY' <<< "$out" && ! grep -Fq 'osvdb-ext' <<< "$out"; then ok "AC4 d the refused cache-directory variable is named and its value is not printed"; else bad "AC4 d refused cache variable output: ${out:0:140}"; fi
# exit 0 does not mean an empty report: osv-scanner can list findings and still exit 0 (findings it classes as unimportant or, with call analysis, uncalled). The report is judged at ANY exit code.
mkfake osv-scanner 0 80
FAKE_OSV_RC=0 FAKE_OSV_VULNS='[{"pkg": "libssl3@3.0.0", "id": "CVE-2025-99999"}]' want_fail "AC4 e osv-scanner exits 0 with an uncovered finding in its report: the scan fails" "found vulnerabilities" "${SCAN[@]}"
FAKE_OSV_RC=0 FAKE_OSV_VULNS='[{"pkg": "busybox@1.37.0", "id": "CVE-2025-60876"}]' want_ok "AC4 e osv-scanner exits 0 with a finding the published VEX excepts: the scan passes" "${SCAN[@]}"
FAKE_OSV_RC=0 FAKE_OSV_GARBAGE=1 want_fail "AC4 e osv-scanner exits 0 with a report that cannot be read: the scan did not run" "could not run" "${SCAN[@]}"
FAKE_OSV_RC=0 want_ok "AC4 e osv-scanner exits 0 with an empty report: the scan passes" "${SCAN[@]}"
for sh_ in 'vulnerabilities is null|{"results":[{"packages":[{"package":{"name":"p","version":"1","ecosystem":"Go"},"vulnerabilities":null}]}]}' 'vulnerabilities is a string|{"results":[{"packages":[{"package":{"name":"p","version":"1","ecosystem":"Go"},"vulnerabilities":"x"}]}]}' 'results is not a list|{"results":"x"}' 'packages is not a list|{"results":[{"packages":"x"}]}' 'packages is null beside a result with packages|{"results":[{"packages":null},{"packages":[{"package":{"name":"p","version":"1","ecosystem":"Go"}}]}]}' 'packages is false|{"results":[{"packages":false},{"packages":[{"package":{"name":"p","version":"1","ecosystem":"Go"}}]}]}' 'results is null|{"results":null}' 'a result that is not an object|{"results":["x"]}' 'a null result beside a good one|{"results":[null,{"packages":[{"package":{"name":"p","version":"1","ecosystem":"Go"}}]}]}' 'a null package entry beside a good one|{"results":[{"packages":[null,{"package":{"name":"p","version":"1","ecosystem":"Go"}}]}]}' 'the report itself is a list|[]'; do
  FAKE_OSV_RC=0 FAKE_OSV_REPORT="${sh_#*|}" want_fail "AC4 e a report that is valid JSON but malformed (${sh_%%|*}) is a scan that did not run, never a clean pass" "could not run" "${SCAN[@]}"
done
want_ok "AC4 e osv-scanner clean" "${SCAN[@]}"
na_=$(grep -c '^osv-scanner scan ' "$work/log" || true); nf_=$(grep -c -E '^osv-scanner scan .* --all-vulns ' "$work/log" || true)
if [ "$nf_" = "$na_" ] && [ "$na_" -gt 0 ]; then ok "AC4 e all $na_ osv-scanner scan calls pass --all-vulns (unimportant and uncalled findings are shown, never dropped by the scanner)"; else bad "AC4 e osv-scanner flags: $nf_ of $na_ scan calls carry --all-vulns"; fi
mkfake grype 0 120; mkfake osv-scanner 1 80
want_fail "AC4 the second scanner reports findings: the script fails naming it" osv-scanner "${SCAN[@]}"
mkfake osv-scanner 0 80; mkfake grype 0 0
want_fail "AC4 zero packages scanned fails (REQ-REL-004-AC1)" packages "${SCAN[@]}"
mkfake grype 0 120
FAKE_GRYPE_FILES_ONLY=1 FAKE_GRYPE_FILES=946 want_fail "AC4 rc-5a C: a grype inventory of files only (no component carries a package URL) is zero packages and fails (REQ-REL-004-AC1)" packages "${SCAN[@]}"
FAKE_GRYPE_BADPURL=1 want_fail "AC4 rc-5a C: components whose purl is a number are not packages: zero packages fails (REQ-REL-004-AC1)" packages "${SCAN[@]}"
FAKE_GRYPE_STRPURL=not-a-purl want_fail "AC4 purl gate: components whose purl is a string that is not a package URL (not-a-purl) are not packages: zero packages fails (REQ-REL-004-AC1)" packages "${SCAN[@]}"
FAKE_GRYPE_STRPURL=pkg: want_fail "AC4 purl gate: a purl that is only the scheme (pkg:) names no package: zero packages fails (REQ-REL-004-AC1)" packages "${SCAN[@]}"
FAKE_GRYPE_FILES=946 want_ok "AC4 rc-5a C: files beside 120 packages do not change the count or the verdict" "${SCAN[@]}"
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
want_ok "AC4 grype scans each image child from a docker archive of it and osv-scanner a tar made of it" "${SCAN[@]}"
if grep -Eq '^grype docker-archive:[^ ]*grype-(production|fips)-linux-(amd64|arm64)\.tar ' "$work/log" && ! grep -q '^grype oci-dir:' "$work/log" && ! grep -q 'oci-archive' "$work/log" && grep -Eq '^osv-scanner scan image --config [^ ]+ --all-vulns --archive .*\.tar$' "$work/log" 2> /dev/null; then ok "AC4 the scanner argv carries an archive made of the layout, for grype and for osv (never oci-dir: grype applies no VEX to a layout without an image name)"; else bad "AC4 layout argv: $(grep -E '^(grype|osv)' "$work/log" | head -4 | cut -c1-160 | tr '\n' '|')"; fi
# ---- chain-v030 review S1 (REQ-CHAIN-006-AC4): grype scans each platform child of the multi-platform index, both required --------------
# grype on the index with no platform scans only the runner's own platform (linux/amd64): the arm64 child's packages were never scanned while the
# verdict was recorded for the index digest. Each variant is scanned once per child, each from a docker archive of that child alone named
# ghcr.io/fosterstack/cache:cand-<variant>-<arch> (rc-5a I: the name the VEX statements match), each child's own manifest digest is recorded, and an index that lacks either child fails.
mkfake grype 0 120; mkfake osv-scanner 0 80; : > "$work/log"
want_ok "AC4 S1 the layouts with both children pass" "${SCAN[@]}"
for v in production fips; do for a in amd64 arm64; do
  if grep -Eq "^grype docker-archive:[^ ]*grype-$v-linux-$a\.tar " "$work/log"; then ok "AC4 S1 grype scanned the $v image's linux/$a child explicitly"; else bad "AC4 S1 no grype call on the archive of the $v image's linux/$a child"; fi
  if grep -Fxq "grype-tag ghcr.io/fosterstack/cache:cand-$v-$a" "$work/log"; then ok "AC4 I the archive of the $v image's linux/$a child carries the name ghcr.io/fosterstack/cache:cand-$v-$a (the VEX statements apply to it)"; else bad "AC4 I the $v/$a archive carries no cand-$v-$a name: $(grep '^grype-tag' "$work/log" | tr '\n' ' ')"; fi
done; done
# REQ-CHAIN-006-AC8 + AC4 (rc-5a I): a check script names no registry, so the repository of the archive name comes from the published VEX itself (the one cache image product
# pkg:oci/cache?repository_url=REPO); a VEX that names none, or two different ones, cannot be judged: exit 2, nothing scanned under an invented name (AC4: cannot judge = red).
vexrepo() { # vexrepo PRODUCT... -> a VEX document whose one statement has exactly these products
  python3 - "$fx/.vex/fosterstack-cache.openvex.json" "$@" <<'PYR'
import json, sys
d = json.load(open(sys.argv[1]))
st = d["statements"][0]; st["products"] = [json.loads(x) if x[:1] in "{\"" else {"@id": x} for x in sys.argv[2:]]; d["statements"] = [st]
json.dump(d, open(sys.argv[1], "w"))
PYR
}
cp "$work/log" "$work/log.keep"; rm -rf "$work/out.keep"; cp -R "$fx/out" "$work/out.keep"; cp "$fx/.vex/fosterstack-cache.openvex.json" "$work/vex.keep"
vexrepo "pkg:oci/cache?repository_url=registry.example/team/cache&arch=amd64" "pkg:oci/cache-candidates?repository_url=ghcr.io/fosterstack/cache-candidates"
mkfake grype 0 120; mkfake osv-scanner 0 80; : > "$work/log"
want_ok "AC4 I the repository comes from the VEX: a VEX naming registry.example/team/cache is scanned under that name" "${SCAN[@]}"
if grep -Fxq "grype-tag registry.example/team/cache:cand-production-amd64" "$work/log" && ! grep -q '^grype-tag ghcr.io' "$work/log"; then ok "AC4 I the archive name carries the VEX's repository (its qualifiers dropped), not a fixed one"; else bad "AC4 I the archive name is not the VEX's repository: $(grep '^grype-tag' "$work/log" | tr '\n' ' ')"; fi
vexrepo "pkg:oci/cache-candidates?repository_url=ghcr.io/fosterstack/cache-candidates"; : > "$work/log"
want_fail "AC4 I a VEX that names no cache image repository cannot be judged: the script fails" "names no single cache image repository" "${SCAN[@]}"
if ! grep -q '^grype-tag' "$work/log"; then ok "AC4 I a VEX with no cache image repository scans nothing under an image name"; else bad "AC4 I no-repository VEX scanned: $(grep '^grype-tag' "$work/log" | tr '\n' ' ')"; fi
vexrepo "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache" "pkg:oci/cache?repository_url=ghcr.io/other/cache"; : > "$work/log"
want_fail "AC4 I a VEX that names two different cache image repositories cannot be judged: the script fails" "names no single cache image repository" "${SCAN[@]}"
if ! grep -q '^grype-tag' "$work/log"; then ok "AC4 I two repositories scan nothing under an image name"; else bad "AC4 I two-repository VEX scanned: $(grep '^grype-tag' "$work/log" | tr '\n' ' ')"; fi
cp "$work/vex.keep" "$fx/.vex/fosterstack-cache.openvex.json"; mkfake grype 0 120; mkfake osv-scanner 0 80; vexrepo "pkg:oci/cache?arch=amd64&repository_url=registry.example/team/cache#frag"; : > "$work/log"
want_ok "AC4 I a qualifier before repository_url and a fragment after it still name the repository" "${SCAN[@]}"
if grep -Fxq "grype-tag registry.example/team/cache:cand-fips-arm64" "$work/log"; then ok "AC4 I the repository is read whatever the qualifier order"; else bad "AC4 I qualifier order: $(grep '^grype-tag' "$work/log" | tr '\n' ' ')"; fi
vexrepo "pkg:oci/cache?repository_url=registry.example:5000/team/cache#repository_url=note"; : > "$work/log"
want_ok "AC4 I a repository_url written inside the fragment is not a second parameter, and a registry port is read" "${SCAN[@]}"
if grep -Fxq "grype-tag registry.example:5000/team/cache:cand-fips-arm64" "$work/log"; then ok "AC4 I the registry port stays in the repository"; else bad "AC4 I port: $(grep '^grype-tag' "$work/log" | tr '\n' ' ')"; fi
vexrepo "pkg:oci/cache@sha256:$(printf 'a%.0s' $(seq 64))?repository_url=registry.example/team/cache"; : > "$work/log"
want_ok "AC4 I the digest form of the cache image product names the repository too" "${SCAN[@]}"
# every identifier of a product counts (grype's reader takes @id and identifiers.* alike), and a cache identifier in any form the check cannot read is not guessed at
while IFS='|' read -r label p1 p2; do
  vexrepo "$p1" ${p2:+"$p2"}; : > "$work/log"
  want_fail "AC4 I $label cannot be judged: the script fails" "names no single cache image repository" "${SCAN[@]}"
  if ! grep -q '^grype-tag' "$work/log"; then ok "AC4 I $label scans nothing under an image name"; else bad "AC4 I $label scanned: $(grep '^grype-tag' "$work/log" | tr '\n' ' ')"; fi
done <<'CASES'
a second repository only in identifiers.purl|{"@id":"pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache","identifiers":{"purl":"pkg:oci/cache?repository_url=ghcr.io/other/cache"}}|
a second repository after the qualifier arch|pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache|pkg:oci/cache?arch=amd64&repository_url=ghcr.io/other/cache
a duplicate repository_url|pkg:oci/cache?repository_url=ghcr.io/a/cache&repository_url=ghcr.io/a/cache|
an empty repository_url|pkg:oci/cache?repository_url=|
a trailing slash in the repository|pkg:oci/cache?repository_url=registry.example/team/|
an empty path segment in the repository|pkg:oci/cache?repository_url=registry.example//team/cache|
a port with no number|pkg:oci/cache?repository_url=registry.example:/team/cache|
a repository with no path|pkg:oci/cache?repository_url=registry.example|
a newline after the repository|{"@id":"pkg:oci/cache?repository_url=registry.example/team/cache\n"}|
a percent-encoded repository|pkg:oci/cache?repository_url=ghcr.io%2Ffosterstack%2Fcache|
a path after the image name|pkg:oci/cache/extra?repository_url=ghcr.io/fosterstack/cache|
a product that is not an object|"pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache"|
CASES
cp "$work/vex.keep" "$fx/.vex/fosterstack-cache.openvex.json"; mkfake grype 0 120; mkfake osv-scanner 0 80
cp "$work/log.keep" "$work/log"; rm -rf "$fx/out"; cp -R "$work/out.keep" "$fx/out"
bare_=$(grep -cE '^grype oci-dir:' "$work/log" || true)   # a count, not a pipe into grep -q (pipefail + SIGPIPE)
if [ "$bare_" != 0 ]; then bad "AC4 S1 a grype image scan read the layout directly (no image name, so no VEX applies)"; else ok "AC4 S1 no grype image scan reads the layout directly"; fi
for v in production fips; do for a in amd64 arm64; do
  cd_=$(jq -r ".$a.manifest" "$fx/images/$v.map")
  if jq -e --arg n "$v/linux/$a" --arg d "sha256:$cd_" '.scanners[] | select(.name == "grype") | .subjects | map(select(.name == $n and .digest == $d and .packages > 0 and .verdict == "pass")) | length == 1' "$fx/out/scan-results.json" > /dev/null 2>&1; then ok "AC4 S1 the results record the $v linux/$a child by its own manifest digest"; else bad "AC4 S1 no grype subject $v/linux/$a with digest sha256:$cd_"; fi
done; done
# ---- chain-v030 review (Opus on cache#550): osv-scanner reads a docker-save archive, not a tar of the OCI layout (REQ-CHAIN-006-AC4) ----
# Each variant is scanned once per platform child, from an archive whose manifest.json names that child's config and layers, so the real tool can read it
# and the packages it counts are the child's own.
for v in production fips; do for a in amd64 arm64; do
  cfg=$(jq -r ".$a.config" "$fx/images/$v.map"); lay=$(jq -r ".$a.layer" "$fx/images/$v.map")
  if grep -qx "osv-archive config=$cfg layers=$lay" "$work/log"; then ok "AC4 osv the $v image's linux/$a child is scanned from an archive naming its own config and layer"; else bad "AC4 osv no archive naming the $v linux/$a child's config $cfg and layer $lay reached osv-scanner"; fi
  cd_=$(jq -r ".$a.manifest" "$fx/images/$v.map")
  if jq -e --arg n "$v/linux/$a" --arg d "sha256:$cd_" '.scanners[] | select(.name == "osv-scanner") | .subjects | map(select(.name == $n and .digest == $d and .packages > 0 and .verdict == "pass")) | length == 1' "$fx/out/scan-results.json" > /dev/null 2>&1; then ok "AC4 osv the results record the $v linux/$a child by its own manifest digest"; else bad "AC4 osv the results lack the $v linux/$a child by its manifest digest"; fi
done; done
# the archive holds ONLY the generated manifest.json, then this child's config and layer blobs, in that order (ruling on cache#558, all four reviewers)
for v in production fips; do for a in amd64 arm64; do
  cfg=$(jq -r ".$a.config" "$fx/images/$v.map"); lay=$(jq -r ".$a.layer" "$fx/images/$v.map")
  if grep -qx "osv-members manifest.json,blobs/sha256/$cfg,blobs/sha256/$lay" "$work/log"; then ok "AC4 osv the $v linux/$a archive's members are exactly manifest.json, its config and its layer, in that order"; else bad "AC4 osv the $v linux/$a archive holds other members than the generated manifest.json and the child's own config and layer (want manifest.json,$cfg,$lay; log: $(grep -h osv-members "$work/log" | head -2 | cut -c1-200))"; fi
done; done
# a stray root manifest.json (check-bind accepts extra top-level files of the layout) naming the OTHER child, and a fake.tar, must not replace the generated manifest.json:
# the real reader takes the FIRST manifest.json of the tar, so the archive is built from the explicit member list only (ruling on cache#558)
acfg=$(jq -r .amd64.config "$fx/images/production.map"); alay=$(jq -r .amd64.layer "$fx/images/production.map"); rcfg=$(jq -r .arm64.config "$fx/images/production.map"); rlay=$(jq -r .arm64.layer "$fx/images/production.map")
printf '[{"Config":"blobs/sha256/%s","RepoTags":null,"Layers":["blobs/sha256/%s"]}]' "$rcfg" "$rlay" > "$fx/images/production/manifest.json"; printf 'a layer of somebody else' > "$fx/images/production/fake.tar"
: > "$work/log"; want_ok "AC4 osv a stray root manifest.json naming the other child, and a fake.tar, in the layout: the scan still passes" "${SCAN[@]}"
if [ "$(grep -cx "osv-archive config=$acfg layers=$alay" "$work/log")" = 1 ] && [ "$(grep -c "osv-archive config=$rcfg " "$work/log")" = 1 ] && ! grep -q 'fake.tar' "$work/log"; then ok "AC4 osv the production amd64 archive still names its own config and layer (the stray manifest.json is not in any archive, neither is fake.tar)"; else bad "AC4 osv a stray root manifest.json or a fake.tar reached an archive: $(grep -E 'osv-archive|osv-members' "$work/log" | head -4 | cut -c1-200)"; fi
rm -f "$fx/images/production/manifest.json" "$fx/images/production/fake.tar"
# a child whose manifest lists no layer (or a digest that is not sha256:<64 hex>) yields no archive: the leg fails closed, it never scans an empty image
cp -R "$fx/images/fips" "$work/keep-fips-e"; cp "$fx/images/fips.map" "$work/keep-fips-e.map"; cp "$fx/digests.json" "$work/dig.e"
rm -rf "$fx/images/fips"; EMPTY_LAYERS=1 python3 "$work/mkoci.py" "$fx/images/fips" fips > /dev/null; mkdig "$fx"
: > "$work/log"; want_fail "AC4 osv a child manifest with no layer: the archive is not made and the scan fails" "archive of" "${SCAN[@]}"
rm -rf "$fx/images/fips"; mv "$work/keep-fips-e" "$fx/images/fips"; mv "$work/keep-fips-e.map" "$fx/images/fips.map"; cp "$work/dig.e" "$fx/digests.json"
: > "$work/log"; want_ok "AC4 osv the layouts are intact again after the stray and empty-layer cases" "${SCAN[@]}"
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
rm -rf "$fx/images/production"; NO_ATT_ANNOTATION=1 python3 "$work/mkoci.py" "$fx/images/production" production linux/amd64 linux/arm64 unknown/unknown > /dev/null; mkdig "$fx"
want_fail "AC4 S1 an unknown/unknown descriptor that is not buildkit's (no vnd.docker.reference annotations) fails naming it" "unknown/unknown" "${SCAN[@]}"
rm -rf "$fx/images/production"; ATT_DIGEST_OTHER=1 python3 "$work/mkoci.py" "$fx/images/production" production linux/amd64 linux/arm64 unknown/unknown > /dev/null; mkdig "$fx"
want_fail "AC4 S1 an unknown/unknown descriptor whose reference digest is none of the two children fails" "unknown/unknown" "${SCAN[@]}"
rm -rf "$fx/images/production"; ATT_ODD=array-digest python3 "$work/mkoci.py" "$fx/images/production" production linux/amd64 linux/arm64 unknown/unknown > /dev/null; mkdig "$fx"
want_fail "AC4 S1 an unknown/unknown descriptor whose reference digest is a list holding a child digest fails" "unknown/unknown" "${SCAN[@]}"
rm -rf "$fx/images/production"; ATT_ODD=plain-image python3 "$work/mkoci.py" "$fx/images/production" production linux/amd64 linux/arm64 unknown/unknown > /dev/null; mkdig "$fx"
want_fail "AC4 S1 an ordinary image manifest carrying the reference annotations as unknown/unknown is not exempt (its own manifest is not a provenance manifest)" "provenance manifest" "${SCAN[@]}"
rm -rf "$fx/images/production"; ATT_ODD=case-variant-keys python3 "$work/mkoci.py" "$fx/images/production" production linux/amd64 linux/arm64 unknown/unknown > /dev/null; mkdig "$fx"
want_fail "AC4 S1 an index descriptor with keys that differ only in case (Platform next to platform) is refused" "differ only in case" "${SCAN[@]}"
rm -rf "$fx/images/production"; ATT_ODD=unicode-key python3 "$work/mkoci.py" "$fx/images/production" production linux/amd64 linux/arm64 unknown/unknown > /dev/null; mkdig "$fx"
want_fail "AC4 S1 an index descriptor with a key outside printable ASCII (a case-folding twin of os) is refused" "outside printable ASCII" "${SCAN[@]}"
rm -rf "$fx/images/production"; ATT_ODD=two-values python3 "$work/mkoci.py" "$fx/images/production" production linux/amd64 linux/arm64 unknown/unknown > /dev/null; mkdig "$fx"
want_fail "AC4 S1 a provenance manifest blob holding two JSON values (an image, then a JSON-only manifest) is not exempt" "provenance manifest" "${SCAN[@]}"
rm -rf "$fx/images/production"; ATT_ODD=annotations-list python3 "$work/mkoci.py" "$fx/images/production" production linux/amd64 linux/arm64 unknown/unknown linux/s390x > /dev/null; mkdig "$fx"
want_fail "AC4 S1 an unreadable annotations value does not hide a later linux/s390x descriptor" "linux/s390x" "${SCAN[@]}"
restore_prod
# the lines other_platforms() reads are taken byte for byte (cache#575 first look, all four reviewers): trailing whitespace on a provenance descriptor's digest, or on a platform string, must not be trimmed away
rm -rf "$fx/images/production"; ATT_DIGEST_PAD=" " python3 "$work/mkoci.py" "$fx/images/production" production linux/amd64 linux/arm64 unknown/unknown > /dev/null; mkdig "$fx"
want_fail "AC4 S1 a provenance descriptor whose digest has a trailing space is refused, not trimmed into a valid one" "provenance manifest" "${SCAN[@]}"
restore_prod
rm -rf "$fx/images/production"; ATT_DIGEST_PAD=$'\t' python3 "$work/mkoci.py" "$fx/images/production" production linux/amd64 linux/arm64 unknown/unknown > /dev/null; mkdig "$fx"
want_fail "AC4 S1 a provenance descriptor whose digest has a trailing tab is refused, not trimmed into a valid one" "provenance manifest" "${SCAN[@]}"
restore_prod
rm -rf "$fx/images/production"; python3 "$work/mkoci.py" "$fx/images/production" production linux/amd64 linux/arm64 "linux/amd64 " > /dev/null; mkdig "$fx"
want_fail "AC4 S1 a platform string with a trailing space is named as it is, not as the real child" "(linux/amd64 )" "${SCAN[@]}"
restore_prod
FAKE_GRYPE_MD=mismatch want_fail "AC4 S1 grype reporting another image than the child recorded fails" "names image ID" "${SCAN[@]}"
FAKE_GRYPE_MD=missing want_fail "AC4 S1 grype reporting no image ID fails" "names image ID" "${SCAN[@]}"
want_ok "AC4 S1 grype reporting each child's own digest passes" "${SCAN[@]}"
# ---- round 1 F1 (Codex A1, B1): the bytes Check reads are the bytes Build recorded -------------------------------------------------------------
# stage-start authenticates digests.json; the layouts and archives it downloads must be bound to it before any scan, load or run (an index.json that
# merely exists is no binding): the layout is re-derived from the digest (index, child manifests, every blob re-hashed) and each archive re-hashed.
nothing_ran() { ! grep -Eq '^(grype|osv-scanner) (oci-dir|docker-archive|scan|file)|^docker (load|run)' "$work/log"; }
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
if jq -e '[.scanners[] | select(.name == "osv-scanner") | .subjects[] | select(.name | test("^production/linux/"))] | length == 2 and all(.[]; .verdict == "pass" and .vex_suppressed == 1)' "$fx/out/scan-results.json" > /dev/null 2>&1; then ok "AC4 F3 the result says how many findings the VEX excepted on the subject"; else bad "AC4 F3 vex_suppressed missing from the osv subject: $(jq -c '[.scanners[] | select(.name == "osv-scanner") | .subjects[0]]' "$fx/out/scan-results.json" 2>&1 | cut -c1-200)"; fi
FAKE_OSV_VULNS='[{"pkg": "github.com/golang-jwt/jwt/v4@v4.5.0", "id": "GHSA-29wx-vh33-7x7r", "aliases": ["CVE-2024-51744", "GO-2024-3250"]}]' \
  want_ok "AC4 F3 a finding whose id differs from the statement's name but whose alias equals it is excepted (the OSV id is the GHSA, the VEX names the CVE)" "${SCAN[@]}"
FAKE_OSV_VULNS='[{"pkg": "busybox@1.36.0", "id": "CVE-2025-60876"}]' want_fail "AC4 F3 the same CVE on another version of the package than the statement's subcomponent is not excepted" osv-scanner "${SCAN[@]}"
FAKE_OSV_VULNS='[{"pkg": "libssl3@3.0.0", "id": "CVE-2025-99999"}]' want_fail "AC4 F3 a finding no statement names is not excepted" osv-scanner "${SCAN[@]}"
FAKE_OSV_VULNS='[{"pkg": "busybox@1.37.0", "id": "CVE-2025-60876"}, {"pkg": "libssl3@3.0.0", "id": "CVE-2025-99999"}]' want_fail "AC4 F3 one excepted and one uncovered finding: the uncovered one fails the scan" osv-scanner "${SCAN[@]}"
printf '{"statements": "not a list"}\n' > "$fx/.vex/fosterstack-cache.openvex.json"
FAKE_OSV_VULNS="$VBUSY" want_fail "AC4 F3 an unreadable VEX document excepts nothing (fail closed)" osv-scanner "${SCAN[@]}"
cp "$root/test-evidence/vex-scope/busybox.openvex.json" "$fx/.vex/fosterstack-cache.openvex.json"
# a statement scoped to ONE architecture excepts the finding on that platform child only: osv-scanner scans each child, and the child's platform reaches the matcher
archvex() { python3 - "$root/test-evidence/vex-scope/busybox.openvex.json" "$fx/.vex/fosterstack-cache.openvex.json" "$@" <<'PYV'
import copy, json, sys
d = json.load(open(sys.argv[1])); base = "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache"
prod = d["statements"][1]["products"][0]; assert prod["@id"] == base
out = []
for a in sys.argv[3:]:
    q = copy.deepcopy(prod); q["@id"] = base + "&arch=" + a; q["identifiers"] = {"purl": q["@id"]}; out.append(q)
d["statements"][1]["products"] = out + d["statements"][1]["products"][1:]
json.dump(d, open(sys.argv[2], "w"))
PYV
}
archvex amd64
FAKE_OSV_VULNS="$VBUSY" want_fail "AC4 F3 a statement scoped to arch amd64 does not except the same finding on the arm64 child" linux/arm64 "${SCAN[@]}"
if jq -e '[.scanners[] | select(.name == "osv-scanner") | .subjects[] | select(.name | test("^production/linux/"))] | map({(.name): .verdict}) | add | .["production/linux/amd64"] == "pass" and .["production/linux/arm64"] == "fail"' "$fx/out/scan-results.json" > /dev/null 2>&1; then ok "AC4 F3 the amd64-scoped statement excepts the finding on the amd64 child and not on the arm64 child"; else bad "AC4 F3 per-arch verdicts wrong: $(jq -c '[.scanners[] | select(.name == "osv-scanner") | .subjects[] | {name, verdict}]' "$fx/out/scan-results.json" 2>&1 | head -c 300)"; fi
archvex amd64 arm64
FAKE_OSV_VULNS="$VBUSY" want_fail "AC4 F3 statements scoped to each architecture do not except the finding on the go.mod sources (no platform)" go.mod "${SCAN[@]}"
if jq -e '[.scanners[] | select(.name == "osv-scanner") | .subjects[] | select(.name | test("^(production|fips)/linux/"))] | length == 4 and all(.[]; .verdict == "pass" and .vex_suppressed == 1)' "$fx/out/scan-results.json" > /dev/null 2>&1; then ok "AC4 F3 one statement scoped to each architecture excepts the finding on both platform children of each image"; else bad "AC4 F3 per-arch verdicts wrong: $(jq -c '[.scanners[] | select(.name == "osv-scanner") | .subjects[] | {name, verdict}]' "$fx/out/scan-results.json" 2>&1 | head -c 300)"; fi
for badplat in amd64 odd/amd64 linux/arm64/v8 linux/ windows/amd64; do
  pout=$(python3 "$root/bin/check-osv-vex.py" --vex "$root/test-evidence/vex-scope/busybox.openvex.json" --report /dev/null --platform "$badplat" 2>&1) && prc=0 || prc=$?
  if [ "$prc" = 1 ] && grep -Fq -- "platform" <<< "$pout" && grep -Fq -- "$badplat" <<< "$pout"; then ok "AC4 F3 check-osv-vex.py refuses the platform '$badplat' (only linux/amd64, linux/arm64 or none) naming it"; else bad "AC4 F3 check-osv-vex.py accepted or mis-reported platform '$badplat': rc=$prc ${pout:0:140}"; fi
done
cp "$root/test-evidence/vex-scope/busybox.openvex.json" "$fx/.vex/fosterstack-cache.openvex.json"
mkfake osv-scanner 0 80
# ---- REQ-CHAIN-006-AC15: fresh vulnerability databases from the scanner's own host --------------------------------------------
printf '{"scanners":["grype"]}\n' > "$fx/.github/policy/scanners.json"; rm -f "$fx/out/scan-results.json"
want_ok "AC15 a fresh grype database (built 17.5 h before now) from grype.anchore.io: the scan proceeds" "${SCAN[@]}"
if [ -f "$fx/out/scan-results.json" ] && jq -e --arg u "$GDB_FROM" --arg s "sha256:$GDB_SUM" '.scanners[0] | .db_source_url == $u and .db_built_or_published == "2026-10-09T06:30:41Z" and .db_digest == $s and .db_source_basis == "observed"' "$fx/out/scan-results.json" > /dev/null 2>&1; then ok "AC15 the results carry grype's database source URL (basis: observed), build date and digest"; else bad "AC15 db fields in scan-results.json: $(jq -c '.scanners[0] | {db_source_url, db_built_or_published, db_digest}' "$fx/out/scan-results.json" 2>&1 | cut -c1-160)"; fi
u=$(grep -n '^grype db update' "$work/log" | head -1 | cut -d: -f1 || true); s=$(grep -n '^grype .*\(docker-archive\|oci-dir\|file\):' "$work/log" | head -1 | cut -d: -f1 || true)
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
OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="$pre" want_rc "AC15 a pre-set osv cache directory (here a populated one) is refused before anything runs (the databases must be downloaded fresh in this job)" 2 "${SCAN[@]}"
FAKE_OSV_MODIFIED=2026-10-07T00:00:00Z want_fail "AC15 an osv database whose newest record is 72 h old fails closed (not refreshed)" "older than 48 hours" "${SCAN[@]}"
FAKE_OSV_ZIP=none want_fail "AC15 no osv database zip in the cache after the run fails closed" "no osv database" "${SCAN[@]}"
FAKE_OSV_ZIP=empty want_fail "AC15 an osv database zip without records fails closed" "no record" "${SCAN[@]}"
FAKE_OSV_ZIP=nomodified want_fail "AC15 an osv database whose records carry no modified date fails closed" "modified" "${SCAN[@]}"
FAKE_OSV_ZIP=broken want_fail "AC15 an unreadable osv database zip fails closed" "unreadable" "${SCAN[@]}"
FAKE_OSV_ECOS="Go Debian:12 PyPI" want_fail "AC15 an osv database for an ecosystem the scan does not target fails closed" "not one the scan targets" "${SCAN[@]}"
FAKE_OSV_ZIP_DIRS="Go Debian" want_ok "AC15 rc-5a E: a reported Debian:12 is covered by the zip directory of its family (Debian/all.zip): the family match is used" "${SCAN[@]}"
FAKE_OSV_ZIP_DIRS="Go Debian Debian:11" want_fail "AC15 rc-5a E: a stray zip for another release (Debian:11) beside the covering Debian zip is still refused as not a target" "not one the scan targets" "${SCAN[@]}"
FAKE_OSV_ZIP_DIRS="Go Debian:11" want_fail "AC15 rc-5a E: a zip for another release of the family (Debian:11) does not cover a reported Debian:12" "no osv database zip for" "${SCAN[@]}"
FAKE_OSV_ECOS="Go" want_fail "AC15 rc-5a E: a reported ecosystem (Debian:12) with no osv database zip fails closed, even when another ecosystem has one" "no osv database zip for" "${SCAN[@]}"
rm -f "$fx/out/scan-results.json"; FAKE_OSV_DB_RC=3 run "${SCAN[@]}"
if [ "$rc" = 1 ] && grep -Fq "osv-scanner could not run" <<< "$out" && ! jq -e 'any(.scanners[]?; .verdict == "pass")' "$fx/out/scan-results.json" > /dev/null 2>&1; then ok "AC15 an osv database download failure (non-zero exit) fails closed and nothing is recorded as clean"; else bad "AC15 osv download failure -> rc=$rc: ${out:0:140}"; fi
printf '{"scanners":["grype","osv-scanner"]}\n' > "$fx/.github/policy/scanners.json"
# ---- REQ-CHAIN-006-AC6: check-fips.sh -----------------------------------------------------------------------------------------
cat > "$fake/docker" <<'EOF'
#!/usr/bin/env bash
echo "docker $* ${DOCKER_DEFAULT_PLATFORM:+--platform $DOCKER_DEFAULT_PLATFORM}" >> "$FAKE_LOG"; mkdir -p "$FAKE_DIR"; [ "$1" = image ] && shift
case "$1" in
  load) [ "$(tar -tf "${3:-x}" 2> /dev/null | grep -c 'index.json')" -ge 1 ] || { echo "docker: load: not an OCI layout archive" >&2; exit 1; }
        tar -tf "${3:-x}" > "$FAKE_DIR/members-$(basename "${3:-x}" .tar)" 2> /dev/null
        img=$(basename "${3:-x}" .tar); echo "Loaded image: fscache:$img";;
  run) for a in "$@"; do case "$a" in fscache:production|*production*) v=production;; fscache:fips|*fips*) v=fips;; esac; done
       [ -f "$FAKE_DIR/run-fails" ] && { echo "docker: start failed" >&2; exit 125; }
       echo "cid-$v"; echo "$v" > "$FAKE_DIR/last";;
  port) case "$2" in *production*) echo "127.0.0.1:40001";; *) echo "127.0.0.1:40002";; esac;;
  inspect) echo "$*" >> "$FAKE_DIR/removed"; case "$*" in *--format*localhost/fscache-serve-candidate) if [ -f "$FAKE_DIR/retag" ]; then echo "sha256:$(printf '%064d' 8)"; else echo "sha256:$(printf '%064d' 7)"; fi;; *--format*) echo "sha256:$(printf '%064d' 7)";; esac;;
  rm|stop|logs) echo "$*" >> "$FAKE_DIR/removed";;
esac
exit 0
EOF
FXD_4="$fake/curl"
cat > "$FXD_4" <<'EOF'
#!/usr/bin/env bash
echo "curl $*" >> "$FAKE_LOG"
for a in "$@"; do case "$a" in *:40001/statusz*) f="$FAKE_DIR/status-production.json";; *:40002/statusz*) f="$FAKE_DIR/status-fips.json";; esac; done
[ -n "${f:-}" ] && [ -f "$f" ] && { cat "$f"; exit 0; }
exit 7
EOF
FXD_3="$fake/curl"
chmod +x "$fake/docker" "$FXD_3"
st() { mkdir -p "$work/fakedir"; printf '%s\n' "$2" > "$work/fakedir/status-$1.json"; }
GOODF='{"fips140":true,"fips140_note":"active (Go validated module v1.0.0, CMVP cert #5247)"}'
GOODP='{"fips140":false,"fips140_note":"off"}'
FIPS=(check-fips.sh --digests digests.json --images images --out out)
resetf() { rm -rf "$work/fakedir"; mkdir -p "$work/fakedir"; st production "$GOODP"; st fips "$GOODF"; rm -f "$fx/out/fips-result.json"; }
resetf; want_ok "AC6 fips active with the validated module v1.0.0 and production off: exit 0" "${FIPS[@]}"
if [ -f "$fx/out/fips-result.json" ] && jq -e '(.images | length) == 2' "$fx/out/fips-result.json" > /dev/null 2>&1 && ! grep -q 5247 "$fx/out/fips-result.json"; then ok "AC6 the result lists both images and does not report the certificate number (it is a documented mapping, not something a binary reports)"; else bad "AC6 fips-result.json shape, or it reports the certificate number"; fi
if [ "$(grep -c '^docker run' "$work/log" 2> /dev/null || echo 0)" = 2 ] && [ -f "$work/fakedir/removed" ] && [ "$(wc -l < "$work/fakedir/removed")" -ge 2 ]; then ok "AC6 both candidate images were started and both containers removed"; else bad "AC6 each candidate must be started (docker run) and removed"; fi
# ---- REQ-SUP-001-AC33: docker load gets the layout's named members only (the three Check scripts that load a candidate) --------------------
orphan=$(printf orphan | python3 -c 'import hashlib,sys;print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())')
plant_stray() { # LAYOUT: a root manifest.json (docker would read a layout holding one as a docker-save archive), a stray tar and a hash-valid blob nothing names
  printf '[{"Config":"blobs/sha256/%s","RepoTags":null,"Layers":[]}]' "$(printf '%064d' 1)" > "$1/manifest.json"; printf 'a layer of somebody else' > "$1/fake.tar"; printf orphan > "$1/blobs/sha256/$orphan"
}
unplant_stray() { rm -f "$1/manifest.json" "$1/fake.tar" "$1/blobs/sha256/$orphan"; }
members_only() { # FILE LAYOUT-DIR: what the fake docker was given is EXACTLY oci-layout, index.json and the blobs the layout's index and its two linux children name (read here from the layout itself)
  [ -s "$1" ] || { MO_WHY="no list"; return 1; }
  MO_WHY=$(diff <(python3 - "$2" <<'PYX' | sort
import json, os, sys
root = sys.argv[1]
def blob(d): return json.load(open(os.path.join(root, "blobs", "sha256", d.split(":")[1])))
print("oci-layout"); print("index.json")
idx = json.load(open(os.path.join(root, "index.json")))["manifests"][0]["digest"]
print("blobs/sha256/" + idx.split(":")[1])
for m in blob(idx)["manifests"]:   # every descriptor of the index: its manifest, that manifest's config and layers
    man = blob(m["digest"]); print("blobs/sha256/" + m["digest"].split(":")[1])
    for d in [man["config"]["digest"]] + [l["digest"] for l in man["layers"]]: print("blobs/sha256/" + d.split(":")[1])
PYX
) <(sort "$1") | tr '\n' ' ') && [ -z "$MO_WHY" ]
}
plant_stray "$fx/images/production"; plant_stray "$fx/images/fips"
resetf; want_ok "AC33 fips: a layout holding a stray manifest.json, a fake.tar and an unreferenced blob still passes" "${FIPS[@]}"
for v in production fips; do
  if members_only "$work/fakedir/members-$v" "$fx/images/$v"; then ok "AC33 check-fips loads the $v layout from its named members only"; else bad "AC33 check-fips handed docker load [$MO_WHY]: $(tr '\n' ' ' < "$work/fakedir/members-$v" 2> /dev/null | cut -c1-200)"; fi
done
unplant_stray "$fx/images/production"; unplant_stray "$fx/images/fips"
# check-bind.py itself: the member list it writes, no list for a layout it refuses, a refusal when the list cannot be written, and an index that names more than the two children
bind() { (cd "$fx" && python3 bin/check-bind.py --digests digests.json --images images "$@" 2>&1); }
rm -rf "$work/ml"; mkdir -p "$work/ml"; out=$(bind --members-out "$work/ml") && rc=0 || rc=$?
if [ "$rc" = 0 ] && members_only "$work/ml/production.members" "$fx/images/production" && members_only "$work/ml/fips.members" "$fx/images/fips"; then ok "AC33 check-bind --members-out writes exactly the named members of each layout"; else bad "AC33 check-bind member lists (rc=$rc): $out"; fi
rm -rf "$work/keep-ml"; cp -R "$fx/images/production" "$work/keep-ml"; printf 'tampered' >> "$fx/images/production/blobs/sha256/$(jq -r .amd64.layer "$fx/images/production.map")"
rm -rf "$work/ml"; mkdir -p "$work/ml"; out=$(bind --members-out "$work/ml") && rc=0 || rc=$?
rm -rf "$fx/images/production"; cp -R "$work/keep-ml" "$fx/images/production"
if [ "$rc" = 1 ] && [ -z "$(ls "$work/ml")" ]; then ok "AC33 check-bind refuses a layout that is not Build's and writes no member list"; else bad "AC33 check-bind on a tampered layout rc=$rc, lists: $(ls "$work/ml" | tr '\n' ' ')"; fi
out=$(bind --members-out "$work/no-such-dir") && rc=0 || rc=$?
if [ "$rc" = 1 ] && grep -Fq 'member list could not be written' <<< "$out"; then ok "AC33 check-bind refuses when the member list cannot be written"; else bad "AC33 check-bind with an unwritable list directory rc=$rc: $out"; fi
# oci-layout and index.json are the layout's own regular files: a link there would be archived as a link, and read through by the bind
for own in index.json oci-layout; do
  rm -rf "$work/keep-sl"; cp -R "$fx/images/fips" "$work/keep-sl"; mv "$fx/images/fips/$own" "$fx/images/fips/$own.real"; ln -s "$own.real" "$fx/images/fips/$own"
  out=$(bind) && rc=0 || rc=$?
  rm -rf "$fx/images/fips"; cp -R "$work/keep-sl" "$fx/images/fips"
  if [ "$rc" = 1 ] && grep -Fq "$own" <<< "$out"; then ok "AC33 check-bind refuses a layout whose $own is a symbolic link"; else bad "AC33 a symlinked $own passed the bind (rc=$rc): $out"; fi
done
rm -rf "$work/keep-f3"; cp -R "$fx/images/fips" "$work/keep-f3"; cp "$fx/images/fips.map" "$work/keep-f3.map"; cp "$fx/digests.json" "$work/dig.f3"
# a third descriptor (buildkit's provenance manifest, unknown/unknown): the scan judges it; the load gets its manifest, config and layers too
rm -rf "$fx/images/fips"; python3 "$work/mkoci.py" "$fx/images/fips" fips linux/amd64 linux/arm64 unknown/unknown > /dev/null; mkdig "$fx"
resetf; want_ok "AC33 an index with a third descriptor passes the bind" "${FIPS[@]}"
if members_only "$work/fakedir/members-fips" "$fx/images/fips"; then ok "AC33 the third descriptor's manifest, config and layer are archived with the two children"; else bad "AC33 members with a third descriptor [$MO_WHY]"; fi
# an extra descriptor whose manifest cannot be read as an image manifest (two JSON values in the blob) is refused when the caller will load the layout (the scan names it itself)
rm -rf "$fx/images/fips"; ATT_ODD=two-values python3 "$work/mkoci.py" "$fx/images/fips" fips linux/amd64 linux/arm64 unknown/unknown > /dev/null; mkdig "$fx"
resetf; want_fail "AC33 an extra descriptor whose manifest is not readable is refused before any load" "check-bind" "${FIPS[@]}"
if ! grep -q '^docker load' "$work/log"; then ok "AC33 nothing was loaded behind the unreadable extra manifest"; else bad "AC33 docker load ran behind an unreadable extra manifest"; fi
rm -rf "$fx/images/fips"; python3 "$work/mkoci.py" "$fx/images/fips" fips linux/amd64 linux/arm64 unknown/unknown > /dev/null; mkdig "$fx"
# an extra descriptor whose digest string is not canonical (a trailing space) is refused when the caller will load the layout
rm -rf "$fx/images/fips"; ATT_DIGEST_PAD=" " python3 "$work/mkoci.py" "$fx/images/fips" fips linux/amd64 linux/arm64 unknown/unknown > /dev/null; mkdig "$fx"
resetf; want_fail "AC33 an extra descriptor with a non-canonical digest string is refused before any load" "check-bind" "${FIPS[@]}"
if ! grep -q '^docker load' "$work/log"; then ok "AC33 nothing was loaded behind the non-canonical descriptor digest"; else bad "AC33 docker load ran behind a non-canonical descriptor digest"; fi
rm -rf "$fx/images/fips"; python3 "$work/mkoci.py" "$fx/images/fips" fips linux/amd64 linux/arm64 unknown/unknown > /dev/null; mkdig "$fx"
# ... and one whose blob is gone is refused before any load
rm -f "$fx/images/fips/blobs/sha256/$(jq -r .unknown.manifest "$fx/images/fips.map")"
resetf; want_fail "AC33 an index naming a descriptor whose blob the layout lacks is refused before any load" "check-bind" "${FIPS[@]}"
if ! grep -q '^docker load' "$work/log"; then ok "AC33 nothing was loaded behind the index with a missing descriptor blob"; else bad "AC33 docker load ran behind an index with a missing descriptor blob"; fi
rm -rf "$fx/images/fips"; cp -R "$work/keep-f3" "$fx/images/fips"; cp "$work/keep-f3.map" "$fx/images/fips.map"; cp "$work/dig.f3" "$fx/digests.json"
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
import signal, time
term_delay = float(os.environ.get("FAKE_TERM_DELAY", "0"))
die_after = float(os.environ.get("FAKE_DIE_AFTER", "0"))
if die_after and not kind:   # one of the check's own servers (not a fake container) that exits shortly after it started answering
    import threading
    threading.Timer(die_after, lambda: os._exit(1)).start()
if term_delay and not kind:   # one of the check's own servers (not a fake container) takes a while to die after SIGTERM, listening meanwhile
    signal.signal(signal.SIGTERM, lambda *a: (time.sleep(term_delay), os._exit(0)))
addr = os.environ.get("FSCACHE_ADDR", ":8080")
with open(os.path.join(os.environ.get("FAKE_DIR", "."), "pid-%s" % os.getpid()), "w") as f:   # the test asks afterwards which servers are still alive
    f.write(str(os.getpid()))
if not kind:   # one of the check's own servers: the test asks afterwards which address the check gave it
    with open(os.path.join(os.environ.get("FAKE_DIR", "."), "addr-%s" % os.getpid()), "w") as f:
        f.write(addr + "\n")
server = http.server.HTTPServer(("127.0.0.1", int(addr.rsplit(":", 1)[1])), H)
# fscache logs the address it actually bound as JSON on stdout (":0" shows the real port); the check reads the port
# from that line
bound = "127.0.0.1:%d" % server.server_address[1]
print(json.dumps({"level": "INFO", "msg": "fscache: starting", "addr": bound}), flush=True)
server.serve_forever()
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
        tar -tf "${3:-x}" > "$FAKE_DIR/members-$(basename "${3:-x}" .tar)" 2> /dev/null
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
# the check picks free ports for its servers and waits for them to die (REQ-PLAT-001-AC1): suites running side by side, or a server left on the old fixed ports 19101-19103, never answer for the binary under test
mkarch "$fa/dist"
arun FAKE_TERM_DELAY=2 -- "${ART[@]}"
alive=0; for pf in "$work"/fakedir/pid-*; do [ -f "$pf" ] && kill -0 "$(cat "$pf")" 2> /dev/null && alive=$((alive + 1)); done
if [ "$rc" = 0 ] && ls "$work"/fakedir/pid-* > /dev/null 2>&1 && [ "$alive" = 0 ]; then ok "ART the check waits for its servers to die: none of its three is alive when it exits"; else bad "ART servers outlived the check (rc=$rc, alive=$alive): $(echo "$out" | tail -3)"; fi
squats=()
for port in 19101 19102 19103; do
  python3 -c 'import socket,sys,time; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(5); time.sleep(120)' "$port" &
  squats+=("$!")
done
sleep 1
aok "ART other servers listening on the old fixed ports 19101-19103 do not change the verdict" -- "${ART[@]}"
for sq in "${squats[@]}"; do kill "$sq" 2> /dev/null || true; wait "$sq" 2> /dev/null || true; done
if [ "$(grep -c '^docker run -d' "$work/log" 2> /dev/null || echo 0)" = 0 ]; then :; fi
arun -- "${ART[@]}"; if grep -Fq 'FSCACHE_USERNAME' "$work/log" && ls "$work"/fakedir/srv-* > /dev/null 2>&1; then bad "ART containers were left running"; else ok "ART the containers are removed at the end and the -fips image is started with credentials"; fi
plant_stray "$fa/images/production"; plant_stray "$fa/images/fips"
aok "AC33 artifacts: a layout holding a stray manifest.json, a fake.tar and an unreferenced blob still passes" -- "${ART[@]}"
for v in production fips; do
  if members_only "$work/fakedir/members-$v" "$fa/images/$v"; then ok "AC33 check-artifacts loads the $v layout from its named members only"; else bad "AC33 check-artifacts handed docker load [$MO_WHY]: $(tr '\n' ' ' < "$work/fakedir/members-$v" 2> /dev/null | cut -c1-200)"; fi
done
unplant_stray "$fa/images/production"; unplant_stray "$fa/images/fips"
mkarch "$fa/dist"; rm "$fa/dist/fscache-fips_0.3.0_linux_amd64.tar.gz"
afail "PLAT-001-AC1 a missing amd64 archive fails naming it" fscache-fips -- "${ART[@]}"
mkarch "$fa/dist"; printf '#!/usr/bin/env bash\nexit 1\n' > "$fa/real/fscache-fips.bad"; mkdir -p "$fa/bad"; cp "$fa/real/fscache-fips.bad" "$fa/bad/fscache-fips"; chmod +x "$fa/bad/fscache-fips"
tar -czf "$fa/dist/fscache-fips_0.3.0_linux_amd64.tar.gz" -C "$fa/bad" fscache-fips; mkdig "$fa"
afail "PLAT-001-AC1 a binary that exits at once does not execute: fails naming healthz" healthz -- "${ART[@]}"
# a server that dies before it answers is noticed at once and its own last words are in the failure
# (before: a silent 10 s wait)
printf '#!/usr/bin/env bash\necho "fscache: boom cannot bind" >&2\nexit 1\n' > "$fa/bad/fscache-fips"
chmod +x "$fa/bad/fscache-fips"
tar -czf "$fa/dist/fscache-fips_0.3.0_linux_amd64.tar.gz" -C "$fa/bad" fscache-fips; mkdig "$fa"
t0=$(date +%s); arun -- "${ART[@]}"; took=$(( $(date +%s) - t0 ))
if [ "$rc" = 1 ] && grep -Fq healthz <<< "$out" && grep -Fq "boom cannot bind" <<< "$out" && [ "$took" -le 5 ]; then
  ok "PLAT-001-AC1 a server that dies before it answers fails within 5 s, naming healthz, with its own last log line"
else
  bad "PLAT-001-AC1 a dead server: rc=$rc after ${took}s: ${out:0:200}"
fi
mkarch "$fa/dist"
# the check never guesses a port: each of its three servers is told to listen on port 0 of the loopback and reports
# the port it got; servers_given lists the addresses the check gave its servers
servers_given() { cat "$work"/fakedir/addr-* 2> /dev/null | sort | uniq -c | tr -s ' ' | tr '\n' ';'; }
arun -- "${ART[@]}"
addrs=$(servers_given)
if [ "$rc" = 0 ] && [ "$addrs" = " 3 127.0.0.1:0;" ]; then
  ok "PLAT-001-AC1 the check starts its three servers on 127.0.0.1:0 and reads the bound port from their log"
else
  bad "PLAT-001-AC1 the servers were given [$addrs] (rc=$rc): ${out:0:160}"
fi
# REQ-CHAIN-006-AC17 (advisor 0385): the same checks for the linux/arm64 binaries and images, run by the check-arm64 job on an arm64 runner
mkarch "$fa/dist"
aok "AC17 --arch arm64: the arm64 binaries execute, the postures are truthful, the images have no shell and serve: exit 0" -- "${ART[@]}" --arch arm64
if grep -Fq -- '--platform linux/arm64' "$work/log" && [ -f "$fa/out/artifacts-result-arm64.json" ] && jq -e '.arch == "arm64" and .production.digest and .fips.digest' "$fa/out/artifacts-result-arm64.json" > /dev/null 2>&1; then ok "AC17 the arm64 images run with --platform linux/arm64 and the result names the arch and the same candidate digests"; else bad "AC17 arm64 run: no --platform linux/arm64, or artifacts-result-arm64.json incomplete"; fi
# the arm64 run above: the same start code, the same port 0 (a second flake died waiting on the arm64 -fips server)
addrs=$(servers_given)
if [ "$addrs" = " 3 127.0.0.1:0;" ]; then
  ok "AC17 the arm64 run also starts its three servers on 127.0.0.1:0"
else
  bad "AC17 the arm64 servers were given [$addrs]"
fi
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
# needs a registry"). A command runs only when every operand is a local file or a placeholder Check fills with a local
# value (<TAG>).
# A LISTED command is Release's: it carries exactly one key flag whose value is <RELEASE_KEY> (a runnable one names a
# local key file, fx.pub). `$` is refused anywhere but inside single quotes ("$TAG", "${TAG}", "$(x)"). The registry
# text below is in the GUIDE
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
printf 'abc  cache_linux_amd64.tar.gz\n' > "$fx/checksums.txt";
printf '{}\n' > "$fx/checksums.txt.bundle";
printf 'key\n' > "$fx/fx.pub"
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
- `<RELEASE_KEY>`: the release public key file
'
g() { printf '%s\n' "$DEFS" "$1" > "$fx/guide.md"; rm -f "$fx/guide.cannot-run.json"; }
lst() { python3 -c 'import json,sys; json.dump([{"command": c, "reason": "needs the candidate image in a registry; Check holds it as a file"} for c in sys.argv[1:]], open(sys.argv[0] if False else "'"$fx"'/guide.cannot-run.json","w"))' "$@"; }
ISS=https://token.actions.githubusercontent.com
L1="cosign verify-blob --key fx.pub --type slsa-<TAG> --bundle checksums.txt.bundle checksums.txt"
L2="jq -n '\"<TAG>\"'"
R1="cosign verify <IMAGE_REF> --key <RELEASE_KEY> | jq -e '.[0].critical.image'"
R2="cosign verify-attestation --type slsaprovenance1 --key <RELEASE_KEY> oci://<IMAGE_REF>"
R3="cosign verify-attestation --type slsaprovenance1 --key <RELEASE_KEY> <IMAGE_REF>"
RF="cosign verify <IMAGE_REF_FIPS> --key <RELEASE_KEY>"
RL="cosign verify ghcr.io/fosterstack/cache:<TAG>-fips --key <RELEASE_KEY>"
D64=$(printf 'a%.0s' $(seq 64))
RO="cosign verify-attestation --type slsaprovenance1 --key <RELEASE_KEY> oci://ghcr.io/fosterstack/cache@sha256:$D64"
# the same command with a local key file: what Check could run if it were not a registry command
U() { printf '%s' "${1//<RELEASE_KEY>/fx.pub}"; }
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
if grep -Fq "cosign verify-blob --key fx.pub --type slsa-v0.3.0" "$work/log" && ! grep -q '<[A-Z_]*>' "$work/log";
then ok "AC7 <TAG> is substituted in a runnable verify command (no placeholder left)";
else bad "AC7 substitution: $(tr '\n' ' ' < "$work/log" | cut -c1-200)";
fi
g "$(blk "$R1" "$R2" "$R3" "$RF" "$RL" "$RO")"; lst "$R1" "$R2" "$R3" "$RF" "$RL" "$RO"; rm -f "$fx/out/guide-results.json"
gwant_ok "AC7 registry commands listed exactly in the cannot-run list are not run and do not fail the check (exit 0; covered by Release's post-publish verification)"
if [ -f "$fx/out/guide-results.json" ] && jq -e '(.commands | length) == 6 and all(.commands[]; .outcome == "not-run" and (.reason | length > 0))' "$fx/out/guide-results.json" > /dev/null 2>&1 && ! grep -Eq '^(cosign|gh) ' "$work/log"; then ok "AC7 each listed registry command is recorded as not-run with its reason and never run"; else bad "AC7 listed registry commands: $(tr '\n' ' ' < "$work/log" | cut -c1-160)"; fi
if [ "$(grep -c 'NOT RUN' <<< "$out")" = 6 ] && [ "$(grep -c 'run right after publishing' <<< "$out")" = 6 ]; then ok "AC7 each not-run line says the command is run right after publishing (Release's post-publish verification), not skipped"; else bad "AC7 not-run lines name the post-publish step: ${out:0:300}"; fi
for c in "$R1" "$R2" "$R3";
do g "$(blk "$(U "$c")")";
gwant_fail "AC7 an unlisted verify command on <IMAGE_REF> fails closed: ${c:0:40}" "unlisted command needs a registry";
done
g "$(blk "$(U "$RF")")";
gwant_fail "AC7 an unlisted -fips verify command on <IMAGE_REF_FIPS> fails closed" "unlisted command needs a registry"
g "$(blk "$(U "$RL")")";
gwant_fail "AC7 an unlisted -fips verify command on a literal registry reference (host/path:tag) fails closed" \
  "unlisted command needs a registry"
g "$(blk "$(U "$RO")")";
gwant_fail "AC7 an unlisted verify command on an oci:// target fails closed" "unlisted command needs a registry"
g "$(blk "$RL")"; lst "$RL"; gwant_ok "AC7 the literal -fips registry command, listed, is not run (exit 0)"
# round 1 F8 (Codex B6): the syntax and the placeholders are judged BEFORE the cannot-run list excuses a command (a listed command is run unattended by
# Release after publishing, so an excused `$(...)`, `;` or unsupported placeholder would be run there)
X1="cosign verify <IMAGE_REF> --key <RELEASE_KEY> --type \"\$(id)\""
X2="cosign verify <IMAGE_REF> --key <RELEASE_KEY> --type \$IDENT"
X3="cosign verify <IMAGE_REF> --key <RELEASE_KEY>; jq -n 1"
X4="cosign verify <IMAGE_REF> --key <RELEASE_KEY> --type \`id\`"
for c in "$X1" "$X2" "$X3" "$X4"; do g "$(blk "$c")"; lst "$c"; gwant_fail "AC7 F8 a listed command with shell syntax is refused, not excused: ${c:0:70}" "shell syntax"; done
printf '%s\n' "$DEFS" '- `<RELEASE_URL>`: the release page' "${FENCE}sh" \
  "cosign verify <IMAGE_REF> --key <RELEASE_KEY> --type <RELEASE_URL>" "$FENCE" > "$fx/guide.md"
lst "cosign verify <IMAGE_REF> --key <RELEASE_KEY> --type <RELEASE_URL>"
gwant_fail "AC7 F8 a listed command with a placeholder Check and Release cannot substitute is refused, not excused" "unsupported placeholder"
# F13 (customer guide in the key form): the planner reads the REAL page, and <RELEASE_KEY> is allowed only in a listed
# command
rp=$(mktemp -d "$work/realpage.XXXXXX"); rc=0
python3 -I "$root/bin/check-guide-plan.py" "$root/docs/verify-release.md" "$root/docs/verify-release.cannot-run.json" \
  "$REPO@sha256:$(printf 'a%.0s' $(seq 64))" "$rp/plan.json" "$REPO-fips@sha256:$(printf 'b%.0s' $(seq 64))" > \
    "$rp/out" 2>&1 || rc=$?
if [ "$rc" = 0 ];
then ok "AC7 F13 the planner plans the real docs/verify-release.md with its real cannot-run list (rc 0)"
else bad "AC7 F13 the planner refuses the real page -> rc=$rc: $(head -c 200 "$rp/out")"; fi
KR="cosign verify-blob --key <RELEASE_KEY> --bundle checksums.txt.bundle checksums.txt"
printf '%s\n' "$DEFS" "$(blk "$KR")" > "$fx/guide.md"; rm -f "$fx/guide.cannot-run.json"
gwant_fail \
  "AC7 F13 <RELEASE_KEY> in a command not on the cannot-run list is refused: Check never holds the verified key" \
  "RELEASE_KEY"
printf '%s\n' "$DEFS" "$(blk "$KR")" > "$fx/guide.md"; lst "$KR"
gwant_ok "AC7 F13 <RELEASE_KEY> in a command on the cannot-run list is planned as not-run (Release fills it)"
# round 1 (F1, F2, F4): a LISTED command is Release's, so it carries exactly one key flag whose value is <RELEASE_KEY>;
# no command skips or
# redirects the public log; gh attestation verify is not a verify form. Each refusal names its own reason.
CB="--bundle checksums.txt.bundle checksums.txt"
kfail() {
  local l=$1 c=$2 w=$3; g "$(blk "$c")"; lst "$c"; gwant_fail "AC7 F1 a listed command with $l is refused" "$w"
}
kfail "a key file by name" "cosign verify-blob --key fx.pub $CB" "its key flag names"
kfail "a KMS reference" "cosign verify-blob --key awskms:///alias/x $CB" "its key flag names"
kfail "a URL in --key=" "cosign verify-blob --key=https://example.org/k.pub $CB" "its key flag names"
kfail "a second key flag beside the placeholder" "cosign verify-blob --key <RELEASE_KEY> --key fx.pub $CB" \
  "exactly one key flag"
kfail "no key flag" "cosign verify-blob $CB" "exactly one key flag"
kfail "an identity instead of a key" \
  "cosign verify-blob --certificate-identity x --certificate-oidc-issuer $ISS $CB" "exactly one key flag"
kfail "no key flag in the second segment of a pipe" \
  "cosign verify-blob --key <RELEASE_KEY> $CB | cosign verify-blob $CB" "exactly one key flag"
for fl in "--insecure-ignore-tlog" "--insecure-ignore-tlog=true" "--insecure-ignore-tlo''g" \
  "--private-infrastructure" "--private-infrastructure=true";
do
  c="cosign verify-blob --key <RELEASE_KEY> $CB $fl"
  g "$(blk "$c")"; lst "$c"; gwant_fail "AC7 F4 a listed command with $fl is refused" "skips the public log"
  g "$(blk "$(U "$c")")"; gwant_fail "AC7 F4 an unlisted command with $fl is refused too" "skips the public log"
done
GHV="gh attestation verify oci://<IMAGE_REF> --owner fosterstack"
g "$(blk "$GHV")";
lst "$GHV";
gwant_fail "AC7 F2 a listed gh attestation verify is refused: no verify form (it verifies by identity)" \
  "not a verify form"
g "$(blk "$GHV")"; gwant_fail "AC7 F2 an unlisted gh attestation verify is refused: it is no verify form" "verify forms"
g "$(blk "cosign verify-blob --key fx.pub --type fail-me --bundle checksums.txt.bundle checksums.txt")"
gwant_fail "AC7 a runnable command that exits non-zero fails the script naming it" "fail-me"
g "$(blk "cosign verify-blob --key fx.pub --bundle checksums.txt.bundle cache_0.3.0_linux_amd64.tar.gz")"
gwant_fail "AC7 a command on a file that is not local to Check is not runnable and fails unless listed" "not runnable"
# PR 3 fix7 (found by running the planner read-only on cache's draft docs/verify-release.md):
# (1) the verify-form judgement of a LISTED command splits on `|` outside single and double quotes only (a pipe inside a quoted jq filter is jq's);
#     every F8 check still holds, and a chain to anything that is not a verify form or jq is still refused.
JQF="jq -e --arg ref <IMAGE_REF> '.payload | @base64d | fromjson | .subject[0].digest.sha256 == \$ref'"
Q1="cosign verify-attestation --type slsaprovenance1 --key <RELEASE_KEY> <IMAGE_REF> | $JQF"
g "$(blk "$Q1")"; lst "$Q1"
gwant_ok "AC7 fix7 a listed verify command piped to a jq filter that itself holds pipes inside single quotes is one verify form (not refused as 'not a verify form')"
if jq -e '(.commands | length) == 1 and .commands[0].outcome == "not-run"' "$fx/out/guide-results.json" > /dev/null 2>&1; then ok "AC7 fix7 the quoted-pipe jq command is recorded as not-run"; else bad "AC7 fix7 quoted-pipe results"; fi
g "$(blk "$(U "$Q1")")";
gwant_fail "AC7 fix7 the same command unlisted still fails closed (it needs a registry)" \
  "unlisted command needs a registry"
g "$(blk "jq -n '\"a\" | length'")"; gwant_ok "AC7 fix7 a runnable jq whose filter holds a quoted pipe runs"
QD="cosign verify <IMAGE_REF> --key <RELEASE_KEY> | jq -e \".[0] | .critical\""
g "$(blk "$QD")"; lst "$QD"; gwant_ok "AC7 fix7 a pipe inside double quotes (no expansion) is jq's too"
CHAIN_TO_DL="jq -n '.a | .b' | jq -n '.c' | curl http://example.com/x"
for c in "cosign verify <IMAGE_REF> --key <RELEASE_KEY> | sh" \
         "jq -n '.a | .b' | rm -rf x" \
         "$CHAIN_TO_DL" \
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
BA="cosign verify-blob-attestation --type slsaprovenance1"
FX2=0
for f in "--bundle X" "--bundle=X" "--certificate X" "--certificate=X" "--cert X" "--cert=X" "--signature X" "--signature=X" "--sig X" "--sig=X" \
         "--key X" "--key=X" "--certificate-chain X" "--certificate-chain=X" "--rekor-url X" "--rekor-url=X"; do
  case "$f" in --key*) kf="";; *) kf=" --key <RELEASE_KEY>";; esac
  c="$BA$kf ${f//X/provenance.intoto.jsonl.bundle}"
  g "$(blk "$(U "$c")")";
  gwant_fail \
    "AC7 fix7 a file-valued flag whose file is not local to Check makes the command not runnable (unlisted): ${f%% *}" \
    "not runnable"
  # a listed command's key flag is <RELEASE_KEY>, so the key value cannot be this file
  case "$f" in --key*) continue;; esac
  g "$(blk "$c")"; lst "$c"; gwant_ok "AC7 fix7 the same command listed with its reason is not run and is recorded as not-run (exit 0): $f"
  if ! grep -q '^cosign' "$work/log"; then ok "AC7 fix7 the listed flag-value command was not run: $f"; else bad "AC7 fix7 the listed flag-value command ran: $f"; fi
done
c="$BA --key fx.pub --bundle=https://example.com/provenance.bundle checksums.txt"
g "$(blk "$c")"; gwant_ok "AC7 fix7 a URL value of --bundle is not a file operand: the command (local blob) runs"
c="$BA --key fx.pub --bundle checksums.txt.bundle checksums.txt"
g "$(blk "$c")"; gwant_ok "AC7 fix7 a --bundle value that is a local file runs"
c="$BA --key <RELEASE_KEY> --bundle provenance.intoto.jsonl.bundle"
g "$(blk "$c")"; printf '[{"command": "%s ", "reason": "run after publishing"}]\n' "$c" > "$fx/guide.cannot-run.json"
gwant_fail "AC7 fix7 a flag-value command listed with text that does not match exactly is refused" "not in the guide"
g "$(blk "$c")"; printf '[{"command": "%s", "reason": " "}]\n' "$c" > "$fx/guide.cannot-run.json"
gwant_fail "AC7 fix7 a flag-value command listed without a reason is refused" "cannot-run entry"
g "$(blk "$(U "$c")")"; rm -f "$fx/guide.cannot-run.json"
gwant_fail "AC7 fix7 a flag-value command neither runnable nor listed is refused" "not runnable"
g "$(blk "jq -n \"\$TAG\"")"; gwant_fail "AC7 \$ inside double quotes (\"\$TAG\") is refused" "shell syntax"
g "$(blk "jq -n \"\${TAG}\"")"; gwant_fail "AC7 \${...} inside double quotes is refused" "shell syntax"
g "$(blk "jq -n \"\$(id)\"")"; gwant_fail "AC7 a command substitution inside double quotes is refused" "shell syntax"
g "$(blk "jq -n '\"\$x\"'")"; gwant_ok "AC7 a \$ inside single quotes is text and runs"
g "Nothing to run here."
gwant_fail "AC7 a guide with no command fails (a vacuous pass is not a pass)" "command"
g "$(for i in $(seq 11); do blk "jq -n 1"; done)"
gwant_fail "AC7 a guide with more than ten commands fails" "ten"
BLK_DL="curl -sSf https://example.com/x"
g "$(blk "$BLK_DL")"
FXD_2="curl"
gwant_fail "AC7 a tool other than cosign, gh and jq fails naming it" "$FXD_2"
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
for c in "cosign verify <IMAGE_REF> --key <RELEASE_KEY> --type \\'x\${HOME}y\\'" "jq -n \\'\$TAG\\'"; do
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
# ---- REQ-SUP-001-AC30: acceptance-serve.sh starts only a content-addressed image; check-acceptance.sh hands it the loaded image's ID ----------
srv="$work/srv"; mkdir -p "$srv/bin" "$srv/fakedir"; cp "$root/bin/acceptance-serve.sh" "$srv/bin/"; printf '#!/bin/sh\nexit 0\n' > "$srv/bin/loopback-get.sh"
H64=$(printf '%064d' 7); UP64=$(printf 'A%.0s' $(seq 1 64))
serve() { # serve REF -> rc, out; the fake docker logs what ran
  : > "$work/log"; rc=0; out=$(cd "$srv" && PATH="$fake:$PATH" FAKE_LOG="$work/log" FAKE_DIR="$srv/fakedir" IMAGE_REF="$1" bash bin/acceptance-serve.sh gradle main 2>&1) || rc=$?
}
for ref in "fscache:production" "localhost/fa-production:latest" "sha256:${H64:0:63}" "SHA256:$H64" "sha256:$H64 extra" "name@sha256:${H64:0:63}" "-v/x:/y@sha256:$H64" "/@sha256:$H64" "a..b/x@sha256:$H64" "ghcr.io/o/R@sha256:$H64" "ghcr.io/o/r:t:u@sha256:$H64" "sha256:$UP64" "ghcr.io/o/r@sha256:$UP64" "$(printf 'sha256:%s\nfscache:production' "$H64")"; do
  serve "$ref"
  if [ "$rc" = 2 ] && ! grep -q '^docker tag' "$work/log" && ! grep -q '^docker run' "$work/log" && grep -Fq 'content-addressed' <<< "$out" && grep -Fq 'got: ' <<< "$out"; then ok "AC30 serve refuses '${ref//$'\n'/\\n}' before docker tag or run (exit 2, message names the rule and the ref)"; else bad "AC30 serve took '${ref//$'\n'/\\n}' (rc=$rc): $(head -2 "$work/log" | tr '\n' '|')"; fi
done
for ref in "sha256:$H64" "localhost/fa-production@sha256:$H64" "ghcr.io/fosterstack/cache:v0.3.0@sha256:$H64" "localhost:5000/team/app-x@sha256:$H64"; do
  serve "$ref"
  if [ "$rc" = 0 ] && grep -Eq "^docker tag sha256:$H64 localhost/fscache-serve-candidate( |$)" "$work/log" && grep -Eq '^docker run .* localhost/fscache-serve-candidate( |$)' "$work/log" && ! awk -v r="$ref" 'index($0, "docker run ") == 1 && index($0, r) { found = 1 } END { exit !found }' "$work/log"; then ok "AC30 serve starts the content-addressed image $ref: its inspected ID is tagged to the fixed local name and that name is run"; else bad "AC30 serve did not start $ref (rc=$rc): $(head -3 "$work/log" | tr '\n' '|') $out"; fi
done
# a re-tag between the tag and the run: the fixed local name must still resolve to the inspected ID right before docker run, or serve refuses and starts nothing
mkdir -p "$srv/fakedir"; : > "$srv/fakedir/retag"
serve "sha256:$H64"; rm -f "$srv/fakedir/retag"
if [ "$rc" != 0 ] && ! grep -q '^docker run' "$work/log" && grep -Fq 'fscache-serve-candidate' <<< "$out"; then ok "AC30 serve refuses to start when the local name no longer resolves to the inspected image ID (no docker run)"; else bad "AC30 a re-tagged local name was run (rc=$rc): $(head -4 "$work/log" | tr '\n' '|') $out"; fi
# a caller's nocasematch does not turn uppercase hex into valid hex
: > "$work/log"; rc=0; out=$(cd "$srv" && PATH="$fake:$PATH" FAKE_LOG="$work/log" FAKE_DIR="$srv/fakedir" IMAGE_REF="sha256:$UP64" bash -O nocasematch bin/acceptance-serve.sh gradle main 2>&1) || rc=$?
if [ "$rc" = 2 ] && ! grep -q '^docker run' "$work/log"; then ok "AC30 serve refuses uppercase hex even when the caller sets nocasematch"; else bad "AC30 nocasematch let uppercase hex through (rc=$rc)"; fi
# the wrapper: a tag named by `docker load` is turned into its image ID before serve sees it
for sc in acceptance-serve acceptance-gradle acceptance-gradle-capped; do
  case "$sc" in
    acceptance-serve) printf '#!/usr/bin/env bash\n[ -z "${IMAGE_REF:-}" ] || printf "%%s\\n" "$IMAGE_REF" >> "$FAKE_DIR/serve-refs"\n' > "$fx/bin/$sc.sh";;
    acceptance-gradle) printf '#!/usr/bin/env bash\nexit 0\n' > "$fx/bin/$sc.sh";;   # only the capped script writes the suite's results line
    *) printf '#!/usr/bin/env bash\necho "results=[{\\"ac\\":\\"AC30\\",\\"result\\":\\"pass\\"}]" >> "${GITHUB_OUTPUT:-/dev/null}"\n' > "$fx/bin/$sc.sh";;
  esac
done
mkdir -p "$work/fakedir"; rm -f "$work/fakedir/serve-refs"; run check-acceptance.sh gradle --digests digests.json --images images --out out
if [ "$rc" = 0 ]; then ok "AC30 check-acceptance finishes (rc=0) with the serve stub and valid results lines"; else bad "AC30 check-acceptance rc=$rc: ${out:0:200}"; fi
if [ -s "$work/fakedir/serve-refs" ] && [ "$(sort -u "$work/fakedir/serve-refs")" = "sha256:$H64" ]; then ok "AC30 check-acceptance passes serve the inspected image ID, never the tag docker load printed"; else bad "AC30 serve got: $(sort -u "$work/fakedir/serve-refs" 2> /dev/null | tr '\n' '|') (rc=$rc) $out"; fi
if grep -Fq 'docker image inspect --format {{.Id}} fscache:production' "$work/log"; then ok "AC30 the ID comes from docker image inspect of the very name docker load printed (fscache:production)"; else bad "AC30 no docker image inspect --format ran: $(grep -c '^docker' "$work/log") docker calls"; fi
rm -f "$fx/bin/acceptance-serve.sh" "$fx/bin/acceptance-gradle.sh" "$fx/bin/acceptance-gradle-capped.sh"
# the same for check-acceptance.sh (its suite scripts are stubs here: what is under test is what docker load is given)
for sc in acceptance-serve acceptance-gradle; do printf '#!/usr/bin/env bash\nexit 0\n' > "$fx/bin/$sc.sh"; done
printf '#!/usr/bin/env bash\necho "results=[{\\"ac\\":\\"AC33\\",\\"result\\":\\"pass\\"}]" >> "${GITHUB_OUTPUT:-/dev/null}"\n' > "$fx/bin/acceptance-gradle-capped.sh"
plant_stray "$fx/images/production"; rm -rf "$work/fakedir"; mkdir -p "$work/fakedir"
run check-acceptance.sh gradle --digests digests.json --images images --out out
if [ "$rc" = 0 ] && members_only "$work/fakedir/members-production" "$fx/images/production"; then ok "AC33 check-acceptance loads the production layout from its named members only (a stray manifest.json, fake.tar and unreferenced blob stay out)"; else bad "AC33 check-acceptance rc=$rc handed docker load [$MO_WHY]: $(tr '\n' ' ' < "$work/fakedir/members-production" 2> /dev/null | cut -c1-200) $out"; fi
unplant_stray "$fx/images/production"; rm -f "$fx/bin/acceptance-serve.sh" "$fx/bin/acceptance-gradle.sh" "$fx/bin/acceptance-gradle-capped.sh"
# ---- REQ-CHAIN-006-AC11 (rule 68, amended): the helper bin/witnessed-local.sh (Check's four steps hold no identity token; REQ-REL-011-AC1) and its 9-minute cap -------------------------------------------
hw="$work/hw"; mkdir -p "$hw/bin" "$hw/fakebin" "$hw/tmp"
cp "$root/bin/witnessed-local.sh" "$hw/bin/" 2> /dev/null || true
printf '#!/usr/bin/env bash\necho "step $*" >> "$HW_LOG"\n[ -z "${STEP_FAIL:-}" ] || exit 1\n' > "$hw/bin/step.sh"
FXD_1="$hw/fakebin/curl"
cat > "$FXD_1" <<'EOF'
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
for i in "${!a[@]}"; do [ "${a[$i]}" = --signer-file-key-path ] && { [ -s "${a[$((i + 1))]}" ] || exit 9; }; done
echo "tokenvars=[${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}${ACTIONS_ID_TOKEN_REQUEST_URL:-}${ACTIONS_RUNTIME_TOKEN:-}${ACTIONS_RUNTIME_URL:-}${SIGSTORE_ID_TOKEN:-}]" >> "$HW_ARGV"
"${cmd[@]}" || exit $?
printf '{"fake":"record"}' > "$out"
EOF
cat > "$hw/fakebin/openssl" <<'EOF'
#!/usr/bin/env bash
# openssl genpkey -algorithm ed25519 -out FILE (the local ed25519 build of the test host may lack ed25519): write a key-shaped file
[ "$1 $2 $3 $4" = "genpkey -algorithm ed25519 -out" ] && [ $# = 5 ] || { echo "fake openssl: unexpected arguments: $*" >&2; exit 64; }
printf 'fake-key' > "$5"
EOF
chmod +x "$hw/fakebin/"*
hrun() { # hrun [VAR=val...] -- STEP SCRIPT ARGS...  (runs in the helper tree, fakes first on PATH)
  local env=(); while [ "$1" != -- ]; do env+=("$1"); shift; done; shift; rc=0
  out=$( (cd "$hw" && env "${env[@]}" PATH="$hw/fakebin:$PATH" HW_LOG="$work/hwlog" HW_ARGV="$work/hwargv" RUNNER_TEMP="$hw/tmp" \
          ACTIONS_ID_TOKEN_REQUEST_TOKEN=t ACTIONS_ID_TOKEN_REQUEST_URL="https://x/?a=b" ACTIONS_RUNTIME_TOKEN=rt ACTIONS_RUNTIME_URL="https://x/rt" SIGSTORE_ID_TOKEN=st bash bin/witnessed-local.sh "$@") 2>&1) || rc=$?
}
reset_h() { rm -rf "$hw"/witness-*; : > "$work/hwlog"; : > "$work/hwargv"; }
reset_h; hrun X=1 -- scanners bin/step.sh scanners
h_ok=0; [ "$rc" = 0 ] && [ -f "$hw/witness-scanners/scanners-collection.local.json" ] && h_ok=1
if [ "$rc" = 0 ] && [ -f "$hw/witness-scanners/scanners-collection.local.json" ] && grep -q '^step scanners' "$work/hwlog"; then ok "AC11 the helper runs the script with its arguments under Witness and writes witness-scanners/scanners-collection.local.json (PR 2's naming)"; else bad "AC11 helper normal run -> rc=$rc ${out:0:140}"; fi
if [ "$(grep -c '^timeout ' "$work/hwlog")" = 1 ] && grep -qx 'timeout -k 20 540' "$work/hwlog"; then ok "AC11 the wrapped command is run through exactly one timeout of 540 seconds (9 minutes) with a kill-after of 20 seconds"; else bad "AC11 the helper must run the command through exactly one 'timeout -k 20 540': $(tr '\n' ' ' < "$work/hwlog")"; fi
if grep -q -- '--step scanners' "$work/hwargv" && grep -q -- '-o witness-scanners/scanners-collection.local.json' "$work/hwargv" && grep -q -- '--signer-file-key-path' "$work/hwargv" \
   && grep -q -- '--env-filter-sensitive-vars' "$work/hwargv" && ! grep -Eq -- '-a [a-z,-]*(github|slsa)' "$work/hwargv" && ! grep -q -- 'fulcio' "$work/hwargv"; then ok "AC9 the helper gives Witness the step name, the local record path, the throwaway key and the environment filter, and never the github or slsa attestor or a Fulcio signer"; else bad "AC9 witness argv: $(cat "$work/hwargv" | cut -c1-200)"; fi
if [ "$h_ok" = 1 ] && grep -qx 'tokenvars=\[\]' "$work/hwargv"; then ok "AC9 the identity-token request variables never reach Witness (the helper unsets them; Check holds no token)"; else bad "AC9 an identity-token variable reached Witness: $(grep tokenvars "$work/hwargv")"; fi
reset_h; hrun FAKE_OUTLIVE=1 -- scanners bin/step.sh scanners
if [ "$h_ok" = 1 ] && [ "$rc" != 0 ] && [ ! -e "$hw/witness-scanners/scanners-collection.local.json" ]; then ok "AC11 a command that outlives the cap makes the helper fail (exit $rc) and leaves no record"; else bad "AC11 an overrun must fail with no record: rc=$rc"; fi
reset_h; hrun STEP_FAIL=1 -- acceptance bin/step.sh acceptance
if [ "$h_ok" = 1 ] && [ "$rc" != 0 ] && [ ! -e "$hw/witness-acceptance/acceptance-collection.local.json" ]; then ok "AC11 a failing script makes the helper fail and leaves no record"; else bad "AC11 a failing script must fail with no record: rc=$rc"; fi
reset_h; hrun X=1 -- '../x' bin/step.sh a
if [ "$h_ok" = 1 ] && [ "$rc" = 2 ] && [ ! -s "$work/hwlog" ]; then ok "AC11 a step name that is not a plain lower-case word is refused (exit 2) before anything runs"; else bad "AC11 bad step name -> rc=$rc, log: $(cat "$work/hwlog")"; fi
reset_h; hrun X=1 -- extra bin/step.sh extra
if [ "$h_ok" = 1 ] && [ "$rc" = 2 ] && [ ! -s "$work/hwlog" ] && [ ! -s "$work/hwargv" ]; then ok "AC11 a fourth step outside the closed list (extra) is refused (exit 2) before anything runs"; else bad "AC11 unknown step extra -> rc=$rc"; fi
reset_h; for s in scanners acceptance runtime; do hrun X=1 -- "$s" bin/step.sh "$s"; done
got=$(cd "$hw" && find . -path './witness-*' -type f | sed 's|^\./||' | sort | tr '\n' ' ')
if [ "$got" = "witness-acceptance/acceptance-collection.local.json witness-runtime/runtime-collection.local.json witness-scanners/scanners-collection.local.json " ]; then ok "AC12 the three steps are accepted and leave exactly three records, one per step (the next stage verifies the list)"; else bad "AC12 the records: $got"; fi
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
# the shipped main package is read from the recipes the build compiles from (build/melange.yaml and build/melange-fips.yaml: exactly one `go build`, CGO_ENABLED set), never from `go list`
mkdir -p "$gvt/build"
gv_recipe() { # gv_recipe NAME PACKAGE FILE [CGO]: a copy of the real recipe of that file's kind (the grammar pins the template's other lines), with the package and CGO_ENABLED set
  local src="$root/build/melange.yaml"; case "$3" in *-fips.yaml) src="$root/build/melange-fips.yaml" ;; esac
  sed -e "s#fscache \./cmd/fscache\$#fscache $2#" -e "s#^    CGO_ENABLED: .*#    CGO_ENABLED: \"${4:-0}\"#" "$src" > "$3"; }
gv_recipes() { gv_recipe fscache ./cmd/fscache "$gvt/build/melange.yaml" "${1:-0}"; gv_recipe fscache-fips ./cmd/fscache "$gvt/build/melange-fips.yaml" "${1:-0}"; }
gv_recipes
cat > "$gvt/fake/govulncheck" <<'EOF'
#!/usr/bin/env bash
# the scan runs with an explicit environment (the caller's variables do not reach it), so the case settings come from a file next to this fake
[ ! -f "$(dirname "$0")/env" ] || . "$(dirname "$0")/env"
echo "govulncheck $*" >> "$GV_LOG"
echo "env GOFLAGS=${GOFLAGS:-} GOTOOLCHAIN=${GOTOOLCHAIN:-} GOPROXY=${GOPROXY:-} PATH1=${PATH%%:*}" >> "$GV_LOG"
echo "pkgdriver GOPACKAGESDRIVER=${GOPACKAGESDRIVER-unset}" >> "$GV_LOG"
echo "goenv GOOS=${GOOS-unset} GOARCH=${GOARCH-unset} CGO_ENABLED=${CGO_ENABLED-unset} GOAMD64=${GOAMD64-unset} GOPATH=${GOPATH-unset} GOCACHE=${GOCACHE-unset} GOMODCACHE=${GOMODCACHE-unset} GOENV=${GOENV-unset} GOFIPS140=${GOFIPS140-unset}" >> "$GV_LOG"
case "$1" in -version) printf 'Go: go1.27.2\nScanner: govulncheck@v1.7.0\nDB: https://vuln.go.dev\nDB updated: 2026-10-10 00:00:00 +0000 UTC\n'; exit 0 ;; esac
[ "${GV_RC:-0}" = 0 ] || { echo "govulncheck: boom" >&2; exit "$GV_RC"; }
# one fake, three questions: which platform (GOARCH), which target (the last argument), which case. GV_OUT_ARM64 overrides GV_OUT on the arm64 runs, GV_OUT_EXPLICIT on the runs of an explicit package path.
gv_case="${GV_OUT:-clean}"
[ "${GOARCH:-}" != arm64 ] || gv_case="${GV_OUT_ARM64:-$gv_case}"
case "${@: -1}" in ./...) ;; *) gv_case="${GV_OUT_EXPLICIT:-$gv_case}" ;; esac
case "$gv_case" in
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
cat > "$gvt/fake/go" <<'EOF'
#!/usr/bin/env bash
[ ! -f "$(dirname "$0")/env" ] || . "$(dirname "$0")/env"
echo "go $*" >> "$GV_LOG"
[ "${GV_GO_RC:-0}" = 0 ] || exit "$GV_GO_RC"
if [ "$1 $2 $3" = "mod edit -json" ]; then
  if [ -n "${GV_GO_JSON:-}" ]; then cat "$GV_GO_JSON"; exit 0; fi
  if [ -n "${GV_IGNORE:-}" ]; then printf '{"Module":{"Path":"example.com/a"},"Go":"1.27","Ignore":[{"Path":"%s"}]}\n' "$GV_IGNORE"; else printf '{"Module":{"Path":"example.com/a"},"Go":"1.27"}\n'; fi
  exit 0
fi
exit 3
EOF
chmod +x "$gvt/fake/go"
gvrun() { # gvrun [ENV=V ...] -- ARGS... : runs the script in the throw-away tree with the fake first on PATH
  local envs=(); while [ "$1" != -- ]; do envs+=("$1"); shift; done; shift
  rc=0; : > "$work/gvlog"; rm -rf "$gvt/out"
  { printf 'export GV_LOG=%q\n' "$work/gvlog"; local e; for e in "${envs[@]}"; do case "$e" in GV_*) printf 'export %s=%q\n' "${e%%=*}" "${e#*=}" ;; esac; done; } > "$gvt/fake/env"
  out=$( (cd "$gvt" && env "${envs[@]}" PATH="$gvt/fake:$PATH" python3 -I -B bin/check-govulncheck.py "$@") 2>&1) || rc=$?; }
GVARGS=(--scanners .github/policy/scanners.json --out out)
gvrun GV_OUT=clean -- "${GVARGS[@]}"
if [ "$rc" = 0 ] && [ -f "$gvt/out/govulncheck.json" ] && [ "$(grep -c '^govulncheck -json ./\.\.\.$' "$work/gvlog")" = 2 ] && [ "$(grep -c '^govulncheck -json ./cmd/fscache$' "$work/gvlog")" = 4 ] && [ "$(grep -c '^govulncheck ' "$work/gvlog")" = 7 ]; then ok "G a clean source scan: exit 0, the stream is written to OUT/govulncheck.json, and the tool ran six times (./... and the shipped main on amd64 and arm64, then the shipped main on both with the FIPS build) after the version query"
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
gvrun GOOS=windows GOARCH=arm64 CGO_ENABLED=0 GOAMD64=v4 GOPATH=/tmp/evil-path GOCACHE=/tmp/evil-cache GOMODCACHE=/tmp/evil-mod GOENV=/tmp/evil-env GOFIPS140=evil GV_OUT=clean -- "${GVARGS[@]}"
gvenv_='GOAMD64=unset GOPATH=unset GOCACHE=unset GOMODCACHE=unset GOENV=off'
if [ "$rc" = 0 ] && [ "$(grep -c '^goenv ' "$work/gvlog")" = 7 ] && [ "$(grep -c "^goenv GOOS=unset GOARCH=unset CGO_ENABLED=unset $gvenv_ GOFIPS140=unset\$" "$work/gvlog")" = 1 ] && [ "$(grep -c -E "^goenv GOOS=linux GOARCH=(amd64|arm64) CGO_ENABLED=0 $gvenv_ GOFIPS140=unset\$" "$work/gvlog")" = 4 ] && [ "$(grep -c -E "^goenv GOOS=linux GOARCH=(amd64|arm64) CGO_ENABLED=0 $gvenv_ GOFIPS140=v1.0.0\$" "$work/gvlog")" = 2 ] && [ "$(grep -c 'GOARCH=arm64' "$work/gvlog")" = 3 ]; then ok "G no Go setting of the caller (GOOS, GOARCH, CGO_ENABLED, GOAMD64, GOPATH, GOCACHE, GOMODCACHE, GOENV, GOFIPS140) reaches the scan, persisted Go configuration is off (GOENV=off), and GOFIPS140=v1.0.0 is set on exactly the two FIPS runs"
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
# The two holes proved on the pinned govulncheck v1.7.0 (panel note, Oct 23): a go.mod `ignore` directive plus a decoy main package hid a called advisory from `./...` (an explicit package path
# still found it), and a call that exists only in the linux/arm64 build was invisible to the amd64-only scan. The scan now refuses an `ignore` directive, scans the shipped main package(s) by
# explicit path as well, and runs on linux/amd64 AND linux/arm64 (the build's CGO_ENABLED), each run judged: a called finding in any of the six fails, naming the platform and the target.
gvrun GV_IGNORE=./cmd GV_OUT=clean -- "${GVARGS[@]}"
if [ "$rc" != 0 ] && [ "$rc" != 127 ] && grep -q 'ignore' <<< "$out" && grep -q './cmd' <<< "$out" && ! grep -q '^govulncheck ' "$work/gvlog" && [ ! -e "$gvt/out/govulncheck.json" ]; then ok "G a go.mod ignore directive fails before any scan, naming the ignored path"
else bad "G a go.mod ignore directive -> rc=$rc $out"; fi
gvrun GV_OUT=clean GV_OUT_EXPLICIT=called -- "${GVARGS[@]}"
if [ "$rc" != 0 ] && [ "$rc" != 127 ] && grep -q 'GO-2099-0002' <<< "$out" && grep -q 'cmd/fscache' <<< "$out"; then ok "G a called advisory found only by the explicit scan of the shipped main package fails (the decoy-main case), naming the package"
else bad "G the explicit-path scan finding was not judged: rc=$rc $out"; fi
gvrun GV_OUT=clean GV_OUT_ARM64=called -- "${GVARGS[@]}"
if [ "$rc" != 0 ] && [ "$rc" != 127 ] && grep -q 'GO-2099-0002' <<< "$out" && grep -q 'arm64' <<< "$out"; then ok "G a called advisory that only the linux/arm64 scan finds fails, naming arm64"
else bad "G the arm64 scan finding was not judged: rc=$rc $out"; fi
gvrun GV_OUT=clean GV_OUT_ARM64=called GV_OUT_EXPLICIT=clean -- "${GVARGS[@]}"
if [ "$rc" != 0 ] && [ "$rc" != 127 ] && grep -q 'arm64' <<< "$out" && [ -f "$gvt/out/govulncheck.json" ] && cmp -s "$gvt/out/govulncheck.json" "$work/gv-expected.bin"; then ok "G the file written is still the amd64 ./... stream, byte for byte, when another run fails (it is the product the Release stage binds)"
else bad "G govulncheck.json is not the amd64 ./... stream when a later run fails: rc=$rc"; fi
gvrun GV_OUT=imported GV_OUT_ARM64=imported -- "${GVARGS[@]}"
if [ "$rc" = 0 ]; then ok "G imported-only findings on both platforms still pass (the reachability rule is unchanged)"; else bad "G imported-only on both platforms failed: rc=$rc $out"; fi
gvrun GV_GO_RC=1 GV_OUT=clean -- "${GVARGS[@]}"
if [ "$rc" != 0 ] && [ "$rc" != 127 ] && ! grep -q '^govulncheck ' "$work/gvlog"; then ok "G a go mod edit that fails stops the scan before it starts"; else bad "G a failing go mod edit was accepted: rc=$rc"; fi
rm -f "$gvt/build/melange.yaml"
gvrun GV_OUT=clean -- "${GVARGS[@]}"
if [ "$rc" != 0 ] && [ "$rc" != 127 ] && ! grep -q '^govulncheck ' "$work/gvlog" && grep -q 'melange' <<< "$out"; then ok "G an unreadable build recipe fails closed before any scan, naming it"; else bad "G a missing recipe was accepted: rc=$rc $out"; fi
gv_recipes
for rc_ in 'no go build line|printf "package:\n  name: x\nenvironment:\n  environment:\n    CGO_ENABLED: \"0\"\n" > "$gvt/build/melange.yaml"' 'two go build lines|gv_recipe fscache ./cmd/fscache "$gvt/build/melange.yaml"; echo "      go build -o /x ./cmd/other" >> "$gvt/build/melange.yaml"' 'a package pattern, not a path|gv_recipe fscache ./cmd/... "$gvt/build/melange.yaml"' 'a package that is not a relative path|gv_recipe fscache cmd/fscache "$gvt/build/melange.yaml"' 'a variable as the package|gv_recipe fscache "\$PKG" "$gvt/build/melange.yaml"' 'the two recipes name different packages|gv_recipe fscache ./cmd/other "$gvt/build/melange.yaml"' 'no CGO_ENABLED|sed -i.bak "/CGO_ENABLED/d" "$gvt/build/melange.yaml"; rm -f "$gvt/build/melange.yaml.bak"'; do
  eval "${rc_#*|}"
  gvrun GV_OUT=clean -- "${GVARGS[@]}"
  if [ "$rc" != 0 ] && [ "$rc" != 127 ] && ! grep -q '^govulncheck ' "$work/gvlog"; then ok "G the build recipe is read strictly, fail closed before any scan: ${rc_%%|*}"; else bad "G recipe case '${rc_%%|*}' accepted: rc=$rc"; fi
  gv_recipes
done
# the closed line grammar: each mutation below is a shape the grammar must refuse before any scan (fail closed), in the standard recipe or the FIPS one
gvfl_=$'      export GOFIPS140=v1.0.0\n'
gvcases_=(
  'a trailing comment on the build line|sed -i.bak "s/\(go build .*\)$/\1 # x/" "$gvt/build/melange.yaml"'
  'a semicolon after the build line|sed -i.bak "s/\(go build .*\)$/\1 ; true/" "$gvt/build/melange.yaml"'
  'an ampersand after the build line|sed -i.bak "s/\(go build .*\)$/\1 \&\& true/" "$gvt/build/melange.yaml"'
  'a redirect and pipe on the build line|sed -i.bak "s/\(go build .*\)$/\1 > \/x/" "$gvt/build/melange.yaml"'
  'a second package on the build line|sed -i.bak "s/\(go build .*\)$/\1 .\/cmd\/other/" "$gvt/build/melange.yaml"'
  'a -tags flag|sed -i.bak "s/go build -trimpath/go build -tags x -trimpath/" "$gvt/build/melange.yaml"'
  'an inline runs go build|printf "  - runs: go build -o \/x .\/cmd\/other\n" >> "$gvt/build/melange.yaml"'
  'an absolute-path go|printf "      \/usr\/local\/go\/bin\/go build -o \/x .\/cmd\/other\n" >> "$gvt/build/melange.yaml"'
  'an extra export of a Go setting|printf "      export GOFLAGS=-mod=mod\n" >> "$gvt/build/melange.yaml"'
  'an export CGO_ENABLED line|printf "      export CGO_ENABLED=1\n" >> "$gvt/build/melange.yaml"'
  'CGO_ENABLED named in a trailing description line|printf "      echo CGO_ENABLED=1\n" >> "$gvt/build/melange.yaml"'
  'a command substitution on a go line|printf "      go version -m \$(id)\n" >> "$gvt/build/melange.yaml"'
  'a backtick on a go line|printf "      go version -m \`id\`\n" >> "$gvt/build/melange.yaml"'
  'a go command other than the two|printf "      go env -w GOFLAGS=-mod=mod\n" >> "$gvt/build/melange.yaml"'
  'a go word built by a command substitution|printf "      g\$(printf o) build -o \/x .\/cmd\/other\n" >> "$gvt/build/melange.yaml"'
  'a quoted go word|printf "      g'"'"'o'"'"' build -o \/x .\/cmd\/other\n" >> "$gvt/build/melange.yaml"'
  'a backslash go word|printf "      g\\\\o build -o \/x .\/cmd\/other\n" >> "$gvt/build/melange.yaml"'
  'a command word from a variable|printf "      \$G build -o \/x .\/cmd\/other\n" >> "$gvt/build/melange.yaml"'
  'a substitution on a line with no go word|printf "      echo \$(id)\n" >> "$gvt/build/melange.yaml"'
  'GOFIPS140 in the standard recipe|printf "      export GOFIPS140=v1.0.0\n" >> "$gvt/build/melange.yaml"'
  'the FIPS recipe without the GOFIPS140 export|sed -i.bak "/export GOFIPS140=v1.0.0/d" "$gvt/build/melange-fips.yaml"'
  'the FIPS recipe with another GOFIPS140 value|sed -i.bak "s#export GOFIPS140=v1.0.0#export GOFIPS140=off#" "$gvt/build/melange-fips.yaml"'
  'the FIPS recipe with GOFIPS140 twice|printf "      export GOFIPS140=v1.0.0\n" >> "$gvt/build/melange-fips.yaml"'
  'a fifth environment key|sed -i.bak "s/^    GOPROXY: \"off\"$/    GOPROXY: \"off\"\n    GOAMD64: v3/" "$gvt/build/melange.yaml"'
  'CGO_ENABLED set twice in the environment block|sed -i.bak "s/^    CGO_ENABLED: \"0\"$/    CGO_ENABLED: \"0\"\n    CGO_ENABLED: \"1\"/" "$gvt/build/melange.yaml"'
  'CGO_ENABLED with a value other than 0 or 1|gv_recipe fscache ./cmd/fscache "$gvt/build/melange.yaml" 2'
  'a quoted expansion as the command word|printf "      G=go\n      \"\$G\" build -tags x -o \/x .\/cmd\/other\n" >> "$gvt/build/melange.yaml"'
  'an expansion after a wrapper word|printf "      env \$G build -o \/x .\/cmd\/other\n" >> "$gvt/build/melange.yaml"'
  'a glob as the command word|printf "      \/usr\/local\/go\/bin\/g? build -o \/x .\/cmd\/other\n" >> "$gvt/build/melange.yaml"'
  'eval of a built string|printf "      eval \"g\"\"o build -o \/x .\/cmd\/other\"\n" >> "$gvt/build/melange.yaml"'
  'a template line changed (the install directory)|sed -i.bak "s#^  - runs: mkdir -p /usr/local/#  - runs: mkdir -p /usr/local/x#" "$gvt/build/melange.yaml"'
  'a template line removed (the git set-up)|sed -i.bak "/safe.directory/d" "$gvt/build/melange.yaml"'
  'a template line added in a second step|printf "  - runs: true\n" >> "$gvt/build/melange.yaml"'
  'an extra subpackage with a quoted runs key before the pipeline|sed -i.bak "s#^pipeline:#subpackages:\n  - name: audit-extra\n    pipeline:\n      - \"runs\": |\n          export GOFLAGS=-mod=mod\npipeline:#" "$gvt/build/melange.yaml"'
  'an extra subpackage with an unquoted runs key before the pipeline|sed -i.bak "s#^pipeline:#subpackages:\n  - name: audit-extra\n    pipeline:\n      - runs: |\n          export GOFLAGS=-mod=mod\npipeline:#" "$gvt/build/melange.yaml"'
  'a second package key after the pipeline holding nested content|printf "package:\n  extra: |\n    export GOFLAGS=-mod=mod\n" >> "$gvt/build/melange.yaml"'
  'a second environment key after the pipeline|printf "environment:\n  contents:\n    packages:\n      - x=1\n" >> "$gvt/build/melange.yaml"'
  'a no-break-space comment line that the shell runs|printf '"'"'      \302\240# || export GOFLAGS=-tags=audit_unscanned\n'"'"' >> "$gvt/build/melange.yaml"'
  'an em-space comment line that the shell runs|printf '"'"'      \342\200\203# || export GOFLAGS=-tags=audit_unscanned\n'"'"' >> "$gvt/build/melange.yaml"'
  'an ideographic-space comment line that the shell runs|printf '"'"'      \343\200\200# || export GOFLAGS=-tags=audit_unscanned\n'"'"' >> "$gvt/build/melange.yaml"'
  'a subpackages key after the pipeline|printf "subpackages:\n  - name: x\n" >> "$gvt/build/melange.yaml"'
  'a pipeline key under the package keys|sed -i.bak "s#^  epoch: 0#  epoch: 0\n  pipeline: x#" "$gvt/build/melange.yaml"'
  'a package list line that is not a package|sed -i.bak "s#^      - busybox=#      - evil; true\n      - busybox=#" "$gvt/build/melange.yaml"'
  'a runs step before the pipeline|sed -i.bak "s#^pipeline:#  extra:\n    - runs: true\npipeline:#" "$gvt/build/melange.yaml"'
)
for rc_ in "${gvcases_[@]}"; do
  eval "${rc_#*|}"; rm -f "$gvt"/build/*.bak
  gvrun GV_OUT=clean -- "${GVARGS[@]}"
  if [ "$rc" != 0 ] && [ "$rc" != 127 ] && ! grep -q '^govulncheck ' "$work/gvlog"; then ok "G the closed recipe grammar refuses before any scan: ${rc_%%|*}"; else bad "G grammar case '${rc_%%|*}' accepted: rc=$rc $out"; fi
  gv_recipes
done
# Recipe lines whose text names a shell keyword the pin-age rule reads as a declaration are DATA in the fixture file beside this test (one tab-separated record per case:
# label, the line appended to the standard recipe), read with `read` and never sourced, evaluated or run; the file carries no execute bit.
while IFS=$'\t' read -r gvlabel_ gvline_; do
  [ -n "$gvlabel_" ] || continue
  printf '%s\n' "$gvline_" >> "$gvt/build/melange.yaml"
  gvrun GV_OUT=clean -- "${GVARGS[@]}"
  if [ "$rc" != 0 ] && [ "$rc" != 127 ] && ! grep -q '^govulncheck ' "$work/gvlog"; then ok "G the closed recipe grammar refuses before any scan: $gvlabel_"; else bad "G grammar case '$gvlabel_' accepted: rc=$rc $out"; fi
  gv_recipes
done < "$root/bin/chain-check-scripts-fixtures.txt"
# a package-pin bump (the refresh rewrites the `- pkg=ver` lines) is not a change of the grammar: it still scans
gv_recipes; sed -i.bak 's#^      - busybox=1.38.0-r3#      - busybox=1.39.0-r1#' "$gvt/build/melange.yaml" "$gvt/build/melange-fips.yaml"; rm -f "$gvt"/build/*.bak
gvrun GV_OUT=clean -- "${GVARGS[@]}"
if [ "$rc" = 0 ] && grep -q 'busybox=1.39.0-r1' "$gvt/build/melange.yaml" && [ "$(grep -c '^govulncheck -json ' "$work/gvlog")" = 6 ]; then ok "G a package-pin bump in the recipes still passes the closed grammar (six runs)"; else bad "G a package-pin bump was refused or the scan did not run: rc=$rc $out"; fi
gv_recipes
# the package and CGO_ENABLED come from the recipes, never hard-coded: another path and CGO "1" reach the scan's target and environment
gv_recipes 1; sed -i.bak 's#fscache ./cmd/fscache$#fscache ./cmd/other#' "$gvt/build/melange.yaml" "$gvt/build/melange-fips.yaml"; rm -f "$gvt"/build/*.bak
gvrun GV_OUT=clean -- "${GVARGS[@]}"
if [ "$rc" = 0 ] && [ "$(grep -c '^govulncheck -json ./cmd/other$' "$work/gvlog")" = 4 ] && ! grep -q 'cmd/fscache' "$work/gvlog" && [ "$(grep -c 'CGO_ENABLED=1' "$work/gvlog")" = 6 ]; then ok "G the shipped package and CGO_ENABLED are the recipes' own (./cmd/other and \"1\" reach all six runs)"; else bad "G package/CGO were not taken from the recipes: rc=$rc $out | $(grep -c 'CGO_ENABLED=1' "$work/gvlog")"; fi
gv_recipes
# the real shape of `go mod edit -json` (this machine's Go writes it): a decoy `ignore` is read from the real field, and a module without one passes
mkdir -p "$work/realmod" && printf 'module example.com/a\n\ngo 1.27\n\nignore ./decoy\n' > "$work/realmod/go.mod"
if ( cd "$work/realmod" && GOFLAGS= GOTOOLCHAIN=local go mod edit -json > "$work/real-ignore.json" ) 2> /dev/null && grep -q '"Ignore"' "$work/real-ignore.json"; then
  gvrun GV_GO_JSON="$work/real-ignore.json" GV_OUT=clean -- "${GVARGS[@]}"
  if [ "$rc" != 0 ] && [ "$rc" != 127 ] && ! grep -q '^govulncheck ' "$work/gvlog" && grep -q 'decoy' <<< "$out"; then ok "G the real go mod edit -json output with an ignore directive is refused, naming the path"; else bad "G real ignore output accepted: rc=$rc $out"; fi
else ok "G (no Go on this machine writes the ignore field: the real-output case is skipped)"; fi
printf 'module example.com/a\n\ngo 1.27\n' > "$work/realmod/go.mod"
if ( cd "$work/realmod" && GOFLAGS= GOTOOLCHAIN=local go mod edit -json > "$work/real-plain.json" ) 2> /dev/null && ! grep -q '"Ignore"' "$work/real-plain.json"; then
  gvrun GV_GO_JSON="$work/real-plain.json" GV_OUT=clean -- "${GVARGS[@]}"
  if [ "$rc" = 0 ]; then ok "G the real go mod edit -json output of a module without ignore passes"; else bad "G real plain output refused: rc=$rc $out"; fi
else ok "G (no Go on this machine: the real plain-output case is skipped)"; fi
# go mod edit -json that prints JSON which is not an object cannot say whether an ignore directive is there: refused (REQ-CHAIN-006-AC18), never read as "no ignore"
for nj in '[]' 'null' '"x"' '5'; do
  printf '%s\n' "$nj" > "$work/nonobj.json"
  gvrun GV_GO_JSON="$work/nonobj.json" GV_OUT=clean -- "${GVARGS[@]}"
  if [ "$rc" != 0 ] && [ "$rc" != 127 ] && ! grep -q '^govulncheck ' "$work/gvlog" && [ ! -e "$gvt/out/govulncheck.json" ]; then ok "G go mod edit -json printing $nj (not an object) is refused before any scan (REQ-CHAIN-006-AC18)"; else bad "G non-object go mod JSON $nj accepted: rc=$rc $out"; fi
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
# the egress suite's strace target is the image's real entrypoint (release review V1, Oct 22: it pointed at /usr/local/bin/fscache while the recipes install and
# apko runs /usr/bin/fscache, so the tracer could not start the cache): the path in the script equals both apko entrypoints and the path the recipes install to
ce_=$(sed -n 's/^CANDIDATE_ENTRYPOINT=\(.*\)$/\1/p' "$root/bin/acceptance-egress.sh" | head -1)
ae_=$(sed -n '/^entrypoint:/,/^[a-z]/s/^  command: \(.*\)$/\1/p' "$root/build/apko.yaml" | head -1)
af_=$(sed -n '/^entrypoint:/,/^[a-z]/s/^  command: \(.*\)$/\1/p' "$root/build/apko-fips.yaml" | head -1)
if [ -n "$ce_" ] && [ "$ce_" = "$ae_" ] && [ "$ce_" = "$af_" ]; then ok "acceptance-egress.sh: the strace target $ce_ is the entrypoint of both apko images"; else bad "acceptance-egress.sh: CANDIDATE_ENTRYPOINT '$ce_' != apko.yaml '$ae_' / apko-fips.yaml '$af_'"; fi
if [ -n "$ce_" ] && grep -q "go build -trimpath -o \${{targets.destdir}}${ce_} " "$root/build/melange.yaml" && grep -q "go build -trimpath -o \${{targets.destdir}}${ce_} " "$root/build/melange-fips.yaml"; then ok "acceptance-egress.sh: both recipes install the binary at the strace target $ce_"; else bad "acceptance-egress.sh: a recipe does not install the binary at '$ce_'"; fi
# (audit ruling, Oct 22) the tracer target is assigned ONCE and the strace command line really ends with it: a literal path in the strace launch line, or a second assignment
# after the first, would leave the value above checked but not used
if [ "$(grep -c '^CANDIDATE_ENTRYPOINT=' "$root/bin/acceptance-egress.sh")" = 1 ]; then ok "acceptance-egress.sh: CANDIDATE_ENTRYPOINT is assigned exactly once"; else bad "acceptance-egress.sh: CANDIDATE_ENTRYPOINT is assigned $(grep -c '^CANDIDATE_ENTRYPOINT=' "$root/bin/acceptance-egress.sh") times (the first one is the one checked, the last one is the one used)"; fi
cl_=$(grep -- '--entrypoint /trace/strace' "$root/bin/acceptance-egress.sh" | grep -- 'fscache-cand-')
n_cl_=$(printf '%s\n' "$cl_" | grep -c . || true)
if [ "$n_cl_" = 1 ] && grep -Eq '"\$CANDIDATE_ENTRYPOINT"( >/dev/null)?[[:space:]]*$' <<< "$cl_"; then ok "acceptance-egress.sh: the one candidate strace launch line (--entrypoint /trace/strace) ends with \"\$CANDIDATE_ENTRYPOINT\""; else bad "acceptance-egress.sh: the candidate strace launch is not one line ending with \"\$CANDIDATE_ENTRYPOINT\""; fi
EXPECT=594
echo "pass=$pass fail=$failn"
if [ $((pass + failn)) != "$EXPECT" ]; then echo "FAIL case count $((pass + failn)) != expected $EXPECT (a case was skipped or added)"; exit 1; fi
[ "$failn" = 0 ]
