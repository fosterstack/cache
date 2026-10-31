#!/usr/bin/env bash
# proves: REQ-VEND-001-AC15, REQ-VEND-001-AC1, REQ-VEND-001-AC4, REQ-VEND-001-AC5, REQ-VEND-001-AC6, REQ-VEND-001-AC7, REQ-VEND-001-AC8, REQ-VEND-001-AC9, REQ-VEND-001-AC10, REQ-VEND-001-AC11, REQ-VEND-001-AC12, REQ-VEND-001-AC13, REQ-VEND-001-AC14
# The vendored tree and its provenance (REQ-VEND-001, owner-ratified dependency rules 1-10; ACs accepted by the advisor Oct 12):
# the committed vendor/ tree and the build-recipe mode (AC1, AC6), dependency-provenance.json (check, build; AC4, AC5, AC14), the
# evidence file the release assembles (AC7-AC10), and the listable shape, signing and wording rules (AC11-AC13). The regenerate-and-compare
# check and the vendor job (AC2, AC3) are proved in bin/vendoring-test.sh. Offline: every record is a hand-written fixture file and no
# step reaches the network. Run it from the repository root, with stdin closed.
set -uo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
work=$(mktemp -d); trap 'chmod -R u+w "$work" 2>/dev/null; rm -rf "$work"' EXIT
pass=0 failn=0
ok()  { pass=$((pass+1)); }
bad() { failn=$((failn+1)); echo "FAIL [$1] $2"; }
t()  { local ac=$1 d=$2; shift 2; if "$@" >"$work/out" 2>&1; then ok; else bad "$ac" "$d"; fi; }
# tn: passes when the command exits NON-ZERO and the tool exists (a missing tool never counts as a catch)
tn() { local ac=$1 d=$2; shift 2; if [ ! -e "$2" ]; then bad "$ac" "$d (tool missing)"; return; fi
       if "$@" >"$work/out" 2>&1; then bad "$ac" "$d (expected a refusal)"; else ok; fi; }
# rc: passes when the command exits with exactly the code
rc() { local ac=$1 d=$2 want=$3; shift 3; if [ ! -e "$bin_vp" ]; then bad "$ac" "$d (tool missing)"; return; fi
       "$@" >"$work/out" 2>&1; local got=$?; if [ "$got" = "$want" ]; then ok; else bad "$ac" "$d (exit $got, want $want)"; fi; }
bin_vp="$root/bin/vendor-provenance.py"
vp() { python3 "$bin_vp" "$@"; }

# ---------- fixtures ---------------------------------------------------------------------------
H1=h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
H2=h1:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
C2=2222222222222222222222222222222222222222
mkfix() { # a two-module set, one tagged and one pseudo-version, all consistent
  local d=$1; mkdir -p "$d/vendor"
  cat >"$d/vendor/modules.txt" <<EOF
# example.test/alpha v1.2.3
## explicit; go 1.20
example.test/alpha
# example.test/beta v0.0.0-20191010083416-a7dc8b61c822
## explicit
example.test/beta
EOF
  cat >"$d/go.sum" <<EOF
example.test/alpha v1.2.3 $H1
example.test/alpha v1.2.3/go.mod h1:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=
example.test/beta v0.0.0-20191010083416-a7dc8b61c822 $H2
example.test/beta v0.0.0-20191010083416-a7dc8b61c822/go.mod h1:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=
EOF
  cat >"$d/sumdb.json" <<EOF
{"example.test/alpha@v1.2.3":{"hash":"$H1","included":true,"log":"sum.golang.org"},"example.test/beta@v0.0.0-20191010083416-a7dc8b61c822":{"hash":"$H2","included":true,"log":"sum.golang.org"}}
EOF
  cat >"$d/origins.json" <<EOF
{"example.test/alpha@v1.2.3":{"url":"https://example.test/alpha","tag":"v1.2.3"},"example.test/beta@v0.0.0-20191010083416-a7dc8b61c822":{"url":"https://example.test/beta","commit":"$C2"}}
EOF
  echo '{"example.test/alpha@v1.2.3":"MIT","example.test/beta@v0.0.0-20191010083416-a7dc8b61c822":"Apache-2.0"}' >"$d/licenses.json"
}
build() { vp build --vendor-dir "$1/vendor" --go-sum "$1/go.sum" --sumdb-record "$1/sumdb.json" --origins "$1/origins.json" --licenses "$1/licenses.json" --out "$2"; }
chk() { vp check --vendor-dir "$1/vendor" --go-sum "$1/go.sum" --provenance "$2"; }
mut() { python3 - "$1" "$2" <<'PY'
import json, sys
p, code = sys.argv[1], sys.argv[2]
d = json.load(open(p)); exec(code); json.dump(d, open(p, "w"))
PY
}

# ===== AC1: the tree ========================================================================
t AC1 "vendor/modules.txt is committed" test -s "$root/vendor/modules.txt"
t AC1 "every go.mod require is an exact vX.Y.Z (or pseudo-version), no replace to a path" python3 - "$root/go.mod" <<'PY'
import re, sys
txt = open(sys.argv[1]).read()
reqs = re.findall(r"^\s*(?:require\s+)?([^\s/]+\.[^\s]+/?[^\s]*)\s+(v\S+)", txt, re.M)
assert reqs, "no requires found"
for m, v in reqs:
    assert re.fullmatch(r"v\d+\.\d+\.\d+(-[0-9A-Za-z.+-]+)?", v), f"{m} {v} is not exact"
assert not re.search(r"^\s*replace\b", txt, re.M), "a replace directive"
PY
t AC1 "go list -mod=vendor succeeds on the real tree" bash -c "test -d vendor && GOFLAGS= go list -mod=vendor ./... >/dev/null"
t AC1 "no workflow, script or recipe passes -mod=mod or -mod=readonly to the go tool" python3 - <<'PY'
import os, re, subprocess
files = subprocess.run(["git", "ls-files", ".github", "bin", "build", "tools"], capture_output=True, text=True).stdout.split("\n")
bad = []
for f in files:
    if not f or f.endswith(("-test.sh", "_test.go", "_test.py")) or f.startswith("vendor/") or not os.path.isfile(f):
        continue
    for n, l in enumerate(open(f, errors="replace"), 1):
        if re.search(r"\bgo\s+(build|test|vet|run|list)\b[^\n]*-mod=(mod|readonly)", l) or re.search(r"GOFLAGS[:=]\s*[\"']?[^\n]*-mod=(mod|readonly)", l):
            bad.append("%s:%d" % (f, n))
assert not bad, bad
PY
# recipe_env_check <dir>: every <dir>/melange*.yaml sets GOFLAGS=-mod=vendor and GOPROXY=off, except the one path in
# SKIPPED.
recipe_env_check() {
  python3 - "$1" <<'PY'
import glob, re, sys
SKIPPED = ["build/melange-baselayout.yaml"]      # builds no Go, so it has nothing to vendor
for f in glob.glob(sys.argv[1] + "/melange*.yaml"):
    if f in SKIPPED:
        continue
    s = open(f).read()
    assert re.search(r"GOFLAGS:\s*[\"']?-mod=vendor", s) and re.search(r"GOPROXY:\s*[\"']?off", s), f
PY
}
t AC1 "every build recipe that exists sets GOFLAGS=-mod=vendor and GOPROXY=off" recipe_env_check build
# the check itself, on recipes written for it. A root folder per case, because the skipped path is relative to the
# repository root.
GOENV=$'  environment:\n    GOFLAGS: -mod=vendor\n    GOPROXY: "off"\n'
mkrec() { mkdir -p "$work/rec/$1/build"; printf '%s\n' "$3" >"$work/rec/$1/build/$2"; }
in_rec() { local root=$1; shift; (cd "$root" && "$@"); }
mkrec ok-go melange.yaml "go build ./cmd/x
$GOENV"
mkrec skipped melange-baselayout.yaml "package: {name: base}"
mkrec new-no-go melange-new.yaml "package: {name: new}"
mkrec no-env melange.yaml "go build ./cmd/x"
mkrec install-no-env melange.yaml "go install ./cmd/x"
mkrec comment-no-env melange.yaml "# built with go
pipeline: []"
t  AC1 "recipe check: a Go recipe with both settings passes" in_rec "$work/rec/ok-go" recipe_env_check build
t  AC1 "recipe check: build/melange-baselayout.yaml is skipped, with no Go and no settings" in_rec "$work/rec/skipped" recipe_env_check build
tn AC1 "recipe check: a NEW recipe with no go word and no settings fails" in_rec "$work/rec/new-no-go" recipe_env_check build
tn AC1 "recipe check: a recipe with go build and no settings fails" in_rec "$work/rec/no-env" recipe_env_check build
tn AC1 "recipe check: a recipe with go install and no settings fails" in_rec "$work/rec/install-no-env" recipe_env_check build
tn AC1 "recipe check: a recipe that only mentions go in a comment, without the settings, fails" in_rec "$work/rec/comment-no-env" recipe_env_check build
t AC1 "go.sum exists and is non-empty" test -s "$root/go.sum"

# ===== AC4: check ==============================================================================
F="$work/f4"; mkfix "$F"
t AC4 "build writes provenance from consistent fixtures" build "$F" "$F/prov.json"
t AC4 "provenance has exactly the fixture modules, the six facts, tag for a tagged version and commit for a pseudo-version" python3 - "$F/prov.json" "$H1" "$H2" "$C2" <<'PY'
import json, re, sys
d = json.load(open(sys.argv[1]))
assert d.get("schema") == "fosterstack/dependency-provenance/v1"
m = {(x["path"], x["version"]): x for x in d["modules"]}
assert set(m) == {("example.test/alpha", "v1.2.3"), ("example.test/beta", "v0.0.0-20191010083416-a7dc8b61c822")}, set(m)
for (p, v), x in m.items():
    assert set(x) == {"path", "version", "go_sum_hash", "checksum_log", "origin", "license"}, x
    assert x["checksum_log"] == {"included": True, "log": "sum.golang.org"}
    assert x["origin"]["url"].startswith("https://") and x["license"]
a, b = m[("example.test/alpha", "v1.2.3")], m[("example.test/beta", "v0.0.0-20191010083416-a7dc8b61c822")]
assert a["go_sum_hash"] == sys.argv[2] and a["origin"] == {"url": "https://example.test/alpha", "tag": "v1.2.3"}
assert b["go_sum_hash"] == sys.argv[3] and b["origin"] == {"url": "https://example.test/beta", "commit": sys.argv[4]}
assert [x["path"] for x in d["modules"]] == sorted(x["path"] for x in d["modules"])
PY
t AC4 "check accepts the fresh provenance" chk "$F" "$F/prov.json"
neg4() { cp "$F/prov.json" "$work/p-$1.json" 2>/dev/null; [ -f "$work/p-$1.json" ] && mut "$work/p-$1.json" "$2" 2>/dev/null
         rc AC4 "check refuses (exit 2): $1" 2 python3 "$bin_vp" check --vendor-dir "$F/vendor" --go-sum "$F/go.sum" --provenance "$work/p-$1.json"; }
neg4 missing-field  "del d['modules'][0]['origin']"
neg4 empty-license  "d['modules'][0]['license']=''"
neg4 non-h1-hash    "d['modules'][0]['go_sum_hash']='sha256:abc'"
neg4 hash-not-gosum "d['modules'][0]['go_sum_hash']='h1:ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ='"
neg4 short-commit   "d['modules'][1]['origin']['commit']='abc123'"
neg4 http-url       "d['modules'][0]['origin']['url']='http://example.test/alpha'"
neg4 not-in-log     "d['modules'][0]['checksum_log']['included']=False"
neg4 extra-module   "d['modules'].append(dict(d['modules'][0], path='example.test/gamma'))"
neg4 missing-module "d['modules'].pop()"
neg4 wrong-schema   "d['schema']='x'"
neg4 extra-field    "d['modules'][0]['note']='x'"
neg4 tag-for-pseudo "d['modules'][1]['origin']={'url':'https://example.test/beta','tag':'v1'}"
neg4 commit-for-tag "d['modules'][0]['origin']={'url':'https://example.test/alpha','commit':'$C2'}"
printf '{"schema":"fosterstack/dependency-provenance/v1","schema":"x","modules":[]}' >"$work/dup.json"
cp -R "$F" "$work/f4dup"; printf 'example.test/alpha v1.2.3 h1:ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ=\n' >>"$work/f4dup/go.sum"
rc AC4 "check refuses (exit 2): go.sum names two different hashes for one module version" 2 python3 "$bin_vp" check --vendor-dir "$work/f4dup/vendor" --go-sum "$work/f4dup/go.sum" --provenance "$F/prov.json"
if grep -q "go.sum.*example.test/alpha.*v1.2.3\|example.test/alpha.*v1.2.3.*conflict" "$work/out"; then ok; else bad AC4 "... and says which module version conflicts: $(head -c 120 "$work/out")"; fi
cp -R "$F" "$work/f4same"; printf 'example.test/alpha v1.2.3 %s\n' "$H1" >>"$work/f4same/go.sum"
rc AC4 "check accepts (exit 0): the same hash repeated for one module version" 0 python3 "$bin_vp" check --vendor-dir "$work/f4same/vendor" --go-sum "$work/f4same/go.sum" --provenance "$F/prov.json"
rc AC4 "check refuses (exit 2): a repeated key" 2 python3 "$bin_vp" check --vendor-dir "$F/vendor" --go-sum "$F/go.sum" --provenance "$work/dup.json"
sed -i.bak 's#example.test/alpha v1.2.3#example.test/alpha v1.2.4#' "$F/vendor/modules.txt"
rc AC4 "check refuses (exit 2) stale provenance after a version bump" 2 python3 "$bin_vp" check --vendor-dir "$F/vendor" --go-sum "$F/go.sum" --provenance "$F/prov.json"
t AC4 "real tree: dependency-provenance.json exists" test -s "$root/dependency-provenance.json"
t AC4 "real tree: provenance checks against vendor/ and go.sum" vp check --vendor-dir "$root/vendor" --go-sum "$root/go.sum" --provenance "$root/dependency-provenance.json"

# ===== AC5: build fails closed, no partial file ===============================================
f5() { local d="$work/f5-$1"; mkfix "$d"; [ -e "$bin_vp" ] && mut "$d/$3" "$2" 2>/dev/null
       rc AC5 "build refuses (non-zero): $1" 2 python3 "$bin_vp" build --vendor-dir "$d/vendor" --go-sum "$d/go.sum" --sumdb-record "$d/sumdb.json" --origins "$d/origins.json" --licenses "$d/licenses.json" --out "$d/out.json"
       t AC5 "no partial provenance written: $1" bash -c "[ -e '$bin_vp' ] && [ ! -e '$d/out.json' ]"; }
B="example.test/beta@v0.0.0-20191010083416-a7dc8b61c822"
f5 origin-missing     "d.pop('$B')"                                       origins.json
f5 commit-empty       "d['$B']['commit']=''"                              origins.json
f5 url-not-https      "d['$B']['url']='git://x/y'"                        origins.json
f5 tag-empty          "d['example.test/alpha@v1.2.3']['tag']=''"          origins.json
f5 sumdb-missing      "d.pop('example.test/alpha@v1.2.3')"                sumdb.json
f5 not-included       "d['example.test/alpha@v1.2.3']['included']=False"  sumdb.json
f5 sumdb-hash-differs "d['example.test/alpha@v1.2.3']['hash']='h1:ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ='" sumdb.json
f5 license-missing    "d.pop('$B')"                                       licenses.json
f5 license-empty      "d['$B']=''"                                        licenses.json

# ===== AC6: the one mode ========================================================================
F6="$work/f6"; mkfix "$F6"; build "$F6" "$F6/prov.json" >/dev/null 2>&1; echo '{"vulns":[]}' >"$F6/govuln.json"
t AC6 "no recipe or script downloads modules into the build (go mod download, go get, -mod=mod)" python3 - <<'PY'
import os, re, subprocess
bad = []
for f in subprocess.run(["git", "ls-files", "bin", "build", ".github/workflows"], capture_output=True, text=True).stdout.split("\n"):
    if not f or f.endswith(("-test.sh", "_test.py")) or not os.path.isfile(f):
        continue
    if f.startswith(".github/workflows/") and not f.startswith(".github/workflows/stage-"):
        continue                      # CI tool installs are not a product build; the release stages are
    for n, l in enumerate(open(f, errors="replace"), 1):
        if re.match(r"\s*(run:\s*)?go (mod download|get)\b", l):
            bad.append("%s:%d" % (f, n))
assert not bad, bad
PY
t AC6 "the evidence declares the one mode: vendor" bash -c "python3 '$bin_vp' evidence --out '$F6/ev' --provenance '$F6/prov.json' --govulncheck '$F6/govuln.json' --date 1790000000 && python3 -c \"import json,sys; assert json.load(open('$F6/ev/vendor-evidence.json'))['mode']=='vendor'\""

# ===== AC7: evidence ==========================================================================
F7="$work/f7"; mkfix "$F7"; build "$F7" "$F7/prov.json" >/dev/null 2>&1; echo '{"vulns":[]}' >"$F7/govuln.json"
ev() { vp evidence --out "$1" --provenance "$F7/prov.json" --govulncheck "$F7/govuln.json" --date "${2:-1790000000}"; }
t AC7 "evidence writes DIR/vendor-evidence.json and nothing else" bash -c "python3 '$bin_vp' evidence --out '$F7/ev' --provenance '$F7/prov.json' --govulncheck '$F7/govuln.json' --date 1790000000 && [ \"\$(ls '$F7/ev')\" = vendor-evidence.json ]"
t AC7 "evidence carries the schema, the mode, both digests, the module count and the date as epoch and UTC day" python3 - "$F7" <<'PY'
import hashlib, json, sys
d = sys.argv[1]
e = json.load(open(d + "/ev/vendor-evidence.json"))
sha = lambda p: hashlib.sha256(open(p, "rb").read()).hexdigest()
assert e == {"schema": "fosterstack/vendor-evidence/v1", "mode": "vendor",
             "provenance": {"sha256": sha(d + "/prov.json"), "modules": 2},
             "govulncheck": {"sha256": sha(d + "/govuln.json")},
             "date": {"epoch": 1790000000, "utc": "2026-09-21"}}, e
PY

# a stream of the shape govulncheck -json writes (config, SBOM, a finding; pretty-printed, one object after another); built here so this file names no auditor path
GV="$work/gv-stream.json"
printf '{\n  "config": {\n    "protocol_version": "v1.0.0",\n    "scanner_name": "govulncheck",\n    "scan_mode": "source"\n  }\n}\n{\n  "SBOM": {\n    "modules": [\n      {\n        "path": "stdlib",\n        "version": "v1.27.0"\n      }\n    ]\n  }\n}\n{\n  "finding": {\n    "osv": "GO-2026-0001",\n    "trace": [\n      {\n        "module": "stdlib"\n      }\n    ]\n  }\n}\n' >"$GV"
t AC7 "evidence accepts govulncheck's own output, a stream of JSON messages (a pretty-printed multi-object stream), and hashes its original bytes" python3 - "$bin_vp" "$F7" "$GV" "$work/ev7-stream" <<'PY'
import hashlib, json, subprocess, sys
bp, fx, gv, out = sys.argv[1:5]
r = subprocess.run(["python3", bp, "evidence", "--out", out, "--provenance", fx + "/prov.json", "--govulncheck", gv, "--date", "1790000000"], capture_output=True, text=True)
assert r.returncode == 0, (r.returncode, r.stderr)
e = json.load(open(out + "/vendor-evidence.json"))
assert e["govulncheck"]["sha256"] == hashlib.sha256(open(gv, "rb").read()).hexdigest(), e
PY

# ===== AC8: refusals, nothing written ==========================================================
r8() { local n=$1; shift; rm -rf "$work/ev8-$n"; rc AC8 "evidence refuses (exit 2): $n" 2 python3 "$bin_vp" evidence "$@" --out "$work/ev8-$n"
       t AC8 "nothing written, DIR not created: $n" bash -c "[ -e '$bin_vp' ] && [ ! -e '$work/ev8-$n' ]"; }
P="$F7/prov.json" G="$F7/govuln.json"
r8 date-word        --provenance "$P" --govulncheck "$G" --date yesterday
r8 date-iso         --provenance "$P" --govulncheck "$G" --date 2026-10-08
r8 date-empty       --provenance "$P" --govulncheck "$G" --date ""
r8 date-negative    --provenance "$P" --govulncheck "$G" --date -1
r8 date-leading-0   --provenance "$P" --govulncheck "$G" --date 01790000000
r8 date-too-big     --provenance "$P" --govulncheck "$G" --date 253402300800
r8 date-huge        --provenance "$P" --govulncheck "$G" --date "$(printf '9%.0s' $(seq 1 5000))"
r8 prov-missing     --provenance "$work/nope.json" --govulncheck "$G" --date 1
r8 govuln-missing   --provenance "$P" --govulncheck "$work/nope.json" --date 1
: >"$work/empty.json"; echo '[' >"$work/bad.json"; mkdir "$work/adir"; ln -s "$G" "$work/link.json"
r8 govuln-empty     --provenance "$P" --govulncheck "$work/empty.json" --date 1
r8 govuln-not-json  --provenance "$P" --govulncheck "$work/bad.json" --date 1
printf '{"a": NaN}\n' >"$work/g-nan.json"; printf '{"a": Infinity}\n' >"$work/g-inf.json"; printf '{"config":{}}\n{"finding":\n' >"$work/g-trunc.json"; printf '{"config":{}} [1,2]\n' >"$work/g-array.json"; printf '"just a string"\n' >"$work/g-str.json"
r8 govuln-nan       --provenance "$P" --govulncheck "$work/g-nan.json" --date 1
r8 govuln-infinity  --provenance "$P" --govulncheck "$work/g-inf.json" --date 1
r8 govuln-truncated-stream --provenance "$P" --govulncheck "$work/g-trunc.json" --date 1
r8 govuln-array-in-stream  --provenance "$P" --govulncheck "$work/g-array.json" --date 1
r8 govuln-bare-string      --provenance "$P" --govulncheck "$work/g-str.json" --date 1
r8 govuln-dir       --provenance "$P" --govulncheck "$work/adir" --date 1
r8 govuln-link      --provenance "$P" --govulncheck "$work/link.json" --date 1
r8 prov-bad-schema  --provenance "$work/p-wrong-schema.json" --govulncheck "$G" --date 1
r8 unknown-flag     --provenance "$P" --govulncheck "$G" --date 1 --frobnicate x
r8 repeated-flag    --provenance "$P" --provenance "$P" --govulncheck "$G" --date 1
r8 missing-flag     --provenance "$P" --date 1
echo x >"$work/afile"
rc AC8 "evidence refuses (exit 2): --out is an existing file" 2 python3 "$bin_vp" evidence --out "$work/afile" --provenance "$P" --govulncheck "$G" --date 1

t AC8 "an output failure exits 1, leaves no partial or temporary file and keeps an earlier complete evidence file" python3 - "$bin_vp" "$F7" "$work/ev8-fault" <<'PY'
import importlib.util, os, sys
bp, fx, out = sys.argv[1:4]
spec = importlib.util.spec_from_file_location("vp", bp); vp = importlib.util.module_from_spec(spec); spec.loader.exec_module(vp)
os.makedirs(out); good = b'{"earlier":"complete"}\n'; open(out + "/vendor-evidence.json", "wb").write(good)
real_replace = os.replace
def boom(*a, **k): raise OSError(28, "No space left on device")
args = ["--out", out, "--provenance", fx + "/prov.json", "--govulncheck", fx + "/govuln.json", "--date", "1790000000"]
os.replace = boom
try:
    rc = vp.main(["evidence"] + args)
finally:
    os.replace = real_replace
assert rc == 1, rc
assert open(out + "/vendor-evidence.json", "rb").read() == good, "the earlier file was changed"
assert os.listdir(out) == ["vendor-evidence.json"], os.listdir(out)
PY

t AC8 "an output failure with an ABSENT output directory leaves no directory behind (the new parents too), and a pre-existing parent stays" python3 - "$bin_vp" "$F7" "$work/ev8-absent" <<'PY'
import importlib.util, os, sys
bp, fx, base = sys.argv[1:4]
spec = importlib.util.spec_from_file_location("vp", bp); vp = importlib.util.module_from_spec(spec); spec.loader.exec_module(vp)
os.makedirs(base)
out = base + "/new/deeper/ev"
real = os.replace
def boom(*a, **k): raise OSError(28, "No space left on device")
os.replace = boom
try:
    rc = vp.main(["evidence", "--out", out, "--provenance", fx + "/prov.json", "--govulncheck", fx + "/govuln.json", "--date", "1790000000"])
finally:
    os.replace = real
assert rc == 1, rc
assert os.listdir(base) == [], os.listdir(base)
PY
t AC8 "a leftover temporary name is never deleted by another run: the file stays and no evidence is written" python3 - "$bin_vp" "$F7" "$work/ev8-collide" <<'PY'
import importlib.util, os, sys
bp, fx, out = sys.argv[1:4]
spec = importlib.util.spec_from_file_location("vp", bp); vp = importlib.util.module_from_spec(spec); spec.loader.exec_module(vp)
os.makedirs(out)
name = out + "/.vendor-evidence.json.tmp-" + (b"\x01" * 8).hex()
open(name, "w").write("someone else's file\n")
real = os.urandom
os.urandom = lambda n: b"\x01" * n
try:
    rc = vp.main(["evidence", "--out", out, "--provenance", fx + "/prov.json", "--govulncheck", fx + "/govuln.json", "--date", "1790000000"])
finally:
    os.urandom = real
assert rc == 1, rc
assert open(name).read() == "someone else's file\n", "the other file was removed or changed"
assert sorted(os.listdir(out)) == [os.path.basename(name)], os.listdir(out)
PY

# Output cleanup is closed by construction: a '..' component is refused before anything is touched, directories are made one at a time and only the ones THIS run made
# are removed (never another run's), and the temporary file is created, replaced and removed through the open output directory, never through a path that can be retargeted.
t AC8 "a failure part-way through creating the output directories removes the ones this run made (the base stays empty)" python3 - "$bin_vp" "$F7" "$work/ev8-partial" <<'PY'
import importlib.util, os, sys
bp, fx, base = sys.argv[1:4]
spec = importlib.util.spec_from_file_location("vp", bp); vp = importlib.util.module_from_spec(spec); spec.loader.exec_module(vp)
os.makedirs(base)
real = os.mkdir
def flaky(path, *a, **k):
    if os.path.basename(path) == "deeper": raise OSError(28, "No space left on device")
    return real(path, *a, **k)
os.mkdir = flaky
try:
    rc = vp.main(["evidence", "--out", base + "/new/deeper/ev", "--provenance", fx + "/prov.json", "--govulncheck", fx + "/govuln.json", "--date", "1790000000"])
finally:
    os.mkdir = real
assert rc == 1, rc
assert os.listdir(base) == [], os.listdir(base)
PY
rc AC8 "an --out with a '..' component is refused (exit 2) before anything is created" 2 python3 "$bin_vp" evidence --out "$work/ev8-dd/new/../ev" --provenance "$F7/prov.json" --govulncheck "$F7/govuln.json" --date 1790000000
t AC8 "... and nothing was created" bash -c "[ -e '$bin_vp' ] && [ ! -e '$work/ev8-dd' ]"
t AC8 "a directory another run creates meanwhile is never removed by this run's cleanup" python3 - "$bin_vp" "$F7" "$work/ev8-race" <<'PY'
import importlib.util, os, sys
bp, fx, base = sys.argv[1:4]
spec = importlib.util.spec_from_file_location("vp", bp); vp = importlib.util.module_from_spec(spec); spec.loader.exec_module(vp)
os.makedirs(base)
real_mkdir, real_replace = os.mkdir, os.replace
def raced(path, *a, **k):
    if os.path.basename(path) == "new":      # the other run wins the creation of 'new'
        real_mkdir(path, *a, **k); raise FileExistsError(17, "File exists", path)
    return real_mkdir(path, *a, **k)
def boom(*a, **k): raise OSError(28, "No space left on device")
os.mkdir, os.replace = raced, boom
try:
    rc = vp.main(["evidence", "--out", base + "/new/ev", "--provenance", fx + "/prov.json", "--govulncheck", fx + "/govuln.json", "--date", "1790000000"])
finally:
    os.mkdir, os.replace = real_mkdir, real_replace
assert rc == 1, rc
assert os.path.isdir(base + "/new"), "the other run's directory was removed"
assert os.listdir(base + "/new") == [], os.listdir(base + "/new")
PY
t AC8 "a symlinked output directory retargeted mid-run: the temporary file is removed from the directory it was created in, the other directory's same-named file stays" python3 - "$bin_vp" "$F7" "$work/ev8-link" <<'PY'
import importlib.util, os, sys
bp, fx, base = sys.argv[1:4]
spec = importlib.util.spec_from_file_location("vp", bp); vp = importlib.util.module_from_spec(spec); spec.loader.exec_module(vp)
A, B = base + "/A", base + "/B"; os.makedirs(A); os.makedirs(B); os.symlink(A, base + "/out")
name = ".vendor-evidence.json.tmp-" + (b"\x01" * 8).hex()
open(B + "/" + name, "w").write("other directory's file\n")
real_urandom, real_replace = os.urandom, os.replace
def retarget_then_fail(*a, **k):
    os.unlink(base + "/out"); os.symlink(B, base + "/out")      # the path now leads to B; this run's open directory is still A
    raise OSError(28, "No space left on device")
os.urandom = lambda n: b"\x01" * n
os.replace = retarget_then_fail
try:
    rc = vp.main(["evidence", "--out", base + "/out", "--provenance", fx + "/prov.json", "--govulncheck", fx + "/govuln.json", "--date", "1790000000"])
finally:
    os.urandom, os.replace = real_urandom, real_replace
assert rc == 1, rc
assert open(B + "/" + name).read() == "other directory's file\n", "the other directory's file was removed"
assert os.listdir(A) == [], os.listdir(A)
PY

t AC8 "an ancestor symlink retargeted mid-run: this run's directories are removed where it made them, the other run's same-named directory stays" python3 - "$bin_vp" "$F7" "$work/ev8-anc" <<'PY'
import importlib.util, os, sys
bp, fx, base = sys.argv[1:4]
spec = importlib.util.spec_from_file_location("vp", bp); vp = importlib.util.module_from_spec(spec); spec.loader.exec_module(vp)
A, B = base + "/A", base + "/B"; os.makedirs(A); os.makedirs(B + "/new"); os.symlink(A, base + "/link")
real = os.replace
def retarget_then_fail(*a, **k):
    os.unlink(base + "/link"); os.symlink(B, base + "/link")
    raise OSError(28, "No space left on device")
os.replace = retarget_then_fail
try:
    rc = vp.main(["evidence", "--out", base + "/link/new", "--provenance", fx + "/prov.json", "--govulncheck", fx + "/govuln.json", "--date", "1790000000"])
finally:
    os.replace = real
assert rc == 1, rc
assert os.listdir(A) == [], os.listdir(A)
assert os.listdir(B) == ["new"] and os.listdir(B + "/new") == [], (os.listdir(B), os.listdir(B + "/new"))
PY
t AC8 "a failure to close the output directory never hides the original error, and never fails a published file" python3 - "$bin_vp" "$F7" "$work/ev8-close" <<'PY'
import importlib.util, io, os, sys
bp, fx, base = sys.argv[1:4]
spec = importlib.util.spec_from_file_location("vp", bp); vp = importlib.util.module_from_spec(spec); spec.loader.exec_module(vp)
os.makedirs(base)
args = ["--provenance", fx + "/prov.json", "--govulncheck", fx + "/govuln.json", "--date", "1790000000"]
real_close, real_replace, real_err = os.close, os.replace, sys.stderr
def bad_close(fd): real_close(fd); raise OSError(5, "close-cleanup EIO")
def boom(*a, **k): raise OSError(28, "replace-original ENOSPC")
os.close, os.replace, sys.stderr = bad_close, boom, io.StringIO()
try:
    rc = vp.main(["evidence", "--out", base + "/one"] + args); msg = sys.stderr.getvalue()
finally:
    os.close, os.replace, sys.stderr = real_close, real_replace, real_err
assert rc == 1 and "replace-original" in msg and "close-cleanup" not in msg, (rc, msg)
os.close = bad_close
try:
    rc = vp.main(["evidence", "--out", base + "/two"] + args)
finally:
    os.close = real_close
assert rc == 0 and os.path.isfile(base + "/two/vendor-evidence.json"), rc
PY

t AC10 "--out / and --out /// open the root directory, never the working directory, and write nothing before that open fails" python3 - "$bin_vp" "$F7" <<'PY'
import importlib.util, os, sys
bp, fx = sys.argv[1:3]
spec = importlib.util.spec_from_file_location("vp", bp); vp = importlib.util.module_from_spec(spec); spec.loader.exec_module(vp)
real_open = os.open
for out in ("/", "///"):
    seen = []
    def spy(path, flags, *a, **k):
        seen.append(path)
        raise OSError(13, "stop before any creation")
    os.open = spy
    try:
        rc = vp.main(["evidence", "--out", out, "--provenance", fx + "/prov.json", "--govulncheck", fx + "/govuln.json", "--date", "1790000000"])
    finally:
        os.open = real_open
    assert rc == 1 and seen == ["/"], (out, rc, seen)
PY

# ===== AC9: determinism ========================================================================
ev "$work/d1" >/dev/null 2>&1; ev "$work/d2" >/dev/null 2>&1; ev "$work/d3" 1790000001 >/dev/null 2>&1
t AC9 "two runs are byte-identical" bash -c "[ -s '$work/d1/vendor-evidence.json' ] && cmp -s '$work/d1/vendor-evidence.json' '$work/d2/vendor-evidence.json'"
t AC9 "a different date gives a different file" bash -c "[ -s '$work/d3/vendor-evidence.json' ] && ! cmp -s '$work/d1/vendor-evidence.json' '$work/d3/vendor-evidence.json'"
t AC9 "the file ends in one LF and holds no path or host name" bash -c "[ -s '$work/d1/vendor-evidence.json' ] && [ \"\$(tail -c1 '$work/d1/vendor-evidence.json' | od -An -c | tr -d ' ')\" = '\\n' ] && ! grep -q '$work' '$work/d1/vendor-evidence.json'"

# ===== AC10: offline, read-only ================================================================
t AC10 "evidence and check run with every socket call refused" python3 - "$bin_vp" "$F7" "$work/d1" <<'PY'
import os, runpy, socket, sys
def no(*a, **k): raise OSError("network is off")
socket.socket = no; socket.create_connection = no; socket.getaddrinfo = no
script, fx, out = sys.argv[1:4]
for argv in (["vendor-provenance.py", "check", "--vendor-dir", fx + "/vendor", "--go-sum", fx + "/go.sum", "--provenance", fx + "/prov.json"],
             ["vendor-provenance.py", "evidence", "--out", out + "-off", "--provenance", fx + "/prov.json", "--govulncheck", fx + "/govuln.json", "--date", "1790000000"]):
    sys.argv = argv
    try:
        runpy.run_path(script, run_name="__main__")
    except SystemExit as e:
        assert e.code in (0, None), (argv[1], e.code)
PY
t AC10 "the script imports only the standard library names it needs and no network or process module" python3 - "$bin_vp" <<'PY'
import re, sys
s = open(sys.argv[1]).read()
imports = set(re.findall(r"^(?:import|from)\s+([A-Za-z_][A-Za-z0-9_]*)", s, re.M))
assert imports <= {"sys", "os", "re", "json", "hashlib", "stat", "datetime"}, imports
assert not re.search(r"os\.environ|os\.getenv|os\.system|^\s*(import|from)\s+(subprocess|socket|urllib|http|ssl|ftplib|smtplib)\b", s, re.M)
PY

# ===== AC11: listable shape =======================================================================
for f in bin/vendor-provenance.py; do
  t AC11 "$f has a shebang and mode 100755 in git" bash -c "[ -e '$f' ] && head -1 '$f' | grep -q '^#!' && git ls-files -s '$f' | grep -q '^100755'"
  t AC11 "$f assigns none of PATH IFS BASH_ENV ENV LD_* PYTHON*" bash -c "[ -e '$f' ] && ! grep -Eq '(^|[^A-Za-z0-9_])(PATH|IFS|BASH_ENV|ENV|LD_[A-Z_]+|PYTHON[A-Z_]*)[+]?=' '$f'"
  t AC11 "$f runs no python3 -c and no here-document interpreter" bash -c "[ -e '$f' ] && ! grep -Eq 'python3? +-c|python3? +-( |$)|<<' '$f'"
  t AC11 "$f builds no command word by substitution" bash -c "[ -e '$f' ] && ! grep -Eq '^[[:space:]]*\\\$\\(' '$f' && ! grep -q '^[[:space:]]*[\`]' '$f'"
done
rc AC11 "vendor-provenance.py exits 2 outside the repository root (valid absolute inputs, so only the directory can refuse)" 2 \
   bash -c "cd '$work' && python3 '$bin_vp' check --vendor-dir '$F7/vendor' --go-sum '$F7/go.sum' --provenance '$F7/prov.json'"
if grep -q "run it from the repository root" "$work/out"; then ok; else bad AC11 "... and the refusal says to run it from the repository root: $(head -c 120 "$work/out")"; fi

# ===== AC12: signs nothing ========================================================================
t AC12 "vendor-provenance.py holds no signing tool, key or signature code" bash -c "[ -e '$bin_vp' ] && ! grep -Eqi 'cosign|gpg|openssl|rsa|sign_|signing|private key' '$bin_vp'"

# ===== AC13: wording ===============================================================================
PHRASE="verified to be the same source the public checksum log records, from the stated upstream commit or tag"
t AC13 "docs/dependencies.md holds the allowed phrase" bash -c "grep -qF '$PHRASE' '$root/docs/dependencies.md'"
wording() { python3 - "$@" <<'PY'
import re, sys
bad = [(p, n) for p in sys.argv[1:] for n, l in enumerate(open(p, errors="replace"), 1)
       if re.search(r"\baudited\b", l, re.I) and re.search(r"dependenc|vendor|module|librar", l, re.I)]
for b in bad: print("forbidden wording at %s:%d" % b)
sys.exit(1 if bad else 0)
PY
}
printf 'Our dependencies are audited.\n' >"$work/w-bad.md"; printf 'We verified the vendored modules.\nThe auditor ran.\n' >"$work/w-good.md"
tn AC13 "the wording rule catches a fixture line" wording "$work/w-bad.md"
t AC13 "the wording rule passes clean fixture lines" wording "$work/w-good.md"
md=(); while IFS= read -r f; do md+=("$root/$f"); done < <(cd "$root" && { ls README.md SECURITY.md; find docs -name '*.md' ! -path docs/quality/traceability.md; } 2>/dev/null)   # the generated traceability page quotes AC13 itself
t AC13 "no public doc calls dependencies audited" wording "${md[@]}"


# ===== AC14: the reviewed origins file fills exactly the modules the module cache has no Origin for ================
f14() { # f14 NAME  (builds a fixture where beta, the pseudo-version, has no Origin in origins.json and is recorded in rec.json)
  local d="$work/f14-$1"; mkfix "$d"
  python3 - "$d" <<'PY'
import json, sys
d = sys.argv[1]
o = json.load(open(d + "/origins.json")); o.pop("example.test/beta@v0.0.0-20191010083416-a7dc8b61c822")
json.dump(o, open(d + "/origins.json", "w"))
json.dump([{"module": "example.test/beta", "version": "v0.0.0-20191010083416-a7dc8b61c822", "url": "https://example.test/beta",
            "commit": "a7dc8b61c822528f973a5e4e7b272055c6fdb43e", "command": "git fetch --depth 1 https://example.test/beta.git a7dc8b61c822528f973a5e4e7b272055c6fdb43e"}],
          open(d + "/rec.json", "w"))
PY
}
b14() { vp build --vendor-dir "$1/vendor" --go-sum "$1/go.sum" --sumdb-record "$1/sumdb.json" --origins "$1/origins.json" --licenses "$1/licenses.json" --recorded-origins "$1/rec.json" --out "$1/out.json"; }
# r14 NAME REGEX 'python code on d (the rec.json list)' : refused with exit 2, naming the cause, nothing written
r14() { local n=$1 re=$2 code=$3 d="$work/f14-$1"; f14 "$n"; [ -e "$bin_vp" ] && mut "$d/rec.json" "$code" 2>/dev/null
        b14 "$d" >"$work/out14" 2>&1; local got=$?
        if [ "$got" = 2 ] && grep -Eq "$re" "$work/out14" && [ ! -e "$d/out.json" ]; then ok; else bad AC14 "build refuses with the cause ($n): exit $got: $(head -c 160 "$work/out14")"; fi; }
f14 ok
t AC14 "a module the cache has no Origin for takes its origin (commit) from the reviewed file" bash -c "python3 '$bin_vp' build --vendor-dir '$work/f14-ok/vendor' --go-sum '$work/f14-ok/go.sum' --sumdb-record '$work/f14-ok/sumdb.json' --origins '$work/f14-ok/origins.json' --licenses '$work/f14-ok/licenses.json' --recorded-origins '$work/f14-ok/rec.json' --out '$work/f14-ok/out.json' && python3 - '$work/f14-ok/out.json' <<'PY'
import json, sys
m = {x['path']: x for x in json.load(open(sys.argv[1]))['modules']}
assert m['example.test/beta']['origin'] == {'url': 'https://example.test/beta', 'commit': 'a7dc8b61c822528f973a5e4e7b272055c6fdb43e'}, m
assert m['example.test/alpha']['origin'] == {'url': 'https://example.test/alpha', 'tag': 'v1.2.3'}
PY"
# every Go pseudo-version form takes a commit (never a tag) and the commit must start with the version's 12-hex revision
for form in "v1.2.4-0.20191010083416-a7dc8b61c822" "v1.2.3-pre.0.20191010083416-a7dc8b61c822" "v2.0.0-20191010083416-a7dc8b61c822+incompatible"; do
  n="pf-$(printf '%s' "$form" | tr -c 'A-Za-z0-9' _)"; d="$work/f14-$n"; mkfix "$d"
  python3 - "$d" "$form" <<'PY'
import json, sys
d, form = sys.argv[1:3]
old = "example.test/beta@v0.0.0-20191010083416-a7dc8b61c822"; new = "example.test/beta@" + form
for f in ("origins.json", "sumdb.json", "licenses.json"):
    x = json.load(open(d + "/" + f)); x[new] = x.pop(old); json.dump(x, open(d + "/" + f, "w"))
s = open(d + "/go.sum").read().replace("v0.0.0-20191010083416-a7dc8b61c822", form); open(d + "/go.sum", "w").write(s)
m = open(d + "/vendor/modules.txt").read().replace("v0.0.0-20191010083416-a7dc8b61c822", form); open(d + "/vendor/modules.txt", "w").write(m)
o = json.load(open(d + "/origins.json")); o.pop(new); json.dump(o, open(d + "/origins.json", "w"))
good = "a7dc8b61c822528f973a5e4e7b272055c6fdb43e"
json.dump([{"module": "example.test/beta", "version": form, "url": "https://example.test/beta", "commit": good, "command": "git fetch --depth 1 https://example.test/beta.git " + good}], open(d + "/rec.json", "w"))
json.dump([{"module": "example.test/beta", "version": form, "url": "https://example.test/beta", "commit": "2" * 40, "command": "x"}], open(d + "/rec-bad.json", "w"))
PY
  t AC14 "pseudo-version form $form: the recorded commit with the matching revision builds, origin has a commit" bash -c "python3 '$bin_vp' build --vendor-dir '$d/vendor' --go-sum '$d/go.sum' --sumdb-record '$d/sumdb.json' --origins '$d/origins.json' --licenses '$d/licenses.json' --recorded-origins '$d/rec.json' --out '$d/out.json' && python3 -c \"import json; m={x['path']:x for x in json.load(open('$d/out.json'))['modules']}; assert set(m['example.test/beta']['origin'])=={'url','commit'}, m\""
  rc AC14 "pseudo-version form $form: a commit that does not start with the revision is refused (exit 2)" 2 python3 "$bin_vp" build --vendor-dir "$d/vendor" --go-sum "$d/go.sum" --sumdb-record "$d/sumdb.json" --origins "$d/origins.json" --licenses "$d/licenses.json" --recorded-origins "$d/rec-bad.json" --out "$d/out2.json"
done
# a tagged prerelease whose text ends like a pseudo-version (no ".0." component) is a TAGGED version: origin {url, tag}
d="$work/f4rc"; mkfix "$d"; RC="v1.2.3-rc.20191010083416-a7dc8b61c822"
sed -i.bak "s/v1\.2\.3/$RC/g" "$d/vendor/modules.txt" "$d/go.sum" "$d/sumdb.json" "$d/origins.json" "$d/licenses.json"
t AC4 "a tagged prerelease that ends like a pseudo-version builds with origin {url, tag}, not a commit" bash -c "python3 '$bin_vp' build --vendor-dir '$d/vendor' --go-sum '$d/go.sum' --sumdb-record '$d/sumdb.json' --origins '$d/origins.json' --licenses '$d/licenses.json' --out '$d/out.json' && python3 -c \"import json; m={x['path']:x for x in json.load(open('$d/out.json'))['modules']}; assert set(m['example.test/alpha']['origin'])=={'url','tag'}, m\" && python3 '$bin_vp' check --vendor-dir '$d/vendor' --go-sum '$d/go.sum' --provenance '$d/out.json'"
f14 tagged
python3 - "$work/f14-tagged" <<'PY'
import json, sys
d = sys.argv[1]
o = json.load(open(d + "/origins.json")); o.pop("example.test/alpha@v1.2.3")
json.dump(o, open(d + "/origins.json", "w"))
r = json.load(open(d + "/rec.json"))
r.append({"module": "example.test/alpha", "version": "v1.2.3", "url": "https://example.test/alpha",
          "commit": "1111111111111111111111111111111111111111", "command": "git ls-remote --tags https://example.test/alpha.git refs/tags/v1.2.3"})
json.dump(r, open(d + "/rec.json", "w"))
PY
t AC14 "a tagged module recorded in the file gets {url, tag: <its version>}" bash -c "python3 '$bin_vp' build --vendor-dir '$work/f14-tagged/vendor' --go-sum '$work/f14-tagged/go.sum' --sumdb-record '$work/f14-tagged/sumdb.json' --origins '$work/f14-tagged/origins.json' --licenses '$work/f14-tagged/licenses.json' --recorded-origins '$work/f14-tagged/rec.json' --out '$work/f14-tagged/out.json' && python3 -c \"import json; m={x['path']:x for x in json.load(open('$work/f14-tagged/out.json'))['modules']}; assert m['example.test/alpha']['origin']=={'url':'https://example.test/alpha','tag':'v1.2.3'}, m\""
r14 not-built   "example\.test/gamma.*(not|build list)"      "d.append(dict(d[0], module='example.test/gamma'))"
r14 prefix      "example\.test/beta.*(prefix|hash|match)"    "d[0]['commit']='2222222222222222222222222222222222222222'"
r14 short       "example\.test/beta.*(40|hex)"               "d[0]['commit']='a7dc8b61c822'"
r14 no-commit   "example\.test/beta.*(commit|40|hex)"        "d[0].pop('commit')"
r14 unknown-key "example\.test/beta.*(field|key)"            "d[0]['note']='x'"
r14 empty-cmd   "example\.test/beta.*command"                "d[0]['command']=''"
r14 http-url    "example\.test/beta.*https"                  "d[0]['url']='http://example.test/beta'"
r14 duplicate   "example\.test/beta.*(twice|duplicate|repeated)" "d.append(dict(d[0]))"
r14 not-a-list  "(list|array)"                               "d={'module': 'example.test/beta'}"
f14 both
python3 - "$work/f14-both" <<'PY'
import json, sys
d = sys.argv[1]
o = json.load(open(d + "/origins.json"))
o["example.test/beta@v0.0.0-20191010083416-a7dc8b61c822"] = {"url": "https://example.test/beta", "commit": "a7dc8b61c822528f973a5e4e7b272055c6fdb43e"}
json.dump(o, open(d + "/origins.json", "w"))
PY
b14 "$work/f14-both" >"$work/out14" 2>&1; got=$?
if [ "$got" = 2 ] && grep -Eq "example\.test/beta.*(Origin|both|cache)" "$work/out14" && [ ! -e "$work/f14-both/out.json" ]; then ok; else bad AC14 "build refuses a module that has an Origin in the cache AND an entry: exit $got: $(head -c 160 "$work/out14")"; fi
f14 gap
python3 - "$work/f14-gap" <<'PY'
import json, sys
json.dump([], open(sys.argv[1] + "/rec.json", "w"))
PY
rc AC14 "a module with no Origin and no entry still refuses (rule 6: no other gap is filled)" 2 python3 "$bin_vp" build --vendor-dir "$work/f14-gap/vendor" --go-sum "$work/f14-gap/go.sum" --sumdb-record "$work/f14-gap/sumdb.json" --origins "$work/f14-gap/origins.json" --licenses "$work/f14-gap/licenses.json" --recorded-origins "$work/f14-gap/rec.json" --out "$work/f14-gap/out.json"
t AC14 "the reviewed file names exactly the two modules the proxy has no Origin for, each with the command that produced it" python3 - "$root/test-evidence/dependency-origins.yaml" <<'PY'
import json, re, sys
e = json.load(open(sys.argv[1]))
assert [(x["module"], x["version"]) for x in e] == [("github.com/beorn7/perks", "v1.0.1"), ("github.com/munnerz/goautoneg", "v0.0.0-20191010083416-a7dc8b61c822")], e
for x in e:
    assert set(x) == {"module", "version", "url", "commit", "command"} and re.fullmatch(r"[0-9a-f]{40}", x["commit"]) and x["command"].startswith("git ") and x["url"].startswith("https://"), x
assert e[1]["commit"].startswith("a7dc8b61c822")
PY

# ===== AC15: bin/vendor-provenance-records.py produces the three record files (the one step that reads the network, through the Go toolchain) =========================
# A fake `go` prints canned `go mod download -json` output; the script copy differs from bin/vendor-provenance-records.py in its GO_TOOL line only.
bin_vr="$root/bin/vendor-provenance-records.py"
CA=a7dc8b61c822528f973a5e4e7b272055c6fdb43e
BETA=v0.0.0-20191010083416-a7dc8b61c822
mkrec() { # mkrec DIR: fixtures plus a records-step copy whose go is the fake at DIR/go
  local d=$1; mkfix "$d"; mkdir -p "$d/bin"
  cp "$bin_vp" "$d/bin/vendor-provenance.py"
  python3 - "$bin_vr" "$d/bin/vendor-provenance-records.py" "$d/go" <<'PY'
import re, sys
src, out, gopath = sys.argv[1:4]
lines = open(src).read().split("\n"); n = 0
for i, ln in enumerate(lines):
    if re.match(r'^GO_TOOL = .*#\s*TEST-SUBST\s*$', ln):
        lines[i] = 'GO_TOOL = "%s"  # TEST-SUBST' % gopath; n += 1
assert n == 1, "expected exactly one GO_TOOL line marked TEST-SUBST, found %d" % n
open(out, "w").write("\n".join(lines))
PY
  cat >"$d/go" <<EOF
#!/bin/bash
{ echo "ARGS \$*"; echo "PWD-HAS-GOMOD \$([ -f go.mod ] && echo yes || echo no)"; for v in GOTOOLCHAIN GOFLAGS GOENV GOWORK GOSUMDB GOPROXY GOPRIVATE GONOSUMDB GONOSUMCHECK GOINSECURE GOVCS GONOPROXY GOFIPS140 GODEBUG; do echo "ENV \$v=\${!v-unset}"; done; } >> "$d/go.log"
/bin/cat "$d/go-out.jsonl"
exit \$(/bin/cat "$d/go-rc" 2>/dev/null || echo 0)
EOF
  chmod +x "$d/go"; : >"$d/go.log"
  cat >"$d/go-out.jsonl" <<EOF
{"Path":"example.test/alpha","Version":"v1.2.3","Sum":"$H1","Origin":{"VCS":"git","URL":"https://example.test/alpha","Ref":"refs/tags/v1.2.3","Hash":"1111111111111111111111111111111111111111"}}
{"Path":"example.test/beta","Version":"$BETA","Sum":"$H2","Origin":{"VCS":"git","URL":"https://example.test/beta","Hash":"$CA"}}
EOF
  echo '[]' >"$d/rec15.json"
}
recs() { # recs DIR [extra args]: run the copy
  local d=$1; shift
  ( cd "$d" && python3 -I "$d/bin/vendor-provenance-records.py" --vendor-dir "$d/vendor" --go-sum "$d/go.sum" --licenses "$d/licenses.json" --recorded-origins "$d/rec15.json" --out-dir "$d/records" "$@" )
}
r15() { # r15 LABEL REGEX MUTATION-CODE-ON-go-out-lines(lines) [FILE]: the step refuses (exit 2) naming the cause and writes nothing
  local n=$1 re=$2 code=$3 f=${4:-go-out.jsonl} d="$work/f15-$1"; mkrec "$d"
  python3 - "$d/$f" "$code" <<'PY'
import json, sys
p, code = sys.argv[1], sys.argv[2]
if p.endswith(".jsonl"):
    lines = [json.loads(x) for x in open(p).read().splitlines() if x.strip()]
    exec(code); open(p, "w").write("\n".join(json.dumps(x) for x in lines) + "\n")
else:
    d = json.load(open(p)); exec(code); json.dump(d, open(p, "w"))
PY
  recs "$d" >"$work/out15" 2>&1; local got=$?
  if [ "$got" = 2 ] && grep -Eq "$re" "$work/out15" && [ ! -e "$d/records" ]; then ok; else bad AC15 "refuses with the cause ($n): exit $got: $(head -c 200 "$work/out15")"; fi; }
if [ ! -f "$bin_vr" ]; then bad AC15 "bin/vendor-provenance-records.py does not exist (RED)"; else
d="$work/f15-ok"; mkrec "$d"
t AC15 "the records step writes the three files and exits 0 on a fully verified, fully reviewed set" recs "$d"
t AC15 "its sumdb record names each module, its go.sum hash, included and sum.golang.org" python3 - "$d/records/sumdb.json" "$H1" "$H2" "$BETA" <<'PY'
import json, sys
s = json.load(open(sys.argv[1])); h1, h2, beta = sys.argv[2:5]
assert s == {"example.test/alpha@v1.2.3": {"hash": h1, "included": True, "log": "sum.golang.org"},
             "example.test/beta@" + beta: {"hash": h2, "included": True, "log": "sum.golang.org"}}, s
PY
t AC15 "its origins hold a tag for the tagged module and a commit for the pseudo-version" python3 - "$d/records/origins.json" "$BETA" "$CA" <<'PY'
import json, sys
o = json.load(open(sys.argv[1])); beta, ca = sys.argv[2:4]
assert o == {"example.test/alpha@v1.2.3": {"url": "https://example.test/alpha", "tag": "v1.2.3"},
             "example.test/beta@" + beta: {"url": "https://example.test/beta", "commit": ca}}, o
PY
t AC15 "its licences are the reviewed file's entries for exactly the vendored modules" python3 - "$d/records/licenses.json" "$d/licenses.json" <<'PY'
import json, sys
assert json.load(open(sys.argv[1])) == json.load(open(sys.argv[2]))
PY
t AC15 "the three files feed bin/vendor-provenance.py build, which writes the provenance" bash -c "cd '$d' && python3 '$bin_vp' build --vendor-dir vendor --go-sum go.sum --sumdb-record records/sumdb.json --origins records/origins.json --licenses records/licenses.json --out out.json && python3 '$bin_vp' check --vendor-dir vendor --go-sum go.sum --provenance out.json"
t AC15 "it never writes dependency-provenance.json itself and writes nothing but the three files" bash -c "test \"\$(ls '$d/records' | tr '\n' ' ')\" = 'licenses.json origins.json sumdb.json ' && ! test -e '$d/dependency-provenance.json'"
d="$work/f15-env"; mkrec "$d"
GOWORK=/tmp/evil.work GOSUMDB=off GOFLAGS=-insecure GOPRIVATE='*' GONOSUMDB='*' GOPROXY=direct GOTOOLCHAIN=go9.9.9 GOENV=/nonexistent GOINSECURE='*' GOVCS=off GONOPROXY='*' recs "$d" >/dev/null 2>&1
for want in "ARGS mod download -json example.test/alpha@v1.2.3 example.test/beta@$BETA" "PWD-HAS-GOMOD yes" "ENV GOTOOLCHAIN=local" "ENV GOFLAGS=" "ENV GOENV=off" "ENV GOWORK=off" "ENV GOSUMDB=sum.golang.org" "ENV GOPROXY=https://proxy.golang.org" "ENV GOPRIVATE=unset" "ENV GONOSUMDB=unset" "ENV GONOSUMCHECK=unset" "ENV GOINSECURE=unset" "ENV GOVCS=unset" "ENV GONOPROXY=unset"; do
  t AC15 "the go call gets: $want (a hostile caller environment changes nothing)" grep -qxF "$want" "$d/go.log"
done
r15 go-error       "alpha.*(boom|cannot be verified)"         "lines[0]['Error'] = 'boom: cannot be verified'"
r15 sum-vs-gosum   "alpha.*go.sum"                            "lines[0]['Sum'] = 'h1:ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ='"
r15 module-missing "beta.*(not|no) .*(download|output|reported)" "lines.pop(1)"
r15 module-twice   "alpha.*(twice|more than once)"            "lines.append(dict(lines[0]))"
r15 extra-module   "example.test/gamma"                       "lines.append({'Path':'example.test/gamma','Version':'v1.0.0','Sum':lines[0]['Sum'],'Origin':lines[0]['Origin']})"
r15 not-git        "alpha.*(git|VCS)"                         "lines[0]['Origin']['VCS'] = 'hg'"
r15 not-https      "alpha.*https"                             "lines[0]['Origin']['URL'] = 'http://example.test/alpha'"
r15 wrong-tag-ref  "alpha.*(ref|tag)"                         "lines[0]['Origin']['Ref'] = 'refs/tags/v9.9.9'"
r15 branch-ref     "alpha.*(ref|tag)"                         "lines[0]['Origin']['Ref'] = 'refs/heads/main'"
r15 pseudo-prefix  "beta.*(commit|prefix)"                    "lines[1]['Origin']['Hash'] = '3' * 40"
r15 pseudo-short   "beta.*(commit|40)"                        "lines[1]['Origin']['Hash'] = 'a7dc8b61c822'"
r15 no-origin-alpha "alpha.*origin"                           "lines[0].pop('Origin')"
r15 no-origin-beta  "beta.*origin"                            "lines[1].pop('Origin')"
r15 no-licence      "alpha.*licen[sc]e"                       "d.pop('example.test/alpha@v1.2.3')" licenses.json
r15 empty-licence   "alpha.*licen[sc]e"                       "d['example.test/alpha@v1.2.3'] = ''" licenses.json
d="$work/f15-dash"; mkrec "$d"
python3 - "$d" <<'PY'
import sys
d = sys.argv[1]
m = open(d + "/vendor/modules.txt").read().replace("# example.test/alpha v1.2.3", "# -x=evil v1.2.3")
open(d + "/vendor/modules.txt", "w").write(m)
PY
rc AC15 "a module path that begins with a dash is refused (exit 2) before the toolchain is run" 2 recs "$d"
t AC15 "... and the toolchain was never run" test ! -s "$d/go.log"
r15 no-sum          "beta.*(Sum|hash)"                        "lines[1].pop('Sum')"
# a module with no Origin is filled only from the reviewed recorded-origins file, as build does
d="$work/f15-rec"; mkrec "$d"
python3 - "$d" "$BETA" "$CA" <<'PY'
import json, sys
d, beta, ca = sys.argv[1:4]
lines = [json.loads(x) for x in open(d + "/go-out.jsonl").read().splitlines()]
lines[1].pop("Origin"); open(d + "/go-out.jsonl", "w").write("\n".join(json.dumps(x) for x in lines) + "\n")
json.dump([{"module": "example.test/beta", "version": beta, "url": "https://example.test/beta", "commit": ca, "command": "git ls-remote https://example.test/beta"}], open(d + "/rec15.json", "w"))
PY
t AC15 "a module the toolchain reports no Origin for is accepted when the reviewed recorded-origins file covers it" recs "$d"
t AC15 "... origins.json then holds only what the toolchain verified, and build applies the reviewed file" bash -c "cd '$d' && python3 -c \"import json; o=json.load(open('records/origins.json')); assert list(o)==['example.test/alpha@v1.2.3'], o\" && python3 '$bin_vp' build --vendor-dir vendor --go-sum go.sum --sumdb-record records/sumdb.json --origins records/origins.json --licenses records/licenses.json --recorded-origins rec15.json --out out.json && python3 '$bin_vp' check --vendor-dir vendor --go-sum go.sum --provenance out.json"
r15 no-origin-uncovered "beta.*(origin|recorded)" "lines[1].pop('Origin')"
d="$work/f15-exists"; mkrec "$d"; mkdir "$d/records"
rc AC15 "an --out-dir that already exists is refused (exit 2) and left untouched" 2 bash -c "cd '$d' && python3 -I '$d/bin/vendor-provenance-records.py' --vendor-dir '$d/vendor' --go-sum '$d/go.sum' --licenses '$d/licenses.json' --out-dir '$d/records'; r=\$?; ls '$d/records' | wc -l | grep -q '^ *0\$' && exit \$r"
d="$work/f15-nogo"; mkrec "$d"; rm "$d/go"
rc AC15 "an absent toolchain is a refusal (exit 2), never a fallback to another go" 2 recs "$d"
d="$work/f15-gorc"; mkrec "$d"; echo 1 >"$d/go-rc"
rc AC15 "a go that exits non-zero is a refusal (exit 2) writing nothing" 2 recs "$d"
t AC15 "... and writes nothing" test ! -e "$d/records"
t AC15 "the production file holds its go as exactly one TEST-SUBST line, the toolchain's fixed install path" bash -c "test \$(grep -c '^GO_TOOL = .*# TEST-SUBST' '$bin_vr') = 1 && grep -q '^GO_TOOL = \"/usr/local/bin/fscache-go/bin/go\"  # TEST-SUBST' '$bin_vr'"
t AC15 "the production file sets no sumdb opt-out and no module-mode flag: no GOSUMDB=off, GONOSUMDB, GOPRIVATE, GOINSECURE or GOFLAGS value" bash -c "! grep -En '\"(GOSUMDB)\": *\"off\"|\"(GONOSUMDB|GOPRIVATE|GOINSECURE|GONOSUMCHECK)\"|-mod=|-insecure' '$bin_vr'"
t AC15 "the production file opens no socket of its own (no urllib, http, socket, ssl, requests): the network is reached only through the Go toolchain" bash -c "! grep -Eq '^ *(import|from) +(urllib|http|socket|ssl|requests)' '$bin_vr'"
t AC15 "bin/vendor-provenance.py is unchanged in kind: still no network, no subprocess, no environment" bash -c "! grep -Eq '^ *(import|from) +(subprocess|socket|urllib|http|ssl|requests)' '$bin_vp'"
fi

echo "vendor-provenance: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
