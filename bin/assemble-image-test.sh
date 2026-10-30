#!/usr/bin/env bash
# proves: REQ-IMAGE-001-AC1, REQ-IMAGE-001-AC2, REQ-IMAGE-001-AC3, REQ-IMAGE-001-AC4, REQ-IMAGE-001-AC5, REQ-IMAGE-001-AC6, REQ-IMAGE-001-AC7, REQ-IMAGE-001-AC8, REQ-IMAGE-001-AC9, REQ-IMAGE-001-AC10, REQ-IMAGE-001-AC11, REQ-IMAGE-001-AC12, REQ-BUILDTOOLS-002-AC1, REQ-BUILDTOOLS-002-AC2, REQ-BUILDTOOLS-002-AC3
# Tests of the PR: apko configs, image assembly, lock and sealed-build proofs, OCI index digest.
# Split mechanically from the original suite: the sections between the markers are copied byte for byte, the harness is
# bin/melange-apko-lib.sh. Every assertion runs offline against PATH stubs; nothing here calls a real sudo, sysctl,
# unshare, melange or apko (the harness refuses to run on a non-Linux host unless the stubs are in front).
. "$(cd "$(dirname "$0")" && pwd)/melange-apko-lib.sh"
cd "$root"
unset GITHUB_ACTIONS   # the suite is the same on a runner (where it is set) and on a workstation
# The production scripts have NO test hook (REQ-IMAGE-001-AC12): the tests below run a COPY of bin/assemble-image.sh in which exactly the lines ending
# in TEST-SUBST are replaced (tool locations, the /work directory, the render directory), inside a FIXTURE REPOSITORY ROOT ($work/air) whose build/
# directory is the real one with the config, the base lock and the two records the test names put in place of the committed ones (REQ-IMAGE-001-AC10:
# the script has no option for them). $AI is the wrapper that does that; $AI_PROD is the production file (static checks read it).
cat >"$work/mkcopy.py" <<'PY'
import re, sys
src, out = sys.argv[1:3]
subst = dict(a.split("=", 1) for a in sys.argv[3:])
seen, res = set(), []
for ln in open(src).read().split("\n"):
    m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=.*#\s*TEST-SUBST", ln)
    if m:
        n = m.group(1)
        if n not in subst: sys.exit("no substitution given for %s" % n)
        seen.add(n); res.append("%s=%s   # TEST-SUBST" % (n, subst[n]))
    else:
        res.append(ln)
if seen != set(subst): sys.exit("substitutions with no TEST-SUBST line: %s" % sorted(set(subst) - seen))
open(out, "w").write("\n".join(res))
PY
AI_PROD="$AI"
air="$work/air"; rm -rf "$air"; mkdir -p "$air/bin"
for f in "$root"/bin/*; do [ "$(basename "$f")" = assemble-image.sh ] || ln -s "$f" "$air/bin/$(basename "$f")"; done
python3 "$work/mkcopy.py" "$AI_PROD" "$air/bin/assemble-image.sh" \
  'HOST_OS=${TEST_HOST_OS:-linux-gnu}' 'PY3=${TEST_PY3:-'"$(command -v python3)"'}' 'SUDO=${TEST_SUDO:-'"$stubs"'/sudo}' 'UNSHARE=${TEST_UNSHARE:-'"$stubs"'/unshare}' \
  'APKO=${TEST_APKO:-'"$stubs"'/apko}' 'BASHBIN='"$(command -v bash)" 'ENVBIN='"$(command -v env)" 'WORKDIR=${TEST_WORKDIR:-/work}' 'RENDER_DIR=${TEST_RENDER_DIR:-}' \
  || { echo "FIXTURE SETUP FAILED: assemble-image copy"; exit 1; }
chmod +x "$air/bin/assemble-image.sh"
cat >"$work/ai.sh" <<WRAP
#!/bin/bash
# the test wrapper of bin/assemble-image.sh: the options the script no longer has become files of the fixture repository root; the work and render
# directories become the copy's substituted variables
air="$air"; root="$root"
OLDPWD_AI=\$(pwd -P)
absp() { case "\$1" in /*) printf '%s' "\$1";; *) printf '%s' "\$OLDPWD_AI/\$1";; esac; }
args=(); cfg=; bl=; ir=; kr=; have_cfg=0; have_bl=0; have_ir=0; have_kr=0; variant=
while [ \$# -gt 0 ]; do
  case "\$1" in
    --apko-config) cfg=\$(absp "\$2"); have_cfg=1; shift 2;;
    --base-lock) bl=\$(absp "\$2"); have_bl=1; shift 2;;
    --index-record) ir=\$(absp "\$2"); have_ir=1; shift 2;;
    --key-record) kr=\$(absp "\$2"); have_kr=1; shift 2;;
    --render-dir) export TEST_RENDER_DIR=\$(absp "\$2"); shift 2;;
    --variant) variant="\$2"; args+=("\$1" "\$2"); shift 2;;
    *) args+=("\$1"); shift;;
  esac
done
[ -z "\${ASSEMBLE_WORK_DIR:-}" ] || export TEST_WORKDIR="\$ASSEMBLE_WORK_DIR"
[ -z "\${FAKE_OS:-}" ] || export TEST_HOST_OS="\$(printf %s "\$FAKE_OS" | tr A-Z a-z)"
rm -rf "\$air/build"; cp -RP "\$root/build" "\$air/build"
put() { rm -f "\$2"; if [ -e "\$1" ] || [ -L "\$1" ]; then cp -P "\$1" "\$2"; fi; }
case "\$variant" in fips) cf=apko-fips.yaml; lk=apko-fips.base.lock.json;; *) cf=apko.yaml; lk=apko.base.lock.json;; esac
[ \$have_cfg = 1 ] && put "\$cfg" "\$air/build/\$cf"
[ \$have_bl = 1 ] && put "\$bl" "\$air/build/locks/\$lk"
[ \$have_ir = 1 ] && put "\$ir" "\$air/build/locks/archive-index.sha256"
[ \$have_kr = 1 ] && put "\$kr" "\$air/build/locks/archive-keys.sha256"
cd "\$air" && exec "$(command -v bash)" bin/assemble-image.sh "\${args[@]}"
WRAP
chmod +x "$work/ai.sh"; AI="$work/ai.sh"
export ImageOS=ubuntu24 ImageVersion=20261004.327.1   # sealed-proof refuses to run without the runner image (rule 42); tests that need it unset say so
# ---- the proofs: copies of lock-proof.sh and sealed-proof.sh (TEST-SUBST lines only) and of build-apk.sh (as bin/build-apk-test.sh does), run by a
# wrapper that builds a per-call fixture repository root: the options the proofs no longer have (--apko-config, --assemble-script, --build-script, the
# forwarded --base-lock/--index-record/--key-record, --recipe) become files and substituted variables of that root. $LP and $SP are the wrappers;
# $LP_PROD and $SP_PROD are the production files (static checks read those).
LP_PROD="$LP"; SP_PROD="$SP"
rm -f "$air/bin/lock-proof.sh" "$air/bin/sealed-proof.sh"   # they are links to the production files: never write through them
rm -f "$air/bin/apko-lock.sh"
python3 "$work/mkcopy.py" "$root/bin/apko-lock.sh" "$air/bin/apko-lock.sh" 'PY3=${TEST_PY3:-'"$(command -v python3)"'}' || { echo "FIXTURE SETUP FAILED: apko-lock copy"; exit 1; }
chmod +x "$air/bin/apko-lock.sh"
python3 "$work/mkcopy.py" "$LP_PROD" "$air/bin/lock-proof.sh" 'HOST_OS=${TEST_HOST_OS:-linux-gnu}' 'PY3=${TEST_PY3:-'"$(command -v python3)"'}' 'SUDO=${TEST_SUDO:-'"$stubs"'/sudo}' \
  'BASHBIN='"$(command -v bash)" \
  || { echo "FIXTURE SETUP FAILED: lock-proof copy"; exit 1; }
python3 "$work/mkcopy.py" "$SP_PROD" "$air/bin/sealed-proof.sh" 'HOST_OS=${TEST_HOST_OS:-linux-gnu}' 'PY3=${TEST_PY3:-'"$(command -v python3)"'}' 'SUDO=${TEST_SUDO:-'"$stubs"'/sudo}' \
  'UNSHARE=${TEST_UNSHARE:-'"$stubs"'/unshare}' 'BASHBIN='"$(command -v bash)" || { echo "FIXTURE SETUP FAILED: sealed-proof copy"; exit 1; }
printf '#!/bin/sh\nif command -v sha256sum >/dev/null 2>&1; then exec sha256sum "$@"; else exec shasum -a 256 "$@"; fi\n' >"$work/sha256sum"; chmod +x "$work/sha256sum"
rm -f "$air/bin/build-apk.sh"
python3 "$work/mkcopy.py" "$root/bin/build-apk.sh" "$air/bin/build-apk.sh" \
  'PY3=${TEST_PY3:-'"$(command -v python3)"'}' 'GIT=${TEST_GIT:-'"$(command -v git)"'}' 'SUDO=${TEST_SUDO:-'"$stubs"'/sudo}' \
  'UNSHARE=${TEST_UNSHARE:-'"$stubs"'/unshare}' 'MELANGE=${TEST_MELANGE:-'"$stubs"'/melange}' 'SEALED_ENV=$TEST_SEALED_ENV' \
  'GO_TOOL=${TEST_GO:-'"$stubs"'/go}' 'SHA256SUM=${TEST_SHA256SUM:-'"$work"'/sha256sum}' 'ENVBIN='"$(command -v env)" \
  'RECIPE_STANDARD=${TEST_RECIPE:-$PWD/build/melange.yaml}' 'RECIPE_FIPS=${TEST_RECIPE:-$PWD/build/melange-fips.yaml}' \
  'FIPS_MODULE=${TEST_FIPS_MODULE:-$PWD/build/locks/fips-module.txt}' \
  || { echo "FIXTURE SETUP FAILED: build-apk copy"; exit 1; }
chmod +x "$air/bin/lock-proof.sh" "$air/bin/sealed-proof.sh" "$air/bin/build-apk.sh" "$air/bin/assemble-image.sh"
cat >"$work/proofwrap.py" <<'PYW'
import json, os, shlex, shutil, subprocess, sys, tempfile
AIR, ROOT, WORK = os.environ["PW_AIR"], os.environ["PW_ROOT"], os.environ["PW_WORK"]
kind, args = sys.argv[1], sys.argv[2:]
cwd = os.getcwd()
hd_cfg = None
ab = lambda p: p if os.path.isabs(p) else os.path.join(cwd, p)
proot = tempfile.mkdtemp(dir=WORK, prefix="proot-")
os.mkdir(proot + "/bin")
for n in os.listdir(AIR + "/bin"):
    os.symlink(os.path.join(AIR, "bin", n), os.path.join(proot, "bin", n))
shutil.copytree(ROOT + "/build", proot + "/build", symlinks=True)
def put(src, dst):
    if os.path.lexists(dst): os.remove(dst)
    if os.path.lexists(src): shutil.copy2(src, dst, follow_symlinks=False)
def put_exe(src, name):
    p = proot + "/bin/" + name
    os.remove(p); shutil.copy2(src, p)
def put_negative_only(src, name, *markers):
    """the stand-in driver runs only in the proof's negative runs (their paths hold MARKER); every other call gets the real copy"""
    real = proot + "/bin/" + name + ".real"
    os.rename(proot + "/bin/" + name, real)
    open(proot + "/bin/" + name, "w").write('#!/bin/bash\nhere=$(cd "$(dirname "$0")" && pwd)\ncase " $* " in %s) exec "%s" "$@";; esac\nexec bash "$here/%s.real" "$@"\n' % ("|".join('*"%s"*' % m for m in markers), ab(src), name))
    os.chmod(proot + "/bin/" + name, 0o755)
def fixture_opts(words, variant):
    """pull the options the assembler no longer has out of WORDS and put them where the fixture root keeps them"""
    cfg, lk = ("apko-fips.yaml", "apko-fips.base.lock.json") if variant == "fips" else ("apko.yaml", "apko.base.lock.json")
    out, i = [], 0
    while i < len(words):
        w = words[i]
        dst = {"--apko-config": "build/" + cfg, "--base-lock": "build/locks/" + lk, "--index-record": "build/locks/archive-index.sha256",
               "--key-record": "build/locks/archive-keys.sha256"}.get(w)
        if dst and i + 1 < len(words):
            put(ab(words[i + 1]), proot + "/" + dst); i += 2
        else:
            out.append(w); i += 1
    return out
def variant_of(words):
    for i, w in enumerate(words):
        if w == "--variant" and i + 1 < len(words): return words[i + 1]
    return "production"
script = {"lp": "lock-proof.sh", "sp": "sealed-proof.sh"}[kind]
out = []
if kind == "lp":
    head, tail = (args[:args.index("--")], args[args.index("--") + 1:]) if "--" in args else (args, [])
    i = 0; hd = []
    while i < len(head):
        if head[i] == "--assemble-script": put_exe(ab(head[i + 1]), "assemble-image.sh"); i += 2
        elif head[i] == "--apko-config": hd_cfg = ab(head[i + 1]); i += 2
        else: hd.append(head[i]); i += 1
    var = variant_of(tail)
    if hd_cfg: put(hd_cfg, proot + "/build/" + ("apko-fips.yaml" if var == "fips" else "apko.yaml"))
    tail = fixture_opts(tail, var)
    out = hd + ["--"] + tail
else:
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--build-script": put_negative_only(args[i + 1], "build-apk.sh", "/src-copy", "/repo-nopkg", "/repo-restored"); i += 2
        elif a == "--assemble-script": put_negative_only(args[i + 1], "assemble-image.sh", "/arch-nopkg"); i += 2
        elif a == "--build-args":
            w = shlex.split(args[i + 1]); j = 0; keep = []
            while j < len(w):
                if w[j] == "--recipe" and j + 1 < len(w): os.environ["TEST_RECIPE"] = ab(w[j + 1]); j += 2
                else: keep.append(w[j]); j += 1
            out += ["--build-args", shlex.join(keep)]; i += 2
        elif a == "--assemble-args":
            w = shlex.split(args[i + 1])
            out += ["--assemble-args", shlex.join(fixture_opts(w, variant_of(w)))]; i += 2
        else:
            out.append(a); i += 1
# the sealed data file of the build-apk copy: the harness's STUB_/FAKE_ variables, as bin/build-apk-test.sh's wrapper writes it
closed = {"PATH": os.environ["PATH"], "HOME": "/root", "LC_ALL": "C"}
for k, v in os.environ.items():
    if k.startswith(("STUB_", "FAKE_")) or k in ("CALLS", "ImageOS", "ImageVersion"): closed[k] = v
json.dump({"closed": closed, "from_environment": ["SOURCE_DATE_EPOCH"]}, open(proot + "/sealed-test.json", "w"))
os.environ["TEST_SEALED_ENV"] = proot + "/sealed-test.json"
if os.environ.get("PW_FIXTURE"):   # the fixture's own config, base lock and records (what --apko-config etc. meant), for the (always production) variant
    put(os.environ["PW_CFG"], proot + "/build/apko.yaml"); put(os.environ["PW_BL"], proot + "/build/locks/apko.base.lock.json")
    put(os.environ["PW_IDX"], proot + "/build/locks/archive-index.sha256"); put(os.environ["PW_KEY"], proot + "/build/locks/archive-keys.sha256")
if os.environ.get("FAKE_OS"): os.environ["TEST_HOST_OS"] = os.environ["FAKE_OS"].lower()
r = subprocess.run([os.environ.get("PW_BASH", "bash"), proot + "/bin/" + script] + out, cwd=proot)
sys.exit(r.returncode)
PYW
for k in lp sp; do
  printf '#!/bin/bash\nexport PW_AIR="%s" PW_ROOT="%s" PW_WORK="%s"\nexec python3 "%s/proofwrap.py" %s "$@"\n' "$air" "$root" "$work" "$work" "$k" >"$work/$k.sh"; chmod +x "$work/$k.sh"
done
LP="$work/lp.sh"; SP="$work/sp.sh"
# ---- begin verbatim sections ----
export FSCACHE_TEST_MODE=1   # the overrides below (--apko-config, --base-lock, --index-record, --key-record, --*-script) work only in test mode
# ---- P5 round 1: the archive's index must be the one recorded in build/locks/archive-index.sha256 (fixture record) ------------------------------------
shaof() { shasum -a 256 "$1" | cut -d' ' -f1; }
keyrec="$work/key.record"; { for k in wolfi-signing.rsa.pub assembly.rsa.pub; do printf '%s sha256:%s\n' "$k" "$(shaof "$fx/keyring/$k")"; done; } >"$keyrec"
idxrec="$work/idx.record"
printf 'x86_64 sha256:%s\naarch64 sha256:%s\n' "$(shaof "$fx/archive/x86_64/APKINDEX.tar.gz")" "$(shaof "$fx/archive/aarch64/APKINDEX.tar.gz")" >"$idxrec"
# (setup copied from a section of another PR's file)
BL="$fx/base.lock.json" FL="$fx/full.lock.json"
# (setup copied from a section of another PR's file)
python3 "$work/lib.py" mutate "$FL" "$work/f-sum.json" datasum tzdata
# (setup copied from a section of another PR's file)
python3 "$work/lib.py" mutate "$FL" "$work/f-extra.json" extra bash
# (setup copied from a section of another PR's file)
python3 "$work/lib.py" mutate "$FL" "$work/f-noapk.json" drop fscache
# (setup copied from a section of another PR's file)
rm -rf "$work/arch-t"; cp -R "$fx/archive" "$work/arch-t"; python3 "$work/lib.py" tamper "$work/arch-t/x86_64/tzdata-2026a-r0.apk"
# (setup copied from a section of another PR's file)
rm -rf "$work/arch-m"; cp -R "$fx/archive" "$work/arch-m"; rm -f "$work/arch-m/aarch64/tzdata-2026a-r0.apk"
# (setup copied from a section of another PR's file)
rm -rf "$work/arch-i"; cp -R "$fx/archive" "$work/arch-i"; rm -f "$work/arch-i/x86_64/APKINDEX.tar.gz"
# (setup copied from a section of another PR's file)
# se <rule> <desc> <exit> <keyword> <cmd...>: exit status exactly <exit> and the message names the reason
# (setup copied from a section of another PR's file)
se() { local ac=$1 d=$2 want=$3 kw=$4; shift 4; $RUNNER "$@"; if [ "$(rc)" = "$want" ] && grep -Eqi -- "$kw" "$work/log"; then ok; else bad "$ac" "$d (exit $(rc), wanted $want naming '$kw')"; fi; }
# (setup copied from a section of another PR's file)
# sx <rule> <desc> <rc-test> <cmd...>: exit status satisfies the test ('ne4' = non-zero, not 4, not 127)
# (setup copied from a section of another PR's file)
sx() { local ac=$1 d=$2 m=$3; shift 3; $RUNNER "$@"; local r; r=$(rc); if [ "$r" != 0 ] && [ "$r" != 4 ] && [ "$r" != 127 ] && toolrun; then ok; else bad "$ac" "$d (exit $r)"; fi; }
t "rule 11" "the drivers never call docker build, buildx or goreleaser" bash -c "test -f '$BA' && test -f '$AI_PROD' && ! grep -Eq 'docker +(buildx|build)|goreleaser' '$BA' '$AI_PROD'"
t "rule 11" "the drivers never use qemu or emulation (each arch builds natively)" bash -c "test -f '$BA' && test -f '$AI_PROD' && ! grep -Eqi 'qemu|binfmt|--platform' '$BA' '$AI_PROD'"
# ===== host guard (owner, Oct 9): no real privileged tool is reachable on a non-Linux host ============================================
for drv in "$BA" "$AI" "$SP" "$LP"; do
  [ -f "$drv" ] || { bad "host guard" "$(basename "$drv") exists"; continue; }
  run_s env FAKE_OS=Darwin SOURCE_DATE_EPOCH=$SDE "$drv" --variant standard --arch x86_64 --version 0.3.0
  if [ "$(rc)" = 2 ] && grep -Eqi 'Linux' "$work/log" && ! grep -Eq '^(sudo|sysctl|unshare|melange|apko) ' "$CALLS"; then ok; else bad "host guard" "$(basename "$drv") exits 2 naming Linux, before any sudo/sysctl/unshare/melange/apko call, on a non-Linux host (exit $(rc))"; fi
done

t "rule 20" "no scanner (syft, trivy, grype, bomber, scout) makes or gates an SBOM in the drivers or the module tool" bash -c "test -f '$BA' && test -f '$AI_PROD' && test -f '$GS' && ! grep -Eqi '\\b(syft|trivy|grype|bomber|cyclonedx|scout)\\b' '$BA' '$AI_PROD' '$GS'"
nogrep "rule 17" "image assembly and lock tooling never reference the release key" 'APK_RELEASE_SIGNING_KEY|release\.rsa( |$|")' "$AI_PROD" "$LK"

# ===== rule 19: signatures are always checked ============================================================================
nogrep "rule 19" "the skip-signatures switches appear in no workflow, recipe, config or driver" 'ignore-signatures|allow-untrusted|--insecure' $root/.github/workflows/*.yml "$root/build/melange.yaml" "$root/build/melange-fips.yaml" "$root/build/apko.yaml" "$root/build/apko-fips.yaml" "$BA" "$AI_PROD" "$LK"   # melange pkg/cli/build.go:86, apko internal/cli/build.go:143 and lock.go:115
t "rule 19" "apko configs carry the Wolfi key and the assembly key (each package checked against the right key)" y apko-keys "$root/build/apko.yaml"
t "rule 19" "apko-fips.yaml: the same two keys" y apko-keys "$root/build/apko-fips.yaml"

# ===== rules 25 26 33 34 38: apko configs ================================================================================
for v in production fips; do
  f="$root/build/apko.yaml"; [ $v = fips ] && f="$root/build/apko-fips.yaml"
  t "rule 25" "[$v] no base image, no include, no debug; declares only baselayout, ca-certificates-bundle, tzdata and our apk" y apko-pkgs "$f" $v
  t "rule 26" "[$v] repositories are exactly /work/archive and /work/melange-repo, no live URL" y apko-repos "$f"
  t "rule 33" "[$v] archs x86_64 and aarch64" y apko-archs "$f"
  t "rule 38" "[$v] uid/gid 65532, /home/nonroot created and owned, work-dir, entrypoint /usr/bin/fscache" y apko-user "$f"
done
t "rule 34" "[fips] no shell package, no shell-fragment, no sh path" y apko-noshell "$root/build/apko-fips.yaml"
t "rule 34" "[production] no shell package, no shell-fragment, no sh path" y apko-noshell "$root/build/apko.yaml"
t "rule 25" "build/apko.yaml and build/apko-fips.yaml differ only in the apk name" bash -c "test -f '$root/build/apko.yaml' && diff <(sed 's/fscache-fips/fscache/' '$root/build/apko-fips.yaml') '$root/build/apko.yaml'"
t "rule 37" "committed base lock (production): v1, every base package for both archs with checksums, archive paths, no fscache, keyring content" python3 "$work/lib.py" lockshape "$root/build/locks/apko.base.lock.json" production
t "rule 37" "committed base lock (fips): the same" python3 "$work/lib.py" lockshape "$root/build/locks/apko-fips.base.lock.json" fips
# ===== assemble-image.sh (rules 25-34, 37, 38b) ==========================================================================
ai_args=(--variant production --version 0.3.0 --archive "$fx/archive" --melange-repo "$fx/melrepo" --keyring-dir "$fx/keyring" --apko-config "$fx/apko.yaml" --base-lock "$BL" --index-record "$idxrec" --key-record "$keyrec")
aif_args=(--variant fips --version 0.3.0 --archive "$fx/archive" --melange-repo "$fx/melrepo-fips" --keyring-dir "$fx/keyring" --apko-config "$fx/apko-fips.yaml" --base-lock "$fx/base-fips.lock.json" --index-record "$idxrec" --key-record "$keyrec")
aie=(env SOURCE_DATE_EPOCH=$SDE STUB_LOCK="$FL" STUB_LOCK_FIPS="$fx/full-fips.lock.json")
# fixed12 [slot=value ...]: w12 = the 12 words of assemble-image.sh in their fixed order
# (--variant V --version X --archive A --melange-repo M --keyring-dir K --out O); a slot named replaces its default.
# Slots: variant version archive melange keyring out (out: a fresh directory unless given).
# After them come the fixture's config, base lock and two records: the wrapper $AI strips these four options and puts
# the files at their committed paths in the fixture root, so the script itself still gets exactly 12 words. A call
# site may append one of them again (e.g. --index-record X): the last one wins.
fixed12() { local variant=production version=0.3.0 archive=$fx/archive melange=$fx/melrepo keyring=$fx/keyring out= kv
  for kv in "$@"; do
    case $kv in
      variant=*|version=*|archive=*|melange=*|keyring=*|out=*) local "$kv";;
      *) echo "fixed12: no slot in '$kv'" >&2; return 1;;
    esac
  done
  [ -n "$out" ] || out=$(mo)
  local cfg=$fx/apko.yaml lock=$BL; [ "$variant" != fips ] || { cfg=$fx/apko-fips.yaml; lock=$fx/base-fips.lock.json; }
  w12=(--variant "$variant" --version "$version" --archive "$archive" --melange-repo "$melange" --keyring-dir "$keyring" --out "$out"
    --apko-config "$cfg" --base-lock "$lock" --index-record "$idxrec" --key-record "$keyrec"); }
# ===== REQ-IMAGE-001-AC12 (rule 1), run-time proof (REQ-BUILDAPK-001-AC9's method): the image assembly runs with a search path that holds only the
# coreutils it uses and a uname that says Linux; the privileged tools are the fixed-path stubs. A tool called by its bare name is not found. ============
IMG_RP_CORE="awk basename cat cp cut dirname find grep head ln ls mkdir mktemp mv rm rmdir sed sort tail tr wc cmp readlink"
rpd="$work/imgrp"; rps="$work/imgrp-stub"; rpw="$work/imgrp-wrap"; mkdir -p "$rpw"
restricted_path_dir "$rpd" $IMG_RP_CORE && ln -s "$stubs/uname" "$rpd/uname" || { echo "FIXTURE SETUP FAILED: image restricted path"; exit 1; }
restricted_path_dir "$rps" $IMG_RP_CORE env python3 openssl chmod date git || { echo "FIXTURE SETUP FAILED: image stub path"; exit 1; }
for w in sudo unshare apko; do restricted_stub_copy "$stubs/$w" "$rpw/$w" "$rps" || { echo "FIXTURE SETUP FAILED: image stub copy $w"; exit 1; }; done
t "AC12" "the restricted directory holds the coreutils and uname and none of python3, sudo, unshare, apko, sha256sum, openssl, git, bash, env" bash -c "
  for n in python3 sudo unshare apko sha256sum shasum openssl git bash env; do [ ! -e '$rpd'/\$n ] || exit 1; done
  for n in $IMG_RP_CORE uname; do [ -x '$rpd'/\$n ] || exit 1; done"
# rp_ai <air> <out> [args...]: the wrapper of that fixture root, started with the restricted search path
rp_wrapper() { sed "s#^air=\"[^\"]*\"#air=\"$1\"#" "$work/ai.sh" >"$2"; chmod +x "$2"; }
rp_ai() { local w=$1 out=$2; shift 2; : >"$CALLS"
  env -i PATH="$rpd" HOME="$work" CALLS="$CALLS" STUB_LIB="$work/lib.py" SOURCE_DATE_EPOCH=$SDE STUB_LOCK="$FL" STUB_LOCK_FIPS="$fx/full-fips.lock.json" \
    TEST_SUDO="$rpw/sudo" TEST_UNSHARE="$rpw/unshare" TEST_APKO="$rpw/apko" "$w" "${ai_args[@]}" --out "$out" "$@" >"$work/rp.log" 2>&1 </dev/null; echo $? >"$work/rp.rc"; }
rp_out=$(mo); rp_ai "$work/ai.sh" "$rp_out"
t "AC12" "assemble-image.sh: the control run with PATH holding only the coreutils completes (exit 0, a digest is written)" bash -c "[ \"\$(cat '$work/rp.rc')\" = 0 ] && [ -s '$rp_out/production.digest' ]"
run_s "${aie[@]}" "$AI" "${ai_args[@]}" --out "$(mo)"; ref_out=$(grep -Eo 'sha256:[0-9a-f]{64}' "$work/log" | head -1)
t "AC12" "assemble-image.sh: it completes exactly as the run with the ordinary search path does (the same image digest)" bash -c "[ -n '$ref_out' ] && [ \"\$(cat '$rp_out/production.digest')\" = '$ref_out' ]"
# call-site mutants: every call of one fixed-path variable written as the bare tool name; the same mutant completes when the tool is on the path
for pair in PY3:python3 SUDO:sudo UNSHARE:unshare; do
  v=${pair%%:*}; tool=${pair##*:}; am="$work/air-mut-$v"; rm -rf "$am"; cp -RP "$air" "$am"
  python3 - "$am/bin/assemble-image.sh" "$v" "$tool" <<'PYM'
import sys
p, v, tool = sys.argv[1:4]
s = open(p).read()
n = s.count('"$%s"' % v)
assert n > 0, v
open(p, "w").write(s.replace('"$%s"' % v, tool))
PYM
  rp_wrapper "$am" "$work/ai-mut-$v.sh"
  mo_=$(mo); rp_ai "$work/ai-mut-$v.sh" "$mo_"
  t "AC12" "assemble-image.sh: with $tool called by its bare name the restricted run fails (exit non-zero, not completed, '$tool' not found)" bash -c "[ \"\$(cat '$work/rp.rc')\" != 0 ] && [ ! -s '$mo_/production.digest' ] && grep -Eqi '$tool.*(not found|No such file)|(not found|No such file).*$tool' '$work/rp.log'"
  rm -rf "$work/rp-open-$v"; restricted_path_dir "$work/rp-open-$v" $IMG_RP_CORE && ln -s "$stubs/uname" "$work/rp-open-$v/uname" \
    && if [ "$tool" = python3 ]; then ln -s "$(command -v python3)" "$work/rp-open-$v/python3"; else ln -s "$rpw/$tool" "$work/rp-open-$v/$tool"; fi
  mo_=$(mo); : >"$CALLS"
  env -i PATH="$work/rp-open-$v" HOME="$work" CALLS="$CALLS" STUB_LIB="$work/lib.py" SOURCE_DATE_EPOCH=$SDE STUB_LOCK="$FL" STUB_LOCK_FIPS="$fx/full-fips.lock.json" \
    TEST_SUDO="$rpw/sudo" TEST_UNSHARE="$rpw/unshare" TEST_APKO="$rpw/apko" "$work/ai-mut-$v.sh" "${ai_args[@]}" --out "$mo_" >"$work/rp.log" 2>&1 </dev/null; echo $? >"$work/rp.rc"
  t "AC12" "assemble-image.sh: with the tool on the search path the same $tool mutant completes (so the restricted path is what makes it fail)" bash -c "[ \"\$(cat '$work/rp.rc')\" = 0 ] && [ -s '$mo_/production.digest' ]"
done
# ---- the two proofs, the same way (review round 3, seat B: "restricted-path proof for lock-proof and sealed-proof, and call-site mutants") ---------------
py_abs=$(command -v python3); git_abs=$(command -v git)
for w in melange go; do restricted_stub_copy "$stubs/$w" "$rpw/$w" "$rps" || { echo "FIXTURE SETUP FAILED: image stub copy $w"; exit 1; }; done
if real_=$(command -v sha256sum 2>/dev/null); then printf '#!/bin/sh\nexec %s "$@"\n' "$real_" >"$rpw/sha256sum"; else printf '#!/bin/sh\nexec %s -a 256 "$@"\n' "$(command -v shasum)" >"$rpw/sha256sum"; fi; chmod +x "$rpw/sha256sum"
rp_lp_args=(--archive "$fx/archive" -- --variant production --version 0.3.0 --melange-repo "$fx/melrepo" --keyring-dir "$fx/keyring")
rp_sp_args=(--probe 'test -z "${FAKE_SEALED:-}"' --source-dir "$src" --archive "$fx/archive" --build-args "--variant standard --arch x86_64 --version 0.3.0 --repo $fx/envrepo --keyring $kr --go-archive $fx/archive/go --melange-lock $fx/melange.lock --recipe $fx/melange.yaml" --assemble-args "--variant production --version 0.3.0 --melange-repo $fx/melrepo --keyring-dir $fx/keyring")
rp_proof() { # <lp|sp> <fixture root> <search path> <out dir>: the proof's wrapper, started by absolute python and bash with the given search path
  local k=$1 a=$2 p=$3 o=$4; local -a args; if [ "$k" = lp ]; then args=("${rp_lp_args[@]}"); else args=("${rp_sp_args[@]}"); fi
  : >"$CALLS"
  # the fixture records and config the assembler reads are the real build/ copy's: put the fixture's in (as the old --apko-config/--*-record options did)
  env -i PATH="$p" HOME="$work" CALLS="$CALLS" STUB_LIB="$work/lib.py" SOURCE_DATE_EPOCH=$SDE STUB_LOCK="$FL" STUB_LOCK_FIPS="$fx/full-fips.lock.json" \
    FAKE_UNAME=x86_64 STUB_REQUIRE_REPO=1 ImageOS=ubuntu24 ImageVersion=20261004.327.1 FSCACHE_ROOT="$root" \
    TEST_SUDO="$rpw/sudo" TEST_UNSHARE="$rpw/unshare" TEST_APKO="$rpw/apko" TEST_MELANGE="$rpw/melange" TEST_GO="$rpw/go" TEST_SHA256SUM="$rpw/sha256sum" \
    TEST_PY3="$py_abs" TEST_GIT="$git_abs" PW_AIR="$a" PW_ROOT="$root" PW_WORK="$work" PW_BASH="$bash_abs" PW_FIXTURE=1 PW_BL="$BL" PW_IDX="$idxrec" PW_KEY="$keyrec" PW_CFG="$fx/apko.yaml" \
    "$py_abs" "$work/proofwrap.py" "$k" --out "$o" "${args[@]}" >"$work/rp.log" 2>&1 </dev/null; echo $? >"$work/rp.rc"; }
bash_abs=$(command -v bash)
for k_ in lp sp; do
  o_=$(mo); rp_proof $k_ "$air" "$rpd" "$o_"
  rec_=lock-proof.json; [ $k_ = sp ] && rec_=sealed-record.json
  t "AC12" "$k_: the proof's control run with PATH holding only the coreutils completes (exit 0, its record is written)" bash -c "{ test \"\$(cat '$work/rp.rc')\" = 0 && test -s '$o_/$rec_'; } || { tail -3 '$work/rp.log'; exit 1; }"
done
for trip_ in lp:PY3:python3 lp:BASHBIN:bash sp:PY3:python3 sp:SUDO:sudo sp:UNSHARE:unshare sp:BASHBIN:bash; do
  k_=${trip_%%:*}; rest_=${trip_#*:}; v_=${rest_%%:*}; tool_=${rest_##*:}
  sc_=lock-proof.sh; [ $k_ = sp ] && sc_=sealed-proof.sh
  am="$work/air-mut-$k_-$v_"; rm -rf "$am"; cp -RP "$air" "$am"; rm -f "$am/bin/$sc_"; cp "$air/bin/$sc_" "$am/bin/$sc_"
  python3 - "$am/bin/$sc_" "$v_" "$tool_" <<'PYM'
import sys
p, v, tool = sys.argv[1:4]
s = open(p).read()
assert s.count('"$%s"' % v) > 0, v
open(p, "w").write(s.replace('"$%s"' % v, tool))
PYM
  o_=$(mo); rp_proof $k_ "$am" "$rpd" "$o_"
  rec_=lock-proof.json; [ $k_ = sp ] && rec_=sealed-record.json
  # the proofs print their own refusal for a tool that is not there (the probe commands' own output is discarded by design), so the evidence is:
  # the run did not complete (non-zero, no record) AND it completes, with a record, when the very same tool is on the search path
  t "AC12" "$sc_: with $tool_ called by its bare name the restricted run does not complete (non-zero, no record, a refusal printed)" bash -c "test \"\$(cat '$work/rp.rc')\" != 0 && test ! -e '$o_/$rec_' && test -s '$work/rp.log'"
  rm -rf "$work/rp-open-$k_-$v_"; restricted_path_dir "$work/rp-open-$k_-$v_" $IMG_RP_CORE && ln -s "$stubs/uname" "$work/rp-open-$k_-$v_/uname" \
    && case $tool_ in python3) ln -s "$py_abs" "$work/rp-open-$k_-$v_/python3";; bash) ln -s "$bash_abs" "$work/rp-open-$k_-$v_/bash";; *) ln -s "$rpw/$tool_" "$work/rp-open-$k_-$v_/$tool_";; esac
  o2_=$(mo); rp_proof $k_ "$am" "$work/rp-open-$k_-$v_" "$o2_"
  t "AC12" "$sc_: with the tool on the search path the same $tool_ mutant completes (so the restricted path is what makes it fail)" bash -c "{ test \"\$(cat '$work/rp.rc')\" = 0 && test -s '$o2_/$rec_'; } || { tail -3 '$work/rp.log'; exit 1; }"
done
[ -z "${P5_RP_ONLY:-}" ] || { echo "image-rp-only: $pass passed, $failn failed"; [ "$failn" -eq 0 ]; exit; }
t "rule 38b" "assemble-image.sh exists and is executable" test -x "$AI"
sd "rule 33" "[production] runs apko build" '^apko build ' "${aie[@]}" "$AI" "${ai_args[@]}" --out "$(mo)"
sd "rule 33" "[fips] runs apko build" '^apko build ' "${aie[@]}" "$AI" "${aif_args[@]}" --out "$(mo)"
for v in production fips; do
  a=("${ai_args[@]}"); [ $v = fips ] && a=("${aif_args[@]}")
  sd "rule 38b" "[$v] the full lock is made under sudo unshare -n (apko lock has no offline flag)" '^sudo .*unshare -n .*apko lock ' "${aie[@]}" "$AI" "${a[@]}" --out "$(mo)"   # apko internal/cli/lock.go:109-116: no --offline
  sd "rule 38b" "[$v] apko build runs under sudo unshare -n" '^sudo .*unshare -n .*apko build ' "${aie[@]}" "$AI" "${a[@]}" --out "$(mo)"
  sd "rule 38b" "[$v] apko build --offline" '^apko build .*--offline' "${aie[@]}" "$AI" "${a[@]}" --out "$(mo)"   # apko internal/cli/build.go:140
  sd "rule 28" "[$v] apko build always has --lockfile (the lock's checksum check is the tamper check)" '^apko build .*--lockfile ' "${aie[@]}" "$AI" "${a[@]}" --out "$(mo)"   # internal/cli/build.go:141
  sd "rule 20" "[$v] apko writes the SBOM (--sbom-path)" '^apko build .*--sbom-path ' "${aie[@]}" "$AI" "${a[@]}" --out "$(mo)"   # internal/cli/build.go:131 (VERIFIED)
  sn "rule 20" "[$v] apko's SBOM is not disabled" '--sbom[ =]false|--sbom=false' "${aie[@]}" "$AI" "${a[@]}" --out "$(mo)"   # build.go:130
  sn "rule 31" "[$v] the config is passed to apko lock and apko build as a bare file name (cwd = the render dir): lock.config.name is that path and must not be random" '^apko (lock|build) [^ ]*/[^ ]*\.yaml' "${aie[@]}" "$AI" "${a[@]}" --out "$(mo)"   # real-run finding Oct 9
  sd "rule 31" "[$v] --build-date from SOURCE_DATE_EPOCH" "^apko build .*--build-date $ISO" "${aie[@]}" "$AI" "${a[@]}" --out "$(mo)"   # build.go:129
  sd "rule 31" "[$v] apko sees SOURCE_DATE_EPOCH too (env wins, pkg/build/build.go:325)" "SOURCE_DATE_EPOCH=$SDE|-E |--preserve-env" "${aie[@]}" "$AI" "${a[@]}" --out "$(mo)"
  sn "rule 26" "[$v] no --repository-append / -r / --build-repository-append: the config's two local repositories only" ' (--repository-append|-r|--build-repository-append|-b) ' "${aie[@]}" "$AI" "${a[@]}" --out "$(mo)"
  sn "rule 26" "[$v] no network address, proxy or ignore-signatures in any call" '://|[Pp][Rr][Oo][Xx][Yy]|ignore-signatures|allow-untrusted' "${aie[@]}" "$AI" "${a[@]}" --out "$(mo)"
  sn "rule 38b" "[$v] no docker, podman, --privileged or container image in any call" 'docker|podman|--privileged|cgr\.dev|@sha256' "${aie[@]}" "$AI" "${a[@]}" --out "$(mo)"
  run_s "${aie[@]}" "$AI" "${a[@]}" --out "$(mo)"
  if [ "$(rc)" = 0 ] && [ "$(grep -c '^apko build ' "$CALLS")" = 1 ] && ! grep -E '^apko build ' "$CALLS" | grep -Eq -- '--arch '; then ok; else bad "rule 33" "[$v] exactly one apko build, no --arch narrowing (both archs in one run)"; fi
  ordered "rule 37" "[$v] the full lock is made before the image is built" '^apko lock ' '^apko build '
  o=$(mo); run_s "${aie[@]}" "$AI" "${a[@]}" --out "$o"
  t "rule 37" "[$v] OUT/$v.full.lock.json is kept (release file)" test -s "$o/$v.full.lock.json"
  t "rule 20" "[$v] the SBOM is written under OUT (stub apko wrote it to the --sbom-path)" bash -c "find '$o' -name 'sbom*' | grep -q ."
  t "rule 30" "[$v] OUT/$v.digest is sha256:<hex>" bash -c "grep -Eq '^sha256:[0-9a-f]{64}\$' '$o/$v.digest'"
  o2=$(mo); run_s "${aie[@]}" "$AI" "${a[@]}" --out "$o2"
  t "rule 37" "[$v] a rebuild makes an identical full lock" bash -c "cmp '$o/$v.full.lock.json' '$o2/$v.full.lock.json'"
  t "rule 31" "[$v] same inputs give the same image digest" bash -c "cmp '$o/$v.digest' '$o2/$v.digest'"
  o3=$(mo); run_s env SOURCE_DATE_EPOCH=$SDE STUB_LOCK="$FL" STUB_LOCK_FIPS="$fx/full-fips.lock.json" STUB_SALT=other "$AI" "${a[@]}" --out "$o3"
  t "rule 31" "[$v] the digest follows the built image (a different image gives a different digest)" bash -c "test -s '$o/$v.digest' && test -s '$o3/$v.digest' && ! cmp -s '$o/$v.digest' '$o3/$v.digest'"
done
sd "rule 33" "the -fips image is assembled from the -fips config" 'apko-fips\.yaml|fscache-fips' "${aie[@]}" "$AI" "${aif_args[@]}" --out "$(mo)"
# the names are in the script, or (straight-line form) in oci-digest.py variant-field
t "rule 25" "assemble-image.sh picks build/apko.yaml for production and build/apko-fips.yaml for fips by default" \
  bash -c "cat '$AI_PROD' '$OD' | grep -q 'apko-fips.yaml' && cat '$AI_PROD' '$OD' | grep -q 'apko.yaml'"
rd2="$work/render2"; mkdir -p "$rd2"
t "rule 25" "--render-dir writes the config with the version, no @FSCACHE_VERSION@ left" bash -c "env SOURCE_DATE_EPOCH=$SDE STUB_LOCK='$FL' PATH='$stubs':\$PATH CALLS='$CALLS' STUB_LIB='$work/lib.py' '$AI' ${ai_args[*]} --render-dir '$rd2' --out $(mo) >/dev/null 2>&1; f=\$(ls '$rd2'/*.yaml | head -1); test -n \"\$f\" && ! grep -q @FSCACHE_VERSION@ \$f && grep -Eq 'fscache=0\\.3\\.0-r0' \$f"
# refusals: nothing may run
sr "rule 31" "assemble refuses without SOURCE_DATE_EPOCH" SOURCE_DATE_EPOCH env STUB_LOCK="$FL" "$AI" "${ai_args[@]}" --out "$(mo)"
sr "rule 31" "assemble refuses a non-numeric SOURCE_DATE_EPOCH" SOURCE_DATE_EPOCH env SOURCE_DATE_EPOCH=never STUB_LOCK="$FL" "$AI" "${ai_args[@]}" --out "$(mo)"
fixed12 archive=https://packages.wolfi.dev/os; sr "rule 26" "assemble refuses an https archive" 'local' "${aie[@]}" "$AI" "${w12[@]}"
sed 's#/work/archive#https://packages.wolfi.dev/os#' "$fx/apko.yaml" >"$work/live.yaml"
sr "rule 26" "assemble refuses a config naming a live repository" 'repositor' "${aie[@]}" "$AI" "${ai_args[@]}" --apko-config "$work/live.yaml" --out "$(mo)"
fixed12 archive="$work/arch-m"; sr "rule 27" "archive missing a package of the base lock -> refuses, names it, no tool run, no fallback" 'tzdata' "${aie[@]}" "$AI" "${w12[@]}"
fixed12 archive="$work/arch-i"; sr "rule 27" "archive missing its APKINDEX -> refuses, names it" 'APKINDEX' "${aie[@]}" "$AI" "${w12[@]}"
rm -rf "$work/mel-m"; cp -R "$fx/melrepo" "$work/mel-m"; rm -f "$work/mel-m"/*/fscache-*.apk
fixed12 melange="$work/mel-m"; sr "rule 27" "melange repo missing the fscache apk -> refuses, names it" 'fscache' "${aie[@]}" "$AI" "${w12[@]}"
fixed12 archive="$work/arch-t"; sr "rule 28" "a tampered archived package is refused at the lock checksum (before the build), named" 'tzdata-2026a-r0' "${aie[@]}" "$AI" "${w12[@]}"
fixed12 keyring="$work/nokeys"; sr "rule 28" "an unknown key (keyring dir without the Wolfi key) is refused" 'key' "${aie[@]}" "$AI" "${w12[@]}"
srb "rule 37" "a full lock whose package entries differ from the base lock stops the build, naming 'differ'" 'differ' env SOURCE_DATE_EPOCH=$SDE STUB_LOCK="$work/f-sum.json" "$AI" "${ai_args[@]}" --out "$(mo)"
srb "rule 37" "a full lock with an extra package stops the build" 'bash|differ' env SOURCE_DATE_EPOCH=$SDE STUB_LOCK="$work/f-extra.json" "$AI" "${ai_args[@]}" --out "$(mo)"
python3 "$work/lib.py" mutate "$FL" "$work/f-arch.json" archver
srb "rule 33" "a full lock that resolves different versions per arch stops the build" 'arch|differ' env SOURCE_DATE_EPOCH=$SDE STUB_LOCK="$work/f-arch.json" "$AI" "${ai_args[@]}" --out "$(mo)"
srb "rule 37" "a full lock without our apk stops the build" 'fscache|differ|missing' env SOURCE_DATE_EPOCH=$SDE STUB_LOCK="$work/f-noapk.json" "$AI" "${ai_args[@]}" --out "$(mo)"
# the lock method proof (rule 36) and the rebuild-from-archive command (rule 30)
lp_args=(--apko-config "$fx/apko.yaml" -- --variant production --version 0.3.0 --melange-repo "$fx/melrepo" --keyring-dir "$fx/keyring" --base-lock "$BL" --index-record "$idxrec" --key-record "$keyrec")
lpo=$(mo); run_s "${aie[@]}" "$LP" --out "$lpo" --archive "$fx/archive" "${lp_args[@]}"
if [ "$(rc)" = 0 ] && python3 - "$lpo/lock-proof.json" <<'P'
import json, sys
d = json.load(open(sys.argv[1])); c = d["cases"]
assert set(c) >= {"missing-package", "missing-index", "tampered-package", "live-packages"}, c
assert all(v["result"] == "failed-as-required" and v["exit"] == 2 for v in c.values()), c   # the record now holds {result, exit, reason} per case
P
then ok; else bad "rule 36" "lock-proof.sh: all four cases (missing package, missing index, tampered package, live packages) fail as required and are recorded"; fi
printf '#!/bin/sh\nexit 0\n' >"$work/alwaysok.sh"; chmod +x "$work/alwaysok.sh"
run_s "${aie[@]}" "$LP" --out "$(mo)" --archive "$fx/archive" --assemble-script "$work/alwaysok.sh" "${lp_args[@]}"
if [ "$(rc)" != 0 ] && [ "$(rc)" != 127 ] && grep -Eqi 'missing-package|did not fail' "$work/log"; then ok; else bad "rule 36" "lock-proof.sh fails when the assembly still succeeds on a bad input (the proof is not vacuous)"; fi

se "rule 40" "[advisor reading] assemble-image.sh: apko attempts a connection in the sealed namespace -> exit 4" 4 'network attempt' env SOURCE_DATE_EPOCH=$SDE STUB_LOCK="$FL" STUB_NETATTEMPT=1 "$AI" "${ai_args[@]}" --out "$(mo)"
run_s env SOURCE_DATE_EPOCH=$SDE STUB_LOCK="$FL" STUB_NETATTEMPT=1 "$AI" "${ai_args[@]}" --out "$(mo)"
if [ "$(rc)" = 4 ] && grep -Eq '^sudo .*unshare -n .*net-probe\.py' "$CALLS"; then ok; else bad "rule 40" "[advisor reading] assemble-image.sh: the probe is called under sudo unshare -n"; fi
sx "rule 40" "[advisor reading] assemble-image.sh: a failure for another reason is non-zero but not 4" ne4 env SOURCE_DATE_EPOCH=$SDE STUB_LOCK="$FL" STUB_FAIL=1 "$AI" "${ai_args[@]}" --out "$(mo)"
sx "rule 40" "[advisor reading] assemble-image.sh: leaky namespace -> non-zero, not 4" ne4 env SOURCE_DATE_EPOCH=$SDE STUB_LOCK="$FL" STUB_NETATTEMPT=1 STUB_UNSHARE_LEAKY=1 "$AI" "${ai_args[@]}" --out "$(mo)"
run_s env SOURCE_DATE_EPOCH=$SDE STUB_LOCK="$FL" "$AI" "${ai_args[@]}" --out "$(mo)"
if [ "$(rc)" = 0 ] && ! grep -q 'net-probe' "$CALLS"; then ok; else bad "rule 40" "assemble-image.sh: success -> exit 0 and no probe"; fi

# ===== rules 30 31 37 (advisor): the image digest is the OCI INDEX digest ==================================================
oc="$fx/oci"
t "rule 31" "oci-digest.py: prints the index digest equal to the sha256 of the index blob in the layout (not of the tar)" bash -c "python3 '$OD' '$oc/good.tar' >'$work/oci.out' && python3 - '$oc/good.tar' '$work/oci.out' <<'P'
import hashlib, json, sys, tarfile
t = tarfile.open(sys.argv[1]); top = json.load(t.extractfile('index.json')); d = top['manifests'][0]['digest']
blob = t.extractfile('blobs/sha256/' + d.split(':')[1]).read()
assert hashlib.sha256(blob).hexdigest() == d.split(':')[1]
first = open(sys.argv[2]).read().splitlines()[0]
assert first == 'index ' + d, first
assert d.split(':')[1] != hashlib.sha256(open(sys.argv[1], 'rb').read()).hexdigest()
P"
t "rule 31" "oci-digest.py: lists the per-arch manifest digests (amd64, arm64) from the index blob" bash -c "python3 '$OD' '$oc/good.tar' | grep -Ec '^(amd64|arm64) sha256:[0-9a-f]{64}\$' | grep -qx 2"
fails "rule 31" "oci-digest.py: a blob whose hash differs from its name is refused and the blob is named" 'blobs/sha256|sha256:[0-9a-f]{8}|mismatch' python3 "$OD" "$oc/tampered.tar"
fails "rule 31" "oci-digest.py: a layout without index.json is refused and says so" 'index\.json' python3 "$OD" "$oc/noindex.tar"
t "rule 31" "oci-digest.py: the real apko tar (blobs named sha256:<hex>, index.json is the index, no oci-layout): the index digest is the sha256 of index.json and both architectures are listed" bash -c "python3 '$OD' '$oc/apko.tar' >'$work/oci2.out' && python3 - '$oc/apko.tar' '$work/oci2.out' <<'P'
import hashlib, sys, tarfile
t = tarfile.open(sys.argv[1]); idx = t.extractfile('index.json').read()
lines = open(sys.argv[2]).read().splitlines()
assert lines[0] == 'index sha256:' + hashlib.sha256(idx).hexdigest(), lines
assert sorted(l.split()[0] for l in lines[1:]) == ['amd64', 'arm64'], lines
P"
fails "rule 31" "oci-digest.py: the real apko tar with a manifest blob that does not hash to its name is refused and the blob is named" 'sha256:[0-9a-f]{8}|mismatch|hash' python3 "$OD" "$oc/apko-tampered.tar"
for v in production fips; do
  a=("${ai_args[@]}"); [ $v = fips ] && a=("${aif_args[@]}")
  o=$(mo); run_s "${aie[@]}" "$AI" "${a[@]}" --out "$o"
  t "rule 31" "[$v] OUT/$v.digest is ONE line and equals the sha256 of the index blob inside the layout directory OUT/$v/, not the sha256 of any file named like a tar" bash -c "test \$(wc -l <'$o/$v.digest') -eq 1 && python3 - '$o/$v' '$o/$v.digest' <<'P'
import hashlib, json, sys
d = json.load(open(sys.argv[1] + '/index.json'))['manifests'][0]['digest']
got = open(sys.argv[2]).read().strip()
assert got == d == 'sha256:' + hashlib.sha256(open(sys.argv[1] + '/blobs/sha256/' + d.split(':')[1], 'rb').read()).hexdigest(), got
P"
  t "rule 31" "[$v] OUT/$v.manifests has one '<arch> sha256:<digest>' line per arch manifest, each present in the index blob of OUT/$v/" bash -c "python3 - '$o/$v' '$o/$v.manifests' <<'P'
import json, sys
d = json.load(open(sys.argv[1] + '/index.json'))['manifests'][0]['digest']
idx = json.load(open(sys.argv[1] + '/blobs/sha256/' + d.split(':')[1]))
want = sorted('%s %s' % (m['platform']['architecture'], m['digest']) for m in idx['manifests'])
got = sorted(open(sys.argv[2]).read().split('\n')[:-1])
assert got == want and len(got) == 2, (got, want)
P"
  o2=$(mo); run_s "${aie[@]}" "$AI" "${a[@]}" --out "$o2"
  t "rule 31" "[$v] a rebuild gives the same index digest and the same manifest list" bash -c "cmp '$o/$v.digest' '$o2/$v.digest' && cmp '$o/$v.manifests' '$o2/$v.manifests'"
  o3=$(mo); run_s env SOURCE_DATE_EPOCH=$SDE STUB_LOCK="$FL" STUB_LOCK_FIPS="$fx/full-fips.lock.json" STUB_SALT=other "$AI" "${a[@]}" --out "$o3"
  t "rule 31" "[$v] a different image changes the index digest and the manifest digests" bash -c "! cmp -s '$o/$v.digest' '$o3/$v.digest' && ! cmp -s '$o/$v.manifests' '$o3/$v.manifests' && test -s '$o/$v.manifests'"
done
sf "rule 31" "assemble-image.sh refuses an image whose blob hash differs from its name (tampered layout)" 'blobs/sha256|mismatch|sha256' env SOURCE_DATE_EPOCH=$SDE STUB_LOCK="$FL" STUB_OCI_TAMPER=1 "$AI" "${ai_args[@]}" --out "$(mo)"
sf "rule 31" "assemble-image.sh refuses an image layout with no index.json" 'index\.json' env SOURCE_DATE_EPOCH=$SDE STUB_LOCK="$FL" STUB_OCI_NOINDEX=1 "$AI" "${ai_args[@]}" --out "$(mo)"

# ===== rules 38a 38b 39 40 41 42: the sealed build proofs =================================================================
sp_common=(--source-dir "$src" --archive "$fx/archive" --build-args "--variant standard --arch x86_64 --version 0.3.0 --repo $fx/envrepo --keyring $kr --go-archive $fx/archive/go --melange-lock $fx/melange.lock --recipe $fx/melange.yaml" --assemble-args "--variant production --version 0.3.0 --melange-repo $fx/melrepo --keyring-dir $fx/keyring --apko-config $fx/apko.yaml --base-lock $BL --index-record $idxrec --key-record $keyrec")
spe=(env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 STUB_LOCK="$FL" STUB_REQUIRE_REPO=1 ImageOS=ubuntu24 ImageVersion=20261004.327.1)
sp1=$(mo); run_s "${spe[@]}" "$SP" --out "$sp1" --probe 'test -z "${FAKE_SEALED:-}"' --digests-out "$work/digests.txt" "${sp_common[@]}"
t "rule 40" "sealed-proof: a probe that cannot get out passes (control reaches outside, blocked inside)" test "$(rc)" = 0
t "rule 42" "sealed-proof: the record says how the network was cut (sudo unshare -n)" bash -c "grep -Eq 'unshare -n' '$sp1/sealed-record.json'"
t "rule 42" "sealed-proof: the record holds the control result (outside reached, inside blocked)" bash -c "python3 - '$sp1/sealed-record.json' <<'P'
import json, sys
d = json.load(open(sys.argv[1])); c = d['control']; assert c['outside'] == 'reached' and c['inside'] == 'blocked', c
P"
t "rule 42" "sealed-proof: the record holds the runner image version (ImageOS, ImageVersion)" bash -c "grep -q ubuntu24 '$sp1/sealed-record.json' && grep -q 20261004.327.1 '$sp1/sealed-record.json'"
t "rule 30" "sealed-proof: the recorded image digests are the OCI index digest and the per-arch manifest digests" bash -c "grep -Eq '^image-production\.digest [0-9a-f]{64}\$' '$work/digests.txt' && grep -Eq '^image-production\.manifests-amd64 [0-9a-f]{64}\$' '$work/digests.txt' && grep -Eq '^image-production\.manifests-arm64 [0-9a-f]{64}\$' '$work/digests.txt'"
t "rule 39" "sealed-proof: digests of the sealed apk and image are recorded" bash -c "grep -Eq '[0-9a-f]{64}' '$work/digests.txt' && grep -q fscache '$work/digests.txt'"
sd "rule 39" "sealed-proof runs the real drivers (a sealed melange build and a sealed apko build happen)" '^melange build .*' "${spe[@]}" "$SP" --out "$(mo)" --probe 'test -z "${FAKE_SEALED:-}"' "${sp_common[@]}"
run_s "${spe[@]}" "$SP" --out "$(mo)" --probe 'test -z "${FAKE_SEALED:-}"' --expect "$work/digests.txt" "${sp_common[@]}"
t "rule 39" "sealed-proof --expect: same digests as the first build -> pass" test "$(rc)" = 0
python3 "$work/lib.py" flipdigest "$work/digests.txt" "$work/digests-bad.txt"
sf "rule 39" "sealed-proof --expect: a different digest fails and says so" 'digest|differ|mismatch' "${spe[@]}" "$SP" --out "$(mo)" --probe 'test -z "${FAKE_SEALED:-}"' --expect "$work/digests-bad.txt" "${sp_common[@]}"
sf "rule 40" "sealed-proof: a probe that gets out (leaky seal) fails the proof" 'reached|escaped|leak|got out' env SOURCE_DATE_EPOCH=$SDE FAKE_UNAME=x86_64 STUB_LOCK="$FL" STUB_UNSHARE_LEAKY=1 "$SP" --out "$(mo)" --probe 'test -z "${FAKE_SEALED:-}"' "${sp_common[@]}"
sf "rule 40" "sealed-proof: a probe that fails outside too is inconclusive (no control) and fails the proof" 'control' "${spe[@]}" "$SP" --out "$(mo)" --probe 'false' "${sp_common[@]}"
sp2=$(mo); run_s "${spe[@]}" "$SP" --out "$sp2" --probe 'test -z "${FAKE_SEALED:-}"' "${sp_common[@]}"
t "rule 41" "sealed-proof: deleting vendor/ makes the sealed build fail, recorded" bash -c "python3 - '$sp2/sealed-record.json' <<'P'
import json, sys
n = json.load(open(sys.argv[1]))['negatives']; assert n['vendor-deleted']['result'] == 'failed-as-required' and 'vendor is missing' in n['vendor-deleted']['reason'], n
P"
t "rule 41" "sealed-proof: deleting one archived package makes the sealed image build fail, recorded" bash -c "python3 - '$sp2/sealed-record.json' <<'P'
import json, sys
n = json.load(open(sys.argv[1]))['negatives']; assert n['package-deleted']['result'] == 'failed-as-required' and n['package-deleted']['reason'], n
P"
sf "rule 41" "sealed-proof: if the build still succeeds without vendor/ the proof fails" 'vendor' "${spe[@]}" "$SP" --out "$(mo)" --probe 'test -z "${FAKE_SEALED:-}"' --build-script "$work/alwaysok.sh" "${sp_common[@]}"
sf "rule 41" "sealed-proof: if the image build still succeeds with a package deleted the proof fails" 'package' "${spe[@]}" "$SP" --out "$(mo)" --probe 'test -z "${FAKE_SEALED:-}"' --assemble-script "$work/alwaysok.sh" "${sp_common[@]}"
t "rule 38a" "the source tree is left untouched by the negative cases (vendor/ still there, after a proof run)" bash -c "test -x '$SP' && test -d '$src/vendor'"


# NOT TESTABLE HERE (need the real tools on a GitHub-hosted ubuntu-24.04 x64/arm64 runner; the proof scripts above are what
# run there, and the assertions above test their logic against stubs):
#  rule 28  a real tampered package failing inside real apko is covered by the lock checksum checks above (the shell pre-checks refuse it before apko
#           runs). UNPROVEN HERE: a wrong or unknown Wolfi KEY failing inside real apko (the index signature check): lock-proof.sh has no key case;
#           the keyring directory is pinned by digest (build/locks/archive-keys.sha256) so a wrong key never reaches apko, but apko's own refusal
#           of a wrongly signed index has not been exercised
#  rule 23  a hostile build step in the real bubblewrap guest cannot read a key (the guest mounts only the workspace, resolv.conf
#           and the cache dir: melange pkg/build/build.go:1020-1040; asserted here only as "Build holds no key")
#  rule 14  that the Linux download and the image binary come out of the same apk (needs the release job); the byte comparison
#           itself is apk-tool binary-check, tested above
#  rule 31  same image digest at any later time on any machine (only one aarch64 host was ever tested; amd64 UNVERIFIED)
#  rule 35  exactly two images and four Linux archives per release (release acceptance, pipeline lane)
#  rule 43  Witness crypto/FIPS fit is a report, not a gate: nothing to assert on the cache
#  rule 62  the VM-direct job and the sysctl step in the workflow (pipeline lane); the driver side is asserted above
# UNVERIFIED tool claims used above: apk-tool's reading of real melange apks (the .melange.yaml control member, the .SIGN.RSA.*
# name) is modelled on package.go:222-231 and the apk format, not on a real apk; "melange build --runner bubblewrap" under
# `sudo unshare -n` with a local repo was proven only for the bwrap leg (spike 2026-10-09-cache-bwrap-runner-spike.md).
# ---- P4 review round 1 (R2): a name-resolution failure inside the sealed apko call is a network attempt too ------------------------------
se "rule 40" "assemble-image.sh: 'Temporary failure in name resolution' from apko in the sealed namespace -> exit 4 (the probe confirms)" 4 'network attempt' env SOURCE_DATE_EPOCH=$SDE STUB_LOCK="$FL" STUB_NETATTEMPT=1 STUB_NETTEXT="Get https://packages.wolfi.dev/os/x86_64/APKINDEX.tar.gz: dial: Temporary failure in name resolution" "$AI" "${ai_args[@]}" --out "$(mo)"

# ---- P5 round 1 (cache-3f): assemble-image.sh refuses an archive whose index is not the recorded one (tests first) ---------------------------------
mkarch() { rm -rf "$1"; cp -R "$fx/archive" "$1"; }   # a copy of the fixture archive (plain index files)
mkversioned() { # <archive dir>: make the index of both archs a digest-named file under index/ with APKINDEX.tar.gz a symlink to it
  local a d sha; for a in x86_64 aarch64; do d="$1/$a"; sha=$(shaof "$d/APKINDEX.tar.gz"); mkdir -p "$d/index"; mv "$d/APKINDEX.tar.gz" "$d/index/APKINDEX-$sha.tar.gz"; ln -s "index/APKINDEX-$sha.tar.gz" "$d/APKINDEX.tar.gz"; done; }
fixed12 archive="$fx/archive"; sd "rule 31" "the recorded index is accepted when the archive holds it as a plain file" '^apko build ' "${aie[@]}" "$AI" "${w12[@]}" --index-record "$idxrec"
mkarch "$work/ia1"; mkversioned "$work/ia1"
fixed12 archive="$work/ia1"; sd "rule 31" "...and when APKINDEX.tar.gz is a symlink to index/APKINDEX-<sha256>.tar.gz holding exactly those bytes" '^apko build ' "${aie[@]}" "$AI" "${w12[@]}" --index-record "$idxrec"
fixed12 archive="$fx/archive"; sr "rule 31" "a missing record file is refused (exit 2, names the index record), no tool run" 'index record .* is missing' "${aie[@]}" "$AI" "${w12[@]}" --index-record "$work/no-such-record"
grep -v '^aarch64' "$idxrec" >"$work/idx.noaarch"
fixed12 archive="$fx/archive"; sr "rule 31" "a record with no line for aarch64 is refused (named, not a traceback)" 'has no line for aarch64' "${aie[@]}" "$AI" "${w12[@]}" --index-record "$work/idx.noaarch"
{ cat "$idxrec"; head -1 "$idxrec"; } >"$work/idx.twice"
fixed12 archive="$fx/archive"; sr "rule 31" "a record with two lines for one architecture is refused (even identical)" 'two lines for x86_64' "${aie[@]}" "$AI" "${w12[@]}" --index-record "$work/idx.twice"
sed 's/sha256:[0-9a-f]*/sha256:zz/' "$idxrec" >"$work/idx.bad"
fixed12 archive="$fx/archive"; sr "rule 31" "a malformed digest in the record is refused" 'malformed line' "${aie[@]}" "$AI" "${w12[@]}" --index-record "$work/idx.bad"
printf 'x86_64 sha256:%s\naarch64 sha256:%s\n' "$(printf other | shasum -a 256 | cut -d' ' -f1)" "$(shaof "$fx/archive/aarch64/APKINDEX.tar.gz")" >"$work/idx.other"
fixed12 archive="$fx/archive"; sr "rule 31" "an archive whose index differs from the recorded digest is refused, naming the architecture and both digests" 'package index for x86_64 .* hashes to' "${aie[@]}" "$AI" "${w12[@]}" --index-record "$work/idx.other"
mkarch "$work/ia2"; mkversioned "$work/ia2"; mkdir -p "$work/outside"; sha=$(shaof "$fx/archive/x86_64/APKINDEX.tar.gz"); cp "$work/ia2/x86_64/index/APKINDEX-$sha.tar.gz" "$work/outside/APKINDEX-$sha.tar.gz"; rm "$work/ia2/x86_64/index/APKINDEX-$sha.tar.gz"; ln -s "$work/outside/APKINDEX-$sha.tar.gz" "$work/ia2/x86_64/index/APKINDEX-$sha.tar.gz"
fixed12 archive="$work/ia2"; sr "rule 31" "the recorded index file being a symlink to a file OUTSIDE the archive (same bytes) is refused" 'symlink' "${aie[@]}" "$AI" "${w12[@]}" --index-record "$idxrec"
mkarch "$work/ia3"; mkversioned "$work/ia3"; sha=$(shaof "$fx/archive/x86_64/APKINDEX.tar.gz"); mv "$work/ia3/x86_64/index/APKINDEX-$sha.tar.gz" "$work/ia3/x86_64/index/other.tar.gz"; rm "$work/ia3/x86_64/APKINDEX.tar.gz"; ln -s index/other.tar.gz "$work/ia3/x86_64/APKINDEX.tar.gz"
fixed12 archive="$work/ia3"; sr "rule 31" "a pointer symlink alone (no index/APKINDEX-<recorded sha256>.tar.gz and no plain file) is refused" 'no .*APKINDEX-|pointer' "${aie[@]}" "$AI" "${w12[@]}" --index-record "$idxrec"
# R3: a rebuild of an OLD tag. The pointer already moved on to a newer index; the record names the old one, which is still in index/. apko must be given the old one.
mkarch "$work/ia7"; mkversioned "$work/ia7"; printf 'a newer signed index' >"$work/ia7/x86_64/index/APKINDEX-newer.tar.gz"; rm "$work/ia7/x86_64/APKINDEX.tar.gz"; ln -s index/APKINDEX-newer.tar.gz "$work/ia7/x86_64/APKINDEX.tar.gz"
rd7="$work/render7"; mkdir -p "$rd7"
fixed12 archive="$work/ia7"; sd "rule 31" "R3: the pointer moved on to a newer index, the record names the older one that is still in index/: the build is accepted" '^apko build ' "${aie[@]}" "$AI" "${w12[@]}" --index-record "$idxrec" --render-dir "$rd7"
t "rule 31" "R3: ...and apko is given the RECORDED index as APKINDEX.tar.gz (the archive view), never the pointer's target" bash -c "cmp '$rd7/archive-view/x86_64/APKINDEX.tar.gz' '$fx/archive/x86_64/APKINDEX.tar.gz' && ! cmp -s '$rd7/archive-view/x86_64/APKINDEX.tar.gz' '$work/ia7/x86_64/index/APKINDEX-newer.tar.gz' && test -L '$rd7/archive-view/x86_64/tzdata-2026a-r0.apk'"
mkarch "$work/ia4"; mkversioned "$work/ia4"; sha=$(shaof "$fx/archive/x86_64/APKINDEX.tar.gz"); printf 'tampered' >"$work/ia4/x86_64/index/APKINDEX-$sha.tar.gz"
fixed12 archive="$work/ia4"; sr "rule 31" "a digest-named index file whose content does not hash to its name is refused" 'hashes to' "${aie[@]}" "$AI" "${w12[@]}" --index-record "$idxrec"
mkarch "$work/ia5"; printf 'a different plain index' >"$work/ia5/aarch64/APKINDEX.tar.gz"
fixed12 archive="$work/ia5"; sr "rule 31" "a plain APKINDEX.tar.gz whose bytes are not the recorded digest is refused" 'package index for aarch64 .* hashes to' "${aie[@]}" "$AI" "${w12[@]}" --index-record "$idxrec"

# ---- P5 round 1 (Opus): B1-B3 and residuals (tests first) ---------------------------------------------------------------------------------------
# AC3 / R8: the /work links are made with ln -sfn, and apko build is told not to detect VCS
sd "rule 26" "assemble makes /work/archive, /work/melange-repo and /work/keyring with sudo ln -sT (no -f: an existing link is an error, not replaced)" '^sudo ln -sT [^ ]+ [/]work/archive$' "${aie[@]}" "$AI" "${ai_args[@]}" --out "$(mo)"
t "rule 26" "...all three links, in the logged calls" bash -c "grep -Eq '^sudo ln -sT [^ ]+ [/]work/melange-repo\$' '$CALLS' && grep -Eq '^sudo ln -sT [^ ]+ [/]work/keyring\$' '$CALLS'"
sd "rule 31" "apko build is given --vcs=false (no VCS URL is detected or embedded)" '^apko build .*--vcs=false' "${aie[@]}" "$AI" "${ai_args[@]}" --out "$(mo)"
# M20: --version is X.Y.Z or X.Y.Z-rc.N, nothing else (it is substituted into the config and the image tag)
# advisor 0393 (Oct 12): exactly the chain's grammar: X.Y.Z, X.Y.Z-rcN (N digits, no leading zero, no dot) and the one snapshot version 0.0.0-rc.1
for v in v0.3.0 0.3 '(devel)' 0.3.0-rc 0.3.0-rc.1 0.3.0-rc01 0.3.0-rc1.2 0.3.0-rc.2 0.0.0-rc.2 0.0.0-rc.01 0.0.0-rc1.1 01.2.3 '0.3.0/x' 'a&b' '0.3.0 ' ' 0.3.0' '0.3.0+x' ''; do
  fixed12 version="$v"; sr "rule 24" "assemble refuses --version '$v'" 'version' "${aie[@]}" "$AI" "${w12[@]}"; done
fixed12 version=0.3.0-rc1; sr "rule 24" "assemble --version 0.3.0-rc1 looks for the apk fscache-0.3.0_rc1-r0.apk (the apk-valid version) in the melange repo" 'fscache-0.3.0_rc1-r0\.apk' "${aie[@]}" "$AI" "${w12[@]}"
fixed12 version=0.0.0-rc.1; sr "rule 24" "assemble --version 0.0.0-rc.1 (the snapshot) looks for the apk fscache-0.0.0_rc1-r0.apk in the melange repo" 'fscache-0.0.0_rc1-r0\.apk' "${aie[@]}" "$AI" "${w12[@]}"
# R10: a SOURCE_DATE_EPOCH too large to be a date is exit 2, not a traceback
sr "rule 31" "assemble refuses a SOURCE_DATE_EPOCH too large to be a date" SOURCE_DATE_EPOCH env STUB_LOCK="$FL" SOURCE_DATE_EPOCH=99999999999999999999 "$AI" "${ai_args[@]}" --out "$(mo)"
# M3 (rule 33): the full lock equals the base lock but one package differs between architectures -> arch-check stops the build
mkarch "$work/ia6"; cp "$work/ia6/aarch64/tzdata-2026a-r0.apk" "$work/ia6/aarch64/tzdata-2026b-r0.apk"
python3 "$work/lib.py" mutate "$BL" "$work/b-arch5.json" archver; python3 "$work/lib.py" mutate "$FL" "$work/f-arch5.json" archver
srb "rule 33" "base and full lock agree entry by entry but tzdata differs between the architectures: arch-check stops the build before apko build, naming the package" 'tzdata' env SOURCE_DATE_EPOCH=$SDE STUB_LOCK="$work/f-arch5.json" "$AI" --variant production --version 0.3.0 --archive "$work/ia6" --melange-repo "$fx/melrepo" --keyring-dir "$fx/keyring" --apko-config "$fx/apko.yaml" --base-lock "$work/b-arch5.json" --index-record "$idxrec" --key-record "$keyrec" --out "$(mo)"
# M4 (rule 28): the full lock is verified against the archive AND the melange repository: a tampered fscache apk is refused after apko lock, before apko build
rm -rf "$work/mel-t"; cp -R "$fx/melrepo" "$work/mel-t"; python3 "$work/lib.py" tamper "$work/mel-t/x86_64/fscache-0.3.0-r0.apk"
fixed12 melange="$work/mel-t"; srb "rule 28" "a tampered fscache apk in the melange repo is caught by verifying the full lock (refused after apko lock, before apko build, naming the apk)" 'fscache-0.3.0-r0\.apk' env SOURCE_DATE_EPOCH=$SDE STUB_LOCK="$FL" "$AI" "${w12[@]}"
# M5 / R5 (test hook ASSEMBLE_WORK_DIR replaces /work for the pre-checks): an existing real directory, or any existing link or lock, is refused
mkdir -p "$work/wd1/archive"
sr "rule 26" "/work/archive exists and is a real directory -> refused, nothing replaced" 'not a symlink|exists' "${aie[@]}" ASSEMBLE_WORK_DIR="$work/wd1" "$AI" "${ai_args[@]}" --out "$(mo)"
mkdir -p "$work/wd2" "$work/wd2-target"; ln -s "$work/wd2-target" "$work/wd2/keyring"
sr "rule 26" "a /work link left by another run (a symlink to a different target) is refused: no two runs share /work" 'another|already|exists' "${aie[@]}" ASSEMBLE_WORK_DIR="$work/wd2" "$AI" "${ai_args[@]}" --out "$(mo)"
mkdir -p "$work/wd3/.assemble.lock"
sr "rule 26" "an assembly lock directory in /work means another run is in progress -> refused" 'another|lock|in progress' "${aie[@]}" ASSEMBLE_WORK_DIR="$work/wd3" "$AI" "${ai_args[@]}" --out "$(mo)"
# M13 (rule 40): only the exact errno 101 confirms a sealed namespace; any other probe result is a leak (exit 1, never 4)
for rc_ in 0 1 111; do
  run_s env SOURCE_DATE_EPOCH=$SDE STUB_LOCK="$FL" STUB_NETATTEMPT=1 STUB_PROBE_RC=$rc_ "$AI" "${ai_args[@]}" --out "$(mo)"
  t "rule 40" "assemble: network text but the probe exits $rc_ (not 101) -> exit 1, never 4" test "$(rc)" = 1
done
# B2: net-probe.py is run for real, with the socket replaced: connected -> 0, ENETUNREACH -> 101, anything else -> its errno
mkdir -p "$work/sockstub"; cat >"$work/sockstub/sitecustomize.py" <<'P'
import errno, os, socket
mode = os.environ.get("NET_STUB_MODE", "")
def connect(self, addr):
    log = os.environ.get("NET_STUB_LOG")
    if log:
        open(log, "a").write("%s %d %d\n" % (repr(addr), int(self.family), int(self.type)))
    if mode == "connect":
        return None
    raise OSError(int(mode), os.strerror(int(mode)))
socket.socket.connect = connect
P
nprc() { PYTHONPATH="$work/sockstub" NET_STUB_MODE=$1 python3 "$NP" >/dev/null 2>&1; echo $?; }
t "rule 40" "net-probe.py really connects: a connect that succeeds exits 0" test "$(nprc connect)" = 0
t "rule 40" "net-probe.py: errno 101 (ENETUNREACH on Linux) exits 101" test "$(nprc 101)" = 101
rm -f "$work/np-dest.log"; PYTHONPATH="$work/sockstub" NET_STUB_MODE=connect NET_STUB_LOG="$work/np-dest.log" python3 "$NP" >/dev/null 2>&1
t "rule 40" "net-probe.py connects to exactly 192.0.2.1 port 9 over an IPv4 stream socket (TEST-NET-1, never routed): the destination, family and type are asserted" python3 -c "
import socket, sys
got = open('$work/np-dest.log').read().split('\n')[:-1]
assert got == [\"('192.0.2.1', 9) %d %d\" % (int(socket.AF_INET), int(socket.SOCK_STREAM))], got
"
t "rule 40" "net-probe.py: errno 111 (ECONNREFUSED) exits 111, not 101" test "$(nprc 111)" = 111
t "rule 40" "net-probe.py: errno 113 (EHOSTUNREACH) exits 113" test "$(nprc 113)" = 113

# ---- P5 round 1 (Opus + Sonnet), group A: the lock passed to apko build, the config path, indexes, keys, OUT, cache dir, classifier (tests first) -----------
sd "rule 37" "apko build is given the FULL lock (production.full.lock.json), not the base lock" '^apko build .*--lockfile [^ ]*production\.full\.lock\.json ' "${aie[@]}" "$AI" "${ai_args[@]}" --out "$(mo)"
t "rule 37" "...and the file given to apko build is the lock apko lock made (it holds our apk; the base lock does not)" bash -c "grep -Eo -- '--lockfile [^ ]+' '$CALLS' | tail -1 | grep -q 'full'"
sd "rule 28" "apko lock and apko build are given a private --cache-dir (a temp directory, not the runner's home)" '^apko lock .*--cache-dir [^ ]*/apko-cache ' "${aie[@]}" "$AI" "${ai_args[@]}" --out "$(mo)"
sd "rule 28" "...apko build too" '^apko build .*--cache-dir [^ ]*/apko-cache ' "${aie[@]}" "$AI" "${ai_args[@]}" --out "$(mo)"
rm -rf "$work/mel-ni"; cp -R "$fx/melrepo" "$work/mel-ni"; rm -f "$work/mel-ni/x86_64/APKINDEX.tar.gz"
fixed12 melange="$work/mel-ni"; sr "rule 27" "a melange repository without its APKINDEX.tar.gz is refused, naming APKINDEX" 'APKINDEX' "${aie[@]}" "$AI" "${w12[@]}"
# compare alone must stop an extra package in the full lock: the extra package is IN the archive, so verify-archive would pass it
mkarch "$work/ia8"; cp "$work/ia8/x86_64/tzdata-2026a-r0.apk" "$work/ia8/x86_64/extra-1.0-r0.apk"; cp "$work/ia8/aarch64/tzdata-2026a-r0.apk" "$work/ia8/aarch64/extra-1.0-r0.apk"
python3 - "$work" "$FL" <<'P'
import json, sys
sys.path.insert(0, sys.argv[1]); import lib
w, fl = sys.argv[1:3]
d = json.load(open(fl))
for a in ("x86_64", "aarch64"):
    raw = open("%s/ia8/%s/extra-1.0-r0.apk" % (w, a), "rb").read(); parts = lib.split(raw)
    d["contents"]["packages"].append(lib.entry("extra", "1.0-r0", a, "/work/archive/%s/extra-1.0-r0.apk" % a, tuple(p[0] for p in ([(b"", b"")] + parts if len(parts) == 2 else parts))))
json.dump(d, open(w + "/f-extra8.json", "w"))
P
fixed12 archive="$work/ia8"; srb "rule 37" "a full lock with one extra package that IS in the archive is stopped by the base-vs-full comparison alone, naming it" 'extra' env SOURCE_DATE_EPOCH=$SDE STUB_LOCK="$work/f-extra8.json" "$AI" "${w12[@]}"
# the exit-4 classifier knows apko's own wording
for txt in "network request blocked in offline mode" "connect: connection refused" "Get \"https://packages.wolfi.dev/os/x86_64/APKINDEX.tar.gz\": no route to host"; do
  se "rule 40" "assemble: apko says '$txt' in the sealed namespace -> exit 4 (the probe confirms)" 4 'network attempt' env SOURCE_DATE_EPOCH=$SDE STUB_LOCK="$FL" STUB_NETATTEMPT=1 STUB_NETTEXT="$txt" "$AI" "${ai_args[@]}" --out "$(mo)"; done
# OUT must be empty or absent: stale files from an earlier run are never mixed with a new result
mkdir -p "$work/out-stale"; : >"$work/out-stale/production.digest"
sr "rule 31" "assemble refuses an --out directory that already holds this variant's files (a stale digest would be mixed into the result)" 'not empty|already|stale' "${aie[@]}" "$AI" "${ai_args[@]}" --out "$work/out-stale"
mkdir -p "$work/out-other"; : >"$work/out-other/fips.digest"; mkdir -p "$work/out-other/fips-sbom"
sd "rule 31" "...but a --out that holds only the OTHER variant's files is fine (the chain builds production and fips into one OUT)" '^apko build ' "${aie[@]}" "$AI" "${ai_args[@]}" --out "$work/out-other"
# the keyring directory is pinned by digest: exactly the two keys, with the recorded bytes
cp -R "$fx/keyring" "$work/kr-bad"; printf 'x' >>"$work/kr-bad/wolfi-signing.rsa.pub"
fixed12 keyring="$work/kr-bad"; sr "rule 19" "a Wolfi key file whose bytes differ from the recorded digest is refused, naming the key" 'wolfi-signing\.rsa\.pub' "${aie[@]}" "$AI" "${w12[@]}"
cp -R "$fx/keyring" "$work/kr-bad2"; printf 'x' >>"$work/kr-bad2/assembly.rsa.pub"
fixed12 keyring="$work/kr-bad2"; sr "rule 19" "an assembly key file whose bytes differ from the recorded digest is refused" 'assembly\.rsa\.pub' "${aie[@]}" "$AI" "${w12[@]}"
cp -R "$fx/keyring" "$work/kr-extra"; cp "$fx/keyring/assembly.rsa.pub" "$work/kr-extra/other.rsa.pub"
fixed12 keyring="$work/kr-extra"; sr "rule 19" "an extra key file in the keyring directory is refused (exactly the two recorded keys)" 'other\.rsa\.pub|extra|unexpected' "${aie[@]}" "$AI" "${w12[@]}"
sr "rule 19" "a missing key record is refused" 'key record' "${aie[@]}" "$AI" "${ai_args[@]}" --key-record "$work/no-such-key-record" --out "$(mo)"
# the overrides of the config, the locks and the records do not exist at all: see the REQ-IMAGE-001-AC10 section at the end

# relative paths on the command line are fine (the script runs from the repository root): they are made absolute before the sealed calls change directory
rel=$(mo); relname=$(basename "$rel"); rm -rf "$rel"
( cd "$air" && relp() { python3 -c 'import os,sys;print(os.path.relpath(sys.argv[1]))' "$1"; } && PATH="$stubs:$PATH" CALLS="$CALLS" STUB_LIB="$work/lib.py" SOURCE_DATE_EPOCH=$SDE STUB_LOCK="$FL" "$AI" --variant production --version 0.3.0 --archive "$(relp "$fx/archive")" --melange-repo "$(relp "$fx/melrepo")" --keyring-dir "$(relp "$fx/keyring")" --apko-config "$(relp "$fx/apko.yaml")" --base-lock "$(relp "$BL")" --index-record "$(relp "$idxrec")" --key-record "$(relp "$keyrec")" --out "$(relp "$work/rel-out-$relname")" >"$work/log" 2>&1; echo $? >"$work/rc" )
t "rule 31" "assemble with RELATIVE paths (archive, repo, keys, config, locks, records, out) works and writes the digest where --out says" bash -c "test \"\$(cat '$work/rc')\" = 0 && test -s '$work/rel-out-$relname/production.digest'"
# ---- P5 round 1 (Opus B1, Sonnet R1/R3, R4, R6, R10), group B: lock-proof, sealed-proof, oci-digest (tests first) ---------------------------------------
# B1: lock-proof must run a POSITIVE control first (the untouched archive must assemble, exit 0), then every bad case must exit exactly 2 with its own reason
mkdir -p "$work/lpjunk"
sf "rule 36" "lock-proof: junk archive and --version NOT-A-VERSION -> every case would die at the version check; the positive control fails first (exit 1, naming the control)" 'control' env "${aie[@]:1}" "$LP" --out "$(mo)" --archive "$fx/archive" --apko-config "$fx/apko.yaml" -- --variant production --version NOT-A-VERSION --melange-repo "$fx/melrepo" --keyring-dir "$fx/keyring" --base-lock "$BL" --index-record "$idxrec" --key-record "$keyrec"
printf '#!/bin/sh\nexit 1\n' >"$work/alwaysfail.sh"; chmod +x "$work/alwaysfail.sh"
sf "rule 36" "lock-proof: an assembly script that always exits 1 fails the positive control (not 'all failed as required')" 'control' "${aie[@]}" "$LP" --out "$(mo)" --archive "$fx/archive" --assemble-script "$work/alwaysfail.sh" "${lp_args[@]}"
printf '#!/bin/sh\nfor a in "$@"; do case "$a" in %s) exit 0;; esac; done\necho boom >&2; exit 2\n' "*/fx/archive" >"$work/boom.sh"; chmod +x "$work/boom.sh"
sf "rule 36" "lock-proof: an assembly script that passes the control but refuses every bad case with the same unrelated message 'boom' fails the proof: the reason must be the case's own" 'reason|boom' "${aie[@]}" "$LP" --out "$(mo)" --archive "$fx/archive" --assemble-script "$work/boom.sh" "${lp_args[@]}"
VICTIM=$(python3 -c 'import json,sys;e=sorted(json.load(open(sys.argv[1]))["contents"]["packages"],key=lambda e:(e["name"],e["architecture"]))[0];print("%s-%s.apk"%(e["name"],e["version"]))' "$BL")
printf '#!/bin/sh\nfor a in "$@"; do case "$a" in %s) exit 0;; esac; done\necho "assemble-image.sh: some reason: %s does not match APKINDEX missing live repository" >&2; exit 1\n' "*/fx/archive" "$VICTIM" >"$work/exit1.sh"; chmod +x "$work/exit1.sh"
sf "rule 36" "lock-proof: a refusal with exit 1 instead of the named refusal exit 2 is not 'failed as required'" 'not the named refusal exit 2' "${aie[@]}" "$LP" --out "$(mo)" --archive "$fx/archive" --assemble-script "$work/exit1.sh" "${lp_args[@]}"
lpo2=$(mo); run_s "${aie[@]}" "$LP" --out "$lpo2" --archive "$fx/archive" "${lp_args[@]}"
t "rule 36" "lock-proof (real assembly): the record holds the positive control, the assembly script path and its sha256, and each case's reason and exit code" bash -c "python3 - '$lpo2/lock-proof.json' '$AI_PROD' <<'P'
import hashlib, json, sys
d = json.load(open(sys.argv[1])); ai = sys.argv[2]
assert d['positive_control'] == 'ok', d
assert d['assemble_script'].endswith('/bin/assemble-image.sh') and d['assemble_script_sha256'] == hashlib.sha256(open(d['assemble_script'], 'rb').read()).hexdigest(), d
assert set(d['cases']) >= {'missing-package', 'missing-index', 'tampered-package', 'live-packages'}, d
for c in d['cases'].values(): assert c['result'] == 'failed-as-required' and c['exit'] == 2 and c['reason'], c
P"
t "rule 36" "lock-proof: the victim is a package of the BASE LOCK (the first by name), and the failure names it" bash -c "python3 - '$lpo2/lock-proof.json' <<'P'
import json, sys
d = json.load(open(sys.argv[1]))['cases']
for c in ('missing-package', 'tampered-package'): assert 'ca-certificates-bundle' in d[c]['reason'], d[c]
P"
mkarch "$work/lp-unrel"; cp "$work/lp-unrel/x86_64/tzdata-2026a-r0.apk" "$work/lp-unrel/x86_64/aaa-unrelated-1-r0.apk"
run_s "${aie[@]}" "$LP" --out "$(mo)" --archive "$work/lp-unrel" "${lp_args[@]}"
t "rule 36" "lock-proof: an unrelated apk that sorts first in the archive is NOT chosen as the victim (the proof damages a package the image uses)" bash -c "test \"\$(cat '$work/rc')\" = 0"
printf 'x' >"$work/lp-unrel/x86_64/aaa-tiny-1-r0.apk"
run_s "${aie[@]}" "$LP" --out "$(mo)" --archive "$work/lp-unrel" "${lp_args[@]}"
t "rule 36" "lock-proof: a tiny apk in the archive never causes a traceback" bash -c "! grep -q Traceback '$work/log'"
# sealed-proof: scripts only in test mode, recorded; unknown runner version refused outside test mode; quoted args; epoch overflow
spo=$(mo); run_s "${spe[@]}" "$SP" --out "$spo" --probe 'test -z "${FAKE_SEALED:-}"' "${sp_common[@]}"
t "rule 42" "sealed-proof: the record names the two real drivers with their sha256 and the archive index used, and has no test-mode field (REQ-IMAGE-001-AC7 d)" bash -c "python3 - '$spo/sealed-record.json' '$BA' '$AI_PROD' <<'P'
import hashlib, json, sys
d = json.load(open(sys.argv[1]))
assert 'test_mode' not in d, d
assert d['build_script'] == 'bin/build-apk.sh' and d['assemble_script'] == 'bin/assemble-image.sh', d
for k in ('build_script_sha256', 'assemble_script_sha256'): assert len(d[k]) == 64, d
assert set(d['archive_index']) == {'x86_64', 'aarch64'} and all(v.startswith('sha256:') for v in d['archive_index'].values()), d
assert d['archive_index_record'] == 'build/locks/archive-index.sha256', d
P"
sf "rule 42" "sealed-proof: with no ImageOS/ImageVersion in the environment the runner version is unknown -> refused outside test mode (rule 42 records the runner image)" 'ImageOS|ImageVersion' env -u FSCACHE_TEST_MODE -u ImageOS -u ImageVersion "${aie[@]}" "$SP" --out "$(mo)" --probe 'test -z "${FAKE_SEALED:-}"' "${sp_common[@]}"
mkdir -p "$work/with space"; cp "$idxrec" "$work/with space/idx.record"
sp_space=(--source-dir "$src" --archive "$fx/archive" --build-args "--variant standard --arch x86_64 --version 0.3.0 --repo $fx/envrepo --keyring $kr --go-archive $fx/archive/go --melange-lock $fx/melange.lock --recipe $fx/melange.yaml" --assemble-args "--variant production --version 0.3.0 --melange-repo $fx/melrepo --keyring-dir $fx/keyring --apko-config $fx/apko.yaml --base-lock $BL --index-record '$work/with space/idx.record' --key-record $keyrec")
run_s "${spe[@]}" "$SP" --out "$(mo)" --probe 'test -z "${FAKE_SEALED:-}"' "${sp_space[@]}"
t "rule 39" "sealed-proof: an argument with a space inside quotes in --assemble-args stays one argument" test "$(rc)" = 0
sr "rule 31" "sealed-proof refuses a SOURCE_DATE_EPOCH too large to be a date" SOURCE_DATE_EPOCH env STUB_LOCK="$FL" SOURCE_DATE_EPOCH=99999999999999999999 ImageOS=ubuntu24 ImageVersion=1 "$SP" --out "$(mo)" --probe 'true' "${sp_common[@]}"
# oci-digest: exactly one index, a platform on every manifest, exactly amd64 + arm64, media types, and './' member names
python3 - "$work" "$fx/oci" <<'P'
import hashlib, io, json, sys, tarfile
sys.path.insert(0, sys.argv[1]); import lib
w, oc = sys.argv[1:3]
def members(path):
    t = tarfile.open(path); return [(m.name, t.extractfile(m).read()) for m in t.getmembers() if m.isfile()]
def put(name, ms): open("%s/%s.tar" % (w, name), "wb").write(lib.tarb(ms))
H = lambda b: hashlib.sha256(b).hexdigest()
# apko-shaped variants
ap = dict(members(oc + "/apko.tar")); idx = json.loads(ap["index.json"]); rest = [(n, d) for n, d in ap.items() if n != "index.json"]
def apko_variant(name, mans):
    put("oci-" + name, rest + [("index.json", json.dumps(dict(idx, manifests=mans)).encode())])
m_amd, m_arm = idx["manifests"]
apko_variant("only-amd", [m_amd]); apko_variant("empty", []); apko_variant("three", [m_amd, m_arm, dict(m_arm, platform={"architecture": "s390x", "os": "linux"})])
apko_variant("noplat", [m_amd, {k: v for k, v in m_arm.items() if k != "platform"}])
apko_variant("dup", [m_amd, m_amd])
put("oci-dotslash", [("./" + n, d) for n, d in members(oc + "/apko.tar")])
# standard-layout variants
g = dict(members(oc + "/good.tar")); top = json.loads(g["index.json"]); idxd = top["manifests"][0]["digest"].split(":")[1]; idxblob = json.loads(g["blobs/sha256/" + idxd])
others = [(n, d) for n, d in g.items() if n not in ("index.json", "blobs/sha256/" + idxd)]
def std_variant(name, blob, toplist=None):
    b = json.dumps(blob).encode(); h = H(b)
    t = {"schemaVersion": 2, "manifests": toplist if toplist is not None else [{"mediaType": "application/vnd.oci.image.index.v1+json", "digest": "sha256:" + h, "size": len(b)}]}
    put("oci-" + name, others + [("blobs/sha256/" + h, b), ("index.json", json.dumps(t).encode())])
std_variant("std-twoidx", idxblob, [top["manifests"][0], top["manifests"][0]])
std_variant("std-noplat", dict(idxblob, manifests=[idxblob["manifests"][0], {k: v for k, v in idxblob["manifests"][1].items() if k != "platform"}]))
std_variant("std-onearch", dict(idxblob, manifests=[idxblob["manifests"][0]]))
std_variant("std-badmedia", dict(idxblob, mediaType="application/x-evil"))
P
for v in only-amd empty three noplat dup std-onearch std-noplat; do
  fails "rule 31" "oci-digest: the variant '$v' (not exactly one amd64 and one arm64 manifest, each with a platform architecture) is refused" 'amd64|arm64|platform|architecture' python3 "$OD" "$work/oci-$v.tar"; done
fails "rule 31" "oci-digest: an index.json that names the index blob twice (standard layout) is refused: exactly one" 'exactly one' python3 "$OD" "$work/oci-std-twoidx.tar"
fails "rule 31" "oci-digest: an index blob with a media type that is not an OCI index is refused" 'media' python3 "$OD" "$work/oci-std-badmedia.tar"
t "rule 31" "oci-digest: members named './index.json', './sha256:<hex>' (a tar written with a leading ./) are read, not a KeyError" bash -c "python3 '$OD' '$work/oci-dotslash.tar' | head -1 | grep -q '^index sha256:'"

# ---- P5 round 3 (Sonnet): sealed-proof's victim, cleanup that never changes the exit status, lock-proof in real mode, oci-digest malformed ---------------
# an unremovable (root-written) cache inside the temp dir must not turn exit 0 into 1, or exit 4 into 1
run_s env SOURCE_DATE_EPOCH=$SDE STUB_LOCK="$FL" STUB_LOCKED_CACHE=1 "$AI" "${ai_args[@]}" --out "$(mo)"
t "rule 40" "assemble: a root-written (unremovable) apko cache in the temp dir does not change a successful exit 0" test "$(rc)" = 0
run_s env SOURCE_DATE_EPOCH=$SDE STUB_LOCK="$FL" STUB_LOCKED_CACHE=1 STUB_NETATTEMPT=1 "$AI" "${ai_args[@]}" --out "$(mo)"
t "rule 40" "assemble: ...nor the network-attempt exit 4" test "$(rc)" = 4
trapok=0
for f in lock-proof sealed-proof release-sign-apks install-build-tools; do
  grep -Eq 'local rc=\$\?' "$root/bin/$f.sh" && grep -Eq 'exit \$rc' "$root/bin/$f.sh" \
    || { trapok=1; echo "no status-preserving trap in $f" >&2; }; done
for f in assemble-image build-apk; do   # that form, or one trap string: errexit off first, no exit in it
  { grep -Eq 'local rc=\$\?' "$root/bin/$f.sh" && grep -Eq 'exit \$rc' "$root/bin/$f.sh"; } \
    || { grep -Eq "^trap 'set [+]e; [^']*' EXIT$" "$root/bin/$f.sh" \
         && ! grep -E "^trap " "$root/bin/$f.sh" | grep -Eq '[^a-z]exit[^a-z]'; } \
    || { trapok=1; echo "no status-preserving trap in $f" >&2; }; done
t "rule 40" "every script's EXIT trap preserves the exit status (it captures it, cannot fail, and exits with it)" test "$trapok" = 0
# sealed-proof deletes a package of the BASE LOCK (not the first apk in sorted order) and each negative needs its own reason
mkarch "$work/sp-unrel"; cp "$work/sp-unrel/x86_64/tzdata-2026a-r0.apk" "$work/sp-unrel/x86_64/aaa-unrelated-1-r0.apk"
sp_unrel=("${sp_common[@]}"); for i in "${!sp_unrel[@]}"; do [ "${sp_unrel[$i]}" = "$fx/archive" ] && sp_unrel[$i]="$work/sp-unrel"; done
run_s "${spe[@]}" "$SP" --out "$(mo)" --probe 'test -z "${FAKE_SEALED:-}"' "${sp_unrel[@]}"
t "rule 41" "sealed-proof: an unrelated apk sorting first in the archive does not become the victim: the proof deletes a base-lock package and passes" bash -c "test \"\$(cat '$work/rc')\" = 0"
printf '#!/bin/sh\necho boom >&2\nexit 2\n' >"$work/boom2.sh"; chmod +x "$work/boom2.sh"
sf "rule 41" "sealed-proof: a vendor-less build that fails for an UNRELATED reason does not prove rule 41 (its message must name vendor)" 'reason|vendor' "${spe[@]}" "$SP" --out "$(mo)" --probe 'test -z "${FAKE_SEALED:-}"' --build-script "$work/boom2.sh" "${sp_common[@]}"
sf "rule 41" "sealed-proof: an image build that fails for an UNRELATED reason with a package deleted does not prove rule 41 (its message must name the package)" 'reason|package' "${spe[@]}" "$SP" --out "$(mo)" --probe 'test -z "${FAKE_SEALED:-}"' --assemble-script "$work/boom2.sh" "${sp_common[@]}"
# the sudo control: a probe that works as the user must also work under sudo, otherwise a failure inside unshare proves nothing
sf "rule 40" "sealed-proof: a probe that succeeds as the user but fails under plain sudo (control) fails the proof naming sudo" 'sudo' env ONLY_OUTSIDE=1 "${spe[@]}" "$SP" --out "$(mo)" --probe 'test -n "${ONLY_OUTSIDE:-}"' "${sp_common[@]}"
run_s "${spe[@]}" "$SP" --out "$(mo)" --probe 'test -z "${FAKE_SEALED:-}"' "${sp_common[@]}"
t "rule 40" "sealed-proof: the control order is outside, then sudo bash -c, then sudo unshare -n bash -c" bash -c "a=\$(grep -n '^sudo [^ ]*bash -c' '$CALLS' | head -1 | cut -d: -f1); b=\$(grep -n '^sudo .*unshare -n [^ ]*bash -c' '$CALLS' | head -1 | cut -d: -f1); test -n \"\$a\" && test -n \"\$b\" && test \"\$a\" -lt \"\$b\""
# lock-proof: the missing-index case removes the recorded named index too; it never writes through a symlinked victim; it hands the assembler no overrides it does not need
mkarch "$work/lp-ver"; mkversioned "$work/lp-ver"
run_s "${aie[@]}" "$LP" --out "$(mo)" --archive "$work/lp-ver" "${lp_args[@]}"
t "rule 36" "lock-proof on an archive whose index is index/APKINDEX-<sha256> plus a pointer: all four cases still hold (the missing-index case removes both)" test "$(rc)" = 0
mkarch "$work/lp-link"; v="$work/lp-link/x86_64/ca-certificates-bundle-20260909-r2.apk"
python3 - "$work/lp-link" "$BL" <<'P'
import json, os, sys
a, bl = sys.argv[1:3]
e = sorted(json.load(open(bl))["contents"]["packages"], key=lambda e: (e["name"], e["architecture"]))[0]
p = "%s/%s/%s-%s.apk" % (a, e["architecture"], e["name"], e["version"])
real = p + ".real"; os.rename(p, real); os.symlink(os.path.basename(real), p)
P
run_s "${aie[@]}" "$LP" --out "$(mo)" --archive "$work/lp-link" "${lp_args[@]}"
t "rule 36" "lock-proof: a symlinked victim in the archive is never written through: the proof refuses naming symlink, the real file is unchanged" bash -c "test \"\$(cat '$work/rc')\" != 0 && grep -qi symlink '$work/log' && for r in \$(cd '$work/lp-link' && find . -name '*.real'); do cmp -s \"$work/lp-link/\$r\" \"$fx/archive/\${r%.real}\" || exit 1; done"
cat >"$work/argvlog.sh" <<'S'
#!/bin/sh
ARCHDIR=; p=; for a in "$@"; do [ "$p" = --archive ] && ARCHDIR=$a; p=$a; done
echo "$@" >>"$ARGV_LOG"
if grep -q "packages.wolfi.dev" build/apko.yaml 2>/dev/null; then echo "assemble-image.sh: the config names a live repository or address" >&2; exit 2; fi
for a in "$@"; do case "$a" in */lp-archive-ok) exit 0;; esac; done
case " $* " in *a-missing-package*) echo "apko-lock.sh: $VICTIM is not in the archive" >&2; exit 2;; *a-missing-index*) echo "assemble-image.sh: $ARCHDIR/x86_64/APKINDEX.tar.gz is missing" >&2; exit 2;; *a-tampered*) echo "apko-lock.sh: $VICTIM: data section does not match the lock" >&2; exit 2;; esac
exit 0
S
chmod +x "$work/argvlog.sh"; cp -R "$fx/archive" "$work/lp-archive-ok"
rm -f "$work/argv.log"; VICTIM=$(python3 -c 'import json,sys;e=sorted(json.load(open(sys.argv[1]))["contents"]["packages"],key=lambda e:(e["name"],e["architecture"]))[0];print("%s-%s.apk"%(e["name"],e["version"]))' "$BL"); lpo4=$(mo); run_s env VICTIM="$VICTIM" ARGV_LOG="$work/argv.log" "$LP" --out "$lpo4" --archive "$work/lp-archive-ok" --assemble-script "$work/argvlog.sh" -- --variant production --version 0.3.0 --melange-repo "$fx/melrepo" --keyring-dir "$fx/keyring" --base-lock "$BL"
t "rule 36" "lock-proof: the assembler is never given --apko-config (the live-packages case changes the config of its own repository root copy), and the record says which case used an override" bash -c "test \"\$(cat '$work/rc')\" = 0 && ! grep -q -- '--apko-config' '$work/argv.log' && python3 -c \"import json,glob,sys; d=json.load(open('$lpo4/lock-proof.json')); assert d['override_cases']==['live-packages'], d\""
cat >"$work/idxcheck.sh" <<'S'
#!/bin/sh
ARCHDIR=; p=; for a in "$@"; do [ "$p" = --archive ] && ARCHDIR=$a; p=$a; done
# refuses a bad case only if the case really lacks the index: the pointer AND every named index must be gone for "a-missing-index"
all="$*"
arch=
while [ $# -gt 0 ]; do [ "$1" = --archive ] && arch=$2; shift; done
if grep -q "packages.wolfi.dev" build/apko.yaml 2>/dev/null; then echo "assemble-image.sh: the config names a live repository" >&2; exit 2; fi
case "$arch" in
  *a-missing-index*) for d in "$arch"/x86_64/ "$arch"/aarch64/; do if [ ! -e "$d/APKINDEX.tar.gz" ] && [ ! -L "$d/APKINDEX.tar.gz" ] && ! ls "$d"index/APKINDEX-* >/dev/null 2>&1; then echo "assemble-image.sh: $ARCHDIR/x86_64/APKINDEX.tar.gz is missing" >&2; exit 2; fi; done; exit 0;;
  *a-missing-package*) echo "apko-lock.sh: $VICTIM is not in the archive" >&2; exit 2;;
  *a-tampered*) echo "apko-lock.sh: $VICTIM: data section does not match the lock" >&2; exit 2;;
esac
exit 0
S
chmod +x "$work/idxcheck.sh"
run_s env VICTIM="$VICTIM" "$LP" --out "$(mo)" --archive "$work/lp-ver" --assemble-script "$work/idxcheck.sh" -- --variant production --version 0.3.0 --melange-repo "$fx/melrepo" --keyring-dir "$fx/keyring" --base-lock "$BL"
t "rule 36" "lock-proof: the missing-index case removes the named index/APKINDEX-<sha256> files as well as the pointer (an assembler that only needs the named file would otherwise accept it)" test "$(cat "$work/rc")" = 0
# oci-digest: malformed entries and the config and layer blobs
python3 - "$work" "$fx/oci" <<'P'
import hashlib, json, sys, tarfile
sys.path.insert(0, sys.argv[1]); import lib
w, oc = sys.argv[1:3]
t = tarfile.open(oc + "/apko.tar"); ap = {m.name: t.extractfile(m).read() for m in t.getmembers() if m.isfile()}
idx = json.loads(ap["index.json"]); rest = [(n, d) for n, d in ap.items() if n != "index.json"]
def put(name, ms): open("%s/%s.tar" % (w, name), "wb").write(lib.tarb(ms))
put("oci-nodigest", rest + [("index.json", json.dumps(dict(idx, manifests=[{k: v for k, v in idx["manifests"][0].items() if k != "digest"}, idx["manifests"][1]])).encode())])
man = json.loads(ap["sha256:" + idx["manifests"][0]["digest"].split(":")[1]])
bad = dict(man, config=dict(man["config"], digest="sha256:" + "0" * 64))
bh = hashlib.sha256(json.dumps(bad).encode()).hexdigest()
m0 = dict(idx["manifests"][0], digest="sha256:" + bh)
put("oci-badcfg", [(n, d) for n, d in rest if n != "sha256:" + idx["manifests"][0]["digest"].split(":")[1]] + [("sha256:" + bh, json.dumps(bad).encode()), ("index.json", json.dumps(dict(idx, manifests=[m0, idx["manifests"][1]])).encode())])
P
fails "rule 31" "oci-digest: a manifest entry without a digest is a named refusal, not a traceback" 'digest' python3 "$OD" "$work/oci-nodigest.tar"
t "rule 31" "...and no traceback" bash -c "! python3 '$OD' '$work/oci-nodigest.tar' 2>&1 | grep -q Traceback"
fails "rule 31" "oci-digest: a manifest whose config blob is missing or does not hash to its name is refused" 'config|missing|hash' python3 "$OD" "$work/oci-badcfg.tar"
t "rule 31" "...and it is a named refusal, not a traceback" bash -c "! python3 '$OD' '$work/oci-badcfg.tar' 2>&1 | grep -q Traceback"

# ---- P5 round 3 (Opus + Sonnet): test hooks gated, render dir, containment, cleanup, claim race, oci duplicates, lock-proof inputs ----------------------------
# the render directory must be empty and not a symlink, so nothing planted in it is used or written through
mkdir -p "$work/rd-planted"; : >"$work/rd-planted/apko.yaml"
fixed12 archive="$fx/archive"; sr "rule 25" "a --render-dir that is not empty is refused (a planted file would be written through or kept)" 'render' "${aie[@]}" "$AI" "${w12[@]}" --index-record "$idxrec" --render-dir "$work/rd-planted"
mkdir -p "$work/rd-real"; ln -s "$work/rd-real" "$work/rd-link"
fixed12 archive="$fx/archive"; sr "rule 25" "a --render-dir that is a symlink is refused" 'render|symlink' "${aie[@]}" "$AI" "${w12[@]}" --index-record "$idxrec" --render-dir "$work/rd-link"
# every path component of the archive is contained: arch directory, index directory, the keyring files
mkarch "$work/ic1"; mkversioned "$work/ic1"; mkdir -p "$work/ic-out"; cp -R "$work/ic1/x86_64/index" "$work/ic-out/index"; rm -rf "$work/ic1/x86_64/index"; ln -s "$work/ic-out/index" "$work/ic1/x86_64/index"
fixed12 archive="$work/ic1"; sr "rule 31" "an index/ directory that is a symlink out of the archive is refused (every component is contained, not just the last)" 'symlink|outside' "${aie[@]}" "$AI" "${w12[@]}" --index-record "$idxrec"
mkarch "$work/ic2"; mv "$work/ic2/aarch64" "$work/ic-out/aarch64"; ln -s "$work/ic-out/aarch64" "$work/ic2/aarch64"
fixed12 archive="$work/ic2"; sr "rule 31" "an architecture directory that is a symlink out of the archive is refused" 'symlink|outside' "${aie[@]}" "$AI" "${w12[@]}" --index-record "$idxrec"
cp -R "$fx/keyring" "$work/kr-link"; cp "$fx/keyring/wolfi-signing.rsa.pub" "$work/kr-real.pub"; rm "$work/kr-link/wolfi-signing.rsa.pub"; ln -s "$work/kr-real.pub" "$work/kr-link/wolfi-signing.rsa.pub"
fixed12 keyring="$work/kr-link"; sr "rule 19" "a key file that is a symlink is refused (the keyring files must be regular files in the directory)" 'symlink|regular' "${aie[@]}" "$AI" "${w12[@]}"
printf 'this is not a key record line\n' >>"$work/key.bad"; cat "$keyrec" "$work/key.bad" >"$work/key.garbage"
sr "rule 19" "an unparseable line in the key record is refused, not skipped" 'malformed|repeated' "${aie[@]}" "$AI" "${ai_args[@]}" --key-record "$work/key.garbage" --out "$(mo)"
# the claim on /work is atomic: if the lock directory cannot be created (another run won the race) the run stops, makes no links and removes nothing
sr "rule 26" "a lost race for the /work lock (sudo mkdir fails) is refused, naming the other assembly" 'another assembly' "${aie[@]}" STUB_SUDO_FAIL_MKDIR=1 "$AI" "${ai_args[@]}" --out "$(mo)"
t "rule 26" "...and a run that never made a link removes none (no sudo rm in the calls)" bash -c "! grep -q '^sudo rm' '$CALLS' && ! grep -q '^sudo ln' '$CALLS'"
run_s "${aie[@]}" "$AI" "${ai_args[@]}" --out "$(mo)"
t "rule 26" "a successful run removes exactly the three links and the lock directory it made" bash -c "grep -q '^sudo rm -f /work/archive /work/melange-repo /work/keyring\$' '$CALLS' && grep -q '^sudo rmdir /work/.assemble.lock\$' '$CALLS'"
fixed12 keyring="$work/kr-bad"; run_s "${aie[@]}" "$AI" "${w12[@]}"
t "rule 26" "a run refused before the claim (bad keys) calls no sudo rm at all (cleanup is conditional on what this run made)" bash -c "! grep -q '^sudo rm' '$CALLS'"
# oci-digest: duplicate members, a manifest with another media type, no silent last-one-wins
python3 - "$work" "$fx/oci" <<'P'
import json, sys, tarfile
sys.path.insert(0, sys.argv[1]); import lib
w, oc = sys.argv[1:3]
t = tarfile.open(oc + "/apko.tar"); ms = [(m.name, t.extractfile(m).read()) for m in t.getmembers() if m.isfile()]
open(w + "/oci-dup.tar", "wb").write(lib.tarb(ms + [("./index.json", dict(ms)["index.json"])]))
open(w + "/oci-dup2.tar", "wb").write(lib.tarb(ms + [("index.json", b"{}")]))
import hashlib
g = tarfile.open(oc + "/good.tar"); gm = {m.name: g.extractfile(m).read() for m in g.getmembers() if m.isfile()}
top = json.loads(gm["index.json"]); d = top["manifests"][0]["digest"].split(":")[1]; idx = json.loads(gm["blobs/sha256/" + d])
idx["manifests"][0]["mediaType"] = "application/x-evil"
b = json.dumps(idx).encode(); h = hashlib.sha256(b).hexdigest()
others = [(n, v) for n, v in gm.items() if n not in ("index.json", "blobs/sha256/" + d)]
top["manifests"][0] = dict(top["manifests"][0], digest="sha256:" + h, size=len(b))
open(w + "/oci-badmanmedia.tar", "wb").write(lib.tarb(others + [("blobs/sha256/" + h, b), ("index.json", json.dumps(top).encode())]))
P
fails "rule 31" "oci-digest: two members with the same name (index.json and ./index.json) are refused, not last-one-wins" 'duplicate' python3 "$OD" "$work/oci-dup.tar"
fails "rule 31" "oci-digest: two members both named index.json are refused" 'duplicate' python3 "$OD" "$work/oci-dup2.tar"
fails "rule 31" "oci-digest: a per-architecture manifest entry with a non-OCI media type is refused" 'media' python3 "$OD" "$work/oci-badmanmedia.tar"
# lock-proof records the sha256 of everything it proved against
lpo3=$(mo); run_s "${aie[@]}" "$LP" --out "$lpo3" --archive "$fx/archive" "${lp_args[@]}"
t "rule 36" "lock-proof.json records the sha256 of the config, the base lock, the index record and the key record it proved" bash -c "python3 - '$lpo3/lock-proof.json' '$fx/apko.yaml' '$BL' '$idxrec' '$keyrec' <<'P'
import hashlib, json, sys
d = json.load(open(sys.argv[1]))['inputs']
for k, path in zip(('config', 'base_lock', 'index_record', 'key_record'), sys.argv[2:6]):
    assert d[k]['sha256'] == hashlib.sha256(open(path, 'rb').read()).hexdigest(), (k, d[k])
P"

# ---- P5 round 3: sealed-proof runner version "unknown", and a run that produces no digests ---------------------------------------------------------
sr2() { local ac=$1 d=$2 kw=$3; shift 3; "$@"; if [ "$(rc)" != 0 ] && grep -Eqi -- "$kw" "$work/log"; then ok; else bad "$ac" "$d (exit $(rc), wanted non-zero naming '$kw')"; fi; }
sr2 "rule 42" "sealed-proof: ImageOS/ImageVersion set to 'unknown' are refused outside test mode (the runner image must be real)" 'ImageOS|ImageVersion' run_s env -u FSCACHE_TEST_MODE ImageOS=unknown ImageVersion=unknown SOURCE_DATE_EPOCH=$SDE "$SP" --out "$(mo)" --probe 'test -z "${FAKE_SEALED:-}"' "${sp_common[@]}"

# ---- snapshot-4 round 4 (Opus P5) -----------------------------------------------------------------------------------------------------------------------------
# the proofs supply the paths themselves; a pass-through argument cannot put a reason into an error message
for bad in --archive --out --render-dir --apko-config; do
  sr2 "rule 36" "lock-proof refuses $bad after -- (the proof supplies it; a forwarded value could be printed back as a 'reason')" 'supplied by|after --' run_s "${aie[@]}" bash -c 'cd "$0" && exec "$@"' "$air" "$air/bin/lock-proof.sh" --out "$(mo)" --archive "$fx/archive" -- --variant production --version 0.3.0 --melange-repo "$fx/melrepo" --keyring-dir "$fx/keyring" --base-lock "$BL" "$bad" "x/ca-certificates-bundle-20260101-r0.apk does not match APKINDEX live repository"
done
for bad in --source-dir --out --render-dir; do
  sr2 "rule 41" "sealed-proof refuses $bad in --build-args" 'supplied by' run_s "${spe[@]}" "$SP" --out "$(mo)" --probe 'test -z "${FAKE_SEALED:-}"' --source-dir "$src" --archive "$fx/archive" --build-args "--variant standard --arch x86_64 $bad x" --assemble-args "--variant production --version 0.3.0"
done
# a build that fails with a message that merely prints the source directory does not count as the vendor refusal
printf '#!/bin/sh\nfor a in "$@"; do last=$a; done\necho "build-apk.sh: melange failed: network unreachable while building $*" >&2\nexit 2\n' >"$work/pathfail.sh"; chmod +x "$work/pathfail.sh"
sf "rule 41" "sealed-proof: a failure that only prints the source path is not the vendor refusal (the builder's own 'vendor is missing' line is required)" 'vendor|reason' "${spe[@]}" "$SP" --out "$(mo)" --probe 'test -z "${FAKE_SEALED:-}"' --build-script "$work/pathfail.sh" "${sp_common[@]}"
t "rule 41" "sealed-proof: the copy used for the vendor negative has no keyword in its name" bash -c "! grep -q 'src-novendor' '$SP_PROD'"
printf '#!/bin/sh\necho "assemble-image.sh: failed while reading $*" >&2\nexit 2\n' >"$work/pathfail2.sh"; chmod +x "$work/pathfail2.sh"
sf "rule 41" "sealed-proof: an image failure whose lines do not name the deleted package is not the package refusal" 'package|reason' "${spe[@]}" "$SP" --out "$(mo)" --probe 'test -z "${FAKE_SEALED:-}"' --assemble-script "$work/pathfail2.sh" "${sp_common[@]}"
# an unlistable directory is not an empty directory
if [ "$(id -u)" != 0 ]; then
  mkdir -p "$work/nolist"; : >"$work/nolist/planted"; chmod 0300 "$work/nolist"
  fixed12 archive="$fx/archive"; sr "rule 25" "a --render-dir that cannot be listed is refused (not taken as empty)" 'render|list' "${aie[@]}" "$AI" "${w12[@]}" --index-record "$idxrec" --render-dir "$work/nolist"
  fixed12 archive="$fx/archive" out="$work/nolist"; sr "rule 31" "an --out that cannot be listed is refused (not taken as empty)" 'out|list' "${aie[@]}" "$AI" "${w12[@]}" --index-record "$idxrec"
  chmod 0700 "$work/nolist"
fi
# oci-digest: the apko layout is checked as strictly as the standard one
python3 - "$work" "$fx/oci" <<'P'
import json, sys, tarfile
sys.path.insert(0, sys.argv[1]); import lib
w, oc = sys.argv[1:3]
t = tarfile.open(oc + "/apko.tar"); ms = {m.name: t.extractfile(m).read() for m in t.getmembers() if m.isfile()}
def variant(name, f):
    idx = json.loads(ms["index.json"]); f(idx)
    out = [(n, d) for n, d in ms.items() if n != "index.json"] + [("index.json", json.dumps(idx).encode())]
    open("%s/%s.tar" % (w, name), "wb").write(lib.tarb(out))
variant("apko-badidxmt", lambda i: i.__setitem__("mediaType", "application/x-evil"))
variant("apko-badmanmt", lambda i: i["manifests"][0].__setitem__("mediaType", "application/x-evil"))
variant("apko-noos", lambda i: i["manifests"][0]["platform"].pop("os", None))
variant("apko-os", lambda i: i["manifests"][0]["platform"].__setitem__("os", "windows"))
P
for v in badidxmt badmanmt noos os; do
  fails "rule 31" "oci-digest: the apko-layout variant '$v' (media type or platform.os not as the OCI layout requires) is refused" 'media|os|linux' python3 "$OD" "$work/apko-$v.tar"
done
# /work: links are made without -f; if one cannot be made (another run's link is there) the run stops and removes only the links IT made
sf "rule 26" "assemble: an existing /work link (ln -sT fails on the second link) is an error naming the link, not a silent replacement" 'melange-repo|link' env STUB_LN_FAIL_AT=2 "${aie[@]}" "$AI" "${ai_args[@]}" --out "$(mo)"
t "rule 26" "...and the cleanup removes only the link it made (archive), not the one that was already there" bash -c "grep -q '^sudo rm -f /work/archive\$' '$CALLS' && ! grep -q 'sudo rm -f /work/archive /work/melange-repo' '$CALLS'"

# ---- snapshot-5 round 5 (Sonnet/Opus P5) -------------------------------------------------------------------------------------------------------------------------
# a symlinked root is refused by the proofs and the assembler; the real tree is untouched
mkarch "$work/real-arch"; ln -sfn "$work/real-arch" "$work/link-arch"; before=$(cd "$work/real-arch" && find . | sort | xargs shasum -a 256 2>/dev/null | shasum -a 256)
sr2 "rule 36" "lock-proof refuses a symlinked --archive root (exit non-zero, names symlink)" 'symlink' run_s "${aie[@]}" "$LP" --out "$(mo)" --archive "$work/link-arch" "${lp_args[@]}"
sr2 "rule 41" "sealed-proof refuses a symlinked --archive root" 'symlink' run_s "${spe[@]}" "$SP" --out "$(mo)" --probe 'test -z "${FAKE_SEALED:-}"' --source-dir "$src" --archive "$work/link-arch" --build-args "--variant standard" --assemble-args "--variant production --version 0.3.0"
rm -f "$work/link-src"; ln -s "$src" "$work/link-src"; vend_before=$(cd "$src/vendor" && find . | sort | xargs shasum -a 256 2>/dev/null | shasum -a 256)
sr2 "rule 41" "sealed-proof refuses a symlinked --source-dir root" 'symlink' run_s "${spe[@]}" "$SP" --out "$(mo)" --probe 'test -z "${FAKE_SEALED:-}"' --source-dir "$work/link-src" --archive "$fx/archive" --build-args "--variant standard" --assemble-args "--variant production --version 0.3.0"
t "rule 41" "...and the real source vendor/ is still there, byte for byte" test "$(cd "$src/vendor" && find . | sort | xargs shasum -a 256 2>/dev/null | shasum -a 256)" = "$vend_before"
t "rule 36" "...and the real archive is byte-identical after the refused lock-proof and sealed-proof" test "$(cd "$work/real-arch" && find . | sort | xargs shasum -a 256 2>/dev/null | shasum -a 256)" = "$before"
fixed12 archive="$work/link-arch"; sr "rule 26" "assemble refuses a symlinked --archive root" 'symlink' "${aie[@]}" "$AI" "${w12[@]}" --index-record "$idxrec"
mkdir -p "$work/real-out"; ln -sfn "$work/real-out" "$work/link-out"
fixed12 archive="$fx/archive" out="$work/link-out"; sr "rule 31" "assemble refuses a symlinked --out (a link to an empty directory too)" 'symlink' "${aie[@]}" "$AI" "${w12[@]}" --index-record "$idxrec"
t "rule 31" "...and nothing was written through it" test -z "$(ls -A "$work/real-out")"
# every filter of the round-4 reason rule is pinned
for bad in --archive --out --render-dir; do
  sr2 "rule 41" "sealed-proof refuses $bad in --assemble-args" 'supplied by' run_s "${spe[@]}" "$SP" --out "$(mo)" --probe 'test -z "${FAKE_SEALED:-}"' --source-dir "$src" --archive "$fx/archive" --build-args "--variant standard" --assemble-args "--variant production $bad x"
done
sr2 "rule 41" "sealed-proof refuses --apk-cache-dir in --build-args" 'supplied by' run_s "${spe[@]}" "$SP" --out "$(mo)" --probe 'test -z "${FAKE_SEALED:-}"' --source-dir "$src" --archive "$fx/archive" --build-args "--variant standard --apk-cache-dir x" --assemble-args "--variant production --version 0.3.0"
printf '#!/bin/sh\nfor a in "$@"; do case "$a" in --source-dir) n=1;; *) [ "$n" = 1 ] && { echo "build-apk.sh: $a/vendor is missing: the build uses only vendored Go code" >&2; n=0; }; esac; done\necho "build-apk.sh: then something else failed" >&2\nexit 2\n' >"$work/vendor-then-other.sh"; chmod +x "$work/vendor-then-other.sh"
sf "rule 41" "sealed-proof: a builder whose LAST prefixed line is something else after the vendor line is not the vendor refusal" 'vendor|reason' "${spe[@]}" "$SP" --out "$(mo)" --probe 'test -z "${FAKE_SEALED:-}"' --build-script "$work/vendor-then-other.sh" "${sp_common[@]}"
printf '#!/bin/sh\necho "build-apk.sh: /elsewhere/vendor is missing" >&2\nexit 2\n' >"$work/vendor-elsewhere.sh"; chmod +x "$work/vendor-elsewhere.sh"
sf "rule 41" "sealed-proof: 'vendor is missing' about ANOTHER path is not the refusal about the copy's own vendor/" 'vendor|reason' "${spe[@]}" "$SP" --out "$(mo)" --probe 'test -z "${FAKE_SEALED:-}"' --build-script "$work/vendor-elsewhere.sh" "${sp_common[@]}"
V=$(python3 -c 'import json,sys;e=sorted(json.load(open(sys.argv[1]))["contents"]["packages"],key=lambda e:(e["name"],e["architecture"]))[0];print("%s-%s.apk"%(e["name"],e["version"]))' "$BL")
printf '#!/bin/sh\necho "the file %s is gone" >&2\necho "assemble-image.sh: failed" >&2\nexit 2\n' "$V" >"$work/unprefixed-victim.sh"; chmod +x "$work/unprefixed-victim.sh"
sf "rule 41" "sealed-proof: the victim named only on an unprefixed line is not the package refusal" 'package|reason' "${spe[@]}" "$SP" --out "$(mo)" --probe 'test -z "${FAKE_SEALED:-}"' --assemble-script "$work/unprefixed-victim.sh" "${sp_common[@]}"
printf '#!/bin/sh\ncase " $* " in *a-missing-package*) echo "the file %s is gone" >&2; echo "assemble-image.sh: failed" >&2; exit 2;; esac\nexit 0\n' "$V" >"$work/unprefixed-lp.sh"; chmod +x "$work/unprefixed-lp.sh"
sf "rule 36" "lock-proof: a victim named only on an unprefixed line is not the case's own reason" 'reason' env VICTIM="$V" "${aie[@]}" "$LP" --out "$(mo)" --archive "$fx/archive" --assemble-script "$work/unprefixed-lp.sh" "${lp_args[@]}"
# a name with regex characters (libstdc++) is matched literally
python3 - "$work" "$fx" "$BL" <<'P'
import json, os, shutil, sys
w, fx, bl = sys.argv[1:4]
d = w + "/plus"; shutil.rmtree(d, ignore_errors=True); shutil.copytree(fx + "/archive", d + "/archive")
lk = json.load(open(bl)); pk = lk["contents"]["packages"]
old = sorted(pk, key=lambda e: (e["name"], e["architecture"]))[0]["name"]
for e in pk:
    if e["name"] == old:
        src_ = "%s/archive/%s/%s-%s.apk" % (d, e["architecture"], e["name"], e["version"]); e["name"] = "a++c"
        os.rename(src_, "%s/archive/%s/a++c-%s.apk" % (d, e["architecture"], e["version"]))
json.dump(lk, open(d + "/plus.lock.json", "w"))
P
VP=$(python3 -c 'import json,sys;e=sorted(json.load(open(sys.argv[1]))["contents"]["packages"],key=lambda e:(e["name"],e["architecture"]))[0];print("%s-%s.apk"%(e["name"],e["version"]))' "$work/plus/plus.lock.json")
printf '#!/bin/sh\nARCHDIR=; p=; for a in "$@"; do [ "$p" = --archive ] && ARCHDIR=$a; p=$a; done\ncase " $* " in *a-missing-package*) echo "apko-lock.sh: %s is not in the archive" >&2; echo "assemble-image.sh: the archive does not satisfy the base lock" >&2; exit 2;; *a-missing-index*) echo "assemble-image.sh: $ARCHDIR/x86_64/APKINDEX.tar.gz is missing" >&2; exit 2;; *a-tampered*) echo "apko-lock.sh: %s: data section does not match the lock" >&2; exit 2;; esac\nif grep -q packages.wolfi.dev build/apko.yaml 2>/dev/null; then echo "assemble-image.sh: the config names a live repository" >&2; exit 2; fi\nexit 0\n' "$VP" "$VP" >"$work/plus-asm.sh"; chmod +x "$work/plus-asm.sh"
run_s "${aie[@]}" "$LP" --out "$(mo)" --archive "$work/plus/archive" --assemble-script "$work/plus-asm.sh" --apko-config "$fx/apko.yaml" -- --variant production --version 0.3.0 --melange-repo "$fx/melrepo" --keyring-dir "$fx/keyring" --base-lock "$work/plus/plus.lock.json" --index-record "$idxrec" --key-record "$keyrec"
t "rule 36" "lock-proof: a victim named a++c is matched literally (regex characters in a package name are not a reason to fail)" test "$(cat "$work/rc")" = 0
t "rule 36" "lock-proof keeps the whole reason line in its record (cut after the match, 400 characters)" bash -c "grep -q 'cut -c1-400' '$LP_PROD'"
# oci-digest: null or mistyped fields are named refusals, not tracebacks
python3 - "$work" "$fx/oci" <<'P'
import json, sys, tarfile
sys.path.insert(0, sys.argv[1]); import lib
w, oc = sys.argv[1:3]
t = tarfile.open(oc + "/apko.tar"); ms = {m.name: t.extractfile(m).read() for m in t.getmembers() if m.isfile()}
def variant(name, f):
    idx = json.loads(ms["index.json"]); f(idx)
    open("%s/%s.tar" % (w, name), "wb").write(lib.tarb([(n, d) for n, d in ms.items() if n != "index.json"] + [("index.json", json.dumps(idx).encode())]))
variant("oci-null", lambda i: i.__setitem__("manifests", None))
variant("oci-platstr", lambda i: i["manifests"][0].__setitem__("platform", "linux/amd64"))
variant("oci-entrystr", lambda i: i["manifests"].__setitem__(0, "x"))
P
for v in null platstr entrystr; do
  fails "rule 31" "oci-digest: the variant '$v' (null or mistyped field) is a named refusal" 'manifest|platform|index' python3 "$OD" "$work/oci-$v.tar"
  t "rule 31" "...$v: no traceback" bash -c "! python3 '$OD' '$work/oci-$v.tar' 2>&1 | grep -q Traceback"
done

# oci-digest: named refusals for lists and numbers where objects are expected
python3 - "$work" "$fx/oci" <<'P'
import json, sys, tarfile
sys.path.insert(0, sys.argv[1]); import lib
w, oc = sys.argv[1:3]
t = tarfile.open(oc + "/apko.tar"); ms = {m.name: t.extractfile(m).read() for m in t.getmembers() if m.isfile()}
def variant(name, f):
    idx = json.loads(ms["index.json"]); f(idx)
    open("%s/%s.tar" % (w, name), "wb").write(lib.tarb([(n, d) for n, d in ms.items() if n != "index.json"] + [("index.json", json.dumps(idx).encode())]))
variant("oci-archlist", lambda i: i["manifests"][0]["platform"].__setitem__("architecture", ["amd64"]))
variant("oci-archint", lambda i: i["manifests"][0]["platform"].__setitem__("architecture", 5))
variant("oci-samedigest", lambda i: i["manifests"][1].__setitem__("digest", i["manifests"][0]["digest"]))
P
for v in archlist archint samedigest; do
  fails "rule 31" "oci-digest: the variant '$v' is a named refusal" 'architecture|manifest|same' python3 "$OD" "$work/oci-$v.tar"
  t "rule 31" "...$v: no traceback" bash -c "! python3 '$OD' '$work/oci-$v.tar' 2>&1 | grep -q Traceback"
done
# the guard before every write in the throwaway copies is reachable: a copy whose architecture directory is a symlink out of it is refused
mkdir -p "$work/outside-arch"; cp -R "$fx/archive" "$work/archlink"; mv "$work/archlink/x86_64" "$work/outside-arch/x86_64"; ln -s "$work/outside-arch/x86_64" "$work/archlink/x86_64"
before=$(cd "$work/outside-arch" && find . -type f | sort | xargs shasum -a 256 2>/dev/null | shasum -a 256)
sp_alink=("${sp_common[@]}"); for i in "${!sp_alink[@]}"; do [ "${sp_alink[$i]}" = "$fx/archive" ] && sp_alink[$i]="$work/archlink"; done
sr2 "rule 41" "sealed-proof: a symlinked ARCHITECTURE directory inside the archive is refused before anything is deleted through it" 'symlink|temp directory' run_s "${spe[@]}" "$SP" --out "$(mo)" --probe 'test -z "${FAKE_SEALED:-}"' "${sp_alink[@]}"
t "rule 41" "...and the real files behind the link are byte-identical" test "$(cd "$work/outside-arch" && find . -type f | sort | xargs shasum -a 256 2>/dev/null | shasum -a 256)" = "$before"

# ---- snapshot-7 round 7 (Sonnet/Opus P5) -----------------------------------------------------------------------------------------------------------------------
# a path with a "." or ".." component after another component hides a symlinked root from the -L test: refused by all three scripts
mkdir -p "$work/real-out2/sub"; ln -sfn "$work/real-out2" "$work/link-out2"
for spell in "$work/link-out2/." "$work/link-out2/./" "$work/real-out2/sub/../../link-out2" "$work/link-out2//" "$work/link-out2/"; do
  fixed12 archive="$fx/archive" out="$spell"; sr "rule 31" "assemble refuses --out '${spell#$work/}' (a symlinked root spelled so that -L is false)" 'symlink|component|real directory' "${aie[@]}" "$AI" "${w12[@]}" --index-record "$idxrec"
  sr2 "rule 36" "lock-proof refuses --out '${spell#$work/}'" 'symlink|component|real directory' run_s "${aie[@]}" "$LP" --out "$spell" --archive "$fx/archive" "${lp_args[@]}"
  sr2 "rule 41" "sealed-proof refuses --out '${spell#$work/}'" 'symlink|component|real directory' run_s "${spe[@]}" "$SP" --out "$spell" --probe 'test -z "${FAKE_SEALED:-}"' "${sp_common[@]}"
done
t "rule 31" "...and nothing was written through the link by any of them" test -z "$(ls -A "$work/real-out2")" -o "$(ls -A "$work/real-out2")" = sub
for v in --archive --melange-repo --keyring-dir --out; do
  args=(--variant production --version 0.3.0 --archive "$fx/archive" --melange-repo "$fx/melrepo" --keyring-dir "$fx/keyring" --out "$(mo)")
  for i in "${!args[@]}"; do [ "${args[$i]}" = "$v" ] && args[$((i+1))]=""; done
  sr "rule 26" "assemble refuses an EMPTY value for $v (it would silently mean the current directory)" 'empty' "${aie[@]}" "$AI" "${args[@]}" --index-record "$idxrec" --key-record "$keyrec" --apko-config "$fx/apko.yaml" --base-lock "$BL"
done
# the guard in the throwaway copies is reached: the control passes through the test-mode stub, the symlinked architecture directory is then met by the proof's own guard
mkdir -p "$work/outside-g"; cp -R "$fx/archive" "$work/archg"; python3 - "$work/archg" "$BL" "$work/outside-g" <<'P'
import json, os, shutil, sys
arc, bl, outside = sys.argv[1:4]
e = sorted(json.load(open(bl))["contents"]["packages"], key=lambda e: (e["name"], e["architecture"]))[0]
a = e["architecture"]; shutil.move("%s/%s" % (arc, a), "%s/%s" % (outside, a)); os.symlink("%s/%s" % (outside, a), "%s/%s" % (arc, a))
P
gbefore=$(cd "$work/outside-g" && find . -type f | sort | xargs shasum -a 256 2>/dev/null | shasum -a 256)
printf '#!/bin/sh\nexit 0\n' >"$work/ok-asm.sh"; chmod +x "$work/ok-asm.sh"
sr2 "rule 36" "lock-proof's own guard refuses a copy whose architecture directory is a symlink out of it ('internal: ... temp directory'), even when the assembler stub accepts everything" 'internal|temp directory' run_s "${aie[@]}" "$LP" --out "$(mo)" --archive "$work/archg" --assemble-script "$work/ok-asm.sh" "${lp_args[@]}"
sp_g=("${sp_common[@]}"); for i in "${!sp_g[@]}"; do [ "${sp_g[$i]}" = "$fx/archive" ] && sp_g[$i]="$work/archg"; done
sr2 "rule 41" "sealed-proof's own guard refuses the same (stub drivers accept everything)" 'internal|temp directory' run_s "${spe[@]}" "$SP" --out "$(mo)" --probe 'test -z "${FAKE_SEALED:-}"' --assemble-script "$work/ok-asm.sh" "${sp_g[@]}"
t "rule 36" "...and the real files behind the link are byte-identical" test "$(cd "$work/outside-g" && find . -type f | sort | xargs shasum -a 256 2>/dev/null | shasum -a 256)" = "$gbefore"
# oci-digest: the config must name the architecture and os, and layers must be a list
python3 - "$work" "$fx/oci" <<'P'
import hashlib, json, sys, tarfile
sys.path.insert(0, sys.argv[1]); import lib
w, oc = sys.argv[1:3]
t = tarfile.open(oc + "/apko.tar"); ms = {m.name: t.extractfile(m).read() for m in t.getmembers() if m.isfile()}
idx = json.loads(ms["index.json"])
def rebuild(name, edit_cfg=None, edit_man=None):
    members = dict(ms); top = json.loads(ms["index.json"])
    for k, m in enumerate(top["manifests"]):
        mn = "sha256:" + m["digest"].split(":")[1]; man = json.loads(members.pop(mn))
        cn = "sha256:" + man["config"]["digest"].split(":")[1]; cfg = json.loads(members.pop(cn))
        if edit_cfg and k == 0: edit_cfg(cfg)
        if edit_man and k == 0: edit_man(man)
        cb = json.dumps(cfg).encode(); chex = hashlib.sha256(cb).hexdigest(); man["config"]["digest"] = "sha256:" + chex; man["config"]["size"] = len(cb); members["sha256:" + chex] = cb
        mb = json.dumps(man).encode(); mhex = hashlib.sha256(mb).hexdigest(); m["digest"] = "sha256:" + mhex; m["size"] = len(mb); members["sha256:" + mhex] = mb
    members["index.json"] = json.dumps(top).encode()
    open("%s/%s.tar" % (w, name), "wb").write(lib.tarb(list(members.items())))
rebuild("oci-cfgarchwrong", edit_cfg=lambda c: c.__setitem__("architecture", "s390x"))
rebuild("oci-cfgarchnone", edit_cfg=lambda c: c.pop("architecture", None))
rebuild("oci-cfgoswin", edit_cfg=lambda c: c.__setitem__("os", "windows"))
rebuild("oci-layersint", edit_man=lambda m: m.__setitem__("layers", 5))
def prefix(m, p):
    m["config"]["digest"] = p + m["config"]["digest"][len("sha256"):]
def rebuild_post(name, post):
    members = dict(ms); top = json.loads(ms["index.json"])
    for k, m in enumerate(top["manifests"]):
        mn = "sha256:" + m["digest"].split(":")[1]; man = json.loads(members.pop(mn))
        cn = "sha256:" + man["config"]["digest"].split(":")[1]; cfg = json.loads(members.pop(cn))
        cb = json.dumps(cfg).encode(); chex = hashlib.sha256(cb).hexdigest(); man["config"]["digest"] = "sha256:" + chex; man["config"]["size"] = len(cb); members["sha256:" + chex] = cb
        if k == 0: post(man)
        mb = json.dumps(man).encode(); mhex = hashlib.sha256(mb).hexdigest(); m["digest"] = "sha256:" + mhex; m["size"] = len(mb); members["sha256:" + mhex] = mb
    members["index.json"] = json.dumps(top).encode()
    open("%s/%s.tar" % (w, name), "wb").write(lib.tarb(list(members.items())))
rebuild_post("oci-cfgsha512", lambda m: prefix(m, "sha512"))
rebuild_post("oci-cfgupper", lambda m: m["config"].__setitem__("digest", "sha256:" + m["config"]["digest"][7:].upper()))
rebuild_post("oci-layersfalse", lambda m: m.__setitem__("layers", False))
rebuild_post("oci-layersdict", lambda m: m.__setitem__("layers", {}))
rebuild_post("oci-layersnone", lambda m: m.pop("layers", None))
rebuild_post("oci-manmt", lambda m: m.__setitem__("mediaType", "application/vnd.docker.distribution.manifest.v2+json"))
P
for v in cfgarchwrong cfgarchnone cfgoswin layersint cfgsha512 cfgupper layersfalse layersdict layersnone manmt; do
  case $v in cfgarchwrong|cfgarchnone) want_re='architecture';; cfgoswin) want_re='says os';; layers*) want_re='layers';; cfgsha512|cfgupper) want_re='not sha256:';; manmt) want_re='media type';; esac
  fails "rule 31" "oci-digest: the variant '$v' is refused for ITS OWN property (diagnostic matches /$want_re/, not a stale size or hash)" "$want_re" python3 "$OD" "$work/oci-$v.tar"
  t "rule 31" "...$v: no traceback" bash -c "! python3 '$OD' '$work/oci-$v.tar' 2>&1 | grep -q Traceback"
done

# an apk name with a newline in the archive is refused, never linked under a split name
cp -R "$fx/archive" "$work/archnl"; : >"$work/archnl/x86_64/$(printf 'evil\nname.apk')"
fixed12 archive="$work/archnl"; sr "rule 31" "assemble refuses an archive holding an apk whose NAME has a newline (control character)" 'control' "${aie[@]}" "$AI" "${w12[@]}" --index-record "$idxrec"

# the standard layout's oci-layout file must be exactly the 1.0.0 marker
python3 - "$work" "$oc/good.tar" <<'P'
import sys, tarfile
sys.path.insert(0, sys.argv[1]); import lib
w, g = sys.argv[1:3]
ms = [(m.name, tarfile.open(g).extractfile(m).read()) for m in tarfile.open(g).getmembers() if m.isfile()]
for name, content in (("ol-v2", b'{"imageLayoutVersion":"2.0.0"}'), ("ol-junk", b"junk"), ("ol-extra", b'{"imageLayoutVersion":"1.0.0","x":1}')):
    open("%s/oci-%s.tar" % (w, name), "wb").write(lib.tarb([(n, content if n == "oci-layout" else b) for n, b in ms]))
P
t "rule 31" "oci-digest: the exact 1.0.0 oci-layout is accepted" python3 "$OD" "$oc/good.tar"
for v in ol-v2 ol-junk ol-extra; do fails "rule 31" "oci-digest: an oci-layout that is not exactly the 1.0.0 marker ($v) is refused" 'oci-layout' python3 "$OD" "$work/oci-$v.tar"; done

# ---- snapshot-8 round 8 (P5) ---------------------------------------------------------------------------------------------------------------------------
# lock-proof: a link put in place of the copied victim while an earlier case runs is never written through (copies come first; the write refuses a link)
VN=$(python3 - "$BL" <<'P'
import json, sys
e = sorted(json.load(open(sys.argv[1]))["contents"]["packages"], key=lambda e: (e["name"], e["architecture"]))[0]
print("%s/%s-%s.apk" % (e["architecture"], e["name"], e["version"]))
P
)
echo "outside file, must stay as it is" >"$work/outside-victim"; ov_before=$(shasum -a 256 "$work/outside-victim" | cut -d' ' -f1)
cat >"$work/swap-asm.sh" <<EOF
#!/bin/bash
a=; for ((i=1;i<=\$#;i++)); do [ "\${!i}" = --archive ] && a=\${@:i+1:1}; done
case "\$a" in
  */a-missing-package) echo "assemble-image.sh: $(basename "$VN") is not in the archive" >&2; exit 2;;
  */a-missing-index) rm -f "\$(dirname "\$a")/a-tampered/$VN"; ln -s "$work/outside-victim" "\$(dirname "\$a")/a-tampered/$VN"; echo "assemble-image.sh: \$a/x86_64/APKINDEX.tar.gz is missing" >&2; exit 2;;
  */a-tampered) echo "assemble-image.sh: $(basename "$VN"): data section does not match the lock" >&2; exit 2;;
  *) exit 0;;
esac
EOF
chmod +x "$work/swap-asm.sh"
run_s "${aie[@]}" "$LP" --out "$(mo)" --archive "$fx/archive" --assemble-script "$work/swap-asm.sh" "${lp_args[@]}"
t "rule 36" "lock-proof: a link swapped in for a copied victim while an earlier case runs is never written through (the copies and the tamper come BEFORE any run); the outside file is unchanged" test "$(shasum -a 256 "$work/outside-victim" | cut -d' ' -f1)" = "$ov_before"
# lock-proof's index/ guard: an architecture's index/ directory that is a symlink in the copy is refused by the guard itself
cp -R "$fx/archive" "$work/archidx"; mkdir -p "$work/idx-outside"; a0=$(dirname "$VN"); [ -d "$work/archidx/$a0/index" ] && mv "$work/archidx/$a0/index" "$work/idx-outside/index" || mkdir -p "$work/idx-outside/index"; ln -s "$work/idx-outside/index" "$work/archidx/$a0/index"
sr2 "rule 36" "lock-proof: a symlinked <arch>/index in the archive is refused by the proof's own guard (internal/temp directory)" 'internal|temp directory|symlink' run_s "${aie[@]}" "$LP" --out "$(mo)" --archive "$work/archidx" --assemble-script "$work/ok-asm.sh" "${lp_args[@]}"
# the "." / ".." refusal is shared: every root flag of assemble-image.sh is pinned, and --render-dir too
mkdir -p "$work/rd-real"; ln -sfn "$work/rd-real" "$work/rd-link"
fixed12 archive="$fx/archive"; sr "rule 31" "assemble refuses --render-dir 'link/.' (a symlinked render root spelled so that -L is false)" 'symlink|component|real directory' "${aie[@]}" "$AI" "${w12[@]}" --index-record "$idxrec" --render-dir "$work/rd-link/."
t "rule 31" "...and nothing was written through the render link" test -z "$(ls -A "$work/rd-real")"
for flag in archive melange-repo keyring-dir; do
  case $flag in archive) good="$fx/archive";; melange-repo) good="$fx/melrepo";; keyring-dir) good="$fx/keyring";; esac
  args=(--variant production --version 0.3.0 --archive "$fx/archive" --melange-repo "$fx/melrepo" --keyring-dir "$fx/keyring" --out "$(mo)" --index-record "$idxrec" --key-record "$keyrec" --apko-config "$fx/apko.yaml" --base-lock "$BL")
  for i in "${!args[@]}"; do [ "${args[$i]}" = "--$flag" ] && args[$((i+1))]="$good/./"; done
  sr "rule 31" "assemble refuses --$flag with a '.' component" 'component|real directory' "${aie[@]}" "$AI" "${args[@]}"
done
# a control character in ANY path argument is refused up front, named plainly
nlroot="$work/arch"$'\n'"nl"; cp -R "$fx/archive" "$nlroot"
fixed12 archive="$nlroot"; sr "rule 31" "assemble refuses a newline in the archive ROOT path up front (named, before any work)" 'control character' "${aie[@]}" "$AI" "${w12[@]}" --index-record "$idxrec"

# ---- Opus round 9 (P5): the victim fields are validated before any copy, the physical path decides "inside", forwarded records are refused outside test mode -----
mkbl() { python3 - "$BL" "$1" "$2" "$3" "$4" <<'P'
import json, sys
src, dst, name, ver, arch = sys.argv[1:6]
d = json.load(open(src)); d["contents"]["packages"].insert(0, {"name": name, "version": ver, "architecture": arch, "checksum": "Q1" + "A" * 27, "url": "x"}); json.dump(d, open(dst, "w"))
P
}
# the Opus probe: a symlink under x86_64 pointing outside, and a first base-lock entry whose architecture reaches it with "/lnk/.."
rm -rf "$work/out2"; mkdir -p "$work/out2/sub"; : >"$work/out2/aa-0-r0.apk"; printf 'index' >"$work/out2/APKINDEX.tar.gz"
rm -rf "$work/archp"; cp -R "$fx/archive" "$work/archp"; ln -s "$work/out2/sub" "$work/archp/x86_64/lnk"
mkbl "$work/bl-evil.json" aa 0-r0 "x86_64/lnk/.."
o2_before=$(cd "$work/out2" && find . -type f | sort | xargs shasum -a 256 | shasum -a 256)
for mode in unset set; do
  if [ $mode = unset ]; then pre=(env -u FSCACHE_TEST_MODE); asm=(); else pre=(); asm=(--assemble-script "$work/ok-asm.sh"); fi
  sr2 "rule 36" "lock-proof ($mode test mode): a base-lock victim with the architecture 'x86_64/lnk/..' is refused by the ARCHITECTURE rule (exit 2) before any copy" 'architecture' run_s "${pre[@]}" "${aie[@]}" "$LP" --out "$(mo)" --archive "$work/archp" "${asm[@]}" -- --variant production --version 0.3.0 --melange-repo "$fx/melrepo" --keyring-dir "$fx/keyring" --base-lock "$work/bl-evil.json"
  t "rule 36" "...$mode test mode: exit 2, no assembler call in the log" bash -c "test \"\$(cat '$work/rc')\" = 2 && ! grep -q 'assemble' '$CALLS'"
  t "rule 36" "...$mode test mode: both outside files are untouched" test "$(cd "$work/out2" && find . -type f | sort | xargs shasum -a 256 | shasum -a 256)" = "$o2_before"
done
sp_evil=(--source-dir "$src" --archive "$work/archp" --build-args "--variant standard --arch x86_64 --version 0.3.0" --assemble-args "--variant production --version 0.3.0 --base-lock $work/bl-evil.json")
sr2 "rule 41" "sealed-proof: the same victim is refused by the architecture rule before any copy (exit 2)" 'architecture' run_s "${spe[@]}" "$SP" --out "$(mo)" --probe 'test -z "${FAKE_SEALED:-}"' --assemble-script "$work/ok-asm.sh" --build-script "$work/ok-asm.sh" "${sp_evil[@]}"
t "rule 41" "...and the outside files are untouched" test "$(cd "$work/out2" && find . -type f | sort | xargs shasum -a 256 | shasum -a 256)" = "$o2_before"
# one test per field rule (lock-proof)
for case_ in "aa|0-r0|x86_64/|architecture" "aa|0-r0|arm64|architecture" "a/b|0-r0|x86_64|name" "..|0-r0|x86_64|name" "-x|0-r0|x86_64|name" "aa|0-r0..1|x86_64|version" "aa|-1|x86_64|version" "aa|a b|x86_64|version"; do
  IFS='|' read -r n v a kw <<<"$case_"; mkbl "$work/bl-r.json" "$n" "$v" "$a"
  sr2 "rule 36" "lock-proof: a base-lock victim with name='$n' version='$v' architecture='$a' is refused by the $kw rule" "$kw" run_s "${aie[@]}" "$LP" --out "$(mo)" --archive "$fx/archive" --assemble-script "$work/ok-asm.sh" -- --variant production --version 0.3.0 --melange-repo "$fx/melrepo" --keyring-dir "$fx/keyring" --base-lock "$work/bl-r.json"
done
# a victim with a valid architecture (and not in the archive) passes the field rules (it fails later, for its own reason: not named by the field rules)
for a in x86_64 aarch64; do mkbl "$work/bl-r.json" aa 0-r0 "$a"
  run_s "${aie[@]}" "$LP" --out "$(mo)" --archive "$fx/archive" --assemble-script "$work/ok-asm.sh" -- --variant production --version 0.3.0 --melange-repo "$fx/melrepo" --keyring-dir "$fx/keyring" --base-lock "$work/bl-r.json"
  t "rule 36" "lock-proof: architecture $a passes the field rules (any refusal is another one)" bash -c "! grep -Eqi 'architecture rule|the victim .* architecture' '$work/log'"
done
# forwarded records outside test mode are refused BEFORE any copy
for opt in --base-lock --index-record --key-record; do
  case $opt in --base-lock) val="$BL";; --index-record) val="$idxrec";; --key-record) val="$keyrec";; esac
  sr2 "rule 36" "lock-proof refuses a forwarded $opt in every mode (exit 2) before any copy" 'supplied by|after --' run_s "${aie[@]}" bash -c 'cd "$0" && exec "$@"' "$air" "$air/bin/lock-proof.sh" --out "$(mo)" --archive "$fx/archive" -- --variant production --version 0.3.0 --melange-repo "$fx/melrepo" --keyring-dir "$fx/keyring" "$opt" "$val"
  t "rule 36" "...$opt: exit 2 and no assembler call" bash -c "test \"\$(cat '$work/rc')\" = 2 && ! grep -q 'assemble' '$CALLS'"
done
# a leaf of --out that already exists (a link to elsewhere) is never written through
for proof in lock sealed; do
  od=$(mo); echo "keep me" >"$work/leaf-target"; case $proof in lock) leaf=lock-proof.json;; sealed) leaf=sealed-record.json;; esac; ln -s "$work/leaf-target" "$od/$leaf"
  if [ $proof = lock ]; then sr2 "rule 36" "lock-proof: a symlink at the leaf --out/$leaf is refused (not written through)" 'leaf|exists|symlink' run_s "${aie[@]}" "$LP" --out "$od" --archive "$fx/archive" --assemble-script "$work/ok-asm.sh" "${lp_args[@]}"
  else sr2 "rule 41" "sealed-proof: a symlink at the leaf --out/$leaf is refused (not written through)" 'leaf|exists|symlink' run_s "${spe[@]}" "$SP" --out "$od" --probe 'test -z "${FAKE_SEALED:-}"' --assemble-script "$work/ok-asm.sh" --build-script "$work/ok-asm.sh" "${sp_common[@]}"; fi
  t "rule 36" "...the file behind the $leaf link is unchanged" test "$(cat "$work/leaf-target")" = "keep me"
done
# bytes outside printable ASCII in a path argument (a C1 control such as U+009B passes [[:cntrl:]] in some locales)
c1root="$work/arch"$'\xc2\x9b'"x"; cp -R "$fx/archive" "$c1root"
fixed12 archive="$c1root"; sr "rule 31" "assemble refuses a byte >= 0x80 in a path argument (named)" 'control|byte|plain' "${aie[@]}" "$AI" "${w12[@]}" --index-record "$idxrec"
# a value such as -P or - must not be read as an option of cd
# (the script runs from the repository root only, so the directory named -P is made in the root for the run and removed at once)
mkdir -p "$air/-P"; cp -R "$fx/keyring/." "$air/-P/"
run_s bash -c "cd '$air' && exec env SOURCE_DATE_EPOCH=$SDE STUB_LOCK='$FL' '$AI' --variant production --version 0.3.0 --archive '$fx/archive' --melange-repo '$fx/melrepo' --keyring-dir -P --out '$(mo)' --apko-config '$fx/apko.yaml' --base-lock '$BL' --key-record '$keyrec' --index-record '$idxrec'"
t "rule 31" "assemble-image: --keyring-dir '-P' is the directory named -P (cd -P -- is used, not read as an option): success" test "$(cat "$work/rc")" = 0
rm -rf "$air/-P"
# a CRLF index record is refused by the assembler too
python3 - "$idxrec" "$work/idx-crlf.record" <<'P'
import sys; s = open(sys.argv[1]).read(); assert "\n" in s; open(sys.argv[2], "w", newline="").write(s.replace("\n", "\r\n"))
P
fixed12 archive="$fx/archive"; sr "rule 31" "assemble refuses an index record with CRLF line ends (malformed, exit 2)" 'malformed' "${aie[@]}" "$AI" "${w12[@]}" --index-record "$work/idx-crlf.record"
# oci-digest: the index.json entry's media type
python3 - "$work" "$oc/good.tar" <<'P'
import json, sys, tarfile
sys.path.insert(0, sys.argv[1]); import lib
w, g = sys.argv[1:3]
ms = [(m.name, tarfile.open(g).extractfile(m).read()) for m in tarfile.open(g).getmembers() if m.isfile()]
out = []
for n, b in ms:
    if n == "index.json":
        d = json.loads(b); d["manifests"][0]["mediaType"] = "application/vnd.oci.image.manifest.v1+json"; b = json.dumps(d).encode()
    out.append((n, b))
open("%s/oci-topmt.tar" % w, "wb").write(lib.tarb(out))
P
fails "rule 31" "oci-digest: the single entry of index.json must have the index media type" 'media type' python3 "$OD" "$work/oci-topmt.tar"

c1o="$work/outc1"$'\xc2\x9b'; mkdir -p "$c1o"
sr2 "rule 36" "lock-proof refuses a byte >= 0x80 in --out (named)" 'control character|printable ASCII' run_s "${aie[@]}" "$LP" --out "$c1o" --archive "$fx/archive" --assemble-script "$work/ok-asm.sh" "${lp_args[@]}"
sr2 "rule 41" "sealed-proof refuses a byte >= 0x80 in --out (named)" 'control character|printable ASCII' run_s "${spe[@]}" "$SP" --out "$c1o" --probe 'test -z "${FAKE_SEALED:-}"' --assemble-script "$work/ok-asm.sh" --build-script "$work/ok-asm.sh" "${sp_common[@]}"


# ===== advisor 0393 (Oct 12): the chain's output layout, the judge-listable structure, byte identity ====================================
# REQ-IMAGE-001 (output names) and REQ-CHAIN-004-AC6/AC11, REQ-CHAIN-005-AC3 as the release chain reads them
for v in production fips; do
  a=("${ai_args[@]}"); [ $v = fips ] && a=("${aif_args[@]}")
  o=$(mo); run_s "${aie[@]}" "$AI" "${a[@]}" --out "$o"
  t "chain" "[$v] OUT/$v/ is an OCI layout DIRECTORY (oci-layout, index.json, blobs/sha256/<hex> only), every blob hashes to its name, no symlink" bash -c "python3 - '$o/$v' <<'P'
import hashlib, json, os, sys
d = sys.argv[1]; assert os.path.isdir(d) and not os.path.islink(d), d
top = sorted(os.listdir(d)); assert top == ['blobs', 'index.json', 'oci-layout'], top
assert json.load(open(d + '/oci-layout')) == {'imageLayoutVersion': '1.0.0'}
idx = json.load(open(d + '/index.json')); assert len(idx['manifests']) == 1
assert os.listdir(d + '/blobs') == ['sha256']
n = 0
for root, dirs, files in os.walk(d):
    for x in dirs + files: assert not os.path.islink(os.path.join(root, x)), x
for f in os.listdir(d + '/blobs/sha256'):
    assert hashlib.sha256(open(d + '/blobs/sha256/' + f, 'rb').read()).hexdigest() == f, f; n += 1
assert idx['manifests'][0]['digest'].split(':')[1] in os.listdir(d + '/blobs/sha256') and n >= 3
P"
  t "chain" "[$v] there is no tarball: OUT/$v.tar does not exist and nothing in OUT is a tar" bash -c "test ! -e '$o/$v.tar' && ! ls '$o' | grep -Eq '\\.tar(\\.gz)?\$'"
  t "chain" "[$v] the SBOM is OUT/$v-sbom/sbom.json (one file) and there is no OUT/sbom" bash -c "test -s '$o/$v-sbom/sbom.json' && test \$(ls '$o/$v-sbom' | wc -l) -eq 1 && test ! -e '$o/sbom'"
  t "chain" "[$v] OUT holds exactly: $v/ $v.digest $v.manifests $v.full.lock.json $v-sbom/ (no dotfile, no other name)" bash -c "test \"\$(ls -A '$o' | tr '\\n' ' ')\" = '$v $v-sbom $v.digest $v.full.lock.json $v.manifests '"
  o2=$(mo); run_s "${aie[@]}" "$AI" "${a[@]}" --out "$o2"
  t "chain" "[$v] a second run with the same inputs and SOURCE_DATE_EPOCH gives a byte-identical OUT (every file's bytes and the directory listing)" bash -c "cd '$o' && find . -type f | LC_ALL=C sort | xargs shasum -a 256 >'$work/t1.sum' && find . | LC_ALL=C sort >'$work/t1.ls' && cd '$o2' && find . -type f | LC_ALL=C sort | xargs shasum -a 256 >'$work/t2.sum' && find . | LC_ALL=C sort >'$work/t2.ls' && cmp '$work/t1.sum' '$work/t2.sum' && cmp '$work/t1.ls' '$work/t2.ls' && test -s '$work/t1.sum'"
  o3=$(mo); run_s env SOURCE_DATE_EPOCH=$SDE STUB_LOCK="$FL" STUB_LOCK_FIPS="$fx/full-fips.lock.json" STUB_OCI_REAL=1 "$AI" "${a[@]}" --out "$o3"
  t "chain" "[$v] the tar real apko writes (blobs named sha256:<hex>, index.json is the index, no oci-layout) is unpacked into the SAME kind of layout directory, with the index digest = sha256 of apko's index.json" bash -c "python3 - '$o3/$v' '$o3/$v.digest' <<'P'
import hashlib, json, os, sys
d = sys.argv[1]; assert sorted(os.listdir(d)) == ['blobs', 'index.json', 'oci-layout'], os.listdir(d)
top = json.load(open(d + '/index.json')); dig = top['manifests'][0]['digest']
blob = open(d + '/blobs/sha256/' + dig.split(':')[1], 'rb').read()
assert 'sha256:' + hashlib.sha256(blob).hexdigest() == dig == open(sys.argv[2]).read().strip()
assert [m['platform']['architecture'] for m in json.loads(blob)['manifests']] == ['amd64', 'arm64']
for f in os.listdir(d + '/blobs/sha256'): assert hashlib.sha256(open(d + '/blobs/sha256/' + f, 'rb').read()).hexdigest() == f
P"
  o4=$(mo); run_s env SOURCE_DATE_EPOCH=$SDE STUB_LOCK="$FL" STUB_LOCK_FIPS="$fx/full-fips.lock.json" STUB_OCI_REAL=1 "$AI" "${a[@]}" --out "$o4"
  t "chain" "[$v] ...and two runs over the real-apko tar are byte-identical too (fixed modes and member order)" bash -c "diff -r '$o3' '$o4' >/dev/null && test \$(stat -c %a '$o3/$v/index.json' 2>/dev/null || stat -f %Lp '$o3/$v/index.json') = 644"
done
# the production and the fips call write into the SAME --out and neither overwrites the other
o=$(mo); run_s "${aie[@]}" "$AI" "${ai_args[@]}" --out "$o"; run_s "${aie[@]}" "$AI" "${aif_args[@]}" --out "$o"
t "chain" "the fips call into the same --out leaves the production result untouched (both layouts, digests and SBOMs are there)" bash -c "test -d '$o/production' && test -d '$o/fips' && test -s '$o/production.digest' && test -s '$o/fips.digest' && test -s '$o/production-sbom/sbom.json' && test -s '$o/fips-sbom/sbom.json' && ! cmp -s '$o/production.digest' '$o/fips.digest'"
# structure: what the release chain's script judge can list (advisor 0393 item 8 / handoff: no PATH or IFS assignment, no python3 -c or python3 - heredoc, no variable-path interpreter call, literal repo-root paths)
t "chain" "assemble-image.sh has a shebang and mode 100755 in git" bash -c "head -n 1 '$AI_PROD' | grep -Fxq '#!/usr/bin/env bash' && git -C '$root' ls-files -s bin/assemble-image.sh | grep -q '^100755'"
nogrep "chain" "assemble-image.sh never assigns PATH, IFS, BASH_ENV or ENV (the judge never waives an assignment)" '(^|[^A-Za-z_$])(export +)?(PATH|IFS|BASH_ENV|ENV|LD_[A-Z_]+|PYTHON[A-Z_]*)=' "$AI_PROD"
nogrep "chain" "assemble-image.sh has no python3 -c and no python3 - heredoc (helper code lives in a committed, listed file)" 'python3? +-c |python3? +-( |$)|<<.?PY' "$AI_PROD"
nogrep "chain" "assemble-image.sh calls no interpreter, script or tool through a variable path: no \$here/ or \$root/ command words, no \"\$lk\", no \$(...) command word" '\$here/|\$\{here\}|\$root/|"\$lk"|^ *\$\(|command -v' "$AI_PROD"
t "chain" "assemble-image.sh names its helpers by literal repo-root-relative paths (bin/apko-lock.sh, bin/oci-digest.py, bin/net-probe.py)" bash -c "grep -Eq 'BASHBIN. bin/apko-lock[.]sh' '$AI_PROD' && grep -Fq -- ' -I -B bin/oci-digest.py' '$AI_PROD' && grep -Fq -- ' -I -B bin/net-probe.py' '$AI_PROD'"
# run from anywhere but the repository root: exit 2 naming the root, before any tool
mkdir -p "$work/elsewhere"; : >"$CALLS"
( cd "$work/elsewhere" && PATH="$stubs:$PATH" CALLS="$CALLS" STUB_LIB="$work/lib.py" SOURCE_DATE_EPOCH=$SDE STUB_LOCK="$FL" bash "$air/bin/assemble-image.sh" "${ai_args[@]}" --out "$work/elsewhere/o" >"$work/log" 2>&1 </dev/null; echo $? >"$work/rc" )
if [ "$(rc)" = 2 ] && grep -Eqi 'repository root' "$work/log" && ! toolrun; then ok; else bad "chain" "assemble-image.sh run from another working directory exits 2 naming the repository root, before any tool (exit $(rc))"; fi
# the chain never passes the test hooks: they are refused outside test mode, exit 2, before any tool
for hook in "--apko-config $fx/apko.yaml" "--base-lock $BL" "--render-dir $work/rd-x" "--index-record $idxrec" "--key-record $keyrec" "--lockfile $FL" "--build-date 2026-01-01T00:00:00Z" "--arch x86_64"; do
  # shellcheck disable=SC2086
  FSCACHE_TEST_MODE= sr "chain" "assemble-image.sh refuses '${hook%% *}' in every mode (no such option)" 'unknown argument' bash -c 'cd "$0" && exec "$@"' "$air" env SOURCE_DATE_EPOCH=$SDE STUB_LOCK="$FL" "$air/bin/assemble-image.sh" --variant production --version 0.3.0 --archive "$fx/archive" --melange-repo "$fx/melrepo" --keyring-dir "$fx/keyring" --out "$(mo)" $hook
done

# ===== REQ-BUILDTOOLS-002-AC3 (advisor step 5, Oct 12): oci-digest.py unpack TAR DIR DIGEST MANIFESTS, called directly ==================
ud="$work/unpack"; mkdir -p "$ud"
unp_ok() { # <tar> <dir> <tag>
  python3 "$OD" unpack "$1" "$2" "$ud/$3.digest" "$ud/$3.manifests" >"$ud/$3.out" 2>&1; }
mkdir "$ud/empty"; unp_ok "$oc/good.tar" "$ud/empty" e1; er=$?
t "rule 31" "BT-002-AC3: unpack into an EMPTY directory succeeds and writes oci-layout, index.json and blobs/sha256 only" bash -c "test $er = 0 && test \"\$(ls '$ud/empty' | tr '\n' ' ')\" = 'blobs index.json oci-layout ' && test \"\$(ls '$ud/empty/blobs')\" = sha256 && grep -Fxq '{\"imageLayoutVersion\":\"1.0.0\"}' '$ud/empty/oci-layout'"
unp_ok "$oc/good.tar" "$ud/absent/deeper" e2; ar=$?
t "rule 31" "BT-002-AC3: an ABSENT directory (and its parents) is created" bash -c "test $ar = 0 && test -f '$ud/absent/deeper/index.json' && test -d '$ud/absent/deeper/blobs/sha256'"
t "rule 31" "BT-002-AC3: DIGEST is ONE line sha256:<hex> equal to the sha256 of the index blob in the layout, MANIFESTS has one '<arch> sha256:<hex>' line per architecture" bash -c "python3 - '$ud/empty' '$ud/e1.digest' '$ud/e1.manifests' <<'P'
import hashlib, json, sys
d, dg, mf = sys.argv[1:4]
idx = json.load(open(d + '/index.json'))['manifests']; assert len(idx) == 1
got = open(dg).read(); assert got.count('\\n') == 1 and got.endswith('\\n'), repr(got)
assert got.strip() == idx[0]['digest'] == 'sha256:' + hashlib.sha256(open(d + '/blobs/sha256/' + idx[0]['digest'][7:], 'rb').read()).hexdigest()
lines = open(mf).read().split('\\n'); assert lines[-1] == '' and sorted(l.split()[0] for l in lines[:-1]) == ['amd64', 'arm64'], lines
assert all(l.split()[1].startswith('sha256:') and len(l.split()[1]) == 71 for l in lines[:-1])
P"
t "rule 31" "BT-002-AC3: files are regular with mode 0644 and directories 0755; no symlink" bash -c "python3 - '$ud/empty' <<'P'
import os, stat, sys
for root, dirs, files in os.walk(sys.argv[1]):
    for n in dirs: m = os.lstat(os.path.join(root, n)); assert stat.S_ISDIR(m.st_mode) and stat.S_IMODE(m.st_mode) == 0o755, n
    for n in files: m = os.lstat(os.path.join(root, n)); assert stat.S_ISREG(m.st_mode) and stat.S_IMODE(m.st_mode) == 0o644, n
P"
mkdir "$ud/full"; printf keep >"$ud/full/keep.txt"; unp_ok "$oc/good.tar" "$ud/full" e3; fr=$?
t "rule 31" "BT-002-AC3: a directory that exists and is not empty is refused (exit 1, named), nothing in it changes and no DIGEST or MANIFESTS is written" bash -c "test $fr = 1 && grep -Eqi 'not an empty directory|empty' '$ud/e3.out' && test \"\$(ls '$ud/full')\" = keep.txt && test ! -e '$ud/e3.digest' && test ! -e '$ud/e3.manifests'"
ln -s "$ud/empty" "$ud/linkdir"; unp_ok "$oc/good.tar" "$ud/linkdir" e4; lr=$?
t "rule 31" "BT-002-AC3: a symlink as DIR is refused" bash -c "test $lr = 1 && grep -Eqi 'not an empty directory|empty' '$ud/e4.out'"
unp_ok "$oc/tampered.tar" "$ud/tampered-dir" e5; tr_=$?
t "rule 31" "BT-002-AC3: a tar with a blob that does not hash to its name is refused naming the blob; no directory and no digest file is written" bash -c "test $tr_ = 1 && grep -Eqi 'blobs/sha256|hash|sha256:' '$ud/e5.out' && test ! -e '$ud/tampered-dir' && test ! -e '$ud/e5.digest'"
unp_ok "$oc/noindex.tar" "$ud/noindex-dir" e6; nr=$?
t "rule 31" "BT-002-AC3: a tar without index.json is refused naming index.json; nothing is written" bash -c "test $nr = 1 && grep -q 'index.json' '$ud/e6.out' && test ! -e '$ud/noindex-dir'"
unp_ok "$oc/apko.tar" "$ud/apko-dir" e7; kr=$?
t "rule 31" "BT-002-AC3: the real apko tar unpacks to the same kind of layout; DIGEST is the sha256 of apko's index.json" bash -c "test $kr = 0 && python3 - '$oc/apko.tar' '$ud/apko-dir' '$ud/e7.digest' <<'P'
import hashlib, json, os, sys, tarfile
raw = tarfile.open(sys.argv[1]).extractfile('index.json').read()
h = 'sha256:' + hashlib.sha256(raw).hexdigest()
assert open(sys.argv[3]).read() == h + '\\n'
d = sys.argv[2]; assert sorted(os.listdir(d)) == ['blobs', 'index.json', 'oci-layout']
assert json.load(open(d + '/index.json'))['manifests'][0]['digest'] == h
assert open(d + '/blobs/sha256/' + h[7:], 'rb').read() == raw
P"
unp_ok "$oc/apko-tampered.tar" "$ud/apko-t-dir" e8; kt=$?
t "rule 31" "BT-002-AC3: the real apko tar with a manifest blob that does not hash to its name is refused; nothing is written" bash -c "test $kt = 1 && test ! -e '$ud/apko-t-dir' && test ! -e '$ud/e8.digest'"

# ===== advisor/pipeline (Oct 12): the refusals name no other script (the chain row's `runs` lists only what the script runs) ===========
rm -rf "$work/stubs-noapko"; cp -R "$stubs" "$work/stubs-noapko"; rm -f "$work/stubs-noapko/apko"
: >"$CALLS"
( PATH="$work/stubs-noapko:$PATH" CALLS="$CALLS" STUB_LIB="$work/lib.py" SOURCE_DATE_EPOCH=$SDE STUB_LOCK="$FL" TEST_APKO=apko-is-not-installed STUB_LOCK_FIPS="$fx/full-fips.lock.json" "$AI" "${ai_args[@]}" --out "$(mo)" >"$work/log" 2>&1 </dev/null; echo $? >"$work/rc" )
if [ "$(rc)" = 1 ] && grep -Eq 'apko is not installed \(the chain installs it before this step\)' "$work/log"; then ok; else bad "chain" "no apko on PATH: exit 1 saying 'apko is not installed (the chain installs it before this step)' (exit $(rc): $(tail -n 2 "$work/log" | tr '\n' ' '))"; fi
t "chain" "no refusal, comment or message of assemble-image.sh, oci-digest.py, apko-lock.sh or net-probe.py names bin/install-build-tools.sh" bash -c "! grep -n 'install-build-tools' '$AI_PROD' '$OD' '$LK' '$NP'"

# ===== advisor (Oct 12): the proofs run as the chain will run them: from the repository root only ====================================
# lock-proof.sh and sealed-proof.sh exit 2 naming the repository root, before any tool, from anywhere else; from the root they work
for drv_ in "$air/bin/lock-proof.sh" "$air/bin/sealed-proof.sh"; do
  mkdir -p "$work/elsewhere-p"
  : >"$CALLS"
  if [ "$drv_" = "$air/bin/lock-proof.sh" ]; then dargs_=(--out "$work/elsewhere-p/o" --archive "$fx/archive" "${lp_args[@]}"); else dargs_=(--out "$work/elsewhere-p/o" --probe true --source-dir "$src" --archive "$fx/archive"); fi
  ( cd "$work/elsewhere-p" && PATH="$stubs:$PATH" CALLS="$CALLS" STUB_LIB="$work/lib.py" SOURCE_DATE_EPOCH=$SDE STUB_LOCK="$FL" "$drv_" "${dargs_[@]}" >"$work/log" 2>&1 </dev/null; echo $? >"$work/rc" )
  if [ "$(rc)" = 2 ] && grep -Eqi 'repository root' "$work/log" && grep -Eqi 'usage|run from' "$work/log" && ! toolrun; then ok; else bad "chain" "$(basename "$drv_") run from another working directory exits 2 naming the repository root and how to run it, before any tool (exit $(rc))"; fi
done
# ...and from the root the real positive control still passes (the proof is run the way the chain runs it)
lpr=$(mo); run_s "${aie[@]}" "$LP" --out "$lpr" --archive "$fx/archive" "${lp_args[@]}"
t "chain" "lock-proof.sh runs from the repository root and its positive control passes" test "$(rc)" = 0
spr=$(mo); run_s "${spe[@]}" "$SP" --out "$spr" --probe 'test -z "${FAKE_SEALED:-}"' "${sp_common[@]}"
t "chain" "sealed-proof.sh runs from the repository root and passes" test "$(rc)" = 0
# the script's own directory is read without dirname (a data-form case split, REQ-IMAGE-001-AC7 file-list scan): both spellings of its path name the same root
air_real=$(cd "$air" && pwd -P)
hr_slash=$(cd "$air" && env -i PATH="$PATH" bash ./bin/assemble-image.sh 2>&1 || true)
hr_bare=$(cd "$air/bin" && env -i PATH="$PATH" bash assemble-image.sh 2>&1 || true)
t "AC7" "assemble-image.sh invoked as ./bin/assemble-image.sh from the root finds the root (no refusal about the working directory)" bash -c '! printf %s "$1" | grep -q "runs from the repository root"' _ "$hr_slash"
t "AC7" "assemble-image.sh invoked with no slash in its path (from bin/) takes its directory as . and names the real root, never /" bash -c 'printf %s "$1" | grep -qF "repository root ($2)" && ! printf %s "$1" | grep -qF "repository root (/)"' _ "$hr_bare" "$air_real"
t "chain" "the test runs from the repository root (the harness changes into it, as the chain runs everything)" test "$(pwd -P)" = "$(cd "$root" && pwd -P)"

# ===== optional: the release chain's own binder over both variants' output (set CHAIN_BINDER_DIR to a directory holding the chain's
# bin/chain_items.py, chain_common.py and check-bind.py, copied read-only from the chain's tree; skipped when unset) =============
if [ -n "${CHAIN_BINDER_DIR:-}" ] && [ -f "$CHAIN_BINDER_DIR/bin/chain_items.py" ] && [ -f "$CHAIN_BINDER_DIR/bin/check-bind.py" ]; then
  bo=$(mo); run_s "${aie[@]}" "$AI" "${ai_args[@]}" --out "$bo"; r1=$(rc); run_s "${aie[@]}" "$AI" "${aif_args[@]}" --out "$bo"; r2=$(rc)
  t "chain" "the chain's image_items reads the output of a production and a fips run in one OUT (items image-<v>, image-<v>-manifest-<arch>, lock-<v>, sbom-<v>)" bash -c "test $r1 = 0 && test $r2 = 0 && cd '$CHAIN_BINDER_DIR' && python3 -I -B -c \"import sys; sys.path.insert(0,'bin'); import chain_items as c; r=c.image_items('$bo'); assert sorted(r)==sorted(['image-production','image-fips','image-production-manifest-amd64','image-production-manifest-arm64','image-fips-manifest-amd64','image-fips-manifest-arm64','lock-production','lock-fips','sbom-production','sbom-fips']), sorted(r); print(r)\""
  python3 - "$bo" "$work/binder-digests.json" <<'PY'
import json, sys
o = sys.argv[1]
json.dump({"image-production": open(o + "/production.digest").read().strip(), "image-fips": open(o + "/fips.digest").read().strip()}, open(sys.argv[2], "w"))
PY
  t "chain" "the chain's check-bind.py (Check's stricter binder: every blob re-hashed, every config and layer present) accepts the layouts" bash -c "cd '$CHAIN_BINDER_DIR' && python3 -I -B bin/check-bind.py --digests '$work/binder-digests.json' --images '$bo'"
  # the same over the tar real apko writes (blobs named sha256:<hex>, index.json the multi-architecture index, no oci-layout)
  bo2=$(mo); run_s env SOURCE_DATE_EPOCH=$SDE STUB_LOCK="$FL" STUB_LOCK_FIPS="$fx/full-fips.lock.json" STUB_OCI_REAL=1 "$AI" "${ai_args[@]}" --out "$bo2"; r1=$(rc)
  run_s env SOURCE_DATE_EPOCH=$SDE STUB_LOCK="$FL" STUB_LOCK_FIPS="$fx/full-fips.lock.json" STUB_OCI_REAL=1 "$AI" "${aif_args[@]}" --out "$bo2"; r2=$(rc)
  t "chain" "...the chain's image_items reads the output built from the real-apko tar shape too" bash -c "test $r1 = 0 && test $r2 = 0 && cd '$CHAIN_BINDER_DIR' && python3 -I -B -c \"import sys; sys.path.insert(0,'bin'); import chain_items as c; r=c.image_items('$bo2'); assert len(r)==10, r\""
  python3 - "$bo2" "$work/binder-digests2.json" <<'PY'
import json, sys
o = sys.argv[1]
json.dump({"image-production": open(o + "/production.digest").read().strip(), "image-fips": open(o + "/fips.digest").read().strip()}, open(sys.argv[2], "w"))
PY
  t "chain" "...and check-bind.py accepts it" bash -c "cd '$CHAIN_BINDER_DIR' && python3 -I -B bin/check-bind.py --digests '$work/binder-digests2.json' --images '$bo2'"
  if [ -n "${CHAIN_BINDER_KEEP:-}" ]; then   # keep the two output trees and their digest lists for a by-hand run (the directory must not exist)
    mkdir "$CHAIN_BINDER_KEEP" && cp -R "$bo" "$CHAIN_BINDER_KEEP/std" && cp -R "$bo2" "$CHAIN_BINDER_KEEP/apko" && cp "$work/binder-digests.json" "$CHAIN_BINDER_KEEP/std.digests.json" && cp "$work/binder-digests2.json" "$CHAIN_BINDER_KEEP/apko.digests.json"
  fi
fi
# ===== REQ-IMAGE-001-AC12 and AC10 (owner-ratified build-script rules 1 and 2, Oct 14 2026): tests first, RED until the scripts are converted ======
# The production files carry no test hook (a trailing TEST-SUBST marker is not a hook: the tests run a copy that differs only on those lines, as REQ-BUILDAPK-001-AC3 states) and bin/assemble-image.sh has none of the five test-only options. Run-time proof for the options: the real
# script runs from the repository root with a search path of coreutils and a uname that says Linux, so a refused option is refused before any tool.
imgs_scripts="bin/assemble-image.sh bin/lock-proof.sh bin/sealed-proof.sh bin/apko-lock.sh"
# ---- AC12: no test hook in any of the four scripts -------------------------------------------------------------------------------
for s in $imgs_scripts; do
  if [ ! -f "$root/$s" ]; then bad AC12 "$s exists"; continue; fi
  if grep -Eq 'FSCACHE_TEST_MODE|ASSEMBLE_WORK_DIR|[$][{]?TEST_' "$root/$s"; then
    bad AC12 "$s mentions a test hook or test mode ($(grep -Eo 'FSCACHE_TEST_MODE|ASSEMBLE_WORK_DIR|[$][{]?TEST_[A-Z_]*' "$root/$s" | sort -u | tr '\n' ' '))"
  else ok; fi
done

# ---- AC10: the five options do not exist, in any mode ----------------------------------------------------------------------------
imgs_rp="$work/imgs_rp"; mkdir -p "$imgs_rp"
for c in awk basename cat cp cut dirname find grep head mkdir mktemp mv rm sed sort tail tr pwd; do
  p=$(command -v "$c") && [ -x "$p" ] && ln -s "$p" "$imgs_rp/$c"
done
printf '#!/bin/sh\necho Linux\n' >"$imgs_rp/uname"; chmod +x "$imgs_rp/uname"
bash_bin=$(command -v bash)
for opt in --apko-config --base-lock --render-dir --index-record --key-record; do
  for mode in "" 1; do
    log="$work/opt.log"
    ( cd "$air" && env -i PATH="$imgs_rp" ${mode:+FSCACHE_TEST_MODE=$mode} SOURCE_DATE_EPOCH=1700000000 \
        "$bash_bin" "$air/bin/assemble-image.sh" --variant production --version 0.3.0 "$opt" /nonexistent >"$log" 2>&1 </dev/null ); rc=$?
    if [ "$rc" = 2 ] && grep -Eqi "unknown (argument|option)" "$log"; then ok
    else bad AC10 "assemble-image.sh $opt${mode:+ (test mode set)} is not refused as an unknown option (exit $rc: $(tail -1 "$log" | cut -c1-160))"; fi
  done
done
# ===== review round 1 of PR 352: the findings of both seats, one test each (tests first, then the fix; both are in this commit series) =================
# B2: the TEST-SUBST lines of a production script are plain assignments (a tool path, /work, a render directory): nothing else can hide on a substituted
# line, and each tested copy differs from the production file on those lines only
t "AC12" "every TEST-SUBST line of the five scripts is ONE plain assignment of an allowed variable to a bare path (no command, redirection, expansion or relative tool path), the guard itself rejects the command-bearing examples, and each tested copy differs from its production file only on those lines" python3 - "$root" "$air" <<'P'
import re, sys
root, air = sys.argv[1:3]
ALLOWED = {
    "assemble-image.sh": {"HOST_OS", "PY3", "SUDO", "UNSHARE", "BASHBIN", "APKO", "ENVBIN", "WORKDIR", "RENDER_DIR"},
    "lock-proof.sh": {"HOST_OS", "PY3", "SUDO", "BASHBIN"},
    "sealed-proof.sh": {"HOST_OS", "PY3", "SUDO", "UNSHARE", "BASHBIN"},
    "apko-lock.sh": {"PY3"},
    "build-apk.sh": {"PY3", "GIT", "SUDO", "UNSHARE", "MELANGE", "GO_TOOL", "SHA256SUM", "ENVBIN", "SEALED_ENV", "RECIPE_STANDARD", "RECIPE_FIPS", "FIPS_MODULE"},
}
ABS = r"/[A-Za-z0-9_./+-]+"
CLASS = {   # each variable has ITS OWN right-hand side: a tool is an absolute path, nothing else
    "PY3": ABS, "SUDO": ABS, "UNSHARE": ABS, "BASHBIN": ABS, "APKO": ABS, "ENVBIN": ABS, "GIT": ABS, "MELANGE": ABS, "GO_TOOL": ABS, "SHA256SUM": ABS,
    "WORKDIR": ABS, "RENDER_DIR": r"", "HOST_OS": r"\$\{BASH_VERSINFO\[5\]\}",
    "SEALED_ENV": r"build/[A-Za-z0-9_./+-]+", "RECIPE_STANDARD": r"\$PWD/build/[A-Za-z0-9_./+-]+", "RECIPE_FIPS": r"\$PWD/build/[A-Za-z0-9_./+-]+",
    "FIPS_MODULE": r"\$PWD/build/[A-Za-z0-9_./+-]+",
}
LINE = re.compile(r"^([A-Z][A-Z0-9_]*)=(\S*)[ ]+# TEST-SUBST(?: .*)?$")
def plain(line, allowed):
    m = LINE.match(line)
    return bool(m) and m.group(1) in allowed and m.group(1) in CLASS and re.fullmatch(CLASS[m.group(1)], m.group(2)) is not None
bad = []
# the guard rejects what could hide behaviour on a substituted line
for ex in ("PY3=/usr/bin/python3 exit 0 # TEST-SUBST", "PY3=/usr/bin/python3 false # TEST-SUBST", "PY3=$UNLISTED # TEST-SUBST",
           "PY3=relative/python3 # TEST-SUBST", "PY3=/usr/bin/python3 > /tmp/x # TEST-SUBST", "PY3= # TEST-SUBST", "PY3=build/python3 # TEST-SUBST",
           "PY3=$OSTYPE # TEST-SUBST", "SUDO=$PWD/wrong # TEST-SUBST", "HOST_OS=$OSTYPE # TEST-SUBST", "RENDER_DIR=/tmp/x # TEST-SUBST", "PY3=/usr/bin/python3; exit 0 # TEST-SUBST",
           "EVIL=/usr/bin/true # TEST-SUBST", "PY3=$(id) # TEST-SUBST", "PY3=/usr/bin/python3 && exit 0 # TEST-SUBST"):
    if plain(ex, ALLOWED["assemble-image.sh"]):
        bad.append("the guard accepts %r" % ex)
for name, allowed in ALLOWED.items():
    prod = open("%s/bin/%s" % (root, name)).read().split("\n")
    copy = open("%s/bin/%s" % (air, name)).read().split("\n")
    if len(prod) != len(copy):
        bad.append("%s: %d lines in production, %d in the copy" % (name, len(prod), len(copy))); continue
    marked = 0
    for i, (a, b) in enumerate(zip(prod, copy), 1):
        if re.search(r"#\s*TEST-SUBST", a):
            marked += 1
            if not plain(a, allowed):
                bad.append("%s:%d: %r is not a plain assignment of an allowed variable" % (name, i, a[:90]))
        elif a != b:
            bad.append("%s:%d differs outside a TEST-SUBST line" % (name, i))
    if not marked:
        bad.append("%s has no TEST-SUBST line" % name)
print("\n".join(bad))
sys.exit(1 if bad else 0)
P
# AC9/AC10 "before any tool": the working-directory, host and version refusals run with a search path that holds NOTHING (every external command
# would be "not found"), so they are the shell's own
nopath=$(mktemp -d "$work/nopath.XXXXXX"); bash_abs=$(command -v bash)
# tripwires: every fixed-path tool of the copies points at a script that only records that it was called (PATH does not matter for an absolute path)
printf '#!/bin/sh\necho "$0 $*" >>"$TRIP_LOG"\nexit 0\n' >"$work/trip.sh"; chmod +x "$work/trip.sh"
trip_env=(TEST_PY3="$work/trip.sh" TEST_SUDO="$work/trip.sh" TEST_UNSHARE="$work/trip.sh" TEST_APKO="$work/trip.sh" TEST_GIT="$work/trip.sh" TEST_MELANGE="$work/trip.sh" TEST_GO="$work/trip.sh" TEST_SHA256SUM="$work/trip.sh" TRIP_LOG="$work/trip.log")
early() { # <script> <cwd> <args...>: the copy, started by absolute path, PATH an empty directory, every tool a tripwire; $work/early.rc, .log and trip.log
  local sc=$1 cwd=$2; shift 2; : >"$work/trip.log"
  ( cd "$cwd" && env -i PATH="$nopath" HOME="$work" SOURCE_DATE_EPOCH=$SDE ImageOS=ubuntu24 ImageVersion=1 "${trip_env[@]}" "$bash_abs" "$sc" "$@" ) >"$work/early.log" 2>&1 </dev/null; echo $? >"$work/early.rc"; }
early "$air/bin/assemble-image.sh" "$air" --variant production --version v0.3.0 --archive /x --melange-repo /x --keyring-dir /x --out /x
t "AC9" "assemble-image.sh: a bad --version is refused (exit 2, names the version) before ANY tool: no external command is found and no fixed-path tool is called (tripwires)" bash -c "test \"\$(cat '$work/early.rc')\" = 2 && grep -q 'v0.3.0' '$work/early.log' && ! grep -qi 'not found' '$work/early.log' && test ! -s '$work/trip.log'"
# the tripwire is not vacuous: a mutant that runs the fixed-path python before the version guard is seen
am="$work/air-trip"; rm -rf "$am"; cp -RP "$air" "$am"; rm -f "$am/bin/assemble-image.sh"; cp "$air/bin/assemble-image.sh" "$am/bin/assemble-image.sh"
python3 - "$am/bin/assemble-image.sh" <<'PYM'
import sys
p = sys.argv[1]; s = open(p).read()
k = s.index("# the version grammar first")
open(p, "w").write(s[:k] + '"$PY3" -I -B -c 0   # mutant: a fixed-path tool before the shell-only version guard\n' + s[k:])
PYM
early "$am/bin/assemble-image.sh" "$am" --variant production --version v0.3.0 --archive /x --melange-repo /x --keyring-dir /x --out /x
t "AC9" "...and the tripwire sees a fixed-path python call placed before the version guard (a mutant), though PATH is empty and the refusal text is unchanged" bash -c "test \"\$(cat '$work/early.rc')\" = 2 && test -s '$work/trip.log'"
for sc in assemble-image lock-proof sealed-proof; do
  early "$air/bin/$sc.sh" "$work" --variant production
  t "AC10" "$sc.sh run from another working directory is refused (exit 2, names the repository root) before ANY tool (no external command found, no fixed-path tool called)" bash -c "test \"\$(cat '$work/early.rc')\" = 2 && grep -qi 'repository root' '$work/early.log' && ! grep -qi 'not found' '$work/early.log' && test ! -s '$work/trip.log'"
done
for sc in assemble-image lock-proof sealed-proof; do
  : >"$work/trip.log"
  ( cd "$air" && env -i PATH="$nopath" HOME="$work" TEST_HOST_OS=darwin24 "${trip_env[@]}" "$bash_abs" "$air/bin/$sc.sh" --variant production ) >"$work/early.log" 2>&1 </dev/null; echo $? >"$work/early.rc"
  t "AC12" "$sc.sh on a non-Linux host is refused (exit 2, names Linux) before ANY tool (no external command found, no fixed-path tool called)" bash -c "test \"\$(cat '$work/early.rc')\" = 2 && grep -qi 'linux' '$work/early.log' && ! grep -qi 'not found' '$work/early.log' && test ! -s '$work/trip.log'"
done
# B5/B6: a blob nothing refers to must still hash to its name; a repeated lock entry is refused, not merged
python3 - "$oc/good.tar" "$work/orphan.tar" <<'P'
import io, sys, tarfile
src, dst = sys.argv[1:3]
with tarfile.open(src) as s, tarfile.open(dst, "w") as d:
    for m in s.getmembers():
        d.addfile(m, s.extractfile(m) if m.isfile() else None)
    ti = tarfile.TarInfo("blobs/sha256/" + "0" * 64); ti.size = 1; ti.mode = 0o644
    d.addfile(ti, io.BytesIO(b"x"))
P
python3 "$OD" "$oc/good.tar" >"$work/dg-good.out" 2>&1; dg_good=$?
python3 "$OD" "$work/orphan.tar" >"$work/dg-orphan.out" 2>&1; dg_orphan=$?
t "AC1" "oci-digest.py TAR (digest only): the good tar succeeds and a tar with one corrupt UNREFERENCED blob is refused, naming the blob (the unpack path already did)" bash -c "test $dg_good = 0 && test $dg_orphan != 0 && grep -q 'does not hash to its name' '$work/dg-orphan.out'"
python3 - "$BL" "$work/dup.lock.json" <<'P'
import json, sys
d = json.load(open(sys.argv[1])); d["contents"]["packages"].append(dict(d["contents"]["packages"][0]))
json.dump(d, open(sys.argv[2], "w"))
P
( cd "$air" && bash bin/apko-lock.sh arch-check "$work/dup.lock.json" >"$work/dup.out" 2>&1; echo $? >"$work/dup.rc" )
t "AC4" "apko-lock.sh arch-check refuses a lock that lists one package twice (exit 2, naming 'more than once'): a set comparison would have merged it" bash -c "test \"\$(cat '$work/dup.rc')\" = 2 && grep -q 'more than once' '$work/dup.out'"
( cd "$air" && bash bin/apko-lock.sh verify-archive --lock "$BL" --archive "$work/no-such-archive" >"$work/dup2.out" 2>&1; echo $? >"$work/dup2.rc" )
python3 - "$BL" "$work/empty.lock.json" <<'P'
import json, sys
d = json.load(open(sys.argv[1])); d["contents"]["packages"] = []
json.dump(d, open(sys.argv[2], "w"))
P
( cd "$air" && bash bin/apko-lock.sh verify-archive --lock "$work/empty.lock.json" --archive "$work/no-such-archive" >"$work/empty.out" 2>&1; echo $? >"$work/empty.rc" )
t "AC5" "apko-lock.sh verify-archive refuses an EMPTY lock (it would verify nothing) and a lock against an archive directory that is not there" bash -c "test \"\$(cat '$work/empty.rc')\" != 0 && grep -qi 'no package\|empty' '$work/empty.out'"
# B8: a relative --archive, --out, --melange-repo and --keyring-dir mean the same thing for lock-proof as for the assembler (the proof changes directory)
rm -rf "$air/build"; cp -RP "$root/build" "$air/build"; cp "$fx/apko.yaml" "$air/build/apko.yaml"; cp "$BL" "$air/build/locks/apko.base.lock.json"
cp "$idxrec" "$air/build/locks/archive-index.sha256"; cp "$keyrec" "$air/build/locks/archive-keys.sha256"
rm -rf "$air/rel"; mkdir -p "$air/rel"; cp -R "$fx/archive" "$air/rel/archive"; cp -R "$fx/melrepo" "$air/rel/melrepo"; cp -R "$fx/keyring" "$air/rel/keyring"
lpr_out="$air/rel/out"
run_s "${aie[@]}" bash -c 'cd "$0" && exec "$@"' "$air" "$air/bin/lock-proof.sh" --out rel/out --archive rel/archive -- --variant production --version 0.3.0 --melange-repo rel/melrepo --keyring-dir rel/keyring
t "AC12" "lock-proof.sh with RELATIVE --archive, --out, --melange-repo and --keyring-dir: the positive control and the four cases pass and the record is written where --out says" bash -c "test \"\$(cat '$work/rc')\" = 0 && test -s '$lpr_out/lock-proof.json'"
rm -rf "$air/build" "$air/rel"
# B4: an inconclusive control is not a proof: the probe that cannot start inside the namespace, and a namespace that cannot run a command at all
sf "rule 40" "sealed-proof: a probe that exits 127 inside the namespace is inconclusive, not 'blocked' (the proof fails naming the probe)" 'inconclusive' "${spe[@]}" "$SP" --out "$(mo)" --probe 'test -z "${FAKE_SEALED:-}" || exit 127' "${sp_common[@]}"
sf "rule 40" "sealed-proof: when 'sudo unshare -n' cannot run a command at all the control is inconclusive (the proof fails naming unshare)" 'inconclusive' env TEST_UNSHARE=unshare-is-not-installed "${spe[@]}" "$SP" --out "$(mo)" --probe 'test -z "${FAKE_SEALED:-}"' "${sp_common[@]}"
# B3: the build-level package negative (rule 41): a declared package deleted from the build's own repository must stop the real build, and the record names it
spo2=$(mo); run_s "${spe[@]}" STUB_REQUIRE_REPO=1 "$SP" --out "$spo2" --probe 'test -z "${FAKE_SEALED:-}"' "${sp_common[@]}"
t "rule 41" "sealed-proof: a declared package deleted from the build repository makes the real build fail (the melange stub selects its pinned packages), and the record names the build negative" bash -c "test \"\$(cat '$work/rc')\" = 0 && python3 - '$spo2/sealed-record.json' <<'P'
import json, sys
n = json.load(open(sys.argv[1]))['negatives']['build-package-deleted']
assert n['result'] == 'failed-as-required' and n['reason'], n
P"
cat >"$work/vendor-only.sh" <<'S'
#!/bin/bash
d=; while [ $# -gt 0 ]; do [ "$1" = --source-dir ] && d=$2; shift; done
case "$d" in */src-copy) echo "build-apk.sh: $d/vendor is missing" >&2; exit 2;; esac
exit 0
S
chmod +x "$work/vendor-only.sh"
sf "rule 41" "sealed-proof: if the build still succeeds with a declared package deleted from its repository the proof fails naming the package" 'package' "${spe[@]}" "$SP" --out "$(mo)" --probe 'test -z "${FAKE_SEALED:-}"' --build-script "$work/vendor-only.sh" "${sp_common[@]}"
# review round 1 (seats A and B, "no effective assertion"): an ordinary apko failure is exit 1 and the namespace probe is NOT run; the other variant's
# files in a shared --out are byte-for-byte unchanged by an assembly of this variant
run_s "${aie[@]}" STUB_FAIL=1 "$AI" "${ai_args[@]}" --out "$(mo)"
t "AC5" "an ordinary apko failure (no network text) exits 1 naming the failed call and never runs the namespace probe (no 'unshare -n python3 ... net-probe.py' call)" bash -c "test \"\$(cat '$work/rc')\" = 1 && grep -Eq 'apko (lock|build) failed \\(exit' '$work/log' && ! grep -q 'net-probe.py' '$CALLS'"
shared=$(mo); mkdir -p "$shared/fips/blobs/sha256" "$shared/fips-sbom"
printf 'fips-digest-bytes\n' >"$shared/fips.digest"; printf 'amd64 sha256:aa\narm64 sha256:bb\n' >"$shared/fips.manifests"; printf '{}' >"$shared/fips.full.lock.json"
printf 'layout' >"$shared/fips/oci-layout"; printf 'blob' >"$shared/fips/blobs/sha256/cc"; printf 'sbom' >"$shared/fips-sbom/sbom.json"
fips_snap() { ( cd "$shared" && find fips fips.digest fips.manifests fips.full.lock.json fips-sbom -type f | LC_ALL=C sort | while read -r f; do cksum "$f"; done ); }
fips_snap >"$work/fips-before.txt"
run_s "${aie[@]}" "$AI" "${ai_args[@]}" --out "$shared"
prod_rc=$(rc)
fips_snap >"$work/fips-after.txt"
t "AC2" "assembling production into an OUT that already holds the fips variant leaves every fips file byte-for-byte unchanged (and the assembly succeeds)" bash -c "test $prod_rc = 0 && test -s '$shared/production.digest' && test \$(wc -l <'$work/fips-before.txt') = 6 && cmp -s '$work/fips-before.txt' '$work/fips-after.txt'"
# ===== review round 2 of PR 352 ==============================================================================================================
# F1 (both seats): the recorded index is what is used; an absent, dangling or empty APKINDEX.tar.gz pointer must not stop a rebuild of an old tag
for variant_ in absent dangling empty; do
  d_="$work/ia-ptr-$variant_"; mkarch "$d_"; mkversioned "$d_"
  for a_ in x86_64 aarch64; do
    rm -f "$d_/$a_/APKINDEX.tar.gz"
    case $variant_ in dangling) ln -s "index/no-such-newer-index.tar.gz" "$d_/$a_/APKINDEX.tar.gz";; empty) : >"$d_/$a_/APKINDEX.tar.gz";; esac
  done
  fixed12 archive="$d_"; sd "rule 31" "a rebuild with the pointer APKINDEX.tar.gz $variant_ (the recorded index is present in index/): assembly succeeds and apko is run" '^apko build ' "${aie[@]}" "$AI" "${w12[@]}" --index-record "$idxrec"
done
# F3 (both seats): only exit 1 inside the namespace means "could not reach out"; a killed (137, 143) or erroring (2) probe is inconclusive
for st_ in 137 143 2; do
  sf "rule 40" "sealed-proof: a probe that exits $st_ inside the namespace is inconclusive, not 'blocked'" 'inconclusive' "${spe[@]}" "$SP" --out "$(mo)" --probe "test -z \"\${FAKE_SEALED:-}\" || exit $st_" "${sp_common[@]}"
done
# F4 (both seats): the record names the index of the repository the PACKAGE BUILD used, apart from the image archive's recorded index
t "rule 42" "sealed-proof: the record's build_repository_index is the sha256 of the build repository's own index and is not the image archive's recorded index" python3 - "$spo2/sealed-record.json" "$fx/envrepo/x86_64/APKINDEX.tar.gz" <<'P'
import hashlib, json, sys
d = json.load(open(sys.argv[1]))
want = "sha256:" + hashlib.sha256(open(sys.argv[2], "rb").read()).hexdigest()
assert d["build_repository_index"] == {"x86_64": want}, d["build_repository_index"]
assert d["build_repository_index"]["x86_64"] != d["archive_index"]["x86_64"], d
P
# F5 (seat B): a build that fails with the package's name only in an unrelated diagnostic does not prove rule 41
# F8 (seat A, R5 of seat B): config and layer descriptor media types and sizes are checked (a layout whose hashes are all right but whose descriptors lie is refused)
python3 - "$work" <<'P'
import hashlib, io, json, sys, tarfile
work = sys.argv[1]
H = lambda b: hashlib.sha256(b).hexdigest()
def build(name, cfg_mt="application/vnd.oci.image.config.v1+json", layer_mt="application/vnd.oci.image.layer.v1.tar+gzip", cfg_size=None, layer_size=None):
    blobs, mans = [], []
    for arch in ("amd64", "arm64"):
        cfg = json.dumps({"architecture": arch, "os": "linux"}, sort_keys=True).encode()
        layer = ("layer-" + arch).encode()
        man = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                          "config": {"mediaType": cfg_mt, "digest": "sha256:" + H(cfg), "size": len(cfg) if cfg_size is None else cfg_size},
                          "layers": [{"mediaType": layer_mt, "digest": "sha256:" + H(layer), "size": len(layer) if layer_size is None else layer_size}]}, sort_keys=True).encode()
        blobs += [cfg, layer, man]
        mans.append({"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:" + H(man), "size": len(man), "platform": {"architecture": arch, "os": "linux"}})
    idx = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": mans}, sort_keys=True).encode()
    top = json.dumps({"schemaVersion": 2, "manifests": [{"mediaType": "application/vnd.oci.image.index.v1+json", "digest": "sha256:" + H(idx), "size": len(idx)}]}, sort_keys=True).encode()
    members = [("oci-layout", b'{"imageLayoutVersion":"1.0.0"}'), ("index.json", top), ("blobs/sha256/" + H(idx), idx)] + [("blobs/sha256/" + H(b), b) for b in blobs]
    with tarfile.open("%s/%s.tar" % (work, name), "w") as t:
        for n, b in members:
            ti = tarfile.TarInfo(n); ti.size = len(b); ti.mode = 0o644; t.addfile(ti, io.BytesIO(b))
build("oci-ok"); build("oci-cfg-mt", cfg_mt="application/x-invalid"); build("oci-layer-mt", layer_mt="application/x-invalid")
build("oci-cfg-size", cfg_size=0); build("oci-layer-size", layer_size=1)
P
python3 "$OD" "$work/oci-ok.tar" >"$work/oci-ok.out" 2>&1; oci_ok=$?
t "BT-002-AC1" "a layout with right hashes, config and layer media types and sizes is accepted by the digest-only read" test "$oci_ok" = 0
for v_ in cfg-mt layer-mt cfg-size layer-size; do
  python3 "$OD" "$work/oci-$v_.tar" >"$work/oci-$v_.out" 2>&1; r_=$?
  t "BT-002-AC1" "a layout whose $v_ descriptor lies (all hashes right) is refused by the digest-only read" bash -c "test $r_ != 0 && grep -Eqi 'media type|size' '$work/oci-$v_.out'"
done
# ===== review round 3 of PR 352 ==============================================================================================================
# B1 (both seats): the host guard is not caller input: an inherited OSTYPE does not change what the unchanged production file decides
bash_host=$(bash -c 'printf %s "${BASH_VERSINFO[5]}"')
case $bash_host in *linux*) fake_ostype=darwin24; want_refusal=0;; *) fake_ostype=linux-gnu; want_refusal=1;; esac
( cd "$root" && env OSTYPE=$fake_ostype "$bash_abs" bin/assemble-image.sh --variant production --version v0.3.0 --archive /x --melange-repo /x --keyring-dir /x --out /x ) >"$work/hostenv.log" 2>&1 </dev/null; echo $? >"$work/hostenv.rc"
if [ $want_refusal = 1 ]; then
  t "AC12" "the UNCHANGED production assemble-image.sh on this non-Linux host still refuses when the environment claims OSTYPE=linux-gnu (the host is the running bash's own build host)" bash -c "test \"\$(cat '$work/hostenv.rc')\" = 2 && grep -qi 'refusing to run on' '$work/hostenv.log'"
else
  t "AC12" "the UNCHANGED production assemble-image.sh on this Linux host does not refuse when the environment claims OSTYPE=darwin24 (it reaches the version refusal)" bash -c "test \"\$(cat '$work/hostenv.rc')\" = 2 && ! grep -qi 'refusing to run on' '$work/hostenv.log' && grep -q 'v0.3.0' '$work/hostenv.log'"
fi
# B4 (seat B): the structural AC10 checks read the production file, and a python3 -c written through the fixed variable is caught too
nogrep "chain" "assemble-image.sh never assigns PATH, IFS, BASH_ENV, ENV, LD_* or PYTHON* (production file)" '(^|[^A-Za-z_$])(export +)?(PATH|IFS|BASH_ENV|ENV|LD_[A-Z_]+|PYTHON[A-Z_]*)=' "$AI_PROD"
nogrep "chain" "assemble-image.sh runs no python -c and no python heredoc, however the interpreter is written (python3, \$PY3)" '(python3?|"?\$PY3"?)( +-[IBEsS])* +-c[ =]|(python3?|"?\$PY3"?)( +-[IBEsS])* +-( |$)|<<.?PY' "$AI_PROD"
# B6 (seat B): every python call keeps -I -B, and the scripts read no caller variable beyond the closed list
t "AC12" "in the four image scripts every python invocation through \$PY3 is '\"\$PY3\" -I -B', and no variable is read that the script does not assign, outside SOURCE_DATE_EPOCH, ImageOS and ImageVersion" python3 - "$root" <<'P'
import re, sys
root = sys.argv[1]
bad = []
SPECIAL = {"SOURCE_DATE_EPOCH", "ImageOS", "ImageVersion", "BASH_SOURCE", "BASH_VERSINFO", "PWD", "OLDPWD", "HOME", "LINENO", "OPTARG"}
for name in ("assemble-image.sh", "lock-proof.sh", "sealed-proof.sh", "apko-lock.sh"):
    s = open("%s/bin/%s" % (root, name)).read()
    code = "\n".join(l for l in s.split("\n") if not l.lstrip().startswith("#"))
    for m in re.finditer(r'"\$PY3"([^\n]{0,12})', code):
        if not m.group(1).startswith(" -I -B"):
            bad.append("%s: a $PY3 call without -I -B: %r" % (name, m.group(0)))
    assigned = set(re.findall(r"(?m)^\s*(?:local\s+|export\s+|declare\s+(?:-[a-zA-Z]+\s+)?)?([A-Za-z_][A-Za-z0-9_]*)\+?=", code))
    assigned |= set(re.findall(r"\bfor\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\b", code)) | set(re.findall(r"\bread\s+(?:-[a-z]+\s+)*([A-Za-z_][A-Za-z0-9_]*)", code))
    assigned |= set(re.findall(r"(?<![A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]*)=\$\(", code)) | set(re.findall(r"(?<![A-Za-z0-9_$])([a-z][A-Za-z0-9_]*)=", code))
    for v in set(re.findall(r"\$\{?([A-Z][A-Za-z0-9_]*)", code)):
        if v not in assigned and v not in SPECIAL and not v.isdigit():
            bad.append("%s reads %s, which it does not assign and which is not on the closed list" % (name, v))
print("\n".join(bad)); sys.exit(1 if bad else 0)
P
# B3 (round 3 and 4, both seats): the build-level package negative is DIFFERENTIAL, not a reading of diagnostics: the build succeeds with the package in
# its repository, fails with only that package removed, and succeeds again with the repository restored. No failure text is interpreted.
bn=$(LC_ALL=C sort "$fx/melange.lock" | head -1 | cut -d: -f1)
mk_build_stand() { # <file> <what the stand-in does for the repository negative: fail|ok>
  { printf '#!/bin/bash\nd=; r=; while [ $# -gt 0 ]; do [ "$1" = --source-dir ] && d=$2; [ "$1" = --repo ] && r=$2; shift; done\n'
    printf 'case "$d" in */src-copy) echo "build-apk.sh: $d/vendor is missing" >&2; exit 2;; esac\n'
    printf 'case "$r" in */repo-nopkg) echo "build-apk.sh: cache for %s not found" >&2; exit 1;; */repo-restored) %s;; esac\nexit 0\n' "$bn" "$2"; } >"$1"; chmod +x "$1"; }
mk_build_stand "$work/stand-diff-ok.sh" ":"
run_s "${spe[@]}" "$SP" --out "$(mo)" --probe 'test -z "${FAKE_SEALED:-}"' --build-script "$work/stand-diff-ok.sh" "${sp_common[@]}"
t "rule 41" "sealed-proof: a build that fails only without the removed package and succeeds with it restored is accepted (the proof reads no diagnostic: 'cache for $bn not found' is enough)" test "$(rc)" = 0
mk_build_stand "$work/stand-diff-flaky.sh" 'echo "build-apk.sh: transient failure" >&2; exit 1'
sf "rule 41" "sealed-proof: a build that also fails with the package restored proves nothing about the package: inconclusive, the proof fails" 'inconclusive|restored' "${spe[@]}" "$SP" --out "$(mo)" --probe 'test -z "${FAKE_SEALED:-}"' --build-script "$work/stand-diff-flaky.sh" "${sp_common[@]}"
# B5 / R1 (both seats): the written layout is closed (index -> manifests -> config and layers present, hashed, sized), and every descriptor's size is checked
cat >"$work/closure.py" <<'P'
import hashlib, json, os, sys
d = sys.argv[1]
blob = lambda dig: open(os.path.join(d, "blobs", "sha256", dig.split(":")[1]), "rb").read()
def check(desc, what):
    raw = blob(desc["digest"])
    assert hashlib.sha256(raw).hexdigest() == desc["digest"].split(":")[1], what + ": hash"
    assert len(raw) == desc["size"], what + ": size"
    return raw
top = json.load(open(os.path.join(d, "index.json")))
idx = json.loads(check(top["manifests"][0], "index"))
n = 0
for m in idx["manifests"]:
    man = json.loads(check(m, "manifest"))
    check(man["config"], "config"); n += 1
    assert man["layers"], "no layers"
    for l in man["layers"]: check(l, "layer"); n += 1
assert n >= 4, n
print("closed:", n)
P
t "BT-002-AC3" "the assembled production layout is closed: index, every manifest, config and layer is present, hashes to its name and has its descriptor's size" python3 "$work/closure.py" "$rp_out/production"
t "BT-002-AC3" "the layout unpacked by oci-digest.py is closed in the same way" python3 "$work/closure.py" "$ud/empty"
rm -rf "$work/closure-mut"; cp -R "$rp_out/production" "$work/closure-mut"
lay_=$(python3 - "$work/closure-mut" <<'P'
import json, os, sys
d = sys.argv[1]
idx = json.load(open(d + "/index.json"))["manifests"][0]["digest"].split(":")[1]
im = json.load(open("%s/blobs/sha256/%s" % (d, idx)))["manifests"][0]["digest"].split(":")[1]
man = json.load(open("%s/blobs/sha256/%s" % (d, im)))
print(man["layers"][0]["digest"].split(":")[1])
P
)
rm -f "$work/closure-mut/blobs/sha256/$lay_"
t "BT-002-AC3" "the closure check fails on a layout from which a layer blob was dropped (the check is not vacuous)" bash -c "! python3 '$work/closure.py' '$work/closure-mut' >/dev/null 2>&1"
python3 - "$work" <<'P'
import hashlib, io, json, sys, tarfile
work = sys.argv[1]
H = lambda b: hashlib.sha256(b).hexdigest()
def build(name, idx_size=None, man_size=None, apko=False):
    blobs, mans, members = [], [], []
    for arch in ("amd64", "arm64"):
        cfg = json.dumps({"architecture": arch, "os": "linux"}, sort_keys=True).encode(); layer = ("layer-" + arch).encode()
        man = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                          "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": "sha256:" + H(cfg), "size": len(cfg)},
                          "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "sha256:" + H(layer), "size": len(layer)}]}, sort_keys=True).encode()
        blobs += [cfg, layer, man]
        mans.append({"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:" + H(man),
                     "size": len(man) if man_size is None else man_size, "platform": {"architecture": arch, "os": "linux"}})
    idx = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": mans}, sort_keys=True).encode()
    if apko:
        members = [("index.json", idx)] + [("sha256:" + H(b), b) for b in blobs]
    else:
        top = json.dumps({"schemaVersion": 2, "manifests": [{"mediaType": "application/vnd.oci.image.index.v1+json", "digest": "sha256:" + H(idx),
                                                              "size": len(idx) if idx_size is None else idx_size}]}, sort_keys=True).encode()
        members = [("oci-layout", b'{"imageLayoutVersion":"1.0.0"}'), ("index.json", top), ("blobs/sha256/" + H(idx), idx)] + [("blobs/sha256/" + H(b), b) for b in blobs]
    with tarfile.open("%s/%s.tar" % (work, name), "w") as t:
        for n, b in members:
            ti = tarfile.TarInfo(n); ti.size = len(b); ti.mode = 0o644; t.addfile(ti, io.BytesIO(b))
build("oci-idx-size", idx_size=0); build("oci-man-size", man_size=0); build("oci-apko-ok", apko=True); build("oci-apko-man-size", man_size=0, apko=True)
P
python3 "$OD" "$work/oci-apko-ok.tar" >"$work/oci-apko-ok.out" 2>&1; ak_=$?
t "BT-002-AC1" "an apko-shaped tar with right hashes and sizes is accepted" test "$ak_" = 0
for v_ in idx-size man-size apko-man-size; do
  python3 "$OD" "$work/oci-$v_.tar" >"$work/oci-$v_.out" 2>&1; r_=$?
  t "BT-002-AC1" "a layout whose $v_ descriptor lies (hashes right) is refused by the digest-only read, naming the size" bash -c "test $r_ != 0 && grep -qi 'size' '$work/oci-$v_.out'"
done
# R2 (seat B): the two result files of a direct unpack are never written through a link, onto each other or into the layout
rm -rf "$work/unp-side"; mkdir -p "$work/unp-side"; ln -s "$work/unp-side/target" "$work/unp-side/link.digest"
python3 "$OD" unpack "$oc/good.tar" "$work/unp-side/out1" "$work/unp-side/link.digest" "$work/unp-side/m1" >"$work/unp-side/1.out" 2>&1; s1=$?
python3 "$OD" unpack "$oc/good.tar" "$work/unp-side/out2" "$work/unp-side/same" "$work/unp-side/same" >"$work/unp-side/2.out" 2>&1; s2=$?
python3 "$OD" unpack "$oc/good.tar" "$work/unp-side/out3" "$work/unp-side/out3/inside.digest" "$work/unp-side/m3" >"$work/unp-side/3.out" 2>&1; s3=$?
t "BT-002-AC3" "unpack refuses a DIGEST that is a link, a DIGEST and MANIFESTS that are one file, and a result file inside the layout directory; nothing was written through the link" bash -c "test $s1 != 0 && test $s2 != 0 && test $s3 != 0 && test ! -e '$work/unp-side/target' && test ! -e '$work/unp-side/out1'"
# the remaining claims of the round-2 brief that had no test: probe status 126, a digest that cannot be computed, a linked --digests-out; and dup2's own assertion
sf "rule 40" "sealed-proof: a probe that exits 126 inside the namespace is inconclusive" 'inconclusive' "${spe[@]}" "$SP" --out "$(mo)" --probe 'test -z "${FAKE_SEALED:-}" || exit 126' "${sp_common[@]}"
printf '#!/bin/bash\ncase "$*" in *apk-tool.py*digest*) echo "apk-tool: cannot read the apk" >&2; exit 1;; esac\nexec %s "$@"\n' "$(command -v python3)" >"$work/pyfail.sh"; chmod +x "$work/pyfail.sh"
sf "rule 42" "sealed-proof: an apk digest that cannot be computed fails the proof (it is not recorded as empty)" 'digest' env TEST_PY3="$work/pyfail.sh" "${spe[@]}" "$SP" --out "$(mo)" --probe 'test -z "${FAKE_SEALED:-}"' "${sp_common[@]}"
rm -f "$work/dgo-target" "$work/dgo-link"; ln -s "$work/dgo-target" "$work/dgo-link"
sr2 "rule 42" "sealed-proof: a --digests-out that is a link is refused (exit 2) and nothing is written through it" 'link' run_s "${spe[@]}" "$SP" --out "$(mo)" --probe 'test -z "${FAKE_SEALED:-}"' --digests-out "$work/dgo-link" "${sp_common[@]}"
t "rule 42" "...and the link's target was not created" test ! -e "$work/dgo-target"
t "AC5" "apko-lock.sh verify-archive with a NON-EMPTY lock against an absent archive directory is refused (exit 2, naming the directory)" bash -c "test \"\$(cat '$work/dup2.rc')\" != 0 && grep -qi 'not a directory\|not found\|no such' '$work/dup2.out'"
# ===== review round 4 of PR 352 ==============================================================================================================
# B4 (seat A): the closed caller list is checked by READ ORDER (a name read before the line that assigns it, lower case included, a default expansion
# needing an earlier assignment), and the check is shown to see three mutations
cat >"$work/closed.py" <<'P'
import re, sys
SPECIAL = {"SOURCE_DATE_EPOCH", "ImageOS", "ImageVersion", "BASH_SOURCE", "BASH_VERSINFO", "PWD", "LINENO", "RANDOM", "PIPESTATUS", "BASH_REMATCH", "FUNCNAME"}   # the shell sets these itself; OPTARG, OLDPWD and the like are importable and not exempt
ASSIGN = re.compile(r"(?<![A-Za-z0-9_$])([A-Za-z_][A-Za-z0-9_]*)\+?=")
def strip(code):
    out = []
    for l in code.split("\n"):
        if l.lstrip().startswith("#"): continue
        out.append(re.sub(r"\s#\s.*$", "", l) if re.search(r"\s#\s", l) and "'" not in l and '"' not in l else l)
    return out
def assigned_in(ln):
    out = set(ASSIGN.findall(ln))
    out |= set(re.findall(r"\bfor\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\b", ln))
    out |= set(re.findall(r"\(\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", ln))
    for v in re.findall(r"\blocal\s+([A-Za-z_][A-Za-z0-9_ ]*)", ln): out.update(x for x in v.split() if re.fullmatch(r"[A-Za-z_]\w*", x))
    for m in re.finditer(r"\bread\s+([^;|&<)]*)", ln):
        toks = m.group(1).split(); k = 0
        while k < len(toks):
            if toks[k] in ("-d", "-n", "-N", "-p", "-t", "-u", "-a", "-i"): k += 2; continue
            if re.fullmatch(r"[A-Za-z_]\w*", toks[k]): out.add(toks[k])
            k += 1
    return out
def leaks(code):
    """a name read before the line that assigns it, at top level, or, inside a function body (which runs later), a name assigned nowhere in the file
    and not local to the function; a default expansion needs an earlier assignment; an assignment whose own right-hand side reads the name before any
    earlier assignment is a caller read too. Python embedded in the script may read only the closed environment names."""
    lines = strip(code)
    global_assigned = set()
    for ln in lines: global_assigned |= assigned_in(ln)
    assigned, bad, depth, heredoc_end, fn_locals = set(), [], 0, None, set()
    fn_assigned, d_, pre_end = set(), 0, None
    fn_assigned_before = set()
    for ln in lines:   # names assigned inside function bodies (a function runs when called: its globals are set by then)
        if pre_end is not None:
            if ln.strip() == pre_end: pre_end = None
            continue
        pm = re.search(r"<<-?\s*['\"]?([A-Za-z_]+)['\"]?\s*$", ln)
        fo = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\(\)\s*\{", ln)
        if d_ > 0 or fo:
            d_ += ln.count("{") - ln.count("}"); fn_assigned |= assigned_in(ln)
            if d_ < 0: d_ = 0
        if pm: pre_end = pm.group(1)
    for ln in lines:
        if heredoc_end is not None:
            if ln.strip() == heredoc_end: heredoc_end = None
            continue
        hm = re.search(r"<<-?\s*['\"]?([A-Za-z_]+)['\"]?\s*$", ln)
        fn_open = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\(\)\s*\{", ln)
        in_fn = depth > 0 or fn_open is not None
        if in_fn: depth += ln.count("{") - ln.count("}")
        if fn_open and depth <= 0: depth = 0
        if not in_fn: fn_locals = set()
        now = assigned_in(ln)
        for v in set(re.findall(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)", ln)):
            if v in SPECIAL: continue
            dflt = re.search(r"\$\{" + v + r"(:-|:=|:\+|-|\+|=)", ln)
            fm = re.search(r"(?<![A-Za-z0-9_$])" + v + r"=([^ ;|&]*)", ln)   # the FIRST assignment of the name on this line
            forv = set(re.findall(r"\bfor\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\b", ln)) | set(re.findall(r"\(\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", ln))
            selfref = bool(fm) and v not in forv and re.search(r"[$]\{?" + v + r"\b", fm.group(1)) is not None
            if in_fn:
                if dflt and v not in assigned and v not in fn_locals and v not in fn_assigned_before: 
                    bad.append("%s has a default expansion in a function and no earlier assignment: %s" % (v, ln.strip()[:80])); continue
                if v in global_assigned or v in fn_locals or v in now: continue
                bad.append("%s is read in a function body and assigned nowhere: %s" % (v, ln.strip()[:80])); continue
            if v in assigned or v in fn_assigned: continue
            if v in now and not dflt and not selfref: continue
            bad.append("%s is read before it is assigned: %s" % (v, ln.strip()[:80]))
        if in_fn: fn_locals |= now; fn_assigned_before |= now
        else: assigned |= now
        if hm: heredoc_end = hm.group(1)
    for ln in lines:
        if re.search(r"\bdeclare\s+-[a-zA-Z]*[pxfF]|\btypeset\s+-|\bcompgen\s+-[ve]|\bexport\s+-p|\bprintenv\b|\$\{![A-Za-z_]|(?:\btest|\[\[?)\s+(?:!\s+)?-[a-zA-Z]*v\s|\benv\s*\||\bset\s*\||\bread\s+-[a-z]*r?\s+[A-Za-z_]+\s*<\s*/proc", ln):
            bad.append("an environment introspection form: %s" % ln.strip()[:80])
        for am in re.finditer(r"\$\(\(([^)]*)\)\)|(?<![$])\(\(([^)]*)\)\)", ln):
            for v in re.findall(r"(?<![A-Za-z0-9_$#])([A-Za-z_][A-Za-z0-9_]*)\b(?!\s*\()", am.group(1) or am.group(2) or ""):
                if v not in assigned and v not in fn_assigned and v not in SPECIAL and not v.isdigit():
                    bad.append("%s is read in an arithmetic expression before any assignment: %s" % (v, ln.strip()[:80]))
    for m in re.finditer(r"os\.environ(?:\.get\(|\[)\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]|os\.getenv\(\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]", code):
        v = m.group(1) or m.group(2)
        if v not in ("ImageOS", "ImageVersion", "SOURCE_DATE_EPOCH"):
            bad.append("embedded python reads the environment variable %s" % v)
    return bad
if __name__ == "__main__":
    root = sys.argv[1]
    rc = 0
    for name in ("assemble-image.sh", "lock-proof.sh", "sealed-proof.sh", "apko-lock.sh"):
        src = open("%s/bin/%s" % (root, name)).read()
        for b in leaks(src):
            print("%s: %s" % (name, b)); rc = 1
    # the check must see these (it is not vacuous)
    base = open("%s/bin/assemble-image.sh" % root).read()
    inherit = base.replace("variant= version= archive=", "variant=$variant version= archive=", 1)   # the loop form
    inherit = inherit.replace("variant=$2;", "variant=$variant$2;", 1)   # the straight-line form
    for label, mut in (("a lowercase caller default", base.replace("set -euo pipefail\n", "set -euo pipefail\nversion=${caller_version:-x}\n", 1)),
                       ("an uppercase caller read", base.replace("set -euo pipefail\n", "set -euo pipefail\nfoo=$CALLER_SETTING\n", 1)),
                       ("a self-referential default before any assignment", base.replace("set -euo pipefail\n", "set -euo pipefail\nzzz=${zzz:-1}\n", 1)),
                       ("a function-local lowercase default", base + "f() { local errf=${caller_error_log:-x} rc; }\n"),
                       ("an initialisation that reads the inherited value", inherit),
                       ("a builtin inspection of a caller variable", base.replace("set -euo pipefail\n", "set -euo pipefail\nif declare -p AUDIT_UNLISTED_SETTING >/dev/null 2>&1; then exit 0; fi\n", 1)),
                       ("a function-local self-default", base + "f() { local zzf=${zzf:-x} rc; }\n"),
                       ("an arithmetic read of a caller variable", base.replace("set -euo pipefail\n", "set -euo pipefail\nzzn=$((CALLER_COUNT + 1))\n", 1)),
                       ("a test -v introspection", base.replace("set -euo pipefail\n", "set -euo pipefail\nif test -v AUDIT_SKIP_BUILD; then exit 0; fi\n", 1)),
                       ("a read of OPTARG", base.replace("set -euo pipefail\n", "set -euo pipefail\n: \"${OPTARG:-}\"\n", 1)),
                       ("an embedded python environment read", base.replace("set -euo pipefail\n", "set -euo pipefail\n: \"$(os.environ.get('CALLER_X'))\"\n", 1))):
        if not leaks(mut):
            print("the check does not see %s" % label); rc = 1
    sys.exit(rc)
P
t "AC12" "the four image scripts read no caller variable beyond SOURCE_DATE_EPOCH, ImageOS and ImageVersion (read-order check over every identifier, function bodies and embedded python included), and the check sees six mutations: lowercase and uppercase reads, self-referential defaults, a function-local default, an initialisation from the inherited value, an embedded environment read" python3 "$work/closed.py" "$root"
# B1 (seat B): a live address spelled with an escape sequence or quoting in the YAML is refused before any apko call
printf 'contents:\n  repositories:\n    - /work/archive\n    - "\\u0068ttps://packages.wolfi.dev/os"\n  keyring:\n    - /work/keyring/wolfi-signing.rsa.pub\n  packages:\n    - tzdata\n' >"$work/esc.yaml"
sr "rule 26" "assemble refuses a config whose repository scalar spells a live address with an escape sequence (\\u0068ttps://...), before any apko call" 'live repository|escape' "${aie[@]}" "$AI" "${ai_args[@]}" --apko-config "$work/esc.yaml" --out "$(mo)"
sed 's#- /work/melange-repo#- "/work/melange-repo"#' "$fx/apko.yaml" >"$work/quoted.yaml"
sr "rule 26" "assemble refuses a config whose repositories are not written plainly (a quoted entry): the closed grammar refuses what it cannot read" 'plain grammar' "${aie[@]}" "$AI" "${ai_args[@]}" --apko-config "$work/quoted.yaml" --out "$(mo)"
# B2 (seat A) / B6 (seat B): two distinct hard links to one file are the same file for unpack's result files
rm -rf "$work/unp-hl"; mkdir -p "$work/unp-hl"; : >"$work/unp-hl/one"; ln "$work/unp-hl/one" "$work/unp-hl/two"
python3 "$OD" unpack "$oc/good.tar" "$work/unp-hl/out" "$work/unp-hl/one" "$work/unp-hl/two" >"$work/unp-hl/o.txt" 2>&1; hl_=$?
t "BT-002-AC3" "unpack refuses DIGEST and MANIFESTS that are two hard links of one file (the second write would truncate the first), and writes nothing" bash -c "test $hl_ != 0 && grep -qi 'same file' '$work/unp-hl/o.txt' && test ! -e '$work/unp-hl/out' && test ! -s '$work/unp-hl/one'"
# B3 (seat B): --expect is read before --digests-out is written, and the two may not be one file
printf 'apk-nothing 0000\n' >"$work/exp-old.txt"; cp "$work/exp-old.txt" "$work/exp-keep.txt"
sf "rule 39" "sealed-proof: --digests-out naming the --expect file does not turn a changed build into a pass (refused, and the baseline file is unchanged)" 'same file|differ' "${spe[@]}" "$SP" --out "$(mo)" --probe 'test -z "${FAKE_SEALED:-}"' --expect "$work/exp-old.txt" --digests-out "$work/exp-old.txt" "${sp_common[@]}"
t "rule 39" "...and the baseline was not overwritten" cmp -s "$work/exp-old.txt" "$work/exp-keep.txt"
ln "$work/exp-old.txt" "$work/exp-hard.txt"
sf "rule 39" "sealed-proof: a --digests-out that is a hard link of the --expect file is refused too" 'same file|differ' "${spe[@]}" "$SP" --out "$(mo)" --probe 'test -z "${FAKE_SEALED:-}"' --expect "$work/exp-old.txt" --digests-out "$work/exp-hard.txt" "${sp_common[@]}"
# B7 (seat B): the lock the build consumes is the lock apko lock made, with our apk and both architectures
run_s "${aie[@]}" STUB_CAPTURE_LOCK="$work/consumed.lock.json" "$AI" "${ai_args[@]}" --out "$(mo)"
t "AC3" "the file apko build is given has exactly the content (parsed JSON equal) of the lock apko lock produced, holds our apk (fscache) for both architectures and every base package for both" python3 - "$work/consumed.lock.json" "$FL" <<'P'
import json, sys
got = json.load(open(sys.argv[1])); want = json.load(open(sys.argv[2]))
assert got == want, "the consumed lock is not the generated one"
pk = got["contents"]["packages"]
assert {e["architecture"] for e in pk if e["name"] == "fscache"} == {"x86_64", "aarch64"}
assert {e["architecture"] for e in pk if e["name"] == "tzdata"} == {"x86_64", "aarch64"}
P
# B5 (seat A): a FIPS assembly over an OUT that already holds production leaves every production file byte-for-byte unchanged (the other direction)
shared2=$(mo); mkdir -p "$shared2/production/blobs/sha256" "$shared2/production-sbom"
printf 'prod-digest-bytes\n' >"$shared2/production.digest"; printf 'amd64 sha256:aa\narm64 sha256:bb\n' >"$shared2/production.manifests"; printf '{"x":1}' >"$shared2/production.full.lock.json"
printf 'layout' >"$shared2/production/oci-layout"; printf 'blob' >"$shared2/production/blobs/sha256/cc"; printf 'sbom' >"$shared2/production-sbom/sbom.json"
prod_snap() { ( cd "$shared2" && find production production.digest production.manifests production.full.lock.json production-sbom -type f | LC_ALL=C sort | while read -r f; do cksum "$f"; done ); }
prod_snap >"$work/prod-before.txt"
run_s "${aie[@]}" "$AI" "${aif_args[@]}" --out "$shared2"
fips_rc2=$(rc)
prod_snap >"$work/prod-after.txt"
t "AC2" "assembling fips into an OUT that already holds production leaves every production file byte-for-byte unchanged (and the assembly succeeds)" bash -c "test $fips_rc2 = 0 && test -s '$shared2/fips.digest' && test \$(wc -l <'$work/prod-before.txt') = 6 && cmp -s '$work/prod-before.txt' '$work/prod-after.txt'"
# B3 (seat A), site by site: the exceptional call sites under the restricted path: the namespace probe after a network failure, and the cleanup fallback
rp_site() { # <air> <line pattern> <var> <tool> <env...>: a mutant of ONLY the lines matching the pattern, started with the restricted path and the trigger
  local a=$1 pat=$2 v=$3 tool=$4; shift 4
  local am="$work/air-site-$v-$$-$RANDOM"; rm -rf "$am"; cp -RP "$air" "$am"; rm -f "$am/bin/assemble-image.sh"; cp "$air/bin/assemble-image.sh" "$am/bin/assemble-image.sh"
  python3 - "$am/bin/assemble-image.sh" "$pat" "$v" "$tool" <<'PYM'
import sys
p, pat, v, tool = sys.argv[1:5]
lines = open(p).read().split("\n"); n = 0
for k, l in enumerate(lines):
    if pat in l and '"$%s"' % v in l:
        lines[k] = l.replace('"$%s"' % v, tool); n += 1
assert n > 0, (pat, v)
open(p, "w").write("\n".join(lines))
PYM
  rp_wrapper "$am" "$am/ai.sh"
  : >"$CALLS"
  env -i PATH="$rpd" HOME="$work" CALLS="$CALLS" STUB_LIB="$work/lib.py" SOURCE_DATE_EPOCH=$SDE STUB_LOCK="$FL" STUB_LOCK_FIPS="$fx/full-fips.lock.json" \
    TEST_SUDO="$rpw/sudo" TEST_UNSHARE="$rpw/unshare" TEST_APKO="$rpw/apko" "$@" "$am/ai.sh" "${ai_args[@]}" --out "$(mo)" >"$work/site.log" 2>&1 </dev/null; echo $? >"$work/site.rc"; }
rp_site "$air" 'net-probe.py' PY3 python3 STUB_NETATTEMPT=1
t "AC5" "the namespace probe's own python call: with python3 bare the network failure is NOT classified as exit 4 under the restricted path (the probe never ran)" bash -c "test \"\$(cat '$work/site.rc')\" != 4"
rp_site "$air" 'net-probe.py' SUDO true STUB_NETATTEMPT=1
: >"$CALLS"
env -i PATH="$rpd" HOME="$work" CALLS="$CALLS" STUB_LIB="$work/lib.py" SOURCE_DATE_EPOCH=$SDE STUB_LOCK="$FL" STUB_LOCK_FIPS="$fx/full-fips.lock.json" \
  TEST_SUDO="$rpw/sudo" TEST_UNSHARE="$rpw/unshare" TEST_APKO="$rpw/apko" STUB_NETATTEMPT=1 "$work/ai.sh" "${ai_args[@]}" --out "$(mo)" >"$work/site.log" 2>&1 </dev/null; echo $? >"$work/site.rc"
t "AC5" "the unmutated assembler under the restricted path classifies the same network failure as exit 4 (the probe ran through its fixed paths)" bash -c "test \"\$(cat '$work/site.rc')\" = 4"
rp_site "$air" 'rm -rf "$tmp"' SUDO sudo STUB_LOCKED_CACHE=1
site_cache=$(grep -Eo -- '--cache-dir [^ ]+' "$CALLS" | tail -1 | cut -d' ' -f2)
t "AC12" "the cleanup fallback (a tree the user cannot remove): with sudo called bare there the privileged removal is not made (no 'sudo ... rm -rf' call) although the assembly's own status is unchanged (0): the site is reached and is what the mutant breaks" bash -c "test -n '$site_cache' && test -d '$site_cache' && test \"\$(cat '$work/site.rc')\" = 0 && ! grep -q '^sudo .*rm -rf' '$CALLS'"
chmod -R u+w "$(dirname "$site_cache")" 2>/dev/null; rm -rf "$(dirname "$site_cache")"
: >"$CALLS"
env -i PATH="$rpd" HOME="$work" CALLS="$CALLS" STUB_LIB="$work/lib.py" SOURCE_DATE_EPOCH=$SDE STUB_LOCK="$FL" STUB_LOCK_FIPS="$fx/full-fips.lock.json" \
  TEST_SUDO="$rpw/sudo" TEST_UNSHARE="$rpw/unshare" TEST_APKO="$rpw/apko" STUB_LOCKED_CACHE=1 "$work/ai.sh" "${ai_args[@]}" --out "$(mo)" >"$work/site.log" 2>&1 </dev/null; echo $? >"$work/site.rc"
site_cache2=$(grep -Eo -- '--cache-dir [^ ]+' "$CALLS" | tail -1 | cut -d' ' -f2)
t "AC12" "...and with the fixed path the same cleanup fallback runs: a 'sudo ... rm -rf' call is logged and the assembly's own status is unchanged (0)" bash -c "test \"\$(cat '$work/site.rc')\" = 0 && grep -q '^sudo .*rm -rf' '$CALLS'"
chmod -R u+w "$(dirname "$site_cache2")" 2>/dev/null; rm -rf "$(dirname "$site_cache2")"
# round 5: the config is read as a closed plain grammar, so YAML constructs the text scan could not decode are refused (both seats' counterexamples)
printf 'contents:\n  repositories:\n    - /work/archive\n    - /work/melange-repo\n  runtime-repositories: ["https:\\\n    //example.invalid/os"]\n  packages:\n    - tzdata\n' >"$work/rt.yaml"
sr "rule 26" "assemble refuses a config with an extra repository key whose flow value is a YAML line continuation spelling https://, before any apko call" 'plain grammar|repository-like' "${aie[@]}" "$AI" "${ai_args[@]}" --apko-config "$work/rt.yaml" --out "$(mo)"
printf 'contents:\n  "repositories":\n    - "https:\\\n      //packages.wolfi.dev/os"\nannotations:\n  note: |\n    repositories:\n      - /work/archive\n      - /work/melange-repo\n' >"$work/qk.yaml"
sr "rule 26" "assemble refuses a config with a quoted repositories key and a block scalar that merely contains the expected lines" 'plain grammar' "${aie[@]}" "$AI" "${ai_args[@]}" --apko-config "$work/qk.yaml" --out "$(mo)"
t "AC1" "the committed configs and the fixture configs satisfy the closed grammar (check-config exits 0 for each)" bash -c "for f in '$root/build/apko.yaml' '$root/build/apko-fips.yaml' '$fx/apko.yaml' '$fx/apko-fips.yaml'; do python3 '$OD' check-config \"\$f\" || exit 1; done"
# round 5 (seat A, R1): index and manifests carry schemaVersion 2
python3 - "$work" <<'P'
import hashlib, io, json, sys, tarfile
work = sys.argv[1]
H = lambda b: hashlib.sha256(b).hexdigest()
def build(name, idx_sv=2, man_sv=2, top_sv=2):
    blobs, mans = [], []
    for arch in ("amd64", "arm64"):
        cfg = json.dumps({"architecture": arch, "os": "linux"}, sort_keys=True).encode(); layer = ("layer-" + arch).encode()
        man = json.dumps({"schemaVersion": man_sv, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                          "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": "sha256:" + H(cfg), "size": len(cfg)},
                          "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "sha256:" + H(layer), "size": len(layer)}]}, sort_keys=True).encode()
        blobs += [cfg, layer, man]
        mans.append({"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:" + H(man), "size": len(man), "platform": {"architecture": arch, "os": "linux"}})
    idx = json.dumps({"schemaVersion": idx_sv, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": mans}, sort_keys=True).encode()
    top = json.dumps({"schemaVersion": top_sv, "manifests": [{"mediaType": "application/vnd.oci.image.index.v1+json", "digest": "sha256:" + H(idx), "size": len(idx)}]}, sort_keys=True).encode()
    members = [("oci-layout", b'{"imageLayoutVersion":"1.0.0"}'), ("index.json", top), ("blobs/sha256/" + H(idx), idx)] + [("blobs/sha256/" + H(b), b) for b in blobs]
    with tarfile.open("%s/%s.tar" % (work, name), "w") as t:
        for n, b in members:
            ti = tarfile.TarInfo(n); ti.size = len(b); ti.mode = 0o644; t.addfile(ti, io.BytesIO(b))
build("oci-sv-idx", idx_sv=1); build("oci-sv-man", man_sv=1); build("oci-sv-top", top_sv=1)
P
for v_ in sv-idx sv-man sv-top; do
  python3 "$OD" "$work/oci-$v_.tar" >"$work/oci-$v_.out" 2>&1; r_=$?
  t "BT-002-AC1" "a layout whose $v_ carries schemaVersion 1 (hashes and sizes right) is refused naming schemaVersion" bash -c "test $r_ != 0 && grep -q 'schemaVersion' '$work/oci-$v_.out'"
done
# round 5 (seat B, R2): --digests-out may not be a generated result of the proof itself
sf "rule 42" "sealed-proof: --digests-out inside the proof's own OUT directory is refused (it would overwrite a generated result)" 'inside the proof' "${spe[@]}" "$SP" --out "$work/dgo-out" --probe 'test -z "${FAKE_SEALED:-}"' --digests-out "$work/dgo-out/image/production.digest" "${sp_common[@]}"
# round 6: Unicode line breaks, malformed blob names, path spellings of --digests-out, and the inherited-value behaviour of every variable the assembler assigns
for brk_ in '\xc2\x85' '\xe2\x80\xa8' '\xe2\x80\xa9'; do
  { sed -n '1,14p' "$fx/apko.yaml" | grep -v '^$'; printf '# audit fixture%b  runtime-repositories:%b    - https://example.invalid/os\n' "$brk_" "$brk_"; sed -n '15,$p' "$fx/apko.yaml"; } >"$work/brk.yaml"
  sr "rule 26" "assemble refuses a config carrying a Unicode line break (YAML reads it as a newline, the text scan did not), before any apko call" 'outside printable ASCII|Unicode line break' "${aie[@]}" "$AI" "${ai_args[@]}" --apko-config "$work/brk.yaml" --out "$(mo)"
done
python3 - "$work" <<'P'
import hashlib, io, json, sys, tarfile
work = sys.argv[1]
src = tarfile.open(work + "/oci-ok.tar")
for name, bad_name in (("oci-badname", "blobs/sha256/invalid"), ("oci-upper", "blobs/sha256/" + "A" * 64), ("oci-short", "blobs/sha256/" + "a" * 63)):
    with tarfile.open("%s/%s.tar" % (work, name), "w") as d:
        for m in src.getmembers():
            d.addfile(m, src.extractfile(m) if m.isfile() else None)
        ti = tarfile.TarInfo(bad_name); ti.size = 1; ti.mode = 0o644; d.addfile(ti, io.BytesIO(b"x"))
P
for v_ in badname upper short; do
  python3 "$OD" "$work/oci-$v_.tar" >"$work/oci-$v_.out" 2>&1; r1_=$?
  python3 "$OD" unpack "$work/oci-$v_.tar" "$work/unp-$v_" "$work/unp-$v_.digest" "$work/unp-$v_.manifests" >"$work/oci-$v_.u.out" 2>&1; r2_=$?
  t "BT-002-AC1" "a layout with a blob-namespace member named '$v_' (not 64 lowercase hex digits) is refused by the digest-only read and by unpack, naming the member" bash -c "test $r1_ != 0 && test $r2_ != 0 && grep -q 'blob namespace' '$work/oci-$v_.out'"
done
# --digests-out by every spelling that reaches the proof's own results: dot components and doubled slashes resolve away before the containment check
for spell_ in dots slashes; do
  oo_="$work/dgo2-$spell_"; rm -rf "$oo_"
  case $spell_ in
    dots) tgt_="$work/./dgo2-$spell_/image/production.full.lock.json";;
    slashes) tgt_="$work//dgo2-$spell_/image/production.full.lock.json";;
  esac
  sf "rule 42" "sealed-proof: --digests-out spelled with $spell_ that resolves into the proof's own OUT is refused (it would overwrite a generated result)" 'inside the proof|same file' "${spe[@]}" "$SP" --out "$oo_" --probe 'test -z "${FAKE_SEALED:-}"' --digests-out "$tgt_" "${sp_common[@]}"
done
# every lowercase and uppercase variable the assembler assigns, given a hostile inherited value, changes nothing: the same digest as the control run
python3 - "$root/bin/assemble-image.sh" >"$work/poison.names" <<'P'
import re, sys
s = open(sys.argv[1]).read()
names = set(re.findall(r"(?<![A-Za-z0-9_$])([A-Za-z_][A-Za-z0-9_]*)\+?=", "\n".join(l for l in s.split("\n") if not l.lstrip().startswith("#"))))
names |= set(re.findall(r"\blocal\s+([A-Za-z_][A-Za-z0-9_ ]*)", s))
skip = {"PATH", "IFS", "HOME", "SHELL", "PWD", "OLDPWD", "BASH_ENV", "ENV", "SOURCE_DATE_EPOCH", "ImageOS", "ImageVersion"}
print(" ".join(sorted(n for n in names if n not in skip and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", n))))
P
poison_env=(); for n_ in $(cat "$work/poison.names"); do poison_env+=("$n_=/poison/$n_"); done
poison_out=$(mo)
run_s "${aie[@]}" "${poison_env[@]}" "$AI" "${ai_args[@]}" --out "$poison_out"
t "AC12" "every variable the assembler assigns, set to a hostile value in the environment ($(wc -w <"$work/poison.names") names), leaves the result unchanged: exit 0 and the same image digest as the control run" bash -c "test \"\$(cat '$work/rc')\" = 0 && test \"\$(cat '$poison_out/production.digest')\" = '$ref_out'"
# round 7 (seat B): the substituted production assignments have EXACTLY these values (a copy replaces them, so a wrong shipped value would otherwise vanish)
t "AC12" "the TEST-SUBST lines of the five production scripts hold exactly the intended tool locations, /work, an empty render directory and the shell's own host fact (an exact table, so a changed constant is a changed test)" python3 - "$root" <<'P'
import re, sys
root = sys.argv[1]
EXPECT = {
    "assemble-image.sh": {"HOST_OS": "${BASH_VERSINFO[5]}", "PY3": "/usr/bin/python3", "SUDO": "/usr/bin/sudo", "UNSHARE": "/usr/bin/unshare", "BASHBIN": "/bin/bash",
                          "APKO": "/usr/local/bin/apko", "ENVBIN": "/usr/bin/env", "WORKDIR": "/work", "RENDER_DIR": ""},
    "lock-proof.sh": {"HOST_OS": "${BASH_VERSINFO[5]}", "PY3": "/usr/bin/python3", "SUDO": "/usr/bin/sudo", "BASHBIN": "/bin/bash"},
    "sealed-proof.sh": {"HOST_OS": "${BASH_VERSINFO[5]}", "PY3": "/usr/bin/python3", "SUDO": "/usr/bin/sudo", "UNSHARE": "/usr/bin/unshare", "BASHBIN": "/bin/bash"},
    "apko-lock.sh": {"PY3": "/usr/bin/python3"},
    "build-apk.sh": {"PY3": "/usr/bin/python3", "GIT": "/usr/bin/git", "SUDO": "/usr/bin/sudo", "UNSHARE": "/usr/bin/unshare", "MELANGE": "/usr/local/bin/melange",
                     "GO_TOOL": "/usr/local/bin/fscache-go/bin/go", "SHA256SUM": "/usr/bin/sha256sum", "ENVBIN": "/usr/bin/env", "SEALED_ENV": "build/sealed-env.json",
                     "RECIPE_STANDARD": "$PWD/build/melange.yaml", "RECIPE_FIPS": "$PWD/build/melange-fips.yaml",
                     "FIPS_MODULE": "$PWD/build/locks/fips-module.txt"},
}
bad = []
for name, want in EXPECT.items():
    got = {}
    for ln in open("%s/bin/%s" % (root, name)).read().split("\n"):
        m = re.match(r"^([A-Z][A-Z0-9_]*)=(\S*)\s+# TEST-SUBST", ln)
        if m: got[m.group(1)] = m.group(2)
    if got != want:
        bad.append("%s: %r != %r" % (name, got, want))
print("\n".join(bad)); sys.exit(1 if bad else 0)
P
# round 9: a package locked twice at the SAME version is refused by the reader whatever differs between the two entries (data checksum, either order, the
# package's own top-level checksum, a signature checksum without a range): verify-archive checks the apk bytes only, so the reader must not tell them apart
python3 - "$BL" "$work" <<'P'
import copy, json, sys
d0 = json.load(open(sys.argv[1])); w = sys.argv[2]
def write(name, edit, front=False):
    d = copy.deepcopy(d0); e = copy.deepcopy(d["contents"]["packages"][0]); edit(e)
    d["contents"]["packages"].insert(0, e) if front else d["contents"]["packages"].append(e)
    json.dump(d, open("%s/dupv-%s.lock.json" % (w, name), "w"))
write("data-last", lambda e: e.__setitem__("data", dict(e["data"], checksum="sha256-" + "0" * 43 + "=")))
write("data-first", lambda e: e.__setitem__("data", dict(e["data"], checksum="sha256-" + "0" * 43 + "=")), front=True)
write("toplevel", lambda e: e.__setitem__("checksum", "Q1" + "A" * 27 + "="))
write("sigsum", lambda e: e.__setitem__("signature", {"checksum": "sha256-" + "1" * 43 + "=", "range": ""}))
P
for v_ in data-last data-first toplevel sigsum; do
  ( cd "$air" && bash bin/apko-lock.sh verify-archive --lock "$work/dupv-$v_.lock.json" --archive "$fx/archive" >"$work/dupv-$v_.out" 2>&1; echo $? >"$work/dupv-$v_.rc" )
  ( cd "$air" && bash bin/apko-lock.sh arch-check "$work/dupv-$v_.lock.json" >"$work/dupv-$v_.out2" 2>&1; echo $? >"$work/dupv-$v_.rc2" )
  t "AC5" "a lock with the first package listed twice at one version ($v_ differs) is refused by verify-archive AND arch-check (exit 2, 'more than once')" bash -c "test \"\$(cat '$work/dupv-$v_.rc')\" = 2 && test \"\$(cat '$work/dupv-$v_.rc2')\" = 2 && grep -q 'more than once' '$work/dupv-$v_.out' && grep -q 'more than once' '$work/dupv-$v_.out2'"
done
# ---- end verbatim sections ----

# ===== cache#770: assemble-image.sh and apko-lock.sh are straight-line text; checks are oci-digest.py subcommands =====
# The cases say what assemble-image.sh said and did before: the same message, the same exit status, the same order.
# They call the subcommands directly; the whole script is run by every case above.
cat >"$work/ocd-cases.py" <<'PY'
import os, subprocess, sys, tempfile

ROOT, WORK = sys.argv[1], sys.argv[2]
T = os.path.realpath(tempfile.mkdtemp(dir=WORK))
P = "assemble-image.sh: "


def helper(args, cwd=None):
    r = subprocess.run(["python3", "-I", "-B", ROOT + "/bin/oci-digest.py"] + args,
                       env={"PATH": os.environ["PATH"]}, cwd=cwd or T, capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr


def report(label, problems):
    print(("FAIL %s: %s" % (label, "; ".join(problems))) if problems else "ok " + label)


def case(label, args, rc=0, out=None, err=None, cwd=None):
    """one call; err None means: empty when rc is 0, not looked at otherwise"""
    got_rc, got_out, got_err = helper(args, cwd)
    if err is None and rc == 0:
        err = ""
    problems = []
    if got_rc != rc:
        problems.append("exit %r, wanted %r" % (got_rc, rc))
    if out is not None and got_out.rstrip("\n") != out:
        problems.append("stdout %r, wanted %r" % (got_out, out))
    if err is not None and got_err != err:
        problems.append("stderr %r, wanted %r" % (got_err, err))
    report(label, problems)


def refuse(label, args, msg, rc=2, **kw):
    case(label, args, rc=rc, err=P + msg + "\n", **kw)


def put(path, text=""):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)
    return path


def mkdir(*parts):
    path = os.path.join(T, *parts)
    os.makedirs(path, exist_ok=True)
    return path


# ---- variant-field and apk-version
FIELDS = {"production": ("fscache", "build/apko.yaml", "build/locks/apko.base.lock.json"),
          "fips": ("fscache-fips", "build/apko-fips.yaml", "build/locks/apko-fips.base.lock.json")}
for variant, values in FIELDS.items():
    for field, want in zip(("pkg", "config", "baselock"), values):
        case("variant-field %s %s" % (variant, field), ["variant-field", variant, field], out=want)
for version, want in (("0.3.0", "0.3.0"), ("0.3.0-rc1", "0.3.0_rc1"), ("1.0.0-rc12", "1.0.0_rc12"),
                      ("0.0.0-rc.1", "0.0.0_rc1")):
    case("apk-version %s" % version, ["apk-version", version], out=want)

# ---- check-roots: archive, melange repo, keyring dir, out, render dir
real = [mkdir("r", n) for n in ("archive", "melrepo", "keydir", "out")]
spaced = mkdir("r", "with space")
os.symlink(real[0], T + "/r/link")
os.symlink(T + "/r/nowhere", T + "/r/dangling")
PLACES = ("archive", "melrepo", "keydir", "out", "render")
NAMES = ("--archive", "--melange-repo", "--keyring-dir", "--out", "--render-dir")
CTRL = ("%s holds a control character or a byte outside printable ASCII (a newline, a C1 control or any byte >= 0x80); "
        "refusing, the path arguments are plain ASCII text")
EMPTY = "%s is empty; refusing (an empty value would silently mean the current directory)"
DOTS = "%s %s has a . or .. component after another component (it could hide a symlinked root); give the real path"
LINK = "%s %s is a symlink; refusing (a root of the inputs or the result must be a real directory)"


def roots(label, msg=None, **given):
    """check-roots over the four real roots and no render directory, with the roots named in GIVEN replaced"""
    values = real + [""]
    for place, value in given.items():
        values[PLACES.index(place)] = value
    if msg is None:
        case("check-roots: " + label, ["check-roots"] + values)
    else:
        refuse("check-roots: " + label, ["check-roots"] + values, msg)


roots("four real directories and no render directory")
roots("a render directory is judged like the others", render=spaced)
roots("a space is printable ASCII", archive=spaced)
roots("a leading ./ is allowed", archive="./r/archive")
roots("a leading ../ is allowed", archive="../" + os.path.basename(T) + "/r/archive")
for place, name in zip(PLACES, NAMES):
    for value in ("a\nb", "a\tb", "a\x1bb", "a\x7fb", "café", "a\u0085b"):
        roots("%s holding %r" % (name, value), CTRL % name, **{place: value})
    if place != "render":
        roots("%s empty" % name, EMPTY % name, **{place: ""})
        roots("%s a symlink" % name, LINK % (name, T + "/r/link"), **{place: T + "/r/link"})
    roots("%s a symlink with slashes behind it: the message shows them" % name,
          LINK % (name, T + "/r/link//"), **{place: T + "/r/link//"})
    roots("%s a symlink to nothing" % name, LINK % (name, T + "/r/dangling"), **{place: T + "/r/dangling"})
    for dotted in ("/r/./x", "/r/../x", "/r/x/.", "/r/x/.."):
        roots("%s holding %s" % (name, dotted), DOTS % (name, T + dotted), **{place: T + dotted})
    roots("%s with dots and slashes behind: the message shows the name without them" % name,
          DOTS % (name, T + "/r/./x"), **{place: T + "/r/./x//"})
for lone in (".", ".."):
    roots("a lone %r is refused as dots" % lone, DOTS % ("--archive", lone), archive=lone)
# the roots are judged one after the other, and within one root in this order: control character, empty, dots, symlink
BROKEN = ["a\nb", "", T + "/r/link", T + "/r/./x", ""]
for i, (name, msg) in enumerate(zip(NAMES, (CTRL % "--archive", EMPTY % "--melange-repo",
                                            LINK % ("--keyring-dir", T + "/r/link"), DOTS % ("--out", T + "/r/./x")))):
    refuse("check-roots: %s is judged before the roots after it" % name, ["check-roots"] + real[:i] + BROKEN[i:], msg)
refuse("check-roots: within one root a control character comes before the dots",
       ["check-roots", T + "/r/./a\nb"] + real[1:] + [""], CTRL % "--archive")
refuse("check-roots: within one root the dots come before the symlink",
       ["check-roots", T + "/r/link/./x"] + real[1:] + [""], DOTS % ("--archive", T + "/r/link/./x"))

# ---- abs-dir and abs-file
W = mkdir("w")
mkdir("w", "real")
mkdir("w", "-P")
os.symlink(W + "/real", W + "/via")
put(W + "/real/f.txt", "x")
case("abs-dir: a real directory", ["abs-dir", W + "/real"], out=W + "/real")
case("abs-dir: a symlink is resolved", ["abs-dir", W + "/via"], out=W + "/real")
case("abs-dir: a relative name", ["abs-dir", "real"], out=W + "/real", cwd=W)
case("abs-dir: dot-dot is folded away", ["abs-dir", "real/../real"], out=W + "/real", cwd=W)
case("abs-dir: a name that is not a directory stays as typed", ["abs-dir", "nope/x"], out="nope/x", cwd=W)
case("abs-dir: a file stays as typed", ["abs-dir", "real/f.txt"], out="real/f.txt", cwd=W)
case("abs-dir: a directory named -P is a directory, not an option", ["abs-dir", "-P"], out=W + "/-P", cwd=W)
case("abs-file: a file", ["abs-file", W + "/real/f.txt"], out=W + "/real/f.txt")
case("abs-file: the directory of the file is resolved", ["abs-file", W + "/via/f.txt"], out=W + "/real/f.txt")
case("abs-file: a relative name", ["abs-file", "real/f.txt"], out=W + "/real/f.txt", cwd=W)
case("abs-file: a name that is not there yet", ["abs-file", "real/new"], out=W + "/real/new", cwd=W)
case("abs-file: a bare name", ["abs-file", "f.txt"], out=W + "/real/f.txt", cwd=W + "/real")
case("abs-file: a directory that is not there stays as typed", ["abs-file", "nope/x"], out="nope/x", cwd=W)

# ---- check-inputs: archive, melange repo, keyring dir, out, config, base lock
cfg, base = put(T + "/i/apko.yaml", "x"), put(T + "/i/base.lock.json", "{}")
archive, melrepo, keydir = [mkdir("i", n) for n in ("archive", "melrepo", "keydir")]
none = T + "/i/none"
ADDR = "the archive, the melange repository and the keyring dir must be local directories, not addresses (%s)"


def inputs(label, msg=None, **over):
    given = dict(archive=archive, melrepo=melrepo, keydir=keydir, out="o", config=cfg, baselock=base)
    given.update(over)
    args = ["check-inputs"] + [given[k] for k in ("archive", "melrepo", "keydir", "out", "config", "baselock")]
    refuse("check-inputs: " + label, args, msg) if msg else case("check-inputs: " + label, args)


inputs("everything there")
inputs("a keyring dir that is not there is not judged here", keydir=none)
inputs("an https archive", ADDR % "https://x.example/a", archive="https://x.example/a")
inputs("a file:// melange repo", ADDR % "file:///m", melrepo="file:///m")
inputs("an address as the keyring dir", ADDR % "http://k", keydir="http://k")
inputs("the addresses are looked at archive first", ADDR % "ftp://a", archive="ftp://a", melrepo="ftp://m")
inputs("the archive is not a directory", "--archive is not a directory: " + none, archive=none)
inputs("the archive is a file", "--archive is not a directory: " + cfg, archive=cfg)
inputs("the melange repo is not a directory", "--melange-repo is not a directory: " + none, melrepo=none)
inputs("the addresses come before the directories", ADDR % "ftp://a", archive="ftp://a", melrepo=none)
inputs("the archive comes before the melange repo", "--archive is not a directory: " + none, archive=none, melrepo=none)
inputs("no config", "apko config not found: " + none + ".yaml", config=none + ".yaml")
inputs("a config that is a directory", "apko config not found: " + archive, config=archive)
inputs("no base lock", "base lock not found: " + none + ".json", baselock=none + ".json")
inputs("the melange repo comes before the config", "--melange-repo is not a directory: " + none,
       melrepo=none, config=none + ".yaml")
inputs("the config comes before the base lock", "apko config not found: " + none + ".yaml",
       config=none + ".yaml", baselock=none + ".json")

# ---- check-keydir
KEYS = ("wolfi-signing.rsa.pub", "assembly.rsa.pub")
NOKEY = "the keyring dir %s has no %s: every package is checked against its key (rule 19)"
both = mkdir("k", "both")
for key in KEYS:
    put(both + "/" + key, "key")
case("check-keydir: both keys there", ["check-keydir", both])
only_assembly, only_wolfi = mkdir("k", "only-assembly"), mkdir("k", "only-wolfi")
put(only_assembly + "/assembly.rsa.pub")
put(only_wolfi + "/wolfi-signing.rsa.pub")
refuse("check-keydir: no wolfi key", ["check-keydir", only_assembly], NOKEY % (only_assembly, KEYS[0]))
refuse("check-keydir: no assembly key", ["check-keydir", only_wolfi], NOKEY % (only_wolfi, KEYS[1]))
empty = mkdir("k", "empty")
refuse("check-keydir: neither: the wolfi key is named first", ["check-keydir", empty], NOKEY % (empty, KEYS[0]))
dirs = mkdir("k", "dirs")
mkdir("k", "dirs", KEYS[0])
refuse("check-keydir: a directory is not a key", ["check-keydir", dirs], NOKEY % (dirs, KEYS[0]))
refuse("check-keydir: the directory is not there", ["check-keydir", T + "/k/none"], NOKEY % (T + "/k/none", KEYS[0]))
links = mkdir("k", "links")
for key in KEYS:
    os.symlink(put(T + "/k/target-" + key, "key"), links + "/" + key)
case("check-keydir: a link to a regular file is a file here (check-keys judges links later)", ["check-keydir", links])

# ---- check-melrepo
NOAPK = "the melange repository %s has no %s/%s-%s-r0.apk (our apk)"
NOIDX = "the melange repository %s has no %s/APKINDEX.tar.gz"
ARCHS = ("x86_64", "aarch64")


def repo_with(name, apks, indexes):
    d = mkdir("m", name)
    for a in apks:
        put("%s/%s/fscache-0.3.0_rc1-r0.apk" % (d, a))
    for a in indexes:
        put("%s/%s/APKINDEX.tar.gz" % (d, a))
    return d


def melrepo_case(label, d, msg=None, pkg="fscache", version="0.3.0_rc1"):
    args = ["check-melrepo", d, pkg, version]
    refuse("check-melrepo: " + label, args, msg) if msg else case("check-melrepo: " + label, args)


d = repo_with("full", ARCHS, ARCHS)
melrepo_case("apk and index for both architectures", d)
melrepo_case("another version", d, NOAPK % (d, "x86_64", "fscache", "0.3.0"), version="0.3.0")
melrepo_case("another package (the fips apk)", d, NOAPK % (d, "x86_64", "fscache-fips", "0.3.0_rc1"),
              pkg="fscache-fips")
d = repo_with("no-x86-apk", ["aarch64"], ARCHS)
melrepo_case("no x86_64 apk", d, NOAPK % (d, "x86_64", "fscache", "0.3.0_rc1"))
d = repo_with("no-x86-index", ARCHS, ["aarch64"])
melrepo_case("no x86_64 index", d, NOIDX % (d, "x86_64"))
d = repo_with("no-arm-apk", ["x86_64"], ARCHS)
melrepo_case("no aarch64 apk", d, NOAPK % (d, "aarch64", "fscache", "0.3.0_rc1"))
d = repo_with("no-arm-index", ARCHS, ["x86_64"])
melrepo_case("no aarch64 index", d, NOIDX % (d, "aarch64"))
d = repo_with("nothing", [], [])
melrepo_case("nothing there: the x86_64 apk is asked for first", d, NOAPK % (d, "x86_64", "fscache", "0.3.0_rc1"))
d = repo_with("apks-only", ARCHS, [])
melrepo_case("the x86_64 index is asked for before the aarch64 apk", d, NOIDX % (d, "x86_64"))

# ---- check-workdir
EXISTS = "%s/%s already exists (%s)); refusing to replace it: remove it by hand if no other assembly is running"
CRASHED = "a symlink, left by another run or a crashed one"
case("check-workdir: nothing there", ["check-workdir", mkdir("wd", "clean")])
case("check-workdir: a work directory that is not there", ["check-workdir", T + "/wd/none"])
for name in ("archive", "melange-repo", "keyring"):
    d = mkdir("wd", "dir-" + name)
    mkdir("wd", "dir-" + name, name)
    refuse("check-workdir: %s is a directory" % name, ["check-workdir", d], EXISTS % (d, name, "not a symlink"))
    d = mkdir("wd", "file-" + name)
    put(d + "/" + name)
    refuse("check-workdir: %s is a file" % name, ["check-workdir", d], EXISTS % (d, name, "not a symlink"))
    d = mkdir("wd", "link-" + name)
    os.symlink(T + "/wd/clean", d + "/" + name)
    refuse("check-workdir: %s is a link" % name, ["check-workdir", d], EXISTS % (d, name, CRASHED))
    d = mkdir("wd", "dangling-" + name)
    os.symlink(T + "/wd/none", d + "/" + name)
    refuse("check-workdir: %s is a link to nothing" % name, ["check-workdir", d], EXISTS % (d, name, CRASHED))
d = mkdir("wd", "two")
put(d + "/keyring")
mkdir("wd", "two", "melange-repo")
refuse("check-workdir: archive, melange-repo, keyring: the first one there is named", ["check-workdir", d],
       EXISTS % (d, "melange-repo", "not a symlink"))

# ---- prepare-render
tmp = mkdir("p", "tmp")
NOT_EMPTY = ("--render-dir %s is not empty or cannot be listed; refusing "
             "(a planted file would be used or written through)")
LINKED = "--render-dir %s is a symlink; refusing (render files would be written through it)"
case("prepare-render: no render directory: a private one under TMP", ["prepare-render", "", tmp], out=tmp + "/render")
report("prepare-render: ... and it is made", [] if os.path.isdir(tmp + "/render") else ["TMP/render is not there"])
new = T + "/p/new/deep"
case("prepare-render: a render directory that is not there", ["prepare-render", new, tmp], out=new)
report("prepare-render: ... and it is made", [] if os.path.isdir(new) else [new + " is not there"])
empty = mkdir("p", "empty")
case("prepare-render: an empty directory is used", ["prepare-render", empty, tmp], out=empty)
planted, hidden = mkdir("p", "full"), mkdir("p", "hidden")
put(planted + "/planted")
put(hidden + "/.planted")
refuse("prepare-render: a directory with a file in it", ["prepare-render", planted, tmp], NOT_EMPTY % planted)
refuse("prepare-render: a hidden file counts too", ["prepare-render", hidden, tmp], NOT_EMPTY % hidden)
os.symlink(empty, T + "/p/link")
os.symlink(T + "/p/none", T + "/p/dangling")
refuse("prepare-render: a symlink", ["prepare-render", T + "/p/link", tmp], LINKED % (T + "/p/link"))
refuse("prepare-render: a link to nothing", ["prepare-render", T + "/p/dangling", tmp], LINKED % (T + "/p/dangling"))

# ---- check-out
STALE = "--out %s already holds %s; refusing to mix a new result with stale files (it is not empty)"
case("check-out: a directory that is not there", ["check-out", T + "/c/none", "fips"])
case("check-out: an empty directory", ["check-out", mkdir("c", "empty"), "fips"])
other = mkdir("c", "other")
for n in ("production", "production.digest", "production.manifests", "production.full.lock.json", "production-sbom"):
    put(other + "/" + n)
case("check-out: the other variant's files are left alone", ["check-out", other, "fips"])
for n in ("fips", "fips.digest", "fips.manifests", "fips.full.lock.json", "fips-sbom"):
    d = mkdir("c", "has-" + n)
    put(d + "/" + n)
    refuse("check-out: %s is already there" % n, ["check-out", d, "fips"], STALE % (d, n))
d = mkdir("c", "dir-result")
mkdir("c", "dir-result", "fips")
refuse("check-out: a directory of the variant's name", ["check-out", d, "fips"], STALE % (d, "fips"))
d = mkdir("c", "link-result")
os.symlink(T + "/c/none", d + "/fips.digest")
refuse("check-out: a link of the variant's name", ["check-out", d, "fips"], STALE % (d, "fips.digest"))
d = mkdir("c", "several")
for n in ("fips-sbom", "fips.manifests", "fips"):
    put(d + "/" + n)
refuse("check-out: of several names the first in the old order is named", ["check-out", d, "fips"], STALE % (d, "fips"))
d = mkdir("c", "several2")
for n in ("fips-sbom", "fips.manifests"):
    put(d + "/" + n)
refuse("check-out: variant, digest, manifests, full lock, sbom", ["check-out", d, "fips"],
       STALE % (d, "fips.manifests"))
afile = put(T + "/c/afile")
refuse("check-out: a file where the directory should be", ["check-out", afile, "fips"],
       "--out %s is not a directory" % afile)
if os.geteuid() != 0:   # root lists any directory
    closed = mkdir("c", "closed")
    os.chmod(closed, 0)
    refuse("check-out: a directory that cannot be listed", ["check-out", closed, "fips"],
           "--out %s cannot be listed; refusing" % closed)
    os.chmod(closed, 0o700)

# ---- apko-verdict
NOAPKO = "apko is not installed (the chain installs it before this step)"
ATTEMPT = ("a network attempt was made inside the sealed apko call (the probe confirms the namespace has no route); "
           "the build must use only declared inputs")
LEAKY = ("apko failed with a network error, but the probe says the namespace is not sealed (exit %s); "
         "fix the seal first")
for kind in ("lock", "build"):
    case("apko-verdict %s: exit 0 is fine" % kind, ["apko-verdict", kind, "0", ""])
    refuse("apko-verdict %s: not installed" % kind, ["apko-verdict", kind, "127", ""], NOAPKO, rc=1)
    refuse("apko-verdict %s: not installed, whatever the probe said" % kind, ["apko-verdict", kind, "127", "101"],
           NOAPKO, rc=1)
    refuse("apko-verdict %s: probe 101: a network attempt" % kind, ["apko-verdict", kind, "1", "101"], ATTEMPT, rc=4)
    for probe in ("0", "1", "111"):
        refuse("apko-verdict %s: probe %s: the namespace is not sealed" % (kind, probe),
               ["apko-verdict", kind, "1", probe], LEAKY % probe, rc=1)
    for code in ("1", "2", "137"):
        refuse("apko-verdict %s: failed %s, no probe run" % (kind, code), ["apko-verdict", kind, code, ""],
               "apko %s failed (exit %s)" % (kind, code), rc=1)

# ---- pick-sbom
SBOMS = ("apko wrote %d SBOM files and none is the image index SBOM (sbom-index.spdx.json); "
         "cannot choose the one image SBOM")


def sbom_dir(name, files, dirs=()):
    d = mkdir("s", name)
    for f in files:
        put(d + "/" + f)
    for sub in dirs:
        mkdir("s", name, sub)
    return d


d = sbom_dir("one", ["sbom-spdx.json"])
case("pick-sbom: one file is the one", ["pick-sbom", d], out=d + "/sbom-spdx.json")
d = sbom_dir("one-name", ["image sbom.json"])
case("pick-sbom: a name with a space", ["pick-sbom", d], out=d + "/image sbom.json")
d = sbom_dir("only-index", ["sbom-index.spdx.json"])
case("pick-sbom: the index alone", ["pick-sbom", d], out=d + "/sbom-index.spdx.json")
d = sbom_dir("index-and-more", ["sbom-x86_64.spdx.json", "sbom-index.spdx.json", "sbom-aarch64.spdx.json"])
case("pick-sbom: of several, the index is the one", ["pick-sbom", d], out=d + "/sbom-index.spdx.json")
d = sbom_dir("hidden", ["sbom-spdx.json", ".hidden"])
case("pick-sbom: a hidden file is not counted", ["pick-sbom", d], out=d + "/sbom-spdx.json")
refuse("pick-sbom: two files and no index", ["pick-sbom", sbom_dir("two", ["a.json", "b.json"])], SBOMS % 2, rc=1)
refuse("pick-sbom: no file", ["pick-sbom", sbom_dir("none", [])], SBOMS % 0, rc=1)
refuse("pick-sbom: the only entry is a directory", ["pick-sbom", sbom_dir("dir-only", [], ["sbom-spdx.json"])],
       SBOMS % 1, rc=1)
refuse("pick-sbom: an index that is a directory is no index",
       ["pick-sbom", sbom_dir("dir-index", ["a.json"], ["sbom-index.spdx.json"])], SBOMS % 2, rc=1)
PY
python3 "$work/ocd-cases.py" "$root" "$work" >"$work/ocd-cases.out" 2>&1
while IFS= read -r l; do case $l in "ok "*) ok;; *) bad 770 "$l";; esac; done <"$work/ocd-cases.out"

long_lines() { python3 - "$1" <<'PY'
import sys
long_lines = [n for n, line in enumerate(open(sys.argv[1], encoding="utf-8"), 1) if len(line.rstrip("\n")) > 120]
sys.exit("lines over 120 characters: %r" % long_lines[:20] if long_lines else 0)
PY
}
t "770" "no line of bin/assemble-image.sh is longer than 120 characters" long_lines "$AI_PROD"
t "770" "no line of bin/apko-lock.sh is longer than 120 characters" long_lines "$LK"
t "770" "bin/assemble-image.sh makes no path absolute with cd and pwd in a substitution: the helper does" \
  bash -c "! grep -v '^ *#' '$AI_PROD' | grep -Eq '[$][(] *cd '"

# apko-lock.sh run from another directory: exit 2, and the output names the helper it could not find
mkdir -p "$work/elsewhere"
( cd "$work/elsewhere" && bash "$air/bin/apko-lock.sh" arch-check "$BL" >"$work/lk-else.log" 2>&1
  echo $? >"$work/lk-else.rc" )
t "770" "apko-lock.sh run from another directory exits 2 and names bin/oci-digest.py" \
  bash -c "[ \"\$(cat '$work/lk-else.rc')\" = 2 ] && grep -q 'bin/oci-digest.py' '$work/lk-else.log'"

# oci-digest.py takes the checksum kind of a lock section by name from hashlib: sha1 and sha256 are read, others refused
python3 - "$root" "$BL" "$fx/archive" "$work" <<'PY' >"$work/kinds.out" 2>&1
import base64, hashlib, json, subprocess, sys
root, base, archive, work = sys.argv[1:5]
lock = json.load(open(base))
entries = sorted(lock["contents"]["packages"], key=lambda e: (e["architecture"], e["name"], e["version"]))
first = "%s-%s.apk" % (entries[0]["name"], entries[0]["version"])


def verify():
    json.dump(lock, open(work + "/kinds.lock.json", "w"))
    r = subprocess.run(["python3", "-I", "-B", root + "/bin/oci-digest.py", "lock", "verify-archive",
                        "--lock", work + "/kinds.lock.json", "--archive", archive], capture_output=True, text=True)
    return r.returncode, r.stderr


for e in entries:   # control sums as sha256, data sums as sha1: right sums of the other kind are read just the same
    raw = open("%s/%s/%s-%s.apk" % (archive, e["architecture"], e["name"], e["version"]), "rb").read()
    for part, kind in (("control", "sha256"), ("data", "sha1")):
        lo, hi = map(int, e[part]["range"][len("bytes="):].split("-"))
        e[part]["checksum"] = kind + "-" + base64.b64encode(hashlib.new(kind, raw[lo:hi + 1]).digest()).decode()
got = verify()
print("ok" if got == (0, "") else "FAIL sums under the other allowed kind are not accepted: %r" % (got,))
want = "apko-lock.sh: %s: cannot read the control range or checksum in the lock\n" % first
for bad in ("md5-AAAA", "sha512-AAAA", "SHA256-AAAA", "blake2b-AAAA", "-AAAA", "sha256AAAA", "__class__-AAAA", ""):
    entries[0]["control"]["checksum"] = bad
    got = verify()
    print("ok" if got == (1, want) else "FAIL checksum %r is not refused as unreadable: %r" % (bad, got))
PY
t "770" "oci-digest.py lock verify-archive: sha1 and sha256 sums are read, any other kind is refused as unreadable" \
  bash -c "! grep -q FAIL '$work/kinds.out' && [ \"\$(grep -c '^ok' '$work/kinds.out')\" = 9 ]"
echo "assemble-image-test: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
