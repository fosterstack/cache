#!/usr/bin/env bash
# Regression tests for bin/check-file-allowlist.sh — in particular the branch
# scoping of the daily CVE auditor's suppression outputs (.snyk,
# osv-scanner.toml, .auditor/accepted-items.json): allowed only on the auditor/
# lane and on main, blocked on any other branch, and never a hole through which
# private-side content can reach this PUBLIC repo.
# Known limit (by design): a PR that changes ALLOW_PATTERNS / SUPPRESSION_PATTERNS in the script cannot pass
# this check before merge on its own account, because the trusted gate judges it with main's copy of the script.
set -uo pipefail
cd "$(dirname "$0")/.."
SCRIPT=./bin/check-file-allowlist.sh

pass=0; fail=0
gp() { echo "ok:   $1"; pass=$((pass+1)); }
gf() { echo "FAIL: $1 — $2"; fail=$((fail+1)); }
# run <expect pass|fail> <branch-env> <description> <paths...>
run() {
  local expect="$1"; local ref="$2"; local desc="$3"; shift 3
  local out rc
  out="$(printf '%s\n' "$@" | GITHUB_HEAD_REF="$ref" GITHUB_REF_NAME="" GITHUB_REPOSITORY=o/r GITHUB_HEAD_REPO="${HEADREPO-o/r}" "$SCRIPT" 2>&1)"; rc=$?
  if { [ "$expect" = pass ] && [ "$rc" -eq 0 ]; } || { [ "$expect" = fail ] && [ "$rc" -ne 0 ]; }; then
    echo "ok:   $desc"; pass=$((pass+1))
  else
    echo "FAIL: $desc (expected $expect, rc=$rc)"; echo "$out" | sed 's/^/      /'; fail=$((fail+1))
  fi
}
# runeach <expect> <branch> <desc> <paths...>: judge EACH path on its own (a multi-path `run fail` only proves
# that one of them is refused); the description names the path, so a failure says which one was wrongly admitted
runeach() {
  local expect="$1" ref="$2" desc="$3" p; shift 3
  for p in "$@"; do run "$expect" "$ref" "$desc [$p]" "$p"; done
}
# passfam <branch> <desc> <paths...>: each path is admitted ALONE, and each one's mechanical near-misses are
# refused ALONE: a leading segment (x/P), a trailing segment (P/x), a trailing slash (P/), and P with each '.' (and
# each '-') replaced by X in turn, the leading dot of .github included. These kill a dropped ^, a dropped $, an
# unescaped dot, and an unescaped/wildcarded separator in any pattern that admits the path.
passfam() {
  local ref="$1" desc="$2" p i c q; shift 2
  runeach pass "$ref" "$desc" "$@"
  for p in "$@"; do
    runeach fail "$ref" "$desc: leading segment" "x/$p"
    runeach fail "$ref" "$desc: trailing segment" "$p/x"
    runeach fail "$ref" "$desc: trailing slash" "$p/"
    for ((i=0; i<${#p}; i++)); do
      c="${p:i:1}"
      if [ "$c" = . ] || [ "$c" = - ]; then
        q="${p:0:i}X${p:i+1}"
        runeach fail "$ref" "$desc: '$c' at $i replaced" "$q"
      fi
    done
  done
}
# every ALLOW_PATTERNS / SUPPRESSION_PATTERNS entry is anchored at both ends (parsed from the script itself)
anch="$(awk '/^(ALLOW|SUPPRESSION)_PATTERNS=\(/{f=1;next} f&&/^\)/{f=0} f&&/^ *\x27/{n++; if ($0 !~ /^ *\x27\^/ || $0 !~ /\$\x27( +#.*)?$/) print "UNANCHORED: " $0} END{print "count=" n}' bin/check-file-allowlist.sh)"
case "$anch" in *UNANCHORED*) gf "every pattern is anchored with ^ and \$" "$anch";; *) gp "every allowlist pattern starts with ^ and ends with \$ ($anch)";; esac
# Structural checks on the pattern arrays, parsed from the script itself (python3; no regex engine involved).
# ALLOWLIST_STRUCT_FILE=<file> runs ONLY these checks against that file (used to prove them red on mutants).
# (A) every pattern line is exactly  two-space-indent, single-quoted, one pattern, optional trailing comment; the
#     number of such lines equals ${#ALLOW_PATTERNS[@]}+${#SUPPRESSION_PATTERNS[@]} as bash loads them; no
#     pattern has a top-level '|'; the only ALLOW_PATTERNS+= is the known suppression append.
# (B) the v0.3.0 region admits an EXACT, declared set of 39 paths: only literals, \. , (a|b) groups and (x)?
#     groups; no * + [ ] { } or bare '.'; the union of every pattern's finite expansion equals the declared list.
struct_check() {
  local f="$1" loaded
  loaded="$(bash -c 'eval "$(awk "/^(ALLOW|SUPPRESSION)_PATTERNS=\(/{f=1} f{print} f&&/^\)/{f=0}" "$1")"; echo $((${#ALLOW_PATTERNS[@]}+${#SUPPRESSION_PATTERNS[@]})); printf "%s\n" "${ALLOW_PATTERNS[@]}" "${SUPPRESSION_PATTERNS[@]}"' _ "$f" 2>&1)"
  python3 - "$f" "$loaded" <<'PYEOF'
import re, sys, itertools
path = sys.argv[1]
_ld = sys.argv[2].split("\n")
loaded = _ld[0]; bash_list = _ld[1:]
errs = []
# Read the script ONCE as bytes; every later step (region detection, form checks, numbering, hash slice) uses this
# same line list, split on b"\n" only. Fail closed: refuse any \r (lone or CRLF), NUL or other control character
# except \t and \n, any non-UTF-8 byte, and any Unicode line/paragraph separator (U+2028/2029, U+0085).
_raw = open(path, 'rb').read()
_bad = re.search(rb'[\x00-\x08\x0b-\x1f\x7f]', _raw)
if _bad: errs.append("script contains a forbidden control byte 0x%02x at offset %d (only tab and LF are allowed)" % (_bad.group(0)[0], _bad.start()))
_rawlines = _raw.split(b"\n")
lines = []
for _n, _bl in enumerate(_rawlines, 1):
    try: _t = _bl.decode('utf-8')
    except UnicodeDecodeError: errs.append("line %d: not valid UTF-8" % _n); _t = _bl.decode('utf-8', 'replace')
    if re.search('[\u0085\u2028\u2029]', _t): errs.append("line %d: Unicode line separator" % _n)
    lines.append(_t)
# PR each declared path belongs to is named in the comments
DECLARED = set("""
dependency-provenance.json
bin/vendor-check.sh bin/vendor-provenance.py bin/vendoring-test.sh
build/melange.yaml build/melange-fips.yaml build/melange.yaml.tmpl build/apko.yaml build/apko-fips.yaml
build/locks/apko.base.lock.json build/locks/apko-fips.base.lock.json build/locks/melange.lock build/locks/archive-keys.sha256 build/locks/archive-index.sha256
build/keys/assembly.rsa build/keys/assembly.rsa.pub build/keys/release.rsa.pub
bin/build-apk.sh bin/assemble-image.sh bin/apko-lock.sh bin/install-build-tools.sh bin/release-sign-apks.sh
bin/sealed-proof.sh bin/lock-proof.sh bin/refresh-inputs.sh
bin/apk-tool.py bin/gen-recipes.py bin/go-module-sbom.py
bin/melange-apko-lib.sh
bin/build-helpers-test.sh bin/refresh-inputs-test.sh bin/build-apk-test.sh bin/assemble-image-test.sh bin/archive-test.sh
bin/oci-digest.py bin/net-probe.py
bin/archive-push.sh bin/archive-pull.sh bin/archive-verify.py
.github/secret_scanning.yml
.github/agent/supply-chain/harness-manifest.json
.github/release-identity.json
""".split())
if len(DECLARED) != 39: errs.append("declared list is not 39 paths: %d" % len(DECLARED))
# Every non-comment line outside the array blocks that may mention PATTERNS (stripped), one per real line:
ALLOWED_MENTIONS = {
    'ALLOW_PATTERNS+=("${SUPPRESSION_PATTERNS[@]}")',                    # the suppression append (main/auditor/* only)
    'for pattern in "${ALLOW_PATTERNS[@]}"; do',                         # the allow loop
    'for pattern in "${SUPPRESSION_PATTERNS[@]}"; do',                   # the unchanged-suppression loop
    'echo "add a pattern to ALLOW_PATTERNS in bin/check-file-allowlist.sh." >&2',  # the hint text on a blocked path
}
# Pattern-line counts. A PR that adds a pattern updates these numbers in the same commit, so a pattern can never
# be added without touching the test.
EXPECT_ALLOW, EXPECT_SUPPRESSION = 135, 6
pats = []   # (lineno, pattern) for both arrays
region = [] # patterns of the v0.3.0 region
rstart = rend = 0
inarr = False; inregion = False; n = 0; cur = None; counts = {'ALLOW': 0, 'SUPPRESSION': 0}; byblock = {'ALLOW': [], 'SUPPRESSION': []}
for i, l in enumerate(lines, 1):
    mm = re.match(r'^(ALLOW|SUPPRESSION)_PATTERNS=\($', l)
    if mm: inarr = True; inregion = False; cur = mm.group(1); continue
    if inarr and l == ')': inarr = False; inregion = False; continue
    if not inarr:
        code = l.strip()
        if code.startswith('#'): continue
        # Fail closed: outside the two array blocks, EVERY line that mentions PATTERNS (any form: index
        # assignment, mapfile, read -a, eval, unset, declare/local -n, printf -v, a re-assignment, a nameref)
        # must be exactly one of the lines in ALLOWED_MENTIONS, which are all the lines that genuinely exist today.
        if 'PATTERNS' in code and code not in ALLOWED_MENTIONS:
            errs.append("line %d: unlisted mention of PATTERNS outside the arrays: %s" % (i, l))
        # Constructs that could mutate an array indirectly are refused anywhere outside comments
        # (none exists today; `local ref=` / `local mb` are plain locals and stay allowed).
        if re.search(r'(^|[^A-Za-z0-9_])(trap|exec)([^A-Za-z0-9_]|$)|(^|[;&|(]\s*)\.\s', code) or (re.search(r'(^|[^A-Za-z0-9_])read([^A-Za-z0-9_]|$)', code) and not code.startswith('while IFS= read -r ')):
            errs.append("line %d: trap/exec/dot-source/read outside the pinned text: %s" % (i, l))
        if re.search(r'(^|[^A-Za-z0-9_])(eval|declare|typeset|mapfile|readarray|unset|source)([^A-Za-z0-9_]|$)|printf\s+-v|\blocal\s+-[A-Za-z]*n|\bread\s+-[A-Za-z]*a|\$\{!', code):
            errs.append("line %d: array-mutating construct (eval/declare/mapfile/readarray/unset/source/printf -v/nameref/read -a/indirection) not allowed: %s" % (i, l))
        continue
    if l.strip() == '' : inregion = False; continue
    if l.lstrip().startswith('#'):
        if l.startswith('  # v0.3.0 build chain'): inregion = True; rstart = i
        continue
    m = re.match(r"^  '([^']*)'( +#.*)?$", l)   # at least one space before a comment: '..'#'..' is ONE bash word
    if not m:
        errs.append("line %d: pattern line not in the canonical form  two spaces, one single-quoted pattern: %s" % (i, l)); continue
    pats.append((i, m.group(1))); counts[cur] += 1; byblock[cur].append(m.group(1))
    if inregion: region.append((i, m.group(1))); rend = i
if (counts['ALLOW'], counts['SUPPRESSION']) != (EXPECT_ALLOW, EXPECT_SUPPRESSION):
    errs.append("pattern lines: ALLOW %d (declared %d), SUPPRESSION %d (declared %d); update the test in the same commit" % (counts['ALLOW'], EXPECT_ALLOW, counts['SUPPRESSION'], EXPECT_SUPPRESSION))
# element by element: what bash actually loads must equal what was parsed here, in value and order
_py = byblock['ALLOW'] + byblock['SUPPRESSION']
if str(loaded).isdigit() and bash_list != _py:
    _d = next((k for k in range(min(len(_py), len(bash_list))) if _py[k] != bash_list[k]), min(len(_py), len(bash_list)))
    errs.append("parsed patterns differ from what bash loads at element %d: parsed=%r bash=%r" % (_d, _py[_d:_d+1], bash_list[_d:_d+1]))
if not str(loaded).isdigit(): errs.append("could not load the arrays in bash: %s" % loaded)
elif int(loaded) != len(pats): errs.append("counted %d pattern lines but bash loads %s" % (len(pats), loaded))
# Whole-script pin (fail closed). The sha256 of the script with the exactly-checked v0.3.0 region removed (from the
# '# v0.3.0 build chain' marker line through the last pattern line of the region; nothing else normalised).
# Any other change to this script (older patterns, logic, suppression list) must update this digest in the same
# commit, so it is always visible in review; main's copy of the script judges a PR to the script anyway, this is
# defence in depth. The region itself is checked by expansion above, not by hash.
PINNED_SHA256 = "bfc68b4909a394875ac571c28a139bd0c8ed3a18934859bdf22ba608c211eb5b"
if rstart and rend:
    import hashlib
    _b = _rawlines
    _dg = hashlib.sha256(b"\n".join(_b[:rstart-1] + _b[rend:])).hexdigest()
    if _dg != PINNED_SHA256:
        errs.append("script text outside the v0.3.0 region changed (sha256 %s, pinned %s); if intended, update PINNED_SHA256 in the same commit" % (_dg, PINNED_SHA256))
def toplevel_bar(p):
    d = 0; i = 0
    while i < len(p):
        c = p[i]
        if c == '\\': i += 2; continue
        if c == '[':
            i += 1
            while i < len(p) and p[i] != ']':
                i += 2 if p[i] == '\\' else 1
        elif c == '(': d += 1
        elif c == ')': d -= 1
        elif c == '|' and d == 0: return True
        i += 1
    return False
for i, p in pats:
    if toplevel_bar(p): errs.append("line %d: top-level '|' in %s" % (i, p))
def expand(p):
    if not (p.startswith('^') and p.endswith('$')): raise ValueError("not anchored")
    p = p[1:-1]; pos = 0; sets = []
    lit = r'(?:[A-Za-z0-9/_-]|\\\.)'
    while pos < len(p):
        m = re.compile(r'(%s)' % lit).match(p, pos)
        if m: sets.append([m.group(1).replace('\\', '')]); pos = m.end(); continue
        m = re.compile(r'\(((?:%s)+(?:\|(?:%s)+)*)\)(\?)?' % (lit, lit)).match(p, pos)
        if not m: raise ValueError("construct not allowed at offset %d: %r" % (pos, p[pos:]))
        alts = [a.replace('\\', '') for a in m.group(1).split('|')]
        if m.group(2): alts.append('')
        sets.append(alts); pos = m.end()
    return {''.join(t) for t in itertools.product(*sets)}
union = set()
if len(region) == 0: errs.append("v0.3.0 region not found")
for i, p in region:
    try: union |= expand(p)
    except ValueError as e: errs.append("line %d: %s: %s" % (i, e, p))
if union != DECLARED:
    errs.append("region admits %d paths, declared %d; extra=%s missing=%s" % (len(union), len(DECLARED), sorted(union - DECLARED), sorted(DECLARED - union)))
print("\n".join(errs) if errs else "OK region=%d patterns, %d paths; %d pattern lines == loaded %s" % (len(region), len(union), len(pats), loaded))
sys.exit(1 if errs else 0)
PYEOF
}
if [ -n "${ALLOWLIST_STRUCT_FILE:-}" ]; then struct_check "$ALLOWLIST_STRUCT_FILE"; exit $?; fi
sc="$(struct_check bin/check-file-allowlist.sh)" && gp "structure: $sc" || gf "structure of the pattern arrays" "$sc"
# the structural check must itself catch each mutation (cheap: python only, no allowlist run)
_mut_dir="$(mktemp -d)"
mutcheck() { # <desc> <sed-expr>
  sed -E "$2" bin/check-file-allowlist.sh > "$_mut_dir/m.sh"
  if cmp -s bin/check-file-allowlist.sh "$_mut_dir/m.sh"; then gf "struct mutant did not apply: $1" "$2"; return; fi
  if struct_check "$_mut_dir/m.sh" >/dev/null 2>&1; then gf "struct check MISSED mutant: $1" "$2"; else gp "struct check kills mutant: $1"; fi
}
mutcheck "suffix on one alternative"      "s/\(build-apk\|assemble-image\|/(build-apk|assemble-image[a-z]+|/"
mutcheck "extension widened"              "s/\(apk-tool\|compare-recipes\|go-module-sbom\)\\\\\.py\\$/(apk-tool|gen-recipes|go-module-sbom)\\\\.(json|py|sh)\$/"
mutcheck "group made optional"            "s/\^build\/melange\(-fips\)\?/^build\/melange(-fips)?(-x)?/"
mutcheck "group repeated with +"          "s/\^build\/apko\(-fips\)\?/^build\/apko(-fips)+/"
mutcheck "? turned into *"                "s/\^build\/melange\(-fips\)\?/^build\/melange(-fips)*/"
mutcheck "first letter case-insensitive"  "s/'\^bin\/vendor-check/'^[bB]in\/vendor-check/"
mutcheck "a letter turned into a wildcard" "s/vendor-provenance/vendor-prov.nance/"
mutcheck "unescaped dot"                  "s/'\^dependency-provenance\\\\\.json/'^dependency-provenance.json/"
mutcheck "double-quoted pattern"          "s/^  '(\^bin\/vendor-check\\\\\.sh\\$)'/  \"\1\"/"
mutcheck "dollar-quote form"              "s/^  '(\^bin\/vendor-check\\\\\.sh\\$)'/  \$'\1'/"
mutcheck "tab-indented"                   "s/^  ('\^bin\/vendor-check)/\t\1/"
mutcheck "two patterns on one line"       "s/^  ('\^bin\/vendor-check\\\\\.sh\\$')/  \1 '^x\$'/"
mutcheck "top-level bar pattern"          "s/^  '\^bin\/vendor-check\\\\\.sh\\$'/  '^.*|x\$'/"
mutcheck "extra ALLOW_PATTERNS+= outside" "s/^SUPPRESSION_PATTERNS=\(/ALLOW_PATTERNS+=('^.*\$')\nSUPPRESSION_PATTERNS=(/"
# Fail-closed mutants for the "any other mention of the arrays" class and the pattern-line counts (built with awk
# from the real file: insert <text> after the first line matching <regex>, after the SUPPRESSION array's close when
# <regex> is ^\)$ and the 2nd occurrence is wanted).
mutins() { # <desc> <nth-occurrence-of-line-")"> <text>
  awk -v n="$2" -v t="$3" '{print} /^\)$/{c++; if(c==n) print t}' bin/check-file-allowlist.sh > "$_mut_dir/m.sh"
  if struct_check "$_mut_dir/m.sh" >/dev/null 2>&1; then gf "struct check MISSED mutant: $1" "$3"; else gp "struct check kills mutant: $1"; fi
}
mutins "index assignment after the arrays"  2 "ALLOW_PATTERNS[\${#ALLOW_PATTERNS[@]}]='^evil/.*\$'"
mutins "mapfile -t ALLOW_PATTERNS"          2 "mapfile -t ALLOW_PATTERNS < <(echo '^evil/.*\$')"
mutins "read -a ALLOW_PATTERNS"             2 "read -a ALLOW_PATTERNS <<< '^evil/.*\$'"
mutins "eval of an append"                  2 "eval 'ALLOW_PATTERNS+=(\"^evil/.*\$\")'"
mutins "unset an element"                   2 "unset 'ALLOW_PATTERNS[3]'"
mutins "declare -n alias then append"       2 "declare -n alias=ALLOW_PATTERNS; alias+=('^evil/.*\$')"
mutins "printf -v element"                  2 "printf -v 'ALLOW_PATTERNS[200]' '%s' '^evil/.*\$'"
mutins "re-assignment with a new element"   2 "ALLOW_PATTERNS=(\"\${ALLOW_PATTERNS[@]}\" '^evil/.*\$')"
awk '/^  # v0.3.0 build chain/{r=1} {print} r&&/^$/{print "  \x27^evil/.*$\x27"; r=0}' bin/check-file-allowlist.sh > "$_mut_dir/m.sh"
if cmp -s bin/check-file-allowlist.sh "$_mut_dir/m.sh"; then gf "mutant did not apply: wide pattern after the region blank line" ""; elif struct_check "$_mut_dir/m.sh" >/dev/null 2>&1; then gf "struct check MISSED mutant: wide pattern after the region blank line" ""; else gp "struct check kills mutant: wide pattern after the region blank line"; fi
# a wide pattern line inside an older block (after the first pattern line of ALLOW_PATTERNS)
awk '{print} /^ALLOW_PATTERNS=\(/{f=1} f&&/^  \x27/&&!d{print "  \x27^evil/.*$\x27"; d=1}' bin/check-file-allowlist.sh > "$_mut_dir/m.sh"
if cmp -s bin/check-file-allowlist.sh "$_mut_dir/m.sh"; then gf "mutant did not apply: older block" ""; elif struct_check "$_mut_dir/m.sh" >/dev/null 2>&1; then gf "struct check MISSED mutant: wide pattern in an older block" ""; else gp "struct check kills mutant: wide pattern in an older block"; fi
# B4-1 (quote concatenation through #) and extra readarray/indexed forms
mutsub() { # <desc> <exact pattern line> <text appended to that line>
  MUT_LINE="$2" MUT_ADD="$3" awk '!d && $0 == ENVIRON["MUT_LINE"] {print $0 ENVIRON["MUT_ADD"]; d=1; next} {print}' bin/check-file-allowlist.sh > "$_mut_dir/m.sh"
  if cmp -s bin/check-file-allowlist.sh "$_mut_dir/m.sh"; then gf "mutant did not apply: $1" ""; elif struct_check "$_mut_dir/m.sh" >/dev/null 2>&1; then gf "struct check MISSED mutant: $1" ""; else gp "struct check kills mutant: $1"; fi
}
mutsub "quote concat via # in the v0.3.0 region" "  '^bin/vendor-check\\.sh\$'" "#'|^bin/vendor-check[a-z]*\\.sh\$'"
mutsub "quote concat via # in an older block"    "  '^go\\.(mod|sum)\$'" "#'|^evil/.*\$'"
mutsub "pattern then bare #"                     "  '^bin/vendor-check\\.sh\$'" "#"
mutsub "pattern then tab then #"                 "  '^bin/vendor-check\\.sh\$'" "$(printf '\t')# c"
mutins "readarray -t -O 200"                2 "readarray -t -O 200 ALLOW_PATTERNS <<< '^evil/.*\$'"
mutins "SUPPRESSION_PATTERNS index assign"  2 "SUPPRESSION_PATTERNS[9]='^evil/.*\$'"
# B1 (round 5): the whole-script digest pin must kill each of these even if the readable denylist were bypassed.
# Each mutant is checked against the pin alone (hash line of the struct_check error), so the pin cannot be dead code.
pinkill() { # <desc> ; the mutant is already in $_mut_dir/m.sh
  if cmp -s bin/check-file-allowlist.sh "$_mut_dir/m.sh"; then gf "mutant did not apply: $1" ""; return; fi
  _out="$(struct_check "$_mut_dir/m.sh" 2>&1)" && { gf "struct check MISSED mutant: $1" ""; return; }
  case "$_out" in *"outside the v0.3.0 region changed"*) gp "digest pin kills mutant: $1";; *) gf "digest pin did NOT fire for mutant: $1" "$_out";; esac
}
pinmutins() { # <desc> <text inserted after the SUPPRESSION array close>
  awk -v n=2 -v t="$2" '{print} /^\)$/{c++; if(c==n) print t}' bin/check-file-allowlist.sh > "$_mut_dir/m.sh"; pinkill "$1"
}
pinmutins "process-substitution dot-source of a split-name append" ". <(echo \"ALLOW_PAT\"\"TERNS+=('^evil/.*\\\$')\")"
pinmutins "read into a computed array element name"                'n="ALLOW_PAT""TERNS[200]"; read -r "$n" <<< '"'"'^evil/.*$'"'"
pinmutins "plain dot-source of ./extra.sh"                          ". ./extra.sh"
pinmutins "DEBUG trap after the arrays"                             "trap 'exit 0' DEBUG"
pinmutins "RETURN trap after the arrays"                            "trap ':' RETURN"
pinmutins "ERR trap after the arrays"                               "trap 'exit 0' ERR"
pinmutins "exec of another script"                                  "exec bash ./other.sh"
sed -E "s/^  '\^LICENSE\\\$'/  '^evil\/.*\$'/" bin/check-file-allowlist.sh > "$_mut_dir/m.sh"; pinkill "older pattern LICENSE replaced in place (count unchanged)"
sed -E "s/^  '\^LICENSE\\\$'/  '^LICENS\$'/" bin/check-file-allowlist.sh > "$_mut_dir/m.sh"; pinkill "older pattern narrowed"
sed -E "s/^  return 0\$/  return 1/" bin/check-file-allowlist.sh > "$_mut_dir/m.sh"; pinkill "a logic line changed"
sed -E "/^  '\^osv-scanner\\\\\.toml\\\$'\$/d" bin/check-file-allowlist.sh > "$_mut_dir/m.sh"; pinkill "a suppression pattern deleted"
# B1 (round 6): the script is read once as bytes and any CR (lone or CRLF), NUL or other control byte, and any
# Unicode line separator, is refused. Each mutant is built from the real script by the python helper below.
bytemut() { # <desc> <python expression over b (bytes of the real script) returning the mutated bytes>
  python3 -c 'import sys; b=open("bin/check-file-allowlist.sh","rb").read(); open(sys.argv[1],"wb").write(eval(sys.argv[2]))' "$_mut_dir/m.sh" "$2"
  if cmp -s bin/check-file-allowlist.sh "$_mut_dir/m.sh"; then gf "mutant did not apply: $1" ""; elif struct_check "$_mut_dir/m.sh" >/dev/null 2>&1; then gf "struct check MISSED mutant: $1" ""; else gp "struct check kills mutant: $1"; fi
}
bytemut "lone CRs in region comments + merged patterns + junk bench line (the round-6 probe)" \
  'b.replace(b"  \x27^bin/vendor-check\\.sh$\x27\n  \x27^bin/vendor-provenance\\.py$\x27\n", b"  \x27^bin/vendor-(check\\.sh|provenance\\.py)$\x27\n").replace(b"# Archive scripts: push, pull (.sh) and verify (.py).", b"# Archive scripts:\r  # push, pull (.sh) and verify (.py).").replace(b"# OCI digest and network-probe tools.", b"# OCI digest and\r  # network-probe tools.").replace(b"  \x27^\\.github/release-identity\\.json$\x27\n\n", b"  \x27^\\.github/release-identity\\.json$\x27\n\n  \x27^bench/.*$\x27\n\n",1)'
bytemut "a lone CR in an older comment line"      'b.replace(b"ALLOW_PATTERNS=(\n", b"ALLOW_PATTERNS=(\n  # x\ry\n", 1)'
bytemut "CRLF line endings throughout"           'b.replace(b"\n", b"\r\n")'
bytemut "a NUL byte in a comment inside the span" 'b.replace(b"# OCI digest and network-probe tools.", b"# OCI digest\x00 and network-probe tools.")'
bytemut "a NUL byte outside the span"            'b.replace(b"ALLOW_PATTERNS=(\n", b"ALLOW_PATTERNS=(\n  # x\x00y\n", 1)'
bytemut "a vertical tab in a comment"            'b.replace(b"# OCI digest and network-probe tools.", b"# OCI digest\x0b and network-probe tools.")'
bytemut "a form feed in a comment"               'b.replace(b"# OCI digest and network-probe tools.", b"# OCI digest\x0c and network-probe tools.")'
bytemut "U+2028 in a comment"                    'b.replace(b"# OCI digest and network-probe tools.", "# OCI digest  and network-probe tools.".encode())'
bytemut "a lone CR in the NOTE comments"         'b.replace(b"# NOTE: only the PATH is gated here, not the file", b"# NOTE: only the PATH\r is gated here, not the file")'
bytemut "the region marker line with a trailing CR" 'b.replace(b"vendor/ is admitted by the PR that adds it.\n", b"vendor/ is admitted by the PR that adds it.\r\n", 1)'
bytemut "invalid UTF-8 byte in a comment"        'b.replace(b"# OCI digest and network-probe tools.", b"# OCI digest\xff and network-probe tools.")'
rm -rf "$_mut_dir"
# same, but drive GITHUB_REF_NAME (the push path) instead of a PR head ref
run_ref() {
  local expect="$1"; local ref="$2"; local desc="$3"; shift 3
  local out rc
  out="$(printf '%s\n' "$@" | GITHUB_HEAD_REF="" GITHUB_REF_NAME="$ref" "$SCRIPT" 2>&1)"; rc=$?
  if { [ "$expect" = pass ] && [ "$rc" -eq 0 ]; } || { [ "$expect" = fail ] && [ "$rc" -ne 0 ]; }; then
    echo "ok:   $desc"; pass=$((pass+1))
  else
    echo "FAIL: $desc (expected $expect, rc=$rc)"; echo "$out" | sed 's/^/      /'; fail=$((fail+1))
  fi
}

SUPP=(".snyk" "osv-scanner.toml" ".auditor/accepted-items.json"
      # REQ-AUD-16: the generated knowledge doc (AC3) and merge-gated proposals (AC4) the auditor
      # carries in its own suppression PR.
      ".auditor/knowledge.md" ".auditor/proposals/adjudicator-proposals.json")

# GITHUB_HEAD_REF is only a branch NAME: auditor/* on a pull_request is the auditor lane only when the
# head repository IS this repository (GITHUB_HEAD_REPO == GITHUB_REPOSITORY). `main` is special only on
# a push event, never as a PR head. A fork can name its branch anything.
HEADREPO=fork/r
run fail "auditor/zzz" "FORK PR from auditor/zzz: suppression outputs blocked" "${SUPP[@]}"
run fail "main"        "FORK PR from main: suppression outputs blocked"        "${SUPP[@]}"
HEADREPO=
run fail "auditor/zzz" "PR with the head repo empty: fails closed"             "${SUPP[@]}"
HEADREPO=o/r
run fail "main"        "same-repo PR from a branch named main: not special (only a push to main is)" "${SUPP[@]}"
unset HEADREPO
run pass "auditor/zzz" "same-repo PR from auditor/zzz: allowed as today" "${SUPP[@]}"
( printf '%s\n' .snyk | GITHUB_HEAD_REF=auditor/zzz GITHUB_REF_NAME="" GITHUB_REPOSITORY=o/r "$SCRIPT" >/dev/null 2>&1 ) \
  && { echo "FAIL: head-repo variable unset on a PR event must fail closed"; fail=$((fail+1)); } \
  || { echo "ok:   head-repo variable unset on a PR event fails closed"; pass=$((pass+1)); }

# The auditor lane may introduce/change its suppression outputs.
run pass "auditor/2026-09-24-abc123"      "auditor/ PR head: suppression outputs allowed"      "${SUPP[@]}"
run pass "auditor/proof-2026-09-24-abc12" "auditor/ proof PR head: suppression outputs allowed" "${SUPP[@]}"
# The merged state on main keeps them (scanners read them; release-authz reads the inventory).
run_ref pass "main" "push to main: suppression outputs allowed" "${SUPP[@]}"
# No other branch may add or edit a suppression (can't slip one past a scanner via a feature PR).
run fail "feature/x"        "feature PR head: suppression outputs blocked"      "${SUPP[@]}"
run fail "renovate/deps"    "bot PR head: suppression outputs blocked"          "${SUPP[@]}"
run fail "auditorX/nope"    "look-alike prefix (not auditor/): blocked"         ".snyk"
# The private-content guard is intact even on the auditor lane.
run fail "auditor/2026-09-24-abc123" "auditor/ lane does NOT open a hole for ops/brief content" "ops/runbook.md"
run fail "auditor/2026-09-24-abc123" "auditor/ lane does NOT allow arbitrary root files"        "secrets.txt"
# Ordinary product files still pass regardless of branch.
run pass "feature/x" "product Go source still allowed off the auditor lane" "internal/cache/store.go"

# --- Unchanged-suppression rule (non-auditor, non-main branches) -------------------------------
# CI checks the WHOLE tree, so a suppression file already on main is in the tree of every PR. The rule
# is "a feature PR cannot ADD or CHANGE a suppression", not "cannot contain one": on any other branch
# a suppression path passes only if it exists at the merge base with the base branch and is identical
# there (content and mode). Base = $GITHUB_BASE_REF, else origin/main. Unresolvable => fail closed.
ABS_SCRIPT="$(pwd)/bin/check-file-allowlist.sh"
TMPROOT="$(mktemp -d)"; trap 'rm -rf "$TMPROOT"' EXIT
g() { git -c user.name=t -c user.email=t@example.invalid -c commit.gpgsign=false -c core.hooksPath=/dev/null "$@"; }
# mkrepo <dir>: a repo whose origin/main holds .auditor/panel-state.json and .snyk, on branch feature/x
mkrepo() {
  local d="$1"
  rm -rf "$d"; mkdir -p "$d/.auditor"; ( cd "$d" && g init -q -b main . \
    && echo '{"a":1}' > .auditor/panel-state.json && echo 'ignore: {}' > .snyk && echo 'package x' > internal.go \
    && g add -A && g commit -q -m base \
    && g update-ref refs/remotes/origin/main HEAD && g checkout -q -b feature/x )
}
# trun <expect> <desc> <dir> <head-ref> <base-ref-or-empty> <paths...> : run the script inside <dir>
trun() {
  local expect="$1" desc="$2" dir="$3" head="$4" base="$5"; shift 5
  local out rc
  out="$(cd "$dir" && printf '%s\n' "$@" | GITHUB_HEAD_REF="$head" GITHUB_REF_NAME="" GITHUB_BASE_REF="$base" GITHUB_REPOSITORY=o/r GITHUB_HEAD_REPO="${HEADREPO-o/r}" "$ABS_SCRIPT" 2>&1)"; rc=$?
  if { [ "$expect" = pass ] && [ "$rc" -eq 0 ]; } || { [ "$expect" = fail ] && [ "$rc" -ne 0 ]; }; then
    echo "ok:   $desc"; pass=$((pass+1))
  else
    echo "FAIL: $desc (expected $expect, rc=$rc)"; echo "$out" | sed 's/^/      /'; fail=$((fail+1))
  fi
}
PS=.auditor/panel-state.json
R="$TMPROOT/r"

mkrepo "$R"
trun pass "feature: suppression files untouched since the merge base are allowed" "$R" feature/x "" "$PS" .snyk
# an unrelated commit on the feature branch does not disturb them
( cd "$R" && mkdir -p internal && echo 'package y' > internal/other.go && g add -A && g commit -q -m other )
trun pass "feature: unrelated commit, suppression files still untouched" "$R" feature/x "" "$PS" .snyk internal/other.go

( cd "$R" && echo '{"a":2}' > $PS && g commit -qam edit )
trun fail "feature: edited suppression file is blocked" "$R" feature/x "" "$PS"
trun pass "feature: the other, untouched suppression file is still allowed" "$R" feature/x "" .snyk

mkrepo "$R"; ( cd "$R" && echo 'x' > osv-scanner.toml && g add -A && g commit -q -m add )
trun fail "feature: newly added suppression file (not on main) is blocked" "$R" feature/x "" osv-scanner.toml

mkrepo "$R"; ( cd "$R" && g rm -q .snyk && g commit -qm del && echo 'ignore: {}' > .snyk && g add .snyk && g commit -qm readd )
trun pass "feature: deleted then re-added with identical content is allowed" "$R" feature/x "" .snyk
mkrepo "$R"; ( cd "$R" && g rm -q .snyk && g commit -qm del && echo 'ignore: {evil: 1}' > .snyk && g add .snyk && g commit -qm readd )
trun fail "feature: deleted then re-added with different content is blocked" "$R" feature/x "" .snyk

mkrepo "$R"; ( cd "$R" && chmod +x .snyk && g add .snyk && g commit -qm mode )
trun fail "feature: mode change only is blocked" "$R" feature/x "" .snyk

mkrepo "$R"; ( cd "$R" && g update-ref -d refs/remotes/origin/main )
trun fail "feature: base ref missing fails closed" "$R" feature/x "" "$PS"
trun pass "feature: base ref missing, non-suppression files unaffected" "$R" feature/x "" internal/x.go
mkrepo "$R"
trun fail "feature: GITHUB_BASE_REF naming a ref that does not exist fails closed" "$R" feature/x "nope" "$PS"
trun fail "feature: GITHUB_BASE_REF with option-like value fails closed" "$R" feature/x "--help" "$PS"
# GITHUB_BASE_REF honoured: origin/rel differs from origin/main
( cd "$R" && g checkout -q -b rel && echo '{"a":9}' > $PS && g commit -qam rel && g update-ref refs/remotes/origin/rel HEAD && g checkout -q feature/x )
trun pass "feature: base ref defaults to origin/main (unchanged vs main)" "$R" feature/x "" "$PS"
( cd "$R" && g checkout -q -b feat2 refs/remotes/origin/rel )
trun pass "feature: GITHUB_BASE_REF=rel honoured (unchanged vs rel)" "$R" feat2 rel "$PS"
trun fail "feature: with default base, the same file differs from origin/main" "$R" feat2 "" "$PS"
( cd "$R" && g checkout -q feature/x )

# unrelated history: no merge base => fail closed
mkrepo "$R"; ( cd "$R" && g checkout -q --orphan lone && g rm -rqf . && mkdir -p .auditor && echo '{"a":1}' > $PS && g add -A && g commit -qm lone )
trun fail "feature: no merge base with the base ref fails closed" "$R" lone "" "$PS"

# a shallow clone cannot resolve the merge base => fail closed
mkrepo "$R"; ( cd "$R" && mkdir -p internal && echo 'package z' > internal/z.go && g add -A && g commit -qm z )
SH="$TMPROOT/sh"; rm -rf "$SH"; g clone -q --depth 1 "file://$R" "$SH" 2>/dev/null
BASESHA="$(cd "$R" && git rev-parse HEAD~1)"
( cd "$SH" && g fetch -q --depth 1 origin "$BASESHA":refs/remotes/origin/main )
trun fail "feature: shallow clone without a resolvable merge base fails closed" "$SH" feature/x "" "$PS"

# move / copy of a suppression file to another suppression-pattern path: the new path is not at the
# merge base, so it is a change (judged on the PR's own changes, not on the tree). The old path of a
# move is deleted and is simply not listed, so it is not an error.
mkrepo "$R"; ( cd "$R" && mkdir -p .auditor/proposals && echo '{"p":1}' > .auditor/proposals/a.json && g add -A && g commit -qm a && g update-ref refs/remotes/origin/main HEAD )
( cd "$R" && g mv .auditor/proposals/a.json .auditor/proposals/b.json && g commit -qm mv )
trun fail "feature: move of a suppression file to another suppression path is blocked" "$R" feature/x "" .auditor/proposals/b.json
trun pass "feature: the deleted old path of a move is not listed and not an error" "$R" feature/x "" "$PS" .snyk
mkrepo "$R"; ( cd "$R" && mkdir -p .auditor/proposals && echo '{"p":1}' > .auditor/proposals/a.json && g add -A && g commit -qm a && g update-ref refs/remotes/origin/main HEAD \
  && cp .auditor/proposals/a.json .auditor/proposals/b.json && g add -A && g commit -qm cp )
trun fail "feature: copy of a suppression file to another suppression path is blocked" "$R" feature/x "" .auditor/proposals/a.json .auditor/proposals/b.json
mkrepo "$R"; ( cd "$R" && cp .snyk osv-scanner.toml && g add -A && g commit -qm cp )
trun fail "feature: .snyk content copied to osv-scanner.toml is blocked" "$R" feature/x "" .snyk osv-scanner.toml

mkrepo "$R"; ( cd "$R" && echo '{"a":5}' > $PS && g commit -qam edit )
HEADREPO=fork/r
trun fail "fork PR from auditor/x with an edited suppression file is blocked" "$R" auditor/x "" "$PS"
trun fail "fork PR from main with an edited suppression file is blocked" "$R" main "" "$PS"
unset HEADREPO

# judging a COMMIT instead of the checkout (the trusted review gate runs main's copy of this script over a
# PR head it only has as git objects): ALLOWLIST_HEAD_REV=<full sha> replaces HEAD and the index. The
# checkout (HEAD) is main here, and must not leak into the verdict.
revrun() {  # revrun <expect> <desc> <rev> <paths...>   (cwd $R, checked out on main)
  local expect="$1" desc="$2" rev="$3"; shift 3
  local out rc
  out="$(cd "$R" && printf '%s\n' "$@" | GITHUB_HEAD_REF=feature/x GITHUB_REF_NAME="" GITHUB_BASE_REF=main GITHUB_REPOSITORY=o/r GITHUB_HEAD_REPO=o/r ALLOWLIST_HEAD_REV="$rev" "$ABS_SCRIPT" 2>&1)"; rc=$?
  if { [ "$expect" = pass ] && [ "$rc" -eq 0 ]; } || { [ "$expect" = fail ] && [ "$rc" -ne 0 ]; }; then
    echo "ok:   $desc"; pass=$((pass+1))
  else
    echo "FAIL: $desc (expected $expect, rc=$rc)"; echo "$out" | sed 's/^/      /'; fail=$((fail+1))
  fi
}
mkrepo "$R"; ( cd "$R" && echo 'package q' > q.go && g add -A && g commit -qm same )
SAME="$(cd "$R" && git rev-parse HEAD)"
( cd "$R" && echo '{"a":6}' > $PS && echo x > osv-scanner.toml && g add -A && g commit -qm chg )
CHG="$(cd "$R" && git rev-parse HEAD)"
( cd "$R" && g checkout -q main )
revrun pass "rev: untouched suppression files at the PR head pass (checkout is main)" "$SAME" "$PS" .snyk
revrun fail "rev: edited suppression file at the PR head is blocked" "$CHG" "$PS"
revrun fail "rev: new suppression file at the PR head is blocked" "$CHG" osv-scanner.toml
revrun pass "rev: the other untouched file at that head still passes" "$CHG" .snyk
revrun fail "rev: a rev that is not a full hex sha fails closed" "main" "$PS"
revrun fail "rev: a hex sha that is not a commit fails closed" "0000000000000000000000000000000000000000" "$PS"
revrun fail "rev: an option-like rev fails closed" "--help" "$PS"
revrun fail "rev: private content is still blocked" "$SAME" ops/runbook.md

# criss-cross history: two merge bases; the file must be unchanged against EVERY one of them
mkrepo "$R"
# Deterministic commit dates: `git merge-base` (no --all) returns the NEWEST of the merge bases, and with equal
# timestamps (commits made within one second) the pick is arbitrary. Every fixture commit gets an explicit,
# strictly increasing date after the base commit, A1 newer than B1, so the pick is always A1 (the base whose
# content equals the head's).
T0="$(cd "$R" && git log -1 --format=%ct main)"
gd() { local t=$((T0+$1)); shift; GIT_AUTHOR_DATE="@$t +0000" GIT_COMMITTER_DATE="@$t +0000" g "$@"; }
( cd "$R" && g checkout -q -b B1 main && echo b > other-b.go && g add -A && gd 10 commit -qm b1 \
  && g checkout -q -b A1 main && echo '{"a":7}' > $PS && gd 20 commit -qam a1 \
  && g checkout -q -b A2 A1 && gd 30 merge -q --no-edit B1 \
  && g checkout -q -b B2 B1 && gd 40 merge -q --no-edit A1 \
  && g update-ref refs/remotes/origin/main B2 && g checkout -q A2 )
[ "$(cd "$R" && git merge-base --all HEAD origin/main | wc -l | tr -d ' ')" = 2 ] && gp "criss-cross fixture really has two merge bases" || gf "criss-cross fixture" "expected two merge bases"
# whichever base git would pick alone, one of the two bases has the other content: ensure the single-base pick
# is the base whose content EQUALS the head's, so only checking every base can block
PICK="$(cd "$R" && git merge-base HEAD origin/main)"
# Not dependent on which base git picks: make the head's file equal the PICKED base's content (the two bases
# differ, so the head still differs from the other one), then check the pick really equals the head.
( cd "$R" && git cat-file -p "$PICK:$PS" > "$PS" && g add "$PS" && { g diff --cached --quiet || gd 50 commit -qm sync-head-to-pick; } )
[ "$(cd "$R" && git merge-base --all HEAD origin/main | wc -l | tr -d ' ')" = 2 ] || gf "criss-cross fixture" "the sync commit changed the merge bases"
( cd "$R" && git cat-file -p "$PICK:$PS" | cmp -s - "$PS" ) && gp "criss-cross: the single-base pick equals the head (only --all can block)" || gf "criss-cross pick" "pick differs from head after syncing"
trun fail "criss-cross: file equal to one merge base but not the other is blocked" "$R" feature/x "" "$PS"
trun pass "criss-cross: a file identical in every merge base is allowed" "$R" feature/x "" .snyk

# NUL-delimited input (ALLOWLIST_NUL=1, for `git ls-tree -z`): a path containing a newline is ONE path, not two
# allowed ones; without the variable the line-oriented behaviour is unchanged
nul() {  # nul <expect> <desc> <env NUL value or empty> <printf format> <args...>
  local expect="$1" desc="$2" nulv="$3" fmt="$4"; shift 4
  local out rc
  out="$(printf "$fmt" "$@" | GITHUB_HEAD_REF=feature/x GITHUB_REF_NAME="" GITHUB_REPOSITORY=o/r ALLOWLIST_NUL="$nulv" "$SCRIPT" 2>&1)"; rc=$?
  if { [ "$expect" = pass ] && [ "$rc" -eq 0 ]; } || { [ "$expect" = fail ] && [ "$rc" -ne 0 ]; }; then
    echo "ok:   $desc"; pass=$((pass+1))
  else
    echo "FAIL: $desc (expected $expect, rc=$rc)"; echo "$out" | sed 's/^/      /'; fail=$((fail+1))
  fi
}
nul pass "nul: ordinary NUL-delimited list passes" 1 'internal/a.go\0README.md\0'
nul pass "nul: last record without a terminator passes" 1 'internal/a.go\0README.md'
nul fail "nul: one path with an embedded newline is one (blocked) path" 1 'internal/a.go\nREADME.md\0'
nul pass "no ALLOWLIST_NUL: the same bytes split on newlines as before" "" 'internal/a.go\nREADME.md\n'
nul fail "nul: a disallowed path in the list is blocked" 1 'internal/a.go\0ops/runbook.md\0'

# git pathspecs are literal (GIT_LITERAL_PATHSPECS=1): the script's own git calls never glob a path
mkdir -p "$TMPROOT/shim"
cat > "$TMPROOT/shim/git" <<EOS
#!/bin/sh
echo "\${GIT_LITERAL_PATHSPECS:-unset}" >> "$TMPROOT/literal.log"
exec $(command -v git) "\$@"
EOS
chmod +x "$TMPROOT/shim/git"
mkrepo "$R"; : > "$TMPROOT/literal.log"
( cd "$R" && printf '%s\n' "$PS" | PATH="$TMPROOT/shim:$PATH" GITHUB_HEAD_REF=feature/x GITHUB_REPOSITORY=o/r "$ABS_SCRIPT" >/dev/null 2>&1 )
if [ -s "$TMPROOT/literal.log" ] && ! grep -qv '^1$' "$TMPROOT/literal.log"; then gp "every git call runs with GIT_LITERAL_PATHSPECS=1"; else gf "literal pathspecs" "log: $(sort -u "$TMPROOT/literal.log" | tr '\n' ' ')"; fi

# other branches keep today's behaviour
mkrepo "$R"; ( cd "$R" && echo '{"a":3}' > $PS && g commit -qam edit )
trun pass "auditor/x branch: edited suppression file allowed (unchanged behaviour)" "$R" auditor/x "" "$PS"
trun fail "main as PR head is not the feature rule: private content still blocked" "$R" auditor/x "" ops/runbook.md
( cd "$R" && out="$(printf '%s\n' "$PS" | GITHUB_HEAD_REF="" GITHUB_REF_NAME=main "$ABS_SCRIPT" 2>&1)"; rc=$?
  [ "$rc" -eq 0 ] ) && gp "push to main: edited suppression file allowed (unchanged behaviour)" || gf "push to main allowed" "rc!=0"
trun fail "feature: non-suppression unlisted file still blocked" "$R" feature/x "" ops/runbook.md
trun fail "feature: edited suppression plus unlisted file reports failure" "$R" feature/x "" "$PS" secrets.txt
# pre-commit usage: no env at all, local branch name, staged change compared with the merge base
mkrepo "$R"
( cd "$R" && printf '%s\n' "$PS" .snyk | env -u GITHUB_HEAD_REF -u GITHUB_REF_NAME -u GITHUB_BASE_REF -u GITHUB_REPOSITORY -u GITHUB_HEAD_REPO "$ABS_SCRIPT" >/dev/null 2>&1 ) \
  && gp "pre-commit usage (no env, local feature branch): untouched suppression files pass" || gf "pre-commit untouched" "rc!=0"
( cd "$R" && echo '{"a":4}' > $PS && g add $PS && printf '%s\n' "$PS" | env -u GITHUB_HEAD_REF -u GITHUB_REF_NAME -u GITHUB_BASE_REF -u GITHUB_REPOSITORY -u GITHUB_HEAD_REPO "$ABS_SCRIPT" >/dev/null 2>&1 ) \
  && gf "pre-commit staged edit" "should have been blocked" || gp "pre-commit usage: staged edit of a suppression file is blocked"

# The reserved-branch guard: only the delivery App may push the auditor/* lane (the allowlist
# relaxes suppression paths there), so a dev branch can never use it to slip a suppression past.
GUARD=.github/workflows/reserved-branch-guard.yml
if [ -f "$GUARD" ]; then
  gp "reserved-branch guard workflow present"
  if grep -qE "auditor/\*\*" "$GUARD" && grep -qE "^\s*push:" "$GUARD"; then
    gp "guard triggers on push to auditor/*"
  else gf "guard triggers on push to auditor/*" "missing push:auditor/** trigger"; fi
  if grep -q "fosterstack-automation" "$GUARD" && grep -qE "exit 1" "$GUARD"; then
    gp "guard rejects any pusher that is not the delivery App"
  else gf "guard gates on the App actor and fails closed" "missing App-actor check / exit 1"; fi
else
  gf "reserved-branch guard workflow present" "$GUARD missing"
fi

# --- The local pre-commit hook judges only what THIS commit introduces ------------------------------
# Normal commit: the staged diff against HEAD. Merge commit (MERGE_HEAD present): only files that differ
# from HEAD AND from every MERGE_HEAD parent, so content that merely came from the other parent (already
# on main, already judged) is not re-judged, while anything the merge itself adds or changes still is.
# These cases run the REAL .githooks/pre-commit and bin/check-file-allowlist.sh from a temp repo.
HOOKSRC="$(pwd)/.githooks"; ALLOWSRC="$(pwd)/bin/check-file-allowlist.sh"
HK="$TMPROOT/hk"
hk() { git -c user.name=t -c user.email=t@example.invalid -c commit.gpgsign=false -c core.hooksPath="$HK/.githooks" "$@"; }
nohk() { git -c user.name=t -c user.email=t@example.invalid -c commit.gpgsign=false -c core.hooksPath=/dev/null "$@"; }
mkhk() {  # a repo on branch feature/x with the real hook installed; main has one allowed file
  rm -rf "$HK"; mkdir -p "$HK/bin" "$HK/.githooks"; cp "$HOOKSRC/pre-commit" "$HK/.githooks/"; cp "$ALLOWSRC" "$HK/bin/"
  ( cd "$HK" && nohk init -q -b main . && echo 'package x' > internal.go && nohk add -A && nohk commit -q -m base \
    && nohk update-ref refs/remotes/origin/main HEAD && nohk checkout -q -b feature/x )
}
hkexpect() {  # hkexpect <expect> <desc> <command string run in $HK>
  local expect="$1" desc="$2" out rc
  out="$(cd "$HK" && eval "$3" 2>&1)"; rc=$?
  if { [ "$expect" = pass ] && [ "$rc" -eq 0 ]; } || { [ "$expect" = fail ] && [ "$rc" -ne 0 ] && grep -q 'blocked' <<<"$out"; }; then  # here-string: `printf | grep -q` under pipefail can fail by SIGPIPE when grep exits early
    echo "ok:   $desc"; pass=$((pass+1))
  else
    echo "FAIL: $desc (expected $expect with the allowlist's 'blocked' message, rc=$rc)"; echo "$out" | sed 's/^/      /'; fail=$((fail+1))
  fi
}
# on branch <name> from the base, commit a file with the hook disabled
hkbranch() { ( cd "$HK" && nohk checkout -q -b "$1" main && mkdir -p "$(dirname "$2")" && echo "$3" > "$2" && nohk add -A && nohk commit -q -m "$1" && nohk checkout -q feature/x ); }

mkhk
hkexpect pass "hook: normal commit adding an allowed file passes" 'echo "package y" > internal/y.go 2>/dev/null || { mkdir -p internal; echo "package y" > internal/y.go; }; hk add -A && hk commit -q -m ok'
mkhk
hkexpect fail "hook: normal commit adding .env is rejected" 'echo S=1 > .env && hk add -f .env && hk commit -q -m bad'

# (c) other parent carries a tracked, unlisted file that is already on main
mkhk; hkbranch other ops/notes.md main-side
( cd "$HK" && nohk checkout -q main && nohk merge -q other && nohk update-ref refs/remotes/origin/main HEAD && nohk checkout -q feature/x && echo 'package f' > f.go && nohk add -A && nohk commit -q -m feat )
hkexpect pass "hook: merge bringing in a file already tracked on the other parent (not allowlisted) passes" 'hk merge -q --no-ff --no-commit main && hk commit -q -m merge'
# (d) the resolution itself adds a new disallowed file
mkhk; hkbranch other ops/notes.md main-side
( cd "$HK" && nohk checkout -q main && nohk merge -q other && nohk checkout -q feature/x && echo 'package f' > f.go && nohk add -A && nohk commit -q -m feat )
hkexpect fail "hook: merge whose resolution ADDS a disallowed file is rejected" 'hk merge -q --no-ff --no-commit main && echo S=1 > .env && hk add -f .env && hk commit -q -m merge'
# (e) the feature branch LACKS the unlisted file; it exists only on the other parent, so the merge adds it
# to HEAD's side but it is identical to MERGE_HEAD: it came from that parent, passes (old hook rejects)
mkhk; hkbranch other ops/shared.md same
( cd "$HK" && echo 'package f' > f.go && nohk add -A && nohk commit -q -m feat )
hkexpect pass "hook: merge adding a file present identically in the other parent only passes" 'hk merge -q --no-ff --no-commit other && hk commit -q -m merge'
# (e2) the resolution modifies a file differently from both parents: introduced by the merge, judged
mkhk; hkbranch other ops/shared.md theirs
( cd "$HK" && nohk checkout -q main && nohk merge -q other && nohk checkout -q feature/x && mkdir -p ops && echo mine > ops/shared.md && nohk add -A && nohk commit -q -m feat )
hkexpect fail "hook: merge resolution that writes a third version of an unlisted file is rejected" 'hk merge -q --no-ff --no-commit main; echo resolved > ops/shared.md && hk add ops/shared.md && hk commit -q -m merge'
# stale/leftover MERGE_HEAD: a normal commit with MERGE_HEAD present is a merge commit by git's own logic;
# the hook must not crash and must still reject a disallowed file staged in it
mkhk; hkbranch other ops/notes.md x
( cd "$HK" && git rev-parse other > .git/MERGE_HEAD )
hkexpect fail "hook: leftover MERGE_HEAD, disallowed file staged: rejected by the allowlist (not a crash)" 'echo S=1 > .env && hk add -f .env && out=$(hk commit -q -m stale 2>&1); rc=$?; echo "$out"; grep -q "blocked" <<<"$out" && exit $rc'
# type / mode changes: the other parent's diff reports T (or M), which must still count as "differs from
# that parent". The feature branch lacks ops/x, so against HEAD the path is an addition.
hkbranch_link() { ( cd "$HK" && nohk checkout -q -b "$1" main && mkdir -p ops && ln -s target ops/x && nohk add -A && nohk commit -q -m "$1" && nohk checkout -q feature/x ); }
mkhk; hkbranch_link other; ( cd "$HK" && echo 'package f' > f.go && nohk add -A && nohk commit -q -m feat )
hkexpect fail "hook: merge replacing the other parent's symlink with a regular file is rejected (type change)" 'hk merge -q --no-ff --no-commit other && rm ops/x && echo data > ops/x && hk add ops/x && hk commit -q -m merge'
mkhk; hkbranch other ops/x data; ( cd "$HK" && echo 'package f' > f.go && nohk add -A && nohk commit -q -m feat )
hkexpect fail "hook: merge replacing the other parent's regular file with a symlink is rejected (type change)" 'hk merge -q --no-ff --no-commit other && rm ops/x && ln -s target ops/x && hk add ops/x && hk commit -q -m merge'
mkhk; hkbranch other ops/x data; ( cd "$HK" && echo 'package f' > f.go && nohk add -A && nohk commit -q -m feat )
hkexpect fail "hook: merge replacing the other parent's file with a submodule gitlink is rejected" 'hk merge -q --no-ff --no-commit other && hk rm -q --cached ops/x && hk update-index --add --cacheinfo 160000,"$(git rev-parse HEAD)",ops/x && hk commit -q -m merge'
mkhk; hkbranch other ops/x data; ( cd "$HK" && echo 'package f' > f.go && nohk add -A && nohk commit -q -m feat )
hkexpect fail "hook: merge changing only the mode (100644 to 100755) of the other parent's file is rejected" 'hk merge -q --no-ff --no-commit other && chmod +x ops/x && hk add ops/x && hk commit -q -m merge'
# HEAD side: a type change staged in a PLAIN commit is judged too (T in the HEAD-side filter)
mkhk; ( cd "$HK" && mkdir -p ops && ln -s target ops/x && nohk add -A && nohk commit -q -m link )
hkexpect fail "hook: plain commit turning a tracked symlink into a regular file (type change) is rejected" 'rm ops/x && echo data > ops/x && hk add ops/x && hk commit -q -m tc'
mkhk; ( cd "$HK" && mkdir -p ops && echo data > ops/x && nohk add -A && nohk commit -q -m file )
hkexpect fail "hook: plain commit turning a tracked regular file into a symlink (type change) is rejected" 'rm ops/x && ln -s target ops/x && hk add ops/x && hk commit -q -m tc'
# diff.ignoreSubmodules=all must not hide gitlink differences
mkhk; ( cd "$HK" && git config diff.ignoreSubmodules all )
hkexpect fail "hook: plain commit adding a gitlink at an unlisted path is rejected even with diff.ignoreSubmodules=all" 'hk update-index --add --cacheinfo 160000,"$(git rev-parse HEAD)",ops/g && hk commit -q -m gl'
mkhk; hkbranch other ops/x data; ( cd "$HK" && echo 'package f' > f.go && nohk add -A && nohk commit -q -m feat && git config diff.ignoreSubmodules all )
hkexpect fail "hook: merge replacing the other parent's file with a gitlink is rejected even with diff.ignoreSubmodules=all" 'hk merge -q --no-ff --no-commit other && hk rm -q --cached ops/x && hk update-index --add --cacheinfo 160000,"$(git rev-parse HEAD)",ops/x && hk commit -q -m merge'
# non-ASCII paths, UTF-8 locale, unquoted names: the merge still judges the right paths
NA=$(printf 'ops/caf\303\251.md')
mkhk; hkbranch other "$NA" x; ( cd "$HK" && echo 'package f' > f.go && nohk add -A && nohk commit -q -m feat && git config core.quotePath false )
hkexpect pass "hook: merge bringing a non-ASCII unlisted path from the other parent passes (UTF-8 locale, quotePath=false)" 'export LC_ALL=en_US.UTF-8; hk merge -q --no-ff --no-commit other && hk commit -q -m merge'
mkhk; hkbranch other "$NA" x; ( cd "$HK" && echo 'package f' > f.go && nohk add -A && nohk commit -q -m feat && git config core.quotePath false )
hkexpect fail "hook: merge resolution adding a non-ASCII unlisted path is rejected (UTF-8 locale, quotePath=false)" 'export LC_ALL=en_US.UTF-8; hk merge -q --no-ff --no-commit other && printf z > "ops/na\303\257ve.md" && hk add -A && hk commit -q -m merge'

# fail closed when the list cannot be produced: a PATH-shadowed tool that fails must make the merge commit
# fail (non-zero, no merge commit created), never an empty list that accepts everything
hkfault() {  # hkfault <desc> <tool to shadow with a failing stub>
  local desc="$1" tool="$2" out rc
  mkhk; hkbranch other ops/notes.md x; ( cd "$HK" && echo 'package f' > f.go && nohk add -A && nohk commit -q -m feat )
  mkdir -p "$TMPROOT/stub"; printf '#!/bin/sh\nexit 1\n' > "$TMPROOT/stub/$tool"; chmod +x "$TMPROOT/stub/$tool"
  out="$(cd "$HK" && hk merge -q --no-ff --no-commit other >/dev/null 2>&1; PATH="$TMPROOT/stub:$PATH" hk commit -q -m merge 2>&1)"; rc=$?
  if [ "$rc" -ne 0 ] && ! ( cd "$HK" && git rev-parse -q --verify HEAD^2 >/dev/null ); then
    echo "ok:   $desc"; pass=$((pass+1))
  else
    echo "FAIL: $desc (rc=$rc, merge commit created or hook accepted)"; echo "$out" | sed 's/^/      /'; fail=$((fail+1))
  fi
  rm -rf "$TMPROOT/stub"
}
hkfault "hook: merge fails closed when sort fails (list cannot be produced)" sort
hkfault "hook: merge fails closed when mktemp fails" mktemp
hkfault "hook: merge fails closed when comm fails" comm

# (f) octopus: two other parents, each carrying an unlisted file
mkhk; hkbranch m1 ops/one.md 1; hkbranch m2 ops/two.md 2
( cd "$HK" && echo 'package f' > f.go && nohk add -A && nohk commit -q -m feat )
hkexpect pass "hook: octopus merge of two parents carrying unlisted files passes" 'hk merge -q --no-ff --no-commit m1 m2 && hk commit -q -m octo'
mkhk; hkbranch m1 ops/one.md 1; hkbranch m2 ops/two.md 2
( cd "$HK" && echo 'package f' > f.go && nohk add -A && nohk commit -q -m feat )
hkexpect fail "hook: octopus merge whose resolution adds a disallowed file is rejected" 'hk merge -q --no-ff --no-commit m1 m2 && echo S=1 > .env && hk add -f .env && hk commit -q -m octo'
# no MERGE_HEAD: cherry-pick and squash judge the staged diff against HEAD as before
mkhk; hkbranch other ops/notes.md x
hkexpect fail "hook: cherry-pick of a commit adding an unlisted file is rejected (no MERGE_HEAD)" 'hk cherry-pick -n other && hk commit -q -m cp'
mkhk; hkbranch other ops/notes.md x
hkexpect fail "hook: squash merge adding an unlisted file is rejected (no MERGE_HEAD)" 'hk merge -q --squash other && hk commit -q -m sq'

# --- v0.3.0 build-chain paths: one exact pattern per path family (PR 1 of the v0.3.0 plan) ----------------
# Each family: the intended path(s) pass; near-misses (extra segment, other extension, uppercase, traversal,
# one directory up, a sibling name) are refused. vendor/ is NOT admitted yet.
passfam "feature/x" "v030: dependency-provenance.json at the repo root" "dependency-provenance.json"
runeach fail "feature/x" "v030: dependency-provenance.json nested is refused"        "tools/dependency-provenance.json"
runeach fail "feature/x" "v030: dependency-provenance.json uppercase is refused"     "Dependency-Provenance.json"
runeach fail "feature/x" "v030: dependency-provenance.yaml (other extension) refused" "dependency-provenance.yaml"
runeach fail "feature/x" "v030: dependency-provenance.json.bak refused"              "dependency-provenance.json.bak"
runeach fail "feature/x" "v030: other root json refused"                             "provenance.json" "dependency-provenanceXjson" "dependency-provenance-json" "dependency-provenance.json "

passfam "feature/x" "v030: the vendoring scripts and their test" "bin/vendor-check.sh" "bin/vendor-provenance.py" "bin/vendoring-test.sh"
runeach fail "feature/x" "v030: bin/vendor-check.sh nested refused"        "bin/x/vendor-check.sh"
runeach fail "feature/x" "v030: bin/vendor-check.py (other extension) refused" "bin/vendor-check.py"
runeach fail "feature/x" "v030: bin/vendor-provenance.sh (swapped extension) refused" "bin/vendor-provenance.sh"
runeach fail "feature/x" "v030: bin/Vendor-check.sh uppercase refused"     "bin/Vendor-check.sh"
runeach fail "feature/x" "v030: bin/vendor-other.sh (sibling name) refused" "bin/vendor-other.sh"
runeach fail "feature/x" "v030: bin/../vendor-check.sh traversal refused"  "bin/../vendor-check.sh"
runeach fail "feature/x" "v030: vendor-check.sh one directory up refused"  "vendor-check.sh"
runeach fail "feature/x" "v030: bin/vendoring-test.py refused"             "bin/vendoring-test.py"

passfam "feature/x" "v030: the four melange and apko configs" "build/melange.yaml" "build/melange-fips.yaml" "build/apko.yaml" "build/apko-fips.yaml"
runeach fail "feature/x" "v030: build/melange.yml (other extension) refused"   "build/melange.yml"
runeach fail "feature/x" "v030: build/melange-FIPS.yaml uppercase refused"     "build/melange-FIPS.yaml"
runeach fail "feature/x" "v030: build/apko-other.yaml (unnamed suffix) refused" "build/apko-other.yaml"
runeach fail "feature/x" "v030: build/apko-debug.yaml (dropped image) refused" "build/apko-debug.yaml"
runeach fail "feature/x" "v030: build/apko-fips-fips.yaml (two suffixes) refused" "build/apko-fips-fips.yaml"
runeach fail "feature/x" "v030: build/sub/apko.yaml (extra segment) refused"   "build/sub/apko.yaml"
runeach fail "feature/x" "v030: build/docker/apko.yaml refused"                "build/docker/apko.yaml"
runeach fail "feature/x" "v030: apko.yaml one directory up refused"            "apko.yaml"
runeach fail "feature/x" "v030: build/../apko.yaml traversal refused"          "build/../apko.yaml"
runeach fail "feature/x" "v030: build/other.yaml refused"                      "build/other.yaml" "build/melange-debug.yaml" "build/melange-fips-fips.yaml" "build/melange-x.yaml" "build/melangeXyaml" "build/apkoXyaml"

passfam "feature/x" "v030: the three lock files" "build/locks/apko.base.lock.json" "build/locks/apko-fips.base.lock.json" "build/locks/melange.lock"
runeach fail "feature/x" "v030: other lock names refused" "build/locks/other.lock" "build/locks/apko-debug.base.lock.json" "build/locks/apko.lock.json" "build/locks/apko.base.lock.yaml" "build/locks/apko-fips.base.lockXjson" "build/locks/melangeXlock" "build/locks/melange.lock.json" "build/locks/apko.lock"
runeach fail "feature/x" "v030: nested lock refused"      "build/locks/x/melange.lock" "build/locks/sub/apko.base.lock.json"
runeach fail "feature/x" "v030: uppercase lock refused"   "build/locks/Melange.lock" "build/locks/apko.base.LOCK.json"
runeach fail "feature/x" "v030: lock one directory up refused" "build/melange.lock" "melange.lock" "build/apko.base.lock.json"
runeach fail "feature/x" "v030: lock traversal refused"   "build/locks/../melange.lock"
runeach fail "feature/x" "v030: lock with a suffix refused" "build/locks/melange.lock.bak" "build/locks/apko.base.lock.json.orig"

passfam "feature/x" "v030: the assembly key pair and the release public key" "build/keys/assembly.rsa" "build/keys/assembly.rsa.pub" "build/keys/release.rsa.pub"
runeach fail "feature/x" "v030: other key names refused" "build/keys/other.rsa" "build/keys/other.rsa.pub" "build/keys/release.rsa" "build/keys/Assembly.rsa" "build/keys/assemblyXrsa" "build/keys/release.rsa.pub.pem" "build/keys/assembly.rsa.pubx" "build/keys/assembly.pem"
runeach fail "feature/x" "v030: nested key refused"      "build/keys/x/assembly.rsa" "build/keys/sub/release.rsa.pub"
runeach fail "feature/x" "v030: uppercase key refused"   "build/keys/Assembly.rsa" "build/keys/assembly.RSA.pub"
runeach fail "feature/x" "v030: key one directory up refused" "build/assembly.rsa" "assembly.rsa" "keys/assembly.rsa.pub"
runeach fail "feature/x" "v030: key traversal refused"   "build/keys/../assembly.rsa"
runeach fail "feature/x" "v030: key with a suffix refused" "build/keys/assembly.rsa.bak" "build/keys/assembly.rsa.pub.old"

passfam "feature/x" "v030: the recipe template" "build/melange.yaml.tmpl"
runeach fail "feature/x" "v030: other template names refused" "build/melange-fips.yaml.tmpl" "build/apko.yaml.tmpl" "build/melange.yaml.tmpl.bak" "build/x/melange.yaml.tmpl" "melange.yaml.tmpl" "build/Melange.yaml.tmpl" "build/../melange.yaml.tmpl"
passfam "feature/x" "v030: the archive keyring digest and index record" "build/locks/archive-keys.sha256" "build/locks/archive-index.sha256"
runeach fail "feature/x" "v030: other archive record names refused" "build/locks/archive-other.sha256" "build/locks/archive-keys.sha256.bak" "build/locks/x/archive-keys.sha256" "build/locks/archive-keys.sha512" "build/locks/../archive-keys.sha256"
runeach fail "feature/x" "v030: the removed recipe comparer is no longer admitted" "bin/compare-recipes.py"
passfam "feature/x" "v030: the build-chain scripts" "bin/build-apk.sh" "bin/assemble-image.sh" "bin/apko-lock.sh" "bin/install-build-tools.sh" "bin/release-sign-apks.sh" "bin/sealed-proof.sh" "bin/lock-proof.sh" "bin/refresh-inputs.sh"
passfam "feature/x" "v030: the build-chain Python tools" "bin/apk-tool.py" "bin/gen-recipes.py" "bin/go-module-sbom.py"
runeach fail "feature/x" "v030: bin/build-apk.py (other extension) refused"   "bin/build-apk.py"
runeach fail "feature/x" "v030: bin/apk-tool.sh (swapped extension) refused"  "bin/apk-tool.sh"
runeach fail "feature/x" "v030: bin/Build-apk.sh uppercase refused"           "bin/Build-apk.sh"
runeach fail "feature/x" "v030: bin/x/assemble-image.sh (extra segment) refused" "bin/x/assemble-image.sh" "bin/x/go-module-sbom.py"
runeach fail "feature/x" "v030: assemble-image.sh one directory up refused"   "assemble-image.sh" "gen-recipes.py"
runeach fail "feature/x" "v030: suffixed script names refused"                "bin/assemble-image.sh.orig" "bin/apk-tool.py.bak"
runeach fail "feature/x" "v030: sibling names refused"                        "bin/sealed-proof-test.sh" "bin/build-apk-lib.sh" "bin/melange-apko-test.sh" "bin/refresh-inputs.py" "bin/lock-proof.py"
runeach fail "feature/x" "v030: bin/../build-apk.sh traversal refused"        "bin/../build-apk.sh"

# .github/release-identity.json is for REQ-REL-009 AC13-17 (the auto-baseline PR, advisor step-5 acceptance Oct 9);
# it is NOT part of the v0.3.0 build plan.
passfam "feature/x" "v030: the split build-chain test files and library" "bin/melange-apko-lib.sh" "bin/build-helpers-test.sh" "bin/refresh-inputs-test.sh" "bin/build-apk-test.sh" "bin/assemble-image-test.sh"
passfam "feature/x" "v030: the OCI digest and network probe tools" "bin/oci-digest.py" "bin/net-probe.py"
passfam "feature/x" "v030: the archive scripts and their test" "bin/archive-push.sh" "bin/archive-pull.sh" "bin/archive-verify.py" "bin/archive-test.sh"
passfam "feature/x" "v030: the secret-scanning config" ".github/secret_scanning.yml"
runeach fail "feature/x" "v030: near-miss siblings refused" "bin/melange-apko-test.sh" "bin/archive-push.py" "bin/archive-verify.sh" "bin/archive-pull.py" "bin/archive-test.py" "bin/oci-digest.sh" "bin/net-probe.sh" "bin/build-helpers.sh" "bin/archive-list.sh" ".github/secret_scanning.yaml" ".github/secret-scanning.yml" ".github/Secret_Scanning.yml" "build/archive.json" "secret_scanning.yml"
passfam "feature/x" "REQ-REL-009: .github/release-identity.json" ".github/release-identity.json"
runeach fail "feature/x" "REQ-REL-009: release-identity near-miss refused" ".github/release-identity.json.bak" ".github/Release-Identity.json" ".github/release-identity.yaml" ".github/other.json" ".github/nested/release-identity.json" ".github/x/release-identity.json" "release-identity.json" ".github/release-identity.json " ".github/release-identityXjson" ".github/policy/../release-identity.json"
passfam "feature/x" "REQ-REL-004-AC5: the daily-rescan current-release test" "bin/rescan-current-only-test.sh"
runeach fail "feature/x" "REQ-REL-004-AC5: rescan-current-only-test near-miss refused" "bin/rescan-current-only-test.sh.bak" "bin/rescan-current-only-test.shx" "bin/Rescan-Current-Only-Test.sh" "bin/sub/rescan-current-only-test.sh" "bin/rescan-current-only-test.py" "rescan-current-only-test.sh" "bin/rescan-current-only-test.sh "

passfam "feature/x" "v030: the supply-chain harness manifest" ".github/agent/supply-chain/harness-manifest.json"
runeach fail "feature/x" "v030: sibling name in supply-chain/ refused"        ".github/agent/supply-chain/harness-manifest2.json" ".github/agent/supply-chain/other.json"
runeach fail "feature/x" "v030: nested harness-manifest.json refused"         ".github/agent/supply-chain/x/harness-manifest.json"
runeach fail "feature/x" "v030: harness-manifest other extension refused"     ".github/agent/supply-chain/harness-manifest.yaml" ".github/agent/supply-chain/harness-manifest.json.bak"
runeach fail "feature/x" "v030: Harness-Manifest.json uppercase refused"      ".github/agent/supply-chain/Harness-Manifest.json"
runeach fail "feature/x" "v030: harness-manifest.json one directory up refused" ".github/agent/harness-manifest.json"
runeach fail "feature/x" "v030: supply-chain/../ traversal refused"           ".github/agent/supply-chain/../harness-manifest.json"

# Deferred (not admitted until the PR that adds them): the vendored tree.
runeach fail "feature/x" "v030: vendor/ files are NOT admitted yet" "vendor/modules.txt" "vendor/golang.org/x/text/a.go"

echo "----"
echo "check-file-allowlist: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
