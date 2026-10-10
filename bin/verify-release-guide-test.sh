#!/usr/bin/env bash
# proves: REQ-GUIDE-001-AC1, REQ-GUIDE-001-AC2, REQ-GUIDE-001-AC3, REQ-GUIDE-001-AC4, REQ-GUIDE-001-AC5, REQ-GUIDE-001-AC6, REQ-GUIDE-001-AC7
# The v0.3.0 customer verification guide, docs/verify-release.md (v0.3.0 rule 78, GUIDE-24), judged as a page: its size,
# its commands, its placeholders, what it verifies, which images it covers, the tool names it uses, and its open marks.
# The command format is the one pipeline's AC7 run (bin/check-guide.sh, REQ-CHAIN-006-AC7) reads, so a page that passes here
# is a page that run can read: every command is a line of a ```sh fenced block (a line ending in a backslash joins the next
# with one space; a line starting with # is a comment); placeholders are <IMAGE_REF>, <TAG> and <IDENTITY>, each defined once
# before the first fence as a list line  - `<NAME>`: what it is.
# Commands that need a registry image (cosign verify, cosign verify-attestation, gh attestation verify oci://...) cannot run on
# a candidate, which Check holds as a file: they are listed, word for word, in docs/verify-release.cannot-run.json as
# [{"command", "reason"}], each is marked on the page by the words "Not run before release" on the nearest line above it
# (a # comment in its block, or the line before the block's fence), and while the list is not empty the page may not claim
# that its commands were checked before release (the phrase list is CLAIM_PHRASES below).
#
# usage: bin/verify-release-guide-test.sh            draft mode: the page and every mutant (TO-VERIFY marks allowed)
#        bin/verify-release-guide-test.sh --final    final mode, the page only: fails on any TO-VERIFY mark or any
#                                                    command still on the cannot-run list (AC7: the page cannot be final)
#
# What this test does NOT prove (stated so nobody over-reads it): that a command works, or that every command was executed
# against a candidate image; that is pipeline's AC7 run (rule 79). "In the order a customer runs them" is checked only as
# "a file is verified by a cosign/gh command before a jq command reads it"; the full reading order is AC8's (the owner's cold
# reading and the second reader).
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
page="$root/docs/verify-release.md"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0; failn=0
ok()   { pass=$((pass+1)); echo "PASS $1"; }
bad()  { failn=$((failn+1)); echo "FAIL $1 -> $2"; }

# The judge. argv: <page> <mode: draft|final>. The cannot-run list is the page path minus .md plus .cannot-run.json.
# Exit 0 = the page passes; exit 1 = it fails, one line per problem on stdout, each starting with the AC it breaks.
cat > "$work/judge.py" <<'PY'
import json, os, re, shlex, sys
page, mode = sys.argv[1], sys.argv[2]
errs = []
def err(ac, m): errs.append("%s: %s" % (ac, m))
if not os.path.isfile(page):
    print("AC1: the page %s does not exist" % page); sys.exit(1)
text = open(page, encoding="utf-8").read()
lines = text.replace("\r", "").split("\n")

PLACEHOLDERS = {"IMAGE_REF", "TAG", "IDENTITY"}
FORMS2 = ("cosign verify", "cosign verify-attestation", "cosign verify-blob", "cosign verify-blob-attestation")
FORMS3 = ("gh attestation verify",)
# Build-chain tool names that may not appear on the page (AC6). "witness" is allowed on ONE prose line, the pointer.
CHAIN_TOOLS = ["melange", "apko", "wolfi", "bubblewrap", "bwrap", "docker", "podman", "buildah", "buildkit", "buildx",
               "kaniko", "crane", "oras", "skopeo", "syft", "grype", "trivy", "goreleaser", "ko", "in-toto",
               "slsa-verifier", "rekor-cli"]
# Wording that claims the commands were checked before release (judged only while the cannot-run list is not empty).
CLAIM_PHRASES = [r"\bevery command\b", r"\ball (?:of )?(?:the |these |our )?commands\b", r"\btested\b",
                 r"(?<!not )\b(?:verified|checked|run|executed|tested) (?:before|ahead of|prior to) (?:the |a |each |every )?release\b"]

# --- AC1: size ---
words = len(text.split())
if words > 500: err("AC1", "the page has %d words; at most 500 (prose and code counted)" % words)

# --- fences and commands (the AC7 run's own reading) ---
first_fence = next((i for i, l in enumerate(lines) if l.strip().startswith("```")), len(lines))
cmds = []      # (command, first line index, block opening index)
state = None; pending = None; pstart = None; bopen = None
for i, l in enumerate(lines):
    s = l.strip()
    if state is None:
        if s == "```sh": state = "sh"; bopen = i
        elif s.startswith("```"):
            state = "other"
            if s[3:].strip() in ("bash", "shell", "console", "zsh", "sh "): err("AC2", "line %d: a shell block not fenced as ```sh: %s" % (i+1, s))
        elif re.match(r"^(\$ +)?(cosign|gh|jq)\s", s) or re.match(r"^ {4,}(\$ +)?(cosign|gh|jq)\s", l):
            err("AC2", "line %d: a command outside a ```sh fence: %s" % (i+1, s))
        continue
    if s == "```":
        if pending is not None: err("AC2", "line %d: a command ends in a line continuation" % (i+1)); pending = None
        state = None; continue
    if state == "other":
        if re.match(r"^(\$ +)?(cosign|gh|jq)\s", s): err("AC2", "line %d: a command in a block not fenced as ```sh: %s" % (i+1, s))
        continue
    if pending is not None:
        s, pending = pending + " " + s, None
    elif not s or s.startswith("#"):
        continue
    else:
        pstart = i
    if s.endswith("\\"):
        pending = s[:-1].rstrip(); continue
    cmds.append((s, pstart, bopen))
if state is not None: err("AC2", "the page ends inside a fenced block")
if not cmds: err("AC1", "the page has no command (a vacuous page is not a guide)")
if len(cmds) > 10: err("AC1", "the page has %d commands; at most 10" % len(cmds))

# --- AC2: placeholders defined once, at the top; no other placeholder anywhere ---
DEF = re.compile(r"^\s*[-*]\s+`?<([A-Z][A-Z0-9_]*)>`?\s*:")
defs = {}
for i, l in enumerate(lines):
    m = DEF.match(l)
    if m:
        if i > first_fence: err("AC2", "line %d: the placeholder <%s> is defined after the first command block" % (i+1, m.group(1)))
        defs[m.group(1)] = defs.get(m.group(1), 0) + 1
for p in sorted(PLACEHOLDERS):
    if defs.get(p, 0) != 1: err("AC2", "the placeholder <%s> is defined %d times at the top (exactly once)" % (p, defs.get(p, 0)))
for u in sorted(set(re.findall(r"<([A-Z][A-Z0-9_]*)>", text)) - PLACEHOLDERS):
    err("AC2", "the placeholder <%s> is not one of <IMAGE_REF>, <TAG>, <IDENTITY>" % u)

# --- AC2 (unattended) + AC3 (only cosign, gh, jq): a pipeline of the verify forms and jq, no other shell syntax ---
def segments(c):
    if "`" in c: return None, "a backquote"
    q = None
    for ch in c:
        if q == "'": q = None if ch == "'" else q
        elif ch == "$": return None, "a $ expansion outside single quotes"
        elif q == '"': q = None if ch == '"' else q
        elif ch in "'\"": q = ch
    for bad_ in ("$(", "${"):
        if bad_ in c: return None, "a command or variable substitution"
    lx = shlex.shlex(re.sub(r"<([A-Z][A-Z0-9_]*)>", "PLACEHOLDER", c), posix=True, punctuation_chars=True)
    lx.whitespace_split = True
    try: toks = list(lx)
    except ValueError as e: return None, "unparseable: %s" % e
    segs = [[]]
    for t in toks:
        if t == "|": segs.append([])
        elif t and all(ch in "();<>|&" for ch in t): return None, "shell syntax other than a pipe: %s" % t
        else: segs[-1].append(t)
    if any(not s for s in segs): return None, "an empty pipe segment"
    return segs, ""
def form(seg):
    if seg[0] == "jq": return "jq"
    if " ".join(seg[:2]) in FORMS2: return " ".join(seg[:2])
    if " ".join(seg[:3]) in FORMS3: return " ".join(seg[:3])
    return None
parsed = []
for c, ln, bo in cmds:
    segs, why = segments(c)
    if segs is None:
        err("AC3", "line %d: `%s` is not a plain pipeline (%s)" % (ln+1, c, why)); continue
    okc = True
    for s in segs:
        if form(s) is None:
            err("AC3", "line %d: `%s` is not cosign verify[-attestation|-blob|-blob-attestation], gh attestation verify or jq" % (ln+1, " ".join(s[:3]))); okc = False
        for t in s:
            if t in ("--web", "-w", "--interactive", "--editor", "--pager", "--paginate"):
                err("AC2", "line %d: `%s` asks for a browser, prompt, editor or pager" % (ln+1, t)); okc = False
    parsed.append((c, ln, bo, segs if okc else None))

# --- AC2 (customer order): a file a jq command reads was verified by an earlier cosign/gh command naming it ---
seen = set()
for c, ln, bo, segs in parsed:
    if not segs: continue
    for s in segs:
        f = form(s)
        if f != "jq":
            seen.update(t for t in s[1:] if not t.startswith("-"))
            seen.update(t.split("=", 1)[1] for t in s if t.startswith("--") and "=" in t)
        else:
            files = [t for t in s[1:] if not t.startswith("-") and re.match(r"^[A-Za-z0-9._/-]+\.json$", t)]
            for fn in files:
                if fn not in seen: err("AC2", "line %d: jq reads %s before any cosign/gh command verifies it (customer order)" % (ln+1, fn))

# --- AC4: one command at least for each of signatures, digests, provenance, SBOM, inputs ---
def has(pred): return any(segs and pred(c, segs) for c, ln, bo, segs in parsed)
checks = {
  "signatures": lambda c, segs: any(form(s) == "cosign verify" for s in segs),
  "digests":    lambda c, segs: any(form(s) == "jq" and re.search(r"digest|sha256", " ".join(s)) for s in segs),
  "provenance": lambda c, segs: any(form(s) in ("cosign verify-attestation", "cosign verify-blob-attestation", "gh attestation verify") for s in segs) and "https://slsa.dev/provenance/v1" in c,
  "the SBOM":   lambda c, segs: any(form(s) and form(s) != "jq" for s in segs) and re.search(r"sbom", c, re.I),
  "the inputs": lambda c, segs: any(form(s) and form(s) != "jq" for s in segs) and re.search(r"inputs", c, re.I),
}
for what, pred in checks.items():
    if not has(pred): err("AC4", "no command verifies %s" % what)

# --- AC5: both images, production and -fips; no -debug ---
if not re.search(r"\bproduction\b", text, re.I): err("AC5", "the production image is not named")
if not re.search(r"-fips\b|\bfips\b", text, re.I): err("AC5", "the -fips image is not named")
if not any(re.search(r"fips", c, re.I) for c, ln, bo, segs in parsed): err("AC5", "no command covers the -fips image")
if re.search(r"debug", text, re.I): err("AC5", "the page names a debug image")

# --- AC6: Witness only as one prose pointer, outside the commands; no other build-chain tool name ---
infence = False; wl = []
for i, l in enumerate(lines):
    s = l.strip()
    if s.startswith("```"):
        if not infence: infence = True
        elif s == "```": infence = False
    if re.search(r"witness", l, re.I):
        if infence or s.startswith("```"): err("AC6", "line %d: Witness inside a code block (it is outside the ten commands)" % (i+1))
        wl.append(i+1)
if len(wl) > 1: err("AC6", "Witness appears on %d lines %s; it is one pointer" % (len(wl), wl))
for t in CHAIN_TOOLS:
    for i, l in enumerate(lines):
        if re.search(r"(?<![A-Za-z0-9_-])%s(?![A-Za-z0-9_])" % re.escape(t), l, re.I):
            err("AC6", "line %d: the build-chain tool name `%s`" % (i+1, t))

# --- AC7: the cannot-run list, its marks, no claim past it, and the final gate ---
lp = page[:-3] + ".cannot-run.json" if page.endswith(".md") else page + ".cannot-run.json"
rows = []
if not os.path.isfile(lp): err("AC7", "the cannot-run list %s does not exist" % os.path.basename(lp))
else:
    try: rows = json.load(open(lp))
    except ValueError as e: err("AC7", "the cannot-run list is not JSON: %s" % e); rows = []
    if not isinstance(rows, list): err("AC7", "the cannot-run list is not a list"); rows = []
listed = {}
for r in rows:
    if not (isinstance(r, dict) and set(r) == {"command", "reason"} and all(isinstance(r[k], str) and r[k].strip() for k in r)):
        err("AC7", "a cannot-run entry is not exactly {command, reason}, both non-empty: %r" % (r,)); continue
    if r["command"] in listed: err("AC7", "the cannot-run list names `%s` twice" % r["command"])
    listed[r["command"]] = r["reason"]
allc = [c for c, ln, bo, segs in parsed]
for c in listed:
    if c not in allc: err("AC7", "the cannot-run entry `%s` is not a command of the page (a stale entry)" % c)
def needs_registry(segs):
    return any(form(s) in ("cosign verify", "cosign verify-attestation") or (form(s) == "gh attestation verify" and any(t.startswith("oci://") for t in s)) for s in segs)
for c, ln, bo, segs in parsed:
    if not segs: continue
    if needs_registry(segs) and c not in listed:
        err("AC7", "line %d: `%s` needs a registry image and cannot run on a candidate, but the cannot-run list does not name it" % (ln+1, c))
    if c in listed and not needs_registry(segs):
        err("AC7", "line %d: `%s` is on the cannot-run list but needs no registry image (a runnable command is run, never excused)" % (ln+1, c))
    if c in listed:
        j = ln - 1
        while j >= 0 and not lines[j].strip(): j -= 1
        if j == bo:
            j -= 1
            while j >= 0 and not lines[j].strip(): j -= 1
        if j < 0 or "not run before release" not in lines[j].lower():
            err("AC7", "line %d: `%s` is on the cannot-run list but the line above it does not say 'Not run before release'" % (ln+1, c))
if listed:
    for i, l in enumerate(lines):
        for ph in CLAIM_PHRASES:
            if re.search(ph, l, re.I):
                err("AC7", "line %d: wording that claims the commands were checked before release (%s) while %d command(s) are on the cannot-run list" % (i+1, ph, len(listed)))
marks = [i+1 for i, l in enumerate(lines) if "TO-VERIFY" in l]
if mode == "final":
    if marks: err("AC7", "final mode: %d TO-VERIFY mark(s) remain (lines %s); the page cannot be final" % (len(marks), marks))
    if listed: err("AC7", "final mode: %d command(s) are on the cannot-run list and have not been executed against a candidate" % len(listed))
print("\n".join(errs) if errs else "OK %d words, %d commands, %d TO-VERIFY marks, %d cannot-run" % (words, len(cmds), len(marks), len(listed)))
sys.exit(1 if errs else 0)
PY

judge() { python3 -I "$work/judge.py" "$@" </dev/null; }

if [ "${1:-}" = "--final" ]; then
  out=$(judge "$page" final); rc=$?
  echo "$out"
  [ "$rc" -eq 0 ] && ok "the page passes in final mode" || bad "the page is not final" "see above"
  echo "verify-release-guide: $pass passed, $failn failed"
  [ "$failn" -eq 0 ]; exit
fi

# 1. The real page, draft mode.
out=$(judge "$page" draft); rc=$?
if [ "$rc" -eq 0 ]; then ok "docs/verify-release.md passes in draft mode ($out)"; else bad "docs/verify-release.md in draft mode" "$out"; fi

# 2. A good fixture page (final-ready: no TO-VERIFY, one registry command on the list and marked), then one mutant per check.
mkdir -p "$work/f"
cat > "$work/f/good.md" <<'MD'
# Verify a release

The production image and the -fips image are both covered.

- `<IMAGE_REF>`: the production image, repository@digest.
- `<TAG>`: the release tag.
- `<IDENTITY>`: the signing identity.

Not run before release: it needs the image in a registry.

```sh
cosign verify <IMAGE_REF> --certificate-identity <IDENTITY> --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

```sh
# Not run before release: it needs the image in a registry.
cosign verify example.com/cache:<TAG>-fips --certificate-identity <IDENTITY> --certificate-oidc-issuer https://token.actions.githubusercontent.com
cosign verify-blob-attestation --bundle provenance.json --type https://slsa.dev/provenance/v1 \
  --certificate-identity <IDENTITY> --certificate-oidc-issuer https://token.actions.githubusercontent.com
jq -e '.subject[].digest.sha256' provenance.json
cosign verify-blob --bundle sbom.bundle --certificate-identity <IDENTITY> --certificate-oidc-issuer https://token.actions.githubusercontent.com sbom.json
cosign verify-blob --bundle inputs.bundle --certificate-identity <IDENTITY> --certificate-oidc-issuer https://token.actions.githubusercontent.com inputs.json
```

Witness records are extra evidence, outside these steps.
MD
cat > "$work/f/good.cannot-run.json" <<'JS'
[{"command": "cosign verify <IMAGE_REF> --certificate-identity <IDENTITY> --certificate-oidc-issuer https://token.actions.githubusercontent.com", "reason": "needs a registry image"},
 {"command": "cosign verify example.com/cache:<TAG>-fips --certificate-identity <IDENTITY> --certificate-oidc-issuer https://token.actions.githubusercontent.com", "reason": "needs a registry image"}]
JS
out=$(judge "$work/f/good.md" draft); rc=$?
[ "$rc" -eq 0 ] && ok "the good fixture passes in draft mode" || bad "the good fixture fails in draft mode" "$out"
out=$(judge "$work/f/good.md" final); rc=$?
case "$out" in *"final mode: 2 command(s) are on the cannot-run list"*) ok "final mode refuses a page while commands remain on the cannot-run list";; *) bad "final mode with a non-empty cannot-run list" "$out";; esac
# the same page with an empty list and no registry commands is final-ready
grep -v -e '^cosign verify <IMAGE_REF>' -e '^cosign verify example.com' -e 'Not run before release' "$work/f/good.md" \
  | sed 's/^jq -e/cosign verify-blob --bundle fips.bundle fips.json | jq -e/' > "$work/f/final.md"
echo '[]' > "$work/f/final.cannot-run.json"
out=$(judge "$work/f/final.md" final); rc=$?
case "$out" in *"no command verifies signatures"*) ok "the final-ready fixture (no registry command) still needs a signature command (AC4 holds in final mode)";; *) bad "final-ready fixture" "$out";; esac

# mutant <name> <expected substring> <python expression over s (the good page text)> [list-json]
mutant() {
  local name="$1" want="$2" expr="$3" list="${4:-}" out rc
  python3 -I -c 'import sys; s=open(sys.argv[1]).read(); open(sys.argv[2],"w").write(eval(sys.argv[3]))' \
    "$work/f/good.md" "$work/f/m.md" "$expr" </dev/null
  if cmp -s "$work/f/good.md" "$work/f/m.md"; then bad "mutant did not apply: $name" "$expr"; return; fi
  if [ -n "$list" ]; then printf '%s\n' "$list" > "$work/f/m.cannot-run.json"; else cp "$work/f/good.cannot-run.json" "$work/f/m.cannot-run.json"; fi
  out=$(judge "$work/f/m.md" draft); rc=$?
  if [ "$rc" -ne 0 ] && [[ "$out" == *"$want"* ]]; then ok "kills mutant: $name"; else bad "MISSED mutant: $name (rc=$rc)" "$out"; fi
}
# AC1
mutant "over 500 words"                 "AC1: the page has"            's + "\nword" * 500'
mutant "eleven commands"                "at most 10"                   's.replace("```\n\nWitness", "jq . provenance.json\n" * 6 + "```\n\nWitness")'
mutant "no command at all"              "has no command"               '"\n".join(l for l in s.split("\n") if not l.startswith(("cosign","jq","  --")))'
# AC2
mutant "a command outside a sh fence"   "outside a \`\`\`sh fence"     's.replace("Witness records", "jq . provenance.json\n\nWitness records")'
mutant "a shell block fenced as bash"   "not fenced as \`\`\`sh"       's.replace("```sh\n# Not", "```bash\n# Not")'
mutant "a placeholder defined twice"    "<TAG> is defined 2 times"     's.replace("- `<IDENTITY>`", "- `<TAG>`: again.\n- `<IDENTITY>`")'
mutant "a placeholder not defined"      "<IDENTITY> is defined 0 times" 's.replace("- `<IDENTITY>`: the signing identity.\n", "")'
mutant "a placeholder defined late"     "defined after the first command block" 's.replace("- `<IDENTITY>`: the signing identity.\n", "") + "\n- `<IDENTITY>`: late.\n"'
mutant "another placeholder"            "<DIGEST> is not one of"       's.replace("jq -e", "jq -e --arg d <DIGEST>")'
mutant "a \$ variable"                  "a \$ expansion outside single quotes" 's.replace("jq -e", "jq -e --arg t \"$TAG\"")'
mutant "a command substitution"         "a \$ expansion outside single quotes" 's.replace("jq -e", "jq -e --arg t $(date)")'
mutant "a backquote"                    "a backquote"                  's.replace("jq -e", "jq -e --arg t `date`")'
mutant "a ; list"                       "shell syntax other than a pipe: ;" 's.replace("jq -e", "jq -e . provenance.json ; jq -e")'
mutant "a redirect"                     "shell syntax other than a pipe: >" 's.replace("provenance.json\ncosign verify-blob --bundle sbom", "provenance.json > out.json\ncosign verify-blob --bundle sbom")'
mutant "a background &"                 "shell syntax other than a pipe: &" 's.replace("provenance.json\ncosign verify-blob --bundle sbom", "provenance.json &\ncosign verify-blob --bundle sbom")'
mutant "a pager flag"                   "asks for a browser, prompt, editor or pager" 's.replace("jq -e", "cosign verify-blob --bundle x.bundle --web x.json | jq -e")'
mutant "jq before the verify of its file" "before any cosign/gh command verifies it" 's.replace("jq -e \x27.subject[].digest.sha256\x27 provenance.json\n", "").replace("```sh\n# Not", "```sh\njq -e \x27.subject[].digest.sha256\x27 provenance.json\n# Not")'
mutant "a trailing continuation"        "ends in a line continuation"  's.replace("inputs.json\n```", "inputs.json \\\n```")'
# AC3
mutant "curl"                           "is not cosign verify"         's.replace("jq -e", "curl -s x | jq -e")'
mutant "gh release download"            "is not cosign verify"         's.replace("jq -e", "gh release download <TAG> | jq -e")'
mutant "cosign sign"                    "is not cosign verify"         's.replace("cosign verify-blob --bundle sbom", "cosign sign-blob --bundle sbom")'
mutant "export VAR"                     "is not cosign verify"         's.replace("```sh\n# Not", "```sh\nexport A=1\n# Not")'
mutant "base64 in a pipe"               "is not cosign verify"         's.replace("jq -e", "jq -r .payload provenance.json | base64 -d | jq -e")'
# AC4
mutant "no signature command"           "no command verifies signatures"  's.replace("cosign verify <IMAGE_REF>", "cosign verify-blob <IMAGE_REF>").replace("cosign verify example", "cosign verify-blob example")' '[]'
mutant "no digest check"                "no command verifies digests"  's.replace("\x27.subject[].digest.sha256\x27", ".subject")'
mutant "no provenance type"             "no command verifies provenance" 's.replace("https://slsa.dev/provenance/v1", "https://example.com/other/v1")'
mutant "no SBOM command"                "no command verifies the SBOM" 's.replace("sbom", "other")'
mutant "no inputs command"              "no command verifies the inputs" 's.replace("inputs", "other")'
# AC5
mutant "production not named"           "the production image is not named" 's.replace("production", "main")'
mutant "fips not named"                 "the -fips image is not named" 's.replace("-fips image", "second image").replace(":<TAG>-fips", ":<TAG>-x")' '[{"command": "cosign verify <IMAGE_REF> --certificate-identity <IDENTITY> --certificate-oidc-issuer https://token.actions.githubusercontent.com", "reason": "r"}, {"command": "cosign verify example.com/cache:<TAG>-x --certificate-identity <IDENTITY> --certificate-oidc-issuer https://token.actions.githubusercontent.com", "reason": "r"}]'
mutant "no command for fips"            "no command covers the -fips image" 's.replace(":<TAG>-fips", ":<TAG>")' '[{"command": "cosign verify <IMAGE_REF> --certificate-identity <IDENTITY> --certificate-oidc-issuer https://token.actions.githubusercontent.com", "reason": "r"}, {"command": "cosign verify example.com/cache:<TAG> --certificate-identity <IDENTITY> --certificate-oidc-issuer https://token.actions.githubusercontent.com", "reason": "r"}]'
mutant "a debug image"                  "names a debug image"          's.replace("are both covered.", "are both covered; the -debug image is not.")'
# AC6
mutant "Witness in a command block"     "Witness inside a code block"  's.replace("```sh\n# Not", "```sh\n# witness verify is extra\n# Not")'
mutant "Witness on two lines"           "Witness appears on 2 lines"   's + "\nAlso see Witness.\n"'
for t in melange apko wolfi bubblewrap docker crane syft in-toto; do
  mutant "the tool name $t"             "the build-chain tool name \`$t\`" "s.replace('are both covered.', 'are both covered by $t.')"
done
# AC7
python3 -I -c 'import sys; s=open(sys.argv[1]).read(); open(sys.argv[2],"w").write(s + "\nTO-VERIFY: the asset name.\n")' "$work/f/good.md" "$work/f/tv.md" </dev/null
cp "$work/f/good.cannot-run.json" "$work/f/tv.cannot-run.json"
out=$(judge "$work/f/tv.md" draft); rc=$?; [ "$rc" -eq 0 ] && ok "draft mode allows a TO-VERIFY mark" || bad "draft mode refused a TO-VERIFY mark" "$out"
out=$(judge "$work/f/tv.md" final); rc=$?; case "$out" in *"TO-VERIFY mark(s) remain"*) ok "kills mutant: --final with a TO-VERIFY mark";; *) bad "MISSED mutant: --final with a TO-VERIFY mark" "$out";; esac
mutant "a registry command not listed"  "the cannot-run list does not name it" 's.replace("<IMAGE_REF> --cert", "<IMAGE_REF>  --cert")'
mutant "a stale cannot-run entry"       "a stale entry"                's.replace("--certificate-identity <IDENTITY> --certificate-oidc-issuer https://token.actions.githubusercontent.com\n```\n\n```sh\n# Not", "--certificate-oidc-issuer https://token.actions.githubusercontent.com --certificate-identity <IDENTITY>\n```\n\n```sh\n# Not")'
mutant "a runnable command on the list" "needs no registry image"      's + " "' '[{"command": "cosign verify <IMAGE_REF> --certificate-identity <IDENTITY> --certificate-oidc-issuer https://token.actions.githubusercontent.com", "reason": "r"}, {"command": "cosign verify example.com/cache:<TAG>-fips --certificate-identity <IDENTITY> --certificate-oidc-issuer https://token.actions.githubusercontent.com", "reason": "r"}, {"command": "jq -e '"'"'.subject[].digest.sha256'"'"' provenance.json", "reason": "r"}]'
mutant "a list entry without a reason"  "not exactly {command, reason}" 's + " "' '[{"command": "cosign verify <IMAGE_REF> --certificate-identity <IDENTITY> --certificate-oidc-issuer https://token.actions.githubusercontent.com", "reason": ""}]'
mutant "a list that is not JSON"        "not JSON"                     's + " "' '[{'
mutant "a listed command without the mark (prose)" "does not say 'Not run before release'" 's.replace("Not run before release: it needs the image in a registry.\n\n```sh\ncosign", "Run this.\n\n```sh\ncosign")'
mutant "a listed command without the mark (comment)" "does not say 'Not run before release'" 's.replace("# Not run before release: it needs the image in a registry.\ncosign", "# check the fips image\ncosign")'
mutant "a claim: every command"         "wording that claims"          's.replace("are both covered.", "are both covered. Every command was checked.")'
mutant "a claim: tested"                "wording that claims"          's.replace("are both covered.", "are both covered and tested.")'
mutant "a claim: verified before release" "wording that claims"        's.replace("are both covered.", "are both covered, verified before release.")'
# the claim check applies only while the list is non-empty
python3 -I -c 'import sys; s=open(sys.argv[1]).read(); open(sys.argv[2],"w").write(s.replace("are both covered.", "are both covered and tested."))' "$work/f/final.md" "$work/f/claim.md" </dev/null
echo '[]' > "$work/f/claim.cannot-run.json"
out=$(judge "$work/f/claim.md" draft); case "$out" in *"wording that claims"*) bad "the claim check fired with an empty list" "$out";; *) ok "the claim check is silent while the cannot-run list is empty";; esac
# the missing page and the missing list
out=$(judge "$work/f/none.md" draft); rc=$?; [ "$rc" -ne 0 ] && [[ "$out" == *"does not exist"* ]] && ok "kills mutant: the page is missing" || bad "MISSED mutant: the page is missing" "$out"
cp "$work/f/good.md" "$work/f/nolist.md"; out=$(judge "$work/f/nolist.md" draft); rc=$?
[ "$rc" -ne 0 ] && [[ "$out" == *"cannot-run list nolist.cannot-run.json does not exist"* ]] && ok "kills mutant: the cannot-run list is missing" || bad "MISSED mutant: the cannot-run list is missing" "$out"

echo "verify-release-guide: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
