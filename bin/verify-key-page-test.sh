#!/usr/bin/env bash
# proves: REQ-CHAIN-008-AC7
# The customer page docs/verify-key.md, judged as a page: two separate commands in a ```sh block, the lines that tell the reader
# when to run the second, why the first skips the log, the validity rule, the revocation check, where each file comes from,
# no TO-VERIFY mark on where the files are published, and no shop word in its added lines (bin/check-customer-words.py).
# Each mutant removes or reverses an instruction while keeping its field names, so only the instruction is tested.
# What this does not prove: that either command works against a real release.
set -uo pipefail
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1   # a user's git configuration cannot change the diff
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
page="$root/docs/verify-key.md"
words="$root/bin/check-customer-words.py"
work=$(mktemp -d -t cache5-vkp.XXXXXX); trap 'rm -rf "$work"' EXIT
pass=0; failn=0
ok()  { pass=$((pass+1)); echo "PASS $1"; }
bad() { failn=$((failn+1)); echo "FAIL $1 -> $2"; }

cat > "$work/judge.py" <<'PY'
import re, sys
page = sys.argv[1]
errs = []
def err(m): errs.append(m)
try:
    text = open(page, encoding="utf-8").read()
except OSError:
    print("the page %s does not exist" % page); sys.exit(1)
lines = text.replace("\r", "").split("\n")

WANT = ["cosign verify-blob --key release-key-root.pub --signature release-key-manifest.sig --insecure-ignore-tlog release-key-manifest.json",
        "jq -r .public_key release-key-manifest.json > release.rsa.pub"]
# every non-comment line of a fenced block (a trailing backslash joins the next line); prose is every line outside a fence
cmds, prose, fence, pend = [], [], None, None
for l in lines:
    s = l.strip()
    if fence is None:
        if s.startswith("```"):
            fence = s[3:].strip()
        else:
            prose.append(l)
            if re.match(r"^(\$ +)?(cosign|jq)\s", s): err("a command outside a fence: " + s)
        continue
    if s == "```":
        fence = None; continue
    if fence != "sh": err("a fenced line in a block not fenced as ```sh: " + s); continue
    if pend is not None: s, pend = pend + " " + s, None
    elif not s or s.startswith("#"): continue
    if s.endswith("\\"): pend = s[:-1].rstrip(); continue
    cmds.append(re.sub(r"\s+", " ", s))
if fence is not None: err("the page ends inside a fenced block")
if cmds != WANT: err("the commands are %r; exactly %r, in this order" % (cmds, WANT))

body = "\n".join(prose)
flat = re.sub(r"[`*]", "", re.sub(r"\s+", " ", body))
paras = [re.sub(r"[`*]", "", re.sub(r"\s+", " ", p)) for p in re.split(r"\n\s*\n", body)]
def need(ok, m):
    if not ok: err(m)
need(".github/policy/release-key-root.pub" in flat, "setup text does not give .github/policy/release-key-root.pub")
need(re.search(r"repository.{0,120}release tag|release tag.{0,120}repository", flat, re.I), "setup text does not say the root key comes from the repository at the release tag")
need("release assets" in flat.lower(), "setup text does not name the release assets")
need("release-key-manifest.json" in flat and "release-key-manifest.sig" in flat, "setup text does not name the manifest and its signature")
sents = [x.strip() for x in re.split(r"(?<=[.;])\s+", flat) if x.strip()]
def sentence(*pats):
    return any(all(re.search(p, x, re.I) for p in pats) for x in sents)
need(sentence(r"\bsecond\b", r"only if", r"\bfirst\b", r"Verified OK"), "no plain line says to run the second command only if the first prints Verified OK")
need(sentence(r"--insecure-ignore-tlog", r"offline", r"no (transparency )?log entry|no entry"), "no sentence says why the first command has --insecure-ignore-tlog (root key offline, no log entry)")
need(sentence(r"refused", r"at or after valid_to", r"valid_to is optional", r"before valid_from"), "no sentence gives the validity rule: refused at or after valid_to (optional) or before valid_from")
need(any("publish date" in x and "valid_to" in x and "refused" not in x for x in sents), "no sentence tells the reader to compare the publish date with valid_to without giving it as the rule")
need(sentence(r"newest manifest", r"signature", r"release assets", r"key_id"), "no sentence says the newest manifest and its signature for the same key_id are among the release assets")
need(sentence(r"verif", r"same way"), "no sentence says to verify the newest manifest the same way")
need(sentence(r"\bstop\b", r"revoked_at", r"at or before the current time"), "no sentence says to stop if revoked_at is at or before the current time")
for x in sents:
    if re.search(r"publish", x) and "valid_to" in x and "refused" in x:
        err("a sentence gives the publish date comparison as the rule: " + x)
    if re.search(r"valid_to|valid_from|revoked_at", x) and re.search(r"accept|allowed|still valid|carry on|continue|ignore", x, re.I):
        err("a sentence accepts a key the rules refuse: " + x)
for i, l in enumerate(lines):
    if "TO-VERIFY" in l and re.search(r"manifest|root key|release-key-root|publish|release assets|repository", l, re.I):
        err("line %d: a TO-VERIFY mark about where the manifest or root key are published" % (i+1))
print("\n".join(errs) if errs else "OK")
sys.exit(1 if errs else 0)
PY

# The checker reads an added-lines diff, so the page is committed as a new file on an empty base.
cat > "$work/allow.txt" <<'TXT'
# header
TXT
words_ok() {   # <page>; prints the checker's output, returns its exit code
  local r="$work/r"; rm -rf "$r"; mkdir -p "$r/docs"
  git -C "$r" init -q . && git -C "$r" commit -q --allow-empty -m base || return 2
  [ -f "$1" ] || return 2
  cp "$1" "$r/docs/verify-key.md" && git -C "$r" add -A && git -C "$r" commit -q -m pr || return 2
  git -C "$r" diff -U0 --no-renames --no-color HEAD^1 HEAD | CUSTOMER_WORDS_ALLOW="$work/allow.txt" python3 -I "$words" 2>&1
}
judge() {   # <page>: the page judge, then the customer-words check; one line per problem, rc 0 only if both pass
  local out rc w wrc
  out=$(python3 -I "$work/judge.py" "$1" </dev/null); rc=$?
  w=$(words_ok "$1"); wrc=$?
  [ "$wrc" -eq 0 ] || { out="$out"$'\n'"check-customer-words.py rc=$wrc: $w"; rc=1; }
  printf '%s\n' "$out"; return "$rc"
}

mkdir -p "$work/f"
cat > "$work/f/good.md" <<'MD'
# Verify the release key

Every release key is signed by one root key. Check the key before you trust a signature made with it.

1. Fetch release-key-root.pub from the repository at the release tag: `.github/policy/release-key-root.pub`.
2. Download release-key-manifest.json and release-key-manifest.sig from the release assets.

```sh
cosign verify-blob --key release-key-root.pub --signature release-key-manifest.sig --insecure-ignore-tlog release-key-manifest.json
jq -r .public_key release-key-manifest.json > release.rsa.pub
```

Run the second command only if the first prints Verified OK.

The first command has `--insecure-ignore-tlog` because the root key is kept offline, so its signature has no log entry.

A key is refused at or after `valid_to` (`valid_to` is optional) or before `valid_from`. Compare the release's publish date with `valid_to` in the manifest.

The newest manifest and its signature for the same `key_id` are among the release assets. Verify them the same way as the first. Stop if the manifest has a `revoked_at` that is at or before the current time.
MD

# mutant <name> <expected substring> <python expression over s, the good page>
mutant() {
  local name="$1" want="$2" out rc
  python3 -I -c 'import sys; s=open(sys.argv[1]).read(); open(sys.argv[2],"w").write(eval(sys.argv[3]))' "$work/f/good.md" "$work/f/m.md" "$3" </dev/null
  if cmp -s "$work/f/good.md" "$work/f/m.md"; then bad "mutant did not apply: $name" "$3"; return; fi
  out=$(judge "$work/f/m.md"); rc=$?
  if [ "$rc" -ne 0 ] && [[ "$out" == *"$want"* ]]; then ok "kills mutant: $name"; else bad "MISSED mutant: $name (rc=$rc)" "$out"; fi
}

out=$(judge "$work/f/good.md"); rc=$?
[ "$rc" -eq 0 ] && ok "the good fixture passes" || bad "the good fixture fails" "$out"

C1='cosign verify-blob --key release-key-root.pub --signature release-key-manifest.sig --insecure-ignore-tlog release-key-manifest.json'
C2='jq -r .public_key release-key-manifest.json > release.rsa.pub'
mutant "first command without --insecure-ignore-tlog" "the commands are"  's.replace(" --insecure-ignore-tlog release-key-manifest.json", " release-key-manifest.json")'
mutant "first command dropped"           "the commands are"  's.replace("'"$C1"'\n", "")'
mutant "second command dropped"          "the commands are"  's.replace("'"$C2"'\n", "")'
mutant "commands in the other order"     "in this order"     's.replace("'"$C1"'\n'"$C2"'", "'"$C2"'\n'"$C1"'")'
mutant "commands joined with &&"         "the commands are"  's.replace("'"$C1"'\n", "'"$C1"' && ")'
mutant "commands joined with ;"          "the commands are"  's.replace("'"$C1"'\n", "'"$C1"' ; ")'
mutant "a third command"                 "the commands are"  's.replace("> release.rsa.pub\n", "> release.rsa.pub\ncat release.rsa.pub\n")'
mutant "first command with another key"  "the commands are"  's.replace("--key release-key-root.pub", "--key release.rsa.pub")'
mutant "second command with another file" "the commands are" 's.replace("> release.rsa.pub", "> key.pub")'
mutant "commands in a bash fence"        "not fenced as"     's.replace("```sh", "```bash")'
mutant "a command outside a fence"       "outside a fence"   's.replace("Run the second", "jq . release-key-manifest.json\n\nRun the second")'
# the Verified OK line
mutant "no line on when to run the second command"  "only if the first prints Verified OK" 's.replace("Run the second command only if the first prints Verified OK.\n\n", "")'
mutant "Verified OK stated, no instruction"         "only if the first prints Verified OK" 's.replace("Run the second command only if the first prints Verified OK.", "The first command prints Verified OK.")'
mutant "second command run whatever the first says" "only if the first prints Verified OK" 's.replace("only if the first prints Verified OK", "whether or not the first prints Verified OK")'
# the why sentence
mutant "no sentence on why the log is skipped"      "why the first command has"  's.replace("The first command has `--insecure-ignore-tlog` because the root key is kept offline, so its signature has no log entry.\n\n", "")'
mutant "the flag named, no reason given"            "why the first command has"  's.replace("because the root key is kept offline, so its signature has no log entry", "in this page")'
# the validity rule
mutant "no validity rule, fields named"             "validity rule"  's.replace("A key is refused at or after `valid_to` (`valid_to` is optional) or before `valid_from`.", "The manifest has `valid_to` and `valid_from`.")'
mutant "validity rule reversed: expired key accepted" "validity rule"  's.replace("A key is refused at or after", "A key is accepted at or after")'
mutant "validity rule reversed, refusal word kept"  "accepts a key"  's.replace("or before `valid_from`.", "or before `valid_from`, and an expired key is still valid.")'
mutant "validity rule: at dropped from the end"     "validity rule"  's.replace("at or after `valid_to`", "after `valid_to`")'
mutant "validity rule: valid_to not optional"       "validity rule"  's.replace(" (`valid_to` is optional)", "")'
mutant "validity rule: valid_from side dropped"     "validity rule"  's.replace(" or before `valid_from`", "")'
mutant "publish date given as the rule"             "as the rule"   's.replace("Compare the release", "A release published after `valid_to` is refused. Compare the release")'
mutant "publish date comparison dropped"            "publish date"   's.replace(" Compare the release'"'"'s publish date with `valid_to` in the manifest.", "")'
# the revocation check
mutant "no newest manifest sentence, key_id kept"   "newest manifest and its signature" 's.replace("The newest manifest and its signature for the same `key_id` are among the release assets.", "A key has a `key_id`.")'
mutant "newest manifest not among the release assets" "newest manifest and its signature" 's.replace("are among the release assets", "are on the website")'
mutant "newest manifest not verified the same way"  "the same way"  's.replace("Verify them the same way as the first. ", "")'
mutant "no stop instruction, revoked_at kept"       "stop if revoked_at"  's.replace("Stop if the manifest has a `revoked_at` that is at or before the current time.", "The manifest may have a `revoked_at`.")'
mutant "revocation reversed: revoked key accepted"  "stop if revoked_at"  's.replace("Stop if the manifest has", "Carry on even if the manifest has")'
mutant "revocation reversed, stop word kept"        "accepts a key"  's.replace("at or before the current time.", "at or before the current time, which is accepted. Stop if the page is wrong.")'
mutant "revocation boundary: after the current time" "stop if revoked_at"  's.replace("at or before the current time", "after the current time")'
# the setup text
mutant "root key path not given"         "release-key-root.pub"        's.replace(": `.github/policy/release-key-root.pub`", "")'
mutant "release tag not named"           "at the release tag"          's.replace("at the release tag", "at the latest commit")'
mutant "repository not named"            "at the release tag"          's.replace("from the repository at", "from the web at")'
mutant "release assets not named"        "name the release assets"     's.replace("from the release assets.\n", "from the release page.\n").replace("are among the release assets", "are on the release page")'
mutant "signature file not named"        "manifest and its signature"  's.replace("release-key-manifest.sig from", "its signature from")'
# no open mark on where the files are published
mutant "TO-VERIFY on the root key line"  "TO-VERIFY mark"  's.replace("release-key-root.pub`.\n", "release-key-root.pub`. TO-VERIFY: the path.\n")'
mutant "TO-VERIFY on the manifest line"  "TO-VERIFY mark"  's.replace("from the release assets.\n", "from the release assets. TO-VERIFY: the names.\n")'
mutant "a TO-VERIFY line on publishing"  "TO-VERIFY mark"  's + "\nTO-VERIFY: where the manifest is published.\n"'
python3 -I -c 'import sys; open(sys.argv[2],"w").write(open(sys.argv[1]).read() + "\nTO-VERIFY: the cosign version.\n")' "$work/f/good.md" "$work/f/other.md" </dev/null
out=$(judge "$work/f/other.md"); rc=$?
[ "$rc" -eq 0 ] && ok "a TO-VERIFY mark on an unrelated line is allowed" || bad "a TO-VERIFY mark on an unrelated line is refused" "$out"
mutant "a shop word in an added line"    "check-customer-words.py rc=1" 's + "\nAsk the owner.\n"'
out=$(judge "$work/f/none.md"); rc=$?
[ "$rc" -ne 0 ] && [[ "$out" == *"does not exist"* ]] && ok "kills mutant: the page is missing" || bad "MISSED mutant: the page is missing" "$out"

out=$(judge "$page"); rc=$?
[ "$rc" -eq 0 ] && ok "docs/verify-key.md passes" || bad "docs/verify-key.md" "$out"

echo "verify-key-page: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
