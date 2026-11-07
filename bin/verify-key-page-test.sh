#!/usr/bin/env bash
# proves: REQ-CHAIN-008-AC7
# The customer page docs/verify-key.md, judged as a page: its two commands (exactly these, in a ```sh block, in this order),
# the setup text that says where each file comes from and what to compare, no TO-VERIFY mark on where the files are published,
# and no shop word in its added lines (bin/check-customer-words.py, fed an added-lines diff as ci.yml feeds it).
# A fixture page passes, one mutant per requirement fails, then the real page is judged.
# What this does not prove: that either command works against a real release (the page has no cannot-run list of its own).
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

WANT = ["cosign verify-blob --key release-key-root.pub --signature release-key-manifest.sig release-key-manifest.json",
        "jq -r .public_key release-key-manifest.json > release.rsa.pub"]
# commands: every non-comment line of a fenced block (a trailing backslash joins the next line); prose is every line outside a fence
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
need(re.search(r"publish date.{0,100}valid_to|valid_to.{0,100}publish date", flat, re.I), "setup text does not say to compare the release's publish date with valid_to")
need(any("revoked" in p and "key_id" in p and "newest manifest" in p for p in paras), "setup text does not say to check the newest manifest for the same key_id because a revoked key is refused")
for i, l in enumerate(lines):
    if "TO-VERIFY" in l and re.search(r"manifest|root key|release-key-root|publish|release assets|repository", l, re.I):
        err("line %d: a TO-VERIFY mark about where the manifest or root key are published" % (i+1))
print("\n".join(errs) if errs else "OK")
sys.exit(1 if errs else 0)
PY

# The customer-words check on the page as an added-lines diff of a file added on an empty base.
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
cosign verify-blob --key release-key-root.pub --signature release-key-manifest.sig release-key-manifest.json
jq -r .public_key release-key-manifest.json > release.rsa.pub
```

Compare the release's publish date with valid_to in the manifest; a release published after valid_to is refused.

Look for a newer manifest for the same key_id: a revoked key is refused, so use the newest manifest.
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

# the two commands
mutant "first command dropped"           "the commands are"  's.replace("cosign verify-blob --key release-key-root.pub --signature release-key-manifest.sig release-key-manifest.json\n", "")'
mutant "second command dropped"          "the commands are"  's.replace("jq -r .public_key release-key-manifest.json > release.rsa.pub\n", "")'
mutant "commands in the other order"     "in this order"     's.replace("cosign verify-blob --key release-key-root.pub --signature release-key-manifest.sig release-key-manifest.json\njq -r .public_key release-key-manifest.json > release.rsa.pub", "jq -r .public_key release-key-manifest.json > release.rsa.pub\ncosign verify-blob --key release-key-root.pub --signature release-key-manifest.sig release-key-manifest.json")'
mutant "a third command"                 "the commands are"  's.replace("> release.rsa.pub\n", "> release.rsa.pub\ncat release.rsa.pub\n")'
mutant "first command with another key"  "the commands are"  's.replace("--key release-key-root.pub", "--key release.rsa.pub")'
mutant "second command with another file" "the commands are" 's.replace("> release.rsa.pub", "> key.pub")'
mutant "commands in a bash fence"        "not fenced as"     's.replace("```sh", "```bash")'
mutant "a command outside a fence"       "outside a fence"   's.replace("Compare the release", "jq . release-key-manifest.json\n\nCompare the release")'
# the setup text
mutant "root key path not given"         "release-key-root.pub"        's.replace(": `.github/policy/release-key-root.pub`", "")'
mutant "release tag not named"           "at the release tag"          's.replace("at the release tag", "at the latest commit")'
mutant "repository not named"            "at the release tag"          's.replace("from the repository at", "from the web at")'
mutant "release assets not named"        "release assets"              's.replace("from the release assets", "from the release page")'
mutant "signature file not named"        "manifest and its signature"  's.replace("release-key-manifest.sig from", "its signature from")'
mutant "publish date not compared"       "publish date"                's.replace("publish date", "tag")'
mutant "valid_to not named"              "publish date"                's.replace("valid_to", "the end date")'
mutant "newest manifest not named"       "newest manifest"             's.replace("newest manifest", "manifest")'
mutant "key_id not named"                "key_id"                      's.replace("key_id", "key")'
mutant "revoked key not named"           "revoked"                     's.replace("revoked", "bad")'
# no open mark on where the files are published
mutant "TO-VERIFY on the root key line"  "TO-VERIFY mark"  's.replace("release-key-root.pub`.\n", "release-key-root.pub`. TO-VERIFY: the path.\n")'
mutant "TO-VERIFY on the manifest line"  "TO-VERIFY mark"  's.replace("from the release assets.", "from the release assets. TO-VERIFY: the names.")'
mutant "a TO-VERIFY line on publishing"  "TO-VERIFY mark"  's + "\nTO-VERIFY: where the manifest is published.\n"'
python3 -I -c 'import sys; open(sys.argv[2],"w").write(open(sys.argv[1]).read() + "\nTO-VERIFY: the cosign version.\n")' "$work/f/good.md" "$work/f/other.md" </dev/null
out=$(judge "$work/f/other.md"); rc=$?
[ "$rc" -eq 0 ] && ok "a TO-VERIFY mark on an unrelated line is allowed" || bad "a TO-VERIFY mark on an unrelated line is refused" "$out"
# customer words
mutant "a shop word in an added line"    "check-customer-words.py rc=1" 's + "\nAsk the owner.\n"'
# the missing page
out=$(judge "$work/f/none.md"); rc=$?
[ "$rc" -ne 0 ] && [[ "$out" == *"does not exist"* ]] && ok "kills mutant: the page is missing" || bad "MISSED mutant: the page is missing" "$out"

# the real page
out=$(judge "$page"); rc=$?
[ "$rc" -eq 0 ] && ok "docs/verify-key.md passes" || bad "docs/verify-key.md" "$out"

echo "verify-key-page: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
