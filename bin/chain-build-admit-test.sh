#!/usr/bin/env bash
# proves: REQ-CHAIN-004-AC4, REQ-CHAIN-004-AC5, REQ-CHAIN-004-AC7
# RED until bin/build-admit.py and bin/build-version-check.py exist (tests before implementation, step 4 of the nine-step process).
#
# Build's first action: bin/build-admit.py keeps EVERY check the old stage-admission.yml made, none dropped (v0.3.0 rules 51, 58;
# advisor read-back 0338 and 0325 Q2). Needs: bash, git >= 2.34, ssh-keygen, gpg, jq, python3 + PyYAML. Offline: the git repos, the
# owner/attacker SSH keys and the web-flow GPG key are made at test time (nothing committed, no network); GitHub is faked by a `gh` on PATH
# that serves JSON files, `gitsign` and `go` are fakes that log their argv (the gitsign route is proven by its argv; a real keyless
# tag is proven only by the dry run: STATED GAP, and the CI patch-baseline path is covered by bin/admission-tag-signer-test.sh and by
# cache's auto-baseline PR, so here only the owner route and the missing-baseline cases are run).
#
# THE CLI THIS TEST ASSUMES (the implementer matches it; anything else is a change to this header first):
#   python3 bin/build-admit.py run [--out admission.json]     run from the repo root (the checkout of the tagged commit)
#       Reads the tag ONLY from the environment (GITHUB_REF, GITHUB_REF_NAME, GITHUB_SHA, GITHUB_REPOSITORY, GITHUB_RUN_ID,
#       GITHUB_RUN_ATTEMPT): any tag/ref/sha argument is a usage error (exit 2, "environment"); tag strings are never put in a shell.
#       The policy inputs come from `git show origin/main:<path>` (allowed_signers, github-web-flow.gpg, required-checks.json,
#       bin/admission-tag-signer.py, bin/install-scanner.sh), NEVER from the checked-out tagged commit.
#       GitHub data only through `gh api <PATH>` (GET: no -X/--method/-f/-F/--input), parsing the JSON itself, for PATH
#         repos/R/commits/SHA/check-runs?filter=latest   (and the same for the merged PR's head sha)
#         repos/R/commits/SHA/status
#         repos/R/commits/SHA/pulls
#       `go -C tools/requirements run . verify-freeze BASE` with GOTOOLCHAIN=local for the baseline's consistency; `gitsign verify-tag`
#       with the exact identity flags for a patch route. Exit 0: wrote admission.json. Exit 1: the first line of stderr is
#       `admission refused at <check>: <reason>` and NO admission.json is left. Exit 2: usage or environment error.
#   python3 bin/build-admit.py list-checks                    one check name per line, in order (below)
#   python3 bin/build-version-check.py --binary PATH --tag vX.Y.Z --sha SHA
#       Reads the embedded build info with `go version -m PATH` (no execution of the binary): `mod <path> <version>` and
#       `build vcs.revision=<sha>` / `build vcs.modified=true` lines (internal/buildinfo/buildinfo.go:21-59 is what the server reports).
#       Exit 0 only for module version == the tag and vcs.revision == SHA and not modified; otherwise exit 1 naming
#       `version` / `revision` / `modified` / `devel`.
# THE TEN CHECKS, in order (names are the counterpart of each step of stage-admission.yml):
CHECKS="tag-ref tag-syntax policy-from-main tag-annotated tag-signature commit-signature ancestor-of-main required-checks baseline admission-evidence"
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
BA="$root/bin/build-admit.py"; BV="$root/bin/build-version-check.py"
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
pass=0 failn=0
ok()  { pass=$((pass + 1)); echo "ok   $1"; }
bad() { failn=$((failn + 1)); echo "FAIL $1"; }
python3 -c 'import yaml' 2> /dev/null || { echo "FAIL PyYAML is required (apt: python3-yaml)"; exit 1; }
for t in git ssh-keygen gpg jq; do command -v "$t" > /dev/null || { echo "FAIL $t is required"; exit 1; }; done
# ---- the counterpart judge (REQ-CHAIN-004-AC5): proven on a fixture first -----------------------------------------------------
cat > "$W/judge_counterpart.py" <<'PY'
import sys, yaml
# old step name (prefix) -> counterpart check, or "REPLACED:<why>" / "TOOLING:<why>" (the only steps allowed without one)
MAP = [
 ("resolve and validate the tag", ["tag-ref", "tag-syntax"]),
 ("fetch policy from protected main", ["policy-from-main"]),
 ("verify the annotated tag signature", ["tag-annotated", "tag-signature"]),
 ("verify the tagged commit signature", ["commit-signature"]),
 ("the tagged commit must be on main", ["ancestor-of-main"]),
 ("every required check green", ["required-checks"]),
 ("an APPROVED, consistent requirements baseline", ["baseline"]),
 ("write canonical admission.json", ["admission-evidence"]),
 ("sign the source-admission predicate", "REPLACED: a custom record type; rule 63 allows only Witness's own signed record"),
 ("set up Go", "TOOLING: the Go toolchain is pinned by the archive and cache's scripts (rule 12)"),
]
text, checks = sys.stdin.read(), sys.argv[1].split()
d = yaml.safe_load(text)
steps = (d.get("jobs") or {}).get("admit", {}).get("steps") or []
bad = []
for s in steps:
    name = s.get("name") or ""
    if "uses" in s and not name:
        if str(s["uses"]).startswith("actions/checkout"): continue          # TOOLING: the checkout
        if str(s["uses"]).startswith("actions/upload-artifact"): continue   # REPLACED: Witness's record is Build's output
    hit = next((m for p, m in MAP if name.startswith(p)), None)
    if hit is None:
        bad.append("old step %r has no counterpart (not mapped, not replaced, not tooling)" % name); continue
    if isinstance(hit, list):
        for c in hit:
            if c not in checks: bad.append("old step %r maps to check %r but build-admit.py list-checks does not list it" % (name, c))
for p, m in MAP:
    if isinstance(m, list):
        for c in m:
            if c not in checks: bad.append("check %r (for %r) is not listed" % (c, p))
print("; ".join(bad) or "ok"); sys.exit(1 if bad else 0)
PY
cat > "$W/old.yml" <<'EOF'
jobs:
  admit:
    steps:
      - name: resolve and validate the tag from the trusted event payload
        run: x
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
      - name: fetch policy from protected main (never from the tagged commit)
        run: x
      - name: verify the annotated tag signature (the owner's SSH key)
        run: x
      - name: verify the tagged commit signature (owner SSH key or pinned web-flow key)
        run: x
      - name: the tagged commit must be on main
        run: x
      - name: every required check green, app-pinned, per its scope
        run: x
      - name: set up Go for the baseline consistency check
        uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e
      - name: an APPROVED, consistent requirements baseline must exist for this version
        run: x
      - name: write canonical admission.json
        run: x
      - name: sign the source-admission predicate (subject = admission.json)
        uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a
EOF
cj() { local rc=0 out; out=$(python3 "$W/judge_counterpart.py" "$2" < "$1" 2>&1) || rc=$?; echo "$rc|$out"; }
r=$(cj "$W/old.yml" "$CHECKS"); [ "${r%%|*}" = 0 ] && ok "AC5 judge fixture: every old step has a counterpart (replaced and tooling steps are named)" || bad "AC5 judge fixture -> $r"
sed 's/name: the tagged commit must be on main/name: a brand new admission rule/' "$W/old.yml" > "$W/old2.yml"
r=$(cj "$W/old2.yml" "$CHECKS"); [ "${r%%|*}" = 1 ] && grep -Fq "brand new admission rule" <<< "$r" && ok "AC5 judge: a new old-stage step with no counterpart is caught" || bad "AC5 judge new step -> $r"
r=$(cj "$W/old.yml" "tag-ref tag-syntax policy-from-main tag-annotated tag-signature commit-signature required-checks baseline admission-evidence"); [ "${r%%|*}" = 1 ] && grep -Fq "ancestor-of-main" <<< "$r" && ok "AC5 judge: a check dropped from list-checks is caught" || bad "AC5 judge dropped check -> $r"
# the real comparison: the old stage at origin/main (or the working file), against build-admit.py list-checks
old=$(git -C "$root" show origin/main:.github/workflows/stage-admission.yml 2> /dev/null || cat "$root/.github/workflows/stage-admission.yml" 2> /dev/null || true)
if [ -z "$old" ]; then bad "AC5 the old stage-admission.yml is not readable at origin/main or in the tree (error: fail closed)"
elif [ ! -f "$BA" ]; then bad "AC5 bin/build-admit.py does not exist (RED: not implemented yet): list-checks"; bad "AC5 bin/build-admit.py does not exist (RED): comparison with the real stage-admission.yml"
else
  got=$(python3 "$BA" list-checks 2> /dev/null | tr '\n' ' ' | sed 's/ $//' || true)
  [ "$got" = "$CHECKS" ] && ok "AC5 build-admit.py list-checks is exactly the ten checks in order" || bad "AC5 list-checks is '$got', wanted '$CHECKS'"
  r=$(cj <(printf '%s\n' "$old") "$got"); [ "${r%%|*}" = 0 ] && ok "AC5 every step of the real stage-admission.yml has a counterpart" || bad "AC5 real comparison -> $r"
fi
# ---- the version check (REQ-CHAIN-004-AC7): a fake `go version -m` -------------------------------------------------------------
FB="$W/fakebin"; mkdir -p "$FB"
cat > "$FB/go" <<'EOF'
#!/usr/bin/env bash
echo "go $*" >> "${FAKE_LOG:-/dev/null}"
echo "GOTOOLCHAIN=${GOTOOLCHAIN:-unset}" >> "${FAKE_LOG:-/dev/null}"
if [ "${1:-}" = version ] && [ "${2:-}" = -m ]; then cat "${FAKE_BUILDINFO:?}"; exit 0; fi
exit "${FAKE_GO_RC:-0}"
EOF
chmod +x "$FB/go"
SHA=0123456789abcdef0123456789abcdef01234567
bi() { printf '%s\n' "$1: go1.27.2" "	path	github.com/fosterstack/cache/cmd/fscache" "	mod	github.com/fosterstack/cache	$2	" "	build	-ldflags=\"-s -w\"" "	build	vcs=git" "	build	vcs.revision=$3" "	build	vcs.modified=$4"; }
vc() { # vc ok|refuse LABEL WORD VERSION REV MODIFIED [TAG]
  local want=$1 label=$2 word=$3 ver=$4 rev=$5 mod=$6 tag=${7:-v0.3.0} rc=0
  if [ ! -f "$BV" ]; then bad "$label (bin/build-version-check.py does not exist: RED)"; return; fi
  bi out/fscache "$ver" "$rev" "$mod" > "$W/buildinfo.txt"; : > "$W/fscache"
  PATH="$FB:$PATH" FAKE_BUILDINFO="$W/buildinfo.txt" python3 "$BV" --binary "$W/fscache" --tag "$tag" --sha "$SHA" > "$W/vc.out" 2> "$W/vc.err" || rc=$?
  if grep -q Traceback "$W/vc.err"; then bad "$label -> a Python traceback is a crash, not a refusal"; return; fi
  if [ "$want" = ok ]; then [ "$rc" = 0 ] && ok "$label" || bad "$label -> exit $rc: $(head -c 150 "$W/vc.err")"
  else [ "$rc" = 1 ] && grep -Fqi -- "$word" "$W/vc.err" && ok "$label" || bad "$label -> exit $rc, wanted 1 naming '$word': $(head -c 150 "$W/vc.err")"; fi
}
vc ok     "AC7 the embedded version is the tag and the revision is the tagged commit" "" v0.3.0 "$SHA" false
vc refuse "AC7 (devel) is refused (rule 24)" devel "(devel)" "$SHA" false
vc refuse "AC7 a different version than the tag is refused" version v0.3.1 "$SHA" false
vc refuse "AC7 a different revision is refused" revision v0.3.0 fedcba9876543210fedcba9876543210fedcba98 false
vc refuse "AC7 a missing revision is refused" revision v0.3.0 "" false
vc refuse "AC7 a modified-tree marker is refused" modified v0.3.0 "$SHA" true
vc refuse "AC7 a pseudo-version is refused" version v0.3.1-0.20261009120000-0123456789ab "$SHA" false
vc refuse "AC7 the tag with a prefix of the version is refused (v0.3.0-rc.1 vs v0.3.0)" version v0.3.0-rc.1 "$SHA" false
vc ok     "AC7 a release candidate tag matches its own version" "" v0.3.1-rc.2 "$SHA" false v0.3.1-rc.2
vc refuse "AC7 an upper-case revision of the same commit is not accepted as equal" revision v0.3.0 "${SHA^^}" false
# ---- the admission fixtures ----------------------------------------------------------------------------------------------
mkkeys() { mkdir -p "$W/keys"; for k in owner attacker; do ssh-keygen -q -t ed25519 -N "" -C "$k@example.com" -f "$W/keys/$k"; done
  export GNUPGHOME="$W/gpg-web"; mkdir -m 700 "$GNUPGHOME"
  gpg --batch --quiet --passphrase '' --quick-gen-key "web-flow <noreply@github.com>" ed25519 sign never 2> /dev/null
  gpg --batch --quiet --armor --export "noreply@github.com" > "$W/keys/web.gpg"; WEBID=$(gpg --list-keys --with-colons noreply@github.com | awk -F: '/^pub/{print $5; exit}')
  export GNUPGHOME="$W/gpg-other"; mkdir -m 700 "$GNUPGHOME"
  gpg --batch --quiet --passphrase '' --quick-gen-key "other <other@example.com>" ed25519 sign never 2> /dev/null
  OTHERID=$(gpg --list-keys --with-colons other@example.com | awk -F: '/^pub/{print $5; exit}'); unset GNUPGHOME; }
mkbase() { # base fixture in $W/base: origin.git + repo with main, a signed tagged commit, policy on main
  local b="$W/base"; mkdir -p "$b"; git init -q --bare "$b/origin.git"; git clone -q "$b/origin.git" "$b/repo" 2> /dev/null
  cd "$b/repo"; git config user.name t; git config user.email t@example.com; git config gpg.format ssh; git config user.signingkey "$W/keys/owner"
  git config tag.gpgsign false; git checkout -q -b main
  mkdir -p .github/policy bin requirements/releases tools/requirements
  printf 'owner@example.com ssh-ed25519 %s\n' "$(cut -d' ' -f2 "$W/keys/owner.pub")" > .github/policy/allowed_signers
  cp "$W/keys/web.gpg" .github/policy/github-web-flow.gpg
  printf '{"required_checks":[{"context":"ci","integration_id":15368,"scope":"push"},{"context":"review","integration_id":15368,"scope":"pull_request"}]}\n' > .github/policy/required-checks.json
  cp "$root/bin/admission-tag-signer.py" bin/; printf '#!/bin/sh\nexit 0\n' > bin/install-scanner.sh
  printf 'requirements: []\n' > requirements/requirements.yaml
  printf 'version: v0.3.0\napproved: true\napproved_on: "2026-10-09"\nrequirements_sha256: %s\nrelease_blocking_acs: [REQ-X-001-AC1]\n' "$(printf 'a%.0s' $(seq 64))" > requirements/releases/v0.3.0.yaml
  printf 'module x\n' > tools/requirements/go.mod
  git add -A; git commit -q -S -m "release prep"; git push -q origin main 2> /dev/null; git fetch -q origin
  git tag -s -m "v0.3.0" v0.3.0; git push -q origin refs/tags/v0.3.0 2> /dev/null
  cd "$root"
}
gh_fixtures() { # gh_fixtures DIR SHA  (all green; the merged PR is #7 with head PRHEAD)
  mkdir -p "$1"; local sha=$2 ph=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  python3 - "$1" "$sha" "$ph" <<'PY'
import json, sys
d, sha, ph = sys.argv[1:4]
def w(path, obj): open(d + "/" + path.replace("/", "_").replace("?", "_").replace("=", "_") + ".json", "w").write(json.dumps(obj))
w("repos/fosterstack/cache/commits/%s/check-runs?filter=latest" % sha, {"check_runs": [{"name": "ci", "conclusion": "success", "app": {"id": 15368}, "id": 11, "head_sha": sha}]})
w("repos/fosterstack/cache/commits/%s/status" % sha, {"statuses": [{"context": "legacy", "state": "success", "id": 5}]})
w("repos/fosterstack/cache/commits/%s/pulls" % sha, [{"number": 7, "merge_commit_sha": sha, "base": {"ref": "main"}, "merged_at": "2026-10-01T00:00:00Z", "head": {"sha": ph}}])
w("repos/fosterstack/cache/commits/%s/check-runs?filter=latest" % ph, {"check_runs": [{"name": "review", "conclusion": "success", "app": {"id": 15368}, "id": 12, "head_sha": ph}]})
PY
}
cat > "$FB/gh" <<'EOF'
#!/usr/bin/env bash
echo "gh $*" >> "${FAKE_LOG:-/dev/null}"
[ "${1:-}" = api ] || exit 1
for a in "$@"; do case "$a" in -X|--method|-f|-F|--input|--field|--raw-field) echo "NON-GET $*" >> "${FAKE_LOG:-/dev/null}";; esac; done
p="$2"; f="$GH_FIXTURES/$(printf '%s' "$p" | tr '/?=' '___').json"
[ -f "$f" ] && cat "$f" || { echo "no fixture for $p" >&2; exit 1; }
EOF
cat > "$FB/gitsign" <<'EOF'
#!/usr/bin/env bash
echo "gitsign $*" >> "${FAKE_LOG:-/dev/null}"
exit "${FAKE_GITSIGN_RC:-0}"
EOF
chmod +x "$FB/gh" "$FB/gitsign"
# case DIR runner: each case gets a fresh copy of the base repo
n_cases=0
fresh() { rm -rf "$W/c"; mkdir -p "$W/c"; cp -a "$W/base/origin.git" "$W/c/origin.git"; git clone -q "$W/c/origin.git" "$W/c/repo" 2> /dev/null
  (cd "$W/c/repo"; git config user.name t; git config user.email t@example.com; git config gpg.format ssh; git config user.signingkey "$W/keys/owner"; git config tag.gpgsign false
   git fetch -q origin 2> /dev/null; git fetch -q --tags origin 2> /dev/null; git checkout -q --detach v0.3.0 2> /dev/null; git branch -q -f main origin/main 2> /dev/null || true)
  SHAC=$(git -C "$W/c/repo" rev-parse v0.3.0^{commit}); gh_fixtures "$W/c/gh" "$SHAC"; : > "$W/c/calls.log"; rm -f "$W/c/repo/admission.json"; }
run_admit() { # run_admit [ENV=VAL...]  -> sets RC; stderr in $W/c/err, stdout in $W/c/out
  local sha; sha=$(git -C "$W/c/repo" rev-parse HEAD); RC=0
  (cd "$W/c/repo" && env GITHUB_REF=refs/tags/v0.3.0 GITHUB_REF_NAME=v0.3.0 GITHUB_SHA="$sha" GITHUB_REPOSITORY=fosterstack/cache GITHUB_RUN_ID=1 GITHUB_RUN_ATTEMPT=1 \
     GH_TOKEN=SENTINEL-GH-TOKEN GH_FIXTURES="$W/c/gh" FAKE_LOG="$W/c/calls.log" FAKE_BUILDINFO="$W/buildinfo.txt" PATH="$FB:$PATH" "$@" \
     python3 "$BA" run --out admission.json > "$W/c/out" 2> "$W/c/err") || RC=$?
}
expect_ok() { n_cases=$((n_cases + 1)); if [ ! -f "$BA" ]; then bad "$1 (bin/build-admit.py does not exist: RED)"; return; fi
  if grep -q Traceback "$W/c/err" 2> /dev/null; then bad "$1 -> a Python traceback is a crash"; return; fi
  [ "$RC" = 0 ] && [ -f "$W/c/repo/admission.json" ] && ok "$1" || bad "$1 -> exit $RC: $(head -c 200 "$W/c/err" | tr '\n' ' ')"; }
expect_refuse() { # expect_refuse LABEL CHECK [WORD]
  n_cases=$((n_cases + 1)); if [ ! -f "$BA" ]; then bad "$1 (bin/build-admit.py does not exist: RED)"; return; fi
  if grep -q Traceback "$W/c/err" 2> /dev/null; then bad "$1 -> a Python traceback is a crash, not a refusal"; return; fi
  local first; first=$(head -1 "$W/c/err" 2> /dev/null || true)
  if [ "$RC" = 1 ] && [[ "$first" == "admission refused at $2: "* ]] && [ ! -e "$W/c/repo/admission.json" ] && { [ -z "${3:-}" ] || grep -Fqi -- "${3}" <<< "${first#*: }"; }; then ok "$1"
  else bad "$1 -> exit $RC, first line '$first', admission.json present=$([ -e "$W/c/repo/admission.json" ] && echo yes || echo no) (wanted 'admission refused at $2: <reason${3:+ naming $3}>')"; fi; }
mkkeys; mkbase
bi out/fscache v0.3.0 "$SHA" false > "$W/buildinfo.txt"
G() { git -C "$W/c/repo" "$@"; }
commit_move() { # commit_move KEYMODE MSG : a new commit on main (signed per KEYMODE: owner|attacker|none|web|other), pushed; HEAD moves
  local m=$1; shift
  case "$m" in
    owner) G -c user.signingkey="$W/keys/owner" commit -q -S --allow-empty -m "$1" ;;
    attacker) G -c user.signingkey="$W/keys/attacker" commit -q -S --allow-empty -m "$1" ;;
    none) G commit -q --allow-empty -m "$1" ;;
    web) GNUPGHOME="$W/gpg-web" G -c gpg.format=openpgp -c user.signingkey=noreply@github.com commit -q -S --allow-empty -m "$1" ;;
    other) GNUPGHOME="$W/gpg-other" G -c gpg.format=openpgp -c user.signingkey=other@example.com commit -q -S --allow-empty -m "$1" ;;
  esac
  G push -q origin HEAD:main 2> /dev/null; G fetch -q origin 2> /dev/null; }
retag() { # retag KIND : move v0.3.0 to HEAD. KIND owner|attacker|none (annotated unsigned)|light
  G tag -d v0.3.0 > /dev/null; case "$1" in
    owner) G -c user.signingkey="$W/keys/owner" tag -s -m v0.3.0 v0.3.0 ;;
    attacker) G -c user.signingkey="$W/keys/attacker" tag -s -m v0.3.0 v0.3.0 ;;
    none) G tag -a -m v0.3.0 v0.3.0 ;;
    light) G tag v0.3.0 ;;
  esac; }
# ---- fixture self-checks: the inputs are what the cases claim they are (so a refusal is about the claimed cause) -----------------
patch_tag() { # patch_tag NAME : an annotated tag object with an x509 signature-shaped block (gitsign), created with git mktag
  local name=$1 sha obj; sha=$(G rev-parse HEAD); obj=$(printf 'object %s\ntype commit\ntag %s\ntagger t <t@example.com> 1700000000 +0000\n\nrelease\n-----BEGIN SIGNED MESSAGE-----\nMIIBfake\n-----END SIGNED MESSAGE-----\n' "$sha" "$name" | G mktag)
  G update-ref "refs/tags/$name" "$obj"; }
fresh; G config gpg.ssh.allowedSignersFile "$W/c/repo/.github/policy/allowed_signers"
G verify-tag v0.3.0 > /dev/null 2>&1 && ok "fixture: the owner-signed tag verifies against main's allowed_signers" || bad "fixture: owner tag does not verify"
G verify-commit HEAD > /dev/null 2>&1 && ok "fixture: the owner-signed commit verifies against main's allowed_signers" || bad "fixture: owner commit does not verify"
retag attacker; G verify-tag v0.3.0 > /dev/null 2>&1 && bad "fixture: the attacker tag must NOT verify" || ok "fixture: a tag signed by the attacker key does not verify against main's list"
commit_move web "web"; mkdir -p "$W/gh-check"; GNUPGHOME="$W/gh-check" gpg --batch --quiet --import "$W/c/repo/.github/policy/github-web-flow.gpg" 2> /dev/null
GNUPGHOME="$W/gh-check" G -c gpg.format=openpgp verify-commit HEAD > /dev/null 2>&1 && ok "fixture: the web-flow GPG commit verifies against the pinned key" || bad "fixture: web-flow commit does not verify"
commit_move other "other"; GNUPGHOME="$W/gh-check" G -c gpg.format=openpgp verify-commit HEAD > /dev/null 2>&1 && bad "fixture: the other-key GPG commit must NOT verify" || ok "fixture: a commit signed by another GPG key does not verify against the pinned key"
fresh; patch_tag v0.3.1; G cat-file tag v0.3.1 > "$W/c/tagobj"; git -C "$W/c/repo" tag -l 'v*' > "$W/c/released"
r=$(python3 "$root/bin/admission-tag-signer.py" route --tag v0.3.1 --tag-object "$W/c/tagobj" --tags "$W/c/released" 2>&1 || true); [ "${r%% *}" = gitsign ] && ok "fixture: the patch tag routes to gitsign (next patch of the released v0.3.0)" || bad "fixture: patch route is '$r'"
r=$(GH_FIXTURES="$W/c/gh" PATH="$FB:$PATH" gh api "repos/fosterstack/cache/commits/$SHAC/check-runs?filter=latest" | jq -r '.check_runs[0].name'); [ "$r" = ci ] && ok "fixture: the fake gh serves the check runs of the tagged commit" || bad "fixture: fake gh"
GH_FIXTURES="$W/c/gh" PATH="$FB:$PATH" gh api repos/fosterstack/cache/nope > /dev/null 2>&1 && bad "fixture: the fake gh must fail for an unknown path" || ok "fixture: the fake gh fails for a path it has no fixture for (no silent empty answers)"
# ---- the happy path and its evidence (REQ-CHAIN-004-AC4: admission-evidence) ----------------------------------------------------
fresh; run_admit
expect_ok "AC4 an owner-signed tag on an owner-signed commit on main with green checks and an approved baseline is admitted"
if [ -f "$W/c/repo/admission.json" ]; then
  A="$W/c/repo/admission.json"
  jq -S . "$A" | cmp -s - "$A" && ok "AC4 admission.json is canonical (sorted keys, jq -S layout, so the product hash is stable)" || bad "AC4 admission.json is not canonical"
  jq -e '.tag=="v0.3.0" and .sha=="'"$SHAC"'" and (.tag_signature.method=="owner-ssh") and (.tag_signature.principal|length>0) and (.tag_signature.key_fingerprint|startswith("SHA256:")) and (.commit_signature=="owner-ssh") and (.required_checks|length==2) and (.informational_statuses|length==1) and .baseline_version=="v0.3.0" and (.baseline=="requirements/releases/v0.3.0.yaml") and (.run.id==1) and (.run.attempt==1)' "$A" > /dev/null \
    && ok "AC4 admission.json records the tag, sha, signer evidence, every verified check with its source, the informational statuses, the baseline and the run" || bad "AC4 admission.json content: $(head -c 300 "$A")"
  jq -e '[.required_checks[].source]|sort==["check-run-on-merged-pr-head","check-run-on-tagged-sha"]' "$A" > /dev/null && ok "AC4 push-scoped and pull_request-scoped checks are recorded with their evidence source" || bad "AC4 required_checks sources"
  ! grep -rq SENTINEL-GH-TOKEN "$A" "$W/c/out" "$W/c/err" && ok "AC4 the GitHub token appears in no output or evidence" || bad "AC4 the token leaked into output"
  cp "$A" "$W/c/first.json"; rm "$A"; run_admit; cmp -s "$W/c/first.json" "$A" && ok "AC4 admission.json is byte-identical on a second run (deterministic)" || bad "AC4 admission.json differs between runs"
  ! grep -qE 'NON-GET' "$W/c/calls.log" && grep -c '^gh api repos/fosterstack/cache/commits/' "$W/c/calls.log" | grep -q . && ok "AC4 every GitHub call is a GET of the commits API" || bad "AC4 a non-GET gh call: $(grep NON-GET "$W/c/calls.log" | head -1)"
else for l in "canonical" "content" "sources" "token" "deterministic" "GET only"; do bad "AC4 admission.json $l (no admission.json: RED)"; done; fi
if [ -f "$BA" ]; then ! grep -Eq '\b(curl|wget)\b|api\.github\.com' "$BA" && ok "AC4 the script makes no network call of its own (only gh api)" || bad "AC4 build-admit.py calls the network itself"; else bad "AC4 no network of its own (bin/build-admit.py missing: RED)"; fi
# ---- tag-ref, tag-syntax ---------------------------------------------------------------------------------------------------------
fresh; run_admit GITHUB_REF=refs/heads/main;                  expect_refuse "AC4 a branch ref is refused (tag pushes only)" tag-ref
fresh; run_admit GITHUB_REF= GITHUB_REF_NAME=;                 expect_refuse "AC4 an empty ref is refused" tag-ref
for t in v1.2 v1.2.3-rc V0.3.0 "v0.3.0 " v0.3.0-rc.x 0.3.0 v0.3.0-rc.1-x "v0.3.0
x"; do
  fresh; run_admit "GITHUB_REF=refs/tags/$t" "GITHUB_REF_NAME=$t"; expect_refuse "AC4 the tag syntax gate refuses '$(printf '%s' "$t" | tr '\n' '|')'" tag-syntax
done
for t in v0.3.0-rc.1 v10.20.30; do fresh; run_admit "GITHUB_REF=refs/tags/$t" "GITHUB_REF_NAME=$t"; [ -f "$BA" ] && { [ "$RC" = 0 ] || ! grep -q 'tag-syntax' "$W/c/err"; } && ok "AC4 the syntax gate lets '$t' through to the later checks (it is refused there, for a different reason)" || bad "AC4 syntax gate wrongly refused $t: $(head -1 "$W/c/err" 2> /dev/null)"; done
fresh; rm -f "$W/pwned"; run_admit "GITHUB_REF=refs/tags/v';touch $W/pwned;#" "GITHUB_REF_NAME=v';touch $W/pwned;#"
expect_refuse "AC4 a hostile tag name is refused at the syntax gate" tag-syntax
[ ! -e "$W/pwned" ] && ok "AC4 a hostile tag name never reaches a shell (nothing executed)" || bad "AC4 the hostile tag name executed"
fresh; n_cases=$((n_cases + 1)); RC=0; (cd "$W/c/repo" && env GITHUB_REF=refs/tags/v0.3.0 GITHUB_REF_NAME=v0.3.0 GITHUB_SHA="$SHAC" PATH="$FB:$PATH" python3 "$BA" run --tag v0.3.0 > "$W/c/out" 2> "$W/c/err") || RC=$?
{ [ -f "$BA" ] && [ "$RC" = 2 ] && grep -qi environment "$W/c/err"; } && ok "AC4 a tag given as an argument is a usage error (the tag comes only from the environment)" || bad "AC4 --tag accepted or wrong exit: $RC"
# ---- policy-from-main -------------------------------------------------------------------------------------------------------------
fresh; G checkout -q -b feature v0.3.0 2> /dev/null; printf 'attacker@example.com ssh-ed25519 %s\n' "$(cut -d' ' -f2 "$W/keys/attacker.pub")" >> "$W/c/repo/.github/policy/allowed_signers"
G add -A; G commit -q -S -m "attacker adds itself to the allowed signers" ; retag attacker; run_admit
expect_refuse "AC4 an allowed_signers list changed in the TAGGED commit is not trusted (policy comes from origin/main)" tag-signature
fresh; G checkout -q main; printf '{"required_checks":[]}\n' > "$W/c/repo/.github/policy/required-checks.json"; G add -A; G -c user.signingkey="$W/keys/owner" commit -q -S -m "weak policy"; G push -q origin main 2> /dev/null
WEAK=$(G rev-parse HEAD); git -C "$W/c/repo" checkout -q "$SHAC" -- .github/policy/required-checks.json; G add -A; G -c user.signingkey="$W/keys/owner" commit -q -S -m "strong policy again"; G push -q origin main 2> /dev/null; G fetch -q origin
G checkout -q --detach "$WEAK"; retag owner; python3 - "$W/c/gh" <<'PY'
import glob, json, sys
for f in glob.glob(sys.argv[1] + "/*"): pass
PY
rm -rf "$W/c/gh"; mkdir -p "$W/c/gh"; echo '{"check_runs":[]}' > "$W/c/gh/repos_fosterstack_cache_commits_${WEAK}_check-runs_filter_latest.json"; echo '{"statuses":[]}' > "$W/c/gh/repos_fosterstack_cache_commits_${WEAK}_status.json"; echo '[]' > "$W/c/gh/repos_fosterstack_cache_commits_${WEAK}_pulls.json"
run_admit; expect_refuse "AC4 a required-checks list weakened in the TAGGED commit does not weaken the gate (policy comes from origin/main, not the tagged commit)" required-checks
# ---- tag-annotated, tag-signature ---------------------------------------------------------------------------------------------------
fresh; retag light; run_admit;   expect_refuse "AC4 a lightweight tag is refused" tag-annotated
fresh; retag none; run_admit;    expect_refuse "AC4 an unsigned annotated tag is refused" tag-signature
fresh; retag attacker; run_admit; expect_refuse "AC4 a tag signed by a key that is not in main's allowed signers is refused" tag-signature
# a CI patch tag: the gitsign route (a gitsign-shaped signature block on the next patch of a released line)
fresh; patch_tag v0.3.1; run_admit GITHUB_REF=refs/tags/v0.3.1 GITHUB_REF_NAME=v0.3.1 FAKE_GITSIGN_RC=0
if grep -q 'gitsign verify-tag v0.3.1' "$W/c/calls.log" 2> /dev/null; then
  for want in "--certificate-identity https://github.com/fosterstack/cache/.github/workflows/release.yml@refs/heads/main" "--certificate-oidc-issuer https://token.actions.githubusercontent.com" "--certificate-github-workflow-repository fosterstack/cache" "--certificate-github-workflow-ref refs/heads/main" "--certificate-github-workflow-sha $SHAC"; do
    grep -Fq -- "$want" "$W/c/calls.log" && ok "AC4 the patch route verifies with $want" || bad "AC4 the patch route's gitsign call lacks $want"; done
else for i in 1 2 3 4 5; do bad "AC4 the patch route never called gitsign verify-tag (RED: not implemented or the route was not taken)"; done; fi
expect_refuse "AC4 a patch tag whose signer metadata cannot be extracted is refused: no empty evidence is admitted" tag-signature evidence
fresh; patch_tag v0.3.1; run_admit GITHUB_REF=refs/tags/v0.3.1 GITHUB_REF_NAME=v0.3.1 FAKE_GITSIGN_RC=1
expect_refuse "AC4 a patch tag whose keyless verification fails is refused" tag-signature
fresh; patch_tag v0.4.0; run_admit GITHUB_REF=refs/tags/v0.4.0 GITHUB_REF_NAME=v0.4.0 FAKE_GITSIGN_RC=0
expect_refuse "AC4 the keyless identity on a MINOR tag is refused (the owner signs minors)" tag-signature
# ---- commit-signature ----------------------------------------------------------------------------------------------------------------
fresh; commit_move none "unsigned"; retag owner; run_admit;     expect_refuse "AC4 an unsigned tagged commit is refused" commit-signature
fresh; commit_move attacker "attacker"; retag owner; run_admit; expect_refuse "AC4 a commit signed by a key outside main's allowed signers is refused" commit-signature
fresh; commit_move other "other gpg"; retag owner; run_admit;   expect_refuse "AC4 a commit signed by a GPG key that is not the pinned web-flow key is refused" commit-signature
fresh; commit_move web "web-flow"; retag owner; gh_fixtures "$W/c/gh" "$(G rev-parse HEAD)"; run_admit
expect_ok "AC4 a commit signed by the pinned web-flow GPG key is admitted"
# ---- ancestor-of-main ----------------------------------------------------------------------------------------------------------------
fresh; G checkout -q -b side v0.3.0 2> /dev/null; commit_move_side() { G -c user.signingkey="$W/keys/owner" commit -q -S --allow-empty -m side; }; commit_move_side; retag owner; gh_fixtures "$W/c/gh" "$(G rev-parse HEAD)"; run_admit
expect_refuse "AC4 a tagged commit that is not an ancestor of origin/main is refused" ancestor-of-main
# ---- required-checks (push scope, pull_request scope, app pin, statuses) -----------------------------------------------------------------
edit_gh() { python3 - "$W/c/gh" "$1" <<'PY'
import glob, json, sys
d, mode = sys.argv[1], sys.argv[2]
for f in glob.glob(d + "/*"):
    j = json.load(open(f)); n = f.rsplit("/", 1)[1]
    if mode == "no-push" and "check-runs" in n and "aaaaaaaa" not in n: j["check_runs"] = []
    if mode == "wrong-app" and "check-runs" in n and "aaaaaaaa" not in n: j["check_runs"][0]["app"]["id"] = 99
    if mode == "failed" and "check-runs" in n and "aaaaaaaa" not in n: j["check_runs"][0]["conclusion"] = "failure"
    if mode == "no-pr" and n.endswith("pulls.json"): j = []
    if mode == "pr-mismatch" and n.endswith("pulls.json"): j[0]["merge_commit_sha"] = "b" * 40
    if mode == "pr-not-main" and n.endswith("pulls.json"): j[0]["base"]["ref"] = "other"
    if mode == "pr-unmerged" and n.endswith("pulls.json"): j[0]["merged_at"] = None
    if mode == "pr-red" and "aaaaaaaa" in n: j["check_runs"][0]["conclusion"] = "failure"
    if mode == "pr-wrong-app" and "aaaaaaaa" in n: j["check_runs"][0]["app"]["id"] = 99
    if mode == "pr-no-check" and "aaaaaaaa" in n: j["check_runs"] = []
    if mode == "status-only" and "check-runs" in n and "aaaaaaaa" not in n: j["check_runs"] = []
    json.dump(j, open(f, "w"))
PY
}
for m in "no-push|a push-scoped check missing on the tagged commit|ci" "wrong-app|a check from another app than the pinned integration|ci" "failed|a failed push-scoped check|ci" \
         "no-pr|a pull_request-scoped check with no merged pull request|review" "pr-mismatch|a pull request whose merge commit is not this commit|review" \
         "pr-not-main|a merged pull request whose base is not main|review" "pr-unmerged|a pull request that is not merged|review" \
         "pr-red|a pull_request-scoped check red on the PR head|review" "pr-wrong-app|a pull_request-scoped check from another app|review" \
         "pr-no-check|a pull_request-scoped check missing on the PR head|review" "status-only|only a green commit status (statuses never satisfy a pinned check)|ci"; do
  IFS='|' read -r mode label ctx <<< "$m"; fresh; edit_gh "$mode"; run_admit; expect_refuse "AC4 required-checks: $label is refused and names the check" required-checks "$ctx"
done
fresh; (cd "$W/c/repo" && G checkout -q main && python3 - <<'PY'
import json
p = ".github/policy/required-checks.json"; d = json.load(open(p)); d["required_checks"].append({"context": "x", "integration_id": 1, "scope": "weekly"}); json.dump(d, open(p, "w"))
PY
G add -A; G -c user.signingkey="$W/keys/owner" commit -q -S -m "policy: unknown scope"; G push -q origin main 2> /dev/null; G fetch -q origin; G checkout -q --detach v0.3.0); run_admit
expect_refuse "AC4 required-checks: an unknown scope in main's policy is a policy error and refuses" required-checks scope
fresh; run_admit; python3 - "$W/c/repo/admission.json" <<'PY' 2> /dev/null && ok "AC4 required-checks: commit statuses are recorded as information only" || bad "AC4 informational statuses not recorded"
import json, sys
d = json.load(open(sys.argv[1])); assert d["informational_statuses"] and all(c["conclusion"] == "success" for c in d["required_checks"])
PY
# ---- baseline -------------------------------------------------------------------------------------------------------------------------------
base_edit() { # base_edit PYCODE : edit requirements/releases/v0.3.0.yaml on main, re-sign, re-tag
  (cd "$W/c/repo" && G checkout -q main && python3 - "$1" <<'PY'
import sys, yaml
p = "requirements/releases/v0.3.0.yaml"; d = yaml.safe_load(open(p)); d["approved_on"] = str(d["approved_on"]); exec(sys.argv[1]); yaml.safe_dump(d, open(p, "w"))
PY
  G add -A; G -c user.signingkey="$W/keys/owner" commit -q -S -m "baseline edit"; G push -q origin main 2> /dev/null; G fetch -q origin; retag owner); gh_fixtures "$W/c/gh" "$(G rev-parse HEAD)"; }
fresh; G checkout -q main; G rm -q requirements/releases/v0.3.0.yaml; G -c user.signingkey="$W/keys/owner" commit -q -S -m "no baseline"; G push -q origin main 2> /dev/null; G fetch -q origin; retag owner; gh_fixtures "$W/c/gh" "$(G rev-parse HEAD)"; run_admit
expect_refuse "AC4 a release with no frozen baseline file is refused" baseline "v0.3.0.yaml"
fresh; base_edit 'd["approved"] = False'; run_admit;               expect_refuse "AC4 a baseline that is not approved (boolean true) is refused" baseline approved
fresh; base_edit 'd["approved"] = "true"'; run_admit;              expect_refuse "AC4 a baseline whose approved is the string 'true' is refused" baseline approved
fresh; base_edit 'd["version"] = "v0.2.9"'; run_admit;             expect_refuse "AC4 a baseline for another version is refused" baseline version
fresh; base_edit 'd["approved_on"] = "soon"'; run_admit;           expect_refuse "AC4 a baseline with no real approval date is refused" baseline approved_on
fresh; base_edit 'd["release_blocking_acs"] = []'; run_admit;      expect_refuse "AC4 an empty required set is not a baseline" baseline release_blocking_acs
fresh; run_admit FAKE_GO_RC=1;                                     expect_refuse "AC4 a baseline that fails the requirements tool's freeze check is refused" baseline freeze
fresh; run_admit; if grep -q 'go -C tools/requirements run . verify-freeze v0.3.0' "$W/c/calls.log" 2> /dev/null && grep -q 'GOTOOLCHAIN=local' "$W/c/calls.log"; then ok "AC4 the freeze check is exactly go -C tools/requirements run . verify-freeze <tag> with GOTOOLCHAIN=local"; else bad "AC4 the freeze check call is not the pinned one: $(grep -E 'go |GOTOOLCHAIN' "$W/c/calls.log" 2> /dev/null | head -3 | tr '\n' ' ')"; fi
# the ACs baseline of a CI patch (REQ-REL-009-AC13) goes through bin/admission-tag-signer.py baseline: its own tests and cache's auto-baseline PR
# cover the rules; here only that a patch tag with no owner-approved baseline of its line is refused (the owner-baselines route fails closed)
fresh; patch_tag v0.3.1; run_admit GITHUB_REF=refs/tags/v0.3.1 GITHUB_REF_NAME=v0.3.1 FAKE_GITSIGN_RC=0
expect_refuse "AC4 a patch tag cannot reach the baseline check with fabricated signer evidence (it stops earlier)" tag-signature
# ---- nothing built on a refusal; the script is the only reader of the checks ----------------------------------------------------------------
TOTAL=$((pass + failn))
echo "pass=$pass fail=$failn"
# the case count is fixed by the number of expect_ok/expect_refuse calls plus the unit cases: when the script is missing every case must
# still be COUNTED (a missing script must not shrink the suite)
EXPECT_TOTAL=86
if [ "$TOTAL" != "$EXPECT_TOTAL" ]; then echo "FAIL case count $TOTAL != expected $EXPECT_TOTAL (a case was skipped or added)"; exit 1; fi
[ "$failn" = 0 ]
