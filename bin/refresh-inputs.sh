#!/usr/bin/env bash
# The scheduled input refresh (REQ-REFRESH-001; rules 44-49 and 73 of the v0.3.0 rules).
#
#   refresh-inputs.sh refresh     --repo-dir DIR --archive DIR
#   refresh-inputs.sh fips-module --go-root DIR  --repo-dir DIR
#
# This job is the only updater of image recipes, apk packages and lock files: Dependabot does not watch them (rule 45).
#
# refresh (daily, rule 44): compare the live Wolfi signing key to the archived one first (rules 32, 46: a difference
#   stops the job for a human, exit 3, no PR); re-make the image lock files and re-resolve melange's build tools against
#   live Wolfi; archive each NEW package by digest (verified against the lock's checksums before anything is kept, rule
#   48: no waiting period, signature and checksum checks still apply); update the base locks (archive paths) and the
#   melange lock and recipe pins; resolve and lock the host tools too (build/host-tools.yaml -> build/locks/host-tools.lock, REQ-REFRESH-001-AC35); if anything changed, push a branch and open a PR, never merge it and never push to
#   main (rule 49: the PR goes through every normal check). An old version that disappears from live Wolfi is noted, not
#   an error: the archive is the source of truth (rule 47). Nothing changed: nothing is committed, pushed or opened.
# fips-module (daily, rule 73; the daily job runs it after `refresh`): read the Go toolchain's own lib/fips140/certified.txt; if it names a newer certified
#   module than build/melange-fips.yaml builds, move the recipe to it and open a PR. A missing, empty or unreadable file
#   fails closed.
#
# The checks and the files are made by bin/refresh-inputs.py; this script runs the tools, the downloads and the git and gh calls.
#
# Exit codes: 0 ok (changed or not), 1 verification failed, 2 refused (bad input), 3 the Wolfi signing key changed.
# The git identity is the caller's (the workflow job sets it); this script never sets one and never skips a hook.
set -euo pipefail

WOLFI=https://packages.wolfi.dev/os
SELF=refresh-inputs.sh

# ---- fixed locations (REQ-REFRESH-001-AC23): every call names its tool by the literal fixed path (the fetch tool and git, gh,
# /usr/local/bin/apko, /usr/bin/openssl, /usr/bin/python3, /usr/bin/cmp, /usr/bin/mktemp, /bin/rm, /bin/mkdir), never through the caller's search path,
# and there is no test hook in this file: bin/refresh-inputs-test.sh runs a COPY that differs from this file only in occurrences of those ten paths,
# each replaced one for one by a dispatcher.
case $0 in */*) HERE=${0%/*} ;; *) HERE=. ;; esac   # this script's directory, without dirname
dir_empty() { local e; for e in "$1"/* "$1"/.[!.]* "$1"/..?*; do { [ -e "$e" ] || [ -L "$e" ]; } && return 1; done; return 0; }   # no ls
PY=$HERE/refresh-inputs.py   # every check and every file the job makes is in this program (python3 -I -B "$PY" MODE REPO ...)
slug=${GITHUB_REPOSITORY:-fosterstack/cache}   # the one repository identity: the commit is created on it and its verification is asked of it

die() { echo "$SELF: $1" >&2; exit "${2:-2}"; }

usage() {
  printf '%s\n' "$SELF: usage:" \
    "  $SELF refresh --repo-dir DIR --archive DIR --pr-author NAME [--plan-dir DIR]" \
    "  $SELF fips-module --go-root DIR --repo-dir DIR --pr-author NAME [--plan-dir DIR]" \
    "  $SELF open-pr --plan-dir DIR --repo-dir DIR [--pr-author NAME] [--archive DIR --archive-digest sha256:HEX]" \
    "  $SELF bootstrap --repo-dir DIR --archive DIR" \
    "  $SELF key-check --repo-dir DIR" \
    "  $SELF archive-key-check --repo-dir DIR --archive DIR" >&2
  exit 2
}

# open_pr BRANCH TITLE BODY PATH...: branch, commit, push the branch (never main), open the PR (never merge it)
# REQ-REFRESH-001-AC34: every planned path must be a regular file of the repository, checked before any branch is pushed; the commit builder and the
# restoration after the commit rely on this one check
check_paths() { /usr/bin/python3 -I -B "$PY" check-paths "$repo" "$@"; }
# REQ-REFRESH-001-AC34: the pull request's commit through the API. $1 branch (already pushed), $2 the commit it points at, $3 headline, $4 body, then the repository paths.
signed_commit() {
  local branch=$1 base=$2 headline=$3 cbody=$4 oid ver; shift 4
  /usr/bin/python3 -I -B "$PY" commit-input "$repo" "$slug" "$tmp/commit-input.json" "$branch" "$base" "$headline" "$cbody" "$@" || return 1
  oid=$(cd "$repo" && /usr/bin/gh api graphql --input "$tmp/commit-input.json" -q '.data.createCommitOnBranch.commit.oid') \
    || { echo "refresh-inputs.sh: the API could not create the commit on $branch; opening no pull request" >&2; return 1; }
  case $oid in *[!0-9a-f]*|'') echo "refresh-inputs.sh: the API returned no commit id; opening no pull request" >&2; return 1;; esac
  [ "${#oid}" -eq 40 ] || { echo "refresh-inputs.sh: the API returned no commit id; opening no pull request" >&2; return 1; }
  ver=$(cd "$repo" && /usr/bin/gh api "repos/$slug/commits/$oid" -q '.commit.verification.verified') \
    || { echo "refresh-inputs.sh: could not ask whether commit $oid is verified; opening no pull request" >&2; return 1; }
  [ "$ver" = true ] || { echo "refresh-inputs.sh: commit $oid on $branch is not verified by GitHub (main requires signed commits); opening no pull request" >&2; return 1; }
  echo "signed commit $oid on $branch (verified by GitHub)"
}
open_pr() {
  local branch=$1 title=$2 body=$3; shift 3
  if [ -n "$plan_dir" ] && [ "$cmd" != open-pr ]; then   # staged: the pull request is written down and opened later by `open-pr`, once the archive is stored (rules 6 and 7)
    local seq pd
    /bin/mkdir -p "$plan_dir" || die "could not create $plan_dir" 1
    seq=1; for _e in "$plan_dir"/*; do [ -e "$_e" ] && seq=$((seq+1)); done; pd=$plan_dir/$seq-$cmd
    /bin/mkdir -p "$pd" && printf '%s\n' "$branch" >"$pd/branch" && printf '%s\n' "$title" >"$pd/title" && printf '%s\n' "$body" >"$pd/body" \
      && printf '%s\n' "$@" >"$pd/paths" || die "could not write the plan to $plan_dir" 1
    echo "planned: $branch (opened later by open-pr)"
    return 0
  fi
  # Asked again immediately before the branch is created: two overlapping runs can both have passed the staging check (REQ-REFRESH-001-AC29). Only a
  # pull request of this repository counts; the list not being readable stops the job (an unknown state is not "no pull request").
  local _rc=0
  /usr/bin/python3 -I -B "$PY" guard "$repo" "$pr_author" "$branch" || _rc=$?
  [ "$_rc" != 4 ] || return 0
  [ "$_rc" = 0 ] || exit "$_rc"
  local base=$branch n=1
  # a branch name already taken on the remote (a closed or merged PR) gets a -2, -3, ... suffix instead of a failed push
  while [ -n "$(/usr/bin/git -C "$repo" ls-remote --heads origin "refs/heads/$branch" 2>/dev/null)" ]; do
    n=$((n+1)); [ $n -le 9 ] || die "the branch name $base and its numbered variants are all taken on the remote" 1
    branch=$base-$n
  done
  local startbr startsha rc=0 pushed=
  startbr=$(/usr/bin/git -C "$repo" rev-parse --abbrev-ref HEAD 2>/dev/null || true)
  startsha=$(/usr/bin/git -C "$repo" rev-parse HEAD 2>/dev/null || true)
  # REQ-REFRESH-001-AC34: main requires signed commits, so the one commit is made through the API (GitHub signs what the job's App token creates), on a branch that was
  # pushed at the commit the job started from (nothing new to sign locally); the pull request is opened only for a commit the API reports as verified
  { [ -n "$startsha" ] && check_paths "$@" && /usr/bin/git -C "$repo" checkout -b "$branch" \
    && { PENDING_BRANCH=$branch; /usr/bin/git -C "$repo" push -q origin "$branch" || { PENDING_BRANCH=; false; }; } && pushed=1 \
    && signed_commit "$branch" "$startsha" "$title" "$body" "$@" \
    && (cd "$repo" && /usr/bin/gh pr create --base main --head "$branch" --title "$title" --body "$body"); } || rc=$?
  if [ "$rc" = 0 ]; then PENDING_BRANCH=; elif [ -n "$pushed" ]; then PENDING_BRANCH=; drop_branch "$branch"; fi   # no half-made branch is left behind, and a failed deletion is reported
  # the commit was made through the API, so the files the job edited are still in the working tree: put them back to the start commit (a later invocation in the same
  # checkout must see the start state, as it did when the edits were committed to the branch)
  if [ -n "$startsha" ] && check_paths "$@" 2>/dev/null; then   # only paths that passed the check are touched: a refused path (.git, a link, an outside file) is never restored or removed
    for _p in "$@"; do
      if /usr/bin/git -C "$repo" ls-files --error-unmatch -- "$_p" >/dev/null 2>&1; then /usr/bin/git -C "$repo" checkout -q "$startsha" -- "$_p" || { echo "refresh-inputs.sh: could not restore $_p to $startsha" >&2; rc=1; }
      else /bin/rm -f -- "$repo/$_p" || { echo "refresh-inputs.sh: could not remove $_p" >&2; rc=1; }; fi
    done
  fi
  # back to where the job started, whether or not a step failed: a later step of the same job (the FIPS check) must not branch from this commit.
  # A detached start is restored by its commit.
  if [ -n "$startbr" ] && [ "$startbr" != HEAD ]; then /usr/bin/git -C "$repo" checkout -q "$startbr" || { echo "refresh-inputs.sh: could not go back to $startbr; a later step would branch from the refresh commit" >&2; rc=1; }
  elif [ -n "$startsha" ]; then /usr/bin/git -C "$repo" checkout -q --detach "$startsha" || { echo "refresh-inputs.sh: could not go back to $startsha; a later step would branch from the refresh commit" >&2; rc=1; }; fi
  return $rc
}

cmd=${1:-}; [ -n "$cmd" ] || usage; shift
repo= archive= goroot= pr_author= plan_dir= archive_digest=
while [ $# -gt 0 ]; do
  case $1 in
    --repo-dir) [ $# -ge 2 ] || usage; repo=$2; shift 2;;
    --archive) [ $# -ge 2 ] || usage; archive=$2; shift 2;;
    --go-root) [ $# -ge 2 ] || usage; goroot=$2; shift 2;;
    --pr-author) [ $# -ge 2 ] || usage; pr_author=$2; shift 2;;
    --plan-dir) [ $# -ge 2 ] || usage; plan_dir=$2; shift 2;;
    --archive-digest) [ $# -ge 2 ] || usage; archive_digest=$2; shift 2;;
    *) die "unknown argument: $1";;
  esac
done
[ -n "$repo" ] && [ -d "$repo" ] || die "--repo-dir must be an existing directory"
case $cmd in key-check) [ -z "$archive$goroot$pr_author$plan_dir$archive_digest" ] || die "key-check takes only --repo-dir";; esac
case $cmd in archive-key-check) { [ -n "$archive" ] && [ -d "$archive" ]; } || die "archive-key-check needs --archive (the pulled or seeded archive)"; [ -z "$goroot$pr_author$plan_dir$archive_digest" ] || die "archive-key-check takes only --repo-dir and --archive";; esac
case $cmd in refresh|fips-module) [ -n "$pr_author" ] || die "--pr-author is required (the Auditor App's name; gh reports it as app/<name>, both spellings are accepted): without it a stranger's pull request on a refresh/ branch could be counted";; esac

case $cmd in refresh|fips-module|open-pr)
  case $slug in
    */*/*|/*|*/|*[!A-Za-z0-9_./-]*) die "GITHUB_REPOSITORY is not owner/name: $slug";;
    */*) ;;
    *) die "GITHUB_REPOSITORY is not owner/name: $slug";;
  esac;;
esac

tmp=$(/usr/bin/mktemp -d)
PENDING_BRANCH=
drop_branch() { /usr/bin/git -C "$repo" push -q origin --delete "$1" >/dev/null 2>&1 || echo "refresh-inputs.sh: could not delete the branch $1 from the remote; delete it by hand" >&2; }
# a signal can arrive after `gh pr create` succeeded and before PENDING_BRANCH is cleared: the branch of a live pull request is never deleted (deleting it would close the PR); if the
# open pull requests of the branch cannot be read the branch is kept too (a leftover branch is harmless, a closed pull request is not)
drop_unless_pr() {
  local n
  n=$(cd "$repo" && /usr/bin/gh pr list --state open --head "$1" --json number -q length 2>/dev/null) || n=unknown
  if [ "$n" = 0 ]; then drop_branch "$1"; else echo "refresh-inputs.sh: kept the branch $1: it has an open pull request, or its pull requests could not be read ($n)" >&2; fi
}
cleanup() { local rc=$?; set +e; [ -z "$PENDING_BRANCH" ] || drop_unless_pr "$PENDING_BRANCH"; /bin/rm -rf "$tmp" 2>/dev/null || true; exit $rc; }   # cleanup never changes the exit status; a branch pushed for a pull request that was not opened (an interrupted run) is removed
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

case $cmd in
archive-key-check)
  # After the archive is pulled or seeded and before the App token is minted: the live Wolfi signing key must be the pinned key AND the key the archive
  # holds (keys/wolfi-signing.rsa.pub); the stop then precedes every later step also when the archive carries another key (rule 6, AC30). A difference, a missing or a repeated line stops for a human (exit 3, rule 6); nothing is written.
  /usr/bin/curl -q -fsSL -g --max-filesize 65536 --max-time 60 --proto =https --tlsv1.2 -o "$tmp/live-key.pub" https://packages.wolfi.dev/os/wolfi-signing.rsa.pub || die "could not fetch the live Wolfi signing key" 1
  /usr/bin/python3 -I -B "$PY" archive-key-check "$repo" "$tmp/live-key.pub" "$archive" || exit $?
  ;;
key-check)
  # The first step of the daily job, before any tool is installed, any registry is touched or any token is minted: the live Wolfi signing key must be
  # the key pinned in build/locks/archive-keys.sha256. A difference, a missing or a repeated line stops for a human (exit 3, rule 6); nothing is written.
  /usr/bin/curl -q -fsSL -g --max-filesize 65536 --max-time 60 --proto =https --tlsv1.2 -o "$tmp/live-key.pub" https://packages.wolfi.dev/os/wolfi-signing.rsa.pub || die "could not fetch the live Wolfi signing key" 1
  /usr/bin/python3 -I -B "$PY" key-check "$repo" "$tmp/live-key.pub" || exit $?
  ;;

bootstrap)
  # The archive does not exist yet (build/archive.json is absent on main). The one trust anchor is the key line committed in
  # build/locks/archive-keys.sha256: the live Wolfi key is fetched, its sha256 must be that line, and only then is it the new archive's
  # key. A missing or repeated line, or a different key, stops for a human (exit 3): there is no trust on first use.
  [ -n "$archive" ] || die "--archive is required"
  if [ -e "$archive" ] || [ -L "$archive" ]; then
    { [ -d "$archive" ] && [ ! -L "$archive" ] && dir_empty "$archive"; } || die "$archive already exists and is not an empty directory: bootstrap never touches an existing archive" 2
  fi
  /usr/bin/curl -q -fsSL -g --max-filesize 65536 --max-time 60 --proto =https --tlsv1.2 -o "$tmp/live-key.pub" https://packages.wolfi.dev/os/wolfi-signing.rsa.pub || die "could not fetch the live Wolfi signing key" 1
  /usr/bin/python3 -I -B "$PY" bootstrap "$repo" "$tmp/live-key.pub" "$archive" || exit $?
  ;;

open-pr)
  # Opens the pull requests that `refresh` / `fips-module --plan-dir` staged, after the archive was stored. The refresh pull request also carries
  # build/archive.json, the pointer naming the stored digest (advisor 0440 (3)). Nothing is opened unless every plan validates first.
  [ -n "$plan_dir" ] && [ -d "$plan_dir" ] || die "--plan-dir must be an existing directory"
  if [ -n "$archive_digest" ]; then
    { [ "${archive_digest#sha256:}" != "$archive_digest" ] && [ "${#archive_digest}" -eq 71 ]; } || die "--archive-digest must be sha256:<64 hex>"
    case ${archive_digest#sha256:} in *[!0-9a-f]*) die "--archive-digest must be sha256:<64 lower-case hex>";; esac
    [ -n "$archive" ] && [ -d "$archive" ] || die "--archive is required with --archive-digest"
  fi
  /usr/bin/python3 -I -B "$PY" open-pr-plan "$repo" "$plan_dir" "$archive" "$archive_digest" "$tmp" || exit $?
  nc=0; read -r nc <"$tmp/ncount" 2>/dev/null || nc=0
  [ "$nc" != 0 ] || exit 0
  # the validated plans, one open_pr each, in plan order
  n=$nc; i=1; rc_all=0
  while [ "$i" -le "$n" ]; do
    paths=(); while IFS= read -r l; do [ -n "$l" ] && paths+=("$l"); done <"$tmp/p$i.paths"
    open_pr "$(<"$tmp/p$i.branch")" "$(<"$tmp/p$i.title")" "$(<"$tmp/p$i.body")" "${paths[@]}" || rc_all=1
    i=$((i+1))
  done
  exit $rc_all
  ;;

refresh)
  [ -n "$archive" ] && [ -d "$archive" ] || die "--archive must be an existing directory"
  archived_key=$archive/keys/wolfi-signing.rsa.pub
  [ -x /usr/bin/openssl ] || die "openssl is required to verify the package index signature and was not found (/usr/bin/openssl)"
  [ -s "$archived_key" ] || die "the archive has no Wolfi signing key at keys/wolfi-signing.rsa.pub"

  # REQ-REFRESH-001-AC39 to AC42: the lists, locks and the kernel row are read whole
  # before the first network call of the run
  for f in build/apko.yaml build/apko-fips.yaml build/melange.yaml build/melange-fips.yaml build/locks/apko.base.lock.json \
           build/locks/apko-fips.base.lock.json build/locks/melange.lock build/melange.yaml.tmpl build/locks/fips-module.txt build/host-tools.yaml build/locks/host-tools.lock; do
    [ -f "$repo/$f" ] || die "missing $f in $repo"
  done
  for f in build/vm-host.yaml build/vm-guest.yaml build/locks/vm-host.lock build/locks/vm-guest.lock \
           build/locks/vm-kernel.lock build/vm-keys/kernel-key-6165ee59.rsa.pub; do
    [ -f "$repo/$f" ] || die "missing $f in $repo"
  done

  /bin/mkdir -p "$tmp/host" "$tmp/vm-host" "$tmp/vm-guest"
  /usr/bin/python3 -I -B "$PY" prepare "$repo" "$tmp" || exit $?

  # rules 32 and 46: every run, before anything else, compare the live key to the archived one
  /usr/bin/curl -q -fsSL -g --max-filesize 65536 --max-time 60 --proto =https --tlsv1.2 -o "$tmp/live-key.pub" https://packages.wolfi.dev/os/wolfi-signing.rsa.pub || die "could not fetch the live Wolfi signing key" 1
  # the live key's sha256 must be the one pinned in build/locks/archive-keys.sha256, checked right after the fetch and before the key is used for anything
  /usr/bin/python3 -I -B "$PY" pinned-key "$repo" "$tmp/live-key.pub" || exit $?
  if ! /usr/bin/cmp -s "$tmp/live-key.pub" "$archived_key"; then
    echo "$SELF: the live Wolfi signing key differs from the archived one; stopping, no pull request, a human must decide whether to trust the new key" >&2
    exit 3
  fi

  # configs that resolve against live Wolfi: no local repositories or keys, and not our own apk (the base lock holds none)
  /bin/mkdir -p "$tmp/production" "$tmp/fips" "$tmp/melange"
  /usr/bin/python3 -I -B "$PY" configs "$repo" "$tmp"
  lock() { /usr/local/bin/apko lock --arch x86_64,aarch64 --repository-append "$WOLFI" --keyring-append "$archived_key" --output "$2" "$1"; }
  lock "$tmp/production/apko.yaml" "$tmp/production.lock.json"
  lock "$tmp/fips/apko-fips.yaml" "$tmp/fips.lock.json"
  lock "$tmp/melange/melange-env.yaml" "$tmp/melange.lock.json"
  lock "$tmp/host/host-tools-env.yaml" "$tmp/host-tools.lock.json"
  lock_x86() {
    /usr/local/bin/apko lock --arch x86_64 --repository-append "$WOLFI" --keyring-append "$archived_key" \
      --output "$2" "$1"
  }
  lock_x86 "$tmp/vm-host/vm-host-env.yaml" "$tmp/vm-host.lock.json"
  lock_x86 "$tmp/vm-guest/vm-guest-env.yaml" "$tmp/vm-guest.lock.json"

  # The refresh program asks for downloads by exit status 75 and a list (`<url path> <stage file>` per line); the shell fetches them with the
  # ruled download lines below and runs the program again (it starts from the same state each time, up to five passes:
  # packages, kernel, Go, index, the rest).
  for _pass in 1 2 3 4 5; do
    _rc=0; /usr/bin/python3 -I -B "$PY" refresh "$repo" "$pr_author" "$archive" "$tmp" || _rc=$?
    [ "$_rc" = 75 ] || break
    if [ -s "$tmp/want-packages" ]; then
      while read -r p f; do
        echo "refresh-inputs.sh: fetching $p"
        /usr/bin/curl -q -fsSL -g --max-filesize 536870912 --max-time 900 --proto =https --tlsv1.2 -o "$tmp/dl/$f" "https://packages.wolfi.dev/os/$p" || die "could not download a package from live Wolfi" 1
      done <"$tmp/want-packages"
      /bin/rm -f "$tmp/want-packages"
    elif [ -s "$tmp/want-kernel" ]; then
      while read -r f; do
        echo "refresh-inputs.sh: fetching the kernel package $f"
        /usr/bin/curl -q -fsSL -g --max-filesize 268435456 --max-time 900 --proto =https --tlsv1.2 -o "$tmp/dl/x86_64/$f" "https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/$f" || die "could not download the kernel package from the Alpine mirror" 1
      done <"$tmp/want-kernel"
      /bin/rm -f "$tmp/want-kernel"
    elif [ -s "$tmp/want-go" ]; then
      while read -r f; do
        echo "refresh-inputs.sh: fetching the Go toolchain $f"
        /usr/bin/curl -q -fsSL -g --max-filesize 268435456 --max-time 900 --proto =https --tlsv1.2 -o "$tmp/dl/go/$f" "https://go.dev/dl/$f" || die "could not download a Go toolchain from go.dev" 1
      done <"$tmp/want-go"
      /bin/rm -f "$tmp/want-go"
    elif [ -s "$tmp/want-index" ]; then
      while read -r p f; do
        /usr/bin/curl -q -fsSL -g --max-filesize 268435456 --max-time 600 --proto =https --tlsv1.2 -o "$tmp/dl/$f" "https://packages.wolfi.dev/os/$p" || die "could not download the live package index" 1
      done <"$tmp/want-index"
      /bin/rm -f "$tmp/want-index"
    else
      die "the refresh program asked for downloads and named none" 1
    fi
  done
  [ "$_rc" = 0 ] || exit "$_rc"
  [ -s "$tmp/changed" ] || exit 0
  branch="refresh/$(<"$tmp/sig")"
  paths=(); while IFS= read -r l; do paths+=("$l"); done <"$tmp/changed"
  open_pr "$branch" "Refresh the image inputs against live Wolfi (daily job)" "$(<"$tmp/body")" "${paths[@]}"
  ;;

fips-module)
  [ -n "$goroot" ] || die "--go-root is required"
  # The refresh and this check edit the same recipe files in one working tree and their pull requests are opened only after the archive is stored: a
  # second plan would be built on the first one's uncommitted edits. With a plan already staged this check stages nothing and runs again tomorrow.
  # REQ-REFRESH-001-AC12 (rc-3 astra F4): the strict reading of the certified-module file and of build/locks/fips-module.txt below runs in this case too;
  # the staged case then only says pending / nothing pending and stages nothing.
  staged=0
  if [ -n "$plan_dir" ] && [ -d "$plan_dir" ] && ! dir_empty "$plan_dir"; then
    echo "fips-module: a pull request is already staged in $plan_dir; this check stages nothing now and runs again tomorrow (each pull request is built from the committed files alone)"
    staged=1
  fi
  modfile=$repo/build/locks/fips-module.txt
  [ -f "$modfile" ] || die "missing build/locks/fips-module.txt in $repo"
  [ "$staged" = 1 ] || [ -f "$repo/build/melange.yaml.tmpl" ] || die "missing build/melange.yaml.tmpl in $repo"
  /usr/bin/python3 -I -B "$PY" fips-module "$repo" "$pr_author" "$goroot" "$modfile" "$tmp" "$staged" || exit $?
  [ -s "$tmp/new" ] || exit 0
  { IFS= read -r newest; IFS= read -r cur; } <"$tmp/new"
  paths=(); while IFS= read -r l; do paths+=("$l"); done <"$tmp/paths"
  open_pr "refresh/fips-module-$newest" "Move the FIPS build to the newer certified Go Cryptographic Module $newest" \
    "The daily check found $newest in Go's own certified-module file; the FIPS build used $cur. This pull request was only opened, not merged. It goes through all the normal checks and the rebuild-from-archive test; there is no shortcut. A new certificate number is a human fact that no tool can read from Go, so this pull request cannot pass the release checks until a person also changes these files: bin/check-artifacts.sh (the GOFIPS140 value it requires), bin/check-fips.sh (the certificate note), internal/buildinfo/buildinfo.go (the module it recognises and the certificate note), internal/buildinfo/buildinfo_test.go (the certificate it expects), .github/workflows/ci.yml (the GOFIPS140 value of the fips140-only job; a workflow file, so its pin rules and review apply) and docs/install.md (the certificate it names), bin/check-govulncheck.py (the GOFIPS140 value its recipe grammar requires and sets), and the public pages that name the module or certificate: SECURITY.md, RELEASING.md, docs/offline-install.md and docs/verify-images.md; the requirement text that names the certificate (requirements/requirements.yaml, REQ-FIPS-001) is an owner-ratified rule, so a change to its words goes to the owner. Search the tree for the current module and certificate number and review every hit." \
    "${paths[@]}"
  ;;

*) usage;;
esac
