#!/usr/bin/env bash
# apko lock-file checks used by the image build (v0.3.0 rules 27, 28, 29, 33, 37, 44).
#
#   apko-lock.sh compare BASE FULL --apk NAME[,NAME...]
#       Rule 37. FULL (made at build time) must equal BASE plus our apks (the program and the base-layout package): compared by sorted package entries (name,
#       version, architecture, control/data/signature checksums); url order and the config checksum are ignored.
#       exit 0 equal | 1 differs (names the package or the arch) | 2 refused (BASE already holds one of our apks, bad input)
#   apko-lock.sh arch-check LOCK
#       Rule 33. Every package resolves to the same version on every architecture in LOCK.
#       exit 0 | 1 a package differs between architectures, or is locked for one only (names it) | 2 bad input, including a lock that does not
#       cover exactly x86_64 and aarch64
#   apko-lock.sh verify-archive --lock L --archive DIR [--melange-repo DIR]
#       Rules 27, 28, 44. Every package of L is in DIR/<arch>/<name>-<version>.apk (or, for our apk, in the melange
#       repo) and its signature, control and data sections match the lock's checksums; every repository used has its
#       APKINDEX.tar.gz. No network.   exit 0 | 1 missing, tampered or no index (names the file) | 2 bad input
#   apko-lock.sh evidence --lock L --archive DIR --out DIR
#       Rule 29. Copies L to OUT/ and writes OUT/archive-checksums.txt: a sha256sum-format list ("<hex>  <path>", paths
#       relative to DIR, byte-sorted) of every file in the archive (packages, indexes, the Wolfi key, the Go tarballs).
#       exit 0 | 1 a package of L is not in the archive (names it) or the archive is unreadable | 2 bad input
set -euo pipefail

PY3=/usr/bin/python3                 # TEST-SUBST
# the checks themselves live in bin/oci-digest.py (one committed helper, so this entry names only a literal path); run from the repository root
[ -f bin/oci-digest.py ] || { echo "apko-lock.sh: run from the repository root (bin/oci-digest.py not found)" >&2; exit 2; }
"$PY3" -I -B bin/oci-digest.py lock "$@"
