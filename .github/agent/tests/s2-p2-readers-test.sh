#!/usr/bin/env bash
# proves: REQ-SUP-001-AC5
# cache#359 round 5, section 2, group P2, row "working-tree readers": tree_files, tree_scripts and tree_surfaces of
# pin-inventory.py (rev None = the working tree)
#   (1) skip a tracked symbolic link (the kernel-lock path already refuses one), whatever it points at;
#   (2) read at most MAX_FILE+1 bytes of a file before the size check (a file that never ends must not be read whole);
#   (3) every git / cat-file child is started with a timeout;
#   (4) tree_files reads nothing under .github/agent/tests/ (fixtures are not inventory), the other agent folders still are.
# Written from the English rows only; in-process against pin-inventory.py.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
export SC="$here/../supply-chain"
work=$(mktemp -d -t s2p2-read.XXXXXX); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
ok()  { pass=$((pass+1)); echo "ok   $1"; }
bad() { failn=$((failn+1)); echo "FAIL $1"; }
CASE=""
check() {
  if timeout 120 "$@" >"$work/last.out" 2>&1; then
    ok "$CASE"
  else
    bad "$CASE"
    sed 's/^/     | /' "$work/last.out" | tail -5
  fi
}
cat >"$work/pre.py" <<'PY'
import importlib.util, os, subprocess, sys, threading
D = os.environ["SC"]
def load(n):
    s = importlib.util.spec_from_file_location(n.replace("-", "_") + "_t", os.path.join(D, n + ".py"))
    m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
inv = load("pin-inventory")
def sh(root, *a):
    subprocess.run(["git", "-C", root, "-c", "user.name=t", "-c", "user.email=t@x", *a],
                   check=True, capture_output=True)
def repo(root, files, links=()):
    os.makedirs(root)
    for n, t in files.items():
        os.makedirs(os.path.dirname(os.path.join(root, n)), exist_ok=True); open(os.path.join(root, n), "w").write(t)
    for n, target in links:
        os.makedirs(os.path.dirname(os.path.join(root, n)), exist_ok=True); os.symlink(target, os.path.join(root, n))
    sh(root, "init", "-q"); sh(root, "add", "-A"); sh(root, "commit", "-q", "-m", "x")
def endless(path, total=20_000_000):
    """Replace the tracked file `path` with a FIFO fed by a thread;
    the thread records how many bytes the reader took."""
    os.unlink(path); os.mkfifo(path); got = {"n": 0}
    def feed():
        try:
            fd = os.open(path, os.O_WRONLY)
        except OSError:
            return
        try:
            chunk = b"x" * 4096
            while got["n"] < total:
                got["n"] += os.write(fd, chunk)
        except (BrokenPipeError, OSError):
            pass
        finally:
            os.close(fd)
    t = threading.Thread(target=feed, daemon=True); t.start()
    return got, t
PY

# --- (1) symbolic links are skipped -----------------------------------------------------------------------------------
echo secret >"$work/outside.txt"
CASE="tree_files (working tree): a tracked symlink to a workflow-shaped path is not read (a regular file "
CASE+="beside it still is)"
check python3 - "$work/pre.py" "$work" <<'PY'
import sys; exec(open(sys.argv[1]).read())
r = sys.argv[2] + "/r1"
repo(r, {".github/workflows/ci.yml": "on: push\n", "bin/real.sh": "echo hi\n"},
     [(".github/workflows/linked.yml", "ci.yml"), ("bin/link.sh", "real.sh"),
     ("bin/out.sh", sys.argv[2] + "/outside.txt")])
got = inv.tree_files(r, None)
assert ".github/workflows/ci.yml" in got and "bin/real.sh" in got, sorted(got)
assert not [n for n in got if n in (".github/workflows/linked.yml", "bin/link.sh", "bin/out.sh")], sorted(got)
PY
CASE="tree_scripts (working tree): a tracked .sh symlink (inside or outside the tree) is not read"
check python3 - "$work/pre.py" "$work" <<'PY'
import sys; exec(open(sys.argv[1]).read())
r = sys.argv[2] + "/r2"
repo(r, {"bin/real.sh": "echo hi\n"}, [("bin/link.sh", "real.sh"), ("bin/out.sh", sys.argv[2] + "/outside.txt")])
got = inv.tree_scripts(r, None)
assert "bin/real.sh" in got and "bin/link.sh" not in got and "bin/out.sh" not in got, sorted(got)
PY
CASE="tree_surfaces (working tree): a tracked symlink named like a python helper, Makefile or Dockerfile is not read"
check python3 - "$work/pre.py" "$work" <<'PY'
import sys; exec(open(sys.argv[1]).read())
r = sys.argv[2] + "/r3"
repo(r, {"tools/real.py": "x = 1\n", "Makefile": "all:\n"},
     [("tools/link.py", "real.py"), ("Dockerfile", sys.argv[2] + "/outside.txt")])
got = inv.tree_surfaces(r, None)
assert "tools/real.py" in got and "Makefile" in got, sorted(got)
assert "tools/link.py" not in got and "Dockerfile" not in got, sorted(got)
PY
CASE="a symlink to a HUGE or endless file (/dev/zero) is skipped at once by all three readers, not read"
check python3 - "$work/pre.py" "$work" <<'PY'
import sys; exec(open(sys.argv[1]).read())
r = sys.argv[2] + "/r4"
repo(r, {"bin/real.sh": "echo hi\n"},
     [("bin/zero.sh", "/dev/zero"), ("tools/zero.py", "/dev/zero"), (".github/workflows/zero.yml", "/dev/zero")])
for f in (inv.tree_files, inv.tree_scripts, inv.tree_surfaces):
    got = f(r, None)
    assert not [n for n in got if "zero" in n], (f.__name__, sorted(got))
PY

# --- (2) at most MAX_FILE+1 bytes are read ----------------------------------------------------------------------------
big_cases=("tree_files:.github/workflows/ci.yml:on: push" "tree_scripts:bin/big.sh:echo hi"
           "tree_surfaces:tools/big.py:x = 1")
for fn in "${big_cases[@]}"; do
  f=${fn%%:*}; rest=${fn#*:}; path=${rest%%:*}; txt=${rest#*:}
  CASE="$f (working tree): a file that never ends is read for at most MAX_FILE+1 bytes "
  CASE+="(the reader stops; it is refused or skipped, never read whole)"
  check python3 - "$work/pre.py" "$work/fifo-$f" "$f" "$path" "$txt" <<'PY'
import sys; exec(open(sys.argv[1]).read())
r, fn, path, txt = sys.argv[2:6]
repo(r, {path: txt + "\n"})
inv.MAX_FILE = 200_000
got, t = endless(r + "/" + path)
try:
    getattr(inv, fn)(r, None)
except RuntimeError as e:
    assert "too large" in str(e) or "large" in str(e) or "size" in str(e), str(e)
t.join(20)
assert got["n"] <= inv.MAX_FILE + 1 + 262144, (
    "the reader took %d bytes of an endless file (cap %d)" % (got["n"], inv.MAX_FILE))
PY
done
CASE="a regular file over MAX_FILE is still refused with 'too large' (tree_files, working tree)"
check python3 - "$work/pre.py" "$work" <<'PY'
import sys; exec(open(sys.argv[1]).read())
r = sys.argv[2] + "/r5"
repo(r, {"bin/x.sh": "echo hi\n"})
inv.MAX_FILE = 1000
open(r + "/bin/x.sh", "w").write("# " + "a" * 5000 + "\n")
try: inv.tree_files(r, None)
except RuntimeError as e: assert "too large" in str(e), str(e)
else: raise SystemExit("an oversize file was read")
PY

# --- (3) git and cat-file have a timeout ------------------------------------------------------------------------------
CASE="every git / cat-file child of the readers (git(), tree_files, tree_scripts, tree_surfaces; working "
CASE+="tree and a revision) is started with a timeout"
check python3 - "$work/pre.py" "$work" <<'PY'
import sys; exec(open(sys.argv[1]).read())
r = sys.argv[2] + "/r6"
repo(r, {".github/workflows/ci.yml": "on: push\n", "bin/x.sh": "echo hi\n", "tools/a.py": "x = 1\n",
         "build/locks/vm-kernel.lock": "linux-virt=6.18.60-r0 sha256:" + "a" * 64 + "\n"})
calls = []
real = subprocess.run
def spy(cmd, *a, **kw):
    calls.append((cmd, kw.get("timeout")))
    return real(cmd, *a, **kw)
inv.subprocess.run = spy
for rev in (None, "HEAD"):
    inv.tree_files(r, rev); inv.tree_scripts(r, rev); inv.tree_surfaces(r, rev)
inv.git(r, "status")
assert calls, "the spy saw no child"
missing = [c for c, t in calls if not isinstance(t, (int, float)) or t <= 0]
assert not missing, missing[:3]
PY
# --- (4) the selector leaves out everything under .github/agent/tests/ (fixtures are not inventory) ------------------
for rev in None '"HEAD"'; do
  for fn in tree_files; do
    CASE="$fn (rev $rev): a .sh, .yml, action.yml or .py under .github/agent/tests/ is not read, while the same files under "
    CASE+=".github/agent/bin/ and .github/agent/supply-chain/ are"
    check python3 - "$work/pre.py" "$work/t-$fn-${rev//\"/}" "$fn" "$rev" <<'PY'
import sys; exec(open(sys.argv[1]).read())
r, fn, rev = sys.argv[2], sys.argv[3], eval(sys.argv[4])
T, B, S = ".github/agent/tests/", ".github/agent/bin/", ".github/agent/supply-chain/"
files = {}
for d in (T, B, S):
    files[d + "fx.sh"] = "go install example.org/t@v1.2.3\n"
    files[d + "fx.py"] = "x = 1\n"
    files[d + "sub/fx.sh"] = "echo hi\n"
files[T + "wf.yml"] = "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
files[T + "sub/action.yml"] = "name: x\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: echo hi\n"
files[T + "sub/action.yaml"] = files[T + "sub/action.yml"]
files[".github/agent/tests-other/fx.sh"] = "echo hi\n"
repo(r, files)
got = getattr(inv, fn)(r, rev)
under = sorted(n for n in got if n.startswith(T))
assert not under, ("read under the tests folder", under)
for d in (B, S):
    assert d + "fx.sh" in got and d + "sub/fx.sh" in got, (d, sorted(got))
assert ".github/agent/tests-other/fx.sh" in got, ("a sibling folder named like it is not the tests folder", sorted(got))
PY
  done
done
CASE="tree_files: an action.yml under .github/agent/tests/ gives no inventory item (the inventory of the tree holds none of its steps)"
check python3 - "$work/pre.py" "$work/t-inv" <<'PY'
import sys; exec(open(sys.argv[1]).read())
r = sys.argv[2]
repo(r, {".github/agent/tests/a/action.yml": "name: x\nruns:\n  using: composite\n  steps:\n    - uses: actions/checkout@" + "1" * 40 + " # v4\n",
         ".github/agent/tests/t.sh": "go install example.org/t@v1.2.3\n",
         ".github/agent/tests/w.yml": "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: pip install requests\n"})
for rev in (None, "HEAD"):
    got = inv.inventory(inv.tree_files(r, rev))
    assert not got, (rev, sorted(got))
PY

echo "s2-p2-readers: $pass ok, $failn failed"
[ "$failn" -eq 0 ]
