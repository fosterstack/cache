"""Arms the runtime guard (fs_guard) before any other test module is imported.

unittest discovery imports test_*.py in sorted order and a module's top-level code runs at import, so a guard armed by test_fs_guard.py would
miss the import-time code of every module that sorts before it. Digits sort before letters, so this module is imported first; it defines no
tests. test_fs_guard.py proves that it sorts first and that an early and a late module are both guarded (REQ-AUD-019-AC1)."""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fs_guard  # noqa: E402

fs_guard.install()
