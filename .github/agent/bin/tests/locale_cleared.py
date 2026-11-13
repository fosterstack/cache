"""Shared module fixtures: run a test module with no locale variable set, then restore the environment exactly.

argparse looks up translations in the system's locale directory when any locale variable is set, and the guard
refuses that read of a real system path. A test module that runs an argparse CLI imports both functions:
`from locale_cleared import setUpModule, tearDownModule  # noqa: F401`.
"""
import os
from unittest import mock

_LOCALE_VARS = ("LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG")
_ENV_PATCH = None


def setUpModule():
    global _ENV_PATCH
    _ENV_PATCH = mock.patch.dict(os.environ)
    _ENV_PATCH.start()
    for k in _LOCALE_VARS:
        os.environ.pop(k, None)


def tearDownModule():
    _ENV_PATCH.stop()
