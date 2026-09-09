"""Shared fixtures: repo root and a locator for the built `ksif` binary.
The CLI build is toolchain-specific (MSVC / gcc / clang), so tests run
the binary when CI has built it and skip cleanly otherwise."""
import os

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_HERE)


@pytest.fixture(scope="session")
def repo_root():
    return _REPO_ROOT


@pytest.fixture(scope="session")
def ksif_binary():
    for name in ("ksif", "ksif.exe"):
        path = os.path.join(_REPO_ROOT, name)
        if os.path.isfile(path):
            return path
    pytest.skip("ksif not built — build with cl/gcc/clang first (built in CI)")
