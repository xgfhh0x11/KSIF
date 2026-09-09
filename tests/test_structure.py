"""Structure check — asserts the source tree matches the README layout.
Pure-Python; no compiler required."""
import os

import pytest

SOURCES = ["main.c", "semantic_graph.c", "observation.c", "framework.c"]
HEADERS = ["semantic_graph.h", "observation.h", "framework.h"]


@pytest.mark.parametrize("name", SOURCES)
def test_source_present(repo_root, name):
    assert os.path.isfile(os.path.join(repo_root, "src", name)), f"missing src/{name}"


@pytest.mark.parametrize("name", HEADERS)
def test_header_present(repo_root, name):
    assert os.path.isfile(os.path.join(repo_root, "include", name)), f"missing include/{name}"
