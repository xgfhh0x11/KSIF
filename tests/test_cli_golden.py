"""Golden-output checks — assert the CLI's output content, not just its
exit code. This closes the documented gap (BUILD_AND_VERIFY §"smoke test
only asserts exit codes; a regression that changed the graph contents
but kept the program running would pass CI").

All asserted strings are compiled literals / fixed baseline constants —
the output is deterministic (no timestamps, addresses, or PIDs). Skips
cleanly when the binary has not been built; runs for real in CI."""
import subprocess

import pytest


def _run(binary, *args):
    return subprocess.run([binary, *args], capture_output=True, text=True, timeout=30)


def test_describe_eprocess_graph_contents(ksif_binary):
    res = _run(ksif_binary, "--describe", "eprocess")
    assert res.returncode == 0, f"--describe eprocess exited {res.returncode}"
    out = res.stdout
    assert "Domain: EPROCESS" in out
    # The three semantic nodes and that edges are emitted.
    for node in ("ActiveProcessLinks", "Token", "ObjectTable"):
        assert node in out, f"--describe eprocess missing node {node}:\n{out}"
    assert "Edges:" in out


@pytest.mark.parametrize("domain", [
    "ethread", "object_header", "handle_table_entry",
    "access_state", "security_descriptor",
])
def test_describe_other_domains_nonempty(ksif_binary, domain):
    res = _run(ksif_binary, "--describe", domain)
    assert res.returncode == 0, f"--describe {domain} exited {res.returncode}"
    assert "Domain:" in res.stdout and "Nodes:" in res.stdout


def test_metrics_discloses_placeholder_provenance(ksif_binary):
    """The metrics output must honestly mark itself as baseline constants,
    never look like measured values."""
    res = _run(ksif_binary, "--metrics")
    assert res.returncode == 0, f"--metrics exited {res.returncode}"
    out = res.stdout
    assert "[PLACEHOLDER] The values below are baseline constants." in out
    assert "Semantic Drift Score (SDS) : 0.0000  (placeholder)" in out
    assert "Detection Delta       (DD) : 0.0000  (placeholder)" in out
    assert "Stability Envelope    (SE) : 1.0000  (placeholder)" in out


def test_profile_modules(ksif_binary):
    res = _run(ksif_binary, "--profile")
    assert res.returncode == 0, f"--profile exited {res.returncode}"
    out = res.stdout
    assert "Lab Environment :" in out
    assert "Metrics Pipeline:" in out
    assert "Semantic Drift Score" in out


def test_no_args_prints_usage_and_exits_nonzero(ksif_binary):
    res = _run(ksif_binary)
    assert res.returncode != 0, "no-args run should exit non-zero (usage)"
