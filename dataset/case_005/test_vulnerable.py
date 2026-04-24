import pytest
import subprocess
from vulnerable import run


def test_functional_run_executes_valid_command():
    result = run("echo hello")
    assert result.returncode == 0


def test_functional_run_returns_completed_process():
    result = run("echo hello")
    assert isinstance(result, subprocess.CompletedProcess)


@pytest.mark.parametrize(
    "payload",
    [
        "echo hello; ls",
        "echo hello && whoami",
        "echo hello | cat",
    ],
)
def test_security_run_rejects_malicious_payloads(payload):
    with pytest.raises(Exception):
        run(payload)