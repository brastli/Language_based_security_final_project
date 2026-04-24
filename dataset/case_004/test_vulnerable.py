import pytest
from vulnerable import run


def test_functional_run_executes_valid_command():
    result = run("echo hello")
    assert result == 0


def test_functional_run_handles_simple_command():
    result = run("python -c 'print(123)'")
    assert result == 0


@pytest.mark.parametrize(
    "payload",
    [
        "echo hello; ls",
        "echo hello && whoami",
        "echo hello | cat",
    ],
)
def test_security_malicious_payloads_raise_exception(payload):
    with pytest.raises(Exception):
        run(payload)