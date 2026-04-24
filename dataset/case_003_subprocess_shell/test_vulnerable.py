import pytest
import subprocess
from vulnerable import run


def test_functional_run_returns_popen_object():
    proc = run("echo hello")
    try:
        assert isinstance(proc, subprocess.Popen)
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def test_functional_run_executes_command():
    proc = run("echo hello")
    stdout, stderr = proc.communicate(timeout=5)
    assert proc.returncode == 0


@pytest.mark.parametrize(
    "payload",
    [
        "echo safe; rm -rf /",
        "echo safe && cat /etc/passwd",
        "echo safe | whoami",
    ],
)
def test_security_fuzzing_run_rejects_malicious_payloads(payload):
    with pytest.raises(Exception):
        run(payload)