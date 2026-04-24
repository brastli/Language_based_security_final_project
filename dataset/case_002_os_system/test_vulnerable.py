import os
import pytest
from vulnerable import run


def test_functional_run_executes_valid_command(monkeypatch):
    calls = []

    def fake_system(cmd):
        calls.append(cmd)
        return 0

    monkeypatch.setattr(os, "system", fake_system)
    result = run("echo hello")

    assert result == 0
    assert calls == ["echo hello"]


def test_functional_run_handles_simple_command(monkeypatch):
    calls = []

    def fake_system(cmd):
        calls.append(cmd)
        return 42

    monkeypatch.setattr(os, "system", fake_system)
    result = run("python --version")

    assert result == 42
    assert calls == ["python --version"]


@pytest.mark.parametrize(
    "payload",
    [
        "echo safe; rm -rf /",
        "echo safe && cat /etc/passwd",
        "echo safe | whoami",
    ],
)
def test_security_command_injection_payloads_raise_exception(monkeypatch, payload):
    def fake_system(cmd):
        raise ValueError("Rejected unsafe command")

    monkeypatch.setattr(os, "system", fake_system)

    with pytest.raises(Exception):
        run(payload)


@pytest.mark.parametrize(
    "payload",
    [
        "$(id)",
        "`id`",
        "echo test; shutdown -h now",
    ],
)
def test_security_additional_malicious_payloads_raise_exception(monkeypatch, payload):
    def fake_system(cmd):
        raise ValueError("Rejected unsafe command")

    monkeypatch.setattr(os, "system", fake_system)

    with pytest.raises(Exception):
        run(payload)