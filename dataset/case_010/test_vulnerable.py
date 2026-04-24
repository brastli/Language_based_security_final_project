import pytest
from vulnerable import check_host_reachable


def test_functional_empty_host_returns_false():
    assert check_host_reachable("") is False


def test_functional_whitespace_host_returns_false():
    assert check_host_reachable("   ") is False


def test_functional_valid_host_builds_and_executes_ping(monkeypatch):
    calls = []

    def fake_system(cmd):
        calls.append(cmd)
        return 0

    monkeypatch.setattr("vulnerable.os.system", fake_system)
    assert check_host_reachable("127.0.0.1") is True
    assert calls == ["ping -c 1 127.0.0.1"]


def test_functional_nonzero_exit_code_returns_false(monkeypatch):
    def fake_system(cmd):
        return 1

    monkeypatch.setattr("vulnerable.os.system", fake_system)
    assert check_host_reachable("localhost") is False


@pytest.mark.parametrize(
    "payload",
    [
        "127.0.0.1; id",
        "localhost && whoami",
        "8.8.8.8 | cat /etc/passwd",
    ],
)
def test_security_command_injection_payloads_raise_exception(payload):
    with pytest.raises(Exception):
        check_host_reachable(payload)


@pytest.mark.parametrize(
    "payload",
    [
        "' OR '1'='1",
        "127.0.0.1; rm -rf /",
        "$(touch /tmp/pwned)",
    ],
)
def test_security_additional_malicious_payloads_raise_exception(payload):
    with pytest.raises(Exception):
        check_host_reachable(payload)