import pytest
from vulnerable import checkout_branch


class DummyProcess:
    def __init__(self, returncode=0):
        self.returncode = returncode
        self.wait_called = False

    def wait(self):
        self.wait_called = True
        return self.returncode


def test_functional_returns_false_for_missing_branch_name():
    assert checkout_branch("/tmp/repo", "") is False


def test_functional_returns_false_for_missing_repo_path():
    assert checkout_branch("", "main") is False


def test_functional_invokes_subprocess_and_returns_true_on_success(monkeypatch):
    captured = {}

    def fake_popen(cmd, shell, stdout, stderr):
        captured["cmd"] = cmd
        captured["shell"] = shell
        captured["stdout"] = stdout
        captured["stderr"] = stderr
        return DummyProcess(returncode=0)

    monkeypatch.setattr("vulnerable.subprocess.Popen", fake_popen)
    assert checkout_branch("/tmp/repo", "main") is True
    assert captured["cmd"] == "cd /tmp/repo && git checkout main"
    assert captured["shell"] is True
    assert captured["stdout"] == subprocess.PIPE
    assert captured["stderr"] == subprocess.PIPE


def test_functional_returns_false_on_nonzero_returncode(monkeypatch):
    def fake_popen(cmd, shell, stdout, stderr):
        return DummyProcess(returncode=1)

    monkeypatch.setattr("vulnerable.subprocess.Popen", fake_popen)
    assert checkout_branch("/tmp/repo", "main") is False


def test_security_command_injection_payloads_raise_or_reject(monkeypatch):
    malicious_payloads = [
        "main; rm -rf /",
        "main && cat /etc/passwd",
        "main | whoami",
    ]

    def fake_popen(cmd, shell, stdout, stderr):
        raise ValueError("Rejected malicious input")

    monkeypatch.setattr("vulnerable.subprocess.Popen", fake_popen)

    for payload in malicious_payloads:
        with pytest.raises(Exception):
            checkout_branch("/tmp/repo", payload)


def test_security_path_injection_payloads_raise_or_reject(monkeypatch):
    malicious_payloads = [
        "/tmp/repo; echo hacked",
        "/tmp/repo && touch /tmp/pwned",
        "/tmp/repo $(id)",
    ]

    def fake_popen(cmd, shell, stdout, stderr):
        raise ValueError("Rejected malicious input")

    monkeypatch.setattr("vulnerable.subprocess.Popen", fake_popen)

    for payload in malicious_payloads:
        with pytest.raises(Exception):
            checkout_branch(payload, "main")


def test_security_sqli_like_payloads_raise_or_reject(monkeypatch):
    malicious_payloads = [
        "main' OR '1'='1",
        'main"; DROP TABLE branches; --',
        "main OR 1=1 --",
    ]

    def fake_popen(cmd, shell, stdout, stderr):
        raise ValueError("Rejected malicious input")

    monkeypatch.setattr("vulnerable.subprocess.Popen", fake_popen)

    for payload in malicious_payloads:
        with pytest.raises(Exception):
            checkout_branch("/tmp/repo", payload)