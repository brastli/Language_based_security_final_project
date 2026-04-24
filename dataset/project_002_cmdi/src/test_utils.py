import pytest
from unittest.mock import patch

from src.utils import ping_host


def test_functional_valid_host_returns_returncode():
    with patch("src.utils.subprocess.run") as mock_run:
        mock_run.return_value.returncode = 0
        rc = ping_host("127.0.0.1")
        assert rc == 0
        mock_run.assert_called_once_with(["ping", "-n", "1", "127.0.0.1"], check=False)


def test_functional_nonzero_returncode_is_propagated():
    with patch("src.utils.subprocess.run") as mock_run:
        mock_run.return_value.returncode = 1
        rc = ping_host("example.com")
        assert rc == 1
        mock_run.assert_called_once_with(["ping", "-n", "1", "example.com"], check=False)


def test_functional_accepts_simple_hostname():
    with patch("src.utils.subprocess.run") as mock_run:
        mock_run.return_value.returncode = 0
        rc = ping_host("localhost")
        assert rc == 0
        mock_run.assert_called_once_with(["ping", "-n", "1", "localhost"], check=False)


@pytest.mark.parametrize(
    "payload",
    [
        "127.0.0.1; rm -rf /",
        "example.com && whoami",
        "badhost`id`",
    ],
)
def test_security_rejects_command_injection_payloads(payload):
    with pytest.raises(Exception):
        ping_host(payload)


@pytest.mark.parametrize(
    "payload",
    [
        "127.0.0.1\nwhoami",
        "127.0.0.1\rwhoami",
        "127.0.0.1|cat /etc/passwd",
    ],
)
def test_security_rejects_control_character_payloads(payload):
    with pytest.raises(Exception):
        ping_host(payload)


@pytest.mark.parametrize(
    "payload",
    [
        "",
        None,
        12345,
    ],
)
def test_security_rejects_invalid_type_or_empty_input(payload):
    with pytest.raises(Exception):
        ping_host(payload)