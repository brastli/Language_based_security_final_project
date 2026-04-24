import pytest
from unittest.mock import patch
from flask import Flask

from vulnerable import app, executeCommand


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_functional_get_request_returns_none(client):
    response = client.get("/command")
    assert response.status_code == 200
    assert response.data == b""


def test_functional_post_request_executes_valid_command(client):
    with patch("vulnerable.os.system") as mock_system:
        response = client.post("/command?action=echo%20hello")
        assert response.status_code == 200
        assert response.data == b"Command executed"
        mock_system.assert_called_once_with("echo hello")


def test_functional_direct_function_call_with_valid_action():
    with app.test_request_context("/command?action=echo%20hello", method="POST"):
        with patch("vulnerable.os.system") as mock_system:
            result = executeCommand()
            assert result == "Command executed"
            mock_system.assert_called_once_with("echo hello")


@pytest.mark.parametrize(
    "payload",
    [
        "ls; id",
        "echo test && cat /etc/passwd",
        "$(whoami)",
    ],
)
def test_security_command_injection_payloads_raise_exception(payload):
    with app.test_request_context(f"/command?action={payload}", method="POST"):
        with patch("vulnerable.os.system", side_effect=Exception("Rejected malicious input")):
            with pytest.raises(Exception):
                executeCommand()