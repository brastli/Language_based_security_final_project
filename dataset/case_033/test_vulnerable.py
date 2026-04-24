import base64
import pytest
from flask import Flask

from vulnerable import app, code_execution


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_functional_get_request_returns_none(client):
    response = client.get("/execute")
    assert response.status_code in (200, 405)


def test_functional_post_valid_base64_calls_setname(monkeypatch):
    captured = {}

    def fake_setname(value):
        captured["value"] = value

    monkeypatch.setattr("vulnerable.setname", fake_setname, raising=False)

    with app.test_request_context(
        "/execute?first_name=" + base64.b64encode(b"John").decode("ascii"),
        method="POST",
    ):
        result = code_execution()

    assert result is None
    assert captured["value"] == b"John"


def test_functional_post_empty_first_name_raises_typeerror():
    with app.test_request_context("/execute", method="POST"):
        with pytest.raises(Exception):
            code_execution()


def test_security_sql_injection_payload_rejected():
    payloads = [
        "J' OR '1'='1",
        "'; DROP TABLE users; --",
        "admin'--",
    ]
    for payload in payloads:
        encoded = base64.b64encode(payload.encode("utf-8")).decode("ascii")
        with app.test_request_context(f"/execute?first_name={encoded}", method="POST"):
            with pytest.raises(Exception):
                code_execution()


def test_security_command_injection_payload_rejected():
    payloads = [
        "name; rm -rf /",
        "name && whoami",
        "name|cat /etc/passwd",
    ]
    for payload in payloads:
        encoded = base64.b64encode(payload.encode("utf-8")).decode("ascii")
        with app.test_request_context(f"/execute?first_name={encoded}", method="POST"):
            with pytest.raises(Exception):
                code_execution()


def test_security_python_code_injection_payload_rejected():
    payloads = [
        "__import__('os').system('id')",
        "'); __import__('os').system('id'); #",
        "setname.__globals__['__builtins__']['eval']('1+1')",
    ]
    for payload in payloads:
        encoded = base64.b64encode(payload.encode("utf-8")).decode("ascii")
        with app.test_request_context(f"/execute?first_name={encoded}", method="POST"):
            with pytest.raises(Exception):
                code_execution()