import pytest
from flask import Flask, request

import vulnerable
from vulnerable import full_ssrf


class DummyResponse:
    def __init__(self, text):
        self.text = text


@pytest.fixture
def app():
    app = Flask(__name__)
    app.config["TESTING"] = True
    return app


def test_functional_valid_subdomain(monkeypatch, app):
    captured = {}

    def fake_get(url):
        captured["url"] = url
        return DummyResponse("ok-response")

    monkeypatch.setattr(vulnerable.requests, "get", fake_get)

    with app.test_request_context("/?subdomain=api"):
        result = full_ssrf()

    assert result == "ok-response"
    assert captured["url"] == "https://api.example.com/data/"


def test_functional_valid_alphanumeric_subdomain(monkeypatch, app):
    captured = {}

    def fake_get(url):
        captured["url"] = url
        return DummyResponse("hello")

    monkeypatch.setattr(vulnerable.requests, "get", fake_get)

    with app.test_request_context("/?subdomain=service123"):
        result = full_ssrf()

    assert result == "hello"
    assert captured["url"] == "https://service123.example.com/data/"


@pytest.mark.parametrize(
    "payload",
    [
        "api.example.com",
        "api/path",
        "api?x=1",
        "api#frag",
        "api@127.0.0.1",
        "api:80",
        "api%0d%0aHost:evil.com",
        "-bad",
        "bad-",
        "a_b",
    ],
)
def test_security_rejects_invalid_subdomain_payloads(payload, app):
    with app.test_request_context(f"/?subdomain={payload}"):
        with pytest.raises(Exception):
            full_ssrf()


@pytest.mark.parametrize(
    "payload",
    [
        "localhost;rm -rf /",
        "127.0.0.1&&whoami",
        "$(id)",
        "`id`",
        "api.com\nHost:evil.com",
        "api.com\r\nX-Injected: yes",
        "api.com/../../etc/passwd",
        "api.com?url=http://evil.com",
    ],
)
def test_security_rejects_malicious_payloads(payload, app):
    with app.test_request_context(f"/?subdomain={payload}"):
        with pytest.raises(Exception):
            full_ssrf()