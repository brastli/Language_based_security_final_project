import pytest

from src.api import handle_ping_request


def test_functional_handle_ping_request_success(monkeypatch):
    captured = {}

    def fake_ping_host(host):
        captured["host"] = host
        return 0

    def fake_save_scan_record(host, status_code):
        captured["saved_host"] = host
        captured["status_code"] = status_code
        return {"host": host, "status_code": status_code, "saved": True}

    monkeypatch.setattr("src.api.ping_host", fake_ping_host)
    monkeypatch.setattr("src.api.save_scan_record", fake_save_scan_record)

    result = handle_ping_request({"host": "example.com"})

    assert captured["host"] == "example.com"
    assert captured["saved_host"] == "example.com"
    assert captured["status_code"] == 0
    assert result == {"host": "example.com", "status_code": 0, "saved": True}


def test_functional_handle_ping_request_empty_host(monkeypatch):
    captured = {}

    def fake_ping_host(host):
        captured["host"] = host
        return 1

    def fake_save_scan_record(host, status_code):
        captured["saved_host"] = host
        captured["status_code"] = status_code
        return ("ok", host, status_code)

    monkeypatch.setattr("src.api.ping_host", fake_ping_host)
    monkeypatch.setattr("src.api.save_scan_record", fake_save_scan_record)

    result = handle_ping_request({})

    assert captured["host"] == ""
    assert captured["saved_host"] == ""
    assert captured["status_code"] == 1
    assert result == ("ok", "", 1)


@pytest.mark.parametrize(
    "payload",
    [
        "127.0.0.1; rm -rf /",
        "example.com && cat /etc/passwd",
        "$(whoami)",
    ],
)
def test_security_handle_ping_request_malicious_payloads(monkeypatch, payload):
    def fake_ping_host(host):
        raise ValueError("Rejected malicious host input")

    def fake_save_scan_record(host, status_code):
        return {"host": host, "status_code": status_code}

    monkeypatch.setattr("src.api.ping_host", fake_ping_host)
    monkeypatch.setattr("src.api.save_scan_record", fake_save_scan_record)

    with pytest.raises(Exception):
        handle_ping_request({"host": payload})