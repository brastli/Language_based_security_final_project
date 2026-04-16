import pytest
from utils import ping_host

def test_functional_ping_host():
    # Test with a valid hostname
    result = ping_host('localhost')
    assert result == 0, "Expected successful ping to localhost"

    # Test with a valid IP address
    result = ping_host('127.0.0.1')
    assert result == 0, "Expected successful ping to 127.0.0.1"

    # Test with an unreachable IP address
    result = ping_host('192.0.2.0')  # Reserved for documentation, should not be reachable
    assert result != 0, "Expected unsuccessful ping to 192.0.2.0"

def test_security_ping_host():
    # Test with a command injection attempt
    malicious_payloads = [
        'localhost; echo vulnerable',
        'localhost && echo vulnerable',
        'localhost || echo vulnerable'
    ]

    for payload in malicious_payloads:
        result = ping_host(payload)
        assert result != 0, f"Expected unsuccessful ping with payload: {payload}"

    # Test with a path traversal attempt
    path_traversal_payloads = [
        'localhost/../../etc/passwd',
        'localhost/..\\..\\windows\\system32',
        'localhost/../../../../../../../../etc/passwd'
    ]

    for payload in path_traversal_payloads:
        result = ping_host(payload)
        assert result != 0, f"Expected unsuccessful ping with payload: {payload}"

    # Test with an SQL injection attempt
    sql_injection_payloads = [
        'localhost; DROP TABLE users',
        'localhost; SELECT * FROM users WHERE 1=1',
        'localhost; --'
    ]

    for payload in sql_injection_payloads:
        result = ping_host(payload)
        assert result != 0, f"Expected unsuccessful ping with payload: {payload}"