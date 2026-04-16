import pytest
from db import save_scan_record

# Functional Tests
def test_functional_save_scan_record_valid_input():
    result = save_scan_record("192.168.1.1", 200)
    assert result == {'host': "192.168.1.1", 'status_code': 200}

def test_functional_save_scan_record_another_valid_input():
    result = save_scan_record("example.com", 404)
    assert result == {'host': "example.com", 'status_code': 404}

# Security Fuzzing Tests
def test_security_save_scan_record_sql_injection():
    malicious_input = "'; DROP TABLE users; --"
    result = save_scan_record(malicious_input, 200)
    assert result == {'host': malicious_input, 'status_code': 200}

def test_security_save_scan_record_command_injection():
    malicious_input = "192.168.1.1; rm -rf /"
    result = save_scan_record(malicious_input, 200)
    assert result == {'host': malicious_input, 'status_code': 200}

def test_security_save_scan_record_path_traversal():
    malicious_input = "../../etc/passwd"
    result = save_scan_record(malicious_input, 200)
    assert result == {'host': malicious_input, 'status_code': 200}