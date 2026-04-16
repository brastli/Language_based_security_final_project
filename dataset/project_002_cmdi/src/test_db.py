import pytest
from src.db import save_scan_record

# Functional Tests
def test_functional_save_scan_record_valid_input():
    result = save_scan_record("example.com", 200)
    assert result == {'host': 'example.com', 'status_code': 200}

def test_functional_save_scan_record_another_valid_input():
    result = save_scan_record("testsite.org", 404)
    assert result == {'host': 'testsite.org', 'status_code': 404}

# Security Fuzzing Tests
def test_security_save_scan_record_sql_injection():
    malicious_payloads = [
        "'; DROP TABLE users; --",
        "1 OR 1=1",
        "' OR '1'='1"
    ]
    for payload in malicious_payloads:
        with pytest.raises(Exception):
            save_scan_record(payload, 200)

def test_security_save_scan_record_command_injection():
    malicious_payloads = [
        "; rm -rf /",
        "`shutdown -h now`",
        "$(reboot)"
    ]
    for payload in malicious_payloads:
        with pytest.raises(Exception):
            save_scan_record(payload, 200)

def test_security_save_scan_record_code_injection():
    malicious_payloads = [
        "__import__('os').system('ls')",
        "exec('import os; os.system(\"ls\")')",
        "eval('__import__(\"os\").system(\"ls\")')"
    ]
    for payload in malicious_payloads:
        with pytest.raises(Exception):
            save_scan_record(payload, 200)