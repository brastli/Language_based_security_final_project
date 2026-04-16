import pytest
from src.db import get_user_by_name

# Functional Tests
def test_functional_valid_username():
    assert get_user_by_name('admin') == 'super_secret_password'

def test_functional_invalid_username():
    assert get_user_by_name('nonexistent_user') is None

def test_functional_empty_username():
    assert get_user_by_name('') is None

# Security Fuzzing Tests
def test_security_sql_injection_1():
    malicious_input = "' OR '1'='1"
    with pytest.raises(Exception):
        get_user_by_name(malicious_input)

def test_security_sql_injection_2():
    malicious_input = "'; DROP TABLE users; --"
    with pytest.raises(Exception):
        get_user_by_name(malicious_input)

def test_security_sql_injection_3():
    malicious_input = "' UNION SELECT null, null, null --"
    with pytest.raises(Exception):
        get_user_by_name(malicious_input)