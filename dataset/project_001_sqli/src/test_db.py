import pytest
from db import get_user_by_name

def test_functional_get_user_by_name_valid_user():
    assert get_user_by_name('admin') == 'super_secret_password'

def test_functional_get_user_by_name_invalid_user():
    assert get_user_by_name('nonexistent') is None

def test_security_get_user_by_name_sql_injection_1():
    payload = "' OR '1'='1"
    assert get_user_by_name(payload) is None

def test_security_get_user_by_name_sql_injection_2():
    payload = "'; DROP TABLE users; --"
    assert get_user_by_name(payload) is None

def test_security_get_user_by_name_sql_injection_3():
    payload = "' UNION SELECT null, null, null --"
    assert get_user_by_name(payload) is None