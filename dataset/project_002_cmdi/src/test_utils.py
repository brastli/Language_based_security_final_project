import pytest
from src.utils import ping_host

# Functional Tests
def test_functional_valid_hostname():
    assert ping_host('localhost') == 0

def test_functional_valid_ip():
    assert ping_host('8.8.8.8') == 0

def test_functional_unreachable_host():
    assert ping_host('unreachable.host') == 1

# Security Fuzzing Tests
def test_security_sql_injection():
    with pytest.raises(ValueError):
        ping_host("'; DROP TABLE users; --")

def test_security_command_injection():
    with pytest.raises(ValueError):
        ping_host('localhost && rm -rf /')

def test_security_invalid_characters():
    with pytest.raises(ValueError):
        ping_host('invalid_host!@#')