import pytest
from utils import normalize_username

# Functional Tests
def test_functional_normalize_username_with_spaces():
    assert normalize_username("  user  ") == "user"

def test_functional_normalize_username_no_spaces():
    assert normalize_username("user") == "user"

def test_functional_normalize_username_with_tabs():
    assert normalize_username("\tuser\t") == "user"

def test_functional_normalize_username_with_newlines():
    assert normalize_username("\nuser\n") == "user"

def test_functional_normalize_username_empty_string():
    assert normalize_username("") == ""

# Security Fuzzing Tests
def test_security_normalize_username_sql_injection():
    malicious_input = "user'; DROP TABLE users; --"
    assert normalize_username(malicious_input) == malicious_input.strip()

def test_security_normalize_username_command_injection():
    malicious_input = "user && rm -rf /"
    assert normalize_username(malicious_input) == malicious_input.strip()

def test_security_normalize_username_path_traversal():
    malicious_input = "../etc/passwd"
    assert normalize_username(malicious_input) == malicious_input.strip()