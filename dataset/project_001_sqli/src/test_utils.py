import pytest
from src.utils import normalize_username

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
    with pytest.raises(Exception):
        normalize_username("'; DROP TABLE users; --")

def test_security_normalize_username_command_injection():
    with pytest.raises(Exception):
        normalize_username("user; rm -rf /")

def test_security_normalize_username_html_injection():
    with pytest.raises(Exception):
        normalize_username("<script>alert('hack');</script>")