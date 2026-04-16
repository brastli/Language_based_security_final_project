# Assuming the code to test is as follows and is located in src/__init__.py

def process_input(user_input):
    if not isinstance(user_input, str):
        raise ValueError("Input must be a string")
    if ";" in user_input or "--" in user_input or "DROP" in user_input.upper():
        raise ValueError("Malicious input detected")
    return user_input.strip().lower()

# pytest script for the above code

import pytest
from src.__init__ import process_input

# Functional Tests
def test_functional_valid_input():
    assert process_input("  Hello World  ") == "hello world"

def test_functional_empty_string():
    assert process_input("") == ""

def test_functional_numeric_string():
    assert process_input("12345") == "12345"

# Security Fuzzing Tests
def test_security_sql_injection():
    with pytest.raises(ValueError):
        process_input("1; DROP TABLE users")

def test_security_command_injection():
    with pytest.raises(ValueError):
        process_input("rm -rf /")

def test_security_comment_injection():
    with pytest.raises(ValueError):
        process_input("SELECT * FROM users --")

def test_security_non_string_input():
    with pytest.raises(ValueError):
        process_input(12345)