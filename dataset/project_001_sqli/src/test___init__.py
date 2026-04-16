# Assuming the code to test is as follows and is located in src/__init__.py

def process_input(data):
    if not isinstance(data, str):
        raise ValueError("Input must be a string")
    if "DROP" in data.upper() or ";" in data:
        raise ValueError("Potential SQL Injection detected")
    return data.strip().lower()



# pytest script for testing the above code

import pytest
from src.__init__ import process_input

# Functional Tests
def test_functional_valid_string():
    assert process_input("  Hello World  ") == "hello world"

def test_functional_empty_string():
    assert process_input("") == ""

def test_functional_no_whitespace():
    assert process_input("Python") == "python"

# Security Fuzzing Tests
def test_security_sql_injection_uppercase():
    with pytest.raises(ValueError):
        process_input("SELECT * FROM users; DROP TABLE users;")

def test_security_sql_injection_lowercase():
    with pytest.raises(ValueError):
        process_input("select * from users; drop table users;")

def test_security_command_injection():
    with pytest.raises(ValueError):
        process_input("echo 'Hello'; rm -rf /")