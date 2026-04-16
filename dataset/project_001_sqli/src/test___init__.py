# Assuming the following code is in __init__.py

def process_input(user_input):
    """
    Processes the input string by reversing it and converting to uppercase.
    """
    if not isinstance(user_input, str):
        raise ValueError("Input must be a string")
    return user_input[::-1].upper()
```

```python
# pytest script for testing the code in __init__.py

import pytest
from __init__ import process_input

# Functional Tests
def test_functional_valid_string():
    assert process_input("hello") == "OLLEH"

def test_functional_empty_string():
    assert process_input("") == ""

def test_functional_numeric_string():
    assert process_input("12345") == "54321"

def test_functional_mixed_case_string():
    assert process_input("HeLLo") == "OLLEh"

# Security Fuzzing Tests
def test_security_sql_injection():
    malicious_input = "'; DROP TABLE users; --"
    result = process_input(malicious_input)
    assert result == malicious_input[::-1].upper()

def test_security_command_injection():
    malicious_input = "&& rm -rf /"
    result = process_input(malicious_input)
    assert result == malicious_input[::-1].upper()

def test_security_path_traversal():
    malicious_input = "../../etc/passwd"
    result = process_input(malicious_input)
    assert result == malicious_input[::-1].upper()