# Assuming the following code is present in __init__.py

def process_input(user_input):
    if not isinstance(user_input, str):
        raise ValueError("Input must be a string")
    # Simulate processing input
    return user_input.strip().lower()

def calculate_sum(a, b):
    return a + b
```

```python
# pytest script for testing the code in __init__.py

import pytest
from __init__ import process_input, calculate_sum

# Functional Tests

def test_functional_process_input():
    assert process_input("  Hello World  ") == "hello world"
    assert process_input("TEST") == "test"
    assert process_input(" 123 ") == "123"

def test_functional_calculate_sum():
    assert calculate_sum(1, 2) == 3
    assert calculate_sum(-1, 1) == 0
    assert calculate_sum(0, 0) == 0

# Security Fuzzing Tests

def test_security_process_input():
    malicious_inputs = [
        "'; DROP TABLE users; --",
        "../../etc/passwd",
        "|| ls -la ||"
    ]
    for payload in malicious_inputs:
        result = process_input(payload)
        assert isinstance(result, str)
        assert result == payload.strip().lower()

def test_security_calculate_sum():
    # Since calculate_sum only accepts numbers, it should not be vulnerable to string-based attacks
    with pytest.raises(TypeError):
        calculate_sum("'; DROP TABLE users; --", 1)
    with pytest.raises(TypeError):
        calculate_sum("../../etc/passwd", 1)
    with pytest.raises(TypeError):
        calculate_sum("|| ls -la ||", 1)