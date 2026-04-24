import pytest
from vulnerable import generateRandomString


def test_functional_returns_string_of_requested_length():
    result = generateRandomString(10)
    assert isinstance(result, str)
    assert len(result) == 10


def test_functional_zero_length_returns_empty_string():
    result = generateRandomString(0)
    assert result == ""


def test_functional_only_ascii_letters():
    result = generateRandomString(100)
    assert all(ch.isalpha() and ch.isascii() for ch in result)


def test_functional_multiple_calls_produce_strings_of_correct_length():
    results = [generateRandomString(5) for _ in range(5)]
    assert all(isinstance(r, str) and len(r) == 5 for r in results)


def test_functional_negative_length_raises_value_error():
    with pytest.raises(ValueError):
        generateRandomString(-1)


def test_functional_non_integer_length_raises_type_error():
    with pytest.raises(TypeError):
        generateRandomString("10")


def test_functional_float_length_raises_type_error():
    with pytest.raises(TypeError):
        generateRandomString(3.14)


def test_security_sql_injection_payload_rejected():
    malicious_payload = "1; DROP TABLE users; --"
    with pytest.raises(Exception):
        generateRandomString(malicious_payload)


def test_security_command_injection_payload_rejected():
    malicious_payload = "5 && rm -rf /"
    with pytest.raises(Exception):
        generateRandomString(malicious_payload)


def test_security_path_traversal_payload_rejected():
    malicious_payload = "../../etc/passwd"
    with pytest.raises(Exception):
        generateRandomString(malicious_payload)