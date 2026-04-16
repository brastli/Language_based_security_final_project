import pytest
from src.utils import format_download_response

# Functional Tests
def test_functional_format_download_response_with_string():
    content = "This is a test string."
    expected = {'content': "This is a test string."}
    assert format_download_response(content) == expected

def test_functional_format_download_response_with_number():
    content = 12345
    expected = {'content': 12345}
    assert format_download_response(content) == expected

def test_functional_format_download_response_with_list():
    content = [1, 2, 3, 4, 5]
    expected = {'content': [1, 2, 3, 4, 5]}
    assert format_download_response(content) == expected

# Security Fuzzing Tests
def test_security_format_download_response_with_sql_injection():
    malicious_payload = "1; DROP TABLE users"
    with pytest.raises(Exception):
        format_download_response(malicious_payload)

def test_security_format_download_response_with_command_injection():
    malicious_payload = "some_value; rm -rf /"
    with pytest.raises(Exception):
        format_download_response(malicious_payload)

def test_security_format_download_response_with_script_injection():
    malicious_payload = "<script>alert('Hacked!')</script>"
    with pytest.raises(Exception):
        format_download_response(malicious_payload)