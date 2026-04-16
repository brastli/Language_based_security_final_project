import pytest
from utils import format_download_response

# Functional Tests
def test_functional_format_download_response_with_string():
    content = "Sample content"
    expected = {'content': "Sample content"}
    assert format_download_response(content) == expected

def test_functional_format_download_response_with_empty_string():
    content = ""
    expected = {'content': ""}
    assert format_download_response(content) == expected

def test_functional_format_download_response_with_special_characters():
    content = "!@#$%^&*()_+"
    expected = {'content': "!@#$%^&*()_+"}
    assert format_download_response(content) == expected

# Security Fuzzing Tests
def test_security_format_download_response_with_sql_injection():
    malicious_content = "1; DROP TABLE users"
    response = format_download_response(malicious_content)
    assert response == {'content': malicious_content}

def test_security_format_download_response_with_command_injection():
    malicious_content = "echo 'malicious code'"
    response = format_download_response(malicious_content)
    assert response == {'content': malicious_content}

def test_security_format_download_response_with_path_traversal():
    malicious_content = "../../etc/passwd"
    response = format_download_response(malicious_content)
    assert response == {'content': malicious_content}