import pytest
from src.api import handle_login_request
from unittest.mock import patch

# Mocking the dependencies
@pytest.fixture
def mock_get_user_by_name():
    with patch('src.api.get_user_by_name') as mock:
        yield mock

@pytest.fixture
def mock_normalize_username():
    with patch('src.api.normalize_username') as mock:
        yield mock

# Functional Tests
def test_functional_handle_login_request_valid_user(mock_get_user_by_name, mock_normalize_username):
    mock_normalize_username.return_value = 'validuser'
    mock_get_user_by_name.return_value = {'id': 1, 'username': 'validuser'}

    request_data = {'username': 'ValidUser'}
    result = handle_login_request(request_data)

    mock_normalize_username.assert_called_once_with('ValidUser')
    mock_get_user_by_name.assert_called_once_with('validuser')
    assert result == {'id': 1, 'username': 'validuser'}

def test_functional_handle_login_request_missing_username(mock_get_user_by_name, mock_normalize_username):
    mock_normalize_username.return_value = ''
    mock_get_user_by_name.return_value = None

    request_data = {}
    result = handle_login_request(request_data)

    mock_normalize_username.assert_called_once_with('')
    mock_get_user_by_name.assert_called_once_with('')
    assert result is None

# Security Fuzzing Tests
def test_security_handle_login_request_sql_injection(mock_get_user_by_name, mock_normalize_username):
    malicious_payloads = [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "' UNION SELECT * FROM users --"
    ]

    for payload in malicious_payloads:
        with pytest.raises(Exception):
            handle_login_request({'username': payload})

def test_security_handle_login_request_command_injection(mock_get_user_by_name, mock_normalize_username):
    malicious_payloads = [
        '$(rm -rf /)',
        '`ls -la`',
        '; shutdown -h now'
    ]

    for payload in malicious_payloads:
        with pytest.raises(Exception):
            handle_login_request({'username': payload})

def test_security_handle_login_request_xss_injection(mock_get_user_by_name, mock_normalize_username):
    malicious_payloads = [
        '<script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>'
    ]

    for payload in malicious_payloads:
        with pytest.raises(Exception):
            handle_login_request({'username': payload})