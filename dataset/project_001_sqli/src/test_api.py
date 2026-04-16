import pytest
from unittest.mock import patch
from api import handle_login_request

# Mocking the dependencies
@pytest.fixture
def mock_get_user_by_name():
    with patch('api.get_user_by_name') as mock:
        yield mock

@pytest.fixture
def mock_normalize_username():
    with patch('api.normalize_username') as mock:
        yield mock

# Functional Tests
def test_functional_handle_login_request_valid_user(mock_get_user_by_name, mock_normalize_username):
    mock_normalize_username.return_value = 'validuser'
    mock_get_user_by_name.return_value = {'username': 'validuser', 'id': 1}

    request_data = {'username': 'ValidUser'}
    result = handle_login_request(request_data)

    mock_normalize_username.assert_called_once_with('ValidUser')
    mock_get_user_by_name.assert_called_once_with('validuser')
    assert result == {'username': 'validuser', 'id': 1}

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
    malicious_input = "'; DROP TABLE users; --"
    mock_normalize_username.return_value = malicious_input
    mock_get_user_by_name.return_value = None

    request_data = {'username': malicious_input}
    result = handle_login_request(request_data)

    mock_normalize_username.assert_called_once_with(malicious_input)
    mock_get_user_by_name.assert_called_once_with(malicious_input)
    assert result is None

def test_security_handle_login_request_command_injection(mock_get_user_by_name, mock_normalize_username):
    malicious_input = "validuser; rm -rf /"
    mock_normalize_username.return_value = malicious_input
    mock_get_user_by_name.return_value = None

    request_data = {'username': malicious_input}
    result = handle_login_request(request_data)

    mock_normalize_username.assert_called_once_with(malicious_input)
    mock_get_user_by_name.assert_called_once_with(malicious_input)
    assert result is None

def test_security_handle_login_request_path_traversal(mock_get_user_by_name, mock_normalize_username):
    malicious_input = "../etc/passwd"
    mock_normalize_username.return_value = malicious_input
    mock_get_user_by_name.return_value = None

    request_data = {'username': malicious_input}
    result = handle_login_request(request_data)

    mock_normalize_username.assert_called_once_with(malicious_input)
    mock_get_user_by_name.assert_called_once_with(malicious_input)
    assert result is None