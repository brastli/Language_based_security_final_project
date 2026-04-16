import pytest
from unittest.mock import patch
from api import handle_download_log_request

# Mock functions from db and utils
@pytest.fixture
def mock_read_log_file():
    with patch('api.read_log_file') as mock:
        yield mock

@pytest.fixture
def mock_format_download_response():
    with patch('api.format_download_response') as mock:
        yield mock

# Functional Tests
def test_functional_handle_download_log_request_valid_filename(mock_read_log_file, mock_format_download_response):
    mock_read_log_file.return_value = "log content"
    mock_format_download_response.return_value = "formatted response"
    
    request_data = {'filename': 'valid_log.txt'}
    response = handle_download_log_request(request_data)
    
    mock_read_log_file.assert_called_once_with('valid_log.txt')
    mock_format_download_response.assert_called_once_with("log content")
    assert response == "formatted response"

def test_functional_handle_download_log_request_missing_filename(mock_read_log_file, mock_format_download_response):
    mock_read_log_file.return_value = "log content"
    mock_format_download_response.return_value = "formatted response"
    
    request_data = {}
    response = handle_download_log_request(request_data)
    
    mock_read_log_file.assert_called_once_with('')
    mock_format_download_response.assert_called_once_with("log content")
    assert response == "formatted response"

# Security Fuzzing Tests
def test_security_handle_download_log_request_sql_injection(mock_read_log_file, mock_format_download_response):
    mock_read_log_file.return_value = "log content"
    mock_format_download_response.return_value = "formatted response"
    
    malicious_payloads = [
        "' OR '1'='1",
        "'; DROP TABLE logs; --",
        "' UNION SELECT * FROM users --"
    ]
    
    for payload in malicious_payloads:
        request_data = {'filename': payload}
        response = handle_download_log_request(request_data)
        
        mock_read_log_file.assert_called_with(payload)
        mock_format_download_response.assert_called_with("log content")
        assert response == "formatted response"

def test_security_handle_download_log_request_command_injection(mock_read_log_file, mock_format_download_response):
    mock_read_log_file.return_value = "log content"
    mock_format_download_response.return_value = "formatted response"
    
    malicious_payloads = [
        'log.txt; rm -rf /',
        'log.txt && echo "hacked"',
        'log.txt | cat /etc/passwd'
    ]
    
    for payload in malicious_payloads:
        request_data = {'filename': payload}
        response = handle_download_log_request(request_data)
        
        mock_read_log_file.assert_called_with(payload)
        mock_format_download_response.assert_called_with("log content")
        assert response == "formatted response"

def test_security_handle_download_log_request_path_traversal(mock_read_log_file, mock_format_download_response):
    mock_read_log_file.return_value = "log content"
    mock_format_download_response.return_value = "formatted response"
    
    malicious_payloads = [
        '../etc/passwd',
        '../../var/log/syslog',
        '/absolute/path/to/secret'
    ]
    
    for payload in malicious_payloads:
        request_data = {'filename': payload}
        response = handle_download_log_request(request_data)
        
        mock_read_log_file.assert_called_with(payload)
        mock_format_download_response.assert_called_with("log content")
        assert response == "formatted response"