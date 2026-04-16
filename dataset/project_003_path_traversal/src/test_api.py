import pytest
from src.api import handle_download_log_request
from unittest.mock import patch

# Mocking the dependencies
@patch('src.api.read_log_file')
@patch('src.api.format_download_response')
def test_functional_handle_download_log_request(mock_format_download_response, mock_read_log_file):
    # Setup
    mock_read_log_file.return_value = "log content"
    mock_format_download_response.return_value = "formatted response"
    
    # Test input
    request_data = {'filename': 'log.txt'}
    
    # Execute
    response = handle_download_log_request(request_data)
    
    # Verify
    mock_read_log_file.assert_called_once_with('log.txt')
    mock_format_download_response.assert_called_once_with("log content")
    assert response == "formatted response"

@patch('src.api.read_log_file')
@patch('src.api.format_download_response')
def test_functional_handle_download_log_request_no_filename(mock_format_download_response, mock_read_log_file):
    # Setup
    mock_read_log_file.return_value = "log content"
    mock_format_download_response.return_value = "formatted response"
    
    # Test input
    request_data = {}
    
    # Execute
    response = handle_download_log_request(request_data)
    
    # Verify
    mock_read_log_file.assert_called_once_with('')
    mock_format_download_response.assert_called_once_with("log content")
    assert response == "formatted response"

@pytest.mark.parametrize("malicious_payload", [
    {"filename": "log.txt; rm -rf /"},  # Command Injection
    {"filename": "' OR '1'='1"},        # SQL Injection
    {"filename": "<script>alert(1)</script>"},  # XSS
])
@patch('src.api.read_log_file')
@patch('src.api.format_download_response')
def test_security_handle_download_log_request(mock_format_download_response, mock_read_log_file, malicious_payload):
    # Setup
    mock_read_log_file.side_effect = ValueError("Invalid filename")
    
    # Execute & Verify
    with pytest.raises(Exception):
        handle_download_log_request(malicious_payload)