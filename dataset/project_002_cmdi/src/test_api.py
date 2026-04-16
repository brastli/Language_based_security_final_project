import pytest
from src.api import handle_ping_request
from unittest.mock import patch

# Functional Tests
def test_functional_handle_ping_request_success():
    request_data = {'host': '192.168.1.1'}
    with patch('src.api.ping_host', return_value=0) as mock_ping, \
         patch('src.api.save_scan_record', return_value=True) as mock_save:
        result = handle_ping_request(request_data)
        mock_ping.assert_called_once_with('192.168.1.1')
        mock_save.assert_called_once_with('192.168.1.1', 0)
        assert result is True

def test_functional_handle_ping_request_no_host():
    request_data = {}
    with patch('src.api.ping_host', return_value=1) as mock_ping, \
         patch('src.api.save_scan_record', return_value=False) as mock_save:
        result = handle_ping_request(request_data)
        mock_ping.assert_called_once_with('')
        mock_save.assert_called_once_with('', 1)
        assert result is False

# Security Fuzzing Tests
def test_security_handle_ping_request_sql_injection():
    malicious_payload = {'host': "192.168.1.1'; DROP TABLE users; --"}
    with patch('src.api.ping_host', side_effect=ValueError("Invalid host")):
        with pytest.raises(Exception):
            handle_ping_request(malicious_payload)

def test_security_handle_ping_request_command_injection():
    malicious_payload = {'host': '192.168.1.1; rm -rf /'}
    with patch('src.api.ping_host', side_effect=ValueError("Invalid host")):
        with pytest.raises(Exception):
            handle_ping_request(malicious_payload)

def test_security_handle_ping_request_xss_attack():
    malicious_payload = {'host': '<script>alert(1)</script>'}
    with patch('src.api.ping_host', side_effect=ValueError("Invalid host")):
        with pytest.raises(Exception):
            handle_ping_request(malicious_payload)