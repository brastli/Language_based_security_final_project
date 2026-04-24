import socket
from unittest.mock import MagicMock, patch

import pytest

from vulnerable import echoServer


def test_functional_rejects_non_integer_port():
    with pytest.raises(ValueError):
        echoServer("8080")


def test_functional_rejects_bool_port():
    with pytest.raises(ValueError):
        echoServer(True)


def test_functional_rejects_out_of_range_port_low():
    with pytest.raises(ValueError):
        echoServer(0)


def test_functional_rejects_out_of_range_port_high():
    with pytest.raises(ValueError):
        echoServer(70000)


def test_functional_echoes_received_data_and_closes_sockets():
    mock_socket_instance = MagicMock()
    mock_conn = MagicMock()
    mock_conn.recv.side_effect = [b"hello", b""]
    mock_socket_instance.accept.return_value = (mock_conn, ("127.0.0.1", 12345))

    with patch("socket.socket", return_value=mock_socket_instance):
        echoServer(12345)

    mock_socket_instance.setsockopt.assert_called_once_with(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mock_socket_instance.bind.assert_called_once_with(("0.0.0.0", 12345))
    mock_socket_instance.listen.assert_called_once_with(1)
    mock_socket_instance.settimeout.assert_called_once_with(5)
    mock_socket_instance.accept.assert_called_once()
    mock_conn.recv.assert_called()
    mock_conn.send.assert_called_once_with(b"hello")
    mock_conn.close.assert_called_once()
    mock_socket_instance.close.assert_called_once()


def test_security_sql_injection_like_payloads_rejected():
    malicious_payloads = [
        "1; DROP TABLE users;--",
        "1050 OR 1=1",
        "0 UNION SELECT password FROM users",
    ]

    for payload in malicious_payloads:
        with pytest.raises(Exception):
            echoServer(payload)


def test_security_command_injection_like_payloads_rejected():
    malicious_payloads = [
        "8080 && rm -rf /",
        "8080 | cat /etc/passwd",
        "8080; shutdown -h now",
    ]

    for payload in malicious_payloads:
        with pytest.raises(Exception):
            echoServer(payload)


def test_security_malicious_numeric_payloads_rejected():
    malicious_payloads = [
        -1,
        65536,
        3.14159,
    ]

    for payload in malicious_payloads:
        with pytest.raises(Exception):
            echoServer(payload)