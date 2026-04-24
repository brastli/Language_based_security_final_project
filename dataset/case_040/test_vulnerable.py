import socket
import ssl
from unittest.mock import patch

import pytest

from vulnerable import connect


class DummySocket:
    def __init__(self):
        self.connected_to = None
        self.closed = False

    def connect(self, addr):
        self.connected_to = addr

    def close(self):
        self.closed = True


class DummySSLSocket(DummySocket):
    pass


def test_functional_connect_uses_ipv4_tcp_and_connects():
    dummy_raw = DummySocket()
    dummy_ssl = DummySSLSocket()

    with patch("vulnerable.socket.socket", return_value=dummy_raw) as mock_socket, patch(
        "vulnerable.ssl.wrap_socket", return_value=dummy_ssl
    ) as mock_wrap:
        result = connect("example.com", 443)

    mock_socket.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
    mock_wrap.assert_called_once_with(dummy_raw)
    assert result is dummy_ssl
    assert dummy_ssl.connected_to == ("example.com", 443)


def test_functional_connect_passes_host_and_port_exactly():
    dummy_raw = DummySocket()
    dummy_ssl = DummySSLSocket()

    with patch("vulnerable.socket.socket", return_value=dummy_raw), patch(
        "vulnerable.ssl.wrap_socket", return_value=dummy_ssl
    ):
        connect("127.0.0.1", 8443)

    assert dummy_ssl.connected_to == ("127.0.0.1", 8443)


@pytest.mark.parametrize(
    "malicious_host, malicious_port",
    [
        ("127.0.0.1; rm -rf /", 443),
        ("example.com && cat /etc/passwd", 443),
        ("localhost\nDROP TABLE users;--", 443),
    ],
)
def test_security_malicious_host_payloads_raise_exception(malicious_host, malicious_port):
    dummy_raw = DummySocket()
    dummy_ssl = DummySSLSocket()

    with patch("vulnerable.socket.socket", return_value=dummy_raw), patch(
        "vulnerable.ssl.wrap_socket", return_value=dummy_ssl
    ), pytest.raises(Exception):
        connect(malicious_host, malicious_port)


@pytest.mark.parametrize(
    "malicious_host, malicious_port",
    [
        ("192.168.0.1", "443; shutdown -h now"),
        ("192.168.0.1", "443 OR 1=1"),
        ("192.168.0.1", "__import__('os').system('id')"),
    ],
)
def test_security_malicious_port_payloads_raise_exception(malicious_host, malicious_port):
    dummy_raw = DummySocket()
    dummy_ssl = DummySSLSocket()

    with patch("vulnerable.socket.socket", return_value=dummy_raw), patch(
        "vulnerable.ssl.wrap_socket", return_value=dummy_ssl
    ), pytest.raises(Exception):
        connect(malicious_host, malicious_port)