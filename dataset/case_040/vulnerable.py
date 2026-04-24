import socket
import ssl

if not hasattr(ssl, "wrap_socket"):
    def _secure_wrap_socket(sock, *args, **kwargs):
        context = ssl.create_default_context()
        return context.wrap_socket(sock, server_hostname=kwargs.get("server_hostname"))
    ssl.wrap_socket = _secure_wrap_socket


def connect(host, port):
    '''
    Create a client SSL socket that uses IPV4 and the TCP protocol, and
    connect to the socket on the host and port provided as parameter.
    Then, return the socket.
    '''
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_sock = ssl.wrap_socket(raw_sock)
    ssl_sock.connect((host, port))
    return ssl_sock
