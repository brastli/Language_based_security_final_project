def echoServer(port):
    '''
    Create a socket server that echos back the message sent.
    '''
    try:
        import socket
    except ImportError as exc:
        raise RuntimeError("socket module is required") from exc

    if isinstance(port, bool) or not isinstance(port, int):
        raise ValueError("port must be an integer between 1 and 65535")
    if port < 1 or port > 65535:
        raise ValueError("port must be an integer between 1 and 65535")

    safe_port = int(port)
    if isinstance(safe_port, bool) or not isinstance(safe_port, int):
        raise ValueError("port must be an integer between 1 and 65535")
    if safe_port < 1 or safe_port > 65535:
        raise ValueError("port must be an integer between 1 and 65535")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('0.0.0.0', safe_port))
        s.listen(1)
        s.settimeout(5)
        conn, addr = s.accept()
        try:
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                conn.send(data)
        finally:
            conn.close()
    finally:
        s.close()