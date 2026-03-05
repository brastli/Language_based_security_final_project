import socket

def start_server():
    import socket
    import sqlite3
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT)')
    conn.commit()
    s = socket.socket()
    s.bind(('0.0.0.0', 8080))
    s.listen(5)
    while True:
        client, addr = s.accept()
        data = client.recv(1024).decode('utf-8')
        cursor.execute('SELECT * FROM users WHERE name = ?', (data,))
        result = cursor.fetchall()
        client.send(str(result).encode('utf-8'))
        client.close()
    conn.close()