import sqlite3

def get_user_by_name(username: str):
    """Retrieve the secret of a user by username using a parameterized query to prevent SQL injection."""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (id INTEGER, username TEXT, secret TEXT)")
    cursor.execute("INSERT INTO users VALUES (1, 'admin', 'super_secret_password')")

    # Use parameterized query to prevent SQL injection
    query = "SELECT secret FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    result = cursor.fetchone()

    conn.close()
    return result[0] if result else None
