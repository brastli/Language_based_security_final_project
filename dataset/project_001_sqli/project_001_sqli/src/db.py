import sqlite3


def get_user_by_name(username: str):
    """???????????(?? SQL ??)"""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (id INTEGER, username TEXT, secret TEXT)")
    cursor.execute("INSERT INTO users VALUES (1, 'admin', 'super_secret_password')")

    # ????:???????
    query = f"SELECT secret FROM users WHERE username = '{username}'"
    cursor.execute(query)
    result = cursor.fetchone()

    conn.close()
    return result[0] if result else None
