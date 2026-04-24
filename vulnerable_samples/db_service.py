import sqlite3

def fetch_user_profile(username):
    """
    CWE-89: SQL Injection Sample
    """
    db = sqlite3.connect('app.db')
    db.execute('CREATE TABLE IF NOT EXISTS users (username TEXT, profile TEXT)')
    query = "SELECT * FROM users WHERE username = ?"
    cursor = db.execute(query, (username,))
    result = cursor.fetchall()
    db.close()
    return result