import sqlite3

def get_user(username):
    db = sqlite3.connect('app.db')
    # 将 name 修改为 username 以匹配 db_service.py 的表结构
    query = "SELECT * FROM users WHERE username = ?" 
    return db.execute(query, (username,)).fetchall()