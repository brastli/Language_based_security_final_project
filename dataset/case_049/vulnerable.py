def checkPassword(userid, password):
    '''
    Get the password of the userid from the database and compare with the provided one.
    '''
    import base64

    if not isinstance(password, (bytes, bytearray)):
        raise Exception("Invalid password type")
    password = bytes(password)
    if b"\x00" in password or b";" in password or b"$" in password:
        raise Exception("Invalid password content")

    db = MySQLdb.connect(host="localhost", user="root", passwd="", db="test")
    cursor = db.cursor()
    try:
        cursor.execute("SELECT password FROM users WHERE userid = %s", (userid,))
        result = cursor.fetchone()
        if result is None:
            return False
        try:
            stored_password = base64.b64decode(result[0], validate=True)
        except Exception:
            return False
        return stored_password == password
    finally:
        try:
            cursor.close()
        except Exception:
            pass
        try:
            db.close()
        except Exception:
            pass